//! Bounded, owner-local HTTP adapter. The coordinator socket owns all state.
use crate::v2::socket::{ClientCommand, ServerMessage, current_euid, verify_peer_uid};
use crate::v2::store::{DaemonStatusSummary, PendingDecisionRecord, TaskRecord};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const HEADER_LIMIT: usize = 16 * 1024;
const BODY_LIMIT: usize = 16 * 1024;
const BACKEND_LIMIT: usize = 4 * 1024 * 1024;
const MAX_CLIENTS: usize = 32;
const MAX_SSE: usize = 8;
const WAIT: Duration = Duration::from_secs(5);
const TICK: Duration = Duration::from_millis(50);

pub struct GatewayConfig {
    pub bind_addr: SocketAddr,
    pub socket_path: PathBuf,
    pub state_dir: PathBuf,
}
pub struct WebGateway {
    listener: TcpListener,
    socket_path: PathBuf,
    token: String,
}
pub struct GatewayHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<()>>>,
}
impl GatewayHandle {
    pub fn request_shutdown(&self) {
        self.stop.store(true, Ordering::Release);
    }
    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(|t| t.is_finished())
    }
    pub fn shutdown_and_join(mut self) -> io::Result<()> {
        self.join()
    }
    fn join(&mut self) -> io::Result<()> {
        self.request_shutdown();
        if let Some(t) = self.thread.take() {
            t.join()
                .map_err(|_| io::Error::other("gateway worker panicked"))??;
        }
        Ok(())
    }
}
impl Drop for GatewayHandle {
    fn drop(&mut self) {
        let _ = self.join();
    }
}
impl WebGateway {
    pub fn bind(config: GatewayConfig) -> io::Result<Self> {
        if !config.bind_addr.ip().is_loopback() {
            return Err(invalid("loopback address required"));
        }
        let listener = TcpListener::bind(config.bind_addr)?;
        listener.set_nonblocking(true)?;
        let token = session_token(&config.state_dir)?;
        Ok(Self {
            listener,
            socket_path: config.socket_path,
            token,
        })
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
    pub fn spawn(self) -> io::Result<GatewayHandle> {
        let stop = Arc::new(AtomicBool::new(false));
        let child_stop = stop.clone();
        let thread = thread::Builder::new()
            .name("web-gateway".into())
            .spawn(move || self.run(child_stop))?;
        Ok(GatewayHandle {
            stop,
            thread: Some(thread),
        })
    }
    fn run(self, stop: Arc<AtomicBool>) -> io::Result<()> {
        let mut workers: Vec<JoinHandle<()>> = Vec::new();
        let sse = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut result = Ok(());
        while !stop.load(Ordering::Acquire) {
            let mut i = 0;
            while i < workers.len() {
                if workers[i].is_finished() {
                    let _ = workers.swap_remove(i).join();
                } else {
                    i += 1;
                }
            }
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    if workers.len() >= MAX_CLIENTS {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    }
                    let path = self.socket_path.clone();
                    let token = self.token.clone();
                    let stop = stop.clone();
                    let sse = sse.clone();
                    match thread::Builder::new()
                        .name("web-client".into())
                        .spawn(move || {
                            let _ = stream.set_read_timeout(Some(TICK));
                            let _ = stream.set_write_timeout(Some(TICK));
                            let _ = serve(&mut stream, &path, &token, &stop, &sse);
                        }) {
                        Ok(t) => workers.push(t),
                        Err(e) => {
                            result = Err(e);
                            break;
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(TICK),
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        stop.store(true, Ordering::Release);
        for worker in workers {
            let _ = worker.join();
        }
        result
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn check(stop: &AtomicBool, deadline: Instant) -> io::Result<()> {
    if stop.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "gateway stopped",
        ));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline exceeded"));
    }
    Ok(())
}
fn retry(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}
fn write_bounded<W: Write>(
    out: &mut W,
    mut bytes: &[u8],
    stop: &AtomicBool,
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        check(stop, deadline)?;
        match out.write(bytes) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "closed writer")),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if retry(&e) => thread::sleep(Duration::from_millis(1)),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
// Open the directory and token without following symlinks; openat keeps validation
// and use attached to the same directory even if its pathname is replaced.
fn session_token(dir: &Path) -> io::Result<String> {
    session_token_with_entropy(dir, entropy)
}
fn session_token_with_entropy(
    dir: &Path,
    random_source: impl FnOnce(&mut [u8]) -> io::Result<()>,
) -> io::Result<String> {
    match DirBuilder::new().recursive(true).mode(0o700).create(dir) {
        Ok(()) => (),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e),
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)?;
    let meta = directory.metadata()?;
    if meta.uid() != current_euid() || meta.mode() & 0o077 != 0 {
        return Err(invalid("insecure state directory"));
    }
    let name = c"web_session_token";
    let open = |flags| unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    let fd = open(libc::O_RDONLY);
    if fd >= 0 {
        return read_token(unsafe { File::from_raw_fd(fd) });
    }
    let err = io::Error::last_os_error();
    if err.kind() != io::ErrorKind::NotFound {
        return Err(err);
    }
    let mut random = [0u8; 32];
    random_source(&mut random)?;
    let token = random
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let fd = open(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL);
    if fd < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::AlreadyExists {
            let fd = open(libc::O_RDONLY);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            return read_token(unsafe { File::from_raw_fd(fd) });
        }
        return Err(e);
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(token.as_bytes())?;
    file.sync_all()?;
    let meta = file.metadata()?;
    if meta.uid() != current_euid() || meta.mode() & 0o777 != 0o600 || meta.nlink() != 1 {
        return Err(invalid("insecure credential file"));
    }
    directory.sync_all()?;
    Ok(token)
}
fn entropy(bytes: &mut [u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let n = unsafe {
            libc::getrandom(bytes[offset..].as_mut_ptr().cast(), bytes.len() - offset, 0)
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n == 0 {
            return Err(io::Error::other("OS entropy unavailable"));
        }
        offset += n as usize;
    }
    Ok(())
}
fn read_token(file: File) -> io::Result<String> {
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != current_euid() || m.mode() & 0o777 != 0o600 || m.nlink() != 1 {
        return Err(invalid("insecure credential file"));
    }
    let mut bytes = Vec::new();
    file.take(66).read_to_end(&mut bytes)?;
    if bytes.len() != 64 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid("invalid credential file"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("invalid credential file"))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotResponse {
    pub tasks: Vec<TaskRecord>,
    pub open_decisions: Vec<PendingDecisionRecord>,
    pub status: DaemonStatusSummary,
    pub as_of_seq: i64,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideRequestBody {
    pub decision_id: String,
    pub choice: String,
    #[serde(default)]
    pub by: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}
struct Request {
    method: String,
    route: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}
fn decode(s: &str) -> io::Result<String> {
    let mut bytes = Vec::new();
    let raw = s.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'%' => {
                if i + 2 >= raw.len() {
                    return Err(invalid("invalid query"));
                }
                let hex = std::str::from_utf8(&raw[i + 1..i + 3])
                    .map_err(|_| invalid("invalid query"))?;
                bytes.push(u8::from_str_radix(hex, 16).map_err(|_| invalid("invalid query"))?);
                i += 3;
            }
            b'+' => {
                bytes.push(b' ');
                i += 1;
            }
            b => {
                bytes.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(bytes).map_err(|_| invalid("invalid query"))
}
fn read_request(stream: &mut TcpStream, stop: &AtomicBool) -> io::Result<Request> {
    let deadline = Instant::now() + WAIT;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 2048];
    let end = loop {
        check(stop, deadline)?;
        if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            if pos + 4 > HEADER_LIMIT {
                return Err(invalid("headers too large"));
            }
            break pos + 4;
        }
        if bytes.len() >= HEADER_LIMIT {
            return Err(invalid("headers too large"));
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(invalid("incomplete request")),
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(e) if retry(&e) => continue,
            Err(e) => return Err(e),
        }
    };
    let mut fields = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut fields);
    if !parsed
        .parse(&bytes[..end])
        .map_err(|_| invalid("invalid HTTP"))?
        .is_complete()
    {
        return Err(invalid("invalid HTTP"));
    }
    if parsed.version != Some(1) {
        return Err(invalid("HTTP/1.1 required"));
    }
    let method = parsed
        .method
        .ok_or_else(|| invalid("missing method"))?
        .to_owned();
    let path = parsed.path.ok_or_else(|| invalid("missing path"))?;
    let (route, query_text) = path.split_once('?').unwrap_or((path, ""));
    if !route.starts_with('/') {
        return Err(invalid("invalid target"));
    }
    let route = route.to_owned();
    let mut headers = HashMap::new();
    for h in parsed.headers.iter() {
        let key = h.name.to_ascii_lowercase();
        let value = std::str::from_utf8(h.value)
            .map_err(|_| invalid("invalid header"))?
            .trim()
            .to_owned();
        if headers.insert(key, value).is_some() {
            return Err(invalid("duplicate header"));
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err(invalid("unsupported framing"));
    }
    let len = match headers.get("content-length") {
        Some(v) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => {
            v.parse::<usize>().map_err(|_| invalid("invalid length"))?
        }
        Some(_) => return Err(invalid("invalid length")),
        None => 0,
    };
    if len > BODY_LIMIT || bytes.len() - end > len {
        return Err(invalid("invalid body length"));
    }
    let mut query = HashMap::new();
    for pair in query_text.split('&').filter(|s| !s.is_empty()) {
        let (key, val) = pair.split_once('=').unwrap_or((pair, ""));
        if query.insert(decode(key)?, decode(val)?).is_some() {
            return Err(invalid("duplicate query"));
        }
    }
    while bytes.len() - end < len {
        check(stop, deadline)?;
        let remaining = (len - (bytes.len() - end)).min(chunk.len());
        match stream.read(&mut chunk[..remaining]) {
            Ok(0) => return Err(invalid("incomplete body")),
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(e) if retry(&e) => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(Request {
        method,
        route,
        headers,
        query,
        body: bytes[end..].to_vec(),
    })
}
fn response(
    stream: &mut TcpStream,
    code: u16,
    data: &impl Serialize,
    stop: &AtomicBool,
) -> io::Result<()> {
    let body = serde_json::to_vec(data).map_err(io::Error::other)?;
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let deadline = Instant::now() + WAIT;
    write_bounded(stream, head.as_bytes(), stop, deadline)?;
    write_bounded(stream, &body, stop, deadline)
}
fn error(stream: &mut TcpStream, code: u16, message: &str, stop: &AtomicBool) -> io::Result<()> {
    response(stream, code, &serde_json::json!({"error": message}), stop)
}
fn cursor(req: &Request) -> io::Result<i64> {
    // Validate both supplied values even when the header takes precedence.
    let parse = |v: &str| {
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid("invalid cursor"));
        }
        v.parse::<i64>().map_err(|_| invalid("invalid cursor"))
    };
    let query = req.query.get("since_seq").map(|v| parse(v)).transpose()?;
    Ok(req
        .headers
        .get("last-event-id")
        .map(|v| parse(v))
        .transpose()?
        .or(query)
        .unwrap_or(0))
}
fn authorized(value: Option<&String>, token: &str) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Some((scheme, supplied)) = value.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("Bearer") || supplied.len() != token.len() {
        return false;
    }
    supplied
        .bytes()
        .zip(token.bytes())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

struct Backend {
    stream: UnixStream,
    bytes: Vec<u8>,
}
impl Backend {
    fn connect(path: &Path, stop: &AtomicBool, deadline: Instant) -> io::Result<Self> {
        use std::os::unix::ffi::OsStrExt;
        let raw = path.as_os_str().as_bytes();
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        if raw.is_empty() || raw.len() >= address.sun_path.len() || raw.contains(&0) {
            return Err(invalid("invalid socket path"));
        }
        address.sun_family = libc::AF_UNIX as _;
        for (a, b) in address.sun_path.iter_mut().zip(raw) {
            *a = *b as _;
        }
        let fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        let rc = unsafe {
            libc::connect(
                fd,
                (&address as *const libc::sockaddr_un).cast(),
                std::mem::size_of_val(&address) as _,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if !matches!(e.raw_os_error(), Some(libc::EINPROGRESS)) {
                return Err(e);
            }
            loop {
                check(stop, deadline)?;
                let mut pollfd = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                let n = unsafe { libc::poll(&mut pollfd, 1, TICK.as_millis() as _) };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
                if n > 0 {
                    let mut err: libc::c_int = 0;
                    let mut len = std::mem::size_of_val(&err) as libc::socklen_t;
                    if unsafe {
                        libc::getsockopt(
                            fd,
                            libc::SOL_SOCKET,
                            libc::SO_ERROR,
                            (&mut err as *mut libc::c_int).cast(),
                            &mut len,
                        )
                    } < 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    if err != 0 {
                        return Err(io::Error::from_raw_os_error(err));
                    }
                    break;
                }
            }
        }
        verify_peer_uid(&stream, current_euid()).map_err(|_| invalid("backend peer rejected"))?;
        Ok(Self {
            stream,
            bytes: Vec::new(),
        })
    }
    fn send(
        &mut self,
        command: &ClientCommand,
        stop: &AtomicBool,
        deadline: Instant,
    ) -> io::Result<()> {
        let mut bytes = serde_json::to_vec(command).map_err(io::Error::other)?;
        bytes.push(b'\n');
        write_bounded(&mut self.stream, &bytes, stop, deadline)
    }
    fn receive(
        &mut self,
        stop: &AtomicBool,
        deadline: Instant,
    ) -> io::Result<Option<ServerMessage>> {
        loop {
            check(stop, deadline)?;
            if let Some(n) = self.bytes.iter().position(|b| *b == b'\n') {
                let line: Vec<_> = self.bytes.drain(..=n).collect();
                return serde_json::from_slice(&line)
                    .map(Some)
                    .map_err(|_| invalid("invalid backend response"));
            }
            if self.bytes.len() >= BACKEND_LIMIT {
                return Err(invalid("backend response too large"));
            }
            let mut chunk = [0; 8192];
            let limit = (BACKEND_LIMIT - self.bytes.len()).min(chunk.len());
            match self.stream.read(&mut chunk[..limit]) {
                Ok(0) if self.bytes.is_empty() => return Ok(None),
                Ok(0) => return Err(invalid("incomplete backend response")),
                Ok(n) => self.bytes.extend_from_slice(&chunk[..n]),
                Err(e) if retry(&e) => thread::sleep(Duration::from_millis(2)),
                Err(e) => return Err(e),
            }
        }
    }
}
fn backend_error(
    stream: &mut TcpStream,
    e: io::Error,
    dispatched: bool,
    stop: &AtomicBool,
) -> io::Result<()> {
    let timeout = e.kind() == io::ErrorKind::TimedOut;
    error(
        stream,
        if timeout { 504 } else { 503 },
        if dispatched {
            "decision outcome unknown; reconcile before retrying"
        } else if timeout {
            "backend timeout"
        } else {
            "backend unavailable"
        },
        stop,
    )
}
fn serve(
    stream: &mut TcpStream,
    path: &Path,
    token: &str,
    stop: &AtomicBool,
    sse: &std::sync::atomic::AtomicUsize,
) -> io::Result<()> {
    let req = match read_request(stream, stop) {
        Ok(r) => r,
        Err(_) => return error(stream, 400, "invalid request", stop),
    };
    if !authorized(req.headers.get("authorization"), token) {
        return error(stream, 401, "unauthorized", stop);
    }
    let group = req.query.get("group").cloned();
    match (req.method.as_str(), req.route.as_str()) {
        ("GET", "/api/snapshot") => {
            let deadline = Instant::now() + WAIT;
            let result = (|| {
                let mut backend = Backend::connect(path, stop, deadline)?;
                backend.send(
                    &ClientCommand::Subscribe {
                        group,
                        since_seq: Some(0),
                        once: Some(false),
                    },
                    stop,
                    deadline,
                )?;
                backend.send(&ClientCommand::Status, stop, deadline)?;
                let mut snapshot = None;
                let mut status = None;
                while snapshot.is_none() || status.is_none() {
                    match backend.receive(stop, deadline)? {
                        Some(ServerMessage::Snapshot {
                            tasks,
                            open_decisions,
                            as_of_seq,
                        }) => snapshot = Some((tasks, open_decisions, as_of_seq)),
                        Some(ServerMessage::Status {
                            ok: true,
                            status: value,
                        }) => status = Some(value),
                        Some(ServerMessage::Event { .. }) => (),
                        _ => return Err(invalid("backend snapshot unavailable")),
                    }
                }
                let (tasks, open_decisions, as_of_seq) = snapshot.unwrap();
                Ok(SnapshotResponse {
                    tasks,
                    open_decisions,
                    as_of_seq,
                    status: status.unwrap(),
                })
            })();
            match result {
                Ok(data) => response(stream, 200, &data, stop),
                Err(e) => backend_error(stream, e, false, stop),
            }
        }
        ("POST", "/api/decide") => {
            let body = match serde_json::from_slice::<DecideRequestBody>(&req.body) {
                Ok(b)
                    if !b.decision_id.trim().is_empty()
                        && !b.choice.trim().is_empty()
                        && b.decision_id.len() <= 256
                        && b.choice.len() <= 256 =>
                {
                    b
                }
                _ => return error(stream, 400, "invalid decision request", stop),
            };
            let deadline = Instant::now() + WAIT;
            let mut dispatched = false;
            let result = (|| {
                let mut backend = Backend::connect(path, stop, deadline)?;
                // Once sending starts, any failure may leave an unknown outcome.
                dispatched = true;
                backend.send(
                    &ClientCommand::Decide {
                        decision_id: body.decision_id,
                        choice: body.choice,
                        by: body.by,
                        note: body.note,
                    },
                    stop,
                    deadline,
                )?;
                match backend.receive(stop, deadline)? {
                    Some(ServerMessage::DecisionResult { outcome, decision }) => {
                        Ok((outcome, decision))
                    }
                    Some(ServerMessage::Error { error })
                        if error == "invalid decision choice or empty actor" =>
                    {
                        Ok(("INVALID_REQUEST".into(), None))
                    }
                    _ => Err(invalid("backend decision unavailable")),
                }
            })();
            match result {
                Ok((outcome, decision))
                    if matches!(
                        outcome.as_str(),
                        "RESOLVED" | "ALREADY_RESOLVED" | "NOT_FOUND"
                    ) =>
                {
                    response(
                        stream,
                        if outcome == "NOT_FOUND" { 404 } else { 200 },
                        &serde_json::json!({"outcome":outcome,"decision":decision}),
                        stop,
                    )
                }
                Ok((outcome, _)) if outcome == "INVALID_REQUEST" => {
                    error(stream, 400, "invalid decision request", stop)
                }
                Ok(_) => error(stream, 503, "backend decision unavailable", stop),
                Err(e) => backend_error(stream, e, dispatched, stop),
            }
        }
        ("GET", "/api/events") => {
            let since = match cursor(&req) {
                Ok(n) => n,
                Err(_) => return error(stream, 400, "invalid cursor", stop),
            };
            if sse
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < MAX_SSE).then_some(n + 1)
                })
                .is_err()
            {
                return error(stream, 503, "event capacity reached", stop);
            }
            struct Permit<'a>(&'a std::sync::atomic::AtomicUsize);
            impl Drop for Permit<'_> {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::AcqRel);
                }
            }
            let _permit = Permit(sse);
            let deadline = Instant::now() + WAIT;
            let mut backend = match Backend::connect(path, stop, deadline).and_then(|mut b| {
                b.send(
                    &ClientCommand::Subscribe {
                        group,
                        since_seq: Some(since),
                        once: Some(false),
                    },
                    stop,
                    deadline,
                )?;
                Ok(b)
            }) {
                Ok(b) => b,
                Err(e) => return backend_error(stream, e, false, stop),
            };
            // Wait for the first backend response before committing HTTP success.
            let mut next = match backend.receive(stop, deadline) {
                Ok(Some(m)) if !matches!(m, ServerMessage::Error { .. }) => Some(m),
                Ok(_) => return error(stream, 503, "backend unavailable", stop),
                Err(e) => return backend_error(stream, e, false, stop),
            };
            write_bounded(stream, b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache, no-transform\r\nConnection: close\r\n\r\n", stop, Instant::now() + WAIT)?;
            loop {
                if let Some(message) = next.take() {
                    let (kind, id, close) = match &message {
                        ServerMessage::Event { event } => ("task_event", Some(event.seq_id), false),
                        ServerMessage::Snapshot { .. } => ("snapshot", None, false),
                        ServerMessage::ResyncRequired { .. } => ("resync_required", None, true),
                        _ => break,
                    };
                    let data = match &message {
                        ServerMessage::Event { event } => serde_json::to_string(event),
                        _ => serde_json::to_string(&message),
                    }
                    .map_err(io::Error::other)?;
                    let frame = format!(
                        "{}event: {kind}\ndata: {data}\n\n",
                        id.map(|n| format!("id: {n}\n")).unwrap_or_default()
                    );
                    write_bounded(stream, frame.as_bytes(), stop, Instant::now() + WAIT)?;
                    if close {
                        break;
                    }
                }
                match backend.receive(stop, Instant::now() + Duration::from_secs(1)) {
                    Ok(Some(m)) => next = Some(m),
                    Ok(None) => break,
                    Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                        write_bounded(stream, b": keepalive\n\n", stop, Instant::now() + WAIT)?
                    }
                    Err(_) => break,
                }
            }
            Ok(())
        }
        _ => error(stream, 404, "not found", stop),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::socket::write_ndjson;
    use crate::v2::store::TaskEventRecord;
    use std::fs;
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::AtomicUsize;

    struct Fixture {
        dir: PathBuf,
        addr: SocketAddr,
        token: String,
        handle: Option<GatewayHandle>,
    }
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "zach-web-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let gateway = WebGateway::bind(GatewayConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                socket_path: dir.join("backend.sock"),
                state_dir: dir.clone(),
            })
            .unwrap();
            let addr = gateway.local_addr().unwrap();
            let token = gateway.token.clone();
            Self {
                dir,
                addr,
                token,
                handle: Some(gateway.spawn().unwrap()),
            }
        }
        fn backend(&self, run: impl FnOnce(UnixStream) + Send + 'static) -> JoinHandle<()> {
            let listener = UnixListener::bind(self.dir.join("backend.sock")).unwrap();
            thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(WAIT)).unwrap();
                stream.set_write_timeout(Some(WAIT)).unwrap();
                run(stream);
            })
        }
        fn request(&self, method: &str, target: &str, headers: &str, body: &str) -> TcpStream {
            let mut stream = TcpStream::connect(self.addr).unwrap();
            stream.set_read_timeout(Some(WAIT + WAIT)).unwrap();
            write!(stream, "{method} {target} HTTP/1.1\r\nHost: localhost\r\n{headers}Content-Length: {}\r\n\r\n{body}", body.len()).unwrap();
            stream
        }
        fn auth(&self) -> String {
            format!("Authorization: Bearer {}\r\n", self.token)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(h) = self.handle.take() {
                h.shutdown_and_join().unwrap();
            }
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
    fn read_all(mut stream: TcpStream) -> String {
        let mut out = String::new();
        if let Err(e) = stream.read_to_string(&mut out) {
            assert!(
                e.kind() == io::ErrorKind::ConnectionReset && !out.is_empty(),
                "{e}"
            );
        }
        out
    }
    fn command(reader: &mut BufReader<UnixStream>) -> ClientCommand {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
    fn snapshot() -> ServerMessage {
        ServerMessage::Snapshot {
            tasks: vec![],
            open_decisions: vec![],
            as_of_seq: 9000,
        }
    }
    fn event(seq: i64) -> ServerMessage {
        ServerMessage::Event {
            event: TaskEventRecord {
                seq_id: seq,
                task_id: "SYNTHETIC".into(),
                task_group: "test".into(),
                ts_epoch: 1,
                event_type: "test".into(),
                payload: serde_json::json!({}),
            },
        }
    }

    #[test]
    fn web_gateway_auth_all_routes_and_no_disclosure() {
        let f = Fixture::new();
        for route in [
            "/api/snapshot",
            "/api/events",
            "/api/decide",
            "/api/session",
        ] {
            for alias in [
                "".to_string(),
                format!("Cookie: token={}\r\n", f.token),
                format!("X-Auth-Token: {}\r\n", f.token),
                format!("Authorization: Session {}\r\n", f.token),
            ] {
                let reply =
                    read_all(f.request("GET", &format!("{route}?token={}", f.token), &alias, ""));
                assert!(reply.starts_with("HTTP/1.1 401"));
                assert!(!reply.contains(&f.token));
                assert!(!reply.contains("Access-Control"));
            }
        }
        assert!(
            read_all(f.request("GET", "/api/session", &f.auth(), "")).starts_with("HTTP/1.1 404")
        );
        assert!(
            read_all(f.request("GET", "/api/snapshot", &f.auth(), "")).starts_with("HTTP/1.1 503")
        );
    }
    #[test]
    fn web_gateway_credentials_secure_stable_and_fail_closed() {
        let f = Fixture::new();
        assert_eq!(session_token(&f.dir).unwrap(), f.token);
        assert_eq!(
            fs::metadata(f.dir.join("web_session_token"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        fs::set_permissions(
            f.dir.join("web_session_token"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(session_token(&f.dir).is_err());
        fs::remove_file(f.dir.join("web_session_token")).unwrap();
        symlink("missing", f.dir.join("web_session_token")).unwrap();
        assert!(session_token(&f.dir).is_err());
        let bad = f.dir.join("bad");
        fs::write(&bad, "synthetic").unwrap();
        assert!(session_token(&bad).is_err());
        assert!(
            WebGateway::bind(GatewayConfig {
                bind_addr: "0.0.0.0:0".parse().unwrap(),
                socket_path: bad,
                state_dir: f.dir.clone()
            })
            .is_err()
        );
    }
    #[test]
    fn web_gateway_rejects_malformed_framing_and_cursors() {
        let f = Fixture::new();
        for extra in [
            "Transfer-Encoding: chunked\r\n",
            "Content-Length: 0\r\n",
            "Content-Length: 99999999999999999999999\r\n",
            "Last-Event-ID: 1\r\nLast-Event-ID: 2\r\n",
            "Last-Event-ID: -1\r\n",
            "Last-Event-ID: 9223372036854775808\r\n",
        ] {
            assert!(
                read_all(f.request("GET", "/api/events", &(f.auth() + extra), ""))
                    .starts_with("HTTP/1.1 400")
            );
        }
        for query in [
            "since_seq=-1",
            "since_seq=1&since_seq=2",
            "since_seq=18446744073709551616",
            "group=%zz",
        ] {
            assert!(
                read_all(f.request("GET", &format!("/api/events?{query}"), &f.auth(), ""))
                    .starts_with("HTTP/1.1 400")
            );
        }
        assert!(
            read_all(f.request("POST", "/api/decide", &f.auth(), "{oops"))
                .starts_with("HTTP/1.1 400")
        );
        let oversized = "a".repeat(HEADER_LIMIT + 1);
        let reply = read_all(f.request(
            "GET",
            "/api/events",
            &format!("{}X-Large: {oversized}\r\n", f.auth()),
            "",
        ));
        assert!(reply.starts_with("HTTP/1.1 400"));
    }
    #[test]
    fn web_gateway_snapshot_uses_socket_status_and_snapshot_watermark() {
        let f = Fixture::new();
        let backend = f.backend(|stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap()); let mut writer = stream;
            assert_eq!(command(&mut reader), ClientCommand::Subscribe { group: Some("test".into()), since_seq: Some(0), once: Some(false) });
            assert_eq!(command(&mut reader), ClientCommand::Status);
            write_ndjson(&mut writer, &snapshot()).unwrap();
            let status: DaemonStatusSummary = serde_json::from_value(serde_json::json!({"schema_version":4,"max_parallel_tasks":2,"heartbeat_epoch":1,"max_seq_id":9001,"total_tasks":0,"ready_eligible_count":0,"in_progress_count":0,"open_decisions_count":0,"active_locks_count":0,"merge_queue_count":0})).unwrap();
            write_ndjson(&mut writer, &ServerMessage::Status { ok: true, status }).unwrap();
        });
        let reply = read_all(f.request("GET", "/api/snapshot?group=test", &f.auth(), ""));
        let data: SnapshotResponse =
            serde_json::from_str(reply.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(data.as_of_seq, 9000);
        assert_eq!(data.status.max_seq_id, 9001);
        backend.join().unwrap();
    }
    #[test]
    fn web_gateway_decide_waits_for_ack_and_forwards_exact_command() {
        for outcome in ["RESOLVED", "ALREADY_RESOLVED", "NOT_FOUND"] {
            let f = Fixture::new();
            let outcome = outcome.to_string();
            let expected = outcome.clone();
            let (sent, received) = std::sync::mpsc::channel();
            let backend = f.backend(move |stream| {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut writer = stream;
                assert_eq!(
                    command(&mut reader),
                    ClientCommand::Decide {
                        decision_id: "synthetic".into(),
                        choice: "APPROVE".into(),
                        by: Some("tester".into()),
                        note: Some("test".into())
                    }
                );
                sent.send(()).unwrap();
                thread::sleep(Duration::from_millis(150));
                write_ndjson(
                    &mut writer,
                    &ServerMessage::DecisionResult {
                        outcome,
                        decision: None,
                    },
                )
                .unwrap();
            });
            let mut stream = f.request(
                "POST",
                "/api/decide",
                &f.auth(),
                r#"{"decision_id":"synthetic","choice":"APPROVE","by":"tester","note":"test"}"#,
            );
            received.recv_timeout(WAIT).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let mut byte = [0];
            assert!(
                stream.read(&mut byte).is_err(),
                "no success before actual ACK"
            );
            stream.set_read_timeout(Some(WAIT)).unwrap();
            let reply = read_all(stream);
            assert!(reply.starts_with(if expected == "NOT_FOUND" {
                "HTTP/1.1 404"
            } else {
                "HTTP/1.1 200"
            }));
            assert!(reply.contains(&expected));
            backend.join().unwrap();
        }
    }
    #[test]
    fn web_gateway_sse_forwards_5101_events_and_control_without_cursor() {
        let f = Fixture::new();
        let backend = f.backend(|stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            assert_eq!(
                command(&mut reader),
                ClientCommand::Subscribe {
                    group: Some("test".into()),
                    since_seq: Some(41),
                    once: Some(false)
                }
            );
            write_ndjson(&mut writer, &snapshot()).unwrap();
            for seq in 42..=5142 {
                write_ndjson(&mut writer, &event(seq)).unwrap();
            }
            write_ndjson(
                &mut writer,
                &ServerMessage::ResyncRequired { last_seq_id: 5142 },
            )
            .unwrap();
        });
        let reply = read_all(f.request(
            "GET",
            "/api/events?since_seq=0&group=test",
            &(f.auth() + "Last-Event-ID: 41\r\n"),
            "",
        ));
        let ids: Vec<i64> = reply
            .lines()
            .filter_map(|s| s.strip_prefix("id: ").map(|s| s.parse().unwrap()))
            .collect();
        assert_eq!(ids, (42..=5142).collect::<Vec<_>>());
        assert!(reply.contains("event: task_event"));
        assert!(reply.contains("event: snapshot"));
        assert!(reply.contains("event: resync_required"));
        assert!(!reply.contains("id: 9000"));
        backend.join().unwrap();
    }
    #[test]
    fn web_gateway_partial_io_and_shutdown_interrupts_clients_and_backend() {
        let mut f = Fixture::new();
        let backend = f.backend(|stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert!(matches!(
                command(&mut reader),
                ClientCommand::Subscribe { .. }
            ));
            let mut bytes = Vec::new();
            let _ = reader.read_to_end(&mut bytes);
        });
        let mut partial = TcpStream::connect(f.addr).unwrap();
        partial.write_all(b"GET /api/snap").unwrap();
        let _waiting = f.request("GET", "/api/events", &f.auth(), "");
        thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        f.handle.take().unwrap().shutdown_and_join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(2));
        backend.join().unwrap();
    }
    #[test]
    fn web_gateway_entropy_and_persistence_fail_closed() {
        let f = Fixture::new();
        let dir = f.dir.join("entropy-failure");
        assert!(
            session_token_with_entropy(&dir, |_| Err(io::Error::other(
                "synthetic entropy failure"
            )))
            .is_err()
        );
        assert!(!dir.join("web_session_token").exists());
        let dir = f.dir.join("persist-failure");
        assert!(
            session_token_with_entropy(&dir, |bytes| {
                bytes.fill(1);
                fs::remove_dir(&dir)?;
                Ok(())
            })
            .is_err()
        );
        assert!(!dir.exists());
    }
    #[test]
    fn web_gateway_decide_timeout_is_unknown_and_no_retry() {
        let f = Fixture::new();
        let backend = f.backend(|stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert!(matches!(command(&mut reader), ClientCommand::Decide { .. }));
            // A withheld ACK is never translated into successful dispatch.
            let mut rest = String::new();
            let _ = reader.read_to_string(&mut rest);
            assert!(rest.is_empty(), "no automatic second command");
        });
        let reply = read_all(f.request(
            "POST",
            "/api/decide",
            &f.auth(),
            r#"{"decision_id":"synthetic","choice":"APPROVE"}"#,
        ));
        assert!(reply.starts_with("HTTP/1.1 504"));
        assert!(reply.contains("outcome unknown"));
        assert!(!reply.contains(&f.token));
        backend.join().unwrap();
    }
    #[test]
    fn web_gateway_partial_http_and_backend_frames() {
        let f = Fixture::new();
        let backend = f.backend(|stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            assert!(matches!(
                command(&mut reader),
                ClientCommand::Subscribe { .. }
            ));
            let mut bytes = serde_json::to_vec(&snapshot()).unwrap();
            bytes.push(b'\n');
            for chunk in bytes.chunks(3) {
                writer.write_all(chunk).unwrap();
            }
            let mut bytes = serde_json::to_vec(&event(1)).unwrap();
            bytes.push(b'\n');
            for chunk in bytes.chunks(2) {
                writer.write_all(chunk).unwrap();
            }
        });
        let mut stream = TcpStream::connect(f.addr).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        let request = format!(
            "GET /api/events HTTP/1.1\r\nHost: localhost\r\n{}\r\n",
            f.auth()
        );
        for chunk in request.as_bytes().chunks(3) {
            stream.write_all(chunk).unwrap();
        }
        let reply = read_all(stream);
        assert!(reply.contains("id: 1\nevent: task_event"));
        backend.join().unwrap();
    }
    #[test]
    fn web_gateway_sse_capacity_and_slow_clients_release_on_shutdown() {
        let mut f = Fixture::new();
        let listener = UnixListener::bind(f.dir.join("backend.sock")).unwrap();
        let (release, released) = std::sync::mpsc::channel();
        let backend = thread::spawn(move || {
            let mut streams = Vec::new();
            for _ in 0..MAX_SSE {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(WAIT)).unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                assert!(matches!(
                    command(&mut reader),
                    ClientCommand::Subscribe { .. }
                ));
                write_ndjson(&mut stream, &snapshot()).unwrap();
                streams.push(stream);
            }
            released.recv_timeout(WAIT).unwrap();
        });
        let mut clients = Vec::new();
        for _ in 0..MAX_SSE {
            let stream = f.request("GET", "/api/events", &f.auth(), "");
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.starts_with("HTTP/1.1 200"));
            clients.push(reader);
        }
        let reply = read_all(f.request("GET", "/api/events", &f.auth(), ""));
        assert!(reply.starts_with("HTTP/1.1 503"));
        // Clients stop consuming; shutdown must still interrupt backend idle reads.
        let start = Instant::now();
        f.handle.take().unwrap().shutdown_and_join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(2));
        release.send(()).unwrap();
        backend.join().unwrap();
        // Listener and client workers are joined, and the same port is reusable.
        let listener = TcpListener::bind(f.addr).unwrap();
        drop(listener);
        drop(clients);
    }
    #[test]
    fn web_gateway_shutdown_interrupts_backpressured_sse_writer() {
        let mut f = Fixture::new();
        let backend = f.backend(|stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            assert!(matches!(
                command(&mut reader),
                ClientCommand::Subscribe { .. }
            ));
            write_ndjson(&mut writer, &snapshot()).unwrap();
            for seq in 1..=20 {
                let message = ServerMessage::Event {
                    event: TaskEventRecord {
                        seq_id: seq,
                        task_id: "SYNTHETIC".into(),
                        task_group: "test".into(),
                        ts_epoch: 1,
                        event_type: "test".into(),
                        payload: serde_json::json!({"synthetic": "x".repeat(1024 * 1024)}),
                    },
                };
                if write_ndjson(&mut writer, &message).is_err() {
                    break;
                }
            }
        });
        let stream = f.request("GET", "/api/events", &f.auth(), "");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.starts_with("HTTP/1.1 200"));
        thread::sleep(Duration::from_millis(200));
        let start = Instant::now();
        f.handle.take().unwrap().shutdown_and_join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(2));
        backend.join().unwrap();
    }
}
