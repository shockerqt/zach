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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

const REQUEST_LINE_LIMIT: usize = 4096;
const QUERY_LIMIT: usize = 32;
const HEADER_LIMIT: usize = 16 * 1024;
const BODY_LIMIT: usize = 16 * 1024;
const BACKEND_LIMIT: usize = 4 * 1024 * 1024;
const MAX_CLIENTS: usize = 32;
const MAX_SSE: usize = 8;
const WAIT: Duration = Duration::from_secs(5);
const TICK: Duration = Duration::from_millis(50);

const DEFAULT_DECISION_KINDS: &[&str] = &[
    "plan_approval",
    "human-plan-approval",
    "retries_exhausted",
    "scope_violation",
    "plan_rework_limit",
    "review_rework_limit",
    "governance_close_failed",
    "governance_publication_failed",
    "checkpoint_unverifiable",
    "repository_ownership_conflict",
    "cross_family_reviewer_unavailable",
    "merge_failed",
    "post_merge_failure",
    "new_apk_required",
    "prod_promotion_approval",
    "delivery_contract_error",
];
struct Policy {
    bind_origin: String,
    allowed_origins: Vec<String>,
    allowed_decision_kinds: Vec<String>,
}
impl Policy {
    fn origin_allowed(&self, origin: &str) -> bool {
        valid_origin(origin)
            && (origin == self.bind_origin || self.allowed_origins.iter().any(|o| o == origin))
    }
    fn kind_allowed(&self, kind: &str) -> bool {
        DEFAULT_DECISION_KINDS.contains(&kind)
            || self.allowed_decision_kinds.iter().any(|k| k == kind)
    }
}
// Deliberately accepts only serialized origins, never URLs or proxy-derived authorities.
fn valid_origin(origin: &str) -> bool {
    if origin.len() > 512
        || !origin.is_ascii()
        || origin
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return false;
    }
    let Some(authority) = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
    else {
        return false;
    };
    if authority.is_empty() || authority.contains(['/', '?', '#', '@', '\\', '*']) {
        return false;
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return false;
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        let port = if tail.is_empty() {
            None
        } else if let Some(port) = tail.strip_prefix(':') {
            Some(port)
        } else {
            return false;
        };
        (host, port)
    } else {
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(h, p)| (h, Some(p)));
        if host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return false;
        }
        (host, port)
    };
    if host.is_empty() {
        return false;
    }
    port.is_none_or(|p| {
        !p.is_empty()
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u16>().is_ok_and(|p| p > 0)
    })
}
pub fn validate_web_policy(origins: &[String], kinds: &[String]) -> io::Result<()> {
    if origins.len() > 16 || kinds.len() > 32 {
        return Err(invalid("too many web policy entries"));
    }
    let mut seen = std::collections::HashSet::new();
    for origin in origins {
        if !valid_origin(origin) || !seen.insert(origin) {
            return Err(invalid("invalid or duplicate allowed origin"));
        }
    }
    let mut seen = std::collections::HashSet::new();
    for kind in kinds {
        if kind.is_empty()
            || kind.len() > 64
            || !kind
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
            || !seen.insert(kind)
        {
            return Err(invalid("invalid or duplicate decision kind"));
        }
    }
    Ok(())
}
fn cors_headers(origin: Option<&str>) -> String {
    match origin {
        Some(origin) => format!("Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\n"),
        None => "Vary: Origin\r\n".into(),
    }
}
fn preflight(
    stream: &mut TcpStream,
    req: &Request,
    origin: Option<&str>,
    stop: &AtomicBool,
) -> io::Result<()> {
    let method = match req.route.as_str() {
        "/api/snapshot" | "/api/events" => "GET",
        "/api/decide" => "POST",
        _ => return error(stream, 403, "preflight forbidden", stop, origin),
    };
    if origin.is_none()
        || !req.body.is_empty()
        || req
            .headers
            .get("access-control-request-method")
            .map(String::as_str)
            != Some(method)
    {
        return error(stream, 403, "preflight forbidden", stop, origin);
    }
    let mut headers = Vec::new();
    if let Some(requested) = req.headers.get("access-control-request-headers") {
        for name in requested.split(',') {
            let name = name.trim_matches([' ', '\t']).to_ascii_lowercase();
            if headers.len() >= 3
                || !["authorization", "content-type", "last-event-id"].contains(&name.as_str())
                || headers.contains(&name)
            {
                return error(stream, 403, "preflight forbidden", stop, origin);
            }
            headers.push(name);
        }
    }
    let head = format!(
        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\nAccess-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Methods: {method}\r\nAccess-Control-Allow-Headers: {}\r\nVary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers\r\n\r\n",
        origin.unwrap(),
        headers.join(", ")
    );
    write_bounded(stream, head.as_bytes(), stop, Instant::now() + WAIT)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CfAccessConfig {
    pub team_domain: String,
    pub aud: String,
    pub allowed_emails: Vec<String>,
}

fn valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.is_ascii()
        && !host
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        && !host.contains(['/', '?', '#', '@', ':', '\\', '*'])
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn valid_email(email: &str) -> bool {
    if email.is_empty()
        || email.len() > 254
        || !email.is_ascii()
        || email
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty() && !domain.contains('@') && valid_hostname(domain)
}

pub fn normalize_cf_access_config(
    team_domain: &str,
    aud: &str,
    emails: &[String],
) -> io::Result<CfAccessConfig> {
    let config = CfAccessConfig {
        team_domain: team_domain.trim().to_ascii_lowercase(),
        aud: aud.trim().to_string(),
        allowed_emails: emails
            .iter()
            .map(|e| e.trim().to_ascii_lowercase())
            .collect(),
    };
    validate_cf_access_config(&config)?;
    Ok(config)
}

pub fn validate_cf_access_config(config: &CfAccessConfig) -> io::Result<()> {
    if !valid_hostname(&config.team_domain) {
        return Err(invalid("invalid Cloudflare Access team domain"));
    }
    if config.aud.is_empty()
        || config.aud.len() > 512
        || !config.aud.is_ascii()
        || config
            .aud
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(invalid("invalid Cloudflare Access aud"));
    }
    if config.allowed_emails.is_empty() || config.allowed_emails.len() > 16 {
        return Err(invalid("invalid Cloudflare Access email list"));
    }
    let mut seen = std::collections::HashSet::new();
    for email in &config.allowed_emails {
        if !valid_email(email) || !seen.insert(email.to_ascii_lowercase()) {
            return Err(invalid("invalid or duplicate Cloudflare Access email"));
        }
    }
    Ok(())
}

pub struct GatewayConfig {
    pub bind_addr: SocketAddr,
    pub socket_path: PathBuf,
    pub state_dir: PathBuf,
    pub allowed_origins: Vec<String>,
    pub allowed_decision_kinds: Vec<String>,
    pub cf_access: Option<CfAccessConfig>,
}
pub struct WebGateway {
    listener: TcpListener,
    socket_path: PathBuf,
    token: String,
    policy: Arc<Policy>,
    cf_access: Option<Arc<AccessJwtVerifier>>,
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
        Self::bind_with_jwks_fetcher(config, Arc::new(fetch_cf_jwks))
    }

    fn bind_with_jwks_fetcher(config: GatewayConfig, fetcher: JwksFetcher) -> io::Result<Self> {
        if !config.bind_addr.ip().is_loopback() {
            return Err(invalid("loopback address required"));
        }
        validate_web_policy(&config.allowed_origins, &config.allowed_decision_kinds)?;
        let cf_access = match config.cf_access {
            Some(cf) => {
                validate_cf_access_config(&cf)?;
                Some(Arc::new(AccessJwtVerifier::new(cf, fetcher)))
            }
            None => None,
        };
        let listener = TcpListener::bind(config.bind_addr)?;
        let policy = Arc::new(Policy {
            bind_origin: format!("http://{}", listener.local_addr()?),
            allowed_origins: config.allowed_origins,
            allowed_decision_kinds: config.allowed_decision_kinds,
        });
        listener.set_nonblocking(true)?;
        let token = session_token(&config.state_dir)?;
        Ok(Self {
            listener,
            socket_path: config.socket_path,
            token,
            policy,
            cf_access,
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
                    let policy = self.policy.clone();
                    let cf_access = self.cf_access.clone();
                    let stop = stop.clone();
                    let sse = sse.clone();
                    match thread::Builder::new()
                        .name("web-client".into())
                        .spawn(move || {
                            let _ = stream.set_read_timeout(Some(TICK));
                            let _ = stream.set_write_timeout(Some(TICK));
                            let _ = serve(
                                &mut stream,
                                &path,
                                &token,
                                &stop,
                                &sse,
                                &policy,
                                cf_access.as_deref(),
                            );
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
        if bytes
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap_or(bytes.len())
            > REQUEST_LINE_LIMIT
        {
            return Err(invalid("request line too large"));
        }
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
    if !route.starts_with('/')
        || route.starts_with("//")
        || path.contains('#')
        || path.contains('\\')
    {
        return Err(invalid("invalid target"));
    }
    let decoded_route = decode(route)?;
    if decoded_route.chars().any(char::is_control) {
        return Err(invalid("invalid target"));
    }
    let route = route.to_owned();
    let mut headers = HashMap::new();
    for h in parsed.headers.iter() {
        let key = h.name.to_ascii_lowercase();
        let value = std::str::from_utf8(h.value)
            .map_err(|_| invalid("invalid header"))?
            .trim_matches([' ', '\t'])
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
    for (index, pair) in query_text.split('&').filter(|s| !s.is_empty()).enumerate() {
        if index >= QUERY_LIMIT {
            return Err(invalid("too many query fields"));
        }
        let (key, val) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode(key)?;
        let val = decode(val)?;
        if [
            "token",
            "access_token",
            "session_token",
            "web_session_token",
            "authorization",
            "bearer",
        ]
        .iter()
        .any(|name| key.eq_ignore_ascii_case(name))
        {
            return Err(invalid("URL credentials forbidden"));
        }
        if key.chars().chain(val.chars()).any(char::is_control) {
            return Err(invalid("invalid query"));
        }
        if query.insert(key, val).is_some() {
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
    origin: Option<&str>,
) -> io::Result<()> {
    let body = serde_json::to_vec(data).map_err(io::Error::other)?;
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        401 => "Unauthorized",
        404 => "Not Found",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n{}\r\n",
        body.len(),
        cors_headers(origin)
    );
    let deadline = Instant::now() + WAIT;
    write_bounded(stream, head.as_bytes(), stop, deadline)?;
    write_bounded(stream, &body, stop, deadline)
}
fn error(
    stream: &mut TcpStream,
    code: u16,
    message: &str,
    stop: &AtomicBool,
    origin: Option<&str>,
) -> io::Result<()> {
    response(
        stream,
        code,
        &serde_json::json!({"error": message}),
        stop,
        origin,
    )
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
    if !scheme.eq_ignore_ascii_case("Bearer") || supplied.len() != 64 || token.len() != 64 {
        return false;
    }
    bool::from(supplied.as_bytes().ct_eq(token.as_bytes()))
}

const JWKS_TTL: Duration = Duration::from_secs(3600);
const JWKS_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);
const JWT_CLOCK_SKEW_SECS: u64 = 60;
const MAX_JWT_LEN: usize = 8192;

type JwksFetcher = Arc<dyn Fn(&str) -> io::Result<Vec<u8>> + Send + Sync>;

struct JwksCache {
    keys: HashMap<String, String>,
    fetched_at: Option<Instant>,
    last_refresh_attempt: Option<Instant>,
}

struct AccessJwtVerifier {
    config: CfAccessConfig,
    fetcher: JwksFetcher,
    cache: Mutex<JwksCache>,
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    kid: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AudClaim {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct AccessClaims {
    aud: AudClaim,
    exp: u64,
    nbf: Option<u64>,
    iss: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct JwksPayload {
    keys: Vec<JwkKey>,
}

#[derive(Deserialize)]
struct JwkKey {
    kty: String,
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
}

impl AccessJwtVerifier {
    fn new(config: CfAccessConfig, fetcher: JwksFetcher) -> Self {
        Self {
            config,
            fetcher,
            cache: Mutex::new(JwksCache {
                keys: HashMap::new(),
                fetched_at: None,
                last_refresh_attempt: None,
            }),
        }
    }

    fn verify(&self, token: &str) -> bool {
        if token.is_empty() || token.len() > MAX_JWT_LEN {
            return false;
        }
        let mut parts = token.split('.');
        let (Some(header_b64), Some(payload_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        if header_b64.is_empty() || payload_b64.is_empty() || sig_b64.is_empty() {
            return false;
        }
        let Some(header_bytes) = base64url_decode(header_b64) else {
            return false;
        };
        let Ok(header) = serde_json::from_slice::<JwtHeader>(&header_bytes) else {
            return false;
        };
        let Some(kid) = header.kid.as_deref().filter(|k| !k.is_empty()) else {
            return false;
        };
        if header.alg != "RS256" {
            return false;
        }
        let Some(signature) = base64url_decode(sig_b64) else {
            return false;
        };
        if signature.is_empty() {
            return false;
        }
        let Some(pem) = self.public_key_pem(kid) else {
            return false;
        };
        let signing_input = format!("{header_b64}.{payload_b64}");
        if !verify_rs256_pem(&pem, signing_input.as_bytes(), &signature) {
            return false;
        }
        let Some(payload_bytes) = base64url_decode(payload_b64) else {
            return false;
        };
        let Ok(claims) = serde_json::from_slice::<AccessClaims>(&payload_bytes) else {
            return false;
        };
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return false;
        };
        self.claims_valid(&claims, now.as_secs())
    }

    fn claims_valid(&self, claims: &AccessClaims, now_secs: u64) -> bool {
        if now_secs > claims.exp.saturating_add(JWT_CLOCK_SKEW_SECS) {
            return false;
        }
        if let Some(nbf) = claims.nbf
            && now_secs.saturating_add(JWT_CLOCK_SKEW_SECS) < nbf
        {
            return false;
        }
        if let Some(iss) = claims.iss.as_deref() {
            let expected_iss = format!("https://{}", self.config.team_domain);
            if iss != expected_iss {
                return false;
            }
        }
        let aud_matches = match &claims.aud {
            AudClaim::One(a) => a == &self.config.aud,
            AudClaim::Many(list) => list.iter().any(|a| a == &self.config.aud),
        };
        if !aud_matches {
            return false;
        }
        let Some(email) = claims.email.as_deref() else {
            return false;
        };
        self.config
            .allowed_emails
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(email))
    }

    fn public_key_pem(&self, kid: &str) -> Option<String> {
        let now = Instant::now();
        {
            let cache = self.cache.lock().ok()?;
            let fresh = cache
                .fetched_at
                .is_some_and(|t| now.saturating_duration_since(t) < JWKS_TTL);
            if fresh && let Some(pem) = cache.keys.get(kid) {
                return Some(pem.clone());
            }
            let cooled_down = cache
                .last_refresh_attempt
                .is_none_or(|t| now.saturating_duration_since(t) >= JWKS_REFRESH_COOLDOWN);
            if !cooled_down {
                return if fresh {
                    cache.keys.get(kid).cloned()
                } else {
                    None
                };
            }
        }
        {
            let mut cache = self.cache.lock().ok()?;
            cache.last_refresh_attempt = Some(Instant::now());
        }
        let raw = (self.fetcher)(&self.config.team_domain).ok()?;
        let parsed = parse_jwks(&raw)?;
        let mut cache = self.cache.lock().ok()?;
        cache.keys = parsed;
        cache.fetched_at = Some(Instant::now());
        cache.keys.get(kid).cloned()
    }
}

fn fetch_cf_jwks(team_domain: &str) -> io::Result<Vec<u8>> {
    let url = format!("https://{team_domain}/cdn-cgi/access/certs");
    let output = std::process::Command::new("curl")
        .args([
            "--proto",
            "=https",
            "--tlsv1.2",
            "--fail",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "3",
            "--max-time",
            "5",
            &url,
        ])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("jwks fetch failed"));
    }
    Ok(output.stdout)
}

fn parse_jwks(raw: &[u8]) -> Option<HashMap<String, String>> {
    let payload: JwksPayload = serde_json::from_slice(raw).ok()?;
    let mut keys = HashMap::new();
    for key in payload.keys {
        if key.kty != "RSA" {
            continue;
        }
        if key.alg.as_deref().is_some_and(|a| a != "RS256") {
            continue;
        }
        if key.use_.as_deref().is_some_and(|u| u != "sig") {
            continue;
        }
        let (Some(kid), Some(n), Some(e)) = (key.kid, key.n, key.e) else {
            continue;
        };
        if kid.is_empty() {
            continue;
        }
        if let Some(pem) = jwk_rsa_to_spki_pem(&n, &e) {
            keys.insert(kid, pem);
        }
    }
    Some(keys)
}

fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let stripped = input.trim_end_matches('=');
    if stripped.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(stripped.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;
    for b in stripped.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buf = (buf << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 && (buf & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        let slice = &bytes[first..];
        out.push(0x80 | (slice.len() as u8));
        out.extend_from_slice(slice);
    }
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    out.push(tag);
    der_len(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

fn der_integer(unsigned: &[u8]) -> Option<Vec<u8>> {
    let first = unsigned.iter().position(|&b| b != 0)?;
    let trimmed = &unsigned[first..];
    let mut body = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        body.push(0);
    }
    body.extend_from_slice(trimmed);
    Some(der_tlv(0x02, &body))
}

fn jwk_rsa_to_spki_pem(n_b64: &str, e_b64: &str) -> Option<String> {
    let n = base64url_decode(n_b64)?;
    let e = base64url_decode(e_b64)?;
    let n_first = n.iter().position(|&b| b != 0)?;
    let n_trimmed = &n[n_first..];
    if n_trimmed.len() < 256 {
        return None;
    }
    let e_first = e.iter().position(|&b| b != 0)?;
    let e_trimmed = &e[e_first..];
    if e_trimmed.last().copied().unwrap_or(0) & 1 == 0 {
        return None;
    }
    let mut rsa_pub = Vec::new();
    rsa_pub.extend_from_slice(&der_integer(n_trimmed)?);
    rsa_pub.extend_from_slice(&der_integer(e_trimmed)?);
    let rsa_seq = der_tlv(0x30, &rsa_pub);

    let mut bit_string = Vec::with_capacity(1 + rsa_seq.len());
    bit_string.push(0);
    bit_string.extend_from_slice(&rsa_seq);
    let spki_bit_string = der_tlv(0x03, &bit_string);

    // rsaEncryption OID (1.2.840.113549.1.1.1) + NULL
    const RSA_ALG_ID: &[u8] = &[
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let mut spki_body = Vec::with_capacity(RSA_ALG_ID.len() + spki_bit_string.len());
    spki_body.extend_from_slice(RSA_ALG_ID);
    spki_body.extend_from_slice(&spki_bit_string);
    let spki = der_tlv(0x30, &spki_body);

    let b64 = base64_encode(&spki);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).ok()?);
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    Some(pem)
}

struct TempGuard(PathBuf);
impl Drop for TempGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn write_temp_secret(prefix: &str, bytes: &[u8]) -> io::Result<TempGuard> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    for _ in 0..8 {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("zach-{prefix}-{pid}-{n}.tmp"));
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(bytes)?;
                return Ok(TempGuard(path));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "cannot allocate temp file",
    ))
}

fn verify_rs256_pem(pem: &str, signing_input: &[u8], signature: &[u8]) -> bool {
    let Ok(pem_file) = write_temp_secret("jwks-pem", pem.as_bytes()) else {
        return false;
    };
    let Ok(sig_file) = write_temp_secret("jwt-sig", signature) else {
        return false;
    };
    let Ok(mut child) = std::process::Command::new("openssl")
        .arg("dgst")
        .arg("-sha256")
        .arg("-verify")
        .arg(&pem_file.0)
        .arg("-signature")
        .arg(&sig_file.0)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take()
        && stdin.write_all(signing_input).is_err()
    {
        let _ = child.wait();
        return false;
    }
    child.wait().is_ok_and(|s| s.success())
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
    origin: Option<&str>,
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
        origin,
    )
}
fn serve(
    stream: &mut TcpStream,
    path: &Path,
    token: &str,
    stop: &AtomicBool,
    sse: &std::sync::atomic::AtomicUsize,
    policy: &Policy,
    cf_access: Option<&AccessJwtVerifier>,
) -> io::Result<()> {
    let req = match read_request(stream, stop) {
        Ok(r) => r,
        Err(_) => return error(stream, 400, "invalid request", stop, None),
    };
    let origin = req.headers.get("origin").map(String::as_str);
    if origin.is_some_and(|o| !policy.origin_allowed(o))
        || (req.method == "POST" && origin.is_none())
    {
        return error(stream, 403, "origin forbidden", stop, None);
    }
    if req.method == "OPTIONS" {
        return preflight(stream, &req, origin, stop);
    }
    let is_authorized = match (cf_access, req.headers.get("cf-access-jwt-assertion")) {
        (Some(verifier), Some(jwt)) => verifier.verify(jwt),
        _ => authorized(req.headers.get("authorization"), token),
    };
    if !is_authorized {
        return error(stream, 401, "unauthorized", stop, origin);
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
                Ok(data) => response(stream, 200, &data, stop, origin),
                Err(e) => backend_error(stream, e, false, stop, origin),
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
                _ => return error(stream, 400, "invalid decision request", stop, origin),
            };
            let deadline = Instant::now() + WAIT;
            let mut dispatched = false;
            let result = (|| {
                let mut backend = Backend::connect(path, stop, deadline)?;
                backend.send(
                    &ClientCommand::GetDecision {
                        decision_id: body.decision_id.clone(),
                    },
                    stop,
                    deadline,
                )?;
                let record = match backend.receive(stop, deadline)? {
                    Some(ServerMessage::Decision { decision: None }) => {
                        return Ok(("NOT_FOUND".into(), None));
                    }
                    Some(ServerMessage::Decision {
                        decision: Some(record),
                    }) if record.decision_id == body.decision_id
                        && matches!(record.status.as_str(), "OPEN" | "RESOLVED")
                        && !record.kind.is_empty() =>
                    {
                        record
                    }
                    _ => return Err(invalid("backend decision unavailable")),
                };
                if !policy.kind_allowed(&record.kind) {
                    return Ok(("FORBIDDEN".into(), None));
                }
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
                        origin,
                    )
                }
                Ok((outcome, _)) if outcome == "FORBIDDEN" => {
                    error(stream, 403, "decision kind forbidden", stop, origin)
                }
                Ok((outcome, _)) if outcome == "INVALID_REQUEST" => {
                    error(stream, 400, "invalid decision request", stop, origin)
                }
                Ok(_) => error(stream, 503, "backend decision unavailable", stop, origin),
                Err(e) => backend_error(stream, e, dispatched, stop, origin),
            }
        }
        ("GET", "/api/events") => {
            let since = match cursor(&req) {
                Ok(n) => n,
                Err(_) => return error(stream, 400, "invalid cursor", stop, origin),
            };
            let mut active = sse.load(Ordering::Acquire);
            loop {
                if active >= MAX_SSE {
                    return error(stream, 503, "event capacity reached", stop, origin);
                }
                match sse.compare_exchange_weak(
                    active,
                    active + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(current) => active = current,
                }
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
                Err(e) => return backend_error(stream, e, false, stop, origin),
            };
            // Wait for the first backend response before committing HTTP success.
            let mut next = match backend.receive(stop, deadline) {
                Ok(Some(m)) if !matches!(m, ServerMessage::Error { .. }) => Some(m),
                Ok(_) => return error(stream, 503, "backend unavailable", stop, origin),
                Err(e) => return backend_error(stream, e, false, stop, origin),
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache, no-transform\r\nConnection: close\r\n{}\r\n",
                cors_headers(origin)
            );
            write_bounded(stream, head.as_bytes(), stop, Instant::now() + WAIT)?;
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
        _ => error(stream, 404, "not found", stop, origin),
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
            Self::with_policy(vec![], vec![])
        }
        fn with_policy(allowed_origins: Vec<String>, allowed_decision_kinds: Vec<String>) -> Self {
            Self::with_cf_access(
                allowed_origins,
                allowed_decision_kinds,
                None,
                Arc::new(fetch_cf_jwks),
            )
        }
        fn with_cf_access(
            allowed_origins: Vec<String>,
            allowed_decision_kinds: Vec<String>,
            cf_access: Option<CfAccessConfig>,
            fetcher: JwksFetcher,
        ) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "zach-web-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let gateway = WebGateway::bind_with_jwks_fetcher(
                GatewayConfig {
                    bind_addr: "127.0.0.1:0".parse().unwrap(),
                    socket_path: dir.join("backend.sock"),
                    state_dir: dir.clone(),
                    allowed_origins,
                    allowed_decision_kinds,
                    cf_access,
                },
                fetcher,
            )
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
            let sock = self.dir.join("backend.sock");
            let _ = std::fs::remove_file(&sock);
            let listener = UnixListener::bind(sock).unwrap();
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
            let origin = if method == "POST" {
                format!("Origin: http://{}\r\n", self.addr)
            } else {
                String::new()
            };
            write!(stream, "{method} {target} HTTP/1.1\r\nHost: localhost\r\n{origin}{headers}Content-Length: {}\r\n\r\n{body}", body.len()).unwrap();
            stream
        }
        fn raw(&self, request: &[u8]) -> String {
            let mut stream = TcpStream::connect(self.addr).unwrap();
            stream.set_read_timeout(Some(WAIT + WAIT)).unwrap();
            let _ = stream.write_all(request);
            stream.shutdown(Shutdown::Write).unwrap();
            read_all(stream)
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
    fn raw_command(reader: &mut BufReader<UnixStream>) -> ClientCommand {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
    fn decision(id: &str, kind: &str, status: &str) -> PendingDecisionRecord {
        serde_json::from_value(serde_json::json!({
            "decision_id": id, "task_id":"SYNTHETIC", "task_group":"test", "kind":kind,
            "question":"choose", "options":["APPROVE","REJECT"], "recommended_option":0,
            "context_summary":"synthetic", "sha":null, "status":status, "created_seq":1,
            "resolved_by":null, "resolved_epoch":null, "choice":null, "note":null
        }))
        .unwrap()
    }
    // Existing ACK regression fixtures now answer the prerequisite authoritative lookup.
    fn command(reader: &mut BufReader<UnixStream>) -> ClientCommand {
        let command = raw_command(reader);
        if let ClientCommand::GetDecision { decision_id } = command {
            write_ndjson(
                reader.get_mut(),
                &ServerMessage::Decision {
                    decision: Some(decision(&decision_id, "plan_approval", "OPEN")),
                },
            )
            .unwrap();
            raw_command(reader)
        } else {
            command
        }
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
                assert!(reply.starts_with("HTTP/1.1 400"));
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
                allowed_origins: vec![],
                allowed_decision_kinds: vec![],
                state_dir: f.dir.clone(),
                cf_access: None,
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
    #[test]
    fn web_gateway_constant_time_auth_behavior_and_empty_file() {
        let token = "a".repeat(64);
        assert!(authorized(Some(&format!("Bearer {token}")), &token));
        for i in 0..64 {
            let mut wrong = token.as_bytes().to_vec();
            wrong[i] = b'b';
            assert!(!authorized(
                Some(&format!("Bearer {}", String::from_utf8(wrong).unwrap())),
                &token
            ));
        }
        for value in [
            "Bearer ".to_string(),
            format!("Basic {token}"),
            format!("Bearer  {token}"),
            format!("Bearer {}", "a".repeat(63)),
            format!("Bearer {}", "a".repeat(65)),
        ] {
            assert!(!authorized(Some(&value), &token));
        }
        assert!(!authorized(Some(&"Bearer ".into()), ""));
        assert!(!authorized(None, &token));
        let f = Fixture::new();
        fs::write(f.dir.join("web_session_token"), "").unwrap();
        assert!(
            WebGateway::bind(GatewayConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                socket_path: f.dir.join("absent"),
                state_dir: f.dir.clone(),
                allowed_origins: vec![],
                allowed_decision_kinds: vec![],
                cf_access: None,
            })
            .is_err()
        );
        assert_eq!(
            fs::metadata(f.dir.join("web_session_token")).unwrap().len(),
            0
        );
    }
    #[test]
    fn web_gateway_url_credentials_and_parser_rejections_never_contact_backend() {
        let f = Fixture::new();
        let listener = UnixListener::bind(f.dir.join("backend.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        for route in ["/api/snapshot", "/api/events", "/api/decide"] {
            for name in [
                "token",
                "ACCESS_TOKEN",
                "%73ession_token",
                "web_session_token",
                "Authorization",
                "bEaReR",
            ] {
                for auth in [String::new(), f.auth()] {
                    let reply =
                        read_all(f.request("GET", &format!("{route}?{name}=synthetic"), &auth, ""));
                    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
                    assert!(!reply.contains(&f.token));
                }
            }
            for headers in [
                format!("Cookie: token={}\r\n", f.token),
                format!("X-Auth-Token: {}\r\n", f.token),
            ] {
                assert!(
                    read_all(f.request("GET", route, &headers, "")).starts_with("HTTP/1.1 401")
                );
            }
        }
        for target in [
            "http://user:secret@localhost/api/events".into(),
            "//localhost/api/events".into(),
            "/api/events?x=%ff".into(),
            "/api/events?x=%0a".into(),
            "/api/%zz".into(),
            format!(
                "/api/events?{}",
                (0..33)
                    .map(|i| format!("q{i}=1"))
                    .collect::<Vec<_>>()
                    .join("&")
            ),
        ] {
            assert!(read_all(f.request("GET", &target, &f.auth(), "")).starts_with("HTTP/1.1 400"));
        }
        let origin = format!("http://{}", f.addr);
        let cases = [
            format!(
                "GET /api/events HTTP/1.1\r\n{}Authorization: Bearer synthetic\r\n\r\n",
                f.auth()
            ),
            format!("POST /api/decide HTTP/1.1\r\nOrigin: {origin}\r\nOrigin: {origin}\r\n\r\n"),
            format!("GET /{}", "x".repeat(REQUEST_LINE_LIMIT)),
            format!(
                "GET /api/events HTTP/1.1\r\n{}\r\n",
                (0..65).map(|i| format!("X-{i}: x\r\n")).collect::<String>()
            ),
            "POST /api/decide HTTP/1.1\r\nContent-Length: 16385\r\n\r\n".into(),
            "POST /api/decide HTTP/1.1\r\nContent-Length: 5\r\n\r\nx".into(),
            "GET /api/events HTTP/1.0\r\n\r\n".into(),
        ];
        for request in cases {
            assert!(f.raw(request.as_bytes()).starts_with("HTTP/1.1 400"));
        }
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn web_gateway_exact_origin_and_preflight() {
        let f = Fixture::with_policy(
            vec!["https://zach.shocker.cl".into(), "http://[::1]:8080".into()],
            vec![],
        );
        let listener = UnixListener::bind(f.dir.join("backend.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        for origin in [
            "null",
            "*",
            "https://zach.shocker.cl.evil",
            "http://zach.shocker.cl",
            "https://zach.shocker.cl:444",
            "https://zach.shocker.cl/",
            "https://user@zach.shocker.cl",
            "https://zach.shocker.cl?x=1",
            "http://localhost:1234",
            "\u{a0}https://zach.shocker.cl",
            "https://zach.shocker.cl\u{a0}",
        ] {
            for method in ["GET", "POST", "OPTIONS"] {
                let reply = f.raw(
                    format!(
                        "{method} /api/decide HTTP/1.1\r\nOrigin: {origin}\r\n{}\r\n",
                        f.auth()
                    )
                    .as_bytes(),
                );
                assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
                assert!(!reply.contains("Access-Control-Allow-Origin"));
            }
        }
        assert!(
            f.raw(format!("POST /api/decide HTTP/1.1\r\n{}\r\n", f.auth()).as_bytes())
                .starts_with("HTTP/1.1 403")
        );
        for origin in [
            format!("http://{}", f.addr),
            "https://zach.shocker.cl".into(),
            "http://[::1]:8080".into(),
        ] {
            let reply = read_all(f.request("GET", "/api/session", &format!("Origin: {origin}\r\n{}Host-Other: evil\r\nForwarded: host=evil\r\nX-Forwarded-Host: evil\r\n", f.auth()), ""));
            assert!(reply.starts_with("HTTP/1.1 404"));
            assert!(reply.contains(&format!("Access-Control-Allow-Origin: {origin}\r\n")));
            assert!(reply.contains("Vary: Origin"));
            assert!(
                read_all(f.request("GET", "/api/session", &format!("Origin: {origin}\r\n"), ""))
                    .starts_with("HTTP/1.1 401")
            );
            for (route, method) in [
                ("/api/snapshot", "GET"),
                ("/api/events", "GET"),
                ("/api/decide", "POST"),
            ] {
                let reply = read_all(f.request("OPTIONS", route, &format!("Origin: {origin}\r\nAccess-Control-Request-Method: {method}\r\nAccess-Control-Request-Headers: AUTHORIZATION, Content-Type, Last-Event-ID\r\n"), ""));
                assert!(reply.starts_with("HTTP/1.1 204"), "{reply}");
                assert!(reply.contains(&format!("Access-Control-Allow-Origin: {origin}\r\n")));
                assert!(!reply.contains("Allow-Credentials"));
                assert!(!reply.contains('*'));
            }
        }
        for (route, method, headers, body) in [
            ("/api/decide", "GET", "authorization", ""),
            ("/api/session", "GET", "authorization", ""),
            ("/api/events", "GET", "cookie", ""),
            ("/api/events", "GET", "authorization, Authorization", ""),
            ("/api/events", "GET", "", "body"),
        ] {
            assert!(read_all(f.request("OPTIONS", route, &format!("Origin: https://zach.shocker.cl\r\nAccess-Control-Request-Method: {method}\r\nAccess-Control-Request-Headers: {headers}\r\n"), body)).starts_with("HTTP/1.1 403"));
        }
        assert!(
            read_all(f.request(
                "OPTIONS",
                "/api/events",
                "Access-Control-Request-Method: GET\r\n",
                ""
            ))
            .starts_with("HTTP/1.1 403")
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn web_gateway_policy_configuration_is_bounded() {
        for origin in [
            "",
            "null",
            "*",
            "ftp://a",
            "https://a/",
            "https://a?b",
            "https://a#b",
            "https://a@b",
            "https://a:0",
            "https://a:65536",
            "https://a:",
            "https://a:1:2",
            "http://[::1",
            "http://[invalid]",
            "https://-bad",
            "https://a..b",
            "https://a b",
            "https://a\r\nx:y",
            "https://a\\b",
        ] {
            assert!(
                validate_web_policy(&[origin.into()], &[]).is_err(),
                "{origin}"
            );
        }
        for origins in [
            vec!["https://a".into(); 2],
            (0..17).map(|i| format!("https://a{i}")).collect(),
            vec![format!("https://{}", "a".repeat(513))],
        ] {
            assert!(validate_web_policy(&origins, &[]).is_err());
        }
        for kinds in [
            vec!["".into()],
            vec!["UPPER".into()],
            vec!["bad kind".into()],
            vec!["a".repeat(65)],
            vec!["a".into(); 2],
            (0..33).map(|i| format!("kind{i}")).collect(),
        ] {
            assert!(validate_web_policy(&[], &kinds).is_err());
        }
        let f = Fixture::new();
        assert!(
            WebGateway::bind(GatewayConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                socket_path: f.dir.join("absent"),
                state_dir: f.dir.clone(),
                allowed_origins: vec!["*".into()],
                allowed_decision_kinds: vec![],
                cf_access: None,
            })
            .is_err()
        );
    }

    #[test]
    fn web_gateway_authoritative_kind_policy_and_exact_opt_in() {
        let mut cases: Vec<(&str, Vec<String>, &str, &str, u16)> = Vec::new();
        for status in ["OPEN", "RESOLVED"] {
            for kind in ["merge_approval", "human-merge-approval"] {
                cases.push((kind, vec![], "innocent", status, 403));
                cases.push((kind, vec![kind.into()], "innocent", status, 200));
                let other = if kind == "merge_approval" {
                    "human-merge-approval"
                } else {
                    "merge_approval"
                };
                cases.push((kind, vec![other.into()], "innocent", status, 403));
            }
        }
        for kind in DEFAULT_DECISION_KINDS {
            cases.push((
                kind,
                vec![],
                "human-merge-approval:looks-like-merge",
                "OPEN",
                200,
            ));
        }
        cases.extend([
            ("future_kind", vec![], "innocent", "OPEN", 403),
            (
                "future_kind",
                vec!["future_kind".into()],
                "innocent",
                "OPEN",
                200,
            ),
            ("", vec![], "innocent", "OPEN", 503),
            ("plan_approval", vec![], "innocent", "UNKNOWN", 503),
        ]);
        for (kind, kinds, id, status, code) in cases {
            let f = Fixture::with_policy(vec![], kinds);
            let record = decision(id, kind, status);
            let resolved = status == "RESOLVED";
            let id = id.to_string();
            let expected_id = id.clone();
            let backend = f.backend(move |stream| {
                let mut reader = BufReader::new(stream);
                assert_eq!(raw_command(&mut reader), ClientCommand::GetDecision { decision_id: expected_id.clone() });
                write_ndjson(reader.get_mut(), &ServerMessage::Decision { decision: Some(record.clone()) }).unwrap();
                if code == 200 {
                    assert!(matches!(raw_command(&mut reader), ClientCommand::Decide { decision_id, .. } if decision_id == expected_id));
                    // A concurrent resolver's winning choice must survive unchanged.
                    let mut winner = record; winner.status = "RESOLVED".into(); winner.choice = Some("REJECT".into());
                    write_ndjson(reader.get_mut(), &ServerMessage::DecisionResult { outcome: if resolved { "ALREADY_RESOLVED" } else { "RESOLVED" }.into(), decision: Some(winner) }).unwrap();
                }
                let mut rest = String::new(); reader.read_to_string(&mut rest).unwrap(); assert!(rest.is_empty(), "no mutation after denial or retry after ACK");
            });
            let reply = read_all(f.request(
                "POST",
                "/api/decide",
                &f.auth(),
                &serde_json::json!({"decision_id":id,"choice":"APPROVE"}).to_string(),
            ));
            assert!(
                reply.starts_with(&format!("HTTP/1.1 {code}")),
                "kind={kind}: {reply}"
            );
            if code == 200 {
                assert!(reply.contains("REJECT"));
                assert!(reply.contains(if resolved {
                    "ALREADY_RESOLVED"
                } else {
                    "RESOLVED"
                }));
            }
            backend.join().unwrap();
        }
    }
    #[test]
    fn web_gateway_lookup_missing_mismatched_malformed_and_timeout_are_not_dispatched() {
        for case in [
            "missing",
            "mismatched",
            "wrong_type",
            "malformed",
            "timeout",
        ] {
            let f = Fixture::new();
            let backend = f.backend(move |stream| {
                let mut reader = BufReader::new(stream);
                assert_eq!(
                    raw_command(&mut reader),
                    ClientCommand::GetDecision {
                        decision_id: "synthetic".into()
                    }
                );
                match case {
                    "missing" => write_ndjson(
                        reader.get_mut(),
                        &ServerMessage::Decision { decision: None },
                    )
                    .unwrap(),
                    "mismatched" => write_ndjson(
                        reader.get_mut(),
                        &ServerMessage::Decision {
                            decision: Some(decision("other", "plan_approval", "OPEN")),
                        },
                    )
                    .unwrap(),
                    "wrong_type" => write_ndjson(reader.get_mut(), &snapshot()).unwrap(),
                    "malformed" => reader.get_mut().write_all(b"{bad}\n").unwrap(),
                    _ => (),
                }
                let mut rest = String::new();
                let _ = reader.read_to_string(&mut rest);
                assert!(rest.is_empty());
            });
            let reply = read_all(f.request(
                "POST",
                "/api/decide",
                &f.auth(),
                r#"{"decision_id":"synthetic","choice":"APPROVE"}"#,
            ));
            let code = match case {
                "missing" => 404,
                "timeout" => 504,
                _ => 503,
            };
            assert!(
                reply.starts_with(&format!("HTTP/1.1 {code}")),
                "{case}: {reply}"
            );
            assert!(!reply.contains("outcome unknown"));
            backend.join().unwrap();
        }
    }
    #[test]
    fn web_gateway_sse_uses_validated_cors() {
        let f = Fixture::new();
        let backend = f.backend(|stream| {
            let mut reader = BufReader::new(stream);
            assert!(matches!(
                raw_command(&mut reader),
                ClientCommand::Subscribe { .. }
            ));
            write_ndjson(reader.get_mut(), &snapshot()).unwrap();
        });
        let reply = read_all(f.request(
            "GET",
            "/api/events",
            &format!("{}Origin: http://{}\r\n", f.auth(), f.addr),
            "",
        ));
        assert!(reply.starts_with("HTTP/1.1 200"));
        assert!(reply.contains(&format!(
            "Access-Control-Allow-Origin: http://{}\r\n",
            f.addr
        )));
        assert!(reply.contains("event: snapshot"));
        backend.join().unwrap();
    }

    fn base64url_encode(bytes: &[u8]) -> String {
        base64_encode(bytes)
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=')
            .to_string()
    }

    fn generate_test_rsa_keypair(dir: &Path) -> (PathBuf, String, String) {
        let priv_path = dir.join("test-cf-priv.pem");
        let status = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&priv_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "openssl genpkey failed");

        let mod_out = std::process::Command::new("openssl")
            .args(["rsa", "-in"])
            .arg(&priv_path)
            .args(["-modulus", "-noout"])
            .output()
            .unwrap();
        assert!(mod_out.status.success(), "openssl rsa -modulus failed");
        let mod_str = String::from_utf8(mod_out.stdout).unwrap();
        let hex_n = mod_str.trim().strip_prefix("Modulus=").unwrap();
        let n_bytes: Vec<u8> = (0..hex_n.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_n[i..i + 2], 16).unwrap())
            .collect();
        let n_b64 = base64url_encode(&n_bytes);
        let e_b64 = base64url_encode(&[0x01, 0x00, 0x01]);
        (priv_path, n_b64, e_b64)
    }

    fn sign_test_jwt(
        priv_path: &Path,
        header: &serde_json::Value,
        claims: &serde_json::Value,
    ) -> String {
        let header_b64 = base64url_encode(&serde_json::to_vec(header).unwrap());
        let claims_b64 = base64url_encode(&serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{header_b64}.{claims_b64}");
        let mut child = std::process::Command::new("openssl")
            .args(["dgst", "-sha256", "-sign"])
            .arg(priv_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(signing_input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "openssl dgst -sign failed");
        let sig_b64 = base64url_encode(&output.stdout);
        format!("{signing_input}.{sig_b64}")
    }

    #[test]
    fn web_gateway_cf_access_jwt_verification_and_bearer_fallback() {
        let key_dir = std::env::temp_dir().join(format!("zach-cf-key-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&key_dir);
        let (priv_path, n_b64, e_b64) = generate_test_rsa_keypair(&key_dir);
        let jwks_json = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": "cf-key-1",
                "alg": "RS256",
                "use": "sig",
                "n": n_b64,
                "e": e_b64,
            }]
        })
        .to_string()
        .into_bytes();

        let fetches = Arc::new(AtomicUsize::new(0));
        let fetches_clone = fetches.clone();
        let fetcher: JwksFetcher = Arc::new(move |domain| {
            assert_eq!(domain, "team.cloudflareaccess.com");
            fetches_clone.fetch_add(1, Ordering::Relaxed);
            Ok(jwks_json.clone())
        });

        let cf_cfg = normalize_cf_access_config(
            "team.cloudflareaccess.com",
            "expected-aud-tag",
            &["Operator@Example.com".into()],
        )
        .unwrap();
        let f = Fixture::with_cf_access(vec![], vec![], Some(cf_cfg), fetcher);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let header = serde_json::json!({ "alg": "RS256", "kid": "cf-key-1", "typ": "JWT" });

        // 1. Valid JWT (with aud array and uppercase email) -> 200, JWKS cached
        let valid_jwt = sign_test_jwt(
            &priv_path,
            &header,
            &serde_json::json!({
                "aud": ["expected-aud-tag"],
                "email": "operator@example.com",
                "iss": "https://team.cloudflareaccess.com",
                "iat": now - 10,
                "nbf": now - 10,
                "exp": now + 300,
            }),
        );
        let backend = f.backend(|stream| {
            let mut reader = BufReader::new(stream);
            let _ = raw_command(&mut reader);
            let _ = raw_command(&mut reader);
            write_ndjson(reader.get_mut(), &snapshot()).unwrap();
            let status: DaemonStatusSummary = serde_json::from_value(serde_json::json!({"schema_version":4,"max_parallel_tasks":2,"heartbeat_epoch":1,"max_seq_id":9001,"total_tasks":0,"ready_eligible_count":0,"in_progress_count":0,"open_decisions_count":0,"active_locks_count":0,"merge_queue_count":0})).unwrap();
            write_ndjson(reader.get_mut(), &ServerMessage::Status { ok: true, status }).unwrap();
        });
        let reply = read_all(f.request(
            "GET",
            "/api/snapshot",
            &format!("Cf-Access-Jwt-Assertion: {valid_jwt}\r\n"),
            "",
        ));
        assert!(reply.starts_with("HTTP/1.1 200"), "valid jwt: {reply}");
        backend.join().unwrap();
        assert_eq!(fetches.load(Ordering::Relaxed), 1);

        // 2. Wrong aud -> 401
        let wrong_aud = sign_test_jwt(
            &priv_path,
            &header,
            &serde_json::json!({
                "aud": "other-aud",
                "email": "operator@example.com",
                "iss": "https://team.cloudflareaccess.com",
                "exp": now + 300,
            }),
        );
        let reply = read_all(f.request(
            "GET",
            "/api/snapshot",
            &format!("Cf-Access-Jwt-Assertion: {wrong_aud}\r\n"),
            "",
        ));
        assert!(reply.starts_with("HTTP/1.1 401"), "wrong aud: {reply}");

        // 3. Wrong email -> 401
        let wrong_email = sign_test_jwt(
            &priv_path,
            &header,
            &serde_json::json!({
                "aud": "expected-aud-tag",
                "email": "intruder@example.com",
                "iss": "https://team.cloudflareaccess.com",
                "exp": now + 300,
            }),
        );
        let reply = read_all(f.request(
            "GET",
            "/api/snapshot",
            &format!("Cf-Access-Jwt-Assertion: {wrong_email}\r\n"),
            "",
        ));
        assert!(reply.starts_with("HTTP/1.1 401"), "wrong email: {reply}");

        // 4. Expired JWT -> 401
        let expired_jwt = sign_test_jwt(
            &priv_path,
            &header,
            &serde_json::json!({
                "aud": "expected-aud-tag",
                "email": "operator@example.com",
                "iss": "https://team.cloudflareaccess.com",
                "exp": now - 120,
            }),
        );
        let reply = read_all(f.request(
            "GET",
            "/api/snapshot",
            &format!("Cf-Access-Jwt-Assertion: {expired_jwt}\r\n"),
            "",
        ));
        assert!(reply.starts_with("HTTP/1.1 401"), "expired jwt: {reply}");

        // 5. Invalid signature (tampered payload) -> 401
        let mut parts: Vec<&str> = valid_jwt.split('.').collect();
        let tampered_claims = base64url_encode(
            &serde_json::to_vec(&serde_json::json!({
                "aud": "expected-aud-tag",
                "email": "operator@example.com",
                "exp": now + 999,
            }))
            .unwrap(),
        );
        parts[1] = &tampered_claims;
        let tampered_jwt = parts.join(".");
        let reply = read_all(f.request(
            "GET",
            "/api/snapshot",
            &format!("Cf-Access-Jwt-Assertion: {tampered_jwt}\r\n"),
            "",
        ));
        assert!(reply.starts_with("HTTP/1.1 401"), "tampered jwt: {reply}");

        // 6. Invalid JWT + valid Bearer -> 401 (no Bearer fallback when Access JWT is presented)
        let reply = read_all(f.request(
            "GET",
            "/api/snapshot",
            &format!("{}Cf-Access-Jwt-Assertion: {tampered_jwt}\r\n", f.auth()),
            "",
        ));
        assert!(
            reply.starts_with("HTTP/1.1 401"),
            "invalid jwt must not fall back to bearer: {reply}"
        );

        // 7. Missing Access JWT + valid Bearer -> 200 (loopback CLI/healthcheck fallback)
        let backend = f.backend(|stream| {
            let mut reader = BufReader::new(stream);
            let _ = raw_command(&mut reader);
            let _ = raw_command(&mut reader);
            write_ndjson(reader.get_mut(), &snapshot()).unwrap();
            let status: DaemonStatusSummary = serde_json::from_value(serde_json::json!({"schema_version":4,"max_parallel_tasks":2,"heartbeat_epoch":1,"max_seq_id":9001,"total_tasks":0,"ready_eligible_count":0,"in_progress_count":0,"open_decisions_count":0,"active_locks_count":0,"merge_queue_count":0})).unwrap();
            write_ndjson(reader.get_mut(), &ServerMessage::Status { ok: true, status }).unwrap();
        });
        let reply = read_all(f.request("GET", "/api/snapshot", &f.auth(), ""));
        assert!(
            reply.starts_with("HTTP/1.1 200"),
            "bearer fallback: {reply}"
        );
        backend.join().unwrap();

        // JWKS stayed cached across all checks with the same kid
        assert_eq!(fetches.load(Ordering::Relaxed), 1);
        let _ = std::fs::remove_dir_all(&key_dir);
    }

    #[test]
    fn cf_access_config_validation_rejects_invalid_inputs() {
        assert!(normalize_cf_access_config("", "aud", &["a@b.com".into()]).is_err());
        assert!(
            normalize_cf_access_config(
                "https://team.cloudflareaccess.com",
                "aud",
                &["a@b.com".into()]
            )
            .is_err()
        );
        assert!(
            normalize_cf_access_config("team.cloudflareaccess.com", "", &["a@b.com".into()])
                .is_err()
        );
        assert!(normalize_cf_access_config("team.cloudflareaccess.com", "aud", &[]).is_err());
        assert!(
            normalize_cf_access_config(
                "team.cloudflareaccess.com",
                "aud",
                &["not-an-email".into()]
            )
            .is_err()
        );
        assert!(
            normalize_cf_access_config(
                "team.cloudflareaccess.com",
                "aud",
                &["op@example.com".into(), "OP@example.com".into()]
            )
            .is_err()
        );
    }
}
