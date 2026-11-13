//! Worker containment. systemd owns resource limits; bubblewrap owns namespaces.
//! Preparation and proxy lifetimes are explicit and separate from argv construction.
use crate::v2::router::ModelFamily;
use crate::v2::runner::{ensure_secure_dir, write_secure_file};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;
use std::time::Duration;

const BRIDGE: &str = "/run/zach-bridge/bridge";
const SOCKET: &str = "/run/zach-net/proxy.sock";
const MAX_TUNNELS: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum NetworkPolicy {
    #[default]
    None,
    ProviderApi(ModelFamily),
}

impl NetworkPolicy {
    pub fn resolve(raw: Option<&str>, family: ModelFamily) -> Result<Self, String> {
        match raw {
            None | Some("provider-api") => Ok(Self::ProviderApi(family)),
            Some("none") => Ok(Self::None),
            _ => Err("invalid context_pack.network: expected none or provider-api".into()),
        }
    }
}

/// All discovered filesystem facts are supplied to the pure argv builder.
#[derive(Debug, Clone)]
pub struct SandboxLayout {
    pub home: PathBuf,
    pub worktree: PathBuf,
    pub writable: bool,
    pub toolchains: Vec<PathBuf>,
    pub git_paths: Vec<PathBuf>,
    pub secrets: Vec<PathBuf>,
    pub readonly_files: Vec<PathBuf>,
    pub auth: Option<(PathBuf, PathBuf)>,
    pub plugin: Option<PathBuf>,
    pub proxy: Option<(PathBuf, PathBuf)>,
}

impl SandboxLayout {
    pub fn declared(home: &Path, worktree: &Path, writable: bool) -> Self {
        Self {
            home: home.into(),
            worktree: worktree.into(),
            writable,
            toolchains: vec![],
            git_paths: vec![worktree.join(".git")],
            secrets: vec![],
            readonly_files: vec![],
            auth: None,
            plugin: None,
            proxy: None,
        }
    }

    pub fn inspect(home: &Path, worktree: &Path, writable: bool) -> Result<Self, String> {
        let worktree = fs::canonicalize(worktree).map_err(|e| e.to_string())?;
        if worktree == Path::new("/") || worktree == home || !worktree.is_dir() {
            return Err("invalid isolation worktree".into());
        }
        let mut layout = Self::declared(home, &worktree, writable);
        layout.git_paths = git_mounts(&worktree)?;
        if layout
            .git_paths
            .iter()
            .any(|path| home.starts_with(path) || worktree.starts_with(path))
        {
            return Err("Git mount would expose an ancestor directory".into());
        }
        scan_secrets(&worktree, &mut layout.secrets)?;
        for suffix in [
            ".local/bin",
            ".local/share/fnm",
            ".codex/packages",
            ".cargo",
            ".rustup",
        ] {
            let path = home.join(suffix);
            if path.exists() {
                layout.toolchains.push(path);
            }
        }
        Ok(layout)
    }
}

/// Never follows directory links. Even template-named symlinks fail closed.
pub fn scan_secrets(dir: &Path, secrets: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if name.starts_with(".env") {
            if meta.file_type().is_symlink() {
                return Err(format!("secret symlink: {}", path.display()));
            }
            if meta.is_file()
                && ![
                    ".env.example",
                    ".env.sample",
                    ".env.template",
                    ".env.dist",
                    ".env.schema",
                ]
                .contains(&name.as_ref())
            {
                secrets.push(path.clone());
            }
        }
        if meta.is_dir() && name != ".git" {
            scan_secrets(&path, secrets)?;
        }
    }
    secrets.sort();
    Ok(())
}

pub fn git_mounts(worktree: &Path) -> Result<Vec<PathBuf>, String> {
    let dotgit = worktree.join(".git");
    let meta = fs::symlink_metadata(&dotgit).map_err(|e| format!("missing .git: {e}"))?;
    if meta.file_type().is_symlink() {
        return Err(".git symlink rejected".into());
    }
    let mut paths = vec![dotgit.clone()];
    if meta.is_file() {
        let text = fs::read_to_string(&dotgit).map_err(|e| e.to_string())?;
        let target = text
            .trim()
            .strip_prefix("gitdir:")
            .ok_or("invalid .git pointer")?
            .trim();
        let gitdir = fs::canonicalize(worktree.join(target)).map_err(|e| e.to_string())?;
        // Linked worktrees reference the common repository through commondir.
        let common_file = gitdir.join("commondir");
        if fs::symlink_metadata(&common_file).is_ok_and(|meta| meta.file_type().is_symlink()) {
            return Err("Git common directory pointer is a symlink".into());
        }
        let common = match fs::read_to_string(common_file) {
            Ok(common) => {
                fs::canonicalize(gitdir.join(common.trim())).map_err(|e| e.to_string())?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => gitdir.clone(),
            Err(e) => return Err(e.to_string()),
        };
        // A pointer must resolve to Git metadata, not an arbitrary credential
        // directory that would otherwise be reintroduced under the masked home.
        for file in [gitdir.join("HEAD"), common.join("config")] {
            let meta = fs::symlink_metadata(file).map_err(|e| e.to_string())?;
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Err("invalid Git metadata file".into());
            }
        }
        let objects = fs::symlink_metadata(common.join("objects")).map_err(|e| e.to_string())?;
        if !objects.is_dir() || objects.file_type().is_symlink() {
            return Err("invalid Git object directory".into());
        }
        paths.push(common);
        paths.push(gitdir);
    } else if !meta.is_dir() {
        return Err("invalid .git type".into());
    }
    // Parent mounts must precede nested mounts.
    paths.sort_by_key(|p| p.components().count());
    paths.dedup();
    Ok(paths)
}

pub fn sandbox_env(home: &Path) -> BTreeMap<String, String> {
    let home = home.display();
    BTreeMap::from([
        ("HOME".into(), format!("{home}")),
        (
            "PATH".into(),
            format!(
                "{home}/.local/bin:{home}/.local/share/fnm/aliases/default/bin:{home}/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
            ),
        ),
        ("LANG".into(), "C.UTF-8".into()),
        ("XDG_RUNTIME_DIR".into(), "/tmp/xdg-runtime".into()),
        ("CODEX_HOME".into(), format!("{home}/.codex")),
        (
            "GEMINI_WORKER_METRICS".into(),
            "/tmp/gemini-worker-metrics.jsonl".into(),
        ),
        ("NO_PROXY".into(), "localhost,127.0.0.1,::1".into()),
    ])
}

/// Pure: no filesystem access, credential staging, listeners or subprocesses.
pub fn bwrap_args(layout: &SandboxLayout, worker: &[String]) -> Vec<String> {
    let mut args: Vec<String> = [
        "/usr/bin/bwrap",
        "--unshare-all",
        "--new-session",
        "--die-with-parent",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/var/tmp",
        "--tmpfs",
        "/home",
        "--tmpfs",
        "/root",
        "--dir",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    args.push(layout.home.display().to_string());
    args.extend([
        "--tmpfs".into(),
        layout.home.join("workspace").display().to_string(),
        "--dir".into(),
        "/tmp/xdg-runtime".into(),
        "--chmod".into(),
        "0700".into(),
        "/tmp/xdg-runtime".into(),
        "--clearenv".into(),
    ]);
    for (key, value) in sandbox_env(&layout.home) {
        args.extend(["--setenv".into(), key, value]);
    }
    let mut bind = |flag: &str, src: &Path, dst: &Path| {
        args.extend([
            flag.into(),
            src.display().to_string(),
            dst.display().to_string(),
        ]);
    };
    if let Some((src, dst)) = &layout.auth {
        bind("--bind", src, dst);
    }
    for path in &layout.toolchains {
        bind("--ro-bind", path, path);
    }
    if let Some(path) = &layout.plugin {
        bind("--ro-bind", path, path);
    }
    bind(
        if layout.writable {
            "--bind"
        } else {
            "--ro-bind"
        },
        &layout.worktree,
        &layout.worktree,
    );
    for path in &layout.git_paths {
        bind("--ro-bind", path, path);
    }
    for path in &layout.secrets {
        bind("--ro-bind", Path::new("/dev/null"), path);
    }
    for path in &layout.readonly_files {
        bind("--ro-bind", path, path);
    }
    if let Some((net, exe)) = &layout.proxy {
        bind("--ro-bind", net, Path::new("/run/zach-net"));
        bind("--ro-bind", exe, Path::new(BRIDGE));
    }
    args.extend([
        "--chdir".into(),
        layout.worktree.display().to_string(),
        "--".into(),
    ]);
    if layout.proxy.is_some() {
        args.extend([
            BRIDGE.into(),
            "__sandbox-bridge".into(),
            "--unix-sock".into(),
            SOCKET.into(),
            "--".into(),
        ]);
    }
    args.extend_from_slice(worker);
    args
}

/// Owns only ephemeral auth and proxy resources; attempt artifacts survive drop.
#[derive(Debug)]
pub struct PreparedResources {
    pub layout: SandboxLayout,
    proxy: Option<ProxyHandle>,
    cleanup_dirs: Vec<PathBuf>,
}

impl PreparedResources {
    pub fn prepare(
        attempt: &Path,
        home: &Path,
        worktree: &Path,
        writable: bool,
        family: Option<ModelFamily>,
        network: NetworkPolicy,
    ) -> Result<Self, String> {
        let mut prepared = Self {
            layout: SandboxLayout::inspect(home, worktree, writable)?,
            proxy: None,
            cleanup_dirs: vec![],
        };
        if let Some(family) = family {
            let (name, destination, files): (&str, &str, &[&str]) = match family {
                ModelFamily::OpenAiSol => ("codex-home", ".codex", &["auth.json"]),
                ModelFamily::GeminiAgy => (
                    "gemini-home",
                    ".gemini",
                    &[
                        "antigravity-cli/antigravity-oauth-token",
                        "jetski-standalone-oauth-token",
                        "antigravity-cli/installation_id",
                        "settings.json",
                        "antigravity-cli/settings.json",
                    ],
                ),
            };
            let staged = attempt.join(name);
            // Never reuse auth from a previous attempt.
            if staged.try_exists().map_err(|e| e.to_string())? {
                return Err("staged auth already exists".into());
            }
            ensure_secure_dir(&staged)?;
            prepared.cleanup_dirs.push(staged.clone());
            for file in files {
                let source = home.join(destination).join(file);
                match fs::symlink_metadata(&source) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e.to_string()),
                    Ok(_) => {}
                }
                reject_symlink_components(&source)?;
                let mut input = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(&source)
                    .map_err(|e| e.to_string())?;
                if !input.metadata().map_err(|e| e.to_string())?.is_file() {
                    return Err("auth source is not a regular file".into());
                }
                let mut bytes = Vec::new();
                input.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
                let target = staged.join(file);
                secure_parents(target.parent().ok_or("auth parent missing")?)?;
                write_secure_file(&target, &bytes)?;
            }
            prepared.layout.auth = Some((staged, home.join(destination)));
            if family == ModelFamily::GeminiAgy {
                let script = Path::new(crate::v2::runner::GEMINI_WORKER_CLI_SCRIPT);
                let plugin = script
                    .parent()
                    .and_then(Path::parent)
                    .ok_or("invalid worker plugin path")?;
                prepared.layout.plugin = Some(fs::canonicalize(plugin).map_err(|e| e.to_string())?);
            }
        }
        if let NetworkPolicy::ProviderApi(family) = network {
            let net = attempt.join("net");
            ensure_secure_dir(&net)?;
            prepared.cleanup_dirs.push(net.clone());
            let proxy = ProxyHandle::start(&net, family)?;
            prepared.layout.proxy =
                Some((net, std::env::current_exe().map_err(|e| e.to_string())?));
            prepared.proxy = Some(proxy);
        }
        Ok(prepared)
    }
}

impl Drop for PreparedResources {
    fn drop(&mut self) {
        self.proxy.take();
        for path in &self.cleanup_dirs {
            let _ = fs::remove_dir_all(path);
        }
    }
}

pub fn reject_symlink_components(path: &Path) -> Result<(), String> {
    let mut prefix = PathBuf::new();
    for part in path.components() {
        if matches!(part, std::path::Component::ParentDir) {
            return Err("parent traversal rejected".into());
        }
        prefix.push(part);
        if fs::symlink_metadata(&prefix)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err(format!("symlink rejected: {}", prefix.display()));
        }
    }
    Ok(())
}

pub fn secure_parents(path: &Path) -> Result<(), String> {
    if path.is_dir() {
        return reject_symlink_components(path);
    }
    secure_parents(path.parent().ok_or("missing parent")?)?;
    ensure_secure_dir(path)?;
    Ok(())
}

fn allowed_hosts(family: ModelFamily) -> &'static [&'static str] {
    match family {
        ModelFamily::OpenAiSol => &[
            "api.openai.com",
            "chatgpt.com",
            "auth.openai.com",
            "auth.api.openai.org",
        ],
        ModelFamily::GeminiAgy => &[
            "daily-cloudcode-pa.googleapis.com",
            "cloudcode-pa.googleapis.com",
            "aicode.googleapis.com",
            "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com",
            "oauth2.googleapis.com",
            "accounts.google.com",
            "play.googleapis.com",
        ],
    }
}

/// HTTP CONNECT authority parsing never accepts IPs, userinfo or URL syntax.
pub fn parse_connect(header: &[u8], family: ModelFamily) -> Result<String, u16> {
    if header.len() > 8192 {
        return Err(400);
    }
    let text = std::str::from_utf8(header).map_err(|_| 400u16)?;
    if !text.ends_with("\r\n\r\n") {
        return Err(400);
    }
    let mut words = text.lines().next().ok_or(400u16)?.split_whitespace();
    let method = words.next().ok_or(400u16)?;
    let authority = words.next().ok_or(400u16)?;
    let version = words.next().ok_or(400u16)?;
    if words.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(400);
    }
    if method != "CONNECT" {
        return Err(403);
    }
    let host = authority
        .strip_suffix(":443")
        .ok_or(403u16)?
        .to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok() || !allowed_hosts(family).contains(&host.as_str()) {
        return Err(403);
    }
    Ok(host)
}

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || b == 0 || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return public_ip(IpAddr::V4(v4));
            }
            let segments = ip.segments();
            // Only global unicast; exclude documentation, Teredo, 6to4 and benchmarking.
            (segments[0] & 0xe000) == 0x2000
                && !(segments[0] == 0x2001 && (segments[1] <= 0x1ff || segments[1] == 0xdb8))
                && segments[0] != 0x2002
                && !(segments[0] == 0x3fff && segments[1] < 0x1000)
        }
    }
}

pub fn validate_addresses(addresses: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, String> {
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|a| a.port() != 443 || !public_ip(a.ip()))
    {
        return Err("unsafe DNS response".into());
    }
    Ok(addresses)
}

// std's resolver has no cancellation API. Bound outstanding resolver threads
// globally and bound each caller's wait; a stuck resolver retains its slot.
fn resolve_public_host(host: &str) -> Result<Vec<SocketAddr>, String> {
    static RESOLVERS: AtomicUsize = AtomicUsize::new(0);
    let mut count = RESOLVERS.load(Ordering::Acquire);
    loop {
        if count >= MAX_TUNNELS {
            return Err("resolver capacity reached".into());
        }
        match RESOLVERS.compare_exchange_weak(count, count + 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => break,
            Err(current) => count = current,
        }
    }
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let host = host.to_owned();
    thread::spawn(move || {
        let result = (host.as_str(), 443)
            .to_socket_addrs()
            .map(|a| a.collect())
            .map_err(|e| e.to_string())
            .and_then(validate_addresses);
        let _ = sender.send(result);
        RESOLVERS.fetch_sub(1, Ordering::AcqRel);
    });
    receiver
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| "DNS timeout".to_owned())?
}

#[derive(Debug)]
struct ProxyClient {
    unix: UnixStream,
    tcp: Option<TcpStream>,
}
impl ProxyClient {
    fn shutdown(&self) {
        let _ = self.unix.shutdown(Shutdown::Both);
        if let Some(tcp) = &self.tcp {
            let _ = tcp.shutdown(Shutdown::Both);
        }
    }
}
type ActiveClients = Arc<Mutex<BTreeMap<usize, ProxyClient>>>;

#[derive(Debug)]
pub struct ProxyHandle {
    stop: Arc<AtomicBool>,
    clients: ActiveClients,
    join: Option<thread::JoinHandle<()>>,
    net: PathBuf,
}

impl ProxyHandle {
    pub fn start(net: &Path, family: ModelFamily) -> Result<Self, String> {
        reject_symlink_components(net)?;
        let path = net.join("proxy.sock");
        // sockaddr_un has a 108-byte limit; a directory FD keeps long state paths
        // usable without changing the required <attempt>/net/proxy.sock location.
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(net)
            .map_err(|e| e.to_string())?;
        let address = format!("/proc/self/fd/{}/proxy.sock", directory.as_raw_fd());
        let listener = UnixListener::bind(address).map_err(|e| e.to_string())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let clients = Arc::new(Mutex::new(BTreeMap::<usize, ProxyClient>::new()));
        let thread_stop = stop.clone();
        let thread_clients = clients.clone();
        let uid = crate::v2::socket::current_euid();
        let join = thread::spawn(move || {
            let mut joins = Vec::new();
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        joins.retain(|join: &thread::JoinHandle<()>| !join.is_finished());
                        if joins.len() >= MAX_TUNNELS
                            || crate::v2::socket::verify_peer_uid(&stream, uid).is_err()
                        {
                            continue;
                        }
                        static CLIENT_ID: AtomicUsize = AtomicUsize::new(0);
                        let id = CLIENT_ID.fetch_add(1, Ordering::Relaxed);
                        let Ok(copy) = stream.try_clone() else {
                            continue;
                        };
                        let Ok(mut clients) = thread_clients.lock() else {
                            break;
                        };
                        clients.insert(
                            id,
                            ProxyClient {
                                unix: copy,
                                tcp: None,
                            },
                        );
                        drop(clients);
                        let clients = thread_clients.clone();
                        joins.push(thread::spawn(move || {
                            let _ = serve_connect(stream, family, &clients, id);
                            if let Ok(mut clients) = clients.lock() {
                                clients.remove(&id);
                            }
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => break,
                }
            }
            if let Ok(clients) = thread_clients.lock() {
                for stream in clients.values() {
                    stream.shutdown();
                }
            }
            for join in joins {
                let _ = join.join();
            }
        });
        Ok(Self {
            stop,
            clients,
            join: Some(join),
            net: net.into(),
        })
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(clients) = self.clients.lock() {
            for stream in clients.values() {
                stream.shutdown();
            }
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        let _ = fs::remove_file(self.net.join("proxy.sock"));
        let _ = fs::remove_dir(&self.net);
    }
}

fn serve_connect(
    mut stream: UnixStream,
    family: ModelFamily,
    clients: &ActiveClients,
    id: usize,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut header = Vec::new();
    let deadline = std::time::Instant::now() + IO_TIMEOUT;
    let code_or_host = loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "CONNECT header timeout")
            })?;
        stream.set_read_timeout(Some(remaining))?;
        let mut byte = [0];
        if stream.read(&mut byte)? == 0 {
            return Ok(());
        }
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break parse_connect(&header, family);
        }
        if header.len() >= 8192 {
            break Err(400);
        }
    };
    let host = match code_or_host {
        Ok(host) => host,
        Err(code) => {
            write!(
                stream,
                "HTTP/1.1 {code} Rejected\r\nContent-Length: 0\r\n\r\n"
            )?;
            return Ok(());
        }
    };
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    let addresses = match resolve_public_host(&host).ok() {
        Some(a) => a,
        None => {
            stream.write_all(b"HTTP/1.1 403 Rejected\r\n\r\n")?;
            return Ok(());
        }
    };
    // Connect to the exact validated address, never resolve the hostname again.
    let deadline = std::time::Instant::now() + Duration::from_secs(9);
    let remote = addresses.iter().find_map(|a| {
        let remaining = deadline.checked_duration_since(std::time::Instant::now())?;
        TcpStream::connect_timeout(a, remaining.min(Duration::from_secs(3))).ok()
    });
    let Some(remote) = remote else {
        stream.write_all(b"HTTP/1.1 502 Unavailable\r\n\r\n")?;
        return Ok(());
    };
    remote.set_read_timeout(Some(IO_TIMEOUT))?;
    remote.set_write_timeout(Some(IO_TIMEOUT))?;
    if let Ok(mut clients) = clients.lock()
        && let Some(client) = clients.get_mut(&id)
    {
        client.tcp = Some(remote.try_clone()?);
    }
    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    relay(stream, remote)
}

fn relay(mut unix: UnixStream, mut tcp: TcpStream) -> std::io::Result<()> {
    let mut unix_copy = unix.try_clone()?;
    let mut tcp_copy = tcp.try_clone()?;
    thread::scope(|scope| {
        scope.spawn(move || {
            if std::io::copy(&mut unix_copy, &mut tcp_copy).is_err() {
                let _ = tcp_copy.shutdown(Shutdown::Both);
                let _ = unix_copy.shutdown(Shutdown::Both);
            } else {
                let _ = tcp_copy.shutdown(Shutdown::Write);
            }
        });
        if std::io::copy(&mut tcp, &mut unix).is_err() {
            let _ = unix.shutdown(Shutdown::Both);
            let _ = tcp.shutdown(Shutdown::Both);
        } else {
            let _ = unix.shutdown(Shutdown::Write);
        }
    });
    Ok(())
}

/// Executed inside the isolated network namespace. Inherited stdio is essential
/// for prompts delivered through systemd-run --pipe.
pub fn sandbox_bridge(args: &[String]) -> Result<i32, String> {
    if args.len() < 4 || args[0] != "--unix-sock" || args[2] != "--" {
        return Err("invalid bridge arguments".into());
    }
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let proxy = format!(
        "http://{}",
        listener.local_addr().map_err(|e| e.to_string())?
    );
    let socket = args[1].clone();
    let active = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            if active.fetch_add(1, Ordering::AcqRel) >= MAX_TUNNELS {
                active.fetch_sub(1, Ordering::AcqRel);
                continue;
            }
            let active = active.clone();
            let socket = socket.clone();
            thread::spawn(move || {
                if let Ok(unix) = UnixStream::connect(socket) {
                    let _ = relay(unix, stream);
                }
                active.fetch_sub(1, Ordering::AcqRel);
            });
        }
    });
    let status = Command::new(&args[3])
        .args(&args[4..])
        .envs([
            ("HTTPS_PROXY", &proxy),
            ("HTTP_PROXY", &proxy),
            ("ALL_PROXY", &proxy),
            ("https_proxy", &proxy),
            ("http_proxy", &proxy),
            ("all_proxy", &proxy),
        ])
        .env("NO_PROXY", "localhost,127.0.0.1,::1")
        .env("no_proxy", "localhost,127.0.0.1,::1")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| e.to_string())?;
    Ok(status.code().unwrap_or(1))
}

pub type IsolationChecker = fn() -> Result<(), String>;
pub fn verify_host_isolation() -> Result<(), String> {
    static VERIFIED: OnceLock<Result<(), String>> = OnceLock::new();
    VERIFIED
        .get_or_init(|| {
            let report = doctor(None);
            if report.ok {
                Ok(())
            } else {
                Err("ISOLATION_PREFLIGHT_FAILED: run zach doctor --json for probe results".into())
            }
        })
        .clone()
}

#[derive(Debug, Serialize)]
pub struct ProbeResult {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}
#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub probes: Vec<ProbeResult>,
}

struct ProbeDirectory(PathBuf);
impl Drop for ProbeDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Uses a disposable repository rather than modifying the operator's Git state.
/// `worktree` selects where the private probe directory is created.
pub fn doctor(worktree: Option<&Path>) -> DoctorReport {
    match doctor_impl(worktree) {
        Ok(probes) => DoctorReport {
            ok: probes.iter().all(|p| p.ok),
            probes,
        },
        Err(detail) => DoctorReport {
            ok: false,
            probes: vec![ProbeResult {
                name: "probe_setup".into(),
                ok: false,
                detail,
            }],
        },
    }
}

fn doctor_impl(worktree: Option<&Path>) -> Result<Vec<ProbeResult>, String> {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let base = fs::canonicalize(worktree.unwrap_or(Path::new("."))).map_err(|e| e.to_string())?;
    let root = base.join(format!(
        ".zach-doctor-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .map_err(|e| e.to_string())?;
    let _cleanup = ProbeDirectory(root.clone());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let primary = root.join("primary");
    let linked = root.join("linked");
    fn git(args: &[&str], dir: &Path) -> Result<String, String> {
        let out = Command::new("git")
            .args(["-c", "core.hooksPath=/dev/null"])
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Zach doctor")
            .env("GIT_AUTHOR_EMAIL", "doctor@localhost")
            .env("GIT_COMMITTER_NAME", "Zach doctor")
            .env("GIT_COMMITTER_EMAIL", "doctor@localhost")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!(
                "probe git setup failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().into())
    }
    git(
        &[
            "init",
            "--quiet",
            primary.to_str().ok_or("non-UTF8 probe path")?,
        ],
        &root,
    )?;
    // A synthetic empty commit is needed only in this disposable repository.
    let tree = git(&["mktree"], &primary)?;
    let commit = git(&["commit-tree", &tree, "-m", "isolation probe"], &primary)?;
    git(&["update-ref", "HEAD", &commit], &primary)?;
    git(
        &[
            "worktree",
            "add",
            "--quiet",
            "--detach",
            linked.to_str().ok_or("non-UTF8 probe path")?,
        ],
        &primary,
    )?;
    for tree in [&primary, &linked] {
        write_secure_file(&tree.join(".env"), b"ZACH_SYNTHETIC_SECRET=unreadable\n")?;
    }
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/home/ubuntu".into()));
    let host_sentinel = root.join("host-only-secret");
    write_secure_file(&host_sentinel, b"synthetic host secret")?;
    let host_listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let host_port = host_listener
        .local_addr()
        .map_err(|e| e.to_string())?
        .port();
    let mut probes = Vec::new();
    for (label, tree) in [("git_directory", &primary), ("git_pointer", &linked)] {
        for writable in [false, true] {
            let attempt = root.join(format!("{label}-{writable}"));
            ensure_secure_dir(&attempt)?;
            let mut prepared = PreparedResources::prepare(
                &attempt,
                &home,
                tree,
                writable,
                None,
                NetworkPolicy::None,
            )?;
            let artifact = attempt.join("schema.json");
            write_secure_file(&artifact, b"{}")?;
            prepared.layout.readonly_files.push(artifact.clone());
            let mut hidden: Vec<PathBuf> = [
                ".config/gh/hosts.yml",
                ".ssh",
                ".config/workspace-actions",
                ".config/gcloud",
                ".local/state/zach",
                ".codex/sessions",
                ".gemini/antigravity-cli/brain",
            ]
            .map(|p| home.join(p))
            .into();
            hidden.push(host_sentinel.clone());
            let dotgit = tree.join(".git");
            let git_write = if dotgit.is_file() {
                dotgit.clone()
            } else {
                dotgit.join("zach-probe")
            };
            let code = format!(
                r#"import pathlib,socket
hidden={hidden}
for p in hidden: assert not pathlib.Path(p).exists(), 'host credential path exposed'
try: secret=pathlib.Path({secret}).read_bytes()
except PermissionError: secret=b''
assert secret==b'', 'synthetic secret exposed'
assert pathlib.Path({artifact}).read_bytes()==b'{{}}', 'schema unavailable'
def denied(p):
 try:
  with open(p,'ab') as f: f.write(b'x')
 except OSError: return
 raise AssertionError('write escaped containment')
denied({outside})
denied({git_write})
denied({primary_git})
denied({artifact})
p={write_target}
if {writable}: pathlib.Path(p).write_text('ok')
else: denied(p)
for host,port in [('127.0.0.1',{port}),('1.1.1.1',443)]:
 try: s=socket.create_connection((host,port),0.5)
 except OSError: continue
 s.close(); raise AssertionError('raw TCP escaped network namespace')
print('filesystem, schema, and offline network containment verified')
"#,
                hidden = serde_json::to_string(&hidden).map_err(|e| e.to_string())?,
                secret = serde_json::to_string(&tree.join(".env")).unwrap(),
                artifact = serde_json::to_string(&artifact).unwrap(),
                outside = "'/usr/local/zach-isolation-probe'",
                git_write = serde_json::to_string(&git_write).unwrap(),
                primary_git = serde_json::to_string(&primary.join(".git/zach-probe")).unwrap(),
                writable = if writable { "True" } else { "False" },
                write_target = serde_json::to_string(&tree.join("write-probe")).unwrap(),
                port = host_port
            );
            probes.push(run_probe(
                &format!(
                    "{label}_{}",
                    if writable { "read_write" } else { "read_only" }
                ),
                &prepared.layout,
                &["python3".into(), "-c".into(), code],
            ));
        }
    }
    for family in [ModelFamily::OpenAiSol, ModelFamily::GeminiAgy] {
        let attempt = root.join(family.as_str());
        ensure_secure_dir(&attempt)?;
        let prepared = match PreparedResources::prepare(
            &attempt,
            &home,
            &linked,
            false,
            Some(family),
            NetworkPolicy::ProviderApi(family),
        ) {
            Ok(p) => p,
            Err(detail) => {
                probes.push(ProbeResult {
                    name: format!("{}_preparation", family.as_str()),
                    ok: false,
                    detail,
                });
                continue;
            }
        };
        let code = format!(
            r#"import os,socket,urllib.parse
for host,port in [('127.0.0.1',{port}),('1.1.1.1',443)]:
 try: s=socket.create_connection((host,port),0.5)
 except OSError: continue
 s.close(); raise AssertionError('raw TCP bypass succeeded')
p=urllib.parse.urlparse(os.environ['HTTPS_PROXY'])
for host in ['example.com','github.com','127.0.0.1','[::1]',{allowed}]:
 with socket.create_connection((p.hostname,p.port),3) as s:
  s.settimeout(20)
  s.sendall(('CONNECT '+host+':443 HTTP/1.1\r\nHost: '+host+'\r\n\r\n').encode())
  response=b''
  while b'\r\n' not in response:
   chunk=s.recv(1024)
   assert chunk, 'proxy closed before status line'
   response+=chunk
  status=response.split(b' ')[1]
  assert status==(b'200' if host=={allowed} else b'403'), (host,status)
print('raw TCP blocked; rejected hosts return 403; declared provider reachable')
"#,
            port = host_port,
            allowed = serde_json::to_string(allowed_hosts(family)[0]).unwrap()
        );
        probes.push(run_probe(
            &format!("{}_network", family.as_str()),
            &prepared.layout,
            &["python3".into(), "-c".into(), code],
        ));
        if family == ModelFamily::OpenAiSol {
            probes.push(run_probe_input("bridge_stdio", &prepared.layout, &[
                "python3".into(), "-c".into(),
                "import sys; assert sys.stdin.buffer.read() == b'x'*524288; print('bridge stdin/stdout verified'); print('bridge stderr verified', file=sys.stderr)".into()
            ], &vec![b'x'; 524288]));
        }
        let cli = match family {
            ModelFamily::OpenAiSol => {
                "test -s \"$CODEX_HOME/auth.json\" && node --version && codex --version".to_owned()
            }
            ModelFamily::GeminiAgy => format!(
                "test -s \"$HOME/.gemini/antigravity-cli/antigravity-oauth-token\" -o -s \"$HOME/.gemini/jetski-standalone-oauth-token\" && node --version && agy --version && node --input-type=module -e 'const m = await import({}); if (typeof m.runCli !== \"function\") process.exit(1)'",
                serde_json::to_string(crate::v2::runner::GEMINI_WORKER_CLI_SCRIPT).unwrap()
            ),
        };
        probes.push(run_probe(
            &format!("{}_cli_readiness", family.as_str()),
            &prepared.layout,
            &["bash".into(), "-c".into(), cli],
        ));
    }
    Ok(probes)
}

fn run_probe(name: &str, layout: &SandboxLayout, worker: &[String]) -> ProbeResult {
    run_probe_input(name, layout, worker, &[])
}

fn run_probe_input(
    name: &str,
    layout: &SandboxLayout,
    worker: &[String],
    input: &[u8],
) -> ProbeResult {
    static PROBE_SEQ: AtomicUsize = AtomicUsize::new(0);
    let unit = format!(
        "--unit=zach-stage-doctor-{}-{}",
        std::process::id(),
        PROBE_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let result = (|| -> std::io::Result<std::process::Output> {
        let mut child = Command::new("systemd-run")
            .arg(unit)
            .args([
                "--user",
                "--quiet",
                "--wait",
                "--pipe",
                "--collect",
                "--slice=zach-workers.slice",
                "-p",
                "RuntimeMaxSec=45",
                "-p",
                "MemoryMax=1G",
                "-p",
                "TasksMax=128",
                "-p",
                "KillMode=control-group",
                "--",
            ])
            .args(bwrap_args(layout, worker))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdin = child.stdin.take();
        thread::scope(|scope| {
            let writer = scope.spawn(move || -> std::io::Result<()> {
                if let Some(mut stdin) = stdin {
                    stdin.write_all(input)?;
                }
                Ok(())
            });
            let out = child.wait_with_output();
            writer
                .join()
                .map_err(|_| std::io::Error::other("probe stdin thread failed"))??;
            out
        })
    })();
    match result {
        Ok(out) => ProbeResult {
            name: name.into(),
            ok: out.status.success(),
            detail: crate::v2::runner::truncate_utf8_bytes(
                &format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                ),
                2048,
            )
            .trim()
            .into(),
        },
        Err(e) => ProbeResult {
            name: name.into(),
            ok: false,
            detail: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join(format!(
                    "isolation-test-{}-{}",
                    std::process::id(),
                    SEQ.fetch_add(1, Ordering::Relaxed)
                ));
            ensure_secure_dir(&root).unwrap();
            Self(root)
        }
        fn repo(&self) -> PathBuf {
            let repo = self.0.join("repo");
            ensure_secure_dir(&repo).unwrap();
            ensure_secure_dir(&repo.join(".git")).unwrap();
            ensure_secure_dir(&repo.join(".git/objects")).unwrap();
            fs::write(repo.join(".git/config"), "[core]\n").unwrap();
            fs::write(repo.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
            repo
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn contains_bind(args: &[String], mode: &str, src: &Path, dst: &Path) -> bool {
        args.windows(3)
            .any(|a| a[0] == mode && Path::new(&a[1]) == src && Path::new(&a[2]) == dst)
    }

    #[test]
    fn relay_preserves_full_response_after_request_half_close() {
        let (mut provider, bridge) = UnixStream::pair().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        provider
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let response = vec![b'x'; 1024 * 1024];
        let expected = response.clone();
        let relay_thread = thread::spawn(move || relay(bridge, server).unwrap());
        let provider_thread = thread::spawn(move || {
            let mut request = Vec::new();
            provider.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"request");
            provider.write_all(&response).unwrap();
            provider.shutdown(Shutdown::Write).unwrap();
        });
        client.write_all(b"request").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut actual = Vec::new();
        client.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected);
        provider_thread.join().unwrap();
        relay_thread.join().unwrap();
    }

    #[test]
    fn codex_package_overlay_follows_staged_home_mount() {
        let home = Path::new("/home/ubuntu");
        let mut layout = SandboxLayout::declared(home, Path::new("/repo"), false);
        layout.auth = Some((PathBuf::from("/attempt/codex-home"), home.join(".codex")));
        layout.toolchains.push(home.join(".codex/packages"));
        let args = bwrap_args(&layout, &[]);
        assert!(
            args.iter()
                .position(|a| a == "/attempt/codex-home")
                .unwrap()
                < args
                    .iter()
                    .position(|a| a == "/home/ubuntu/.codex/packages")
                    .unwrap()
        );
    }

    #[test]
    fn git_pointer_cannot_reintroduce_a_non_git_host_directory() {
        let temp = Temp::new();
        let repo = temp.repo();
        let linked = temp.0.join("linked");
        ensure_secure_dir(&linked).unwrap();
        fs::write(linked.join(".git"), format!("gitdir: {}", temp.0.display())).unwrap();
        assert!(git_mounts(&linked).is_err());
        fs::write(repo.join(".git/commondir"), "../..\n").unwrap();
        fs::write(
            linked.join(".git"),
            format!("gitdir: {}", repo.join(".git").display()),
        )
        .unwrap();
        assert!(git_mounts(&linked).is_err());
    }

    #[test]
    fn proxy_drop_closes_clients_waiting_for_request_headers() {
        let temp = Temp::new();
        let net = temp.0.join("net");
        ensure_secure_dir(&net).unwrap();
        let proxy = ProxyHandle::start(&net, ModelFamily::OpenAiSol).unwrap();
        let dir = fs::File::open(&net).unwrap();
        let mut client =
            UnixStream::connect(format!("/proc/self/fd/{}/proxy.sock", dir.as_raw_fd())).unwrap();
        client.write_all(b"CONNECT ").unwrap();
        thread::sleep(Duration::from_millis(30));
        let start = std::time::Instant::now();
        drop(proxy);
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(!net.exists());
    }

    #[test]
    fn artifact_and_auth_paths_reject_symlink_ancestors() {
        let temp = Temp::new();
        let real = temp.0.join("real");
        ensure_secure_dir(&real).unwrap();
        let link = temp.0.join("link");
        symlink(&real, &link).unwrap();
        assert!(secure_parents(&link.join("child")).is_err());
        assert!(ensure_secure_dir(&link.join("child")).is_err());
        assert!(write_secure_file(&link.join("artifact"), b"x").is_err());
        assert!(!real.join("child").exists() && !real.join("artifact").exists());
    }

    #[test]
    fn argv_masks_host_state_and_preserves_namespace_and_environment_boundaries() {
        let layout = SandboxLayout::declared(
            Path::new("/home/ubuntu"),
            Path::new("/home/ubuntu/workspace/task"),
            false,
        );
        let args = bwrap_args(&layout, &["codex".into(), "exec".into(), "-".into()]);
        for flag in [
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
        ] {
            assert!(args.iter().any(|a| a == flag));
        }
        for path in [
            "/home",
            "/root",
            "/tmp",
            "/run",
            "/var/tmp",
            "/home/ubuntu/workspace",
        ] {
            assert!(args.windows(2).any(|a| a[0] == "--tmpfs" && a[1] == path));
        }
        assert!(contains_bind(
            &args,
            "--ro-bind",
            &layout.worktree,
            &layout.worktree
        ));
        assert!(contains_bind(
            &args,
            "--ro-bind",
            &layout.worktree.join(".git"),
            &layout.worktree.join(".git")
        ));
        assert!(
            !args
                .iter()
                .any(|a| a == BRIDGE || a == "--share-net" || a == "--unshare-net=false")
        );
        assert!(
            args.windows(3)
                .any(|a| a == ["--chmod", "0700", "/tmp/xdg-runtime"])
        );
        let env = sandbox_env(&layout.home);
        assert_eq!(env["XDG_RUNTIME_DIR"], "/tmp/xdg-runtime");
        assert!(env["PATH"].contains("fnm/aliases/default/bin"));
        assert!(!env.keys().any(|k| k == "GH_TOKEN" || k == "GITHUB_TOKEN"));
        assert_eq!(args.last().unwrap(), "-");
    }

    #[test]
    fn argv_network_directory_and_bridge_mounts_follow_run_mask_and_do_not_overlap() {
        let mut layout =
            SandboxLayout::declared(Path::new("/home/ubuntu"), Path::new("/repo"), true);
        layout.proxy = Some((
            PathBuf::from("/state/attempts/a/net"),
            PathBuf::from("/bin/zach"),
        ));
        let args = bwrap_args(&layout, &["node".into(), "worker.mjs".into()]);
        assert!(contains_bind(
            &args,
            "--bind",
            &layout.worktree,
            &layout.worktree
        ));
        assert!(contains_bind(
            &args,
            "--ro-bind",
            Path::new("/state/attempts/a/net"),
            Path::new("/run/zach-net")
        ));
        assert!(contains_bind(
            &args,
            "--ro-bind",
            Path::new("/bin/zach"),
            Path::new(BRIDGE)
        ));
        let run = args
            .windows(2)
            .position(|a| a == ["--tmpfs", "/run"])
            .unwrap();
        let net = args.iter().position(|a| a == "/run/zach-net").unwrap();
        assert!(run < net);
        assert!(!BRIDGE.starts_with("/run/zach-net/"));
        assert!(
            args.windows(5)
                .any(|a| a == [BRIDGE, "__sandbox-bridge", "--unix-sock", SOCKET, "--"])
        );
    }

    #[test]
    fn argv_exact_schema_mount_survives_tmp_and_home_masks_without_attempt_exposure() {
        for path in [
            "/tmp/review-schema.json",
            "/home/ubuntu/.local/state/zach/attempts/a/review-schema.json",
        ] {
            let mut layout =
                SandboxLayout::declared(Path::new("/home/ubuntu"), Path::new("/repo"), false);
            layout.readonly_files.push(path.into());
            let args = bwrap_args(
                &layout,
                &[
                    "codex".into(),
                    "exec".into(),
                    "--output-schema".into(),
                    path.into(),
                    "-".into(),
                ],
            );
            assert!(contains_bind(
                &args,
                "--ro-bind",
                Path::new(path),
                Path::new(path)
            ));
            assert!(!contains_bind(
                &args,
                "--ro-bind",
                Path::new("/home/ubuntu/.local/state/zach"),
                Path::new("/home/ubuntu/.local/state/zach")
            ));
            let mask = args
                .windows(2)
                .position(|a| a == ["--tmpfs", "/tmp"])
                .unwrap();
            let file = args.iter().position(|a| a == path).unwrap();
            assert!(mask < file);
        }
    }

    #[test]
    fn secret_scan_masks_nested_files_but_exempts_exact_templates_and_skips_directories() {
        let temp = Temp::new();
        ensure_secure_dir(&temp.0.join("nested")).unwrap();
        ensure_secure_dir(&temp.0.join(".env.d")).unwrap();
        for file in [
            ".env",
            "nested/.env.production",
            ".envrc",
            ".env.Example",
            ".env.d/.env.secret",
            ".env.example",
            ".env.sample",
            ".env.template",
            ".env.dist",
            ".env.schema",
        ] {
            fs::write(temp.0.join(file), "secret").unwrap();
        }
        let mut files = Vec::new();
        scan_secrets(&temp.0, &mut files).unwrap();
        assert_eq!(files.len(), 5);
        assert!(!files.contains(&temp.0.join(".env.d")));
        assert!(!files.contains(&temp.0.join(".env.example")));
        assert!(files.contains(&temp.0.join(".env.d/.env.secret")));
    }

    #[test]
    fn secret_scan_rejects_file_directory_dangling_and_template_symlinks() {
        for name in [".env", ".env.local", ".env.example", ".env.d"] {
            let temp = Temp::new();
            symlink("missing", temp.0.join(name)).unwrap();
            assert!(
                scan_secrets(&temp.0, &mut Vec::new())
                    .unwrap_err()
                    .contains("secret symlink")
            );
        }
    }

    #[test]
    fn secret_scan_never_follows_other_directory_links_or_git_metadata() {
        let temp = Temp::new();
        let repo = temp.repo();
        fs::write(repo.join(".git/.env"), "metadata").unwrap();
        symlink(&temp.0, repo.join("cycle")).unwrap();
        assert!(scan_secrets(&repo, &mut Vec::new()).is_ok());
    }

    #[test]
    fn git_directory_is_always_overlaid_readonly() {
        let temp = Temp::new();
        let repo = temp.repo();
        let layout = SandboxLayout::inspect(&temp.0, &repo, true).unwrap();
        assert_eq!(layout.git_paths, vec![repo.join(".git")]);
        assert!(contains_bind(
            &bwrap_args(&layout, &[]),
            "--ro-bind",
            &repo.join(".git"),
            &repo.join(".git")
        ));
    }

    #[test]
    fn git_relative_pointer_resolves_worktree_metadata_and_primary_repository() {
        let temp = Temp::new();
        let repo = temp.repo();
        let gitdir = repo.join(".git/worktrees/linked");
        fs::create_dir_all(&gitdir).unwrap();
        fs::write(gitdir.join("commondir"), "../..\n").unwrap();
        fs::write(gitdir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let linked = temp.0.join("linked");
        ensure_secure_dir(&linked).unwrap();
        fs::write(
            linked.join(".git"),
            "gitdir: ../repo/.git/worktrees/linked\n",
        )
        .unwrap();
        let mounts = git_mounts(&linked).unwrap();
        assert!(
            mounts.contains(&linked.join(".git"))
                && mounts.contains(&repo.join(".git"))
                && mounts.contains(&gitdir)
        );
        assert!(
            mounts.iter().position(|p| p == &repo.join(".git")).unwrap()
                < mounts.iter().position(|p| p == &gitdir).unwrap()
        );
    }

    #[test]
    fn git_separate_directory_pointer_and_invalid_or_symlink_metadata() {
        let temp = Temp::new();
        let repo = temp.repo();
        let linked = temp.0.join("linked");
        ensure_secure_dir(&linked).unwrap();
        fs::write(
            linked.join(".git"),
            format!("gitdir: {}", repo.join(".git").display()),
        )
        .unwrap();
        let mounts = git_mounts(&linked).unwrap();
        assert!(mounts.contains(&repo.join(".git")));
        fs::write(linked.join(".git"), "broken").unwrap();
        assert!(git_mounts(&linked).is_err());
        fs::remove_file(linked.join(".git")).unwrap();
        symlink(repo.join(".git"), linked.join(".git")).unwrap();
        assert!(git_mounts(&linked).is_err());
        fs::remove_file(linked.join(".git")).unwrap();
        assert!(git_mounts(&linked).is_err());
    }

    #[test]
    fn connect_parser_allows_only_exact_family_hosts_and_tls_ports() {
        for family in [ModelFamily::OpenAiSol, ModelFamily::GeminiAgy] {
            for host in allowed_hosts(family) {
                let header = format!(
                    "CONNECT {}:443 HTTP/1.1\r\nHost: ignored\r\n\r\n",
                    host.to_ascii_uppercase()
                );
                assert_eq!(
                    parse_connect(header.as_bytes(), family),
                    Ok(host.to_string())
                );
                assert_eq!(
                    parse_connect(header.as_bytes(), family.opposite()),
                    Err(403)
                );
            }
        }
    }

    #[test]
    fn connect_parser_rejects_url_authority_confusion_ips_suffixes_and_other_methods() {
        for authority in [
            "example.com:443",
            "github.com:443",
            "127.0.0.1:443",
            "[::1]:443",
            "[::ffff:127.0.0.1]:443",
            "api.openai.com:80",
            "api.openai.com:0443",
            "api.openai.com.:443",
            "api.openai.com.evil:443",
            "evilapi.openai.com:443",
            "https://api.openai.com:443",
            "user@api.openai.com:443",
            "api.openai.com/path:443",
            "api.openai.com?q:443",
            "api.openai.com#x:443",
            "api.openai.com:443:443",
        ] {
            assert_eq!(
                parse_connect(
                    format!("CONNECT {authority} HTTP/1.1\r\n\r\n").as_bytes(),
                    ModelFamily::OpenAiSol
                ),
                Err(403),
                "{authority}"
            );
        }
        assert_eq!(
            parse_connect(
                b"GET https://api.openai.com HTTP/1.1\r\n\r\n",
                ModelFamily::OpenAiSol
            ),
            Err(403)
        );
    }

    #[test]
    fn connect_parser_enforces_header_limit_and_request_shape() {
        for header in [
            b"".to_vec(),
            b"CONNECT api.openai.com:443 HTTP/2\r\n\r\n".to_vec(),
            b"CONNECT api.openai.com:443 HTTP/1.1 extra\r\n\r\n".to_vec(),
            b"CONNECT api.openai.com:443 HTTP/1.1\n\n".to_vec(),
            vec![b'x'; 8193],
            vec![255; 10],
        ] {
            assert_eq!(parse_connect(&header, ModelFamily::OpenAiSol), Err(400));
        }
    }

    #[test]
    fn ssrf_rejects_nonpublic_ipv4_and_ipv6_including_mapped_and_transition_ranges() {
        for ip in [
            "0.0.0.1",
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.19.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "::",
            "::1",
            "fc00::1",
            "fd00::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "2001:db8::1",
            "2001:0:1234::1",
            "2002:7f00:1::1",
            "3fff::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "100.128.0.1",
            "172.32.0.1",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
        ] {
            assert!(public_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn dns_rebinding_guard_rejects_mixed_answers_and_returns_pinned_addresses() {
        let public: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let private: SocketAddr = "127.0.0.1:443".parse().unwrap();
        assert!(validate_addresses(vec![]).is_err());
        for addresses in [
            vec![public, private],
            vec![private, public],
            vec!["[::ffff:127.0.0.1]:443".parse().unwrap()],
            vec!["8.8.8.8:80".parse().unwrap()],
        ] {
            assert!(validate_addresses(addresses).is_err());
        }
        assert_eq!(validate_addresses(vec![public]).unwrap(), vec![public]);
    }

    #[test]
    fn proxy_rejects_disallowed_connects_empirically_and_cleans_up_its_directory() {
        let temp = Temp::new();
        let net = temp.0.join("net");
        ensure_secure_dir(&net).unwrap();
        let proxy = ProxyHandle::start(&net, ModelFamily::OpenAiSol).unwrap();
        assert_eq!(
            fs::metadata(net.join("proxy.sock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        // The same directory-fd technique supports tests under a long worktree path.
        let dir = fs::File::open(&net).unwrap();
        let socket = format!("/proc/self/fd/{}/proxy.sock", dir.as_raw_fd());
        for host in ["example.com", "github.com", "127.0.0.1", "[::1]"] {
            let mut stream = UnixStream::connect(&socket).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            write!(stream, "CONNECT {host}:443 HTTP/1.1\r\n\r\n").unwrap();
            let mut out = String::new();
            stream.read_to_string(&mut out).unwrap();
            assert!(out.starts_with("HTTP/1.1 403"));
        }
        drop(proxy);
        assert!(!net.exists());
    }

    #[test]
    fn auth_staging_is_minimal_private_writable_and_cleaned_while_artifacts_survive() {
        let temp = Temp::new();
        let repo = temp.repo();
        let home = temp.0.join("home");
        ensure_secure_dir(&home).unwrap();
        ensure_secure_dir(&home.join(".codex")).unwrap();
        fs::write(home.join(".codex/auth.json"), "auth").unwrap();
        fs::write(home.join(".codex/history.jsonl"), "private history").unwrap();
        let attempt = temp.0.join("attempt");
        ensure_secure_dir(&attempt).unwrap();
        fs::write(attempt.join("result.json"), "{}").unwrap();
        let prepared = PreparedResources::prepare(
            &attempt,
            &home,
            &repo,
            false,
            Some(ModelFamily::OpenAiSol),
            NetworkPolicy::None,
        )
        .unwrap();
        let staged = attempt.join("codex-home");
        assert_eq!(fs::read_dir(&staged).unwrap().count(), 1);
        assert_eq!(
            fs::metadata(&staged).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(staged.join("auth.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::write(staged.join("auth.json"), "refreshed").unwrap();
        assert_eq!(
            fs::read_to_string(home.join(".codex/auth.json")).unwrap(),
            "auth"
        );
        assert!(prepared.layout.proxy.is_none());
        drop(prepared);
        assert!(!staged.exists());
        assert!(attempt.join("result.json").exists());
    }

    #[test]
    fn auth_source_links_and_reused_staging_directories_fail_closed() {
        let temp = Temp::new();
        let repo = temp.repo();
        let home = temp.0.join("home");
        fs::create_dir_all(home.join(".codex")).unwrap();
        fs::write(home.join("secret"), "auth").unwrap();
        symlink(home.join("secret"), home.join(".codex/auth.json")).unwrap();
        let attempt = temp.0.join("attempt");
        ensure_secure_dir(&attempt).unwrap();
        assert!(
            PreparedResources::prepare(
                &attempt,
                &home,
                &repo,
                false,
                Some(ModelFamily::OpenAiSol),
                NetworkPolicy::None
            )
            .is_err()
        );
        assert!(!attempt.join("codex-home").exists());
        ensure_secure_dir(&attempt.join("codex-home")).unwrap();
        assert!(
            PreparedResources::prepare(
                &attempt,
                &home,
                &repo,
                false,
                Some(ModelFamily::OpenAiSol),
                NetworkPolicy::None
            )
            .is_err()
        );
        assert!(attempt.join("codex-home").exists());
    }

    #[test]
    fn offline_checks_receive_neither_auth_nor_proxy_nor_plugin() {
        let temp = Temp::new();
        let repo = temp.repo();
        let attempt = temp.0.join("attempt");
        ensure_secure_dir(&attempt).unwrap();
        let prepared =
            PreparedResources::prepare(&attempt, &temp.0, &repo, true, None, NetworkPolicy::None)
                .unwrap();
        assert!(
            prepared.layout.auth.is_none()
                && prepared.layout.proxy.is_none()
                && prepared.layout.plugin.is_none()
        );
        assert_eq!(fs::read_dir(attempt).unwrap().count(), 0);
    }

    #[test]
    fn network_resolution_is_exact_and_unknown_values_fail_closed() {
        for family in [ModelFamily::OpenAiSol, ModelFamily::GeminiAgy] {
            assert_eq!(
                NetworkPolicy::resolve(None, family).unwrap(),
                NetworkPolicy::ProviderApi(family)
            );
            assert_eq!(
                NetworkPolicy::resolve(Some("provider-api"), family).unwrap(),
                NetworkPolicy::ProviderApi(family)
            );
            assert_eq!(
                NetworkPolicy::resolve(Some("none"), family).unwrap(),
                NetworkPolicy::None
            );
            for raw in [
                "",
                "all",
                "install-only",
                "Provider-api",
                "none ",
                "null",
                "true",
            ] {
                assert!(NetworkPolicy::resolve(Some(raw), family).is_err());
            }
        }
    }

    #[test]
    fn bridge_arguments_are_validated_without_spawning_a_worker() {
        assert!(sandbox_bridge(&[]).is_err());
        assert!(
            sandbox_bridge(&[
                "--unix-sock".into(),
                SOCKET.into(),
                "wrong".into(),
                "true".into()
            ])
            .is_err()
        );
    }
}
