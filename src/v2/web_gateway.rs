use crate::v2::default_state_dir;
use crate::v2::socket::{ClientCommand, ServerMessage, write_ndjson};
use crate::v2::store::{
    DaemonStatusSummary, DecisionResolution, PendingDecisionRecord, TaskRecord, V2Store,
    V2StoreError,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotResponse {
    pub tasks: Vec<TaskRecord>,
    pub open_decisions: Vec<PendingDecisionRecord>,
    pub status: DaemonStatusSummary,
    pub as_of_seq: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecideRequestBody {
    pub decision_id: String,
    pub choice: String,
    #[serde(default)]
    pub by: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecideResponse {
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<PendingDecisionRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionResponse {
    pub authenticated: bool,
    pub session_token: String,
    pub user: String,
}

#[derive(Clone)]
pub enum StoreHandle {
    Path(PathBuf),
    Shared(Arc<Mutex<V2Store>>),
}

#[derive(Clone)]
pub struct WebGateway {
    pub bind_addr: String,
    pub store_handle: StoreHandle,
    pub socket_path: PathBuf,
    pub session_token: String,
    pub shutdown: Arc<AtomicBool>,
}

fn generate_random_token() -> String {
    let mut bytes = [0u8; 24];
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        if f.read_exact(&mut bytes).is_ok() {
            return bytes.iter().map(|b| format!("{:02x}", b)).collect();
        }
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let rand_val = unsafe { libc::rand() as u32 };
    format!("{:016x}{:08x}{:08x}", now, pid, rand_val)
}

pub fn get_or_create_web_session_token() -> String {
    if let Ok(token) = std::env::var("ZACH_WEB_SESSION_TOKEN")
        && !token.trim().is_empty()
    {
        return token.trim().to_string();
    }
    if let Ok(token) = std::env::var("ZACH_AUTH_TOKEN")
        && !token.trim().is_empty()
    {
        return token.trim().to_string();
    }
    let state_dir = default_state_dir();
    let token_path = state_dir.join("web_session_token");
    if let Ok(content) = fs::read_to_string(&token_path) {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let token = generate_random_token();
    let _ = fs::create_dir_all(&state_dir);
    let _ = fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700));
    if let Ok(mut f) = fs::File::create(&token_path) {
        let _ = f.write_all(token.as_bytes());
        let _ = fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600));
    }
    token
}

pub fn check_session_auth(
    headers: &HashMap<String, String>,
    query: &HashMap<String, String>,
    expected_token: &str,
) -> bool {
    if expected_token.is_empty() {
        return true;
    }
    if let Some(auth) = headers.get("authorization") {
        let auth_trimmed = auth.trim();
        if let Some(token) = auth_trimmed
            .strip_prefix("Bearer ")
            .or_else(|| auth_trimmed.strip_prefix("bearer "))
        {
            if token.trim() == expected_token {
                return true;
            }
        } else if let Some(token) = auth_trimmed
            .strip_prefix("Session ")
            .or_else(|| auth_trimmed.strip_prefix("session "))
        {
            if token.trim() == expected_token {
                return true;
            }
        } else if auth_trimmed == expected_token {
            return true;
        }
    }
    if let Some(cookie) = headers.get("cookie") {
        for part in cookie.split(';') {
            let part = part.trim();
            if let Some((name, val)) = part.split_once('=') {
                let name = name.trim();
                let val = val.trim().trim_matches('"');
                if (name == "session"
                    || name == "zach_session"
                    || name == "session_token"
                    || name == "token")
                    && val == expected_token
                {
                    return true;
                }
            }
        }
    }
    if let Some(token) = headers
        .get("x-session-token")
        .or_else(|| headers.get("x-auth-token"))
    {
        if token.trim() == expected_token {
            return true;
        }
    }
    if let Some(token) = query.get("token").or_else(|| query.get("session")) {
        if token.trim() == expected_token {
            return true;
        }
    }
    false
}

pub fn url_decode(s: &str) -> String {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                result.push(byte);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            result.push(b' ');
            i += 1;
            continue;
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

pub fn parse_query_params(query_str: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in query_str.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (url_decode(k), url_decode(v)),
            None => (url_decode(pair), String::new()),
        };
        map.insert(k, v);
    }
    map
}

#[derive(Debug)]
pub struct ParsedHttpRequest {
    pub method: String,
    pub path: String,
    pub route: String,
    pub query_params: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

pub fn read_http_request(stream: &mut TcpStream) -> std::io::Result<ParsedHttpRequest> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    let body_start: usize;
    let mut header_count: usize = 0;

    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before headers",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 65536 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP headers too large",
            ));
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(offset)) => {
                body_start = offset;
                for (i, h) in req.headers.iter().enumerate() {
                    if h.name.is_empty() {
                        header_count = i;
                        break;
                    }
                    header_count = i + 1;
                }
                break;
            }
            Ok(httparse::Status::Partial) => {
                continue;
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("HTTP parse error: {e}"),
                ));
            }
        }
    }

    let mut headers_arr = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers_arr);
    let _ = req.parse(&buf);

    let method = req.method.unwrap_or("GET").to_uppercase();
    let full_path = req.path.unwrap_or("/").to_string();

    let mut headers_map = HashMap::new();
    for h in &headers_arr[..header_count] {
        let name = h.name.to_ascii_lowercase();
        let value = String::from_utf8_lossy(h.value).trim().to_string();
        headers_map.insert(name, value);
    }

    let (route, query_str) = match full_path.find('?') {
        Some(idx) => (
            full_path[..idx].to_string(),
            full_path[idx + 1..].to_string(),
        ),
        None => (full_path.clone(), String::new()),
    };
    let query_params = parse_query_params(&query_str);

    let content_len: usize = headers_map
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = buf[body_start..].to_vec();
    while body.len() < content_len {
        let needed = content_len - body.len();
        let to_read = needed.min(tmp.len());
        let n = stream.read(&mut tmp[..to_read])?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    if body.len() > content_len {
        body.truncate(content_len);
    }

    Ok(ParsedHttpRequest {
        method,
        path: full_path,
        route,
        query_params,
        headers: headers_map,
        body,
    })
}

pub fn write_cors_preflight(stream: &mut TcpStream) -> std::io::Result<()> {
    let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-Session-Token, X-Auth-Token, Last-Event-ID\r\nAccess-Control-Max-Age: 86400\r\nConnection: close\r\n\r\n";
    stream.write_all(resp.as_bytes())?;
    stream.flush()?;
    Ok(())
}

pub fn write_json_response<T: Serialize>(
    stream: &mut TcpStream,
    status_code: u16,
    reason: &str,
    data: &T,
) -> std::io::Result<()> {
    let json_bytes = serde_json::to_vec(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let headers = format!(
        "HTTP/1.1 {status_code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-Session-Token, X-Auth-Token, Last-Event-ID\r\nConnection: close\r\n\r\n",
        json_bytes.len()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(&json_bytes)?;
    stream.flush()?;
    Ok(())
}

pub fn write_error_response(
    stream: &mut TcpStream,
    status_code: u16,
    reason: &str,
    message: &str,
) -> std::io::Result<()> {
    let body = serde_json::json!({
        "error": reason.to_ascii_lowercase().replace(' ', "_"),
        "message": message,
    });
    write_json_response(stream, status_code, reason, &body)
}

pub fn stream_sse_events(
    gateway: &WebGateway,
    stream: &mut TcpStream,
    since_seq: i64,
    group: Option<String>,
) -> std::io::Result<()> {
    let sse_headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache, no-transform\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-Session-Token, X-Auth-Token, Last-Event-ID\r\n\r\n";
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    stream.write_all(sse_headers.as_bytes())?;
    stream.flush()?;

    let mut high_watermark = since_seq;

    // 1. Initial replay of missed events from SQLite store
    let replay_res =
        gateway.with_store(|store| store.list_events_since(group.as_deref(), high_watermark, 5000));
    if let Ok(events) = replay_res {
        for event in events {
            if event.seq_id > high_watermark {
                high_watermark = event.seq_id;
                let payload = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_string());
                let chunk = format!(
                    "id: {}\nevent: {}\ndata: {}\n\n",
                    event.seq_id, event.event_type, payload
                );
                if stream.write_all(chunk.as_bytes()).is_err() {
                    return Ok(());
                }
                let _ = stream.flush();
            }
        }
    }

    // 2. Connect to Unix socket pub/sub or fall back to store polling
    let mut unix_sub: Option<(UnixStream, BufReader<UnixStream>)> =
        match UnixStream::connect(&gateway.socket_path) {
            Ok(sock) => {
                let mut s = sock;
                let cmd = ClientCommand::Subscribe {
                    group: group.clone(),
                    since_seq: Some(high_watermark),
                    once: Some(false),
                };
                let _ = write_ndjson(&mut s, &cmd);
                let _ = s.set_read_timeout(Some(Duration::from_millis(250)));
                if let Ok(cloned) = s.try_clone() {
                    Some((s, BufReader::new(cloned)))
                } else {
                    None
                }
            }
            Err(_) => None,
        };

    let mut last_heartbeat = SystemTime::now();

    while !gateway.shutdown.load(Ordering::Relaxed) {
        let mut had_activity = false;

        if let Some((_, ref mut reader)) = unix_sub {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    unix_sub = None;
                }
                Ok(_) => {
                    had_activity = true;
                    let trimmed = line.trim();
                    if let Ok(ServerMessage::Event { event }) =
                        serde_json::from_str::<ServerMessage>(trimmed)
                    {
                        if event.seq_id > high_watermark {
                            high_watermark = event.seq_id;
                            let payload =
                                serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_string());
                            let chunk = format!(
                                "id: {}\nevent: {}\ndata: {}\n\n",
                                event.seq_id, event.event_type, payload
                            );
                            if stream.write_all(chunk.as_bytes()).is_err() {
                                return Ok(());
                            }
                            let _ = stream.flush();
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => {
                    unix_sub = None;
                }
            }
        } else {
            let events_res = gateway
                .with_store(|store| store.list_events_since(group.as_deref(), high_watermark, 200));
            if let Ok(events) = events_res {
                if !events.is_empty() {
                    had_activity = true;
                    for event in events {
                        if event.seq_id > high_watermark {
                            high_watermark = event.seq_id;
                            let payload =
                                serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_string());
                            let chunk = format!(
                                "id: {}\nevent: {}\ndata: {}\n\n",
                                event.seq_id, event.event_type, payload
                            );
                            if stream.write_all(chunk.as_bytes()).is_err() {
                                return Ok(());
                            }
                            let _ = stream.flush();
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        if last_heartbeat
            .elapsed()
            .map(|d| d.as_secs() >= 15)
            .unwrap_or(false)
        {
            last_heartbeat = SystemTime::now();
            if stream.write_all(b": ping\n\n").is_err() {
                return Ok(());
            }
            let _ = stream.flush();
        }

        if !had_activity && unix_sub.is_some() {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    Ok(())
}

impl WebGateway {
    pub fn new(bind_addr: String, db_path: PathBuf, socket_path: PathBuf) -> Self {
        let session_token = get_or_create_web_session_token();
        Self {
            bind_addr,
            store_handle: StoreHandle::Path(db_path),
            socket_path,
            session_token,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_shared_store(
        bind_addr: String,
        store: Arc<Mutex<V2Store>>,
        socket_path: PathBuf,
    ) -> Self {
        let session_token = get_or_create_web_session_token();
        Self {
            bind_addr,
            store_handle: StoreHandle::Shared(store),
            socket_path,
            session_token,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    pub fn with_store<F, R>(&self, f: F) -> Result<R, V2StoreError>
    where
        F: FnOnce(&mut V2Store) -> Result<R, V2StoreError>,
    {
        match &self.store_handle {
            StoreHandle::Path(path) => {
                let mut store = V2Store::open(path)?;
                f(&mut store)
            }
            StoreHandle::Shared(shared) => {
                let mut store = shared
                    .lock()
                    .map_err(|e| V2StoreError(format!("mutex poisoned: {e}")))?;
                f(&mut store)
            }
        }
    }

    pub fn run_loop(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.bind_addr)?;
        listener.set_nonblocking(true)?;

        while !self.shutdown.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let gateway_clone = self.clone();
                    std::thread::spawn(move || {
                        let _ = gateway_clone.handle_client(stream);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    pub fn handle_client(&self, mut stream: TcpStream) -> std::io::Result<()> {
        let req = match read_http_request(&mut stream) {
            Ok(r) => r,
            Err(e) => {
                let _ = write_error_response(&mut stream, 400, "Bad Request", &e.to_string());
                return Ok(());
            }
        };

        if req.method == "OPTIONS" {
            return write_cors_preflight(&mut stream);
        }

        let normalized_route = req.route.trim_end_matches('/');
        let route = if normalized_route.is_empty() {
            "/"
        } else {
            normalized_route
        };

        match (req.method.as_str(), route) {
            ("GET", "/health") | ("GET", "/api/health") => {
                let body = serde_json::json!({ "ok": true, "status": "healthy" });
                write_json_response(&mut stream, 200, "OK", &body)
            }
            ("GET", "/api/session") => {
                let is_auth =
                    check_session_auth(&req.headers, &req.query_params, &self.session_token);
                let resp = SessionResponse {
                    authenticated: is_auth,
                    session_token: self.session_token.clone(),
                    user: std::env::var("USER").unwrap_or_else(|_| "operator".to_string()),
                };
                write_json_response(&mut stream, 200, "OK", &resp)
            }
            ("GET", "/api/snapshot") => {
                let group = req.query_params.get("group").cloned();
                let snapshot_res = self.with_store(|store| {
                    let tasks = store.list_tasks(group.as_deref())?;
                    let open_decisions = store.list_decisions(true, group.as_deref())?;
                    let status = store.status_summary()?;
                    let as_of_seq = store.max_seq_id()?;
                    Ok(SnapshotResponse {
                        tasks,
                        open_decisions,
                        status,
                        as_of_seq,
                    })
                });
                match snapshot_res {
                    Ok(snapshot) => write_json_response(&mut stream, 200, "OK", &snapshot),
                    Err(e) => write_error_response(
                        &mut stream,
                        500,
                        "Internal Server Error",
                        &format!("Failed to query snapshot: {e}"),
                    ),
                }
            }
            ("GET", "/api/events") => {
                let header_seq = req
                    .headers
                    .get("last-event-id")
                    .and_then(|v| v.parse::<i64>().ok());
                let query_seq = req
                    .query_params
                    .get("since_seq")
                    .or_else(|| req.query_params.get("seq_id"))
                    .and_then(|v| v.parse::<i64>().ok());
                let since_seq = header_seq.or(query_seq).unwrap_or(0);
                let group = req.query_params.get("group").cloned();
                stream_sse_events(self, &mut stream, since_seq, group)
            }
            ("POST", "/api/decide") => {
                if !check_session_auth(&req.headers, &req.query_params, &self.session_token) {
                    return write_error_response(
                        &mut stream,
                        401,
                        "Unauthorized",
                        "Missing or invalid session token",
                    );
                }
                let body: DecideRequestBody = match serde_json::from_slice(&req.body) {
                    Ok(b) => b,
                    Err(e) => {
                        return write_error_response(
                            &mut stream,
                            400,
                            "Bad Request",
                            &format!("Invalid decide request JSON: {e}"),
                        );
                    }
                };
                if body.decision_id.trim().is_empty() || body.choice.trim().is_empty() {
                    return write_error_response(
                        &mut stream,
                        400,
                        "Bad Request",
                        "decision_id and choice must not be empty",
                    );
                }
                let actor = body
                    .by
                    .clone()
                    .or_else(|| std::env::var("USER").ok())
                    .unwrap_or_else(|| "operator".to_string());
                let resolution = self.with_store(|store| {
                    store.resolve_decision(
                        &body.decision_id,
                        &body.choice,
                        &actor,
                        body.note.as_deref(),
                    )
                });
                match resolution {
                    Ok(DecisionResolution::Resolved(rec)) => {
                        let resp = DecideResponse {
                            outcome: "RESOLVED".to_string(),
                            decision: Some(rec),
                            error: None,
                        };
                        write_json_response(&mut stream, 200, "OK", &resp)
                    }
                    Ok(DecisionResolution::AlreadyResolved(rec)) => {
                        let resp = DecideResponse {
                            outcome: "ALREADY_RESOLVED".to_string(),
                            decision: Some(rec),
                            error: None,
                        };
                        write_json_response(&mut stream, 200, "OK", &resp)
                    }
                    Ok(DecisionResolution::NotFound) => {
                        let resp = DecideResponse {
                            outcome: "NOT_FOUND".to_string(),
                            decision: None,
                            error: Some(format!("Decision not found: {}", body.decision_id)),
                        };
                        write_json_response(&mut stream, 404, "Not Found", &resp)
                    }
                    Err(e) => write_error_response(
                        &mut stream,
                        500,
                        "Internal Server Error",
                        &format!("Failed to resolve decision: {e}"),
                    ),
                }
            }
            _ => write_error_response(
                &mut stream,
                404,
                "Not Found",
                &format!("No route for {} {}", req.method, req.route),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::store::{ContextPackSpec, TaskRecord};
    use std::io::{BufRead, BufReader};

    fn setup_test_store() -> (V2Store, String) {
        let mut store = V2Store::open_in_memory().unwrap();
        let task = TaskRecord {
            task_id: "TEST-001".to_string(),
            task_group: "test".to_string(),
            title: "Test Task".to_string(),
            repository: "test-repo".to_string(),
            github_repo: None,
            issue_number: None,
            weight: "XS".to_string(),
            status: "Ready".to_string(),
            worktree_path: None,
            branch: None,
            context_pack: ContextPackSpec::default(),
            depends_on: vec![],
            required_stages: vec!["impl".to_string()],
            stages_completed: vec![],
            current_stage: None,
            active_attempt_id: None,
            plan_base_sha: None,
            reviewed_sha: None,
            pr_number: None,
            executor: None,
            autonomous_consent: true,
            retry_count: 0,
            memory: Default::default(),
            version: 1,
            updated_epoch: 1000,
        };
        store.upsert_task(&task).unwrap();

        let dec_id = "DEC-TEST-001".to_string();
        store
            .open_decision(
                &dec_id,
                "TEST-001",
                "test",
                "human-plan-approval",
                "Approve plan?",
                &["APPROVE".to_string(), "REJECT".to_string()],
                Some(0),
                "test context",
                None,
            )
            .unwrap();

        (store, dec_id)
    }

    fn read_test_response(stream: &mut TcpStream) -> (u16, HashMap<String, String>, Vec<u8>) {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        let body_start: usize;
        let status_code: u16;
        let mut headers_map = HashMap::new();

        loop {
            let n = stream.read(&mut tmp).unwrap();
            if n == 0 {
                panic!("stream closed before response headers");
            }
            buf.extend_from_slice(&tmp[..n]);
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut resp = httparse::Response::new(&mut headers);
            match resp.parse(&buf) {
                Ok(httparse::Status::Complete(offset)) => {
                    body_start = offset;
                    status_code = resp.code.unwrap_or(0);
                    for h in resp.headers.iter() {
                        if h.name.is_empty() {
                            break;
                        }
                        headers_map.insert(
                            h.name.to_ascii_lowercase(),
                            String::from_utf8_lossy(h.value).trim().to_string(),
                        );
                    }
                    break;
                }
                Ok(httparse::Status::Partial) => continue,
                Err(e) => panic!("response parse error: {e}"),
            }
        }

        let content_len: usize = headers_map
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut body = buf[body_start..].to_vec();
        while body.len() < content_len {
            let n = stream.read(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        (status_code, headers_map, body)
    }

    #[test]
    fn test_web_gateway_snapshot_and_decide_and_events() {
        let (store, dec_id) = setup_test_store();
        let store_arc = Arc::new(Mutex::new(store));

        // Find an ephemeral open port
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let bind_addr = format!("127.0.0.1:{port}");
        let mut gateway = WebGateway::with_shared_store(
            bind_addr.clone(),
            store_arc.clone(),
            PathBuf::from("/tmp/nonexistent-test.sock"),
        );
        gateway.session_token = "secret-test-session".to_string();

        let gw_clone = gateway.clone();
        let handle = std::thread::spawn(move || {
            let _ = gw_clone.run_loop();
        });

        // Give server time to bind
        std::thread::sleep(Duration::from_millis(100));

        // AC-1: Test GET /api/snapshot
        {
            let mut stream = TcpStream::connect(&bind_addr).unwrap();
            let req = "GET /api/snapshot HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            stream.write_all(req.as_bytes()).unwrap();

            let (code, _headers, body) = read_test_response(&mut stream);
            assert_eq!(code, 200);
            let snap: SnapshotResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(snap.tasks.len(), 1);
            assert_eq!(snap.tasks[0].task_id, "TEST-001");
            assert_eq!(snap.open_decisions.len(), 1);
            assert_eq!(snap.open_decisions[0].decision_id, dec_id);
            assert_eq!(snap.status.schema_version, 2);
        }

        // AC-3: Test unauthenticated POST /api/decide is rejected with 401
        {
            let mut stream = TcpStream::connect(&bind_addr).unwrap();
            let body = serde_json::json!({
                "decision_id": dec_id,
                "choice": "APPROVE"
            })
            .to_string();
            let req = format!(
                "POST /api/decide HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(req.as_bytes()).unwrap();
            let (code, _headers, resp_body) = read_test_response(&mut stream);
            assert_eq!(code, 401);
            let err_val: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
            assert_eq!(err_val["error"], "unauthorized");
        }

        // AC-3: Test authenticated POST /api/decide succeeds
        {
            let mut stream = TcpStream::connect(&bind_addr).unwrap();
            let body = serde_json::json!({
                "decision_id": dec_id,
                "choice": "APPROVE",
                "by": "test-operator",
                "note": "verified"
            })
            .to_string();
            let req = format!(
                "POST /api/decide HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret-test-session\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(req.as_bytes()).unwrap();
            let (code, _headers, resp_body) = read_test_response(&mut stream);
            assert_eq!(code, 200);
            let res: DecideResponse = serde_json::from_slice(&resp_body).unwrap();
            assert_eq!(res.outcome, "RESOLVED");
            assert_eq!(res.decision.unwrap().status, "RESOLVED");
        }

        // AC-3: Second resolve returns ALREADY_RESOLVED
        {
            let mut stream = TcpStream::connect(&bind_addr).unwrap();
            let body = serde_json::json!({
                "decision_id": dec_id,
                "choice": "APPROVE"
            })
            .to_string();
            let req = format!(
                "POST /api/decide HTTP/1.1\r\nHost: localhost\r\nCookie: session=secret-test-session\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(req.as_bytes()).unwrap();
            let (code, _headers, resp_body) = read_test_response(&mut stream);
            assert_eq!(code, 200);
            let res: DecideResponse = serde_json::from_slice(&resp_body).unwrap();
            assert_eq!(res.outcome, "ALREADY_RESOLVED");
        }

        // AC-2: Test GET /api/events SSE stream replays events
        {
            let mut stream = TcpStream::connect(&bind_addr).unwrap();
            let req = "GET /api/events?since_seq=0 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            stream.write_all(req.as_bytes()).unwrap();

            let mut reader = BufReader::new(stream);
            let mut status_line = String::new();
            reader.read_line(&mut status_line).unwrap();
            assert!(status_line.contains("200 OK"));

            let mut found_event = false;
            let mut line = String::new();
            for _ in 0..20 {
                line.clear();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                if line.starts_with("data:") {
                    found_event = true;
                    let event_json = line.strip_prefix("data:").unwrap().trim();
                    let ev: serde_json::Value = serde_json::from_str(event_json).unwrap();
                    assert!(ev["seq_id"].as_i64().unwrap() > 0);
                    break;
                }
            }
            assert!(found_event, "Expected at least one replayed SSE event");
        }

        // Test GET /api/session
        {
            let mut stream = TcpStream::connect(&bind_addr).unwrap();
            let req = "GET /api/session HTTP/1.1\r\nHost: localhost\r\nX-Session-Token: secret-test-session\r\nConnection: close\r\n\r\n";
            stream.write_all(req.as_bytes()).unwrap();
            let (code, _headers, resp_body) = read_test_response(&mut stream);
            assert_eq!(code, 200);
            let sess: SessionResponse = serde_json::from_slice(&resp_body).unwrap();
            assert!(sess.authenticated);
            assert_eq!(sess.session_token, "secret-test-session");
        }

        // Test OPTIONS CORS preflight
        {
            let mut stream = TcpStream::connect(&bind_addr).unwrap();
            let req =
                "OPTIONS /api/decide HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            stream.write_all(req.as_bytes()).unwrap();
            let (code, headers, _) = read_test_response(&mut stream);
            assert_eq!(code, 204);
            assert!(headers.contains_key("access-control-allow-origin"));
            assert!(headers.contains_key("access-control-allow-methods"));
        }

        // Test GET /health
        {
            let mut stream = TcpStream::connect(&bind_addr).unwrap();
            let req = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            stream.write_all(req.as_bytes()).unwrap();
            let (code, _, body) = read_test_response(&mut stream);
            assert_eq!(code, 200);
            let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(val["status"], "healthy");
        }

        // AC-3: Not found decision returns 404
        {
            let mut stream = TcpStream::connect(&bind_addr).unwrap();
            let body = serde_json::json!({
                "decision_id": "DEC-DOES-NOT-EXIST",
                "choice": "APPROVE"
            })
            .to_string();
            let req = format!(
                "POST /api/decide HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret-test-session\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(req.as_bytes()).unwrap();
            let (code, _, resp_body) = read_test_response(&mut stream);
            assert_eq!(code, 404);
            let res: DecideResponse = serde_json::from_slice(&resp_body).unwrap();
            assert_eq!(res.outcome, "NOT_FOUND");
        }

        // AC-2: Test Last-Event-ID header for SSE replay
        {
            let mut stream = TcpStream::connect(&bind_addr).unwrap();
            let req = "GET /api/events HTTP/1.1\r\nHost: localhost\r\nLast-Event-ID: 1000\r\nConnection: close\r\n\r\n";
            stream.write_all(req.as_bytes()).unwrap();

            let mut reader = BufReader::new(stream);
            let mut status_line = String::new();
            reader.read_line(&mut status_line).unwrap();
            assert!(status_line.contains("200 OK"));
        }

        // Test trailing slash normalization: GET /api/snapshot/
        {
            let mut stream = TcpStream::connect(&bind_addr).unwrap();
            let req = "GET /api/snapshot/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            stream.write_all(req.as_bytes()).unwrap();
            let (code, _headers, body) = read_test_response(&mut stream);
            assert_eq!(code, 200);
            let snap: SnapshotResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(snap.tasks.len(), 1);
        }

        // AC-3: Test query parameter authentication: ?token=...
        {
            let mut stream = TcpStream::connect(&bind_addr).unwrap();
            let body = serde_json::json!({
                "decision_id": dec_id,
                "choice": "APPROVE"
            })
            .to_string();
            let req = format!(
                "POST /api/decide?token=secret-test-session HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(req.as_bytes()).unwrap();
            let (code, _headers, resp_body) = read_test_response(&mut stream);
            assert_eq!(code, 200);
            let res: DecideResponse = serde_json::from_slice(&resp_body).unwrap();
            assert_eq!(res.outcome, "ALREADY_RESOLVED");
        }

        gateway.request_shutdown();
        let _ = handle.join();
    }
}
