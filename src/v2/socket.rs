pub const DEFAULT_MAX_BUFFER_LEN: usize = 256;
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(2);

use crate::v2::gemini::TaskExplainInput;
use crate::v2::now_epoch;
use crate::v2::store::{
    AttemptAuditRecord, DaemonStatusSummary, DecisionResolution, PendingDecisionRecord,
    ProviderCooldownRecord, StageAttemptRecord, TaskEventRecord, TaskExplanationRecord, TaskRecord,
    V2Store, V2StoreError,
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ClientCommand {
    #[serde(alias = "SUBSCRIBE", alias = "Subscribe")]
    Subscribe {
        #[serde(default)]
        group: Option<String>,
        #[serde(default)]
        since_seq: Option<i64>,
        #[serde(default)]
        once: Option<bool>,
    },
    #[serde(alias = "STATUS", alias = "Status")]
    Status,
    Run {
        #[serde(default)]
        task: Option<String>,
        #[serde(default)]
        group: Option<String>,
        #[serde(default)]
        once: bool,
    },
    GetDecision {
        decision_id: String,
    },
    #[serde(alias = "GET_TASK_DETAIL", alias = "GetTaskDetail")]
    GetTaskDetail {
        task_id: String,
    },
    #[serde(alias = "DECIDE", alias = "Decide")]
    Decide {
        decision_id: String,
        choice: String,
        #[serde(default)]
        by: Option<String>,
        #[serde(default)]
        note: Option<String>,
    },
    #[serde(alias = "RELOAD_CONFIG", alias = "ReloadConfig")]
    ReloadConfig {
        #[serde(default)]
        path: Option<String>,
    },
    #[serde(alias = "COOLDOWN_LIST", alias = "CooldownList")]
    CooldownList,
    #[serde(alias = "COOLDOWN_CLEAR", alias = "CooldownClear")]
    CooldownClear {
        #[serde(default)]
        family: Option<String>,
    },
    #[serde(alias = "STAGE_RUN", alias = "StageRun")]
    StageRun {
        task: String,
        stage: String,
        #[serde(default)]
        wait: bool,
    },
    #[serde(alias = "ANNOUNCE", alias = "Announce")]
    Announce {
        #[serde(default)]
        holder: Option<String>,
        #[serde(default)]
        executor: Option<String>,
        #[serde(default)]
        actor: Option<String>,
        intent: String,
        #[serde(default)]
        task_id: Option<String>,
        #[serde(default)]
        repo: Option<String>,
        #[serde(default)]
        stage: Option<String>,
        #[serde(default)]
        note: Option<String>,
        #[serde(default)]
        ttl_secs: Option<i64>,
    },
    #[serde(alias = "SESSIONS", alias = "Sessions")]
    Sessions {
        #[serde(default)]
        include_stale: bool,
    },
    #[serde(alias = "EXPLAIN_TASK", alias = "ExplainTask")]
    ExplainTask {
        task_id: String,
        #[serde(default)]
        refresh: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionAnnouncementRecord {
    pub holder: String,
    pub executor: String,
    pub actor: String,
    pub intent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub announced_at_epoch: i64,
    pub ttl_secs: i64,
    pub expires_at_epoch: i64,
}

pub const SESSION_GROUP_NAME: &str = "_sessions";

pub const VALID_SESSION_INTENTS: &[&str] = &[
    "starting",
    "planning",
    "implementing",
    "reviewing",
    "merging",
    "handoff",
    "idle",
    "done",
    "blocked",
    "heartbeat",
];

#[allow(clippy::too_many_arguments)]
pub fn validate_session_announcement(
    holder: Option<&str>,
    executor: Option<&str>,
    actor: Option<&str>,
    intent: &str,
    task_id: Option<&str>,
    repo: Option<&str>,
    stage: Option<&str>,
    note: Option<&str>,
    ttl_secs: Option<i64>,
    now: i64,
) -> Result<SessionAnnouncementRecord, String> {
    if !VALID_SESSION_INTENTS.contains(&intent) {
        return Err(format!(
            "invalid announcement intent '{intent}': must be one of {}",
            VALID_SESSION_INTENTS.join(", ")
        ));
    }
    let holder_str = holder.unwrap_or("cli").trim();
    if holder_str.is_empty()
        || holder_str.len() > 64
        || !holder_str
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("invalid announcement holder".into());
    }
    let executor_str = executor.unwrap_or("session").trim();
    if !matches!(executor_str, "session" | "zach") {
        return Err(format!("invalid announcement executor '{executor_str}'"));
    }
    let actor_str = actor.unwrap_or("unknown").trim();
    if actor_str.is_empty()
        || actor_str.len() > 32
        || !actor_str
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("invalid announcement actor".into());
    }
    let clean_task_id = match task_id.map(str::trim).filter(|s| !s.is_empty()) {
        Some(t) => {
            if t.len() > 32
                || !t.contains('-')
                || !t
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
            {
                return Err(format!("invalid announcement task_id '{t}'"));
            }
            Some(t.to_owned())
        }
        None => None,
    };
    let clean_repo = match repo.map(str::trim).filter(|s| !s.is_empty()) {
        Some(r) => {
            if r.len() > 64
                || !r.chars().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
                })
            {
                return Err(format!("invalid announcement repo '{r}'"));
            }
            Some(r.to_owned())
        }
        None => None,
    };
    let clean_stage = match stage.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => {
            if s.len() > 32
                || !s
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
            {
                return Err(format!("invalid announcement stage '{s}'"));
            }
            Some(s.to_owned())
        }
        None => None,
    };
    let clean_note = match note.map(str::trim).filter(|s| !s.is_empty()) {
        Some(n) => {
            if n.contains('\n') || n.contains('\r') {
                return Err("announcement note must be a single line".into());
            }
            if n.chars().count() > 120 {
                return Err("announcement note exceeds 120 characters".into());
            }
            const FORBIDDEN_SNIPPETS: &[&str] = &[
                "/home/",
                "/etc/",
                "/opt/",
                "/tmp/",
                "/var/",
                "/usr/",
                "/root/",
                "/proc/",
                "/Users/",
                "~/",
                "C:\\",
                "ghp_",
                "gho_",
                "github_pat_",
                "sk-",
                "AKIA",
                "AIza",
                "BEGIN PRIVATE KEY",
                "Bearer ",
            ];
            if FORBIDDEN_SNIPPETS.iter().any(|pat| n.contains(pat)) {
                return Err(
                    "announcement note rejected by ADR-004 content safety (path or secret pattern)"
                        .into(),
                );
            }
            Some(n.to_owned())
        }
        None => None,
    };
    let ttl = ttl_secs.unwrap_or(1800);
    if !(60..=7200).contains(&ttl) {
        return Err("announcement ttl_secs must be between 60 and 7200".into());
    }
    Ok(SessionAnnouncementRecord {
        holder: holder_str.to_owned(),
        executor: executor_str.to_owned(),
        actor: actor_str.to_owned(),
        intent: intent.to_owned(),
        task_id: clean_task_id,
        repo: clean_repo,
        stage: clean_stage,
        note: clean_note,
        announced_at_epoch: now,
        ttl_secs: ttl,
        expires_at_epoch: now + ttl,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
#[allow(clippy::large_enum_variant)]
pub enum ServerMessage {
    #[serde(rename = "SNAPSHOT")]
    Snapshot {
        tasks: Vec<TaskRecord>,
        open_decisions: Vec<PendingDecisionRecord>,
        #[serde(default)]
        board_statuses: std::collections::BTreeMap<String, String>,
        as_of_seq: i64,
    },
    #[serde(rename = "EVENT")]
    Event { event: TaskEventRecord },
    #[serde(rename = "STATUS")]
    Status {
        ok: bool,
        status: DaemonStatusSummary,
    },
    #[serde(rename = "DECISION")]
    Decision {
        decision: Option<PendingDecisionRecord>,
    },
    #[serde(rename = "TASK_DETAIL")]
    TaskDetail {
        task: Option<TaskRecord>,
        attempts: Vec<StageAttemptRecord>,
        audits: Vec<AttemptAuditRecord>,
        decisions: Vec<PendingDecisionRecord>,
    },
    #[serde(rename = "DECISION_RESULT")]
    DecisionResult {
        outcome: String,
        decision: Option<PendingDecisionRecord>,
    },
    #[serde(rename = "RESYNC_REQUIRED")]
    ResyncRequired { last_seq_id: i64 },
    #[serde(rename = "RUN_ACCEPTED")]
    RunAccepted { ready: bool },
    #[serde(rename = "CONFIG_RELOADED")]
    ConfigReloaded {
        ok: bool,
        path: String,
        warnings: Vec<String>,
        error: Option<String>,
    },
    #[serde(rename = "COOLDOWNS")]
    Cooldowns {
        cooldowns: Vec<ProviderCooldownRecord>,
    },
    #[serde(rename = "COOLDOWN_CLEARED")]
    CooldownCleared { cleared: usize },
    #[serde(rename = "STAGE_RUN_RESULT")]
    StageRunResult {
        ok: bool,
        task_id: String,
        stage: String,
        status: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        attempt_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        summary: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        stage_receipt: Option<crate::v2::runner::StageReceiptV1>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    #[serde(rename = "SESSION_ANNOUNCEMENT")]
    SessionAnnouncement {
        ok: bool,
        announcement: SessionAnnouncementRecord,
        seq_id: i64,
    },
    #[serde(rename = "SESSIONS_LIST")]
    SessionsList {
        sessions: Vec<SessionAnnouncementRecord>,
        as_of_seq: i64,
    },
    #[serde(rename = "TASK_EXPLANATION")]
    TaskExplanation {
        ok: bool,
        task_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        explanation: Option<TaskExplanationRecord>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_code: Option<String>,
    },
    #[serde(rename = "ERROR")]
    Error { error: String },
}

pub fn verify_peer_uid(stream: &UnixStream, expected_uid: u32) -> Result<(), String> {
    let fd = stream.as_raw_fd();
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let res = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if res != 0 {
        return Err(format!(
            "getsockopt(SO_PEERCRED) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if ucred.uid != expected_uid {
        return Err(format!(
            "peer UID {} does not match expected UID {}",
            ucred.uid, expected_uid
        ));
    }
    Ok(())
}

pub fn current_euid() -> u32 {
    unsafe { libc::geteuid() }
}

pub fn bind_unix_socket(path: &Path) -> std::io::Result<UnixListener> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub fn write_ndjson<T: Serialize>(stream: &mut UnixStream, message: &T) -> std::io::Result<()> {
    let mut payload = serde_json::to_vec(message)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    payload.push(b'\n');
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

pub struct SubscriberSession {
    pub id: usize,
    pub stream: UnixStream,
    pub task_group: Option<String>,
    pub high_watermark_seq: i64,
    pub buffer: VecDeque<TaskEventRecord>,
    pub max_buffer_len: usize,
    pub is_subscribed: bool,
    pub is_once: bool,
    pub is_evicted: bool,
    pub in_buf: Vec<u8>,
}

impl SubscriberSession {
    pub fn new(
        id: usize,
        stream: UnixStream,
        group: Option<String>,
        since_seq: i64,
        once: bool,
    ) -> Self {
        let _ = stream.set_write_timeout(Some(DEFAULT_WRITE_TIMEOUT));
        let _ = stream.set_read_timeout(Some(DEFAULT_READ_TIMEOUT));
        Self {
            id,
            stream,
            task_group: group,
            high_watermark_seq: since_seq,
            buffer: VecDeque::new(),
            max_buffer_len: DEFAULT_MAX_BUFFER_LEN,
            is_subscribed: false,
            is_once: once,
            is_evicted: false,
            in_buf: Vec::new(),
        }
    }

    pub fn matches_group(&self, group: &str) -> bool {
        match &self.task_group {
            Some(g) => g.eq_ignore_ascii_case(group),
            None => true,
        }
    }

    pub fn enqueue_event(&mut self, event: TaskEventRecord) -> bool {
        if !self.matches_group(&event.task_group) {
            return true;
        }
        if self.buffer.len() >= self.max_buffer_len {
            self.evict_resync_required();
            return false;
        }
        self.buffer.push_back(event);
        true
    }

    pub fn send_message(&mut self, message: &ServerMessage) -> std::io::Result<()> {
        write_ndjson(&mut self.stream, message)
    }

    pub fn send_event(&mut self, event: &TaskEventRecord) -> std::io::Result<()> {
        self.send_message(&ServerMessage::Event {
            event: event.clone(),
        })?;
        self.high_watermark_seq = self.high_watermark_seq.max(event.seq_id);
        Ok(())
    }

    pub fn flush_buffer(&mut self) -> Result<usize, std::io::Error> {
        let mut sent = 0;
        while let Some(event) = self.buffer.pop_front() {
            if event.seq_id > self.high_watermark_seq {
                if let Err(e) = self.send_event(&event) {
                    self.evict_resync_required();
                    return Err(e);
                }
                sent += 1;
            }
        }
        Ok(sent)
    }

    pub fn evict_resync_required(&mut self) {
        if !self.is_evicted {
            self.is_evicted = true;
            let msg = ServerMessage::ResyncRequired {
                last_seq_id: self.high_watermark_seq,
            };
            let _ = write_ndjson(&mut self.stream, &msg);
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

pub fn handle_subscribe(
    session: &mut SubscriberSession,
    store: &V2Store,
    since_seq: Option<i64>,
) -> Result<(), V2StoreError> {
    session.is_subscribed = true;
    let effective_since_seq = since_seq.unwrap_or(0);
    session.high_watermark_seq = effective_since_seq;

    let tasks = store.list_tasks(session.task_group.as_deref())?;
    let open_decisions = store.list_decisions(true, session.task_group.as_deref())?;
    let as_of_seq = store.max_seq_id()?;
    let missed_events =
        store.list_events_since(session.task_group.as_deref(), effective_since_seq, 5000)?;

    let snapshot = ServerMessage::Snapshot {
        tasks,
        open_decisions,
        board_statuses: store.board_statuses(session.task_group.as_deref())?,
        as_of_seq,
    };
    if let Err(e) = session.send_message(&snapshot) {
        session.evict_resync_required();
        return Err(V2StoreError(e.to_string()));
    }

    for event in &missed_events {
        if let Err(e) = session.send_event(event) {
            session.evict_resync_required();
            return Err(V2StoreError(e.to_string()));
        }
    }

    if let Err(e) = session.flush_buffer() {
        return Err(V2StoreError(e.to_string()));
    }

    if session.is_once {
        session.is_evicted = true;
        let _ = session.stream.shutdown(std::net::Shutdown::Both);
    }

    Ok(())
}

pub struct OutboxBroadcaster {
    pub last_broadcast_seq: i64,
}

impl OutboxBroadcaster {
    pub fn new(last_seq: i64) -> Self {
        Self {
            last_broadcast_seq: last_seq,
        }
    }

    pub fn broadcast_new_events(
        &mut self,
        store: &V2Store,
        subscribers: &mut [SubscriberSession],
    ) -> Result<usize, V2StoreError> {
        let events = store.list_events_since(None, self.last_broadcast_seq, 1000)?;
        if events.is_empty() {
            return Ok(0);
        }
        let count = events.len();
        for event in &events {
            self.last_broadcast_seq = self.last_broadcast_seq.max(event.seq_id);
            for sub in subscribers.iter_mut() {
                if !sub.is_subscribed || sub.is_evicted {
                    continue;
                }
                let _ = sub.enqueue_event(event.clone());
            }
        }
        for sub in subscribers.iter_mut() {
            if sub.is_subscribed && !sub.is_evicted {
                let _ = sub.flush_buffer();
            }
        }
        Ok(count)
    }
}

pub struct DaemonServer {
    pub socket_path: PathBuf,
    pub listener: UnixListener,
    pub broadcaster: OutboxBroadcaster,
    pub subscribers: Vec<SubscriberSession>,
    pub next_sub_id: usize,
    pub shutdown: Arc<AtomicBool>,
}

impl DaemonServer {
    pub fn bind(socket_path: &Path, initial_seq: i64) -> std::io::Result<Self> {
        let listener = bind_unix_socket(socket_path)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            socket_path: socket_path.to_path_buf(),
            listener,
            broadcaster: OutboxBroadcaster::new(initial_seq),
            subscribers: Vec::new(),
            next_sub_id: 0,
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    fn accept_new_connections(&mut self) {
        while let Ok((stream, _)) = self.listener.accept() {
            if let Err(e) = verify_peer_uid(&stream, current_euid()) {
                eprintln!("Rejected peer: {e}");
                continue;
            }
            let _ = stream.set_nonblocking(true);
            let _ = stream.set_write_timeout(Some(DEFAULT_WRITE_TIMEOUT));
            self.next_sub_id += 1;
            self.subscribers.push(SubscriberSession::new(
                self.next_sub_id,
                stream,
                None,
                0,
                false,
            ));
        }
    }

    fn read_from_subscriber(sub: &mut SubscriberSession) {
        let mut chunk = [0u8; 4096];
        loop {
            match sub.stream.read(&mut chunk) {
                Ok(0) => {
                    sub.is_evicted = true;
                    break;
                }
                Ok(n) => {
                    sub.in_buf.extend_from_slice(&chunk[..n]);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(_) => {
                    sub.is_evicted = true;
                    break;
                }
            }
        }
    }

    fn process_incoming_commands(
        sub: &mut SubscriberSession,
        store: &mut V2Store,
    ) -> Result<(), V2StoreError> {
        while let Some(pos) = sub.in_buf.iter().position(|&b| b == b'\n') {
            let line_bytes: Vec<u8> = sub.in_buf.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&line_bytes);
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<ClientCommand>(trimmed) {
                Ok(ClientCommand::Subscribe {
                    group,
                    since_seq,
                    once,
                }) => {
                    sub.task_group = group;
                    sub.is_once = once.unwrap_or(false);
                    handle_subscribe(sub, store, since_seq)?;
                }
                Ok(ClientCommand::Status) => {
                    let summary = store.status_summary()?;
                    let msg = ServerMessage::Status {
                        ok: true,
                        status: summary,
                    };
                    let _ = write_ndjson(&mut sub.stream, &msg);
                }
                Ok(ClientCommand::GetDecision { decision_id }) => {
                    let decision = store.get_decision(&decision_id)?;
                    let _ = write_ndjson(&mut sub.stream, &ServerMessage::Decision { decision });
                }
                Ok(ClientCommand::GetTaskDetail { task_id }) => {
                    let msg = build_task_detail_message(store, &task_id)?;
                    let _ = write_ndjson(&mut sub.stream, &msg);
                }
                Ok(ClientCommand::Decide {
                    decision_id,
                    choice,
                    by,
                    note,
                }) => {
                    let resolution = store.resolve_decision(
                        &decision_id,
                        &choice,
                        by.as_deref().unwrap_or("operator"),
                        note.as_deref(),
                    )?;
                    let (outcome, decision) = match resolution {
                        DecisionResolution::Resolved(rec) => ("RESOLVED".to_string(), Some(rec)),
                        DecisionResolution::AlreadyResolved(rec) => {
                            ("ALREADY_RESOLVED".to_string(), Some(rec))
                        }
                        DecisionResolution::NotFound => ("NOT_FOUND".to_string(), None),
                    };
                    let msg = ServerMessage::DecisionResult { outcome, decision };
                    let _ = write_ndjson(&mut sub.stream, &msg);
                }
                Ok(ClientCommand::Run { .. }) => {
                    let _result = write_ndjson(
                        &mut sub.stream,
                        &ServerMessage::Error {
                            error: "run requires coordinator".into(),
                        },
                    );
                }
                Ok(ClientCommand::StageRun { .. }) => {
                    let _result = write_ndjson(
                        &mut sub.stream,
                        &ServerMessage::Error {
                            error: "stage run requires coordinator".into(),
                        },
                    );
                }
                Ok(ClientCommand::ReloadConfig { path }) => {
                    let msg = match crate::v2::router::reload_router_config(
                        path.as_deref().map(std::path::Path::new),
                    ) {
                        Ok((loaded_path, warnings)) => ServerMessage::ConfigReloaded {
                            ok: true,
                            path: loaded_path.display().to_string(),
                            warnings,
                            error: None,
                        },
                        Err(err) => ServerMessage::ConfigReloaded {
                            ok: false,
                            path: path.unwrap_or_else(|| {
                                crate::v2::router::default_router_config_path()
                                    .display()
                                    .to_string()
                            }),
                            warnings: Vec::new(),
                            error: Some(err),
                        },
                    };
                    let _ = write_ndjson(&mut sub.stream, &msg);
                }
                Ok(ClientCommand::CooldownList) => {
                    let cooldowns = store.list_provider_cooldowns(Some(now_epoch()))?;
                    let _ = write_ndjson(&mut sub.stream, &ServerMessage::Cooldowns { cooldowns });
                }
                Ok(ClientCommand::CooldownClear { family }) => {
                    let cleared = store.clear_provider_cooldown(family.as_deref())?;
                    let _ =
                        write_ndjson(&mut sub.stream, &ServerMessage::CooldownCleared { cleared });
                }
                Ok(ClientCommand::Announce {
                    holder,
                    executor,
                    actor,
                    intent,
                    task_id,
                    repo,
                    stage,
                    note,
                    ttl_secs,
                }) => {
                    let now = now_epoch();
                    let msg = match validate_session_announcement(
                        holder.as_deref(),
                        executor.as_deref(),
                        actor.as_deref(),
                        &intent,
                        task_id.as_deref(),
                        repo.as_deref(),
                        stage.as_deref(),
                        note.as_deref(),
                        ttl_secs,
                        now,
                    ) {
                        Ok(announcement) => {
                            let event = store.record_session_announcement(&announcement)?;
                            ServerMessage::SessionAnnouncement {
                                ok: true,
                                announcement,
                                seq_id: event.seq_id,
                            }
                        }
                        Err(error) => ServerMessage::Error { error },
                    };
                    let _ = write_ndjson(&mut sub.stream, &msg);
                }
                Ok(ClientCommand::Sessions { include_stale }) => {
                    let as_of_seq = store.max_seq_id()?;
                    let sessions = store.list_session_announcements(include_stale, now_epoch())?;
                    let _ = write_ndjson(
                        &mut sub.stream,
                        &ServerMessage::SessionsList {
                            sessions,
                            as_of_seq,
                        },
                    );
                }
                Ok(ClientCommand::ExplainTask { task_id, .. }) => {
                    let _ = write_ndjson(
                        &mut sub.stream,
                        &ServerMessage::TaskExplanation {
                            ok: false,
                            task_id,
                            explanation: None,
                            error: Some("explain_task requires coordinator".into()),
                            error_code: Some("UNSUPPORTED".into()),
                        },
                    );
                }
                Err(e) => {
                    let msg = ServerMessage::Error {
                        error: format!("invalid command: {e}"),
                    };
                    let _ = write_ndjson(&mut sub.stream, &msg);
                }
            }
        }
        Ok(())
    }

    pub fn tick(&mut self, store: &mut V2Store) -> Result<usize, V2StoreError> {
        self.accept_new_connections();

        for i in 0..self.subscribers.len() {
            Self::read_from_subscriber(&mut self.subscribers[i]);
            Self::process_incoming_commands(&mut self.subscribers[i], store)?;
        }

        let broadcast_count = self
            .broadcaster
            .broadcast_new_events(store, &mut self.subscribers)?;

        self.subscribers.retain(|s| !s.is_evicted);
        Ok(broadcast_count)
    }

    pub fn run_loop(&mut self, store: &mut V2Store, once: bool) -> Result<(), V2StoreError> {
        if once {
            self.tick(store)?;
            return Ok(());
        }
        while !self.shutdown.load(Ordering::Relaxed) {
            self.tick(store)?;
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }
}

impl Drop for DaemonServer {
    fn drop(&mut self) {
        if self.socket_path.exists() {
            let _ = fs::remove_file(&self.socket_path);
        }
    }
}

static SIGNAL_SHUTDOWN: AtomicBool = AtomicBool::new(false);
extern "C" fn shutdown_signal(_: libc::c_int) {
    SIGNAL_SHUTDOWN.store(true, Ordering::Relaxed);
}

pub fn install_shutdown_signals() -> std::io::Result<()> {
    SIGNAL_SHUTDOWN.store(false, Ordering::Relaxed);
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = shutdown_signal as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) != 0
            || libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// sd_notify is optional and independent of all worker/coordinator jobs.
pub fn sd_notify(message: &str) -> std::io::Result<()> {
    use std::os::linux::net::SocketAddrExt;
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_bytes();
    let socket = std::os::unix::net::UnixDatagram::unbound()?;
    socket.set_nonblocking(true)?;
    if bytes.first() == Some(&b'@') {
        let address = std::os::unix::net::SocketAddr::from_abstract_name(&bytes[1..])?;
        socket.send_to_addr(message.as_bytes(), &address)?;
    } else {
        socket.send_to(message.as_bytes(), Path::new(&path))?;
    }
    Ok(())
}

struct ControlConnection {
    id: usize,
    stream: UnixStream,
    input: Vec<u8>,
    output: VecDeque<Vec<u8>>,
    offset: usize,
    queued_bytes: usize,
    group: Option<String>,
    subscribed: bool,
    once: bool,
    close: bool,
    last_seq: i64,
    replaying: bool,
    replay_in_flight: bool,
    subscribe_requested: bool,
}
impl ControlConnection {
    fn queue(&mut self, message: &ServerMessage) {
        if self.close {
            return;
        }
        let Ok(mut bytes) = serde_json::to_vec(message) else {
            self.close = true;
            return;
        };
        bytes.push(b'\n');
        if self.queued_bytes + bytes.len() > 1024 * 1024 {
            self.close = true;
            return;
        }
        self.queued_bytes += bytes.len();
        self.output.push_back(bytes);
    }
    fn flush(&mut self) {
        let mut budget = 64 * 1024;
        while budget > 0 {
            let Some(front) = self.output.front() else {
                break;
            };
            let end = (self.offset + budget).min(front.len());
            match self.stream.write(&front[self.offset..end]) {
                Ok(0) => {
                    self.close = true;
                    break;
                }
                Ok(n) => {
                    self.offset += n;
                    self.queued_bytes -= n;
                    budget -= n;
                    if self.offset == front.len() {
                        self.output.pop_front();
                        self.offset = 0;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.close = true;
                    break;
                }
            }
        }
        if self.once && self.subscribed && !self.replaying && self.output.is_empty() {
            self.close = true;
        }
    }
}

impl DaemonServer {
    /// Every read, write, accept, channel drain, and input buffer is bounded. No
    /// SQLite or subprocess operation executes on this 50ms socket thread.
    pub fn run_coordinated(
        &mut self,
        handle: crate::v2::coordinator::CoordinatorHandle,
        once: bool,
    ) -> Result<(), String> {
        use crate::v2::coordinator::{CoordinatorEvent, SocketDelivery};
        let mut clients: Vec<ControlConnection> = Vec::new();
        let mut next_id = 0;
        let mut watchdog = std::time::Instant::now() - Duration::from_secs(60);
        let watchdog_period = std::env::var("WATCHDOG_USEC")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(|us| Duration::from_micros((us / 2).max(1)))
            .unwrap_or(Duration::from_secs(5));
        let mut ready_notified = false;
        let mut outcome = Ok(());
        loop {
            let tick_start = std::time::Instant::now();
            if SIGNAL_SHUTDOWN.load(Ordering::Relaxed) || self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            for _ in 0..32 {
                match self.listener.accept() {
                    Ok((stream, _)) => {
                        if clients.len() >= 128 || verify_peer_uid(&stream, current_euid()).is_err()
                        {
                            continue;
                        }
                        stream.set_nonblocking(true).map_err(|e| e.to_string())?;
                        next_id += 1;
                        clients.push(ControlConnection {
                            id: next_id,
                            stream,
                            input: Vec::new(),
                            output: VecDeque::new(),
                            offset: 0,
                            queued_bytes: 0,
                            group: None,
                            subscribed: false,
                            once: false,
                            close: false,
                            last_seq: 0,
                            replaying: false,
                            replay_in_flight: false,
                            subscribe_requested: false,
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e.to_string()),
                }
            }
            for client in &mut clients {
                let mut bytes = [0u8; 4096];
                for _ in 0..16 {
                    match client.stream.read(&mut bytes) {
                        Ok(0) => {
                            client.close = true;
                            break;
                        }
                        Ok(n) => {
                            client.input.extend_from_slice(&bytes[..n]);
                            if client.input.len() > 64 * 1024 {
                                client.close = true;
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => {
                            client.close = true;
                            break;
                        }
                    }
                }
                for _ in 0..16 {
                    let Some(pos) = client.input.iter().position(|b| *b == b'\n') else {
                        break;
                    };
                    let line = client.input.drain(..=pos).collect::<Vec<_>>();
                    match serde_json::from_slice::<ClientCommand>(&line) {
                        Ok(command) => {
                            if let ClientCommand::Subscribe {
                                group,
                                once,
                                since_seq,
                            } = &command
                            {
                                if client.subscribe_requested {
                                    client.queue(&ServerMessage::Error{error:"subscribe once per connection; reconnect to change replay scope".into()});
                                    continue;
                                }
                                client.subscribe_requested = true;
                                client.group = group.clone();
                                client.once = once.unwrap_or(false);
                                client.last_seq = since_seq.unwrap_or(0);
                            }
                            if handle
                                .commands
                                .try_send(CoordinatorEvent::Socket {
                                    client_id: client.id,
                                    command,
                                })
                                .is_err()
                            {
                                client.queue(&ServerMessage::Error {
                                    error: "coordinator busy; retry request".into(),
                                });
                            }
                        }
                        Err(error) => client.queue(&ServerMessage::Error {
                            error: format!("invalid command: {error}"),
                        }),
                    }
                }
            }
            for _ in 0..128 {
                match handle.deliveries.try_recv() {
                    Ok(SocketDelivery::Reply {
                        client_id,
                        messages,
                    }) => {
                        if let Some(client) = clients.iter_mut().find(|c| c.id == client_id) {
                            for message in messages {
                                if let ServerMessage::Snapshot { .. } = &message {
                                    client.subscribed = true;
                                    client.replaying = true;
                                    client.replay_in_flight = false;
                                }
                                if let ServerMessage::RunAccepted { ready: true } = &message {
                                    ready_notified = true;
                                }
                                client.queue(&message);
                            }
                        }
                    }
                    Ok(SocketDelivery::Events(events)) => {
                        for event in events {
                            for client in
                                clients.iter_mut().filter(|c| c.subscribed && !c.replaying)
                            {
                                if event.seq_id > client.last_seq
                                    && client
                                        .group
                                        .as_ref()
                                        .is_none_or(|g| g.eq_ignore_ascii_case(&event.task_group))
                                {
                                    client.queue(&ServerMessage::Event {
                                        event: event.clone(),
                                    });
                                    client.last_seq = event.seq_id;
                                }
                            }
                        }
                    }
                    Ok(SocketDelivery::ReplayPage {
                        client_id,
                        events,
                        as_of_seq,
                    }) => {
                        if let Some(client) = clients.iter_mut().find(|c| c.id == client_id) {
                            let complete = events.len() < 128;
                            for event in events {
                                if event.seq_id > client.last_seq {
                                    client.last_seq = event.seq_id;
                                    client.queue(&ServerMessage::Event { event });
                                }
                            }
                            client.replay_in_flight = false;
                            if complete {
                                client.last_seq = client.last_seq.max(as_of_seq);
                                client.replaying = false;
                            }
                        }
                    }
                    Ok(SocketDelivery::Ready) => {
                        ready_notified = true;
                        if let Err(error) = sd_notify("READY=1") {
                            eprintln!("sd_notify: {error}");
                        }
                    }
                    Ok(SocketDelivery::Stopped) => {
                        self.request_shutdown();
                    }
                    Ok(SocketDelivery::Fatal(error)) => {
                        outcome = Err(error);
                        self.request_shutdown();
                        break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        break;
                    }
                    Err(_) => {
                        outcome = Err("coordinator disconnected".into());
                        self.request_shutdown();
                        break;
                    }
                }
            }
            for client in &mut clients {
                client.flush();
                if client.replaying
                    && !client.replay_in_flight
                    && client.queued_bytes < 128 * 1024
                    && handle
                        .commands
                        .try_send(CoordinatorEvent::Replay {
                            client_id: client.id,
                            group: client.group.clone(),
                            since_seq: client.last_seq,
                        })
                        .is_ok()
                {
                    client.replay_in_flight = true;
                }
            }
            clients.retain(|c| !c.close);
            if watchdog.elapsed() >= watchdog_period {
                if let Err(error) = sd_notify(if ready_notified {
                    "READY=1\nWATCHDOG=1"
                } else {
                    "WATCHDOG=1"
                }) {
                    eprintln!("sd_notify: {error}");
                }
                watchdog = std::time::Instant::now();
            }
            if once {
                break;
            }
            if let Some(remaining) = Duration::from_millis(50).checked_sub(tick_start.elapsed()) {
                std::thread::sleep(remaining);
            }
        }
        if let Err(error) = sd_notify("STOPPING=1") {
            eprintln!("sd_notify: {error}");
        }
        let _shutdown = handle.commands.try_send(CoordinatorEvent::Shutdown);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            match handle.deliveries.recv_timeout(Duration::from_millis(50)) {
                Ok(SocketDelivery::Stopped)
                | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                _ => {}
            }
        }
        outcome
    }
}

fn sanitize_detail_text(raw: &str) -> String {
    let redacted = crate::v2::audit::redact_adr004_text(raw, crate::v2::runner::MAX_SUMMARY_BYTES);
    crate::v2::runner::truncate_utf8_bytes(&redacted, crate::v2::runner::MAX_SUMMARY_BYTES)
}

pub(crate) fn build_task_detail_message(
    store: &V2Store,
    task_id: &str,
) -> Result<ServerMessage, V2StoreError> {
    let Some(mut task) = store.get_task(task_id)? else {
        return Ok(ServerMessage::TaskDetail {
            task: None,
            attempts: Vec::new(),
            audits: Vec::new(),
            decisions: Vec::new(),
        });
    };
    if let Some(ref mut failure) = task.memory.last_check_failure {
        *failure = sanitize_detail_text(failure);
    }
    for entry in &mut task.memory.decisions_log {
        *entry = sanitize_detail_text(entry);
    }

    let mut attempts = store.list_stage_attempts(task_id)?;
    for attempt in &mut attempts {
        if let Some(ref mut summary) = attempt.summary {
            *summary = sanitize_detail_text(summary);
        }
    }

    let mut audits = store.list_attempt_audits(task_id)?;
    for audit in &mut audits {
        if let Some(ref mut error_code) = audit.error_code {
            *error_code = sanitize_detail_text(error_code);
        }
    }

    let mut decisions = store.list_decisions_for_task(task_id)?;
    for decision in &mut decisions {
        decision.context_summary = sanitize_detail_text(&decision.context_summary);
        if let Some(ref mut note) = decision.note {
            *note = sanitize_detail_text(note);
        }
        if let Some(ref mut reason) = decision.retirement_reason {
            *reason = sanitize_detail_text(reason);
        }
    }

    Ok(ServerMessage::TaskDetail {
        task: Some(task),
        attempts,
        audits,
        decisions,
    })
}

pub(crate) fn build_task_explain_input(
    store: &V2Store,
    task_id: &str,
) -> Result<Option<(TaskExplainInput, i64, Option<String>)>, V2StoreError> {
    let ServerMessage::TaskDetail {
        task: Some(task),
        attempts,
        audits: _,
        decisions,
    } = build_task_detail_message(store, task_id)?
    else {
        return Ok(None);
    };
    let updated_epoch = task.updated_epoch;
    let open_decision_id = decisions
        .iter()
        .find(|d| d.status == "OPEN")
        .map(|d| d.decision_id.clone());
    let attempts_summary = attempts
        .iter()
        .rev()
        .take(3)
        .map(|a| {
            let summary = a.summary.as_deref().unwrap_or("");
            if summary.is_empty() {
                format!("{} {}", a.stage, a.status)
            } else {
                format!("{} {}: {}", a.stage, a.status, summary)
            }
        })
        .collect();
    let decisions_summary = decisions
        .iter()
        .filter(|d| d.status == "OPEN")
        .take(2)
        .map(|d| format!("{} [{}]", d.question, d.options.join(", ")))
        .collect();
    let input = TaskExplainInput {
        task_id: task.task_id,
        title: task.title,
        status: task.status,
        current_stage: task.current_stage,
        last_check_failure: task.memory.last_check_failure,
        attempts_summary,
        decisions_summary,
    };
    Ok(Some((input, updated_epoch, open_decision_id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::store::TaskRecord;
    use serde_json::json;
    use std::io::{BufRead, BufReader};

    #[test]
    fn test_socket_permissions_0600_inside_0700_dir() {
        let temp_dir =
            PathBuf::from("target").join(format!("zach-sock-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        let sock_path = temp_dir.join("substate/test.sock");

        let listener = bind_unix_socket(&sock_path).expect("bind socket");
        drop(listener);

        let parent_meta = fs::metadata(sock_path.parent().unwrap()).expect("parent meta");
        assert_eq!(
            parent_meta.permissions().mode() & 0o777,
            0o700,
            "parent state directory must be 0700"
        );

        let sock_meta = fs::metadata(&sock_path).expect("sock meta");
        assert_eq!(
            sock_meta.permissions().mode() & 0o777,
            0o600,
            "socket file must be 0600"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_peer_credential_verification_so_peercred() {
        let (client, server) = UnixStream::pair().expect("unix stream pair");
        let my_uid = current_euid();

        assert!(
            verify_peer_uid(&server, my_uid).is_ok(),
            "valid UID must be accepted"
        );
        assert!(
            verify_peer_uid(&client, my_uid).is_ok(),
            "valid UID from other side must be accepted"
        );

        let wrong_uid = my_uid + 7777;
        let res = verify_peer_uid(&server, wrong_uid);
        assert!(res.is_err(), "mismatched UID must be rejected");
        assert!(
            res.unwrap_err().contains("does not match expected UID"),
            "error should mention mismatched UID"
        );
    }

    #[test]
    fn test_gapless_replay_deduplication_and_outbox_broadcast() {
        let mut store = V2Store::open_in_memory().expect("open store");

        // Seed initial tasks and events
        let task = TaskRecord {
            task_id: "TASK-REPLAY-1".into(),
            task_group: "balance".into(),
            title: "Replay Test".into(),
            repository: "zach".into(),
            github_repo: None,
            issue_number: None,
            weight: "M".into(),
            status: "Ready".into(),
            worktree_path: None,
            branch: None,
            context_pack: Default::default(),
            depends_on: vec![],
            required_stages: vec!["plan".into()],
            stages_completed: vec![],
            current_stage: None,
            active_attempt_id: None,
            plan_base_sha: None,
            reviewed_sha: None,
            pr_number: None,
            executor: None,
            autonomous_consent: true,
            retry_count: 0,
            next_retry_epoch: 0,
            lease_owner: None,
            lease_expires_epoch: None,
            memory: Default::default(),
            version: 1,
            updated_epoch: 100,
        };
        store.upsert_task(&task).expect("upsert task");

        let ev1 = store
            .append_event("TASK-REPLAY-1", "balance", "EV1", &json!({"val": 1}))
            .expect("ev1");
        let ev2 = store
            .append_event("TASK-REPLAY-1", "balance", "EV2", &json!({"val": 2}))
            .expect("ev2");
        let ev3 = store
            .append_event("TASK-REPLAY-1", "balance", "EV3", &json!({"val": 3}))
            .expect("ev3");
        assert_eq!(ev1.seq_id, 1);
        assert_eq!(ev2.seq_id, 2);
        assert_eq!(ev3.seq_id, 3);

        let (client, server) = UnixStream::pair().expect("unix pair");
        let mut session = SubscriberSession::new(1, server, Some("balance".into()), 1, false);

        // Simulate live event arriving and enqueued concurrently before replay completes
        let ev4 = store
            .append_event("TASK-REPLAY-1", "balance", "EV4", &json!({"val": 4}))
            .expect("ev4");
        assert_eq!(ev4.seq_id, 4);
        session.buffer.push_back(ev4.clone());

        // Now run replay protocol starting from since_seq = 1
        handle_subscribe(&mut session, &store, Some(1)).expect("handle_subscribe");

        let mut reader = BufReader::new(client);
        let mut line = String::new();

        // 1. Snapshot message
        reader.read_line(&mut line).expect("read snapshot");
        let snap: serde_json::Value = serde_json::from_str(&line).expect("parse snap");
        assert_eq!(snap["type"], "SNAPSHOT");
        assert_eq!(snap["as_of_seq"], 4);
        assert_eq!(snap["tasks"][0]["task_id"], "TASK-REPLAY-1");
        assert_eq!(snap["board_statuses"], json!({}));
        let mut legacy = snap;
        legacy.as_object_mut().unwrap().remove("board_statuses");
        assert!(
            matches!(serde_json::from_value::<ServerMessage>(legacy).unwrap(),
            ServerMessage::Snapshot { board_statuses, .. } if board_statuses.is_empty())
        );
        line.clear();

        // 2. Historical events since_seq > 1: EV2, EV3, EV4
        reader.read_line(&mut line).expect("read ev2");
        let m2: serde_json::Value = serde_json::from_str(&line).expect("parse ev2");
        assert_eq!(m2["type"], "EVENT");
        assert_eq!(m2["event"]["seq_id"], 2);
        line.clear();

        reader.read_line(&mut line).expect("read ev3");
        let m3: serde_json::Value = serde_json::from_str(&line).expect("parse ev3");
        assert_eq!(m3["type"], "EVENT");
        assert_eq!(m3["event"]["seq_id"], 3);
        line.clear();

        reader.read_line(&mut line).expect("read ev4");
        let m4: serde_json::Value = serde_json::from_str(&line).expect("parse ev4");
        assert_eq!(m4["type"], "EVENT");
        assert_eq!(m4["event"]["seq_id"], 4);
        line.clear();

        // Note: EV4 was also in buffer, but must be deduplicated by high_watermark_seq!
        // Now broadcast a subsequent committed event EV5
        let _ev5 = store
            .append_event("TASK-REPLAY-1", "balance", "EV5", &json!({"val": 5}))
            .expect("ev5");
        let mut broadcaster = OutboxBroadcaster::new(4);
        let sent = broadcaster
            .broadcast_new_events(&store, &mut [session])
            .expect("broadcast");
        assert_eq!(sent, 1);

        reader.read_line(&mut line).expect("read ev5");
        let m5: serde_json::Value = serde_json::from_str(&line).expect("parse ev5");
        assert_eq!(m5["type"], "EVENT");
        assert_eq!(m5["event"]["seq_id"], 5);
        assert_eq!(m5["event"]["payload"]["val"], 5);
    }

    #[test]
    fn test_slow_consumer_eviction_resync_required() {
        let (_client, server) = UnixStream::pair().expect("unix pair");
        let mut session = SubscriberSession::new(1, server, Some("balance".into()), 0, false);
        session.max_buffer_len = 5;

        // Fill buffer up to 5 events
        for i in 1..=5 {
            let ev = TaskEventRecord {
                seq_id: i,
                task_id: "T1".into(),
                task_group: "balance".into(),
                ts_epoch: 100,
                event_type: "STAGE_PROGRESS".into(),
                payload: json!({"step": i}),
            };
            assert!(session.enqueue_event(ev));
        }
        assert_eq!(session.buffer.len(), 5);
        assert!(!session.is_evicted);

        // 6th event exceeds max_buffer_len=5 and triggers RESYNC_REQUIRED eviction
        let ev6 = TaskEventRecord {
            seq_id: 6,
            task_id: "T1".into(),
            task_group: "balance".into(),
            ts_epoch: 100,
            event_type: "STAGE_PROGRESS".into(),
            payload: json!({"step": 6}),
        };
        let ok = session.enqueue_event(ev6);
        assert!(!ok);
        assert!(session.is_evicted);
    }

    #[test]
    fn test_slow_consumer_default_buffer_limit_256() {
        let (_client, server) = UnixStream::pair().expect("unix pair");
        let mut session = SubscriberSession::new(1, server, None, 0, false);
        assert_eq!(session.max_buffer_len, 256);

        for i in 1..=256 {
            let ev = TaskEventRecord {
                seq_id: i,
                task_id: "T1".into(),
                task_group: "default".into(),
                ts_epoch: 100,
                event_type: "TICK".into(),
                payload: json!({}),
            };
            assert!(session.enqueue_event(ev));
        }
        assert_eq!(session.buffer.len(), 256);
        assert!(!session.is_evicted);

        // 257th event exceeds 256
        let ev257 = TaskEventRecord {
            seq_id: 257,
            task_id: "T1".into(),
            task_group: "default".into(),
            ts_epoch: 100,
            event_type: "TICK".into(),
            payload: json!({}),
        };
        assert!(!session.enqueue_event(ev257));
        assert!(session.is_evicted);
    }

    #[test]
    fn test_bidirectional_subscribe_status_and_decide_commands() {
        let temp_dir =
            PathBuf::from("target").join(format!("zach-bidi-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        let sock_path = temp_dir.join("zach.sock");

        let mut store = V2Store::open_in_memory().expect("open store");

        // Seed a task and pending decision
        let task = TaskRecord {
            task_id: "TASK-DEC-1".into(),
            task_group: "balance".into(),
            title: "Decision Test".into(),
            repository: "zach".into(),
            github_repo: None,
            issue_number: None,
            weight: "M".into(),
            status: "Blocked".into(),
            worktree_path: None,
            branch: None,
            context_pack: Default::default(),
            depends_on: vec![],
            required_stages: vec!["plan".into()],
            stages_completed: vec![],
            current_stage: None,
            active_attempt_id: None,
            plan_base_sha: None,
            reviewed_sha: None,
            pr_number: None,
            executor: None,
            autonomous_consent: true,
            retry_count: 0,
            next_retry_epoch: 0,
            lease_owner: None,
            lease_expires_epoch: None,
            memory: Default::default(),
            version: 1,
            updated_epoch: 100,
        };
        store.upsert_task(&task).expect("upsert task");

        store
            .open_decision(
                "DEC-001",
                "TASK-DEC-1",
                "balance",
                "APPROVAL",
                "Approve migration?",
                &["approve".into(), "reject".into()],
                Some(0),
                "Database migration ready",
                None,
            )
            .expect("open decision");

        let mut server = DaemonServer::bind(&sock_path, 0).expect("bind daemon");

        // Client 1: connect and query status
        let client1 = UnixStream::connect(&sock_path).expect("connect client 1");
        let mut write_client1 = client1.try_clone().expect("try clone client 1");
        let mut reader1 = BufReader::new(client1);

        write_ndjson(&mut write_client1, &ClientCommand::Status).expect("write status");

        server.tick(&mut store).expect("server tick");

        let mut line = String::new();
        reader1.read_line(&mut line).expect("read status line");
        let status_resp: serde_json::Value = serde_json::from_str(&line).expect("parse status");
        assert_eq!(status_resp["type"], "STATUS");
        assert_eq!(status_resp["ok"], true);
        assert_eq!(status_resp["status"]["open_decisions_count"], 1);

        let before_lookup = store.status_summary().unwrap();
        write_ndjson(
            &mut write_client1,
            &ClientCommand::GetDecision {
                decision_id: "DEC-001".into(),
            },
        )
        .unwrap();
        server.tick(&mut store).unwrap();
        line.clear();
        reader1.read_line(&mut line).unwrap();
        let lookup: ServerMessage = serde_json::from_str(&line).unwrap();
        assert_eq!(
            lookup,
            ServerMessage::Decision {
                decision: store.get_decision("DEC-001").unwrap()
            }
        );
        assert_eq!(store.status_summary().unwrap(), before_lookup);

        // Client 1: resolve decision
        write_ndjson(
            &mut write_client1,
            &ClientCommand::Decide {
                decision_id: "DEC-001".into(),
                choice: "approve".into(),
                by: Some("alice".into()),
                note: Some("Looks good".into()),
            },
        )
        .expect("write decide");

        server.tick(&mut store).expect("server tick decide");

        line.clear();
        reader1.read_line(&mut line).expect("read decide response");
        let dec_resp: serde_json::Value = serde_json::from_str(&line).expect("parse decide resp");
        assert_eq!(dec_resp["type"], "DECISION_RESULT");
        assert_eq!(dec_resp["outcome"], "RESOLVED");
        assert_eq!(dec_resp["decision"]["choice"].as_str(), Some("approve"));

        let before_lookup = store.status_summary().unwrap();
        for id in ["DEC-001", "missing"] {
            write_ndjson(
                &mut write_client1,
                &ClientCommand::GetDecision {
                    decision_id: id.into(),
                },
            )
            .unwrap();
            server.tick(&mut store).unwrap();
            line.clear();
            reader1.read_line(&mut line).unwrap();
            assert_eq!(
                serde_json::from_str::<ServerMessage>(&line).unwrap(),
                ServerMessage::Decision {
                    decision: store.get_decision(id).unwrap()
                }
            );
        }
        assert_eq!(store.status_summary().unwrap(), before_lookup);

        // Client 1: decide again -> ALREADY_RESOLVED
        write_ndjson(
            &mut write_client1,
            &ClientCommand::Decide {
                decision_id: "DEC-001".into(),
                choice: "approve".into(),
                by: Some("alice".into()),
                note: None,
            },
        )
        .expect("write decide again");

        server.tick(&mut store).expect("server tick decide again");

        line.clear();
        reader1
            .read_line(&mut line)
            .expect("read decide again resp");
        let dec_resp2: serde_json::Value = serde_json::from_str(&line).expect("parse decide 2");
        assert_eq!(dec_resp2["type"], "DECISION_RESULT");
        assert_eq!(dec_resp2["outcome"], "ALREADY_RESOLVED");

        // Client 2: subscribe and verify replay
        let mut client2 = UnixStream::connect(&sock_path).expect("connect client 2");
        write_ndjson(
            &mut client2,
            &ClientCommand::Subscribe {
                group: Some("balance".into()),
                since_seq: Some(0),
                once: Some(true),
            },
        )
        .expect("write subscribe");

        server.tick(&mut store).expect("server tick subscribe");

        let mut reader2 = BufReader::new(client2);
        line.clear();
        reader2.read_line(&mut line).expect("read snapshot line");
        let snap: serde_json::Value = serde_json::from_str(&line).expect("parse snap");
        assert_eq!(snap["type"], "SNAPSHOT");

        // Next line should be an event (DECISION_REQUIRED or DECISION_RESOLVED)
        line.clear();
        reader2.read_line(&mut line).expect("read event line");
        let ev: serde_json::Value = serde_json::from_str(&line).expect("parse ev");
        assert_eq!(ev["type"], "EVENT");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn socket_cooldown_list_and_clear_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!(
            "zach-sock-cooldown-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        let sock_path = temp_dir.join("zach.sock");
        let db_path = temp_dir.join("zach.db");
        let mut store = V2Store::open(&db_path).unwrap();
        store
            .upsert_provider_cooldown("openai-sol", now_epoch() + 1800, "usage limit")
            .unwrap();
        store
            .upsert_provider_cooldown("gemini-agy", now_epoch() + 900, "429")
            .unwrap();

        let mut server = DaemonServer::bind(&sock_path, 0).unwrap();
        let mut client = UnixStream::connect(&sock_path).unwrap();
        write_ndjson(&mut client, &ClientCommand::CooldownList).unwrap();
        server.tick(&mut store).unwrap();

        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let msg: ServerMessage = serde_json::from_str(&line).unwrap();
        match msg {
            ServerMessage::Cooldowns { cooldowns } => assert_eq!(cooldowns.len(), 2),
            other => panic!("expected COOLDOWNS, got {other:?}"),
        }

        write_ndjson(
            &mut client,
            &ClientCommand::CooldownClear {
                family: Some("openai-sol".into()),
            },
        )
        .unwrap();
        server.tick(&mut store).unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        let cleared_msg: ServerMessage = serde_json::from_str(&line).unwrap();
        assert_eq!(cleared_msg, ServerMessage::CooldownCleared { cleared: 1 });

        write_ndjson(&mut client, &ClientCommand::CooldownClear { family: None }).unwrap();
        server.tick(&mut store).unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        let cleared_all: ServerMessage = serde_json::from_str(&line).unwrap();
        assert_eq!(cleared_all, ServerMessage::CooldownCleared { cleared: 1 });

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn announce_and_sessions_socket_commands_validate_adr004_and_broadcast() {
        assert!(
            validate_session_announcement(
                Some("abc123"),
                Some("session"),
                Some("antigravity"),
                "bad-intent",
                None,
                None,
                None,
                None,
                Some(600),
                1000,
            )
            .is_err()
        );
        assert!(
            validate_session_announcement(
                Some("abc123"),
                Some("session"),
                Some("antigravity"),
                "implementing",
                Some("ZACH-079"),
                Some("zach"),
                Some("impl"),
                Some("editing /home/ubuntu/secret"),
                Some(600),
                1000,
            )
            .is_err()
        );
        assert!(
            validate_session_announcement(
                Some("abc123"),
                Some("session"),
                Some("antigravity"),
                "implementing",
                Some("ZACH-079"),
                Some("zach"),
                Some("impl"),
                Some("token ghp_1234567890abcdef"),
                Some(600),
                1000,
            )
            .is_err()
        );
        let wire = r#"{"cmd":"announce","holder":"deadbeef1234","executor":"session","actor":"antigravity","intent":"implementing","task_id":"ZACH-079","repo":"zach","stage":"impl","note":"Layer 2 wire check","ttl_secs":900}"#;
        let parsed: ClientCommand = serde_json::from_str(wire).unwrap();
        assert!(matches!(parsed, ClientCommand::Announce { .. }));

        let temp_dir =
            std::env::temp_dir().join(format!("zach-sock-sessions-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        let sock_path = temp_dir.join("zach.sock");
        let mut store = V2Store::open_in_memory().unwrap();
        let mut server = DaemonServer::bind(&sock_path, 0).unwrap();

        let mut client = UnixStream::connect(&sock_path).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write_ndjson(&mut client, &parsed).unwrap();
        server.tick(&mut store).unwrap();

        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let reply: ServerMessage = serde_json::from_str(&line).unwrap();
        match reply {
            ServerMessage::SessionAnnouncement {
                ok,
                announcement,
                seq_id,
            } => {
                assert!(ok);
                assert_eq!(announcement.holder, "deadbeef1234");
                assert!(seq_id > 0);
            }
            other => panic!("expected SESSION_ANNOUNCEMENT, got {other:?}"),
        }

        write_ndjson(
            &mut client,
            &ClientCommand::Sessions {
                include_stale: false,
            },
        )
        .unwrap();
        server.tick(&mut store).unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        let list_reply: ServerMessage = serde_json::from_str(&line).unwrap();
        match list_reply {
            ServerMessage::SessionsList {
                sessions,
                as_of_seq,
            } => {
                assert_eq!(sessions.len(), 1);
                assert_eq!(sessions[0].task_id.as_deref(), Some("ZACH-079"));
                assert!(as_of_seq > 0);
            }
            other => panic!("expected SESSIONS_LIST, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
