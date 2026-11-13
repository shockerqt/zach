pub mod coordinator;
pub mod delivery;
pub mod intake;
pub mod isolation;
pub mod merge_queue;
pub mod pipeline;
pub mod router;
pub mod runner;
pub mod scheduler;
pub mod socket;
pub mod store;
pub mod web_gateway;

use std::env;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: u32 = 4;
pub const DEFAULT_WEB_PORT: u16 = 8096;

pub fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn default_state_dir() -> PathBuf {
    if let Ok(dir) = env::var("ZACH_STATE_DIR")
        && !dir.trim().is_empty()
    {
        return PathBuf::from(dir);
    }
    if let Ok(xdg) = env::var("XDG_STATE_HOME")
        && !xdg.trim().is_empty()
    {
        return PathBuf::from(xdg).join("zach");
    }
    let home = env::var("HOME").unwrap_or_else(|_| "/home/ubuntu".to_owned());
    PathBuf::from(home).join(".local/state/zach")
}

pub fn default_db_path() -> PathBuf {
    if let Ok(path) = env::var("ZACH_DB_PATH")
        && !path.trim().is_empty()
    {
        return PathBuf::from(path);
    }
    default_state_dir().join("zach-v2.sqlite3")
}

pub fn default_socket_path() -> PathBuf {
    if let Ok(path) = env::var("ZACH_SOCKET_PATH")
        && !path.trim().is_empty()
    {
        return PathBuf::from(path);
    }
    default_state_dir().join("zach.sock")
}

pub fn default_ws_task_bin() -> PathBuf {
    if let Ok(bin) = env::var("ZACH_WS_TASK_BIN")
        && !bin.trim().is_empty()
    {
        return PathBuf::from(bin);
    }
    PathBuf::from("/home/ubuntu/workspace/governance/bin/ws-task")
}

pub fn default_gemini_worker_cli() -> PathBuf {
    if let Ok(script) = env::var("ZACH_GEMINI_WORKER_CLI")
        && !script.trim().is_empty()
    {
        return PathBuf::from(script);
    }
    PathBuf::from("/home/ubuntu/workspace/agent-tooling/plugins/gemini-worker/scripts/worker.mjs")
}
