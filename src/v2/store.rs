use crate::v2::{SCHEMA_VERSION, now_epoch};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2StoreError(pub String);

impl fmt::Display for V2StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for V2StoreError {}

impl From<rusqlite::Error> for V2StoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self(value.to_string())
    }
}

impl From<serde_json::Error> for V2StoreError {
    fn from(value: serde_json::Error) -> Self {
        Self(value.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TargetFileSpec {
    pub path: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AcceptanceCriterionSpec {
    pub id: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ContextPackSpec {
    #[serde(default)]
    pub weight: String,
    #[serde(default)]
    pub base_sha: Option<String>,
    #[serde(default)]
    pub target_files: Vec<TargetFileSpec>,
    #[serde(default)]
    pub forbidden_paths: Vec<String>,
    #[serde(default)]
    pub worker_checks: Vec<String>,
    #[serde(default)]
    pub gate_checks: Vec<String>,
    #[serde(default)]
    pub human_operations: Vec<String>,
    #[serde(default)]
    pub verification_commands: Vec<String>,
    #[serde(default)]
    pub acceptance_criteria: Vec<AcceptanceCriterionSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TaskMemory {
    #[serde(default)]
    pub decisions_log: Vec<String>,
    #[serde(default)]
    pub recent_attempts: Vec<String>,
    #[serde(default)]
    pub token_usage_by_stage: BTreeMap<String, u64>,
    #[serde(default)]
    pub last_check_failure: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskRecord {
    pub task_id: String,
    pub task_group: String,
    pub title: String,
    pub repository: String,
    pub github_repo: Option<String>,
    pub issue_number: Option<i64>,
    pub weight: String,
    pub status: String,
    pub worktree_path: Option<String>,
    pub branch: Option<String>,
    pub context_pack: ContextPackSpec,
    pub depends_on: Vec<String>,
    pub required_stages: Vec<String>,
    pub stages_completed: Vec<String>,
    pub current_stage: Option<String>,
    pub active_attempt_id: Option<String>,
    pub plan_base_sha: Option<String>,
    pub reviewed_sha: Option<String>,
    pub pr_number: Option<i64>,
    pub executor: Option<String>,
    pub autonomous_consent: bool,
    pub retry_count: i64,
    pub memory: TaskMemory,
    pub version: i64,
    pub updated_epoch: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StageAttemptRecord {
    pub attempt_id: String,
    pub task_id: String,
    pub stage: String,
    pub model: String,
    pub effort: String,
    pub systemd_unit: Option<String>,
    pub invocation_id: Option<String>,
    pub started_epoch: i64,
    pub ended_epoch: Option<i64>,
    pub status: String,
    pub failure_class: Option<String>,
    pub summary: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub sha_before: Option<String>,
    pub sha_after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskEventRecord {
    pub seq_id: i64,
    pub task_id: String,
    pub task_group: String,
    pub ts_epoch: i64,
    pub event_type: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingDecisionRecord {
    pub decision_id: String,
    pub task_id: String,
    pub task_group: String,
    pub kind: String,
    pub question: String,
    pub options: Vec<String>,
    pub recommended_option: Option<usize>,
    pub context_summary: String,
    pub sha: Option<String>,
    pub status: String,
    pub created_seq: i64,
    pub resolved_by: Option<String>,
    pub resolved_epoch: Option<i64>,
    pub choice: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathLockRecord {
    pub repo: String,
    pub path: String,
    pub task_id: String,
    pub acquired_epoch: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MergeQueueRecord {
    pub repo: String,
    pub task_id: String,
    pub pr_number: i64,
    pub reviewed_sha: String,
    pub enqueued_epoch: i64,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DecisionResolution {
    Resolved(PendingDecisionRecord),
    AlreadyResolved(PendingDecisionRecord),
    NotFound,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonStatusSummary {
    pub schema_version: u32,
    pub max_parallel_tasks: usize,
    pub heartbeat_epoch: i64,
    pub max_seq_id: i64,
    pub total_tasks: usize,
    pub ready_eligible_count: usize,
    pub in_progress_count: usize,
    pub open_decisions_count: usize,
    pub active_locks_count: usize,
    pub merge_queue_count: usize,
}

pub struct V2Store {
    conn: Connection,
}

impl V2Store {
    pub fn open(path: &Path) -> Result<Self, V2StoreError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| V2StoreError(e.to_string()))?;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_millis(5_000))?;
        let mut store = Self { conn };
        store.initialize()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, V2StoreError> {
        let conn = Connection::open_in_memory()?;
        let mut store = Self { conn };
        store.initialize()?;
        Ok(store)
    }

    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    fn initialize(&mut self) -> Result<(), V2StoreError> {
        self.conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;

             CREATE TABLE IF NOT EXISTS daemon_meta (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS tasks (
                 task_id TEXT PRIMARY KEY,
                 task_group TEXT NOT NULL,
                 title TEXT NOT NULL,
                 repository TEXT NOT NULL,
                 github_repo TEXT,
                 issue_number INTEGER,
                 weight TEXT NOT NULL,
                 status TEXT NOT NULL,
                 worktree_path TEXT,
                 branch TEXT,
                 context_pack_json TEXT NOT NULL,
                 depends_on_json TEXT NOT NULL,
                 required_stages_json TEXT NOT NULL,
                 stages_completed_json TEXT NOT NULL,
                 current_stage TEXT,
                 active_attempt_id TEXT,
                 plan_base_sha TEXT,
                 reviewed_sha TEXT,
                 pr_number INTEGER,
                 executor TEXT,
                 autonomous_consent INTEGER NOT NULL DEFAULT 1,
                 retry_count INTEGER NOT NULL DEFAULT 0,
                 memory_json TEXT NOT NULL DEFAULT '{}',
                 version INTEGER NOT NULL DEFAULT 1,
                 updated_epoch INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS stage_attempts (
                 attempt_id TEXT PRIMARY KEY,
                 task_id TEXT NOT NULL,
                 stage TEXT NOT NULL,
                 model TEXT NOT NULL,
                 effort TEXT NOT NULL,
                 systemd_unit TEXT,
                 invocation_id TEXT,
                 started_epoch INTEGER NOT NULL,
                 ended_epoch INTEGER,
                 status TEXT NOT NULL,
                 failure_class TEXT,
                 summary TEXT,
                 input_tokens INTEGER NOT NULL DEFAULT 0,
                 output_tokens INTEGER NOT NULL DEFAULT 0,
                 total_tokens INTEGER NOT NULL DEFAULT 0,
                 sha_before TEXT,
                 sha_after TEXT,
                 FOREIGN KEY(task_id) REFERENCES tasks(task_id)
             );

             CREATE TABLE IF NOT EXISTS task_events (
                 seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                 task_id TEXT NOT NULL,
                 task_group TEXT NOT NULL,
                 ts_epoch INTEGER NOT NULL,
                 event_type TEXT NOT NULL,
                 payload_json TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_task_events_group_seq
                 ON task_events(task_group, seq_id);

             CREATE TABLE IF NOT EXISTS pending_decisions (
                 decision_id TEXT PRIMARY KEY,
                 task_id TEXT NOT NULL,
                 task_group TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 question TEXT NOT NULL,
                 options_json TEXT NOT NULL,
                 recommended_option INTEGER,
                 context_summary TEXT NOT NULL,
                 sha TEXT,
                 status TEXT NOT NULL CHECK(status IN ('OPEN', 'RESOLVED')),
                 created_seq INTEGER NOT NULL,
                 resolved_by TEXT,
                 resolved_epoch INTEGER,
                 choice TEXT,
                 note TEXT,
                 FOREIGN KEY(task_id) REFERENCES tasks(task_id)
             );

             CREATE TABLE IF NOT EXISTS path_locks (
                 repo TEXT NOT NULL,
                 path TEXT NOT NULL,
                 task_id TEXT NOT NULL,
                 acquired_epoch INTEGER NOT NULL,
                 PRIMARY KEY(repo, path)
             );

             CREATE TABLE IF NOT EXISTS merge_queue (
                 repo TEXT NOT NULL,
                 task_id TEXT NOT NULL,
                 pr_number INTEGER NOT NULL,
                 reviewed_sha TEXT NOT NULL,
                 enqueued_epoch INTEGER NOT NULL,
                 state TEXT NOT NULL,
                 PRIMARY KEY(repo, task_id)
             );",
        )?;

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO daemon_meta(key, value) VALUES('schema_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![SCHEMA_VERSION.to_string()],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO daemon_meta(key, value) VALUES('max_parallel_tasks', '2')",
            [],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO daemon_meta(key, value) VALUES('heartbeat_epoch', ?1)",
            params![now_epoch().to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_heartbeat(&mut self, ts_epoch: i64) -> Result<(), V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO daemon_meta(key, value) VALUES('heartbeat_epoch', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![ts_epoch.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn set_max_parallel_tasks(&mut self, max_parallel: usize) -> Result<(), V2StoreError> {
        if max_parallel == 0 || max_parallel > 16 {
            return Err(V2StoreError(
                "max_parallel_tasks must be between 1 and 16".into(),
            ));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO daemon_meta(key, value) VALUES('max_parallel_tasks', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![max_parallel.to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn max_parallel_tasks(&self) -> Result<usize, V2StoreError> {
        let val: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM daemon_meta WHERE key = 'max_parallel_tasks'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(val
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(2)
            .clamp(1, 16))
    }

    fn get_task_tx(
        tx: &rusqlite::Transaction<'_>,
        task_id: &str,
    ) -> Result<Option<TaskRecord>, V2StoreError> {
        let mut stmt = tx.prepare(
            "SELECT task_id, task_group, title, repository, github_repo, issue_number,
                    weight, status, worktree_path, branch, context_pack_json,
                    depends_on_json, required_stages_json, stages_completed_json,
                    current_stage, active_attempt_id, plan_base_sha, reviewed_sha,
                    pr_number, executor, autonomous_consent, retry_count, memory_json,
                    version, updated_epoch
             FROM tasks WHERE task_id = ?1",
        )?;
        stmt.query_row(params![task_id], Self::map_task_row)
            .optional()
            .map_err(V2StoreError::from)
    }

    fn insert_task_tx(
        tx: &rusqlite::Transaction<'_>,
        task: &TaskRecord,
        now: i64,
    ) -> Result<TaskRecord, V2StoreError> {
        let context_pack_json = serde_json::to_string(&task.context_pack)?;
        let depends_on_json = serde_json::to_string(&task.depends_on)?;
        let required_stages_json = serde_json::to_string(&task.required_stages)?;
        let stages_completed_json = serde_json::to_string(&task.stages_completed)?;
        let memory_json = serde_json::to_string(&task.memory)?;
        tx.execute(
            "INSERT INTO tasks (
                task_id, task_group, title, repository, github_repo, issue_number,
                weight, status, worktree_path, branch, context_pack_json,
                depends_on_json, required_stages_json, stages_completed_json,
                current_stage, active_attempt_id, plan_base_sha, reviewed_sha,
                pr_number, executor, autonomous_consent, retry_count, memory_json,
                version, updated_epoch
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6,
                ?7, ?8, ?9, ?10, ?11,
                ?12, ?13, ?14,
                ?15, ?16, ?17, ?18,
                ?19, ?20, ?21, ?22, ?23,
                1, ?24
             )",
            params![
                task.task_id,
                task.task_group,
                task.title,
                task.repository,
                task.github_repo,
                task.issue_number,
                task.weight,
                task.status,
                task.worktree_path,
                task.branch,
                context_pack_json,
                depends_on_json,
                required_stages_json,
                stages_completed_json,
                task.current_stage,
                task.active_attempt_id,
                task.plan_base_sha,
                task.reviewed_sha,
                task.pr_number,
                task.executor,
                i64::from(task.autonomous_consent),
                task.retry_count,
                memory_json,
                now,
            ],
        )?;
        let mut inserted = task.clone();
        inserted.version = 1;
        inserted.updated_epoch = now;
        Ok(inserted)
    }

    fn update_task_tx(
        tx: &rusqlite::Transaction<'_>,
        old: &TaskRecord,
        next: &TaskRecord,
        now: i64,
    ) -> Result<TaskRecord, V2StoreError> {
        let context_pack_json = serde_json::to_string(&next.context_pack)?;
        let depends_on_json = serde_json::to_string(&next.depends_on)?;
        let required_stages_json = serde_json::to_string(&next.required_stages)?;
        let stages_completed_json = serde_json::to_string(&next.stages_completed)?;
        let memory_json = serde_json::to_string(&next.memory)?;
        let next_ver = old.version + 1;

        tx.execute(
            "UPDATE tasks SET
                task_group = ?2,
                title = ?3,
                repository = ?4,
                github_repo = ?5,
                issue_number = ?6,
                weight = ?7,
                status = ?8,
                worktree_path = ?9,
                branch = ?10,
                context_pack_json = ?11,
                depends_on_json = ?12,
                required_stages_json = ?13,
                stages_completed_json = ?14,
                current_stage = ?15,
                active_attempt_id = ?16,
                plan_base_sha = ?17,
                reviewed_sha = ?18,
                pr_number = ?19,
                executor = ?20,
                autonomous_consent = ?21,
                retry_count = ?22,
                memory_json = ?23,
                version = ?24,
                updated_epoch = ?25
             WHERE task_id = ?1 AND version = ?26",
            params![
                next.task_id,
                next.task_group,
                next.title,
                next.repository,
                next.github_repo,
                next.issue_number,
                next.weight,
                next.status,
                next.worktree_path,
                next.branch,
                context_pack_json,
                depends_on_json,
                required_stages_json,
                stages_completed_json,
                next.current_stage,
                next.active_attempt_id,
                next.plan_base_sha,
                next.reviewed_sha,
                next.pr_number,
                next.executor,
                i64::from(next.autonomous_consent),
                next.retry_count,
                memory_json,
                next_ver,
                now,
                old.version,
            ],
        )?;

        if old.weight != next.weight {
            Self::insert_event_tx(
                tx,
                &next.task_id,
                &next.task_group,
                now,
                "WEIGHT_ESCALATED",
                &serde_json::json!({
                    "from_weight": old.weight,
                    "to_weight": next.weight,
                }),
            )?;
        }
        if old.status != next.status && next.status.eq_ignore_ascii_case("Done") {
            Self::insert_event_tx(
                tx,
                &next.task_id,
                &next.task_group,
                now,
                "TASK_DONE",
                &serde_json::json!({ "status": next.status }),
            )?;
        }

        let mut updated = next.clone();
        updated.version = next_ver;
        updated.updated_epoch = now;
        Ok(updated)
    }

    pub fn upsert_task(&mut self, task: &TaskRecord) -> Result<TaskRecord, V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = if task.updated_epoch > 0 {
            task.updated_epoch
        } else {
            now_epoch()
        };
        let result = match Self::get_task_tx(&tx, &task.task_id)? {
            Some(old) => {
                let mut next = task.clone();
                coalesce_runtime_fields(&old, &mut next);
                Self::update_task_tx(&tx, &old, &next, now)?
            }
            None => Self::insert_task_tx(&tx, task, now)?,
        };
        tx.commit()?;
        Ok(result)
    }

    /// Syncs a board-exported task record into the store while preserving Zach-owned
    /// runtime state for active (non-terminal) tasks unless the board status is terminal.
    pub fn sync_task(&mut self, incoming: &TaskRecord) -> Result<TaskRecord, V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = if incoming.updated_epoch > 0 {
            incoming.updated_epoch
        } else {
            now_epoch()
        };
        let result = match Self::get_task_tx(&tx, &incoming.task_id)? {
            Some(old) => {
                let mut next = incoming.clone();
                if should_preserve_zach_state(&old, incoming) {
                    next.status = old.status.clone();
                    next.stages_completed = old.stages_completed.clone();
                    next.current_stage = old.current_stage.clone();
                    next.active_attempt_id = old.active_attempt_id.clone();
                    next.plan_base_sha = old.plan_base_sha.clone();
                    next.reviewed_sha = old.reviewed_sha.clone();
                    next.pr_number = old.pr_number;
                    next.executor = old.executor.clone();
                    next.retry_count = old.retry_count;
                    next.memory = old.memory.clone();
                } else {
                    coalesce_runtime_fields(&old, &mut next);
                    next.retry_count = old.retry_count.max(next.retry_count);
                }
                Self::update_task_tx(&tx, &old, &next, now)?
            }
            None => Self::insert_task_tx(&tx, incoming, now)?,
        };
        tx.commit()?;
        Ok(result)
    }

    pub fn get_task(&self, task_id: &str) -> Result<Option<TaskRecord>, V2StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT task_id, task_group, title, repository, github_repo, issue_number,
                    weight, status, worktree_path, branch, context_pack_json,
                    depends_on_json, required_stages_json, stages_completed_json,
                    current_stage, active_attempt_id, plan_base_sha, reviewed_sha,
                    pr_number, executor, autonomous_consent, retry_count, memory_json,
                    version, updated_epoch
             FROM tasks WHERE task_id = ?1",
        )?;
        stmt.query_row(params![task_id], Self::map_task_row)
            .optional()
            .map_err(V2StoreError::from)
    }

    pub fn list_tasks(&self, group_filter: Option<&str>) -> Result<Vec<TaskRecord>, V2StoreError> {
        let mut out = Vec::new();
        if let Some(group) = group_filter {
            let mut stmt = self.conn.prepare(
                "SELECT task_id, task_group, title, repository, github_repo, issue_number,
                        weight, status, worktree_path, branch, context_pack_json,
                        depends_on_json, required_stages_json, stages_completed_json,
                        current_stage, active_attempt_id, plan_base_sha, reviewed_sha,
                        pr_number, executor, autonomous_consent, retry_count, memory_json,
                        version, updated_epoch
                 FROM tasks WHERE LOWER(task_group) = LOWER(?1) ORDER BY task_id ASC",
            )?;
            let rows = stmt.query_map(params![group], Self::map_task_row)?;
            for r in rows {
                out.push(r?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT task_id, task_group, title, repository, github_repo, issue_number,
                        weight, status, worktree_path, branch, context_pack_json,
                        depends_on_json, required_stages_json, stages_completed_json,
                        current_stage, active_attempt_id, plan_base_sha, reviewed_sha,
                        pr_number, executor, autonomous_consent, retry_count, memory_json,
                        version, updated_epoch
                 FROM tasks ORDER BY task_id ASC",
            )?;
            let rows = stmt.query_map([], Self::map_task_row)?;
            for r in rows {
                out.push(r?);
            }
        }
        Ok(out)
    }

    pub fn list_ready_queue(
        &self,
        group_filter: Option<&str>,
    ) -> Result<Vec<TaskRecord>, V2StoreError> {
        let all_tasks = self.list_tasks(None)?;
        let done_ids: BTreeSet<String> = all_tasks
            .iter()
            .filter(|t| t.status == "Done")
            .map(|t| t.task_id.clone())
            .collect();
        let open_decisions = self.list_decisions(true, None)?;
        let blocked_by_decision: BTreeSet<String> =
            open_decisions.iter().map(|d| d.task_id.clone()).collect();

        let mut eligible = Vec::new();
        for task in all_tasks {
            if let Some(group) = group_filter
                && !task.task_group.eq_ignore_ascii_case(group)
            {
                continue;
            }
            if task.status != "Ready" || !task.autonomous_consent {
                continue;
            }
            if blocked_by_decision.contains(&task.task_id) {
                continue;
            }
            if task.depends_on.iter().all(|dep| done_ids.contains(dep)) {
                eligible.push(task);
            }
        }
        Ok(eligible)
    }

    pub fn append_event(
        &mut self,
        task_id: &str,
        task_group: &str,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<TaskEventRecord, V2StoreError> {
        let now = now_epoch();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let seq_id = Self::insert_event_tx(&tx, task_id, task_group, now, event_type, payload)?;
        tx.commit()?;
        Ok(TaskEventRecord {
            seq_id,
            task_id: task_id.to_owned(),
            task_group: task_group.to_owned(),
            ts_epoch: now,
            event_type: event_type.to_owned(),
            payload: payload.clone(),
        })
    }

    fn insert_event_tx(
        tx: &rusqlite::Transaction<'_>,
        task_id: &str,
        task_group: &str,
        ts_epoch: i64,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<i64, V2StoreError> {
        let payload_json = serde_json::to_string(payload)?;
        tx.execute(
            "INSERT INTO task_events(task_id, task_group, ts_epoch, event_type, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![task_id, task_group, ts_epoch, event_type, payload_json],
        )?;
        Ok(tx.last_insert_rowid())
    }

    pub fn list_events_since(
        &self,
        group_filter: Option<&str>,
        since_seq: i64,
        limit: usize,
    ) -> Result<Vec<TaskEventRecord>, V2StoreError> {
        let mut events = Vec::new();
        let cap = limit.clamp(1, 5000) as i64;
        if let Some(group) = group_filter {
            let mut stmt = self.conn.prepare(
                "SELECT seq_id, task_id, task_group, ts_epoch, event_type, payload_json
                 FROM task_events
                 WHERE LOWER(task_group) = LOWER(?1) AND seq_id > ?2
                 ORDER BY seq_id ASC LIMIT ?3",
            )?;
            let rows = stmt.query_map(params![group, since_seq, cap], Self::map_event_row)?;
            for row in rows {
                events.push(row?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT seq_id, task_id, task_group, ts_epoch, event_type, payload_json
                 FROM task_events
                 WHERE seq_id > ?1
                 ORDER BY seq_id ASC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![since_seq, cap], Self::map_event_row)?;
            for row in rows {
                events.push(row?);
            }
        }
        Ok(events)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_decision(
        &mut self,
        decision_id: &str,
        task_id: &str,
        task_group: &str,
        kind: &str,
        question: &str,
        options: &[String],
        recommended_option: Option<usize>,
        context_summary: &str,
        sha: Option<&str>,
    ) -> Result<PendingDecisionRecord, V2StoreError> {
        let now = now_epoch();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let seq_id = Self::insert_event_tx(
            &tx,
            task_id,
            task_group,
            now,
            "DECISION_REQUIRED",
            &serde_json::json!({
                "decision_id": decision_id,
                "kind": kind,
                "question": question,
                "options": options,
                "recommended_option": recommended_option,
                "sha": sha,
            }),
        )?;
        let options_json = serde_json::to_string(options)?;
        tx.execute(
            "INSERT INTO pending_decisions (
                decision_id, task_id, task_group, kind, question, options_json,
                recommended_option, context_summary, sha, status, created_seq
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'OPEN', ?10)
             ON CONFLICT(decision_id) DO NOTHING",
            params![
                decision_id,
                task_id,
                task_group,
                kind,
                question,
                options_json,
                recommended_option.map(|v| v as i64),
                context_summary,
                sha,
                seq_id,
            ],
        )?;
        tx.execute(
            "UPDATE tasks SET status = 'Blocked', version = version + 1, updated_epoch = ?2 WHERE task_id = ?1",
            params![task_id, now],
        )?;
        tx.commit()?;
        self.get_decision(decision_id)?
            .ok_or_else(|| V2StoreError("Failed to read created decision".into()))
    }

    pub fn resolve_decision(
        &mut self,
        decision_id: &str,
        choice: &str,
        resolved_by: &str,
        note: Option<&str>,
    ) -> Result<DecisionResolution, V2StoreError> {
        let now = now_epoch();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE pending_decisions
             SET status = 'RESOLVED', choice = ?2, resolved_by = ?3, resolved_epoch = ?4, note = ?5
             WHERE decision_id = ?1 AND status = 'OPEN'",
            params![decision_id, choice, resolved_by, now, note],
        )?;
        if changed == 0 {
            tx.commit()?;
            return match self.get_decision(decision_id)? {
                Some(existing) => Ok(DecisionResolution::AlreadyResolved(existing)),
                None => Ok(DecisionResolution::NotFound),
            };
        }
        let (task_id, task_group, kind): (String, String, String) = tx.query_row(
            "SELECT task_id, task_group, kind FROM pending_decisions WHERE decision_id = ?1",
            params![decision_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

        let memory_str: String = tx
            .query_row(
                "SELECT memory_json FROM tasks WHERE task_id = ?1",
                params![task_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_else(|| "{}".to_owned());
        let mut memory: TaskMemory = serde_json::from_str(&memory_str).unwrap_or_default();
        memory.decisions_log.push(format!(
            "[{decision_id}:{kind}] choice={choice} by={resolved_by} note={}",
            note.unwrap_or("")
        ));
        if memory.decisions_log.len() > 20 {
            let drain = memory.decisions_log.len() - 20;
            memory.decisions_log.drain(0..drain);
        }
        let updated_memory_json = serde_json::to_string(&memory)?;
        tx.execute(
            "UPDATE tasks SET status = CASE WHEN status = 'Blocked' THEN 'Ready' ELSE status END,
                              memory_json = ?2,
                              version = version + 1,
                              updated_epoch = ?3
             WHERE task_id = ?1",
            params![task_id, updated_memory_json, now],
        )?;
        Self::insert_event_tx(
            &tx,
            &task_id,
            &task_group,
            now,
            "DECISION_RESOLVED",
            &serde_json::json!({
                "decision_id": decision_id,
                "kind": kind,
                "choice": choice,
                "resolved_by": resolved_by,
                "note": note,
            }),
        )?;
        tx.commit()?;
        let rec = self
            .get_decision(decision_id)?
            .ok_or_else(|| V2StoreError("Resolved decision missing".into()))?;
        Ok(DecisionResolution::Resolved(rec))
    }

    pub fn get_decision(
        &self,
        decision_id: &str,
    ) -> Result<Option<PendingDecisionRecord>, V2StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT decision_id, task_id, task_group, kind, question, options_json,
                    recommended_option, context_summary, sha, status, created_seq,
                    resolved_by, resolved_epoch, choice, note
             FROM pending_decisions WHERE decision_id = ?1",
        )?;
        stmt.query_row(params![decision_id], Self::map_decision_row)
            .optional()
            .map_err(V2StoreError::from)
    }

    pub fn list_decisions(
        &self,
        open_only: bool,
        group_filter: Option<&str>,
    ) -> Result<Vec<PendingDecisionRecord>, V2StoreError> {
        let mut all = Vec::new();
        let mut stmt = self.conn.prepare(
            "SELECT decision_id, task_id, task_group, kind, question, options_json,
                    recommended_option, context_summary, sha, status, created_seq,
                    resolved_by, resolved_epoch, choice, note
             FROM pending_decisions ORDER BY created_seq ASC",
        )?;
        let rows = stmt.query_map([], Self::map_decision_row)?;
        for r in rows {
            let item = r?;
            if open_only && item.status != "OPEN" {
                continue;
            }
            if let Some(group) = group_filter
                && !item.task_group.eq_ignore_ascii_case(group)
            {
                continue;
            }
            all.push(item);
        }
        Ok(all)
    }

    pub fn record_stage_attempt(
        &mut self,
        attempt: &StageAttemptRecord,
    ) -> Result<(), V2StoreError> {
        let now = now_epoch();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO stage_attempts (
                attempt_id, task_id, stage, model, effort, systemd_unit, invocation_id,
                started_epoch, ended_epoch, status, failure_class, summary,
                input_tokens, output_tokens, total_tokens, sha_before, sha_after
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16, ?17
             )
             ON CONFLICT(attempt_id) DO UPDATE SET
                systemd_unit = excluded.systemd_unit,
                invocation_id = excluded.invocation_id,
                ended_epoch = excluded.ended_epoch,
                status = excluded.status,
                failure_class = excluded.failure_class,
                summary = excluded.summary,
                input_tokens = excluded.input_tokens,
                output_tokens = excluded.output_tokens,
                total_tokens = excluded.total_tokens,
                sha_before = excluded.sha_before,
                sha_after = excluded.sha_after",
            params![
                attempt.attempt_id,
                attempt.task_id,
                attempt.stage,
                attempt.model,
                attempt.effort,
                attempt.systemd_unit,
                attempt.invocation_id,
                attempt.started_epoch,
                attempt.ended_epoch,
                attempt.status,
                attempt.failure_class,
                attempt.summary,
                attempt.input_tokens as i64,
                attempt.output_tokens as i64,
                attempt.total_tokens as i64,
                attempt.sha_before,
                attempt.sha_after,
            ],
        )?;

        let task_group: String = tx
            .query_row(
                "SELECT task_group FROM tasks WHERE task_id = ?1",
                params![attempt.task_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_else(|| "default".to_owned());

        let event_type = if attempt.ended_epoch.is_some() {
            "STAGE_COMPLETED"
        } else {
            "STAGE_STARTED"
        };
        Self::insert_event_tx(
            &tx,
            &attempt.task_id,
            &task_group,
            now,
            event_type,
            &serde_json::json!({
                "attempt_id": attempt.attempt_id,
                "stage": attempt.stage,
                "model": attempt.model,
                "effort": attempt.effort,
                "status": attempt.status,
                "total_tokens": attempt.total_tokens,
            }),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn acquire_path_locks(
        &mut self,
        repo: &str,
        paths: &[String],
        task_id: &str,
    ) -> Result<bool, V2StoreError> {
        let now = now_epoch();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        // If the repository already has a wildcard lock held by someone else, reject
        let wildcard_holder: Option<String> = tx
            .query_row(
                "SELECT task_id FROM path_locks WHERE repo = ?1 AND path = '*'",
                params![repo],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = wildcard_holder
            && existing != task_id
        {
            return Ok(false);
        }

        for path in paths {
            if path == "*" {
                let any_holder: Option<String> = tx
                    .query_row(
                        "SELECT task_id FROM path_locks WHERE repo = ?1 AND task_id != ?2 LIMIT 1",
                        params![repo, task_id],
                        |row| row.get(0),
                    )
                    .optional()?;
                if any_holder.is_some() {
                    return Ok(false);
                }
            } else {
                let holder: Option<String> = tx
                    .query_row(
                        "SELECT task_id FROM path_locks WHERE repo = ?1 AND path = ?2",
                        params![repo, path],
                        |row| row.get(0),
                    )
                    .optional()?;
                if let Some(existing) = holder
                    && existing != task_id
                {
                    return Ok(false);
                }
            }
        }

        for path in paths {
            tx.execute(
                "INSERT INTO path_locks(repo, path, task_id, acquired_epoch)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(repo, path) DO UPDATE SET acquired_epoch = excluded.acquired_epoch",
                params![repo, path, task_id, now],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    pub fn release_path_locks(&mut self, task_id: &str) -> Result<usize, V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let removed = tx.execute(
            "DELETE FROM path_locks WHERE task_id = ?1",
            params![task_id],
        )?;
        tx.commit()?;
        Ok(removed)
    }

    pub fn list_path_locks(
        &self,
        repo_filter: Option<&str>,
    ) -> Result<Vec<PathLockRecord>, V2StoreError> {
        let mut locks = Vec::new();
        if let Some(repo) = repo_filter {
            let mut stmt = self.conn.prepare(
                "SELECT repo, path, task_id, acquired_epoch
                 FROM path_locks WHERE repo = ?1 ORDER BY path ASC",
            )?;
            let rows = stmt.query_map(params![repo], |row| {
                Ok(PathLockRecord {
                    repo: row.get(0)?,
                    path: row.get(1)?,
                    task_id: row.get(2)?,
                    acquired_epoch: row.get(3)?,
                })
            })?;
            for r in rows {
                locks.push(r?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT repo, path, task_id, acquired_epoch
                 FROM path_locks ORDER BY repo ASC, path ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(PathLockRecord {
                    repo: row.get(0)?,
                    path: row.get(1)?,
                    task_id: row.get(2)?,
                    acquired_epoch: row.get(3)?,
                })
            })?;
            for r in rows {
                locks.push(r?);
            }
        }
        Ok(locks)
    }

    pub fn enqueue_merge_queue(
        &mut self,
        repo: &str,
        task_id: &str,
        pr_number: i64,
        reviewed_sha: &str,
    ) -> Result<MergeQueueRecord, V2StoreError> {
        let now = now_epoch();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO merge_queue(repo, task_id, pr_number, reviewed_sha, enqueued_epoch, state)
             VALUES (?1, ?2, ?3, ?4, ?5, 'QUEUED')
             ON CONFLICT(repo, task_id) DO UPDATE SET
                 pr_number = excluded.pr_number,
                 reviewed_sha = excluded.reviewed_sha,
                 enqueued_epoch = excluded.enqueued_epoch,
                 state = 'QUEUED'",
            params![repo, task_id, pr_number, reviewed_sha, now],
        )?;
        let task_group: String = tx
            .query_row(
                "SELECT task_group FROM tasks WHERE task_id = ?1",
                params![task_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_else(|| "default".to_owned());
        Self::insert_event_tx(
            &tx,
            task_id,
            &task_group,
            now,
            "MERGE_ENQUEUED",
            &serde_json::json!({
                "repo": repo,
                "task_id": task_id,
                "pr_number": pr_number,
                "reviewed_sha": reviewed_sha,
            }),
        )?;
        tx.commit()?;
        Ok(MergeQueueRecord {
            repo: repo.to_owned(),
            task_id: task_id.to_owned(),
            pr_number,
            reviewed_sha: reviewed_sha.to_owned(),
            enqueued_epoch: now,
            state: "QUEUED".to_owned(),
        })
    }

    pub fn list_merge_queue(
        &self,
        repo_filter: Option<&str>,
    ) -> Result<Vec<MergeQueueRecord>, V2StoreError> {
        let mut entries = Vec::new();
        if let Some(repo) = repo_filter {
            let mut stmt = self.conn.prepare(
                "SELECT repo, task_id, pr_number, reviewed_sha, enqueued_epoch, state
                 FROM merge_queue WHERE repo = ?1 ORDER BY enqueued_epoch ASC",
            )?;
            let rows = stmt.query_map(params![repo], Self::map_merge_queue_row)?;
            for r in rows {
                entries.push(r?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT repo, task_id, pr_number, reviewed_sha, enqueued_epoch, state
                 FROM merge_queue ORDER BY enqueued_epoch ASC",
            )?;
            let rows = stmt.query_map([], Self::map_merge_queue_row)?;
            for r in rows {
                entries.push(r?);
            }
        }
        Ok(entries)
    }

    pub fn get_merge_queue_entry(
        &self,
        repo: &str,
        task_id: &str,
    ) -> Result<Option<MergeQueueRecord>, V2StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT repo, task_id, pr_number, reviewed_sha, enqueued_epoch, state
             FROM merge_queue WHERE repo = ?1 AND task_id = ?2",
        )?;
        stmt.query_row(params![repo, task_id], Self::map_merge_queue_row)
            .optional()
            .map_err(V2StoreError::from)
    }

    pub fn update_merge_queue_state(
        &mut self,
        repo: &str,
        task_id: &str,
        new_state: &str,
    ) -> Result<(), V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE merge_queue SET state = ?3 WHERE repo = ?1 AND task_id = ?2",
            params![repo, task_id, new_state],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_merge_queue_entry(
        &mut self,
        repo: &str,
        task_id: &str,
    ) -> Result<usize, V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let removed = tx.execute(
            "DELETE FROM merge_queue WHERE repo = ?1 AND task_id = ?2",
            params![repo, task_id],
        )?;
        tx.commit()?;
        Ok(removed)
    }

    fn map_merge_queue_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MergeQueueRecord> {
        Ok(MergeQueueRecord {
            repo: row.get(0)?,
            task_id: row.get(1)?,
            pr_number: row.get(2)?,
            reviewed_sha: row.get(3)?,
            enqueued_epoch: row.get(4)?,
            state: row.get(5)?,
        })
    }

    pub fn max_seq_id(&self) -> Result<i64, V2StoreError> {
        let max_seq: Option<i64> =
            self.conn
                .query_row("SELECT MAX(seq_id) FROM task_events", [], |row| row.get(0))?;
        Ok(max_seq.unwrap_or(0))
    }

    pub fn status_summary(&self) -> Result<DaemonStatusSummary, V2StoreError> {
        let max_parallel_tasks = self.max_parallel_tasks()?;
        let heartbeat_epoch: i64 = self
            .conn
            .query_row(
                "SELECT value FROM daemon_meta WHERE key = 'heartbeat_epoch'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        let max_seq_id = self.max_seq_id()?;
        let all_tasks = self.list_tasks(None)?;
        let ready_eligible = self.list_ready_queue(None)?;
        let in_progress_count = all_tasks
            .iter()
            .filter(|t| {
                matches!(
                    t.status.as_str(),
                    "Planning" | "Plan Review" | "In Progress" | "PR Review"
                )
            })
            .count();
        let open_decisions_count = self.list_decisions(true, None)?.len();
        let active_locks_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM path_locks", [], |row| row.get(0))?;
        let merge_queue_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM merge_queue", [], |row| row.get(0))?;

        Ok(DaemonStatusSummary {
            schema_version: SCHEMA_VERSION,
            max_parallel_tasks,
            heartbeat_epoch,
            max_seq_id,
            total_tasks: all_tasks.len(),
            ready_eligible_count: ready_eligible.len(),
            in_progress_count,
            open_decisions_count,
            active_locks_count: active_locks_count as usize,
            merge_queue_count: merge_queue_count as usize,
        })
    }

    fn map_task_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TaskRecord> {
        let context_pack_str: String = row.get(10)?;
        let depends_on_str: String = row.get(11)?;
        let required_stages_str: String = row.get(12)?;
        let stages_completed_str: String = row.get(13)?;
        let memory_str: String = row.get(22)?;
        let autonomous_int: i64 = row.get(20)?;

        Ok(TaskRecord {
            task_id: row.get(0)?,
            task_group: row.get(1)?,
            title: row.get(2)?,
            repository: row.get(3)?,
            github_repo: row.get(4)?,
            issue_number: row.get(5)?,
            weight: row.get(6)?,
            status: row.get(7)?,
            worktree_path: row.get(8)?,
            branch: row.get(9)?,
            context_pack: serde_json::from_str(&context_pack_str).unwrap_or_default(),
            depends_on: serde_json::from_str(&depends_on_str).unwrap_or_default(),
            required_stages: serde_json::from_str(&required_stages_str).unwrap_or_default(),
            stages_completed: serde_json::from_str(&stages_completed_str).unwrap_or_default(),
            current_stage: row.get(14)?,
            active_attempt_id: row.get(15)?,
            plan_base_sha: row.get(16)?,
            reviewed_sha: row.get(17)?,
            pr_number: row.get(18)?,
            executor: row.get(19)?,
            autonomous_consent: autonomous_int != 0,
            retry_count: row.get(21)?,
            memory: serde_json::from_str(&memory_str).unwrap_or_default(),
            version: row.get(23)?,
            updated_epoch: row.get(24)?,
        })
    }

    fn map_event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TaskEventRecord> {
        let payload_str: String = row.get(5)?;
        Ok(TaskEventRecord {
            seq_id: row.get(0)?,
            task_id: row.get(1)?,
            task_group: row.get(2)?,
            ts_epoch: row.get(3)?,
            event_type: row.get(4)?,
            payload: serde_json::from_str(&payload_str).unwrap_or(serde_json::Value::Null),
        })
    }

    fn map_decision_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PendingDecisionRecord> {
        let options_str: String = row.get(5)?;
        let rec_opt: Option<i64> = row.get(6)?;
        Ok(PendingDecisionRecord {
            decision_id: row.get(0)?,
            task_id: row.get(1)?,
            task_group: row.get(2)?,
            kind: row.get(3)?,
            question: row.get(4)?,
            options: serde_json::from_str(&options_str).unwrap_or_default(),
            recommended_option: rec_opt.and_then(|v| usize::try_from(v).ok()),
            context_summary: row.get(7)?,
            sha: row.get(8)?,
            status: row.get(9)?,
            created_seq: row.get(10)?,
            resolved_by: row.get(11)?,
            resolved_epoch: row.get(12)?,
            choice: row.get(13)?,
            note: row.get(14)?,
        })
    }
}

fn is_terminal_task_status(status: &str) -> bool {
    status.eq_ignore_ascii_case("Done") || status.eq_ignore_ascii_case("Cancelled")
}

fn coalesce_runtime_fields(old: &TaskRecord, next: &mut TaskRecord) {
    if next.current_stage.is_none() {
        next.current_stage = old.current_stage.clone();
    }
    if next.active_attempt_id.is_none() {
        next.active_attempt_id = old.active_attempt_id.clone();
    }
    if next.plan_base_sha.is_none() {
        next.plan_base_sha = old.plan_base_sha.clone();
    }
    if next.reviewed_sha.is_none() {
        next.reviewed_sha = old.reviewed_sha.clone();
    }
    if next.pr_number.is_none() {
        next.pr_number = old.pr_number;
    }
    if next.memory == TaskMemory::default() {
        next.memory = old.memory.clone();
    }
}

fn is_zach_executor(executor: Option<&str>) -> bool {
    executor.is_some_and(|e| e.trim().eq_ignore_ascii_case("zach"))
}

fn should_preserve_zach_state(existing: &TaskRecord, incoming: &TaskRecord) -> bool {
    is_zach_executor(existing.executor.as_deref())
        && !is_terminal_task_status(&existing.status)
        && !is_terminal_task_status(&incoming.status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_task(id: &str, status: &str, deps: Vec<String>) -> TaskRecord {
        TaskRecord {
            task_id: id.to_owned(),
            task_group: id
                .split('-')
                .next()
                .unwrap_or("default")
                .to_ascii_lowercase(),
            title: format!("Task {id}"),
            repository: "zach".to_owned(),
            github_repo: Some("shockerqt/zach".to_owned()),
            issue_number: Some(1),
            weight: "S".to_owned(),
            status: status.to_owned(),
            worktree_path: Some(format!("/home/ubuntu/workspace/zach--{id}")),
            branch: Some(format!("task/{id}")),
            context_pack: ContextPackSpec::default(),
            depends_on: deps,
            required_stages: vec!["impl".to_owned(), "pr-review".to_owned()],
            stages_completed: Vec::new(),
            current_stage: None,
            active_attempt_id: None,
            plan_base_sha: None,
            reviewed_sha: None,
            pr_number: None,
            executor: None,
            autonomous_consent: true,
            retry_count: 0,
            memory: TaskMemory::default(),
            version: 1,
            updated_epoch: 1000,
        }
    }

    #[test]
    fn sqlite_store_initializes_tables_monotonic_events_and_optimistic_versions() {
        let mut store = V2Store::open_in_memory().expect("open in-memory store");
        let t1 = store
            .upsert_task(&sample_task("ZACH-004", "Ready", vec!["GOV-048".into()]))
            .expect("insert ZACH-004");
        assert_eq!(t1.version, 1);

        let mut escalated = t1.clone();
        escalated.weight = "M".to_owned();
        let t1_v2 = store.upsert_task(&escalated).expect("update ZACH-004");
        assert_eq!(t1_v2.version, 2);

        // Before GOV-048 is Done, ZACH-004 is not in the ready queue
        assert!(store.list_ready_queue(None).unwrap().is_empty());

        store
            .upsert_task(&sample_task("GOV-048", "Done", Vec::new()))
            .expect("insert GOV-048 Done");
        let ready = store.list_ready_queue(Some("zach")).unwrap();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].task_id, "ZACH-004");

        // Opening a decision blocks the task from the ready queue and records a monotonic event
        let dec = store
            .open_decision(
                "dec-1",
                "ZACH-004",
                "zach",
                "plan_approval",
                "Approve M plan?",
                &["Approve".into(), "Reject".into()],
                Some(0),
                "Summary",
                None,
            )
            .expect("open decision");
        assert_eq!(dec.status, "OPEN");
        assert!(store.list_ready_queue(None).unwrap().is_empty());

        // Resolving the decision is idempotent and restores Ready status
        let res1 = store
            .resolve_decision("dec-1", "Approve", "shockerqt", Some("LGTM"))
            .unwrap();
        assert!(matches!(res1, DecisionResolution::Resolved(_)));
        let res2 = store
            .resolve_decision("dec-1", "Reject", "other", None)
            .unwrap();
        assert!(matches!(res2, DecisionResolution::AlreadyResolved(_)));

        let events = store.list_events_since(Some("zach"), 0, 100).unwrap();
        assert!(events.len() >= 3);
        for pair in events.windows(2) {
            assert!(pair[1].seq_id > pair[0].seq_id);
        }
    }

    #[test]
    fn merge_queue_and_path_locks_work_as_expected() {
        let mut store = V2Store::open_in_memory().expect("open store");

        // Path locks: acquire specific paths
        let paths1 = vec!["src/v2/router.rs".to_owned(), "src/v2/runner.rs".to_owned()];
        assert!(store.acquire_path_locks("zach", &paths1, "TASK-1").unwrap());

        // Same task re-acquiring same paths succeeds
        assert!(store.acquire_path_locks("zach", &paths1, "TASK-1").unwrap());

        // Different task trying to acquire overlapping path fails
        let paths2 = vec![
            "src/v2/runner.rs".to_owned(),
            "src/v2/pipeline.rs".to_owned(),
        ];
        assert!(!store.acquire_path_locks("zach", &paths2, "TASK-2").unwrap());

        // Wildcard conflicts with existing paths
        assert!(
            !store
                .acquire_path_locks("zach", &[String::from("*")], "TASK-3")
                .unwrap()
        );

        // Non-overlapping paths in same repo succeed
        assert!(
            store
                .acquire_path_locks("zach", &[String::from("src/v2/intake.rs")], "TASK-2")
                .unwrap()
        );

        // Overlapping path in different repo succeeds
        assert!(
            store
                .acquire_path_locks("governance", &paths1, "TASK-2")
                .unwrap()
        );

        // Check list_path_locks
        let zach_locks = store.list_path_locks(Some("zach")).unwrap();
        assert_eq!(zach_locks.len(), 3);
        let all_locks = store.list_path_locks(None).unwrap();
        assert_eq!(all_locks.len(), 5);

        // Release TASK-1 locks
        let released = store.release_path_locks("TASK-1").unwrap();
        assert_eq!(released, 2);
        assert_eq!(store.list_path_locks(Some("zach")).unwrap().len(), 1);

        // Merge queue FIFO operations
        let entry1 = store
            .enqueue_merge_queue("zach", "TASK-1", 101, "sha-1")
            .unwrap();
        assert_eq!(entry1.state, "QUEUED");
        assert_eq!(entry1.pr_number, 101);

        let entry2 = store
            .enqueue_merge_queue("zach", "TASK-2", 102, "sha-2")
            .unwrap();
        assert_eq!(entry2.state, "QUEUED");

        let mq = store.list_merge_queue(Some("zach")).unwrap();
        assert_eq!(mq.len(), 2);
        assert_eq!(mq[0].task_id, "TASK-1");
        assert_eq!(mq[1].task_id, "TASK-2");

        // Update state
        store
            .update_merge_queue_state("zach", "TASK-1", "MERGING")
            .unwrap();
        let fetched = store
            .get_merge_queue_entry("zach", "TASK-1")
            .unwrap()
            .unwrap();
        assert_eq!(fetched.state, "MERGING");

        // Remove entry
        let removed = store.remove_merge_queue_entry("zach", "TASK-1").unwrap();
        assert_eq!(removed, 1);
        let remaining = store.list_merge_queue(Some("zach")).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].task_id, "TASK-2");
    }

    #[test]
    fn sync_task_preserves_zach_owned_runtime_state_and_refreshes_spec_fields() {
        let mut db_path = std::env::temp_dir();
        db_path.push(format!(
            "zach_v2_sync_preserve_{}_{}.sqlite3",
            std::process::id(),
            now_epoch()
        ));
        let _ = std::fs::remove_file(&db_path);

        let mut store = V2Store::open(&db_path).expect("open file-backed sqlite store");

        let mut mem = TaskMemory::default();
        mem.recent_attempts.push("impl-attempt-1".to_owned());
        mem.token_usage_by_stage.insert("impl".to_owned(), 4200);
        mem.last_check_failure = Some("clippy warning".to_owned());

        let mut internal = sample_task("ZACH-021", "Queued for Merge", vec!["ZACH-020".into()]);
        internal.executor = Some("Zach".to_owned());
        internal.stages_completed = vec![
            "plan".to_owned(),
            "plan-review".to_owned(),
            "impl".to_owned(),
            "pr-review".to_owned(),
        ];
        internal.current_stage = Some("merge_queue".to_owned());
        internal.active_attempt_id = Some("zach-021-pr-review-3".to_owned());
        internal.plan_base_sha = Some("base-sha-111".to_owned());
        internal.reviewed_sha = Some("reviewed-sha-222".to_owned());
        internal.pr_number = Some(54);
        internal.retry_count = 2;
        internal.memory = mem.clone();
        store.upsert_task(&internal).expect("seed zach-owned task");

        // Incoming board sync with stale/reset runtime fields and updated spec fields.
        let mut incoming = sample_task("ZACH-021", "Ready", vec!["GOV-050".into()]);
        incoming.task_group = "platform".to_owned();
        incoming.title = "Refreshed spec title".to_owned();
        incoming.repository = "zach-core".to_owned();
        incoming.github_repo = Some("shockerqt/zach-core".to_owned());
        incoming.issue_number = Some(99);
        incoming.weight = "M".to_owned();
        incoming.branch = Some("task/ZACH-021-refreshed".to_owned());
        incoming.worktree_path = Some("/tmp/zach--ZACH-021-refreshed".to_owned());
        incoming.autonomous_consent = false;
        incoming.context_pack = ContextPackSpec {
            weight: "M".to_owned(),
            base_sha: Some("board-base-sha-999".to_owned()),
            target_files: vec![TargetFileSpec {
                path: "src/v2/intake.rs".to_owned(),
                action: "modify".to_owned(),
                summary: "Use sync_task".to_owned(),
            }],
            ..ContextPackSpec::default()
        };
        incoming.stages_completed = Vec::new();
        incoming.current_stage = None;
        incoming.active_attempt_id = None;
        incoming.plan_base_sha = Some("board-base-sha-999".to_owned());
        incoming.reviewed_sha = Some("board-reviewed-sha-888".to_owned());
        incoming.pr_number = None;
        incoming.executor = None;
        incoming.retry_count = 0;
        incoming.memory = TaskMemory::default();

        let synced = store.sync_task(&incoming).expect("sync_task");
        assert_eq!(synced.version, 2);

        // Re-open from disk to prove SQLite persistence.
        drop(store);
        let reopened = V2Store::open(&db_path).expect("reopen file-backed sqlite store");
        let stored = reopened.get_task("ZACH-021").unwrap().unwrap();

        // AC-1: Runtime state preserved untouched
        assert_eq!(stored.status, "Queued for Merge");
        assert_eq!(
            stored.stages_completed,
            vec!["plan", "plan-review", "impl", "pr-review"]
        );
        assert_eq!(stored.current_stage.as_deref(), Some("merge_queue"));
        assert_eq!(
            stored.active_attempt_id.as_deref(),
            Some("zach-021-pr-review-3")
        );
        assert_eq!(stored.plan_base_sha.as_deref(), Some("base-sha-111"));
        assert_eq!(stored.reviewed_sha.as_deref(), Some("reviewed-sha-222"));
        assert_eq!(stored.pr_number, Some(54));
        assert_eq!(stored.executor.as_deref(), Some("Zach"));
        assert_eq!(stored.retry_count, 2);
        assert_eq!(stored.memory, mem);

        // AC-2: Spec fields refreshed
        assert_eq!(stored.title, "Refreshed spec title");
        assert_eq!(stored.context_pack, incoming.context_pack);
        assert_eq!(stored.weight, "M");
        assert_eq!(stored.depends_on, vec!["GOV-050".to_owned()]);
        assert_eq!(stored.branch.as_deref(), Some("task/ZACH-021-refreshed"));
        assert_eq!(
            stored.worktree_path.as_deref(),
            Some("/tmp/zach--ZACH-021-refreshed")
        );
        assert_eq!(stored.task_group, "platform");
        assert_eq!(stored.repository, "zach-core");
        assert_eq!(stored.github_repo.as_deref(), Some("shockerqt/zach-core"));
        assert_eq!(stored.issue_number, Some(99));
        assert!(!stored.autonomous_consent);

        drop(reopened);
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn sync_task_allows_terminal_board_status_and_non_zach_overrides() {
        let mut store = V2Store::open_in_memory().expect("open store");

        // 1. Zach-owned non-terminal task overridden when board status is Cancelled or Done
        let mut zach_task = sample_task("ZACH-100", "In Progress", Vec::new());
        zach_task.executor = Some("zach".to_owned());
        zach_task.current_stage = Some("impl".to_owned());
        zach_task.stages_completed = vec!["plan".to_owned()];
        zach_task.retry_count = 1;
        store.upsert_task(&zach_task).unwrap();

        let mut board_cancelled = sample_task("ZACH-100", "Cancelled", Vec::new());
        board_cancelled.title = "Cancelled on board".to_owned();
        board_cancelled.executor = None;
        let res_cancel = store.sync_task(&board_cancelled).unwrap();
        assert_eq!(res_cancel.status, "Cancelled");
        assert_eq!(res_cancel.title, "Cancelled on board");
        assert_eq!(
            store.get_task("ZACH-100").unwrap().unwrap().status,
            "Cancelled"
        );

        // 2. Reopening a terminal Zach task (Done/Cancelled) from board succeeds
        let mut board_reopened = sample_task("ZACH-100", "Ready", Vec::new());
        board_reopened.executor = Some("zach".to_owned());
        let res_reopen = store.sync_task(&board_reopened).unwrap();
        assert_eq!(res_reopen.status, "Ready");

        // 3. Board status Done wins over Zach-owned non-terminal state and emits TASK_DONE
        let mut zach_queued = sample_task("ZACH-101", "Queued for Merge", Vec::new());
        zach_queued.executor = Some("zach".to_owned());
        store.upsert_task(&zach_queued).unwrap();

        let board_done = sample_task("ZACH-101", "Done", Vec::new());
        let res_done = store.sync_task(&board_done).unwrap();
        assert_eq!(res_done.status, "Done");
        let events = store.list_events_since(Some("zach"), 0, 100).unwrap();
        assert!(
            events
                .iter()
                .any(|e| e.task_id == "ZACH-101" && e.event_type == "TASK_DONE")
        );

        // 4. Non-Zach task refreshes status/stages_completed/executor from board while
        // preserving COALESCE runtime fields and monotonic retry_count when incoming omits them.
        let mut other_mem = TaskMemory::default();
        other_mem.recent_attempts.push("agy-attempt-1".to_owned());

        let mut other_task = sample_task("ZACH-102", "In Progress", Vec::new());
        other_task.executor = Some("agy".to_owned());
        other_task.current_stage = Some("impl".to_owned());
        other_task.active_attempt_id = Some("agy-att-1".to_owned());
        other_task.plan_base_sha = Some("agy-base-sha".to_owned());
        other_task.reviewed_sha = Some("agy-reviewed-sha".to_owned());
        other_task.pr_number = Some(88);
        other_task.stages_completed = vec!["plan".to_owned()];
        other_task.retry_count = 3;
        other_task.memory = other_mem.clone();
        store.upsert_task(&other_task).unwrap();

        let board_reset = sample_task("ZACH-102", "Ready", Vec::new());
        let res_other = store.sync_task(&board_reset).unwrap();
        assert_eq!(res_other.status, "Ready");
        assert!(res_other.stages_completed.is_empty());
        assert_eq!(res_other.executor, None);
        assert_eq!(res_other.current_stage.as_deref(), Some("impl"));
        assert_eq!(res_other.active_attempt_id.as_deref(), Some("agy-att-1"));
        assert_eq!(res_other.plan_base_sha.as_deref(), Some("agy-base-sha"));
        assert_eq!(res_other.reviewed_sha.as_deref(), Some("agy-reviewed-sha"));
        assert_eq!(res_other.pr_number, Some(88));
        assert_eq!(res_other.retry_count, 3);
        assert_eq!(res_other.memory, other_mem);
    }
}
