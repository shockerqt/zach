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

    pub fn upsert_task(&mut self, task: &TaskRecord) -> Result<TaskRecord, V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(String, String, i64, String)> = tx
            .query_row(
                "SELECT status, weight, version, memory_json FROM tasks WHERE task_id = ?1",
                params![task.task_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;

        let context_pack_json = serde_json::to_string(&task.context_pack)?;
        let depends_on_json = serde_json::to_string(&task.depends_on)?;
        let required_stages_json = serde_json::to_string(&task.required_stages)?;
        let stages_completed_json = serde_json::to_string(&task.stages_completed)?;
        let now = if task.updated_epoch > 0 {
            task.updated_epoch
        } else {
            now_epoch()
        };

        let next_version = match &existing {
            Some((old_status, old_weight, old_version, old_memory_json)) => {
                let merged_memory_json = if task.memory == TaskMemory::default() {
                    old_memory_json.clone()
                } else {
                    serde_json::to_string(&task.memory)?
                };
                let next_ver = old_version + 1;
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
                        current_stage = COALESCE(?15, current_stage),
                        active_attempt_id = COALESCE(?16, active_attempt_id),
                        plan_base_sha = COALESCE(?17, plan_base_sha),
                        reviewed_sha = COALESCE(?18, reviewed_sha),
                        pr_number = COALESCE(?19, pr_number),
                        executor = ?20,
                        autonomous_consent = ?21,
                        memory_json = ?22,
                        version = ?23,
                        updated_epoch = ?24
                     WHERE task_id = ?1 AND version = ?25",
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
                        merged_memory_json,
                        next_ver,
                        now,
                        old_version,
                    ],
                )?;
                if old_weight != &task.weight {
                    Self::insert_event_tx(
                        &tx,
                        &task.task_id,
                        &task.task_group,
                        now,
                        "WEIGHT_ESCALATED",
                        &serde_json::json!({
                            "from_weight": old_weight,
                            "to_weight": task.weight,
                        }),
                    )?;
                }
                if old_status != &task.status && task.status == "Done" {
                    Self::insert_event_tx(
                        &tx,
                        &task.task_id,
                        &task.task_group,
                        now,
                        "TASK_DONE",
                        &serde_json::json!({ "status": "Done" }),
                    )?;
                }
                next_ver
            }
            None => {
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
                1
            }
        };
        tx.commit()?;
        let mut updated = task.clone();
        updated.version = next_version;
        updated.updated_epoch = now;
        Ok(updated)
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
        for path in paths {
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
}
