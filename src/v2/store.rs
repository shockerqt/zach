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
    pub network: Option<String>,
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

/// Reconciliation is an explicit offline operation, never ordinary daemon sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    Standard,
    ReconcileFinishedLegacy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TaskMemory {
    /// An authoritative Governance export observed a terminal task. Local
    /// delivery recovery must never reinterpret that as premature completion.
    #[serde(default)]
    pub governance_terminal_observed: bool,
    #[serde(default)]
    pub halt_requested: bool,
    #[serde(default)]
    pub governance_started: bool,
    #[serde(default)]
    pub merge_retry_count: u32,
    #[serde(default)]
    pub merge_retry_generation: u64,
    #[serde(default)]
    pub suspended_impl_attempt_id: Option<String>,
    #[serde(default)]
    pub merge_lane_released: bool,
    #[serde(default)]
    pub plan_rework_generation: u64,
    #[serde(default)]
    pub review_rework_generation: u64,
    #[serde(default)]
    pub retry_reset_epoch: i64,
    #[serde(default)]
    pub retry_generation: u64,
    #[serde(default)]
    pub pipeline_checkpoint: Option<PipelineCheckpoint>,
    #[serde(default)]
    pub merge_checkpoint: Option<MergeCheckpoint>,
    #[serde(default)]
    pub last_pr_review_evidence: Option<String>,
    #[serde(default)]
    pub last_pr_review_evidence_sha: Option<String>,
    #[serde(default)]
    pub last_pr_review_evidence_path: Option<String>,
    #[serde(default)]
    pub applied_decisions: Vec<String>,
    #[serde(default)]
    pub decisions_log: Vec<String>,
    #[serde(default)]
    pub recent_attempts: Vec<String>,
    #[serde(default)]
    pub token_usage_by_stage: BTreeMap<String, u64>,
    #[serde(default)]
    pub last_check_failure: Option<String>,
    #[serde(default)]
    pub approved_plan: Option<String>,
    #[serde(default)]
    pub candidate_plan_artifact_path: Option<String>,
    #[serde(default)]
    pub approved_plan_artifact_path: Option<String>,
    #[serde(default)]
    pub plan_rework_count: u32,
    #[serde(default)]
    pub last_plan_review_findings: Option<String>,
    #[serde(default)]
    pub last_review_findings: Option<String>,
    #[serde(default)]
    pub review_rework_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PipelineCheckpoint {
    pub attempt_id: String,
    pub operation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MergeCheckpoint {
    pub phase: String,
    pub target_sha: String,
    pub pr_number: i64,
    pub merge_sha: Option<String>,
    pub post_merge_verified: bool,
    #[serde(default)]
    pub phase_started_epoch: i64,
}

pub struct FailureDecision {
    pub decision_id: String,
    pub kind: String,
    pub question: String,
    pub options: Vec<String>,
    pub context: String,
    pub sha: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleOperation {
    #[serde(default)]
    pub attempt_id: Option<String>,
    #[serde(default)]
    pub decision_id: Option<String>,
    pub operation_id: String,
    pub task_id: String,
    pub kind: String,
    pub args: Vec<String>,
    pub body_path: Option<String>,
    pub depends_on: Option<String>,
    pub state: String,
    pub retry_epoch: i64,
    pub attempts: u32,
    pub last_error: Option<String>,
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
    #[serde(default)]
    pub next_retry_epoch: i64,
    #[serde(default)]
    pub lease_owner: Option<String>,
    #[serde(default)]
    pub lease_expires_epoch: Option<i64>,
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
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub sha_before: Option<String>,
    pub sha_after: Option<String>,
    #[serde(default = "default_attempt_phase")]
    pub phase: String,
    #[serde(default)]
    pub last_liveness_epoch: i64,
    #[serde(default)]
    pub last_output_bytes: u64,
    #[serde(default)]
    pub last_cpu_usage_usec: Option<u64>,
    #[serde(default)]
    pub control_group: Option<String>,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub exit_code_kind: Option<String>,
    #[serde(default)]
    pub retry_generation: u64,
}

fn default_attempt_phase() -> String {
    "RUNNING".to_owned()
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
    #[serde(default)]
    pub active_units: usize,
    #[serde(default)]
    pub occupied_repositories: usize,
    #[serde(default)]
    pub running_task_slots: usize,
    #[serde(default)]
    pub backoff_tasks: usize,
    #[serde(default)]
    pub pending_write_backs: usize,
    #[serde(default)]
    pub reconciliation_errors: u64,
    #[serde(default)]
    pub last_sync_epoch: i64,
}

/// Durable post-merge work. `rule_json` is the immutable contract rule captured
/// at `merge_sha`; evidence and dispatch identifiers survive process restarts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostMergeDelivery {
    pub delivery_id: String,
    pub task_id: String,
    pub repository: String,
    pub github_repo: String,
    pub merge_sha: String,
    pub kind: String,
    pub name: String,
    pub state: String,
    pub workflow: String,
    pub run_id: Option<String>,
    pub build_run_id: Option<String>,
    pub artifact_digest: Option<String>,
    pub expected_current: Option<String>,
    pub evidence_json: serde_json::Value,
    pub rule_json: serde_json::Value,
    pub decision_id: Option<String>,
    pub attempt: i64,
    pub updated_epoch: i64,
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

    pub fn open_read_only(path: &Path) -> Result<Self, V2StoreError> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Self { conn })
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
        // Never downgrade or rewrite a database created by a newer binary.
        // This check deliberately precedes even additive schema mutations.
        let has_meta: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'daemon_meta')",
            [],
            |row| row.get(0),
        )?;
        if has_meta {
            let version: Option<String> = self
                .conn
                .query_row(
                    "SELECT value FROM daemon_meta WHERE key = 'schema_version'",
                    [],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(raw) = version {
                let version = raw
                    .parse::<u32>()
                    .map_err(|_| V2StoreError("invalid SQLite schema_version".into()))?;
                if version == 0 || version > SCHEMA_VERSION {
                    return Err(V2StoreError(format!(
                        "unsupported SQLite schema_version {version} (supported through {SCHEMA_VERSION})"
                    )));
                }
            }
        }
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
                 input_tokens INTEGER,
                 output_tokens INTEGER,
                 total_tokens INTEGER,
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
             );

             CREATE TABLE IF NOT EXISTS post_merge_deliveries (
                 delivery_id TEXT PRIMARY KEY,
                 task_id TEXT NOT NULL REFERENCES tasks(task_id),
                 repository TEXT NOT NULL,
                 github_repo TEXT NOT NULL,
                 merge_sha TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 name TEXT NOT NULL,
                 state TEXT NOT NULL,
                 workflow TEXT NOT NULL,
                 run_id TEXT,
                 build_run_id TEXT,
                 artifact_digest TEXT,
                 expected_current TEXT,
                 evidence_json TEXT NOT NULL DEFAULT '{}',
                 rule_json TEXT NOT NULL DEFAULT '{}',
                 decision_id TEXT,
                 attempt INTEGER NOT NULL DEFAULT 0,
                 updated_epoch INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_deliveries_task ON post_merge_deliveries(task_id);",
        )?;

        if self
            .meta("schema_version")?
            .and_then(|v| v.parse::<u32>().ok())
            .is_some_and(|version| version > SCHEMA_VERSION)
        {
            return Err(V2StoreError(
                "database schema is newer than this daemon".into(),
            ));
        }
        self.migrate_supervision()?;
        self.migrate_stage_attempts_nullable_tokens()?;
        // These additive fields also tolerate an interrupted pre-release upgrade.
        let delivery_columns: BTreeSet<String> = {
            let mut stmt = self
                .conn
                .prepare("PRAGMA table_info('post_merge_deliveries')")?;
            stmt.query_map([], |row| row.get(1))?
                .collect::<Result<_, _>>()?
        };
        for (name, definition) in [
            ("rule_json", "TEXT NOT NULL DEFAULT '{}'"),
            ("attempt", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            if !delivery_columns.contains(name) {
                self.conn.execute_batch(&format!(
                    "ALTER TABLE post_merge_deliveries ADD COLUMN {name} {definition}"
                ))?;
            }
        }

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

    /// Migrates pre-existing `stage_attempts` tables whose token columns were
    /// created with `NOT NULL DEFAULT 0` to nullable `INTEGER` with no default.
    fn migrate_stage_attempts_nullable_tokens(&mut self) -> Result<(), V2StoreError> {
        let needs_migration = {
            let mut stmt = self.conn.prepare("PRAGMA table_info('stage_attempts')")?;
            let rows = stmt.query_map([], |row| {
                let name: String = row.get(1)?;
                let notnull: i64 = row.get(3)?;
                let dflt: Option<String> = row.get(4)?;
                Ok((name, notnull, dflt))
            })?;
            let mut needs = false;
            for r in rows {
                let (name, notnull, dflt) = r?;
                if matches!(
                    name.as_str(),
                    "input_tokens" | "output_tokens" | "total_tokens"
                ) && (notnull != 0 || dflt.is_some())
                {
                    needs = true;
                }
            }
            needs
        };

        if !needs_migration {
            return Ok(());
        }

        self.conn.execute_batch("PRAGMA foreign_keys=OFF;")?;
        let res = (|| -> Result<(), V2StoreError> {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(
                "CREATE TABLE stage_attempts_new (
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
                     input_tokens INTEGER,
                     output_tokens INTEGER,
                     total_tokens INTEGER,
                     sha_before TEXT,
                     sha_after TEXT,
                     phase TEXT NOT NULL DEFAULT 'RUNNING', last_liveness_epoch INTEGER NOT NULL DEFAULT 0,
                     last_output_bytes INTEGER NOT NULL DEFAULT 0, last_cpu_usage_usec INTEGER,
                     control_group TEXT, exit_code INTEGER, exit_code_kind TEXT,
                     retry_generation INTEGER NOT NULL DEFAULT 0,
                     FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                 );
                 INSERT INTO stage_attempts_new (
                     attempt_id, task_id, stage, model, effort, systemd_unit, invocation_id,
                     started_epoch, ended_epoch, status, failure_class, summary,
                     input_tokens, output_tokens, total_tokens, sha_before, sha_after, phase, last_liveness_epoch, last_output_bytes, last_cpu_usage_usec, control_group, exit_code, exit_code_kind, retry_generation
                 )
                 SELECT
                     attempt_id, task_id, stage, model, effort, systemd_unit, invocation_id,
                     started_epoch, ended_epoch, status, failure_class, summary,
                     input_tokens, output_tokens, total_tokens, sha_before, sha_after, phase, last_liveness_epoch, last_output_bytes, last_cpu_usage_usec, control_group, exit_code, exit_code_kind, retry_generation
                 FROM stage_attempts;
                 DROP TABLE stage_attempts;
                 ALTER TABLE stage_attempts_new RENAME TO stage_attempts;",
            )?;
            tx.commit()?;
            Ok(())
        })();
        let fk_res = self.conn.execute_batch("PRAGMA foreign_keys=ON;");
        res?;
        fk_res?;
        Ok(())
    }

    fn migrate_supervision(&mut self) -> Result<(), V2StoreError> {
        // Column introduction and compatibility classification are indivisible:
        // a reopen must never mistake a partially classified legacy DB for current state.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (table, columns) in [
            (
                "tasks",
                vec![
                    ("next_retry_epoch", "INTEGER NOT NULL DEFAULT 0"),
                    ("lease_owner", "TEXT"),
                    ("lease_expires_epoch", "INTEGER"),
                ],
            ),
            (
                "stage_attempts",
                vec![
                    ("phase", "TEXT NOT NULL DEFAULT 'RUNNING'"),
                    ("last_liveness_epoch", "INTEGER NOT NULL DEFAULT 0"),
                    ("last_output_bytes", "INTEGER NOT NULL DEFAULT 0"),
                    ("last_cpu_usage_usec", "INTEGER"),
                    ("control_group", "TEXT"),
                    ("exit_code", "INTEGER"),
                    ("exit_code_kind", "TEXT"),
                    ("retry_generation", "INTEGER NOT NULL DEFAULT 0"),
                ],
            ),
        ] {
            let present: BTreeSet<String> = tx
                .prepare(&format!("PRAGMA table_info({table})"))?
                .query_map([], |r| r.get(1))?
                .collect::<Result<_, _>>()?;
            for (name, declaration) in columns {
                if !present.contains(name) {
                    tx.execute_batch(&format!(
                        "ALTER TABLE {table} ADD COLUMN {name} {declaration}"
                    ))?;
                    if table == "stage_attempts" && name == "phase" {
                        tx.execute("UPDATE stage_attempts SET phase='COMPLETE' WHERE ended_epoch IS NOT NULL AND status IN ('PASSED','FAILED')", [])?;
                    }
                }
            }
        }
        tx.execute_batch("UPDATE stage_attempts SET last_liveness_epoch=started_epoch WHERE last_liveness_epoch=0;
            CREATE TABLE IF NOT EXISTS lifecycle_ops (
                operation_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id),
                kind TEXT NOT NULL, args_json TEXT NOT NULL, body_path TEXT, depends_on TEXT, attempt_id TEXT, decision_id TEXT,
                state TEXT NOT NULL DEFAULT 'PENDING', retry_epoch INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT,
                created_epoch INTEGER NOT NULL, updated_epoch INTEGER NOT NULL
            );")?;
        let columns: BTreeSet<String> = tx
            .prepare("PRAGMA table_info(lifecycle_ops)")?
            .query_map([], |r| r.get(1))?
            .collect::<Result<_, _>>()?;
        for name in ["attempt_id", "decision_id"] {
            if !columns.contains(name) {
                tx.execute_batch(&format!("ALTER TABLE lifecycle_ops ADD COLUMN {name} TEXT"))?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn set_meta(&mut self, key: &str, value: &str) -> Result<(), V2StoreError> {
        self.conn.execute("INSERT INTO daemon_meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key,value])?;
        Ok(())
    }

    pub fn meta(&self, key: &str) -> Result<Option<String>, V2StoreError> {
        Ok(self
            .conn
            .query_row("SELECT value FROM daemon_meta WHERE key=?1", [key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    fn enqueue_lifecycle_tx(
        tx: &rusqlite::Transaction<'_>,
        op: &LifecycleOperation,
    ) -> Result<(), V2StoreError> {
        tx.execute("INSERT OR IGNORE INTO lifecycle_ops(operation_id,task_id,kind,args_json,body_path,depends_on,state,retry_epoch,attempts,last_error,created_epoch,updated_epoch,attempt_id,decision_id) VALUES(?1,?2,?3,?4,?5,?6,'PENDING',0,0,NULL,?7,?7,?8,?9)",
            params![op.operation_id, op.task_id, op.kind, serde_json::to_string(&op.args)?, op.body_path, op.depends_on, now_epoch(),op.attempt_id,op.decision_id])?;
        Ok(())
    }

    pub fn enqueue_lifecycle(&mut self, op: &LifecycleOperation) -> Result<(), V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::enqueue_lifecycle_tx(&tx, op)?;
        tx.commit()?;
        Ok(())
    }

    pub fn checkpoint_with_lifecycle(
        &mut self,
        task: &TaskRecord,
        op: &LifecycleOperation,
    ) -> Result<(), V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = Self::get_task_tx(&tx, &task.task_id)?
            .ok_or_else(|| V2StoreError("outbox task missing".into()))?;
        Self::update_task_tx(&tx, &old, task, now_epoch())?;
        Self::enqueue_lifecycle_tx(&tx, op)?;
        tx.commit()?;
        Ok(())
    }

    pub fn lifecycle_ops(&self) -> Result<Vec<LifecycleOperation>, V2StoreError> {
        Ok(self.conn.prepare("SELECT operation_id,task_id,kind,args_json,body_path,depends_on,state,retry_epoch,attempts,last_error,attempt_id,decision_id FROM lifecycle_ops ORDER BY rowid")?.query_map([], |r| {
            let args: String = r.get(3)?;
            Ok(LifecycleOperation { attempt_id:r.get(10)?,decision_id:r.get(11)?,operation_id:r.get(0)?,task_id:r.get(1)?,kind:r.get(2)?,args:serde_json::from_str(&args).unwrap_or_default(),body_path:r.get(4)?,depends_on:r.get(5)?,state:r.get(6)?,retry_epoch:r.get(7)?,attempts:r.get(8)?,last_error:r.get(9)? })
        })?.collect::<Result<_,_>>()?)
    }

    pub fn has_pending_lifecycle(&self, task_id: &str) -> Result<bool, V2StoreError> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM lifecycle_ops WHERE task_id=?1 AND state!='ACKNOWLEDGED')",
            [task_id],
            |r| r.get(0),
        )?)
    }

    pub fn update_lifecycle(
        &mut self,
        id: &str,
        state: &str,
        error: Option<&str>,
        retry_epoch: i64,
    ) -> Result<(), V2StoreError> {
        let error = error.map(|s| crate::v2::runner::truncate_utf8_bytes(s, 1024));
        self.conn.execute("UPDATE lifecycle_ops SET state=?2,last_error=?3,retry_epoch=?4,updated_epoch=?5,attempts=attempts+CASE WHEN ?2='IN_FLIGHT' THEN 1 ELSE 0 END WHERE operation_id=?1",params![id,state,error,retry_epoch,now_epoch()])?;
        Ok(())
    }

    pub fn acknowledge_lifecycle(
        &mut self,
        task: &TaskRecord,
        op: &LifecycleOperation,
        attempt_id: Option<&str>,
    ) -> Result<(), V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = Self::get_task_tx(&tx, &task.task_id)?
            .ok_or_else(|| V2StoreError("missing lifecycle task".into()))?;
        Self::update_task_tx(&tx, &old, task, now_epoch())?;
        if let Some(id) = attempt_id {
            tx.execute(
                "UPDATE stage_attempts SET phase='COMPLETE' WHERE attempt_id=?1",
                [id],
            )?;
        }
        if op.kind == "merge-parity" {
            tx.execute(
                "UPDATE merge_queue SET reviewed_sha=?2 WHERE task_id=?1",
                params![task.task_id, task.reviewed_sha],
            )?;
        }
        if op.kind == "close" {
            tx.execute("DELETE FROM merge_queue WHERE task_id=?1", [&task.task_id])?;
            tx.execute("DELETE FROM path_locks WHERE task_id=?1", [&task.task_id])?;
            Self::insert_event_tx(
                &tx,
                &task.task_id,
                &task.task_group,
                now_epoch(),
                "MERGE_COMPLETED",
                &serde_json::json!({"receipt":task.memory.merge_checkpoint}),
            )?;
        }
        tx.execute("UPDATE lifecycle_ops SET state='ACKNOWLEDGED',last_error=NULL,updated_epoch=?2 WHERE operation_id=?1",params![op.operation_id,now_epoch()])?;
        tx.commit()?;
        Ok(())
    }

    /// Atomically reserves the repository and records the launch intent before a worker can start.
    pub fn prepare_launch(
        &mut self,
        task: &TaskRecord,
        attempt: &StageAttemptRecord,
    ) -> Result<(), V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let conflict: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM path_locks WHERE repo=?1 AND task_id!=?2)",
            params![task.repository, task.task_id],
            |r| r.get(0),
        )?;
        if conflict {
            return Err(V2StoreError("repository already owned".into()));
        }
        tx.execute("INSERT OR IGNORE INTO path_locks(repo,path,task_id,acquired_epoch) VALUES(?1,'*',?2,?3)",params![task.repository,task.task_id,now_epoch()])?;
        let old = Self::get_task_tx(&tx, &task.task_id)?
            .ok_or_else(|| V2StoreError("task missing".into()))?;
        Self::update_task_tx(&tx, &old, task, now_epoch())?;
        tx.execute("INSERT INTO stage_attempts(attempt_id,task_id,stage,model,effort,systemd_unit,started_epoch,status,sha_before,phase,last_liveness_epoch,retry_generation) VALUES(?1,?2,?3,?4,?5,?6,?7,'RUNNING',?8,'LAUNCH_PENDING',?7,?9)",params![attempt.attempt_id,attempt.task_id,attempt.stage,attempt.model,attempt.effort,attempt.systemd_unit,attempt.started_epoch,attempt.sha_before,attempt.retry_generation])?;
        Self::insert_event_tx(
            &tx,
            &task.task_id,
            &task.task_group,
            now_epoch(),
            "STAGE_STARTED",
            &serde_json::json!({"attempt_id":attempt.attempt_id,"stage":attempt.stage}),
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
                    version, updated_epoch, next_retry_epoch, lease_owner, lease_expires_epoch
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
                version, updated_epoch, next_retry_epoch, lease_owner, lease_expires_epoch
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6,
                ?7, ?8, ?9, ?10, ?11,
                ?12, ?13, ?14,
                ?15, ?16, ?17, ?18,
                ?19, ?20, ?21, ?22, ?23,
                1, ?24, ?25, ?26, ?27
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
                task.next_retry_epoch,
                task.lease_owner,
                task.lease_expires_epoch,
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
                updated_epoch = ?25, next_retry_epoch = ?27, lease_owner = ?28, lease_expires_epoch = ?29
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
                old.version, next.next_retry_epoch, next.lease_owner, next.lease_expires_epoch,
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
                let next = task.clone();
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
        self.sync_task_with_mode(incoming, SyncMode::Standard)
    }

    /// Offline mode requires the caller to hold DaemonLock and exclude all workers
    /// before opening this store. Ordinary daemon intake must use Standard.
    pub fn sync_task_with_mode(
        &mut self,
        incoming: &TaskRecord,
        mode: SyncMode,
    ) -> Result<TaskRecord, V2StoreError> {
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
                let verified_delivery: bool = old.status == "Done" && tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM post_merge_deliveries WHERE task_id=?1)
                        AND NOT EXISTS(SELECT 1 FROM post_merge_deliveries WHERE task_id=?1 AND state!='verified')",
                    [&old.task_id], |row| row.get(0),
                )?;
                if should_preserve_zach_state(&old, incoming)
                    || (verified_delivery && !is_terminal_task_status(&incoming.status))
                {
                    next.status = old.status.clone();
                    next.stages_completed = old.stages_completed.clone();
                    next.current_stage = old.current_stage.clone();
                    next.active_attempt_id = old.active_attempt_id.clone();
                    next.plan_base_sha = old.plan_base_sha.clone();
                    next.reviewed_sha = old.reviewed_sha.clone();
                    next.pr_number = old.pr_number;
                    next.executor = old.executor.clone();
                    if incoming.executor.as_deref().is_some_and(|executor| {
                        !executor.trim().is_empty() && !executor.eq_ignore_ascii_case("zach")
                    }) {
                        next.autonomous_consent = false;
                    }
                    next.retry_count = old.retry_count;
                    next.memory = old.memory.clone();
                    next.memory.governance_started |= incoming.memory.governance_started;
                    next.weight = if crate::v2::pipeline::weight_rank(&old.weight)
                        >= crate::v2::pipeline::weight_rank(&incoming.weight)
                    {
                        old.weight.clone()
                    } else {
                        incoming.weight.clone()
                    };
                    next.required_stages = crate::v2::intake::default_required_stages(&next.weight);
                    for stage in &old.required_stages {
                        if !next.required_stages.contains(stage) {
                            next.required_stages.push(stage.clone());
                        }
                    }
                    next.context_pack = old.context_pack.clone();
                    next.context_pack.weight = next.weight.clone();
                    next.repository = old.repository.clone();
                    next.github_repo = old.github_repo.clone();
                    next.issue_number = old.issue_number;
                    next.branch = old.branch.clone();
                    next.worktree_path = old.worktree_path.clone();
                    next.next_retry_epoch = old.next_retry_epoch;
                    next.lease_owner = old.lease_owner.clone();
                    next.lease_expires_epoch = old.lease_expires_epoch;
                } else {
                    coalesce_runtime_fields(&old, &mut next);
                    next.retry_count = old.retry_count.max(next.retry_count);
                }
                let offline_terminal = mode == SyncMode::ReconcileFinishedLegacy
                    && matches!(incoming.status.as_str(), "Done" | "Cancelled");
                let retire = offline_terminal && Self::can_retire_finished_tx(&tx, &old, incoming)?;
                if offline_terminal && !retire {
                    // A rejected proof must retain the blocker itself, including
                    // identity, lease, references and version. Export defaults
                    // must not make a subsequent reconciliation appear eligible.
                    return Ok(old);
                }
                if offline_terminal {
                    // An export is not the owner of completed stage or receipt history.
                    next.stages_completed = old.stages_completed.clone();
                    next.memory = old.memory.clone();
                    next.autonomous_consent = old.autonomous_consent;
                    next.current_stage = old.current_stage.clone();
                    next.retry_count = old.retry_count;
                    if retire {
                        next.active_attempt_id = None;
                    }
                }
                next.memory.governance_terminal_observed |= old.memory.governance_terminal_observed
                    || is_terminal_task_status(&incoming.status);
                let saved = Self::update_task_tx(&tx, &old, &next, now)?;
                if retire {
                    // BEGIN IMMEDIATE excludes competing writers. Check the result
                    // before deleting coordination state, including trigger failures.
                    let persisted = Self::get_task_tx(&tx, &old.task_id)?
                        .ok_or_else(|| V2StoreError("reconciliation task disappeared".into()))?;
                    if persisted.version != saved.version || persisted.active_attempt_id.is_some() {
                        return Err(V2StoreError(
                            "reconciliation task update did not succeed".into(),
                        ));
                    }
                    tx.execute(
                        "DELETE FROM merge_queue WHERE repo=?1 AND task_id=?2 AND state='FAILED'",
                        params![old.repository, old.task_id],
                    )?;
                }
                saved
            }
            None => {
                let mut next = incoming.clone();
                next.memory.governance_terminal_observed |=
                    is_terminal_task_status(&incoming.status);
                Self::insert_task_tx(&tx, &next, now)?
            }
        };
        tx.commit()?;
        Ok(result)
    }

    fn can_retire_finished_tx(
        tx: &rusqlite::Transaction<'_>,
        old: &TaskRecord,
        incoming: &TaskRecord,
    ) -> Result<bool, V2StoreError> {
        let pending_memory = |t: &TaskRecord| {
            t.memory.pipeline_checkpoint.is_some()
                || t.memory.merge_checkpoint.is_some()
                || t.memory.suspended_impl_attempt_id.is_some()
        };
        if old.repository != incoming.repository
            || pending_memory(old)
            || pending_memory(incoming)
            || incoming
                .active_attempt_id
                .as_ref()
                .is_some_and(|id| Some(id) != old.active_attempt_id.as_ref())
            || old.lease_owner.is_some()
            || old.lease_expires_epoch.is_some()
            || incoming.lease_owner.is_some()
            || incoming.lease_expires_epoch.is_some()
        {
            return Ok(false);
        }
        let effects: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM lifecycle_ops WHERE task_id=?1 AND state!='ACKNOWLEDGED') OR EXISTS(SELECT 1 FROM post_merge_deliveries WHERE task_id=?1 AND state!='verified') OR EXISTS(SELECT 1 FROM merge_queue WHERE task_id=?1 AND state!='FAILED')", [&old.task_id], |r| r.get(0))?;
        if effects {
            return Ok(false);
        }
        let decisions = tx
            .prepare("SELECT decision_id,status FROM pending_decisions WHERE task_id=?1")?
            .query_map([&old.task_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if decisions
            .iter()
            .any(|(id, status)| status != "RESOLVED" || !old.memory.applied_decisions.contains(id))
        {
            return Ok(false);
        }
        // Canonical completed labels (including human approvals) are metadata,
        // not native completion proof. Only persisted stages prove a passed
        // attempt finished; successful sync retains that exact persisted vector.
        let attempts = tx.prepare("SELECT attempt_id,stage,status,phase,ended_epoch FROM stage_attempts WHERE task_id=?1")?
            .query_map([&old.task_id], |r| Ok((r.get::<_, String>(0)?,r.get::<_, String>(1)?,r.get::<_, String>(2)?,r.get::<_, String>(3)?,r.get::<_, Option<i64>>(4)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        if attempts.is_empty()
            || attempts.iter().any(|(_, stage, status, phase, end)| {
                end.is_none()
                    || phase != "COMPLETE"
                    || !matches!(status.as_str(), "PASSED" | "FAILED")
                    || (status == "PASSED" && !old.stages_completed.contains(stage))
            })
        {
            return Ok(false);
        }
        Ok(old.active_attempt_id.as_ref().is_none_or(|id| {
            attempts.iter().any(|(a, stage, status, _, _)| {
                a == id && status == "PASSED" && old.stages_completed.contains(stage)
            })
        }))
    }

    fn upsert_delivery_tx(
        tx: &rusqlite::Transaction<'_>,
        delivery: &PostMergeDelivery,
    ) -> Result<(), V2StoreError> {
        let changed = tx.execute(
            "INSERT INTO post_merge_deliveries (
                 delivery_id, task_id, repository, github_repo, merge_sha, kind,
                 name, state, workflow, run_id, build_run_id, artifact_digest,
                 expected_current, evidence_json, rule_json, decision_id, attempt, updated_epoch
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
             ON CONFLICT(delivery_id) DO UPDATE SET
                 state = excluded.state, workflow = excluded.workflow,
                 run_id = excluded.run_id, build_run_id = excluded.build_run_id,
                 artifact_digest = excluded.artifact_digest,
                 expected_current = excluded.expected_current,
                 evidence_json = excluded.evidence_json, rule_json = excluded.rule_json,
                 decision_id = excluded.decision_id, attempt = excluded.attempt,
                 updated_epoch = excluded.updated_epoch
             WHERE post_merge_deliveries.task_id = excluded.task_id
               AND post_merge_deliveries.merge_sha = excluded.merge_sha",
            params![
                delivery.delivery_id, delivery.task_id, delivery.repository,
                delivery.github_repo, delivery.merge_sha, delivery.kind,
                delivery.name, delivery.state, delivery.workflow, delivery.run_id,
                delivery.build_run_id, delivery.artifact_digest, delivery.expected_current,
                serde_json::to_string(&delivery.evidence_json)?,
                serde_json::to_string(&delivery.rule_json)?, delivery.decision_id,
                delivery.attempt, delivery.updated_epoch,
            ],
        )?;
        if changed == 0 {
            return Err(V2StoreError(
                "delivery_id is already bound to another task or merge".into(),
            ));
        }
        Ok(())
    }

    pub fn upsert_delivery(&mut self, delivery: &PostMergeDelivery) -> Result<(), V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::upsert_delivery_tx(&tx, delivery)?;
        tx.commit()?;
        Ok(())
    }

    /// Checkpoint task and delivery rows together before releasing merge lane/locks.
    pub fn save_deliveries_and_task(
        &mut self,
        task: &TaskRecord,
        deliveries: &[PostMergeDelivery],
    ) -> Result<(), V2StoreError> {
        self.save_delivery_checkpoint(task, deliveries, None)
    }

    /// Delivery verification and its receipt commit together; task completion
    /// remains exclusively owned by the close acknowledgment.
    pub fn save_delivery_status(
        &mut self,
        task: &TaskRecord,
        verified_rows: Option<&[PostMergeDelivery]>,
    ) -> Result<(), V2StoreError> {
        let payload = verified_rows.map(|rows| serde_json::json!({"deliveries": rows}));
        self.save_delivery_checkpoint(task, &[], payload.as_ref())
    }

    fn save_delivery_checkpoint(
        &mut self,
        task: &TaskRecord,
        deliveries: &[PostMergeDelivery],
        verified_event: Option<&serde_json::Value>,
    ) -> Result<(), V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now_epoch();
        match Self::get_task_tx(&tx, &task.task_id)? {
            Some(old) => {
                if (is_terminal_task_status(&old.status) || old.status == "Delivery Aborted")
                    && task.status != old.status
                {
                    return Err(V2StoreError(
                        "delivery checkpoint cannot change a terminal task".into(),
                    ));
                }

                Self::update_task_tx(&tx, &old, task, now)?;
            }
            None => {
                Self::insert_task_tx(&tx, task, now)?;
            }
        }
        for delivery in deliveries {
            if delivery.task_id != task.task_id {
                return Err(V2StoreError("delivery belongs to another task".into()));
            }
            Self::upsert_delivery_tx(&tx, delivery)?;
        }
        if let Some(payload) = verified_event {
            let rows = payload["deliveries"]
                .as_array()
                .filter(|rows| !rows.is_empty())
                .ok_or_else(|| V2StoreError("verification requires delivery evidence".into()))?;
            let sha = rows[0]["merge_sha"]
                .as_str()
                .ok_or_else(|| V2StoreError("verification requires merge SHA".into()))?;
            if rows.iter().any(|row| {
                row["task_id"] != task.task_id
                    || row["merge_sha"] != sha
                    || row["state"] != "verified"
            }) {
                return Err(V2StoreError(
                    "inconsistent delivery verification evidence".into(),
                ));
            }
            if !Self::delivery_verification_recorded_on(&tx, &task.task_id, sha)? {
                Self::insert_event_tx(
                    &tx,
                    &task.task_id,
                    &task.task_group,
                    now,
                    "POST_MERGE_DELIVERY_VERIFIED",
                    payload,
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn delivery_verification_recorded(
        &self,
        task_id: &str,
        sha: &str,
    ) -> Result<bool, V2StoreError> {
        Self::delivery_verification_recorded_on(&self.conn, task_id, sha)
    }

    fn delivery_verification_recorded_on(
        conn: &Connection,
        task_id: &str,
        sha: &str,
    ) -> Result<bool, V2StoreError> {
        let mut stmt = conn.prepare("SELECT payload_json FROM task_events WHERE task_id=?1 AND event_type='POST_MERGE_DELIVERY_VERIFIED'")?;
        for payload in stmt.query_map([task_id], |row| row.get::<_, String>(0))? {
            let payload: serde_json::Value = serde_json::from_str(&payload?)?;
            if payload["deliveries"].as_array().is_some_and(|rows| {
                !rows.is_empty()
                    && rows
                        .iter()
                        .all(|row| row["merge_sha"] == sha && row["state"] == "verified")
            }) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Repair only a Zach-owned, provably unfinished legacy delivery close.
    /// An authoritative terminal export or an acknowledged close always wins.
    pub fn recover_unclosed_delivery(
        &mut self,
        id: &str,
    ) -> Result<Option<TaskRecord>, V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(old) = Self::get_task_tx(&tx, id)? else {
            return Ok(None);
        };
        if old.status != "Done"
            || !is_zach_executor(old.executor.as_deref())
            || old.memory.governance_terminal_observed
            || old.memory.halt_requested
            || !old.autonomous_consent
        {
            return Ok(None);
        }
        let Some(cp) = old.memory.merge_checkpoint.as_ref().filter(|cp| {
            cp.post_merge_verified
                && matches!(cp.phase.as_str(), "DELIVERY_PENDING" | "CLOSE_PENDING")
                && Some(cp.pr_number) == old.pr_number
        }) else {
            return Ok(None);
        };
        let Some(sha) = cp.merge_sha.as_deref().filter(|sha| !sha.is_empty()) else {
            return Ok(None);
        };
        let matches_receipt: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM post_merge_deliveries WHERE task_id=?1)
             AND NOT EXISTS(SELECT 1 FROM post_merge_deliveries WHERE task_id=?1 AND (state!='verified' OR merge_sha!=?2))
             AND NOT EXISTS(SELECT 1 FROM lifecycle_ops WHERE task_id=?1 AND kind='close' AND state='ACKNOWLEDGED')",
            params![id, sha], |row| row.get(0),
        )?;
        if !matches_receipt {
            return Ok(None);
        }
        let mut next = old.clone();
        next.status = "Delivery Pending".into();
        next.memory.merge_lane_released = true;
        let saved = Self::update_task_tx(&tx, &old, &next, now_epoch())?;
        tx.commit()?;
        Ok(Some(saved))
    }

    /// Record a completed board write without replacing delivery/decision state
    /// captured before network I/O. A concurrent decision invalidates this receipt.
    pub fn mark_delivery_board_synced(
        &mut self,
        task_id: &str,
        expected_version: i64,
        status: &str,
    ) -> Result<bool, V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(task) = Self::get_task_tx(&tx, task_id)? else {
            return Ok(false);
        };
        if task.version != expected_version || task.status != status {
            return Ok(false);
        }
        let rows: Vec<(String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT delivery_id, evidence_json FROM post_merge_deliveries WHERE task_id = ?1",
            )?;
            stmt.query_map(params![task_id], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<Result<_, _>>()?
        };
        for (id, raw) in rows {
            let mut evidence: serde_json::Value = serde_json::from_str(&raw)?;
            evidence["board_synced_status"] = serde_json::json!(status);
            tx.execute(
                "UPDATE post_merge_deliveries SET evidence_json = ?2 WHERE delivery_id = ?1",
                params![id, serde_json::to_string(&evidence)?],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    pub fn list_deliveries(
        &self,
        task_id: Option<&str>,
    ) -> Result<Vec<PostMergeDelivery>, V2StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT delivery_id, task_id, repository, github_repo, merge_sha, kind,
                    name, state, workflow, run_id, build_run_id, artifact_digest,
                    expected_current, evidence_json, rule_json, decision_id, attempt, updated_epoch
             FROM post_merge_deliveries WHERE (?1 IS NULL OR task_id = ?1)
             ORDER BY delivery_id",
        )?;
        let records = stmt.query_map(params![task_id], |row| {
            let json_at = |index| -> rusqlite::Result<serde_json::Value> {
                let raw: String = row.get(index)?;
                serde_json::from_str(&raw).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        index,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
            };
            Ok(PostMergeDelivery {
                delivery_id: row.get(0)?,
                task_id: row.get(1)?,
                repository: row.get(2)?,
                github_repo: row.get(3)?,
                merge_sha: row.get(4)?,
                kind: row.get(5)?,
                name: row.get(6)?,
                state: row.get(7)?,
                workflow: row.get(8)?,
                run_id: row.get(9)?,
                build_run_id: row.get(10)?,
                artifact_digest: row.get(11)?,
                expected_current: row.get(12)?,
                evidence_json: json_at(13)?,
                rule_json: json_at(14)?,
                decision_id: row.get(15)?,
                attempt: row.get(16)?,
                updated_epoch: row.get(17)?,
            })
        })?;
        records
            .collect::<Result<Vec<_>, _>>()
            .map_err(V2StoreError::from)
    }

    pub fn get_task(&self, task_id: &str) -> Result<Option<TaskRecord>, V2StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT task_id, task_group, title, repository, github_repo, issue_number,
                    weight, status, worktree_path, branch, context_pack_json,
                    depends_on_json, required_stages_json, stages_completed_json,
                    current_stage, active_attempt_id, plan_base_sha, reviewed_sha,
                    pr_number, executor, autonomous_consent, retry_count, memory_json,
                    version, updated_epoch, next_retry_epoch, lease_owner, lease_expires_epoch
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
                        version, updated_epoch, next_retry_epoch, lease_owner, lease_expires_epoch
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
                        version, updated_epoch, next_retry_epoch, lease_owner, lease_expires_epoch
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
            if task.status != "Ready"
                || !task.autonomous_consent
                || task.next_retry_epoch > now_epoch()
                || self.has_pending_lifecycle(&task.task_id)?
            {
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
        if let Some(existing) = self.get_decision(decision_id)? {
            return Ok(existing);
        }
        let now = now_epoch();
        let bounded_context = crate::v2::runner::truncate_utf8_bytes(
            context_summary,
            crate::v2::runner::MAX_SUMMARY_BYTES,
        );
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
                bounded_context,
                sha,
                seq_id,
            ],
        )?;
        tx.execute(
            "UPDATE tasks SET status = CASE
                 WHEN status IN ('Delivery Pending', 'Waiting New APK', 'Pending Prod Promotion', 'Delivery Aborted', 'Done', 'Cancelled') THEN status
                 WHEN ?3 IN ('new_apk_required', 'prod_promotion_approval', 'delivery_contract_error') THEN 'Delivery Pending'
                 ELSE 'Blocked' END,
                 version = version + 1, updated_epoch = ?2 WHERE task_id = ?1",
            params![task_id, now, kind],
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
        let choice = if let Some(existing) = self.get_decision(decision_id)? {
            if existing.status == "RESOLVED" {
                return Ok(DecisionResolution::AlreadyResolved(existing));
            }
            let task = self
                .get_task(&existing.task_id)?
                .ok_or_else(|| V2StoreError("decision task missing".into()))?;
            let delivery = existing.kind != "governance_close_failed"
                && (is_post_merge_decision(&existing.kind)
                    || is_post_merge_status(&task.status)
                    || !self.list_deliveries(Some(&existing.task_id))?.is_empty());
            let selected = if delivery {
                choice
                    .parse::<usize>()
                    .ok()
                    .and_then(|index| index.checked_sub(1))
                    .and_then(|index| existing.options.get(index))
                    .or_else(|| {
                        existing
                            .options
                            .iter()
                            .find(|o| o.eq_ignore_ascii_case(choice))
                    })
            } else {
                existing.options.iter().find(|o| o.as_str() == choice)
            };
            if resolved_by.trim().is_empty() || selected.is_none() {
                return Err(V2StoreError(
                    "invalid decision choice or empty actor".into(),
                ));
            }
            selected.cloned().unwrap_or_default()
        } else {
            return Ok(DecisionResolution::NotFound);
        };
        let choice = choice.as_str();
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

        let task_status: String = tx.query_row(
            "SELECT status FROM tasks WHERE task_id = ?1",
            params![task_id],
            |row| row.get(0),
        )?;
        let linked: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM post_merge_deliveries WHERE task_id = ?1)",
            params![task_id],
            |row| row.get(0),
        )?;
        let post_merge = kind != "governance_close_failed"
            && (is_post_merge_decision(&kind) || is_post_merge_status(&task_status) || linked);
        let mut next_status = task_status.as_str();
        if post_merge {
            let options_raw: String = tx.query_row(
                "SELECT options_json FROM pending_decisions WHERE decision_id = ?1",
                params![decision_id],
                |row| row.get(0),
            )?;
            let options: Vec<String> = serde_json::from_str(&options_raw)?;
            // Accept the displayed option or its one-based CLI index. Persist the
            // canonical option so approval cannot be inferred from free-form text.
            let selected = choice
                .parse::<usize>()
                .ok()
                .and_then(|index| index.checked_sub(1))
                .and_then(|index| options.get(index))
                .or_else(|| {
                    options
                        .iter()
                        .find(|option| option.eq_ignore_ascii_case(choice))
                })
                .ok_or_else(|| V2StoreError("choice is not a post-merge decision option".into()))?;
            let first_word = selected
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            let rejected = matches!(first_word.as_str(), "reject" | "abort" | "cancel");
            let approved =
                kind == "prod_promotion_approval" && selected.eq_ignore_ascii_case("Approve");
            let terminal =
                is_terminal_task_status(&task_status) || task_status == "Delivery Aborted";
            next_status = if terminal {
                &task_status
            } else if rejected {
                "Delivery Aborted"
            } else {
                "Delivery Pending"
            };
            let delivery_state = if rejected || terminal {
                "aborted"
            } else if approved {
                "approved"
            } else {
                "pending"
            };
            tx.execute(
                "UPDATE post_merge_deliveries SET state = ?2,
                     attempt = attempt + 1,
                     run_id = CASE WHEN ?2 = 'pending' THEN NULL ELSE run_id END,
                     decision_id = CASE WHEN ?2 = 'pending' THEN NULL ELSE decision_id END,
                     updated_epoch = ?3
                 WHERE task_id = ?4 AND decision_id = ?1",
                params![decision_id, delivery_state, now, task_id],
            )?;
            tx.execute(
                "UPDATE pending_decisions SET choice = ?2 WHERE decision_id = ?1",
                params![decision_id, selected],
            )?;
        }

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
            "UPDATE tasks SET status = ?4,
                              memory_json = ?2,
                              version = version + 1,
                              updated_epoch = ?3
             WHERE task_id = ?1",
            params![task_id, updated_memory_json, now, next_status],
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
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::record_stage_attempt_tx(&tx, attempt)?;
        tx.commit()?;
        Ok(())
    }

    fn record_stage_attempt_tx(
        tx: &rusqlite::Transaction<'_>,
        attempt: &StageAttemptRecord,
    ) -> Result<(), V2StoreError> {
        let now = now_epoch();
        let bounded_summary = attempt.summary.as_deref().map(|s| {
            crate::v2::runner::truncate_utf8_bytes(s, crate::v2::runner::MAX_SUMMARY_BYTES)
        });
        let previous: Option<(String, Option<i64>)> = tx
            .query_row(
                "SELECT status,ended_epoch FROM stage_attempts WHERE attempt_id=?1",
                [&attempt.attempt_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        tx.execute(
            "INSERT INTO stage_attempts (
                attempt_id, task_id, stage, model, effort, systemd_unit, invocation_id,
                started_epoch, ended_epoch, status, failure_class, summary,
                input_tokens, output_tokens, total_tokens, sha_before, sha_after, phase, last_liveness_epoch, last_output_bytes, last_cpu_usage_usec, control_group, exit_code, exit_code_kind, retry_generation
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25
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
                sha_after = excluded.sha_after, phase = excluded.phase,
                last_liveness_epoch = excluded.last_liveness_epoch,
                last_output_bytes = excluded.last_output_bytes,
                last_cpu_usage_usec = excluded.last_cpu_usage_usec,
                control_group = excluded.control_group, exit_code = excluded.exit_code,
                exit_code_kind = excluded.exit_code_kind, retry_generation = excluded.retry_generation",
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
                bounded_summary,
                attempt
                    .input_tokens
                    .map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
                attempt
                    .output_tokens
                    .map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
                attempt
                    .total_tokens
                    .map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
                attempt.sha_before,
                attempt.sha_after, attempt.phase,
                if attempt.last_liveness_epoch == 0 { attempt.started_epoch } else { attempt.last_liveness_epoch },
                attempt.last_output_bytes, attempt.last_cpu_usage_usec, attempt.control_group,
                attempt.exit_code, attempt.exit_code_kind, attempt.retry_generation,
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

        let event_type = if previous.is_none() {
            Some(if attempt.ended_epoch.is_some() {
                "STAGE_COMPLETED"
            } else {
                "STAGE_STARTED"
            })
        } else if attempt.ended_epoch.is_some()
            && previous
                .as_ref()
                .is_some_and(|(status, ended)| ended.is_none() || status != &attempt.status)
        {
            Some("STAGE_COMPLETED")
        } else {
            None
        };
        if let Some(event_type) = event_type {
            Self::insert_event_tx(
                tx,
                &attempt.task_id,
                &task_group,
                now,
                event_type,
                &serde_json::json!({"attempt_id":attempt.attempt_id,"stage":attempt.stage,"model":attempt.model,"effort":attempt.effort,"status":attempt.status,"total_tokens":attempt.total_tokens}),
            )?;
        }
        Ok(())
    }

    /// Checkpoints task and attempt together, optionally releasing an ordinary
    /// pre-merge lane and opening its failure decision in the same transaction.
    pub fn transition_attempt(
        &mut self,
        task: &TaskRecord,
        attempt: &StageAttemptRecord,
        release: bool,
        decision: Option<&FailureDecision>,
    ) -> Result<(), V2StoreError> {
        self.transition_task(task, Some(attempt), release, decision)
    }

    pub fn transition_task(
        &mut self,
        task: &TaskRecord,
        attempt: Option<&StageAttemptRecord>,
        release: bool,
        decision: Option<&FailureDecision>,
    ) -> Result<(), V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = Self::get_task_tx(&tx, &task.task_id)?
            .ok_or_else(|| V2StoreError("transition task missing".into()))?;
        Self::update_task_tx(&tx, &old, task, now_epoch())?;
        if let Some(attempt) = attempt {
            Self::record_stage_attempt_tx(&tx, attempt)?;
        }
        if release {
            tx.execute("DELETE FROM path_locks WHERE task_id=?1", [&task.task_id])?;
            tx.execute("DELETE FROM merge_queue WHERE task_id=?1", [&task.task_id])?;
        }
        if let Some(decision) = decision {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM pending_decisions WHERE decision_id=?1)",
                [&decision.decision_id],
                |r| r.get(0),
            )?;
            if !exists {
                let seq = Self::insert_event_tx(
                    &tx,
                    &task.task_id,
                    &task.task_group,
                    now_epoch(),
                    "DECISION_REQUIRED",
                    &serde_json::json!({"decision_id":decision.decision_id,"kind":decision.kind,"question":decision.question,"options":decision.options,"sha":decision.sha}),
                )?;
                tx.execute("INSERT INTO pending_decisions(decision_id,task_id,task_group,kind,question,options_json,recommended_option,context_summary,sha,status,created_seq) VALUES(?1,?2,?3,?4,?5,?6,0,?7,?8,'OPEN',?9)",params![decision.decision_id,task.task_id,task.task_group,decision.kind,decision.question,serde_json::to_string(&decision.options)?,crate::v2::runner::truncate_utf8_bytes(&decision.context,1024),decision.sha,seq])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Reads a single `stage_attempts` row by `attempt_id`.
    pub fn get_stage_attempt(
        &self,
        attempt_id: &str,
    ) -> Result<Option<StageAttemptRecord>, V2StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT attempt_id, task_id, stage, model, effort, systemd_unit, invocation_id,
                    started_epoch, ended_epoch, status, failure_class, summary,
                    input_tokens, output_tokens, total_tokens, sha_before, sha_after, phase, last_liveness_epoch, last_output_bytes, last_cpu_usage_usec, control_group, exit_code, exit_code_kind, retry_generation
             FROM stage_attempts WHERE attempt_id = ?1",
        )?;
        stmt.query_row(params![attempt_id], Self::map_stage_attempt_row)
            .optional()
            .map_err(V2StoreError::from)
    }

    /// Lists all `stage_attempts` rows for `task_id` in insertion order.
    pub fn list_stage_attempts(
        &self,
        task_id: &str,
    ) -> Result<Vec<StageAttemptRecord>, V2StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT attempt_id, task_id, stage, model, effort, systemd_unit, invocation_id,
                    started_epoch, ended_epoch, status, failure_class, summary,
                    input_tokens, output_tokens, total_tokens, sha_before, sha_after, phase, last_liveness_epoch, last_output_bytes, last_cpu_usage_usec, control_group, exit_code, exit_code_kind, retry_generation
             FROM stage_attempts WHERE task_id = ?1 ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map(params![task_id], Self::map_stage_attempt_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn acquire_path_locks(
        &mut self,
        repo: &str,
        _paths: &[String],
        task_id: &str,
    ) -> Result<bool, V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let conflict: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM path_locks WHERE repo=?1 AND task_id!=?2)",
            params![repo, task_id],
            |r| r.get(0),
        )?;
        if conflict {
            return Ok(false);
        }
        tx.execute(
            "DELETE FROM path_locks WHERE repo=?1 AND task_id=?2 AND path!='*'",
            params![repo, task_id],
        )?;
        tx.execute("INSERT OR IGNORE INTO path_locks(repo,path,task_id,acquired_epoch) VALUES(?1,'*',?2,?3)",params![repo,task_id,now_epoch()])?;
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

    pub fn occupies_task_slot(&self, task: &TaskRecord) -> Result<bool, V2StoreError> {
        if matches!(
            task.status.as_str(),
            "Planning" | "Plan Review" | "In Progress" | "PR Review"
        ) {
            return Ok(true);
        }
        let Some(id) = task.active_attempt_id.as_deref() else {
            return Ok(false);
        };
        Ok(self.get_stage_attempt(id)?.is_some_and(|a| {
            matches!(
                a.phase.as_str(),
                "LAUNCH_PENDING" | "RUNNING" | "EXIT_OBSERVED" | "HARVESTED"
            )
        }))
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
            active_units: all_tasks
                .iter()
                .filter_map(|t| t.active_attempt_id.as_deref())
                .map(|id| self.get_stage_attempt(id))
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .flatten()
                .filter(|a| {
                    matches!(
                        a.phase.as_str(),
                        "LAUNCH_PENDING" | "RUNNING" | "EXIT_OBSERVED" | "HARVESTED"
                    )
                })
                .count(),
            occupied_repositories: self
                .list_path_locks(None)?
                .iter()
                .map(|l| &l.repo)
                .collect::<BTreeSet<_>>()
                .len(),
            running_task_slots: all_tasks
                .iter()
                .map(|t| self.occupies_task_slot(t))
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .filter(|occupied| **occupied)
                .count(),
            backoff_tasks: all_tasks
                .iter()
                .filter(|t| t.next_retry_epoch > now_epoch())
                .count(),
            pending_write_backs: self
                .lifecycle_ops()?
                .iter()
                .filter(|o| o.state != "ACKNOWLEDGED")
                .count(),
            reconciliation_errors: self
                .meta("reconciliation_errors")?
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            last_sync_epoch: self
                .meta("last_sync_epoch")?
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
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
            next_retry_epoch: row.get(25)?,
            lease_owner: row.get(26)?,
            lease_expires_epoch: row.get(27)?,
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

    fn map_stage_attempt_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StageAttemptRecord> {
        let input_tokens: Option<i64> = row.get(12)?;
        let output_tokens: Option<i64> = row.get(13)?;
        let total_tokens: Option<i64> = row.get(14)?;
        Ok(StageAttemptRecord {
            attempt_id: row.get(0)?,
            task_id: row.get(1)?,
            stage: row.get(2)?,
            model: row.get(3)?,
            effort: row.get(4)?,
            systemd_unit: row.get(5)?,
            invocation_id: row.get(6)?,
            started_epoch: row.get(7)?,
            ended_epoch: row.get(8)?,
            status: row.get(9)?,
            failure_class: row.get(10)?,
            summary: row.get(11)?,
            input_tokens: input_tokens.and_then(|v| u64::try_from(v).ok()),
            output_tokens: output_tokens.and_then(|v| u64::try_from(v).ok()),
            total_tokens: total_tokens.and_then(|v| u64::try_from(v).ok()),
            sha_before: row.get(15)?,
            sha_after: row.get(16)?,
            phase: row.get(17)?,
            last_liveness_epoch: row.get(18)?,
            last_output_bytes: row.get(19)?,
            last_cpu_usage_usec: row.get(20)?,
            control_group: row.get(21)?,
            exit_code: row.get(22)?,
            exit_code_kind: row.get(23)?,
            retry_generation: row.get(24)?,
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
    } else if next.memory.merge_checkpoint.is_none() {
        // Board exports cannot replace a durable merge/delivery receipt.
        next.memory.merge_checkpoint = old.memory.merge_checkpoint.clone();
        next.memory.merge_lane_released = old.memory.merge_lane_released;
    }
}

fn is_zach_executor(executor: Option<&str>) -> bool {
    executor.is_some_and(|e| e.trim().eq_ignore_ascii_case("zach"))
}

pub fn is_post_merge_status(status: &str) -> bool {
    matches!(
        status,
        "Delivery Pending" | "Waiting New APK" | "Pending Prod Promotion" | "Delivery Aborted"
    )
}

fn is_post_merge_decision(kind: &str) -> bool {
    matches!(
        kind,
        "new_apk_required" | "prod_promotion_approval" | "delivery_contract_error"
    )
}

fn should_preserve_zach_state(existing: &TaskRecord, incoming: &TaskRecord) -> bool {
    (is_post_merge_status(&existing.status)
        || (is_zach_executor(existing.executor.as_deref())
            && !is_terminal_task_status(&existing.status)))
        && !is_terminal_task_status(&incoming.status)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct LegacyTestDb(std::path::PathBuf);
    impl LegacyTestDb {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "zach-legacy-{}-{}.sqlite3",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            Self(path)
        }
    }
    impl Drop for LegacyTestDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(self.0.with_extension("sqlite3-wal"));
            let _ = std::fs::remove_file(self.0.with_extension("sqlite3-shm"));
        }
    }
    fn finished_fixture(store: &mut V2Store) -> TaskRecord {
        let mut task = sample_task("SYNTHETIC-1", "Queued for Merge", vec![]);
        task.stages_completed = vec!["impl".into()];
        task.current_stage = Some("impl".into());
        task.active_attempt_id = Some("finished".into());
        task.memory.recent_attempts = vec!["history".into()];
        let task = store.upsert_task(&task).unwrap();
        store.conn.execute_batch("INSERT INTO stage_attempts(attempt_id,task_id,stage,model,effort,started_epoch,ended_epoch,status,phase,last_liveness_epoch,summary,input_tokens,sha_after) VALUES('finished','SYNTHETIC-1','impl','synthetic','low',10,20,'PASSED','COMPLETE',15,'preserve',42,'sha'); INSERT INTO merge_queue(repo,task_id,pr_number,reviewed_sha,enqueued_epoch,state) VALUES('zach','SYNTHETIC-1',1,'sha',30,'FAILED');").unwrap();
        task
    }
    fn terminal_input() -> TaskRecord {
        let mut t = sample_task("SYNTHETIC-1", "Done", vec![]);
        t.autonomous_consent = false; // stale export is not consent/history ownership
        t
    }

    #[test]
    fn finished_legacy_missing_phase_is_atomic_and_history_preserving_on_reopen() {
        let db = LegacyTestDb::new();
        let mut store = V2Store::open(&db.0).unwrap();
        finished_fixture(&mut store);
        for (id, status, end) in [
            ("failed", "FAILED", Some(20)),
            ("unknown", "OTHER", Some(20)),
            ("unended", "PASSED", None),
        ] {
            store.conn.execute("INSERT INTO stage_attempts(attempt_id,task_id,stage,model,effort,started_epoch,ended_epoch,status,phase,last_liveness_epoch) VALUES(?1,'SYNTHETIC-1','impl','synthetic','low',10,?2,?3,'RUNNING',15)",params![id,end,status]).unwrap();
        }
        let before = store.list_stage_attempts("SYNTHETIC-1").unwrap();
        store.conn.execute_batch("ALTER TABLE stage_attempts DROP COLUMN phase; UPDATE daemon_meta SET value='2' WHERE key='schema_version'; CREATE TRIGGER refuse_phase BEFORE UPDATE OF phase ON stage_attempts BEGIN SELECT RAISE(ABORT,'synthetic migration failure'); END;").unwrap();
        drop(store);
        assert!(V2Store::open(&db.0).is_err());
        let conn = Connection::open(&db.0).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM pragma_table_info('stage_attempts') WHERE name='phase'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        conn.execute_batch("DROP TRIGGER refuse_phase;").unwrap();
        drop(conn);
        for _ in 0..2 {
            let store = V2Store::open(&db.0).unwrap();
            let after = store.list_stage_attempts("SYNTHETIC-1").unwrap();
            for original in &before {
                let mut expected = original.clone();
                expected.phase = if original.ended_epoch.is_some()
                    && matches!(original.status.as_str(), "PASSED" | "FAILED")
                {
                    "COMPLETE"
                } else {
                    "RUNNING"
                }
                .into();
                assert_eq!(
                    after
                        .iter()
                        .find(|a| a.attempt_id == original.attempt_id)
                        .unwrap(),
                    &expected
                );
            }
        }
    }

    #[test]
    fn finished_legacy_current_phases_are_never_reclassified() {
        let db = LegacyTestDb::new();
        let mut store = V2Store::open(&db.0).unwrap();
        finished_fixture(&mut store);
        for phase in ["RUNNING", "POSTPROCESSING", "HARVESTED", "COMPLETE"] {
            store
                .conn
                .execute("UPDATE stage_attempts SET phase=?1", [phase])
                .unwrap();
            let before = store.get_stage_attempt("finished").unwrap().unwrap();
            drop(store);
            store = V2Store::open(&db.0).unwrap();
            assert_eq!(
                store.get_stage_attempt("finished").unwrap().unwrap(),
                before
            );
        }
    }

    #[test]
    fn finished_legacy_opt_in_preserves_native_history_despite_export_completion_differences() {
        for terminal in ["Done", "Cancelled"] {
            for history in [
                vec![],
                vec!["impl"],
                vec!["impl", "human-plan", "human-merge"],
                vec!["external-completed-label"],
            ] {
                let db = LegacyTestDb::new();
                let mut store = V2Store::open(&db.0).unwrap();
                let old = finished_fixture(&mut store);
                let attempts = store.list_stage_attempts(&old.task_id).unwrap();
                let mut receipt = sample_delivery(&old);
                receipt.state = "verified".into();
                store.upsert_delivery(&receipt).unwrap();
                store.conn.execute_batch("ALTER TABLE stage_attempts DROP COLUMN phase; UPDATE daemon_meta SET value='2' WHERE key='schema_version'").unwrap();
                drop(store);
                store = V2Store::open(&db.0).unwrap();
                let mut incoming = terminal_input();
                incoming.status = terminal.into();
                incoming.stages_completed = history.iter().map(|s| s.to_string()).collect();
                let ordinary = store.sync_task(&incoming).unwrap();
                assert!(ordinary.active_attempt_id.is_some());
                assert_eq!(ordinary.stages_completed, incoming.stages_completed);
                // Ordinary sync behavior is unchanged. Restore its fixture so
                // only the opt-in path is responsible for native preservation.
                store.upsert_task(&old).unwrap();
                for _ in 0..2 {
                    let result = store
                        .sync_task_with_mode(&incoming, SyncMode::ReconcileFinishedLegacy)
                        .unwrap();
                    let mut expected = old.clone();
                    expected.status = terminal.into();
                    expected.active_attempt_id = None;
                    expected.memory.governance_terminal_observed = true;
                    expected.version = result.version;
                    expected.updated_epoch = result.updated_epoch;
                    assert_eq!(result, expected, "{terminal}: {history:?}");
                    assert!(store.list_merge_queue(None).unwrap().is_empty());
                    assert_eq!(store.list_stage_attempts(&old.task_id).unwrap(), attempts);
                    assert!(store.lifecycle_ops().unwrap().is_empty());
                    assert!(store.list_decisions(false, None).unwrap().is_empty());
                    assert_eq!(store.list_deliveries(None).unwrap(), vec![receipt.clone()]);
                    drop(store);
                    store = V2Store::open(&db.0).unwrap();
                    assert_eq!(store.get_task(&old.task_id).unwrap().unwrap(), result);
                    assert_eq!(store.list_stage_attempts(&old.task_id).unwrap(), attempts);
                    assert_eq!(store.list_deliveries(None).unwrap(), vec![receipt.clone()]);
                }
            }
        }
    }

    #[test]
    fn finished_legacy_ambiguous_or_recoverable_work_is_retained() {
        for case in [
            "nonterminal",
            "missing",
            "running",
            "postprocessing",
            "harvested",
            "unended",
            "unknown",
            "failed-ref",
            "stage",
            "pipeline",
            "merge",
            "suspended",
            "lease",
            "lease-expiry",
            "incoming-lease",
            "incoming-merge",
            "incoming-suspended",
            "lifecycle",
            "decision",
            "delivery",
            "queue",
            "repository",
            "incoming-checkpoint",
            "incoming-reference",
            "other-attempt",
        ] {
            let db = LegacyTestDb::new();
            let mut store = V2Store::open(&db.0).unwrap();
            let mut old = finished_fixture(&mut store);
            let mut input = terminal_input();
            // Even canonical completion of impl cannot satisfy a missing old
            // native completion. Extra labels must not mask any runtime conflict.
            input.stages_completed = vec!["impl".into(), "human-plan".into(), "human-merge".into()];
            match case {
                "nonterminal" => input.status = "Backlog".into(),
                "missing" => {
                    store
                        .conn
                        .execute("DELETE FROM stage_attempts", [])
                        .unwrap();
                }
                "running" | "postprocessing" | "harvested" => {
                    store
                        .conn
                        .execute("UPDATE stage_attempts SET phase=?1", [case.to_uppercase()])
                        .unwrap();
                }
                "unended" => {
                    store
                        .conn
                        .execute("UPDATE stage_attempts SET ended_epoch=NULL", [])
                        .unwrap();
                }
                "unknown" => {
                    store
                        .conn
                        .execute("UPDATE stage_attempts SET status='OTHER'", [])
                        .unwrap();
                }
                "failed-ref" => {
                    store
                        .conn
                        .execute("UPDATE stage_attempts SET status='FAILED'", [])
                        .unwrap();
                }
                "stage" => old.stages_completed.clear(),
                "pipeline" => {
                    old.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
                        attempt_id: "finished".into(),
                        operation: "VALIDATE".into(),
                    })
                }
                "incoming-checkpoint" => {
                    input.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
                        attempt_id: "finished".into(),
                        operation: "VALIDATE".into(),
                    })
                }
                "merge" => {
                    old.memory.merge_checkpoint = Some(MergeCheckpoint {
                        phase: "MERGE_PENDING".into(),
                        target_sha: "sha".into(),
                        pr_number: 1,
                        merge_sha: None,
                        post_merge_verified: false,
                        phase_started_epoch: 1,
                    })
                }
                "suspended" => old.memory.suspended_impl_attempt_id = Some("finished".into()),
                "lease" => old.lease_owner = Some("live".into()),
                "lease-expiry" => old.lease_expires_epoch = Some(9999999999),
                "incoming-lease" => input.lease_owner = Some("incoming-live".into()),
                "incoming-merge" => {
                    input.memory.merge_checkpoint = Some(MergeCheckpoint {
                        phase: "MERGE_PENDING".into(),
                        target_sha: "sha".into(),
                        pr_number: 1,
                        merge_sha: None,
                        post_merge_verified: false,
                        phase_started_epoch: 1,
                    })
                }
                "incoming-suspended" => {
                    input.memory.suspended_impl_attempt_id = Some("finished".into())
                }
                "lifecycle" => {
                    store.conn.execute_batch("INSERT INTO lifecycle_ops(operation_id,task_id,kind,args_json,state,created_epoch,updated_epoch) VALUES('pending','SYNTHETIC-1','close','[]','PENDING',1,1)").unwrap();
                }
                "decision" => {
                    store
                        .open_decision(
                            "decision",
                            &old.task_id,
                            "synthetic",
                            "test",
                            "test",
                            &["wait".into()],
                            None,
                            "test",
                            None,
                        )
                        .unwrap();
                }
                "delivery" => {
                    store.conn.execute_batch("INSERT INTO post_merge_deliveries(delivery_id,task_id,repository,github_repo,merge_sha,kind,name,state,workflow,updated_epoch) VALUES('receipt','SYNTHETIC-1','zach','owner/repo','sha','test','test','pending','test',1)").unwrap();
                }
                "queue" => {
                    store
                        .conn
                        .execute("UPDATE merge_queue SET state='QUEUED'", [])
                        .unwrap();
                }
                "repository" => input.repository = "other".into(),
                "incoming-reference" => input.active_attempt_id = Some("conflicting".into()),
                "other-attempt" => {
                    store.conn.execute_batch("INSERT INTO stage_attempts(attempt_id,task_id,stage,model,effort,started_epoch,status,last_liveness_epoch) VALUES('other','SYNTHETIC-1','impl','synthetic','low',1,'RUNNING',1)").unwrap();
                }
                _ => unreachable!(),
            }
            store.upsert_task(&old).unwrap();
            let attempts = store.list_stage_attempts(&old.task_id).unwrap();
            let persisted = store.get_task(&old.task_id).unwrap().unwrap();
            let queue = store.list_merge_queue(None).unwrap();
            for _ in 0..2 {
                let out = store
                    .sync_task_with_mode(&input, SyncMode::ReconcileFinishedLegacy)
                    .unwrap();
                assert!(out.active_attempt_id.is_some(), "{case}");
                if case != "nonterminal" {
                    assert_eq!(out, persisted, "rejected proof mutated {case}");
                    assert_eq!(
                        store.get_task(&old.task_id).unwrap().unwrap(),
                        persisted,
                        "repeated rejected proof mutated {case}"
                    );
                }
                assert_eq!(store.list_merge_queue(None).unwrap(), queue, "{case}");
                assert_eq!(
                    store.list_stage_attempts(&old.task_id).unwrap(),
                    attempts,
                    "{case}"
                );
                drop(store);
                store = V2Store::open(&db.0).unwrap();
                if case != "nonterminal" {
                    assert_eq!(
                        store.get_task(&old.task_id).unwrap().unwrap(),
                        persisted,
                        "reopen changed {case}"
                    );
                }
            }
        }
    }

    #[test]
    fn finished_legacy_verified_receipts_survive_without_replay() {
        let mut store = V2Store::open_in_memory().unwrap();
        let old = finished_fixture(&mut store);
        let mut receipt = sample_delivery(&old);
        receipt.state = "verified".into();
        store.upsert_delivery(&receipt).unwrap();
        store
            .sync_task_with_mode(&terminal_input(), SyncMode::ReconcileFinishedLegacy)
            .unwrap();
        assert_eq!(
            store.list_deliveries(Some(&old.task_id)).unwrap(),
            vec![receipt]
        );
        assert!(store.lifecycle_ops().unwrap().is_empty());
        assert!(
            store
                .get_task(&old.task_id)
                .unwrap()
                .unwrap()
                .active_attempt_id
                .is_none()
        );
    }

    #[test]
    fn finished_legacy_transaction_observes_new_checkpoint_and_rolls_back_failed_update() {
        let db = LegacyTestDb::new();
        let mut store = V2Store::open(&db.0).unwrap();
        finished_fixture(&mut store);
        let other = Connection::open(&db.0).unwrap();
        store
            .conn
            .busy_timeout(std::time::Duration::from_millis(10))
            .unwrap();
        other.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert!(
            store
                .sync_task_with_mode(&terminal_input(), SyncMode::ReconcileFinishedLegacy)
                .is_err()
        );
        assert_eq!(store.list_merge_queue(None).unwrap().len(), 1);
        other.execute_batch("ROLLBACK").unwrap();
        other.execute_batch(r#"BEGIN IMMEDIATE; UPDATE tasks SET memory_json='{"pipeline_checkpoint":{"attempt_id":"finished","operation":"PUSH"}}',version=version+1; COMMIT;"#).unwrap();
        let result = store
            .sync_task_with_mode(&terminal_input(), SyncMode::ReconcileFinishedLegacy)
            .unwrap();
        assert!(result.active_attempt_id.is_some());
        store.conn.execute_batch("UPDATE tasks SET memory_json='{}'; CREATE TRIGGER refuse_task BEFORE UPDATE ON tasks BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            store
                .sync_task_with_mode(&terminal_input(), SyncMode::ReconcileFinishedLegacy)
                .is_err()
        );
        assert_eq!(store.list_merge_queue(None).unwrap().len(), 1);
        assert!(
            store
                .get_task("SYNTHETIC-1")
                .unwrap()
                .unwrap()
                .active_attempt_id
                .is_some()
        );
    }

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
            next_retry_epoch: 0,
            lease_owner: None,
            lease_expires_epoch: None,
            memory: TaskMemory::default(),
            version: 1,
            updated_epoch: 1000,
        }
    }

    #[test]
    fn zach027_plan_memory_defaults_and_sync_preserve_approved_scope_weight_and_boundaries() {
        let legacy: TaskMemory =
            serde_json::from_str(r#"{"approved_plan":"legacy excerpt"}"#).unwrap();
        assert_eq!(legacy.plan_rework_count, 0);
        assert!(legacy.approved_plan_artifact_path.is_none());
        let mut store = V2Store::open_in_memory().unwrap();
        let mut old = sample_task("ZACH-027-SYNC", "Blocked", Vec::new());
        old.executor = Some("zach".to_owned());
        old.weight = "L".to_owned();
        old.context_pack.weight = "L".to_owned();
        old.context_pack.forbidden_paths = vec![
            "src/ledger/**".to_owned(),
            ".github/workflows/**".to_owned(),
            "private/**".to_owned(),
        ];
        old.context_pack.target_files = vec![TargetFileSpec {
            path: "src/v2/pipeline.rs".to_owned(),
            ..Default::default()
        }];
        old.context_pack.worker_checks = vec!["cargo test".to_owned()];
        old.context_pack.gate_checks = vec!["cargo fmt --check".to_owned()];
        old.memory.approved_plan = Some("bounded excerpt".to_owned());
        old.memory.approved_plan_artifact_path = Some("/state/plans/approved.md".to_owned());
        old.memory.candidate_plan_artifact_path = Some("/state/plans/candidate.md".to_owned());
        old.memory.plan_rework_count = 1;
        old.memory.last_plan_review_findings = Some("bounded findings".to_owned());
        store.upsert_task(&old).unwrap();
        let mut incoming = sample_task(&old.task_id, "Ready", Vec::new());
        incoming.weight = "M".to_owned();
        incoming.context_pack = ContextPackSpec::default();
        incoming.required_stages = crate::v2::intake::default_required_stages("M");
        store.sync_task(&incoming).unwrap();
        let saved = store.get_task(&old.task_id).unwrap().unwrap();
        assert_eq!(saved.weight, "L");
        assert_eq!(saved.context_pack.weight, "L");
        assert_eq!(
            saved.required_stages,
            crate::v2::intake::default_required_stages("L")
        );
        assert_eq!(saved.memory, old.memory);
        assert_eq!(
            saved.context_pack.target_files,
            old.context_pack.target_files
        );
        assert_eq!(
            saved.context_pack.forbidden_paths,
            old.context_pack.forbidden_paths
        );
        assert_eq!(
            saved.context_pack.worker_checks,
            old.context_pack.worker_checks
        );
        assert_eq!(saved.context_pack.gate_checks, old.context_pack.gate_checks);
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
        let mut store = V2Store::open_in_memory().unwrap();
        assert!(
            store
                .acquire_path_locks("zach", &["src/a.rs".into()], "TASK-1")
                .unwrap()
        );
        assert!(
            !store
                .acquire_path_locks("zach", &["src/b.rs".into()], "TASK-2")
                .unwrap()
        );
        assert!(
            store
                .acquire_path_locks("governance", &["*".into()], "TASK-2")
                .unwrap()
        );
        let locks = store.list_path_locks(Some("zach")).unwrap();
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].path, "*");
        assert_eq!(store.release_path_locks("TASK-1").unwrap(), 1);
        assert!(store.list_path_locks(Some("zach")).unwrap().is_empty());

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
        let mut expected_context = internal.context_pack.clone();
        expected_context.weight = stored.weight.clone();
        assert_eq!(stored.context_pack, expected_context);
        assert_eq!(stored.weight, "M");
        assert_eq!(stored.depends_on, vec!["GOV-050".to_owned()]);
        assert_eq!(stored.branch, internal.branch);
        assert_eq!(
            stored.worktree_path.as_deref(),
            internal.worktree_path.as_deref()
        );
        assert_eq!(stored.task_group, "platform");
        assert_eq!(stored.repository, internal.repository);
        assert_eq!(stored.github_repo, internal.github_repo);
        assert_eq!(stored.issue_number, internal.issue_number);
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

    #[test]
    fn sqlite_store_persists_retry_count_and_stage_attempt_failure_class() {
        let mut db_path = std::env::temp_dir();
        db_path.push(format!(
            "zach_v2_retry_failure_class_{}_{}.sqlite3",
            std::process::id(),
            now_epoch()
        ));
        let _ = std::fs::remove_file(&db_path);

        let mut store = V2Store::open(&db_path).expect("open file-backed sqlite store");
        let mut task = sample_task("ZACH-015", "Ready", Vec::new());
        store.upsert_task(&task).expect("insert task");
        assert_eq!(store.get_task("ZACH-015").unwrap().unwrap().retry_count, 0);

        task.retry_count += 1;
        store.upsert_task(&task).expect("update retry_count");

        let failed_attempt = StageAttemptRecord {
            attempt_id: "zach-015-impl-1".to_owned(),
            task_id: "ZACH-015".to_owned(),
            stage: "impl".to_owned(),
            model: "gpt-6.1-sol".to_owned(),
            effort: "medium".to_owned(),
            systemd_unit: Some("zach-stage-zach-015-impl-1".to_owned()),
            invocation_id: Some("inv-1".to_owned()),
            started_epoch: 1000,
            ended_epoch: Some(1010),
            status: "FAILED".to_owned(),
            failure_class: Some("infra".to_owned()),
            summary: Some("worker timed out".to_owned()),
            input_tokens: Some(100),
            output_tokens: Some(20),
            total_tokens: Some(120),
            sha_before: Some("abc".to_owned()),
            sha_after: None,
            phase: "RUNNING".into(),
            last_liveness_epoch: 0,
            last_output_bytes: 0,
            last_cpu_usage_usec: None,
            control_group: None,
            exit_code: None,
            exit_code_kind: None,
            retry_generation: 0,
        };
        store
            .record_stage_attempt(&failed_attempt)
            .expect("record failed attempt");

        let passed_attempt = StageAttemptRecord {
            attempt_id: "zach-015-impl-2".to_owned(),
            task_id: "ZACH-015".to_owned(),
            stage: "impl".to_owned(),
            model: "gpt-6.1-sol".to_owned(),
            effort: "high".to_owned(),
            systemd_unit: Some("zach-stage-zach-015-impl-2".to_owned()),
            invocation_id: Some("inv-2".to_owned()),
            started_epoch: 1020,
            ended_epoch: Some(1030),
            status: "PASSED".to_owned(),
            failure_class: None,
            summary: Some("implemented".to_owned()),
            input_tokens: Some(200),
            output_tokens: Some(50),
            total_tokens: Some(250),
            sha_before: Some("abc".to_owned()),
            sha_after: Some("def".to_owned()),
            phase: "RUNNING".into(),
            last_liveness_epoch: 0,
            last_output_bytes: 0,
            last_cpu_usage_usec: None,
            control_group: None,
            exit_code: None,
            exit_code_kind: None,
            retry_generation: 0,
        };
        store
            .record_stage_attempt(&passed_attempt)
            .expect("record passed attempt");

        drop(store);
        let reopened = V2Store::open(&db_path).expect("reopen file-backed sqlite store");
        let reloaded_task = reopened.get_task("ZACH-015").unwrap().unwrap();
        assert_eq!(reloaded_task.retry_count, 1);

        let attempts = reopened.list_stage_attempts("ZACH-015").unwrap();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].attempt_id, "zach-015-impl-1");
        assert_eq!(attempts[0].status, "FAILED");
        assert_eq!(attempts[0].failure_class.as_deref(), Some("infra"));
        assert_eq!(attempts[1].attempt_id, "zach-015-impl-2");
        assert_eq!(attempts[1].status, "PASSED");
        assert_eq!(attempts[1].failure_class, None);

        let single = reopened
            .get_stage_attempt("zach-015-impl-1")
            .unwrap()
            .unwrap();
        assert_eq!(single.failure_class.as_deref(), Some("infra"));

        drop(reopened);
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn record_stage_attempt_and_open_decision_enforce_1024_byte_summary_cap() {
        let mut store = V2Store::open_in_memory().expect("in-memory store");
        let task = sample_task("ZACH-019-STORE", "Ready", Vec::new());
        store.upsert_task(&task).unwrap();

        let long_utf8 = format!("{}€{}", "x".repeat(1020), "y".repeat(200));
        let attempt = StageAttemptRecord {
            attempt_id: "zach-019-store-impl-1".to_owned(),
            task_id: "ZACH-019-STORE".to_owned(),
            stage: "impl".to_owned(),
            model: "gpt-6.1-sol".to_owned(),
            effort: "medium".to_owned(),
            systemd_unit: Some("zach-stage-zach-019-store-impl-1".to_owned()),
            invocation_id: None,
            started_epoch: 1000,
            ended_epoch: Some(1005),
            status: "FAILED".to_owned(),
            failure_class: Some("infra".to_owned()),
            summary: Some(long_utf8.clone()),
            input_tokens: Some(10),
            output_tokens: Some(5),
            total_tokens: Some(15),
            sha_before: None,
            sha_after: None,
            phase: "RUNNING".into(),
            last_liveness_epoch: 0,
            last_output_bytes: 0,
            last_cpu_usage_usec: None,
            control_group: None,
            exit_code: None,
            exit_code_kind: None,
            retry_generation: 0,
        };
        store.record_stage_attempt(&attempt).unwrap();

        let saved = store
            .get_stage_attempt("zach-019-store-impl-1")
            .unwrap()
            .unwrap();
        let saved_summary = saved.summary.expect("summary present");
        assert!(saved_summary.len() <= 1024);
        assert!(saved_summary.ends_with("..."));

        let dec = store
            .open_decision(
                "dec-019-store",
                "ZACH-019-STORE",
                "zach",
                "scope_violation",
                "Question?",
                &["Abort".to_owned()],
                Some(0),
                &long_utf8,
                None,
            )
            .unwrap();
        assert!(dec.context_summary.len() <= 1024);
        assert!(dec.context_summary.ends_with("..."));
    }

    #[test]
    fn stage_attempts_persist_unknown_tokens_as_sql_null_and_migrate_legacy_not_null_schema() {
        let db_path = std::env::temp_dir().join("zach_test_v2_nullable_tokens_migration.db");
        let _ = std::fs::remove_file(&db_path);

        // Simulate a pre-ZACH-020 SQLite database with NOT NULL DEFAULT 0 token columns.
        {
            let conn = Connection::open(&db_path).expect("create legacy db");
            conn.execute_batch(
                "CREATE TABLE tasks (
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
                 CREATE TABLE stage_attempts (
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
                 INSERT INTO tasks (
                     task_id, task_group, title, repository, weight, status,
                     context_pack_json, depends_on_json, required_stages_json,
                     stages_completed_json, updated_epoch
                 ) VALUES (
                     'ZACH-020-LEGACY', 'zach', 'Legacy task', 'zach', 'S', 'Ready',
                     '{}', '[]', '[]', '[]', 1000
                 );
                 INSERT INTO stage_attempts (
                     attempt_id, task_id, stage, model, effort, started_epoch, status,
                     input_tokens, output_tokens, total_tokens
                 ) VALUES (
                     'zach-020-legacy-1', 'ZACH-020-LEGACY', 'impl', 'gpt-6.1-sol', 'medium', 1000, 'PASSED',
                     120, 30, 150
                 );",
            )
            .expect("seed legacy schema");
        }

        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch("ALTER TABLE stage_attempts ADD COLUMN phase TEXT NOT NULL DEFAULT 'POSTPROCESSING'; ALTER TABLE stage_attempts ADD COLUMN retry_generation INTEGER NOT NULL DEFAULT 7; ALTER TABLE stage_attempts ADD COLUMN last_output_bytes INTEGER NOT NULL DEFAULT 42;").unwrap();
        }
        let mut store = V2Store::open(&db_path).expect("open and migrate legacy db");

        // Verify PRAGMA table_info now reports nullable with no default for all 3 token columns.
        {
            let mut stmt = store
                .connection_mut()
                .prepare("PRAGMA table_info('stage_attempts')")
                .unwrap();
            let cols: Vec<(String, i64, Option<String>)> = stmt
                .query_map([], |row| Ok((row.get(1)?, row.get(3)?, row.get(4)?)))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            for col_name in ["input_tokens", "output_tokens", "total_tokens"] {
                let (_, notnull, dflt) = cols
                    .iter()
                    .find(|(name, _, _)| name == col_name)
                    .expect("token column exists");
                assert_eq!(*notnull, 0, "{col_name} must be nullable");
                assert_eq!(*dflt, None, "{col_name} must not have DEFAULT 0");
            }
        }

        // Legacy row values are preserved.
        let legacy_row = store
            .get_stage_attempt("zach-020-legacy-1")
            .unwrap()
            .expect("legacy row preserved");
        assert_eq!(legacy_row.input_tokens, Some(120));
        assert_eq!(legacy_row.output_tokens, Some(30));
        assert_eq!(legacy_row.total_tokens, Some(150));
        assert_eq!(legacy_row.phase, "POSTPROCESSING");
        assert_eq!(legacy_row.retry_generation, 7);
        assert_eq!(legacy_row.last_output_bytes, 42);

        // Recording unknown usage persists SQL NULL (not 0).
        let unknown_attempt = StageAttemptRecord {
            attempt_id: "zach-020-unknown-1".to_owned(),
            task_id: "ZACH-020-LEGACY".to_owned(),
            stage: "impl".to_owned(),
            model: "gpt-6.1-sol".to_owned(),
            effort: "medium".to_owned(),
            systemd_unit: Some("zach-stage-zach-020-unknown-1".to_owned()),
            invocation_id: None,
            started_epoch: 1010,
            ended_epoch: Some(1020),
            status: "FAILED".to_owned(),
            failure_class: Some("infra".to_owned()),
            summary: Some("quota exhausted".to_owned()),
            input_tokens: None,
            output_tokens: None,
            total_tokens: None,
            sha_before: None,
            sha_after: None,
            phase: "RUNNING".into(),
            last_liveness_epoch: 0,
            last_output_bytes: 0,
            last_cpu_usage_usec: None,
            control_group: None,
            exit_code: None,
            exit_code_kind: None,
            retry_generation: 0,
        };
        store.record_stage_attempt(&unknown_attempt).unwrap();

        let (raw_in, raw_out, raw_tot): (Option<i64>, Option<i64>, Option<i64>) = store
            .connection_mut()
            .query_row(
                "SELECT input_tokens, output_tokens, total_tokens
                 FROM stage_attempts WHERE attempt_id = ?1",
                params!["zach-020-unknown-1"],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(raw_in.is_none(), "expected SQL NULL input_tokens");
        assert!(raw_out.is_none(), "expected SQL NULL output_tokens");
        assert!(raw_tot.is_none(), "expected SQL NULL total_tokens");

        let mapped = store
            .get_stage_attempt("zach-020-unknown-1")
            .unwrap()
            .unwrap();
        assert_eq!(mapped.input_tokens, None);
        assert_eq!(mapped.output_tokens, None);
        assert_eq!(mapped.total_tokens, None);

        drop(store);
        let _ = std::fs::remove_file(&db_path);
    }

    fn delivery_task(status: &str) -> TaskRecord {
        let mut task = sample_task("TASK-001", status, Vec::new());
        task.repository = "sample-app".into();
        task.github_repo = Some("acme/sample-app".into());
        task.worktree_path = None;
        task
    }

    fn sample_delivery(task: &TaskRecord) -> PostMergeDelivery {
        PostMergeDelivery {
            delivery_id: format!("{}:promotion:release", task.task_id),
            task_id: task.task_id.clone(),
            repository: task.repository.clone(),
            github_repo: "acme/sample-app".into(),
            merge_sha: "a".repeat(40),
            kind: "promotion".into(),
            name: "release".into(),
            state: "waiting_decision".into(),
            workflow: "release.yml".into(),
            run_id: Some("42".into()),
            build_run_id: Some("41".into()),
            artifact_digest: Some("b".repeat(64)),
            expected_current: Some("none".into()),
            evidence_json: serde_json::json!({"source_sha": "a".repeat(40)}),
            rule_json: serde_json::json!({"name": "release"}),
            decision_id: Some("release:0:42".into()),
            attempt: 0,
            updated_epoch: 1,
        }
    }

    #[test]
    fn delivery_schema_upgrade_is_additive_idempotent_and_rejects_future_versions() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE daemon_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO daemon_meta VALUES ('schema_version', '2');",
        )
        .unwrap();
        let mut store = V2Store { conn };
        store.initialize().unwrap();
        let task = delivery_task("Delivery Pending");
        let delivery = sample_delivery(&task);
        store
            .save_deliveries_and_task(&task, std::slice::from_ref(&delivery))
            .unwrap();
        store.initialize().unwrap();
        assert_eq!(
            store.list_deliveries(Some(&task.task_id)).unwrap(),
            vec![delivery]
        );
        let schema: String = store
            .conn
            .query_row(
                "SELECT value FROM daemon_meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(schema, SCHEMA_VERSION.to_string());

        for value in ["999", "invalid", "0"] {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute_batch(
                "CREATE TABLE daemon_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO daemon_meta VALUES ('schema_version', ?1)",
                params![value],
            )
            .unwrap();
            let mut incompatible = V2Store { conn };
            assert!(incompatible.initialize().is_err());
            let tables: i64 = incompatible.conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name != 'daemon_meta'",
                [], |row| row.get(0),
            ).unwrap();
            assert_eq!(tables, 0, "must reject before changing schema");
        }
    }

    #[test]
    fn delivery_sync_preserves_waiting_states_without_executor_until_terminal_board_state() {
        for status in [
            "Delivery Pending",
            "Waiting New APK",
            "Pending Prod Promotion",
            "Delivery Aborted",
        ] {
            let mut store = V2Store::open_in_memory().unwrap();
            let task = delivery_task(status);
            store.upsert_task(&task).unwrap();
            for board_status in ["Blocked", "Ready"] {
                let mut incoming = task.clone();
                incoming.status = board_status.into();
                let synced = store.sync_task(&incoming).unwrap();
                assert_eq!(synced.status, status);
                assert_eq!(synced.executor, None);
                assert!(store.list_ready_queue(None).unwrap().is_empty());
                assert_eq!(store.status_summary().unwrap().in_progress_count, 0);
            }
            for terminal in ["Done", "Cancelled"] {
                store.upsert_task(&task).unwrap();
                let mut incoming = task.clone();
                incoming.status = terminal.into();
                assert_eq!(store.sync_task(&incoming).unwrap().status, terminal);
            }
        }
    }

    #[test]
    fn delivery_decision_resolution_is_atomic_and_retries_do_not_reopen_implementation() {
        let mut store = V2Store::open_in_memory().unwrap();
        let task = delivery_task("Pending Prod Promotion");
        let mut delivery = sample_delivery(&task);
        store
            .save_deliveries_and_task(&task, std::slice::from_ref(&delivery))
            .unwrap();
        let options = vec!["Approve".into(), "Retry".into(), "Reject".into()];
        let decision_id = delivery.decision_id.clone().unwrap();
        store
            .open_decision(
                &decision_id,
                &task.task_id,
                &task.task_group,
                "prod_promotion_approval",
                "Approve release?",
                &options,
                None,
                "release evidence",
                Some(&delivery.merge_sha),
            )
            .unwrap();
        assert_eq!(
            store.get_task(&task.task_id).unwrap().unwrap().status,
            "Pending Prod Promotion"
        );
        assert!(
            store
                .resolve_decision(&decision_id, "Deploy everything", "operator", None)
                .is_err()
        );
        assert_eq!(
            store.get_decision(&decision_id).unwrap().unwrap().status,
            "OPEN"
        );
        assert_eq!(
            store.list_deliveries(None).unwrap()[0].state,
            "waiting_decision"
        );
        store
            .resolve_decision(&decision_id, "1", "operator", None)
            .unwrap();
        delivery = store.list_deliveries(None).unwrap().remove(0);
        assert_eq!(delivery.state, "approved");
        assert_eq!(delivery.attempt, 1);
        assert_eq!(
            store
                .get_decision(&decision_id)
                .unwrap()
                .unwrap()
                .choice
                .as_deref(),
            Some("Approve")
        );
        assert_eq!(
            store.get_task(&task.task_id).unwrap().unwrap().status,
            "Delivery Pending"
        );
        assert!(store.list_ready_queue(None).unwrap().is_empty());

        // A later run gets a different gate and remains resolvable after retry.
        delivery.state = "waiting_decision".into();
        delivery.decision_id = Some(format!("{}:{}:43", delivery.delivery_id, delivery.attempt));
        let next_id = delivery.decision_id.clone().unwrap();
        store.upsert_delivery(&delivery).unwrap();
        store
            .open_decision(
                &next_id,
                &task.task_id,
                &task.task_group,
                "prod_promotion_approval",
                "Approve new plan?",
                &options,
                None,
                "new evidence",
                Some(&delivery.merge_sha),
            )
            .unwrap();
        store
            .resolve_decision(&next_id, "Retry", "operator", None)
            .unwrap();
        delivery = store.list_deliveries(None).unwrap().remove(0);
        assert_eq!(delivery.state, "pending");
        assert_eq!(delivery.attempt, 2);
        assert_eq!(delivery.run_id, None);
        assert_eq!(delivery.decision_id, None);
        assert_eq!(store.list_decisions(false, None).unwrap().len(), 2);
        assert_eq!(
            store.get_task(&task.task_id).unwrap().unwrap().status,
            "Delivery Pending"
        );
    }

    #[test]
    fn delivery_reject_aborts_linked_work_and_fallback_gate_never_becomes_ready() {
        for kind in [
            "new_apk_required",
            "prod_promotion_approval",
            "delivery_contract_error",
            "custom_gate",
        ] {
            let mut store = V2Store::open_in_memory().unwrap();
            let task = delivery_task("Waiting New APK");
            let delivery = sample_delivery(&task);
            store
                .save_deliveries_and_task(&task, std::slice::from_ref(&delivery))
                .unwrap();
            let decision_id = delivery.decision_id.clone().unwrap();
            let options = vec!["Retry".into(), "Abort delivery".into()];
            store
                .open_decision(
                    &decision_id,
                    &task.task_id,
                    &task.task_group,
                    kind,
                    "Continue?",
                    &options,
                    None,
                    "",
                    None,
                )
                .unwrap();
            assert_eq!(
                store.get_task(&task.task_id).unwrap().unwrap().status,
                "Waiting New APK"
            );
            store
                .resolve_decision(&decision_id, "Abort delivery", "operator", None)
                .unwrap();
            assert_eq!(store.list_deliveries(None).unwrap()[0].state, "aborted");
            assert_eq!(
                store.get_task(&task.task_id).unwrap().unwrap().status,
                "Delivery Aborted"
            );
            assert!(store.list_ready_queue(None).unwrap().is_empty());
            store
                .open_decision(
                    "stale-gate",
                    &task.task_id,
                    &task.task_group,
                    kind,
                    "Retry?",
                    &["Retry".into()],
                    None,
                    "",
                    None,
                )
                .unwrap();
            store
                .resolve_decision("stale-gate", "Retry", "operator", None)
                .unwrap();
            assert_eq!(
                store.get_task(&task.task_id).unwrap().unwrap().status,
                "Delivery Aborted",
                "an abort is terminal even if another decision remains open"
            );
        }

        let mut store = V2Store::open_in_memory().unwrap();
        let task = delivery_task("Blocked");
        let delivery = sample_delivery(&task);
        store
            .save_deliveries_and_task(&task, std::slice::from_ref(&delivery))
            .unwrap();
        store
            .open_decision(
                "unlinked-gate",
                &task.task_id,
                &task.task_group,
                "custom_gate",
                "Retry?",
                &["Retry".into()],
                None,
                "",
                None,
            )
            .unwrap();
        store
            .resolve_decision("unlinked-gate", "Retry", "operator", None)
            .unwrap();
        assert_eq!(
            store.get_task(&task.task_id).unwrap().unwrap().status,
            "Delivery Pending"
        );
        assert_eq!(
            store.list_deliveries(None).unwrap()[0].state,
            "waiting_decision",
            "unrelated gate must remain untouched"
        );
    }

    #[test]
    fn delivery_task_checkpoint_rolls_back_if_a_row_belongs_to_another_task() {
        let mut store = V2Store::open_in_memory().unwrap();
        let mut task = delivery_task("Delivery Pending");
        store.upsert_task(&task).unwrap();
        let mut delivery = sample_delivery(&task);
        delivery.task_id = "TASK-OTHER".into();
        task.status = "Done".into();
        assert!(store.save_deliveries_and_task(&task, &[delivery]).is_err());
        assert_eq!(
            store.get_task(&task.task_id).unwrap().unwrap().status,
            "Delivery Pending"
        );
        assert!(store.list_deliveries(None).unwrap().is_empty());
    }

    #[test]
    fn delivery_board_receipt_preserves_concurrent_approval_and_terminal_task_state() {
        let mut store = V2Store::open_in_memory().unwrap();
        let task = delivery_task("Pending Prod Promotion");
        let delivery = sample_delivery(&task);
        store
            .save_deliveries_and_task(&task, std::slice::from_ref(&delivery))
            .unwrap();
        let decision_id = delivery.decision_id.as_deref().unwrap();
        store
            .open_decision(
                decision_id,
                &task.task_id,
                &task.task_group,
                "prod_promotion_approval",
                "Approve release?",
                &["Approve".into(), "Retry".into(), "Reject".into()],
                None,
                "release evidence",
                Some(&delivery.merge_sha),
            )
            .unwrap();
        let before_network = store.get_task(&task.task_id).unwrap().unwrap();
        store
            .resolve_decision(decision_id, "Approve", "operator", None)
            .unwrap();
        let approved_task = store.get_task(&task.task_id).unwrap().unwrap();
        let approved_row = store
            .list_deliveries(Some(&task.task_id))
            .unwrap()
            .remove(0);
        assert_eq!(approved_task.status, "Delivery Pending");
        assert_eq!(approved_row.state, "approved");
        assert_eq!(approved_row.attempt, delivery.attempt + 1);
        assert!(approved_task.version > before_network.version);

        assert!(
            !store
                .mark_delivery_board_synced(
                    &task.task_id,
                    before_network.version,
                    "Pending Prod Promotion",
                )
                .unwrap()
        );
        assert_eq!(
            store.list_deliveries(Some(&task.task_id)).unwrap(),
            vec![approved_row.clone()]
        );
        assert_eq!(
            store.get_task(&task.task_id).unwrap().unwrap(),
            approved_task
        );

        assert!(
            store
                .mark_delivery_board_synced(
                    &task.task_id,
                    approved_task.version,
                    &approved_task.status,
                )
                .unwrap()
        );
        let mut expected_row = approved_row;
        expected_row.evidence_json["board_synced_status"] = serde_json::json!("Delivery Pending");
        assert_eq!(
            store.list_deliveries(Some(&task.task_id)).unwrap(),
            vec![expected_row]
        );
        assert_eq!(
            store.get_task(&task.task_id).unwrap().unwrap(),
            approved_task
        );

        for terminal in ["Done", "Cancelled"] {
            let mut terminal_store = V2Store::open_in_memory().unwrap();
            let stale_task = delivery_task("Delivery Pending");
            let stale_row = sample_delivery(&stale_task);
            terminal_store
                .save_deliveries_and_task(&stale_task, std::slice::from_ref(&stale_row))
                .unwrap();
            let mut terminal_task = terminal_store
                .get_task(&stale_task.task_id)
                .unwrap()
                .unwrap();
            terminal_task.status = terminal.into();
            terminal_store.upsert_task(&terminal_task).unwrap();
            assert!(
                terminal_store
                    .save_deliveries_and_task(&stale_task, std::slice::from_ref(&stale_row))
                    .is_err()
            );
            terminal_store
                .open_decision(
                    "late-delivery-gate",
                    &stale_task.task_id,
                    &stale_task.task_group,
                    "delivery_contract_error",
                    "Retry delivery?",
                    &["Retry".into(), "Abort".into()],
                    None,
                    "late observation",
                    Some(&stale_row.merge_sha),
                )
                .unwrap();
            assert_eq!(
                terminal_store
                    .get_task(&stale_task.task_id)
                    .unwrap()
                    .unwrap()
                    .status,
                terminal
            );
            assert_eq!(
                terminal_store
                    .list_deliveries(Some(&stale_task.task_id))
                    .unwrap(),
                vec![stale_row]
            );
        }
    }
    #[test]
    fn v4_upgrades_both_v3_lineages_and_older_schemas_without_data_loss() {
        for version in [1, 2, 3] {
            for delivery_lineage in [false, true] {
                let mut store = V2Store::open_in_memory().unwrap();
                let mut task = delivery_task("Delivery Pending");
                task.next_retry_epoch = 42;
                task.lease_owner = Some("owner".into());
                let row = sample_delivery(&task);
                store
                    .save_deliveries_and_task(&task, std::slice::from_ref(&row))
                    .unwrap();
                store.conn.execute_batch("INSERT INTO stage_attempts(attempt_id,task_id,stage,model,effort,started_epoch,status,input_tokens) VALUES('legacy','TASK-001','impl','model','high',1,'PASSED',NULL);").unwrap();
                if delivery_lineage {
                    store.conn.execute_batch("ALTER TABLE tasks DROP COLUMN next_retry_epoch; ALTER TABLE tasks DROP COLUMN lease_owner; ALTER TABLE tasks DROP COLUMN lease_expires_epoch; DROP TABLE lifecycle_ops;").unwrap();
                    for column in [
                        "phase",
                        "last_liveness_epoch",
                        "last_output_bytes",
                        "last_cpu_usage_usec",
                        "control_group",
                        "exit_code",
                        "exit_code_kind",
                        "retry_generation",
                    ] {
                        store
                            .conn
                            .execute_batch(&format!(
                                "ALTER TABLE stage_attempts DROP COLUMN {column}"
                            ))
                            .unwrap();
                    }
                } else {
                    store
                        .conn
                        .execute_batch("DROP TABLE post_merge_deliveries;")
                        .unwrap();
                }
                store
                    .conn
                    .execute(
                        "UPDATE daemon_meta SET value=?1 WHERE key='schema_version'",
                        [version.to_string()],
                    )
                    .unwrap();
                for _ in 0..2 {
                    store.initialize().unwrap();
                    assert_eq!(store.meta("schema_version").unwrap().as_deref(), Some("4"));
                    let saved = store.get_task(&task.task_id).unwrap().unwrap();
                    assert_eq!(
                        saved.next_retry_epoch,
                        if delivery_lineage { 0 } else { 42 }
                    );
                    assert_eq!(
                        saved.lease_owner.as_deref(),
                        if delivery_lineage {
                            None
                        } else {
                            Some("owner")
                        }
                    );
                    let attempt = store.get_stage_attempt("legacy").unwrap().unwrap();
                    assert_eq!(attempt.input_tokens, None);
                    assert_eq!(attempt.phase, "RUNNING");
                    let rows = store.list_deliveries(Some(&task.task_id)).unwrap();
                    assert_eq!(
                        rows,
                        if delivery_lineage {
                            vec![row.clone()]
                        } else {
                            vec![]
                        }
                    );
                    assert!(store.lifecycle_ops().unwrap().is_empty());
                }
            }
        }
    }

    #[test]
    fn delivery_verification_receipt_is_atomic_and_idempotent_without_completing_task() {
        let mut store = V2Store::open_in_memory().unwrap();
        let mut task = delivery_task("Delivery Pending");
        store.upsert_task(&task).unwrap();
        let mut row = sample_delivery(&task);
        row.state = "verified".into();
        store.upsert_delivery(&row).unwrap();
        task.memory.merge_lane_released = true;
        store.conn.execute_batch("CREATE TRIGGER reject_verified BEFORE INSERT ON task_events WHEN NEW.event_type='POST_MERGE_DELIVERY_VERIFIED' BEGIN SELECT RAISE(ABORT,'injected event failure'); END;").unwrap();
        assert!(
            store
                .save_delivery_status(&task, Some(std::slice::from_ref(&row)))
                .is_err()
        );
        assert_eq!(
            store.get_task(&task.task_id).unwrap().unwrap().status,
            "Delivery Pending"
        );
        assert!(
            !store
                .get_task(&task.task_id)
                .unwrap()
                .unwrap()
                .memory
                .merge_lane_released
        );
        assert!(
            !store
                .delivery_verification_recorded(&task.task_id, &row.merge_sha)
                .unwrap()
        );
        store
            .conn
            .execute_batch("DROP TRIGGER reject_verified")
            .unwrap();
        for _ in 0..2 {
            store
                .save_delivery_status(&task, Some(std::slice::from_ref(&row)))
                .unwrap();
        }
        assert_eq!(
            store.get_task(&task.task_id).unwrap().unwrap().status,
            "Delivery Pending"
        );
        assert!(
            store
                .delivery_verification_recorded(&task.task_id, &row.merge_sha)
                .unwrap()
        );
        assert_eq!(
            store
                .list_events_since(None, 0, 100)
                .unwrap()
                .iter()
                .filter(|e| e.event_type == "POST_MERGE_DELIVERY_VERIFIED")
                .count(),
            1
        );
    }
}
