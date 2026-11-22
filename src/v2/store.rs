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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StageRunGrant {
    pub stage: String,
    pub granted_epoch: i64,
    #[serde(default)]
    pub consumed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_attempt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_summary: Option<String>,
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
    pub stage_run_grant: Option<StageRunGrant>,
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
    #[serde(default)]
    pub fallback_stages: Vec<String>,
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

// These proofs deliberately do not change the permissive Standard decoder.
// Deserialize through a visitor first: Value/derived structs alone erase duplicates.
struct UniqueJson(serde_json::Value);
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("unambiguous JSON")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| UniqueJson(n.into()))
                    .ok_or_else(|| E::custom("number"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(serde_json::Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(v)) = a.next_element()? {
                    values.push(v);
                }
                Ok(UniqueJson(values.into()))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = a.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate"));
                    }
                    let UniqueJson(value) = a.next_value()?;
                    values.insert(key, value);
                }
                Ok(UniqueJson(values.into()))
            }
        }
        d.deserialize_any(Visitor)
    }
}

fn raw_proof_error() -> V2StoreError {
    V2StoreError("ambiguous persisted task JSON".into())
}

fn known_object(value: &serde_json::Value, model: serde_json::Value) -> Result<(), V2StoreError> {
    let object = value.as_object().ok_or_else(raw_proof_error)?;
    let keys = model.as_object().ok_or_else(raw_proof_error)?;
    if object.keys().any(|key| !keys.contains_key(key)) {
        return Err(raw_proof_error());
    }
    Ok(())
}

// A complete raw row also makes trigger side effects visible to the postcondition.
type RawTask = BTreeMap<String, rusqlite::types::Value>;
fn raw_task(conn: &Connection, id: &str) -> Result<RawTask, V2StoreError> {
    let mut stmt = conn.prepare("SELECT * FROM tasks WHERE task_id=?1")?;
    let names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    Ok(stmt.query_row([id], |row| {
        names
            .iter()
            .enumerate()
            .map(|(i, n)| Ok((n.clone(), row.get(i)?)))
            .collect()
    })?)
}

fn strict_task_json(conn: &Connection, task: &mut TaskRecord) -> Result<RawTask, V2StoreError> {
    let raw = raw_task(conn, &task.task_id)?;
    let parse = |column: &str| -> Result<serde_json::Value, V2StoreError> {
        let Some(rusqlite::types::Value::Text(s)) = raw.get(column) else {
            return Err(raw_proof_error());
        };
        serde_json::from_str::<UniqueJson>(s)
            .map(|v| v.0)
            .map_err(|_| raw_proof_error())
    };
    let memory = parse("memory_json")?;
    known_object(&memory, serde_json::to_value(TaskMemory::default())?)?;
    if let Some(cp) = memory.get("pipeline_checkpoint").filter(|v| !v.is_null()) {
        known_object(cp, serde_json::to_value(PipelineCheckpoint::default())?)?;
    }
    if let Some(cp) = memory.get("merge_checkpoint").filter(|v| !v.is_null()) {
        known_object(cp, serde_json::to_value(MergeCheckpoint::default())?)?;
    }
    task.memory = serde_json::from_value(memory).map_err(|_| raw_proof_error())?;
    let context = parse("context_pack_json")?;
    known_object(&context, serde_json::to_value(ContextPackSpec::default())?)?;
    for (name, model) in [
        (
            "target_files",
            serde_json::to_value(TargetFileSpec::default())?,
        ),
        (
            "acceptance_criteria",
            serde_json::to_value(AcceptanceCriterionSpec::default())?,
        ),
    ] {
        if let Some(items) = context.get(name).and_then(|v| v.as_array()) {
            for item in items {
                known_object(item, model.clone())?;
            }
        }
    }
    task.context_pack = serde_json::from_value(context).map_err(|_| raw_proof_error())?;
    task.depends_on =
        serde_json::from_value(parse("depends_on_json")?).map_err(|_| raw_proof_error())?;
    task.required_stages =
        serde_json::from_value(parse("required_stages_json")?).map_err(|_| raw_proof_error())?;
    task.stages_completed =
        serde_json::from_value(parse("stages_completed_json")?).map_err(|_| raw_proof_error())?;
    Ok(raw)
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

impl TaskRecord {
    pub fn has_active_stage_grant(&self) -> bool {
        self.memory
            .stage_run_grant
            .as_ref()
            .is_some_and(|g| !g.consumed)
    }

    pub fn has_any_execution_grant(&self) -> bool {
        self.autonomous_consent || self.has_active_stage_grant()
    }

    pub fn has_execution_grant_for(&self, stage: Option<&str>) -> bool {
        if self.autonomous_consent {
            return true;
        }
        self.memory
            .stage_run_grant
            .as_ref()
            .is_some_and(|g| !g.consumed && stage.is_none_or(|s| s == g.stage))
    }
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
pub struct AttemptAuditRecord {
    pub attempt_id: String,
    pub task_id: String,
    pub stage: String,
    pub turn_count: u64,
    pub tool_call_count: u64,
    pub tool_error_count: u64,
    pub edit_compile_fail_loops: u64,
    pub redundant_read_count: u64,
    pub cached_input_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    pub check_divergence: bool,
    pub error_code: Option<String>,
    pub created_epoch: i64,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retirement_reason: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub linked_unverified_delivery: bool,
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
pub struct ProviderCooldownRecord {
    pub family: String,
    pub until_epoch: i64,
    pub reason: String,
    pub updated_epoch: i64,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveTaskDetail {
    pub task_id: String,
    pub task_group: String,
    pub repository: String,
    pub weight: String,
    pub status: String,
    #[serde(default)]
    pub board_status: Option<String>,
    #[serde(default)]
    pub open_decision_id: Option<String>,
    pub title: String,
    pub executor: Option<String>,
    pub current_stage: Option<String>,
    pub attempt_id: Option<String>,
    pub attempt_phase: Option<String>,
    pub model: Option<String>,
    pub occupies_slot: bool,
    pub target_files: Vec<String>,
    pub reservation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WaitingTaskDetail {
    pub task_id: String,
    pub task_group: String,
    pub repository: String,
    pub weight: String,
    pub status: String,
    #[serde(default)]
    pub board_status: Option<String>,
    #[serde(default)]
    pub open_decision_id: Option<String>,
    pub title: String,
    pub wait_reason: String,
    pub target_files: Vec<String>,
    pub next_retry_epoch: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetailedStatusReport {
    pub summary: DaemonStatusSummary,
    pub active_tasks: Vec<ActiveTaskDetail>,
    pub waiting_tasks: Vec<WaitingTaskDetail>,
    pub path_locks: Vec<PathLockRecord>,
    pub merge_queue: Vec<MergeQueueRecord>,
    pub open_decisions: Vec<PendingDecisionRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoReservation {
    WholeRepo { task_id: String },
    ScopedPaths { task_id: String, paths: Vec<String> },
}

impl RepoReservation {
    pub fn task_id(&self) -> &str {
        match self {
            Self::WholeRepo { task_id } | Self::ScopedPaths { task_id, .. } => task_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoConflict {
    RepoLocked { owner: String },
    PathConflict { owner: String, path: String },
}

pub fn normalize_repo_path(raw: &str) -> String {
    let mut s = raw.trim().to_owned();
    while s.contains("//") {
        s = s.replace("//", "/");
    }
    while let Some(rest) = s.strip_prefix("./") {
        s = rest.to_owned();
    }
    let trimmed = s.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "." || trimmed == "*" {
        "*".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn extract_attempt_id_from_path(raw: &str) -> Option<String> {
    let components: Vec<_> = Path::new(raw).components().collect();
    let mut found = None;
    for window in components.windows(2) {
        if window[0].as_os_str() == "attempts"
            && let std::path::Component::Normal(id) = window[1]
            && let Some(id_str) = id.to_str()
            && !id_str.trim().is_empty()
        {
            found = Some(id_str.to_owned());
        }
    }
    found
}

pub fn paths_overlap(a: &str, b: &str) -> bool {
    let a = normalize_repo_path(a);
    let b = normalize_repo_path(b);
    if a == "*" || b == "*" {
        return true;
    }
    a == b || b.starts_with(&format!("{a}/")) || a.starts_with(&format!("{b}/"))
}

pub fn repo_conflict_for_task(
    reservations: &[RepoReservation],
    task: &TaskRecord,
) -> Option<RepoConflict> {
    let others: Vec<&RepoReservation> = reservations
        .iter()
        .filter(|res| res.task_id() != task.task_id)
        .collect();
    if others.is_empty() {
        return None;
    }

    for res in &others {
        if let RepoReservation::WholeRepo { task_id } = res {
            return Some(RepoConflict::RepoLocked {
                owner: task_id.clone(),
            });
        }
    }

    let task_paths: Vec<String> = task
        .context_pack
        .target_files
        .iter()
        .map(|f| normalize_repo_path(&f.path))
        .collect();
    if task_paths.is_empty() || task_paths.iter().any(|p| p == "*") {
        return others.first().map(|res| RepoConflict::RepoLocked {
            owner: res.task_id().to_owned(),
        });
    }

    for res in others {
        if let RepoReservation::ScopedPaths { task_id, paths } = res {
            for tp in &task_paths {
                for rp in paths {
                    if rp == "*" {
                        return Some(RepoConflict::RepoLocked {
                            owner: task_id.clone(),
                        });
                    }
                    if paths_overlap(tp, rp) {
                        return Some(RepoConflict::PathConflict {
                            owner: task_id.clone(),
                            path: tp.clone(),
                        });
                    }
                }
            }
        }
    }

    None
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
             CREATE INDEX IF NOT EXISTS idx_deliveries_task ON post_merge_deliveries(task_id);

             CREATE TABLE IF NOT EXISTS provider_cooldowns (
                 family TEXT PRIMARY KEY,
                 until_epoch INTEGER NOT NULL,
                 reason TEXT NOT NULL,
                 updated_epoch INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS attempt_audits (
                 attempt_id TEXT PRIMARY KEY,
                 task_id TEXT NOT NULL,
                 stage TEXT NOT NULL,
                 turn_count INTEGER NOT NULL DEFAULT 0,
                 tool_call_count INTEGER NOT NULL DEFAULT 0,
                 tool_error_count INTEGER NOT NULL DEFAULT 0,
                 edit_compile_fail_loops INTEGER NOT NULL DEFAULT 0,
                 redundant_read_count INTEGER NOT NULL DEFAULT 0,
                 cached_input_tokens INTEGER,
                 reasoning_tokens INTEGER,
                 check_divergence INTEGER NOT NULL DEFAULT 0,
                 error_code TEXT,
                 created_epoch INTEGER NOT NULL
             );",
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
        self.migrate_attempt_audits()?;
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

    fn migrate_attempt_audits(&mut self) -> Result<(), V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: BTreeSet<String> = {
            let mut stmt = tx.prepare("PRAGMA table_info('attempt_audits')")?;
            stmt.query_map([], |row| row.get(1))?
                .collect::<Result<_, _>>()?
        };
        for (name, definition) in [
            ("task_id", "TEXT NOT NULL DEFAULT ''"),
            ("stage", "TEXT NOT NULL DEFAULT ''"),
            ("turn_count", "INTEGER NOT NULL DEFAULT 0"),
            ("tool_call_count", "INTEGER NOT NULL DEFAULT 0"),
            ("tool_error_count", "INTEGER NOT NULL DEFAULT 0"),
            ("edit_compile_fail_loops", "INTEGER NOT NULL DEFAULT 0"),
            ("redundant_read_count", "INTEGER NOT NULL DEFAULT 0"),
            ("cached_input_tokens", "INTEGER"),
            ("reasoning_tokens", "INTEGER"),
            ("check_divergence", "INTEGER NOT NULL DEFAULT 0"),
            ("error_code", "TEXT"),
            ("created_epoch", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            if !existing.contains(name) {
                tx.execute_batch(&format!(
                    "ALTER TABLE attempt_audits ADD COLUMN {name} {definition};"
                ))?;
            }
        }
        tx.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_attempt_audits_task ON attempt_audits(task_id);",
        )?;
        tx.commit()?;
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
        self.read_lifecycle_ops(false)
    }

    pub(crate) fn replayable_lifecycle_ops(&self) -> Result<Vec<LifecycleOperation>, V2StoreError> {
        self.read_lifecycle_ops(true)
    }

    fn read_lifecycle_ops(
        &self,
        replay_only: bool,
    ) -> Result<Vec<LifecycleOperation>, V2StoreError> {
        Ok(self.conn.prepare("SELECT operation_id,task_id,kind,args_json,body_path,depends_on,state,retry_epoch,attempts,last_error,attempt_id,decision_id FROM lifecycle_ops l
            WHERE NOT ?1 OR l.state='ACKNOWLEDGED' OR l.decision_id IS NULL OR NOT EXISTS(
                SELECT 1 FROM task_events e WHERE e.task_id=l.task_id AND e.event_type='DECISION_RETIRED'
                AND json_extract(e.payload_json,'$.decision_id')=l.decision_id)
            ORDER BY rowid")?.query_map([replay_only], |r| {
            let args: String = r.get(3)?;
            Ok(LifecycleOperation { attempt_id:r.get(10)?,decision_id:r.get(11)?,operation_id:r.get(0)?,task_id:r.get(1)?,kind:r.get(2)?,args:serde_json::from_str(&args).unwrap_or_default(),body_path:r.get(4)?,depends_on:r.get(5)?,state:r.get(6)?,retry_epoch:r.get(7)?,attempts:r.get(8)?,last_error:r.get(9)? })
        })?.collect::<Result<_,_>>()?)
    }

    pub fn has_pending_lifecycle(&self, task_id: &str) -> Result<bool, V2StoreError> {
        Self::has_pending_lifecycle_on(&self.conn, task_id)
    }

    fn has_pending_lifecycle_on(conn: &Connection, task_id: &str) -> Result<bool, V2StoreError> {
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM lifecycle_ops l WHERE task_id=?1 AND state!='ACKNOWLEDGED'
                AND (l.decision_id IS NULL OR NOT EXISTS(SELECT 1 FROM task_events e
                     WHERE e.task_id=l.task_id AND e.event_type='DECISION_RETIRED'
                     AND json_extract(e.payload_json,'$.decision_id')=l.decision_id)))",
            [task_id],
            |r| r.get(0),
        )?)
    }

    pub(crate) fn lifecycle_in_flight(&self, id: &str) -> Result<bool, V2StoreError> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM lifecycle_ops WHERE operation_id=?1 AND state IN ('IN_FLIGHT','QUEUED'))",
            [id],
            |row| row.get(0),
        )?)
    }

    pub(crate) fn grant_decision_publication(&mut self, id: &str) -> Result<bool, V2StoreError> {
        Ok(self.conn.execute(
            "UPDATE lifecycle_ops SET state='DISPATCHED', updated_epoch=?2
             WHERE operation_id=?1 AND state='QUEUED'
             AND EXISTS (SELECT 1 FROM tasks t WHERE t.task_id=lifecycle_ops.task_id
                 AND lower(t.status) NOT IN ('done','cancelled') AND t.autonomous_consent)
             AND EXISTS (SELECT 1 FROM pending_decisions d WHERE d.decision_id=lifecycle_ops.decision_id
                 AND d.task_id=lifecycle_ops.task_id AND d.status='RESOLVED')
             AND NOT EXISTS (SELECT 1 FROM task_events e WHERE e.task_id=lifecycle_ops.task_id
                 AND e.event_type='DECISION_RETIRED'
                 AND json_extract(e.payload_json,'$.decision_id')=lifecycle_ops.decision_id)
             AND NOT EXISTS (SELECT 1 FROM lifecycle_ops other
                 WHERE other.task_id=lifecycle_ops.task_id AND other.state='DISPATCHED')",
            params![id, now_epoch()],
        )? == 1)
    }

    pub(crate) fn deferred_terminal(
        &self,
        operation_id: &str,
        task: &TaskRecord,
    ) -> Result<Option<(String, bool)>, V2StoreError> {
        Self::effective_deferred_terminal_on(&self.conn, operation_id, task)
    }

    fn effective_deferred_terminal_on(
        conn: &Connection,
        operation_id: &str,
        task: &TaskRecord,
    ) -> Result<Option<(String, bool)>, V2StoreError> {
        let deferred = Self::deferred_terminal_on(conn, operation_id)?;
        if deferred.as_ref().is_some_and(|(_, board)| *board)
            && Self::delivery_holds_terminal(conn, task)?
        {
            return Ok(None);
        }
        Ok(deferred)
    }

    fn deferred_terminal_on(
        conn: &Connection,
        operation_id: &str,
    ) -> Result<Option<(String, bool)>, V2StoreError> {
        Ok(conn
            .query_row(
                "SELECT json_extract(payload_json,'$.status'),json_extract(payload_json,'$.board')
             FROM task_events WHERE event_type='TASK_TERMINAL_DEFERRED'
             AND json_extract(payload_json,'$.operation_id')=?1 ORDER BY seq_id DESC LIMIT 1",
                [operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    fn defer_terminal_tx(
        tx: &rusqlite::Transaction<'_>,
        task: &TaskRecord,
        status: &str,
        board: bool,
        now: i64,
    ) -> Result<bool, V2StoreError> {
        if !is_terminal_task_status(status) || is_terminal_task_status(&task.status) {
            return Ok(false);
        }
        let Some(id) = tx
            .query_row(
                "SELECT operation_id FROM lifecycle_ops WHERE task_id=?1 AND state='DISPATCHED'",
                [&task.task_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        else {
            return Ok(false);
        };
        if Self::deferred_terminal_on(tx, &id)?
            .as_ref()
            .is_none_or(|(previous, from_board)| previous != status || *from_board != board)
        {
            Self::insert_event_tx(
                tx,
                &task.task_id,
                &task.task_group,
                now,
                "TASK_TERMINAL_DEFERRED",
                &serde_json::json!({"operation_id":id,"status":status,"board":board}),
            )?;
        }
        Ok(true)
    }

    fn delivery_holds_terminal(conn: &Connection, task: &TaskRecord) -> Result<bool, V2StoreError> {
        Ok(!is_terminal_task_status(&task.status) && conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM post_merge_deliveries p
             WHERE p.task_id=?1 AND p.decision_id IS NOT NULL AND p.state NOT IN ('verified','aborted')
             AND NOT EXISTS(SELECT 1 FROM task_events e WHERE e.task_id=p.task_id
               AND e.event_type='DECISION_RETIRED' AND json_extract(e.payload_json,'$.decision_id')=p.decision_id))",
            [&task.task_id], |row| row.get(0),
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
        self.conn.execute("UPDATE lifecycle_ops SET state=?2,last_error=?3,retry_epoch=?4,updated_epoch=?5,attempts=attempts+CASE WHEN ?2 IN ('IN_FLIGHT','QUEUED') THEN 1 ELSE 0 END WHERE operation_id=?1",params![id,state,error,retry_epoch,now_epoch()])?;
        Ok(())
    }

    pub fn acknowledge_lifecycle(
        &mut self,
        task: &TaskRecord,
        op: &LifecycleOperation,
        attempt_id: Option<&str>,
    ) -> Result<(), V2StoreError> {
        self.finish_lifecycle(task, op, attempt_id, None)
    }

    pub(crate) fn settle_decision_publication(
        &mut self,
        task: &TaskRecord,
        op: &LifecycleOperation,
        settlement_id: &str,
    ) -> Result<(), V2StoreError> {
        self.finish_lifecycle(task, op, None, Some(settlement_id))
    }

    fn finish_lifecycle(
        &mut self,
        task: &TaskRecord,
        op: &LifecycleOperation,
        attempt_id: Option<&str>,
        settlement_id: Option<&str>,
    ) -> Result<(), V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old = Self::get_task_tx(&tx, &task.task_id)?
            .ok_or_else(|| V2StoreError("missing lifecycle task".into()))?;
        if let Some(id) = &op.decision_id
            && (is_terminal_task_status(&old.status)
                || Self::get_decision_on(&tx, id)?
                    .is_some_and(|decision| decision.status == "RETIRED"))
        {
            return Ok(());
        }
        let mut next = task.clone();
        if op.state == "DISPATCHED"
            && let Some((status, board)) =
                Self::effective_deferred_terminal_on(&tx, &op.operation_id, &old)?
        {
            next = old.clone();
            next.status = status;
            next.memory.governance_terminal_observed |= board;
            // Clear the fence only inside the acknowledgment transaction. Keep the
            // publication pending for retirement until the terminal transition is recorded.
            tx.execute(
                "UPDATE lifecycle_ops SET state='SETTLING' WHERE operation_id=?1",
                [&op.operation_id],
            )?;
        }
        let now = now_epoch();
        let retirement = if let Some(settlement_id) = settlement_id {
            if op.state != "DISPATCHED" {
                return Err(V2StoreError("publication is no longer dispatched".into()));
            }
            let id = op
                .decision_id
                .clone()
                .ok_or_else(|| V2StoreError("publication has no decision".into()))?;
            next.memory.applied_decisions.push(settlement_id.into());
            if !is_terminal_task_status(&next.status) && !is_post_merge_status(&next.status) {
                next.memory.halt_requested = true;
            }
            Some((id, "publication_settled"))
        } else if op.state == "DISPATCHED" {
            let id = format!("settle-{}", op.operation_id);
            Self::get_decision_on(&tx, &id)?
                .filter(|decision| decision.status != "RETIRED")
                .map(|_| (id, "publication_confirmed"))
        } else {
            None
        };
        let saved = Self::update_task_tx(&tx, &old, &next, now)?;
        if let Some((id, reason)) = retirement
            && Self::get_decision_on(&tx, &id)?.is_some_and(|decision| decision.status != "RETIRED")
        {
            let reason = if is_terminal_task_status(&saved.status) {
                saved.status.as_str()
            } else {
                reason
            };
            Self::insert_event_tx(
                &tx,
                &task.task_id,
                &task.task_group,
                now,
                "DECISION_RETIRED",
                &serde_json::json!({"task_id":task.task_id,"decision_id":id,"reason":reason,"settlement_id":settlement_id}),
            )?;
        }
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
        tx.execute(
            "UPDATE lifecycle_ops SET state=?2,last_error=CASE WHEN ?2='ACKNOWLEDGED' THEN NULL ELSE last_error END,
             updated_epoch=?3 WHERE operation_id=?1",
            params![op.operation_id, if settlement_id.is_some() { "SETTLED" } else { "ACKNOWLEDGED" }, now],
        )?;
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
        if is_terminal_task_status(&task.status) {
            Self::retire_decisions_tx(tx, task, now)?;
        }
        let mut inserted = task.clone();
        inserted.version = 1;
        inserted.updated_epoch = now;
        Ok(inserted)
    }

    fn board_status_on(conn: &Connection, task_id: &str) -> Result<Option<String>, V2StoreError> {
        Ok(conn
            .query_row(
                "SELECT json_extract(payload_json,'$.board_status') FROM task_events
             WHERE task_id=?1 AND event_type='BOARD_STATUS_OBSERVED' ORDER BY seq_id DESC LIMIT 1",
                [task_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn board_statuses(
        &self,
        group: Option<&str>,
    ) -> Result<BTreeMap<String, String>, V2StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT t.task_id,json_extract(e.payload_json,'$.board_status')
             FROM (
                SELECT task_id,MAX(seq_id) AS seq_id FROM task_events
                WHERE event_type='BOARD_STATUS_OBSERVED' GROUP BY task_id
             ) latest JOIN task_events e ON e.seq_id=latest.seq_id
             JOIN tasks t ON t.task_id=latest.task_id
             WHERE ?1 IS NULL OR t.task_group=?1 COLLATE NOCASE",
        )?;
        Ok(stmt
            .query_map([group], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?)
    }

    fn retire_decisions_tx(
        tx: &rusqlite::Transaction<'_>,
        task: &TaskRecord,
        now: i64,
    ) -> Result<(), V2StoreError> {
        let decisions = tx.prepare(
            "SELECT decision_id,status,EXISTS(
                 SELECT 1 FROM lifecycle_ops l WHERE l.task_id=d.task_id
                   AND l.decision_id=d.decision_id AND l.state!='ACKNOWLEDGED'
             ) FROM pending_decisions d WHERE task_id=?1
             AND NOT EXISTS(SELECT 1 FROM task_events e WHERE e.task_id=d.task_id
               AND e.event_type='DECISION_RETIRED' AND json_extract(e.payload_json,'$.decision_id')=d.decision_id)
             ORDER BY created_seq",
        )?.query_map([&task.task_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, bool>(2)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        for (id, status, pending_publication) in decisions {
            if status == "OPEN"
                || (status == "RESOLVED"
                    && (pending_publication || !task.memory.applied_decisions.contains(&id)))
            {
                Self::insert_event_tx(
                    tx,
                    &task.task_id,
                    &task.task_group,
                    now,
                    "DECISION_RETIRED",
                    &serde_json::json!({"task_id":task.task_id,"decision_id":id,"reason":task.status}),
                )?;
            }
        }
        Ok(())
    }

    pub(crate) fn retire_terminal_decisions(&mut self) -> Result<(), V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let ids = tx.prepare(
            "SELECT DISTINCT t.task_id FROM tasks t JOIN pending_decisions d ON t.task_id=d.task_id
             WHERE lower(t.status) IN ('done','cancelled')",
        )?.query_map([], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
        for id in ids {
            if let Some(task) = Self::get_task_tx(&tx, &id)? {
                Self::retire_decisions_tx(&tx, &task, now_epoch())?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn publish_status_tx(
        tx: &rusqlite::Transaction<'_>,
        task: &TaskRecord,
        now: i64,
        metadata_only: bool,
    ) -> Result<(), V2StoreError> {
        let event = if task.status.eq_ignore_ascii_case("Done") {
            "TASK_DONE"
        } else {
            "TASK_STATUS_CHANGED"
        };
        Self::insert_event_tx(
            tx,
            &task.task_id,
            &task.task_group,
            now,
            event,
            &serde_json::json!({"task_id":task.task_id,"status":task.status,
                "board_status":Self::board_status_on(tx, &task.task_id)?, "metadata_only":metadata_only}),
        )?;
        Ok(())
    }

    fn update_task_tx(
        tx: &rusqlite::Transaction<'_>,
        old: &TaskRecord,
        next: &TaskRecord,
        now: i64,
    ) -> Result<TaskRecord, V2StoreError> {
        if Self::defer_terminal_tx(tx, old, &next.status, false, now)? {
            return Ok(old.clone());
        }
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
        if old.status != next.status {
            Self::publish_status_tx(tx, next, now, false)?;
        }
        if is_terminal_task_status(&next.status) {
            Self::retire_decisions_tx(tx, next, now)?;
        } else if is_terminal_task_status(&old.status) {
            Self::retire_decisions_tx(tx, old, now)?;
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
        let existing = Self::get_task_tx(&tx, &incoming.task_id)?;
        if mode == SyncMode::ReconcileFinishedLegacy
            && let Some(old) = existing.as_ref()
            && Self::offline_identity_conflicts(old, incoming)
        {
            return Ok(old.clone());
        }
        let group = match (&existing, mode) {
            (Some(old), SyncMode::ReconcileFinishedLegacy)
                if is_terminal_task_status(&incoming.status) =>
            {
                &old.task_group
            }
            _ => &incoming.task_group,
        };
        let observed = crate::v2::runner::truncate_utf8_bytes(&incoming.status, 128);
        if Self::board_status_on(&tx, &incoming.task_id)?.as_deref() != Some(observed.as_str()) {
            Self::insert_event_tx(
                &tx,
                &incoming.task_id,
                group,
                now,
                "BOARD_STATUS_OBSERVED",
                &serde_json::json!({"task_id":incoming.task_id,"board_status":observed}),
            )?;
        }
        let result = match existing {
            Some(mut old) => {
                if mode == SyncMode::ReconcileFinishedLegacy
                    && is_terminal_task_status(&incoming.status)
                {
                    if !matches!(incoming.status.as_str(), "Done" | "Cancelled") {
                        tx.commit()?;
                        return Ok(old);
                    }
                    let raw = strict_task_json(&tx, &mut old)?;
                    let saved = Self::reconcile_offline_tx(&tx, &old, incoming, raw, now)?;
                    tx.commit()?;
                    return Ok(saved);
                }
                let delivery_hold = is_terminal_task_status(&incoming.status)
                    && Self::delivery_holds_terminal(&tx, &old)?;
                if !delivery_hold
                    && Self::defer_terminal_tx(&tx, &old, &incoming.status, true, now)?
                {
                    tx.commit()?;
                    return Ok(old);
                }
                if !is_terminal_task_status(&incoming.status) && tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM lifecycle_ops WHERE task_id=?1 AND state='DISPATCHED')",
                    [&old.task_id], |row| row.get::<_, bool>(0),
                )? {
                    let foreign_executor = incoming.executor.as_deref().filter(|executor| {
                        !executor.trim().is_empty() && !executor.eq_ignore_ascii_case("zach")
                    });
                    let mut next = old.clone();
                    next.autonomous_consent &= incoming.autonomous_consent && foreign_executor.is_none();
                    if let Some(foreign) = foreign_executor {
                        if old.autonomous_consent
                            || old.active_attempt_id.is_some()
                            || old
                                .executor
                                .as_deref()
                                .is_some_and(|e| e.eq_ignore_ascii_case("zach"))
                        {
                            let payload = serde_json::json!({
                                "task_id": old.task_id,
                                "previous_executor": old.executor,
                                "incoming_executor": foreign,
                                "active_attempt_id": old.active_attempt_id,
                            });
                            Self::insert_event_tx(
                                &tx,
                                &old.task_id,
                                &old.task_group,
                                now,
                                "CLAIM_CONFLICT_OBSERVED",
                                &payload,
                            )?;
                            Self::insert_event_tx(
                                &tx,
                                &old.task_id,
                                crate::v2::socket::SESSION_GROUP_NAME,
                                now,
                                "CLAIM_CHANGED",
                                &payload,
                            )?;
                        }
                    } else if old.autonomous_consent && !incoming.autonomous_consent {
                        Self::insert_event_tx(
                            &tx,
                            &old.task_id,
                            &old.task_group,
                            now,
                            "CONSENT_REVOKED_EXTERNALLY",
                            &serde_json::json!({
                                "task_id": old.task_id,
                                "active_attempt_id": old.active_attempt_id,
                            }),
                        )?;
                    }
                    if next.autonomous_consent != old.autonomous_consent {
                        old = Self::update_task_tx(&tx, &old, &next, now)?;
                    }
                    tx.commit()?;
                    return Ok(old);
                }
                let mut next = incoming.clone();
                let verified_delivery: bool = old.status == "Done" && tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM post_merge_deliveries WHERE task_id=?1)
                        AND NOT EXISTS(SELECT 1 FROM post_merge_deliveries WHERE task_id=?1 AND state!='verified')",
                    [&old.task_id], |row| row.get(0),
                )?;
                let is_blocked_to_ready = old.status == "Blocked" && incoming.status == "Ready";
                let has_pending_lifecycle_ops = Self::has_pending_lifecycle_on(&tx, &old.task_id)?;
                let has_open_decision: bool = !is_terminal_task_status(&old.status) && tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM pending_decisions WHERE task_id=?1 AND status='OPEN'
                     AND NOT EXISTS(SELECT 1 FROM task_events e WHERE e.task_id=pending_decisions.task_id
                       AND e.event_type='DECISION_RETIRED' AND json_extract(e.payload_json,'$.decision_id')=pending_decisions.decision_id))",
                    [&old.task_id],
                    |row| row.get(0),
                )?;
                let idle_reset_eligible = matches!(incoming.status.as_str(), "Backlog" | "Ready")
                    && !is_blocked_to_ready
                    && old.active_attempt_id.is_none()
                    && old.memory.pipeline_checkpoint.is_none()
                    && old.memory.merge_checkpoint.is_none()
                    && !is_post_merge_status(&old.status)
                    && !verified_delivery
                    && !has_pending_lifecycle_ops
                    && !has_open_decision;
                let idle_reset = idle_reset_eligible
                    && (old.status != incoming.status || incoming.status == "Backlog");
                if !idle_reset
                    && (delivery_hold
                        || (has_open_decision
                            && old.status == "Blocked"
                            && incoming.status == "Backlog")
                        || should_preserve_zach_state(&old, incoming)
                        || (verified_delivery && !is_terminal_task_status(&incoming.status)))
                {
                    next.status = old.status.clone();
                    next.stages_completed = old.stages_completed.clone();
                    next.current_stage = old.current_stage.clone();
                    next.active_attempt_id = old.active_attempt_id.clone();
                    next.plan_base_sha = old.plan_base_sha.clone();
                    next.reviewed_sha = old.reviewed_sha.clone();
                    next.pr_number = old.pr_number;
                    next.executor = old.executor.clone();
                    let foreign_executor = incoming.executor.as_deref().filter(|executor| {
                        !executor.trim().is_empty() && !executor.eq_ignore_ascii_case("zach")
                    });
                    if let Some(foreign) = foreign_executor {
                        next.autonomous_consent = false;
                        if old.active_attempt_id.is_some() {
                            let payload = serde_json::json!({
                                "task_id": old.task_id,
                                "previous_executor": old.executor,
                                "incoming_executor": foreign,
                                "active_attempt_id": old.active_attempt_id,
                            });
                            Self::insert_event_tx(
                                &tx,
                                &old.task_id,
                                &old.task_group,
                                now,
                                "CLAIM_CONFLICT_OBSERVED",
                                &payload,
                            )?;
                            Self::insert_event_tx(
                                &tx,
                                &old.task_id,
                                crate::v2::socket::SESSION_GROUP_NAME,
                                now,
                                "CLAIM_CHANGED",
                                &payload,
                            )?;
                        }
                    } else if old.active_attempt_id.is_some()
                        && old.autonomous_consent
                        && !incoming.autonomous_consent
                    {
                        Self::insert_event_tx(
                            &tx,
                            &old.task_id,
                            &old.task_group,
                            now,
                            "CONSENT_REVOKED_EXTERNALLY",
                            &serde_json::json!({
                                "task_id": old.task_id,
                                "active_attempt_id": old.active_attempt_id,
                            }),
                        )?;
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
                    if old.status == "Blocked" && incoming.status == "Ready" {
                        next.status = "Ready".into();
                        next.retry_count = 0;
                        next.next_retry_epoch = 0;
                        next.memory.halt_requested = false;
                        if old.retry_count > 0 || old.memory.halt_requested {
                            next.memory.retry_generation += 1;
                            next.memory.retry_reset_epoch = now_epoch();
                        }
                    }
                } else {
                    coalesce_runtime_fields(&old, &mut next);
                    if is_terminal_task_status(&next.status) {
                        next.lease_owner = old.lease_owner.clone();
                        next.lease_expires_epoch = old.lease_expires_epoch;
                        next.next_retry_epoch = old.next_retry_epoch;
                        next.memory = old.memory.clone();
                        next.memory.governance_started |= incoming.memory.governance_started;
                    }
                    if idle_reset {
                        next.status = incoming.status.clone();
                        next.current_stage = None;
                        next.memory.governance_started = incoming.memory.governance_started;
                        tx.execute(
                            "DELETE FROM lifecycle_ops WHERE task_id=?1 AND kind='start' AND state='ACKNOWLEDGED'",
                            [&old.task_id],
                        )?;
                        if incoming.status == "Backlog" {
                            tx.execute("DELETE FROM path_locks WHERE task_id=?1", [&old.task_id])?;
                        }
                    }
                    if old.status == "Blocked" && incoming.status == "Ready" {
                        next.status = "Ready".into();
                        next.retry_count = 0;
                        next.next_retry_epoch = 0;
                        next.memory.halt_requested = false;
                        if old.retry_count > 0 || old.memory.halt_requested {
                            next.memory.retry_generation = old
                                .memory
                                .retry_generation
                                .max(next.memory.retry_generation)
                                + 1;
                            next.memory.retry_reset_epoch = now_epoch();
                        }
                    } else {
                        next.retry_count = old.retry_count.max(next.retry_count);
                    }
                }
                next.memory.governance_terminal_observed |= old.memory.governance_terminal_observed
                    || (!delivery_hold && is_terminal_task_status(&incoming.status));
                Self::update_task_tx(&tx, &old, &next, now)?
            }
            None => {
                let mut next = incoming.clone();
                next.memory.governance_terminal_observed |=
                    is_terminal_task_status(&incoming.status);
                Self::publish_status_tx(&tx, &next, now, true)?;
                Self::insert_task_tx(&tx, &next, now)?
            }
        };
        tx.commit()?;
        Ok(result)
    }

    fn offline_identity_conflicts(old: &TaskRecord, incoming: &TaskRecord) -> bool {
        old.repository != incoming.repository
            || old
                .github_repo
                .as_ref()
                .zip(incoming.github_repo.as_ref())
                .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty() && a != b)
            || old
                .issue_number
                .zip(incoming.issue_number)
                .is_some_and(|(a, b)| a != b)
    }

    fn reconcile_offline_tx(
        tx: &rusqlite::Transaction<'_>,
        old: &TaskRecord,
        incoming: &TaskRecord,
        mut raw: RawTask,
        now: i64,
    ) -> Result<TaskRecord, V2StoreError> {
        let conflicting = Self::offline_identity_conflicts(old, incoming)
            || incoming.current_stage.is_some()
            || incoming.lease_owner.is_some()
            || incoming.lease_expires_epoch.is_some()
            || incoming.retry_count != 0
            || incoming.next_retry_epoch != 0
            || incoming.memory.halt_requested
            || incoming.memory.retry_generation != 0
            || incoming.memory.retry_reset_epoch != 0
            || incoming.memory.merge_retry_count != 0
            || incoming.memory.merge_retry_generation != 0
            || incoming.memory.plan_rework_count != 0
            || incoming.memory.plan_rework_generation != 0
            || incoming.memory.review_rework_count != 0
            || incoming.memory.review_rework_generation != 0;
        if conflicting {
            return Ok(old.clone());
        }
        let empty = Self::can_classify_empty_tx(tx, old, incoming)?;
        if !empty && !Self::can_retire_finished_tx(tx, old, incoming)? {
            return Ok(old.clone());
        }
        let mut memory = match raw.get("memory_json") {
            Some(rusqlite::types::Value::Text(s)) => s.clone(),
            _ => return Err(raw_proof_error()),
        };
        if !empty && !old.memory.governance_terminal_observed {
            let UniqueJson(mut value) =
                serde_json::from_str(&memory).map_err(|_| raw_proof_error())?;
            value
                .as_object_mut()
                .ok_or_else(raw_proof_error)?
                .insert("governance_terminal_observed".into(), true.into());
            memory = serde_json::to_string(&value)?;
        }
        let active = if empty {
            old.active_attempt_id.clone()
        } else {
            None
        };
        let changed = old.status != incoming.status
            || old.active_attempt_id != active
            || raw.get("memory_json") != Some(&rusqlite::types::Value::Text(memory.clone()));
        if changed {
            let version = old
                .version
                .checked_add(1)
                .ok_or_else(|| V2StoreError("offline version overflow".into()))?;
            let affected = if empty {
                tx.execute("UPDATE tasks SET status=?1,version=?2,updated_epoch=?3 WHERE task_id=?4 AND version=?5", params![incoming.status,version,now,old.task_id,old.version])?
            } else {
                tx.execute("UPDATE tasks SET status=?1,active_attempt_id=NULL,memory_json=?2,version=?3,updated_epoch=?4 WHERE task_id=?5 AND version=?6", params![incoming.status,memory,version,now,old.task_id,old.version])?
            };
            raw.insert("status".into(), incoming.status.clone().into());
            raw.insert("version".into(), version.into());
            raw.insert("updated_epoch".into(), now.into());
            if !empty {
                raw.insert("active_attempt_id".into(), rusqlite::types::Value::Null);
                raw.insert("memory_json".into(), memory.into());
            }
            if affected != 1 || raw_task(tx, &old.task_id)? != raw {
                return Err(V2StoreError(
                    "offline task update postcondition failed".into(),
                ));
            }
        }
        if !empty {
            tx.execute(
                "DELETE FROM merge_queue WHERE repo=?1 AND task_id=?2 AND state='FAILED'",
                params![old.repository, old.task_id],
            )?;
            let remaining: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM merge_queue WHERE task_id=?1)",
                [&old.task_id],
                |r| r.get(0),
            )?;
            if remaining {
                return Err(V2StoreError(
                    "offline queue cleanup postcondition failed".into(),
                ));
            }
        }
        if raw_task(tx, &old.task_id)? != raw {
            return Err(V2StoreError("offline task changed during cleanup".into()));
        }
        let saved = Self::get_task_tx(tx, &old.task_id)?
            .ok_or_else(|| V2StoreError("offline task disappeared".into()))?;
        if old.status != saved.status {
            Self::publish_status_tx(tx, &saved, now, empty)?;
        }
        Self::retire_decisions_tx(tx, &saved, now)?;
        Ok(saved)
    }

    fn can_classify_empty_tx(
        tx: &rusqlite::Transaction<'_>,
        old: &TaskRecord,
        incoming: &TaskRecord,
    ) -> Result<bool, V2StoreError> {
        if old.current_stage.is_some()
            || old.active_attempt_id.is_some()
            || old.plan_base_sha.is_some()
            || old.reviewed_sha.is_some()
            || old.pr_number.is_some()
            || old.executor.is_some()
            || old.lease_owner.is_some()
            || old.lease_expires_epoch.is_some()
            || old.retry_count != 0
            || old.next_retry_epoch != 0
            || !old.stages_completed.is_empty()
            || old.memory != TaskMemory::default()
            || incoming.active_attempt_id.is_some()
            || incoming.memory.pipeline_checkpoint.is_some()
            || incoming.memory.merge_checkpoint.is_some()
            || incoming.memory.suspended_impl_attempt_id.is_some()
        {
            return Ok(false);
        }
        for table in [
            "stage_attempts",
            "lifecycle_ops",
            "post_merge_deliveries",
            "pending_decisions",
            "merge_queue",
            "path_locks",
        ] {
            let exists: bool = tx.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE task_id=?1)"),
                [&old.task_id],
                |r| r.get(0),
            )?;
            if exists {
                return Ok(false);
            }
        }
        let native_events: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM task_events WHERE task_id=?1
             AND event_type!='BOARD_STATUS_OBSERVED'
             AND NOT(event_type IN ('TASK_DONE','TASK_STATUS_CHANGED') AND
                     coalesce(json_extract(payload_json,'$.metadata_only'),0)=1))",
            [&old.task_id],
            |row| row.get(0),
        )?;
        Ok(!native_events)
    }

    /// Status/consent alone never proves that Zach owns startup recovery. Validate
    /// raw data before a manual exclusion, including rows the ordinary reader defaults.
    pub(crate) fn native_startup_owned(&self, task: &TaskRecord) -> Result<bool, V2StoreError> {
        let mut task = task.clone();
        strict_task_json(&self.conn, &mut task)?;
        if matches!(
            task.status.as_str(),
            "Planning" | "Plan Review" | "In Progress" | "PR Review"
        ) && task.active_attempt_id.is_none()
            && task.memory.pipeline_checkpoint.is_none()
            && (task.memory.merge_checkpoint.is_some()
                || task.memory.suspended_impl_attempt_id.is_some())
        {
            return Err(V2StoreError(
                "ambiguous native startup checkpoint status".into(),
            ));
        }
        if is_zach_executor(task.executor.as_deref())
            || task.active_attempt_id.is_some()
            || task.next_retry_epoch != 0
            || task.lease_owner.is_some()
            || task.lease_expires_epoch.is_some()
            || task.memory.pipeline_checkpoint.is_some()
            || task.memory.merge_checkpoint.is_some()
            || task.memory.suspended_impl_attempt_id.is_some()
        {
            return Ok(true);
        }
        if self.has_pending_lifecycle(&task.task_id)? {
            return Ok(true);
        }
        for table in ["post_merge_deliveries", "merge_queue", "path_locks"] {
            let filter = if table == "post_merge_deliveries" {
                " AND state NOT IN ('verified','aborted')"
            } else {
                ""
            };
            let exists: bool = self.conn.query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE task_id=?1{filter})"),
                [&task.task_id],
                |r| r.get(0),
            )?;
            if exists {
                return Ok(true);
            }
        }
        let attempts = self.list_stage_attempts(&task.task_id)?;
        if attempts
            .iter()
            .any(|a| a.ended_epoch.is_none() || a.phase != "COMPLETE")
        {
            return Ok(true);
        }
        let confirmed_terminal_history = task.memory.governance_terminal_observed
            && matches!(task.status.as_str(), "Done" | "Cancelled");
        if attempts.iter().any(|a| {
            !(matches!(a.status.as_str(), "PASSED" | "FAILED")
                || (confirmed_terminal_history && a.status == "LOST"))
                || (a.status == "PASSED"
                    && !task.memory.governance_terminal_observed
                    && !task.stages_completed.contains(&a.stage))
        }) {
            return Err(V2StoreError("ambiguous native startup history".into()));
        }
        let mut decisions = self.conn.prepare(&format!(
            "{} WHERE d.task_id=?1",
            Self::DECISION_HISTORY_SELECT,
        ))?;
        for row in decisions.query_map([&task.task_id], Self::map_decision_row)? {
            let decision = row?;
            if decision.status != "RETIRED"
                && (decision.status != "RESOLVED"
                    || !task
                        .memory
                        .applied_decisions
                        .contains(&decision.decision_id))
            {
                return Ok(true);
            }
        }
        // A terminal observation can outlive a later human reopen. With every
        // current native reference/effect excluded above, completed worker stages
        // and merge-stage labels are historical, even if Standard replaced labels.
        if task.memory.governance_terminal_observed {
            if task.current_stage.as_deref().is_some_and(|stage| {
                !matches!(stage, "merge" | "merge_queue")
                    && !task.stages_completed.iter().any(|s| s == stage)
                    && !attempts.iter().any(|a| a.stage == stage)
            }) {
                return Err(V2StoreError(
                    "ambiguous native historical startup stage".into(),
                ));
            }
            return Ok(false);
        }
        Ok(task.memory.governance_started || task.current_stage.is_some())
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
        let effects: bool = Self::has_pending_lifecycle_on(tx, &old.task_id)?
            || tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM post_merge_deliveries WHERE task_id=?1 AND state!='verified')
                 OR EXISTS(SELECT 1 FROM merge_queue WHERE task_id=?1 AND (state!='FAILED' OR repo!=?2))",
                params![old.task_id, old.repository], |r| r.get(0),
            )?;
        if effects {
            return Ok(false);
        }
        let decisions = tx
            .prepare("SELECT decision_id,status FROM pending_decisions d WHERE task_id=?1
                AND NOT EXISTS(SELECT 1 FROM task_events e WHERE e.task_id=d.task_id
                    AND e.event_type='DECISION_RETIRED' AND json_extract(e.payload_json,'$.decision_id')=d.decision_id)")?
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
        Self::retire_decisions_tx(&tx, &old, now_epoch())?;
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
            let has_active_grant = task.has_active_stage_grant();
            let status_eligible = task.status == "Ready"
                || (has_active_grant
                    && matches!(
                        task.status.as_str(),
                        "Planning" | "Plan Review" | "In Progress" | "PR Review"
                    )
                    && task.active_attempt_id.is_none()
                    && task.memory.pipeline_checkpoint.is_none());
            if !status_eligible
                || !task.has_any_execution_grant()
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

    pub fn record_session_announcement(
        &mut self,
        announcement: &crate::v2::socket::SessionAnnouncementRecord,
    ) -> Result<TaskEventRecord, V2StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let task_id = announcement
            .task_id
            .as_deref()
            .unwrap_or(crate::v2::socket::SESSION_GROUP_NAME);
        let payload = serde_json::to_value(announcement)?;
        let seq_id = Self::insert_event_tx(
            &tx,
            task_id,
            crate::v2::socket::SESSION_GROUP_NAME,
            announcement.announced_at_epoch,
            "SESSION_ANNOUNCEMENT",
            &payload,
        )?;
        tx.commit()?;
        Ok(TaskEventRecord {
            seq_id,
            task_id: task_id.to_owned(),
            task_group: crate::v2::socket::SESSION_GROUP_NAME.to_owned(),
            ts_epoch: announcement.announced_at_epoch,
            event_type: "SESSION_ANNOUNCEMENT".to_owned(),
            payload,
        })
    }

    pub fn list_session_announcements(
        &self,
        include_stale: bool,
        now: i64,
    ) -> Result<Vec<crate::v2::socket::SessionAnnouncementRecord>, V2StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT payload_json FROM task_events
             WHERE task_group = ?1 AND event_type = 'SESSION_ANNOUNCEMENT'
             ORDER BY seq_id ASC",
        )?;
        let mut by_holder = std::collections::BTreeMap::<
            String,
            crate::v2::socket::SessionAnnouncementRecord,
        >::new();
        let rows = stmt.query_map(params![crate::v2::socket::SESSION_GROUP_NAME], |row| {
            row.get::<_, String>(0)
        })?;
        for row in rows {
            let raw = row?;
            if let Ok(rec) =
                serde_json::from_str::<crate::v2::socket::SessionAnnouncementRecord>(&raw)
            {
                by_holder.insert(rec.holder.clone(), rec);
            }
        }
        let mut out: Vec<_> = by_holder
            .into_values()
            .filter(|rec| include_stale || rec.expires_at_epoch >= now)
            .collect();
        out.sort_by(|a, b| a.holder.cmp(&b.holder));
        Ok(out)
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
        let bounded_context = crate::v2::runner::truncate_utf8_bytes(
            context_summary,
            crate::v2::runner::MAX_SUMMARY_BYTES,
        );
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = Self::get_decision_on(&tx, decision_id)? {
            return Ok(existing);
        }
        let old = Self::get_task_tx(&tx, task_id)?;
        if old
            .as_ref()
            .is_some_and(|task| is_terminal_task_status(&task.status))
        {
            return Err(V2StoreError(
                "cannot open a decision for a terminal task".into(),
            ));
        }
        let linked_unverified_delivery: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM post_merge_deliveries
                           WHERE task_id=?1 AND decision_id=?2 AND state NOT IN ('verified','aborted'))",
            params![task_id, decision_id],
            |row| row.get(0),
        )?;
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
                "linked_unverified_delivery": linked_unverified_delivery,
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
        if let (Some(old), Some(next)) = (old, Self::get_task_tx(&tx, task_id)?)
            && old.status != next.status
        {
            Self::publish_status_tx(&tx, &next, now, false)?;
        }
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
        let choice = if let Some(existing) = Self::get_decision_on(&tx, decision_id)? {
            if existing.status == "RETIRED" {
                return Ok(DecisionResolution::NotFound);
            }
            if existing.status == "RESOLVED" {
                return Ok(DecisionResolution::AlreadyResolved(existing));
            }
            let task = Self::get_task_tx(&tx, &existing.task_id)?
                .ok_or_else(|| V2StoreError("decision task missing".into()))?;
            let delivery = !matches!(
                existing.kind.as_str(),
                "governance_close_failed" | "governance_publication_uncertain"
            ) && (is_post_merge_decision(&existing.kind)
                || is_post_merge_status(&task.status)
                || tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM post_merge_deliveries WHERE task_id=?1)",
                    [&existing.task_id],
                    |row| row.get(0),
                )?);
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
        let changed = tx.execute(
            "UPDATE pending_decisions
             SET status = 'RESOLVED', choice = ?2, resolved_by = ?3, resolved_epoch = ?4, note = ?5
             WHERE decision_id = ?1 AND status = 'OPEN'
               AND EXISTS(SELECT 1 FROM tasks t WHERE t.task_id=pending_decisions.task_id
                          AND lower(t.status) NOT IN ('done','cancelled'))
               AND NOT EXISTS(SELECT 1 FROM task_events e WHERE e.task_id=pending_decisions.task_id
                   AND e.event_type='DECISION_RETIRED' AND json_extract(e.payload_json,'$.decision_id')=?1)",
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
        let post_merge =
            !matches!(
                kind.as_str(),
                "governance_close_failed" | "governance_publication_uncertain"
            ) && (is_post_merge_decision(&kind) || is_post_merge_status(&task_status) || linked);
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
        if next_status != task_status
            && let Some(task) = Self::get_task_tx(&tx, &task_id)?
        {
            Self::publish_status_tx(&tx, &task, now, false)?;
        }
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
        Self::get_decision_on(&self.conn, decision_id)
    }

    const DECISION_HISTORY_SELECT: &str = "
        SELECT d.decision_id,d.task_id,d.task_group,d.kind,d.question,d.options_json,
               d.recommended_option,d.context_summary,d.sha,d.status,d.created_seq,
               d.resolved_by,d.resolved_epoch,d.choice,d.note,
               coalesce(
                   (SELECT json_extract(e.payload_json,'$.reason') FROM task_events e
                    WHERE e.task_id=d.task_id AND e.event_type='DECISION_RETIRED'
                    AND json_extract(e.payload_json,'$.decision_id')=d.decision_id
                    ORDER BY seq_id DESC LIMIT 1),
                   (SELECT t.status FROM tasks t WHERE t.task_id=d.task_id
                    AND d.status='OPEN' AND lower(t.status) IN ('done','cancelled'))
               ) AS retirement_reason,
               EXISTS(SELECT 1 FROM post_merge_deliveries p
                      WHERE p.task_id=d.task_id AND p.decision_id=d.decision_id
                      AND p.state NOT IN ('verified','aborted'))
        FROM pending_decisions d";

    fn get_decision_on(
        conn: &Connection,
        decision_id: &str,
    ) -> Result<Option<PendingDecisionRecord>, V2StoreError> {
        Ok(conn
            .prepare(&format!(
                "{} WHERE d.decision_id=?1",
                Self::DECISION_HISTORY_SELECT
            ))?
            .query_row([decision_id], Self::map_decision_row)
            .optional()?)
    }

    pub fn list_decisions(
        &self,
        open_only: bool,
        group_filter: Option<&str>,
    ) -> Result<Vec<PendingDecisionRecord>, V2StoreError> {
        let mut stmt = self.conn.prepare(&format!(
            "{} WHERE (?1 IS NULL OR d.task_group=?1 COLLATE NOCASE) ORDER BY d.created_seq",
            Self::DECISION_HISTORY_SELECT,
        ))?;
        let rows = stmt.query_map([group_filter], Self::map_decision_row)?;
        let mut decisions = Vec::new();
        for row in rows {
            let decision = row?;
            if !open_only || decision.status == "OPEN" {
                decisions.push(decision);
            }
        }
        Ok(decisions)
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
        if decision.is_some()
            && is_terminal_task_status(&old.status)
            && !is_terminal_task_status(&task.status)
        {
            return Err(V2StoreError(
                "decision cannot reopen a terminal task".into(),
            ));
        }
        Self::update_task_tx(&tx, &old, task, now_epoch())?;
        if let Some(attempt) = attempt {
            Self::record_stage_attempt_tx(&tx, attempt)?;
        }
        if release {
            tx.execute("DELETE FROM path_locks WHERE task_id=?1", [&task.task_id])?;
            tx.execute("DELETE FROM merge_queue WHERE task_id=?1", [&task.task_id])?;
        }
        if let Some(decision) = decision
            && !is_terminal_task_status(&task.status)
            && !is_terminal_task_status(&old.status)
        {
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

    pub fn record_attempt_audit(&mut self, audit: &AttemptAuditRecord) -> Result<(), V2StoreError> {
        let sanitized_error_code = audit
            .error_code
            .as_deref()
            .map(|c| {
                crate::v2::audit::redact_adr004_text(
                    c,
                    crate::v2::audit::MAX_AUDIT_DIGEST_ERROR_SIGNATURE_LEN,
                )
            })
            .filter(|c| !c.is_empty());
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO attempt_audits (
                attempt_id, task_id, stage, turn_count, tool_call_count, tool_error_count,
                edit_compile_fail_loops, redundant_read_count, cached_input_tokens,
                reasoning_tokens, check_divergence, error_code, created_epoch
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(attempt_id) DO UPDATE SET
                task_id = excluded.task_id,
                stage = excluded.stage,
                turn_count = excluded.turn_count,
                tool_call_count = excluded.tool_call_count,
                tool_error_count = excluded.tool_error_count,
                edit_compile_fail_loops = excluded.edit_compile_fail_loops,
                redundant_read_count = excluded.redundant_read_count,
                cached_input_tokens = COALESCE(excluded.cached_input_tokens, attempt_audits.cached_input_tokens),
                reasoning_tokens = COALESCE(excluded.reasoning_tokens, attempt_audits.reasoning_tokens),
                check_divergence = MAX(attempt_audits.check_divergence, excluded.check_divergence),
                error_code = COALESCE(excluded.error_code, attempt_audits.error_code),
                created_epoch = excluded.created_epoch",
            params![
                audit.attempt_id,
                audit.task_id,
                audit.stage,
                audit.turn_count as i64,
                audit.tool_call_count as i64,
                audit.tool_error_count as i64,
                audit.edit_compile_fail_loops as i64,
                audit.redundant_read_count as i64,
                audit.cached_input_tokens.map(|v| v as i64),
                audit.reasoning_tokens.map(|v| v as i64),
                i64::from(audit.check_divergence),
                sanitized_error_code,
                audit.created_epoch,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_attempt_audit(
        &self,
        attempt_id: &str,
    ) -> Result<Option<AttemptAuditRecord>, V2StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT attempt_id, task_id, stage, turn_count, tool_call_count, tool_error_count,
                    edit_compile_fail_loops, redundant_read_count, cached_input_tokens,
                    reasoning_tokens, check_divergence, error_code, created_epoch
             FROM attempt_audits WHERE attempt_id = ?1",
        )?;
        stmt.query_row(params![attempt_id], Self::map_attempt_audit_row)
            .optional()
            .map_err(V2StoreError::from)
    }

    pub fn list_attempt_audits(
        &self,
        task_id: &str,
    ) -> Result<Vec<AttemptAuditRecord>, V2StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT attempt_id, task_id, stage, turn_count, tool_call_count, tool_error_count,
                    edit_compile_fail_loops, redundant_read_count, cached_input_tokens,
                    reasoning_tokens, check_divergence, error_code, created_epoch
             FROM attempt_audits WHERE task_id = ?1 ORDER BY created_epoch ASC, rowid ASC",
        )?;
        let rows = stmt.query_map(params![task_id], Self::map_attempt_audit_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn mark_attempt_check_divergence(
        &mut self,
        attempt_id: &str,
        task_id: &str,
        stage: &str,
        error_code: Option<&str>,
    ) -> Result<(), V2StoreError> {
        let sanitized_error_code = error_code
            .map(|c| {
                crate::v2::audit::redact_adr004_text(
                    c,
                    crate::v2::audit::MAX_AUDIT_DIGEST_ERROR_SIGNATURE_LEN,
                )
            })
            .filter(|c| !c.is_empty());
        let now = now_epoch();
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO attempt_audits (
                attempt_id, task_id, stage, turn_count, tool_call_count, tool_error_count,
                edit_compile_fail_loops, redundant_read_count, cached_input_tokens,
                reasoning_tokens, check_divergence, error_code, created_epoch
             ) VALUES (?1, ?2, ?3, 0, 0, 0, 0, 0, NULL, NULL, 1, ?4, ?5)
             ON CONFLICT(attempt_id) DO UPDATE SET
                check_divergence = 1,
                error_code = COALESCE(excluded.error_code, attempt_audits.error_code)",
            params![attempt_id, task_id, stage, sanitized_error_code, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn list_task_events(&self, task_id: &str) -> Result<Vec<TaskEventRecord>, V2StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT seq_id, task_id, task_group, ts_epoch, event_type, payload_json
             FROM task_events WHERE task_id = ?1 ORDER BY seq_id ASC",
        )?;
        let rows = stmt.query_map(params![task_id], Self::map_event_row)?;
        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    fn map_attempt_audit_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AttemptAuditRecord> {
        Ok(AttemptAuditRecord {
            attempt_id: row.get(0)?,
            task_id: row.get(1)?,
            stage: row.get(2)?,
            turn_count: row.get::<_, i64>(3)?.max(0) as u64,
            tool_call_count: row.get::<_, i64>(4)?.max(0) as u64,
            tool_error_count: row.get::<_, i64>(5)?.max(0) as u64,
            edit_compile_fail_loops: row.get::<_, i64>(6)?.max(0) as u64,
            redundant_read_count: row.get::<_, i64>(7)?.max(0) as u64,
            cached_input_tokens: row.get::<_, Option<i64>>(8)?.map(|v| v.max(0) as u64),
            reasoning_tokens: row.get::<_, Option<i64>>(9)?.map(|v| v.max(0) as u64),
            check_divergence: row.get::<_, i64>(10)? != 0,
            error_code: row.get(11)?,
            created_epoch: row.get(12)?,
        })
    }

    /// Returns the set of `attempt_id`s that are non-terminal or referenced by
    /// active tasks, in-flight lifecycle operations, or non-terminal task checkpoints.
    pub fn active_attempt_ids(&self) -> Result<BTreeSet<String>, V2StoreError> {
        let mut active = BTreeSet::new();

        {
            let mut stmt = self.conn.prepare(
                "SELECT attempt_id FROM stage_attempts
                 WHERE phase != 'COMPLETE' OR ended_epoch IS NULL OR status = 'RUNNING'",
            )?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            for row in rows {
                let id = row?;
                if !id.trim().is_empty() {
                    active.insert(id);
                }
            }
        }

        {
            let mut stmt = self
                .conn
                .prepare("SELECT active_attempt_id, status, memory_json FROM tasks")?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                let (active_attempt_id, status, memory_json) = row?;
                if let Some(id) = active_attempt_id
                    && !id.trim().is_empty()
                {
                    active.insert(id);
                }
                if !matches!(status.trim(), "Done" | "Cancelled") {
                    let memory: TaskMemory = serde_json::from_str(&memory_json).map_err(|e| {
                        V2StoreError(format!(
                            "decode task memory_json in active_attempt_ids: {e}"
                        ))
                    })?;
                    if let Some(cp) = memory.pipeline_checkpoint.as_ref()
                        && !cp.attempt_id.trim().is_empty()
                    {
                        active.insert(cp.attempt_id.clone());
                    }
                    if let Some(id) = memory.suspended_impl_attempt_id.as_deref()
                        && !id.trim().is_empty()
                    {
                        active.insert(id.to_owned());
                    }
                    if let Some(path) = memory.last_pr_review_evidence_path.as_deref()
                        && let Some(id) = extract_attempt_id_from_path(path)
                    {
                        active.insert(id);
                    }
                }
            }
        }

        {
            let mut stmt = self.conn.prepare(
                "SELECT attempt_id, body_path FROM lifecycle_ops WHERE state NOT IN ('ACKNOWLEDGED','SETTLED')",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            })?;
            for row in rows {
                let (attempt_id, body_path) = row?;
                if let Some(id) = attempt_id
                    && !id.trim().is_empty()
                {
                    active.insert(id);
                }
                if let Some(path) = body_path
                    && let Some(id) = extract_attempt_id_from_path(&path)
                {
                    active.insert(id);
                }
            }
        }

        Ok(active)
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
            // Human active labels reserve their repository, but only native
            // ownership consumes global execution capacity. This also counts
            // the scheduler's lock-before-attempt preparation window.
            return self.native_startup_owned(task);
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
                .filter(|o| !matches!(o.state.as_str(), "ACKNOWLEDGED" | "SETTLED"))
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

    pub fn repo_reservations(
        &self,
        all_tasks: &[TaskRecord],
    ) -> Result<BTreeMap<String, Vec<RepoReservation>>, V2StoreError> {
        let mut by_repo: BTreeMap<String, Vec<RepoReservation>> = BTreeMap::new();
        for lock in self.list_path_locks(None)? {
            by_repo
                .entry(lock.repo)
                .or_default()
                .push(RepoReservation::WholeRepo {
                    task_id: lock.task_id,
                });
        }
        for t in all_tasks {
            if t.status == "Queued for Merge" {
                by_repo
                    .entry(t.repository.clone())
                    .or_default()
                    .push(RepoReservation::WholeRepo {
                        task_id: t.task_id.clone(),
                    });
            } else if matches!(
                t.status.as_str(),
                "Planning" | "Plan Review" | "In Progress" | "PR Review"
            ) {
                if t.executor.as_deref() == Some("session") {
                    let paths: Vec<String> = t
                        .context_pack
                        .target_files
                        .iter()
                        .map(|f| normalize_repo_path(&f.path))
                        .collect();
                    if paths.is_empty() || paths.iter().any(|p| p == "*") {
                        by_repo.entry(t.repository.clone()).or_default().push(
                            RepoReservation::WholeRepo {
                                task_id: t.task_id.clone(),
                            },
                        );
                    } else {
                        by_repo.entry(t.repository.clone()).or_default().push(
                            RepoReservation::ScopedPaths {
                                task_id: t.task_id.clone(),
                                paths,
                            },
                        );
                    }
                } else {
                    by_repo.entry(t.repository.clone()).or_default().push(
                        RepoReservation::WholeRepo {
                            task_id: t.task_id.clone(),
                        },
                    );
                }
            }
        }
        for entry in self.list_merge_queue(None)? {
            by_repo
                .entry(entry.repo)
                .or_default()
                .push(RepoReservation::WholeRepo {
                    task_id: entry.task_id,
                });
        }
        Ok(by_repo)
    }

    pub fn detailed_status(
        &self,
        group_filter: Option<&str>,
    ) -> Result<DetailedStatusReport, V2StoreError> {
        let summary = self.status_summary()?;
        let all_tasks = self.list_tasks(None)?;
        let done_ids: BTreeSet<String> = all_tasks
            .iter()
            .filter(|t| t.status == "Done")
            .map(|t| t.task_id.clone())
            .collect();
        let all_open_decisions = self.list_decisions(true, None)?;
        let blocked_by_decision: BTreeSet<String> = all_open_decisions
            .iter()
            .map(|d| d.task_id.clone())
            .collect();
        let reservations = self.repo_reservations(&all_tasks)?;
        let max_parallel = self.max_parallel_tasks()?;
        let active_slot_count = all_tasks
            .iter()
            .map(|task| self.occupies_task_slot(task))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|occupied| *occupied)
            .count();
        let available_slots = max_parallel.saturating_sub(active_slot_count);
        let now = now_epoch();

        let board_statuses = self.board_statuses(group_filter)?;
        let open_decisions = self.list_decisions(true, group_filter)?;
        let mut active_tasks = Vec::new();
        let mut waiting_tasks = Vec::new();
        let mut group_task_ids = BTreeSet::new();

        for task in &all_tasks {
            if let Some(group) = group_filter
                && !task.task_group.eq_ignore_ascii_case(group)
            {
                continue;
            }
            group_task_ids.insert(task.task_id.clone());
            let board_status = board_statuses.get(&task.task_id).cloned();
            let open_decision_id = open_decisions
                .iter()
                .filter(|decision| decision.task_id == task.task_id)
                .max_by_key(|decision| (decision.linked_unverified_delivery, decision.created_seq))
                .map(|decision| decision.decision_id.clone());

            let target_files: Vec<String> = task
                .context_pack
                .target_files
                .iter()
                .map(|f| normalize_repo_path(&f.path))
                .collect();

            if matches!(
                task.status.as_str(),
                "Planning" | "Plan Review" | "In Progress" | "PR Review" | "Queued for Merge"
            ) {
                let attempt = if let Some(id) = task.active_attempt_id.as_deref() {
                    self.get_stage_attempt(id)?
                } else {
                    None
                };
                let occupies_slot = self.occupies_task_slot(task)?;
                let reservation = if task.status != "Queued for Merge"
                    && task.executor.as_deref() == Some("session")
                    && !target_files.is_empty()
                    && !target_files.iter().any(|p| p == "*")
                {
                    "scoped_paths".to_owned()
                } else {
                    "whole_repo".to_owned()
                };
                active_tasks.push(ActiveTaskDetail {
                    task_id: task.task_id.clone(),
                    task_group: task.task_group.clone(),
                    repository: task.repository.clone(),
                    weight: task.weight.clone(),
                    status: task.status.clone(),
                    board_status,
                    open_decision_id,
                    title: task.title.clone(),
                    executor: task.executor.clone(),
                    current_stage: task.current_stage.clone(),
                    attempt_id: task.active_attempt_id.clone(),
                    attempt_phase: attempt.as_ref().map(|a| a.phase.clone()),
                    model: attempt.map(|a| a.model),
                    occupies_slot,
                    target_files,
                    reservation,
                });
            } else if matches!(task.status.as_str(), "Ready" | "Blocked")
                || is_post_merge_status(&task.status)
                || open_decision_id.is_some()
            {
                let wait_reason = if !task.autonomous_consent {
                    "awaiting_consent".to_owned()
                } else if blocked_by_decision.contains(&task.task_id) {
                    "open_decision".to_owned()
                } else if self.has_pending_lifecycle(&task.task_id)? {
                    "pending_lifecycle".to_owned()
                } else if task.next_retry_epoch > now {
                    "retry_backoff".to_owned()
                } else if let Some(dep) =
                    task.depends_on.iter().find(|dep| !done_ids.contains(*dep))
                {
                    format!("dependency:{dep}")
                } else if task.status == "Blocked" {
                    "blocked".to_owned()
                } else if let Some(conflict) = repo_conflict_for_task(
                    reservations
                        .get(&task.repository)
                        .map(Vec::as_slice)
                        .unwrap_or(&[]),
                    task,
                ) {
                    match conflict {
                        RepoConflict::RepoLocked { owner } => format!("repo_locked:{owner}"),
                        RepoConflict::PathConflict { owner, path } => {
                            format!("path_conflict:{owner}:{path}")
                        }
                    }
                } else if is_post_merge_status(&task.status) {
                    "post_merge_delivery".to_owned()
                } else if available_slots == 0 {
                    "no_free_slots".to_owned()
                } else {
                    "eligible".to_owned()
                };

                waiting_tasks.push(WaitingTaskDetail {
                    task_id: task.task_id.clone(),
                    task_group: task.task_group.clone(),
                    repository: task.repository.clone(),
                    weight: task.weight.clone(),
                    status: task.status.clone(),
                    board_status,
                    open_decision_id,
                    title: task.title.clone(),
                    wait_reason,
                    target_files,
                    next_retry_epoch: task.next_retry_epoch,
                });
            }
        }

        let path_locks = self
            .list_path_locks(None)?
            .into_iter()
            .filter(|lock| group_filter.is_none() || group_task_ids.contains(&lock.task_id))
            .collect();
        let merge_queue = self
            .list_merge_queue(None)?
            .into_iter()
            .filter(|entry| group_filter.is_none() || group_task_ids.contains(&entry.task_id))
            .collect();
        Ok(DetailedStatusReport {
            summary,
            active_tasks,
            waiting_tasks,
            path_locks,
            merge_queue,
            open_decisions,
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
        let retirement_reason = row.get::<_, Option<String>>(15)?;
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
            status: if retirement_reason.is_some() {
                "RETIRED".into()
            } else {
                row.get(9)?
            },
            created_seq: row.get(10)?,
            resolved_by: row.get(11)?,
            resolved_epoch: row.get(12)?,
            choice: row.get(13)?,
            note: row.get(14)?,
            retirement_reason,
            linked_unverified_delivery: row.get(16)?,
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

    pub fn upsert_provider_cooldown(
        &mut self,
        family: &str,
        until_epoch: i64,
        reason: &str,
    ) -> Result<(), V2StoreError> {
        let updated_epoch = now_epoch();
        self.conn.execute(
            "INSERT INTO provider_cooldowns(family, until_epoch, reason, updated_epoch)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(family) DO UPDATE SET
                 until_epoch = MAX(provider_cooldowns.until_epoch, excluded.until_epoch),
                 reason = excluded.reason,
                 updated_epoch = excluded.updated_epoch",
            params![family, until_epoch, reason, updated_epoch],
        )?;
        Ok(())
    }

    pub fn get_active_provider_cooldown(
        &self,
        family: &str,
        now: i64,
    ) -> Result<Option<ProviderCooldownRecord>, V2StoreError> {
        self.conn
            .query_row(
                "SELECT family, until_epoch, reason, updated_epoch
                 FROM provider_cooldowns
                 WHERE family = ?1 AND until_epoch > ?2",
                params![family, now],
                Self::row_to_provider_cooldown,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_provider_cooldowns(
        &self,
        now: Option<i64>,
    ) -> Result<Vec<ProviderCooldownRecord>, V2StoreError> {
        match now {
            Some(ts) => {
                let mut stmt = self.conn.prepare(
                    "SELECT family, until_epoch, reason, updated_epoch
                     FROM provider_cooldowns
                     WHERE until_epoch > ?1
                     ORDER BY until_epoch ASC, family ASC",
                )?;
                let rows = stmt
                    .query_map(params![ts], Self::row_to_provider_cooldown)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            }
            None => {
                let mut stmt = self.conn.prepare(
                    "SELECT family, until_epoch, reason, updated_epoch
                     FROM provider_cooldowns
                     ORDER BY until_epoch ASC, family ASC",
                )?;
                let rows = stmt
                    .query_map([], Self::row_to_provider_cooldown)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            }
        }
    }

    pub fn clear_provider_cooldown(&mut self, family: Option<&str>) -> Result<usize, V2StoreError> {
        let count = match family {
            Some(fam) => self.conn.execute(
                "DELETE FROM provider_cooldowns WHERE family = ?1",
                params![fam],
            )?,
            None => self.conn.execute("DELETE FROM provider_cooldowns", [])?,
        };
        Ok(count)
    }

    fn row_to_provider_cooldown(
        row: &rusqlite::Row<'_>,
    ) -> rusqlite::Result<ProviderCooldownRecord> {
        Ok(ProviderCooldownRecord {
            family: row.get(0)?,
            until_epoch: row.get(1)?,
            reason: row.get(2)?,
            updated_epoch: row.get(3)?,
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
    let incoming_governance_started = next.memory.governance_started;
    if next.memory == TaskMemory::default() {
        next.memory = old.memory.clone();
    } else if next.memory.merge_checkpoint.is_none() {
        // Board exports cannot replace a durable merge/delivery receipt.
        next.memory.merge_checkpoint = old.memory.merge_checkpoint.clone();
        next.memory.merge_lane_released = old.memory.merge_lane_released;
    }
    if matches!(next.status.as_str(), "Backlog" | "Ready")
        && !incoming_governance_started
        && !(old.status == "Blocked" && next.status == "Ready")
    {
        next.memory.governance_started = false;
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

    fn table_rows(store: &V2Store, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
        let mut stmt = store
            .conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let count = stmt.column_count();
        stmt.query_map([], |r| (0..count).map(|i| r.get(i)).collect())
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn terminalization_preserves_decision_history_and_runtime_across_replay_and_restart() {
        for terminal in ["Done", "Cancelled"] {
            for from_board in [true, false] {
                let db = LegacyTestDb::new();
                let mut store = V2Store::open(&db.0).unwrap();
                let mut task = sample_task("SYNTHETIC-1", "Backlog", vec![]);
                task.autonomous_consent = false;
                store.sync_task(&task).unwrap();
                store
                    .open_decision(
                        "stale",
                        &task.task_id,
                        &task.task_group,
                        "failure",
                        "Retry?",
                        &["Retry stage".into()],
                        Some(0),
                        "original failure",
                        None,
                    )
                    .unwrap();
                let mut saved = store.get_task(&task.task_id).unwrap().unwrap();
                saved.active_attempt_id = Some("running".into());
                saved.lease_owner = Some("owner".into());
                saved.lease_expires_epoch = Some(55);
                saved.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
                    attempt_id: "running".into(),
                    operation: "VALIDATE".into(),
                });
                store.upsert_task(&saved).unwrap();
                store.conn.execute_batch("INSERT INTO stage_attempts(attempt_id,task_id,stage,model,effort,started_epoch,status,phase,last_liveness_epoch) VALUES('running','SYNTHETIC-1','impl','synthetic','low',1,'RUNNING','RUNNING',1)").unwrap();
                assert!(
                    store
                        .acquire_path_locks(&task.repository, &["*".into()], &task.task_id)
                        .unwrap()
                );
                let raw_decisions = table_rows(&store, "pending_decisions");
                let raw_attempts = table_rows(&store, "stage_attempts");
                let raw_locks = table_rows(&store, "path_locks");
                assert_eq!(store.sync_task(&task).unwrap().status, "Blocked");
                assert_eq!(store.status_summary().unwrap().open_decisions_count, 1);
                let cursor = store.max_seq_id().unwrap();
                task.status = terminal.into();
                if from_board {
                    store.sync_task(&task).unwrap();
                } else {
                    saved.status = terminal.into();
                    store.transition_task(&saved, None, false, None).unwrap();
                }
                let events = store.list_events_since(None, cursor, 10).unwrap();
                let mut expected = vec![];
                if from_board {
                    expected.push("BOARD_STATUS_OBSERVED");
                }
                expected.extend([
                    if terminal == "Done" {
                        "TASK_DONE"
                    } else {
                        "TASK_STATUS_CHANGED"
                    },
                    "DECISION_RETIRED",
                ]);
                assert_eq!(
                    events
                        .iter()
                        .map(|event| event.event_type.as_str())
                        .collect::<Vec<_>>(),
                    expected
                );
                assert_eq!(
                    events[events.len() - 2].payload["board_status"],
                    if from_board { terminal } else { "Backlog" }
                );
                assert_eq!(store.status_summary().unwrap().open_decisions_count, 0);
                assert!(store.list_decisions(true, None).unwrap().is_empty());
                let history = store.list_decisions(false, None).unwrap().remove(0);
                assert_eq!(history.status, "RETIRED");
                assert_eq!(history.retirement_reason.as_deref(), Some(terminal));
                assert_eq!(history.context_summary, "original failure");
                assert_eq!(history.choice, None);
                assert!(
                    store
                        .open_decision(
                            "late",
                            &task.task_id,
                            &task.task_group,
                            "failure",
                            "Late?",
                            &["Retry stage".into()],
                            None,
                            "",
                            None
                        )
                        .is_err()
                );
                if from_board {
                    store.sync_task(&task).unwrap();
                }
                drop(store);
                let mut store = V2Store::open(&db.0).unwrap();
                store.retire_terminal_decisions().unwrap();
                assert_eq!(store.list_events_since(None, cursor, 10).unwrap(), events);
                let mut reopened = store.get_task(&task.task_id).unwrap().unwrap();
                assert_eq!(reopened.active_attempt_id, saved.active_attempt_id);
                assert_eq!(reopened.lease_owner, saved.lease_owner);
                assert_eq!(reopened.lease_expires_epoch, saved.lease_expires_epoch);
                assert_eq!(
                    reopened.memory.pipeline_checkpoint,
                    saved.memory.pipeline_checkpoint
                );
                reopened.status = "Ready".into();
                store.upsert_task(&reopened).unwrap();
                assert!(matches!(
                    store
                        .resolve_decision("stale", "Retry stage", "actor", None)
                        .unwrap(),
                    DecisionResolution::NotFound
                ));
                assert!(store.list_decisions(true, None).unwrap().is_empty());
                assert_eq!(table_rows(&store, "pending_decisions"), raw_decisions);
                assert_eq!(table_rows(&store, "stage_attempts"), raw_attempts);
                assert_eq!(table_rows(&store, "path_locks"), raw_locks);
                assert_eq!(store.get_decision("stale").unwrap().unwrap(), history);
            }
        }
    }

    #[test]
    fn declined_offline_observation_is_idempotent_and_leaves_empty_row_eligible() {
        let mut store = V2Store::open_in_memory().unwrap();
        let mut input = terminal_input();
        let original = sample_task(&input.task_id, "Backlog", vec![]);
        store.upsert_task(&original).unwrap();
        let raw = raw_task(&store.conn, &input.task_id).unwrap();
        input.current_stage = Some("conflicting".into());
        for _ in 0..2 {
            store
                .sync_task_with_mode(&input, SyncMode::ReconcileFinishedLegacy)
                .unwrap();
            assert_eq!(raw_task(&store.conn, &input.task_id).unwrap(), raw);
            assert_eq!(store.max_seq_id().unwrap(), 1);
        }
        input.current_stage = None;
        let accepted = store
            .sync_task_with_mode(&input, SyncMode::ReconcileFinishedLegacy)
            .unwrap();
        assert_eq!(accepted.status, "Done");
        assert_eq!(store.max_seq_id().unwrap(), 2);
        let mut expected = raw;
        expected.insert("status".into(), "Done".to_owned().into());
        expected.insert("version".into(), accepted.version.into());
        expected.insert("updated_epoch".into(), accepted.updated_epoch.into());
        assert_eq!(raw_task(&store.conn, &input.task_id).unwrap(), expected);
    }

    #[test]
    fn offline_empty_metadata_preserves_raw_rows_events_and_repeats_after_reopen() {
        for terminal in ["Done", "Cancelled"] {
            for status in ["Backlog", "Ready", "In Progress", terminal] {
                for memory in [
                    " { } ",
                    "{ \"halt_requested\": false, \"retry_generation\":0, \"pipeline_checkpoint\":null }",
                ] {
                    let db = LegacyTestDb::new();
                    let mut store = V2Store::open(&db.0).unwrap();
                    let mut t = sample_task("SYNTHETIC-1", status, vec![]);
                    t.autonomous_consent = status == "Ready";
                    store.upsert_task(&t).unwrap();
                    // Native upsert emits Done only on UPDATE, not this initial INSERT.
                    store.conn.execute("UPDATE tasks SET memory_json=?1, context_pack_json=' { } ', stages_completed_json=' [ ] ', depends_on_json=' [ ] '",[memory]).unwrap();
                    let before = raw_task(&store.conn, &t.task_id).unwrap();
                    let export = serde_json::json!({"schema_version":2,"tasks":[{"id":t.task_id,"repository":t.repository,"status":terminal,"executor":"external","reviewed_sha":"canonical-review","context_pack":{"base_sha":"canonical-base"},"stages_completed":["manual-complete"],"branch":"task/planned","worktree":"/predeclared","autonomous_consent":!t.autonomous_consent}]});
                    let incoming = crate::v2::intake::decode_export_records(&export.to_string())
                        .unwrap()
                        .remove(0);
                    let out = store
                        .sync_task_with_mode(&incoming, SyncMode::ReconcileFinishedLegacy)
                        .unwrap();
                    let mut expected = before;
                    expected.insert("status".into(), terminal.to_string().into());
                    if status != terminal {
                        expected.insert("version".into(), out.version.into());
                        expected.insert("updated_epoch".into(), out.updated_epoch.into());
                    }
                    assert_eq!(raw_task(&store.conn, &t.task_id).unwrap(), expected);
                    let events = store.list_task_events(&t.task_id).unwrap();
                    let mut expected_types = vec!["BOARD_STATUS_OBSERVED"];
                    if status != terminal {
                        expected_types.push(if terminal == "Done" {
                            "TASK_DONE"
                        } else {
                            "TASK_STATUS_CHANGED"
                        });
                    }
                    assert_eq!(
                        events
                            .iter()
                            .map(|e| e.event_type.as_str())
                            .collect::<Vec<_>>(),
                        expected_types
                    );
                    for table in [
                        "stage_attempts",
                        "lifecycle_ops",
                        "post_merge_deliveries",
                        "pending_decisions",
                        "merge_queue",
                        "path_locks",
                    ] {
                        assert!(table_rows(&store, table).is_empty());
                    }
                    drop(store);
                    let mut reopened = V2Store::open(&db.0).unwrap();
                    reopened
                        .sync_task_with_mode(&incoming, SyncMode::ReconcileFinishedLegacy)
                        .unwrap();
                    assert_eq!(raw_task(&reopened.conn, &t.task_id).unwrap(), expected);
                    assert_eq!(reopened.list_task_events(&t.task_id).unwrap(), events);
                }
            }
        }
    }

    #[test]
    fn both_offline_admissions_reject_original_json_ambiguities_without_mutation() {
        let memory_invalid = [
            "",
            "{",
            "[]",
            "null",
            "3",
            "true",
            "{\"unknown_native\":null}",
            "{\"halt_requested\":0}",
            "{\"retry_generation\":1.0}",
            "{\"merge_retry_count\":4294967296}",
            "{\"retry_generation\":18446744073709551616}",
            "{\"retry_reset_epoch\":9223372036854775808}",
            "{\"token_usage_by_stage\":{\"impl\":-1}}",
            "{\"applied_decisions\":[0]}",
            "{\"pipeline_checkpoint\":{\"attempt_id\":\"hidden\",\"operation\":\"PUSH\"},\"halt_requested\":0}",
            "{\"pipeline_checkpoint\":{\"attempt_id\":\"hidden\",\"operation\":\"PUSH\",\"future\":true}}",
            "{\"halt_requested\":false,\"halt_requested\":true}",
            "{\"token_usage_by_stage\":{\"impl\":1,\"impl\":2}}",
            "{\"merge_checkpoint\":{}}",
            "{\"suspended_impl_attempt_id\":false}",
        ];
        for finished in [false, true] {
            for (column, invalid) in memory_invalid
                .into_iter()
                .map(|v| ("memory_json", v))
                .chain([
                    ("context_pack_json", "{\"future\":false}"),
                    (
                        "context_pack_json",
                        "{\"target_files\":[{\"path\":\"x\",\"future\":false}]}",
                    ),
                    ("context_pack_json", "{\"target_files\":[{}]}"),
                    (
                        "context_pack_json",
                        "{\"acceptance_criteria\":[{\"id\":\"a\",\"id\":\"b\"}]}",
                    ),
                    (
                        "context_pack_json",
                        "{\"acceptance_criteria\":[{\"id\":\"a\",\"description\":false}]}",
                    ),
                    ("context_pack_json", "null"),
                    ("context_pack_json", "{\"weight\":1}"),
                    ("depends_on_json", "{}"),
                    ("required_stages_json", "[false]"),
                    ("stages_completed_json", "null"),
                    ("stages_completed_json", "[1]"),
                ])
            {
                let mut store = V2Store::open_in_memory().unwrap();
                if finished {
                    finished_fixture(&mut store);
                } else {
                    store
                        .upsert_task(&sample_task("SYNTHETIC-1", "In Progress", vec![]))
                        .unwrap();
                }
                store
                    .conn
                    .execute(&format!("UPDATE tasks SET {column}=?1"), [invalid])
                    .unwrap();
                let before = raw_task(&store.conn, "SYNTHETIC-1").unwrap();
                let queue = table_rows(&store, "merge_queue");
                for _ in 0..2 {
                    let error = store
                        .sync_task_with_mode(&terminal_input(), SyncMode::ReconcileFinishedLegacy)
                        .unwrap_err();
                    assert_eq!(error.0, "ambiguous persisted task JSON");
                    assert_eq!(raw_task(&store.conn, "SYNTHETIC-1").unwrap(), before);
                    assert_eq!(table_rows(&store, "merge_queue"), queue);
                }
            }
        }
    }

    #[test]
    fn finished_offline_changes_only_named_columns_and_memory_marker() {
        let mut store = V2Store::open_in_memory().unwrap();
        let mut old = finished_fixture(&mut store);
        old.retry_count = 7;
        old.memory.applied_decisions = vec!["applied".into()];
        store.upsert_task(&old).unwrap();
        store
            .open_decision(
                "applied",
                &old.task_id,
                "synthetic",
                "test",
                "q",
                &["yes".into()],
                None,
                "ctx",
                None,
            )
            .unwrap();
        store
            .resolve_decision("applied", "yes", "actor", None)
            .unwrap();
        let memory = r#" { "token_usage_by_stage":{"impl":18446744073709551615}, "retry_generation":18446744073709551615, "retry_reset_epoch":-9223372036854775808, "applied_decisions":["applied"],"approved_plan":"line\n\"quoted\"", "last_check_failure":null } "#;
        store.conn.execute("UPDATE tasks SET memory_json=?1, stages_completed_json=' [ \"impl\" ] ',context_pack_json=' { } '",[memory]).unwrap();
        let mut expected = raw_task(&store.conn, &old.task_id).unwrap();
        let mut history = BTreeMap::new();
        for table in [
            "stage_attempts",
            "task_events",
            "pending_decisions",
            "post_merge_deliveries",
            "lifecycle_ops",
            "path_locks",
        ] {
            history.insert(table, table_rows(&store, table));
        }
        let out = store
            .sync_task_with_mode(&terminal_input(), SyncMode::ReconcileFinishedLegacy)
            .unwrap();
        expected.insert("status".into(), "Done".to_string().into());
        expected.insert("active_attempt_id".into(), rusqlite::types::Value::Null);
        expected.insert("version".into(), out.version.into());
        expected.insert("updated_epoch".into(), out.updated_epoch.into());
        let after = raw_task(&store.conn, &old.task_id).unwrap();
        let Some(rusqlite::types::Value::Text(after_memory)) = after.get("memory_json") else {
            panic!("missing memory")
        };
        let mut value: serde_json::Value = serde_json::from_str(after_memory).unwrap();
        assert_eq!(
            value
                .as_object_mut()
                .unwrap()
                .remove("governance_terminal_observed"),
            Some(true.into())
        );
        assert_eq!(
            value,
            serde_json::from_str::<serde_json::Value>(memory).unwrap()
        );
        expected.insert("memory_json".into(), after_memory.clone().into());
        assert_eq!(after, expected);
        for (table, rows) in history {
            let after = table_rows(&store, table);
            if table == "task_events" {
                assert_eq!(after[..rows.len()], rows);
                assert_eq!(
                    after[rows.len()..]
                        .iter()
                        .map(|row| row[4].clone())
                        .collect::<Vec<_>>(),
                    vec![
                        "BOARD_STATUS_OBSERVED".to_owned().into(),
                        "TASK_DONE".to_owned().into()
                    ]
                );
            } else {
                assert_eq!(after, rows, "{table}");
            }
        }
        store
            .sync_task_with_mode(&terminal_input(), SyncMode::ReconcileFinishedLegacy)
            .unwrap();
        assert_eq!(raw_task(&store.conn, &old.task_id).unwrap(), expected);
    }

    #[test]
    fn empty_admission_rejects_each_native_history_table_and_runtime_or_identity_conflict() {
        let inserts = [
            "INSERT INTO stage_attempts(attempt_id,task_id,stage,model,effort,started_epoch,status,phase) VALUES('native','SYNTHETIC-1','impl','synthetic','low',1,'RUNNING','RUNNING')",
            "INSERT INTO lifecycle_ops(operation_id,task_id,kind,args_json,state,created_epoch,updated_epoch) VALUES('ack','SYNTHETIC-1','start','[]','ACKNOWLEDGED',1,1)",
            "INSERT INTO post_merge_deliveries(delivery_id,task_id,repository,github_repo,merge_sha,kind,name,state,workflow,updated_epoch) VALUES('verified','SYNTHETIC-1','zach','owner/repo','sha','test','test','verified','test',1)",
            "INSERT INTO merge_queue(repo,task_id,pr_number,reviewed_sha,enqueued_epoch,state) VALUES('zach','SYNTHETIC-1',1,'sha',1,'FAILED')",
            "INSERT INTO path_locks(repo,path,task_id,acquired_epoch) VALUES('zach','*','SYNTHETIC-1',1)",
            "INSERT INTO task_events(task_id,task_group,ts_epoch,event_type,payload_json) VALUES('SYNTHETIC-1','test',1,'HISTORY','{}')",
        ];
        for sql in inserts {
            let mut store = V2Store::open_in_memory().unwrap();
            store
                .upsert_task(&sample_task("SYNTHETIC-1", "In Progress", vec![]))
                .unwrap();
            store.conn.execute_batch(sql).unwrap();
            let before = raw_task(&store.conn, "SYNTHETIC-1").unwrap();
            let mut tables = BTreeMap::new();
            for t in [
                "stage_attempts",
                "lifecycle_ops",
                "post_merge_deliveries",
                "merge_queue",
                "path_locks",
                "task_events",
            ] {
                tables.insert(t, table_rows(&store, t));
            }
            store
                .sync_task_with_mode(&terminal_input(), SyncMode::ReconcileFinishedLegacy)
                .unwrap();
            assert_eq!(raw_task(&store.conn, "SYNTHETIC-1").unwrap(), before);
            for (t, rows) in tables {
                let after = table_rows(&store, t);
                if t == "task_events" {
                    assert_eq!(after.len(), rows.len() + 1);
                    assert_eq!(after[..rows.len()], rows);
                    assert_eq!(
                        after[rows.len()][4],
                        "BOARD_STATUS_OBSERVED".to_owned().into()
                    );
                } else {
                    assert_eq!(after, rows);
                }
            }
        }
        for finished in [false, true] {
            for case in [
                "github",
                "issue",
                "incoming-stage",
                "incoming-lease-zero",
                "incoming-retry",
                "incoming-generation",
                "incoming-halt",
                "old-lease-zero",
                "old-checkpoint",
                "queue-owner",
            ] {
                let mut store = V2Store::open_in_memory().unwrap();
                if finished {
                    finished_fixture(&mut store);
                } else {
                    store
                        .upsert_task(&sample_task("SYNTHETIC-1", "Ready", vec![]))
                        .unwrap();
                }
                let mut incoming = terminal_input();
                match case {
                    "github" => incoming.github_repo = Some("other/owner".into()),
                    "issue" => incoming.issue_number = Some(2),
                    "incoming-stage" => incoming.current_stage = Some("impl".into()),
                    "incoming-lease-zero" => incoming.lease_expires_epoch = Some(0),
                    "incoming-retry" => incoming.next_retry_epoch = 1,
                    "incoming-generation" => incoming.memory.retry_generation = 1,
                    "incoming-halt" => incoming.memory.halt_requested = true,
                    "old-lease-zero" => {
                        store
                            .conn
                            .execute("UPDATE tasks SET lease_expires_epoch=0", [])
                            .unwrap();
                    }
                    "old-checkpoint" => {
                        store.conn.execute_batch(r#"UPDATE tasks SET memory_json='{"pipeline_checkpoint":{"attempt_id":"native","operation":"PUSH"}}'"#).unwrap();
                    }
                    "queue-owner" => {
                        store.conn.execute_batch("DELETE FROM merge_queue;INSERT INTO merge_queue(repo,task_id,pr_number,reviewed_sha,enqueued_epoch,state) VALUES('another-repository','SYNTHETIC-1',1,'sha',1,'FAILED')").unwrap();
                    }
                    _ => unreachable!(),
                }
                let before = raw_task(&store.conn, "SYNTHETIC-1").unwrap();
                let queue = table_rows(&store, "merge_queue");
                store
                    .sync_task_with_mode(&incoming, SyncMode::ReconcileFinishedLegacy)
                    .unwrap();
                assert_eq!(
                    raw_task(&store.conn, "SYNTHETIC-1").unwrap(),
                    before,
                    "{case}"
                );
                assert_eq!(table_rows(&store, "merge_queue"), queue);
            }
        }
    }

    #[test]
    fn failed_queue_delete_is_transactional_and_queue_only_cleanup_does_not_rewrite_task() {
        let mut store = V2Store::open_in_memory().unwrap();
        finished_fixture(&mut store);
        let before = raw_task(&store.conn, "SYNTHETIC-1").unwrap();
        store.conn.execute_batch("CREATE TRIGGER refuse_delete BEFORE DELETE ON merge_queue BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        assert!(
            store
                .sync_task_with_mode(&terminal_input(), SyncMode::ReconcileFinishedLegacy)
                .is_err()
        );
        assert_eq!(raw_task(&store.conn, "SYNTHETIC-1").unwrap(), before);
        assert_eq!(store.list_merge_queue(None).unwrap().len(), 1);
        store
            .conn
            .execute_batch("DROP TRIGGER refuse_delete")
            .unwrap();
        store
            .sync_task_with_mode(&terminal_input(), SyncMode::ReconcileFinishedLegacy)
            .unwrap();
        let before = raw_task(&store.conn, "SYNTHETIC-1").unwrap();
        store.conn.execute_batch("INSERT INTO merge_queue(repo,task_id,pr_number,reviewed_sha,enqueued_epoch,state) VALUES('zach','SYNTHETIC-1',1,'sha',1,'FAILED')").unwrap();
        store
            .sync_task_with_mode(&terminal_input(), SyncMode::ReconcileFinishedLegacy)
            .unwrap();
        assert_eq!(raw_task(&store.conn, "SYNTHETIC-1").unwrap(), before);
        assert!(store.list_merge_queue(None).unwrap().is_empty());
    }

    #[test]
    fn offline_updates_roll_back_ignored_aborted_and_trigger_modified_rows() {
        for finished in [false, true] {
            for trigger in [
                "BEFORE UPDATE ON tasks BEGIN SELECT RAISE(IGNORE); END",
                "BEFORE UPDATE ON tasks BEGIN SELECT RAISE(ABORT,'synthetic'); END",
                "AFTER UPDATE ON tasks BEGIN UPDATE tasks SET title='unexpected'; END",
                "AFTER UPDATE ON tasks BEGIN UPDATE tasks SET version=version+1; END",
            ] {
                let db = LegacyTestDb::new();
                let mut store = V2Store::open(&db.0).unwrap();
                if finished {
                    finished_fixture(&mut store);
                } else {
                    store
                        .upsert_task(&sample_task("SYNTHETIC-1", "Ready", vec![]))
                        .unwrap();
                }
                let before = raw_task(&store.conn, "SYNTHETIC-1").unwrap();
                let queue = table_rows(&store, "merge_queue");
                store
                    .conn
                    .execute_batch(&format!("CREATE TRIGGER synthetic {trigger};"))
                    .unwrap();
                assert!(
                    store
                        .sync_task_with_mode(&terminal_input(), SyncMode::ReconcileFinishedLegacy)
                        .is_err()
                );
                drop(store);
                let reopened = V2Store::open(&db.0).unwrap();
                assert_eq!(raw_task(&reopened.conn, "SYNTHETIC-1").unwrap(), before);
                assert_eq!(table_rows(&reopened, "merge_queue"), queue);
            }
        }
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
    fn terminal_exports_do_not_retire_an_unverified_linked_delivery_gate() {
        for terminal in ["Done", "Cancelled"] {
            let db = LegacyTestDb::new();
            let mut store = V2Store::open(&db.0).unwrap();
            let task = delivery_task("Pending Prod Promotion");
            let mut row = sample_delivery(&task);
            let id = row.decision_id.clone().unwrap();
            store
                .save_deliveries_and_task(&task, std::slice::from_ref(&row))
                .unwrap();
            let mut incoming = task.clone();
            incoming.status = terminal.into();
            // The persisted link protects the checkpoint before the gate is published.
            assert_eq!(store.sync_task(&incoming).unwrap().status, task.status);
            let original = store
                .open_decision(
                    &id,
                    &task.task_id,
                    &task.task_group,
                    "prod_promotion_approval",
                    "Promote?",
                    &["Approve".into(), "Reject".into()],
                    None,
                    "hold",
                    None,
                )
                .unwrap();
            let unrelated = store
                .open_decision(
                    "newer",
                    &task.task_id,
                    &task.task_group,
                    "failure",
                    "Retry?",
                    &["Retry stage".into()],
                    None,
                    "unrelated",
                    None,
                )
                .unwrap();
            assert!(original.linked_unverified_delivery);
            assert!(!unrelated.linked_unverified_delivery);
            assert!(unrelated.created_seq > original.created_seq);
            let cursor = store.max_seq_id().unwrap();
            drop(store);
            let mut store = V2Store::open(&db.0).unwrap();
            store.retire_terminal_decisions().unwrap();
            for mode in [
                SyncMode::Standard,
                SyncMode::ReconcileFinishedLegacy,
                SyncMode::Standard,
            ] {
                let saved = store.sync_task_with_mode(&incoming, mode).unwrap();
                assert_eq!(saved.status, task.status);
                assert!(!saved.memory.governance_terminal_observed);
                assert_eq!(store.list_deliveries(None).unwrap(), vec![row.clone()]);
                assert_eq!(
                    store.list_decisions(true, None).unwrap(),
                    vec![original.clone(), unrelated.clone()]
                );
                assert_eq!(store.board_statuses(None).unwrap()[&task.task_id], terminal);
                let detail = store.detailed_status(None).unwrap();
                assert_eq!(
                    detail.waiting_tasks[0].open_decision_id.as_deref(),
                    Some(id.as_str())
                );
                assert_eq!(store.max_seq_id().unwrap(), cursor);
            }
            row.state = "verified".into();
            store.upsert_delivery(&row).unwrap();
            assert_eq!(store.sync_task(&incoming).unwrap().status, terminal);
            assert_eq!(store.get_decision(&id).unwrap().unwrap().status, "RETIRED");
            assert!(matches!(
                store
                    .resolve_decision(&id, "Approve", "actor", None)
                    .unwrap(),
                DecisionResolution::NotFound
            ));
            assert_eq!(store.list_deliveries(None).unwrap(), vec![row]);
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
            assert!(
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
                    .is_err()
            );
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

    #[test]
    fn sync_task_blocked_to_ready_resets_retry_count_and_preserves_runtime_memory() {
        let mut store = V2Store::open_in_memory().unwrap();

        // Case 1: zach-owned task in Blocked state re-readied via board sync
        let mut zach_task = sample_task("ZACH-901", "Blocked", vec![]);
        zach_task.executor = Some("zach".into());
        zach_task.retry_count = 3;
        zach_task.next_retry_epoch = 9999;
        zach_task.stages_completed = vec!["plan".into(), "plan-review".into()];
        zach_task.current_stage = Some("impl".into());
        zach_task.reviewed_sha = Some("deadbeef".into());
        zach_task.memory.halt_requested = true;
        zach_task.memory.retry_generation = 2;
        zach_task.memory.fallback_stages = vec!["impl".into()];
        store.upsert_task(&zach_task).unwrap();

        let mut incoming_zach = sample_task("ZACH-901", "Ready", vec![]);
        incoming_zach.executor = Some("zach".into());
        let synced_zach = store
            .sync_task_with_mode(&incoming_zach, SyncMode::Standard)
            .unwrap();
        assert_eq!(synced_zach.status, "Ready");
        assert_eq!(synced_zach.retry_count, 0);
        assert_eq!(synced_zach.next_retry_epoch, 0);
        assert!(!synced_zach.memory.halt_requested);
        assert_eq!(synced_zach.memory.retry_generation, 3);
        assert!(synced_zach.memory.retry_reset_epoch > 0);
        assert_eq!(
            synced_zach.stages_completed,
            vec!["plan".to_owned(), "plan-review".to_owned()]
        );
        assert_eq!(synced_zach.reviewed_sha.as_deref(), Some("deadbeef"));
        assert_eq!(synced_zach.memory.fallback_stages, vec!["impl".to_owned()]);

        // Case 2: non-zach task in Blocked state re-readied via board sync
        let mut ext_task = sample_task("ZACH-902", "Blocked", vec![]);
        ext_task.executor = None;
        ext_task.retry_count = 4;
        ext_task.next_retry_epoch = 8888;
        ext_task.reviewed_sha = Some("cafebabe".into());
        ext_task.memory.halt_requested = true;
        ext_task.memory.retry_generation = 1;
        ext_task.memory.fallback_stages = vec!["plan".into()];
        store.upsert_task(&ext_task).unwrap();

        let mut incoming_ext = sample_task("ZACH-902", "Ready", vec![]);
        incoming_ext.executor = None;
        let synced_ext = store
            .sync_task_with_mode(&incoming_ext, SyncMode::Standard)
            .unwrap();
        assert_eq!(synced_ext.status, "Ready");
        assert_eq!(synced_ext.retry_count, 0);
        assert_eq!(synced_ext.next_retry_epoch, 0);
        assert!(!synced_ext.memory.halt_requested);
        assert_eq!(synced_ext.memory.retry_generation, 2);
        assert!(synced_ext.memory.retry_reset_epoch > 0);
        assert_eq!(synced_ext.reviewed_sha.as_deref(), Some("cafebabe"));
        assert_eq!(synced_ext.memory.fallback_stages, vec!["plan".to_owned()]);
    }

    #[test]
    fn normalize_repo_path_and_paths_overlap_are_segment_aware() {
        assert_eq!(normalize_repo_path(""), "*");
        assert_eq!(normalize_repo_path("."), "*");
        assert_eq!(normalize_repo_path("./"), "*");
        assert_eq!(normalize_repo_path("*"), "*");
        assert_eq!(normalize_repo_path("./src//v2/"), "src/v2");
        assert_eq!(
            normalize_repo_path("././src/v2/store.rs"),
            "src/v2/store.rs"
        );

        assert!(paths_overlap("./src/v2/", "src//v2/store.rs"));
        assert!(paths_overlap("src/v2/store.rs", "src"));
        assert!(paths_overlap("*", "src/v2/store.rs"));
        assert!(paths_overlap(".", "src/v2/store.rs"));
        assert!(!paths_overlap("src", "src2"));
        assert!(!paths_overlap("src/v2/store.rs", "src/v2/scheduler.rs"));
    }

    #[test]
    fn detailed_status_reports_wait_reasons_active_details_and_group_filter() {
        let mut store = V2Store::open_in_memory().unwrap();
        store.set_max_parallel_tasks(3).unwrap();

        let mut active_session = sample_task("ZACH-1", "In Progress", vec![]);
        active_session.repository = "zach".to_owned();
        active_session.task_group = "ZACH".to_owned();
        active_session.executor = Some("session".to_owned());
        active_session.autonomous_consent = false;
        active_session.current_stage = None;
        active_session.context_pack.target_files = vec![TargetFileSpec {
            path: "./src/v2/store.rs".to_owned(),
            ..Default::default()
        }];
        store.upsert_task(&active_session).unwrap();

        let mut done_dep = sample_task("ZACH-0", "Done", vec![]);
        done_dep.task_group = "ZACH".to_owned();
        store.upsert_task(&done_dep).unwrap();

        let mut pending_dep = sample_task("ZACH-DEP", "Backlog", vec![]);
        pending_dep.task_group = "ZACH".to_owned();
        store.upsert_task(&pending_dep).unwrap();

        let mut w_consent = sample_task("ZACH-2", "Ready", vec![]);
        w_consent.task_group = "ZACH".to_owned();
        w_consent.autonomous_consent = false;
        store.upsert_task(&w_consent).unwrap();

        let mut w_decision = sample_task("ZACH-3", "Ready", vec![]);
        w_decision.task_group = "ZACH".to_owned();
        store.upsert_task(&w_decision).unwrap();
        store
            .open_decision(
                "DEC-3",
                "ZACH-3",
                "ZACH",
                "clarification",
                "Need answer",
                &["ok".into()],
                Some(0),
                "context",
                None,
            )
            .unwrap();

        let mut w_lifecycle = sample_task("ZACH-4", "Ready", vec![]);
        w_lifecycle.task_group = "ZACH".to_owned();
        store.upsert_task(&w_lifecycle).unwrap();
        store
            .enqueue_lifecycle(&LifecycleOperation {
                attempt_id: None,
                decision_id: None,
                operation_id: "op-4".to_owned(),
                task_id: "ZACH-4".to_owned(),
                kind: "label_sync".to_owned(),
                args: vec![],
                body_path: None,
                depends_on: None,
                state: "PENDING".to_owned(),
                retry_epoch: 0,
                attempts: 0,
                last_error: None,
            })
            .unwrap();

        let mut w_backoff = sample_task("ZACH-5", "Ready", vec![]);
        w_backoff.task_group = "ZACH".to_owned();
        w_backoff.next_retry_epoch = now_epoch() + 300;
        store.upsert_task(&w_backoff).unwrap();

        let mut w_dep = sample_task("ZACH-6", "Ready", vec!["ZACH-DEP".to_owned()]);
        w_dep.task_group = "ZACH".to_owned();
        store.upsert_task(&w_dep).unwrap();

        let mut w_path_conflict = sample_task("ZACH-7", "Ready", vec!["ZACH-0".to_owned()]);
        w_path_conflict.repository = "zach".to_owned();
        w_path_conflict.task_group = "ZACH".to_owned();
        w_path_conflict.context_pack.target_files = vec![TargetFileSpec {
            path: "src/v2".to_owned(),
            ..Default::default()
        }];
        store.upsert_task(&w_path_conflict).unwrap();

        let mut w_repo_locked = sample_task("ZACH-8", "Ready", vec![]);
        w_repo_locked.repository = "zach".to_owned();
        w_repo_locked.task_group = "ZACH".to_owned();
        store.upsert_task(&w_repo_locked).unwrap();

        let mut w_eligible = sample_task("OTHER-1", "Ready", vec![]);
        w_eligible.repository = "other-repo".to_owned();
        w_eligible.task_group = "OTHER".to_owned();
        store.upsert_task(&w_eligible).unwrap();

        let report = store.detailed_status(None).unwrap();
        assert_eq!(report.active_tasks.len(), 1);
        assert_eq!(report.active_tasks[0].task_id, "ZACH-1");
        assert_eq!(report.active_tasks[0].reservation, "scoped_paths");
        assert!(!report.active_tasks[0].occupies_slot);

        let reasons: BTreeMap<String, String> = report
            .waiting_tasks
            .iter()
            .map(|w| (w.task_id.clone(), w.wait_reason.clone()))
            .collect();
        assert_eq!(reasons["ZACH-2"], "awaiting_consent");
        assert_eq!(reasons["ZACH-3"], "open_decision");
        assert_eq!(reasons["ZACH-4"], "pending_lifecycle");
        assert_eq!(reasons["ZACH-5"], "retry_backoff");
        assert_eq!(reasons["ZACH-6"], "dependency:ZACH-DEP");
        assert_eq!(reasons["ZACH-7"], "path_conflict:ZACH-1:src/v2");
        assert_eq!(reasons["ZACH-8"], "repo_locked:ZACH-1");
        assert_eq!(reasons["OTHER-1"], "eligible");

        let filtered = store.detailed_status(Some("OTHER")).unwrap();
        assert!(filtered.active_tasks.is_empty());
        assert_eq!(filtered.waiting_tasks.len(), 1);
        assert_eq!(filtered.waiting_tasks[0].task_id, "OTHER-1");
        assert!(filtered.open_decisions.is_empty());

        store.set_max_parallel_tasks(1).unwrap();
        let mut native_active = sample_task("NATIVE-1", "In Progress", vec![]);
        native_active.repository = "native-repo".to_owned();
        native_active.task_group = "NATIVE".to_owned();
        native_active.current_stage = Some("impl".to_owned());
        store.upsert_task(&native_active).unwrap();
        assert!(
            store
                .acquire_path_locks("native-repo", &["*".to_owned()], "NATIVE-1")
                .unwrap()
        );
        let no_slots = store.detailed_status(Some("OTHER")).unwrap();
        assert_eq!(no_slots.waiting_tasks[0].wait_reason, "no_free_slots");
        assert!(no_slots.path_locks.is_empty());
        let native_report = store.detailed_status(Some("NATIVE")).unwrap();
        assert_eq!(native_report.path_locks.len(), 1);
        assert_eq!(native_report.path_locks[0].task_id, "NATIVE-1");
    }

    #[test]
    fn sync_task_idle_reset_resets_backlog_ready_and_preserves_blocked_ready_and_active_guards() {
        let mut store = V2Store::open_in_memory().unwrap();

        let make_started = |id: &str, status: &str| {
            let mut t = sample_task(id, status, vec![]);
            t.executor = Some("zach".into());
            t.weight = "M".into();
            t.current_stage = Some("impl".into());
            t.stages_completed = vec!["plan".into(), "plan-review".into()];
            t.memory.governance_started = true;
            t
        };

        let insert_ack_start = |store: &mut V2Store, id: &str| {
            let op_id = format!("start-{id}-v1");
            let op = LifecycleOperation {
                attempt_id: None,
                decision_id: None,
                operation_id: op_id.clone(),
                task_id: id.into(),
                kind: "start".into(),
                args: vec!["start".into(), id.into()],
                body_path: None,
                depends_on: None,
                state: "ACKNOWLEDGED".into(),
                retry_epoch: 0,
                attempts: 1,
                last_error: None,
            };
            store.enqueue_lifecycle(&op).unwrap();
            store
                .connection_mut()
                .execute(
                    "UPDATE lifecycle_ops SET state='ACKNOWLEDGED' WHERE operation_id=?1",
                    [&op_id],
                )
                .unwrap();
        };

        // 1. Idle In Progress -> Backlog: resets status, current_stage, governance_started, releases path_locks, retires start op.
        let t1 = make_started("IDLE-BACKLOG", "In Progress");
        store.upsert_task(&t1).unwrap();
        assert!(
            store
                .acquire_path_locks("zach", &["*".into()], "IDLE-BACKLOG")
                .unwrap()
        );
        insert_ack_start(&mut store, "IDLE-BACKLOG");
        let mut incoming1 = sample_task("IDLE-BACKLOG", "Backlog", vec![]);
        incoming1.executor = Some("zach".into());
        let synced1 = store.sync_task(&incoming1).unwrap();
        assert_eq!(synced1.status, "Backlog");
        assert!(synced1.current_stage.is_none());
        assert!(!synced1.memory.governance_started);
        assert!(
            store
                .lifecycle_ops()
                .unwrap()
                .into_iter()
                .all(|op| op.task_id != "IDLE-BACKLOG")
        );
        assert!(
            store
                .acquire_path_locks("zach", &["*".into()], "OTHER-TASK")
                .unwrap()
        );
        assert_eq!(store.release_path_locks("OTHER-TASK").unwrap(), 1);

        // 2. Idle In Progress -> Ready: resets status, current_stage, governance_started, retires start op.
        let t2 = make_started("IDLE-READY", "In Progress");
        store.upsert_task(&t2).unwrap();
        insert_ack_start(&mut store, "IDLE-READY");
        let mut incoming2 = sample_task("IDLE-READY", "Ready", vec![]);
        incoming2.executor = Some("zach".into());
        let synced2 = store.sync_task(&incoming2).unwrap();
        assert_eq!(synced2.status, "Ready");
        assert!(synced2.current_stage.is_none());
        assert!(!synced2.memory.governance_started);
        assert!(
            store
                .lifecycle_ops()
                .unwrap()
                .into_iter()
                .all(|op| op.task_id != "IDLE-READY")
        );

        // 3. Idle Done -> Ready (without verified delivery): resets governance_started.
        let t3 = make_started("DONE-READY", "Done");
        store.upsert_task(&t3).unwrap();
        let mut incoming3 = sample_task("DONE-READY", "Ready", vec![]);
        incoming3.executor = Some("zach".into());
        let synced3 = store.sync_task(&incoming3).unwrap();
        assert_eq!(synced3.status, "Ready");
        assert!(synced3.current_stage.is_none());
        assert!(!synced3.memory.governance_started);

        // 4. Idle Blocked -> Backlog: resets governance_started and releases path_locks.
        let t4 = make_started("BLOCKED-BACKLOG", "Blocked");
        store.upsert_task(&t4).unwrap();
        assert!(
            store
                .acquire_path_locks("zach", &["*".into()], "BLOCKED-BACKLOG")
                .unwrap()
        );
        let mut incoming4 = sample_task("BLOCKED-BACKLOG", "Backlog", vec![]);
        incoming4.executor = Some("zach".into());
        let synced4 = store.sync_task(&incoming4).unwrap();
        assert_eq!(synced4.status, "Backlog");
        assert!(synced4.current_stage.is_none());
        assert!(!synced4.memory.governance_started);
        assert!(
            store
                .acquire_path_locks("zach", &["*".into()], "OTHER-TASK-2")
                .unwrap()
        );
        assert_eq!(store.release_path_locks("OTHER-TASK-2").unwrap(), 1);

        // 5. Blocked -> Ready recovery: preserves stages_completed, weight, context_pack, and governance_started.
        let mut t5 = make_started("BLOCKED-READY", "Blocked");
        t5.context_pack.weight = "M".into();
        store.upsert_task(&t5).unwrap();
        let mut incoming5 = sample_task("BLOCKED-READY", "Ready", vec![]);
        incoming5.executor = Some("zach".into());
        incoming5.weight = "XS".into();
        let synced5 = store.sync_task(&incoming5).unwrap();
        assert_eq!(synced5.status, "Ready");
        assert_eq!(synced5.weight, "M");
        assert_eq!(synced5.context_pack.weight, "M");
        assert_eq!(synced5.stages_completed, vec!["plan", "plan-review"]);
        assert!(synced5.memory.governance_started);

        // 6. Verified delivery Done -> Ready: preserved.
        let t6 = make_started("VERIFIED-DONE", "Done");
        store.upsert_task(&t6).unwrap();
        store
            .connection_mut()
            .execute(
                "INSERT INTO post_merge_deliveries(delivery_id,task_id,repository,github_repo,merge_sha,kind,name,state,workflow,updated_epoch) VALUES('del-1','VERIFIED-DONE','zach','owner/repo','sha','test','test','verified','test',100)",
                [],
            )
            .unwrap();
        let mut incoming6 = sample_task("VERIFIED-DONE", "Ready", vec![]);
        incoming6.executor = Some("zach".into());
        let synced6 = store.sync_task(&incoming6).unwrap();
        assert_eq!(synced6.status, "Done");
        assert!(synced6.memory.governance_started);

        // 7. OPEN decision task Blocked -> Backlog: preserved.
        let t7 = make_started("OPEN-DEC", "In Progress");
        store.upsert_task(&t7).unwrap();
        store
            .open_decision(
                "DEC-OPEN",
                "OPEN-DEC",
                "zach",
                "plan_approval",
                "Approve?",
                &["approve".into()],
                None,
                "ctx",
                None,
            )
            .unwrap();
        let mut incoming7 = sample_task("OPEN-DEC", "Backlog", vec![]);
        incoming7.executor = Some("zach".into());
        let synced7 = store.sync_task(&incoming7).unwrap();
        assert_eq!(synced7.status, "Blocked");
        assert!(synced7.memory.governance_started);

        // 8. Active attempt In Progress -> Ready: preserved.
        let mut t8 = make_started("ACTIVE-ATT", "In Progress");
        t8.active_attempt_id = Some("att-1".into());
        store.upsert_task(&t8).unwrap();
        let mut incoming8 = sample_task("ACTIVE-ATT", "Ready", vec![]);
        incoming8.executor = Some("zach".into());
        let synced8 = store.sync_task(&incoming8).unwrap();
        assert_eq!(synced8.status, "In Progress");
        assert!(synced8.memory.governance_started);
    }

    #[test]
    fn provider_cooldowns_persist_across_store_reopen_and_clear() {
        let dir = std::env::temp_dir().join(format!(
            "zach-store-cooldown-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("zach.db");
        let future = now_epoch() + 3600;

        {
            let mut store = V2Store::open(&db_path).unwrap();
            store
                .upsert_provider_cooldown("openai-sol", future, "usage limit reached")
                .unwrap();
            store
                .upsert_provider_cooldown("gemini-agy", future + 120, "429 resource exhausted")
                .unwrap();
        }

        {
            let mut reopened = V2Store::open(&db_path).unwrap();
            let now = now_epoch();
            let active = reopened
                .get_active_provider_cooldown("openai-sol", now)
                .unwrap();
            assert!(active.is_some());
            let rec = active.unwrap();
            assert_eq!(rec.family, "openai-sol");
            assert_eq!(rec.until_epoch, future);
            assert_eq!(rec.reason, "usage limit reached");

            let listed = reopened.list_provider_cooldowns(Some(now)).unwrap();
            assert_eq!(listed.len(), 2);
            assert!(
                reopened
                    .get_active_provider_cooldown("openai-sol", future + 1)
                    .unwrap()
                    .is_none()
            );

            assert_eq!(
                reopened
                    .clear_provider_cooldown(Some("openai-sol"))
                    .unwrap(),
                1
            );
            assert_eq!(
                reopened.list_provider_cooldowns(Some(now)).unwrap().len(),
                1
            );
            assert_eq!(reopened.clear_provider_cooldown(None).unwrap(), 1);
            assert!(reopened.list_provider_cooldowns(None).unwrap().is_empty());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn active_attempt_ids_tracks_in_flight_references_excludes_terminal_and_fails_closed() {
        let mut store = V2Store::open_in_memory().unwrap();
        let now = now_epoch();

        // 1. Active/non-terminal task referencing active_attempt_id, pipeline_checkpoint,
        //    suspended_impl_attempt_id, and last_pr_review_evidence_path.
        let mut active_task = sample_task("ZACH-071-ACTIVE", "In Progress", vec![]);
        active_task.active_attempt_id = Some("att-task-active".into());
        active_task.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
            attempt_id: "att-checkpoint".into(),
            operation: "VALIDATE".into(),
        });
        active_task.memory.suspended_impl_attempt_id = Some("att-suspended".into());
        active_task.memory.last_pr_review_evidence_path =
            Some("/var/lib/zach/attempts/att-evidence/stage-evidence.md".into());
        store.upsert_task(&active_task).unwrap();

        // 2. Terminal ("Done") task whose memory still holds old checkpoint/evidence paths:
        //    its historical memory references must NOT protect expired attempt dirs.
        let mut done_task = sample_task("ZACH-071-DONE", "Done", vec![]);
        done_task.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
            attempt_id: "att-done-checkpoint".into(),
            operation: "VALIDATE".into(),
        });
        done_task.memory.last_pr_review_evidence_path =
            Some("/var/lib/zach/attempts/att-done-evidence/stage-evidence.md".into());
        store.upsert_task(&done_task).unwrap();

        // 3. Stage attempts: one non-COMPLETE, one ended_epoch=None, one RUNNING, one COMPLETE.
        let make_attempt =
            |id: &str, task_id: &str, phase: &str, status: &str, ended: Option<i64>| {
                StageAttemptRecord {
                    attempt_id: id.into(),
                    task_id: task_id.into(),
                    stage: "impl".into(),
                    model: "gemini-4-hydrogen-high".into(),
                    effort: "high".into(),
                    systemd_unit: None,
                    invocation_id: None,
                    started_epoch: now - 100,
                    ended_epoch: ended,
                    status: status.into(),
                    failure_class: None,
                    summary: None,
                    input_tokens: None,
                    output_tokens: None,
                    total_tokens: None,
                    sha_before: None,
                    sha_after: None,
                    phase: phase.into(),
                    last_liveness_epoch: now,
                    last_output_bytes: 0,
                    last_cpu_usage_usec: None,
                    control_group: None,
                    exit_code: None,
                    exit_code_kind: None,
                    retry_generation: 0,
                }
            };
        store
            .record_stage_attempt(&make_attempt(
                "att-harvested",
                "ZACH-071-ACTIVE",
                "HARVESTED",
                "PASSED",
                Some(now),
            ))
            .unwrap();
        store
            .record_stage_attempt(&make_attempt(
                "att-no-end",
                "ZACH-071-ACTIVE",
                "COMPLETE",
                "PASSED",
                None,
            ))
            .unwrap();
        store
            .record_stage_attempt(&make_attempt(
                "att-running",
                "ZACH-071-ACTIVE",
                "COMPLETE",
                "RUNNING",
                Some(now),
            ))
            .unwrap();
        store
            .record_stage_attempt(&make_attempt(
                "att-finished",
                "ZACH-071-DONE",
                "COMPLETE",
                "PASSED",
                Some(now - 50),
            ))
            .unwrap();

        // 4. Lifecycle ops: one PENDING (with attempt_id and body_path), one ACKNOWLEDGED.
        store
            .conn
            .execute(
                "INSERT INTO lifecycle_ops(operation_id,task_id,kind,args_json,body_path,state,created_epoch,updated_epoch,attempt_id)
                 VALUES('op-pending','ZACH-071-ACTIVE','stage','[]','/state/attempts/att-op-body/body.md','PENDING',1,1,'att-op-id')",
                [],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO lifecycle_ops(operation_id,task_id,kind,args_json,body_path,state,created_epoch,updated_epoch,attempt_id)
                 VALUES('op-acked','ZACH-071-DONE','stage','[]','/state/attempts/att-acked-body/body.md','ACKNOWLEDGED',1,1,'att-acked-id')",
                [],
            )
            .unwrap();

        let ids = store.active_attempt_ids().unwrap();
        for expected in [
            "att-task-active",
            "att-checkpoint",
            "att-suspended",
            "att-evidence",
            "att-harvested",
            "att-no-end",
            "att-running",
            "att-op-id",
            "att-op-body",
        ] {
            assert!(
                ids.contains(expected),
                "missing expected active id {expected} in {ids:?}"
            );
        }
        for excluded in [
            "att-finished",
            "att-done-checkpoint",
            "att-done-evidence",
            "att-acked-id",
            "att-acked-body",
        ] {
            assert!(
                !ids.contains(excluded),
                "unexpected terminal id {excluded} in {ids:?}"
            );
        }

        // 5. Fail closed when a non-terminal task has corrupt memory_json.
        store
            .conn
            .execute(
                "UPDATE tasks SET memory_json = '{not-valid-json' WHERE task_id = 'ZACH-071-ACTIVE'",
                [],
            )
            .unwrap();
        let err = store.active_attempt_ids().unwrap_err();
        assert!(
            err.0
                .contains("decode task memory_json in active_attempt_ids"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn attempt_audits_migration_and_round_trip_persistence() {
        let db = LegacyTestDb::new();
        let db_path = &db.0;

        // Pre-seed a partial attempt_audits table with an existing row to verify
        // additive migration with SQLite DEFAULT clauses works on non-empty tables.
        {
            let conn = Connection::open(db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE attempt_audits (
                     attempt_id TEXT PRIMARY KEY
                 );
                 INSERT INTO attempt_audits(attempt_id) VALUES('att-legacy-1');",
            )
            .unwrap();
        }

        let mut store = V2Store::open(db_path).expect("migrate partial attempt_audits table");
        let legacy = store
            .get_attempt_audit("att-legacy-1")
            .unwrap()
            .expect("legacy row preserved");
        assert_eq!(legacy.attempt_id, "att-legacy-1");
        assert_eq!(legacy.task_id, "");
        assert_eq!(legacy.stage, "");
        assert_eq!(legacy.turn_count, 0);
        assert!(!legacy.check_divergence);

        let rec = AttemptAuditRecord {
            attempt_id: "att-1".to_owned(),
            task_id: "ZACH-072".to_owned(),
            stage: "impl".to_owned(),
            turn_count: 4,
            tool_call_count: 11,
            tool_error_count: 2,
            edit_compile_fail_loops: 1,
            redundant_read_count: 3,
            cached_input_tokens: Some(420),
            reasoning_tokens: Some(95),
            check_divergence: false,
            error_code: Some("api_key=secret123456 failure".to_owned()),
            created_epoch: 1_700_000_001,
        };
        store.record_attempt_audit(&rec).unwrap();

        let loaded = store.get_attempt_audit("att-1").unwrap().unwrap();
        assert_eq!(loaded.turn_count, 4);
        assert_eq!(loaded.tool_call_count, 11);
        assert_eq!(loaded.tool_error_count, 2);
        assert_eq!(loaded.edit_compile_fail_loops, 1);
        assert_eq!(loaded.redundant_read_count, 3);
        assert_eq!(loaded.cached_input_tokens, Some(420));
        assert_eq!(loaded.reasoning_tokens, Some(95));
        assert!(!loaded.check_divergence);
        assert_eq!(
            loaded.error_code.as_deref(),
            Some("[REDACTED_CREDENTIAL] failure")
        );

        // Marking check_divergence persists even if record_attempt_audit is called again with false.
        store
            .mark_attempt_check_divergence("att-1", "ZACH-072", "impl", Some("semantic"))
            .unwrap();
        store.record_attempt_audit(&rec).unwrap();
        let after_div = store.get_attempt_audit("att-1").unwrap().unwrap();
        assert!(after_div.check_divergence);

        let list = store.list_attempt_audits("ZACH-072").unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].attempt_id, "att-1");
    }

    #[test]
    fn zach_080_startup_guard_accepts_lost_complete_only_for_confirmed_terminal_rows() {
        let mut store = V2Store::open_in_memory().unwrap();
        let mut task = sample_task("GOV-066", "Done", vec![]);
        task.executor = None;
        task.active_attempt_id = None;
        task.memory.governance_terminal_observed = true;
        store.upsert_task(&task).unwrap();
        store
            .conn
            .execute_batch(
                "INSERT INTO stage_attempts(attempt_id,task_id,stage,model,effort,started_epoch,ended_epoch,status,phase) \
                 VALUES('gov-066-plan-lost','GOV-066','plan','gemini-4-hydrogen-high','high',100,200,'LOST','COMPLETE')",
            )
            .unwrap();

        // 1. Confirmed Done with LOST/COMPLETE historical attempt passes as closed history (not native-owned).
        assert_eq!(store.native_startup_owned(&task).unwrap(), false);

        // 2. Confirmed Cancelled with LOST/COMPLETE also passes as closed history.
        task.status = "Cancelled".to_owned();
        store.upsert_task(&task).unwrap();
        assert_eq!(store.native_startup_owned(&task).unwrap(), false);

        // 3. Same row without governance_terminal_observed still fails closed.
        task.status = "Done".to_owned();
        task.memory.governance_terminal_observed = false;
        store.upsert_task(&task).unwrap();
        let err = store.native_startup_owned(&task).unwrap_err();
        assert!(
            err.to_string().contains("ambiguous native startup history"),
            "unexpected error: {err}"
        );

        // 4. Same row in Planning (even with governance_terminal_observed=true) still fails closed.
        task.status = "Planning".to_owned();
        task.memory.governance_terminal_observed = true;
        store.upsert_task(&task).unwrap();
        let err = store.native_startup_owned(&task).unwrap_err();
        assert!(
            err.to_string().contains("ambiguous native startup history"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sync_task_emits_claim_conflict_and_consent_revocation_events() {
        let mut store = V2Store::open_in_memory().unwrap();
        let mut task = sample_task("ZACH-790", "In Progress", vec![]);
        task.status = "In Progress".to_owned();
        task.executor = Some("zach".to_owned());
        task.autonomous_consent = true;
        task.active_attempt_id = Some("att-live-790".to_owned());
        store.upsert_task(&task).unwrap();

        // 1. Foreign executor takeover during active zach attempt emits CLAIM_CONFLICT_OBSERVED + CLAIM_CHANGED
        let mut incoming_conflict = task.clone();
        incoming_conflict.executor = Some("session".to_owned());
        incoming_conflict.active_attempt_id = None;
        let synced = store
            .sync_task_with_mode(&incoming_conflict, SyncMode::Standard)
            .unwrap();
        assert!(!synced.autonomous_consent);
        let events = store.list_events_since(None, 0, 100).unwrap();
        assert!(
            events
                .iter()
                .any(|e| e.event_type == "CLAIM_CONFLICT_OBSERVED" && e.task_id == "ZACH-790"),
            "expected CLAIM_CONFLICT_OBSERVED event, got: {events:?}"
        );
        assert!(
            events.iter().any(|e| {
                e.event_type == "CLAIM_CHANGED"
                    && e.task_group == crate::v2::socket::SESSION_GROUP_NAME
            }),
            "expected CLAIM_CHANGED event on _sessions group, got: {events:?}"
        );

        // 2. External consent revocation (without foreign executor) emits CONSENT_REVOKED_EXTERNALLY
        let mut task2 = sample_task("ZACH-791", "In Progress", vec![]);
        task2.status = "In Progress".to_owned();
        task2.executor = Some("zach".to_owned());
        task2.autonomous_consent = true;
        task2.active_attempt_id = Some("att-live-791".to_owned());
        store.upsert_task(&task2).unwrap();

        let mut incoming_revoke = task2.clone();
        incoming_revoke.autonomous_consent = false;
        incoming_revoke.active_attempt_id = None;
        store
            .sync_task_with_mode(&incoming_revoke, SyncMode::Standard)
            .unwrap();
        let events2 = store.list_events_since(None, 0, 100).unwrap();
        assert!(
            events2
                .iter()
                .any(|e| e.event_type == "CONSENT_REVOKED_EXTERNALLY" && e.task_id == "ZACH-791"),
            "expected CONSENT_REVOKED_EXTERNALLY event, got: {events2:?}"
        );
    }
}
