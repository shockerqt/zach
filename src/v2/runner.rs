use crate::v2::isolation::{
    self, IsolationChecker, NetworkPolicy, PreparedResources, SandboxLayout,
};
use crate::v2::pipeline::DiffFileEntry;
use crate::v2::router::{ModelFamily, StageRoute};
use crate::v2::store::{TaskRecord, V2Store};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub const MAX_SUMMARY_BYTES: usize = 1024;
pub const MAX_RECENT_ATTEMPT_BYTES: usize = 256;
pub const DEFAULT_ATTEMPT_RETENTION_DAYS: u64 = 7;
pub const SYSTEMD_RUNTIME_MAX_GRACE_SECS: u64 = 60;

pub const ALLOWED_ENV_KEYS: &[&str] = &[
    "HOME",
    "USER",
    "PATH",
    "LANG",
    "XDG_RUNTIME_DIR",
    "CODEX_HOME",
];

pub const GEMINI_WORKER_CLI_SCRIPT: &str =
    "/home/ubuntu/workspace/agent-tooling/plugins/gemini-worker/scripts/worker.mjs";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageCommandSpec {
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub writable: bool,
    pub unit_name: String,
    pub program: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub worktree_path: String,
    pub timeout_secs: u64,
    pub stall_timeout_secs: u64,
    #[serde(default)]
    pub prompt: String,
    #[serde(default)]
    pub stdin_payload: String,
    #[serde(default)]
    pub output_schema_json: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StageExecutionResult {
    pub status: String,
    pub summary: String,
    pub review_markdown: Option<String>,
    #[serde(default)]
    pub review_output: Option<String>,
    #[serde(default)]
    pub stage_output: Option<String>,
    pub invocation_id: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    #[serde(default)]
    pub duration_seconds: Option<f64>,
    pub sha_before: Option<String>,
    pub sha_after: Option<String>,
    pub diff_files: Vec<DiffFileEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineRange {
    pub start: usize,
    pub end: usize,
}

impl LineRange {
    pub fn contains(&self, line: usize) -> bool {
        line >= self.start && line <= self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReviewedDiffContext {
    pub merge_base_sha: String,
    pub reviewed_sha: String,
    pub commit_range: String,
    pub files: BTreeMap<String, Vec<LineRange>>,
    #[serde(default)]
    pub diff_excerpt: String,
}

/// ADR-004 / ADR-014 content-safe token usage counters for `StageReceipt` v1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StageReceiptTokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
}

/// Canonical ADR-004 / ADR-014 `StageReceipt` v1 matching `governance/contracts/stage-contract.yaml`.
/// Strictly contains operational metadata and numeric counters only (never prompts, responses,
/// transcripts, raw stdout/stderr, or credentials).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StageReceiptV1 {
    pub schema_version: u32,
    pub task_id: String,
    pub stage: String,
    pub actor: String,
    pub executor: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_error_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_usage: Option<StageReceiptTokenUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
}

pub fn build_stage_receipt_v1(
    task_id: &str,
    attempt_id: &str,
    route: &StageRoute,
    result: &StageExecutionResult,
    failure_class: Option<&str>,
) -> StageReceiptV1 {
    let driver = worker_driver(route.family);
    let status = if result.status == "PASSED" {
        "completed"
    } else if result.status == "BLOCKED" {
        "blocked"
    } else {
        "failed"
    };
    let token_usage = match (result.input_tokens, result.output_tokens) {
        (Some(input_tokens), Some(output_tokens)) => Some(StageReceiptTokenUsage {
            input_tokens,
            output_tokens,
            total_tokens: Some(
                result
                    .total_tokens
                    .unwrap_or_else(|| input_tokens.saturating_add(output_tokens)),
            ),
        }),
        _ => None,
    };
    let duration_secs = result
        .duration_seconds
        .filter(|d| d.is_finite() && *d >= 0.0)
        .map(|d| d.round() as u64);
    StageReceiptV1 {
        schema_version: 1,
        task_id: task_id.to_owned(),
        stage: route.stage.clone(),
        actor: driver.actor().to_owned(),
        executor: "zach".to_owned(),
        status: status.to_owned(),
        attempt_id: Some(attempt_id.to_owned()),
        harness: Some(driver.harness().to_owned()),
        model: (!route.model.trim().is_empty()).then(|| route.model.clone()),
        effort: Some(route.effort.as_str().to_owned()),
        failure_class: failure_class
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| truncate_utf8_bytes(s, 128)),
        duration_secs,
        retry_count: None,
        tool_error_count: None,
        sha_before: result.sha_before.clone(),
        sha_after: result.sha_after.clone(),
        token_usage,
        generated_at: Some(format!("{}", crate::v2::now_epoch())),
    }
}

pub fn write_stage_receipt_json(
    attempt_dir: &std::path::Path,
    receipt: &StageReceiptV1,
) -> Result<PathBuf, String> {
    let path = attempt_dir.join("stage-receipt.json");
    let bytes = serde_json::to_vec_pretty(receipt)
        .map_err(|e| format!("failed to serialize stage-receipt.json: {e}"))?;
    write_secure_file(&path, &bytes)?;
    Ok(path)
}

/// Decouples harness-specific CLI invocation, JSON schema attachment, and output/token
/// parsing from the `systemd-run` + `bwrap` stage supervisor (`ADR-014`).
pub trait WorkerDriver: Send + Sync {
    fn harness(&self) -> &'static str;
    fn actor(&self) -> &'static str;
    fn build_worker_invocation(
        &self,
        task: &TaskRecord,
        route: &StageRoute,
        worktree_path: &str,
        prompt: &str,
    ) -> Result<(Vec<String>, String), String>;
    fn attach_output_schema(&self, args: &[String], schema_path: &std::path::Path) -> Vec<String>;
    fn parse_output(
        &self,
        stdout: &str,
        stderr: &str,
        exit_code: Option<i32>,
        is_systemd_timeout: bool,
    ) -> Result<StageExecutionResult, String>;
}

pub struct OpenAiSolDriver;

impl WorkerDriver for OpenAiSolDriver {
    fn harness(&self) -> &'static str {
        "codex"
    }

    fn actor(&self) -> &'static str {
        "codex"
    }

    fn build_worker_invocation(
        &self,
        _task: &TaskRecord,
        route: &StageRoute,
        worktree_path: &str,
        prompt: &str,
    ) -> Result<(Vec<String>, String), String> {
        let args = vec![
            "codex".to_owned(),
            "exec".to_owned(),
            "--ignore-user-config".to_owned(),
            "-m".to_owned(),
            route.model.clone(),
            "-c".to_owned(),
            format!("model_reasoning_effort={}", route.effort.as_str()),
            "--dangerously-bypass-approvals-and-sandbox".to_owned(),
            "-C".to_owned(),
            worktree_path.to_owned(),
            "--json".to_owned(),
            "-".to_owned(),
        ];
        Ok((args, prompt.to_owned()))
    }

    fn attach_output_schema(&self, args: &[String], schema_path: &std::path::Path) -> Vec<String> {
        inject_codex_output_schema_args(args, schema_path)
    }

    fn parse_output(
        &self,
        stdout: &str,
        stderr: &str,
        exit_code: Option<i32>,
        _is_systemd_timeout: bool,
    ) -> Result<StageExecutionResult, String> {
        let p = parse_codex_jsonl_output(stdout, stderr, exit_code)?;
        Ok(StageExecutionResult {
            status: p.status,
            summary: p.summary,
            review_markdown: p.review_markdown,
            review_output: p.review_output.clone(),
            stage_output: p.review_output,
            invocation_id: None,
            input_tokens: p.input_tokens,
            output_tokens: p.output_tokens,
            total_tokens: p.total_tokens,
            duration_seconds: None,
            sha_before: None,
            sha_after: None,
            diff_files: Vec::new(),
        })
    }
}

pub struct GeminiAgyDriver;

impl WorkerDriver for GeminiAgyDriver {
    fn harness(&self) -> &'static str {
        "agy"
    }

    fn actor(&self) -> &'static str {
        "antigravity"
    }

    fn build_worker_invocation(
        &self,
        task: &TaskRecord,
        route: &StageRoute,
        _worktree_path: &str,
        prompt: &str,
    ) -> Result<(Vec<String>, String), String> {
        let args = vec![
            "node".to_owned(),
            GEMINI_WORKER_CLI_SCRIPT.to_owned(),
            "--cli".to_owned(),
        ];
        let payload = crate::v2::pipeline::build_agy_cli_payload(task, route, prompt);
        let stdin_payload = serde_json::to_string(&payload)
            .map_err(|e| format!("failed to serialize agy cli payload: {e}"))?;
        Ok((args, stdin_payload))
    }

    fn attach_output_schema(&self, args: &[String], schema_path: &std::path::Path) -> Vec<String> {
        inject_agy_json_schema_args(args, schema_path)
    }

    fn parse_output(
        &self,
        stdout: &str,
        stderr: &str,
        exit_code: Option<i32>,
        is_systemd_timeout: bool,
    ) -> Result<StageExecutionResult, String> {
        match crate::v2::pipeline::parse_agy_cli_response(stdout, stderr, exit_code) {
            Ok(res) => Ok(res),
            Err(mut agy_err) => {
                if is_systemd_timeout && agy_err.failure_class == "AGY_EXIT" {
                    agy_err.failure_class = "AGY_TIMEOUT".to_owned();
                }
                if agy_err.input_tokens.is_some()
                    || agy_err.output_tokens.is_some()
                    || agy_err.total_tokens.is_some()
                    || agy_err.duration_seconds.is_some()
                {
                    Ok(StageExecutionResult {
                        status: "FAILED".to_owned(),
                        summary: truncate_utf8_bytes(&agy_err.to_string(), MAX_SUMMARY_BYTES),
                        review_markdown: None,
                        review_output: None,
                        stage_output: None,
                        invocation_id: None,
                        input_tokens: agy_err.input_tokens,
                        output_tokens: agy_err.output_tokens,
                        total_tokens: agy_err.total_tokens,
                        duration_seconds: agy_err.duration_seconds,
                        sha_before: None,
                        sha_after: None,
                        diff_files: Vec::new(),
                    })
                } else {
                    Err(agy_err.to_string())
                }
            }
        }
    }
}

pub fn worker_driver(family: ModelFamily) -> Box<dyn WorkerDriver> {
    match family {
        ModelFamily::OpenAiSol => Box::new(OpenAiSolDriver),
        ModelFamily::GeminiAgy => Box::new(GeminiAgyDriver),
    }
}

pub fn inject_agy_json_schema_args(args: &[String], schema_path: &std::path::Path) -> Vec<String> {
    if args.iter().any(|a| a == "--json-schema") {
        return args.to_vec();
    }
    let Some(cli_idx) = args.iter().position(|a| a == "--cli") else {
        return args.to_vec();
    };
    let mut updated = Vec::with_capacity(args.len() + 2);
    updated.extend_from_slice(&args[..=cli_idx]);
    updated.push("--json-schema".to_owned());
    updated.push(schema_path.to_string_lossy().into_owned());
    updated.extend_from_slice(&args[cli_idx + 1..]);
    updated
}

pub trait StageExecutor {
    fn persist_plan_artifact(
        &mut self,
        _task: &TaskRecord,
        _artifact_id: &str,
        _markdown: &str,
    ) -> Result<PathBuf, String> {
        Err("plan artifact persistence is unsupported by this executor".to_owned())
    }

    fn read_plan_artifact(&self, _path: &std::path::Path) -> Result<String, String> {
        Err("plan artifact reading is unsupported by this executor".to_owned())
    }

    fn publish_plan_stage(
        &mut self,
        _task: &TaskRecord,
        _plan_artifact_path: &std::path::Path,
        _plan_markdown: &str,
    ) -> Result<(), String> {
        Err("plan publication is unsupported by this executor".to_owned())
    }

    fn execute_stage(
        &mut self,
        task: &TaskRecord,
        attempt_id: &str,
        route: &StageRoute,
        spec: &StageCommandSpec,
    ) -> Result<StageExecutionResult, String>;

    fn run_checks(&mut self, worktree_path: &str, commands: &[String]) -> Result<(), String>;

    fn run_gate_checks(&mut self, worktree_path: &str, commands: &[String]) -> Result<(), String> {
        self.run_checks(worktree_path, commands)
    }

    fn commit_worktree(&mut self, task: &TaskRecord, worktree_path: &str)
    -> Result<String, String>;

    fn push_and_ensure_pr(
        &mut self,
        task: &TaskRecord,
        worktree_path: &str,
        reviewed_sha: &str,
    ) -> Result<i64, String>;

    fn collect_reviewed_diff(
        &mut self,
        task: &TaskRecord,
        worktree_path: &str,
        reviewed_sha: &str,
    ) -> Result<ReviewedDiffContext, String>;
}

/// Builds a strict allowlisted environment map for worker execution, explicitly
/// stripping `GH_TOKEN`, `GITHUB_TOKEN`, and any `*_TOKEN` / `*_SECRET` / `*_KEY`.
pub fn build_clean_env(base_env: &[(String, String)]) -> BTreeMap<String, String> {
    let mut clean = BTreeMap::new();
    for (raw_key, val) in base_env {
        let key = raw_key.trim();
        let upper = key.to_ascii_uppercase();
        if upper == "GH_TOKEN"
            || upper == "GITHUB_TOKEN"
            || upper.ends_with("_TOKEN")
            || upper.ends_with("_SECRET")
            || upper.ends_with("_KEY")
            || upper.starts_with("AWS_")
            || upper.starts_with("BITBUCKET_")
            || upper.starts_with("PLANE_")
        {
            continue;
        }
        if ALLOWED_ENV_KEYS.contains(&key) && !val.trim().is_empty() {
            clean.insert(key.to_owned(), val.clone());
        }
    }
    clean
        .entry("HOME".to_owned())
        .or_insert_with(|| "/home/ubuntu".to_owned());
    clean
        .entry("LANG".to_owned())
        .or_insert_with(|| "C.UTF-8".to_owned());
    clean.entry("PATH".to_owned()).or_insert_with(|| {
        "/home/ubuntu/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            .to_owned()
    });
    clean
}

pub fn build_clean_env_from_process() -> BTreeMap<String, String> {
    let pairs: Vec<(String, String)> = env::vars().collect();
    build_clean_env(&pairs)
}

fn sanitize_unit_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "x".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Checks whether a task has remaining token budget under `route.max_task_tokens`.
pub fn check_token_budget(task: &TaskRecord, route: &StageRoute) -> Result<u64, String> {
    let used: u64 = task.memory.token_usage_by_stage.values().copied().sum();
    if used >= route.max_task_tokens {
        return Err(format!(
            "token budget exhausted for task {}: used {} >= max {} tokens",
            task.task_id, used, route.max_task_tokens
        ));
    }
    Ok(route.max_task_tokens - used)
}

/// Builds a transient `systemd-run --user` command specification with cgroup resource
/// limits and a declarative bubblewrap namespace wrapper. Runtime filesystem
/// discovery and resource staging happen only in execute_stage.
pub fn build_systemd_stage_command(
    task: &TaskRecord,
    attempt_id: &str,
    route: &StageRoute,
    prompt: &str,
) -> Result<StageCommandSpec, String> {
    build_systemd_stage_command_with_env(
        task,
        attempt_id,
        route,
        prompt,
        &build_clean_env_from_process(),
    )
}

pub fn build_systemd_stage_command_with_env(
    task: &TaskRecord,
    attempt_id: &str,
    route: &StageRoute,
    prompt: &str,
    clean_env: &BTreeMap<String, String>,
) -> Result<StageCommandSpec, String> {
    if route.model.trim().is_empty() {
        return Err("refusing to build stage command with empty model".to_owned());
    }
    if !task.autonomous_consent {
        return Err(format!(
            "task {} does not have autonomous_consent enabled",
            task.task_id
        ));
    }
    let worktree_path = task
        .worktree_path
        .as_deref()
        .map(str::trim)
        .filter(|w| !w.is_empty() && *w != "none")
        .ok_or_else(|| format!("task {} has no governed worktree_path", task.task_id))?
        .to_owned();

    let unit_name = format!(
        "zach-stage-{}-{}-{}",
        sanitize_unit_component(&task.task_id),
        sanitize_unit_component(&route.stage),
        sanitize_unit_component(attempt_id)
    );

    let network = NetworkPolicy::resolve(task.context_pack.network.as_deref(), route.family)?;
    let writable = route.stage == "impl";
    let home = clean_env
        .get("HOME")
        .cloned()
        .unwrap_or_else(|| "/home/ubuntu".to_owned());

    let mut args = vec![
        "--user".to_owned(),
        "--no-block".to_owned(),
        "--service-type=exec".to_owned(),
        "-p".to_owned(),
        "RemainAfterExit=yes".to_owned(),
        "-p".to_owned(),
        "CollectMode=inactive".to_owned(),
        format!("--unit={unit_name}.service"),
        "--slice=zach-workers.slice".to_owned(),
        "-p".to_owned(),
        format!(
            "RuntimeMaxSec={}",
            route
                .timeout_secs
                .saturating_add(SYSTEMD_RUNTIME_MAX_GRACE_SECS)
        ),
        "-p".to_owned(),
        "MemoryMax=4G".to_owned(),
        "-p".to_owned(),
        "CPUWeight=20".to_owned(),
        "-p".to_owned(),
        "TasksMax=512".to_owned(),
        "-p".to_owned(),
        "KillMode=control-group".to_owned(),
        "-p".to_owned(),
        "TimeoutStopSec=20".to_owned(),
        format!("--working-directory={worktree_path}"),
    ];

    for (k, v) in clean_env {
        args.push(format!("--setenv={k}={v}"));
    }

    args.push("--".to_owned());

    let driver = worker_driver(route.family);
    let (worker_args, stdin_payload) =
        driver.build_worker_invocation(task, route, &worktree_path, prompt)?;
    args.extend(worker_args);

    let output_schema_json = (matches!(route.stage.as_str(), "plan-review" | "pr-review"))
        .then(crate::v2::pipeline::review_verdict_json_schema_string);

    let worker_start = args
        .iter()
        .position(|a| a == "--")
        .ok_or("missing worker separator")?
        + 1;
    let worker = args.split_off(worker_start);
    let declared = SandboxLayout::declared(
        std::path::Path::new(&home),
        std::path::Path::new(&worktree_path),
        writable,
    );
    args.extend(isolation::bwrap_args(&declared, &worker));

    Ok(StageCommandSpec {
        network,
        writable,
        unit_name,
        program: "systemd-run".to_owned(),
        args,
        env: clean_env.clone(),
        worktree_path,
        timeout_secs: route.timeout_secs,
        stall_timeout_secs: route.stall_timeout_secs,
        prompt: prompt.to_owned(),
        stdin_payload,
        output_schema_json,
    })
}

fn replace_sandbox_args(args: &[String], layout: &SandboxLayout) -> Result<Vec<String>, String> {
    let outer = args
        .iter()
        .position(|a| a == "--")
        .ok_or("missing supervisor separator")?;
    let bwrap = outer + 1;
    if args.get(bwrap).map(String::as_str) != Some("/usr/bin/bwrap") {
        return Err("missing bubblewrap wrapper".into());
    }
    let worker_start = args[bwrap..]
        .iter()
        .position(|a| a == "--")
        .ok_or("missing sandbox separator")?
        + bwrap
        + 1;
    let mut out = args[..=outer].to_vec();
    out.extend(isolation::bwrap_args(layout, &args[worker_start..]));
    Ok(out)
}

fn validate_stage_isolation_spec(
    task: &TaskRecord,
    route: &StageRoute,
    spec: &StageCommandSpec,
) -> Result<(), String> {
    if spec.program != "systemd-run" {
        return Err("invalid worker supervisor".into());
    }
    let network = NetworkPolicy::resolve(task.context_pack.network.as_deref(), route.family)?;
    if network != spec.network || spec.writable != (route.stage == "impl") {
        return Err("stage isolation declaration mismatch".into());
    }
    let home = spec
        .env
        .get("HOME")
        .map(String::as_str)
        .unwrap_or("/home/ubuntu");
    let declared = SandboxLayout::declared(
        std::path::Path::new(home),
        std::path::Path::new(&spec.worktree_path),
        spec.writable,
    );
    // Reuse the pure replacement path to prove wrapper position before staging.
    replace_sandbox_args(&spec.args, &declared).map(|_| ())
}

/// Inserts `--output-schema <schema_path>` before the trailing positional prompt/`"-"`
/// argument of a `codex exec` invocation.
pub fn inject_codex_output_schema_args(
    args: &[String],
    schema_path: &std::path::Path,
) -> Vec<String> {
    let Some(codex_idx) = args.iter().position(|a| a == "codex") else {
        return args.to_vec();
    };
    let Some(rel_exec) = args[codex_idx + 1..].iter().position(|a| a == "exec") else {
        return args.to_vec();
    };
    let exec_idx = codex_idx + 1 + rel_exec;
    let last_idx = args.len().saturating_sub(1);
    if last_idx <= exec_idx {
        return args.to_vec();
    }
    let mut updated = Vec::with_capacity(args.len() + 2);
    updated.extend_from_slice(&args[..last_idx]);
    updated.push("--output-schema".to_owned());
    updated.push(schema_path.to_string_lossy().into_owned());
    updated.push(args[last_idx].clone());
    updated
}

/// Parses `systemctl --user list-units 'zach-stage-*' --no-legend --plain` output
/// and returns unit names (without `.service` suffix) that are not in `active_units`.
pub fn parse_orphan_units(systemctl_output: &str, active_units: &BTreeSet<String>) -> Vec<String> {
    let mut orphans = Vec::new();
    for line in systemctl_output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some(first_token) = trimmed.split_whitespace().next() else {
            continue;
        };
        let normalized = first_token.strip_suffix(".service").unwrap_or(first_token);
        if !normalized.starts_with("zach-stage-") {
            continue;
        }
        if !active_units.contains(normalized) && !active_units.contains(first_token) {
            orphans.push(normalized.to_owned());
        }
    }
    orphans.sort();
    orphans.dedup();
    orphans
}

/// Reconciles running `stage_attempts` in SQLite against live `zach-stage-*` user units.
pub fn reconcile_orphan_units(store: &mut V2Store) -> Result<Vec<String>, String> {
    let mut active_units = BTreeSet::new();
    {
        let conn = store.connection_mut();
        let mut stmt = conn
            .prepare(
                "SELECT systemd_unit FROM stage_attempts
                 WHERE status = 'RUNNING' AND systemd_unit IS NOT NULL",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        for r in rows {
            let unit = r.map_err(|e| e.to_string())?;
            active_units.insert(unit.strip_suffix(".service").unwrap_or(&unit).to_owned());
        }
    }

    let output = Command::new("systemctl")
        .args([
            "--user",
            "list-units",
            "zach-stage-*",
            "--no-legend",
            "--plain",
        ])
        .output();

    let Ok(out) = output else {
        return Ok(Vec::new());
    };
    if !out.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let orphans = parse_orphan_units(&stdout, &active_units);
    for unit in &orphans {
        let _ = Command::new("systemctl")
            .args(["--user", "stop", unit])
            .output();
    }

    // Also mark any RUNNING attempt whose unit is no longer present in systemctl output as LOST
    let live_units: BTreeSet<String> = stdout
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(|u| u.strip_suffix(".service").unwrap_or(u).to_owned())
        .collect();

    let conn = store.connection_mut();
    for unit in &active_units {
        if !live_units.contains(unit) {
            let _ = conn.execute(
                "UPDATE stage_attempts
                 SET status = 'LOST', failure_class = 'ORPHAN_LOST'
                 WHERE systemd_unit = ?1 AND status = 'RUNNING'",
                params![unit],
            );
        }
    }

    Ok(orphans)
}

/// Truncates `input` so its UTF-8 byte length is `<= max_bytes` without splitting
/// a multi-byte UTF-8 character. Appends `"..."` when `max_bytes >= 3`.
pub fn truncate_utf8_bytes(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_owned();
    }
    if max_bytes < 3 {
        let mut end = max_bytes;
        while end > 0 && !input.is_char_boundary(end) {
            end -= 1;
        }
        return input[..end].to_owned();
    }
    let mut end = max_bytes - 3;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &input[..end])
}

/// Returns attempt directory retention from `ZACH_ATTEMPT_RETENTION_DAYS`
/// (defaults to `DEFAULT_ATTEMPT_RETENTION_DAYS` = 7 days).
pub fn attempt_retention_from_env() -> std::time::Duration {
    let days = env::var("ZACH_ATTEMPT_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_ATTEMPT_RETENTION_DAYS);
    std::time::Duration::from_secs(days.saturating_mul(86_400))
}

/// Prunes `<state_dir>/attempts/<attempt_id>` directories older than `retention`
/// that are not in `active_attempt_ids`.
pub fn prune_old_attempts(
    state_dir: &std::path::Path,
    retention: std::time::Duration,
    active_attempt_ids: &BTreeSet<String>,
) -> Result<usize, String> {
    prune_old_attempts_at(
        state_dir,
        retention,
        std::time::SystemTime::now(),
        active_attempt_ids,
    )
}

/// Prunes `<state_dir>/attempts/<attempt_id>` directories older than `retention`
/// relative to `now`, skipping any directory in `active_attempt_ids`, symlinks,
/// and non-directories without following links.
pub fn prune_old_attempts_at(
    state_dir: &std::path::Path,
    retention: std::time::Duration,
    now: std::time::SystemTime,
    active_attempt_ids: &BTreeSet<String>,
) -> Result<usize, String> {
    let attempts_root = state_dir.join("attempts");
    let root_meta = match std::fs::symlink_metadata(&attempts_root) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(format!("failed to stat {}: {e}", attempts_root.display())),
    };
    if root_meta.file_type().is_symlink() || !root_meta.file_type().is_dir() {
        return Err(format!(
            "attempts root {} is not a real directory",
            attempts_root.display()
        ));
    }

    let cutoff = now.checked_sub(retention).unwrap_or(std::time::UNIX_EPOCH);
    let entries = std::fs::read_dir(&attempts_root)
        .map_err(|e| format!("failed to read {}: {e}", attempts_root.display()))?;

    let mut pruned = 0usize;
    for entry_res in entries {
        let Ok(entry) = entry_res else {
            continue;
        };
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() || !ft.is_dir() {
            continue;
        }
        let path = entry.path();
        let Some(attempt_id) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if active_attempt_ids.contains(attempt_id) {
            continue;
        }
        let Ok(dir_meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if dir_meta.file_type().is_symlink() || !dir_meta.file_type().is_dir() {
            continue;
        }
        let Ok(modified) = dir_meta.modified() else {
            continue;
        };
        if modified < cutoff && std::fs::remove_dir_all(&path).is_ok() {
            pruned += 1;
        }
    }
    Ok(pruned)
}

pub(crate) fn validate_attempt_id(attempt_id: &str) -> Result<&str, String> {
    if attempt_id.is_empty()
        || attempt_id == "."
        || attempt_id == ".."
        || attempt_id.contains(['/', '\\', '\0'])
        || attempt_id.trim() != attempt_id
    {
        return Err(format!("invalid attempt_id '{attempt_id}'"));
    }
    Ok(attempt_id)
}

pub(crate) fn ensure_secure_dir(dir: &std::path::Path) -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    if let Some(parent) = dir.parent() {
        isolation::reject_symlink_components(parent)?;
    }
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(format!("refusing symlink directory {}", dir.display()));
            }
            if !meta.file_type().is_dir() {
                return Err(format!("expected directory at {}", dir.display()));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(dir)
                .map_err(|err| format!("failed to create directory {}: {err}", dir.display()))?;
        }
        Err(e) => {
            return Err(format!("failed to stat directory {}: {e}", dir.display()));
        }
    }
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .and_then(|file| file.set_permissions(std::fs::Permissions::from_mode(0o700)))
        .map_err(|e| format!("failed to secure directory {}: {e}", dir.display()))?;
    Ok(dir.to_path_buf())
}

pub(crate) fn write_secure_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if let Some(parent) = path.parent() {
        isolation::reject_symlink_components(parent)?;
    }
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(format!("refusing to write to symlink {}", path.display()));
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("failed to open {}: {e}", path.display()))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("artifact is not a regular file".to_owned());
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("failed to chmod 0600 {}: {e}", path.display()))?;
    file.write_all(bytes)
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    file.sync_all()
        .map_err(|e| format!("failed to flush {}: {e}", path.display()))?;
    Ok(())
}

fn path_io_err(op: &str, path: &std::path::Path, err: impl std::fmt::Display) -> String {
    format!("{op} {}: {err}", path.display())
}

fn spawn_output_ctx(cmd: &mut Command, label: &str) -> Result<std::process::Output, String> {
    cmd.output().map_err(|e| format!("spawning {label}: {e}"))
}

pub(crate) fn write_supervisor_error_log(
    attempt_dir: &std::path::Path,
    stage: Option<&str>,
    key: Option<&str>,
    error: &str,
) {
    let ts = crate::v2::now_epoch();
    let content = format!(
        "timestamp={ts}\nstage={}\nkey={}\nerror={error}\n",
        stage.unwrap_or("unknown"),
        key.unwrap_or("none"),
    );
    let _ = write_secure_file(
        &attempt_dir.join("supervisor-error.log"),
        content.as_bytes(),
    );
}

#[derive(Debug, Clone)]
pub struct SystemdStageExecutor {
    pub state_dir: PathBuf,
    pub ws_task_bin: PathBuf,
    pub isolation_checker: IsolationChecker,
    #[cfg(test)]
    fixture_transport: bool,
}

impl Default for SystemdStageExecutor {
    fn default() -> Self {
        Self {
            state_dir: crate::v2::default_state_dir(),
            ws_task_bin: crate::v2::default_ws_task_bin(),
            isolation_checker: isolation::verify_host_isolation,
            #[cfg(test)]
            fixture_transport: false,
        }
    }
}

impl SystemdStageExecutor {
    pub fn with_isolation_checker(mut self, checker: IsolationChecker) -> Self {
        self.isolation_checker = checker;
        self
    }

    fn check_isolation(&self) -> Result<(), String> {
        (self.isolation_checker)()
            .map_err(|_| "ISOLATION_PREFLIGHT_FAILED: worker dispatch stopped".to_owned())
    }

    pub fn with_state_dir(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
            ws_task_bin: crate::v2::default_ws_task_bin(),
            isolation_checker: isolation::verify_host_isolation,
            #[cfg(test)]
            fixture_transport: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCodexOutput {
    pub status: String,
    pub summary: String,
    pub review_markdown: Option<String>,
    pub review_output: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

/// Parses `codex exec --json` JSONL events (`ThreadEvent` lines), summing token
/// usage across `turn.completed` events and extracting the final `agent_message`
/// or `turn.failed` / `error` summary. Returns `None` token fields when no valid
/// `turn.completed` usage event is observed.
pub fn parse_codex_jsonl_output(
    stdout: &str,
    stderr: &str,
    exit_code: Option<i32>,
) -> Result<ParsedCodexOutput, String> {
    let mut parsed_json_events = 0usize;
    let mut agent_messages: Vec<String> = Vec::new();
    let mut error_messages: Vec<String> = Vec::new();
    let mut saw_turn_failed = false;
    let mut sum_input: u64 = 0;
    let mut sum_output: u64 = 0;
    let mut sum_total: u64 = 0;
    let mut saw_valid_turn_usage = false;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        if !val.is_object() {
            continue;
        }
        parsed_json_events += 1;

        match val.get("type").and_then(|v| v.as_str()) {
            Some("item.completed") => {
                if val
                    .get("item")
                    .and_then(|i| i.get("type"))
                    .and_then(|v| v.as_str())
                    == Some("agent_message")
                    && let Some(text) = val
                        .get("item")
                        .and_then(|i| i.get("text"))
                        .and_then(|v| v.as_str())
                    && !text.trim().is_empty()
                {
                    agent_messages.push(text.to_owned());
                }
            }
            Some("turn.completed") => {
                if let Some(usage) = val.get("usage").and_then(|v| v.as_object())
                    && let (Some(inp), Some(out)) = (
                        usage.get("input_tokens").and_then(|v| v.as_u64()),
                        usage.get("output_tokens").and_then(|v| v.as_u64()),
                    )
                {
                    // Codex ThreadEvent usage omits `total_tokens`; `input_tokens` already
                    // includes `cached_input_tokens` and `output_tokens` includes reasoning.
                    let tot = usage
                        .get("total_tokens")
                        .and_then(|v| v.as_u64())
                        .unwrap_or_else(|| inp.saturating_add(out));
                    sum_input = sum_input.saturating_add(inp);
                    sum_output = sum_output.saturating_add(out);
                    sum_total = sum_total.saturating_add(tot);
                    saw_valid_turn_usage = true;
                }
            }
            Some("turn.failed") => {
                saw_turn_failed = true;
                if let Some(msg) = val
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|v| v.as_str())
                    && !msg.trim().is_empty()
                {
                    error_messages.push(msg.trim().to_owned());
                }
            }
            Some("error") => {
                if let Some(msg) = val.get("message").and_then(|v| v.as_str())
                    && !msg.trim().is_empty()
                {
                    error_messages.push(msg.trim().to_owned());
                }
            }
            _ => {}
        }
    }

    let succeeded = exit_code == Some(0) && !saw_turn_failed;
    let (input_tokens, output_tokens, total_tokens) = if saw_valid_turn_usage {
        (Some(sum_input), Some(sum_output), Some(sum_total))
    } else {
        (None, None, None)
    };

    let last_agent_message = agent_messages.last().cloned();
    let structured_rejection = if succeeded {
        last_agent_message
            .as_deref()
            .and_then(|msg| crate::v2::pipeline::validate_structured_impl_report(msg).err())
    } else {
        None
    };

    let final_succeeded = succeeded && structured_rejection.is_none();
    let status = if final_succeeded { "PASSED" } else { "FAILED" }.to_owned();
    let raw_summary = if let Some(ref rejection) = structured_rejection {
        rejection.clone()
    } else if !final_succeeded && let Some(err) = error_messages.last() {
        err.clone()
    } else if let Some(ref msg) = last_agent_message {
        msg.clone()
    } else if let Some(err) = error_messages.last() {
        err.clone()
    } else if parsed_json_events == 0 && !stdout.trim().is_empty() {
        stdout.lines().take(10).collect::<Vec<_>>().join("\n")
    } else if !stderr.trim().is_empty() {
        stderr.lines().take(10).collect::<Vec<_>>().join("\n")
    } else {
        stdout.lines().take(10).collect::<Vec<_>>().join("\n")
    };
    let summary = truncate_utf8_bytes(&raw_summary, MAX_SUMMARY_BYTES);

    let review_output = last_agent_message.clone();
    let review_markdown = if structured_rejection.is_some() {
        None
    } else {
        last_agent_message
            .filter(|msg| msg.contains('|'))
            .or_else(|| {
                (parsed_json_events == 0 && stdout.contains('|')).then(|| stdout.to_owned())
            })
    };

    Ok(ParsedCodexOutput {
        status,
        summary,
        review_markdown,
        review_output,
        input_tokens,
        output_tokens,
        total_tokens,
    })
}

fn write_stage_result_json(
    attempt_dir: &std::path::Path,
    attempt_id: &str,
    task_id: &str,
    stage: &str,
    exit_code: Option<i32>,
    result: &StageExecutionResult,
) -> Result<(), String> {
    let result_json = serde_json::json!({
        "attempt_id": attempt_id,
        "task_id": task_id,
        "stage": stage,
        "exit_code": exit_code,
        "result": result,
    });
    write_secure_file(
        &attempt_dir.join("result.json"),
        serde_json::to_string_pretty(&result_json)
            .unwrap_or_default()
            .as_bytes(),
    )
}

impl StageExecutor for SystemdStageExecutor {
    fn persist_plan_artifact(
        &mut self,
        task: &TaskRecord,
        artifact_id: &str,
        markdown: &str,
    ) -> Result<PathBuf, String> {
        validate_attempt_id(&task.task_id)?;
        validate_attempt_id(artifact_id)?;
        ensure_secure_dir(&self.state_dir)?;
        let dir = ensure_secure_dir(&self.state_dir.join("plans"))?;
        let path = dir.join(format!("{}-{}.md", task.task_id, artifact_id));
        write_secure_file(&path, markdown.as_bytes())?;
        Ok(path)
    }

    fn read_plan_artifact(&self, path: &std::path::Path) -> Result<String, String> {
        let dir = self.state_dir.join("plans");
        if path.parent() != Some(dir.as_path()) {
            return Err("plan artifact is outside plans directory".to_owned());
        }
        ensure_secure_dir(&self.state_dir)?;
        ensure_secure_dir(&dir)?;
        let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err("refusing non-file or symlink plan artifact".to_owned());
        }
        std::fs::read_to_string(path).map_err(|e| e.to_string())
    }

    fn publish_plan_stage(
        &mut self,
        task: &TaskRecord,
        path: &std::path::Path,
        markdown: &str,
    ) -> Result<(), String> {
        if self.read_plan_artifact(path)? != markdown {
            return Err("plan publication body differs from artifact".into());
        }
        let artifact_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or("invalid plan artifact name")?;
        let op =
            crate::v2::intake::publish_plan_stage(task, &format!("zach-plan-{artifact_id}"), path);
        crate::v2::intake::WsTaskClient::execute(
            &crate::v2::intake::SystemWsTaskClient {
                bin: self.ws_task_bin.clone(),
            },
            &op.args,
        )
        .map_err(|error| format!("failed to publish plan: {error}"))?;
        Ok(())
    }

    fn execute_stage(
        &mut self,
        task: &TaskRecord,
        attempt_id: &str,
        route: &StageRoute,
        spec: &StageCommandSpec,
    ) -> Result<StageExecutionResult, String> {
        if !cfg!(test) {
            return Err(
                "worker execution is owned by zachd; submit through the daemon socket".into(),
            );
        }
        self.check_isolation()?;
        // Test fixture transports are not a production host-transport fallback.
        #[cfg(test)]
        let fixture_transport = self.fixture_transport;
        #[cfg(not(test))]
        let fixture_transport = false;
        if !fixture_transport {
            validate_stage_isolation_spec(task, route, spec)?;
        }
        let valid_attempt_id = validate_attempt_id(attempt_id)?;
        isolation::secure_parents(&self.state_dir)?;
        let attempts_root = ensure_secure_dir(&self.state_dir.join("attempts"))?;
        let attempt_dir = ensure_secure_dir(&attempts_root.join(valid_attempt_id))?;

        write_secure_file(&attempt_dir.join("prompt.md"), spec.prompt.as_bytes())?;
        let (_, bootstrap_meta) =
            crate::v2::pipeline::resolve_stage_bootstrap(task, &route.stage, &spec.worktree_path);
        if let Ok(bootstrap_bytes) = serde_json::to_vec_pretty(&bootstrap_meta) {
            let _ = write_secure_file(&attempt_dir.join("bootstrap.json"), &bootstrap_bytes);
        }

        let driver = worker_driver(route.family);
        let mut effective_args = spec.args.clone();
        let mut readonly_files = Vec::new();
        if let Some(ref schema_json) = spec.output_schema_json {
            let schema_path = attempt_dir.join("review-schema.json");
            write_secure_file(&schema_path, schema_json.as_bytes())?;
            effective_args = driver.attach_output_schema(&effective_args, &schema_path);
            readonly_files.push(schema_path);
        }

        let _resources = if fixture_transport {
            None
        } else {
            let network =
                NetworkPolicy::resolve(task.context_pack.network.as_deref(), route.family)?;
            let home = std::env::var("HOME").unwrap_or_else(|_| "/home/ubuntu".into());
            if spec.writable {
                prepare_web_node_modules(
                    std::path::Path::new(&home),
                    std::path::Path::new(&spec.worktree_path),
                )?;
            }
            let mut resources = PreparedResources::prepare(
                &attempt_dir,
                std::path::Path::new(&home),
                std::path::Path::new(&spec.worktree_path),
                spec.writable,
                Some(route.family),
                network,
            )?;
            resources.layout.readonly_files = readonly_files;
            effective_args = replace_sandbox_args(&effective_args, &resources.layout)?;
            Some(resources)
        };

        let sha_before = git_head_sha(&spec.worktree_path);
        let mut child = match Command::new(&spec.program)
            .args(&effective_args)
            .env_clear()
            .envs(&spec.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                let err_msg = truncate_utf8_bytes(
                    &format!("failed to spawn {}: {e}", spec.program),
                    MAX_SUMMARY_BYTES,
                );
                let _ = write_secure_file(&attempt_dir.join("stdout.jsonl"), b"");
                let _ = write_secure_file(&attempt_dir.join("stderr.log"), err_msg.as_bytes());
                let result_json = serde_json::json!({
                    "attempt_id": valid_attempt_id,
                    "task_id": task.task_id,
                    "stage": route.stage,
                    "status": "FAILED",
                    "exit_code": serde_json::Value::Null,
                    "summary": err_msg,
                });
                let _ = write_secure_file(
                    &attempt_dir.join("result.json"),
                    serde_json::to_string_pretty(&result_json)
                        .unwrap_or_default()
                        .as_bytes(),
                );
                return Err(err_msg);
            }
        };

        let child_stdin = child.stdin.take();
        let stdin_bytes = spec.stdin_payload.as_bytes();
        let (writer_join, output_res) = std::thread::scope(|scope| {
            let writer = scope.spawn(move || -> std::io::Result<()> {
                use std::io::Write;
                if let Some(mut stdin) = child_stdin
                    && !stdin_bytes.is_empty()
                {
                    stdin.write_all(stdin_bytes)?;
                    stdin.flush()?;
                }
                // `child_stdin` is dropped here to send EOF while `wait_with_output()` drains stdout/stderr.
                Ok(())
            });
            let output_res = child.wait_with_output();
            let writer_join = writer.join();
            (writer_join, output_res)
        });

        let output = match output_res {
            Ok(out) => out,
            Err(e) => {
                let err_msg = truncate_utf8_bytes(
                    &format!("failed waiting for {}: {e}", spec.program),
                    MAX_SUMMARY_BYTES,
                );
                let _ = write_secure_file(&attempt_dir.join("stdout.jsonl"), b"");
                let _ = write_secure_file(&attempt_dir.join("stderr.log"), err_msg.as_bytes());
                let result_json = serde_json::json!({
                    "attempt_id": valid_attempt_id,
                    "task_id": task.task_id,
                    "stage": route.stage,
                    "status": "FAILED",
                    "exit_code": serde_json::Value::Null,
                    "summary": err_msg,
                });
                let _ = write_secure_file(
                    &attempt_dir.join("result.json"),
                    serde_json::to_string_pretty(&result_json)
                        .unwrap_or_default()
                        .as_bytes(),
                );
                return Err(err_msg);
            }
        };

        write_secure_file(&attempt_dir.join("stdout.jsonl"), &output.stdout)?;
        write_secure_file(&attempt_dir.join("stderr.log"), &output.stderr)?;

        if let Ok(Err(e)) = writer_join
            && e.kind() != std::io::ErrorKind::BrokenPipe
        {
            let err_msg = truncate_utf8_bytes(
                &format!("failed writing stdin to {}: {e}", spec.program),
                MAX_SUMMARY_BYTES,
            );
            let result_json = serde_json::json!({
                "attempt_id": valid_attempt_id,
                "task_id": task.task_id,
                "stage": route.stage,
                "status": "FAILED",
                "exit_code": output.status.code(),
                "summary": err_msg,
            });
            let _ = write_secure_file(
                &attempt_dir.join("result.json"),
                serde_json::to_string_pretty(&result_json)
                    .unwrap_or_default()
                    .as_bytes(),
            );
            return Err(err_msg);
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let sha_after = git_head_sha(&spec.worktree_path);
        let diff_files = collect_worktree_diff_entries(&spec.worktree_path);

        match driver.parse_output(&stdout, &stderr, output.status.code(), false) {
            Ok(mut parsed) => {
                if route.stage == "impl"
                    && parsed.status == "PASSED"
                    && let Err(rejection) =
                        crate::v2::pipeline::validate_impl_execution_result(&parsed)
                {
                    parsed.status = "FAILED".to_owned();
                    parsed.summary = truncate_utf8_bytes(&rejection, MAX_SUMMARY_BYTES);
                }
                parsed.sha_before = sha_before;
                parsed.sha_after = sha_after;
                parsed.diff_files = diff_files;
                parsed.summary = truncate_utf8_bytes(&parsed.summary, MAX_SUMMARY_BYTES);
                write_stage_result_json(
                    &attempt_dir,
                    valid_attempt_id,
                    &task.task_id,
                    &route.stage,
                    output.status.code(),
                    &parsed,
                )?;
                let failure_class = if parsed.status == "PASSED" {
                    None
                } else if route.stage == "impl"
                    && parsed
                        .summary
                        .to_ascii_lowercase()
                        .contains("impl_validation_failed:")
                {
                    Some(crate::v2::pipeline::FAILURE_CLASS_SEMANTIC)
                } else {
                    Some("STAGE_FAILED")
                };
                let receipt = build_stage_receipt_v1(
                    &task.task_id,
                    valid_attempt_id,
                    route,
                    &parsed,
                    failure_class,
                );
                let _ = write_stage_receipt_json(&attempt_dir, &receipt);
                let _ = crate::v2::audit::extract_and_write_attempt_audit(&attempt_dir);
                Ok(parsed)
            }
            Err(err_raw) => {
                let err_msg = truncate_utf8_bytes(&err_raw, MAX_SUMMARY_BYTES);
                let result_json = serde_json::json!({
                    "attempt_id": valid_attempt_id,
                    "task_id": task.task_id,
                    "stage": route.stage,
                    "status": "FAILED",
                    "exit_code": output.status.code(),
                    "summary": err_msg,
                });
                write_secure_file(
                    &attempt_dir.join("result.json"),
                    serde_json::to_string_pretty(&result_json)
                        .unwrap_or_default()
                        .as_bytes(),
                )?;
                let failed_res = StageExecutionResult {
                    status: "FAILED".to_owned(),
                    summary: err_msg.clone(),
                    review_markdown: None,
                    review_output: None,
                    stage_output: None,
                    invocation_id: None,
                    input_tokens: None,
                    output_tokens: None,
                    total_tokens: None,
                    duration_seconds: None,
                    sha_before,
                    sha_after,
                    diff_files,
                };
                let receipt = build_stage_receipt_v1(
                    &task.task_id,
                    valid_attempt_id,
                    route,
                    &failed_res,
                    Some("DRIVER_ERROR"),
                );
                let _ = write_stage_receipt_json(&attempt_dir, &receipt);
                let _ = crate::v2::audit::extract_and_write_attempt_audit(&attempt_dir);
                Err(err_msg)
            }
        }
    }

    fn run_checks(&mut self, worktree_path: &str, commands: &[String]) -> Result<(), String> {
        self.check_isolation()?;
        let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/home/ubuntu".into()));
        let worktree = std::path::Path::new(worktree_path);
        prepare_web_node_modules(&home, worktree)?;
        let layout = SandboxLayout::inspect(&home, worktree, true)?;
        for cmd in commands {
            let worker = vec!["bash".into(), "-c".into(), cmd.clone()];
            static CHECK_SEQ: std::sync::atomic::AtomicUsize =
                std::sync::atomic::AtomicUsize::new(0);
            let unit = format!(
                "--unit=zach-stage-worker-checks-{}-{}",
                std::process::id(),
                CHECK_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            );
            let out = Command::new("systemd-run")
                .arg(unit)
                .args([
                    "--user",
                    "--collect",
                    "--wait",
                    "--pipe",
                    "--slice=zach-workers.slice",
                    "-p",
                    "RuntimeMaxSec=1800",
                    "-p",
                    "MemoryMax=4G",
                    "-p",
                    "CPUWeight=20",
                    "-p",
                    "TasksMax=512",
                    "-p",
                    "KillMode=control-group",
                    "--",
                ])
                .args(isolation::bwrap_args(&layout, &worker))
                .stdin(Stdio::null())
                .output()
                .map_err(|e| format!("failed to run check '{cmd}': {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "check '{cmd}' failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
        }
        Ok(())
    }

    fn run_gate_checks(&mut self, worktree_path: &str, commands: &[String]) -> Result<(), String> {
        let clean_env = build_clean_env_from_process();
        for cmd in commands {
            let out = Command::new("bash")
                .args(["-lc", cmd])
                .current_dir(worktree_path)
                .env_clear()
                .envs(&clean_env)
                .output()
                .map_err(|e| format!("failed to run check '{cmd}': {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "check '{cmd}' failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
        }
        Ok(())
    }

    fn commit_worktree(
        &mut self,
        task: &TaskRecord,
        worktree_path: &str,
    ) -> Result<String, String> {
        let trimmed_worktree = worktree_path.trim();
        if trimmed_worktree.is_empty() || trimmed_worktree == "none" {
            return Err(format!(
                "task {} has no governed worktree_path to commit",
                task.task_id
            ));
        }

        // Commit uncommitted changes if worktree is dirty
        let status_out = Command::new("git")
            .args(["-C", trimmed_worktree, "status", "--porcelain"])
            .output()
            .map_err(|e| format!("failed to check git status: {e}"))?;
        if !status_out.status.success() {
            return Err(format!(
                "git status failed in '{}': {}",
                trimmed_worktree,
                String::from_utf8_lossy(&status_out.stderr).trim()
            ));
        }

        let status_str = String::from_utf8_lossy(&status_out.stdout);
        if !status_str.trim().is_empty() {
            let add_out = Command::new("git")
                .args(["-C", trimmed_worktree, "add", "-A"])
                .output()
                .map_err(|e| format!("git add failed: {e}"))?;
            if !add_out.status.success() {
                return Err(format!(
                    "git add failed: {}",
                    String::from_utf8_lossy(&add_out.stderr).trim()
                ));
            }

            let commit_msg = format!(
                "feat({}): {}\n\nGovernance-Task: {}\nZach-Attempt: {}",
                task.task_id.to_ascii_lowercase(),
                task.title,
                task.task_id,
                task.active_attempt_id.as_deref().unwrap_or("none")
            );
            let commit_out = Command::new("git")
                .args(["-C", trimmed_worktree, "commit", "-m", &commit_msg])
                .output()
                .map_err(|e| format!("git commit failed: {e}"))?;
            if !commit_out.status.success() {
                return Err(format!(
                    "git commit failed: {}",
                    String::from_utf8_lossy(&commit_out.stderr).trim()
                ));
            }
        }

        git_head_sha(trimmed_worktree)
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty() && s != "head-sha")
            .ok_or_else(|| {
                format!(
                    "failed to resolve committed HEAD SHA in worktree '{}'",
                    trimmed_worktree
                )
            })
    }

    fn push_and_ensure_pr(
        &mut self,
        task: &TaskRecord,
        worktree_path: &str,
        reviewed_sha: &str,
    ) -> Result<i64, String> {
        let trimmed_worktree = worktree_path.trim();
        if trimmed_worktree.is_empty() || trimmed_worktree == "none" {
            return Err(format!(
                "task {} has no governed worktree_path for PR delivery",
                task.task_id
            ));
        }

        let trimmed_sha = reviewed_sha.trim();
        if trimmed_sha.is_empty() || trimmed_sha == "head-sha" {
            return Err(format!(
                "task {} is missing a valid reviewed_sha for PR delivery",
                task.task_id
            ));
        }

        let branch = task
            .branch
            .as_deref()
            .map(str::trim)
            .filter(|b| !b.is_empty() && *b != "none")
            .ok_or_else(|| format!("task {} has no branch for PR push", task.task_id))?;

        let push_out = Command::new("git")
            .args(["-C", trimmed_worktree, "push", "-u", "origin", branch])
            .output()
            .map_err(|e| format!("git push failed: {e}"))?;
        if !push_out.status.success() {
            return Err(format!(
                "git push failed: {}",
                String::from_utf8_lossy(&push_out.stderr).trim()
            ));
        }

        if let Some(pr) = task.pr_number.filter(|&p| p > 0) {
            return Ok(pr);
        }

        let gh_repo = task.github_repo.as_deref().unwrap_or(&task.repository);
        let list_out = Command::new("gh")
            .args([
                "pr",
                "list",
                "--repo",
                gh_repo,
                "--head",
                branch,
                "--json",
                "number",
                "-q",
                ".[0].number",
            ])
            .output();

        if let Ok(lo) = list_out
            && lo.status.success()
        {
            let num_str = String::from_utf8_lossy(&lo.stdout).trim().to_owned();
            if let Ok(num) = num_str.parse::<i64>()
                && num > 0
            {
                return Ok(num);
            }
        }

        let body = format!(
            "Closes #{}\n\nGovernance-Task: {}",
            task.issue_number.unwrap_or(0),
            task.task_id
        );
        let title = format!("{}: {}", task.task_id, task.title);
        let create_out = Command::new("gh")
            .args([
                "pr", "create", "--repo", gh_repo, "--head", branch, "--title", &title, "--body",
                &body,
            ])
            .output()
            .map_err(|e| format!("gh pr create failed: {e}"))?;

        if !create_out.status.success() {
            let err = String::from_utf8_lossy(&create_out.stderr);
            return Err(format!("gh pr create failed: {}", err.trim()));
        }

        let pr_url = String::from_utf8_lossy(&create_out.stdout);
        pr_url
            .trim()
            .rsplit('/')
            .next()
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|&n| n > 0)
            .ok_or_else(|| {
                format!(
                    "gh pr create did not return a valid PR number in output: '{}'",
                    pr_url.trim()
                )
            })
    }

    fn collect_reviewed_diff(
        &mut self,
        task: &TaskRecord,
        worktree_path: &str,
        reviewed_sha: &str,
    ) -> Result<ReviewedDiffContext, String> {
        let base_hint = task
            .plan_base_sha
            .as_deref()
            .or(task.context_pack.base_sha.as_deref());
        collect_reviewed_diff_ranges(worktree_path, base_hint, reviewed_sha)
    }
}

/// Normalizes a cited diff path relative to `worktree_path`, rejecting empty,
/// escaping (`..`), or foreign absolute paths.
pub fn normalize_cited_diff_path(raw: &str, worktree_path: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return Err("cited file path is empty or contains NUL".to_owned());
    }
    let normalized_slashes = trimmed.replace('\\', "/");
    let wt_trimmed = worktree_path.trim().trim_end_matches('/');
    let mut rel = normalized_slashes.as_str();
    if !wt_trimmed.is_empty() && wt_trimmed != "none" {
        let wt_prefix = format!("{wt_trimmed}/");
        if let Some(stripped) = rel.strip_prefix(&wt_prefix) {
            rel = stripped;
        } else if let Ok(canon_wt) = std::fs::canonicalize(wt_trimmed)
            && let Some(canon_str) = canon_wt.to_str()
        {
            let canon_prefix = format!("{}/", canon_str.trim_end_matches('/'));
            if let Some(stripped) = rel.strip_prefix(&canon_prefix) {
                rel = stripped;
            }
        }
    }
    while let Some(stripped) = rel.strip_prefix("./") {
        rel = stripped;
    }
    if rel.starts_with('/') {
        return Err(format!(
            "cited file path '{raw}' is outside governed worktree '{worktree_path}'"
        ));
    }
    let path = std::path::Path::new(rel);
    if path.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    }) {
        return Err(format!(
            "cited file path '{raw}' contains escaping traversal"
        ));
    }
    let clean = rel.trim_start_matches('/').to_owned();
    if clean.is_empty() {
        return Err(format!("cited file path '{raw}' normalized to empty"));
    }
    Ok(clean)
}

fn resolve_merge_base_for_reviewed_sha(
    worktree_path: &str,
    plan_base_sha: Option<&str>,
    reviewed_sha: &str,
) -> Result<(String, String), String> {
    let trimmed_rev = reviewed_sha.trim();
    if trimmed_rev.is_empty() || trimmed_rev == "head-sha" {
        return Err("cannot collect reviewed diff without valid reviewed_sha".to_owned());
    }
    let rev_verify = Command::new("git")
        .args([
            "-C",
            worktree_path,
            "rev-parse",
            "--verify",
            &format!("{trimmed_rev}^{{commit}}"),
        ])
        .output()
        .map_err(|e| format!("failed to verify reviewed_sha '{trimmed_rev}': {e}"))?;
    if !rev_verify.status.success() {
        return Err(format!(
            "failed to resolve reviewed_sha '{trimmed_rev}' in '{worktree_path}': {}",
            String::from_utf8_lossy(&rev_verify.stderr).trim()
        ));
    }
    let reviewed_oid = String::from_utf8_lossy(&rev_verify.stdout)
        .trim()
        .to_owned();

    let mut candidates = Vec::new();
    if let Ok(sym) = Command::new("git")
        .args([
            "-C",
            worktree_path,
            "symbolic-ref",
            "--short",
            "refs/remotes/origin/HEAD",
        ])
        .output()
        && sym.status.success()
    {
        let sym_str = String::from_utf8_lossy(&sym.stdout);
        if let Some(branch) = crate::v2::merge_queue::parse_default_branch(&sym_str, "") {
            candidates.push(format!("origin/{branch}"));
        }
    }
    for fallback in ["origin/main", "origin/master"] {
        if !candidates.iter().any(|c| c == fallback) {
            candidates.push(fallback.to_owned());
        }
    }
    if let Some(base_hint) = plan_base_sha.map(str::trim).filter(|s| !s.is_empty())
        && !candidates.iter().any(|c| c == base_hint)
    {
        candidates.push(base_hint.to_owned());
    }

    for base_ref in candidates {
        if let Ok(out) = Command::new("git")
            .args(["-C", worktree_path, "merge-base", &base_ref, &reviewed_oid])
            .output()
            && out.status.success()
        {
            let sha = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            if !sha.is_empty() {
                return Ok((sha, reviewed_oid));
            }
        }
    }

    if let Ok(parent_out) = Command::new("git")
        .args([
            "-C",
            worktree_path,
            "rev-parse",
            "--verify",
            &format!("{reviewed_oid}^"),
        ])
        .output()
        && parent_out.status.success()
    {
        let sha = String::from_utf8_lossy(&parent_out.stdout)
            .trim()
            .to_owned();
        if !sha.is_empty() {
            return Ok((sha, reviewed_oid));
        }
    }

    Err(format!(
        "unable to resolve merge-base for reviewed_sha '{reviewed_oid}' in '{worktree_path}'"
    ))
}

fn parse_hunk_span(spec: &str) -> Option<(usize, usize)> {
    let trimmed = spec.trim();
    if let Some((start_s, count_s)) = trimmed.split_once(',') {
        let start = start_s.parse::<usize>().ok()?;
        let count = count_s.parse::<usize>().ok()?;
        Some((start, count))
    } else {
        let start = trimmed.parse::<usize>().ok()?;
        Some((start, 1))
    }
}

fn parse_hunk_header(line: &str) -> Option<((usize, usize), (usize, usize))> {
    let rest = line.strip_prefix("@@ -")?;
    let (old_part, after_old) = rest.split_once(" +")?;
    let (new_part, _) = after_old.split_once(" @@")?;
    let old_span = parse_hunk_span(old_part)?;
    let new_span = parse_hunk_span(new_part)?;
    Some((old_span, new_span))
}

/// Parses `git diff --unified=0 --no-ext-diff -M` output into per-file changed
/// 1-based line ranges, handling omitted counts, empty added/deleted files,
/// pure deletions, pure renames, and binary files.
pub fn parse_unified_zero_diff(diff_text: &str) -> BTreeMap<String, Vec<LineRange>> {
    #[derive(Default)]
    struct FileState {
        old_path: Option<String>,
        new_path: Option<String>,
        is_deleted: bool,
        ranges: Vec<LineRange>,
    }

    fn flush_file(out: &mut BTreeMap<String, Vec<LineRange>>, state: Option<FileState>) {
        let Some(mut st) = state else {
            return;
        };
        let target = if st.is_deleted {
            st.old_path.or(st.new_path)
        } else {
            st.new_path.or(st.old_path)
        };
        let Some(raw_path) = target else {
            return;
        };
        let clean = raw_path.trim().trim_start_matches("./").to_owned();
        if clean.is_empty() || clean == "/dev/null" {
            return;
        }
        if st.ranges.is_empty() {
            st.ranges.push(LineRange { start: 1, end: 1 });
        }
        out.entry(clean).or_default().extend(st.ranges);
    }

    let mut out: BTreeMap<String, Vec<LineRange>> = BTreeMap::new();
    let mut current: Option<FileState> = None;

    for raw_line in diff_text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("diff --git ") {
            flush_file(&mut out, current.take());
            let mut st = FileState::default();
            if let Some(after_a) = rest.strip_prefix("a/") {
                let bytes = after_a.as_bytes();
                let mut exact_pair = None;
                if bytes.len() >= 3 && (bytes.len() - 3).is_multiple_of(2) {
                    let mid = (bytes.len() - 3) / 2;
                    if after_a.is_char_boundary(mid)
                        && after_a[mid..].starts_with(" b/")
                        && after_a[..mid] == after_a[mid + 3..]
                    {
                        exact_pair =
                            Some((after_a[..mid].to_owned(), after_a[mid + 3..].to_owned()));
                    }
                }
                if let Some((old_p, new_p)) = exact_pair {
                    st.old_path = Some(old_p);
                    st.new_path = Some(new_p);
                } else if let Some((old_p, new_p)) = after_a.split_once(" b/") {
                    st.old_path = Some(old_p.to_owned());
                    st.new_path = Some(new_p.to_owned());
                }
            }
            current = Some(st);
            continue;
        }

        let Some(st) = current.as_mut() else {
            continue;
        };

        if line.starts_with("deleted file mode ") || line == "+++ /dev/null" {
            st.is_deleted = true;
            if line == "+++ /dev/null" {
                st.new_path = None;
            }
        } else if let Some(p) = line.strip_prefix("rename from ") {
            st.old_path = Some(p.to_owned());
        } else if let Some(p) = line.strip_prefix("rename to ") {
            st.new_path = Some(p.to_owned());
        } else if let Some(p) = line.strip_prefix("copy to ") {
            st.new_path = Some(p.to_owned());
        } else if let Some(p) = line.strip_prefix("--- a/") {
            st.old_path = Some(p.to_owned());
        } else if let Some(p) = line.strip_prefix("+++ b/") {
            st.new_path = Some(p.to_owned());
        } else if line.starts_with("Binary files ") && line.ends_with(" differ") {
            if line.ends_with(" and /dev/null differ") {
                st.is_deleted = true;
                if let Some(after_a) = line.strip_prefix("Binary files a/")
                    && let Some((old_p, _)) = after_a.split_once(" and /dev/null differ")
                {
                    st.old_path = Some(old_p.to_owned());
                }
            } else if let Some((_, rhs)) = line.rsplit_once(" and b/")
                && let Some(new_p) = rhs.strip_suffix(" differ")
            {
                st.new_path = Some(new_p.to_owned());
            }
        } else if line.starts_with("@@ ")
            && let Some(((old_start, old_count), (new_start, new_count))) = parse_hunk_header(line)
        {
            if st.is_deleted {
                let start = old_start.max(1);
                let end = start.saturating_add(old_count.max(1) - 1);
                st.ranges.push(LineRange { start, end });
            } else if new_count == 0 {
                let anchor = new_start.max(1);
                st.ranges.push(LineRange {
                    start: anchor,
                    end: anchor,
                });
            } else {
                let start = new_start.max(1);
                let end = start.saturating_add(new_count - 1);
                st.ranges.push(LineRange { start, end });
            }
        }
    }

    flush_file(&mut out, current.take());
    out
}

/// Collects per-file changed line ranges over `<merge-base>..<reviewed_sha>`.
pub fn collect_reviewed_diff_ranges(
    worktree_path: &str,
    plan_base_sha: Option<&str>,
    reviewed_sha: &str,
) -> Result<ReviewedDiffContext, String> {
    let trimmed_wt = worktree_path.trim();
    if trimmed_wt.is_empty() || trimmed_wt == "none" {
        return Err("cannot collect reviewed diff without governed worktree_path".to_owned());
    }
    let (merge_base_sha, reviewed_oid) =
        resolve_merge_base_for_reviewed_sha(trimmed_wt, plan_base_sha, reviewed_sha)?;
    let commit_range = format!("{merge_base_sha}..{reviewed_oid}");
    let out = Command::new("git")
        .args([
            "-C",
            trimmed_wt,
            "-c",
            "diff.noprefix=false",
            "-c",
            "core.quotePath=false",
            "diff",
            "--unified=0",
            "--no-ext-diff",
            "-M",
            &commit_range,
        ])
        .output()
        .map_err(|e| format!("failed to run git diff for '{commit_range}': {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git diff '{commit_range}' failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let diff_text = String::from_utf8_lossy(&out.stdout);
    let files = parse_unified_zero_diff(&diff_text);
    let diff_excerpt = truncate_utf8_bytes(&diff_text, 4096);
    Ok(ReviewedDiffContext {
        merge_base_sha,
        reviewed_sha: reviewed_oid,
        commit_range,
        files,
        diff_excerpt,
    })
}

fn git_head_sha(worktree_path: &str) -> Option<String> {
    let out = Command::new("git")
        .args(["-C", worktree_path, "rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn resolve_diff_base(worktree_path: &str) -> Option<String> {
    let mut candidates = Vec::new();
    if let Ok(sym) = Command::new("git")
        .args([
            "-C",
            worktree_path,
            "symbolic-ref",
            "--short",
            "refs/remotes/origin/HEAD",
        ])
        .output()
        && sym.status.success()
    {
        let sym_str = String::from_utf8_lossy(&sym.stdout);
        if let Some(branch) = crate::v2::merge_queue::parse_default_branch(&sym_str, "") {
            candidates.push(format!("origin/{branch}"));
        }
    }
    for fallback in ["origin/main", "origin/master"] {
        if !candidates.iter().any(|c| c == fallback) {
            candidates.push(fallback.to_owned());
        }
    }

    for base_ref in candidates {
        if let Ok(out) = Command::new("git")
            .args(["-C", worktree_path, "merge-base", &base_ref, "HEAD"])
            .output()
            && out.status.success()
        {
            let sha = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            if !sha.is_empty() {
                return Some(sha);
            }
        }
    }

    let head = Command::new("git")
        .args(["-C", worktree_path, "rev-parse", "--verify", "HEAD"])
        .output()
        .ok()?;
    if head.status.success() {
        let sha = String::from_utf8_lossy(&head.stdout).trim().to_owned();
        if !sha.is_empty() {
            return Some(sha);
        }
    }
    None
}

fn normalize_git_diff_status(raw: &str) -> String {
    match raw.trim().bytes().next() {
        Some(b'A' | b'C') => "A".to_owned(),
        Some(b'D') => "D".to_owned(),
        Some(b'R') => "R".to_owned(),
        _ => "M".to_owned(),
    }
}

fn parse_name_status_z(bytes: &[u8]) -> BTreeMap<String, String> {
    let tokens: Vec<String> = bytes
        .split(|&b| b == 0)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    let mut statuses = BTreeMap::new();
    let mut i = 0;
    while i < tokens.len() {
        let raw_status = tokens[i].trim();
        i += 1;
        if raw_status.is_empty() {
            continue;
        }
        let norm = normalize_git_diff_status(raw_status);
        if raw_status.starts_with('R') || raw_status.starts_with('C') {
            if i + 1 < tokens.len() {
                let new_path = tokens[i + 1].clone();
                if !new_path.is_empty() {
                    statuses.insert(new_path, norm);
                }
                i += 2;
            } else {
                break;
            }
        } else if i < tokens.len() {
            let path = tokens[i].clone();
            if !path.is_empty() {
                statuses.insert(path, norm);
            }
            i += 1;
        }
    }
    statuses
}

fn parse_numstat_z(bytes: &[u8]) -> BTreeMap<String, (usize, usize)> {
    let tokens: Vec<String> = bytes
        .split(|&b| b == 0)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    let mut stats = BTreeMap::new();
    let mut i = 0;
    while i < tokens.len() {
        let token = &tokens[i];
        i += 1;
        if token.is_empty() {
            continue;
        }
        let mut parts = token.splitn(3, '\t');
        let (Some(added_s), Some(deleted_s), Some(path_part)) =
            (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let added = added_s.parse::<usize>().unwrap_or(0);
        let deleted = deleted_s.parse::<usize>().unwrap_or(0);
        if path_part.is_empty() {
            if i + 1 < tokens.len() {
                let new_path = tokens[i + 1].clone();
                if !new_path.is_empty() {
                    stats.insert(new_path, (added, deleted));
                }
                i += 2;
            } else {
                break;
            }
        } else {
            stats.insert(path_part.to_owned(), (added, deleted));
        }
    }
    stats
}

fn count_untracked_file_lines(worktree_path: &str, rel_path: &str) -> usize {
    let full_path = std::path::Path::new(worktree_path).join(rel_path);
    let Ok(bytes) = std::fs::read(&full_path) else {
        return 0;
    };
    if bytes.contains(&0) {
        return 0;
    }
    String::from_utf8_lossy(&bytes).lines().count()
}

pub fn collect_worktree_diff_entries(worktree_path: &str) -> Vec<DiffFileEntry> {
    let mut entries: BTreeMap<String, DiffFileEntry> = BTreeMap::new();

    let diff_target = resolve_diff_base(worktree_path).unwrap_or_else(|| "--cached".to_owned());
    let name_status_out = Command::new("git")
        .args([
            "-C",
            worktree_path,
            "diff",
            "--name-status",
            "-M",
            "-z",
            &diff_target,
        ])
        .output();
    let numstat_out = Command::new("git")
        .args([
            "-C",
            worktree_path,
            "diff",
            "--numstat",
            "-M",
            "-z",
            &diff_target,
        ])
        .output();

    if let (Ok(ns), Ok(num)) = (name_status_out, numstat_out)
        && ns.status.success()
        && num.status.success()
    {
        let statuses = parse_name_status_z(&ns.stdout);
        let stats = parse_numstat_z(&num.stdout);
        for (path, status) in statuses {
            let (added_lines, deleted_lines) = stats.get(&path).copied().unwrap_or((0, 0));
            entries.insert(
                path.clone(),
                DiffFileEntry {
                    path,
                    status,
                    added_lines,
                    deleted_lines,
                },
            );
        }
        for (path, (added_lines, deleted_lines)) in stats {
            entries.entry(path.clone()).or_insert(DiffFileEntry {
                path,
                status: "M".to_owned(),
                added_lines,
                deleted_lines,
            });
        }
    }

    if let Ok(untracked) = Command::new("git")
        .args([
            "-C",
            worktree_path,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
        ])
        .output()
        && untracked.status.success()
    {
        for chunk in untracked.stdout.split(|&b| b == 0) {
            if chunk.is_empty() {
                continue;
            }
            let rel_path = String::from_utf8_lossy(chunk).into_owned();
            entries.entry(rel_path.clone()).or_insert_with(|| {
                let added_lines = count_untracked_file_lines(worktree_path, &rel_path);
                DiffFileEntry {
                    path: rel_path,
                    status: "A".to_owned(),
                    added_lines,
                    deleted_lines: 0,
                }
            });
        }
    }

    entries.into_values().collect()
}

pub(crate) fn is_valid_git_worktree(worktree_path: &str) -> bool {
    let trimmed = worktree_path.trim();
    if trimmed.is_empty() || trimmed == "none" {
        return false;
    }
    let path = std::path::Path::new(trimmed);
    if !path.is_dir() {
        return false;
    }
    let Ok(out) = Command::new("git")
        .args(["-C", trimmed, "rev-parse", "--show-toplevel"])
        .output()
    else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let toplevel = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if toplevel.is_empty() {
        return false;
    }
    match (
        std::fs::canonicalize(path),
        std::fs::canonicalize(std::path::Path::new(&toplevel)),
    ) {
        (Ok(wt_canon), Ok(top_canon)) => wt_canon == top_canon,
        _ => false,
    }
}

fn run_git_status_porcelain(worktree_path: &str) -> Result<bool, String> {
    let out = Command::new("git")
        .args(["-C", worktree_path, "status", "--porcelain"])
        .output()
        .map_err(|e| format!("failed to run git status in '{worktree_path}': {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git status failed in '{}': {}",
            worktree_path,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(!String::from_utf8_lossy(&out.stdout).trim().is_empty())
}

pub(crate) fn reset_worktree_uncommitted_changes(worktree_path: &str) -> Result<(), String> {
    if !is_valid_git_worktree(worktree_path) {
        return Ok(());
    }
    if !run_git_status_porcelain(worktree_path)? {
        return Ok(());
    }
    let reset_out = Command::new("git")
        .args(["-C", worktree_path, "reset", "--hard", "HEAD"])
        .output()
        .map_err(|e| format!("failed to run git reset --hard HEAD in '{worktree_path}': {e}"))?;
    if !reset_out.status.success() {
        return Err(format!(
            "git reset --hard HEAD failed in '{}': {}",
            worktree_path,
            String::from_utf8_lossy(&reset_out.stderr).trim()
        ));
    }
    // Never pass -x so .gitignored caches such as target/ and web/node_modules/ survive.
    let clean_out = Command::new("git")
        .args(["-C", worktree_path, "clean", "-fd"])
        .output()
        .map_err(|e| format!("failed to run git clean -fd in '{worktree_path}': {e}"))?;
    if !clean_out.status.success() {
        return Err(format!(
            "git clean -fd failed in '{}': {}",
            worktree_path,
            String::from_utf8_lossy(&clean_out.stderr).trim()
        ));
    }
    Ok(())
}

fn suspended_impl_snapshot_ref(attempt_id: &str) -> Result<String, String> {
    let valid = validate_attempt_id(attempt_id)?;
    let sanitized: String = valid
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect();
    Ok(format!("refs/zach/suspended-impl/{sanitized}"))
}

pub(crate) fn drop_suspended_impl_snapshot_ref(worktree_path: &str, attempt_id: &str) {
    if !is_valid_git_worktree(worktree_path) {
        return;
    }
    if let Ok(snap_ref) = suspended_impl_snapshot_ref(attempt_id) {
        let _ = Command::new("git")
            .args(["-C", worktree_path, "update-ref", "-d", &snap_ref])
            .output();
    }
}

pub(crate) fn snapshot_and_clean_suspended_impl_worktree(
    worktree_path: &str,
    attempt_id: &str,
) -> Result<Option<String>, String> {
    if !is_valid_git_worktree(worktree_path) {
        return Ok(None);
    }
    if !run_git_status_porcelain(worktree_path)? {
        return Ok(None);
    }
    let head_sha = git_head_sha(worktree_path)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("cannot resolve HEAD SHA in '{worktree_path}'"))?;
    let snap_ref = suspended_impl_snapshot_ref(attempt_id)?;
    let git_dir_out = Command::new("git")
        .args(["-C", worktree_path, "rev-parse", "--git-dir"])
        .output()
        .map_err(|e| format!("failed to resolve git dir in '{worktree_path}': {e}"))?;
    if !git_dir_out.status.success() {
        return Err(format!(
            "git rev-parse --git-dir failed in '{}': {}",
            worktree_path,
            String::from_utf8_lossy(&git_dir_out.stderr).trim()
        ));
    }
    let raw_git_dir = String::from_utf8_lossy(&git_dir_out.stdout)
        .trim()
        .to_owned();
    let git_dir = {
        let p = PathBuf::from(&raw_git_dir);
        if p.is_absolute() {
            p
        } else {
            std::path::Path::new(worktree_path).join(p)
        }
    };
    static SNAP_IDX_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let idx_path = git_dir.join(format!(
        "zach-suspended-idx-{}-{}",
        std::process::id(),
        SNAP_IDX_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&idx_path);
    struct TempIndexGuard(PathBuf);
    impl Drop for TempIndexGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _guard = TempIndexGuard(idx_path.clone());

    let read_tree = Command::new("git")
        .args(["-C", worktree_path, "read-tree", "HEAD"])
        .env("GIT_INDEX_FILE", &idx_path)
        .output()
        .map_err(|e| format!("git read-tree HEAD failed in '{worktree_path}': {e}"))?;
    if !read_tree.status.success() {
        return Err(format!(
            "git read-tree HEAD failed in '{}': {}",
            worktree_path,
            String::from_utf8_lossy(&read_tree.stderr).trim()
        ));
    }

    let add_out = Command::new("git")
        .args(["-C", worktree_path, "add", "-A"])
        .env("GIT_INDEX_FILE", &idx_path)
        .output()
        .map_err(|e| format!("git add -A failed in '{worktree_path}': {e}"))?;
    if !add_out.status.success() {
        return Err(format!(
            "git add -A failed in '{}': {}",
            worktree_path,
            String::from_utf8_lossy(&add_out.stderr).trim()
        ));
    }

    let write_tree = Command::new("git")
        .args(["-C", worktree_path, "write-tree"])
        .env("GIT_INDEX_FILE", &idx_path)
        .output()
        .map_err(|e| format!("git write-tree failed in '{worktree_path}': {e}"))?;
    if !write_tree.status.success() {
        return Err(format!(
            "git write-tree failed in '{}': {}",
            worktree_path,
            String::from_utf8_lossy(&write_tree.stderr).trim()
        ));
    }
    let tree_sha = String::from_utf8_lossy(&write_tree.stdout)
        .trim()
        .to_owned();
    if tree_sha.is_empty() {
        return Err(format!(
            "git write-tree returned empty SHA in '{worktree_path}'"
        ));
    }

    let commit_out = Command::new("git")
        .args([
            "-C",
            worktree_path,
            "commit-tree",
            &tree_sha,
            "-p",
            &head_sha,
            "-m",
            &format!("zach suspended impl snapshot for {attempt_id}"),
        ])
        .env("GIT_INDEX_FILE", &idx_path)
        .env("GIT_AUTHOR_NAME", "Zach")
        .env("GIT_AUTHOR_EMAIL", "zach@localhost")
        .env("GIT_COMMITTER_NAME", "Zach")
        .env("GIT_COMMITTER_EMAIL", "zach@localhost")
        .output()
        .map_err(|e| format!("git commit-tree failed in '{worktree_path}': {e}"))?;
    if !commit_out.status.success() {
        return Err(format!(
            "git commit-tree failed in '{}': {}",
            worktree_path,
            String::from_utf8_lossy(&commit_out.stderr).trim()
        ));
    }
    let snapshot_sha = String::from_utf8_lossy(&commit_out.stdout)
        .trim()
        .to_owned();
    if snapshot_sha.is_empty() {
        return Err(format!(
            "git commit-tree returned empty SHA in '{worktree_path}'"
        ));
    }

    let update_ref = Command::new("git")
        .args(["-C", worktree_path, "update-ref", &snap_ref, &snapshot_sha])
        .output()
        .map_err(|e| format!("git update-ref failed in '{worktree_path}': {e}"))?;
    if !update_ref.status.success() {
        return Err(format!(
            "git update-ref failed in '{}': {}",
            worktree_path,
            String::from_utf8_lossy(&update_ref.stderr).trim()
        ));
    }

    if let Err(err) = reset_worktree_uncommitted_changes(worktree_path) {
        drop_suspended_impl_snapshot_ref(worktree_path, attempt_id);
        return Err(err);
    }

    Ok(Some(snapshot_sha))
}

pub(crate) fn restore_suspended_impl_snapshot(
    worktree_path: &str,
    snapshot_sha: &str,
    attempt_id: &str,
) -> Result<(), String> {
    if !is_valid_git_worktree(worktree_path) {
        return Ok(());
    }
    let head_sha = git_head_sha(worktree_path)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("cannot resolve HEAD SHA in '{worktree_path}'"))?;
    let parent_spec = format!("{snapshot_sha}^");
    let parent_out = Command::new("git")
        .args(["-C", worktree_path, "rev-parse", "--verify", &parent_spec])
        .output()
        .map_err(|e| format!("failed to verify suspended impl snapshot parent: {e}"))?;
    if !parent_out.status.success() {
        return Err(format!(
            "suspended impl snapshot {snapshot_sha} parent cannot be resolved: {}",
            String::from_utf8_lossy(&parent_out.stderr).trim()
        ));
    }
    let parent_sha = String::from_utf8_lossy(&parent_out.stdout)
        .trim()
        .to_owned();
    if parent_sha != head_sha {
        return Err(format!(
            "suspended impl snapshot {snapshot_sha} parent {parent_sha} does not match current HEAD {head_sha}"
        ));
    }

    let read_tree = Command::new("git")
        .args([
            "-C",
            worktree_path,
            "read-tree",
            "--reset",
            "-u",
            snapshot_sha,
        ])
        .output()
        .map_err(|e| format!("git read-tree --reset -u failed in '{worktree_path}': {e}"))?;
    if !read_tree.status.success() {
        return Err(format!(
            "git read-tree --reset -u failed in '{}': {}",
            worktree_path,
            String::from_utf8_lossy(&read_tree.stderr).trim()
        ));
    }

    let reset_mixed = Command::new("git")
        .args(["-C", worktree_path, "reset", "--mixed", "HEAD"])
        .output()
        .map_err(|e| format!("git reset --mixed HEAD failed in '{worktree_path}': {e}"))?;
    if !reset_mixed.status.success() {
        return Err(format!(
            "git reset --mixed HEAD failed in '{}': {}",
            worktree_path,
            String::from_utf8_lossy(&reset_mixed.stderr).trim()
        ));
    }

    drop_suspended_impl_snapshot_ref(worktree_path, attempt_id);
    Ok(())
}

pub struct MockStageExecutor {
    pub plan_artifacts: BTreeMap<PathBuf, String>,
    pub published_plans: Vec<(PathBuf, String)>,
    pub publish_plan_error: Option<String>,
    pub staged_results: Vec<StageExecutionResult>,
    pub executed_specs: Vec<StageCommandSpec>,
    pub executed_routes: Vec<StageRoute>,
    pub executed_checks: Vec<String>,
    pub executed_gate_checks: Vec<String>,
    pub executed_stage_reviewed_shas: Vec<Option<String>>,
    pub committed_worktrees: Vec<String>,
    pub committed_sha_to_return: Option<String>,
    pub finalized_sha: Option<String>,
    pub pr_number_to_return: Option<i64>,
    pub reviewed_diff: Option<ReviewedDiffContext>,
    pub last_impl_diff_files: Vec<DiffFileEntry>,
}

impl Default for MockStageExecutor {
    fn default() -> Self {
        Self {
            plan_artifacts: BTreeMap::new(),
            published_plans: Vec::new(),
            publish_plan_error: None,
            staged_results: Vec::new(),
            executed_specs: Vec::new(),
            executed_routes: Vec::new(),
            executed_checks: Vec::new(),
            executed_gate_checks: Vec::new(),
            executed_stage_reviewed_shas: Vec::new(),
            committed_worktrees: Vec::new(),
            committed_sha_to_return: Some("mock-committed-sha".to_owned()),
            finalized_sha: None,
            pr_number_to_return: Some(42),
            reviewed_diff: None,
            last_impl_diff_files: Vec::new(),
        }
    }
}

impl StageExecutor for MockStageExecutor {
    fn persist_plan_artifact(
        &mut self,
        task: &TaskRecord,
        artifact_id: &str,
        markdown: &str,
    ) -> Result<PathBuf, String> {
        let path = PathBuf::from(format!("/virtual/plans/{}-{artifact_id}.md", task.task_id));
        self.plan_artifacts
            .insert(path.clone(), markdown.to_owned());
        Ok(path)
    }

    fn read_plan_artifact(&self, path: &std::path::Path) -> Result<String, String> {
        self.plan_artifacts
            .get(path)
            .cloned()
            .ok_or_else(|| "missing mock plan artifact".to_owned())
    }

    fn publish_plan_stage(
        &mut self,
        _task: &TaskRecord,
        path: &std::path::Path,
        markdown: &str,
    ) -> Result<(), String> {
        if let Some(err) = &self.publish_plan_error {
            return Err(err.clone());
        }
        self.published_plans
            .push((path.to_path_buf(), markdown.to_owned()));
        Ok(())
    }

    fn execute_stage(
        &mut self,
        task: &TaskRecord,
        _attempt_id: &str,
        route: &StageRoute,
        spec: &StageCommandSpec,
    ) -> Result<StageExecutionResult, String> {
        self.executed_routes.push(route.clone());
        self.executed_specs.push(spec.clone());
        self.executed_stage_reviewed_shas
            .push(task.reviewed_sha.clone());
        if self.staged_results.is_empty() {
            return Err("MockStageExecutor had no staged_results left".to_owned());
        }
        let res = self.staged_results.remove(0);
        if route.stage == "impl" && !res.diff_files.is_empty() {
            self.last_impl_diff_files = res.diff_files.clone();
        }
        Ok(res)
    }

    fn run_checks(&mut self, _worktree_path: &str, commands: &[String]) -> Result<(), String> {
        self.executed_checks.extend(commands.iter().cloned());
        Ok(())
    }
    fn run_gate_checks(&mut self, worktree_path: &str, commands: &[String]) -> Result<(), String> {
        self.executed_gate_checks.extend(commands.iter().cloned());
        self.run_checks(worktree_path, commands)
    }

    fn commit_worktree(
        &mut self,
        task: &TaskRecord,
        worktree_path: &str,
    ) -> Result<String, String> {
        self.committed_worktrees.push(worktree_path.to_owned());
        self.committed_sha_to_return
            .as_deref()
            .map(str::trim)
            .filter(|sha| !sha.is_empty() && *sha != "head-sha")
            .map(str::to_owned)
            .ok_or_else(|| format!("missing committed_sha for task {}", task.task_id))
    }

    fn push_and_ensure_pr(
        &mut self,
        task: &TaskRecord,
        _worktree_path: &str,
        reviewed_sha: &str,
    ) -> Result<i64, String> {
        let trimmed_sha = reviewed_sha.trim();
        if trimmed_sha.is_empty() || trimmed_sha == "head-sha" {
            return Err(format!("missing reviewed_sha for task {}", task.task_id));
        }
        self.finalized_sha = Some(trimmed_sha.to_owned());
        task.pr_number
            .filter(|&p| p > 0)
            .or_else(|| self.pr_number_to_return.filter(|&p| p > 0))
            .ok_or_else(|| format!("missing pr_number for task {}", task.task_id))
    }

    fn collect_reviewed_diff(
        &mut self,
        task: &TaskRecord,
        _worktree_path: &str,
        reviewed_sha: &str,
    ) -> Result<ReviewedDiffContext, String> {
        if let Some(ref ctx) = self.reviewed_diff {
            return Ok(ctx.clone());
        }
        let merge_base_sha = task
            .plan_base_sha
            .clone()
            .or_else(|| task.context_pack.base_sha.clone())
            .unwrap_or_else(|| "mock-base".to_owned());
        let mut files = BTreeMap::new();
        if !self.last_impl_diff_files.is_empty() {
            for entry in &self.last_impl_diff_files {
                files.insert(
                    entry.path.trim_start_matches("./").to_owned(),
                    vec![LineRange {
                        start: 1,
                        end: 10_000,
                    }],
                );
            }
        } else {
            for tf in &task.context_pack.target_files {
                files.insert(
                    tf.path.trim_start_matches("./").to_owned(),
                    vec![LineRange {
                        start: 1,
                        end: 10_000,
                    }],
                );
            }
        }
        let commit_range = format!("{merge_base_sha}..{reviewed_sha}");
        Ok(ReviewedDiffContext {
            merge_base_sha,
            reviewed_sha: reviewed_sha.to_owned(),
            commit_range,
            files,
            diff_excerpt: String::new(),
        })
    }
}

/// Version 1 mounts net/ as a directory; older socket-inode mounts cannot recover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttemptManifest {
    pub mount_layout_version: u32,
    pub attempt_id: String,
    pub task_id: String,
    pub route: StageRoute,
    pub spec: StageCommandSpec,
    pub sha_before: String,
    pub attempt_dir: PathBuf,
}

pub struct PreparedLaunch {
    pub manifest: AttemptManifest,
    pub resources: PreparedResources,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitState {
    Running,
    Starting,
    Exited,
    Failed,
    Stopping,
    Dead,
    Missing,
}

#[derive(Debug, Clone, Default)]
pub struct UnitObservation {
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub result: String,
    pub exit_code_kind: String,
    pub exit_code: Option<i32>,
    pub invocation_id: String,
    pub control_group: String,
    pub output_bytes: u64,
    pub cpu_usage_usec: Option<u64>,
}

impl UnitObservation {
    pub fn parse(raw: &str) -> Self {
        let fields: BTreeMap<_, _> = raw.lines().filter_map(|l| l.split_once('=')).collect();
        let field = |k| fields.get(k).copied().unwrap_or("").to_owned();
        Self {
            load_state: field("LoadState"),
            active_state: field("ActiveState"),
            sub_state: field("SubState"),
            result: field("Result"),
            exit_code_kind: field("ExecMainCode"),
            exit_code: field("ExecMainStatus").parse().ok(),
            invocation_id: field("InvocationID"),
            control_group: field("ControlGroup"),
            ..Self::default()
        }
    }
    pub fn state(&self) -> Result<UnitState, String> {
        if self.load_state == "not-found" {
            return Ok(UnitState::Missing);
        }
        match (self.active_state.as_str(), self.sub_state.as_str()) {
            ("failed", _) => Ok(UnitState::Failed),
            (_, "exited") => Ok(UnitState::Exited),
            ("active", "running") => Ok(UnitState::Running),
            ("activating", _) => Ok(UnitState::Starting),
            ("deactivating", _) => Ok(UnitState::Stopping),
            ("inactive", "dead") => Ok(UnitState::Dead),
            _ => Err(format!(
                "unrecognized unit state {}/{}",
                self.active_state, self.sub_state
            )),
        }
    }
    pub fn success(&self) -> bool {
        self.result == "success"
            && matches!(self.exit_code_kind.as_str(), "1" | "exited")
            && self.exit_code == Some(0)
    }
}

pub trait UnitController: Send + Sync {
    fn inspect(&self, unit: &str) -> Result<UnitObservation, String>;
    fn launch(&self, manifest: &AttemptManifest) -> Result<(), String>;
    fn stop(&self, unit: &str) -> Result<(), String>;
    fn reset_failed(&self, unit: &str) -> Result<(), String>;
    fn list_units(&self) -> Result<Vec<String>, String>;
}

#[derive(Default)]
pub struct SystemUnitController;

impl UnitController for SystemUnitController {
    fn inspect(&self, unit: &str) -> Result<UnitObservation, String> {
        let out = spawn_output_ctx(
            Command::new("systemctl").args([
                "--user",
                "show",
                unit,
                "--no-pager",
                "--property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,InvocationID,ControlGroup",
            ]),
            "systemctl show",
        )?;
        let raw = String::from_utf8_lossy(&out.stdout);
        let observed = UnitObservation::parse(&raw);
        // A manager error is never evidence that a unit is absent.
        if !out.status.success() && observed.load_state != "not-found" {
            return Err(format!(
                "systemctl inspection failed: {}",
                truncate_utf8_bytes(&String::from_utf8_lossy(&out.stderr), 1024)
            ));
        }
        observed.state()?;
        Ok(observed)
    }
    fn launch(&self, manifest: &AttemptManifest) -> Result<(), String> {
        let out = spawn_output_ctx(
            Command::new(&manifest.spec.program)
                .args(&manifest.spec.args)
                .env_clear()
                .envs(&manifest.spec.env)
                .stdin(Stdio::null()),
            &manifest.spec.program,
        )?;
        write_secure_file(
            &manifest.attempt_dir.join("launcher.log"),
            &[out.stdout.as_slice(), out.stderr.as_slice()].concat(),
        )?;
        if !out.status.success() {
            return Err(format!(
                "systemd-run rejected launch: {}",
                truncate_utf8_bytes(&String::from_utf8_lossy(&out.stderr), 1024)
            ));
        }
        Ok(())
    }
    fn stop(&self, unit: &str) -> Result<(), String> {
        let out = spawn_output_ctx(
            Command::new("systemctl").args(["--user", "stop", unit]),
            "systemctl stop",
        )?;
        let observed = self.inspect(unit)?;
        if !matches!(
            observed.state()?,
            UnitState::Missing | UnitState::Dead | UnitState::Failed
        ) {
            return Err(format!(
                "unit {unit} is not confirmed stopped ({})",
                out.status
            ));
        }
        Ok(())
    }
    fn reset_failed(&self, unit: &str) -> Result<(), String> {
        let out = spawn_output_ctx(
            Command::new("systemctl").args(["--user", "reset-failed", unit]),
            "systemctl reset-failed",
        )?;
        if !out.status.success() && self.inspect(unit)?.state()? != UnitState::Missing {
            return Err("reset-failed failed".into());
        }
        Ok(())
    }
    fn list_units(&self) -> Result<Vec<String>, String> {
        let out = spawn_output_ctx(
            Command::new("systemctl").args([
                "--user",
                "list-units",
                "--all",
                "zach-stage-*",
                "--no-legend",
                "--plain",
                "--no-pager",
            ]),
            "systemctl list-units",
        )?;
        if !out.status.success() {
            return Err("cannot enumerate worker units".into());
        }
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| {
                l.split_whitespace()
                    .find(|p| p.starts_with("zach-stage-"))
                    .map(str::to_owned)
            })
            .collect())
    }
}

pub fn prepare_detached_launch(
    state_dir: &std::path::Path,
    task: &TaskRecord,
    attempt_id: &str,
    route: &StageRoute,
    spec: StageCommandSpec,
) -> Result<PreparedLaunch, String> {
    validate_stage_isolation_spec(task, route, &spec)?;
    validate_attempt_id(attempt_id)?;
    isolation::secure_parents(state_dir)?;
    let state_path = ensure_secure_dir(state_dir)?;
    let state = std::fs::canonicalize(&state_path)
        .map_err(|e| path_io_err("canonicalizing state dir", &state_path, e))?;
    let root = ensure_secure_dir(&state.join("attempts"))?;
    let dir = ensure_secure_dir(&root.join(attempt_id))?;
    let result = prepare_detached_launch_in_dir(&state, &dir, task, attempt_id, route, spec);
    if let Err(ref err) = result {
        write_supervisor_error_log(
            &dir,
            task.current_stage.as_deref().or(Some("prepare")),
            None,
            err,
        );
    }
    result
}

fn prepare_detached_launch_in_dir(
    state: &std::path::Path,
    dir: &std::path::Path,
    task: &TaskRecord,
    attempt_id: &str,
    route: &StageRoute,
    mut spec: StageCommandSpec,
) -> Result<PreparedLaunch, String> {
    let worktree_input = std::path::Path::new(&spec.worktree_path);
    let worktree = std::fs::canonicalize(worktree_input)
        .map_err(|e| path_io_err("canonicalizing worktree", worktree_input, e))?;
    if state.starts_with(&worktree) {
        return Err(
            "isolation policy: daemon state directory must be outside the worker worktree".into(),
        );
    }
    spec.worktree_path = worktree.to_string_lossy().into_owned();
    for arg in &mut spec.args {
        if arg.starts_with("--working-directory=") {
            *arg = format!("--working-directory={}", spec.worktree_path);
        }
    }
    let sha_before = git_head_sha(&spec.worktree_path).ok_or("cannot resolve sha_before")?;
    write_secure_file(&dir.join("prompt.md"), spec.prompt.as_bytes())?;
    let (_, bootstrap_meta) =
        crate::v2::pipeline::resolve_stage_bootstrap(task, &route.stage, &spec.worktree_path);
    if let Ok(bootstrap_bytes) = serde_json::to_vec_pretty(&bootstrap_meta) {
        let _ = write_secure_file(&dir.join("bootstrap.json"), &bootstrap_bytes);
    }
    write_secure_file(&dir.join("stdin"), spec.stdin_payload.as_bytes())?;
    for name in ["stdout.jsonl", "stderr.log"] {
        write_secure_file(&dir.join(name), b"")?;
    }
    let home = PathBuf::from(spec.env.get("HOME").ok_or("missing HOME")?);
    if spec.writable {
        prepare_web_node_modules(&home, &worktree)?;
    }
    let mut resources = PreparedResources::prepare(
        dir,
        &home,
        &worktree,
        spec.writable,
        Some(route.family),
        spec.network,
    )?;
    if let Some(schema) = &spec.output_schema_json {
        let path = dir.join("review-schema.json");
        write_secure_file(&path, schema.as_bytes())?;
        let driver = worker_driver(route.family);
        resources.layout.readonly_files.push(path.clone());
        spec.args = driver.attach_output_schema(&spec.args, &path);
    }
    spec.args = replace_sandbox_args(&spec.args, &resources.layout)?;
    let separator = spec
        .args
        .iter()
        .position(|a| a == "--")
        .ok_or("missing supervisor separator")?;
    let mut io = Vec::new();
    for (property, file) in [
        ("StandardInput", "stdin"),
        ("StandardOutput", "stdout.jsonl"),
        ("StandardError", "stderr.log"),
    ] {
        let io_path = dir.join(file);
        let path = std::fs::canonicalize(&io_path)
            .map_err(|e| path_io_err("canonicalizing attempt file", &io_path, e))?;
        io.extend([
            "-p".to_owned(),
            format!("{property}=file:{}", path.display()),
        ]);
    }
    spec.args.splice(separator..separator, io);
    spec.prompt.clear();
    spec.stdin_payload.clear();
    let manifest = AttemptManifest {
        mount_layout_version: 1,
        attempt_id: attempt_id.into(),
        task_id: task.task_id.clone(),
        route: route.clone(),
        spec,
        sha_before,
        attempt_dir: dir.to_path_buf(),
    };
    let manifest_path = dir.join("manifest.json");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| path_io_err("serializing attempt manifest", &manifest_path, e))?;
    write_secure_file(&manifest_path, &manifest_bytes)?;
    // Preparation is not allowed to destroy resources after an uncertain handoff.
    resources.retain();
    Ok(PreparedLaunch {
        manifest,
        resources,
    })
}

/// Ensures `web/node_modules` is available offline for writable worktree stages
/// and checks when `web/package.json` is present.
pub fn prepare_web_node_modules(
    home: &std::path::Path,
    worktree: &std::path::Path,
) -> Result<(), String> {
    let web_dir = worktree.join("web");
    if !std::fs::symlink_metadata(&web_dir).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
    {
        return Ok(());
    }
    let pkg = web_dir.join("package.json");
    if !std::fs::symlink_metadata(&pkg).is_ok_and(|m| m.is_file() && !m.file_type().is_symlink()) {
        return Ok(());
    }
    let dst = web_dir.join("node_modules");
    match std::fs::symlink_metadata(&dst) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(format!(
                "web/node_modules symlink rejected: {}",
                dst.display()
            ));
        }
        Ok(meta) if meta.is_dir() && isolation::dir_is_non_empty(&dst) => {
            return Ok(());
        }
        Ok(meta) if !meta.is_dir() => return Ok(()),
        _ => {}
    }
    if isolation::discover_web_node_modules_mount(worktree, true)?.is_some() {
        return Ok(());
    }
    let lock = web_dir.join("package-lock.json");
    if !std::fs::symlink_metadata(&lock).is_ok_and(|m| m.is_file() && !m.file_type().is_symlink()) {
        return Ok(());
    }
    let fnm_npm = home.join(".local/share/fnm/aliases/default/bin/npm");
    let npm_bin = if fnm_npm.is_file() {
        fnm_npm
    } else {
        PathBuf::from("npm")
    };
    let env = isolation::sandbox_env(home);
    let output = Command::new(&npm_bin)
        .args([
            "ci",
            "--offline",
            "--no-audit",
            "--no-fund",
            "--prefix",
            "web",
        ])
        .current_dir(worktree)
        .env_clear()
        .envs(&env)
        .stdin(Stdio::null())
        .output();
    if !matches!(output, Ok(out) if out.status.success())
        && std::fs::symlink_metadata(&dst).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
    {
        let _ = std::fs::remove_dir_all(&dst);
    }
    Ok(())
}

pub fn read_attempt_manifest(
    state_dir: &std::path::Path,
    attempt_id: &str,
) -> Result<AttemptManifest, String> {
    validate_attempt_id(attempt_id)?;
    let attempt_path = state_dir.join("attempts").join(attempt_id);
    let dir = std::fs::canonicalize(&attempt_path)
        .map_err(|e| path_io_err("canonicalizing attempt dir", &attempt_path, e))?;
    isolation::reject_symlink_components(&dir)?;
    let path = dir.join("manifest.json");
    isolation::reject_symlink_components(&path)?;
    use std::os::unix::fs::MetadataExt;
    let directory_meta =
        std::fs::metadata(&dir).map_err(|e| path_io_err("reading metadata", &dir, e))?;
    let file_meta =
        std::fs::symlink_metadata(&path).map_err(|e| path_io_err("reading metadata", &path, e))?;
    if !file_meta.is_file()
        || file_meta.uid() != unsafe { libc::geteuid() }
        || file_meta.mode() & 0o077 != 0
        || directory_meta.uid() != unsafe { libc::geteuid() }
        || directory_meta.mode() & 0o077 != 0
    {
        return Err("unsafe attempt manifest ownership or permissions".into());
    }
    let bytes =
        std::fs::read(&path).map_err(|e| path_io_err("reading attempt manifest", &path, e))?;
    let manifest: AttemptManifest = serde_json::from_slice(&bytes)
        .map_err(|e| path_io_err("parsing attempt manifest", &path, e))?;
    if manifest.attempt_id != attempt_id
        || manifest.attempt_dir != dir
        || manifest.mount_layout_version != 1
    {
        return Err("incompatible attempt manifest / legacy socket mount".into());
    }
    Ok(manifest)
}

pub fn sample_attempt(
    manifest: &AttemptManifest,
    mut observation: UnitObservation,
) -> UnitObservation {
    observation.output_bytes = ["stdout.jsonl", "stderr.log"]
        .iter()
        .filter_map(|f| std::fs::metadata(manifest.attempt_dir.join(f)).ok())
        .map(|m| m.len())
        .sum();
    if observation.control_group.starts_with('/')
        && !observation.control_group.split('/').any(|s| s == "..")
    {
        let path = format!("/sys/fs/cgroup{}/cpu.stat", observation.control_group);
        observation.cpu_usage_usec = std::fs::read_to_string(path).ok().and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("usage_usec ").and_then(|n| n.parse().ok()))
        });
    }
    observation
}

pub fn harvest_detached(
    manifest: &AttemptManifest,
    observation: &UnitObservation,
) -> Result<StageExecutionResult, String> {
    let stdout_path = manifest.attempt_dir.join("stdout.jsonl");
    let stdout = std::fs::read_to_string(&stdout_path)
        .map_err(|e| path_io_err("reading stdout", &stdout_path, e))?;
    let stderr_path = manifest.attempt_dir.join("stderr.log");
    let stderr = std::fs::read_to_string(&stderr_path)
        .map_err(|e| path_io_err("reading stderr", &stderr_path, e))?;
    let code = if observation.success() {
        Some(0)
    } else {
        Some(observation.exit_code.unwrap_or(1).max(1))
    };
    let is_systemd_timeout = observation.result.trim().eq_ignore_ascii_case("timeout");
    let effective_stderr = if is_systemd_timeout
        && !stderr.contains("timed out")
        && !stderr.contains("TIMEOUT")
        && !stderr.contains("RuntimeMaxSec")
    {
        if stderr.trim().is_empty() {
            "systemd unit timed out (Result=timeout RuntimeMaxSec)".to_owned()
        } else {
            format!(
                "{}\nsystemd unit timed out (Result=timeout RuntimeMaxSec)",
                stderr.trim_end()
            )
        }
    } else {
        stderr.clone()
    };
    let driver = worker_driver(manifest.route.family);
    let mut result = driver.parse_output(&stdout, &effective_stderr, code, is_systemd_timeout)?;
    if manifest.route.stage == "impl"
        && result.status == "PASSED"
        && let Err(rejection) = crate::v2::pipeline::validate_impl_execution_result(&result)
    {
        result.status = "FAILED".to_owned();
        result.summary = truncate_utf8_bytes(&rejection, MAX_SUMMARY_BYTES);
    }
    result.sha_before = Some(manifest.sha_before.clone());
    result.sha_after = git_head_sha(&manifest.spec.worktree_path);
    result.invocation_id =
        (!observation.invocation_id.is_empty()).then(|| observation.invocation_id.clone());
    result.diff_files = collect_worktree_diff_entries(&manifest.spec.worktree_path);
    let failure_class = if result.status == "PASSED" {
        None
    } else if is_systemd_timeout {
        Some("TIMEOUT")
    } else if manifest.route.stage == "impl"
        && result
            .summary
            .to_ascii_lowercase()
            .contains("impl_validation_failed:")
    {
        Some(crate::v2::pipeline::FAILURE_CLASS_SEMANTIC)
    } else {
        Some("STAGE_FAILED")
    };
    let receipt = build_stage_receipt_v1(
        &manifest.task_id,
        &manifest.attempt_id,
        &manifest.route,
        &result,
        failure_class,
    );
    let _ = write_stage_receipt_json(&manifest.attempt_dir, &receipt);
    let harvest_path = manifest.attempt_dir.join("harvest.json");
    let harvest_bytes = serde_json::to_vec(&result)
        .map_err(|e| path_io_err("serializing harvest", &harvest_path, e))?;
    write_secure_file(&harvest_path, &harvest_bytes)?;
    Ok(result)
}

/// Caller persists HARVESTED before invoking this function. Failure retains files.
pub fn stop_and_cleanup(
    controller: &dyn UnitController,
    unit: &str,
    dir: &std::path::Path,
    resources: Option<PreparedResources>,
    failed: bool,
) -> Result<(), String> {
    controller.stop(unit)?;
    if failed {
        controller.reset_failed(unit)?;
    }
    match controller.inspect(unit)?.state()? {
        UnitState::Dead | UnitState::Missing | UnitState::Failed => {}
        _ => return Err("cleanup refused while execution remains".into()),
    }
    if std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir()) {
        let _ = crate::v2::audit::extract_and_write_attempt_audit(dir);
    }
    if let Some(resources) = resources {
        resources.cleanup_after_stop()?;
    }
    for name in ["codex-home", "gemini-home", "net"] {
        let path = dir.join(name);
        isolation::reject_symlink_components(&path)?;
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(path_io_err("removing attempt subdir", &path, e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_executor(state: impl Into<PathBuf>) -> SystemdStageExecutor {
        let mut executor =
            SystemdStageExecutor::with_state_dir(state).with_isolation_checker(|| Ok(()));
        executor.fixture_transport = true;
        executor
    }

    use crate::v2::router::resolve_stage_route;
    use crate::v2::store::{ContextPackSpec, TaskMemory};

    fn sample_task() -> TaskRecord {
        TaskRecord {
            task_id: "ZACH-005".to_owned(),
            task_group: "zach".to_owned(),
            title: "Stage runner".to_owned(),
            repository: "zach".to_owned(),
            github_repo: Some("shockerqt/zach".to_owned()),
            issue_number: Some(5),
            weight: "S".to_owned(),
            status: "Ready".to_owned(),
            worktree_path: Some("/home/ubuntu/workspace/zach--ZACH-005".to_owned()),
            branch: Some("task/ZACH-005".to_owned()),
            context_pack: ContextPackSpec::default(),
            depends_on: Vec::new(),
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
    fn isolation_preflight_rejects_stages_and_checks_before_any_side_effects() {
        let root = TempTestDir::new("isolation-rejected");
        let state = root.path().join("uncreated");
        let task = sample_task();
        let route = resolve_stage_route("S", "impl", 0, None).unwrap().unwrap();
        let spec =
            build_systemd_stage_command_with_env(&task, "rejected", &route, "p", &BTreeMap::new())
                .unwrap();
        let mut executor = SystemdStageExecutor::with_state_dir(&state)
            .with_isolation_checker(|| Err("forbidden policy diagnostic".into()));
        let error = executor
            .execute_stage(&task, "rejected", &route, &spec)
            .unwrap_err();
        assert!(error.starts_with("ISOLATION_PREFLIGHT_FAILED"));
        assert_eq!(
            crate::v2::pipeline::classify_failure_class("impl", "FAILED", &error),
            "infra"
        );
        assert_eq!(
            executor
                .run_checks("/missing", &["touch marker".into()])
                .unwrap_err(),
            error
        );
        assert_eq!(executor.run_checks("/missing", &[]).unwrap_err(), error);
        assert!(!state.exists());
    }

    #[test]
    fn production_transport_cannot_be_replaced_with_a_host_subprocess() {
        let root = TempTestDir::new("isolation-transport");
        let mut executor =
            SystemdStageExecutor::with_state_dir(root.path()).with_isolation_checker(|| Ok(()));
        let task = sample_task();
        let route = resolve_stage_route("S", "impl", 0, None).unwrap().unwrap();
        let mut spec =
            build_systemd_stage_command_with_env(&task, "transport", &route, "p", &BTreeMap::new())
                .unwrap();
        spec.program = "/usr/bin/touch".into();
        let marker = root.path().join("escaped");
        spec.args = vec![marker.display().to_string()];
        assert_eq!(
            executor
                .execute_stage(&task, "transport", &route, &spec)
                .unwrap_err(),
            "invalid worker supervisor"
        );
        assert!(!marker.exists());
    }

    #[test]
    fn stage_declarations_are_pure_network_validated_and_readonly_except_impl() {
        let mut task = sample_task();
        // This deliberately nonexistent path must never be inspected by planning.
        task.worktree_path = Some("/does-not-exist/zach-task".into());
        for stage in ["plan", "plan-review", "impl", "pr-review"] {
            let route = resolve_stage_route("M", stage, 0, Some(ModelFamily::OpenAiSol))
                .unwrap()
                .unwrap();
            let spec = build_systemd_stage_command_with_env(
                &task,
                "pure",
                &route,
                "prompt",
                &BTreeMap::new(),
            )
            .unwrap();
            assert_eq!(spec.writable, stage == "impl");
            assert_eq!(spec.network, NetworkPolicy::ProviderApi(route.family));
            task.context_pack.network = Some("none".into());
            let offline = build_systemd_stage_command_with_env(
                &task,
                "offline",
                &route,
                "p",
                &BTreeMap::new(),
            )
            .unwrap();
            assert_eq!(offline.network, NetworkPolicy::None);
            task.context_pack.network = None;
        }
        task.context_pack.network = Some("all".into());
        let route = resolve_stage_route("S", "impl", 0, None).unwrap().unwrap();
        assert!(
            build_systemd_stage_command_with_env(&task, "bad", &route, "p", &BTreeMap::new())
                .is_err()
        );
    }

    #[test]
    fn runtime_schema_injection_keeps_cli_path_and_exact_readonly_mount() {
        let task = sample_task();
        let route = resolve_stage_route("S", "impl", 0, None).unwrap().unwrap();
        let spec =
            build_systemd_stage_command_with_env(&task, "schema", &route, "p", &BTreeMap::new())
                .unwrap();
        let schema = std::path::Path::new("/tmp/state/attempts/schema/review-schema.json");
        let args = inject_codex_output_schema_args(&spec.args, schema);
        let mut layout = SandboxLayout::declared(
            std::path::Path::new("/home/ubuntu"),
            std::path::Path::new(&spec.worktree_path),
            false,
        );
        layout.readonly_files.push(schema.into());
        let args = replace_sandbox_args(&args, &layout).unwrap();
        assert!(
            args.windows(3).any(|a| a[0] == "--ro-bind"
                && a[1] == schema.display().to_string()
                && a[2] == a[1])
        );
        assert!(
            args.windows(2)
                .any(|a| a[0] == "--output-schema" && a[1] == schema.display().to_string())
        );
        assert_eq!(args.last().unwrap(), "-");
        assert_eq!(
            args.iter()
                .filter(|a| a.as_str() == "/usr/bin/bwrap")
                .count(),
            1
        );
    }

    fn codex_test_route(stage: &str) -> StageRoute {
        let mut route = resolve_stage_route("M", stage, 0, None).unwrap().unwrap();
        route.family = ModelFamily::OpenAiSol;
        route.model = "gpt-6.1-sol".into();
        route
    }

    fn assert_external_codex_envelope(spec: &StageCommandSpec, stage: &str) {
        assert_eq!(spec.program, "systemd-run");
        let outer = spec.args.iter().position(|a| a == "--").unwrap();
        assert_eq!(spec.args[outer + 1], "/usr/bin/bwrap");
        assert_eq!(spec.args[outer + 2], "--unshare-all");
        let codex = spec.args.iter().position(|a| a == "codex").unwrap();
        let external = spec
            .args
            .iter()
            .position(|a| a == "--dangerously-bypass-approvals-and-sandbox")
            .unwrap();
        assert!(external > codex && codex > outer + 2);
        assert_eq!(
            spec.args
                .iter()
                .filter(|a| *a == "--dangerously-bypass-approvals-and-sandbox")
                .count(),
            1
        );
        assert!(!spec.args.iter().any(|a| matches!(
            a.as_str(),
            "-s" | "--sandbox" | "workspace-write" | "--approve-for-me"
        )));
        assert!(spec.args.contains(&"--ignore-user-config".into()));
        assert!(spec.args.contains(&"--slice=zach-workers.slice".into()));
        assert!(spec.args.contains(&"KillMode=control-group".into()));
        assert!(spec.args.windows(2).any(|a| a == ["--tmpfs", "/home"]));
        assert_eq!(spec.writable, stage == "impl");
        let bind = if spec.writable { "--bind" } else { "--ro-bind" };
        assert!(
            spec.args.windows(3).any(|a| {
                a[0] == bind && a[1] == spec.worktree_path && a[2] == spec.worktree_path
            })
        );
        assert_eq!(spec.args.last().unwrap(), "-");
        assert_eq!(
            spec.output_schema_json.is_some(),
            matches!(stage, "plan-review" | "pr-review")
        );
    }

    #[test]
    fn codex_external_mode_stays_inside_outer_envelope_for_all_stages() {
        let task = sample_task();
        for stage in ["plan", "plan-review", "impl", "pr-review"] {
            let route = codex_test_route(stage);
            let spec = build_systemd_stage_command_with_env(
                &task,
                stage,
                &route,
                "prompt only on stdin",
                &BTreeMap::new(),
            )
            .unwrap();
            validate_stage_isolation_spec(&task, &route, &spec).unwrap();
            assert_external_codex_envelope(&spec, stage);
            assert_eq!(spec.stdin_payload, "prompt only on stdin");
            assert!(!spec.args.iter().any(|a| a.contains("prompt only on stdin")));
            let layout = SandboxLayout::declared(
                std::path::Path::new("/home/ubuntu"),
                std::path::Path::new(&spec.worktree_path),
                spec.writable,
            );
            let mut replaced = spec.clone();
            replaced.args = replace_sandbox_args(&spec.args, &layout).unwrap();
            assert_external_codex_envelope(&replaced, stage);
        }
    }

    #[test]
    fn malformed_stage_specs_fail_both_paths_before_attempt_or_auth_staging() {
        let root = TempTestDir::new("zach042-preflight");
        let home = root.path().join("synthetic-home");
        ensure_secure_dir(&home).unwrap();
        ensure_secure_dir(&home.join(".codex")).unwrap();
        write_secure_file(&home.join(".codex/auth.json"), b"synthetic-auth").unwrap();
        for stage in ["impl", "plan"] {
            for case in [
                "supervisor",
                "write-mode",
                "network",
                "missing-wrapper",
                "misplaced-wrapper",
                "missing-worker-separator",
            ] {
                let mut task = sample_task();
                task.context_pack.network = Some("none".into());
                let route = codex_test_route(stage);
                let env = BTreeMap::from([("HOME".into(), home.display().to_string())]);
                let mut spec = build_systemd_stage_command_with_env(
                    &task,
                    "invalid",
                    &route,
                    "must never be staged",
                    &env,
                )
                .unwrap();
                let outer = spec.args.iter().position(|a| a == "--").unwrap();
                let expected = match case {
                    "supervisor" => {
                        spec.program = "/usr/bin/touch".into();
                        "invalid worker supervisor"
                    }
                    "write-mode" => {
                        spec.writable = !spec.writable;
                        "stage isolation declaration mismatch"
                    }
                    "network" => {
                        spec.network = NetworkPolicy::ProviderApi(route.family);
                        "stage isolation declaration mismatch"
                    }
                    "missing-wrapper" => {
                        spec.args.remove(outer + 1);
                        "missing bubblewrap wrapper"
                    }
                    "misplaced-wrapper" => {
                        spec.args.insert(outer + 1, "/usr/bin/true".into());
                        "missing bubblewrap wrapper"
                    }
                    _ => {
                        let separator = spec.args.iter().rposition(|a| a == "--").unwrap();
                        spec.args.remove(separator);
                        "missing sandbox separator"
                    }
                };
                let state = root.path().join(format!("uncreated-{stage}-{case}"));
                let mut direct =
                    SystemdStageExecutor::with_state_dir(&state).with_isolation_checker(|| Ok(()));
                assert_eq!(
                    direct
                        .execute_stage(&task, "invalid", &route, &spec)
                        .unwrap_err(),
                    expected
                );
                assert!(!state.exists());
                let error = prepare_detached_launch(&state, &task, "invalid", &route, spec)
                    .err()
                    .expect("invalid detached spec must refuse");
                assert_eq!(error, expected);
                assert!(!state.exists());
                assert_eq!(
                    std::fs::read(home.join(".codex/auth.json")).unwrap(),
                    b"synthetic-auth"
                );
            }
        }
    }

    #[test]
    fn detached_codex_all_stages_preserve_external_mode_mounts_and_schema_without_launch() {
        let root = TempTestDir::new("zach042-detached");
        let home = root.path().join("home");
        ensure_secure_dir(&home).unwrap();
        ensure_secure_dir(&home.join(".codex")).unwrap();
        write_secure_file(&home.join(".codex/auth.json"), b"{}").unwrap();
        let worker = root.path().join("worker");
        assert!(
            Command::new("git")
                .args([
                    "clone",
                    "--quiet",
                    "--shared",
                    "--no-checkout",
                    env!("CARGO_MANIFEST_DIR")
                ])
                .arg(&worker)
                .status()
                .unwrap()
                .success()
        );
        let mut task = sample_task();
        task.worktree_path = Some(worker.display().to_string());
        task.context_pack.network = Some("none".into());
        let env = BTreeMap::from([("HOME".into(), home.display().to_string())]);
        for stage in ["plan", "plan-review", "impl", "pr-review"] {
            let route = codex_test_route(stage);
            let spec = build_systemd_stage_command_with_env(
                &task,
                stage,
                &route,
                "synthetic prompt",
                &env,
            )
            .unwrap();
            let PreparedLaunch {
                manifest,
                resources,
            } = prepare_detached_launch(&root.path().join("state"), &task, stage, &route, spec)
                .unwrap();
            assert_external_codex_envelope(&manifest.spec, stage);
            assert_eq!(manifest.spec.network, NetworkPolicy::None);
            assert!(manifest.attempt_dir.join("codex-home/auth.json").exists());
            assert!(manifest.spec.args.windows(3).any(|a| {
                a[0] == "--ro-bind"
                    && a[1] == worker.join(".git").display().to_string()
                    && a[1] == a[2]
            }));
            if manifest.spec.output_schema_json.is_some() {
                let schema = manifest
                    .attempt_dir
                    .join("review-schema.json")
                    .display()
                    .to_string();
                assert!(
                    manifest
                        .spec
                        .args
                        .windows(2)
                        .any(|a| { a[0] == "--output-schema" && a[1] == schema })
                );
                assert!(
                    manifest
                        .spec
                        .args
                        .windows(3)
                        .any(|a| { a[0] == "--ro-bind" && a[1] == schema && a[2] == schema })
                );
            }
            resources.cleanup_after_stop().unwrap();
        }
    }

    #[test]
    fn clean_env_strips_tokens_and_secrets_and_systemd_command_isolates_credentials() {
        let dirty_env = vec![
            ("HOME".to_owned(), "/home/ubuntu".to_owned()),
            ("USER".to_owned(), "ubuntu".to_owned()),
            ("GH_TOKEN".to_owned(), "ghp_secret123".to_owned()),
            ("GITHUB_TOKEN".to_owned(), "ghs_secret456".to_owned()),
            ("OPENAI_API_KEY".to_owned(), "sk-secret".to_owned()),
            ("AWS_SECRET_ACCESS_KEY".to_owned(), "aws-secret".to_owned()),
            ("CODEX_HOME".to_owned(), "/home/ubuntu/.codex".to_owned()),
        ];
        let clean = build_clean_env(&dirty_env);
        assert!(!clean.contains_key("GH_TOKEN"));
        assert!(!clean.contains_key("GITHUB_TOKEN"));
        assert!(!clean.contains_key("OPENAI_API_KEY"));
        assert!(!clean.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert_eq!(clean.get("HOME").map(String::as_str), Some("/home/ubuntu"));
        assert_eq!(
            clean.get("CODEX_HOME").map(String::as_str),
            Some("/home/ubuntu/.codex")
        );

        let task = sample_task();
        let route = resolve_stage_route("S", "impl", 0, None).unwrap().unwrap();
        let spec =
            build_systemd_stage_command_with_env(&task, "att-1", &route, "Prompt text", &clean)
                .expect("build systemd spec");

        assert_eq!(spec.program, "systemd-run");
        assert_eq!(spec.unit_name, "zach-stage-zach-005-impl-att-1");
        assert!(spec.args.contains(&"--slice=zach-workers.slice".to_owned()));
        assert!(spec.args.contains(&"KillMode=control-group".to_owned()));
        assert!(spec.args.contains(&"/usr/bin/bwrap".to_owned()));
        assert!(spec.args.contains(&"--unshare-all".to_owned()));
        assert!(spec.args.windows(2).any(|a| a == ["--tmpfs", "/home"]));
        assert!(spec.args.contains(&"codex".to_owned()));
        assert!(spec.args.contains(&"--ignore-user-config".to_owned()));
        assert_eq!(spec.args.last().map(String::as_str), Some("-"));
        assert!(!spec.args.iter().any(|a| a.contains("Prompt text")));
        assert_eq!(spec.prompt, "Prompt text");
        assert_eq!(spec.stdin_payload, "Prompt text");
    }

    #[test]
    fn token_budget_and_orphan_unit_detection_work_as_expected() {
        let mut task = sample_task();
        let route = resolve_stage_route("XS", "impl", 0, None).unwrap().unwrap();
        assert_eq!(check_token_budget(&task, &route).unwrap(), 150_000);

        task.memory
            .token_usage_by_stage
            .insert("impl".to_owned(), 150_000);
        assert!(check_token_budget(&task, &route).is_err());

        let systemctl_out = "\
zach-stage-zach-005-impl-att-1.service loaded active running
zach-stage-lumi-007-impl-att-9.service loaded active running
other-user-unit.service loaded active running
";
        let mut active = BTreeSet::new();
        active.insert("zach-stage-zach-005-impl-att-1".to_owned());
        let orphans = parse_orphan_units(systemctl_out, &active);
        assert_eq!(orphans, vec!["zach-stage-lumi-007-impl-att-9".to_owned()]);
    }

    #[test]
    fn gemini_worker_timeout_is_clamped_to_3600_and_systemd_has_grace() {
        let task = sample_task();
        let mut route = resolve_stage_route("M", "impl", 0, None).unwrap().unwrap();
        route.family = ModelFamily::GeminiAgy;
        route.model = "gemini-4-hydrogen-high".to_owned();
        route.timeout_secs = 3600;

        let clean_env = BTreeMap::new();
        let secret_prompt = "prompt with sensitive instructions";
        let spec = build_systemd_stage_command_with_env(
            &task,
            "att-gemini",
            &route,
            secret_prompt,
            &clean_env,
        )
        .expect("build command");

        assert!(
            !spec
                .args
                .iter()
                .any(|a| a == "--dangerously-bypass-approvals-and-sandbox")
        );
        assert!(spec.args.contains(&"--no-block".to_owned()));
        assert!(spec.args.contains(&"RemainAfterExit=yes".to_owned()));
        assert!(spec.args.contains(&"CollectMode=inactive".to_owned()));
        assert!(spec.args.contains(&"--service-type=exec".to_owned()));
        assert!(
            spec.args.contains(&format!(
                "RuntimeMaxSec={}",
                3600 + SYSTEMD_RUNTIME_MAX_GRACE_SECS
            )),
            "expected RuntimeMaxSec=3660, got {:?}",
            spec.args
        );
        assert_eq!(spec.timeout_secs, 3600);
        assert!(
            !spec
                .args
                .iter()
                .any(|a| matches!(a.as_str(), "--wait" | "--pipe" | "--collect"))
        );
        assert!(!spec.args.iter().any(|a| a.contains(secret_prompt)));
        for forbidden_flag in ["--model", "--worktree", "--timeout", "--prompt"] {
            assert!(
                !spec.args.iter().any(|a| a == forbidden_flag),
                "unexpected flag {forbidden_flag} in argv: {:?}",
                spec.args
            );
        }
        assert!(
            spec.args.ends_with(&[
                "node".to_owned(),
                GEMINI_WORKER_CLI_SCRIPT.to_owned(),
                "--cli".to_owned()
            ]),
            "expected trailing node worker.mjs --cli, got {:?}",
            spec.args
        );
        assert_eq!(spec.prompt, secret_prompt);

        let payload: serde_json::Value =
            serde_json::from_str(&spec.stdin_payload).expect("valid JSON stdin_payload");
        assert_eq!(payload["action"], "run");
        assert_eq!(payload["model"], "gemini-4-hydrogen-high");
        assert_eq!(payload["task"], secret_prompt);
        assert_eq!(payload["timeout_seconds"], 3600);
        assert_eq!(payload["orchestration_id"], "zach-005");

        // Verify upper bound clamp (3600) while systemd keeps +60s grace above route.timeout_secs
        route.timeout_secs = 7200;
        let high_spec =
            build_systemd_stage_command_with_env(&task, "att-gemini-high", &route, "p", &clean_env)
                .expect("build high timeout command");
        let high_payload: serde_json::Value =
            serde_json::from_str(&high_spec.stdin_payload).expect("valid JSON");
        assert_eq!(high_payload["timeout_seconds"], 3600);
        assert!(high_spec.args.contains(&format!(
            "RuntimeMaxSec={}",
            7200 + SYSTEMD_RUNTIME_MAX_GRACE_SECS
        )));

        // Also verify lower bound clamp (30) and +60s grace
        route.timeout_secs = 5;
        let low_spec =
            build_systemd_stage_command_with_env(&task, "att-gemini-low", &route, "p", &clean_env)
                .expect("build low timeout command");
        let low_payload: serde_json::Value =
            serde_json::from_str(&low_spec.stdin_payload).expect("valid JSON");
        assert_eq!(low_payload["timeout_seconds"], 30);
        assert!(low_spec.args.contains(&format!(
            "RuntimeMaxSec={}",
            5 + SYSTEMD_RUNTIME_MAX_GRACE_SECS
        )));

        // Verify OpenAiSol route also receives +60s RuntimeMaxSec grace
        let mut codex_route = resolve_stage_route("M", "impl", 0, None).unwrap().unwrap();
        codex_route.family = ModelFamily::OpenAiSol;
        codex_route.timeout_secs = 1800;
        let codex_spec =
            build_systemd_stage_command_with_env(&task, "att-codex", &codex_route, "p", &clean_env)
                .expect("build codex command");
        assert!(codex_spec.args.contains(&format!(
            "RuntimeMaxSec={}",
            1800 + SYSTEMD_RUNTIME_MAX_GRACE_SECS
        )));
        assert_eq!(codex_spec.timeout_secs, 1800);
    }

    #[test]
    fn zach027_plan_artifacts_are_private_symlink_safe_and_publication_fails_closed() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = TempTestDir::new("zach027-plan-publish");
        let script = temp.path().join("ws-task");
        std::fs::write(&script, "#!/usr/bin/env python3\nimport sys,json,pathlib\np=pathlib.Path(__file__)\np.with_suffix('.args').write_text(json.dumps(sys.argv[1:]))\nif p.with_suffix('.fail').exists():\n print('publication rejected',file=sys.stderr)\n sys.exit(37)\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut exec = fixture_executor(temp.path().join("state"));
        exec.ws_task_bin = script.clone();
        let mut task = sample_task();
        let markdown = format!("## [PLAN]\n{}", "full plan é".repeat(500));
        let path = exec
            .persist_plan_artifact(&task, "plan-attempt-123", &markdown)
            .unwrap();
        assert_eq!(exec.read_plan_artifact(&path).unwrap(), markdown);
        for (file, mode) in [
            (&exec.state_dir, 0o700),
            (&exec.state_dir.join("plans"), 0o700),
            (&path, 0o600),
        ] {
            assert_eq!(
                std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
                mode
            );
        }
        for sha in [
            Some("base123"),
            None,
            Some(""),
            Some("  "),
            Some("head-sha"),
        ] {
            task.plan_base_sha = sha.map(str::to_owned);
            exec.publish_plan_stage(&task, &path, &markdown).unwrap();
            let args: Vec<String> = serde_json::from_str(
                &std::fs::read_to_string(script.with_extension("args")).unwrap(),
            )
            .unwrap();
            let mut expected = vec![
                "stage".to_owned(),
                task.task_id.clone(),
                "plan".to_owned(),
                "--actor".to_owned(),
                "zach".to_owned(),
                "--body-file".to_owned(),
                path.to_string_lossy().into_owned(),
            ];
            if sha == Some("base123") {
                expected.extend(["--sha".to_owned(), "base123".to_owned()]);
            }
            expected.extend([
                "--idempotency-key".to_owned(),
                format!("zach-plan-{}-plan-attempt-123", task.task_id),
            ]);
            assert_eq!(args, expected);
        }
        std::fs::write(script.with_extension("fail"), "fail").unwrap();
        assert!(
            exec.publish_plan_stage(&task, &path, &markdown)
                .unwrap_err()
                .contains("publication rejected")
        );
        exec.ws_task_bin = temp.path().join("missing-command");
        assert!(
            exec.publish_plan_stage(&task, &path, &markdown)
                .unwrap_err()
                .contains("failed to publish plan")
        );
        assert!(
            exec.publish_plan_stage(&task, &path, "different body")
                .is_err()
        );
        assert!(
            exec.persist_plan_artifact(&task, "../escape", "bad")
                .is_err()
        );
        let outside = temp.path().join("outside.md");
        std::fs::write(&outside, "original").unwrap();
        std::fs::remove_file(&path).unwrap();
        symlink(&outside, &path).unwrap();
        assert!(exec.read_plan_artifact(&path).is_err());
        assert!(
            exec.persist_plan_artifact(&task, "plan-attempt-123", "overwrite")
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "original");
        let other = TempTestDir::new("zach027-plan-symlink-dir");
        symlink(temp.path().join("state/plans"), other.path().join("plans")).unwrap();
        let mut exec = fixture_executor(other.path());
        assert!(exec.persist_plan_artifact(&task, "other", "bad").is_err());
    }

    #[test]
    fn zach027_systemd_preserves_full_stage_output_for_both_families_and_plan_stages() {
        let temp = TempTestDir::new("zach027-stage-output");
        let task = sample_task();
        let mut exec = fixture_executor(temp.path());
        for family in [ModelFamily::OpenAiSol, ModelFamily::GeminiAgy] {
            for stage in ["plan", "plan-review"] {
                let text = if stage == "plan" {
                    format!("## [PLAN]\n{}", "🦀 useful plan\n".repeat(600))
                } else {
                    serde_json::json!({"verdict":"APPROVED","ac_results":[],"findings":[],"summary":"review é".repeat(600)}).to_string()
                };
                let stdout = match family {
                    ModelFamily::OpenAiSol => format!("{}\n{}\n", serde_json::json!({"type":"item.completed","item":{"type":"agent_message","text":"earlier commentary"}}), serde_json::json!({"type":"item.completed","item":{"type":"agent_message","text":text}})),
                    ModelFamily::GeminiAgy => serde_json::json!({"execution_succeeded":true,"summary":"short worker summary","response":text}).to_string(),
                };
                let mut route =
                    crate::v2::router::resolve_stage_route("M", stage, 0, Some(family.opposite()))
                        .unwrap()
                        .unwrap();
                route.family = family;
                let attempt = format!("{}-{stage}", family.as_str());
                let mut spec =
                    build_systemd_stage_command(&task, &attempt, &route, "read only").unwrap();
                spec.program = "python3".to_owned();
                spec.args = vec![
                    "-c".to_owned(),
                    "import sys; sys.stdout.write(sys.argv[1])".to_owned(),
                    stdout,
                ];
                spec.worktree_path = temp.path_str().to_owned();
                let result = exec.execute_stage(&task, &attempt, &route, &spec).unwrap();
                assert_eq!(result.stage_output.as_deref(), Some(text.as_str()));
                assert_eq!(result.review_output.as_deref(), Some(text.as_str()));
                assert!(result.summary.len() <= MAX_SUMMARY_BYTES);
                let saved: serde_json::Value = serde_json::from_str(
                    &std::fs::read_to_string(
                        temp.path()
                            .join("attempts")
                            .join(&attempt)
                            .join("result.json"),
                    )
                    .unwrap(),
                )
                .unwrap();
                assert_eq!(saved["result"]["stage_output"], text);
                assert_eq!(spec.output_schema_json.is_some(), stage == "plan-review");
            }
        }
    }

    struct TempTestDir(std::path::PathBuf);

    impl TempTestDir {
        fn new(prefix: &str) -> Self {
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("{prefix}-{}-{id}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create temp test dir");
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }

        fn path_str(&self) -> &str {
            self.0.to_str().expect("utf-8 temp path")
        }
    }

    impl Drop for TempTestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn git(dir: &std::path::Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .expect("run git command");
        assert!(
            out.status.success(),
            "git {:?} failed in {}: {}",
            args,
            dir.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn init_git_identity(dir: &std::path::Path) {
        git(dir, &["config", "user.email", "zach-test@example.com"]);
        git(dir, &["config", "user.name", "Zach Test"]);
    }

    fn write_rel(dir: &std::path::Path, rel: &str, contents: &str) {
        let full = dir.join(rel);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).expect("create parent dirs");
        }
        std::fs::write(full, contents).expect("write test file");
    }

    #[test]
    fn collect_worktree_diff_entries_diffs_against_merge_base_with_real_statuses_and_untracked() {
        let root = TempTestDir::new("zach-017-merge-base");
        let origin_dir = root.path().join("origin.git");
        let seed_dir = root.path().join("seed");
        let work_dir = root.path().join("work");
        std::fs::create_dir_all(&origin_dir).unwrap();
        std::fs::create_dir_all(&seed_dir).unwrap();

        git(&origin_dir, &["init", "--bare", "-b", "main"]);
        git(&seed_dir, &["init", "-b", "main"]);
        init_git_identity(&seed_dir);
        write_rel(&seed_dir, ".gitignore", "*.log\n");
        write_rel(&seed_dir, "src/keep.rs", "fn keep() {}\n");
        write_rel(&seed_dir, "src/to_delete.rs", "fn gone() {}\n");
        write_rel(&seed_dir, "src/to_rename.rs", "fn old_name() {}\n");
        git(&seed_dir, &["add", "."]);
        git(&seed_dir, &["commit", "-m", "base commit"]);
        git(
            &seed_dir,
            &["remote", "add", "origin", origin_dir.to_str().unwrap()],
        );
        git(&seed_dir, &["push", "-u", "origin", "main"]);

        let clone_out = Command::new("git")
            .args([
                "clone",
                origin_dir.to_str().unwrap(),
                work_dir.to_str().unwrap(),
            ])
            .output()
            .expect("clone origin");
        assert!(clone_out.status.success());
        init_git_identity(&work_dir);
        git(&work_dir, &["checkout", "-b", "task/zach-017"]);

        // Advance origin/main past the branch point to verify merge-base (not tip) is used.
        write_rel(&seed_dir, "src/other_on_main.rs", "fn unrelated() {}\n");
        git(&seed_dir, &["add", "src/other_on_main.rs"]);
        git(&seed_dir, &["commit", "-m", "advance origin/main"]);
        git(&seed_dir, &["push", "origin", "main"]);
        git(&work_dir, &["fetch", "origin"]);

        // Committed changes on the task branch since merge-base.
        write_rel(
            &work_dir,
            "src/keep.rs",
            "fn keep() {}\nfn committed_1() {}\nfn committed_2() {}\n",
        );
        write_rel(&work_dir, "src/committed_new.rs", "a\nb\nc\n");
        git(&work_dir, &["add", "src/keep.rs", "src/committed_new.rs"]);
        git(&work_dir, &["commit", "-m", "task progress"]);

        // Working tree edits: modify src/keep.rs again (must deduplicate), delete, rename, untracked, ignored.
        write_rel(
            &work_dir,
            "src/keep.rs",
            "fn keep() {}\nfn committed_1() {}\nfn committed_2() {}\nfn dirty_3() {}\n",
        );
        git(&work_dir, &["rm", "src/to_delete.rs"]);
        git(&work_dir, &["mv", "src/to_rename.rs", "src/renamed.rs"]);
        write_rel(&work_dir, "src/untracked_new.rs", "u1\nu2\nu3\nu4\n");
        write_rel(&work_dir, "ignored.log", "should be ignored\n");

        let entries = collect_worktree_diff_entries(work_dir.to_str().unwrap());
        assert_eq!(
            entries,
            vec![
                DiffFileEntry {
                    path: "src/committed_new.rs".to_owned(),
                    status: "A".to_owned(),
                    added_lines: 3,
                    deleted_lines: 0,
                },
                DiffFileEntry {
                    path: "src/keep.rs".to_owned(),
                    status: "M".to_owned(),
                    added_lines: 3,
                    deleted_lines: 0,
                },
                DiffFileEntry {
                    path: "src/renamed.rs".to_owned(),
                    status: "R".to_owned(),
                    added_lines: 0,
                    deleted_lines: 0,
                },
                DiffFileEntry {
                    path: "src/to_delete.rs".to_owned(),
                    status: "D".to_owned(),
                    added_lines: 0,
                    deleted_lines: 1,
                },
                DiffFileEntry {
                    path: "src/untracked_new.rs".to_owned(),
                    status: "A".to_owned(),
                    added_lines: 4,
                    deleted_lines: 0,
                },
            ]
        );
    }

    #[test]
    fn collect_worktree_diff_entries_enforces_forbidden_out_of_scope_and_s_to_m_escalation() {
        use crate::v2::pipeline::{DiffCheckOutcome, verify_worktree_diff_with};
        use crate::v2::store::{ContextPackSpec, TargetFileSpec};
        use std::os::unix::fs::PermissionsExt;

        let root = TempTestDir::new("zach-017-ac");
        let stub_ws_task = root.path().join("ws-task-stub");
        std::fs::write(
            &stub_ws_task,
            r#"#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
assert args[0] == "classify-weight", args
assert "--new-files" in args, args
new_files = int(args[args.index("--new-files") + 1])
escalated = new_files > 0
print(json.dumps({
    "repository": "zach",
    "requested_weight": "S",
    "floor_weight": "M" if escalated else "S",
    "effective_weight": "M" if escalated else "S",
    "escalated": escalated,
    "required_stages": ["plan", "plan-review", "impl", "pr-review"] if escalated else ["impl", "pr-review"],
    "reasons": [f"[M] adds {new_files} new code/config file(s)"] if escalated else ["[S] ok"],
}))
"#,
        )
        .unwrap();
        std::fs::set_permissions(&stub_ws_task, std::fs::Permissions::from_mode(0o755)).unwrap();

        let origin_dir = root.path().join("origin.git");
        let work_dir = root.path().join("work");
        std::fs::create_dir_all(&origin_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();

        git(&origin_dir, &["init", "--bare", "-b", "main"]);
        git(&work_dir, &["init", "-b", "main"]);
        init_git_identity(&work_dir);
        write_rel(&work_dir, "src/v2/runner.rs", "fn base() {}\n");
        git(&work_dir, &["add", "."]);
        git(&work_dir, &["commit", "-m", "initial"]);
        git(
            &work_dir,
            &["remote", "add", "origin", origin_dir.to_str().unwrap()],
        );
        git(&work_dir, &["push", "-u", "origin", "main"]);
        // Ensure origin/HEAD is absent so origin/main fallback is also exercised.
        let _ = Command::new("git")
            .arg("-C")
            .arg(&work_dir)
            .args(["remote", "set-head", "origin", "-d"])
            .output();
        git(&work_dir, &["checkout", "-b", "task/zach-017"]);

        let pack = ContextPackSpec {
            weight: "S".to_owned(),
            target_files: vec![TargetFileSpec {
                path: "src/v2/**".to_owned(),
                action: "modify".to_owned(),
                summary: "runner changes".to_owned(),
            }],
            forbidden_paths: vec![
                "src/ledger/**".to_owned(),
                ".github/workflows/**".to_owned(),
            ],
            ..ContextPackSpec::default()
        };

        // AC-1a: new untracked file under .github/workflows/** -> status "A" -> ForbiddenPathViolation
        write_rel(
            &work_dir,
            ".github/workflows/ci.yml",
            "name: CI\non: push\n",
        );
        let entries = collect_worktree_diff_entries(work_dir.to_str().unwrap());
        assert!(
            entries
                .iter()
                .any(|e| e.path == ".github/workflows/ci.yml" && e.status == "A")
        );
        assert_eq!(
            verify_worktree_diff_with("zach", "S", &pack, &entries, &stub_ws_task).unwrap(),
            DiffCheckOutcome::ForbiddenPathViolation {
                path: ".github/workflows/ci.yml".to_owned(),
                pattern: ".github/workflows/**".to_owned(),
            }
        );
        std::fs::remove_file(work_dir.join(".github/workflows/ci.yml")).unwrap();

        // AC-1b: new untracked file under src/ledger/** -> status "A" -> ForbiddenPathViolation
        write_rel(&work_dir, "src/ledger/x.rs", "pub fn x() {}\n");
        let entries = collect_worktree_diff_entries(work_dir.to_str().unwrap());
        assert!(
            entries
                .iter()
                .any(|e| e.path == "src/ledger/x.rs" && e.status == "A")
        );
        assert_eq!(
            verify_worktree_diff_with("zach", "S", &pack, &entries, &stub_ws_task).unwrap(),
            DiffCheckOutcome::ForbiddenPathViolation {
                path: "src/ledger/x.rs".to_owned(),
                pattern: "src/ledger/**".to_owned(),
            }
        );
        std::fs::remove_file(work_dir.join("src/ledger/x.rs")).unwrap();

        // AC-2: new untracked file outside target_files -> OutOfScopeFiles
        write_rel(&work_dir, "src/outside.rs", "pub fn outside() {}\n");
        let entries = collect_worktree_diff_entries(work_dir.to_str().unwrap());
        assert_eq!(
            verify_worktree_diff_with("zach", "S", &pack, &entries, &stub_ws_task).unwrap(),
            DiffCheckOutcome::OutOfScopeFiles {
                files: vec!["src/outside.rs".to_owned()],
            }
        );
        std::fs::remove_file(work_dir.join("src/outside.rs")).unwrap();

        // AC-3: new untracked file inside target_files counts towards created_files -> S escalates to M
        write_rel(
            &work_dir,
            "src/v2/new_helper.rs",
            "pub fn one() {}\npub fn two() {}\n",
        );
        let entries = collect_worktree_diff_entries(work_dir.to_str().unwrap());
        assert_eq!(
            entries,
            vec![DiffFileEntry {
                path: "src/v2/new_helper.rs".to_owned(),
                status: "A".to_owned(),
                added_lines: 2,
                deleted_lines: 0,
            }]
        );
        match verify_worktree_diff_with("zach", "S", &pack, &entries, &stub_ws_task).unwrap() {
            DiffCheckOutcome::WeightEscalated {
                from_weight,
                to_weight,
                required_stages,
                ..
            } => {
                assert_eq!(from_weight, "S");
                assert_eq!(to_weight, "M");
                assert_eq!(
                    required_stages,
                    vec!["plan", "plan-review", "impl", "pr-review"]
                );
            }
            other => panic!("expected WeightEscalated S -> M, got {other:?}"),
        }
    }

    #[test]
    fn collect_worktree_diff_entries_falls_back_to_head_and_parses_copy_rename_z_outputs() {
        let repo = TempTestDir::new("zach-017-fallback");
        git(repo.path(), &["init", "-b", "master"]);
        init_git_identity(repo.path());
        write_rel(repo.path(), "tracked.txt", "line1\n");
        git(repo.path(), &["add", "tracked.txt"]);
        git(repo.path(), &["commit", "-m", "initial"]);

        write_rel(repo.path(), "tracked.txt", "line1\nline2\n");
        write_rel(repo.path(), "new.txt", "alpha\nbeta");

        let entries = collect_worktree_diff_entries(repo.path_str());
        assert_eq!(
            entries,
            vec![
                DiffFileEntry {
                    path: "new.txt".to_owned(),
                    status: "A".to_owned(),
                    added_lines: 2,
                    deleted_lines: 0,
                },
                DiffFileEntry {
                    path: "tracked.txt".to_owned(),
                    status: "M".to_owned(),
                    added_lines: 1,
                    deleted_lines: 0,
                },
            ]
        );

        let ns = b"R085\x00old.rs\x00new.rs\x00C100\x00src.rs\x00copy.rs\x00";
        let num = b"4\t2\t\x00old.rs\x00new.rs\x0010\t0\t\x00src.rs\x00copy.rs\x00";
        let statuses = parse_name_status_z(ns);
        let stats = parse_numstat_z(num);
        assert_eq!(statuses.get("new.rs").map(String::as_str), Some("R"));
        assert_eq!(statuses.get("copy.rs").map(String::as_str), Some("A"));
        assert_eq!(stats.get("new.rs"), Some(&(4, 2)));
        assert_eq!(stats.get("copy.rs"), Some(&(10, 0)));
    }

    #[test]
    fn systemd_commit_worktree_commits_dirty_changes_and_handles_clean_tree() {
        let repo = TempTestDir::new("zach-016-commit-worktree");
        git(repo.path(), &["init", "-b", "main"]);
        init_git_identity(repo.path());
        write_rel(repo.path(), "src/lib.rs", "pub fn base() -> i32 { 1 }\n");
        git(repo.path(), &["add", "src/lib.rs"]);
        git(repo.path(), &["commit", "-m", "initial commit"]);

        let sha_before = git(repo.path(), &["rev-parse", "HEAD"]).trim().to_owned();

        // Worker modifies a tracked file and creates an untracked file without committing.
        write_rel(repo.path(), "src/lib.rs", "pub fn base() -> i32 { 2 }\n");
        write_rel(repo.path(), "src/added.rs", "pub fn added() -> i32 { 3 }\n");

        let mut task = sample_task();
        task.task_id = "ZACH-016".to_owned();
        task.worktree_path = Some(repo.path_str().to_owned());
        task.active_attempt_id = Some("zach-016-impl-1".to_owned());

        let mut exec = SystemdStageExecutor::default();
        let committed_sha = exec
            .commit_worktree(&task, repo.path_str())
            .expect("commit_worktree should stage and commit dirty changes");

        assert_ne!(committed_sha, sha_before);
        assert_eq!(
            committed_sha,
            git(repo.path(), &["rev-parse", "HEAD"]).trim()
        );
        assert!(
            git(repo.path(), &["status", "--porcelain"])
                .trim()
                .is_empty()
        );
        let changed = git(
            repo.path(),
            &["diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"],
        );
        assert!(changed.lines().any(|l| l == "src/lib.rs"));
        assert!(changed.lines().any(|l| l == "src/added.rs"));

        // Second call on a clean tree should succeed without error and return the same HEAD.
        let second_sha = exec
            .commit_worktree(&task, repo.path_str())
            .expect("commit_worktree on clean tree should return HEAD");
        assert_eq!(second_sha, committed_sha);
    }

    #[test]
    fn systemd_push_and_ensure_pr_rejects_missing_sha_or_branch() {
        let mut exec = SystemdStageExecutor::default();
        let mut task = sample_task();
        assert!(
            exec.push_and_ensure_pr(&task, "/tmp/zach--ZACH-005", "head-sha")
                .is_err()
        );
        assert!(
            exec.push_and_ensure_pr(&task, "/tmp/zach--ZACH-005", "")
                .is_err()
        );
        task.branch = None;
        assert!(
            exec.push_and_ensure_pr(&task, "/tmp/zach--ZACH-005", "abc1234")
                .is_err()
        );
    }

    #[test]
    fn truncate_utf8_bytes_handles_small_limits_and_multibyte_boundaries() {
        assert_eq!(truncate_utf8_bytes("hello", 10), "hello");
        assert_eq!(truncate_utf8_bytes("hello", 5), "hello");
        assert_eq!(truncate_utf8_bytes("hello", 0), "");
        assert_eq!(truncate_utf8_bytes("€abc", 0), "");
        assert_eq!(truncate_utf8_bytes("€abc", 1), "");
        assert_eq!(truncate_utf8_bytes("€abc", 2), "");
        assert_eq!(truncate_utf8_bytes("abc", 2), "ab");
        assert_eq!(truncate_utf8_bytes("abcd", 3), "...");

        // 1020 ASCII + 3-byte '€' + 2 ASCII = 1025 bytes; 1024 - 3 = 1021 falls inside '€'.
        let mut input = "a".repeat(1020);
        input.push('€');
        input.push_str("bc");
        let truncated = truncate_utf8_bytes(&input, MAX_SUMMARY_BYTES);
        assert!(truncated.len() <= MAX_SUMMARY_BYTES);
        assert_eq!(truncated.len(), 1023);
        assert!(truncated.ends_with("..."));
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
    }

    #[test]
    fn systemd_executor_delivers_large_stdin_writes_secure_artifacts_and_bounds_summary() {
        use std::os::unix::fs::PermissionsExt;

        let state_dir = TempTestDir::new("zach-019-exec-state");
        let work_dir = TempTestDir::new("zach-019-exec-work");
        let mut exec = fixture_executor(state_dir.path());

        let mut task = sample_task();
        task.worktree_path = Some(work_dir.path_str().to_owned());
        let route = resolve_stage_route("S", "impl", 0, None).unwrap().unwrap();

        // > 64 KB stdin payload to prove concurrent writer + wait_with_output avoids pipe deadlock.
        let large_prompt = "P".repeat(96 * 1024);
        let mut spec = build_systemd_stage_command_with_env(
            &task,
            "att-real-1",
            &route,
            &large_prompt,
            &build_clean_env_from_process(),
        )
        .expect("build spec");

        // Replace systemd-run with a real subprocess reading all stdin and emitting > 1024B UTF-8 stdout + stderr.
        spec.program = "/bin/sh".to_owned();
        spec.args = vec![
            "-c".to_owned(),
            "bytes=$(wc -c); printf 'stdin_bytes=%s\\n' \"$bytes\"; printf '€%.0s' $(seq 1 600); echo 'err-line' >&2"
                .to_owned(),
        ];

        let res = exec
            .execute_stage(&task, "att-real-1", &route, &spec)
            .expect("real subprocess execution should succeed");

        assert_eq!(res.status, "PASSED");
        assert!(res.summary.len() <= MAX_SUMMARY_BYTES);
        assert!(res.summary.starts_with("stdin_bytes=98304"));
        assert!(res.summary.ends_with("..."));

        let attempts_dir = state_dir.path().join("attempts");
        let attempt_dir = attempts_dir.join("att-real-1");
        assert_eq!(
            std::fs::metadata(&attempts_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&attempt_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        for name in ["prompt.md", "stdout.jsonl", "stderr.log", "result.json"] {
            let p = attempt_dir.join(name);
            assert!(p.exists(), "missing artifact {name}");
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600,
                "artifact {name} should have 0600 mode"
            );
        }

        assert_eq!(
            std::fs::read_to_string(attempt_dir.join("prompt.md")).unwrap(),
            large_prompt
        );
        let stdout_contents = std::fs::read_to_string(attempt_dir.join("stdout.jsonl")).unwrap();
        assert!(stdout_contents.starts_with("stdin_bytes=98304\n"));
        assert_eq!(
            std::fs::read_to_string(attempt_dir.join("stderr.log")).unwrap(),
            "err-line\n"
        );
        let result_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(attempt_dir.join("result.json")).unwrap(),
        )
        .expect("valid result.json");
        assert_eq!(result_json["attempt_id"], "att-real-1");
        assert_eq!(result_json["exit_code"], 0);
        assert_eq!(result_json["result"]["status"], "PASSED");
    }

    #[test]
    fn systemd_executor_rejects_invalid_attempt_ids_and_symlinks() {
        let state_dir = TempTestDir::new("zach-019-sec");
        let mut exec = fixture_executor(state_dir.path());
        let task = sample_task();
        let route = resolve_stage_route("S", "impl", 0, None).unwrap().unwrap();
        let mut spec = build_systemd_stage_command_with_env(
            &task,
            "att-sec",
            &route,
            "hello",
            &BTreeMap::new(),
        )
        .unwrap();
        spec.program = "/bin/true".to_owned();
        spec.args = Vec::new();

        for bad_id in ["", ".", "..", "a/b", "a\\b", " bad "] {
            assert!(
                exec.execute_stage(&task, bad_id, &route, &spec).is_err(),
                "expected invalid attempt_id '{bad_id}' to be rejected"
            );
        }

        // Symlink attempt dir is rejected
        let attempts_dir = state_dir.path().join("attempts");
        std::fs::create_dir_all(&attempts_dir).unwrap();
        let outside = TempTestDir::new("zach-019-outside");
        std::os::unix::fs::symlink(outside.path(), attempts_dir.join("sym-att")).unwrap();
        assert!(exec.execute_stage(&task, "sym-att", &route, &spec).is_err());
    }

    #[test]
    fn prune_old_attempts_at_prunes_expired_dirs_and_skips_symlinks_and_files() {
        let state_dir = TempTestDir::new("zach-019-prune");
        let outside = TempTestDir::new("zach-019-prune-outside");
        write_rel(outside.path(), "keep.txt", "do not delete");

        let attempts_dir = state_dir.path().join("attempts");
        let old_dir = attempts_dir.join("old-attempt");
        let fresh_dir = attempts_dir.join("fresh-attempt");
        std::fs::create_dir_all(&old_dir).unwrap();
        std::fs::create_dir_all(&fresh_dir).unwrap();
        std::fs::write(old_dir.join("prompt.md"), "old").unwrap();
        std::fs::write(fresh_dir.join("prompt.md"), "fresh").unwrap();
        std::fs::write(attempts_dir.join("stray-file.txt"), "keep").unwrap();
        std::os::unix::fs::symlink(outside.path(), attempts_dir.join("sym-attempt")).unwrap();

        // Set old_dir mtime to 10 days ago using `touch`
        let status = Command::new("touch")
            .args(["-d", "10 days ago"])
            .arg(&old_dir)
            .status()
            .expect("run touch");
        assert!(status.success());

        let pruned = prune_old_attempts_at(
            state_dir.path(),
            std::time::Duration::from_secs(7 * 86_400),
            std::time::SystemTime::now(),
            &BTreeSet::new(),
        )
        .expect("prune succeeds");

        assert_eq!(pruned, 1);
        assert!(!old_dir.exists());
        assert!(fresh_dir.exists());
        assert!(attempts_dir.join("stray-file.txt").exists());
        assert!(attempts_dir.join("sym-attempt").symlink_metadata().is_ok());
        assert!(outside.path().join("keep.txt").exists());
    }

    #[test]
    fn parse_codex_jsonl_output_sums_turns_and_handles_failures() {
        let ok_jsonl = include_str!("../../tests/fixtures/codex_exec_usage.jsonl");
        let parsed = parse_codex_jsonl_output(ok_jsonl, "", Some(0)).expect("parse codex jsonl");
        assert_eq!(parsed.status, "PASSED");
        assert_eq!(
            parsed.summary,
            "Implemented token parsing and verified tests."
        );
        assert_eq!(parsed.input_tokens, Some(44_105));
        assert_eq!(parsed.output_tokens, Some(132));
        assert_eq!(parsed.total_tokens, Some(44_237));
        assert_eq!(parsed.review_markdown, None);

        let failed_jsonl = include_str!("../../tests/fixtures/codex_exec_failed.jsonl");
        let failed =
            parse_codex_jsonl_output(failed_jsonl, "", Some(1)).expect("parse failed codex jsonl");
        assert_eq!(failed.status, "FAILED");
        assert!(failed.summary.contains("usage limit"));
        assert_eq!(failed.input_tokens, None);
        assert_eq!(failed.output_tokens, None);
        assert_eq!(failed.total_tokens, None);
    }

    #[test]
    fn systemd_executor_branches_on_model_family_for_codex_and_gemini() {
        let state_dir = TempTestDir::new("zach-020-exec-state");
        let work_dir = TempTestDir::new("zach-020-exec-work");
        let mut exec = fixture_executor(state_dir.path());
        let mut task = sample_task();
        task.worktree_path = Some(work_dir.path_str().to_owned());

        // 1. OpenAiSol executes codex JSONL branch
        let codex_route = resolve_stage_route("S", "impl", 0, None).unwrap().unwrap();
        assert_eq!(codex_route.family, ModelFamily::OpenAiSol);
        let codex_fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/codex_exec_usage.jsonl");
        let mut codex_spec = build_systemd_stage_command_with_env(
            &task,
            "att-codex-ok",
            &codex_route,
            "run codex",
            &build_clean_env_from_process(),
        )
        .unwrap();
        codex_spec.program = "/bin/cat".to_owned();
        codex_spec.args = vec![codex_fixture.to_string_lossy().into_owned()];

        let codex_res = exec
            .execute_stage(&task, "att-codex-ok", &codex_route, &codex_spec)
            .expect("codex fixture execution");
        assert_eq!(codex_res.status, "PASSED");
        assert_eq!(codex_res.input_tokens, Some(44_105));
        assert_eq!(codex_res.output_tokens, Some(132));
        assert_eq!(codex_res.total_tokens, Some(44_237));

        // 2. GeminiAgy executes gemini-worker JSON branch
        let mut gemini_route = resolve_stage_route("M", "impl", 0, None).unwrap().unwrap();
        gemini_route.family = ModelFamily::GeminiAgy;
        gemini_route.model = "gemini-4-hydrogen-medium".to_owned();
        let gemini_fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/gemini_worker_usage.json");
        let mut gemini_spec = build_systemd_stage_command_with_env(
            &task,
            "att-gemini-ok",
            &gemini_route,
            "run gemini",
            &build_clean_env_from_process(),
        )
        .unwrap();
        gemini_spec.program = "/bin/cat".to_owned();
        gemini_spec.args = vec![gemini_fixture.to_string_lossy().into_owned()];

        let gemini_res = exec
            .execute_stage(&task, "att-gemini-ok", &gemini_route, &gemini_spec)
            .expect("gemini fixture execution");
        assert_eq!(gemini_res.status, "PASSED");
        assert_eq!(gemini_res.input_tokens, Some(9_967));
        assert_eq!(gemini_res.output_tokens, Some(43));
        assert_eq!(gemini_res.total_tokens, Some(10_010));
    }

    #[test]
    fn pr_review_spec_inserts_output_schema_before_trailing_dash_and_writes_0600_schema_file() {
        use std::os::unix::fs::PermissionsExt;

        let task = sample_task();
        let review_route = resolve_stage_route("S", "pr-review", 0, Some(ModelFamily::GeminiAgy))
            .unwrap()
            .unwrap();
        assert_eq!(review_route.family, ModelFamily::OpenAiSol);

        let spec = build_systemd_stage_command_with_env(
            &task,
            "att-rev-schema",
            &review_route,
            "review prompt",
            &build_clean_env_from_process(),
        )
        .expect("build pr-review spec");
        assert!(spec.output_schema_json.is_some());
        assert_eq!(spec.args.last().map(String::as_str), Some("-"));

        let schema_path = std::path::Path::new("/tmp/att-rev/review-schema.json");
        let injected = inject_codex_output_schema_args(&spec.args, schema_path);
        let schema_flag_idx = injected
            .iter()
            .position(|a| a == "--output-schema")
            .expect("--output-schema flag present");
        let dash_idx = injected
            .iter()
            .rposition(|a| a == "-")
            .expect("trailing - present");
        let double_dash_idx = injected
            .iter()
            .position(|a| a == "--")
            .expect("-- separator present");
        assert!(schema_flag_idx > double_dash_idx);
        assert_eq!(
            injected[schema_flag_idx + 1],
            "/tmp/att-rev/review-schema.json"
        );
        assert_eq!(dash_idx, injected.len() - 1);
        assert!(schema_flag_idx + 1 < dash_idx);

        // Execute with SystemdStageExecutor using a fake wrapper script that captures argv
        let state_dir = TempTestDir::new("zach-026-schema-state");
        let work_dir = TempTestDir::new("zach-026-schema-work");
        let mut exec = fixture_executor(state_dir.path());
        let mut run_spec = spec.clone();
        run_spec.worktree_path = work_dir.path_str().to_owned();
        // Keep "codex exec ... -" after "--" in args so inject_codex_output_schema_args triggers,
        // using `/usr/bin/env` as program? No, `/bin/echo` prints all args! Let's use a tiny script.
        let echo_script = state_dir.path().join("capture_args.sh");
        std::fs::write(
            &echo_script,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$(dirname \"$0\")/captured_argv.txt\"\nprintf '{\"type\":\"item.completed\",\"item\":{\"id\":\"item_0\",\"type\":\"agent_message\",\"text\":\"{\\\"verdict\\\":\\\"APPROVED\\\",\\\"ac_results\\\":[],\\\"findings\\\":[],\\\"summary\\\":\\\"ok\\\"}\"}}\\n{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}\\n'\n",
        )
        .unwrap();
        std::fs::set_permissions(&echo_script, std::fs::Permissions::from_mode(0o700)).unwrap();
        run_spec.program = echo_script.to_string_lossy().into_owned();

        let res = exec
            .execute_stage(&task, "att-rev-schema", &review_route, &run_spec)
            .expect("execute with schema");
        assert_eq!(res.status, "PASSED");
        assert!(
            res.review_output
                .as_deref()
                .is_some_and(|s| s.contains("\"verdict\":\"APPROVED\""))
        );

        let schema_on_disk = state_dir
            .path()
            .join("attempts/att-rev-schema/review-schema.json");
        assert!(schema_on_disk.exists());
        assert_eq!(
            std::fs::metadata(&schema_on_disk)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let captured = std::fs::read_to_string(state_dir.path().join("captured_argv.txt")).unwrap();
        let argv_lines: Vec<&str> = captured.lines().collect();
        let out_idx = argv_lines
            .iter()
            .position(|l| *l == "--output-schema")
            .expect("captured --output-schema");
        assert_eq!(argv_lines[out_idx + 1], schema_on_disk.to_string_lossy());
        assert_eq!(argv_lines.last().copied(), Some("-"));
    }

    #[test]
    fn parse_codex_jsonl_output_preserves_untruncated_json_verdict_in_review_output() {
        let large_summary = "S".repeat(1400);
        let verdict_json = format!(
            r#"{{"verdict":"APPROVED","ac_results":[{{"id":"AC-1","status":"PASS","file":"src/v2/router.rs","line":10,"evidence":"ok"}}],"findings":[],"summary":"{large_summary}"}}"#
        );
        let line1 = serde_json::json!({
            "type": "item.completed",
            "item": { "id": "item_0", "type": "agent_message", "text": verdict_json }
        });
        let line2 = serde_json::json!({
            "type": "turn.completed",
            "usage": { "input_tokens": 500, "output_tokens": 200 }
        });
        let jsonl = format!("{line1}\n{line2}\n");
        let parsed = parse_codex_jsonl_output(&jsonl, "", Some(0)).expect("parse codex verdict");
        assert_eq!(parsed.status, "PASSED");
        assert!(parsed.summary.len() <= MAX_SUMMARY_BYTES);
        assert_eq!(parsed.review_output.as_deref(), Some(verdict_json.as_str()));
    }

    #[test]
    fn collect_reviewed_diff_ranges_handles_all_hunk_and_special_file_edge_cases() {
        // 1. Unit test parse_unified_zero_diff across all git diff edge cases
        let synthetic_diff = "\
diff --git a/src/omitted.rs b/src/omitted.rs
--- a/src/omitted.rs
+++ b/src/omitted.rs
@@ -4 +4 @@ fn one() {}
diff --git a/src/added.rs b/src/added.rs
new file mode 100644
--- /dev/null
+++ b/src/added.rs
@@ -0,0 +1,5 @@
diff --git a/src/empty_added.rs b/src/empty_added.rs
new file mode 100644
index 0000000..e69de29
diff --git a/src/deleted_all.rs b/src/deleted_all.rs
deleted file mode 100644
--- a/src/deleted_all.rs
+++ /dev/null
@@ -1,4 +0,0 @@
diff --git a/src/empty_deleted.rs b/src/empty_deleted.rs
deleted file mode 100644
index e69de29..0000000
diff --git a/src/pure_del_hunk.rs b/src/pure_del_hunk.rs
--- a/src/pure_del_hunk.rs
+++ b/src/pure_del_hunk.rs
@@ -10,3 +9,0 @@ fn keep() {}
diff --git a/src/old_name.rs b/src/new_name.rs
similarity index 100%
rename from src/old_name.rs
rename to src/new_name.rs
diff --git a/src/old_edit.rs b/src/new_edit.rs
similarity index 80%
rename from src/old_edit.rs
rename to src/new_edit.rs
--- a/src/old_edit.rs
+++ b/src/new_edit.rs
@@ -2 +2,3 @@
diff --git a/assets/logo.bin b/assets/logo.bin
new file mode 100644
Binary files /dev/null and b/assets/logo.bin differ
";
        let parsed = parse_unified_zero_diff(synthetic_diff);
        assert_eq!(
            parsed.get("src/omitted.rs"),
            Some(&vec![LineRange { start: 4, end: 4 }])
        );
        assert_eq!(
            parsed.get("src/added.rs"),
            Some(&vec![LineRange { start: 1, end: 5 }])
        );
        assert_eq!(
            parsed.get("src/empty_added.rs"),
            Some(&vec![LineRange { start: 1, end: 1 }])
        );
        assert_eq!(
            parsed.get("src/deleted_all.rs"),
            Some(&vec![LineRange { start: 1, end: 4 }])
        );
        assert_eq!(
            parsed.get("src/empty_deleted.rs"),
            Some(&vec![LineRange { start: 1, end: 1 }])
        );
        assert_eq!(
            parsed.get("src/pure_del_hunk.rs"),
            Some(&vec![LineRange { start: 9, end: 9 }])
        );
        assert_eq!(
            parsed.get("src/new_name.rs"),
            Some(&vec![LineRange { start: 1, end: 1 }])
        );
        assert_eq!(
            parsed.get("src/new_edit.rs"),
            Some(&vec![LineRange { start: 2, end: 4 }])
        );
        assert_eq!(
            parsed.get("assets/logo.bin"),
            Some(&vec![LineRange { start: 1, end: 1 }])
        );

        // 2. Real git repo without remotes (uses plan_base_sha so merge-base..reviewed_sha is never sha..sha)
        let repo = TempTestDir::new("zach-026-diff-noremote");
        git(repo.path(), &["init", "-b", "main"]);
        init_git_identity(repo.path());
        write_rel(repo.path(), "src/lib.rs", "line1\nline2\nline3\nline4\n");
        write_rel(repo.path(), "src/remove.rs", "a\nb\nc\n");
        write_rel(repo.path(), "src/move_me.rs", "same\n");
        git(repo.path(), &["add", "."]);
        git(repo.path(), &["commit", "-m", "base"]);
        let base_sha = git(repo.path(), &["rev-parse", "HEAD"]).trim().to_owned();

        git(repo.path(), &["checkout", "-b", "task/ZACH-026-DIFF"]);
        write_rel(
            repo.path(),
            "src/lib.rs",
            "line1\nchanged2\nline3\nline4\nadded5\n",
        );
        std::fs::remove_file(repo.path().join("src/remove.rs")).unwrap();
        git(repo.path(), &["mv", "src/move_me.rs", "src/moved_here.rs"]);
        write_rel(repo.path(), "src/empty.rs", "");
        git(repo.path(), &["add", "-A"]);
        git(repo.path(), &["commit", "-m", "task change"]);
        let reviewed_sha = git(repo.path(), &["rev-parse", "HEAD"]).trim().to_owned();

        let ctx = collect_reviewed_diff_ranges(repo.path_str(), Some(&base_sha), &reviewed_sha)
            .expect("collect diff ranges without remotes");
        assert_eq!(ctx.merge_base_sha, base_sha);
        assert_eq!(ctx.reviewed_sha, reviewed_sha);
        assert_eq!(ctx.commit_range, format!("{base_sha}..{reviewed_sha}"));
        assert!(ctx.files["src/lib.rs"].iter().any(|r| r.contains(2)));
        assert!(ctx.files["src/lib.rs"].iter().any(|r| r.contains(5)));
        assert!(!ctx.files["src/lib.rs"].iter().any(|r| r.contains(3)));
        assert!(ctx.files["src/remove.rs"].iter().any(|r| r.contains(1)));
        assert!(ctx.files["src/moved_here.rs"].iter().any(|r| r.contains(1)));
        assert!(ctx.files["src/empty.rs"].iter().any(|r| r.contains(1)));

        // 3. Path normalization checks
        assert_eq!(
            normalize_cited_diff_path("./src/lib.rs", repo.path_str()).unwrap(),
            "src/lib.rs"
        );
        assert_eq!(
            normalize_cited_diff_path(&format!("{}/src/lib.rs", repo.path_str()), repo.path_str())
                .unwrap(),
            "src/lib.rs"
        );
        assert!(normalize_cited_diff_path("../secret.rs", repo.path_str()).is_err());
        assert!(normalize_cited_diff_path("/etc/passwd", repo.path_str()).is_err());
    }
    #[test]
    fn detached_unit_observation_distinguishes_retained_exit_failure_and_manager_absence() {
        for (load, active, sub, expected) in [
            ("loaded", "active", "running", UnitState::Running),
            ("loaded", "active", "exited", UnitState::Exited),
            ("loaded", "failed", "failed", UnitState::Failed),
            ("loaded", "activating", "start", UnitState::Starting),
            ("loaded", "deactivating", "stop", UnitState::Stopping),
            ("loaded", "inactive", "dead", UnitState::Dead),
            ("not-found", "inactive", "dead", UnitState::Missing),
        ] {
            let raw = format!(
                "LoadState={load}\nActiveState={active}\nSubState={sub}\nResult=success\nExecMainCode=1\nExecMainStatus=0\nInvocationID=\nControlGroup=\n"
            );
            let observation = UnitObservation::parse(&raw);
            assert_eq!(observation.state().unwrap(), expected);
            assert!(observation.success());
            assert!(observation.invocation_id.is_empty());
            assert!(observation.control_group.is_empty());
        }
        assert!(UnitObservation::parse("").state().is_err());
        let signaled = UnitObservation::parse(
            "LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=signal\nExecMainCode=2\nExecMainStatus=9",
        );
        assert!(!signaled.success());
    }

    #[test]
    fn detached_preparation_resolves_relative_state_io_and_preserves_schema_mount_without_launch() {
        let root = PathBuf::from(format!("target/z25-prepare-{}", std::process::id()));
        std::fs::create_dir_all(root.join("home/.codex")).unwrap();
        write_secure_file(&root.join("home/.codex/auth.json"), b"{}").unwrap();
        let mut task = sample_task();
        let worker = root.join("worker");
        assert!(
            Command::new("git")
                .args([
                    "clone",
                    "--quiet",
                    "--shared",
                    "--no-checkout",
                    env!("CARGO_MANIFEST_DIR")
                ])
                .arg(&worker)
                .status()
                .unwrap()
                .success()
        );
        task.worktree_path = Some(
            std::fs::canonicalize(&worker)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
        task.context_pack.network = Some("none".into());
        let route = resolve_stage_route("S", "pr-review", 0, Some(ModelFamily::GeminiAgy))
            .unwrap()
            .unwrap();
        let env = BTreeMap::from([(
            "HOME".into(),
            std::fs::canonicalize(root.join("home"))
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        )]);
        let spec =
            build_systemd_stage_command_with_env(&task, "relative-io", &route, "prompt", &env)
                .unwrap();
        assert!(!root.join("state").exists());
        let PreparedLaunch {
            manifest,
            resources,
        } = prepare_detached_launch(&root.join("state"), &task, "relative-io", &route, spec)
            .unwrap();
        assert!(manifest.attempt_dir.is_absolute());
        assert!(manifest.attempt_dir.join("codex-home/auth.json").exists());
        for property in [
            "StandardInput=file:",
            "StandardOutput=file:",
            "StandardError=file:",
        ] {
            let value = manifest
                .spec
                .args
                .iter()
                .find_map(|a| a.strip_prefix(property))
                .unwrap();
            assert!(std::path::Path::new(value).is_absolute());
            assert_eq!(std::fs::canonicalize(value).unwrap(), PathBuf::from(value));
        }
        let schema = manifest
            .attempt_dir
            .join("review-schema.json")
            .to_string_lossy()
            .into_owned();
        assert!(
            manifest
                .spec
                .args
                .windows(3)
                .any(|args| args == ["--ro-bind", schema.as_str(), schema.as_str()])
        );
        resources.cleanup_after_stop().unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prepare_detached_launch_missing_worktree_contextualizes_and_writes_error_log() {
        let root = TempTestDir::new("zach059-missing-worktree");
        let missing_wt = root.path().join("does-not-exist");
        let state = root.path().join("state");
        let mut task = sample_task();
        task.worktree_path = Some(missing_wt.display().to_string());
        let route = codex_test_route("plan");
        let env = BTreeMap::from([("HOME".into(), root.path().display().to_string())]);
        let spec =
            build_systemd_stage_command_with_env(&task, "plan", &route, "prompt", &env).unwrap();
        let err = prepare_detached_launch(&state, &task, "attempt-miss", &route, spec)
            .err()
            .expect("missing worktree must fail");
        assert!(err.contains("canonicalizing worktree"), "err={err}");
        assert!(err.contains(&missing_wt.display().to_string()), "err={err}");
        let log = std::fs::read_to_string(state.join("attempts/attempt-miss/supervisor-error.log"))
            .expect("supervisor-error.log should be written");
        assert!(log.contains("canonicalizing worktree"), "log={log}");
        assert!(log.contains(&missing_wt.display().to_string()), "log={log}");
    }

    #[test]
    fn system_unit_controller_launch_spawn_failure_names_program() {
        let root = TempTestDir::new("zach059-spawn-fail");
        let mut task = sample_task();
        task.worktree_path = Some(root.path().display().to_string());
        let route = codex_test_route("plan");
        let env = BTreeMap::from([("HOME".into(), root.path().display().to_string())]);
        let mut spec =
            build_systemd_stage_command_with_env(&task, "plan", &route, "prompt", &env).unwrap();
        let missing_bin = root.path().join("no-such-systemd-run");
        spec.program = missing_bin.display().to_string();
        let manifest = AttemptManifest {
            mount_layout_version: 1,
            attempt_id: "attempt-spawn".into(),
            task_id: task.task_id.clone(),
            route,
            spec,
            sha_before: "0000000".into(),
            attempt_dir: root.path().to_path_buf(),
        };
        let err = SystemUnitController.launch(&manifest).unwrap_err();
        assert!(err.contains("spawning"), "err={err}");
        assert!(
            err.contains(&missing_bin.display().to_string()),
            "err={err}"
        );
    }

    #[test]
    fn harvest_detached_maps_systemd_result_timeout_to_agy_timeout() {
        let root = TempTestDir::new("zach071-harvest-timeout");
        let attempt_dir = root.path().join("att-timeout");
        std::fs::create_dir_all(&attempt_dir).unwrap();
        let mut task = sample_task();
        task.worktree_path = Some(root.path().display().to_string());
        let mut route = resolve_stage_route("M", "impl", 0, Some(ModelFamily::GeminiAgy))
            .unwrap()
            .unwrap();
        route.family = ModelFamily::GeminiAgy;
        let env = BTreeMap::from([("HOME".into(), root.path().display().to_string())]);
        let spec =
            build_systemd_stage_command_with_env(&task, "att-timeout", &route, "p", &env).unwrap();
        let manifest = AttemptManifest {
            mount_layout_version: 1,
            attempt_id: "att-timeout".into(),
            task_id: task.task_id.clone(),
            route,
            spec,
            sha_before: "0000000".into(),
            attempt_dir: attempt_dir.clone(),
        };
        let timeout_obs = UnitObservation::parse(
            "LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=timeout\nExecMainCode=2\nExecMainStatus=15\nInvocationID=inv-1\nControlGroup=/user.slice/zach\n",
        );

        // 1. Empty stdout + empty stderr on Result=timeout -> AGY_TIMEOUT (never AGY_EXIT)
        std::fs::write(attempt_dir.join("stdout.jsonl"), "").unwrap();
        std::fs::write(attempt_dir.join("stderr.log"), "").unwrap();
        let err = harvest_detached(&manifest, &timeout_obs).unwrap_err();
        assert!(
            err.starts_with("AGY_TIMEOUT:"),
            "expected AGY_TIMEOUT for empty stdout, got: {err}"
        );

        // 2. Truncated non-JSON stdout + empty stderr on Result=timeout -> AGY_TIMEOUT
        std::fs::write(attempt_dir.join("stdout.jsonl"), "{\"status\": \"running\"").unwrap();
        let err = harvest_detached(&manifest, &timeout_obs).unwrap_err();
        assert!(
            err.starts_with("AGY_TIMEOUT:"),
            "expected AGY_TIMEOUT for truncated non-JSON stdout, got: {err}"
        );

        // 3. Valid completed JSON envelope flushed before timeout is preserved
        std::fs::write(
            attempt_dir.join("stdout.jsonl"),
            serde_json::json!({
                "status": "ok",
                "execution_succeeded": true,
                "summary": "completed right before limit",
                "duration_seconds": 1799.2,
                "usage": { "input_tokens": 100, "output_tokens": 50, "total_tokens": 150 }
            })
            .to_string(),
        )
        .unwrap();
        let ok = harvest_detached(&manifest, &timeout_obs).unwrap();
        assert_eq!(ok.status, "PASSED");
        assert_eq!(ok.total_tokens, Some(150));
        assert_eq!(ok.duration_seconds, Some(1799.2));
    }

    #[test]
    fn harvest_detached_preserves_usage_and_duration_on_failed_agy_envelope() {
        let root = TempTestDir::new("zach071-harvest-failed-usage");
        let attempt_dir = root.path().join("att-failed-usage");
        std::fs::create_dir_all(&attempt_dir).unwrap();
        let mut task = sample_task();
        task.worktree_path = Some(root.path().display().to_string());
        let mut route = resolve_stage_route("M", "impl", 0, Some(ModelFamily::GeminiAgy))
            .unwrap()
            .unwrap();
        route.family = ModelFamily::GeminiAgy;
        let env = BTreeMap::from([("HOME".into(), root.path().display().to_string())]);
        let spec =
            build_systemd_stage_command_with_env(&task, "att-failed-usage", &route, "p", &env)
                .unwrap();
        let manifest = AttemptManifest {
            mount_layout_version: 1,
            attempt_id: "att-failed-usage".into(),
            task_id: task.task_id.clone(),
            route,
            spec,
            sha_before: "abc1234".into(),
            attempt_dir: attempt_dir.clone(),
        };
        let obs = UnitObservation::parse(
            "LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainCode=1\nExecMainStatus=1\nInvocationID=inv-fail-1\nControlGroup=/user.slice/zach\n",
        );
        std::fs::write(
            attempt_dir.join("stdout.jsonl"),
            serde_json::json!({
                "status": "error",
                "execution_succeeded": false,
                "process_status": "timeout",
                "error_code": "AGY_TIMEOUT",
                "summary": "worker timed out after 1800s",
                "duration_seconds": 1800.4,
                "usage": {
                    "input_tokens": 55000,
                    "output_tokens": 2500,
                    "total_tokens": 57500
                }
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(attempt_dir.join("stderr.log"), "").unwrap();

        let result =
            harvest_detached(&manifest, &obs).expect("failed envelope with usage returns Ok");
        assert_eq!(result.status, "FAILED");
        assert!(
            result.summary.starts_with("AGY_TIMEOUT:"),
            "summary={}",
            result.summary
        );
        assert_eq!(result.input_tokens, Some(55_000));
        assert_eq!(result.output_tokens, Some(2_500));
        assert_eq!(result.total_tokens, Some(57_500));
        assert_eq!(result.duration_seconds, Some(1800.4));
        assert_eq!(result.invocation_id.as_deref(), Some("inv-fail-1"));

        let harvest_json: StageExecutionResult =
            serde_json::from_slice(&std::fs::read(attempt_dir.join("harvest.json")).unwrap())
                .expect("valid harvest.json");
        assert_eq!(harvest_json.status, "FAILED");
        assert_eq!(harvest_json.total_tokens, Some(57_500));
        assert_eq!(harvest_json.duration_seconds, Some(1800.4));
    }

    #[test]
    fn prune_old_attempts_at_prunes_manifest_dirs_unless_in_active_attempt_ids() {
        let state_dir = TempTestDir::new("zach071-prune-active-set");
        let attempts_dir = state_dir.path().join("attempts");
        let old_completed = attempts_dir.join("att-old-completed");
        let old_active = attempts_dir.join("att-old-active");
        let fresh_completed = attempts_dir.join("att-fresh-completed");
        for dir in [&old_completed, &old_active, &fresh_completed] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("manifest.json"), "{}").unwrap();
        }

        for dir in [&old_completed, &old_active] {
            let status = Command::new("touch")
                .args(["-d", "10 days ago"])
                .arg(dir)
                .status()
                .expect("run touch");
            assert!(status.success());
        }

        let active = BTreeSet::from(["att-old-active".to_owned()]);
        let pruned = prune_old_attempts_at(
            state_dir.path(),
            std::time::Duration::from_secs(7 * 86_400),
            std::time::SystemTime::now(),
            &active,
        )
        .expect("prune succeeds");

        assert_eq!(pruned, 1);
        assert!(
            !old_completed.exists(),
            "expired completed dir with manifest.json must be pruned"
        );
        assert!(
            old_active.exists(),
            "expired dir in active_attempt_ids must be preserved"
        );
        assert!(fresh_completed.exists(), "fresh dir must be preserved");
    }

    #[test]
    fn stop_and_cleanup_extracts_audit_json_before_deleting_codex_and_gemini_homes() {
        struct DeadController;
        impl UnitController for DeadController {
            fn inspect(&self, _unit: &str) -> Result<UnitObservation, String> {
                Ok(UnitObservation {
                    load_state: "not-found".into(),
                    active_state: "inactive".into(),
                    sub_state: "dead".into(),
                    ..Default::default()
                })
            }
            fn launch(&self, _manifest: &AttemptManifest) -> Result<(), String> {
                Ok(())
            }
            fn stop(&self, _unit: &str) -> Result<(), String> {
                Ok(())
            }
            fn reset_failed(&self, _unit: &str) -> Result<(), String> {
                Ok(())
            }
            fn list_units(&self) -> Result<Vec<String>, String> {
                Ok(Vec::new())
            }
        }

        let dir = TempTestDir::new("zach072-stop-cleanup-audit");
        let attempt_dir = dir.path();
        std::fs::write(
            attempt_dir.join("manifest.json"),
            r#"{"attempt_id":"att-clean-1","task_id":"ZACH-072","route":{"stage":"impl","family":"OpenAiSol"}}"#,
        )
        .unwrap();
        std::fs::write(
            attempt_dir.join("stdout.jsonl"),
            r#"{"type":"turn.completed","usage":{"input_tokens":500,"cached_input_tokens":100,"output_tokens":120,"reasoning_output_tokens":30}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(attempt_dir.join("codex-home/sessions")).unwrap();
        std::fs::write(
            attempt_dir.join("codex-home/auth.json"),
            r#"{"OPENAI_API_KEY":"sk-supersecretkey1234567890123456"}"#,
        )
        .unwrap();
        std::fs::write(
            attempt_dir.join("codex-home/sessions/rollout-1.jsonl"),
            [
                r#"{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":500,"cached_input_tokens":100,"output_tokens":120,"reasoning_output_tokens":30,"total_tokens":620}}}}"#,
                r#"{"type":"response_item","payload":{"type":"function_call","call_id":"call-1","name":"edit_file","arguments":"{\"path\":\"src/lib.rs\"}"}}"#,
                r#"{"type":"response_item","payload":{"type":"function_call_output","call_id":"call-1","output":"Exit code: 0"}}"#,
                r#"{"type":"response_item","payload":{"type":"local_shell_call","call_id":"call-2","action":{"command":["cargo","test"]}}}"#,
                r#"{"type":"response_item","payload":{"type":"local_shell_call_output","call_id":"call-2","output":"Exit code: 101"}}"#,
            ]
            .join("\n"),
        )
        .unwrap();
        std::fs::create_dir_all(attempt_dir.join("gemini-home/logs")).unwrap();
        std::fs::write(
            attempt_dir.join("gemini-home/oauth.json"),
            r#"{"access_token":"ghp_1234567890abcdefghij123456"}"#,
        )
        .unwrap();
        std::fs::write(
            attempt_dir.join("gemini-home/logs/transcript.jsonl"),
            r#"{"step_index":1,"type":"PLANNER_RESPONSE","status":"DONE","tool_calls":[{"name":"read_file","arguments":{"Path":"src/lib.rs"}}]}"#,
        )
        .unwrap();

        stop_and_cleanup(&DeadController, "zach-test-unit", attempt_dir, None, false)
            .expect("stop_and_cleanup succeeds");

        assert!(
            !attempt_dir.join("codex-home").exists(),
            "codex-home must be removed"
        );
        assert!(
            !attempt_dir.join("gemini-home").exists(),
            "gemini-home must be removed"
        );
        let audit_path = attempt_dir.join("audit.json");
        assert!(
            audit_path.is_file(),
            "audit.json must be extracted before cleanup"
        );
        let audit_bytes = std::fs::read(&audit_path).unwrap();
        assert!(audit_bytes.len() <= crate::v2::audit::MAX_AUDIT_JSON_BYTES);
        let audit_text = String::from_utf8(audit_bytes).unwrap();
        assert!(!audit_text.contains("sk-supersecretkey"));
        assert!(!audit_text.contains("ghp_1234567890"));
        let report: crate::v2::audit::AttemptAuditReport =
            serde_json::from_str(&audit_text).unwrap();
        assert_eq!(report.attempt_id, "att-clean-1");
        assert_eq!(report.task_id, "ZACH-072");
        assert_eq!(report.cached_input_tokens, Some(100));
        assert_eq!(report.reasoning_tokens, Some(30));
        assert_eq!(report.tool_call_count, 2);
        assert_eq!(report.tool_error_count, 1);
        assert_eq!(report.edit_compile_fail_loops, 1);
    }

    #[test]
    fn zach_074_worker_driver_gemini_schema_and_stage_receipt_v1() {
        use std::path::Path;
        let mut task = sample_task();
        task.task_id = "ZACH-074".to_owned();
        task.autonomous_consent = true;
        task.worktree_path = Some("/tmp/zach-074-wt".to_owned());

        let mut gemini_route =
            resolve_stage_route("M", "pr-review", 0, Some(ModelFamily::OpenAiSol))
                .unwrap()
                .unwrap();
        gemini_route.family = ModelFamily::GeminiAgy;
        gemini_route.model = "gemini-4-hydrogen-high".to_owned();

        // 1. WorkerDriver builds clean stage_mode + json_schema payload and attaches --json-schema
        let clean_env = BTreeMap::from([("HOME".to_owned(), "/home/ubuntu".to_owned())]);
        let spec = build_systemd_stage_command_with_env(
            &task,
            "att-zach-074-rev",
            &gemini_route,
            "review prompt",
            &clean_env,
        )
        .expect("build gemini review command");
        assert!(spec.output_schema_json.is_some());
        assert!(!spec.writable, "pr-review must stay read-only");
        let payload: serde_json::Value =
            serde_json::from_str(&spec.stdin_payload).expect("valid agy stdin json");
        assert_eq!(payload["harness"], "agy");
        assert_eq!(payload["stage_mode"], true);
        assert_eq!(payload["stream_json"], true);
        assert_eq!(payload["task_id"], "ZACH-074");
        assert_eq!(payload["stage"], "pr-review");
        assert!(payload["json_schema"].is_object());

        let driver = worker_driver(ModelFamily::GeminiAgy);
        let schema_attached =
            driver.attach_output_schema(&spec.args, Path::new("/tmp/schema.json"));
        assert!(schema_attached.contains(&"--json-schema".to_owned()));
        assert!(schema_attached.contains(&"/tmp/schema.json".to_owned()));

        // 2. WorkerDriver parses multi-line NDJSON (liveness + terminal envelope)
        let ndjson = format!(
            "{}\n{}\n",
            serde_json::json!({"event":"agy_stream","type":"turn","turn":1}),
            serde_json::json!({
                "execution_succeeded": true,
                "status": "SUCCESS",
                "response": "{\"verdict\":\"APPROVED\",\"ac_results\":[],\"findings\":[],\"summary\":\"ok\"}",
                "usage": {"input_tokens": 300, "output_tokens": 50, "total_tokens": 350},
                "duration_seconds": 14.2
            })
        );
        let parsed = driver
            .parse_output(&ndjson, "", Some(0), false)
            .expect("parse multi-line agy stream output");
        assert_eq!(parsed.status, "PASSED");
        assert_eq!(parsed.input_tokens, Some(300));
        assert_eq!(parsed.output_tokens, Some(50));
        assert_eq!(parsed.total_tokens, Some(350));

        // 3. StageReceiptV1 is ADR-004 content-safe and wired into intake::stage_operation_with_receipt
        let receipt = build_stage_receipt_v1(
            &task.task_id,
            "att-zach-074-rev",
            &gemini_route,
            &parsed,
            None,
        );
        assert_eq!(receipt.schema_version, 1);
        assert_eq!(receipt.actor, "antigravity");
        assert_eq!(receipt.executor, "zach");
        assert_eq!(receipt.status, "completed");
        assert_eq!(receipt.harness.as_deref(), Some("agy"));
        assert_eq!(receipt.duration_secs, Some(14));
        assert_eq!(
            receipt.token_usage,
            Some(StageReceiptTokenUsage {
                input_tokens: 300,
                output_tokens: 50,
                total_tokens: Some(350),
            })
        );
        let receipt_json = serde_json::to_string(&receipt).unwrap();
        assert!(!receipt_json.contains("prompt"));
        assert!(!receipt_json.contains("transcript"));

        let op = crate::v2::intake::stage_operation_with_receipt(
            &task,
            "k-1",
            "pr-review",
            Path::new("/tmp/body.md"),
            Some("APPROVED"),
            Some("abc1234"),
            "zach",
            Some(Path::new("/tmp/stage-receipt.json")),
        );
        assert!(op.args.contains(&"--receipt".to_owned()));
        assert!(op.args.contains(&"/tmp/stage-receipt.json".to_owned()));
    }

    #[test]
    fn zach_074_four_role_bootstrap_fixtures_isolation_and_diagnostics() {
        let base_dir = std::env::temp_dir().join(format!(
            "zach-074-bootstrap-test-{}-{}",
            std::process::id(),
            crate::v2::now_epoch()
        ));
        let _ = std::fs::remove_dir_all(&base_dir);
        let gov_root = base_dir.join("governance");
        let worktree = base_dir.join("repo-instructions-only");
        std::fs::create_dir_all(&worktree).unwrap();
        std::fs::write(
            worktree.join("INSTRUCTIONS.md"),
            "# Repo Instructions\nAlways run targeted checks.\n",
        )
        .unwrap();

        for (stage, skill) in [
            ("plan", "governance-planner"),
            ("plan-review", "governance-plan-reviewer"),
            ("impl", "governance-implementer"),
            ("pr-review", "governance-pr-reviewer"),
        ] {
            let skill_dir = gov_root.join(".agents/skills").join(skill);
            std::fs::create_dir_all(&skill_dir).unwrap();
            std::fs::write(
                skill_dir.join("SKILL.md"),
                format!("# {skill}\nRole guidance for {stage}.\n"),
            )
            .unwrap();
        }

        let mut task = sample_task();
        task.task_id = "ZACH-074".to_owned();
        task.autonomous_consent = true;
        task.repository = "zach".to_owned();
        task.branch = Some("task/ZACH-074-test".to_owned());
        task.worktree_path = Some(worktree.to_string_lossy().into_owned());
        let clean_env = BTreeMap::from([("HOME".to_owned(), "/home/ubuntu".to_owned())]);

        // AC-B1 & AC-B2: Verify all 4 roles observe real cwd, repo/worktree, isolation,
        // INSTRUCTIONS.md bootstrap, sibling governance skill, and bounded learnings.
        for stage in ["plan", "plan-review", "impl", "pr-review"] {
            let (sections, meta) = crate::v2::pipeline::resolve_stage_bootstrap_from_roots(
                &task,
                stage,
                &worktree.to_string_lossy(),
                &gov_root,
                Some("Known pitfall: run cargo fmt before commit.".to_owned()),
            );
            assert_eq!(meta.role, stage);
            assert_eq!(meta.cwd, worktree.to_string_lossy());
            assert_eq!(meta.repository, "zach");
            assert_eq!(meta.branch, "task/ZACH-074-test");
            assert_eq!(meta.writable, stage == "impl");
            assert!(meta.repo_instructions_loaded);
            assert_eq!(
                meta.repo_instruction_paths,
                vec!["INSTRUCTIONS.md".to_owned()]
            );
            assert!(meta.role_skill_loaded);
            assert!(
                meta.role_skill_path
                    .as_deref()
                    .unwrap()
                    .contains(".agents/skills")
            );
            assert!(meta.learnings_loaded);
            assert!(meta.learnings_chars <= crate::v2::pipeline::LEARNINGS_MAX_CHARS);
            assert!(meta.missing_required_instructions.is_empty());
            assert!(sections.iter().any(|(k, _)| k == "Repository Instructions"));
            assert!(sections.iter().any(|(k, _)| k == "Operational Learnings"));

            let route = resolve_stage_route("M", stage, 0, None).unwrap().unwrap();
            let spec = build_systemd_stage_command_with_env(
                &task,
                &format!("att-role-{stage}"),
                &route,
                "prompt",
                &clean_env,
            )
            .expect("build command for role");
            assert_eq!(spec.worktree_path, worktree.to_string_lossy());
            assert_eq!(spec.writable, stage == "impl");
        }

        // AC-B3: Missing mandatory instructions are observable in bounded metadata without prompt content
        let empty_wt = base_dir.join("empty-wt");
        let missing_gov = base_dir.join("missing-gov");
        std::fs::create_dir_all(&empty_wt).unwrap();
        let (_, missing_meta) = crate::v2::pipeline::resolve_stage_bootstrap_from_roots(
            &task,
            "impl",
            &empty_wt.to_string_lossy(),
            &missing_gov,
            None,
        );
        assert!(!missing_meta.repo_instructions_loaded);
        assert!(!missing_meta.role_skill_loaded);
        assert!(
            missing_meta
                .missing_required_instructions
                .iter()
                .any(|m| m.contains("governance-implementer"))
        );
        assert!(
            missing_meta
                .missing_required_instructions
                .iter()
                .any(|m| m.contains("AGENTS.md|INSTRUCTIONS.md"))
        );
        let meta_json = serde_json::to_string(&missing_meta).unwrap();
        assert!(!meta_json.contains("Known pitfall"));
        assert!(!meta_json.contains("Always run targeted checks"));
        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn prepare_web_node_modules_handles_offline_fallback_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = TempTestDir::new("zach048-web-prep");
        let home = root.path().join("home");
        let bin_dir = home.join(".local/share/fnm/aliases/default/bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let fake_npm = bin_dir.join("npm");
        std::fs::write(
            &fake_npm,
            "#!/bin/sh\nif [ \"$1\" = \"ci\" ] && [ \"$2\" = \"--offline\" ]; then\n  if [ -f web/fail-ci ]; then\n    mkdir -p web/node_modules/partial\n    exit 1\n  fi\n  mkdir -p web/node_modules\n  touch web/node_modules/.ok\n  exit 0\nfi\nexit 1\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake_npm, std::fs::Permissions::from_mode(0o755)).unwrap();

        let wt = root.path().join("wt");
        std::fs::create_dir_all(wt.join(".git")).unwrap();

        // No web/package.json -> no-op.
        prepare_web_node_modules(&home, &wt).unwrap();
        assert!(!wt.join("web/node_modules").exists());

        // Failed offline npm ci removes partial web/node_modules so future runs retry cleanly.
        std::fs::create_dir_all(wt.join("web")).unwrap();
        std::fs::write(wt.join("web/package.json"), "{}").unwrap();
        std::fs::write(wt.join("web/package-lock.json"), "{}").unwrap();
        std::fs::write(wt.join("web/fail-ci"), "1").unwrap();
        prepare_web_node_modules(&home, &wt).unwrap();
        assert!(!wt.join("web/node_modules").exists());

        // Standalone repo with web/package.json + package-lock.json -> invokes offline npm ci.
        std::fs::remove_file(wt.join("web/fail-ci")).unwrap();
        prepare_web_node_modules(&home, &wt).unwrap();
        assert!(wt.join("web/node_modules/.ok").is_file());

        // Symlinked web/node_modules fails closed.
        std::fs::remove_dir_all(wt.join("web/node_modules")).unwrap();
        symlink(root.path(), wt.join("web/node_modules")).unwrap();
        assert!(prepare_web_node_modules(&home, &wt).is_err());
    }

    #[test]
    fn parse_codex_jsonl_output_rejects_partial_blocked_and_failed_validation_impl_reports_preserving_usage()
     {
        let partial_jsonl = [
            serde_json::json!({"type": "turn.completed", "usage": {"input_tokens": 300, "output_tokens": 40}}).to_string(),
            serde_json::json!({
                "type": "item.completed",
                "item": {
                    "type": "agent_message",
                    "text": "{\"status\":\"partial\",\"summary\":\"left tests failing\",\"validation\":{\"passed\":false,\"summary\":\"cargo test failed\"}}"
                }
            }).to_string(),
            serde_json::json!({"type": "turn.completed", "usage": {"input_tokens": 200, "output_tokens": 60}}).to_string(),
        ]
        .join("\n");
        let parsed = parse_codex_jsonl_output(&partial_jsonl, "", Some(0)).unwrap();
        assert_eq!(parsed.status, "FAILED");
        assert!(
            parsed.summary.starts_with("impl_validation_failed:"),
            "summary={}",
            parsed.summary
        );
        assert!(parsed.summary.contains("status=partial"));
        assert!(parsed.review_output.is_some());
        assert!(parsed.review_markdown.is_none());
        assert_eq!(parsed.input_tokens, Some(500));
        assert_eq!(parsed.output_tokens, Some(100));
        assert_eq!(parsed.total_tokens, Some(600));

        let blocked_fenced = [
            serde_json::json!({"type": "turn.completed", "usage": {"input_tokens": 100, "output_tokens": 20}}).to_string(),
            serde_json::json!({
                "type": "item.completed",
                "item": {
                    "type": "agent_message",
                    "text": "```json\n{\"status\":\"blocked\",\"summary\":\"blocked on missing fixture\"}\n```"
                }
            }).to_string(),
        ]
        .join("\n");
        let blocked = parse_codex_jsonl_output(&blocked_fenced, "", Some(0)).unwrap();
        assert_eq!(blocked.status, "FAILED");
        assert!(blocked.summary.starts_with("impl_validation_failed:"));
        assert!(blocked.summary.contains("status=blocked"));
        assert_eq!(blocked.total_tokens, Some(120));

        let completed_null = [
            serde_json::json!({"type": "turn.completed", "usage": {"input_tokens": 50, "output_tokens": 10}}).to_string(),
            serde_json::json!({
                "type": "item.completed",
                "item": {
                    "type": "agent_message",
                    "text": "{\"status\":\"completed\",\"summary\":\"done\",\"validation\":{\"passed\":null}}"
                }
            }).to_string(),
        ]
        .join("\n");
        let ok = parse_codex_jsonl_output(&completed_null, "", Some(0)).unwrap();
        assert_eq!(ok.status, "PASSED");
    }

    #[test]
    fn harvest_detached_persists_failed_status_on_partial_or_failed_validation_impl_report() {
        let root = TempTestDir::new("zach063-harvest-partial");
        let obs = UnitObservation::parse(
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainCode=1\nExecMainStatus=0\nInvocationID=inv-063\nControlGroup=/user.slice/zach\n",
        );

        // 1. AGY impl partial report -> harvest.json FAILED + stage-receipt.json failure_class="semantic"
        let agy_dir = root.path().join("att-agy");
        std::fs::create_dir_all(&agy_dir).unwrap();
        let mut task = sample_task();
        task.worktree_path = Some(root.path().display().to_string());
        let mut agy_route = resolve_stage_route("S", "impl", 0, Some(ModelFamily::GeminiAgy))
            .unwrap()
            .unwrap();
        agy_route.family = ModelFamily::GeminiAgy;
        let env = BTreeMap::from([("HOME".into(), root.path().display().to_string())]);
        let agy_spec =
            build_systemd_stage_command_with_env(&task, "att-agy", &agy_route, "p", &env).unwrap();
        let agy_manifest = AttemptManifest {
            mount_layout_version: 1,
            attempt_id: "att-agy".into(),
            task_id: task.task_id.clone(),
            route: agy_route,
            spec: agy_spec,
            sha_before: "abc1234".into(),
            attempt_dir: agy_dir.clone(),
        };
        std::fs::write(
            agy_dir.join("stdout.jsonl"),
            serde_json::json!({
                "status": "ok",
                "execution_succeeded": true,
                "response": "{\"status\":\"partial\",\"summary\":\"half done\",\"validation\":{\"passed\":false,\"summary\":\"tests failed\"}}",
                "duration_seconds": 33.2,
                "usage": { "input_tokens": 900, "output_tokens": 100, "total_tokens": 1000 }
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(agy_dir.join("stderr.log"), "").unwrap();

        let res = harvest_detached(&agy_manifest, &obs).unwrap();
        assert_eq!(res.status, "FAILED");
        assert!(res.summary.starts_with("impl_validation_failed:"));
        let harvest_json: StageExecutionResult =
            serde_json::from_slice(&std::fs::read(agy_dir.join("harvest.json")).unwrap()).unwrap();
        assert_eq!(harvest_json.status, "FAILED");
        let receipt_json: StageReceiptV1 =
            serde_json::from_slice(&std::fs::read(agy_dir.join("stage-receipt.json")).unwrap())
                .unwrap();
        assert_eq!(receipt_json.status, "failed");
        assert_eq!(receipt_json.failure_class.as_deref(), Some("semantic"));

        // 2. Codex impl blocked report -> harvest.json FAILED + stage-receipt.json failure_class="semantic"
        let codex_dir = root.path().join("att-codex");
        std::fs::create_dir_all(&codex_dir).unwrap();
        let mut codex_route = resolve_stage_route("S", "impl", 0, Some(ModelFamily::OpenAiSol))
            .unwrap()
            .unwrap();
        codex_route.family = ModelFamily::OpenAiSol;
        let codex_spec =
            build_systemd_stage_command_with_env(&task, "att-codex", &codex_route, "p", &env)
                .unwrap();
        let codex_manifest = AttemptManifest {
            mount_layout_version: 1,
            attempt_id: "att-codex".into(),
            task_id: task.task_id.clone(),
            route: codex_route,
            spec: codex_spec,
            sha_before: "abc1234".into(),
            attempt_dir: codex_dir.clone(),
        };
        std::fs::write(
            codex_dir.join("stdout.jsonl"),
            [
                serde_json::json!({"type":"turn.completed","usage":{"input_tokens":200,"output_tokens":50}}).to_string(),
                serde_json::json!({"type":"item.completed","item":{"type":"agent_message","text":"{\"status\":\"blocked\",\"summary\":\"cannot compile\"}"}}).to_string(),
            ]
            .join("\n"),
        )
        .unwrap();
        std::fs::write(codex_dir.join("stderr.log"), "").unwrap();
        let codex_res = harvest_detached(&codex_manifest, &obs).unwrap();
        assert_eq!(codex_res.status, "FAILED");
        let codex_receipt: StageReceiptV1 =
            serde_json::from_slice(&std::fs::read(codex_dir.join("stage-receipt.json")).unwrap())
                .unwrap();
        assert_eq!(codex_receipt.failure_class.as_deref(), Some("semantic"));
    }

    #[test]
    fn worktree_snapshot_clean_and_restore_preserves_ignored_dirs_and_resets_failed_edits() {
        let root = TempTestDir::new("zach063-git-wt");
        let non_git = root.path().join("plain-dir");
        std::fs::create_dir_all(&non_git).unwrap();
        assert!(!is_valid_git_worktree(non_git.to_str().unwrap()));
        assert_eq!(
            snapshot_and_clean_suspended_impl_worktree(non_git.to_str().unwrap(), "att-1").unwrap(),
            None
        );

        let wt = root.path().join("repo");
        std::fs::create_dir_all(&wt).unwrap();
        git(&wt, &["init", "-b", "main"]);
        // Initialize base commit using explicit -c identity so local repo has NO user.name/user.email config.
        write_rel(&wt, ".gitignore", "target/\nweb/node_modules/\n");
        write_rel(&wt, "src/lib.rs", "pub fn base() -> i32 { 1 }\n");
        write_rel(&wt, "src/old.rs", "pub fn remove_me() {}\n");
        git(&wt, &["add", "."]);
        git(
            &wt,
            &[
                "-c",
                "user.name=Init",
                "-c",
                "user.email=init@localhost",
                "commit",
                "-m",
                "base",
            ],
        );

        // Ignored build/dependency caches that MUST survive every clean/snapshot/restore.
        write_rel(&wt, "target/debug/cache.bin", "cached-rust-artifact");
        write_rel(&wt, "web/node_modules/pkg/index.js", "module.exports = 1;");

        // Uncommitted impl edits: modify tracked, delete tracked, add untracked.
        write_rel(&wt, "src/lib.rs", "pub fn base() -> i32 { 42 }\n");
        std::fs::remove_file(wt.join("src/old.rs")).unwrap();
        write_rel(&wt, "src/new_mod.rs", "pub fn added() {}\n");

        // Snapshot succeeds even without repo/global git identity!
        let snap_sha =
            snapshot_and_clean_suspended_impl_worktree(wt.to_str().unwrap(), "att-snap-1")
                .unwrap()
                .expect("dirty git worktree yields snapshot SHA");
        assert!(
            git(&wt, &["status", "--porcelain"]).trim().is_empty(),
            "worktree must be clean after snapshot"
        );
        assert_eq!(
            std::fs::read_to_string(wt.join("src/lib.rs")).unwrap(),
            "pub fn base() -> i32 { 1 }\n"
        );
        assert!(wt.join("src/old.rs").is_file());
        assert!(!wt.join("src/new_mod.rs").exists());
        assert!(wt.join("target/debug/cache.bin").is_file());
        assert!(wt.join("web/node_modules/pkg/index.js").is_file());
        let ref_sha = git(&wt, &["rev-parse", "refs/zach/suspended-impl/att-snap-1"]);
        assert_eq!(ref_sha.trim(), snap_sha);

        // Restore brings back exact dirty edits + deletes + untracked files and removes the ref.
        restore_suspended_impl_snapshot(wt.to_str().unwrap(), &snap_sha, "att-snap-1").unwrap();
        assert_eq!(
            std::fs::read_to_string(wt.join("src/lib.rs")).unwrap(),
            "pub fn base() -> i32 { 42 }\n"
        );
        assert!(!wt.join("src/old.rs").exists());
        assert_eq!(
            std::fs::read_to_string(wt.join("src/new_mod.rs")).unwrap(),
            "pub fn added() {}\n"
        );
        assert!(wt.join("target/debug/cache.bin").is_file());
        assert!(wt.join("web/node_modules/pkg/index.js").is_file());
        let ref_check = Command::new("git")
            .args([
                "-C",
                wt.to_str().unwrap(),
                "rev-parse",
                "--verify",
                "refs/zach/suspended-impl/att-snap-1",
            ])
            .output()
            .unwrap();
        assert!(!ref_check.status.success());

        // Reset cleans uncommitted changes while preserving ignored directories.
        reset_worktree_uncommitted_changes(wt.to_str().unwrap()).unwrap();
        assert!(git(&wt, &["status", "--porcelain"]).trim().is_empty());
        assert!(wt.join("target/debug/cache.bin").is_file());
        assert!(wt.join("web/node_modules/pkg/index.js").is_file());

        // Fail closed when HEAD advances past snapshot parent.
        write_rel(&wt, "src/lib.rs", "pub fn base() -> i32 { 99 }\n");
        let drifted_snap =
            snapshot_and_clean_suspended_impl_worktree(wt.to_str().unwrap(), "att-snap-2")
                .unwrap()
                .unwrap();
        write_rel(&wt, "src/other.rs", "pub fn moved() {}\n");
        git(&wt, &["add", "src/other.rs"]);
        git(
            &wt,
            &[
                "-c",
                "user.name=Init",
                "-c",
                "user.email=init@localhost",
                "commit",
                "-m",
                "advance head",
            ],
        );
        let drift_err =
            restore_suspended_impl_snapshot(wt.to_str().unwrap(), &drifted_snap, "att-snap-2")
                .unwrap_err();
        assert!(
            drift_err.contains("does not match current HEAD"),
            "err={drift_err}"
        );
        drop_suspended_impl_snapshot_ref(wt.to_str().unwrap(), "att-snap-2");
    }
}
