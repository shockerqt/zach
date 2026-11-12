use crate::v2::pipeline::DiffFileEntry;
use crate::v2::router::{ModelFamily, StageRoute, is_forbidden_daemon_model};
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageExecutionResult {
    pub status: String,
    pub summary: String,
    pub review_markdown: Option<String>,
    #[serde(default)]
    pub review_output: Option<String>,
    pub invocation_id: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
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

pub trait StageExecutor {
    fn execute_stage(
        &mut self,
        task: &TaskRecord,
        attempt_id: &str,
        route: &StageRoute,
        spec: &StageCommandSpec,
    ) -> Result<StageExecutionResult, String>;

    fn run_checks(&mut self, worktree_path: &str, commands: &[String]) -> Result<(), String>;

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
/// limits, credential path isolation (`InaccessiblePaths`), and clean environment.
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
    if is_forbidden_daemon_model(&route.model) {
        return Err(format!(
            "refusing to build stage command with forbidden daemon model '{}'",
            route.model
        ));
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

    let home = clean_env
        .get("HOME")
        .cloned()
        .unwrap_or_else(|| "/home/ubuntu".to_owned());

    let mut args = vec![
        "--user".to_owned(),
        "--collect".to_owned(),
        "--wait".to_owned(),
        "--pipe".to_owned(),
        format!("--unit={unit_name}"),
        "--slice=zach-workers.slice".to_owned(),
        "-p".to_owned(),
        format!("RuntimeMaxSec={}", route.timeout_secs),
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
        "-p".to_owned(),
        format!("InaccessiblePaths=-{home}/.config/gh"),
        "-p".to_owned(),
        format!("InaccessiblePaths=-{worktree_path}/.env"),
        "-p".to_owned(),
        format!("InaccessiblePaths=-{worktree_path}/.env.local"),
        format!("--working-directory={worktree_path}"),
    ];

    for (k, v) in clean_env {
        args.push(format!("--setenv={k}={v}"));
    }

    args.push("--".to_owned());

    let stdin_payload = match route.family {
        ModelFamily::OpenAiSol => {
            args.extend([
                "codex".to_owned(),
                "exec".to_owned(),
                "--ignore-user-config".to_owned(),
                "-m".to_owned(),
                route.model.clone(),
                "-c".to_owned(),
                format!("model_reasoning_effort={}", route.effort.as_str()),
                "-s".to_owned(),
                "workspace-write".to_owned(),
                "-C".to_owned(),
                worktree_path.clone(),
                "--json".to_owned(),
                "-".to_owned(),
            ]);
            prompt.to_owned()
        }
        ModelFamily::GeminiAgy => {
            args.extend([
                "node".to_owned(),
                GEMINI_WORKER_CLI_SCRIPT.to_owned(),
                "--cli".to_owned(),
            ]);
            let payload = crate::v2::pipeline::build_agy_cli_payload(task, route, prompt);
            serde_json::to_string(&payload)
                .map_err(|e| format!("failed to serialize agy cli payload: {e}"))?
        }
    };

    let output_schema_json =
        (route.stage == "pr-review").then(crate::v2::pipeline::review_verdict_json_schema_string);

    Ok(StageCommandSpec {
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

/// Prunes `<state_dir>/attempts/<attempt_id>` directories older than `retention`.
pub fn prune_old_attempts(
    state_dir: &std::path::Path,
    retention: std::time::Duration,
) -> Result<usize, String> {
    prune_old_attempts_at(state_dir, retention, std::time::SystemTime::now())
}

/// Prunes `<state_dir>/attempts/<attempt_id>` directories older than `retention`
/// relative to `now`, skipping symlinks and non-directories without following links.
pub fn prune_old_attempts_at(
    state_dir: &std::path::Path,
    retention: std::time::Duration,
    now: std::time::SystemTime,
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

fn validate_attempt_id(attempt_id: &str) -> Result<&str, String> {
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

fn ensure_secure_dir(dir: &std::path::Path) -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
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
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("failed to chmod 0700 {}: {e}", dir.display()))?;
    Ok(dir.to_path_buf())
}

fn write_secure_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
        .open(path)
        .map_err(|e| format!("failed to open {}: {e}", path.display()))?;
    file.write_all(bytes)
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    file.flush()
        .map_err(|e| format!("failed to flush {}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("failed to chmod 0600 {}: {e}", path.display()))?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct SystemdStageExecutor {
    pub state_dir: PathBuf,
}

impl Default for SystemdStageExecutor {
    fn default() -> Self {
        Self {
            state_dir: crate::v2::default_state_dir(),
        }
    }
}

impl SystemdStageExecutor {
    pub fn with_state_dir(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
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
    let status = if succeeded { "PASSED" } else { "FAILED" }.to_owned();
    let (input_tokens, output_tokens, total_tokens) = if saw_valid_turn_usage {
        (Some(sum_input), Some(sum_output), Some(sum_total))
    } else {
        (None, None, None)
    };

    let last_agent_message = agent_messages.last().cloned();
    let raw_summary = if !succeeded && let Some(err) = error_messages.last() {
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
    let review_markdown = last_agent_message
        .filter(|msg| msg.contains('|'))
        .or_else(|| (parsed_json_events == 0 && stdout.contains('|')).then(|| stdout.to_owned()));

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
    fn execute_stage(
        &mut self,
        task: &TaskRecord,
        attempt_id: &str,
        route: &StageRoute,
        spec: &StageCommandSpec,
    ) -> Result<StageExecutionResult, String> {
        let valid_attempt_id = validate_attempt_id(attempt_id)?;
        std::fs::create_dir_all(&self.state_dir).map_err(|e| {
            format!(
                "failed to create state_dir {}: {e}",
                self.state_dir.display()
            )
        })?;
        let attempts_root = ensure_secure_dir(&self.state_dir.join("attempts"))?;
        let attempt_dir = ensure_secure_dir(&attempts_root.join(valid_attempt_id))?;

        write_secure_file(&attempt_dir.join("prompt.md"), spec.prompt.as_bytes())?;

        let mut effective_args = spec.args.clone();
        if let Some(ref schema_json) = spec.output_schema_json {
            let schema_path = attempt_dir.join("review-schema.json");
            write_secure_file(&schema_path, schema_json.as_bytes())?;
            if route.family == ModelFamily::OpenAiSol {
                effective_args = inject_codex_output_schema_args(&effective_args, &schema_path);
            }
        }

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

        match route.family {
            ModelFamily::GeminiAgy => {
                match crate::v2::pipeline::parse_agy_cli_response(
                    &stdout,
                    &stderr,
                    output.status.code(),
                ) {
                    Ok(mut parsed) => {
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
                        Ok(parsed)
                    }
                    Err(agy_err) => {
                        let err_msg = truncate_utf8_bytes(&agy_err.to_string(), MAX_SUMMARY_BYTES);
                        let result_json = serde_json::json!({
                            "attempt_id": valid_attempt_id,
                            "task_id": task.task_id,
                            "stage": route.stage,
                            "status": "FAILED",
                            "failure_class": agy_err.failure_class,
                            "exit_code": output.status.code(),
                            "summary": err_msg,
                        });
                        write_secure_file(
                            &attempt_dir.join("result.json"),
                            serde_json::to_string_pretty(&result_json)
                                .unwrap_or_default()
                                .as_bytes(),
                        )?;
                        Err(err_msg)
                    }
                }
            }
            ModelFamily::OpenAiSol => {
                let parsed = parse_codex_jsonl_output(&stdout, &stderr, output.status.code())?;
                let result = StageExecutionResult {
                    status: parsed.status,
                    summary: parsed.summary,
                    review_markdown: parsed.review_markdown,
                    review_output: parsed.review_output,
                    invocation_id: None,
                    input_tokens: parsed.input_tokens,
                    output_tokens: parsed.output_tokens,
                    total_tokens: parsed.total_tokens,
                    sha_before,
                    sha_after,
                    diff_files,
                };
                write_stage_result_json(
                    &attempt_dir,
                    valid_attempt_id,
                    &task.task_id,
                    &route.stage,
                    output.status.code(),
                    &result,
                )?;
                Ok(result)
            }
        }
    }

    fn run_checks(&mut self, worktree_path: &str, commands: &[String]) -> Result<(), String> {
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
                let stderr = String::from_utf8_lossy(&out.stderr);
                return Err(format!("check '{cmd}' failed: {}", stderr.trim()));
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

pub struct MockStageExecutor {
    pub staged_results: Vec<StageExecutionResult>,
    pub executed_specs: Vec<StageCommandSpec>,
    pub executed_routes: Vec<StageRoute>,
    pub executed_checks: Vec<String>,
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
            staged_results: Vec::new(),
            executed_specs: Vec::new(),
            executed_routes: Vec::new(),
            executed_checks: Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;
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
            memory: TaskMemory::default(),
            version: 1,
            updated_epoch: 1000,
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
        assert!(
            spec.args
                .contains(&"InaccessiblePaths=-/home/ubuntu/.config/gh".to_owned())
        );
        assert!(
            spec.args.contains(
                &"InaccessiblePaths=-/home/ubuntu/workspace/zach--ZACH-005/.env".to_owned()
            )
        );
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
    fn gemini_worker_timeout_is_clamped_to_1800() {
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

        assert!(spec.args.contains(&"--pipe".to_owned()));
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
        assert_eq!(payload["timeout_seconds"], 1800);
        assert_eq!(payload["orchestration_id"], "zach-005");

        // Also verify lower bound clamp (30)
        route.timeout_secs = 5;
        let low_spec =
            build_systemd_stage_command_with_env(&task, "att-gemini-low", &route, "p", &clean_env)
                .expect("build low timeout command");
        let low_payload: serde_json::Value =
            serde_json::from_str(&low_spec.stdin_payload).expect("valid JSON");
        assert_eq!(low_payload["timeout_seconds"], 30);
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
        let mut exec = SystemdStageExecutor::with_state_dir(state_dir.path());

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
        let mut exec = SystemdStageExecutor::with_state_dir(state_dir.path());
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
        let mut exec = SystemdStageExecutor::with_state_dir(state_dir.path());
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
        let mut exec = SystemdStageExecutor::with_state_dir(state_dir.path());
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
}
