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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageExecutionResult {
    pub status: String,
    pub summary: String,
    pub review_markdown: Option<String>,
    pub invocation_id: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub sha_before: Option<String>,
    pub sha_after: Option<String>,
    pub diff_files: Vec<DiffFileEntry>,
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
    })
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

        let sha_before = git_head_sha(&spec.worktree_path);
        let mut child = match Command::new(&spec.program)
            .args(&spec.args)
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

        match crate::v2::pipeline::parse_agy_cli_response(&stdout, &stderr, output.status.code()) {
            Ok(mut parsed) => {
                parsed.sha_before = sha_before;
                parsed.sha_after = sha_after;
                parsed.diff_files = diff_files;
                parsed.summary = truncate_utf8_bytes(&parsed.summary, MAX_SUMMARY_BYTES);
                let result_json = serde_json::json!({
                    "attempt_id": valid_attempt_id,
                    "task_id": task.task_id,
                    "stage": route.stage,
                    "exit_code": output.status.code(),
                    "result": &parsed,
                });
                write_secure_file(
                    &attempt_dir.join("result.json"),
                    serde_json::to_string_pretty(&result_json)
                        .unwrap_or_default()
                        .as_bytes(),
                )?;
                return Ok(parsed);
            }
            Err(agy_err) if route.family == ModelFamily::GeminiAgy => {
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
                return Err(err_msg);
            }
            Err(_) => {}
        }

        let status = if output.status.success() {
            "PASSED".to_owned()
        } else {
            "FAILED".to_owned()
        };
        let raw_summary = if stdout.trim().is_empty() {
            stderr.lines().take(10).collect::<Vec<_>>().join("\n")
        } else {
            stdout.lines().take(10).collect::<Vec<_>>().join("\n")
        };
        let summary = truncate_utf8_bytes(&raw_summary, MAX_SUMMARY_BYTES);

        let result = StageExecutionResult {
            status,
            summary,
            review_markdown: if stdout.contains('|') {
                Some(stdout)
            } else {
                None
            },
            invocation_id: None,
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            sha_before,
            sha_after,
            diff_files,
        };
        let result_json = serde_json::json!({
            "attempt_id": valid_attempt_id,
            "task_id": task.task_id,
            "stage": route.stage,
            "exit_code": output.status.code(),
            "result": &result,
        });
        write_secure_file(
            &attempt_dir.join("result.json"),
            serde_json::to_string_pretty(&result_json)
                .unwrap_or_default()
                .as_bytes(),
        )?;
        Ok(result)
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
        Ok(self.staged_results.remove(0))
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
        use crate::v2::pipeline::{DiffCheckOutcome, verify_worktree_diff};
        use crate::v2::store::{ContextPackSpec, TargetFileSpec};

        let root = TempTestDir::new("zach-017-ac");
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
            verify_worktree_diff("S", &pack, &entries),
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
            verify_worktree_diff("S", &pack, &entries),
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
            verify_worktree_diff("S", &pack, &entries),
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
        match verify_worktree_diff("S", &pack, &entries) {
            DiffCheckOutcome::WeightEscalated {
                from_weight,
                to_weight,
                ..
            } => {
                assert_eq!(from_weight, "S");
                assert_eq!(to_weight, "M");
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
}
