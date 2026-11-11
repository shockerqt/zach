use crate::v2::pipeline::DiffFileEntry;
use crate::v2::router::{ModelFamily, StageRoute, is_forbidden_daemon_model};
use crate::v2::store::{TaskRecord, V2Store};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::process::Command;

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

    fn finalize_xs_s_delivery(
        &mut self,
        task: &TaskRecord,
        reviewed_sha: &str,
    ) -> Result<Option<i64>, String>;
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

    match route.family {
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
                prompt.to_owned(),
            ]);
        }
        ModelFamily::GeminiAgy => {
            let worker_timeout = route.timeout_secs.min(1800);
            args.extend([
                "node".to_owned(),
                GEMINI_WORKER_CLI_SCRIPT.to_owned(),
                "--cli".to_owned(),
                "--model".to_owned(),
                route.model.clone(),
                "--worktree".to_owned(),
                worktree_path.clone(),
                "--timeout".to_owned(),
                worker_timeout.to_string(),
                "--prompt".to_owned(),
                prompt.to_owned(),
            ]);
        }
    }

    Ok(StageCommandSpec {
        unit_name,
        program: "systemd-run".to_owned(),
        args,
        env: clean_env.clone(),
        worktree_path,
        timeout_secs: route.timeout_secs,
        stall_timeout_secs: route.stall_timeout_secs,
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

pub struct SystemdStageExecutor;

impl StageExecutor for SystemdStageExecutor {
    fn execute_stage(
        &mut self,
        _task: &TaskRecord,
        _attempt_id: &str,
        _route: &StageRoute,
        spec: &StageCommandSpec,
    ) -> Result<StageExecutionResult, String> {
        let sha_before = git_head_sha(&spec.worktree_path);
        let output = Command::new(&spec.program)
            .args(&spec.args)
            .env_clear()
            .envs(&spec.env)
            .output()
            .map_err(|e| format!("failed to spawn {}: {e}", spec.program))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let sha_after = git_head_sha(&spec.worktree_path);
        let diff_files = collect_worktree_diff_entries(&spec.worktree_path);

        if let Ok(mut parsed) =
            crate::v2::pipeline::parse_agy_cli_response(&stdout, &stderr, output.status.code())
        {
            parsed.sha_before = sha_before;
            parsed.sha_after = sha_after;
            parsed.diff_files = diff_files;
            return Ok(parsed);
        }

        let status = if output.status.success() {
            "PASSED".to_owned()
        } else {
            "FAILED".to_owned()
        };
        let summary = if stdout.trim().is_empty() {
            stderr.lines().take(10).collect::<Vec<_>>().join("\n")
        } else {
            stdout.lines().take(10).collect::<Vec<_>>().join("\n")
        };

        Ok(StageExecutionResult {
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
        })
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

    fn finalize_xs_s_delivery(
        &mut self,
        task: &TaskRecord,
        _reviewed_sha: &str,
    ) -> Result<Option<i64>, String> {
        let worktree_path = match task.worktree_path.as_deref() {
            Some(w) if !w.is_empty() => w,
            _ => return Ok(None),
        };

        // 1. Commit uncommitted changes if worktree is dirty
        let status_out = Command::new("git")
            .args(["-C", worktree_path, "status", "--porcelain"])
            .output()
            .map_err(|e| format!("failed to check git status: {e}"))?;
        let status_str = String::from_utf8_lossy(&status_out.stdout);
        if !status_str.trim().is_empty() {
            let add_out = Command::new("git")
                .args(["-C", worktree_path, "add", "-A"])
                .output()
                .map_err(|e| format!("git add failed: {e}"))?;
            if !add_out.status.success() {
                return Err(format!(
                    "git add failed: {}",
                    String::from_utf8_lossy(&add_out.stderr)
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
                .args(["-C", worktree_path, "commit", "-m", &commit_msg])
                .output()
                .map_err(|e| format!("git commit failed: {e}"))?;
            if !commit_out.status.success() {
                return Err(format!(
                    "git commit failed: {}",
                    String::from_utf8_lossy(&commit_out.stderr)
                ));
            }
        }

        // 2. Push branch
        let branch = match task.branch.as_deref() {
            Some(b) if !b.is_empty() && b != "none" => b,
            _ => return Ok(None),
        };

        let push_out = Command::new("git")
            .args(["-C", worktree_path, "push", "-u", "origin", branch])
            .output()
            .map_err(|e| format!("git push failed: {e}"))?;
        if !push_out.status.success() {
            return Err(format!(
                "git push failed: {}",
                String::from_utf8_lossy(&push_out.stderr)
            ));
        }

        // 3. Find or create PR
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

        if let Ok(lo) = list_out {
            let num_str = String::from_utf8_lossy(&lo.stdout).trim().to_owned();
            if let Ok(num) = num_str.parse::<i64>() {
                return Ok(Some(num));
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
            return Err(format!("gh pr create failed: {err}"));
        }

        let pr_url = String::from_utf8_lossy(&create_out.stdout);
        let pr_num = pr_url
            .trim()
            .rsplit('/')
            .next()
            .and_then(|s| s.parse::<i64>().ok());

        Ok(pr_num)
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

pub fn collect_worktree_diff_entries(worktree_path: &str) -> Vec<DiffFileEntry> {
    let numstat = Command::new("git")
        .args(["-C", worktree_path, "diff", "--numstat", "HEAD"])
        .output();
    let Ok(out) = numstat else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut entries = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() == 3 {
            let added = parts[0].parse::<usize>().unwrap_or(0);
            let deleted = parts[1].parse::<usize>().unwrap_or(0);
            entries.push(DiffFileEntry {
                path: parts[2].to_owned(),
                status: "M".to_owned(),
                added_lines: added,
                deleted_lines: deleted,
            });
        }
    }
    entries
}

pub struct MockStageExecutor {
    pub staged_results: Vec<StageExecutionResult>,
    pub executed_specs: Vec<StageCommandSpec>,
    pub executed_routes: Vec<StageRoute>,
    pub executed_checks: Vec<String>,
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
            finalized_sha: None,
            pr_number_to_return: Some(42),
        }
    }
}

impl StageExecutor for MockStageExecutor {
    fn execute_stage(
        &mut self,
        _task: &TaskRecord,
        _attempt_id: &str,
        route: &StageRoute,
        spec: &StageCommandSpec,
    ) -> Result<StageExecutionResult, String> {
        self.executed_routes.push(route.clone());
        self.executed_specs.push(spec.clone());
        if self.staged_results.is_empty() {
            return Err("MockStageExecutor had no staged_results left".to_owned());
        }
        Ok(self.staged_results.remove(0))
    }

    fn run_checks(&mut self, _worktree_path: &str, commands: &[String]) -> Result<(), String> {
        self.executed_checks.extend(commands.iter().cloned());
        Ok(())
    }

    fn finalize_xs_s_delivery(
        &mut self,
        _task: &TaskRecord,
        reviewed_sha: &str,
    ) -> Result<Option<i64>, String> {
        self.finalized_sha = Some(reviewed_sha.to_owned());
        Ok(self.pr_number_to_return)
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
        route.model = "gemini-3.8-flash-high".to_owned();
        route.timeout_secs = 3600;

        let clean_env = BTreeMap::new();
        let spec =
            build_systemd_stage_command_with_env(&task, "att-gemini", &route, "prompt", &clean_env)
                .expect("build command");

        let timeout_idx = spec
            .args
            .iter()
            .position(|a| a == "--timeout")
            .expect("timeout flag");
        assert_eq!(spec.args[timeout_idx + 1], "1800");
    }
}
