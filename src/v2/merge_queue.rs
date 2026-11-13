use crate::v2::delivery::{self, ContractLookup, DeliveryDriver, SystemDeliveryDriver};
use crate::v2::pipeline::matches_path_pattern;
use crate::v2::runner::build_clean_env_from_process;
use crate::v2::scheduler::{HeavyCheckSemaphore, is_heavy_verification_command};
use crate::v2::store::{MergeQueueRecord, TargetFileSpec, TaskRecord, V2Store};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::process::Command;
use std::time::{Duration, Instant};

pub const DEFAULT_CI_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_CI_POLL_INTERVAL_SECS: u64 = 10;
pub const MAX_MERGE_RETRIES: i64 = 2;
pub const MAX_REREVIEW_CYCLES: usize = 2;

const TRANSIENT_ATTEMPT_PREFIX: &str = "[MERGE_TRANSIENT]";
const REREVIEW_ATTEMPT_PREFIX: &str = "[MERGE_REREVIEW]";
const MERGE_FAIL_ATTEMPT_PREFIX: &str = "[MERGE_FAILED]";
const POST_MERGE_SHA_MAX_ATTEMPTS: usize = 3;
const POST_MERGE_SHA_RETRY_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CiPollConfig {
    pub timeout: Duration,
    pub poll_interval: Duration,
}

impl Default for CiPollConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_CI_TIMEOUT_SECS),
            poll_interval: Duration::from_secs(DEFAULT_CI_POLL_INTERVAL_SECS),
        }
    }
}

impl CiPollConfig {
    pub fn from_env() -> Self {
        let timeout_secs = std::env::var("ZACH_CI_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_CI_TIMEOUT_SECS);
        let interval_secs = std::env::var("ZACH_CI_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_CI_POLL_INTERVAL_SECS);
        Self {
            timeout: Duration::from_secs(timeout_secs),
            poll_interval: Duration::from_secs(interval_secs),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeOriginOutcome {
    Merged(String),
    Conflict { conflicted_files: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CiCheckState {
    Pending { pending_checks: Vec<String> },
    Success { passed_checks: Vec<String> },
    Failed { failed_checks: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CiPollOutcome {
    Success { passed_checks: Vec<String> },
    Failed { failed_checks: Vec<String> },
    TimedOut { pending_checks: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewedDiffOutcome {
    Clean,
    Touched(Vec<String>),
    DiffUnavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    Pushed,
    NonFastForward(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergePrError {
    PreMerge(String),
    PostMergeShaUnavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergeQueueOutcome {
    Idle,
    Blocked {
        task_id: String,
        reason: String,
    },
    Merged {
        task_id: String,
        pr_number: i64,
        merge_sha: String,
    },
    MergedPendingDelivery {
        task_id: String,
        pr_number: i64,
        merge_sha: String,
    },
    Failed {
        task_id: String,
        reason: String,
    },
    ReReviewRequired {
        task_id: String,
        touched_files: Vec<String>,
    },
}

pub trait MergeDriver {
    fn default_branch(&mut self, repo: &str, worktree_path: &str) -> Result<String, String>;

    fn merge_origin_default(
        &mut self,
        repo: &str,
        worktree_path: &str,
        default_branch: &str,
    ) -> Result<MergeOriginOutcome, String>;

    fn run_gate_checks(
        &mut self,
        repo: &str,
        worktree_path: &str,
        checks: &[String],
        semaphore: &HeavyCheckSemaphore,
    ) -> Result<(), String>;

    fn diff_touched_task_files(
        &mut self,
        worktree_path: &str,
        reviewed_sha: &str,
        head_sha: &str,
        target_files: &[TargetFileSpec],
    ) -> Result<ReviewedDiffOutcome, String>;

    fn push_head(
        &mut self,
        repo: &str,
        worktree_path: &str,
        branch: &str,
    ) -> Result<PushOutcome, String>;

    fn query_exact_sha_ci(&mut self, gh_repo: &str, sha: &str) -> Result<CiCheckState, String>;

    fn merge_pr_match_head(
        &mut self,
        gh_repo: &str,
        pr_number: i64,
        head_sha: &str,
    ) -> Result<String, MergePrError>;

    /// Defaults preserve compatibility with merge drivers predating delivery contracts.
    fn delivery_contract(&mut self, _gh_repo: &str, _sha: &str) -> ContractLookup {
        ContractLookup::ContractNotFound
    }

    fn delivery_changed_paths(
        &mut self,
        _gh_repo: &str,
        _sha: &str,
    ) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }

    fn query_delivery_aware_post_merge_ci(
        &mut self,
        gh_repo: &str,
        sha: &str,
        _excluded_workflows: &[String],
    ) -> Result<CiCheckState, String> {
        self.query_post_merge_ci(gh_repo, sha)
    }

    fn query_post_merge_ci(
        &mut self,
        gh_repo: &str,
        merge_sha: &str,
    ) -> Result<CiCheckState, String> {
        self.query_exact_sha_ci(gh_repo, merge_sha)
    }
}

/// Pure helper to resolve the default branch name from `git symbolic-ref`
/// and `git ls-remote` outputs.
pub fn parse_default_branch(symbolic_ref_output: &str, ls_remote_output: &str) -> Option<String> {
    let sym = symbolic_ref_output.trim();
    if !sym.is_empty() {
        let first_line = sym.lines().next().unwrap_or("").trim();
        let stripped = first_line
            .strip_prefix("refs/remotes/origin/")
            .unwrap_or(first_line);
        let branch = stripped.strip_prefix("origin/").unwrap_or(stripped).trim();
        if !branch.is_empty() {
            return Some(branch.to_owned());
        }
    }

    for line in ls_remote_output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("ref:") {
            let target = rest.split_whitespace().next().unwrap_or("").trim();
            let branch = target.strip_prefix("refs/heads/").unwrap_or(target).trim();
            if !branch.is_empty() {
                return Some(branch.to_owned());
            }
        }
    }

    None
}

/// Evaluates JSON output from `gh api --paginate repos/{owner}/{repo}/commits/{sha}/check-runs`.
///
/// Notes on GitHub API and literal AC-2 semantics:
/// - Covers GitHub Actions Check Runs (`check_runs` endpoint); legacy commit statuses API is excluded.
/// - Handles multi-page `--paginate` output (concatenated JSON objects or JSON arrays).
/// - Empty `check_runs` returns `Pending` to tolerate post-push registration delay (a repository
///   with zero check-runs will therefore time out into a decision).
/// - If any check-run has `status != "completed"` or lacks a non-empty `conclusion`, returns
///   `Pending` even if other check-runs have already completed or failed.
/// - Once all check-runs are `completed`, **any** `conclusion != "success"` (case-insensitive,
///   including `failure`, `cancelled`, `timed_out`, `action_required`, `neutral`, `skipped`, and
///   `stale`) returns `Failed`, following literal AC-2 ("any non-successful check fails the gate").
pub fn evaluate_check_runs_json(raw: &str) -> Result<CiCheckState, String> {
    if raw.trim().is_empty() {
        return Err("empty check-runs JSON response".to_owned());
    }

    let mut pages = Vec::new();
    let stream = serde_json::Deserializer::from_str(raw).into_iter::<serde_json::Value>();
    for item in stream {
        let value = item.map_err(|e| format!("invalid check-runs JSON: {e}"))?;
        match value {
            serde_json::Value::Array(arr) => pages.extend(arr),
            other => pages.push(other),
        }
    }

    if pages.is_empty() {
        return Err("empty check-runs JSON payload".to_owned());
    }

    let mut all_runs = Vec::new();
    let mut saw_check_runs_field = false;
    for page in &pages {
        if let Some(arr) = page.get("check_runs").and_then(|v| v.as_array()) {
            saw_check_runs_field = true;
            all_runs.extend(arr.iter());
        } else if let Some(msg) = page.get("message").and_then(|v| v.as_str()) {
            return Err(format!("github check-runs API error: {msg}"));
        }
    }

    if !saw_check_runs_field {
        return Err("check-runs JSON response missing 'check_runs' array".to_owned());
    }

    if all_runs.is_empty() {
        return Ok(CiCheckState::Pending {
            pending_checks: Vec::new(),
        });
    }

    let mut pending_checks = Vec::new();
    let mut failed_checks = Vec::new();
    let mut passed_checks = Vec::new();

    for run in all_runs {
        let name = run
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("unnamed-check")
            .to_owned();
        let status = run
            .get("status")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .unwrap_or("");
        let conclusion = run
            .get("conclusion")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());

        if !status.eq_ignore_ascii_case("completed") || conclusion.is_none() {
            pending_checks.push(name);
            continue;
        }

        let conclusion_val = conclusion.unwrap_or("");
        if conclusion_val.eq_ignore_ascii_case("success") {
            passed_checks.push(name);
        } else {
            failed_checks.push(format!("{name} ({conclusion_val})"));
        }
    }

    if !pending_checks.is_empty() {
        return Ok(CiCheckState::Pending { pending_checks });
    }
    if !failed_checks.is_empty() {
        return Ok(CiCheckState::Failed { failed_checks });
    }
    Ok(CiCheckState::Success { passed_checks })
}

/// Parses `gh pr view --json state,mergeCommit` and returns `Some(oid)` only when
/// `state == "MERGED"` and `mergeCommit.oid` is non-empty.
pub fn parse_pr_merge_commit_oid(raw: &str) -> Result<Option<String>, String> {
    let val: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("invalid gh pr view JSON: {e}"))?;
    let state = val
        .get("state")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    if !state.eq_ignore_ascii_case("MERGED") {
        return Ok(None);
    }
    let oid = val
        .get("mergeCommit")
        .and_then(|mc| mc.get("oid"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    Ok(oid)
}

/// Filters changed paths from `git diff --name-only` against `target_files` patterns.
/// If `target_files` is empty, any non-empty changed file path is treated as touched.
pub fn filter_touched_task_files(
    changed: &[String],
    target_files: &[TargetFileSpec],
) -> Vec<String> {
    let mut touched = Vec::new();
    for raw_path in changed {
        let path = raw_path.trim();
        if path.is_empty() {
            continue;
        }
        let matches = if target_files.is_empty() {
            true
        } else {
            target_files
                .iter()
                .any(|tf| matches_path_pattern(path, &tf.path))
        };
        if matches && !touched.iter().any(|p| p == path) {
            touched.push(path.to_owned());
        }
    }
    touched
}

pub fn is_non_fast_forward_push_stderr(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("non-fast-forward")
        || lower.contains("fetch first")
        || lower.contains("updates were rejected")
        || lower.contains("[rejected]")
}

fn is_transient_gh_error(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("connection")
        || lower.contains("network")
        || lower.contains("tls")
        || lower.contains("eof")
        || lower.contains("502")
        || lower.contains("503")
        || lower.contains("504")
        || lower.contains("rate limit")
        || lower.contains("temporarily unavailable")
}

/// Polls exact-SHA CI state until completion or timeout using an injectable sleeper.
pub fn poll_exact_sha_ci_with_sleep<Q, S>(
    mut query_fn: Q,
    ci_config: CiPollConfig,
    mut sleep_fn: S,
) -> Result<CiPollOutcome, String>
where
    Q: FnMut() -> Result<CiCheckState, String>,
    S: FnMut(Duration),
{
    let started = Instant::now();
    let mut simulated_elapsed = Duration::ZERO;

    loop {
        match query_fn()? {
            CiCheckState::Success { passed_checks } => {
                return Ok(CiPollOutcome::Success { passed_checks });
            }
            CiCheckState::Failed { failed_checks } => {
                return Ok(CiPollOutcome::Failed { failed_checks });
            }
            CiCheckState::Pending { pending_checks } => {
                let effective_elapsed = simulated_elapsed.max(started.elapsed());
                if effective_elapsed >= ci_config.timeout {
                    return Ok(CiPollOutcome::TimedOut { pending_checks });
                }
                let remaining = ci_config.timeout.saturating_sub(effective_elapsed);
                let sleep_dur = ci_config.poll_interval.min(remaining);
                sleep_fn(sleep_dur);
                let advance = if sleep_dur.is_zero() {
                    Duration::from_secs(1).min(remaining)
                } else {
                    sleep_dur
                };
                simulated_elapsed = simulated_elapsed.saturating_add(advance);
            }
        }
    }
}

pub fn poll_exact_sha_ci<Q>(query_fn: Q, ci_config: CiPollConfig) -> Result<CiPollOutcome, String>
where
    Q: FnMut() -> Result<CiCheckState, String>,
{
    poll_exact_sha_ci_with_sleep(query_fn, ci_config, std::thread::sleep)
}

fn run_shell_check(
    worktree_path: &str,
    cmd: &str,
    clean_env: &BTreeMap<String, String>,
    label: &str,
) -> Result<(), String> {
    let out = Command::new("bash")
        .args(["-lc", cmd])
        .current_dir(worktree_path)
        .env_clear()
        .envs(clean_env)
        .output()
        .map_err(|e| format!("failed to run {label} '{cmd}': {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("{label} '{cmd}' failed: {}", stderr.trim()));
    }
    Ok(())
}

fn fetch_merged_pr_commit_oid_with_sleep<F, S>(
    mut query_pr_view: F,
    mut sleep_fn: S,
) -> Result<String, String>
where
    F: FnMut() -> Result<String, String>,
    S: FnMut(Duration),
{
    let mut last_reason = String::from("PR mergeCommit.oid was not populated");
    for attempt in 0..POST_MERGE_SHA_MAX_ATTEMPTS {
        match query_pr_view() {
            Ok(stdout) => match parse_pr_merge_commit_oid(&stdout) {
                Ok(Some(oid)) => return Ok(oid),
                Ok(None) => {
                    last_reason = "PR not yet MERGED or mergeCommit.oid is null".to_owned();
                }
                Err(err) => {
                    last_reason = err;
                }
            },
            Err(err) => {
                last_reason = err;
            }
        }
        if attempt + 1 < POST_MERGE_SHA_MAX_ATTEMPTS {
            sleep_fn(POST_MERGE_SHA_RETRY_DELAY);
        }
    }
    Err(last_reason)
}

pub struct SystemMergeDriver;

impl MergeDriver for SystemMergeDriver {
    fn delivery_contract(&mut self, gh_repo: &str, sha: &str) -> ContractLookup {
        SystemDeliveryDriver.contract(gh_repo, sha)
    }

    fn delivery_changed_paths(&mut self, gh_repo: &str, sha: &str) -> Result<Vec<String>, String> {
        SystemDeliveryDriver.changed_paths(gh_repo, sha)
    }

    fn query_delivery_aware_post_merge_ci(
        &mut self,
        gh_repo: &str,
        sha: &str,
        excluded: &[String],
    ) -> Result<CiCheckState, String> {
        if excluded.is_empty() {
            self.query_post_merge_ci(gh_repo, sha)
        } else {
            delivery::query_contract_ci(gh_repo, sha, excluded)
        }
    }

    fn default_branch(&mut self, repo: &str, worktree_path: &str) -> Result<String, String> {
        let sym_output = Command::new("git")
            .args([
                "-C",
                worktree_path,
                "symbolic-ref",
                "--short",
                "refs/remotes/origin/HEAD",
            ])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
            .unwrap_or_default();

        let ls_remote_output = if parse_default_branch(&sym_output, "").is_none() {
            Command::new("git")
                .args([
                    "-C",
                    worktree_path,
                    "ls-remote",
                    "--symref",
                    "origin",
                    "HEAD",
                ])
                .output()
                .ok()
                .filter(|out| out.status.success())
                .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
                .unwrap_or_default()
        } else {
            String::new()
        };

        parse_default_branch(&sym_output, &ls_remote_output)
            .ok_or_else(|| format!("could not resolve default branch for repository {repo}"))
    }

    fn merge_origin_default(
        &mut self,
        _repo: &str,
        worktree_path: &str,
        default_branch: &str,
    ) -> Result<MergeOriginOutcome, String> {
        let fetch = Command::new("git")
            .args(["-C", worktree_path, "fetch", "origin", default_branch])
            .output()
            .map_err(|e| format!("git fetch failed: {e}"))?;
        if !fetch.status.success() {
            let stderr = String::from_utf8_lossy(&fetch.stderr);
            return Err(format!(
                "git fetch origin/{default_branch} failed: {}",
                stderr.trim()
            ));
        }

        let merge = Command::new("git")
            .args([
                "-C",
                worktree_path,
                "merge",
                "--no-edit",
                &format!("origin/{default_branch}"),
            ])
            .output()
            .map_err(|e| format!("git merge failed: {e}"))?;

        if !merge.status.success() {
            let stderr = String::from_utf8_lossy(&merge.stderr);
            let conflicted_files: Vec<String> = Command::new("git")
                .args([
                    "-C",
                    worktree_path,
                    "diff",
                    "--name-only",
                    "--diff-filter=U",
                ])
                .output()
                .ok()
                .filter(|out| out.status.success())
                .map(|out| {
                    String::from_utf8_lossy(&out.stdout)
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();

            let _ = Command::new("git")
                .args(["-C", worktree_path, "merge", "--abort"])
                .output();

            if !conflicted_files.is_empty() {
                return Ok(MergeOriginOutcome::Conflict { conflicted_files });
            }
            return Err(format!(
                "git merge --no-edit origin/{default_branch} failed: {}",
                stderr.trim()
            ));
        }

        let rev = Command::new("git")
            .args(["-C", worktree_path, "rev-parse", "HEAD"])
            .output()
            .map_err(|e| format!("git rev-parse HEAD failed: {e}"))?;
        if !rev.status.success() {
            return Err("git rev-parse HEAD failed after merge".to_owned());
        }
        Ok(MergeOriginOutcome::Merged(
            String::from_utf8_lossy(&rev.stdout).trim().to_owned(),
        ))
    }

    fn run_gate_checks(
        &mut self,
        _repo: &str,
        worktree_path: &str,
        checks: &[String],
        semaphore: &HeavyCheckSemaphore,
    ) -> Result<(), String> {
        let clean_env = build_clean_env_from_process();
        for cmd in checks {
            if is_heavy_verification_command(cmd) {
                semaphore.run_serialized(|| {
                    run_shell_check(worktree_path, cmd, &clean_env, "heavy check")
                })?;
            } else {
                run_shell_check(worktree_path, cmd, &clean_env, "check")?;
            }
        }
        Ok(())
    }

    fn diff_touched_task_files(
        &mut self,
        worktree_path: &str,
        reviewed_sha: &str,
        head_sha: &str,
        target_files: &[TargetFileSpec],
    ) -> Result<ReviewedDiffOutcome, String> {
        let rev_sha = reviewed_sha.trim();
        let new_sha = head_sha.trim();
        if rev_sha.is_empty() || rev_sha == "head-sha" {
            return Ok(ReviewedDiffOutcome::DiffUnavailable(
                "missing or placeholder reviewed_sha".to_owned(),
            ));
        }
        if rev_sha == new_sha {
            return Ok(ReviewedDiffOutcome::Clean);
        }

        let diff = Command::new("git")
            .args(["-C", worktree_path, "diff", "--name-only", rev_sha, new_sha])
            .output();
        let out = match diff {
            Ok(out) => out,
            Err(e) => {
                return Ok(ReviewedDiffOutcome::DiffUnavailable(format!(
                    "git diff failed to spawn: {e}"
                )));
            }
        };
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Ok(ReviewedDiffOutcome::DiffUnavailable(format!(
                "git diff {rev_sha}..{new_sha} failed: {}",
                stderr.trim()
            )));
        }

        let changed: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect();
        let touched = filter_touched_task_files(&changed, target_files);
        if touched.is_empty() {
            Ok(ReviewedDiffOutcome::Clean)
        } else {
            Ok(ReviewedDiffOutcome::Touched(touched))
        }
    }

    fn push_head(
        &mut self,
        _repo: &str,
        worktree_path: &str,
        branch: &str,
    ) -> Result<PushOutcome, String> {
        let trimmed = branch.trim();
        if trimmed.is_empty() {
            return Err("cannot push head: task branch is empty".to_owned());
        }
        let refspec = format!("HEAD:refs/heads/{trimmed}");
        let out = Command::new("git")
            .args(["-C", worktree_path, "push", "origin", &refspec])
            .output()
            .map_err(|e| format!("git push failed to spawn: {e}"))?;
        if out.status.success() {
            return Ok(PushOutcome::Pushed);
        }
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        if is_non_fast_forward_push_stderr(&stderr) {
            return Ok(PushOutcome::NonFastForward(stderr));
        }
        Err(format!("git push origin {refspec} failed: {stderr}"))
    }

    fn query_exact_sha_ci(&mut self, gh_repo: &str, sha: &str) -> Result<CiCheckState, String> {
        let endpoint = format!("repos/{gh_repo}/commits/{sha}/check-runs");
        let out = Command::new("gh")
            .args(["api", "--paginate", &endpoint])
            .output()
            .map_err(|e| format!("gh api {endpoint} failed: {e}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!("gh api {endpoint} failed: {}", stderr.trim()));
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        evaluate_check_runs_json(&stdout)
    }

    fn merge_pr_match_head(
        &mut self,
        gh_repo: &str,
        pr_number: i64,
        head_sha: &str,
    ) -> Result<String, MergePrError> {
        let pr_arg = pr_number.to_string();
        let out = Command::new("gh")
            .args([
                "pr",
                "merge",
                &pr_arg,
                "--merge",
                "--match-head-commit",
                head_sha,
                "--repo",
                gh_repo,
            ])
            .output()
            .map_err(|e| MergePrError::PreMerge(format!("gh pr merge failed: {e}")))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(MergePrError::PreMerge(format!(
                "gh pr merge failed: {}",
                stderr.trim()
            )));
        }

        // gh pr merge succeeded on GitHub: never parse merge SHA from stdout and never
        // route back to impl from here. Query mergeCommit.oid via gh pr view with backoff.
        fetch_merged_pr_commit_oid_with_sleep(
            || {
                let view = Command::new("gh")
                    .args([
                        "pr",
                        "view",
                        &pr_arg,
                        "--repo",
                        gh_repo,
                        "--json",
                        "state,mergeCommit",
                    ])
                    .output()
                    .map_err(|e| format!("gh pr view failed: {e}"))?;
                if !view.status.success() {
                    let stderr = String::from_utf8_lossy(&view.stderr);
                    return Err(format!("gh pr view failed: {}", stderr.trim()));
                }
                Ok(String::from_utf8_lossy(&view.stdout).into_owned())
            },
            std::thread::sleep,
        )
        .map_err(MergePrError::PostMergeShaUnavailable)
    }
}

/// Enqueues a task's pull request into the per-repository FIFO merge queue.
pub fn enqueue_for_merge(
    store: &mut V2Store,
    repo: &str,
    task_id: &str,
    pr_number: i64,
    reviewed_sha: &str,
) -> Result<MergeQueueRecord, String> {
    let rec = store
        .enqueue_merge_queue(repo, task_id, pr_number, reviewed_sha)
        .map_err(|e| e.to_string())?;

    if let Ok(Some(mut task)) = store.get_task(task_id) {
        task.status = "Queued for Merge".to_owned();
        task.current_stage = Some("merge_queue".to_owned());
        task.pr_number = Some(pr_number);
        task.reviewed_sha = Some(reviewed_sha.to_owned());
        let _ = store.upsert_task(&task);
    }

    Ok(rec)
}

/// Returns the next eligible `QUEUED` item in FIFO order for `repo`, or `None`
/// if the repo lane is busy (`MERGING`) or blocked (`MERGE_QUEUE_BLOCKED`).
pub fn dequeue_next(store: &V2Store, repo: &str) -> Result<Option<MergeQueueRecord>, String> {
    let entries = store
        .list_merge_queue(Some(repo))
        .map_err(|e| e.to_string())?;

    if entries
        .iter()
        .any(|e| e.state == "MERGING" || e.state == "MERGE_QUEUE_BLOCKED")
    {
        return Ok(None);
    }

    for entry in entries {
        if entry.state == "QUEUED" {
            return Ok(Some(entry));
        }
    }
    Ok(None)
}

fn push_recent_attempt(task: &mut TaskRecord, entry: String) {
    task.memory.recent_attempts.push(entry);
    if task.memory.recent_attempts.len() > 10 {
        let drain = task.memory.recent_attempts.len() - 10;
        task.memory.recent_attempts.drain(0..drain);
    }
}

fn count_attempts_with_prefix(task: &TaskRecord, prefix: &str) -> usize {
    task.memory
        .recent_attempts
        .iter()
        .filter(|a| a.starts_with(prefix))
        .count()
}

fn strip_post_plan_stages(task: &mut TaskRecord) {
    task.stages_completed
        .retain(|s| s != "impl" && s != "pr-review" && s != "human-merge-approval");
}

fn strip_review_stages(task: &mut TaskRecord) {
    task.stages_completed
        .retain(|s| s != "pr-review" && s != "human-merge-approval");
}

struct DecisionSpec<'a> {
    kind: &'a str,
    question: &'a str,
    context: &'a str,
    strip_stages: bool,
    sha: Option<&'a str>,
}

fn return_task_to_impl(
    store: &mut V2Store,
    repo: &str,
    task: &mut TaskRecord,
    reason: &str,
    detail: &str,
) -> Result<MergeQueueOutcome, String> {
    strip_post_plan_stages(task);
    task.retry_count += 1;
    task.status = "Ready".to_owned();
    task.current_stage = Some("impl".to_owned());
    task.memory.last_check_failure = Some(detail.to_owned());
    push_recent_attempt(
        task,
        format!("{MERGE_FAIL_ATTEMPT_PREFIX} [{reason}] {detail}"),
    );

    // Upsert task state before removing merge_queue entry to close the crash window.
    store.upsert_task(task).map_err(|e| e.to_string())?;
    store
        .remove_merge_queue_entry(repo, &task.task_id)
        .map_err(|e| e.to_string())?;

    let _ = store.append_event(
        &task.task_id,
        &task.task_group,
        "MERGE_FAILED",
        &serde_json::json!({
            "step": reason,
            "error": detail,
            "returned_to": "impl",
        }),
    );

    Ok(MergeQueueOutcome::Failed {
        task_id: task.task_id.clone(),
        reason: detail.to_owned(),
    })
}

fn return_task_for_rereview(
    store: &mut V2Store,
    repo: &str,
    task: &mut TaskRecord,
    touched_files: Vec<String>,
    detail: &str,
) -> Result<MergeQueueOutcome, String> {
    strip_review_stages(task);
    task.status = "Ready".to_owned();
    task.current_stage = Some("pr-review".to_owned());
    task.memory.last_check_failure = Some(detail.to_owned());
    push_recent_attempt(task, format!("{REREVIEW_ATTEMPT_PREFIX} {detail}"));

    store.upsert_task(task).map_err(|e| e.to_string())?;
    store
        .remove_merge_queue_entry(repo, &task.task_id)
        .map_err(|e| e.to_string())?;

    let _ = store.append_event(
        &task.task_id,
        &task.task_group,
        "MERGE_REQUIRES_PR_REVIEW",
        &serde_json::json!({
            "touched_files": touched_files,
            "reason": detail,
        }),
    );

    Ok(MergeQueueOutcome::ReReviewRequired {
        task_id: task.task_id.clone(),
        touched_files,
    })
}

fn fail_entry_with_decision(
    store: &mut V2Store,
    repo: &str,
    task: &mut TaskRecord,
    spec: DecisionSpec<'_>,
) -> Result<MergeQueueOutcome, String> {
    if spec.strip_stages {
        strip_post_plan_stages(task);
    }
    task.status = "Blocked".to_owned();
    task.memory.last_check_failure = Some(spec.context.to_owned());
    push_recent_attempt(
        task,
        format!(
            "{MERGE_FAIL_ATTEMPT_PREFIX} [{}] {}",
            spec.kind, spec.context
        ),
    );

    let persisted = store.upsert_task(task).map_err(|e| e.to_string())?;
    let dec_id = format!(
        "dec-{}-{}-v{}",
        persisted.task_id.to_ascii_lowercase(),
        spec.kind.replace('_', "-"),
        persisted.version
    );
    let options = vec!["Retry merge".to_owned(), "Abandon".to_owned()];
    store
        .open_decision(
            &dec_id,
            &persisted.task_id,
            &persisted.task_group,
            spec.kind,
            spec.question,
            &options,
            Some(0),
            spec.context,
            spec.sha,
        )
        .map_err(|e| e.to_string())?;

    store
        .remove_merge_queue_entry(repo, &persisted.task_id)
        .map_err(|e| e.to_string())?;

    let _ = store.append_event(
        &persisted.task_id,
        &persisted.task_group,
        "MERGE_FAILED",
        &serde_json::json!({
            "step": spec.kind,
            "error": spec.context,
            "decision_id": dec_id,
        }),
    );

    Ok(MergeQueueOutcome::Blocked {
        task_id: persisted.task_id,
        reason: spec.context.to_owned(),
    })
}

fn handle_transient_merge_error(
    store: &mut V2Store,
    repo: &str,
    task: &mut TaskRecord,
    step: &str,
    err: &str,
) -> Result<MergeQueueOutcome, String> {
    let transient_count = count_attempts_with_prefix(task, TRANSIENT_ATTEMPT_PREFIX);
    if transient_count >= MAX_MERGE_RETRIES as usize {
        let kind = format!("merge_{step}_failed");
        let question = format!(
            "Merge queue step '{step}' for {} failed repeatedly ({err}). How should we proceed?",
            task.task_id
        );
        return fail_entry_with_decision(
            store,
            repo,
            task,
            DecisionSpec {
                kind: &kind,
                question: &question,
                context: err,
                strip_stages: false,
                sha: None,
            },
        );
    }

    task.memory.last_check_failure = Some(format!("[{step}] {err}"));
    push_recent_attempt(task, format!("{TRANSIENT_ATTEMPT_PREFIX} [{step}] {err}"));
    store.upsert_task(task).map_err(|e| e.to_string())?;

    // Explicitly reset state from MERGING back to QUEUED so the lane does not stick.
    store
        .update_merge_queue_state(repo, &task.task_id, "QUEUED")
        .map_err(|e| e.to_string())?;

    let _ = store.append_event(
        &task.task_id,
        &task.task_group,
        "MERGE_FAILED",
        &serde_json::json!({
            "step": step,
            "error": err,
            "transient": true,
        }),
    );

    Ok(MergeQueueOutcome::Failed {
        task_id: task.task_id.clone(),
        reason: err.to_owned(),
    })
}

fn block_repo_with_decision(
    store: &mut V2Store,
    repo: &str,
    task: &mut TaskRecord,
    pr_number: i64,
    options: &[String],
    spec: DecisionSpec<'_>,
) -> Result<MergeQueueOutcome, String> {
    store
        .update_merge_queue_state(repo, &task.task_id, "MERGE_QUEUE_BLOCKED")
        .map_err(|e| e.to_string())?;

    task.status = "Blocked".to_owned();
    task.memory.last_check_failure = Some(spec.context.to_owned());
    push_recent_attempt(
        task,
        format!(
            "{MERGE_FAIL_ATTEMPT_PREFIX} [{}] {}",
            spec.kind, spec.context
        ),
    );
    let persisted = store.upsert_task(task).map_err(|e| e.to_string())?;

    let dec_id = format!(
        "dec-{}-{}-v{}",
        persisted.task_id.to_ascii_lowercase(),
        spec.kind.replace('_', "-"),
        persisted.version
    );
    store
        .open_decision(
            &dec_id,
            &persisted.task_id,
            &persisted.task_group,
            spec.kind,
            spec.question,
            options,
            Some(0),
            spec.context,
            spec.sha,
        )
        .map_err(|e| e.to_string())?;

    let _ = store.append_event(
        &persisted.task_id,
        &persisted.task_group,
        "MERGE_QUEUE_BLOCKED",
        &serde_json::json!({
            "repo": repo,
            "merge_sha": spec.sha,
            "pr_number": pr_number,
            "kind": spec.kind,
            "decision_id": dec_id,
        }),
    );

    Ok(MergeQueueOutcome::Blocked {
        task_id: persisted.task_id,
        reason: spec.context.to_owned(),
    })
}

fn route_retryable_or_decision(
    store: &mut V2Store,
    repo: &str,
    task: &mut TaskRecord,
    step: &str,
    spec: DecisionSpec<'_>,
) -> Result<MergeQueueOutcome, String> {
    if task.retry_count < MAX_MERGE_RETRIES {
        return_task_to_impl(store, repo, task, step, spec.context)
    } else {
        fail_entry_with_decision(store, repo, task, spec)
    }
}

/// Drives the head of the per-repository FIFO merge queue through:
/// 1. `git merge --no-edit origin/<default>` (aborting cleanly on conflict)
/// 2. Gate checks under `HeavyCheckSemaphore`
/// 3. Reviewed-SHA diff check against `target_files` (AC-4, before push/CI)
/// 4. `git push origin HEAD:refs/heads/<branch>` without `--force` (AC-1)
/// 5. Exact-SHA CI polling until complete or timeout (AC-2)
/// 6. Merge via `gh pr merge --match-head-commit <sha>` + `gh pr view` `mergeCommit.oid` (AC-3)
/// 7. Post-merge CI polling on `merge_sha`
pub fn process_repo_merge_queue(
    store: &mut V2Store,
    repo: &str,
    driver: &mut dyn MergeDriver,
    semaphore: &HeavyCheckSemaphore,
) -> Result<MergeQueueOutcome, String> {
    process_repo_merge_queue_with_config(
        store,
        repo,
        driver,
        semaphore,
        CiPollConfig::from_env(),
        std::thread::sleep,
    )
}

pub fn process_repo_merge_queue_with_config<S>(
    store: &mut V2Store,
    repo: &str,
    driver: &mut dyn MergeDriver,
    semaphore: &HeavyCheckSemaphore,
    ci_config: CiPollConfig,
    mut sleep_fn: S,
) -> Result<MergeQueueOutcome, String>
where
    S: FnMut(Duration),
{
    let entries = store
        .list_merge_queue(Some(repo))
        .map_err(|e| e.to_string())?;

    // A crash after the durable delivery handoff can leave the merge entry
    // MERGING. Delivery rows prove merge CI already passed; never merge again.
    for entry in &entries {
        let deliveries = store
            .list_deliveries(Some(&entry.task_id))
            .map_err(|e| e.to_string())?;
        if let Some(first) = deliveries.first() {
            if first.repository != repo
                || deliveries
                    .iter()
                    .any(|row| row.merge_sha != first.merge_sha)
            {
                return Err("inconsistent persisted merge delivery handoff".into());
            }
            let task = store
                .get_task(&entry.task_id)
                .map_err(|e| e.to_string())?
                .ok_or("delivery handoff task missing")?;
            // Keep the queue entry until lock release succeeds so another crash
            // still leaves enough durable evidence to finish the handoff.
            store
                .release_path_locks(&entry.task_id)
                .map_err(|e| e.to_string())?;
            store
                .remove_merge_queue_entry(repo, &entry.task_id)
                .map_err(|e| e.to_string())?;
            return Ok(if task.status == "Done" {
                MergeQueueOutcome::Merged {
                    task_id: entry.task_id.clone(),
                    pr_number: entry.pr_number,
                    merge_sha: first.merge_sha.clone(),
                }
            } else {
                MergeQueueOutcome::MergedPendingDelivery {
                    task_id: entry.task_id.clone(),
                    pr_number: entry.pr_number,
                    merge_sha: first.merge_sha.clone(),
                }
            });
        }
    }

    if let Some(blocked) = entries.iter().find(|e| e.state == "MERGE_QUEUE_BLOCKED") {
        return Ok(MergeQueueOutcome::Blocked {
            task_id: blocked.task_id.clone(),
            reason: format!(
                "merge queue for repository '{repo}' is blocked pending human intervention"
            ),
        });
    }

    let Some(entry) = dequeue_next(store, repo)? else {
        return Ok(MergeQueueOutcome::Idle);
    };

    store
        .update_merge_queue_state(repo, &entry.task_id, "MERGING")
        .map_err(|e| e.to_string())?;

    let mut task = store
        .get_task(&entry.task_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("task '{}' not found in store", entry.task_id))?;
    let task_id = task.task_id.clone();

    let gh_repo = task
        .github_repo
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(repo)
        .to_owned();

    let worktree_path = task.worktree_path.clone().unwrap_or_default();
    if worktree_path.trim().is_empty() {
        return fail_entry_with_decision(
            store,
            repo,
            &mut task,
            DecisionSpec {
                kind: "merge_missing_worktree",
                question: &format!("Task {task_id} has no worktree_path configured"),
                context: "worktree_path is missing or empty",
                strip_stages: false,
                sha: None,
            },
        );
    }

    let default_branch = match driver.default_branch(repo, &worktree_path) {
        Ok(branch) => branch,
        Err(err) => {
            return handle_transient_merge_error(store, repo, &mut task, "default_branch", &err);
        }
    };

    // 1. Merge origin/<default_branch>
    let merge_head = match driver.merge_origin_default(repo, &worktree_path, &default_branch) {
        Ok(MergeOriginOutcome::Merged(head)) => head,
        Ok(MergeOriginOutcome::Conflict { conflicted_files }) => {
            let detail = format!(
                "merge conflict with origin/{default_branch} in files: {}",
                conflicted_files.join(", ")
            );
            if !task.weight.trim().eq_ignore_ascii_case("L") && task.retry_count < MAX_MERGE_RETRIES
            {
                return return_task_to_impl(store, repo, &mut task, "merge_conflict", &detail);
            }
            return fail_entry_with_decision(
                store,
                repo,
                &mut task,
                DecisionSpec {
                    kind: "merge_conflict",
                    question: &format!(
                        "Merge conflict on {task_id} against origin/{default_branch}. How should we proceed?"
                    ),
                    context: &detail,
                    strip_stages: true,
                    sha: None,
                },
            );
        }
        Err(err) => {
            return handle_transient_merge_error(
                store,
                repo,
                &mut task,
                "merge_origin_default",
                &err,
            );
        }
    };

    let target_sha = if !merge_head.trim().is_empty() {
        merge_head
    } else {
        entry.reviewed_sha.clone()
    };

    // 2. Gate checks under heavy semaphore
    if let Err(err) = driver.run_gate_checks(
        repo,
        &worktree_path,
        &task.context_pack.gate_checks,
        semaphore,
    ) {
        return route_retryable_or_decision(
            store,
            repo,
            &mut task,
            "gate_checks",
            DecisionSpec {
                kind: "merge_gate_checks_failed",
                question: &format!("Gate checks failed in merge queue for {task_id}"),
                context: &err,
                strip_stages: true,
                sha: Some(&target_sha),
            },
        );
    }

    // 3. AC-4: Check reviewed_sha..target_sha diff BEFORE push_head and CI polling so
    // a required re-review does not push an unreviewed merge or wait on CI.
    let reviewed_sha = task
        .reviewed_sha
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&entry.reviewed_sha)
        .to_owned();
    let rereview_reason = match driver.diff_touched_task_files(
        &worktree_path,
        &reviewed_sha,
        &target_sha,
        &task.context_pack.target_files,
    ) {
        Ok(ReviewedDiffOutcome::Clean) => None,
        Ok(ReviewedDiffOutcome::Touched(files)) => Some((
            files.clone(),
            format!(
                "merge with origin/{default_branch} touched task files since {reviewed_sha}: {}",
                files.join(", ")
            ),
        )),
        Ok(ReviewedDiffOutcome::DiffUnavailable(reason)) | Err(reason) => Some((
            Vec::new(),
            format!("unable to verify diff between {reviewed_sha} and {target_sha}: {reason}"),
        )),
    };

    if let Some((touched_files, detail)) = rereview_reason {
        let cycles = count_attempts_with_prefix(&task, REREVIEW_ATTEMPT_PREFIX);
        if cycles < MAX_REREVIEW_CYCLES {
            return return_task_for_rereview(store, repo, &mut task, touched_files, &detail);
        }
        return fail_entry_with_decision(
            store,
            repo,
            &mut task,
            DecisionSpec {
                kind: "merge_rereview_limit",
                question: &format!(
                    "Task {task_id} exceeded {MAX_REREVIEW_CYCLES} merge re-review cycles. How should we proceed?"
                ),
                context: &detail,
                strip_stages: false,
                sha: Some(&target_sha),
            },
        );
    }

    // 4. AC-1: Push merged branch head before querying exact-SHA CI (no --force).
    let Some(branch) = task
        .branch
        .as_deref()
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .map(str::to_owned)
    else {
        return fail_entry_with_decision(
            store,
            repo,
            &mut task,
            DecisionSpec {
                kind: "merge_missing_branch",
                question: &format!("Task {task_id} has no branch configured for push"),
                context: "task.branch is missing or empty",
                strip_stages: false,
                sha: Some(&target_sha),
            },
        );
    };

    match driver.push_head(repo, &worktree_path, &branch) {
        Ok(PushOutcome::Pushed) => {}
        Ok(PushOutcome::NonFastForward(stderr)) => {
            // Non-FF push rejection opens a decision with strip_stages = false.
            let detail = format!("non-fast-forward push rejected for {branch}: {stderr}");
            return fail_entry_with_decision(
                store,
                repo,
                &mut task,
                DecisionSpec {
                    kind: "merge_push_non_ff",
                    question: &format!(
                        "Remote branch '{branch}' diverged and rejected non-force push for {task_id}. How should we proceed?"
                    ),
                    context: &detail,
                    strip_stages: false,
                    sha: Some(&target_sha),
                },
            );
        }
        Err(err) => {
            return handle_transient_merge_error(store, repo, &mut task, "push_head", &err);
        }
    }

    // 5. AC-2: Poll exact-SHA CI until all checks complete or timeout.
    match poll_exact_sha_ci_with_sleep(
        || driver.query_exact_sha_ci(&gh_repo, &target_sha),
        ci_config,
        &mut sleep_fn,
    ) {
        Ok(CiPollOutcome::Success { .. }) => {}
        Ok(CiPollOutcome::Failed { failed_checks }) => {
            let detail = format!(
                "exact-SHA CI failed for sha {target_sha}: {}",
                failed_checks.join(", ")
            );
            return route_retryable_or_decision(
                store,
                repo,
                &mut task,
                "exact_sha_ci",
                DecisionSpec {
                    kind: "merge_ci_failed",
                    question: &format!(
                        "Exact-SHA CI failed for {task_id} ({target_sha}) after retries"
                    ),
                    context: &detail,
                    strip_stages: true,
                    sha: Some(&target_sha),
                },
            );
        }
        Ok(CiPollOutcome::TimedOut { pending_checks }) => {
            // CI timeout opens a decision with strip_stages = false (never misreported as failed).
            let pending_desc = if pending_checks.is_empty() {
                "no check-runs reported".to_owned()
            } else {
                pending_checks.join(", ")
            };
            let detail = format!(
                "exact-SHA CI timed out after {}s for sha {target_sha} (pending: {pending_desc})",
                ci_config.timeout.as_secs()
            );
            return fail_entry_with_decision(
                store,
                repo,
                &mut task,
                DecisionSpec {
                    kind: "merge_ci_timeout",
                    question: &format!(
                        "CI timed out waiting for checks on {task_id} ({target_sha}). Retry merge or abandon?"
                    ),
                    context: &detail,
                    strip_stages: false,
                    sha: Some(&target_sha),
                },
            );
        }
        Err(err) => {
            return handle_transient_merge_error(store, repo, &mut task, "exact_sha_ci", &err);
        }
    }

    // 6. AC-3: Merge PR with --match-head-commit <sha> and read mergeCommit.oid from PR.
    let merge_sha = match driver.merge_pr_match_head(&gh_repo, entry.pr_number, &target_sha) {
        Ok(sha) => sha,
        Err(MergePrError::PostMergeShaUnavailable(err)) => {
            // PR is already merged on GitHub: block the repo lane with manual options,
            // never Retry merge and never return_task_to_impl.
            let options = vec![
                "Record merge SHA manually".to_owned(),
                "Unblock lane".to_owned(),
            ];
            let context = format!(
                "PR #{} merged on GitHub but mergeCommit.oid could not be read: {err}",
                entry.pr_number
            );
            let question = format!(
                "PR #{} for {task_id} merged on GitHub, but its mergeCommit.oid was unavailable. Record the merge SHA manually or unblock repository '{repo}'.",
                entry.pr_number
            );
            return block_repo_with_decision(
                store,
                repo,
                &mut task,
                entry.pr_number,
                &options,
                DecisionSpec {
                    kind: "post_merge_sha_unavailable",
                    question: &question,
                    context: &context,
                    strip_stages: false,
                    sha: None,
                },
            );
        }
        Err(MergePrError::PreMerge(err)) => {
            if is_transient_gh_error(&err) {
                return handle_transient_merge_error(
                    store,
                    repo,
                    &mut task,
                    "merge_pr_match_head",
                    &err,
                );
            }
            return route_retryable_or_decision(
                store,
                repo,
                &mut task,
                "merge_pr_match_head",
                DecisionSpec {
                    kind: "merge_pr_failed",
                    question: &format!(
                        "gh pr merge failed for PR #{} on {task_id}",
                        entry.pr_number
                    ),
                    context: &err,
                    strip_stages: true,
                    sha: Some(&target_sha),
                },
            );
        }
    };

    // Discover the contract at the immutable merge SHA before evaluating push CI.
    // Contract delivery jobs are observed by the delivery poller, not the repo lane.
    let contract = driver.delivery_contract(&gh_repo, &merge_sha);
    let excluded_workflows: Vec<String> = match &contract {
        ContractLookup::Found(contract) => contract
            .post_merge_workflows
            .iter()
            .map(|rule| rule.workflow.clone())
            .chain(
                contract
                    .promotions
                    .iter()
                    .map(|rule| rule.build_workflow.clone()),
            )
            .collect(),
        _ => Vec::new(),
    };

    // 7. Verify merge CI, excluding the contract-owned delivery workflows.
    let post_merge_failure = match poll_exact_sha_ci_with_sleep(
        || driver.query_delivery_aware_post_merge_ci(&gh_repo, &merge_sha, &excluded_workflows),
        ci_config,
        &mut sleep_fn,
    ) {
        Ok(CiPollOutcome::Success { .. }) => None,
        Ok(CiPollOutcome::Failed { failed_checks }) => Some(format!(
            "post-merge CI failed for PR #{} ({merge_sha}): {}",
            entry.pr_number,
            failed_checks.join(", ")
        )),
        Ok(CiPollOutcome::TimedOut { pending_checks }) => Some(format!(
            "post-merge CI timed out for PR #{} ({merge_sha}): {}",
            entry.pr_number,
            if pending_checks.is_empty() {
                "no check-runs reported".to_owned()
            } else {
                pending_checks.join(", ")
            }
        )),
        Err(err) => Some(format!(
            "post-merge CI check failed for PR #{} ({merge_sha}): {err}",
            entry.pr_number
        )),
    };

    if let Some(reason) = post_merge_failure {
        let options = vec![
            "Revert merge commit".to_owned(),
            "Fix forward".to_owned(),
            "Ignore failure and unblock".to_owned(),
        ];
        let question = format!(
            "Post-merge CI failed on default branch after merging PR #{} (merge_sha={merge_sha}). Immediate intervention required to unblock repository '{repo}'",
            entry.pr_number
        );
        return block_repo_with_decision(
            store,
            repo,
            &mut task,
            entry.pr_number,
            &options,
            DecisionSpec {
                kind: "post_merge_ci_failed",
                question: &question,
                context: &reason,
                strip_stages: false,
                sha: Some(&merge_sha),
            },
        );
    }

    // 8. Persist the delivery handoff BEFORE releasing the merge lane/locks.
    let deliveries = match contract {
        ContractLookup::ContractNotFound => Vec::new(),
        ContractLookup::Found(contract) => {
            let needs_paths = contract
                .post_merge_workflows
                .iter()
                .any(|r| !r.when_paths.is_empty())
                || contract.promotions.iter().any(|r| !r.when_paths.is_empty());
            let changed = if needs_paths {
                driver.delivery_changed_paths(&gh_repo, &merge_sha)
            } else {
                Ok(Vec::new())
            };
            match changed {
                Ok(paths) => delivery::seed_deliveries(&task, &merge_sha, &contract, &paths),
                Err(error) => vec![delivery::contract_error_row(&task, &merge_sha, &error)],
            }
        }
        ContractLookup::FetchError(error) | ContractLookup::ParseError(error) => {
            vec![delivery::contract_error_row(&task, &merge_sha, &error)]
        }
    };
    let pending_delivery = !deliveries.is_empty();
    task.status = if pending_delivery {
        "Delivery Pending"
    } else {
        "Done"
    }
    .to_owned();
    task.current_stage = None;
    task.active_attempt_id = None;
    store
        .save_deliveries_and_task(&task, &deliveries)
        .map_err(|e| e.to_string())?;
    store
        .release_path_locks(&entry.task_id)
        .map_err(|e| e.to_string())?;
    store
        .remove_merge_queue_entry(repo, &entry.task_id)
        .map_err(|e| e.to_string())?;

    let _ = store.append_event(
        &entry.task_id,
        &task.task_group,
        "MERGE_COMPLETED",
        &serde_json::json!({
            "repo": repo,
            "pr_number": entry.pr_number,
            "merge_sha": merge_sha,
        }),
    );

    if pending_delivery {
        Ok(MergeQueueOutcome::MergedPendingDelivery {
            task_id: entry.task_id,
            pr_number: entry.pr_number,
            merge_sha,
        })
    } else {
        Ok(MergeQueueOutcome::Merged {
            task_id: entry.task_id,
            pr_number: entry.pr_number,
            merge_sha,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::v2::store::{ContextPackSpec, TargetFileSpec, TaskMemory, TaskRecord};
    use std::collections::VecDeque;

    #[derive(Default)]
    pub struct MockMergeDriver {
        pub default_branch: Option<String>,
        pub default_branch_error: Option<String>,
        pub merged_against: Option<String>,
        pub origin_default_sha: Option<String>,
        pub merge_origin_outcome: Option<MergeOriginOutcome>,
        pub merge_origin_error: Option<String>,
        pub gate_checks_error: Option<String>,
        pub diff_outcome: Option<ReviewedDiffOutcome>,
        pub diff_error: Option<String>,
        pub push_outcome: Option<PushOutcome>,
        pub push_error: Option<String>,
        pub exact_sha_ci_states: VecDeque<Result<CiCheckState, String>>,
        pub post_merge_ci_states: VecDeque<Result<CiCheckState, String>>,
        pub merge_pr_result: Option<String>,
        pub merge_pr_error: Option<MergePrError>,
        pub steps: Vec<String>,
        pub ci_queries: Vec<(String, String)>,
        pub pushed_branches: Vec<String>,
        pub merged_pr_repos: Vec<String>,
        pub contract_lookup: Option<ContractLookup>,
        pub delivery_changed_paths_result: Option<Result<Vec<String>, String>>,
        pub contract_queries: Vec<(String, String)>,
        pub delivery_path_queries: Vec<(String, String)>,
        pub excluded_workflow_queries: Vec<Vec<String>>,
    }

    impl MergeDriver for MockMergeDriver {
        fn delivery_contract(&mut self, gh_repo: &str, sha: &str) -> ContractLookup {
            self.contract_queries
                .push((gh_repo.to_owned(), sha.to_owned()));
            self.contract_lookup
                .clone()
                .unwrap_or(ContractLookup::ContractNotFound)
        }

        fn delivery_changed_paths(
            &mut self,
            gh_repo: &str,
            sha: &str,
        ) -> Result<Vec<String>, String> {
            self.delivery_path_queries
                .push((gh_repo.to_owned(), sha.to_owned()));
            self.delivery_changed_paths_result
                .clone()
                .unwrap_or_else(|| Ok(Vec::new()))
        }

        fn query_delivery_aware_post_merge_ci(
            &mut self,
            gh_repo: &str,
            sha: &str,
            excluded_workflows: &[String],
        ) -> Result<CiCheckState, String> {
            self.excluded_workflow_queries
                .push(excluded_workflows.to_vec());
            self.query_post_merge_ci(gh_repo, sha)
        }

        fn default_branch(&mut self, _repo: &str, _worktree_path: &str) -> Result<String, String> {
            if let Some(ref err) = self.default_branch_error {
                return Err(err.clone());
            }
            Ok(self
                .default_branch
                .clone()
                .unwrap_or_else(|| "main".to_owned()))
        }

        fn merge_origin_default(
            &mut self,
            _repo: &str,
            _worktree_path: &str,
            default_branch: &str,
        ) -> Result<MergeOriginOutcome, String> {
            self.merged_against = Some(default_branch.to_owned());
            self.steps.push("merge_origin_default".to_owned());
            if let Some(ref err) = self.merge_origin_error {
                return Err(err.clone());
            }
            if let Some(ref outcome) = self.merge_origin_outcome {
                return Ok(outcome.clone());
            }
            Ok(MergeOriginOutcome::Merged(
                self.origin_default_sha
                    .clone()
                    .unwrap_or_else(|| "mock-merge-head-sha".to_owned()),
            ))
        }

        fn run_gate_checks(
            &mut self,
            _repo: &str,
            _worktree_path: &str,
            _checks: &[String],
            _semaphore: &HeavyCheckSemaphore,
        ) -> Result<(), String> {
            self.steps.push("run_gate_checks".to_owned());
            if let Some(ref err) = self.gate_checks_error {
                return Err(err.clone());
            }
            Ok(())
        }

        fn diff_touched_task_files(
            &mut self,
            _worktree_path: &str,
            _reviewed_sha: &str,
            _head_sha: &str,
            _target_files: &[TargetFileSpec],
        ) -> Result<ReviewedDiffOutcome, String> {
            self.steps.push("diff_touched_task_files".to_owned());
            if let Some(ref err) = self.diff_error {
                return Err(err.clone());
            }
            Ok(self
                .diff_outcome
                .clone()
                .unwrap_or(ReviewedDiffOutcome::Clean))
        }

        fn push_head(
            &mut self,
            _repo: &str,
            _worktree_path: &str,
            branch: &str,
        ) -> Result<PushOutcome, String> {
            self.steps.push("push_head".to_owned());
            self.pushed_branches.push(branch.to_owned());
            if let Some(ref err) = self.push_error {
                return Err(err.clone());
            }
            Ok(self.push_outcome.clone().unwrap_or(PushOutcome::Pushed))
        }

        fn query_exact_sha_ci(&mut self, gh_repo: &str, sha: &str) -> Result<CiCheckState, String> {
            self.steps.push("query_exact_sha_ci".to_owned());
            self.ci_queries.push((gh_repo.to_owned(), sha.to_owned()));
            self.exact_sha_ci_states.pop_front().unwrap_or_else(|| {
                Ok(CiCheckState::Success {
                    passed_checks: vec!["ci".to_owned()],
                })
            })
        }

        fn merge_pr_match_head(
            &mut self,
            gh_repo: &str,
            _pr_number: i64,
            _head_sha: &str,
        ) -> Result<String, MergePrError> {
            self.steps.push("merge_pr_match_head".to_owned());
            self.merged_pr_repos.push(gh_repo.to_owned());
            if let Some(ref err) = self.merge_pr_error {
                return Err(err.clone());
            }
            Ok(self
                .merge_pr_result
                .clone()
                .unwrap_or_else(|| "mock-final-merge-sha".to_owned()))
        }

        fn query_post_merge_ci(
            &mut self,
            gh_repo: &str,
            merge_sha: &str,
        ) -> Result<CiCheckState, String> {
            self.steps.push("query_post_merge_ci".to_owned());
            self.ci_queries
                .push((gh_repo.to_owned(), merge_sha.to_owned()));
            self.post_merge_ci_states.pop_front().unwrap_or_else(|| {
                Ok(CiCheckState::Success {
                    passed_checks: vec!["ci".to_owned()],
                })
            })
        }
    }

    fn test_ci_config() -> CiPollConfig {
        CiPollConfig {
            timeout: Duration::from_secs(30),
            poll_interval: Duration::from_secs(10),
        }
    }

    fn sample_task(id: &str, repo: &str, targets: Vec<&str>) -> TaskRecord {
        TaskRecord {
            task_id: id.to_owned(),
            task_group: "test".to_owned(),
            title: format!("Task {id}"),
            repository: repo.to_owned(),
            github_repo: Some(format!("shockerqt/{repo}")),
            issue_number: Some(1),
            weight: "M".to_owned(),
            status: "Ready".to_owned(),
            worktree_path: Some(format!("/home/ubuntu/workspace/{repo}--{id}")),
            branch: Some(format!("task/{id}")),
            context_pack: ContextPackSpec {
                weight: "M".to_owned(),
                target_files: targets
                    .into_iter()
                    .map(|p| TargetFileSpec {
                        path: p.to_owned(),
                        action: "modify".to_owned(),
                        summary: String::new(),
                    })
                    .collect(),
                gate_checks: vec!["cargo test".to_owned()],
                ..ContextPackSpec::default()
            },
            depends_on: Vec::new(),
            required_stages: vec!["impl".to_owned(), "pr-review".to_owned()],
            stages_completed: vec!["impl".to_owned(), "pr-review".to_owned()],
            current_stage: None,
            active_attempt_id: None,
            plan_base_sha: None,
            reviewed_sha: Some("reviewed-sha-123".to_owned()),
            pr_number: Some(42),
            executor: None,
            autonomous_consent: true,
            retry_count: 0,
            memory: TaskMemory::default(),
            version: 1,
            updated_epoch: 1000,
        }
    }

    #[test]
    fn evaluate_check_runs_json_scenarios() {
        // Empty check_runs -> Pending
        let empty = r#"{"total_count":0,"check_runs":[]}"#;
        assert_eq!(
            evaluate_check_runs_json(empty).unwrap(),
            CiCheckState::Pending {
                pending_checks: Vec::new()
            }
        );

        // Multi-page --paginate output, all completed + success -> Success
        let paginated_ok = r#"
            {"total_count":2,"check_runs":[{"name":"lint","status":"completed","conclusion":"success"}]}
            {"total_count":2,"check_runs":[{"name":"test","status":"completed","conclusion":"success"}]}
        "#;
        assert_eq!(
            evaluate_check_runs_json(paginated_ok).unwrap(),
            CiCheckState::Success {
                passed_checks: vec!["lint".to_owned(), "test".to_owned()],
            }
        );

        // One in_progress + one failure -> Pending (pending never misreported as failed)
        let pending_and_fail = r#"{"total_count":2,"check_runs":[
            {"name":"build","status":"completed","conclusion":"failure"},
            {"name":"e2e","status":"in_progress","conclusion":null}
        ]}"#;
        assert_eq!(
            evaluate_check_runs_json(pending_and_fail).unwrap(),
            CiCheckState::Pending {
                pending_checks: vec!["e2e".to_owned()],
            }
        );

        // All completed, one failed among several -> Failed
        let one_failed = r#"{"total_count":3,"check_runs":[
            {"name":"fmt","status":"completed","conclusion":"success"},
            {"name":"clippy","status":"completed","conclusion":"failure"},
            {"name":"test","status":"completed","conclusion":"success"}
        ]}"#;
        assert_eq!(
            evaluate_check_runs_json(one_failed).unwrap(),
            CiCheckState::Failed {
                failed_checks: vec!["clippy (failure)".to_owned()],
            }
        );

        // Literal AC-2: neutral / skipped conclusions fail the gate once all complete
        let skipped = r#"{"total_count":2,"check_runs":[
            {"name":"test","status":"completed","conclusion":"success"},
            {"name":"cond","status":"completed","conclusion":"skipped"}
        ]}"#;
        assert_eq!(
            evaluate_check_runs_json(skipped).unwrap(),
            CiCheckState::Failed {
                failed_checks: vec!["cond (skipped)".to_owned()],
            }
        );

        let neutral = r#"{"total_count":1,"check_runs":[
            {"name":"advisory","status":"completed","conclusion":"neutral"}
        ]}"#;
        assert_eq!(
            evaluate_check_runs_json(neutral).unwrap(),
            CiCheckState::Failed {
                failed_checks: vec!["advisory (neutral)".to_owned()],
            }
        );
    }

    #[test]
    fn parse_pr_merge_commit_oid_scenarios() {
        let merged = r#"{"state":"MERGED","mergeCommit":{"oid":"abc123def"}}"#;
        assert_eq!(
            parse_pr_merge_commit_oid(merged).unwrap(),
            Some("abc123def".to_owned())
        );

        let open = r#"{"state":"OPEN","mergeCommit":null}"#;
        assert_eq!(parse_pr_merge_commit_oid(open).unwrap(), None);

        let null_oid = r#"{"state":"MERGED","mergeCommit":{"oid":null}}"#;
        assert_eq!(parse_pr_merge_commit_oid(null_oid).unwrap(), None);

        assert!(parse_pr_merge_commit_oid("not-json").is_err());
    }

    #[test]
    fn fetch_merged_pr_commit_oid_retries_then_succeeds_or_exhausts() {
        let mut responses = VecDeque::from([
            Ok(r#"{"state":"OPEN","mergeCommit":null}"#.to_owned()),
            Ok(r#"{"state":"MERGED","mergeCommit":{"oid":"real-merge-oid"}}"#.to_owned()),
        ]);
        let mut sleeps = 0usize;
        let oid = fetch_merged_pr_commit_oid_with_sleep(
            || responses.pop_front().unwrap(),
            |_| {
                sleeps += 1;
            },
        )
        .unwrap();
        assert_eq!(oid, "real-merge-oid");
        assert_eq!(sleeps, 1);

        let mut always_null = VecDeque::from([
            Ok(r#"{"state":"MERGED","mergeCommit":null}"#.to_owned()),
            Ok(r#"{"state":"MERGED","mergeCommit":null}"#.to_owned()),
            Ok(r#"{"state":"MERGED","mergeCommit":null}"#.to_owned()),
        ]);
        let mut exhaust_sleeps = 0usize;
        assert!(
            fetch_merged_pr_commit_oid_with_sleep(
                || always_null.pop_front().unwrap(),
                |_| {
                    exhaust_sleeps += 1;
                }
            )
            .is_err()
        );
        assert_eq!(exhaust_sleeps, 2);
    }

    #[test]
    fn filter_touched_task_files_scenarios() {
        let targets = vec![
            TargetFileSpec {
                path: "src/v2/merge_queue.rs".to_owned(),
                action: "modify".to_owned(),
                summary: String::new(),
            },
            TargetFileSpec {
                path: "src/api/**".to_owned(),
                action: "modify".to_owned(),
                summary: String::new(),
            },
        ];
        let changed = vec![
            "README.md".to_owned(),
            "src/api/routes.rs".to_owned(),
            "src/v2/merge_queue.rs".to_owned(),
        ];
        assert_eq!(
            filter_touched_task_files(&changed, &targets),
            vec![
                "src/api/routes.rs".to_owned(),
                "src/v2/merge_queue.rs".to_owned()
            ]
        );

        assert_eq!(
            filter_touched_task_files(&["README.md".to_owned()], &targets),
            Vec::<String>::new()
        );

        // Empty target_files treats any changed file as touched
        assert_eq!(
            filter_touched_task_files(&["README.md".to_owned()], &[]),
            vec!["README.md".to_owned()]
        );
    }

    #[test]
    fn poll_exact_sha_ci_pending_then_success_and_timeout() {
        let mut states = VecDeque::from([
            Ok(CiCheckState::Pending {
                pending_checks: vec!["ci".to_owned()],
            }),
            Ok(CiCheckState::Pending {
                pending_checks: vec!["ci".to_owned()],
            }),
            Ok(CiCheckState::Success {
                passed_checks: vec!["ci".to_owned()],
            }),
        ]);
        let mut sleeps = Vec::new();
        let out = poll_exact_sha_ci_with_sleep(
            || states.pop_front().unwrap(),
            test_ci_config(),
            |d| sleeps.push(d),
        )
        .unwrap();
        assert_eq!(
            out,
            CiPollOutcome::Success {
                passed_checks: vec!["ci".to_owned()]
            }
        );
        assert_eq!(sleeps.len(), 2);

        let timed_out = poll_exact_sha_ci_with_sleep(
            || {
                Ok(CiCheckState::Pending {
                    pending_checks: vec!["slow-job".to_owned()],
                })
            },
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert_eq!(
            timed_out,
            CiPollOutcome::TimedOut {
                pending_checks: vec!["slow-job".to_owned()]
            }
        );
    }

    #[test]
    fn merge_queue_enforces_per_repo_fifo_ordering() {
        let mut store = V2Store::open_in_memory().expect("open store");

        enqueue_for_merge(&mut store, "zach", "TASK-1", 101, "sha-1").unwrap();
        enqueue_for_merge(&mut store, "zach", "TASK-2", 102, "sha-2").unwrap();
        enqueue_for_merge(&mut store, "governance", "GOV-1", 201, "gov-sha-1").unwrap();

        let next_zach = dequeue_next(&store, "zach").unwrap().unwrap();
        assert_eq!(next_zach.task_id, "TASK-1");

        let next_gov = dequeue_next(&store, "governance").unwrap().unwrap();
        assert_eq!(next_gov.task_id, "GOV-1");
    }

    #[test]
    fn process_repo_merge_queue_success_pushes_before_ci_and_releases_locks() {
        let mut store = V2Store::open_in_memory().expect("open store");
        let task = sample_task("TASK-1", "zach", vec!["src/v2/merge_queue.rs"]);
        store.upsert_task(&task).unwrap();

        assert!(
            store
                .acquire_path_locks("zach", &[String::from("src/v2/merge_queue.rs")], "TASK-1")
                .unwrap()
        );
        assert_eq!(store.list_path_locks(Some("zach")).unwrap().len(), 1);

        enqueue_for_merge(&mut store, "zach", "TASK-1", 42, "reviewed-sha-123").unwrap();

        let semaphore = HeavyCheckSemaphore::new();
        let mut driver = MockMergeDriver {
            origin_default_sha: Some("sha-merge-head".to_owned()),
            merge_pr_result: Some("final-commit-sha".to_owned()),
            ..Default::default()
        };

        let outcome = process_repo_merge_queue_with_config(
            &mut store,
            "zach",
            &mut driver,
            &semaphore,
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert_eq!(
            outcome,
            MergeQueueOutcome::Merged {
                task_id: "TASK-1".to_owned(),
                pr_number: 42,
                merge_sha: "final-commit-sha".to_owned(),
            }
        );

        let updated_task = store.get_task("TASK-1").unwrap().unwrap();
        assert_eq!(updated_task.status, "Done");
        assert!(store.list_merge_queue(Some("zach")).unwrap().is_empty());
        assert!(store.list_path_locks(Some("zach")).unwrap().is_empty());

        // AC-1 & AC-4 ordering: diff check before push, push strictly after merge and before CI
        assert_eq!(
            driver.steps,
            vec![
                "merge_origin_default",
                "run_gate_checks",
                "diff_touched_task_files",
                "push_head",
                "query_exact_sha_ci",
                "merge_pr_match_head",
                "query_post_merge_ci",
            ]
        );
        assert_eq!(driver.pushed_branches, vec!["task/TASK-1"]);
        assert_eq!(
            driver.ci_queries,
            vec![
                ("shockerqt/zach".to_owned(), "sha-merge-head".to_owned()),
                ("shockerqt/zach".to_owned(), "final-commit-sha".to_owned()),
            ]
        );
        assert_eq!(driver.merged_pr_repos, vec!["shockerqt/zach"]);
    }

    #[test]
    fn process_repo_merge_queue_pending_then_success_completes_merge() {
        let mut store = V2Store::open_in_memory().expect("open store");
        let task = sample_task("TASK-1", "zach", vec!["src/v2/merge_queue.rs"]);
        store.upsert_task(&task).unwrap();
        enqueue_for_merge(&mut store, "zach", "TASK-1", 42, "reviewed-sha-123").unwrap();

        let semaphore = HeavyCheckSemaphore::new();
        let mut driver = MockMergeDriver {
            origin_default_sha: Some("sha-merge-head".to_owned()),
            exact_sha_ci_states: VecDeque::from([
                Ok(CiCheckState::Pending {
                    pending_checks: vec!["cargo-test".to_owned()],
                }),
                Ok(CiCheckState::Pending {
                    pending_checks: vec!["cargo-test".to_owned()],
                }),
                Ok(CiCheckState::Success {
                    passed_checks: vec!["cargo-test".to_owned()],
                }),
            ]),
            merge_pr_result: Some("final-commit-sha".to_owned()),
            ..Default::default()
        };

        let mut sleeps = 0usize;
        let outcome = process_repo_merge_queue_with_config(
            &mut store,
            "zach",
            &mut driver,
            &semaphore,
            test_ci_config(),
            |_| {
                sleeps += 1;
            },
        )
        .unwrap();
        assert!(matches!(outcome, MergeQueueOutcome::Merged { .. }));
        assert_eq!(sleeps, 2);
        assert_eq!(
            driver
                .steps
                .iter()
                .filter(|s| s.as_str() == "query_exact_sha_ci")
                .count(),
            3
        );
    }

    #[test]
    fn process_repo_merge_queue_one_failed_check_returns_to_impl() {
        let mut store = V2Store::open_in_memory().expect("open store");
        let task = sample_task("TASK-1", "zach", vec!["src/v2/merge_queue.rs"]);
        store.upsert_task(&task).unwrap();
        assert!(
            store
                .acquire_path_locks("zach", &[String::from("src/v2/merge_queue.rs")], "TASK-1")
                .unwrap()
        );
        enqueue_for_merge(&mut store, "zach", "TASK-1", 42, "reviewed-sha-123").unwrap();

        let semaphore = HeavyCheckSemaphore::new();
        let mut driver = MockMergeDriver {
            origin_default_sha: Some("sha-merge-head".to_owned()),
            exact_sha_ci_states: VecDeque::from([Ok(CiCheckState::Failed {
                failed_checks: vec!["clippy (failure)".to_owned()],
            })]),
            ..Default::default()
        };

        let outcome = process_repo_merge_queue_with_config(
            &mut store,
            "zach",
            &mut driver,
            &semaphore,
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert!(matches!(outcome, MergeQueueOutcome::Failed { .. }));

        let updated = store.get_task("TASK-1").unwrap().unwrap();
        assert_eq!(updated.status, "Ready");
        assert_eq!(updated.current_stage.as_deref(), Some("impl"));
        assert_eq!(updated.retry_count, 1);
        assert!(
            !updated
                .stages_completed
                .iter()
                .any(|s| s == "impl" || s == "pr-review"),
            "impl and pr-review must be stripped on return to impl"
        );
        assert!(
            updated
                .memory
                .last_check_failure
                .as_deref()
                .unwrap_or("")
                .contains("clippy (failure)")
        );
        assert!(store.list_merge_queue(Some("zach")).unwrap().is_empty());
        assert_eq!(store.list_path_locks(Some("zach")).unwrap().len(), 1);
    }

    #[test]
    fn process_repo_merge_queue_ci_timeout_opens_decision_without_stripping_stages() {
        let mut store = V2Store::open_in_memory().expect("open store");
        let task = sample_task("TASK-1", "zach", vec!["src/v2/merge_queue.rs"]);
        store.upsert_task(&task).unwrap();
        enqueue_for_merge(&mut store, "zach", "TASK-1", 42, "reviewed-sha-123").unwrap();

        let semaphore = HeavyCheckSemaphore::new();
        let mut driver = MockMergeDriver {
            origin_default_sha: Some("sha-merge-head".to_owned()),
            exact_sha_ci_states: VecDeque::from([
                Ok(CiCheckState::Pending {
                    pending_checks: vec!["slow-ci".to_owned()],
                }),
                Ok(CiCheckState::Pending {
                    pending_checks: vec!["slow-ci".to_owned()],
                }),
                Ok(CiCheckState::Pending {
                    pending_checks: vec!["slow-ci".to_owned()],
                }),
                Ok(CiCheckState::Pending {
                    pending_checks: vec!["slow-ci".to_owned()],
                }),
            ]),
            ..Default::default()
        };

        let outcome = process_repo_merge_queue_with_config(
            &mut store,
            "zach",
            &mut driver,
            &semaphore,
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert!(matches!(outcome, MergeQueueOutcome::Blocked { .. }));

        let updated = store.get_task("TASK-1").unwrap().unwrap();
        assert_eq!(updated.status, "Blocked");
        assert_eq!(updated.retry_count, 0);
        assert_eq!(
            updated.stages_completed,
            vec!["impl".to_owned(), "pr-review".to_owned()]
        );
        assert!(store.list_merge_queue(Some("zach")).unwrap().is_empty());

        let decs = store.list_decisions(true, None).unwrap();
        assert_eq!(decs.len(), 1);
        assert_eq!(decs[0].task_id, "TASK-1");
        assert_eq!(decs[0].kind, "merge_ci_timeout");
        assert_eq!(decs[0].options, vec!["Retry merge", "Abandon"]);
    }

    #[test]
    fn process_repo_merge_queue_merge_conflict_returns_to_impl_and_exhausts_to_decision() {
        let mut store = V2Store::open_in_memory().expect("open store");
        let task = sample_task("TASK-1", "zach", vec!["src/v2/merge_queue.rs"]);
        store.upsert_task(&task).unwrap();
        enqueue_for_merge(&mut store, "zach", "TASK-1", 42, "reviewed-sha-123").unwrap();

        let semaphore = HeavyCheckSemaphore::new();
        let mut driver = MockMergeDriver {
            merge_origin_outcome: Some(MergeOriginOutcome::Conflict {
                conflicted_files: vec!["src/v2/merge_queue.rs".to_owned()],
            }),
            ..Default::default()
        };

        // First conflict -> returned to impl with stripped stages
        let first = process_repo_merge_queue_with_config(
            &mut store,
            "zach",
            &mut driver,
            &semaphore,
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert!(matches!(first, MergeQueueOutcome::Failed { .. }));
        let t1 = store.get_task("TASK-1").unwrap().unwrap();
        assert_eq!(t1.status, "Ready");
        assert_eq!(t1.current_stage.as_deref(), Some("impl"));
        assert_eq!(t1.retry_count, 1);
        assert!(t1.stages_completed.is_empty());
        assert!(store.list_merge_queue(Some("zach")).unwrap().is_empty());

        // Exhausted retries -> opens decision
        let mut t2 = t1;
        t2.retry_count = MAX_MERGE_RETRIES;
        t2.stages_completed = vec!["impl".to_owned(), "pr-review".to_owned()];
        store.upsert_task(&t2).unwrap();
        enqueue_for_merge(&mut store, "zach", "TASK-1", 42, "reviewed-sha-123").unwrap();

        let second = process_repo_merge_queue_with_config(
            &mut store,
            "zach",
            &mut driver,
            &semaphore,
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert!(matches!(second, MergeQueueOutcome::Blocked { .. }));
        let decs = store.list_decisions(true, None).unwrap();
        assert_eq!(decs.len(), 1);
        assert_eq!(decs[0].task_id, "TASK-1");
        assert_eq!(decs[0].kind, "merge_conflict");
    }

    #[test]
    fn process_repo_merge_queue_non_ff_push_opens_decision_without_stripping_stages() {
        let mut store = V2Store::open_in_memory().expect("open store");
        let task = sample_task("TASK-1", "zach", vec!["src/v2/merge_queue.rs"]);
        store.upsert_task(&task).unwrap();
        enqueue_for_merge(&mut store, "zach", "TASK-1", 42, "reviewed-sha-123").unwrap();

        let semaphore = HeavyCheckSemaphore::new();
        let mut driver = MockMergeDriver {
            push_outcome: Some(PushOutcome::NonFastForward(
                "! [rejected] HEAD -> task/TASK-1 (non-fast-forward)".to_owned(),
            )),
            ..Default::default()
        };

        let outcome = process_repo_merge_queue_with_config(
            &mut store,
            "zach",
            &mut driver,
            &semaphore,
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert!(matches!(outcome, MergeQueueOutcome::Blocked { .. }));

        let updated = store.get_task("TASK-1").unwrap().unwrap();
        assert_eq!(updated.status, "Blocked");
        assert_eq!(
            updated.stages_completed,
            vec!["impl".to_owned(), "pr-review".to_owned()]
        );
        let decs = store.list_decisions(true, None).unwrap();
        assert_eq!(decs.len(), 1);
        assert_eq!(decs[0].task_id, "TASK-1");
        assert_eq!(decs[0].kind, "merge_push_non_ff");
    }

    #[test]
    fn process_repo_merge_queue_rereview_runs_before_push_and_caps_cycles() {
        let mut store = V2Store::open_in_memory().expect("open store");
        let task = sample_task("TASK-1", "zach", vec!["src/v2/merge_queue.rs"]);
        store.upsert_task(&task).unwrap();
        enqueue_for_merge(&mut store, "zach", "TASK-1", 42, "reviewed-sha-123").unwrap();

        let semaphore = HeavyCheckSemaphore::new();
        let mut driver = MockMergeDriver {
            diff_outcome: Some(ReviewedDiffOutcome::Touched(vec![
                "src/v2/merge_queue.rs".to_owned(),
            ])),
            ..Default::default()
        };

        // Cycle 1: triggers ReReviewRequired before push_head / CI
        let outcome = process_repo_merge_queue_with_config(
            &mut store,
            "zach",
            &mut driver,
            &semaphore,
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert_eq!(
            outcome,
            MergeQueueOutcome::ReReviewRequired {
                task_id: "TASK-1".to_owned(),
                touched_files: vec!["src/v2/merge_queue.rs".to_owned()],
            }
        );
        assert!(!driver.steps.iter().any(|s| s == "push_head"));
        assert!(!driver.steps.iter().any(|s| s == "query_exact_sha_ci"));

        let t1 = store.get_task("TASK-1").unwrap().unwrap();
        assert_eq!(t1.status, "Ready");
        assert_eq!(t1.current_stage.as_deref(), Some("pr-review"));
        assert_eq!(t1.retry_count, 0);
        assert_eq!(t1.stages_completed, vec!["impl".to_owned()]);
        assert!(store.list_merge_queue(Some("zach")).unwrap().is_empty());

        // Cycle 2
        enqueue_for_merge(&mut store, "zach", "TASK-1", 42, "reviewed-sha-123").unwrap();
        let second = process_repo_merge_queue_with_config(
            &mut store,
            "zach",
            &mut driver,
            &semaphore,
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert!(matches!(second, MergeQueueOutcome::ReReviewRequired { .. }));

        // Cycle 3 -> exceeds MAX_REREVIEW_CYCLES -> opens decision
        enqueue_for_merge(&mut store, "zach", "TASK-1", 42, "reviewed-sha-123").unwrap();
        let third = process_repo_merge_queue_with_config(
            &mut store,
            "zach",
            &mut driver,
            &semaphore,
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert!(matches!(third, MergeQueueOutcome::Blocked { .. }));
        let decs = store.list_decisions(true, None).unwrap();
        assert_eq!(decs.len(), 1);
        assert_eq!(decs[0].task_id, "TASK-1");
        assert_eq!(decs[0].kind, "merge_rereview_limit");
    }

    #[test]
    fn process_repo_merge_queue_post_merge_sha_unavailable_blocks_lane_with_manual_options() {
        let mut store = V2Store::open_in_memory().expect("open store");
        let task = sample_task("TASK-1", "zach", vec!["src/v2/merge_queue.rs"]);
        store.upsert_task(&task).unwrap();
        enqueue_for_merge(&mut store, "zach", "TASK-1", 42, "reviewed-sha-123").unwrap();

        let semaphore = HeavyCheckSemaphore::new();
        let mut driver = MockMergeDriver {
            merge_pr_error: Some(MergePrError::PostMergeShaUnavailable(
                "mergeCommit.oid stayed null".to_owned(),
            )),
            ..Default::default()
        };

        let outcome = process_repo_merge_queue_with_config(
            &mut store,
            "zach",
            &mut driver,
            &semaphore,
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert!(matches!(outcome, MergeQueueOutcome::Blocked { .. }));

        let entry = store
            .get_merge_queue_entry("zach", "TASK-1")
            .unwrap()
            .unwrap();
        assert_eq!(entry.state, "MERGE_QUEUE_BLOCKED");

        let updated = store.get_task("TASK-1").unwrap().unwrap();
        assert_eq!(updated.status, "Blocked");
        assert_eq!(updated.retry_count, 0);
        assert_eq!(
            updated.stages_completed,
            vec!["impl".to_owned(), "pr-review".to_owned()]
        );

        let decs = store.list_decisions(true, None).unwrap();
        assert_eq!(decs.len(), 1);
        assert_eq!(decs[0].task_id, "TASK-1");
        assert_eq!(decs[0].kind, "post_merge_sha_unavailable");
        assert_eq!(
            decs[0].options,
            vec!["Record merge SHA manually", "Unblock lane"]
        );
        assert!(dequeue_next(&store, "zach").unwrap().is_none());
    }

    #[test]
    fn process_repo_merge_queue_blocks_repo_lane_and_opens_decision_on_post_merge_ci_failure() {
        let mut store = V2Store::open_in_memory().expect("open store");
        let task1 = sample_task("TASK-1", "zach", vec!["src/v2/a.rs"]);
        let task2 = sample_task("TASK-2", "zach", vec!["src/v2/b.rs"]);
        store.upsert_task(&task1).unwrap();
        store.upsert_task(&task2).unwrap();

        enqueue_for_merge(&mut store, "zach", "TASK-1", 42, "sha-1").unwrap();
        enqueue_for_merge(&mut store, "zach", "TASK-2", 43, "sha-2").unwrap();

        let semaphore = HeavyCheckSemaphore::new();
        let mut driver = MockMergeDriver {
            origin_default_sha: Some("head-1".to_owned()),
            merge_pr_result: Some("merge-commit-1".to_owned()),
            post_merge_ci_states: VecDeque::from([Ok(CiCheckState::Failed {
                failed_checks: vec!["post-merge-ci (failure)".to_owned()],
            })]),
            ..Default::default()
        };

        let outcome = process_repo_merge_queue_with_config(
            &mut store,
            "zach",
            &mut driver,
            &semaphore,
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert!(matches!(outcome, MergeQueueOutcome::Blocked { .. }));

        let entry = store
            .get_merge_queue_entry("zach", "TASK-1")
            .unwrap()
            .unwrap();
        assert_eq!(entry.state, "MERGE_QUEUE_BLOCKED");

        let decs = store.list_decisions(true, None).unwrap();
        assert_eq!(decs.len(), 1);
        assert_eq!(decs[0].kind, "post_merge_ci_failed");
        assert_eq!(decs[0].task_id, "TASK-1");

        assert!(dequeue_next(&store, "zach").unwrap().is_none());

        let next_outcome = process_repo_merge_queue_with_config(
            &mut store,
            "zach",
            &mut driver,
            &semaphore,
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert!(matches!(next_outcome, MergeQueueOutcome::Blocked { .. }));
    }

    #[test]
    fn parse_default_branch_scenarios() {
        assert_eq!(
            parse_default_branch("origin/master\n", ""),
            Some("master".to_owned())
        );
        assert_eq!(
            parse_default_branch("", "ref: refs/heads/master\tHEAD\nabc123\tHEAD\n"),
            Some("master".to_owned())
        );
        assert_eq!(parse_default_branch("", ""), None);
    }

    #[test]
    fn process_repo_merge_queue_uses_resolved_default_branch() {
        let mut store = V2Store::open_in_memory().expect("open store");
        let task = sample_task("GOV-1", "governance", vec!["README.md"]);
        store.upsert_task(&task).unwrap();

        enqueue_for_merge(&mut store, "governance", "GOV-1", 10, "rev-sha").unwrap();

        let semaphore = HeavyCheckSemaphore::new();
        let mut driver = MockMergeDriver {
            default_branch: Some("master".to_owned()),
            origin_default_sha: Some("sha-merge-head".to_owned()),
            merge_pr_result: Some("final-commit-sha".to_owned()),
            ..Default::default()
        };

        let outcome = process_repo_merge_queue_with_config(
            &mut store,
            "governance",
            &mut driver,
            &semaphore,
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert!(matches!(outcome, MergeQueueOutcome::Merged { .. }));
        assert_eq!(driver.merged_against, Some("master".to_owned()));
    }

    #[test]
    fn process_repo_merge_queue_retries_transient_then_opens_decision_when_default_branch_unresolvable()
     {
        let mut store = V2Store::open_in_memory().expect("open store");
        let task = sample_task("TASK-1", "zach", vec!["src/v2/merge_queue.rs"]);
        store.upsert_task(&task).unwrap();

        enqueue_for_merge(&mut store, "zach", "TASK-1", 42, "reviewed-sha-123").unwrap();

        let semaphore = HeavyCheckSemaphore::new();
        let mut driver = MockMergeDriver {
            default_branch_error: Some(
                "could not resolve default branch for repository zach".to_owned(),
            ),
            ..Default::default()
        };

        // First two transient failures reset queue entry back to QUEUED (never FAILED)
        for expected_attempts in 1..=2 {
            let outcome = process_repo_merge_queue_with_config(
                &mut store,
                "zach",
                &mut driver,
                &semaphore,
                test_ci_config(),
                |_| {},
            )
            .unwrap();
            assert_eq!(
                outcome,
                MergeQueueOutcome::Failed {
                    task_id: "TASK-1".to_owned(),
                    reason: "could not resolve default branch for repository zach".to_owned(),
                }
            );
            let entry = store
                .get_merge_queue_entry("zach", "TASK-1")
                .unwrap()
                .unwrap();
            assert_eq!(entry.state, "QUEUED");
            let updated = store.get_task("TASK-1").unwrap().unwrap();
            assert_eq!(updated.retry_count, 0);
            assert_eq!(
                count_attempts_with_prefix(&updated, TRANSIENT_ATTEMPT_PREFIX),
                expected_attempts
            );
        }

        // Third failure exhausts transient retries -> removes entry & opens decision
        let final_outcome = process_repo_merge_queue_with_config(
            &mut store,
            "zach",
            &mut driver,
            &semaphore,
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert!(matches!(final_outcome, MergeQueueOutcome::Blocked { .. }));
        assert!(store.list_merge_queue(Some("zach")).unwrap().is_empty());

        let blocked_task = store.get_task("TASK-1").unwrap().unwrap();
        assert_eq!(blocked_task.status, "Blocked");

        let decs = store.list_decisions(true, None).unwrap();
        assert_eq!(decs.len(), 1);
        assert_eq!(decs[0].task_id, "TASK-1");
        assert_eq!(decs[0].kind, "merge_default_branch_failed");
    }

    fn generic_delivery_contract(pattern: &str) -> delivery::DeliveryContract {
        delivery::parse_contract(&format!(
            "schema_version: 1\npost_merge_workflows:\n  - workflow: sample-client.yml\n    when_paths:\n      - '{pattern}'\n    artifacts: []\n    failure_states: []\n    health_checks: []\npromotions: []\n"
        )).unwrap()
    }

    fn delivery_merge_fixture(contract: ContractLookup) -> (V2Store, TaskRecord, MockMergeDriver) {
        let mut store = V2Store::open_in_memory().unwrap();
        let mut task = sample_task("TASK-DELIVERY", "sample-app", vec!["src/main.rs"]);
        task.github_repo = Some("acme/sample-app".into());
        task.worktree_path = Some("/tmp/sample-app--TASK-DELIVERY".into());
        task.reviewed_sha = Some("d".repeat(40));
        store.upsert_task(&task).unwrap();
        assert!(
            store
                .acquire_path_locks("sample-app", &["src/main.rs".into()], &task.task_id)
                .unwrap()
        );
        enqueue_for_merge(&mut store, "sample-app", &task.task_id, 42, &"d".repeat(40)).unwrap();
        let driver = MockMergeDriver {
            origin_default_sha: Some("b".repeat(40)),
            merge_pr_result: Some("a".repeat(40)),
            contract_lookup: Some(contract),
            delivery_changed_paths_result: Some(Ok(vec!["src/main.rs".into()])),
            ..Default::default()
        };
        (store, task, driver)
    }

    #[test]
    fn delivery_contract_handoff_seeds_pending_work_and_releases_lane_and_locks() {
        let contract = generic_delivery_contract("src/**");
        let (mut store, task, mut driver) = delivery_merge_fixture(ContractLookup::Found(contract));
        let result = process_repo_merge_queue_with_config(
            &mut store,
            "sample-app",
            &mut driver,
            &HeavyCheckSemaphore::new(),
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert_eq!(
            result,
            MergeQueueOutcome::MergedPendingDelivery {
                task_id: task.task_id.clone(),
                pr_number: 42,
                merge_sha: "a".repeat(40),
            }
        );
        let saved = store.get_task(&task.task_id).unwrap().unwrap();
        assert_eq!(saved.status, "Delivery Pending");
        assert_eq!(saved.current_stage, None);
        assert_eq!(saved.active_attempt_id, None);
        assert!(
            store
                .list_merge_queue(Some("sample-app"))
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .list_path_locks(Some("sample-app"))
                .unwrap()
                .is_empty()
        );
        let rows = store.list_deliveries(Some(&task.task_id)).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, "pending");
        assert_eq!(rows[0].kind, "workflow");
        assert_eq!(rows[0].github_repo, "acme/sample-app");
        assert_eq!(rows[0].merge_sha, "a".repeat(40));
        assert_eq!(
            driver.contract_queries,
            vec![("acme/sample-app".into(), "a".repeat(40))]
        );
        assert_eq!(
            driver.delivery_path_queries,
            vec![("acme/sample-app".into(), "a".repeat(40))]
        );
        assert_eq!(
            driver.excluded_workflow_queries,
            vec![vec!["sample-client.yml".to_owned()]]
        );
        assert!(store.list_ready_queue(None).unwrap().is_empty());
    }

    #[test]
    fn delivery_contract_with_no_matching_paths_completes_without_delivery_rows() {
        let (mut store, task, mut driver) =
            delivery_merge_fixture(ContractLookup::Found(generic_delivery_contract("docs/**")));
        let result = process_repo_merge_queue_with_config(
            &mut store,
            "sample-app",
            &mut driver,
            &HeavyCheckSemaphore::new(),
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert!(matches!(result, MergeQueueOutcome::Merged { .. }));
        assert_eq!(
            store.get_task(&task.task_id).unwrap().unwrap().status,
            "Done"
        );
        assert!(
            store
                .list_deliveries(Some(&task.task_id))
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .list_merge_queue(Some("sample-app"))
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .list_path_locks(Some("sample-app"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn delivery_contract_absence_differs_from_fetch_parse_and_changed_paths_errors() {
        let lookups = [
            ContractLookup::ContractNotFound,
            ContractLookup::FetchError("contract unavailable".into()),
            ContractLookup::ParseError("unknown contract field".into()),
            ContractLookup::Found(generic_delivery_contract("src/**")),
        ];
        for lookup in lookups {
            let absent = matches!(lookup, ContractLookup::ContractNotFound);
            let paths_error = matches!(lookup, ContractLookup::Found(_));
            let (mut store, task, mut driver) = delivery_merge_fixture(lookup);
            if paths_error {
                driver.delivery_changed_paths_result = Some(Err("commit files unavailable".into()));
            }
            let result = process_repo_merge_queue_with_config(
                &mut store,
                "sample-app",
                &mut driver,
                &HeavyCheckSemaphore::new(),
                test_ci_config(),
                |_| {},
            )
            .unwrap();
            let rows = store.list_deliveries(Some(&task.task_id)).unwrap();
            if absent {
                assert!(matches!(result, MergeQueueOutcome::Merged { .. }));
                assert_eq!(
                    store.get_task(&task.task_id).unwrap().unwrap().status,
                    "Done"
                );
                assert!(rows.is_empty());
            } else {
                assert!(matches!(
                    result,
                    MergeQueueOutcome::MergedPendingDelivery { .. }
                ));
                assert_eq!(
                    store.get_task(&task.task_id).unwrap().unwrap().status,
                    "Delivery Pending"
                );
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].kind, "contract");
                assert!(
                    rows[0].evidence_json["error"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty())
                );
            }
            assert!(
                store
                    .list_merge_queue(Some("sample-app"))
                    .unwrap()
                    .is_empty()
            );
            assert!(
                store
                    .list_path_locks(Some("sample-app"))
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn delivery_contract_does_not_exempt_regular_failed_merge_ci() {
        let (mut store, task, mut driver) =
            delivery_merge_fixture(ContractLookup::Found(generic_delivery_contract("src/**")));
        driver.post_merge_ci_states = VecDeque::from([Ok(CiCheckState::Failed {
            failed_checks: vec!["sample-lint (failure)".into()],
        })]);
        let result = process_repo_merge_queue_with_config(
            &mut store,
            "sample-app",
            &mut driver,
            &HeavyCheckSemaphore::new(),
            test_ci_config(),
            |_| {},
        )
        .unwrap();
        assert!(matches!(result, MergeQueueOutcome::Blocked { .. }));
        assert_eq!(
            store
                .get_merge_queue_entry("sample-app", &task.task_id)
                .unwrap()
                .unwrap()
                .state,
            "MERGE_QUEUE_BLOCKED"
        );
        assert_eq!(store.list_path_locks(Some("sample-app")).unwrap().len(), 1);
        assert!(
            store
                .list_deliveries(Some(&task.task_id))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store.list_decisions(true, None).unwrap()[0].kind,
            "post_merge_ci_failed"
        );
        assert_eq!(
            driver.excluded_workflow_queries,
            vec![vec!["sample-client.yml".to_owned()]]
        );
    }

    #[test]
    fn delivery_handoff_recovers_a_crash_without_merging_again_or_resetting_waiting_state() {
        for status in ["Delivery Pending", "Waiting New APK", "Done"] {
            let contract = generic_delivery_contract("src/**");
            let (mut store, mut task, mut driver) =
                delivery_merge_fixture(ContractLookup::Found(contract.clone()));
            let mut rows = delivery::seed_deliveries(
                &task,
                &"a".repeat(40),
                &contract,
                &["src/main.rs".into()],
            );
            task.status = status.into();
            rows[0].state = if status == "Done" {
                "verified"
            } else if status == "Waiting New APK" {
                "waiting"
            } else {
                "pending"
            }
            .into();
            store.save_deliveries_and_task(&task, &rows).unwrap();
            store
                .update_merge_queue_state("sample-app", &task.task_id, "MERGING")
                .unwrap();
            let result = process_repo_merge_queue_with_config(
                &mut store,
                "sample-app",
                &mut driver,
                &HeavyCheckSemaphore::new(),
                test_ci_config(),
                |_| {},
            )
            .unwrap();
            assert_eq!(
                store.get_task(&task.task_id).unwrap().unwrap().status,
                status
            );
            if status == "Done" {
                assert!(matches!(result, MergeQueueOutcome::Merged { .. }));
            } else {
                assert!(matches!(
                    result,
                    MergeQueueOutcome::MergedPendingDelivery { .. }
                ));
            }
            assert!(
                store
                    .list_merge_queue(Some("sample-app"))
                    .unwrap()
                    .is_empty()
            );
            assert!(
                store
                    .list_path_locks(Some("sample-app"))
                    .unwrap()
                    .is_empty()
            );
            assert!(
                driver.steps.is_empty(),
                "must not repeat git merge, push, CI, or PR merge"
            );
            assert!(
                driver.contract_queries.is_empty(),
                "the immutable contract is already persisted"
            );
            assert_eq!(store.list_deliveries(Some(&task.task_id)).unwrap(), rows);
        }
    }
}
