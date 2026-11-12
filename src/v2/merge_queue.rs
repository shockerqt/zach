use crate::v2::runner::build_clean_env_from_process;
use crate::v2::scheduler::{HeavyCheckSemaphore, is_heavy_verification_command};
use crate::v2::store::{MergeQueueRecord, V2Store};
use serde::{Deserialize, Serialize};
use std::process::Command;

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
    Failed {
        task_id: String,
        reason: String,
    },
}

pub trait MergeDriver {
    fn default_branch(&mut self, repo: &str, worktree_path: &str) -> Result<String, String>;

    fn merge_origin_default(
        &mut self,
        repo: &str,
        worktree_path: &str,
        default_branch: &str,
    ) -> Result<String, String>;

    fn run_gate_checks(
        &mut self,
        repo: &str,
        worktree_path: &str,
        checks: &[String],
        semaphore: &HeavyCheckSemaphore,
    ) -> Result<(), String>;

    fn verify_exact_sha_ci(&mut self, repo: &str, sha: &str) -> Result<bool, String>;

    fn merge_pr_match_head(
        &mut self,
        repo: &str,
        pr_number: i64,
        head_sha: &str,
    ) -> Result<String, String>;

    fn verify_post_merge_ci(&mut self, repo: &str, merge_sha: &str) -> Result<bool, String>;
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

pub struct SystemMergeDriver;

impl MergeDriver for SystemMergeDriver {
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
    ) -> Result<String, String> {
        let fetch = Command::new("git")
            .args(["-C", worktree_path, "fetch", "origin", default_branch])
            .output()
            .map_err(|e| format!("git fetch failed: {e}"))?;
        if !fetch.status.success() {
            let stderr = String::from_utf8_lossy(&fetch.stderr);
            return Err(format!(
                "git fetch origin/{default_branch} failed: {stderr}"
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
            return Err(format!(
                "git merge --no-edit origin/{default_branch} failed: {stderr}"
            ));
        }

        let rev = Command::new("git")
            .args(["-C", worktree_path, "rev-parse", "HEAD"])
            .output()
            .map_err(|e| format!("git rev-parse HEAD failed: {e}"))?;
        if !rev.status.success() {
            return Err("git rev-parse HEAD failed after merge".to_owned());
        }
        Ok(String::from_utf8_lossy(&rev.stdout).trim().to_owned())
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
                semaphore.run_serialized(|| -> Result<(), String> {
                    let out = Command::new("bash")
                        .args(["-lc", cmd])
                        .current_dir(worktree_path)
                        .env_clear()
                        .envs(&clean_env)
                        .output()
                        .map_err(|e| format!("failed to run heavy check '{cmd}': {e}"))?;
                    if !out.status.success() {
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        return Err(format!("heavy check '{cmd}' failed: {}", stderr.trim()));
                    }
                    Ok(())
                })?;
            } else {
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
        }
        Ok(())
    }

    fn verify_exact_sha_ci(&mut self, repo: &str, sha: &str) -> Result<bool, String> {
        let out = Command::new("gh")
            .args([
                "run",
                "list",
                "--commit",
                sha,
                "--repo",
                repo,
                "--json",
                "conclusion,status",
            ])
            .output()
            .map_err(|e| format!("gh run list failed: {e}"))?;
        if !out.status.success() {
            return Ok(false);
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let runs: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or(serde_json::Value::Array(Vec::new()));
        let Some(arr) = runs.as_array() else {
            return Ok(false);
        };
        if arr.is_empty() {
            return Ok(false);
        }
        for run in arr {
            let conclusion = run.get("conclusion").and_then(|v| v.as_str()).unwrap_or("");
            if conclusion.eq_ignore_ascii_case("success") {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn merge_pr_match_head(
        &mut self,
        repo: &str,
        pr_number: i64,
        head_sha: &str,
    ) -> Result<String, String> {
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
                repo,
            ])
            .output()
            .map_err(|e| format!("gh pr merge failed: {e}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!("gh pr merge failed: {stderr}"));
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        Ok(stdout.trim().to_owned())
    }

    fn verify_post_merge_ci(&mut self, repo: &str, merge_sha: &str) -> Result<bool, String> {
        self.verify_exact_sha_ci(repo, merge_sha)
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

    // If an item in this repo lane is currently MERGING or MERGE_QUEUE_BLOCKED, lane is non-dispatchable
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

/// Drives the head of the per-repository FIFO merge queue through:
/// 1. `git merge --no-edit origin/<default>`
/// 2. Gate checks under `HeavyCheckSemaphore`
/// 3. Exact-SHA CI verification
/// 4. Merge via `gh pr merge --match-head-commit <sha>`
/// 5. Post-merge CI verification
///
/// On post-merge CI failure: blocks the repo lane with `MERGE_QUEUE_BLOCKED` + `DECISION_REQUIRED`.
/// On success: marks task `Done`, removes queue entry, and releases path locks.
pub fn process_repo_merge_queue(
    store: &mut V2Store,
    repo: &str,
    driver: &mut dyn MergeDriver,
    semaphore: &HeavyCheckSemaphore,
) -> Result<MergeQueueOutcome, String> {
    let entries = store
        .list_merge_queue(Some(repo))
        .map_err(|e| e.to_string())?;

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

    let worktree_path = task.worktree_path.clone().unwrap_or_default();
    let default_branch = match driver.default_branch(repo, &worktree_path) {
        Ok(branch) => branch,
        Err(err) => {
            let _ = store.update_merge_queue_state(repo, &entry.task_id, "FAILED");
            let _ = store.append_event(
                &entry.task_id,
                &task.task_group,
                "MERGE_FAILED",
                &serde_json::json!({
                    "step": "default_branch",
                    "error": err,
                }),
            );
            return Ok(MergeQueueOutcome::Failed {
                task_id: entry.task_id,
                reason: err,
            });
        }
    };

    // 1. Merge origin/<default_branch>
    let merge_head = match driver.merge_origin_default(repo, &worktree_path, &default_branch) {
        Ok(head) => head,
        Err(err) => {
            let _ = store.update_merge_queue_state(repo, &entry.task_id, "FAILED");
            let _ = store.append_event(
                &entry.task_id,
                &task.task_group,
                "MERGE_FAILED",
                &serde_json::json!({
                    "step": "merge_origin_default",
                    "error": err,
                }),
            );
            return Ok(MergeQueueOutcome::Failed {
                task_id: entry.task_id,
                reason: err,
            });
        }
    };

    // 2. Gate checks under heavy semaphore
    if let Err(err) = driver.run_gate_checks(
        repo,
        &worktree_path,
        &task.context_pack.gate_checks,
        semaphore,
    ) {
        let _ = store.update_merge_queue_state(repo, &entry.task_id, "FAILED");
        let _ = store.append_event(
            &entry.task_id,
            &task.task_group,
            "MERGE_FAILED",
            &serde_json::json!({
                "step": "gate_checks",
                "error": err,
            }),
        );
        return Ok(MergeQueueOutcome::Failed {
            task_id: entry.task_id,
            reason: err,
        });
    }

    // 3. Verify exact-SHA CI
    let target_sha = if !merge_head.trim().is_empty() {
        merge_head.clone()
    } else {
        entry.reviewed_sha.clone()
    };
    match driver.verify_exact_sha_ci(repo, &target_sha) {
        Ok(true) => {}
        Ok(false) => {
            let err = format!("exact-SHA CI check failed or pending for sha {target_sha}");
            let _ = store.update_merge_queue_state(repo, &entry.task_id, "FAILED");
            let _ = store.append_event(
                &entry.task_id,
                &task.task_group,
                "MERGE_FAILED",
                &serde_json::json!({
                    "step": "exact_sha_ci",
                    "error": err,
                }),
            );
            return Ok(MergeQueueOutcome::Failed {
                task_id: entry.task_id,
                reason: err,
            });
        }
        Err(err) => {
            let _ = store.update_merge_queue_state(repo, &entry.task_id, "FAILED");
            return Ok(MergeQueueOutcome::Failed {
                task_id: entry.task_id,
                reason: err,
            });
        }
    }

    // 4. Merge PR with --match-head-commit <sha>
    let merge_sha = match driver.merge_pr_match_head(repo, entry.pr_number, &target_sha) {
        Ok(sha) => sha,
        Err(err) => {
            let _ = store.update_merge_queue_state(repo, &entry.task_id, "FAILED");
            let _ = store.append_event(
                &entry.task_id,
                &task.task_group,
                "MERGE_FAILED",
                &serde_json::json!({
                    "step": "merge_pr_match_head",
                    "error": err,
                }),
            );
            return Ok(MergeQueueOutcome::Failed {
                task_id: entry.task_id,
                reason: err,
            });
        }
    };

    // 5. Post-merge CI verification
    let post_merge_ok = driver
        .verify_post_merge_ci(repo, &merge_sha)
        .unwrap_or(false);

    if !post_merge_ok {
        // Block the repository lane with MERGE_QUEUE_BLOCKED + DECISION_REQUIRED
        let _ = store.update_merge_queue_state(repo, &entry.task_id, "MERGE_QUEUE_BLOCKED");
        let dec_id = format!("dec-{}-post-merge-ci", entry.task_id.to_ascii_lowercase());
        let _ = store.open_decision(
            &dec_id,
            &entry.task_id,
            &task.task_group,
            "post_merge_ci_failed",
            &format!(
                "Post-merge CI failed on default branch after merging PR #{} (merge_sha={}). Immediate intervention required to unblock repository '{}'",
                entry.pr_number, merge_sha, repo
            ),
            &[
                "Revert merge commit".to_owned(),
                "Fix forward".to_owned(),
                "Ignore failure and unblock".to_owned(),
            ],
            Some(0),
            "Post-merge CI failed on default branch",
            Some(&merge_sha),
        );

        let _ = store.append_event(
            &entry.task_id,
            &task.task_group,
            "MERGE_QUEUE_BLOCKED",
            &serde_json::json!({
                "repo": repo,
                "merge_sha": merge_sha,
                "pr_number": entry.pr_number,
                "decision_id": dec_id,
            }),
        );

        task.status = "Blocked".to_owned();
        let _ = store.upsert_task(&task);

        return Ok(MergeQueueOutcome::Blocked {
            task_id: entry.task_id,
            reason: format!(
                "post-merge CI failed for PR #{} ({merge_sha}); repository '{repo}' lane blocked",
                entry.pr_number
            ),
        });
    }

    // Success: mark Done, remove merge queue entry, and release path locks
    task.status = "Done".to_owned();
    task.current_stage = None;
    task.active_attempt_id = None;
    let _ = store.upsert_task(&task);

    let _ = store.remove_merge_queue_entry(repo, &entry.task_id);
    let _ = store.release_path_locks(&entry.task_id);

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

    Ok(MergeQueueOutcome::Merged {
        task_id: entry.task_id,
        pr_number: entry.pr_number,
        merge_sha,
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::v2::store::{ContextPackSpec, TargetFileSpec, TaskMemory, TaskRecord};

    #[derive(Default)]
    pub struct MockMergeDriver {
        pub default_branch: Option<String>,
        pub default_branch_error: Option<String>,
        pub merged_against: Option<String>,
        pub origin_default_sha: Option<String>,
        pub merge_origin_error: Option<String>,
        pub gate_checks_error: Option<String>,
        pub exact_sha_ci_result: bool,
        pub exact_sha_ci_error: Option<String>,
        pub merge_pr_result: Option<String>,
        pub merge_pr_error: Option<String>,
        pub post_merge_ci_result: bool,
        pub post_merge_ci_error: Option<String>,
        pub steps: Vec<String>,
    }

    impl MergeDriver for MockMergeDriver {
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
        ) -> Result<String, String> {
            self.merged_against = Some(default_branch.to_owned());
            self.steps.push("merge_origin_default".to_owned());
            if let Some(ref err) = self.merge_origin_error {
                return Err(err.clone());
            }
            Ok(self
                .origin_default_sha
                .clone()
                .unwrap_or_else(|| "mock-merge-head-sha".to_owned()))
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

        fn verify_exact_sha_ci(&mut self, _repo: &str, _sha: &str) -> Result<bool, String> {
            self.steps.push("verify_exact_sha_ci".to_owned());
            if let Some(ref err) = self.exact_sha_ci_error {
                return Err(err.clone());
            }
            Ok(self.exact_sha_ci_result)
        }

        fn merge_pr_match_head(
            &mut self,
            _repo: &str,
            _pr_number: i64,
            _head_sha: &str,
        ) -> Result<String, String> {
            self.steps.push("merge_pr_match_head".to_owned());
            if let Some(ref err) = self.merge_pr_error {
                return Err(err.clone());
            }
            Ok(self
                .merge_pr_result
                .clone()
                .unwrap_or_else(|| "mock-final-merge-sha".to_owned()))
        }

        fn verify_post_merge_ci(&mut self, _repo: &str, _merge_sha: &str) -> Result<bool, String> {
            self.steps.push("verify_post_merge_ci".to_owned());
            if let Some(ref err) = self.post_merge_ci_error {
                return Err(err.clone());
            }
            Ok(self.post_merge_ci_result)
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
    fn merge_queue_enforces_per_repo_fifo_ordering() {
        let mut store = V2Store::open_in_memory().expect("open store");

        enqueue_for_merge(&mut store, "zach", "TASK-1", 101, "sha-1").unwrap();
        enqueue_for_merge(&mut store, "zach", "TASK-2", 102, "sha-2").unwrap();
        enqueue_for_merge(&mut store, "governance", "GOV-1", 201, "gov-sha-1").unwrap();

        // dequeue_next on zach returns TASK-1 first
        let next_zach = dequeue_next(&store, "zach").unwrap().unwrap();
        assert_eq!(next_zach.task_id, "TASK-1");

        // governance lane has its own independent head
        let next_gov = dequeue_next(&store, "governance").unwrap().unwrap();
        assert_eq!(next_gov.task_id, "GOV-1");
    }

    #[test]
    fn process_repo_merge_queue_success_releases_path_locks_and_completes_task() {
        let mut store = V2Store::open_in_memory().expect("open store");
        let task = sample_task("TASK-1", "zach", vec!["src/v2/merge_queue.rs"]);
        store.upsert_task(&task).unwrap();

        // Acquire path locks for TASK-1 (as held from impl/pr-review)
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
            exact_sha_ci_result: true,
            merge_pr_result: Some("final-commit-sha".to_owned()),
            post_merge_ci_result: true,
            ..Default::default()
        };

        let outcome =
            process_repo_merge_queue(&mut store, "zach", &mut driver, &semaphore).unwrap();
        assert_eq!(
            outcome,
            MergeQueueOutcome::Merged {
                task_id: "TASK-1".to_owned(),
                pr_number: 42,
                merge_sha: "final-commit-sha".to_owned(),
            }
        );

        // Task marked Done
        let updated_task = store.get_task("TASK-1").unwrap().unwrap();
        assert_eq!(updated_task.status, "Done");

        // Merge queue entry removed
        assert!(store.list_merge_queue(Some("zach")).unwrap().is_empty());

        // Path locks released on completion!
        assert!(store.list_path_locks(Some("zach")).unwrap().is_empty());

        // Steps executed in exact required order
        assert_eq!(
            driver.steps,
            vec![
                "merge_origin_default",
                "run_gate_checks",
                "verify_exact_sha_ci",
                "merge_pr_match_head",
                "verify_post_merge_ci",
            ]
        );
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
            exact_sha_ci_result: true,
            merge_pr_result: Some("merge-commit-1".to_owned()),
            post_merge_ci_result: false, // POST-MERGE CI FAILS!
            ..Default::default()
        };

        let outcome =
            process_repo_merge_queue(&mut store, "zach", &mut driver, &semaphore).unwrap();
        assert!(matches!(outcome, MergeQueueOutcome::Blocked { .. }));

        // Queue entry state is MERGE_QUEUE_BLOCKED
        let entry = store
            .get_merge_queue_entry("zach", "TASK-1")
            .unwrap()
            .unwrap();
        assert_eq!(entry.state, "MERGE_QUEUE_BLOCKED");

        // Decision opened with kind 'post_merge_ci_failed'
        let decs = store.list_decisions(true, None).unwrap();
        assert_eq!(decs.len(), 1);
        assert_eq!(decs[0].kind, "post_merge_ci_failed");
        assert_eq!(decs[0].task_id, "TASK-1");

        // Subsequent dequeue_next for zach returns None because repo lane is blocked!
        assert!(dequeue_next(&store, "zach").unwrap().is_none());

        // And subsequent process_repo_merge_queue also reports Blocked!
        let next_outcome =
            process_repo_merge_queue(&mut store, "zach", &mut driver, &semaphore).unwrap();
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
            exact_sha_ci_result: true,
            merge_pr_result: Some("final-commit-sha".to_owned()),
            post_merge_ci_result: true,
            ..Default::default()
        };

        let outcome =
            process_repo_merge_queue(&mut store, "governance", &mut driver, &semaphore).unwrap();
        assert!(matches!(outcome, MergeQueueOutcome::Merged { .. }));
        assert_eq!(driver.merged_against, Some("master".to_owned()));
    }

    #[test]
    fn process_repo_merge_queue_fails_when_default_branch_unresolvable() {
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

        let outcome =
            process_repo_merge_queue(&mut store, "zach", &mut driver, &semaphore).unwrap();
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
        assert_eq!(entry.state, "FAILED");
    }
}
