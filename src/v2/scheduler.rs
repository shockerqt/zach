use crate::v2::intake::default_required_stages;
use crate::v2::store::{TaskRecord, V2Store};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledDispatch {
    pub task_id: String,
    pub repository: String,
    pub stage: String,
    pub acquired_paths: Vec<String>,
}

/// Returns `true` if `cmd` represents a resource-intensive verification command
/// that must be serialized via `HeavyCheckSemaphore`.
pub fn is_heavy_verification_command(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    lower.contains("cargo test")
        || lower.contains("cargo clippy")
        || lower.contains("pytest")
        || lower.contains("npm run build")
        || lower.contains("playwright")
}

/// A global or daemon-wide semaphore enforcing `max_heavy_checks = 1`.
#[derive(Clone, Default)]
pub struct HeavyCheckSemaphore {
    inner: Arc<Mutex<()>>,
}

pub struct HeavyCheckPermit<'a> {
    _guard: MutexGuard<'a, ()>,
}

impl HeavyCheckSemaphore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(())),
        }
    }

    pub fn try_acquire(&self) -> Option<HeavyCheckPermit<'_>> {
        self.inner
            .try_lock()
            .ok()
            .map(|_guard| HeavyCheckPermit { _guard })
    }

    pub fn acquire(&self) -> HeavyCheckPermit<'_> {
        HeavyCheckPermit {
            _guard: self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        }
    }

    pub fn run_serialized<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _permit = self.acquire();
        f()
    }
}

pub fn determine_next_stage(task: &TaskRecord) -> Option<String> {
    let stages = if task.required_stages.is_empty() {
        default_required_stages(&task.weight)
    } else {
        task.required_stages.clone()
    };
    stages
        .into_iter()
        .find(|stage| !task.stages_completed.contains(stage))
}

/// Evaluates ready tasks in the store and schedules the next eligible dispatches.
///
/// Guarantees:
/// 1. Enforces `store.max_parallel_tasks()`.
/// 2. Allows read-only stages (`plan`, `plan-review`) to run in parallel without acquiring `path_locks`.
/// 3. For `impl`, atomically acquires per-repo `path_locks` based on `task.context_pack.target_files`
///    (defaulting to `["*"]` if empty). Skips conflicting tasks while allowing non-overlapping tasks to proceed.
/// 4. Preserves `path_locks` from `impl` through `pr-review` and `merge_queue`.
pub fn schedule_next_dispatches(store: &mut V2Store) -> Result<Vec<ScheduledDispatch>, String> {
    let max_parallel = store.max_parallel_tasks().map_err(|e| e.to_string())?;
    let all_tasks = store.list_tasks(None).map_err(|e| e.to_string())?;
    let active_count = all_tasks
        .iter()
        .filter(|t| {
            matches!(
                t.status.as_str(),
                "Planning" | "Plan Review" | "In Progress" | "PR Review"
            )
        })
        .count();

    if active_count >= max_parallel {
        return Ok(Vec::new());
    }
    let available_slots = max_parallel.saturating_sub(active_count);

    let ready_tasks = store.list_ready_queue(None).map_err(|e| e.to_string())?;
    let mut dispatches = Vec::new();

    for mut task in ready_tasks {
        if dispatches.len() >= available_slots {
            break;
        }

        let Some(stage) = determine_next_stage(&task) else {
            continue;
        };

        if stage == "human-plan-approval" || stage == "human-merge-approval" {
            // Human gates are evaluated in the pipeline or decision engine, not dispatched to workers
            continue;
        }

        if stage == "plan" || stage == "plan-review" {
            // Read-only stages: run concurrently without acquiring path_locks
            let new_status = if stage == "plan" {
                "Planning"
            } else {
                "Plan Review"
            };
            task.status = new_status.to_owned();
            task.current_stage = Some(stage.clone());
            store.upsert_task(&task).map_err(|e| e.to_string())?;

            dispatches.push(ScheduledDispatch {
                task_id: task.task_id,
                repository: task.repository,
                stage,
                acquired_paths: Vec::new(),
            });
            continue;
        }

        if stage == "impl" {
            let paths: Vec<String> = if task.context_pack.target_files.is_empty() {
                vec!["*".to_owned()]
            } else {
                task.context_pack
                    .target_files
                    .iter()
                    .map(|tf| tf.path.clone())
                    .collect()
            };

            let acquired = store
                .acquire_path_locks(&task.repository, &paths, &task.task_id)
                .map_err(|e| e.to_string())?;

            if !acquired {
                // Path conflict: skip this task for now, leaving it in Ready for non-conflicting tasks
                continue;
            }

            task.status = "In Progress".to_owned();
            task.current_stage = Some("impl".to_owned());
            store.upsert_task(&task).map_err(|e| e.to_string())?;

            dispatches.push(ScheduledDispatch {
                task_id: task.task_id,
                repository: task.repository,
                stage,
                acquired_paths: paths,
            });
            continue;
        }

        if stage == "pr-review" {
            // Locks were acquired before impl and must remain held
            let paths: Vec<String> = if task.context_pack.target_files.is_empty() {
                vec!["*".to_owned()]
            } else {
                task.context_pack
                    .target_files
                    .iter()
                    .map(|tf| tf.path.clone())
                    .collect()
            };
            // Ensure lock remains registered for this task
            let _ = store.acquire_path_locks(&task.repository, &paths, &task.task_id);

            task.status = "PR Review".to_owned();
            task.current_stage = Some("pr-review".to_owned());
            store.upsert_task(&task).map_err(|e| e.to_string())?;

            dispatches.push(ScheduledDispatch {
                task_id: task.task_id,
                repository: task.repository,
                stage,
                acquired_paths: paths,
            });
        }
    }

    Ok(dispatches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::store::{ContextPackSpec, TargetFileSpec, TaskMemory};

    fn make_test_task(
        id: &str,
        repo: &str,
        weight: &str,
        status: &str,
        targets: Vec<&str>,
        completed: Vec<&str>,
    ) -> TaskRecord {
        TaskRecord {
            task_id: id.to_owned(),
            task_group: "test".to_owned(),
            title: format!("Task {id}"),
            repository: repo.to_owned(),
            github_repo: Some(format!("shockerqt/{repo}")),
            issue_number: Some(1),
            weight: weight.to_owned(),
            status: status.to_owned(),
            worktree_path: Some(format!("/home/ubuntu/workspace/{repo}--{id}")),
            branch: Some(format!("task/{id}")),
            context_pack: ContextPackSpec {
                weight: weight.to_owned(),
                target_files: targets
                    .into_iter()
                    .map(|p| TargetFileSpec {
                        path: p.to_owned(),
                        action: "modify".to_owned(),
                        summary: String::new(),
                    })
                    .collect(),
                ..ContextPackSpec::default()
            },
            depends_on: Vec::new(),
            required_stages: default_required_stages(weight),
            stages_completed: completed.into_iter().map(str::to_owned).collect(),
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
    fn heavy_verification_command_detection_works() {
        assert!(is_heavy_verification_command("cargo test --workspace"));
        assert!(is_heavy_verification_command("cargo clippy -- -D warnings"));
        assert!(is_heavy_verification_command("pytest tests/"));
        assert!(is_heavy_verification_command("npm run build"));
        assert!(is_heavy_verification_command("npx playwright test"));
        assert!(!is_heavy_verification_command("git status"));
        assert!(!is_heavy_verification_command("echo hello"));
    }

    #[test]
    fn heavy_check_semaphore_serializes_execution() {
        let semaphore = HeavyCheckSemaphore::new();
        let permit = semaphore.try_acquire();
        assert!(permit.is_some());

        // Second attempt to acquire while permit held fails
        assert!(semaphore.try_acquire().is_none());

        // Drop permit
        drop(permit);

        // Can acquire again
        assert!(semaphore.try_acquire().is_some());

        // run_serialized works
        let result = semaphore.run_serialized(|| 42);
        assert_eq!(result, 42);
    }

    #[test]
    fn scheduler_enforces_max_parallel_and_readonly_stages_run_in_parallel() {
        let mut store = V2Store::open_in_memory().expect("open store");
        store.set_max_parallel_tasks(2).unwrap();

        // Two M tasks in Ready state (starting at 'plan' stage)
        let t1 = make_test_task("ZACH-001", "zach", "M", "Ready", vec!["src/a.rs"], vec![]);
        let t2 = make_test_task("ZACH-002", "zach", "M", "Ready", vec!["src/a.rs"], vec![]);
        let t3 = make_test_task("ZACH-003", "zach", "M", "Ready", vec!["src/b.rs"], vec![]);

        store.upsert_task(&t1).unwrap();
        store.upsert_task(&t2).unwrap();
        store.upsert_task(&t3).unwrap();

        // First dispatch: max_parallel = 2, both run read-only 'plan' stage concurrently
        // even though t1 and t2 touch the same path 'src/a.rs' (read-only stages don't lock paths!)
        let dispatches = schedule_next_dispatches(&mut store).unwrap();
        assert_eq!(dispatches.len(), 2);
        assert_eq!(dispatches[0].task_id, "ZACH-001");
        assert_eq!(dispatches[0].stage, "plan");
        assert!(dispatches[0].acquired_paths.is_empty());
        assert_eq!(dispatches[1].task_id, "ZACH-002");
        assert_eq!(dispatches[1].stage, "plan");
        assert!(dispatches[1].acquired_paths.is_empty());

        // Store now has 2 active tasks ("Planning"), so next schedule tick returns 0 dispatches
        let dispatches2 = schedule_next_dispatches(&mut store).unwrap();
        assert!(dispatches2.is_empty());
    }

    #[test]
    fn scheduler_enforces_path_locks_for_impl_and_allows_non_overlapping_tasks() {
        let mut store = V2Store::open_in_memory().expect("open store");
        store.set_max_parallel_tasks(4).unwrap();

        // Three tasks ready for 'impl':
        // t1 modifies src/router.rs
        // t2 modifies src/router.rs and src/runner.rs (conflicts with t1)
        // t3 modifies src/intake.rs (no conflict)
        let t1 = make_test_task("T-1", "zach", "S", "Ready", vec!["src/router.rs"], vec![]);
        let t2 = make_test_task(
            "T-2",
            "zach",
            "S",
            "Ready",
            vec!["src/router.rs", "src/runner.rs"],
            vec![],
        );
        let t3 = make_test_task("T-3", "zach", "S", "Ready", vec!["src/intake.rs"], vec![]);

        store.upsert_task(&t1).unwrap();
        store.upsert_task(&t2).unwrap();
        store.upsert_task(&t3).unwrap();

        let dispatches = schedule_next_dispatches(&mut store).unwrap();
        // T-1 is scheduled and acquires src/router.rs
        // T-2 conflicts on src/router.rs and is skipped
        // T-3 does not conflict and is scheduled
        assert_eq!(dispatches.len(), 2);
        assert_eq!(dispatches[0].task_id, "T-1");
        assert_eq!(dispatches[0].acquired_paths, vec!["src/router.rs"]);
        assert_eq!(dispatches[1].task_id, "T-3");
        assert_eq!(dispatches[1].acquired_paths, vec!["src/intake.rs"]);

        // Verify path locks in store
        let locks = store.list_path_locks(Some("zach")).unwrap();
        assert_eq!(locks.len(), 2);

        // Path locks are held across pr-review and not released between impl and pr-review
        let mut t1_updated = store.get_task("T-1").unwrap().unwrap();
        t1_updated.stages_completed.push("impl".to_owned());
        t1_updated.status = "Ready".to_owned();
        store.upsert_task(&t1_updated).unwrap();

        let dispatches_pr = schedule_next_dispatches(&mut store).unwrap();
        assert_eq!(dispatches_pr.len(), 1);
        assert_eq!(dispatches_pr[0].task_id, "T-1");
        assert_eq!(dispatches_pr[0].stage, "pr-review");

        // Locks still held!
        let locks_after = store.list_path_locks(Some("zach")).unwrap();
        assert_eq!(locks_after.len(), 2);
    }
}
