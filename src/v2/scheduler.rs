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

/// Each task owns the entire repository from preparation through merge/human gates.
/// Queued merges and human waits reserve a repository but consume no execution slot.
pub fn schedule_next_dispatches(store: &mut V2Store) -> Result<Vec<ScheduledDispatch>, String> {
    schedule_scoped_dispatches(store, None, None)
}

pub fn schedule_scoped_dispatches(
    store: &mut V2Store,
    task_id: Option<&str>,
    group: Option<&str>,
) -> Result<Vec<ScheduledDispatch>, String> {
    let max_parallel = store.max_parallel_tasks().map_err(|e| e.to_string())?;
    let all_tasks = store.list_tasks(None).map_err(|e| e.to_string())?;
    let active_count = all_tasks
        .iter()
        .map(|task| store.occupies_task_slot(task))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?
        .iter()
        .filter(|occupied| **occupied)
        .count();
    let available_slots = max_parallel.saturating_sub(active_count);
    let mut occupied = std::collections::BTreeMap::new();
    for lock in store.list_path_locks(None).map_err(|e| e.to_string())? {
        occupied.insert(lock.repo, lock.task_id);
    }
    for t in &all_tasks {
        if matches!(
            t.status.as_str(),
            "Planning" | "Plan Review" | "In Progress" | "PR Review" | "Queued for Merge"
        ) {
            occupied
                .entry(t.repository.clone())
                .or_insert_with(|| t.task_id.clone());
        }
    }
    for e in store.list_merge_queue(None).map_err(|e| e.to_string())? {
        occupied.entry(e.repo).or_insert(e.task_id);
    }
    let ready_tasks = store.list_ready_queue(group).map_err(|e| e.to_string())?;
    let mut dispatches = Vec::new();
    for mut task in ready_tasks {
        if dispatches.len() >= available_slots {
            break;
        }
        if task_id.is_some_and(|id| id != task.task_id) {
            continue;
        }
        if occupied
            .get(&task.repository)
            .is_some_and(|owner| owner != &task.task_id)
        {
            continue;
        }
        let Some(stage) = determine_next_stage(&task) else {
            continue;
        };
        let status = match stage.as_str() {
            "plan" => "Planning",
            "plan-review" => "Plan Review",
            "impl" => "In Progress",
            "pr-review" => "PR Review",
            _ => continue,
        };
        let paths = vec!["*".to_owned()];
        if !store
            .acquire_path_locks(&task.repository, &paths, &task.task_id)
            .map_err(|e| e.to_string())?
        {
            continue;
        }
        task.status = status.to_owned();
        task.current_stage = Some(stage.clone());
        store.upsert_task(&task).map_err(|e| e.to_string())?;
        occupied.insert(task.repository.clone(), task.task_id.clone());
        dispatches.push(ScheduledDispatch {
            task_id: task.task_id,
            repository: task.repository,
            stage,
            acquired_paths: paths,
        });
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
            next_retry_epoch: 0,
            lease_owner: None,
            lease_expires_epoch: None,
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
    fn scheduler_serializes_planning_per_repo_and_bounds_parallel_repos() {
        let mut store = V2Store::open_in_memory().expect("open store");
        store.set_max_parallel_tasks(2).unwrap();

        // Two M tasks in Ready state (starting at 'plan' stage)
        let t1 = make_test_task("ZACH-001", "zach", "M", "Ready", vec!["src/a.rs"], vec![]);
        let t2 = make_test_task("ZACH-002", "other", "M", "Ready", vec!["src/a.rs"], vec![]);
        let t3 = make_test_task("ZACH-003", "zach", "M", "Ready", vec!["src/b.rs"], vec![]);

        store.upsert_task(&t1).unwrap();
        store.upsert_task(&t2).unwrap();
        store.upsert_task(&t3).unwrap();

        // First dispatch: max_parallel = 2, different repositories run concurrently
        // Different repositories can plan in parallel; the third task waits for its repository.
        let dispatches = schedule_next_dispatches(&mut store).unwrap();
        assert_eq!(dispatches.len(), 2);
        assert_eq!(dispatches[0].task_id, "ZACH-001");
        assert_eq!(dispatches[0].stage, "plan");
        assert_eq!(dispatches[0].acquired_paths, vec!["*"]);
        assert_eq!(dispatches[1].task_id, "ZACH-002");
        assert_eq!(dispatches[1].stage, "plan");
        assert_eq!(dispatches[1].acquired_paths, vec!["*"]);

        // Store now has 2 active tasks ("Planning"), so next schedule tick returns 0 dispatches
        let dispatches2 = schedule_next_dispatches(&mut store).unwrap();
        assert!(dispatches2.is_empty());
    }

    #[test]
    fn scheduler_serializes_disjoint_impl_paths_and_reacquires_for_review() {
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
        let t3 = make_test_task("T-3", "other", "S", "Ready", vec!["src/intake.rs"], vec![]);

        store.upsert_task(&t1).unwrap();
        store.upsert_task(&t2).unwrap();
        store.upsert_task(&t3).unwrap();

        let dispatches = schedule_next_dispatches(&mut store).unwrap();
        // T-1 is scheduled and acquires src/router.rs
        // T-2 conflicts on src/router.rs and is skipped
        // T-3 does not conflict and is scheduled
        assert_eq!(dispatches.len(), 2);
        assert_eq!(dispatches[0].task_id, "T-1");
        assert_eq!(dispatches[0].acquired_paths, vec!["*"]);
        assert_eq!(dispatches[1].task_id, "T-3");
        assert_eq!(dispatches[1].acquired_paths, vec!["*"]);

        // Verify path locks in store
        let locks = store.list_path_locks(Some("zach")).unwrap();
        assert_eq!(locks.len(), 1);

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
        assert_eq!(locks_after.len(), 1);
    }
    #[test]
    fn queued_merges_and_human_waits_reserve_repo_without_consuming_task_slots() {
        let mut store = V2Store::open_in_memory().unwrap();
        store.set_max_parallel_tasks(1).unwrap();
        let queued = make_test_task(
            "QUEUED",
            "repo-a",
            "S",
            "Queued for Merge",
            vec![],
            vec!["impl", "pr-review"],
        );
        store.upsert_task(&queued).unwrap();
        let mut human = make_test_task(
            "HUMAN",
            "repo-b",
            "L",
            "Blocked",
            vec![],
            vec!["plan", "plan-review"],
        );
        human.current_stage = Some("human-plan-approval".into());
        store.upsert_task(&human).unwrap();
        store
            .acquire_path_locks("repo-b", &["*".into()], "HUMAN")
            .unwrap();
        for (id, repo) in [("A", "repo-a"), ("B", "repo-b"), ("C", "repo-c")] {
            store
                .upsert_task(&make_test_task(id, repo, "M", "Ready", vec![], vec![]))
                .unwrap();
        }
        let dispatches = schedule_next_dispatches(&mut store).unwrap();
        assert_eq!(dispatches.len(), 1);
        assert_eq!(dispatches[0].task_id, "C");
    }

    #[test]
    fn retry_backoff_releases_slot_and_future_retries_do_not_dispatch() {
        let mut store = V2Store::open_in_memory().unwrap();
        store.set_max_parallel_tasks(1).unwrap();
        let mut delayed = make_test_task("A", "repo-a", "S", "Ready", vec![], vec![]);
        delayed.next_retry_epoch = crate::v2::now_epoch() + 60;
        store.upsert_task(&delayed).unwrap();
        store
            .upsert_task(&make_test_task("B", "repo-a", "S", "Ready", vec![], vec![]))
            .unwrap();
        let dispatches = schedule_next_dispatches(&mut store).unwrap();
        assert_eq!(dispatches[0].task_id, "B");
    }
}
