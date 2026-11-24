use crate::v2::intake::default_required_stages;
use crate::v2::store::{RepoReservation, TaskRecord, V2Store, repo_conflict_for_task};
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
    let mut reservations = store
        .repo_reservations(&all_tasks)
        .map_err(|e| e.to_string())?;
    let ready_tasks = store.list_ready_queue(group).map_err(|e| e.to_string())?;
    let mut dispatches = Vec::new();
    for mut task in ready_tasks {
        if dispatches.len() >= available_slots {
            break;
        }
        if task_id.is_some_and(|id| id != task.task_id) {
            continue;
        }
        if let Some(repo_res) = reservations.get(&task.repository)
            && repo_conflict_for_task(repo_res, &task).is_some()
        {
            continue;
        }
        let Some(stage) = determine_next_stage(&task) else {
            continue;
        };
        if !task.has_execution_grant_for(Some(&stage)) {
            continue;
        }
        let author_stage = match stage.as_str() {
            "plan-review" => Some("plan"),
            "pr-review" => Some("impl"),
            _ => None,
        };
        let author_family = if let Some(src_stage) = author_stage {
            store
                .list_stage_attempts(&task.task_id)
                .map_err(|e| e.to_string())?
                .into_iter()
                .rev()
                .find(|a| a.stage == src_stage && a.status == "PASSED")
                .map(|a| crate::v2::router::infer_model_family(&a.model))
        } else {
            None
        };
        if let Ok(Some(base_route)) = crate::v2::router::resolve_stage_route(
            &task.weight,
            &stage,
            task.retry_count,
            author_family,
        ) {
            let route = crate::v2::pipeline::apply_stage_fallback_route(&task, base_route);
            let now = crate::v2::now_epoch();
            if store
                .get_active_provider_cooldown(route.family.as_str(), now)
                .map_err(|e| e.to_string())?
                .is_some()
            {
                let can_fallback = !matches!(stage.as_str(), "plan-review" | "pr-review")
                    && route.fallback_model.is_some()
                    && match route.fallback_family {
                        Some(fb_family) => store
                            .get_active_provider_cooldown(fb_family.as_str(), now)
                            .map_err(|e| e.to_string())?
                            .is_none(),
                        None => false,
                    };
                if can_fallback {
                    if !task.memory.fallback_stages.iter().any(|s| s == &stage) {
                        task.memory.fallback_stages.push(stage.clone());
                    }
                } else {
                    continue;
                }
            }
        }
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
        reservations
            .entry(task.repository.clone())
            .or_default()
            .push(RepoReservation::WholeRepo {
                task_id: task.task_id.clone(),
            });
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
    use crate::v2::store::{ContextPackSpec, PipelineCheckpoint, TargetFileSpec, TaskMemory};

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

    #[test]
    fn manual_active_rows_reserve_their_repository_without_consuming_native_slots() {
        let mut store = V2Store::open_in_memory().unwrap();
        store.set_max_parallel_tasks(1).unwrap();
        for (i, status) in ["Planning", "Plan Review", "In Progress", "PR Review"]
            .into_iter()
            .enumerate()
        {
            let mut manual = make_test_task(
                &format!("MANUAL-{i}"),
                "human-repo",
                "M",
                status,
                vec![],
                vec!["plan", "plan-review"],
            );
            manual.autonomous_consent = i % 2 == 0;
            manual.executor = match i {
                0 => None,
                1 => Some("external".into()),
                _ => Some("session".into()),
            };
            store.upsert_task(&manual).unwrap();
        }
        for (id, repo) in [
            ("A-SAME", "human-repo"),
            ("B-OTHER", "other-repo"),
            ("C-OTHER", "third-repo"),
        ] {
            store
                .upsert_task(&make_test_task(id, repo, "S", "Ready", vec![], vec![]))
                .unwrap();
        }
        let before = store.status_summary().unwrap();
        assert_eq!(before.in_progress_count, 4);
        assert_eq!(before.running_task_slots, 0);

        let dispatched = schedule_next_dispatches(&mut store).unwrap();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].task_id, "B-OTHER");
        assert_eq!(store.get_task("A-SAME").unwrap().unwrap().status, "Ready");
        assert!(
            store
                .list_path_locks(Some("human-repo"))
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.status_summary().unwrap().running_task_slots, 1);
        assert_eq!(store.get_task("C-OTHER").unwrap().unwrap().status, "Ready");
        assert!(
            store
                .list_path_locks(Some("third-repo"))
                .unwrap()
                .is_empty()
        );
        // The native lock counts before an attempt or coordinator checkpoint exists.
        assert!(schedule_next_dispatches(&mut store).unwrap().is_empty());
        assert_eq!(store.status_summary().unwrap().running_task_slots, 1);
        assert_eq!(store.get_task("C-OTHER").unwrap().unwrap().status, "Ready");
        assert!(
            store
                .list_path_locks(Some("third-repo"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn native_reservations_consume_capacity_after_consent_revocation_and_reassignment() {
        for evidence in ["lock", "preparing", "live"] {
            let mut store = V2Store::open_in_memory().unwrap();
            store.set_max_parallel_tasks(1).unwrap();
            let mut native =
                make_test_task("NATIVE", "native-repo", "S", "In Progress", vec![], vec![]);
            native.autonomous_consent = false;
            native.executor = Some("external".into());
            if evidence == "preparing" {
                native.current_stage = Some("impl".into());
                native.memory.pipeline_checkpoint = Some(PipelineCheckpoint {
                    attempt_id: "preparing-attempt".into(),
                    operation: "PREPARING".into(),
                });
            } else if evidence == "live" {
                native.active_attempt_id = Some("live-attempt".into());
            }
            store.upsert_task(&native).unwrap();
            if evidence == "lock" {
                assert!(
                    store
                        .acquire_path_locks("native-repo", &["*".into()], "NATIVE")
                        .unwrap()
                );
            } else if evidence == "live" {
                store.connection_mut().execute_batch("INSERT INTO stage_attempts(attempt_id,task_id,stage,model,effort,started_epoch,status,phase) VALUES('live-attempt','NATIVE','impl','synthetic','low',1,'RUNNING','RUNNING')").unwrap();
            }
            store
                .upsert_task(&make_test_task(
                    "READY",
                    "other-repo",
                    "S",
                    "Ready",
                    vec![],
                    vec![],
                ))
                .unwrap();
            assert_eq!(store.status_summary().unwrap().running_task_slots, 1);
            assert!(schedule_next_dispatches(&mut store).unwrap().is_empty());
            assert_eq!(store.get_task("READY").unwrap().unwrap().status, "Ready");
        }
    }

    #[test]
    fn reopened_native_history_reserves_human_lane_without_consuming_capacity() {
        let mut store = V2Store::open_in_memory().unwrap();
        store.set_max_parallel_tasks(1).unwrap();
        let mut historical = make_test_task(
            "HISTORY",
            "human-repo",
            "S",
            "In Progress",
            vec![],
            vec!["impl"],
        );
        historical.autonomous_consent = false;
        historical.executor = Some("session".into());
        historical.current_stage = Some("impl".into());
        historical.memory.governance_started = true;
        historical.memory.governance_terminal_observed = true;
        store.upsert_task(&historical).unwrap();
        store.connection_mut().execute_batch("INSERT INTO stage_attempts(attempt_id,task_id,stage,model,effort,started_epoch,ended_epoch,status,phase) VALUES('historical-attempt','HISTORY','impl','synthetic','low',1,2,'PASSED','COMPLETE')").unwrap();
        for (id, repo) in [("A-SAME", "human-repo"), ("B-OTHER", "other-repo")] {
            store
                .upsert_task(&make_test_task(id, repo, "S", "Ready", vec![], vec![]))
                .unwrap();
        }
        assert_eq!(store.status_summary().unwrap().running_task_slots, 0);
        let historical_before = store.get_task("HISTORY").unwrap().unwrap();
        let dispatched = schedule_next_dispatches(&mut store).unwrap();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].task_id, "B-OTHER");
        assert_eq!(
            store.get_task("HISTORY").unwrap().unwrap(),
            historical_before
        );
        assert_eq!(store.get_task("A-SAME").unwrap().unwrap().status, "Ready");
        assert!(
            store
                .list_path_locks(Some("human-repo"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn ambiguous_ownership_fails_before_scheduler_mutates_tasks_or_locks() {
        for memory in [
            "{\"unknown_native\":false}",
            "{\"governance_started\":false,\"governance_started\":true}",
            "{\"halt_requested\":0}",
        ] {
            let mut store = V2Store::open_in_memory().unwrap();
            store
                .upsert_task(&make_test_task(
                    "A-READY",
                    "ready-repo",
                    "S",
                    "Ready",
                    vec![],
                    vec![],
                ))
                .unwrap();
            store
                .upsert_task(&make_test_task(
                    "Z-INVALID",
                    "manual-repo",
                    "S",
                    "In Progress",
                    vec![],
                    vec![],
                ))
                .unwrap();
            store
                .connection_mut()
                .execute(
                    "UPDATE tasks SET memory_json=?1 WHERE task_id='Z-INVALID'",
                    [memory],
                )
                .unwrap();
            let before = store.list_tasks(None).unwrap();
            let events = store.max_seq_id().unwrap();
            assert!(store.status_summary().is_err());
            assert!(schedule_next_dispatches(&mut store).is_err());
            assert_eq!(store.list_tasks(None).unwrap(), before);
            assert_eq!(store.max_seq_id().unwrap(), events);
            assert!(store.list_path_locks(None).unwrap().is_empty());
            let raw: String = store
                .connection_mut()
                .query_row(
                    "SELECT memory_json FROM tasks WHERE task_id='Z-INVALID'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(raw, memory);
        }
    }

    #[test]
    fn scheduler_allows_disjoint_session_target_files_and_blocks_overlapping_or_empty() {
        let mut store = V2Store::open_in_memory().unwrap();
        store.set_max_parallel_tasks(2).unwrap();

        let mut active_session = make_test_task(
            "SESSION-1",
            "zach",
            "S",
            "In Progress",
            vec!["./src/v2/store.rs"],
            vec![],
        );
        active_session.executor = Some("session".into());
        store.upsert_task(&active_session).unwrap();

        let ready_overlap =
            make_test_task("A-OVERLAP", "zach", "S", "Ready", vec!["src/v2"], vec![]);
        let ready_empty = make_test_task("B-EMPTY", "zach", "S", "Ready", vec![], vec![]);
        let ready_disjoint = make_test_task(
            "C-DISJOINT",
            "zach",
            "S",
            "Ready",
            vec!["src/v2/scheduler.rs"],
            vec![],
        );
        store.upsert_task(&ready_overlap).unwrap();
        store.upsert_task(&ready_empty).unwrap();
        store.upsert_task(&ready_disjoint).unwrap();

        let dispatches = schedule_next_dispatches(&mut store).unwrap();
        assert_eq!(dispatches.len(), 1);
        assert_eq!(dispatches[0].task_id, "C-DISJOINT");
        assert_eq!(dispatches[0].acquired_paths, vec!["*".to_owned()]);
        assert_eq!(
            store.get_task("A-OVERLAP").unwrap().unwrap().status,
            "Ready"
        );
        assert_eq!(store.get_task("B-EMPTY").unwrap().unwrap().status, "Ready");
    }

    #[test]
    fn resumed_task_returns_to_ready_and_redispatches_without_stranding_path_locks() {
        let mut store = V2Store::open_in_memory().unwrap();
        store.set_max_parallel_tasks(1).unwrap();

        let mut task = make_test_task("RESUME-1", "zach", "S", "Ready", vec![], vec![]);
        task.memory.governance_started = true;
        store.upsert_task(&task).unwrap();

        let first = schedule_scoped_dispatches(&mut store, None, None).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].task_id, "RESUME-1");

        // Simulate lifecycle_ack("start") returning an idle task to Ready while keeping path_locks for the same task.
        let mut acked = store.get_task("RESUME-1").unwrap().unwrap();
        acked.status = "Ready".into();
        store.upsert_task(&acked).unwrap();

        let second = schedule_scoped_dispatches(&mut store, None, None).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].task_id, "RESUME-1");
        assert_eq!(
            store.get_task("RESUME-1").unwrap().unwrap().status,
            "In Progress"
        );
    }

    #[test]
    fn cooldown_routes_primary_to_fallback_when_available_and_defers_when_unavailable() {
        let mut store = V2Store::open_in_memory().unwrap();
        store.set_max_parallel_tasks(2).unwrap();
        let future = crate::v2::now_epoch() + 1800;

        // S/impl primary is OpenAiSol, fallback is GeminiAgy.
        let mut impl_task = make_test_task("CD-IMPL", "repo-a", "S", "Ready", vec![], vec![]);
        impl_task.memory.governance_started = true;
        store.upsert_task(&impl_task).unwrap();

        // Cooldown OpenAiSol only -> S/impl should route to GeminiAgy fallback.
        store
            .upsert_provider_cooldown("openai-sol", future, "usage limit")
            .unwrap();
        let dispatches = schedule_scoped_dispatches(&mut store, Some("CD-IMPL"), None).unwrap();
        assert_eq!(dispatches.len(), 1);
        let updated = store.get_task("CD-IMPL").unwrap().unwrap();
        assert_eq!(updated.status, "In Progress");
        assert!(updated.memory.fallback_stages.contains(&"impl".to_owned()));

        // Now cooldown GeminiAgy too -> a second S/impl task must wait in Ready without path locks.
        store
            .upsert_provider_cooldown("gemini-agy", future, "429 resource exhausted")
            .unwrap();
        let mut blocked_task = make_test_task("CD-BOTH", "repo-b", "S", "Ready", vec![], vec![]);
        blocked_task.memory.governance_started = true;
        store.upsert_task(&blocked_task).unwrap();

        let dispatches2 = schedule_scoped_dispatches(&mut store, Some("CD-BOTH"), None).unwrap();
        assert!(dispatches2.is_empty());
        let still_ready = store.get_task("CD-BOTH").unwrap().unwrap();
        assert_eq!(still_ready.status, "Ready");
        assert!(
            store
                .list_path_locks(None)
                .unwrap()
                .into_iter()
                .all(|l| l.task_id != "CD-BOTH")
        );

        // Review stage cannot fall back: if reviewer family (OpenAiSol when author was GeminiAgy) is cooled down, it waits.
        store.clear_provider_cooldown(Some("gemini-agy")).unwrap();
        let mut review_task =
            make_test_task("CD-REV", "repo-c", "S", "Ready", vec![], vec!["impl"]);
        review_task.memory.governance_started = true;
        store.upsert_task(&review_task).unwrap();
        let mut impl_attempt = crate::v2::store::StageAttemptRecord {
            attempt_id: "att-impl-1".into(),
            task_id: "CD-REV".into(),
            stage: "impl".into(),
            model: "gemini-4-hydrogen-medium".into(),
            effort: "medium".into(),
            systemd_unit: None,
            invocation_id: None,
            started_epoch: 100,
            ended_epoch: Some(200),
            status: "PASSED".into(),
            failure_class: None,
            summary: Some("ok".into()),
            input_tokens: None,
            output_tokens: None,
            total_tokens: None,
            sha_before: None,
            sha_after: None,
            phase: "COMPLETE".into(),
            last_liveness_epoch: 200,
            last_output_bytes: 0,
            last_cpu_usage_usec: None,
            control_group: None,
            exit_code: Some(0),
            exit_code_kind: None,
            retry_generation: 0,
        };
        store.record_stage_attempt(&impl_attempt).unwrap();
        impl_attempt.attempt_id = "att-impl-1".into();

        let rev_dispatches = schedule_scoped_dispatches(&mut store, Some("CD-REV"), None).unwrap();
        assert!(rev_dispatches.is_empty());
        assert_eq!(store.get_task("CD-REV").unwrap().unwrap().status, "Ready");
    }
}
