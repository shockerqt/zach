use crate::v2::intake::default_required_stages;
use crate::v2::now_epoch;
use crate::v2::router::{ModelFamily, StageRoute, resolve_stage_route};
use crate::v2::runner::{
    StageExecutor, SystemdStageExecutor, build_clean_env_from_process, build_systemd_stage_command,
    build_systemd_stage_command_with_env, check_token_budget,
};
use crate::v2::store::{ContextPackSpec, StageAttemptRecord, TaskRecord, V2Store};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffFileEntry {
    pub path: String,
    pub status: String,
    pub added_lines: usize,
    pub deleted_lines: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffCheckOutcome {
    Clean,
    WeightEscalated {
        from_weight: String,
        to_weight: String,
        reason: String,
    },
    ForbiddenPathViolation {
        path: String,
        pattern: String,
    },
    OutOfScopeFiles {
        files: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DryRunStagePlan {
    pub stage: String,
    pub route: Option<StageRoute>,
    pub systemd_unit: Option<String>,
    pub command_preview: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DryRunTaskPlan {
    pub task_id: String,
    pub weight: String,
    pub repository: String,
    pub worktree_path: Option<String>,
    pub remaining_token_budget: u64,
    pub clean_env_keys: Vec<String>,
    pub stages: Vec<DryRunStagePlan>,
}

pub fn weight_rank(weight: &str) -> u8 {
    match weight.trim().to_ascii_uppercase().as_str() {
        "XS" => 1,
        "S" => 2,
        "M" => 3,
        "L" => 4,
        _ => 3,
    }
}

pub fn matches_path_pattern(path: &str, pattern: &str) -> bool {
    let norm_path = path.trim_start_matches("./");
    let norm_pat = pattern.trim_start_matches("./");
    if let Some(prefix) = norm_pat.strip_suffix("/**") {
        norm_path == prefix || norm_path.starts_with(&format!("{prefix}/"))
    } else if let Some(prefix) = norm_pat.strip_suffix("/*") {
        norm_path.starts_with(&format!("{prefix}/"))
    } else {
        norm_path == norm_pat
    }
}

/// Mechanically verifies a worktree diff against `forbidden_paths`, `target_files`,
/// and weight ceilings (`XS -> S -> M -> L`).
pub fn verify_worktree_diff(
    current_weight: &str,
    context_pack: &ContextPackSpec,
    diff_entries: &[DiffFileEntry],
) -> DiffCheckOutcome {
    for entry in diff_entries {
        if matches_path_pattern(&entry.path, ".github/workflows/**") {
            return DiffCheckOutcome::ForbiddenPathViolation {
                path: entry.path.clone(),
                pattern: ".github/workflows/**".to_owned(),
            };
        }
        for pattern in &context_pack.forbidden_paths {
            if matches_path_pattern(&entry.path, pattern) {
                return DiffCheckOutcome::ForbiddenPathViolation {
                    path: entry.path.clone(),
                    pattern: pattern.clone(),
                };
            }
        }
    }

    if !context_pack.target_files.is_empty() {
        let mut out_of_scope = Vec::new();
        for entry in diff_entries {
            let allowed = context_pack
                .target_files
                .iter()
                .any(|tf| matches_path_pattern(&entry.path, &tf.path));
            if !allowed {
                out_of_scope.push(entry.path.clone());
            }
        }
        if !out_of_scope.is_empty() {
            out_of_scope.sort();
            out_of_scope.dedup();
            return DiffCheckOutcome::OutOfScopeFiles {
                files: out_of_scope,
            };
        }
    }

    let total_files = diff_entries.len();
    let total_lines: usize = diff_entries
        .iter()
        .map(|e| e.added_lines + e.deleted_lines)
        .sum();
    let created_files = diff_entries
        .iter()
        .filter(|e| {
            matches!(
                e.status.trim().to_ascii_uppercase().as_str(),
                "A" | "CREATE" | "CREATED"
            )
        })
        .count();

    let touches_critical_l = diff_entries.iter().any(|e| {
        let p = e.path.trim_start_matches("./");
        p.starts_with("infrastructure/") || p.ends_with(".sql")
    });

    let (required_weight, reason) = if touches_critical_l {
        (
            "L",
            "diff touches critical infrastructure or SQL migration path".to_owned(),
        )
    } else if total_files <= 2 && total_lines <= 30 && created_files == 0 {
        ("XS", "within XS ceiling".to_owned())
    } else if total_files <= 4 && total_lines <= 150 && created_files == 0 {
        (
            "S",
            format!(
                "diff ({total_files} files, {total_lines} lines, {created_files} new) exceeds XS ceiling (<=2 files, <=30 lines, 0 new)"
            ),
        )
    } else {
        (
            "M",
            format!(
                "diff ({total_files} files, {total_lines} lines, {created_files} new) exceeds S ceiling (<=4 files, <=150 lines, 0 new)"
            ),
        )
    };

    let norm_current = current_weight.trim().to_ascii_uppercase();
    if weight_rank(required_weight) > weight_rank(&norm_current) {
        return DiffCheckOutcome::WeightEscalated {
            from_weight: norm_current,
            to_weight: required_weight.to_owned(),
            reason,
        };
    }

    DiffCheckOutcome::Clean
}

/// Validates that a `pr-review` markdown output contains a 5-column AC verification
/// table (`| AC | Criterion | Code (file:line) | Test | Status |`) with `PASS` and
/// a `file:line` reference for every expected AC.
pub fn validate_pr_review_table(markdown: &str, expected_ac_ids: &[String]) -> Result<(), String> {
    let mut verified_acs = std::collections::BTreeMap::new();

    for line in markdown.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') || !trimmed.ends_with('|') {
            continue;
        }
        let cols: Vec<&str> = trimmed
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        if cols.len() < 5 {
            continue;
        }
        let ac_id = cols[0];
        if ac_id.eq_ignore_ascii_case("AC") || ac_id.chars().all(|c| c == '-' || c == ':') {
            continue;
        }
        let code_ref = cols[2];
        let test_ref = cols[3];
        let status = cols[4];

        let has_file_line = code_ref.split_once(':').is_some_and(|(file, line_part)| {
            !file.trim().is_empty()
                && line_part
                    .trim_matches('`')
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit())
        });
        if !has_file_line {
            return Err(format!(
                "PR review row for '{ac_id}' is missing a valid file:line reference in column 3 ('{code_ref}')"
            ));
        }
        if test_ref.is_empty() || test_ref == "-" {
            return Err(format!(
                "PR review row for '{ac_id}' is missing test evidence in column 4"
            ));
        }
        if !status.eq_ignore_ascii_case("PASS") {
            return Err(format!(
                "PR review row for '{ac_id}' did not PASS (status='{status}')"
            ));
        }
        verified_acs.insert(ac_id.to_owned(), true);
    }

    if expected_ac_ids.is_empty() {
        if verified_acs.is_empty() {
            return Err("PR review markdown contains no valid PASS rows in AC table".to_owned());
        }
        return Ok(());
    }

    for expected in expected_ac_ids {
        if !verified_acs.contains_key(expected) {
            return Err(format!(
                "PR review table is missing PASS verification row for '{expected}'"
            ));
        }
    }
    Ok(())
}

/// Builds a dry-run execution plan for a task without spawning any worker units.
pub fn plan_task_execution(task: &TaskRecord) -> Result<DryRunTaskPlan, String> {
    let clean_env = build_clean_env_from_process();
    let clean_env_keys: Vec<String> = clean_env.keys().cloned().collect();

    let mut author_family: Option<ModelFamily> = None;
    let mut stages = Vec::new();
    let mut remaining_token_budget = 0u64;

    let stage_list = if task.required_stages.is_empty() {
        default_required_stages(&task.weight)
    } else {
        task.required_stages.clone()
    };

    let mut synthetic_task = task.clone();
    if synthetic_task.worktree_path.is_none() {
        synthetic_task.worktree_path = Some(format!(
            "/home/ubuntu/workspace/{}--{}",
            synthetic_task.repository, synthetic_task.task_id
        ));
    }

    for (idx, stage) in stage_list.iter().enumerate() {
        let route_opt = resolve_stage_route(&task.weight, stage, task.retry_count, author_family)?;
        if let Some(route) = route_opt {
            if matches!(stage.as_str(), "plan" | "impl") {
                author_family = Some(route.family);
            }
            if remaining_token_budget == 0 {
                remaining_token_budget = check_token_budget(task, &route)?;
            }
            let attempt_id = format!("dryrun-{}", idx + 1);
            let spec = build_systemd_stage_command_with_env(
                &synthetic_task,
                &attempt_id,
                &route,
                "<prompt>",
                &clean_env,
            )?;
            let mut preview = vec![spec.program.clone()];
            preview.extend(spec.args.clone());
            stages.push(DryRunStagePlan {
                stage: stage.clone(),
                route: Some(route),
                systemd_unit: Some(spec.unit_name),
                command_preview: preview,
            });
        } else {
            stages.push(DryRunStagePlan {
                stage: stage.clone(),
                route: None,
                systemd_unit: None,
                command_preview: Vec::new(),
            });
        }
    }

    Ok(DryRunTaskPlan {
        task_id: task.task_id.clone(),
        weight: task.weight.clone(),
        repository: task.repository.clone(),
        worktree_path: task.worktree_path.clone(),
        remaining_token_budget,
        clean_env_keys,
        stages,
    })
}

pub fn execute_xs_s_pipeline(store: &mut V2Store, task_id: &str) -> Result<TaskRecord, String> {
    let mut executor = SystemdStageExecutor;
    execute_xs_s_pipeline_with_executor(store, task_id, &mut executor)
}

/// Drives an `XS` or `S` task end-to-end through `impl`, mechanical diff & check gates,
/// cross-model `pr-review` (when `S`), and exact-SHA delivery.
pub fn execute_xs_s_pipeline_with_executor(
    store: &mut V2Store,
    task_id: &str,
    executor: &mut dyn StageExecutor,
) -> Result<TaskRecord, String> {
    let mut task = store
        .get_task(task_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("task '{task_id}' not found in store"))?;

    let initial_weight = task.weight.trim().to_ascii_uppercase();
    if !matches!(initial_weight.as_str(), "XS" | "S") {
        return Err(format!(
            "task {} has weight '{}' (XS/S pipeline only executes XS or S tasks)",
            task.task_id, task.weight
        ));
    }
    if !task.autonomous_consent {
        return Err(format!(
            "task {} does not have autonomous_consent enabled",
            task.task_id
        ));
    }

    let lock_paths: Vec<String> = task
        .context_pack
        .target_files
        .iter()
        .map(|tf| tf.path.clone())
        .collect();
    if !lock_paths.is_empty() {
        let acquired = store
            .acquire_path_locks(&task.repository, &lock_paths, &task.task_id)
            .map_err(|e| e.to_string())?;
        if !acquired {
            return Err(format!(
                "path locks busy for repository '{}' on task {}",
                task.repository, task.task_id
            ));
        }
    }

    if task.worktree_path.is_none() {
        task.worktree_path = Some(format!(
            "/home/ubuntu/workspace/{}--{}",
            task.repository, task.task_id
        ));
    }
    let worktree_path = task.worktree_path.clone().unwrap_or_default();

    // Stage 1: impl
    let impl_route = resolve_stage_route(&task.weight, "impl", task.retry_count, None)?
        .ok_or_else(|| "missing impl route".to_owned())?;
    check_token_budget(&task, &impl_route)?;

    let impl_attempt_id = format!(
        "{}-impl-{}",
        task.task_id.to_ascii_lowercase(),
        task.version
    );
    let impl_prompt = format!(
        "Implement task {} ({}) inside governed worktree {}",
        task.task_id, task.title, worktree_path
    );
    let impl_spec =
        build_systemd_stage_command(&task, &impl_attempt_id, &impl_route, &impl_prompt)?;

    task.status = "In Progress".to_owned();
    task.current_stage = Some("impl".to_owned());
    task.active_attempt_id = Some(impl_attempt_id.clone());
    task.executor = Some(impl_route.model.clone());
    task = store.upsert_task(&task).map_err(|e| e.to_string())?;

    let started_epoch = now_epoch();
    let mut attempt_rec = StageAttemptRecord {
        attempt_id: impl_attempt_id.clone(),
        task_id: task.task_id.clone(),
        stage: "impl".to_owned(),
        model: impl_route.model.clone(),
        effort: impl_route.effort.as_str().to_owned(),
        systemd_unit: Some(impl_spec.unit_name.clone()),
        invocation_id: None,
        started_epoch,
        ended_epoch: None,
        status: "RUNNING".to_owned(),
        failure_class: None,
        summary: None,
        input_tokens: 0,
        output_tokens: 0,
        total_tokens: 0,
        sha_before: None,
        sha_after: None,
    };
    store
        .record_stage_attempt(&attempt_rec)
        .map_err(|e| e.to_string())?;

    let impl_result = executor.execute_stage(&task, &impl_attempt_id, &impl_route, &impl_spec)?;
    attempt_rec.ended_epoch = Some(now_epoch());
    attempt_rec.status = impl_result.status.clone();
    attempt_rec.summary = Some(impl_result.summary.clone());
    attempt_rec.invocation_id = impl_result.invocation_id.clone();
    attempt_rec.input_tokens = impl_result.input_tokens;
    attempt_rec.output_tokens = impl_result.output_tokens;
    attempt_rec.total_tokens = impl_result.total_tokens;
    attempt_rec.sha_before = impl_result.sha_before.clone();
    attempt_rec.sha_after = impl_result.sha_after.clone();
    store
        .record_stage_attempt(&attempt_rec)
        .map_err(|e| e.to_string())?;

    *task
        .memory
        .token_usage_by_stage
        .entry("impl".to_owned())
        .or_insert(0) += impl_result.total_tokens;
    task.memory.recent_attempts.push(format!(
        "[impl:{}] status={} tokens={}",
        impl_attempt_id, impl_result.status, impl_result.total_tokens
    ));

    if impl_result.status != "PASSED" {
        task.retry_count += 1;
        task = store.upsert_task(&task).map_err(|e| e.to_string())?;
        let _ = store.release_path_locks(&task.task_id);
        return Err(format!(
            "impl stage failed for {}: {}",
            task.task_id, impl_result.summary
        ));
    }

    // Mechanical Gate 1: Worktree diff verification (forbidden_paths, target_files, weight ceilings)
    match verify_worktree_diff(&task.weight, &task.context_pack, &impl_result.diff_files) {
        DiffCheckOutcome::Clean => {}
        DiffCheckOutcome::ForbiddenPathViolation { path, pattern } => {
            let dec_id = format!("dec-{}-forbidden", task.task_id.to_ascii_lowercase());
            let _ = store.open_decision(
                &dec_id,
                &task.task_id,
                &task.task_group,
                "scope_violation",
                &format!("Worker modified forbidden path '{path}' (matching '{pattern}')"),
                &[
                    "Revert and cancel".to_owned(),
                    "Inspect worktree".to_owned(),
                ],
                Some(0),
                &impl_result.summary,
                impl_result.sha_after.as_deref(),
            );
            let _ = store.release_path_locks(&task.task_id);
            return Err(format!(
                "forbidden path violation on {}: {} matches {}",
                task.task_id, path, pattern
            ));
        }
        DiffCheckOutcome::OutOfScopeFiles { files } => {
            let dec_id = format!("dec-{}-scope", task.task_id.to_ascii_lowercase());
            let _ = store.open_decision(
                &dec_id,
                &task.task_id,
                &task.task_group,
                "scope_violation",
                &format!("Worker modified files outside target_files: {:?}", files),
                &[
                    "Expand target_files".to_owned(),
                    "Reject attempt".to_owned(),
                ],
                Some(1),
                &impl_result.summary,
                impl_result.sha_after.as_deref(),
            );
            let _ = store.release_path_locks(&task.task_id);
            return Err(format!(
                "out-of-scope files modified on {}: {:?}",
                task.task_id, files
            ));
        }
        DiffCheckOutcome::WeightEscalated {
            from_weight: _,
            to_weight,
            reason,
        } => {
            task.weight = to_weight.clone();
            task.context_pack.weight = to_weight.clone();
            task.required_stages = default_required_stages(&to_weight);
            task.memory
                .decisions_log
                .push(format!("weight escalated to {to_weight}: {reason}"));
            task = store.upsert_task(&task).map_err(|e| e.to_string())?;
            if matches!(to_weight.as_str(), "M" | "L") {
                let _ = store.release_path_locks(&task.task_id);
                return Ok(task);
            }
        }
    }

    // Mechanical Gate 2: worker_checks and gate_checks
    if !task.context_pack.worker_checks.is_empty() {
        executor.run_checks(&worktree_path, &task.context_pack.worker_checks)?;
    }
    if !task.context_pack.gate_checks.is_empty() {
        executor.run_checks(&worktree_path, &task.context_pack.gate_checks)?;
    }

    if !task.stages_completed.iter().any(|s| s == "impl") {
        task.stages_completed.push("impl".to_owned());
    }

    // Stage 2: Cross-model pr-review for weight S
    if task.weight.eq_ignore_ascii_case("S")
        || task.required_stages.iter().any(|s| s == "pr-review")
    {
        let review_route = resolve_stage_route(
            &task.weight,
            "pr-review",
            task.retry_count,
            Some(impl_route.family),
        )?
        .ok_or_else(|| "missing pr-review route".to_owned())?;

        check_token_budget(&task, &review_route)?;

        let rev_attempt_id = format!(
            "{}-pr-review-{}",
            task.task_id.to_ascii_lowercase(),
            task.version
        );
        let rev_prompt = format!(
            "Review implementation of {} ({}) and produce AC verification table",
            task.task_id, task.title
        );
        let rev_spec =
            build_systemd_stage_command(&task, &rev_attempt_id, &review_route, &rev_prompt)?;

        task.status = "PR Review".to_owned();
        task.current_stage = Some("pr-review".to_owned());
        task.active_attempt_id = Some(rev_attempt_id.clone());
        task = store.upsert_task(&task).map_err(|e| e.to_string())?;

        let rev_started = now_epoch();
        let mut rev_attempt = StageAttemptRecord {
            attempt_id: rev_attempt_id.clone(),
            task_id: task.task_id.clone(),
            stage: "pr-review".to_owned(),
            model: review_route.model.clone(),
            effort: review_route.effort.as_str().to_owned(),
            systemd_unit: Some(rev_spec.unit_name.clone()),
            invocation_id: None,
            started_epoch: rev_started,
            ended_epoch: None,
            status: "RUNNING".to_owned(),
            failure_class: None,
            summary: None,
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            sha_before: impl_result.sha_after.clone(),
            sha_after: impl_result.sha_after.clone(),
        };
        store
            .record_stage_attempt(&rev_attempt)
            .map_err(|e| e.to_string())?;

        let rev_result =
            executor.execute_stage(&task, &rev_attempt_id, &review_route, &rev_spec)?;
        rev_attempt.ended_epoch = Some(now_epoch());
        rev_attempt.status = rev_result.status.clone();
        rev_attempt.summary = Some(rev_result.summary.clone());
        rev_attempt.input_tokens = rev_result.input_tokens;
        rev_attempt.output_tokens = rev_result.output_tokens;
        rev_attempt.total_tokens = rev_result.total_tokens;
        store
            .record_stage_attempt(&rev_attempt)
            .map_err(|e| e.to_string())?;

        *task
            .memory
            .token_usage_by_stage
            .entry("pr-review".to_owned())
            .or_insert(0) += rev_result.total_tokens;

        if rev_result.status != "PASSED" {
            let _ = store.release_path_locks(&task.task_id);
            return Err(format!(
                "pr-review stage failed for {}: {}",
                task.task_id, rev_result.summary
            ));
        }

        let expected_acs: Vec<String> = task
            .context_pack
            .acceptance_criteria
            .iter()
            .map(|ac| ac.id.clone())
            .collect();
        let review_md = rev_result
            .review_markdown
            .as_deref()
            .unwrap_or(&rev_result.summary);
        validate_pr_review_table(review_md, &expected_acs)?;

        if !task.stages_completed.iter().any(|s| s == "pr-review") {
            task.stages_completed.push("pr-review".to_owned());
        }
    }

    let reviewed_sha = impl_result
        .sha_after
        .clone()
        .unwrap_or_else(|| "head-sha".to_owned());
    task.reviewed_sha = Some(reviewed_sha.clone());
    if let Some(pr_num) = executor.finalize_xs_s_delivery(&task, &reviewed_sha)? {
        task.pr_number = Some(pr_num);
    }

    task.status = "Done".to_owned();
    task.current_stage = None;
    task.active_attempt_id = None;
    task = store.upsert_task(&task).map_err(|e| e.to_string())?;
    let _ = store.release_path_locks(&task.task_id);

    Ok(task)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::runner::{MockStageExecutor, StageExecutionResult};
    use crate::v2::store::{AcceptanceCriterionSpec, TargetFileSpec, TaskMemory};

    fn sample_context_pack(weight: &str) -> ContextPackSpec {
        ContextPackSpec {
            weight: weight.to_owned(),
            base_sha: Some("abc1234".to_owned()),
            target_files: vec![
                TargetFileSpec {
                    path: "src/v2/router.rs".to_owned(),
                    action: "modify".to_owned(),
                    summary: "Router".to_owned(),
                },
                TargetFileSpec {
                    path: "src/v2/runner.rs".to_owned(),
                    action: "modify".to_owned(),
                    summary: "Runner".to_owned(),
                },
            ],
            forbidden_paths: vec![".github/workflows/**".to_owned()],
            worker_checks: vec!["cargo test".to_owned()],
            gate_checks: vec!["cargo clippy -- -D warnings".to_owned()],
            human_operations: Vec::new(),
            verification_commands: vec!["make test".to_owned()],
            acceptance_criteria: vec![AcceptanceCriterionSpec {
                id: "AC-1".to_owned(),
                description: "Router maps models deterministically".to_owned(),
            }],
        }
    }

    #[test]
    fn verify_worktree_diff_enforces_forbidden_paths_target_files_and_weight_escalation() {
        let pack = sample_context_pack("XS");

        // 1. Forbidden path (.github/workflows/ci.yml)
        let forbidden_diff = vec![DiffFileEntry {
            path: ".github/workflows/ci.yml".to_owned(),
            status: "M".to_owned(),
            added_lines: 2,
            deleted_lines: 1,
        }];
        assert_eq!(
            verify_worktree_diff("XS", &pack, &forbidden_diff),
            DiffCheckOutcome::ForbiddenPathViolation {
                path: ".github/workflows/ci.yml".to_owned(),
                pattern: ".github/workflows/**".to_owned(),
            }
        );

        // 2. Out-of-scope file
        let oos_diff = vec![DiffFileEntry {
            path: "src/other.rs".to_owned(),
            status: "M".to_owned(),
            added_lines: 5,
            deleted_lines: 0,
        }];
        assert_eq!(
            verify_worktree_diff("XS", &pack, &oos_diff),
            DiffCheckOutcome::OutOfScopeFiles {
                files: vec!["src/other.rs".to_owned()],
            }
        );

        // 3. Clean XS diff (<=2 files, <=30 lines, 0 created)
        let clean_xs = vec![DiffFileEntry {
            path: "src/v2/router.rs".to_owned(),
            status: "M".to_owned(),
            added_lines: 15,
            deleted_lines: 5,
        }];
        assert_eq!(
            verify_worktree_diff("XS", &pack, &clean_xs),
            DiffCheckOutcome::Clean
        );

        // 4. XS escalates to S when lines > 30 (e.g. 60 lines in 1 modified file)
        let s_diff = vec![DiffFileEntry {
            path: "src/v2/router.rs".to_owned(),
            status: "M".to_owned(),
            added_lines: 45,
            deleted_lines: 15,
        }];
        match verify_worktree_diff("XS", &pack, &s_diff) {
            DiffCheckOutcome::WeightEscalated {
                from_weight,
                to_weight,
                ..
            } => {
                assert_eq!(from_weight, "XS");
                assert_eq!(to_weight, "S");
            }
            other => panic!("expected WeightEscalated XS -> S, got {other:?}"),
        }

        // 5. S escalates to M when a new file is created ("A")
        let created_diff = vec![DiffFileEntry {
            path: "src/v2/router.rs".to_owned(),
            status: "A".to_owned(),
            added_lines: 20,
            deleted_lines: 0,
        }];
        match verify_worktree_diff("S", &pack, &created_diff) {
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
    fn execute_xs_s_pipeline_drives_s_task_through_impl_and_cross_model_pr_review() {
        let mut store = V2Store::open_in_memory().expect("in-memory store");
        let task = TaskRecord {
            task_id: "ZACH-005".to_owned(),
            task_group: "zach".to_owned(),
            title: "S pipeline test".to_owned(),
            repository: "zach".to_owned(),
            github_repo: Some("shockerqt/zach".to_owned()),
            issue_number: Some(5),
            weight: "S".to_owned(),
            status: "Ready".to_owned(),
            worktree_path: Some("/home/ubuntu/workspace/zach--ZACH-005".to_owned()),
            branch: Some("task/ZACH-005".to_owned()),
            context_pack: sample_context_pack("S"),
            depends_on: Vec::new(),
            required_stages: vec!["impl".to_owned(), "pr-review".to_owned()],
            stages_completed: Vec::new(),
            current_stage: None,
            active_attempt_id: None,
            plan_base_sha: Some("abc1234".to_owned()),
            reviewed_sha: None,
            pr_number: None,
            executor: None,
            autonomous_consent: true,
            retry_count: 0,
            memory: TaskMemory::default(),
            version: 1,
            updated_epoch: 1000,
        };
        store.upsert_task(&task).expect("upsert task");

        let mut mock = MockStageExecutor {
            staged_results: vec![
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Implemented router and runner".to_owned(),
                    review_markdown: None,
                    invocation_id: Some("inv-1".to_owned()),
                    input_tokens: 12_000,
                    output_tokens: 3_000,
                    total_tokens: 15_000,
                    sha_before: Some("abc1234".to_owned()),
                    sha_after: Some("def5678".to_owned()),
                    diff_files: vec![DiffFileEntry {
                        path: "src/v2/router.rs".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 40,
                        deleted_lines: 10,
                    }],
                },
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "PR Review LGTM".to_owned(),
                    review_markdown: Some(
                        "| AC | Criterion | Code (file:line) | Test | Status |\n\
                         |---|---|---|---|---|\n\
                         | AC-1 | Router maps models deterministically | src/v2/router.rs:102 | router::tests::router_enforces_cross_model_review_family_separation_and_retry_escalation | PASS |\n"
                            .to_owned(),
                    ),
                    invocation_id: Some("inv-2".to_owned()),
                    input_tokens: 8_000,
                    output_tokens: 1_500,
                    total_tokens: 9_500,
                    sha_before: Some("def5678".to_owned()),
                    sha_after: Some("def5678".to_owned()),
                    diff_files: Vec::new(),
                },
            ],
            ..MockStageExecutor::default()
        };

        let completed = execute_xs_s_pipeline_with_executor(&mut store, "ZACH-005", &mut mock)
            .expect("pipeline should succeed");

        assert_eq!(completed.status, "Done");
        assert_eq!(completed.reviewed_sha.as_deref(), Some("def5678"));
        assert_eq!(completed.pr_number, Some(42));
        assert_eq!(
            completed.stages_completed,
            vec!["impl".to_owned(), "pr-review".to_owned()]
        );
        assert_eq!(mock.executed_routes.len(), 2);
        // Verify cross-model family separation between impl and pr-review
        assert_eq!(mock.executed_routes[0].family, ModelFamily::OpenAiSol);
        assert_eq!(mock.executed_routes[1].family, ModelFamily::GeminiAgy);
        assert_eq!(mock.finalized_sha.as_deref(), Some("def5678"));
    }
}
