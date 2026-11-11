use crate::v2::intake::default_required_stages;
use crate::v2::now_epoch;
use crate::v2::router::{ModelFamily, ReasoningEffort, StageRoute, resolve_stage_route};
use crate::v2::runner::{
    StageExecutionResult, StageExecutor, SystemdStageExecutor, build_clean_env_from_process,
    build_systemd_stage_command, build_systemd_stage_command_with_env, check_token_budget,
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
    let normalized = if markdown.contains("\\n") {
        markdown.replace("\\n", "\n")
    } else {
        markdown.to_owned()
    };
    let mut verified_acs = std::collections::BTreeMap::new();

    for line in normalized.lines() {
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
        let is_pass = status.eq_ignore_ascii_case("PASS")
            || status.eq_ignore_ascii_case("MET")
            || status.eq_ignore_ascii_case("VERIFIED")
            || status.eq_ignore_ascii_case("OK");
        if !is_pass {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgyCliError {
    pub failure_class: String,
    pub message: String,
}

impl std::fmt::Display for AgyCliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.failure_class, self.message)
    }
}

impl std::error::Error for AgyCliError {}

/// Builds a structured JSON payload for `agent-tooling/plugins/gemini-worker/scripts/worker.mjs --cli`.
pub fn build_agy_cli_payload(
    task: &TaskRecord,
    route: &StageRoute,
    prompt: &str,
) -> serde_json::Value {
    let kind = match route.stage.as_str() {
        "impl" => "implementation",
        "plan-review" | "pr-review" => "review",
        _ => "code_analysis",
    };
    let worktree = task.worktree_path.clone().unwrap_or_default();
    let allowed_files: Vec<String> = task
        .context_pack
        .target_files
        .iter()
        .map(|tf| tf.path.clone())
        .collect();

    serde_json::json!({
        "action": "run",
        "kind": kind,
        "task": prompt,
        "model": route.model,
        "workspace_paths": [worktree],
        "allowed_files": allowed_files,
        "confirmed": true,
        "timeout_seconds": route.timeout_secs,
        "orchestration_id": task.task_id,
    })
}

pub fn build_impl_prompt(task: &TaskRecord, worktree_path: &str) -> String {
    let mut prompt = format!(
        "Implement task {} ({}) inside governed worktree {}.\n",
        task.task_id, task.title, worktree_path
    );
    if !task.context_pack.acceptance_criteria.is_empty() {
        prompt.push_str("\n## Acceptance Criteria:\n");
        for ac in &task.context_pack.acceptance_criteria {
            prompt.push_str(&format!("- {}: {}\n", ac.id, ac.description));
        }
    }
    if !task.context_pack.target_files.is_empty() {
        prompt.push_str("\n## Target Files:\n");
        for tf in &task.context_pack.target_files {
            prompt.push_str(&format!(
                "- {} (action: {}, summary: {})\n",
                tf.path, tf.action, tf.summary
            ));
        }
    }
    if !task.context_pack.verification_commands.is_empty() {
        prompt.push_str("\n## Verification Commands:\n");
        for cmd in &task.context_pack.verification_commands {
            prompt.push_str(&format!("- {}\n", cmd));
        }
    }
    prompt
}

pub fn build_pr_review_prompt(task: &TaskRecord, worktree_path: &str) -> String {
    let mut prompt = format!(
        "Review implementation of task {} ({}) inside worktree {}.\n\
         You MUST inspect the code changes and test execution.\n\
         You MUST output a 5-column markdown table in the exact format:\n\
         | AC | Criterion | Code (file:line) | Test | Status |\n\
         |---|---|---|---|---|\n",
        task.task_id, task.title, worktree_path
    );
    for ac in &task.context_pack.acceptance_criteria {
        prompt.push_str(&format!("Verify AC: {} - {}\n", ac.id, ac.description));
    }
    prompt
}

/// Parses the JSON stdout/stderr produced by `worker.mjs --cli`, mapping infrastructure
/// failures to `AGY_STATUS`, `AGY_EXIT`, `AGY_TIMEOUT`, or `AGY_SPAWN`.
pub fn parse_agy_cli_response(
    stdout: &str,
    stderr: &str,
    exit_code: Option<i32>,
) -> Result<StageExecutionResult, AgyCliError> {
    let Some(code) = exit_code else {
        return Err(AgyCliError {
            failure_class: "AGY_SPAWN".to_owned(),
            message: if stderr.trim().is_empty() {
                "failed to spawn worker.mjs process".to_owned()
            } else {
                stderr.trim().to_owned()
            },
        });
    };

    if stderr.contains("timed out")
        || stderr.contains("TIMEOUT")
        || stderr.contains("RuntimeMaxSec")
        || stdout.contains("TIMEOUT")
    {
        return Err(AgyCliError {
            failure_class: "AGY_TIMEOUT".to_owned(),
            message: format!(
                "worker execution timed out (code={code}): {}",
                stderr.trim()
            ),
        });
    }

    let trimmed_out = stdout.trim();
    if trimmed_out.is_empty() {
        return Err(AgyCliError {
            failure_class: "AGY_EXIT".to_owned(),
            message: format!(
                "worker exited with code {code} and empty stdout: {}",
                stderr.trim()
            ),
        });
    }

    let json: serde_json::Value = match serde_json::from_str(trimmed_out) {
        Ok(v) => v,
        Err(_) => {
            return Err(AgyCliError {
                failure_class: "AGY_EXIT".to_owned(),
                message: format!(
                    "worker exited with code {code} with non-JSON output: {trimmed_out}"
                ),
            });
        }
    };

    let status_str = json.get("status").and_then(|v| v.as_str()).unwrap_or("");
    let exec_succeeded = json
        .get("execution_succeeded")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    if status_str.eq_ignore_ascii_case("error") || !exec_succeeded {
        let err_code = json
            .get("error_code")
            .and_then(|v| v.as_str())
            .unwrap_or("AGY_STATUS_ERROR");
        let summary = json
            .get("summary")
            .or_else(|| json.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or(trimmed_out);
        return Err(AgyCliError {
            failure_class: "AGY_STATUS".to_owned(),
            message: format!("{err_code}: {summary}"),
        });
    }

    let summary = json
        .get("summary")
        .or_else(|| json.get("response"))
        .and_then(|v| v.as_str())
        .unwrap_or("AGY worker completed successfully")
        .to_owned();

    let mut review_markdown = json
        .get("review_markdown")
        .or_else(|| json.get("review"))
        .or_else(|| json.get("review_target"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    if review_markdown.is_none()
        && let Some(resp_str) = json.get("response").and_then(|v| v.as_str())
    {
        if let Ok(inner_json) = serde_json::from_str::<serde_json::Value>(resp_str) {
            if let Some(inner_summary) = inner_json.get("summary").and_then(|v| v.as_str()) {
                review_markdown = Some(inner_summary.to_owned());
            } else if let Some(inner_md) =
                inner_json.get("review_markdown").and_then(|v| v.as_str())
            {
                review_markdown = Some(inner_md.to_owned());
            } else {
                review_markdown = Some(resp_str.to_owned());
            }
        } else {
            review_markdown = Some(resp_str.to_owned());
        }
    }

    if review_markdown.is_none() && summary.contains('|') {
        review_markdown = Some(summary.clone());
    }

    let invocation_id = json
        .get("orchestration_id")
        .or_else(|| json.get("run_id"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    let total_tokens = json
        .get("task_usage")
        .and_then(|u| u.get("total_tokens"))
        .and_then(|v| v.as_u64())
        .or_else(|| json.get("total_tokens").and_then(|v| v.as_u64()))
        .unwrap_or(0);

    let input_tokens = json
        .get("task_usage")
        .and_then(|u| u.get("input_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let output_tokens = json
        .get("task_usage")
        .and_then(|u| u.get("output_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    Ok(StageExecutionResult {
        status: "PASSED".to_owned(),
        summary,
        review_markdown,
        invocation_id,
        input_tokens,
        output_tokens,
        total_tokens,
        sha_before: None,
        sha_after: None,
        diff_files: Vec::new(),
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
    let impl_prompt = build_impl_prompt(&task, &worktree_path);
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
        let rev_prompt = build_pr_review_prompt(&task, &worktree_path);
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

pub fn execute_m_l_pipeline(store: &mut V2Store, task_id: &str) -> Result<TaskRecord, String> {
    let mut executor = SystemdStageExecutor;
    execute_m_l_pipeline_with_executor(store, task_id, &mut executor)
}

/// Drives an `M` or `L` task end-to-end through:
/// - Stage 1: `plan` (read-only, parallel, no path locks)
/// - Stage 2: `plan-review` (read-only, cross-model review of plan)
/// - [For L]: `human-plan-approval` gate (opens `DECISION_REQUIRED`, pauses in `Blocked` until resolved)
/// - Stage 3: `impl` (acquires atomic `path_locks` before impl and holds them)
/// - Stage 4: `pr-review` (cross-model review with 5-column AC verification table)
/// - [For L]: `human-merge-approval` gate (opens `DECISION_REQUIRED`, pauses in `Blocked` until resolved)
/// - Final: Enqueues pull request into per-repo FIFO `merge_queue` (retaining `path_locks`)
///
/// Automatically falls back to `gpt-6.1-sol` after 2 AGY infrastructure failures.
pub fn execute_m_l_pipeline_with_executor(
    store: &mut V2Store,
    task_id: &str,
    executor: &mut dyn StageExecutor,
) -> Result<TaskRecord, String> {
    let mut task = store
        .get_task(task_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("task '{task_id}' not found in store"))?;

    let norm_weight = task.weight.trim().to_ascii_uppercase();
    if !matches!(norm_weight.as_str(), "M" | "L") {
        return Err(format!(
            "task {} has weight '{}' (M/L pipeline only executes M or L tasks)",
            task.task_id, task.weight
        ));
    }
    if !task.autonomous_consent {
        return Err(format!(
            "task {} does not have autonomous_consent enabled",
            task.task_id
        ));
    }

    if task.worktree_path.is_none() {
        task.worktree_path = Some(format!(
            "/home/ubuntu/workspace/{}--{}",
            task.repository, task.task_id
        ));
    }
    let worktree_path = task.worktree_path.clone().unwrap_or_default();

    let count_agy_infra_failures = |t: &TaskRecord| -> usize {
        t.memory
            .recent_attempts
            .iter()
            .filter(|a| {
                a.contains("AGY_STATUS")
                    || a.contains("AGY_EXIT")
                    || a.contains("AGY_TIMEOUT")
                    || a.contains("AGY_SPAWN")
            })
            .count()
    };

    // Stage 1: plan (read-only, no path locks)
    if !task.stages_completed.iter().any(|s| s == "plan")
        && (task.required_stages.is_empty() || task.required_stages.iter().any(|s| s == "plan"))
    {
        let plan_route_initial = resolve_stage_route(&task.weight, "plan", task.retry_count, None)?
            .ok_or_else(|| "missing plan route".to_owned())?;

        let mut plan_route = plan_route_initial;
        if plan_route.family == ModelFamily::GeminiAgy && count_agy_infra_failures(&task) >= 2 {
            plan_route.family = ModelFamily::OpenAiSol;
            plan_route.model = plan_route
                .fallback_model
                .clone()
                .unwrap_or_else(|| "gpt-6.1-sol".to_owned());
            if let Some(effort) = plan_route.fallback_effort {
                plan_route.effort = effort;
            }
        }

        check_token_budget(&task, &plan_route)?;

        let plan_attempt_id = format!(
            "{}-plan-{}",
            task.task_id.to_ascii_lowercase(),
            task.version
        );
        let plan_prompt = format!(
            "Formulate plan for task {} ({}) inside worktree {}",
            task.task_id, task.title, worktree_path
        );
        let plan_spec =
            build_systemd_stage_command(&task, &plan_attempt_id, &plan_route, &plan_prompt)?;

        task.status = "Planning".to_owned();
        task.current_stage = Some("plan".to_owned());
        task.active_attempt_id = Some(plan_attempt_id.clone());
        task.executor = Some(plan_route.model.clone());
        task = store.upsert_task(&task).map_err(|e| e.to_string())?;

        let plan_started = now_epoch();
        let mut plan_rec = StageAttemptRecord {
            attempt_id: plan_attempt_id.clone(),
            task_id: task.task_id.clone(),
            stage: "plan".to_owned(),
            model: plan_route.model.clone(),
            effort: plan_route.effort.as_str().to_owned(),
            systemd_unit: Some(plan_spec.unit_name.clone()),
            invocation_id: None,
            started_epoch: plan_started,
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
            .record_stage_attempt(&plan_rec)
            .map_err(|e| e.to_string())?;

        let mut plan_res = executor.execute_stage(&task, &plan_attempt_id, &plan_route, &plan_spec);

        if plan_route.family == ModelFamily::GeminiAgy {
            let is_infra_err = match &plan_res {
                Err(e) => {
                    let cls = if e.contains("TIMEOUT") {
                        "AGY_TIMEOUT"
                    } else if e.contains("SPAWN") {
                        "AGY_SPAWN"
                    } else if e.contains("EXIT") {
                        "AGY_EXIT"
                    } else {
                        "AGY_STATUS"
                    };
                    Some((cls, e.clone()))
                }
                Ok(res) if res.status != "PASSED" => {
                    let cls = if res.summary.contains("TIMEOUT") {
                        "AGY_TIMEOUT"
                    } else if res.summary.contains("SPAWN") {
                        "AGY_SPAWN"
                    } else if res.summary.contains("EXIT") {
                        "AGY_EXIT"
                    } else {
                        "AGY_STATUS"
                    };
                    Some((cls, res.summary.clone()))
                }
                _ => None,
            };

            if let Some((cls, sum)) = is_infra_err {
                task.memory
                    .recent_attempts
                    .push(format!("[AGY_INFRA:{cls}] {sum}"));
                if count_agy_infra_failures(&task) >= 2 {
                    let fb_route = StageRoute {
                        family: ModelFamily::OpenAiSol,
                        model: "gpt-6.1-sol".to_owned(),
                        effort: ReasoningEffort::High,
                        fallback_family: None,
                        fallback_model: None,
                        fallback_effort: None,
                        ..plan_route.clone()
                    };
                    let fb_attempt_id = format!(
                        "{}-plan-fb-{}",
                        task.task_id.to_ascii_lowercase(),
                        task.version
                    );
                    let fb_spec = build_systemd_stage_command(
                        &task,
                        &fb_attempt_id,
                        &fb_route,
                        &plan_prompt,
                    )?;
                    plan_res = executor.execute_stage(&task, &fb_attempt_id, &fb_route, &fb_spec);
                }
            }
        }

        let plan_result = plan_res?;
        plan_rec.ended_epoch = Some(now_epoch());
        plan_rec.status = plan_result.status.clone();
        plan_rec.summary = Some(plan_result.summary.clone());
        plan_rec.total_tokens = plan_result.total_tokens;
        store
            .record_stage_attempt(&plan_rec)
            .map_err(|e| e.to_string())?;

        *task
            .memory
            .token_usage_by_stage
            .entry("plan".to_owned())
            .or_insert(0) += plan_result.total_tokens;

        if plan_result.status != "PASSED" {
            task.retry_count += 1;
            let _ = store.upsert_task(&task);
            return Err(format!(
                "plan stage failed for {}: {}",
                task.task_id, plan_result.summary
            ));
        }

        task.stages_completed.push("plan".to_owned());
        task = store.upsert_task(&task).map_err(|e| e.to_string())?;
    }

    // Stage 2: plan-review (read-only, cross-model review of plan)
    if !task.stages_completed.iter().any(|s| s == "plan-review")
        && (task.required_stages.is_empty()
            || task.required_stages.iter().any(|s| s == "plan-review"))
    {
        let rev_route_initial = resolve_stage_route(
            &task.weight,
            "plan-review",
            task.retry_count,
            Some(ModelFamily::OpenAiSol),
        )?
        .ok_or_else(|| "missing plan-review route".to_owned())?;

        let mut rev_route = rev_route_initial;
        if rev_route.family == ModelFamily::GeminiAgy && count_agy_infra_failures(&task) >= 2 {
            rev_route.family = ModelFamily::OpenAiSol;
            rev_route.model = rev_route
                .fallback_model
                .clone()
                .unwrap_or_else(|| "gpt-6.1-sol".to_owned());
            if let Some(effort) = rev_route.fallback_effort {
                rev_route.effort = effort;
            }
        }

        check_token_budget(&task, &rev_route)?;

        let rev_attempt_id = format!(
            "{}-plan-review-{}",
            task.task_id.to_ascii_lowercase(),
            task.version
        );
        let rev_prompt = format!(
            "Review architectural plan for {} ({})",
            task.task_id, task.title
        );
        let rev_spec =
            build_systemd_stage_command(&task, &rev_attempt_id, &rev_route, &rev_prompt)?;

        task.status = "Plan Review".to_owned();
        task.current_stage = Some("plan-review".to_owned());
        task.active_attempt_id = Some(rev_attempt_id.clone());
        task.executor = Some(rev_route.model.clone());
        task = store.upsert_task(&task).map_err(|e| e.to_string())?;

        let rev_started = now_epoch();
        let mut rev_rec = StageAttemptRecord {
            attempt_id: rev_attempt_id.clone(),
            task_id: task.task_id.clone(),
            stage: "plan-review".to_owned(),
            model: rev_route.model.clone(),
            effort: rev_route.effort.as_str().to_owned(),
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
            sha_before: None,
            sha_after: None,
        };
        store
            .record_stage_attempt(&rev_rec)
            .map_err(|e| e.to_string())?;

        let mut rev_res = executor.execute_stage(&task, &rev_attempt_id, &rev_route, &rev_spec);

        if rev_route.family == ModelFamily::GeminiAgy {
            let is_infra_err = match &rev_res {
                Err(e) => {
                    let cls = if e.contains("TIMEOUT") {
                        "AGY_TIMEOUT"
                    } else if e.contains("SPAWN") {
                        "AGY_SPAWN"
                    } else if e.contains("EXIT") {
                        "AGY_EXIT"
                    } else {
                        "AGY_STATUS"
                    };
                    Some((cls, e.clone()))
                }
                Ok(res) if res.status != "PASSED" => {
                    let cls = if res.summary.contains("TIMEOUT") {
                        "AGY_TIMEOUT"
                    } else if res.summary.contains("SPAWN") {
                        "AGY_SPAWN"
                    } else if res.summary.contains("EXIT") {
                        "AGY_EXIT"
                    } else {
                        "AGY_STATUS"
                    };
                    Some((cls, res.summary.clone()))
                }
                _ => None,
            };

            if let Some((cls, sum)) = is_infra_err {
                task.memory
                    .recent_attempts
                    .push(format!("[AGY_INFRA:{cls}] {sum}"));
                if count_agy_infra_failures(&task) >= 2 {
                    let fb_route = StageRoute {
                        family: ModelFamily::OpenAiSol,
                        model: "gpt-6.1-sol".to_owned(),
                        effort: ReasoningEffort::High,
                        fallback_family: None,
                        fallback_model: None,
                        fallback_effort: None,
                        ..rev_route.clone()
                    };
                    let fb_attempt_id = format!(
                        "{}-plan-review-fb-{}",
                        task.task_id.to_ascii_lowercase(),
                        task.version
                    );
                    let fb_spec =
                        build_systemd_stage_command(&task, &fb_attempt_id, &fb_route, &rev_prompt)?;
                    rev_res = executor.execute_stage(&task, &fb_attempt_id, &fb_route, &fb_spec);
                }
            }
        }

        let rev_result = rev_res?;
        rev_rec.ended_epoch = Some(now_epoch());
        rev_rec.status = rev_result.status.clone();
        rev_rec.summary = Some(rev_result.summary.clone());
        rev_rec.total_tokens = rev_result.total_tokens;
        store
            .record_stage_attempt(&rev_rec)
            .map_err(|e| e.to_string())?;

        *task
            .memory
            .token_usage_by_stage
            .entry("plan-review".to_owned())
            .or_insert(0) += rev_result.total_tokens;

        if rev_result.status != "PASSED" {
            task.retry_count += 1;
            let _ = store.upsert_task(&task);
            return Err(format!(
                "plan-review stage failed for {}: {}",
                task.task_id, rev_result.summary
            ));
        }

        task.stages_completed.push("plan-review".to_owned());
        task = store.upsert_task(&task).map_err(|e| e.to_string())?;
    }

    // Human Gate 1: human-plan-approval for L tasks
    if norm_weight == "L"
        && !task
            .stages_completed
            .iter()
            .any(|s| s == "human-plan-approval")
    {
        let dec_id = format!("dec-{}-plan-approval", task.task_id.to_ascii_lowercase());
        let existing_dec = store.get_decision(&dec_id).map_err(|e| e.to_string())?;
        match existing_dec {
            None => {
                store.open_decision(
                    &dec_id,
                    &task.task_id,
                    &task.task_group,
                    "plan_approval",
                    &format!("Approve architectural plan for {}?", task.task_id),
                    &[
                        "Approve".to_owned(),
                        "Request Changes".to_owned(),
                        "Reject".to_owned(),
                    ],
                    Some(0),
                    "Plan and plan-review completed. Human approval required before implementation.",
                    task.plan_base_sha.as_deref(),
                ).map_err(|e| e.to_string())?;

                task.status = "Blocked".to_owned();
                task.current_stage = Some("human-plan-approval".to_owned());
                task = store.upsert_task(&task).map_err(|e| e.to_string())?;
                return Ok(task);
            }
            Some(dec) if dec.status == "OPEN" => {
                task.status = "Blocked".to_owned();
                task.current_stage = Some("human-plan-approval".to_owned());
                task = store.upsert_task(&task).map_err(|e| e.to_string())?;
                return Ok(task);
            }
            Some(dec) => {
                let choice = dec.choice.as_deref().unwrap_or("");
                if choice.eq_ignore_ascii_case("Approve") || choice.starts_with("Approve") {
                    task.stages_completed.push("human-plan-approval".to_owned());
                    task.status = "Ready".to_owned();
                    task = store.upsert_task(&task).map_err(|e| e.to_string())?;
                } else {
                    task.status = "Blocked".to_owned();
                    let _ = store.upsert_task(&task);
                    return Err(format!(
                        "plan approval rejected for {}: choice='{choice}'",
                        task.task_id
                    ));
                }
            }
        }
    }

    // Stage 3: impl (Atomic path_locks acquired before impl and held!)
    let mut impl_result_holder = None;
    if !task.stages_completed.iter().any(|s| s == "impl")
        && (task.required_stages.is_empty() || task.required_stages.iter().any(|s| s == "impl"))
    {
        let lock_paths: Vec<String> = if task.context_pack.target_files.is_empty() {
            vec!["*".to_owned()]
        } else {
            task.context_pack
                .target_files
                .iter()
                .map(|tf| tf.path.clone())
                .collect()
        };

        let acquired = store
            .acquire_path_locks(&task.repository, &lock_paths, &task.task_id)
            .map_err(|e| e.to_string())?;
        if !acquired {
            return Err(format!(
                "path locks busy for repository '{}' on task {}",
                task.repository, task.task_id
            ));
        }

        let impl_route_initial = resolve_stage_route(&task.weight, "impl", task.retry_count, None)?
            .ok_or_else(|| "missing impl route".to_owned())?;

        let mut impl_route = impl_route_initial;
        if impl_route.family == ModelFamily::GeminiAgy && count_agy_infra_failures(&task) >= 2 {
            impl_route.family = ModelFamily::OpenAiSol;
            impl_route.model = impl_route
                .fallback_model
                .clone()
                .unwrap_or_else(|| "gpt-6.1-sol".to_owned());
            if let Some(effort) = impl_route.fallback_effort {
                impl_route.effort = effort;
            }
        }

        check_token_budget(&task, &impl_route)?;

        let impl_attempt_id = format!(
            "{}-impl-{}",
            task.task_id.to_ascii_lowercase(),
            task.version
        );
        let impl_prompt = build_impl_prompt(&task, &worktree_path);
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

        let mut impl_res = executor.execute_stage(&task, &impl_attempt_id, &impl_route, &impl_spec);

        if impl_route.family == ModelFamily::GeminiAgy {
            let is_infra_err = match &impl_res {
                Err(e) => {
                    let cls = if e.contains("TIMEOUT") {
                        "AGY_TIMEOUT"
                    } else if e.contains("SPAWN") {
                        "AGY_SPAWN"
                    } else if e.contains("EXIT") {
                        "AGY_EXIT"
                    } else {
                        "AGY_STATUS"
                    };
                    Some((cls, e.clone()))
                }
                Ok(res) if res.status != "PASSED" => {
                    let cls = if res.summary.contains("TIMEOUT") {
                        "AGY_TIMEOUT"
                    } else if res.summary.contains("SPAWN") {
                        "AGY_SPAWN"
                    } else if res.summary.contains("EXIT") {
                        "AGY_EXIT"
                    } else {
                        "AGY_STATUS"
                    };
                    Some((cls, res.summary.clone()))
                }
                _ => None,
            };

            if let Some((cls, sum)) = is_infra_err {
                task.memory
                    .recent_attempts
                    .push(format!("[AGY_INFRA:{cls}] {sum}"));
                if count_agy_infra_failures(&task) >= 2 {
                    let fb_route = StageRoute {
                        family: ModelFamily::OpenAiSol,
                        model: "gpt-6.1-sol".to_owned(),
                        effort: ReasoningEffort::High,
                        fallback_family: None,
                        fallback_model: None,
                        fallback_effort: None,
                        ..impl_route.clone()
                    };
                    let fb_attempt_id = format!(
                        "{}-impl-fb-{}",
                        task.task_id.to_ascii_lowercase(),
                        task.version
                    );
                    let fb_spec = build_systemd_stage_command(
                        &task,
                        &fb_attempt_id,
                        &fb_route,
                        &impl_prompt,
                    )?;
                    impl_res = executor.execute_stage(&task, &fb_attempt_id, &fb_route, &fb_spec);
                }
            }
        }

        let impl_result = impl_res.inspect_err(|_| {
            let _ = store.release_path_locks(&task.task_id);
        })?;

        attempt_rec.ended_epoch = Some(now_epoch());
        attempt_rec.status = impl_result.status.clone();
        attempt_rec.summary = Some(impl_result.summary.clone());
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

        if impl_result.status != "PASSED" {
            task.retry_count += 1;
            let _ = store.upsert_task(&task);
            let _ = store.release_path_locks(&task.task_id);
            return Err(format!(
                "impl stage failed for {}: {}",
                task.task_id, impl_result.summary
            ));
        }

        // Mechanical diff verification
        match verify_worktree_diff(&task.weight, &task.context_pack, &impl_result.diff_files) {
            DiffCheckOutcome::Clean => {}
            DiffCheckOutcome::ForbiddenPathViolation { path, pattern } => {
                let _ = store.release_path_locks(&task.task_id);
                return Err(format!(
                    "forbidden path violation on {}: {} matches {}",
                    task.task_id, path, pattern
                ));
            }
            DiffCheckOutcome::OutOfScopeFiles { files } => {
                let _ = store.release_path_locks(&task.task_id);
                return Err(format!(
                    "out-of-scope files modified on {}: {:?}",
                    task.task_id, files
                ));
            }
            DiffCheckOutcome::WeightEscalated { to_weight, .. } => {
                task.weight = to_weight.clone();
                task.context_pack.weight = to_weight;
            }
        }

        if !task.context_pack.worker_checks.is_empty() {
            executor.run_checks(&worktree_path, &task.context_pack.worker_checks)?;
        }
        if !task.context_pack.gate_checks.is_empty() {
            executor.run_checks(&worktree_path, &task.context_pack.gate_checks)?;
        }

        task.stages_completed.push("impl".to_owned());
        if let Some(ref sha) = impl_result.sha_after {
            task.reviewed_sha = Some(sha.clone());
        }
        task = store.upsert_task(&task).map_err(|e| e.to_string())?;
        impl_result_holder = Some(impl_result);
    }

    // Stage 4: pr-review (Cross-model review, path_locks remain held!)
    if !task.stages_completed.iter().any(|s| s == "pr-review")
        && (task.required_stages.is_empty()
            || task.required_stages.iter().any(|s| s == "pr-review"))
    {
        let rev_route_initial = resolve_stage_route(
            &task.weight,
            "pr-review",
            task.retry_count,
            Some(ModelFamily::OpenAiSol),
        )?
        .ok_or_else(|| "missing pr-review route".to_owned())?;

        let mut rev_route = rev_route_initial;
        if rev_route.family == ModelFamily::GeminiAgy && count_agy_infra_failures(&task) >= 2 {
            rev_route.family = ModelFamily::OpenAiSol;
            rev_route.model = rev_route
                .fallback_model
                .clone()
                .unwrap_or_else(|| "gpt-6.1-sol".to_owned());
            if let Some(effort) = rev_route.fallback_effort {
                rev_route.effort = effort;
            }
        }

        check_token_budget(&task, &rev_route)?;

        let rev_attempt_id = format!(
            "{}-pr-review-{}",
            task.task_id.to_ascii_lowercase(),
            task.version
        );
        let rev_prompt = build_pr_review_prompt(&task, &worktree_path);
        let rev_spec =
            build_systemd_stage_command(&task, &rev_attempt_id, &rev_route, &rev_prompt)?;

        task.status = "PR Review".to_owned();
        task.current_stage = Some("pr-review".to_owned());
        task.active_attempt_id = Some(rev_attempt_id.clone());
        task = store.upsert_task(&task).map_err(|e| e.to_string())?;

        let rev_started = now_epoch();
        let mut rev_rec = StageAttemptRecord {
            attempt_id: rev_attempt_id.clone(),
            task_id: task.task_id.clone(),
            stage: "pr-review".to_owned(),
            model: rev_route.model.clone(),
            effort: rev_route.effort.as_str().to_owned(),
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
            sha_before: task.reviewed_sha.clone(),
            sha_after: task.reviewed_sha.clone(),
        };
        store
            .record_stage_attempt(&rev_rec)
            .map_err(|e| e.to_string())?;

        let mut rev_res = executor.execute_stage(&task, &rev_attempt_id, &rev_route, &rev_spec);

        if rev_route.family == ModelFamily::GeminiAgy {
            let is_infra_err = match &rev_res {
                Err(e) => {
                    let cls = if e.contains("TIMEOUT") {
                        "AGY_TIMEOUT"
                    } else if e.contains("SPAWN") {
                        "AGY_SPAWN"
                    } else if e.contains("EXIT") {
                        "AGY_EXIT"
                    } else {
                        "AGY_STATUS"
                    };
                    Some((cls, e.clone()))
                }
                Ok(res) if res.status != "PASSED" => {
                    let cls = if res.summary.contains("TIMEOUT") {
                        "AGY_TIMEOUT"
                    } else if res.summary.contains("SPAWN") {
                        "AGY_SPAWN"
                    } else if res.summary.contains("EXIT") {
                        "AGY_EXIT"
                    } else {
                        "AGY_STATUS"
                    };
                    Some((cls, res.summary.clone()))
                }
                _ => None,
            };

            if let Some((cls, sum)) = is_infra_err {
                task.memory
                    .recent_attempts
                    .push(format!("[AGY_INFRA:{cls}] {sum}"));
                if count_agy_infra_failures(&task) >= 2 {
                    let fb_route = StageRoute {
                        family: ModelFamily::OpenAiSol,
                        model: "gpt-6.1-sol".to_owned(),
                        effort: ReasoningEffort::High,
                        fallback_family: None,
                        fallback_model: None,
                        fallback_effort: None,
                        ..rev_route.clone()
                    };
                    let fb_attempt_id = format!(
                        "{}-pr-review-fb-{}",
                        task.task_id.to_ascii_lowercase(),
                        task.version
                    );
                    let fb_spec =
                        build_systemd_stage_command(&task, &fb_attempt_id, &fb_route, &rev_prompt)?;
                    rev_res = executor.execute_stage(&task, &fb_attempt_id, &fb_route, &fb_spec);
                }
            }
        }

        let rev_result = rev_res.inspect_err(|_| {
            let _ = store.release_path_locks(&task.task_id);
        })?;

        rev_rec.ended_epoch = Some(now_epoch());
        rev_rec.status = rev_result.status.clone();
        rev_rec.summary = Some(rev_result.summary.clone());
        rev_rec.total_tokens = rev_result.total_tokens;
        store
            .record_stage_attempt(&rev_rec)
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
        if let Err(err) = validate_pr_review_table(review_md, &expected_acs) {
            let _ = store.release_path_locks(&task.task_id);
            return Err(err);
        }

        task.stages_completed.push("pr-review".to_owned());
        task = store.upsert_task(&task).map_err(|e| e.to_string())?;
    }

    // Human Gate 2: human-merge-approval for L tasks
    if norm_weight == "L"
        && !task
            .stages_completed
            .iter()
            .any(|s| s == "human-merge-approval")
    {
        let dec_id = format!("dec-{}-merge-approval", task.task_id.to_ascii_lowercase());
        let existing_dec = store.get_decision(&dec_id).map_err(|e| e.to_string())?;
        match existing_dec {
            None => {
                store.open_decision(
                    &dec_id,
                    &task.task_id,
                    &task.task_group,
                    "merge_approval",
                    &format!("Approve PR merge for {}?", task.task_id),
                    &["Approve".to_owned(), "Reject".to_owned()],
                    Some(0),
                    "PR review passed with verified AC table. Human approval required before merge.",
                    task.reviewed_sha.as_deref(),
                ).map_err(|e| e.to_string())?;

                task.status = "Blocked".to_owned();
                task.current_stage = Some("human-merge-approval".to_owned());
                task = store.upsert_task(&task).map_err(|e| e.to_string())?;
                return Ok(task);
            }
            Some(dec) if dec.status == "OPEN" => {
                task.status = "Blocked".to_owned();
                task.current_stage = Some("human-merge-approval".to_owned());
                task = store.upsert_task(&task).map_err(|e| e.to_string())?;
                return Ok(task);
            }
            Some(dec) => {
                let choice = dec.choice.as_deref().unwrap_or("");
                if choice.eq_ignore_ascii_case("Approve") || choice.starts_with("Approve") {
                    task.stages_completed
                        .push("human-merge-approval".to_owned());
                    task.status = "Ready".to_owned();
                    task = store.upsert_task(&task).map_err(|e| e.to_string())?;
                } else {
                    task.status = "Blocked".to_owned();
                    let _ = store.release_path_locks(&task.task_id);
                    let _ = store.upsert_task(&task);
                    return Err(format!(
                        "merge approval rejected for {}: choice='{choice}'",
                        task.task_id
                    ));
                }
            }
        }
    }

    // Step 5: Enqueue into FIFO merge queue (path locks remain held until merge completes!)
    let reviewed_sha = task
        .reviewed_sha
        .clone()
        .or_else(|| impl_result_holder.and_then(|r| r.sha_after))
        .unwrap_or_else(|| "head-sha".to_owned());
    task.reviewed_sha = Some(reviewed_sha.clone());

    let pr_number = if let Some(pr) = task.pr_number {
        pr
    } else if let Some(pr) = executor.finalize_xs_s_delivery(&task, &reviewed_sha)? {
        task.pr_number = Some(pr);
        pr
    } else {
        1
    };

    crate::v2::merge_queue::enqueue_for_merge(
        store,
        &task.repository,
        &task.task_id,
        pr_number,
        &reviewed_sha,
    )?;

    task.status = "Queued for Merge".to_owned();
    task.current_stage = Some("merge_queue".to_owned());
    task = store.upsert_task(&task).map_err(|e| e.to_string())?;

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

    #[test]
    fn execute_m_l_pipeline_drives_m_task_through_4_steps_and_enqueues_for_merge() {
        let mut store = V2Store::open_in_memory().expect("open in-memory store");
        let task = TaskRecord {
            task_id: "ZACH-006".to_owned(),
            task_group: "zach".to_owned(),
            title: "M pipeline test".to_owned(),
            repository: "zach".to_owned(),
            github_repo: Some("shockerqt/zach".to_owned()),
            issue_number: Some(6),
            weight: "M".to_owned(),
            status: "Ready".to_owned(),
            worktree_path: Some("/home/ubuntu/workspace/zach--ZACH-006".to_owned()),
            branch: Some("task/ZACH-006".to_owned()),
            context_pack: sample_context_pack("M"),
            depends_on: Vec::new(),
            required_stages: vec![
                "plan".to_owned(),
                "plan-review".to_owned(),
                "impl".to_owned(),
                "pr-review".to_owned(),
            ],
            stages_completed: Vec::new(),
            current_stage: None,
            active_attempt_id: None,
            plan_base_sha: Some("base123".to_owned()),
            reviewed_sha: None,
            pr_number: None,
            executor: None,
            autonomous_consent: true,
            retry_count: 0,
            memory: TaskMemory::default(),
            version: 1,
            updated_epoch: 1000,
        };
        store.upsert_task(&task).unwrap();

        let mut mock = MockStageExecutor {
            staged_results: vec![
                // 1. plan
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Architectural plan generated".to_owned(),
                    review_markdown: None,
                    invocation_id: Some("inv-plan".to_owned()),
                    input_tokens: 10_000,
                    output_tokens: 2_000,
                    total_tokens: 12_000,
                    sha_before: None,
                    sha_after: None,
                    diff_files: Vec::new(),
                },
                // 2. plan-review
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Plan review approved".to_owned(),
                    review_markdown: None,
                    invocation_id: Some("inv-plan-review".to_owned()),
                    input_tokens: 8_000,
                    output_tokens: 1_000,
                    total_tokens: 9_000,
                    sha_before: None,
                    sha_after: None,
                    diff_files: Vec::new(),
                },
                // 3. impl
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Implementation complete".to_owned(),
                    review_markdown: None,
                    invocation_id: Some("inv-impl".to_owned()),
                    input_tokens: 15_000,
                    output_tokens: 3_000,
                    total_tokens: 18_000,
                    sha_before: Some("base123".to_owned()),
                    sha_after: Some("sha-m-impl".to_owned()),
                    diff_files: vec![DiffFileEntry {
                        path: "src/v2/router.rs".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 10,
                        deleted_lines: 2,
                    }],
                },
                // 4. pr-review
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "PR review verified".to_owned(),
                    review_markdown: Some(
                        "| AC | Criterion | Code (file:line) | Test | Status |\n\
                         |---|---|---|---|---|\n\
                         | AC-1 | Router maps models deterministically | src/v2/router.rs:102 | router::tests::router_enforces_cross_model_review_family_separation_and_retry_escalation | PASS |\n"
                            .to_owned(),
                    ),
                    invocation_id: Some("inv-pr-rev".to_owned()),
                    input_tokens: 12_000,
                    output_tokens: 2_000,
                    total_tokens: 14_000,
                    sha_before: Some("sha-m-impl".to_owned()),
                    sha_after: Some("sha-m-impl".to_owned()),
                    diff_files: Vec::new(),
                },
            ],
            ..MockStageExecutor::default()
        };

        let result = execute_m_l_pipeline_with_executor(&mut store, "ZACH-006", &mut mock)
            .expect("M pipeline should execute and enqueue");

        // Verify task state
        assert_eq!(result.status, "Queued for Merge");
        assert_eq!(result.current_stage.as_deref(), Some("merge_queue"));
        assert_eq!(
            result.stages_completed,
            vec!["plan", "plan-review", "impl", "pr-review"]
        );

        // Verify merge queue entry
        let mq = store.list_merge_queue(Some("zach")).unwrap();
        assert_eq!(mq.len(), 1);
        assert_eq!(mq[0].task_id, "ZACH-006");
        assert_eq!(mq[0].reviewed_sha, "sha-m-impl");
        assert_eq!(mq[0].state, "QUEUED");

        // Verify path locks remain held for merge queue!
        let locks = store.list_path_locks(Some("zach")).unwrap();
        assert_eq!(locks.len(), 2);
    }

    #[test]
    fn execute_m_l_pipeline_pauses_at_human_gates_for_l_task_and_resumes() {
        let mut store = V2Store::open_in_memory().expect("open in-memory store");
        let task = TaskRecord {
            task_id: "ZACH-007-L".to_owned(),
            task_group: "zach".to_owned(),
            title: "L pipeline human gates".to_owned(),
            repository: "zach".to_owned(),
            github_repo: Some("shockerqt/zach".to_owned()),
            issue_number: Some(7),
            weight: "L".to_owned(),
            status: "Ready".to_owned(),
            worktree_path: Some("/home/ubuntu/workspace/zach--ZACH-007-L".to_owned()),
            branch: Some("task/ZACH-007-L".to_owned()),
            context_pack: sample_context_pack("L"),
            depends_on: Vec::new(),
            required_stages: vec![
                "plan".to_owned(),
                "plan-review".to_owned(),
                "human-plan-approval".to_owned(),
                "impl".to_owned(),
                "pr-review".to_owned(),
                "human-merge-approval".to_owned(),
            ],
            stages_completed: Vec::new(),
            current_stage: None,
            active_attempt_id: None,
            plan_base_sha: Some("base-l".to_owned()),
            reviewed_sha: None,
            pr_number: None,
            executor: None,
            autonomous_consent: true,
            retry_count: 0,
            memory: TaskMemory::default(),
            version: 1,
            updated_epoch: 1000,
        };
        store.upsert_task(&task).unwrap();

        let mut mock = MockStageExecutor {
            staged_results: vec![
                // 1. plan
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "L Plan".to_owned(),
                    review_markdown: None,
                    invocation_id: None,
                    input_tokens: 1_000,
                    output_tokens: 500,
                    total_tokens: 1_500,
                    sha_before: None,
                    sha_after: None,
                    diff_files: Vec::new(),
                },
                // 2. plan-review
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "L Plan Review".to_owned(),
                    review_markdown: None,
                    invocation_id: None,
                    input_tokens: 1_000,
                    output_tokens: 500,
                    total_tokens: 1_500,
                    sha_before: None,
                    sha_after: None,
                    diff_files: Vec::new(),
                },
            ],
            ..MockStageExecutor::default()
        };

        // Run 1: Should execute plan -> plan-review -> pause at human-plan-approval
        let paused_1 =
            execute_m_l_pipeline_with_executor(&mut store, "ZACH-007-L", &mut mock).unwrap();
        assert_eq!(paused_1.status, "Blocked");
        assert_eq!(
            paused_1.current_stage.as_deref(),
            Some("human-plan-approval")
        );

        // Verify DECISION_REQUIRED was opened
        let decs = store.list_decisions(true, None).unwrap();
        assert_eq!(decs.len(), 1);
        assert_eq!(decs[0].kind, "plan_approval");
        let dec_id = decs[0].decision_id.clone();

        // Human resolves the decision
        store
            .resolve_decision(&dec_id, "Approve", "lead-architect", Some("Plan approved"))
            .unwrap();

        // Stage next results for impl and pr-review
        mock.staged_results.push(StageExecutionResult {
            status: "PASSED".to_owned(),
            summary: "L Impl".to_owned(),
            review_markdown: None,
            invocation_id: None,
            input_tokens: 5_000,
            output_tokens: 1_000,
            total_tokens: 6_000,
            sha_before: Some("base-l".to_owned()),
            sha_after: Some("sha-l-impl".to_owned()),
            diff_files: vec![DiffFileEntry {
                path: "src/v2/router.rs".to_owned(),
                status: "M".to_owned(),
                added_lines: 5,
                deleted_lines: 1,
            }],
        });
        mock.staged_results.push(StageExecutionResult {
            status: "PASSED".to_owned(),
            summary: "L PR Review".to_owned(),
            review_markdown: Some(
                "| AC | Criterion | Code (file:line) | Test | Status |\n\
                 |---|---|---|---|---|\n\
                 | AC-1 | Router maps models deterministically | src/v2/router.rs:102 | test:1 | PASS |\n"
                    .to_owned(),
            ),
            invocation_id: None,
            input_tokens: 5_000,
            output_tokens: 1_000,
            total_tokens: 6_000,
            sha_before: Some("sha-l-impl".to_owned()),
            sha_after: Some("sha-l-impl".to_owned()),
            diff_files: Vec::new(),
        });

        // Run 2: Resumes -> executes impl -> pr-review -> pauses at human-merge-approval
        let paused_2 =
            execute_m_l_pipeline_with_executor(&mut store, "ZACH-007-L", &mut mock).unwrap();
        assert_eq!(paused_2.status, "Blocked");
        assert_eq!(
            paused_2.current_stage.as_deref(),
            Some("human-merge-approval")
        );

        // Verify DECISION_REQUIRED for merge_approval was opened
        let open_decs = store.list_decisions(true, None).unwrap();
        assert_eq!(open_decs.len(), 1);
        assert_eq!(open_decs[0].kind, "merge_approval");
        let merge_dec_id = open_decs[0].decision_id.clone();

        // Path locks are STILL HELD during human merge approval gate!
        assert!(!store.list_path_locks(Some("zach")).unwrap().is_empty());

        // Human approves merge
        store
            .resolve_decision(
                &merge_dec_id,
                "Approve",
                "lead-maintainer",
                Some("Merge approved"),
            )
            .unwrap();

        // Run 3: Resumes and enqueues into merge_queue!
        let completed =
            execute_m_l_pipeline_with_executor(&mut store, "ZACH-007-L", &mut mock).unwrap();
        assert_eq!(completed.status, "Queued for Merge");
        assert_eq!(completed.current_stage.as_deref(), Some("merge_queue"));

        // Verify it was enqueued
        let mq = store.list_merge_queue(Some("zach")).unwrap();
        assert_eq!(mq.len(), 1);
        assert_eq!(mq[0].task_id, "ZACH-007-L");
    }

    #[test]
    fn agy_cli_payload_parsing_and_automatic_fallback_after_2_infra_failures() {
        let pack = sample_context_pack("M");
        let task = TaskRecord {
            task_id: "ZACH-008".to_owned(),
            task_group: "zach".to_owned(),
            title: "AGY CLI integration".to_owned(),
            repository: "zach".to_owned(),
            github_repo: Some("shockerqt/zach".to_owned()),
            issue_number: Some(8),
            weight: "M".to_owned(),
            status: "Ready".to_owned(),
            worktree_path: Some("/home/ubuntu/workspace/zach--ZACH-008".to_owned()),
            branch: Some("task/ZACH-008".to_owned()),
            context_pack: pack,
            depends_on: Vec::new(),
            required_stages: vec!["plan".to_owned()],
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
        };

        // 1. Test build_agy_cli_payload
        let route = StageRoute {
            weight: "M".to_owned(),
            stage: "plan".to_owned(),
            family: ModelFamily::GeminiAgy,
            model: "gemini-4-argon-high".to_owned(),
            effort: ReasoningEffort::High,
            fallback_family: Some(ModelFamily::OpenAiSol),
            fallback_model: Some("gpt-6.1-sol".to_owned()),
            fallback_effort: Some(ReasoningEffort::High),
            max_task_tokens: 1_200_000,
            timeout_secs: 1200,
            stall_timeout_secs: 600,
        };
        let payload = build_agy_cli_payload(&task, &route, "Generate architecture plan");
        assert_eq!(payload["action"], "run");
        assert_eq!(payload["kind"], "code_analysis");
        assert_eq!(payload["confirmed"], true);
        assert_eq!(payload["model"], "gemini-4-argon-high");
        assert_eq!(payload["timeout_seconds"], 1200);

        // 2. Test parse_agy_cli_response: success
        let ok_json = r#"{"execution_succeeded":true,"summary":"Analysis complete","task_usage":{"total_tokens":5432}}"#;
        let ok_res = parse_agy_cli_response(ok_json, "", Some(0)).unwrap();
        assert_eq!(ok_res.status, "PASSED");
        assert_eq!(ok_res.total_tokens, 5432);

        // 3. Test parse_agy_cli_response: failures
        // AGY_SPAWN
        let spawn_err = parse_agy_cli_response("", "spawn ENOENT", None).unwrap_err();
        assert_eq!(spawn_err.failure_class, "AGY_SPAWN");

        // AGY_TIMEOUT
        let timeout_err =
            parse_agy_cli_response("", "systemd unit timed out RuntimeMaxSec", Some(124))
                .unwrap_err();
        assert_eq!(timeout_err.failure_class, "AGY_TIMEOUT");

        // AGY_EXIT
        let exit_err = parse_agy_cli_response("", "node process crashed", Some(1)).unwrap_err();
        assert_eq!(exit_err.failure_class, "AGY_EXIT");

        // AGY_STATUS
        let status_json =
            r#"{"status":"error","error_code":"PROCESS_FAILED","summary":"Worker crashed"}"#;
        let status_err = parse_agy_cli_response(status_json, "", Some(1)).unwrap_err();
        assert_eq!(status_err.failure_class, "AGY_STATUS");

        // 4. Test automatic fallback to gpt-6.1-sol after 2 AGY infrastructure failures
        let mut store = V2Store::open_in_memory().expect("open store");
        let mut agy_task = task.clone();
        // Pre-populate 2 AGY infra failures in task memory
        agy_task
            .memory
            .recent_attempts
            .push("[AGY_INFRA:AGY_TIMEOUT] attempt 1 timed out".to_owned());
        agy_task
            .memory
            .recent_attempts
            .push("[AGY_INFRA:AGY_STATUS] attempt 2 provider error".to_owned());
        store.upsert_task(&agy_task).unwrap();

        let mut mock = MockStageExecutor {
            staged_results: vec![StageExecutionResult {
                status: "PASSED".to_owned(),
                summary: "Fallback succeeded".to_owned(),
                review_markdown: None,
                invocation_id: None,
                input_tokens: 1_000,
                output_tokens: 500,
                total_tokens: 1_500,
                sha_before: None,
                sha_after: None,
                diff_files: Vec::new(),
            }],
            ..MockStageExecutor::default()
        };

        let completed =
            execute_m_l_pipeline_with_executor(&mut store, "ZACH-008", &mut mock).unwrap();
        assert!(completed.stages_completed.contains(&"plan".to_owned()));

        // Verify that route was automatically switched to OpenAiSol (gpt-6.1-sol) instead of GeminiAgy
        assert_eq!(mock.executed_routes.len(), 1);
        assert_eq!(mock.executed_routes[0].family, ModelFamily::OpenAiSol);
        assert_eq!(mock.executed_routes[0].model, "gpt-6.1-sol");
    }

    #[test]
    fn validate_pr_review_table_accepts_met_and_verified() {
        let md = "\
| AC | Criterion | Code (file:line) | Test | Status |
|---|---|---|---|---|
| AC-1 | Feature works | src/lib.rs:10 | cargo test | Met |
| AC-2 | API works | src/api.rs:20 | cargo test | Verified |
";
        let expected = vec!["AC-1".to_owned(), "AC-2".to_owned()];
        assert!(validate_pr_review_table(md, &expected).is_ok());
    }

    #[test]
    fn validate_pr_review_table_handles_escaped_newlines() {
        let escaped = "Summary\\n\\n| AC | Criterion | Code (file:line) | Test | Status |\\n|---|---|---|---|---|\\n| AC-1 | Feature works | src/lib.rs:10 | cargo test | PASS |\\n";
        let expected = vec!["AC-1".to_owned()];
        assert!(validate_pr_review_table(escaped, &expected).is_ok());
    }
}
