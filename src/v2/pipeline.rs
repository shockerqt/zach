use crate::v2::default_ws_task_bin;
use crate::v2::intake::default_required_stages;
use crate::v2::now_epoch;
use crate::v2::router::{
    ModelFamily, ReasoningEffort, StageRoute, infer_model_family,
    is_no_cross_family_reviewer_error, resolve_stage_route,
};
use crate::v2::runner::{
    MAX_RECENT_ATTEMPT_BYTES, MAX_SUMMARY_BYTES, ReviewedDiffContext, StageExecutionResult,
    StageExecutor, SystemdStageExecutor, build_clean_env_from_process, build_systemd_stage_command,
    build_systemd_stage_command_with_env, check_token_budget, normalize_cited_diff_path,
    truncate_utf8_bytes,
};
use crate::v2::store::{ContextPackSpec, StageAttemptRecord, TaskRecord, V2Store};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

pub const MAX_APPROVED_PLAN_BYTES: usize = 2048;
pub const MAX_REVIEW_REWORK_LOOPS: u32 = 2;
pub const MAX_WORKER_PROMPT_CHARS: usize = 18_000;
pub const MAX_PLAN_REWORK_CYCLES: u32 = 2;

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
        required_stages: Vec<String>,
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

#[derive(Debug, Clone, Deserialize)]
struct ClassifyWeightOutput {
    effective_weight: String,
    #[serde(default)]
    escalated: bool,
    #[serde(default)]
    required_stages: Vec<String>,
    #[serde(default)]
    reasons: Vec<String>,
}

const LOCKFILE_SUFFIXES: [&str; 4] = [
    "Cargo.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
];
const TEST_DOC_DIR_NAMES: [&str; 5] = ["test", "tests", "__tests__", "doc", "docs"];
const DOC_EXTENSIONS: [&str; 5] = [".md", ".mdx", ".txt", ".rst", ".adoc"];

fn is_lockfile_path(path: &str) -> bool {
    LOCKFILE_SUFFIXES.iter().any(|lock| path.ends_with(lock))
}

fn is_test_or_doc_path(path: &str) -> bool {
    let norm = path
        .replace('\\', "/")
        .trim_matches('/')
        .to_ascii_lowercase();
    if norm.is_empty() {
        return false;
    }
    let parts: Vec<&str> = norm
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let Some((&base, dir_parts)) = parts.split_last() else {
        return false;
    };
    if dir_parts
        .iter()
        .any(|part| TEST_DOC_DIR_NAMES.contains(part))
    {
        return true;
    }
    if DOC_EXTENSIONS
        .iter()
        .any(|ext| base.ends_with(ext) && base.len() > ext.len())
    {
        return true;
    }
    base.contains(".test.")
        || base.contains(".spec.")
        || base.contains("_test.")
        || (base.starts_with("test_") && base["test_".len()..].contains('.'))
        || base.starts_with("tests.")
        || base.starts_with("test.")
        || base.contains("selftest")
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
        _ => 0,
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
/// and Governance weight floor rules by delegating classification to `ws-task classify-weight`.
pub fn verify_worktree_diff(
    repository: &str,
    current_weight: &str,
    context_pack: &ContextPackSpec,
    diff_entries: &[DiffFileEntry],
) -> Result<DiffCheckOutcome, String> {
    verify_worktree_diff_with(
        repository,
        current_weight,
        context_pack,
        diff_entries,
        &default_ws_task_bin(),
    )
}

/// Injectable variant of [`verify_worktree_diff`] accepting an explicit `ws-task` binary path.
pub fn verify_worktree_diff_with(
    repository: &str,
    current_weight: &str,
    context_pack: &ContextPackSpec,
    diff_entries: &[DiffFileEntry],
    ws_task_bin: &Path,
) -> Result<DiffCheckOutcome, String> {
    for entry in diff_entries {
        for pattern in &context_pack.forbidden_paths {
            if matches_path_pattern(&entry.path, pattern) {
                return Ok(DiffCheckOutcome::ForbiddenPathViolation {
                    path: entry.path.clone(),
                    pattern: pattern.clone(),
                });
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
            return Ok(DiffCheckOutcome::OutOfScopeFiles {
                files: out_of_scope,
            });
        }
    }

    let mut all_paths = Vec::with_capacity(diff_entries.len());
    let mut diff_lines = 0usize;
    let mut new_files = 0usize;
    for entry in diff_entries {
        let trimmed_path = entry.path.trim();
        if !trimmed_path.is_empty() {
            all_paths.push(trimmed_path.to_owned());
        }
        if is_lockfile_path(trimmed_path) || is_test_or_doc_path(trimmed_path) {
            continue;
        }
        diff_lines = diff_lines.saturating_add(entry.added_lines + entry.deleted_lines);
        if matches!(
            entry.status.trim().to_ascii_uppercase().as_str(),
            "A" | "CREATE" | "CREATED"
        ) {
            new_files = new_files.saturating_add(1);
        }
    }
    let paths_arg = all_paths.join(",");

    let norm_current = current_weight.trim().to_ascii_uppercase();
    let mut cmd = Command::new(ws_task_bin);
    cmd.arg("classify-weight")
        .arg("--repo")
        .arg(repository)
        .arg(format!("--paths={paths_arg}"))
        .arg("--diff-lines")
        .arg(diff_lines.to_string())
        .arg("--new-files")
        .arg(new_files.to_string());
    if !norm_current.is_empty() {
        cmd.arg("--requested").arg(&norm_current);
    }
    let output = cmd.output().map_err(|e| {
        format!(
            "failed to invoke {} classify-weight: {e}",
            ws_task_bin.display()
        )
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "ws-task classify-weight exited with {}: {}",
            output.status,
            stderr.trim()
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| format!("ws-task classify-weight stdout was not valid UTF-8: {e}"))?;
    let response: ClassifyWeightOutput = serde_json::from_str(&stdout)
        .map_err(|e| format!("failed to parse ws-task classify-weight JSON: {e}"))?;

    let effective = response.effective_weight.trim().to_ascii_uppercase();
    if !matches!(effective.as_str(), "XS" | "S" | "M" | "L") {
        return Err(format!(
            "ws-task classify-weight returned invalid effective_weight '{}'",
            response.effective_weight
        ));
    }

    if response.escalated || weight_rank(&effective) > weight_rank(&norm_current) {
        let reason = if response.reasons.is_empty() {
            format!("escalated by ws-task classify-weight to {effective}")
        } else {
            response.reasons.join("; ")
        };
        return Ok(DiffCheckOutcome::WeightEscalated {
            from_weight: norm_current,
            to_weight: effective,
            required_stages: response.required_stages,
            reason,
        });
    }

    Ok(DiffCheckOutcome::Clean)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcResultEntry {
    pub id: String,
    pub status: String,
    pub file: String,
    pub line: usize,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewFindingEntry {
    pub severity: String,
    pub file: String,
    pub line: usize,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewVerdict {
    pub verdict: String,
    pub ac_results: Vec<AcResultEntry>,
    pub findings: Vec<ReviewFindingEntry>,
    pub summary: String,
}

/// Returns the strict JSON Schema enforced on `pr-review` verdicts.
pub fn review_verdict_json_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["verdict", "ac_results", "findings", "summary"],
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["APPROVED", "CHANGES_REQUESTED"]
            },
            "ac_results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["id", "status", "file", "line", "evidence"],
                    "properties": {
                        "id": { "type": "string", "minLength": 1 },
                        "status": { "type": "string", "enum": ["PASS", "FAIL"] },
                        "file": { "type": "string", "minLength": 1 },
                        "line": { "type": "integer", "minimum": 1 },
                        "evidence": { "type": "string", "minLength": 1 }
                    }
                }
            },
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["severity", "file", "line", "summary"],
                    "properties": {
                        "severity": { "type": "string", "enum": ["blocking", "non_blocking"] },
                        "file": { "type": "string", "minLength": 1 },
                        "line": { "type": "integer", "minimum": 1 },
                        "summary": { "type": "string", "minLength": 1 }
                    }
                }
            },
            "summary": { "type": "string", "minLength": 1 }
        }
    })
}

pub fn review_verdict_json_schema_string() -> String {
    serde_json::to_string_pretty(&review_verdict_json_schema()).unwrap_or_default()
}

fn verify_cited_diff_location(
    file: &str,
    line: usize,
    context_label: &str,
    reviewed_diff: &ReviewedDiffContext,
    worktree_path: &str,
) -> Result<(), String> {
    if line < 1 {
        return Err(format!(
            "PR review {context_label} cites invalid line {line} (< 1) in '{file}'"
        ));
    }
    let norm_path = normalize_cited_diff_path(file, worktree_path)
        .map_err(|e| format!("PR review {context_label} has invalid path: {e}"))?;
    let Some(ranges) = reviewed_diff.files.get(&norm_path) else {
        return Err(format!(
            "PR review {context_label} cites '{norm_path}:{line}' which is not in reviewed diff {}",
            reviewed_diff.commit_range
        ));
    };
    if !ranges.iter().any(|r| r.contains(line)) {
        return Err(format!(
            "PR review {context_label} cites '{norm_path}:{line}' which is outside reviewed diff hunks in {}",
            reviewed_diff.commit_range
        ));
    }
    Ok(())
}

/// Strictly validates a `pr-review` JSON verdict against [`ReviewVerdict`],
/// acceptance criterion coverage, consistency rules, and real diff hunk ranges.
/// Free-form markdown is never parsed.
pub fn validate_review_verdict(
    raw_json: &str,
    expected_ac_ids: &[String],
    reviewed_diff: &ReviewedDiffContext,
    worktree_path: &str,
) -> Result<ReviewVerdict, String> {
    let trimmed = raw_json.trim();
    if trimmed.is_empty() {
        return Err("PR review verdict is empty (expected strict ReviewVerdict JSON)".to_owned());
    }
    let verdict: ReviewVerdict = serde_json::from_str(trimmed).map_err(|e| {
        format!("PR review verdict failed ReviewVerdict JSON schema validation: {e}")
    })?;

    if !matches!(verdict.verdict.as_str(), "APPROVED" | "CHANGES_REQUESTED") {
        return Err(format!(
            "PR review verdict has invalid verdict '{}' (expected APPROVED or CHANGES_REQUESTED)",
            verdict.verdict
        ));
    }
    if verdict.summary.trim().is_empty() {
        return Err("PR review verdict summary must be non-empty".to_owned());
    }

    let mut seen_ac_ids = BTreeSet::new();
    for ac in &verdict.ac_results {
        let ac_id = ac.id.trim();
        if ac_id.is_empty() {
            return Err("PR review ac_results entry has empty id".to_owned());
        }
        if !seen_ac_ids.insert(ac_id.to_owned()) {
            return Err(format!(
                "PR review ac_results contains duplicate id '{ac_id}'"
            ));
        }
        if !matches!(ac.status.as_str(), "PASS" | "FAIL") {
            return Err(format!(
                "PR review ac_results '{ac_id}' has invalid status '{}' (expected PASS or FAIL)",
                ac.status
            ));
        }
        if ac.file.trim().is_empty() {
            return Err(format!("PR review ac_results '{ac_id}' has empty file"));
        }
        if ac.evidence.trim().is_empty() {
            return Err(format!("PR review ac_results '{ac_id}' has empty evidence"));
        }
        verify_cited_diff_location(
            &ac.file,
            ac.line,
            &format!("AC '{ac_id}'"),
            reviewed_diff,
            worktree_path,
        )?;
    }

    for expected in expected_ac_ids {
        if !seen_ac_ids.contains(expected.trim()) {
            return Err(format!(
                "PR review verdict is missing ac_results entry for '{expected}'"
            ));
        }
    }

    for (idx, finding) in verdict.findings.iter().enumerate() {
        if !matches!(finding.severity.as_str(), "blocking" | "non_blocking") {
            return Err(format!(
                "PR review finding[{idx}] has invalid severity '{}' (expected blocking or non_blocking)",
                finding.severity
            ));
        }
        if finding.file.trim().is_empty() {
            return Err(format!("PR review finding[{idx}] has empty file"));
        }
        if finding.summary.trim().is_empty() {
            return Err(format!("PR review finding[{idx}] has empty summary"));
        }
        verify_cited_diff_location(
            &finding.file,
            finding.line,
            &format!("finding[{idx}]"),
            reviewed_diff,
            worktree_path,
        )?;
    }

    if verdict.verdict == "APPROVED" {
        if let Some(failed_ac) = verdict.ac_results.iter().find(|a| a.status != "PASS") {
            return Err(format!(
                "PR review verdict is APPROVED but AC '{}' has status '{}'",
                failed_ac.id, failed_ac.status
            ));
        }
        if let Some(blocking) = verdict.findings.iter().find(|f| f.severity == "blocking") {
            return Err(format!(
                "PR review verdict is APPROVED despite blocking finding at {}:{}",
                blocking.file, blocking.line
            ));
        }
    }

    Ok(verdict)
}

/// Formats bounded findings and failing ACs from a `CHANGES_REQUESTED` verdict
/// for persistence in `task.memory.last_review_findings`.
pub fn format_review_findings(verdict: &ReviewVerdict) -> String {
    let mut lines = vec![format!("Summary: {}", verdict.summary.trim())];
    for ac in verdict.ac_results.iter().filter(|a| a.status != "PASS") {
        lines.push(format!(
            "- [AC {} FAIL] {}:{} - {}",
            ac.id.trim(),
            ac.file.trim(),
            ac.line,
            ac.evidence.trim()
        ));
    }
    for f in &verdict.findings {
        lines.push(format!(
            "- [{}] {}:{} - {}",
            f.severity.trim(),
            f.file.trim(),
            f.line,
            f.summary.trim()
        ));
    }
    truncate_utf8_bytes(&lines.join("\n"), MAX_SUMMARY_BYTES)
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

const MAX_RECENT_ATTEMPTS: usize = 10;
const MAX_ALLOWED_FILES: usize = 50;

fn filter_existing_allowed_files(
    worktree: &str,
    target_files: &[crate::v2::store::TargetFileSpec],
) -> Vec<String> {
    let trimmed_wt = worktree.trim();
    if trimmed_wt.is_empty() || trimmed_wt == "none" {
        return Vec::new();
    }
    let Ok(canonical_wt) = std::fs::canonicalize(trimmed_wt) else {
        return Vec::new();
    };
    let mut allowed = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for tf in target_files {
        let raw = tf.path.trim();
        if raw.is_empty()
            || raw.contains('*')
            || raw.contains('?')
            || raw.contains('[')
            || raw.contains(']')
        {
            continue;
        }
        let rel_path = std::path::Path::new(raw);
        if rel_path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            continue;
        }
        let candidate = if rel_path.is_absolute() {
            rel_path.to_path_buf()
        } else {
            canonical_wt.join(rel_path)
        };
        let Ok(canonical_file) = std::fs::canonicalize(&candidate) else {
            continue;
        };
        if !canonical_file.starts_with(&canonical_wt) || !canonical_file.is_file() {
            continue;
        }
        if let Ok(rel) = canonical_file.strip_prefix(&canonical_wt)
            && let Some(rel_str) = rel.to_str()
            && !rel_str.is_empty()
            && seen.insert(rel_str.to_owned())
        {
            allowed.push(rel_str.to_owned());
            if allowed.len() >= MAX_ALLOWED_FILES {
                break;
            }
        }
    }
    allowed
}

/// Pushes a bounded pointer entry (`<= 256` bytes) into `task.memory.recent_attempts`,
/// retaining at most `MAX_RECENT_ATTEMPTS` (10) recent entries.
pub fn push_bounded_recent_attempt(task: &mut TaskRecord, entry: impl AsRef<str>) {
    let bounded = truncate_utf8_bytes(entry.as_ref(), MAX_RECENT_ATTEMPT_BYTES);
    task.memory.recent_attempts.push(bounded);
    if task.memory.recent_attempts.len() > MAX_RECENT_ATTEMPTS {
        let drain = task.memory.recent_attempts.len() - MAX_RECENT_ATTEMPTS;
        task.memory.recent_attempts.drain(0..drain);
    }
}

fn classify_agy_infra_failure(res: &Result<StageExecutionResult, String>) -> Option<&'static str> {
    let msg = match res {
        Err(e) => e.as_str(),
        Ok(r) if r.status != "PASSED" => r.summary.as_str(),
        _ => return None,
    };
    if msg.contains("TIMEOUT") {
        Some("AGY_TIMEOUT")
    } else if msg.contains("SPAWN") {
        Some("AGY_SPAWN")
    } else if msg.contains("EXIT") {
        Some("AGY_EXIT")
    } else {
        Some("AGY_STATUS")
    }
}

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
    let allowed_files = filter_existing_allowed_files(&worktree, &task.context_pack.target_files);
    let timeout_seconds = route.timeout_secs.clamp(30, 1800);
    let orchestration_id = task.task_id.to_ascii_lowercase();

    serde_json::json!({
        "action": "run",
        "kind": kind,
        "task": prompt,
        "model": route.model,
        "workspace_paths": [worktree],
        "allowed_files": allowed_files,
        "confirmed": true,
        "timeout_seconds": timeout_seconds,
        "orchestration_id": orchestration_id,
    })
}

/// Locate the same Context Pack-shaped YAML block Governance consumes, skipping
/// unrelated fenced examples. Offsets include the fences for canonical publication.
fn context_pack_block(markdown: &str) -> Result<(&str, std::ops::Range<usize>), String> {
    let mut offset = 0;
    let mut fence: Option<(bool, usize, usize)> = None;
    for line in markdown.split_inclusive('\n') {
        let trimmed = line.trim();
        if let Some((yaml, start, body_start)) = fence {
            if trimmed.starts_with("```") {
                let body = &markdown[body_start..offset];
                if yaml
                    && body.lines().any(|l| {
                        l.starts_with("target_files:") || l.starts_with("acceptance_criteria:")
                    })
                {
                    return Ok((body, start..offset + line.len()));
                }
                fence = None;
            }
        } else if trimmed.starts_with("```") {
            fence = Some((
                matches!(trimmed, "```yaml" | "```yml"),
                offset,
                offset + line.len(),
            ));
        }
        offset += line.len();
    }
    Err("plan must contain a closed yaml/yml Context Pack block".to_owned())
}

// This deliberately supports a small, auditable YAML subset, with no dependency
// or subprocess parser. Unsupported YAML constructs fail closed.
fn yaml_without_comment(line: &str) -> Result<String, String> {
    let mut quote = None;
    let mut escaped = false;
    let mut out = String::new();
    let mut prev_space = true;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        if quote == Some('"') && ch == '\\' {
            out.push(ch);
            escaped = true;
            continue;
        }
        if let Some(q) = quote {
            if ch == q {
                if q == '\'' && chars.peek() == Some(&'\'') {
                    out.push(ch);
                    out.push(chars.next().unwrap());
                    continue;
                }
                quote = None;
            }
        } else if matches!(ch, '\'' | '"') && prev_space {
            quote = Some(ch);
        } else if ch == '#' && prev_space {
            break;
        }
        out.push(ch);
        prev_space = ch.is_whitespace();
    }
    if quote.is_some() {
        return Err("unterminated YAML quote".to_owned());
    }
    Ok(out.trim_end().to_owned())
}

fn yaml_scalar(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.starts_with('"') {
        return serde_json::from_str::<String>(raw)
            .map_err(|e| format!("invalid YAML string: {e}"));
    }
    if raw.starts_with('\'') {
        return raw
            .strip_prefix('\'')
            .and_then(|s| s.strip_suffix('\''))
            .map(|s| s.replace("''", "'"))
            .ok_or_else(|| "invalid single-quoted YAML string".to_owned());
    }
    if raw.is_empty()
        || raw.starts_with(['[', '{', '&', '*', '!', '|', '>'])
        || raw.contains(": ")
        || matches!(raw, "null" | "~")
    {
        return Err(format!("unsupported YAML scalar: {raw}"));
    }
    Ok(raw.to_owned())
}

pub fn extract_and_parse_context_pack_yaml(markdown: &str) -> Result<ContextPackSpec, String> {
    use serde_json::{Map, Value};
    let (body, _) = context_pack_block(markdown)?;
    let mut map = Map::new();
    let mut current = String::new();
    let mut item_indent = None;
    for raw in body.lines() {
        if raw.contains('\t') {
            return Err("tabs are unsupported in Context Pack YAML".to_owned());
        }
        let line = yaml_without_comment(raw)?;
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let text = line.trim();
        if indent == 0 && !text.starts_with("- ") {
            let (key, value) = text
                .split_once(':')
                .ok_or_else(|| "expected YAML key: value".to_owned())?;
            if map.contains_key(key) {
                return Err(format!("duplicate Context Pack key: {key}"));
            }
            let value = value.trim();
            let parsed = match key {
                "weight" | "base_sha" | "network" => Value::String(yaml_scalar(value)?),
                "target_files"
                | "acceptance_criteria"
                | "forbidden_paths"
                | "worker_checks"
                | "gate_checks"
                | "human_operations"
                | "verification_commands" => {
                    if !value.is_empty() && value != "[]" {
                        return Err(format!("{key} requires a block list or []"));
                    }
                    Value::Array(Vec::new())
                }
                _ => return Err(format!("unsupported Context Pack key: {key}")),
            };
            current = key.to_owned();
            item_indent = None;
            map.insert(current.clone(), parsed);
            continue;
        }
        let list = map
            .get_mut(&current)
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "unexpected YAML indentation".to_owned())?;
        if let Some(value) = text.strip_prefix("- ") {
            if item_indent.is_some_and(|i| i != indent) {
                return Err("inconsistent YAML list indentation".to_owned());
            }
            item_indent = Some(indent);
            if matches!(current.as_str(), "target_files" | "acceptance_criteria") {
                let mapping = if value.starts_with(['\'', '"']) {
                    None
                } else {
                    value
                        .split_once(": ")
                        .or_else(|| value.strip_suffix(':').map(|k| (k, "")))
                };
                if let Some((key, value)) = mapping {
                    let mut obj = Map::new();
                    obj.insert(key.to_owned(), Value::String(yaml_scalar(value)?));
                    list.push(Value::Object(obj));
                } else if current == "target_files" {
                    list.push(serde_json::json!({"path": yaml_scalar(value)?}));
                } else {
                    return Err("acceptance_criteria requires id/description entries".to_owned());
                }
            } else {
                list.push(Value::String(yaml_scalar(value)?));
            }
        } else {
            if !matches!(current.as_str(), "target_files" | "acceptance_criteria")
                || item_indent.is_none_or(|i| indent != i + 2)
            {
                return Err("unexpected YAML list continuation".to_owned());
            }
            let (key, value) = text
                .split_once(':')
                .ok_or_else(|| "expected YAML entry field".to_owned())?;
            let obj = list
                .last_mut()
                .and_then(Value::as_object_mut)
                .ok_or_else(|| "YAML field without list entry".to_owned())?;
            if obj.contains_key(key) {
                return Err(format!("duplicate YAML entry field: {key}"));
            }
            obj.insert(key.to_owned(), Value::String(yaml_scalar(value)?));
        }
    }
    for (key, allowed) in [
        ("target_files", &["path", "action", "summary"][..]),
        ("acceptance_criteria", &["id", "description"][..]),
    ] {
        if let Some(entries) = map.get(key).and_then(Value::as_array) {
            for entry in entries {
                if entry
                    .as_object()
                    .is_some_and(|o| o.keys().any(|k| !allowed.contains(&k.as_str())))
                {
                    return Err(format!("unknown field in {key}"));
                }
            }
        }
    }
    serde_json::from_value(Value::Object(map)).map_err(|e| format!("invalid Context Pack: {e}"))
}

fn merge_plan_context(
    task: &TaskRecord,
    mut proposed: ContextPackSpec,
) -> Result<ContextPackSpec, String> {
    if proposed.target_files.is_empty() {
        return Err("M/L plan requires non-empty target_files".to_owned());
    }
    if !proposed.weight.is_empty() && !matches!(proposed.weight.as_str(), "XS" | "S" | "M" | "L") {
        return Err("invalid plan weight".to_owned());
    }
    for path in &task.context_pack.forbidden_paths {
        if !proposed.forbidden_paths.contains(path) {
            return Err(format!("plan removes existing forbidden path: {path}"));
        }
    }
    for mandatory in ["src/ledger/**", ".github/workflows/**"] {
        if !proposed.forbidden_paths.iter().any(|p| p == mandatory) {
            proposed.forbidden_paths.push(mandatory.to_owned());
        }
    }
    let mut paths = BTreeSet::new();
    for target in &proposed.target_files {
        let path = normalize_cited_diff_path(&target.path, "")?;
        if path != target.path
            || path.contains(['*', '?', '[', '\\'])
            || !paths.insert(path.clone())
        {
            return Err(format!("invalid or duplicate plan target: {}", target.path));
        }
        if proposed
            .forbidden_paths
            .iter()
            .any(|f| matches_path_pattern(&path, f))
        {
            return Err(format!("plan target is forbidden: {path}"));
        }
    }
    if weight_rank(&proposed.weight) < weight_rank(&task.weight) {
        proposed.weight = task.weight.clone();
    }
    proposed.base_sha = task.context_pack.base_sha.clone().or(proposed.base_sha);
    // A plan may narrow network access, but cannot widen an offline contract.
    crate::v2::isolation::NetworkPolicy::resolve(
        proposed.network.as_deref(),
        ModelFamily::OpenAiSol,
    )?;
    if task.context_pack.network.as_deref() == Some("none") || proposed.network.is_none() {
        proposed.network = task.context_pack.network.clone();
    }
    for (old, new) in [
        (
            &task.context_pack.worker_checks,
            &mut proposed.worker_checks,
        ),
        (&task.context_pack.gate_checks, &mut proposed.gate_checks),
        (
            &task.context_pack.verification_commands,
            &mut proposed.verification_commands,
        ),
        (
            &task.context_pack.human_operations,
            &mut proposed.human_operations,
        ),
    ] {
        for entry in old {
            if !new.contains(entry) {
                new.push(entry.clone());
            }
        }
    }
    // A generated plan may add criteria, but cannot remove or weaken Issue criteria.
    for ac in &task.context_pack.acceptance_criteria {
        if let Some(found) = proposed
            .acceptance_criteria
            .iter_mut()
            .find(|a| a.id == ac.id)
        {
            *found = ac.clone();
        } else {
            proposed.acceptance_criteria.push(ac.clone());
        }
    }
    let mut ids = BTreeSet::new();
    if proposed
        .acceptance_criteria
        .iter()
        .any(|a| a.id.trim().is_empty() || !ids.insert(a.id.clone()))
    {
        return Err("invalid or duplicate acceptance criterion id".to_owned());
    }
    Ok(proposed)
}

/// Publish the merged pack, since ws-task replaces the board pack with this block.
fn plan_with_context(markdown: &str, pack: &ContextPackSpec) -> Result<String, String> {
    let (_, span) = context_pack_block(markdown)?;
    let value = serde_json::to_value(pack).map_err(|e| e.to_string())?;
    let mut yaml = String::from("```yaml\n");
    for (key, value) in value.as_object().ok_or("invalid Context Pack object")? {
        if value.is_null() {
            continue;
        }
        match value {
            serde_json::Value::Array(entries) => {
                yaml.push_str(&format!(
                    "{key}:{}\n",
                    if entries.is_empty() { " []" } else { "" }
                ));
                for entry in entries {
                    if let Some(obj) = entry.as_object() {
                        for (idx, (k, v)) in obj.iter().enumerate() {
                            yaml.push_str(&format!(
                                "  {}{k}: {v}\n",
                                if idx == 0 { "- " } else { "  " }
                            ));
                        }
                    } else {
                        yaml.push_str(&format!("  - {entry}\n"));
                    }
                }
            }
            _ => yaml.push_str(&format!("{key}: {value}\n")),
        }
    }
    yaml.push_str("```\n");
    Ok(format!(
        "{}{}{}",
        &markdown[..span.start],
        yaml,
        &markdown[span.end..]
    ))
}

pub fn validate_plan_review_verdict(
    raw: &str,
    task: &TaskRecord,
    proposed: &ContextPackSpec,
    artifact: &str,
    worktree: &str,
) -> Result<ReviewVerdict, String> {
    // Reuse the strict schema/coverage/consistency validator with plan citation
    // ranges. PR reviews still use only actual changed hunks (ZACH-026).
    let raw_verdict: ReviewVerdict =
        serde_json::from_str(raw).map_err(|e| format!("plan-review schema: {e}"))?;
    let mut context = ReviewedDiffContext::default();
    for (file, line) in raw_verdict
        .ac_results
        .iter()
        .map(|a| (&a.file, a.line))
        .chain(raw_verdict.findings.iter().map(|f| (&f.file, f.line)))
    {
        let virtual_plan = file == "plan" || file == artifact;
        let normalized = if virtual_plan {
            "plan".to_owned()
        } else {
            normalize_cited_diff_path(file, worktree)?
        };
        if line < 1
            || (!virtual_plan
                && !proposed.target_files.iter().any(|t| t.path == normalized)
                && !task
                    .context_pack
                    .target_files
                    .iter()
                    .any(|t| t.path == normalized)
                && !Path::new(worktree).join(&normalized).is_file())
        {
            return Err(format!("invalid plan-review citation: {file}:{line}"));
        }
        context.files.insert(
            normalized,
            vec![crate::v2::runner::LineRange {
                start: 1,
                end: usize::MAX,
            }],
        );
    }
    let mut normalized_verdict = raw_verdict;
    for file in normalized_verdict
        .ac_results
        .iter_mut()
        .map(|a| &mut a.file)
        .chain(normalized_verdict.findings.iter_mut().map(|f| &mut f.file))
    {
        if file == artifact {
            *file = "plan".to_owned();
        }
    }
    let expected: Vec<String> = proposed
        .acceptance_criteria
        .iter()
        .map(|a| a.id.clone())
        .collect();
    validate_review_verdict(
        &serde_json::to_string(&normalized_verdict).map_err(|e| e.to_string())?,
        &expected,
        &context,
        worktree,
    )
}

/// Character-safe section budgets keep all headings and the output schema present,
/// even when a skill, plan, context pack, or diagnostic is unexpectedly large.
/// Count UTF-16 units for worker.mjs; this also bounds Rust scalar characters.
fn truncate_prompt_section(text: &str, max_chars: usize) -> String {
    if text.encode_utf16().count() <= max_chars {
        return text.to_owned();
    }
    let mut units = 0;
    let mut out: String = text
        .chars()
        .take_while(|ch| {
            units += ch.len_utf16();
            units <= max_chars.saturating_sub(1)
        })
        .collect();
    if max_chars > 0 {
        out.push('…');
    }
    out
}

fn bounded_prompt(header: String, sections: Vec<(&str, String)>) -> String {
    let mut out = truncate_prompt_section(&header, 1000);
    let headings: usize = sections
        .iter()
        .map(|(name, _)| name.encode_utf16().count() + 8)
        .sum();
    let mut budget = MAX_WORKER_PROMPT_CHARS.saturating_sub(out.encode_utf16().count() + headings);
    // Share spare capacity among sections; short schemas/findings remain complete.
    let mut caps = vec![0; sections.len()];
    for (i, (name, body)) in sections.iter().enumerate() {
        if *name == "Required Output Format (Strict JSON Only)" {
            caps[i] = body.encode_utf16().count();
            budget = budget.saturating_sub(caps[i]);
        }
    }
    loop {
        let active: Vec<usize> = sections
            .iter()
            .enumerate()
            .filter(|(i, (_, body))| caps[*i] < body.encode_utf16().count())
            .map(|(i, _)| i)
            .collect();
        if active.is_empty() || budget == 0 {
            break;
        }
        let share = (budget / active.len()).max(1);
        for i in active {
            let add = share
                .min(budget)
                .min(sections[i].1.encode_utf16().count() - caps[i]);
            caps[i] += add;
            budget -= add;
        }
    }
    for ((name, body), cap) in sections.into_iter().zip(caps) {
        out.push_str(&format!("\n## {name}:\n"));
        out.push_str(&truncate_prompt_section(&body, cap));
        out.push('\n');
    }
    debug_assert!(out.encode_utf16().count() <= MAX_WORKER_PROMPT_CHARS);
    out
}

fn governance_skill(name: &str) -> String {
    let root = std::env::var_os("ZACH_GOVERNANCE_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/home/ubuntu/workspace/governance".into());
    format!(
        "{}\nDaemon mode: return output to zachd. Do not publish stages or call ws-task/gh; zachd owns publication.",
        governance_skill_from_root(&root, name)
    )
}

fn governance_skill_from_root(root: &Path, name: &str) -> String {
    std::fs::read_to_string(root.join(".agents/skills").join(name).join("SKILL.md"))
        .unwrap_or_else(|_| match name {
            "governance-planner" => "governance-planner: Explore canonical owners read-only; propose architecture, risks, tests and a ## [PLAN] with a fenced yaml Context Pack containing weight, target_files, forbidden_paths, verification_commands and acceptance_criteria. Escalate weight for critical scope; preserve existing boundaries and criteria.".to_owned(),
            _ => "governance-plan-reviewer: Independently audit ownership and path existence, weight accuracy, testability of every acceptance criterion, safety and forbidden paths. Return APPROVED or CHANGES_REQUESTED using the required ReviewVerdict schema.".to_owned(),
        })
}

fn prompt_context(task: &TaskRecord) -> String {
    serde_json::to_string_pretty(&task.context_pack).unwrap_or_default()
}

fn prompt_acs(task: &TaskRecord) -> String {
    task.context_pack
        .acceptance_criteria
        .iter()
        .map(|ac| format!("- {}: {}", ac.id, ac.description))
        .collect::<Vec<_>>()
        .join("\n")
}

fn prompt_diagnostic(text: &Option<String>) -> String {
    truncate_utf8_bytes(text.as_deref().unwrap_or_default(), MAX_SUMMARY_BYTES)
}

pub fn build_plan_prompt(task: &TaskRecord, worktree_path: &str) -> String {
    bounded_prompt(
        format!(
            "Plan task {} ({}) inside governed worktree {}.\nDaemon mode: read-only. Return the full plan; do not publish stages or call ws-task, git, or gh. Use only the supported YAML subset: scalars, block lists/maps, and inline []. Preserve forbidden_paths and acceptance criteria.\n",
            task.task_id, task.title, worktree_path
        ),
        vec![
            ("governance-planner", governance_skill("governance-planner")),
            ("Context Pack", prompt_context(task)),
            ("Acceptance Criteria", prompt_acs(task)),
            (
                "Prior Plan Review Findings",
                prompt_diagnostic(&task.memory.last_plan_review_findings),
            ),
        ],
    )
}

pub fn build_plan_review_prompt(task: &TaskRecord, worktree_path: &str, plan: &str) -> String {
    bounded_prompt(
        format!(
            "Review architectural plan for {} ({}) inside {}.\nDaemon mode: read-only; return JSON only; do not publish or call ws-task, git, or gh. Citations must use line >= 1 in plan, the candidate artifact, or existing/proposed repository files. APPROVED requires every AC PASS and no blocking findings.\n",
            task.task_id, task.title, worktree_path
        ),
        vec![
            (
                "governance-plan-reviewer",
                governance_skill("governance-plan-reviewer"),
            ),
            (
                "Required Output Format (Strict JSON Only)",
                review_verdict_json_schema_string(),
            ),
            ("Context Pack", prompt_context(task)),
            ("Acceptance Criteria", prompt_acs(task)),
            ("Candidate Plan", plan.to_owned()),
            (
                "Prior Plan Review Findings",
                prompt_diagnostic(&task.memory.last_plan_review_findings),
            ),
        ],
    )
}

fn task_with_full_approved_plan(
    task: &TaskRecord,
    executor: &dyn StageExecutor,
) -> Result<TaskRecord, String> {
    let mut prompt_task = task.clone();
    if let Some(path) = &task.memory.approved_plan_artifact_path {
        prompt_task.memory.approved_plan = Some(executor.read_plan_artifact(Path::new(path))?);
    }
    Ok(prompt_task)
}

pub fn build_impl_prompt(task: &TaskRecord, worktree_path: &str) -> String {
    bounded_prompt(
        format!(
            "Implement task {} ({}) inside governed worktree {}.\n",
            task.task_id, task.title, worktree_path
        ),
        vec![
            ("Context Pack", prompt_context(task)),
            ("Acceptance Criteria", prompt_acs(task)),
            (
                "Approved Plan",
                task.memory.approved_plan.clone().unwrap_or_default(),
            ),
            (
                "Prior Review Findings (Address All Blocking Items)",
                prompt_diagnostic(&task.memory.last_review_findings),
            ),
            (
                "Prior Check Failure",
                prompt_diagnostic(&task.memory.last_check_failure),
            ),
        ],
    )
}

pub fn build_pr_review_prompt(
    task: &TaskRecord,
    worktree_path: &str,
    diff_ctx: &ReviewedDiffContext,
) -> String {
    bounded_prompt(
        format!(
            "Review implementation of task {} ({}) inside governed worktree {}.\nYou MUST inspect the real git diff and verify every acceptance criterion.\nReviewed Commit Range: {}\nMerge Base SHA: {}\nReviewed SHA: {}\nInspect with: git diff {}\nEvery cited file and line MUST exist in the reviewed commit range.\n",
            task.task_id,
            task.title,
            worktree_path,
            diff_ctx.commit_range,
            diff_ctx.merge_base_sha,
            diff_ctx.reviewed_sha,
            diff_ctx.commit_range
        ),
        vec![
            (
                "Required Output Format (Strict JSON Only)",
                review_verdict_json_schema_string(),
            ),
            ("Context Pack", prompt_context(task)),
            ("Acceptance Criteria", prompt_acs(task)),
            (
                "Approved Plan",
                task.memory.approved_plan.clone().unwrap_or_else(|| {
                    "No approved plan recorded (XS/S task or pre-plan resume).".to_owned()
                }),
            ),
            (
                "Prior Review Findings",
                prompt_diagnostic(&task.memory.last_review_findings),
            ),
            (
                "Changed Files & Valid Line Ranges",
                diff_ctx
                    .files
                    .iter()
                    .map(|(p, r)| {
                        format!(
                            "{p}: lines [{}]",
                            r.iter()
                                .map(|r| format!("{}-{}", r.start, r.end))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            ("Diff Excerpt (--unified=0)", diff_ctx.diff_excerpt.clone()),
        ],
    )
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

    let raw_response = json
        .get("response")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let explicit_review = json
        .get("review_markdown")
        .or_else(|| json.get("review"))
        .or_else(|| json.get("review_target"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    // Preserve the full untruncated worker response (including ReviewVerdict JSON)
    // without discarding it via `.summary`.
    let review_output = raw_response
        .clone()
        .or_else(|| explicit_review.clone())
        .or_else(|| {
            json.get("verdict")
                .is_some()
                .then(|| trimmed_out.to_owned())
        });

    let review_markdown = explicit_review
        .or_else(|| raw_response.filter(|r| r.contains('|')))
        .or_else(|| summary.contains('|').then(|| summary.clone()));

    let invocation_id = json
        .get("orchestration_id")
        .or_else(|| json.get("run_id"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    let (input_tokens, output_tokens, total_tokens) = parse_agy_usage(&json);

    Ok(StageExecutionResult {
        status: "PASSED".to_owned(),
        summary,
        review_markdown,
        stage_output: review_output.clone(),
        review_output,
        invocation_id,
        input_tokens,
        output_tokens,
        total_tokens,
        sha_before: None,
        sha_after: None,
        diff_files: Vec::new(),
    })
}

fn parse_agy_usage(json: &serde_json::Value) -> (Option<u64>, Option<u64>, Option<u64>) {
    let usage = json.get("usage").and_then(|v| v.as_object());
    let input_tokens = usage
        .and_then(|u| u.get("input_tokens"))
        .and_then(|v| v.as_u64());
    let output_tokens = usage
        .and_then(|u| u.get("output_tokens"))
        .and_then(|v| v.as_u64());
    let direct_total = usage
        .and_then(|u| u.get("total_tokens"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            input_tokens
                .zip(output_tokens)
                .map(|(i, o)| i.saturating_add(o))
        });

    if let Some(total) = direct_total {
        return (input_tokens, output_tokens, Some(total));
    }

    // Fall back to per-invocation `budget.observed_total_tokens` only when
    // `unknown_usage_calls == 0` and at least one call ran. Never fall back to
    // `task_usage`, which accumulates across runs for the same orchestration_id.
    if let Some(budget) = json.get("budget").and_then(|v| v.as_object()) {
        let unknown_calls = budget.get("unknown_usage_calls").and_then(|v| v.as_u64());
        let calls_used = budget.get("model_calls_used").and_then(|v| v.as_u64());
        let observed = budget.get("observed_total_tokens").and_then(|v| v.as_u64());
        if unknown_calls == Some(0) && calls_used.is_none_or(|c| c > 0) && observed.is_some() {
            return (input_tokens, output_tokens, observed);
        }
    }

    (None, None, None)
}

pub const FAILURE_CLASS_INFRA: &str = "infra";
pub const FAILURE_CLASS_SEMANTIC: &str = "semantic";
pub const FAILURE_CLASS_POLICY: &str = "policy";

/// Maps a failed stage, execution error, or gate violation to `"infra"`, `"semantic"`, or `"policy"`.
pub fn classify_failure_class(stage: &str, status: &str, message: &str) -> &'static str {
    if message.starts_with("ISOLATION_PREFLIGHT_FAILED") {
        return FAILURE_CLASS_INFRA;
    }
    let lower_msg = message.to_ascii_lowercase();
    let lower_status = status.trim().to_ascii_lowercase();
    let lower_stage = stage.trim().to_ascii_lowercase();

    if lower_msg.contains("forbidden")
        || lower_msg.contains("out-of-scope")
        || lower_msg.contains("scope_violation")
        || lower_msg.contains("outside target_files")
        || lower_msg.contains("token budget")
        || lower_msg.contains("budget exhausted")
        || lower_msg.contains("size policy")
        || lower_msg.contains("policy")
        || lower_msg.contains("exceeds xs ceiling")
        || lower_msg.contains("exceeds s ceiling")
        || lower_msg.contains("verdict gate")
        || lower_msg.contains("approval rejected")
        || lower_msg.contains("autonomous_consent")
    {
        return FAILURE_CLASS_POLICY;
    }

    if lower_status == "timeout"
        || lower_status == "lost"
        || lower_status == "error"
        || lower_msg.contains("agy_spawn")
        || lower_msg.contains("agy_timeout")
        || lower_msg.contains("agy_exit")
        || lower_msg.contains("agy_status")
        || lower_msg.contains("agy_infra")
        || lower_msg.contains("orphan_lost")
        || lower_msg.contains("timed out")
        || lower_msg.contains("timeout")
        || lower_msg.contains("runtimemaxsec")
        || lower_msg.contains("failed to spawn")
        || lower_msg.contains("failed to run check")
        || lower_msg.contains("non-json")
        || lower_msg.contains("empty stdout")
        || lower_msg.contains("parse error")
        || lower_msg.contains("transient")
        || lower_msg.contains("no staged_results")
    {
        return FAILURE_CLASS_INFRA;
    }

    if lower_msg.contains("changes_requested")
        || lower_msg.contains("changes requested")
        || lower_msg.contains("review verdict")
        || lower_msg.contains("not in reviewed diff")
        || lower_msg.contains("outside reviewed diff")
        || lower_msg.contains("invalid review")
        || lower_msg.contains("check '")
        || lower_msg.contains("verification")
        || lower_msg.contains("validation")
        || lower_msg.contains("pr review")
        || lower_msg.contains("file:line")
        || lower_msg.contains("test evidence")
        || lower_msg.contains("did not pass")
        || lower_msg.contains("missing pass")
        || lower_msg.contains("cargo test")
        || lower_msg.contains("cargo clippy")
        || lower_msg.contains("test failed")
        || lower_msg.contains("tests failed")
        || lower_msg.contains("clippy")
        || lower_msg.contains("semantic")
        || matches!(lower_stage.as_str(), "plan-review" | "pr-review")
    {
        return FAILURE_CLASS_SEMANTIC;
    }

    FAILURE_CLASS_INFRA
}

fn apply_stage_result_usage(
    task: &mut TaskRecord,
    attempt: &mut StageAttemptRecord,
    stage: &str,
    result: &StageExecutionResult,
) {
    attempt.ended_epoch = Some(now_epoch());
    attempt.status = result.status.clone();
    attempt.summary = Some(truncate_utf8_bytes(&result.summary, MAX_SUMMARY_BYTES));
    attempt.invocation_id = result.invocation_id.clone();
    attempt.input_tokens = result.input_tokens;
    attempt.output_tokens = result.output_tokens;
    attempt.total_tokens = result.total_tokens;
    if let Some(tokens) = result.total_tokens {
        *task
            .memory
            .token_usage_by_stage
            .entry(stage.to_owned())
            .or_insert(0) += tokens;
    }
}

fn fail_stage_attempt(
    store: &mut V2Store,
    task: &mut TaskRecord,
    attempt: &mut StageAttemptRecord,
    failure_class: &str,
    summary: String,
    release_locks: bool,
) -> Result<(), String> {
    attempt.ended_epoch = Some(now_epoch());
    if attempt.status == "RUNNING" || attempt.status == "PASSED" {
        attempt.status = "FAILED".to_owned();
    }
    attempt.failure_class = Some(failure_class.to_owned());
    attempt.summary = Some(truncate_utf8_bytes(&summary, MAX_SUMMARY_BYTES));
    store
        .record_stage_attempt(attempt)
        .map_err(|e| e.to_string())?;
    task.retry_count += 1;
    *task = store.upsert_task(task).map_err(|e| e.to_string())?;
    if release_locks {
        let _ = store.release_path_locks(&task.task_id);
    }
    Ok(())
}

fn run_stage_checks(
    store: &mut V2Store,
    task: &mut TaskRecord,
    attempt: &mut StageAttemptRecord,
    executor: &mut dyn StageExecutor,
    worktree_path: &str,
    commands: &[String],
) -> Result<(), String> {
    if commands.is_empty() {
        return Ok(());
    }
    if let Err(err) = executor.run_checks(worktree_path, commands) {
        let bounded_err = truncate_utf8_bytes(&err, MAX_SUMMARY_BYTES);
        task.memory.last_check_failure = Some(bounded_err.clone());
        let class = classify_failure_class(&attempt.stage, "FAILED", &err);
        fail_stage_attempt(store, task, attempt, class, bounded_err, true)?;
        return Err(err);
    }
    Ok(())
}

fn run_host_gate_checks(
    store: &mut V2Store,
    task: &mut TaskRecord,
    attempt: &mut StageAttemptRecord,
    executor: &mut dyn StageExecutor,
    worktree_path: &str,
    commands: &[String],
) -> Result<(), String> {
    if commands.is_empty() {
        return Ok(());
    }
    if let Err(err) = executor.run_gate_checks(worktree_path, commands) {
        let bounded_err = truncate_utf8_bytes(&err, MAX_SUMMARY_BYTES);
        task.memory.last_check_failure = Some(bounded_err.clone());
        let class = classify_failure_class(&attempt.stage, "FAILED", &err);
        fail_stage_attempt(store, task, attempt, class, bounded_err, true)?;
        return Err(err);
    }
    Ok(())
}

fn commit_impl_worktree(
    store: &mut V2Store,
    executor: &mut dyn StageExecutor,
    task: &mut TaskRecord,
    attempt: &mut StageAttemptRecord,
    worktree_path: &str,
) -> Result<String, String> {
    let raw_sha = match executor.commit_worktree(task, worktree_path) {
        Ok(sha) => sha,
        Err(err) => {
            let class = classify_failure_class("impl", "FAILED", &err);
            fail_stage_attempt(store, task, attempt, class, err.clone(), true)?;
            return Err(format!(
                "failed to commit worktree for {}: {}",
                task.task_id, err
            ));
        }
    };
    let committed_sha = raw_sha.trim().to_owned();
    if committed_sha.is_empty() || committed_sha == "head-sha" {
        let err = format!(
            "commit_worktree returned invalid SHA '{}' for {}",
            committed_sha, task.task_id
        );
        fail_stage_attempt(store, task, attempt, FAILURE_CLASS_INFRA, err.clone(), true)?;
        return Err(err);
    }
    attempt.sha_after = Some(committed_sha.clone());
    store
        .record_stage_attempt(attempt)
        .map_err(|e| e.to_string())?;
    task.reviewed_sha = Some(committed_sha.clone());
    if !task.stages_completed.iter().any(|s| s == "impl") {
        task.stages_completed.push("impl".to_owned());
    }
    *task = store.upsert_task(task).map_err(|e| e.to_string())?;
    Ok(committed_sha)
}

fn apply_weight_escalation(
    task: &mut TaskRecord,
    to_weight: String,
    required_stages: Vec<String>,
    reason: &str,
) {
    task.weight = to_weight.clone();
    task.context_pack.weight = to_weight.clone();
    task.required_stages = if required_stages.is_empty() {
        default_required_stages(&to_weight)
    } else {
        required_stages
    };
    task.memory
        .decisions_log
        .push(format!("weight escalated to {to_weight}: {reason}"));
}

fn count_agy_infra_for_stage(task: &TaskRecord, stage: &str) -> usize {
    let stage_marker = format!("stage={stage}");
    task.memory
        .recent_attempts
        .iter()
        .filter(|line| {
            line.starts_with("[AGY_INFRA:")
                && (!line.contains("stage=") || line.contains(&stage_marker))
        })
        .count()
}

fn resolve_author_family(
    store: &V2Store,
    task_id: &str,
    stage: &str,
    in_run_family: Option<ModelFamily>,
) -> Result<ModelFamily, String> {
    if let Some(family) = in_run_family {
        return Ok(family);
    }
    let attempts = store
        .list_stage_attempts(task_id)
        .map_err(|e| e.to_string())?;
    if let Some(attempt) = attempts
        .iter()
        .rev()
        .find(|a| a.stage == stage && a.status == "PASSED")
        .or_else(|| attempts.iter().rev().find(|a| a.stage == stage))
    {
        return Ok(infer_model_family(&attempt.model));
    }
    let task = store
        .get_task(task_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("missing task {task_id}"))?;
    resolve_stage_route(&task.weight, stage, task.retry_count, None)?
        .map(|route| route.family)
        .ok_or_else(|| format!("missing {stage} author route"))
}

fn pause_for_missing_cross_family_reviewer(
    store: &mut V2Store,
    task: &mut TaskRecord,
    stage: &str,
    author_family: ModelFamily,
    reason: &str,
) -> Result<TaskRecord, String> {
    let dec_id = format!(
        "dec-{}-{}-cross-family-v{}",
        task.task_id.to_ascii_lowercase(),
        stage,
        task.version
    );
    let question = format!(
        "Cross-family reviewer unavailable for {} at stage '{}' (author family: {}).",
        task.task_id,
        stage,
        author_family.as_str()
    );
    let context_summary = truncate_utf8_bytes(reason, MAX_SUMMARY_BYTES);
    store
        .open_decision(
            &dec_id,
            &task.task_id,
            &task.task_group,
            "cross_family_reviewer_unavailable",
            &question,
            &[
                "Wait for cross-family model availability".to_owned(),
                "Abort task".to_owned(),
            ],
            Some(0),
            &context_summary,
            task.reviewed_sha
                .as_deref()
                .or(task.plan_base_sha.as_deref()),
        )
        .map_err(|e| e.to_string())?;
    task.memory.decisions_log.push(format!(
        "paused at {stage}: cross-family reviewer unavailable (author={})",
        author_family.as_str()
    ));
    task.status = "Blocked".to_owned();
    task.current_stage = Some(stage.to_owned());
    task.active_attempt_id = None;
    store.upsert_task(task).map_err(|e| e.to_string())
}

enum PrReviewOutcome {
    Approved(TaskRecord),
    NeedsRework(TaskRecord),
    PausedBlocked(TaskRecord),
}

fn execute_pr_review_gate(
    store: &mut V2Store,
    executor: &mut dyn StageExecutor,
    mut task: TaskRecord,
    worktree_path: &str,
    author_family: ModelFamily,
    impl_committed_in_run: bool,
) -> Result<PrReviewOutcome, String> {
    let rev_route = match resolve_stage_route(
        &task.weight,
        "pr-review",
        task.retry_count,
        Some(author_family),
    ) {
        Ok(Some(route)) => route,
        Ok(None) => return Err("missing pr-review route".to_owned()),
        Err(err) if is_no_cross_family_reviewer_error(&err) => {
            let paused = pause_for_missing_cross_family_reviewer(
                store,
                &mut task,
                "pr-review",
                author_family,
                &err,
            )?;
            return Ok(PrReviewOutcome::PausedBlocked(paused));
        }
        Err(err) => return Err(err),
    };

    if rev_route.family == ModelFamily::GeminiAgy
        && count_agy_infra_for_stage(&task, "pr-review") >= 2
    {
        let paused = pause_for_missing_cross_family_reviewer(
            store,
            &mut task,
            "pr-review",
            author_family,
            "Gemini AGY reviewer unavailable after >= 2 AGY infra failures; refusing same-family review fallback",
        )?;
        return Ok(PrReviewOutcome::PausedBlocked(paused));
    }

    check_token_budget(&task, &rev_route)?;

    let reviewed_sha = task
        .reviewed_sha
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("pr-review requires reviewed_sha on task {}", task.task_id))?;

    let diff_ctx = executor
        .collect_reviewed_diff(&task, worktree_path, &reviewed_sha)
        .map_err(|err| {
            format!(
                "failed to collect reviewed diff for {}: {err}",
                task.task_id
            )
        })?;

    let rev_attempt_id = format!(
        "{}-pr-review-{}",
        task.task_id.to_ascii_lowercase(),
        task.version
    );
    let prompt_task = task_with_full_approved_plan(&task, executor)?;
    let rev_prompt = build_pr_review_prompt(&prompt_task, worktree_path, &diff_ctx);
    let rev_spec = build_systemd_stage_command(&task, &rev_attempt_id, &rev_route, &rev_prompt)?;

    task.status = "PR Review".to_owned();
    task.current_stage = Some("pr-review".to_owned());
    task.active_attempt_id = Some(rev_attempt_id.clone());
    task = store.upsert_task(&task).map_err(|e| e.to_string())?;

    let rev_started = now_epoch();
    let mut rev_attempt = StageAttemptRecord {
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
        input_tokens: None,
        output_tokens: None,
        total_tokens: None,
        sha_before: Some(reviewed_sha.clone()),
        sha_after: Some(reviewed_sha),
    };
    store
        .record_stage_attempt(&rev_attempt)
        .map_err(|e| e.to_string())?;

    let rev_res = executor.execute_stage(&task, &rev_attempt_id, &rev_route, &rev_spec);
    if rev_route.family == ModelFamily::GeminiAgy
        && let Some(cls) = classify_agy_infra_failure(&rev_res)
    {
        push_bounded_recent_attempt(
            &mut task,
            format!(
                "[AGY_INFRA:{cls}] stage=pr-review attempt={rev_attempt_id} log=attempts/{rev_attempt_id}/stderr.log"
            ),
        );
        if count_agy_infra_for_stage(&task, "pr-review") >= 2 {
            let reason = match &rev_res {
                Err(e) => format!("cross-family AGY reviewer unavailable ({cls}): {e}"),
                Ok(res) => format!(
                    "cross-family AGY reviewer unavailable ({cls}): {}",
                    res.summary
                ),
            };
            rev_attempt.ended_epoch = Some(now_epoch());
            rev_attempt.status = "FAILED".to_owned();
            rev_attempt.failure_class = Some(FAILURE_CLASS_INFRA.to_owned());
            rev_attempt.summary = Some(truncate_utf8_bytes(&reason, MAX_SUMMARY_BYTES));
            store
                .record_stage_attempt(&rev_attempt)
                .map_err(|e| e.to_string())?;
            let paused = pause_for_missing_cross_family_reviewer(
                store,
                &mut task,
                "pr-review",
                author_family,
                &reason,
            )?;
            return Ok(PrReviewOutcome::PausedBlocked(paused));
        }
    }

    let rev_result = match rev_res {
        Ok(res) => res,
        Err(err) => {
            let class = classify_failure_class("pr-review", "FAILED", &err);
            fail_stage_attempt(store, &mut task, &mut rev_attempt, class, err.clone(), true)?;
            return Err(format!(
                "pr-review stage failed for {}: {}",
                task.task_id, err
            ));
        }
    };

    apply_stage_result_usage(&mut task, &mut rev_attempt, "pr-review", &rev_result);
    if let Some(sha) = rev_result
        .sha_after
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "head-sha")
    {
        rev_attempt.sha_after = Some(sha.to_owned());
    }

    if rev_result.status != "PASSED" {
        let class = classify_failure_class("pr-review", &rev_result.status, &rev_result.summary);
        fail_stage_attempt(
            store,
            &mut task,
            &mut rev_attempt,
            class,
            rev_result.summary.clone(),
            true,
        )?;
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
    let raw_verdict = rev_result
        .stage_output
        .as_deref()
        .or(rev_result.review_output.as_deref())
        .unwrap_or(&rev_result.summary);
    let verdict =
        match validate_review_verdict(raw_verdict, &expected_acs, &diff_ctx, worktree_path) {
            Ok(verdict) => verdict,
            Err(err) => {
                let class = classify_failure_class("pr-review", "FAILED", &err);
                fail_stage_attempt(store, &mut task, &mut rev_attempt, class, err.clone(), true)?;
                return Err(err);
            }
        };

    rev_attempt.failure_class = None;
    rev_attempt.summary = Some(truncate_utf8_bytes(
        &format!("{}: {}", verdict.verdict, verdict.summary),
        MAX_SUMMARY_BYTES,
    ));
    store
        .record_stage_attempt(&rev_attempt)
        .map_err(|e| e.to_string())?;

    if verdict.verdict == "APPROVED" {
        if !task.stages_completed.iter().any(|s| s == "pr-review") {
            task.stages_completed.push("pr-review".to_owned());
        }
        task.memory.last_review_findings = None;
        if let Some(sha) = rev_result
            .sha_after
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && *s != "head-sha")
            && (!impl_committed_in_run || rev_result.sha_after != rev_result.sha_before)
        {
            task.reviewed_sha = Some(sha.to_owned());
        }
        task = store.upsert_task(&task).map_err(|e| e.to_string())?;
        return Ok(PrReviewOutcome::Approved(task));
    }

    let findings_text = format_review_findings(&verdict);
    task.memory.last_review_findings = Some(findings_text.clone());
    if task.memory.review_rework_count >= MAX_REVIEW_REWORK_LOOPS {
        let dec_id = format!(
            "dec-{}-review-rework-{}",
            task.task_id.to_ascii_lowercase(),
            task.memory.review_rework_count
        );
        let question = format!(
            "PR review requested changes on {} after {} rework loop(s). How should we proceed?",
            task.task_id, task.memory.review_rework_count
        );
        store
            .open_decision(
                &dec_id,
                &task.task_id,
                &task.task_group,
                "review_rework_limit",
                &question,
                &[
                    "Authorize additional impl rework".to_owned(),
                    "Abort task".to_owned(),
                ],
                Some(0),
                &findings_text,
                task.reviewed_sha.as_deref(),
            )
            .map_err(|e| e.to_string())?;
        task.memory.decisions_log.push(format!(
            "paused at pr-review: rework limit ({MAX_REVIEW_REWORK_LOOPS}) reached"
        ));
        task.status = "Blocked".to_owned();
        task.current_stage = Some("pr-review".to_owned());
        task.active_attempt_id = None;
        let paused = store.upsert_task(&task).map_err(|e| e.to_string())?;
        return Ok(PrReviewOutcome::PausedBlocked(paused));
    }

    task.memory.review_rework_count = task.memory.review_rework_count.saturating_add(1);
    let rework_num = task.memory.review_rework_count;
    push_bounded_recent_attempt(
        &mut task,
        format!(
            "[pr-review:{}] CHANGES_REQUESTED rework={}/{}",
            rev_attempt_id, rework_num, MAX_REVIEW_REWORK_LOOPS
        ),
    );
    task.stages_completed
        .retain(|s| s != "impl" && s != "pr-review");
    task.status = "In Progress".to_owned();
    task.current_stage = Some("impl".to_owned());
    task.active_attempt_id = None;
    let updated = store.upsert_task(&task).map_err(|e| e.to_string())?;
    Ok(PrReviewOutcome::NeedsRework(updated))
}

pub fn execute_xs_s_pipeline(store: &mut V2Store, task_id: &str) -> Result<TaskRecord, String> {
    let mut executor = SystemdStageExecutor::default();
    execute_xs_s_pipeline_with_executor(store, task_id, &mut executor)
}

/// Drives an `XS` or `S` task end-to-end through `impl`, mechanical diff & check gates,
/// cross-model `pr-review` (when `S`), and enqueues the pull request into the per-repo FIFO
/// `merge_queue` (retaining `path_locks` until merge completes).
pub fn execute_xs_s_pipeline_with_executor(
    store: &mut V2Store,
    task_id: &str,
    executor: &mut dyn StageExecutor,
) -> Result<TaskRecord, String> {
    execute_xs_s_pipeline_with_executor_and_ws_task(
        store,
        task_id,
        executor,
        &default_ws_task_bin(),
    )
}

/// Injectable variant of [`execute_xs_s_pipeline_with_executor`] accepting an explicit `ws-task` binary path.
pub fn execute_xs_s_pipeline_with_executor_and_ws_task(
    store: &mut V2Store,
    task_id: &str,
    executor: &mut dyn StageExecutor,
    ws_task_bin: &Path,
) -> Result<TaskRecord, String> {
    let mut task = store
        .get_task(task_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("task '{task_id}' not found in store"))?;
    crate::v2::isolation::NetworkPolicy::resolve(
        task.context_pack.network.as_deref(),
        ModelFamily::OpenAiSol,
    )?;

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

    let mut impl_author_family: Option<ModelFamily> = None;
    let mut impl_committed_in_run = false;
    loop {
        // Stage 1: impl
        if !task.stages_completed.iter().any(|s| s == "impl")
            && (task.required_stages.is_empty() || task.required_stages.iter().any(|s| s == "impl"))
        {
            let impl_route = resolve_stage_route(&task.weight, "impl", task.retry_count, None)?
                .ok_or_else(|| "missing impl route".to_owned())?;
            impl_author_family = Some(impl_route.family);
            check_token_budget(&task, &impl_route)?;

            let impl_attempt_id = format!(
                "{}-impl-{}",
                task.task_id.to_ascii_lowercase(),
                task.version
            );
            let prompt_task = task_with_full_approved_plan(&task, executor)?;
            let impl_prompt = build_impl_prompt(&prompt_task, &worktree_path);
            let impl_spec =
                build_systemd_stage_command(&task, &impl_attempt_id, &impl_route, &impl_prompt)?;

            task.status = "In Progress".to_owned();
            task.current_stage = Some("impl".to_owned());
            task.active_attempt_id = Some(impl_attempt_id.clone());
            task.executor = Some("zach".to_owned());
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
                input_tokens: None,
                output_tokens: None,
                total_tokens: None,
                sha_before: None,
                sha_after: None,
            };
            store
                .record_stage_attempt(&attempt_rec)
                .map_err(|e| e.to_string())?;

            let impl_result =
                match executor.execute_stage(&task, &impl_attempt_id, &impl_route, &impl_spec) {
                    Ok(res) => res,
                    Err(err) => {
                        let class = classify_failure_class("impl", "FAILED", &err);
                        fail_stage_attempt(
                            store,
                            &mut task,
                            &mut attempt_rec,
                            class,
                            err.clone(),
                            true,
                        )?;
                        return Err(format!("impl stage failed for {}: {}", task.task_id, err));
                    }
                };
            apply_stage_result_usage(&mut task, &mut attempt_rec, "impl", &impl_result);
            attempt_rec.sha_before = impl_result.sha_before.clone();
            attempt_rec.sha_after = impl_result.sha_after.clone();
            push_bounded_recent_attempt(
                &mut task,
                format!(
                    "[impl:{}] status={} tokens={}",
                    impl_attempt_id,
                    impl_result.status,
                    impl_result
                        .total_tokens
                        .map_or_else(|| "unknown".to_owned(), |t| t.to_string())
                ),
            );

            if impl_result.status != "PASSED" {
                let class =
                    classify_failure_class("impl", &impl_result.status, &impl_result.summary);
                fail_stage_attempt(
                    store,
                    &mut task,
                    &mut attempt_rec,
                    class,
                    impl_result.summary.clone(),
                    true,
                )?;
                return Err(format!(
                    "impl stage failed for {}: {}",
                    task.task_id, impl_result.summary
                ));
            }

            attempt_rec.failure_class = None;
            store
                .record_stage_attempt(&attempt_rec)
                .map_err(|e| e.to_string())?;

            // Mechanical Gate 1: Worktree diff verification (forbidden_paths, target_files, ws-task weight floor)
            match verify_worktree_diff_with(
                &task.repository,
                &task.weight,
                &task.context_pack,
                &impl_result.diff_files,
                ws_task_bin,
            ) {
                Ok(DiffCheckOutcome::Clean) => {}
                Ok(DiffCheckOutcome::ForbiddenPathViolation { path, pattern }) => {
                    let err_msg = format!(
                        "forbidden path violation on {}: {} matches {}",
                        task.task_id, path, pattern
                    );
                    fail_stage_attempt(
                        store,
                        &mut task,
                        &mut attempt_rec,
                        FAILURE_CLASS_POLICY,
                        err_msg.clone(),
                        true,
                    )?;
                    let dec_id = format!("dec-{}-forbidden", task.task_id.to_ascii_lowercase());
                    let bounded_context =
                        truncate_utf8_bytes(&impl_result.summary, MAX_SUMMARY_BYTES);
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
                        &bounded_context,
                        impl_result.sha_after.as_deref(),
                    );
                    return Err(err_msg);
                }
                Ok(DiffCheckOutcome::OutOfScopeFiles { files }) => {
                    let err_msg = format!(
                        "out-of-scope files modified on {}: {:?}",
                        task.task_id, files
                    );
                    fail_stage_attempt(
                        store,
                        &mut task,
                        &mut attempt_rec,
                        FAILURE_CLASS_POLICY,
                        err_msg.clone(),
                        true,
                    )?;
                    let dec_id = format!("dec-{}-scope", task.task_id.to_ascii_lowercase());
                    let bounded_context =
                        truncate_utf8_bytes(&impl_result.summary, MAX_SUMMARY_BYTES);
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
                        &bounded_context,
                        impl_result.sha_after.as_deref(),
                    );
                    return Err(err_msg);
                }
                Ok(DiffCheckOutcome::WeightEscalated {
                    from_weight: _,
                    to_weight,
                    required_stages,
                    reason,
                }) => {
                    apply_weight_escalation(&mut task, to_weight.clone(), required_stages, &reason);
                    task = store.upsert_task(&task).map_err(|e| e.to_string())?;
                    if matches!(to_weight.as_str(), "M" | "L") {
                        let _ = store.release_path_locks(&task.task_id);
                        return Ok(task);
                    }
                }
                Err(err) => {
                    fail_stage_attempt(
                        store,
                        &mut task,
                        &mut attempt_rec,
                        FAILURE_CLASS_INFRA,
                        err.clone(),
                        true,
                    )?;
                    return Err(err);
                }
            }

            // Mechanical Gate 2: worker_checks and gate_checks
            let worker_checks = task.context_pack.worker_checks.clone();
            run_stage_checks(
                store,
                &mut task,
                &mut attempt_rec,
                executor,
                &worktree_path,
                &worker_checks,
            )?;
            let gate_checks = task.context_pack.gate_checks.clone();
            run_host_gate_checks(
                store,
                &mut task,
                &mut attempt_rec,
                executor,
                &worktree_path,
                &gate_checks,
            )?;

            let _committed_sha =
                commit_impl_worktree(store, executor, &mut task, &mut attempt_rec, &worktree_path)?;
            impl_committed_in_run = true;
        }

        // Stage 2: Cross-model pr-review for weight S
        if !task.stages_completed.iter().any(|s| s == "pr-review")
            && (task.weight.eq_ignore_ascii_case("S")
                || task.required_stages.iter().any(|s| s == "pr-review"))
        {
            let author_family =
                resolve_author_family(store, &task.task_id, "impl", impl_author_family)?;
            match execute_pr_review_gate(
                store,
                executor,
                task,
                &worktree_path,
                author_family,
                impl_committed_in_run,
            )? {
                PrReviewOutcome::Approved(updated) => {
                    task = updated;
                    break;
                }
                PrReviewOutcome::NeedsRework(updated) => {
                    task = updated;
                    impl_committed_in_run = false;
                    continue;
                }
                PrReviewOutcome::PausedBlocked(paused) => {
                    return Ok(paused);
                }
            }
        }
        break;
    }

    // Final: Enqueue into FIFO merge queue (path locks remain held until merge completes!)
    enqueue_pipeline_task_for_merge(store, executor, task, &worktree_path)
}

pub fn execute_m_l_pipeline(store: &mut V2Store, task_id: &str) -> Result<TaskRecord, String> {
    let mut executor = SystemdStageExecutor::default();
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
    execute_m_l_pipeline_with_executor_and_ws_task(store, task_id, executor, &default_ws_task_bin())
}

/// Injectable variant of [`execute_m_l_pipeline_with_executor`] accepting an explicit `ws-task` binary path.
pub fn execute_m_l_pipeline_with_executor_and_ws_task(
    store: &mut V2Store,
    task_id: &str,
    executor: &mut dyn StageExecutor,
    ws_task_bin: &Path,
) -> Result<TaskRecord, String> {
    let mut task = store
        .get_task(task_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("task '{task_id}' not found in store"))?;
    crate::v2::isolation::NetworkPolicy::resolve(
        task.context_pack.network.as_deref(),
        ModelFamily::OpenAiSol,
    )?;

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

    loop {
        // Stage 1: plan (read-only, no path locks)
        let mut plan_author_family: Option<ModelFamily> = None;
        if !task.stages_completed.iter().any(|s| s == "plan")
            && (task.required_stages.is_empty() || task.required_stages.iter().any(|s| s == "plan"))
        {
            let plan_route_initial =
                resolve_stage_route(&task.weight, "plan", task.retry_count, None)?
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
            plan_author_family = Some(plan_route.family);

            check_token_budget(&task, &plan_route)?;

            let plan_attempt_id = format!(
                "{}-plan-{}",
                task.task_id.to_ascii_lowercase(),
                task.version
            );
            let plan_prompt = build_plan_prompt(&task, &worktree_path);
            let plan_spec =
                build_systemd_stage_command(&task, &plan_attempt_id, &plan_route, &plan_prompt)?;

            task.status = "Planning".to_owned();
            task.current_stage = Some("plan".to_owned());
            task.active_attempt_id = Some(plan_attempt_id.clone());
            task.executor = Some("zach".to_owned());
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
                input_tokens: None,
                output_tokens: None,
                total_tokens: None,
                sha_before: None,
                sha_after: None,
            };
            store
                .record_stage_attempt(&plan_rec)
                .map_err(|e| e.to_string())?;

            let mut plan_res =
                executor.execute_stage(&task, &plan_attempt_id, &plan_route, &plan_spec);

            if plan_route.family == ModelFamily::GeminiAgy
                && let Some(cls) = classify_agy_infra_failure(&plan_res)
            {
                push_bounded_recent_attempt(
                    &mut task,
                    format!(
                        "[AGY_INFRA:{cls}] stage=plan attempt={plan_attempt_id} log=attempts/{plan_attempt_id}/stderr.log"
                    ),
                );
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
                    plan_rec.status = "FAILED".to_owned();
                    plan_rec.ended_epoch = Some(now_epoch());
                    plan_rec.failure_class = Some(FAILURE_CLASS_INFRA.to_owned());
                    store
                        .record_stage_attempt(&plan_rec)
                        .map_err(|e| e.to_string())?;
                    plan_rec.attempt_id = fb_attempt_id.clone();
                    plan_rec.model = fb_route.model.clone();
                    plan_rec.effort = fb_route.effort.as_str().to_owned();
                    plan_rec.systemd_unit = Some(fb_spec.unit_name.clone());
                    plan_rec.status = "RUNNING".to_owned();
                    plan_rec.ended_epoch = None;
                    plan_rec.failure_class = None;
                    store
                        .record_stage_attempt(&plan_rec)
                        .map_err(|e| e.to_string())?;
                    task.active_attempt_id = Some(fb_attempt_id.clone());
                    task = store.upsert_task(&task).map_err(|e| e.to_string())?;
                    plan_author_family = Some(fb_route.family);
                    plan_res = executor.execute_stage(&task, &fb_attempt_id, &fb_route, &fb_spec);
                }
            }

            let plan_result = match plan_res {
                Ok(res) => res,
                Err(err) => {
                    let class = classify_failure_class("plan", "FAILED", &err);
                    fail_stage_attempt(store, &mut task, &mut plan_rec, class, err.clone(), false)?;
                    return Err(format!("plan stage failed for {}: {}", task.task_id, err));
                }
            };
            apply_stage_result_usage(&mut task, &mut plan_rec, "plan", &plan_result);

            if plan_result.status != "PASSED" {
                let class =
                    classify_failure_class("plan", &plan_result.status, &plan_result.summary);
                fail_stage_attempt(
                    store,
                    &mut task,
                    &mut plan_rec,
                    class,
                    plan_result.summary.clone(),
                    false,
                )?;
                return Err(format!(
                    "plan stage failed for {}: {}",
                    task.task_id, plan_result.summary
                ));
            }

            plan_rec.failure_class = None;
            store
                .record_stage_attempt(&plan_rec)
                .map_err(|e| e.to_string())?;

            let prepared = (|| {
                let plan_text = plan_result
                    .stage_output
                    .as_deref()
                    .or(plan_result.review_output.as_deref())
                    .filter(|s| !s.trim().is_empty())
                    .ok_or_else(|| "plan stage returned no full stage_output".to_owned())?;
                let artifact =
                    executor.persist_plan_artifact(&task, &plan_rec.attempt_id, plan_text)?;
                task.memory.candidate_plan_artifact_path =
                    Some(artifact.to_string_lossy().into_owned());
                extract_and_parse_context_pack_yaml(plan_text)
                    .and_then(|p| merge_plan_context(&task, p))?;
                Ok::<(), String>(())
            })();
            if let Err(err) = prepared {
                fail_stage_attempt(
                    store,
                    &mut task,
                    &mut plan_rec,
                    FAILURE_CLASS_SEMANTIC,
                    err.clone(),
                    false,
                )?;
                return Err(err);
            }
            // Never label a candidate as approved, including after rework/resume.
            task.memory.approved_plan = None;
            task.memory.approved_plan_artifact_path = None;
            task.stages_completed.push("plan".to_owned());
            task = store.upsert_task(&task).map_err(|e| e.to_string())?;
        }

        // Stage 2: plan-review (read-only, cross-model review of plan)
        if !task.stages_completed.iter().any(|s| s == "plan-review")
            && (task.required_stages.is_empty()
                || task.required_stages.iter().any(|s| s == "plan-review"))
        {
            let plan_author =
                resolve_author_family(store, &task.task_id, "plan", plan_author_family)?;
            let rev_route = match resolve_stage_route(
                &task.weight,
                "plan-review",
                task.retry_count,
                Some(plan_author),
            ) {
                Ok(Some(route)) => route,
                Ok(None) => return Err("missing plan-review route".to_owned()),
                Err(err) if is_no_cross_family_reviewer_error(&err) => {
                    return pause_for_missing_cross_family_reviewer(
                        store,
                        &mut task,
                        "plan-review",
                        plan_author,
                        &err,
                    );
                }
                Err(err) => return Err(err),
            };

            if rev_route.family == ModelFamily::GeminiAgy
                && count_agy_infra_for_stage(&task, "plan-review") >= 2
            {
                return pause_for_missing_cross_family_reviewer(
                    store,
                    &mut task,
                    "plan-review",
                    plan_author,
                    "Gemini AGY plan reviewer unavailable after >= 2 AGY infra failures; refusing same-family fallback",
                );
            }

            check_token_budget(&task, &rev_route)?;

            let rev_attempt_id = format!(
                "{}-plan-review-{}",
                task.task_id.to_ascii_lowercase(),
                task.version
            );
            let candidate_path = task
                .memory
                .candidate_plan_artifact_path
                .clone()
                .ok_or_else(|| "plan-review requires a candidate plan artifact".to_owned())?;
            let candidate = executor.read_plan_artifact(Path::new(&candidate_path))?;
            let proposed = extract_and_parse_context_pack_yaml(&candidate)
                .and_then(|pack| merge_plan_context(&task, pack))?;
            let canonical_plan = plan_with_context(&candidate, &proposed)?;
            let mut review_task = task.clone();
            review_task.context_pack = proposed.clone();
            let rev_prompt =
                build_plan_review_prompt(&review_task, &worktree_path, &canonical_plan);
            let mut rev_spec =
                build_systemd_stage_command(&task, &rev_attempt_id, &rev_route, &rev_prompt)?;
            rev_spec.output_schema_json = Some(review_verdict_json_schema_string());

            task.status = "Plan Review".to_owned();
            task.current_stage = Some("plan-review".to_owned());
            task.active_attempt_id = Some(rev_attempt_id.clone());
            task.executor = Some("zach".to_owned());
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
                input_tokens: None,
                output_tokens: None,
                total_tokens: None,
                sha_before: None,
                sha_after: None,
            };
            store
                .record_stage_attempt(&rev_rec)
                .map_err(|e| e.to_string())?;

            let rev_res = executor.execute_stage(&task, &rev_attempt_id, &rev_route, &rev_spec);

            if rev_route.family == ModelFamily::GeminiAgy
                && let Some(cls) = classify_agy_infra_failure(&rev_res)
            {
                push_bounded_recent_attempt(
                    &mut task,
                    format!(
                        "[AGY_INFRA:{cls}] stage=plan-review attempt={rev_attempt_id} log=attempts/{rev_attempt_id}/stderr.log"
                    ),
                );
                if count_agy_infra_for_stage(&task, "plan-review") >= 2 {
                    let reason = match &rev_res {
                        Err(e) => {
                            format!("cross-family AGY plan reviewer unavailable ({cls}): {e}")
                        }
                        Ok(res) => format!(
                            "cross-family AGY plan reviewer unavailable ({cls}): {}",
                            res.summary
                        ),
                    };
                    rev_rec.ended_epoch = Some(now_epoch());
                    rev_rec.status = "FAILED".to_owned();
                    rev_rec.failure_class = Some(FAILURE_CLASS_INFRA.to_owned());
                    rev_rec.summary = Some(truncate_utf8_bytes(&reason, MAX_SUMMARY_BYTES));
                    store
                        .record_stage_attempt(&rev_rec)
                        .map_err(|e| e.to_string())?;
                    return pause_for_missing_cross_family_reviewer(
                        store,
                        &mut task,
                        "plan-review",
                        plan_author,
                        &reason,
                    );
                }
            }

            let rev_result = match rev_res {
                Ok(res) => res,
                Err(err) => {
                    let class = classify_failure_class("plan-review", "FAILED", &err);
                    fail_stage_attempt(store, &mut task, &mut rev_rec, class, err.clone(), false)?;
                    return Err(format!(
                        "plan-review stage failed for {}: {}",
                        task.task_id, err
                    ));
                }
            };
            apply_stage_result_usage(&mut task, &mut rev_rec, "plan-review", &rev_result);

            if rev_result.status != "PASSED" {
                let class =
                    classify_failure_class("plan-review", &rev_result.status, &rev_result.summary);
                fail_stage_attempt(
                    store,
                    &mut task,
                    &mut rev_rec,
                    class,
                    rev_result.summary.clone(),
                    false,
                )?;
                return Err(format!(
                    "plan-review stage failed for {}: {}",
                    task.task_id, rev_result.summary
                ));
            }

            let raw_verdict = rev_result
                .stage_output
                .as_deref()
                .or(rev_result.review_output.as_deref())
                .unwrap_or(&rev_result.summary);
            let verdict = match validate_plan_review_verdict(
                raw_verdict,
                &task,
                &proposed,
                &candidate_path,
                &worktree_path,
            ) {
                Ok(verdict) => verdict,
                Err(err) => {
                    fail_stage_attempt(
                        store,
                        &mut task,
                        &mut rev_rec,
                        FAILURE_CLASS_SEMANTIC,
                        err.clone(),
                        false,
                    )?;
                    return Err(err);
                }
            };
            rev_rec.failure_class = None;
            rev_rec.summary = Some(truncate_utf8_bytes(
                &format!("{}: {}", verdict.verdict, verdict.summary),
                MAX_SUMMARY_BYTES,
            ));
            store
                .record_stage_attempt(&rev_rec)
                .map_err(|e| e.to_string())?;
            if verdict.verdict == "CHANGES_REQUESTED" {
                let findings = format_review_findings(&verdict);
                task.memory.last_plan_review_findings = Some(findings.clone());
                task.memory.approved_plan = None;
                task.memory.approved_plan_artifact_path = None;
                task.active_attempt_id = None;
                if task.memory.plan_rework_count >= MAX_PLAN_REWORK_CYCLES {
                    let decision_id = format!(
                        "dec-{}-plan-rework-{}",
                        task.task_id.to_ascii_lowercase(),
                        task.memory.plan_rework_count
                    );
                    store
                        .open_decision(
                            &decision_id,
                            &task.task_id,
                            &task.task_group,
                            "plan_rework_limit",
                            "Plan rework limit reached. How should we proceed?",
                            &[
                                "Authorize additional plan rework".to_owned(),
                                "Abort task".to_owned(),
                            ],
                            Some(0),
                            &findings,
                            task.plan_base_sha.as_deref(),
                        )
                        .map_err(|e| e.to_string())?;
                    task.status = "Blocked".to_owned();
                    return store.upsert_task(&task).map_err(|e| e.to_string());
                }
                task.memory.plan_rework_count += 1;
                task.stages_completed.retain(|s| {
                    !matches!(s.as_str(), "plan" | "plan-review" | "human-plan-approval")
                });
                task.memory.candidate_plan_artifact_path = None;
                task.current_stage = Some("plan".to_owned());
                task = store.upsert_task(&task).map_err(|e| e.to_string())?;
                continue;
            }
            let artifact = executor.persist_plan_artifact(
                &task,
                &format!("approved-plan-{rev_attempt_id}"),
                &canonical_plan,
            )?;
            if let Err(err) = executor.publish_plan_stage(&task, &artifact, &canonical_plan) {
                fail_stage_attempt(
                    store,
                    &mut task,
                    &mut rev_rec,
                    FAILURE_CLASS_INFRA,
                    err.clone(),
                    false,
                )?;
                return Err(err);
            }
            if weight_rank(&proposed.weight) > weight_rank(&task.weight) {
                apply_weight_escalation(
                    &mut task,
                    proposed.weight.clone(),
                    Vec::new(),
                    "approved plan",
                );
            }
            task.context_pack = proposed;
            task.required_stages = default_required_stages(&task.weight);
            task.memory.approved_plan = Some(truncate_utf8_bytes(
                &canonical_plan,
                MAX_APPROVED_PLAN_BYTES,
            ));
            task.memory.approved_plan_artifact_path = Some(artifact.to_string_lossy().into_owned());
            task.memory.last_plan_review_findings = None;
            task.stages_completed.push("plan-review".to_owned());
            task.active_attempt_id = None;
            task = store.upsert_task(&task).map_err(|e| e.to_string())?;
        }
        break;
    }

    // Human Gate 1: human-plan-approval for L tasks
    if task.weight.trim().eq_ignore_ascii_case("L")
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

    // Stage 3 + 4 loop: impl (Atomic path_locks acquired before impl and held!) -> pr-review (rework on CHANGES_REQUESTED)
    let mut impl_author_family: Option<ModelFamily> = None;
    let mut impl_committed_in_run = false;
    loop {
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

            let impl_route_initial =
                resolve_stage_route(&task.weight, "impl", task.retry_count, None)?
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
            impl_author_family = Some(impl_route.family);

            check_token_budget(&task, &impl_route)?;

            let impl_attempt_id = format!(
                "{}-impl-{}",
                task.task_id.to_ascii_lowercase(),
                task.version
            );
            let prompt_task = task_with_full_approved_plan(&task, executor)?;
            let impl_prompt = build_impl_prompt(&prompt_task, &worktree_path);
            let impl_spec =
                build_systemd_stage_command(&task, &impl_attempt_id, &impl_route, &impl_prompt)?;

            task.status = "In Progress".to_owned();
            task.current_stage = Some("impl".to_owned());
            task.active_attempt_id = Some(impl_attempt_id.clone());
            task.executor = Some("zach".to_owned());
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
                input_tokens: None,
                output_tokens: None,
                total_tokens: None,
                sha_before: None,
                sha_after: None,
            };
            store
                .record_stage_attempt(&attempt_rec)
                .map_err(|e| e.to_string())?;

            let mut impl_res =
                executor.execute_stage(&task, &impl_attempt_id, &impl_route, &impl_spec);

            if impl_route.family == ModelFamily::GeminiAgy
                && let Some(cls) = classify_agy_infra_failure(&impl_res)
            {
                push_bounded_recent_attempt(
                    &mut task,
                    format!(
                        "[AGY_INFRA:{cls}] stage=impl attempt={impl_attempt_id} log=attempts/{impl_attempt_id}/stderr.log"
                    ),
                );
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
                    impl_author_family = Some(fb_route.family);
                    impl_res = executor.execute_stage(&task, &fb_attempt_id, &fb_route, &fb_spec);
                }
            }

            let impl_result = match impl_res {
                Ok(res) => res,
                Err(err) => {
                    let class = classify_failure_class("impl", "FAILED", &err);
                    fail_stage_attempt(
                        store,
                        &mut task,
                        &mut attempt_rec,
                        class,
                        err.clone(),
                        true,
                    )?;
                    return Err(format!("impl stage failed for {}: {}", task.task_id, err));
                }
            };

            apply_stage_result_usage(&mut task, &mut attempt_rec, "impl", &impl_result);
            attempt_rec.sha_before = impl_result.sha_before.clone();
            attempt_rec.sha_after = impl_result.sha_after.clone();

            if impl_result.status != "PASSED" {
                let class =
                    classify_failure_class("impl", &impl_result.status, &impl_result.summary);
                fail_stage_attempt(
                    store,
                    &mut task,
                    &mut attempt_rec,
                    class,
                    impl_result.summary.clone(),
                    true,
                )?;
                return Err(format!(
                    "impl stage failed for {}: {}",
                    task.task_id, impl_result.summary
                ));
            }

            attempt_rec.failure_class = None;
            store
                .record_stage_attempt(&attempt_rec)
                .map_err(|e| e.to_string())?;

            // Mechanical diff verification
            match verify_worktree_diff_with(
                &task.repository,
                &task.weight,
                &task.context_pack,
                &impl_result.diff_files,
                ws_task_bin,
            ) {
                Ok(DiffCheckOutcome::Clean) => {}
                Ok(DiffCheckOutcome::ForbiddenPathViolation { path, pattern }) => {
                    let err_msg = format!(
                        "forbidden path violation on {}: {} matches {}",
                        task.task_id, path, pattern
                    );
                    fail_stage_attempt(
                        store,
                        &mut task,
                        &mut attempt_rec,
                        FAILURE_CLASS_POLICY,
                        err_msg.clone(),
                        true,
                    )?;
                    return Err(err_msg);
                }
                Ok(DiffCheckOutcome::OutOfScopeFiles { files }) => {
                    let err_msg = format!(
                        "out-of-scope files modified on {}: {:?}",
                        task.task_id, files
                    );
                    fail_stage_attempt(
                        store,
                        &mut task,
                        &mut attempt_rec,
                        FAILURE_CLASS_POLICY,
                        err_msg.clone(),
                        true,
                    )?;
                    return Err(err_msg);
                }
                Ok(DiffCheckOutcome::WeightEscalated {
                    from_weight: _,
                    to_weight,
                    required_stages,
                    reason,
                }) => {
                    apply_weight_escalation(&mut task, to_weight, required_stages, &reason);
                    task = store.upsert_task(&task).map_err(|e| e.to_string())?;
                }
                Err(err) => {
                    fail_stage_attempt(
                        store,
                        &mut task,
                        &mut attempt_rec,
                        FAILURE_CLASS_INFRA,
                        err.clone(),
                        true,
                    )?;
                    return Err(err);
                }
            }

            let worker_checks = task.context_pack.worker_checks.clone();
            run_stage_checks(
                store,
                &mut task,
                &mut attempt_rec,
                executor,
                &worktree_path,
                &worker_checks,
            )?;
            let gate_checks = task.context_pack.gate_checks.clone();
            run_host_gate_checks(
                store,
                &mut task,
                &mut attempt_rec,
                executor,
                &worktree_path,
                &gate_checks,
            )?;

            let _committed_sha =
                commit_impl_worktree(store, executor, &mut task, &mut attempt_rec, &worktree_path)?;
            impl_committed_in_run = true;
        }

        // Stage 4: pr-review (Cross-model review, path_locks remain held!)
        if !task.stages_completed.iter().any(|s| s == "pr-review")
            && (task.required_stages.is_empty()
                || task.required_stages.iter().any(|s| s == "pr-review"))
        {
            let author_family =
                resolve_author_family(store, &task.task_id, "impl", impl_author_family)?;
            match execute_pr_review_gate(
                store,
                executor,
                task,
                &worktree_path,
                author_family,
                impl_committed_in_run,
            )? {
                PrReviewOutcome::Approved(updated) => {
                    task = updated;
                    break;
                }
                PrReviewOutcome::NeedsRework(updated) => {
                    task = updated;
                    impl_committed_in_run = false;
                    continue;
                }
                PrReviewOutcome::PausedBlocked(paused) => {
                    return Ok(paused);
                }
            }
        }
        break;
    }

    // Human Gate 2: human-merge-approval for L tasks (check live task.weight after any M->L escalation)
    if task.weight.trim().eq_ignore_ascii_case("L")
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
    enqueue_pipeline_task_for_merge(store, executor, task, &worktree_path)
}

/// Pushes the committed branch and opens (or looks up) its pull request, enqueues the
/// task into the per-repo FIFO `merge_queue`, and transitions the task to
/// `Queued for Merge` while keeping `path_locks` held until `merge_queue` completes.
fn enqueue_pipeline_task_for_merge(
    store: &mut V2Store,
    executor: &mut dyn StageExecutor,
    mut task: TaskRecord,
    worktree_path: &str,
) -> Result<TaskRecord, String> {
    let reviewed_sha = task
        .reviewed_sha
        .as_deref()
        .map(str::trim)
        .filter(|sha| !sha.is_empty() && *sha != "head-sha")
        .ok_or_else(|| format!("task {} is missing a valid reviewed_sha", task.task_id))?
        .to_owned();
    task.reviewed_sha = Some(reviewed_sha.clone());

    let pr_number = executor.push_and_ensure_pr(&task, worktree_path, &reviewed_sha)?;
    if pr_number <= 0 {
        return Err(format!(
            "invalid pr_number {} returned for task {}",
            pr_number, task.task_id
        ));
    }
    task.pr_number = Some(pr_number);

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

    fn plan_result(text: String) -> StageExecutionResult {
        StageExecutionResult {
            status: "PASSED".to_owned(),
            summary: "bounded summary".to_owned(),
            stage_output: Some(text),
            review_output: None,
            review_markdown: None,
            invocation_id: None,
            input_tokens: None,
            output_tokens: None,
            total_tokens: None,
            sha_before: None,
            sha_after: None,
            diff_files: Vec::new(),
        }
    }

    fn sample_plan_task(id: &str) -> TaskRecord {
        let mut task = sample_s_task(id);
        task.weight = "M".to_owned();
        task.context_pack = sample_context_pack("M");
        task.required_stages = default_required_stages("M");
        task
    }

    #[test]
    fn invalid_network_is_rejected_before_pipeline_dispatch_or_path_locks() {
        let mut store = V2Store::open_in_memory().unwrap();
        for weight in ["S", "M"] {
            let mut task = sample_plan_task(&format!("INVALID-{weight}"));
            task.weight = weight.into();
            task.context_pack.network = Some("all".into());
            let task = store.upsert_task(&task).unwrap();
            let mut mock = MockStageExecutor::default();
            let result = if weight == "S" {
                execute_xs_s_pipeline_with_executor_and_ws_task(
                    &mut store,
                    &task.task_id,
                    &mut mock,
                    Path::new("/missing/ws-task"),
                )
            } else {
                execute_m_l_pipeline_with_executor_and_ws_task(
                    &mut store,
                    &task.task_id,
                    &mut mock,
                    Path::new("/missing/ws-task"),
                )
            };
            assert!(result.unwrap_err().contains("context_pack.network"));
            assert!(mock.executed_specs.is_empty());
            assert_eq!(store.get_task(&task.task_id).unwrap().unwrap(), task);
        }
    }

    #[test]
    fn network_yaml_roundtrip_preserves_offline_boundary_and_invalid_values_fail_resolution() {
        let mut task = sample_plan_task("NETWORK");
        let mut pack = sample_context_pack("M");
        pack.network = Some("provider-api".into());
        task.context_pack.network = Some("none".into());
        let merged = merge_plan_context(&task, pack.clone()).unwrap();
        assert_eq!(merged.network.as_deref(), Some("none"));
        pack.network = Some("bogus".into());
        assert!(merge_plan_context(&task, pack).is_err());
        let markdown = plan_with_context(
            "## [PLAN]\n```yaml\nweight: M\ntarget_files: []\n```\n",
            &merged,
        )
        .unwrap();
        assert_eq!(
            extract_and_parse_context_pack_yaml(&markdown)
                .unwrap()
                .network
                .as_deref(),
            Some("none")
        );
        assert_eq!(
            classify_failure_class(
                "impl",
                "FAILED",
                "ISOLATION_PREFLIGHT_FAILED: forbidden policy"
            ),
            FAILURE_CLASS_INFRA
        );
    }

    #[test]
    fn zach027_ac1_all_four_prompts_budget_unicode_and_retain_schema_and_sections() {
        let mut task = sample_plan_task("ZACH-027-PROMPTS");
        let huge = "🦀é".repeat(30_000);
        task.memory.approved_plan = Some(format!("approved marker {huge}"));
        task.memory.last_plan_review_findings = Some(format!("plan finding marker {huge}"));
        task.memory.last_review_findings = Some(format!("review finding marker {huge}"));
        task.memory.last_check_failure = Some(huge.clone());
        task.context_pack.acceptance_criteria[0].description = format!("AC marker {huge}");
        task.context_pack.target_files[0].summary = huge.clone();
        let diff = ReviewedDiffContext {
            diff_excerpt: huge.clone(),
            ..Default::default()
        };
        let prompts = [
            build_plan_prompt(&task, "/wt"),
            build_plan_review_prompt(&task, "/wt", &format!("candidate marker {huge}")),
            build_impl_prompt(&task, "/wt"),
            build_pr_review_prompt(&task, "/wt", &diff),
        ];
        for prompt in &prompts {
            assert!(prompt.chars().count() <= MAX_WORKER_PROMPT_CHARS);
            assert!(prompt.encode_utf16().count() <= MAX_WORKER_PROMPT_CHARS);
            assert!(prompt.contains("## Context Pack:"));
            assert!(prompt.contains("## Acceptance Criteria:\n- AC-1: AC marker"));
        }
        assert!(prompts[0].contains("governance-planner"));
        assert!(prompts[0].contains("plan finding marker"));
        assert!(prompts[1].contains("governance-plan-reviewer"));
        assert!(prompts[1].contains("candidate marker"));
        assert!(prompts[2].contains("approved marker"));
        assert!(prompts[3].contains("approved marker"));
        for index in [1, 3] {
            assert!(prompts[index].contains(&review_verdict_json_schema_string()));
        }
        assert!(
            governance_skill_from_root(Path::new("/nonexistent-governance"), "governance-planner")
                .contains("read-only")
        );
        assert!(
            governance_skill_from_root(
                Path::new("/nonexistent-governance"),
                "governance-plan-reviewer"
            )
            .contains("ReviewVerdict")
        );
    }

    #[test]
    fn zach027_ac3_yaml_subset_multiblock_quotes_comments_and_invariants() {
        let text = "```yaml\nunrelated: true\n```\n```text\ntarget_files: []\n```\n## [PLAN]\n```yml\nweight: 'L' # escalate\ntarget_files:\n  - path: \"src/v2/pipeline.rs\" # owner\n    action: modify\n    summary: 'it''s # quoted: text'\n  - src/v2/runner.rs\nforbidden_paths:\n  - '.github/workflows/**' # preserve\nworker_checks:\n  - 'cargo test'\ngate_checks: []\nhuman_operations: []\nverification_commands:\n  - \"cargo fmt --check\"\nacceptance_criteria:\n  - id: AC-2\n    description: \"extra: criterion # preserved\"\n```\n";
        let task = sample_plan_task("ZACH-027-YAML");
        let parsed = extract_and_parse_context_pack_yaml(text).unwrap();
        assert_eq!(parsed.target_files[0].summary, "it's # quoted: text");
        assert_eq!(parsed.target_files[1].path, "src/v2/runner.rs");
        let merged = merge_plan_context(&task, parsed).unwrap();
        assert_eq!(merged.weight, "L");
        assert!(merged.forbidden_paths.contains(&"src/ledger/**".to_owned()));
        assert_eq!(merged.worker_checks, task.context_pack.worker_checks);
        assert_eq!(merged.gate_checks, task.context_pack.gate_checks);
        assert_eq!(merged.acceptance_criteria.len(), 2);
        assert_eq!(
            extract_and_parse_context_pack_yaml(&plan_with_context(text, &merged).unwrap())
                .unwrap(),
            merged
        );
        for bad in [
            "```yaml\ntarget_files: []\n",
            "```yaml\ntarget_files: [foo]\n```",
            "```yaml\ntarget_files: []\nweight: M\nweight: L\n```",
            "```yaml\ntarget_files:\n  - path: foo\n    unknown: field\n```",
            "```yaml\ntarget_files:\n  - path: 'unterminated\n```",
        ] {
            assert!(
                extract_and_parse_context_pack_yaml(bad).is_err(),
                "accepted {bad}"
            );
        }
        for path in [
            "src/ledger/store.rs",
            ".github/workflows/test.yml",
            "../escape",
            "/absolute",
            "src/*",
        ] {
            let mut pack = task.context_pack.clone();
            pack.target_files[0].path = path.to_owned();
            assert!(merge_plan_context(&task, pack).is_err(), "accepted {path}");
        }
        let mut pack = task.context_pack.clone();
        pack.forbidden_paths.clear();
        assert!(merge_plan_context(&task, pack).is_err());
        let mut pack = task.context_pack.clone();
        pack.target_files.clear();
        assert!(merge_plan_context(&task, pack).is_err());
        let mut pack = task.context_pack.clone();
        pack.weight = "S".to_owned();
        assert_eq!(merge_plan_context(&task, pack).unwrap().weight, "M");
    }

    #[test]
    fn zach027_plan_review_schema_coverage_consistency_and_plan_citations() {
        let task = sample_plan_task("ZACH-027-SCHEMA");
        let pack = task.context_pack.clone();
        for file in ["plan:1", "/virtual/candidate.md:5", "src/v2/router.rs:500"] {
            let verdict = approved_verdict_json("AC-1", file);
            validate_plan_review_verdict(&verdict, &task, &pack, "/virtual/candidate.md", "/wt")
                .unwrap();
        }
        let original: serde_json::Value =
            serde_json::from_str(&approved_verdict_json("AC-1", "plan:1")).unwrap();
        for variant in 0..7 {
            let mut bad = original.clone();
            match variant {
                0 => bad["extra"] = true.into(),
                1 => bad["ac_results"] = serde_json::json!([]),
                2 => bad["ac_results"][0]["status"] = "FAIL".into(),
                3 => bad["ac_results"][0]["line"] = 0.into(),
                4 => bad["ac_results"][0]["file"] = "../escape".into(),
                5 => {
                    bad["findings"] = serde_json::json!([{"severity":"blocking","file":"plan","line":1,"summary":"unsafe"}])
                }
                _ => bad["ac_results"][0]["file"] = "missing.rs".into(),
            }
            assert!(
                validate_plan_review_verdict(
                    &bad.to_string(),
                    &task,
                    &pack,
                    "/virtual/candidate.md",
                    "/wt"
                )
                .is_err()
            );
        }
        assert!(
            validate_plan_review_verdict("APPROVED", &task, &pack, "candidate", "/wt").is_err()
        );
    }

    #[test]
    fn zach027_ac2_ac3_plan_scope_publication_and_live_l_gates() {
        let mut store = V2Store::open_in_memory().unwrap();
        let task = sample_plan_task("ZACH-027-SCOPE");
        store.upsert_task(&task).unwrap();
        let mut pack = task.context_pack.clone();
        pack.weight = "L".to_owned();
        pack.target_files = vec![TargetFileSpec {
            path: "src/v2/pipeline.rs".to_owned(),
            ..Default::default()
        }];
        let candidate = plan_with_context(
            "## [PLAN]\nThread all stages.\n```yaml\ntarget_files: []\n```\n",
            &pack,
        )
        .unwrap();
        let mut mock = MockStageExecutor {
            staged_results: vec![
                plan_result(candidate.clone()),
                plan_result(approved_verdict_json("AC-1", "plan:1")),
            ],
            ..Default::default()
        };
        let stub = StubWsTask::passthrough_clean("zach027-plan-scope");
        let paused = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            &task.task_id,
            &mut mock,
            stub.path(),
        )
        .unwrap();
        assert_eq!(paused.current_stage.as_deref(), Some("human-plan-approval"));
        assert_eq!(paused.weight, "L");
        assert_eq!(paused.required_stages, default_required_stages("L"));
        assert_eq!(paused.context_pack.target_files, pack.target_files);
        assert_eq!(mock.executed_specs.len(), 2);
        assert!(mock.executed_specs[1].output_schema_json.is_some());
        assert_ne!(
            mock.executed_routes[0].family,
            mock.executed_routes[1].family
        );
        assert_eq!(mock.published_plans.len(), 1);
        assert!(mock.plan_artifacts.values().any(|p| p == &candidate));
        let (path, published) = &mock.published_plans[0];
        assert_eq!(
            paused.memory.approved_plan_artifact_path.as_deref(),
            path.to_str()
        );
        assert_eq!(
            extract_and_parse_context_pack_yaml(published).unwrap(),
            paused.context_pack
        );
        for prompt in [
            build_impl_prompt(&paused, "/wt"),
            build_pr_review_prompt(&paused, "/wt", &ReviewedDiffContext::default()),
        ] {
            assert!(prompt.contains("Thread all stages."));
        }
        let diff = vec![DiffFileEntry {
            path: "src/v2/pipeline.rs".to_owned(),
            status: "M".to_owned(),
            added_lines: 1,
            deleted_lines: 0,
        }];
        assert!(!matches!(
            verify_worktree_diff_with("zach", "L", &paused.context_pack, &diff, stub.path())
                .unwrap(),
            DiffCheckOutcome::OutOfScopeFiles { .. }
        ));
        let old_diff = vec![DiffFileEntry {
            path: "src/v2/router.rs".to_owned(),
            ..diff[0].clone()
        }];
        assert!(matches!(
            verify_worktree_diff_with("zach", "L", &paused.context_pack, &old_diff, stub.path())
                .unwrap(),
            DiffCheckOutcome::OutOfScopeFiles { .. }
        ));

        store
            .resolve_decision("dec-zach-027-scope-plan-approval", "Approve", "test", None)
            .unwrap();
        let mut implementation = plan_result("implementation".to_owned());
        implementation.diff_files = diff;
        mock.staged_results = vec![
            implementation,
            plan_result(approved_verdict_json("AC-1", "src/v2/pipeline.rs:1")),
        ];
        let paused = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            &task.task_id,
            &mut mock,
            stub.path(),
        )
        .unwrap();
        assert_eq!(
            paused.current_stage.as_deref(),
            Some("human-merge-approval")
        );
        assert_eq!(mock.published_plans.len(), 1);
        assert!(mock.executed_specs[2].prompt.contains("Thread all stages."));
        assert!(mock.executed_specs[3].prompt.contains("Thread all stages."));
    }

    #[test]
    fn zach027_changes_requested_replans_without_process_retry_and_blocks_at_limit() {
        let mut store = V2Store::open_in_memory().unwrap();
        let task = sample_plan_task("ZACH-027-REWORK");
        store.upsert_task(&task).unwrap();
        let mut changes: serde_json::Value =
            serde_json::from_str(&approved_verdict_json("AC-1", "plan:1")).unwrap();
        changes["verdict"] = "CHANGES_REQUESTED".into();
        changes["ac_results"][0]["status"] = "FAIL".into();
        changes["summary"] = format!("clarify scope {}", "é".repeat(2000)).into();
        let mut mock = MockStageExecutor::default();
        for _ in 0..=MAX_PLAN_REWORK_CYCLES {
            mock.staged_results.push(plan_result(plan_fixture("M")));
            mock.staged_results.push(plan_result(changes.to_string()));
        }
        let stub = StubWsTask::passthrough_clean("zach027-rework");
        let paused = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            &task.task_id,
            &mut mock,
            stub.path(),
        )
        .unwrap();
        assert_eq!(paused.status, "Blocked");
        assert_eq!(paused.retry_count, 0);
        assert_eq!(paused.memory.plan_rework_count, MAX_PLAN_REWORK_CYCLES);
        assert!(
            paused
                .memory
                .last_plan_review_findings
                .as_ref()
                .unwrap()
                .len()
                <= MAX_SUMMARY_BYTES
        );
        assert!(paused.memory.approved_plan.is_none());
        assert!(mock.published_plans.is_empty());
        assert!(mock.executed_specs[2].prompt.contains("clarify scope"));
        assert!(
            store
                .list_decisions(true, None)
                .unwrap()
                .iter()
                .any(|d| d.kind == "plan_rework_limit")
        );
        assert!(
            store
                .list_stage_attempts(&task.task_id)
                .unwrap()
                .iter()
                .all(|a| a.status == "PASSED" && a.failure_class.is_none())
        );
    }

    #[test]
    fn zach027_rework_can_approve_and_full_artifact_reaches_downstream_prompts() {
        let mut store = V2Store::open_in_memory().unwrap();
        let task = sample_plan_task("ZACH-027-REWORK-APPROVE");
        store.upsert_task(&task).unwrap();
        let mut changes: serde_json::Value =
            serde_json::from_str(&approved_verdict_json("AC-1", "plan:1")).unwrap();
        changes["verdict"] = "CHANGES_REQUESTED".into();
        changes["summary"] = "Add the missing late step".into();
        let approved_plan = format!(
            "{}\n{}\nlate step: test the full artifact",
            plan_fixture("M"),
            "padding ".repeat(400)
        );
        let mut implementation = plan_result("implementation".to_owned());
        implementation.diff_files = vec![DiffFileEntry {
            path: "src/v2/router.rs".to_owned(),
            status: "M".to_owned(),
            added_lines: 1,
            deleted_lines: 0,
        }];
        let mut mock = MockStageExecutor {
            staged_results: vec![
                plan_result(plan_fixture("M")),
                plan_result(changes.to_string()),
                plan_result(approved_plan),
                plan_result(approved_verdict_json("AC-1", "plan:1")),
                implementation,
                plan_result(approved_verdict_json("AC-1", "src/v2/router.rs:1")),
            ],
            ..Default::default()
        };
        let stub = StubWsTask::passthrough_clean("zach027-rework-approve");
        let done = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            &task.task_id,
            &mut mock,
            stub.path(),
        )
        .unwrap();
        assert_eq!(done.status, "Queued for Merge");
        assert_eq!(done.retry_count, 0);
        assert_eq!(done.memory.plan_rework_count, 1);
        assert!(done.memory.last_plan_review_findings.is_none());
        assert_eq!(mock.published_plans.len(), 1);
        let excerpt = done.memory.approved_plan.as_ref().unwrap();
        assert!(excerpt.len() <= MAX_APPROVED_PLAN_BYTES);
        assert!(!excerpt.contains("late step: test the full artifact"));
        for index in [4, 5] {
            assert!(
                mock.executed_specs[index]
                    .prompt
                    .contains("late step: test the full artifact")
            );
        }
    }

    #[test]
    fn zach027_invalid_or_missing_full_plan_never_reaches_review_or_publication() {
        for text in [
            None,
            Some("summary-only plan".to_owned()),
            Some("```yaml\nweight: M\ntarget_files: []\n```".to_owned()),
        ] {
            let mut store = V2Store::open_in_memory().unwrap();
            let task = sample_plan_task("ZACH-027-BAD-CANDIDATE");
            store.upsert_task(&task).unwrap();
            let mut result = plan_result(String::new());
            result.stage_output = text;
            let mut mock = MockStageExecutor {
                staged_results: vec![result],
                ..Default::default()
            };
            let stub = StubWsTask::passthrough_clean("zach027-bad-candidate");
            assert!(
                execute_m_l_pipeline_with_executor_and_ws_task(
                    &mut store,
                    &task.task_id,
                    &mut mock,
                    stub.path()
                )
                .is_err()
            );
            assert_eq!(mock.executed_specs.len(), 1);
            assert!(mock.published_plans.is_empty());
            let saved = store.get_task(&task.task_id).unwrap().unwrap();
            assert!(saved.memory.approved_plan.is_none());
            assert!(!saved.stages_completed.contains(&"plan".to_owned()));
            assert_eq!(
                store.list_stage_attempts(&task.task_id).unwrap()[0].status,
                "FAILED"
            );
        }
    }

    #[test]
    fn zach027_plan_fallback_records_actual_author_for_cross_family_review_on_resume() {
        let mut store = V2Store::open_in_memory().unwrap();
        let mut task = sample_plan_task("ZACH-027-FALLBACK");
        task.retry_count = 1; // M plan retries route to Gemini.
        task.memory
            .recent_attempts
            .push("[AGY_INFRA:AGY_TIMEOUT] stage=plan".to_owned());
        store.upsert_task(&task).unwrap();
        let mut failed = plan_result("provider failure".to_owned());
        failed.status = "FAILED".to_owned();
        failed.summary = "AGY_STATUS provider unavailable".to_owned();
        let mut mock = MockStageExecutor {
            staged_results: vec![
                failed,
                plan_result(plan_fixture("L")),
                plan_result(approved_verdict_json("AC-1", "plan:1")),
            ],
            ..Default::default()
        };
        let stub = StubWsTask::passthrough_clean("zach027-plan-fallback");
        let paused = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            &task.task_id,
            &mut mock,
            stub.path(),
        )
        .unwrap();
        assert_eq!(paused.current_stage.as_deref(), Some("human-plan-approval"));
        assert_eq!(mock.executed_routes[0].family, ModelFamily::GeminiAgy);
        assert_eq!(mock.executed_routes[1].family, ModelFamily::OpenAiSol);
        assert_eq!(mock.executed_routes[2].family, ModelFamily::GeminiAgy);
        assert_eq!(
            resolve_author_family(&store, &task.task_id, "plan", None).unwrap(),
            ModelFamily::OpenAiSol
        );
        let attempts = store.list_stage_attempts(&task.task_id).unwrap();
        assert_eq!(attempts.iter().filter(|a| a.stage == "plan").count(), 2);
        let actual = attempts
            .iter()
            .find(|a| a.stage == "plan" && a.status == "PASSED")
            .unwrap();
        assert_eq!(infer_model_family(&actual.model), ModelFamily::OpenAiSol);
        assert!(actual.attempt_id.contains("plan-fb"));
        assert!(
            paused
                .memory
                .candidate_plan_artifact_path
                .as_ref()
                .unwrap()
                .contains(&actual.attempt_id)
        );
    }

    #[test]
    fn zach027_resume_uses_persisted_author_and_publication_fails_closed() {
        let mut store = V2Store::open_in_memory().unwrap();
        let mut task = sample_plan_task("ZACH-027-RESUME");
        task.stages_completed.push("plan".to_owned());
        let mut mock = MockStageExecutor::default();
        let candidate = mock
            .persist_plan_artifact(&task, "old-attempt", &plan_fixture("M"))
            .unwrap();
        task.memory.candidate_plan_artifact_path = Some(candidate.to_string_lossy().into_owned());
        store.upsert_task(&task).unwrap();
        store
            .record_stage_attempt(&StageAttemptRecord {
                attempt_id: "old-attempt".to_owned(),
                task_id: task.task_id.clone(),
                stage: "plan".to_owned(),
                model: "gemini-4-argon-high".to_owned(),
                effort: "high".to_owned(),
                systemd_unit: None,
                invocation_id: None,
                started_epoch: 1,
                ended_epoch: Some(2),
                status: "PASSED".to_owned(),
                failure_class: None,
                summary: Some("truncated".to_owned()),
                input_tokens: None,
                output_tokens: None,
                total_tokens: None,
                sha_before: None,
                sha_after: None,
            })
            .unwrap();
        mock.staged_results
            .push(plan_result(approved_verdict_json("AC-1", "plan:1")));
        mock.publish_plan_error = Some("publication unavailable".to_owned());
        let stub = StubWsTask::passthrough_clean("zach027-resume");
        let error = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            &task.task_id,
            &mut mock,
            stub.path(),
        )
        .unwrap_err();
        assert!(error.contains("publication unavailable"));
        assert_eq!(mock.executed_routes[0].family, ModelFamily::OpenAiSol);
        assert_eq!(mock.executed_specs.len(), 1);
        assert!(
            mock.executed_specs[0]
                .prompt
                .contains("Step 1: update router")
        );
        let saved = store.get_task(&task.task_id).unwrap().unwrap();
        assert!(!saved.stages_completed.contains(&"plan-review".to_owned()));
        assert!(saved.memory.approved_plan.is_none());
        // Without an opposite-family AGY reviewer, a resumed OpenAI-authored plan pauses.
        let mut task = saved;
        task.task_id = "ZACH-027-NO-REVIEWER".to_owned();
        task.retry_count = 0;
        task.memory.recent_attempts =
            vec!["[AGY_INFRA:AGY_STATUS] stage=plan-review".to_owned(); 2];
        task.version = 1;
        store.upsert_task(&task).unwrap();
        let paused = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            &task.task_id,
            &mut mock,
            stub.path(),
        )
        .unwrap();
        assert_eq!(paused.status, "Blocked");
        assert_eq!(mock.executed_specs.len(), 1);
    }

    fn plan_fixture(weight: &str) -> String {
        plan_with_context(
            "## [PLAN]\nStep 1: update router\n```yaml\ntarget_files: []\n```\n",
            &sample_context_pack(weight),
        )
        .unwrap()
    }

    fn sample_context_pack(weight: &str) -> ContextPackSpec {
        ContextPackSpec {
            network: None,
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

    struct StubWsTask {
        _dir: std::path::PathBuf,
        bin_path: std::path::PathBuf,
    }

    impl StubWsTask {
        fn from_python(label: &str, body: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "zach_ws_task_stub_{label}_{}_{}",
                std::process::id(),
                seq
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create stub dir");
            let bin_path = dir.join("ws-task");
            std::fs::write(&bin_path, body).expect("write stub script");
            std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod stub script");
            Self {
                _dir: dir,
                bin_path,
            }
        }

        fn passthrough_clean(label: &str) -> Self {
            Self::from_python(
                label,
                r#"#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
repo = args[args.index("--repo") + 1] if "--repo" in args else "zach"
req = args[args.index("--requested") + 1] if "--requested" in args else "XS"
stages = {
    "XS": ["impl"],
    "S": ["impl", "pr-review"],
    "M": ["plan", "plan-review", "impl", "pr-review"],
    "L": ["plan", "plan-review", "human-plan-approval", "impl", "pr-review", "human-merge-approval"],
}.get(req, ["impl"])
print(json.dumps({
    "repository": repo,
    "requested_weight": req,
    "floor_weight": req,
    "effective_weight": req,
    "escalated": False,
    "required_stages": stages,
    "reasons": ["[stub] clean"],
}))
"#,
            )
        }

        fn fixed_json(label: &str, json_output: &str) -> Self {
            let escaped = serde_json::to_string(json_output).unwrap();
            Self::from_python(
                label,
                &format!("#!/usr/bin/env python3\nprint({escaped})\n"),
            )
        }

        fn failing(label: &str, exit_code: i32, stderr: &str) -> Self {
            let escaped = serde_json::to_string(stderr).unwrap();
            Self::from_python(
                label,
                &format!(
                    "#!/usr/bin/env python3\nimport sys\nsys.stderr.write({escaped})\nsys.exit({exit_code})\n"
                ),
            )
        }

        fn path(&self) -> &Path {
            &self.bin_path
        }
    }

    impl Drop for StubWsTask {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self._dir);
        }
    }

    #[test]
    fn verify_worktree_diff_enforces_forbidden_paths_target_files_and_weight_escalation() {
        let pack = sample_context_pack("XS");
        let clean_stub = StubWsTask::passthrough_clean("diff-clean");

        // 1. Forbidden path (.github/workflows/ci.yml)
        let forbidden_diff = vec![DiffFileEntry {
            path: ".github/workflows/ci.yml".to_owned(),
            status: "M".to_owned(),
            added_lines: 2,
            deleted_lines: 1,
        }];
        assert_eq!(
            verify_worktree_diff_with("zach", "XS", &pack, &forbidden_diff, clean_stub.path())
                .unwrap(),
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
            verify_worktree_diff_with("zach", "XS", &pack, &oos_diff, clean_stub.path()).unwrap(),
            DiffCheckOutcome::OutOfScopeFiles {
                files: vec!["src/other.rs".to_owned()],
            }
        );

        // 3. Clean XS diff
        let clean_xs = vec![DiffFileEntry {
            path: "src/v2/router.rs".to_owned(),
            status: "M".to_owned(),
            added_lines: 10,
            deleted_lines: 2,
        }];
        assert_eq!(
            verify_worktree_diff_with("zach", "XS", &pack, &clean_xs, clean_stub.path()).unwrap(),
            DiffCheckOutcome::Clean
        );

        // 4. XS escalates to S when ws-task returns effective_weight = S
        let s_stub = StubWsTask::fixed_json(
            "xs-to-s",
            r#"{"repository":"zach","requested_weight":"XS","floor_weight":"S","effective_weight":"S","escalated":true,"required_stages":["impl","pr-review"],"reasons":["[S] modifies executable code above ceiling"]}"#,
        );
        let s_diff = vec![DiffFileEntry {
            path: "src/v2/router.rs".to_owned(),
            status: "M".to_owned(),
            added_lines: 45,
            deleted_lines: 15,
        }];
        match verify_worktree_diff_with("zach", "XS", &pack, &s_diff, s_stub.path()).unwrap() {
            DiffCheckOutcome::WeightEscalated {
                from_weight,
                to_weight,
                required_stages,
                ..
            } => {
                assert_eq!(from_weight, "XS");
                assert_eq!(to_weight, "S");
                assert_eq!(required_stages, vec!["impl", "pr-review"]);
            }
            other => panic!("expected WeightEscalated XS -> S, got {other:?}"),
        }

        // 5. S escalates to M when ws-task returns effective_weight = M
        let m_stub = StubWsTask::fixed_json(
            "s-to-m",
            r#"{"repository":"zach","requested_weight":"S","floor_weight":"M","effective_weight":"M","escalated":true,"required_stages":["plan","plan-review","impl","pr-review"],"reasons":["[M] adds 1 new code/config file(s)"]}"#,
        );
        let created_diff = vec![DiffFileEntry {
            path: "src/v2/router.rs".to_owned(),
            status: "A".to_owned(),
            added_lines: 20,
            deleted_lines: 0,
        }];
        match verify_worktree_diff_with("zach", "S", &pack, &created_diff, m_stub.path()).unwrap() {
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

    fn assert_merge_queue_completes_task(
        store: &mut V2Store,
        repo: &str,
        task_id: &str,
        pr_number: i64,
        merge_sha: &str,
    ) {
        let semaphore = crate::v2::scheduler::HeavyCheckSemaphore::new();
        let mut merge_driver = crate::v2::merge_queue::tests::MockMergeDriver {
            origin_default_sha: Some(format!("{task_id}-merge-head")),
            merge_pr_result: Some(merge_sha.to_owned()),
            ..Default::default()
        };
        let ci_cfg = crate::v2::merge_queue::CiPollConfig {
            timeout: std::time::Duration::from_secs(30),
            poll_interval: std::time::Duration::from_secs(10),
        };
        let outcome = crate::v2::merge_queue::process_repo_merge_queue_with_config(
            store,
            repo,
            &mut merge_driver,
            &semaphore,
            ci_cfg,
            |_| {},
        )
        .expect("merge queue should succeed");
        assert_eq!(
            outcome,
            crate::v2::merge_queue::MergeQueueOutcome::Merged {
                task_id: task_id.to_owned(),
                pr_number,
                merge_sha: merge_sha.to_owned(),
            }
        );
        let merged = store.get_task(task_id).unwrap().unwrap();
        assert_eq!(merged.status, "Done");
        assert!(store.list_merge_queue(Some(repo)).unwrap().is_empty());
        assert!(store.list_path_locks(Some(repo)).unwrap().is_empty());
    }

    fn approved_verdict_json(ac_id: &str, file_line: &str) -> String {
        let (file, line_str) = file_line
            .rsplit_once(':')
            .expect("test file_line must be path:line");
        let line: u32 = line_str.parse().expect("valid line number");
        serde_json::json!({
            "verdict": "APPROVED",
            "ac_results": [{
                "id": ac_id,
                "status": "PASS",
                "file": file,
                "line": line,
                "evidence": "cargo test"
            }],
            "findings": [],
            "summary": "All acceptance criteria verified against the reviewed diff."
        })
        .to_string()
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
                    stage_output: None,
                    review_output: None,
                    invocation_id: Some("inv-1".to_owned()),
                    input_tokens: Some(12_000),
                    output_tokens: Some(3_000),
                    total_tokens: Some(15_000),
                    sha_before: Some("abc1234".to_owned()),
                    sha_after: Some("abc1234".to_owned()),
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
                    review_markdown: None,
                    stage_output: None,
                    review_output: Some(approved_verdict_json("AC-1", "src/v2/router.rs:10")),
                    invocation_id: Some("inv-2".to_owned()),
                    input_tokens: Some(8_000),
                    output_tokens: Some(1_500),
                    total_tokens: Some(9_500),
                    sha_before: Some("def5678".to_owned()),
                    sha_after: Some("def5678".to_owned()),
                    diff_files: Vec::new(),
                },
            ],
            committed_sha_to_return: Some("def5678".to_owned()),
            ..MockStageExecutor::default()
        };

        let ws_stub = StubWsTask::passthrough_clean("zach-005");
        let queued = execute_xs_s_pipeline_with_executor_and_ws_task(
            &mut store,
            "ZACH-005",
            &mut mock,
            ws_stub.path(),
        )
        .expect("pipeline should succeed and enqueue for merge");

        assert_eq!(queued.status, "Queued for Merge");
        assert_eq!(queued.current_stage.as_deref(), Some("merge_queue"));
        assert_eq!(queued.reviewed_sha.as_deref(), Some("def5678"));
        assert_eq!(queued.pr_number, Some(42));
        assert_eq!(
            queued.stages_completed,
            vec!["impl".to_owned(), "pr-review".to_owned()]
        );
        assert_eq!(mock.executed_gate_checks, task.context_pack.gate_checks);
        assert!(
            mock.executed_checks
                .iter()
                .any(|check| task.context_pack.worker_checks.contains(check))
        );
        assert_eq!(mock.executed_routes.len(), 2);
        // Verify cross-model family separation between impl and pr-review
        assert_eq!(mock.executed_routes[0].family, ModelFamily::OpenAiSol);
        assert_eq!(mock.executed_routes[1].family, ModelFamily::GeminiAgy);
        assert_eq!(
            mock.executed_stage_reviewed_shas,
            vec![None, Some("def5678".to_owned())]
        );
        assert_eq!(mock.finalized_sha.as_deref(), Some("def5678"));

        // Verify merge queue entry exists and path locks remain held until merge completes
        let mq = store.list_merge_queue(Some("zach")).unwrap();
        assert_eq!(mq.len(), 1);
        assert_eq!(mq[0].task_id, "ZACH-005");
        assert_eq!(mq[0].pr_number, 42);
        assert_eq!(mq[0].reviewed_sha, "def5678");
        assert_eq!(mq[0].state, "QUEUED");
        assert_eq!(store.list_path_locks(Some("zach")).unwrap().len(), 2);

        // Done only occurs after merge_queue succeeds
        assert_merge_queue_completes_task(&mut store, "zach", "ZACH-005", 42, "final-merge-sha");
    }

    #[test]
    fn execute_xs_pipeline_enqueues_for_merge_and_marks_done_only_after_merge() {
        let mut store = V2Store::open_in_memory().expect("in-memory store");
        let task = TaskRecord {
            task_id: "ZACH-023-XS".to_owned(),
            task_group: "zach".to_owned(),
            title: "XS pipeline test".to_owned(),
            repository: "zach".to_owned(),
            github_repo: Some("shockerqt/zach".to_owned()),
            issue_number: Some(56),
            weight: "XS".to_owned(),
            status: "Ready".to_owned(),
            worktree_path: Some("/home/ubuntu/workspace/zach--ZACH-023-XS".to_owned()),
            branch: Some("task/ZACH-023-XS".to_owned()),
            context_pack: sample_context_pack("XS"),
            depends_on: Vec::new(),
            required_stages: vec!["impl".to_owned()],
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
            staged_results: vec![StageExecutionResult {
                status: "PASSED".to_owned(),
                summary: "Implemented XS change".to_owned(),
                review_markdown: None,
                stage_output: None,
                review_output: None,
                invocation_id: Some("inv-xs-1".to_owned()),
                input_tokens: Some(4_000),
                output_tokens: Some(800),
                total_tokens: Some(4_800),
                sha_before: Some("abc1234".to_owned()),
                sha_after: Some("xs-sha-1".to_owned()),
                diff_files: vec![DiffFileEntry {
                    path: "src/v2/router.rs".to_owned(),
                    status: "M".to_owned(),
                    added_lines: 5,
                    deleted_lines: 2,
                }],
            }],
            committed_sha_to_return: Some("xs-sha-1".to_owned()),
            pr_number_to_return: Some(77),
            ..MockStageExecutor::default()
        };

        let ws_stub = StubWsTask::passthrough_clean("zach-023-xs");
        let queued = execute_xs_s_pipeline_with_executor_and_ws_task(
            &mut store,
            "ZACH-023-XS",
            &mut mock,
            ws_stub.path(),
        )
        .expect("XS pipeline should enqueue for merge");

        assert_eq!(queued.status, "Queued for Merge");
        assert_eq!(queued.current_stage.as_deref(), Some("merge_queue"));
        assert_eq!(queued.reviewed_sha.as_deref(), Some("xs-sha-1"));
        assert_eq!(queued.pr_number, Some(77));
        assert_eq!(queued.stages_completed, vec!["impl".to_owned()]);

        let mq = store.list_merge_queue(Some("zach")).unwrap();
        assert_eq!(mq.len(), 1);
        assert_eq!(mq[0].task_id, "ZACH-023-XS");
        assert_eq!(mq[0].pr_number, 77);
        assert_eq!(mq[0].reviewed_sha, "xs-sha-1");
        assert_eq!(mq[0].state, "QUEUED");
        assert_eq!(store.list_path_locks(Some("zach")).unwrap().len(), 2);

        assert_merge_queue_completes_task(&mut store, "zach", "ZACH-023-XS", 77, "xs-final-sha");
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
                    stage_output: Some(plan_fixture("M")),
                    review_output: None,
                    invocation_id: Some("inv-plan".to_owned()),
                    input_tokens: Some(10_000),
                    output_tokens: Some(2_000),
                    total_tokens: Some(12_000),
                    sha_before: None,
                    sha_after: None,
                    diff_files: Vec::new(),
                },
                // 2. plan-review
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Plan review approved".to_owned(),
                    review_markdown: None,
                    stage_output: Some(approved_verdict_json("AC-1", "plan:1")),
                    review_output: None,
                    invocation_id: Some("inv-plan-review".to_owned()),
                    input_tokens: Some(8_000),
                    output_tokens: Some(1_000),
                    total_tokens: Some(9_000),
                    sha_before: None,
                    sha_after: None,
                    diff_files: Vec::new(),
                },
                // 3. impl
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Implementation complete".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: None,
                    invocation_id: Some("inv-impl".to_owned()),
                    input_tokens: Some(15_000),
                    output_tokens: Some(3_000),
                    total_tokens: Some(18_000),
                    sha_before: Some("base123".to_owned()),
                    sha_after: Some("base123".to_owned()),
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
                    review_markdown: None,
                    stage_output: None,
                    review_output: Some(approved_verdict_json("AC-1", "src/v2/router.rs:10")),
                    invocation_id: Some("inv-pr-rev".to_owned()),
                    input_tokens: Some(12_000),
                    output_tokens: Some(2_000),
                    total_tokens: Some(14_000),
                    sha_before: Some("sha-m-impl".to_owned()),
                    sha_after: Some("sha-m-impl".to_owned()),
                    diff_files: Vec::new(),
                },
            ],
            committed_sha_to_return: Some("sha-m-impl".to_owned()),
            ..MockStageExecutor::default()
        };

        let ws_stub = StubWsTask::passthrough_clean("zach-006");
        let result = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            "ZACH-006",
            &mut mock,
            ws_stub.path(),
        )
        .expect("M pipeline should execute and enqueue");

        // Verify task state
        assert_eq!(result.status, "Queued for Merge");
        assert_eq!(result.current_stage.as_deref(), Some("merge_queue"));
        assert_eq!(
            mock.executed_stage_reviewed_shas,
            vec![None, None, None, Some("sha-m-impl".to_owned())]
        );
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
                    stage_output: Some(plan_fixture("L")),
                    review_output: None,
                    invocation_id: None,
                    input_tokens: Some(1_000),
                    output_tokens: Some(500),
                    total_tokens: Some(1_500),
                    sha_before: None,
                    sha_after: None,
                    diff_files: Vec::new(),
                },
                // 2. plan-review
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "L Plan Review".to_owned(),
                    review_markdown: None,
                    stage_output: Some(approved_verdict_json("AC-1", "plan:1")),
                    review_output: None,
                    invocation_id: None,
                    input_tokens: Some(1_000),
                    output_tokens: Some(500),
                    total_tokens: Some(1_500),
                    sha_before: None,
                    sha_after: None,
                    diff_files: Vec::new(),
                },
            ],
            committed_sha_to_return: Some("sha-l-impl".to_owned()),
            ..MockStageExecutor::default()
        };

        let ws_stub = StubWsTask::passthrough_clean("zach-007-l");

        // Run 1: Should execute plan -> plan-review -> pause at human-plan-approval
        let paused_1 = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            "ZACH-007-L",
            &mut mock,
            ws_stub.path(),
        )
        .unwrap();
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
            stage_output: None,
            review_output: None,
            invocation_id: None,
            input_tokens: Some(5_000),
            output_tokens: Some(1_000),
            total_tokens: Some(6_000),
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
            review_markdown: None,
            stage_output: None,
            review_output: Some(approved_verdict_json("AC-1", "src/v2/router.rs:10")),
            invocation_id: None,
            input_tokens: Some(5_000),
            output_tokens: Some(1_000),
            total_tokens: Some(6_000),
            sha_before: Some("sha-l-impl".to_owned()),
            sha_after: Some("sha-l-impl".to_owned()),
            diff_files: Vec::new(),
        });

        // Run 2: Resumes -> executes impl -> pr-review -> pauses at human-merge-approval
        let paused_2 = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            "ZACH-007-L",
            &mut mock,
            ws_stub.path(),
        )
        .unwrap();
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
        let completed = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            "ZACH-007-L",
            &mut mock,
            ws_stub.path(),
        )
        .unwrap();
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
        assert_eq!(payload["orchestration_id"], "zach-008");
        assert_eq!(payload["allowed_files"], serde_json::json!([]));

        // 2. Test parse_agy_cli_response: success with real worker.mjs usage shape
        let ok_json = r#"{"execution_succeeded":true,"summary":"Analysis complete","usage":{"input_tokens":5000,"output_tokens":432,"total_tokens":5432},"budget":{"model_calls_used":1,"observed_total_tokens":5432,"unknown_usage_calls":0}}"#;
        let ok_res = parse_agy_cli_response(ok_json, "", Some(0)).unwrap();
        assert_eq!(ok_res.status, "PASSED");
        assert_eq!(ok_res.input_tokens, Some(5000));
        assert_eq!(ok_res.output_tokens, Some(432));
        assert_eq!(ok_res.total_tokens, Some(5432));

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
        agy_task.reviewed_sha = Some("plan-sha-008".to_owned());
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
                stage_output: Some(plan_fixture("M")),
                review_output: None,
                invocation_id: None,
                input_tokens: Some(1_000),
                output_tokens: Some(500),
                total_tokens: Some(1_500),
                sha_before: None,
                sha_after: None,
                diff_files: Vec::new(),
            }],
            ..MockStageExecutor::default()
        };

        let ws_stub = StubWsTask::passthrough_clean("zach-008");
        let completed = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            "ZACH-008",
            &mut mock,
            ws_stub.path(),
        )
        .unwrap();
        assert!(completed.stages_completed.contains(&"plan".to_owned()));

        // Verify that route was automatically switched to OpenAiSol (gpt-6.1-sol) instead of GeminiAgy
        assert_eq!(mock.executed_routes.len(), 1);
        assert_eq!(mock.executed_routes[0].family, ModelFamily::OpenAiSol);
        assert_eq!(mock.executed_routes[0].model, "gpt-6.1-sol");
    }

    #[test]
    fn validate_review_verdict_enforces_schema_acs_and_diff_hunks() {
        let mut files = std::collections::BTreeMap::new();
        files.insert(
            "src/v2/router.rs".to_owned(),
            vec![crate::v2::runner::LineRange { start: 10, end: 25 }],
        );
        let diff_ctx = crate::v2::runner::ReviewedDiffContext {
            merge_base_sha: "abc1234".to_owned(),
            reviewed_sha: "def5678".to_owned(),
            commit_range: "abc1234..def5678".to_owned(),
            files,
            diff_excerpt: String::new(),
        };
        let expected = vec!["AC-1".to_owned(), "AC-2".to_owned()];

        // 1. Valid APPROVED verdict citing diff hunk lines passes
        let valid_json = serde_json::json!({
            "verdict": "APPROVED",
            "ac_results": [
                {
                    "id": "AC-1",
                    "status": "PASS",
                    "file": "src/v2/router.rs",
                    "line": 10,
                    "evidence": "cargo test"
                },
                {
                    "id": "AC-2",
                    "status": "PASS",
                    "file": "./src/v2/router.rs",
                    "line": 25,
                    "evidence": "cargo test"
                }
            ],
            "findings": [],
            "summary": "Verified cleanly."
        })
        .to_string();
        assert!(validate_review_verdict(&valid_json, &expected, &diff_ctx, "").is_ok());

        // 2. Markdown table or free-form prose is rejected (AC-2)
        let md = "\
| AC | Criterion | Code (file:line) | Test | Status |
|---|---|---|---|---|
| AC-1 | Feature works | src/v2/router.rs:10 | cargo test | PASS |
";
        assert!(validate_review_verdict(md, &["AC-1".to_owned()], &diff_ctx, "").is_err());

        // 3. Extra unknown fields are rejected by #[serde(deny_unknown_fields)] (AC-2)
        let extra_field = serde_json::json!({
            "verdict": "APPROVED",
            "ac_results": [{
                "id": "AC-1",
                "status": "PASS",
                "file": "src/v2/router.rs",
                "line": 12,
                "evidence": "cargo test"
            }],
            "findings": [],
            "summary": "ok",
            "unexpected": true
        })
        .to_string();
        assert!(
            validate_review_verdict(&extra_field, &["AC-1".to_owned()], &diff_ctx, "").is_err()
        );

        // 4. Cited line outside reviewed diff hunks is rejected (AC-3)
        let outside_line = serde_json::json!({
            "verdict": "APPROVED",
            "ac_results": [{
                "id": "AC-1",
                "status": "PASS",
                "file": "src/v2/router.rs",
                "line": 99,
                "evidence": "cargo test"
            }],
            "findings": [],
            "summary": "bad line"
        })
        .to_string();
        let err = validate_review_verdict(&outside_line, &["AC-1".to_owned()], &diff_ctx, "")
            .unwrap_err();
        assert!(
            err.contains("outside reviewed diff hunks"),
            "unexpected err: {err}"
        );

        // 5. Finding citing file:line outside reviewed diff hunks is rejected (AC-3)
        let bad_finding = serde_json::json!({
            "verdict": "CHANGES_REQUESTED",
            "ac_results": [{
                "id": "AC-1",
                "status": "FAIL",
                "file": "src/v2/router.rs",
                "line": 12,
                "evidence": "cargo test"
            }],
            "findings": [{
                "severity": "blocking",
                "file": "src/other.rs",
                "line": 1,
                "summary": "Untouched file"
            }],
            "summary": "needs fix"
        })
        .to_string();
        assert!(
            validate_review_verdict(&bad_finding, &["AC-1".to_owned()], &diff_ctx, "").is_err()
        );

        // 6. APPROVED with FAIL ac_result or blocking finding is rejected
        let approved_with_fail = serde_json::json!({
            "verdict": "APPROVED",
            "ac_results": [{
                "id": "AC-1",
                "status": "FAIL",
                "file": "src/v2/router.rs",
                "line": 12,
                "evidence": "cargo test"
            }],
            "findings": [],
            "summary": "contradictory"
        })
        .to_string();
        assert!(
            validate_review_verdict(&approved_with_fail, &["AC-1".to_owned()], &diff_ctx, "")
                .is_err()
        );
    }

    #[test]
    fn ac1_pr_review_and_impl_prompts_include_context_and_stay_bounded() {
        let mut task = sample_s_task("ZACH-026-AC1");
        task.memory.approved_plan = Some(format!("Plan step: {}", "p".repeat(5000)));
        task.memory.last_review_findings = Some(format!("Blocking: {}", "f".repeat(2000)));
        task.memory.last_check_failure = Some("cargo test failed on test_x".to_owned());

        let mut files = std::collections::BTreeMap::new();
        files.insert(
            "src/v2/router.rs".to_owned(),
            vec![crate::v2::runner::LineRange { start: 10, end: 25 }],
        );
        let diff_ctx = crate::v2::runner::ReviewedDiffContext {
            merge_base_sha: "abc1234".to_owned(),
            reviewed_sha: "def5678".to_owned(),
            commit_range: "abc1234..def5678".to_owned(),
            files,
            diff_excerpt: format!("+changed\n{}", "+x".repeat(20_000)),
        };

        let impl_prompt = build_impl_prompt(&task, "/tmp/wt");
        assert!(impl_prompt.contains("## Approved Plan:"));
        assert!(impl_prompt.contains("## Prior Review Findings"));
        assert!(impl_prompt.contains("## Prior Check Failure:"));
        assert!(impl_prompt.len() <= MAX_WORKER_PROMPT_CHARS);

        let rev_prompt = build_pr_review_prompt(&task, "/tmp/wt", &diff_ctx);
        assert!(rev_prompt.contains("abc1234..def5678"));
        assert!(rev_prompt.contains("src/v2/router.rs: lines [10-25]"));
        assert!(rev_prompt.contains("AC-1"));
        assert!(rev_prompt.contains("## Approved Plan:"));
        assert!(rev_prompt.contains("\"ac_results\""));
        assert!(rev_prompt.contains("\"findings\""));
        assert!(rev_prompt.len() <= MAX_WORKER_PROMPT_CHARS);
    }

    #[test]
    fn ac2_parse_agy_cli_response_preserves_full_review_verdict_json_beyond_summary_cap() {
        let long_evidence = "cargo test --locked passed all 226 cases cleanly; ".repeat(30);
        let full_verdict_json = serde_json::json!({
            "verdict": "APPROVED",
            "ac_results": [{
                "id": "AC-1",
                "status": "PASS",
                "file": "src/v2/router.rs",
                "line": 12,
                "evidence": long_evidence
            }],
            "findings": [],
            "summary": "Verified complete implementation against AC-1."
        })
        .to_string();
        assert!(full_verdict_json.len() > MAX_SUMMARY_BYTES);

        let truncated_summary = truncate_utf8_bytes(&full_verdict_json, MAX_SUMMARY_BYTES);
        let agy_payload = serde_json::json!({
            "execution_succeeded": true,
            "summary": truncated_summary,
            "response": full_verdict_json,
            "usage": {
                "input_tokens": 2000,
                "output_tokens": 500,
                "total_tokens": 2500
            }
        })
        .to_string();

        let parsed = parse_agy_cli_response(&agy_payload, "", Some(0)).unwrap();
        assert_eq!(parsed.status, "PASSED");
        assert!(parsed.summary.len() <= MAX_SUMMARY_BYTES);
        assert_eq!(
            parsed.review_output.as_deref(),
            Some(full_verdict_json.as_str())
        );

        let mut files = std::collections::BTreeMap::new();
        files.insert(
            "src/v2/router.rs".to_owned(),
            vec![crate::v2::runner::LineRange { start: 10, end: 20 }],
        );
        let diff_ctx = crate::v2::runner::ReviewedDiffContext {
            merge_base_sha: "abc".to_owned(),
            reviewed_sha: "def".to_owned(),
            commit_range: "abc..def".to_owned(),
            files,
            diff_excerpt: String::new(),
        };
        let verdict = validate_review_verdict(
            parsed.review_output.as_deref().unwrap(),
            &["AC-1".to_owned()],
            &diff_ctx,
            "",
        )
        .expect("untruncated review_output should validate cleanly");
        assert_eq!(verdict.verdict, "APPROVED");
    }

    #[test]
    fn ac4_changes_requested_rework_loops_for_s_and_m_and_blocks_at_limit() {
        let ws_stub = StubWsTask::passthrough_clean("zach-026-ac4");
        let changes_requested_json = serde_json::json!({
            "verdict": "CHANGES_REQUESTED",
            "ac_results": [{
                "id": "AC-1",
                "status": "FAIL",
                "file": "src/v2/router.rs",
                "line": 10,
                "evidence": "Missing edge case handling"
            }],
            "findings": [{
                "severity": "blocking",
                "file": "src/v2/router.rs",
                "line": 12,
                "summary": "Handle empty route fallback cleanly"
            }],
            "summary": "Fix blocking finding before merge."
        })
        .to_string();

        // 1. S pipeline: impl -> pr-review (CHANGES_REQUESTED) -> rework impl -> pr-review (APPROVED)
        let mut s_store = V2Store::open_in_memory().expect("open store");
        s_store
            .upsert_task(&sample_s_task("ZACH-026-S-REWORK"))
            .unwrap();
        let mut s_mock = MockStageExecutor {
            staged_results: vec![
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Initial impl".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: None,
                    invocation_id: Some("impl-1".to_owned()),
                    input_tokens: Some(1_000),
                    output_tokens: Some(200),
                    total_tokens: Some(1_200),
                    sha_before: Some("abc1234".to_owned()),
                    sha_after: Some("sha-impl-1".to_owned()),
                    diff_files: vec![DiffFileEntry {
                        path: "src/v2/router.rs".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 10,
                        deleted_lines: 1,
                    }],
                },
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Requested changes".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: Some(changes_requested_json.clone()),
                    invocation_id: Some("rev-1".to_owned()),
                    input_tokens: Some(500),
                    output_tokens: Some(100),
                    total_tokens: Some(600),
                    sha_before: Some("mock-committed-sha".to_owned()),
                    sha_after: Some("mock-committed-sha".to_owned()),
                    diff_files: Vec::new(),
                },
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Rework impl".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: None,
                    invocation_id: Some("impl-2".to_owned()),
                    input_tokens: Some(1_000),
                    output_tokens: Some(200),
                    total_tokens: Some(1_200),
                    sha_before: Some("mock-committed-sha".to_owned()),
                    sha_after: Some("sha-impl-2".to_owned()),
                    diff_files: vec![DiffFileEntry {
                        path: "src/v2/router.rs".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 12,
                        deleted_lines: 1,
                    }],
                },
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Approved rework".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: Some(approved_verdict_json("AC-1", "src/v2/router.rs:10")),
                    invocation_id: Some("rev-2".to_owned()),
                    input_tokens: Some(500),
                    output_tokens: Some(100),
                    total_tokens: Some(600),
                    sha_before: Some("mock-committed-sha".to_owned()),
                    sha_after: Some("mock-committed-sha".to_owned()),
                    diff_files: Vec::new(),
                },
            ],
            committed_sha_to_return: Some("mock-committed-sha".to_owned()),
            ..MockStageExecutor::default()
        };
        let s_done = execute_xs_s_pipeline_with_executor_and_ws_task(
            &mut s_store,
            "ZACH-026-S-REWORK",
            &mut s_mock,
            ws_stub.path(),
        )
        .expect("S rework loop should succeed");
        assert_eq!(s_done.status, "Queued for Merge");
        assert_eq!(s_done.retry_count, 0);
        assert_eq!(s_done.memory.review_rework_count, 1);
        assert_eq!(s_done.memory.last_review_findings, None);
        assert_eq!(s_mock.executed_specs.len(), 4);
        assert!(s_mock.executed_specs[1].output_schema_json.is_some());
        assert!(
            s_mock.executed_specs[2]
                .prompt
                .contains("Handle empty route fallback cleanly")
        );
        let s_attempts = s_store.list_stage_attempts("ZACH-026-S-REWORK").unwrap();
        assert!(s_attempts.iter().all(|a| a.status == "PASSED"));

        // 2. M pipeline: plan populates approved_plan -> plan-review -> impl -> pr-review (CHANGES_REQUESTED) -> rework impl -> pr-review (APPROVED)
        let mut m_store = V2Store::open_in_memory().expect("open store");
        let mut m_task = sample_s_task("ZACH-026-M-REWORK");
        m_task.weight = "M".to_owned();
        m_task.context_pack = sample_context_pack("M");
        m_task.required_stages = vec![
            "plan".to_owned(),
            "plan-review".to_owned(),
            "impl".to_owned(),
            "pr-review".to_owned(),
        ];
        m_store.upsert_task(&m_task).unwrap();
        let long_plan = format!("{}\n{}", plan_fixture("M"), "x".repeat(3000));
        let mut m_mock = MockStageExecutor {
            staged_results: vec![
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Plan done".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: Some(long_plan),
                    invocation_id: None,
                    input_tokens: Some(500),
                    output_tokens: Some(100),
                    total_tokens: Some(600),
                    sha_before: None,
                    sha_after: None,
                    diff_files: Vec::new(),
                },
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Plan approved".to_owned(),
                    review_markdown: None,
                    stage_output: Some(approved_verdict_json("AC-1", "plan:1")),
                    review_output: None,
                    invocation_id: None,
                    input_tokens: Some(500),
                    output_tokens: Some(100),
                    total_tokens: Some(600),
                    sha_before: None,
                    sha_after: None,
                    diff_files: Vec::new(),
                },
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Impl 1".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: None,
                    invocation_id: None,
                    input_tokens: Some(500),
                    output_tokens: Some(100),
                    total_tokens: Some(600),
                    sha_before: Some("abc".to_owned()),
                    sha_after: Some("sha-1".to_owned()),
                    diff_files: vec![DiffFileEntry {
                        path: "src/v2/router.rs".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 10,
                        deleted_lines: 1,
                    }],
                },
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Changes requested".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: Some(changes_requested_json.clone()),
                    invocation_id: None,
                    input_tokens: Some(500),
                    output_tokens: Some(100),
                    total_tokens: Some(600),
                    sha_before: Some("sha-m-1".to_owned()),
                    sha_after: Some("sha-m-1".to_owned()),
                    diff_files: Vec::new(),
                },
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Impl 2".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: None,
                    invocation_id: None,
                    input_tokens: Some(500),
                    output_tokens: Some(100),
                    total_tokens: Some(600),
                    sha_before: Some("sha-m-1".to_owned()),
                    sha_after: Some("sha-2".to_owned()),
                    diff_files: vec![DiffFileEntry {
                        path: "src/v2/router.rs".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 10,
                        deleted_lines: 1,
                    }],
                },
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Approved".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: Some(approved_verdict_json("AC-1", "src/v2/router.rs:10")),
                    invocation_id: None,
                    input_tokens: Some(500),
                    output_tokens: Some(100),
                    total_tokens: Some(600),
                    sha_before: Some("sha-m-2".to_owned()),
                    sha_after: Some("sha-m-2".to_owned()),
                    diff_files: Vec::new(),
                },
            ],
            committed_sha_to_return: Some("sha-m-rework".to_owned()),
            ..MockStageExecutor::default()
        };
        let m_done = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut m_store,
            "ZACH-026-M-REWORK",
            &mut m_mock,
            ws_stub.path(),
        )
        .expect("M rework loop should succeed");
        assert_eq!(m_done.status, "Queued for Merge");
        assert_eq!(m_done.retry_count, 0);
        assert_eq!(m_done.memory.review_rework_count, 1);
        let saved_plan = m_done.memory.approved_plan.as_deref().unwrap();
        assert!(saved_plan.contains("Step 1: update router"));
        assert!(saved_plan.len() <= MAX_APPROVED_PLAN_BYTES);
        assert!(
            m_mock.executed_specs[3]
                .prompt
                .contains("Step 1: update router")
        );
        assert!(
            m_mock.executed_specs[4]
                .prompt
                .contains("Handle empty route fallback cleanly")
        );

        // 3. Exceeding MAX_REVIEW_REWORK_LOOPS pauses cleanly as Blocked with DECISION_REQUIRED and keeps path locks
        let mut limit_store = V2Store::open_in_memory().expect("open store");
        let mut limit_task = sample_s_task("ZACH-026-REWORK-LIMIT");
        limit_task.memory.review_rework_count = MAX_REVIEW_REWORK_LOOPS;
        limit_store.upsert_task(&limit_task).unwrap();
        let mut limit_mock = MockStageExecutor {
            staged_results: vec![
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Impl".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: None,
                    invocation_id: None,
                    input_tokens: Some(500),
                    output_tokens: Some(100),
                    total_tokens: Some(600),
                    sha_before: Some("abc".to_owned()),
                    sha_after: Some("sha-limit".to_owned()),
                    diff_files: vec![DiffFileEntry {
                        path: "src/v2/router.rs".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 10,
                        deleted_lines: 1,
                    }],
                },
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Still needs changes".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: Some(changes_requested_json),
                    invocation_id: None,
                    input_tokens: Some(500),
                    output_tokens: Some(100),
                    total_tokens: Some(600),
                    sha_before: Some("sha-limit".to_owned()),
                    sha_after: Some("sha-limit".to_owned()),
                    diff_files: Vec::new(),
                },
            ],
            committed_sha_to_return: Some("sha-limit".to_owned()),
            ..MockStageExecutor::default()
        };
        let paused = execute_xs_s_pipeline_with_executor_and_ws_task(
            &mut limit_store,
            "ZACH-026-REWORK-LIMIT",
            &mut limit_mock,
            ws_stub.path(),
        )
        .expect("rework limit should pause cleanly as Blocked");
        assert_eq!(paused.status, "Blocked");
        assert_eq!(paused.current_stage.as_deref(), Some("pr-review"));
        let decs = limit_store.list_decisions(true, None).unwrap();
        assert_eq!(decs.len(), 1);
        assert_eq!(decs[0].kind, "review_rework_limit");
        assert_eq!(
            decs[0].decision_id,
            "dec-zach-026-rework-limit-review-rework-2"
        );
        assert!(
            !limit_store
                .list_path_locks(Some("zach"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn ac5_missing_cross_family_reviewer_pauses_blocked_instead_of_same_family_fallback() {
        let mut store = V2Store::open_in_memory().expect("open store");
        let mut task = sample_s_task("ZACH-026-AC5");
        task.weight = "M".to_owned();
        task.context_pack = sample_context_pack("M");
        task.required_stages = vec![
            "plan".to_owned(),
            "plan-review".to_owned(),
            "impl".to_owned(),
            "pr-review".to_owned(),
        ];
        task.stages_completed = vec!["plan".to_owned(), "plan-review".to_owned()];
        // Simulate 1 prior pr-review AGY infra failure; next failure hits >= 2 and must pause Blocked
        task.memory
            .recent_attempts
            .push("[AGY_INFRA:AGY_TIMEOUT] stage=pr-review attempt=zach-026-ac5-pr-review-1 log=attempts/1/stderr.log".to_owned());
        store.upsert_task(&task).unwrap();

        let ws_stub = StubWsTask::passthrough_clean("zach-026-ac5");
        let mut mock = MockStageExecutor {
            staged_results: vec![
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "impl ok".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: None,
                    invocation_id: None,
                    input_tokens: Some(1_000),
                    output_tokens: Some(200),
                    total_tokens: Some(1_200),
                    sha_before: Some("abc".to_owned()),
                    sha_after: Some("sha-ac5".to_owned()),
                    diff_files: vec![DiffFileEntry {
                        path: "src/v2/router.rs".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 5,
                        deleted_lines: 1,
                    }],
                },
                StageExecutionResult {
                    status: "FAILED".to_owned(),
                    summary: "AGY_TIMEOUT: gemini worker timed out".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: None,
                    invocation_id: None,
                    input_tokens: None,
                    output_tokens: None,
                    total_tokens: None,
                    sha_before: None,
                    sha_after: None,
                    diff_files: Vec::new(),
                },
            ],
            committed_sha_to_return: Some("sha-ac5".to_owned()),
            ..MockStageExecutor::default()
        };

        let paused = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            "ZACH-026-AC5",
            &mut mock,
            ws_stub.path(),
        )
        .expect("missing cross-family reviewer should pause cleanly as Blocked");

        assert_eq!(paused.status, "Blocked");
        assert_eq!(paused.current_stage.as_deref(), Some("pr-review"));
        assert_eq!(mock.executed_routes.len(), 2);
        assert_eq!(mock.executed_routes[0].family, ModelFamily::OpenAiSol);
        assert_eq!(mock.executed_routes[1].family, ModelFamily::GeminiAgy);

        let decs = store.list_decisions(true, None).unwrap();
        assert_eq!(decs.len(), 1);
        assert_eq!(decs[0].kind, "cross_family_reviewer_unavailable");
        assert!(!store.list_path_locks(Some("zach")).unwrap().is_empty());

        // Also verify resolve_author_family infers author family from prior PASSED attempt on resume
        store
            .record_stage_attempt(&StageAttemptRecord {
                attempt_id: "zach-026-ac5-impl-prior".to_owned(),
                task_id: "ZACH-026-AC5".to_owned(),
                stage: "impl".to_owned(),
                model: "gemini-4-hydrogen-high".to_owned(),
                effort: "high".to_owned(),
                systemd_unit: None,
                invocation_id: None,
                started_epoch: 100,
                ended_epoch: Some(110),
                status: "PASSED".to_owned(),
                failure_class: None,
                summary: Some("ok".to_owned()),
                input_tokens: None,
                output_tokens: None,
                total_tokens: None,
                sha_before: None,
                sha_after: None,
            })
            .unwrap();
        assert_eq!(
            resolve_author_family(&store, "ZACH-026-AC5", "impl", None).unwrap(),
            ModelFamily::GeminiAgy
        );
    }

    #[test]
    fn pipeline_retains_zach_executor_and_preserves_state_across_sync() {
        // 1. XS/S pipeline stopping in In Progress retains executor = Some("zach") across sync
        let mut store = V2Store::open_in_memory().expect("open store");
        let s_task = TaskRecord {
            task_id: "ZACH-021-S".to_owned(),
            task_group: "zach".to_owned(),
            title: "S pipeline preserve test".to_owned(),
            repository: "zach".to_owned(),
            github_repo: Some("shockerqt/zach".to_owned()),
            issue_number: Some(21),
            weight: "S".to_owned(),
            status: "Ready".to_owned(),
            worktree_path: Some("/tmp/zach--ZACH-021-S".to_owned()),
            branch: Some("task/ZACH-021-S".to_owned()),
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
        store.upsert_task(&s_task).unwrap();

        let mut fail_mock = MockStageExecutor {
            staged_results: vec![StageExecutionResult {
                status: "FAILED".to_owned(),
                summary: "transient failure".to_owned(),
                review_markdown: None,
                stage_output: None,
                review_output: None,
                invocation_id: Some("inv-fail".to_owned()),
                input_tokens: Some(100),
                output_tokens: Some(50),
                total_tokens: Some(150),
                sha_before: None,
                sha_after: None,
                diff_files: Vec::new(),
            }],
            ..MockStageExecutor::default()
        };
        let ws_stub = StubWsTask::passthrough_clean("zach-021");
        assert!(
            execute_xs_s_pipeline_with_executor_and_ws_task(
                &mut store,
                "ZACH-021-S",
                &mut fail_mock,
                ws_stub.path()
            )
            .is_err()
        );

        let driven_s = store.get_task("ZACH-021-S").unwrap().unwrap();
        assert_eq!(driven_s.status, "In Progress");
        assert_eq!(driven_s.executor.as_deref(), Some("zach"));
        assert_eq!(driven_s.retry_count, 1);

        let mut board_ready_s = s_task.clone();
        board_ready_s.title = "Updated S title".to_owned();
        board_ready_s.status = "Ready".to_owned();
        board_ready_s.executor = None;
        let synced_s = store.sync_task(&board_ready_s).unwrap();
        assert_eq!(synced_s.status, "In Progress");
        assert_eq!(synced_s.current_stage.as_deref(), Some("impl"));
        assert_eq!(synced_s.executor.as_deref(), Some("zach"));
        assert_eq!(synced_s.retry_count, 1);
        assert_eq!(synced_s.title, "Updated S title");

        // 2. M pipeline reaching Queued for Merge retains executor = Some("zach") across sync
        let m_task = TaskRecord {
            task_id: "ZACH-021-M".to_owned(),
            task_group: "zach".to_owned(),
            title: "M pipeline preserve test".to_owned(),
            repository: "zach".to_owned(),
            github_repo: Some("shockerqt/zach".to_owned()),
            issue_number: Some(22),
            weight: "M".to_owned(),
            status: "Ready".to_owned(),
            worktree_path: Some("/tmp/zach--ZACH-021-M".to_owned()),
            branch: Some("task/ZACH-021-M".to_owned()),
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
        store.upsert_task(&m_task).unwrap();

        let mut ok_mock = MockStageExecutor {
            staged_results: vec![
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Plan ok".to_owned(),
                    review_markdown: None,
                    stage_output: Some(plan_fixture("M")),
                    review_output: None,
                    invocation_id: Some("inv-plan".to_owned()),
                    input_tokens: Some(1_000),
                    output_tokens: Some(200),
                    total_tokens: Some(1_200),
                    sha_before: None,
                    sha_after: None,
                    diff_files: Vec::new(),
                },
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Plan review ok".to_owned(),
                    review_markdown: None,
                    stage_output: Some(approved_verdict_json("AC-1", "plan:1")),
                    review_output: None,
                    invocation_id: Some("inv-plan-rev".to_owned()),
                    input_tokens: Some(800),
                    output_tokens: Some(100),
                    total_tokens: Some(900),
                    sha_before: None,
                    sha_after: None,
                    diff_files: Vec::new(),
                },
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Impl ok".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: None,
                    invocation_id: Some("inv-impl".to_owned()),
                    input_tokens: Some(1_500),
                    output_tokens: Some(300),
                    total_tokens: Some(1_800),
                    sha_before: Some("base123".to_owned()),
                    sha_after: Some("sha-m-impl".to_owned()),
                    diff_files: vec![DiffFileEntry {
                        path: "src/v2/router.rs".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 5,
                        deleted_lines: 1,
                    }],
                },
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "PR review ok".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: Some(approved_verdict_json("AC-1", "src/v2/router.rs:10")),
                    invocation_id: Some("inv-pr-rev".to_owned()),
                    input_tokens: Some(900),
                    output_tokens: Some(150),
                    total_tokens: Some(1_050),
                    sha_before: Some("sha-m-impl".to_owned()),
                    sha_after: Some("sha-m-impl".to_owned()),
                    diff_files: Vec::new(),
                },
            ],
            committed_sha_to_return: Some("sha-m-impl".to_owned()),
            ..MockStageExecutor::default()
        };

        let queued = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            "ZACH-021-M",
            &mut ok_mock,
            ws_stub.path(),
        )
        .expect("M pipeline should queue for merge");
        assert_eq!(queued.status, "Queued for Merge");
        assert_eq!(queued.executor.as_deref(), Some("zach"));

        let mut board_ready_m = m_task.clone();
        board_ready_m.title = "Updated M title".to_owned();
        board_ready_m.status = "Ready".to_owned();
        board_ready_m.executor = None;
        let synced_m = store.sync_task(&board_ready_m).unwrap();
        assert_eq!(synced_m.status, "Queued for Merge");
        assert_eq!(synced_m.current_stage.as_deref(), Some("merge_queue"));
        assert_eq!(
            synced_m.stages_completed,
            vec!["plan", "plan-review", "impl", "pr-review"]
        );
        assert_eq!(synced_m.reviewed_sha.as_deref(), Some("sha-m-impl"));
        assert_eq!(synced_m.executor.as_deref(), Some("zach"));
        assert_eq!(synced_m.title, "Updated M title");
    }

    #[test]
    fn execute_m_l_pipeline_advances_reviewed_sha_on_pr_review_pass() {
        let mut store = V2Store::open_in_memory().expect("open store");
        let task = TaskRecord {
            task_id: "ZACH-022-REV".to_owned(),
            task_group: "zach".to_owned(),
            title: "Advance reviewed_sha on pr-review".to_owned(),
            repository: "zach".to_owned(),
            github_repo: Some("shockerqt/zach".to_owned()),
            issue_number: Some(55),
            weight: "M".to_owned(),
            status: "Ready".to_owned(),
            worktree_path: Some("/tmp/zach--ZACH-022-REV".to_owned()),
            branch: Some("task/ZACH-022-REV".to_owned()),
            context_pack: sample_context_pack("M"),
            depends_on: Vec::new(),
            required_stages: vec![
                "plan".to_owned(),
                "plan-review".to_owned(),
                "impl".to_owned(),
                "pr-review".to_owned(),
            ],
            stages_completed: vec![
                "plan".to_owned(),
                "plan-review".to_owned(),
                "impl".to_owned(),
            ],
            current_stage: Some("pr-review".to_owned()),
            active_attempt_id: None,
            plan_base_sha: Some("base123".to_owned()),
            reviewed_sha: Some("stale-reviewed-sha".to_owned()),
            pr_number: Some(55),
            executor: Some("zach".to_owned()),
            autonomous_consent: true,
            retry_count: 0,
            memory: TaskMemory::default(),
            version: 1,
            updated_epoch: 1000,
        };
        store.upsert_task(&task).unwrap();

        let mut mock = MockStageExecutor {
            staged_results: vec![StageExecutionResult {
                status: "PASSED".to_owned(),
                summary: "Re-review ok".to_owned(),
                review_markdown: None,
                stage_output: None,
                review_output: Some(approved_verdict_json("AC-1", "src/v2/router.rs:10")),
                invocation_id: Some("inv-pr-rerev".to_owned()),
                input_tokens: Some(500),
                output_tokens: Some(100),
                total_tokens: Some(600),
                sha_before: Some("stale-reviewed-sha".to_owned()),
                sha_after: Some("new-merged-reviewed-sha".to_owned()),
                diff_files: Vec::new(),
            }],
            ..MockStageExecutor::default()
        };

        let ws_stub = StubWsTask::passthrough_clean("zach-022-rev");
        let queued = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            "ZACH-022-REV",
            &mut mock,
            ws_stub.path(),
        )
        .expect("re-review should enqueue with updated sha");
        assert_eq!(queued.status, "Queued for Merge");
        assert_eq!(
            queued.reviewed_sha.as_deref(),
            Some("new-merged-reviewed-sha")
        );

        let mq = store.list_merge_queue(Some("zach")).unwrap();
        assert_eq!(mq.len(), 1);
        assert_eq!(mq[0].reviewed_sha, "new-merged-reviewed-sha");
    }

    struct FailingChecksExecutor {
        inner: MockStageExecutor,
        check_err: String,
    }

    impl StageExecutor for FailingChecksExecutor {
        fn execute_stage(
            &mut self,
            task: &TaskRecord,
            attempt_id: &str,
            route: &StageRoute,
            spec: &crate::v2::runner::StageCommandSpec,
        ) -> Result<StageExecutionResult, String> {
            self.inner.execute_stage(task, attempt_id, route, spec)
        }

        fn run_checks(&mut self, _worktree_path: &str, _commands: &[String]) -> Result<(), String> {
            Err(self.check_err.clone())
        }

        fn commit_worktree(
            &mut self,
            task: &TaskRecord,
            worktree_path: &str,
        ) -> Result<String, String> {
            self.inner.commit_worktree(task, worktree_path)
        }

        fn collect_reviewed_diff(
            &mut self,
            task: &TaskRecord,
            worktree_path: &str,
            reviewed_sha: &str,
        ) -> Result<crate::v2::runner::ReviewedDiffContext, String> {
            self.inner
                .collect_reviewed_diff(task, worktree_path, reviewed_sha)
        }

        fn push_and_ensure_pr(
            &mut self,
            task: &TaskRecord,
            worktree_path: &str,
            reviewed_sha: &str,
        ) -> Result<i64, String> {
            self.inner
                .push_and_ensure_pr(task, worktree_path, reviewed_sha)
        }
    }

    fn temp_sqlite_path(label: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "zach_v2_pipeline_{label}_{}_{}.sqlite3",
            std::process::id(),
            now_epoch()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn sample_s_task(id: &str) -> TaskRecord {
        TaskRecord {
            task_id: id.to_owned(),
            task_group: "zach".to_owned(),
            title: format!("Test {id}"),
            repository: "zach".to_owned(),
            github_repo: Some("shockerqt/zach".to_owned()),
            issue_number: Some(15),
            weight: "S".to_owned(),
            status: "Ready".to_owned(),
            worktree_path: Some(format!("/tmp/zach--{id}")),
            branch: Some(format!("task/{id}")),
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
        }
    }

    #[test]
    fn classify_failure_class_maps_infra_semantic_and_policy() {
        assert_eq!(
            classify_failure_class("impl", "FAILED", "AGY_TIMEOUT: timed out"),
            "infra"
        );
        assert_eq!(
            classify_failure_class("impl", "FAILED", "failed to spawn systemd-run"),
            "infra"
        );
        assert_eq!(
            classify_failure_class("impl", "FAILED", "check 'cargo test' failed: 1 failed"),
            "semantic"
        );
        assert_eq!(
            classify_failure_class(
                "pr-review",
                "FAILED",
                "PR review table is missing PASS verification row for 'AC-1'"
            ),
            "semantic"
        );
        assert_eq!(
            classify_failure_class("pr-review", "FAILED", "changes_requested by reviewer"),
            "semantic"
        );
        assert_eq!(
            classify_failure_class(
                "impl",
                "FAILED",
                "forbidden path violation on ZACH-015: .github/workflows/ci.yml"
            ),
            "policy"
        );
        assert_eq!(
            classify_failure_class("impl", "FAILED", "token budget exhausted for task ZACH-015"),
            "policy"
        );
    }

    #[test]
    fn real_sqlite_store_persists_retry_count_and_failure_class_for_failed_and_passed_stages() {
        let ws_stub = StubWsTask::passthrough_clean("zach-015");
        // 1. Infra failure in XS/S impl (execute_stage returns Err) -> retry_count == 1, failure_class == "infra"
        let db_infra = temp_sqlite_path("infra");
        {
            let mut store = V2Store::open(&db_infra).expect("open sqlite store");
            store.upsert_task(&sample_s_task("ZACH-015-INFRA")).unwrap();

            let mut err_mock = MockStageExecutor::default(); // empty staged_results -> Err
            assert!(
                execute_xs_s_pipeline_with_executor_and_ws_task(
                    &mut store,
                    "ZACH-015-INFRA",
                    &mut err_mock,
                    ws_stub.path(),
                )
                .is_err()
            );
        }
        {
            let reopened = V2Store::open(&db_infra).expect("reopen sqlite store");
            let task = reopened.get_task("ZACH-015-INFRA").unwrap().unwrap();
            assert_eq!(task.retry_count, 1);

            let attempts = reopened.list_stage_attempts("ZACH-015-INFRA").unwrap();
            assert_eq!(attempts.len(), 1);
            assert_eq!(attempts[0].status, "FAILED");
            assert_eq!(attempts[0].failure_class.as_deref(), Some("infra"));
        }
        let _ = std::fs::remove_file(&db_infra);

        // 2. Passed impl (failure_class == NULL) followed by failed pr-review semantic gate -> retry_count == 1, failure_class == "semantic"
        let db_semantic = temp_sqlite_path("semantic");
        {
            let mut store = V2Store::open(&db_semantic).expect("open sqlite store");
            store.upsert_task(&sample_s_task("ZACH-015-SEM")).unwrap();

            let mut sem_mock = MockStageExecutor {
                staged_results: vec![
                    StageExecutionResult {
                        status: "PASSED".to_owned(),
                        summary: "impl ok".to_owned(),
                        review_markdown: None,
                        stage_output: None,
                        review_output: None,
                        invocation_id: Some("inv-impl".to_owned()),
                        input_tokens: Some(1_000),
                        output_tokens: Some(200),
                        total_tokens: Some(1_200),
                        sha_before: Some("abc1234".to_owned()),
                        sha_after: Some("def5678".to_owned()),
                        diff_files: vec![DiffFileEntry {
                            path: "src/v2/router.rs".to_owned(),
                            status: "M".to_owned(),
                            added_lines: 10,
                            deleted_lines: 2,
                        }],
                    },
                    StageExecutionResult {
                        status: "PASSED".to_owned(),
                        summary: "missing table".to_owned(),
                        review_markdown: Some("No AC table here".to_owned()),
                        stage_output: None,
                        review_output: None,
                        invocation_id: Some("inv-rev".to_owned()),
                        input_tokens: Some(500),
                        output_tokens: Some(100),
                        total_tokens: Some(600),
                        sha_before: Some("def5678".to_owned()),
                        sha_after: Some("def5678".to_owned()),
                        diff_files: Vec::new(),
                    },
                ],
                ..MockStageExecutor::default()
            };
            assert!(
                execute_xs_s_pipeline_with_executor_and_ws_task(
                    &mut store,
                    "ZACH-015-SEM",
                    &mut sem_mock,
                    ws_stub.path(),
                )
                .is_err()
            );
        }
        {
            let reopened = V2Store::open(&db_semantic).expect("reopen sqlite store");
            let task = reopened.get_task("ZACH-015-SEM").unwrap().unwrap();
            assert_eq!(task.retry_count, 1);

            let attempts = reopened.list_stage_attempts("ZACH-015-SEM").unwrap();
            assert_eq!(attempts.len(), 2);
            assert_eq!(attempts[0].stage, "impl");
            assert_eq!(attempts[0].status, "PASSED");
            assert_eq!(attempts[0].failure_class, None);
            assert_eq!(attempts[1].stage, "pr-review");
            assert_eq!(attempts[1].status, "FAILED");
            assert_eq!(attempts[1].failure_class.as_deref(), Some("semantic"));
        }
        let _ = std::fs::remove_file(&db_semantic);

        // 3. Failed worker_checks after impl -> retry_count == 1, failure_class == "semantic"
        let db_checks = temp_sqlite_path("checks");
        {
            let mut store = V2Store::open(&db_checks).expect("open sqlite store");
            store.upsert_task(&sample_s_task("ZACH-015-CHK")).unwrap();

            let mut chk_exec = FailingChecksExecutor {
                inner: MockStageExecutor {
                    staged_results: vec![StageExecutionResult {
                        status: "PASSED".to_owned(),
                        summary: "impl ok".to_owned(),
                        review_markdown: None,
                        stage_output: None,
                        review_output: None,
                        invocation_id: None,
                        input_tokens: Some(100),
                        output_tokens: Some(50),
                        total_tokens: Some(150),
                        sha_before: Some("abc".to_owned()),
                        sha_after: Some("def".to_owned()),
                        diff_files: vec![DiffFileEntry {
                            path: "src/v2/router.rs".to_owned(),
                            status: "M".to_owned(),
                            added_lines: 5,
                            deleted_lines: 1,
                        }],
                    }],
                    ..MockStageExecutor::default()
                },
                check_err: "check 'cargo test' failed: test failure".to_owned(),
            };
            assert!(
                execute_xs_s_pipeline_with_executor_and_ws_task(
                    &mut store,
                    "ZACH-015-CHK",
                    &mut chk_exec,
                    ws_stub.path(),
                )
                .is_err()
            );
        }
        {
            let reopened = V2Store::open(&db_checks).expect("reopen sqlite store");
            let task = reopened.get_task("ZACH-015-CHK").unwrap().unwrap();
            assert_eq!(task.retry_count, 1);

            let attempts = reopened.list_stage_attempts("ZACH-015-CHK").unwrap();
            assert_eq!(attempts.len(), 1);
            assert_eq!(attempts[0].status, "FAILED");
            assert_eq!(attempts[0].failure_class.as_deref(), Some("semantic"));
        }
        let _ = std::fs::remove_file(&db_checks);

        // 4. Policy failure on forbidden_paths -> retry_count == 1, status == "Blocked", failure_class == "policy"
        let db_policy = temp_sqlite_path("policy");
        {
            let mut store = V2Store::open(&db_policy).expect("open sqlite store");
            store.upsert_task(&sample_s_task("ZACH-015-POL")).unwrap();

            let mut pol_mock = MockStageExecutor {
                staged_results: vec![StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "edited workflow".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: None,
                    invocation_id: None,
                    input_tokens: Some(100),
                    output_tokens: Some(50),
                    total_tokens: Some(150),
                    sha_before: Some("abc".to_owned()),
                    sha_after: Some("def".to_owned()),
                    diff_files: vec![DiffFileEntry {
                        path: ".github/workflows/ci.yml".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 2,
                        deleted_lines: 1,
                    }],
                }],
                ..MockStageExecutor::default()
            };
            assert!(
                execute_xs_s_pipeline_with_executor_and_ws_task(
                    &mut store,
                    "ZACH-015-POL",
                    &mut pol_mock,
                    ws_stub.path(),
                )
                .is_err()
            );
        }
        {
            let reopened = V2Store::open(&db_policy).expect("reopen sqlite store");
            let task = reopened.get_task("ZACH-015-POL").unwrap().unwrap();
            assert_eq!(task.retry_count, 1);
            assert_eq!(task.status, "Blocked");

            let attempts = reopened.list_stage_attempts("ZACH-015-POL").unwrap();
            assert_eq!(attempts.len(), 1);
            assert_eq!(attempts[0].status, "FAILED");
            assert_eq!(attempts[0].failure_class.as_deref(), Some("policy"));
        }
        let _ = std::fs::remove_file(&db_policy);

        // 5. M/L pipeline: plan passes (NULL failure_class), plan-review fails -> retry_count == 1, failure_class == "semantic"
        let db_ml = temp_sqlite_path("ml");
        {
            let mut store = V2Store::open(&db_ml).expect("open sqlite store");
            let mut m_task = sample_s_task("ZACH-015-ML");
            m_task.weight = "M".to_owned();
            m_task.context_pack = sample_context_pack("M");
            m_task.required_stages = vec![
                "plan".to_owned(),
                "plan-review".to_owned(),
                "impl".to_owned(),
                "pr-review".to_owned(),
            ];
            store.upsert_task(&m_task).unwrap();

            let mut ml_mock = MockStageExecutor {
                staged_results: vec![
                    StageExecutionResult {
                        status: "PASSED".to_owned(),
                        summary: "plan ok".to_owned(),
                        review_markdown: None,
                        stage_output: Some(plan_fixture("M")),
                        review_output: None,
                        invocation_id: None,
                        input_tokens: Some(100),
                        output_tokens: Some(50),
                        total_tokens: Some(150),
                        sha_before: None,
                        sha_after: None,
                        diff_files: Vec::new(),
                    },
                    StageExecutionResult {
                        status: "FAILED".to_owned(),
                        summary: "changes_requested: clarify migration steps".to_owned(),
                        review_markdown: None,
                        stage_output: None,
                        review_output: None,
                        invocation_id: None,
                        input_tokens: Some(100),
                        output_tokens: Some(50),
                        total_tokens: Some(150),
                        sha_before: None,
                        sha_after: None,
                        diff_files: Vec::new(),
                    },
                ],
                ..MockStageExecutor::default()
            };
            assert!(
                execute_m_l_pipeline_with_executor_and_ws_task(
                    &mut store,
                    "ZACH-015-ML",
                    &mut ml_mock,
                    ws_stub.path(),
                )
                .is_err()
            );
        }
        {
            let reopened = V2Store::open(&db_ml).expect("reopen sqlite store");
            let task = reopened.get_task("ZACH-015-ML").unwrap().unwrap();
            assert_eq!(task.retry_count, 1);

            let attempts = reopened.list_stage_attempts("ZACH-015-ML").unwrap();
            assert_eq!(attempts.len(), 2);
            assert_eq!(attempts[0].stage, "plan");
            assert_eq!(attempts[0].status, "PASSED");
            assert_eq!(attempts[0].failure_class, None);
            assert_eq!(attempts[1].stage, "plan-review");
            assert_eq!(attempts[1].status, "FAILED");
            assert_eq!(attempts[1].failure_class.as_deref(), Some("semantic"));
        }
        let _ = std::fs::remove_file(&db_ml);
    }

    #[test]
    fn missing_reviewed_sha_or_pr_number_returns_error_without_fallbacks() {
        let mut store = V2Store::open_in_memory().expect("in-memory store");
        let ws_stub = StubWsTask::passthrough_clean("zach-016");

        let s_impl_ok = || StageExecutionResult {
            status: "PASSED".to_owned(),
            summary: "impl ok".to_owned(),
            review_markdown: None,
            stage_output: None,
            review_output: None,
            invocation_id: Some("inv-impl".to_owned()),
            input_tokens: Some(1_000),
            output_tokens: Some(200),
            total_tokens: Some(1_200),
            sha_before: Some("abc1234".to_owned()),
            sha_after: Some("abc1234".to_owned()),
            diff_files: vec![DiffFileEntry {
                path: "src/v2/router.rs".to_owned(),
                status: "M".to_owned(),
                added_lines: 5,
                deleted_lines: 1,
            }],
        };
        let s_rev_ok = || StageExecutionResult {
            status: "PASSED".to_owned(),
            summary: "review ok".to_owned(),
            review_markdown: None,
            stage_output: None,
            review_output: Some(approved_verdict_json("AC-1", "src/v2/router.rs:10")),
            invocation_id: Some("inv-rev".to_owned()),
            input_tokens: Some(500),
            output_tokens: Some(100),
            total_tokens: Some(600),
            sha_before: Some("real-sha".to_owned()),
            sha_after: Some("real-sha".to_owned()),
            diff_files: Vec::new(),
        };

        // 1. Missing committed SHA returns Err (never falls back to "head-sha")
        store
            .upsert_task(&sample_s_task("ZACH-016-NO-SHA"))
            .unwrap();
        let mut no_sha_mock = MockStageExecutor {
            staged_results: vec![s_impl_ok(), s_rev_ok()],
            committed_sha_to_return: None,
            ..MockStageExecutor::default()
        };
        assert!(
            execute_xs_s_pipeline_with_executor_and_ws_task(
                &mut store,
                "ZACH-016-NO-SHA",
                &mut no_sha_mock,
                ws_stub.path(),
            )
            .is_err()
        );
        assert!(store.list_merge_queue(Some("zach")).unwrap().is_empty());

        // 2. Literal placeholder "head-sha" is rejected as invalid
        store
            .upsert_task(&sample_s_task("ZACH-016-PLACEHOLDER-SHA"))
            .unwrap();
        let mut placeholder_mock = MockStageExecutor {
            staged_results: vec![s_impl_ok(), s_rev_ok()],
            committed_sha_to_return: Some("head-sha".to_owned()),
            ..MockStageExecutor::default()
        };
        assert!(
            execute_xs_s_pipeline_with_executor_and_ws_task(
                &mut store,
                "ZACH-016-PLACEHOLDER-SHA",
                &mut placeholder_mock,
                ws_stub.path(),
            )
            .is_err()
        );
        assert!(store.list_merge_queue(Some("zach")).unwrap().is_empty());

        // 3. Missing PR number returns Err (never falls back to 1)
        store.upsert_task(&sample_s_task("ZACH-016-NO-PR")).unwrap();
        let mut no_pr_mock = MockStageExecutor {
            staged_results: vec![s_impl_ok(), s_rev_ok()],
            committed_sha_to_return: Some("real-sha".to_owned()),
            pr_number_to_return: None,
            ..MockStageExecutor::default()
        };
        assert!(
            execute_xs_s_pipeline_with_executor_and_ws_task(
                &mut store,
                "ZACH-016-NO-PR",
                &mut no_pr_mock,
                ws_stub.path(),
            )
            .is_err()
        );
        assert!(store.list_merge_queue(Some("zach")).unwrap().is_empty());

        // 4. Direct enqueue_pipeline_task_for_merge rejects None and "head-sha"
        let mut bad_task = sample_s_task("ZACH-016-ENQ");
        let mut ok_mock = MockStageExecutor::default();
        assert!(
            enqueue_pipeline_task_for_merge(&mut store, &mut ok_mock, bad_task.clone(), "/tmp")
                .is_err()
        );
        bad_task.reviewed_sha = Some("head-sha".to_owned());
        assert!(
            enqueue_pipeline_task_for_merge(&mut store, &mut ok_mock, bad_task, "/tmp").is_err()
        );
    }

    #[test]
    fn temp_git_repo_pipeline_commits_before_pr_review_and_records_committed_reviewed_sha() {
        use std::process::Command;

        struct TempRepoGuard(std::path::PathBuf);
        impl Drop for TempRepoGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn run_git(dir: &std::path::Path, args: &[&str]) -> String {
            let out = Command::new("git")
                .arg("-C")
                .arg(dir)
                .args(args)
                .output()
                .expect("run git");
            assert!(
                out.status.success(),
                "git {:?} failed in {}: {}",
                args,
                dir.display(),
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).into_owned()
        }

        struct RealGitPipelineExecutor {
            systemd: SystemdStageExecutor,
            pr_number: i64,
            pr_review_observed_task_reviewed_sha: Option<String>,
            pr_review_observed_head_sha: Option<String>,
            pr_review_observed_porcelain: Option<String>,
        }

        impl StageExecutor for RealGitPipelineExecutor {
            fn execute_stage(
                &mut self,
                task: &TaskRecord,
                _attempt_id: &str,
                route: &StageRoute,
                spec: &crate::v2::runner::StageCommandSpec,
            ) -> Result<StageExecutionResult, String> {
                let worktree = std::path::Path::new(&spec.worktree_path);
                if route.stage == "impl" {
                    let sha_before = run_git(worktree, &["rev-parse", "HEAD"]).trim().to_owned();
                    // Worker modifies a file in target_files WITHOUT committing (zachd must commit).
                    std::fs::write(
                        worktree.join("src/v2/router.rs"),
                        "pub fn route() -> &'static str { \"v2\" }\n",
                    )
                    .expect("modify router.rs");
                    let sha_after = run_git(worktree, &["rev-parse", "HEAD"]).trim().to_owned();
                    assert_eq!(
                        sha_before, sha_after,
                        "impl worker does not commit on its own"
                    );
                    let diff_files =
                        crate::v2::runner::collect_worktree_diff_entries(&spec.worktree_path);
                    return Ok(StageExecutionResult {
                        status: "PASSED".to_owned(),
                        summary: "Modified router without committing".to_owned(),
                        review_markdown: None,
                        stage_output: None,
                        review_output: None,
                        invocation_id: Some("inv-real-impl".to_owned()),
                        input_tokens: Some(1_000),
                        output_tokens: Some(200),
                        total_tokens: Some(1_200),
                        sha_before: Some(sha_before),
                        sha_after: Some(sha_after),
                        diff_files,
                    });
                }

                // pr-review: verify worktree was ALREADY committed and clean before review started!
                let head_sha = run_git(worktree, &["rev-parse", "HEAD"]).trim().to_owned();
                let porcelain = run_git(worktree, &["status", "--porcelain"]);
                self.pr_review_observed_task_reviewed_sha = task.reviewed_sha.clone();
                self.pr_review_observed_head_sha = Some(head_sha.clone());
                self.pr_review_observed_porcelain = Some(porcelain);

                Ok(StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "Reviewed committed head".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: Some(approved_verdict_json("AC-1", "src/v2/router.rs:1")),
                    invocation_id: Some("inv-real-rev".to_owned()),
                    input_tokens: Some(600),
                    output_tokens: Some(100),
                    total_tokens: Some(700),
                    sha_before: Some(head_sha.clone()),
                    sha_after: Some(head_sha),
                    diff_files: Vec::new(),
                })
            }

            fn run_checks(
                &mut self,
                _worktree_path: &str,
                _commands: &[String],
            ) -> Result<(), String> {
                Ok(())
            }

            fn commit_worktree(
                &mut self,
                task: &TaskRecord,
                worktree_path: &str,
            ) -> Result<String, String> {
                self.systemd.commit_worktree(task, worktree_path)
            }

            fn collect_reviewed_diff(
                &mut self,
                task: &TaskRecord,
                worktree_path: &str,
                reviewed_sha: &str,
            ) -> Result<crate::v2::runner::ReviewedDiffContext, String> {
                self.systemd
                    .collect_reviewed_diff(task, worktree_path, reviewed_sha)
            }

            fn push_and_ensure_pr(
                &mut self,
                task: &TaskRecord,
                worktree_path: &str,
                reviewed_sha: &str,
            ) -> Result<i64, String> {
                let branch = task.branch.as_deref().expect("task branch");
                let out = Command::new("git")
                    .args(["-C", worktree_path, "push", "-u", "origin", branch])
                    .output()
                    .expect("git push");
                assert!(
                    out.status.success(),
                    "git push failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                assert!(!reviewed_sha.is_empty() && reviewed_sha != "head-sha");
                Ok(self.pr_number)
            }
        }

        let root = std::env::temp_dir().join(format!("zach-016-real-git-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let origin_dir = root.join("origin.git");
        let work_dir = root.join("work");
        std::fs::create_dir_all(&origin_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        let _guard = TempRepoGuard(root);

        run_git(&origin_dir, &["init", "--bare", "-b", "main"]);
        run_git(&work_dir, &["init", "-b", "main"]);
        run_git(
            &work_dir,
            &["config", "user.email", "zach-test@example.com"],
        );
        run_git(&work_dir, &["config", "user.name", "Zach Test"]);
        std::fs::create_dir_all(work_dir.join("src/v2")).unwrap();
        std::fs::write(
            work_dir.join("src/v2/router.rs"),
            "pub fn route() -> &'static str { \"v1\" }\n",
        )
        .unwrap();
        run_git(&work_dir, &["add", "."]);
        run_git(&work_dir, &["commit", "-m", "base commit"]);
        run_git(
            &work_dir,
            &["remote", "add", "origin", origin_dir.to_str().unwrap()],
        );
        run_git(&work_dir, &["push", "-u", "origin", "main"]);
        run_git(&work_dir, &["checkout", "-b", "task/ZACH-016-REAL"]);

        let sha_before = run_git(&work_dir, &["rev-parse", "HEAD"]).trim().to_owned();

        let mut store = V2Store::open_in_memory().expect("in-memory store");
        let mut task = sample_s_task("ZACH-016-REAL");
        task.worktree_path = Some(work_dir.to_str().unwrap().to_owned());
        task.branch = Some("task/ZACH-016-REAL".to_owned());
        task.plan_base_sha = Some(sha_before.clone());
        store.upsert_task(&task).unwrap();

        let mut exec = RealGitPipelineExecutor {
            systemd: SystemdStageExecutor::default(),
            pr_number: 101,
            pr_review_observed_task_reviewed_sha: None,
            pr_review_observed_head_sha: None,
            pr_review_observed_porcelain: None,
        };

        let ws_stub = StubWsTask::passthrough_clean("zach-016-real");
        let queued = execute_xs_s_pipeline_with_executor_and_ws_task(
            &mut store,
            "ZACH-016-REAL",
            &mut exec,
            ws_stub.path(),
        )
        .expect("pipeline with real git repo should succeed");

        let committed_head = run_git(&work_dir, &["rev-parse", "HEAD"]).trim().to_owned();
        let reviewed_sha = queued.reviewed_sha.as_deref().expect("reviewed_sha set");

        assert_ne!(reviewed_sha, sha_before);
        assert_eq!(reviewed_sha, committed_head);
        assert_eq!(queued.pr_number, Some(101));

        // Prove commit happened BEFORE pr-review ran and worktree was clean during pr-review
        assert_eq!(
            exec.pr_review_observed_task_reviewed_sha.as_deref(),
            Some(reviewed_sha)
        );
        assert_eq!(
            exec.pr_review_observed_head_sha.as_deref(),
            Some(reviewed_sha)
        );
        assert_eq!(exec.pr_review_observed_porcelain.as_deref(), Some(""));

        // Prove the commit on HEAD contains the implementation diff and remote received it
        let changed_files = run_git(
            &work_dir,
            &["diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"],
        );
        assert!(changed_files.lines().any(|l| l == "src/v2/router.rs"));
        let remote_sha = run_git(&origin_dir, &["rev-parse", "refs/heads/task/ZACH-016-REAL"]);
        assert_eq!(remote_sha.trim(), reviewed_sha);

        // Prove merge_queue and stage_attempts recorded the exact committed reviewed_sha
        let mq = store.list_merge_queue(Some("zach")).unwrap();
        assert_eq!(mq.len(), 1);
        assert_eq!(mq[0].reviewed_sha, reviewed_sha);
        assert_eq!(mq[0].pr_number, 101);

        let attempts = store.list_stage_attempts("ZACH-016-REAL").unwrap();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].stage, "impl");
        assert_eq!(attempts[0].sha_before.as_deref(), Some(sha_before.as_str()));
        assert_eq!(attempts[0].sha_after.as_deref(), Some(reviewed_sha));
        assert_eq!(attempts[1].stage, "pr-review");
        assert_eq!(attempts[1].sha_before.as_deref(), Some(reviewed_sha));
        assert_eq!(attempts[1].sha_after.as_deref(), Some(reviewed_sha));
    }

    #[test]
    fn build_agy_cli_payload_filters_allowed_files_clamps_timeout_and_lowercases_id() {
        let root = std::env::temp_dir().join(format!("zach-019-allowed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        for i in 0..55 {
            std::fs::write(root.join(format!("src/file_{i:02}.rs")), "fn f() {}\n").unwrap();
        }
        let outside_file =
            std::env::temp_dir().join(format!("zach-019-outside-{}.rs", std::process::id()));
        std::fs::write(&outside_file, "fn out() {}\n").unwrap();

        let mut target_files = vec![
            TargetFileSpec {
                path: "src/**".to_owned(),
                action: "modify".to_owned(),
                summary: "glob must be filtered".to_owned(),
            },
            TargetFileSpec {
                path: "src/missing.rs".to_owned(),
                action: "create".to_owned(),
                summary: "missing file must be filtered".to_owned(),
            },
            TargetFileSpec {
                path: "../outside.rs".to_owned(),
                action: "modify".to_owned(),
                summary: "traversal must be filtered".to_owned(),
            },
            TargetFileSpec {
                path: outside_file.to_str().unwrap().to_owned(),
                action: "modify".to_owned(),
                summary: "outside worktree must be filtered".to_owned(),
            },
        ];
        for i in 0..55 {
            target_files.push(TargetFileSpec {
                path: format!("src/file_{i:02}.rs"),
                action: "modify".to_owned(),
                summary: "existing file".to_owned(),
            });
        }

        let mut task = sample_s_task("ZACH-019-AGY");
        task.worktree_path = Some(root.to_str().unwrap().to_owned());
        task.context_pack.target_files = target_files;

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
            timeout_secs: 9999,
            stall_timeout_secs: 600,
        };

        let payload = build_agy_cli_payload(&task, &route, "Plan work");
        assert_eq!(payload["orchestration_id"], "zach-019-agy");
        assert_eq!(payload["timeout_seconds"], 1800);
        let allowed = payload["allowed_files"].as_array().expect("array");
        assert_eq!(allowed.len(), 50);
        assert!(allowed.iter().all(|v| {
            let s = v.as_str().unwrap();
            s.starts_with("src/file_") && !s.contains('*') && !s.contains("..")
        }));

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(&outside_file);
    }

    #[test]
    fn pipeline_bounds_attempt_summary_check_failure_decision_context_and_recent_attempts() {
        let mut store = V2Store::open_in_memory().expect("in-memory store");
        let ws_stub = StubWsTask::passthrough_clean("zach-019-bound");
        let giant_raw = format!("RAW_STDERR_MARKER {}", "z".repeat(4000));

        // 1. M pipeline AGY infra failure records bounded pointer (not raw stderr/summary) and truncates summary <= 1024
        let mut m_task = sample_s_task("ZACH-019-BOUND-ML");
        m_task.weight = "M".to_owned();
        m_task.retry_count = 1; // ("M", "plan") routes to GeminiAgy on retry
        m_task.context_pack = sample_context_pack("M");
        m_task.required_stages = vec!["plan".to_owned()];
        store.upsert_task(&m_task).unwrap();

        let mut agy_fail_mock = MockStageExecutor {
            staged_results: vec![StageExecutionResult {
                status: "FAILED".to_owned(),
                summary: format!("AGY_TIMEOUT: {giant_raw}"),
                review_markdown: None,
                stage_output: None,
                review_output: None,
                invocation_id: None,
                input_tokens: Some(100),
                output_tokens: Some(50),
                total_tokens: Some(150),
                sha_before: None,
                sha_after: None,
                diff_files: Vec::new(),
            }],
            ..MockStageExecutor::default()
        };
        assert!(
            execute_m_l_pipeline_with_executor_and_ws_task(
                &mut store,
                "ZACH-019-BOUND-ML",
                &mut agy_fail_mock,
                ws_stub.path(),
            )
            .is_err()
        );

        let updated_ml = store.get_task("ZACH-019-BOUND-ML").unwrap().unwrap();
        assert_eq!(updated_ml.memory.recent_attempts.len(), 1);
        let ptr = &updated_ml.memory.recent_attempts[0];
        assert!(ptr.contains("[AGY_INFRA:AGY_TIMEOUT]"));
        assert!(ptr.contains("stage=plan"));
        assert!(ptr.contains("attempt=zach-019-bound-ml-plan-1"));
        assert!(ptr.contains("log=attempts/zach-019-bound-ml-plan-1/stderr.log"));
        assert!(!ptr.contains("RAW_STDERR_MARKER"));

        let attempts = store.list_stage_attempts("ZACH-019-BOUND-ML").unwrap();
        assert_eq!(attempts.len(), 1);
        let sum = attempts[0].summary.as_deref().unwrap();
        assert!(sum.len() <= MAX_SUMMARY_BYTES);
        assert!(sum.ends_with("..."));

        // 2. Forbidden path violation bounds open_decision context_summary <= 1024 and routes impl recent_attempts via push_bounded_recent_attempt
        let mut pol_task = sample_s_task("ZACH-019-BOUND-POL");
        store.upsert_task(&pol_task).unwrap();
        let mut pol_mock = MockStageExecutor {
            staged_results: vec![StageExecutionResult {
                status: "PASSED".to_owned(),
                summary: giant_raw.clone(),
                review_markdown: None,
                stage_output: None,
                review_output: None,
                invocation_id: None,
                input_tokens: Some(10),
                output_tokens: Some(5),
                total_tokens: Some(15),
                sha_before: None,
                sha_after: None,
                diff_files: vec![DiffFileEntry {
                    path: ".github/workflows/ci.yml".to_owned(),
                    status: "M".to_owned(),
                    added_lines: 1,
                    deleted_lines: 0,
                }],
            }],
            ..MockStageExecutor::default()
        };
        assert!(
            execute_xs_s_pipeline_with_executor_and_ws_task(
                &mut store,
                "ZACH-019-BOUND-POL",
                &mut pol_mock,
                ws_stub.path(),
            )
            .is_err()
        );
        let decs = store.list_decisions(true, None).unwrap();
        assert_eq!(decs.len(), 1);
        assert!(decs[0].context_summary.len() <= MAX_SUMMARY_BYTES);
        assert!(decs[0].context_summary.ends_with("..."));

        // 3. FailingChecksExecutor bounds task.memory.last_check_failure <= 1024
        store
            .upsert_task(&sample_s_task("ZACH-019-BOUND-CHK"))
            .unwrap();
        let mut chk_exec = FailingChecksExecutor {
            inner: MockStageExecutor {
                staged_results: vec![StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "impl ok".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: None,
                    invocation_id: None,
                    input_tokens: Some(10),
                    output_tokens: Some(5),
                    total_tokens: Some(15),
                    sha_before: Some("abc".to_owned()),
                    sha_after: Some("def".to_owned()),
                    diff_files: vec![DiffFileEntry {
                        path: "src/v2/router.rs".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 5,
                        deleted_lines: 1,
                    }],
                }],
                ..MockStageExecutor::default()
            },
            check_err: giant_raw,
        };
        assert!(
            execute_xs_s_pipeline_with_executor_and_ws_task(
                &mut store,
                "ZACH-019-BOUND-CHK",
                &mut chk_exec,
                ws_stub.path(),
            )
            .is_err()
        );
        let chk_task = store.get_task("ZACH-019-BOUND-CHK").unwrap().unwrap();
        let last_chk = chk_task.memory.last_check_failure.as_deref().unwrap();
        assert!(last_chk.len() <= MAX_SUMMARY_BYTES);
        assert!(last_chk.ends_with("..."));

        // 4. push_bounded_recent_attempt caps at 10 entries and <= 256 bytes per entry
        for i in 0..15 {
            push_bounded_recent_attempt(&mut pol_task, format!("entry-{i}-{}", "a".repeat(400)));
        }
        assert_eq!(pol_task.memory.recent_attempts.len(), 10);
        assert!(
            pol_task
                .memory
                .recent_attempts
                .iter()
                .all(|e| e.len() <= MAX_RECENT_ATTEMPT_BYTES)
        );
        assert!(pol_task.memory.recent_attempts[0].starts_with("entry-5-"));
    }

    #[test]
    fn parse_agy_cli_response_parses_real_fixture_and_distinguishes_zero_vs_unknown() {
        let fixture = include_str!("../../tests/fixtures/gemini_worker_usage.json");
        let parsed = parse_agy_cli_response(fixture, "", Some(0)).expect("parse real fixture");
        assert_eq!(parsed.status, "PASSED");
        assert_eq!(parsed.summary, "OK");
        assert_eq!(
            parsed.invocation_id.as_deref(),
            Some("task_d0e234eb4c1343aea395c9de8c5428b0")
        );
        assert_eq!(parsed.input_tokens, Some(9_967));
        assert_eq!(parsed.output_tokens, Some(43));
        assert_eq!(parsed.total_tokens, Some(10_010));

        // Do not double-count or override per-invocation usage with cumulative task_usage.
        let multi_run = r#"{
            "execution_succeeded": true,
            "summary": "Done",
            "usage": {"input_tokens": 100, "output_tokens": 50, "total_tokens": 150},
            "budget": {"model_calls_used": 1, "observed_total_tokens": 150, "unknown_usage_calls": 0},
            "task_usage": {"usage_complete": true, "unknown_usage_calls": 0, "input_tokens": 80000, "output_tokens": 10000, "observed_total_tokens": 90000}
        }"#;
        let multi_res = parse_agy_cli_response(multi_run, "", Some(0)).unwrap();
        assert_eq!(multi_res.input_tokens, Some(100));
        assert_eq!(multi_res.output_tokens, Some(50));
        assert_eq!(multi_res.total_tokens, Some(150));

        // Compute total_tokens from input + output when total_tokens is omitted.
        let computed_total = r#"{
            "execution_succeeded": true,
            "summary": "Computed total",
            "usage": {"input_tokens": 200, "output_tokens": 40}
        }"#;
        let computed_res = parse_agy_cli_response(computed_total, "", Some(0)).unwrap();
        assert_eq!(computed_res.input_tokens, Some(200));
        assert_eq!(computed_res.output_tokens, Some(40));
        assert_eq!(computed_res.total_tokens, Some(240));

        // Explicit zero usage is recorded as Some(0), distinct from unknown None.
        let explicit_zero = r#"{
            "execution_succeeded": true,
            "summary": "Cached zero",
            "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
        }"#;
        let zero_res = parse_agy_cli_response(explicit_zero, "", Some(0)).unwrap();
        assert_eq!(zero_res.input_tokens, Some(0));
        assert_eq!(zero_res.output_tokens, Some(0));
        assert_eq!(zero_res.total_tokens, Some(0));

        // Empty usage `{}` with unknown_usage_calls > 0 / usage_complete == false yields None.
        let unknown_usage = r#"{
            "execution_succeeded": true,
            "summary": "Unparseable AGY usage",
            "usage": {},
            "budget": {"model_calls_used": 1, "observed_total_tokens": 0, "unknown_usage_calls": 1},
            "task_usage": {"usage_complete": false, "unknown_usage_calls": 1, "observed_total_tokens": 5000}
        }"#;
        let unknown_res = parse_agy_cli_response(unknown_usage, "", Some(0)).unwrap();
        assert_eq!(unknown_res.input_tokens, None);
        assert_eq!(unknown_res.output_tokens, None);
        assert_eq!(unknown_res.total_tokens, None);

        // Fallback to budget.observed_total_tokens when usage is empty and unknown_usage_calls == 0.
        let budget_fallback = r#"{
            "execution_succeeded": true,
            "summary": "Budget fallback",
            "usage": {},
            "budget": {"model_calls_used": 1, "observed_total_tokens": 333, "unknown_usage_calls": 0}
        }"#;
        let fallback_res = parse_agy_cli_response(budget_fallback, "", Some(0)).unwrap();
        assert_eq!(fallback_res.input_tokens, None);
        assert_eq!(fallback_res.output_tokens, None);
        assert_eq!(fallback_res.total_tokens, Some(333));
    }

    #[test]
    fn pipeline_accumulates_token_usage_enforces_budget_and_records_null_on_unknown() {
        let mut store = V2Store::open_in_memory().expect("open store");
        let ws_stub = StubWsTask::passthrough_clean("zach-020-acc");
        let mut task = sample_s_task("ZACH-020-ACC");
        task.context_pack.target_files = vec![TargetFileSpec {
            path: "src/v2/**".to_owned(),
            action: "modify".to_owned(),
            summary: "token usage".to_owned(),
        }];
        store.upsert_task(&task).unwrap();

        let route = resolve_stage_route("S", "impl", 0, None).unwrap().unwrap();
        assert_eq!(route.max_task_tokens, 400_000);

        // Attempt 1: impl fails after consuming 250_000 tokens -> accumulated into token_usage_by_stage["impl"].
        let mut fail_exec = MockStageExecutor {
            staged_results: vec![StageExecutionResult {
                status: "FAILED".to_owned(),
                summary: "first impl failed".to_owned(),
                review_markdown: None,
                stage_output: None,
                review_output: None,
                invocation_id: None,
                input_tokens: Some(200_000),
                output_tokens: Some(50_000),
                total_tokens: Some(250_000),
                sha_before: None,
                sha_after: None,
                diff_files: Vec::new(),
            }],
            ..MockStageExecutor::default()
        };
        assert!(
            execute_xs_s_pipeline_with_executor_and_ws_task(
                &mut store,
                "ZACH-020-ACC",
                &mut fail_exec,
                ws_stub.path(),
            )
            .is_err()
        );
        let after_fail = store.get_task("ZACH-020-ACC").unwrap().unwrap();
        assert_eq!(
            after_fail.memory.token_usage_by_stage.get("impl").copied(),
            Some(250_000)
        );
        assert_eq!(check_token_budget(&after_fail, &route).unwrap(), 150_000);

        // Attempt 2 & 3: impl succeeds (100_000) + pr-review succeeds (60_000) -> total = 410_000 >= 400_000.
        let mut pass_exec = MockStageExecutor {
            staged_results: vec![
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "impl ok".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: None,
                    invocation_id: None,
                    input_tokens: Some(80_000),
                    output_tokens: Some(20_000),
                    total_tokens: Some(100_000),
                    sha_before: Some("abc".to_owned()),
                    sha_after: Some("def".to_owned()),
                    diff_files: vec![DiffFileEntry {
                        path: "src/v2/runner.rs".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 10,
                        deleted_lines: 2,
                    }],
                },
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "review ok".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: Some(approved_verdict_json("AC-1", "src/v2/runner.rs:10")),
                    invocation_id: None,
                    input_tokens: Some(50_000),
                    output_tokens: Some(10_000),
                    total_tokens: Some(60_000),
                    sha_before: Some("def".to_owned()),
                    sha_after: Some("def".to_owned()),
                    diff_files: Vec::new(),
                },
            ],
            ..MockStageExecutor::default()
        };
        let completed = execute_xs_s_pipeline_with_executor_and_ws_task(
            &mut store,
            "ZACH-020-ACC",
            &mut pass_exec,
            ws_stub.path(),
        )
        .expect("pipeline succeeds before exceeding budget on next stage");
        assert_eq!(
            completed.memory.token_usage_by_stage.get("impl").copied(),
            Some(350_000)
        );
        assert_eq!(
            completed
                .memory
                .token_usage_by_stage
                .get("pr-review")
                .copied(),
            Some(60_000)
        );
        let budget_err = check_token_budget(&completed, &route).unwrap_err();
        assert!(budget_err.contains("token budget exhausted"));

        // Unknown usage attempt (from real codex_exec_failed.jsonl) records SQL NULL (not 0).
        let mut null_task = sample_s_task("ZACH-020-NULL");
        null_task.weight = "XS".to_owned();
        null_task.context_pack.weight = "XS".to_owned();
        null_task.required_stages = vec!["impl".to_owned()];
        store.upsert_task(&null_task).unwrap();
        let failed_codex = crate::v2::runner::parse_codex_jsonl_output(
            include_str!("../../tests/fixtures/codex_exec_failed.jsonl"),
            "",
            Some(1),
        )
        .unwrap();
        let mut null_exec = MockStageExecutor {
            staged_results: vec![StageExecutionResult {
                status: failed_codex.status,
                summary: failed_codex.summary,
                review_markdown: failed_codex.review_markdown,
                stage_output: None,
                review_output: failed_codex.review_output,
                invocation_id: None,
                input_tokens: failed_codex.input_tokens,
                output_tokens: failed_codex.output_tokens,
                total_tokens: failed_codex.total_tokens,
                sha_before: None,
                sha_after: None,
                diff_files: Vec::new(),
            }],
            ..MockStageExecutor::default()
        };
        assert!(
            execute_xs_s_pipeline_with_executor_and_ws_task(
                &mut store,
                "ZACH-020-NULL",
                &mut null_exec,
                ws_stub.path(),
            )
            .is_err()
        );
        null_task = store.get_task("ZACH-020-NULL").unwrap().unwrap();
        assert!(null_task.memory.token_usage_by_stage.is_empty());

        let attempts = store.list_stage_attempts("ZACH-020-NULL").unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].input_tokens, None);
        assert_eq!(attempts[0].output_tokens, None);
        assert_eq!(attempts[0].total_tokens, None);

        let (raw_in, raw_out, raw_tot): (Option<i64>, Option<i64>, Option<i64>) = store
            .connection_mut()
            .query_row(
                "SELECT input_tokens, output_tokens, total_tokens
                 FROM stage_attempts WHERE attempt_id = ?1",
                rusqlite::params![attempts[0].attempt_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(raw_in.is_none());
        assert!(raw_out.is_none());
        assert!(raw_tot.is_none());
    }

    #[test]
    fn is_test_or_doc_path_and_lockfile_parity_with_governance() {
        assert!(is_lockfile_path("Cargo.lock"));
        assert!(is_lockfile_path("web/package-lock.json"));
        assert!(is_lockfile_path("pnpm-lock.yaml"));
        assert!(is_lockfile_path("yarn.lock"));
        assert!(!is_lockfile_path("Cargo.toml"));
        assert!(!is_lockfile_path("src/lock.rs"));

        assert!(is_test_or_doc_path("README.md"));
        assert!(is_test_or_doc_path("docs/architecture/v2.rst"));
        assert!(is_test_or_doc_path("tests/audit_cases.rs"));
        assert!(is_test_or_doc_path("src/__tests__/app.ts"));
        assert!(is_test_or_doc_path("src/router.test.ts"));
        assert!(is_test_or_doc_path("src/router.spec.tsx"));
        assert!(is_test_or_doc_path("src/router_test.rs"));
        assert!(is_test_or_doc_path("scripts/test_runner.py"));
        assert!(is_test_or_doc_path("bin/ws-selftest"));
        assert!(!is_test_or_doc_path("src/v2/router.rs"));
        assert!(!is_test_or_doc_path(".md"));
        assert!(!is_test_or_doc_path("Cargo.toml"));
    }

    #[test]
    fn verify_worktree_diff_matches_ws_task_classify_weight_fixtures_and_infrastructure_is_l() {
        #[derive(Deserialize)]
        struct FixtureCase {
            name: String,
            repo: String,
            requested: String,
            paths: String,
            diff_lines: usize,
            new_files: usize,
            output: ClassifyWeightOutput,
        }

        let raw_fixtures =
            include_str!("../../tests/fixtures/ws_task_classify_weight_fixtures.json");
        let cases: Vec<FixtureCase> =
            serde_json::from_str(raw_fixtures).expect("parse golden classify-weight fixtures");
        assert!(!cases.is_empty());

        let fixture_stub = StubWsTask::from_python(
            "fixture-parity",
            &format!(
                r#"#!/usr/bin/env python3
import json, sys

FIXTURES = json.loads({escaped_fixtures})
args = sys.argv[1:]
assert args[0] == "classify-weight", args
repo = args[args.index("--repo") + 1]
paths = ""
for a in args:
    if a.startswith("--paths="):
        paths = a[len("--paths="):]
diff_lines = int(args[args.index("--diff-lines") + 1])
new_files = int(args[args.index("--new-files") + 1])
requested = args[args.index("--requested") + 1] if "--requested" in args else ""

for case in FIXTURES:
    if (
        case["repo"] == repo
        and case["paths"] == paths
        and case["diff_lines"] == diff_lines
        and case["new_files"] == new_files
        and case["requested"] == requested
    ):
        print(json.dumps(case["output"]))
        sys.exit(0)

raise SystemExit(f"no matching fixture for repo={{repo}} paths={{paths}} lines={{diff_lines}} new={{new_files}} req={{requested}}")
"#,
                escaped_fixtures = serde_json::to_string(raw_fixtures).unwrap(),
            ),
        );

        let real_ws_task = Path::new("/home/ubuntu/workspace/governance/bin/ws-task");
        let has_real_ws_task = real_ws_task.exists();

        for case in &cases {
            let diff_entries = match case.name.as_str() {
                "small_doc_only_xs" => vec![
                    DiffFileEntry {
                        path: "README.md".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 120,
                        deleted_lines: 10,
                    },
                    DiffFileEntry {
                        path: "docs/guide.md".to_owned(),
                        status: "A".to_owned(),
                        added_lines: 50,
                        deleted_lines: 0,
                    },
                ],
                "mixed_doc_lockfile_and_small_code_xs" => vec![
                    DiffFileEntry {
                        path: "README.md".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 200,
                        deleted_lines: 10,
                    },
                    DiffFileEntry {
                        path: "Cargo.lock".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 400,
                        deleted_lines: 100,
                    },
                    DiffFileEntry {
                        path: "src/v2/router.rs".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 8,
                        deleted_lines: 2,
                    },
                ],
                _ if case.paths.trim().is_empty() => Vec::new(),
                _ => vec![DiffFileEntry {
                    path: case.paths.clone(),
                    status: if case.new_files > 0 { "A" } else { "M" }.to_owned(),
                    added_lines: case.diff_lines,
                    deleted_lines: 0,
                }],
            };

            let pack = ContextPackSpec::default();
            let expected = if case.output.escalated {
                DiffCheckOutcome::WeightEscalated {
                    from_weight: case.requested.clone(),
                    to_weight: case.output.effective_weight.clone(),
                    required_stages: case.output.required_stages.clone(),
                    reason: case.output.reasons.join("; "),
                }
            } else {
                DiffCheckOutcome::Clean
            };

            let stub_outcome = verify_worktree_diff_with(
                &case.repo,
                &case.requested,
                &pack,
                &diff_entries,
                fixture_stub.path(),
            )
            .unwrap_or_else(|e| panic!("fixture {} failed via stub: {e}", case.name));
            assert_eq!(
                stub_outcome, expected,
                "stub mismatch for fixture {}",
                case.name
            );

            if case.repo == "infrastructure" {
                match &stub_outcome {
                    DiffCheckOutcome::WeightEscalated { to_weight, .. } => {
                        assert_eq!(to_weight, "L", "AC-3 infrastructure must classify L");
                    }
                    other => panic!("expected L escalation for infrastructure, got {other:?}"),
                }
            }

            if has_real_ws_task {
                let real_outcome = verify_worktree_diff_with(
                    &case.repo,
                    &case.requested,
                    &pack,
                    &diff_entries,
                    real_ws_task,
                )
                .unwrap_or_else(|e| panic!("fixture {} failed via real ws-task: {e}", case.name));
                assert_eq!(
                    real_outcome, expected,
                    "real ws-task mismatch for fixture {}",
                    case.name
                );
            }
        }
    }

    #[test]
    fn verify_worktree_diff_and_pipelines_fail_closed_on_ws_task_errors_and_release_locks() {
        let missing_bin = Path::new("/nonexistent/path/to/ws-task");
        let fail_stub = StubWsTask::failing("fail-exit", 2, "classify-weight boom\n");
        let pack = sample_context_pack("S");
        let diff = vec![DiffFileEntry {
            path: "src/v2/router.rs".to_owned(),
            status: "M".to_owned(),
            added_lines: 5,
            deleted_lines: 1,
        }];

        assert!(verify_worktree_diff_with("zach", "S", &pack, &diff, missing_bin).is_err());
        assert!(verify_worktree_diff_with("zach", "S", &pack, &diff, fail_stub.path()).is_err());

        // XS/S pipeline marks attempt FAILED (infra) and releases path_locks on ws-task error
        let mut store = V2Store::open_in_memory().expect("in-memory store");
        store
            .upsert_task(&sample_s_task("ZACH-028-XS-ERR"))
            .unwrap();
        let mut xs_mock = MockStageExecutor {
            staged_results: vec![StageExecutionResult {
                status: "PASSED".to_owned(),
                summary: "impl ok".to_owned(),
                review_markdown: None,
                stage_output: None,
                review_output: None,
                invocation_id: None,
                input_tokens: Some(100),
                output_tokens: Some(50),
                total_tokens: Some(150),
                sha_before: Some("abc".to_owned()),
                sha_after: Some("def".to_owned()),
                diff_files: diff.clone(),
            }],
            ..MockStageExecutor::default()
        };
        let xs_err = execute_xs_s_pipeline_with_executor_and_ws_task(
            &mut store,
            "ZACH-028-XS-ERR",
            &mut xs_mock,
            fail_stub.path(),
        )
        .unwrap_err();
        assert!(xs_err.contains("ws-task classify-weight exited with"));
        assert!(store.list_path_locks(Some("zach")).unwrap().is_empty());
        let xs_attempts = store.list_stage_attempts("ZACH-028-XS-ERR").unwrap();
        assert_eq!(xs_attempts.len(), 1);
        assert_eq!(xs_attempts[0].status, "FAILED");
        assert_eq!(xs_attempts[0].failure_class.as_deref(), Some("infra"));

        // M/L pipeline marks attempt FAILED (infra) and releases path_locks on missing ws-task
        let mut ml_task = sample_s_task("ZACH-028-ML-ERR");
        ml_task.weight = "M".to_owned();
        ml_task.context_pack = sample_context_pack("M");
        ml_task.required_stages = vec!["impl".to_owned(), "pr-review".to_owned()];
        ml_task.stages_completed = vec!["plan".to_owned(), "plan-review".to_owned()];
        store.upsert_task(&ml_task).unwrap();
        let mut ml_mock = MockStageExecutor {
            staged_results: vec![StageExecutionResult {
                status: "PASSED".to_owned(),
                summary: "impl ok".to_owned(),
                review_markdown: None,
                stage_output: None,
                review_output: None,
                invocation_id: None,
                input_tokens: Some(100),
                output_tokens: Some(50),
                total_tokens: Some(150),
                sha_before: Some("abc".to_owned()),
                sha_after: Some("def".to_owned()),
                diff_files: diff,
            }],
            ..MockStageExecutor::default()
        };
        let ml_err = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            "ZACH-028-ML-ERR",
            &mut ml_mock,
            missing_bin,
        )
        .unwrap_err();
        assert!(ml_err.contains("failed to invoke"));
        assert!(store.list_path_locks(Some("zach")).unwrap().is_empty());
        let ml_attempts = store.list_stage_attempts("ZACH-028-ML-ERR").unwrap();
        assert_eq!(ml_attempts.len(), 1);
        assert_eq!(ml_attempts[0].status, "FAILED");
        assert_eq!(ml_attempts[0].failure_class.as_deref(), Some("infra"));
    }

    #[test]
    fn execute_m_l_pipeline_honors_m_to_l_escalation_required_stages_and_merge_approval_gate() {
        let mut store = V2Store::open_in_memory().expect("in-memory store");
        let mut task = sample_s_task("ZACH-028-M-TO-L");
        task.weight = "M".to_owned();
        task.context_pack = sample_context_pack("M");
        task.required_stages = vec![
            "plan".to_owned(),
            "plan-review".to_owned(),
            "impl".to_owned(),
            "pr-review".to_owned(),
        ];
        task.stages_completed = vec!["plan".to_owned(), "plan-review".to_owned()];
        store.upsert_task(&task).unwrap();

        let escalate_to_l_stub = StubWsTask::fixed_json(
            "m-to-l",
            r#"{"repository":"zach","requested_weight":"M","floor_weight":"L","effective_weight":"L","escalated":true,"required_stages":["plan","plan-review","human-plan-approval","impl","pr-review","human-merge-approval"],"reasons":["[L] critical path"]}"#,
        );

        let mut mock = MockStageExecutor {
            staged_results: vec![
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "impl touched critical path".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: None,
                    invocation_id: Some("inv-impl".to_owned()),
                    input_tokens: Some(1_000),
                    output_tokens: Some(200),
                    total_tokens: Some(1_200),
                    sha_before: Some("abc1234".to_owned()),
                    sha_after: Some("abc1234".to_owned()),
                    diff_files: vec![DiffFileEntry {
                        path: "src/v2/router.rs".to_owned(),
                        status: "M".to_owned(),
                        added_lines: 5,
                        deleted_lines: 1,
                    }],
                },
                StageExecutionResult {
                    status: "PASSED".to_owned(),
                    summary: "pr-review ok".to_owned(),
                    review_markdown: None,
                    stage_output: None,
                    review_output: Some(approved_verdict_json("AC-1", "src/v2/router.rs:1")),
                    invocation_id: Some("inv-rev".to_owned()),
                    input_tokens: Some(500),
                    output_tokens: Some(100),
                    total_tokens: Some(600),
                    sha_before: Some("mock-committed-sha".to_owned()),
                    sha_after: Some("mock-committed-sha".to_owned()),
                    diff_files: Vec::new(),
                },
            ],
            ..MockStageExecutor::default()
        };

        let paused = execute_m_l_pipeline_with_executor_and_ws_task(
            &mut store,
            "ZACH-028-M-TO-L",
            &mut mock,
            escalate_to_l_stub.path(),
        )
        .expect("M->L escalation should complete pr-review and pause at human-merge-approval");

        assert_eq!(paused.weight, "L");
        assert_eq!(paused.context_pack.weight, "L");
        assert_eq!(
            paused.required_stages,
            vec![
                "plan",
                "plan-review",
                "human-plan-approval",
                "impl",
                "pr-review",
                "human-merge-approval"
            ]
        );
        assert_eq!(paused.status, "Blocked");
        assert_eq!(
            paused.current_stage.as_deref(),
            Some("human-merge-approval")
        );
        let open_decs = store.list_decisions(true, None).unwrap();
        assert_eq!(open_decs.len(), 1);
        assert_eq!(open_decs[0].kind, "merge_approval");
    }
}
