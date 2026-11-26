use crate::v2::now_epoch;
use crate::v2::store::{
    AcceptanceCriterionSpec, ContextPackSpec, SyncMode, TargetFileSpec, TaskMemory, TaskRecord,
    V2Store, V2StoreError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportContract {
    pub schema_version: u32,
    #[serde(default)]
    pub exported_at: Option<String>,
    #[serde(default)]
    pub total_tasks: usize,
    #[serde(default)]
    pub tasks: Vec<ExportTaskItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportClaimSummary {
    #[serde(default)]
    pub executor: Option<String>,
    #[serde(default)]
    pub holder: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub alive: bool,
    #[serde(default)]
    pub state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportTaskItem {
    pub id: String,
    #[serde(default)]
    pub task_group: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub repository: String,
    #[serde(default)]
    pub github_repo: Option<String>,
    #[serde(default)]
    pub issue_number: Option<i64>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub weight: String,
    #[serde(default)]
    pub required_stages: Vec<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub worktree: Option<String>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub stages_completed: Vec<String>,
    #[serde(default)]
    pub reviewed_sha: Option<String>,
    #[serde(default)]
    pub executor: Option<String>,
    #[serde(default)]
    pub claim: Option<ExportClaimSummary>,
    #[serde(default = "default_true")]
    pub autonomous_consent: bool,
    #[serde(default)]
    pub context_pack: Option<Value>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntakeSummary {
    pub ingested_count: usize,
    pub ready_eligible_count: usize,
    pub ready_task_ids: Vec<String>,
}

pub fn parse_context_pack(raw: Option<&Value>, fallback_weight: &str) -> ContextPackSpec {
    let Some(Value::Object(map)) = raw else {
        return ContextPackSpec {
            weight: fallback_weight.to_owned(),
            ..ContextPackSpec::default()
        };
    };

    let weight = map
        .get("weight")
        .and_then(Value::as_str)
        .unwrap_or(fallback_weight)
        .to_owned();
    let base_sha = map
        .get("base_sha")
        .and_then(Value::as_str)
        .map(str::to_owned);

    let target_files = map
        .get("target_files")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| match item {
                    Value::String(s) => Some(TargetFileSpec {
                        path: s.clone(),
                        action: "modify".to_owned(),
                        summary: String::new(),
                    }),
                    Value::Object(obj) => {
                        let path = obj.get("path").and_then(Value::as_str)?.to_owned();
                        let action = obj
                            .get("action")
                            .and_then(Value::as_str)
                            .unwrap_or("modify")
                            .to_owned();
                        let summary = obj
                            .get("summary")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned();
                        Some(TargetFileSpec {
                            path,
                            action,
                            summary,
                        })
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    let string_list = |key: &str| -> Vec<String> {
        map.get(key)
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };

    let acceptance_criteria = map
        .get("acceptance_criteria")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .enumerate()
                .filter_map(|(idx, item)| match item {
                    Value::String(s) => {
                        let (id, desc) = s
                            .split_once(':')
                            .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
                            .unwrap_or_else(|| (format!("AC-{}", idx + 1), s.clone()));
                        Some(AcceptanceCriterionSpec {
                            id,
                            description: desc,
                        })
                    }
                    Value::Object(obj) => {
                        let id = obj
                            .get("id")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                            .unwrap_or_else(|| format!("AC-{}", idx + 1));
                        let description = obj
                            .get("description")
                            .or_else(|| obj.get("criterion"))
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned();
                        Some(AcceptanceCriterionSpec { id, description })
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    ContextPackSpec {
        // Preserve invalid values for per-task rejection; never poison the export.
        network: map.get("network").filter(|v| !v.is_null()).map(|v| {
            v.as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| v.to_string())
        }),
        weight,
        base_sha,
        target_files,
        forbidden_paths: string_list("forbidden_paths"),
        worker_checks: string_list("worker_checks"),
        gate_checks: string_list("gate_checks"),
        human_operations: string_list("human_operations"),
        verification_commands: string_list("verification_commands"),
        acceptance_criteria,
    }
}

/// Legacy stage-list fallback used only when an ingested export task omits
/// `required_stages` (or in unit fixtures); weight floor classification itself
/// is owned exclusively by `ws-task classify-weight`.
pub fn default_required_stages(weight: &str) -> Vec<String> {
    match weight.to_ascii_uppercase().as_str() {
        "XS" => vec!["impl".to_owned()],
        "S" => vec!["impl".to_owned(), "pr-review".to_owned()],
        "L" => vec![
            "plan".to_owned(),
            "plan-review".to_owned(),
            "human-plan-approval".to_owned(),
            "impl".to_owned(),
            "pr-review".to_owned(),
            "human-merge-approval".to_owned(),
        ],
        _ => vec![
            "plan".to_owned(),
            "plan-review".to_owned(),
            "impl".to_owned(),
            "pr-review".to_owned(),
        ],
    }
}

pub fn decode_export_records(json_payload: &str) -> Result<Vec<TaskRecord>, V2StoreError> {
    let contract: ExportContract = serde_json::from_str(json_payload)?;
    if contract.schema_version != 2 {
        return Err(V2StoreError(format!(
            "unsupported ws-task export schema_version: {} (expected 2)",
            contract.schema_version
        )));
    }

    let now = now_epoch();
    let mut records = Vec::new();

    for item in &contract.tasks {
        let weight = if item.weight.trim().is_empty() {
            "M".to_owned()
        } else {
            item.weight.trim().to_ascii_uppercase()
        };
        let task_group = if item.task_group.trim().is_empty() {
            item.id
                .split('-')
                .next()
                .unwrap_or("default")
                .to_ascii_lowercase()
        } else {
            item.task_group.trim().to_ascii_lowercase()
        };
        let required_stages = if item.required_stages.is_empty() {
            default_required_stages(&weight)
        } else {
            item.required_stages.clone()
        };
        let context_pack = parse_context_pack(item.context_pack.as_ref(), &weight);
        let plan_base_sha = context_pack.base_sha.clone();
        let branch = item
            .branch
            .as_ref()
            .filter(|b| !b.is_empty() && b.as_str() != "none")
            .cloned();
        let worktree_path = item
            .worktree
            .as_ref()
            .filter(|w| !w.is_empty() && w.as_str() != "none")
            .cloned();

        let effective_executor = item
            .claim
            .as_ref()
            .filter(|c| c.alive)
            .and_then(|c| c.executor.clone())
            .or_else(|| item.executor.clone());
        let record = TaskRecord {
            task_id: item.id.clone(),
            task_group,
            title: item.title.clone(),
            repository: if item.repository.trim().is_empty() {
                "governance".to_owned()
            } else {
                item.repository.clone()
            },
            github_repo: item.github_repo.clone(),
            issue_number: item.issue_number,
            weight,
            status: if item.status.trim().is_empty() {
                "Backlog".to_owned()
            } else {
                item.status.clone()
            },
            worktree_path,
            branch,
            context_pack,
            depends_on: item.depends_on.clone(),
            required_stages,
            stages_completed: item.stages_completed.clone(),
            current_stage: None,
            active_attempt_id: None,
            plan_base_sha,
            reviewed_sha: item.reviewed_sha.clone(),
            pr_number: None,
            executor: effective_executor.clone(),
            autonomous_consent: item.autonomous_consent,
            retry_count: 0,
            next_retry_epoch: 0,
            lease_owner: None,
            lease_expires_epoch: None,
            memory: TaskMemory {
                governance_started: effective_executor
                    .as_deref()
                    .is_some_and(|executor| executor.eq_ignore_ascii_case("zach"))
                    && matches!(
                        item.status.as_str(),
                        "Planning" | "Plan Review" | "In Progress" | "PR Review" | "Blocked"
                    ),
                ..TaskMemory::default()
            },
            version: 1,
            updated_epoch: now,
        };
        records.push(record);
    }

    Ok(records)
}

pub fn ingest_export_json(
    store: &mut V2Store,
    json_payload: &str,
) -> Result<IntakeSummary, V2StoreError> {
    ingest_task_records(store, decode_export_records(json_payload)?)
}

pub fn ingest_task_records(
    store: &mut V2Store,
    records: Vec<TaskRecord>,
) -> Result<IntakeSummary, V2StoreError> {
    ingest_task_records_with_mode(store, records, SyncMode::Standard)
}

/// Caller must establish and hold native offline ownership for reconciliation.
pub fn ingest_task_records_with_mode(
    store: &mut V2Store,
    records: Vec<TaskRecord>,
    mode: SyncMode,
) -> Result<IntakeSummary, V2StoreError> {
    let ingested_count = records.len();
    for record in records {
        store.sync_task_with_mode(&record, mode)?;
    }
    store.set_meta("last_sync_epoch", &now_epoch().to_string())?;
    let ready_task_ids = store
        .list_ready_queue(None)?
        .into_iter()
        .map(|t| t.task_id)
        .collect::<Vec<_>>();
    Ok(IntakeSummary {
        ingested_count,
        ready_eligible_count: ready_task_ids.len(),
        ready_task_ids,
    })
}

pub fn sync_from_ws_task(
    store: &mut V2Store,
    ws_task_bin: &Path,
) -> Result<IntakeSummary, V2StoreError> {
    let output = Command::new(ws_task_bin)
        .env("WS_TASK_EXECUTOR", "zach")
        .args(["export", "--sync", "--json"])
        .output()
        .map_err(|e| V2StoreError(format!("failed to invoke {}: {e}", ws_task_bin.display())))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(V2StoreError(format!(
            "ws-task export --json exited with {}: {}",
            output.status,
            stderr.trim()
        )));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| V2StoreError(format!("ws-task export output was not valid UTF-8: {e}")))?;
    ingest_export_json(store, &stdout)
}

/// All invocations run on coordinator workers; arguments never pass through a shell.
pub trait WsTaskClient: Send + Sync {
    fn execute(&self, args: &[String]) -> Result<String, String>;
}

pub struct SystemWsTaskClient {
    pub bin: std::path::PathBuf,
}

impl WsTaskClient for SystemWsTaskClient {
    fn execute(&self, args: &[String]) -> Result<String, String> {
        let out = Command::new(&self.bin)
            .env("WS_TASK_EXECUTOR", "zach")
            .args(args)
            .output()
            .map_err(|e| format!("ws-task spawn: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "ws-task {} failed ({}): {}",
                args.first().map(String::as_str).unwrap_or(""),
                out.status,
                crate::v2::runner::truncate_utf8_bytes(&String::from_utf8_lossy(&out.stderr), 1024)
            ));
        }
        String::from_utf8(out.stdout).map_err(|e| e.to_string())
    }
}

pub fn stage_operation(
    task: &TaskRecord,
    key: &str,
    stage: &str,
    body_path: &Path,
    verdict: Option<&str>,
    sha: Option<&str>,
    actor: &str,
) -> crate::v2::store::LifecycleOperation {
    stage_operation_with_receipt(task, key, stage, body_path, verdict, sha, actor, None)
}

#[allow(clippy::too_many_arguments)]
pub fn stage_operation_with_receipt(
    task: &TaskRecord,
    key: &str,
    stage: &str,
    body_path: &Path,
    verdict: Option<&str>,
    sha: Option<&str>,
    actor: &str,
    receipt_path: Option<&Path>,
) -> crate::v2::store::LifecycleOperation {
    let mut args = vec![
        "stage".into(),
        task.task_id.clone(),
        stage.into(),
        "--actor".into(),
        actor.into(),
        "--body-file".into(),
        body_path.to_string_lossy().into_owned(),
    ];
    if let Some(verdict) = verdict {
        args.extend(["--verdict".into(), verdict.into()]);
    }
    if let Some(sha) = sha {
        args.extend(["--sha".into(), sha.into()]);
    }
    if let Some(receipt) = receipt_path {
        args.extend(["--receipt".into(), receipt.to_string_lossy().into_owned()]);
    }
    args.extend(["--idempotency-key".into(), key.into()]);
    crate::v2::store::LifecycleOperation {
        attempt_id: task.active_attempt_id.clone(),
        decision_id: key.strip_prefix("decision-").map(str::to_owned),
        operation_id: key.into(),
        task_id: task.task_id.clone(),
        kind: stage.into(),
        args,
        body_path: Some(body_path.to_string_lossy().into_owned()),
        depends_on: None,
        state: "PENDING".into(),
        retry_epoch: 0,
        attempts: 0,
        last_error: None,
    }
}

/// Git provisioning may print diagnostics before ws-task's final JSON receipt.
pub fn parse_start_receipt(output: &str, task_id: &str) -> Result<Value, String> {
    for (offset, _) in output.match_indices('{') {
        if let Ok(value) = serde_json::from_str::<Value>(&output[offset..])
            && value["task_id"].as_str() == Some(task_id)
        {
            return Ok(value);
        }
    }
    Err("ws-task start did not return a matching structured receipt".into())
}

/// Shared candidate-plan publication contract, used before plan-review dispatch.
pub fn publish_plan_stage(
    task: &TaskRecord,
    key: &str,
    path: &Path,
) -> crate::v2::store::LifecycleOperation {
    let sha = task
        .plan_base_sha
        .as_deref()
        .filter(|s| !s.trim().is_empty() && *s != "head-sha");
    stage_operation(task, key, "plan", path, None, sha, "zach")
}

pub fn infer_pack_weight_floor(paths: &[String], has_new_file: bool) -> &'static str {
    let mut floor = "XS";
    for raw in paths {
        let p = raw
            .trim()
            .trim_start_matches("./")
            .trim_start_matches('/')
            .to_ascii_lowercase();
        if p.starts_with("infrastructure/")
            || p.starts_with(".github/workflows/")
            || p.starts_with("migrations/")
            || p.contains("/migrations/")
            || p.ends_with(".sql")
            || p == "governance-manifest.yaml"
        {
            return "L";
        }
        if matches!(
            p.rsplit('/').next().unwrap_or(""),
            "cargo.toml" | "cargo.lock" | "package.json" | "pyproject.toml" | "go.mod"
        ) {
            floor = "M";
        }
    }
    if floor == "M" || has_new_file || paths.len() > 4 {
        "M"
    } else if paths.len() > 2 {
        "S"
    } else {
        floor
    }
}

pub fn draft_context_pack_yaml(repo_root: &Path, candidate_paths: &[String]) -> String {
    let (mut norm_paths, mut entries, mut has_new) = (Vec::new(), Vec::new(), false);
    for raw in candidate_paths {
        let norm = raw
            .trim()
            .trim_start_matches("./")
            .trim_start_matches('/')
            .to_owned();
        if norm.is_empty() {
            continue;
        }
        let action = if repo_root.join(&norm).exists() {
            "modify"
        } else {
            has_new = true;
            "create"
        };
        entries.push(format!(
            "  - path: {norm}\n    action: {action}\n    summary: \"TODO: describe change\""
        ));
        norm_paths.push(norm);
    }
    let weight = infer_pack_weight_floor(&norm_paths, has_new);
    let files_block = if entries.is_empty() {
        " []".to_owned()
    } else {
        format!("\n{}", entries.join("\n"))
    };
    format!(
        "network: none\nweight: {weight}\ntarget_files:{files_block}\nforbidden_paths:\n  - \".github/workflows/**\"\nworker_checks:\n  - \"cargo test --locked\"\ngate_checks:\n  - \"git diff --check\"\nverification_commands:\n  - \"cargo test --locked\"\nacceptance_criteria:\n  - id: AC-1\n    description: \"TODO: describe acceptance criterion\"\n"
    )
}

pub fn validate_context_pack_yaml(yaml_text: &str) -> Result<(), Vec<String>> {
    let strip_q = |s: &str| s.trim().trim_matches('"').trim_matches('\'').to_owned();
    let push_pair = |list: &mut Vec<(String, String)>, line: &str, k1: &str, k2: &str| {
        if let Some(rest) = line.strip_prefix("- ") {
            list.push((String::new(), String::new()));
            if let Some(v) = rest.trim().strip_prefix(k1) {
                list.last_mut().unwrap().0 = strip_q(v);
            }
        } else if let Some(last) = list.last_mut() {
            if let Some(v) = line.strip_prefix(k1) {
                last.0 = strip_q(v);
            } else if let Some(v) = line.strip_prefix(k2) {
                last.1 = strip_q(v);
            }
        }
    };
    let (mut section, mut seen, mut check_count) = ("", std::collections::HashSet::new(), 0usize);
    let (mut target_files, mut acs) = (Vec::new(), Vec::new());
    for raw in yaml_text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("```") {
            continue;
        }
        if !raw.starts_with(' ') && !raw.starts_with('\t') {
            if let Some((k, _)) = line.split_once(':') {
                section = k.trim();
                seen.insert(section.to_owned());
                continue;
            }
        }
        match section {
            "target_files" => push_pair(&mut target_files, line, "path:", "action:"),
            "acceptance_criteria" => push_pair(&mut acs, line, "id:", "description:"),
            "worker_checks" | "gate_checks" | "verification_commands"
                if line
                    .strip_prefix("- ")
                    .is_some_and(|v| !strip_q(v).is_empty()) =>
            {
                check_count += 1
            }
            _ => {}
        }
    }
    let mut errs = Vec::new();
    for req in [
        "target_files",
        "forbidden_paths",
        "worker_checks",
        "gate_checks",
        "verification_commands",
        "acceptance_criteria",
    ] {
        if !seen.contains(req) {
            errs.push(format!("missing required section: {req}"));
        }
    }
    if target_files.is_empty() {
        errs.push("target_files must be a non-empty list".into());
    }
    for (i, (p, a)) in target_files.iter().enumerate() {
        if p.is_empty() {
            errs.push(format!("target_files[{i}].path must be non-empty"));
        }
        if !matches!(a.as_str(), "modify" | "create" | "delete") {
            errs.push(format!(
                "target_files[{i}].action must be modify|create|delete, got '{a}'"
            ));
        }
    }
    if check_count == 0 {
        errs.push("at least one check in worker_checks, gate_checks, or verification_commands is required".into());
    }
    if acs.is_empty() {
        errs.push("acceptance_criteria must be a non-empty list".into());
    }
    for (i, (id, desc)) in acs.iter().enumerate() {
        if !id
            .strip_prefix("AC-")
            .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
        {
            errs.push(format!(
                "acceptance_criteria[{i}].id must be numbered like AC-1, got '{id}'"
            ));
        }
        if desc.is_empty() {
            errs.push(format!(
                "acceptance_criteria[{i}].description must be non-empty"
            ));
        }
    }
    if errs.is_empty() { Ok(()) } else { Err(errs) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_offline_intake_preserves_completed_stage_history_from_empty_export() {
        let mut store = V2Store::open_in_memory().unwrap();
        let payload = r#"{"schema_version":2,"tasks":[{"id":"SYNTHETIC-INTAKE","repository":"zach","status":"Done","weight":"S","autonomous_consent":true}]}"#;
        ingest_export_json(&mut store, payload).unwrap();
        let mut old = store.get_task("SYNTHETIC-INTAKE").unwrap().unwrap();
        old.active_attempt_id = Some("finished-intake".into());
        old.stages_completed = vec!["impl".into()];
        old.current_stage = Some("impl".into());
        store.upsert_task(&old).unwrap();
        store.connection_mut().execute_batch("INSERT INTO stage_attempts(attempt_id,task_id,stage,model,effort,started_epoch,ended_epoch,status,phase) VALUES('finished-intake','SYNTHETIC-INTAKE','impl','synthetic','low',1,2,'PASSED','COMPLETE')").unwrap();
        let records = decode_export_records(payload).unwrap();
        ingest_task_records_with_mode(&mut store, records, SyncMode::ReconcileFinishedLegacy)
            .unwrap();
        let after = store.get_task(&old.task_id).unwrap().unwrap();
        assert!(after.active_attempt_id.is_none());
        assert_eq!(after.stages_completed, old.stages_completed);
        assert_eq!(after.current_stage, old.current_stage);
        assert_eq!(after.autonomous_consent, old.autonomous_consent);
        assert!(store.lifecycle_ops().unwrap().is_empty());
        assert!(store.list_ready_queue(None).unwrap().is_empty());
    }

    #[test]
    fn network_intake_preserves_invalid_values_for_per_task_rejection() {
        use crate::v2::isolation::NetworkPolicy;
        use crate::v2::router::ModelFamily;
        for value in [
            serde_json::json!("all"),
            serde_json::json!(true),
            serde_json::json!(["none"]),
        ] {
            let raw = serde_json::json!({"network":value});
            let pack = parse_context_pack(Some(&raw), "S");
            assert!(pack.network.is_some());
            assert!(
                NetworkPolicy::resolve(pack.network.as_deref(), ModelFamily::OpenAiSol).is_err()
            );
        }
        for network in ["none", "provider-api"] {
            let raw = serde_json::json!({"network":network});
            assert_eq!(
                parse_context_pack(Some(&raw), "S").network.as_deref(),
                Some(network)
            );
        }
        assert_eq!(
            parse_context_pack(Some(&serde_json::json!({})), "S").network,
            None
        );
        let mut store = V2Store::open_in_memory().unwrap();
        let export = serde_json::json!({"schema_version":2,"tasks":[
            {"id":"BAD","weight":"S","repository":"zach","status":"Ready","context_pack":{"network":true}},
            {"id":"GOOD","weight":"S","repository":"zach","status":"Ready","context_pack":{"network":"none"}}
        ]});
        assert_eq!(
            ingest_export_json(&mut store, &export.to_string())
                .unwrap()
                .ingested_count,
            2
        );
        assert_eq!(
            store
                .get_task("GOOD")
                .unwrap()
                .unwrap()
                .context_pack
                .network
                .as_deref(),
            Some("none")
        );
        assert_eq!(
            store
                .get_task("BAD")
                .unwrap()
                .unwrap()
                .context_pack
                .network
                .as_deref(),
            Some("true")
        );
    }

    #[test]
    fn ingest_export_json_populates_store_and_filters_ready_queue_by_dependencies() {
        let mut store = V2Store::open_in_memory().expect("in-memory store");
        let payload = r#"{
            "schema_version": 2,
            "exported_at": "2026-11-11T16:00:00Z",
            "total_tasks": 3,
            "tasks": [
                {
                    "id": "GOV-048",
                    "task_group": "gov",
                    "title": "Board and ws-task v2 CLI",
                    "repository": "governance",
                    "status": "Done",
                    "weight": "M",
                    "depends_on": [],
                    "autonomous_consent": true
                },
                {
                    "id": "ZACH-004",
                    "task_group": "zach",
                    "title": "SQLite store and intake",
                    "repository": "zach",
                    "status": "Ready",
                    "weight": "M",
                    "depends_on": ["GOV-048"],
                    "autonomous_consent": true,
                    "context_pack": {
                        "weight": "M",
                        "target_files": [
                            {"path": "src/v2/store.rs", "action": "create", "summary": "SQLite store"}
                        ],
                        "worker_checks": ["cargo test"],
                        "gate_checks": ["cargo test"],
                        "acceptance_criteria": [
                            {"id": "AC-1", "description": "SQLite WAL store works"}
                        ]
                    }
                },
                {
                    "id": "ZACH-005",
                    "task_group": "zach",
                    "title": "Stage runner",
                    "repository": "zach",
                    "status": "Ready",
                    "weight": "M",
                    "depends_on": ["ZACH-004"],
                    "autonomous_consent": true
                }
            ]
        }"#;

        let summary = ingest_export_json(&mut store, payload).expect("ingest");
        assert_eq!(summary.ingested_count, 3);
        assert_eq!(summary.ready_eligible_count, 1);
        assert_eq!(summary.ready_task_ids, vec!["ZACH-004".to_owned()]);

        let z4 = store.get_task("ZACH-004").unwrap().unwrap();
        assert_eq!(z4.context_pack.target_files.len(), 1);
        assert_eq!(z4.context_pack.target_files[0].path, "src/v2/store.rs");
        assert_eq!(z4.context_pack.acceptance_criteria[0].id, "AC-1");
    }

    #[test]
    fn ingest_export_json_preserves_zach_owned_task_state_and_honors_terminal_board_status() {
        let mut store = V2Store::open_in_memory().expect("in-memory store");

        let mut memory = TaskMemory::default();
        memory.recent_attempts.push("attempt-1".to_owned());
        memory.token_usage_by_stage.insert("impl".to_owned(), 1500);
        memory.last_check_failure = Some("prior failure".to_owned());

        let zach_task = TaskRecord {
            task_id: "ZACH-021".to_owned(),
            task_group: "zach".to_owned(),
            title: "Original title".to_owned(),
            repository: "zach".to_owned(),
            github_repo: Some("shockerqt/zach".to_owned()),
            issue_number: Some(54),
            weight: "S".to_owned(),
            status: "Queued for Merge".to_owned(),
            worktree_path: Some("/tmp/old-wt".to_owned()),
            branch: Some("task/old-branch".to_owned()),
            context_pack: ContextPackSpec::default(),
            depends_on: Vec::new(),
            required_stages: default_required_stages("S"),
            stages_completed: vec!["impl".to_owned(), "pr-review".to_owned()],
            current_stage: Some("merge_queue".to_owned()),
            active_attempt_id: Some("zach-021-pr-review-2".to_owned()),
            plan_base_sha: Some("internal-base-sha".to_owned()),
            reviewed_sha: Some("internal-reviewed-sha".to_owned()),
            pr_number: Some(65),
            executor: Some("zach".to_owned()),
            autonomous_consent: true,
            retry_count: 2,
            next_retry_epoch: 0,
            lease_owner: None,
            lease_expires_epoch: None,
            memory: memory.clone(),
            version: 1,
            updated_epoch: 1000,
        };
        store.upsert_task(&zach_task).expect("seed zach task");

        // Sync while board still says Ready with empty stages_completed and no executor,
        // but updated spec fields.
        let sync_payload = r#"{
            "schema_version": 2,
            "tasks": [
                {
                    "id": "ZACH-021",
                    "task_group": "platform",
                    "title": "Updated title from board",
                    "repository": "zach-next",
                    "github_repo": "shockerqt/zach-next",
                    "issue_number": 77,
                    "status": "Ready",
                    "weight": "M",
                    "branch": "task/new-branch",
                    "worktree": "/tmp/new-wt",
                    "depends_on": ["GOV-001"],
                    "stages_completed": [],
                    "reviewed_sha": "board-reviewed-sha",
                    "executor": null,
                    "autonomous_consent": false,
                    "context_pack": {
                        "weight": "M",
                        "base_sha": "board-base-sha",
                        "target_files": ["src/v2/intake.rs", "src/v2/store.rs"],
                        "acceptance_criteria": ["AC-1: preserve runtime state"]
                    }
                }
            ]
        }"#;

        let summary = ingest_export_json(&mut store, sync_payload).expect("sync ingest");
        assert_eq!(summary.ingested_count, 1);
        // Must NOT be placed back in ready queue since internal status remains Queued for Merge.
        assert!(summary.ready_task_ids.is_empty());

        let persisted = store.get_task("ZACH-021").unwrap().unwrap();
        // AC-1: Runtime state preserved
        assert_eq!(persisted.status, "Queued for Merge");
        assert_eq!(persisted.stages_completed, vec!["impl", "pr-review"]);
        assert_eq!(persisted.current_stage.as_deref(), Some("merge_queue"));
        assert_eq!(
            persisted.active_attempt_id.as_deref(),
            Some("zach-021-pr-review-2")
        );
        assert_eq!(
            persisted.plan_base_sha.as_deref(),
            Some("internal-base-sha")
        );
        assert_eq!(
            persisted.reviewed_sha.as_deref(),
            Some("internal-reviewed-sha")
        );
        assert_eq!(persisted.pr_number, Some(65));
        assert_eq!(persisted.executor.as_deref(), Some("zach"));
        assert_eq!(persisted.retry_count, 2);
        assert_eq!(persisted.memory, memory);

        // AC-2: Spec fields refreshed
        assert_eq!(persisted.title, "Updated title from board");
        assert_eq!(persisted.weight, "M");
        assert_eq!(persisted.depends_on, vec!["GOV-001".to_owned()]);
        assert_eq!(persisted.branch, zach_task.branch);
        assert_eq!(persisted.worktree_path, zach_task.worktree_path);
        assert_eq!(persisted.task_group, "platform");
        assert_eq!(persisted.repository, zach_task.repository);
        assert_eq!(
            persisted.github_repo.as_deref(),
            zach_task.github_repo.as_deref()
        );
        assert_eq!(persisted.issue_number, zach_task.issue_number);
        assert!(!persisted.autonomous_consent);
        assert_eq!(
            persisted.context_pack.target_files,
            zach_task.context_pack.target_files
        );

        // AC-2: Board status of Cancelled wins even when executor == "zach"
        let cancel_payload = r#"{
            "schema_version": 2,
            "tasks": [
                {
                    "id": "ZACH-021",
                    "task_group": "platform",
                    "title": "Cancelled title",
                    "repository": "zach-next",
                    "status": "Cancelled",
                    "weight": "M",
                    "autonomous_consent": true
                }
            ]
        }"#;
        ingest_export_json(&mut store, cancel_payload).expect("cancel ingest");
        let cancelled = store.get_task("ZACH-021").unwrap().unwrap();
        assert_eq!(cancelled.status, "Cancelled");
        assert_eq!(cancelled.title, "Cancelled title");
    }

    #[test]
    fn pack_draft_infers_actions_floor_weight_and_validates_read_only() {
        let tmp = std::env::temp_dir().join(format!("zach-pack-draft-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join("src")).unwrap();
        std::fs::write(tmp.join("src/a.rs"), "// existing\n").unwrap();

        let xs = draft_context_pack_yaml(&tmp, &["src/a.rs".into()]);
        assert!(xs.contains("weight: XS\n") && xs.contains("action: modify"));
        assert!(validate_context_pack_yaml(&xs).is_ok());

        let m = draft_context_pack_yaml(&tmp, &["src/a.rs".into(), "src/new.rs".into()]);
        assert!(m.contains("weight: M\n") && m.contains("action: create"));
        assert!(validate_context_pack_yaml(&m).is_ok());

        assert_eq!(
            infer_pack_weight_floor(&["a.rs".into(), "b.rs".into(), "c.rs".into()], false),
            "S"
        );
        for p in [
            "infrastructure/main.tf",
            ".github/workflows/ci.yml",
            "db/001.sql",
        ] {
            assert_eq!(infer_pack_weight_floor(&[p.into()], false), "L");
        }

        let bad = "target_files:\n  - path: src/a.rs\n    action: bogus\nacceptance_criteria:\n  - id: bad\n    description: \"\"\n";
        let errs = validate_context_pack_yaml(bad).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("forbidden_paths")));
        assert!(errs.iter().any(|e| e.contains("modify|create|delete")));
        assert!(errs.iter().any(|e| e.contains("AC-1")));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
