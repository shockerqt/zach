use crate::v2::now_epoch;
use crate::v2::store::{
    AcceptanceCriterionSpec, ContextPackSpec, TargetFileSpec, TaskMemory, TaskRecord, V2Store,
    V2StoreError,
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

pub fn ingest_export_json(
    store: &mut V2Store,
    json_payload: &str,
) -> Result<IntakeSummary, V2StoreError> {
    let contract: ExportContract = serde_json::from_str(json_payload)?;
    if contract.schema_version != 2 {
        return Err(V2StoreError(format!(
            "unsupported ws-task export schema_version: {} (expected 2)",
            contract.schema_version
        )));
    }

    let now = now_epoch();
    let mut ingested_count = 0usize;

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
            executor: item.executor.clone(),
            autonomous_consent: item.autonomous_consent,
            retry_count: 0,
            memory: TaskMemory::default(),
            version: 1,
            updated_epoch: now,
        };
        store.sync_task(&record)?;
        ingested_count += 1;
    }

    store.record_heartbeat(now)?;
    let ready = store.list_ready_queue(None)?;
    let ready_task_ids: Vec<String> = ready.iter().map(|t| t.task_id.clone()).collect();

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
        .args(["export", "--json"])
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(persisted.branch.as_deref(), Some("task/new-branch"));
        assert_eq!(persisted.worktree_path.as_deref(), Some("/tmp/new-wt"));
        assert_eq!(persisted.task_group, "platform");
        assert_eq!(persisted.repository, "zach-next");
        assert_eq!(
            persisted.github_repo.as_deref(),
            Some("shockerqt/zach-next")
        );
        assert_eq!(persisted.issue_number, Some(77));
        assert!(!persisted.autonomous_consent);
        assert_eq!(persisted.context_pack.target_files.len(), 2);

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
}
