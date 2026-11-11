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
        store.upsert_task(&record)?;
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
}
