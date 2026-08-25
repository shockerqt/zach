use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use zach::{
    AuditError, AuditIdempotencyStore, AuditRequest, AuditSnapshot, BranchObservation,
    IdempotencyClaim, PullRequestEvidence, RepresentationEvidence, RunEvidence, RunEvidenceRole,
    WorkflowEvidence, canonical_request_digest, evaluate_snapshot, execute_idempotent_audit,
    select_audited_implementation,
};

const IMPL: &str = "1111111111111111111111111111111111111111";
const MERGE: &str = "2222222222222222222222222222222222222222";
const GOV42_IMPL: &str = "2766a9b6434dccf31773405a0e0e2fa240578be3";
const GOV42_HEAD: &str = "f0a39592a707f8fa8d9df3930334f1ca67dc3a82";
const GOV42_MERGE: &str = "8ce820805b38834176d5e8af7eb8042a9a1b3157";

fn request(task_id: &str, request_id: &str) -> AuditRequest {
    AuditRequest {
        task_id: task_id.into(),
        request_id: request_id.into(),
    }
}

fn implementation(path: &str, sha: &str) -> RunEvidence {
    RunEvidence {
        run_path: path.into(),
        publication_sha: sha.into(),
        implementation_sha: sha.into(),
        ci_sha: sha.into(),
        ci_conclusion: "success".into(),
        pull_request_url: "https://github.com/shockerqt/example/pull/9".into(),
        pull_request_head_sha: sha.into(),
        role: RunEvidenceRole::Implementation,
    }
}

fn integration_audit(path: &str, terminal_sha: &str, audited_sha: &str) -> RunEvidence {
    RunEvidence {
        run_path: path.into(),
        publication_sha: terminal_sha.into(),
        implementation_sha: terminal_sha.into(),
        ci_sha: terminal_sha.into(),
        ci_conclusion: "success".into(),
        pull_request_url: "https://github.com/shockerqt/example/pull/9".into(),
        pull_request_head_sha: terminal_sha.into(),
        role: RunEvidenceRole::IntegrationAudit {
            audited_implementation_sha: audited_sha.into(),
            audited_pull_request_url: "https://github.com/shockerqt/example/pull/9".into(),
        },
    }
}

fn snapshot_for(req: &AuditRequest, digest: &str) -> AuditSnapshot {
    AuditSnapshot {
        task_id: req.task_id.clone(),
        request_id: req.request_id.clone(),
        request_digest: digest.into(),
        governance_sha: "3333333333333333333333333333333333333333".into(),
        target_repository: "shockerqt/example".into(),
        canonical_branch: "task/GOV-999-example".into(),
        audited_implementation: implementation("runs/GOV-999/implementation.md", IMPL),
        pull_request: PullRequestEvidence {
            url: "https://github.com/shockerqt/example/pull/9".into(),
            merged: true,
            merge_commit_sha: Some(MERGE.into()),
            merged_at: Some("2026-08-22T00:00:00Z".into()),
            head_sha: IMPL.into(),
        },
        representation: RepresentationEvidence {
            implementation_is_ancestor_or_equal_of_pr_head: true,
            pr_head_is_ancestor_or_equal_of_merge: true,
        },
        post_merge_runs: vec![WorkflowEvidence {
            id: 42,
            head_sha: MERGE.into(),
            conclusion: "success".into(),
            url: "https://github.com/shockerqt/example/actions/runs/42".into(),
        }],
        branch: BranchObservation::Present {
            sha: IMPL.into(),
            open_pr_urls: Vec::new(),
        },
    }
}

fn snapshot() -> AuditSnapshot {
    let req = request("GOV-999", "fixture-1");
    let digest = canonical_request_digest(&req).unwrap();
    snapshot_for(&req, &digest)
}

#[test]
fn implementation_equal_to_final_pr_head_is_represented() {
    let receipt = evaluate_snapshot(snapshot()).unwrap();
    let json = receipt.to_json();
    assert!(json.contains("\"implementation_represented\":true"));
    assert!(json.contains("\"method\":\"git_ancestry_through_merged_pr_head\""));
}

#[test]
fn gov042_prior_implementation_is_represented_through_final_administrative_head() {
    let mut value = snapshot();
    value.audited_implementation = RunEvidence {
        run_path: "runs/GOV-042/20260822-165000-harden-grandfathering-and-integrate.md".into(),
        publication_sha: GOV42_IMPL.into(),
        implementation_sha: GOV42_IMPL.into(),
        ci_sha: GOV42_IMPL.into(),
        ci_conclusion: "success".into(),
        pull_request_url: "https://github.com/shockerqt/workspace-governance/pull/45".into(),
        pull_request_head_sha: GOV42_IMPL.into(),
        role: RunEvidenceRole::Implementation,
    };
    value.target_repository = "shockerqt/workspace-governance".into();
    value.canonical_branch = "task/GOV-042-audit-agent-provenance".into();
    value.pull_request = PullRequestEvidence {
        url: "https://github.com/shockerqt/workspace-governance/pull/45".into(),
        merged: true,
        merge_commit_sha: Some(GOV42_MERGE.into()),
        merged_at: Some("2026-08-22T17:01:08Z".into()),
        head_sha: GOV42_HEAD.into(),
    };
    value.post_merge_runs = vec![WorkflowEvidence {
        id: 32586468273,
        head_sha: GOV42_MERGE.into(),
        conclusion: "success".into(),
        url: "https://github.com/shockerqt/workspace-governance/actions/runs/32586468273".into(),
    }];
    value.branch = BranchObservation::Absent;
    let receipt = evaluate_snapshot(value).unwrap();
    let json = receipt.to_json();
    assert!(json.contains(GOV42_IMPL));
    assert!(json.contains(GOV42_HEAD));
    assert!(json.contains(GOV42_MERGE));
}

#[test]
fn existing_but_unrelated_sha_is_rejected() {
    let mut value = snapshot();
    value.pull_request.head_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    value
        .representation
        .implementation_is_ancestor_or_equal_of_pr_head = false;
    assert!(matches!(
        evaluate_snapshot(value),
        Err(AuditError::Verification(message)) if message.contains("not represented")
    ));
}

#[test]
fn later_or_not_represented_implementation_is_rejected() {
    let mut value = snapshot();
    value
        .representation
        .implementation_is_ancestor_or_equal_of_pr_head = false;
    assert!(matches!(
        evaluate_snapshot(value),
        Err(AuditError::Verification(message)) if message.contains("not represented")
    ));
}

#[test]
fn pr_head_not_represented_by_merge_is_rejected() {
    let mut value = snapshot();
    value.representation.pr_head_is_ancestor_or_equal_of_merge = false;
    assert!(matches!(
        evaluate_snapshot(value),
        Err(AuditError::Verification(message)) if message.contains("not represented")
    ));
}

#[test]
fn absent_branch_is_valid_observation() {
    let mut value = snapshot();
    value.branch = BranchObservation::Absent;
    let receipt = evaluate_snapshot(value).unwrap();
    assert!(receipt.to_json().contains("\"state\":\"absent\""));
}

#[test]
fn unmerged_pr_fails_closed() {
    let mut value = snapshot();
    value.pull_request.merged = false;
    assert!(matches!(
        evaluate_snapshot(value),
        Err(AuditError::Verification(message)) if message.contains("not merged")
    ));
}

#[test]
fn ci_from_another_sha_fails_closed() {
    let mut value = snapshot();
    value.post_merge_runs[0].head_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    assert!(matches!(
        evaluate_snapshot(value),
        Err(AuditError::Verification(message)) if message.contains("exact merge SHA")
    ));
}

#[test]
fn failed_exact_sha_ci_fails_closed() {
    let mut value = snapshot();
    value.post_merge_runs[0].conclusion = "failure".into();
    assert!(matches!(
        evaluate_snapshot(value),
        Err(AuditError::Verification(message)) if message.contains("exact merge SHA")
    ));
}

#[test]
fn two_coherent_incompatible_implementation_runs_are_ambiguous() {
    let one = implementation(
        "runs/GOV-999/one.md",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let two = implementation(
        "runs/GOV-999/two.md",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    assert!(matches!(
        select_audited_implementation(&[one, two]),
        Err(AuditError::AmbiguousEvidence(_))
    ));
}

#[test]
fn implementation_plus_records_only_integration_run_selects_implementation() {
    let implementation = implementation(
        "runs/GOV-999/implementation.md",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let administrative = integration_audit(
        "runs/GOV-999/integration.md",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    assert_eq!(
        select_audited_implementation(&[implementation.clone(), administrative]).unwrap(),
        implementation
    );
}

#[test]
fn explicit_integration_audit_distinguishes_one_of_multiple_implementations() {
    let old = implementation(
        "runs/GOV-999/old.md",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let final_impl = implementation(
        "runs/GOV-999/final.md",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    let audit = integration_audit(
        "runs/GOV-999/integration.md",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    assert_eq!(
        select_audited_implementation(&[old, final_impl.clone(), audit]).unwrap(),
        final_impl
    );
}

#[test]
fn semantically_wrong_administrative_terminal_evidence_cannot_be_audited_implementation() {
    let actual = implementation(
        "runs/GOV-999/implementation.md",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let wrong_admin = integration_audit(
        "runs/GOV-999/integration.md",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    assert!(matches!(
        select_audited_implementation(&[actual, wrong_admin]),
        Err(AuditError::Verification(_))
    ));
}

#[derive(Default)]
struct MemoryStore {
    records: BTreeMap<String, (String, Option<String>)>,
}

impl AuditIdempotencyStore for MemoryStore {
    fn claim(
        &mut self,
        request_id: &str,
        request_digest: &str,
    ) -> Result<IdempotencyClaim, AuditError> {
        if let Some((digest, terminal)) = self.records.get(request_id) {
            return Ok(IdempotencyClaim::Existing {
                request_digest: digest.clone(),
                terminal_receipt: terminal.clone(),
            });
        }
        self.records
            .insert(request_id.into(), (request_digest.into(), None));
        Ok(IdempotencyClaim::Claimed)
    }

    fn complete(
        &mut self,
        request_id: &str,
        request_digest: &str,
        terminal_receipt: &str,
    ) -> Result<(), AuditError> {
        let Some((digest, terminal)) = self.records.get_mut(request_id) else {
            return Err(AuditError::Idempotency("claim disappeared".into()));
        };
        if digest != request_digest || terminal.is_some() {
            return Err(AuditError::Idempotency(
                "terminal completion does not match one pending claim".into(),
            ));
        }
        *terminal = Some(terminal_receipt.into());
        Ok(())
    }
}

#[test]
fn exact_replay_after_online_snapshot_changes_returns_identical_terminal_receipt() {
    let req = request("GOV-999", "replay-1");
    let mut store = MemoryStore::default();
    let first = execute_idempotent_audit(&mut store, &req, |digest| {
        evaluate_snapshot(snapshot_for(&req, digest))
    })
    .unwrap();

    let mut reran = false;
    let second = execute_idempotent_audit(&mut store, &req, |_digest| {
        reran = true;
        panic!("a terminal replay must not query a changed online snapshot")
    })
    .unwrap();

    assert!(!reran);
    assert_eq!(first, second);
}

#[test]
fn same_request_id_with_different_request_digest_conflicts_before_execution() {
    let first_request = request("GOV-999", "conflict-1");
    let second_request = request("GOV-998", "conflict-1");
    let mut store = MemoryStore::default();
    execute_idempotent_audit(&mut store, &first_request, |digest| {
        evaluate_snapshot(snapshot_for(&first_request, digest))
    })
    .unwrap();

    let mut reran = false;
    let result = execute_idempotent_audit(&mut store, &second_request, |_digest| {
        reran = true;
        panic!("conflicting request identity must fail before online execution")
    });
    assert!(!reran);
    assert!(matches!(result, Err(AuditError::Idempotency(_))));
}

struct FileStore {
    path: PathBuf,
}

impl FileStore {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn read(&self) -> Result<Option<(String, String, Option<String>)>, AuditError> {
        if !self.path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&self.path)
            .map_err(|error| AuditError::Idempotency(format!("test store read failed: {error}")))?;
        let mut lines = content.lines();
        let request_id = lines
            .next()
            .ok_or_else(|| AuditError::Idempotency("test store missing request id".into()))?;
        let digest = lines
            .next()
            .ok_or_else(|| AuditError::Idempotency("test store missing digest".into()))?;
        let state = lines
            .next()
            .ok_or_else(|| AuditError::Idempotency("test store missing state".into()))?;
        let terminal = match state {
            "pending" => None,
            "terminal" => Some(lines.collect::<Vec<_>>().join("\n")),
            _ => return Err(AuditError::Idempotency("test store has invalid state".into())),
        };
        Ok(Some((request_id.into(), digest.into(), terminal)))
    }

    fn write(
        &self,
        request_id: &str,
        digest: &str,
        terminal: Option<&str>,
    ) -> Result<(), AuditError> {
        let content = match terminal {
            Some(receipt) => format!("{request_id}\n{digest}\nterminal\n{receipt}"),
            None => format!("{request_id}\n{digest}\npending\n"),
        };
        fs::write(&self.path, content)
            .map_err(|error| AuditError::Idempotency(format!("test store write failed: {error}")))
    }
}

impl AuditIdempotencyStore for FileStore {
    fn claim(
        &mut self,
        request_id: &str,
        request_digest: &str,
    ) -> Result<IdempotencyClaim, AuditError> {
        if let Some((stored_id, digest, terminal)) = self.read()? {
            if stored_id != request_id {
                return Err(AuditError::Idempotency(
                    "test store contains another request".into(),
                ));
            }
            return Ok(IdempotencyClaim::Existing {
                request_digest: digest,
                terminal_receipt: terminal,
            });
        }
        self.write(request_id, request_digest, None)?;
        Ok(IdempotencyClaim::Claimed)
    }

    fn complete(
        &mut self,
        request_id: &str,
        request_digest: &str,
        terminal_receipt: &str,
    ) -> Result<(), AuditError> {
        let Some((stored_id, digest, terminal)) = self.read()? else {
            return Err(AuditError::Idempotency("test claim disappeared".into()));
        };
        if stored_id != request_id || digest != request_digest || terminal.is_some() {
            return Err(AuditError::Idempotency(
                "test completion does not match pending claim".into(),
            ));
        }
        self.write(request_id, request_digest, Some(terminal_receipt))
    }
}

fn unique_temp_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "zach-audit-idempotency-{}-{nanos}.txt",
        std::process::id()
    ))
}

fn cleanup(path: &Path) {
    let _ = fs::remove_file(path);
}

#[test]
fn terminal_replay_survives_new_store_instance() {
    let path = unique_temp_path();
    let req = request("GOV-999", "restart-1");
    let first = {
        let mut store = FileStore::new(path.clone());
        execute_idempotent_audit(&mut store, &req, |digest| {
            evaluate_snapshot(snapshot_for(&req, digest))
        })
        .unwrap()
    };
    let second = {
        let mut store = FileStore::new(path.clone());
        execute_idempotent_audit(&mut store, &req, |_digest| {
            panic!("fresh logical instance must replay persisted terminal receipt")
        })
        .unwrap()
    };
    cleanup(&path);
    assert_eq!(first, second);
}

#[test]
fn prior_terminal_receipt_cannot_be_replaced_by_later_evidence() {
    let req = request("GOV-999", "immutable-terminal-1");
    let mut store = MemoryStore::default();
    let first = execute_idempotent_audit(&mut store, &req, |digest| {
        evaluate_snapshot(snapshot_for(&req, digest))
    })
    .unwrap();
    let second = execute_idempotent_audit(&mut store, &req, |_digest| {
        panic!("stored terminal evidence is immutable for a request id")
    })
    .unwrap();
    assert_eq!(first, second);
}
