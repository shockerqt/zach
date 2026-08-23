use zach::{
    AuditError, AuditSnapshot, BranchObservation, PullRequestEvidence, RunEvidence,
    WorkflowEvidence, evaluate_snapshot,
};

const IMPL: &str = "1111111111111111111111111111111111111111";
const MERGE: &str = "2222222222222222222222222222222222222222";

fn snapshot() -> AuditSnapshot {
    AuditSnapshot {
        task_id: "GOV-999".into(),
        request_id: "fixture-1".into(),
        governance_sha: "3333333333333333333333333333333333333333".into(),
        target_repository: "shockerqt/example".into(),
        canonical_branch: "task/GOV-999-example".into(),
        audited_implementation: RunEvidence {
            run_path: "runs/GOV-999/implementation.md".into(),
            publication_sha: IMPL.into(),
            implementation_sha: IMPL.into(),
            ci_sha: IMPL.into(),
            ci_conclusion: "success".into(),
            pull_request_url: "https://github.com/shockerqt/example/pull/9".into(),
            pull_request_head_sha: IMPL.into(),
        },
        pull_request: PullRequestEvidence {
            url: "https://github.com/shockerqt/example/pull/9".into(),
            merged: true,
            merge_commit_sha: Some(MERGE.into()),
            merged_at: Some("2026-08-22T00:00:00Z".into()),
            head_sha: IMPL.into(),
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

#[test]
fn positive_present_branch_receipt_keeps_evidence_namespaces_separate() {
    let receipt = evaluate_snapshot(snapshot()).unwrap();
    let json = receipt.to_json();
    assert!(json.contains("\"audit_run_publication\":null"));
    assert!(json.contains("\"audited_implementation\""));
    assert!(json.contains("\"integration_evidence\""));
    assert!(json.contains("\"state\":\"present\""));
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
fn implementation_not_represented_fails_closed() {
    let mut value = snapshot();
    value.pull_request.head_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    assert!(matches!(
        evaluate_snapshot(value),
        Err(AuditError::Verification(message)) if message.contains("exact merged pull-request head")
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
fn receipt_identity_is_idempotent_for_same_immutable_snapshot() {
    let first = evaluate_snapshot(snapshot()).unwrap();
    let second = evaluate_snapshot(snapshot()).unwrap();
    assert_eq!(first.receipt_id, second.receipt_id);
    assert_eq!(first.to_json(), second.to_json());
}
