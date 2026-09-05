use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("zach-test-{}-{}-{}", name, std::process::id(), id));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("failed to create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run_cli(args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_zach-actions");
    Command::new(bin)
        .args(args)
        .output()
        .expect("failed to execute zach-actions")
}

fn make_event(
    action: &str,
    repo_id: u64,
    repo_name: &str,
    sender_id: u64,
    author_id: u64,
    issue_id: u64,
    issue_num: u64,
    body: &str,
    is_pr: bool,
) -> String {
    let pr_entry = if is_pr {
        r#","pull_request":{"url":"https://api.github.com/repos/shockerqt/zach/pulls/1"}"#
    } else {
        ""
    };
    let escaped_body = body
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");

    format!(
        r#"{{"action":"{action}","repository":{{"id":{repo_id},"full_name":"{repo_name}"}},"sender":{{"id":{sender_id}}},"issue":{{"id":{issue_id},"number":{issue_num},"user":{{"id":{author_id}}},"body":"{escaped_body}"{pr_entry}}}}}"#
    )
}

const SAMPLE_REQUEST_JSON: &str = r#"{
  "schema_version": 1,
  "request_id": "uds007-inspect-build-01",
  "operation": "github.ci.inspect",
  "parameters": {
    "repository": "ui-design-sandbox",
    "source_sha": "4330f61359da78543b12bd3b71f79fdaef235a86"
  }
}"#;

const SAMPLE_POLICY_REV: &str = "4ae216576b054f528c9edbcfed4a2711bccaa476";
const SAMPLE_ACCEPTED_AT: &str = "2026-09-05T07:47:52Z";

#[test]
fn test_unauthorized_acceptance() {
    let temp = TempDir::new("unauthorized");

    // Sender unauthorized (sender_id 9999 not in allowed 2001,2002)
    let event_unauth_sender = make_event(
        "opened",
        1001,
        "shockerqt/zach",
        9999,
        2001,
        501,
        42,
        SAMPLE_REQUEST_JSON,
        false,
    );
    let event_path_1 = temp.path().join("event_unauth_sender.json");
    fs::write(&event_path_1, event_unauth_sender).unwrap();

    let output_1 = run_cli(&[
        "accept",
        "--event",
        event_path_1.to_str().unwrap(),
        "--event-name",
        "issues",
        "--repository-id",
        "1001",
        "--repository-full-name",
        "shockerqt/zach",
        "--allowed-actor-ids",
        "2001,2002",
        "--accepted-at",
        SAMPLE_ACCEPTED_AT,
        "--policy-revision",
        SAMPLE_POLICY_REV,
    ]);

    assert_eq!(output_1.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&output_1.stderr).trim(),
        "unauthorized_sender"
    );
    assert!(output_1.stdout.is_empty());

    // Author unauthorized (author_id 9999 not in allowed 2001,2002)
    let event_unauth_author = make_event(
        "opened",
        1001,
        "shockerqt/zach",
        2001,
        9999,
        501,
        42,
        SAMPLE_REQUEST_JSON,
        false,
    );
    let event_path_2 = temp.path().join("event_unauth_author.json");
    fs::write(&event_path_2, event_unauth_author).unwrap();

    let output_2 = run_cli(&[
        "accept",
        "--event",
        event_path_2.to_str().unwrap(),
        "--event-name",
        "issues",
        "--repository-id",
        "1001",
        "--repository-full-name",
        "shockerqt/zach",
        "--allowed-actor-ids",
        "2001,2002",
        "--accepted-at",
        SAMPLE_ACCEPTED_AT,
        "--policy-revision",
        SAMPLE_POLICY_REV,
    ]);

    assert_eq!(output_2.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&output_2.stderr).trim(),
        "unauthorized_author"
    );
    assert!(output_2.stdout.is_empty());
}

#[test]
fn test_duplicate_flags() {
    let temp = TempDir::new("dup_flags");
    let event = make_event(
        "opened",
        1001,
        "shockerqt/zach",
        2001,
        2001,
        501,
        42,
        SAMPLE_REQUEST_JSON,
        false,
    );
    let event_path = temp.path().join("event.json");
    fs::write(&event_path, event).unwrap();

    // Duplicate --event flag
    let output = run_cli(&[
        "accept",
        "--event",
        event_path.to_str().unwrap(),
        "--event",
        event_path.to_str().unwrap(),
        "--event-name",
        "issues",
        "--repository-id",
        "1001",
        "--repository-full-name",
        "shockerqt/zach",
        "--allowed-actor-ids",
        "2001,2002",
        "--accepted-at",
        SAMPLE_ACCEPTED_AT,
        "--policy-revision",
        SAMPLE_POLICY_REV,
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "duplicate_flag"
    );
    assert!(output.stdout.is_empty());

    // Duplicate --record flag on claim
    let output_claim = run_cli(&[
        "claim",
        "--record",
        "rec1.json",
        "--record",
        "rec2.json",
        "--execution-id",
        "exec-01",
    ]);
    assert_eq!(output_claim.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&output_claim.stderr).trim(),
        "duplicate_flag"
    );
}

#[test]
fn test_lifecycle_accept_claim_repeated_claim_complete_terminal_replay() {
    let temp = TempDir::new("lifecycle");
    let event = make_event(
        "opened",
        1001,
        "shockerqt/zach",
        2001,
        2001,
        501,
        42,
        SAMPLE_REQUEST_JSON,
        false,
    );
    let event_path = temp.path().join("event.json");
    fs::write(&event_path, &event).unwrap();

    let record_path = temp.path().join("record.json");

    // 1. accept -> exit 0
    let out_accept = run_cli(&[
        "accept",
        "--event",
        event_path.to_str().unwrap(),
        "--event-name",
        "issues",
        "--repository-id",
        "1001",
        "--repository-full-name",
        "shockerqt/zach",
        "--allowed-actor-ids",
        "2001,2002",
        "--accepted-at",
        SAMPLE_ACCEPTED_AT,
        "--policy-revision",
        SAMPLE_POLICY_REV,
    ]);

    assert_eq!(out_accept.status.code(), Some(0));
    assert!(out_accept.stderr.is_empty());
    let accept_json = String::from_utf8(out_accept.stdout).unwrap();
    assert!(accept_json.contains("\"state\":\"accepted\""));
    assert!(accept_json.contains("\"request_id\":\"uds007-inspect-build-01\""));
    fs::write(&record_path, &accept_json).unwrap();

    // 2. claim -> Granted exit 0
    let out_claim = run_cli(&[
        "claim",
        "--record",
        record_path.to_str().unwrap(),
        "--execution-id",
        "exec-001",
    ]);

    assert_eq!(out_claim.status.code(), Some(0));
    assert!(out_claim.stderr.is_empty());
    let claim_json = String::from_utf8(out_claim.stdout).unwrap();
    assert!(claim_json.contains("\"state\":\"executing\""));
    assert!(claim_json.contains("\"execution_id\":\"exec-001\""));
    fs::write(&record_path, &claim_json).unwrap();

    // 3. repeated claim -> ReconciliationRequired exit 75
    let out_claim_repeat = run_cli(&[
        "claim",
        "--record",
        record_path.to_str().unwrap(),
        "--execution-id",
        "exec-001",
    ]);

    assert_eq!(out_claim_repeat.status.code(), Some(75));
    assert!(out_claim_repeat.stderr.is_empty());
    let repeat_json = String::from_utf8(out_claim_repeat.stdout).unwrap();
    assert!(repeat_json.contains("\"state\":\"executing\""));
    assert!(repeat_json.contains("\"execution_id\":\"exec-001\""));

    // Repeated claim with a different execution ID also exit 75
    let out_claim_diff = run_cli(&[
        "claim",
        "--record",
        record_path.to_str().unwrap(),
        "--execution-id",
        "exec-002",
    ]);
    assert_eq!(out_claim_diff.status.code(), Some(75));
    assert!(out_claim_diff.stderr.is_empty());

    // 4. complete -> exit 0
    let out_complete = run_cli(&[
        "complete",
        "--record",
        record_path.to_str().unwrap(),
        "--state",
        "succeeded",
        "--code",
        "build_passed",
        "--reference",
        "sha-commit-12345",
    ]);

    assert_eq!(out_complete.status.code(), Some(0));
    assert!(out_complete.stderr.is_empty());
    let complete_json = String::from_utf8(out_complete.stdout).unwrap();
    assert!(complete_json.contains("\"state\":\"succeeded\""));
    assert!(complete_json.contains("\"terminal_code\":\"build_passed\""));
    assert!(complete_json.contains("\"terminal_reference\":\"sha-commit-12345\""));
    fs::write(&record_path, &complete_json).unwrap();

    // 5. claim on terminal record -> TerminalReplay exit 10
    let out_terminal_claim = run_cli(&[
        "claim",
        "--record",
        record_path.to_str().unwrap(),
        "--execution-id",
        "exec-003",
    ]);

    assert_eq!(out_terminal_claim.status.code(), Some(10));
    assert!(out_terminal_claim.stderr.is_empty());
    let terminal_json = String::from_utf8(out_terminal_claim.stdout).unwrap();
    assert!(terminal_json.contains("\"state\":\"succeeded\""));
    assert!(terminal_json.contains("\"terminal_code\":\"build_passed\""));
    assert!(terminal_json.contains("\"terminal_reference\":\"sha-commit-12345\""));
}

#[test]
fn test_edited_request_conflict() {
    let temp = TempDir::new("edited_conflict");
    let event = make_event(
        "opened",
        1001,
        "shockerqt/zach",
        2001,
        2001,
        501,
        42,
        SAMPLE_REQUEST_JSON,
        false,
    );
    let event_path = temp.path().join("event.json");
    fs::write(&event_path, &event).unwrap();

    let record_path = temp.path().join("record.json");

    // Accept original event
    let out_accept = run_cli(&[
        "accept",
        "--event",
        event_path.to_str().unwrap(),
        "--event-name",
        "issues",
        "--repository-id",
        "1001",
        "--repository-full-name",
        "shockerqt/zach",
        "--allowed-actor-ids",
        "2001,2002",
        "--accepted-at",
        SAMPLE_ACCEPTED_AT,
        "--policy-revision",
        SAMPLE_POLICY_REV,
    ]);
    assert_eq!(out_accept.status.code(), Some(0));
    fs::write(&record_path, out_accept.stdout).unwrap();

    // Exact replay succeeds -> exit 0
    let out_replay_ok = run_cli(&[
        "replay",
        "--record",
        record_path.to_str().unwrap(),
        "--event",
        event_path.to_str().unwrap(),
        "--event-name",
        "issues",
        "--repository-id",
        "1001",
        "--repository-full-name",
        "shockerqt/zach",
        "--allowed-actor-ids",
        "2001,2002",
    ]);
    assert_eq!(out_replay_ok.status.code(), Some(0));
    assert!(out_replay_ok.stderr.is_empty());

    // Edited event with different parameters
    let edited_request_json = r#"{
  "schema_version": 1,
  "request_id": "uds007-inspect-build-01",
  "operation": "github.ci.inspect",
  "parameters": {
    "repository": "different-sandbox",
    "source_sha": "4330f61359da78543b12bd3b71f79fdaef235a86"
  }
}"#;
    let edited_event = make_event(
        "edited",
        1001,
        "shockerqt/zach",
        2002,
        2001,
        501,
        42,
        edited_request_json,
        false,
    );
    let edited_event_path = temp.path().join("edited_event.json");
    fs::write(&edited_event_path, edited_event).unwrap();

    let out_replay_conflict = run_cli(&[
        "replay",
        "--record",
        record_path.to_str().unwrap(),
        "--event",
        edited_event_path.to_str().unwrap(),
        "--event-name",
        "issues",
        "--repository-id",
        "1001",
        "--repository-full-name",
        "shockerqt/zach",
        "--allowed-actor-ids",
        "2001,2002",
    ]);
    assert_eq!(out_replay_conflict.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out_replay_conflict.stderr).trim(),
        "replay_canonical_request_mismatch"
    );
    assert!(out_replay_conflict.stdout.is_empty());

    // Edited event with different author_id
    let diff_author_event = make_event(
        "opened",
        1001,
        "shockerqt/zach",
        2001,
        2002, // author changed from 2001 to 2002
        501,
        42,
        SAMPLE_REQUEST_JSON,
        false,
    );
    let diff_author_path = temp.path().join("diff_author_event.json");
    fs::write(&diff_author_path, diff_author_event).unwrap();

    let out_replay_author = run_cli(&[
        "replay",
        "--record",
        record_path.to_str().unwrap(),
        "--event",
        diff_author_path.to_str().unwrap(),
        "--event-name",
        "issues",
        "--repository-id",
        "1001",
        "--repository-full-name",
        "shockerqt/zach",
        "--allowed-actor-ids",
        "2001,2002",
    ]);
    assert_eq!(out_replay_author.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out_replay_author.stderr).trim(),
        "replay_author_id_mismatch"
    );
}

#[test]
fn test_malformed_and_oversized_files() {
    let temp = TempDir::new("malformed_oversized");

    // 1. Malformed event JSON
    let bad_event_path = temp.path().join("bad_event.json");
    fs::write(&bad_event_path, "{ not valid json }").unwrap();

    let out_bad_event = run_cli(&[
        "accept",
        "--event",
        bad_event_path.to_str().unwrap(),
        "--event-name",
        "issues",
        "--repository-id",
        "1001",
        "--repository-full-name",
        "shockerqt/zach",
        "--allowed-actor-ids",
        "2001,2002",
        "--accepted-at",
        SAMPLE_ACCEPTED_AT,
        "--policy-revision",
        SAMPLE_POLICY_REV,
    ]);
    assert_eq!(out_bad_event.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out_bad_event.stderr).trim(),
        "malformed_event_json"
    );

    // 2. Oversized event file (> 256 KiB)
    let huge_event_path = temp.path().join("huge_event.json");
    let huge_data = vec![b'a'; 256 * 1024 + 10];
    fs::write(&huge_event_path, huge_data).unwrap();

    let out_huge_event = run_cli(&[
        "accept",
        "--event",
        huge_event_path.to_str().unwrap(),
        "--event-name",
        "issues",
        "--repository-id",
        "1001",
        "--repository-full-name",
        "shockerqt/zach",
        "--allowed-actor-ids",
        "2001,2002",
        "--accepted-at",
        SAMPLE_ACCEPTED_AT,
        "--policy-revision",
        SAMPLE_POLICY_REV,
    ]);
    assert_eq!(out_huge_event.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out_huge_event.stderr).trim(),
        "event_payload_too_large"
    );

    // 3. Malformed journal record JSON
    let bad_record_path = temp.path().join("bad_record.json");
    fs::write(&bad_record_path, "not an object json").unwrap();

    let out_bad_record = run_cli(&[
        "claim",
        "--record",
        bad_record_path.to_str().unwrap(),
        "--execution-id",
        "exec-001",
    ]);
    assert_eq!(out_bad_record.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out_bad_record.stderr).trim(),
        "journal_json_malformed"
    );

    // 4. Oversized journal record file (> 64 KiB)
    let huge_record_path = temp.path().join("huge_record.json");
    let huge_record_data = vec![b'x'; 64 * 1024 + 10];
    fs::write(&huge_record_path, huge_record_data).unwrap();

    let out_huge_record = run_cli(&[
        "claim",
        "--record",
        huge_record_path.to_str().unwrap(),
        "--execution-id",
        "exec-001",
    ]);
    assert_eq!(out_huge_record.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out_huge_record.stderr).trim(),
        "journal_payload_too_large"
    );
}

#[test]
fn test_ambiguous_and_reconcile() {
    let temp = TempDir::new("ambiguous_reconcile");
    let event = make_event(
        "opened",
        1001,
        "shockerqt/zach",
        2001,
        2001,
        501,
        42,
        SAMPLE_REQUEST_JSON,
        false,
    );
    let event_path = temp.path().join("event.json");
    fs::write(&event_path, &event).unwrap();

    let record_path = temp.path().join("record.json");

    // 1. Accept
    let out_accept = run_cli(&[
        "accept",
        "--event",
        event_path.to_str().unwrap(),
        "--event-name",
        "issues",
        "--repository-id",
        "1001",
        "--repository-full-name",
        "shockerqt/zach",
        "--allowed-actor-ids",
        "2001,2002",
        "--accepted-at",
        SAMPLE_ACCEPTED_AT,
        "--policy-revision",
        SAMPLE_POLICY_REV,
    ]);
    assert_eq!(out_accept.status.code(), Some(0));
    fs::write(&record_path, out_accept.stdout).unwrap();

    // 2. Claim
    let out_claim = run_cli(&[
        "claim",
        "--record",
        record_path.to_str().unwrap(),
        "--execution-id",
        "exec-001",
    ]);
    assert_eq!(out_claim.status.code(), Some(0));
    fs::write(&record_path, out_claim.stdout).unwrap();

    // 3. Mark ambiguous
    let out_ambiguous = run_cli(&["ambiguous", "--record", record_path.to_str().unwrap()]);
    assert_eq!(out_ambiguous.status.code(), Some(0));
    let ambiguous_json = String::from_utf8(out_ambiguous.stdout).unwrap();
    assert!(ambiguous_json.contains("\"state\":\"ambiguous\""));
    assert!(ambiguous_json.contains("\"execution_id\":\"exec-001\""));
    fs::write(&record_path, &ambiguous_json).unwrap();

    // 4. complete on ambiguous record is forbidden -> exit 2 unauthorized_reconciliation
    let out_unauth = run_cli(&[
        "complete",
        "--record",
        record_path.to_str().unwrap(),
        "--state",
        "succeeded",
        "--code",
        "ok",
    ]);
    assert_eq!(out_unauth.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out_unauth.stderr).trim(),
        "unauthorized_reconciliation"
    );

    // 5. Reconcile with verified observation -> exit 0
    let out_reconcile = run_cli(&[
        "reconcile",
        "--record",
        record_path.to_str().unwrap(),
        "--state",
        "succeeded",
        "--code",
        "audit_verified_success",
        "--reference",
        "merge-sha-abcdef",
    ]);
    assert_eq!(out_reconcile.status.code(), Some(0));
    let reconciled_json = String::from_utf8(out_reconcile.stdout).unwrap();
    assert!(reconciled_json.contains("\"state\":\"succeeded\""));
    assert!(reconciled_json.contains("\"terminal_code\":\"audit_verified_success\""));
    assert!(reconciled_json.contains("\"terminal_reference\":\"merge-sha-abcdef\""));
    fs::write(&record_path, &reconciled_json).unwrap();

    // 6. Conflicting reconcile on already terminal record -> exit 2 conflicting_terminal_result
    let out_conflict = run_cli(&[
        "reconcile",
        "--record",
        record_path.to_str().unwrap(),
        "--state",
        "rejected",
        "--code",
        "failed_check",
    ]);
    assert_eq!(out_conflict.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out_conflict.stderr).trim(),
        "conflicting_terminal_result"
    );
}

#[test]
fn test_cli_flags_rejections() {
    // Missing command
    let out = run_cli(&[]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "missing_command"
    );

    // Unknown command
    let out = run_cli(&["invalid-cmd"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "unknown_command"
    );

    // Unknown flag
    let out = run_cli(&["accept", "--unknown-flag", "val"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "unknown_flag");

    // Missing flag value (at end of args)
    let out = run_cli(&["claim", "--record", "file.json", "--execution-id"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "missing_flag_value"
    );

    // Missing flag value (followed by another flag)
    let out = run_cli(&["claim", "--record", "--execution-id", "id1"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "missing_flag_value"
    );

    // Unexpected positional
    let out = run_cli(&["ambiguous", "pos_arg", "--record", "file.json"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "unexpected_positional"
    );

    // Missing required flag
    let out = run_cli(&["claim", "--record", "file.json"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "missing_required_flag"
    );

    // Invalid flag value (non-integer repository id)
    let out = run_cli(&[
        "accept",
        "--event",
        "file.json",
        "--event-name",
        "issues",
        "--repository-id",
        "not-a-number",
        "--repository-full-name",
        "owner/repo",
        "--allowed-actor-ids",
        "101",
        "--accepted-at",
        SAMPLE_ACCEPTED_AT,
        "--policy-revision",
        SAMPLE_POLICY_REV,
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr).trim(),
        "invalid_flag_value"
    );

    // IO error (non-existent file)
    let out = run_cli(&[
        "claim",
        "--record",
        "/path/that/definitely/does/not/exist.json",
        "--execution-id",
        "exec-01",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "io_error");

    // Help output contains restriction text
    let out_help = run_cli(&["reconcile", "--help"]);
    assert_eq!(out_help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out_help.stdout).contains("RESTRICTION:"));
}

#[test]
fn test_preserve_existing_binary() {
    let bin = env!("CARGO_BIN_EXE_zach");
    let out = Command::new(bin)
        .arg("--health")
        .output()
        .expect("failed to execute zach");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "zach: healthy");
}
