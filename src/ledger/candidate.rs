//! Preparatory candidate data; callers establish trusted context authority.
use super::actions::ActionOperation;
use super::actions_journal::{JournalRecord, JournalState};
use super::json::{Json, jcs};
use super::validator::{ChangeOperation, PinnedGovernanceValidator};
#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const CANDIDATE_REVISION: &str = "7f7af5752ef2e016ffe7116f84648b3350fe507f";
/// Integrated transport profile; does not replace the candidate tooling pin.
pub const ACTIONS_TRANSPORT_REVISION: &str = "4eec2150563db6b32907797080b305cb9f443d40";
pub const MAX_INPUT_BYTES: u64 = 256 * 1024;
const OPERATIONS: &[&str] = &[
    "task.create",
    "run.create",
    "task.start_run",
    "run.record_evidence",
    "run.record_remote_evidence",
    "run.transition_status",
    "task.append_run",
    "task.transition_status",
];

#[derive(Debug, Clone, Default)]
pub struct TrustedLedgerContext {
    pub(super) remote_preflight: Option<Json>,
    pub(super) remote_evidence: Option<Json>,
}
impl TrustedLedgerContext {
    fn to_json(&self) -> Json {
        let mut fields = Vec::new();
        if let Some(value) = &self.remote_preflight {
            fields.push(("remote_preflight".into(), value.clone()));
        }
        if let Some(value) = &self.remote_evidence {
            fields.push(("remote_evidence".into(), value.clone()));
        }
        Json::Object(fields)
    }
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        if text.len() as u64 > MAX_INPUT_BYTES {
            return Err("input-too-large");
        }
        let value = Json::parse(text).map_err(|_| "invalid-trusted-context")?;
        let object = value.as_object().ok_or("invalid-trusted-context")?;
        let mut context = Self::default();
        for (key, value) in object {
            if value.as_object().is_none() {
                return Err("invalid-trusted-context");
            }
            match key.as_str() {
                "remote_preflight" => context.remote_preflight = Some(value.clone()),
                "remote_evidence" => context.remote_evidence = Some(value.clone()),
                _ => return Err("invalid-trusted-context"),
            }
        }
        jcs(&value).map_err(|_| "invalid-trusted-context")?;
        Ok(context)
    }
}

fn expiry(accepted_at: &str) -> Result<String, &'static str> {
    if accepted_at.len() > 35 {
        return Err("request-time-invalid");
    }
    let epoch =
        super::actions_journal::parse_utc_epoch(accepted_at).ok_or("request-time-invalid")?;
    let expires = epoch.checked_add(3600).ok_or("request-time-invalid")?;
    let mut result = super::epoch_to_rfc3339(expires);
    if result.len() != 20 {
        return Err("request-time-invalid");
    }
    if let Some((_, fraction)) = accepted_at.strip_suffix('Z').unwrap().split_once('.') {
        result.pop();
        result.push('.');
        result.push_str(fraction);
        result.push('Z');
    }
    Ok(result)
}

fn inner_request(journal: &JournalRecord) -> Result<Json, &'static str> {
    if journal.operation() != ActionOperation::GovernanceLedger
        || journal.state() != JournalState::Executing
        || journal.execution_id().is_none()
    {
        return Err("journal-binding-invalid");
    }
    let outer = Json::parse(journal.canonical_request()).map_err(|_| "journal-binding-invalid")?;
    let parameters = outer.get("parameters").ok_or("request-invalid")?;
    let fields = parameters.as_object().ok_or("request-invalid")?;
    if !matches!(fields.len(), 3 | 4)
        || fields.iter().any(|(key, _)| {
            !["base_sha", "operation", "parameters", "agent_declaration"].contains(&key.as_str())
        })
    {
        return Err("request-invalid");
    }
    let base = parameters
        .get("base_sha")
        .and_then(Json::as_str)
        .ok_or("request-invalid")?;
    let operation = parameters
        .get("operation")
        .and_then(Json::as_str)
        .ok_or("request-invalid")?;
    let inner_parameters = parameters.get("parameters").ok_or("request-invalid")?;
    if let Some(declaration) = parameters.get("agent_declaration") {
        if !matches!(operation, "run.create" | "task.start_run")
            || declaration.as_object().is_none()
        {
            return Err("request-invalid");
        }
    } else if fields.len() != 3 {
        return Err("request-invalid");
    }
    if !super::sha40(base) || inner_parameters.as_object().is_none() {
        return Err("request-invalid");
    }
    if !OPERATIONS.contains(&operation)
        || (operation == "task.transition_status"
            && !matches!(
                inner_parameters.get("target_status").and_then(Json::as_str),
                Some("planned" | "active" | "blocked" | "cancelled")
            ))
    {
        return Err("operation-not-allowed");
    }
    Ok(Json::Object(vec![
        ("schema_version".into(), Json::Number("1".into())),
        (
            "request_id".into(),
            Json::String(journal.request_id().into()),
        ),
        ("base_sha".into(), Json::String(base.into())),
        ("operation".into(), Json::String(operation.into())),
        ("parameters".into(), inner_parameters.clone()),
        (
            "created_at".into(),
            Json::String(journal.accepted_at().into()),
        ),
        (
            "expires_at".into(),
            Json::String(expiry(journal.accepted_at())?),
        ),
        (
            "contract_revision".into(),
            Json::String(CANDIDATE_REVISION.into()),
        ),
    ]))
}

/// Derive bound candidate data from a frozen executing journal. The caller must
/// independently authenticate the journal, revisions, context and producer.
pub fn derive_actions_candidate(
    mirror: PathBuf,
    journal_json: &str,
    accepted_revision: &str,
    claim_revision: &str,
    context: &TrustedLedgerContext,
) -> Result<String, String> {
    if !super::sha40(accepted_revision) || !super::sha40(claim_revision) {
        return Err("journal-revision-invalid".into());
    }
    let journal =
        JournalRecord::from_json(journal_json).map_err(|_| "journal-invalid".to_owned())?;
    let inner = inner_request(&journal).map_err(str::to_owned)?;
    let request = jcs(&inner).map_err(|_| "request-invalid".to_owned())?;
    let candidate = derive_candidate(mirror, &request, journal.accepted_at(), context)?;
    let candidate = Json::parse(&candidate).map_err(|_| "validator-output-invalid".to_owned())?;
    bound_artifact(
        &journal,
        accepted_revision,
        claim_revision,
        inner,
        context,
        candidate,
    )
}

fn bound_artifact(
    journal: &JournalRecord,
    accepted_revision: &str,
    claim_revision: &str,
    inner: Json,
    context: &TrustedLedgerContext,
    candidate: Json,
) -> Result<String, String> {
    let result = jcs(&Json::Object(vec![
        (
            "kind".into(),
            Json::String("governance-actions-ledger-candidate".into()),
        ),
        ("schema_version".into(), Json::Number("1".into())),
        (
            "request_id".into(),
            Json::String(journal.request_id().into()),
        ),
        (
            "outer_request_digest".into(),
            Json::String(journal.request_digest().into()),
        ),
        (
            "accepted_revision".into(),
            Json::String(accepted_revision.into()),
        ),
        ("claim_revision".into(), Json::String(claim_revision.into())),
        (
            "policy_revision".into(),
            Json::String(journal.policy_revision().into()),
        ),
        (
            "accepted_at".into(),
            Json::String(journal.accepted_at().into()),
        ),
        ("inner_request".into(), inner),
        ("trusted_context".into(), context.to_json()),
        ("candidate".into(), candidate),
    ]))
    .map_err(|_| "candidate-invalid".to_owned())?;
    if result.len() as u64 > MAX_INPUT_BYTES {
        return Err("artifact-too-large".into());
    }
    Ok(result)
}

/// Returns exact candidate JSON, without receipt authentication or publication.
pub fn derive_candidate(
    mirror: PathBuf,
    request_json: &str,
    accepted_at: &str,
    context: &TrustedLedgerContext,
) -> Result<String, String> {
    if request_json.len() as u64 > MAX_INPUT_BYTES {
        return Err("input-too-large".into());
    }
    let value = Json::parse(request_json).map_err(|_| "request-invalid".to_owned())?;
    let request = super::parse_request_object(&value).map_err(str::to_owned)?;
    if !OPERATIONS.contains(&request.operation.as_str()) {
        return Err("operation-not-allowed".into());
    }
    if request.operation == "task.transition_status"
        && !matches!(
            request
                .parameters
                .get("target_status")
                .and_then(Json::as_str),
            Some("planned" | "active" | "blocked" | "cancelled")
        )
    {
        return Err("operation-not-allowed".into());
    }
    let validator = PinnedGovernanceValidator::candidate(mirror).map_err(|error| error.code)?;
    let result = validator
        .validate_with_context(&request, accepted_at, Some(context))
        .map_err(|error| error.code)?;
    let changes = result
        .changes
        .into_iter()
        .map(|change| {
            Json::Object(vec![
                ("path".into(), Json::String(change.path)),
                (
                    "operation".into(),
                    Json::String(
                        match change.operation {
                            ChangeOperation::Upsert => "upsert",
                            ChangeOperation::Delete => "delete",
                        }
                        .into(),
                    ),
                ),
                (
                    "content".into(),
                    change.content.map(Json::String).unwrap_or(Json::Null),
                ),
                (
                    "blob_sha".into(),
                    change.blob_sha.map(Json::String).unwrap_or(Json::Null),
                ),
            ])
        })
        .collect();
    let output = jcs(&Json::Object(vec![
        (
            "kind".into(),
            Json::String("governance-ledger-candidate".into()),
        ),
        ("schema_version".into(), Json::Number("1".into())),
        ("request_id".into(), Json::String(request.request_id)),
        (
            "request_digest".into(),
            Json::String(request.request_digest),
        ),
        ("base_sha".into(), Json::String(request.base_sha)),
        (
            "contract_revision".into(),
            Json::String(request.contract_revision),
        ),
        (
            "validator_revision".into(),
            Json::String(CANDIDATE_REVISION.into()),
        ),
        ("candidate_validated".into(), Json::Bool(true)),
        (
            "validated_tree_sha".into(),
            Json::String(result.validated_tree_sha),
        ),
        ("changes".into(), Json::Array(changes)),
    ]))
    .map_err(|_| "validator-output-invalid".to_owned())?;
    if output.len() > 60_000 {
        return Err("receipt-too-large".into());
    }
    Ok(output)
}

#[cfg(target_os = "linux")]
pub fn read_bounded(path: &Path) -> Result<String, &'static str> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "input-file-invalid")?;
    read_regular(file)
}
#[cfg(target_os = "linux")]
fn read_regular(file: File) -> Result<String, &'static str> {
    let metadata = file.metadata().map_err(|_| "input-file-invalid")?;
    if !metadata.is_file() {
        return Err("input-file-invalid");
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err("input-too-large");
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "input-file-invalid")?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("input-too-large");
    }
    String::from_utf8(bytes).map_err(|_| "input-file-invalid")
}
#[cfg(target_os = "linux")]
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "output-file-invalid")?;
    file.write_all(bytes).map_err(|_| "output-file-invalid")
}

#[cfg(not(target_os = "linux"))]
pub fn read_bounded(_path: &Path) -> Result<String, &'static str> {
    Err("unsupported-platform")
}
#[cfg(not(target_os = "linux"))]
pub fn write_private(_path: &Path, _bytes: &[u8]) -> Result<(), &'static str> {
    Err("unsupported-platform")
}

#[cfg(test)]
mod tests {
    use super::super::actions::AcceptedIssue;
    use super::super::json::sha256_hex;
    use super::*;

    fn journal(parameters: &str, time: &str, id: &str, policy: &str) -> JournalRecord {
        let parameters = Json::parse(parameters).unwrap();
        let canonical_request = jcs(&Json::Object(vec![
            ("schema_version".into(), Json::Number("1".into())),
            ("request_id".into(), Json::String(id.into())),
            ("operation".into(), Json::String("governance.ledger".into())),
            ("parameters".into(), parameters.clone()),
        ]))
        .unwrap();
        let request_digest = sha256_hex(canonical_request.as_bytes());
        let issue = AcceptedIssue {
            repository_id: 1,
            repository_full_name: "owner/repo".into(),
            issue_id: 2,
            issue_number: 3,
            author_id: 4,
            sender_id: 5,
            request_id: id.into(),
            operation: ActionOperation::GovernanceLedger,
            parameters,
            canonical_request,
            request_digest,
        };
        let mut journal = JournalRecord::new(issue, time, policy).unwrap();
        journal.claim_execution("execution-1").unwrap();
        journal
    }

    fn outer_parameters() -> String {
        format!(
            r#"{{"base_sha":"{CANDIDATE_REVISION}","operation":"run.record_evidence","parameters":{{}}}}"#
        )
    }

    #[test]
    fn startup_declaration_is_outer_bound_not_a_mutator_parameter() {
        let parameters = format!(
            r#"{{"agent_declaration":{{"schema_version":1}},"base_sha":"{CANDIDATE_REVISION}","operation":"task.start_run","parameters":{{}}}}"#
        );
        let record = journal(
            &parameters,
            "2026-10-20T00:00:00Z",
            "startup-test",
            CANDIDATE_REVISION,
        );
        let inner = inner_request(&record).unwrap();
        assert!(inner.get("agent_declaration").is_none());
        assert_eq!(
            inner.get("operation").and_then(Json::as_str),
            Some("task.start_run")
        );
        let wrong = parameters.replace("task.start_run", "run.record_evidence");
        assert!(
            inner_request(&journal(
                &wrong,
                "2026-10-20T00:00:00Z",
                "startup-test",
                CANDIDATE_REVISION
            ))
            .is_err()
        );
        let wrong = parameters.replace(
            "\"agent_declaration\":{\"schema_version\":1}",
            "\"agent_declaration\":true",
        );
        assert!(
            inner_request(&journal(
                &wrong,
                "2026-10-20T00:00:00Z",
                "startup-test",
                CANDIDATE_REVISION
            ))
            .is_err()
        );
    }

    #[test]
    fn expiry_preserves_fractions_and_checks_calendar_boundaries() {
        for (accepted, expected) in [
            ("2026-12-31T23:30:01.001200Z", "2027-01-01T00:30:01.001200Z"),
            ("2028-02-28T23:30:00Z", "2028-02-29T00:30:00Z"),
            ("2028-02-29T23:30:00Z", "2028-03-01T00:30:00Z"),
            ("1970-01-01T00:00:00Z", "1970-01-01T01:00:00Z"),
            ("9999-12-31T22:59:59Z", "9999-12-31T23:59:59Z"),
        ] {
            assert_eq!(expiry(accepted), Ok(expected.into()));
        }
        for accepted in [
            "9999-12-31T23:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-01-01T00:00:60Z",
            "2026-01-01T00:00:00.Z",
            "2026-01-01T00:00:00+00:00",
            "9223372036854775807-01-01T00:00:00Z",
            "2026-1-01T00:00:00Z",
        ] {
            assert!(expiry(accepted).is_err(), "{accepted}");
        }
    }

    #[test]
    fn frozen_mapping_and_artifact_are_deterministic_and_bound() {
        let record = journal(
            &outer_parameters(),
            "2026-10-11T00:00:00.123Z",
            "journal-test",
            CANDIDATE_REVISION,
        );
        let accepted = record
            .to_json()
            .unwrap()
            .replace("\"executing\"", "\"accepted\"")
            .replace("\"execution-1\"", "null");
        assert_eq!(
            derive_actions_candidate(
                "/missing".into(),
                &accepted,
                CANDIDATE_REVISION,
                CANDIDATE_REVISION,
                &TrustedLedgerContext::default()
            ),
            Err("journal-binding-invalid".into())
        );
        let inner = inner_request(&record).unwrap();
        let digest = super::super::parse_request_object(&inner)
            .unwrap()
            .request_digest;
        assert_ne!(digest, record.request_digest());
        assert_eq!(
            inner.get("created_at").unwrap().as_str(),
            Some(record.accepted_at())
        );
        assert_eq!(
            inner.get("expires_at").unwrap().as_str(),
            Some("2026-10-11T01:00:00.123Z")
        );
        let artifact = |record: &JournalRecord, accepted: &str, claim: &str| {
            bound_artifact(
                record,
                accepted,
                claim,
                inner_request(record).unwrap(),
                &TrustedLedgerContext::default(),
                Json::Object(vec![]),
            )
            .unwrap()
        };
        let original = artifact(&record, CANDIDATE_REVISION, CANDIDATE_REVISION);
        let mut reordered = Json::parse(&record.to_json().unwrap()).unwrap();
        if let Json::Object(fields) = &mut reordered {
            fields.reverse();
        }
        let reordered = format!(
            "{{{}}}",
            reordered
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| format!(
                    "{}:{}",
                    jcs(&Json::String(key.clone())).unwrap(),
                    jcs(value).unwrap()
                ))
                .collect::<Vec<_>>()
                .join(",")
        );
        let replay = JournalRecord::from_json(&reordered).unwrap();
        assert_eq!(
            original,
            artifact(&replay, CANDIDATE_REVISION, CANDIDATE_REVISION)
        );
        let other_revision = "a".repeat(40);
        for changed in [
            artifact(&record, &other_revision, CANDIDATE_REVISION),
            artifact(&record, CANDIDATE_REVISION, &other_revision),
            artifact(
                &journal(
                    &outer_parameters(),
                    "2026-10-11T00:00:00.124Z",
                    "journal-test",
                    CANDIDATE_REVISION,
                ),
                CANDIDATE_REVISION,
                CANDIDATE_REVISION,
            ),
            artifact(
                &journal(
                    &outer_parameters(),
                    record.accepted_at(),
                    "journal-other",
                    CANDIDATE_REVISION,
                ),
                CANDIDATE_REVISION,
                CANDIDATE_REVISION,
            ),
            artifact(
                &journal(
                    &outer_parameters(),
                    record.accepted_at(),
                    "journal-test",
                    &other_revision,
                ),
                CANDIDATE_REVISION,
                CANDIDATE_REVISION,
            ),
        ] {
            assert_ne!(original, changed);
        }
        let output = Json::parse(&original).unwrap();
        assert_eq!(output.as_object().unwrap().len(), 11);
        assert_eq!(
            jcs(output.get("inner_request").unwrap()).unwrap(),
            jcs(&inner).unwrap()
        );
        assert!(
            bound_artifact(
                &record,
                CANDIDATE_REVISION,
                CANDIDATE_REVISION,
                inner,
                &TrustedLedgerContext::parse(&format!(
                    r#"{{"remote_evidence":{{"large":"{}"}}}}"#,
                    "x".repeat(262_000)
                ))
                .unwrap(),
                Json::String("x".repeat(1000))
            )
            .is_err()
        );
    }

    #[test]
    fn journal_bridge_rejects_unclaimed_foreign_and_hostile_inputs() {
        let record = journal(
            &outer_parameters(),
            "2026-10-11T00:00:00Z",
            "journal-test",
            CANDIDATE_REVISION,
        );
        for parameters in [
            "{}".into(),
            outer_parameters().replace("run.record_evidence", "task.complete"),
            outer_parameters()
                .replace("run.record_evidence", "task.transition_status")
                .replace(
                    "\"parameters\":{}",
                    "\"parameters\":{\"target_status\":\"completed\"}",
                ),
            outer_parameters().replace(
                "\"parameters\":{}",
                "\"parameters\":{},\"remote_evidence\":{}",
            ),
            outer_parameters().replace(CANDIDATE_REVISION, "main"),
            outer_parameters().replace("\"parameters\":{}", "\"parameters\":null"),
        ] {
            let record = journal(
                &parameters,
                record.accepted_at(),
                "journal-test",
                CANDIDATE_REVISION,
            );
            assert!(inner_request(&record).is_err());
        }
        for state in ["accepted", "ambiguous", "succeeded", "rejected"] {
            let text = record
                .to_json()
                .unwrap()
                .replace("\"executing\"", &format!("\"{state}\""));
            assert!(
                derive_actions_candidate(
                    "/missing".into(),
                    &text,
                    CANDIDATE_REVISION,
                    CANDIDATE_REVISION,
                    &TrustedLedgerContext::default()
                )
                .is_err()
            );
        }
        for text in [
            "{}".into(),
            "x".repeat(65_537),
            record
                .to_json()
                .unwrap()
                .replace(record.request_digest(), &"a".repeat(64)),
            record.to_json().unwrap().replace("\"execution-1\"", "null"),
            record
                .to_json()
                .unwrap()
                .replace("governance.ledger", "github.ci.inspect"),
        ] {
            assert_eq!(
                derive_actions_candidate(
                    "/missing".into(),
                    &text,
                    CANDIDATE_REVISION,
                    CANDIDATE_REVISION,
                    &TrustedLedgerContext::default()
                ),
                Err("journal-invalid".into())
            );
        }
        assert_eq!(
            derive_actions_candidate(
                "/missing".into(),
                &record.to_json().unwrap(),
                "main",
                CANDIDATE_REVISION,
                &TrustedLedgerContext::default()
            ),
            Err("journal-revision-invalid".into())
        );
    }
    #[test]
    fn context_is_separate_and_bounded() {
        assert!(TrustedLedgerContext::parse("{}").is_ok());
        for text in [
            r#"{"closure_evidence":{}}"#,
            r#"{"remote_preflight":null}"#,
            r#"{"remote_evidence":{},"remote_evidence":{}}"#,
            r#"{"remote_evidence":{"n":9007199254740992}}"#,
        ] {
            assert!(TrustedLedgerContext::parse(text).is_err());
        }
    }
    #[test]
    fn compatibility_pins_are_unchanged() {
        assert_eq!(
            super::super::validator::TRUSTED_CONTRACT_REVISION,
            "3bbbb3463573893571f45ee92625a54414f8df13"
        );
    }

    fn request() -> String {
        format!(
            r#"{{"schema_version":1,"request_id":"candidate-test","created_at":"2026-09-30T22:00:00Z","expires_at":"2026-09-30T23:00:00Z","base_sha":"{CANDIDATE_REVISION}","operation":"task.complete","parameters":{{}},"contract_revision":"{CANDIDATE_REVISION}"}}"#
        )
    }

    #[test]
    fn ordinary_request_order_does_not_change_identity() {
        let first = Json::parse(&request()).unwrap();
        let mut second = first.clone();
        if let Json::Object(fields) = &mut second {
            fields.reverse();
        }
        assert_eq!(
            super::super::parse_request_object(&first).unwrap(),
            super::super::parse_request_object(&second).unwrap()
        );
    }

    #[test]
    fn closure_operations_are_rejected_before_tooling() {
        for operation in ["task.complete", "task.complete_verified", "unknown"] {
            let text = request().replace("task.complete", operation);
            assert_eq!(
                derive_candidate(
                    "/missing".into(),
                    &text,
                    "invalid",
                    &TrustedLedgerContext::default()
                ),
                Err("operation-not-allowed".into())
            );
        }
        let text = request()
            .replace("task.complete", "task.transition_status")
            .replace(
                "\"parameters\":{}",
                "\"parameters\":{\"target_status\":\"completed\"}",
            );
        assert_eq!(
            derive_candidate(
                "/missing".into(),
                &text,
                "invalid",
                &TrustedLedgerContext::default()
            ),
            Err("operation-not-allowed".into())
        );
    }

    #[test]
    fn nesting_and_numbers_fail_closed() {
        let text = format!("{}0{}", "[".repeat(100), "]".repeat(100));
        assert!(Json::parse(&text).is_err());
        assert!(
            super::super::parse_request_object(
                &Json::parse(&request().replace(
                    "\"parameters\":{}",
                    "\"parameters\":{\"number\":9007199254740992}"
                ))
                .unwrap()
            )
            .is_err()
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn regular_file_bounds_and_private_creation() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory =
            std::env::temp_dir().join(format!("zach-candidate-file-test-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let file = directory.join("input");
        write_private(&file, b"{}").unwrap();
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(read_bounded(&file), Ok("{}".into()));
        assert!(write_private(&file, b"overwrite").is_err());
        let link = directory.join("link");
        symlink(&file, &link).unwrap();
        assert!(read_bounded(&link).is_err());
        assert!(read_bounded(&directory).is_err());
        std::fs::write(&file, vec![b'x'; MAX_INPUT_BYTES as usize + 1]).unwrap();
        assert_eq!(read_bounded(&file), Err("input-too-large"));
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
