//! Preparatory candidate data; callers establish trusted context authority.
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
    use super::*;
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
