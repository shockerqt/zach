pub mod actions;
mod json;
mod publisher;
mod store;
mod validator;

use json::{Json, jcs, object_get, object_string, object_u64, sha256_hex, verify_github_signature};
use publisher::{
    GithubAppReceiptPublisher, GithubCredential, ReceiptPublisher, TrustedReceiptAuth,
};
use std::env;
use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use store::{Claim, ClaimInput, PublicationClaim, SqliteStore};
use validator::{
    ChangeOperation, LedgerChange, LedgerRequest, LedgerValidator, MAX_RECEIPT_UTF8_BYTES,
    PinnedGovernanceValidator, enforce_result_limits,
};

pub const PUBLIC_WEBHOOK_OPERATIONS: &[&str] = &["governance.validate-ledger"];
const REQUEST_MARKER: &str = "<!-- governance-ledger-request:v1 -->";
const RECEIPT_MARKER: &str = "<!-- governance-ledger-receipt:v1 -->";
const GOVERNANCE_REPOSITORY: &str = "shockerqt/workspace-governance";
const EXECUTION_LEASE_SECONDS: i64 = 300;
const PUBLICATION_LEASE_SECONDS: i64 = 120;
const MAX_HTTP_BODY_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookHeaders {
    pub signature_256: String,
    pub delivery_id: String,
    pub event: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookOutcome {
    pub status_code: u16,
    pub code: String,
    pub terminal_receipt: Option<String>,
    pub replayed: bool,
}

impl WebhookOutcome {
    fn simple(status_code: u16, code: impl Into<String>) -> Self {
        Self {
            status_code,
            code: code.into(),
            terminal_receipt: None,
            replayed: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError(pub String);

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ServiceError {}

pub trait Clock: Send + Sync {
    fn now_epoch(&self) -> i64;
}

#[derive(Debug, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_epoch(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| i64::try_from(value.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }
}

pub(crate) struct WebhookService<V, P, C> {
    webhook_secret: Vec<u8>,
    repository: String,
    state_db: PathBuf,
    instance_id: String,
    validator: V,
    publisher: P,
    clock: C,
    receipt_auth: TrustedReceiptAuth,
}

pub(crate) struct ServiceConfig<V, P, C> {
    pub webhook_secret: Vec<u8>,
    pub repository: String,
    pub state_db: PathBuf,
    pub instance_id: String,
    pub validator: V,
    pub publisher: P,
    pub clock: C,
    pub receipt_auth: TrustedReceiptAuth,
}

impl<V, P, C> WebhookService<V, P, C>
where
    V: LedgerValidator,
    P: ReceiptPublisher,
    C: Clock,
{
    pub fn new(config: ServiceConfig<V, P, C>) -> Result<Self, ServiceError> {
        if config.webhook_secret.is_empty() {
            return Err(ServiceError("webhook secret must not be empty".into()));
        }
        if config.repository != GOVERNANCE_REPOSITORY {
            return Err(ServiceError(
                "validator is restricted to the canonical Governance repository".into(),
            ));
        }
        if config.instance_id.trim().is_empty() {
            return Err(ServiceError("instance identity must not be empty".into()));
        }
        Ok(Self {
            webhook_secret: config.webhook_secret,
            repository: config.repository,
            state_db: config.state_db,
            instance_id: config.instance_id,
            validator: config.validator,
            publisher: config.publisher,
            clock: config.clock,
            receipt_auth: config.receipt_auth,
        })
    }

    pub fn handle(&self, headers: &WebhookHeaders, raw_body: &[u8]) -> WebhookOutcome {
        if !verify_github_signature(&self.webhook_secret, raw_body, headers.signature_256.trim()) {
            return WebhookOutcome::simple(401, "signature-invalid");
        }
        if headers.event != "issues" {
            return WebhookOutcome::simple(202, "event-ignored");
        }
        if !valid_delivery_id(&headers.delivery_id) {
            return WebhookOutcome::simple(400, "delivery-id-invalid");
        }
        let body = match std::str::from_utf8(raw_body) {
            Ok(value) => value,
            Err(_) => return WebhookOutcome::simple(400, "webhook-json-invalid"),
        };
        let event = match parse_issue_event(body, &self.repository) {
            Ok(value) => value,
            Err(code) => return WebhookOutcome::simple(400, code),
        };
        let accepted = match parse_canonical_request(&event.issue_body) {
            Ok(value) => value,
            Err(code) => return WebhookOutcome::simple(400, code),
        };
        let now_epoch = self.clock.now_epoch();
        let accepted_at = epoch_to_rfc3339(now_epoch);
        let mut store = match SqliteStore::open(&self.state_db) {
            Ok(value) => value,
            Err(_) => return WebhookOutcome::simple(503, "durable-store-unavailable"),
        };
        let claim = match store.claim(&ClaimInput {
            request_id: &accepted.request.request_id,
            request_digest: &accepted.request.request_digest,
            issue_number: match i64::try_from(event.issue_number) {
                Ok(value) => value,
                Err(_) => return WebhookOutcome::simple(400, "issue-number-invalid"),
            },
            canonical_request: &accepted.request.canonical_json,
            canonical_identity: &accepted.request.request_digest,
            delivery_id: &headers.delivery_id,
            instance_id: &self.instance_id,
            now_epoch,
            lease_seconds: EXECUTION_LEASE_SECONDS,
        }) {
            Ok(value) => value,
            Err(_) => return WebhookOutcome::simple(503, "durable-store-unavailable"),
        };

        match claim {
            Claim::Execute => {
                let terminal = match validate_time_window(&accepted.request, now_epoch) {
                    Ok(()) => match self.validator.validate(&accepted.request, &accepted_at) {
                        Ok(result) => build_success_receipt(
                            &accepted.request,
                            self.validator.validator_revision(),
                            result.changes,
                            &result.validated_tree_sha,
                        ),
                        Err(error) => build_rejection_receipt(
                            &accepted.request,
                            self.validator.validator_revision(),
                            &error.code,
                        ),
                    },
                    Err(code) => build_rejection_receipt(
                        &accepted.request,
                        self.validator.validator_revision(),
                        code,
                    ),
                };
                self.finish_and_publish(
                    &mut store,
                    &accepted.request,
                    event.issue_number,
                    terminal,
                    false,
                )
            }
            Claim::AmbiguousRecovery => {
                let terminal = build_rejection_receipt(
                    &accepted.request,
                    self.validator.validator_revision(),
                    "ambiguous-recovery",
                );
                self.finish_and_publish(
                    &mut store,
                    &accepted.request,
                    event.issue_number,
                    terminal,
                    false,
                )
            }
            Claim::Replay {
                terminal_receipt,
                terminal_result_id,
            } => self.publish_existing(
                &mut store,
                &accepted.request,
                event.issue_number,
                terminal_receipt,
                terminal_result_id,
            ),
            Claim::InFlight => WebhookOutcome::simple(202, "transaction-in-flight"),
            Claim::RequestConflict => WebhookOutcome::simple(409, "request-id-conflict"),
            Claim::IssueRequestFrozen => WebhookOutcome::simple(409, "issue-request-frozen"),
            Claim::DeliveryConflict => WebhookOutcome::simple(409, "delivery-id-conflict"),
        }
    }

    fn finish_and_publish(
        &self,
        store: &mut SqliteStore,
        request: &LedgerRequest,
        issue_number: u64,
        terminal: TerminalReceipt,
        replayed: bool,
    ) -> WebhookOutcome {
        if store
            .complete(
                &request.request_id,
                &request.request_digest,
                &self.instance_id,
                &terminal.body,
                &terminal.result_id,
            )
            .is_err()
        {
            return WebhookOutcome::simple(503, "durable-terminal-write-failed");
        }
        self.publish_terminal(
            store,
            request,
            issue_number,
            terminal.body,
            terminal.result_id,
            replayed,
        )
    }

    fn publish_existing(
        &self,
        store: &mut SqliteStore,
        request: &LedgerRequest,
        issue_number: u64,
        terminal_receipt: String,
        terminal_result_id: String,
    ) -> WebhookOutcome {
        self.publish_terminal(
            store,
            request,
            issue_number,
            terminal_receipt,
            terminal_result_id,
            true,
        )
    }

    fn publish_terminal(
        &self,
        store: &mut SqliteStore,
        request: &LedgerRequest,
        issue_number: u64,
        terminal_receipt: String,
        _terminal_result_id: String,
        replayed: bool,
    ) -> WebhookOutcome {
        // Publication gets its own fresh clock read. Validation duration must not consume the
        // publication lease before the sole POST permission is even claimed.
        let publication_now = self.clock.now_epoch();
        let claim = match store.claim_publication(
            &request.request_id,
            &request.request_digest,
            &self.instance_id,
            publication_now,
            PUBLICATION_LEASE_SECONDS,
        ) {
            Ok(value) => value,
            Err(_) => return WebhookOutcome::simple(503, "receipt-outbox-unavailable"),
        };
        match claim {
            PublicationClaim::Sent(_) => WebhookOutcome {
                status_code: 200,
                code: "terminal-replayed".into(),
                terminal_receipt: Some(terminal_receipt),
                replayed: true,
            },
            PublicationClaim::InFlight => WebhookOutcome {
                status_code: 202,
                code: "receipt-publication-in-flight".into(),
                terminal_receipt: Some(terminal_receipt),
                replayed,
            },
            PublicationClaim::Reconcile => {
                let comment_id = match self.publisher.reconcile_terminal(
                    &self.receipt_auth,
                    issue_number,
                    &terminal_receipt,
                ) {
                    Ok(Some(value)) => value,
                    Ok(None) | Err(_) => {
                        return WebhookOutcome {
                            status_code: 503,
                            code: "receipt-publication-ambiguous".into(),
                            terminal_receipt: Some(terminal_receipt),
                            replayed: true,
                        };
                    }
                };
                if store
                    .mark_reconciled(&request.request_id, &request.request_digest, comment_id)
                    .is_err()
                {
                    return WebhookOutcome {
                        status_code: 503,
                        code: "receipt-publication-record-failed".into(),
                        terminal_receipt: Some(terminal_receipt),
                        replayed: true,
                    };
                }
                WebhookOutcome {
                    status_code: 200,
                    code: "terminal-replayed".into(),
                    terminal_receipt: Some(terminal_receipt),
                    replayed: true,
                }
            }
            PublicationClaim::Publish => {
                let comment_id = match self.publisher.publish_terminal(
                    &self.receipt_auth,
                    issue_number,
                    &terminal_receipt,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        return WebhookOutcome {
                            status_code: 503,
                            code: "receipt-publication-ambiguous".into(),
                            terminal_receipt: Some(terminal_receipt),
                            replayed,
                        };
                    }
                };
                if store
                    .mark_published(
                        &request.request_id,
                        &request.request_digest,
                        &self.instance_id,
                        comment_id,
                    )
                    .is_err()
                {
                    return WebhookOutcome {
                        status_code: 503,
                        code: "receipt-publication-record-failed".into(),
                        terminal_receipt: Some(terminal_receipt),
                        replayed,
                    };
                }
                WebhookOutcome {
                    status_code: 200,
                    code: if replayed {
                        "terminal-replayed".into()
                    } else {
                        "terminal-published".into()
                    },
                    terminal_receipt: Some(terminal_receipt),
                    replayed,
                }
            }
        }
    }
}

#[derive(Debug)]
struct IssueEvent {
    issue_number: u64,
    issue_body: String,
}

fn parse_issue_event(body: &str, trusted_repository: &str) -> Result<IssueEvent, &'static str> {
    let json = Json::parse(body).map_err(|_| "webhook-json-invalid")?;
    let object = json.as_object().ok_or("webhook-json-invalid")?;
    let action = object_string(object, "action").ok_or("issue-action-invalid")?;
    if !matches!(action, "opened" | "edited") {
        return Err("issue-action-invalid");
    }
    let repository = object_get(object, "repository")
        .and_then(Json::as_object)
        .ok_or("repository-invalid")?;
    if object_string(repository, "full_name") != Some(trusted_repository) {
        return Err("repository-invalid");
    }
    let issue = object_get(object, "issue")
        .and_then(Json::as_object)
        .ok_or("issue-invalid")?;
    let issue_number = object_u64(issue, "number").ok_or("issue-number-invalid")?;
    let issue_body = object_string(issue, "body")
        .ok_or("issue-body-invalid")?
        .to_owned();
    Ok(IssueEvent {
        issue_number,
        issue_body,
    })
}

struct AcceptedRequest {
    request: LedgerRequest,
}

fn parse_canonical_request(body: &str) -> Result<AcceptedRequest, &'static str> {
    let prefix = format!("{REQUEST_MARKER}\n```json\n");
    let payload = body
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix("\n```\n"))
        .ok_or("request-envelope-invalid")?;
    let envelope = Json::parse(payload).map_err(|_| "request-envelope-invalid")?;
    if jcs(&envelope).map_err(|_| "request-envelope-invalid")? != payload {
        return Err("request-envelope-not-canonical");
    }
    let envelope_object = envelope.as_object().ok_or("request-envelope-invalid")?;
    require_exact_keys(
        envelope_object,
        &["kind", "schema_version", "request_digest", "request"],
    )?;
    if object_string(envelope_object, "kind") != Some("governance-ledger-request")
        || object_u64(envelope_object, "schema_version") != Some(1)
    {
        return Err("request-envelope-invalid");
    }
    let declared_digest =
        object_string(envelope_object, "request_digest").ok_or("request-digest-invalid")?;
    if !hex64(declared_digest) {
        return Err("request-digest-invalid");
    }
    let request = object_get(envelope_object, "request").ok_or("request-invalid")?;
    let request_object = request.as_object().ok_or("request-invalid")?;
    require_exact_keys(
        request_object,
        &[
            "schema_version",
            "request_id",
            "created_at",
            "expires_at",
            "base_sha",
            "operation",
            "parameters",
            "contract_revision",
        ],
    )?;
    if object_u64(request_object, "schema_version") != Some(1) {
        return Err("request-invalid");
    }
    let request_id = object_string(request_object, "request_id").ok_or("request-id-invalid")?;
    if !valid_request_id(request_id) {
        return Err("request-id-invalid");
    }
    let created_at = object_string(request_object, "created_at").ok_or("request-time-invalid")?;
    let expires_at = object_string(request_object, "expires_at").ok_or("request-time-invalid")?;
    let base_sha = object_string(request_object, "base_sha").ok_or("base-sha-invalid")?;
    let contract_revision =
        object_string(request_object, "contract_revision").ok_or("contract-revision-invalid")?;
    if !sha40(base_sha) || !sha40(contract_revision) {
        return Err("request-invalid");
    }
    let operation = object_string(request_object, "operation").ok_or("operation-invalid")?;
    if operation.is_empty() {
        return Err("operation-invalid");
    }
    let parameters = object_get(request_object, "parameters")
        .filter(|value| value.as_object().is_some())
        .ok_or("parameters-invalid")?
        .clone();
    let canonical_json = jcs(request).map_err(|_| "request-invalid")?;
    let digest = sha256_hex(canonical_json.as_bytes());
    if digest != declared_digest {
        return Err("request-digest-mismatch");
    }
    Ok(AcceptedRequest {
        request: LedgerRequest {
            request_id: request_id.to_owned(),
            created_at: created_at.to_owned(),
            expires_at: expires_at.to_owned(),
            base_sha: base_sha.to_owned(),
            operation: operation.to_owned(),
            parameters,
            contract_revision: contract_revision.to_owned(),
            canonical_json,
            request_digest: digest,
        },
    })
}

fn require_exact_keys(object: &[(String, Json)], expected: &[&str]) -> Result<(), &'static str> {
    if object.len() != expected.len()
        || expected.iter().any(|key| object_get(object, key).is_none())
    {
        return Err("request-invalid");
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct TerminalReceipt {
    body: String,
    result_id: String,
}

fn build_success_receipt(
    request: &LedgerRequest,
    validator_revision: &str,
    mut changes: Vec<LedgerChange>,
    validated_tree_sha: &str,
) -> TerminalReceipt {
    if validator_revision.len() != 40 || !sha40(validator_revision) || !sha40(validated_tree_sha) {
        return build_rejection_receipt(request, validator_revision, "validator-output-invalid");
    }
    changes.sort_by(|left, right| left.path.cmp(&right.path));
    if changes.windows(2).any(|pair| pair[0].path == pair[1].path)
        || enforce_result_limits(&changes).is_err()
    {
        return build_rejection_receipt(request, validator_revision, "result-too-large");
    }
    let changes_json = changes.iter().map(change_json).collect::<Vec<_>>();
    let core = Json::Object(vec![
        (
            "kind".into(),
            Json::String("governance-ledger-receipt".into()),
        ),
        ("schema_version".into(), Json::Number("1".into())),
        ("status".into(), Json::String("succeeded".into())),
        (
            "request_id".into(),
            Json::String(request.request_id.clone()),
        ),
        (
            "request_digest".into(),
            Json::String(request.request_digest.clone()),
        ),
        ("base_sha".into(), Json::String(request.base_sha.clone())),
        (
            "contract_revision".into(),
            Json::String(request.contract_revision.clone()),
        ),
        (
            "validator_revision".into(),
            Json::String(validator_revision.to_owned()),
        ),
        (
            "validated_tree_sha".into(),
            Json::String(validated_tree_sha.to_owned()),
        ),
        ("changes".into(), Json::Array(changes_json)),
    ]);
    match finalize_receipt(core) {
        Ok(value) if value.body.len() <= MAX_RECEIPT_UTF8_BYTES => value,
        _ => build_rejection_receipt(request, validator_revision, "receipt-too-large"),
    }
}

fn build_rejection_receipt(
    request: &LedgerRequest,
    validator_revision: &str,
    reason: &str,
) -> TerminalReceipt {
    let core = Json::Object(vec![
        (
            "kind".into(),
            Json::String("governance-ledger-receipt".into()),
        ),
        ("schema_version".into(), Json::Number("1".into())),
        ("status".into(), Json::String("rejected".into())),
        (
            "request_id".into(),
            Json::String(request.request_id.clone()),
        ),
        (
            "request_digest".into(),
            Json::String(request.request_digest.clone()),
        ),
        ("base_sha".into(), Json::String(request.base_sha.clone())),
        (
            "contract_revision".into(),
            Json::String(request.contract_revision.clone()),
        ),
        (
            "validator_revision".into(),
            Json::String(validator_revision.to_owned()),
        ),
        ("reason".into(), Json::String(reason.to_owned())),
        ("fallback".into(), Json::String("strict-path".into())),
    ]);
    finalize_receipt(core).unwrap_or_else(|_| TerminalReceipt {
        body: format!(
            "{RECEIPT_MARKER}\n```json\n{{\"kind\":\"governance-ledger-receipt\",\"schema_version\":1,\"status\":\"rejected\",\"reason\":\"internal-receipt-error\"}}\n```\n"
        ),
        result_id: sha256_hex(b"internal-receipt-error"),
    })
}

fn finalize_receipt(mut core: Json) -> Result<TerminalReceipt, ServiceError> {
    let canonical_core = jcs(&core).map_err(|error| ServiceError(error.to_string()))?;
    let result_id = sha256_hex(canonical_core.as_bytes());
    let object = match &mut core {
        Json::Object(value) => value,
        _ => return Err(ServiceError("receipt core is not an object".into())),
    };
    object.push(("terminal_result_id".into(), Json::String(result_id.clone())));
    let payload = jcs(&core).map_err(|error| ServiceError(error.to_string()))?;
    Ok(TerminalReceipt {
        body: format!("{RECEIPT_MARKER}\n```json\n{payload}\n```\n"),
        result_id,
    })
}

fn change_json(change: &LedgerChange) -> Json {
    Json::Object(vec![
        ("path".into(), Json::String(change.path.clone())),
        (
            "operation".into(),
            Json::String(match change.operation {
                ChangeOperation::Upsert => "upsert".into(),
                ChangeOperation::Delete => "delete".into(),
            }),
        ),
        (
            "content".into(),
            change
                .content
                .clone()
                .map(Json::String)
                .unwrap_or(Json::Null),
        ),
        (
            "blob_sha".into(),
            change
                .blob_sha
                .clone()
                .map(Json::String)
                .unwrap_or(Json::Null),
        ),
    ])
}

fn validate_time_window(request: &LedgerRequest, accepted_epoch: i64) -> Result<(), &'static str> {
    let created = parse_utc_epoch(&request.created_at).ok_or("request-time-invalid")?;
    let expires = parse_utc_epoch(&request.expires_at).ok_or("request-time-invalid")?;
    if expires <= created || accepted_epoch < created || accepted_epoch > expires {
        return Err("request-time-invalid");
    }
    Ok(())
}

fn parse_utc_epoch(value: &str) -> Option<i64> {
    let raw = value.strip_suffix('Z')?;
    let (date, time) = raw.split_once('T')?;
    let mut date_parts = date.split('-');
    let year = date_parts.next()?.parse::<i64>().ok()?;
    let month = date_parts.next()?.parse::<u32>().ok()?;
    let day = date_parts.next()?.parse::<u32>().ok()?;
    if date_parts.next().is_some() || year < 1970 || !(1..=12).contains(&month) {
        return None;
    }
    let mut time_parts = time.split(':');
    let hour = time_parts.next()?.parse::<u32>().ok()?;
    let minute = time_parts.next()?.parse::<u32>().ok()?;
    let second_text = time_parts.next()?;
    if time_parts.next().is_some() || hour > 23 || minute > 59 {
        return None;
    }
    let second = second_text
        .split_once('.')
        .map(|(whole, fraction)| {
            (!fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit()))
                .then_some(whole)
        })
        .unwrap_or(Some(second_text))?
        .parse::<u32>()
        .ok()?;
    if second > 59 || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    let days =
        days_before_year(year) + i64::from(days_before_month(year, month)) + i64::from(day - 1)
            - days_before_year(1970);
    Some(days * 86_400 + i64::from(hour * 3600 + minute * 60 + second))
}

fn days_before_year(year: i64) -> i64 {
    let previous = year - 1;
    previous * 365 + previous / 4 - previous / 100 + previous / 400
}

fn days_before_month(year: i64, month: u32) -> u32 {
    let common = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    common[(month - 1) as usize] + u32::from(month > 2 && leap_year(year))
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn epoch_to_rfc3339(epoch: i64) -> String {
    let epoch = epoch.max(0);
    let days = epoch / 86_400;
    let seconds = epoch % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3600;
    let minute = (seconds % 3600) / 60;
    let second = seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

fn valid_request_id(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}

fn valid_delivery_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn sha40(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub fn serve_from_env(bind_addr: &str) -> Result<(), ServiceError> {
    let secret = env::var("ZACH_WEBHOOK_SECRET")
        .map_err(|_| ServiceError("ZACH_WEBHOOK_SECRET is required".into()))?;
    let state_db = env::var("ZACH_STATE_DB")
        .map(PathBuf::from)
        .map_err(|_| ServiceError("ZACH_STATE_DB is required".into()))?;
    let mirror = env::var("ZACH_GOVERNANCE_MIRROR")
        .map(PathBuf::from)
        .map_err(|_| ServiceError("ZACH_GOVERNANCE_MIRROR is required".into()))?;
    let token = env::var("ZACH_GITHUB_APP_INSTALLATION_TOKEN")
        .map_err(|_| ServiceError("ZACH_GITHUB_APP_INSTALLATION_TOKEN is required".into()))?;
    let installation_id = env::var("ZACH_GITHUB_APP_INSTALLATION_ID")
        .map_err(|_| ServiceError("ZACH_GITHUB_APP_INSTALLATION_ID is required".into()))?
        .parse::<u64>()
        .map_err(|_| ServiceError("ZACH_GITHUB_APP_INSTALLATION_ID is invalid".into()))?;
    let app_id = env::var("ZACH_GITHUB_APP_ID")
        .map_err(|_| ServiceError("ZACH_GITHUB_APP_ID is required".into()))?
        .parse::<u64>()
        .map_err(|_| ServiceError("ZACH_GITHUB_APP_ID is invalid".into()))?;
    let auth = TrustedReceiptAuth::try_from_credential(GithubCredential::AppInstallation {
        token,
        installation_id,
        app_id,
    })
    .map_err(|error| ServiceError(error.to_string()))?;
    let validator =
        PinnedGovernanceValidator::new(mirror).map_err(|error| ServiceError(error.to_string()))?;
    let publisher = GithubAppReceiptPublisher::new(GOVERNANCE_REPOSITORY.into())
        .map_err(|error| ServiceError(error.to_string()))?;
    let clock = SystemClock;
    let instance_id = format!("zach-{}-{}", std::process::id(), clock.now_epoch());
    let service = Arc::new(WebhookService::new(ServiceConfig {
        webhook_secret: secret.into_bytes(),
        repository: GOVERNANCE_REPOSITORY.into(),
        state_db,
        instance_id,
        validator,
        publisher,
        clock,
        receipt_auth: auth,
    })?);
    let listener = TcpListener::bind(bind_addr)
        .map_err(|error| ServiceError(format!("could not bind webhook listener: {error}")))?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let service = Arc::clone(&service);
                std::thread::spawn(move || {
                    let _ = handle_http_connection(stream, &service);
                });
            }
            Err(error) => return Err(ServiceError(format!("webhook listener failed: {error}"))),
        }
    }
    Ok(())
}

fn handle_http_connection<V, P, C>(
    mut stream: TcpStream,
    service: &WebhookService<V, P, C>,
) -> Result<(), ServiceError>
where
    V: LedgerValidator,
    P: ReceiptPublisher,
    C: Clock,
{
    let (headers, body) = read_http_request(&mut stream)?;
    let outcome = service.handle(&headers, &body);
    let response_body = format!("{{\"code\":\"{}\"}}\n", outcome.code);
    let reason = match outcome.status_code {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        409 => "Conflict",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        outcome.status_code,
        response_body.len(),
        response_body
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|error| ServiceError(format!("could not write HTTP response: {error}")))
}

fn read_http_request(stream: &mut TcpStream) -> Result<(WebhookHeaders, Vec<u8>), ServiceError> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let count = stream
            .read(&mut buffer)
            .map_err(|error| ServiceError(format!("could not read HTTP request: {error}")))?;
        if count == 0 {
            return Err(ServiceError("HTTP request ended before headers".into()));
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > 65_536 {
            return Err(ServiceError("HTTP headers too large".into()));
        }
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| ServiceError("HTTP headers are not UTF-8".into()))?;
    let mut lines = header_text.split("\r\n");
    if lines.next() != Some("POST /github/webhook HTTP/1.1") {
        return Err(ServiceError("unsupported HTTP request target".into()));
    }
    let mut signature = None;
    let mut delivery = None;
    let mut event = None;
    let mut length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.to_ascii_lowercase().as_str() {
            "x-hub-signature-256" => signature = Some(value.trim().to_owned()),
            "x-github-delivery" => delivery = Some(value.trim().to_owned()),
            "x-github-event" => event = Some(value.trim().to_owned()),
            "content-length" => {
                length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .map_err(|_| ServiceError("invalid Content-Length".into()))?,
                )
            }
            _ => {}
        }
    }
    let length = length.ok_or_else(|| ServiceError("Content-Length is required".into()))?;
    if length > MAX_HTTP_BODY_BYTES {
        return Err(ServiceError(
            "webhook body exceeds configured hard limit".into(),
        ));
    }
    while bytes.len() - header_end < length {
        let count = stream
            .read(&mut buffer)
            .map_err(|error| ServiceError(format!("could not read HTTP body: {error}")))?;
        if count == 0 {
            return Err(ServiceError("HTTP body ended early".into()));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let body = bytes[header_end..header_end + length].to_vec();
    Ok((
        WebhookHeaders {
            signature_256: signature
                .ok_or_else(|| ServiceError("missing signature header".into()))?,
            delivery_id: delivery.ok_or_else(|| ServiceError("missing delivery header".into()))?,
            event: event.ok_or_else(|| ServiceError("missing event header".into()))?,
        },
        body,
    ))
}

#[cfg(test)]
mod tests {
    use super::json::hmac_sha256_hex;
    use super::validator::TRUSTED_CONTRACT_REVISION;
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    static NEXT_DB: AtomicU64 = AtomicU64::new(1);
    const NOW: i64 = 1_788_000_000;

    #[derive(Clone)]
    struct FixedClock(i64);
    impl Clock for FixedClock {
        fn now_epoch(&self) -> i64 {
            self.0
        }
    }

    #[derive(Clone)]
    struct SequenceClock {
        values: Arc<Mutex<Vec<i64>>>,
    }

    impl SequenceClock {
        fn new(values: Vec<i64>) -> Self {
            Self {
                values: Arc::new(Mutex::new(values)),
            }
        }
    }

    impl Clock for SequenceClock {
        fn now_epoch(&self) -> i64 {
            self.values.lock().unwrap().remove(0)
        }
    }

    #[derive(Clone)]
    struct FakeValidator {
        calls: Arc<AtomicUsize>,
        result: Arc<Mutex<Result<validator::ValidatedLedgerResult, validator::ValidationError>>>,
        sleep_ms: u64,
    }

    impl LedgerValidator for FakeValidator {
        fn validator_revision(&self) -> &str {
            validator::TRUSTED_VALIDATOR_REVISION
        }

        fn validate(
            &self,
            request: &LedgerRequest,
            _accepted_at: &str,
        ) -> Result<validator::ValidatedLedgerResult, validator::ValidationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.sleep_ms != 0 {
                thread::sleep(Duration::from_millis(self.sleep_ms));
            }
            if !matches!(
                request.operation.as_str(),
                "task.create"
                    | "run.create"
                    | "run.record_evidence"
                    | "task.append_run"
                    | "task.transition_status"
                    | "task.complete"
            ) {
                return Err(validator::ValidationError::new(
                    "unsupported-operation",
                    "strict path required",
                ));
            }
            self.result.lock().unwrap().clone()
        }
    }

    #[derive(Clone, Default)]
    struct FakePublisher {
        post_calls: Arc<AtomicUsize>,
        reconcile_calls: Arc<AtomicUsize>,
        remote: Arc<Mutex<Vec<(String, i64)>>>,
        fail_after_accept: bool,
        post_sleep_ms: u64,
    }

    impl ReceiptPublisher for FakePublisher {
        fn publish_terminal(
            &self,
            _auth: &TrustedReceiptAuth,
            _issue_number: u64,
            receipt: &str,
        ) -> Result<i64, publisher::PublicationError> {
            let call = self.post_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.post_sleep_ms != 0 {
                thread::sleep(Duration::from_millis(self.post_sleep_ms));
            }
            let id = i64::try_from(1000 + call).unwrap();
            self.remote.lock().unwrap().push((receipt.to_owned(), id));
            if self.fail_after_accept {
                Err(publisher::PublicationError(
                    "simulated crash/transport ambiguity after remote acceptance".into(),
                ))
            } else {
                Ok(id)
            }
        }

        fn reconcile_terminal(
            &self,
            _auth: &TrustedReceiptAuth,
            _issue_number: u64,
            receipt: &str,
        ) -> Result<Option<i64>, publisher::PublicationError> {
            self.reconcile_calls.fetch_add(1, Ordering::SeqCst);
            let matches = self
                .remote
                .lock()
                .unwrap()
                .iter()
                .filter(|(body, _)| body == receipt)
                .map(|(_, id)| *id)
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [] => Ok(None),
                [id] => Ok(Some(*id)),
                _ => Err(publisher::PublicationError(
                    "multiple trusted terminal comments match one transaction".into(),
                )),
            }
        }
    }

    struct TestDb(PathBuf);
    impl TestDb {
        fn new() -> Self {
            let id = NEXT_DB.fetch_add(1, Ordering::Relaxed);
            Self(env::temp_dir().join(format!(
                "zach-webhook-test-{}-{id}.sqlite3",
                std::process::id()
            )))
        }
    }
    impl Drop for TestDb {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_file(self.0.with_extension("sqlite3-wal"));
            let _ = fs::remove_file(self.0.with_extension("sqlite3-shm"));
        }
    }

    fn auth() -> TrustedReceiptAuth {
        TrustedReceiptAuth::try_from_credential(GithubCredential::AppInstallation {
            token: "ghs_12345678901234567890".into(),
            installation_id: 7,
            app_id: 9,
        })
        .unwrap()
    }

    fn one_change(content: &str) -> LedgerChange {
        LedgerChange {
            path: "tasks/ZACH-001-build-workspace-control-agent.md".into(),
            operation: ChangeOperation::Upsert,
            content: Some(content.into()),
            blob_sha: Some("1111111111111111111111111111111111111111".into()),
        }
    }

    fn validator_result(changes: Vec<LedgerChange>) -> validator::ValidatedLedgerResult {
        validator::ValidatedLedgerResult {
            changes,
            validated_tree_sha: "2222222222222222222222222222222222222222".into(),
        }
    }

    fn service<C: Clock>(
        db: &Path,
        validator: FakeValidator,
        publisher: FakePublisher,
        clock: C,
        instance: &str,
    ) -> WebhookService<FakeValidator, FakePublisher, C> {
        WebhookService::new(ServiceConfig {
            webhook_secret: b"secret".to_vec(),
            repository: GOVERNANCE_REPOSITORY.into(),
            state_db: db.to_path_buf(),
            instance_id: instance.into(),
            validator,
            publisher,
            clock,
            receipt_auth: auth(),
        })
        .unwrap()
    }

    fn canonical_request(request_id: &str, operation: &str, parameters: Json) -> Json {
        Json::Object(vec![
            ("schema_version".into(), Json::Number("1".into())),
            ("request_id".into(), Json::String(request_id.into())),
            (
                "created_at".into(),
                Json::String("2026-01-01T00:00:00Z".into()),
            ),
            (
                "expires_at".into(),
                Json::String("2027-01-01T00:00:00Z".into()),
            ),
            (
                "base_sha".into(),
                Json::String("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
            ),
            ("operation".into(), Json::String(operation.into())),
            ("parameters".into(), parameters),
            (
                "contract_revision".into(),
                Json::String(TRUSTED_CONTRACT_REVISION.into()),
            ),
        ])
    }

    fn issue_body(request: Json, override_digest: Option<&str>) -> String {
        let canonical = jcs(&request).unwrap();
        let digest = override_digest
            .map(str::to_owned)
            .unwrap_or_else(|| sha256_hex(canonical.as_bytes()));
        let envelope = Json::Object(vec![
            (
                "kind".into(),
                Json::String("governance-ledger-request".into()),
            ),
            ("schema_version".into(), Json::Number("1".into())),
            ("request_digest".into(), Json::String(digest)),
            ("request".into(), request),
        ]);
        format!(
            "{REQUEST_MARKER}\n```json\n{}\n```\n",
            jcs(&envelope).unwrap()
        )
    }

    fn webhook_body(issue_number: u64, action: &str, issue_body: &str) -> Vec<u8> {
        jcs(&Json::Object(vec![
            ("action".into(), Json::String(action.into())),
            (
                "repository".into(),
                Json::Object(vec![(
                    "full_name".into(),
                    Json::String(GOVERNANCE_REPOSITORY.into()),
                )]),
            ),
            (
                "issue".into(),
                Json::Object(vec![
                    ("number".into(), Json::Number(issue_number.to_string())),
                    ("body".into(), Json::String(issue_body.into())),
                ]),
            ),
        ]))
        .unwrap()
        .into_bytes()
    }

    fn headers(body: &[u8], delivery: &str) -> WebhookHeaders {
        WebhookHeaders {
            signature_256: format!("sha256={}", hmac_sha256_hex(b"secret", body)),
            delivery_id: delivery.into(),
            event: "issues".into(),
        }
    }

    fn default_validator(calls: Arc<AtomicUsize>) -> FakeValidator {
        FakeValidator {
            calls,
            result: Arc::new(Mutex::new(Ok(validator_result(vec![one_change(
                "active\n",
            )])))),
            sleep_ms: 0,
        }
    }

    fn persist_terminal(db: &Path, request: Json, issue_number: u64, now: i64) -> Vec<u8> {
        let issue = issue_body(request, None);
        let accepted = parse_canonical_request(&issue).unwrap();
        let terminal = build_rejection_receipt(
            &accepted.request,
            validator::TRUSTED_VALIDATOR_REVISION,
            "test-terminal",
        );
        let mut store = SqliteStore::open(db).unwrap();
        assert_eq!(
            store
                .claim(&ClaimInput {
                    request_id: &accepted.request.request_id,
                    request_digest: &accepted.request.request_digest,
                    issue_number: i64::try_from(issue_number).unwrap(),
                    canonical_request: &accepted.request.canonical_json,
                    canonical_identity: &accepted.request.request_digest,
                    delivery_id: "seed-delivery",
                    instance_id: "seed-instance",
                    now_epoch: now,
                    lease_seconds: 10,
                })
                .unwrap(),
            Claim::Execute
        );
        store
            .complete(
                &accepted.request.request_id,
                &accepted.request.request_digest,
                "seed-instance",
                &terminal.body,
                &terminal.result_id,
            )
            .unwrap();
        webhook_body(issue_number, "edited", &issue)
    }

    #[test]
    fn public_webhook_surface_is_only_validate_ledger() {
        assert_eq!(PUBLIC_WEBHOOK_OPERATIONS, &["governance.validate-ledger"]);
    }

    #[test]
    fn valid_signature_allows_an_allowed_ledger_mutation() {
        let db = TestDb::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let publisher = FakePublisher::default();
        let service = service(
            &db.0,
            default_validator(Arc::clone(&calls)),
            publisher.clone(),
            FixedClock(NOW),
            "a",
        );
        let request = canonical_request(
            "request-allowed-0001",
            "task.transition_status",
            Json::Object(vec![
                ("task_id".into(), Json::String("ZACH-001".into())),
                ("target_status".into(), Json::String("active".into())),
            ]),
        );
        let body = webhook_body(1, "opened", &issue_body(request, None));
        let outcome = service.handle(&headers(&body, "delivery-a"), &body);
        assert_eq!(outcome.status_code, 200);
        assert!(
            outcome
                .terminal_receipt
                .unwrap()
                .contains("\"status\":\"succeeded\"")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(publisher.post_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn invalid_signature_is_rejected_before_json_parsing() {
        let db = TestDb::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let service = service(
            &db.0,
            default_validator(Arc::clone(&calls)),
            FakePublisher::default(),
            FixedClock(NOW),
            "a",
        );
        let body = b"definitely not json";
        let outcome =
            service.handle(
                &WebhookHeaders {
                    signature_256:
                        "sha256=0000000000000000000000000000000000000000000000000000000000000000"
                            .into(),
                    delivery_id: "delivery-a".into(),
                    event: "issues".into(),
                },
                body,
            );
        assert_eq!(outcome.code, "signature-invalid");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn prohibited_mutation_is_terminally_rejected() {
        let db = TestDb::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let service = service(
            &db.0,
            default_validator(Arc::clone(&calls)),
            FakePublisher::default(),
            FixedClock(NOW),
            "a",
        );
        let request = canonical_request("request-prohibit-1", "repo.delete", Json::Object(vec![]));
        let body = webhook_body(2, "opened", &issue_body(request, None));
        let outcome = service.handle(&headers(&body, "delivery-b"), &body);
        let receipt = outcome.terminal_receipt.unwrap();
        assert!(receipt.contains("\"status\":\"rejected\""));
        assert!(receipt.contains("unsupported-operation"));
    }

    #[test]
    fn request_digest_mismatch_fails_closed() {
        let db = TestDb::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let service = service(
            &db.0,
            default_validator(Arc::clone(&calls)),
            FakePublisher::default(),
            FixedClock(NOW),
            "a",
        );
        let request = canonical_request(
            "request-digest-1",
            "task.transition_status",
            Json::Object(vec![]),
        );
        let body = webhook_body(
            3,
            "opened",
            &issue_body(
                request,
                Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            ),
        );
        let outcome = service.handle(&headers(&body, "delivery-c"), &body);
        assert_eq!(outcome.code, "request-digest-mismatch");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn exact_duplicate_replays_persisted_receipt_without_revalidation_even_after_reopen() {
        let db = TestDb::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let publisher = FakePublisher::default();
        let request = canonical_request(
            "request-replay-1",
            "task.transition_status",
            Json::Object(vec![]),
        );
        let body = webhook_body(4, "opened", &issue_body(request.clone(), None));
        let first_receipt = {
            let service = service(
                &db.0,
                default_validator(Arc::clone(&calls)),
                publisher.clone(),
                FixedClock(NOW),
                "a",
            );
            service
                .handle(&headers(&body, "delivery-d"), &body)
                .terminal_receipt
                .unwrap()
        };
        let reopened = service(
            &db.0,
            default_validator(Arc::clone(&calls)),
            publisher.clone(),
            FixedClock(NOW + 1),
            "b",
        );
        let replay = reopened.handle(&headers(&body, "delivery-e"), &body);
        assert!(replay.replayed);
        assert_eq!(replay.terminal_receipt.unwrap(), first_receipt);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(publisher.post_calls.load(Ordering::SeqCst), 1);
        assert_eq!(publisher.reconcile_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn conflicting_request_id_never_executes_second_transaction() {
        let db = TestDb::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let service = service(
            &db.0,
            default_validator(Arc::clone(&calls)),
            FakePublisher::default(),
            FixedClock(NOW),
            "a",
        );
        let first = canonical_request(
            "request-conflict-1",
            "task.transition_status",
            Json::Object(vec![]),
        );
        let first_body = webhook_body(5, "opened", &issue_body(first, None));
        assert_eq!(
            service
                .handle(&headers(&first_body, "delivery-f"), &first_body)
                .status_code,
            200
        );
        let second = canonical_request(
            "request-conflict-1",
            "task.append_run",
            Json::Object(vec![]),
        );
        let second_body = webhook_body(6, "opened", &issue_body(second, None));
        let outcome = service.handle(&headers(&second_body, "delivery-g"), &second_body);
        assert_eq!(outcome.code, "request-id-conflict");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn first_issue_request_is_immutable_after_body_edit() {
        let db = TestDb::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let service = service(
            &db.0,
            default_validator(Arc::clone(&calls)),
            FakePublisher::default(),
            FixedClock(NOW),
            "a",
        );
        let first = canonical_request(
            "request-freeze-01",
            "task.transition_status",
            Json::Object(vec![]),
        );
        let first_body = webhook_body(7, "opened", &issue_body(first, None));
        assert_eq!(
            service
                .handle(&headers(&first_body, "delivery-h"), &first_body)
                .status_code,
            200
        );
        let edited =
            canonical_request("request-freeze-02", "task.append_run", Json::Object(vec![]));
        let edited_body = webhook_body(7, "edited", &issue_body(edited, None));
        let outcome = service.handle(&headers(&edited_body, "delivery-i"), &edited_body);
        assert_eq!(outcome.code, "issue-request-frozen");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn concurrent_duplicate_executes_validator_at_most_once() {
        let db = TestDb::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let validator = FakeValidator {
            sleep_ms: 120,
            ..default_validator(Arc::clone(&calls))
        };
        let service = Arc::new(service(
            &db.0,
            validator,
            FakePublisher::default(),
            FixedClock(NOW),
            "a",
        ));
        let request = canonical_request(
            "request-concurr-1",
            "task.transition_status",
            Json::Object(vec![]),
        );
        let body = Arc::new(webhook_body(8, "opened", &issue_body(request, None)));
        let first_service = Arc::clone(&service);
        let first_body = Arc::clone(&body);
        let first = thread::spawn(move || {
            first_service.handle(&headers(&first_body, "delivery-j"), &first_body)
        });
        thread::sleep(Duration::from_millis(20));
        let second = service.handle(&headers(&body, "delivery-k"), &body);
        let first = first.join().unwrap();
        assert_eq!(first.status_code, 200);
        assert_eq!(second.code, "transaction-in-flight");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ambiguous_intermediate_state_fails_closed_without_revalidation() {
        let db = TestDb::new();
        let request = canonical_request(
            "request-ambig-01",
            "task.transition_status",
            Json::Object(vec![]),
        );
        let issue = issue_body(request.clone(), None);
        let accepted = parse_canonical_request(&issue).unwrap();
        {
            let mut store = SqliteStore::open(&db.0).unwrap();
            assert_eq!(
                store
                    .claim(&ClaimInput {
                        request_id: &accepted.request.request_id,
                        request_digest: &accepted.request.request_digest,
                        issue_number: 9,
                        canonical_request: &accepted.request.canonical_json,
                        canonical_identity: &accepted.request.request_digest,
                        delivery_id: "delivery-l",
                        instance_id: "dead-instance",
                        now_epoch: NOW - 1_000,
                        lease_seconds: 1,
                    })
                    .unwrap(),
                Claim::Execute
            );
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let service = service(
            &db.0,
            default_validator(Arc::clone(&calls)),
            FakePublisher::default(),
            FixedClock(NOW),
            "new-instance",
        );
        let body = webhook_body(9, "edited", &issue);
        let outcome = service.handle(&headers(&body, "delivery-m"), &body);
        assert!(
            outcome
                .terminal_receipt
                .unwrap()
                .contains("ambiguous-recovery")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn expired_request_is_terminally_rejected_before_validator() {
        let db = TestDb::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let service = service(
            &db.0,
            default_validator(Arc::clone(&calls)),
            FakePublisher::default(),
            FixedClock(NOW),
            "a",
        );
        let mut request = canonical_request(
            "request-expired-1",
            "task.transition_status",
            Json::Object(vec![]),
        );
        if let Json::Object(ref mut object) = request {
            let expires = object
                .iter_mut()
                .find(|(key, _)| key == "expires_at")
                .unwrap();
            expires.1 = Json::String("2020-01-01T00:00:00Z".into());
        }
        let body = webhook_body(10, "opened", &issue_body(request, None));
        let outcome = service.handle(&headers(&body, "delivery-n"), &body);
        assert!(
            outcome
                .terminal_receipt
                .unwrap()
                .contains("request-time-invalid")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn publication_claim_uses_fresh_clock_after_validation() {
        let db = TestDb::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let publisher = FakePublisher {
            fail_after_accept: true,
            ..FakePublisher::default()
        };
        let service = service(
            &db.0,
            default_validator(Arc::clone(&calls)),
            publisher,
            SequenceClock::new(vec![NOW, NOW + 1_000]),
            "slow-validator-instance",
        );
        let request = canonical_request(
            "request-fresh-clock",
            "task.transition_status",
            Json::Object(vec![]),
        );
        let body = webhook_body(11, "opened", &issue_body(request.clone(), None));
        let outcome = service.handle(&headers(&body, "delivery-fresh"), &body);
        assert_eq!(outcome.code, "receipt-publication-ambiguous");

        let accepted = parse_canonical_request(&issue_body(request, None)).unwrap();
        let mut store = SqliteStore::open(&db.0).unwrap();
        assert_eq!(
            store
                .claim_publication(
                    &accepted.request.request_id,
                    &accepted.request.request_digest,
                    "observer",
                    NOW + 1_001,
                    PUBLICATION_LEASE_SECONDS,
                )
                .unwrap(),
            PublicationClaim::InFlight
        );
    }

    #[test]
    fn crash_after_remote_post_reconciles_without_second_post() {
        let db = TestDb::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let publisher = FakePublisher {
            fail_after_accept: true,
            ..FakePublisher::default()
        };
        let request = canonical_request(
            "request-post-crash",
            "task.transition_status",
            Json::Object(vec![]),
        );
        let body = webhook_body(12, "opened", &issue_body(request, None));
        let first = service(
            &db.0,
            default_validator(Arc::clone(&calls)),
            publisher.clone(),
            FixedClock(NOW),
            "publisher-a",
        )
        .handle(&headers(&body, "delivery-crash-a"), &body);
        assert_eq!(first.code, "receipt-publication-ambiguous");
        assert_eq!(publisher.post_calls.load(Ordering::SeqCst), 1);

        let replay = service(
            &db.0,
            default_validator(Arc::clone(&calls)),
            publisher.clone(),
            FixedClock(NOW + PUBLICATION_LEASE_SECONDS + 1),
            "publisher-b",
        )
        .handle(&headers(&body, "delivery-crash-b"), &body);
        assert_eq!(replay.status_code, 200);
        assert_eq!(replay.code, "terminal-replayed");
        assert_eq!(publisher.post_calls.load(Ordering::SeqCst), 1);
        assert_eq!(publisher.reconcile_calls.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn uncertain_sending_with_no_remote_match_fails_closed_without_post() {
        let db = TestDb::new();
        let request = canonical_request(
            "request-no-match-1",
            "task.transition_status",
            Json::Object(vec![]),
        );
        let body = persist_terminal(&db.0, request.clone(), 13, NOW);
        let accepted = parse_canonical_request(&issue_body(request, None)).unwrap();
        {
            let mut store = SqliteStore::open(&db.0).unwrap();
            assert_eq!(
                store
                    .claim_publication(
                        &accepted.request.request_id,
                        &accepted.request.request_digest,
                        "publisher-a",
                        NOW,
                        PUBLICATION_LEASE_SECONDS,
                    )
                    .unwrap(),
                PublicationClaim::Publish
            );
        }

        let publisher = FakePublisher::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let outcome = service(
            &db.0,
            default_validator(Arc::clone(&calls)),
            publisher.clone(),
            FixedClock(NOW + PUBLICATION_LEASE_SECONDS + 1),
            "publisher-b",
        )
        .handle(&headers(&body, "delivery-no-match"), &body);
        assert_eq!(outcome.status_code, 503);
        assert_eq!(outcome.code, "receipt-publication-ambiguous");
        assert_eq!(publisher.post_calls.load(Ordering::SeqCst), 0);
        assert_eq!(publisher.reconcile_calls.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn independent_concurrent_publishers_emit_at_most_one_terminal_post() {
        let db = TestDb::new();
        let request = canonical_request(
            "request-publish-race",
            "task.transition_status",
            Json::Object(vec![]),
        );
        let body = Arc::new(persist_terminal(&db.0, request, 14, NOW));
        let publisher = FakePublisher {
            post_sleep_ms: 120,
            ..FakePublisher::default()
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let first_service = service(
            &db.0,
            default_validator(Arc::clone(&calls)),
            publisher.clone(),
            FixedClock(NOW),
            "publisher-a",
        );
        let second_service = service(
            &db.0,
            default_validator(Arc::clone(&calls)),
            publisher.clone(),
            FixedClock(NOW),
            "publisher-b",
        );
        let first_body = Arc::clone(&body);
        let first = thread::spawn(move || {
            first_service.handle(&headers(&first_body, "delivery-race-a"), &first_body)
        });
        thread::sleep(Duration::from_millis(20));
        let second = second_service.handle(&headers(&body, "delivery-race-b"), &body);
        let first = first.join().unwrap();
        assert_eq!(first.status_code, 200);
        assert_eq!(second.code, "receipt-publication-in-flight");
        assert!(publisher.post_calls.load(Ordering::SeqCst) <= 1);
        assert_eq!(publisher.post_calls.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn result_changes_are_sorted_and_boundaries_cannot_be_overridden() {
        let request = LedgerRequest {
            request_id: "request-sort-0001".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2027-01-01T00:00:00Z".into(),
            base_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            operation: "task.transition_status".into(),
            parameters: Json::Object(vec![(
                "max_changed_files".into(),
                Json::Number("999".into()),
            )]),
            contract_revision: TRUSTED_CONTRACT_REVISION.into(),
            canonical_json: "{}".into(),
            request_digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .into(),
        };
        let receipt = build_success_receipt(
            &request,
            validator::TRUSTED_VALIDATOR_REVISION,
            vec![
                LedgerChange {
                    path: "tasks/B.md".into(),
                    operation: ChangeOperation::Delete,
                    content: None,
                    blob_sha: None,
                },
                LedgerChange {
                    path: "tasks/A.md".into(),
                    operation: ChangeOperation::Delete,
                    content: None,
                    blob_sha: None,
                },
            ],
            "cccccccccccccccccccccccccccccccccccccccc",
        );
        let a = receipt.body.find("tasks/A.md").unwrap();
        let b = receipt.body.find("tasks/B.md").unwrap();
        assert!(a < b);

        let nine = (0..9)
            .map(|index| LedgerChange {
                path: format!("tasks/{index}.md"),
                operation: ChangeOperation::Delete,
                content: None,
                blob_sha: None,
            })
            .collect::<Vec<_>>();
        let overflow = build_success_receipt(
            &request,
            validator::TRUSTED_VALIDATOR_REVISION,
            nine,
            "cccccccccccccccccccccccccccccccccccccccc",
        );
        assert!(overflow.body.contains("result-too-large"));
    }

    fn receipt_boundary_request() -> LedgerRequest {
        LedgerRequest {
            request_id: "request-receipt-1".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2027-01-01T00:00:00Z".into(),
            base_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            operation: "task.transition_status".into(),
            parameters: Json::Object(vec![]),
            contract_revision: TRUSTED_CONTRACT_REVISION.into(),
            canonical_json: "{}".into(),
            request_digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .into(),
        }
    }

    #[test]
    fn receipt_60000_bytes_is_accepted_and_60001_is_rejected() {
        let request = receipt_boundary_request();
        let empty = build_success_receipt(
            &request,
            validator::TRUSTED_VALIDATOR_REVISION,
            vec![one_change("")],
            "cccccccccccccccccccccccccccccccccccccccc",
        );
        let one_nul = build_success_receipt(
            &request,
            validator::TRUSTED_VALIDATOR_REVISION,
            vec![one_change("\0")],
            "cccccccccccccccccccccccccccccccccccccccc",
        );
        let escaped_unit = one_nul.body.len() - empty.body.len();
        let target_delta = MAX_RECEIPT_UTF8_BYTES - empty.body.len();
        let nul_count = target_delta / escaped_unit;
        let remainder = target_delta % escaped_unit;
        let mut content = "\0".repeat(nul_count);
        content.push_str(&"x".repeat(remainder));
        assert!(content.len() <= validator::MAX_TOTAL_RESULT_UTF8_BYTES);

        let exact = build_success_receipt(
            &request,
            validator::TRUSTED_VALIDATOR_REVISION,
            vec![one_change(&content)],
            "cccccccccccccccccccccccccccccccccccccccc",
        );
        assert_eq!(exact.body.len(), MAX_RECEIPT_UTF8_BYTES);
        assert!(exact.body.contains("\"status\":\"succeeded\""));

        content.push('x');
        let over = build_success_receipt(
            &request,
            validator::TRUSTED_VALIDATOR_REVISION,
            vec![one_change(&content)],
            "cccccccccccccccccccccccccccccccccccccccc",
        );
        assert!(over.body.contains("receipt-too-large"));
        assert!(!over.body.contains("\"status\":\"succeeded\""));
    }

    #[test]
    fn receipt_over_60000_bytes_becomes_terminal_failure_not_truncated_success() {
        let request = receipt_boundary_request();
        let change = LedgerChange {
            path: "tasks/A.md".into(),
            operation: ChangeOperation::Upsert,
            content: Some("\0".repeat(20_000)),
            blob_sha: Some("1111111111111111111111111111111111111111".into()),
        };
        let receipt = build_success_receipt(
            &request,
            validator::TRUSTED_VALIDATOR_REVISION,
            vec![change],
            "cccccccccccccccccccccccccccccccccccccccc",
        );
        assert!(receipt.body.contains("receipt-too-large"));
        assert!(!receipt.body.contains("\"status\":\"succeeded\""));
        assert!(receipt.body.len() <= MAX_RECEIPT_UTF8_BYTES);
    }

    #[test]
    fn result_over_48000_bytes_is_rejected() {
        let request = receipt_boundary_request();
        let receipt = build_success_receipt(
            &request,
            validator::TRUSTED_VALIDATOR_REVISION,
            vec![LedgerChange {
                path: "tasks/A.md".into(),
                operation: ChangeOperation::Upsert,
                content: Some("x".repeat(48_001)),
                blob_sha: Some("1111111111111111111111111111111111111111".into()),
            }],
            "cccccccccccccccccccccccccccccccccccccccc",
        );
        assert!(receipt.body.contains("result-too-large"));
    }

    #[test]
    fn request_or_candidate_cannot_choose_validator_revision() {
        let request = canonical_request(
            "request-validator-1",
            "task.transition_status",
            Json::Object(vec![(
                "validator_revision".into(),
                Json::String("ffffffffffffffffffffffffffffffffffffffff".into()),
            )]),
        );
        let accepted = parse_canonical_request(&issue_body(request, None)).unwrap();
        let receipt = build_rejection_receipt(
            &accepted.request,
            validator::TRUSTED_VALIDATOR_REVISION,
            "candidate-invalid",
        );
        assert!(receipt.body.contains(validator::TRUSTED_VALIDATOR_REVISION));
        assert!(
            !receipt
                .body
                .contains("ffffffffffffffffffffffffffffffffffffffff")
        );
    }

    #[test]
    fn utc_parser_matches_formatter_and_supports_fractional_seconds() {
        let rendered = epoch_to_rfc3339(NOW);
        assert_eq!(parse_utc_epoch(&rendered), Some(NOW));
        assert_eq!(
            parse_utc_epoch("2026-08-26T23:30:00.123Z"),
            parse_utc_epoch("2026-08-26T23:30:00Z")
        );
    }
}
