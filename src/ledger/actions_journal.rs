//! # Actions Request Journal State Machine
//!
//! Pure immutable-request journal state machine for Actions retries.
//!
//! ## Required Caller Invariants
//!
//! **CRITICAL STORAGE INVARIANT**:
//! The storage subsystem (e.g. SQLite database, key-value store) MUST additionally
//! enforce a global unique index on `request_id` across all repositories and issues.
//! This module validates local replay consistency against a single journal record,
//! but does not claim that this module alone enforces global storage-level uniqueness
//! or durable persistence.

use super::actions::{
    AcceptedIssue, ActionOperation, MAX_BODY_BYTES, MAX_JSON_DEPTH, check_json_depth,
};
use super::json::{Json, MAX_SAFE_INTEGER, jcs, object_get, object_string, object_u64, sha256_hex};
use std::fmt;

pub const SCHEMA_VERSION: u64 = 1;
pub const MAX_JOURNAL_BYTES: usize = 64 * 1024; // 64 KiB
pub const MAX_EXECUTION_ID_BYTES: usize = 128;
pub const MAX_TERMINAL_CODE_BYTES: usize = 128;
pub const MAX_TERMINAL_REF_BYTES: usize = 512;

const KNOWN_JOURNAL_KEYS: &[&str] = &[
    "schema_version",
    "repository_id",
    "repository_full_name",
    "issue_id",
    "issue_number",
    "author_id",
    "sender_id",
    "request_id",
    "operation",
    "canonical_request",
    "request_digest",
    "accepted_at",
    "policy_revision",
    "state",
    "execution_id",
    "terminal_code",
    "terminal_reference",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalError {
    pub code: &'static str,
    pub message: String,
}

impl JournalError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for JournalError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JournalState {
    Accepted,
    Executing,
    Succeeded,
    Rejected,
    Ambiguous,
}

impl JournalState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Executing => "executing",
            Self::Succeeded => "succeeded",
            Self::Rejected => "rejected",
            Self::Ambiguous => "ambiguous",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "accepted" => Some(Self::Accepted),
            "executing" => Some(Self::Executing),
            "succeeded" => Some(Self::Succeeded),
            "rejected" => Some(Self::Rejected),
            "ambiguous" => Some(Self::Ambiguous),
            _ => None,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Succeeded | Self::Rejected)
    }
}

impl fmt::Display for JournalState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    Granted,
    ReconciliationRequired,
    TerminalReplay {
        state: JournalState,
        terminal_code: String,
        terminal_reference: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedReconciliationObservation {
    pub terminal_state: JournalState,
    pub terminal_code: String,
    pub terminal_reference: Option<String>,
}

impl TrustedReconciliationObservation {
    pub fn succeeded(code: impl Into<String>, reference: Option<&str>) -> Self {
        Self {
            terminal_state: JournalState::Succeeded,
            terminal_code: code.into(),
            terminal_reference: reference.map(str::to_string),
        }
    }

    pub fn rejected(code: impl Into<String>, reference: Option<&str>) -> Self {
        Self {
            terminal_state: JournalState::Rejected,
            terminal_code: code.into(),
            terminal_reference: reference.map(str::to_string),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalRecord {
    schema_version: u64,
    accepted_issue: AcceptedIssue,
    accepted_at: String,
    policy_revision: String,
    state: JournalState,
    execution_id: Option<String>,
    terminal_code: Option<String>,
    terminal_reference: Option<String>,
}

impl JournalRecord {
    /// Freeze a validated `AcceptedIssue` into an initial `JournalRecord` in `Accepted` state.
    pub fn new(
        accepted_issue: AcceptedIssue,
        accepted_at: impl Into<String>,
        policy_revision: impl Into<String>,
    ) -> Result<Self, JournalError> {
        let accepted_at = accepted_at.into();
        let policy_revision = policy_revision.into();

        if accepted_issue.repository_id == 0 {
            return Err(JournalError::new(
                "invalid_source_identity",
                "repository_id must be non-zero",
            ));
        }
        if accepted_issue.repository_full_name.trim().is_empty()
            || !accepted_issue.repository_full_name.contains('/')
        {
            return Err(JournalError::new(
                "invalid_source_identity",
                "repository_full_name must be non-empty and formatted as owner/repo",
            ));
        }
        if accepted_issue.issue_id == 0 {
            return Err(JournalError::new(
                "invalid_source_identity",
                "issue_id must be non-zero",
            ));
        }
        if accepted_issue.issue_number == 0 {
            return Err(JournalError::new(
                "invalid_source_identity",
                "issue_number must be non-zero",
            ));
        }
        if accepted_issue.author_id == 0 {
            return Err(JournalError::new(
                "invalid_source_identity",
                "author_id must be non-zero",
            ));
        }
        if accepted_issue.sender_id == 0 {
            return Err(JournalError::new(
                "invalid_source_identity",
                "sender_id must be non-zero",
            ));
        }
        if !valid_request_id(&accepted_issue.request_id) {
            return Err(JournalError::new(
                "invalid_request_id",
                "request_id format invalid",
            ));
        }
        if !is_hex64(&accepted_issue.request_digest) {
            return Err(JournalError::new(
                "invalid_request_digest",
                "request_digest must be a 64-character lowercase hex SHA-256",
            ));
        }
        let computed_digest = sha256_hex(accepted_issue.canonical_request.as_bytes());
        if computed_digest != accepted_issue.request_digest {
            return Err(JournalError::new(
                "canonical_request_digest_mismatch",
                "canonical_request digest does not match request_digest",
            ));
        }

        if !validate_utc_timestamp(&accepted_at) {
            return Err(JournalError::new(
                "invalid_accepted_at",
                "accepted_at must be an RFC-3339 UTC timestamp ending in Z",
            ));
        }
        if !is_lowercase_sha40(&policy_revision) {
            return Err(JournalError::new(
                "invalid_policy_revision",
                "policy_revision must be a 40-character lowercase hex SHA-1",
            ));
        }

        let parameters = parse_canonical_request(
            &accepted_issue.canonical_request,
            &accepted_issue.request_id,
            accepted_issue.operation,
            &accepted_issue.request_digest,
        )?;
        if parameters != accepted_issue.parameters {
            return Err(JournalError::new(
                "canonical_parameters_mismatch",
                "decoded parameters differ from frozen canonical request",
            ));
        }

        let record = Self {
            schema_version: SCHEMA_VERSION,
            accepted_issue,
            accepted_at,
            policy_revision,
            state: JournalState::Accepted,
            execution_id: None,
            terminal_code: None,
            terminal_reference: None,
        };
        // Apply exactly the same persistence bounds at acceptance and restart.
        Self::from_json(&record.to_json()?)
    }

    /// Replay check requiring identical identity, request, and digest.
    ///
    /// Validates that:
    /// - `repository_id` matches
    /// - `repository_full_name` matches
    /// - `issue_id` matches
    /// - `issue_number` matches
    /// - `author_id` matches original issue author
    /// - `request_id` matches
    /// - `canonical_request` matches
    /// - `request_digest` matches
    ///
    /// `sender_id` may differ because the Issue decoder already authorized it.
    /// The frozen journal record retains the original sender identity.
    ///
    /// Any request ID reused for another Issue, different author, or edited payload conflicts.
    ///
    /// # Storage Invariant Notice
    /// Storage must additionally enforce a global request-ID index across all issues and
    /// repositories. This method verifies replay against this single record, and does not claim
    /// that this module alone enforces global uniqueness across the entire storage system.
    pub fn check_replay(&self, incoming: &AcceptedIssue) -> Result<(), JournalError> {
        if incoming.request_id != self.accepted_issue.request_id {
            return Err(JournalError::new(
                "replay_request_id_mismatch",
                "incoming request_id does not match frozen journal record",
            ));
        }
        if incoming.repository_id != self.accepted_issue.repository_id {
            return Err(JournalError::new(
                "replay_repository_id_mismatch",
                "incoming repository_id does not match frozen journal record",
            ));
        }
        if incoming.repository_full_name != self.accepted_issue.repository_full_name {
            return Err(JournalError::new(
                "replay_repository_name_mismatch",
                "incoming repository_full_name does not match frozen journal record",
            ));
        }
        if incoming.issue_id != self.accepted_issue.issue_id {
            return Err(JournalError::new(
                "replay_issue_id_mismatch",
                "incoming issue_id does not match frozen journal record",
            ));
        }
        if incoming.issue_number != self.accepted_issue.issue_number {
            return Err(JournalError::new(
                "replay_issue_number_mismatch",
                "incoming issue_number does not match frozen journal record",
            ));
        }
        if incoming.author_id != self.accepted_issue.author_id {
            return Err(JournalError::new(
                "replay_author_id_mismatch",
                "incoming author_id does not match frozen journal record original author",
            ));
        }
        if incoming.canonical_request != self.accepted_issue.canonical_request {
            return Err(JournalError::new(
                "replay_canonical_request_mismatch",
                "incoming canonical_request does not match frozen journal record",
            ));
        }
        if incoming.request_digest != self.accepted_issue.request_digest {
            return Err(JournalError::new(
                "replay_request_digest_mismatch",
                "incoming request_digest does not match frozen journal record",
            ));
        }

        Ok(())
    }

    /// Claim execution for this request.
    ///
    /// Execution can only be claimed from `Accepted` -> `Executing`.
    /// Repeated claim, even with the same execution ID, returns `ReconciliationRequired`
    /// without granting another execution.
    ///
    /// If already terminal, returns `TerminalReplay` without granting another execution.
    pub fn claim_execution(&mut self, execution_id: &str) -> Result<ClaimOutcome, JournalError> {
        if !valid_execution_id(execution_id) {
            return Err(JournalError::new(
                "invalid_execution_id",
                "execution_id must be 1-128 non-secret safe characters",
            ));
        }

        match self.state {
            JournalState::Accepted => {
                self.state = JournalState::Executing;
                self.execution_id = Some(execution_id.to_string());
                Ok(ClaimOutcome::Granted)
            }
            JournalState::Executing | JournalState::Ambiguous => {
                Ok(ClaimOutcome::ReconciliationRequired)
            }
            JournalState::Succeeded | JournalState::Rejected => {
                let terminal_code = self.terminal_code.clone().unwrap_or_default();
                let terminal_reference = self.terminal_reference.clone();
                Ok(ClaimOutcome::TerminalReplay {
                    state: self.state,
                    terminal_code,
                    terminal_reference,
                })
            }
        }
    }

    /// Record terminal completion from `Executing` state.
    ///
    /// Once terminal, exact replay with identical outcome is an immutable no-op.
    /// Conflicting terminal outcome is rejected.
    ///
    /// If in `Ambiguous` state, resolution to terminal is forbidden through this method
    /// and MUST go through `resolve_trusted_reconciliation`.
    pub fn complete_terminal(
        &mut self,
        state: JournalState,
        terminal_code: impl Into<String>,
        terminal_reference: Option<&str>,
    ) -> Result<(), JournalError> {
        if !state.is_terminal() {
            return Err(JournalError::new(
                "invalid_state_transition",
                "complete_terminal requires Succeeded or Rejected state",
            ));
        }
        let code = terminal_code.into();
        let reference = terminal_reference.map(str::to_string);

        if !valid_terminal_code(&code) {
            return Err(JournalError::new(
                "invalid_terminal_code",
                "terminal_code must be 1-128 printable ASCII characters",
            ));
        }
        if let Some(ref r) = reference
            && !valid_terminal_reference(r)
        {
            return Err(JournalError::new(
                "invalid_terminal_reference",
                "terminal_reference must be 1-512 printable ASCII characters",
            ));
        }

        match self.state {
            JournalState::Executing => {
                self.state = state;
                self.terminal_code = Some(code);
                self.terminal_reference = reference;
                Ok(())
            }
            JournalState::Succeeded | JournalState::Rejected => {
                if self.state == state
                    && self.terminal_code.as_deref() == Some(&code)
                    && self.terminal_reference == reference
                {
                    // Immutable exact replay
                    Ok(())
                } else {
                    Err(JournalError::new(
                        "conflicting_terminal_result",
                        "conflicting terminal outcome for already-completed journal record",
                    ))
                }
            }
            JournalState::Accepted => Err(JournalError::new(
                "invalid_state_transition",
                "cannot complete execution before claiming execution",
            )),
            JournalState::Ambiguous => Err(JournalError::new(
                "unauthorized_reconciliation",
                "ambiguous record must be resolved via resolve_trusted_reconciliation",
            )),
        }
    }

    pub fn complete_succeeded(
        &mut self,
        terminal_code: impl Into<String>,
        terminal_reference: Option<&str>,
    ) -> Result<(), JournalError> {
        self.complete_terminal(JournalState::Succeeded, terminal_code, terminal_reference)
    }

    pub fn complete_rejected(
        &mut self,
        terminal_code: impl Into<String>,
        terminal_reference: Option<&str>,
    ) -> Result<(), JournalError> {
        self.complete_terminal(JournalState::Rejected, terminal_code, terminal_reference)
    }

    /// Mark this record ambiguous from `Executing` state.
    ///
    /// Retains request identity and `execution_id`.
    pub fn mark_ambiguous(&mut self) -> Result<(), JournalError> {
        match self.state {
            JournalState::Executing => {
                self.state = JournalState::Ambiguous;
                Ok(())
            }
            JournalState::Ambiguous => Ok(()),
            JournalState::Accepted => Err(JournalError::new(
                "invalid_state_transition",
                "cannot mark ambiguous before execution is claimed",
            )),
            JournalState::Succeeded | JournalState::Rejected => Err(JournalError::new(
                "invalid_state_transition",
                "cannot mark ambiguous for an already terminal record",
            )),
        }
    }

    /// Explicitly named trusted-reconciliation API to resolve an `Ambiguous` record to terminal.
    ///
    /// The future adapter must supply independently verified effect observations.
    /// Does not grant a second execution or allow automatic elapsed-time retry.
    pub fn resolve_trusted_reconciliation(
        &mut self,
        observation: &TrustedReconciliationObservation,
    ) -> Result<(), JournalError> {
        if !observation.terminal_state.is_terminal() {
            return Err(JournalError::new(
                "invalid_state_transition",
                "reconciliation observation must specify Succeeded or Rejected terminal state",
            ));
        }
        if !valid_terminal_code(&observation.terminal_code) {
            return Err(JournalError::new(
                "invalid_terminal_code",
                "observation terminal_code must be 1-128 printable ASCII characters",
            ));
        }
        if let Some(ref r) = observation.terminal_reference
            && !valid_terminal_reference(r)
        {
            return Err(JournalError::new(
                "invalid_terminal_reference",
                "observation terminal_reference must be 1-512 printable ASCII characters",
            ));
        }

        match self.state {
            JournalState::Ambiguous => {
                self.state = observation.terminal_state;
                self.terminal_code = Some(observation.terminal_code.clone());
                self.terminal_reference = observation.terminal_reference.clone();
                Ok(())
            }
            JournalState::Succeeded | JournalState::Rejected => {
                if self.state == observation.terminal_state
                    && self.terminal_code.as_deref() == Some(&observation.terminal_code)
                    && self.terminal_reference == observation.terminal_reference
                {
                    Ok(())
                } else {
                    Err(JournalError::new(
                        "conflicting_terminal_result",
                        "trusted reconciliation conflicts with existing terminal outcome",
                    ))
                }
            }
            JournalState::Accepted | JournalState::Executing => Err(JournalError::new(
                "invalid_state_transition",
                "trusted reconciliation is only valid for Ambiguous records",
            )),
        }
    }

    /// Serialize to canonical JSON for storage persistence.
    pub fn to_json(&self) -> Result<String, JournalError> {
        let entries = vec![
            (
                "schema_version".into(),
                Json::Number(self.schema_version.to_string()),
            ),
            (
                "repository_id".into(),
                Json::Number(self.accepted_issue.repository_id.to_string()),
            ),
            (
                "repository_full_name".into(),
                Json::String(self.accepted_issue.repository_full_name.clone()),
            ),
            (
                "issue_id".into(),
                Json::Number(self.accepted_issue.issue_id.to_string()),
            ),
            (
                "issue_number".into(),
                Json::Number(self.accepted_issue.issue_number.to_string()),
            ),
            (
                "author_id".into(),
                Json::Number(self.accepted_issue.author_id.to_string()),
            ),
            (
                "sender_id".into(),
                Json::Number(self.accepted_issue.sender_id.to_string()),
            ),
            (
                "request_id".into(),
                Json::String(self.accepted_issue.request_id.clone()),
            ),
            (
                "operation".into(),
                Json::String(self.accepted_issue.operation.as_str().into()),
            ),
            (
                "canonical_request".into(),
                Json::String(self.accepted_issue.canonical_request.clone()),
            ),
            (
                "request_digest".into(),
                Json::String(self.accepted_issue.request_digest.clone()),
            ),
            ("accepted_at".into(), Json::String(self.accepted_at.clone())),
            (
                "policy_revision".into(),
                Json::String(self.policy_revision.clone()),
            ),
            ("state".into(), Json::String(self.state.as_str().into())),
            (
                "execution_id".into(),
                match &self.execution_id {
                    Some(id) => Json::String(id.clone()),
                    None => Json::Null,
                },
            ),
            (
                "terminal_code".into(),
                match &self.terminal_code {
                    Some(code) => Json::String(code.clone()),
                    None => Json::Null,
                },
            ),
            (
                "terminal_reference".into(),
                match &self.terminal_reference {
                    Some(r) => Json::String(r.clone()),
                    None => Json::Null,
                },
            ),
        ];

        let json = Json::Object(entries);
        let serialized = jcs(&json).map_err(|e| JournalError::new("serialization_failed", e.0))?;
        if serialized.len() > MAX_JOURNAL_BYTES {
            return Err(JournalError::new(
                "journal_payload_too_large",
                "serialized journal exceeds 64 KiB",
            ));
        }
        Ok(serialized)
    }

    /// Deserialize and validate a persistent journal record from JSON.
    ///
    /// Validates bounded length (max 64 KiB), depth limit (max 32), strict known fields,
    /// source identity, canonical request and digest, timestamp, SHA formats,
    /// bounded execution ID, bounded terminal results, and all required state-field
    /// cross-field consistency. Corrupted or inconsistent records fail closed.
    pub fn from_json(input: &str) -> Result<Self, JournalError> {
        if input.len() > MAX_JOURNAL_BYTES {
            return Err(JournalError::new(
                "journal_payload_too_large",
                "journal payload exceeds 64 KiB",
            ));
        }

        check_json_depth(input, MAX_JSON_DEPTH)
            .map_err(|e| JournalError::new("journal_json_depth_exceeded", e.code))?;

        let json =
            Json::parse(input).map_err(|e| JournalError::new("journal_json_malformed", e.0))?;

        let obj = json.as_object().ok_or_else(|| {
            JournalError::new("journal_not_an_object", "journal root must be an object")
        })?;

        // Strict known keys: reject arbitrary pass-through fields
        for (key, _) in obj {
            if !KNOWN_JOURNAL_KEYS.contains(&key.as_str()) {
                return Err(JournalError::new(
                    "journal_unknown_field",
                    format!("unknown field in journal record: {key}"),
                ));
            }
        }

        let schema_ver = object_u64(obj, "schema_version").ok_or_else(|| {
            JournalError::new(
                "invalid_schema_version",
                "missing or invalid schema_version",
            )
        })?;
        if schema_ver != SCHEMA_VERSION {
            return Err(JournalError::new(
                "invalid_schema_version",
                "unsupported schema_version",
            ));
        }

        let repo_id = object_u64(obj, "repository_id").ok_or_else(|| {
            JournalError::new(
                "invalid_source_identity",
                "missing or invalid repository_id",
            )
        })?;
        if repo_id == 0 {
            return Err(JournalError::new(
                "invalid_source_identity",
                "repository_id must be non-zero",
            ));
        }

        let repo_full_name = object_string(obj, "repository_full_name").ok_or_else(|| {
            JournalError::new(
                "invalid_source_identity",
                "missing or invalid repository_full_name",
            )
        })?;
        if repo_full_name.trim().is_empty() || !repo_full_name.contains('/') {
            return Err(JournalError::new(
                "invalid_source_identity",
                "repository_full_name must be non-empty and formatted as owner/repo",
            ));
        }

        let issue_id = object_u64(obj, "issue_id").ok_or_else(|| {
            JournalError::new("invalid_source_identity", "missing or invalid issue_id")
        })?;
        if issue_id == 0 {
            return Err(JournalError::new(
                "invalid_source_identity",
                "issue_id must be non-zero",
            ));
        }

        let issue_num = object_u64(obj, "issue_number").ok_or_else(|| {
            JournalError::new("invalid_source_identity", "missing or invalid issue_number")
        })?;
        if issue_num == 0 {
            return Err(JournalError::new(
                "invalid_source_identity",
                "issue_number must be non-zero",
            ));
        }

        let author_id = object_u64(obj, "author_id").ok_or_else(|| {
            JournalError::new("invalid_source_identity", "missing or invalid author_id")
        })?;
        if author_id == 0 {
            return Err(JournalError::new(
                "invalid_source_identity",
                "author_id must be non-zero",
            ));
        }

        let sender_id = object_u64(obj, "sender_id").ok_or_else(|| {
            JournalError::new("invalid_source_identity", "missing or invalid sender_id")
        })?;
        if sender_id == 0 {
            return Err(JournalError::new(
                "invalid_source_identity",
                "sender_id must be non-zero",
            ));
        }

        let request_id = object_string(obj, "request_id").ok_or_else(|| {
            JournalError::new("invalid_request_id", "missing or invalid request_id")
        })?;
        if !valid_request_id(request_id) {
            return Err(JournalError::new(
                "invalid_request_id",
                "request_id format invalid",
            ));
        }

        let op_str = object_string(obj, "operation").ok_or_else(|| {
            JournalError::new("invalid_operation", "missing or invalid operation")
        })?;
        let operation = ActionOperation::parse(op_str).ok_or_else(|| {
            JournalError::new("invalid_operation", "unrecognized action operation")
        })?;

        let canonical_request = object_string(obj, "canonical_request").ok_or_else(|| {
            JournalError::new(
                "canonical_request_missing",
                "missing canonical_request string",
            )
        })?;

        let request_digest = object_string(obj, "request_digest").ok_or_else(|| {
            JournalError::new(
                "invalid_request_digest",
                "missing or invalid request_digest",
            )
        })?;
        if !is_hex64(request_digest) {
            return Err(JournalError::new(
                "invalid_request_digest",
                "request_digest must be 64-char lowercase hex",
            ));
        }

        let parameters =
            parse_canonical_request(canonical_request, request_id, operation, request_digest)?;

        let accepted_at = object_string(obj, "accepted_at").ok_or_else(|| {
            JournalError::new("invalid_accepted_at", "missing or invalid accepted_at")
        })?;
        if !validate_utc_timestamp(accepted_at) {
            return Err(JournalError::new(
                "invalid_accepted_at",
                "accepted_at must be an RFC-3339 UTC timestamp ending in Z",
            ));
        }

        let policy_revision = object_string(obj, "policy_revision").ok_or_else(|| {
            JournalError::new(
                "invalid_policy_revision",
                "missing or invalid policy_revision",
            )
        })?;
        if !is_lowercase_sha40(policy_revision) {
            return Err(JournalError::new(
                "invalid_policy_revision",
                "policy_revision must be a 40-character lowercase hex SHA-1",
            ));
        }

        let state_str = object_string(obj, "state").ok_or_else(|| {
            JournalError::new("invalid_journal_state", "missing or invalid state")
        })?;
        let state = JournalState::parse(state_str).ok_or_else(|| {
            JournalError::new("invalid_journal_state", "unrecognized journal state")
        })?;

        let execution_id = match object_get(obj, "execution_id") {
            None | Some(Json::Null) => None,
            Some(Json::String(s)) => {
                if !valid_execution_id(s) {
                    return Err(JournalError::new(
                        "invalid_execution_id",
                        "execution_id must be 1-128 non-secret safe characters",
                    ));
                }
                Some(s.clone())
            }
            _ => {
                return Err(JournalError::new(
                    "invalid_execution_id",
                    "execution_id must be a string or null",
                ));
            }
        };

        let terminal_code = match object_get(obj, "terminal_code") {
            None | Some(Json::Null) => None,
            Some(Json::String(s)) => {
                if !valid_terminal_code(s) {
                    return Err(JournalError::new(
                        "invalid_terminal_code",
                        "terminal_code must be 1-128 printable ASCII characters",
                    ));
                }
                Some(s.clone())
            }
            _ => {
                return Err(JournalError::new(
                    "invalid_terminal_code",
                    "terminal_code must be a string or null",
                ));
            }
        };

        let terminal_reference = match object_get(obj, "terminal_reference") {
            None | Some(Json::Null) => None,
            Some(Json::String(s)) => {
                if !valid_terminal_reference(s) {
                    return Err(JournalError::new(
                        "invalid_terminal_reference",
                        "terminal_reference must be 1-512 printable ASCII characters",
                    ));
                }
                Some(s.clone())
            }
            _ => {
                return Err(JournalError::new(
                    "invalid_terminal_reference",
                    "terminal_reference must be a string or null",
                ));
            }
        };

        // State-field consistency checks to ensure corrupted journals fail closed:
        match state {
            JournalState::Accepted => {
                if execution_id.is_some() || terminal_code.is_some() || terminal_reference.is_some()
                {
                    return Err(JournalError::new(
                        "inconsistent_state_fields",
                        "Accepted record cannot have execution_id or terminal fields",
                    ));
                }
            }
            JournalState::Executing => {
                if execution_id.is_none() || terminal_code.is_some() || terminal_reference.is_some()
                {
                    return Err(JournalError::new(
                        "inconsistent_state_fields",
                        "Executing record must have execution_id and cannot have terminal fields",
                    ));
                }
            }
            JournalState::Ambiguous => {
                if execution_id.is_none() || terminal_code.is_some() || terminal_reference.is_some()
                {
                    return Err(JournalError::new(
                        "inconsistent_state_fields",
                        "Ambiguous record must retain execution_id and cannot have terminal fields",
                    ));
                }
            }
            JournalState::Succeeded | JournalState::Rejected => {
                if execution_id.is_none() || terminal_code.is_none() {
                    return Err(JournalError::new(
                        "inconsistent_state_fields",
                        "Terminal record must have both execution_id and terminal_code",
                    ));
                }
            }
        }

        let accepted_issue = AcceptedIssue {
            repository_id: repo_id,
            repository_full_name: repo_full_name.to_string(),
            issue_id,
            issue_number: issue_num,
            author_id,
            sender_id,
            request_id: request_id.to_string(),
            operation,
            parameters,
            canonical_request: canonical_request.to_string(),
            request_digest: request_digest.to_string(),
        };

        Ok(Self {
            schema_version: schema_ver,
            accepted_issue,
            accepted_at: accepted_at.to_string(),
            policy_revision: policy_revision.to_string(),
            state,
            execution_id,
            terminal_code,
            terminal_reference,
        })
    }

    pub fn repository_id(&self) -> u64 {
        self.accepted_issue.repository_id
    }
    pub fn repository_full_name(&self) -> &str {
        &self.accepted_issue.repository_full_name
    }
    pub fn issue_id(&self) -> u64 {
        self.accepted_issue.issue_id
    }
    pub fn issue_number(&self) -> u64 {
        self.accepted_issue.issue_number
    }
    pub fn author_id(&self) -> u64 {
        self.accepted_issue.author_id
    }
    pub fn sender_id(&self) -> u64 {
        self.accepted_issue.sender_id
    }
    pub fn request_id(&self) -> &str {
        &self.accepted_issue.request_id
    }
    pub fn operation(&self) -> ActionOperation {
        self.accepted_issue.operation
    }
    pub fn canonical_request(&self) -> &str {
        &self.accepted_issue.canonical_request
    }
    pub fn request_digest(&self) -> &str {
        &self.accepted_issue.request_digest
    }
    pub fn accepted_at(&self) -> &str {
        &self.accepted_at
    }
    pub fn policy_revision(&self) -> &str {
        &self.policy_revision
    }
    pub fn state(&self) -> JournalState {
        self.state
    }
    pub fn execution_id(&self) -> Option<&str> {
        self.execution_id.as_deref()
    }
    pub fn terminal_code(&self) -> Option<&str> {
        self.terminal_code.as_deref()
    }
    pub fn terminal_reference(&self) -> Option<&str> {
        self.terminal_reference.as_deref()
    }
}

fn parse_canonical_request(
    canonical_str: &str,
    expected_request_id: &str,
    expected_operation: ActionOperation,
    expected_digest: &str,
) -> Result<Json, JournalError> {
    if canonical_str.len() > MAX_BODY_BYTES {
        return Err(JournalError::new(
            "canonical_request_too_large",
            "canonical_request exceeds maximum body size",
        ));
    }

    let actual_digest = sha256_hex(canonical_str.as_bytes());
    if actual_digest != expected_digest {
        return Err(JournalError::new(
            "canonical_request_digest_mismatch",
            "canonical_request digest does not match request_digest",
        ));
    }

    check_json_depth(canonical_str, MAX_JSON_DEPTH)
        .map_err(|e| JournalError::new("canonical_request_depth_exceeded", e.code))?;

    let json = Json::parse(canonical_str)
        .map_err(|e| JournalError::new("canonical_request_malformed", e.0))?;

    let req_obj = json.as_object().ok_or_else(|| {
        JournalError::new(
            "canonical_request_not_object",
            "canonical_request must be a JSON object",
        )
    })?;

    if req_obj.len() != 4 {
        return Err(JournalError::new(
            "canonical_request_invalid_keys",
            "canonical_request must contain exactly 4 keys",
        ));
    }

    let schema_ver = object_u64(req_obj, "schema_version").ok_or_else(|| {
        JournalError::new(
            "canonical_request_invalid_schema",
            "missing or invalid schema_version in canonical_request",
        )
    })?;
    if schema_ver != 1 {
        return Err(JournalError::new(
            "canonical_request_invalid_schema",
            "canonical_request schema_version must be 1",
        ));
    }

    let req_id = object_string(req_obj, "request_id").ok_or_else(|| {
        JournalError::new(
            "canonical_request_invalid_id",
            "missing request_id in canonical_request",
        )
    })?;
    if req_id != expected_request_id {
        return Err(JournalError::new(
            "canonical_request_id_mismatch",
            "canonical_request request_id does not match record request_id",
        ));
    }

    let op_str = object_string(req_obj, "operation").ok_or_else(|| {
        JournalError::new(
            "canonical_request_invalid_operation",
            "missing operation in canonical_request",
        )
    })?;
    let op = ActionOperation::parse(op_str).ok_or_else(|| {
        JournalError::new(
            "canonical_request_unknown_operation",
            "unknown operation in canonical_request",
        )
    })?;
    if op != expected_operation {
        return Err(JournalError::new(
            "canonical_request_operation_mismatch",
            "canonical_request operation does not match record operation",
        ));
    }

    let parameters = object_get(req_obj, "parameters").ok_or_else(|| {
        JournalError::new(
            "canonical_request_missing_parameters",
            "missing parameters in canonical_request",
        )
    })?;
    if parameters.as_object().is_none() {
        return Err(JournalError::new(
            "canonical_request_parameters_not_object",
            "parameters must be an object",
        ));
    }

    validate_json_numbers(&json)?;

    let canonicalized =
        jcs(&json).map_err(|e| JournalError::new("canonical_request_not_canonical", e.0))?;
    if canonicalized != canonical_str {
        return Err(JournalError::new(
            "canonical_request_not_canonical",
            "canonical_request is not in canonical JCS format",
        ));
    }

    Ok(parameters.clone())
}

fn validate_json_numbers(value: &Json) -> Result<(), JournalError> {
    match value {
        Json::Number(n) => {
            if n.contains('.') || n.contains('e') || n.contains('E') || n.contains('+') {
                return Err(JournalError::new(
                    "unsafe_integer",
                    "floating point numbers are forbidden",
                ));
            }
            let Ok(num) = n.parse::<i64>() else {
                return Err(JournalError::new(
                    "unsafe_integer",
                    "number cannot be parsed as i64",
                ));
            };
            if num.unsigned_abs() > MAX_SAFE_INTEGER as u64 {
                return Err(JournalError::new(
                    "unsafe_integer",
                    "number exceeds IEEE-754 safe integer range",
                ));
            }
            Ok(())
        }
        Json::Array(items) => {
            for item in items {
                validate_json_numbers(item)?;
            }
            Ok(())
        }
        Json::Object(entries) => {
            for (_, item) in entries {
                validate_json_numbers(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn is_lowercase_sha40(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_execution_id(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_EXECUTION_ID_BYTES {
        return false;
    }
    let safe_chars = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
    if !safe_chars {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("ghp_")
        || lower.starts_with("gho_")
        || lower.starts_with("ghu_")
        || lower.starts_with("ghs_")
        || lower.starts_with("ghr_")
        || lower.starts_with("github_pat_")
        || lower.starts_with("bearer")
        || lower.starts_with("token")
    {
        return false;
    }
    true
}

fn valid_terminal_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TERMINAL_CODE_BYTES
        && value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

fn valid_terminal_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TERMINAL_REF_BYTES
        && value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

fn valid_request_id(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn validate_utc_timestamp(value: &str) -> bool {
    if value.is_empty() || value.len() > 35 {
        return false;
    }
    parse_utc_epoch(value).is_some()
}

fn parse_utc_epoch(value: &str) -> Option<i64> {
    // Bound calendar fields before arithmetic, including malicious huge years.
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || !bytes[..4].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_POLICY_REV: &str = "4ae216576b054f528c9edbcfed4a2711bccaa476";
    const SAMPLE_ACCEPTED_AT: &str = "2026-09-05T07:47:52Z";

    fn sample_accepted_issue() -> AcceptedIssue {
        let canonical_request = r#"{"operation":"github.ci.inspect","parameters":{"repository":"ui-design-sandbox","source_sha":"4330f61359da78543b12bd3b71f79fdaef235a86"},"request_id":"uds007-inspect-build-01","schema_version":1}"#.to_string();
        let request_digest = sha256_hex(canonical_request.as_bytes());

        AcceptedIssue {
            repository_id: 1001,
            repository_full_name: "shockerqt/zach".to_string(),
            issue_id: 501,
            issue_number: 42,
            author_id: 2001,
            sender_id: 2002,
            request_id: "uds007-inspect-build-01".to_string(),
            operation: ActionOperation::GithubCiInspect,
            parameters: Json::Object(vec![
                (
                    "repository".into(),
                    Json::String("ui-design-sandbox".into()),
                ),
                (
                    "source_sha".into(),
                    Json::String("4330f61359da78543b12bd3b71f79fdaef235a86".into()),
                ),
            ]),
            canonical_request,
            request_digest,
        }
    }

    #[test]
    fn acceptance_rejects_inconsistent_canonical_fields_and_huge_year() {
        let mut issue = sample_accepted_issue();
        issue.operation = ActionOperation::GovernanceLedger;
        assert!(JournalRecord::new(issue, SAMPLE_ACCEPTED_AT, SAMPLE_POLICY_REV).is_err());
        let mut issue = sample_accepted_issue();
        issue.parameters = Json::Object(vec![]);
        assert_eq!(
            JournalRecord::new(issue, SAMPLE_ACCEPTED_AT, SAMPLE_POLICY_REV)
                .unwrap_err()
                .code(),
            "canonical_parameters_mismatch"
        );
        for timestamp in ["9223372036854775807-01-01T00:00:00Z", "2026-9-05T00:00:00Z"] {
            assert!(
                JournalRecord::new(sample_accepted_issue(), timestamp, SAMPLE_POLICY_REV).is_err()
            );
        }
    }

    #[test]
    fn serialization_restart_exact_replay() {
        let issue = sample_accepted_issue();
        let record =
            JournalRecord::new(issue.clone(), SAMPLE_ACCEPTED_AT, SAMPLE_POLICY_REV).unwrap();

        let json = record.to_json().unwrap();
        let loaded = JournalRecord::from_json(&json).unwrap();

        assert_eq!(record, loaded);

        // Exact replay against loaded record succeeds
        assert!(loaded.check_replay(&issue).is_ok());

        // Replay with different sender succeeds and original sender is retained
        let mut diff_sender_issue = issue.clone();
        diff_sender_issue.sender_id = 9999;
        assert!(loaded.check_replay(&diff_sender_issue).is_ok());
        assert_eq!(loaded.sender_id(), 2002);
    }

    #[test]
    fn mismatched_issue_digest_body_author_rejection() {
        let issue = sample_accepted_issue();
        let record =
            JournalRecord::new(issue.clone(), SAMPLE_ACCEPTED_AT, SAMPLE_POLICY_REV).unwrap();

        // Mismatched issue_id
        let mut bad_issue = issue.clone();
        bad_issue.issue_id = 999;
        let err = record.check_replay(&bad_issue).unwrap_err();
        assert_eq!(err.code(), "replay_issue_id_mismatch");

        // Mismatched issue_number
        let mut bad_num = issue.clone();
        bad_num.issue_number = 99;
        let err = record.check_replay(&bad_num).unwrap_err();
        assert_eq!(err.code(), "replay_issue_number_mismatch");

        // Mismatched repository_id
        let mut bad_repo = issue.clone();
        bad_repo.repository_id = 2002;
        let err = record.check_replay(&bad_repo).unwrap_err();
        assert_eq!(err.code(), "replay_repository_id_mismatch");

        // Mismatched repository_full_name
        let mut bad_repo_name = issue.clone();
        bad_repo_name.repository_full_name = "other/zach".to_string();
        let err = record.check_replay(&bad_repo_name).unwrap_err();
        assert_eq!(err.code(), "replay_repository_name_mismatch");

        // Mismatched author_id
        let mut bad_author = issue.clone();
        bad_author.author_id = 7777;
        let err = record.check_replay(&bad_author).unwrap_err();
        assert_eq!(err.code(), "replay_author_id_mismatch");

        // Mismatched request_id
        let mut bad_req_id = issue.clone();
        bad_req_id.request_id = "req-different-01".to_string();
        let err = record.check_replay(&bad_req_id).unwrap_err();
        assert_eq!(err.code(), "replay_request_id_mismatch");

        // Mismatched canonical_request body
        let mut bad_body = issue.clone();
        bad_body.canonical_request = r#"{"operation":"github.ci.inspect","parameters":{"repository":"other-sandbox"},"request_id":"uds007-inspect-build-01","schema_version":1}"#.to_string();
        let err = record.check_replay(&bad_body).unwrap_err();
        assert_eq!(err.code(), "replay_canonical_request_mismatch");

        // Mismatched request_digest
        let mut bad_digest = issue.clone();
        bad_digest.request_digest = "a".repeat(64);
        let err = record.check_replay(&bad_digest).unwrap_err();
        assert_eq!(err.code(), "replay_request_digest_mismatch");
    }

    #[test]
    fn single_claim_and_repeated_claim_reconciliation_required() {
        let issue = sample_accepted_issue();
        let mut record = JournalRecord::new(issue, SAMPLE_ACCEPTED_AT, SAMPLE_POLICY_REV).unwrap();

        assert_eq!(record.state(), JournalState::Accepted);
        assert_eq!(record.execution_id(), None);

        // First claim transitions to Executing
        let outcome1 = record.claim_execution("exec-run-101").unwrap();
        assert_eq!(outcome1, ClaimOutcome::Granted);
        assert_eq!(record.state(), JournalState::Executing);
        assert_eq!(record.execution_id(), Some("exec-run-101"));

        // Repeated claim with the same execution ID returns ReconciliationRequired
        let outcome2 = record.claim_execution("exec-run-101").unwrap();
        assert_eq!(outcome2, ClaimOutcome::ReconciliationRequired);
        assert_eq!(record.state(), JournalState::Executing);
        assert_eq!(record.execution_id(), Some("exec-run-101"));

        // Repeated claim with a different execution ID also returns ReconciliationRequired
        let outcome3 = record.claim_execution("exec-run-102").unwrap();
        assert_eq!(outcome3, ClaimOutcome::ReconciliationRequired);
        assert_eq!(record.state(), JournalState::Executing);
        assert_eq!(record.execution_id(), Some("exec-run-101"));
    }

    #[test]
    fn interrupted_state_requires_reconciliation() {
        let issue = sample_accepted_issue();
        let mut record = JournalRecord::new(issue, SAMPLE_ACCEPTED_AT, SAMPLE_POLICY_REV).unwrap();

        record.claim_execution("exec-run-201").unwrap();
        assert_eq!(record.state(), JournalState::Executing);

        // Mark ambiguous retains execution_id
        record.mark_ambiguous().unwrap();
        assert_eq!(record.state(), JournalState::Ambiguous);
        assert_eq!(record.execution_id(), Some("exec-run-201"));

        // Repeated claim on Ambiguous state requires reconciliation
        let claim_result = record.claim_execution("exec-run-202").unwrap();
        assert_eq!(claim_result, ClaimOutcome::ReconciliationRequired);

        // Serialization roundtrip preserves Ambiguous state and execution_id
        let json = record.to_json().unwrap();
        let loaded = JournalRecord::from_json(&json).unwrap();
        assert_eq!(loaded.state(), JournalState::Ambiguous);
        assert_eq!(loaded.execution_id(), Some("exec-run-201"));
    }

    #[test]
    fn immutable_terminal_results() {
        let issue = sample_accepted_issue();
        let mut record = JournalRecord::new(issue, SAMPLE_ACCEPTED_AT, SAMPLE_POLICY_REV).unwrap();

        record.claim_execution("exec-run-301").unwrap();

        // Complete terminal execution
        record
            .complete_succeeded("build_passed", Some("sha-1234567890"))
            .unwrap();
        assert_eq!(record.state(), JournalState::Succeeded);
        assert_eq!(record.terminal_code(), Some("build_passed"));
        assert_eq!(record.terminal_reference(), Some("sha-1234567890"));

        // Exact replay of terminal outcome is an immutable no-op
        assert!(
            record
                .complete_succeeded("build_passed", Some("sha-1234567890"))
                .is_ok()
        );

        // Conflicting terminal outcome is rejected
        let conflict_err = record.complete_rejected("build_failed", None).unwrap_err();
        assert_eq!(conflict_err.code(), "conflicting_terminal_result");

        let conflict_code_err = record
            .complete_succeeded("different_code", Some("sha-1234567890"))
            .unwrap_err();
        assert_eq!(conflict_code_err.code(), "conflicting_terminal_result");

        // Claim execution on terminal record returns TerminalReplay
        let replay_outcome = record.claim_execution("exec-run-302").unwrap();
        assert_eq!(
            replay_outcome,
            ClaimOutcome::TerminalReplay {
                state: JournalState::Succeeded,
                terminal_code: "build_passed".to_string(),
                terminal_reference: Some("sha-1234567890".to_string()),
            }
        );
    }

    #[test]
    fn explicit_ambiguous_resolution() {
        let issue = sample_accepted_issue();
        let mut record = JournalRecord::new(issue, SAMPLE_ACCEPTED_AT, SAMPLE_POLICY_REV).unwrap();

        record.claim_execution("exec-run-401").unwrap();
        record.mark_ambiguous().unwrap();
        assert_eq!(record.state(), JournalState::Ambiguous);

        // Standard completion is forbidden from Ambiguous
        let unauth_err = record.complete_succeeded("test", None).unwrap_err();
        assert_eq!(unauth_err.code(), "unauthorized_reconciliation");

        // Explicit trusted reconciliation succeeds
        let observation = TrustedReconciliationObservation::succeeded(
            "verified_audit_clean",
            Some("commit-abcdef123456"),
        );
        record.resolve_trusted_reconciliation(&observation).unwrap();

        assert_eq!(record.state(), JournalState::Succeeded);
        assert_eq!(record.terminal_code(), Some("verified_audit_clean"));
        assert_eq!(record.terminal_reference(), Some("commit-abcdef123456"));
        assert_eq!(record.execution_id(), Some("exec-run-401"));

        // Replay of same observation is immutable no-op
        assert!(record.resolve_trusted_reconciliation(&observation).is_ok());

        // Conflicting observation rejects
        let conflict_obs = TrustedReconciliationObservation::rejected("failed_verification", None);
        let err = record
            .resolve_trusted_reconciliation(&conflict_obs)
            .unwrap_err();
        assert_eq!(err.code(), "conflicting_terminal_result");
    }

    #[test]
    fn malformed_oversized_duplicate_key_journal_rejection() {
        let issue = sample_accepted_issue();
        let record = JournalRecord::new(issue, SAMPLE_ACCEPTED_AT, SAMPLE_POLICY_REV).unwrap();
        let valid_json = record.to_json().unwrap();

        // Malformed JSON
        assert_eq!(
            JournalRecord::from_json("{ not valid json }")
                .unwrap_err()
                .code(),
            "journal_json_malformed"
        );

        // Non-object JSON
        assert_eq!(
            JournalRecord::from_json("[\"not an object\"]")
                .unwrap_err()
                .code(),
            "journal_not_an_object"
        );

        // Oversized JSON (> 64 KiB)
        let oversized = format!(
            "{{\"padding\":\"{}\",{}",
            "x".repeat(MAX_JOURNAL_BYTES),
            &valid_json[1..]
        );
        assert_eq!(
            JournalRecord::from_json(&oversized).unwrap_err().code(),
            "journal_payload_too_large"
        );

        // Duplicate key in journal JSON
        let dup_key_json = valid_json.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        assert_eq!(
            JournalRecord::from_json(&dup_key_json).unwrap_err().code(),
            "journal_json_malformed"
        );

        // Unknown field in journal JSON fails closed
        let unknown_field_json = valid_json.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"unauthorized_passthrough\":true",
            1,
        );
        assert_eq!(
            JournalRecord::from_json(&unknown_field_json)
                .unwrap_err()
                .code(),
            "journal_unknown_field"
        );

        // Depth exceeded (> 32)
        let mut deep = String::new();
        for _ in 0..33 {
            deep.push_str("{\"nested\":");
        }
        deep.push('1');
        for _ in 0..33 {
            deep.push('}');
        }
        assert_eq!(
            JournalRecord::from_json(&deep).unwrap_err().code(),
            "journal_json_depth_exceeded"
        );
    }

    #[test]
    fn inconsistent_state_fields_rejected_on_deserialization() {
        let issue = sample_accepted_issue();
        let record = JournalRecord::new(issue, SAMPLE_ACCEPTED_AT, SAMPLE_POLICY_REV).unwrap();
        let base_json = record.to_json().unwrap();

        // Accepted record with execution_id
        let bad_accepted =
            base_json.replace("\"execution_id\":null", "\"execution_id\":\"exec-01\"");
        assert_eq!(
            JournalRecord::from_json(&bad_accepted).unwrap_err().code(),
            "inconsistent_state_fields"
        );

        // Executing record without execution_id
        let bad_executing = base_json.replace("\"state\":\"accepted\"", "\"state\":\"executing\"");
        assert_eq!(
            JournalRecord::from_json(&bad_executing).unwrap_err().code(),
            "inconsistent_state_fields"
        );

        // Executing record with terminal_code
        let bad_exec_term = bad_executing
            .replace("\"execution_id\":null", "\"execution_id\":\"exec-01\"")
            .replace("\"terminal_code\":null", "\"terminal_code\":\"premature\"");
        assert_eq!(
            JournalRecord::from_json(&bad_exec_term).unwrap_err().code(),
            "inconsistent_state_fields"
        );

        // Succeeded record without terminal_code
        let bad_succeeded = base_json
            .replace("\"state\":\"accepted\"", "\"state\":\"succeeded\"")
            .replace("\"execution_id\":null", "\"execution_id\":\"exec-01\"");
        assert_eq!(
            JournalRecord::from_json(&bad_succeeded).unwrap_err().code(),
            "inconsistent_state_fields"
        );

        // Rejected record without execution_id
        let bad_rejected = base_json
            .replace("\"state\":\"accepted\"", "\"state\":\"rejected\"")
            .replace("\"terminal_code\":null", "\"terminal_code\":\"denied\"");
        assert_eq!(
            JournalRecord::from_json(&bad_rejected).unwrap_err().code(),
            "inconsistent_state_fields"
        );
    }

    #[test]
    fn bounded_fields_validation() {
        let issue = sample_accepted_issue();

        // Invalid accepted_at
        assert_eq!(
            JournalRecord::new(issue.clone(), "not-a-timestamp", SAMPLE_POLICY_REV)
                .unwrap_err()
                .code(),
            "invalid_accepted_at"
        );
        assert_eq!(
            JournalRecord::new(issue.clone(), "2025-02-29T12:00:00Z", SAMPLE_POLICY_REV)
                .unwrap_err()
                .code(),
            "invalid_accepted_at"
        );
        assert_eq!(
            JournalRecord::new(
                issue.clone(),
                "2026-09-05T07:47:52+00:00",
                SAMPLE_POLICY_REV
            )
            .unwrap_err()
            .code(),
            "invalid_accepted_at"
        );

        // Invalid policy_revision (uppercase or wrong length)
        assert_eq!(
            JournalRecord::new(
                issue.clone(),
                SAMPLE_ACCEPTED_AT,
                "4AE216576B054F528C9EDBCFED4A2711BCCAA476"
            )
            .unwrap_err()
            .code(),
            "invalid_policy_revision"
        );
        assert_eq!(
            JournalRecord::new(issue.clone(), SAMPLE_ACCEPTED_AT, "4ae216576b054f52")
                .unwrap_err()
                .code(),
            "invalid_policy_revision"
        );

        // Invalid execution_id
        let mut record =
            JournalRecord::new(issue.clone(), SAMPLE_ACCEPTED_AT, SAMPLE_POLICY_REV).unwrap();
        assert_eq!(
            record.claim_execution("").unwrap_err().code(),
            "invalid_execution_id"
        );
        assert_eq!(
            record
                .claim_execution(&"a".repeat(MAX_EXECUTION_ID_BYTES + 1))
                .unwrap_err()
                .code(),
            "invalid_execution_id"
        );
        assert_eq!(
            record
                .claim_execution("ghp_secretToken123")
                .unwrap_err()
                .code(),
            "invalid_execution_id"
        );
        assert_eq!(
            record
                .claim_execution("github_pat_secret123")
                .unwrap_err()
                .code(),
            "invalid_execution_id"
        );
        assert_eq!(
            record.claim_execution("has space").unwrap_err().code(),
            "invalid_execution_id"
        );

        // Invalid terminal code and reference
        record.claim_execution("exec-valid-01").unwrap();
        assert_eq!(
            record.complete_succeeded("", None).unwrap_err().code(),
            "invalid_terminal_code"
        );
        assert_eq!(
            record
                .complete_succeeded(&"c".repeat(MAX_TERMINAL_CODE_BYTES + 1), None)
                .unwrap_err()
                .code(),
            "invalid_terminal_code"
        );
        assert_eq!(
            record
                .complete_succeeded("valid_code", Some(&"r".repeat(MAX_TERMINAL_REF_BYTES + 1)))
                .unwrap_err()
                .code(),
            "invalid_terminal_reference"
        );
        assert_eq!(
            record
                .complete_succeeded("code\nwith\nnewlines", None)
                .unwrap_err()
                .code(),
            "invalid_terminal_code"
        );
    }

    #[test]
    fn corrupted_canonical_request_rejected_on_deserialization() {
        let issue = sample_accepted_issue();
        let record = JournalRecord::new(issue, SAMPLE_ACCEPTED_AT, SAMPLE_POLICY_REV).unwrap();
        let base_json = record.to_json().unwrap();

        // Canonical request digest mismatch
        let tampered_digest = base_json.replace(
            &record.request_digest(),
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(
            JournalRecord::from_json(&tampered_digest)
                .unwrap_err()
                .code(),
            "canonical_request_digest_mismatch"
        );

        // Canonical request with non-canonical formatting
        let non_canonical = base_json.replace(
            "\"canonical_request\":\"{\\\"operation",
            "\"canonical_request\":\"{ \\\"operation",
        );
        // Note: altering canonical_request also breaks the digest, but even if digest matched it fails not_canonical
        assert!(JournalRecord::from_json(&non_canonical).is_err());
    }
}
