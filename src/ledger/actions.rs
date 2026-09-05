use super::json::{Json, MAX_SAFE_INTEGER, jcs, object_get, object_string, object_u64, sha256_hex};
use std::collections::BTreeSet;
use std::fmt;

pub const MAX_EVENT_BYTES: usize = 256 * 1024; // 256 KiB
pub const MAX_BODY_BYTES: usize = 32 * 1024; // 32 KiB
pub const MAX_JSON_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionOperation {
    GovernanceLedger,
    GovernanceAuditTaskIntegration,
    GithubCiInspect,
    WorkspaceRecipeDispatch,
}

impl ActionOperation {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::GovernanceLedger => "governance.ledger",
            Self::GovernanceAuditTaskIntegration => "governance.audit-task-integration",
            Self::GithubCiInspect => "github.ci.inspect",
            Self::WorkspaceRecipeDispatch => "workspace.recipe.dispatch",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "governance.ledger" => Some(Self::GovernanceLedger),
            "governance.audit-task-integration" => Some(Self::GovernanceAuditTaskIntegration),
            "github.ci.inspect" => Some(Self::GithubCiInspect),
            "workspace.recipe.dispatch" => Some(Self::WorkspaceRecipeDispatch),
            _ => None,
        }
    }
}

impl fmt::Display for ActionOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq<str> for ActionOperation {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for ActionOperation {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionsRequestError {
    pub code: &'static str,
}

impl ActionsRequestError {
    pub const fn new(code: &'static str) -> Self {
        Self { code }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn as_str(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for ActionsRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}

impl std::error::Error for ActionsRequestError {}

impl AsRef<str> for ActionsRequestError {
    fn as_ref(&self) -> &str {
        self.code
    }
}

impl std::ops::Deref for ActionsRequestError {
    type Target = str;
    fn deref(&self) -> &str {
        self.code
    }
}

impl PartialEq<str> for ActionsRequestError {
    fn eq(&self, other: &str) -> bool {
        self.code == other
    }
}

impl PartialEq<&str> for ActionsRequestError {
    fn eq(&self, other: &&str) -> bool {
        self.code == *other
    }
}

impl From<&'static str> for ActionsRequestError {
    fn from(code: &'static str) -> Self {
        Self::new(code)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedIssuePolicy {
    pub repository_id: u64,
    pub full_name: String,
    pub allowed_actor_ids: Vec<u64>,
}

impl TrustedIssuePolicy {
    pub fn new(
        repository_id: u64,
        full_name: impl Into<String>,
        allowed_actor_ids: impl IntoIterator<Item = u64>,
    ) -> Result<Self, ActionsRequestError> {
        let policy = Self {
            repository_id,
            full_name: full_name.into(),
            allowed_actor_ids: allowed_actor_ids.into_iter().collect(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), ActionsRequestError> {
        if self.repository_id == 0 {
            return Err(ActionsRequestError::new("policy_repository_id_zero"));
        }
        if self.full_name.trim().is_empty() {
            return Err(ActionsRequestError::new("policy_full_name_empty"));
        }
        if self.allowed_actor_ids.is_empty() {
            return Err(ActionsRequestError::new("policy_allowed_actor_ids_empty"));
        }
        let mut seen = BTreeSet::new();
        for &actor_id in &self.allowed_actor_ids {
            if actor_id == 0 {
                return Err(ActionsRequestError::new("policy_actor_id_zero"));
            }
            if !seen.insert(actor_id) {
                return Err(ActionsRequestError::new("policy_duplicate_actor_id"));
            }
        }
        Ok(())
    }

    pub fn is_actor_allowed(&self, actor_id: u64) -> bool {
        actor_id > 0 && self.allowed_actor_ids.contains(&actor_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedIssue {
    pub repository_id: u64,
    pub repository_full_name: String,
    pub issue_id: u64,
    pub issue_number: u64,
    pub author_id: u64,
    pub sender_id: u64,
    pub request_id: String,
    pub operation: ActionOperation,
    pub(crate) parameters: Json,
    pub canonical_request: String,
    pub request_digest: String,
}

impl AcceptedIssue {
    pub fn issue_author_id(&self) -> u64 {
        self.author_id
    }

    pub fn repository_name(&self) -> &str {
        &self.repository_full_name
    }

    pub fn operation_name(&self) -> &'static str {
        self.operation.as_str()
    }
}

pub(super) fn check_json_depth(input: &str, max_depth: usize) -> Result<(), ActionsRequestError> {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut chars = input.chars();

    while let Some(ch) = chars.next() {
        if in_string {
            match ch {
                '\\' => {
                    if chars.next().is_none() {
                        return Err(ActionsRequestError::new("malformed_json"));
                    }
                }
                '"' => {
                    in_string = false;
                }
                _ => {}
            }
        } else {
            match ch {
                '"' => {
                    in_string = true;
                }
                '{' | '[' => {
                    depth = depth
                        .checked_add(1)
                        .ok_or_else(|| ActionsRequestError::new("depth_limit_exceeded"))?;
                    if depth > max_depth {
                        return Err(ActionsRequestError::new("depth_limit_exceeded"));
                    }
                }
                '}' | ']' => {
                    if depth == 0 {
                        return Err(ActionsRequestError::new("malformed_json"));
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
    }

    if in_string || depth != 0 {
        return Err(ActionsRequestError::new("malformed_json"));
    }

    Ok(())
}

fn extract_body_json(body: &str) -> Result<&str, ActionsRequestError> {
    let trimmed = body.trim_start();
    if trimmed.is_empty() {
        return Err(ActionsRequestError::new("empty_request_body"));
    }

    if trimmed.starts_with("```") {
        let first_newline = trimmed.find('\n').unwrap_or(trimmed.len());
        let opening_line = &trimmed[..first_newline];
        let info = opening_line.strip_prefix("```").unwrap().trim();
        if !info.eq_ignore_ascii_case("json") {
            return Err(ActionsRequestError::new("invalid_fence_tag"));
        }
        if first_newline == trimmed.len() {
            return Err(ActionsRequestError::new("unterminated_fence"));
        }

        let after_opening = &trimmed[first_newline + 1..];
        let mut offset = 0;
        let mut closing_start = None;
        let mut closing_end = None;

        for line in after_opening.split_inclusive('\n') {
            let line_len = line.len();
            let trimmed_line = line.trim();
            if trimmed_line == "```" {
                if closing_start.is_none() {
                    closing_start = Some(offset);
                    closing_end = Some(offset + line_len);
                } else {
                    return Err(ActionsRequestError::new("multiple_fences_rejected"));
                }
            } else if trimmed_line.starts_with("```") {
                return Err(ActionsRequestError::new("multiple_fences_rejected"));
            }
            offset += line_len;
        }

        let (Some(start), Some(end)) = (closing_start, closing_end) else {
            return Err(ActionsRequestError::new("unterminated_fence"));
        };

        let after_closing = &after_opening[end..];
        if !after_closing.trim().is_empty() {
            return Err(ActionsRequestError::new("prose_after_fence_rejected"));
        }

        let content = &after_opening[..start];
        let content_trimmed = content.trim();
        if content_trimmed.is_empty() {
            return Err(ActionsRequestError::new("empty_request_body"));
        }
        Ok(content_trimmed)
    } else {
        if !trimmed.starts_with('{') {
            return Err(ActionsRequestError::new("prose_before_request_rejected"));
        }
        let content_trimmed = trimmed.trim();
        Ok(content_trimmed)
    }
}

fn validate_json_numbers(value: &Json) -> Result<(), ActionsRequestError> {
    match value {
        Json::Number(n) => {
            if n.contains('.') || n.contains('e') || n.contains('E') || n.contains('+') {
                return Err(ActionsRequestError::new("unsafe_integer"));
            }
            let Ok(num) = n.parse::<i64>() else {
                return Err(ActionsRequestError::new("unsafe_integer"));
            };
            if num.unsigned_abs() > MAX_SAFE_INTEGER as u64 {
                return Err(ActionsRequestError::new("unsafe_integer"));
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

pub fn decode_issue_event(
    event_name: &str,
    event_json: &str,
    policy: &TrustedIssuePolicy,
) -> Result<AcceptedIssue, ActionsRequestError> {
    policy.validate()?;

    if event_name != "issues" {
        return Err(ActionsRequestError::new("unsupported_event_name"));
    }

    if event_json.len() > MAX_EVENT_BYTES {
        return Err(ActionsRequestError::new("event_payload_too_large"));
    }

    check_json_depth(event_json, MAX_JSON_DEPTH)?;

    let event =
        Json::parse(event_json).map_err(|_| ActionsRequestError::new("malformed_event_json"))?;

    let Some(event_obj) = event.as_object() else {
        return Err(ActionsRequestError::new("invalid_event_payload"));
    };

    let Some(action) = object_string(event_obj, "action") else {
        return Err(ActionsRequestError::new("missing_issue_action"));
    };
    if action != "opened" && action != "edited" {
        return Err(ActionsRequestError::new("unsupported_issue_action"));
    }

    let Some(repo) = object_get(event_obj, "repository").and_then(Json::as_object) else {
        return Err(ActionsRequestError::new("missing_repository"));
    };
    let Some(repo_id) = object_u64(repo, "id") else {
        return Err(ActionsRequestError::new("invalid_repository_id"));
    };
    if repo_id != policy.repository_id {
        return Err(ActionsRequestError::new("foreign_repository_id"));
    }
    let Some(repo_full_name) = object_string(repo, "full_name") else {
        return Err(ActionsRequestError::new("missing_repository_name"));
    };
    if repo_full_name != policy.full_name {
        return Err(ActionsRequestError::new("foreign_repository_name"));
    }

    let Some(sender) = object_get(event_obj, "sender").and_then(Json::as_object) else {
        return Err(ActionsRequestError::new("missing_sender"));
    };
    let Some(sender_id) = object_u64(sender, "id") else {
        return Err(ActionsRequestError::new("invalid_sender_id"));
    };
    if sender_id == 0 || !policy.is_actor_allowed(sender_id) {
        return Err(ActionsRequestError::new("unauthorized_sender"));
    }

    let Some(issue) = object_get(event_obj, "issue").and_then(Json::as_object) else {
        return Err(ActionsRequestError::new("missing_issue"));
    };

    if object_get(issue, "pull_request").is_some() {
        return Err(ActionsRequestError::new("pull_request_event_rejected"));
    }

    let Some(issue_id) = object_u64(issue, "id") else {
        return Err(ActionsRequestError::new("invalid_issue_id"));
    };
    if issue_id == 0 {
        return Err(ActionsRequestError::new("invalid_issue_id"));
    }

    let Some(issue_number) = object_u64(issue, "number") else {
        return Err(ActionsRequestError::new("invalid_issue_number"));
    };
    if issue_number == 0 {
        return Err(ActionsRequestError::new("invalid_issue_number"));
    }

    let Some(user) = object_get(issue, "user").and_then(Json::as_object) else {
        return Err(ActionsRequestError::new("missing_issue_author"));
    };
    let Some(author_id) = object_u64(user, "id") else {
        return Err(ActionsRequestError::new("invalid_author_id"));
    };
    if author_id == 0 || !policy.is_actor_allowed(author_id) {
        return Err(ActionsRequestError::new("unauthorized_author"));
    }

    let Some(body) = object_string(issue, "body") else {
        return Err(ActionsRequestError::new("missing_issue_body"));
    };

    if body.len() > MAX_BODY_BYTES {
        return Err(ActionsRequestError::new("request_body_too_large"));
    }

    let request_text = extract_body_json(body)?;
    check_json_depth(request_text, MAX_JSON_DEPTH)?;

    let request_json = Json::parse(request_text)
        .map_err(|_| ActionsRequestError::new("malformed_request_json"))?;

    let Some(request_obj) = request_json.as_object() else {
        return Err(ActionsRequestError::new("request_must_be_object"));
    };

    if request_obj.len() != 4 {
        return Err(ActionsRequestError::new("invalid_request_keys"));
    }

    let Some(schema_version_val) = object_get(request_obj, "schema_version") else {
        return Err(ActionsRequestError::new("invalid_request_keys"));
    };
    let Some(request_id_val) = object_get(request_obj, "request_id") else {
        return Err(ActionsRequestError::new("invalid_request_keys"));
    };
    let Some(operation_val) = object_get(request_obj, "operation") else {
        return Err(ActionsRequestError::new("invalid_request_keys"));
    };
    let Some(parameters_val) = object_get(request_obj, "parameters") else {
        return Err(ActionsRequestError::new("invalid_request_keys"));
    };

    match schema_version_val {
        Json::Number(n) if n == "1" => {}
        _ => return Err(ActionsRequestError::new("invalid_schema_version")),
    }

    let Some(request_id) = request_id_val.as_str() else {
        return Err(ActionsRequestError::new("invalid_request_id"));
    };
    if !(8..=128).contains(&request_id.len()) {
        return Err(ActionsRequestError::new("invalid_request_id"));
    }
    if !request_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ActionsRequestError::new("invalid_request_id"));
    }

    let Some(op_str) = operation_val.as_str() else {
        return Err(ActionsRequestError::new("invalid_operation"));
    };
    let Some(operation) = ActionOperation::parse(op_str) else {
        return Err(ActionsRequestError::new("unknown_operation"));
    };

    if parameters_val.as_object().is_none() {
        return Err(ActionsRequestError::new("parameters_must_be_object"));
    }

    validate_json_numbers(&request_json)?;

    let canonical_request =
        jcs(&request_json).map_err(|_| ActionsRequestError::new("canonicalization_failed"))?;
    let request_digest = sha256_hex(canonical_request.as_bytes());

    Ok(AcceptedIssue {
        repository_id: repo_id,
        repository_full_name: repo_full_name.to_string(),
        issue_id,
        issue_number,
        author_id,
        sender_id,
        request_id: request_id.to_string(),
        operation,
        parameters: parameters_val.clone(),
        canonical_request,
        request_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy() -> TrustedIssuePolicy {
        TrustedIssuePolicy::new(1001, "shockerqt/zach", vec![2001, 2002]).unwrap()
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

    #[test]
    fn unfenced_and_fenced_json_yield_same_canonical_digest() {
        let policy = sample_policy();
        let unfenced_body = SAMPLE_REQUEST_JSON;
        let fenced_body = format!("```json\n{SAMPLE_REQUEST_JSON}\n```");

        let event_unfenced = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            501,
            42,
            unfenced_body,
            false,
        );
        let event_fenced = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            501,
            42,
            &fenced_body,
            false,
        );

        let accepted_unfenced = decode_issue_event("issues", &event_unfenced, &policy).unwrap();
        let accepted_fenced = decode_issue_event("issues", &event_fenced, &policy).unwrap();

        assert_eq!(
            accepted_unfenced.canonical_request,
            accepted_fenced.canonical_request
        );
        assert_eq!(
            accepted_unfenced.request_digest,
            accepted_fenced.request_digest
        );
        assert_eq!(
            accepted_unfenced.operation,
            ActionOperation::GithubCiInspect
        );
        assert_eq!(accepted_unfenced.request_id, "uds007-inspect-build-01");
        assert_eq!(accepted_unfenced.author_id, 2001);
        assert_eq!(accepted_unfenced.sender_id, 2001);
    }

    #[test]
    fn edited_issue_event_is_accepted() {
        let policy = sample_policy();
        let event = make_event(
            "edited",
            1001,
            "shockerqt/zach",
            2002,
            2001,
            501,
            42,
            SAMPLE_REQUEST_JSON,
            false,
        );
        let accepted = decode_issue_event("issues", &event, &policy).unwrap();
        assert_eq!(accepted.author_id, 2001);
        assert_eq!(accepted.sender_id, 2002);
    }

    #[test]
    fn different_requests_differ_in_digest() {
        let policy = sample_policy();
        let req1 = r#"{
  "schema_version": 1,
  "request_id": "req-00000001",
  "operation": "governance.ledger",
  "parameters": { "step": 1 }
}"#;
        let req2 = r#"{
  "schema_version": 1,
  "request_id": "req-00000002",
  "operation": "governance.ledger",
  "parameters": { "step": 1 }
}"#;
        let req3 = r#"{
  "schema_version": 1,
  "request_id": "req-00000001",
  "operation": "governance.ledger",
  "parameters": { "step": 2 }
}"#;

        let ev1 = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            req1,
            false,
        );
        let ev2 = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            req2,
            false,
        );
        let ev3 = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            req3,
            false,
        );

        let acc1 = decode_issue_event("issues", &ev1, &policy).unwrap();
        let acc2 = decode_issue_event("issues", &ev2, &policy).unwrap();
        let acc3 = decode_issue_event("issues", &ev3, &policy).unwrap();

        assert_ne!(acc1.request_digest, acc2.request_digest);
        assert_ne!(acc1.request_digest, acc3.request_digest);
        assert_ne!(acc2.request_digest, acc3.request_digest);
    }

    #[test]
    fn foreign_repository_id_and_name_are_rejected() {
        let policy = sample_policy();
        let ev_foreign_id = make_event(
            "opened",
            9999,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            SAMPLE_REQUEST_JSON,
            false,
        );
        let err = decode_issue_event("issues", &ev_foreign_id, &policy).unwrap_err();
        assert_eq!(err.code(), "foreign_repository_id");

        let ev_foreign_name = make_event(
            "opened",
            1001,
            "other/repo",
            2001,
            2001,
            10,
            1,
            SAMPLE_REQUEST_JSON,
            false,
        );
        let err = decode_issue_event("issues", &ev_foreign_name, &policy).unwrap_err();
        assert_eq!(err.code(), "foreign_repository_name");
    }

    #[test]
    fn unauthorized_sender_and_author_are_rejected() {
        let policy = sample_policy();
        let ev_unauth_sender = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            9999,
            2001,
            10,
            1,
            SAMPLE_REQUEST_JSON,
            false,
        );
        let err = decode_issue_event("issues", &ev_unauth_sender, &policy).unwrap_err();
        assert_eq!(err.code(), "unauthorized_sender");

        let ev_unauth_author = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            9999,
            10,
            1,
            SAMPLE_REQUEST_JSON,
            false,
        );
        let err = decode_issue_event("issues", &ev_unauth_author, &policy).unwrap_err();
        assert_eq!(err.code(), "unauthorized_author");
    }

    #[test]
    fn pr_shaped_event_is_rejected() {
        let policy = sample_policy();
        let ev_pr = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            SAMPLE_REQUEST_JSON,
            true,
        );
        let err = decode_issue_event("issues", &ev_pr, &policy).unwrap_err();
        assert_eq!(err.code(), "pull_request_event_rejected");
    }

    #[test]
    fn changed_and_unsupported_actions_are_rejected() {
        let policy = sample_policy();
        for action in &["closed", "deleted", "reopened", "labeled", "assigned"] {
            let ev = make_event(
                action,
                1001,
                "shockerqt/zach",
                2001,
                2001,
                10,
                1,
                SAMPLE_REQUEST_JSON,
                false,
            );
            let err = decode_issue_event("issues", &ev, &policy).unwrap_err();
            assert_eq!(err.code(), "unsupported_issue_action");
        }

        let ev_wrong_event = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            SAMPLE_REQUEST_JSON,
            false,
        );
        let err = decode_issue_event("pull_request", &ev_wrong_event, &policy).unwrap_err();
        assert_eq!(err.code(), "unsupported_event_name");
    }

    #[test]
    fn malformed_json_in_event_and_body_are_rejected() {
        let policy = sample_policy();
        let err = decode_issue_event("issues", "{ not json }", &policy).unwrap_err();
        assert_eq!(err.code(), "malformed_event_json");

        let ev_bad_body = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            "{ invalid: json }",
            false,
        );
        let err = decode_issue_event("issues", &ev_bad_body, &policy).unwrap_err();
        assert_eq!(err.code(), "malformed_request_json");
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let policy = sample_policy();
        let dup_event = r#"{"action":"opened","action":"opened","repository":{"id":1001,"full_name":"shockerqt/zach"},"sender":{"id":2001},"issue":{"id":1,"number":1,"user":{"id":2001},"body":"{\"schema_version\":1,\"request_id\":\"req-00001\",\"operation\":\"github.ci.inspect\",\"parameters\":{}}"}}"#;
        let err = decode_issue_event("issues", dup_event, &policy).unwrap_err();
        assert_eq!(err.code(), "malformed_event_json");

        let dup_body = r#"{
  "schema_version": 1,
  "schema_version": 1,
  "request_id": "req-00000001",
  "operation": "github.ci.inspect",
  "parameters": {}
}"#;
        let ev_dup_body = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            dup_body,
            false,
        );
        let err = decode_issue_event("issues", &ev_dup_body, &policy).unwrap_err();
        assert_eq!(err.code(), "malformed_request_json");

        let dup_param = r#"{
  "schema_version": 1,
  "request_id": "req-00000001",
  "operation": "github.ci.inspect",
  "parameters": {
    "key": 1,
    "key": 2
  }
}"#;
        let ev_dup_param = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            dup_param,
            false,
        );
        let err = decode_issue_event("issues", &ev_dup_param, &policy).unwrap_err();
        assert_eq!(err.code(), "malformed_request_json");
    }

    #[test]
    fn unknown_operation_and_unknown_fields_are_rejected() {
        let policy = sample_policy();
        let unknown_op = r#"{
  "schema_version": 1,
  "request_id": "req-00000001",
  "operation": "github.ci.run",
  "parameters": {}
}"#;
        let ev = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            unknown_op,
            false,
        );
        let err = decode_issue_event("issues", &ev, &policy).unwrap_err();
        assert_eq!(err.code(), "unknown_operation");

        let extra_field = r#"{
  "schema_version": 1,
  "request_id": "req-00000001",
  "operation": "github.ci.inspect",
  "parameters": {},
  "extra": true
}"#;
        let ev_extra = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            extra_field,
            false,
        );
        let err = decode_issue_event("issues", &ev_extra, &policy).unwrap_err();
        assert_eq!(err.code(), "invalid_request_keys");

        let missing_field = r#"{
  "schema_version": 1,
  "request_id": "req-00000001",
  "operation": "github.ci.inspect"
}"#;
        let ev_missing = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            missing_field,
            false,
        );
        let err = decode_issue_event("issues", &ev_missing, &policy).unwrap_err();
        assert_eq!(err.code(), "invalid_request_keys");
    }

    #[test]
    fn nonobject_parameters_are_rejected() {
        let policy = sample_policy();
        for param in &["[1, 2, 3]", "\"string\"", "123", "true", "null"] {
            let body = format!(
                r#"{{
  "schema_version": 1,
  "request_id": "req-00000001",
  "operation": "github.ci.inspect",
  "parameters": {param}
}}"#
            );
            let ev = make_event(
                "opened",
                1001,
                "shockerqt/zach",
                2001,
                2001,
                10,
                1,
                &body,
                false,
            );
            let err = decode_issue_event("issues", &ev, &policy).unwrap_err();
            assert_eq!(err.code(), "parameters_must_be_object");
        }
    }

    #[test]
    fn limits_on_event_body_and_depth_are_enforced() {
        let policy = sample_policy();

        // Event size limit (256 KiB)
        let large_padding = "a".repeat(MAX_EVENT_BYTES);
        let large_event = format!(
            r#"{{"action":"opened","repository":{{"id":1001,"full_name":"shockerqt/zach"}},"sender":{{"id":2001}},"issue":{{"id":1,"number":1,"user":{{"id":2001}},"body":"{SAMPLE_REQUEST_JSON}"}},"padding":"{large_padding}"}}"#
        );
        assert!(large_event.len() > MAX_EVENT_BYTES);
        let err = decode_issue_event("issues", &large_event, &policy).unwrap_err();
        assert_eq!(err.code(), "event_payload_too_large");

        // Body size limit (32 KiB)
        let large_body_padding = "x".repeat(MAX_BODY_BYTES);
        let large_body = format!(
            r#"{{
  "schema_version": 1,
  "request_id": "req-00000001",
  "operation": "github.ci.inspect",
  "parameters": {{ "pad": "{large_body_padding}" }}
}}"#
        );
        assert!(large_body.len() > MAX_BODY_BYTES);
        let ev_large_body = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            &large_body,
            false,
        );
        let err = decode_issue_event("issues", &ev_large_body, &policy).unwrap_err();
        assert_eq!(err.code(), "request_body_too_large");

        // Depth limit > 32 in request body
        let mut deep_open = String::new();
        let mut deep_close = String::new();
        for _ in 0..33 {
            deep_open.push_str("{\"k\":");
            deep_close.push('}');
        }
        let deep_body = format!(
            r#"{{
  "schema_version": 1,
  "request_id": "req-00000001",
  "operation": "github.ci.inspect",
  "parameters": {deep_open}1{deep_close}
}}"#
        );
        let ev_deep_body = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            &deep_body,
            false,
        );
        let err = decode_issue_event("issues", &ev_deep_body, &policy).unwrap_err();
        assert_eq!(err.code(), "depth_limit_exceeded");
    }

    #[test]
    fn delimiters_inside_strings_do_not_confuse_depth_or_fence_parsing() {
        let policy = sample_policy();
        let tricky_string = r#"delimiters: { [ } ] \" \n \\ \t ```json ``` "#;
        let unfenced_body = format!(
            r#"{{
  "schema_version": 1,
  "request_id": "req-delimiters-01",
  "operation": "github.ci.inspect",
  "parameters": {{
    "data": "{tricky_string}"
  }}
}}"#
        );
        let fenced_body = format!("```json\n{unfenced_body}\n```");

        let ev_unfenced = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            &unfenced_body,
            false,
        );
        let ev_fenced = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            &fenced_body,
            false,
        );

        let acc_unfenced = decode_issue_event("issues", &ev_unfenced, &policy).unwrap();
        let acc_fenced = decode_issue_event("issues", &ev_fenced, &policy).unwrap();

        assert_eq!(acc_unfenced.canonical_request, acc_fenced.canonical_request);
        assert_eq!(acc_unfenced.request_digest, acc_fenced.request_digest);
    }

    #[test]
    fn policy_configuration_rejects_empty_zero_and_duplicate_ids() {
        assert_eq!(
            TrustedIssuePolicy::new(0, "shockerqt/zach", vec![2001])
                .unwrap_err()
                .code(),
            "policy_repository_id_zero"
        );
        assert_eq!(
            TrustedIssuePolicy::new(1001, "   ", vec![2001])
                .unwrap_err()
                .code(),
            "policy_full_name_empty"
        );
        assert_eq!(
            TrustedIssuePolicy::new(1001, "shockerqt/zach", Vec::new())
                .unwrap_err()
                .code(),
            "policy_allowed_actor_ids_empty"
        );
        assert_eq!(
            TrustedIssuePolicy::new(1001, "shockerqt/zach", vec![2001, 0])
                .unwrap_err()
                .code(),
            "policy_actor_id_zero"
        );
        assert_eq!(
            TrustedIssuePolicy::new(1001, "shockerqt/zach", vec![2001, 2001])
                .unwrap_err()
                .code(),
            "policy_duplicate_actor_id"
        );

        // Also test invalid policy passed directly to decode_issue_event
        let bad_policy = TrustedIssuePolicy {
            repository_id: 0,
            full_name: "shockerqt/zach".into(),
            allowed_actor_ids: vec![2001],
        };
        let ev = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            SAMPLE_REQUEST_JSON,
            false,
        );
        assert_eq!(
            decode_issue_event("issues", &ev, &bad_policy)
                .unwrap_err()
                .code(),
            "policy_repository_id_zero"
        );
    }

    #[test]
    fn unsafe_integers_and_floats_are_rejected() {
        let policy = sample_policy();
        let float_body = r#"{
  "schema_version": 1,
  "request_id": "req-00000001",
  "operation": "github.ci.inspect",
  "parameters": { "val": 1.23 }
}"#;
        let ev_float = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            float_body,
            false,
        );
        let err = decode_issue_event("issues", &ev_float, &policy).unwrap_err();
        assert_eq!(err.code(), "unsafe_integer");

        let unsafe_int_body = r#"{
  "schema_version": 1,
  "request_id": "req-00000001",
  "operation": "github.ci.inspect",
  "parameters": { "val": 9007199254740992 }
}"#;
        let ev_unsafe_int = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            unsafe_int_body,
            false,
        );
        let err = decode_issue_event("issues", &ev_unsafe_int, &policy).unwrap_err();
        assert_eq!(err.code(), "unsafe_integer");
    }

    #[test]
    fn prose_and_multiple_fences_are_rejected() {
        let policy = sample_policy();

        let prose_before = format!("Leading prose here\n```json\n{SAMPLE_REQUEST_JSON}\n```");
        let ev1 = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            &prose_before,
            false,
        );
        assert_eq!(
            decode_issue_event("issues", &ev1, &policy)
                .unwrap_err()
                .code(),
            "prose_before_request_rejected"
        );

        let prose_after = format!("```json\n{SAMPLE_REQUEST_JSON}\n```\nTrailing prose here");
        let ev2 = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            &prose_after,
            false,
        );
        assert_eq!(
            decode_issue_event("issues", &ev2, &policy)
                .unwrap_err()
                .code(),
            "prose_after_fence_rejected"
        );

        let multi_fence =
            format!("```json\n{SAMPLE_REQUEST_JSON}\n```\n```json\n{SAMPLE_REQUEST_JSON}\n```");
        let ev3 = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            &multi_fence,
            false,
        );
        assert_eq!(
            decode_issue_event("issues", &ev3, &policy)
                .unwrap_err()
                .code(),
            "multiple_fences_rejected"
        );

        let unfenced_prose_before = format!("Hello\n{SAMPLE_REQUEST_JSON}");
        let ev4 = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            &unfenced_prose_before,
            false,
        );
        assert_eq!(
            decode_issue_event("issues", &ev4, &policy)
                .unwrap_err()
                .code(),
            "prose_before_request_rejected"
        );
    }

    #[test]
    fn request_id_format_is_enforced() {
        let policy = sample_policy();
        for short_id in &["a", "1234567"] {
            let body = format!(
                r#"{{
  "schema_version": 1,
  "request_id": "{short_id}",
  "operation": "github.ci.inspect",
  "parameters": {{}}
}}"#
            );
            let ev = make_event(
                "opened",
                1001,
                "shockerqt/zach",
                2001,
                2001,
                10,
                1,
                &body,
                false,
            );
            assert_eq!(
                decode_issue_event("issues", &ev, &policy)
                    .unwrap_err()
                    .code(),
                "invalid_request_id"
            );
        }

        let long_id = "a".repeat(129);
        let body = format!(
            r#"{{
  "schema_version": 1,
  "request_id": "{long_id}",
  "operation": "github.ci.inspect",
  "parameters": {{}}
}}"#
        );
        let ev = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            &body,
            false,
        );
        assert_eq!(
            decode_issue_event("issues", &ev, &policy)
                .unwrap_err()
                .code(),
            "invalid_request_id"
        );

        let invalid_char_id = "req!0000001";
        let body = format!(
            r#"{{
  "schema_version": 1,
  "request_id": "{invalid_char_id}",
  "operation": "github.ci.inspect",
  "parameters": {{}}
}}"#
        );
        let ev = make_event(
            "opened",
            1001,
            "shockerqt/zach",
            2001,
            2001,
            10,
            1,
            &body,
            false,
        );
        assert_eq!(
            decode_issue_event("issues", &ev, &policy)
                .unwrap_err()
                .code(),
            "invalid_request_id"
        );
    }

    #[test]
    fn all_four_recognized_operations_succeed() {
        let policy = sample_policy();
        let ops = [
            ("governance.ledger", ActionOperation::GovernanceLedger),
            (
                "governance.audit-task-integration",
                ActionOperation::GovernanceAuditTaskIntegration,
            ),
            ("github.ci.inspect", ActionOperation::GithubCiInspect),
            (
                "workspace.recipe.dispatch",
                ActionOperation::WorkspaceRecipeDispatch,
            ),
        ];

        for (op_str, op_enum) in ops {
            let body = format!(
                r#"{{
  "schema_version": 1,
  "request_id": "uds007-inspect-build-01",
  "operation": "{op_str}",
  "parameters": {{}}
}}"#
            );
            let ev = make_event(
                "opened",
                1001,
                "shockerqt/zach",
                2001,
                2001,
                10,
                1,
                &body,
                false,
            );
            let accepted = decode_issue_event("issues", &ev, &policy).unwrap();
            assert_eq!(accepted.operation, op_enum);
            assert_eq!(accepted.operation.as_str(), op_str);
        }
    }
}
