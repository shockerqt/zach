use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::v2::isolation;
use crate::v2::now_epoch;
use crate::v2::store::{AttemptAuditRecord, StageAttemptRecord, V2Store};

pub const MAX_AUDIT_JSON_BYTES: usize = 32 * 1024;
pub const MAX_TRACE_FILE_READ_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_AUDIT_TOOL_CALL_SUMMARIES: usize = 64;
pub const MAX_AUDIT_DIGEST_ERROR_SIGNATURES: usize = 10;
pub const MAX_AUDIT_DIGEST_ERROR_SIGNATURE_LEN: usize = 160;
pub const MAX_AUDIT_IDENTIFIER_LEN: usize = 64;
const MAX_TRACE_DISCOVERY_DEPTH: usize = 6;

pub const FORBIDDEN_DURABLE_KEYS: &[&str] = &[
    "prompt",
    "prompts",
    "response",
    "responses",
    "credential",
    "credentials",
    "secret",
    "secrets",
    "token",
    "tokens",
    "password",
    "passwords",
    "file_content",
    "raw_content",
    "raw_payload",
    "raw_command",
    "command_output",
    "raw_command_output",
    "raw_output",
    "stdout",
    "stderr",
    "transcript",
    "transcripts",
    "raw_transcript",
    "conversation",
    "messages",
];

pub const AUDIT_DIGEST_COUNTERS: &[&str] = &[
    "stage_attempts_count",
    "rework_count",
    "retry_count",
    "tool_error_count",
    "blocked_events",
    "supervisor_errors",
    "edit_compile_fail_loops",
];

pub const AUDIT_DIGEST_ALLOWED_KEYS: &[&str] = &[
    "schema_version",
    "task_id",
    "executor",
    "generated_at",
    "stage_attempts_count",
    "rework_count",
    "retry_count",
    "tool_error_count",
    "blocked_events",
    "supervisor_errors",
    "edit_compile_fail_loops",
    "check_divergence",
    "token_usage",
    "error_signatures",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditedToolCall {
    pub tool_name: String,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttemptAuditReport {
    pub schema_version: u32,
    pub attempt_id: String,
    pub task_id: String,
    pub stage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    pub turn_count: u64,
    pub tool_call_count: u64,
    pub tool_error_count: u64,
    pub edit_compile_fail_loops: u64,
    pub redundant_read_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
    pub check_divergence: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub error_signatures: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<AuditedToolCall>,
    pub created_epoch: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditDigestTokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskAuditDigest {
    pub schema_version: u32,
    pub task_id: String,
    pub executor: String,
    pub generated_at: String,
    pub stage_attempts_count: u64,
    pub rework_count: u64,
    pub retry_count: u64,
    pub tool_error_count: u64,
    pub blocked_events: u64,
    pub supervisor_errors: u64,
    pub edit_compile_fail_loops: u64,
    pub check_divergence: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_usage: Option<AuditDigestTokenUsage>,
    #[serde(default)]
    pub error_signatures: Vec<String>,
}

pub fn format_utc_iso8601(epoch_secs: i64) -> String {
    let secs = epoch_secs.max(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(m <= 2);
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn starts_at_word_boundary(s: &str, byte_idx: usize) -> bool {
    if byte_idx == 0 {
        return true;
    }
    s[..byte_idx]
        .chars()
        .next_back()
        .is_none_or(|c| !is_word_char(c))
}

fn ends_at_word_boundary(s: &str, byte_idx: usize) -> bool {
    if byte_idx >= s.len() {
        return true;
    }
    s[byte_idx..]
        .chars()
        .next()
        .is_none_or(|c| !is_word_char(c))
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let mut out = String::new();
    for ch in s.chars().take(max_chars) {
        out.push(ch);
    }
    out
}

fn collapse_whitespace(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_space = false;
    for ch in raw.chars() {
        let mapped = if matches!(ch, '\r' | '\n' | '\t' | '\0') || ch.is_control() {
            ' '
        } else {
            ch
        };
        if mapped.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(mapped);
            prev_space = false;
        }
    }
    out.trim().to_owned()
}

fn match_raw_prompt_prefix_len(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    let rest = &line[idx..];
    let lower = rest.to_ascii_lowercase();
    const PREFIXES: &[&str] = &[
        "prompt",
        "response",
        "stdout",
        "stderr",
        "command_output",
        "command-output",
        "command output",
        "commandoutput",
        "raw_output",
        "raw-output",
        "raw output",
        "rawoutput",
        "raw_payload",
        "raw-payload",
        "raw payload",
        "rawpayload",
        "raw_content",
        "raw-content",
        "raw content",
        "rawcontent",
    ];
    for prefix in PREFIXES {
        if lower.starts_with(prefix) {
            let mut after = idx + prefix.len();
            while after < bytes.len() && bytes[after].is_ascii_whitespace() {
                after += 1;
            }
            if after < bytes.len() && matches!(bytes[after], b':' | b'=') {
                after += 1;
                while after < bytes.len() && bytes[after].is_ascii_whitespace() {
                    after += 1;
                }
                return Some(after);
            }
        }
    }
    None
}

fn strip_leading_raw_prompt_prefixes(input: &str) -> String {
    let mut current = input;
    while let Some(advance) = match_raw_prompt_prefix_len(current) {
        current = &current[advance..];
    }
    current.trim().to_owned()
}

fn match_private_key_header_end(s: &str, start: usize) -> Option<usize> {
    let rest = &s[start..];
    if !rest.starts_with("-----BEGIN ") {
        return None;
    }
    let marker = "PRIVATE KEY-----";
    let marker_rel = rest.find(marker)?;
    // Guard against spanning unrelated prose between distant dashes.
    let between = &rest["-----BEGIN ".len()..marker_rel];
    if between.len() > 32
        || !between
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b' ' || b == b'-')
    {
        return None;
    }
    let header_end = start + marker_rel + marker.len();
    // If a matching END block exists, redact through the END marker as well.
    if let Some(end_rel) = s[header_end..].find("-----END ") {
        let after_end = &s[header_end + end_rel..];
        if let Some(end_marker_rel) = after_end.find(marker) {
            return Some(header_end + end_rel + end_marker_rel + marker.len());
        }
    }
    Some(header_end)
}

fn match_authorization_bearer_end(s: &str, start: usize, allow_bare_bearer: bool) -> Option<usize> {
    if !starts_at_word_boundary(s, start) {
        return None;
    }
    let rest = &s[start..];
    let bytes = rest.as_bytes();
    if rest.len() >= 13 && rest[..13].eq_ignore_ascii_case("authorization") {
        let mut i = 13;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b':' {
            return None;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i + 6 <= bytes.len() && rest[i..i + 6].eq_ignore_ascii_case("bearer") {
            i += 6;
            let ws_start = i;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i == ws_start || i >= bytes.len() {
                return None;
            }
            let tok_start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i > tok_start {
                return Some(start + i);
            }
        }
        return None;
    }

    if allow_bare_bearer && rest.len() >= 7 && rest[..6].eq_ignore_ascii_case("bearer") {
        let mut i = 6;
        let ws_start = i;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i == ws_start || i >= bytes.len() {
            return None;
        }
        let tok_start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric()
                || matches!(bytes[i], b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-'))
        {
            i += 1;
        }
        if i - tok_start >= 8 {
            return Some(start + i);
        }
    }
    None
}

fn match_credential_assignment_end(s: &str, start: usize, include_extra: bool) -> Option<usize> {
    if !starts_at_word_boundary(s, start) {
        return None;
    }
    let rest = &s[start..];
    let bytes = rest.as_bytes();
    const BASE_KEYS: &[&str] = &[
        "aws_secret_access_key",
        "aws-secret-access-key",
        "awssecretaccesskey",
        "client_secret",
        "client-secret",
        "clientsecret",
        "access_token",
        "access-token",
        "accesstoken",
        "api_key",
        "api-key",
        "apikey",
        "password",
        "passwd",
        "pwd",
    ];
    const EXTRA_KEYS: &[&str] = &["auth_token", "auth-token", "authtoken", "secret"];

    let mut matched_len = None;
    for key in BASE_KEYS {
        if rest.len() >= key.len() && rest[..key.len()].eq_ignore_ascii_case(key) {
            matched_len = Some(key.len());
            break;
        }
    }
    if matched_len.is_none() && include_extra {
        for key in EXTRA_KEYS {
            if rest.len() >= key.len() && rest[..key.len()].eq_ignore_ascii_case(key) {
                matched_len = Some(key.len());
                break;
            }
        }
    }
    let mut i = matched_len?;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || !matches!(bytes[i], b':' | b'=') {
        return None;
    }
    i += 1;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let val_start = i;
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i > val_start { Some(start + i) } else { None }
}

fn match_credential_uri_end(s: &str, start: usize) -> Option<usize> {
    if !starts_at_word_boundary(s, start) {
        return None;
    }
    let rest = &s[start..];
    let bytes = rest.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return None;
    }
    let mut i = 1;
    while i < bytes.len()
        && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'+' | b'.' | b'-'))
    {
        i += 1;
    }
    if i + 3 > bytes.len() || &bytes[i..i + 3] != b"://" {
        return None;
    }
    i += 3;
    let user_start = i;
    while i < bytes.len()
        && !bytes[i].is_ascii_whitespace()
        && !matches!(bytes[i], b':' | b'/' | b'@')
    {
        i += 1;
    }
    if i == user_start || i >= bytes.len() || bytes[i] != b':' {
        return None;
    }
    i += 1;
    let pass_start = i;
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() && !matches!(bytes[i], b'/' | b'@') {
        i += 1;
    }
    if i == pass_start || i >= bytes.len() || bytes[i] != b'@' {
        return None;
    }
    i += 1;
    let host_start = i;
    while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i > host_start {
        Some(start + i)
    } else {
        None
    }
}

fn match_github_token_end(s: &str, start: usize) -> Option<usize> {
    if !starts_at_word_boundary(s, start) {
        return None;
    }
    let rest = &s[start..];
    let bytes = rest.as_bytes();
    let prefix_len = if rest.starts_with("github_pat_") {
        "github_pat_".len()
    } else if bytes.len() >= 4
        && bytes[0] == b'g'
        && bytes[1] == b'h'
        && matches!(bytes[2], b'p' | b'o' | b'u' | b's' | b'r')
        && bytes[3] == b'_'
    {
        4
    } else {
        return None;
    };
    let mut i = prefix_len;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    if i - prefix_len >= 20 && ends_at_word_boundary(s, start + i) {
        Some(start + i)
    } else {
        None
    }
}

fn match_aws_access_key_end(s: &str, start: usize) -> Option<usize> {
    if !starts_at_word_boundary(s, start) {
        return None;
    }
    let rest = &s[start..];
    let bytes = rest.as_bytes();
    if bytes.len() < 20 || !(rest.starts_with("AKIA") || rest.starts_with("ASIA")) {
        return None;
    }
    if bytes[4..20]
        .iter()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        && ends_at_word_boundary(s, start + 20)
    {
        Some(start + 20)
    } else {
        None
    }
}

fn match_slack_token_end(s: &str, start: usize) -> Option<usize> {
    if !starts_at_word_boundary(s, start) {
        return None;
    }
    let rest = &s[start..];
    let bytes = rest.as_bytes();
    if bytes.len() < 15
        || !rest.starts_with("xox")
        || !matches!(bytes[3], b'b' | b'a' | b'p' | b'r' | b's')
        || bytes[4] != b'-'
    {
        return None;
    }
    let mut i = 5;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-') {
        i += 1;
    }
    if i - 5 >= 10 && ends_at_word_boundary(s, start + i) {
        Some(start + i)
    } else {
        None
    }
}

fn match_jwt_end(s: &str, start: usize) -> Option<usize> {
    if !starts_at_word_boundary(s, start) {
        return None;
    }
    let rest = &s[start..];
    if !rest.starts_with("eyJ") {
        return None;
    }
    let bytes = rest.as_bytes();
    let is_b64u = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    let mut i = 3;
    let p1_start = i;
    while i < bytes.len() && is_b64u(bytes[i]) {
        i += 1;
    }
    if i - p1_start < 8 || i >= bytes.len() || bytes[i] != b'.' {
        return None;
    }
    i += 1;
    let p2_start = i;
    while i < bytes.len() && is_b64u(bytes[i]) {
        i += 1;
    }
    if i - p2_start < 8 || i >= bytes.len() || bytes[i] != b'.' {
        return None;
    }
    i += 1;
    let p3_start = i;
    while i < bytes.len() && is_b64u(bytes[i]) {
        i += 1;
    }
    if i - p3_start >= 8 && ends_at_word_boundary(s, start + i) {
        Some(start + i)
    } else {
        None
    }
}

fn match_openai_secret_end(s: &str, start: usize) -> Option<usize> {
    if !starts_at_word_boundary(s, start) {
        return None;
    }
    let rest = &s[start..];
    if !rest.starts_with("sk-") {
        return None;
    }
    let bytes = rest.as_bytes();
    let mut i = 3;
    while i < bytes.len()
        && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'-')
    {
        i += 1;
    }
    if i - 3 >= 20 && ends_at_word_boundary(s, start + i) {
        Some(start + i)
    } else {
        None
    }
}

fn match_google_api_key_end(s: &str, start: usize) -> Option<usize> {
    if !starts_at_word_boundary(s, start) {
        return None;
    }
    let rest = &s[start..];
    if !rest.starts_with("AIza") {
        return None;
    }
    let bytes = rest.as_bytes();
    let mut i = 4;
    while i < bytes.len()
        && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'-')
    {
        i += 1;
    }
    if i - 4 >= 20 && ends_at_word_boundary(s, start + i) {
        Some(start + i)
    } else {
        None
    }
}

fn sensitive_pattern_hits(text: &str) -> Vec<&'static str> {
    let mut hits = Vec::new();
    let mut push_hit = |name: &'static str| {
        if !hits.contains(&name) {
            hits.push(name);
        }
    };

    for line in text.lines() {
        if match_raw_prompt_prefix_len(line).is_some() {
            push_hit("raw-prompt");
            break;
        }
    }

    for (idx, _) in text.char_indices() {
        if match_private_key_header_end(text, idx).is_some() {
            push_hit("private-key");
        }
        if match_credential_assignment_end(text, idx, false).is_some() {
            push_hit("credential-assignment");
        }
        if match_authorization_bearer_end(text, idx, false).is_some() {
            push_hit("authorization-bearer");
        }
        if match_github_token_end(text, idx).is_some() {
            push_hit("github-token");
        }
        if match_aws_access_key_end(text, idx).is_some() {
            push_hit("aws-access-key");
        }
        if match_slack_token_end(text, idx).is_some() {
            push_hit("slack-token");
        }
        if match_jwt_end(text, idx).is_some() {
            push_hit("jwt");
        }
        if match_openai_secret_end(text, idx).is_some() {
            push_hit("openai-style-secret");
        }
        if match_credential_uri_end(text, idx).is_some() {
            push_hit("credential-uri");
        }
    }

    hits
}

fn redact_sensitive_spans(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut idx = 0usize;
    while idx < input.len() {
        if let Some(end) = match_private_key_header_end(input, idx) {
            out.push_str("[REDACTED_PRIVATE_KEY]");
            idx = end;
            continue;
        }
        if let Some(end) = match_authorization_bearer_end(input, idx, true) {
            out.push_str("[REDACTED_AUTH]");
            idx = end;
            continue;
        }
        if let Some(end) = match_credential_assignment_end(input, idx, true) {
            out.push_str("[REDACTED_CREDENTIAL]");
            idx = end;
            continue;
        }
        if let Some(end) = match_credential_uri_end(input, idx) {
            out.push_str("[REDACTED_URI]");
            idx = end;
            continue;
        }
        if let Some(end) = match_github_token_end(input, idx)
            .or_else(|| match_aws_access_key_end(input, idx))
            .or_else(|| match_slack_token_end(input, idx))
            .or_else(|| match_jwt_end(input, idx))
            .or_else(|| match_openai_secret_end(input, idx))
            .or_else(|| match_google_api_key_end(input, idx))
        {
            out.push_str("[REDACTED_TOKEN]");
            idx = end;
            continue;
        }
        let Some(ch) = input[idx..].chars().next() else {
            break;
        };
        out.push(ch);
        idx += ch.len_utf8();
    }
    out
}

pub fn redact_adr004_text(raw: &str, max_chars: usize) -> String {
    let collapsed = collapse_whitespace(raw);
    let stripped = strip_leading_raw_prompt_prefixes(&collapsed);
    let redacted = redact_sensitive_spans(&stripped);
    let restrip = strip_leading_raw_prompt_prefixes(&redacted);
    let mut bounded = truncate_chars(restrip.trim(), max_chars);
    if !sensitive_pattern_hits(&bounded).is_empty() {
        let re_redacted = strip_leading_raw_prompt_prefixes(&redact_sensitive_spans(&bounded));
        bounded = truncate_chars(re_redacted.trim(), max_chars);
    }
    bounded.trim().to_owned()
}

pub fn validate_adr004_value(value: &Value, where_path: &str) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    collect_adr004_problems(value, where_path, &mut problems);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

fn collect_adr004_problems(value: &Value, where_path: &str, problems: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let lower = key.to_ascii_lowercase();
                if FORBIDDEN_DURABLE_KEYS.contains(&lower.as_str()) {
                    problems.push(format!("{where_path}: forbidden durable field '{key}'"));
                }
                collect_adr004_problems(child, &format!("{where_path}.{key}"), problems);
            }
        }
        Value::Array(items) => {
            for (idx, child) in items.iter().enumerate() {
                collect_adr004_problems(child, &format!("{where_path}[{idx}]"), problems);
            }
        }
        Value::String(s) => {
            for category in sensitive_pattern_hits(s) {
                problems.push(format!(
                    "{where_path}: prohibited durable content category {category}"
                ));
            }
        }
        _ => {}
    }
}

fn read_regular_file_nofollow(path: &Path, max_bytes: u64) -> Result<String, String> {
    isolation::reject_symlink_components(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("metadata {}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("not a regular file: {}", path.display()));
    }
    let mut buf = Vec::new();
    file.take(max_bytes)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn discover_trace_files(
    root: &Path,
    predicate: &dyn Fn(&str) -> bool,
    max_depth: usize,
) -> Vec<PathBuf> {
    if isolation::reject_symlink_components(root).is_err() {
        return Vec::new();
    }
    let Ok(meta) = fs::symlink_metadata(root) else {
        return Vec::new();
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let path = entry.path();
            if ft.is_dir() {
                if depth < max_depth {
                    stack.push((path, depth + 1));
                }
            } else if ft.is_file()
                && let Some(name) = entry.file_name().to_str()
                && predicate(name)
            {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

#[derive(Debug, Default)]
struct TraceMetrics {
    turn_count: u64,
    tool_call_count: u64,
    tool_error_count: u64,
    edit_compile_fail_loops: u64,
    redundant_read_count: u64,
    cached_input_tokens: Option<u64>,
    reasoning_tokens: Option<u64>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    total_tokens: Option<u64>,
    saw_passing_check: bool,
    last_check_passed: Option<bool>,
    error_code: Option<String>,
    error_signatures: Vec<String>,
    tool_calls: Vec<AuditedToolCall>,
    pending_edit: bool,
    seen_reads: BTreeSet<String>,
}

impl TraceMetrics {
    fn add_tokens(
        &mut self,
        input: Option<u64>,
        output: Option<u64>,
        total: Option<u64>,
        cached: Option<u64>,
        reasoning: Option<u64>,
    ) {
        if let Some(v) = input {
            self.input_tokens = Some(self.input_tokens.unwrap_or(0).saturating_add(v));
        }
        if let Some(v) = output {
            self.output_tokens = Some(self.output_tokens.unwrap_or(0).saturating_add(v));
        }
        if let Some(v) = total {
            self.total_tokens = Some(self.total_tokens.unwrap_or(0).saturating_add(v));
        } else if let (Some(i), Some(o)) = (input, output) {
            self.total_tokens = Some(
                self.total_tokens
                    .unwrap_or(0)
                    .saturating_add(i.saturating_add(o)),
            );
        }
        if let Some(v) = cached {
            self.cached_input_tokens =
                Some(self.cached_input_tokens.unwrap_or(0).saturating_add(v));
        }
        if let Some(v) = reasoning {
            self.reasoning_tokens = Some(self.reasoning_tokens.unwrap_or(0).saturating_add(v));
        }
    }

    fn set_cumulative_tokens(
        &mut self,
        input: Option<u64>,
        output: Option<u64>,
        total: Option<u64>,
        cached: Option<u64>,
        reasoning: Option<u64>,
    ) {
        if let Some(v) = input {
            self.input_tokens = Some(self.input_tokens.unwrap_or(0).max(v));
        }
        if let Some(v) = output {
            self.output_tokens = Some(self.output_tokens.unwrap_or(0).max(v));
        }
        if let Some(v) = total {
            self.total_tokens = Some(self.total_tokens.unwrap_or(0).max(v));
        } else if let (Some(i), Some(o)) = (input, output) {
            self.total_tokens = Some(self.total_tokens.unwrap_or(0).max(i.saturating_add(o)));
        }
        if let Some(v) = cached {
            self.cached_input_tokens = Some(self.cached_input_tokens.unwrap_or(0).max(v));
        }
        if let Some(v) = reasoning {
            self.reasoning_tokens = Some(self.reasoning_tokens.unwrap_or(0).max(v));
        }
    }

    fn push_error_signature(&mut self, raw: &str) {
        let sig = redact_adr004_text(raw, MAX_AUDIT_DIGEST_ERROR_SIGNATURE_LEN);
        if !sig.is_empty()
            && !self
                .error_signatures
                .iter()
                .any(|existing| existing == &sig)
            && self.error_signatures.len() < MAX_AUDIT_DIGEST_ERROR_SIGNATURES
        {
            self.error_signatures.push(sig);
        }
    }

    fn set_error_code_if_empty(&mut self, raw: &str) {
        if self.error_code.is_some() {
            return;
        }
        let clean = redact_adr004_text(raw, MAX_AUDIT_DIGEST_ERROR_SIGNATURE_LEN);
        if !clean.is_empty() {
            self.error_code = Some(clean);
        }
    }

    fn record_tool_call(
        &mut self,
        tool_name: &str,
        category: &str,
        target_path: Option<String>,
        read_span: Option<String>,
        exit_code: Option<i32>,
        is_error: bool,
    ) {
        self.tool_call_count = self.tool_call_count.saturating_add(1);
        if is_error {
            self.tool_error_count = self.tool_error_count.saturating_add(1);
        }
        let clean_name = redact_adr004_text(tool_name, MAX_AUDIT_IDENTIFIER_LEN);
        let clean_path = target_path
            .map(|p| sanitize_path_summary(&p))
            .filter(|p| !p.is_empty());

        match category {
            "edit" => {
                self.pending_edit = true;
                if let Some(ref p) = clean_path {
                    let prefix = format!("{p}::");
                    self.seen_reads.retain(|k| !k.starts_with(&prefix));
                } else {
                    self.seen_reads.clear();
                }
            }
            "read" => {
                if let Some(ref p) = clean_path {
                    let span = read_span.unwrap_or_else(|| "*".to_owned());
                    let key = format!("{p}::{span}");
                    if !self.seen_reads.insert(key) {
                        self.redundant_read_count = self.redundant_read_count.saturating_add(1);
                    }
                }
            }
            "compile_check" => {
                if is_error {
                    self.last_check_passed = Some(false);
                    if self.pending_edit {
                        self.edit_compile_fail_loops =
                            self.edit_compile_fail_loops.saturating_add(1);
                        self.pending_edit = false;
                    }
                } else {
                    self.saw_passing_check = true;
                    self.last_check_passed = Some(true);
                    self.pending_edit = false;
                }
            }
            _ => {}
        }

        if self.tool_calls.len() < MAX_AUDIT_TOOL_CALL_SUMMARIES {
            self.tool_calls.push(AuditedToolCall {
                tool_name: if clean_name.is_empty() {
                    "unknown".to_owned()
                } else {
                    clean_name
                },
                category: category.to_owned(),
                target_path: clean_path,
                exit_code,
                is_error,
            });
        }
    }

    fn record_deferred_tool_error(&mut self, category: Option<&str>) {
        self.tool_error_count = self.tool_error_count.saturating_add(1);
        if category == Some("compile_check") {
            self.last_check_passed = Some(false);
            if self.pending_edit {
                self.edit_compile_fail_loops = self.edit_compile_fail_loops.saturating_add(1);
                self.pending_edit = false;
            }
        }
    }

    fn merge_max(&mut self, other: TraceMetrics) {
        self.turn_count = self.turn_count.max(other.turn_count);
        self.tool_call_count = self.tool_call_count.max(other.tool_call_count);
        self.tool_error_count = self.tool_error_count.max(other.tool_error_count);
        self.edit_compile_fail_loops = self
            .edit_compile_fail_loops
            .max(other.edit_compile_fail_loops);
        self.redundant_read_count = self.redundant_read_count.max(other.redundant_read_count);
        self.cached_input_tokens = opt_max(self.cached_input_tokens, other.cached_input_tokens);
        self.reasoning_tokens = opt_max(self.reasoning_tokens, other.reasoning_tokens);
        self.input_tokens = opt_max(self.input_tokens, other.input_tokens);
        self.output_tokens = opt_max(self.output_tokens, other.output_tokens);
        self.total_tokens = opt_max(self.total_tokens, other.total_tokens);
        self.saw_passing_check = self.saw_passing_check || other.saw_passing_check;
        if other.last_check_passed.is_some()
            && (self.last_check_passed.is_none() || other.tool_call_count > self.tool_call_count)
        {
            self.last_check_passed = other.last_check_passed;
        }
        if self.error_code.is_none() {
            self.error_code = other.error_code;
        }
        for sig in other.error_signatures {
            self.push_error_signature(&sig);
        }
        if other.tool_calls.len() > self.tool_calls.len() {
            self.tool_calls = other.tool_calls;
        }
    }
}

fn opt_max(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

fn sanitize_path_summary(raw: &str) -> String {
    let trimmed = raw.trim().trim_matches(|c| matches!(c, '\'' | '"'));
    redact_adr004_text(trimmed, 128)
}

#[derive(Debug, Default)]
struct ExtractedUsage {
    input: Option<u64>,
    output: Option<u64>,
    total: Option<u64>,
    cached: Option<u64>,
    reasoning: Option<u64>,
}

struct PendingToolCall {
    id: String,
    name: String,
    category: &'static str,
    path: Option<String>,
    span: Option<String>,
}

fn extract_usage_fields(usage: &serde_json::Map<String, Value>) -> ExtractedUsage {
    let input = usage
        .get("input_tokens")
        .or_else(|| usage.get("prompt_tokens"))
        .or_else(|| usage.get("promptTokenCount"))
        .and_then(Value::as_u64);
    let output = usage
        .get("output_tokens")
        .or_else(|| usage.get("completion_tokens"))
        .or_else(|| usage.get("candidatesTokenCount"))
        .and_then(Value::as_u64);
    let total = usage
        .get("total_tokens")
        .or_else(|| usage.get("totalTokenCount"))
        .and_then(Value::as_u64);
    let cached = usage
        .get("cached_input_tokens")
        .or_else(|| usage.get("cache_read_input_tokens"))
        .or_else(|| usage.get("cachedContentTokenCount"))
        .and_then(Value::as_u64)
        .or_else(|| {
            usage
                .get("input_tokens_details")
                .and_then(|d| d.get("cached_tokens"))
                .and_then(Value::as_u64)
        });
    let reasoning = usage
        .get("reasoning_output_tokens")
        .or_else(|| usage.get("reasoning_tokens"))
        .or_else(|| usage.get("thoughts_token_count"))
        .or_else(|| usage.get("thoughtsTokenCount"))
        .and_then(Value::as_u64)
        .or_else(|| {
            usage
                .get("output_tokens_details")
                .and_then(|d| d.get("reasoning_tokens"))
                .and_then(Value::as_u64)
        });
    ExtractedUsage {
        input,
        output,
        total,
        cached,
        reasoning,
    }
}

fn command_value_to_string(val: &Value) -> Option<String> {
    if let Some(s) = val.as_str() {
        let trimmed = s.trim();
        return (!trimmed.is_empty()).then(|| trimmed.to_owned());
    }
    if let Some(arr) = val.as_array() {
        let parts: Vec<&str> = arr.iter().filter_map(Value::as_str).collect();
        if !parts.is_empty() {
            return Some(parts.join(" "));
        }
    }
    None
}

fn unwrap_shell_command(cmd: &str) -> &str {
    let trimmed = cmd.trim();
    for prefix in [
        "bash -lc ",
        "bash -c ",
        "/bin/bash -lc ",
        "/bin/bash -c ",
        "sh -c ",
        "/bin/sh -c ",
    ] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return rest.trim().trim_matches(|c| matches!(c, '\'' | '"'));
        }
    }
    trimmed
}

fn classify_shell_command(raw_cmd: &str) -> (&'static str, Option<String>, Option<String>) {
    let inner = unwrap_shell_command(raw_cmd);
    let lower = inner.to_ascii_lowercase();

    const COMPILE_CHECK_MARKERS: &[&str] = &[
        "cargo test",
        "cargo check",
        "cargo clippy",
        "cargo build",
        "cargo fmt --check",
        "rustc ",
        "pytest",
        "npm test",
        "npm run build",
        "npm run lint",
        "npm run test",
        "pnpm test",
        "yarn test",
        "make test",
        "make lint",
        "make build",
        "ws-task-selftest",
        "go test",
        "mypy",
        "ruff check",
    ];
    if COMPILE_CHECK_MARKERS.iter().any(|m| lower.contains(m)) {
        return ("compile_check", None, None);
    }

    if lower.contains("apply_patch")
        || lower.contains("sed -i")
        || lower.contains("perl -pi")
        || lower.contains("tee ")
        || inner.contains(" > ")
        || inner.contains(" >> ")
    {
        return ("edit", extract_shell_edit_target(inner), None);
    }

    let tokens: Vec<&str> = inner.split_whitespace().collect();
    if let Some(&first) = tokens.first() {
        let bin = Path::new(first)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(first);
        if matches!(bin, "cat" | "head" | "tail" | "nl") {
            let file_arg = tokens
                .iter()
                .skip(1)
                .rev()
                .find(|tok| !tok.starts_with('-') && !tok.chars().all(|c| c.is_ascii_digit()))
                .copied();
            if let Some(path) = file_arg {
                return ("read", Some(path.to_owned()), None);
            }
        } else if bin == "sed" && tokens.contains(&"-n") {
            let span = tokens
                .iter()
                .skip(1)
                .find(|tok| {
                    let s = tok.trim_matches(|c| matches!(c, '\'' | '"'));
                    s.ends_with('p') && s.chars().any(|c| c.is_ascii_digit())
                })
                .map(|s| s.trim_matches(|c| matches!(c, '\'' | '"')).to_owned());
            let file_arg = tokens
                .iter()
                .skip(1)
                .rev()
                .find(|tok| !tok.starts_with('-'))
                .copied();
            if let Some(path) = file_arg {
                return ("read", Some(path.to_owned()), span);
            }
        }
    }

    ("other", None, None)
}

fn extract_shell_edit_target(cmd: &str) -> Option<String> {
    if let Some(idx) = cmd.find(" > ").or_else(|| cmd.find(" >> ")) {
        let after = cmd[idx..].trim_start_matches([' ', '>']);
        let target = after.split_whitespace().next()?;
        if !target.is_empty() && !target.starts_with('&') && target != "/dev/null" {
            return Some(target.to_owned());
        }
    }
    let tokens: Vec<&str> = cmd.split_whitespace().collect();
    if tokens.first().is_some_and(|t| *t == "sed") && tokens.iter().any(|t| t.starts_with("-i")) {
        return tokens
            .iter()
            .rev()
            .find(|t| !t.starts_with('-'))
            .map(|s| (*s).to_owned());
    }
    None
}

fn extract_arg_path_and_span(args: &Value) -> (Option<String>, Option<String>) {
    let obj = match args {
        Value::Object(map) => Some(map.clone()),
        Value::String(s) => serde_json::from_str::<serde_json::Map<String, Value>>(s).ok(),
        _ => None,
    };
    let Some(map) = obj else {
        return (None, None);
    };
    let path = map
        .get("Path")
        .or_else(|| map.get("path"))
        .or_else(|| map.get("file_path"))
        .or_else(|| map.get("AbsolutePath"))
        .or_else(|| map.get("TargetFile"))
        .or_else(|| map.get("target_file"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let start = map
        .get("StartLine")
        .or_else(|| map.get("start_line"))
        .or_else(|| map.get("offset"))
        .and_then(Value::as_u64);
    let end = map
        .get("EndLine")
        .or_else(|| map.get("end_line"))
        .or_else(|| map.get("limit"))
        .and_then(Value::as_u64);
    let span = match (start, end) {
        (Some(s), Some(e)) => Some(format!("{s}-{e}")),
        (Some(s), None) => Some(format!("{s}-")),
        (None, Some(e)) => Some(format!("-{e}")),
        (None, None) => None,
    };
    (path, span)
}

fn extract_arg_command(args: &Value) -> Option<String> {
    let obj = match args {
        Value::Object(map) => Some(map.clone()),
        Value::String(s) => serde_json::from_str::<serde_json::Map<String, Value>>(s).ok(),
        _ => None,
    };
    let map = obj?;
    map.get("CommandLine")
        .or_else(|| map.get("command"))
        .or_else(|| map.get("cmd"))
        .and_then(command_value_to_string)
}

fn classify_named_tool(
    tool_name: &str,
    args: Option<&Value>,
) -> (&'static str, Option<String>, Option<String>) {
    let lower = tool_name.to_ascii_lowercase();
    let short = lower.rsplit(':').next().unwrap_or(&lower);
    let (arg_path, arg_span) = args.map(extract_arg_path_and_span).unwrap_or((None, None));

    if matches!(
        short,
        "read_file" | "view_file" | "read" | "open_file" | "view_file_outline" | "view_code_item"
    ) {
        return ("read", arg_path, arg_span);
    }
    if matches!(
        short,
        "edit_file"
            | "write_file"
            | "write_to_file"
            | "replace_file_content"
            | "multi_replace_file_content"
            | "apply_patch"
            | "patch_apply"
            | "file_change"
            | "create_file"
    ) {
        return ("edit", arg_path, None);
    }
    if matches!(
        short,
        "run_command"
            | "execute_command"
            | "shell"
            | "bash"
            | "command_execution"
            | "local_shell_call"
            | "exec_command"
    ) {
        if let Some(cmd) = args.and_then(extract_arg_command) {
            return classify_shell_command(&cmd);
        }
        return ("other", None, None);
    }
    if lower.starts_with("mcp:") || lower.starts_with("mcp__") {
        return ("mcp", arg_path, None);
    }
    ("other", arg_path, arg_span)
}

fn parse_trace_content(content: &str) -> TraceMetrics {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return TraceMetrics::default();
    }

    // Check for single-object AGY worker.mjs JSON envelope first.
    if trimmed.starts_with('{')
        && let Ok(val) = serde_json::from_str::<Value>(trimmed)
        && let Some(obj) = val.as_object()
        && is_agy_envelope(obj)
    {
        return parse_agy_envelope(obj);
    }

    let mut metrics = TraceMetrics::default();
    let mut pending_codex_items: BTreeMap<String, Value> = BTreeMap::new();
    let mut pending_rollout_calls: BTreeMap<String, PendingToolCall> = BTreeMap::new();
    let mut pending_stream_tools: Vec<PendingToolCall> = Vec::new();
    let mut last_tool_category: Option<&'static str> = None;
    let mut saw_cumulative_rollout_tokens = false;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(obj) = val.as_object() else {
            continue;
        };

        let event_type = obj.get("type").and_then(Value::as_str).unwrap_or("");
        match event_type {
            // --- Codex JSONL ---
            "turn.completed" => {
                metrics.turn_count = metrics.turn_count.saturating_add(1);
                if let Some(usage) = obj.get("usage").and_then(Value::as_object) {
                    let u = extract_usage_fields(usage);
                    metrics.add_tokens(u.input, u.output, u.total, u.cached, u.reasoning);
                }
            }
            "turn.failed" => {
                metrics.turn_count = metrics.turn_count.saturating_add(1);
                if let Some(err) = obj.get("error").and_then(Value::as_object) {
                    if let Some(code) = err.get("code").and_then(Value::as_str) {
                        metrics.set_error_code_if_empty(code);
                        metrics.push_error_signature(code);
                    }
                    if let Some(msg) = err.get("message").and_then(Value::as_str) {
                        metrics.set_error_code_if_empty(msg);
                        metrics.push_error_signature(msg);
                    }
                } else if let Some(msg) = obj.get("message").and_then(Value::as_str) {
                    metrics.set_error_code_if_empty(msg);
                    metrics.push_error_signature(msg);
                }
            }
            "error" => {
                if let Some(code) = obj
                    .get("code")
                    .or_else(|| obj.get("error").and_then(|e| e.get("code")))
                    .and_then(Value::as_str)
                {
                    metrics.set_error_code_if_empty(code);
                    metrics.push_error_signature(code);
                }
                if let Some(msg) = obj
                    .get("message")
                    .or_else(|| obj.get("error").and_then(|e| e.get("message")))
                    .and_then(Value::as_str)
                {
                    metrics.set_error_code_if_empty(msg);
                    metrics.push_error_signature(msg);
                }
            }
            "item.started" => {
                if let Some(item) = obj.get("item")
                    && let Some(id) = item.get("id").and_then(Value::as_str)
                {
                    pending_codex_items.insert(id.to_owned(), item.clone());
                }
            }
            "item.completed" => {
                if let Some(item) = obj.get("item") {
                    if let Some(id) = item.get("id").and_then(Value::as_str) {
                        pending_codex_items.remove(id);
                    }
                    process_codex_item(&mut metrics, item);
                }
            }
            // --- Codex rollout-*.jsonl ---
            "event_msg" => {
                if let Some(payload) = obj.get("payload").and_then(Value::as_object)
                    && payload.get("type").and_then(Value::as_str) == Some("token_count")
                    && let Some(info) = payload.get("info").and_then(Value::as_object)
                {
                    if let Some(total_usage) =
                        info.get("total_token_usage").and_then(Value::as_object)
                    {
                        saw_cumulative_rollout_tokens = true;
                        let u = extract_usage_fields(total_usage);
                        metrics.set_cumulative_tokens(
                            u.input,
                            u.output,
                            u.total,
                            u.cached,
                            u.reasoning,
                        );
                    } else if !saw_cumulative_rollout_tokens
                        && let Some(last_usage) =
                            info.get("last_token_usage").and_then(Value::as_object)
                    {
                        let u = extract_usage_fields(last_usage);
                        metrics.add_tokens(u.input, u.output, u.total, u.cached, u.reasoning);
                    }
                }
            }
            "response_item" => {
                if let Some(payload) = obj.get("payload").and_then(Value::as_object) {
                    let ptype = payload.get("type").and_then(Value::as_str).unwrap_or("");
                    match ptype {
                        "message"
                            if payload.get("role").and_then(Value::as_str) == Some("assistant") =>
                        {
                            metrics.turn_count = metrics.turn_count.saturating_add(1);
                        }
                        "function_call" | "custom_tool_call" | "local_shell_call" => {
                            let name = payload
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or(ptype)
                                .to_owned();
                            let args = payload
                                .get("arguments")
                                .or_else(|| payload.get("input"))
                                .or_else(|| payload.get("action"));
                            let (category, path, span) = if ptype == "local_shell_call" {
                                payload
                                    .get("action")
                                    .and_then(|a| a.get("command"))
                                    .and_then(command_value_to_string)
                                    .map(|c| classify_shell_command(&c))
                                    .unwrap_or(("other", None, None))
                            } else {
                                classify_named_tool(&name, args)
                            };
                            if let Some(call_id) = payload.get("call_id").and_then(Value::as_str) {
                                pending_rollout_calls.insert(
                                    call_id.to_owned(),
                                    PendingToolCall {
                                        id: call_id.to_owned(),
                                        name,
                                        category,
                                        path,
                                        span,
                                    },
                                );
                            } else {
                                metrics.record_tool_call(&name, category, path, span, None, false);
                            }
                        }
                        "function_call_output"
                        | "custom_tool_call_output"
                        | "local_shell_call_output" => {
                            let (exit_code, is_error) = parse_rollout_output_status(payload);
                            if let Some(call_id) = payload.get("call_id").and_then(Value::as_str)
                                && let Some(call) = pending_rollout_calls.remove(call_id)
                            {
                                metrics.record_tool_call(
                                    &call.name,
                                    call.category,
                                    call.path,
                                    call.span,
                                    exit_code,
                                    is_error,
                                );
                            } else if is_error {
                                metrics.record_deferred_tool_error(None);
                            }
                        }
                        _ => {}
                    }
                }
            }
            // --- AGY stream-json ---
            "assistant" => {
                metrics.turn_count = metrics.turn_count.saturating_add(1);
                if let Some(turn) = obj
                    .get("num_turns")
                    .or_else(|| obj.get("turn"))
                    .and_then(Value::as_u64)
                {
                    metrics.turn_count = metrics.turn_count.max(turn);
                }
                if let Some(usage) = obj.get("usage").and_then(Value::as_object) {
                    let u = extract_usage_fields(usage);
                    metrics.add_tokens(u.input, u.output, u.total, u.cached, u.reasoning);
                }
            }
            "tool_use" | "tool_call" => {
                let name = obj
                    .get("name")
                    .or_else(|| obj.get("tool_name"))
                    .or_else(|| obj.get("tool"))
                    .and_then(Value::as_str)
                    .unwrap_or("tool");
                let args = obj
                    .get("input")
                    .or_else(|| obj.get("arguments"))
                    .or_else(|| obj.get("args"));
                let (category, path, span) = classify_named_tool(name, args);
                let exit_code = obj
                    .get("exit_code")
                    .and_then(Value::as_i64)
                    .map(|v| v as i32);
                let has_outcome = exit_code.is_some()
                    || obj.get("is_error").is_some()
                    || obj.get("status").is_some();
                last_tool_category = Some(category);
                if !has_outcome
                    && let Some(id) = obj
                        .get("id")
                        .or_else(|| obj.get("tool_use_id"))
                        .or_else(|| obj.get("call_id"))
                        .and_then(Value::as_str)
                {
                    pending_stream_tools.push(PendingToolCall {
                        id: id.to_owned(),
                        name: name.to_owned(),
                        category,
                        path,
                        span,
                    });
                } else {
                    let is_error = is_value_error(obj, exit_code);
                    metrics.record_tool_call(name, category, path, span, exit_code, is_error);
                }
            }
            "tool_result" => {
                let exit_code = obj
                    .get("exit_code")
                    .and_then(Value::as_i64)
                    .map(|v| v as i32);
                let is_error = is_value_error(obj, exit_code);
                if let Some(id) = obj
                    .get("tool_use_id")
                    .or_else(|| obj.get("call_id"))
                    .and_then(Value::as_str)
                    && let Some(pos) = pending_stream_tools.iter().position(|c| c.id == id)
                {
                    for call in pending_stream_tools.drain(..pos) {
                        metrics.record_tool_call(
                            &call.name,
                            call.category,
                            call.path,
                            call.span,
                            None,
                            false,
                        );
                    }
                    let call = pending_stream_tools.remove(0);
                    metrics.record_tool_call(
                        &call.name,
                        call.category,
                        call.path,
                        call.span,
                        exit_code,
                        is_error,
                    );
                } else if is_error {
                    metrics.record_deferred_tool_error(last_tool_category);
                }
            }
            "result" => {
                if let Some(turns) = obj
                    .get("num_turns")
                    .or_else(|| obj.get("turns"))
                    .and_then(Value::as_u64)
                {
                    metrics.turn_count = metrics.turn_count.max(turns);
                }
                if let Some(usage) = obj.get("usage").and_then(Value::as_object) {
                    let u = extract_usage_fields(usage);
                    metrics.set_cumulative_tokens(
                        u.input,
                        u.output,
                        u.total,
                        u.cached,
                        u.reasoning,
                    );
                }
                if is_value_error(obj, None)
                    && let Some(msg) = obj
                        .get("error")
                        .and_then(Value::as_str)
                        .or_else(|| obj.get("message").and_then(Value::as_str))
                {
                    metrics.set_error_code_if_empty(msg);
                    metrics.push_error_signature(msg);
                }
            }
            // --- AGY gemini-home/**/transcript.jsonl ---
            "PLANNER_RESPONSE" => {
                metrics.turn_count = metrics.turn_count.saturating_add(1);
                if let Some(usage) = obj.get("usage").and_then(Value::as_object) {
                    let u = extract_usage_fields(usage);
                    metrics.add_tokens(u.input, u.output, u.total, u.cached, u.reasoning);
                }
                let step_error = obj.get("status").and_then(Value::as_str).is_some_and(|s| {
                    s.eq_ignore_ascii_case("error") || s.eq_ignore_ascii_case("failed")
                });
                let mut had_tool_calls = false;
                if let Some(calls) = obj.get("tool_calls").and_then(Value::as_array) {
                    for call in calls {
                        had_tool_calls = true;
                        let name = call
                            .get("name")
                            .or_else(|| call.get("tool_name"))
                            .or_else(|| call.get("tool"))
                            .and_then(Value::as_str)
                            .unwrap_or("tool");
                        let args = call
                            .get("arguments")
                            .or_else(|| call.get("args"))
                            .or_else(|| call.get("input"));
                        let (category, path, span) = classify_named_tool(name, args);
                        let exit_code = call
                            .get("exit_code")
                            .and_then(Value::as_i64)
                            .map(|v| v as i32);
                        let call_err = call
                            .as_object()
                            .is_some_and(|m| is_value_error(m, exit_code));
                        last_tool_category = Some(category);
                        metrics.record_tool_call(name, category, path, span, exit_code, call_err);
                    }
                }
                if step_error && !had_tool_calls {
                    metrics.tool_error_count = metrics.tool_error_count.saturating_add(1);
                }
            }
            _ => {
                // Generic AGY transcript step (e.g., TOOL_RESULT / CODE_ACTION / RUN_COMMAND) or stream-json with `tool`/`usage`.
                if let Some(usage) = obj.get("usage").and_then(Value::as_object) {
                    let u = extract_usage_fields(usage);
                    metrics.add_tokens(u.input, u.output, u.total, u.cached, u.reasoning);
                }
                if let Some(calls) = obj.get("tool_calls").and_then(Value::as_array) {
                    for call in calls {
                        let name = call
                            .get("name")
                            .or_else(|| call.get("tool_name"))
                            .and_then(Value::as_str)
                            .unwrap_or("tool");
                        let args = call
                            .get("arguments")
                            .or_else(|| call.get("args"))
                            .or_else(|| call.get("input"));
                        let (category, path, span) = classify_named_tool(name, args);
                        let exit_code = call
                            .get("exit_code")
                            .and_then(Value::as_i64)
                            .map(|v| v as i32);
                        let is_err = call
                            .as_object()
                            .is_some_and(|m| is_value_error(m, exit_code));
                        last_tool_category = Some(category);
                        metrics.record_tool_call(name, category, path, span, exit_code, is_err);
                    }
                } else if obj.get("tool").is_some() || obj.get("tool_name").is_some() {
                    let name = obj
                        .get("tool_name")
                        .or_else(|| obj.get("tool"))
                        .and_then(Value::as_str)
                        .unwrap_or("tool");
                    let args = obj
                        .get("input")
                        .or_else(|| obj.get("arguments"))
                        .or_else(|| obj.get("args"));
                    let (category, path, span) = classify_named_tool(name, args);
                    let exit_code = obj
                        .get("exit_code")
                        .and_then(Value::as_i64)
                        .map(|v| v as i32);
                    let is_err = is_value_error(obj, exit_code);
                    last_tool_category = Some(category);
                    metrics.record_tool_call(name, category, path, span, exit_code, is_err);
                } else if is_value_error(obj, None)
                    && (event_type.contains("TOOL")
                        || event_type.contains("COMMAND")
                        || obj.get("step_index").is_some())
                {
                    metrics.record_deferred_tool_error(last_tool_category);
                    if let Some(msg) = obj
                        .get("error")
                        .and_then(Value::as_str)
                        .or_else(|| obj.get("error_code").and_then(Value::as_str))
                    {
                        metrics.set_error_code_if_empty(msg);
                        metrics.push_error_signature(msg);
                    }
                }
            }
        }
    }

    // Flush any uncompleted Codex item.started entries or unpaired rollout tool calls.
    for (_, item) in pending_codex_items {
        process_codex_item(&mut metrics, &item);
    }
    for (_, call) in pending_rollout_calls {
        metrics.record_tool_call(&call.name, call.category, call.path, call.span, None, false);
    }
    for call in pending_stream_tools {
        metrics.record_tool_call(&call.name, call.category, call.path, call.span, None, false);
    }

    metrics
}

fn is_agy_envelope(obj: &serde_json::Map<String, Value>) -> bool {
    if obj.contains_key("type") {
        return false;
    }
    obj.contains_key("execution_succeeded")
        || obj.contains_key("diagnostic")
        || obj.contains_key("budget")
        || obj.contains_key("process_status")
        || (obj.contains_key("usage")
            && (obj.contains_key("status") || obj.contains_key("attempt")))
}

fn parse_agy_envelope(obj: &serde_json::Map<String, Value>) -> TraceMetrics {
    let mut metrics = TraceMetrics::default();
    if let Some(usage) = obj.get("usage").and_then(Value::as_object) {
        let u = extract_usage_fields(usage);
        metrics.set_cumulative_tokens(u.input, u.output, u.total, u.cached, u.reasoning);
    }
    let turns = obj
        .get("budget")
        .and_then(|b| b.get("model_calls_used"))
        .and_then(Value::as_u64)
        .or_else(|| obj.get("attempt").and_then(Value::as_u64))
        .or_else(|| obj.get("num_turns").and_then(Value::as_u64))
        .unwrap_or(1);
    metrics.turn_count = turns;

    let status_err = obj
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|s| s.eq_ignore_ascii_case("error") || s.eq_ignore_ascii_case("failed"));
    let exec_failed = obj.get("execution_succeeded").and_then(Value::as_bool) == Some(false);
    if status_err || exec_failed {
        let code = obj
            .get("diagnostic")
            .and_then(|d| d.get("code"))
            .and_then(Value::as_str)
            .or_else(|| obj.get("error_code").and_then(Value::as_str));
        let summary = obj
            .get("diagnostic")
            .and_then(|d| d.get("summary"))
            .and_then(Value::as_str)
            .or_else(|| obj.get("summary").and_then(Value::as_str))
            .or_else(|| obj.get("message").and_then(Value::as_str));
        if let Some(c) = code {
            metrics.set_error_code_if_empty(c);
        }
        match (code, summary) {
            (Some(c), Some(s)) => metrics.push_error_signature(&format!("{c}: {s}")),
            (Some(c), None) => metrics.push_error_signature(c),
            (None, Some(s)) => {
                metrics.set_error_code_if_empty(s);
                metrics.push_error_signature(s);
            }
            (None, None) => {}
        }
    }
    metrics
}

fn process_codex_item(metrics: &mut TraceMetrics, item: &Value) {
    let Some(obj) = item.as_object() else {
        return;
    };
    let item_type = obj.get("type").and_then(Value::as_str).unwrap_or("");
    match item_type {
        "command_execution" => {
            let cmd = obj
                .get("command")
                .or_else(|| obj.get("cmd"))
                .and_then(command_value_to_string)
                .unwrap_or_default();
            let (category, path, span) = classify_shell_command(&cmd);
            let exit_code = obj
                .get("exit_code")
                .and_then(Value::as_i64)
                .map(|v| v as i32);
            let is_error = exit_code.is_some_and(|c| c != 0)
                || obj.get("status").and_then(Value::as_str).is_some_and(|s| {
                    matches!(
                        s.to_ascii_lowercase().as_str(),
                        "failed" | "error" | "declined"
                    )
                });
            metrics.record_tool_call(
                "command_execution",
                category,
                path,
                span,
                exit_code,
                is_error,
            );
        }
        "mcp_tool_call" => {
            let server = obj.get("server").and_then(Value::as_str).unwrap_or("");
            let tool = obj
                .get("tool")
                .or_else(|| obj.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("mcp");
            let tool_name = if server.is_empty() {
                format!("mcp:{tool}")
            } else {
                format!("mcp:{server}/{tool}")
            };
            let is_error = obj.get("error").is_some_and(|v| !v.is_null())
                || obj
                    .get("status")
                    .and_then(Value::as_str)
                    .is_some_and(|s| matches!(s.to_ascii_lowercase().as_str(), "failed" | "error"));
            let (path, _) = obj
                .get("arguments")
                .map(extract_arg_path_and_span)
                .unwrap_or((None, None));
            metrics.record_tool_call(&tool_name, "mcp", path, None, None, is_error);
        }
        "file_change" | "patch_apply" => {
            let path = obj
                .get("changes")
                .and_then(Value::as_array)
                .and_then(|arr| arr.first())
                .and_then(|entry| {
                    entry
                        .get("path")
                        .and_then(Value::as_str)
                        .or_else(|| entry.as_str())
                })
                .or_else(|| obj.get("path").and_then(Value::as_str))
                .map(ToOwned::to_owned);
            let is_error = obj
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|s| matches!(s.to_ascii_lowercase().as_str(), "failed" | "error"));
            metrics.record_tool_call(item_type, "edit", path, None, None, is_error);
        }
        _ => {}
    }
}

fn parse_rollout_output_status(payload: &serde_json::Map<String, Value>) -> (Option<i32>, bool) {
    let mut exit_code = payload
        .get("exit_code")
        .and_then(Value::as_i64)
        .map(|v| v as i32);
    let mut is_error = is_value_error(payload, exit_code);
    if exit_code.is_none()
        && let Some(output_str) = payload.get("output").and_then(Value::as_str)
    {
        if let Ok(parsed) = serde_json::from_str::<Value>(output_str)
            && let Some(code) = parsed
                .get("metadata")
                .and_then(|m| m.get("exit_code"))
                .or_else(|| parsed.get("exit_code"))
                .and_then(Value::as_i64)
        {
            exit_code = Some(code as i32);
            if code != 0 {
                is_error = true;
            }
        } else if let Some(rest) = output_str.split("Exit code:").nth(1)
            && let Some(num) = rest.split_whitespace().next()
            && let Ok(code) = num.parse::<i32>()
        {
            exit_code = Some(code);
            if code != 0 {
                is_error = true;
            }
        }
    }
    (exit_code, is_error)
}

fn is_value_error(obj: &serde_json::Map<String, Value>, exit_code: Option<i32>) -> bool {
    if exit_code.is_some_and(|c| c != 0) {
        return true;
    }
    if obj.get("is_error").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    if obj.get("status").and_then(Value::as_str).is_some_and(|s| {
        matches!(
            s.to_ascii_lowercase().as_str(),
            "error" | "failed" | "declined"
        )
    }) {
        return true;
    }
    false
}

fn read_json_object_nofollow(path: &Path) -> Option<serde_json::Map<String, Value>> {
    let text = read_regular_file_nofollow(path, MAX_TRACE_FILE_READ_BYTES).ok()?;
    serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|v| v.as_object().cloned())
}

fn indicates_check_failure(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.starts_with("check '")
        || lower.starts_with("failed to run check '")
        || lower.contains("check_failed")
        || lower.contains("check failed")
        || lower.contains("verification check")
}

pub fn extract_attempt_audit(attempt_dir: &Path) -> Result<AttemptAuditReport, String> {
    isolation::reject_symlink_components(attempt_dir)?;
    let dir_meta = fs::symlink_metadata(attempt_dir)
        .map_err(|e| format!("stat {}: {e}", attempt_dir.display()))?;
    if dir_meta.file_type().is_symlink() || !dir_meta.is_dir() {
        return Err(format!(
            "attempt_dir is not a real directory: {}",
            attempt_dir.display()
        ));
    }

    let manifest = read_json_object_nofollow(&attempt_dir.join("manifest.json"));
    let result_json = read_json_object_nofollow(&attempt_dir.join("result.json"));
    let harvest_json = read_json_object_nofollow(&attempt_dir.join("harvest.json"));
    let supervisor_err =
        read_regular_file_nofollow(&attempt_dir.join("supervisor-error.log"), 256 * 1024).ok();

    let dir_name = attempt_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    let attempt_id = manifest
        .as_ref()
        .and_then(|m| m.get("attempt_id").and_then(Value::as_str))
        .or_else(|| {
            result_json
                .as_ref()
                .and_then(|r| r.get("attempt_id").and_then(Value::as_str))
        })
        .unwrap_or(dir_name);
    let task_id = manifest
        .as_ref()
        .and_then(|m| m.get("task_id").and_then(Value::as_str))
        .or_else(|| {
            result_json
                .as_ref()
                .and_then(|r| r.get("task_id").and_then(Value::as_str))
        })
        .unwrap_or("UNKNOWN");
    let stage = manifest
        .as_ref()
        .and_then(|m| {
            m.get("route")
                .and_then(|r| r.get("stage"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            result_json
                .as_ref()
                .and_then(|r| r.get("stage").and_then(Value::as_str))
        })
        .unwrap_or("unknown");
    let harness = manifest
        .as_ref()
        .and_then(|m| {
            m.get("route")
                .and_then(|r| r.get("family"))
                .and_then(Value::as_str)
        })
        .map(|s| redact_adr004_text(s, MAX_AUDIT_IDENTIFIER_LEN))
        .filter(|s| !s.is_empty());

    let mut combined = TraceMetrics::default();
    if let Ok(stdout_text) =
        read_regular_file_nofollow(&attempt_dir.join("stdout.jsonl"), MAX_TRACE_FILE_READ_BYTES)
    {
        combined = parse_trace_content(&stdout_text);
    }

    let codex_rollouts = discover_trace_files(
        &attempt_dir.join("codex-home"),
        &|name| name.starts_with("rollout-") && name.ends_with(".jsonl"),
        MAX_TRACE_DISCOVERY_DEPTH,
    );
    let gemini_transcripts = discover_trace_files(
        &attempt_dir.join("gemini-home"),
        &|name| name == "transcript.jsonl",
        MAX_TRACE_DISCOVERY_DEPTH,
    );

    let mut aux_combined = TraceMetrics::default();
    for path in codex_rollouts.iter().chain(gemini_transcripts.iter()) {
        if let Ok(content) = read_regular_file_nofollow(path, MAX_TRACE_FILE_READ_BYTES) {
            let parsed = parse_trace_content(&content);
            aux_combined.merge_max(parsed);
        }
    }
    combined.merge_max(aux_combined);

    // Fallback token usage & error metadata from harvest.json / result.json / supervisor-error.log.
    let mut explicit_check_divergence = false;
    let mut gate_check_failed = false;

    for meta_obj in [harvest_json.as_ref(), result_json.as_ref()]
        .into_iter()
        .flatten()
    {
        let inp = meta_obj.get("input_tokens").and_then(Value::as_u64);
        let out = meta_obj.get("output_tokens").and_then(Value::as_u64);
        let tot = meta_obj.get("total_tokens").and_then(Value::as_u64);
        combined.set_cumulative_tokens(inp, out, tot, None, None);

        if meta_obj.get("check_divergence").and_then(Value::as_bool) == Some(true) {
            explicit_check_divergence = true;
        }
        let status_failed = meta_obj
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.eq_ignore_ascii_case("passed"));
        if let Some(fc) = meta_obj.get("failure_class").and_then(Value::as_str)
            && !fc.trim().is_empty()
        {
            combined.set_error_code_if_empty(fc);
            if indicates_check_failure(fc) {
                gate_check_failed = true;
            }
        }
        if status_failed
            && let Some(summary) = meta_obj.get("summary").and_then(Value::as_str)
            && !summary.trim().is_empty()
        {
            combined.push_error_signature(summary);
            if indicates_check_failure(summary) {
                gate_check_failed = true;
            }
        }
    }

    if let Some(ref sup_err) = supervisor_err {
        let first_line = sup_err.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        if !first_line.is_empty() {
            combined.set_error_code_if_empty("supervisor_error");
            combined.push_error_signature(first_line);
            if indicates_check_failure(sup_err) {
                gate_check_failed = true;
            }
        }
    }

    let check_divergence = explicit_check_divergence
        || (combined.last_check_passed == Some(true) && gate_check_failed);

    Ok(AttemptAuditReport {
        schema_version: 1,
        attempt_id: redact_adr004_text(attempt_id, MAX_AUDIT_IDENTIFIER_LEN),
        task_id: redact_adr004_text(task_id, MAX_AUDIT_IDENTIFIER_LEN),
        stage: redact_adr004_text(stage, MAX_AUDIT_IDENTIFIER_LEN),
        harness,
        turn_count: combined.turn_count,
        tool_call_count: combined.tool_call_count,
        tool_error_count: combined.tool_error_count,
        edit_compile_fail_loops: combined.edit_compile_fail_loops,
        redundant_read_count: combined.redundant_read_count,
        cached_input_tokens: combined.cached_input_tokens,
        reasoning_tokens: combined.reasoning_tokens,
        input_tokens: combined.input_tokens,
        output_tokens: combined.output_tokens,
        total_tokens: combined.total_tokens,
        check_divergence,
        error_code: combined
            .error_code
            .map(|c| redact_adr004_text(&c, MAX_AUDIT_DIGEST_ERROR_SIGNATURE_LEN))
            .filter(|c| !c.is_empty()),
        error_signatures: combined
            .error_signatures
            .into_iter()
            .map(|s| redact_adr004_text(&s, MAX_AUDIT_DIGEST_ERROR_SIGNATURE_LEN))
            .filter(|s| !s.is_empty())
            .take(MAX_AUDIT_DIGEST_ERROR_SIGNATURES)
            .collect(),
        tool_calls: combined
            .tool_calls
            .into_iter()
            .take(MAX_AUDIT_TOOL_CALL_SUMMARIES)
            .collect(),
        created_epoch: now_epoch(),
    })
}

pub fn serialize_bounded_audit_json(report: &AttemptAuditReport) -> Result<Vec<u8>, String> {
    let mut sanitized = report.clone();
    sanitized.attempt_id = redact_adr004_text(&sanitized.attempt_id, MAX_AUDIT_IDENTIFIER_LEN);
    sanitized.task_id = redact_adr004_text(&sanitized.task_id, MAX_AUDIT_IDENTIFIER_LEN);
    sanitized.stage = redact_adr004_text(&sanitized.stage, MAX_AUDIT_IDENTIFIER_LEN);
    sanitized.harness = sanitized
        .harness
        .map(|h| redact_adr004_text(&h, MAX_AUDIT_IDENTIFIER_LEN))
        .filter(|h| !h.is_empty());
    sanitized.error_code = sanitized
        .error_code
        .map(|c| redact_adr004_text(&c, MAX_AUDIT_DIGEST_ERROR_SIGNATURE_LEN))
        .filter(|c| !c.is_empty());
    sanitized.error_signatures = sanitized
        .error_signatures
        .into_iter()
        .map(|s| redact_adr004_text(&s, MAX_AUDIT_DIGEST_ERROR_SIGNATURE_LEN))
        .filter(|s| !s.is_empty())
        .take(MAX_AUDIT_DIGEST_ERROR_SIGNATURES)
        .collect();
    sanitized.tool_calls.truncate(MAX_AUDIT_TOOL_CALL_SUMMARIES);
    for call in &mut sanitized.tool_calls {
        call.tool_name = redact_adr004_text(&call.tool_name, MAX_AUDIT_IDENTIFIER_LEN);
        if call.tool_name.is_empty() {
            call.tool_name = "unknown".to_owned();
        }
        call.category = redact_adr004_text(&call.category, MAX_AUDIT_IDENTIFIER_LEN);
        call.target_path = call
            .target_path
            .take()
            .map(|p| sanitize_path_summary(&p))
            .filter(|p| !p.is_empty());
    }

    loop {
        let value =
            serde_json::to_value(&sanitized).map_err(|e| format!("serialize audit value: {e}"))?;
        validate_adr004_value(&value, "attempt_audit")
            .map_err(|probs| format!("ADR-004 validation failed: {}", probs.join("; ")))?;
        let bytes = serde_json::to_vec_pretty(&sanitized)
            .map_err(|e| format!("serialize audit json: {e}"))?;
        if bytes.len() <= MAX_AUDIT_JSON_BYTES {
            return Ok(bytes);
        }
        if !sanitized.tool_calls.is_empty() {
            let next_len = sanitized.tool_calls.len() / 2;
            sanitized.tool_calls.truncate(next_len);
        } else if !sanitized.error_signatures.is_empty() {
            let next_len = sanitized.error_signatures.len() / 2;
            sanitized.error_signatures.truncate(next_len);
        } else {
            return Err(format!(
                "attempt audit JSON exceeds {} bytes even after truncation ({} bytes)",
                MAX_AUDIT_JSON_BYTES,
                bytes.len()
            ));
        }
    }
}

pub fn extract_and_write_attempt_audit(attempt_dir: &Path) -> Result<AttemptAuditReport, String> {
    let report = extract_attempt_audit(attempt_dir)?;
    let bytes = serialize_bounded_audit_json(&report)?;
    crate::v2::runner::write_secure_file(&attempt_dir.join("audit.json"), &bytes)?;
    Ok(report)
}

pub fn read_or_extract_attempt_audit_record(
    attempt_dir: &Path,
    attempt: &StageAttemptRecord,
) -> AttemptAuditRecord {
    let report =
        read_regular_file_nofollow(&attempt_dir.join("audit.json"), MAX_AUDIT_JSON_BYTES as u64)
            .ok()
            .and_then(|text| serde_json::from_str::<AttemptAuditReport>(&text).ok())
            .or_else(|| extract_attempt_audit(attempt_dir).ok());

    match report {
        Some(rep) => AttemptAuditRecord {
            attempt_id: attempt.attempt_id.clone(),
            task_id: attempt.task_id.clone(),
            stage: attempt.stage.clone(),
            turn_count: rep.turn_count,
            tool_call_count: rep.tool_call_count,
            tool_error_count: rep.tool_error_count,
            edit_compile_fail_loops: rep.edit_compile_fail_loops,
            redundant_read_count: rep.redundant_read_count,
            cached_input_tokens: rep.cached_input_tokens,
            reasoning_tokens: rep.reasoning_tokens,
            check_divergence: rep.check_divergence,
            error_code: rep
                .error_code
                .map(|c| redact_adr004_text(&c, MAX_AUDIT_DIGEST_ERROR_SIGNATURE_LEN))
                .filter(|c| !c.is_empty()),
            created_epoch: rep.created_epoch,
        },
        None => AttemptAuditRecord {
            attempt_id: attempt.attempt_id.clone(),
            task_id: attempt.task_id.clone(),
            stage: attempt.stage.clone(),
            turn_count: 0,
            tool_call_count: 0,
            tool_error_count: 0,
            edit_compile_fail_loops: 0,
            redundant_read_count: 0,
            cached_input_tokens: None,
            reasoning_tokens: None,
            check_divergence: false,
            error_code: attempt
                .failure_class
                .as_deref()
                .map(|c| redact_adr004_text(c, MAX_AUDIT_DIGEST_ERROR_SIGNATURE_LEN))
                .filter(|c| !c.is_empty()),
            created_epoch: now_epoch(),
        },
    }
}

pub fn validate_task_audit_digest(digest: &TaskAuditDigest) -> Result<Value, Vec<String>> {
    let value = serde_json::to_value(digest).map_err(|e| vec![format!("serialize digest: {e}")])?;
    let Some(obj) = value.as_object() else {
        return Err(vec!["audit_digest must be a JSON object".to_owned()]);
    };

    let mut problems = Vec::new();
    collect_adr004_problems(&value, "audit_digest", &mut problems);

    let mut unknown_keys: Vec<String> = obj
        .keys()
        .filter(|k| !AUDIT_DIGEST_ALLOWED_KEYS.contains(&k.as_str()))
        .cloned()
        .collect();
    unknown_keys.sort();
    if !unknown_keys.is_empty() {
        problems.push(format!(
            "audit_digest contains unsupported field(s): {}",
            unknown_keys.join(", ")
        ));
    }

    match obj.get("schema_version").and_then(Value::as_u64) {
        Some(1) => {}
        other => problems.push(format!(
            "audit_digest.schema_version must be 1, got {other:?}"
        )),
    }

    for key in ["task_id", "executor", "generated_at"] {
        match obj.get(key).and_then(Value::as_str) {
            Some(s)
                if !s.trim().is_empty() && s.trim().chars().count() <= MAX_AUDIT_IDENTIFIER_LEN => {
            }
            _ => problems.push(format!(
                "audit_digest.{key} must be a non-empty string <= {MAX_AUDIT_IDENTIFIER_LEN} chars"
            )),
        }
    }

    for counter in AUDIT_DIGEST_COUNTERS {
        match obj.get(*counter) {
            Some(v) if v.as_u64().is_some() => {}
            None => problems.push(format!("audit_digest.{counter} is required")),
            Some(_) => problems.push(format!(
                "audit_digest.{counter} must be a non-negative integer"
            )),
        }
    }

    match obj.get("check_divergence") {
        Some(Value::Bool(_)) => {}
        None => problems.push("audit_digest.check_divergence is required".to_owned()),
        Some(_) => problems.push("audit_digest.check_divergence must be a boolean".to_owned()),
    }

    if let Some(tu_val) = obj.get("token_usage")
        && !tu_val.is_null()
    {
        let Some(tu) = tu_val.as_object() else {
            problems.push("audit_digest.token_usage must be an object".to_owned());
            return Err(problems);
        };
        const ALLOWED_TU: &[&str] = &["input_tokens", "output_tokens", "total_tokens"];
        let mut extra_tu: Vec<String> = tu
            .keys()
            .filter(|k| !ALLOWED_TU.contains(&k.as_str()))
            .cloned()
            .collect();
        extra_tu.sort();
        if !extra_tu.is_empty() {
            problems.push(format!(
                "audit_digest.token_usage contains unsupported field(s): {}",
                extra_tu.join(", ")
            ));
        }
        for req_k in ["input_tokens", "output_tokens"] {
            if tu.get(req_k).and_then(Value::as_u64).is_none() {
                problems.push(format!(
                    "audit_digest.token_usage.{req_k} must be a non-negative integer"
                ));
            }
        }
        if let Some(tot) = tu.get("total_tokens")
            && !tot.is_null()
            && tot.as_u64().is_none()
        {
            problems.push(
                "audit_digest.token_usage.total_tokens must be a non-negative integer".to_owned(),
            );
        }
    }

    if let Some(sigs_val) = obj.get("error_signatures")
        && !sigs_val.is_null()
    {
        let Some(sigs) = sigs_val.as_array() else {
            problems.push("audit_digest.error_signatures must be a list".to_owned());
            return Err(problems);
        };
        if sigs.len() > MAX_AUDIT_DIGEST_ERROR_SIGNATURES {
            problems.push(format!(
                "audit_digest.error_signatures exceeds max length of {MAX_AUDIT_DIGEST_ERROR_SIGNATURES}"
            ));
        } else {
            for (idx, item) in sigs.iter().enumerate() {
                match item.as_str() {
                    Some(s) if !s.trim().is_empty() => {
                        if s.trim().chars().count() > MAX_AUDIT_DIGEST_ERROR_SIGNATURE_LEN {
                            problems.push(format!(
                                "audit_digest.error_signatures[{idx}] exceeds {MAX_AUDIT_DIGEST_ERROR_SIGNATURE_LEN} chars"
                            ));
                        }
                    }
                    _ => problems.push(format!(
                        "audit_digest.error_signatures[{idx}] must be a non-empty string"
                    )),
                }
            }
        }
    }

    if problems.is_empty() {
        Ok(value)
    } else {
        Err(problems)
    }
}

pub fn build_task_audit_digest(store: &V2Store, task_id: &str) -> Result<TaskAuditDigest, String> {
    let task = store.get_task(task_id).map_err(|e| e.to_string())?;
    let attempts = store
        .list_stage_attempts(task_id)
        .map_err(|e| e.to_string())?;
    let audits = store
        .list_attempt_audits(task_id)
        .map_err(|e| e.to_string())?;
    let events = store.list_task_events(task_id).map_err(|e| e.to_string())?;

    if task.is_none() && attempts.is_empty() && audits.is_empty() {
        return Err(format!("task not found: {task_id}"));
    }

    let stage_attempts_count = attempts.len().max(audits.len()) as u64;
    let rework_count = task.as_ref().map_or(0, |t| {
        let mem_rework = u64::from(t.memory.plan_rework_count)
            .saturating_add(u64::from(t.memory.review_rework_count));
        let recent_rework = t
            .memory
            .recent_attempts
            .iter()
            .filter(|entry| {
                entry.contains("[MERGE_REREVIEW]") || entry.contains("CHANGES_REQUESTED")
            })
            .count() as u64;
        mem_rework.max(recent_rework)
    });

    let retried_failed_attempts = attempts
        .iter()
        .filter(|a| a.status != "PASSED" && a.status != "RUNNING")
        .count() as u64;
    let retry_count = task.as_ref().map_or(retried_failed_attempts, |t| {
        let base =
            (t.retry_count.max(0) as u64).saturating_add(u64::from(t.memory.merge_retry_count));
        base.max(retried_failed_attempts)
    });

    let tool_error_count = audits.iter().map(|a| a.tool_error_count).sum::<u64>();
    let blocked_event_rows = events
        .iter()
        .filter(|e| matches!(e.event_type.as_str(), "DECISION_REQUIRED" | "TASK_BLOCKED"))
        .count() as u64;
    let blocked_events = blocked_event_rows.max(u64::from(
        task.as_ref().is_some_and(|t| t.status == "Blocked"),
    ));

    let supervisor_event_rows = events
        .iter()
        .filter(|e| e.event_type == "SUPERVISOR_ERROR")
        .count() as u64;
    let supervisor_attempt_rows = attempts
        .iter()
        .filter(|a| {
            matches!(a.status.as_str(), "LOST" | "STALLED")
                || a.failure_class.as_deref() == Some("infra")
        })
        .count() as u64;
    let supervisor_errors = supervisor_event_rows.max(supervisor_attempt_rows);

    let edit_compile_fail_loops = audits
        .iter()
        .map(|a| a.edit_compile_fail_loops)
        .sum::<u64>();
    let check_divergence = audits.iter().any(|a| a.check_divergence);

    let has_tokens = attempts
        .iter()
        .any(|a| a.input_tokens.is_some() || a.output_tokens.is_some() || a.total_tokens.is_some());
    let token_usage = if has_tokens {
        let mut inp_sum = 0u64;
        let mut out_sum = 0u64;
        let mut tot_sum = 0u64;
        for a in &attempts {
            let i = a.input_tokens.unwrap_or(0);
            let o = a.output_tokens.unwrap_or(0);
            let t = a.total_tokens.unwrap_or_else(|| i.saturating_add(o));
            inp_sum = inp_sum.saturating_add(i);
            out_sum = out_sum.saturating_add(o);
            tot_sum = tot_sum.saturating_add(t);
        }
        Some(AuditDigestTokenUsage {
            input_tokens: inp_sum,
            output_tokens: out_sum,
            total_tokens: Some(tot_sum),
        })
    } else {
        None
    };

    let mut error_signatures = Vec::new();
    let mut push_sig = |raw: &str| {
        if error_signatures.len() >= MAX_AUDIT_DIGEST_ERROR_SIGNATURES {
            return;
        }
        let clean = redact_adr004_text(raw, MAX_AUDIT_DIGEST_ERROR_SIGNATURE_LEN);
        let trimmed = clean.trim();
        if trimmed.is_empty() {
            return;
        }
        if !sensitive_pattern_hits(trimmed).is_empty() {
            return;
        }
        if !error_signatures.iter().any(|existing| existing == trimmed) {
            error_signatures.push(trimmed.to_owned());
        }
    };

    for audit in &audits {
        if let Some(ref code) = audit.error_code {
            push_sig(code);
        }
    }
    for attempt in &attempts {
        if attempt.status != "PASSED" && attempt.status != "RUNNING" {
            let fc = attempt.failure_class.as_deref().unwrap_or(&attempt.status);
            if let Some(ref summary) = attempt.summary {
                push_sig(&format!("{}:{fc}: {summary}", attempt.stage));
            } else {
                push_sig(&format!("{}:{fc}", attempt.stage));
            }
        }
    }
    for event in &events {
        if event.event_type == "SUPERVISOR_ERROR"
            && let Some(err) = event.payload.get("error").and_then(Value::as_str)
        {
            push_sig(err);
        }
    }

    let clean_task_id = redact_adr004_text(task_id, MAX_AUDIT_IDENTIFIER_LEN);
    let digest = TaskAuditDigest {
        schema_version: 1,
        task_id: clean_task_id,
        executor: "zach".to_owned(),
        generated_at: format_utc_iso8601(now_epoch()),
        stage_attempts_count,
        rework_count,
        retry_count,
        tool_error_count,
        blocked_events,
        supervisor_errors,
        edit_compile_fail_loops,
        check_divergence,
        token_usage,
        error_signatures,
    };

    validate_task_audit_digest(&digest)
        .map_err(|probs| format!("invalid TASK_AUDIT_DIGEST: {}", probs.join("; ")))?;
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(prefix: &str) -> Self {
            static SEQ: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "zach-audit-test-{prefix}-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn codex_jsonl_extracts_command_execution_mcp_tool_calls_and_turn_completed_cached_reasoning_tokens()
     {
        let dir = TempDir::new("codex");
        fs::write(
            dir.0.join("manifest.json"),
            r#"{"attempt_id":"att-codex-1","task_id":"ZACH-072","route":{"stage":"impl","family":"OpenAiSol"}}"#,
        )
        .unwrap();
        let stdout_jsonl = [
            r#"{"type":"item.completed","item":{"id":"cmd-1","type":"command_execution","command":"bash -lc 'cat src/main.rs'","exit_code":0,"status":"completed"}}"#,
            r#"{"type":"item.completed","item":{"id":"cmd-2","type":"command_execution","command":"bash -lc 'cargo test'","exit_code":101,"status":"failed"}}"#,
            r#"{"type":"item.completed","item":{"id":"mcp-1","type":"mcp_tool_call","server":"context7","tool":"query-docs","status":"completed"}}"#,
            r#"{"type":"item.completed","item":{"id":"mcp-2","type":"mcp_tool_call","server":"github","tool":"get_pr","status":"failed","error":{"message":"rate limit"}}}"#,
            r#"{"type":"turn.completed","usage":{"input_tokens":1200,"cached_input_tokens":450,"output_tokens":300,"reasoning_output_tokens":120}}"#,
            r#"{"type":"turn.completed","usage":{"input_tokens":800,"input_tokens_details":{"cached_tokens":200},"output_tokens":150,"output_tokens_details":{"reasoning_tokens":80}}}"#,
        ]
        .join("\n");
        fs::write(dir.0.join("stdout.jsonl"), stdout_jsonl).unwrap();

        let rollout_dir = dir.0.join("codex-home/sessions/2026");
        fs::create_dir_all(&rollout_dir).unwrap();
        let rollout_jsonl = [
            r#"{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":2000,"cached_input_tokens":650,"output_tokens":450,"reasoning_output_tokens":200,"total_tokens":2450}}}}"#,
            r#"{"type":"response_item","payload":{"type":"function_call","call_id":"c1","name":"read_file","arguments":"{\"path\":\"src/main.rs\"}"}}"#,
            r#"{"type":"response_item","payload":{"type":"function_call_output","call_id":"c1","output":"Exit code: 0"}}"#,
        ]
        .join("\n");
        fs::write(rollout_dir.join("rollout-2026-001.jsonl"), rollout_jsonl).unwrap();

        let report = extract_attempt_audit(&dir.0).expect("extract codex audit");
        assert_eq!(report.attempt_id, "att-codex-1");
        assert_eq!(report.task_id, "ZACH-072");
        assert_eq!(report.stage, "impl");
        assert_eq!(report.turn_count, 2);
        assert_eq!(report.tool_call_count, 4);
        assert_eq!(report.tool_error_count, 2);
        // Combined with rollout without double-counting:
        assert_eq!(report.input_tokens, Some(2000));
        assert_eq!(report.output_tokens, Some(450));
        assert_eq!(report.total_tokens, Some(2450));
        assert_eq!(report.cached_input_tokens, Some(650));
        assert_eq!(report.reasoning_tokens, Some(200));
        assert!(
            report
                .tool_calls
                .iter()
                .any(|c| c.tool_name == "mcp:context7/query-docs" && !c.is_error)
        );
        assert!(
            report
                .tool_calls
                .iter()
                .any(|c| c.tool_name == "mcp:github/get_pr" && c.is_error)
        );
    }

    #[test]
    fn agy_extracts_stdout_envelope_stream_json_and_gemini_home_transcript_jsonl() {
        // 1. Envelope + gemini-home transcript.jsonl
        let dir = TempDir::new("agy-env");
        fs::write(
            dir.0.join("manifest.json"),
            r#"{"attempt_id":"att-agy-1","task_id":"ZACH-072","route":{"stage":"pr-review","family":"GeminiAgy"}}"#,
        )
        .unwrap();
        let envelope = r#"{
            "status": "error",
            "execution_succeeded": false,
            "attempt": 2,
            "budget": {"model_calls_used": 3},
            "usage": {
                "input_tokens": 5000,
                "output_tokens": 900,
                "total_tokens": 5900,
                "cached_input_tokens": 1100,
                "reasoning_tokens": 350
            },
            "diagnostic": {"code": "AGY_TOOL_FAIL", "summary": "command exited 1"}
        }"#;
        fs::write(dir.0.join("stdout.jsonl"), envelope).unwrap();

        let tx_dir = dir
            .0
            .join("gemini-home/antigravity-cli/brain/conv-1/.system_generated/logs");
        fs::create_dir_all(&tx_dir).unwrap();
        let transcript = [
            r#"{"step_index":1,"type":"PLANNER_RESPONSE","status":"DONE","tool_calls":[{"name":"read_file","arguments":{"Path":"src/v2/store.rs"}}]}"#,
            r#"{"step_index":2,"type":"PLANNER_RESPONSE","status":"DONE","tool_calls":[{"name":"edit_file","arguments":{"Path":"src/v2/store.rs"}}]}"#,
            r#"{"step_index":3,"type":"PLANNER_RESPONSE","status":"DONE","tool_calls":[{"name":"run_command","arguments":{"CommandLine":"cargo test"},"exit_code":101,"is_error":true}]}"#,
            r#"{"step_index":4,"type":"TOOL_RESULT","status":"ERROR","error":"cargo test failed"}"#,
        ]
        .join("\n");
        fs::write(tx_dir.join("transcript.jsonl"), transcript).unwrap();

        let report = extract_attempt_audit(&dir.0).expect("extract agy envelope+transcript");
        assert_eq!(report.turn_count, 3);
        assert_eq!(report.tool_call_count, 3);
        assert_eq!(report.tool_error_count, 2);
        assert_eq!(report.edit_compile_fail_loops, 1);
        assert_eq!(report.input_tokens, Some(5000));
        assert_eq!(report.output_tokens, Some(900));
        assert_eq!(report.total_tokens, Some(5900));
        assert_eq!(report.cached_input_tokens, Some(1100));
        assert_eq!(report.reasoning_tokens, Some(350));
        assert_eq!(report.error_code.as_deref(), Some("AGY_TOOL_FAIL"));

        // 2. Multi-line AGY stream-json
        let stream_dir = TempDir::new("agy-stream");
        let stream_json = [
            r#"{"type":"assistant","num_turns":1,"usage":{"input_tokens":300,"output_tokens":100,"cached_input_tokens":50,"reasoning_tokens":20}}"#,
            r#"{"type":"tool_use","id":"tu-1","name":"edit_file","input":{"Path":"src/lib.rs"}}"#,
            r#"{"type":"tool_use","id":"tu-2","name":"run_command","input":{"CommandLine":"cargo clippy -- -D warnings"}}"#,
            r#"{"type":"tool_result","tool_use_id":"tu-2","is_error":true}"#,
            r#"{"type":"assistant","num_turns":2,"usage":{"input_tokens":400,"output_tokens":120}}"#,
        ]
        .join("\n");
        fs::write(stream_dir.0.join("stdout.jsonl"), stream_json).unwrap();
        let stream_report = extract_attempt_audit(&stream_dir.0).expect("extract stream-json");
        assert_eq!(stream_report.turn_count, 2);
        assert_eq!(stream_report.tool_call_count, 2);
        assert_eq!(stream_report.tool_error_count, 1);
        assert_eq!(stream_report.edit_compile_fail_loops, 1);
        assert_eq!(stream_report.input_tokens, Some(700));
        assert_eq!(stream_report.output_tokens, Some(220));
        assert_eq!(stream_report.cached_input_tokens, Some(50));
        assert_eq!(stream_report.reasoning_tokens, Some(20));
    }

    #[test]
    fn adr004_redaction_strips_credentials_tokens_prompts_and_enforces_32kib_cap() {
        let dirty_samples = [
            "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjE= -----END OPENSSH PRIVATE KEY-----",
            "Authorization: Bearer supersecrettoken1234567890 failed",
            "api_key=sk-1234567890abcdefghij1234567890 password=mysecretpass",
            "github token ghp_1234567890abcdefghij123456 and github_pat_1234567890abcdefghij123456",
            "aws AKIAIOSFODNN7EXAMPLE slack xoxb-1234567890-abcdef",
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "openai sk-abcdefghijklmnopqrstuvwxyz123456 google AIzaSyA1234567890abcdefghijklmno",
            "uri https://alice:s3cr3tpass@example.com/repo.git",
            "prompt: stdout: stderr: raw_payload=actual error summary",
            "prompt: ",
        ];
        for sample in dirty_samples {
            let clean = redact_adr004_text(sample, 160);
            assert!(
                sensitive_pattern_hits(&clean).is_empty(),
                "leaked sensitive pattern in '{clean}' from '{sample}'"
            );
            assert!(!clean.contains("supersecrettoken"));
            assert!(!clean.contains("mysecretpass"));
            assert!(!clean.contains("ghp_"));
            assert!(!clean.contains("AKIAIOSFODNN7EXAMPLE"));
            assert!(!clean.contains("s3cr3tpass"));
        }
        assert_eq!(
            redact_adr004_text("prompt: stdout: actual error", 160),
            "actual error"
        );
        assert_eq!(redact_adr004_text("prompt: ", 160), "");

        // Verify 32 KiB cap with > 100 verbose tool calls
        let mut tool_calls = Vec::new();
        for i in 0..400 {
            tool_calls.push(AuditedToolCall {
                tool_name: format!("very_long_tool_name_number_{i:04}_with_padding_xyz"),
                category: "read".to_owned(),
                target_path: Some(format!(
                    "src/v2/deeply/nested/module/path/number_{i:04}/very_long_filename_here.rs"
                )),
                exit_code: Some(0),
                is_error: false,
            });
        }
        let report = AttemptAuditReport {
            schema_version: 1,
            attempt_id: "att-cap-1".to_owned(),
            task_id: "ZACH-072".to_owned(),
            stage: "impl".to_owned(),
            harness: Some("OpenAiSol".to_owned()),
            turn_count: 5,
            tool_call_count: 400,
            tool_error_count: 0,
            edit_compile_fail_loops: 0,
            redundant_read_count: 0,
            cached_input_tokens: Some(10),
            reasoning_tokens: Some(20),
            input_tokens: Some(100),
            output_tokens: Some(50),
            total_tokens: Some(150),
            check_divergence: false,
            error_code: Some("api_key=secret123".to_owned()),
            error_signatures: dirty_samples.iter().map(|s| (*s).to_owned()).collect(),
            tool_calls,
            created_epoch: 1_700_000_000,
        };

        let bytes = serialize_bounded_audit_json(&report).expect("bounded serialization");
        assert!(
            bytes.len() <= MAX_AUDIT_JSON_BYTES,
            "audit.json exceeded 32 KiB: {} bytes",
            bytes.len()
        );
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(validate_adr004_value(&parsed, "audit").is_ok());
    }

    #[test]
    fn loop_redundancy_and_check_divergence_heuristics_count_accurately() {
        let dir = TempDir::new("heuristics");
        let stdout_jsonl = [
            // Read src/a.rs twice -> 1 redundant read
            r#"{"type":"item.completed","item":{"id":"1","type":"command_execution","command":"cat src/a.rs","exit_code":0}}"#,
            r#"{"type":"item.completed","item":{"id":"2","type":"command_execution","command":"cat src/a.rs","exit_code":0}}"#,
            // Edit src/a.rs -> resets read cache & sets pending_edit
            r#"{"type":"item.completed","item":{"id":"3","type":"file_change","changes":[{"path":"src/a.rs"}]}}"#,
            // Re-reading src/a.rs after edit is NOT redundant
            r#"{"type":"item.completed","item":{"id":"4","type":"command_execution","command":"cat src/a.rs","exit_code":0}}"#,
            // Failing compile check after edit -> loop 1
            r#"{"type":"item.completed","item":{"id":"5","type":"command_execution","command":"cargo test","exit_code":101}}"#,
            // Second failing check without intervening edit -> does NOT increment loop
            r#"{"type":"item.completed","item":{"id":"6","type":"command_execution","command":"cargo test","exit_code":101}}"#,
            // Edit again + failing clippy -> loop 2
            r#"{"type":"item.completed","item":{"id":"7","type":"file_change","changes":[{"path":"src/a.rs"}]}}"#,
            r#"{"type":"item.completed","item":{"id":"8","type":"command_execution","command":"cargo clippy -- -D warnings","exit_code":1}}"#,
            // Edit again + passing cargo test -> does NOT increment loop, records last_check_passed = true
            r#"{"type":"item.completed","item":{"id":"9","type":"file_change","changes":[{"path":"src/a.rs"}]}}"#,
            r#"{"type":"item.completed","item":{"id":"10","type":"command_execution","command":"cargo test","exit_code":0}}"#,
        ]
        .join("\n");
        fs::write(dir.0.join("stdout.jsonl"), stdout_jsonl).unwrap();
        // Gate subsequently failed on verification check despite worker's passing cargo test -> check_divergence = true
        fs::write(
            dir.0.join("result.json"),
            r#"{"status":"FAILED","failure_class":"semantic","summary":"check 'cargo test' failed with exit code 101"}"#,
        )
        .unwrap();

        let report = extract_attempt_audit(&dir.0).expect("extract heuristics");
        assert_eq!(report.redundant_read_count, 1);
        assert_eq!(report.edit_compile_fail_loops, 2);
        assert!(report.check_divergence);
    }

    #[test]
    fn symlink_trace_files_in_codex_and_gemini_home_are_rejected() {
        let outside = TempDir::new("outside");
        let secret_file = outside.0.join("secret.jsonl");
        fs::write(
            &secret_file,
            r#"{"type":"turn.completed","usage":{"input_tokens":9999,"output_tokens":8888}}"#,
        )
        .unwrap();

        let dir = TempDir::new("symlink");
        fs::create_dir_all(dir.0.join("codex-home/sessions")).unwrap();
        fs::create_dir_all(dir.0.join("gemini-home/logs")).unwrap();
        symlink(&secret_file, dir.0.join("stdout.jsonl")).unwrap();
        symlink(
            &secret_file,
            dir.0.join("codex-home/sessions/rollout-evil.jsonl"),
        )
        .unwrap();
        symlink(
            &secret_file,
            dir.0.join("gemini-home/logs/transcript.jsonl"),
        )
        .unwrap();

        let report = extract_attempt_audit(&dir.0).expect("extract ignores symlinks safely");
        assert_eq!(report.turn_count, 0);
        assert_eq!(report.input_tokens, None);
        assert_eq!(report.output_tokens, None);
    }

    #[test]
    fn format_utc_iso8601_formats_known_timestamps() {
        assert_eq!(format_utc_iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc_iso8601(1_700_000_000), "2023-11-14T22:13:20Z");
    }
}
