//! Versioned, repository-owned post-merge delivery contracts.
//!
//! The YAML subset supports block maps/lists, quoted scalars and empty []/{}.
//! Artifact declarations use `name` (a template) and `file` (a relative JSON path).
//! Failure declarations may supply `marker` to match failed-run logs. Health checks
//! are HTTPS URL scalars or maps with `url`, `contains`, and `source_sha_field`.
//! Templates accept ${sha}, ${source_sha}, ${run_id}, ${attempt}, ${build_run_id},
//! ${artifact_digest}, and ${expected_current}. Artifact names are exact except
//! `plan_artifact_prefix`, which selects a unique prefix (an exact match wins).
//! Promotions may declare `delivery_file`; otherwise a health check must verify
//! `source_sha_field`. Dispatches use the discovered default branch and the API's
//! returned run ID; build/source/digest evidence stays pinned to the merge SHA.
//! Promotion plan JSON must echo
//! source_sha, build_run_id, artifact_digest (or artifact_sha256), expected_current.
use crate::v2::merge_queue::{CiCheckState, evaluate_check_runs_json};
use crate::v2::now_epoch;
use crate::v2::pipeline::matches_path_pattern;
use crate::v2::store::{PostMergeDelivery, TaskRecord, V2Store, V2StoreError};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_FILE: usize = 1024 * 1024;
const MAX_ARCHIVE: usize = 8 * MAX_FILE;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeliveryContract {
    pub schema_version: u32,
    #[serde(default)]
    pub post_merge_workflows: Vec<WorkflowDelivery>,
    #[serde(default)]
    pub promotions: Vec<Promotion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDelivery {
    pub workflow: String,
    #[serde(default)]
    pub when_paths: Vec<String>,
    #[serde(default)]
    pub artifacts: Vec<Artifact>,
    #[serde(default)]
    pub failure_states: Vec<FailureState>,
    #[serde(default)]
    pub health_checks: Vec<HealthCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub name: String,
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FailureState {
    #[serde(default)]
    pub marker: String,
    pub waiting_state: String,
    pub decision_kind: String,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Promotion {
    pub name: String,
    #[serde(default)]
    pub when_paths: Vec<String>,
    pub build_workflow: String,
    pub artifact_name_template: String,
    pub digest_file: String,
    pub promote_workflow: String,
    pub plan_inputs: BTreeMap<String, String>,
    pub approve_inputs: BTreeMap<String, String>,
    pub plan_artifact_prefix: String,
    pub plan_file: String,
    #[serde(default)]
    pub delivery_file: Option<String>,
    #[serde(default)]
    pub current_source_probe: Option<String>,
    #[serde(default)]
    pub health_checks: Vec<HealthCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum HealthCheck {
    Url(String),
    Detailed(HealthCheckSpec),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckSpec {
    pub url: String,
    #[serde(default)]
    pub contains: Option<String>,
    #[serde(default)]
    pub source_sha_field: Option<String>,
}

impl HealthCheck {
    fn url(&self) -> &str {
        match self {
            Self::Url(url) => url,
            Self::Detailed(check) => &check.url,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractLookup {
    ContractNotFound,
    Found(DeliveryContract),
    FetchError(String),
    ParseError(String),
}

// A deliberately small parser: indentation is structural; duplicate keys and
// unsupported YAML syntax fail closed rather than being silently ignored.
#[derive(Clone)]
struct Line {
    indent: usize,
    text: String,
}

fn uncomment(raw: &str) -> Result<String, String> {
    let mut quote = None;
    let mut escaped = false;
    let chars: Vec<char> = raw.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if escaped {
            escaped = false;
        } else if quote == Some('"') && ch == '\\' {
            escaped = true;
        } else if quote == Some('\'') && ch == '\'' && chars.get(i + 1) == Some(&'\'') {
            i += 1;
        } else if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
        } else if ch == '\'' || ch == '"' {
            quote = Some(ch);
        } else if ch == '#' && (i == 0 || chars[i - 1].is_whitespace()) {
            return Ok(chars[..i].iter().collect::<String>().trim_end().to_owned());
        } else if matches!(ch, '&' | '*') {
            // Globs/templates can contain * inside a scalar; YAML aliases and
            // anchors occur at token boundaries, never inside a path glob.
            if i == 0 || chars[i - 1].is_whitespace() || chars[i - 1] == ':' {
                return Err("YAML anchors and aliases are unsupported; quote path globs".into());
            }
        }
        i += 1;
    }
    if quote.is_some() {
        return Err("unterminated quoted YAML scalar".into());
    }
    Ok(raw.trim_end().to_owned())
}

fn scalar(raw: &str) -> Result<Value, String> {
    let s = raw.trim();
    if s.starts_with('"') {
        return serde_json::from_str::<String>(s)
            .map(Value::String)
            .map_err(|e| format!("invalid quoted scalar: {e}"));
    }
    if s.starts_with('\'') {
        if s.len() < 2 || !s.ends_with('\'') {
            return Err("invalid single-quoted scalar".into());
        }
        let inner = &s[1..s.len() - 1];
        if inner.replace("''", "").contains('\'') {
            return Err("invalid single-quote escape".into());
        }
        return Ok(Value::String(inner.replace("''", "'")));
    }
    match s {
        "[]" => Ok(json!([])),
        "{}" => Ok(json!({})),
        "" | "null" | "~" => Err("empty/null scalar is unsupported".into()),
        _ if s.starts_with(['[', '{', '!', '|', '>', '&', '*']) || s.contains(": ") => {
            Err("unsupported YAML scalar syntax".into())
        }
        _ => Ok(Value::String(s.to_owned())),
    }
}

fn key_value(s: &str) -> Result<(&str, &str), String> {
    let (key, value) = s.split_once(':').ok_or("expected YAML map entry")?;
    if key.is_empty()
        || key == "<<"
        || !key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
    {
        return Err(format!("unsupported YAML key: {key}"));
    }
    if !value.is_empty() && !value.starts_with(' ') {
        return Err("expected space after map colon".into());
    }
    Ok((key, value.trim()))
}

fn map_entry(
    lines: &[Line],
    pos: &mut usize,
    indent: usize,
    text: &str,
    map: &mut Map<String, Value>,
) -> Result<(), String> {
    let (key, raw) = key_value(text)?;
    let value = if raw.is_empty() {
        let next = lines.get(*pos).ok_or("missing nested YAML value")?;
        if next.indent != indent + 2 {
            return Err("nested YAML must use two-space indentation".into());
        }
        parse_block(lines, pos, indent + 2)?
    } else {
        scalar(raw)?
    };
    if map.insert(key.to_owned(), value).is_some() {
        return Err(format!("duplicate YAML key: {key}"));
    }
    Ok(())
}

fn parse_block(lines: &[Line], pos: &mut usize, indent: usize) -> Result<Value, String> {
    if indent > 32 {
        return Err("YAML nesting limit exceeded".into());
    }
    let list = lines[*pos].text.starts_with("- ") || lines[*pos].text == "-";
    let mut items = Vec::new();
    let mut map = Map::new();
    while let Some(line) = lines.get(*pos) {
        if line.indent < indent {
            break;
        }
        if line.indent != indent {
            return Err("unexpected YAML indentation".into());
        }
        let text = line.text.clone();
        *pos += 1;
        if list {
            let rest = text.strip_prefix('-').ok_or("mixed YAML map/list")?;
            if !rest.is_empty() && !rest.starts_with(' ') {
                return Err("invalid list item".into());
            }
            let rest = rest.trim();
            if rest.is_empty() {
                if lines.get(*pos).map(|l| l.indent) != Some(indent + 2) {
                    return Err("missing list value".into());
                }
                items.push(parse_block(lines, pos, indent + 2)?);
            } else if !rest.starts_with(['\'', '"']) && (rest.contains(": ") || rest.ends_with(':'))
            {
                let mut entry = Map::new();
                map_entry(lines, pos, indent + 2, rest, &mut entry)?;
                while let Some(next) = lines.get(*pos) {
                    if next.indent <= indent {
                        break;
                    }
                    if next.indent != indent + 2 {
                        return Err("invalid map-list indentation".into());
                    }
                    let next_text = next.text.clone();
                    *pos += 1;
                    map_entry(lines, pos, indent + 2, &next_text, &mut entry)?;
                }
                items.push(Value::Object(entry));
            } else {
                items.push(scalar(rest)?);
            }
        } else {
            map_entry(lines, pos, indent, &text, &mut map)?;
        }
    }
    Ok(if list {
        Value::Array(items)
    } else {
        Value::Object(map)
    })
}

pub fn parse_contract(raw: &str) -> Result<DeliveryContract, String> {
    if raw.len() > MAX_FILE || raw.contains('\t') || raw.contains('\0') {
        return Err("contract is oversized or contains tabs/NUL".into());
    }
    let mut lines = Vec::new();
    for raw_line in raw.lines() {
        let text = uncomment(raw_line)?;
        if text.trim().is_empty() {
            continue;
        }
        let indent = text.len() - text.trim_start_matches(' ').len();
        lines.push(Line {
            indent,
            text: text[indent..].to_owned(),
        });
    }
    if lines.first().map(|l| l.indent) != Some(0) {
        return Err("contract must start at indentation zero".into());
    }
    let mut pos = 0;
    let mut value = parse_block(&lines, &mut pos, 0)?;
    if pos != lines.len() {
        return Err("unparsed YAML content".into());
    }
    if value.get("schema_version").and_then(Value::as_str) != Some("1") {
        return Err("unsupported delivery schema_version (expected 1)".into());
    }
    value["schema_version"] = json!(1);
    let contract: DeliveryContract = serde_json::from_value(value).map_err(|e| e.to_string())?;
    contract.validate()?;
    Ok(contract)
}

fn safe_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        && !value.starts_with('-')
}

pub fn validate_repo(repo: &str) -> Result<(), String> {
    let parts: Vec<&str> = repo.split('/').collect();
    if parts.len() != 2
        || parts
            .iter()
            .any(|p| !safe_token(p) || *p == "." || *p == "..")
    {
        return Err("invalid GitHub repository".into());
    }
    Ok(())
}

pub fn validate_workflow(workflow: &str) -> Result<(), String> {
    if !safe_token(workflow)
        || workflow.contains("..")
        || !(workflow.ends_with(".yml") || workflow.ends_with(".yaml"))
    {
        return Err("invalid workflow filename".into());
    }
    Ok(())
}

fn validate_sha(sha: &str) -> Result<(), String> {
    if sha.len() != 40 || !sha.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("expected a 40-hex SHA".into());
    }
    Ok(())
}

fn validate_run(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > 24 || !id.bytes().all(|c| c.is_ascii_digit()) {
        return Err("invalid workflow run ID".into());
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<(), String> {
    if key.is_empty()
        || key.len() > 64
        || !key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
    {
        return Err("invalid dispatch input key".into());
    }
    Ok(())
}

fn validate_input_value(key: &str, value: &str) -> Result<(), String> {
    if value.len() > 1024 || value.chars().any(char::is_control) {
        return Err("unsafe dispatch input".into());
    }
    match key {
        "build_run_id" => validate_run(value),
        "source_sha" | "sha" => validate_sha(value),
        "expected_current" if !safe_token(value) => Err("unsafe expected_current input".into()),
        _ => Ok(()),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
        || (a == 100 && (64..=127).contains(&b)))
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => {
            let bytes = ip.octets();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || bytes[0] & 0xfe == 0xfc
                || (bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80)
                || bytes[0] == 0xff
                || bytes[..12].iter().all(|b| *b == 0)
                || ip.to_ipv4_mapped().is_some())
        }
    }
}

fn url_host(url: &str) -> Result<(String, u16), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or("delivery URL must use HTTPS")?;
    if url.chars().any(|c| c.is_whitespace() || c.is_control())
        || rest.contains(['@', '\\', '%', '#'])
    {
        return Err("unsafe delivery URL".into());
    }
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (host, tail) = v6.split_once(']').ok_or("invalid IPv6 URL")?;
        let port = if tail.is_empty() {
            443
        } else {
            tail.strip_prefix(':')
                .ok_or("invalid URL authority")?
                .parse::<u16>()
                .map_err(|_| "invalid URL port")?
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err("invalid IPv6 host".into());
        }
        (host.to_owned(), port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, port.parse::<u16>().map_err(|_| "invalid URL port")?),
            None => (authority, 443),
        };
        (host.to_ascii_lowercase(), port)
    };
    if host.ends_with('.') {
        return Err("trailing-dot host is unsupported".into());
    }
    if host.is_empty()
        || port == 0
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host == "local"
        || host == "internal"
    {
        return Err("private delivery host".into());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !public_ip(ip) {
            return Err("private delivery IP".into());
        }
    } else if !host.contains('.')
        || host.split('.').any(|p| {
            p.is_empty()
                || p.starts_with('-')
                || p.ends_with('-')
                || !p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
        || host
            .split('.')
            .all(|p| p.bytes().all(|c| c.is_ascii_digit()))
    {
        return Err("invalid delivery hostname".into());
    }
    Ok((host, port))
}

pub fn validate_url(url: &str) -> Result<(), String> {
    url_host(url).map(|_| ())
}

fn relative_file(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.contains(['\\', '\0', ':'])
        || Path::new(path)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err("unsafe artifact path".into());
    }
    if path
        .split('/')
        .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err("unsafe artifact path".into());
    }
    Ok(())
}

fn validate_template(template: &str) -> Result<(), String> {
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        let end = rest[start + 2..]
            .find('}')
            .ok_or("unterminated template token")?
            + start
            + 2;
        if ![
            "sha",
            "source_sha",
            "run_id",
            "attempt",
            "build_run_id",
            "artifact_digest",
            "expected_current",
        ]
        .contains(&&rest[start + 2..end])
        {
            return Err("unknown delivery template token".into());
        }
        rest = &rest[end + 1..];
    }
    if template.chars().any(char::is_control) {
        return Err("control character in template".into());
    }
    Ok(())
}

impl DeliveryContract {
    fn validate(&self) -> Result<(), String> {
        let mut names = BTreeSet::new();
        for rule in &self.post_merge_workflows {
            validate_workflow(&rule.workflow)?;
            if !names.insert(format!("workflow:{}", rule.workflow)) {
                return Err("duplicate workflow rule".into());
            }
            for artifact in &rule.artifacts {
                validate_template(&artifact.name)?;
                relative_file(&artifact.file)?;
            }
            for failure in &rule.failure_states {
                if ![
                    "Delivery Pending",
                    "Waiting New APK",
                    "Pending Prod Promotion",
                ]
                .contains(&failure.waiting_state.as_str())
                    || ![
                        "new_apk_required",
                        "prod_promotion_approval",
                        "delivery_contract_error",
                    ]
                    .contains(&failure.decision_kind.as_str())
                    || failure.options.is_empty()
                    || failure.options.iter().any(|o| o.trim().is_empty())
                {
                    return Err("invalid delivery failure gate".into());
                }
            }
            for check in &rule.health_checks {
                validate_url(check.url())?;
            }
        }
        for rule in &self.promotions {
            if !safe_token(&rule.name) || !names.insert(format!("promotion:{}", rule.name)) {
                return Err("invalid/duplicate promotion name".into());
            }
            validate_workflow(&rule.build_workflow)?;
            validate_workflow(&rule.promote_workflow)?;
            relative_file(&rule.digest_file)?;
            relative_file(&rule.plan_file)?;
            if let Some(file) = &rule.delivery_file {
                relative_file(file)?;
            }
            if rule.delivery_file.is_none()
                && !rule.health_checks.iter().any(
                    |c| matches!(c, HealthCheck::Detailed(spec) if spec.source_sha_field.is_some()),
                )
            {
                return Err(
                    "promotion requires delivery_file or a health check with source_sha_field"
                        .into(),
                );
            }
            validate_template(&rule.artifact_name_template)?;
            validate_template(&rule.plan_artifact_prefix)?;
            if rule.plan_inputs.is_empty()
                || rule.approve_inputs.is_empty()
                || rule.plan_inputs == rule.approve_inputs
            {
                return Err("promotion must declare distinct plan and approval inputs".into());
            }
            for inputs in [&rule.plan_inputs, &rule.approve_inputs] {
                for (key, value) in inputs {
                    validate_key(key)?;
                    validate_template(value)?;
                }
            }
            if rule
                .plan_inputs
                .get("approve_production")
                .is_some_and(|v| v != "false")
                || rule
                    .approve_inputs
                    .get("approve_production")
                    .is_some_and(|v| v != "true")
            {
                return Err("invalid production approval inputs".into());
            }
            if let Some(url) = &rule.current_source_probe {
                validate_url(url)?;
            }
            for check in &rule.health_checks {
                validate_url(check.url())?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowRun {
    pub id: String,
    pub attempt: i64,
    pub completed: bool,
    pub success: bool,
}

pub trait DeliveryDriver {
    fn contract(&mut self, repo: &str, sha: &str) -> ContractLookup;
    fn changed_paths(&mut self, repo: &str, sha: &str) -> Result<Vec<String>, String>;
    fn find_run(
        &mut self,
        repo: &str,
        workflow: &str,
        sha: &str,
        event: &str,
        after: u64,
    ) -> Result<Option<WorkflowRun>, String>;
    fn artifact(
        &mut self,
        repo: &str,
        run: &str,
        name: &str,
        file: &str,
        prefix: bool,
    ) -> Result<Vec<u8>, String>;
    fn failed_logs(&mut self, repo: &str, run: &str) -> Result<String, String>;
    fn dispatch(
        &mut self,
        repo: &str,
        workflow: &str,
        sha: &str,
        inputs: &BTreeMap<String, String>,
    ) -> Result<String, String>;
    fn query_run(
        &mut self,
        repo: &str,
        workflow: &str,
        run_id: &str,
    ) -> Result<Option<WorkflowRun>, String>;
    fn get_https(&mut self, url: &str) -> Result<String, String>;
    fn sync_board(&mut self, _task: &TaskRecord) -> Result<(), String> {
        Ok(())
    }
}

pub struct SystemDeliveryDriver;

// All subprocesses receive explicit argv; no contract value is executable code.
fn output(mut command: Command, limit: usize) -> Result<Vec<u8>, String> {
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let mut stdout = child.stdout.take().ok_or("missing subprocess stdout")?;
    let stderr = child.stderr.take().ok_or("missing subprocess stderr")?;
    // Drain both pipes concurrently to avoid deadlock. Bound memory even for logs.
    let err_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.take(64 * 1024).read_to_end(&mut bytes);
        bytes
    });
    let mut bytes = Vec::new();
    let read = stdout
        .by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() > limit {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    let errors = err_reader.join().unwrap_or_default();
    read.map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("subprocess output exceeds delivery limit".into());
    }
    if !status.success() {
        return Err(format!(
            "subprocess failed: {}",
            String::from_utf8_lossy(&errors)
        ));
    }
    Ok(bytes)
}

fn gh_bytes(args: &[&str], limit: usize) -> Result<Vec<u8>, String> {
    let mut cmd = Command::new("gh");
    cmd.args(args).env("GH_PROMPT_DISABLED", "1");
    output(cmd, limit)
}

fn gh_json(endpoint: &str) -> Result<Value, String> {
    serde_json::from_slice(&gh_bytes(&["api", endpoint], MAX_ARCHIVE)?).map_err(|e| e.to_string())
}

fn pages(raw: &[u8]) -> Result<Vec<Value>, String> {
    serde_json::Deserializer::from_slice(raw)
        .into_iter::<Value>()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

impl DeliveryDriver for SystemDeliveryDriver {
    fn contract(&mut self, repo: &str, sha: &str) -> ContractLookup {
        if let Err(err) = validate_repo(repo).and_then(|_| validate_sha(sha)) {
            return ContractLookup::FetchError(err);
        }
        let endpoint = format!("repos/{repo}/contents/.github/zach-delivery.yaml?ref={sha}");
        match gh_bytes(
            &[
                "api",
                &endpoint,
                "-H",
                "Accept: application/vnd.github.raw+json",
            ],
            MAX_FILE,
        ) {
            Ok(raw) => match String::from_utf8(raw)
                .map_err(|e| e.to_string())
                .and_then(|s| parse_contract(&s))
            {
                Ok(contract) => ContractLookup::Found(contract),
                Err(err) => ContractLookup::ParseError(err),
            },
            Err(err) if err.contains("(HTTP 404)") => ContractLookup::ContractNotFound,
            Err(err) => ContractLookup::FetchError(err),
        }
    }

    fn changed_paths(&mut self, repo: &str, sha: &str) -> Result<Vec<String>, String> {
        validate_repo(repo)?;
        validate_sha(sha)?;
        // GitHub's files[] compares the merge commit with its first parent,
        // including two-parent merges (equivalent to diff-tree -r -m --first-parent).
        let endpoint = format!("repos/{repo}/commits/{sha}?per_page=100");
        let data = pages(&gh_bytes(&["api", "--paginate", &endpoint], MAX_ARCHIVE)?)?;
        let mut files = Vec::new();
        for page in data {
            for file in page["files"].as_array().ok_or("commit files missing")? {
                files.push(
                    file["filename"]
                        .as_str()
                        .ok_or("filename missing")?
                        .to_owned(),
                );
                // A rename must also match rules covering the old path.
                if let Some(old) = file["previous_filename"].as_str() {
                    files.push(old.to_owned());
                }
            }
        }
        if files.len() >= 3000 {
            return Err("commit file list may be truncated".into());
        }
        Ok(files)
    }

    fn find_run(
        &mut self,
        repo: &str,
        workflow: &str,
        sha: &str,
        event: &str,
        after: u64,
    ) -> Result<Option<WorkflowRun>, String> {
        validate_repo(repo)?;
        validate_workflow(workflow)?;
        validate_sha(sha)?;
        if !["push", "workflow_dispatch"].contains(&event) {
            return Err("invalid workflow event".into());
        }
        let endpoint = format!(
            "repos/{repo}/actions/workflows/{workflow}/runs?head_sha={sha}&event={event}&per_page=100"
        );
        let data = pages(&gh_bytes(&["api", "--paginate", &endpoint], MAX_ARCHIVE)?)?;
        let mut runs = Vec::new();
        for page in data {
            for run in page["workflow_runs"]
                .as_array()
                .ok_or("workflow runs missing")?
            {
                let id = run["id"].as_u64().ok_or("run ID missing")?;
                if id <= after
                    || run["head_sha"].as_str() != Some(sha)
                    || run["event"].as_str() != Some(event)
                {
                    continue;
                }
                runs.push((
                    id,
                    WorkflowRun {
                        id: id.to_string(),
                        attempt: run["run_attempt"].as_i64().unwrap_or(1),
                        completed: run["status"] == "completed",
                        success: run["conclusion"] == "success",
                    },
                ));
            }
        }
        // Return the latest matching run; the caller records a watermark before dispatch.
        runs.sort_by_key(|(id, _)| *id);
        Ok(runs.pop().map(|(_, run)| run))
    }

    fn artifact(
        &mut self,
        repo: &str,
        run: &str,
        name: &str,
        file: &str,
        prefix: bool,
    ) -> Result<Vec<u8>, String> {
        validate_repo(repo)?;
        validate_run(run)?;
        relative_file(file)?;
        if !safe_token(name) {
            return Err("invalid artifact name".into());
        }
        let endpoint = format!("repos/{repo}/actions/runs/{run}/artifacts?per_page=100");
        let mut found = Vec::new();
        for page in pages(&gh_bytes(&["api", "--paginate", &endpoint], MAX_ARCHIVE)?)? {
            for artifact in page["artifacts"].as_array().ok_or("artifacts missing")? {
                if artifact["name"]
                    .as_str()
                    .is_some_and(|n| n == name || (prefix && n.starts_with(name)))
                    && artifact["expired"] == false
                {
                    found.push(artifact.clone());
                }
            }
        }
        if found.iter().any(|a| a["name"] == name) {
            found.retain(|a| a["name"] == name);
        }
        if found.len() != 1 {
            return Err("expected exactly one unexpired delivery artifact".into());
        }
        let id = found[0]["id"].as_u64().ok_or("artifact ID missing")?;
        let archive = gh_bytes(
            &["api", &format!("repos/{repo}/actions/artifacts/{id}/zip")],
            MAX_ARCHIVE,
        )?;
        let entries = validate_zip(&archive)?;
        let temp = IsolatedDir::new()?;
        extract_zip(&archive, &entries, &temp.0)?;
        inspect_tree(&temp.0)?;
        let path = temp.0.join(file);
        let mut handle = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut handle)
            .take(MAX_FILE as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > MAX_FILE {
            return Err("artifact file exceeds 1 MiB".into());
        }
        Ok(bytes)
    }

    fn failed_logs(&mut self, repo: &str, run: &str) -> Result<String, String> {
        validate_repo(repo)?;
        validate_run(run)?;
        String::from_utf8(gh_bytes(
            &["run", "view", run, "--repo", repo, "--log-failed"],
            MAX_FILE,
        )?)
        .map_err(|e| e.to_string())
    }

    fn dispatch(
        &mut self,
        repo: &str,
        workflow: &str,
        sha: &str,
        inputs: &BTreeMap<String, String>,
    ) -> Result<String, String> {
        validate_repo(repo)?;
        validate_workflow(workflow)?;
        validate_sha(sha)?;
        if inputs.len() > 25 {
            return Err("too many dispatch inputs".into());
        }
        for (key, value) in inputs {
            validate_key(key)?;
            validate_input_value(key, value)?;
        }
        // workflow_dispatch accepts a branch/tag ref. Discover the repository's
        // default branch; artifact evidence and inputs remain bound to merge_sha.
        let repository = gh_json(&format!("repos/{repo}"))?;
        let branch = repository["default_branch"]
            .as_str()
            .ok_or("missing default branch")?;
        if branch.is_empty()
            || branch.len() > 255
            || branch.starts_with('-')
            || branch.contains("..")
            || !branch
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        {
            return Err("unsafe dispatch branch".into());
        }
        let endpoint = format!("repos/{repo}/actions/workflows/{workflow}/dispatches");
        let mut child = Command::new("gh")
            .args([
                "api",
                &endpoint,
                "--method",
                "POST",
                "-H",
                "X-GitHub-Api-Version: 2022-11-28",
                "--input",
                "-",
            ])
            .env("GH_PROMPT_DISABLED", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        let body = serde_json::to_vec(
            &json!({"ref": branch, "inputs": inputs, "return_run_details": true}),
        )
        .map_err(|e| e.to_string())?;
        let write = child
            .stdin
            .take()
            .ok_or("missing dispatch stdin")?
            .write_all(&body);
        if write.is_err() {
            let _ = child.kill();
        }
        let mut bytes = Vec::new();
        let read = child
            .stdout
            .take()
            .ok_or("missing dispatch stdout")?
            .take(MAX_FILE as u64 + 1)
            .read_to_end(&mut bytes);
        if read.is_err() || bytes.len() > MAX_FILE {
            let _ = child.kill();
        }
        let status = child.wait().map_err(|e| e.to_string())?;
        write.map_err(|e| e.to_string())?;
        read.map_err(|e| e.to_string())?;
        if !status.success() || bytes.len() > MAX_FILE {
            return Err("workflow dispatch failed; inspect before retrying".into());
        }
        let response: Value = serde_json::from_slice(&bytes)
            .map_err(|_| "dispatch outcome unknown: run ID response missing")?;
        let id = response["workflow_run_id"]
            .as_u64()
            .filter(|id| *id > 0)
            .ok_or("dispatch outcome unknown: run ID missing")?
            .to_string();
        Ok(id)
    }

    fn query_run(
        &mut self,
        repo: &str,
        workflow: &str,
        run_id: &str,
    ) -> Result<Option<WorkflowRun>, String> {
        validate_repo(repo)?;
        validate_workflow(workflow)?;
        validate_run(run_id)?;
        let bytes = match gh_bytes(
            &["api", &format!("repos/{repo}/actions/runs/{run_id}")],
            MAX_FILE,
        ) {
            Ok(bytes) => bytes,
            Err(error) if error.contains("(HTTP 404)") => return Ok(None),
            Err(error) => return Err(error),
        };
        let value: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if value["id"].as_u64().map(|id| id.to_string()).as_deref() != Some(run_id)
            || value["event"] != "workflow_dispatch"
            || value["path"].as_str().and_then(|s| s.split('@').next())
                != Some(format!(".github/workflows/{workflow}").as_str())
        {
            return Err("dispatched run identity mismatch".into());
        }
        Ok(Some(WorkflowRun {
            id: run_id.into(),
            attempt: value["run_attempt"].as_i64().unwrap_or(1),
            completed: value["status"] == "completed",
            success: value["conclusion"] == "success",
        }))
    }

    fn get_https(&mut self, url: &str) -> Result<String, String> {
        let (host, port) = url_host(url)?;
        let addresses: BTreeSet<IpAddr> = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .map(|a| a.ip())
            .collect();
        if addresses.is_empty() || addresses.iter().any(|ip| !public_ip(*ip)) {
            return Err("delivery DNS resolved to a private address".into());
        }
        let ip = addresses.iter().next().ok_or("no delivery address")?;
        let ip_arg = if ip.is_ipv6() {
            format!("[{ip}]")
        } else {
            ip.to_string()
        };
        let host_arg = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        let mut cmd = Command::new("curl");
        cmd.args([
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-redirs",
            "0",
            "--connect-timeout",
            "5",
            "--max-time",
            "15",
            "--fail-with-body",
            "--silent",
            "--show-error",
            "--noproxy",
            "*",
            "--write-out",
            "\n%{http_code}",
            "--resolve",
            &format!("{host_arg}:{port}:{ip_arg}"),
            "--",
            url,
        ]);
        let output = String::from_utf8(output(cmd, MAX_FILE + 8)?).map_err(|e| e.to_string())?;
        let (body, status) = output.rsplit_once('\n').ok_or("missing HTTP status")?;
        if !status.starts_with('2') || status.len() != 3 {
            return Err(format!("health HTTP status {status}"));
        }
        Ok(body.into())
    }

    fn sync_board(&mut self, task: &TaskRecord) -> Result<(), String> {
        sync_project_status(task)
    }
}

struct ZipEntry {
    name: String,
    start: usize,
    end: usize,
    size: usize,
    method: usize,
    crc: u32,
    is_dir: bool,
}

// Bounded raw DEFLATE decoding keeps extraction tied to the archive that was
// validated, without invoking an extractor or adding a dependency.
struct Bits<'a> {
    bytes: &'a [u8],
    bit: usize,
}
impl Bits<'_> {
    fn read(&mut self, count: usize) -> Result<usize, String> {
        if self.bit + count > self.bytes.len() * 8 {
            return Err("truncated DEFLATE stream".into());
        }
        let mut value = 0;
        for i in 0..count {
            value |= (((self.bytes[(self.bit + i) / 8] >> ((self.bit + i) % 8)) & 1) as usize) << i;
        }
        self.bit += count;
        Ok(value)
    }
}

struct Huffman {
    table: Vec<(usize, usize)>,
    max: usize,
}
impl Huffman {
    fn new(lengths: &[usize]) -> Result<Self, String> {
        let max = *lengths.iter().max().unwrap_or(&0);
        if max == 0 {
            return Ok(Self {
                table: vec![(0, 0)],
                max: 0,
            });
        }
        if max > 15 {
            return Err("invalid DEFLATE code lengths".into());
        }
        let mut counts = [0usize; 16];
        for length in lengths {
            if *length > 0 {
                counts[*length] += 1;
            }
        }
        let mut next = [0usize; 16];
        let mut code = 0;
        for bits in 1..=15 {
            code = (code + counts[bits - 1]) << 1;
            next[bits] = code;
            if code + counts[bits] > (1 << bits) {
                return Err("oversubscribed DEFLATE tree".into());
            }
        }
        let mut table = vec![(0, 0); 1 << max];
        for (symbol, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let reversed = next[len].reverse_bits() >> (usize::BITS as usize - len);
            next[len] += 1;
            for slot in (reversed..table.len()).step_by(1 << len) {
                table[slot] = (symbol, len);
            }
        }
        Ok(Self { table, max })
    }
    fn symbol(&self, bits: &mut Bits<'_>) -> Result<usize, String> {
        let available = (bits.bytes.len() * 8 - bits.bit).min(self.max);
        let saved = bits.bit;
        let peek = bits.read(available)?;
        let (symbol, len) = self.table[peek];
        if len == 0 || len > available {
            return Err("invalid DEFLATE symbol".into());
        }
        bits.bit = saved + len;
        Ok(symbol)
    }
}

fn inflate(bytes: &[u8], size: usize) -> Result<Vec<u8>, String> {
    let mut bits = Bits { bytes, bit: 0 };
    let mut out = Vec::with_capacity(size);
    let mut blocks = 0;
    loop {
        blocks += 1;
        if blocks > 256 {
            return Err("DEFLATE block limit exceeded".into());
        }
        let last = bits.read(1)? != 0;
        let kind = bits.read(2)?;
        if kind == 0 {
            bits.bit = bits.bit.div_ceil(8) * 8;
            let len = bits.read(16)?;
            if bits.read(16)? != len ^ 0xffff || out.len() + len > size {
                return Err("invalid stored DEFLATE block".into());
            }
            for _ in 0..len {
                out.push(bits.read(8)? as u8);
            }
        } else if kind <= 2 {
            let (literals, distances) = if kind == 1 {
                let lengths: Vec<usize> = (0..288)
                    .map(|i| match i {
                        0..=143 => 8,
                        144..=255 => 9,
                        256..=279 => 7,
                        _ => 8,
                    })
                    .collect();
                (Huffman::new(&lengths)?, Huffman::new(&[5; 32])?)
            } else {
                let nlit = bits.read(5)? + 257;
                let ndist = bits.read(5)? + 1;
                let ncode = bits.read(4)? + 4;
                if nlit > 286 || ndist > 32 {
                    return Err("invalid dynamic DEFLATE counts".into());
                }
                let order = [
                    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                ];
                let mut lengths = [0; 19];
                for i in 0..ncode {
                    lengths[order[i]] = bits.read(3)?;
                }
                let codes = Huffman::new(&lengths)?;
                let mut lengths = Vec::new();
                while lengths.len() < nlit + ndist {
                    let symbol = codes.symbol(&mut bits)?;
                    let (value, repeat) = match symbol {
                        0..=15 => (symbol, 1),
                        16 => (
                            *lengths.last().ok_or("DEFLATE repeat without prior code")?,
                            bits.read(2)? + 3,
                        ),
                        17 => (0, bits.read(3)? + 3),
                        18 => (0, bits.read(7)? + 11),
                        _ => return Err("invalid DEFLATE length code".into()),
                    };
                    if lengths.len() + repeat > nlit + ndist {
                        return Err("DEFLATE code repeat overflow".into());
                    }
                    lengths.extend(std::iter::repeat_n(value, repeat));
                }
                if lengths[256] == 0 {
                    return Err("DEFLATE end code missing".into());
                }
                (
                    Huffman::new(&lengths[..nlit])?,
                    Huffman::new(&lengths[nlit..])?,
                )
            };
            loop {
                let symbol = literals.symbol(&mut bits)?;
                match symbol {
                    0..=255 => {
                        if out.len() == size {
                            return Err("DEFLATE size exceeded".into());
                        }
                        out.push(symbol as u8);
                    }
                    256 => break,
                    257..=285 => {
                        const LEN: [usize; 29] = [
                            3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51,
                            59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
                        ];
                        const EXTRA: [usize; 29] = [
                            0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4,
                            5, 5, 5, 5, 0,
                        ];
                        const DIST: [usize; 30] = [
                            1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385,
                            513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385,
                            24577,
                        ];
                        const DEXTRA: [usize; 30] = [
                            0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10,
                            10, 11, 11, 12, 12, 13, 13,
                        ];
                        let len = LEN[symbol - 257] + bits.read(EXTRA[symbol - 257])?;
                        let dist = distances.symbol(&mut bits)?;
                        if dist >= 30 {
                            return Err("invalid DEFLATE distance".into());
                        }
                        let back = DIST[dist] + bits.read(DEXTRA[dist])?;
                        if back > out.len() || out.len() + len > size {
                            return Err("DEFLATE distance/size exceeded".into());
                        }
                        for _ in 0..len {
                            out.push(out[out.len() - back]);
                        }
                    }
                    _ => return Err("invalid DEFLATE literal".into()),
                }
            }
        } else {
            return Err("reserved DEFLATE block".into());
        }
        if last {
            break;
        }
    }
    if out.len() != size || bits.bit.div_ceil(8) != bytes.len() {
        return Err("DEFLATE size mismatch".into());
    }
    Ok(out)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn extract_zip(bytes: &[u8], entries: &[ZipEntry], root: &Path) -> Result<(), String> {
    for entry in entries {
        let path = root.join(&entry.name);
        if entry.is_dir {
            fs::create_dir_all(path).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let compressed = &bytes[entry.start..entry.end];
        let data = if entry.method == 8 {
            inflate(compressed, entry.size)?
        } else {
            compressed.to_vec()
        };
        if data.len() != entry.size || crc32(&data) != entry.crc {
            return Err("ZIP content checksum/size mismatch".into());
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .and_then(|mut file| file.write_all(&data))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

struct IsolatedDir(PathBuf);
impl IsolatedDir {
    fn new() -> Result<Self, String> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..10 {
            #[cfg(not(test))]
            let base = std::env::temp_dir();
            #[cfg(test)]
            let base = {
                let base = std::env::current_dir()
                    .map_err(|e| e.to_string())?
                    .join("target/delivery-tests");
                fs::create_dir_all(&base).map_err(|e| e.to_string())?;
                base
            };
            let path = base.join(format!(
                "zach-delivery-{}-{}-{}",
                std::process::id(),
                now_epoch(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.to_string()),
            }
        }
        Err("unable to create isolated artifact directory".into())
    }
}
impl Drop for IsolatedDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn inspect_tree(path: &Path) -> Result<(), String> {
    let mut entries = vec![path.to_path_buf()];
    let mut count = 0;
    let mut total = 0;
    while let Some(entry) = entries.pop() {
        count += 1;
        if count > 1024 {
            return Err("too many artifact entries".into());
        }
        let meta = fs::symlink_metadata(&entry).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            return Err("artifact symlink rejected".into());
        }
        if meta.is_dir() {
            for child in fs::read_dir(&entry).map_err(|e| e.to_string())? {
                entries.push(child.map_err(|e| e.to_string())?.path());
            }
        } else if !meta.is_file() || meta.len() > MAX_FILE as u64 {
            return Err("unsafe or oversized artifact entry".into());
        } else {
            total += meta.len();
            if total > MAX_ARCHIVE as u64 {
                return Err("artifact extraction limit exceeded".into());
            }
        }
    }
    Ok(())
}

// Preflight central and local ZIP headers, including Unix symlink mode bits.
// ZIP64, encrypted archives and ambiguous names are deliberately unsupported.
fn validate_zip(bytes: &[u8]) -> Result<Vec<ZipEntry>, String> {
    let u16_at = |offset: usize| -> Result<usize, String> {
        let b = bytes.get(offset..offset + 2).ok_or("truncated ZIP")?;
        Ok(u16::from_le_bytes([b[0], b[1]]) as usize)
    };
    let u32_at = |offset: usize| -> Result<usize, String> {
        let b = bytes.get(offset..offset + 4).ok_or("truncated ZIP")?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    let end = (bytes.len().saturating_sub(65557)..bytes.len().saturating_sub(21))
        .rev()
        .find(|i| bytes.get(*i..*i + 4) == Some(b"PK\x05\x06"))
        .ok_or("ZIP end record missing")?;
    if u16_at(end + 4)? != 0
        || u16_at(end + 6)? != 0
        || u16_at(end + 8)? != u16_at(end + 10)?
        || end + 22 + u16_at(end + 20)? != bytes.len()
    {
        return Err("unsupported ZIP archive".into());
    }
    let count = u16_at(end + 10)?;
    if count == 0 || count > 1024 {
        return Err("invalid ZIP entry count".into());
    }
    let mut pos = u32_at(end + 16)?;
    let central_end = pos
        .checked_add(u32_at(end + 12)?)
        .ok_or("invalid ZIP size")?;
    if central_end != end {
        return Err("unsupported ZIP central directory".into());
    }
    let mut total = 0;
    let mut names = BTreeSet::new();
    let mut entries = Vec::new();
    for _ in 0..count {
        if bytes.get(pos..pos + 4) != Some(b"PK\x01\x02") {
            return Err("invalid ZIP central entry".into());
        }
        if u16_at(pos + 8)? & 1 != 0 {
            return Err("encrypted ZIP rejected".into());
        }
        let mode = u32_at(pos + 38)? >> 16;
        if mode & 0xf000 == 0xa000
            || (mode & 0xf000 != 0 && ![0x8000, 0x4000].contains(&(mode & 0xf000)))
        {
            return Err("ZIP symlink/special file rejected".into());
        }
        let size = u32_at(pos + 24)?;
        total += size;
        if size > MAX_FILE || total > MAX_ARCHIVE {
            return Err("oversized ZIP entry".into());
        }
        let name_len = u16_at(pos + 28)?;
        let name_bytes = bytes
            .get(pos + 46..pos + 46 + name_len)
            .ok_or("truncated ZIP name")?;
        let name = std::str::from_utf8(name_bytes).map_err(|e| e.to_string())?;
        relative_file(name.trim_end_matches('/'))?;
        if !names.insert(name.trim_end_matches('/')) {
            return Err("duplicate ZIP path".into());
        }
        let local = u32_at(pos + 42)?;
        if bytes.get(local..local + 4) != Some(b"PK\x03\x04")
            || u16_at(local + 26)? != name_len
            || bytes.get(local + 30..local + 30 + name_len) != Some(name_bytes)
            || u16_at(local + 6)? & 1 != 0
        {
            return Err("ZIP local header mismatch".into());
        }
        let data_end = local
            .checked_add(30 + name_len + u16_at(local + 28)?)
            .and_then(|v| v.checked_add(u32_at(pos + 20).ok()?))
            .ok_or("invalid ZIP bounds")?;
        if data_end > u32_at(end + 16)? {
            return Err("invalid ZIP data extent".into());
        }
        let start = local + 30 + name_len + u16_at(local + 28)?;
        let method = u16_at(pos + 10)?;
        if ![0, 8].contains(&method) || method != u16_at(local + 8)? {
            return Err("unsupported ZIP compression".into());
        }
        let is_dir = name.ends_with('/');
        if is_dir && size != 0 {
            return Err("invalid ZIP directory".into());
        }
        entries.push(ZipEntry {
            name: name.into(),
            start,
            end: data_end,
            size,
            method,
            crc: u32_at(pos + 16)? as u32,
            is_dir,
        });
        pos += 46 + name_len + u16_at(pos + 30)? + u16_at(pos + 32)?;
    }
    if pos != central_end {
        return Err("ZIP entry count mismatch".into());
    }
    Ok(entries)
}

/// Only delivery waiting states map to the existing board's Blocked column.
/// SQLite remains authoritative for their precise meanings.
pub fn board_status(status: &str) -> &str {
    match status {
        "Delivery Pending" | "Waiting New APK" | "Pending Prod Promotion" | "Delivery Aborted" => {
            "Blocked"
        }
        other => other,
    }
}

fn graphql(query: &str, variables: Value) -> Result<Value, String> {
    // GraphQL variables use JSON stdin too; repository/issue values never enter query text.
    let body = json!({"query": query, "variables": variables});
    let mut child = Command::new("gh")
        .args(["api", "graphql", "--input", "-"])
        .env("GH_PROMPT_DISABLED", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let write = child
        .stdin
        .take()
        .ok_or("missing graphql stdin")?
        .write_all(&serde_json::to_vec(&body).map_err(|e| e.to_string())?);
    if write.is_err() {
        let _ = child.kill();
    }
    let mut bytes = Vec::new();
    child
        .stdout
        .take()
        .ok_or("missing graphql stdout")?
        .take(MAX_ARCHIVE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_ARCHIVE {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    write.map_err(|e| e.to_string())?;
    if !status.success() || bytes.len() > MAX_ARCHIVE {
        return Err("board GraphQL request failed".into());
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if value.get("errors").is_some() {
        return Err("board GraphQL returned errors".into());
    }
    Ok(value)
}

fn sync_project_status(task: &TaskRecord) -> Result<(), String> {
    let repo = task
        .github_repo
        .as_deref()
        .ok_or("missing GitHub repository")?;
    validate_repo(repo)?;
    let (owner, name) = repo.split_once('/').ok_or("invalid repository")?;
    let number = task
        .issue_number
        .filter(|n| *n > 0)
        .ok_or("missing issue number")?;
    let data = graphql(
        "query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){issue(number:$number){projectItems(first:100){pageInfo{hasNextPage} nodes{id project{id} fieldValues(first:100){pageInfo{hasNextPage} nodes{... on ProjectV2ItemFieldSingleSelectValue{name field{... on ProjectV2SingleSelectField{id name options{id name}}}}}}}}}}}",
        json!({"owner":owner,"name":name,"number":number}),
    )?;
    let items = &data["data"]["repository"]["issue"]["projectItems"];
    if items["pageInfo"]["hasNextPage"] == true {
        return Err("too many issue projects".into());
    }
    let configured = std::env::var("ZACH_PROJECT_ID").ok();
    let mut matches = Vec::new();
    for item in items["nodes"]
        .as_array()
        .ok_or("issue project items missing")?
    {
        if configured
            .as_deref()
            .is_some_and(|id| item["project"]["id"] != id)
        {
            continue;
        }
        if item["fieldValues"]["pageInfo"]["hasNextPage"] == true {
            return Err("too many board fields".into());
        }
        for field in item["fieldValues"]["nodes"]
            .as_array()
            .ok_or("board field values missing")?
        {
            if field["field"]["name"] != "Status" {
                continue;
            }
            for option in field["field"]["options"]
                .as_array()
                .ok_or("board status options missing")?
            {
                if option["name"] == board_status(&task.status) {
                    matches.push((item.clone(), field.clone(), option.clone()));
                }
            }
        }
    }
    if matches.len() != 1 {
        return Err("delivery board must resolve to one project (set ZACH_PROJECT_ID)".into());
    }
    let (item, field, option) = &matches[0];
    if field["name"] == board_status(&task.status) {
        return Ok(());
    }
    graphql(
        "mutation($project:ID!,$item:ID!,$field:ID!,$option:String!){updateProjectV2ItemFieldValue(input:{projectId:$project,itemId:$item,fieldId:$field,value:{singleSelectOptionId:$option}}){projectV2Item{id}}}",
        json!({"project":item["project"]["id"],"item":item["id"],"field":field["field"]["id"],"option":option["id"]}),
    )?;
    Ok(())
}

/// Filter using check-run IDs belonging to the declared workflow runs, rather
/// than job display names (which need not resemble workflow filenames).
pub fn query_contract_ci(
    repo: &str,
    sha: &str,
    excluded: &[String],
) -> Result<CiCheckState, String> {
    validate_repo(repo)?;
    validate_sha(sha)?;
    let mut excluded_ids = BTreeSet::new();
    for workflow in excluded {
        validate_workflow(workflow)?;
        let endpoint =
            format!("repos/{repo}/actions/workflows/{workflow}/runs?head_sha={sha}&per_page=100");
        for page in pages(&gh_bytes(&["api", "--paginate", &endpoint], MAX_ARCHIVE)?)? {
            for run in page["workflow_runs"]
                .as_array()
                .ok_or("workflow runs missing")?
            {
                if run["head_sha"].as_str() != Some(sha) {
                    continue;
                }
                let id = run["id"].as_u64().ok_or("run ID missing")?;
                let jobs = format!("repos/{repo}/actions/runs/{id}/jobs?filter=all&per_page=100");
                for jobs_page in pages(&gh_bytes(&["api", "--paginate", &jobs], MAX_ARCHIVE)?)? {
                    for job in jobs_page["jobs"]
                        .as_array()
                        .ok_or("workflow jobs missing")?
                    {
                        excluded_ids.insert(
                            job["check_run_url"]
                                .as_str()
                                .and_then(|u| u.rsplit('/').next())
                                .and_then(|id| id.parse::<u64>().ok())
                                .ok_or("check-run URL/ID missing")?,
                        );
                    }
                }
            }
        }
    }
    let endpoint = format!("repos/{repo}/commits/{sha}/check-runs?per_page=100");
    evaluate_delivery_checks(
        pages(&gh_bytes(&["api", "--paginate", &endpoint], MAX_ARCHIVE)?)?,
        &excluded_ids,
    )
}

fn evaluate_delivery_checks(
    pages: Vec<Value>,
    excluded_ids: &BTreeSet<u64>,
) -> Result<CiCheckState, String> {
    let mut checks = Vec::new();
    let mut removed = false;
    for page in pages {
        for check in page["check_runs"].as_array().ok_or("check-runs missing")? {
            if check["id"]
                .as_u64()
                .is_some_and(|id| excluded_ids.contains(&id))
            {
                removed = true;
            } else {
                checks.push(check.clone());
            }
        }
    }
    if checks.is_empty() && removed {
        return Ok(CiCheckState::Success {
            passed_checks: Vec::new(),
        });
    }
    evaluate_check_runs_json(&json!({"check_runs": checks}).to_string())
}

fn matches_rule(patterns: &[String], changed: &[String]) -> bool {
    patterns.is_empty()
        || patterns.iter().any(|pattern| {
            changed
                .iter()
                .any(|path| matches_path_pattern(path, pattern))
        })
}

fn new_row(
    task: &TaskRecord,
    sha: &str,
    kind: &str,
    name: &str,
    workflow: &str,
    rule: Value,
) -> PostMergeDelivery {
    PostMergeDelivery {
        delivery_id: format!("{}:{sha}:{kind}:{name}", task.task_id),
        task_id: task.task_id.clone(),
        repository: task.repository.clone(),
        github_repo: task.github_repo.clone().unwrap_or_default(),
        merge_sha: sha.to_owned(),
        kind: kind.into(),
        name: name.into(),
        state: "pending".into(),
        workflow: workflow.into(),
        run_id: None,
        build_run_id: None,
        artifact_digest: None,
        expected_current: None,
        evidence_json: json!({}),
        rule_json: rule,
        decision_id: None,
        attempt: 1,
        updated_epoch: now_epoch(),
    }
}

pub fn seed_deliveries(
    task: &TaskRecord,
    sha: &str,
    contract: &DeliveryContract,
    changed: &[String],
) -> Vec<PostMergeDelivery> {
    let mut rows = Vec::new();
    for rule in &contract.post_merge_workflows {
        if matches_rule(&rule.when_paths, changed) {
            rows.push(new_row(
                task,
                sha,
                "workflow",
                &rule.workflow,
                &rule.workflow,
                json!(rule),
            ));
        }
    }
    for rule in &contract.promotions {
        if matches_rule(&rule.when_paths, changed) {
            rows.push(new_row(
                task,
                sha,
                "promotion",
                &rule.name,
                &rule.promote_workflow,
                json!(rule),
            ));
        }
    }
    rows
}

pub fn contract_error_row(task: &TaskRecord, sha: &str, error: &str) -> PostMergeDelivery {
    let mut row = new_row(task, sha, "contract", "contract", "", json!({}));
    row.evidence_json["error"] = json!(error);
    row
}

fn render(
    template: &str,
    row: &PostMergeDelivery,
    run: Option<&WorkflowRun>,
) -> Result<String, String> {
    validate_sha(&row.merge_sha)?;
    for id in [
        row.build_run_id.as_deref(),
        row.run_id.as_deref(),
        run.map(|r| r.id.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        validate_run(id)?;
    }
    if let Some(current) = &row.expected_current
        && !safe_token(current)
    {
        return Err("unsafe expected_current token".into());
    }
    if let Some(digest) = &row.artifact_digest
        && (digest.len() != 64 || !digest.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return Err("invalid artifact digest".into());
    }
    validate_template(template)?;
    let mut value = template.to_owned();
    let run_id = run
        .map(|r| r.id.as_str())
        .or(row.run_id.as_deref())
        .unwrap_or("");
    let attempt = run.map(|r| r.attempt).unwrap_or(row.attempt).to_string();
    for (key, replacement) in [
        ("sha", row.merge_sha.as_str()),
        ("source_sha", row.merge_sha.as_str()),
        ("run_id", run_id),
        ("attempt", attempt.as_str()),
        ("build_run_id", row.build_run_id.as_deref().unwrap_or("")),
        (
            "artifact_digest",
            row.artifact_digest.as_deref().unwrap_or(""),
        ),
        (
            "expected_current",
            row.expected_current.as_deref().unwrap_or("none"),
        ),
    ] {
        let token = format!("${{{key}}}");
        if value.contains(&token) && replacement.is_empty() {
            return Err(format!("missing template value {key}"));
        }
        value = value.replace(&token, replacement);
    }
    Ok(value)
}

/// Store calls are short coordinator operations. Network calls stay on the
/// polling worker; each durable checkpoint is acknowledged before it continues.
pub trait DeliveryStore {
    fn access<T: Send + 'static>(
        &mut self,
        operation: impl FnOnce(&mut V2Store) -> Result<T, V2StoreError> + Send + 'static,
    ) -> Result<T, V2StoreError>;

    fn get_task(&mut self, id: &str) -> Result<Option<TaskRecord>, V2StoreError> {
        let id = id.to_owned();
        self.access(move |store| V2Store::get_task(store, &id))
    }
    fn list_deliveries(
        &mut self,
        id: Option<&str>,
    ) -> Result<Vec<PostMergeDelivery>, V2StoreError> {
        let id = id.map(str::to_owned);
        self.access(move |store| V2Store::list_deliveries(store, id.as_deref()))
    }
    fn append_event(
        &mut self,
        task: &str,
        group: &str,
        kind: &str,
        payload: &Value,
    ) -> Result<crate::v2::store::TaskEventRecord, V2StoreError> {
        let (task, group, kind, payload) = (
            task.to_owned(),
            group.to_owned(),
            kind.to_owned(),
            payload.clone(),
        );
        self.access(move |store| store.append_event(&task, &group, &kind, &payload))
    }
    fn mark_delivery_board_synced(
        &mut self,
        task: &str,
        version: i64,
        status: &str,
    ) -> Result<bool, V2StoreError> {
        let (task, status) = (task.to_owned(), status.to_owned());
        self.access(move |store| store.mark_delivery_board_synced(&task, version, &status))
    }
}

impl DeliveryStore for V2Store {
    fn access<T: Send + 'static>(
        &mut self,
        operation: impl FnOnce(&mut V2Store) -> Result<T, V2StoreError> + Send + 'static,
    ) -> Result<T, V2StoreError> {
        operation(self)
    }
}

fn checkpoint(
    store: &mut impl DeliveryStore,
    row: &PostMergeDelivery,
    status: &str,
) -> Result<(), String> {
    let row = row.clone();
    let status = status.to_owned();
    store
        .access(move |store| {
            (|| -> Result<(), String> {
                let mut task = store
                    .get_task(&row.task_id)
                    .map_err(|e| e.to_string())?
                    .ok_or("delivery task missing")?;
                if !task.autonomous_consent
                    || task.memory.halt_requested
                    || matches!(
                        task.status.as_str(),
                        "Done" | "Cancelled" | "Delivery Aborted"
                    )
                {
                    return Err("delivery task is already terminal".into());
                }
                task.status = status;
                task.current_stage = None;
                task.active_attempt_id = None;
                let mut saved = row.clone();
                saved.updated_epoch = now_epoch();
                store
                    .save_deliveries_and_task(&task, std::slice::from_ref(&saved))
                    .map_err(|e| e.to_string())
            })()
            .map_err(V2StoreError)
        })
        .map_err(|e| e.to_string())
}

fn open_gate(
    store: &mut impl DeliveryStore,
    row: &mut PostMergeDelivery,
    kind: &str,
    status: &str,
    options: &[String],
    context: &str,
) -> Result<(), String> {
    let mut row = row.clone();
    let (kind, status, options, context) = (
        kind.to_owned(),
        status.to_owned(),
        options.to_vec(),
        context.to_owned(),
    );
    store
        .access(move |store| {
            (|| -> Result<(), String> {
                let task = store
                    .get_task(&row.task_id)
                    .map_err(|e| e.to_string())?
                    .ok_or("delivery task missing")?;
                if !task.autonomous_consent
                    || task.memory.halt_requested
                    || matches!(
                        task.status.as_str(),
                        "Done" | "Cancelled" | "Delivery Aborted"
                    )
                {
                    return Ok(());
                }
                if row.state == "waiting"
                    && let Some(id) = &row.decision_id
                    && store.get_decision(id).map_err(|e| e.to_string())?.is_some()
                {
                    // Resolution already updated the persisted row in its transaction.
                    // A stale tick must not replace that resolved gate with another one.
                    return Ok(());
                }
                let id = if row.state == "waiting"
                    && row
                        .decision_id
                        .as_ref()
                        .is_some_and(|id| store.get_decision(id).ok().flatten().is_none())
                {
                    row.decision_id.clone().ok_or("missing gate ID")?
                } else {
                    format!(
                        "{}:{}:{}:{}:{}",
                        row.delivery_id,
                        row.attempt,
                        row.run_id.as_deref().unwrap_or("0"),
                        kind,
                        task.version
                    )
                };
                row.decision_id = Some(id.clone());
                row.state = "waiting".into();
                row.evidence_json["gate_kind"] = json!(kind);
                row.evidence_json["waiting_status"] = json!(status);
                row.evidence_json["gate_options"] = json!(options);
                row.evidence_json["gate_context"] = json!(context);
                checkpoint(store, &row, &status)?;
                if store
                    .get_decision(&id)
                    .map_err(|e| e.to_string())?
                    .is_none()
                {
                    store
                        .open_decision(
                            &id,
                            &task.task_id,
                            &task.task_group,
                            &kind,
                            &context,
                            &options,
                            Some(0),
                            &context,
                            Some(&row.merge_sha),
                        )
                        .map_err(|e| e.to_string())?;
                }
                Ok(())
            })()
            .map_err(V2StoreError)
        })
        .map_err(|e| e.to_string())
}

fn error_gate(
    store: &mut impl DeliveryStore,
    row: &mut PostMergeDelivery,
    error: &str,
) -> Result<(), String> {
    row.evidence_json["error"] = json!(error);
    let context = format!(
        "Delivery {} at {} requires intervention: {error}",
        row.name, row.merge_sha
    );
    open_gate(
        store,
        row,
        "delivery_contract_error",
        "Delivery Pending",
        &["Retry".into(), "Abort".into()],
        &context,
    )
}

fn check_health(
    driver: &mut dyn DeliveryDriver,
    checks: &[HealthCheck],
    sha: &str,
) -> Result<(), String> {
    for check in checks {
        validate_url(check.url())?;
        let body = driver.get_https(check.url())?;
        if let HealthCheck::Detailed(spec) = check {
            if spec
                .contains
                .as_ref()
                .is_some_and(|text| !body.contains(&text.replace("${source_sha}", sha)))
            {
                return Err("health check body did not match".into());
            }
            if let Some(field) = &spec.source_sha_field {
                let value: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
                if value.get(field).and_then(Value::as_str) != Some(sha) {
                    return Err("health check source SHA mismatch".into());
                }
            }
        }
    }
    Ok(())
}

fn artifact_json(
    driver: &mut dyn DeliveryDriver,
    row: &PostMergeDelivery,
    run: &WorkflowRun,
    name: &str,
    file: &str,
    prefix: bool,
) -> Result<Value, String> {
    let name = render(name, row, Some(run))?;
    let bytes = driver.artifact(&row.github_repo, &run.id, &name, file, prefix)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if value["source_sha"].as_str() != Some(&row.merge_sha) {
        return Err("artifact source_sha mismatch".into());
    }
    Ok(value)
}

fn probe(driver: &mut dyn DeliveryDriver, rule: &Promotion) -> Result<String, String> {
    let Some(url) = &rule.current_source_probe else {
        return Ok("none".into());
    };
    let body = driver.get_https(url)?;
    let token = match serde_json::from_str::<Value>(&body) {
        Ok(Value::Object(map)) => map
            .get("source_sha")
            .and_then(Value::as_str)
            .ok_or("probe missing source_sha")?
            .to_owned(),
        Ok(Value::String(token)) => token,
        _ => body.trim().to_owned(),
    };
    if !safe_token(&token) {
        return Err("unsafe current source probe value".into());
    }
    Ok(token)
}

fn workflow_tick(
    store: &mut impl DeliveryStore,
    driver: &mut dyn DeliveryDriver,
    row: &mut PostMergeDelivery,
) -> Result<(), String> {
    let rule: WorkflowDelivery =
        serde_json::from_value(row.rule_json.clone()).map_err(|e| e.to_string())?;
    let Some(run) = driver.find_run(&row.github_repo, &rule.workflow, &row.merge_sha, "push", 0)?
    else {
        return Ok(());
    };
    // A retried job can retain its run ID; require a newer run or run_attempt.
    if let Some(prior) = row
        .evidence_json
        .get("failed_run_id")
        .and_then(Value::as_str)
        && prior == run.id
        && run.attempt
            <= row.evidence_json["failed_run_attempt"]
                .as_i64()
                .unwrap_or(1)
    {
        return Ok(());
    }
    row.run_id = Some(run.id.clone());
    if !run.completed {
        return checkpoint(store, row, "Delivery Pending");
    }
    if !run.success {
        let logs = driver.failed_logs(&row.github_repo, &run.id)?;
        row.evidence_json["failed_run_id"] = json!(run.id);
        row.evidence_json["failed_run_attempt"] = json!(run.attempt);
        for failure in &rule.failure_states {
            if failure.marker.is_empty() || logs.contains(&failure.marker) {
                let context = format!(
                    "{} for source {} (run {}, attempt {})",
                    failure.decision_kind, row.merge_sha, run.id, run.attempt
                );
                return open_gate(
                    store,
                    row,
                    &failure.decision_kind,
                    &failure.waiting_state,
                    &failure.options,
                    &context,
                );
            }
        }
        return Err(format!("delivery workflow failed (run {})", run.id));
    }
    let mut artifacts = Vec::new();
    for artifact in &rule.artifacts {
        let value = artifact_json(driver, row, &run, &artifact.name, &artifact.file, false)?;
        if value
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|s| {
                ["failed", "failure", "error", "NEW_APK_REQUIRED"]
                    .iter()
                    .any(|bad| s.eq_ignore_ascii_case(bad))
            })
        {
            return Err("delivery artifact reports a failure".into());
        }
        artifacts.push(value);
    }
    row.evidence_json["artifacts"] = json!(artifacts);
    check_health(driver, &rule.health_checks, &row.merge_sha)?;
    row.state = "verified".into();
    checkpoint(store, row, "Delivery Pending")
}

fn verify_plan(value: &Value, row: &PostMergeDelivery) -> Result<(), String> {
    if value
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|s| {
            ["failed", "failure", "error", "blocked", "NEW_APK_REQUIRED"]
                .iter()
                .any(|bad| s.eq_ignore_ascii_case(bad))
        })
    {
        return Err("promotion artifact reports a failure".into());
    }

    let digest = value["artifact_digest"]
        .as_str()
        .or(value["artifact_sha256"].as_str());
    let build = value["build_run_id"]
        .as_str()
        .map(str::to_owned)
        .or_else(|| value["build_run_id"].as_u64().map(|v| v.to_string()));
    if value["source_sha"].as_str() != Some(&row.merge_sha)
        || build.as_deref() != row.build_run_id.as_deref()
        || digest != row.artifact_digest.as_deref()
        || value["expected_current"].as_str() != row.expected_current.as_deref()
    {
        return Err(
            "promotion artifact does not match the approved build/source/digest/current".into(),
        );
    }
    Ok(())
}

fn promotion_tick(
    store: &mut impl DeliveryStore,
    driver: &mut dyn DeliveryDriver,
    row: &mut PostMergeDelivery,
) -> Result<(), String> {
    let rule: Promotion =
        serde_json::from_value(row.rule_json.clone()).map_err(|e| e.to_string())?;
    match row.state.as_str() {
        "pending" => {
            let Some(run) = driver.find_run(
                &row.github_repo,
                &rule.build_workflow,
                &row.merge_sha,
                "push",
                0,
            )?
            else {
                return Ok(());
            };
            if !run.completed {
                return Ok(());
            }
            if !run.success {
                return Err("promotion build failed".into());
            }
            let name = render(&rule.artifact_name_template, row, Some(&run))?;
            let bytes =
                driver.artifact(&row.github_repo, &run.id, &name, &rule.digest_file, false)?;
            let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
            let digest = text
                .split_whitespace()
                .next()
                .ok_or("missing artifact digest")?;
            if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid artifact digest".into());
            }
            row.build_run_id = Some(run.id);
            row.artifact_digest = Some(digest.to_owned());
            row.expected_current = Some(probe(driver, &rule)?);
            row.state = "plan_dispatch".into();
            checkpoint(store, row, "Delivery Pending")
        }
        "plan_dispatch" | "approved" => {
            let approved = row.state == "approved";
            if approved && probe(driver, &rule)? != row.expected_current.clone().unwrap_or_default()
            {
                // The approval was for a different production base. Re-plan and
                // require a fresh gate; never silently deploy across this race.
                row.state = "pending".into();
                row.attempt += 1;
                row.decision_id = None;
                return checkpoint(store, row, "Delivery Pending");
            }
            let inputs = if approved {
                &rule.approve_inputs
            } else {
                &rule.plan_inputs
            };
            let inputs: BTreeMap<String, String> = inputs
                .iter()
                .map(|(k, v)| render(v, row, None).map(|value| (k.clone(), value)))
                .collect::<Result<_, _>>()?;
            // Persist intent before dispatch; the API returns the exact run ID.
            // An interrupted request is never automatically redispatched.
            row.run_id = None;
            row.state = if approved {
                "approve_dispatching"
            } else {
                "plan_dispatching"
            }
            .into();
            checkpoint(store, row, "Delivery Pending")?;
            let run_id = driver.dispatch(
                &row.github_repo,
                &rule.promote_workflow,
                &row.merge_sha,
                &inputs,
            )?;
            validate_run(&run_id)?;
            row.evidence_json[if approved {
                "approve_dispatch_run_id"
            } else {
                "plan_dispatch_run_id"
            }] = json!(run_id);
            row.run_id = Some(run_id);
            row.state = if approved {
                "approve_waiting"
            } else {
                "plan_waiting"
            }
            .into();
            checkpoint(store, row, "Delivery Pending")
        }
        "plan_dispatching" | "approve_dispatching" => Err(
            "dispatch outcome unknown after interruption; inspect workflow runs before retry"
                .into(),
        ),
        "plan_waiting" | "approve_waiting" => {
            let approved = row.state == "approve_waiting";
            let id = row.run_id.as_deref().ok_or("dispatched run ID missing")?;
            let Some(run) = driver.query_run(&row.github_repo, &rule.promote_workflow, id)? else {
                return Ok(());
            };
            if !run.completed {
                return checkpoint(store, row, "Delivery Pending");
            }
            if !run.success {
                return Err(format!(
                    "promotion {} run failed",
                    if approved { "approval" } else { "plan" }
                ));
            }
            let value = if !approved || rule.delivery_file.is_some() {
                let name = render(&rule.plan_artifact_prefix, row, Some(&run))?;
                let file = if approved {
                    rule.delivery_file
                        .as_deref()
                        .ok_or("delivery file missing")?
                } else {
                    &rule.plan_file
                };
                let value = artifact_json(driver, row, &run, &name, file, true)?;
                verify_plan(&value, row)?;
                value
            } else {
                json!({"source_sha": row.merge_sha, "run_id": run.id})
            };
            row.evidence_json[if approved { "promotion" } else { "plan" }] = value;
            if approved {
                check_health(driver, &rule.health_checks, &row.merge_sha)?;
                row.state = "verified".into();
                checkpoint(store, row, "Delivery Pending")
            } else {
                let context = format!(
                    "Approve production promotion {}? build_run_id={}, source_sha={}, artifact_digest={}, expected_current={}",
                    row.name,
                    row.build_run_id.as_deref().unwrap_or(""),
                    row.merge_sha,
                    row.artifact_digest.as_deref().unwrap_or(""),
                    row.expected_current.as_deref().unwrap_or("")
                );
                open_gate(
                    store,
                    row,
                    "prod_promotion_approval",
                    "Pending Prod Promotion",
                    &["Approve".into(), "Retry".into(), "Reject".into()],
                    &context,
                )
            }
        }
        other => Err(format!("unknown promotion state {other}")),
    }
}

fn contract_tick(
    store: &mut impl DeliveryStore,
    driver: &mut dyn DeliveryDriver,
    row: &mut PostMergeDelivery,
) -> Result<(), String> {
    let task = store
        .get_task(&row.task_id)
        .map_err(|e| e.to_string())?
        .ok_or("delivery task missing")?;
    let mut rows = match driver.contract(&row.github_repo, &row.merge_sha) {
        ContractLookup::ContractNotFound => Vec::new(),
        ContractLookup::Found(contract) => {
            let paths = driver.changed_paths(&row.github_repo, &row.merge_sha)?;
            seed_deliveries(&task, &row.merge_sha, &contract, &paths)
        }
        ContractLookup::FetchError(err) | ContractLookup::ParseError(err) => return Err(err),
    };
    row.state = "verified".into();
    rows.push(row.clone());
    let task_id = task.task_id;
    store
        .access(move |store| {
            let task = store
                .get_task(&task_id)?
                .ok_or_else(|| V2StoreError("delivery task missing".into()))?;
            if !task.autonomous_consent
                || task.memory.halt_requested
                || matches!(
                    task.status.as_str(),
                    "Done" | "Cancelled" | "Delivery Aborted"
                )
            {
                return Ok(());
            }
            store.save_deliveries_and_task(&task, &rows)
        })
        .map_err(|e| e.to_string())
}

/// One bounded observation/transition per row per tick, with no workflow wait or
/// sleep loop. The daemon runs this on a bounded worker using coordinator store access.
pub fn poll_post_merge_deliveries(
    store: &mut impl DeliveryStore,
    driver: &mut dyn DeliveryDriver,
) -> Result<(), String> {
    let rows = store.list_deliveries(None).map_err(|e| e.to_string())?;
    let mut tasks = BTreeSet::new();
    for mut row in rows {
        let Some(task) = store.get_task(&row.task_id).map_err(|e| e.to_string())? else {
            continue;
        };
        if !task.autonomous_consent
            || task.memory.halt_requested
            || matches!(task.status.as_str(), "Cancelled" | "Delivery Aborted")
        {
            continue;
        }
        if task.status == "Done" {
            if row.state == "verified" && row.evidence_json["board_synced_status"] != "Done" {
                tasks.insert(row.task_id.clone());
            }
            continue;
        }
        tasks.insert(row.task_id.clone());
        if matches!(row.state.as_str(), "verified" | "aborted") {
            continue;
        }
        let result = if row.state == "waiting" {
            // Repair a crash between persisting the gate and creating its decision.
            let kind = row.evidence_json["gate_kind"]
                .as_str()
                .unwrap_or("delivery_contract_error")
                .to_owned();
            let status = row.evidence_json["waiting_status"]
                .as_str()
                .unwrap_or("Delivery Pending")
                .to_owned();
            let options = serde_json::from_value(row.evidence_json["gate_options"].clone())
                .unwrap_or_else(|_| vec!["Retry".into(), "Abort".into()]);
            let context = row.evidence_json["gate_context"]
                .as_str()
                .unwrap_or("Delivery requires intervention")
                .to_owned();
            open_gate(store, &mut row, &kind, &status, &options, &context)
        } else {
            match row.kind.as_str() {
                "contract" => contract_tick(store, driver, &mut row),
                "workflow" => workflow_tick(store, driver, &mut row),
                "promotion" => promotion_tick(store, driver, &mut row),
                _ => Err("unknown delivery kind".into()),
            }
        };
        if let Err(error) = result {
            error_gate(store, &mut row, &error)?;
        }
    }
    for id in tasks {
        let Some((task, rows)) = store
            .access(move |store| {
                (|| -> Result<Option<(TaskRecord, Vec<PostMergeDelivery>)>, String> {
                    let mut task = store
                        .get_task(&id)
                        .map_err(|e| e.to_string())?
                        .ok_or("delivery task missing")?;
                    if !task.autonomous_consent
                        || task.memory.halt_requested
                        || matches!(task.status.as_str(), "Cancelled" | "Delivery Aborted")
                    {
                        return Ok(None);
                    }
                    let rows = store
                        .list_deliveries(Some(&id))
                        .map_err(|e| e.to_string())?;
                    if task.status == "Done" && rows.iter().any(|r| r.state != "verified") {
                        return Ok(None);
                    }
                    let status = if rows.iter().any(|r| r.state == "aborted") {
                        "Delivery Aborted"
                    } else if rows.iter().all(|r| r.state == "verified") {
                        "Done"
                    } else if rows.iter().any(|r| {
                        r.state == "waiting"
                            && r.evidence_json["waiting_status"] == "Waiting New APK"
                    }) {
                        "Waiting New APK"
                    } else if rows.iter().any(|r| {
                        r.state == "waiting"
                            && r.evidence_json["waiting_status"] == "Pending Prod Promotion"
                    }) {
                        "Pending Prod Promotion"
                    } else {
                        "Delivery Pending"
                    };
                    let became_done = task.status != "Done" && status == "Done";
                    task.status = status.into();
                    store
                        .save_delivery_status(&task, became_done.then_some(rows.as_slice()))
                        .map_err(|e| e.to_string())?;
                    let task = store
                        .get_task(&id)
                        .map_err(|e| e.to_string())?
                        .ok_or("delivery task missing")?;
                    Ok(Some((task, rows)))
                })()
                .map_err(V2StoreError)
            })
            .map_err(|e| e.to_string())?
        else {
            continue;
        };
        if rows
            .iter()
            .all(|r| r.evidence_json["board_synced_status"] == task.status)
        {
            continue;
        }
        // A human decision during board I/O invalidates this versioned receipt.
        if let Err(error) = driver.sync_board(&task) {
            store
                .append_event(
                    &task.task_id,
                    &task.task_group,
                    "DELIVERY_BOARD_SYNC_ERROR",
                    &json!({"error": error}),
                )
                .map_err(|e| e.to_string())?;
        } else {
            store
                .mark_delivery_board_synced(&task.task_id, task.version, &task.status)
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::v2::store::{ContextPackSpec, TaskMemory};

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn task() -> TaskRecord {
        TaskRecord {
            task_id: "DEMO-1".into(),
            task_group: "demo".into(),
            title: "Example delivery".into(),
            repository: "sample-app".into(),
            github_repo: Some("acme/sample-app".into()),
            issue_number: Some(1),
            weight: "L".into(),
            status: "Delivery Pending".into(),
            worktree_path: None,
            branch: None,
            context_pack: ContextPackSpec::default(),
            depends_on: vec![],
            required_stages: vec![],
            stages_completed: vec![],
            current_stage: None,
            active_attempt_id: None,
            plan_base_sha: None,
            reviewed_sha: None,
            pr_number: Some(1),
            executor: None,
            autonomous_consent: true,
            retry_count: 0,
            next_retry_epoch: 0,
            lease_owner: None,
            lease_expires_epoch: None,
            memory: TaskMemory::default(),
            version: 1,
            updated_epoch: 1,
        }
    }

    fn workflow() -> WorkflowDelivery {
        WorkflowDelivery {
            workflow: "publish-sample.yml".into(),
            when_paths: vec![],
            artifacts: vec![Artifact {
                name: "sample-${sha}-${attempt}".into(),
                file: "delivery.json".into(),
            }],
            failure_states: vec![FailureState {
                marker: "NEW_APK_REQUIRED".into(),
                waiting_state: "Waiting New APK".into(),
                decision_kind: "new_apk_required".into(),
                options: vec!["Retry".into(), "Abort".into()],
            }],
            health_checks: vec![HealthCheck::Url("https://example.invalid/health".into())],
        }
    }

    pub(crate) fn promotion() -> Promotion {
        let mut plan_inputs = BTreeMap::from([
            ("build_run_id".into(), "${build_run_id}".into()),
            ("source_sha".into(), "${source_sha}".into()),
            ("expected_current".into(), "${expected_current}".into()),
            ("approve_production".into(), "false".into()),
        ]);
        let mut approve_inputs = plan_inputs.clone();
        approve_inputs.insert("approve_production".into(), "true".into());
        plan_inputs.insert("release-label".into(), "sample".into());
        Promotion {
            name: "sample-service".into(),
            when_paths: vec![],
            build_workflow: "build-sample.yml".into(),
            artifact_name_template: "sample-${sha}".into(),
            digest_file: "package.sha256".into(),
            promote_workflow: "promote-sample.yml".into(),
            plan_inputs,
            approve_inputs,
            plan_artifact_prefix: "promotion-${run_id}-${attempt}".into(),
            plan_file: "plan.json".into(),
            delivery_file: Some("result.json".into()),
            current_source_probe: None,
            health_checks: vec![HealthCheck::Detailed(HealthCheckSpec {
                url: "https://example.invalid/release".into(),
                contains: None,
                source_sha_field: Some("source_sha".into()),
            })],
        }
    }

    #[test]
    fn declared_workflow_check_ids_are_excluded_independently_of_job_names() {
        let failed_delivery = json!({"id":11,"name":"arbitrary job label","status":"completed","conclusion":"failure"});
        let pending_delivery = json!({"id":12,"name":"long-running publishing","status":"in_progress","conclusion":null});
        let merge_ci =
            json!({"id":13,"name":"sample lint","status":"completed","conclusion":"success"});
        let ids = BTreeSet::from([11, 12]);
        assert!(matches!(
            evaluate_delivery_checks(
                vec![json!({"check_runs":[failed_delivery,pending_delivery,merge_ci]})],
                &ids
            )
            .unwrap(),
            CiCheckState::Success { .. }
        ));
        assert!(matches!(
            evaluate_delivery_checks(
                vec![json!({"check_runs":[failed_delivery,pending_delivery]})],
                &ids
            )
            .unwrap(),
            CiCheckState::Success { .. }
        ));
        let failed_ci =
            json!({"id":13,"name":"sample lint","status":"completed","conclusion":"failure"});
        assert!(matches!(
            evaluate_delivery_checks(
                vec![json!({"check_runs":[failed_delivery,failed_ci]})],
                &ids
            )
            .unwrap(),
            CiCheckState::Failed { .. }
        ));
        assert!(matches!(
            evaluate_delivery_checks(vec![json!({"check_runs":[]})], &ids).unwrap(),
            CiCheckState::Pending { .. }
        ));
    }

    #[test]
    fn failed_promotion_artifacts_do_not_open_an_approval_gate() {
        let (mut store, mut driver) = promotion_setup();
        tick(&mut store, &mut driver);
        tick(&mut store, &mut driver);
        driver.run(
            "promote-sample.yml",
            "workflow_dispatch",
            "201",
            1,
            true,
            true,
        );
        driver.promotion_result("201", "plan.json");
        let bytes = driver
            .files
            .get_mut(&("201".into(), "plan.json".into()))
            .unwrap();
        let mut value: Value = serde_json::from_slice(bytes).unwrap();
        value["status"] = json!("failed");
        *bytes = serde_json::to_vec(&value).unwrap();
        tick(&mut store, &mut driver);
        assert_eq!(status(&store), "Delivery Pending");
        assert_eq!(
            store.list_decisions(true, None).unwrap()[0].kind,
            "delivery_contract_error"
        );
    }

    #[test]
    fn strict_yaml_parses_nested_contract_and_quoted_lists() {
        let raw = r#"schema_version: 1
post_merge_workflows:
  - workflow: publish-sample.yml
    when_paths:
      - 'src/**'
    artifacts:
      - name: 'sample-${sha}-${attempt}'
        file: delivery.json
    failure_states:
      - marker: 'NEW_APK_REQUIRED'
        waiting_state: Waiting New APK
        decision_kind: new_apk_required
        options:
          - "Retry: after rebuilding"
          - 'Abort # this delivery'
    health_checks:
      - https://example.invalid/health
promotions:
  - name: sample-service
    build_workflow: build-sample.yml
    artifact_name_template: 'sample-${sha}'
    digest_file: package.sha256
    promote_workflow: promote-sample.yml
    plan_inputs:
      build_run_id: '${build_run_id}'
      approve_production: false
      release-label: 'sample: quoted'
    approve_inputs:
      build_run_id: '${build_run_id}'
      approve_production: true
    plan_artifact_prefix: 'promotion-${run_id}-${attempt}'
    plan_file: plan.json
    health_checks:
      - url: https://example.invalid/release
        source_sha_field: source_sha
"#;
        let contract = parse_contract(raw).unwrap();
        assert_eq!(
            contract.post_merge_workflows[0].failure_states[0].options[0],
            "Retry: after rebuilding"
        );
        assert_eq!(
            contract.promotions[0].plan_inputs["release-label"],
            "sample: quoted"
        );
        assert_eq!(
            seed_deliveries(&task(), SHA, &contract, &["src/main.rs".into()]).len(),
            2
        );
        assert_eq!(
            seed_deliveries(&task(), SHA, &contract, &["docs/readme.md".into()]).len(),
            1
        );
    }

    #[test]
    fn strict_yaml_rejects_unsupported_unknown_duplicate_and_bad_indentation() {
        for raw in [
            "schema_version: 2",
            "schema_version: 1\nunknown: true",
            "schema_version: 1\nschema_version: 1",
            "schema_version: 1\npost_merge_workflows:\n\t- workflow: sample.yml",
            "schema_version: 1\npost_merge_workflows: &rules",
            "schema_version: 1\npost_merge_workflows: *rules",
            "schema_version: 1\n<<: anything",
            "schema_version: 1\npost_merge_workflows:\n   - workflow: sample.yml",
            "schema_version: 1\npost_merge_workflows:\n  - workflow: sample.yml\n    typo: true",
            "schema_version: 1\npost_merge_workflows:\n  - workflow: sample.yml\n    health_checks:\n      - url: https://example.invalid/health\n        typo: true",
            "schema_version: 1\npost_merge_workflows:\n  - workflow: sample.yml\n    artifacts:\n      - name: sample\n        file: ../escape",
        ] {
            assert!(parse_contract(raw).is_err(), "accepted {raw}");
        }
        assert!(
            parse_contract("schema_version: 1\npost_merge_workflows: []\npromotions: []").is_ok()
        );
    }

    #[test]
    fn security_rejects_unsafe_urls_workflows_repositories_and_tokens() {
        for url in [
            "http://example.invalid",
            "https://user@example.invalid/",
            "https://example.invalid/a\nb",
            "https://localhost/",
            "https://x.localhost/",
            "https://x.local/",
            "https://x.internal/",
            "https://127.0.0.2/",
            "https://10.3.4.5/",
            "https://172.16.0.1/",
            "https://172.31.255.255/",
            "https://192.168.9.2/",
            "https://169.254.169.254/",
            "https://100.64.0.1/",
            "https://100.127.9.1/",
            "https://0.0.0.0/",
            "https://[::1]/",
            "https://[::]/",
            "https://[fc00::5]/",
            "https://[fdff::5]/",
            "https://[fe80::1234]/",
            "https://[::ffff:127.0.0.1]/",
            "https://[::ffff:8.8.8.8]/",
            "https://2130706433/",
            "https://0177.0.0.1/",
            "https://example.invalid./",
            "https://example.invalid%2f/",
            "https://example.invalid\\@localhost/",
            "https://example.invalid:0/",
        ] {
            assert!(validate_url(url).is_err(), "accepted {url}");
        }
        assert!(validate_url("https://example.invalid:443/release?q=value").is_ok());
        for workflow in [
            "../sample.yml",
            "-sample.yml",
            "x/y.yml",
            "sample y.yml",
            "sample\ny.yml",
            "sample..yml",
        ] {
            assert!(validate_workflow(workflow).is_err());
        }
        for repo in [
            "-x/sample-app",
            "acme/../sample-app",
            "acme/sample app",
            "acme/sample-app?x=y",
            "acme/sample-app\n",
        ] {
            assert!(validate_repo(repo).is_err());
        }
        for key in ["", "--input=", "key/value", "key value"] {
            assert!(validate_key(key).is_err());
        }
        assert!(validate_key("release-label_1").is_ok());
        assert!(validate_input_value("build_run_id", "12\n--input=@secret").is_err());
        assert!(validate_input_value("expected_current", "@file").is_err());
        assert!(validate_input_value("source_sha", "--sha").is_err());
        let mut row = new_row(&task(), SHA, "promotion", "sample", "sample.yml", json!({}));
        row.build_run_id = Some("12 --flag".into());
        assert!(render("${build_run_id}", &row, None).is_err());
        assert!(validate_template("${unknown}").is_err());
    }

    #[derive(Default)]
    pub(crate) struct MockDriver {
        pub(crate) probe_barrier:
            Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
        pub(crate) dispatch_barrier:
            Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
        runs: BTreeMap<(String, String), Vec<WorkflowRun>>,
        files: BTreeMap<(String, String), Vec<u8>>,
        dispatches: Vec<BTreeMap<String, String>>,
        logs: String,
        polls: usize,
        current: String,
        health_error: bool,
        board_errors: usize,
        board_calls: Vec<String>,
        contract: Option<ContractLookup>,
    }
    impl MockDriver {
        fn run(
            &mut self,
            workflow: &str,
            event: &str,
            id: &str,
            attempt: i64,
            completed: bool,
            success: bool,
        ) {
            let runs = self
                .runs
                .entry((workflow.into(), event.into()))
                .or_default();
            runs.retain(|r| r.id != id);
            runs.push(WorkflowRun {
                id: id.into(),
                attempt,
                completed,
                success,
            });
        }
        fn promotion_result(&mut self, run: &str, file: &str) {
            self.files.insert((run.into(), file.into()), serde_json::to_vec(&json!({"source_sha":SHA,"build_run_id":"100","artifact_digest":DIGEST,"expected_current":"none","status":"success"})).unwrap());
        }
    }
    impl DeliveryDriver for MockDriver {
        fn contract(&mut self, _: &str, _: &str) -> ContractLookup {
            self.contract
                .clone()
                .unwrap_or(ContractLookup::ContractNotFound)
        }
        fn changed_paths(&mut self, _: &str, _: &str) -> Result<Vec<String>, String> {
            Ok(vec!["src/main.rs".into()])
        }
        fn find_run(
            &mut self,
            _: &str,
            workflow: &str,
            _: &str,
            event: &str,
            after: u64,
        ) -> Result<Option<WorkflowRun>, String> {
            self.polls += 1;
            Ok(self
                .runs
                .get(&(workflow.into(), event.into()))
                .and_then(|runs| {
                    runs.iter()
                        .filter(|r| r.id.parse::<u64>().unwrap() > after)
                        .max_by_key(|r| r.id.parse::<u64>().unwrap())
                        .cloned()
                }))
        }
        fn artifact(
            &mut self,
            _: &str,
            run: &str,
            _: &str,
            file: &str,
            _: bool,
        ) -> Result<Vec<u8>, String> {
            self.files
                .get(&(run.into(), file.into()))
                .cloned()
                .ok_or("artifact not ready".into())
        }
        fn failed_logs(&mut self, _: &str, _: &str) -> Result<String, String> {
            Ok(self.logs.clone())
        }
        fn dispatch(
            &mut self,
            _: &str,
            _: &str,
            _: &str,
            inputs: &BTreeMap<String, String>,
        ) -> Result<String, String> {
            if let Some((entered, resume)) = self.dispatch_barrier.take() {
                entered.send(()).unwrap();
                resume.recv().unwrap();
            }
            self.dispatches.push(inputs.clone());
            Ok((200 + self.dispatches.len()).to_string())
        }
        fn query_run(
            &mut self,
            _: &str,
            workflow: &str,
            id: &str,
        ) -> Result<Option<WorkflowRun>, String> {
            self.polls += 1;
            Ok(self
                .runs
                .get(&(workflow.into(), "workflow_dispatch".into()))
                .and_then(|runs| runs.iter().find(|r| r.id == id).cloned()))
        }
        fn get_https(&mut self, url: &str) -> Result<String, String> {
            if let Some((entered, resume)) = self.probe_barrier.take() {
                entered.send(()).unwrap();
                resume.recv().unwrap();
            }
            if url.ends_with("/current") {
                return Ok(if self.current.is_empty() {
                    "none".into()
                } else {
                    self.current.clone()
                });
            }
            if self.health_error {
                Err("health failed".into())
            } else {
                Ok(json!({"source_sha": SHA}).to_string())
            }
        }
        fn sync_board(&mut self, task: &TaskRecord) -> Result<(), String> {
            self.board_calls.push(board_status(&task.status).into());
            if self.board_errors > 0 {
                self.board_errors -= 1;
                Err("board unavailable".into())
            } else {
                Ok(())
            }
        }
    }

    fn setup(contract: DeliveryContract) -> (V2Store, MockDriver) {
        let mut store = V2Store::open_in_memory().unwrap();
        let task = task();
        store.upsert_task(&task).unwrap();
        store
            .save_deliveries_and_task(&task, &seed_deliveries(&task, SHA, &contract, &[]))
            .unwrap();
        (store, MockDriver::default())
    }
    fn status(store: &V2Store) -> String {
        store.get_task("DEMO-1").unwrap().unwrap().status
    }
    fn only_row(store: &V2Store) -> PostMergeDelivery {
        store.list_deliveries(Some("DEMO-1")).unwrap().remove(0)
    }
    fn tick(store: &mut V2Store, driver: &mut MockDriver) {
        poll_post_merge_deliveries(store, driver).unwrap();
    }
    fn approve(store: &mut V2Store, choice: &str) {
        let decision = store.list_decisions(true, None).unwrap().remove(0);
        store
            .resolve_decision(&decision.decision_id, choice, "operator", None)
            .unwrap();
    }

    #[test]
    fn workflow_waits_for_new_apk_retry_attempts_and_preserves_artifact_evidence() {
        let contract = DeliveryContract {
            schema_version: 1,
            post_merge_workflows: vec![workflow()],
            promotions: vec![],
        };
        let (mut store, mut driver) = setup(contract);
        tick(&mut store, &mut driver);
        assert_eq!(driver.polls, 1); // no internal polling loop
        driver.logs = "build stopped: NEW_APK_REQUIRED".into();
        driver.run("publish-sample.yml", "push", "101", 1, true, false);
        tick(&mut store, &mut driver);
        assert_eq!(status(&store), "Waiting New APK");
        let first_gate = only_row(&store).decision_id.unwrap();
        approve(&mut store, "Retry");
        assert_eq!(status(&store), "Delivery Pending");
        tick(&mut store, &mut driver);
        assert_eq!(status(&store), "Delivery Pending");
        driver.run("publish-sample.yml", "push", "101", 2, true, false);
        tick(&mut store, &mut driver);
        assert_ne!(only_row(&store).decision_id.unwrap(), first_gate);
        approve(&mut store, "Retry");
        driver.run("publish-sample.yml", "push", "101", 3, true, true);
        driver.files.insert(("101".into(), "delivery.json".into()), serde_json::to_vec(&json!({"source_sha":SHA,"update_id":"sample-update","group_id":"sample-group","previous_group_id":"sample-previous"})).unwrap());
        tick(&mut store, &mut driver);
        assert_eq!(status(&store), "Done");
        assert_eq!(
            only_row(&store).evidence_json["artifacts"][0]["group_id"],
            "sample-group"
        );
        assert_eq!(driver.board_calls.last().unwrap(), "Done");
    }

    fn promotion_setup() -> (V2Store, MockDriver) {
        let (store, mut driver) = setup(DeliveryContract {
            schema_version: 1,
            post_merge_workflows: vec![],
            promotions: vec![promotion()],
        });
        driver.run("build-sample.yml", "push", "100", 1, true, true);
        driver.files.insert(
            ("100".into(), "package.sha256".into()),
            DIGEST.as_bytes().to_vec(),
        );
        (store, driver)
    }
    fn reach_approval(store: &mut V2Store, driver: &mut MockDriver) {
        tick(store, driver); // observe build/digest/current
        tick(store, driver); // dispatch plan
        assert_eq!(
            driver.dispatches.last().unwrap()["approve_production"],
            "false"
        );
        driver.run(
            "promote-sample.yml",
            "workflow_dispatch",
            "201",
            1,
            true,
            true,
        );
        driver.promotion_result("201", "plan.json");
        tick(store, driver);
        assert_eq!(status(store), "Pending Prod Promotion");
    }

    #[test]
    fn production_requires_plan_explicit_approval_new_run_and_health_checks() {
        let (mut store, mut driver) = promotion_setup();
        reach_approval(&mut store, &mut driver);
        let row = only_row(&store);
        let gate = store
            .get_decision(row.decision_id.as_deref().unwrap())
            .unwrap()
            .unwrap();
        for value in ["100", SHA, DIGEST, "none"] {
            assert!(gate.question.contains(value));
        }
        tick(&mut store, &mut driver);
        assert_eq!(driver.dispatches.len(), 1); // waiting never dispatches
        approve(&mut store, "Approve");
        tick(&mut store, &mut driver);
        assert_eq!(driver.dispatches[1]["approve_production"], "true");
        assert_eq!(driver.dispatches[1]["build_run_id"], "100");
        assert_eq!(only_row(&store).run_id.as_deref(), Some("202"));
        tick(&mut store, &mut driver); // old plan cannot replace the dispatched production run
        assert_eq!(status(&store), "Delivery Pending");
        // A newer unrelated plan must not substitute for this dispatch's ID.
        driver.run(
            "promote-sample.yml",
            "workflow_dispatch",
            "999",
            1,
            true,
            true,
        );
        driver.promotion_result("999", "result.json");
        tick(&mut store, &mut driver);
        assert_eq!(status(&store), "Delivery Pending");
        driver.run(
            "promote-sample.yml",
            "workflow_dispatch",
            "202",
            1,
            true,
            true,
        );
        driver.promotion_result("202", "result.json");
        tick(&mut store, &mut driver);
        assert_eq!(status(&store), "Done");
        assert_eq!(only_row(&store).state, "verified");
        assert!(
            store
                .list_events_since(None, 0, 100)
                .unwrap()
                .iter()
                .any(|e| e.event_type == "POST_MERGE_DELIVERY_VERIFIED")
        );
    }

    #[test]
    fn approved_promotion_error_opens_fresh_gate_and_retry_requires_new_plan() {
        let (mut store, mut driver) = promotion_setup();
        reach_approval(&mut store, &mut driver);
        let original = only_row(&store).decision_id.unwrap();
        approve(&mut store, "Approve");
        tick(&mut store, &mut driver);
        driver.run(
            "promote-sample.yml",
            "workflow_dispatch",
            "202",
            1,
            true,
            true,
        );
        driver.promotion_result("202", "result.json");
        driver.health_error = true;
        tick(&mut store, &mut driver);
        assert_eq!(status(&store), "Delivery Pending");
        assert_ne!(only_row(&store).decision_id.unwrap(), original);
        assert_eq!(
            store.list_decisions(true, None).unwrap()[0].kind,
            "delivery_contract_error"
        );
        approve(&mut store, "Retry");
        tick(&mut store, &mut driver);
        tick(&mut store, &mut driver);
        assert_eq!(
            driver.dispatches.last().unwrap()["approve_production"],
            "false"
        );
        assert_eq!(only_row(&store).run_id.as_deref(), Some("203"));
    }

    #[test]
    fn production_base_drift_invalidates_approval_and_unknown_dispatch_does_not_replay() {
        let (mut store, mut driver) = promotion_setup();
        let mut row = only_row(&store);
        row.rule_json["current_source_probe"] = json!("https://example.invalid/current");
        store.upsert_delivery(&row).unwrap();
        reach_approval(&mut store, &mut driver);
        approve(&mut store, "Approve");
        driver.current = "new-production-version".into();
        tick(&mut store, &mut driver);
        assert_eq!(only_row(&store).state, "pending");
        assert_eq!(driver.dispatches.len(), 1);
        let mut row = only_row(&store);
        row.state = "approve_dispatching".into();
        store.upsert_delivery(&row).unwrap();
        tick(&mut store, &mut driver);
        assert_eq!(driver.dispatches.len(), 1);
        assert_eq!(only_row(&store).state, "waiting");
    }

    #[test]
    fn mismatched_artifacts_and_rejected_promotions_never_finish_or_become_ready() {
        let (mut store, mut driver) = promotion_setup();
        tick(&mut store, &mut driver);
        tick(&mut store, &mut driver);
        driver.run(
            "promote-sample.yml",
            "workflow_dispatch",
            "201",
            1,
            true,
            true,
        );
        driver.files.insert(
            ("201".into(), "plan.json".into()),
            b"{\"source_sha\":\"wrong\"}".to_vec(),
        );
        tick(&mut store, &mut driver);
        assert_eq!(only_row(&store).state, "waiting");
        approve(&mut store, "Abort");
        assert_eq!(status(&store), "Delivery Aborted");
        let dispatches = driver.dispatches.len();
        tick(&mut store, &mut driver);
        assert_eq!(driver.dispatches.len(), dispatches);
        assert!(store.list_ready_queue(None).unwrap().is_empty());
    }

    #[test]
    fn all_deliveries_must_verify_and_final_board_sync_is_retried() {
        let mut second = workflow();
        second.workflow = "publish-other.yml".into();
        second.artifacts.clear();
        let mut first = workflow();
        first.artifacts.clear();
        let (mut store, mut driver) = setup(DeliveryContract {
            schema_version: 1,
            post_merge_workflows: vec![first, second],
            promotions: vec![],
        });
        driver.run("publish-sample.yml", "push", "101", 1, true, true);
        tick(&mut store, &mut driver);
        assert_eq!(status(&store), "Delivery Pending");
        driver.run("publish-other.yml", "push", "102", 1, true, true);
        driver.board_errors = 1;
        tick(&mut store, &mut driver);
        assert_eq!(status(&store), "Done");
        let calls = driver.board_calls.len();
        tick(&mut store, &mut driver);
        assert_eq!(driver.board_calls.len(), calls + 1);
        tick(&mut store, &mut driver);
        assert_eq!(driver.board_calls.len(), calls + 1);
    }

    #[test]
    fn contract_errors_can_resume_from_merge_sha_and_terminal_tasks_are_preserved() {
        let mut store = V2Store::open_in_memory().unwrap();
        let task = task();
        store.upsert_task(&task).unwrap();
        let row = contract_error_row(&task, SHA, "fetch unavailable");
        store.upsert_delivery(&row).unwrap();
        let mut driver = MockDriver {
            contract: Some(ContractLookup::ParseError("bad YAML".into())),
            ..Default::default()
        };
        tick(&mut store, &mut driver);
        assert_eq!(status(&store), "Delivery Pending");
        assert_eq!(
            store.list_decisions(true, None).unwrap()[0].kind,
            "delivery_contract_error"
        );
        approve(&mut store, "Retry");
        driver.contract = Some(ContractLookup::ContractNotFound);
        tick(&mut store, &mut driver);
        assert_eq!(status(&store), "Done");
        assert!(checkpoint(&mut store, &row, "Delivery Pending").is_err());
        assert_eq!(status(&store), "Done");
        for state in [
            "Delivery Pending",
            "Waiting New APK",
            "Pending Prod Promotion",
        ] {
            assert_eq!(board_status(state), "Blocked");
        }
    }

    fn zip(name: &str, data: &[u8], compressed: &[u8], method: u16, mode: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        let crc = crc32(data);
        bytes.extend(b"PK\x03\x04");
        for value in [20u16, 0, method, 0, 0] {
            bytes.extend(value.to_le_bytes());
        }
        for value in [crc, compressed.len() as u32, data.len() as u32] {
            bytes.extend(value.to_le_bytes());
        }
        bytes.extend((name.len() as u16).to_le_bytes());
        bytes.extend(0u16.to_le_bytes());
        bytes.extend(name.as_bytes());
        bytes.extend(compressed);
        let start = bytes.len() as u32;
        bytes.extend(b"PK\x01\x02");
        for value in [0x0314u16, 20, 0, method, 0, 0] {
            bytes.extend(value.to_le_bytes());
        }
        for value in [crc, compressed.len() as u32, data.len() as u32] {
            bytes.extend(value.to_le_bytes());
        }
        for value in [name.len() as u16, 0, 0, 0, 0] {
            bytes.extend(value.to_le_bytes());
        }
        bytes.extend((mode << 16).to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(name.as_bytes());
        let central = bytes.len() as u32 - start;
        bytes.extend(b"PK\x05\x06");
        for value in [0u16, 0, 1, 1] {
            bytes.extend(value.to_le_bytes());
        }
        bytes.extend(central.to_le_bytes());
        bytes.extend(start.to_le_bytes());
        bytes.extend(0u16.to_le_bytes());
        bytes
    }

    #[test]
    fn artifacts_are_bounded_checked_extracted_and_cleaned() {
        let archive = zip(
            "evidence/result.json",
            b"hello",
            &[203, 72, 205, 201, 201, 7, 0],
            8,
            0o100644,
        );
        let entries = validate_zip(&archive).unwrap();
        let root;
        {
            let temp = IsolatedDir::new().unwrap();
            root = temp.0.clone();
            extract_zip(&archive, &entries, &root).unwrap();
            inspect_tree(&root).unwrap();
            assert_eq!(
                fs::read(root.join("evidence/result.json")).unwrap(),
                b"hello"
            );
        }
        assert!(!root.exists());
        for name in [
            "../escape",
            "/absolute",
            "safe/../../escape",
            "safe\\escape",
            "safe/./escape",
        ] {
            assert!(validate_zip(&zip(name, b"x", b"x", 0, 0o100644)).is_err());
        }
        assert!(validate_zip(&zip("link", b"target", b"target", 0, 0o120777)).is_err());
        assert!(validate_zip(&zip("large", &vec![0; MAX_FILE + 1], b"x", 0, 0o100644)).is_err());
        let mut corrupted = archive.clone();
        corrupted[50] ^= 1;
        if let Ok(entries) = validate_zip(&corrupted) {
            let temp = IsolatedDir::new().unwrap();
            assert!(extract_zip(&corrupted, &entries, &temp.0).is_err());
        }
        let temp = IsolatedDir::new().unwrap();
        std::os::unix::fs::symlink("/outside", temp.0.join("link")).unwrap();
        assert!(inspect_tree(&temp.0).is_err());
        assert_eq!(
            inflate(&[1, 5, 0, 250, 255, b'h', b'e', b'l', b'l', b'o'], 5).unwrap(),
            b"hello"
        );
        assert!(inflate(&[203, 72, 205, 201, 201, 7, 0], 4).is_err());
    }
    #[test]
    fn dynamic_deflate_and_literal_only_empty_distance_tree_are_supported() {
        let hex = "edcbc10983401405c0567e055663038b3ee38291e082f59b323ccc7998794f7d72e6ea4b8df6fd1da92b47da48ed6dd4fd87ad67addc7dcdb964aad9300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc3300cc378f17800";
        let bytes: Vec<u8> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        let expected = b"The generic sample release has verified evidence. ".repeat(1000);
        assert_eq!(inflate(&bytes, expected.len()).unwrap(), expected);
        // RFC1951 permits a dynamic literal-only block with no distance tree.
        let literal_only = [5, 192, 129, 8, 0, 0, 0, 0, 32, 182, 253, 165, 78];
        assert_eq!(inflate(&literal_only, 1).unwrap(), b"A");
        for end in 0..bytes.len() {
            assert!(inflate(&bytes[..end], expected.len()).is_err());
        }
    }
}
