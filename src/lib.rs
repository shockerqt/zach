use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::process::Command;

pub const OPERATION: &str = "governance.audit-task-integration";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRequest {
    pub task_id: String,
    pub request_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunEvidenceRole {
    Implementation,
    IntegrationAudit {
        audited_implementation_sha: String,
        audited_pull_request_url: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunEvidence {
    pub run_path: String,
    pub publication_sha: String,
    pub implementation_sha: String,
    pub ci_sha: String,
    pub ci_conclusion: String,
    pub pull_request_url: String,
    pub pull_request_head_sha: String,
    pub role: RunEvidenceRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequestEvidence {
    pub url: String,
    pub merged: bool,
    pub merge_commit_sha: Option<String>,
    pub merged_at: Option<String>,
    pub head_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowEvidence {
    pub id: u64,
    pub head_sha: String,
    pub conclusion: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchObservation {
    Present {
        sha: String,
        open_pr_urls: Vec<String>,
    },
    Absent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepresentationEvidence {
    pub implementation_is_ancestor_or_equal_of_pr_head: bool,
    pub pr_head_is_ancestor_or_equal_of_merge: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSnapshot {
    pub task_id: String,
    pub request_id: String,
    pub request_digest: String,
    pub governance_sha: String,
    pub target_repository: String,
    pub canonical_branch: String,
    pub audited_implementation: RunEvidence,
    pub pull_request: PullRequestEvidence,
    pub representation: RepresentationEvidence,
    pub post_merge_runs: Vec<WorkflowEvidence>,
    pub branch: BranchObservation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReceipt {
    pub receipt_id: String,
    pub snapshot: AuditSnapshot,
    pub selected_ci: WorkflowEvidence,
}

impl AuditReceipt {
    pub fn to_json(&self) -> String {
        let s = &self.snapshot;
        let branch = match &s.branch {
            BranchObservation::Absent => "{\"state\":\"absent\"}".to_owned(),
            BranchObservation::Present { sha, open_pr_urls } => format!(
                "{{\"state\":\"present\",\"sha\":{},\"open_pr_urls\":[{}]}}",
                json_string(sha),
                open_pr_urls
                    .iter()
                    .map(|value| json_string(value))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        };
        let merge_sha = s.pull_request.merge_commit_sha.as_deref().unwrap_or("");
        format!(
            concat!(
                "{{\"schema_version\":1,",
                "\"operation\":{},\"receipt_id\":{},",
                "\"request\":{{\"task_id\":{},\"request_id\":{},\"request_digest\":{},\"governance_sha\":{}}},",
                "\"audit_run_publication\":null,",
                "\"audited_implementation\":{{",
                "\"source_run_path\":{},\"publication_sha\":{},\"implementation_sha\":{},",
                "\"implementation_ci_sha\":{},\"implementation_ci_conclusion\":{},",
                "\"pull_request_url\":{}",
                "}},",
                "\"integration_evidence\":{{",
                "\"target_repository\":{},\"canonical_branch\":{},",
                "\"pull_request_merged\":true,\"merge_commit_sha\":{},\"merged_at\":{},",
                "\"implementation_represented\":true,",
                "\"representation\":{{",
                "\"method\":\"git_ancestry_through_merged_pr_head\",",
                "\"implementation_sha\":{},\"merged_pr_head_sha\":{},\"merge_commit_sha\":{}",
                "}},",
                "\"post_merge_ci\":{{\"sha\":{},\"conclusion\":\"success\",\"run_id\":{},\"url\":{}}},",
                "\"branch_observation\":{}",
                "}}}}"
            ),
            json_string(OPERATION),
            json_string(&self.receipt_id),
            json_string(&s.task_id),
            json_string(&s.request_id),
            json_string(&s.request_digest),
            json_string(&s.governance_sha),
            json_string(&s.audited_implementation.run_path),
            json_string(&s.audited_implementation.publication_sha),
            json_string(&s.audited_implementation.implementation_sha),
            json_string(&s.audited_implementation.ci_sha),
            json_string(&s.audited_implementation.ci_conclusion),
            json_string(&s.audited_implementation.pull_request_url),
            json_string(&s.target_repository),
            json_string(&s.canonical_branch),
            json_string(merge_sha),
            json_string(s.pull_request.merged_at.as_deref().unwrap_or("")),
            json_string(&s.audited_implementation.implementation_sha),
            json_string(&s.pull_request.head_sha),
            json_string(merge_sha),
            json_string(&self.selected_ci.head_sha),
            self.selected_ci.id,
            json_string(&self.selected_ci.url),
            branch
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    InvalidRequest(String),
    Configuration(String),
    Github(String),
    CanonicalState(String),
    AmbiguousEvidence(String),
    Idempotency(String),
    Verification(String),
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(value) => write!(f, "invalid request: {value}"),
            Self::Configuration(value) => write!(f, "configuration: {value}"),
            Self::Github(value) => write!(f, "github: {value}"),
            Self::CanonicalState(value) => write!(f, "canonical state: {value}"),
            Self::AmbiguousEvidence(value) => write!(f, "ambiguous evidence: {value}"),
            Self::Idempotency(value) => write!(f, "idempotency: {value}"),
            Self::Verification(value) => write!(f, "verification failed: {value}"),
        }
    }
}

impl std::error::Error for AuditError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotencyClaim {
    Claimed,
    Existing {
        request_digest: String,
        terminal_receipt: Option<String>,
    },
}

pub trait AuditIdempotencyStore {
    fn claim(
        &mut self,
        request_id: &str,
        request_digest: &str,
    ) -> Result<IdempotencyClaim, AuditError>;

    fn complete(
        &mut self,
        request_id: &str,
        request_digest: &str,
        terminal_receipt: &str,
    ) -> Result<(), AuditError>;
}

struct UnavailableDurableStore;

impl AuditIdempotencyStore for UnavailableDurableStore {
    fn claim(
        &mut self,
        _request_id: &str,
        _request_digest: &str,
    ) -> Result<IdempotencyClaim, AuditError> {
        Err(AuditError::Configuration(
            "durable audit idempotency store is unavailable; canonical persistent SQLite idempotency is owned by ZACH-001 and is not implemented yet"
                .into(),
        ))
    }

    fn complete(
        &mut self,
        _request_id: &str,
        _request_digest: &str,
        _terminal_receipt: &str,
    ) -> Result<(), AuditError> {
        Err(AuditError::Configuration(
            "durable audit idempotency store is unavailable".into(),
        ))
    }
}

pub fn canonical_request_digest(request: &AuditRequest) -> Result<String, AuditError> {
    validate_request(request)?;
    let canonical = format!(
        "{{\"operation\":{},\"request_id\":{},\"task_id\":{}}}",
        json_string(OPERATION),
        json_string(&request.request_id),
        json_string(&request.task_id)
    );
    Ok(sha256_hex(canonical.as_bytes()))
}

pub fn execute_idempotent_audit<S, F>(
    store: &mut S,
    request: &AuditRequest,
    action: F,
) -> Result<String, AuditError>
where
    S: AuditIdempotencyStore,
    F: FnOnce(&str) -> Result<AuditReceipt, AuditError>,
{
    let digest = canonical_request_digest(request)?;
    match store.claim(&request.request_id, &digest)? {
        IdempotencyClaim::Existing {
            request_digest,
            terminal_receipt,
        } => {
            if request_digest != digest {
                return Err(AuditError::Idempotency(
                    "request_id is already bound to a different request digest".into(),
                ));
            }
            terminal_receipt.ok_or_else(|| {
                AuditError::Idempotency(
                    "request_id has a non-terminal durable claim; ambiguous recovery fails closed"
                        .into(),
                )
            })
        }
        IdempotencyClaim::Claimed => {
            let receipt = action(&digest)?;
            if receipt.snapshot.task_id != request.task_id
                || receipt.snapshot.request_id != request.request_id
                || receipt.snapshot.request_digest != digest
            {
                return Err(AuditError::Idempotency(
                    "terminal receipt does not match the claimed canonical request identity".into(),
                ));
            }
            let json = receipt.to_json();
            store.complete(&request.request_id, &digest, &json)?;
            Ok(json)
        }
    }
}

fn coherent_terminal(run: &RunEvidence) -> bool {
    run.publication_sha == run.implementation_sha
        && run.implementation_sha == run.ci_sha
        && run.implementation_sha == run.pull_request_head_sha
        && run.ci_conclusion == "success"
}

pub fn select_audited_implementation(runs: &[RunEvidence]) -> Result<RunEvidence, AuditError> {
    let candidates = runs
        .iter()
        .filter(|run| {
            matches!(&run.role, RunEvidenceRole::Implementation) && coherent_terminal(run)
        })
        .collect::<Vec<_>>();

    let mut explicit = BTreeSet::new();
    for run in runs {
        if let RunEvidenceRole::IntegrationAudit {
            audited_implementation_sha,
            audited_pull_request_url,
        } = &run.role
        {
            if !coherent_terminal(run) {
                return Err(AuditError::Verification(
                    "integration audit carries incoherent historical implementation terminal evidence"
                        .into(),
                ));
            }
            explicit.insert((
                audited_implementation_sha.clone(),
                audited_pull_request_url.clone(),
            ));
        }
    }

    if explicit.len() > 1 {
        return Err(AuditError::AmbiguousEvidence(
            "integration records disagree on the audited implementation identity".into(),
        ));
    }

    if let Some((implementation_sha, pull_request_url)) = explicit.into_iter().next() {
        let matches = candidates
            .iter()
            .filter(|run| {
                run.implementation_sha == implementation_sha
                    && run.pull_request_url == pull_request_url
            })
            .copied()
            .collect::<Vec<_>>();
        return match matches.len() {
            1 => Ok(matches[0].clone()),
            0 => Err(AuditError::Verification(
                "explicit audited implementation is not backed by one canonical implementation run"
                    .into(),
            )),
            _ => Err(AuditError::AmbiguousEvidence(
                "multiple implementation runs match the explicit audited implementation".into(),
            )),
        };
    }

    match candidates.len() {
        0 => Err(AuditError::Verification(
            "no coherent implementation terminal evidence found".into(),
        )),
        1 => Ok(candidates[0].clone()),
        _ => Err(AuditError::AmbiguousEvidence(
            "multiple coherent implementation runs exist without one explicit audited implementation"
                .into(),
        )),
    }
}

pub fn evaluate_snapshot(snapshot: AuditSnapshot) -> Result<AuditReceipt, AuditError> {
    let expected_digest = canonical_request_digest(&AuditRequest {
        task_id: snapshot.task_id.clone(),
        request_id: snapshot.request_id.clone(),
    })?;
    if snapshot.request_digest != expected_digest {
        return Err(AuditError::Verification(
            "snapshot request digest does not bind the canonical request identity".into(),
        ));
    }

    let implementation = &snapshot.audited_implementation;
    if !coherent_terminal(implementation) {
        return Err(AuditError::Verification(
            "audited implementation terminal evidence is incoherent".into(),
        ));
    }
    let pr = &snapshot.pull_request;
    if !pr.merged {
        return Err(AuditError::Verification(
            "target pull request is not merged".into(),
        ));
    }
    let merge_sha = pr.merge_commit_sha.as_deref().ok_or_else(|| {
        AuditError::Verification("merged pull request has no merge commit SHA".into())
    })?;
    if pr.merged_at.is_none() {
        return Err(AuditError::Verification(
            "merged pull request has no merge timestamp".into(),
        ));
    }
    if pr.url != implementation.pull_request_url {
        return Err(AuditError::Verification(
            "merged pull request identity differs from canonical implementation evidence".into(),
        ));
    }
    if !snapshot
        .representation
        .implementation_is_ancestor_or_equal_of_pr_head
        || !snapshot
            .representation
            .pr_head_is_ancestor_or_equal_of_merge
    {
        return Err(AuditError::Verification(
            "implementation SHA is not represented by immutable ancestry through the merged pull-request head"
                .into(),
        ));
    }

    let mut successful = snapshot
        .post_merge_runs
        .iter()
        .filter(|run| run.head_sha == merge_sha && run.conclusion == "success")
        .cloned()
        .collect::<Vec<_>>();
    successful.sort_by_key(|run| run.id);
    let selected_ci = successful.pop().ok_or_else(|| {
        AuditError::Verification("no successful post-merge CI on exact merge SHA".into())
    })?;

    let receipt_id = stable_receipt_id(&snapshot, &selected_ci);
    Ok(AuditReceipt {
        receipt_id,
        snapshot,
        selected_ci,
    })
}

fn stable_receipt_id(snapshot: &AuditSnapshot, ci: &WorkflowEvidence) -> String {
    let branch_identity = match &snapshot.branch {
        BranchObservation::Absent => "absent",
        BranchObservation::Present { sha, .. } => sha,
    };
    let material = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        snapshot.request_digest,
        snapshot.governance_sha,
        snapshot.audited_implementation.implementation_sha,
        snapshot.pull_request.head_sha,
        snapshot
            .pull_request
            .merge_commit_sha
            .as_deref()
            .unwrap_or(""),
        ci.head_sha,
        ci.id,
        branch_identity
    );
    format!("zach-audit-{}", sha256_hex(material.as_bytes()))
}

#[derive(Debug, Clone)]
pub struct GithubConfig {
    api_url: String,
    token: String,
    governance_repository: String,
    governance_default_branch: String,
}

impl GithubConfig {
    pub fn from_env() -> Result<Self, AuditError> {
        let token = env::var("GITHUB_TOKEN")
            .map_err(|_| AuditError::Configuration("GITHUB_TOKEN is required".into()))?;
        if token.trim().is_empty() {
            return Err(AuditError::Configuration(
                "GITHUB_TOKEN must not be empty".into(),
            ));
        }
        Ok(Self {
            api_url: env::var("GITHUB_API_URL").unwrap_or_else(|_| "https://api.github.com".into()),
            token,
            governance_repository: env::var("GOVERNANCE_REPOSITORY")
                .unwrap_or_else(|_| "shockerqt/workspace-governance".into()),
            governance_default_branch: env::var("GOVERNANCE_DEFAULT_BRANCH")
                .unwrap_or_else(|_| "master".into()),
        })
    }
}

pub fn audit_task_integration(
    config: &GithubConfig,
    request: &AuditRequest,
) -> Result<String, AuditError> {
    let mut store = UnavailableDurableStore;
    audit_task_integration_with_store(config, request, &mut store)
}

pub fn audit_task_integration_with_store<S: AuditIdempotencyStore>(
    config: &GithubConfig,
    request: &AuditRequest,
    store: &mut S,
) -> Result<String, AuditError> {
    execute_idempotent_audit(store, request, |request_digest| {
        collect_audit_receipt(config, request, request_digest)
    })
}

fn collect_audit_receipt(
    config: &GithubConfig,
    request: &AuditRequest,
    request_digest: &str,
) -> Result<AuditReceipt, AuditError> {
    let github = GithubHttp::new(config);

    // Resolve Governance exactly once. Every canonical task/run/project read below is pinned to it.
    let governance_sha = github.commit_sha(
        &config.governance_repository,
        &config.governance_default_branch,
    )?;
    let manifest = github.raw_content(
        &config.governance_repository,
        "governance-manifest.yaml",
        &governance_sha,
    )?;
    let route = parse_manifest_task(&manifest, &request.task_id)?;
    let task_markdown =
        github.raw_content(&config.governance_repository, &route.path, &governance_sha)?;
    let canonical_branch = frontmatter_value(&task_markdown, "branch")?
        .ok_or_else(|| AuditError::CanonicalState("task.branch is missing".into()))?;
    if matches!(canonical_branch.as_str(), "null" | "none") {
        return Err(AuditError::CanonicalState(
            "task.branch is not a code branch".into(),
        ));
    }
    let target_key = frontmatter_value(&task_markdown, "target_repository")?
        .ok_or_else(|| AuditError::CanonicalState("task.target_repository is missing".into()))?;
    let projects = github.raw_content(
        &config.governance_repository,
        "projects.yaml",
        &governance_sha,
    )?;
    let target_repository = resolve_repository(&projects, &target_key)?;

    let mut runs = Vec::new();
    for path in &route.run_paths {
        let markdown = github.raw_content(&config.governance_repository, path, &governance_sha)?;
        if let Some(evidence) = parse_run_evidence(path, &markdown)? {
            runs.push(evidence);
        }
    }
    let implementation = select_audited_implementation(&runs)?;
    let pr_location = parse_pr_url(&implementation.pull_request_url)?;
    if pr_location.repository != target_repository {
        return Err(AuditError::Verification(format!(
            "terminal evidence PR repository {} does not match canonical target {}",
            pr_location.repository, target_repository
        )));
    }

    let pull_request = github.pull_request(&pr_location)?;
    let merge_sha = pull_request
        .merge_commit_sha
        .as_deref()
        .ok_or_else(|| AuditError::Verification("pull request lacks merge SHA".into()))?;
    let representation = RepresentationEvidence {
        implementation_is_ancestor_or_equal_of_pr_head: github.is_ancestor_or_equal(
            &target_repository,
            &implementation.implementation_sha,
            &pull_request.head_sha,
        )?,
        pr_head_is_ancestor_or_equal_of_merge: github.is_ancestor_or_equal(
            &target_repository,
            &pull_request.head_sha,
            merge_sha,
        )?,
    };
    let post_merge_runs = github.workflow_runs(&target_repository, merge_sha)?;
    // Observe the exact canonical branch once after immutable integration evidence is collected.
    let branch = github.branch_observation(&target_repository, &canonical_branch)?;

    evaluate_snapshot(AuditSnapshot {
        task_id: request.task_id.clone(),
        request_id: request.request_id.clone(),
        request_digest: request_digest.to_owned(),
        governance_sha,
        target_repository,
        canonical_branch,
        audited_implementation: implementation,
        pull_request,
        representation,
        post_merge_runs,
        branch,
    })
}

fn validate_request(request: &AuditRequest) -> Result<(), AuditError> {
    let task_valid = (5..=32).contains(&request.task_id.len())
        && request
            .task_id
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
        && request.task_id.contains('-');
    if !task_valid {
        return Err(AuditError::InvalidRequest(
            "task_id is not canonical".into(),
        ));
    }
    let request_valid = !request.request_id.is_empty()
        && request.request_id.len() <= 128
        && request
            .request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
    if !request_valid {
        return Err(AuditError::InvalidRequest(
            "request_id contains unsupported characters".into(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct ManifestRoute {
    path: String,
    run_paths: Vec<String>,
}

fn parse_manifest_task(manifest: &str, task_id: &str) -> Result<ManifestRoute, AuditError> {
    let marker = format!("- id: {task_id}");
    let start = manifest.find(&marker).ok_or_else(|| {
        AuditError::CanonicalState(format!("task {task_id} is absent from manifest"))
    })?;
    let rest = &manifest[start..];
    let end = rest[marker.len()..]
        .find("\n- id: ")
        .map(|offset| marker.len() + offset)
        .unwrap_or(rest.len());
    let block = &rest[..end];
    let path = scalar_line(block, "path:")?
        .ok_or_else(|| AuditError::CanonicalState("manifest task path is missing".into()))?;
    let mut run_paths = Vec::new();
    let mut in_runs = false;
    for line in block.lines() {
        let trimmed = line.trim();
        if trimmed == "run_paths:" {
            in_runs = true;
            continue;
        }
        if in_runs {
            if let Some(value) = trimmed.strip_prefix("- runs/") {
                run_paths.push(format!("runs/{value}"));
            } else if !trimmed.is_empty() && !trimmed.starts_with('-') {
                break;
            }
        }
    }
    if run_paths.is_empty() {
        return Err(AuditError::CanonicalState(
            "task has no execution runs".into(),
        ));
    }
    Ok(ManifestRoute { path, run_paths })
}

fn frontmatter_value(markdown: &str, key: &str) -> Result<Option<String>, AuditError> {
    let mut lines = markdown.lines();
    if lines.next() != Some("---") {
        return Err(AuditError::CanonicalState(
            "record has no YAML frontmatter".into(),
        ));
    }
    let prefix = format!("{key}:");
    let mut values = Vec::new();
    for line in lines {
        if line == "---" {
            break;
        }
        if let Some(value) = line.trim().strip_prefix(&prefix) {
            values.push(unquote(value.trim()));
        }
    }
    unique_value(values, key)
}

fn resolve_repository(projects: &str, key: &str) -> Result<String, AuditError> {
    let mut active = false;
    for line in projects.lines() {
        let trimmed = line.trim();
        if let Some(repository) = trimmed.strip_prefix("- repository:") {
            active = repository.trim() == key;
        } else if active && let Some(url) = trimmed.strip_prefix("clone_url:") {
            let value = url.trim().trim_end_matches('/').trim_end_matches(".git");
            if let Some(full_name) = value.strip_prefix("https://github.com/") {
                return Ok(full_name.to_owned());
            }
            return Err(AuditError::CanonicalState(
                "unsupported project clone_url".into(),
            ));
        }
    }
    Err(AuditError::CanonicalState(format!(
        "target repository key {key} is not registered"
    )))
}

fn parse_run_evidence(path: &str, markdown: &str) -> Result<Option<RunEvidence>, AuditError> {
    if frontmatter_value(markdown, "status")?.as_deref() != Some("completed")
        || frontmatter_value(markdown, "run_type")?.as_deref() != Some("execution")
    {
        return Ok(None);
    }
    let Some(publication) = extract_section(markdown, "## Remote publication evidence") else {
        return Ok(None);
    };
    let Some(terminal) = extract_section(markdown, "## Remote terminal evidence") else {
        return Ok(None);
    };
    let role =
        if let Some(integration) = extract_section(markdown, "## Remote integration evidence") {
            RunEvidenceRole::IntegrationAudit {
                audited_implementation_sha: required_scalar(integration, "implementation_sha:")?,
                audited_pull_request_url: required_scalar(integration, "pull_request_url:")?,
            }
        } else {
            RunEvidenceRole::Implementation
        };
    Ok(Some(RunEvidence {
        run_path: path.to_owned(),
        publication_sha: required_scalar(publication, "published_after_sha:")?,
        implementation_sha: required_scalar(terminal, "implementation_sha:")?,
        ci_sha: required_scalar(terminal, "ci_sha:")?,
        ci_conclusion: required_scalar(terminal, "ci_conclusion:")?,
        pull_request_url: required_scalar(terminal, "pull_request_url:")?,
        pull_request_head_sha: required_scalar(terminal, "pull_request_head_sha:")?,
        role,
    }))
}

fn extract_section<'a>(markdown: &'a str, heading: &str) -> Option<&'a str> {
    let start = markdown.find(heading)? + heading.len();
    let rest = &markdown[start..];
    let end = rest.find("\n## ").unwrap_or(rest.len());
    Some(&rest[..end])
}

fn required_scalar(text: &str, key: &str) -> Result<String, AuditError> {
    scalar_line(text, key)?.ok_or_else(|| AuditError::CanonicalState(format!("missing {key}")))
}

fn scalar_line(text: &str, key: &str) -> Result<Option<String>, AuditError> {
    let values = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix(key))
        .map(|value| unquote(value.trim()))
        .collect::<Vec<_>>();
    unique_value(values, key)
}

fn unique_value(values: Vec<String>, key: &str) -> Result<Option<String>, AuditError> {
    let mut unique = Vec::new();
    for value in values {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    match unique.len() {
        0 => Ok(None),
        1 => Ok(unique.pop()),
        _ => Err(AuditError::AmbiguousEvidence(format!(
            "conflicting values for {key}"
        ))),
    }
}

fn unquote(value: &str) -> String {
    if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
    {
        return inner.to_owned();
    }
    if let Some(inner) = value
        .strip_prefix('\'')
        .and_then(|inner| inner.strip_suffix('\''))
    {
        return inner.to_owned();
    }
    value.to_owned()
}

#[derive(Debug)]
struct PrLocation {
    repository: String,
    number: u64,
}

fn parse_pr_url(url: &str) -> Result<PrLocation, AuditError> {
    let path = url.strip_prefix("https://github.com/").ok_or_else(|| {
        AuditError::CanonicalState("pull_request_url is not a github.com URL".into())
    })?;
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.len() != 4 || parts[2] != "pull" {
        return Err(AuditError::CanonicalState(
            "pull_request_url has unexpected shape".into(),
        ));
    }
    let number = parts[3]
        .parse::<u64>()
        .map_err(|_| AuditError::CanonicalState("pull request number is invalid".into()))?;
    Ok(PrLocation {
        repository: format!("{}/{}", parts[0], parts[1]),
        number,
    })
}

struct GithubHttp<'a> {
    config: &'a GithubConfig,
}

impl<'a> GithubHttp<'a> {
    fn new(config: &'a GithubConfig) -> Self {
        Self { config }
    }

    fn commit_sha(&self, repo: &str, reference: &str) -> Result<String, AuditError> {
        let json = self.get_json(&format!("/repos/{repo}/commits/{}", pct(reference)))?;
        json.get_string("sha")
            .map(str::to_owned)
            .ok_or_else(|| AuditError::Github("commit response lacks sha".into()))
    }

    fn raw_content(&self, repo: &str, path: &str, reference: &str) -> Result<String, AuditError> {
        let endpoint = format!(
            "/repos/{repo}/contents/{}?ref={}",
            pct_path(path),
            pct(reference)
        );
        self.request(&endpoint, true, true).map(|(_, body)| body)
    }

    fn pull_request(&self, location: &PrLocation) -> Result<PullRequestEvidence, AuditError> {
        let json = self.get_json(&format!(
            "/repos/{}/pulls/{}",
            location.repository, location.number
        ))?;
        let head = json
            .get_object("head")
            .ok_or_else(|| AuditError::Github("pull request response lacks head".into()))?;
        let head_sha = object_string(head, "sha")
            .ok_or_else(|| AuditError::Github("pull request response lacks head.sha".into()))?
            .to_owned();
        let url = json
            .get_string("html_url")
            .ok_or_else(|| AuditError::Github("pull request response lacks html_url".into()))?
            .to_owned();
        Ok(PullRequestEvidence {
            url,
            merged: json.get_bool("merged").unwrap_or(false),
            merge_commit_sha: json.get_nullable_string("merge_commit_sha"),
            merged_at: json.get_nullable_string("merged_at"),
            head_sha,
        })
    }

    fn is_ancestor_or_equal(
        &self,
        repo: &str,
        ancestor: &str,
        descendant: &str,
    ) -> Result<bool, AuditError> {
        if ancestor == descendant {
            return Ok(true);
        }
        let json = self.get_json(&format!(
            "/repos/{repo}/compare/{}...{}",
            pct(ancestor),
            pct(descendant)
        ))?;
        match json.get_string("status") {
            Some("ahead") | Some("identical") => Ok(true),
            Some("behind") | Some("diverged") => Ok(false),
            Some(other) => Err(AuditError::Github(format!(
                "unexpected GitHub compare status {other}"
            ))),
            None => Err(AuditError::Github(
                "GitHub compare response lacks status".into(),
            )),
        }
    }

    fn workflow_runs(&self, repo: &str, sha: &str) -> Result<Vec<WorkflowEvidence>, AuditError> {
        let json = self.get_json(&format!(
            "/repos/{repo}/actions/runs?head_sha={}&event=push&status=completed&per_page=100",
            pct(sha)
        ))?;
        let runs = json.get_array("workflow_runs").ok_or_else(|| {
            AuditError::Github("workflow runs response lacks workflow_runs".into())
        })?;
        let mut result = Vec::new();
        for run in runs {
            let Some(object) = run.as_object() else {
                continue;
            };
            let (Some(id), Some(head_sha), Some(url)) = (
                object_u64(object, "id"),
                object_string(object, "head_sha"),
                object_string(object, "html_url"),
            ) else {
                continue;
            };
            result.push(WorkflowEvidence {
                id,
                head_sha: head_sha.to_owned(),
                conclusion: object_nullable_string(object, "conclusion").unwrap_or_default(),
                url: url.to_owned(),
            });
        }
        Ok(result)
    }

    fn branch_observation(
        &self,
        repo: &str,
        branch: &str,
    ) -> Result<BranchObservation, AuditError> {
        let endpoint = format!("/repos/{repo}/git/ref/heads/{}", pct_path(branch));
        let (status, body) = self.request(&endpoint, false, false)?;
        if status == 404 {
            return Ok(BranchObservation::Absent);
        }
        if status != 200 {
            return Err(AuditError::Github(format!(
                "branch lookup returned HTTP {status}"
            )));
        }
        let json = JsonValue::parse(&body)?;
        let object = json
            .get_object("object")
            .ok_or_else(|| AuditError::Github("branch response lacks object".into()))?;
        let sha = object_string(object, "sha")
            .ok_or_else(|| AuditError::Github("branch response lacks object.sha".into()))?
            .to_owned();
        let owner = repo
            .split('/')
            .next()
            .ok_or_else(|| AuditError::CanonicalState("invalid repository name".into()))?;
        let prs = self.get_json(&format!(
            "/repos/{repo}/pulls?state=open&head={}",
            pct(&format!("{owner}:{branch}"))
        ))?;
        let mut open_pr_urls = Vec::new();
        if let Some(array) = prs.as_array() {
            for value in array {
                if let Some(url) = value
                    .as_object()
                    .and_then(|object| object_string(object, "html_url"))
                {
                    open_pr_urls.push(url.to_owned());
                }
            }
        }
        open_pr_urls.sort();
        open_pr_urls.dedup();
        Ok(BranchObservation::Present { sha, open_pr_urls })
    }

    fn get_json(&self, endpoint: &str) -> Result<JsonValue, AuditError> {
        let (_, body) = self.request(endpoint, true, false)?;
        JsonValue::parse(&body)
    }

    fn request(&self, endpoint: &str, fail: bool, raw: bool) -> Result<(u16, String), AuditError> {
        let url = format!("{}{}", self.config.api_url.trim_end_matches('/'), endpoint);
        let output = Command::new("curl")
            .args(["--silent", "--show-error", "--location", "--request", "GET"])
            .arg("--header")
            .arg("X-GitHub-Api-Version: 2022-11-28")
            .arg("--header")
            .arg(format!("Authorization: Bearer {}", self.config.token))
            .arg("--header")
            .arg(if raw {
                "Accept: application/vnd.github.raw+json"
            } else {
                "Accept: application/vnd.github+json"
            })
            .args(["--write-out", "\n%{http_code}"])
            .arg(url)
            .output()
            .map_err(|error| {
                AuditError::Github(format!(
                    "failed to execute bounded GitHub HTTP client: {error}"
                ))
            })?;
        if !output.status.success() {
            return Err(AuditError::Github(
                "bounded GitHub HTTP client failed".into(),
            ));
        }
        let stdout = String::from_utf8(output.stdout)
            .map_err(|_| AuditError::Github("GitHub response was not UTF-8".into()))?;
        let (body, status_text) = stdout.rsplit_once('\n').ok_or_else(|| {
            AuditError::Github("GitHub response lacked HTTP status trailer".into())
        })?;
        let status = status_text
            .parse::<u16>()
            .map_err(|_| AuditError::Github("invalid HTTP status trailer".into()))?;
        if fail && !(200..300).contains(&status) {
            return Err(AuditError::Github(format!(
                "GitHub request returned HTTP {status}"
            )));
        }
        Ok((status, body.to_owned()))
    }
}

fn pct(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn pct_path(value: &str) -> String {
    value.split('/').map(pct).collect::<Vec<_>>().join("/")
}

fn json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value.is_control() => {
                output.push_str(&format!("\\u{:04x}", value as u32));
            }
            value => output.push(value),
        }
    }
    output.push('"');
    output
}

fn sha256_hex(input: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h = [
        0x6a09e667_u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut message = input.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.as_chunks::<64>().0 {
        let mut w = [0_u32; 64];
        for (index, word) in w.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    h.iter().map(|value| format!("{value:08x}")).collect()
}

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    fn parse(input: &str) -> Result<Self, AuditError> {
        let mut parser = JsonParser {
            bytes: input.as_bytes(),
            pos: 0,
        };
        let value = parser.value()?;
        parser.ws();
        if parser.pos != parser.bytes.len() {
            return Err(AuditError::Github(
                "trailing data in GitHub JSON response".into(),
            ));
        }
        Ok(value)
    }

    fn as_object(&self) -> Option<&BTreeMap<String, JsonValue>> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }

    fn get_object(&self, key: &str) -> Option<&BTreeMap<String, JsonValue>> {
        self.as_object()?.get(key)?.as_object()
    }

    fn get_array(&self, key: &str) -> Option<&[JsonValue]> {
        self.as_object()?.get(key)?.as_array()
    }

    fn get_string(&self, key: &str) -> Option<&str> {
        object_string(self.as_object()?, key)
    }

    fn get_nullable_string(&self, key: &str) -> Option<String> {
        object_nullable_string(self.as_object()?, key)
    }

    fn get_bool(&self, key: &str) -> Option<bool> {
        match self.as_object()?.get(key)? {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }
}

fn object_string<'a>(object: &'a BTreeMap<String, JsonValue>, key: &str) -> Option<&'a str> {
    match object.get(key)? {
        JsonValue::String(value) => Some(value),
        _ => None,
    }
}

fn object_nullable_string(object: &BTreeMap<String, JsonValue>, key: &str) -> Option<String> {
    match object.get(key)? {
        JsonValue::String(value) => Some(value.clone()),
        JsonValue::Null => None,
        _ => None,
    }
}

fn object_u64(object: &BTreeMap<String, JsonValue>, key: &str) -> Option<u64> {
    match object.get(key)? {
        JsonValue::Number(value) => value.parse().ok(),
        _ => None,
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl JsonParser<'_> {
    fn ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn value(&mut self) -> Result<JsonValue, AuditError> {
        self.ws();
        let byte = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| AuditError::Github("unexpected end of JSON".into()))?;
        match byte {
            b'n' => {
                self.literal(b"null")?;
                Ok(JsonValue::Null)
            }
            b't' => {
                self.literal(b"true")?;
                Ok(JsonValue::Bool(true))
            }
            b'f' => {
                self.literal(b"false")?;
                Ok(JsonValue::Bool(false))
            }
            b'"' => Ok(JsonValue::String(self.string()?)),
            b'[' => self.array(),
            b'{' => self.object(),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(AuditError::Github("unsupported JSON token".into())),
        }
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), AuditError> {
        if self.bytes.get(self.pos..self.pos + literal.len()) == Some(literal) {
            self.pos += literal.len();
            Ok(())
        } else {
            Err(AuditError::Github("invalid JSON literal".into()))
        }
    }

    fn string(&mut self) -> Result<String, AuditError> {
        self.pos += 1;
        let mut output = String::new();
        while self.pos < self.bytes.len() {
            let byte = self.bytes[self.pos];
            self.pos += 1;
            match byte {
                b'"' => return Ok(output),
                b'\\' => {
                    let escape = *self
                        .bytes
                        .get(self.pos)
                        .ok_or_else(|| AuditError::Github("bad JSON escape".into()))?;
                    self.pos += 1;
                    match escape {
                        b'"' => output.push('"'),
                        b'\\' => output.push('\\'),
                        b'/' => output.push('/'),
                        b'b' => output.push('\u{0008}'),
                        b'f' => output.push('\u{000c}'),
                        b'n' => output.push('\n'),
                        b'r' => output.push('\r'),
                        b't' => output.push('\t'),
                        b'u' => {
                            let hex = self
                                .bytes
                                .get(self.pos..self.pos + 4)
                                .ok_or_else(|| AuditError::Github("short unicode escape".into()))?;
                            self.pos += 4;
                            let text = std::str::from_utf8(hex)
                                .map_err(|_| AuditError::Github("invalid unicode escape".into()))?;
                            let code = u16::from_str_radix(text, 16)
                                .map_err(|_| AuditError::Github("invalid unicode escape".into()))?;
                            output.push(char::from_u32(u32::from(code)).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err(AuditError::Github("invalid JSON escape".into())),
                    }
                }
                value if value < 0x20 => {
                    return Err(AuditError::Github("control byte in JSON string".into()));
                }
                value if value.is_ascii() => output.push(value as char),
                _ => {
                    let start = self.pos - 1;
                    let text = std::str::from_utf8(&self.bytes[start..])
                        .map_err(|_| AuditError::Github("invalid UTF-8 JSON string".into()))?;
                    let character = text
                        .chars()
                        .next()
                        .ok_or_else(|| AuditError::Github("invalid UTF-8 JSON string".into()))?;
                    output.push(character);
                    self.pos = start + character.len_utf8();
                }
            }
        }
        Err(AuditError::Github("unterminated JSON string".into()))
    }

    fn number(&mut self) -> Result<JsonValue, AuditError> {
        let start = self.pos;
        while self.pos < self.bytes.len()
            && matches!(
                self.bytes[self.pos],
                b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'
            )
        {
            self.pos += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| AuditError::Github("invalid JSON number".into()))?;
        Ok(JsonValue::Number(text.to_owned()))
    }

    fn array(&mut self) -> Result<JsonValue, AuditError> {
        self.pos += 1;
        let mut values = Vec::new();
        loop {
            self.ws();
            if self.bytes.get(self.pos) == Some(&b']') {
                self.pos += 1;
                break;
            }
            values.push(self.value()?);
            self.ws();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(AuditError::Github("invalid JSON array".into())),
            }
        }
        Ok(JsonValue::Array(values))
    }

    fn object(&mut self) -> Result<JsonValue, AuditError> {
        self.pos += 1;
        let mut values = BTreeMap::new();
        loop {
            self.ws();
            if self.bytes.get(self.pos) == Some(&b'}') {
                self.pos += 1;
                break;
            }
            if self.bytes.get(self.pos) != Some(&b'"') {
                return Err(AuditError::Github("invalid JSON object key".into()));
            }
            let key = self.string()?;
            self.ws();
            if self.bytes.get(self.pos) != Some(&b':') {
                return Err(AuditError::Github("missing JSON object colon".into()));
            }
            self.pos += 1;
            let value = self.value()?;
            values.insert(key, value);
            self.ws();
            match self.bytes.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(AuditError::Github("invalid JSON object".into())),
            }
        }
        Ok(JsonValue::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn implementation(path: &str, sha: &str) -> RunEvidence {
        RunEvidence {
            run_path: path.into(),
            publication_sha: sha.into(),
            implementation_sha: sha.into(),
            ci_sha: sha.into(),
            ci_conclusion: "success".into(),
            pull_request_url: "https://github.com/shockerqt/example/pull/7".into(),
            pull_request_head_sha: sha.into(),
            role: RunEvidenceRole::Implementation,
        }
    }

    fn integration_audit(sha: &str) -> RunEvidence {
        RunEvidence {
            run_path: "runs/GOV-999/integration.md".into(),
            publication_sha: sha.into(),
            implementation_sha: sha.into(),
            ci_sha: sha.into(),
            ci_conclusion: "success".into(),
            pull_request_url: "https://github.com/shockerqt/example/pull/7".into(),
            pull_request_head_sha: sha.into(),
            role: RunEvidenceRole::IntegrationAudit {
                audited_implementation_sha: sha.into(),
                audited_pull_request_url: "https://github.com/shockerqt/example/pull/7".into(),
            },
        }
    }

    #[test]
    fn integration_audit_explicitly_selects_the_audited_implementation() {
        let old = implementation(
            "runs/GOV-999/old.md",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let selected = implementation(
            "runs/GOV-999/final.md",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        let audit = integration_audit("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert_eq!(
            select_audited_implementation(&[old, selected.clone(), audit]).unwrap(),
            selected
        );
    }

    #[test]
    fn multiple_implementation_candidates_without_explicit_audit_are_ambiguous() {
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
    fn administrative_integration_run_is_not_itself_an_implementation_candidate() {
        let implementation = implementation(
            "runs/GOV-999/implementation.md",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let audit = integration_audit("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(
            select_audited_implementation(&[implementation.clone(), audit]).unwrap(),
            implementation
        );
    }

    #[test]
    fn administrative_hint_without_matching_implementation_fails_closed() {
        let implementation = implementation(
            "runs/GOV-999/implementation.md",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let audit = integration_audit("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        assert!(matches!(
            select_audited_implementation(&[implementation, audit]),
            Err(AuditError::Verification(_))
        ));
    }

    #[test]
    fn conflicting_terminal_fields_are_ambiguous() {
        let section = "implementation_sha: a\nimplementation_sha: b\n";
        assert!(matches!(
            required_scalar(section, "implementation_sha:"),
            Err(AuditError::AmbiguousEvidence(_))
        ));
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn minimal_json_parser_reads_nested_github_shapes() {
        let value = JsonValue::parse(
            r#"{"merged":true,"head":{"sha":"abc"},"workflow_runs":[{"id":1}],"status":"ahead"}"#,
        )
        .unwrap();
        assert_eq!(value.get_bool("merged"), Some(true));
        assert_eq!(
            object_string(value.get_object("head").unwrap(), "sha"),
            Some("abc")
        );
        assert_eq!(
            object_u64(
                value.get_array("workflow_runs").unwrap()[0]
                    .as_object()
                    .unwrap(),
                "id"
            ),
            Some(1)
        );
        assert_eq!(value.get_string("status"), Some("ahead"));
    }
}
