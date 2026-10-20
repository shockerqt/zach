//! Read-only facts for a separately authenticated Actions verification job.
//! These values are neither an authorized receipt nor a closure attestation.
use super::*;
use std::io::{Read, Write};
use std::process::{Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const MAX_SAFE_ID: u64 = 9_007_199_254_740_991;

fn safe_id(id: u64) -> bool {
    id > 0 && id <= MAX_SAFE_ID
}

pub(super) fn configure_observer_command(command: &mut Command) {
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8");
    command.args([
        "-q",
        "--proto",
        "=https",
        "--connect-timeout",
        "10",
        "--max-time",
        "30",
        "--max-filesize",
        "1048576",
        "--max-redirs",
        "0",
        "--header",
        "@-",
    ]);
}

fn bounded_read(reader: impl Read, maximum: usize) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    reader
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > maximum {
        Err(())
    } else {
        Ok(bytes)
    }
}

/// Pipe credentials and cap both streams independently of curl's version or
/// Content-Length. Any overflow/error/timeout kills and reaps the child.
pub(super) fn bounded_http_output(
    command: &mut Command,
    token: &str,
) -> Result<Output, AuditError> {
    require(
        !token.is_empty() && token.len() <= 4096 && token.bytes().all(|b| b.is_ascii_graphic()),
        "invalid observer credential shape",
    )?;
    let failure = || AuditError::Github("bounded observer HTTP process failed".into());
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| failure())?;
    let stdout = child.stdout.take().ok_or_else(failure)?;
    let stderr = child.stderr.take().ok_or_else(failure)?;
    let (send, receive) = mpsc::channel();
    let send_err = send.clone();
    let out_thread = std::thread::spawn(move || {
        let _ = send.send((true, bounded_read(stdout, 1_048_580)));
    });
    let err_thread = std::thread::spawn(move || {
        let _ = send_err.send((false, bounded_read(stderr, 8192)));
    });
    let written = child
        .stdin
        .take()
        .ok_or_else(failure)
        .and_then(|mut input| {
            input
                .write_all(format!("Authorization: Bearer {token}\n").as_bytes())
                .map_err(|_| failure())
        });
    let mut out = None;
    let mut err = None;
    let mut failed = written.is_err();
    for _ in 0..2 {
        if failed {
            break;
        }
        match receive.recv_timeout(Duration::from_secs(35)) {
            Ok((is_stdout, Ok(bytes))) => {
                if is_stdout {
                    out = Some(bytes);
                } else {
                    err = Some(bytes);
                }
            }
            _ => failed = true,
        }
    }
    if failed {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|_| failure());
    let _ = out_thread.join();
    let _ = err_thread.join();
    if failed {
        return Err(failure());
    }
    Ok(Output {
        status: status?,
        stdout: out.ok_or_else(failure)?,
        stderr: err.ok_or_else(failure)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenIntegrationRequest {
    pub governance_sha: String,
    pub task_id: String,
    pub run_id: String,
    pub request_id: String,
}

/// Reviewed runtime configuration, never an Issue parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationObserverPolicy {
    pub ci_workflow_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenIntegrationObservations {
    pub request: FrozenIntegrationRequest,
    pub repository: String,
    pub repository_alias: String,
    pub branch: String,
    pub implementation: RunEvidence,
    pub implementation_ci: WorkflowEvidence,
    pub ci_workflow_id: u64,
    pub pull_request: PullRequestEvidence,
    pub representation: RepresentationEvidence,
    pub post_merge_ci: WorkflowEvidence,
    pub remote_branch: BranchObservation,
    /// Queried even when the canonical branch no longer exists.
    pub open_pr_urls: Vec<String>,
}

fn require(ok: bool, message: &str) -> Result<(), AuditError> {
    if ok {
        Ok(())
    } else {
        Err(AuditError::Verification(message.into()))
    }
}

fn sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn bounded_json_depth(raw: &str) -> Result<(), AuditError> {
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    for byte in raw.bytes() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    require(depth <= 32, "observer JSON nesting exceeds bound")?;
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => (),
            }
        }
    }
    Ok(())
}

fn validate_request(
    request: &FrozenIntegrationRequest,
    policy: &IntegrationObserverPolicy,
) -> Result<(), AuditError> {
    super::validate_request(&AuditRequest {
        task_id: request.task_id.clone(),
        request_id: request.request_id.clone(),
    })?;
    require(
        sha(&request.governance_sha),
        "frozen Governance SHA is invalid",
    )?;
    require(
        !request.run_id.is_empty()
            && request.run_id.len() <= 200
            && request
                .run_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "explicit run identity is invalid",
    )?;
    require(
        policy.ci_workflow_path.starts_with(".github/workflows/")
            && policy.ci_workflow_path.ends_with(".yml")
            && !policy.ci_workflow_path.contains("..")
            && policy.ci_workflow_path.len() <= 200,
        "trusted CI workflow policy is invalid",
    )
}

fn scalar(markdown: &str, key: &str, expected: &str) -> Result<(), AuditError> {
    require(
        frontmatter_value(markdown, key)?.as_deref() == Some(expected),
        "canonical implementation metadata mismatch",
    )
}

fn canonical_run<R: GovernanceReader>(
    reader: &mut R,
    request: &FrozenIntegrationRequest,
) -> Result<(String, String, String, RunEvidence, String), AuditError> {
    let revision = &request.governance_sha;
    let routing = parse_manifest_discovery(&reader.read("governance-manifest.yaml", revision)?)?;
    let membership = resolve_global_task_membership(
        &reader.read(&routing.global_tasks, revision)?,
        &routing,
        &request.task_id,
    )?;
    let path = resolve_project_shard(
        &reader.read(&membership.index_path, revision)?,
        &membership.project,
        &request.task_id,
    )?;
    let task = reader.read(&path, revision)?;
    scalar(&task, "kind", "task")?;
    scalar(&task, "schema_version", "1")?;
    scalar(&task, "id", &request.task_id)?;
    scalar(&task, "project", &membership.project)?;
    let branch = frontmatter_value(&task, "branch")?
        .ok_or_else(|| AuditError::CanonicalState("missing canonical branch".into()))?;
    require(
        branch.starts_with("task/") && branch.len() <= 200 && !branch.contains(".."),
        "invalid canonical task branch",
    )?;
    let alias = frontmatter_value(&task, "target_repository")?
        .ok_or_else(|| AuditError::CanonicalState("missing target repository".into()))?;
    let repository = resolve_repository(&reader.read("projects.yaml", revision)?, &alias)?;
    let links = parse_task_run_links(&task, &request.task_id)?;
    require(links.len() <= 100, "too many canonical run links")?;
    let mut selected = None;
    for link in links {
        let run = reader.read(&link.path, revision)?;
        scalar(&run, "id", &link.id)?;
        require(
            run_task_identity(&run)?.as_deref() == Some(&request.task_id),
            "linked run belongs to another task",
        )?;
        require(
            frontmatter_value(&run, "status")?.as_deref() != Some("active"),
            "task has active runs",
        )?;
        if link.id == request.run_id {
            for (key, value) in [
                ("kind", "run"),
                ("schema_version", "1"),
                ("status", "completed"),
                ("run_type", "execution"),
                ("execution_profile", "github-connector"),
                ("worktree", "none"),
                ("repository", alias.as_str()),
                ("branch", branch.as_str()),
            ] {
                scalar(&run, key, value)?;
            }
            require(
                matches!(
                    frontmatter_value(&run, "execution_role")?.as_deref(),
                    None | Some("standard")
                ),
                "implementation run must have standard role",
            )?;
            require(
                markdown_section(&run, "## Remote integration evidence")?.is_none(),
                "implementation cannot contain audit evidence",
            )?;
            let publication = owned_section(
                &run,
                "## Remote publication evidence",
                request,
                &alias,
                &branch,
                "publication",
            )?;
            let terminal = owned_section(
                &run,
                "## Remote terminal evidence",
                request,
                &alias,
                &branch,
                "terminal",
            )?;
            let evidence = parse_run_evidence(&link.path, &run)?.ok_or_else(|| {
                AuditError::Verification("missing implementation evidence".into())
            })?;
            require(
                coherent_terminal(&evidence)
                    && sha(&evidence.implementation_sha)
                    && required_scalar(&publication, "published_after_sha:")?
                        == evidence.implementation_sha,
                "implementation terminal binding is incoherent",
            )?;
            selected = Some((evidence, required_scalar(&terminal, "ci_run_url:")?));
        }
    }
    let (implementation, ci_url) = selected.ok_or_else(|| {
        AuditError::CanonicalState("explicit run is not linked by canonical task".into())
    })?;
    Ok((repository, alias, branch, implementation, ci_url))
}

fn owned_section(
    run: &str,
    heading: &str,
    request: &FrozenIntegrationRequest,
    alias: &str,
    branch: &str,
    stage: &str,
) -> Result<String, AuditError> {
    let section = markdown_section(run, heading)?
        .ok_or_else(|| AuditError::Verification("missing owned evidence".into()))?;
    require(
        matches!(
            required_scalar(&section, "schema_version:")?.as_str(),
            "1" | "2"
        ),
        "unsupported evidence schema",
    )?;
    // The existing scalar parser rejects duplicates. Bound ownership and the
    // repository/branch mapping rather than accepting copied evidence.
    require(
        required_scalar(&section, "run_id:")? == request.run_id
            && required_scalar(&section, "stage:")? == stage,
        "evidence ownership mismatch",
    )?;
    require(
        yaml_scalar_at_path(&section, &["repository", "name"])?.as_deref() == Some(alias)
            && yaml_scalar_at_path(&section, &["branch", "name"])?.as_deref() == Some(branch),
        "evidence location mismatch",
    )?;
    Ok(section)
}

fn ci_id(url: &str, repository: &str) -> Result<u64, AuditError> {
    let prefix = format!("https://github.com/{repository}/actions/runs/");
    let suffix = url
        .strip_prefix(&prefix)
        .ok_or_else(|| AuditError::Verification("CI URL repository mismatch".into()))?;
    // Exact attempt URLs are deliberately rejected until attempt-specific reads
    // are implemented; never silently substitute the latest attempt.
    require(
        !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()),
        "CI URL is not an exact run URL",
    )?;
    let id = suffix
        .parse::<u64>()
        .map_err(|_| AuditError::Verification("invalid CI run ID".into()))?;
    require(id > 0 && id <= 9_007_199_254_740_991, "invalid CI run ID")?;
    Ok(id)
}

fn verify_ci(
    json: &JsonValue,
    repository: &str,
    repository_id: u64,
    id: u64,
    expected_sha: &str,
    path: &str,
) -> Result<WorkflowEvidence, AuditError> {
    require(
        safe_id(repository_id) && safe_id(id),
        "CI numeric identity exceeds bound",
    )?;
    let object = json
        .as_object()
        .ok_or_else(|| AuditError::Verification("invalid CI response".into()))?;
    let repo = json
        .get_object("repository")
        .ok_or_else(|| AuditError::Verification("CI repository missing".into()))?;
    require(
        object_u64(object, "id") == Some(id)
            && object_string(repo, "full_name") == Some(repository)
            && object_u64(repo, "id") == Some(repository_id),
        "CI identity mismatch",
    )?;
    require(
        json.get_string("head_sha") == Some(expected_sha)
            && json.get_string("status") == Some("completed")
            && json.get_string("conclusion") == Some("success")
            && json.get_string("path") == Some(path),
        "CI SHA, workflow or conclusion mismatch",
    )?;
    let expected_url = format!("https://github.com/{repository}/actions/runs/{id}");
    require(
        json.get_string("html_url") == Some(expected_url.as_str()),
        "CI URL mismatch",
    )?;
    Ok(WorkflowEvidence {
        id,
        head_sha: expected_sha.into(),
        conclusion: "success".into(),
        url: expected_url,
    })
}

/// Independent GET-only collection. Caller supplies trusted frozen context;
/// Actions owns acceptance, claims, immutable artifacts and replay. Publisher
/// must authenticate this job/artifact before any lifecycle transition.
pub fn collect_frozen_integration(
    config: &GithubConfig,
    request: &FrozenIntegrationRequest,
    policy: &IntegrationObserverPolicy,
) -> Result<FrozenIntegrationObservations, AuditError> {
    collect(config, request, policy).map_err(|error| match error {
        AuditError::Github(_) => {
            AuditError::Github("frozen integration GitHub observation failed".into())
        }
        AuditError::CanonicalState(_) => {
            AuditError::CanonicalState("frozen canonical state is invalid".into())
        }
        AuditError::AmbiguousEvidence(_) => {
            AuditError::AmbiguousEvidence("frozen integration evidence is ambiguous".into())
        }
        AuditError::Verification(_) => {
            AuditError::Verification("frozen integration verification failed".into())
        }
        AuditError::InvalidRequest(_) => {
            AuditError::InvalidRequest("frozen integration request is invalid".into())
        }
        AuditError::Configuration(_) => {
            AuditError::Configuration("frozen integration configuration is invalid".into())
        }
        AuditError::Idempotency(_) => {
            AuditError::Idempotency("unexpected collector idempotency failure".into())
        }
    })
}

fn collect(
    config: &GithubConfig,
    request: &FrozenIntegrationRequest,
    policy: &IntegrationObserverPolicy,
) -> Result<FrozenIntegrationObservations, AuditError> {
    require(
        config.api_url.trim_end_matches('/') == "https://api.github.com"
            && config.governance_repository == "shockerqt/workspace-governance"
            && config.governance_default_branch == "master",
        "observer source configuration is fixed",
    )?;
    validate_request(request, policy)?;
    let github = GithubHttp {
        config,
        bounded_observer: true,
    };
    let integrated_head = github.commit_sha(&config.governance_repository, "master")?;
    require(sha(&integrated_head), "invalid integrated Governance head")?;
    let represented = github.is_ancestor_or_equal(
        &config.governance_repository,
        &request.governance_sha,
        &integrated_head,
    )?;
    verify_source_representation(&request.governance_sha, &integrated_head, represented)?;
    let mut reader = GithubGovernanceReader {
        github: &github,
        repository: &config.governance_repository,
    };
    let (repository, repository_alias, branch, implementation, ci_url) =
        canonical_run(&mut reader, request)?;
    let repo = github.get_json(&format!("/repos/{repository}"))?;
    require(
        repo.get_string("full_name") == Some(repository.as_str()),
        "repository identity mismatch",
    )?;
    let repository_id = repo
        .as_object()
        .and_then(|o| object_u64(o, "id"))
        .filter(|id| safe_id(*id))
        .ok_or_else(|| AuditError::Verification("repository numeric identity missing".into()))?;
    let default_branch = repo
        .get_string("default_branch")
        .filter(|value| !value.is_empty() && value.len() <= 200)
        .ok_or_else(|| AuditError::Verification("repository default branch missing".into()))?;
    let id = ci_id(&ci_url, &repository)?;
    let ci = github.get_json(&format!("/repos/{repository}/actions/runs/{id}"))?;
    let ci_workflow_id = ci
        .as_object()
        .and_then(|o| object_u64(o, "workflow_id"))
        .filter(|id| safe_id(*id))
        .ok_or_else(|| AuditError::Verification("CI workflow identity missing".into()))?;
    let workflow = github.get_json(&format!(
        "/repos/{repository}/actions/workflows/{ci_workflow_id}"
    ))?;
    require(
        workflow.as_object().and_then(|o| object_u64(o, "id")) == Some(ci_workflow_id)
            && workflow.get_string("path") == Some(policy.ci_workflow_path.as_str())
            && workflow.get_string("state") == Some("active"),
        "trusted CI workflow metadata mismatch",
    )?;
    let implementation_ci = verify_ci(
        &ci,
        &repository,
        repository_id,
        id,
        &implementation.implementation_sha,
        &policy.ci_workflow_path,
    )?;
    let pr_location = parse_pr_url(&implementation.pull_request_url)?;
    require(
        pr_location.repository == repository,
        "PR repository mismatch",
    )?;
    let pull_request = github.pull_request(&pr_location)?;
    let merge_sha = pull_request
        .merge_commit_sha
        .as_deref()
        .ok_or_else(|| AuditError::Verification("missing merge SHA".into()))?;
    require(
        sha(merge_sha) && sha(&pull_request.head_sha),
        "invalid PR SHA",
    )?;
    let representation = RepresentationEvidence {
        implementation_is_ancestor_or_equal_of_pr_head: github.is_ancestor_or_equal(
            &repository,
            &implementation.implementation_sha,
            &pull_request.head_sha,
        )?,
        pr_head_is_ancestor_or_equal_of_merge: github.is_ancestor_or_equal(
            &repository,
            &pull_request.head_sha,
            merge_sha,
        )?,
    };
    let mut post_merge_runs = Vec::new();
    for candidate in github.workflow_runs(&repository, merge_sha)? {
        if candidate.conclusion != "success" {
            continue;
        }
        let json = github.get_json(&format!(
            "/repos/{repository}/actions/runs/{}",
            candidate.id
        ))?;
        if json.get_string("path") != Some(policy.ci_workflow_path.as_str()) {
            continue;
        }
        verify_post_merge_context(&json, default_branch, ci_workflow_id)?;
        post_merge_runs.push(verify_ci(
            &json,
            &repository,
            repository_id,
            candidate.id,
            merge_sha,
            &policy.ci_workflow_path,
        )?);
    }
    let remote_branch = github.branch_observation(&repository, &branch)?;
    let open_pr_urls = open_prs(&github, &repository, &branch)?;
    verify_cleanup_stability(&remote_branch, &open_pr_urls)?;
    let audit_request = AuditRequest {
        task_id: request.task_id.clone(),
        request_id: request.request_id.clone(),
    };
    let evaluated = evaluate_snapshot(AuditSnapshot {
        task_id: request.task_id.clone(),
        request_id: request.request_id.clone(),
        request_digest: canonical_request_digest(&audit_request)?,
        governance_sha: request.governance_sha.clone(),
        target_repository: repository.clone(),
        canonical_branch: branch.clone(),
        audited_implementation: implementation.clone(),
        pull_request: pull_request.clone(),
        representation: representation.clone(),
        post_merge_runs,
        branch: remote_branch.clone(),
    })?;
    Ok(FrozenIntegrationObservations {
        request: request.clone(),
        repository,
        repository_alias,
        branch,
        implementation,
        implementation_ci,
        ci_workflow_id,
        pull_request,
        representation,
        post_merge_ci: evaluated.selected_ci,
        remote_branch,
        open_pr_urls,
    })
}

fn verify_source_representation(
    frozen: &str,
    integrated: &str,
    represented: bool,
) -> Result<(), AuditError> {
    require(
        sha(frozen) && sha(integrated) && represented,
        "frozen Governance source is not integrated",
    )
}

fn verify_post_merge_context(
    json: &JsonValue,
    default_branch: &str,
    workflow_id: u64,
) -> Result<(), AuditError> {
    require(
        safe_id(workflow_id)
            && json.as_object().and_then(|o| object_u64(o, "workflow_id")) == Some(workflow_id)
            && json.get_string("event") == Some("push")
            && json.get_string("head_branch") == Some(default_branch)
            && !default_branch.is_empty(),
        "post-merge CI is not the canonical default-branch workflow",
    )
}

fn verify_cleanup_stability(
    branch: &BranchObservation,
    open_pr_urls: &[String],
) -> Result<(), AuditError> {
    if let BranchObservation::Present {
        sha: observed,
        open_pr_urls: first,
    } = branch
    {
        require(
            sha(observed) && first == open_pr_urls,
            "branch cleanup observations are invalid or unstable",
        )?;
    }
    Ok(())
}

fn open_prs(
    github: &GithubHttp<'_>,
    repository: &str,
    branch: &str,
) -> Result<Vec<String>, AuditError> {
    let owner = repository
        .split('/')
        .next()
        .ok_or_else(|| AuditError::Verification("invalid repository".into()))?;
    let json = github.get_json(&format!(
        "/repos/{repository}/pulls?state=open&head={}&per_page=100",
        pct(&format!("{owner}:{branch}"))
    ))?;
    parse_open_prs(&json, repository)
}

fn parse_open_prs(json: &JsonValue, repository: &str) -> Result<Vec<String>, AuditError> {
    let entries = json
        .as_array()
        .ok_or_else(|| AuditError::Verification("invalid open PR response".into()))?;
    require(entries.len() < 100, "open PR response may be truncated")?;
    let mut result = Vec::new();
    for entry in entries {
        let object = entry
            .as_object()
            .ok_or_else(|| AuditError::Verification("invalid open PR".into()))?;
        let url = object_string(object, "html_url")
            .ok_or_else(|| AuditError::Verification("missing open PR URL".into()))?;
        require(
            parse_pr_url(url)?.repository == repository,
            "open PR repository mismatch",
        )?;
        result.push(url.into());
    }
    result.sort();
    result.dedup();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: &str = "ZACH-002-20261020-000000-implementation";
    const RUN_PATH: &str = "runs/ZACH-002/20261020-000000-implementation.md";
    const BRANCH: &str = "task/ZACH-002-audit";

    struct Reader(BTreeMap<String, String>);
    impl GovernanceReader for Reader {
        fn read(&mut self, path: &str, revision: &str) -> Result<String, AuditError> {
            assert_eq!(revision, "a".repeat(40));
            self.0
                .get(path)
                .cloned()
                .ok_or_else(|| AuditError::CanonicalState("fixture missing".into()))
        }
    }
    fn request() -> FrozenIntegrationRequest {
        FrozenIntegrationRequest {
            governance_sha: "a".repeat(40),
            task_id: "ZACH-002".into(),
            run_id: RUN.into(),
            request_id: "request-0001".into(),
        }
    }
    fn fixture() -> Reader {
        let mut files = BTreeMap::new();
        files.insert("governance-manifest.yaml".into(), "schema_version: 2\nledger:\n  discovery:\n    global_tasks: indexes/tasks.yaml\n    project_tasks: indexes/tasks/<project>.yaml\n".into());
        files.insert("indexes/tasks.yaml".into(), r#"{"schema_version":1,"projects":[{"project":"zach","index":"indexes/tasks/zach.yaml","task_ids":["ZACH-002"]}]}"#.into());
        files.insert("indexes/tasks/zach.yaml".into(), r#"{"schema_version":1,"project":"zach","tasks":[{"id":"ZACH-002","path":"tasks/ZACH-002-audit.md"}]}"#.into());
        files.insert(
            "projects.yaml".into(),
            "projects:\n- repository: zach\n  clone_url: https://github.com/shockerqt/zach\n"
                .into(),
        );
        files.insert("tasks/ZACH-002-audit.md".into(), format!("---\nkind: task\nschema_version: 1\nid: ZACH-002\nproject: zach\ntarget_repository: zach\nbranch: {BRANCH}\n---\n## Runs\n- [{RUN}](../{RUN_PATH})\n"));
        let owned = |stage: &str| {
            format!(
                "schema_version: 2\nrun_id: {RUN}\nstage: {stage}\nrepository:\n  name: zach\nbranch:\n  name: {BRANCH}\n"
            )
        };
        let implementation = "b".repeat(40);
        files.insert(RUN_PATH.into(), format!("---\nkind: run\nschema_version: 1\nid: {RUN}\ntask: ZACH-002\nstatus: completed\nrun_type: execution\nexecution_profile: github-connector\nworktree: none\nrepository: zach\nbranch: {BRANCH}\n---\n## Remote publication evidence\n```yaml\n{}publication:\n  published_after_sha: {implementation}\n```\n## Remote terminal evidence\n```yaml\n{}terminal:\n  implementation_sha: {implementation}\n  ci_sha: {implementation}\n  ci_conclusion: success\n  ci_run_url: https://github.com/shockerqt/zach/actions/runs/12\n  pull_request_url: https://github.com/shockerqt/zach/pull/2\n  pull_request_head_sha: {implementation}\n```\n", owned("publication"), owned("terminal")));
        Reader(files)
    }
    #[test]
    fn frozen_selection_and_metadata_fail_closed() {
        assert!(canonical_run(&mut fixture(), &request()).is_ok());
        let mut wrong = request();
        wrong.run_id = "ZACH-002-wrong".into();
        assert!(canonical_run(&mut fixture(), &wrong).is_err());
        for (from, to) in [
            (
                "execution_profile: github-connector",
                "execution_profile: local",
            ),
            ("worktree: none", "worktree: /tmp/other"),
            ("run_type: execution", "run_type: definition"),
            ("repository: zach", "repository: other"),
            ("schema_version: 1", "schema_version: 0"),
            ("status: completed", "status: active"),
        ] {
            let mut reader = fixture();
            let run = reader.0.get_mut(RUN_PATH).unwrap();
            *run = run.replacen(from, to, 1);
            assert!(canonical_run(&mut reader, &request()).is_err(), "{from}");
        }
        let mut reader = fixture();
        let run = reader.0.get_mut(RUN_PATH).unwrap();
        *run = run.replacen(
            "worktree: none",
            "execution_role: integration-audit\nworktree: none",
            1,
        );
        assert!(canonical_run(&mut reader, &request()).is_err());
        let mut reader = fixture();
        let run = reader.0.get_mut(RUN_PATH).unwrap();
        *run = run.replacen(&format!("run_id: {RUN}"), "run_id: ZACH-002-other", 1);
        assert!(canonical_run(&mut reader, &request()).is_err());
    }
    fn ci() -> String {
        format!(
            r#"{{"id":12,"repository":{{"id":123,"full_name":"shockerqt/zach"}},"head_sha":"{}","path":".github/workflows/ci.yml","status":"completed","conclusion":"success","html_url":"https://github.com/shockerqt/zach/actions/runs/12"}}"#,
            "b".repeat(40)
        )
    }
    #[test]
    fn independent_ci_rejects_mismatched_identity_sha_workflow_and_state() {
        let check = |raw: &str| {
            verify_ci(
                &JsonValue::parse(raw).unwrap(),
                "shockerqt/zach",
                123,
                12,
                &"b".repeat(40),
                ".github/workflows/ci.yml",
            )
        };
        assert!(check(&ci()).is_ok());
        for (from, to) in [
            ("\"id\":12,", "\"id\":13,"),
            ("\"id\":123", "\"id\":124"),
            ("shockerqt/zach", "attacker/zach"),
            ("ci.yml", "other.yml"),
            ("completed", "in_progress"),
            ("success", "failure"),
        ] {
            assert!(check(&ci().replace(from, to)).is_err());
        }
        assert!(check(&ci().replace(&"b".repeat(40), &"c".repeat(40))).is_err());
        assert!(
            ci_id(
                "https://github.com/shockerqt/zach/actions/runs/12/attempts/1",
                "shockerqt/zach"
            )
            .is_err()
        );
    }
    #[test]
    fn open_pr_observation_is_independent_of_ref_presence() {
        // This parser is called unconditionally after branch lookup, including Absent.
        let json = JsonValue::parse(r#"[{"html_url":"https://github.com/shockerqt/zach/pull/2"}]"#)
            .unwrap();
        assert_eq!(
            parse_open_prs(&json, "shockerqt/zach").unwrap(),
            vec!["https://github.com/shockerqt/zach/pull/2"]
        );
        assert!(parse_open_prs(&json, "attacker/zach").is_err());
        assert!(bounded_json_depth(&"[".repeat(33)).is_err());
        assert!(bounded_json_depth(r#"{"quoted":"[[[\"[[["}"#).is_ok());
    }

    #[test]
    fn fixed_sources_are_rejected_before_any_http() {
        let policy = IntegrationObserverPolicy {
            ci_workflow_path: ".github/workflows/ci.yml".into(),
        };
        for (api, repository) in [
            ("https://attacker.invalid", "shockerqt/workspace-governance"),
            ("https://api.github.com", "attacker/governance"),
        ] {
            let config = GithubConfig {
                api_url: api.into(),
                governance_repository: repository.into(),
                token: "synthetic-only".into(),
                governance_default_branch: "master".into(),
            };
            assert!(collect_frozen_integration(&config, &request(), &policy).is_err());
        }
        assert!(!safe_id(MAX_SAFE_ID + 1));
        assert!(!safe_id(0));
    }

    #[test]
    fn integrated_source_default_branch_and_stable_cleanup_are_required() {
        assert!(verify_source_representation(&"a".repeat(40), &"b".repeat(40), true).is_ok());
        assert!(verify_source_representation(&"a".repeat(40), &"b".repeat(40), false).is_err());
        let json = |branch: &str| {
            JsonValue::parse(&format!(
                r#"{{"workflow_id":12,"event":"push","head_branch":"{branch}"}}"#
            ))
            .unwrap()
        };
        assert!(verify_post_merge_context(&json("main"), "main", 12).is_ok());
        assert!(verify_post_merge_context(&json("task/other"), "main", 12).is_err());
        assert!(
            verify_post_merge_context(
                &JsonValue::parse(r#"{"workflow_id":12,"event":"push"}"#).unwrap(),
                "main",
                12
            )
            .is_err()
        );
        let present = BranchObservation::Present {
            sha: "a".repeat(40),
            open_pr_urls: vec!["https://github.com/shockerqt/zach/pull/2".into()],
        };
        assert!(verify_cleanup_stability(&present, &[]).is_err());
        let malformed = BranchObservation::Present {
            sha: "invalid".into(),
            open_pr_urls: vec![],
        };
        assert!(verify_cleanup_stability(&malformed, &[]).is_err());
        assert!(
            verify_cleanup_stability(
                &BranchObservation::Absent,
                &["https://github.com/shockerqt/zach/pull/2".into()]
            )
            .is_ok()
        );
    }

    #[test]
    fn observer_command_does_not_put_authorization_in_arguments() {
        let mut command = Command::new("curl");
        command.env("GITHUB_TOKEN", "synthetic-only");
        configure_observer_command(&mut command);
        let args = command
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(args.first().map(String::as_str), Some("-q"));
        assert!(args.windows(2).any(|pair| pair == ["--proto", "=https"]));
        assert_eq!(command.get_envs().count(), 3);
        assert!(command.get_envs().all(|(key, _)| key != "GITHUB_TOKEN"));
        assert!(args.windows(2).any(|pair| pair == ["--header", "@-"]));
        assert!(
            !args
                .iter()
                .any(|arg| arg.contains("Authorization") || arg.contains("synthetic-only"))
        );
        assert!(bounded_read(&b"12345"[..], 4).is_err());
        assert_eq!(bounded_read(&b"1234"[..], 4).unwrap(), b"1234");
    }

    #[cfg(unix)]
    #[test]
    fn observer_runner_bounds_both_pipes_and_passes_header_only_on_stdin() {
        let mut command = Command::new("sh");
        command.args(["-c", "read header; test -n \"$header\"; printf ok"]);
        let output = bounded_http_output(&mut command, "synthetic-only").unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"ok");
        for script in ["head -c 1048581 /dev/zero", "head -c 8193 /dev/zero >&2"] {
            let mut command = Command::new("sh");
            command.args(["-c", script]);
            assert!(bounded_http_output(&mut command, "synthetic-only").is_err());
        }
        let mut command = Command::new("sh");
        command.args(["-c", "exit 99"]);
        assert!(bounded_http_output(&mut command, "invalid\nheader").is_err());
    }
}
