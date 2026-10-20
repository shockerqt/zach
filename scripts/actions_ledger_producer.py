"""Bounded read-only producer observations; neither artifact data nor permission."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import re

from actions_request_handler import _validate_execution_bundle

REPOSITORY = "shockerqt/workspace-governance"
REPOSITORY_ID = 1260920764
MAX_PAGES = 10
MAX_ARCHIVE_BYTES = 393216


class LedgerProducerError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class LedgerProducerPolicy:
    workflow_id: int
    workflow_revision: str
    tool_revision: str
    repository_id: int = REPOSITORY_ID
    repository_full_name: str = REPOSITORY
    default_branch: str = "master"
    workflow_path: str = ".github/workflows/workspace-ledger-pilot.yml"
    producer_job_name: str = "control"
    artifact_prefix: str = "workspace-ledger-candidate"


@dataclass(frozen=True)
class IntegrationProducerPolicy:
    workflow_id: int
    workflow_revision: str
    tool_revision: str
    repository_id: int = REPOSITORY_ID
    repository_full_name: str = REPOSITORY
    default_branch: str = "master"
    workflow_path: str = ".github/workflows/workspace-operations.yml"
    producer_job_name: str = "verify"
    artifact_prefix: str = "workspace-integration-observation"


@dataclass(frozen=True)
class ArtifactReference:
    repository_id: int
    repository_full_name: str
    run_id: int
    run_attempt: int
    artifact_id: int
    archive_sha256: str
    content_sha256: str


def _require(value, code):
    if not value:
        raise LedgerProducerError(code)


def _id(value):
    return type(value) is int and 0 < value <= 2**53 - 1


def _same_id(value, expected):
    return _id(value) and value == expected


def _hash(value, length):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def _time(value):
    _require(isinstance(value, str) and len(value) <= 35 and re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", value
    ), "producer_time_invalid")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _pages(get, path, key):
    result, ids, total = [], set(), None
    for page in range(1, MAX_PAGES + 1):
        response = get(f"{path}?per_page=100&page={page}")
        count, entries = response.get("total_count"), response.get(key)
        _require(type(count) is int and 0 <= count <= 1000 and isinstance(entries, list)
                 and len(entries) <= 100 and (total is None or total == count), "producer_pagination_invalid")
        total = count
        for entry in entries:
            _require(isinstance(entry, dict) and _id(entry.get("id")) and entry["id"] not in ids,
                     "producer_pagination_invalid")
            ids.add(entry["id"])
            result.append(entry)
        _require(len(result) <= total, "producer_pagination_invalid")
        if len(result) == total:
            return result
        _require(len(entries) == 100, "producer_pagination_incomplete")
    raise LedgerProducerError("producer_pagination_incomplete")


def observe_ledger_producer(api, bundle, reference, policy, now):
    """Observe one exact producer attempt. Caller compares two observations and
    verifies downloaded archive/content hashes before publishing. No writes.
    """
    try:
        return _observe(api, bundle, reference, policy, now)
    except LedgerProducerError:
        raise
    except Exception:
        raise LedgerProducerError("producer_observation_invalid") from None


def observe_integration_producer(api, bundle, reference, policy, now):
    """Observe the separate fixed verification producer; not closure authority."""
    try:
        return _observe(api, bundle, reference, policy, now, integration=True)
    except LedgerProducerError:
        raise
    except Exception:
        raise LedgerProducerError("producer_observation_invalid") from None


def _observe(api, bundle, reference, policy, now, *, integration=False):
    policy_type = IntegrationProducerPolicy if integration else LedgerProducerPolicy
    workflow_path = (".github/workflows/workspace-operations.yml" if integration
                     else ".github/workflows/workspace-ledger-pilot.yml")
    job_name = "verify" if integration else "control"
    artifact_prefix = "workspace-integration-observation" if integration else "workspace-ledger-candidate"
    _require(isinstance(policy, policy_type) and isinstance(reference, ArtifactReference), "producer_policy_invalid")
    _require(policy.repository_id == REPOSITORY_ID and policy.repository_full_name == REPOSITORY
             and policy.default_branch == "master" and policy.workflow_path == workflow_path
             and policy.producer_job_name == job_name and policy.artifact_prefix == artifact_prefix
             and _id(policy.workflow_id) and _hash(policy.workflow_revision, 40) and _hash(policy.tool_revision, 40), "producer_policy_invalid")
    _require(reference.repository_id == REPOSITORY_ID and reference.repository_full_name == REPOSITORY
             and all(_id(getattr(reference, key)) for key in ("run_id", "run_attempt", "artifact_id"))
             and reference.run_attempt == 1 and _hash(reference.archive_sha256, 64)
             and _hash(reference.content_sha256, 64), "producer_reference_invalid")
    record = _validate_execution_bundle(bundle)
    parameters = getattr(bundle, "parameters", None)
    closure = isinstance(parameters, dict) and parameters.get("operation") == "task.complete_verified"
    _require(closure if integration else not closure, "producer_operation_invalid")
    _require(bundle.operation == "governance.ledger" and record["policy_revision"] == policy.workflow_revision
             and bundle.execution_id == f"{reference.run_id}-1", "producer_bundle_mismatch")
    now = _time(now) if isinstance(now, str) else now
    _require(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() == timezone.utc.utcoffset(now), "producer_time_invalid")

    def get(path):
        value = api("GET", path, body=None)
        _require(isinstance(value, dict), "producer_response_invalid")
        return value

    def public_zach_get(path):
        public_get = getattr(api, "public_zach_get", None)
        _require(callable(public_get), "producer_public_observation_unavailable")
        value = public_get(path)
        _require(type(value) is dict, "producer_response_invalid")
        return value

    root = f"/repos/{REPOSITORY}"
    repository = get(root)
    _require(_same_id(repository.get("id"), REPOSITORY_ID) and repository.get("full_name") == REPOSITORY
             and repository.get("default_branch") == "master", "producer_repository_mismatch")
    workflow = get(f"{root}/actions/workflows/{policy.workflow_id}")
    _require(_same_id(workflow.get("id"), policy.workflow_id) and workflow.get("path") == policy.workflow_path
             and workflow.get("state") == "active", "producer_workflow_mismatch")
    for repo, branch, revision in ((REPOSITORY, "master", policy.workflow_revision), ("shockerqt/zach", "main", policy.tool_revision)):
        observe = get if repo == REPOSITORY else public_zach_get
        head = observe(f"/repos/{repo}/git/ref/heads/{branch}").get("object", {}).get("sha")
        _require(_hash(head, 40), "producer_revision_invalid")
        if head != revision:
            comparison = observe(f"/repos/{repo}/compare/{revision}...{head}")
            _require(comparison.get("status") == "ahead" and comparison.get("base_commit", {}).get("sha") == revision
                     and comparison.get("merge_base_commit", {}).get("sha") == revision, "producer_revision_unrepresented")
    run = get(f"{root}/actions/runs/{reference.run_id}/attempts/{reference.run_attempt}")
    _require(_same_id(run.get("id"), reference.run_id) and _same_id(run.get("run_attempt"), 1)
             and _same_id(run.get("workflow_id"), policy.workflow_id) and run.get("path") == policy.workflow_path
             and run.get("head_sha") == policy.workflow_revision and run.get("event") == "issues"
             and run.get("head_branch") == "master" and _same_id(run.get("actor", {}).get("id"), record["sender_id"])
             and all(_same_id(run.get(key, {}).get("id"), REPOSITORY_ID) and run.get(key, {}).get("full_name") == REPOSITORY
                     for key in ("repository", "head_repository")), "producer_run_mismatch")
    jobs = _pages(get, f"{root}/actions/runs/{reference.run_id}/attempts/1/jobs", "jobs")
    matches = [job for job in jobs if job.get("name") == job_name]
    _require(len(matches) == 1, "producer_job_ambiguous")
    job = matches[0]
    _require(_same_id(job.get("run_id"), reference.run_id) and _same_id(job.get("run_attempt"), 1)
             and job.get("head_sha") == policy.workflow_revision and job.get("status") == "completed"
             and job.get("conclusion") == "success", "producer_job_incomplete")
    start, end = _time(job.get("started_at")), _time(job.get("completed_at"))
    _require(start <= end <= now, "producer_time_invalid")
    artifact = get(f"{root}/actions/artifacts/{reference.artifact_id}")
    artifacts = _pages(get, f"{root}/actions/runs/{reference.run_id}/artifacts", "artifacts")
    name = f"{policy.artifact_prefix}-{reference.run_id}-1"
    matches = [item for item in artifacts if item.get("name") == name or item.get("id") == reference.artifact_id]
    _require(len(matches) == 1 and matches[0] == artifact, "producer_artifact_ambiguous")
    wr = artifact.get("workflow_run", {})
    _require(_same_id(artifact.get("id"), reference.artifact_id) and artifact.get("name") == name
             and artifact.get("expired") is False and type(artifact.get("size_in_bytes")) is int
             and 0 < artifact["size_in_bytes"] <= MAX_ARCHIVE_BYTES
             and artifact.get("digest") == "sha256:" + reference.archive_sha256
             and _same_id(wr.get("id"), reference.run_id) and _same_id(wr.get("repository_id"), REPOSITORY_ID)
             and _same_id(wr.get("head_repository_id"), REPOSITORY_ID) and wr.get("head_sha") == policy.workflow_revision
             and wr.get("head_branch") == "master", "producer_artifact_mismatch")
    created = _time(artifact.get("created_at"))
    _require(start <= created <= end and _time(artifact.get("expires_at")) > now, "producer_artifact_time_invalid")
    return {"reference": asdict(reference), "producer_job_id": job["id"], "producer_started_at": job["started_at"],
            "producer_completed_at": job["completed_at"], "artifact_created_at": artifact["created_at"],
            "artifact_expires_at": artifact["expires_at"], "artifact_updated_at": artifact.get("updated_at"),
            "artifact_size_in_bytes": artifact["size_in_bytes"], "workflow_revision": policy.workflow_revision,
            "tool_revision": policy.tool_revision}
