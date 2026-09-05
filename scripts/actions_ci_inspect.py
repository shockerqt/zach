"""Bounded, read-only GitHub Actions CI observation.

The returned facts describe one configured CI workflow at one exact commit. They
do not authorize task closure, integration, deployment, or any other effect.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import re
from typing import Any, Callable, Final, Mapping, Optional


PER_PAGE: Final[int] = 100
MAX_PAGES: Final[int] = 10
MAX_RECENT_RUNS: Final[int] = 10
MAX_RESULT_BYTES: Final[int] = 16 * 1024
MAX_LABEL_BYTES: Final[int] = 160
FIXED_WORKFLOW_PATH: Final[str] = ".github/workflows/ci.yml"
SHA40_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")
ALIAS_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
REPOSITORY_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,99})/[A-Za-z0-9_.-]{1,100}$"
)
TIMESTAMP_RE: Final[re.Pattern[str]] = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
RUN_STATUSES: Final[frozenset[str]] = frozenset(
    {"queued", "in_progress", "completed", "waiting", "requested", "pending"}
)
RUN_CONCLUSIONS: Final[frozenset[str]] = frozenset(
    {
        "success",
        "failure",
        "neutral",
        "cancelled",
        "skipped",
        "timed_out",
        "action_required",
        "stale",
        "startup_failure",
    }
)


class CiInspectError(Exception):
    """Sanitized inspection failure with an optional safe-to-repeat signal."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True)
class CiInspectionPolicy:
    """Trusted repository and CI workflow identity supplied by configuration."""

    repository_alias: str
    repository_full_name: str
    repository_id: int
    workflow_id: int
    workflow_path: str


def _positive_int(value: Any) -> bool:
    return type(value) is int and 0 < value <= 2**53 - 1


def _same_positive_id(value: Any, expected: int) -> bool:
    return _positive_int(value) and value == expected


def _validate_policy(policy: CiInspectionPolicy) -> None:
    if not isinstance(policy, CiInspectionPolicy):
        raise CiInspectError("invalid_policy")
    if not isinstance(policy.repository_alias, str) or not ALIAS_RE.fullmatch(policy.repository_alias):
        raise CiInspectError("invalid_policy")
    if not isinstance(policy.repository_full_name, str) or not REPOSITORY_RE.fullmatch(policy.repository_full_name):
        raise CiInspectError("invalid_policy")
    if not _positive_int(policy.repository_id) or not _positive_int(policy.workflow_id):
        raise CiInspectError("invalid_policy")
    if policy.workflow_path != FIXED_WORKFLOW_PATH:
        raise CiInspectError("invalid_policy")


def _validate_parameters(parameters: Mapping[str, Any], policy: CiInspectionPolicy) -> str:
    if type(parameters) is not dict or set(parameters) != {"repository", "source_sha"}:
        raise CiInspectError("invalid_parameters")
    if parameters["repository"] != policy.repository_alias:
        raise CiInspectError("repository_not_allowed")
    source_sha = parameters["source_sha"]
    if not isinstance(source_sha, str) or not SHA40_RE.fullmatch(source_sha):
        raise CiInspectError("invalid_source_sha")
    return source_sha


def _get(api_transport: Callable[..., Any], path: str) -> Any:
    try:
        return api_transport("GET", path, body=None)
    except Exception:
        raise CiInspectError("api_request_failed", retryable=True) from None


def _validate_status(status: Any, conclusion: Any, code: str) -> tuple[str, Optional[str]]:
    if not isinstance(status, str) or status not in RUN_STATUSES:
        raise CiInspectError(code)
    if status == "completed":
        if not isinstance(conclusion, str) or conclusion not in RUN_CONCLUSIONS:
            raise CiInspectError(code)
        return status, conclusion
    if conclusion is not None:
        raise CiInspectError(code)
    return status, None


def _validate_timestamp(value: Any, code: str) -> str:
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        raise CiInspectError(code)
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise CiInspectError(code) from None
    return value


def _run_summary(
    row: Any,
    policy: CiInspectionPolicy,
    source_sha: str,
) -> dict[str, Any]:
    if not isinstance(row, dict):
        raise CiInspectError("malformed_run")
    run_id = row.get("id")
    attempt = row.get("run_attempt")
    if not _positive_int(run_id) or not _positive_int(attempt):
        raise CiInspectError("malformed_run")
    repository = row.get("repository")
    head_repository = row.get("head_repository")
    if (
        not isinstance(repository, dict)
        or not _same_positive_id(repository.get("id"), policy.repository_id)
        or repository.get("full_name") != policy.repository_full_name
        or not isinstance(head_repository, dict)
        or not _same_positive_id(head_repository.get("id"), policy.repository_id)
        or head_repository.get("full_name") != policy.repository_full_name
        or not _same_positive_id(row.get("workflow_id"), policy.workflow_id)
        or row.get("path") != policy.workflow_path
        or row.get("head_sha") != source_sha
    ):
        raise CiInspectError("foreign_run")
    html_url = f"https://github.com/{policy.repository_full_name}/actions/runs/{run_id}"
    if row.get("html_url") != html_url:
        raise CiInspectError("foreign_run")
    event = row.get("event")
    if (
        not isinstance(event, str)
        or not 1 <= len(event) <= 64
        or not event.isascii()
        or not all(char.isalnum() or char in "_.-" for char in event)
    ):
        raise CiInspectError("malformed_run")
    status, conclusion = _validate_status(row.get("status"), row.get("conclusion"), "malformed_run")
    return {
        "id": run_id,
        "attempt": attempt,
        "workflow_id": policy.workflow_id,
        "workflow_path": policy.workflow_path,
        "event": event,
        "status": status,
        "conclusion": conclusion,
        "head_sha": source_sha,
        "repository_id": policy.repository_id,
        "head_repository_id": policy.repository_id,
        "created_at": _validate_timestamp(row.get("created_at"), "malformed_run"),
        "updated_at": _validate_timestamp(row.get("updated_at"), "malformed_run"),
        "html_url": html_url,
    }


def _page_items(response: Any, collection_key: str, expected_total: Optional[int]) -> tuple[int, list[Any]]:
    if not isinstance(response, dict):
        raise CiInspectError("malformed_pagination")
    for completeness_key in ("truncated", "incomplete_results"):
        if completeness_key in response:
            if type(response[completeness_key]) is not bool:
                raise CiInspectError("malformed_pagination")
            if response[completeness_key]:
                raise CiInspectError("incomplete_pagination", retryable=True)
    total = response.get("total_count")
    items = response.get(collection_key)
    if type(total) is not int or total < 0 or not isinstance(items, list) or len(items) > PER_PAGE:
        raise CiInspectError("malformed_pagination")
    if expected_total is not None and total != expected_total:
        raise CiInspectError("pagination_changed", retryable=True)
    return total, items


def _list_runs(
    api_transport: Callable[..., Any], policy: CiInspectionPolicy, source_sha: str
) -> tuple[int, list[dict[str, Any]]]:
    base = f"/repos/{policy.repository_full_name}/actions/workflows/{policy.workflow_id}/runs"
    summaries: list[dict[str, Any]] = []
    seen: set[int] = set()
    expected_total: Optional[int] = None
    for page in range(1, MAX_PAGES + 1):
        response = _get(
            api_transport,
            f"{base}?head_sha={source_sha}&per_page={PER_PAGE}&page={page}",
        )
        total, rows = _page_items(response, "workflow_runs", expected_total)
        if expected_total is None:
            expected_total = total
            # GitHub caps filtered workflow-run searches at 1,000 results.
            if total >= PER_PAGE * MAX_PAGES:
                raise CiInspectError("incomplete_pagination", retryable=True)
        for row in rows:
            summary = _run_summary(row, policy, source_sha)
            if summary["id"] in seen:
                raise CiInspectError("malformed_pagination")
            seen.add(summary["id"])
            summaries.append(summary)
        if len(summaries) == total:
            return total, summaries
        if len(summaries) > total or not rows or len(rows) < PER_PAGE:
            raise CiInspectError("incomplete_pagination", retryable=True)
    raise CiInspectError("incomplete_pagination", retryable=True)


def _truncate_label(value: Any) -> tuple[str, bool]:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise CiInspectError("malformed_job")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise CiInspectError("malformed_job") from None
    if len(encoded) <= MAX_LABEL_BYTES:
        return value, False
    prefix = encoded[: MAX_LABEL_BYTES - 3]
    while prefix:
        try:
            return prefix.decode("utf-8") + "…", True
        except UnicodeDecodeError:
            prefix = prefix[:-1]
    raise CiInspectError("malformed_job")


def _job_summary(
    row: Any,
    policy: CiInspectionPolicy,
    source_sha: str,
    run_id: int,
    attempt: int,
) -> tuple[dict[str, Any], bool]:
    if not isinstance(row, dict) or not _positive_int(row.get("id")):
        raise CiInspectError("malformed_job")
    job_id = row["id"]
    if (not _same_positive_id(row.get("run_id"), run_id)
            or not _same_positive_id(row.get("run_attempt"), attempt)
            or row.get("head_sha") != source_sha):
        raise CiInspectError("foreign_job")
    html_url = f"https://github.com/{policy.repository_full_name}/actions/runs/{run_id}/job/{job_id}"
    if row.get("html_url") != html_url:
        raise CiInspectError("foreign_job")
    status, conclusion = _validate_status(row.get("status"), row.get("conclusion"), "malformed_job")
    name, truncated = _truncate_label(row.get("name"))
    steps = row.get("steps")
    if not isinstance(steps, list):
        raise CiInspectError("malformed_job")
    failed_steps: list[dict[str, Any]] = []
    seen_steps: set[int] = set()
    for step in steps:
        if not isinstance(step, dict) or not _positive_int(step.get("number")):
            raise CiInspectError("malformed_job")
        number = step["number"]
        if number in seen_steps:
            raise CiInspectError("malformed_job")
        seen_steps.add(number)
        _, step_conclusion = _validate_status(
            step.get("status"), step.get("conclusion"), "malformed_job"
        )
        if step_conclusion not in (None, "success", "neutral", "skipped"):
            step_name, step_truncated = _truncate_label(step.get("name"))
            truncated = truncated or step_truncated
            failed_steps.append(
                {"number": number, "name": step_name, "conclusion": step_conclusion}
            )
    return (
        {
            "id": job_id,
            "name": name,
            "status": status,
            "conclusion": conclusion,
            "html_url": html_url,
            "failed_steps": failed_steps,
        },
        truncated,
    )


def _list_jobs(
    api_transport: Callable[..., Any],
    policy: CiInspectionPolicy,
    source_sha: str,
    run_id: int,
    attempt: int,
) -> tuple[int, list[dict[str, Any]], bool]:
    base = (
        f"/repos/{policy.repository_full_name}/actions/runs/{run_id}"
        f"/attempts/{attempt}/jobs"
    )
    jobs: list[dict[str, Any]] = []
    seen: set[int] = set()
    labels_truncated = False
    expected_total: Optional[int] = None
    for page in range(1, MAX_PAGES + 1):
        response = _get(api_transport, f"{base}?per_page={PER_PAGE}&page={page}")
        total, rows = _page_items(response, "jobs", expected_total)
        if expected_total is None:
            expected_total = total
            if total > PER_PAGE * MAX_PAGES:
                raise CiInspectError("incomplete_pagination", retryable=True)
        for row in rows:
            summary, truncated = _job_summary(row, policy, source_sha, run_id, attempt)
            if summary["id"] in seen:
                raise CiInspectError("malformed_pagination")
            seen.add(summary["id"])
            labels_truncated = labels_truncated or truncated
            jobs.append(summary)
        if len(jobs) == total:
            return total, jobs, labels_truncated
        if len(jobs) > total or not rows or len(rows) < PER_PAGE:
            raise CiInspectError("incomplete_pagination", retryable=True)
    raise CiInspectError("incomplete_pagination", retryable=True)


def _bounded_result(result: dict[str, Any]) -> dict[str, Any]:
    try:
        encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise CiInspectError("result_encoding_failed") from None
    if len(encoded) > MAX_RESULT_BYTES:
        raise CiInspectError("result_too_large")
    return result


def inspect_ci(
    parameters: Mapping[str, Any],
    policy: CiInspectionPolicy,
    api_transport: Callable[..., Any],
) -> dict[str, Any]:
    """Return complete, bounded CI facts for the configured workflow and exact SHA."""
    _validate_policy(policy)
    if not callable(api_transport):
        raise CiInspectError("invalid_transport")
    source_sha = _validate_parameters(parameters, policy)

    repository = _get(api_transport, f"/repos/{policy.repository_full_name}")
    if (
        not isinstance(repository, dict)
        or not _same_positive_id(repository.get("id"), policy.repository_id)
        or repository.get("full_name") != policy.repository_full_name
    ):
        raise CiInspectError("repository_identity_mismatch")

    workflow = _get(
        api_transport,
        f"/repos/{policy.repository_full_name}/actions/workflows/{policy.workflow_id}",
    )
    if (
        not isinstance(workflow, dict)
        or not _same_positive_id(workflow.get("id"), policy.workflow_id)
        or workflow.get("path") != policy.workflow_path
        or workflow.get("state") != "active"
    ):
        raise CiInspectError("workflow_identity_mismatch")

    commit = _get(api_transport, f"/repos/{policy.repository_full_name}/commits/{source_sha}")
    if not isinstance(commit, dict) or commit.get("sha") != source_sha:
        raise CiInspectError("commit_identity_mismatch")

    observed_total, runs = _list_runs(api_transport, policy, source_sha)
    runs.sort(key=lambda run: (run["created_at"], run["id"]), reverse=True)
    base_result: dict[str, Any] = {
        "schema_version": 1,
        "kind": "github.ci.inspect",
        "repository": policy.repository_alias,
        "repository_full_name": policy.repository_full_name,
        "repository_id": policy.repository_id,
        "source_sha": source_sha,
        "workflow": {
            "id": policy.workflow_id,
            "path": policy.workflow_path,
            "state": "active",
        },
        "observed_total": observed_total,
        "complete": True,
        "runs": runs[:MAX_RECENT_RUNS],
    }
    if not runs:
        base_result.update(
            {
                "result": "not_found",
                "selected_run": None,
                "jobs_observed_total": 0,
                "jobs_complete": True,
                "jobs": [],
                "labels_truncated": False,
            }
        )
        return _bounded_result(base_result)

    selected = runs[0]
    jobs_total, jobs, labels_truncated = _list_jobs(
        api_transport,
        policy,
        source_sha,
        selected["id"],
        selected["attempt"],
    )
    jobs.sort(key=lambda job: job["id"])
    # Define a final observation boundary: a new run may have appeared while
    # jobs were collected even if the originally selected run did not change.
    final_total, final_runs = _list_runs(api_transport, policy, source_sha)
    final_runs.sort(key=lambda run: (run["created_at"], run["id"]), reverse=True)
    if not final_runs or final_runs[0] != selected:
        raise CiInspectError("run_changed", retryable=True)
    base_result["observed_total"] = final_total
    base_result["runs"] = final_runs[:MAX_RECENT_RUNS]
    # Observe the run again after collecting the exact attempt's jobs. A rerun or
    # state change during pagination invalidates the otherwise internally complete view.
    exact = _get(
        api_transport,
        f"/repos/{policy.repository_full_name}/actions/runs/{selected['id']}",
    )
    exact_summary = _run_summary(exact, policy, source_sha)
    if exact_summary != selected:
        raise CiInspectError("run_changed", retryable=True)
    base_result.update(
        {
            "result": "found",
            "selected_run": exact_summary,
            "jobs_observed_total": jobs_total,
            "jobs_complete": True,
            "jobs": jobs,
            "labels_truncated": labels_truncated,
        }
    )
    return _bounded_result(base_result)
