"""Dispatch one trusted, typed GitHub Actions recipe without exposing raw inputs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Callable, Final, Mapping
import urllib.parse

from actions_git_journal import ApiError


MAX_SAFE_INTEGER: Final[int] = 2**53 - 1
MAX_RESULT_BYTES: Final[int] = 16 * 1024
MAX_RECONCILIATION_PAGES: Final[int] = 10
RECONCILIATION_PER_PAGE: Final[int] = 100
DISPATCH_CLOCK_SKEW: Final[timedelta] = timedelta(minutes=5)
DISPATCH_MAX_DELAY: Final[timedelta] = timedelta(minutes=15)
SUPPORTED_RECIPE: Final[str] = "sandbox.delivery"
SHA40_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
ALIAS_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
REPOSITORY_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,99})/[A-Za-z0-9_.-]{1,100}$"
)
WORKFLOW_PATH_RE: Final[re.Pattern[str]] = re.compile(
    r"^\.github/workflows/([A-Za-z0-9][A-Za-z0-9_.-]{0,99}\.ya?ml)$"
)
REF_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")


class RecipeDispatchError(Exception):
    """Sanitized recipe failure, including unknown-effect outcomes."""

    def __init__(self, code: str, *, retryable: bool = False, ambiguous: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.ambiguous = ambiguous


@dataclass(frozen=True)
class RecipeDispatchPolicy:
    """Trusted identity and fixed workflow selected outside the Issue request."""

    recipe: str
    repository_alias: str
    repository_full_name: str
    repository_id: int
    workflow_id: int
    workflow_path: str
    ref: str
    actor_id: int

    def __post_init__(self) -> None:
        _validate_policy(self)


def _positive_int(value: Any) -> bool:
    return type(value) is int and 0 < value <= MAX_SAFE_INTEGER


def _validate_policy(policy: RecipeDispatchPolicy) -> None:
    if not isinstance(policy, RecipeDispatchPolicy):
        raise RecipeDispatchError("invalid_recipe_policy")
    workflow_match = (
        WORKFLOW_PATH_RE.fullmatch(policy.workflow_path)
        if isinstance(policy.workflow_path, str)
        else None
    )
    if (
        policy.recipe != SUPPORTED_RECIPE
        or not isinstance(policy.repository_alias, str)
        or not ALIAS_RE.fullmatch(policy.repository_alias)
        or not isinstance(policy.repository_full_name, str)
        or not REPOSITORY_RE.fullmatch(policy.repository_full_name)
        or not _positive_int(policy.repository_id)
        or not _positive_int(policy.workflow_id)
        or workflow_match is None
        or not isinstance(policy.ref, str)
        or not REF_RE.fullmatch(policy.ref)
        or ".." in policy.ref.split("/")
        or not _positive_int(policy.actor_id)
    ):
        raise RecipeDispatchError("invalid_recipe_policy")


def _validate_parameters(
    parameters: Mapping[str, Any], policy: RecipeDispatchPolicy, request_id: str
) -> tuple[str, dict[str, str]]:
    if type(parameters) is not dict or parameters.get("recipe") != policy.recipe:
        raise RecipeDispatchError("recipe_not_allowed")
    if not isinstance(request_id, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9._-]{7,127}", request_id
    ):
        raise RecipeDispatchError("invalid_request_id")

    operation = parameters.get("operation")
    common = {"recipe", "operation", "source_sha", "artifact_sha256", "expected_current"}
    deploy_only = {
        "artifact_run_id",
        "artifact_run_attempt",
        "artifact_id",
        "transport_digest",
    }
    if operation == "deploy":
        if set(parameters) != common | deploy_only:
            raise RecipeDispatchError("invalid_recipe_parameters")
    elif operation == "rollback":
        if set(parameters) != common:
            raise RecipeDispatchError("invalid_recipe_parameters")
    else:
        raise RecipeDispatchError("recipe_operation_not_allowed")

    source_sha = parameters.get("source_sha")
    artifact_sha256 = parameters.get("artifact_sha256")
    expected_current = parameters.get("expected_current")
    if not isinstance(source_sha, str) or not SHA40_RE.fullmatch(source_sha):
        raise RecipeDispatchError("invalid_recipe_source")
    if not isinstance(artifact_sha256, str) or not SHA256_RE.fullmatch(artifact_sha256):
        raise RecipeDispatchError("invalid_recipe_artifact_digest")
    if not isinstance(expected_current, str) or not SHA40_RE.fullmatch(expected_current):
        raise RecipeDispatchError("invalid_recipe_expected_current")

    inputs = {
        "operation": operation,
        "request_id": request_id,
        "source_sha": source_sha,
        "artifact_sha256": artifact_sha256,
        "expected_current": expected_current,
    }
    if operation == "deploy":
        for name in ("artifact_run_id", "artifact_run_attempt", "artifact_id"):
            value = parameters.get(name)
            if not _positive_int(value):
                raise RecipeDispatchError("invalid_recipe_artifact_identity")
            inputs[name] = str(value)
        transport_digest = parameters.get("transport_digest")
        if not isinstance(transport_digest, str) or not SHA256_RE.fullmatch(
            transport_digest
        ):
            raise RecipeDispatchError("invalid_recipe_transport_digest")
        inputs["transport_digest"] = transport_digest
    inputs["request_binding"] = hashlib.sha256(
        json.dumps(inputs, allow_nan=False, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
    ).hexdigest()
    return operation, inputs


def _get(api_transport: Callable[..., Any], path: str) -> Any:
    try:
        return api_transport("GET", path, body=None)
    except Exception:
        raise RecipeDispatchError("recipe_preflight_failed", retryable=True) from None


def _bounded(result: dict[str, Any]) -> dict[str, Any]:
    try:
        encoded = json.dumps(result, allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise RecipeDispatchError("recipe_result_invalid", ambiguous=True) from None
    if len(encoded) > MAX_RESULT_BYTES:
        raise RecipeDispatchError("recipe_result_too_large", ambiguous=True)
    return result


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
    ):
        raise RecipeDispatchError("invalid_recipe_acceptance_time")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise RecipeDispatchError("invalid_recipe_acceptance_time") from None
    return parsed


def _preflight(
    policy: RecipeDispatchPolicy,
    api_transport: Callable[..., Any],
    *,
    require_dispatchable: bool,
) -> int:
    repository = _get(api_transport, f"/repos/{policy.repository_full_name}")
    if (
        type(repository) is not dict
        or repository.get("id") != policy.repository_id
        or repository.get("full_name") != policy.repository_full_name
        or (require_dispatchable and repository.get("default_branch") != policy.ref)
    ):
        raise RecipeDispatchError("recipe_repository_identity_mismatch")

    workflow = _get(
        api_transport,
        f"/repos/{policy.repository_full_name}/actions/workflows/{policy.workflow_id}",
    )
    workflow_id = workflow.get("id") if type(workflow) is dict else None
    if (
        workflow_id != policy.workflow_id
        or workflow.get("path") != policy.workflow_path
        or (require_dispatchable and workflow.get("state") != "active")
    ):
        raise RecipeDispatchError("recipe_workflow_identity_mismatch")
    return workflow_id


def _expected_title(operation: str, request_id: str, request_binding: str) -> str:
    return f"Sandbox {operation} / {request_id} / {request_binding}"


def _validate_run(
    run: Any,
    run_id: int,
    operation: str,
    request_id: str,
    accepted_at: datetime,
    inputs: Mapping[str, str],
    policy: RecipeDispatchPolicy,
) -> dict[str, Any]:
    if type(run) is not dict:
        raise RecipeDispatchError("recipe_dispatch_readback_ambiguous", ambiguous=True)
    actor = run.get("actor")
    repository = run.get("repository")
    head_repository = run.get("head_repository")
    head_sha = run.get("head_sha")
    status = run.get("status")
    conclusion = run.get("conclusion")
    created_at_value = run.get("created_at")
    try:
        created_at = _parse_timestamp(created_at_value)
    except RecipeDispatchError:
        raise RecipeDispatchError("recipe_dispatch_readback_ambiguous", ambiguous=True) from None
    run_url = f"https://api.github.com/repos/{policy.repository_full_name}/actions/runs/{run_id}"
    html_url = f"https://github.com/{policy.repository_full_name}/actions/runs/{run_id}"
    if (
        run.get("id") != run_id
        or run.get("workflow_id") != policy.workflow_id
        or run.get("path") != policy.workflow_path
        or run.get("event") != "workflow_dispatch"
        or run.get("head_branch") != policy.ref
        or run.get("display_title")
        != _expected_title(operation, request_id, inputs["request_binding"])
        or created_at < accepted_at - DISPATCH_CLOCK_SKEW
        or created_at > accepted_at + DISPATCH_MAX_DELAY
        or not isinstance(head_sha, str)
        or not SHA40_RE.fullmatch(head_sha)
        or type(actor) is not dict
        or actor.get("id") != policy.actor_id
        or type(repository) is not dict
        or repository.get("id") != policy.repository_id
        or repository.get("full_name") != policy.repository_full_name
        or type(head_repository) is not dict
        or head_repository.get("id") != policy.repository_id
        or head_repository.get("full_name") != policy.repository_full_name
        or run.get("url") != run_url
        or run.get("html_url") != html_url
        or status not in {"queued", "in_progress", "waiting", "requested", "pending", "completed"}
        or (status == "completed" and not isinstance(conclusion, str))
        or (status != "completed" and conclusion is not None)
    ):
        raise RecipeDispatchError("recipe_dispatch_readback_ambiguous", ambiguous=True)

    return _bounded(
        {
            "schema_version": 1,
            "kind": "workspace.recipe.dispatch.result",
            "result": "dispatched",
            "recipe": policy.recipe,
            "operation": operation,
            "request_id": request_id,
            "request_binding": inputs["request_binding"],
            "repository": policy.repository_alias,
            "repository_full_name": policy.repository_full_name,
            "repository_id": policy.repository_id,
            "workflow": {"id": policy.workflow_id, "path": policy.workflow_path},
            "ref": policy.ref,
            "workflow_head_sha": head_sha,
            "status": status,
            "workflow_run": {
                "id": run_id,
                "run_url": run_url,
                "html_url": html_url,
            },
            "source_sha": inputs["source_sha"],
            "artifact_sha256": inputs["artifact_sha256"],
            "expected_current": inputs["expected_current"],
        }
    )


def _readback(
    api_transport: Callable[..., Any],
    run_id: int,
    operation: str,
    request_id: str,
    accepted_at: datetime,
    inputs: Mapping[str, str],
    policy: RecipeDispatchPolicy,
) -> dict[str, Any]:
    try:
        run = api_transport(
            "GET",
            f"/repos/{policy.repository_full_name}/actions/runs/{run_id}",
            body=None,
        )
    except Exception:
        raise RecipeDispatchError("recipe_dispatch_readback_ambiguous", ambiguous=True) from None
    return _validate_run(run, run_id, operation, request_id, accepted_at, inputs, policy)


def _run_snapshot(run: Any) -> tuple[Any, ...]:
    if type(run) is not dict or not _positive_int(run.get("id")):
        raise RecipeDispatchError("recipe_reconciliation_malformed", ambiguous=True)
    actor = run.get("actor")
    repository = run.get("repository")
    head_repository = run.get("head_repository")
    return (
        run.get("id"),
        run.get("workflow_id"),
        run.get("path"),
        run.get("event"),
        run.get("head_branch"),
        run.get("head_sha"),
        run.get("display_title"),
        run.get("created_at"),
        actor.get("id") if type(actor) is dict else None,
        repository.get("id") if type(repository) is dict else None,
        repository.get("full_name") if type(repository) is dict else None,
        head_repository.get("id") if type(head_repository) is dict else None,
        head_repository.get("full_name") if type(head_repository) is dict else None,
        run.get("url"),
        run.get("html_url"),
    )


def _scan_runs(
    api_transport: Callable[..., Any], policy: RecipeDispatchPolicy
) -> tuple[tuple[tuple[Any, ...], ...], list[dict[str, Any]]]:
    seen: set[int] = set()
    snapshot: list[tuple[Any, ...]] = []
    runs: list[dict[str, Any]] = []
    encoded_ref = urllib.parse.quote(policy.ref, safe="")
    for page in range(1, MAX_RECONCILIATION_PAGES + 1):
        path = (
            f"/repos/{policy.repository_full_name}/actions/workflows/{policy.workflow_id}/runs"
            f"?event=workflow_dispatch&branch={encoded_ref}"
            f"&per_page={RECONCILIATION_PER_PAGE}&page={page}"
        )
        try:
            response = api_transport("GET", path, body=None)
        except Exception:
            raise RecipeDispatchError("recipe_reconciliation_api_failed", ambiguous=True) from None
        page_runs = response.get("workflow_runs") if type(response) is dict else None
        total_count = response.get("total_count") if type(response) is dict else None
        if (
            type(total_count) is not int
            or total_count < 0
            or type(page_runs) is not list
            or len(page_runs) > RECONCILIATION_PER_PAGE
        ):
            raise RecipeDispatchError("recipe_reconciliation_malformed", ambiguous=True)
        for run in page_runs:
            item = _run_snapshot(run)
            run_id = item[0]
            if run_id in seen:
                raise RecipeDispatchError("recipe_reconciliation_duplicate_run", ambiguous=True)
            seen.add(run_id)
            snapshot.append(item)
            runs.append(run)
        if len(page_runs) < RECONCILIATION_PER_PAGE:
            if len(runs) != total_count:
                raise RecipeDispatchError("recipe_reconciliation_incomplete", ambiguous=True)
            return tuple(snapshot), runs
    raise RecipeDispatchError("recipe_reconciliation_pagination_exceeded", ambiguous=True)


def dispatch_recipe(
    parameters: Mapping[str, Any],
    request_id: str,
    accepted_at: str,
    policy: RecipeDispatchPolicy,
    api_transport: Callable[..., Any],
) -> dict[str, Any]:
    """Validate and dispatch the one configured recipe, returning its immutable run ID."""
    _validate_policy(policy)
    if not callable(api_transport):
        raise RecipeDispatchError("invalid_recipe_transport")
    operation, inputs = _validate_parameters(parameters, policy, request_id)
    acceptance_time = _parse_timestamp(accepted_at)
    workflow_id = _preflight(policy, api_transport, require_dispatchable=True)

    try:
        response = api_transport(
            "POST",
            f"/repos/{policy.repository_full_name}/actions/workflows/{workflow_id}/dispatches",
            body={"ref": policy.ref, "inputs": inputs},
        )
    except ApiError as error:
        if 400 <= error.status < 500:
            raise RecipeDispatchError("recipe_dispatch_rejected") from None
        raise RecipeDispatchError("recipe_dispatch_ambiguous", ambiguous=True) from None
    except Exception:
        raise RecipeDispatchError("recipe_dispatch_ambiguous", ambiguous=True) from None

    run_id = response.get("workflow_run_id") if type(response) is dict else None
    if not _positive_int(run_id) or set(response) != {
        "workflow_run_id",
        "run_url",
        "html_url",
    }:
        raise RecipeDispatchError("recipe_dispatch_response_ambiguous", ambiguous=True)
    run_url = f"https://api.github.com/repos/{policy.repository_full_name}/actions/runs/{run_id}"
    html_url = f"https://github.com/{policy.repository_full_name}/actions/runs/{run_id}"
    if response.get("run_url") != run_url or response.get("html_url") != html_url:
        raise RecipeDispatchError("recipe_dispatch_response_ambiguous", ambiguous=True)
    return _readback(
        api_transport,
        run_id,
        operation,
        request_id,
        acceptance_time,
        inputs,
        policy,
    )


def reconcile_recipe(
    parameters: Mapping[str, Any],
    request_id: str,
    accepted_at: str,
    policy: RecipeDispatchPolicy,
    api_transport: Callable[..., Any],
) -> dict[str, Any]:
    """Find one previously dispatched run without repeating the dispatch effect."""
    _validate_policy(policy)
    if not callable(api_transport):
        raise RecipeDispatchError("invalid_recipe_transport")
    operation, inputs = _validate_parameters(parameters, policy, request_id)
    acceptance_time = _parse_timestamp(accepted_at)
    _preflight(policy, api_transport, require_dispatchable=False)

    snapshot_1, runs = _scan_runs(api_transport, policy)
    snapshot_2, _ = _scan_runs(api_transport, policy)
    if snapshot_1 != snapshot_2:
        raise RecipeDispatchError("recipe_reconciliation_unstable", ambiguous=True)

    matches: list[int] = []
    expected_title = _expected_title(operation, request_id, inputs["request_binding"])
    for run in runs:
        if run.get("display_title") != expected_title:
            continue
        try:
            _validate_run(
                run,
                run["id"],
                operation,
                request_id,
                acceptance_time,
                inputs,
                policy,
            )
        except (KeyError, RecipeDispatchError):
            continue
        matches.append(run["id"])

    if len(matches) != 1:
        code = (
            "recipe_reconciliation_not_found"
            if not matches
            else "recipe_reconciliation_multiple_runs"
        )
        raise RecipeDispatchError(code, ambiguous=True)

    return _readback(
        api_transport,
        matches[0],
        operation,
        request_id,
        acceptance_time,
        inputs,
        policy,
    )
