"""Trusted request execution and effect reconciliation for GitHub Actions.

This module separates Publisher and Control authorities into distinct phases:
  Phase A: Publisher prepare (with Publisher authority)
    - durable acceptance & claim in operational journal
    - produce bounded, immutable execution bundle
  Phase B: Control execute (with Control authority, WITHOUT Governance Contents authority)
    - consume and validate frozen execution bundle
    - execute an allowlisted typed effect
    - publish authenticated receipt comment with readback
    - return bounded execution outcome without mutating journal
  Phase C: Publisher finalize (with Publisher authority, WITHOUT Control private key)
    - independently observe receipt on Issue with dual-scan observation
    - strictly verify Control App ID, bot user ID/type, exact revisions, and canonical body
    - terminalize journal record
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Any, Callable, Final, Mapping, Optional

from actions_ci_inspect import CiInspectError, CiInspectionPolicy, inspect_ci
from actions_recipe_dispatch import (
    RecipeDispatchError,
    RecipeDispatchPolicy,
    dispatch_recipe,
    reconcile_recipe,
)
from actions_git_journal import (
    AmbiguousPublication,
    ActionsGitJournal,
    ApiError,
    MAX_RECORD_BYTES,
    parse_and_validate_record,
    validate_request_id,
)
from actions_journal_coordinator import (
    ActionsJournalCoordinator,
    ClaimDisposition,
    CoordinatorError,
    TrustedIssuePolicy,
    TrustedReconciliationObservation,
)


MAX_EVENT_BYTES: Final[int] = 256 * 1024
MAX_RESULT_ENVELOPE_BYTES: Final[int] = 32 * 1024
MAX_COMMENT_BODY_BYTES: Final[int] = 64 * 1024
MAX_RECONCILIATION_PAGES: Final[int] = 10
RECONCILIATION_PER_PAGE: Final[int] = 100
MAX_TERMINAL_CODE_BYTES: Final[int] = 128
MAX_TERMINAL_REFERENCE_BYTES: Final[int] = 512
MAX_PUBLISHER_CHECKPOINT_BYTES: Final[int] = 64 * 1024

SHA40_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
EXECUTION_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

RECEIPT_MARKER_RE: Final[re.Pattern[str]] = re.compile(
    r"^<!-- zach-actions:receipt:v1:request_id=([A-Za-z0-9_.:-]{1,128}):"
    r"digest=([0-9a-f]{64}):op=([a-z0-9_.-]{1,64}):"
    r"accepted_revision=([0-9a-f]{40}):claim_revision=([0-9a-f]{40}) -->$"
)
PUBLISHER_INTENT_MARKER_RE: Final[re.Pattern[str]] = re.compile(
    r"^<!-- zach-actions:publisher-intent:v1:request_id=([A-Za-z0-9_-]{8,128}):"
    r"digest=([0-9a-f]{64}):execution_digest=([0-9a-f]{64}) -->$"
)
PUBLISHER_PREPARE_MARKER_RE: Final[re.Pattern[str]] = re.compile(
    r"^<!-- zach-actions:publisher-prepare:v1:request_id=([A-Za-z0-9_-]{8,128}):"
    r"digest=([0-9a-f]{64}):execution_digest=([0-9a-f]{64}):"
    r"accepted_revision=([0-9a-f]{40}):claim_revision=([0-9a-f]{40}) -->$"
)

EXECUTABLE_OPERATIONS: Final[frozenset[str]] = frozenset(
    {"github.ci.inspect", "workspace.recipe.dispatch"}
)
KNOWN_UNSUPPORTED_OPERATIONS: Final[frozenset[str]] = frozenset(
    {
        "governance.ledger",
        "governance.audit-task-integration",
    }
)


class ActionsHandlerError(Exception):
    """Sanitized failure that never leaks raw payloads, credentials, or traces."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable

    def __repr__(self) -> str:
        return f"ActionsHandlerError(code={self.code!r}, retryable={self.retryable!r})"

    def __str__(self) -> str:
        return self.code


@dataclass(frozen=True)
class TrustedReceiptPolicy:
    """Trusted GitHub App and bot identity required for valid result receipts."""

    app_id: int
    bot_user_id: int

    def __post_init__(self) -> None:
        if type(self.app_id) is not int or not (0 < self.app_id <= 2**53 - 1):
            raise ValueError("invalid_app_id")
        if type(self.bot_user_id) is not int or not (0 < self.bot_user_id <= 2**53 - 1):
            raise ValueError("invalid_bot_user_id")


@dataclass(frozen=True)
class ExecutionReceipt:
    """Bounded, machine-readable result receipt for a handled or reconciled request."""

    request_id: str
    durable_revision: str
    terminal_state: str
    terminal_code: str
    terminal_reference: Optional[str]
    envelope: dict[str, Any] = field(repr=False)
    replayed: bool = False
    reconciled: bool = False


@dataclass(frozen=True)
class ExecutionBundle:
    """Bounded, immutable execution bundle produced by Publisher and consumed by Control."""

    request_id: str
    request_digest: str
    operation: str
    repository_id: int
    repository_full_name: str
    issue_id: int
    issue_number: int
    execution_id: str
    canonical_record: str
    accepted_revision: str
    claim_revision: str
    parameters: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        validate_request_id(self.request_id)
        if type(self.repository_id) is not int or self.repository_id <= 0:
            raise ValueError("invalid_repository_id")
        if not isinstance(self.repository_full_name, str) or "/" not in self.repository_full_name:
            raise ValueError("invalid_repository_full_name")
        if type(self.issue_id) is not int or self.issue_id <= 0:
            raise ValueError("invalid_issue_id")
        if type(self.issue_number) is not int or self.issue_number <= 0:
            raise ValueError("invalid_issue_number")
        if not isinstance(self.execution_id, str) or not EXECUTION_ID_RE.fullmatch(self.execution_id):
            raise ValueError("invalid_execution_id")
        if not isinstance(self.accepted_revision, str) or not SHA40_RE.fullmatch(self.accepted_revision):
            raise ValueError("invalid_accepted_revision")
        if not isinstance(self.claim_revision, str) or not SHA40_RE.fullmatch(self.claim_revision):
            raise ValueError("invalid_claim_revision")
        if not isinstance(self.request_digest, str) or not SHA256_RE.fullmatch(self.request_digest):
            raise ValueError("invalid_request_digest")
        if not isinstance(self.canonical_record, str):
            raise ValueError("invalid_canonical_record")
        if not isinstance(self.parameters, dict):
            raise ValueError("invalid_parameters")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "actions.execution.bundle",
            "request_id": self.request_id,
            "request_digest": self.request_digest,
            "operation": self.operation,
            "repository_id": self.repository_id,
            "repository_full_name": self.repository_full_name,
            "issue_id": self.issue_id,
            "issue_number": self.issue_number,
            "execution_id": self.execution_id,
            "canonical_record": self.canonical_record,
            "accepted_revision": self.accepted_revision,
            "claim_revision": self.claim_revision,
            "parameters": self.parameters,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutionBundle:
        if not isinstance(data, dict):
            raise ActionsHandlerError("invalid_execution_bundle")
        expected_keys = {
            "schema_version", "kind", "request_id", "request_digest", "operation",
            "repository_id", "repository_full_name", "issue_id", "issue_number",
            "execution_id", "canonical_record", "accepted_revision", "claim_revision",
            "parameters",
        }
        if (
            set(data) != expected_keys
            or data.get("schema_version") != 1
            or data.get("kind") != "actions.execution.bundle"
        ):
            raise ActionsHandlerError("invalid_execution_bundle")
        try:
            return cls(
                request_id=data["request_id"],
                request_digest=data["request_digest"],
                operation=data["operation"],
                repository_id=data["repository_id"],
                repository_full_name=data["repository_full_name"],
                issue_id=data["issue_id"],
                issue_number=data["issue_number"],
                execution_id=data["execution_id"],
                canonical_record=data["canonical_record"],
                accepted_revision=data["accepted_revision"],
                claim_revision=data["claim_revision"],
                parameters=data["parameters"],
            )
        except (KeyError, ValueError, TypeError):
            raise ActionsHandlerError("invalid_execution_bundle") from None

    @classmethod
    def from_json(cls, s: str) -> ExecutionBundle:
        try:
            data = json.loads(s)
        except Exception:
            raise ActionsHandlerError("invalid_execution_bundle") from None
        return cls.from_dict(data)


def _validate_execution_bundle(bundle: ExecutionBundle) -> dict[str, Any]:
    """Bind the effect parameters and identities to the frozen publisher record."""
    try:
        record = parse_and_validate_record(bundle.canonical_record, bundle.request_id)
        fields = ("request_id", "request_digest", "operation", "repository_id",
                  "repository_full_name", "issue_id", "issue_number", "execution_id")
        if any(record.get(key) != getattr(bundle, key) for key in fields):
            raise ValueError("bundle binding")
        request = json.loads(record["canonical_request"])
        if record.get("state") != "executing" or request["parameters"] != bundle.parameters:
            raise ValueError("bundle parameters")
        return record
    except Exception:
        raise ActionsHandlerError("invalid_execution_bundle") from None


@dataclass(frozen=True)
class PrepareResult:
    """Result of Phase A: Publisher prepare."""

    disposition: ClaimDisposition
    request_id: str
    bundle: Optional[ExecutionBundle] = None
    receipt: Optional[ExecutionReceipt] = None


@dataclass(frozen=True)
class ControlExecutionResult:
    """Result of Phase B: Control execute."""

    request_id: str
    execution_id: str
    terminal_state: Optional[str] = None
    terminal_code: Optional[str] = None
    terminal_reference: Optional[str] = None
    envelope: Optional[dict[str, Any]] = None
    ambiguous: bool = False
    ambiguous_code: Optional[str] = None
    replayed: bool = False


@dataclass(frozen=True)
class DurablePrepareCheckpoint:
    """Authenticated Publisher handoff recovered from an Issue comment."""

    disposition: ClaimDisposition
    bundle: ExecutionBundle
    comment_id: int


def _format_receipt_comment(envelope: dict[str, Any]) -> str:
    envelope_json = json.dumps(envelope, indent=2, sort_keys=True)
    if len(envelope_json.encode("utf-8")) > MAX_RESULT_ENVELOPE_BYTES:
        raise ActionsHandlerError("result_envelope_too_large")

    marker = (
        f"<!-- zach-actions:receipt:v1:request_id={envelope['request_id']}:"
        f"digest={envelope['request_digest']}:op={envelope['operation']}:"
        f"accepted_revision={envelope['accepted_revision']}:"
        f"claim_revision={envelope['claim_revision']} -->"
    )
    comment_body = f"{marker}\n```json\n{envelope_json}\n```\n"
    if len(comment_body.encode("utf-8")) > MAX_COMMENT_BODY_BYTES:
        raise ActionsHandlerError("comment_body_too_large")
    return comment_body


def _parse_receipt_comment(
    body: str,
    expected_request_id: str,
    expected_digest: str,
    expected_operation: str,
    expected_accepted_revision: Optional[str] = None,
    expected_claim_revision: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Strictly parse a machine receipt, enforcing exact canonical format and bindings."""
    if not isinstance(body, str):
        return None

    if "<!-- zach-actions:receipt:v1:" not in body:
        return None

    # Must have exactly one marker and one fenced json block
    if body.count("<!-- zach-actions:receipt:v1:") != 1:
        raise ActionsHandlerError("receipt_canonical_body_mismatch")
    if body.count("```json\n") != 1 or body.count("\n```\n") != 1:
        raise ActionsHandlerError("receipt_canonical_body_mismatch")

    lines = body.split("\n")
    if not lines:
        raise ActionsHandlerError("receipt_canonical_body_mismatch")

    # First line MUST be the exact marker
    first_line = lines[0]
    marker_match = RECEIPT_MARKER_RE.fullmatch(first_line)
    if not marker_match:
        raise ActionsHandlerError("receipt_canonical_body_mismatch")

    req_id, digest, op, acc_rev, claim_rev = marker_match.groups()
    if req_id != expected_request_id:
        return None

    if digest != expected_digest or op != expected_operation:
        raise ActionsHandlerError("receipt_binding_mismatch")

    if expected_accepted_revision is not None and acc_rev != expected_accepted_revision:
        raise ActionsHandlerError("receipt_revision_mismatch")
    if expected_claim_revision is not None and claim_rev != expected_claim_revision:
        raise ActionsHandlerError("receipt_revision_mismatch")

    # Must start with marker followed immediately by ```json
    if len(lines) < 4 or lines[1] != "```json" or lines[-2] != "```" or lines[-1] != "":
        raise ActionsHandlerError("receipt_canonical_body_mismatch")

    json_str = "\n".join(lines[2:-2])
    try:
        envelope = json.loads(json_str)
    except Exception:
        raise ActionsHandlerError("receipt_json_invalid") from None

    if not isinstance(envelope, dict):
        raise ActionsHandlerError("receipt_envelope_invalid")
    if envelope.get("schema_version") != 1:
        raise ActionsHandlerError("receipt_version_unsupported")
    if envelope.get("kind") != "actions.request.receipt":
        raise ActionsHandlerError("receipt_kind_invalid")
    if envelope.get("request_id") != expected_request_id:
        raise ActionsHandlerError("receipt_request_id_mismatch")
    if envelope.get("request_digest") != expected_digest:
        raise ActionsHandlerError("receipt_digest_mismatch")
    if envelope.get("operation") != expected_operation:
        raise ActionsHandlerError("receipt_operation_mismatch")
    if envelope.get("accepted_revision") != acc_rev:
        raise ActionsHandlerError("receipt_revision_mismatch")
    if envelope.get("claim_revision") != claim_rev:
        raise ActionsHandlerError("receipt_revision_mismatch")
    if expected_accepted_revision is not None and envelope.get("accepted_revision") != expected_accepted_revision:
        raise ActionsHandlerError("receipt_revision_mismatch")
    if expected_claim_revision is not None and envelope.get("claim_revision") != expected_claim_revision:
        raise ActionsHandlerError("receipt_revision_mismatch")

    state = envelope.get("terminal_state")
    if state not in ("succeeded", "rejected"):
        raise ActionsHandlerError("receipt_state_invalid")

    code = envelope.get("terminal_code")
    if not isinstance(code, str) or not (1 <= len(code) <= MAX_TERMINAL_CODE_BYTES):
        raise ActionsHandlerError("receipt_code_invalid")

    if not isinstance(envelope.get("result"), dict):
        raise ActionsHandlerError("receipt_result_invalid")

    # Exact canonical body check: regenerate from envelope and verify byte equality
    canonical = _format_receipt_comment(envelope)
    if body != canonical:
        raise ActionsHandlerError("receipt_canonical_body_mismatch")

    return envelope


def _validate_comment_identity(
    comment: Any,
    trusted_receipt_policy: TrustedReceiptPolicy,
    expected_repo: str,
    expected_issue_number: int,
    expected_body: Optional[str] = None,
) -> int:
    """Validate all mandatory identity and authorship fields of a GitHub comment."""
    if not isinstance(comment, dict):
        raise ActionsHandlerError("comment_identity_mismatch")

    comment_id = comment.get("id")
    if type(comment_id) is not int or comment_id <= 0:
        raise ActionsHandlerError("comment_identity_mismatch")

    # 1. Mandatory authorship: bot user
    user = comment.get("user")
    if not isinstance(user, dict):
        raise ActionsHandlerError("comment_authorship_missing")
    if user.get("id") != trusted_receipt_policy.bot_user_id:
        raise ActionsHandlerError("comment_bot_id_mismatch")
    if user.get("type") != "Bot":
        raise ActionsHandlerError("comment_user_not_bot")

    # 2. Mandatory authorship: GitHub App
    app = comment.get("performed_via_github_app")
    if not isinstance(app, dict):
        raise ActionsHandlerError("comment_app_metadata_missing")
    if app.get("id") != trusted_receipt_policy.app_id:
        raise ActionsHandlerError("comment_app_id_mismatch")

    # 3. Mandatory canonical URLs
    issue_url = comment.get("issue_url")
    expected_issue_url = f"https://api.github.com/repos/{expected_repo}/issues/{expected_issue_number}"
    if issue_url != expected_issue_url:
        raise ActionsHandlerError("comment_issue_url_mismatch")

    html_url = comment.get("html_url")
    expected_html_url = (
        f"https://github.com/{expected_repo}/issues/{expected_issue_number}#issuecomment-{comment_id}"
    )
    if html_url != expected_html_url:
        raise ActionsHandlerError("comment_html_url_mismatch")

    # 4. Mandatory exact canonical body if provided
    if expected_body is not None:
        if comment.get("body") != expected_body:
            raise ActionsHandlerError("comment_body_mismatch")

    return comment_id


def _is_trusted_comment_author(
    comment: Any,
    trusted_receipt_policy: TrustedReceiptPolicy,
    expected_repo: str,
    expected_issue_number: int,
) -> bool:
    """Check whether a comment satisfies the trusted App/bot authorship contract."""
    try:
        _validate_comment_identity(
            comment=comment,
            trusted_receipt_policy=trusted_receipt_policy,
            expected_repo=expected_repo,
            expected_issue_number=expected_issue_number,
        )
        return True
    except ActionsHandlerError:
        return False


def _execution_digest(execution_id: str) -> str:
    if not isinstance(execution_id, str) or not EXECUTION_ID_RE.fullmatch(execution_id):
        raise ActionsHandlerError("invalid_execution_id")
    return hashlib.sha256(execution_id.encode("utf-8")).hexdigest()


def _format_publisher_comment(kind: str, envelope: dict[str, Any]) -> str:
    if kind == "intent":
        marker = (
            f"<!-- zach-actions:publisher-intent:v1:request_id={envelope['request_id']}:"
            f"digest={envelope['request_digest']}:"
            f"execution_digest={_execution_digest(envelope['execution_id'])} -->"
        )
    elif kind == "prepare":
        bundle = envelope["bundle"]
        marker = (
            f"<!-- zach-actions:publisher-prepare:v1:request_id={bundle['request_id']}:"
            f"digest={bundle['request_digest']}:"
            f"execution_digest={_execution_digest(bundle['execution_id'])}:"
            f"accepted_revision={bundle['accepted_revision']}:"
            f"claim_revision={bundle['claim_revision']} -->"
        )
    else:
        raise ActionsHandlerError("invalid_publisher_checkpoint")
    encoded = json.dumps(envelope, indent=2, sort_keys=True, allow_nan=False)
    body = f"{marker}\n```json\n{encoded}\n```\n"
    if len(body.encode("utf-8")) > MAX_PUBLISHER_CHECKPOINT_BYTES:
        raise ActionsHandlerError("publisher_checkpoint_too_large")
    return body


def _parse_publisher_comment(
    body: Any,
    kind: str,
    execution_id: str,
    request_id: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    if not isinstance(body, str):
        return None
    prefix = f"<!-- zach-actions:publisher-{kind}:v1:"
    if prefix not in body:
        return None
    if body.count(prefix) != 1 or body.count("```json\n") != 1 or body.count("\n```\n") != 1:
        raise ActionsHandlerError("publisher_checkpoint_canonical_mismatch")
    lines = body.split("\n")
    if len(lines) < 4 or lines[1] != "```json" or lines[-2] != "```" or lines[-1] != "":
        raise ActionsHandlerError("publisher_checkpoint_canonical_mismatch")
    marker_re = PUBLISHER_INTENT_MARKER_RE if kind == "intent" else PUBLISHER_PREPARE_MARKER_RE
    match = marker_re.fullmatch(lines[0])
    if match is None:
        raise ActionsHandlerError("publisher_checkpoint_canonical_mismatch")
    marker_request_id = match.group(1)
    if request_id is not None and marker_request_id != request_id:
        return None
    if match.group(3) != _execution_digest(execution_id):
        return None
    try:
        envelope = json.loads("\n".join(lines[2:-2]))
    except (json.JSONDecodeError, RecursionError):
        raise ActionsHandlerError("publisher_checkpoint_json_invalid") from None
    if type(envelope) is not dict:
        raise ActionsHandlerError("publisher_checkpoint_invalid")

    if kind == "intent":
        expected_keys = {
            "schema_version", "kind", "request_id", "request_digest", "operation",
            "repository_id", "repository_full_name", "issue_id", "issue_number",
            "execution_id", "accepted_revision", "policy_revision",
        }
        if set(envelope) != expected_keys or envelope.get("kind") != "actions.publisher.intent":
            raise ActionsHandlerError("publisher_checkpoint_invalid")
        if (
            envelope.get("schema_version") != 1
            or envelope.get("request_id") != marker_request_id
            or envelope.get("request_digest") != match.group(2)
            or envelope.get("execution_id") != execution_id
            or not isinstance(envelope.get("operation"), str)
            or not SHA40_RE.fullmatch(envelope.get("accepted_revision", ""))
            or not SHA40_RE.fullmatch(envelope.get("policy_revision", ""))
        ):
            raise ActionsHandlerError("publisher_checkpoint_binding_mismatch")
    else:
        expected_keys = {"schema_version", "kind", "disposition", "bundle"}
        if set(envelope) != expected_keys or envelope.get("kind") != "actions.publisher.prepare":
            raise ActionsHandlerError("publisher_checkpoint_invalid")
        if envelope.get("schema_version") != 1 or envelope.get("disposition") not in {
            ClaimDisposition.GRANTED.value,
            ClaimDisposition.RECONCILIATION_REQUIRED.value,
        }:
            raise ActionsHandlerError("publisher_checkpoint_invalid")
        bundle = ExecutionBundle.from_dict(envelope.get("bundle"))
        try:
            _validate_execution_bundle(bundle)
        except ActionsHandlerError:
            raise ActionsHandlerError("publisher_checkpoint_binding_mismatch") from None
        if (
            bundle.request_id != marker_request_id
            or bundle.request_digest != match.group(2)
            or bundle.execution_id != execution_id
            or bundle.accepted_revision != match.group(4)
            or bundle.claim_revision != match.group(5)
        ):
            raise ActionsHandlerError("publisher_checkpoint_binding_mismatch")

    if body != _format_publisher_comment(kind, envelope):
        raise ActionsHandlerError("publisher_checkpoint_canonical_mismatch")
    return envelope


def _scan_issue_comments(
    api_transport: Callable[..., Any],
    repo_full_name: str,
    issue_number: int,
) -> tuple[tuple[Any, ...], list[dict[str, Any]]]:
    comments: list[dict[str, Any]] = []
    snapshot: list[tuple[Any, ...]] = []
    seen: set[int] = set()
    for page in range(1, MAX_RECONCILIATION_PAGES + 1):
        path = f"/repos/{repo_full_name}/issues/{issue_number}/comments?per_page={RECONCILIATION_PER_PAGE}&page={page}"
        try:
            items = api_transport("GET", path, body=None)
        except Exception:
            raise ActionsHandlerError("reconciliation_api_failed") from None
        if type(items) is not list or len(items) > RECONCILIATION_PER_PAGE:
            raise ActionsHandlerError("reconciliation_malformed_response")
        for item in items:
            if type(item) is not dict or type(item.get("id")) is not int or item["id"] <= 0:
                raise ActionsHandlerError("reconciliation_malformed_response")
            if item["id"] in seen:
                raise ActionsHandlerError("reconciliation_duplicate_comment_ids")
            seen.add(item["id"])
            user = item.get("user")
            app = item.get("performed_via_github_app")
            snapshot.append((
                item["id"], item.get("body"),
                user.get("id") if type(user) is dict else None,
                user.get("type") if type(user) is dict else None,
                app.get("id") if type(app) is dict else None,
                item.get("issue_url"), item.get("html_url"),
            ))
            comments.append(item)
        if len(items) < RECONCILIATION_PER_PAGE:
            return tuple(snapshot), comments
    raise ActionsHandlerError("reconciliation_pagination_exceeded")


def load_durable_prepare_checkpoint(
    api_transport: Callable[..., Any],
    trusted_publisher_policy: TrustedReceiptPolicy,
    repository_full_name: str,
    issue_number: int,
    execution_id: str,
    request_id: Optional[str] = None,
) -> DurablePrepareCheckpoint:
    """Load exactly one stable, authenticated Publisher prepare checkpoint."""
    _execution_digest(execution_id)
    if request_id is not None:
        validate_request_id(request_id)
    first, comments = _scan_issue_comments(api_transport, repository_full_name, issue_number)
    second, _ = _scan_issue_comments(api_transport, repository_full_name, issue_number)
    if first != second:
        raise ActionsHandlerError("reconciliation_observation_unstable")
    matches: list[tuple[dict[str, Any], int]] = []
    for comment in comments:
        if not _is_trusted_comment_author(
            comment, trusted_publisher_policy, repository_full_name, issue_number
        ):
            continue
        envelope = _parse_publisher_comment(
            comment.get("body"), "prepare", execution_id, request_id
        )
        if envelope is not None:
            matches.append((envelope, comment["id"]))
    if not matches:
        raise ActionsHandlerError("publisher_prepare_checkpoint_not_found")
    if len(matches) > 1:
        raise ActionsHandlerError("duplicate_publisher_prepare_checkpoints")
    envelope, comment_id = matches[0]
    bundle = ExecutionBundle.from_dict(envelope["bundle"])
    if (
        bundle.repository_full_name != repository_full_name
        or bundle.issue_number != issue_number
    ):
        raise ActionsHandlerError("publisher_checkpoint_binding_mismatch")
    return DurablePrepareCheckpoint(
        disposition=ClaimDisposition(envelope["disposition"]),
        bundle=bundle,
        comment_id=comment_id,
    )


class PublisherPhase:
    """Phase A (prepare) and Phase C (finalize) executor with Publisher authority.

    Operates with Governance Contents / Journal authority and, when configured,
    publishes authenticated durable handoff checkpoints on the control Issue.
    It has no Control App private key and does not run candidate effects.
    """

    def __init__(
        self,
        coordinator: ActionsJournalCoordinator,
        trusted_issue_policy: TrustedIssuePolicy,
        trusted_receipt_policy: TrustedReceiptPolicy,
        read_api_transport: Optional[Callable[..., Any]] = None,
        trusted_publisher_policy: Optional[TrustedReceiptPolicy] = None,
    ) -> None:
        if not isinstance(coordinator, ActionsJournalCoordinator):
            raise TypeError("coordinator must be an ActionsJournalCoordinator instance")
        if not isinstance(trusted_issue_policy, TrustedIssuePolicy):
            raise TypeError("trusted_issue_policy must be a TrustedIssuePolicy instance")
        if not isinstance(trusted_receipt_policy, TrustedReceiptPolicy):
            raise TypeError("trusted_receipt_policy must be a TrustedReceiptPolicy instance")
        if read_api_transport is not None and not callable(read_api_transport):
            raise TypeError("read_api_transport must be callable")
        if trusted_publisher_policy is not None and not isinstance(
            trusted_publisher_policy, TrustedReceiptPolicy
        ):
            raise TypeError("trusted_publisher_policy must be a TrustedReceiptPolicy instance or None")

        self._coordinator = coordinator
        self._trusted_issue_policy = trusted_issue_policy
        self._trusted_receipt_policy = trusted_receipt_policy
        self._trusted_publisher_policy = trusted_publisher_policy
        self._read_api_transport = read_api_transport or coordinator._api_transport

    def validate_comment_identity(
        self,
        comment: Any,
        expected_repo: str,
        expected_issue_number: int,
        expected_body: Optional[str] = None,
    ) -> int:
        return _validate_comment_identity(
            comment=comment,
            trusted_receipt_policy=self._trusted_receipt_policy,
            expected_repo=expected_repo,
            expected_issue_number=expected_issue_number,
            expected_body=expected_body,
        )

    def is_trusted_comment_author(
        self,
        comment: Any,
        expected_repo: str,
        expected_issue_number: int,
    ) -> bool:
        return _is_trusted_comment_author(
            comment=comment,
            trusted_receipt_policy=self._trusted_receipt_policy,
            expected_repo=expected_repo,
            expected_issue_number=expected_issue_number,
        )

    def prepare(
        self,
        event_bytes: bytes,
        execution_id: str,
        accepted_at: str,
        policy_revision: str,
    ) -> PrepareResult:
        """Phase A: validate/authenticate Issue, durable accept, durable claim, produce execution bundle."""
        if type(event_bytes) is not bytes:
            raise ActionsHandlerError("invalid_event_bytes")
        if len(event_bytes) > MAX_EVENT_BYTES:
            raise ActionsHandlerError("event_payload_too_large")
        if not isinstance(execution_id, str) or not EXECUTION_ID_RE.fullmatch(execution_id):
            raise ActionsHandlerError("invalid_execution_id")

        # 1. Durable journal acceptance
        try:
            acceptance = self._coordinator.accept(
                event_bytes,
                self._trusted_issue_policy,
                accepted_at,
                policy_revision,
            )
        except (CoordinatorError, AmbiguousPublication, ApiError) as e:
            code = getattr(e, "code", "acceptance_failed")
            raise ActionsHandlerError(code) from None

        if self._trusted_publisher_policy is not None:
            return self._prepare_durable(acceptance, execution_id)

        # 2. Durable execution claim
        try:
            claim = self._coordinator.claim(acceptance.request_id, execution_id)
        except (CoordinatorError, AmbiguousPublication, ApiError) as e:
            code = getattr(e, "code", "claim_failed")
            raise ActionsHandlerError(code) from None

        if claim.disposition == ClaimDisposition.TERMINAL_REPLAY:
            stored = parse_and_validate_record(claim.record_json, acceptance.request_id)
            receipt = ExecutionReceipt(
                request_id=acceptance.request_id,
                durable_revision=claim.durable_revision,
                terminal_state=stored["state"],
                terminal_code=stored.get("terminal_code") or "",
                terminal_reference=stored.get("terminal_reference"),
                envelope={},
                replayed=True,
            )
            return PrepareResult(
                disposition=ClaimDisposition.TERMINAL_REPLAY,
                request_id=acceptance.request_id,
                receipt=receipt,
            )

        if claim.disposition == ClaimDisposition.RECONCILIATION_REQUIRED:
            return PrepareResult(
                disposition=ClaimDisposition.RECONCILIATION_REQUIRED,
                request_id=acceptance.request_id,
            )

        if claim.disposition != ClaimDisposition.GRANTED:
            raise ActionsHandlerError("unexpected_claim_disposition")

        # 3. Produce bounded, immutable execution bundle
        record = parse_and_validate_record(claim.record_json, acceptance.request_id)
        canonical_req = json.loads(record["canonical_request"])
        parameters = canonical_req.get("parameters", {})

        bundle = ExecutionBundle(
            request_id=record["request_id"],
            request_digest=record["request_digest"],
            operation=record["operation"],
            repository_id=record["repository_id"],
            repository_full_name=record["repository_full_name"],
            issue_id=record["issue_id"],
            issue_number=record["issue_number"],
            execution_id=execution_id,
            canonical_record=claim.record_json,
            accepted_revision=acceptance.durable_revision,
            claim_revision=claim.durable_revision,
            parameters=parameters,
        )

        return PrepareResult(
            disposition=ClaimDisposition.GRANTED,
            request_id=acceptance.request_id,
            bundle=bundle,
        )

    def _prepare_durable(self, acceptance: Any, execution_id: str) -> PrepareResult:
        """Persist intent before claim and a complete Issue handoff after claim."""
        accepted_or_later = parse_and_validate_record(
            acceptance.record_json, acceptance.request_id
        )
        if accepted_or_later["state"] in ("succeeded", "rejected"):
            return self._terminal_replay(
                acceptance.request_id, acceptance.durable_revision, accepted_or_later
            )

        if accepted_or_later["state"] == "accepted":
            intent = self._intent_envelope(
                accepted_or_later, execution_id, acceptance.durable_revision
            )
            self._ensure_publisher_comment("intent", intent)
        else:
            intent = self._load_publisher_intent(
                accepted_or_later, execution_id
            )

        try:
            claim = self._coordinator.claim(acceptance.request_id, execution_id)
        except (CoordinatorError, AmbiguousPublication, ApiError) as error:
            raise ActionsHandlerError(getattr(error, "code", "claim_failed")) from None

        if claim.disposition == ClaimDisposition.TERMINAL_REPLAY:
            stored = parse_and_validate_record(claim.record_json, acceptance.request_id)
            return self._terminal_replay(
                acceptance.request_id, claim.durable_revision, stored
            )

        record = parse_and_validate_record(claim.record_json, acceptance.request_id)
        if claim.disposition == ClaimDisposition.RECONCILIATION_REQUIRED:
            if record.get("state") not in {"executing", "ambiguous"} or record.get(
                "execution_id"
            ) != execution_id:
                raise ActionsHandlerError("publisher_prepare_resume_state_invalid")
            try:
                checkpoint = load_durable_prepare_checkpoint(
                    self._read_api_transport,
                    self._trusted_publisher_policy,
                    record["repository_full_name"],
                    record["issue_number"],
                    execution_id,
                    acceptance.request_id,
                )
            except ActionsHandlerError as error:
                if error.code != "publisher_prepare_checkpoint_not_found":
                    raise
                if record["state"] == "ambiguous":
                    raise ActionsHandlerError(
                        "publisher_prepare_checkpoint_missing_after_effect"
                    ) from None
            else:
                self._validate_recovered_bundle(checkpoint.bundle, record)
                return PrepareResult(
                    disposition=ClaimDisposition.RECONCILIATION_REQUIRED,
                    request_id=acceptance.request_id,
                    bundle=checkpoint.bundle,
                )
            disposition = ClaimDisposition.RECONCILIATION_REQUIRED
        elif claim.disposition == ClaimDisposition.GRANTED:
            disposition = ClaimDisposition.GRANTED
        else:
            raise ActionsHandlerError("unexpected_claim_disposition")

        bundle = self._bundle_from_record(
            record,
            claim.record_json,
            execution_id,
            intent["accepted_revision"],
            claim.durable_revision,
        )
        self._validate_intent_snapshot(intent, record)
        envelope = {
            "schema_version": 1,
            "kind": "actions.publisher.prepare",
            "disposition": disposition.value,
            "bundle": bundle.to_dict(),
        }
        self._ensure_publisher_comment("prepare", envelope)
        return PrepareResult(
            disposition=disposition,
            request_id=acceptance.request_id,
            bundle=bundle,
        )

    @staticmethod
    def _terminal_replay(
        request_id: str, durable_revision: str, record: dict[str, Any]
    ) -> PrepareResult:
        return PrepareResult(
            disposition=ClaimDisposition.TERMINAL_REPLAY,
            request_id=request_id,
            receipt=ExecutionReceipt(
                request_id=request_id,
                durable_revision=durable_revision,
                terminal_state=record["state"],
                terminal_code=record.get("terminal_code") or "",
                terminal_reference=record.get("terminal_reference"),
                envelope={},
                replayed=True,
            ),
        )

    @staticmethod
    def _intent_envelope(
        record: dict[str, Any], execution_id: str, accepted_revision: str
    ) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "actions.publisher.intent",
            "request_id": record["request_id"],
            "request_digest": record["request_digest"],
            "operation": record["operation"],
            "repository_id": record["repository_id"],
            "repository_full_name": record["repository_full_name"],
            "issue_id": record["issue_id"],
            "issue_number": record["issue_number"],
            "execution_id": execution_id,
            "accepted_revision": accepted_revision,
            "policy_revision": record["policy_revision"],
        }

    @staticmethod
    def _bundle_from_record(
        record: dict[str, Any],
        record_json: str,
        execution_id: str,
        accepted_revision: str,
        claim_revision: str,
    ) -> ExecutionBundle:
        request = json.loads(record["canonical_request"])
        return ExecutionBundle(
            request_id=record["request_id"],
            request_digest=record["request_digest"],
            operation=record["operation"],
            repository_id=record["repository_id"],
            repository_full_name=record["repository_full_name"],
            issue_id=record["issue_id"],
            issue_number=record["issue_number"],
            execution_id=execution_id,
            canonical_record=record_json,
            accepted_revision=accepted_revision,
            claim_revision=claim_revision,
            parameters=request["parameters"],
        )

    def _load_publisher_intent(
        self, record: dict[str, Any], execution_id: str
    ) -> dict[str, Any]:
        first, comments = _scan_issue_comments(
            self._read_api_transport,
            record["repository_full_name"],
            record["issue_number"],
        )
        second, _ = _scan_issue_comments(
            self._read_api_transport,
            record["repository_full_name"],
            record["issue_number"],
        )
        if first != second:
            raise ActionsHandlerError("reconciliation_observation_unstable")
        matches: list[dict[str, Any]] = []
        for comment in comments:
            if not _is_trusted_comment_author(
                comment,
                self._trusted_publisher_policy,
                record["repository_full_name"],
                record["issue_number"],
            ):
                continue
            envelope = _parse_publisher_comment(
                comment.get("body"), "intent", execution_id, record["request_id"]
            )
            if envelope is not None:
                matches.append(envelope)
        if not matches:
            raise ActionsHandlerError("publisher_intent_missing_after_claim")
        if len(matches) > 1:
            raise ActionsHandlerError("duplicate_publisher_intents")
        self._validate_intent_snapshot(matches[0], record)
        return matches[0]

    def _validate_intent_snapshot(
        self, intent: dict[str, Any], current: dict[str, Any]
    ) -> None:
        immutable = (
            "request_id", "request_digest", "operation", "repository_id",
            "repository_full_name", "issue_id", "issue_number", "policy_revision",
        )
        if any(intent.get(key) != current.get(key) for key in immutable):
            raise ActionsHandlerError("publisher_intent_binding_mismatch")
        journal = ActionsGitJournal(
            request=self._read_api_transport,
            validate_transition=lambda _old, _new: False,
        )
        try:
            accepted = journal.load_at(current["request_id"], intent["accepted_revision"])
            if accepted.record_json is None:
                raise ValueError("missing accepted snapshot")
            accepted_record = parse_and_validate_record(
                accepted.record_json, current["request_id"]
            )
            expected = dict(
                current,
                state="accepted",
                execution_id=None,
                terminal_code=None,
                terminal_reference=None,
            )
            if accepted_record != expected:
                raise ValueError("accepted snapshot mismatch")
        except Exception:
            raise ActionsHandlerError("publisher_intent_revision_mismatch") from None

    @staticmethod
    def _validate_recovered_bundle(
        bundle: ExecutionBundle, current: dict[str, Any]
    ) -> None:
        frozen = _validate_execution_bundle(bundle)
        mutable = {"state", "terminal_code", "terminal_reference"}
        if (
            bundle.execution_id != current.get("execution_id")
            or {key: value for key, value in frozen.items() if key not in mutable}
            != {key: value for key, value in current.items() if key not in mutable}
        ):
            raise ActionsHandlerError("publisher_prepare_checkpoint_journal_mismatch")

    def _ensure_publisher_comment(
        self, kind: str, envelope: dict[str, Any]
    ) -> int:
        body = _format_publisher_comment(kind, envelope)
        if kind == "intent":
            request_id = envelope["request_id"]
            execution_id = envelope["execution_id"]
            repository = envelope["repository_full_name"]
            issue_number = envelope["issue_number"]
        else:
            bundle = ExecutionBundle.from_dict(envelope["bundle"])
            request_id = bundle.request_id
            execution_id = bundle.execution_id
            repository = bundle.repository_full_name
            issue_number = bundle.issue_number

        existing = self._matching_publisher_comments(
            kind, repository, issue_number, execution_id, request_id
        )
        if len(existing) > 1:
            raise ActionsHandlerError(f"duplicate_publisher_{kind}s")
        if len(existing) == 1:
            if existing[0].get("body") != body:
                raise ActionsHandlerError("publisher_checkpoint_conflict")
            return existing[0]["id"]

        post_path = f"/repos/{repository}/issues/{issue_number}/comments"
        try:
            posted = self._read_api_transport("POST", post_path, body={"body": body})
            comment_id = _validate_comment_identity(
                posted, self._trusted_publisher_policy, repository, issue_number, body
            )
            readback = self._read_api_transport(
                "GET", f"/repos/{repository}/issues/comments/{comment_id}", body=None
            )
            readback_id = _validate_comment_identity(
                readback, self._trusted_publisher_policy, repository, issue_number, body
            )
            if readback_id != comment_id:
                raise ActionsHandlerError("publisher_comment_readback_identity_mismatch")
            return comment_id
        except Exception:
            recovered = self._matching_publisher_comments(
                kind, repository, issue_number, execution_id, request_id
            )
            if len(recovered) == 1 and recovered[0].get("body") == body:
                return recovered[0]["id"]
            if len(recovered) > 1:
                raise ActionsHandlerError(f"duplicate_publisher_{kind}s") from None
            raise ActionsHandlerError("publisher_comment_publication_ambiguous") from None

    def _matching_publisher_comments(
        self,
        kind: str,
        repository: str,
        issue_number: int,
        execution_id: str,
        request_id: str,
    ) -> list[dict[str, Any]]:
        first, comments = _scan_issue_comments(
            self._read_api_transport, repository, issue_number
        )
        second, _ = _scan_issue_comments(
            self._read_api_transport, repository, issue_number
        )
        if first != second:
            raise ActionsHandlerError("reconciliation_observation_unstable")
        matches: list[dict[str, Any]] = []
        for comment in comments:
            if not _is_trusted_comment_author(
                comment, self._trusted_publisher_policy, repository, issue_number
            ):
                continue
            envelope = _parse_publisher_comment(
                comment.get("body"), kind, execution_id, request_id
            )
            if envelope is not None:
                matches.append(comment)
        return matches

    def finalize(
        self,
        bundle: ExecutionBundle,
        control_result: Optional[ControlExecutionResult] = None,
    ) -> ExecutionReceipt:
        """Phase C: load journal, independently observe Control receipt, verify exact bindings, terminalize."""
        if not isinstance(bundle, ExecutionBundle):
            raise TypeError("bundle must be an ExecutionBundle instance")

        # Bind the original bundle to the independently loaded durable request.
        frozen = _validate_execution_bundle(bundle)
        head_sha, record = self._coordinator.load_record(bundle.request_id)
        mutable_fields = {"state", "terminal_code", "terminal_reference"}
        if ({k: v for k, v in frozen.items() if k not in mutable_fields}
                != {k: v for k, v in record.items() if k not in mutable_fields}):
            raise ActionsHandlerError("bundle_journal_mismatch")

        # Caller-supplied SHA strings are not proof: independently read both
        # immutable journal snapshots and bind them to the accepted request/claim.
        journal = ActionsGitJournal(request=self._read_api_transport,
                                    validate_transition=lambda _old, _new: False)
        try:
            for base, head in ((bundle.accepted_revision, bundle.claim_revision),
                               (bundle.claim_revision, head_sha)):
                if base == head:
                    continue
                comparison = self._read_api_transport(
                    "GET", f"/repos/{journal.REPOSITORY}/compare/{base}...{head}", body=None)
                if (comparison.get("status") != "ahead"
                        or comparison.get("base_commit", {}).get("sha") != base
                        or comparison.get("merge_base_commit", {}).get("sha") != base):
                    raise ValueError("not journal ancestry")
            accepted = journal.load_at(bundle.request_id, bundle.accepted_revision)
            claimed = journal.load_at(bundle.request_id, bundle.claim_revision)
            if claimed.record_json != bundle.canonical_record or accepted.record_json is None:
                raise ValueError("snapshot mismatch")
            accepted_record = parse_and_validate_record(accepted.record_json, bundle.request_id)
            expected_accepted = dict(frozen, state="accepted", execution_id=None,
                                     terminal_code=None, terminal_reference=None)
            if accepted_record != expected_accepted:
                raise ValueError("acceptance mismatch")
        except Exception:
            raise ActionsHandlerError("bundle_revision_mismatch") from None

        if record["state"] in ("succeeded", "rejected"):
            return ExecutionReceipt(
                request_id=bundle.request_id,
                durable_revision=head_sha,
                terminal_state=record["state"],
                terminal_code=record.get("terminal_code") or "",
                terminal_reference=record.get("terminal_reference"),
                envelope={},
                replayed=True,
            )

        if record["state"] not in ("executing", "ambiguous"):
            raise ActionsHandlerError("reconciliation_invalid_state")

        owner_exec_id = record.get("execution_id")
        if bundle.execution_id != owner_exec_id:
            raise ActionsHandlerError("execution_owner_mismatch")

        # Handle ambiguous outcome reported by Control
        if control_result is not None and control_result.ambiguous:
            if record["state"] == "executing":
                self._safe_mark_ambiguous(bundle.request_id, bundle.execution_id)
            code = control_result.ambiguous_code or "comment_publication_ambiguous"
            raise ActionsHandlerError(code)

        # 2. Independently observe the receipt published by Control
        repo_full_name = bundle.repository_full_name
        issue_number = bundle.issue_number

        snapshot_1, comments_1 = self._scan_comments(repo_full_name, issue_number)
        snapshot_2, comments_2 = self._scan_comments(repo_full_name, issue_number)

        if snapshot_1 != snapshot_2:
            raise ActionsHandlerError("reconciliation_observation_unstable")

        matching_receipts: list[tuple[dict[str, Any], str]] = []
        for item in comments_1:
            body = item.get("body")
            if not isinstance(body, str):
                continue

            if f"request_id={bundle.request_id}" in body and "zach-actions:receipt:v1:" in body:
                # 3. Verify trusted Control App ID, bot user ID and type
                if not self.is_trusted_comment_author(item, repo_full_name, issue_number):
                    continue

                # Verify canonical receipt body, request ID, digest, operation,
                # and EXACT accepted_revision and claim_revision
                envelope = _parse_receipt_comment(
                    body=body,
                    expected_request_id=bundle.request_id,
                    expected_digest=bundle.request_digest,
                    expected_operation=bundle.operation,
                    expected_accepted_revision=bundle.accepted_revision,
                    expected_claim_revision=bundle.claim_revision,
                )
                if envelope is not None:
                    comment_id = item["id"]
                    ref = f"https://github.com/{repo_full_name}/issues/{issue_number}#issuecomment-{comment_id}"
                    matching_receipts.append((envelope, ref))

        if len(matching_receipts) > 1:
            raise ActionsHandlerError("duplicate_receipts_found")

        if len(matching_receipts) == 0:
            if record["state"] == "executing":
                self._safe_mark_ambiguous(bundle.request_id, bundle.execution_id)
            raise ActionsHandlerError("comment_publication_ambiguous")

        envelope, canonical_reference = matching_receipts[0]
        terminal_state = envelope["terminal_state"]
        terminal_code = envelope["terminal_code"]

        # 4. Only after verification, terminalize the journal
        if record["state"] == "executing":
            try:
                mutation = self._coordinator.complete(
                    request_id=bundle.request_id,
                    execution_id=bundle.execution_id,
                    state=terminal_state,
                    terminal_code=terminal_code,
                    terminal_reference=canonical_reference,
                )
            except Exception:
                raise ActionsHandlerError("journal_completion_failed") from None
        else:
            obs = TrustedReconciliationObservation(
                terminal_state=terminal_state,
                terminal_code=terminal_code,
                terminal_reference=canonical_reference,
            )
            try:
                mutation = self._coordinator.reconcile(bundle.request_id, bundle.execution_id, obs)
            except CoordinatorError as e:
                raise ActionsHandlerError(e.code) from None

        return ExecutionReceipt(
            request_id=bundle.request_id,
            durable_revision=mutation.durable_revision,
            terminal_state=terminal_state,
            terminal_code=terminal_code,
            terminal_reference=canonical_reference,
            envelope=envelope,
            replayed=False,
            reconciled=(record["state"] == "ambiguous"),
        )

    def reconcile_request(
        self,
        request_id: str,
        execution_id: Optional[str] = None,
        expected_accepted_revision: Optional[str] = None,
        expected_claim_revision: Optional[str] = None,
    ) -> ExecutionReceipt:
        """Independently observe issue comments to reconcile an ambiguous or executing request."""
        validate_request_id(request_id)
        head_sha, record = self._coordinator.load_record(request_id)

        if record["state"] in ("succeeded", "rejected"):
            return ExecutionReceipt(
                request_id=request_id,
                durable_revision=head_sha,
                terminal_state=record["state"],
                terminal_code=record.get("terminal_code") or "",
                terminal_reference=record.get("terminal_reference"),
                envelope={},
                replayed=True,
            )

        if record["state"] == "executing":
            owner_exec_id = record.get("execution_id")
            if execution_id is not None and execution_id != owner_exec_id:
                raise ActionsHandlerError("execution_owner_mismatch")
            return ExecutionReceipt(
                request_id=request_id,
                durable_revision=head_sha,
                terminal_state="executing",
                terminal_code="reconciliation_required",
                terminal_reference=None,
                envelope={},
                replayed=False,
                reconciled=False,
            )

        if record["state"] != "ambiguous":
            raise ActionsHandlerError("reconciliation_invalid_state")

        owner_exec_id = record.get("execution_id")
        if owner_exec_id is None:
            raise ActionsHandlerError("reconciliation_unclaimed_request")

        if execution_id is not None and execution_id != owner_exec_id:
            raise ActionsHandlerError("execution_owner_mismatch")

        repo_full_name = record["repository_full_name"]
        issue_number = record["issue_number"]
        expected_req_id = record["request_id"]
        expected_digest = record["request_digest"]
        expected_operation = record["operation"]

        snapshot_1, comments_1 = self._scan_comments(repo_full_name, issue_number)
        snapshot_2, comments_2 = self._scan_comments(repo_full_name, issue_number)

        if snapshot_1 != snapshot_2:
            raise ActionsHandlerError("reconciliation_observation_unstable")

        matching_receipts: list[tuple[dict[str, Any], str]] = []
        for item in comments_1:
            body = item.get("body")
            if not isinstance(body, str):
                continue

            if f"request_id={expected_req_id}" in body and "zach-actions:receipt:v1:" in body:
                if not self.is_trusted_comment_author(item, repo_full_name, issue_number):
                    continue

                envelope = _parse_receipt_comment(
                    body=body,
                    expected_request_id=expected_req_id,
                    expected_digest=expected_digest,
                    expected_operation=expected_operation,
                    expected_accepted_revision=expected_accepted_revision,
                    expected_claim_revision=expected_claim_revision,
                )
                if envelope is not None:
                    comment_id = item["id"]
                    ref = f"https://github.com/{repo_full_name}/issues/{issue_number}#issuecomment-{comment_id}"
                    matching_receipts.append((envelope, ref))

        if len(matching_receipts) > 1:
            raise ActionsHandlerError("duplicate_receipts_found")

        if len(matching_receipts) == 1:
            envelope, _reference = matching_receipts[0]
            # The receipt supplies candidates, never trusted revision facts.
            # finalize independently checks these immutable journal snapshots.
            journal = ActionsGitJournal(request=self._read_api_transport,
                                        validate_transition=lambda _old, _new: False)
            try:
                claimed = journal.load_at(request_id, envelope["claim_revision"])
                if claimed.record_json is None:
                    raise ValueError("missing claim")
                bundle = ExecutionBundle(
                    request_id=request_id, request_digest=expected_digest,
                    operation=expected_operation, repository_id=record["repository_id"],
                    repository_full_name=repo_full_name, issue_id=record["issue_id"],
                    issue_number=issue_number, execution_id=owner_exec_id,
                    canonical_record=claimed.record_json,
                    accepted_revision=envelope["accepted_revision"],
                    claim_revision=envelope["claim_revision"],
                    parameters=json.loads(record["canonical_request"])["parameters"],
                )
            except Exception:
                raise ActionsHandlerError("bundle_revision_mismatch") from None
            return self.finalize(bundle)

        # 0 matching receipts found: uncertainty without positive trusted evidence remains uncertainty.
        return ExecutionReceipt(
            request_id=request_id,
            durable_revision=head_sha,
            terminal_state="ambiguous",
            terminal_code="reconciliation_required",
            terminal_reference=None,
            envelope={},
            replayed=False,
            reconciled=False,
        )

    def _scan_comments(
        self,
        repo_full_name: str,
        issue_number: int,
    ) -> tuple[tuple[Any, ...], list[dict[str, Any]]]:
        all_comments: list[dict[str, Any]] = []
        seen_ids: set[int] = set()
        snapshot_items: list[tuple[Any, ...]] = []
        page = 1

        while True:
            if page > MAX_RECONCILIATION_PAGES:
                raise ActionsHandlerError("reconciliation_pagination_exceeded")

            path = f"/repos/{repo_full_name}/issues/{issue_number}/comments?per_page={RECONCILIATION_PER_PAGE}&page={page}"
            try:
                comments_page = self._read_api_transport("GET", path, body=None)
            except Exception:
                raise ActionsHandlerError("reconciliation_api_failed") from None

            if not isinstance(comments_page, list) or len(comments_page) > RECONCILIATION_PER_PAGE:
                raise ActionsHandlerError("reconciliation_malformed_response")

            for item in comments_page:
                if not isinstance(item, dict):
                    raise ActionsHandlerError("reconciliation_malformed_response")

                comment_id = item.get("id")
                if type(comment_id) is not int or comment_id <= 0:
                    raise ActionsHandlerError("reconciliation_malformed_response")

                if comment_id in seen_ids:
                    raise ActionsHandlerError("reconciliation_duplicate_comment_ids")
                seen_ids.add(comment_id)

                body = item.get("body")
                user = item.get("user")
                user_id = user.get("id") if isinstance(user, dict) else None
                user_type = user.get("type") if isinstance(user, dict) else None
                app = item.get("performed_via_github_app")
                app_id = app.get("id") if isinstance(app, dict) else None
                issue_url = item.get("issue_url")
                html_url = item.get("html_url")

                snapshot_items.append((comment_id, body, user_id, user_type, app_id, issue_url, html_url))
                all_comments.append(item)

            if len(comments_page) < RECONCILIATION_PER_PAGE:
                break
            page += 1

        return tuple(snapshot_items), all_comments

    def _safe_mark_ambiguous(self, request_id: str, execution_id: str) -> None:
        try:
            self._coordinator.mark_ambiguous(request_id, execution_id)
        except Exception:
            pass


class ControlPhase:
    """Phase B executor with Control authority.

    Operates strictly with Control App authority (CI inspect, comment POST, readback).
    Has NO Governance Contents authority and NO journal coordinator access.
    """

    def __init__(
        self,
        api_transport: Callable[..., Any],
        trusted_receipt_policy: TrustedReceiptPolicy,
        ci_policy: Optional[CiInspectionPolicy] = None,
        recipe_policy: Optional[RecipeDispatchPolicy] = None,
    ) -> None:
        if not callable(api_transport):
            raise TypeError("api_transport must be callable")
        if not isinstance(trusted_receipt_policy, TrustedReceiptPolicy):
            raise TypeError("trusted_receipt_policy must be a TrustedReceiptPolicy instance")
        if ci_policy is not None and not isinstance(ci_policy, CiInspectionPolicy):
            raise TypeError("ci_policy must be a CiInspectionPolicy instance or None")
        if recipe_policy is not None and not isinstance(recipe_policy, RecipeDispatchPolicy):
            raise TypeError("recipe_policy must be a RecipeDispatchPolicy instance or None")

        self._api_transport = api_transport
        self._trusted_receipt_policy = trusted_receipt_policy
        self._ci_policy = ci_policy
        self._recipe_policy = recipe_policy

    def validate_comment_identity(
        self,
        comment: Any,
        expected_repo: str,
        expected_issue_number: int,
        expected_body: Optional[str] = None,
    ) -> int:
        return _validate_comment_identity(
            comment=comment,
            trusted_receipt_policy=self._trusted_receipt_policy,
            expected_repo=expected_repo,
            expected_issue_number=expected_issue_number,
            expected_body=expected_body,
        )

    def is_trusted_comment_author(
        self,
        comment: Any,
        expected_repo: str,
        expected_issue_number: int,
    ) -> bool:
        return _is_trusted_comment_author(
            comment=comment,
            trusted_receipt_policy=self._trusted_receipt_policy,
            expected_repo=expected_repo,
            expected_issue_number=expected_issue_number,
        )

    def execute(
        self,
        bundle: ExecutionBundle,
        *,
        reconcile_recipe_only: bool = False,
    ) -> ControlExecutionResult:
        """Execute a typed effect, or reconcile a prior recipe dispatch, then publish its receipt."""
        if not isinstance(bundle, ExecutionBundle):
            try:
                if isinstance(bundle, dict):
                    bundle = ExecutionBundle.from_dict(bundle)
                elif isinstance(bundle, str):
                    bundle = ExecutionBundle.from_json(bundle)
                else:
                    raise ActionsHandlerError("invalid_execution_bundle")
            except Exception:
                raise ActionsHandlerError("invalid_execution_bundle") from None

        frozen_record = _validate_execution_bundle(bundle)

        operation = bundle.operation

        if reconcile_recipe_only:
            replay = self._existing_receipt(bundle)
            if replay is not None:
                return replay

        # Execute only the allowlisted, typed operations configured by trusted policy.
        if operation == "github.ci.inspect":
            if self._ci_policy is None:
                raise ActionsHandlerError("ci_policy_missing")
            try:
                ci_result = inspect_ci(bundle.parameters, self._ci_policy, self._api_transport)
                terminal_state = "succeeded"
                terminal_code = ci_result.get("result", "found")
                result_payload = ci_result
            except CiInspectError as e:
                terminal_state = "rejected"
                terminal_code = e.code
                result_payload = {"error": e.code, "retryable": e.retryable}
        elif operation == "workspace.recipe.dispatch":
            if self._recipe_policy is None:
                raise ActionsHandlerError("recipe_policy_missing")
            try:
                dispatcher = reconcile_recipe if reconcile_recipe_only else dispatch_recipe
                result_payload = dispatcher(
                    bundle.parameters,
                    bundle.request_id,
                    frozen_record.get("accepted_at"),
                    self._recipe_policy,
                    self._api_transport,
                )
                terminal_state = "succeeded"
                terminal_code = "dispatched"
            except RecipeDispatchError as error:
                if error.ambiguous or reconcile_recipe_only:
                    return ControlExecutionResult(
                        request_id=bundle.request_id,
                        execution_id=bundle.execution_id,
                        ambiguous=True,
                        ambiguous_code=error.code,
                    )
                terminal_state = "rejected"
                terminal_code = error.code
                result_payload = {"error": error.code, "retryable": error.retryable}
        elif operation in KNOWN_UNSUPPORTED_OPERATIONS or operation not in EXECUTABLE_OPERATIONS:
            terminal_state = "rejected"
            terminal_code = "unsupported_operation"
            result_payload = {"error": "unsupported_operation", "operation": operation}
        else:
            terminal_state = "rejected"
            terminal_code = "unsupported_operation"
            result_payload = {"error": "unsupported_operation", "operation": operation}

        # Build bounded result envelope carrying real accepted_revision and claim_revision
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": bundle.request_id,
            "request_digest": bundle.request_digest,
            "operation": bundle.operation,
            "accepted_revision": bundle.accepted_revision,
            "claim_revision": bundle.claim_revision,
            "terminal_state": terminal_state,
            "terminal_code": terminal_code,
            "result": result_payload,
        }

        comment_body = _format_receipt_comment(envelope)

        repo_full_name = bundle.repository_full_name
        issue_number = bundle.issue_number

        # Reconciliation has no write effect before this point. Observe again so
        # a receipt that appeared during destination reconciliation is replayed.
        if reconcile_recipe_only:
            replay = self._existing_receipt(bundle)
            if replay is not None:
                return replay

        if len(comment_body.encode("utf-8")) > MAX_COMMENT_BODY_BYTES:
            raise ActionsHandlerError("comment_body_too_large")

        post_path = f"/repos/{repo_full_name}/issues/{issue_number}/comments"
        try:
            post_res = self._api_transport("POST", post_path, body={"body": comment_body})
        except Exception:
            return ControlExecutionResult(
                request_id=bundle.request_id,
                execution_id=bundle.execution_id,
                ambiguous=True,
                ambiguous_code="comment_publication_ambiguous",
            )

        try:
            comment_id = self.validate_comment_identity(
                comment=post_res,
                expected_repo=repo_full_name,
                expected_issue_number=issue_number,
                expected_body=comment_body,
            )
        except ActionsHandlerError as e:
            return ControlExecutionResult(
                request_id=bundle.request_id,
                execution_id=bundle.execution_id,
                ambiguous=True,
                ambiguous_code=e.code,
            )

        # Read back by immutable ID
        get_path = f"/repos/{repo_full_name}/issues/comments/{comment_id}"
        try:
            get_res = self._api_transport("GET", get_path, body=None)
        except Exception:
            return ControlExecutionResult(
                request_id=bundle.request_id,
                execution_id=bundle.execution_id,
                ambiguous=True,
                ambiguous_code="comment_publication_ambiguous",
            )

        try:
            readback_id = self.validate_comment_identity(
                comment=get_res,
                expected_repo=repo_full_name,
                expected_issue_number=issue_number,
                expected_body=comment_body,
            )
        except ActionsHandlerError as e:
            return ControlExecutionResult(
                request_id=bundle.request_id,
                execution_id=bundle.execution_id,
                ambiguous=True,
                ambiguous_code=e.code,
            )

        if readback_id != comment_id:
            return ControlExecutionResult(
                request_id=bundle.request_id,
                execution_id=bundle.execution_id,
                ambiguous=True,
                ambiguous_code="comment_readback_identity_mismatch",
            )

        canonical_reference = (
            f"https://github.com/{repo_full_name}/issues/{issue_number}#issuecomment-{comment_id}"
        )
        if len(canonical_reference.encode("utf-8")) > MAX_TERMINAL_REFERENCE_BYTES:
            return ControlExecutionResult(
                request_id=bundle.request_id,
                execution_id=bundle.execution_id,
                ambiguous=True,
                ambiguous_code="terminal_reference_too_large",
            )

        return ControlExecutionResult(
            request_id=bundle.request_id,
            execution_id=bundle.execution_id,
            terminal_state=terminal_state,
            terminal_code=terminal_code,
            terminal_reference=canonical_reference,
            envelope=envelope,
            ambiguous=False,
        )

    def _existing_receipt(
        self, bundle: ExecutionBundle
    ) -> Optional[ControlExecutionResult]:
        first, comments = _scan_issue_comments(
            self._api_transport, bundle.repository_full_name, bundle.issue_number
        )
        second, _ = _scan_issue_comments(
            self._api_transport, bundle.repository_full_name, bundle.issue_number
        )
        if first != second:
            raise ActionsHandlerError("reconciliation_observation_unstable")
        matches: list[tuple[dict[str, Any], int]] = []
        for comment in comments:
            if not _is_trusted_comment_author(
                comment,
                self._trusted_receipt_policy,
                bundle.repository_full_name,
                bundle.issue_number,
            ):
                continue
            envelope = _parse_receipt_comment(
                comment.get("body"),
                bundle.request_id,
                bundle.request_digest,
                bundle.operation,
                bundle.accepted_revision,
                bundle.claim_revision,
            )
            if envelope is not None:
                matches.append((envelope, comment["id"]))
        if len(matches) > 1:
            raise ActionsHandlerError("duplicate_receipts_found")
        if not matches:
            return None
        envelope, comment_id = matches[0]
        reference = (
            f"https://github.com/{bundle.repository_full_name}/issues/"
            f"{bundle.issue_number}#issuecomment-{comment_id}"
        )
        return ControlExecutionResult(
            request_id=bundle.request_id,
            execution_id=bundle.execution_id,
            terminal_state=envelope["terminal_state"],
            terminal_code=envelope["terminal_code"],
            terminal_reference=reference,
            envelope=envelope,
            replayed=True,
        )


class ActionsRequestHandler:
    """Coordinate trusted request execution across Publisher and Control authorities."""

    def __init__(
        self,
        coordinator: ActionsJournalCoordinator,
        api_transport: Callable[..., Any],
        trusted_issue_policy: TrustedIssuePolicy,
        trusted_receipt_policy: TrustedReceiptPolicy,
        ci_policy: Optional[CiInspectionPolicy] = None,
        recipe_policy: Optional[RecipeDispatchPolicy] = None,
        *,
        publisher_api_transport: Optional[Callable[..., Any]] = None,
        control_api_transport: Optional[Callable[..., Any]] = None,
    ) -> None:
        pub_transport = publisher_api_transport or api_transport
        ctrl_transport = control_api_transport or api_transport

        self.publisher = PublisherPhase(
            coordinator=coordinator,
            trusted_issue_policy=trusted_issue_policy,
            trusted_receipt_policy=trusted_receipt_policy,
            read_api_transport=pub_transport,
        )
        self.control = ControlPhase(
            api_transport=ctrl_transport,
            trusted_receipt_policy=trusted_receipt_policy,
            ci_policy=ci_policy,
            recipe_policy=recipe_policy,
        )

        self._coordinator = coordinator
        self._api_transport = api_transport
        self._trusted_issue_policy = trusted_issue_policy
        self._trusted_receipt_policy = trusted_receipt_policy
        self._ci_policy = ci_policy
        self._recipe_policy = recipe_policy

    def validate_comment_identity(
        self,
        comment: Any,
        expected_repo: str,
        expected_issue_number: int,
        expected_body: Optional[str] = None,
    ) -> int:
        return self.publisher.validate_comment_identity(
            comment=comment,
            expected_repo=expected_repo,
            expected_issue_number=expected_issue_number,
            expected_body=expected_body,
        )

    def is_trusted_comment_author(
        self,
        comment: Any,
        expected_repo: str,
        expected_issue_number: int,
    ) -> bool:
        return self.publisher.is_trusted_comment_author(
            comment=comment,
            expected_repo=expected_repo,
            expected_issue_number=expected_issue_number,
        )

    def prepare(
        self,
        event_bytes: bytes,
        execution_id: str,
        accepted_at: str,
        policy_revision: str,
    ) -> PrepareResult:
        return self.publisher.prepare(event_bytes, execution_id, accepted_at, policy_revision)

    def execute(self, bundle: ExecutionBundle) -> ControlExecutionResult:
        return self.control.execute(bundle)

    def finalize(
        self,
        bundle: ExecutionBundle,
        control_result: Optional[ControlExecutionResult] = None,
    ) -> ExecutionReceipt:
        return self.publisher.finalize(bundle, control_result)

    def handle_request(
        self,
        event_bytes: bytes,
        execution_id: str,
        accepted_at: str,
        policy_revision: str,
    ) -> ExecutionReceipt:
        """Process an incoming Issue event across Publisher -> Control -> Publisher phases."""
        prep = self.publisher.prepare(
            event_bytes=event_bytes,
            execution_id=execution_id,
            accepted_at=accepted_at,
            policy_revision=policy_revision,
        )

        if prep.disposition == ClaimDisposition.TERMINAL_REPLAY:
            assert prep.receipt is not None
            return prep.receipt

        if prep.disposition == ClaimDisposition.RECONCILIATION_REQUIRED:
            return self.reconcile_request(prep.request_id, execution_id=None)

        if prep.disposition != ClaimDisposition.GRANTED:
            raise ActionsHandlerError("unexpected_claim_disposition")

        assert prep.bundle is not None
        ctrl_res = self.control.execute(prep.bundle)
        return self.publisher.finalize(prep.bundle, ctrl_res)

    def reconcile_request(
        self,
        request_id: str,
        execution_id: Optional[str] = None,
    ) -> ExecutionReceipt:
        """Independently observe issue comments to reconcile an ambiguous request."""
        return self.publisher.reconcile_request(request_id, execution_id=execution_id)

    @staticmethod
    def _format_receipt_comment(envelope: dict[str, Any]) -> str:
        return _format_receipt_comment(envelope)

    @classmethod
    def _parse_receipt_comment(
        cls,
        body: str,
        expected_request_id: str,
        expected_digest: str,
        expected_operation: str,
        expected_accepted_revision: Optional[str] = None,
        expected_claim_revision: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        return _parse_receipt_comment(
            body=body,
            expected_request_id=expected_request_id,
            expected_digest=expected_digest,
            expected_operation=expected_operation,
            expected_accepted_revision=expected_accepted_revision,
            expected_claim_revision=expected_claim_revision,
        )


ActionsPublisherPhase = PublisherPhase
ActionsControlPhase = ControlPhase
