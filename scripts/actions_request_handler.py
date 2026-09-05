"""Trusted request execution and effect reconciliation for GitHub Actions.

This module composes the already-integrated pieces:
  GitHub Issue event
  -> trusted decode & durable journal acceptance (via ActionsJournalCoordinator.accept)
  -> durable execution claim (via ActionsJournalCoordinator.claim)
  -> typed effect handler (github.ci.inspect canary; deterministic rejection for unsupported)
  -> durable bounded connector-readable result (authenticated Issue comment with readback)
  -> journal terminalization / reconciliation (via ActionsJournalCoordinator.complete/reconcile)
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any, Callable, Final, Mapping, Optional

from actions_ci_inspect import CiInspectError, CiInspectionPolicy, inspect_ci
from actions_git_journal import (
    AmbiguousPublication,
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

SHA40_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")

RECEIPT_MARKER_RE: Final[re.Pattern[str]] = re.compile(
    r"^<!-- zach-actions:receipt:v1:request_id=([A-Za-z0-9_.:-]{1,128}):"
    r"digest=([0-9a-f]{64}):op=([a-z0-9_.-]{1,64}):"
    r"accepted_revision=([0-9a-f]{40}):claim_revision=([0-9a-f]{40}) -->$"
)

EXECUTABLE_OPERATIONS: Final[frozenset[str]] = frozenset({"github.ci.inspect"})
KNOWN_UNSUPPORTED_OPERATIONS: Final[frozenset[str]] = frozenset(
    {
        "governance.ledger",
        "governance.audit-task-integration",
        "workspace.recipe.dispatch",
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


class ActionsRequestHandler:
    """Coordinate trusted request execution, effect emission, and reconciliation."""

    def __init__(
        self,
        coordinator: ActionsJournalCoordinator,
        api_transport: Callable[..., Any],
        trusted_issue_policy: TrustedIssuePolicy,
        trusted_receipt_policy: TrustedReceiptPolicy,
        ci_policy: Optional[CiInspectionPolicy] = None,
    ) -> None:
        if not isinstance(coordinator, ActionsJournalCoordinator):
            raise TypeError("coordinator must be an ActionsJournalCoordinator instance")
        if not callable(api_transport):
            raise TypeError("api_transport must be callable")
        if not isinstance(trusted_issue_policy, TrustedIssuePolicy):
            raise TypeError("trusted_issue_policy must be a TrustedIssuePolicy instance")
        if not isinstance(trusted_receipt_policy, TrustedReceiptPolicy):
            raise TypeError("trusted_receipt_policy must be a TrustedReceiptPolicy instance")
        if ci_policy is not None and not isinstance(ci_policy, CiInspectionPolicy):
            raise TypeError("ci_policy must be a CiInspectionPolicy instance or None")

        self._coordinator = coordinator
        self._api_transport = api_transport
        self._trusted_issue_policy = trusted_issue_policy
        self._trusted_receipt_policy = trusted_receipt_policy
        self._ci_policy = ci_policy

    def validate_comment_identity(
        self,
        comment: Any,
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
        if user.get("id") != self._trusted_receipt_policy.bot_user_id:
            raise ActionsHandlerError("comment_bot_id_mismatch")
        if user.get("type") != "Bot":
            raise ActionsHandlerError("comment_user_not_bot")

        # 2. Mandatory authorship: GitHub App
        app = comment.get("performed_via_github_app")
        if not isinstance(app, dict):
            raise ActionsHandlerError("comment_app_metadata_missing")
        if app.get("id") != self._trusted_receipt_policy.app_id:
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

    def is_trusted_comment_author(
        self,
        comment: Any,
        expected_repo: str,
        expected_issue_number: int,
    ) -> bool:
        """Check whether a comment satisfies the trusted App/bot authorship contract."""
        try:
            self.validate_comment_identity(comment, expected_repo, expected_issue_number)
            return True
        except ActionsHandlerError:
            return False

    def handle_request(
        self,
        event_bytes: bytes,
        execution_id: str,
        accepted_at: str,
        policy_revision: str,
    ) -> ExecutionReceipt:
        """Process an incoming Issue event through acceptance, claim, dispatch, and completion."""
        if type(event_bytes) is not bytes:
            raise ActionsHandlerError("invalid_event_bytes")
        if len(event_bytes) > MAX_EVENT_BYTES:
            raise ActionsHandlerError("event_payload_too_large")

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

        # 2. Durable execution claim
        try:
            claim = self._coordinator.claim(acceptance.request_id, execution_id)
        except (CoordinatorError, AmbiguousPublication, ApiError) as e:
            code = getattr(e, "code", "claim_failed")
            raise ActionsHandlerError(code) from None

        if claim.disposition == ClaimDisposition.TERMINAL_REPLAY:
            stored = parse_and_validate_record(claim.record_json, acceptance.request_id)
            return ExecutionReceipt(
                request_id=acceptance.request_id,
                durable_revision=claim.durable_revision,
                terminal_state=stored["state"],
                terminal_code=stored.get("terminal_code") or "",
                terminal_reference=stored.get("terminal_reference"),
                envelope={},
                replayed=True,
            )

        if claim.disposition == ClaimDisposition.RECONCILIATION_REQUIRED:
            return self.reconcile_request(acceptance.request_id, execution_id=None)

        if claim.disposition != ClaimDisposition.GRANTED:
            raise ActionsHandlerError("unexpected_claim_disposition")

        # 3. Dispatch strictly from frozen canonical journal record
        record = parse_and_validate_record(claim.record_json, acceptance.request_id)
        operation = record["operation"]
        request_id = record["request_id"]
        request_digest = record["request_digest"]
        repo_full_name = record["repository_full_name"]
        issue_number = record["issue_number"]
        canonical_req = json.loads(record["canonical_request"])
        parameters = canonical_req.get("parameters", {})

        # 4. Effect execution
        if operation == "github.ci.inspect":
            if self._ci_policy is None:
                raise ActionsHandlerError("ci_policy_missing")
            try:
                ci_result = inspect_ci(parameters, self._ci_policy, self._api_transport)
                terminal_state = "succeeded"
                terminal_code = ci_result.get("result", "found")
                result_payload = ci_result
            except CiInspectError as e:
                terminal_state = "rejected"
                terminal_code = e.code
                result_payload = {"error": e.code, "retryable": e.retryable}
        elif operation in KNOWN_UNSUPPORTED_OPERATIONS or operation not in EXECUTABLE_OPERATIONS:
            terminal_state = "rejected"
            terminal_code = "unsupported_operation"
            result_payload = {"error": "unsupported_operation", "operation": operation}
        else:
            terminal_state = "rejected"
            terminal_code = "unsupported_operation"
            result_payload = {"error": "unsupported_operation", "operation": operation}

        # 5. Build bounded result envelope carrying both accepted_revision and claim_revision
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": request_id,
            "request_digest": request_digest,
            "operation": operation,
            "accepted_revision": acceptance.durable_revision,
            "claim_revision": claim.durable_revision,
            "terminal_state": terminal_state,
            "terminal_code": terminal_code,
            "result": result_payload,
        }

        comment_body = self._format_receipt_comment(envelope)

        # 6. Result comment publication with authenticated readback
        terminal_reference = self._publish_result_comment(
            repo_full_name=repo_full_name,
            issue_number=issue_number,
            comment_body=comment_body,
            request_id=request_id,
            execution_id=execution_id,
        )

        # 7. Terminalize journal record
        try:
            mutation = self._coordinator.complete(
                request_id=request_id,
                execution_id=execution_id,
                state=terminal_state,
                terminal_code=terminal_code,
                terminal_reference=terminal_reference,
            )
        except Exception:
            raise ActionsHandlerError("journal_completion_failed") from None

        return ExecutionReceipt(
            request_id=request_id,
            durable_revision=mutation.durable_revision,
            terminal_state=terminal_state,
            terminal_code=terminal_code,
            terminal_reference=terminal_reference,
            envelope=envelope,
        )

    def reconcile_request(
        self,
        request_id: str,
        execution_id: Optional[str] = None,
    ) -> ExecutionReceipt:
        """Independently observe issue comments to reconcile an ambiguous request."""
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
            # Finding 2: The original owner is still executing and authoritative.
            # Reconciliation MUST NOT infer owner death, mark ambiguous, or mutate journal state.
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

        # Finding 1: Full dual-scan paginated observation to guarantee observation stability
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
                # Enforce trusted GitHub App and bot authorship
                if not self.is_trusted_comment_author(item, repo_full_name, issue_number):
                    continue

                # Strict canonical receipt parsing
                envelope = self._parse_receipt_comment(
                    body=body,
                    expected_request_id=expected_req_id,
                    expected_digest=expected_digest,
                    expected_operation=expected_operation,
                )
                if envelope is not None:
                    comment_id = item["id"]
                    ref = f"https://github.com/{repo_full_name}/issues/{issue_number}#issuecomment-{comment_id}"
                    matching_receipts.append((envelope, ref))

        if len(matching_receipts) > 1:
            raise ActionsHandlerError("duplicate_receipts_found")

        if len(matching_receipts) == 1:
            envelope, canonical_reference = matching_receipts[0]
            observation = TrustedReconciliationObservation(
                terminal_state=envelope["terminal_state"],
                terminal_code=envelope["terminal_code"],
                terminal_reference=canonical_reference,
            )
            try:
                mutation = self._coordinator.reconcile(request_id, owner_exec_id, observation)
            except CoordinatorError as e:
                raise ActionsHandlerError(e.code) from None
            return ExecutionReceipt(
                request_id=request_id,
                durable_revision=mutation.durable_revision,
                terminal_state=envelope["terminal_state"],
                terminal_code=envelope["terminal_code"],
                terminal_reference=canonical_reference,
                envelope=envelope,
                reconciled=True,
            )

        # 0 matching receipts found: uncertainty without positive trusted evidence remains uncertainty.
        # Finding 2: DO NOT terminalize to rejected or invent negative certainty.
        # Leave journal in ambiguous state and return a non-terminal receipt.
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
        """Perform a single bounded paginated read of all comments on the issue.

        Returns:
            A tuple of (snapshot_fingerprint, list_of_raw_comment_dicts).
        """
        all_comments: list[dict[str, Any]] = []
        seen_ids: set[int] = set()
        snapshot_items: list[tuple[Any, ...]] = []
        page = 1

        while True:
            if page > MAX_RECONCILIATION_PAGES:
                raise ActionsHandlerError("reconciliation_pagination_exceeded")

            path = f"/repos/{repo_full_name}/issues/{issue_number}/comments?per_page={RECONCILIATION_PER_PAGE}&page={page}"
            try:
                comments_page = self._api_transport("GET", path, body=None)
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

    def _publish_result_comment(
        self,
        repo_full_name: str,
        issue_number: int,
        comment_body: str,
        request_id: str,
        execution_id: str,
    ) -> str:
        """POST comment, validate identity, GET readback, verify exact body, and return reference."""
        if len(comment_body.encode("utf-8")) > MAX_COMMENT_BODY_BYTES:
            raise ActionsHandlerError("comment_body_too_large")

        post_path = f"/repos/{repo_full_name}/issues/{issue_number}/comments"
        try:
            post_res = self._api_transport("POST", post_path, body={"body": comment_body})
        except Exception:
            self._safe_mark_ambiguous(request_id, execution_id)
            raise ActionsHandlerError("comment_publication_ambiguous") from None

        try:
            comment_id = self.validate_comment_identity(
                comment=post_res,
                expected_repo=repo_full_name,
                expected_issue_number=issue_number,
                expected_body=comment_body,
            )
        except ActionsHandlerError:
            self._safe_mark_ambiguous(request_id, execution_id)
            raise

        # Read back by immutable ID
        get_path = f"/repos/{repo_full_name}/issues/comments/{comment_id}"
        try:
            get_res = self._api_transport("GET", get_path, body=None)
        except Exception:
            self._safe_mark_ambiguous(request_id, execution_id)
            raise ActionsHandlerError("comment_publication_ambiguous") from None

        try:
            readback_id = self.validate_comment_identity(
                comment=get_res,
                expected_repo=repo_full_name,
                expected_issue_number=issue_number,
                expected_body=comment_body,
            )
        except ActionsHandlerError:
            self._safe_mark_ambiguous(request_id, execution_id)
            raise

        if readback_id != comment_id:
            self._safe_mark_ambiguous(request_id, execution_id)
            raise ActionsHandlerError("comment_readback_identity_mismatch")

        canonical_reference = (
            f"https://github.com/{repo_full_name}/issues/{issue_number}#issuecomment-{comment_id}"
        )
        if len(canonical_reference.encode("utf-8")) > MAX_TERMINAL_REFERENCE_BYTES:
            self._safe_mark_ambiguous(request_id, execution_id)
            raise ActionsHandlerError("terminal_reference_too_large")

        return canonical_reference

    def _safe_mark_ambiguous(self, request_id: str, execution_id: str) -> None:
        try:
            self._coordinator.mark_ambiguous(request_id, execution_id)
        except Exception:
            pass

    @staticmethod
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

    @classmethod
    def _parse_receipt_comment(
        cls,
        body: str,
        expected_request_id: str,
        expected_digest: str,
        expected_operation: str,
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

        state = envelope.get("terminal_state")
        if state not in ("succeeded", "rejected"):
            raise ActionsHandlerError("receipt_state_invalid")

        code = envelope.get("terminal_code")
        if not isinstance(code, str) or not (1 <= len(code) <= MAX_TERMINAL_CODE_BYTES):
            raise ActionsHandlerError("receipt_code_invalid")

        if not isinstance(envelope.get("result"), dict):
            raise ActionsHandlerError("receipt_result_invalid")

        # Exact canonical body check: regenerate from envelope and verify byte equality
        canonical = cls._format_receipt_comment(envelope)
        if body != canonical:
            raise ActionsHandlerError("receipt_canonical_body_mismatch")

        return envelope
