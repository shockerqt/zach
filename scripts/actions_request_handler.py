"""Trusted request execution and effect reconciliation for GitHub Actions.

This module composes the already-integrated pieces:
  GitHub Issue event
  -> trusted decode & durable journal acceptance (via ActionsJournalCoordinator.accept)
  -> durable execution claim (via ActionsJournalCoordinator.claim)
  -> typed effect handler (github.ci.inspect canary; deterministic rejection for unsupported)
  -> durable bounded connector-readable result (Issue comment with readback)
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

RECEIPT_MARKER_RE: Final[re.Pattern[str]] = re.compile(
    r"<!-- zach-actions:receipt:v1:request_id=([A-Za-z0-9_.:-]{1,128}):"
    r"digest=([0-9a-f]{64}):op=([a-z0-9_.-]{1,64}):"
    r"revision=([0-9a-f]{40}) -->"
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
        ci_policy: Optional[CiInspectionPolicy] = None,
    ) -> None:
        if not isinstance(coordinator, ActionsJournalCoordinator):
            raise TypeError("coordinator must be an ActionsJournalCoordinator instance")
        if not callable(api_transport):
            raise TypeError("api_transport must be callable")
        if not isinstance(trusted_issue_policy, TrustedIssuePolicy):
            raise TypeError("trusted_issue_policy must be a TrustedIssuePolicy instance")
        if ci_policy is not None and not isinstance(ci_policy, CiInspectionPolicy):
            raise TypeError("ci_policy must be a CiInspectionPolicy instance or None")

        self._coordinator = coordinator
        self._api_transport = api_transport
        self._trusted_issue_policy = trusted_issue_policy
        self._ci_policy = ci_policy

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

        # 5. Build bounded result envelope
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": request_id,
            "request_digest": request_digest,
            "operation": operation,
            "accepted_revision": claim.durable_revision,
            "terminal_state": terminal_state,
            "terminal_code": terminal_code,
            "result": result_payload,
        }

        comment_body = self._format_receipt_comment(envelope)

        # 6. Result comment publication with readback
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

        matching_receipts: list[tuple[dict[str, Any], str]] = []
        page = 1

        while True:
            if page > MAX_RECONCILIATION_PAGES:
                raise ActionsHandlerError("reconciliation_pagination_exceeded")

            path = f"/repos/{repo_full_name}/issues/{issue_number}/comments?per_page={RECONCILIATION_PER_PAGE}&page={page}"
            try:
                comments_page = self._api_transport("GET", path, body=None)
            except Exception:
                raise ActionsHandlerError("reconciliation_api_failed") from None

            if not isinstance(comments_page, list):
                raise ActionsHandlerError("reconciliation_malformed_response")

            if len(comments_page) > RECONCILIATION_PER_PAGE:
                raise ActionsHandlerError("reconciliation_malformed_response")

            for item in comments_page:
                if not isinstance(item, dict):
                    raise ActionsHandlerError("reconciliation_malformed_response")
                comment_id = item.get("id")
                if type(comment_id) is not int or comment_id <= 0:
                    raise ActionsHandlerError("reconciliation_malformed_response")
                body = item.get("body")
                if not isinstance(body, str):
                    continue

                if f"request_id={expected_req_id}" in body and "zach-actions:receipt:v1:" in body:
                    envelope = self._parse_receipt_comment(
                        body=body,
                        expected_request_id=expected_req_id,
                        expected_digest=expected_digest,
                        expected_operation=expected_operation,
                    )
                    if envelope is not None:
                        ref = f"https://github/{repo_full_name}/issues/{issue_number}#issuecomment-{comment_id}".replace(
                            "https://github/", "https://github.com/"
                        )
                        matching_receipts.append((envelope, ref))

            if len(comments_page) < RECONCILIATION_PER_PAGE:
                break
            page += 1

        if len(matching_receipts) > 1:
            raise ActionsHandlerError("duplicate_receipts_found")

        if len(matching_receipts) == 1:
            envelope, canonical_reference = matching_receipts[0]
            observation = TrustedReconciliationObservation(
                terminal_state=envelope["terminal_state"],
                terminal_code=envelope["terminal_code"],
                terminal_reference=canonical_reference,
            )
            if record["state"] == "executing":
                self._coordinator.mark_ambiguous(request_id, owner_exec_id)
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

        # 0 matching receipts found
        if expected_operation == "github.ci.inspect":
            observation = TrustedReconciliationObservation(
                terminal_state="rejected",
                terminal_code="no_result_published",
                terminal_reference=None,
            )
            if record["state"] == "executing":
                self._coordinator.mark_ambiguous(request_id, owner_exec_id)
            try:
                mutation = self._coordinator.reconcile(request_id, owner_exec_id, observation)
            except CoordinatorError as e:
                raise ActionsHandlerError(e.code) from None
            return ExecutionReceipt(
                request_id=request_id,
                durable_revision=mutation.durable_revision,
                terminal_state="rejected",
                terminal_code="no_result_published",
                terminal_reference=None,
                envelope={"error": "no_result_published"},
                reconciled=True,
            )

        raise ActionsHandlerError("reconciliation_no_receipt")

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

        if not isinstance(post_res, dict):
            self._safe_mark_ambiguous(request_id, execution_id)
            raise ActionsHandlerError("comment_publication_ambiguous")

        comment_id = post_res.get("id")
        if type(comment_id) is not int or comment_id <= 0:
            self._safe_mark_ambiguous(request_id, execution_id)
            raise ActionsHandlerError("comment_publication_ambiguous")

        issue_url = post_res.get("issue_url")
        if isinstance(issue_url, str):
            expected_suffix = f"/repos/{repo_full_name}/issues/{issue_number}"
            if not issue_url.endswith(expected_suffix):
                self._safe_mark_ambiguous(request_id, execution_id)
                raise ActionsHandlerError("comment_identity_mismatch")

        # Read back by immutable ID
        get_path = f"/repos/{repo_full_name}/issues/comments/{comment_id}"
        try:
            get_res = self._api_transport("GET", get_path, body=None)
        except Exception:
            self._safe_mark_ambiguous(request_id, execution_id)
            raise ActionsHandlerError("comment_publication_ambiguous") from None

        if not isinstance(get_res, dict):
            self._safe_mark_ambiguous(request_id, execution_id)
            raise ActionsHandlerError("comment_publication_ambiguous")

        if get_res.get("id") != comment_id:
            self._safe_mark_ambiguous(request_id, execution_id)
            raise ActionsHandlerError("comment_readback_identity_mismatch")

        readback_body = get_res.get("body")
        if readback_body != comment_body:
            self._safe_mark_ambiguous(request_id, execution_id)
            raise ActionsHandlerError("comment_body_mismatch")

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
            f"revision={envelope['accepted_revision']} -->"
        )
        comment_body = f"{marker}\n```json\n{envelope_json}\n```\n"
        if len(comment_body.encode("utf-8")) > MAX_COMMENT_BODY_BYTES:
            raise ActionsHandlerError("comment_body_too_large")
        return comment_body

    @staticmethod
    def _parse_receipt_comment(
        body: str,
        expected_request_id: str,
        expected_digest: str,
        expected_operation: str,
    ) -> Optional[dict[str, Any]]:
        marker_match = RECEIPT_MARKER_RE.search(body)
        if not marker_match:
            return None

        marker_req_id, marker_digest, marker_op, marker_rev = marker_match.groups()
        if (
            marker_req_id != expected_request_id
            or marker_digest != expected_digest
            or marker_op != expected_operation
        ):
            return None

        json_match = re.search(r"```json\s*([\s\S]*?)\s*```", body)
        if not json_match:
            raise ActionsHandlerError("receipt_json_missing")

        json_str = json_match.group(1).strip()
        try:
            envelope = json.loads(json_str)
        except Exception:
            raise ActionsHandlerError("receipt_json_invalid")

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
        if envelope.get("accepted_revision") != marker_rev:
            raise ActionsHandlerError("receipt_revision_mismatch")

        state = envelope.get("terminal_state")
        if state not in ("succeeded", "rejected"):
            raise ActionsHandlerError("receipt_state_invalid")

        code = envelope.get("terminal_code")
        if not isinstance(code, str) or not (1 <= len(code) <= MAX_TERMINAL_CODE_BYTES):
            raise ActionsHandlerError("receipt_code_invalid")

        if not isinstance(envelope.get("result"), dict):
            raise ActionsHandlerError("receipt_result_invalid")

        return envelope
