"""Focused adversarial tests for the trusted Actions request handler and reconciliation."""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Optional
import unittest
from urllib.parse import parse_qs, urlsplit

from actions_ci_inspect import CiInspectionPolicy
from actions_git_journal import (
    AmbiguousPublication,
    ApiError,
    FIXED_REF,
    FIXED_REPOSITORY,
    JournalSnapshot,
    parse_and_validate_record,
)
from actions_journal_coordinator import (
    ActionsJournalCoordinator,
    ClaimDisposition,
    CoordinatorError,
    TrustedIssuePolicy,
    TrustedReconciliationObservation,
)
from actions_request_handler import (
    ActionsHandlerError,
    ActionsRequestHandler,
    ExecutionReceipt,
    MAX_COMMENT_BODY_BYTES,
    MAX_EVENT_BYTES,
    MAX_RESULT_ENVELOPE_BYTES,
)


CLI = str((Path(__file__).resolve().parent.parent / "target" / "debug" / "zach-actions").resolve())
POLICY_REVISION = "4ae216576b054f528c9edbcfed4a2711bccaa476"
ACCEPTED_AT = "2026-09-05T07:47:52Z"
REQUEST_ID = "uds007-inspect-build-01"
SOURCE_SHA = "4" * 40
EXECUTION_ID = "run-claim-101"

CI_POLICY = CiInspectionPolicy(
    repository_alias="ui-design-sandbox",
    repository_full_name="shockerqt/ui-design-sandbox",
    repository_id=1002,
    workflow_id=339778910,
    workflow_path=".github/workflows/ci.yml",
)

TRUSTED_POLICY = TrustedIssuePolicy(
    repository_id=1001,
    repository_full_name="shockerqt/zach",
    allowed_actor_ids=(2001,),
)


def make_event(
    *,
    request_id: str = REQUEST_ID,
    operation: str = "github.ci.inspect",
    parameters: Optional[dict[str, Any]] = None,
    sender_id: int = 2001,
    author_id: int = 2001,
    repo_id: int = 1001,
    repo_full_name: str = "shockerqt/zach",
    issue_id: int = 501,
    issue_number: int = 42,
    raw_body: Optional[str] = None,
) -> bytes:
    if raw_body is None:
        if parameters is None:
            parameters = {"repository": "ui-design-sandbox", "source_sha": SOURCE_SHA}
        request = {
            "schema_version": 1,
            "request_id": request_id,
            "operation": operation,
            "parameters": parameters,
        }
        body_str = json.dumps(request, separators=(",", ":"))
    else:
        body_str = raw_body

    event = {
        "action": "opened",
        "repository": {"id": repo_id, "full_name": repo_full_name},
        "sender": {"id": sender_id},
        "issue": {
            "id": issue_id,
            "number": issue_number,
            "user": {"id": author_id},
            "body": body_str,
        },
    }
    return json.dumps(event, separators=(",", ":")).encode("utf-8")


class UnifiedFakeApi:
    """Mock GitHub API implementing Git Data, CI Observation, and Issue Comments."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []

        # Git Data journal storage
        self.refs: dict[str, str] = {}
        self.commits: dict[str, dict[str, Any]] = {}
        self.trees: dict[str, dict[str, Any]] = {}
        self.blobs: dict[str, str] = {}
        self.bad_next_journal_patch = False
        empty_tree = hashlib.sha1(b"tree empty").hexdigest()
        root_commit = hashlib.sha1(b"commit root").hexdigest()
        self.trees[empty_tree] = {}
        self.commits[root_commit] = {
            "sha": root_commit,
            "tree": {"sha": empty_tree},
            "parents": [],
        }
        self.refs[FIXED_REF] = root_commit

        # CI Observation data
        self.ci_repo: dict[str, Any] = {
            "id": CI_POLICY.repository_id,
            "full_name": CI_POLICY.repository_full_name,
        }
        self.ci_workflow: dict[str, Any] = {
            "id": CI_POLICY.workflow_id,
            "path": CI_POLICY.workflow_path,
            "state": "active",
        }
        self.ci_commit: dict[str, Any] = {"sha": SOURCE_SHA}
        self.ci_runs: list[dict[str, Any]] = [
            {
                "id": 33958090021,
                "run_attempt": 1,
                "workflow_id": CI_POLICY.workflow_id,
                "path": CI_POLICY.workflow_path,
                "event": "push",
                "status": "completed",
                "conclusion": "success",
                "head_sha": SOURCE_SHA,
                "repository": {"id": CI_POLICY.repository_id, "full_name": CI_POLICY.repository_full_name},
                "head_repository": {"id": CI_POLICY.repository_id, "full_name": CI_POLICY.repository_full_name},
                "created_at": "2026-09-05T09:28:46Z",
                "updated_at": "2026-09-05T09:28:46Z",
                "html_url": f"https://github.com/{CI_POLICY.repository_full_name}/actions/runs/33958090021",
            }
        ]
        self.ci_jobs: list[dict[str, Any]] = [
            {
                "id": 7001,
                "run_id": 33958090021,
                "run_attempt": 1,
                "head_sha": SOURCE_SHA,
                "name": "test",
                "status": "completed",
                "conclusion": "success",
                "html_url": f"https://github.com/{CI_POLICY.repository_full_name}/actions/runs/33958090021/job/7001",
                "steps": [],
            }
        ]
        self.ci_runs_page_limit: Optional[int] = None
        self.ci_runs_change_on_second_call = False
        self._ci_runs_call_count = 0

        # Issue comments storage
        self.comments: dict[int, dict[str, Any]] = {}
        self.next_comment_id = 1
        self.bad_post_comment = False
        self.bad_post_identity = False
        self.bad_get_comment_readback = False
        self.bad_comment_body_on_readback = False
        self.bad_comments_pagination = False
        self.comment_pagination_page_limit: Optional[int] = None

    def request(self, method: str, path: str, body: Any = None) -> Any:
        self.calls.append((method, path, body))

        # 1. Git Data journal endpoints
        ref_path = f"/repos/{FIXED_REPOSITORY}/git/ref/{FIXED_REF}"
        refs_path = f"/repos/{FIXED_REPOSITORY}/git/refs/{FIXED_REF}"

        if method == "GET" and path in (ref_path, refs_path):
            return {"ref": f"refs/{FIXED_REF}", "object": {"sha": self.refs[FIXED_REF]}}

        if method == "PATCH" and path in (ref_path, refs_path):
            if self.bad_next_journal_patch:
                raise ApiError(500, "journal_patch_failed")
            assert body is not None and body.get("force") is False
            candidate = body["sha"]
            current = self.refs[FIXED_REF]
            parents = [entry["sha"] for entry in self.commits[candidate]["parents"]]
            if current not in parents:
                raise ApiError(422, "stale")
            self.refs[FIXED_REF] = candidate
            return {"ref": f"refs/{FIXED_REF}", "object": {"sha": candidate}}

        if method == "POST" and path == f"/repos/{FIXED_REPOSITORY}/git/blobs":
            assert body is not None
            raw = base64.b64decode(body["content"])
            sha = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            self.blobs[sha] = body["content"]
            return {"sha": sha}

        tree_prefix = f"/repos/{FIXED_REPOSITORY}/git/trees/"
        if method == "GET" and path.startswith(tree_prefix):
            sha = path[len(tree_prefix):]
            entries = self.trees[sha]
            direct = [dict(entry) for name, entry in entries.items() if "/" not in name]
            nested = {
                name.split("/", 1)[1]: dict(entry, path=name.split("/", 1)[1])
                for name, entry in entries.items()
                if name.startswith("requests/")
            }
            if nested:
                subtree = hashlib.sha1(json.dumps(nested, sort_keys=True).encode()).hexdigest()
                self.trees[subtree] = nested
                direct.append({"path": "requests", "mode": "040000", "type": "tree", "sha": subtree})
            return {"sha": sha, "tree": direct, "truncated": False}

        if method == "POST" and path == f"/repos/{FIXED_REPOSITORY}/git/trees":
            assert body is not None
            entries = dict(self.trees[body["base_tree"]])
            for entry in body["tree"]:
                entries[entry["path"]] = dict(entry)
            sha = hashlib.sha1(json.dumps(entries, sort_keys=True).encode()).hexdigest()
            self.trees[sha] = entries
            return {"sha": sha}

        commit_prefix = f"/repos/{FIXED_REPOSITORY}/git/commits/"
        if method == "POST" and path == f"/repos/{FIXED_REPOSITORY}/git/commits":
            assert body is not None
            serial = len(self.commits)
            sha = hashlib.sha1(
                json.dumps([body["tree"], body["parents"], body["message"], serial]).encode()
            ).hexdigest()
            self.commits[sha] = {
                "sha": sha,
                "tree": {"sha": body["tree"]},
                "parents": [{"sha": parent} for parent in body["parents"]],
            }
            return {"sha": sha}
        if method == "GET" and path.startswith(commit_prefix):
            return self.commits[path[len(commit_prefix):]]

        contents_prefix = f"/repos/{FIXED_REPOSITORY}/contents/"
        if method == "GET" and path.startswith(contents_prefix):
            record_path, ref = path[len(contents_prefix):].split("?ref=", 1)
            tree = self.trees[self.commits[ref]["tree"]["sha"]]
            if record_path not in tree:
                raise ApiError(404, "not_found")
            entry = tree[record_path]
            content = self.blobs[entry["sha"]]
            raw = base64.b64decode(content)
            return {
                "type": "file",
                "encoding": "base64",
                "size": len(raw),
                "content": content,
                "sha": entry["sha"],
            }

        # 2. Issue comments endpoints
        repo = TRUSTED_POLICY.repository_full_name
        if method == "POST" and path == f"/repos/{repo}/issues/42/comments":
            if self.bad_post_comment:
                raise ApiError(500, "comment_post_failed")
            comment_id = self.next_comment_id
            self.next_comment_id += 1
            issue_url = (
                f"https://api.github.com/repos/{repo}/issues/999"
                if self.bad_post_identity
                else f"https://api.github.com/repos/{repo}/issues/42"
            )
            item = {
                "id": comment_id,
                "body": body["body"],
                "issue_url": issue_url,
                "html_url": f"https://github.com/{repo}/issues/42#issuecomment-{comment_id}",
            }
            self.comments[comment_id] = item
            return item

        if method == "GET" and path.startswith(f"/repos/{repo}/issues/comments/"):
            if self.bad_get_comment_readback:
                raise ApiError(500, "comment_readback_failed")
            comment_id = int(path.rsplit("/", 1)[-1])
            if comment_id not in self.comments:
                raise ApiError(404, "not_found")
            res = dict(self.comments[comment_id])
            if self.bad_comment_body_on_readback:
                res["body"] = res["body"] + " [corrupted]"
            return res

        if method == "GET" and path.startswith(f"/repos/{repo}/issues/42/comments?"):
            if self.bad_comments_pagination:
                raise ApiError(500, "pagination_failed")
            parsed = urlsplit(path)
            query = parse_qs(parsed.query)
            page = int(query.get("page", ["1"])[0])
            per_page = int(query.get("per_page", ["100"])[0])
            if self.comment_pagination_page_limit and page > self.comment_pagination_page_limit:
                # Infinite loop simulation
                return [dict(self.comments[1])] if self.comments else []
            all_items = list(self.comments.values())
            start = (page - 1) * per_page
            return all_items[start : start + per_page]

        # 3. CI endpoints
        ci_repo_base = f"/repos/{CI_POLICY.repository_full_name}"
        if method == "GET" and path == ci_repo_base:
            return self.ci_repo

        if method == "GET" and path == f"{ci_repo_base}/actions/workflows/{CI_POLICY.workflow_id}":
            return self.ci_workflow

        if method == "GET" and path == f"{ci_repo_base}/commits/{SOURCE_SHA}":
            return self.ci_commit

        if method == "GET" and path.startswith(f"{ci_repo_base}/actions/workflows/{CI_POLICY.workflow_id}/runs?"):
            self._ci_runs_call_count += 1
            if self.ci_runs_page_limit:
                return {"total_count": 9999, "workflow_runs": [dict(self.ci_runs[0])]}
            runs = list(self.ci_runs)
            if self.ci_runs_change_on_second_call and self._ci_runs_call_count >= 2:
                changed = dict(runs[0])
                changed["id"] = 99999999
                changed["html_url"] = f"https://github.com/{CI_POLICY.repository_full_name}/actions/runs/99999999"
                runs = [changed]
            return {"total_count": len(runs), "workflow_runs": runs}

        if method == "GET" and path.startswith(f"{ci_repo_base}/actions/runs/") and "/jobs?" in path:
            return {"total_count": len(self.ci_jobs), "jobs": self.ci_jobs}

        if method == "GET" and path.startswith(f"{ci_repo_base}/actions/runs/"):
            run_id = int(path.rsplit("/", 1)[-1])
            for r in self.ci_runs:
                if r["id"] == run_id:
                    return r
            raise ApiError(404, "run_not_found")

        raise ApiError(404, f"unhandled endpoint: {method} {path}")


class TestActionsRequestHandler(unittest.TestCase):
    def setUp(self) -> None:
        self.api = UnifiedFakeApi()
        self.coordinator = ActionsJournalCoordinator(CLI, lambda method, path, body=None: self.api.request(method, path, body))
        self.handler = ActionsRequestHandler(
            coordinator=self.coordinator,
            api_transport=lambda method, path, body=None: self.api.request(method, path, body),
            trusted_issue_policy=TRUSTED_POLICY,
            ci_policy=CI_POLICY,
        )

    # 1. valid github.ci.inspect request end-to-end
    def test_01_valid_ci_inspect_request_end_to_end(self) -> None:
        event = make_event()
        receipt = self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)

        self.assertEqual(receipt.request_id, REQUEST_ID)
        self.assertEqual(receipt.terminal_state, "succeeded")
        self.assertEqual(receipt.terminal_code, "found")
        self.assertTrue(receipt.terminal_reference.startswith("https://github.com/shockerqt/zach/issues/42#issuecomment-"))
        self.assertFalse(receipt.replayed)
        self.assertFalse(receipt.reconciled)

        # Journal is terminal succeeded
        _, record = self.coordinator.load_record(REQUEST_ID)
        self.assertEqual(record["state"], "succeeded")
        self.assertEqual(record["terminal_code"], "found")
        self.assertEqual(record["terminal_reference"], receipt.terminal_reference)

    # 2. unauthorized actor
    def test_02_unauthorized_actor(self) -> None:
        event = make_event(sender_id=9999, author_id=9999)
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(ctx.exception.code, "cli_validation_failed")
        self.assertEqual(len(self.api.comments), 0)

    # 3. repository metadata mismatch
    def test_03_repository_metadata_mismatch(self) -> None:
        event = make_event(repo_id=9999, repo_full_name="other/repo")
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(ctx.exception.code, "cli_validation_failed")
        self.assertEqual(len(self.api.comments), 0)

    # 4. malformed Issue JSON
    def test_04_malformed_issue_json(self) -> None:
        event = make_event(raw_body="invalid-json{{{")
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(ctx.exception.code, "cli_validation_failed")
        self.assertEqual(len(self.api.comments), 0)

    # 5. exact acceptance replay
    def test_05_exact_acceptance_replay(self) -> None:
        event = make_event()
        # Accept first directly
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        self.assertFalse(acceptance.replayed)

        # Handler handles same event
        receipt = self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(receipt.terminal_state, "succeeded")
        self.assertEqual(receipt.terminal_code, "found")

    # 6. durable claim required before inspector invocation
    def test_06_durable_claim_required_before_inspector_invocation(self) -> None:
        event = make_event()
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        # Make journal ref update fail so claim cannot be durably published
        self.api.bad_next_journal_patch = True
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(ctx.exception.code, "claim_failed")

        # Verify no CI endpoint was called
        ci_calls = [call for call in self.api.calls if "actions/workflows" in call[1]]
        self.assertEqual(len(ci_calls), 0)

    # 7. terminal replay does not invoke inspector
    def test_07_terminal_replay_does_not_invoke_inspector(self) -> None:
        event = make_event()
        receipt1 = self.handler.handle_request(event, "run-first", ACCEPTED_AT, POLICY_REVISION)
        self.assertFalse(receipt1.replayed)

        ci_calls_before = len([call for call in self.api.calls if "actions/workflows" in call[1]])
        comment_posts_before = len(self.api.comments)

        # Call again with another execution_id
        receipt2 = self.handler.handle_request(event, "run-second", ACCEPTED_AT, POLICY_REVISION)
        self.assertTrue(receipt2.replayed)
        self.assertEqual(receipt2.terminal_state, "succeeded")
        self.assertEqual(receipt2.terminal_reference, receipt1.terminal_reference)

        # No new CI calls or comment posts
        ci_calls_after = len([call for call in self.api.calls if "actions/workflows" in call[1]])
        comment_posts_after = len(self.api.comments)
        self.assertEqual(ci_calls_before, ci_calls_after)
        self.assertEqual(comment_posts_before, comment_posts_after)

    # 8. reconciliation-required does not invoke inspector
    def test_08_reconciliation_required_does_not_invoke_inspector(self) -> None:
        event = make_event()
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        self.coordinator.claim(acceptance.request_id, "run-first")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-first")

        ci_calls_before = len([call for call in self.api.calls if "actions/workflows" in call[1]])

        # Calling handle_request encounters ClaimDisposition.RECONCILIATION_REQUIRED
        receipt = self.handler.handle_request(event, "run-second", ACCEPTED_AT, POLICY_REVISION)
        self.assertTrue(receipt.reconciled)

        # No CI calls made during reconciliation
        ci_calls_after = len([call for call in self.api.calls if "actions/workflows" in call[1]])
        self.assertEqual(ci_calls_before, ci_calls_after)

    # 9. unsupported known operation produces rejection and no handler effect
    def test_09_unsupported_known_operation_produces_rejection_and_no_handler_effect(self) -> None:
        event = make_event(
            request_id="gov-ledger-req-01",
            operation="governance.ledger",
            parameters={"step": 1},
        )
        receipt = self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)

        self.assertEqual(receipt.terminal_state, "rejected")
        self.assertEqual(receipt.terminal_code, "unsupported_operation")
        self.assertIsNotNone(receipt.terminal_reference)

        # Assert no CI calls
        ci_calls = [call for call in self.api.calls if "actions/workflows" in call[1]]
        self.assertEqual(len(ci_calls), 0)

        # Journal completed as rejected
        _, record = self.coordinator.load_record("gov-ledger-req-01")
        self.assertEqual(record["state"], "rejected")
        self.assertEqual(record["terminal_code"], "unsupported_operation")

    # 10. wrong repository alias
    def test_10_wrong_repository_alias(self) -> None:
        event = make_event(
            request_id="wrong-repo-01",
            parameters={"repository": "forbidden-repo", "source_sha": SOURCE_SHA},
        )
        receipt = self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(receipt.terminal_state, "rejected")
        self.assertEqual(receipt.terminal_code, "repository_not_allowed")

        _, record = self.coordinator.load_record("wrong-repo-01")
        self.assertEqual(record["state"], "rejected")
        self.assertEqual(record["terminal_code"], "repository_not_allowed")

    # 11. wrong exact source SHA format
    def test_11_wrong_exact_source_sha_format(self) -> None:
        event = make_event(
            request_id="wrong-sha-01",
            parameters={"repository": "ui-design-sandbox", "source_sha": "not-a-40-hex-sha"},
        )
        receipt = self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(receipt.terminal_state, "rejected")
        self.assertEqual(receipt.terminal_code, "invalid_source_sha")

        _, record = self.coordinator.load_record("wrong-sha-01")
        self.assertEqual(record["state"], "rejected")
        self.assertEqual(record["terminal_code"], "invalid_source_sha")

    # 12. foreign/malformed CI response
    def test_12_foreign_malformed_ci_response(self) -> None:
        self.api.ci_workflow["id"] = 999999999  # Mismatch with policy.workflow_id
        event = make_event(request_id="ci-malformed-01")
        receipt = self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(receipt.terminal_state, "rejected")
        self.assertEqual(receipt.terminal_code, "workflow_identity_mismatch")

    # 13. incomplete CI pagination
    def test_13_incomplete_ci_pagination(self) -> None:
        self.api.ci_runs_page_limit = 10
        event = make_event(request_id="ci-pagination-01")
        receipt = self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(receipt.terminal_state, "rejected")
        self.assertEqual(receipt.terminal_code, "incomplete_pagination")

    # 14. CI run changes during observation
    def test_14_ci_run_changes_during_observation(self) -> None:
        self.api.ci_runs_change_on_second_call = True
        event = make_event(request_id="ci-raced-01")
        receipt = self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(receipt.terminal_state, "rejected")
        self.assertEqual(receipt.terminal_code, "run_changed")

    # 15. successful result comment + exact readback
    def test_15_successful_result_comment_and_exact_readback(self) -> None:
        event = make_event(request_id="readback-01")
        receipt = self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(receipt.terminal_state, "succeeded")

        # Verify comment in API
        comment_id = int(receipt.terminal_reference.rsplit("-", 1)[-1])
        comment = self.api.comments[comment_id]
        self.assertIn("zach-actions:receipt:v1:request_id=readback-01", comment["body"])

    # 16. foreign Issue/comment identity rejected
    def test_16_foreign_issue_comment_identity_rejected(self) -> None:
        self.api.bad_post_identity = True
        event = make_event(request_id="identity-mismatch-01")
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(ctx.exception.code, "comment_identity_mismatch")

        # Journal is marked ambiguous
        _, record = self.coordinator.load_record("identity-mismatch-01")
        self.assertEqual(record["state"], "ambiguous")

    # 17. comment body mismatch on readback rejected
    def test_17_comment_body_mismatch_on_readback_rejected(self) -> None:
        self.api.bad_comment_body_on_readback = True
        event = make_event(request_id="body-mismatch-01")
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(ctx.exception.code, "comment_body_mismatch")

        # Journal is marked ambiguous
        _, record = self.coordinator.load_record("body-mismatch-01")
        self.assertEqual(record["state"], "ambiguous")

    # 18. oversized result rejected before POST
    def test_18_oversized_result_rejected_before_post(self) -> None:
        import actions_request_handler
        orig_inspect = actions_request_handler.inspect_ci
        try:
            actions_request_handler.inspect_ci = lambda *args, **kwargs: {"result": "x" * (MAX_RESULT_ENVELOPE_BYTES + 1)}
            event = make_event(request_id="oversized-01")
            comments_before = len(self.api.comments)
            with self.assertRaises(ActionsHandlerError) as ctx:
                self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
            self.assertEqual(ctx.exception.code, "result_envelope_too_large")
            self.assertEqual(len(self.api.comments), comments_before)
        finally:
            actions_request_handler.inspect_ci = orig_inspect

    # 19. result comment transport failure before known effect
    def test_19_result_comment_transport_failure_before_known_effect(self) -> None:
        self.api.bad_post_comment = True
        event = make_event(request_id="transport-fail-01")
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(ctx.exception.code, "comment_publication_ambiguous")

        # Record marked ambiguous
        _, record = self.coordinator.load_record("transport-fail-01")
        self.assertEqual(record["state"], "ambiguous")

    # 20. ambiguous comment publication never auto-retries
    def test_20_ambiguous_comment_publication_never_auto_retries(self) -> None:
        self.api.bad_post_comment = True
        event = make_event(request_id="auto-retry-01")
        with self.assertRaises(ActionsHandlerError):
            self.handler.handle_request(event, "run-initial", ACCEPTED_AT, POLICY_REVISION)

        post_calls_before = len([call for call in self.api.calls if call[0] == "POST" and "comments" in call[1]])

        # Another run arrives with same event
        self.api.bad_post_comment = False
        receipt = self.handler.handle_request(event, "run-subsequent", ACCEPTED_AT, POLICY_REVISION)

        post_calls_after = len([call for call in self.api.calls if call[0] == "POST" and "comments" in call[1]])
        # Did NOT attempt another comment POST
        self.assertEqual(post_calls_before, post_calls_after)
        self.assertTrue(receipt.reconciled)

    # 21. ambiguous request can reconcile from exactly one bound receipt
    def test_21_ambiguous_request_can_reconcile_from_exactly_one_bound_receipt(self) -> None:
        event = make_event(request_id="reconcile-01")
        # Simulate readback failure after comment POST
        self.api.bad_get_comment_readback = True
        with self.assertRaises(ActionsHandlerError):
            self.handler.handle_request(event, "run-1", ACCEPTED_AT, POLICY_REVISION)

        # Comment is already in self.api.comments!
        self.assertEqual(len(self.api.comments), 1)
        self.api.bad_get_comment_readback = False

        # Reconcile request
        receipt = self.handler.reconcile_request("reconcile-01")
        self.assertTrue(receipt.reconciled)
        self.assertEqual(receipt.terminal_state, "succeeded")
        self.assertEqual(receipt.terminal_code, "found")

        _, record = self.coordinator.load_record("reconcile-01")
        self.assertEqual(record["state"], "succeeded")
        self.assertEqual(record["terminal_code"], "found")

    # 22. duplicate bound receipts fail closed
    def test_22_duplicate_bound_receipts_fail_closed(self) -> None:
        event = make_event(request_id="dup-receipts-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        self.coordinator.claim(acceptance.request_id, "run-dup")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-dup")

        # Manually create two comments matching the marker
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "dup-receipts-01",
            "request_digest": "0" * 64,
            "operation": "github.ci.inspect",
            "accepted_revision": acceptance.durable_revision,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {},
        }
        # Update digest to match acceptance
        _, record = self.coordinator.load_record("dup-receipts-01")
        digest = record["request_digest"]
        envelope["request_digest"] = digest
        comment_body = ActionsRequestHandler._format_receipt_comment(envelope)

        self.api.comments[1] = {"id": 1, "body": comment_body}
        self.api.comments[2] = {"id": 2, "body": comment_body}

        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.reconcile_request("dup-receipts-01")
        self.assertEqual(ctx.exception.code, "duplicate_receipts_found")

    # 23. reconciliation with malformed/incomplete comment pagination fails closed
    def test_23_reconciliation_with_malformed_incomplete_comment_pagination_fails_closed(self) -> None:
        event = make_event(request_id="malformed-reconcile-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        self.coordinator.claim(acceptance.request_id, "run-malformed")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-malformed")

        self.api.bad_comments_pagination = True
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.reconcile_request("malformed-reconcile-01")
        self.assertEqual(ctx.exception.code, "reconciliation_api_failed")

    # 24. terminal journal publication only happens after proven result receipt
    def test_24_terminal_journal_publication_only_happens_after_proven_result_receipt(self) -> None:
        event = make_event(request_id="ordering-01")
        self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)

        post_comment_idx = -1
        get_comment_idx = -1
        last_journal_patch_idx = -1

        for i, call in enumerate(self.api.calls):
            if call[0] == "POST" and "comments" in call[1]:
                post_comment_idx = i
            elif call[0] == "GET" and "issues/comments" in call[1]:
                get_comment_idx = i
            elif call[0] == "PATCH" and "git/refs" in call[1]:
                last_journal_patch_idx = i

        self.assertTrue(post_comment_idx < get_comment_idx < last_journal_patch_idx)

    # 25. terminal journal publication ambiguity does not post another receipt
    def test_25_terminal_journal_publication_ambiguity_does_not_post_another_receipt(self) -> None:
        # We allow claim patch to succeed, but terminal complete patch to fail
        self.api.bad_next_journal_patch = False
        patch_count = [0]
        original_request = self.api.request

        def patched_request(method: str, path: str, body: Any = None) -> Any:
            if method == "PATCH" and "git/refs" in path:
                patch_count[0] += 1
                if patch_count[0] == 3:  # complete call
                    raise ApiError(500, "git_patch_ambiguity")
            return original_request(method, path, body)

        self.api.request = patched_request  # type: ignore[assignment]
        event = make_event(request_id="complete-ambiguous-01")

        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(ctx.exception.code, "journal_completion_failed")

        # Verify only 1 comment POST was made
        post_calls = [call for call in self.api.calls if call[0] == "POST" and "comments" in call[1]]
        self.assertEqual(len(post_calls), 1)

    # 26. no arbitrary command execution
    def test_26_no_arbitrary_command_execution(self) -> None:
        source_path = Path(__file__).resolve().parent / "actions_request_handler.py"
        tree = ast.parse(source_path.read_text())
        forbidden_imports = {"subprocess", "os.system", "pty", "shutil", "commands"}
        forbidden_calls = {"eval", "exec", "system", "popen", "spawn"}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotIn(alias.name, forbidden_imports)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.assertNotIn(node.module, forbidden_imports)
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    self.assertNotIn(node.func.id, forbidden_calls)

    # 27. credential/token leakage suppression
    def test_27_credential_token_leakage_suppression(self) -> None:
        token_sample = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        # Terminal code cannot contain token prefix
        with self.assertRaises(CoordinatorError) as ctx:
            self.coordinator._validate_terminal_value(token_sample, 128, "invalid_terminal_code")
        self.assertEqual(ctx.exception.code, "invalid_terminal_code")

    # 28. raw event/body/stderr not present in external errors or repr
    def test_28_raw_event_body_stderr_not_present_in_external_errors_or_repr(self) -> None:
        secret_content = "super_secret_password_in_body_12345"
        event = make_event(raw_body=f'{{"invalid_json": "{secret_content}"')
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)

        error_str = str(ctx.exception)
        error_repr = repr(ctx.exception)
        self.assertNotIn(secret_content, error_str)
        self.assertNotIn(secret_content, error_repr)

        receipt = ExecutionReceipt("req-1", "rev-1", "succeeded", "ok", None, {"secret": secret_content})
        receipt_repr = repr(receipt)
        self.assertNotIn(secret_content, receipt_repr)

    # 29. exact execution owner enforcement
    def test_29_exact_execution_owner_enforcement(self) -> None:
        event = make_event(request_id="owner-enforce-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        self.coordinator.claim(acceptance.request_id, "run-true-owner")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-true-owner")

        # Explicit reconcile with different execution_id
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.reconcile_request("owner-enforce-01", execution_id="run-fake-owner")
        self.assertEqual(ctx.exception.code, "execution_owner_mismatch")

    # 30. trusted reconciliation cannot be fabricated from caller input
    def test_30_trusted_reconciliation_cannot_be_fabricated_from_caller_input(self) -> None:
        # Coordinator rejects arbitrary object
        with self.assertRaises(CoordinatorError) as ctx:
            self.coordinator.reconcile("req-1", "owner-1", "fabricated_observation")  # type: ignore[arg-type]
        self.assertEqual(ctx.exception.code, "invalid_reconciliation_observation")

        with self.assertRaises(CoordinatorError) as ctx:
            self.coordinator.reconcile("req-1", "owner-1", {"terminal_state": "succeeded"})  # type: ignore[arg-type]
        self.assertEqual(ctx.exception.code, "invalid_reconciliation_observation")


if __name__ == "__main__":
    unittest.main()
