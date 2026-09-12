"""Focused adversarial tests for the trusted Actions request handler and reconciliation."""

from __future__ import annotations

import ast
from dataclasses import replace
import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Optional
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from actions_ci_inspect import CiInspectionPolicy
from actions_recipe_dispatch import RecipeDispatchPolicy
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
    ActionsControlPhase,
    ActionsHandlerError,
    ActionsPublisherPhase,
    ActionsRequestHandler,
    ControlExecutionResult,
    ControlPhase,
    ExecutionBundle,
    ExecutionReceipt,
    MAX_COMMENT_BODY_BYTES,
    MAX_EVENT_BYTES,
    MAX_RESULT_ENVELOPE_BYTES,
    PrepareResult,
    PublisherPhase,
    SHA40_RE,
    TrustedReceiptPolicy,
    _format_publisher_comment,
    _format_receipt_comment,
    load_durable_prepare_checkpoint,
    _parse_receipt_comment,
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

TRUSTED_RECEIPT_POLICY = TrustedReceiptPolicy(
    app_id=9876,
    bot_user_id=54321,
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
        self.bad_post_bot_id = False
        self.bad_post_user_type = False
        self.missing_post_app = False
        self.bad_post_app_id = False
        self.bad_get_comment_readback = False
        self.bad_comment_body_on_readback = False
        self.bad_comments_pagination = False
        self.comment_pagination_page_limit: Optional[int] = None
        self.comment_page_changes_on_second_call = False
        self._comment_get_call_count = 0
        self.on_comments_get: Optional[Any] = None
        self.duplicate_comment_ids_in_pagination = False

    def request(self, method: str, path: str, body: Any = None) -> Any:
        self.calls.append((method, path, body))

        compare_prefix = f"/repos/{FIXED_REPOSITORY}/compare/"
        if method == "GET" and path.startswith(compare_prefix):
            base, head = path[len(compare_prefix):].split("...")
            cursor = head
            seen = set()
            while cursor != base and cursor not in seen:
                seen.add(cursor)
                parents = self.commits[cursor]["parents"]
                if not parents:
                    break
                cursor = parents[0]["sha"]
            return {"status": "ahead" if cursor == base else "diverged",
                    "base_commit": {"sha": base},
                    "merge_base_commit": {"sha": base if cursor == base else head}}

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
            user_id = 99999 if self.bad_post_bot_id else TRUSTED_RECEIPT_POLICY.bot_user_id
            user_type = "User" if self.bad_post_user_type else "Bot"
            item: dict[str, Any] = {
                "id": comment_id,
                "body": body["body"],
                "issue_url": issue_url,
                "html_url": f"https://github.com/{repo}/issues/42#issuecomment-{comment_id}",
                "user": {"id": user_id, "type": user_type},
            }
            if not self.missing_post_app:
                app_id = 11111 if self.bad_post_app_id else TRUSTED_RECEIPT_POLICY.app_id
                item["performed_via_github_app"] = {"id": app_id}
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
            self._comment_get_call_count += 1
            parsed = urlsplit(path)
            query = parse_qs(parsed.query)
            page = int(query.get("page", ["1"])[0])
            per_page = int(query.get("per_page", ["100"])[0])

            if self.on_comments_get is not None:
                self.on_comments_get(page, self._comment_get_call_count)

            if self.bad_comments_pagination:
                raise ApiError(500, "pagination_failed")
            if self.comment_page_changes_on_second_call and self._comment_get_call_count >= 2:
                return [
                    {
                        "id": 999999,
                        "body": "unstable comment",
                        "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
                        "html_url": f"https://github.com/{repo}/issues/42#issuecomment-999999",
                        "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
                        "performed_via_github_app": {"id": TRUSTED_RECEIPT_POLICY.app_id},
                    }
                ]
            if self.comment_pagination_page_limit and page > self.comment_pagination_page_limit:
                # Infinite loop simulation
                return [dict(self.comments[1])] if self.comments else []

            all_items = sorted(self.comments.values(), key=lambda c: c["id"])
            if self.duplicate_comment_ids_in_pagination and page == 2 and all_items:
                dup_item = dict(all_items[0])
                return [dup_item]

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
            trusted_receipt_policy=TRUSTED_RECEIPT_POLICY,
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
        self.assertFalse(receipt.reconciled)
        self.assertEqual(receipt.terminal_state, "ambiguous")
        self.assertEqual(receipt.terminal_code, "reconciliation_required")

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
        self.assertEqual(ctx.exception.code, "comment_issue_url_mismatch")

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
        self.assertFalse(receipt.reconciled)
        self.assertEqual(receipt.terminal_state, "ambiguous")
        self.assertEqual(receipt.terminal_code, "reconciliation_required")

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
            "claim_revision": "b" * 40,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {},
        }
        # Update digest to match acceptance
        _, record = self.coordinator.load_record("dup-receipts-01")
        digest = record["request_digest"]
        envelope["request_digest"] = digest
        comment_body = ActionsRequestHandler._format_receipt_comment(envelope)

        repo = TRUSTED_POLICY.repository_full_name
        self.api.comments[1] = {
            "id": 1,
            "body": comment_body,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-1",
            "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
            "performed_via_github_app": {"id": TRUSTED_RECEIPT_POLICY.app_id},
        }
        self.api.comments[2] = {
            "id": 2,
            "body": comment_body,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-2",
            "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
            "performed_via_github_app": {"id": TRUSTED_RECEIPT_POLICY.app_id},
        }

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

    # 31. Finding 1: result publication requires trusted bot user ID
    def test_31_receipt_requires_trusted_bot_user_id(self) -> None:
        self.api.bad_post_bot_id = True
        event = make_event(request_id="bot-id-mismatch-01")
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(ctx.exception.code, "comment_bot_id_mismatch")

        _, record = self.coordinator.load_record("bot-id-mismatch-01")
        self.assertEqual(record["state"], "ambiguous")

    # 32. Finding 1: result publication requires user type "Bot"
    def test_32_receipt_requires_user_type_bot(self) -> None:
        self.api.bad_post_user_type = True
        event = make_event(request_id="user-type-mismatch-01")
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(ctx.exception.code, "comment_user_not_bot")

        _, record = self.coordinator.load_record("user-type-mismatch-01")
        self.assertEqual(record["state"], "ambiguous")

    # 33. Finding 1: result publication requires performed_via_github_app metadata
    def test_33_receipt_requires_github_app_metadata(self) -> None:
        self.api.missing_post_app = True
        event = make_event(request_id="missing-app-01")
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(ctx.exception.code, "comment_app_metadata_missing")

        _, record = self.coordinator.load_record("missing-app-01")
        self.assertEqual(record["state"], "ambiguous")

    # 34. Finding 1: result publication requires trusted GitHub App ID
    def test_34_receipt_requires_trusted_app_id(self) -> None:
        self.api.bad_post_app_id = True
        event = make_event(request_id="app-id-mismatch-01")
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.handle_request(event, EXECUTION_ID, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(ctx.exception.code, "comment_app_id_mismatch")

        _, record = self.coordinator.load_record("app-id-mismatch-01")
        self.assertEqual(record["state"], "ambiguous")

    # 35. Finding 1: reconciliation ignores copied receipt from untrusted human collaborator
    def test_35_reconciliation_ignores_untrusted_author_receipt(self) -> None:
        event = make_event(request_id="untrusted-author-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        claim = self.coordinator.claim(acceptance.request_id, "run-untrusted")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-untrusted")

        # Fake comment posted by human actor with valid envelope and marker
        _, record = self.coordinator.load_record("untrusted-author-01")
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "untrusted-author-01",
            "request_digest": record["request_digest"],
            "operation": "github.ci.inspect",
            "accepted_revision": acceptance.durable_revision,
            "claim_revision": claim.durable_revision,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {},
        }
        comment_body = ActionsRequestHandler._format_receipt_comment(envelope)
        repo = TRUSTED_POLICY.repository_full_name
        self.api.comments[1] = {
            "id": 1,
            "body": comment_body,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-1",
            "user": {"id": 2001, "type": "User"},  # Human collaborator, not bot!
            # Missing performed_via_github_app
        }

        # Reconciliation ignores the human-authored receipt and leaves journal ambiguous
        receipt = self.handler.reconcile_request("untrusted-author-01")
        self.assertFalse(receipt.reconciled)
        self.assertEqual(receipt.terminal_state, "ambiguous")
        self.assertEqual(receipt.terminal_code, "reconciliation_required")
        _, record = self.coordinator.load_record("untrusted-author-01")
        self.assertEqual(record["state"], "ambiguous")

    # 36. Finding 1: reconciliation ignores receipt with mismatched GitHub App ID
    def test_36_reconciliation_ignores_receipt_with_wrong_app_id(self) -> None:
        event = make_event(request_id="wrong-app-reconcile-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        claim = self.coordinator.claim(acceptance.request_id, "run-wrong-app")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-wrong-app")

        _, record = self.coordinator.load_record("wrong-app-reconcile-01")
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "wrong-app-reconcile-01",
            "request_digest": record["request_digest"],
            "operation": "github.ci.inspect",
            "accepted_revision": acceptance.durable_revision,
            "claim_revision": claim.durable_revision,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {},
        }
        comment_body = ActionsRequestHandler._format_receipt_comment(envelope)
        repo = TRUSTED_POLICY.repository_full_name
        self.api.comments[1] = {
            "id": 1,
            "body": comment_body,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-1",
            "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
            "performed_via_github_app": {"id": 11111},  # Untrusted App ID
        }

        receipt = self.handler.reconcile_request("wrong-app-reconcile-01")
        self.assertFalse(receipt.reconciled)
        self.assertEqual(receipt.terminal_state, "ambiguous")
        self.assertEqual(receipt.terminal_code, "reconciliation_required")
        _, record = self.coordinator.load_record("wrong-app-reconcile-01")
        self.assertEqual(record["state"], "ambiguous")

    # 37. Finding 1: authentic receipt succeeds even when human spoof comment is present
    def test_37_trusted_app_receipt_succeeds_even_with_human_spoof_present(self) -> None:
        event = make_event(request_id="spoof-and-authentic-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        claim = self.coordinator.claim(acceptance.request_id, "run-legit")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-legit")

        _, record = self.coordinator.load_record("spoof-and-authentic-01")
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "spoof-and-authentic-01",
            "request_digest": record["request_digest"],
            "operation": "github.ci.inspect",
            "accepted_revision": acceptance.durable_revision,
            "claim_revision": claim.durable_revision,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {"run_id": 33958090021},
        }
        comment_body = ActionsRequestHandler._format_receipt_comment(envelope)
        repo = TRUSTED_POLICY.repository_full_name

        # Comment 1 is spoofed by a human
        self.api.comments[1] = {
            "id": 1,
            "body": comment_body,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-1",
            "user": {"id": 2001, "type": "User"},
        }
        # Comment 2 is authentic from the bot and App
        self.api.comments[2] = {
            "id": 2,
            "body": comment_body,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-2",
            "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
            "performed_via_github_app": {"id": TRUSTED_RECEIPT_POLICY.app_id},
        }

        receipt = self.handler.reconcile_request("spoof-and-authentic-01")
        self.assertTrue(receipt.reconciled)
        self.assertEqual(receipt.terminal_state, "succeeded")
        self.assertEqual(receipt.terminal_code, "found")
        self.assertEqual(
            receipt.terminal_reference,
            f"https://github.com/{repo}/issues/42#issuecomment-2",
        )

    # 38. Finding 2: concurrent execution does not mutate executing journal
    def test_38_concurrent_execution_does_not_mutate_executing_journal(self) -> None:
        event = make_event(request_id="concurrent-exec-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        self.coordinator.claim(acceptance.request_id, "worker-1")

        # Worker 1 is actively executing. Zero comments on issue.
        self.assertEqual(len(self.api.comments), 0)

        # Worker 2 arrives with the same event
        receipt2 = self.handler.handle_request(event, "worker-2", ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(receipt2.terminal_state, "executing")
        self.assertEqual(receipt2.terminal_code, "reconciliation_required")
        self.assertFalse(receipt2.replayed)
        self.assertFalse(receipt2.reconciled)

        # Verify journal remains executing under worker-1
        _, record = self.coordinator.load_record("concurrent-exec-01")
        self.assertEqual(record["state"], "executing")
        self.assertEqual(record["execution_id"], "worker-1")

        # Verify Worker 2 did NOT perform CI calls or comment POST
        ci_calls = [call for call in self.api.calls if "actions/workflows" in call[1]]
        self.assertEqual(len(ci_calls), 0)
        self.assertEqual(len(self.api.comments), 0)

        # Now Worker 1 completes cleanly
        mutation = self.coordinator.complete(
            request_id="concurrent-exec-01",
            execution_id="worker-1",
            state="succeeded",
            terminal_code="found",
            terminal_reference="https://github.com/shockerqt/zach/issues/42#issuecomment-10",
        )
        self.assertIsNotNone(mutation.durable_revision)
        _, final_record = self.coordinator.load_record("concurrent-exec-01")
        self.assertEqual(final_record["state"], "succeeded")

    # 39. Finding 2: receipt appearing while owner executing does not permit takeover
    def test_39_receipt_appearing_while_owner_executing_does_not_permit_takeover(self) -> None:
        event = make_event(request_id="no-takeover-exec-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        claim = self.coordinator.claim(acceptance.request_id, "worker-original")

        # Authentic comment is placed in comments (e.g. out of band or early)
        _, record = self.coordinator.load_record("no-takeover-exec-01")
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "no-takeover-exec-01",
            "request_digest": record["request_digest"],
            "operation": "github.ci.inspect",
            "accepted_revision": acceptance.durable_revision,
            "claim_revision": claim.durable_revision,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {},
        }
        comment_body = ActionsRequestHandler._format_receipt_comment(envelope)
        repo = TRUSTED_POLICY.repository_full_name
        self.api.comments[1] = {
            "id": 1,
            "body": comment_body,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-1",
            "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
            "performed_via_github_app": {"id": TRUSTED_RECEIPT_POLICY.app_id},
        }

        # Worker 2 cannot take over or reconcile while worker-original is still executing
        receipt2 = self.handler.handle_request(event, "worker-takeover", ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(receipt2.terminal_state, "executing")
        self.assertEqual(receipt2.terminal_code, "reconciliation_required")

        # Journal is still executing under worker-original
        _, record = self.coordinator.load_record("no-takeover-exec-01")
        self.assertEqual(record["state"], "executing")
        self.assertEqual(record["execution_id"], "worker-original")

    # 40. Finding 2: explicit foreign execution ID on executing request is rejected
    def test_40_explicit_foreign_execution_id_on_executing_request_is_rejected(self) -> None:
        event = make_event(request_id="foreign-owner-exec-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        self.coordinator.claim(acceptance.request_id, "worker-real")

        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.reconcile_request("foreign-owner-exec-01", execution_id="worker-imposter")
        self.assertEqual(ctx.exception.code, "execution_owner_mismatch")

    # 41. Finding 2: reconcile already ambiguous request with zero comments leaves journal ambiguous
    def test_41_reconcile_already_ambiguous_request_with_zero_comments_leaves_ambiguous(self) -> None:
        event = make_event(request_id="ambiguous-zero-comments-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        self.coordinator.claim(acceptance.request_id, "worker-1")
        self.coordinator.mark_ambiguous(acceptance.request_id, "worker-1")

        receipt = self.handler.reconcile_request("ambiguous-zero-comments-01")
        self.assertFalse(receipt.reconciled)
        self.assertEqual(receipt.terminal_state, "ambiguous")
        self.assertEqual(receipt.terminal_code, "reconciliation_required")

        _, record = self.coordinator.load_record("ambiguous-zero-comments-01")
        self.assertEqual(record["state"], "ambiguous")
        self.assertIsNone(record.get("terminal_code"))

    # 42. Finding 2: reconcile already ambiguous request with authentic receipt succeeds
    def test_42_reconcile_already_ambiguous_request_with_authentic_receipt_succeeds(self) -> None:
        event = make_event(request_id="ambiguous-authentic-receipt-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        claim = self.coordinator.claim(acceptance.request_id, "worker-1")
        self.coordinator.mark_ambiguous(acceptance.request_id, "worker-1")

        _, record = self.coordinator.load_record("ambiguous-authentic-receipt-01")
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "ambiguous-authentic-receipt-01",
            "request_digest": record["request_digest"],
            "operation": "github.ci.inspect",
            "accepted_revision": acceptance.durable_revision,
            "claim_revision": claim.durable_revision,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {"run_id": 12345},
        }
        comment_body = ActionsRequestHandler._format_receipt_comment(envelope)
        repo = TRUSTED_POLICY.repository_full_name
        self.api.comments[1] = {
            "id": 1,
            "body": comment_body,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-1",
            "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
            "performed_via_github_app": {"id": TRUSTED_RECEIPT_POLICY.app_id},
        }

        receipt = self.handler.reconcile_request("ambiguous-authentic-receipt-01")
        self.assertTrue(receipt.reconciled)
        self.assertEqual(receipt.terminal_state, "succeeded")
        self.assertEqual(receipt.terminal_code, "found")

    # 43. Finding 3: receipt parsing rejects prefix text before marker
    def test_43_receipt_parsing_rejects_prefix_text(self) -> None:
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "canon-prefix-01",
            "request_digest": "a" * 64,
            "operation": "github.ci.inspect",
            "accepted_revision": "1" * 40,
            "claim_revision": "2" * 40,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {},
        }
        canonical = ActionsRequestHandler._format_receipt_comment(envelope)
        corrupted = "Surrounding human note\n" + canonical

        with self.assertRaises(ActionsHandlerError) as ctx:
            ActionsRequestHandler._parse_receipt_comment(corrupted, "canon-prefix-01", "a" * 64, "github.ci.inspect")
        self.assertEqual(ctx.exception.code, "receipt_canonical_body_mismatch")

    # 44. Finding 3: receipt parsing rejects suffix text after closing fence
    def test_44_receipt_parsing_rejects_suffix_text(self) -> None:
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "canon-suffix-01",
            "request_digest": "a" * 64,
            "operation": "github.ci.inspect",
            "accepted_revision": "1" * 40,
            "claim_revision": "2" * 40,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {},
        }
        canonical = ActionsRequestHandler._format_receipt_comment(envelope)
        corrupted = canonical + "Trailing human signature\n"

        with self.assertRaises(ActionsHandlerError) as ctx:
            ActionsRequestHandler._parse_receipt_comment(corrupted, "canon-suffix-01", "a" * 64, "github.ci.inspect")
        self.assertEqual(ctx.exception.code, "receipt_canonical_body_mismatch")

    # 45. Finding 3: receipt parsing rejects duplicate markers
    def test_45_receipt_parsing_rejects_duplicate_markers(self) -> None:
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "canon-dup-marker-01",
            "request_digest": "a" * 64,
            "operation": "github.ci.inspect",
            "accepted_revision": "1" * 40,
            "claim_revision": "2" * 40,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {},
        }
        canonical = ActionsRequestHandler._format_receipt_comment(envelope)
        corrupted = canonical + canonical

        with self.assertRaises(ActionsHandlerError) as ctx:
            ActionsRequestHandler._parse_receipt_comment(corrupted, "canon-dup-marker-01", "a" * 64, "github.ci.inspect")
        self.assertEqual(ctx.exception.code, "receipt_canonical_body_mismatch")

    # 46. Finding 3: receipt parsing rejects extra fenced code blocks
    def test_46_receipt_parsing_rejects_extra_fenced_blocks(self) -> None:
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "canon-extra-fence-01",
            "request_digest": "a" * 64,
            "operation": "github.ci.inspect",
            "accepted_revision": "1" * 40,
            "claim_revision": "2" * 40,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {},
        }
        canonical = ActionsRequestHandler._format_receipt_comment(envelope)
        corrupted = canonical + "```json\n{\"extra\": 1}\n```\n"

        with self.assertRaises(ActionsHandlerError) as ctx:
            ActionsRequestHandler._parse_receipt_comment(corrupted, "canon-extra-fence-01", "a" * 64, "github.ci.inspect")
        self.assertEqual(ctx.exception.code, "receipt_canonical_body_mismatch")

    # 47. Finding 3: receipt parsing rejects non-canonical JSON formatting
    def test_47_receipt_parsing_rejects_non_canonical_json_formatting(self) -> None:
        marker = (
            "<!-- zach-actions:receipt:v1:request_id=canon-format-01:"
            "digest=" + "a" * 64 + ":op=github.ci.inspect:"
            "accepted_revision=" + "1" * 40 + ":claim_revision=" + "2" * 40 + " -->"
        )
        compact_json = '{"accepted_revision":"' + "1"*40 + '","claim_revision":"' + "2"*40 + '","kind":"actions.request.receipt","operation":"github.ci.inspect","request_digest":"' + "a"*64 + '","request_id":"canon-format-01","result":{},"schema_version":1,"terminal_code":"found","terminal_state":"succeeded"}'
        non_canonical = f"{marker}\n```json\n{compact_json}\n```\n"

        with self.assertRaises(ActionsHandlerError) as ctx:
            ActionsRequestHandler._parse_receipt_comment(non_canonical, "canon-format-01", "a" * 64, "github.ci.inspect")
        self.assertEqual(ctx.exception.code, "receipt_canonical_body_mismatch")

    # 48. Finding 3: receipt parsing enforces both accepted_revision and claim_revision
    def test_48_receipt_parsing_enforces_both_accepted_and_claim_revisions(self) -> None:
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "rev-bind-01",
            "request_digest": "a" * 64,
            "operation": "github.ci.inspect",
            "accepted_revision": "1" * 40,
            "claim_revision": "2" * 40,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {},
        }
        canonical = ActionsRequestHandler._format_receipt_comment(envelope)

        # Parsing matches expected
        parsed = ActionsRequestHandler._parse_receipt_comment(canonical, "rev-bind-01", "a" * 64, "github.ci.inspect")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["accepted_revision"], "1" * 40)
        self.assertEqual(parsed["claim_revision"], "2" * 40)

        # Mismatch in claim_revision
        tampered_envelope = dict(envelope)
        tampered_envelope["claim_revision"] = "3" * 40
        tampered_json = json.dumps(tampered_envelope, indent=2, sort_keys=True)
        marker = (
            "<!-- zach-actions:receipt:v1:request_id=rev-bind-01:"
            "digest=" + "a" * 64 + ":op=github.ci.inspect:"
            "accepted_revision=" + "1" * 40 + ":claim_revision=" + "2" * 40 + " -->"
        )
        tampered_body = f"{marker}\n```json\n{tampered_json}\n```\n"
        with self.assertRaises(ActionsHandlerError) as ctx:
            ActionsRequestHandler._parse_receipt_comment(tampered_body, "rev-bind-01", "a" * 64, "github.ci.inspect")
        self.assertEqual(ctx.exception.code, "receipt_revision_mismatch")

    # 49. Finding 3: validate_comment_identity strictly checks all identity fields
    def test_49_validate_comment_identity_requires_all_canonical_fields(self) -> None:
        repo = "shockerqt/zach"
        issue_no = 42
        valid_comment = {
            "id": 100,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/{issue_no}",
            "html_url": f"https://github.com/{repo}/issues/{issue_no}#issuecomment-100",
            "body": "exact body",
            "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
            "performed_via_github_app": {"id": TRUSTED_RECEIPT_POLICY.app_id},
        }

        # Valid comment passes
        cid = self.handler.validate_comment_identity(valid_comment, repo, issue_no, "exact body")
        self.assertEqual(cid, 100)

        # Not a dict
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.validate_comment_identity("not-dict", repo, issue_no)
        self.assertEqual(ctx.exception.code, "comment_identity_mismatch")

        # Invalid comment ID
        bad = dict(valid_comment, id=-1)
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.validate_comment_identity(bad, repo, issue_no)
        self.assertEqual(ctx.exception.code, "comment_identity_mismatch")

        # User missing
        bad = dict(valid_comment)
        del bad["user"]
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.validate_comment_identity(bad, repo, issue_no)
        self.assertEqual(ctx.exception.code, "comment_authorship_missing")

        # User ID mismatch
        bad = dict(valid_comment, user={"id": 99999, "type": "Bot"})
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.validate_comment_identity(bad, repo, issue_no)
        self.assertEqual(ctx.exception.code, "comment_bot_id_mismatch")

        # User type not Bot
        bad = dict(valid_comment, user={"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "User"})
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.validate_comment_identity(bad, repo, issue_no)
        self.assertEqual(ctx.exception.code, "comment_user_not_bot")

        # App missing
        bad = dict(valid_comment)
        del bad["performed_via_github_app"]
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.validate_comment_identity(bad, repo, issue_no)
        self.assertEqual(ctx.exception.code, "comment_app_metadata_missing")

        # App ID mismatch
        bad = dict(valid_comment, performed_via_github_app={"id": 11111})
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.validate_comment_identity(bad, repo, issue_no)
        self.assertEqual(ctx.exception.code, "comment_app_id_mismatch")

        # Issue URL mismatch
        bad = dict(valid_comment, issue_url="https://api.github.com/repos/shockerqt/zach/issues/999")
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.validate_comment_identity(bad, repo, issue_no)
        self.assertEqual(ctx.exception.code, "comment_issue_url_mismatch")

        # Html URL mismatch
        bad = dict(valid_comment, html_url="https://github.com/shockerqt/zach/issues/999#issuecomment-100")
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.validate_comment_identity(bad, repo, issue_no)
        self.assertEqual(ctx.exception.code, "comment_html_url_mismatch")

        # Body mismatch
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.validate_comment_identity(valid_comment, repo, issue_no, "different body")
        self.assertEqual(ctx.exception.code, "comment_body_mismatch")

    # 50. Finding 3: reconciliation fails closed when comment page observation is unstable
    def test_50_reconciliation_observation_unstable_fails_closed(self) -> None:
        event = make_event(request_id="unstable-obs-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        self.coordinator.claim(acceptance.request_id, "run-unstable")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-unstable")

        self.api.comment_page_changes_on_second_call = True
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.reconcile_request("unstable-obs-01")
        self.assertEqual(ctx.exception.code, "reconciliation_observation_unstable")

    # 51. TrustedReceiptPolicy numeric validation
    def test_51_trusted_receipt_policy_numeric_validation(self) -> None:
        with self.assertRaises(ValueError):
            TrustedReceiptPolicy(app_id=0, bot_user_id=100)
        with self.assertRaises(ValueError):
            TrustedReceiptPolicy(app_id=100, bot_user_id=0)
        with self.assertRaises(ValueError):
            TrustedReceiptPolicy(app_id=2**54, bot_user_id=100)
        with self.assertRaises(ValueError):
            TrustedReceiptPolicy(app_id="100", bot_user_id=100)  # type: ignore[arg-type]

    # 52. 101+ comments, stable receipt on second page succeeds
    def test_52_stable_receipt_on_second_page_with_101_plus_comments_succeeds(self) -> None:
        event = make_event(request_id="page2-receipt-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        claim = self.coordinator.claim(acceptance.request_id, "run-p2")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-p2")

        repo = TRUSTED_POLICY.repository_full_name
        # Add 100 dummy comments for page 1
        for cid in range(1, 101):
            self.api.comments[cid] = {
                "id": cid,
                "body": f"Human discussion comment #{cid}",
                "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
                "html_url": f"https://github.com/{repo}/issues/42#issuecomment-{cid}",
                "user": {"id": 2001, "type": "User"},
            }

        # Add authentic receipt on page 2 (comment ID 101)
        _, record = self.coordinator.load_record("page2-receipt-01")
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "page2-receipt-01",
            "request_digest": record["request_digest"],
            "operation": "github.ci.inspect",
            "accepted_revision": acceptance.durable_revision,
            "claim_revision": claim.durable_revision,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {"run_id": 33958090021},
        }
        comment_body = ActionsRequestHandler._format_receipt_comment(envelope)
        self.api.comments[101] = {
            "id": 101,
            "body": comment_body,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-101",
            "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
            "performed_via_github_app": {"id": TRUSTED_RECEIPT_POLICY.app_id},
        }

        receipt = self.handler.reconcile_request("page2-receipt-01")
        self.assertTrue(receipt.reconciled)
        self.assertEqual(receipt.terminal_state, "succeeded")
        self.assertEqual(receipt.terminal_code, "found")
        self.assertEqual(
            receipt.terminal_reference,
            f"https://github.com/{repo}/issues/42#issuecomment-101",
        )
        _, record = self.coordinator.load_record("page2-receipt-01")
        self.assertEqual(record["state"], "succeeded")

    # 53. page 1 unchanged but page 2 changes between scans => fail closed
    def test_53_page_1_unchanged_but_page_2_changes_fails_closed(self) -> None:
        event = make_event(request_id="p2-unstable-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        claim = self.coordinator.claim(acceptance.request_id, "run-p2-unstable")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-p2-unstable")

        repo = TRUSTED_POLICY.repository_full_name
        for cid in range(1, 101):
            self.api.comments[cid] = {
                "id": cid,
                "body": f"Human discussion comment #{cid}",
                "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
                "html_url": f"https://github.com/{repo}/issues/42#issuecomment-{cid}",
                "user": {"id": 2001, "type": "User"},
            }
        self.api.comments[101] = {
            "id": 101,
            "body": "Page 2 original comment",
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-101",
            "user": {"id": 2001, "type": "User"},
        }

        def on_get(page: int, call_count: int) -> None:
            if call_count == 3:  # start of scan 2 (page 1)
                self.api.comments[101]["body"] = "Page 2 mutated comment"

        self.api.on_comments_get = on_get

        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.reconcile_request("p2-unstable-01")
        self.assertEqual(ctx.exception.code, "reconciliation_observation_unstable")

    # 54. second matching trusted receipt appears on later page between scans => fail closed
    def test_54_second_matching_receipt_appears_on_later_page_between_scans_fails_closed(self) -> None:
        event = make_event(request_id="dup-race-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        claim = self.coordinator.claim(acceptance.request_id, "run-dup-race")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-dup-race")

        repo = TRUSTED_POLICY.repository_full_name
        _, record = self.coordinator.load_record("dup-race-01")
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "dup-race-01",
            "request_digest": record["request_digest"],
            "operation": "github.ci.inspect",
            "accepted_revision": acceptance.durable_revision,
            "claim_revision": claim.durable_revision,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {},
        }
        comment_body = ActionsRequestHandler._format_receipt_comment(envelope)

        # Receipt 1 is on page 1
        self.api.comments[1] = {
            "id": 1,
            "body": comment_body,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-1",
            "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
            "performed_via_github_app": {"id": TRUSTED_RECEIPT_POLICY.app_id},
        }
        # Fill page 1 with 99 more dummy comments
        for cid in range(2, 101):
            self.api.comments[cid] = {
                "id": cid,
                "body": f"Human discussion comment #{cid}",
                "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
                "html_url": f"https://github.com/{repo}/issues/42#issuecomment-{cid}",
                "user": {"id": 2001, "type": "User"},
            }

        def on_get(page: int, call_count: int) -> None:
            if call_count == 3:  # At start of scan 2 (page 1), add second receipt to page 2
                self.api.comments[101] = {
                    "id": 101,
                    "body": comment_body,
                    "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
                    "html_url": f"https://github.com/{repo}/issues/42#issuecomment-101",
                    "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
                    "performed_via_github_app": {"id": TRUSTED_RECEIPT_POLICY.app_id},
                }

        self.api.on_comments_get = on_get

        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.reconcile_request("dup-race-01")
        self.assertEqual(ctx.exception.code, "reconciliation_observation_unstable")

    # 55. duplicate comment IDs across pagination fails closed
    def test_55_duplicate_comment_ids_across_pagination_fails_closed(self) -> None:
        event = make_event(request_id="dup-id-pagination-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        self.coordinator.claim(acceptance.request_id, "run-dup-id")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-dup-id")

        repo = TRUSTED_POLICY.repository_full_name
        for cid in range(1, 101):
            self.api.comments[cid] = {
                "id": cid,
                "body": f"Comment #{cid}",
                "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
                "html_url": f"https://github.com/{repo}/issues/42#issuecomment-{cid}",
                "user": {"id": 2001, "type": "User"},
            }
        self.api.duplicate_comment_ids_in_pagination = True

        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.reconcile_request("dup-id-pagination-01")
        self.assertEqual(ctx.exception.code, "reconciliation_duplicate_comment_ids")

    # 56. zero trusted receipts on ambiguous request leaves journal ambiguous
    def test_56_zero_trusted_receipts_leaves_journal_ambiguous(self) -> None:
        event = make_event(request_id="zero-receipts-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        self.coordinator.claim(acceptance.request_id, "run-zero")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-zero")

        self.assertEqual(len(self.api.comments), 0)
        receipt = self.handler.reconcile_request("zero-receipts-01")
        self.assertFalse(receipt.reconciled)
        self.assertEqual(receipt.terminal_state, "ambiguous")
        self.assertEqual(receipt.terminal_code, "reconciliation_required")

        _, record = self.coordinator.load_record("zero-receipts-01")
        self.assertEqual(record["state"], "ambiguous")

    # 57. zero trusted receipts causes no journal terminal mutation
    def test_57_zero_trusted_receipts_causes_no_journal_terminal_mutation(self) -> None:
        event = make_event(request_id="no-terminal-mutation-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        self.coordinator.claim(acceptance.request_id, "run-no-term")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-no-term")

        ref_before = self.api.refs[FIXED_REF]
        patch_calls_before = [c for c in self.api.calls if c[0] == "PATCH"]

        receipt = self.handler.reconcile_request("no-terminal-mutation-01")
        self.assertEqual(receipt.terminal_state, "ambiguous")

        ref_after = self.api.refs[FIXED_REF]
        patch_calls_after = [c for c in self.api.calls if c[0] == "PATCH"]

        self.assertEqual(ref_before, ref_after)
        self.assertEqual(len(patch_calls_before), len(patch_calls_after))

        _, record = self.coordinator.load_record("no-terminal-mutation-01")
        self.assertEqual(record["state"], "ambiguous")
        self.assertIsNone(record.get("terminal_code"))
        self.assertIsNone(record.get("terminal_reference"))

    # 58. zero trusted receipts causes no effect execution
    def test_58_zero_trusted_receipts_causes_no_effect_execution(self) -> None:
        event = make_event(request_id="no-effect-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        self.coordinator.claim(acceptance.request_id, "run-no-effect")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-no-effect")

        ci_calls_before = [c for c in self.api.calls if "actions/workflows" in c[1]]
        self.handler.reconcile_request("no-effect-01")
        ci_calls_after = [c for c in self.api.calls if "actions/workflows" in c[1]]

        self.assertEqual(len(ci_calls_before), len(ci_calls_after))

    # 59. zero trusted receipts causes no comment POST
    def test_59_zero_trusted_receipts_causes_no_comment_post(self) -> None:
        event = make_event(request_id="no-post-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        self.coordinator.claim(acceptance.request_id, "run-no-post")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-no-post")

        post_calls_before = [c for c in self.api.calls if c[0] == "POST" and "comments" in c[1]]
        self.handler.reconcile_request("no-post-01")
        post_calls_after = [c for c in self.api.calls if c[0] == "POST" and "comments" in c[1]]

        self.assertEqual(len(post_calls_before), len(post_calls_after))
        self.assertEqual(len(self.api.comments), 0)

    # 60. later reconciliation can succeed if a trusted receipt appears after earlier zero-match observation
    def test_60_later_reconciliation_succeeds_after_earlier_zero_match_observation(self) -> None:
        event = make_event(request_id="delayed-receipt-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        claim = self.coordinator.claim(acceptance.request_id, "run-delayed")
        self.coordinator.mark_ambiguous(acceptance.request_id, "run-delayed")

        # 1. First observation: 0 matching receipts -> stays ambiguous
        receipt1 = self.handler.reconcile_request("delayed-receipt-01")
        self.assertFalse(receipt1.replayed)
        self.assertFalse(receipt1.reconciled)
        self.assertEqual(receipt1.terminal_state, "ambiguous")
        self.assertEqual(receipt1.terminal_code, "reconciliation_required")

        _, record = self.coordinator.load_record("delayed-receipt-01")
        self.assertEqual(record["state"], "ambiguous")

        # 2. Delayed receipt arrives on GitHub
        repo = TRUSTED_POLICY.repository_full_name
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "delayed-receipt-01",
            "request_digest": record["request_digest"],
            "operation": "github.ci.inspect",
            "accepted_revision": acceptance.durable_revision,
            "claim_revision": claim.durable_revision,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {"run_id": 33958090021},
        }
        comment_body = ActionsRequestHandler._format_receipt_comment(envelope)
        self.api.comments[1] = {
            "id": 1,
            "body": comment_body,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-1",
            "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
            "performed_via_github_app": {"id": TRUSTED_RECEIPT_POLICY.app_id},
        }

        # 3. Second reconciliation: finds trusted receipt and successfully reconciles
        receipt2 = self.handler.reconcile_request("delayed-receipt-01")
        self.assertTrue(receipt2.reconciled)
        self.assertEqual(receipt2.terminal_state, "succeeded")
        self.assertEqual(receipt2.terminal_code, "found")
        self.assertEqual(
            receipt2.terminal_reference,
            f"https://github.com/{repo}/issues/42#issuecomment-1",
        )

        _, final_record = self.coordinator.load_record("delayed-receipt-01")
        self.assertEqual(final_record["state"], "succeeded")
        self.assertEqual(final_record["terminal_code"], "found")

    # 61. executing owner protections remain authoritative
    def test_61_executing_owner_protections_remain_authoritative(self) -> None:
        event = make_event(request_id="exec-owner-auth-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        self.coordinator.claim(acceptance.request_id, "owner-real")

        # Concurrent worker arrives via handle_request
        receipt = self.handler.handle_request(event, "owner-imposter", ACCEPTED_AT, POLICY_REVISION)
        self.assertFalse(receipt.replayed)
        self.assertFalse(receipt.reconciled)
        self.assertEqual(receipt.terminal_state, "executing")
        self.assertEqual(receipt.terminal_code, "reconciliation_required")

        # Foreign execution ID explicitly reconciling raises execution_owner_mismatch
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.handler.reconcile_request("exec-owner-auth-01", execution_id="owner-imposter")
        self.assertEqual(ctx.exception.code, "execution_owner_mismatch")

        # Journal is still executing under owner-real
        _, record = self.coordinator.load_record("exec-owner-auth-01")
        self.assertEqual(record["state"], "executing")
        self.assertEqual(record["execution_id"], "owner-real")


class PublisherTransportAdapter:
    """Restricted transport providing Publisher authority only.

    Allowed:
      - Git journal endpoints on shockerqt/workspace-governance
      - GET /repos/{repo}/issues/{number}/comments
    Forbidden:
      - POST to issue comments (requires Control authority)
      - CI inspection endpoints (requires Control authority)
    """

    def __init__(self, backend: UnifiedFakeApi) -> None:
        self._backend = backend

    def __call__(self, method: str, path: str, body: Any = None) -> Any:
        if method == "POST" and "comments" in path:
            raise PermissionError("Publisher authority cannot post comments")
        if "actions/workflows" in path or "actions/runs" in path:
            raise PermissionError("Publisher authority cannot access CI")
        return self._backend.request(method, path, body)


class ControlTransportAdapter:
    """Restricted transport providing Control authority only.

    Allowed:
      - CI inspection endpoints
      - POST /repos/{repo}/issues/{number}/comments
      - GET /repos/{repo}/issues/comments/{id}
    Forbidden:
      - Git journal endpoints on shockerqt/workspace-governance
    """

    def __init__(self, backend: UnifiedFakeApi) -> None:
        self._backend = backend

    def __call__(self, method: str, path: str, body: Any = None) -> Any:
        if FIXED_REPOSITORY in path or "automation/requests" in path:
            raise PermissionError("Control authority cannot access Git journal")
        return self._backend.request(method, path, body)


class SeparatedAuthorityPhasesTests(unittest.TestCase):
    """Rigorous tests for the separation of Publisher and Control authorities."""

    def setUp(self) -> None:
        self.api = UnifiedFakeApi()
        self.publisher_api = PublisherTransportAdapter(self.api)
        self.control_api = ControlTransportAdapter(self.api)

        # Coordinator uses Publisher authority (journal persistence)
        self.coordinator = ActionsJournalCoordinator(
            cli_executable=CLI,
            api_transport=self.publisher_api,
        )

        # PublisherPhase uses ONLY Publisher authority
        self.publisher = PublisherPhase(
            coordinator=self.coordinator,
            trusted_issue_policy=TRUSTED_POLICY,
            trusted_receipt_policy=TRUSTED_RECEIPT_POLICY,
            read_api_transport=self.publisher_api,
        )

        # ControlPhase uses ONLY Control authority (no coordinator!)
        self.control = ControlPhase(
            api_transport=self.control_api,
            trusted_receipt_policy=TRUSTED_RECEIPT_POLICY,
            ci_policy=CI_POLICY,
        )

        # ActionsRequestHandler composing both with separated transports
        self.handler = ActionsRequestHandler(
            coordinator=self.coordinator,
            api_transport=self.api,
            trusted_issue_policy=TRUSTED_POLICY,
            trusted_receipt_policy=TRUSTED_RECEIPT_POLICY,
            ci_policy=CI_POLICY,
            publisher_api_transport=self.publisher_api,
            control_api_transport=self.control_api,
        )

    def test_control_rejects_parameters_and_numeric_identity_tampering(self) -> None:
        prep = self.publisher.prepare(make_event(request_id="binding-check-01"), "exec-binding", ACCEPTED_AT, POLICY_REVISION)
        bundle = prep.bundle
        assert bundle is not None
        calls = len(self.api.calls)
        for altered in (
            replace(bundle, parameters={"repository": "ui-design-sandbox", "source_sha": "9" * 40}),
            replace(bundle, repository_id=bundle.repository_id + 1),
            replace(bundle, issue_id=bundle.issue_id + 1),
        ):
            with self.assertRaisesRegex(ActionsHandlerError, "invalid_execution_bundle"):
                self.control.execute(altered)
        self.assertEqual(len(self.api.calls), calls)

    def test_finalize_rejects_invented_journal_revisions(self) -> None:
        prep = self.publisher.prepare(make_event(request_id="revision-check-01"), "exec-revision", ACCEPTED_AT, POLICY_REVISION)
        assert prep.bundle is not None
        altered = replace(prep.bundle, accepted_revision="0" * 40, claim_revision="1" * 40)
        with self.assertRaisesRegex(ActionsHandlerError, "bundle_revision_mismatch"):
            self.publisher.finalize(altered)
        _, record = self.coordinator.load_record(prep.request_id)
        self.assertEqual(record["state"], "executing")

    def test_finalize_rejects_matching_off_branch_claim(self) -> None:
        prep = self.publisher.prepare(make_event(request_id="offbranch-claim-01"), "exec-branch", ACCEPTED_AT, POLICY_REVISION)
        assert prep.bundle is not None
        original = self.api.commits[prep.bundle.claim_revision]
        detached = "f" * 40
        self.api.commits[detached] = dict(original, sha=detached)
        # Equal bytes exist, but this detached commit never became the journal ref.
        altered = replace(prep.bundle, claim_revision=detached)
        with self.assertRaisesRegex(ActionsHandlerError, "bundle_revision_mismatch"):
            self.publisher.finalize(altered)

    def test_reconciliation_rejects_receipt_with_invented_revisions(self) -> None:
        prep = self.publisher.prepare(make_event(request_id="reconcile-revision-01"), "exec-revision", ACCEPTED_AT, POLICY_REVISION)
        assert prep.bundle is not None
        altered = replace(prep.bundle, accepted_revision="0" * 40, claim_revision="1" * 40)
        self.control.execute(altered)
        self.coordinator.mark_ambiguous(prep.request_id, altered.execution_id)
        with self.assertRaisesRegex(ActionsHandlerError, "bundle_revision_mismatch"):
            self.publisher.reconcile_request(prep.request_id)
        _, record = self.coordinator.load_record(prep.request_id)
        self.assertEqual(record["state"], "ambiguous")

    def test_finalize_original_bundle_after_control_handoff_interruption(self) -> None:
        prep = self.publisher.prepare(make_event(request_id="handoff-recover-01"), "original-owner", ACCEPTED_AT, POLICY_REVISION)
        assert prep.bundle is not None
        self.control.execute(prep.bundle)
        # Phase C did not run. Reload the durable transfer artifact in a new process.
        recovered = ExecutionBundle.from_json(prep.bundle.to_json())
        resumed = PublisherPhase(self.coordinator, TRUSTED_POLICY, TRUSTED_RECEIPT_POLICY, self.publisher_api)
        result = resumed.finalize(recovered)
        self.assertEqual(result.terminal_state, "succeeded")
        self.assertEqual(len(self.api.comments), 1)
        self.assertTrue(resumed.finalize(recovered).replayed)

    def test_finalize_binds_bundle_to_durable_request_before_observation(self) -> None:
        prep = self.publisher.prepare(make_event(request_id="durable-binding-01"), "exec-binding", ACCEPTED_AT, POLICY_REVISION)
        bundle = prep.bundle
        assert bundle is not None
        frozen = json.loads(bundle.canonical_record)
        frozen["issue_number"] = 999
        altered = replace(bundle, issue_number=999, canonical_record=json.dumps(frozen))
        with self.assertRaisesRegex(ActionsHandlerError, "bundle_journal_mismatch"):
            self.publisher.finalize(altered)
        _, record = self.coordinator.load_record(bundle.request_id)
        self.assertEqual(record["state"], "executing")

    # 1. Publisher prepare produce un frozen claimed execution con revisions reales.
    def test_01_publisher_prepare_produces_frozen_claimed_execution_with_real_revisions(self) -> None:
        event = make_event(request_id="sep-prep-01")
        prep = self.publisher.prepare(event, "exec-01", ACCEPTED_AT, POLICY_REVISION)

        self.assertEqual(prep.disposition, ClaimDisposition.GRANTED)
        self.assertIsNotNone(prep.bundle)
        bundle = prep.bundle
        self.assertEqual(bundle.request_id, "sep-prep-01")
        self.assertEqual(bundle.operation, "github.ci.inspect")
        self.assertEqual(bundle.execution_id, "exec-01")
        self.assertTrue(bool(SHA40_RE.fullmatch(bundle.accepted_revision)))
        self.assertTrue(bool(SHA40_RE.fullmatch(bundle.claim_revision)))
        self.assertNotEqual(bundle.accepted_revision, bundle.claim_revision)

        record = parse_and_validate_record(bundle.canonical_record, "sep-prep-01")
        self.assertEqual(record["state"], "executing")
        self.assertEqual(record["execution_id"], "exec-01")

        self.assertEqual(len(self.api.comments), 0)
        ci_calls = [c for c in self.api.calls if "actions/workflows" in c[1]]
        self.assertEqual(len(ci_calls), 0)

    # 2. Control execute funciona sin journal/Publisher transport.
    def test_02_control_execute_works_without_journal_or_publisher_transport(self) -> None:
        event = make_event(request_id="sep-ctrl-01")
        prep = self.publisher.prepare(event, "exec-02", ACCEPTED_AT, POLICY_REVISION)
        assert prep.bundle is not None

        ctrl_res = self.control.execute(prep.bundle)
        self.assertFalse(ctrl_res.ambiguous)
        self.assertEqual(ctrl_res.terminal_state, "succeeded")
        self.assertEqual(ctrl_res.terminal_code, "found")
        self.assertIsNotNone(ctrl_res.terminal_reference)
        self.assertIn("issues/42#issuecomment-", ctrl_res.terminal_reference)
        self.assertIsNotNone(ctrl_res.envelope)
        self.assertEqual(ctrl_res.envelope["accepted_revision"], prep.bundle.accepted_revision)
        self.assertEqual(ctrl_res.envelope["claim_revision"], prep.bundle.claim_revision)

        comment_id = int(ctrl_res.terminal_reference.rsplit("-", 1)[-1])
        self.assertIn(comment_id, self.api.comments)
        comment = self.api.comments[comment_id]
        self.assertIn(f"accepted_revision={prep.bundle.accepted_revision}", comment["body"])
        self.assertIn(f"claim_revision={prep.bundle.claim_revision}", comment["body"])

    # 3. Control execute no puede realizar mutaciones de journal.
    def test_03_control_execute_cannot_perform_journal_mutations(self) -> None:
        event = make_event(request_id="sep-nomut-01")
        prep = self.publisher.prepare(event, "exec-03", ACCEPTED_AT, POLICY_REVISION)
        assert prep.bundle is not None

        self.assertFalse(hasattr(self.control, "_coordinator"))

        journal_ref_before = self.api.refs[FIXED_REF]
        patch_calls_before = [c for c in self.api.calls if c[0] == "PATCH"]

        ctrl_res = self.control.execute(prep.bundle)
        self.assertFalse(ctrl_res.ambiguous)

        journal_ref_after = self.api.refs[FIXED_REF]
        patch_calls_after = [c for c in self.api.calls if c[0] == "PATCH"]
        self.assertEqual(journal_ref_before, journal_ref_after)
        self.assertEqual(len(patch_calls_before), len(patch_calls_after))

        _, record = self.coordinator.load_record("sep-nomut-01")
        self.assertEqual(record["state"], "executing")

    # 4. Publisher finalize funciona sin Control credential.
    def test_04_publisher_finalize_works_without_control_credentials(self) -> None:
        event = make_event(request_id="sep-fin-01")
        prep = self.publisher.prepare(event, "exec-04", ACCEPTED_AT, POLICY_REVISION)
        assert prep.bundle is not None
        ctrl_res = self.control.execute(prep.bundle)

        post_calls_before = len([c for c in self.api.calls if c[0] == "POST" and "comments" in c[1]])

        receipt = self.publisher.finalize(prep.bundle, ctrl_res)

        post_calls_after = len([c for c in self.api.calls if c[0] == "POST" and "comments" in c[1]])
        self.assertEqual(post_calls_before, post_calls_after)

        self.assertEqual(receipt.terminal_state, "succeeded")
        self.assertEqual(receipt.terminal_code, "found")
        self.assertEqual(receipt.terminal_reference, ctrl_res.terminal_reference)
        self.assertFalse(receipt.replayed)
        self.assertFalse(receipt.reconciled)

        _, record = self.coordinator.load_record("sep-fin-01")
        self.assertEqual(record["state"], "succeeded")
        self.assertEqual(record["terminal_code"], "found")
        self.assertEqual(record["terminal_reference"], ctrl_res.terminal_reference)

    # 5. Receipt con App incorrecta es rechazado.
    def test_05_receipt_with_wrong_app_is_rejected(self) -> None:
        event = make_event(request_id="sep-badapp-01")
        prep = self.publisher.prepare(event, "exec-05", ACCEPTED_AT, POLICY_REVISION)
        assert prep.bundle is not None

        self.api.bad_post_app_id = True
        ctrl_res = self.control.execute(prep.bundle)
        self.assertTrue(ctrl_res.ambiguous)
        self.assertEqual(ctrl_res.ambiguous_code, "comment_app_id_mismatch")

        with self.assertRaises(ActionsHandlerError) as ctx:
            self.publisher.finalize(prep.bundle, ctrl_res)
        self.assertEqual(ctx.exception.code, "comment_app_id_mismatch")

        _, record = self.coordinator.load_record("sep-badapp-01")
        self.assertEqual(record["state"], "ambiguous")

        bad_comment = {
            "id": 101,
            "issue_url": f"https://api.github.com/repos/{TRUSTED_POLICY.repository_full_name}/issues/42",
            "html_url": f"https://github.com/{TRUSTED_POLICY.repository_full_name}/issues/42#issuecomment-101",
            "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
            "performed_via_github_app": {"id": 99999},
        }
        with self.assertRaises(ActionsHandlerError) as ctx2:
            self.publisher.validate_comment_identity(
                bad_comment, TRUSTED_POLICY.repository_full_name, 42
            )
        self.assertEqual(ctx2.exception.code, "comment_app_id_mismatch")

    # 6. Receipt con bot incorrecto es rechazado.
    def test_06_receipt_with_wrong_bot_is_rejected(self) -> None:
        event = make_event(request_id="sep-badbot-01")
        prep = self.publisher.prepare(event, "exec-06", ACCEPTED_AT, POLICY_REVISION)
        assert prep.bundle is not None

        self.api.bad_post_bot_id = True
        ctrl_res = self.control.execute(prep.bundle)
        self.assertTrue(ctrl_res.ambiguous)
        self.assertEqual(ctrl_res.ambiguous_code, "comment_bot_id_mismatch")

        with self.assertRaises(ActionsHandlerError) as ctx:
            self.publisher.finalize(prep.bundle, ctrl_res)
        self.assertEqual(ctx.exception.code, "comment_bot_id_mismatch")

        bad_comment = {
            "id": 102,
            "issue_url": f"https://api.github.com/repos/{TRUSTED_POLICY.repository_full_name}/issues/42",
            "html_url": f"https://github.com/{TRUSTED_POLICY.repository_full_name}/issues/42#issuecomment-102",
            "user": {"id": 88888, "type": "Bot"},
            "performed_via_github_app": {"id": TRUSTED_RECEIPT_POLICY.app_id},
        }
        with self.assertRaises(ActionsHandlerError) as ctx2:
            self.publisher.validate_comment_identity(
                bad_comment, TRUSTED_POLICY.repository_full_name, 42
            )
        self.assertEqual(ctx2.exception.code, "comment_bot_id_mismatch")

    # 7. Receipt forged por usuario es rechazado.
    def test_07_receipt_forged_by_user_is_rejected(self) -> None:
        event = make_event(request_id="sep-forged-01")
        prep = self.publisher.prepare(event, "exec-07", ACCEPTED_AT, POLICY_REVISION)
        assert prep.bundle is not None

        repo = TRUSTED_POLICY.repository_full_name
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "sep-forged-01",
            "request_digest": prep.bundle.request_digest,
            "operation": "github.ci.inspect",
            "accepted_revision": prep.bundle.accepted_revision,
            "claim_revision": prep.bundle.claim_revision,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {},
        }
        body = _format_receipt_comment(envelope)
        self.api.comments[77] = {
            "id": 77,
            "body": body,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-77",
            "user": {"id": 2001, "type": "User"},
        }

        with self.assertRaises(ActionsHandlerError) as ctx:
            self.publisher.finalize(prep.bundle)
        self.assertEqual(ctx.exception.code, "comment_publication_ambiguous")

        with self.assertRaises(ActionsHandlerError) as ctx2:
            self.publisher.validate_comment_identity(
                self.api.comments[77], repo, 42
            )
        self.assertEqual(ctx2.exception.code, "comment_bot_id_mismatch")

    # 8. Receipt con accepted revision incorrecta es rechazado.
    def test_08_receipt_with_wrong_accepted_revision_is_rejected(self) -> None:
        event = make_event(request_id="sep-badaccrev-01")
        prep = self.publisher.prepare(event, "exec-08", ACCEPTED_AT, POLICY_REVISION)
        assert prep.bundle is not None

        repo = TRUSTED_POLICY.repository_full_name
        wrong_accepted_rev = "0" * 40
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "sep-badaccrev-01",
            "request_digest": prep.bundle.request_digest,
            "operation": "github.ci.inspect",
            "accepted_revision": wrong_accepted_rev,
            "claim_revision": prep.bundle.claim_revision,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {},
        }
        body = _format_receipt_comment(envelope)
        self.api.comments[88] = {
            "id": 88,
            "body": body,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-88",
            "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
            "performed_via_github_app": {"id": TRUSTED_RECEIPT_POLICY.app_id},
        }

        with self.assertRaises(ActionsHandlerError) as ctx:
            self.publisher.finalize(prep.bundle)
        self.assertEqual(ctx.exception.code, "receipt_revision_mismatch")

        with self.assertRaises(ActionsHandlerError) as ctx2:
            _parse_receipt_comment(
                body,
                "sep-badaccrev-01",
                prep.bundle.request_digest,
                "github.ci.inspect",
                expected_accepted_revision=prep.bundle.accepted_revision,
                expected_claim_revision=prep.bundle.claim_revision,
            )
        self.assertEqual(ctx2.exception.code, "receipt_revision_mismatch")

    # 9. Receipt con claim revision incorrecta es rechazado.
    def test_09_receipt_with_wrong_claim_revision_is_rejected(self) -> None:
        event = make_event(request_id="sep-badclaimrev-01")
        prep = self.publisher.prepare(event, "exec-09", ACCEPTED_AT, POLICY_REVISION)
        assert prep.bundle is not None

        repo = TRUSTED_POLICY.repository_full_name
        wrong_claim_rev = "0" * 40
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "sep-badclaimrev-01",
            "request_digest": prep.bundle.request_digest,
            "operation": "github.ci.inspect",
            "accepted_revision": prep.bundle.accepted_revision,
            "claim_revision": wrong_claim_rev,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {},
        }
        body = _format_receipt_comment(envelope)
        self.api.comments[89] = {
            "id": 89,
            "body": body,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-89",
            "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
            "performed_via_github_app": {"id": TRUSTED_RECEIPT_POLICY.app_id},
        }

        with self.assertRaises(ActionsHandlerError) as ctx:
            self.publisher.finalize(prep.bundle)
        self.assertEqual(ctx.exception.code, "receipt_revision_mismatch")

        with self.assertRaises(ActionsHandlerError) as ctx2:
            _parse_receipt_comment(
                body,
                "sep-badclaimrev-01",
                prep.bundle.request_digest,
                "github.ci.inspect",
                expected_accepted_revision=prep.bundle.accepted_revision,
                expected_claim_revision=prep.bundle.claim_revision,
            )
        self.assertEqual(ctx2.exception.code, "receipt_revision_mismatch")

    # 10. Duplicate receipts fallan cerrado.
    def test_10_duplicate_receipts_fail_closed(self) -> None:
        event = make_event(request_id="sep-duprec-01")
        prep = self.publisher.prepare(event, "exec-10", ACCEPTED_AT, POLICY_REVISION)
        assert prep.bundle is not None

        repo = TRUSTED_POLICY.repository_full_name
        envelope = {
            "schema_version": 1,
            "kind": "actions.request.receipt",
            "request_id": "sep-duprec-01",
            "request_digest": prep.bundle.request_digest,
            "operation": "github.ci.inspect",
            "accepted_revision": prep.bundle.accepted_revision,
            "claim_revision": prep.bundle.claim_revision,
            "terminal_state": "succeeded",
            "terminal_code": "found",
            "result": {},
        }
        body = _format_receipt_comment(envelope)
        self.api.comments[1] = {
            "id": 1,
            "body": body,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-1",
            "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
            "performed_via_github_app": {"id": TRUSTED_RECEIPT_POLICY.app_id},
        }
        self.api.comments[2] = {
            "id": 2,
            "body": body,
            "issue_url": f"https://api.github.com/repos/{repo}/issues/42",
            "html_url": f"https://github.com/{repo}/issues/42#issuecomment-2",
            "user": {"id": TRUSTED_RECEIPT_POLICY.bot_user_id, "type": "Bot"},
            "performed_via_github_app": {"id": TRUSTED_RECEIPT_POLICY.app_id},
        }

        with self.assertRaises(ActionsHandlerError) as ctx:
            self.publisher.finalize(prep.bundle)
        self.assertEqual(ctx.exception.code, "duplicate_receipts_found")

    # 11. Unauthorized Issue es rechazado antes de otorgar ejecución.
    def test_11_unauthorized_issue_rejected_before_granting_execution(self) -> None:
        event = make_event(request_id="sep-unauth-01", sender_id=9999, author_id=9999)
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.publisher.prepare(event, "exec-11", ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(ctx.exception.code, "cli_validation_failed")

        patch_calls = [c for c in self.api.calls if c[0] == "PATCH"]
        self.assertEqual(len(patch_calls), 0)
        self.assertEqual(len(self.api.comments), 0)

    # 12. Replay terminal conserva idempotencia.
    def test_12_terminal_replay_preserves_idempotency(self) -> None:
        event = make_event(request_id="sep-replay-01")
        prep1 = self.publisher.prepare(event, "exec-12", ACCEPTED_AT, POLICY_REVISION)
        assert prep1.bundle is not None
        ctrl_res = self.control.execute(prep1.bundle)
        receipt1 = self.publisher.finalize(prep1.bundle, ctrl_res)
        self.assertEqual(receipt1.terminal_state, "succeeded")

        ref_after_first = self.api.refs[FIXED_REF]
        post_calls_after_first = len([c for c in self.api.calls if c[0] == "POST" and "comments" in c[1]])

        prep2 = self.publisher.prepare(event, "exec-12-replay", ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(prep2.disposition, ClaimDisposition.TERMINAL_REPLAY)
        self.assertIsNone(prep2.bundle)
        self.assertIsNotNone(prep2.receipt)
        self.assertTrue(prep2.receipt.replayed)
        self.assertEqual(prep2.receipt.terminal_state, "succeeded")
        self.assertEqual(prep2.receipt.terminal_code, "found")

        self.assertEqual(self.api.refs[FIXED_REF], ref_after_first)
        self.assertEqual(
            len([c for c in self.api.calls if c[0] == "POST" and "comments" in c[1]]),
            post_calls_after_first,
        )

    # 13. Ambiguous publication no inventa terminal success/failure.
    def test_13_ambiguous_publication_does_not_invent_terminal_success_or_failure(self) -> None:
        event = make_event(request_id="sep-ambig-01")
        prep = self.publisher.prepare(event, "exec-13", ACCEPTED_AT, POLICY_REVISION)
        assert prep.bundle is not None

        self.api.bad_post_comment = True
        ctrl_res = self.control.execute(prep.bundle)
        self.assertTrue(ctrl_res.ambiguous)
        self.assertEqual(ctrl_res.ambiguous_code, "comment_publication_ambiguous")

        with self.assertRaises(ActionsHandlerError) as ctx:
            self.publisher.finalize(prep.bundle, ctrl_res)
        self.assertEqual(ctx.exception.code, "comment_publication_ambiguous")

        _, record = self.coordinator.load_record("sep-ambig-01")
        self.assertEqual(record["state"], "ambiguous")
        self.assertIsNone(record.get("terminal_code"))

        rec_receipt = self.publisher.reconcile_request("sep-ambig-01")
        self.assertFalse(rec_receipt.reconciled)
        self.assertEqual(rec_receipt.terminal_state, "ambiguous")
        self.assertEqual(rec_receipt.terminal_code, "reconciliation_required")

        _, record2 = self.coordinator.load_record("sep-ambig-01")
        self.assertEqual(record2["state"], "ambiguous")

    # 14. Existing "github.ci.inspect" behavior continúa funcionando.
    def test_14_existing_github_ci_inspect_behavior_continues_to_work(self) -> None:
        event = make_event(request_id="sep-inspect-01")
        receipt = self.handler.handle_request(event, "exec-14", ACCEPTED_AT, POLICY_REVISION)

        self.assertEqual(receipt.terminal_state, "succeeded")
        self.assertEqual(receipt.terminal_code, "found")
        self.assertFalse(receipt.replayed)
        self.assertFalse(receipt.reconciled)

        comment_id = int(receipt.terminal_reference.rsplit("-", 1)[-1])
        comment = self.api.comments[comment_id]
        self.assertIn("zach-actions:receipt:v1:request_id=sep-inspect-01", comment["body"])

        _, record = self.coordinator.load_record("sep-inspect-01")
        self.assertEqual(record["state"], "succeeded")
        self.assertEqual(record["terminal_code"], "found")

    # 15. ExecutionBundle serialization roundtrip and validation.
    def test_15_bundle_serialization_roundtrip_and_validation(self) -> None:
        event = make_event(request_id="sep-bundle-01")
        prep = self.publisher.prepare(event, "exec-15", ACCEPTED_AT, POLICY_REVISION)
        assert prep.bundle is not None
        bundle = prep.bundle

        bundle_json = bundle.to_json()
        restored = ExecutionBundle.from_json(bundle_json)
        self.assertEqual(bundle, restored)

        tampered = ExecutionBundle(
            request_id=bundle.request_id,
            request_digest="f" * 64,
            operation=bundle.operation,
            repository_id=bundle.repository_id,
            repository_full_name=bundle.repository_full_name,
            issue_id=bundle.issue_id,
            issue_number=bundle.issue_number,
            execution_id=bundle.execution_id,
            canonical_record=bundle.canonical_record,
            accepted_revision=bundle.accepted_revision,
            claim_revision=bundle.claim_revision,
            parameters=bundle.parameters,
        )
        with self.assertRaises(ActionsHandlerError) as ctx:
            self.control.execute(tampered)
        self.assertEqual(ctx.exception.code, "invalid_execution_bundle")


class DurablePublisherCheckpointTests(unittest.TestCase):
    """Adversarial coverage for cross-attempt Issue checkpoints."""

    def setUp(self) -> None:
        self.api = UnifiedFakeApi()
        self.coordinator = ActionsJournalCoordinator(CLI, self.api.request)
        self.publisher = PublisherPhase(
            self.coordinator,
            TRUSTED_POLICY,
            TRUSTED_RECEIPT_POLICY,
            self.api.request,
            trusted_publisher_policy=TRUSTED_RECEIPT_POLICY,
        )
        self.control = ControlPhase(
            self.api.request,
            TRUSTED_RECEIPT_POLICY,
            ci_policy=CI_POLICY,
        )

    def test_intent_is_read_back_before_claim_and_prepare_checkpoint(self) -> None:
        result = self.publisher.prepare(
            make_event(request_id="durable-order-01"),
            "991-1",
            ACCEPTED_AT,
            POLICY_REVISION,
        )
        assert result.bundle is not None
        mutations = [
            (method, path, body)
            for method, path, body in self.api.calls
            if method == "PATCH"
            or (method == "POST" and path.endswith("/comments"))
        ]
        self.assertEqual([entry[0] for entry in mutations], ["PATCH", "POST", "PATCH", "POST"])
        self.assertIn("publisher-intent:v1", mutations[1][2]["body"])
        self.assertIn("publisher-prepare:v1", mutations[3][2]["body"])
        self.assertEqual(result.disposition, ClaimDisposition.GRANTED)

    def test_rerun_reconstructs_prepare_from_intent_and_executing_journal(self) -> None:
        event = make_event(request_id="durable-crash-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        accepted = parse_and_validate_record(acceptance.record_json, acceptance.request_id)
        intent = self.publisher._intent_envelope(accepted, "992-1", acceptance.durable_revision)
        self.publisher._ensure_publisher_comment("intent", intent)
        claim = self.coordinator.claim(acceptance.request_id, "992-1")
        self.assertEqual(claim.disposition, ClaimDisposition.GRANTED)

        resumed = PublisherPhase(
            self.coordinator,
            TRUSTED_POLICY,
            TRUSTED_RECEIPT_POLICY,
            self.api.request,
            trusted_publisher_policy=TRUSTED_RECEIPT_POLICY,
        ).prepare(event, "992-1", ACCEPTED_AT, POLICY_REVISION)
        assert resumed.bundle is not None
        self.assertEqual(resumed.disposition, ClaimDisposition.RECONCILIATION_REQUIRED)
        self.assertEqual(resumed.bundle.accepted_revision, acceptance.durable_revision)
        self.assertEqual(resumed.bundle.claim_revision, self.api.refs[FIXED_REF])
        checkpoint = load_durable_prepare_checkpoint(
            self.api.request,
            TRUSTED_RECEIPT_POLICY,
            TRUSTED_POLICY.repository_full_name,
            42,
            "992-1",
        )
        self.assertEqual(checkpoint.bundle, resumed.bundle)

    def test_executing_record_without_prior_intent_fails_closed(self) -> None:
        event = make_event(request_id="missing-intent-01")
        acceptance = self.coordinator.accept(event, TRUSTED_POLICY, ACCEPTED_AT, POLICY_REVISION)
        self.coordinator.claim(acceptance.request_id, "993-1")
        with self.assertRaisesRegex(ActionsHandlerError, "publisher_intent_missing_after_claim"):
            self.publisher.prepare(event, "993-1", ACCEPTED_AT, POLICY_REVISION)
        self.assertFalse(any("publisher-prepare:v1" in item["body"] for item in self.api.comments.values()))

    def test_rerun_of_complete_prepare_requires_reconciliation(self) -> None:
        event = make_event(request_id="durable-rerun-01")
        first = self.publisher.prepare(event, "9922-1", ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(first.disposition, ClaimDisposition.GRANTED)
        resumed = self.publisher.prepare(event, "9922-1", ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(resumed.disposition, ClaimDisposition.RECONCILIATION_REQUIRED)
        self.assertEqual(resumed.bundle, first.bundle)

    def test_ambiguous_rerun_recovers_the_durable_prepare_checkpoint(self) -> None:
        event = make_event(request_id="durable-ambiguous-01")
        first = self.publisher.prepare(event, "9923-1", ACCEPTED_AT, POLICY_REVISION)
        assert first.bundle is not None
        self.coordinator.mark_ambiguous(first.request_id, first.bundle.execution_id)
        resumed = self.publisher.prepare(event, "9923-1", ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(resumed.disposition, ClaimDisposition.RECONCILIATION_REQUIRED)
        self.assertEqual(resumed.bundle, first.bundle)

    def test_duplicate_prepare_checkpoints_fail_closed(self) -> None:
        result = self.publisher.prepare(
            make_event(request_id="duplicate-prep-01"), "994-1", ACCEPTED_AT, POLICY_REVISION
        )
        assert result.bundle is not None
        prepare = next(
            item for item in self.api.comments.values() if "publisher-prepare:v1" in item["body"]
        )
        duplicate = dict(prepare, id=self.api.next_comment_id)
        duplicate["html_url"] = (
            f"https://github.com/{TRUSTED_POLICY.repository_full_name}/issues/42"
            f"#issuecomment-{self.api.next_comment_id}"
        )
        self.api.comments[self.api.next_comment_id] = duplicate
        self.api.next_comment_id += 1
        with self.assertRaisesRegex(
            ActionsHandlerError, "duplicate_publisher_prepare_checkpoints"
        ):
            load_durable_prepare_checkpoint(
                self.api.request,
                TRUSTED_RECEIPT_POLICY,
                TRUSTED_POLICY.repository_full_name,
                42,
                "994-1",
            )

    def test_tampered_prepare_checkpoint_is_rejected(self) -> None:
        result = self.publisher.prepare(
            make_event(request_id="tampered-prep-01"), "995-1", ACCEPTED_AT, POLICY_REVISION
        )
        assert result.bundle is not None
        prepare = next(
            item for item in self.api.comments.values() if "publisher-prepare:v1" in item["body"]
        )
        prepare["body"] = prepare["body"].replace('"issue_number": 42', '"issue_number": 43')
        with self.assertRaisesRegex(ActionsHandlerError, "publisher_checkpoint_binding_mismatch"):
            load_durable_prepare_checkpoint(
                self.api.request,
                TRUSTED_RECEIPT_POLICY,
                TRUSTED_POLICY.repository_full_name,
                42,
                "995-1",
            )

    def test_control_reconcile_replays_existing_receipt_without_second_effect_or_post(self) -> None:
        prepared = self.publisher.prepare(
            make_event(request_id="receipt-replay-01"), "996-1", ACCEPTED_AT, POLICY_REVISION
        )
        assert prepared.bundle is not None
        first = self.control.execute(prepared.bundle)
        self.assertFalse(first.ambiguous)
        calls_before = len(self.api.calls)
        posts_before = len(
            [call for call in self.api.calls if call[0] == "POST" and call[1].endswith("/comments")]
        )
        replay = self.control.execute(prepared.bundle, reconcile_recipe_only=True)
        later_calls = self.api.calls[calls_before:]
        self.assertTrue(replay.replayed)
        self.assertFalse(any("actions/workflows" in path or "actions/runs" in path for _, path, _ in later_calls))
        self.assertEqual(
            len([call for call in self.api.calls if call[0] == "POST" and call[1].endswith("/comments")]),
            posts_before,
        )

    def test_checkpoint_size_limit_is_enforced_before_post(self) -> None:
        envelope = {
            "schema_version": 1,
            "kind": "actions.publisher.intent",
            "request_id": "oversized-intent-01",
            "request_digest": "1" * 64,
            "operation": "github.ci.inspect",
            "repository_id": 1001,
            "repository_full_name": "shockerqt/zach",
            "issue_id": 501,
            "issue_number": 42,
            "execution_id": "997-1",
            "accepted_revision": "2" * 40,
            "policy_revision": "3" * 40,
            "extra": "x" * (64 * 1024),
        }
        with self.assertRaisesRegex(ActionsHandlerError, "publisher_checkpoint_too_large"):
            _format_publisher_comment("intent", envelope)

    def test_control_reconcile_without_receipt_reconciles_without_dispatch_and_posts_once(self) -> None:
        parameters = {
            "artifact_sha256": "6" * 64,
            "expected_current": "7" * 40,
            "operation": "rollback",
            "recipe": "sandbox.delivery",
            "source_sha": "5" * 40,
        }
        prepared = self.publisher.prepare(
            make_event(
                request_id="recipe-recover-01",
                operation="workspace.recipe.dispatch",
                parameters=parameters,
            ),
            "998-1",
            ACCEPTED_AT,
            POLICY_REVISION,
        )
        assert prepared.bundle is not None
        recipe_policy = RecipeDispatchPolicy(
            recipe="sandbox.delivery",
            repository_alias="ui-design-sandbox",
            repository_full_name="shockerqt/ui-design-sandbox",
            repository_id=1002,
            workflow_id=7654321,
            workflow_path=".github/workflows/sandbox-delivery.yml",
            ref="main",
            actor_id=TRUSTED_RECEIPT_POLICY.bot_user_id,
        )
        control = ControlPhase(
            self.api.request,
            TRUSTED_RECEIPT_POLICY,
            recipe_policy=recipe_policy,
        )
        reconciled = {
            "schema_version": 1,
            "kind": "workspace.recipe.dispatch.result",
            "result": "dispatched",
            "run_id": 12345,
        }
        posts_before = len(
            [call for call in self.api.calls if call[0] == "POST" and call[1].endswith("/comments")]
        )
        with (
            patch("actions_request_handler.reconcile_recipe", return_value=reconciled) as reconcile,
            patch("actions_request_handler.dispatch_recipe", side_effect=AssertionError("dispatch forbidden")),
        ):
            result = control.execute(prepared.bundle, reconcile_recipe_only=True)
        self.assertFalse(result.ambiguous)
        reconcile.assert_called_once()
        self.assertEqual(
            len([call for call in self.api.calls if call[0] == "POST" and call[1].endswith("/comments")]),
            posts_before + 1,
        )


if __name__ == "__main__":
    unittest.main()
