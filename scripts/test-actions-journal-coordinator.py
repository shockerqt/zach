"""Critical integration tests for the durable Actions journal coordinator."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import unittest
from typing import Any, Optional

from actions_git_journal import AmbiguousPublication, ApiError, FIXED_REF, FIXED_REPOSITORY
from actions_journal_coordinator import (
    MAX_CLI_STDOUT_BYTES,
    AcceptanceResult,
    ActionsJournalCoordinator,
    ClaimDisposition,
    CliProcessResult,
    CoordinatorError,
    TrustedIssuePolicy,
    TrustedReconciliationObservation,
    _ExactTransitionValidator,
)


CLI = str((Path(__file__).resolve().parent.parent / "target" / "debug" / "zach-actions").resolve())
POLICY_REVISION = "4ae216576b054f528c9edbcfed4a2711bccaa476"
ACCEPTED_AT = "2026-09-05T07:47:52Z"
REQUEST_ID = "uds007-inspect-build-01"


def make_event(*, request_id: str = REQUEST_ID, source_sha: str = "4" * 40, issue_id: int = 501) -> bytes:
    request = {
        "schema_version": 1,
        "request_id": request_id,
        "operation": "github.ci.inspect",
        "parameters": {"repository": "ui-design-sandbox", "source_sha": source_sha},
    }
    event = {
        "action": "opened",
        "repository": {"id": 1001, "full_name": "shockerqt/zach"},
        "sender": {"id": 2001},
        "issue": {
            "id": issue_id,
            "number": 42,
            "user": {"id": 2001},
            "body": json.dumps(request, separators=(",", ":")),
        },
    }
    return json.dumps(event, separators=(",", ":")).encode("utf-8")


class FakeGitHubApi:
    """Small in-memory implementation of the fixed Git Data journal endpoints."""

    def __init__(self) -> None:
        self.refs: dict[str, str] = {}
        self.commits: dict[str, dict[str, Any]] = {}
        self.trees: dict[str, dict[str, Any]] = {}
        self.blobs: dict[str, str] = {}
        self.calls: list[tuple[str, str, Any]] = []
        self.bad_next_readback = False
        self._after_patch = False
        empty_tree = hashlib.sha1(b"tree empty").hexdigest()
        root_commit = hashlib.sha1(b"commit root").hexdigest()
        self.trees[empty_tree] = {}
        self.commits[root_commit] = {
            "sha": root_commit,
            "tree": {"sha": empty_tree},
            "parents": [],
        }
        self.refs[FIXED_REF] = root_commit

    def request(self, method: str, path: str, body: Optional[dict[str, Any]] = None) -> Any:
        self.calls.append((method, path, body))
        ref_path = f"/repos/{FIXED_REPOSITORY}/git/ref/{FIXED_REF}"
        refs_path = f"/repos/{FIXED_REPOSITORY}/git/refs/{FIXED_REF}"

        if method == "GET" and path in (ref_path, refs_path):
            if self._after_patch and self.bad_next_readback:
                self.bad_next_readback = False
                self._after_patch = False
                return {"ref": f"refs/{FIXED_REF}", "object": {"sha": "0" * 40}}
            self._after_patch = False
            return {"ref": f"refs/{FIXED_REF}", "object": {"sha": self.refs[FIXED_REF]}}

        if method == "PATCH" and path in (ref_path, refs_path):
            assert body is not None and body.get("force") is False
            candidate = body["sha"]
            current = self.refs[FIXED_REF]
            parents = [entry["sha"] for entry in self.commits[candidate]["parents"]]
            if current not in parents:
                raise ApiError(422, "stale")
            self.refs[FIXED_REF] = candidate
            self._after_patch = True
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
        raise ApiError(404, "unknown_endpoint")


class TestActionsJournalCoordinator(unittest.TestCase):
    def setUp(self) -> None:
        if not os.path.isfile(CLI):
            self.fail("target/debug/zach-actions must be built before this test")
        self.api = FakeGitHubApi()
        self.policy = TrustedIssuePolicy(1001, "shockerqt/zach", (2001, 2002))
        self.coordinator = ActionsJournalCoordinator(CLI, self.api.request)

    def accept(self, event: bytes = make_event(), accepted_at: str = ACCEPTED_AT, revision: str = POLICY_REVISION) -> AcceptanceResult:
        return self.coordinator.accept(event, self.policy, accepted_at, revision)

    def test_accept_and_replay_preserve_frozen_metadata(self) -> None:
        first = self.accept()
        self.assertFalse(first.replayed)
        self.assertEqual(json.loads(first.record_json)["state"], "accepted")

        replay = self.accept(
            accepted_at="2026-09-05T09:00:00Z",
            revision="b" * 40,
        )
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.record_json, first.record_json)
        frozen = json.loads(replay.record_json)
        self.assertEqual(frozen["accepted_at"], ACCEPTED_AT)
        self.assertEqual(frozen["policy_revision"], POLICY_REVISION)

    def test_terminal_credentials_are_rejected_before_storage(self) -> None:
        accepted = self.accept()
        self.coordinator.claim(accepted.request_id, "run-owner")
        head = self.api.refs[FIXED_REF]
        dummy = "github_pat_DUMMY_NOT_A_CREDENTIAL"
        for code, reference in ((dummy, None), ("ok", dummy), ("ok", "prefix:" + dummy)):
            with self.assertRaises(CoordinatorError):
                self.coordinator.complete(accepted.request_id, "run-owner", "succeeded", code, reference)
            self.assertEqual(self.api.refs[FIXED_REF], head)
        self.assertNotIn("canonical_request", repr(accepted))
        self.assertNotIn(dummy, repr(CliProcessResult(0, dummy.encode(), dummy.encode())))

    def test_global_request_id_conflict_fails_closed(self) -> None:
        self.accept()
        with self.assertRaises(CoordinatorError) as error:
            self.accept(make_event(source_sha="5" * 40, issue_id=999))
        self.assertEqual(error.exception.code, "cli_validation_failed")

    def test_claim_is_granted_only_after_durable_publish(self) -> None:
        accepted = self.accept()
        claim = self.coordinator.claim(accepted.request_id, "run-100")
        self.assertEqual(claim.disposition, ClaimDisposition.GRANTED)
        self.assertEqual(self.api.refs[FIXED_REF], claim.durable_revision)
        self.assertEqual(json.loads(claim.record_json)["execution_id"], "run-100")

        repeated = self.coordinator.claim(accepted.request_id, "run-100")
        self.assertEqual(repeated.disposition, ClaimDisposition.RECONCILIATION_REQUIRED)
        self.assertEqual(repeated.durable_revision, claim.durable_revision)

    def test_interrupted_claim_publication_never_returns_grant(self) -> None:
        accepted = self.accept()
        self.api.bad_next_readback = True
        with self.assertRaises(AmbiguousPublication):
            self.coordinator.claim(accepted.request_id, "run-ambiguous")

    def test_ambiguity_transition_retains_owner_and_blocks_claims(self) -> None:
        accepted = self.accept()
        self.coordinator.claim(accepted.request_id, "run-owner")
        ambiguous = self.coordinator.mark_ambiguous(accepted.request_id, "run-owner")
        record = json.loads(ambiguous.record_json)
        self.assertEqual(record["state"], "ambiguous")
        self.assertEqual(record["execution_id"], "run-owner")
        repeated = self.coordinator.claim(accepted.request_id, "run-owner")
        self.assertEqual(repeated.disposition, ClaimDisposition.RECONCILIATION_REQUIRED)

    def test_only_exact_execution_owner_can_terminalize_or_mark_ambiguous(self) -> None:
        accepted = self.accept()
        self.coordinator.claim(accepted.request_id, "run-owner")
        with self.assertRaises(CoordinatorError) as complete_error:
            self.coordinator.complete(accepted.request_id, "run-other", "succeeded", "ok")
        self.assertEqual(complete_error.exception.code, "execution_owner_mismatch")
        with self.assertRaises(CoordinatorError) as ambiguous_error:
            self.coordinator.mark_ambiguous(accepted.request_id, "run-other")
        self.assertEqual(ambiguous_error.exception.code, "execution_owner_mismatch")

        completed = self.coordinator.complete(
            accepted.request_id, "run-owner", "succeeded", "build_passed", "commit:abc"
        )
        self.assertEqual(json.loads(completed.record_json)["state"], "succeeded")
        terminal = self.coordinator.claim(accepted.request_id, "later-run")
        self.assertEqual(terminal.disposition, ClaimDisposition.TERMINAL_REPLAY)

    def test_exact_transition_validator_rejects_forged_pairs(self) -> None:
        validator = _ExactTransitionValidator("old-bytes", "new-bytes")
        self.assertTrue(validator("old-bytes", "new-bytes"))
        self.assertFalse(validator("other-old", "new-bytes"))
        self.assertFalse(validator("old-bytes", "other-new"))

    def test_child_output_and_private_inputs_are_bounded(self) -> None:
        observed_modes: list[int] = []

        def oversized_runner(argv: tuple[str, ...], timeout: float) -> CliProcessResult:
            self.assertEqual(argv[1], "accept")
            event_path = argv[argv.index("--event") + 1]
            observed_modes.append(os.stat(event_path).st_mode & 0o777)
            return CliProcessResult(0, b"x" * (MAX_CLI_STDOUT_BYTES + 1))

        coordinator = ActionsJournalCoordinator("/trusted/zach-actions", self.api.request, cli_runner=oversized_runner)
        with self.assertRaises(CoordinatorError) as error:
            coordinator.accept(make_event(), self.policy, ACCEPTED_AT, POLICY_REVISION)
        self.assertEqual(error.exception.code, "cli_output_too_large")
        self.assertEqual(observed_modes, [0o600])

    def test_reconcile_resolves_ambiguous_record_and_enforces_owner(self) -> None:
        accepted = self.accept()
        self.coordinator.claim(accepted.request_id, "run-owner")
        self.coordinator.mark_ambiguous(accepted.request_id, "run-owner")

        # Reconcile rejects execution owner mismatch
        observation = TrustedReconciliationObservation("succeeded", "ci_passed", "https://github.com/shockerqt/zach/issues/42#issuecomment-1")
        with self.assertRaises(CoordinatorError) as error:
            self.coordinator.reconcile(accepted.request_id, "run-wrong-owner", observation)
        self.assertEqual(error.exception.code, "execution_owner_mismatch")

        # Reconcile rejects non-TrustedReconciliationObservation
        with self.assertRaises(CoordinatorError) as error:
            self.coordinator.reconcile(accepted.request_id, "run-owner", "not-an-observation")  # type: ignore[arg-type]
        self.assertEqual(error.exception.code, "invalid_reconciliation_observation")

        # Successful reconciliation by exact owner
        reconciled = self.coordinator.reconcile(accepted.request_id, "run-owner", observation)
        record = json.loads(reconciled.record_json)
        self.assertEqual(record["state"], "succeeded")
        self.assertEqual(record["terminal_code"], "ci_passed")
        self.assertEqual(record["terminal_reference"], "https://github.com/shockerqt/zach/issues/42#issuecomment-1")

        # Subsequent claim is terminal replay
        terminal = self.coordinator.claim(accepted.request_id, "later-run")
        self.assertEqual(terminal.disposition, ClaimDisposition.TERMINAL_REPLAY)

    def test_load_record_returns_snapshot_and_parsed_record(self) -> None:
        accepted = self.accept()
        head_sha, record = self.coordinator.load_record(accepted.request_id)
        self.assertEqual(head_sha, self.api.refs[FIXED_REF])
        self.assertEqual(record["request_id"], accepted.request_id)
        self.assertEqual(record["state"], "accepted")

        with self.assertRaises(CoordinatorError) as error:
            self.coordinator.load_record("req-non-existent")
        self.assertEqual(error.exception.code, "request_not_found")


if __name__ == "__main__":
    unittest.main()
