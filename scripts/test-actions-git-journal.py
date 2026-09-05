"""Adversarial fake-API tests for Actions Git-data operational journal persistence backend.

Validates:
- Frozen reads & immutability
- Global hashed key mapping
- Absent ref vs absent file 404 distinction
- Malformed content, request IDs, and SHAs
- Stale snapshot conflict without writes
- Exact publish tree/path/parent/force mechanics
- Lost PATCH response proven success via readback
- Readback tree/ref mismatch raising AmbiguousPublication
- Sibling concurrent updates permitting at most one winner
- No-op replay after fresh ref equality
- Mandatory transition validator enforcement
- Fixed repository and ref exposure
"""

from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError
import hashlib
import json
import unittest
from typing import Any, Callable, Optional

from actions_git_journal import (
    FIXED_REF,
    FIXED_REPOSITORY,
    ActionsGitJournal,
    AmbiguousPublication,
    ApiError,
    JournalError,
    JournalSnapshot,
    JournalValidationError,
    PublicationReceipt,
    StaleSnapshotConflict,
    record_path_for_request_id,
    validate_request_id,
    validate_sha40,
)


class FakeGitHubApi:
    """In-memory GitHub Git Data and Contents API simulator with fault injection."""

    def __init__(self) -> None:
        self.refs: dict[str, str] = {}
        self.commits: dict[str, dict[str, Any]] = {}
        self.trees: dict[str, dict[str, Any]] = {}
        self.blobs: dict[str, str] = {}
        self.calls: list[tuple[str, str, Any]] = []

        # Fault injection hooks
        self.patch_hook: Optional[Callable[[dict[str, Any]], None]] = None
        self.readback_ref_hook: Optional[Callable[[], Any]] = None
        self.readback_commit_hook: Optional[Callable[[str], Any]] = None
        self.contents_hook: Optional[Callable[[str], Any]] = None
        self.get_ref_hook: Optional[Callable[[str], Any]] = None
        self.in_readback: bool = False

    def request(self, method: str, relative_path: str, body: Optional[dict[str, Any]] = None) -> Any:
        self.calls.append((method, relative_path, body))

        # 1. Ref endpoints
        ref_prefix = f"/repos/{FIXED_REPOSITORY}/git/ref/{FIXED_REF}"
        refs_prefix = f"/repos/{FIXED_REPOSITORY}/git/refs/{FIXED_REF}"

        if method == "GET" and (relative_path == ref_prefix or relative_path == refs_prefix):
            if self.in_readback and self.readback_ref_hook:
                return self.readback_ref_hook()
            if self.get_ref_hook:
                return self.get_ref_hook(relative_path)
            if FIXED_REF not in self.refs:
                raise ApiError(404, f"Ref {FIXED_REF} not found")
            return {
                "ref": f"refs/{FIXED_REF}",
                "object": {"sha": self.refs[FIXED_REF], "type": "commit"},
            }

        if method == "PATCH" and (relative_path == refs_prefix or relative_path == ref_prefix):
            if FIXED_REF not in self.refs:
                raise ApiError(404, f"Ref {FIXED_REF} not found")
            if not body or body.get("force") is not False:
                raise ApiError(400, "force must be False")
            candidate_sha = body["sha"]
            candidate_commit = self.commits.get(candidate_sha)
            if not candidate_commit:
                raise ApiError(404, f"Commit {candidate_sha} not found")

            parents = [p["sha"] for p in candidate_commit["parents"]]
            current_head = self.refs[FIXED_REF]
            if current_head not in parents:
                raise ApiError(422, "Reference update is not a fast-forward")

            self.refs[FIXED_REF] = candidate_sha
            self.in_readback = True

            if self.patch_hook:
                self.patch_hook(body)

            return {
                "ref": f"refs/{FIXED_REF}",
                "object": {"sha": candidate_sha, "type": "commit"},
            }

        # 2. Blobs endpoint
        if method == "POST" and relative_path == f"/repos/{FIXED_REPOSITORY}/git/blobs":
            assert body is not None
            content_b64 = body["content"]
            raw = base64.b64decode(content_b64)
            blob_sha = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            self.blobs[blob_sha] = content_b64
            return {"sha": blob_sha}

        # Non-recursive tree views preserve Git mode evidence separately from Contents.
        if method == "GET" and relative_path.startswith(f"/repos/{FIXED_REPOSITORY}/git/trees/"):
            tree_sha = relative_path.rsplit("/", 1)[-1]
            entries = self.trees[tree_sha]
            nested = {k.split("/", 1)[1]: dict(v, path=k.split("/", 1)[1])
                      for k, v in entries.items() if k.startswith("requests/")}
            direct = [v for k, v in entries.items() if "/" not in k]
            if nested:
                subtree_sha = hashlib.sha1(json.dumps(nested, sort_keys=True).encode()).hexdigest()
                self.trees[subtree_sha] = nested
                direct.append({"path": "requests", "mode": "040000", "type": "tree", "sha": subtree_sha})
            return {"sha": tree_sha, "tree": direct, "truncated": False}

        # 3. Trees endpoint
        if method == "POST" and relative_path == f"/repos/{FIXED_REPOSITORY}/git/trees":
            assert body is not None
            base_tree = body.get("base_tree")
            tree_entries = body.get("tree", [])
            entries = dict(self.trees.get(base_tree, {}))
            for entry in tree_entries:
                entries[entry["path"]] = entry
            tree_repr = json.dumps(entries, sort_keys=True).encode()
            tree_sha = hashlib.sha1(b"tree " + tree_repr).hexdigest()
            self.trees[tree_sha] = entries
            return {"sha": tree_sha}

        # 4. Commits endpoint
        if method == "POST" and relative_path == f"/repos/{FIXED_REPOSITORY}/git/commits":
            assert body is not None
            tree_sha = body["tree"]
            parents = body["parents"]
            message = body["message"]
            seq = len(self.commits)
            commit_repr = f"{tree_sha}:{parents}:{message}:{seq}".encode()
            commit_sha = hashlib.sha1(b"commit " + commit_repr).hexdigest()
            commit_obj = {
                "sha": commit_sha,
                "tree": {"sha": tree_sha},
                "parents": [{"sha": p} for p in parents],
                "message": message,
            }
            self.commits[commit_sha] = commit_obj
            return {"sha": commit_sha}

        if method == "GET" and relative_path.startswith(f"/repos/{FIXED_REPOSITORY}/git/commits/"):
            commit_sha = relative_path.split("/")[-1]
            if self.in_readback and self.readback_commit_hook:
                return self.readback_commit_hook(commit_sha)
            if commit_sha not in self.commits:
                raise ApiError(404, f"Commit {commit_sha} not found")
            return self.commits[commit_sha]

        # 5. Contents endpoint
        contents_base = f"/repos/{FIXED_REPOSITORY}/contents/"
        if method == "GET" and relative_path.startswith(contents_base):
            if self.contents_hook:
                return self.contents_hook(relative_path)
            query_parts = relative_path[len(contents_base):].split("?ref=")
            path = query_parts[0]
            ref_sha = query_parts[1] if len(query_parts) > 1 else self.refs.get(FIXED_REF)
            if not ref_sha or ref_sha not in self.commits:
                raise ApiError(404, f"Commit ref {ref_sha} not found")
            tree_sha = self.commits[ref_sha]["tree"]["sha"]
            tree = self.trees.get(tree_sha, {})
            if path not in tree:
                raise ApiError(404, f"Path {path} not found in tree {tree_sha}")
            entry = tree[path]
            blob_sha = entry["sha"]
            content_b64 = self.blobs[blob_sha]
            raw = base64.b64decode(content_b64)
            return {
                "type": "file",
                "encoding": "base64",
                "size": len(raw),
                "name": path.split("/")[-1],
                "path": path,
                "content": content_b64,
                "sha": blob_sha,
            }

        raise ApiError(404, f"Unknown endpoint: {method} {relative_path}")


def init_journal_branch(api: FakeGitHubApi) -> tuple[str, str]:
    """Initialize empty tree and root commit on the fixed ref."""
    empty_tree_sha = hashlib.sha1(b"tree empty").hexdigest()
    api.trees[empty_tree_sha] = {}
    init_commit_sha = hashlib.sha1(b"commit root").hexdigest()
    api.commits[init_commit_sha] = {
        "sha": init_commit_sha,
        "tree": {"sha": empty_tree_sha},
        "parents": [],
        "message": "init journal",
    }
    api.refs[FIXED_REF] = init_commit_sha
    return init_commit_sha, empty_tree_sha


def mock_validator(old_record: Optional[str], new_record: str) -> None:
    """Example transition validator mimicking state machine semantics."""
    new_obj = json.loads(new_record)
    if old_record is not None:
        old_obj = json.loads(old_record)
        if old_obj.get("state") == "succeeded" and new_obj.get("state") != "succeeded":
            raise JournalValidationError("Cannot leave terminal state")


class TestActionsGitJournal(unittest.TestCase):
    def setUp(self) -> None:
        self.api = FakeGitHubApi()
        self.head_sha, self.tree_sha = init_journal_branch(self.api)
        self.journal = ActionsGitJournal(request=self.api.request, validate_transition=mock_validator)

    def test_fixed_repository_and_ref(self) -> None:
        self.assertEqual(ActionsGitJournal.REPOSITORY, "shockerqt/workspace-governance")
        self.assertEqual(ActionsGitJournal.REF, "heads/automation/requests")
        self.assertEqual(self.journal.REPOSITORY, FIXED_REPOSITORY)
        self.assertEqual(self.journal.REF, FIXED_REF)

    def test_validator_required_in_constructor(self) -> None:
        with self.assertRaises(TypeError):
            ActionsGitJournal(request=self.api.request, validate_transition=None)  # type: ignore
        with self.assertRaises(TypeError):
            ActionsGitJournal(request=None, validate_transition=mock_validator)  # type: ignore

    def test_global_key_mapping(self) -> None:
        req_id = "uds007-inspect-build-01"
        path = record_path_for_request_id(req_id)
        expected_digest = hashlib.sha256(req_id.encode("utf-8")).hexdigest()
        self.assertEqual(path, f"requests/{expected_digest}.json")

        other_id = "uds007-inspect-build-02"
        other_path = record_path_for_request_id(other_id)
        self.assertNotEqual(path, other_path)

    def test_frozen_reads(self) -> None:
        req_id = "test-request-001"
        rec = json.dumps({"request_id": req_id, "state": "accepted"})
        snap = self.journal.load(req_id)
        self.assertIsInstance(snap, JournalSnapshot)
        self.assertIsNone(snap.record_json)
        self.assertEqual(snap.head_sha, self.head_sha)
        self.assertEqual(snap.tree_sha, self.tree_sha)

        # Immutability
        with self.assertRaises(FrozenInstanceError):
            snap.head_sha = "1111111111111111111111111111111111111111"  # type: ignore

        # Publish and re-read
        self.journal.publish(snap, req_id, rec)
        snap2 = self.journal.load(req_id)
        self.assertEqual(snap2.record_json, rec)
        self.assertIsNotNone(snap2.record_blob_sha)
        validate_sha40(snap2.record_blob_sha)

        # Check content read pinned to exact commit SHA
        expected_url = f"/repos/{FIXED_REPOSITORY}/contents/{record_path_for_request_id(req_id)}?ref={snap2.head_sha}"
        self.assertTrue(any(c[0] == "GET" and c[1] == expected_url for c in self.api.calls))

    def test_absent_ref_fails_closed(self) -> None:
        del self.api.refs[FIXED_REF]
        with self.assertRaises(ApiError) as ctx:
            self.journal.load("test-request-001")
        self.assertEqual(ctx.exception.status, 404)
        # Branch was never auto-created
        self.assertNotIn(FIXED_REF, self.api.refs)

    def test_absent_file_returns_none_record_but_other_errors_fail(self) -> None:
        snap = self.journal.load("test-request-nonexistent")
        self.assertIsNone(snap.record_json)
        self.assertIsNone(snap.record_blob_sha)

        # Contents returning 500 fails closed
        self.api.contents_hook = lambda _: (_ for _ in ()).throw(ApiError(500, "Internal GitHub error"))
        with self.assertRaises(ApiError) as ctx:
            self.journal.load("test-request-nonexistent")
        self.assertEqual(ctx.exception.status, 500)

    def test_malformed_request_ids(self) -> None:
        invalid_ids = ["short", "a" * 129, "has spaces", "bad@char", "path/traversal", ""]
        for bad_id in invalid_ids:
            with self.assertRaises(JournalValidationError):
                validate_request_id(bad_id)
            with self.assertRaises(JournalValidationError):
                self.journal.load(bad_id)

    def test_malformed_content_and_duplicate_keys(self) -> None:
        req_id = "test-request-malformed"
        snap = self.journal.load(req_id)

        # 1. Payload > 64 KiB
        huge_record = json.dumps({"request_id": req_id, "extra": "x" * (65 * 1024)})
        with self.assertRaises(JournalValidationError):
            self.journal.publish(snap, req_id, huge_record)

        # 2. Duplicate keys
        dup_json = f'{{"request_id": "{req_id}", "state": "accepted", "state": "executing"}}'
        with self.assertRaises(JournalValidationError):
            self.journal.publish(snap, req_id, dup_json)

        # 3. ID mismatch in record
        mismatched_json = json.dumps({"request_id": "different-id-001", "state": "accepted"})
        with self.assertRaises(JournalValidationError):
            self.journal.publish(snap, req_id, mismatched_json)

        # 4. Non-object root
        array_json = json.dumps([req_id])
        with self.assertRaises(JournalValidationError):
            self.journal.publish(snap, req_id, array_json)

    def test_malformed_shas_fail_validation(self) -> None:
        invalid_shas = [
            "A" * 40,  # uppercase
            "a" * 39,  # short
            "a" * 41,  # long
            "g" * 40,  # non-hex
            123,  # non-string
        ]
        for bad_sha in invalid_shas:
            with self.assertRaises(JournalValidationError):
                validate_sha40(bad_sha)

    def test_stale_snapshot_no_writes(self) -> None:
        req_id = "test-request-stale"
        snap = self.journal.load(req_id)

        # Advance ref in background
        new_commit = hashlib.sha1(b"concurrent commit").hexdigest()
        self.api.commits[new_commit] = {
            "sha": new_commit,
            "tree": {"sha": self.tree_sha},
            "parents": [{"sha": self.head_sha}],
            "message": "other update",
        }
        self.api.refs[FIXED_REF] = new_commit

        calls_before = len(self.api.calls)
        rec = json.dumps({"request_id": req_id, "state": "accepted"})
        with self.assertRaises(StaleSnapshotConflict):
            self.journal.publish(snap, req_id, rec)

        # Ensure no write calls (POST blobs, trees, commits, PATCH) were made
        new_calls = self.api.calls[calls_before:]
        self.assertTrue(all(method == "GET" for method, _, _ in new_calls))

    def test_exact_publish_mechanics(self) -> None:
        req_id = "uds007-inspect-build-01"
        rec = json.dumps({"request_id": req_id, "state": "accepted"})
        snap = self.journal.load(req_id)

        receipt = self.journal.publish(snap, req_id, rec)
        self.assertIsInstance(receipt, PublicationReceipt)
        self.assertFalse(receipt.replayed)
        validate_sha40(receipt.commit_sha)
        validate_sha40(receipt.tree_sha)

        # Verify calls made
        patch_calls = [c for c in self.api.calls if c[0] == "PATCH"]
        self.assertEqual(len(patch_calls), 1)
        _, patch_path, patch_body = patch_calls[0]
        self.assertEqual(patch_path, f"/repos/{FIXED_REPOSITORY}/git/refs/{FIXED_REF}")
        self.assertFalse(patch_body["force"])
        self.assertEqual(patch_body["sha"], receipt.commit_sha)

        # Verify candidate commit structure
        commit = self.api.commits[receipt.commit_sha]
        self.assertEqual(commit["parents"], [{"sha": snap.head_sha}])
        self.assertEqual(commit["tree"]["sha"], receipt.tree_sha)

        # Verify tree structure
        tree = self.api.trees[receipt.tree_sha]
        expected_path = record_path_for_request_id(req_id)
        self.assertIn(expected_path, tree)
        self.assertEqual(tree[expected_path]["mode"], "100644")
        self.assertEqual(tree[expected_path]["type"], "blob")

    def test_lost_patch_response_proven_success(self) -> None:
        req_id = "test-lost-response-01"
        rec = json.dumps({"request_id": req_id, "state": "accepted"})
        snap = self.journal.load(req_id)

        # Simulate network failure on PATCH after ref is updated on server
        def patch_fault(body: dict[str, Any]) -> None:
            raise ApiError(500, "Network dropped / 500 error after ref updated")

        self.api.patch_hook = patch_fault

        # Even though PATCH raised, readback proves ref and commit are exact match
        receipt = self.journal.publish(snap, req_id, rec)
        self.assertIsInstance(receipt, PublicationReceipt)
        self.assertFalse(receipt.replayed)
        self.assertEqual(self.api.refs[FIXED_REF], receipt.commit_sha)

    def test_readback_mismatch_raises_ambiguous(self) -> None:
        req_id = "test-ambiguous-01"
        rec = json.dumps({"request_id": req_id, "state": "accepted"})
        snap = self.journal.load(req_id)

        # Scenario 1: Ref mismatch during readback
        self.api.readback_ref_hook = lambda: {
            "ref": f"refs/{FIXED_REF}",
            "object": {"sha": "0000000000000000000000000000000000000000", "type": "commit"},
        }
        with self.assertRaises(AmbiguousPublication) as ctx:
            self.journal.publish(snap, req_id, rec)
        self.assertEqual(ctx.exception.base_sha, snap.head_sha)
        validate_sha40(ctx.exception.candidate_sha)
        validate_sha40(ctx.exception.tree_sha)

        # Scenario 2: Commit tree mismatch during readback
        self.api.refs[FIXED_REF] = self.head_sha
        self.api.in_readback = False
        self.api.readback_ref_hook = None
        self.api.readback_commit_hook = lambda csha: {
            "sha": csha,
            "tree": {"sha": "9999999999999999999999999999999999999999"},
            "parents": [{"sha": snap.head_sha}],
            "message": "test",
        }
        with self.assertRaises(AmbiguousPublication):
            self.journal.publish(snap, req_id, rec)

        # Scenario 3: Commit parents mismatch during readback
        self.api.refs[FIXED_REF] = self.head_sha
        self.api.in_readback = False
        self.api.readback_commit_hook = lambda csha: {
            "sha": csha,
            "tree": {"sha": self.tree_sha},
            "parents": [{"sha": "8888888888888888888888888888888888888888"}],
            "message": "test",
        }
        with self.assertRaises(AmbiguousPublication):
            self.journal.publish(snap, req_id, rec)

        # Scenario 4: Readback GET ref raises 500
        self.api.refs[FIXED_REF] = self.head_sha
        self.api.in_readback = False
        self.api.readback_commit_hook = None
        self.api.readback_ref_hook = lambda: (_ for _ in ()).throw(ApiError(500, "Ref lookup down"))
        with self.assertRaises(AmbiguousPublication):
            self.journal.publish(snap, req_id, rec)

    def test_sibling_concurrent_updates_never_both_succeed(self) -> None:
        req_id_1 = "sibling-worker-1"
        req_id_2 = "sibling-worker-2"
        rec1 = json.dumps({"request_id": req_id_1, "state": "accepted"})
        rec2 = json.dumps({"request_id": req_id_2, "state": "accepted"})

        # Both workers take snapshot at initial head
        snap1 = self.journal.load(req_id_1)
        snap2 = self.journal.load(req_id_2)
        self.assertEqual(snap1.head_sha, snap2.head_sha)

        # Worker 1 publishes first and wins
        receipt1 = self.journal.publish(snap1, req_id_1, rec1)
        self.assertFalse(receipt1.replayed)
        self.assertEqual(self.api.refs[FIXED_REF], receipt1.commit_sha)

        # Worker 2 attempts publish: since ref moved to receipt1.commit_sha,
        # non-forced PATCH fails fast-forward check (or stale check before writing).
        # In either case, Worker 2 cannot succeed!
        with self.assertRaises((StaleSnapshotConflict, AmbiguousPublication)):
            self.journal.publish(snap2, req_id_2, rec2)

        # Sibling 1's commit remains the head
        self.assertEqual(self.api.refs[FIXED_REF], receipt1.commit_sha)

    def test_noop_replay_after_fresh_ref_equality(self) -> None:
        req_id = "test-replay-request-01"
        rec = json.dumps({"request_id": req_id, "state": "accepted"})
        snap = self.journal.load(req_id)

        # Initial publication
        receipt1 = self.journal.publish(snap, req_id, rec)
        self.assertFalse(receipt1.replayed)

        # Load fresh snapshot with the published record
        snap_published = self.journal.load(req_id)
        self.assertEqual(snap_published.record_json, rec)

        calls_before = len(self.api.calls)
        receipt2 = self.journal.publish(snap_published, req_id, rec)
        self.assertTrue(receipt2.replayed)
        self.assertEqual(receipt2.commit_sha, snap_published.head_sha)
        self.assertEqual(receipt2.tree_sha, snap_published.tree_sha)

        # Ensure no write calls were made during replay
        replay_calls = self.api.calls[calls_before:]
        self.assertTrue(all(method == "GET" for method, _, _ in replay_calls))

        # If ref moved during replay, must raise StaleSnapshotConflict
        new_commit = hashlib.sha1(b"concurrent commit 2").hexdigest()
        self.api.commits[new_commit] = {
            "sha": new_commit,
            "tree": {"sha": snap_published.tree_sha},
            "parents": [{"sha": snap_published.head_sha}],
            "message": "concurrent",
        }
        self.api.refs[FIXED_REF] = new_commit

        with self.assertRaises(StaleSnapshotConflict):
            self.journal.publish(snap_published, req_id, rec)

    def test_forged_snapshot_cannot_omit_existing_record(self) -> None:
        req_id = "test-forged-snapshot"
        record = json.dumps({"request_id": req_id, "state": "accepted"})
        self.journal.publish(self.journal.load(req_id), req_id, record)
        actual = self.journal.load(req_id)
        forged = JournalSnapshot(actual.head_sha, actual.tree_sha, None)
        calls = len(self.api.calls)
        with self.assertRaises(JournalValidationError):
            self.journal.publish(forged, req_id, record)
        self.assertTrue(all(method == "GET" for method, _, _ in self.api.calls[calls:]))

    def test_contents_followed_symlink_is_rejected_by_git_mode(self) -> None:
        req_id = "test-symlink-record"
        record = json.dumps({"request_id": req_id, "state": "accepted"})
        result = self.journal.publish(self.journal.load(req_id), req_id, record)
        path = record_path_for_request_id(req_id)
        self.api.trees[result.tree_sha][path]["mode"] = "120000"
        with self.assertRaises(JournalValidationError):
            self.journal.load(req_id)

    def test_modified_contents_cannot_reuse_a_pinned_blob_sha(self) -> None:
        req_id = "test-tampered-contents"
        record = json.dumps({"request_id": req_id, "state": "accepted"})
        self.journal.publish(self.journal.load(req_id), req_id, record)
        snapshot = self.journal.load(req_id)
        raw = json.dumps({"request_id": req_id, "state": "executing"}).encode()
        self.api.contents_hook = lambda _: {
            "type": "file", "encoding": "base64", "size": len(raw),
            "content": base64.b64encode(raw).decode(), "sha": snapshot.record_blob_sha,
        }
        with self.assertRaises(JournalValidationError):
            self.journal.load(req_id)

    def test_validator_transition_enforcement(self) -> None:
        req_id = "test-validator-enforcement"
        rec1 = json.dumps({"request_id": req_id, "state": "succeeded"})
        snap = self.journal.load(req_id)
        self.journal.publish(snap, req_id, rec1)

        snap2 = self.journal.load(req_id)
        # Attempt illegal transition: succeeded -> executing
        rec2 = json.dumps({"request_id": req_id, "state": "executing"})
        with self.assertRaises(JournalValidationError):
            self.journal.publish(snap2, req_id, rec2)


if __name__ == "__main__":
    unittest.main()
