"""Publication effect mechanics only; mocked seams do not prove online authority."""
import base64
from dataclasses import asdict
import hashlib
import io
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from actions_ledger_producer import ArtifactReference
import actions_ledger_publication as module


BASE, TREE, RESULT, COMMIT, REVISION = (character * 40 for character in "abcde")
BRANCH = "task/GOV-041-workspace-command-fast-path"
POLICY = module.LedgerPublicationPolicy("GOV-041", "tasks/GOV-041-workspace-command-fast-path.md", BRANCH)
OWNER = ("---\nkind: task\nschema_version: 1\nid: GOV-041\nstatus: active\nproject: governance\n"
         f"target_repository: governance\nbranch: {BRANCH}\n---\n# Owner\n").encode()
OWNER_SHA = hashlib.sha1(b"blob " + str(len(OWNER)).encode() + b"\0" + OWNER).hexdigest()


class Api:
    def __init__(self):
        self.head = BASE
        self.calls = []
        self.commits = {BASE: {"sha": BASE, "tree": {"sha": TREE}, "parents": []}}
        self.checkpoint = None
        self.patch_mode = "ok"
        self.bad_tree = False
        self.owner = OWNER
        self.owner_mode = "100644"
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("candidate.json", b"candidate")
        self.archive = buffer.getvalue()

    def __call__(self, method, path, body=None):
        self.calls.append((method, path, body))
        tail = path.split("/workspace-governance/", 1)[1]
        owner_sha = hashlib.sha1(b"blob " + str(len(self.owner)).encode() + b"\0" + self.owner).hexdigest()
        if method == "GET" and tail.startswith("git/ref/"):
            return {"ref": "refs/heads/" + BRANCH, "object": {"type": "commit", "sha": self.head}}
        if method == "GET" and tail.startswith("git/commits/"):
            return self.commits[tail.rsplit("/", 1)[1]]
        if method == "GET" and tail == "git/trees/" + TREE:
            return {"sha": TREE, "truncated": False, "tree": [{"path": "tasks", "type": "tree", "mode": "040000", "sha": "f" * 40}]}
        if method == "GET" and tail == "git/trees/" + "f" * 40:
            return {"sha": "f" * 40, "truncated": False, "tree": [{"path": POLICY.owner_task_path.split("/")[1], "mode": self.owner_mode, "type": "blob", "sha": owner_sha}]}
        if method == "GET" and tail == "git/blobs/" + owner_sha:
            return {"sha": owner_sha, "encoding": "base64", "size": len(self.owner), "content": base64.b64encode(self.owner).decode()}
        if method == "POST" and tail == "git/blobs":
            raw = base64.b64decode(body["content"])
            return {"sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}
        if method == "POST" and tail == "git/trees":
            return {"sha": TREE if self.bad_tree else RESULT}
        if method == "POST" and tail == "git/commits":
            self.commits[COMMIT] = {"sha": COMMIT, "tree": {"sha": body["tree"]}, "parents": [{"sha": value} for value in body["parents"]]}
            return self.commits[COMMIT]
        if method == "PATCH":
            assert self.checkpoint is not None, "No ref effect before checkpoint"
            assert self.head == BASE and body == {"sha": COMMIT, "force": False}
            if self.patch_mode != "no_effect":
                self.head = body["sha"]
            if self.patch_mode != "ok":
                raise RuntimeError("lost response")
            return {}
        raise AssertionError((method, tail))

    def download_artifact(self, _repo, _identifier):
        return self.archive

    def load_ledger_publication_checkpoint(self, _bundle):
        return self.checkpoint

    def checkpoint_ledger_publication(self, bundle, publication):
        self.calls.append(("checkpoint", "", None))
        self.checkpoint = SimpleNamespace(bundle=bundle, publication=publication, comment_id=42)
        return self.checkpoint


class Tests(unittest.TestCase):
    def setUp(self):
        self.api = Api()
        self.bundle = SimpleNamespace(operation="governance.ledger", request_id="request-001", parameters={"operation": "run.record_evidence"})
        self.producer = SimpleNamespace(workflow_revision=REVISION)
        self.reference = ArtifactReference(1260920764, module.REPOSITORY, 100, 1, 200,
            hashlib.sha256(self.api.archive).hexdigest(), hashlib.sha256(b"candidate").hexdigest())
        content = "evidence\n"
        raw = content.encode()
        self.now = "2026-10-11T00:00:00Z"
        self.clock = lambda: self.now
        self.candidate = {"inner_request": {"created_at": "2026-10-10T23:30:00Z", "expires_at": "2026-10-11T00:30:00Z"},
            "candidate": {"base_sha": BASE, "validated_tree_sha": RESULT, "changes": [
            {"path": "runs/GOV-041/active.md", "operation": "upsert", "content": content,
             "blob_sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}]}}

    def invoke(self):
        with patch.object(module, "_validate_execution_bundle", return_value={"policy_revision": REVISION}), \
             patch.object(module, "observe_ledger_producer", return_value={"stable": "observation"}), \
             patch.object(module, "derive_bound_candidate", return_value=b"candidate"), \
             patch.object(module, "validate_bound_candidate", return_value=self.candidate):
            return module.publish_ledger_candidate(self.api, self.api, self.bundle, self.reference,
                self.producer, POLICY, "/trusted/cli", "/trusted/mirror", self.now, clock=self.clock)

    def test_published_checkpoint_precedes_nonforced_patch_and_replay_is_read_only(self):
        result = self.invoke()
        self.assertFalse(result["replayed"])
        self.assertEqual(self.api.head, COMMIT)
        self.api.calls.clear()
        self.assertTrue(self.invoke()["replayed"])
        self.assertTrue(all(method == "GET" for method, _, _ in self.api.calls))

    def test_lost_patch_response_is_reconciled_without_repeat(self):
        self.api.patch_mode = "lost_response"
        self.invoke()
        self.assertEqual(sum(method == "PATCH" for method, _, _ in self.api.calls), 1)

    def test_uncertain_effect_blocks_retry_writes(self):
        self.api.patch_mode = "no_effect"
        with self.assertRaisesRegex(module.LedgerPublicationError, "ledger_publication_ambiguous"):
            self.invoke()
        self.api.calls.clear()
        with self.assertRaises(module.LedgerPublicationError):
            self.invoke()
        self.assertTrue(all(method == "GET" for method, _, _ in self.api.calls))

    def test_ref_conflict_and_owner_spoof_precede_writes(self):
        for fault in ("ref", "owner", "mode"):
            self.setUp()
            if fault == "ref": self.api.head = "f" * 40
            if fault == "owner": self.api.owner = OWNER.replace(b"governance", b"infrastructure", 1)
            if fault == "mode": self.api.owner_mode = "120000"
            with self.assertRaises(module.LedgerPublicationError): self.invoke()
            self.assertFalse(any(method in ("POST", "PATCH", "checkpoint") for method, _, _ in self.api.calls))

    def test_materialized_wrong_tree_never_gets_checkpoint_or_patch(self):
        self.api.bad_tree = True
        with self.assertRaisesRegex(module.LedgerPublicationError, "ledger_tree_mismatch"): self.invoke()
        self.assertFalse(any(method in ("PATCH", "checkpoint") for method, _, _ in self.api.calls))

    def test_correctly_hashed_ambiguous_yaml_owner_cannot_authorize(self):
        for decoration in ('"target_repository": infrastructure', "'branch': task/GOV-999-wrong",
                           "? target_repository\n: infrastructure", "<<: {target_repository: infrastructure}",
                           "target_repository: infrastructure", "&key target_repository: infrastructure"):
            self.setUp()
            self.api.owner = OWNER.replace(b"\n---\n", b"\n" + decoration.encode() + b"\n---\n", 1)
            with self.assertRaisesRegex(module.LedgerPublicationError, "ledger_owner_ambiguous"):
                self.invoke()
            self.assertFalse(any(method in ("POST", "PATCH", "checkpoint") for method, _, _ in self.api.calls))

    def test_noop_has_exact_base_tree_and_no_git_writes(self):
        self.candidate["candidate"].update(changes=[], validated_tree_sha=TREE)
        self.assertEqual(self.invoke()["publication"]["commit_sha"], BASE)
        self.assertFalse(any(method in ("POST", "PATCH") for method, _, _ in self.api.calls))

    def test_expired_request_has_no_new_writes_but_recovery_remains_read_only(self):
        self.invoke()
        self.now = "2026-10-11T00:30:00Z"
        self.api.calls.clear()
        self.assertTrue(self.invoke()["replayed"])
        self.assertTrue(all(method == "GET" for method, _, _ in self.api.calls))
        self.api.checkpoint = None
        self.api.head = BASE
        self.api.calls.clear()
        with self.assertRaisesRegex(module.LedgerPublicationError, "ledger_request_expired"):
            self.invoke()
        self.assertFalse(any(method in ("POST", "PATCH", "checkpoint") for method, _, _ in self.api.calls))

    def test_expiration_during_publication_prevents_ref_update(self):
        moments = iter([self.now, "2026-10-11T00:30:00Z"])
        self.clock = lambda: next(moments)
        with self.assertRaisesRegex(module.LedgerPublicationError, "ledger_request_expired"):
            self.invoke()
        self.assertEqual(self.api.head, BASE)
        self.assertFalse(any(method == "PATCH" for method, _, _ in self.api.calls))

    def test_fractional_expiration_is_exact_and_invalid_calendar_fails_closed(self):
        self.candidate["inner_request"]["expires_at"] = "2026-10-11T00:00:00.00000001Z"
        self.now = "2026-10-11T00:00:00.000000009Z"
        self.invoke()
        self.setUp()
        self.candidate["inner_request"]["expires_at"] = "2026-02-30T00:00:00Z"
        with self.assertRaisesRegex(module.LedgerPublicationError, "ledger_time_invalid"):
            self.invoke()
        self.assertFalse(any(method in ("POST", "PATCH", "checkpoint") for method, _, _ in self.api.calls))


if __name__ == "__main__":
    unittest.main()
