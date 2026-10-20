"""Fake-API adversarial tests; no server or artifact-download proof."""
import copy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from actions_ledger_producer import (ArtifactReference, LedgerProducerPolicy,
                                    IntegrationProducerPolicy, observe_integration_producer,
                                    LedgerProducerError, observe_ledger_producer,
                                    REPOSITORY, REPOSITORY_ID)


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.sha = "a" * 40
        self.policy = LedgerProducerPolicy(41, self.sha, "b" * 40)
        self.ref = ArtifactReference(REPOSITORY_ID, REPOSITORY, 51, 1, 61, "c" * 64, "d" * 64)
        self.bundle = SimpleNamespace(operation="governance.ledger", execution_id="51-1")
        root = "/repos/" + REPOSITORY
        self.root = root
        repo = {"id": REPOSITORY_ID, "full_name": REPOSITORY}
        self.artifact = {"id": 61, "name": "workspace-ledger-candidate-51-1", "expired": False,
                         "size_in_bytes": 500, "digest": "sha256:" + "c" * 64,
                         "created_at": "2026-10-11T02:00:30Z", "updated_at": "2026-10-11T02:00:30Z",
                         "expires_at": "2026-10-12T02:00:00Z",
                         "workflow_run": {"id": 51, "repository_id": REPOSITORY_ID,
                                          "head_repository_id": REPOSITORY_ID,
                                          "head_sha": self.sha, "head_branch": "master"}}
        self.job = {"id": 71, "name": "control", "run_id": 51, "run_attempt": 1,
                    "head_sha": self.sha, "status": "completed", "conclusion": "success",
                    "started_at": "2026-10-11T02:00:00Z", "completed_at": "2026-10-11T02:01:00Z"}
        self.responses = {
            root: dict(repo, default_branch="master"),
            root + "/actions/workflows/41": {"id": 41, "path": self.policy.workflow_path, "state": "active"},
            root + "/git/ref/heads/master": {"object": {"sha": self.sha}},
            "/repos/shockerqt/zach/git/ref/heads/main": {"object": {"sha": "b" * 40}},
            root + "/actions/runs/51/attempts/1": {"id": 51, "run_attempt": 1, "workflow_id": 41,
                "path": self.policy.workflow_path, "head_sha": self.sha, "event": "issues", "head_branch": "master",
                "actor": {"id": 81}, "repository": repo, "head_repository": repo, "status": "in_progress"},
            root + "/actions/runs/51/attempts/1/jobs?per_page=100&page=1": {"total_count": 1, "jobs": [self.job]},
            root + "/actions/artifacts/61": self.artifact,
            root + "/actions/runs/51/artifacts?per_page=100&page=1": {"total_count": 1, "artifacts": [self.artifact]},
        }

    def observe(self, ref=None, *, public_available=True, observer=observe_ledger_producer):
        def api(method, path, body=None):
            self.assertEqual(method, "GET")
            self.assertIsNone(body)
            self.assertTrue(path.startswith(self.root), "Zach must never use Publisher token namespace")
            return copy.deepcopy(self.responses[path])
        def public_zach_get(path):
            self.assertTrue(path.startswith("/repos/shockerqt/zach/"))
            return copy.deepcopy(self.responses[path])
        if public_available:
            api.public_zach_get = public_zach_get
        with patch("actions_ledger_producer._validate_execution_bundle", return_value={"policy_revision": self.sha, "author_id": 80, "sender_id": 81}):
            return observer(api, self.bundle, ref or self.ref, self.policy, "2026-10-11T03:00:00Z")

    def test_success_and_observation_changes(self):
        original = self.observe()
        self.assertEqual(original["producer_job_id"], 71)
        self.artifact["updated_at"] = "2026-10-11T02:00:31Z"
        self.assertNotEqual(original, self.observe())

    def test_missing_public_capability_is_not_authenticated_fallback(self):
        with self.assertRaisesRegex(LedgerProducerError, "producer_public_observation_unavailable"):
            self.observe(public_available=False)

    def test_public_zach_ancestry_remains_strict(self):
        head = "e" * 40
        self.responses["/repos/shockerqt/zach/git/ref/heads/main"] = {"object": {"sha": head}}
        path = "/repos/shockerqt/zach/compare/" + "b" * 40 + "..." + head
        self.responses[path] = {"status": "ahead", "base_commit": {"sha": "b" * 40},
                                "merge_base_commit": {"sha": "b" * 40}}
        self.observe()
        for key, changed in [("status", "diverged"), ("base_commit", {"sha": head}),
                             ("merge_base_commit", {"sha": head})]:
            old = self.responses[path][key]
            self.responses[path][key] = changed
            with self.subTest(key=key), self.assertRaises(LedgerProducerError):
                self.observe()
            self.responses[path][key] = old

    def test_attempt_bound(self):
        from dataclasses import replace
        with self.assertRaises(LedgerProducerError):
            self.observe(replace(self.ref, run_attempt=2))

    def test_boolean_metadata_ids_rejected(self):
        run = self.responses[self.root + "/actions/runs/51/attempts/1"]
        workflow = self.responses[self.root + "/actions/workflows/41"]
        for target, key in [(run, "id"), (run, "workflow_id"), (run, "run_attempt"),
                            (workflow, "id"), (self.job, "id"), (self.job, "run_id"),
                            (self.job, "run_attempt"), (self.artifact, "id"),
                            (self.artifact["workflow_run"], "id"),
                            (self.artifact["workflow_run"], "repository_id"),
                            (self.artifact["workflow_run"], "head_repository_id")]:
            old = target[key]
            target[key] = True
            with self.subTest(key=key), self.assertRaises(LedgerProducerError):
                self.observe()
            target[key] = old

    def test_actor_binds_sender_not_author(self):
        self.observe()  # author 80 differs from authorized sender 81.
        run = self.responses[self.root + "/actions/runs/51/attempts/1"]
        run["actor"]["id"] = 80
        with self.assertRaises(LedgerProducerError):
            self.observe()

    def test_hostile_observations(self):
        run = self.responses[self.root + "/actions/runs/51/attempts/1"]
        jobs = self.responses[self.root + "/actions/runs/51/attempts/1/jobs?per_page=100&page=1"]
        artifacts = self.responses[self.root + "/actions/runs/51/artifacts?per_page=100&page=1"]
        cases = [(self.job, "status", "in_progress"), (self.job, "conclusion", "failure"),
                 (self.artifact, "expired", True), (self.artifact, "digest", "sha256:" + "e" * 64),
                 (self.artifact, "created_at", "2026-10-11T01:00:00Z"),
                 (self.artifact, "expires_at", "2026-10-11T02:00:00Z"),
                 (run, "head_sha", "e" * 40), (run, "actor", {"id": 82}),
                 (jobs, "total_count", 2), (artifacts, "artifacts", []),
                 (artifacts, "total_count", 2)]
        for target, key, hostile in cases:
            old = target[key]
            target[key] = hostile
            with self.subTest(key=key, hostile=hostile), self.assertRaises(LedgerProducerError):
                self.observe()
            target[key] = old
        duplicate = dict(self.artifact, id=62)
        artifacts.update(total_count=2, artifacts=[self.artifact, duplicate])
        with self.assertRaises(LedgerProducerError):
            self.observe()

    def test_revision_representation(self):
        path = self.root + "/git/ref/heads/master"
        head = "e" * 40
        self.responses[path] = {"object": {"sha": head}}
        compare = self.root + f"/compare/{self.sha}...{head}"
        self.responses[compare] = {"status": "ahead", "base_commit": {"sha": self.sha},
                                   "merge_base_commit": {"sha": self.sha}}
        self.observe()
        self.responses[compare]["status"] = "diverged"
        with self.assertRaises(LedgerProducerError):
            self.observe()


class IntegrationProducerTests(ProducerTests):
    """Same mock HTTP proofs applied to the distinct fixed verification profile."""
    def setUp(self):
        super().setUp()
        self.policy = IntegrationProducerPolicy(41, self.sha, "b" * 40)
        self.bundle.parameters = {"operation": "task.complete_verified"}
        self.job["name"] = "verify"
        self.artifact["name"] = "workspace-integration-observation-51-1"
        self.responses[self.root + "/actions/workflows/41"]["path"] = self.policy.workflow_path
        self.responses[self.root + "/actions/runs/51/attempts/1"]["path"] = self.policy.workflow_path

    def observe(self, ref=None, *, public_available=True, observer=observe_integration_producer):
        return super().observe(ref, public_available=public_available, observer=observer)

    def test_cross_profile_and_operation_rejected(self):
        from dataclasses import replace
        self.observe()
        with self.assertRaisesRegex(LedgerProducerError, "producer_policy_invalid"):
            self.observe(observer=observe_ledger_producer)
        integration_policy = self.policy
        self.policy = LedgerProducerPolicy(41, self.sha, "b" * 40)
        with self.assertRaisesRegex(LedgerProducerError, "producer_policy_invalid"):
            self.observe()
        with self.assertRaisesRegex(LedgerProducerError, "producer_operation_invalid"):
            self.observe(observer=observe_ledger_producer)
        self.policy = integration_policy
        for operation in ("run.record_evidence", "run.record_remote_evidence", None):
            self.bundle.parameters = {"operation": operation}
            with self.subTest(operation=operation), self.assertRaisesRegex(LedgerProducerError, "producer_operation_invalid"):
                self.observe()
        self.bundle.parameters = {"operation": "task.complete_verified"}
        for key, value in (("workflow_path", ".github/workflows/workspace-ledger-pilot.yml"),
                           ("producer_job_name", "control"), ("artifact_prefix", "workspace-ledger-candidate")):
            self.policy = replace(integration_policy, **{key: value})
            with self.subTest(key=key), self.assertRaisesRegex(LedgerProducerError, "producer_policy_invalid"):
                self.observe()

    def test_wrong_profile_observations_rejected(self):
        workflow = self.responses[self.root + "/actions/workflows/41"]
        run = self.responses[self.root + "/actions/runs/51/attempts/1"]
        for target, key, value in ((workflow, "path", ".github/workflows/workspace-ledger-pilot.yml"),
                                   (run, "path", ".github/workflows/workspace-ledger-pilot.yml"),
                                   (self.job, "name", "control"),
                                   (self.artifact, "name", "workspace-ledger-candidate-51-1")):
            old = target[key]
            target[key] = value
            with self.subTest(key=key), self.assertRaises(LedgerProducerError):
                self.observe()
            target[key] = old


if __name__ == "__main__":
    unittest.main()
