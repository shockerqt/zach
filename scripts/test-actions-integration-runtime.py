"""Real bundle/ZIP bindings with synthetic producer and publication seams.

These tests establish no online authentication or integration lifecycle proof.
"""
import hashlib
from dataclasses import replace
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

import actions_integration_runtime as module
from actions_journal_coordinator import ActionsJournalCoordinator, TrustedIssuePolicy, CliProcessResult
from actions_request_handler import ExecutionBundle
from actions_ledger_candidate import read_integration_archive, CandidateError
from actions_ledger_producer import IntegrationProducerPolicy, ArtifactReference, REPOSITORY, REPOSITORY_ID
from actions_ledger_publication import LedgerPublicationPolicy, LedgerPublicationError

spec = importlib.util.spec_from_file_location("integration_handler_fixtures", Path(__file__).with_name("test-actions-request-handler.py"))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def archive(raw, name="integration-observation.json"):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr(name, raw)
    return output.getvalue()


class IntegrationRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.remote = fixtures.UnifiedFakeApi()
        coordinator = ActionsJournalCoordinator(fixtures.CLI, self.remote.request)
        params = {"base_sha": "4" * 40, "operation": "task.complete_verified",
                  "parameters": {"run_id": "GOV-041-20261020-original", "task_id": "GOV-041"}}
        event = fixtures.make_event(request_id="integration-runtime-01", operation="governance.ledger", parameters=params,
                                    repo_id=REPOSITORY_ID, repo_full_name=REPOSITORY)
        policy = TrustedIssuePolicy(REPOSITORY_ID, REPOSITORY, (2001,))
        accepted = coordinator.accept(event, policy, fixtures.ACCEPTED_AT, fixtures.POLICY_REVISION)
        claimed = coordinator.claim(accepted.request_id, "100-1")
        record = json.loads(claimed.record_json)
        self.bundle = ExecutionBundle(accepted.request_id, record["request_digest"], "governance.ledger",
            REPOSITORY_ID, REPOSITORY, 501, 42, "100-1", claimed.record_json,
            accepted.durable_revision, claimed.durable_revision, params)
        self.policy = IntegrationProducerPolicy(10, fixtures.POLICY_REVISION, "a" * 40)
        self.publication_policy = LedgerPublicationPolicy("GOV-041", "tasks/GOV-041-workspace-command-fast-path.md", "task/GOV-041-workspace-command-fast-path")
        self.data = {"schema_version": 1, "task_id": "GOV-041", "run_id": params["parameters"]["run_id"],
            "repository": "governance", "branch": self.publication_policy.branch,
            "request_id": self.bundle.request_id, "request_digest": self.bundle.request_digest,
            "accepted_journal_sha": self.bundle.accepted_revision, "policy_revision": self.policy.workflow_revision,
            "tool_revision": self.policy.tool_revision, "verified_at": fixtures.ACCEPTED_AT,
            "implementation": {"sha": "1" * 40, "ci_sha": "1" * 40, "ci_run_url": "synthetic", "pr_url": "synthetic", "pr_head_sha": "1" * 40},
            "integration": {"merge_commit_sha": "2" * 40, "merged_at": fixtures.ACCEPTED_AT,
                "post_merge_ci_sha": "2" * 40, "post_merge_ci_run_url": "synthetic", "post_merge_ci_conclusion": "success",
                "pull_request_merged": True, "implementation_represented": True,
                "cleanup": {"remote_branch": "retained", "local_worktree": "not-applicable", "local_branch": "not-applicable"}}}
        self.first = {"producer_started_at": "2026-09-05T07:00:00Z", "producer_completed_at": "2026-09-05T08:00:00Z", "producer_job_id": 123}
        self.handoff = {"stage": "integration-observed", "producer_run_id": 100, "producer_run_attempt": 1,
            "artifact_name": "workspace-integration-observation-100-1", "content_sha256": hashlib.sha256(canonical(self.data)).hexdigest()}
        self.api = Mock()
        self.publisher = Mock()

    def prepare_archive(self):
        raw = canonical(self.data)
        zipped = archive(raw)
        reference = ArtifactReference(REPOSITORY_ID, REPOSITORY, 100, 1, 99,
            hashlib.sha256(zipped).hexdigest(), hashlib.sha256(raw).hexdigest())
        self.handoff["content_sha256"] = reference.content_sha256
        self.api.download_artifact.return_value = zipped
        return reference

    def runtime(self):
        return module.IntegrationPublisherRuntime(self.api, self.policy, self.publication_policy,
            "/trusted/candidate", "/trusted/mirror", clock=lambda: "2026-09-05T08:05:00Z")

    def test_real_zip_bounds_digest_and_fixed_filename(self):
        for size in (1, 32768):
            raw = b"x" * size
            zipped = archive(raw)
            self.assertEqual(read_integration_archive(zipped, hashlib.sha256(zipped).hexdigest()), raw)
        for zipped, digest in ((archive(b"x" * 32769), None), (archive(b"x", "candidate.json"), None), (archive(b"x"), "0" * 64)):
            with self.assertRaises(CandidateError):
                read_integration_archive(zipped, digest or hashlib.sha256(zipped).hexdigest())

    def test_authenticated_source_precedes_parse_and_explicit_closure_derivation(self):
        reference = self.prepare_archive()
        order = []
        def observe(*args):
            order.append("observe")
            return self.first
        def derive(bundle, cli, mirror, context, **kwargs):
            order.append("derive")
            self.assertEqual(kwargs, {"integration_closure": True})
            self.assertEqual(context["integration_attestation"]["observations"], self.data)
            self.assertEqual(context["integration_attestation"]["verification"]["artifact_sha256"], reference.archive_sha256)
            return b"candidate"
        def publish(*args):
            order.append("effect-gate")
            args[-1]()
            return {"synthetic": True}
        with patch.object(module, "_artifact_reference", return_value=reference), patch.object(module, "_recover_publication", return_value=None), \
             patch.object(module, "observe_integration_producer", side_effect=observe), \
             patch.object(module, "derive_bound_candidate", side_effect=derive), \
             patch.object(module, "validate_bound_candidate", return_value={"synthetic": "artifact"}), \
             patch.object(module, "_publish_validated_candidate", side_effect=publish):
            self.assertEqual(self.runtime()(self.publisher, self.bundle, self.handoff), {"synthetic": True})
        self.assertEqual(order, ["observe", "derive", "effect-gate", "observe"])

    def test_authentication_failure_prevents_download_parse_derivation_and_effect(self):
        reference = self.prepare_archive()
        with patch.object(module, "_artifact_reference", return_value=reference), patch.object(module, "_recover_publication", return_value=None), \
             patch.object(module, "observe_integration_producer", side_effect=ValueError("untrusted")), \
             patch.object(module, "_observations") as parse, patch.object(module, "derive_bound_candidate") as derive, \
             patch.object(module, "_publish_validated_candidate") as effect, self.assertRaises(LedgerPublicationError):
            self.runtime()(self.publisher, self.bundle, self.handoff)
        self.api.download_artifact.assert_not_called()
        parse.assert_not_called(); derive.assert_not_called(); effect.assert_not_called()

    def test_checkpoint_recovery_precedes_producer_download_and_derivation(self):
        reference = self.prepare_archive()
        with patch.object(module, "_artifact_reference", return_value=reference), patch.object(module, "_recover_publication", return_value={"replayed": True}), \
             patch.object(module, "observe_integration_producer") as observe, patch.object(module, "derive_bound_candidate") as derive:
            self.assertEqual(self.runtime()(self.publisher, self.bundle, self.handoff), {"replayed": True})
        observe.assert_not_called(); derive.assert_not_called(); self.api.download_artifact.assert_not_called()

    def test_real_bundle_binding_and_content_digest_fail_closed(self):
        changed = replace(self.bundle, parameters=dict(self.bundle.parameters, base_sha="0" * 40))
        with patch.object(module, "_artifact_reference") as reference, self.assertRaises(LedgerPublicationError):
            self.runtime()(self.publisher, changed, self.handoff)
        reference.assert_not_called()
        reference = replace(self.prepare_archive(), content_sha256="0" * 64)
        with patch.object(module, "_artifact_reference", return_value=reference), patch.object(module, "_recover_publication", return_value=None), \
             patch.object(module, "observe_integration_producer", return_value=self.first), patch.object(module, "_observations") as parse, \
             patch.object(module, "derive_bound_candidate") as derive, self.assertRaises(LedgerPublicationError):
            self.runtime()(self.publisher, self.bundle, self.handoff)
        parse.assert_not_called(); derive.assert_not_called()

    def test_bad_observation_bindings_or_time_fail_before_derivation(self):
        for field, value in (("request_digest", "0" * 64), ("policy_revision", "0" * 40), ("verified_at", "2026-09-05T09:00:00Z")):
            original = self.data[field]
            self.data[field] = value
            reference = self.prepare_archive()
            with self.subTest(field=field), patch.object(module, "_artifact_reference", return_value=reference), patch.object(module, "_recover_publication", return_value=None), \
                 patch.object(module, "observe_integration_producer", return_value=self.first), \
                 patch.object(module, "derive_bound_candidate") as derive, patch.object(module, "_publish_validated_candidate") as effect, self.assertRaises(LedgerPublicationError):
                self.runtime()(self.publisher, self.bundle, self.handoff)
            derive.assert_not_called(); effect.assert_not_called()
            self.data[field] = original

    def test_derivation_or_final_producer_recheck_failure_cannot_return_effect(self):
        reference = self.prepare_archive()
        for fail_derive in (True, False):
            effects = []
            def effect(*args):
                args[-1]()
                effects.append("write")
            with patch.object(module, "_artifact_reference", return_value=reference), patch.object(module, "_recover_publication", return_value=None), \
                 patch.object(module, "observe_integration_producer", side_effect=[self.first, dict(self.first, producer_job_id=999)]), \
                 patch.object(module, "derive_bound_candidate", side_effect=ValueError("reject") if fail_derive else None, return_value=b"candidate"), \
                 patch.object(module, "validate_bound_candidate", return_value={}), patch.object(module, "_publish_validated_candidate", side_effect=effect), self.assertRaises(LedgerPublicationError):
                self.runtime()(self.publisher, self.bundle, self.handoff)
            self.assertEqual(effects, [])

    def test_observer_builds_input_from_bundle_and_only_trusted_process_receives_token(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "observation.json"
            def run(argv, token):
                self.assertEqual(token, "synthetic-token")
                source = json.loads(Path(argv[2]).read_text())
                self.assertEqual(source["request"]["governance_sha"], self.bundle.parameters["base_sha"])
                self.assertEqual(source["bindings"]["request_digest"], self.bundle.request_digest)
                Path(argv[4]).write_bytes(canonical(self.data))
                return CliProcessResult(0, b"", b"")
            runtime = module.IntegrationObservationRuntime("/usr/bin/true", str(output), "synthetic-token", self.policy, clock=lambda: self.data["verified_at"])
            with patch.object(ActionsJournalCoordinator, "_run_observer_subprocess", side_effect=run), patch.object(module, "derive_bound_candidate") as derive:
                handoff = runtime(self.bundle)
            self.assertEqual(output.read_bytes(), canonical(self.data))
            self.assertEqual(handoff, self.handoff)
            derive.assert_not_called()
            output.unlink()
            self.data["request_digest"] = "0" * 64
            with patch.object(ActionsJournalCoordinator, "_run_observer_subprocess", side_effect=run), self.assertRaises(LedgerPublicationError):
                runtime(self.bundle)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
