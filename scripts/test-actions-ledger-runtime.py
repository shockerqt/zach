"""Local runtime wiring tests; synthetic API fixtures confer no remote authority."""
from dataclasses import asdict
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

import actions_ledger_runtime as runtime
import actions_ledger_publication as publication
from actions_ledger_producer import ArtifactReference, LedgerProducerPolicy, REPOSITORY
from actions_request_handler import _validate_execution_bundle

spec = importlib.util.spec_from_file_location("runtime_handler_fixtures", Path(__file__).with_name("test-actions-request-handler.py"))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)

POLICY = publication.LedgerPublicationPolicy("GOV-041", "tasks/GOV-041-workspace-command-fast-path.md", "task/GOV-041-workspace-command-fast-path")
PRODUCER = LedgerProducerPolicy(10, fixtures.POLICY_REVISION, "b" * 40)


class Api:
    def __init__(self, pages):
        self.pages, self.calls = pages, []
        self.archive = b""

    def __call__(self, method, path, body=None):
        assert method == "GET" and body is None
        self.calls.append(path)
        assert path.startswith(f"/repos/{REPOSITORY}/actions/runs/123/artifacts?")
        return self.pages[int(path.rsplit("=", 1)[1]) - 1]

    def download_artifact(self, repository, identifier):
        assert repository == REPOSITORY and identifier == 200
        return self.archive


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        with patch.object(fixtures, "EXECUTION_ID", "123-1"):
            fixture = fixtures.LedgerPublicationCheckpointTests()
            fixture.setUp()
        self.bundle = fixture.bundle
        _validate_execution_bundle(self.bundle)
        self.content = b"synthetic candidate"
        self.handoff = {"stage": "candidate-ready", "producer_run_id": 123,
            "producer_run_attempt": 1, "artifact_name": "workspace-ledger-candidate-123-1",
            "content_sha256": hashlib.sha256(self.content).hexdigest()}
        self.artifact = {"id": 200, "name": self.handoff["artifact_name"], "digest": "sha256:" + "c" * 64}
        self.publisher = Mock()
        self.publisher.load_ledger_publication_checkpoint.return_value = None

    def invoke(self, api, handoff=None):
        return runtime.LedgerPublisherRuntime(api, PRODUCER, POLICY, "/trusted/cli", "/trusted/mirror", clock=lambda: "2026-10-11T00:00:00Z")(self.publisher, self.bundle, self.handoff if handoff is None else handoff)

    def test_configuration_fails_closed(self):
        for paths in (("relative", "/mirror", "/output"), ("/cli", None, "/output"), ("/cli", "/mirror", "output")):
            with self.assertRaisesRegex(publication.LedgerPublicationError, "ledger_configuration_invalid"):
                runtime.LedgerCandidateRuntime(*paths)
        api = Api([])
        for arguments in ((lambda *a: {}, PRODUCER, POLICY, "/cli", "/mirror"),
                          (api, {}, POLICY, "/cli", "/mirror"),
                          (api, PRODUCER, {}, "/cli", "/mirror"),
                          (api, PRODUCER, POLICY, "cli", "/mirror")):
            with self.assertRaises(publication.LedgerPublicationError):
                runtime.LedgerPublisherRuntime(*arguments)
        with self.assertRaises(publication.LedgerPublicationError):
            runtime.LedgerPublisherRuntime(api, PRODUCER, POLICY, "/cli", "/mirror", clock="untrusted")

    def test_candidate_wrapper_uses_bound_bundle_and_private_exclusive_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = directory + "/candidate.json"
            callback = runtime.LedgerCandidateRuntime("/trusted/cli", "/trusted/mirror", output)
            with patch.dict(os.environ, {"GITHUB_TOKEN": "synthetic-secret"}), patch.object(runtime, "derive_bound_candidate", return_value=self.content) as derive:
                self.assertEqual(callback(self.bundle), self.handoff)
                derive.assert_called_once_with(self.bundle, "/trusted/cli", "/trusted/mirror", {})
                self.assertEqual(Path(output).read_bytes(), self.content)
                self.assertEqual(stat.S_IMODE(os.stat(output).st_mode), 0o600)
                with self.assertRaisesRegex(publication.LedgerPublicationError, "ledger_candidate_output_failed"):
                    callback(self.bundle)
                self.assertEqual(Path(output).read_bytes(), self.content)
                link = directory + "/link.json"
                os.symlink(output, link)
                with self.assertRaises(publication.LedgerPublicationError):
                    runtime.LedgerCandidateRuntime("/trusted/cli", "/trusted/mirror", link)(self.bundle)
                self.assertEqual(Path(output).read_bytes(), self.content)

    def test_handoff_exact_binding_precedes_checkpoint_or_lookup(self):
        faults = {"producer_run_id": 124, "producer_run_attempt": 2, "artifact_name": "other",
                  "content_sha256": "not-a-digest", "stage": "success", "extra": True}
        for key, value in faults.items():
            handoff = dict(self.handoff, **{key: value})
            api = Api([])
            with self.subTest(key=key), self.assertRaisesRegex(publication.LedgerPublicationError, "ledger_handoff_invalid"):
                self.invoke(api, handoff)
            self.assertEqual(api.calls, [])
        self.publisher.load_ledger_publication_checkpoint.assert_not_called()

    def test_control_shared_profile_passes_empty_context_to_candidate(self):
        # Guard/wiring test only: authentication and Rust derivation are seams.
        self.assertIs(runtime.EMPTY_CONTEXT_LEDGER_OPERATIONS, publication.EMPTY_CONTEXT_LEDGER_OPERATIONS)
        self.assertIsInstance(runtime.EMPTY_CONTEXT_LEDGER_OPERATIONS, frozenset)
        for operation in ("run.record_evidence", "run.transition_status", "task.append_run", "task.transition_status"):
            bundle = SimpleNamespace(operation="governance.ledger", parameters={"operation": operation}, execution_id="123-1")
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory, \
                 patch.object(runtime, "_validate_execution_bundle") as validate, \
                 patch.object(runtime, "derive_bound_candidate", return_value=self.content) as derive:
                callback = runtime.LedgerCandidateRuntime("/trusted/cli", "/trusted/mirror", directory + "/candidate.json")
                self.assertEqual(callback(bundle), self.handoff)
                validate.assert_called_once_with(bundle)
                derive.assert_called_once_with(bundle, "/trusted/cli", "/trusted/mirror", {})

    def test_control_unavailable_profiles_never_derive_or_write(self):
        # A synthetic validated bundle isolates the composition gate itself.
        for operation in ("run.create", "task.start_run", "run.record_remote_evidence", "task.create", "task.complete", "task.complete_verified", "unknown", None):
            bundle = SimpleNamespace(operation="governance.ledger", parameters={"operation": operation}, execution_id="123-1")
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory, \
                 patch.object(runtime, "_validate_execution_bundle"), \
                 patch.object(runtime, "derive_bound_candidate") as derive:
                output = directory + "/candidate.json"
                with self.assertRaisesRegex(publication.LedgerPublicationError, "ledger_context_profile_unavailable"):
                    runtime.LedgerCandidateRuntime("/trusted/cli", "/trusted/mirror", output)(bundle)
                derive.assert_not_called()
                self.assertFalse(Path(output).exists())

    def test_control_propagates_candidate_lifecycle_rejection_without_output(self):
        # The rejection is injected here; actual lifecycle proof is Rust/Git.
        bundle = SimpleNamespace(operation="governance.ledger", parameters={"operation": "task.transition_status", "parameters": {"target_status": "completed"}}, execution_id="123-1")
        with tempfile.TemporaryDirectory() as directory, patch.object(runtime, "_validate_execution_bundle"), \
             patch.object(runtime, "derive_bound_candidate", side_effect=publication.LedgerPublicationError("candidate_rejected")) as derive:
            output = directory + "/candidate.json"
            with self.assertRaisesRegex(publication.LedgerPublicationError, "candidate_rejected"):
                runtime.LedgerCandidateRuntime("/trusted/cli", "/trusted/mirror", output)(bundle)
            derive.assert_called_once_with(bundle, "/trusted/cli", "/trusted/mirror", {})
            self.assertFalse(Path(output).exists())

    def test_unique_lookup_binds_exact_reference_and_clock(self):
        api = Api([{"total_count": 1, "artifacts": [self.artifact]}])
        with patch.object(runtime, "publish_ledger_candidate", return_value={"synthetic": True}) as publish:
            self.assertEqual(self.invoke(api), {"synthetic": True})
        args = publish.call_args.args
        self.assertEqual(args[3], ArtifactReference(1260920764, REPOSITORY, 123, 1, 200, "c" * 64, self.handoff["content_sha256"]))
        self.assertEqual(args[-1], "2026-10-11T00:00:00Z")
        self.assertEqual(len(api.calls), 1)

    def test_pagination_complete_and_inconsistent_failures(self):
        first = [{"id": value, "name": "unrelated"} for value in range(1, 101)]
        api = Api([{"total_count": 101, "artifacts": first}, {"total_count": 101, "artifacts": [self.artifact]}])
        with patch.object(runtime, "publish_ledger_candidate"):
            self.invoke(api)
        self.assertEqual(len(api.calls), 2)
        failures = [
            [{"total_count": 1, "artifacts": []}],
            [{"total_count": 2, "artifacts": [self.artifact, dict(self.artifact, id=201)]}],
            [{"total_count": 2, "artifacts": [self.artifact, self.artifact]}],
            [{"total_count": 101, "artifacts": first}, {"total_count": 102, "artifacts": [self.artifact]}],
            [{"total_count": 0, "artifacts": []}],
            [{"total_count": 1, "artifacts": [dict(self.artifact, digest="https://untrusted")]}],
        ]
        for pages in failures:
            with self.subTest(pages=len(pages)), patch.object(runtime, "publish_ledger_candidate") as publish, self.assertRaises(publication.LedgerPublicationError):
                self.invoke(Api(pages))
            publish.assert_not_called()

    def test_authenticated_checkpoint_recovery_avoids_new_lookup(self):
        reference = ArtifactReference(1260920764, REPOSITORY, 123, 1, 200, "d" * 64, self.handoff["content_sha256"])
        self.publisher.load_ledger_publication_checkpoint.return_value = SimpleNamespace(publication={"artifact_reference": asdict(reference)})
        api = Api([])
        with patch.object(runtime, "publish_ledger_candidate", return_value={"replayed": True}) as publish:
            self.assertEqual(self.invoke(api), {"replayed": True})
        self.assertEqual(api.calls, [])
        self.assertEqual(publish.call_args.args[3], reference)
        self.publisher.load_ledger_publication_checkpoint.return_value.publication["artifact_reference"]["content_sha256"] = "e" * 64
        with self.assertRaisesRegex(publication.LedgerPublicationError, "ledger_checkpoint_conflict"):
            self.invoke(api)
        self.assertEqual(api.calls, [])

    def test_content_digest_mismatch_before_derivation_or_publication(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("candidate.json", b"different synthetic content")
        api = Api([{"total_count": 1, "artifacts": [dict(self.artifact, digest="sha256:" + hashlib.sha256(stream.getvalue()).hexdigest())]}])
        api.archive = stream.getvalue()
        with patch.object(publication, "observe_ledger_producer", return_value={}), patch.object(publication, "derive_bound_candidate") as derive, self.assertRaisesRegex(publication.LedgerPublicationError, "ledger_content_digest_mismatch"):
            self.invoke(api)
        derive.assert_not_called()
        self.publisher.checkpoint_ledger_publication.assert_not_called()


if __name__ == "__main__":
    unittest.main()
