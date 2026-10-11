"""Synthetic local fixtures; these tests do not establish remote evidence."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import actions_ledger_candidate as candidate
from actions_journal_coordinator import ActionsJournalCoordinator, CliProcessResult, CoordinatorError


spec = importlib.util.spec_from_file_location("handler_fixtures", Path(__file__).with_name("test-actions-request-handler.py"))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class CandidateTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.LedgerPublicationCheckpointTests()
        fixture.setUp()
        self.bundle = fixture.bundle
        record = json.loads(self.bundle.canonical_record)
        inner = {"schema_version": 1, "request_id": self.bundle.request_id,
                 **self.bundle.parameters, "created_at": record["accepted_at"],
                 "expires_at": "2026-09-05T04:04:09Z", "contract_revision": candidate.PIN}
        content = "synthetic evidence\n"
        blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content.encode()).hexdigest()
        self.data = {"kind": "governance-actions-ledger-candidate", "schema_version": 1,
            "request_id": self.bundle.request_id, "outer_request_digest": self.bundle.request_digest,
            "accepted_revision": self.bundle.accepted_revision, "claim_revision": self.bundle.claim_revision,
            "policy_revision": record["policy_revision"], "accepted_at": record["accepted_at"],
            "inner_request": inner, "trusted_context": {}, "candidate": {
                "kind": "governance-ledger-candidate", "schema_version": 1,
                "request_id": self.bundle.request_id, "request_digest": "a" * 64,
                "base_sha": self.bundle.parameters["base_sha"], "contract_revision": candidate.PIN,
                "validator_revision": candidate.PIN, "candidate_validated": True,
                "validated_tree_sha": "b" * 40, "changes": [{"path": "runs/ZACH-003/synthetic.md",
                "operation": "upsert", "content": content, "blob_sha": blob}]}}

    def raw(self):
        return json.dumps(self.data, separators=(",", ":"), sort_keys=True).encode()

    def test_exact_rederivation_and_frozen_binding(self):
        raw = self.raw()
        self.assertEqual(candidate.validate_bound_candidate(raw, raw, self.bundle, {}), self.data)
        with self.assertRaises(candidate.CandidateError):
            candidate.validate_bound_candidate(raw + b" ", raw, self.bundle, {})
        self.data["accepted_revision"] = "e" * 40
        with self.assertRaises(candidate.CandidateError):
            candidate.validate_bound_candidate(self.raw(), self.raw(), self.bundle, {})

    def test_blob_hash_and_paths(self):
        for change in ({"blob_sha": "0" * 40}, {"path": "tasks/../policy.md"},
                       {"operation": "delete"}, {"extra": True}):
            with self.subTest(change=change):
                original = self.data["candidate"]["changes"][0].copy()
                self.data["candidate"]["changes"][0].update(change)
                with self.assertRaises(candidate.CandidateError):
                    candidate.validate_bound_candidate(self.raw(), self.raw(), self.bundle, {})
                self.data["candidate"]["changes"][0] = original

    def test_empty_changes_preserve_idempotent_candidate(self):
        # Synthetic bytes test consumer mechanics only. Production callers must
        # obtain the independently rederived bytes from the trusted Rust CLI.
        self.data["candidate"]["changes"] = []
        raw = self.raw()
        self.assertEqual(candidate.validate_bound_candidate(raw, raw, self.bundle, {})["candidate"]["changes"], [])

    def test_strict_json(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'[' * 40 + b'0' + b']' * 40, b'"\\ud800"', b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(candidate.CandidateError):
                candidate._json(raw)

    def test_private_invocation_replay_and_output(self):
        raw = self.raw()
        calls = []
        def run(argv, timeout):
            calls.append(argv)
            journal = argv[argv.index("--journal-record") + 1]
            self.assertEqual(stat.S_IMODE(os.stat(journal).st_mode), 0o600)
            self.assertEqual(Path(journal).read_text(), self.bundle.canonical_record)
            ActionsJournalCoordinator._write_private(str(Path(argv[-1]).parent), "candidate.json", raw)
            return CliProcessResult(0, b"", b"")
        with tempfile.TemporaryDirectory() as mirror, patch.object(ActionsJournalCoordinator, "_run_subprocess", side_effect=run):
            first = candidate.derive_bound_candidate(self.bundle, "/usr/bin/true", mirror, {})
            second = candidate.derive_bound_candidate(self.bundle, "/usr/bin/true", mirror, {})
        self.assertEqual(first, second)
        self.assertEqual(len(calls), 2)
        with tempfile.TemporaryDirectory() as mirror:
            for result in (CliProcessResult(1, b"", b"secret"), CliProcessResult(0, b"secret", b"")):
                with patch.object(ActionsJournalCoordinator, "_run_subprocess", return_value=result), self.assertRaises(candidate.CandidateError) as failure:
                    candidate.derive_bound_candidate(self.bundle, "/usr/bin/true", mirror, {})
                self.assertNotIn("secret", str(failure.exception))

    def test_existing_runner_minimal_environment_and_timeout(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "synthetic-secret"}):
            result = ActionsJournalCoordinator._run_subprocess(("/usr/bin/env",), 2)
        self.assertEqual(set(result.stdout.splitlines()), {b"LANG=C.UTF-8", b"LC_ALL=C.UTF-8"})
        for argv, timeout, code in ((("/usr/bin/sleep", "1"), .01, "cli_timed_out"),
                                    (("/usr/bin/yes",), 2, "cli_output_too_large")):
            with self.assertRaises(CoordinatorError) as failure:
                ActionsJournalCoordinator._run_subprocess(argv, timeout)
            self.assertEqual(failure.exception.code, code)
        with tempfile.TemporaryDirectory() as mirror, patch.object(ActionsJournalCoordinator, "_run_subprocess", side_effect=CoordinatorError("cli_timed_out")), self.assertRaises(candidate.CandidateError) as failure:
            candidate.derive_bound_candidate(self.bundle, "/usr/bin/true", mirror, {})
        self.assertEqual(failure.exception.code, "cli_timed_out")

    def test_regular_output_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            file = ActionsJournalCoordinator._write_private(directory, "large", b"x" * (candidate.MAX_ARTIFACT_BYTES + 1))
            os.symlink(file, directory + "/link")
            for path in (file, directory + "/link", directory):
                with self.assertRaises(candidate.CandidateError):
                    candidate._regular_read(path)


class ArchiveTests(unittest.TestCase):
    def archive(self, entries, compression=zipfile.ZIP_DEFLATED):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=compression) as output:
            for name, content in entries:
                output.writestr(name, content)
        return stream.getvalue()

    def read(self, raw):
        return candidate.read_candidate_archive(raw, hashlib.sha256(raw).hexdigest())

    def test_valid_and_bad_digest(self):
        raw = self.archive([("candidate.json", b"{}")])
        self.assertEqual(self.read(raw), b"{}")
        with self.assertRaises(candidate.CandidateError):
            candidate.read_candidate_archive(raw, "0" * 64)

    def test_invalid_archive_shapes_and_bounds(self):
        link = zipfile.ZipInfo("candidate.json")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        variants = [self.archive([]), self.archive([("other.json", b"{}")]),
            self.archive([("candidate.json/", b"{}")]), self.archive([(link, b"target")]),
            self.archive([("candidate.json", b"{}"), ("other", b"{}")]),
            self.archive([("candidate.json", b"x" * (candidate.MAX_ARTIFACT_BYTES + 1))]),
            self.archive([("candidate.json", b"{}")], zipfile.ZIP_BZIP2),
            self.archive([("candidate.json", b"{}")])[:-5], b"invalid"]
        for raw in variants:
            with self.subTest(size=len(raw)), self.assertRaises(candidate.CandidateError):
                self.read(raw)

    def test_encrypted_duplicate_and_corrupt_payload(self):
        original = self.archive([("candidate.json", b"synthetic")], zipfile.ZIP_STORED)
        encrypted = bytearray(original)
        central = encrypted.index(b"PK\x01\x02")
        struct.pack_into("<H", encrypted, 6, 1)
        struct.pack_into("<H", encrypted, central + 8, 1)
        corrupt = original.replace(b"synthetic", b"corrupted", 1)
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            duplicate = self.archive([("candidate.json", b"{}"), ("candidate.json", b"{}")])
        for raw in (bytes(encrypted), corrupt, duplicate):
            with self.assertRaises(candidate.CandidateError):
                self.read(raw)


if __name__ == "__main__":
    unittest.main()
