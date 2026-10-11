"""Secret-free candidate bridge. Caller establishes producer/context authority.

Canonical bytes come only from the pinned Rust CLI; Python never substitutes a
JCS implementation. Archive integrity is not producer authentication.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import tempfile
import zipfile

from actions_journal_coordinator import ActionsJournalCoordinator, CoordinatorError
from actions_request_handler import ExecutionBundle, _validate_execution_bundle

PIN = "7f7af5752ef2e016ffe7116f84648b3350fe507f"
MAX_ARTIFACT_BYTES = 262144
MAX_ARCHIVE_BYTES = 393216


class CandidateError(Exception):
    """Only bounded machine codes cross this boundary."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _reject(code="candidate_invalid"):
    raise CandidateError(code)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _reject()
        result[key] = value
    return result


def _json(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_ARTIFACT_BYTES:
        _reject()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: _reject())
        def check(node, depth=0):
            if depth > 32:
                _reject()
            if isinstance(node, str):
                node.encode("utf-8")
            elif isinstance(node, dict):
                for key, child in node.items():
                    check(key, depth + 1)
                    check(child, depth + 1)
            elif isinstance(node, list):
                for child in node:
                    check(child, depth + 1)
            elif isinstance(node, float):
                # Rust JCS rejects nonfinite values, including overflowed numbers.
                import math
                if not math.isfinite(node):
                    _reject()
        check(value)
        return value
    except CandidateError:
        raise
    except (ValueError, UnicodeError, RecursionError, TypeError):
        _reject()


def _sha(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def _regular_read(path):
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_ARTIFACT_BYTES:
            _reject()
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            data = handle.read(MAX_ARTIFACT_BYTES + 1)
        if len(data) != info.st_size or len(data) > MAX_ARTIFACT_BYTES:
            _reject()
        return data
    except OSError:
        _reject()
    finally:
        if fd >= 0:
            os.close(fd)


def derive_bound_candidate(bundle, cli_path, mirror, trusted_context, *, timeout_seconds=30.0):
    """Invoke configured trusted absolute paths, never paths from Issue data."""
    try:
        bundle = ExecutionBundle.from_dict(bundle.to_dict())
        _validate_execution_bundle(bundle)
        if bundle.operation != "governance.ledger":
            _reject()
        for path in (cli_path, mirror):
            if not isinstance(path, str) or not os.path.isabs(path) or not os.path.exists(path):
                _reject("candidate_configuration_invalid")
        if not os.path.isfile(cli_path) or not os.access(cli_path, os.X_OK) or not os.path.isdir(mirror):
            _reject("candidate_configuration_invalid")
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 120:
            _reject("candidate_configuration_invalid")
        context = json.dumps(trusted_context, ensure_ascii=False, allow_nan=False).encode("utf-8")
        parsed_context = _json(context)
        if not isinstance(parsed_context, dict) or set(parsed_context) - {"remote_preflight", "remote_evidence"} or any(type(v) is not dict for v in parsed_context.values()):
            _reject()
        with tempfile.TemporaryDirectory(prefix="zach-ledger-candidate-") as directory:
            record_path = ActionsJournalCoordinator._write_private(directory, "journal.json", bundle.canonical_record.encode("utf-8"))
            context_path = ActionsJournalCoordinator._write_private(directory, "context.json", context)
            output = os.path.join(directory, "candidate.json")
            result = ActionsJournalCoordinator._run_subprocess((cli_path,
                "--journal-record", record_path, "--accepted-revision", bundle.accepted_revision,
                "--claim-revision", bundle.claim_revision, "--mirror", mirror,
                "--trusted-context", context_path, "--output", output), timeout_seconds)
            if result.returncode != 0 or result.stdout:
                _reject("candidate_derivation_failed")
            raw = _regular_read(output)
            validate_bound_candidate(raw, raw, bundle, parsed_context)
            return raw
    except CandidateError:
        raise
    except CoordinatorError as error:
        raise CandidateError(error.code) from None
    except Exception:
        _reject("candidate_derivation_failed")


def validate_bound_candidate(raw, rederived_bytes, bundle, trusted_context):
    """Require exact independently rederived bytes, then check bounded bindings.

    Neither candidate_validated nor caller provenance claims grant authority.
    Returns parsed data for the already authenticated Publisher to consume.
    """
    if type(raw) is not bytes or type(rederived_bytes) is not bytes or raw != rederived_bytes:
        _reject("candidate_bytes_mismatch")
    try:
        bundle = ExecutionBundle.from_dict(bundle.to_dict())
        record = _validate_execution_bundle(bundle)
        data = _json(raw)
        outer = {"kind", "schema_version", "request_id", "outer_request_digest", "accepted_revision", "claim_revision", "policy_revision", "accepted_at", "inner_request", "trusted_context", "candidate"}
        if type(data) is not dict or set(data) != outer or type(data["schema_version"]) is not int or data["schema_version"] != 1 or data["kind"] != "governance-actions-ledger-candidate":
            _reject()
        expected = {"request_id": bundle.request_id, "outer_request_digest": bundle.request_digest,
                    "accepted_revision": bundle.accepted_revision, "claim_revision": bundle.claim_revision,
                    "policy_revision": record["policy_revision"], "accepted_at": record["accepted_at"],
                    "trusted_context": trusted_context}
        if bundle.operation != "governance.ledger" or any(data[k] != v for k, v in expected.items()):
            _reject()
        inner = data["inner_request"]
        if type(inner) is not dict or set(inner) != {"schema_version", "request_id", "base_sha", "operation", "parameters", "created_at", "expires_at", "contract_revision"}:
            _reject()
        if type(inner["schema_version"]) is not int or inner["schema_version"] != 1 or inner["request_id"] != bundle.request_id or inner["created_at"] != record["accepted_at"] or inner["contract_revision"] != PIN or any(inner[k] != bundle.parameters[k] for k in ("base_sha", "operation", "parameters")):
            _reject()
        candidate = data["candidate"]
        fields = {"kind", "schema_version", "request_id", "request_digest", "base_sha", "contract_revision", "validator_revision", "candidate_validated", "validated_tree_sha", "changes"}
        if type(candidate) is not dict or set(candidate) != fields or type(candidate["schema_version"]) is not int or candidate["schema_version"] != 1 or candidate["kind"] != "governance-ledger-candidate":
            _reject()
        if candidate["request_id"] != bundle.request_id or candidate["base_sha"] != inner["base_sha"] or candidate["contract_revision"] != PIN or candidate["validator_revision"] != PIN or candidate["candidate_validated"] is not True or not _sha(candidate["validated_tree_sha"]) or not _sha(candidate["base_sha"]) or not isinstance(candidate["request_digest"], str) or not re.fullmatch(r"[0-9a-f]{64}", candidate["request_digest"]):
            _reject()
        # Trusted Rust rederivation establishes JCS digest, expiry and the exact
        # 60000-byte nested candidate limit. Alternative Python JSON encodings
        # can be longer than JCS, so they cannot enforce that canonical limit.
        changes = candidate["changes"]
        if type(changes) is not list or len(changes) > 8:
            _reject()
        paths, total = [], 0
        for change in changes:
            if type(change) is not dict or set(change) != {"path", "operation", "content", "blob_sha"}:
                _reject()
            path = change["path"]
            if not isinstance(path, str) or len(path.encode("utf-8")) > 512 or not re.fullmatch(r"(?:tasks|runs|indexes)/[A-Za-z0-9_./-]+", path) or any(part in ("", ".", "..") for part in path.split("/")):
                _reject()
            paths.append(path)
            if change["operation"] == "upsert" and isinstance(change["content"], str):
                content = change["content"].encode("utf-8")
                total += len(content)
                blob = hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()
                if change["blob_sha"] != blob:
                    _reject()
            elif change["operation"] != "delete" or change["content"] is not None or change["blob_sha"] is not None:
                _reject()
        if paths != sorted(set(paths)) or total > 48000:
            _reject()
        return data
    except CandidateError:
        raise
    except Exception:
        _reject()


def read_candidate_archive(zip_bytes, expected_archive_sha256):
    """Verify archive digest and return its sole regular candidate.json in memory."""
    if type(zip_bytes) is not bytes or not 0 < len(zip_bytes) <= MAX_ARCHIVE_BYTES or not isinstance(expected_archive_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_archive_sha256) or hashlib.sha256(zip_bytes).hexdigest() != expected_archive_sha256:
        _reject("candidate_archive_invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
            entries = archive.infolist()
            if len(entries) != 1:
                _reject("candidate_archive_invalid")
            entry = entries[0]
            mode = entry.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if entry.filename != "candidate.json" or entry.is_dir() or kind not in (0, stat.S_IFREG) or entry.external_attr & 0x10 or entry.flag_bits & 1 or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) or not 0 < entry.file_size <= MAX_ARTIFACT_BYTES:
                _reject("candidate_archive_invalid")
            with archive.open(entry) as handle:
                raw = handle.read(MAX_ARTIFACT_BYTES + 1)
            if len(raw) != entry.file_size or len(raw) > MAX_ARTIFACT_BYTES:
                _reject("candidate_archive_invalid")
            return raw
    except CandidateError:
        raise
    except Exception:
        _reject("candidate_archive_invalid")
