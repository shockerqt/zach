"""GitHub Git-data operational journal persistence backend for Actions requests.

Provides storage mechanics using GitHub's Git database APIs (refs, commits, trees, blobs)
and content endpoints, with injected transport and transition validator.

Caller responsibilities:
- Transport: Injected request(method, relative_path, body=None) returning decoded JSON
  or raising typed ApiError(status). Requires GitHub App installation token.
- Transition validator: Mandatory callback validate_transition(old_record_json_or_None, new_record_json)
  enforcing domain-level journal state transitions (e.g. from Rust adapter).
- Safety invariant: Callers must never execute requested operations or claim a grant before
  publish() durably returns success.
- Concurrency & Ambiguity: On AmbiguousPublication, callers must block further effects and trigger
  reconciliation. Do not retry write effects automatically.
- Architecture: Persistence mechanics only; not an Actions queue.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Callable, Final, Optional

FIXED_REPOSITORY: Final[str] = "shockerqt/workspace-governance"
FIXED_REF: Final[str] = "heads/automation/requests"
MAX_RECORD_BYTES: Final[int] = 64 * 1024  # 64 KiB
REQUEST_ID_REGEX: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
SHA40_REGEX: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")


class ApiError(Exception):
    """Raised by injected transport on API or HTTP errors."""

    def __init__(self, status: int, message: str = "", body: Any = None) -> None:
        super().__init__(f"API error {status}: {message}" if message else f"API error {status}")
        self.status, self.message, self.body = status, message, body


class JournalError(Exception):
    """Base exception for Git operational journal errors."""


class JournalValidationError(JournalError, ValueError):
    """Raised when record JSON, request ID, or SHA fails strict validation."""


class StaleSnapshotConflict(JournalError):
    """Raised when ref head changed before effects, indicating a stale snapshot."""


StaleSnapshotError = StaleSnapshotConflict


class AmbiguousPublication(JournalError):
    """Raised on unresolved write/readback mismatch. Never retry automatically."""

    def __init__(self, candidate_sha: str, base_sha: str, tree_sha: str, message: str = "") -> None:
        super().__init__(
            message or f"Ambiguous publication: candidate={candidate_sha}, base={base_sha}, tree={tree_sha}"
        )
        self.candidate_sha, self.base_sha, self.tree_sha = candidate_sha, base_sha, tree_sha


@dataclass(frozen=True)
class JournalSnapshot:
    """Frozen snapshot of ref, commit tree, and request record."""

    head_sha: str
    tree_sha: str
    record_json: Optional[str]
    record_blob_sha: Optional[str] = None


@dataclass(frozen=True)
class PublicationReceipt:
    """Receipt proving durable non-forced publication or verified replay."""

    commit_sha: str
    tree_sha: str
    replayed: bool = False


def validate_sha40(sha: Any, field_name: str = "SHA") -> str:
    """Require 40-character lowercase hexadecimal SHA string."""
    if not isinstance(sha, str) or not SHA40_REGEX.fullmatch(sha):
        raise JournalValidationError(f"Invalid {field_name}: must be 40-character lowercase hex")
    return sha


def validate_request_id(request_id: Any) -> str:
    """Validate request ID matches [A-Za-z0-9_-]{8,128}."""
    if not isinstance(request_id, str) or not REQUEST_ID_REGEX.fullmatch(request_id):
        raise JournalValidationError("Invalid request_id")
    return request_id


def record_path_for_request_id(request_id: str) -> str:
    """Compute deterministic storage path requests/<sha256(request_id)>.json."""
    validate_request_id(request_id)
    digest = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
    return f"requests/{digest}.json"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise JournalValidationError("Duplicate key in record JSON")
        obj[key] = value
    return obj


def parse_and_validate_record(content: str, expected_request_id: str) -> dict[str, Any]:
    """Strictly parse record JSON, enforcing size bounds, duplicate rejection, and ID binding."""
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_RECORD_BYTES:
        raise JournalValidationError(f"Record payload {len(encoded)} exceeds {MAX_RECORD_BYTES} bytes")
    try:
        parsed = json.loads(content, object_pairs_hook=_reject_duplicate_keys)
    except Exception as exc:
        raise JournalValidationError("Record is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise JournalValidationError("Record JSON root must be an object")
    req_id = parsed.get("request_id")
    if req_id != expected_request_id:
        raise JournalValidationError("Record request_id does not match storage key")
    return parsed


def _extract_ref_sha(ref_resp: Any) -> Any:
    if not isinstance(ref_resp, dict):
        return None
    obj = ref_resp.get("object")
    return obj.get("sha") if isinstance(obj, dict) else ref_resp.get("sha")


def _extract_tree_sha(commit_resp: Any) -> Any:
    if not isinstance(commit_resp, dict):
        return None
    tree_obj = commit_resp.get("tree")
    return tree_obj.get("sha") if isinstance(tree_obj, dict) else tree_obj


class ActionsGitJournal:
    """Narrowly scoped GitHub Git-data persistence backend for the Actions operational journal."""

    REPOSITORY: Final[str] = FIXED_REPOSITORY
    REF: Final[str] = FIXED_REF

    def __init__(
        self,
        transport: Optional[Callable[..., Any]] = None,
        validate_transition: Optional[Callable[[Optional[str], str], Any]] = None,
        *,
        request: Optional[Callable[..., Any]] = None,
    ) -> None:
        actual_transport = request if request is not None else transport
        if not callable(actual_transport):
            raise TypeError("ActionsGitJournal requires an injected API transport callable")
        if not callable(validate_transition):
            raise TypeError("ActionsGitJournal requires a mandatory validate_transition callback")
        self._transport, self.validate_transition = actual_transport, validate_transition

    def request(self, method: str, relative_path: str, body: Optional[dict[str, Any]] = None) -> Any:
        return self._transport(method, relative_path, body=body)

    def _regular_blob_sha(self, tree_sha: str, path: str) -> Optional[str]:
        # Contents may follow repository symlinks. Prove both Git modes first.
        parts = path.split("/")
        for index, part in enumerate(parts):
            response = self.request("GET", f"/repos/{self.REPOSITORY}/git/trees/{tree_sha}")
            if not isinstance(response, dict) or response.get("truncated") is not False:
                raise JournalValidationError("Incomplete Git tree")
            entries = response.get("tree")
            if not isinstance(entries, list) or any(not isinstance(e, dict) for e in entries):
                raise JournalValidationError("Malformed Git tree")
            matches = [e for e in entries if e.get("path") == part]
            if not matches:
                return None
            if len(matches) != 1:
                raise JournalValidationError("Duplicate Git tree entry")
            entry = matches[0]
            expected = ("040000", "tree") if index == 0 else ("100644", "blob")
            if (entry.get("mode"), entry.get("type")) != expected:
                raise JournalValidationError("Journal path must contain a directory and regular file")
            tree_sha = validate_sha40(entry.get("sha"), "entry SHA")
        return tree_sha

    def load(self, request_id: str) -> JournalSnapshot:
        """Read existing fixed ref, pinned commit/tree, and record at exact commit SHA."""
        validate_request_id(request_id)
        path = record_path_for_request_id(request_id)

        # 1. Read existing fixed ref. Missing ref fails closed (never auto-create branch).
        ref_path = f"/repos/{self.REPOSITORY}/git/ref/{self.REF}"
        head_sha = _extract_ref_sha(self.request("GET", ref_path))
        validate_sha40(head_sha, "head_sha")

        # 2. Read immutable commit to pin tree SHA
        commit_path = f"/repos/{self.REPOSITORY}/git/commits/{head_sha}"
        tree_sha = _extract_tree_sha(self.request("GET", commit_path))
        validate_sha40(tree_sha, "tree_sha")

        expected_blob_sha = self._regular_blob_sha(tree_sha, path)
        # 3. Read pinned record content at exact commit SHA
        contents_path = f"/repos/{self.REPOSITORY}/contents/{path}?ref={head_sha}"
        try:
            content_resp = self.request("GET", contents_path)
        except ApiError as err:
            if err.status == 404 and expected_blob_sha is None:
                return JournalSnapshot(head_sha=head_sha, tree_sha=tree_sha, record_json=None)
            raise

        if expected_blob_sha is None:
            raise JournalValidationError("Content is absent from the pinned Git tree")
        if not isinstance(content_resp, dict) or content_resp.get("type") != "file":
            raise JournalError(f"Record at {path} is not a regular file")
        if content_resp.get("encoding") != "base64":
            raise JournalError(f"Record at {path} has unexpected encoding: {content_resp.get('encoding')!r}")

        size = content_resp.get("size")
        if type(size) is not int or not 0 <= size <= MAX_RECORD_BYTES:
            raise JournalValidationError(f"Record size {size} exceeds {MAX_RECORD_BYTES} bytes")

        raw_b64 = content_resp.get("content")
        if not isinstance(raw_b64, str) or len(raw_b64) > 2 * MAX_RECORD_BYTES:
            raise JournalError(f"Missing content in response from {contents_path}")

        try:
            raw_bytes = base64.b64decode("".join(raw_b64.split()), validate=True)
        except Exception as exc:
            raise JournalValidationError(f"Record content failed strict base64 decoding: {exc}") from exc

        if len(raw_bytes) > MAX_RECORD_BYTES or len(raw_bytes) != size:
            raise JournalValidationError(f"Decoded content {len(raw_bytes)} exceeds {MAX_RECORD_BYTES} bytes")

        try:
            record_str = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise JournalValidationError(f"Record content is not valid UTF-8: {exc}") from exc

        parse_and_validate_record(record_str, request_id)
        blob_sha = validate_sha40(content_resp.get("sha"), "record_blob_sha")
        actual_blob_sha = hashlib.sha1(b"blob " + str(len(raw_bytes)).encode() + b"\0" + raw_bytes).hexdigest()
        if blob_sha != expected_blob_sha or actual_blob_sha != blob_sha:
            raise JournalValidationError("Record bytes do not match pinned Git blob")

        return JournalSnapshot(
            head_sha=head_sha,
            tree_sha=tree_sha,
            record_json=record_str,
            record_blob_sha=blob_sha,
        )

    def publish(
        self,
        snapshot: JournalSnapshot,
        request_id: str,
        new_record_json: str | bytes,
    ) -> PublicationReceipt:
        """Publish updated record with single-path tree, single parent, and non-forced ref update."""
        if not isinstance(snapshot, JournalSnapshot):
            raise JournalValidationError("snapshot must be a JournalSnapshot instance")
        validate_sha40(snapshot.head_sha, "snapshot.head_sha")
        validate_sha40(snapshot.tree_sha, "snapshot.tree_sha")
        if snapshot.record_blob_sha is not None:
            validate_sha40(snapshot.record_blob_sha, "snapshot.record_blob_sha")

        validate_request_id(request_id)
        path = record_path_for_request_id(request_id)

        if isinstance(new_record_json, bytes):
            try:
                new_record_str = new_record_json.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise JournalValidationError(f"new_record_json bytes is not valid UTF-8: {exc}") from exc
        elif isinstance(new_record_json, str):
            new_record_str = new_record_json
        else:
            raise JournalValidationError("new_record_json must be str or UTF-8 bytes")

        parse_and_validate_record(new_record_str, request_id)

        # Transition callback validation before any effect
        res = self.validate_transition(snapshot.record_json, new_record_str)
        if res is not None and res is not True:
            raise JournalValidationError("State transition rejected by transition validator")

        # Re-read the complete bound snapshot, not only its head: a caller must
        # not substitute another tree or omit an existing request's old state.
        fresh = self.load(request_id)
        if fresh.head_sha != snapshot.head_sha:
            raise StaleSnapshotConflict("Journal head moved before writing")
        if fresh != snapshot:
            raise JournalValidationError("Snapshot does not match pinned journal state")
        if snapshot.record_json is not None and snapshot.record_json == new_record_str:
            return PublicationReceipt(commit_sha=snapshot.head_sha, tree_sha=snapshot.tree_sha, replayed=True)

        # 1. Create base64 blob
        b64_content = base64.b64encode(new_record_str.encode("utf-8")).decode("ascii")
        blob_resp = self.request(
            "POST",
            f"/repos/{self.REPOSITORY}/git/blobs",
            body={"content": b64_content, "encoding": "base64"},
        )
        blob_sha = blob_resp.get("sha") if isinstance(blob_resp, dict) else None
        validate_sha40(blob_sha, "created blob_sha")
        raw_record = new_record_str.encode("utf-8")
        expected_blob = hashlib.sha1(b"blob " + str(len(raw_record)).encode() + b"\0" + raw_record).hexdigest()
        if blob_sha != expected_blob:
            raise JournalValidationError("Created blob does not bind proposed record bytes")

        # 2. Create single-path tree with base_tree
        tree_body = {
            "base_tree": snapshot.tree_sha,
            "tree": [{"path": path, "mode": "100644", "type": "blob", "sha": blob_sha}],
        }
        tree_resp = self.request("POST", f"/repos/{self.REPOSITORY}/git/trees", body=tree_body)
        derived_tree_sha = tree_resp.get("sha") if isinstance(tree_resp, dict) else None
        validate_sha40(derived_tree_sha, "derived_tree_sha")

        # 3. Create single-parent commit
        commit_body = {
            "message": f"chore(actions): record {request_id}",
            "tree": derived_tree_sha,
            "parents": [snapshot.head_sha],
        }
        commit_resp = self.request("POST", f"/repos/{self.REPOSITORY}/git/commits", body=commit_body)
        candidate_sha = commit_resp.get("sha") if isinstance(commit_resp, dict) else None
        validate_sha40(candidate_sha, "candidate_sha")

        # 4. Non-forced PATCH to fixed ref
        patch_path = f"/repos/{self.REPOSITORY}/git/refs/{self.REF}"
        patch_body = {"sha": candidate_sha, "force": False}
        try:
            self.request("PATCH", patch_path, body=patch_body)
        except Exception:
            pass

        # 5. Independent readback verification
        try:
            readback_ref = self.request("GET", f"/repos/{self.REPOSITORY}/git/ref/{self.REF}")
            current_ref_sha = _extract_ref_sha(readback_ref)
            readback_commit = self.request("GET", f"/repos/{self.REPOSITORY}/git/commits/{candidate_sha}")
            parents_raw = readback_commit.get("parents", []) if isinstance(readback_commit, dict) else []
            parents = [p["sha"] if isinstance(p, dict) else p for p in parents_raw]
            tree_sha = _extract_tree_sha(readback_commit)

            if (
                current_ref_sha == candidate_sha
                and readback_commit.get("sha") == candidate_sha
                and parents == [snapshot.head_sha]
                and tree_sha == derived_tree_sha
            ):
                return PublicationReceipt(commit_sha=candidate_sha, tree_sha=derived_tree_sha, replayed=False)
        except Exception:
            pass

        raise AmbiguousPublication(
            candidate_sha=candidate_sha,
            base_sha=snapshot.head_sha,
            tree_sha=derived_tree_sha,
        )
