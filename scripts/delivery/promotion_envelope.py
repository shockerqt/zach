#!/usr/bin/env python3
"""Validate Zach build provenance, release archive integrity, and promotion envelopes."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import posixpath
import re
import sys
import tarfile
from pathlib import Path
from typing import Any

EXPECTED_RUST_TARGET = "aarch64-unknown-linux-gnu"
EXPECTED_BUILD_WORKFLOW = ".github/workflows/ci.yml"
HEX_40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
BUILD_RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
RELEASE_SHA256_RE = re.compile(r"^([0-9a-f]{64})  zach-release\.tar\.gz\n?$")
SHA256SUM_LINE_RE = re.compile(r"^([0-9a-f]{64})  ([^\n]+)$")

MAX_METADATA_BYTES = 65536
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_TAR_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 10000

REQUIRED_ARCHIVE_FILES = frozenset(
    {
        "zach",
        "SOURCE_SHA",
        "RUST_TARGET",
        "SHA256SUMS",
        "zach-release.json",
        "web/dist/index.html",
        "web/dist/release.json",
    }
)


class EnvelopeError(Exception):
    """Raised when provenance, archive, plan, or delivery validation fails."""


def _unique_keys_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EnvelopeError(f"Duplicate JSON key: {key!r}")
        result[key] = value
    return result


def parse_strict_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    if len(raw) == 0 or len(raw) > MAX_METADATA_BYTES:
        raise EnvelopeError(f"{label} size out of bounds ({len(raw)} bytes)")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EnvelopeError(f"{label} is not valid UTF-8: {exc}") from exc

    def _reject_constant(val: str) -> None:
        raise EnvelopeError(f"{label} contains non-standard JSON constant: {val}")

    try:
        data = json.loads(
            text,
            object_pairs_hook=_unique_keys_hook,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise EnvelopeError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise EnvelopeError(f"{label} must be a JSON object")
    return data


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _validate_build_run_id(value: Any, expected: str, label: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise EnvelopeError(f"{label} build_run_id must be int or str")
    text = str(value)
    if not BUILD_RUN_ID_RE.fullmatch(text):
        raise EnvelopeError(f"{label} build_run_id is malformed: {text!r}")
    if text != expected:
        raise EnvelopeError(f"{label} build_run_id {text!r} != expected {expected!r}")
    return text


def _validate_expected_current(value: str) -> str:
    if value != "none" and not HEX_40_RE.fullmatch(value):
        raise EnvelopeError(f"expected_current must be 40-hex SHA or 'none', got {value!r}")
    return value


class _BoundedDecompressStream:
    """Wrap gzip stream to enforce MAX_TAR_BYTES during tar iteration."""

    def __init__(self, gz_stream: gzip.GzipFile, max_bytes: int) -> None:
        self._gz = gz_stream
        self._max = max_bytes
        self._read = 0

    def read(self, size: int = -1) -> bytes:
        data = self._gz.read(size)
        self._read += len(data)
        if self._read > self._max:
            raise EnvelopeError("Decompressed tar stream exceeds 512 MiB limit")
        return data


def _validate_member_path(member: tarfile.TarInfo) -> str:
    raw = member.name
    if not raw or raw.startswith("/") or "\x00" in raw:
        raise EnvelopeError(f"Invalid archive member path: {raw!r}")
    clean = raw[2:] if raw.startswith("./") else raw
    clean = clean.rstrip("/")
    if not clean or clean == ".":
        raise EnvelopeError(f"Empty archive member path: {raw!r}")
    parts = clean.split("/")
    for part in parts:
        if part in ("", ".", "..") or part == ".artifact-sha256":
            raise EnvelopeError(f"Disallowed archive path component: {raw!r}")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in part):
            raise EnvelopeError(f"Control character in archive path: {raw!r}")
    if posixpath.normpath(clean) != clean:
        raise EnvelopeError(f"Unnormalized archive path: {raw!r}")

    if clean in ("zach", "SOURCE_SHA", "RUST_TARGET", "SHA256SUMS", "zach-release.json"):
        if not member.isreg():
            raise EnvelopeError(f"{clean} must be a regular file")
    elif clean in ("web", "web/dist"):
        if not member.isdir():
            raise EnvelopeError(f"{clean} must be a directory")
    elif clean.startswith("web/dist/"):
        if not (member.isreg() or member.isdir()):
            raise EnvelopeError(f"Unsupported member type for {clean}")
    else:
        raise EnvelopeError(f"Unexpected member in unified archive: {clean!r}")
    return clean


def _validate_member_type(member: tarfile.TarInfo, clean_name: str) -> None:
    if member.issym() or member.islnk() or member.isfifo() or member.ischr() or member.isblk():
        raise EnvelopeError(f"Disallowed special file in archive: {clean_name}")
    if member.linkname or member.issparse():
        raise EnvelopeError(f"Disallowed link/sparse member in archive: {clean_name}")
    if not (member.isreg() or member.isdir()):
        raise EnvelopeError(f"Unsupported member type for {clean_name}")


def verify_artifact(
    build_run_path: Path,
    release_sha256_path: Path,
    archive_path: Path,
    build_run_id: str,
    expected_source: str | None = None,
    expected_digest: str | None = None,
) -> dict[str, Any]:
    if not BUILD_RUN_ID_RE.fullmatch(build_run_id):
        raise EnvelopeError(f"Invalid --build-run-id: {build_run_id!r}")
    if expected_source is not None and not HEX_40_RE.fullmatch(expected_source):
        raise EnvelopeError(f"Invalid --expected-source: {expected_source!r}")
    if expected_digest is not None and not HEX_64_RE.fullmatch(expected_digest):
        raise EnvelopeError(f"Invalid --expected-digest: {expected_digest!r}")

    build_run = parse_strict_json_bytes(build_run_path.read_bytes(), str(build_run_path))
    _validate_build_run_id(build_run.get("id"), build_run_id, "build-run.json")
    if build_run.get("conclusion") != "success":
        raise EnvelopeError(f"build-run.json conclusion is {build_run.get('conclusion')!r}, expected 'success'")
    if build_run.get("head_branch") != "main":
        raise EnvelopeError(f"build-run.json head_branch is {build_run.get('head_branch')!r}, expected 'main'")
    if build_run.get("event") not in ("push", "workflow_dispatch"):
        raise EnvelopeError(f"build-run.json event {build_run.get('event')!r} is not allowed")
    if build_run.get("path") != EXPECTED_BUILD_WORKFLOW:
        raise EnvelopeError(f"build-run.json path {build_run.get('path')!r} != {EXPECTED_BUILD_WORKFLOW!r}")

    source_sha = build_run.get("head_sha")
    if not isinstance(source_sha, str) or not HEX_40_RE.fullmatch(source_sha):
        raise EnvelopeError(f"build-run.json head_sha is invalid: {source_sha!r}")
    if expected_source is not None and source_sha != expected_source:
        raise EnvelopeError(f"build-run.json head_sha {source_sha} != expected {expected_source}")

    sha_text = release_sha256_path.read_text(encoding="utf-8", errors="strict")
    sha_match = RELEASE_SHA256_RE.fullmatch(sha_text)
    if not sha_match:
        raise EnvelopeError("release.sha256 format is invalid")
    declared_digest = sha_match.group(1)
    if expected_digest is not None and declared_digest != expected_digest:
        raise EnvelopeError(f"release.sha256 digest {declared_digest} != expected {expected_digest}")

    if not archive_path.is_file():
        raise EnvelopeError(f"Archive not found: {archive_path}")
    archive_size = archive_path.stat().st_size
    if archive_size == 0 or archive_size > MAX_ARCHIVE_BYTES:
        raise EnvelopeError(f"Archive size out of bounds: {archive_size} bytes")
    actual_archive_sha = _sha256_file(archive_path)
    if actual_archive_sha != declared_digest:
        raise EnvelopeError(
            f"Archive SHA-256 {actual_archive_sha} does not match release.sha256 {declared_digest}"
        )

    seen_paths: set[str] = set()
    file_digests: dict[str, str] = {}
    small_contents: dict[str, bytes] = {}
    zach_header = b""
    zach_size = 0
    web_index_size = 0
    entries_count = 0
    total_extracted_bytes = 0

    small_targets = {
        "SOURCE_SHA",
        "RUST_TARGET",
        "SHA256SUMS",
        "zach-release.json",
        "web/dist/release.json",
    }

    try:
        with gzip.GzipFile(filename=archive_path, mode="rb") as gz:
            bounded = _BoundedDecompressStream(gz, MAX_TAR_BYTES)
            with tarfile.open(fileobj=bounded, mode="r|") as tar:
                for member in tar:
                    entries_count += 1
                    if entries_count > MAX_ENTRIES:
                        raise EnvelopeError("Archive exceeds max entry count")
                    clean_name = _validate_member_path(member)
                    _validate_member_type(member, clean_name)
                    if clean_name in seen_paths:
                        raise EnvelopeError(f"Duplicate member path: {clean_name}")
                    seen_paths.add(clean_name)

                    if member.isdir():
                        continue

                    if member.size < 0 or total_extracted_bytes + member.size > MAX_TOTAL_BYTES:
                        raise EnvelopeError("Extracted size exceeds 256 MiB limit")
                    total_extracted_bytes += member.size

                    src_file = tar.extractfile(member)
                    if src_file is None:
                        raise EnvelopeError(f"Cannot read archive member {clean_name}")

                    digest = hashlib.sha256()
                    chunks: list[bytes] = []
                    captured_len = 0
                    while True:
                        chunk = src_file.read(65536)
                        if not chunk:
                            break
                        digest.update(chunk)
                        if clean_name == "zach" and len(zach_header) < 20:
                            need = 20 - len(zach_header)
                            zach_header += chunk[:need]
                        elif clean_name in small_targets:
                            captured_len += len(chunk)
                            if captured_len > MAX_METADATA_BYTES * 8:
                                raise EnvelopeError(f"{clean_name} exceeds metadata size limit")
                            chunks.append(chunk)

                    file_digests[clean_name] = digest.hexdigest()
                    if clean_name == "zach":
                        zach_size = member.size
                    elif clean_name == "web/dist/index.html":
                        web_index_size = member.size
                    elif clean_name in small_targets:
                        small_contents[clean_name] = b"".join(chunks)
    except EnvelopeError:
        raise
    except (tarfile.TarError, gzip.BadGzipFile, EOFError, OSError) as exc:
        raise EnvelopeError(f"Failed to read archive: {exc}") from exc

    missing = sorted(REQUIRED_ARCHIVE_FILES - set(file_digests.keys()))
    if missing:
        raise EnvelopeError(f"Missing required archive entries: {', '.join(missing)}")

    if zach_size <= 0:
        raise EnvelopeError("zach binary in archive is empty")
    if len(zach_header) < 20 or zach_header[:6] != b"\x7fELF\x02\x01":
        raise EnvelopeError("zach binary in archive is not little-endian ELF64")
    machine = int.from_bytes(zach_header[18:20], "little")
    if machine != 183:
        raise EnvelopeError(f"zach binary ELF machine {machine} is not aarch64 (183)")

    if web_index_size <= 0:
        raise EnvelopeError("web/dist/index.html in archive is empty")

    actual_source = small_contents["SOURCE_SHA"].decode("utf-8", errors="strict").strip()
    if actual_source != source_sha:
        raise EnvelopeError(f"SOURCE_SHA {actual_source!r} != {source_sha!r}")

    actual_target = small_contents["RUST_TARGET"].decode("utf-8", errors="strict").strip()
    if actual_target != EXPECTED_RUST_TARGET:
        raise EnvelopeError(f"RUST_TARGET {actual_target!r} != {EXPECTED_RUST_TARGET!r}")

    release_meta = parse_strict_json_bytes(small_contents["zach-release.json"], "zach-release.json")
    if release_meta.get("source_sha") != source_sha:
        raise EnvelopeError("zach-release.json source_sha mismatch")
    if release_meta.get("rust_target") != EXPECTED_RUST_TARGET:
        raise EnvelopeError("zach-release.json rust_target mismatch")
    if release_meta.get("binary_sha256") != file_digests["zach"]:
        raise EnvelopeError("zach-release.json binary_sha256 mismatch")
    _validate_build_run_id(release_meta.get("build_run_id"), build_run_id, "zach-release.json")

    panel_release = parse_strict_json_bytes(
        small_contents["web/dist/release.json"], "web/dist/release.json"
    )
    if panel_release != {"schema_version": 1, "source_sha": source_sha}:
        raise EnvelopeError("web/dist/release.json must match schema_version=1 and source_sha")

    sums_text = small_contents["SHA256SUMS"].decode("utf-8", errors="strict")
    listed_sums: dict[str, str] = {}
    for line in sums_text.splitlines():
        if not line.strip():
            continue
        match = SHA256SUM_LINE_RE.fullmatch(line)
        if not match:
            raise EnvelopeError(f"Malformed SHA256SUMS line: {line!r}")
        expected_hex, rel_path = match.group(1), match.group(2)
        if rel_path in listed_sums:
            raise EnvelopeError(f"Duplicate SHA256SUMS entry: {rel_path}")
        if rel_path not in file_digests:
            raise EnvelopeError(f"SHA256SUMS references missing file: {rel_path}")
        if file_digests[rel_path] != expected_hex:
            raise EnvelopeError(f"SHA256SUMS mismatch for {rel_path}")
        listed_sums[rel_path] = expected_hex

    expected_covered = set(file_digests.keys()) - {"SHA256SUMS"}
    uncovered = sorted(expected_covered - set(listed_sums.keys()))
    if uncovered:
        raise EnvelopeError(f"SHA256SUMS missing entries: {', '.join(uncovered)}")

    tree_digest = hashlib.sha256()
    prefix = "web/dist/"
    for rel_path in sorted(k for k in file_digests if k.startswith(prefix)):
        sub_rel = rel_path[len(prefix):]
        tree_digest.update(sub_rel.encode("utf-8") + b"\0")
        tree_digest.update(file_digests[rel_path].encode("utf-8") + b"\n")
    panel_sha256 = tree_digest.hexdigest()

    if "panel_sha256" in release_meta and release_meta["panel_sha256"] != panel_sha256:
        raise EnvelopeError("zach-release.json panel_sha256 mismatch")

    return {
        "source_sha": source_sha,
        "build_run_id": build_run_id,
        "artifact_sha256": actual_archive_sha,
        "artifact_digest": actual_archive_sha,
        "binary_sha256": file_digests["zach"],
        "panel_sha256": panel_sha256,
    }


def normalize_plan(
    raw_plan_path: Path,
    build_run_id: str,
    expected_source: str,
    expected_digest: str,
    expected_current: str | None = None,
) -> dict[str, Any]:
    if not BUILD_RUN_ID_RE.fullmatch(build_run_id):
        raise EnvelopeError(f"Invalid --build-run-id: {build_run_id!r}")
    if not HEX_40_RE.fullmatch(expected_source):
        raise EnvelopeError(f"Invalid --expected-source: {expected_source!r}")
    if not HEX_64_RE.fullmatch(expected_digest):
        raise EnvelopeError(f"Invalid --expected-digest: {expected_digest!r}")
    if expected_current is not None:
        _validate_expected_current(expected_current)

    raw = parse_strict_json_bytes(raw_plan_path.read_bytes(), str(raw_plan_path))
    if raw.get("status") != "plan":
        raise EnvelopeError(f"plan status must be 'plan', got {raw.get('status')!r}")
    if raw.get("compatible") is not True:
        raise EnvelopeError(f"plan compatible must be true, got {raw.get('compatible')!r}")
    if raw.get("journal_pending") is not False:
        raise EnvelopeError(f"plan journal_pending must be false, got {raw.get('journal_pending')!r}")
    if type(raw.get("workers_quiescent")) is not bool:
        raise EnvelopeError("plan workers_quiescent must be a boolean")

    if raw.get("source_sha") != expected_source:
        raise EnvelopeError(f"plan source_sha {raw.get('source_sha')!r} != {expected_source!r}")
    _validate_build_run_id(raw.get("build_run_id"), build_run_id, "plan")

    if raw.get("artifact_sha256") != expected_digest:
        raise EnvelopeError(f"plan artifact_sha256 {raw.get('artifact_sha256')!r} != {expected_digest!r}")
    if "artifact_digest" in raw and raw["artifact_digest"] != expected_digest:
        raise EnvelopeError(f"plan artifact_digest {raw.get('artifact_digest')!r} != {expected_digest!r}")

    binary_sha256 = raw.get("binary_sha256")
    panel_sha256 = raw.get("panel_sha256")
    if not isinstance(binary_sha256, str) or not HEX_64_RE.fullmatch(binary_sha256):
        raise EnvelopeError("plan binary_sha256 must be 64-hex")
    if not isinstance(panel_sha256, str) or not HEX_64_RE.fullmatch(panel_sha256):
        raise EnvelopeError("plan panel_sha256 must be 64-hex")

    current = raw.get("current")
    if current is None:
        observed_current = "none"
    elif isinstance(current, dict):
        cur_sha = current.get("source_sha")
        if not isinstance(cur_sha, str) or not HEX_40_RE.fullmatch(cur_sha):
            raise EnvelopeError("plan current.source_sha must be 40-hex")
        observed_current = cur_sha
    else:
        raise EnvelopeError("plan current must be null or object")

    if "expected_current" in raw and raw["expected_current"] != observed_current:
        raise EnvelopeError(
            f"plan expected_current {raw['expected_current']!r} != observed current {observed_current!r}"
        )
    if expected_current is not None and observed_current != expected_current:
        raise EnvelopeError(
            f"Host current state {observed_current!r} drifted from expected_current {expected_current!r}"
        )

    return {
        "status": "plan",
        "compatible": True,
        "source_sha": expected_source,
        "build_run_id": build_run_id,
        "artifact_digest": expected_digest,
        "artifact_sha256": expected_digest,
        "expected_current": observed_current,
        "binary_sha256": binary_sha256,
        "panel_sha256": panel_sha256,
        "workers_quiescent": raw["workers_quiescent"],
        "journal_pending": False,
        "current": current,
        "previous": raw.get("previous"),
    }


def normalize_delivery(
    raw_plan_path: Path,
    raw_delivery_path: Path,
    build_run_id: str,
    expected_source: str,
    expected_digest: str,
    expected_current: str,
) -> dict[str, Any]:
    _validate_expected_current(expected_current)
    plan = normalize_plan(
        raw_plan_path=raw_plan_path,
        build_run_id=build_run_id,
        expected_source=expected_source,
        expected_digest=expected_digest,
        expected_current=expected_current,
    )

    raw = parse_strict_json_bytes(raw_delivery_path.read_bytes(), str(raw_delivery_path))
    if raw.get("status") != "published":
        raise EnvelopeError(f"delivery status must be 'published', got {raw.get('status')!r}")
    if raw.get("operation") != "deploy":
        raise EnvelopeError(f"delivery operation must be 'deploy', got {raw.get('operation')!r}")
    if raw.get("source_sha") != expected_source:
        raise EnvelopeError(f"delivery source_sha {raw.get('source_sha')!r} != {expected_source!r}")
    _validate_build_run_id(raw.get("build_run_id"), build_run_id, "delivery")

    if raw.get("artifact_sha256") != expected_digest:
        raise EnvelopeError(
            f"delivery artifact_sha256 {raw.get('artifact_sha256')!r} != {expected_digest!r}"
        )
    if "artifact_digest" in raw and raw["artifact_digest"] != expected_digest:
        raise EnvelopeError(
            f"delivery artifact_digest {raw.get('artifact_digest')!r} != {expected_digest!r}"
        )
    if raw.get("expected_current") != expected_current:
        raise EnvelopeError(
            f"delivery expected_current {raw.get('expected_current')!r} != {expected_current!r}"
        )
    if raw.get("binary_sha256") != plan["binary_sha256"]:
        raise EnvelopeError("delivery binary_sha256 does not match plan")
    if raw.get("panel_sha256") != plan["panel_sha256"]:
        raise EnvelopeError("delivery panel_sha256 does not match plan")

    return {
        "status": "published",
        "operation": "deploy",
        "source_sha": expected_source,
        "build_run_id": build_run_id,
        "artifact_digest": expected_digest,
        "artifact_sha256": expected_digest,
        "expected_current": expected_current,
        "binary_sha256": plan["binary_sha256"],
        "panel_sha256": plan["panel_sha256"],
        "previous": raw.get("previous"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate and normalize Zach promotion envelopes.")
    sub = parser.add_subparsers(dest="command", required=True)

    art = sub.add_parser("artifact")
    art.add_argument("--build-run-file", type=Path, default=Path("build-run.json"))
    art.add_argument("--release-sha256", type=Path, default=Path("release.sha256"))
    art.add_argument("--archive", type=Path, default=Path("zach-release.tar.gz"))
    art.add_argument("--build-run-id", required=True)
    art.add_argument("--expected-source", default=None)
    art.add_argument("--expected-digest", default=None)

    pln = sub.add_parser("plan")
    pln.add_argument("--raw-plan", type=Path, default=Path("zach-plan.raw.json"))
    pln.add_argument("--build-run-id", required=True)
    pln.add_argument("--expected-source", required=True)
    pln.add_argument("--expected-digest", required=True)
    pln.add_argument("--expected-current", default=None)

    dlv = sub.add_parser("delivery")
    dlv.add_argument("--raw-plan", type=Path, default=Path("zach-plan.raw.json"))
    dlv.add_argument("--raw-delivery", type=Path, default=Path("zach-delivery.raw.json"))
    dlv.add_argument("--build-run-id", required=True)
    dlv.add_argument("--expected-source", required=True)
    dlv.add_argument("--expected-digest", required=True)
    dlv.add_argument("--expected-current", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "artifact":
            result = verify_artifact(
                build_run_path=args.build_run_file,
                release_sha256_path=args.release_sha256,
                archive_path=args.archive,
                build_run_id=args.build_run_id,
                expected_source=args.expected_source,
                expected_digest=args.expected_digest,
            )
        elif args.command == "plan":
            result = normalize_plan(
                raw_plan_path=args.raw_plan,
                build_run_id=args.build_run_id,
                expected_source=args.expected_source,
                expected_digest=args.expected_digest,
                expected_current=args.expected_current,
            )
        else:
            result = normalize_delivery(
                raw_plan_path=args.raw_plan,
                raw_delivery_path=args.raw_delivery,
                build_run_id=args.build_run_id,
                expected_source=args.expected_source,
                expected_digest=args.expected_digest,
                expected_current=args.expected_current,
            )
    except EnvelopeError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 1

    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
