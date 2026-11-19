#!/usr/bin/env python3
"""Deterministically package and fail-closed verify a Zach release archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

EXPECTED_RUST_TARGET = "aarch64-unknown-linux-gnu"
HEX_40_RE = re.compile(r"^[0-9a-f]{40}$")
BUILD_RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")

MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_WEB_TOTAL_BYTES = 256 * 1024 * 1024
MAX_WEB_ENTRIES = 9990
MAX_METADATA_BYTES = 65536
MAX_COMPRESSED_BYTES = 256 * 1024 * 1024
MAX_TAR_BYTES = 512 * 1024 * 1024


class PackagingError(Exception):
    """Raised when release packaging inputs fail validation."""


def _unique_keys_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PackagingError(f"Duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _strict_parse_json(raw: bytes, label: str) -> dict[str, object]:
    if len(raw) == 0 or len(raw) > MAX_METADATA_BYTES:
        raise PackagingError(f"{label} size out of bounds ({len(raw)} bytes)")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PackagingError(f"{label} is not valid UTF-8: {exc}") from exc

    def _reject_constant(val: str) -> None:
        raise PackagingError(f"{label} contains non-standard JSON constant: {val}")

    try:
        data = json.loads(
            text,
            object_pairs_hook=_unique_keys_hook,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise PackagingError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise PackagingError(f"{label} must be a JSON object")
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


def _verify_git_head(source_sha: str) -> None:
    if not HEX_40_RE.fullmatch(source_sha):
        raise PackagingError(f"source_sha must be 40 lowercase hex chars, got {source_sha!r}")
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise PackagingError(f"git rev-parse HEAD failed: {proc.stderr.strip()}")
    head = proc.stdout.strip()
    if head != source_sha:
        raise PackagingError(f"source_sha {source_sha} does not match git HEAD {head}")


def _verify_binary(binary_path: Path) -> str:
    if os.path.islink(binary_path):
        raise PackagingError(f"Binary must not be a symlink: {binary_path}")
    try:
        st = os.lstat(binary_path)
    except OSError as exc:
        raise PackagingError(f"Cannot stat binary {binary_path}: {exc}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise PackagingError(f"Binary is not a regular file: {binary_path}")
    if st.st_size <= 0 or st.st_size > MAX_BINARY_BYTES:
        raise PackagingError(f"Binary size out of bounds: {st.st_size} bytes")

    fd = os.open(binary_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(fd, "rb") as handle:
            header = handle.read(20)
    except OSError as exc:
        raise PackagingError(f"Cannot read binary {binary_path}: {exc}") from exc

    if len(header) < 20 or header[:6] != b"\x7fELF\x02\x01":
        raise PackagingError("Binary is not little-endian ELF64")
    machine = int.from_bytes(header[18:20], "little")
    if machine != 183:
        raise PackagingError(f"Binary ELF e_machine={machine} is not aarch64 (183)")
    return _sha256_file(binary_path)


def _validate_rel_component(part: str) -> None:
    if not part or part in (".", "..") or part == ".artifact-sha256":
        raise PackagingError(f"Disallowed path component in web/dist: {part!r}")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in part):
        raise PackagingError(f"Control character in path component: {part!r}")


def _collect_web_dist(web_dist: Path, source_sha: str) -> tuple[list[str], list[tuple[str, Path, str]], str]:
    if os.path.islink(web_dist) or not web_dist.is_dir():
        raise PackagingError(f"web-dist must be a real directory: {web_dist}")

    dirs: list[str] = []
    files: list[tuple[str, Path, str]] = []
    entry_count = 0
    total_bytes = 0

    for dirpath, dirnames, filenames in os.walk(web_dist, topdown=True, followlinks=False):
        dirnames.sort()
        filenames.sort()
        cur = Path(dirpath)
        rel_dir = cur.relative_to(web_dist)
        if rel_dir != Path("."):
            for part in rel_dir.parts:
                _validate_rel_component(part)

        for dname in dirnames:
            _validate_rel_component(dname)
            candidate = cur / dname
            if os.path.islink(candidate):
                raise PackagingError(f"Symlink directory not allowed in web-dist: {candidate}")
            entry_count += 1
            if entry_count > MAX_WEB_ENTRIES:
                raise PackagingError("web-dist exceeds max entry count")
            rel_posix = posixpath.join("web/dist", candidate.relative_to(web_dist).as_posix())
            dirs.append(rel_posix)

        for fname in filenames:
            _validate_rel_component(fname)
            candidate = cur / fname
            if os.path.islink(candidate):
                raise PackagingError(f"Symlink file not allowed in web-dist: {candidate}")
            try:
                st = os.lstat(candidate)
            except OSError as exc:
                raise PackagingError(f"Cannot stat {candidate}: {exc}") from exc
            if not stat.S_ISREG(st.st_mode):
                raise PackagingError(f"Special file not allowed in web-dist: {candidate}")
            entry_count += 1
            if entry_count > MAX_WEB_ENTRIES:
                raise PackagingError("web-dist exceeds max entry count")
            total_bytes += st.st_size
            if total_bytes > MAX_WEB_TOTAL_BYTES:
                raise PackagingError("web-dist exceeds 256 MiB total size")
            rel_posix = posixpath.join("web/dist", candidate.relative_to(web_dist).as_posix())
            files.append((rel_posix, candidate, _sha256_file(candidate)))

    index_path = web_dist / "index.html"
    if os.path.islink(index_path) or not index_path.is_file() or index_path.stat().st_size == 0:
        raise PackagingError("web/dist/index.html must be a non-empty regular file")

    release_json_path = web_dist / "release.json"
    if os.path.islink(release_json_path) or not release_json_path.is_file():
        raise PackagingError("web/dist/release.json must be a regular file")
    release_meta = _strict_parse_json(release_json_path.read_bytes(), "web/dist/release.json")
    if release_meta != {"schema_version": 1, "source_sha": source_sha}:
        raise PackagingError(
            "web/dist/release.json must strictly equal {'schema_version': 1, 'source_sha': source_sha}"
        )

    # Match zach_delivery.py:_tree_digest algorithm exactly.
    tree_digest = hashlib.sha256()
    prefix = "web/dist/"
    for rel_posix, _, file_sha in sorted(files, key=lambda item: item[0]):
        sub_rel = rel_posix[len(prefix):]
        tree_digest.update(sub_rel.encode("utf-8") + b"\0")
        tree_digest.update(file_sha.encode("utf-8") + b"\n")

    return dirs, files, tree_digest.hexdigest()


def _add_dir_entry(tar: tarfile.TarFile, arcname: str) -> None:
    info = tarfile.TarInfo(name=arcname)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    tar.addfile(info)


def _add_bytes_entry(tar: tarfile.TarFile, arcname: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name=arcname)
    info.type = tarfile.REGTYPE
    info.mode = mode
    info.size = len(data)
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    tar.addfile(info, io.BytesIO(data))


def _add_file_entry(tar: tarfile.TarFile, arcname: str, src_path: Path, mode: int) -> None:
    st = src_path.stat()
    info = tarfile.TarInfo(name=arcname)
    info.type = tarfile.REGTYPE
    info.mode = mode
    info.size = st.st_size
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    with src_path.open("rb") as handle:
        tar.addfile(info, handle)


def package_release(
    binary_path: Path,
    web_dist: Path,
    source_sha: str,
    build_run_id: str,
    output_dir: Path,
) -> tuple[Path, Path, str]:
    _verify_git_head(source_sha)
    if not BUILD_RUN_ID_RE.fullmatch(build_run_id):
        raise PackagingError(f"build_run_id must be 1..20 positive digits, got {build_run_id!r}")

    binary_sha256 = _verify_binary(binary_path)
    web_dirs, web_files, panel_sha256 = _collect_web_dist(web_dist, source_sha)

    source_sha_bytes = f"{source_sha}\n".encode("utf-8")
    rust_target_bytes = f"{EXPECTED_RUST_TARGET}\n".encode("utf-8")
    release_meta = {
        "binary_sha256": binary_sha256,
        "build_run_id": build_run_id,
        "panel_sha256": panel_sha256,
        "rust_target": EXPECTED_RUST_TARGET,
        "schema_version": 1,
        "source_sha": source_sha,
    }
    release_meta_bytes = (
        json.dumps(release_meta, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")

    checksum_map: dict[str, str] = {
        "RUST_TARGET": hashlib.sha256(rust_target_bytes).hexdigest(),
        "SOURCE_SHA": hashlib.sha256(source_sha_bytes).hexdigest(),
        "zach": binary_sha256,
        "zach-release.json": hashlib.sha256(release_meta_bytes).hexdigest(),
    }
    for rel_posix, _, file_sha in web_files:
        checksum_map[rel_posix] = file_sha

    sha256sums_lines = [f"{checksum_map[k]}  {k}\n" for k in sorted(checksum_map.keys())]
    sha256sums_bytes = "".join(sha256sums_lines).encode("utf-8")

    output_dir.mkdir(parents=True, exist_ok=True)
    tmp_archive_fd, tmp_archive_str = tempfile.mkstemp(
        prefix=".zach-release-", suffix=".tar.gz", dir=output_dir
    )
    os.close(tmp_archive_fd)
    tmp_archive = Path(tmp_archive_str)

    tmp_sha_fd, tmp_sha_str = tempfile.mkstemp(
        prefix=".release-", suffix=".sha256", dir=output_dir
    )
    os.close(tmp_sha_fd)
    tmp_sha = Path(tmp_sha_str)

    try:
        entries: list[tuple[str, str, object]] = [
            ("bytes", "RUST_TARGET", (rust_target_bytes, 0o644)),
            ("bytes", "SHA256SUMS", (sha256sums_bytes, 0o644)),
            ("bytes", "SOURCE_SHA", (source_sha_bytes, 0o644)),
            ("dir", "web", None),
            ("dir", "web/dist", None),
            ("file", "zach", (binary_path, 0o755)),
            ("bytes", "zach-release.json", (release_meta_bytes, 0o644)),
        ]
        for d in web_dirs:
            entries.append(("dir", d, None))
        for rel_posix, src_path, _ in web_files:
            entries.append(("file", rel_posix, (src_path, 0o644)))

        entries.sort(key=lambda item: item[1])

        with tmp_archive.open("wb") as raw_out:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw_out, mtime=0) as gz:
                class _CountingWriter:
                    def __init__(self, inner: gzip.GzipFile) -> None:
                        self._inner = inner
                        self.written = 0

                    def write(self, data: bytes) -> int:
                        self.written += len(data)
                        if self.written > MAX_TAR_BYTES:
                            raise PackagingError("Uncompressed tar stream exceeds 512 MiB limit")
                        return self._inner.write(data)

                    def flush(self) -> None:
                        self._inner.flush()

                writer = _CountingWriter(gz)
                with tarfile.open(fileobj=writer, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                    for kind, arcname, payload in entries:
                        if kind == "dir":
                            _add_dir_entry(tar, arcname)
                        elif kind == "bytes":
                            data, mode = payload  # type: ignore[misc]
                            _add_bytes_entry(tar, arcname, data, mode)
                        elif kind == "file":
                            src_path, mode = payload  # type: ignore[misc]
                            _add_file_entry(tar, arcname, src_path, mode)

        compressed_size = tmp_archive.stat().st_size
        if compressed_size == 0 or compressed_size > MAX_COMPRESSED_BYTES:
            raise PackagingError(f"Compressed archive size out of bounds: {compressed_size} bytes")

        archive_sha256 = _sha256_file(tmp_archive)
        tmp_sha.write_text(f"{archive_sha256}  zach-release.tar.gz\n", encoding="utf-8")

        final_archive = output_dir / "zach-release.tar.gz"
        final_sha = output_dir / "release.sha256"
        os.replace(tmp_archive, final_archive)
        os.replace(tmp_sha, final_sha)
        return final_archive, final_sha, archive_sha256
    except Exception:
        for p in (tmp_archive, tmp_sha):
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package deterministic Zach release archive.")
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--web-dist", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--build-run-id", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        archive, sha_file, digest = package_release(
            binary_path=args.binary,
            web_dist=args.web_dist,
            source_sha=args.source_sha,
            build_run_id=args.build_run_id,
            output_dir=args.output_dir,
        )
    except PackagingError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 1

    print(
        json.dumps(
            {
                "archive": str(archive),
                "sha256_file": str(sha_file),
                "artifact_sha256": digest,
                "source_sha": args.source_sha,
                "build_run_id": args.build_run_id,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
