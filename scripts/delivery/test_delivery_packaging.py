#!/usr/bin/env python3
"""Offline unit and CLI tests for Zach release packaging and promotion envelopes."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

DELIVERY_DIR = Path(__file__).resolve().parent
PACKAGE_SCRIPT = DELIVERY_DIR / "package-release.py"
ENVELOPE_SCRIPT = DELIVERY_DIR / "promotion_envelope.py"

sys.path.insert(0, str(DELIVERY_DIR))
import promotion_envelope  # noqa: E402


def _load_package_module():
    spec = importlib.util.spec_from_file_location("package_release", PACKAGE_SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


package_release = _load_package_module()


def _make_elf64(machine: int = 183) -> bytes:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # ELFCLASS64
    header[5] = 1  # ELFDATA2LSB
    header[6] = 1  # EV_CURRENT
    header[16:18] = (2).to_bytes(2, "little")  # ET_EXEC
    header[18:20] = machine.to_bytes(2, "little")
    return bytes(header) + b"\x00" * 128


def _init_git_repo(repo_dir: Path) -> str:
    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
    (repo_dir / "README.md").write_text("zach\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo_dir, check=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo_dir, capture_output=True, text=True, check=True
    ).stdout.strip()


def _create_web_dist(web_dir: Path, source_sha: str) -> None:
    (web_dir / "assets").mkdir(parents=True, exist_ok=True)
    (web_dir / "index.html").write_text("<html><body>Zach</body></html>\n", encoding="utf-8")
    (web_dir / "assets" / "app.js").write_text("console.log('zach');\n", encoding="utf-8")
    (web_dir / "release.json").write_text(
        json.dumps({"schema_version": 1, "source_sha": source_sha}) + "\n",
        encoding="utf-8",
    )


class DeliveryPackagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.head_sha = _init_git_repo(self.repo)
        self.binary = self.root / "zach"
        self.binary.write_bytes(_make_elf64(183))
        self.web_dist = self.root / "web-dist"
        _create_web_dist(self.web_dist, self.head_sha)
        self.out_dir = self.root / "out"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run_packager(
        self,
        *,
        binary: Path | None = None,
        web_dist: Path | None = None,
        source_sha: str | None = None,
        build_run_id: str = "123456789",
        out_dir: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(PACKAGE_SCRIPT),
                "--binary",
                str(binary or self.binary),
                "--web-dist",
                str(web_dist or self.web_dist),
                "--source-sha",
                source_sha if source_sha is not None else self.head_sha,
                "--build-run-id",
                build_run_id,
                "--output-dir",
                str(out_dir or self.out_dir),
            ],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_valid_packaging_and_determinism_across_mtimes(self) -> None:
        res1 = self._run_packager()
        self.assertEqual(res1.returncode, 0, res1.stderr)
        archive1 = (self.out_dir / "zach-release.tar.gz").read_bytes()
        sha1 = (self.out_dir / "release.sha256").read_text(encoding="utf-8")

        # Touch files with different mtimes and package into a second directory.
        os.utime(self.binary, (1000000, 1000000))
        os.utime(self.web_dist / "index.html", (2000000, 2000000))
        out2 = self.root / "out2"
        res2 = self._run_packager(out_dir=out2)
        self.assertEqual(res2.returncode, 0, res2.stderr)
        archive2 = (out2 / "zach-release.tar.gz").read_bytes()
        sha2 = (out2 / "release.sha256").read_text(encoding="utf-8")

        self.assertEqual(archive1, archive2)
        self.assertEqual(sha1, sha2)

        expected_digest = hashlib.sha256(archive1).hexdigest()
        self.assertEqual(sha1, f"{expected_digest}  zach-release.tar.gz\n")

    def test_fail_closed_rejections_leave_zero_outputs(self) -> None:
        other_sha = "0" * 40
        cases = []

        # 1. Mismatched / invalid source SHA
        cases.append(("bad_sha_len", dict(source_sha="abc")))
        cases.append(("mismatched_sha", dict(source_sha=other_sha)))

        # 2. Invalid build_run_id
        cases.append(("bad_run_id", dict(build_run_id="0")))
        cases.append(("non_numeric_run_id", dict(build_run_id="12abc")))

        # 3. x86_64 binary, non-ELF binary, symlink binary
        x86_bin = self.root / "zach-x86"
        x86_bin.write_bytes(_make_elf64(62))
        cases.append(("x86_64_binary", dict(binary=x86_bin)))

        txt_bin = self.root / "zach-txt"
        txt_bin.write_bytes(b"#!/bin/sh\necho hi\n")
        cases.append(("non_elf_binary", dict(binary=txt_bin)))

        sym_bin = self.root / "zach-sym"
        sym_bin.symlink_to(self.binary)
        cases.append(("symlink_binary", dict(binary=sym_bin)))

        for idx, (label, kwargs) in enumerate(cases):
            out = self.root / f"fail-out-{idx}"
            res = self._run_packager(out_dir=out, **kwargs)
            self.assertNotEqual(res.returncode, 0, f"{label} unexpectedly succeeded")
            self.assertFalse((out / "zach-release.tar.gz").exists(), label)
            self.assertFalse((out / "release.sha256").exists(), label)

    def test_web_dist_fail_closed_cases(self) -> None:
        # Symlink inside web/dist
        sym_dist = self.root / "web-sym"
        _create_web_dist(sym_dist, self.head_sha)
        (sym_dist / "leak").symlink_to("/etc/passwd")
        self.assertNotEqual(self._run_packager(web_dist=sym_dist).returncode, 0)

        # Missing index.html
        no_idx = self.root / "web-no-idx"
        _create_web_dist(no_idx, self.head_sha)
        (no_idx / "index.html").unlink()
        self.assertNotEqual(self._run_packager(web_dist=no_idx).returncode, 0)

        # Empty index.html
        empty_idx = self.root / "web-empty-idx"
        _create_web_dist(empty_idx, self.head_sha)
        (empty_idx / "index.html").write_bytes(b"")
        self.assertNotEqual(self._run_packager(web_dist=empty_idx).returncode, 0)

        # Missing release.json
        no_rel = self.root / "web-no-rel"
        _create_web_dist(no_rel, self.head_sha)
        (no_rel / "release.json").unlink()
        self.assertNotEqual(self._run_packager(web_dist=no_rel).returncode, 0)

        # Duplicate key in release.json
        dup_rel = self.root / "web-dup-rel"
        _create_web_dist(dup_rel, self.head_sha)
        (dup_rel / "release.json").write_text(
            f'{{"schema_version":1,"schema_version":1,"source_sha":"{self.head_sha}"}}\n',
            encoding="utf-8",
        )
        self.assertNotEqual(self._run_packager(web_dist=dup_rel).returncode, 0)

        # Extra key in release.json
        extra_rel = self.root / "web-extra-rel"
        _create_web_dist(extra_rel, self.head_sha)
        (extra_rel / "release.json").write_text(
            json.dumps({"schema_version": 1, "source_sha": self.head_sha, "extra": True}),
            encoding="utf-8",
        )
        self.assertNotEqual(self._run_packager(web_dist=extra_rel).returncode, 0)

        # Mismatched source_sha in release.json
        mismatch_rel = self.root / "web-mismatch-rel"
        _create_web_dist(mismatch_rel, self.head_sha)
        (mismatch_rel / "release.json").write_text(
            json.dumps({"schema_version": 1, "source_sha": "a" * 40}),
            encoding="utf-8",
        )
        self.assertNotEqual(self._run_packager(web_dist=mismatch_rel).returncode, 0)

        # Disallowed .artifact-sha256 member
        art_dist = self.root / "web-art-member"
        _create_web_dist(art_dist, self.head_sha)
        (art_dist / ".artifact-sha256").write_text("abc\n", encoding="utf-8")
        self.assertNotEqual(self._run_packager(web_dist=art_dist).returncode, 0)

        self.assertFalse((self.out_dir / "zach-release.tar.gz").exists())


class PromotionEnvelopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.head_sha = _init_git_repo(self.repo)
        self.binary = self.root / "zach"
        self.binary.write_bytes(_make_elf64(183))
        self.web_dist = self.root / "web-dist"
        _create_web_dist(self.web_dist, self.head_sha)
        self.out_dir = self.root / "out"
        self.build_run_id = "987654321"

        res = subprocess.run(
            [
                sys.executable,
                str(PACKAGE_SCRIPT),
                "--binary",
                str(self.binary),
                "--web-dist",
                str(self.web_dist),
                "--source-sha",
                self.head_sha,
                "--build-run-id",
                self.build_run_id,
                "--output-dir",
                str(self.out_dir),
            ],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=True,
        )
        self.packaged = json.loads(res.stdout)
        self.digest = self.packaged["artifact_sha256"]
        self.archive = self.out_dir / "zach-release.tar.gz"
        self.sha_file = self.out_dir / "release.sha256"
        self.build_run = self.out_dir / "build-run.json"
        self._write_build_run()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write_build_run(self, **overrides: object) -> None:
        data: dict[str, object] = {
            "id": int(self.build_run_id),
            "head_sha": self.head_sha,
            "head_branch": "main",
            "conclusion": "success",
            "event": "push",
            "path": ".github/workflows/ci.yml",
        }
        data.update(overrides)
        self.build_run.write_text(json.dumps(data), encoding="utf-8")

    def test_artifact_verification_cli_and_tamper_rejection(self) -> None:
        proc = subprocess.run(
            [
                sys.executable,
                str(ENVELOPE_SCRIPT),
                "artifact",
                "--build-run-file",
                str(self.build_run),
                "--release-sha256",
                str(self.sha_file),
                "--archive",
                str(self.archive),
                "--build-run-id",
                self.build_run_id,
                "--expected-source",
                self.head_sha,
                "--expected-digest",
                self.digest,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        verified = json.loads(proc.stdout)
        self.assertEqual(verified["artifact_digest"], self.digest)
        self.assertEqual(verified["source_sha"], self.head_sha)
        self.binary_sha256 = verified["binary_sha256"]
        self.panel_sha256 = verified["panel_sha256"]

        # Tampered build-run.json
        for bad in [
            {"conclusion": "failure"},
            {"head_branch": "feature"},
            {"path": ".github/workflows/other.yml"},
            {"id": True},
            {"head_sha": "b" * 40},
        ]:
            self._write_build_run(**bad)
            with self.assertRaises(promotion_envelope.EnvelopeError):
                promotion_envelope.verify_artifact(
                    self.build_run, self.sha_file, self.archive, self.build_run_id
                )
        self._write_build_run()

        # release.sha256 drift
        self.sha_file.write_text(f"{'c' * 64}  zach-release.tar.gz\n", encoding="utf-8")
        with self.assertRaises(promotion_envelope.EnvelopeError):
            promotion_envelope.verify_artifact(
                self.build_run, self.sha_file, self.archive, self.build_run_id
            )
        self.sha_file.write_text(f"{self.digest}  zach-release.tar.gz\n", encoding="utf-8")

    def test_corrupted_sha256sums_and_unexpected_tar_members(self) -> None:
        # Rewrite archive with corrupted SHA256SUMS
        bad_sums_archive = self.root / "bad-sums.tar.gz"
        with tarfile.open(self.archive, "r:gz") as src, tarfile.open(
            bad_sums_archive, "w:gz"
        ) as dst:
            for member in src.getmembers():
                data = src.extractfile(member).read() if member.isfile() else None
                if member.name == "SHA256SUMS":
                    data = b"0" * 64 + b"  zach\n"
                    member.size = len(data)
                dst.addfile(member, io.BytesIO(data) if data is not None else None)
        bad_sha_file = self.root / "bad-sums.sha256"
        bad_sha_file.write_text(
            f"{hashlib.sha256(bad_sums_archive.read_bytes()).hexdigest()}  zach-release.tar.gz\n",
            encoding="utf-8",
        )
        with self.assertRaises(promotion_envelope.EnvelopeError):
            promotion_envelope.verify_artifact(
                self.build_run, bad_sha_file, bad_sums_archive, self.build_run_id
            )

        # Rewrite archive with symlink and unexpected entry
        for kind in ("symlink", "unexpected", "duplicate"):
            bad_archive = self.root / f"bad-{kind}.tar.gz"
            with tarfile.open(self.archive, "r:gz") as src, tarfile.open(
                bad_archive, "w:gz"
            ) as dst:
                for member in src.getmembers():
                    data = src.extractfile(member).read() if member.isfile() else None
                    dst.addfile(member, io.BytesIO(data) if data is not None else None)
                    if kind == "duplicate" and member.name == "SOURCE_SHA":
                        dst.addfile(member, io.BytesIO(data))
                if kind == "symlink":
                    sym = tarfile.TarInfo("web/dist/evil")
                    sym.type = tarfile.SYMTYPE
                    sym.linkname = "/etc/passwd"
                    dst.addfile(sym)
                elif kind == "unexpected":
                    extra = tarfile.TarInfo("extra.txt")
                    extra.size = 2
                    dst.addfile(extra, io.BytesIO(b"hi"))
            bad_sha = self.root / f"bad-{kind}.sha256"
            bad_sha.write_text(
                f"{hashlib.sha256(bad_archive.read_bytes()).hexdigest()}  zach-release.tar.gz\n",
                encoding="utf-8",
            )
            with self.assertRaises(promotion_envelope.EnvelopeError):
                promotion_envelope.verify_artifact(
                    self.build_run, bad_sha, bad_archive, self.build_run_id
                )

    def test_plan_and_delivery_normalization_and_cas(self) -> None:
        art = promotion_envelope.verify_artifact(
            self.build_run, self.sha_file, self.archive, self.build_run_id
        )
        bin_sha = art["binary_sha256"]
        pan_sha = art["panel_sha256"]

        # 1. Bootstrap (current: None -> expected_current: "none"), workers_quiescent: False allowed
        raw_plan = self.out_dir / "zach-plan.raw.json"
        raw_plan.write_text(
            json.dumps(
                {
                    "status": "plan",
                    "compatible": True,
                    "source_sha": self.head_sha,
                    "build_run_id": self.build_run_id,
                    "artifact_digest": self.digest,
                    "artifact_sha256": self.digest,
                    "expected_current": "none",
                    "current": None,
                    "previous": None,
                    "binary_sha256": bin_sha,
                    "panel_sha256": pan_sha,
                    "workers_quiescent": False,
                    "journal_pending": False,
                }
            ),
            encoding="utf-8",
        )
        plan = promotion_envelope.normalize_plan(
            raw_plan, self.build_run_id, self.head_sha, self.digest
        )
        self.assertEqual(plan["expected_current"], "none")
        self.assertFalse(plan["workers_quiescent"])

        # 2. Existing 40-hex current + CAS mismatch rejection
        prev_sha = "d" * 40
        raw_plan.write_text(
            json.dumps(
                {
                    "status": "plan",
                    "compatible": True,
                    "source_sha": self.head_sha,
                    "build_run_id": self.build_run_id,
                    "artifact_sha256": self.digest,
                    "expected_current": prev_sha,
                    "current": {"source_sha": prev_sha, "managed": True},
                    "previous": None,
                    "binary_sha256": bin_sha,
                    "panel_sha256": pan_sha,
                    "workers_quiescent": True,
                    "journal_pending": False,
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaises(promotion_envelope.EnvelopeError):
            promotion_envelope.normalize_plan(
                raw_plan,
                self.build_run_id,
                self.head_sha,
                self.digest,
                expected_current="none",
            )

        # 3. Delivery receipt binding
        raw_delivery = self.out_dir / "zach-delivery.raw.json"
        raw_delivery.write_text(
            json.dumps(
                {
                    "status": "published",
                    "operation": "deploy",
                    "source_sha": self.head_sha,
                    "build_run_id": self.build_run_id,
                    "artifact_digest": self.digest,
                    "artifact_sha256": self.digest,
                    "expected_current": prev_sha,
                    "previous": prev_sha,
                    "binary_sha256": bin_sha,
                    "panel_sha256": pan_sha,
                }
            ),
            encoding="utf-8",
        )
        delivery = promotion_envelope.normalize_delivery(
            raw_plan,
            raw_delivery,
            self.build_run_id,
            self.head_sha,
            self.digest,
            prev_sha,
        )
        self.assertEqual(delivery["status"], "published")
        self.assertEqual(delivery["expected_current"], prev_sha)

        # CAS mismatch in delivery
        with self.assertRaises(promotion_envelope.EnvelopeError):
            promotion_envelope.normalize_delivery(
                raw_plan,
                raw_delivery,
                self.build_run_id,
                self.head_sha,
                self.digest,
                "e" * 40,
            )


if __name__ == "__main__":
    unittest.main()
