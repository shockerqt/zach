"""Durable coordinator for the trusted ``zach-actions`` journal state machine.

This module only coordinates journal state.  It does not execute requested effects,
retry publications, reconcile ambiguous effects, invoke Git, or expose a generic
subprocess interface.  A ``GRANTED`` claim result is execution permission only after
the corresponding record has been durably published and read back.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
import os
import re
import selectors
import subprocess
import tempfile
import time
from typing import Any, Callable, Final, Iterable, Optional

from actions_git_journal import (
    MAX_RECORD_BYTES,
    ActionsGitJournal,
    JournalSnapshot,
    PublicationReceipt,
    parse_and_validate_record,
    validate_request_id,
)


MAX_EVENT_BYTES: Final[int] = 256 * 1024
MAX_CLI_STDOUT_BYTES: Final[int] = MAX_RECORD_BYTES + 1  # canonical record plus newline
MAX_CLI_STDERR_BYTES: Final[int] = 1024
MAX_POLICY_ACTORS: Final[int] = 256
DEFAULT_TIMEOUT_SECONDS: Final[float] = 15.0
SHA40_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")
EXECUTION_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
TOKEN_PREFIXES: Final[tuple[str, ...]] = (
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "bearer",
    "token",
)


class CoordinatorError(Exception):
    """Sanitized coordinator failure that never includes records, paths, or stderr."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class TrustedIssuePolicy:
    """Trusted numeric identity policy supplied by the workflow configuration."""

    repository_id: int
    repository_full_name: str
    allowed_actor_ids: tuple[int, ...]


@dataclass(frozen=True)
class CliProcessResult:
    """Bounded result shape used by the injected CLI-runner test seam."""

    returncode: int
    stdout: bytes = field(repr=False)
    stderr: bytes = field(default=b"", repr=False)


class ClaimDisposition(str, Enum):
    GRANTED = "granted"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    TERMINAL_REPLAY = "terminal_replay"


@dataclass(frozen=True)
class AcceptanceResult:
    request_id: str
    durable_revision: str
    record_json: str = field(repr=False)
    replayed: bool


@dataclass(frozen=True)
class ClaimResult:
    request_id: str
    durable_revision: str
    record_json: str = field(repr=False)
    disposition: ClaimDisposition


@dataclass(frozen=True)
class JournalMutationResult:
    request_id: str
    durable_revision: str
    record_json: str = field(repr=False)
    replayed: bool


class _ExactTransitionValidator:
    """Allow exactly the old/new byte strings produced for one CLI transition."""

    def __init__(self, old_record: Optional[str], new_record: str) -> None:
        self.__old_record = old_record
        self.__new_record = new_record

    def __call__(self, old_record: Optional[str], new_record: str) -> bool:
        return old_record == self.__old_record and new_record == self.__new_record


CliRunner = Callable[[tuple[str, ...], float], CliProcessResult]


class ActionsJournalCoordinator:
    """Connect the trusted Rust state machine to durable Git journal storage."""

    def __init__(
        self,
        cli_executable: str,
        api_transport: Callable[..., Any],
        *,
        cli_runner: Optional[CliRunner] = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if not isinstance(cli_executable, str) or not os.path.isabs(cli_executable):
            raise ValueError("cli_executable must be an absolute path")
        if "\x00" in cli_executable or len(os.fsencode(cli_executable)) > 4096:
            raise ValueError("cli_executable is invalid")
        if not callable(api_transport):
            raise TypeError("api_transport must be callable")
        if cli_runner is not None and not callable(cli_runner):
            raise TypeError("cli_runner must be callable")
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 120:
            raise ValueError("timeout_seconds must be between 0 and 120")

        self.__cli_executable = os.path.realpath(cli_executable)
        self.__api_transport = api_transport
        self.__cli_runner = cli_runner or self._run_subprocess
        self.__timeout_seconds = float(timeout_seconds)

    @staticmethod
    def _run_subprocess(argv: tuple[str, ...], timeout_seconds: float) -> CliProcessResult:
        """Run the pinned binary with a minimal environment and bounded pipes."""
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                cwd="/",
                env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
                close_fds=True,
            )
        except (OSError, ValueError):
            raise CoordinatorError("cli_start_failed") from None

        assert process.stdout is not None
        assert process.stderr is not None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, ("stdout", MAX_CLI_STDOUT_BYTES))
        selector.register(process.stderr, selectors.EVENT_READ, ("stderr", MAX_CLI_STDERR_BYTES))
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + timeout_seconds

        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CoordinatorError("cli_timed_out")
                events = selector.select(remaining)
                if not events:
                    raise CoordinatorError("cli_timed_out")
                for key, _ in events:
                    name, limit = key.data
                    chunk = os.read(key.fd, min(65536, limit - len(buffers[name]) + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffers[name].extend(chunk)
                    if len(buffers[name]) > limit:
                        raise CoordinatorError("cli_output_too_large")

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CoordinatorError("cli_timed_out")
            returncode = process.wait(timeout=remaining)
            return CliProcessResult(returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]))
        except subprocess.TimeoutExpired:
            raise CoordinatorError("cli_timed_out") from None
        except CoordinatorError:
            raise
        except (OSError, ValueError):
            raise CoordinatorError("cli_failed") from None
        finally:
            selector.close()
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                pass
            process.stdout.close()
            process.stderr.close()

    @staticmethod
    def _write_private(directory: str, name: str, content: bytes) -> str:
        path = os.path.join(directory, name)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError:
            raise CoordinatorError("private_input_failed") from None
        try:
            try:
                with os.fdopen(fd, "wb") as handle:
                    fd = -1
                    handle.write(content)
            except OSError:
                raise CoordinatorError("private_input_failed") from None
        finally:
            if fd >= 0:
                os.close(fd)
        return path

    @staticmethod
    def _validate_policy(policy: TrustedIssuePolicy) -> str:
        if not isinstance(policy, TrustedIssuePolicy):
            raise CoordinatorError("invalid_policy")
        if type(policy.repository_id) is not int or not 0 < policy.repository_id <= 2**64 - 1:
            raise CoordinatorError("invalid_policy")
        repo = policy.repository_full_name
        if (
            not isinstance(repo, str)
            or not repo.isascii()
            or not 3 <= len(repo) <= 255
            or repo.count("/") != 1
            or any(ord(char) < 0x21 or ord(char) > 0x7E for char in repo)
            or repo.startswith("--")
        ):
            raise CoordinatorError("invalid_policy")
        actors = policy.allowed_actor_ids
        if (
            type(actors) is not tuple
            or not 1 <= len(actors) <= MAX_POLICY_ACTORS
            or any(type(actor) is not int or not 0 < actor <= 2**64 - 1 for actor in actors)
            or len(set(actors)) != len(actors)
        ):
            raise CoordinatorError("invalid_policy")
        return ",".join(str(actor) for actor in actors)

    @staticmethod
    def _validate_execution_id(execution_id: str) -> None:
        if not isinstance(execution_id, str) or not EXECUTION_ID_RE.fullmatch(execution_id):
            raise CoordinatorError("invalid_execution_id")
        if execution_id.lower().startswith(TOKEN_PREFIXES):
            raise CoordinatorError("invalid_execution_id")

    @staticmethod
    def _validate_terminal_value(value: str, maximum: int, code: str) -> None:
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= maximum
            or not value.isascii()
            or any(ord(char) < 0x20 or ord(char) > 0x7E for char in value)
            or value.startswith("--")
            or any(prefix in value.lower() for prefix in TOKEN_PREFIXES[:6])
            or value.lower().startswith("bearer ")
        ):
            raise CoordinatorError(code)

    def _invoke(self, command: str, arguments: Iterable[str], allowed_codes: set[int]) -> CliProcessResult:
        argv = (self.__cli_executable, command, *tuple(arguments))
        if any(not isinstance(arg, str) or "\x00" in arg or len(os.fsencode(arg)) > 4096 for arg in argv):
            raise CoordinatorError("invalid_cli_argument")
        try:
            result = self.__cli_runner(argv, self.__timeout_seconds)
        except CoordinatorError:
            raise
        except Exception:
            raise CoordinatorError("cli_failed") from None
        if not isinstance(result, CliProcessResult) or type(result.returncode) is not int:
            raise CoordinatorError("invalid_cli_result")
        if type(result.stdout) is not bytes or type(result.stderr) is not bytes:
            raise CoordinatorError("invalid_cli_result")
        if len(result.stdout) > MAX_CLI_STDOUT_BYTES or len(result.stderr) > MAX_CLI_STDERR_BYTES:
            raise CoordinatorError("cli_output_too_large")
        if result.returncode not in allowed_codes:
            if result.returncode == 2:
                raise CoordinatorError("cli_validation_failed")
            if result.returncode == 1:
                raise CoordinatorError("cli_io_failed")
            raise CoordinatorError("cli_failed")
        if result.stderr:
            raise CoordinatorError("cli_unexpected_stderr")
        return result

    @staticmethod
    def _record_from_stdout(stdout: bytes, expected_request_id: Optional[str] = None) -> tuple[str, dict[str, Any]]:
        if not stdout.endswith(b"\n") or stdout.count(b"\n") != 1:
            raise CoordinatorError("cli_record_output_invalid")
        raw = stdout[:-1]
        if not raw or len(raw) > MAX_RECORD_BYTES:
            raise CoordinatorError("cli_record_output_invalid")
        try:
            record = raw.decode("utf-8")

            def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                parsed: dict[str, Any] = {}
                for key, value in pairs:
                    if key in parsed:
                        raise ValueError("duplicate")
                    parsed[key] = value
                return parsed

            def reject_constant(_constant: str) -> None:
                raise ValueError("constant")

            parsed = json.loads(
                record,
                object_pairs_hook=reject_duplicates,
                parse_constant=reject_constant,
            )
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise CoordinatorError("cli_record_output_invalid") from None
        if not isinstance(parsed, dict) or not isinstance(parsed.get("request_id"), str):
            raise CoordinatorError("cli_record_output_invalid")
        request_id = parsed["request_id"]
        try:
            validate_request_id(request_id)
            parse_and_validate_record(record, expected_request_id or request_id)
        except Exception:
            raise CoordinatorError("cli_record_output_invalid") from None
        return record, parsed

    def _journal(self, old_record: Optional[str], new_record: Optional[str] = None) -> ActionsGitJournal:
        if new_record is None:
            validator: Callable[[Optional[str], str], bool] = lambda _old, _new: False
        else:
            validator = _ExactTransitionValidator(old_record, new_record)
        return ActionsGitJournal(request=self.__api_transport, validate_transition=validator)

    def _load(self, request_id: str) -> JournalSnapshot:
        try:
            validate_request_id(request_id)
        except Exception:
            raise CoordinatorError("invalid_request_id") from None
        return self._journal(None).load(request_id)

    def _publish(
        self, snapshot: JournalSnapshot, request_id: str, new_record: str
    ) -> PublicationReceipt:
        return self._journal(snapshot.record_json, new_record).publish(snapshot, request_id, new_record)

    def accept(
        self,
        event: bytes,
        policy: TrustedIssuePolicy,
        accepted_at: str,
        policy_revision: str,
    ) -> AcceptanceResult:
        """Validate an Issue request and durably accept it, or validate exact replay."""
        if type(event) is not bytes or not 0 < len(event) <= MAX_EVENT_BYTES:
            raise CoordinatorError("invalid_event")
        actor_ids = self._validate_policy(policy)
        if (
            not isinstance(accepted_at, str)
            or not accepted_at.isascii()
            or not 1 <= len(accepted_at) <= 35
            or accepted_at.startswith("--")
            or not isinstance(policy_revision, str)
            or not SHA40_RE.fullmatch(policy_revision)
        ):
            raise CoordinatorError("invalid_acceptance_metadata")

        with tempfile.TemporaryDirectory(prefix="zach-actions-") as directory:
            event_path = self._write_private(directory, "event.json", event)
            accepted = self._invoke(
                "accept",
                (
                    "--event", event_path,
                    "--event-name", "issues",
                    "--repository-id", str(policy.repository_id),
                    "--repository-full-name", policy.repository_full_name,
                    "--allowed-actor-ids", actor_ids,
                    "--accepted-at", accepted_at,
                    "--policy-revision", policy_revision,
                ),
                {0},
            )
            candidate, candidate_obj = self._record_from_stdout(accepted.stdout)
            request_id = candidate_obj["request_id"]
            if (
                candidate_obj.get("repository_id") != policy.repository_id
                or candidate_obj.get("repository_full_name") != policy.repository_full_name
                or candidate_obj.get("accepted_at") != accepted_at
                or candidate_obj.get("policy_revision") != policy_revision
                or candidate_obj.get("state") != "accepted"
                or candidate_obj.get("execution_id") is not None
                or candidate_obj.get("terminal_code") is not None
                or candidate_obj.get("terminal_reference") is not None
            ):
                raise CoordinatorError("cli_acceptance_mismatch")

            snapshot = self._load(request_id)
            if snapshot.record_json is not None:
                record_path = self._write_private(directory, "record.json", snapshot.record_json.encode("utf-8"))
                replay = self._invoke(
                    "replay",
                    (
                        "--record", record_path,
                        "--event", event_path,
                        "--event-name", "issues",
                        "--repository-id", str(policy.repository_id),
                        "--repository-full-name", policy.repository_full_name,
                        "--allowed-actor-ids", actor_ids,
                    ),
                    {0},
                )
                replay_record, _ = self._record_from_stdout(replay.stdout, request_id)
                if replay_record != snapshot.record_json:
                    raise CoordinatorError("replay_record_changed")
                return AcceptanceResult(request_id, snapshot.head_sha, snapshot.record_json, True)

            receipt = self._publish(snapshot, request_id, candidate)
            return AcceptanceResult(request_id, receipt.commit_sha, candidate, receipt.replayed)

    def claim(self, request_id: str, execution_id: str) -> ClaimResult:
        """Claim once; only a returned ``GRANTED`` disposition permits effects."""
        self._validate_execution_id(execution_id)
        snapshot = self._load(request_id)
        if snapshot.record_json is None:
            raise CoordinatorError("request_not_found")
        with tempfile.TemporaryDirectory(prefix="zach-actions-") as directory:
            record_path = self._write_private(directory, "record.json", snapshot.record_json.encode("utf-8"))
            invocation = self._invoke(
                "claim",
                ("--record", record_path, "--execution-id", execution_id),
                {0, 10, 75},
            )
            candidate, candidate_obj = self._record_from_stdout(invocation.stdout, request_id)

        if invocation.returncode == 75:
            if candidate != snapshot.record_json:
                raise CoordinatorError("reconciliation_record_changed")
            return ClaimResult(
                request_id, snapshot.head_sha, snapshot.record_json,
                ClaimDisposition.RECONCILIATION_REQUIRED,
            )
        if invocation.returncode == 10:
            if candidate != snapshot.record_json:
                raise CoordinatorError("terminal_replay_record_changed")
            return ClaimResult(
                request_id, snapshot.head_sha, snapshot.record_json,
                ClaimDisposition.TERMINAL_REPLAY,
            )
        if candidate_obj.get("state") != "executing" or candidate_obj.get("execution_id") != execution_id:
            raise CoordinatorError("claim_candidate_invalid")
        receipt = self._publish(snapshot, request_id, candidate)
        return ClaimResult(request_id, receipt.commit_sha, candidate, ClaimDisposition.GRANTED)

    def complete(
        self,
        request_id: str,
        execution_id: str,
        state: str,
        terminal_code: str,
        terminal_reference: Optional[str] = None,
    ) -> JournalMutationResult:
        """Persist a terminal result only for the exact durable execution owner."""
        self._validate_execution_id(execution_id)
        if state not in ("succeeded", "rejected"):
            raise CoordinatorError("invalid_terminal_state")
        self._validate_terminal_value(terminal_code, 128, "invalid_terminal_code")
        if terminal_reference is not None:
            self._validate_terminal_value(terminal_reference, 512, "invalid_terminal_reference")
        return self._owned_mutation(
            request_id,
            execution_id,
            "complete",
            ("--state", state, "--code", terminal_code),
            terminal_reference,
        )

    def mark_ambiguous(self, request_id: str, execution_id: str) -> JournalMutationResult:
        """Persist ambiguity only for the exact durable execution owner."""
        self._validate_execution_id(execution_id)
        return self._owned_mutation(request_id, execution_id, "ambiguous", (), None)

    def _owned_mutation(
        self,
        request_id: str,
        execution_id: str,
        command: str,
        arguments: tuple[str, ...],
        reference: Optional[str],
    ) -> JournalMutationResult:
        snapshot = self._load(request_id)
        if snapshot.record_json is None:
            raise CoordinatorError("request_not_found")
        try:
            stored = parse_and_validate_record(snapshot.record_json, request_id)
        except Exception:
            raise CoordinatorError("stored_record_invalid") from None
        if stored.get("execution_id") != execution_id:
            raise CoordinatorError("execution_owner_mismatch")

        with tempfile.TemporaryDirectory(prefix="zach-actions-") as directory:
            record_path = self._write_private(directory, "record.json", snapshot.record_json.encode("utf-8"))
            argv = ("--record", record_path, *arguments)
            if reference is not None:
                argv = (*argv, "--reference", reference)
            invocation = self._invoke(command, argv, {0})
            candidate, candidate_obj = self._record_from_stdout(invocation.stdout, request_id)
        if candidate_obj.get("execution_id") != execution_id:
            raise CoordinatorError("execution_owner_changed")
        receipt = self._publish(snapshot, request_id, candidate)
        return JournalMutationResult(request_id, receipt.commit_sha, candidate, receipt.replayed)
