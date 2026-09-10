#!/usr/bin/env python3
"""Bounded GitHub Actions entry point for isolated Publisher and Control phases."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
import re
import stat
import sys
from typing import Any, Final, Optional, Sequence

from actions_ci_inspect import CiInspectionPolicy
from actions_git_journal import FIXED_REPOSITORY
from actions_github_api import GithubApi
from actions_journal_coordinator import ActionsJournalCoordinator, ClaimDisposition, TrustedIssuePolicy
from actions_request_handler import (
    ActionsHandlerError,
    ControlPhase,
    ExecutionBundle,
    PublisherPhase,
    TrustedReceiptPolicy,
)


TOKEN_ENV: Final[str] = "ZACH_INSTALLATION_TOKEN"
RESULT_KIND: Final[str] = "zach.actions.phase.result"
MAX_POLICY_BYTES: Final[int] = 32 * 1024
MAX_PREPARE_RESULT_BYTES: Final[int] = 128 * 1024
MAX_EVENT_BYTES: Final[int] = 256 * 1024
MAX_OUTPUT_BYTES: Final[int] = 128 * 1024
SAFE_CODE_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
SHA40_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")


class PhaseCliError(Exception):
    """Sanitized CLI failure safe for a bounded machine result."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code if SAFE_CODE_RE.fullmatch(code) else "phase_failed"


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise PhaseCliError("invalid_arguments")


@dataclass(frozen=True)
class PhasePolicy:
    issue: TrustedIssuePolicy
    receipt: TrustedReceiptPolicy
    ci: CiInspectionPolicy
    policy_revision: str


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PhaseCliError("invalid_json")
        result[key] = value
    return result


def _read_bounded(path: str, maximum: int, code: str) -> bytes:
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
                raise PhaseCliError(code)
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                data = handle.read(maximum + 1)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except PhaseCliError:
        raise
    except (OSError, ValueError):
        raise PhaseCliError(code) from None
    if not data or len(data) > maximum:
        raise PhaseCliError(code)
    return data


def _read_json(path: str, maximum: int, code: str) -> dict[str, Any]:
    raw = _read_bounded(path, maximum, code)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except PhaseCliError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise PhaseCliError(code) from None
    if type(value) is not dict:
        raise PhaseCliError(code)
    return value


def _exact_keys(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise PhaseCliError(code)
    return value


def _load_policy(path: str) -> PhasePolicy:
    value = _read_json(path, MAX_POLICY_BYTES, "invalid_policy")
    _exact_keys(
        value,
        {"schema_version", "repository", "allowed_actor_ids", "control_identity", "ci", "policy_revision"},
        "invalid_policy",
    )
    repository = _exact_keys(value["repository"], {"id", "full_name"}, "invalid_policy")
    control = _exact_keys(value["control_identity"], {"app_id", "bot_user_id"}, "invalid_policy")
    ci = _exact_keys(
        value["ci"],
        {"repository_alias", "repository_id", "repository_full_name", "workflow_id", "workflow_path"},
        "invalid_policy",
    )
    actors = value["allowed_actor_ids"]
    revision = value["policy_revision"]
    if (
        value["schema_version"] != 1
        or type(actors) is not list
        or not actors
        or len(actors) > 256
        or any(type(actor) is not int for actor in actors)
        or len(set(actors)) != len(actors)
        or not isinstance(revision, str)
        or not SHA40_RE.fullmatch(revision)
    ):
        raise PhaseCliError("invalid_policy")
    try:
        return PhasePolicy(
            issue=TrustedIssuePolicy(
                repository_id=repository["id"],
                repository_full_name=repository["full_name"],
                allowed_actor_ids=tuple(actors),
            ),
            receipt=TrustedReceiptPolicy(
                app_id=control["app_id"],
                bot_user_id=control["bot_user_id"],
            ),
            ci=CiInspectionPolicy(
                repository_alias=ci["repository_alias"],
                repository_full_name=ci["repository_full_name"],
                repository_id=ci["repository_id"],
                workflow_id=ci["workflow_id"],
                workflow_path=ci["workflow_path"],
            ),
            policy_revision=revision,
        )
    except (KeyError, TypeError, ValueError):
        raise PhaseCliError("invalid_policy") from None


def _installation_token() -> str:
    token = os.environ.get(TOKEN_ENV)
    if token is None:
        raise PhaseCliError("missing_installation_token")
    if not token or not token.isascii() or any(character.isspace() or ord(character) < 0x20 for character in token):
        raise PhaseCliError("invalid_installation_token")
    return token


def _validate_cli_path(path: str) -> str:
    if not isinstance(path, str) or not os.path.isabs(path):
        raise PhaseCliError("invalid_rust_cli")
    try:
        resolved = os.path.realpath(path)
        metadata = os.stat(resolved)
    except OSError:
        raise PhaseCliError("invalid_rust_cli") from None
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise PhaseCliError("invalid_rust_cli")
    return resolved


def _prepare_bundle(path: str) -> ExecutionBundle:
    value = _read_json(path, MAX_PREPARE_RESULT_BYTES, "invalid_prepare_result")
    _exact_keys(
        value,
        {"schema_version", "kind", "phase", "state", "disposition", "request_id", "bundle"},
        "invalid_prepare_result",
    )
    if (
        value["schema_version"] != 1
        or value["kind"] != RESULT_KIND
        or value["phase"] != "prepare"
        or value["state"] != "ok"
        or value["disposition"] != ClaimDisposition.GRANTED.value
        or type(value["bundle"]) is not dict
    ):
        raise PhaseCliError("execution_not_granted")
    try:
        bundle = ExecutionBundle.from_dict(value["bundle"])
    except (ActionsHandlerError, TypeError, ValueError):
        raise PhaseCliError("invalid_prepare_result") from None
    if value["request_id"] != bundle.request_id:
        raise PhaseCliError("invalid_prepare_result")
    return bundle


def _transport(token: str, repositories: set[str]) -> GithubApi:
    try:
        return GithubApi(token=token, allowed_repositories=repositories)
    except (TypeError, ValueError):
        raise PhaseCliError("invalid_policy") from None


def _publisher(policy: PhasePolicy, token: str, cli_path: str, *, finalize: bool) -> PublisherPhase:
    repositories = {FIXED_REPOSITORY}
    if finalize:
        repositories.add(policy.issue.repository_full_name)
    api = _transport(token, repositories)
    coordinator = ActionsJournalCoordinator(cli_executable=cli_path, api_transport=api)
    return PublisherPhase(
        coordinator=coordinator,
        trusted_issue_policy=policy.issue,
        trusted_receipt_policy=policy.receipt,
        read_api_transport=api,
    )


def _run_prepare(args: argparse.Namespace, policy: PhasePolicy, token: str) -> dict[str, Any]:
    cli_path = _validate_cli_path(args.rust_cli)
    event = _read_bounded(args.event_file, MAX_EVENT_BYTES, "invalid_event_file")
    result = _publisher(policy, token, cli_path, finalize=False).prepare(
        event_bytes=event,
        execution_id=args.execution_id,
        accepted_at=args.accepted_at,
        policy_revision=policy.policy_revision,
    )
    output: dict[str, Any] = {
        "schema_version": 1,
        "kind": RESULT_KIND,
        "phase": "prepare",
        "state": "ok",
        "disposition": result.disposition.value,
        "request_id": result.request_id,
    }
    if result.disposition == ClaimDisposition.GRANTED:
        if result.bundle is None:
            raise PhaseCliError("invalid_prepare_result")
        output["bundle"] = result.bundle.to_dict()
    elif result.disposition == ClaimDisposition.TERMINAL_REPLAY:
        if result.receipt is None:
            raise PhaseCliError("invalid_prepare_result")
        output["terminal"] = {
            "state": result.receipt.terminal_state,
            "code": result.receipt.terminal_code,
            "reference": result.receipt.terminal_reference,
            "durable_revision": result.receipt.durable_revision,
        }
    return output


def _run_control(args: argparse.Namespace, policy: PhasePolicy, token: str) -> tuple[dict[str, Any], int]:
    bundle = _prepare_bundle(args.prepare_result)
    api = _transport(token, {policy.issue.repository_full_name, policy.ci.repository_full_name})
    result = ControlPhase(
        api_transport=api,
        trusted_receipt_policy=policy.receipt,
        ci_policy=policy.ci,
    ).execute(bundle)
    if result.ambiguous:
        return (
            {
                "schema_version": 1,
                "kind": RESULT_KIND,
                "phase": "control",
                "state": "ambiguous",
                "code": result.ambiguous_code or "comment_publication_ambiguous",
                "request_id": result.request_id,
                "execution_id": result.execution_id,
            },
            1,
        )
    return (
        {
            "schema_version": 1,
            "kind": RESULT_KIND,
            "phase": "control",
            "state": result.terminal_state,
            "code": result.terminal_code,
            "reference": result.terminal_reference,
            "request_id": result.request_id,
            "execution_id": result.execution_id,
        },
        0,
    )


def _run_finalize(args: argparse.Namespace, policy: PhasePolicy, token: str) -> dict[str, Any]:
    cli_path = _validate_cli_path(args.rust_cli)
    bundle = _prepare_bundle(args.prepare_result)
    receipt = _publisher(policy, token, cli_path, finalize=True).finalize(bundle)
    return {
        "schema_version": 1,
        "kind": RESULT_KIND,
        "phase": "finalize",
        "state": receipt.terminal_state,
        "code": receipt.terminal_code,
        "reference": receipt.terminal_reference,
        "request_id": receipt.request_id,
        "durable_revision": receipt.durable_revision,
        "replayed": receipt.replayed,
        "reconciled": receipt.reconciled,
    }


def _write_result(path: str, result: dict[str, Any]) -> None:
    try:
        encoded = (json.dumps(result, allow_nan=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise PhaseCliError("invalid_phase_result") from None
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise PhaseCliError("phase_result_too_large")
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(encoded)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except OSError:
        raise PhaseCliError("output_file_error") from None


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="actions_phase_cli.py", add_help=True)
    subparsers = parser.add_subparsers(dest="phase", required=True)
    for name in ("prepare", "control", "finalize"):
        command = subparsers.add_parser(name)
        command.add_argument("--policy-file", required=True)
        command.add_argument("--output-file", required=True)
        if name in ("prepare", "finalize"):
            command.add_argument("--rust-cli", required=True)
        if name == "prepare":
            command.add_argument("--event-file", required=True)
            command.add_argument("--execution-id", required=True)
            command.add_argument("--accepted-at", required=True)
        else:
            command.add_argument("--prepare-result", required=True)
    return parser


def _safe_code(error: Exception) -> str:
    code = getattr(error, "code", None)
    if isinstance(code, str) and SAFE_CODE_RE.fullmatch(code):
        return code
    return "phase_failed"


def main(argv: Optional[Sequence[str]] = None) -> int:
    output_path: Optional[str] = None
    phase = "unknown"
    try:
        args = _parser().parse_args(argv)
        phase = args.phase
        output_path = args.output_file
        policy = _load_policy(args.policy_file)
        token = _installation_token()
        exit_code = 0
        if phase == "prepare":
            output = _run_prepare(args, policy, token)
        elif phase == "control":
            output, exit_code = _run_control(args, policy, token)
        else:
            output = _run_finalize(args, policy, token)
        _write_result(output_path, output)
        return exit_code
    except Exception as error:
        code = _safe_code(error)
        if output_path is not None:
            try:
                _write_result(
                    output_path,
                    {
                        "schema_version": 1,
                        "kind": RESULT_KIND,
                        "phase": phase,
                        "state": "error",
                        "code": code,
                    },
                )
            except PhaseCliError:
                print("actions_phase_cli_failed", file=sys.stderr)
        else:
            print("actions_phase_cli_failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
