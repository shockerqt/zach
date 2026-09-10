"""Focused tests for the bounded isolated phase CLI."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import actions_phase_cli as cli
from actions_journal_coordinator import ClaimDisposition
from actions_request_handler import (
    ActionsHandlerError,
    ControlExecutionResult,
    ExecutionBundle,
    ExecutionReceipt,
    PrepareResult,
)


REQUEST_ID = "phase-cli-request-01"


def bundle() -> ExecutionBundle:
    return ExecutionBundle(
        request_id=REQUEST_ID,
        request_digest="1" * 64,
        operation="github.ci.inspect",
        repository_id=1001,
        repository_full_name="shockerqt/zach",
        issue_id=501,
        issue_number=42,
        execution_id="run-101",
        canonical_record="{}",
        accepted_revision="2" * 40,
        claim_revision="3" * 40,
        parameters={"repository": "ui-design-sandbox", "source_sha": "4" * 40},
    )


class FakeApi:
    constructed: list[tuple[str, frozenset[str]]] = []

    def __init__(self, token: str, allowed_repositories: set[str]) -> None:
        self.constructed.append((token, frozenset(allowed_repositories)))

    def __call__(self, _method: str, _path: str, body: object = None) -> object:
        raise AssertionError("unexpected transport call")


class FakeCoordinator:
    def __init__(self, cli_executable: str, api_transport: object) -> None:
        self.cli_executable = cli_executable
        self.api_transport = api_transport


class FakePublisher:
    prepare_error: ActionsHandlerError | None = None
    finalize_calls: list[ExecutionBundle] = []

    def __init__(self, **_kwargs: object) -> None:
        pass

    def prepare(self, **_kwargs: object) -> PrepareResult:
        if self.prepare_error is not None:
            raise self.prepare_error
        return PrepareResult(ClaimDisposition.GRANTED, REQUEST_ID, bundle=bundle())

    def finalize(self, value: ExecutionBundle) -> ExecutionReceipt:
        self.finalize_calls.append(value)
        return ExecutionReceipt(
            request_id=value.request_id,
            durable_revision="5" * 40,
            terminal_state="succeeded",
            terminal_code="found",
            terminal_reference="https://github.com/shockerqt/zach/issues/42#issuecomment-7",
            envelope={},
        )


class FakeControl:
    def __init__(self, **_kwargs: object) -> None:
        pass

    def execute(self, value: ExecutionBundle) -> ControlExecutionResult:
        return ControlExecutionResult(
            request_id=value.request_id,
            execution_id=value.execution_id,
            terminal_state="succeeded",
            terminal_code="found",
            terminal_reference="https://github.com/shockerqt/zach/issues/42#issuecomment-7",
        )


class PhaseCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.policy = self.root / "policy.json"
        self.policy.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "repository": {"id": 1001, "full_name": "shockerqt/zach"},
                    "allowed_actor_ids": [2001],
                    "control_identity": {"app_id": 9876, "bot_user_id": 54321},
                    "ci": {
                        "repository_alias": "ui-design-sandbox",
                        "repository_id": 1002,
                        "repository_full_name": "shockerqt/ui-design-sandbox",
                        "workflow_id": 339778910,
                        "workflow_path": ".github/workflows/ci.yml",
                    },
                    "policy_revision": "4" * 40,
                }
            ),
            encoding="utf-8",
        )
        self.event = self.root / "event.json"
        self.event.write_text("{}", encoding="utf-8")
        self.rust_cli = self.root / "zach-actions"
        self.rust_cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.rust_cli.chmod(0o700)
        FakeApi.constructed = []
        FakePublisher.prepare_error = None
        FakePublisher.finalize_calls = []

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _prepare_file(self) -> Path:
        path = self.root / "prepare-input.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": cli.RESULT_KIND,
                    "phase": "prepare",
                    "state": "ok",
                    "disposition": "granted",
                    "request_id": REQUEST_ID,
                    "bundle": bundle().to_dict(),
                }
            ),
            encoding="utf-8",
        )
        return path

    def _run(self, arguments: list[str]) -> int:
        with (
            patch.dict(os.environ, {cli.TOKEN_ENV: "installation-token"}, clear=True),
            patch.object(cli, "GithubApi", FakeApi),
            patch.object(cli, "ActionsJournalCoordinator", FakeCoordinator),
            patch.object(cli, "PublisherPhase", FakePublisher),
            patch.object(cli, "ControlPhase", FakeControl),
        ):
            return cli.main(arguments)

    def test_prepare_writes_only_a_granted_result_file(self) -> None:
        output = self.root / "prepare-output.json"
        status = self._run(
            [
                "prepare",
                "--policy-file", str(self.policy),
                "--event-file", str(self.event),
                "--execution-id", "run-101",
                "--accepted-at", "2026-09-10T22:21:00Z",
                "--rust-cli", str(self.rust_cli),
                "--output-file", str(output),
            ]
        )
        self.assertEqual(status, 0)
        result = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(result["disposition"], "granted")
        self.assertEqual(result["bundle"]["request_id"], REQUEST_ID)
        self.assertEqual(FakeApi.constructed, [("installation-token", frozenset({"shockerqt/workspace-governance"}))])
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_prepare_authorization_failure_is_sanitized_and_nonzero(self) -> None:
        FakePublisher.prepare_error = ActionsHandlerError("cli_validation_failed")
        output = self.root / "rejected.json"
        status = self._run(
            [
                "prepare",
                "--policy-file", str(self.policy),
                "--event-file", str(self.event),
                "--execution-id", "run-101",
                "--accepted-at", "2026-09-10T22:21:00Z",
                "--rust-cli", str(self.rust_cli),
                "--output-file", str(output),
            ]
        )
        self.assertEqual(status, 2)
        self.assertEqual(
            json.loads(output.read_text(encoding="utf-8")),
            {
                "schema_version": 1,
                "kind": cli.RESULT_KIND,
                "phase": "prepare",
                "state": "error",
                "code": "cli_validation_failed",
            },
        )

    def test_control_uses_only_control_and_ci_namespaces(self) -> None:
        output = self.root / "control.json"
        status = self._run(
            [
                "control",
                "--policy-file", str(self.policy),
                "--prepare-result", str(self._prepare_file()),
                "--output-file", str(output),
            ]
        )
        self.assertEqual(status, 0)
        result = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual((result["state"], result["code"]), ("succeeded", "found"))
        self.assertEqual(
            FakeApi.constructed,
            [
                (
                    "installation-token",
                    frozenset({"shockerqt/zach", "shockerqt/ui-design-sandbox"}),
                )
            ],
        )

    def test_finalize_observes_from_prepare_bundle_without_control_result(self) -> None:
        output = self.root / "finalize.json"
        status = self._run(
            [
                "finalize",
                "--policy-file", str(self.policy),
                "--prepare-result", str(self._prepare_file()),
                "--rust-cli", str(self.rust_cli),
                "--output-file", str(output),
            ]
        )
        self.assertEqual(status, 0)
        self.assertEqual(len(FakePublisher.finalize_calls), 1)
        result = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual((result["state"], result["code"]), ("succeeded", "found"))
        self.assertEqual(
            FakeApi.constructed,
            [
                (
                    "installation-token",
                    frozenset({"shockerqt/workspace-governance", "shockerqt/zach"}),
                )
            ],
        )

    def test_control_rejects_non_granted_prepare_result_without_transport(self) -> None:
        prepare = self.root / "not-granted.json"
        prepare.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": cli.RESULT_KIND,
                    "phase": "prepare",
                    "state": "ok",
                    "disposition": "reconciliation_required",
                    "request_id": REQUEST_ID,
                }
            ),
            encoding="utf-8",
        )
        output = self.root / "control-error.json"
        status = self._run(
            [
                "control",
                "--policy-file", str(self.policy),
                "--prepare-result", str(prepare),
                "--output-file", str(output),
            ]
        )
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["code"], "invalid_prepare_result")
        self.assertEqual(FakeApi.constructed, [])


if __name__ == "__main__":
    unittest.main()
