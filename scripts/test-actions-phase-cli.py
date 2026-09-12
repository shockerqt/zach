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
    DurablePrepareCheckpoint,
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
    reconcile_values: list[bool] = []

    def __init__(self, **_kwargs: object) -> None:
        pass

    def execute(
        self,
        value: ExecutionBundle,
        *,
        reconcile_recipe_only: bool = False,
    ) -> ControlExecutionResult:
        self.reconcile_values.append(reconcile_recipe_only)
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
        FakeControl.reconcile_values = []

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

    def test_recipe_control_uses_issue_and_recipe_namespaces_only(self) -> None:
        policy_value = json.loads(self.policy.read_text(encoding="utf-8"))
        policy_value["ci"].update(
            {
                "repository_alias": "infrastructure",
                "repository_id": 1003,
                "repository_full_name": "shockerqt/infrastructure",
            }
        )
        policy_value["recipe"] = {
            "recipe": "sandbox.delivery",
            "repository_alias": "ui-design-sandbox",
            "repository_id": 1324116785,
            "repository_full_name": "shockerqt/ui-design-sandbox",
            "workflow_id": 987654,
            "workflow_path": ".github/workflows/sandbox-delivery.yml",
            "ref": "main",
            "actor_id": 54321,
        }
        self.policy.write_text(json.dumps(policy_value), encoding="utf-8")
        prepare = json.loads(self._prepare_file().read_text(encoding="utf-8"))
        prepare["bundle"]["operation"] = "workspace.recipe.dispatch"
        prepare["bundle"]["parameters"] = {
            "recipe": "sandbox.delivery",
            "operation": "rollback",
            "source_sha": "4" * 40,
            "artifact_sha256": "5" * 64,
            "expected_current": "6" * 40,
        }
        prepare_path = self.root / "recipe-prepare.json"
        prepare_path.write_text(json.dumps(prepare), encoding="utf-8")
        output = self.root / "recipe-control.json"
        status = self._run(
            [
                "control",
                "--policy-file", str(self.policy),
                "--prepare-result", str(prepare_path),
                "--output-file", str(output),
            ]
        )
        self.assertEqual(status, 0)
        self.assertEqual(
            FakeApi.constructed,
            [("installation-token", frozenset({"shockerqt/zach", "shockerqt/ui-design-sandbox"}))],
        )
        self.assertEqual(FakeControl.reconcile_values, [False])

        reconcile_output = self.root / "recipe-reconcile.json"
        status = self._run(
            [
                "control-reconcile",
                "--policy-file", str(self.policy),
                "--prepare-result", str(prepare_path),
                "--output-file", str(reconcile_output),
            ]
        )
        self.assertEqual(status, 0)
        self.assertEqual(
            json.loads(reconcile_output.read_text(encoding="utf-8"))["phase"],
            "control-reconcile",
        )
        self.assertEqual(FakeControl.reconcile_values, [False, True])

    def test_recipe_actor_must_match_receipt_bot(self) -> None:
        policy_value = json.loads(self.policy.read_text(encoding="utf-8"))
        policy_value["recipe"] = {
            "recipe": "sandbox.delivery",
            "repository_alias": "ui-design-sandbox",
            "repository_id": 1324116785,
            "repository_full_name": "shockerqt/ui-design-sandbox",
            "workflow_id": 987654,
            "workflow_path": ".github/workflows/sandbox-delivery.yml",
            "ref": "main",
            "actor_id": 99999,
        }
        self.policy.write_text(json.dumps(policy_value), encoding="utf-8")
        output = self.root / "invalid-policy.json"
        status = self._run(
            [
                "control",
                "--policy-file", str(self.policy),
                "--prepare-result", str(self._prepare_file()),
                "--output-file", str(output),
            ]
        )
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["code"], "invalid_policy")

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

    def test_control_loads_durable_checkpoint_by_issue_and_execution(self) -> None:
        policy = json.loads(self.policy.read_text(encoding="utf-8"))
        policy["publisher_identity"] = {"app_id": 1234, "bot_user_id": 5678}
        self.policy.write_text(json.dumps(policy), encoding="utf-8")
        output = self.root / "control-locator.json"
        checkpoint = DurablePrepareCheckpoint(
            disposition=ClaimDisposition.GRANTED,
            bundle=bundle(),
            comment_id=77,
        )
        with patch.object(cli, "load_durable_prepare_checkpoint", return_value=checkpoint) as load:
            status = self._run(
                [
                    "control",
                    "--policy-file", str(self.policy),
                    "--issue-number", "42",
                    "--execution-id", "run-101",
                    "--request-id", REQUEST_ID,
                    "--output-file", str(output),
                ]
            )
        self.assertEqual(status, 0)
        load.assert_called_once()
        self.assertEqual(
            FakeApi.constructed,
            [
                ("installation-token", frozenset({"shockerqt/zach"})),
                (
                    "installation-token",
                    frozenset({"shockerqt/zach", "shockerqt/ui-design-sandbox"}),
                ),
            ],
        )

    def test_prepare_with_publisher_identity_allows_only_issue_and_journal(self) -> None:
        policy = json.loads(self.policy.read_text(encoding="utf-8"))
        policy["publisher_identity"] = {"app_id": 1234, "bot_user_id": 5678}
        self.policy.write_text(json.dumps(policy), encoding="utf-8")
        output = self.root / "durable-prepare.json"
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
        self.assertEqual(
            FakeApi.constructed,
            [
                (
                    "installation-token",
                    frozenset({"shockerqt/workspace-governance", "shockerqt/zach"}),
                )
            ],
        )

    def test_policy_rejects_collapsed_publisher_and_control_identity(self) -> None:
        policy = json.loads(self.policy.read_text(encoding="utf-8"))
        policy["publisher_identity"] = dict(policy["control_identity"])
        self.policy.write_text(json.dumps(policy), encoding="utf-8")
        output = self.root / "collapsed-identities.json"
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
            json.loads(output.read_text(encoding="utf-8"))["code"], "invalid_policy"
        )

    def test_locator_and_prepare_result_are_mutually_exclusive(self) -> None:
        output = self.root / "invalid-sources.json"
        status = self._run(
            [
                "control",
                "--policy-file", str(self.policy),
                "--prepare-result", str(self._prepare_file()),
                "--issue-number", "42",
                "--execution-id", "run-101",
                "--output-file", str(output),
            ]
        )
        self.assertEqual(status, 2)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["code"], "invalid_arguments")

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
