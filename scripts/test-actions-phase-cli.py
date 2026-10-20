"""Focused tests for the bounded isolated phase CLI."""

from __future__ import annotations

import json
from dataclasses import replace
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

    def _ledger_policy(self):
        value = json.loads(self.policy.read_text())
        value["ledger"] = {
            "producer": {"workflow_id": 10, "workflow_revision": value["policy_revision"], "tool_revision": "a" * 40},
            "publication": {"owner_task_id": "GOV-041", "owner_task_path": "tasks/GOV-041-workspace-command-fast-path.md", "branch": "task/GOV-041-workspace-command-fast-path"},
        }
        self.policy.write_text(json.dumps(value))
        return value

    def test_ledger_policy_typed_fixed_routing_and_fail_closed(self):
        value = self._ledger_policy()
        policy = cli._load_policy(str(self.policy))
        self.assertEqual(policy.ledger_producer.repository_full_name, "shockerqt/workspace-governance")
        self.assertEqual(policy.ledger_producer.workflow_revision, policy.policy_revision)
        faults = [
            ("producer", "workflow_id", True), ("producer", "workflow_id", 0),
            ("producer", "workflow_revision", "b" * 40), ("producer", "tool_revision", "bad"),
            ("producer", "repository_full_name", "client/repository"),
            ("publication", "branch", "master"), ("publication", "owner_task_path", "tasks/../policy.md"),
            ("publication", "repository", "client/repository"),
        ]
        for section, key, replacement in faults:
            changed = json.loads(json.dumps(value))
            changed["ledger"][section][key] = replacement
            self.policy.write_text(json.dumps(changed))
            with self.subTest(section=section, key=key), self.assertRaisesRegex(cli.PhaseCliError, "invalid_policy"):
                cli._load_policy(str(self.policy))

    def test_ledger_control_factory_and_missing_paths(self):
        self._ledger_policy()
        policy = cli._load_policy(str(self.policy))
        checkpoint = DurablePrepareCheckpoint(ClaimDisposition.GRANTED, replace(bundle(), operation="governance.ledger"), 0)
        args = cli._parser().parse_args(["control", "--policy-file", str(self.policy), "--output-file", str(self.root / "result"),
            "--ledger-cli", str(self.rust_cli), "--governance-mirror", str(self.root),
            "--ledger-candidate-output", str(self.root / "candidate.json")])
        callback = lambda value: {}
        with patch.object(cli, "_load_checkpoint", return_value=checkpoint), patch.object(cli, "GithubApi", FakeApi), \
             patch.object(cli, "LedgerCandidateRuntime", return_value=callback) as factory, patch.object(cli, "ControlPhase") as phase:
            phase.return_value.execute.return_value = ControlExecutionResult(REQUEST_ID, "run-101", terminal_state="succeeded", terminal_code="ledger_candidate_ready")
            cli._run_control(args, policy, "installation-token")
            factory.assert_called_once_with(str(self.rust_cli.resolve()), str(self.root), str(self.root / "candidate.json"))
            self.assertIs(phase.call_args.kwargs["ledger_candidate"], callback)
            self.assertEqual(FakeApi.constructed[-1][1], frozenset({policy.issue.repository_full_name}))
            args.governance_mirror = str(self.root / "absent")
            with self.assertRaisesRegex(cli.PhaseCliError, "invalid_governance_mirror"):
                cli._run_control(args, policy, "installation-token")
            args.governance_mirror = str(self.root)
            args.ledger_candidate_output = None
            with self.assertRaisesRegex(cli.PhaseCliError, "invalid_ledger_candidate_output"):
                cli._run_control(args, policy, "installation-token")
            args.ledger_cli = None
            with self.assertRaisesRegex(cli.PhaseCliError, "invalid_rust_cli"):
                cli._run_control(args, policy, "installation-token")

    def _integration_policy(self):
        value = self._ledger_policy()
        value["publisher_identity"] = {"app_id": 9877, "bot_user_id": 54322}
        value["ledger"]["integration_producer"] = dict(value["ledger"]["producer"], workflow_id=11)
        self.policy.write_text(json.dumps(value))
        return value

    def test_integration_policy_fixed_fields_revisions_and_publisher_required(self):
        value = self._integration_policy()
        policy = cli._load_policy(str(self.policy))
        self.assertEqual(policy.integration_producer.workflow_path, ".github/workflows/workspace-operations.yml")
        self.assertEqual(policy.integration_producer.producer_job_name, "verify")
        self.assertEqual(policy.integration_producer.tool_revision, policy.ledger_producer.tool_revision)
        for key, replacement in (("workflow_id", True), ("workflow_id", 0),
                                 ("workflow_revision", "b" * 40), ("tool_revision", "b" * 40),
                                 ("repository_full_name", "untrusted/repository"), ("workflow_path", "other.yml")):
            changed = json.loads(json.dumps(value))
            changed["ledger"]["integration_producer"][key] = replacement
            self.policy.write_text(json.dumps(changed))
            with self.subTest(key=key), self.assertRaisesRegex(cli.PhaseCliError, "invalid_policy"):
                cli._load_policy(str(self.policy))
        del value["publisher_identity"]
        self.policy.write_text(json.dumps(value))
        with self.assertRaisesRegex(cli.PhaseCliError, "invalid_policy"):
            cli._load_policy(str(self.policy))

    def test_closure_control_and_publisher_select_distinct_runtimes(self):
        self._integration_policy()
        policy = cli._load_policy(str(self.policy))
        closure = replace(bundle(), operation="governance.ledger", parameters={"operation": "task.complete_verified"})
        checkpoint = DurablePrepareCheckpoint(ClaimDisposition.GRANTED, closure, 0)
        args = cli._parser().parse_args(["control", "--policy-file", str(self.policy), "--output-file", str(self.root / "result"),
            "--ledger-cli", str(self.rust_cli), "--governance-mirror", str(self.root), "--observer-cli", str(self.rust_cli),
            "--ledger-candidate-output", str(self.root / "observation.json")])
        callback = lambda *values: {}
        with patch.object(cli, "_load_checkpoint", return_value=checkpoint), patch.object(cli, "GithubApi", FakeApi), \
             patch.object(cli, "IntegrationObservationRuntime", return_value=callback) as factory, \
             patch.object(cli, "LedgerCandidateRuntime") as candidate, patch.object(cli, "ControlPhase") as phase:
            phase.return_value.execute.return_value = ControlExecutionResult(REQUEST_ID, "run-101", terminal_state="candidate_ready", terminal_code="ledger_candidate_ready")
            cli._run_control(args, policy, "installation-token")
            factory.assert_called_once_with(str(self.rust_cli.resolve()), str(self.root / "observation.json"), "installation-token", policy.integration_producer)
            candidate.assert_not_called()
            self.assertIs(phase.call_args.kwargs["ledger_candidate"], callback)
        with patch.object(cli, "GithubApi", FakeApi), patch.object(cli, "ActionsJournalCoordinator", FakeCoordinator), \
             patch.object(cli, "IntegrationPublisherRuntime", return_value=callback) as factory, \
             patch.object(cli, "LedgerPublisherRuntime") as candidate, patch.object(cli, "PublisherPhase") as phase:
            cli._publisher(policy, "installation-token", str(self.rust_cli), finalize=True, ledger_args=args, integration_closure=True)
            self.assertEqual(factory.call_args.args[1:3], (policy.integration_producer, policy.ledger_publication))
            candidate.assert_not_called()
        args.rust_cli = str(self.rust_cli)
        with patch.object(cli, "_load_checkpoint", return_value=checkpoint), patch.object(cli, "_publisher", return_value=FakePublisher()) as factory:
            cli._run_finalize(args, policy, "installation-token")
            self.assertIs(factory.call_args.kwargs["integration_closure"], True)
        with patch.object(cli, "_load_checkpoint", return_value=checkpoint), patch.object(cli, "GithubApi", FakeApi), \
             self.assertRaisesRegex(cli.PhaseCliError, "integration_profile_unavailable"):
            cli._run_control(args, replace(policy, integration_producer=None), "installation-token")

    def test_ledger_publisher_uses_existing_api_and_policy_absent_stays_unwired(self):
        self._ledger_policy()
        policy = cli._load_policy(str(self.policy))
        args = cli._parser().parse_args(["finalize", "--policy-file", str(self.policy), "--output-file", str(self.root / "result"),
            "--rust-cli", str(self.rust_cli), "--ledger-cli", str(self.rust_cli), "--governance-mirror", str(self.root)])
        callback = lambda *values: {}
        with patch.object(cli, "GithubApi", FakeApi), patch.object(cli, "ActionsJournalCoordinator", FakeCoordinator), \
             patch.object(cli, "LedgerPublisherRuntime", return_value=callback) as factory, patch.object(cli, "PublisherPhase") as phase:
            cli._publisher(policy, "installation-token", str(self.rust_cli), finalize=True, ledger_args=args)
            self.assertIs(factory.call_args.args[0], phase.call_args.kwargs["read_api_transport"])
            self.assertIs(phase.call_args.kwargs["ledger_publisher"], callback)
            self.assertEqual(factory.call_args.args[1:3], (policy.ledger_producer, policy.ledger_publication))
            self.assertEqual(FakeApi.constructed[-1][1], frozenset({cli.FIXED_REPOSITORY, policy.issue.repository_full_name}))
            cli._publisher(policy, "installation-token", str(self.rust_cli), finalize=False)
            self.assertNotIn("ledger_publisher", phase.call_args.kwargs)
        policy = replace(policy, ledger_producer=None, ledger_publication=None)
        checkpoint = DurablePrepareCheckpoint(ClaimDisposition.GRANTED, replace(bundle(), operation="governance.ledger"), 0)
        with patch.object(cli, "_load_checkpoint", return_value=checkpoint), patch.object(cli, "GithubApi", FakeApi), patch.object(cli, "ControlPhase") as phase:
            phase.return_value.execute.return_value = ControlExecutionResult(REQUEST_ID, "run-101", terminal_state="rejected", terminal_code="operation_unsupported")
            args.phase = "control"
            cli._run_control(args, policy, "installation-token")
            self.assertNotIn("ledger_candidate", phase.call_args.kwargs)

    def test_finalize_selects_ledger_runtime_only_for_configured_ledger_bundle(self):
        self._ledger_policy()
        policy = cli._load_policy(str(self.policy))
        args = cli._parser().parse_args(["finalize", "--policy-file", str(self.policy),
            "--output-file", str(self.root / "result"), "--rust-cli", str(self.rust_cli)])
        for operation, configured in (("governance.ledger", True), ("github.ci.inspect", True), ("governance.ledger", False)):
            selected = policy if configured else replace(policy, ledger_producer=None, ledger_publication=None)
            frozen = replace(bundle(), operation=operation)
            checkpoint = DurablePrepareCheckpoint(ClaimDisposition.GRANTED, frozen, 0)
            with patch.object(cli, "_load_checkpoint", return_value=checkpoint), patch.object(cli, "_publisher", return_value=FakePublisher()) as factory:
                cli._run_finalize(args, selected, "installation-token")
                self.assertIs(factory.call_args.kwargs["ledger_args"], args if operation == "governance.ledger" and configured else None)

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
