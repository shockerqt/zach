"""Tests for the fixed typed recipe dispatcher."""

from __future__ import annotations

import hashlib
import json
import unittest

from actions_git_journal import ApiError
from actions_recipe_dispatch import (
    RecipeDispatchError,
    RecipeDispatchPolicy,
    dispatch_recipe,
    reconcile_recipe,
)
from actions_request_handler import ControlPhase, ExecutionBundle, TrustedReceiptPolicy


SOURCE = "a" * 40
CURRENT = "b" * 40
DIGEST = "c" * 64
TRANSPORT = "d" * 64
REQUEST_ID = "uds007-web-pilot-01"
ACCEPTED_AT = "2026-09-12T12:00:00Z"
REPOSITORY = "shockerqt/ui-design-sandbox"
REPOSITORY_ID = 1324116785
WORKFLOW_ID = 987654
ACTOR_ID = 325457439


def request_binding(inputs: dict[str, str]) -> str:
    return hashlib.sha256(
        json.dumps(inputs, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


DEPLOY_INPUTS = {
    "operation": "deploy",
    "request_id": REQUEST_ID,
    "source_sha": SOURCE,
    "artifact_sha256": DIGEST,
    "expected_current": CURRENT,
    "artifact_run_id": "1234",
    "artifact_run_attempt": "1",
    "artifact_id": "5678",
    "transport_digest": TRANSPORT,
}
DEPLOY_BINDING = request_binding(DEPLOY_INPUTS)


def policy() -> RecipeDispatchPolicy:
    return RecipeDispatchPolicy(
        recipe="sandbox.delivery",
        repository_alias="ui-design-sandbox",
        repository_full_name=REPOSITORY,
        repository_id=REPOSITORY_ID,
        workflow_id=WORKFLOW_ID,
        workflow_path=".github/workflows/sandbox-delivery.yml",
        ref="main",
        actor_id=ACTOR_ID,
    )


def deploy_parameters() -> dict:
    return {
        "recipe": "sandbox.delivery",
        "operation": "deploy",
        "source_sha": SOURCE,
        "artifact_sha256": DIGEST,
        "expected_current": CURRENT,
        "artifact_run_id": 1234,
        "artifact_run_attempt": 1,
        "artifact_id": 5678,
        "transport_digest": TRANSPORT,
    }


class FakeApi:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, object]] = []
        self.dispatch_error = False
        self.response: object = {
            "workflow_run_id": 2468,
            "run_url": f"https://api.github.com/repos/{REPOSITORY}/actions/runs/2468",
            "html_url": f"https://github.com/{REPOSITORY}/actions/runs/2468",
        }
        self.run: dict = {
            "id": 2468,
            "workflow_id": WORKFLOW_ID,
            "path": ".github/workflows/sandbox-delivery.yml",
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": "e" * 40,
            "display_title": f"Sandbox deploy / {REQUEST_ID} / {DEPLOY_BINDING}",
            "created_at": "2026-09-12T12:00:10Z",
            "actor": {"id": ACTOR_ID},
            "repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
            "head_repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
            "url": f"https://api.github.com/repos/{REPOSITORY}/actions/runs/2468",
            "html_url": f"https://github.com/{REPOSITORY}/actions/runs/2468",
            "status": "queued",
            "conclusion": None,
        }

    def __call__(self, method: str, path: str, body: object = None) -> object:
        self.calls.append((method, path, body))
        if method == "GET" and path == f"/repos/{REPOSITORY}":
            return {"id": REPOSITORY_ID, "full_name": REPOSITORY, "default_branch": "main"}
        if method == "GET" and path.endswith(f"/actions/workflows/{WORKFLOW_ID}"):
            return {
                "id": WORKFLOW_ID,
                "path": ".github/workflows/sandbox-delivery.yml",
                "state": "active",
            }
        if method == "GET" and path.endswith("/actions/runs/2468"):
            return dict(self.run)
        if method == "GET" and f"/actions/workflows/{WORKFLOW_ID}/runs?" in path:
            return {"total_count": 1, "workflow_runs": [dict(self.run)]}
        if method == "POST" and path.endswith("/dispatches"):
            if self.dispatch_error:
                raise TimeoutError("lost response")
            return self.response
        raise AssertionError((method, path, body))


class RecipeDispatchTests(unittest.TestCase):
    def test_dispatches_exact_deploy_inputs_and_returns_run_identity(self) -> None:
        api = FakeApi()
        result = dispatch_recipe(deploy_parameters(), REQUEST_ID, ACCEPTED_AT, policy(), api)
        self.assertEqual((result["result"], result["workflow_run"]["id"]), ("dispatched", 2468))
        self.assertEqual(
            next(call for call in api.calls if call[0] == "POST"),
            (
                "POST",
                f"/repos/{REPOSITORY}/actions/workflows/{WORKFLOW_ID}/dispatches",
                {
                    "ref": "main",
                    "inputs": {**DEPLOY_INPUTS, "request_binding": DEPLOY_BINDING},
                },
            ),
        )

    def test_dispatches_rollback_without_deploy_only_inputs(self) -> None:
        api = FakeApi()
        parameters = {
            "recipe": "sandbox.delivery",
            "operation": "rollback",
            "source_sha": SOURCE,
            "artifact_sha256": DIGEST,
            "expected_current": CURRENT,
        }
        rollback_inputs = {
            "operation": "rollback",
            "request_id": REQUEST_ID,
            "source_sha": SOURCE,
            "artifact_sha256": DIGEST,
            "expected_current": CURRENT,
        }
        rollback_binding = request_binding(rollback_inputs)
        api_run = dict(api.run)
        api_run["display_title"] = (
            f"Sandbox rollback / {REQUEST_ID} / {rollback_binding}"
        )

        def transport(method: str, path: str, body: object = None) -> object:
            if method == "GET" and path.endswith("/actions/runs/2468"):
                api.calls.append((method, path, body))
                return api_run
            return api(method, path, body)

        dispatch_recipe(parameters, REQUEST_ID, ACCEPTED_AT, policy(), transport)
        self.assertEqual(
            next(call for call in api.calls if call[0] == "POST")[2]["inputs"],
            {**rollback_inputs, "request_binding": rollback_binding},
        )

    def test_rejects_unknown_recipe_operation_or_extra_inputs_before_api(self) -> None:
        for change in (
            {"recipe": "other.delivery"},
            {"operation": "shell"},
            {"extra": "value"},
        ):
            with self.subTest(change=change):
                api = FakeApi()
                parameters = deploy_parameters()
                parameters.update(change)
                with self.assertRaises(RecipeDispatchError):
                    dispatch_recipe(parameters, REQUEST_ID, ACCEPTED_AT, policy(), api)
                self.assertEqual(api.calls, [])

    def test_rejects_malformed_identity_and_digest_inputs(self) -> None:
        for field, value in (
            ("source_sha", SOURCE.upper()),
            ("artifact_sha256", "x" * 64),
            ("expected_current", "none"),
            ("artifact_run_id", True),
            ("artifact_id", 0),
            ("transport_digest", TRANSPORT.upper()),
        ):
            with self.subTest(field=field):
                api = FakeApi()
                parameters = deploy_parameters()
                parameters[field] = value
                with self.assertRaises(RecipeDispatchError):
                    dispatch_recipe(parameters, REQUEST_ID, ACCEPTED_AT, policy(), api)
                self.assertEqual(api.calls, [])

    def test_rejects_repository_or_workflow_identity_before_dispatch(self) -> None:
        for response_index, value in ((0, {"id": 9}), (1, {"id": 1, "state": "disabled"})):
            with self.subTest(response_index=response_index):
                api = FakeApi()
                original = api.__call__
                responses = [
                    {"id": REPOSITORY_ID, "full_name": REPOSITORY, "default_branch": "main"},
                    {"id": WORKFLOW_ID, "path": ".github/workflows/sandbox-delivery.yml", "state": "active"},
                ]
                responses[response_index] = value
                count = 0

                def transport(method: str, path: str, body: object = None) -> object:
                    nonlocal count
                    if method == "GET":
                        result = responses[count]
                        count += 1
                        return result
                    return original(method, path, body)

                with self.assertRaises(RecipeDispatchError):
                    dispatch_recipe(
                        deploy_parameters(), REQUEST_ID, ACCEPTED_AT, policy(), transport
                    )
                self.assertLessEqual(count, 2)

    def test_lost_or_malformed_dispatch_response_is_ambiguous(self) -> None:
        for response in (None, {"workflow_run_id": 2468}, "invalid"):
            with self.subTest(response=response):
                api = FakeApi()
                api.response = response
                with self.assertRaises(RecipeDispatchError) as caught:
                    dispatch_recipe(deploy_parameters(), REQUEST_ID, ACCEPTED_AT, policy(), api)
                self.assertTrue(caught.exception.ambiguous)

        api = FakeApi()
        api.dispatch_error = True
        with self.assertRaises(RecipeDispatchError) as caught:
            dispatch_recipe(deploy_parameters(), REQUEST_ID, ACCEPTED_AT, policy(), api)
        self.assertTrue(caught.exception.ambiguous)

    def test_definitive_client_rejection_is_not_ambiguous(self) -> None:
        api = FakeApi()

        def transport(method: str, path: str, body: object = None) -> object:
            if method == "POST":
                raise ApiError(422, "invalid inputs")
            return api(method, path, body)

        with self.assertRaises(RecipeDispatchError) as caught:
            dispatch_recipe(deploy_parameters(), REQUEST_ID, ACCEPTED_AT, policy(), transport)
        self.assertEqual(caught.exception.code, "recipe_dispatch_rejected")
        self.assertFalse(caught.exception.ambiguous)

    def test_run_readback_mismatch_is_ambiguous_after_one_dispatch(self) -> None:
        api = FakeApi()

        def transport(method: str, path: str, body: object = None) -> object:
            value = api(method, path, body)
            if method == "GET" and path.endswith("/actions/runs/2468"):
                value["actor"] = {"id": ACTOR_ID + 1}
            return value

        with self.assertRaises(RecipeDispatchError) as caught:
            dispatch_recipe(deploy_parameters(), REQUEST_ID, ACCEPTED_AT, policy(), transport)
        self.assertTrue(caught.exception.ambiguous)
        self.assertEqual(sum(call[0] == "POST" for call in api.calls), 1)

    def test_run_readback_binds_exact_inputs_and_acceptance_window(self) -> None:
        for title, created_at in (
            (f"Sandbox deploy / {REQUEST_ID} / {'f' * 64}", "2026-09-12T12:00:10Z"),
            (f"Sandbox deploy / {REQUEST_ID} / {DEPLOY_BINDING}", "2026-09-12T12:15:01Z"),
        ):
            with self.subTest(title=title, created_at=created_at):
                api = FakeApi()
                api.run["display_title"] = title
                api.run["created_at"] = created_at
                with self.assertRaises(RecipeDispatchError) as caught:
                    dispatch_recipe(
                        deploy_parameters(), REQUEST_ID, ACCEPTED_AT, policy(), api
                    )
                self.assertTrue(caught.exception.ambiguous)

    def test_reconciliation_finds_one_stable_run_without_dispatch(self) -> None:
        api = FakeApi()
        result = reconcile_recipe(
            deploy_parameters(), REQUEST_ID, ACCEPTED_AT, policy(), api
        )
        self.assertEqual(result["workflow_run"]["id"], 2468)
        self.assertEqual(sum(call[0] == "POST" for call in api.calls), 0)
        self.assertEqual(
            sum("/actions/workflows/987654/runs?" in call[1] for call in api.calls),
            2,
        )

    def test_reconciliation_zero_or_multiple_matches_remains_ambiguous(self) -> None:
        for run_count in (0, 2):
            with self.subTest(run_count=run_count):
                api = FakeApi()
                runs = []
                for offset in range(run_count):
                    run = dict(api.run)
                    run["id"] = 2468 + offset
                    run["url"] = (
                        f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{2468 + offset}"
                    )
                    run["html_url"] = (
                        f"https://github.com/{REPOSITORY}/actions/runs/{2468 + offset}"
                    )
                    runs.append(run)

                def transport(method: str, path: str, body: object = None) -> object:
                    if method == "GET" and "/actions/workflows/987654/runs?" in path:
                        api.calls.append((method, path, body))
                        return {"total_count": len(runs), "workflow_runs": runs}
                    return api(method, path, body)

                with self.assertRaises(RecipeDispatchError) as caught:
                    reconcile_recipe(
                        deploy_parameters(), REQUEST_ID, ACCEPTED_AT, policy(), transport
                    )
                self.assertTrue(caught.exception.ambiguous)
                self.assertEqual(sum(call[0] == "POST" for call in api.calls), 0)

    def test_reconciliation_scans_all_pages_before_accepting_one_run(self) -> None:
        api = FakeApi()
        unrelated: list[dict] = []
        for offset in range(100):
            run_id = 3000 + offset
            run = dict(api.run)
            run.update(
                {
                    "id": run_id,
                    "display_title": f"Sandbox deploy / unrelated-{offset:03d}",
                    "url": f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run_id}",
                    "html_url": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
                }
            )
            unrelated.append(run)

        def transport(method: str, path: str, body: object = None) -> object:
            if method == "GET" and "/actions/workflows/987654/runs?" in path:
                api.calls.append((method, path, body))
                page = unrelated if path.endswith("page=1") else [dict(api.run)]
                return {"total_count": 101, "workflow_runs": page}
            return api(method, path, body)

        result = reconcile_recipe(
            deploy_parameters(), REQUEST_ID, ACCEPTED_AT, policy(), transport
        )
        self.assertEqual(result["workflow_run"]["id"], 2468)
        self.assertEqual(
            sum("/actions/workflows/987654/runs?" in call[1] for call in api.calls),
            4,
        )
        self.assertEqual(sum(call[0] == "POST" for call in api.calls), 0)

    def test_reconciliation_rejects_unstable_or_pre_acceptance_run(self) -> None:
        api = FakeApi()
        scan_count = 0

        def unstable(method: str, path: str, body: object = None) -> object:
            nonlocal scan_count
            if method == "GET" and "/actions/workflows/987654/runs?" in path:
                api.calls.append((method, path, body))
                scan_count += 1
                run = dict(api.run)
                if scan_count == 2:
                    run["head_sha"] = "f" * 40
                return {"total_count": 1, "workflow_runs": [run]}
            return api(method, path, body)

        with self.assertRaises(RecipeDispatchError) as caught:
            reconcile_recipe(
                deploy_parameters(), REQUEST_ID, ACCEPTED_AT, policy(), unstable
            )
        self.assertEqual(caught.exception.code, "recipe_reconciliation_unstable")
        self.assertEqual(sum(call[0] == "POST" for call in api.calls), 0)

        before_acceptance = FakeApi()
        before_acceptance.run["created_at"] = "2026-09-12T11:54:59Z"
        with self.assertRaises(RecipeDispatchError) as caught:
            reconcile_recipe(
                deploy_parameters(),
                REQUEST_ID,
                ACCEPTED_AT,
                policy(),
                before_acceptance,
            )
        self.assertEqual(caught.exception.code, "recipe_reconciliation_not_found")
        self.assertEqual(sum(call[0] == "POST" for call in before_acceptance.calls), 0)

    def test_control_receipt_claims_dispatch_only_and_ambiguity_posts_nothing(self) -> None:
        class ControlApi(FakeApi):
            def __init__(self) -> None:
                super().__init__()
                self.comment = None

            def __call__(self, method: str, path: str, body: object = None) -> object:
                if method == "GET" and path.startswith(
                    f"/repos/shockerqt/workspace-governance/issues/42/comments?"
                ):
                    self.calls.append((method, path, body))
                    return []
                if method == "POST" and path.endswith("/issues/42/comments"):
                    self.calls.append((method, path, body))
                    self.comment = {
                        "id": 91,
                        "user": {"id": ACTOR_ID, "type": "Bot"},
                        "performed_via_github_app": {"id": 4845317},
                        "issue_url": "https://api.github.com/repos/shockerqt/workspace-governance/issues/42",
                        "html_url": "https://github.com/shockerqt/workspace-governance/issues/42#issuecomment-91",
                        "body": body["body"],
                    }
                    return self.comment
                if method == "GET" and path.endswith("/issues/comments/91"):
                    self.calls.append((method, path, body))
                    return self.comment
                return super().__call__(method, path, body)

        parameters = deploy_parameters()
        record = {
            "request_id": REQUEST_ID,
            "request_digest": "1" * 64,
            "operation": "workspace.recipe.dispatch",
            "repository_id": 1260920764,
            "repository_full_name": "shockerqt/workspace-governance",
            "issue_id": 501,
            "issue_number": 42,
            "execution_id": "run-101",
            "state": "executing",
            "accepted_at": ACCEPTED_AT,
            "canonical_request": json.dumps({"parameters": parameters}),
        }
        bundle = ExecutionBundle(
            request_id=REQUEST_ID,
            request_digest="1" * 64,
            operation="workspace.recipe.dispatch",
            repository_id=1260920764,
            repository_full_name="shockerqt/workspace-governance",
            issue_id=501,
            issue_number=42,
            execution_id="run-101",
            canonical_record=json.dumps(record),
            accepted_revision="2" * 40,
            claim_revision="3" * 40,
            parameters=parameters,
        )
        api = ControlApi()
        control = ControlPhase(
            api_transport=api,
            trusted_receipt_policy=TrustedReceiptPolicy(
                app_id=4845317,
                bot_user_id=ACTOR_ID,
            ),
            recipe_policy=policy(),
        )
        result = control.execute(bundle)
        self.assertFalse(result.ambiguous)
        self.assertEqual((result.terminal_state, result.terminal_code), ("succeeded", "dispatched"))
        self.assertEqual(result.envelope["result"]["status"], "queued")

        ambiguous_api = ControlApi()
        ambiguous_api.dispatch_error = True
        ambiguous = ControlPhase(
            api_transport=ambiguous_api,
            trusted_receipt_policy=TrustedReceiptPolicy(
                app_id=4845317,
                bot_user_id=ACTOR_ID,
            ),
            recipe_policy=policy(),
        ).execute(bundle)
        self.assertTrue(ambiguous.ambiguous)
        self.assertEqual(ambiguous.ambiguous_code, "recipe_dispatch_ambiguous")
        self.assertFalse(any("/issues/42/comments" in call[1] for call in ambiguous_api.calls))

        reconcile_api = ControlApi()
        reconciled = ControlPhase(
            api_transport=reconcile_api,
            trusted_receipt_policy=TrustedReceiptPolicy(
                app_id=4845317,
                bot_user_id=ACTOR_ID,
            ),
            recipe_policy=policy(),
        ).execute(bundle, reconcile_recipe_only=True)
        self.assertFalse(reconciled.ambiguous)
        self.assertEqual(
            (reconciled.terminal_state, reconciled.terminal_code),
            ("succeeded", "dispatched"),
        )
        self.assertFalse(
            any(call[0] == "POST" and call[1].endswith("/dispatches") for call in reconcile_api.calls)
        )


if __name__ == "__main__":
    unittest.main()
