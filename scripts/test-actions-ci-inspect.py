"""Adversarial fake-API tests for the read-only CI inspection handler."""

from __future__ import annotations

import json
import unittest
from typing import Any, Optional
from urllib.parse import parse_qs, urlsplit

from actions_ci_inspect import (
    MAX_RESULT_BYTES,
    CiInspectError,
    CiInspectionPolicy,
    inspect_ci,
)


SOURCE_SHA = "763f14e8dc0451be527cac6ff89e77ee71799bd3"
POLICY = CiInspectionPolicy(
    repository_alias="zach",
    repository_full_name="shockerqt/zach",
    repository_id=1342354297,
    workflow_id=339778910,
    workflow_path=".github/workflows/ci.yml",
)


def make_run(
    run_id: int,
    *,
    status: str = "completed",
    conclusion: Optional[str] = "success",
    created_at: str = "2026-09-05T09:28:46Z",
    attempt: int = 1,
) -> dict[str, Any]:
    return {
        "id": run_id,
        "run_attempt": attempt,
        "workflow_id": POLICY.workflow_id,
        "path": POLICY.workflow_path,
        "event": "pull_request",
        "status": status,
        "conclusion": conclusion,
        "head_sha": SOURCE_SHA,
        "repository": {"id": POLICY.repository_id, "full_name": POLICY.repository_full_name},
        "head_repository": {"id": POLICY.repository_id, "full_name": POLICY.repository_full_name},
        "created_at": created_at,
        "updated_at": created_at,
        "html_url": f"https://github.com/{POLICY.repository_full_name}/actions/runs/{run_id}",
    }


def make_job(
    job_id: int,
    run_id: int,
    *,
    name: str = "test",
    conclusion: Optional[str] = "success",
    steps: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    status = "completed" if conclusion is not None else "in_progress"
    return {
        "id": job_id,
        "run_id": run_id,
        "run_attempt": 1,
        "head_sha": SOURCE_SHA,
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "html_url": (
            f"https://github.com/{POLICY.repository_full_name}/actions/runs/{run_id}/job/{job_id}"
        ),
        "steps": steps if steps is not None else [],
    }


class FakeApi:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self.repository: Any = {"id": POLICY.repository_id, "full_name": POLICY.repository_full_name}
        self.workflow: Any = {
            "id": POLICY.workflow_id,
            "path": POLICY.workflow_path,
            "state": "active",
        }
        self.commit: Any = {"sha": SOURCE_SHA}
        self.runs: list[Any] = [make_run(33958090021)]
        self.exact_run: Any = dict(self.runs[0])
        self.jobs: list[Any] = [make_job(7001, 33958090021)]
        self.run_total_by_page: dict[int, int] = {}
        self.job_total_by_page: dict[int, int] = {}
        self.run_truncated = False

    def request(self, method: str, path: str, body: Any = None) -> Any:
        self.calls.append((method, path, body))
        repo_base = f"/repos/{POLICY.repository_full_name}"
        if path == repo_base:
            return self.repository
        if path == f"{repo_base}/actions/workflows/{POLICY.workflow_id}":
            return self.workflow
        if path == f"{repo_base}/commits/{SOURCE_SHA}":
            return self.commit
        if path == f"{repo_base}/actions/runs/{self.exact_run.get('id', -1)}":
            return self.exact_run

        parsed = urlsplit(path)
        query = parse_qs(parsed.query)
        page = int(query.get("page", ["1"])[0])
        if parsed.path == f"{repo_base}/actions/workflows/{POLICY.workflow_id}/runs":
            start = (page - 1) * 100
            return {
                "total_count": self.run_total_by_page.get(page, len(self.runs)),
                "workflow_runs": self.runs[start : start + 100],
                "truncated": self.run_truncated,
            }
        jobs_prefix = f"{repo_base}/actions/runs/{self.exact_run.get('id', -1)}/attempts/"
        if parsed.path.startswith(jobs_prefix) and parsed.path.endswith("/jobs"):
            start = (page - 1) * 100
            return {
                "total_count": self.job_total_by_page.get(page, len(self.jobs)),
                "jobs": self.jobs[start : start + 100],
            }
        raise AssertionError("unexpected endpoint")


def inspect(api: FakeApi, parameters: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    return inspect_ci(
        parameters or {"repository": "zach", "source_sha": SOURCE_SHA},
        POLICY,
        api.request,
    )


class TestCiInspect(unittest.TestCase):
    def test_happy_path_is_bounded_and_read_only(self) -> None:
        api = FakeApi()
        result = inspect(api)
        self.assertEqual(result["result"], "found")
        self.assertTrue(result["complete"])
        self.assertEqual(result["selected_run"]["id"], 33958090021)
        self.assertEqual(result["jobs"][0]["id"], 7001)
        self.assertLessEqual(
            len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode()),
            MAX_RESULT_BYTES,
        )
        self.assertTrue(all(method == "GET" and body is None for method, _, body in api.calls))

    def test_repository_workflow_and_commit_are_bound_to_policy(self) -> None:
        cases = []
        wrong_repo = FakeApi()
        wrong_repo.repository["id"] += 1
        cases.append((wrong_repo, "repository_identity_mismatch"))
        wrong_workflow = FakeApi()
        wrong_workflow.workflow["path"] = ".github/workflows/other.yml"
        cases.append((wrong_workflow, "workflow_identity_mismatch"))
        disabled_workflow = FakeApi()
        disabled_workflow.workflow["state"] = "disabled_manually"
        cases.append((disabled_workflow, "workflow_identity_mismatch"))
        wrong_commit = FakeApi()
        wrong_commit.commit["sha"] = "a" * 40
        cases.append((wrong_commit, "commit_identity_mismatch"))
        for api, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(CiInspectError) as error:
                    inspect(api)
                self.assertEqual(error.exception.code, code)

    def test_foreign_or_non_ci_runs_cannot_satisfy_inspection(self) -> None:
        mutations = [
            ("repository", {"id": 1, "full_name": POLICY.repository_full_name}),
            ("head_repository", {"id": 1, "full_name": POLICY.repository_full_name}),
            ("workflow_id", POLICY.workflow_id + 1),
            ("path", ".github/workflows/release.yml"),
            ("head_sha", "a" * 40),
            ("html_url", "https://example.invalid/run"),
        ]
        for field, value in mutations:
            api = FakeApi()
            api.runs[0][field] = value
            with self.subTest(field=field):
                with self.assertRaises(CiInspectError) as error:
                    inspect(api)
                self.assertEqual(error.exception.code, "foreign_run")

    def test_no_run_is_explicitly_not_found(self) -> None:
        api = FakeApi()
        api.runs = []
        result = inspect(api)
        self.assertEqual(result["result"], "not_found")
        self.assertEqual(result["observed_total"], 0)
        self.assertIsNone(result["selected_run"])
        self.assertEqual(result["jobs"], [])

    def test_newest_pending_or_failure_never_reuses_older_success(self) -> None:
        for newest in [
            make_run(200, status="in_progress", conclusion=None, created_at="2026-09-05T10:00:00Z"),
            make_run(201, status="completed", conclusion="failure", created_at="2026-09-05T10:00:00Z"),
        ]:
            api = FakeApi()
            older = make_run(100, created_at="2026-09-05T09:00:00Z")
            api.runs = [older, newest]
            api.exact_run = dict(newest)
            api.jobs = []
            with self.subTest(status=newest["status"]):
                result = inspect(api)
                self.assertEqual(result["selected_run"]["id"], newest["id"])
                self.assertEqual(result["selected_run"]["conclusion"], newest["conclusion"])

    def test_run_pagination_is_exhaustive_and_deterministic(self) -> None:
        api = FakeApi()
        api.runs = [make_run(run_id, created_at="2026-09-05T09:28:46Z") for run_id in range(1, 102)]
        api.exact_run = dict(api.runs[-1])
        api.jobs = []
        result = inspect(api)
        self.assertEqual(result["observed_total"], 101)
        self.assertEqual(len(result["runs"]), 10)
        self.assertEqual([row["id"] for row in result["runs"]], list(range(101, 91, -1)))
        run_calls = [path for _, path, _ in api.calls if "/workflows/" in path and "/runs?" in path]
        self.assertEqual(len(run_calls), 4)

    def test_malformed_incomplete_and_changing_pagination_fail_closed(self) -> None:
        malformed = FakeApi()
        malformed.runs = ["not-an-object"]
        incomplete = FakeApi()
        incomplete.runs = [make_run(i) for i in range(1, 51)]
        incomplete.run_total_by_page[1] = 101
        changing = FakeApi()
        changing.runs = [make_run(i) for i in range(1, 102)]
        changing.run_total_by_page = {1: 101, 2: 102}
        truncated = FakeApi()
        truncated.run_truncated = True
        malformed_flag = FakeApi()
        malformed_flag.run_truncated = "yes"
        for api, code in [
            (malformed, "malformed_run"),
            (incomplete, "incomplete_pagination"),
            (changing, "pagination_changed"),
            (truncated, "incomplete_pagination"),
            (malformed_flag, "malformed_pagination"),
        ]:
            with self.subTest(code=code):
                with self.assertRaises(CiInspectError) as error:
                    inspect(api)
                self.assertEqual(error.exception.code, code)

    def test_newer_run_during_jobs_invalidates_old_success(self) -> None:
        api = FakeApi()
        original = api.request

        def changing(method, path, body=None):
            result = original(method, path, body)
            if "/jobs?" in path:
                api.runs.append(make_run(33958090022, status="in_progress", conclusion=None,
                                         created_at="2026-09-05T09:29:00Z"))
            return result

        with self.assertRaises(CiInspectError) as error:
            inspect_ci({"repository": "zach", "source_sha": SOURCE_SHA}, POLICY, changing)
        self.assertEqual(error.exception.code, "run_changed")
        self.assertTrue(error.exception.retryable)

    def test_surrogate_labels_and_wrong_job_attempt_fail_closed(self) -> None:
        for field, value, code in (("name", "\ud800", "malformed_job"),
                                   ("run_attempt", 2, "foreign_job")):
            api = FakeApi()
            api.jobs[0][field] = value
            with self.assertRaises(CiInspectError) as error:
                inspect(api)
            self.assertEqual(error.exception.code, code)

    def test_run_attempt_race_is_retryable(self) -> None:
        api = FakeApi()
        api.exact_run["run_attempt"] = 2
        with self.assertRaises(CiInspectError) as error:
            inspect(api)
        self.assertEqual(error.exception.code, "run_changed")
        self.assertTrue(error.exception.retryable)

    def test_foreign_job_identity_or_url_fails_closed(self) -> None:
        for field, value in [
            ("run_id", 1),
            ("head_sha", "a" * 40),
            ("html_url", "https://example.invalid/job"),
        ]:
            api = FakeApi()
            api.jobs[0][field] = value
            with self.subTest(field=field):
                with self.assertRaises(CiInspectError) as error:
                    inspect(api)
                self.assertEqual(error.exception.code, "foreign_job")

    def test_jobs_and_failed_steps_have_validated_ids_urls_and_truncated_labels(self) -> None:
        api = FakeApi()
        long_name = "é" * 200
        api.jobs = [
            make_job(
                7002,
                33958090021,
                name=long_name,
                conclusion="failure",
                steps=[
                    {"number": 1, "name": "checkout", "status": "completed", "conclusion": "success"},
                    {"number": 2, "name": long_name, "status": "completed", "conclusion": "failure"},
                ],
            )
        ]
        result = inspect(api)
        job = result["jobs"][0]
        self.assertTrue(result["labels_truncated"])
        self.assertTrue(job["name"].endswith("…"))
        self.assertEqual(job["failed_steps"], [
            {"number": 2, "name": job["failed_steps"][0]["name"], "conclusion": "failure"}
        ])
        self.assertTrue(job["failed_steps"][0]["name"].endswith("…"))

    def test_strict_parameters_policy_and_result_bound(self) -> None:
        bad_parameters = [
            {"repository": "zach", "source_sha": SOURCE_SHA, "workflow_id": 1},
            {"repository": "infrastructure", "source_sha": SOURCE_SHA},
            {"repository": "zach", "source_sha": SOURCE_SHA.upper()},
            {"repository": "zach", "source_sha": SOURCE_SHA, "ref": "main"},
        ]
        for parameters in bad_parameters:
            api = FakeApi()
            with self.subTest(parameters=parameters):
                with self.assertRaises(CiInspectError):
                    inspect(api, parameters)
                self.assertEqual(api.calls, [])

        api = FakeApi()
        api.jobs = [make_job(i, 33958090021, name="x" * 200) for i in range(1, 101)]
        with self.assertRaises(CiInspectError) as error:
            inspect(api)
        self.assertEqual(error.exception.code, "result_too_large")


if __name__ == "__main__":
    unittest.main()
