"""Unit tests for actions_github_api module.

Validates:
- Namespace confinement & constructor repository allowlist enforcement
- Encoded traversal, backslash, fragment, userinfo, and control character rejection
- Redirect refusal and _NoRedirectHandler enforcement
- Request headers, token authorization, and 20s timeout
- Request and response bounds (256 KiB body, 2 MiB response)
- Strict JSON handling: duplicate key rejection, NaN/Infinity rejection, UTF-8 validation
- HTTP 204 empty-body requirement
- HTTP status errors, network failures, and timeout errors
- Zero retries on mutating request failure
- Token and body secrecy in exceptions, repr, and logs
- Allowed HTTP methods
- Compatibility with ActionsGitJournal transport contract
"""

from __future__ import annotations

import io
import json
import socket
import unittest
from typing import Any, Callable, Optional
import urllib.error
import urllib.request

from actions_git_journal import ActionsGitJournal, ApiError
from actions_github_api import (
    FIXED_BASE_URL,
    GithubApi,
    RequestValidationError,
    _NoRedirectHandler,
)

SYNTHETIC_TOKEN = "ghp_SYNTHETIC_TEST_TOKEN_0123456789abcdef"


class MockResponse:
    """Mock urllib response object."""

    def __init__(
        self,
        body: bytes = b"",
        status: int = 200,
        content_type: str = "application/json; charset=utf-8",
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        self._body = io.BytesIO(body)
        self.status = status
        hdrs = dict(headers or {})
        if "Content-Type" not in hdrs and content_type:
            hdrs["Content-Type"] = content_type
        self.headers = hdrs
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def getcode(self) -> int:
        return self.status

    def close(self) -> None:
        self.closed = True


class MockOpener:
    """Mock urllib OpenerDirector recording calls and returning scripted responses."""

    def __init__(self, handler: Callable[[urllib.request.Request, float], Any]) -> None:
        self.handler = handler
        self.calls: list[tuple[urllib.request.Request, float]] = []

    def open(self, req: urllib.request.Request, timeout: float = 0) -> Any:
        self.calls.append((req, timeout))
        return self.handler(req, timeout)


class TestGithubApi(unittest.TestCase):
    def setUp(self) -> None:
        self.default_repos = ["shockerqt/workspace-governance", "shockerqt/zach"]
        self.mock_opener = MockOpener(lambda req, timeout: MockResponse(body=b"{}"))
        self.api = GithubApi(
            token=SYNTHETIC_TOKEN,
            allowed_repositories=self.default_repos,
            opener=self.mock_opener,  # type: ignore[arg-type]
        )

    def test_constructor_allowlist_validation(self) -> None:
        # Non-empty subsets of trusted repositories are allowed
        api1 = GithubApi(SYNTHETIC_TOKEN, ["shockerqt/zach"])
        self.assertEqual(api1._allowed_repositories, frozenset(["shockerqt/zach"]))

        api2 = GithubApi(
            SYNTHETIC_TOKEN,
            [
                "shockerqt/workspace-governance",
                "shockerqt/zach",
                "shockerqt/ui-design-sandbox",
                "shockerqt/infrastructure",
            ],
        )
        self.assertEqual(len(api2._allowed_repositories), 4)

        # Empty allowlist rejected
        with self.assertRaises(ValueError):
            GithubApi(SYNTHETIC_TOKEN, [])

        with self.assertRaises(ValueError):
            GithubApi(SYNTHETIC_TOKEN, None)  # type: ignore[arg-type]

        # Untrusted repository rejected
        with self.assertRaises(ValueError):
            GithubApi(SYNTHETIC_TOKEN, ["shockerqt/unknown-repo"])

        with self.assertRaises(ValueError):
            GithubApi(SYNTHETIC_TOKEN, ["attacker/evil-repo"])

        with self.assertRaises(ValueError):
            GithubApi(SYNTHETIC_TOKEN, ["shockerqt/zach", "attacker/evil-repo"])

    def test_token_validation_and_secrecy(self) -> None:
        # Empty or whitespace tokens rejected
        for bad_token in ["", "   ", "\t", "\n", "token with spaces", "bad\x00token", "bad\ntoken"]:
            with self.assertRaises(ValueError) as ctx:
                GithubApi(bad_token, self.default_repos)
            # Ensure the bad token is not in the error message
            if bad_token:
                self.assertNotIn(bad_token, str(ctx.exception))

        # Repr never reveals token
        self.assertNotIn(SYNTHETIC_TOKEN, repr(self.api))
        self.assertIn("GithubApi", repr(self.api))

    def test_namespace_confinement(self) -> None:
        # Valid path targeting allowed repo
        self.api.request("GET", "/repos/shockerqt/zach/git/ref/heads/main")
        self.assertEqual(len(self.mock_opener.calls), 1)

        # Path targeting trusted repo that is NOT in this instance's allowlist
        single_repo_api = GithubApi(
            token=SYNTHETIC_TOKEN,
            allowed_repositories=["shockerqt/zach"],
            opener=self.mock_opener,  # type: ignore[arg-type]
        )
        with self.assertRaises(ApiError) as ctx:
            single_repo_api.request("GET", "/repos/shockerqt/workspace-governance/git/ref")
        self.assertEqual(ctx.exception.status, 403)

        # Path targeting completely untrusted repo
        with self.assertRaises(ApiError) as ctx:
            self.api.request("GET", "/repos/attacker/evil/git/ref")
        self.assertEqual(ctx.exception.status, 403)

        # Exact namespace boundary: prefix match without boundary must fail
        with self.assertRaises(ApiError) as ctx:
            self.api.request("GET", "/repos/shockerqt/zachary/git/ref")
        self.assertEqual(ctx.exception.status, 403)

        # Exact repo root path is allowed
        self.api.request("GET", "/repos/shockerqt/zach")

        # Non-repo endpoints rejected
        with self.assertRaises(ApiError) as ctx:
            self.api.request("GET", "/orgs/shockerqt/repos")
        self.assertEqual(ctx.exception.status, 400)

        with self.assertRaises(ApiError) as ctx:
            self.api.request("GET", "/users/shockerqt")
        self.assertEqual(ctx.exception.status, 400)

    def test_encoded_traversal_and_invalid_paths(self) -> None:
        invalid_paths = [
            "/repos/shockerqt/zach/..",
            "/repos/shockerqt/zach/.",
            "/repos/shockerqt/zach/../workspace-governance",
            "/repos/shockerqt/zach/./git/refs",
            "/repos/shockerqt/zach/%2e%2e/workspace-governance",
            "/repos/shockerqt/zach/%2e/git/refs",
            "/repos/shockerqt/zach/%2E%2E/foo",
            "/repos/shockerqt/zach/%252e%252e/foo",  # double encoded
            "/repos/shockerqt/zach/..%2ffoo",
            "/repos/shockerqt/zach/%2e%2e%2ffoo",
            "/repos/shockerqt/zach\\something",
            "/repos/shockerqt/zach/%5csomething",
            "/repos/shockerqt/zach#fragment",
            "/repos/shockerqt/zach/%23fragment",
            "/repos/shockerqt/zach@attacker",
            "/repos/shockerqt/zach/%40attacker",
            "//api.github.com/repos/shockerqt/zach",
            "https://api.github.com/repos/shockerqt/zach",
            "http://api.github.com/repos/shockerqt/zach",
            "/repos/shockerqt/zach/invalid\nchar",
            "/repos/shockerqt/zach/invalid\0char",
            "/repos/shockerqt/zach//git/refs",
        ]
        for path in invalid_paths:
            with self.subTest(path=path):
                with self.assertRaises(ApiError) as ctx:
                    self.api.request("GET", path)
                self.assertIn(ctx.exception.status, (400, 403))

    def test_query_string_pagination_allowed(self) -> None:
        self.api.request("GET", "/repos/shockerqt/zach/git/refs?page=2&per_page=100")
        req, _ = self.mock_opener.calls[-1]
        self.assertEqual(
            req.full_url,
            f"{FIXED_BASE_URL}/repos/shockerqt/zach/git/refs?page=2&per_page=100",
        )

        self.api.request(
            "GET",
            "/repos/shockerqt/workspace-governance/contents/requests/item.json?ref=heads/automation/requests",
        )
        req2, _ = self.mock_opener.calls[-1]
        self.assertEqual(
            req2.full_url,
            f"{FIXED_BASE_URL}/repos/shockerqt/workspace-governance/contents/requests/item.json?ref=heads/automation/requests",
        )

    def test_allowed_http_methods(self) -> None:
        for method in ["GET", "POST", "PATCH", "PUT", "DELETE"]:
            with self.subTest(method=method):
                self.api.request(method, "/repos/shockerqt/zach")

        for bad_method in ["HEAD", "OPTIONS", "TRACE", "CONNECT", "PURGE", "INVALID"]:
            with self.subTest(bad_method=bad_method):
                with self.assertRaises(ApiError) as ctx:
                    self.api.request(bad_method, "/repos/shockerqt/zach")
                self.assertEqual(ctx.exception.status, 400)

    def test_headers_authorization_and_timeout(self) -> None:
        self.api.request("POST", "/repos/shockerqt/zach/git/blobs", body={"content": "test"})
        req, timeout = self.mock_opener.calls[-1]
        self.assertEqual(timeout, 20.0)
        self.assertEqual(req.get_header("Accept"), "application/vnd.github+json")
        self.assertEqual(req.get_header("X-github-api-version"), "2026-03-10")
        self.assertEqual(req.get_header("User-agent"), "zach-actions")
        self.assertEqual(req.get_header("Authorization"), f"Bearer {SYNTHETIC_TOKEN}")
        self.assertEqual(req.get_header("Content-type"), "application/json")

        # GET without body should NOT set Content-Type
        self.api.request("GET", "/repos/shockerqt/zach")
        req_get, _ = self.mock_opener.calls[-1]
        self.assertIsNone(req_get.get_header("Content-type"))

    def test_request_body_finite_strict_json(self) -> None:
        # Non-finite float values rejected
        with self.assertRaises(ApiError) as ctx:
            self.api.request("POST", "/repos/shockerqt/zach", body={"nan": float("nan")})
        self.assertEqual(ctx.exception.status, 400)

        with self.assertRaises(ApiError) as ctx:
            self.api.request("POST", "/repos/shockerqt/zach", body={"inf": float("inf")})
        self.assertEqual(ctx.exception.status, 400)

        # Body > 256 KiB rejected
        oversize_body = {"data": "x" * (256 * 1024)}
        with self.assertRaises(ApiError) as ctx:
            self.api.request("POST", "/repos/shockerqt/zach", body=oversize_body)
        self.assertEqual(ctx.exception.status, 400)

    def test_response_bounded_reads(self) -> None:
        # Response > 2 MiB rejected
        huge_bytes = b'{"data":"' + (b"a" * (2 * 1024 * 1024 + 10)) + b'"}'
        self.mock_opener.handler = lambda req, timeout: MockResponse(body=huge_bytes)
        with self.assertRaises(ApiError) as ctx:
            self.api.request("GET", "/repos/shockerqt/zach")
        self.assertEqual(ctx.exception.status, 200)
        self.assertIn("exceeds maximum size", str(ctx.exception))

    def test_response_strict_json_and_duplicate_rejection(self) -> None:
        # Duplicate keys rejected
        dup_json = b'{"key": 1, "key": 2}'
        self.mock_opener.handler = lambda req, timeout: MockResponse(body=dup_json)
        with self.assertRaises(ApiError) as ctx:
            self.api.request("GET", "/repos/shockerqt/zach")
        self.assertIn("Duplicate key", str(ctx.exception))

        # Non-finite numbers rejected in response
        for raw in [b'{"v": NaN}', b'{"v": Infinity}', b'{"v": -Infinity}']:
            self.mock_opener.handler = lambda req, timeout: MockResponse(body=raw)
            with self.assertRaises(ApiError) as ctx:
                self.api.request("GET", "/repos/shockerqt/zach")
            self.assertIn("Non-finite JSON", str(ctx.exception))

        # Invalid UTF-8 rejected
        self.mock_opener.handler = lambda req, timeout: MockResponse(body=b'{"bad": \xff\xfe}')
        with self.assertRaises(ApiError) as ctx:
            self.api.request("GET", "/repos/shockerqt/zach")
        self.assertIn("UTF-8", str(ctx.exception))

        # Root must be object or array
        for non_obj in [b'"just string"', b'12345', b'true', b'null']:
            self.mock_opener.handler = lambda req, timeout: MockResponse(body=non_obj)
            with self.assertRaises(ApiError) as ctx:
                self.api.request("GET", "/repos/shockerqt/zach")
            self.assertIn("object or array", str(ctx.exception))

        # Array root is allowed
        self.mock_opener.handler = lambda req, timeout: MockResponse(body=b'[{"id": 1}]')
        res = self.api.request("GET", "/repos/shockerqt/zach")
        self.assertEqual(res, [{"id": 1}])

    def test_response_content_type_validation(self) -> None:
        for bad_ct in ["text/html", "text/plain", "application/xml", "image/png"]:
            self.mock_opener.handler = lambda req, timeout: MockResponse(body=b"{}", content_type=bad_ct)
            with self.assertRaises(ApiError) as ctx:
                self.api.request("GET", "/repos/shockerqt/zach")
            self.assertIn("Content-Type", str(ctx.exception))

        # Non UTF-8 charset rejected
        self.mock_opener.handler = lambda req, timeout: MockResponse(
            body=b"{}", content_type="application/json; charset=iso-8859-1"
        )
        with self.assertRaises(ApiError) as ctx:
            self.api.request("GET", "/repos/shockerqt/zach")
        self.assertIn("charset", str(ctx.exception))

        # Valid GitHub content types
        for valid_ct in [
            "application/json",
            "application/json; charset=utf-8",
            "application/vnd.github+json",
            "application/vnd.github+json; charset=utf-8",
        ]:
            self.mock_opener.handler = lambda req, timeout: MockResponse(body=b"{}", content_type=valid_ct)
            res = self.api.request("GET", "/repos/shockerqt/zach")
            self.assertEqual(res, {})

    def test_numeric_overflow_is_not_finite_json(self) -> None:
        self.mock_opener.handler = lambda req, timeout: MockResponse(body=b'{"x":1e999}')
        with self.assertRaises(ApiError):
            self.api.request("GET", "/repos/shockerqt/zach")

    def test_deeply_encoded_traversal_is_rejected(self) -> None:
        path = "/repos/shockerqt/zach/" + "%" + "25" * 10 + "2e/other"
        with self.assertRaises(ApiError):
            self.api.request("GET", path)

    def test_http_204_semantics(self) -> None:
        # 204 with empty body returns None
        self.mock_opener.handler = lambda req, timeout: MockResponse(body=b"", status=204)
        res = self.api.request("DELETE", "/repos/shockerqt/zach")
        self.assertIsNone(res)

        # 204 with non-empty body raises ApiError(204)
        self.mock_opener.handler = lambda req, timeout: MockResponse(body=b"extra content", status=204)
        with self.assertRaises(ApiError) as ctx:
            self.api.request("DELETE", "/repos/shockerqt/zach")
        self.assertEqual(ctx.exception.status, 204)

    def test_redirect_refusal(self) -> None:
        # Redirect status returned directly
        for code in [301, 302, 303, 307, 308]:
            self.mock_opener.handler = lambda req, timeout, c=code: MockResponse(body=b"", status=c)
            with self.assertRaises(ApiError) as ctx:
                self.api.request("GET", "/repos/shockerqt/zach")
            self.assertEqual(ctx.exception.status, code)

        # _NoRedirectHandler raises HTTPError
        handler = _NoRedirectHandler()
        req = urllib.request.Request("https://api.github.com/repos/shockerqt/zach")
        self.assertIsNone(handler.redirect_request(req, None, 302, "Found", {}, "https://evil.com"))
        with self.assertRaises(urllib.error.HTTPError) as ctx2:
            handler.http_error_302(req, None, 302, "Found", {})
        self.assertEqual(ctx2.exception.code, 302)

    def test_http_errors_and_network_failures(self) -> None:
        # HTTP errors preserve numeric status
        for status_code in [401, 403, 404, 422, 500, 502, 503]:
            def raise_http(req: urllib.request.Request, timeout: float, c: int = status_code) -> Any:
                raise urllib.error.HTTPError(req.full_url, c, f"Error {c}", {}, None)

            self.mock_opener.handler = raise_http
            with self.assertRaises(ApiError) as ctx:
                self.api.request("GET", "/repos/shockerqt/zach")
            self.assertEqual(ctx.exception.status, status_code)

        # Network error raises 500
        def raise_url_err(req: urllib.request.Request, timeout: float) -> Any:
            raise urllib.error.URLError("Connection refused")

        self.mock_opener.handler = raise_url_err
        with self.assertRaises(ApiError) as ctx:
            self.api.request("GET", "/repos/shockerqt/zach")
        self.assertEqual(ctx.exception.status, 500)
        self.assertEqual(ctx.exception.message, "Network failure")

        # Timeout raises 504
        def raise_timeout(req: urllib.request.Request, timeout: float) -> Any:
            raise urllib.error.URLError(socket.timeout("timed out"))

        self.mock_opener.handler = raise_timeout
        with self.assertRaises(ApiError) as ctx:
            self.api.request("GET", "/repos/shockerqt/zach")
        self.assertEqual(ctx.exception.status, 504)
        self.assertEqual(ctx.exception.message, "Request timed out")

    def test_zero_retries_after_mutating_failure(self) -> None:
        call_count = 0

        def failing_handler(req: urllib.request.Request, timeout: float) -> Any:
            nonlocal call_count
            call_count += 1
            raise urllib.error.HTTPError(req.full_url, 500, "Internal Server Error", {}, None)

        self.mock_opener.handler = failing_handler

        for method in ["POST", "PATCH", "PUT", "DELETE"]:
            call_count = 0
            with self.subTest(method=method):
                with self.assertRaises(ApiError):
                    self.api.request(method, "/repos/shockerqt/zach", body={"state": "mutating"})
                self.assertEqual(call_count, 1)

    def test_secret_absence_in_all_errors(self) -> None:
        sensitive_body = {"secret_data": "VERY_SENSITIVE_BODY_12345"}

        # 1. Validation error
        try:
            self.api.request("GET", "/repos/untrusted/repo")
        except Exception as exc:
            self.assertNotIn(SYNTHETIC_TOKEN, str(exc))
            self.assertNotIn(SYNTHETIC_TOKEN, repr(exc))

        # 2. HTTP error
        self.mock_opener.handler = lambda req, timeout: (_ for _ in ()).throw(
            urllib.error.HTTPError(req.full_url, 401, "Bad credentials", {}, None)
        )
        try:
            self.api.request("POST", "/repos/shockerqt/zach", body=sensitive_body)
        except Exception as exc:
            self.assertNotIn(SYNTHETIC_TOKEN, str(exc))
            self.assertNotIn(SYNTHETIC_TOKEN, repr(exc))
            self.assertNotIn("VERY_SENSITIVE_BODY_12345", str(exc))
            self.assertNotIn("VERY_SENSITIVE_BODY_12345", repr(exc))

        # 3. Timeout error
        self.mock_opener.handler = lambda req, timeout: (_ for _ in ()).throw(TimeoutError("timed out"))
        try:
            self.api.request("POST", "/repos/shockerqt/zach", body=sensitive_body)
        except Exception as exc:
            self.assertNotIn(SYNTHETIC_TOKEN, str(exc))
            self.assertNotIn(SYNTHETIC_TOKEN, repr(exc))
            self.assertNotIn("VERY_SENSITIVE_BODY_12345", str(exc))

    def test_request_key_collision_and_recursive_shapes(self) -> None:
        cyclic = {}
        cyclic["self"] = cyclic
        for body in ({1: "first", "1": "second"}, {"nested": [{True: "value"}]}, cyclic):
            with self.subTest(body_type=type(body).__name__):
                with self.assertRaises(RequestValidationError):
                    self.api.request("POST", "/repos/shockerqt/zach", body=body)
                self.assertEqual(self.mock_opener.calls, [])

    def test_path_size_and_ascii_bounds(self) -> None:
        prefix = "/repos/shockerqt/zach?value="
        exact = prefix + "x" * (8192 - len(prefix))
        self.assertEqual(self.api.request("GET", exact), {})
        self.mock_opener.calls.clear()
        for invalid in (exact + "x", prefix + "ñ", prefix + "\ud800"):
            with self.assertRaises(RequestValidationError):
                self.api.request("GET", invalid)
            self.assertEqual(self.mock_opener.calls, [])

    def test_actions_git_journal_compatibility(self) -> None:
        def mock_journal_handler(req: urllib.request.Request, timeout: float) -> Any:
            # Simulate minimal ref lookup
            if "/git/ref/" in req.full_url:
                return MockResponse(
                    body=json.dumps({"ref": "refs/heads/automation/requests", "object": {"sha": "a" * 40}}).encode(
                        "utf-8"
                    )
                )
            return MockResponse(body=b"{}")

        self.mock_opener.handler = mock_journal_handler

        # ActionsGitJournal accepts api.request or api as transport
        journal = ActionsGitJournal(request=self.api.request, validate_transition=lambda old, new: None)
        res = journal.request("GET", "/repos/shockerqt/workspace-governance/git/ref/heads/automation/requests")
        self.assertIsInstance(res, dict)
        self.assertEqual(res["ref"], "refs/heads/automation/requests")


if __name__ == "__main__":
    unittest.main()
