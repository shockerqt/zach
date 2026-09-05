"""Authenticated bounded GitHub JSON HTTP transport.

Transport is a trusted workflow utility, not an authorization substitute.
Caller responsibilities:
- Identity & authorization: Callers must independently bind numeric repository IDs,
  Issue IDs/numbers, and actor identities against configured identity allowlists.
- Policy enforcement: Callers must independently validate typed parameters and
  enforce operation and recipe policy before dispatching requests.
- Concurrency & idempotency: Callers must observe durable journal receipts and
  reconcile ambiguous publications before retrying effects.
- Credential safety: Callers must safeguard GitHub App tokens and prevent leakage.
"""

from __future__ import annotations

import json
import math
from typing import Any, Final, Iterable, Optional
import urllib.error
import urllib.parse
import urllib.request

from actions_git_journal import ApiError

class RequestValidationError(ApiError, ValueError):
    """Raised when request arguments fail validation."""

    def __init__(self, status: int = 400, message: str = "Request validation error") -> None:
        super().__init__(status, message)


FIXED_BASE_URL: Final[str] = "https://api.github.com"
ALLOWED_METHODS: Final[frozenset[str]] = frozenset({"GET", "POST", "PATCH", "PUT", "DELETE"})
TRUSTED_REPOSITORIES: Final[frozenset[str]] = frozenset({
    "shockerqt/workspace-governance",
    "shockerqt/zach",
    "shockerqt/ui-design-sandbox",
    "shockerqt/infrastructure",
})
MAX_PATH_BYTES: Final[int] = 8192
MAX_REQUEST_BYTES: Final[int] = 256 * 1024  # 256 KiB
MAX_RESPONSE_BYTES: Final[int] = 2 * 1024 * 1024  # 2 MiB
TIMEOUT_SECONDS: Final[float] = 20.0


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuses all HTTP redirects."""

    def redirect_request(self, *args: Any) -> None:
        return None

    def http_error_301(self, req: Any, fp: Any, code: int, msg: str, hdrs: Any) -> None:
        raise urllib.error.HTTPError(req.full_url, code, f"HTTP redirect {code} refused", hdrs, fp)

    http_error_302 = http_error_303 = http_error_307 = http_error_308 = http_error_301


class GithubApi:
    """Authenticated bounded GitHub JSON HTTP transport client."""

    def __init__(
        self,
        token: str,
        allowed_repositories: Iterable[str],
        opener: Optional[urllib.request.OpenerDirector] = None,
    ) -> None:
        if not isinstance(token, str) or not token or not token.isascii() or any(ord(c) < 32 or ord(c) == 127 or c.isspace() for c in token):
            raise ValueError("Token must be a non-empty string without whitespace or controls")
        allowed_set = frozenset(allowed_repositories) if allowed_repositories is not None else frozenset()
        if not allowed_set or not allowed_set.issubset(TRUSTED_REPOSITORIES):
            raise ValueError("allowed_repositories must be a nonempty subset of trusted repositories")
        self._token, self._allowed_repositories = token, allowed_set
        self._opener = opener if opener is not None else urllib.request.build_opener(_NoRedirectHandler())

    def __repr__(self) -> str:
        return f"GithubApi(allowed_repositories={sorted(self._allowed_repositories)!r})"

    def _validate_path(self, relative_path: str) -> str:
        if not isinstance(relative_path, str):
            raise RequestValidationError(400, "relative_path must be a string")
        if len(relative_path) > MAX_PATH_BYTES or not relative_path.isascii():
            raise RequestValidationError(400, "Path must be bounded ASCII; encode non-ASCII characters")
        if any(c in "\\#@" or ord(c) < 32 or ord(c) == 127 for c in relative_path):
            raise RequestValidationError(400, "Control characters, backslashes, fragments or userinfo rejected")
        if relative_path.startswith("//") or not relative_path.startswith("/repos/"):
            raise RequestValidationError(400, "Path must be relative starting with /repos/")
        unq_full = urllib.parse.unquote(relative_path)
        if any(c in "\\#@" or ord(c) < 32 or ord(c) == 127 for c in unq_full):
            raise RequestValidationError(400, "Encoded invalid characters rejected")

        path, _, query = relative_path.partition("?")
        if "//" in path:
            raise RequestValidationError(400, "Empty path segments rejected")
        curr = path
        for _ in range(9):
            if any(p in (".", "..") for p in curr.split("/")):
                raise RequestValidationError(400, "Dot/dot-dot path segments rejected")
            if any(c in "\\#@?" or ord(c) < 32 or ord(c) == 127 for c in curr):
                raise RequestValidationError(400, "Encoded path delimiters rejected")
            unq = urllib.parse.unquote(curr)
            if unq == curr:
                break
            curr = unq
        else:
            raise RequestValidationError(400, "Excessively encoded path rejected")

        if not any(path == f"/repos/{r}" or path.startswith(f"/repos/{r}/") for r in self._allowed_repositories):
            raise RequestValidationError(403, "Namespace boundary violation: path outside allowed repositories")

        full_url = f"{FIXED_BASE_URL}{relative_path}"
        u = urllib.parse.urlsplit(full_url)
        if (u.scheme, u.netloc, u.path) != ("https", "api.github.com", path) or u.username or u.port:
            raise RequestValidationError(400, "URL host or path alteration detected")
        return full_url

    def request(self, method: str, relative_path: str, body: Any = None) -> Any:
        if not isinstance(method, str) or method not in ALLOWED_METHODS:
            raise RequestValidationError(400, "HTTP method is not allowed")
        full_url = self._validate_path(relative_path)
        encoded_body: Optional[bytes] = None
        if body is not None:
            # JSON encoding coerces integer keys and can create duplicate names.
            # Validate the Python shape before encoding or touching the transport.
            pending = [(body, 0)]
            visited = 0
            while pending:
                value, depth = pending.pop()
                visited += 1
                if depth > 32 or visited > MAX_REQUEST_BYTES:
                    raise RequestValidationError(400, "Request JSON nesting or node count exceeds maximum")
                if type(value) is dict:
                    if len(value) > MAX_REQUEST_BYTES or any(type(key) is not str for key in value):
                        raise RequestValidationError(400, "Request JSON mappings require bounded string keys")
                    pending.extend((item, depth + 1) for item in value.values())
                elif type(value) is list:
                    if len(value) > MAX_REQUEST_BYTES:
                        raise RequestValidationError(400, "Request JSON node count exceeds maximum")
                    pending.extend((item, depth + 1) for item in value)
                elif type(value) not in (str, int, float, bool, type(None)):
                    raise RequestValidationError(400, "Request body contains non-JSON values")
            try:
                encoded_body = json.dumps(body, allow_nan=False, separators=(",", ":")).encode("utf-8")
            except (ValueError, TypeError, RecursionError, OverflowError):
                raise RequestValidationError(400, "Request body is not valid finite JSON") from None
            if len(encoded_body) > MAX_REQUEST_BYTES:
                raise RequestValidationError(400, f"Request body exceeds {MAX_REQUEST_BYTES} bytes")

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "zach-actions",
            "Authorization": f"Bearer {self._token}",
        }
        if encoded_body is not None:
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url=full_url, data=encoded_body, headers=headers, method=method)
        response = None
        try:
            response = self._opener.open(req, timeout=TIMEOUT_SECONDS)
            status = getattr(response, "status", None)
            if status is None and hasattr(response, "getcode"):
                status = response.getcode()
            if status == 204:
                if response.read(1):
                    raise ApiError(204, "HTTP 204 response must have empty body")
                return None
            if status not in (200, 201, 202):
                raise ApiError(status, f"HTTP error {status}")

            ct = response.headers.get("Content-Type", "") if getattr(response, "headers", None) else ""
            media_type = ct.split(";")[0].strip().lower()
            if media_type != "application/json" and not media_type.endswith("+json"):
                raise ApiError(status, "Response Content-Type is not JSON")
            for p in ct.split(";")[1:]:
                k, _, v = p.partition("=")
                if k.strip().lower() == "charset" and v.strip().strip('"').lower() != "utf-8":
                    raise ApiError(status, "Response charset is not UTF-8")

            raw_bytes = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw_bytes) > MAX_RESPONSE_BYTES:
                raise ApiError(status, "Response payload exceeds maximum size")
            try:
                body_str = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                raise ApiError(status, "Response body is not valid UTF-8") from None

            def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
                obj: dict[str, Any] = {}
                for k, v in pairs:
                    if k in obj:
                        raise ApiError(status, "Duplicate key in response JSON")
                    obj[k] = v
                return obj

            def _reject_const(c: str) -> None:
                raise ApiError(status, f"Non-finite JSON constant {c} rejected")

            def _finite_float(value: str) -> float:
                number = float(value)
                if not math.isfinite(number):
                    raise ApiError(status, "Non-finite JSON number rejected")
                return number

            try:
                parsed = json.loads(
                    body_str,
                    object_pairs_hook=_reject_duplicates,
                    parse_constant=_reject_const,
                    parse_float=_finite_float,
                )
            except ApiError:
                raise
            except Exception:
                raise ApiError(status, "Malformed JSON response") from None

            if not isinstance(parsed, (dict, list)):
                raise ApiError(status, "Response JSON root must be an object or array")
            return parsed
        except RequestValidationError:
            raise
        except ApiError:
            raise
        except urllib.error.HTTPError as exc:
            try:
                exc.close()
            except OSError:
                pass
            raise ApiError(exc.code, f"HTTP error {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", None)
            if isinstance(reason, TimeoutError) or "timed out" in str(reason or exc).lower():
                raise ApiError(504, "Request timed out") from None
            raise ApiError(500, "Network failure") from None
        except Exception:
            raise ApiError(500, "Transport failure") from None
        finally:
            if response is not None and hasattr(response, "close"):
                try:
                    response.close()
                except OSError:
                    pass

    def __call__(self, method: str, relative_path: str, body: Any = None) -> Any:
        return self.request(method, relative_path, body=body)
