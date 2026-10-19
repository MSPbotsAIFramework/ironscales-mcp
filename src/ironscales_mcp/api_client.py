# Copyright 2026 MSPbots.ai
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Async client for the IRONSCALES Management API (AppAPI) with its JWT exchange."""

import asyncio
import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx

from ._json import error_envelope
from .config import API_BASE_URL, DEFAULT_SCOPE_SETS

logger = logging.getLogger("ironscales_mcp.api")

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_MAX_RETRIES = 2
_MAX_BACKOFF_SECONDS = 20.0
# Whole-call budget including retries; the gateway times a tool call out at 120s.
_CALL_BUDGET_SECONDS = 100.0
_DEFAULT_TOKEN_SECONDS = 20 * 60.0
_TOKEN_REFRESH_MARGIN_SECONDS = 60.0

# One connection pool for the process. It never holds credentials: the
# Authorization header is built per request from the caller's own token.
_shared_http_client: httpx.AsyncClient | None = None

# JWTs keyed by a SHA-256 of the API key plus the scopes they were issued for,
# so a token is only ever reused by a caller holding the same key.
_token_cache: dict[str, tuple[str, float]] = {}
# Which default scope set worked for a key (hash), so later calls skip the probe.
_scope_choice: dict[str, tuple[str, ...]] = {}


def _get_shared_http_client() -> httpx.AsyncClient:
    global _shared_http_client
    if _shared_http_client is None:
        _shared_http_client = httpx.AsyncClient(timeout=_TIMEOUT)
    return _shared_http_client


# status_code -> (error code, retryable). 0 means no HTTP response at all
# (connection error or timeout).
_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    409: ("invalid_argument", False),
    422: ("invalid_argument", False),
    429: ("rate_limited", True),
}


def classify_status(status_code: int) -> tuple[str, bool]:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if status_code >= 500:
        return "upstream_error", True
    if status_code >= 400:
        return "invalid_argument", False
    return "upstream_error", True


class IronscalesError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"IRONSCALES API error {status_code}: {message}")

    def to_envelope(self) -> str:
        code, retryable = classify_status(self.status_code)
        return error_envelope(code, self.message, retryable)


@dataclass(frozen=True)
class IronscalesCredentials:
    api_key: str
    company_id: int
    scopes: tuple[str, ...] | None = None

    def __repr__(self) -> str:  # never leak the key into logs or tracebacks
        return f"IronscalesCredentials(company_id={self.company_id}, api_key=<redacted>)"

    def key_hash(self) -> str:
        return hashlib.sha256(self.api_key.encode()).hexdigest()


def _jwt_expiry(token: str) -> float:
    """Seconds from now until the JWT's exp claim, or a default when it cannot be read."""
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return max(0.0, float(claims["exp"]) - time.time())
    except (IndexError, ValueError, KeyError, TypeError):
        return _DEFAULT_TOKEN_SECONDS


class IronscalesClient:
    """Thin wrapper over the IRONSCALES AppAPI for one caller's key and company."""

    def __init__(self, credentials: IronscalesCredentials, http_client: httpx.AsyncClient | None = None):
        self._credentials = credentials
        self._http = http_client
        self.company_id = credentials.company_id

    # ---- auth -----------------------------------------------------------------

    def _redact(self, text: str) -> str:
        # The token endpoint echoes the submitted key in its error message.
        return text.replace(self._credentials.api_key, "<redacted>") if self._credentials.api_key else text

    async def _fetch_token(self, scopes: tuple[str, ...]) -> str:
        http = self._http or _get_shared_http_client()
        try:
            resp = await http.post(f"{API_BASE_URL}/get-token/", json={"key": self._credentials.api_key, "scopes": list(scopes)})
        except httpx.TimeoutException as e:
            raise IronscalesError(0, "Timed out requesting an IRONSCALES token") from e
        except httpx.RequestError as e:
            raise IronscalesError(0, f"Network error requesting an IRONSCALES token: {type(e).__name__}") from e
        logger.info("ironscales_token status=%s scopes=%s", resp.status_code, ",".join(scopes))
        if resp.status_code >= 400:
            message = self._redact(_error_message(resp, "get-token"))
            raise IronscalesError(401 if resp.status_code in (400, 401, 403) else resp.status_code, message)
        try:
            token = resp.json()["jwt"]
        except (ValueError, KeyError, TypeError) as e:
            raise IronscalesError(502, "IRONSCALES returned an unexpected token response") from e
        return token

    async def _token(self, force_refresh: bool = False) -> str:
        key_hash = self._credentials.key_hash()
        if self._credentials.scopes:
            candidates: tuple[tuple[str, ...], ...] = (self._credentials.scopes,)
        elif key_hash in _scope_choice:
            candidates = (_scope_choice[key_hash],)
        else:
            candidates = DEFAULT_SCOPE_SETS
        last: IronscalesError | None = None
        for scopes in candidates:
            cache_key = f"{key_hash}:{','.join(scopes)}"
            cached = _token_cache.get(cache_key)
            if cached and not force_refresh and cached[1] - _TOKEN_REFRESH_MARGIN_SECONDS > time.monotonic():
                return cached[0]
            try:
                token = await self._fetch_token(scopes)
            except IronscalesError as e:
                # "Company does not have permission for requested scopes": try the next scope set.
                if e.status_code == 401 and "scope" in e.message.lower():
                    last = e
                    continue
                raise
            _token_cache[cache_key] = (token, time.monotonic() + _jwt_expiry(token))
            if not self._credentials.scopes:
                _scope_choice[key_hash] = scopes
            return token
        assert last is not None
        raise last

    # ---- requests ---------------------------------------------------------------

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request("GET", path, params=params)

    async def post(self, path: str, body: Any = None) -> Any:
        return await self.request("POST", path, body=body)

    async def delete(self, path: str, body: Any = None) -> Any:
        return await self.request("DELETE", path, body=body)

    async def request(self, method: str, path: str, params: dict[str, Any] | None = None, body: Any = None) -> Any:
        http = self._http or _get_shared_http_client()
        url = f"{API_BASE_URL}/{path.lstrip('/')}"
        query = {k: _param_value(v) for k, v in (params or {}).items() if v is not None}
        token = await self._token()
        refreshed = False
        started = time.monotonic()
        attempt = 0
        while True:
            t0 = time.monotonic()
            resp: httpx.Response | None = None
            error: IronscalesError | None = None
            headers = {"Authorization": f"JWT {token}", "Accept": "application/json"}
            try:
                kwargs: dict[str, Any] = {"params": query, "headers": headers}
                if body is not None:
                    kwargs["json"] = body
                resp = await http.request(method, url, **kwargs)
                status = resp.status_code
            except httpx.TimeoutException:
                status, error = 0, IronscalesError(0, f"Timed out calling IRONSCALES ({method} {path})")
            except httpx.RequestError as e:
                status, error = 0, IronscalesError(0, f"Network error calling IRONSCALES ({method} {path}): {type(e).__name__}")

            logger.info(
                "ironscales_api method=%s path=%s status=%s ms=%d attempt=%d",
                method, _log_path(path), status, (time.monotonic() - t0) * 1000, attempt,
            )

            # An expired or revoked JWT: fetch a fresh one once.
            if status in (401, 403) and not refreshed and resp is not None and "jwt" in resp.text.lower():
                refreshed = True
                token = await self._token(force_refresh=True)
                continue

            # 429 is refused before processing, so any method may retry it; other
            # failures are retried only for reads, so a write never runs twice.
            retryable = status == 429 or (method == "GET" and (status == 0 or status >= 500))
            if retryable and attempt < _MAX_RETRIES:
                delay = _retry_delay(resp, attempt)
                if time.monotonic() - started + delay < _CALL_BUDGET_SECONDS:
                    attempt += 1
                    await asyncio.sleep(delay)
                    continue
            if error is not None:
                raise error
            assert resp is not None
            if resp.status_code >= 400:
                raise IronscalesError(resp.status_code, _error_message(resp, _log_path(path)))
            if not resp.content or not resp.content.strip():
                return None
            try:
                return resp.json()
            except ValueError:
                return {"raw_response": resp.text[:2000]}


def _log_path(path: str) -> str:
    return path.split("?", 1)[0]


def _param_value(value: Any) -> Any:
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def _retry_delay(resp: httpx.Response | None, attempt: int) -> float:
    if resp is not None:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return max(0.0, min(float(retry_after), _MAX_BACKOFF_SECONDS))
            except ValueError:
                pass
    return min(float(2**attempt), _MAX_BACKOFF_SECONDS)


def _error_message(resp: httpx.Response, path: str) -> str:
    fallback = f"IRONSCALES returned HTTP {resp.status_code} for {path}"
    try:
        payload = resp.json()
    except ValueError:
        text = resp.text.strip()
        if text.lower().startswith("<"):
            return fallback  # an HTML error page, not useful to the agent
        return f"{fallback}: {text[:300]}" if text else fallback
    if isinstance(payload, dict):
        message = payload.get("error_message") or payload.get("message") or payload.get("detail") or payload.get("error")
        if message:
            return f"{fallback}: {str(message)[:500]}"
        if payload:
            details = "; ".join(f"{k}: {v}" for k, v in list(payload.items())[:5])
            return f"{fallback}: {details[:500]}"
    return fallback
