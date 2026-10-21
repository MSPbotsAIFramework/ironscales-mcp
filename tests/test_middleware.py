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
"""Credential middleware: 401 on missing headers, deferred format errors, optional scopes, isolation."""

import asyncio

import pytest
from starlette.testclient import TestClient

from ironscales_mcp.__main__ import build_http_app
from ironscales_mcp.server import GatewayCredentialsMiddleware, _credentials_var, create_mcp_server, get_client_from_context, parse_scopes

MCP_HEADERS = {"Accept": "application/json, text/event-stream"}
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
CREDS = {"X-Ironscales-API-Key": "key", "X-Ironscales-Company-ID": "123456"}


def _client() -> TestClient:
    return TestClient(build_http_app(create_mcp_server()))


def test_health_is_local():
    with _client() as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.parametrize(
    "headers",
    [{}, {"X-Ironscales-API-Key": "key"}, {"X-Ironscales-Company-ID": "1"}, CREDS | {"X-Ironscales-API-Key": "${KEY}"}],
)
def test_missing_headers_return_401(headers):
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | headers)
    assert resp.status_code == 401
    assert resp.json()["required_headers"] == list(CREDS)


@pytest.mark.parametrize(
    "extra",
    [{"X-Ironscales-Company-ID": "abc"}, {"X-Ironscales-Company-ID": "0"}, {"X-Ironscales-Scopes": "company.all, DROP TABLE"}],
)
def test_invalid_values_are_reported_by_tools(extra):
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "ironscales_incidents_list", "arguments": {}}}
    with _client() as client:
        resp = client.post("/mcp", json=call, headers=MCP_HEADERS | CREDS | extra)
    assert resp.status_code == 200
    assert '\\"invalid_argument\\"' in resp.text and "must" in resp.text


def test_invalid_values_still_list_tools():
    # The admin console refreshes the tool catalog with placeholder header values.
    headers = {"X-Ironscales-API-Key": "placeholder", "X-Ironscales-Company-ID": "placeholder", "X-Ironscales-Scopes": "placeholder"}
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | headers)
    assert resp.status_code == 200
    assert "ironscales_incidents_list" in resp.text


def test_invalid_values_are_combined():
    seen = _run_middleware([(b"x-ironscales-api-key", b"key"), (b"x-ironscales-company-id", b"abc"), (b"x-ironscales-scopes", b"bad scope")])
    error = seen["client"].header_error
    assert "X-Ironscales-Company-ID must be the numeric company id" in error
    assert "; X-Ironscales-Scopes must list scopes like company.all" in error


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, None),
        ("", None),
        ("company.all", ("company.all",)),
        ("Company.View, company.classify;company.view", ("company.view", "company.classify")),
    ],
)
def test_parse_scopes(value, expected):
    assert parse_scopes(value) == expected


def test_tools_list_over_http():
    with _client() as client:
        resp = client.post("/mcp", json=LIST_TOOLS, headers=MCP_HEADERS | CREDS)
    assert resp.status_code == 200
    for name in ("ironscales_incidents_list", "ironscales_remediation_act", "ironscales_allowlist_manage"):
        assert name in resp.text


async def _receive():
    return {"type": "http.request", "body": b"", "more_body": False}


async def _send(_message):
    return None


def _run_middleware(headers: list[tuple[bytes, bytes]]) -> dict:
    seen: dict = {}

    async def app(scope, receive, send):
        seen["credentials"] = _credentials_var.get()
        seen["client"] = get_client_from_context()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    asyncio.run(GatewayCredentialsMiddleware(app)({"type": "http", "path": "/mcp", "headers": headers}, _receive, _send))
    return seen


def test_credentials_reach_request_context_and_are_reset():
    seen = _run_middleware(
        [(b"x-ironscales-api-key", b" key-123 "), (b"x-ironscales-company-id", b" 4242 "), (b"x-ironscales-scopes", b"company.view")]
    )
    assert seen["client"].company_id == 4242
    assert seen["credentials"].api_key == "key-123" and seen["credentials"].scopes == ("company.view",)
    assert _credentials_var.get() is None


def test_concurrent_requests_do_not_share_credentials():
    observed: list[tuple[str, str]] = []

    async def app(scope, receive, send):
        before = _credentials_var.get().api_key
        await asyncio.sleep(0.01)
        observed.append((before, _credentials_var.get().api_key))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = GatewayCredentialsMiddleware(app)

    def scope(key: bytes) -> dict:
        return {"type": "http", "path": "/mcp", "headers": [(b"x-ironscales-api-key", key), (b"x-ironscales-company-id", b"1")]}

    async def both():
        await asyncio.gather(middleware(scope(b"tenant-a"), _receive, _send), middleware(scope(b"tenant-b"), _receive, _send))

    asyncio.run(both())
    assert sorted(observed) == [("tenant-a", "tenant-a"), ("tenant-b", "tenant-b")]


def test_credentials_repr_hides_key():
    seen = _run_middleware([(b"x-ironscales-api-key", b"very-secret-key"), (b"x-ironscales-company-id", b"1")])
    assert "very-secret-key" not in repr(seen["credentials"])
