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
"""JWT exchange, request shapes and tool behaviour against a mocked IRONSCALES AppAPI."""

import base64
import json
import time

import httpx
import pytest

from ironscales_mcp import api_client
from ironscales_mcp.api_client import IronscalesClient, IronscalesCredentials, IronscalesError
from ironscales_mcp.server import _credentials_var, create_mcp_server

CREDS = IronscalesCredentials("key-123", 4242)


def make_jwt(exp: float) -> str:
    def part(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{part({'alg': 'HS256'})}.{part({'exp': exp})}.sig"


@pytest.fixture(autouse=True)
def no_sleep_and_fresh_tokens(monkeypatch):
    async def instant(_seconds):
        return None

    monkeypatch.setattr(api_client.asyncio, "sleep", instant)
    api_client._token_cache.clear()
    api_client._scope_choice.clear()
    yield
    api_client._token_cache.clear()
    api_client._scope_choice.clear()


class Recorder:
    """Mock transport: /get-token/ plus AppAPI routes by method + path below /appapi/."""

    def __init__(self, routes=None, default=None, token=None):
        self.requests: list[httpx.Request] = []
        self.token_requests: list[httpx.Request] = []
        self.routes = routes or {}
        self.default = default if default is not None else {}
        self.token = token

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/appapi/")
        if path == "get-token/":
            self.token_requests.append(request)
            if callable(self.token):
                return self.token(request)
            return httpx.Response(200, json={"jwt": f"jwt-{len(self.token_requests)}"})
        self.requests.append(request)
        reply = self.routes.get(f"{request.method} {path}", self.routes.get(path, self.default))
        if callable(reply):
            return reply(request)
        return httpx.Response(200, json=reply)

    def calls(self, path: str, method: str | None = None) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path == f"/appapi/{path}" and (method is None or r.method == method)]


def body(request: httpx.Request):
    return json.loads(request.content) if request.content else None


async def _call(monkeypatch, recorder: Recorder, tool: str, args: dict, creds: IronscalesCredentials = CREDS):
    http = httpx.AsyncClient(transport=httpx.MockTransport(recorder))
    monkeypatch.setattr(api_client, "_get_shared_http_client", lambda: http)
    ctx = _credentials_var.set(creds)
    try:
        content, _ = await create_mcp_server().call_tool(tool, args)
    finally:
        _credentials_var.reset(ctx)
    return json.loads(content[0].text)


def _client(recorder: Recorder, creds: IronscalesCredentials = CREDS) -> IronscalesClient:
    return IronscalesClient(creds, httpx.AsyncClient(transport=httpx.MockTransport(recorder)))


# ---- auth ------------------------------------------------------------------


async def test_token_exchange_and_jwt_header():
    rec = Recorder({"incident/4242/open/": {"incident_ids": [1, 2]}})
    client = _client(rec)
    await client.get("incident/4242/open/")
    await client.get("incident/4242/open/")
    assert len(rec.token_requests) == 1
    assert body(rec.token_requests[0]) == {"key": "key-123", "scopes": ["company.all"]}
    assert rec.requests[0].headers["authorization"] == "JWT jwt-1"
    assert str(rec.requests[0].url) == "https://appapi.ironscales.com/appapi/incident/4242/open/"


async def test_partner_scope_fallback_is_remembered():
    def token(request):
        scopes = body(request)["scopes"]
        if scopes == ["company.all"]:
            return httpx.Response(403, json={"message": "Company does not have permission for requested scopes"})
        return httpx.Response(200, json={"jwt": "partner-jwt"})

    rec = Recorder(token=token)
    await _client(rec).get("incident/4242/open/")
    assert [body(r)["scopes"] for r in rec.token_requests] == [["company.all"], ["partner.all"]]
    api_client._token_cache.clear()
    await _client(rec).get("incident/4242/open/")
    assert [body(r)["scopes"] for r in rec.token_requests][-1] == ["partner.all"] and len(rec.token_requests) == 3


async def test_explicit_scopes_are_used():
    rec = Recorder()
    await _client(rec, IronscalesCredentials("key-123", 4242, ("company.view", "company.classify"))).get("incident/4242/open/")
    assert body(rec.token_requests[0])["scopes"] == ["company.view", "company.classify"]


async def test_jwt_expiry_is_read_from_the_token():
    soon = make_jwt(time.time() + 30)  # inside the refresh margin: not reused
    rec = Recorder(token=lambda r: httpx.Response(200, json={"jwt": soon}))
    client = _client(rec)
    await client.get("incident/4242/open/")
    await client.get("incident/4242/open/")
    assert len(rec.token_requests) == 2


async def test_bad_key_is_unauthorized_and_redacted(monkeypatch):
    rec = Recorder(token=lambda r: httpx.Response(403, json={"message": "No company found for API key [key-123]"}))
    result = await _call(monkeypatch, rec, "ironscales_status", {})
    assert result["error"]["code"] == "unauthorized"
    assert "key-123" not in result["error"]["message"] and "<redacted>" in result["error"]["message"]
    assert rec.requests == []


async def test_expired_jwt_is_refreshed_once():
    replies = iter([httpx.Response(403, json={"detail": "Signature has expired. Failed to decode JWT"}), httpx.Response(200, json={"incident_ids": []})])
    rec = Recorder({"incident/4242/open/": lambda r: next(replies)})
    assert await _client(rec).get("incident/4242/open/") == {"incident_ids": []}
    assert len(rec.token_requests) == 2 and rec.requests[1].headers["authorization"] == "JWT jwt-2"


async def test_permission_error_is_not_retried(monkeypatch):
    rec = Recorder({"incident/4242/open/": lambda r: httpx.Response(403, json={"detail": "Insufficient rights"})})
    result = await _call(monkeypatch, rec, "ironscales_status", {})
    assert result["error"]["code"] == "unauthorized" and len(rec.token_requests) == 1


async def test_get_retries_5xx_but_writes_do_not():
    replies = iter([httpx.Response(502), httpx.Response(200, json={})])
    rec = Recorder({"GET settings/4242/allow-list/": lambda r: next(replies), "POST settings/4242/allow-list/": lambda r: httpx.Response(500)})
    client = _client(rec)
    await client.get("settings/4242/allow-list/")
    with pytest.raises(IronscalesError):
        await client.post("settings/4242/allow-list/", {})
    assert len(rec.calls("settings/4242/allow-list/", "GET")) == 2 and len(rec.calls("settings/4242/allow-list/", "POST")) == 1


# ---- status / incidents ----------------------------------------------------


async def test_status(monkeypatch):
    rec = Recorder({"incident/4242/open/": {"incident_ids": [1, 2, 3]}})
    result = await _call(monkeypatch, rec, "ironscales_status", {})
    assert result["connected"] is True and result["company_id"] == 4242 and result["open_incidents"] == 3


async def test_incidents_list_query_and_paging(monkeypatch):
    rec = Recorder({"incident/4242/list/": {"page": 3, "total_pages": 5, "total_count": 120, "incidents": [{"incidentID": 9}]}})
    args = {"status": "open", "classification": "phishing", "sender_email": "x@example.com", "limit": 25, "offset": 50}
    result = await _call(monkeypatch, rec, "ironscales_incidents_list", args)
    params = rec.requests[0].url.params
    assert (params["page"], params["items_per_page"], params["state"], params["classification"]) == ("3", "25", "unclassified", "phishing")
    assert params["search_sender_email"] == "x@example.com" and params["sort"] == "created" and params["order"] == "desc"
    assert result == {"incidents": [{"incidentID": 9}], "count": 1, "total": 120, "page": 3, "has_more": True, "next_offset": 75}


@pytest.mark.parametrize("status,state", [("closed", "classified"), ("pending", "challenged"), ("in_progress", "unclassified")])
async def test_incident_status_mapping(monkeypatch, status, state):
    rec = Recorder({"incident/4242/list/": {"incidents": []}})
    await _call(monkeypatch, rec, "ironscales_incidents_list", {"status": status})
    assert rec.requests[0].url.params["state"] == state


async def test_incident_get_trims_body(monkeypatch):
    record = {"incident_id": 9, "original_email_body": "<html>big</html>", "email_body_text": "x" * 5000}
    rec = Recorder({"incident/4242/details/9": record})
    result = await _call(monkeypatch, rec, "ironscales_incidents_get", {"incident_id": "#9"})
    assert "original_email_body" not in result and len(result["email_body_text"]) == 4000 and result["email_body_truncated"] is True


async def test_incident_id_must_be_numeric(monkeypatch):
    result = await _call(monkeypatch, Recorder(), "ironscales_incidents_get", {"incident_id": "abc"})
    assert result["error"]["code"] == "invalid_argument"


# ---- sender lookup ---------------------------------------------------------


async def test_email_classify_is_a_history_lookup(monkeypatch):
    incidents = [
        {"incidentID": 1, "classification": "Attack", "emailSubject": "Invoice due"},
        {"incidentID": 2, "classification": "Attack", "emailSubject": "Hello"},
        {"incidentID": 3, "classification": "False Positive", "emailSubject": "Invoice due again"},
    ]

    def allow(request):
        kind = request.url.params["type"]
        rows = [{"id": 7, "value": "example.com", "type": 2, "scope": 1}] if kind == "domain" else []
        return httpx.Response(200, json={"allow_list": rows})

    rec = Recorder({"incident/4242/list/": {"incidents": incidents}, "settings/4242/allow-list/": allow})
    result = await _call(monkeypatch, rec, "ironscales_email_classify", {"sender": "billing@example.com", "subject": "invoice", "body_text": "secret"})
    assert rec.calls("incident/4242/list/")[0].url.params["search_sender_email"] == "billing@example.com"
    assert result["verdict"] is None and result["past_incidents"] == 3
    assert result["classifications"] == {"Attack": 2, "False Positive": 1}
    assert result["same_subject_incidents"] == [1, 3]
    assert result["allow_list_entries"] == [{"id": 7, "value": "example.com", "type": 2, "scope": 1}]
    assert all("secret" not in str(r.url) for r in rec.requests)


# ---- remediation -----------------------------------------------------------


async def test_remediation_needs_confirm_and_maps_to_classification(monkeypatch):
    rec = Recorder({"incident/4242/details/9": {"classification": "Report", "sender_email": "bad@example.net", "affected_mailbox_count": 14}})
    args = {"incident_id": "9", "action": "quarantine", "classifying_user_email": "analyst@example.com"}
    preview = await _call(monkeypatch, rec, "ironscales_remediation_act", args)
    assert preview["done"] is False and "14 mailboxes" in preview["action"] and not rec.calls("incident/4242/classify/9")
    result = await _call(monkeypatch, rec, "ironscales_remediation_act", args | {"confirm": True})
    assert body(rec.calls("incident/4242/classify/9", "POST")[0]) == {
        "classification": "Attack",
        "prev_classification": "Report",
        "classifying_user_email": "analyst@example.com",
    }
    assert result["done"] is True and result["classification"] == "Attack"


@pytest.mark.parametrize(
    "current,expected",
    [("Attack", "Attack"), ("phishing", "Attack"), ("safe", "False Positive"), ("Spam", "Spam"), ("Close Phishing", "Close Phishing"), (None, "Report")],
)
def test_previous_classification(current, expected):
    from ironscales_mcp.tools.remediation import previous_classification

    assert previous_classification(current) == expected


async def test_remediation_needs_analyst_email(monkeypatch):
    rec = Recorder()
    result = await _call(monkeypatch, rec, "ironscales_remediation_act", {"incident_id": "9", "action": "mark_false_positive", "confirm": True})
    assert result["error"]["code"] == "invalid_argument" and "classifying_user_email" in result["error"]["message"]
    assert rec.requests == []


@pytest.mark.parametrize("action", ["block_sender", "report_to_microsoft"])
async def test_unsupported_remediations(monkeypatch, action):
    rec = Recorder()
    result = await _call(monkeypatch, rec, "ironscales_remediation_act", {"incident_id": "9", "action": action, "confirm": True})
    assert result["error"]["code"] == "invalid_argument" and rec.requests == [] and rec.token_requests == []


# ---- stats -----------------------------------------------------------------


@pytest.mark.parametrize("period,code", [("7d", "1"), ("90d", "2"), ("1y", "4"), ("24h", "0"), ("all", "6")])
async def test_stats_presets(monkeypatch, period, code):
    rec = Recorder({"mitigation/4242/stats/v2/": {"inspected_emails": {"inspected": 100}}})
    result = await _call(monkeypatch, rec, "ironscales_stats_company", {"period": period})
    assert rec.requests[0].url.params["period"] == code
    assert result["stats"] == {"inspected_emails": {"inspected": 100}}


async def test_stats_30_days_uses_date_range(monkeypatch):
    rec = Recorder({"mitigation/4242/stats/emails/": {"phishing": 4}, "incident/4242/stats/remediation-statuses/": {"resolved": 3}})
    result = await _call(monkeypatch, rec, "ironscales_stats_company", {})
    assert result["emails"] == {"phishing": 4} and result["remediation_statuses"] == {"resolved": 3}
    params = rec.calls("mitigation/4242/stats/emails/")[0].url.params
    assert "start_time" in params and "end_time" in params


# ---- allow list ------------------------------------------------------------


async def test_allowlist_list(monkeypatch):
    rows = [{"id": 1, "value": "example.com", "type": 2, "scope": 1}]
    rec = Recorder({"settings/4242/allow-list/": {"allow_list": rows, "pages_count": 2, "page": 1}})
    result = await _call(monkeypatch, rec, "ironscales_allowlist_manage", {"operation": "list", "entry_type": "domain", "value": "example"})
    params = rec.requests[0].url.params
    assert (params["type"], params["search"]) == ("domain", "example")
    assert result["entries"] == [{"id": 1, "value": "example.com", "type": "domain", "scope": "skip_all_inspections"}]
    assert result["has_more"] is True


async def test_allowlist_add(monkeypatch):
    rec = Recorder({"POST settings/4242/allow-list/": lambda r: httpx.Response(204)})
    args = {"operation": "add", "entry_type": "email", "value": " news@example.com ", "reason": "vendor newsletter", "scope": "spam_filter"}
    result = await _call(monkeypatch, rec, "ironscales_allowlist_manage", args)
    assert body(rec.requests[0]) == {"type": 3, "value": "news@example.com", "comment": "vendor newsletter", "scope": 4}
    assert result["done"] is True


async def test_allowlist_remove_by_exact_value(monkeypatch):
    rows = [{"id": 5, "value": "10.0.0.1"}, {"id": 6, "value": "10.0.0.10"}]
    rec = Recorder({"GET settings/4242/allow-list/": {"allow_list": rows}, "DELETE settings/4242/allow-list/": lambda r: httpx.Response(204)})
    result = await _call(monkeypatch, rec, "ironscales_allowlist_manage", {"operation": "remove", "entry_type": "ip", "value": "10.0.0.1"})
    assert body(rec.calls("settings/4242/allow-list/", "DELETE")[0]) == {"selected_ids": [5]}
    assert result["removed_ids"] == [5]


async def test_allowlist_remove_unknown_and_missing_args(monkeypatch):
    rec = Recorder({"GET settings/4242/allow-list/": {"allow_list": []}})
    unknown = await _call(monkeypatch, rec, "ironscales_allowlist_manage", {"operation": "remove", "entry_type": "ip", "value": "1.2.3.4"})
    assert unknown["error"]["code"] == "invalid_argument" and not rec.calls("settings/4242/allow-list/", "DELETE")
    missing = await _call(monkeypatch, rec, "ironscales_allowlist_manage", {"operation": "add"})
    assert missing["error"]["code"] == "invalid_argument"
