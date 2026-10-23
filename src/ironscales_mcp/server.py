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
"""FastMCP factory and the per-request credential middleware."""

import contextvars
import re
import uuid
from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ._arguments import EnvelopeFastMCP
from .api_client import IronscalesClient, IronscalesCredentials
from .config import Settings

HEADER_API_KEY = "X-Ironscales-API-Key"
HEADER_COMPANY_ID = "X-Ironscales-Company-ID"
HEADER_SCOPES = "X-Ironscales-Scopes"  # optional
REQUIRED_HEADERS = [HEADER_API_KEY, HEADER_COMPANY_ID]

_PLACEHOLDER = re.compile(r"^\$\{.*\}$")
_SCOPE = re.compile(r"^[a-z_]+(\.[a-z_]+)+$")

# Per-request isolation: the middleware sets these for the duration of one
# HTTP request and resets them in `finally`. The token cache is keyed by a
# hash of the API key, never by anything a caller could share.
_credentials_var: contextvars.ContextVar[IronscalesCredentials | None] = contextvars.ContextVar(
    "ironscales_credentials", default=None
)
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("ironscales_request_id", default="-")

INSTRUCTIONS = (
    "IRONSCALES is an email security platform: employees and its AI report "
    "suspicious emails, which become incidents (clusters of similar emails "
    "across mailboxes) that an analyst classifies as phishing, spam or safe; "
    "classifying phishing removes the emails from every affected mailbox.\n"
    "Usage:\n"
    "- Triage: ironscales_incidents_list(status='open') -> ironscales_incidents_get.\n"
    "- Is a sender known: ironscales_email_classify(sender=...) looks up past "
    "incidents and allow-list entries; it does not scan the email.\n"
    "- Posture: ironscales_stats_company(period).\n"
    "- Allow list: ironscales_allowlist_manage(operation='list'|'add'|'remove').\n"
    "ironscales_remediation_act changes mailboxes (needs confirm: true after "
    "the user approved that exact action, and the analyst's email). Adding or "
    "removing allow-list entries changes filtering: only when the user "
    "explicitly asks. The API allows 120 calls per minute per company."
)


def get_client_from_context() -> IronscalesClient | None:
    """The client for the current request, or None outside a request."""
    credentials = _credentials_var.get()
    if credentials is None:
        return None
    return IronscalesClient(credentials)


def _clean(value: str | None) -> str | None:
    text = (value or "").strip()
    if not text or _PLACEHOLDER.match(text):
        return None
    return text


def parse_scopes(value: str | None) -> tuple[str, ...] | None:
    """'company.view, company.classify' -> ('company.view', 'company.classify'); None when empty."""
    items = tuple(dict.fromkeys(s.strip().lower() for s in (value or "").replace(";", ",").split(",") if s.strip()))
    return items or None


def _error(scope: Scope, receive: Receive, send: Send, status: int, error: str, message: str):
    return JSONResponse({"error": error, "message": message, "required_headers": REQUIRED_HEADERS}, status_code=status)(
        scope, receive, send
    )


class GatewayCredentialsMiddleware:
    """Reads the IRONSCALES API key and company id on /mcp requests into the request context.

    Missing required headers -> 401 listing them. A malformed company id or scope list
    does not block the request (tools/list must work with any values); tools report it instead.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        api_key = _clean(request.headers.get(HEADER_API_KEY))
        company = _clean(request.headers.get(HEADER_COMPANY_ID))
        if not (api_key and company):
            missing = [h for h, v in ((HEADER_API_KEY, api_key), (HEADER_COMPANY_ID, company)) if not v]
            await _error(scope, receive, send, 401, "Missing credentials", f"Missing header(s): {', '.join(missing)}")
            return
        errors = []
        company_id = int(company) if company.isdigit() else 0
        if company_id < 1:
            errors.append(f"{HEADER_COMPANY_ID} must be the numeric company id")
        scopes = parse_scopes(_clean(request.headers.get(HEADER_SCOPES)))
        if scopes and not all(_SCOPE.match(s) for s in scopes):
            errors.append(f"{HEADER_SCOPES} must list scopes like company.all")
            scopes = None
        header_error = "; ".join(errors) or None

        request_id = (request.headers.get("x-request-id") or "").strip()[:64] or uuid.uuid4().hex[:12]
        creds_token = _credentials_var.set(IronscalesCredentials(api_key, company_id, scopes, header_error))
        rid_token = request_id_var.set(request_id)
        try:
            await self.app(scope, receive, send)
        finally:
            _credentials_var.reset(creds_token)
            request_id_var.reset(rid_token)


def create_mcp_server(settings: Settings | None = None) -> FastMCP:
    """Build the FastMCP server and register every tool."""
    mcp = EnvelopeFastMCP(
        name="ironscales-mcp",
        instructions=INSTRUCTIONS,
        # The service sits behind the gateway, so Host is never localhost;
        # DNS-rebinding protection would reject those requests with 421.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
    )

    client_factory: Callable[[], IronscalesClient | None] = get_client_from_context

    from .tools import allowlist, email, incidents, navigation, remediation, stats

    for module in (navigation, incidents, email, remediation, stats, allowlist):
        module.register(mcp, client_factory)

    return mcp
