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
"""Tool discovery (kept for compatibility: every tool is always listed) and the connection check."""

from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .._json import compact as to_json
from ..api_client import IronscalesClient
from ._common import LOCAL, READ_ONLY, ClientFactory, run_tool

DOMAINS: dict[str, tuple[str, list[str]]] = {
    "incidents": ("Reported phishing incidents: list and details.", ["ironscales_incidents_list", "ironscales_incidents_get"]),
    "email": ("What IRONSCALES already knows about a sender.", ["ironscales_email_classify"]),
    "remediation": ("Classify an incident (phishing removes the emails from mailboxes).", ["ironscales_remediation_act"]),
    "stats": ("Company mitigation statistics.", ["ironscales_stats_company"]),
    "allowlist": ("Allow-list entries: list, add, remove.", ["ironscales_allowlist_manage"]),
}

Domain = Literal["incidents", "email", "remediation", "stats", "allowlist"]


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=LOCAL)
    async def ironscales_navigate(domain: Annotated[Domain, Field(description="Area to describe.")]) -> str:
        """Describe the tools of one IRONSCALES area. All tools are already callable; this changes nothing."""
        summary, tools = DOMAINS[domain]
        return to_json({"domain": domain, "summary": summary, "tools": tools})

    @mcp.tool(annotations=LOCAL)
    async def ironscales_back() -> str:
        """Kept for compatibility: there is no navigation state, every tool is always available."""
        return to_json({"domains": list(DOMAINS), "message": "All tools are listed; call any of them directly."})

    @mcp.tool(annotations=READ_ONLY)
    async def ironscales_status() -> str:
        """Check the IRONSCALES connection: company id and how many incidents are open."""

        async def action(client: IronscalesClient) -> dict:
            payload = await client.get(f"incident/{client.company_id}/open/")
            ids = payload.get("incident_ids") if isinstance(payload, dict) else payload
            return {
                "connected": True,
                "company_id": client.company_id,
                "open_incidents": len(ids) if isinstance(ids, list) else None,
                "domains": list(DOMAINS),
            }

        return await run_tool("ironscales_status", client_factory, action)
