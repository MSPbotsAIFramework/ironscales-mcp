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
"""Allow list: senders, domains and IPs that skip some or all IRONSCALES inspections."""

from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import IronscalesClient
from ._common import WRITES, ClientFactory, compact, run_tool

EntryType = Literal["email", "domain", "ip", "link_domain"]
# Our entry type -> (list filter value, numeric type for new entries).
_TYPES = {"email": ("address", 3), "domain": ("domain", 2), "ip": ("ip", 1), "link_domain": ("link_domain", 4)}
_TYPE_NAMES = {1: "ip", 2: "domain", 3: "email", 4: "link_domain"}
_SCOPES = {1: "skip_all_inspections", 2: "bypass_impersonation_banners", 3: "bypass_link_clicking", 4: "spam_filter", 6: "bypass_link_scanning"}
Scope = Literal["skip_all_inspections", "bypass_impersonation_banners", "bypass_link_clicking", "spam_filter", "bypass_link_scanning"]


def _entry(row: dict) -> dict:
    out = dict(row)
    if isinstance(out.get("type"), int):
        out["type"] = _TYPE_NAMES.get(out["type"], out["type"])
    if isinstance(out.get("scope"), int):
        out["scope"] = _SCOPES.get(out["scope"], out["scope"])
    return out


async def _find(client: IronscalesClient, entry_type: str | None, value: str | None, page: int = 1, size: int = 100) -> dict:
    params = compact(
        {"type": _TYPES[entry_type][0] if entry_type else None, "search": value, "page": page, "items_per_page": size, "sort": "date", "order": "desc"}
    )
    payload = await client.get(f"settings/{client.company_id}/allow-list/", params)
    return payload if isinstance(payload, dict) else {}


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=WRITES)
    async def ironscales_allowlist_manage(
        operation: Annotated[Literal["add", "remove", "list"], Field(description="list (read), add or remove an entry.")],
        entry_type: Annotated[EntryType | None, Field(description="email = sender address, domain, ip (address or CIDR), link_domain.")] = None,
        value: Annotated[str | None, Field(description="The address, domain or IP. For list: text to search for.")] = None,
        reason: Annotated[str | None, Field(description="add: saved as the entry's comment.")] = None,
        scope: Annotated[Scope | None, Field(description="add: what the entry bypasses (IRONSCALES default when omitted).")] = None,
        expiration_date: Annotated[str | None, Field(description="add: YYYY-MM-DD after which the entry stops applying.")] = None,
        page: Annotated[int, Field(description="list: page number.", ge=1)] = 1,
    ) -> str:
        """List, add or remove allow-list entries. add / remove change filtering: only when explicitly asked.

        An allowed sender skips IRONSCALES inspections, so prefer the narrowest entry and scope.
        """

        async def action(client: IronscalesClient) -> Any:
            if operation == "list":
                payload = await _find(client, entry_type, value, page)
                entries = [_entry(e) for e in payload.get("allow_list") or [] if isinstance(e, dict)]
                pages = payload.get("pages_count") or 0
                return compact({"entries": entries, "count": len(entries), "page": page, "has_more": page < pages})
            if not entry_type or not value:
                raise ValueError(f"{operation} needs entry_type and value.")
            if operation == "add":
                scope_code = next((k for k, v in _SCOPES.items() if v == scope), None)
                body = compact(
                    {
                        "type": _TYPES[entry_type][1],
                        "value": value.strip(),
                        "comment": reason,
                        "scope": scope_code,
                        "expiration_date": expiration_date,
                    }
                )
                await client.post(f"settings/{client.company_id}/allow-list/", body)
                return {"done": True, "operation": "add", "entry_type": entry_type, "value": value.strip()}
            matches = [
                e
                for e in (await _find(client, entry_type, value.strip(), 1, 500)).get("allow_list") or []
                if isinstance(e, dict) and str(e.get("value") or "").lower() == value.strip().lower()
            ]
            if not matches:
                raise ValueError(f"No {entry_type} allow-list entry equals {value!r}; list entries to see the exact values.")
            ids = [e["id"] for e in matches]
            await client.delete(f"settings/{client.company_id}/allow-list/", {"selected_ids": ids})
            return {"done": True, "operation": "remove", "removed_ids": ids, "value": value.strip()}

        return await run_tool("ironscales_allowlist_manage", client_factory, action)
