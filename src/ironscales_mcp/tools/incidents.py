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
"""Incidents: reported suspicious emails, clustered across mailboxes."""

from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import IronscalesClient
from ..config import DEFAULT_LIMIT, MAX_LIMIT
from ._common import READ_ONLY, ClientFactory, IncidentId, compact, incident_number, run_tool

Status = Literal["open", "closed", "in_progress", "pending"]
Classification = Literal["phishing", "spam", "compromised", "safe", "open", "silent"]
# Older status words -> IRONSCALES incident state.
_STATE = {"open": "unclassified", "in_progress": "unclassified", "closed": "classified", "pending": "challenged"}
_BODY_CHARS = 4000


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def ironscales_incidents_list(
        status: Annotated[
            Status | None,
            Field(description="open / in_progress = not yet classified, closed = classified, pending = challenged (release request or user report)."),
        ] = None,
        classification: Annotated[Classification | None, Field(description="Only incidents with this classification.")] = None,
        sender_email: Annotated[str | None, Field(description="Sender email contains this text.")] = None,
        recipient_email: Annotated[str | None, Field(description="Recipient email contains this text.")] = None,
        subject: Annotated[str | None, Field(description="Email subject contains this text.")] = None,
        created_after: Annotated[str | None, Field(description="ISO 8601: created on or after.")] = None,
        created_before: Annotated[str | None, Field(description="ISO 8601: created on or before.")] = None,
        limit: Annotated[int | None, Field(description=f"Incidents per page (default {DEFAULT_LIMIT}, max {MAX_LIMIT}).", ge=1, le=MAX_LIMIT)] = None,
        offset: Annotated[int | None, Field(description="Incidents to skip; rounded down to a whole page.", ge=0)] = None,
    ) -> str:
        """List incidents, newest first: subject, sender, recipient, classification, mailbox count, dates."""

        async def action(client: IronscalesClient) -> dict:
            size = limit or DEFAULT_LIMIT
            page = (offset or 0) // size + 1
            params = compact(
                {
                    "page": page,
                    "items_per_page": size,
                    "sort": "created",
                    "order": "desc",
                    "state": _STATE[status] if status else None,
                    "classification": classification,
                    "search_sender_email": sender_email,
                    "search_recipient_email": recipient_email,
                    "search_email_subject": subject,
                    "created_start_time": created_after,
                    "created_end_time": created_before,
                }
            )
            payload = await client.get(f"incident/{client.company_id}/list/", params)
            payload = payload if isinstance(payload, dict) else {}
            incidents = payload.get("incidents") or []
            total_pages = payload.get("total_pages") or 0
            return compact(
                {
                    "incidents": incidents,
                    "count": len(incidents),
                    "total": payload.get("total_count"),
                    "page": page,
                    "has_more": page < total_pages,
                    "next_offset": page * size if page < total_pages else None,
                }
            )

        return await run_tool("ironscales_incidents_list", client_factory, action)

    @mcp.tool(annotations=READ_ONLY)
    async def ironscales_incidents_get(incident_id: IncidentId) -> str:
        """Get one incident: classification, sender reputation, SPF, links, attachments, affected mailboxes."""

        async def action(client: IronscalesClient) -> Any:
            record = await client.get(f"incident/{client.company_id}/details/{incident_number(incident_id)}")
            if not isinstance(record, dict):
                return record
            out = {k: v for k, v in record.items() if k != "original_email_body"}
            text = out.get("email_body_text")
            if isinstance(text, str) and len(text) > _BODY_CHARS:
                out["email_body_text"] = text[:_BODY_CHARS]
                out["email_body_truncated"] = True
            return out

        return await run_tool("ironscales_incidents_get", client_factory, action)
