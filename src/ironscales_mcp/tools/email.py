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
"""Sender lookup: what IRONSCALES has already seen and decided about a sender."""

from collections import Counter
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from ..api_client import IronscalesClient
from ._common import READ_ONLY, ClientFactory, run_tool

_LOOKBACK = 100


class Attachment(BaseModel):
    filename: str | None = None
    content_type: str | None = None
    size_bytes: float | None = None


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().lower() if "@" in address else address.strip().lower()


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def ironscales_email_classify(
        sender: Annotated[str, Field(description="Sender email address.", min_length=3)],
        subject: Annotated[str | None, Field(description="Subject, to find incidents about the same email.")] = None,
        sender_display_name: Annotated[str | None, Field(description="Not sent to IRONSCALES.")] = None,
        reply_to: Annotated[str | None, Field(description="Reply-To address; also checked against the allow list.")] = None,
        body_text: Annotated[str | None, Field(description="Not sent to IRONSCALES.")] = None,
        body_html: Annotated[str | None, Field(description="Not sent to IRONSCALES.")] = None,
        headers: Annotated[dict[str, Any] | None, Field(description="Not sent to IRONSCALES.")] = None,
        urls: Annotated[list[str] | None, Field(description="Not sent to IRONSCALES.")] = None,
        attachments: Annotated[list[Attachment] | None, Field(description="Not sent to IRONSCALES.")] = None,
    ) -> str:
        """Look up a sender: past incidents from it, how they were classified, and allow-list entries.

        IRONSCALES has no API to scan an arbitrary email, so this returns history, not a verdict on new content.
        """

        async def action(client: IronscalesClient) -> dict:
            company = client.company_id
            params: dict[str, Any] = {"search_sender_email": sender, "items_per_page": _LOOKBACK, "sort": "created", "order": "desc"}
            payload = await client.get(f"incident/{company}/list/", params)
            incidents = (payload.get("incidents") if isinstance(payload, dict) else None) or []
            counts = Counter(str(i.get("classification") or "unknown") for i in incidents)
            same_subject = [i for i in incidents if subject and subject.strip().lower() in str(i.get("emailSubject") or "").lower()]
            allowed = []
            for value, kind in ((sender, "address"), (_domain(sender), "domain"), (reply_to, "address")):
                if not value:
                    continue
                entries = await client.get(f"settings/{company}/allow-list/", {"type": kind, "search": value, "items_per_page": 20})
                for e in (entries.get("allow_list") if isinstance(entries, dict) else None) or []:
                    if str(e.get("value") or "").lower() == value.strip().lower():
                        allowed.append({k: e.get(k) for k in ("id", "value", "type", "scope", "comment", "expiration_date") if e.get(k) is not None})
            return {
                "sender": sender,
                "verdict": None,
                "note": "History only: IRONSCALES cannot scan this email through its API.",
                "past_incidents": len(incidents),
                "classifications": dict(counts),
                "latest_incidents": incidents[:10],
                "same_subject_incidents": [i.get("incidentID") for i in same_subject],
                "allow_list_entries": allowed,
            }

        return await run_tool("ironscales_email_classify", client_factory, action)
