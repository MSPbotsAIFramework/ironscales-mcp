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
"""Remediation: classifying an incident, which is how IRONSCALES acts on the emails."""

from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .._json import error_envelope
from ..api_client import IronscalesClient
from ._common import DESTRUCTIVE, ClientFactory, Confirm, IncidentId, incident_number, not_confirmed, run_tool

Action = Literal["quarantine", "delete", "mark_spam", "mark_false_positive", "block_sender", "report_to_microsoft"]
# Remediation action -> IRONSCALES classification. Classifying as an attack
# removes the email from every affected mailbox.
_CLASSIFY = {"quarantine": "Attack", "delete": "Attack", "mark_spam": "Spam", "mark_false_positive": "False Positive"}
_KNOWN = ("Attack", "False Positive", "Spam", "Close Phishing", "Report")
_UNSUPPORTED = {
    "block_sender": "Classifying the incident as phishing (action 'quarantine') blocks further emails like it; "
    "a sender block list is not available through the API.",
    "report_to_microsoft": "Reporting to Microsoft is not available through the IRONSCALES API.",
}


def previous_classification(value: Any) -> str:
    """Map an incident's current classification onto the values the classify call accepts."""
    text = str(value or "").strip()
    if text in _KNOWN:
        return text
    lower = text.lower()
    if "close" in lower:
        return "Close Phishing"
    if any(w in lower for w in ("attack", "phish", "malicious", "compromis")):
        return "Attack"
    if any(w in lower for w in ("false", "safe", "fp", "legit")):
        return "False Positive"
    if "spam" in lower:
        return "Spam"
    return "Report"


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=DESTRUCTIVE)
    async def ironscales_remediation_act(
        incident_id: IncidentId,
        action: Annotated[
            Action,
            Field(description="quarantine / delete = classify as phishing (removes the emails from mailboxes); mark_spam; mark_false_positive."),
        ],
        classifying_user_email: Annotated[
            str | None, Field(description="Email of the analyst the classification is recorded under (required by IRONSCALES).")
        ] = None,
        confirm: Confirm = None,
    ) -> str:
        """Act on an incident by classifying it (phishing, spam or false positive). Needs confirm: true.

        Phishing removes the email from every affected mailbox. Only when the user explicitly asks.
        """
        if action in _UNSUPPORTED:
            return error_envelope("invalid_argument", _UNSUPPORTED[action], False)

        async def action_fn(client: IronscalesClient) -> Any:
            number = incident_number(incident_id)
            if not classifying_user_email or "@" not in classifying_user_email:
                raise ValueError("Pass classifying_user_email: IRONSCALES records every classification under an analyst's email.")
            details = await client.get(f"incident/{client.company_id}/details/{number}")
            details = details if isinstance(details, dict) else {}
            previous = previous_classification(details.get("classification"))
            target = _CLASSIFY[action]
            mailboxes = details.get("affected_mailbox_count")
            if confirm is not True:
                return not_confirmed(
                    f"Classify incident {number} ({details.get('sender_email') or 'unknown sender'}, "
                    f"{mailboxes if mailboxes is not None else '?'} mailboxes) from {previous} to {target}"
                )
            body = {"classification": target, "prev_classification": previous, "classifying_user_email": classifying_user_email}
            result = await client.post(f"incident/{client.company_id}/classify/{number}", body)
            return {"done": True, "incident_id": number, "classification": target, "previous_classification": previous, "result": result}

        return await run_tool("ironscales_remediation_act", client_factory, action_fn)
