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
"""tools/list snapshot, annotations and error-envelope mapping. No network access."""

import asyncio
import json

import pytest

from ironscales_mcp.api_client import IronscalesError
from ironscales_mcp.server import INSTRUCTIONS, create_mcp_server
from ironscales_mcp.tools.navigation import DOMAINS

# Tool names are a public contract: existing agents and tenant connections
# depend on them. Changing this snapshot is a breaking change.
EXPECTED_TOOLS: dict[str, set[str]] = {
    "ironscales_navigate": {"domain"},
    "ironscales_back": set(),
    "ironscales_status": set(),
    "ironscales_incidents_list": set(),
    "ironscales_incidents_get": {"incident_id"},
    "ironscales_email_classify": {"sender"},
    "ironscales_remediation_act": {"incident_id", "action"},
    "ironscales_stats_company": set(),
    "ironscales_allowlist_manage": {"operation"},
}
LOCAL_TOOLS = {"ironscales_navigate", "ironscales_back"}
WRITE_TOOLS = {"ironscales_remediation_act", "ironscales_allowlist_manage"}


@pytest.fixture(scope="module")
def tools():
    return {t.name: t for t in asyncio.run(create_mcp_server().list_tools())}


def test_tool_names_are_stable(tools):
    assert set(tools) == set(EXPECTED_TOOLS)


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_required_params(tools, name):
    assert set(tools[name].inputSchema.get("required", [])) == EXPECTED_TOOLS[name]


def test_enums_keep_the_old_values(tools):
    remediation = tools["ironscales_remediation_act"].inputSchema["properties"]["action"]["enum"]
    assert {"quarantine", "delete", "block_sender", "mark_false_positive", "report_to_microsoft"} <= set(remediation)
    period = tools["ironscales_stats_company"].inputSchema["properties"]["period"]["enum"]
    assert {"7d", "30d", "90d", "1y"} <= set(period)
    status = tools["ironscales_incidents_list"].inputSchema["properties"]["status"]["anyOf"][0]["enum"]
    assert set(status) == {"open", "closed", "in_progress", "pending"}


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_description_budget(tools, name):
    description = (tools[name].description or "").strip()
    assert description, f"{name} has no description"
    assert len(description) <= 500
    assert len(description.splitlines()[0]) <= 100


@pytest.mark.parametrize("name", sorted(EXPECTED_TOOLS))
def test_annotations_match_side_effects(tools, name):
    annotations = tools[name].annotations
    assert annotations is not None
    assert annotations.readOnlyHint is (name not in WRITE_TOOLS)
    assert bool(annotations.destructiveHint) is (name == "ironscales_remediation_act")
    assert (annotations.openWorldHint is False) is (name in LOCAL_TOOLS)


@pytest.mark.parametrize("name", sorted(WRITE_TOOLS))
def test_write_tools_say_when_to_use_them(tools, name):
    assert "explicitly ask" in tools[name].description


def test_remediation_takes_confirm(tools):
    assert "confirm" in tools["ironscales_remediation_act"].inputSchema["properties"]


def test_navigate_lists_every_tool():
    listed = {tool for _, names in DOMAINS.values() for tool in names}
    assert listed | {"ironscales_navigate", "ironscales_back", "ironscales_status"} == set(EXPECTED_TOOLS)


def test_instructions_budget():
    assert len(INSTRUCTIONS) <= 1500
    assert "\n" in INSTRUCTIONS


@pytest.mark.parametrize(
    "status,code,retryable",
    [
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (404, "not_found", False),
        (400, "invalid_argument", False),
        (429, "rate_limited", True),
        (500, "upstream_error", True),
        (0, "upstream_error", True),
    ],
)
def test_error_envelope(status, code, retryable):
    envelope = json.loads(IronscalesError(status, "boom").to_envelope())
    assert envelope == {"error": {"code": code, "message": "boom", "retryable": retryable}}


def test_tool_without_credentials_returns_not_configured():
    content, _ = asyncio.run(create_mcp_server().call_tool("ironscales_incidents_list", {}))
    assert json.loads(content[0].text)["error"]["code"] == "not_configured"
