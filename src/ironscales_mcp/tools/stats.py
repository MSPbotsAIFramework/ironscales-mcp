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
"""Company mitigation statistics."""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..api_client import IronscalesClient
from ._common import READ_ONLY, ClientFactory, run_tool

Period = Literal["24h", "7d", "30d", "90d", "180d", "1y", "ytd", "all"]
# IRONSCALES period codes for the preset statistics.
_PERIOD_CODE = {"24h": 0, "7d": 1, "90d": 2, "180d": 3, "1y": 4, "ytd": 5, "all": 6}


def register(mcp: FastMCP, client_factory: ClientFactory) -> None:
    @mcp.tool(annotations=READ_ONLY)
    async def ironscales_stats_company(
        period: Annotated[Period, Field(description="Time window (1y = last 360 days, ytd = this year).")] = "30d",
    ) -> str:
        """Company mitigation stats: emails inspected, phishing / spam found, incidents resolved, time saved."""

        async def action(client: IronscalesClient) -> dict:
            company = client.company_id
            if period in _PERIOD_CODE:
                stats = await client.get(f"mitigation/{company}/stats/v2/", {"period": _PERIOD_CODE[period]})
                return {"company_id": company, "period": period, "stats": stats}
            # No preset covers 30 days: use the date-range statistics instead.
            end = datetime.now(UTC)
            window = {"start_time": (end - timedelta(days=30)).isoformat(), "end_time": end.isoformat()}
            emails = await client.get(f"mitigation/{company}/stats/emails/", window)
            remediation = await client.get(f"incident/{company}/stats/remediation-statuses/", window)
            return {"company_id": company, "period": period, "window": window, "emails": emails, "remediation_statuses": remediation}

        return await run_tool("ironscales_stats_company", client_factory, action)
