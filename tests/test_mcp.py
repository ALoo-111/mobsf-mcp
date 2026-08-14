from __future__ import annotations

import pytest
from mcp import Client

from mobsf_mcp.server import mcp


@pytest.mark.asyncio
async def test_mcp_surface_is_registered() -> None:
    async with Client(mcp) as client:
        tool_result = await client.list_tools()
        template_result = await client.list_resource_templates()
    tool_names = {tool.name for tool in tool_result.tools}
    assert {"analyze_apk", "mobsf_upload", "mobsf_report", "mobsf_dynamic_analysis"} <= tool_names
    template_uris = {template.uri_template for template in template_result.resource_templates}
    assert "analysis://{scan_hash}/report" in template_uris
