"""真实stdio验证通用工具的对象契约，不访问ERP或本人的运行资料。"""
import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def test_stdio_read_interface_evidence_is_an_object_and_no_self_approval(tmp_path):
    entry = tmp_path / "controlled_server.py"
    entry.write_text('''from pathlib import Path
from jst_connector.mcp_server import create_server
class ControlledClient:
    def call(self, action, body=None):
        return {"ok": True, "action": action, "body": body}
create_server(Path("."), "codex", client=ControlledClient()).run(transport="stdio")
''', encoding="utf-8")

    async def scenario():
        params = StdioServerParameters(command=sys.executable, args=[str(entry)], cwd=str(Path.cwd()),
                                       env={**os.environ, "PYTHONPATH": str(Path.cwd() / "src")})
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            tools = {tool.name: tool for tool in (await session.list_tools()).tools}
            assert len(tools) == 15
            assert tools["propose_read_interface"].inputSchema["properties"]["read_evidence"]["type"] == "object"
            assert not any("approve" in name for name in tools)
            body = {"discovery_id": "fixture-discovery", "request_id": "fixture-request", "name": "fixture-query",
                    "purpose": "Read fixture records", "read_evidence": {
                        "source_url": "https://www.erp321.com/epaas", "description": "Official search request"},
                    "parameters": [], "response_rules": {
                        "success": [{"path": "/code", "equals": 0}],
                        "required": [{"path": "/data", "type": "array"}], "data_path": "/data"}}
            result = await session.call_tool("propose_read_interface", body)
            value = result.structuredContent or json.loads(result.content[0].text)
            assert value["action"] == "interface-propose" and value["body"] == body
            invalid = await session.call_tool("propose_read_interface", {**body, "read_evidence": "not-an-object"})
            assert invalid.isError

    asyncio.run(scenario())
