"""实际 MCP stdio 子进程和本机组件连通，禁止触达真实 ERP。"""
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
from cryptography.fernet import Fernet
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def test_real_mcp_stdio_handshake_catalog_and_disconnected_status(tmp_path):
    env = {**os.environ, "JST_CONNECTOR_MASTER_KEY": Fernet.generate_key().decode(), "PYTHONUTF8": "1"}
    args = [sys.executable, "-m", "jst_connector"]
    server = subprocess.Popen(args + ["serve", "--data-dir", str(tmp_path)], env=env,
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        state = tmp_path / "agent.json"
        for _ in range(200):
            if server.poll() is not None:
                raise AssertionError("受控本机组件未能启动")
            if state.exists():
                url = json.loads(state.read_text(encoding="utf-8"))["url"]
                try:
                    if httpx.get(url + "/health", timeout=0.3, trust_env=False).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
            time.sleep(0.05)
        else:
            raise AssertionError("受控本机组件启动超时")

        duplicate = subprocess.run(args + ["serve", "--data-dir", str(tmp_path)], env=env,
                                   capture_output=True, text=True, encoding="utf-8", timeout=10, check=False)
        assert duplicate.returncode == 1
        assert "agent_already_running" in duplicate.stderr
        assert "Traceback" not in duplicate.stderr

        async def scenario():
            params = StdioServerParameters(command=sys.executable,
                args=["-m", "jst_connector", "mcp", "--client", "codex", "--data-dir", str(tmp_path)], env=env,
                cwd=str(Path(__file__).resolve().parents[1]))
            async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
                initialized = await session.initialize()
                assert initialized.serverInfo.name == "聚水潭个人连接器"
                names = {tool.name for tool in (await session.list_tools()).tools}
                assert {"connector_status", "search_capabilities", "query_erp", "execute_confirmed_operation"} <= names
                assert not any(name in names for name in ("approve", "set_identity", "set_cookie", "http_request"))
                catalog = await session.call_tool("search_capabilities", {"query": ""})
                value = catalog.structuredContent or json.loads(catalog.content[0].text)
                assert len(value["capabilities"]) == 21
                status = await session.call_tool("connector_status", {})
                value = status.structuredContent or json.loads(status.content[0].text)
                assert value["connection"]["status"] == "disconnected"
                denied = await session.call_tool("query_erp", {"capability_id": "Q02", "parameters": {"i_id": "fixture"}})
                value = denied.structuredContent or json.loads(denied.content[0].text)
                assert value["ok"] is False
        asyncio.run(scenario())
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
