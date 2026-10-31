"""真实Chromium捕获与实际HTTP写回闭环；网络严格限受控回环服务器。"""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit, urlunsplit

import httpx
import pytest
from cryptography.fernet import Fernet
from playwright.async_api import async_playwright

import jst_connector.discovery_browser as discovery_module
import jst_connector.interface_registry as registry_module
from jst_connector.agent import create_app
from jst_connector.browser import BrowserManager
from jst_connector.discovery_browser import DiscoveryBrowser
from jst_connector.interface_registry import InterfaceRegistry
from jst_connector.service import ConnectorService
from jst_connector.vault import Vault

IDS = {"company_id": "101", "user_id": "201"}
RULES = {"success": [{"path": "/code", "equals": 0}], "required": [{"path": "/data", "type": "object"}], "data_path": "/data"}


@pytest.fixture
async def wire(tmp_path, monkeypatch):
    received = []
    state = {"id": "7", "note": "before", "status": "draft"}
    html = b'''<!doctype html><meta charset="utf-8"><body><h1>Controlled write fixture</h1>
    <button onclick="fetch('/GetDocument',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:'7',uid:999,coid:888,__ajax_token:'OLD-DUMMY'})})">Read</button>
    <button onclick="fetch('/SaveDocument',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({document_id:'7',note:'after',uid:999,coid:888,__ajax_token:'OLD-DUMMY'})})">Write JSON</button>
    <button onclick="fetch('/SaveDocument',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({document_id:'7',note:'after',uid:999,coid:888,__ajax_token:'OLD-DUMMY'})})">Write form</button></body>'''

    async def handler(reader, writer):
        raw = await reader.readuntil(b"\r\n\r\n")
        method, path, _ = raw.split(b"\r\n", 1)[0].split(b" ")
        length = next((int(line.split(b":", 1)[1]) for line in raw.split(b"\r\n") if line.lower().startswith(b"content-length:")), 0)
        body = await reader.readexactly(length) if length else b""
        content_type = next((line.split(b":", 1)[1].strip().decode() for line in raw.split(b"\r\n") if line.lower().startswith(b"content-type:")), "")
        parsed = json.loads(body) if body and "json" in content_type else {key: values[0] for key, values in parse_qs(body.decode()).items()}
        received.append({"method": method.decode(), "path": path.decode(), "body": parsed,
                         "cookie_present": b"\r\ncookie:" in raw.lower()})
        payload, kind = html, b"text/html"
        if path == b"/GetDocument":
            payload, kind = json.dumps({"code": 0, "data": state}).encode(), b"application/json"
        elif path == b"/SaveDocument":
            assert parsed["document_id"] == "7"
            state["note"] = parsed["note"]
            payload, kind = b'{"code":0,"data":{"id":"7"}}', b"application/json"
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: " + kind + b"\r\nContent-Length: " + str(len(payload)).encode()
                     + b"\r\nConnection: close\r\n\r\n" + payload)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    origin = "http://127.0.0.1:" + str(server.sockets[0].getsockname()[1])
    original_url = registry_module._url

    def local_url(value, *, entry=False):
        return value if isinstance(value, str) and value.startswith(origin + "/") else original_url(value, entry=entry)

    monkeypatch.setattr(registry_module, "_url", local_url)
    monkeypatch.setattr(registry_module, "_BUILTINS", {origin + "/entry.html"})
    monkeypatch.setattr(discovery_module, "_erp_url", lambda url: isinstance(url, str) and url.startswith(origin + "/"))
    monkeypatch.setattr(discovery_module, "_asset_url", lambda url: False)
    monkeypatch.setattr(discovery_module, "_NAVIGATION", {origin + "/entry.html"})
    monkeypatch.setattr(discovery_module, "_public_destination", AsyncMock())
    monkeypatch.setattr(discovery_module, "safe_url", lambda value: urlunsplit((*urlsplit(value)[:3], "", "")))
    vault = Vault(tmp_path, key=Fernet.generate_key())
    vault.save_session("codex", {"cookies": [{"name": "u_cid", "value": "CURRENT-DUMMY", "domain": "127.0.0.1",
                                               "path": "/", "expires": -1, "httpOnly": True, "secure": False, "sameSite": "Lax"}], "origins": []}, IDS)
    async with async_playwright() as playwright:
        chromium = await playwright.chromium.launch(headless=True)

        async def factory(storage):
            return await chromium.new_context(storage_state=storage, service_workers="block")

        async def verify(context):
            return dict(IDS)

        browser = BrowserManager(vault, context_factory=factory, identity_verifier=verify, idle_seconds=0)
        discovery = DiscoveryBrowser(browser)
        service = ConnectorService(tmp_path, vault=vault, browser=browser)
        service._discovery = discovery
        service._interfaces = InterfaceRegistry(tmp_path, vault, browser, discovery)
        try:
            yield SimpleNamespace(origin=origin, service=service, received=received, state=state)
        finally:
            await service.close()
            await chromium.close()
            server.close()
            await server.wait_closed()


def element(snapshot, label):
    return next(item["element_ref"] for frame in snapshot["frames"] for item in frame["elements"] if item.get("label") == label)


async def captured(discovery, identifier, suffix):
    for _ in range(100):
        snapshot = await discovery.inspect("codex", identifier, "requests")
        found = next((item for item in snapshot["requests"] if item["url"].endswith(suffix)), None)
        if found:
            return found["request_id"]
        await asyncio.sleep(0.02)
    raise AssertionError("受控请求未被捕获")


@pytest.mark.parametrize("encoding", ["JSON", "form"])
async def test_actual_capture_preview_browser_grant_http_write_readback_and_dedup(wire, encoding):
    service = wire.service
    source = wire.origin + "/entry.html"
    snapshot = (await service.start_discovery("codex", source))["discovery"]
    identifier = snapshot["discovery_id"]
    discovery = service._discovery
    await discovery.interact("codex", identifier, element(snapshot, "Read"), "click")
    read_id = await captured(discovery, identifier, "/GetDocument")
    snapshot = await discovery.inspect("codex", identifier)
    await discovery.interact("codex", identifier, element(snapshot, "Write " + encoding), "click")
    write_id = await captured(discovery, identifier, "/SaveDocument")
    assert not any(item["method"] == "POST" for item in wire.received)
    query = await service.propose_read_interface("codex", {
        "discovery_id": identifier, "request_id": read_id, "name": "精确回查", "purpose": "受控单据真实回查",
        "read_evidence": {"source_url": source, "description": "页面读取按钮查询单个对象"},
        "parameters": [{"name": "id", "path": "/body/id", "type": "string", "required": True}], "response_rules": RULES})
    read_interface = query["interface"]["interface_id"]
    await service.validate_read_interface("codex", read_interface, {"id": "7"})
    proposed = await service.propose_write_interface("codex", {
        "discovery_id": identifier, "request_id": write_id, "name": "受控写入", "purpose": "维护当前对象备注",
        "parameters": [{"name": "note", "path": "/body/note", "type": "string", "required": True}], "response_rules": RULES,
        "target": {"request_path": "/body/document_id", "read_interface_id": read_interface,
                   "read_parameters": {"id": "/body/document_id"}, "read_target_path": "/id"},
        "preconditions": [{"path": "/status", "equals": "draft"}], "expected": [{"path": "/note", "request_path": "/body/note"}]})
    preview = (await service.preview_write_interface("codex", proposed["interface"]["interface_id"], {"note": "after"}))["preview"]
    assert preview["payload"]["before"]["note"] == "before"
    assert not any(item["path"] == "/SaveDocument" for item in wire.received)
    opened = []
    app = create_app(service, opener=lambda url: opened.append(url) or True)
    token = service.vault.ensure_client("codex")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        data = {"preview_id": preview["preview_id"], "digest": preview["digest"]}
        result = await client.post("/api/open-confirmation", headers={"Authorization": "Bearer " + token}, json=data)
        assert result.status_code == 200 and "grant" not in result.text
        grant = parse_qs(urlsplit(opened[-1]).fragment)["grant"][0]
        approved = await client.post("/confirmation/approve", headers={"Authorization": "Bearer " + grant}, json={"digest": preview["digest"]})
        assert approved.status_code == 200
        executed = await client.post("/api/execute", headers={"Authorization": "Bearer " + token}, json=data)
        assert executed.status_code == 200 and executed.json()["ok"], executed.text
        repeat = await client.post("/api/execute", headers={"Authorization": "Bearer " + token}, json=data)
        assert repeat.json()["ok"]
    writes = [item for item in wire.received if item["path"] == "/SaveDocument"]
    assert len(writes) == 1 and wire.state["note"] == "after"
    assert str(writes[0]["body"]["uid"]) == "201" and str(writes[0]["body"]["coid"]) == "101"
    assert writes[0]["body"]["__ajax_token"] == "1.CURRENT-DUMMY-" and writes[0]["cookie_present"]
    assert "OLD-DUMMY" not in json.dumps(preview) and "CURRENT-DUMMY" not in json.dumps(preview)
