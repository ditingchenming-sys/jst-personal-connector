"""组合真实浏览器、管理授权、通用契约和保存复用；只访问受控回环服务器。"""
import asyncio
import json
import time
from urllib.parse import urlsplit, urlunsplit

import httpx
import pytest
import test_discovery_browser as browser_fixtures
from test_discovery_browser import captured, element

import jst_connector.discovery_browser as discovery_module
import jst_connector.interface_registry as registry_module
from jst_connector.agent import create_app
from jst_connector.interface_registry import InterfaceRegistry
from jst_connector.service import ConnectorService

engine = browser_fixtures.engine


@pytest.mark.asyncio
async def test_unknown_page_query_connected_read_trial_and_reuse_without_discovery_memory(engine, monkeypatch):
    origin = engine.origin
    original_url = registry_module._url

    def local_only(value, *, entry=False):
        if isinstance(value, str) and value.startswith(origin + "/"):
            return value
        return original_url(value, entry=entry)

    monkeypatch.setattr(registry_module, "_url", local_only)
    # Production origins have no ports; retain the random loopback port only in this controlled fixture.
    def local_safe_url(value):
        parts = urlsplit(value)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    monkeypatch.setattr(discovery_module, "safe_url", local_safe_url)
    entry_url = origin + "/entry.html"
    monkeypatch.setattr(registry_module, "_BUILTINS", {entry_url})
    service = ConnectorService(engine.root, vault=engine.vault, browser=engine.browser)
    service._discovery = engine.discovery
    service._interfaces = InterfaceRegistry(engine.root, engine.vault, engine.browser, engine.discovery)
    token = engine.vault.ensure_client("codex")
    client_headers = {"Authorization": "Bearer " + token}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(service)), base_url="http://testserver") as client:
        start = await client.post("/api/discovery-start", headers=client_headers, json={"url": entry_url})
        assert start.status_code == 200
        snapshot = start.json()["discovery"]
        discovery_id = snapshot["discovery_id"]
        filled = await client.post("/api/discovery-interact", headers=client_headers, json={
            "discovery_id": discovery_id, "element_ref": element(snapshot, "SKU filter"), "action": "fill", "value": "FIRST"})
        snapshot = filled.json()["discovery"]
        clicked = await client.post("/api/discovery-interact", headers=client_headers, json={
            "discovery_id": discovery_id, "element_ref": element(snapshot, "Query"), "action": "click"})
        assert clicked.status_code == 200
        deadline = time.monotonic() + 3
        query_request = None
        while time.monotonic() < deadline:
            observed = await captured(engine, discovery_id)
            query_request = next((item for item in observed["requests"]
                                  if item["method"] == "POST" and item["url"].endswith("/query")), None)
            if query_request:
                break
            await asyncio.sleep(0.02)
        assert query_request is not None
        assert not any(item["method"] == "POST" for item in engine.received)
        draft_request = {"discovery_id": discovery_id, "request_id": query_request["request_id"],
                         "name": "Local query", "purpose": "Read fixture SKU records",
                         "read_evidence": {"source_url": entry_url, "description": "Page query button issues the list request"},
                         "parameters": [{"name": "sku", "path": "/body/sku", "type": "string", "required": True}],
                         "response_rules": {"success": [], "required": [{"path": "/records", "type": "array"}], "data_path": "/records"}}
        proposed = await client.post("/api/interface-propose", headers=client_headers, json=draft_request)
        assert proposed.status_code == 200, proposed.text
        record = proposed.json()["interface"]
        assert record["status"] == "ready_for_validation"
        args = {"interface_id": record["interface_id"], "parameters": {"sku": "FIRST"}}
        denied = await client.post("/api/interface-call", headers=client_headers, json=args)
        assert denied.status_code == 409
        approval = {"profile": "codex", "interface_id": record["interface_id"], "digest": record["digest"]}
        assert (await client.post("/manage/interface-approve", headers=client_headers, json=approval)).status_code == 401
        assert (await client.post("/api/interface-approve", headers=client_headers, json=approval)).status_code == 409
        assert not any(item["method"] == "POST" for item in engine.received)
        trial = await client.post("/api/interface-validate", headers=client_headers, json=args)
        assert trial.status_code == 200, trial.text
        assert trial.json()["result"]["data"] == [{"sku": "DUMMY-SKU"}]
        await engine.discovery.close()
        service._interfaces = InterfaceRegistry(engine.root, engine.vault, engine.browser, engine.discovery)
        reused = await client.post("/api/interface-call", headers=client_headers, json={
            "interface_id": record["interface_id"], "parameters": {"sku": "SECOND"}})
        assert reused.status_code == 200, reused.text
        assert reused.json()["result"]["complete"] is None
        catalog = await client.post("/api/catalog", headers=client_headers, json={"query": "Local"})
        assert catalog.status_code == 200 and len(catalog.json()["saved_interfaces"]) == 1
        posts = [json.loads(item["body"]) for item in engine.received if item["method"] == "POST"]
        assert [item["sku"] for item in posts] == ["FIRST", "SECOND"]
        assert all(item["uid"] == 201 and item["coid"] == 101 for item in posts)
        assert all(item["__ajax_token"] == "1.CURRENT-ONLY-DUMMY-" for item in posts)
        assert "OLD-NEVER-PERSIST" not in json.dumps(record)
