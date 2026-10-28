"""探索引擎：真实Chromium仅访问回环HTTP，生产域测试只做纯规则判断。"""
import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet
from playwright.async_api import async_playwright

import jst_connector.discovery_browser as discovery_module
from jst_connector.browser import BrowserManager
from jst_connector.discovery_browser import (
    DiscoveryBrowser,
    _asset_url,
    _erp_url,
    _page_url,
    _public_destination,
)
from jst_connector.errors import ConnectorError
from jst_connector.vault import Vault

IDS = {"company_id": "101", "user_id": "201"}


@pytest.mark.parametrize("url", ["http://www.erp321.com/epaas", "https://127.0.0.1/a.aspx", "https://www.erp321.com.evil.test/a.aspx",
    "https://user:pass@www.erp321.com/a.aspx", "https://www.erp321.com:443/a.aspx", "https://www.erp321.com/a.aspx#frag",
    "https://www.erp321.com/a/%2e%2e/write.aspx", "https://www.erp321.com/a/../write.aspx", "https://www.erp321.com\\evil.test/a.aspx"])
def test_host_tricks_and_private_or_ambiguous_urls_are_rejected(url):
    assert not _erp_url(url)


def test_page_and_public_asset_boundaries():
    assert _page_url("https://www.erp321.com/epaas")
    assert not _page_url("https://www.erp321.com/a.aspx?action=delete")
    assert not _page_url("https://www.erp321.com/Logout.aspx")
    assert not _page_url("https://www.erp321.com/DeleteOrder.aspx")
    assert not _page_url("https://www.erp321.com/deleteorder.aspx")
    assert not _page_url("https://www.erp321.com/DELETEORDER.aspx")
    assert not _page_url("https://www.erp321.com/account/Update.aspx")
    assert not _asset_url("https://api.erp321.com/business/Delete.png")
    assert not _asset_url("https://src.erp321.com/x.js?token=PRIVATE")
    assert _asset_url("https://cdn-static.erp321.cn/cdn/react/17/react.js")
    assert not _asset_url("https://cdn-static.erp321.cn/business/x.js")


@pytest.mark.asyncio
async def test_dns_private_address_is_rejected_without_connecting(monkeypatch):
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", AsyncMock(return_value=[(None, None, None, None, ("127.0.0.1", 443))]))
    with pytest.raises(ConnectorError):
        await _public_destination("https://www.erp321.com/a.aspx")


@pytest.mark.asyncio
@pytest.mark.parametrize(("addresses", "expected"), [
    (["8.8.8.8"], "public"), (["198.18.0.1"], "synthetic_proxy"),
    (["198.19.255.254", "8.8.8.8"], "synthetic_proxy"),
    (["198.18.0.1", "10.0.0.1"], None), (["127.0.0.1"], None), (["169.254.169.254"], None),
    (["172.16.1.1"], None), (["192.168.1.1"], None), (["::1"], None),
    (["fc00::1"], None), (["fe80::1"], None), ([], None),
])
async def test_fixed_official_dns_allows_only_public_or_synthetic_proxy_answers(monkeypatch, addresses, expected):
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", AsyncMock(return_value=[
        (None, None, None, None, (address, 443)) for address in addresses]))
    if expected:
        assert await _public_destination("https://www.erp321.com/epaas") == expected
    else:
        with pytest.raises(ConnectorError) as error:
            await _public_destination("https://www.erp321.com/epaas")
        assert error.value.details == {"stage": "dns_policy", "dns_policy": "rejected_address"}
        assert all(address not in json.dumps(error.value.as_dict()) for address in addresses)


@pytest.mark.asyncio
@pytest.mark.parametrize("url", ["https://unknown.example/a.js", "https://localhost/a.aspx", "http://www.erp321.com/epaas",
    "https://www.erp321.com.evil.example/epaas", "https://user:PRIVATE@www.erp321.com/epaas"])
async def test_synthetic_proxy_exception_never_applies_to_unknown_or_unsafe_host(monkeypatch, url):
    dns = AsyncMock(return_value=[(None, None, None, None, ("198.18.0.1", 443))])
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", dns)
    with pytest.raises(ConnectorError) as error:
        await _public_destination(url)
    assert error.value.details["dns_policy"] == "host_not_allowed"
    assert "PRIVATE" not in json.dumps(error.value.as_dict())
    dns.assert_not_awaited()


@pytest.fixture
async def engine(tmp_path, monkeypatch):
    received = []
    html = b'''<!doctype html><meta charset="utf-8"><script src="/public.js"></script>
      <body><h1>Local inventory</h1><input aria-label="SKU filter" id="sku" value="visible-business-value">
      <input type="hidden" name="__VIEWSTATE" value="HIDDEN-NEVER-OUTPUT">
      <input type="password" value="PASSWORD-NEVER-OUTPUT">
      <select aria-label="state"><option>All</option><option>Open</option></select>
      <button onclick="fetch('/query',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({uid:999,coid:888,__ajax_token:'OLD-NEVER-PERSIST',sku:document.querySelector('#sku').value})})">Query</button>
      <form action="/submit" method="POST"><input name="__VIEWSTATE" type="hidden" value="HIDDEN-NEVER-PERSIST"><button>Submit form</button></form>
      <a href="/next.aspx">Next page</a><a href="/write.aspx?action=delete">Forbidden link</a>
      <a href="/Logout.aspx">Logout</a><iframe src="/DeleteOrder.aspx"></iframe>
      <iframe src="/frame.html"></iframe></body>'''
    script = b"window.publicLoaded=true;const token='PUBLIC-SECRET-NEVER-OUTPUT';"

    async def handler(reader, writer):
        raw = await reader.readuntil(b"\r\n\r\n")
        method, path, _ = raw.split(b"\r\n", 1)[0].split(b" ")
        length = next((int(line.split(b":", 1)[1]) for line in raw.split(b"\r\n") if line.lower().startswith(b"content-length:")), 0)
        body = await reader.readexactly(length) if length else b""
        received.append({"method": method.decode(), "path": path.decode(), "cookie_present": b"\r\ncookie:" in raw.lower(), "body": body})
        result, kind = html, b"text/html"
        if path == b"/public.js":
            result, kind = script, b"application/javascript"
        elif path == b"/frame.html":
            result = b"<body><h2>Nested frame</h2><button>Frame query</button></body>"
        elif path == b"/next.aspx":
            result = b"<body>Observed next page</body>"
        elif path == b"/query":
            result, kind = b'{"records":[{"sku":"DUMMY-SKU"}]}', b"application/json"
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: " + kind + b"\r\nContent-Length: " + str(len(result)).encode()
                     + b"\r\nConnection: close\r\n\r\n" + result)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    origin = "http://127.0.0.1:" + str(server.sockets[0].getsockname()[1])
    # Only this fixture remaps production URL/DNS rules to a controlled local server.
    monkeypatch.setattr(discovery_module, "_erp_url", lambda url: isinstance(url, str) and url.startswith(origin + "/") and "#" not in url)
    monkeypatch.setattr(discovery_module, "_asset_url", lambda url: url == origin + "/public.js")
    monkeypatch.setattr(discovery_module, "_NAVIGATION", {origin + "/entry.html"})
    monkeypatch.setattr(discovery_module, "_public_destination", AsyncMock())
    key = Fernet.generate_key()
    vault = Vault(tmp_path, key=key)
    vault.save_session("codex", {"cookies": [{"name": "u_cid", "value": "CURRENT-ONLY-DUMMY", "domain": "127.0.0.1",
        "path": "/", "expires": -1, "httpOnly": True, "secure": False, "sameSite": "Lax"}], "origins": []}, IDS)
    async with async_playwright() as playwright:
        chromium = await playwright.chromium.launch(headless=True)

        async def factory(state):
            return await chromium.new_context(storage_state=state, service_workers="block")

        async def verified(context):
            return dict(IDS)

        browser = BrowserManager(vault, context_factory=factory, identity_verifier=verified, idle_seconds=0)
        discovery = DiscoveryBrowser(browser)
        try:
            yield SimpleNamespace(browser=browser, discovery=discovery, vault=vault, key=key, root=tmp_path,
                                  origin=origin, received=received, chromium=chromium)
        finally:
            await discovery.close()
            await browser.close()
            await chromium.close()
            server.close()
            await server.wait_closed()


def element(snapshot, label):
    return next(item["element_ref"] for frame in snapshot["frames"] for item in frame["elements"] if item.get("label") == label)


async def captured(engine, discovery_id, path="/query"):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        value = await engine.discovery.inspect("codex", discovery_id, "requests")
        value["requests"] = [item for item in value["requests"] if item["url"].endswith(path)]
        if value["requests"]:
            return value
        await asyncio.sleep(0.01)
    raise AssertionError("回环请求未被截获")


@pytest.mark.asyncio
async def test_real_chromium_unknown_query_is_blocked_then_private_descriptor_executes_with_current_identity(engine):
    snapshot = await engine.discovery.start("codex", engine.origin + "/entry.html")
    discovery_id = snapshot["discovery_id"]
    assert len(engine.chromium.contexts) == 2  # Main login context remains separate.
    assert engine.browser._sessions["codex"].page.url == "about:blank"
    assert any("Nested frame" in frame["text"] for frame in snapshot["frames"])
    assert all(secret not in json.dumps(snapshot) for secret in ("HIDDEN-NEVER-OUTPUT", "PASSWORD-NEVER-OUTPUT", "CURRENT-ONLY-DUMMY"))
    initial_ref = element(snapshot, "SKU filter")
    snapshot = await engine.discovery.interact("codex", discovery_id, initial_ref, "fill", "DUMMY-SKU")
    with pytest.raises(ConnectorError):
        await engine.discovery.interact("codex", discovery_id, initial_ref, "fill", "stale-ref")
    await engine.discovery.interact("codex", discovery_id, element(snapshot, "Query"), "click")
    public = await captured(engine, discovery_id)
    assert not any(item["method"] == "POST" for item in engine.received)
    assert not any(item["path"] in {"/Logout.aspx", "/DeleteOrder.aspx"} for item in engine.received)
    assert "DUMMY-SKU" not in json.dumps(public) and "OLD-NEVER-PERSIST" not in json.dumps(public)
    request = await engine.discovery.get_request("codex", discovery_id, public["requests"][0]["request_id"])
    assert request["body"] == {"uid": None, "coid": None, "__ajax_token": None, "sku": "DUMMY-SKU"}
    assert "OLD-NEVER-PERSIST" not in json.dumps(request)
    result = await engine.discovery.execute_read("codex", request)  # Internal approved-registry boundary exercised by trusted fixture.
    assert result["status"] == 200 and "DUMMY-SKU" in result["text"]
    sent = next(item for item in engine.received if item["method"] == "POST")
    assert json.loads(sent["body"]) == {"uid": 201, "coid": 101, "__ajax_token": "1.CURRENT-ONLY-DUMMY-", "sku": "DUMMY-SKU"}
    assert sent["cookie_present"]
    script = next(item for item in engine.received if item["path"] == "/public.js")
    assert not script["cookie_present"]  # Real anonymous HTTP, despite cookies in both browser contexts.
    source = next(item for frame in snapshot["frames"] for item in frame["elements"] if item["tag"] == "script")
    text = await engine.discovery.inspect("codex", discovery_id, "source", source["source_id"], "publicLoaded")
    assert "PUBLIC-SECRET-NEVER-OUTPUT" not in text["text"] and len(text["sha256"]) == 64
    catalog = await engine.discovery.inspect("codex", discovery_id, "source")
    assert catalog["total"] == 1 and catalog["sources"][0]["source_id"] == source["source_id"]


@pytest.mark.asyncio
async def test_observed_navigation_hidden_form_and_profile_lifecycle_are_restricted(engine):
    snapshot = await engine.discovery.start("codex", engine.origin + "/entry.html")
    discovery_id = snapshot["discovery_id"]
    with pytest.raises(ConnectorError):
        await engine.discovery.inspect("other-profile", discovery_id)
    with pytest.raises(ConnectorError):
        await engine.discovery.interact("codex", discovery_id, element(snapshot, "Forbidden link"), "navigate")
    # A blocked native form navigation may replace its document; it still must not send.
    with pytest.raises(ConnectorError):
        await engine.discovery.interact("codex", discovery_id, element(snapshot, "Submit form"), "click")
    public = await captured(engine, discovery_id, "/submit")
    request = await engine.discovery.get_request("codex", discovery_id, public["requests"][0]["request_id"])
    assert request["source"]["credential_fields"] == ["/body/__VIEWSTATE"]
    assert "HIDDEN-NEVER-PERSIST" not in json.dumps(request)
    with pytest.raises(ConnectorError):
        await engine.discovery.execute_read("codex", request)
    assert not any(item["method"] == "POST" for item in engine.received)
    await engine.discovery.close_profile("codex")
    snapshot = await engine.discovery.start("codex", engine.origin + "/entry.html")
    discovery_id = snapshot["discovery_id"]
    result = await engine.discovery.interact("codex", discovery_id, element(snapshot, "Next page"), "navigate")
    assert result["url"].endswith("/next.aspx")
    await engine.browser.logout("codex")
    assert not engine.discovery._discoveries and len(engine.chromium.contexts) == 0


@pytest.mark.asyncio
async def test_dynamic_entry_approval_and_scope_change_are_fail_closed(engine):
    with pytest.raises(ConnectorError):
        await engine.discovery.start("codex", engine.origin + "/next.aspx")
    with pytest.raises(ConnectorError):
        await engine.discovery.start("codex", engine.origin + "/next.aspx", entry_approved=True, expected_binding="stale")
    snapshot = await engine.discovery.start("codex", engine.origin + "/entry.html")
    other = Vault(engine.root, key=engine.key)
    other.clear_session("codex")
    other.save_session("codex", {"cookies": [], "origins": []}, {"company_id": "303", "user_id": "404"})
    with pytest.raises(ConnectorError):
        await engine.discovery.inspect("codex", snapshot["discovery_id"])


@pytest.mark.asyncio
async def test_binding_change_during_dns_prevents_credentialed_fetch(engine, monkeypatch):
    snapshot = await engine.discovery.start("codex", engine.origin + "/entry.html")
    await engine.discovery.interact("codex", snapshot["discovery_id"], element(snapshot, "Query"), "click")
    public = await captured(engine, snapshot["discovery_id"])
    descriptor = await engine.discovery.get_request("codex", snapshot["discovery_id"], public["requests"][0]["request_id"])
    other = Vault(engine.root, key=engine.key)

    async def changed(url):
        other.clear_session("codex")
        other.save_session("codex", {"cookies": [], "origins": []}, IDS)

    monkeypatch.setattr(discovery_module, "_public_destination", changed)
    with pytest.raises(ConnectorError):
        await engine.discovery.execute_read("codex", descriptor)
    assert not any(item["method"] == "POST" for item in engine.received)


@pytest.mark.asyncio
async def test_document_dns_binding_change_never_calls_route_fetch(engine, monkeypatch):
    snapshot = await engine.discovery.start("codex", engine.origin + "/entry.html")
    discovery = engine.discovery._discoveries[snapshot["discovery_id"]]
    other = Vault(engine.root, key=engine.key)

    async def changed(url):
        other.clear_session("codex")
        other.save_session("codex", {"cookies": [], "origins": []}, IDS)

    monkeypatch.setattr(discovery_module, "_public_destination", changed)
    route = SimpleNamespace(request=SimpleNamespace(method="GET", resource_type="document", url=engine.origin + "/next.aspx"),
                            fetch=AsyncMock(), abort=AsyncMock())
    await engine.discovery._route(discovery, route)
    route.fetch.assert_not_awaited()
    route.abort.assert_awaited_once()


def test_serialized_unknown_json_is_removed_instead_of_retaining_dispatch_identity_or_credentials():
    bindings, removed = [], []
    result = discovery_module._scrub({"data": '{"method":"DeleteOrder","uid":999,"password":"PRIVATE-PASSWORD"}'},
                                     "/body", bindings, removed)
    assert result == {"data": None} and removed == ["/body/data"]
    assert "PRIVATE" not in json.dumps(result) and not bindings


@pytest.mark.asyncio
async def test_idle_cleanup_releases_discovery_copy(engine):
    await engine.discovery.start("codex", engine.origin + "/entry.html")
    await engine.browser.close_idle()
    assert not engine.discovery._discoveries and not engine.chromium.contexts


@pytest.mark.asyncio
async def test_failed_start_keeps_safe_dns_diagnostic_without_raw_address_or_exception(engine, monkeypatch):
    async def denied(url):
        raise ConnectorError("DISCOVERY_REJECTED", "目标网络策略未通过。",
                             details={"stage": "dns_policy", "dns_policy": "rejected_address"})

    monkeypatch.setattr(discovery_module, "_public_destination", denied)
    with pytest.raises(ConnectorError) as error:
        await engine.discovery.start("codex", engine.origin + "/entry.html")
    assert error.value.code == "DISCOVERY_PAGE_FAILED"
    assert error.value.details["stage"] == "dns_policy"
    assert error.value.details["dns_policy"] == "rejected_address"
    assert error.value.details["diagnostics"][0]["failure"] == "policy_rejected"
    assert not engine.discovery._discoveries
