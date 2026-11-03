"""真实Chromium跨域商品iframe与受控HTTP闭环；所有来源均为隔离回环夹具。"""
import asyncio
import base64
import json
from types import SimpleNamespace
from urllib.parse import urlsplit, urlunsplit

import pytest
from cryptography.fernet import Fernet
from playwright.async_api import async_playwright

import jst_connector.discovery_browser as discovery_module
import jst_connector.drp_read_policy as read_policy
from jst_connector.drp import DrpBrowserManager
from jst_connector.errors import ConnectorError
from jst_connector.platform_policy import get_policy
from jst_connector.platform_store import ensure_platform
from jst_connector.service import ConnectorService
from jst_connector.vault import Vault

IDENTITY = {"company_id": "101", "user_id": "201"}
LIST_PATH = "/api/goods/myself/rapidly/goods/list"
GOODS_PATH = "/manage/goods/goodsManage/index"
RULES = {"success": [{"path": "/success", "equals": True}],
         "required": [{"path": "/data", "type": "array"}, {"path": "/total", "type": "integer"}], "data_path": "/data"}
PARAMETERS = [{"name": "page", "path": "/body/pageNum", "type": "integer", "required": True, "minimum": 1, "maximum": 100},
              {"name": "size", "path": "/body/pageSize", "type": "integer", "default": 2, "minimum": 1, "maximum": 10000},
              {"name": "keyword", "path": "/body/keyword", "type": "string", "required": True}]


@pytest.fixture
async def flow(tmp_path, monkeypatch):
    received, origins = [], {}
    state = SimpleNamespace(mode="success", total=5, module=False, hash=False, generic=False)

    async def handle(role, reader, writer):
        raw = await reader.readuntil(b"\r\n\r\n")
        method, path, _ = raw.split(b"\r\n", 1)[0].split(b" ")
        headers = {line.split(b":", 1)[0].decode().lower(): line.split(b":", 1)[1].strip().decode()
                   for line in raw.split(b"\r\n")[1:] if b":" in line}
        length = int(headers.get("content-length", "0"))
        body = await reader.readexactly(length) if length else b""
        body = json.loads(body) if body else None
        request_path = path.decode()
        received.append({"role": role, "method": method.decode(), "path": request_path, "body": body, "headers": headers})
        status, kind = b"200 OK", b"text/html"
        if role == "sc":
            # The iframe is inserted dynamically; static HTML parsing alone is insufficient.
            target = ((origins["module"] + "/workspace?season=2026&dimension=remaining" + ("#/stock?categoryPath=clothes" if state.hash else ""))
                      if state.module else origins["goods"] + GOODS_PATH + "?appcode=main&__POWERED_BY_GYL_FRAME__=1")
            payload = ('<!doctype html><body><h1>SC fixture shell</h1><script>'
                       'const f=document.createElement("iframe");f.id="goods-frame";f.src=' + json.dumps(target) + ';'
                       'f.style="width:900px;height:500px";document.body.appendChild(f);'
                       'const e=document.createElement("iframe");e.src=' + json.dumps(origins["assets"] + "/evil.html") + ';document.body.appendChild(e);'
                       'for(const src of ' + json.dumps([origins["goods"] + "/api/company/deactivate", origins["sc"] + "/api/goods/customUnknown"]) + ')'
                       '{const a=document.createElement("iframe");a.src=src;document.body.appendChild(a);}'
                       '</script></body>').encode()
        elif role in {"goods", "module"}:
            payload = ('<!doctype html><body><h2>Goods fixture</h2><div id="init">initializing</div>'
                       '<input id="keyword" aria-label="商品搜索" value="FIRST"><button id="query">Query products</button>'
                       '<button id="add">Add product</button><button id="publish">Publish product</button><button id="save">Save product</button>'
                       '<button id="dispatch">Dispatch write</button><button id="header">Header write</button>'
                       '<div id="rows">loading</div><div id="cookie-probe"></div><script src=' + json.dumps(origins["assets"] + "/prod/goods/app.js") + '></script></body>').encode()
        elif role == "assets":
            kind = b"application/javascript"
            payload = ('''const api=API_ORIGIN;
              const options={method:'POST',credentials:'include',headers:{'Content-Type':'application/json','Authorization':'STALE-BROWSER-TOKEN'}};
              function query(extra={},endpoint=LIST_PATH,headers={}) {
                const body={pageNum:1,pageSize:2,searchType:1,checkHasData:true,keyword:document.querySelector('#keyword').value,...extra};
                return fetch(api+endpoint,{...options,headers:{...options.headers,...headers},body:JSON.stringify(body)})
                  .then(r=>r.json()).then(v=>{document.querySelector('#rows').innerText=v.data.map(x=>x.sku).join(' | ');})
                  .catch(()=>{document.querySelector('#rows').innerText='REQUEST_FAILED';});
              }
              fetch(api+'/api/drp/user/supplier/getUserInfo?supplierType=shop&terminalName=SUPPLIER',
                    {credentials:'include',headers:{'Authorization':'STALE-BROWSER-TOKEN'}})
                    .then(r=>r.json()).then(()=>{document.querySelector('#init').innerText='Initialization ready';});
              document.querySelector('#query').onclick=()=>query();
              for(const action of ['add','publish','save']) document.querySelector('#'+action).onclick=()=>query({},'/api/goods/myself/rapidly/goods/'+action);
              document.querySelector('#dispatch').onclick=()=>query({action:'PublishGoods'});
              document.querySelector('#header').onclick=()=>query({},LIST_PATH,{'Action-Name':'SaveGoods'});
              query();'''.replace("API_ORIGIN", json.dumps(origins["api"])).replace("LIST_PATH", json.dumps("/api/drp/any/QueryNewBusiness" if state.generic else LIST_PATH))).encode()
            # A real shared DRP chunk exceeds the old 2 MB per-resource limit.
            payload += b"/*" + b" " * (3 * 1024 * 1024) + b"LARGE-CHUNK-END-MARKER*/"
            payload += b"document.querySelector('#cookie-probe').innerText=document.cookie;fetch(api+'/api/drp/unknown/GetProbe?q='+encodeURIComponent(document.cookie));"
        else:
            kind = b"application/json"
            if request_path.startswith("/api/drp/user/supplier/getUserInfo"):
                value = {"success": True, "data": {"coId": 101, "userName": "fixture only"}}
            elif state.mode == "business_fail":
                value = {"success": False, "data": [], "total": 0}
            elif state.mode == "shape_changed":
                value = {"success": True, "data": {}, "total": 5}
            else:
                start = (int(body["pageNum"]) - 1) * int(body["pageSize"])
                count = max(0, min(int(body["pageSize"]), 5 - start))
                value = {"success": True, "data": [{"sku": str(body["keyword"]) + "-" + str(index + 1)} for index in range(start, start + count)], "total": state.total}
            payload = json.dumps(value).encode()
        cookie = b"\r\nSet-Cookie: HTML_NEW_COOKIE=HTTP-COOKIE-REINTRODUCTION-MARKER; Path=/" if role == "sc" else b""
        writer.write(b"HTTP/1.1 " + status + b"\r\nContent-Type: " + kind + b"\r\nContent-Length: " + str(len(payload)).encode() + cookie
                     + b"\r\nConnection: close\r\n\r\n" + payload)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    servers = []
    for index, role in enumerate(("sc", "goods", "api", "assets", "module"), 1):
        server = await asyncio.start_server(lambda reader, writer, role=role: handle(role, reader, writer), "127.0.0." + str(index), 0)
        servers.append(server)
        origins[role] = "http://127.0.0." + str(index) + ":" + str(server.sockets[0].getsockname()[1])
    hosts = {"sc": "sc.scm121.com", "goods": "goods.scm121.com", "api": "gyl.scm121.com", "assets": "assets.sursung.com", "module": "stock.scm121.com"}

    def official(url):
        for role, origin in origins.items():
            if isinstance(url, str) and url.startswith(origin + "/"):
                parts = urlsplit(url)
                return urlunsplit(("https", hosts[role], parts.path, parts.query, parts.fragment))
        return url

    real_parts = read_policy._strict_parts
    monkeypatch.setattr(read_policy, "_strict_parts", lambda value: real_parts(official(value)))
    # Retain random ports only for this isolated loopback fixture.
    monkeypatch.setattr(discovery_module, "safe_url", lambda value: urlunsplit((urlsplit(value).scheme, urlsplit(value).netloc, urlsplit(value).path, "", "")))
    policy = get_policy("drp")

    class FixturePolicy:
        platform = "drp"
        entry_url = origins["sc"] + "/"
        csrf_cookie = None
        page_hosts = frozenset({"127.0.0.1", "127.0.0.2"})
        navigation_urls = frozenset({entry_url})

        def business_url(self, value):
            return any(value.startswith(origin + "/") for origin in origins.values()) and policy.business_url(official(value))

        def page_url(self, value):
            return (isinstance(value, str) and any(value.startswith(origins[role] + "/") for role in ("sc", "goods"))
                    and policy.page_url(official(value)))

        def candidate_page_url(self, value):
            return isinstance(value, str) and any(value.startswith(origin + "/") for origin in origins.values()) and policy.candidate_page_url(official(value))

        def asset_url(self, value):
            return value.startswith(origins["assets"] + "/") and policy.asset_url(official(value))

    fixture_policy = FixturePolicy()
    # Only these isolated fixture origins bypass public DNS; production helpers remain unchanged.
    async def destination(url, *, policy=None, page=False):
        if not (fixture_policy.business_url(url) or fixture_policy.asset_url(url) or page and fixture_policy.candidate_page_url(url)):
            raise ConnectorError("fixture_destination_rejected", "非夹具地址禁止请求。")
    monkeypatch.setattr(discovery_module, "_public_destination", destination)

    ensure_platform(tmp_path, "drp")
    key = Fernet.generate_key()
    vault = Vault(tmp_path, key=key)
    vault.save_session("codex", {"cookies": [
        {"name": "DISTRYBUTION_TOKEN", "value": "CURRENT-ACTOR-DRP-TOKEN", "domain": "127.0.0.3", "path": "/", "expires": -1, "httpOnly": True, "secure": False, "sameSite": "Lax"},
        {"name": "ERP_PRIVATE", "value": "ERP-NEVER-SENT", "domain": "www.erp321.com", "path": "/", "expires": -1, "httpOnly": True, "secure": False, "sameSite": "Lax"},
        {"name": "ASSET_PRIVATE", "value": "ASSET-NEVER-SENT", "domain": "127.0.0.4", "path": "/", "expires": -1, "httpOnly": True, "secure": False, "sameSite": "Lax"},
        {"name": "DANGEROUS_MODULE_TOKEN", "value": "PARENT-COOKIE-ISOLATION-MARKER", "domain": "127.0.0.5", "path": "/", "expires": -1, "httpOnly": False, "secure": False, "sameSite": "Lax"}], "origins": []}, IDENTITY)
    async with async_playwright() as playwright:
        chromium = await playwright.chromium.launch(headless=True)

        async def factory(storage):
            return await chromium.new_context(storage_state=storage, service_workers="block")

        async def verify(context):
            return dict(IDENTITY)

        def make_service():
            current_vault = Vault(tmp_path, key=key)
            browser = DrpBrowserManager(current_vault, context_factory=factory, identity_verifier=verify, idle_seconds=0)
            browser.site_policy = fixture_policy

            async def trusted_headers(session, url):
                assert fixture_policy.business_url(url)
                values = [cookie["value"] for cookie in await session.context.cookies([url]) if cookie["name"] == "DISTRYBUTION_TOKEN"]
                assert values == ["CURRENT-ACTOR-DRP-TOKEN"]
                return {"Authorization": values[0], "appCode": "main"}

            browser.business_headers = trusted_headers
            service = ConnectorService(tmp_path, vault=current_vault, browser=browser, platform="drp")
            discovery, _ = service._generic()
            discovery._destination = destination
            return service

        service = make_service()
        env = SimpleNamespace(service=service, make_service=make_service, origins=origins, received=received, state=state, chromium=chromium)
        try:
            yield env
        finally:
            await env.service.close()
            await chromium.close()
            for server in servers:
                server.close()
                await server.wait_closed()


async def loaded(flow, url=""):
    result = await flow.service.start_discovery("codex", url)
    discovery_id = result["discovery"]["discovery_id"]
    for _ in range(100):
        snapshot = (await flow.service.inspect_discovery("codex", discovery_id))["discovery"]
        if any("FIRST-1" in frame["text"] for frame in snapshot["frames"]):
            return discovery_id, snapshot
        await asyncio.sleep(0.02)
    diagnostics = await flow.service.inspect_discovery("codex", discovery_id, kind="requests")
    raise AssertionError("商品iframe未渲染真实受控列表响应：" + str(diagnostics) + str(flow.service._discovery._discoveries[discovery_id].diagnostics))


async def proposal(flow, discovery_id, *, weak=False):
    observed = (await flow.service.inspect_discovery("codex", discovery_id, kind="requests"))["discovery"]["requests"]
    captured = next(item for item in observed if item["url"].endswith(LIST_PATH) and not item["source"]["blocked"])
    result = await flow.service.propose_read_interface("codex", {
        "discovery_id": discovery_id, "request_id": captured["request_id"], "name": "分销商品列表", "purpose": "精确保存当前商品页查询",
        "read_evidence": {"source_url": captured["source"]["page_url"], "description": "已核官方goods列表入口，实际请求和成功响应来自本次iframe"},
        "parameters": PARAMETERS, "response_rules": {**RULES, "success": []} if weak else RULES})
    return result["interface"], captured


async def test_dynamic_sc_to_goods_iframe_response_capture_save_restart_and_reuse(flow):
    discovery_id, snapshot = await loaded(flow)
    assert any("Goods fixture" in frame["text"] and "FIRST-2" in frame["text"] for frame in snapshot["frames"])
    source = next(item for frame in snapshot["frames"] for item in frame["elements"] if item.get("source_id"))
    searched = await flow.service.inspect_discovery("codex", discovery_id, kind="source", reference=source["source_id"], search="LARGE-CHUNK-END-MARKER")
    assert searched["discovery"]["offset"] > 2_000_000 and "LARGE-CHUNK-END-MARKER" in searched["discovery"]["text"]
    interface, captured = await proposal(flow, discovery_id)
    assert captured["source"]["read_authorized"] and len(captured["source"]["frame_chain"]) == 2
    assert captured["observed_response"]["schema"]["total"] == "number"
    assert captured["observed_response"]["business_success"] is True
    first = await flow.service.validate_read_interface("codex", interface["interface_id"], {"page": 1, "keyword": "FIRST"})
    assert first["result"]["pagination"] == {"page": 1, "page_size": 2, "returned": 2, "total": 5, "has_more": True}
    assert first["result"]["complete"] is None
    await flow.service.close()
    flow.service = flow.make_service()
    assert not flow.service._discovery._discoveries
    second = await flow.service.call_saved_interface("codex", interface["interface_id"], {"page": 2, "keyword": "SECOND"})
    assert second["result"]["data"] == [{"sku": "SECOND-3"}, {"sku": "SECOND-4"}]
    last = await flow.service.call_saved_interface("codex", interface["interface_id"], {"page": 3, "keyword": "SECOND"})
    assert last["result"]["pagination"]["has_more"] is False and last["result"]["complete"] is None
    assert all(item["headers"].get("authorization") == "CURRENT-ACTOR-DRP-TOKEN" for item in flow.received if item["role"] == "api")
    assert all("ERP-NEVER-SENT" not in str(item) and "ASSET-NEVER-SENT" not in str(item) for item in flow.received)
    assert all("cookie" not in item["headers"] for item in flow.received if item["role"] == "assets")
    assert not any(item["path"] == "/evil.html" for item in flow.received)
    assert not any(item["path"] in {"/api/company/deactivate", "/api/goods/customUnknown"} for item in flow.received)
    assert "CURRENT-ACTOR-DRP-TOKEN" not in json.dumps(interface)


async def test_unknown_add_publish_save_and_write_dispatch_are_blocked_before_server(flow):
    discovery_id, _ = await loaded(flow)
    for label in ("Add product", "Publish product", "Save product", "Dispatch write", "Header write"):
        snapshot = (await flow.service.inspect_discovery("codex", discovery_id))["discovery"]
        reference = next(item["element_ref"] for frame in snapshot["frames"] for item in frame["elements"] if item.get("label") == label)
        await flow.service.interact_discovery("codex", discovery_id, reference, "click")
    await asyncio.sleep(0.1)
    requests = (await flow.service.inspect_discovery("codex", discovery_id, kind="requests"))["discovery"]["requests"]
    blocked = [item for item in requests if item["source"]["blocked"] and item["method"] == "POST"]
    assert len(blocked) >= 5
    assert len([item for item in flow.received if item["role"] == "api" and item["method"] == "POST"]) == 1
    for item in blocked:
        candidate = await flow.service.propose_read_interface("codex", {
            "discovery_id": discovery_id, "request_id": item["request_id"], "name": "待判断请求", "purpose": "不得借查询执行写入",
            "read_evidence": {"source_url": item["source"]["page_url"], "description": "仅为请求线索，不能自报只读放行"},
            "parameters": [], "response_rules": RULES})
        assert candidate["interface"]["kind"] != "query"


@pytest.mark.parametrize("mode", ["business_fail", "shape_changed"])
async def test_known_list_failure_cannot_be_weak_rule_empty_success(flow, mode):
    discovery_id, _ = await loaded(flow)
    interface, _ = await proposal(flow, discovery_id, weak=True)
    flow.state.mode = mode
    with pytest.raises(ConnectorError, match="不能视为空列表"):
        await flow.service.validate_read_interface("codex", interface["interface_id"], {"page": 1, "keyword": "FIRST"})


async def test_changed_parameters_cannot_bypass_known_read_limits_or_actor_binding(flow):
    discovery_id, _ = await loaded(flow)
    interface, _ = await proposal(flow, discovery_id)
    await flow.service.validate_read_interface("codex", interface["interface_id"], {"page": 1, "keyword": "FIRST"})
    before = len(flow.received)
    with pytest.raises(ConnectorError, match="只读边界"):
        await flow.service.call_saved_interface("codex", interface["interface_id"], {"page": 1, "size": 501, "keyword": "FIRST"})
    assert len(flow.received) == before
    with pytest.raises(ConnectorError):
        await flow.service.call_saved_interface("other", interface["interface_id"], {"page": 1, "keyword": "FIRST"})
    assert len(flow.received) == before


async def test_unknown_total_is_not_fabricated_as_zero_or_complete(flow):
    discovery_id, _ = await loaded(flow)
    interface, _ = await proposal(flow, discovery_id)
    flow.state.total = -1
    result = await flow.service.validate_read_interface("codex", interface["interface_id"], {"page": 1, "keyword": "FIRST"})
    assert result["result"]["pagination"]["total"] is None
    assert result["result"]["pagination"]["has_more"] is None and result["result"]["complete"] is None


@pytest.mark.parametrize("role", ["sc", "goods"])
async def test_fixed_frontend_direct_hash_entry_validates_and_starts_real_browser(flow, role):
    _, registry = flow.service._generic()
    fixture_policy = registry.site_policy
    registry.site_policy = get_policy("drp")
    official = "https://" + {"sc": "sc.scm121.com", "goods": "goods.scm121.com"}[role]
    try:
        valid = official + "/#/inventory?categoryPath=remaining&brand=NEW"
        assert registry.validate_url(valid, entry=True) == valid
        assert registry.entry_allowed("codex", valid)
        for suffix in ("/#/login", "/#/inventory?token=secret", "/#/inventory?action=save", "/#/api/goods/list"):
            assert not registry.entry_allowed("codex", official + suffix)
        with pytest.raises(ConnectorError):
            registry.validate_url("https://gyl.scm121.com/api/goods/supplier/goods/list#/inventory")
    finally:
        registry.site_policy = fixture_policy
    direct = flow.origins[role] + "/#/inventory?categoryPath=remaining&brand=NEW"
    identifier, snapshot = await loaded(flow, direct)
    assert any("FIRST-1" in frame["text"] for frame in snapshot["frames"])
    requests = (await flow.service.inspect_discovery("codex", identifier, kind="requests"))["discovery"]["requests"]
    assert any(item["url"].endswith(LIST_PATH) and item["source"]["blocked"] is False for item in requests)


async def test_api_cannot_be_opened_as_document_or_reuse_expired_discovery(flow):
    discovery_id, _ = await loaded(flow)
    before = len(flow.received)
    with pytest.raises(ConnectorError):
        await flow.service.start_discovery("codex", flow.origins["goods"] + "/api/company/deactivate")
    assert len(flow.received) == before
    flow.service.vault.clear_session("codex")
    with pytest.raises(ConnectorError):
        await flow.service.inspect_discovery("codex", discovery_id, kind="requests")
    assert len(flow.received) == before


@pytest.mark.parametrize("hash_route", [False, True])
async def test_observed_new_module_source_can_save_unknown_query_and_reuse_after_restart(flow, hash_route):
    flow.state.module, flow.state.hash, flow.state.generic = True, hash_route, True
    with pytest.raises(ConnectorError):
        await flow.service.start_discovery("codex", flow.origins["module"] + "/workspace")
    assert not flow.received
    started = await flow.service.start_discovery("codex")
    identifier = started["discovery"]["discovery_id"]
    for _ in range(80):
        requests = (await flow.service.inspect_discovery("codex", identifier, kind="requests"))["discovery"]["requests"]
        captured = next((item for item in requests if item["url"].endswith("QueryNewBusiness")), None)
        if captured:
            break
        await asyncio.sleep(0.02)
    assert captured and captured["source"]["blocked"] is True
    if hash_route:
        snapshot = (await flow.service.inspect_discovery("codex", identifier))["discovery"]
        reference = next(item["element_ref"] for frame in snapshot["frames"] for item in frame["elements"]
                         if item.get("tag") == "iframe" and item.get("url", "").startswith(flow.origins["module"]))
        await flow.service.interact_discovery("codex", identifier, reference, "navigate")
        for _ in range(80):
            requests = (await flow.service.inspect_discovery("codex", identifier, kind="requests"))["discovery"]["requests"]
            matches = [item for item in requests if item["url"].endswith("QueryNewBusiness")]
            if len(matches) >= 2:
                captured = matches[-1]
                break
            await asyncio.sleep(0.02)
        assert len(matches) >= 2
    assert captured["source"]["page_chain"][0].startswith(flow.origins["module"])
    assert captured["source"]["page_chain"][-1] == flow.origins["sc"] + "/"
    candidate = await flow.service.propose_read_interface("codex", {
        "discovery_id": identifier, "request_id": captured["request_id"], "name": "新模块通用查询", "purpose": "由实际源页面捕获并试查复用未知查询",
        "read_evidence": {"source_url": captured["source"]["page_url"], "description": "当前官方模块页面实际捕获的明确Query接口"},
        "parameters": PARAMETERS, "response_rules": RULES})
    interface_id = candidate["interface"]["interface_id"]
    first = await flow.service.validate_read_interface("codex", interface_id, {"page": 1, "keyword": "NEW"})
    assert first["result"]["data"][0]["sku"] == "NEW-1"
    active = flow.service._discovery._discoveries[identifier]
    assert not any(cookie["name"] == "HTML_NEW_COOKIE" for cookie in await active.context.cookies())
    assert "PARENT-COOKIE-ISOLATION-MARKER" not in json.dumps(active.requests)
    rendered = (await flow.service.inspect_discovery("codex", identifier))["discovery"]
    assert "PARENT-COOKIE-ISOLATION-MARKER" not in json.dumps(rendered)
    assert any(cookie["value"] == "PARENT-COOKIE-ISOLATION-MARKER" for cookie in flow.service.vault.load_session("codex")["state"]["cookies"])
    await flow.service.close()
    flow.service = flow.make_service()
    second = await flow.service.call_saved_interface("codex", interface_id, {"page": 2, "keyword": "REUSED"})
    assert second["result"]["data"][0]["sku"] == "REUSED-3"
    assert all("cookie" not in item["headers"] and "authorization" not in item["headers"] for item in flow.received if item["role"] == "module")
    actual = [item for item in flow.received if item["path"].endswith("QueryNewBusiness")]
    assert len(actual) == 2 and all(item["headers"]["referer"] == captured["source"]["page_url"] for item in actual)
    assert "PARENT-COOKIE-ISOLATION-MARKER" not in json.dumps(flow.received)


async def test_real_credentials_are_absent_even_after_official_parent_cookie_setter_and_jmx_message(flow):
    discovery = flow.service._discovery
    fixture_policy = discovery.site_policy
    discovery.site_policy = get_policy("drp")
    marker = "REAL-CREDENTIAL-MUST-NEVER-ENTER-EXPLORATION"
    source = {"cookies": [{"name": "DISTRYBUTION_TOKEN", "value": marker, "domain": ".scm121.com", "path": "/",
                           "expires": -1, "httpOnly": False, "secure": True, "sameSite": "Lax"},
                          {"name": "OTHER_PRIVATE", "value": marker, "domain": "sc.scm121.com", "path": "/",
                           "expires": -1, "httpOnly": False, "secure": True, "sameSite": "Lax"}],
              "origins": [{"origin": "https://sc.scm121.com", "localStorage": [{"name": "secret", "value": marker}]},
                          {"origin": "https://stock.scm121.com", "localStorage": [{"name": "secret", "value": marker}]}]}
    before = json.dumps(source)
    try:
        isolated = discovery._exploration_state(source, IDENTITY)
    finally:
        discovery.site_policy = fixture_policy
    assert json.dumps(source) == before and isolated["origins"] == []
    assert marker not in json.dumps(isolated)
    assert {cookie["name"] for cookie in isolated["cookies"]} == {"DISTRYBUTION_TOKEN"}
    token = isolated["cookies"][0]["value"]
    def decoded(segment):
        return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    assert decoded(token.split(".")[0])["alg"] == "JST_DISCOVERY_ONLY"
    assert decoded(token.split(".")[1])["user"] == {"coId": "101", "uid": "201"}
    assert token.endswith(".DISCOVERY_NOT_A_SIGNATURE")
    context = await flow.chromium.new_context(storage_state=isolated)
    probes = []
    async def fixture(route):
        probes.append(route.request.url)
        if "/GetProbe" in route.request.url:
            await route.fulfill(body="{}", content_type="application/json")
        elif route.request.url.startswith("https://sc.scm121.com"):
            await route.fulfill(body="""<body><script>
                const token=document.cookie.split('; ').find(x=>x.startsWith('DISTRYBUTION_TOKEN=')).split('=')[1];
                document.cookie='DISTRYBUTION_TOKEN='+token+'; Domain=.scm121.com; Path=/; Secure';
                document.body.append(document.cookie+'|'+localStorage.getItem('secret'));
                const frame=document.createElement('iframe');frame.src='https://stock.scm121.com/child';
                frame.onload=()=>frame.contentWindow.postMessage({gylToken:token},'https://stock.scm121.com');document.body.append(frame);
                </script></body>""", content_type="text/html")
        else:
            await route.fulfill(body="""<body><script>window.addEventListener('message',event=>{
                document.body.innerText='MESSAGE_READY|'+document.cookie+'|'+localStorage.getItem('secret')+'|'+event.data.gylToken;
                fetch('/GetProbe?q='+encodeURIComponent(document.body.innerText));});</script></body>""", content_type="text/html")
    await context.route("**/*", fixture)
    try:
        page = await context.new_page()
        await page.goto("https://sc.scm121.com/")
        for _ in range(60):
            children = [frame for frame in page.frames if frame.url.startswith("https://stock.scm121.com")]
            if children and "MESSAGE_READY" in await children[0].locator("body").inner_text():
                break
            await asyncio.sleep(0.02)
        assert children and "MESSAGE_READY" in await children[0].locator("body").inner_text()
        assert token in await children[0].locator("body").inner_text()
        assert marker not in await page.locator("body").inner_text()
        assert marker not in await children[0].locator("body").inner_text()
        assert marker not in json.dumps(await context.storage_state())
        assert marker not in json.dumps(probes)
    finally:
        await context.close()



