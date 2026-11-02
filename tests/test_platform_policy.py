"""平台策略、契约及传输隔离；不连接真实ERP或分销业务系统。"""
import asyncio
import copy
import json
from contextlib import asynccontextmanager
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet

from jst_connector.discovery_browser import DiscoveryBrowser, _public_destination
from jst_connector.errors import ConnectorError
from jst_connector.interface_registry import InterfaceRegistry
from jst_connector.ledger import Ledger
from jst_connector.platform_policy import get_policy
from jst_connector.vault import Vault
from jst_connector.write_registry import WriteRegistry

IDENTITY = {"company_id": "101", "user_id": "201"}
RULES = {"success": [{"path": "/code", "equals": 0}], "required": [{"path": "/data", "type": "object"}], "data_path": "/data"}


def descriptor(policy, kind, base):
    return {"request_id": kind, "url": base + ("/GetDocument" if kind == "read" else "/SaveDocument"),
            "method": "POST", "encoding": "json", "query": {},
            "body": {"id": "7", "uid": None, "coid": None, **({"note": "after"} if kind == "write" else {})},
            "headers": {"Content-Type": "application/json"},
            "identity_bindings": [{"path": "/body/uid", "kind": "user_id", "value_type": "number"},
                                  {"path": "/body/coid", "kind": "company_id", "value_type": "number"}], "json_fields": [],
            "source": {"page_url": policy.entry_url, "discovery_id": "discovery", "resource_type": "xhr", "blocked": True},
            "_scope": {"profile": "codex", "identity": IDENTITY, "platform": policy.platform}}


@pytest.fixture(params=["erp", "drp"])
def transport(tmp_path, request):
    policy = get_policy(request.param)
    root = tmp_path / policy.platform
    vault = Vault(root, key=Fernet.generate_key())
    vault.save_session("codex", {"cookies": [], "origins": []}, IDENTITY)
    binding = vault.session_binding("codex")
    state = {"id": "7", "note": "before", "status": "draft"}
    sent = []

    async def fetch(url, **options):
        body = options["data"]
        sent.append({"url": url, "headers": copy.deepcopy(options["headers"]), "body": copy.deepcopy(body)})
        if url.endswith("/SaveDocument"):
            state["note"] = body["note"]
        return SimpleNamespace(status=200, url=url, headers={"content-type": "application/json"},
                               text=AsyncMock(return_value=json.dumps({"code": 0, "data": state})), dispose=AsyncMock())

    context = SimpleNamespace(request=SimpleNamespace(fetch=AsyncMock(side_effect=fetch)), cookies=AsyncMock(return_value=[]))
    session = SimpleNamespace(context=context, vault_binding=binding, identity=copy.deepcopy(IDENTITY),
                              verified=True, binding="test-context-generation")

    @asynccontextmanager
    async def scope(profile):
        assert profile == "codex"
        yield copy.deepcopy(IDENTITY)

    browser = SimpleNamespace(platform=policy.platform, site_policy=policy, vault=vault, _sessions={"codex": session},
                              verified_scope=scope, _assert_scope=lambda *args: None,
                              add_profile_cleanup=lambda callback: None, identity=AsyncMock(return_value=copy.deepcopy(IDENTITY)))
    browser.business_headers = AsyncMock(return_value={"Authorization": "DRP-ONLY-PRIVATE", "appCode": "main"})
    discovery = DiscoveryBrowser(browser)

    async def destination(url):
        assert discovery._business_url(url)

    discovery._destination = AsyncMock(side_effect=destination)
    base = "https://api.erp321.com/test" if policy.platform == "erp" else "https://gyl.scm121.com/api/drp/test"
    descriptors = {kind: descriptor(policy, kind, base) for kind in ("read", "write")}
    for captured_record in descriptors.values():
        captured_record["_scope"]["session_binding"] = binding
    discovery.get_request = AsyncMock(side_effect=lambda profile, discovery_id, identifier: copy.deepcopy(descriptors[identifier]))
    reads = InterfaceRegistry(root, vault, browser, discovery)
    ledger = Ledger(root, vault)
    return SimpleNamespace(policy=policy, browser=browser, discovery=discovery, reads=reads, vault=vault,
                           ledger=ledger, descriptors=descriptors, sent=sent, state=state, root=root)


def test_policy_is_frozen_and_keeps_business_auth_and_asset_domains_separate():
    erp, drp = get_policy("erp"), get_policy("drp")
    assert erp.business_url("https://api.erp321.com/test/GetData")
    assert not erp.business_url("https://gyl.scm121.com/api/drp/GetData")
    assert drp.business_url("https://gyl.scm121.com/api/drp/GetData")
    assert drp.business_url("https://innerapi.scm121.com/api/aftersale/GetData")
    assert not drp.business_url("https://api.erp321.com/test/GetData")
    assert not drp.business_url("https://gyl.scm121.com/api/auth/open/v2/login/gyl/accountLogin")
    assert not drp.business_url("https://account.scm121.com/user/login")
    assert not drp.business_url("https://sc.scm121.com/user/login")
    assert drp.asset_url("https://assets.sursung.com/prod/gylsc/main.js")
    assert not drp.asset_url("https://assets.sursung.com/unknown/main.js")
    assert not drp.business_url("https://assets.sursung.com/prod/gylsc/main.js")
    assert not erp.asset_url("https://assets.sursung.com/prod/gylsc/main.js")
    assert drp.csrf_cookie is None and erp.csrf_cookie == "u_cid"
    with pytest.raises(FrozenInstanceError):
        drp.platform = "erp"
    with pytest.raises(ConnectorError):
        get_policy("https://other.example")


@pytest.mark.parametrize("value", ["https://gyl.scm121.com.evil.test/api/drp/GetData", "https://user:pass@gyl.scm121.com/api/drp/GetData",
                                    "https://gyl.scm121.com:443/api/drp/GetData", "http://gyl.scm121.com/api/drp/GetData",
                                    "https://gyl.scm121.com/api/drp/%2e%2e/auth", "https://gyl.scm121.com/api/drp/../auth",
                                    "https://gyl.scm121.com/api/drp/GetData#fragment", "https://gyl.scm121.com/api/market/GetData"])
def test_drp_url_tricks_and_unverified_api_prefixes_are_not_allowed(value):
    assert not get_policy("drp").business_url(value)


@pytest.mark.parametrize("value", ["https://sc.scm121.com/", "https://sc.scm121.com/orders/list", "https://sc.scm121.com/retail/order"])
def test_drp_ordinary_spa_paths_are_readable_pages(value):
    assert get_policy("drp").page_url(value)


@pytest.mark.parametrize("value", ["https://sc.scm121.com/user/login", "https://sc.scm121.com/orders/submit",
                                    "https://sc.scm121.com/order/GetAndSubmit", "https://sc.scm121.com/orders/list?action=Delete",
                                    "https://gyl.scm121.com/api/drp/GetData"])
def test_actions_auth_and_api_json_do_not_become_spa_pages(value):
    assert not get_policy("drp").page_url(value)


@pytest.mark.parametrize("base", ["https://gyl.scm121.com/api/drp/", "https://innerapi.scm121.com/api/innerdrp/"])
@pytest.mark.parametrize("operation", ["QueryNewBusiness", "CreateNewBusiness"])
def test_new_namespaces_under_verified_sdk_bases_are_not_limited_by_example_catalog(base, operation):
    assert get_policy("drp").business_url(base + "not-in-any-catalog/" + operation)


async def test_read_and_write_contracts_use_only_instance_platform_and_trusted_auth_headers(transport):
    env = transport
    query = await env.reads.propose("codex", "discovery", "read", "回查单据", "按对象回查",
                                    {"source_url": env.policy.entry_url, "description": "当前平台页面的读取按钮"},
                                    [{"name": "id", "path": "/body/id", "type": "string", "required": True}], RULES)
    assert query["platform"] == env.policy.platform
    await env.reads.validate("codex", query["interface_id"], {"id": "7"})
    writes = WriteRegistry(env.root, env.vault, env.browser, env.discovery, env.reads, env.ledger)
    proposal = await writes.propose("codex", {
        "discovery_id": "discovery", "request_id": "write", "name": "维护单据", "purpose": "本平台写入",
        "parameters": [{"name": "note", "path": "/body/note", "type": "string", "required": True}], "response_rules": RULES,
        "target": {"request_path": "/body/id", "read_interface_id": query["interface_id"], "read_parameters": {"id": "/body/id"}, "read_target_path": "/id"},
        "preconditions": [{"path": "/status", "equals": "draft"}], "expected": [{"path": "/note", "request_path": "/body/note"}]})
    preview = await writes.prepare("codex", proposal["interface_id"], {"note": "after"})
    env.ledger.approve("codex", preview["preview_id"], preview["digest"], IDENTITY)
    claimed = env.ledger.claim("codex", preview["preview_id"], preview["digest"], IDENTITY)
    assert await writes.revalidate("codex", claimed["payload"])
    result = await writes.execute("codex", claimed["payload"])
    assert result["verified"] and env.state["note"] == "after"
    assert all(env.policy.business_url(item["url"]) for item in env.sent)
    assert all(item["body"]["uid"] == 201 and item["body"]["coid"] == 101 for item in env.sent)
    assert all(item["headers"]["Referer"] == env.policy.entry_url for item in env.sent)
    if env.policy.platform == "drp":
        assert all(item["headers"]["Authorization"] == "DRP-ONLY-PRIVATE" for item in env.sent)
    else:
        env.browser.business_headers.assert_not_awaited()
        assert all("Authorization" not in item["headers"] for item in env.sent)
    assert "DRP-ONLY-PRIVATE" not in json.dumps(preview)
    assert all(b"DRP-ONLY-PRIVATE" not in path.read_bytes() for path in env.root.glob("*.sqlite3"))


async def test_cross_platform_url_source_and_forged_scope_fail_before_fetch(transport):
    env = transport
    wrong = copy.deepcopy(env.descriptors["write"])
    wrong["url"] = ("https://gyl.scm121.com/api/drp/SaveDocument" if env.policy.platform == "erp"
                    else "https://api.erp321.com/test/SaveDocument")
    with pytest.raises(ConnectorError):
        env.reads.validate_descriptor(wrong)
    with pytest.raises(ConnectorError):
        await env.discovery.execute_write("codex", wrong)
    source = copy.deepcopy(env.descriptors["read"])
    source["source"]["page_url"] = get_policy("erp" if env.policy.platform == "drp" else "drp").entry_url
    with pytest.raises(ConnectorError):
        env.reads.validate_descriptor(source)
    scope = copy.deepcopy(env.descriptors["write"])
    scope["_scope"]["platform"] = "erp" if env.policy.platform == "drp" else "drp"
    with pytest.raises(ConnectorError):
        await env.discovery.execute_write("codex", scope)
    assert not env.sent
    env.browser.business_headers.assert_not_awaited()


async def test_saved_contract_cannot_be_transplanted_to_the_other_platform(transport):
    env = transport
    query = await env.reads.propose("codex", "discovery", "read", "对象读取", "当前平台对象查询",
                                    {"source_url": env.policy.entry_url, "description": "官方页面读取对象"}, [], RULES)
    other_browser = copy.copy(env.browser)
    other_browser.site_policy = get_policy("erp" if env.policy.platform == "drp" else "drp")
    other_browser.platform = other_browser.site_policy.platform
    other = InterfaceRegistry(env.root, env.vault, other_browser, DiscoveryBrowser(other_browser))
    with pytest.raises(ConnectorError):
        other.get("codex", query["interface_id"])
    with pytest.raises(ConnectorError, match="不属于当前连接平台"):
        await other.validate("codex", query["interface_id"])
    assert not env.sent


async def test_response_from_another_realm_is_disposed_without_parsing(transport):
    env = transport
    response = SimpleNamespace(status=200,
                               url=get_policy("erp" if env.policy.platform == "drp" else "drp").entry_url,
                               headers={"content-type": "application/json"},
                               text=AsyncMock(return_value='{"code":0,"data":{}}'), dispose=AsyncMock())
    fetch = env.browser._sessions["codex"].context.request.fetch
    fetch.side_effect = None
    fetch.return_value = response
    with pytest.raises(ConnectorError):
        await env.discovery.execute_read("codex", env.descriptors["read"])
    response.text.assert_not_awaited()
    response.dispose.assert_awaited_once()


async def test_drp_cannot_rebuild_erp_csrf_or_accept_model_authorization_header(transport):
    env = transport
    if env.policy.platform != "drp":
        return
    descriptor = copy.deepcopy(env.descriptors["write"])
    descriptor["body"]["__ajax_token"] = None
    descriptor["identity_bindings"].append({"path": "/body/__ajax_token", "kind": "u_cid_ajax", "value_type": "string"})
    with pytest.raises(ConnectorError, match="不能套用ERP令牌"):
        await env.discovery.execute_write("codex", descriptor)
    descriptor = copy.deepcopy(env.descriptors["write"])
    descriptor["headers"]["Authorization"] = "SELF-REPORTED"
    with pytest.raises(ConnectorError):
        env.reads.validate_descriptor(descriptor)
    with pytest.raises(ConnectorError):
        await env.discovery.execute_write("codex", descriptor)
    assert not env.sent


async def test_drp_dns_synthetic_proxy_exception_is_scoped_to_official_policy(monkeypatch):
    dns = AsyncMock(return_value=[(None, None, None, None, ("198.18.0.1", 443))])
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", dns)
    assert await _public_destination("https://gyl.scm121.com/api/drp/GetData", policy=get_policy("drp")) == "synthetic_proxy"
    dns.reset_mock()
    for url in ("https://api.erp321.com/test/GetData", "https://evil.example/GetData", "https://gyl.scm121.com/api/auth/login"):
        with pytest.raises(ConnectorError):
            await _public_destination(url, policy=get_policy("drp"))
    dns.assert_not_awaited()
    with pytest.raises(ConnectorError):
        await _public_destination("https://gyl.scm121.com/api/drp/GetData")
