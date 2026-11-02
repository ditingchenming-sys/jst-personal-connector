"""ERP官方接续只走服务端配对/换发，不复用ERP Cookie或接受模型票据。"""
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from jst_connector.agent import create_app
from jst_connector.erp_sso import REDIRECT_TOKEN_URL, ErpLinks, connect_from_erp
from jst_connector.errors import ConnectorError
from jst_connector.platform_store import ensure_platform
from jst_connector.remote import EmployeeStore, create_remote_app
from jst_connector.service import ConnectorService
from jst_connector.vault import Vault

ERP_ID = {"company_id": "101", "user_id": "201"}
DRP_ID = {"company_id": "301", "user_id": "401"}
SCM_TOKEN = "fixture-private-issued-SCM-token"


@pytest.fixture
def bridge(tmp_path, monkeypatch):
    monkeypatch.setenv("JST_CONNECTOR_MASTER_KEY", Fernet.generate_key().decode())
    source_root, target_root = tmp_path / "erp", tmp_path / "drp"
    ensure_platform(source_root, "erp")
    ensure_platform(target_root, "drp")
    source_vault, target_vault = Vault(source_root), Vault(target_root)
    source_vault.save_session("erp-me", {"cookies": [{"name": "erp-only", "value": "private-erp-cookie"}]}, ERP_ID)
    state = SimpleNamespace(exit_failure=False, source_changed=False, replace_target=False, identities=[], tokens=[])
    response = SimpleNamespace(url=REDIRECT_TOKEN_URL, status=200, dispose=AsyncMock(),
        body=AsyncMock(return_value=json.dumps({"code": 0, "act": 0, "data": {"details": {"access_token": SCM_TOKEN}}}).encode()))
    request = SimpleNamespace(post=AsyncMock(return_value=response))
    source_session = SimpleNamespace(context=SimpleNamespace(request=request))

    @asynccontextmanager
    async def scope(profile):
        assert profile == "erp-me"
        yield dict(ERP_ID)
        if state.replace_target:
            target_vault.clear_session("drp-me")
            target_vault.save_session("drp-me", {}, {"company_id": "501", "user_id": "601"})
        if state.exit_failure:
            raise ConnectorError("IDENTITY_CHANGED", "fixture source changed on scope exit")

    source = SimpleNamespace(vault=source_vault, close=AsyncMock(), browser=SimpleNamespace(
        verified_scope=scope, _sessions={"erp-me": source_session}, _assert_scope=lambda *args: None))

    async def accept(profile, token, identity):
        assert profile == "drp-me"
        state.identities.append(identity)
        state.tokens.append(token)
        target_vault.save_session(profile, {"cookies": [{"name": "DISTRYBUTION_TOKEN", "value": token}]}, DRP_ID)
        binding = target_vault.session_binding(profile)
        if state.source_changed:
            source_vault.clear_session("erp-me")
            source_vault.save_session("erp-me", {}, ERP_ID)
        return {"status": "connected", "identity": DRP_ID, "_issued_binding": binding}

    async def discard(profile, binding):
        return target_vault.clear_session(profile, expected_binding=binding)

    async def status(profile):
        saved = target_vault.load_session(profile)
        return {"status": "connected" if saved else "disconnected", "identity": saved and saved["identity"]}

    async def login_status(profile):
        return {"status": "connected" if target_vault.load_session(profile) else "disconnected"}

    browser = SimpleNamespace(accept_erp_token=AsyncMock(side_effect=accept), discard_if_binding=AsyncMock(side_effect=discard),
                              status=status, login_status=login_status,
                              close=AsyncMock(), close_idle=AsyncMock())
    target = ConnectorService(target_root, platform="drp", vault=target_vault, browser=browser)
    links = ErpLinks(target_root, target_vault)
    links.pair("drp-me", source_root, "erp-me")
    return SimpleNamespace(source=source, target=target, request=request, response=response, state=state,
                           factory=lambda *a, **kw: source, links=links)


async def test_trusted_erp_exchange_saves_distinct_drp_identity_without_leaking_tokens(bridge):
    result = await connect_from_erp(bridge.target, "drp-me", source_factory=bridge.factory)
    assert result == {"ok": True, "login": {"status": "connected", "identity": DRP_ID}}
    assert bridge.state.identities == [ERP_ID] and bridge.state.tokens == [SCM_TOKEN]
    args, options = bridge.request.post.call_args
    assert args == (REDIRECT_TOKEN_URL,)
    assert options["data"] == {"data": {}, "uid": 201, "coid": 101}
    assert options["max_redirects"] == 0
    assert "private-erp-cookie" not in json.dumps(options)
    assert SCM_TOKEN not in json.dumps(result) and "_issued_binding" not in json.dumps(result)
    bridge.response.dispose.assert_awaited_once()
    bridge.source.close.assert_awaited_once()


async def test_scope_exit_failure_rolls_back_only_this_drp_login(bridge):
    bridge.state.exit_failure = True
    with pytest.raises(ConnectorError):
        await connect_from_erp(bridge.target, "drp-me", source_factory=bridge.factory)
    assert bridge.target.vault.load_session("drp-me") is None
    bridge.target.browser.discard_if_binding.assert_awaited_once()


async def test_rollback_does_not_delete_a_later_valid_drp_login(bridge):
    bridge.state.exit_failure = bridge.state.replace_target = True
    with pytest.raises(ConnectorError):
        await connect_from_erp(bridge.target, "drp-me", source_factory=bridge.factory)
    assert bridge.target.vault.load_session("drp-me")["identity"] == {"company_id": "501", "user_id": "601"}


async def test_source_binding_rotation_after_exchange_revokes_this_target(bridge):
    bridge.state.source_changed = True
    with pytest.raises(ConnectorError):
        await connect_from_erp(bridge.target, "drp-me", source_factory=bridge.factory)
    assert bridge.target.vault.load_session("drp-me") is None


@pytest.mark.parametrize("changed", ["redirect", "business_failure", "missing_token", "another_employee"])
async def test_unverified_or_unpaired_exchange_never_reaches_drp(bridge, changed):
    if changed == "redirect":
        bridge.response.url = "https://untrusted.example/token"
    elif changed == "business_failure":
        bridge.response.body.return_value = b'{"code":9,"act":0}'
    elif changed == "missing_token":
        bridge.response.body.return_value = b'{"code":0,"act":0,"data":{}}'
    with pytest.raises(ConnectorError):
        await connect_from_erp(bridge.target, "other-person" if changed == "another_employee" else "drp-me",
                               source_factory=bridge.factory)
    bridge.target.browser.accept_erp_token.assert_not_awaited()


def test_model_bearer_cannot_supply_erp_token_or_pairing_for_login(bridge):
    token = bridge.target.vault.ensure_client("drp-me")
    with TestClient(create_app(bridge.target)) as client:
        result = client.post("/api/login-from-erp", json={"token": SCM_TOKEN, "source_profile": "erp-me"},
                             headers={"Authorization": "Bearer " + token, "X-JST-Platform": "drp"})
        assert result.status_code == 409
    store = EmployeeStore(bridge.target.root, bridge.target.vault)
    issued = store.create_employee("alice", "fixture-long-enough-password")
    with TestClient(create_remote_app(bridge.target, "https://connector.example.com", employees=store),
                    base_url="https://connector.example.com") as client:
        response = client.post("/portal/connection/login-from-erp", json={"token": SCM_TOKEN},
            headers={"Authorization": "Bearer " + issued["access_token"], "Origin": "https://connector.example.com"})
        assert response.status_code == 401
    bridge.target.browser.accept_erp_token.assert_not_awaited()


def test_paired_erp_connects_from_personal_login_page_in_real_chromium(bridge, monkeypatch):
    from urllib.parse import urlencode

    from playwright.sync_api import expect, sync_playwright

    async def paired(service, profile):
        return await connect_from_erp(service, profile, source_factory=bridge.factory)
    monkeypatch.setattr("jst_connector.erp_sso.connect_from_erp", paired)
    origin = "http://127.0.0.1:19738"
    with TestClient(create_app(bridge.target), base_url=origin) as client, sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))

        def only_fixture(route):
            assert route.request.url.startswith(origin + "/")
            response = client.request(route.request.method, route.request.url,
                                      headers=route.request.headers, content=route.request.post_data)
            route.fulfill(status=response.status_code, headers=dict(response.headers), body=response.content)

        page.route("**/*", only_fixture)
        page.goto(origin + "/ui#" + urlencode({"profile": "drp-me", "token": bridge.target.vault.manager_token()}))
        assert page.locator("iframe").count() == 0
        expect(page.locator("#erp-connect")).to_be_visible()
        page.get_by_role("button", name="使用已登录的ERP接续分销", exact=True).click()
        expect(page.locator("#connected-area")).to_be_visible()
        assert bridge.target.vault.load_session("drp-me")["identity"] == DRP_ID
        assert bridge.request.post.await_count == 1 and not errors
        browser.close()
