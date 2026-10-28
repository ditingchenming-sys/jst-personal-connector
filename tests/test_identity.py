"""身份适配器仅用离线响应/临时Vault；不请求ERP、不读真实凭据。"""
import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet
from playwright.async_api import Error as PlaywrightError

from jst_connector.adapters.login import LOGIN_URL
from jst_connector.auth_receipt import PASSPORT_URL
from jst_connector.browser import BrowserManager, _Session, approved_request
from jst_connector.errors import ConnectorError
from jst_connector.identity import GET_USER_INFO_URL, ServerIdentityVerifier
from jst_connector.login_flow import PasswordLoginFlows
from jst_connector.vault import Vault

IDS = {"company_id": "101", "user_id": "201"}
NAMES = {"company_name": "本机测试公司", "user_name": "测试员工"}
VALUE = {"code": 0, "act": 0, "data": {"coId": 101, "uid": 201,
         "companyName": NAMES["company_name"], "userName": NAMES["user_name"], "isAdmin": False, "apps": ""}}


class Response:
    def __init__(self, value=None, *, status=200, url=GET_USER_INFO_URL, raw=None):
        self.status, self.url = status, url
        self.raw = json.dumps(VALUE if value is None else value).encode() if raw is None else raw
        self.disposed = False

    async def body(self):
        return self.raw

    async def dispose(self):
        self.disposed = True


def session_for(response=None, *, fresh=True):
    post = AsyncMock(return_value=response or Response())
    context = SimpleNamespace(request=SimpleNamespace(post=post),
                              cookies=AsyncMock(side_effect=AssertionError("不得从Jar取得身份")))
    session = _Session(context, SimpleNamespace(), login=fresh, controlled_login=fresh,
                       vault_binding=None if fresh else "encrypted-vault-binding")
    if fresh:
        session.server_passport_receipted = True
        session.server_identity_candidate = dict(IDS)
        session.server_identity_sources = {key: {"response_url": PASSPORT_URL, "method": "POST", "via": "set-cookie",
                                                "cookie_name": cookie}
                                           for key, cookie in (("company_id", "u_co_id"), ("user_id", "u_id"))}
    else:
        session.identity = dict(IDS)
    return session


@pytest.mark.asyncio
@pytest.mark.parametrize("fresh", [True, False])
async def test_exact_server_identity_request_matches_receipt_or_vault_and_returns_display_only_names(fresh):
    response = Response()
    session = session_for(response, fresh=fresh)
    assert await ServerIdentityVerifier().verify_session(session) == {**IDS, **NAMES}
    session.context.request.post.assert_awaited_once_with(
        GET_USER_INFO_URL, data={"data": {}, "uid": 201, "coid": 101},
        headers={"Content-Type": "application/json", "Referer": "https://www.erp321.com/epaas"},
        max_redirects=0, timeout=15000)
    session.context.cookies.assert_not_awaited()
    assert response.disposed and not session.verified
    assert not approved_request("POST", GET_USER_INFO_URL, {"data": {}, "uid": 201, "coid": 101})


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["no_receipt", "conflict", "missing_source", "foreign_source", "no_candidate", "no_binding"])
async def test_unproven_private_expected_identity_is_rejected_before_request(mutation):
    session = session_for(fresh=mutation != "no_binding")
    if mutation == "no_receipt":
        session.server_passport_receipted = False
    elif mutation == "conflict":
        session.server_identity_conflicted = True
    elif mutation == "missing_source":
        session.server_identity_sources.clear()
    elif mutation == "foreign_source":
        session.server_identity_sources["user_id"]["response_url"] = "https://example.test/"
    elif mutation == "no_candidate":
        session.server_identity_candidate.clear()
    else:
        session.vault_binding = None
    with pytest.raises(ConnectorError):
        await ServerIdentityVerifier().verify_session(session)
    session.context.request.post.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("options", [
    {"status": 302}, {"status": 401}, {"status": 500}, {"url": GET_USER_INFO_URL + "?uid=201"},
    {"raw": b"{}"}, {"raw": b"not-json-with-private-material"}, {"raw": b"x" * 262145},
    {"value": {**VALUE, "code": False}}, {"value": {**VALUE, "act": False}},
    {"value": {**VALUE, "code": 1}}, {"value": {**VALUE, "act": 1}},
    {"value": {**VALUE, "data": {**VALUE["data"], "coId": 999}}},
    {"value": {**VALUE, "data": {**VALUE["data"], "uid": 999}}},
    {"value": {**VALUE, "data": {**VALUE["data"], "uid": True}}},
    {"value": {**VALUE, "data": {**VALUE["data"], "uid": 201.0}}},
    {"value": {**VALUE, "data": {**VALUE["data"], "coId": "101"}}},
])
async def test_failure_redirect_wrong_identity_or_schema_never_becomes_verified(options):
    response = Response(**options)
    session = session_for(response)
    with pytest.raises(ConnectorError) as error:
        await ServerIdentityVerifier().verify_session(session)
    assert "private-material" not in str(error.value) and response.disposed and not session.verified


class Context:
    def __init__(self, response):
        self.request = SimpleNamespace(post=AsyncMock(return_value=response))
        self.page = SimpleNamespace(url=LOGIN_URL, goto=AsyncMock())
        self.cookies = AsyncMock(side_effect=AssertionError("不得从Jar取得身份"))
        self.close = AsyncMock()

    async def new_page(self):
        return self.page

    async def route(self, pattern, handler):
        pass

    def on(self, event, handler):
        pass

    async def storage_state(self):
        return {"cookies": [], "origins": []}


def manager_for(tmp_path, *, response=None, key=None):
    vault = Vault(tmp_path, key=key or Fernet.generate_key())
    contexts = []

    async def factory(state):
        context = Context(response or Response())
        contexts.append(context)
        return context

    manager = BrowserManager(vault, context_factory=factory, identity_verifier=ServerIdentityVerifier(), idle_seconds=0)
    passwords = []

    class Driver:
        async def password(self, username, password, terms_accepted):
            passwords.append(True)

        async def outcome(self, session, revision):
            # Fake upstream HTTP receipt, run through the real collector and its active-attempt guards.
            upstream = SimpleNamespace(url=PASSPORT_URL, status=200,
                body=AsyncMock(return_value=b'{"code":0}'), headers_array=[
                    {"name": "Set-Cookie", "value": "u_id=201; Domain=.erp321.com; Path=/"},
                    {"name": "Set-Cookie", "value": "u_co_id=101; Domain=.erp321.com; Path=/"}])
            await manager._capture_server_identity_receipt(session, SimpleNamespace(method="POST", url=PASSPORT_URL), upstream)
            return "authenticated"

    manager._password_flows = PasswordLoginFlows(manager, driver_factory=lambda page: Driver(), password_cooldown=0)
    return manager, vault, contexts, passwords


async def settled(manager):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        state = await manager.login_status("codex")
        if state["status"] in {"connected", "failed", "cancelled"}:
            return state
        await asyncio.sleep(0.01)
    raise AssertionError("离线身份接线未完成")


@pytest.mark.asyncio
async def test_fresh_login_verified_before_cas_save_names_do_not_enter_identity_binding(tmp_path):
    manager, vault, contexts, passwords = manager_for(tmp_path)
    await manager.password_login("codex", "dummy-test", "DUMMY-ONLY", terms_accepted=True)
    assert (await settled(manager))["status"] == "connected"
    assert vault.load_session("codex")["identity"] == IDS
    assert vault.load_session("codex")["credentials"] is None
    status = await manager.status("codex")
    assert status["status"] == "connected" and status["identity"] == IDS and status["identity_display"] == NAMES
    assert passwords == [True]
    contexts[0].cookies.assert_not_awaited()
    await manager.close()


@pytest.mark.asyncio
async def test_status_after_restart_restores_by_server_current_identity_without_password_or_new_receipt(tmp_path):
    manager, vault, contexts, passwords = manager_for(tmp_path)
    vault.save_session("codex", {"cookies": [], "origins": []}, IDS)
    status = await manager.status("codex")
    assert status["status"] == "connected" and status["identity_display"] == NAMES
    session = manager._sessions["codex"]
    assert not session.server_passport_receipted and not session.server_identity_candidate
    assert passwords == [] and len(contexts) == 1
    assert vault.load_session("codex")["identity"] == IDS
    await manager.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["expired", "mismatch", "timeout"])
async def test_failed_restore_status_is_unverified_and_never_submits_password(tmp_path, failure):
    response = Response(status=401) if failure == "expired" else Response(value={**VALUE, "data": {**VALUE["data"], "uid": 999}})
    manager, vault, contexts, passwords = manager_for(tmp_path, response=response)
    vault.save_session("codex", {"cookies": [], "origins": []}, IDS)
    if failure == "timeout":
        await manager._open("codex")
        contexts[0].request.post.side_effect = PlaywrightError("PRIVATE-TRANSPORT-ERROR")
    status = await manager.status("codex")
    assert status["status"] == "saved_unverified" and status["identity_display"] == {}
    assert "PRIVATE" not in json.dumps(status) and passwords == []
    assert not manager._sessions["codex"].verified
    await manager.close()


@pytest.mark.asyncio
async def test_cancel_during_identity_request_cannot_save_connected_or_display_names(tmp_path):
    entered, release = asyncio.Event(), asyncio.Event()

    async def block():
        await entered.wait()
        await manager.cancel_login("codex")
        release.set()

    async def slow_body():
        entered.set()
        await release.wait()
        return json.dumps(VALUE).encode()

    response = Response()
    response.body = slow_body
    manager, vault, contexts, _ = manager_for(tmp_path, response=response)
    cancel = asyncio.create_task(block())
    await manager.password_login("codex", "dummy-test", "DUMMY-ONLY", terms_accepted=True)
    await cancel
    assert (await manager.login_status("codex"))["status"] == "cancelled"
    assert vault.load_session("codex") is None and "codex" not in manager._sessions
    assert contexts[0].close.await_count == 1
    await manager.close()


@pytest.mark.asyncio
async def test_cross_process_first_save_cas_still_rejects_late_identity_success(tmp_path):
    key = Fernet.generate_key()
    response = Response()
    other = Vault(tmp_path, key=key)

    async def race_body():
        other.save_session("codex", {"cookies": [], "origins": [], "other_process": True}, IDS)
        return json.dumps(VALUE).encode()

    response.body = race_body
    manager, vault, _, _ = manager_for(tmp_path, response=response, key=key)
    await manager.password_login("codex", "dummy-test", "DUMMY-ONLY", terms_accepted=True)
    assert (await settled(manager))["status"] == "failed"
    assert vault.load_session("codex")["state"]["other_process"] is True
    assert "codex" not in manager._sessions
    await manager.close()


@pytest.mark.asyncio
async def test_receipt_deleted_while_current_user_response_is_pending_cannot_connect():
    response = Response()
    session = session_for(response)

    async def tainted_body():
        session.server_identity_conflicted = True
        session.server_identity_candidate.clear()
        return json.dumps(VALUE).encode()

    response.body = tainted_body
    with pytest.raises(ConnectorError):
        await ServerIdentityVerifier().verify_session(session)
