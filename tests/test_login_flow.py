"""后台登录专项：只用新建加密资料及离线浏览器，不访问ERP或旧凭据。"""
import asyncio
import json
import time
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from jst_connector.adapters.login import AUTH_POST_URLS, LOGIN_TERMS, LOGIN_URL
from jst_connector.browser import BrowserManager, auth_response_schema
from jst_connector.errors import ConnectorError
from jst_connector.login_flow import PasswordLoginFlows, auth_login_signal, login_site_mode
from jst_connector.vault import Vault

PROFILE = "codex"
IDENTITY = {"company_id": "101", "user_id": "201"}
ACCOUNT = "dummy-account-example"
PASSWORD = "DUMMY-ONLY-PASSWORD-123"


class Context:
    def __init__(self, state):
        self.state = state or {"cookies": [], "origins": [], "fresh": True}
        self.closed = False
        self.page = SimpleNamespace(url=LOGIN_URL)

        async def goto(url, **kwargs):
            self.page.url = url

        self.page.goto = goto

    async def new_page(self):
        return self.page

    async def route(self, pattern, handler):
        self.handler = handler

    def on(self, event, handler):
        pass

    async def storage_state(self):
        return self.state

    async def close(self):
        self.closed = True


class Driver:
    def __init__(self, outcomes):
        self.outcomes = iter(outcomes)
        self.passwords = 0
        self.sends = 0
        self.codes = 0
        self.notices = 0
        self.notice_result = True

    async def password(self, username, password, terms_accepted):
        assert terms_accepted is True
        self.passwords += 1

    async def send(self):
        self.sends += 1

    async def code(self, code):
        self.codes += 1

    async def outcome(self, session, revision):
        await asyncio.sleep(0)
        return next(self.outcomes)

    async def notice(self):
        self.notices += 1
        return self.notice_result


def make_manager(tmp_path, outcomes=("authenticated",), verifier=None, key=None, **flow_options):
    vault = Vault(tmp_path, key=key or Fernet.generate_key())
    contexts = []
    driver = Driver(outcomes)

    async def factory(state):
        context = Context(state)
        contexts.append(context)
        return context

    manager = BrowserManager(vault, context_factory=factory, identity_verifier=verifier, idle_seconds=0)
    manager._password_flows = PasswordLoginFlows(manager, driver_factory=lambda page: driver,
                                                  password_cooldown=0, **flow_options)
    return manager, vault, contexts, driver


async def verified(context):
    return dict(IDENTITY)


async def wait_for(manager, expected):
    # The production notice driver can wait 3s for a dialog and 3s for a click/navigation.
    # Use wall-clock budget, rather than assuming a fixed number of 2ms event-loop turns.
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        status = await manager.login_status(PROFILE)
        if status["status"] == expected:
            return status
        await asyncio.sleep(0.01)
    raise AssertionError("后台登录未达到预期状态：" + str(status))


async def begin(manager, remember=False):
    return await manager.password_login(PROFILE, ACCOUNT, PASSWORD, remember, terms_accepted=True)


@pytest.mark.asyncio
async def test_nonblocking_single_flight_normal_login_never_sends_sms_without_request(tmp_path):
    manager, vault, contexts, driver = make_manager(tmp_path)
    results = await asyncio.gather(*(begin(manager) for _ in range(8)))
    assert all(result["status"] == "starting" for result in results)
    result = await wait_for(manager, "identity_pending")
    assert len(contexts) == driver.passwords == 1 and driver.sends == 0
    assert not result["can_send_code"] and vault.load_session(PROFILE) is None
    assert ACCOUNT not in json.dumps(result) and PASSWORD not in json.dumps(result)
    await manager.close_idle()
    assert not contexts[0].closed  # Active login has an explicit TTL, not the business idle timeout.
    await manager.cancel_login(PROFILE)
    assert contexts[0].closed
    attempt = manager._password_flows.attempts[PROFILE]
    assert not attempt.username and not attempt.password and attempt.queue.empty()
    assert (await manager.login_status(PROFILE))["status"] == "cancelled"


@pytest.mark.asyncio
async def test_verified_login_remembers_only_after_success_and_idle_preserves_encrypted_credentials(tmp_path):
    manager, vault, contexts, driver = make_manager(tmp_path, verifier=verified)
    await begin(manager, remember=True)
    result = await wait_for(manager, "connected")
    assert result["remember_password"] and (await manager.status(PROFILE))["status"] == "connected"
    assert vault.load_session(PROFILE)["credentials"]["password"] == PASSWORD
    assert PASSWORD.encode() not in (tmp_path / "vault.enc").read_bytes()
    assert not manager._password_flows.attempts[PROFILE].password
    await manager.close_idle()
    assert contexts[0].closed and vault.load_session(PROFILE)["credentials"]["password"] == PASSWORD
    assert driver.sends == 0
    await manager.logout(PROFILE)
    assert vault.load_session(PROFILE) is None
    assert (await manager.login_status(PROFILE))["status"] == "disconnected"


@pytest.mark.asyncio
async def test_terms_and_typed_flags_are_required_before_any_browser_or_authentication(tmp_path):
    manager, _, contexts, driver = make_manager(tmp_path)
    for options in ({}, {"terms_accepted": False}, {"terms_accepted": "true"},
                    {"terms_accepted": True, "remember": "false"}):
        with pytest.raises(ConnectorError):
            await manager.password_login(PROFILE, ACCOUNT, PASSWORD, **options)
    assert not contexts and not driver.passwords and not manager._password_flows.attempts


@pytest.mark.asyncio
async def test_initial_status_restores_trusted_saved_state_without_reentering_credentials(tmp_path):
    manager, vault, contexts, driver = make_manager(tmp_path, verifier=verified)
    vault.save_session(PROFILE, {"cookies": [], "origins": []}, IDENTITY)
    assert (await manager.status(PROFILE))["status"] == "saved_unverified"
    assert (await manager.login_status(PROFILE))["status"] == "starting"
    await wait_for(manager, "connected")
    assert len(contexts) == 1 and driver.passwords == driver.sends == 0
    await manager.close()


@pytest.mark.asyncio
async def test_saved_state_without_identity_adapter_is_preserved_and_not_called_connected(tmp_path):
    manager, vault, _contexts, driver = make_manager(tmp_path)
    vault.save_session(PROFILE, {"cookies": [], "origins": []}, IDENTITY)
    original_binding = vault.session_binding(PROFILE)
    assert (await manager.login_status(PROFILE))["status"] == "identity_pending"
    with pytest.raises(ConnectorError):
        await manager.identity(PROFILE)
    assert (await manager.status(PROFILE))["status"] == "saved_unverified"
    assert vault.session_binding(PROFILE) == original_binding and driver.passwords == driver.sends == 0
    await manager.close()


@pytest.mark.asyncio
async def test_failed_verifier_does_not_mark_restored_session_as_verified(tmp_path):
    async def expired(context):
        raise ConnectorError("ERP_SESSION_REJECTED", "测试过期")

    manager, vault, _, _ = make_manager(tmp_path, verifier=expired)
    vault.save_session(PROFILE, {"cookies": [], "origins": []}, IDENTITY)
    with pytest.raises(ConnectorError):
        await manager.identity(PROFILE)
    assert (await manager.status(PROFILE))["status"] == "saved_unverified"
    await manager.close()


@pytest.mark.asyncio
async def test_only_expired_remembered_session_replays_password_once_without_sms(tmp_path):
    async def verifier(context):
        if not context.state.get("fresh"):
            raise ConnectorError("SESSION_EXPIRED", "测试过期")
        return dict(IDENTITY)

    manager, vault, _, driver = make_manager(tmp_path, verifier=verifier)
    vault.save_session(PROFILE, {"cookies": [], "origins": [], "fresh": False}, IDENTITY,
                       credentials={"username": ACCOUNT, "password": PASSWORD, "terms_accepted": True})
    await manager.login_status(PROFILE)
    await wait_for(manager, "connected")
    assert driver.passwords == 1 and driver.sends == 0
    await manager.close()


@pytest.mark.asyncio
async def test_sms_requires_explicit_click_then_acknowledgement_and_valid_six_digit_input(tmp_path):
    manager, _, _, driver = make_manager(tmp_path, ("need_code", "code_sent", "authenticated"), verifier=verified)
    with pytest.raises(ConnectorError):
        await manager.send_login_code(PROFILE)
    await begin(manager)
    await wait_for(manager, "need_code")
    assert driver.sends == 0
    with pytest.raises(ConnectorError):
        await manager.submit_login_code(PROFILE, "123456")
    await manager.send_login_code(PROFILE)
    with pytest.raises(ConnectorError) as error:
        await manager.send_login_code(PROFILE)
    assert error.value.code == "LOGIN_RATE_LIMITED"
    for _ in range(100):
        result = await manager.login_status(PROFILE)
        if result.get("code_sent"):
            break
        await asyncio.sleep(0.002)
    for invalid in (123456, True, "1234", "１２３４５６", {"code": "123456"}):
        with pytest.raises(ConnectorError):
            await manager.submit_login_code(PROFILE, invalid)
    await manager.submit_login_code(PROFILE, "123456")
    await wait_for(manager, "connected")
    assert driver.sends == driver.codes == 1
    await manager.close()


@pytest.mark.asyncio
async def test_unadapted_graphic_or_risk_challenge_never_becomes_sms_step(tmp_path):
    manager, vault, contexts, driver = make_manager(tmp_path, ("unsupported",))
    await begin(manager)
    status = await wait_for(manager, "failed")
    assert not status["can_send_code"] and not driver.sends and vault.load_session(PROFILE) is None
    assert status["error_code"] == "LOGIN_FLOW_UNADAPTED" and "未适配" in status["message"]
    assert contexts[0].closed


@pytest.mark.asyncio
async def test_code_guess_limit_and_sms_cooldown_survive_cancel_restart(tmp_path):
    manager, _, _, driver = make_manager(tmp_path, ["need_code", "code_sent"] + ["code_rejected"] * 5 + ["need_code"],
                                         code_cooldown=0)
    await begin(manager)
    await wait_for(manager, "need_code")
    await manager.send_login_code(PROFILE)
    for _ in range(100):
        if (await manager.login_status(PROFILE)).get("code_sent"):
            break
        await asyncio.sleep(0.002)
    for _ in range(5):
        await manager.submit_login_code(PROFILE, "123456")
        await wait_for(manager, "need_code")
    with pytest.raises(ConnectorError) as error:
        await manager.submit_login_code(PROFILE, "123456")
    assert error.value.code == "LOGIN_RATE_LIMITED"
    await manager.cancel_login(PROFILE)
    await begin(manager)
    status = await wait_for(manager, "need_code")
    assert not status["can_send_code"] and status["code_retry_after_seconds"] > 0
    with pytest.raises(ConnectorError):
        await manager.send_login_code(PROFILE)
    assert driver.sends == 1 and driver.codes == 5
    await manager.close()


@pytest.mark.asyncio
async def test_expiry_cancel_and_logout_never_save_unverified_or_late_results(tmp_path):
    manager, vault, contexts, _ = make_manager(tmp_path, ("need_code",), ttl=0.03)
    await begin(manager, remember=True)
    await wait_for(manager, "expired")
    assert contexts[0].closed and vault.load_session(PROFILE) is None
    assert not manager._password_flows.attempts[PROFILE].password
    await manager.logout(PROFILE)
    assert (await manager.login_status(PROFILE))["status"] == "disconnected"


@pytest.mark.asyncio
async def test_cancel_while_identity_verifier_is_running_cannot_commit_credentials(tmp_path):
    entered = asyncio.Event()

    async def slow_verifier(context):
        entered.set()
        try:
            await asyncio.Future()
        except asyncio.CancelledError:
            return dict(IDENTITY)  # Even a badly behaved verifier cannot commit after cancellation.

    manager, vault, contexts, _ = make_manager(tmp_path, verifier=slow_verifier)
    await begin(manager, remember=True)
    await asyncio.wait_for(entered.wait(), timeout=1)
    await manager.cancel_login(PROFILE)
    assert vault.load_session(PROFILE) is None and contexts[0].closed
    assert (await manager.login_status(PROFILE))["status"] == "cancelled"


@pytest.mark.asyncio
async def test_worker_errors_never_publish_original_password_or_exception(tmp_path, capsys):
    manager, _, _, driver = make_manager(tmp_path)

    async def fail(*args):
        raise RuntimeError(PASSWORD)

    driver.password = fail
    await begin(manager)
    status = await wait_for(manager, "failed")
    assert PASSWORD not in json.dumps(status) and PASSWORD not in repr(manager._password_flows.attempts[PROFILE])
    capture = capsys.readouterr()
    assert PASSWORD not in capture.out + capture.err


class Route:
    def __init__(self, url):
        self.request = SimpleNamespace(method="POST", url=url, resource_type="xhr", post_data_json={})
        self.allowed = False
        self.blocked = False

    async def fetch(self, **kwargs):
        assert kwargs["max_redirects"] == 0
        return self

    status = 200

    async def dispose(self):
        pass

    async def fulfill(self, **kwargs):
        self.allowed = True

    async def abort(self, reason):
        self.blocked = True


@pytest.mark.asyncio
async def test_route_enforces_one_auth_post_and_no_automatic_sms_during_password_or_polling(tmp_path):
    manager, _, _, _ = make_manager(tmp_path, ("need_code",))
    await begin(manager)
    await wait_for(manager, "need_code")
    session = manager._sessions[PROFILE]
    send_url = next(url for url in AUTH_POST_URLS if url.endswith("/SendIdaasVerification"))
    auto = Route(send_url)
    await manager._route(session, auto)
    assert auto.blocked
    manager._grant_login_action(session, "password")
    still_auto = Route(send_url)
    await manager._route(session, still_auto)
    assert still_auto.blocked
    manager._grant_login_action(session, "send")
    first, repeated = Route(send_url), Route(send_url)
    await manager._route(session, first)
    await manager._route(session, repeated)
    assert first.allowed and repeated.blocked
    await manager.close()


def test_authentication_signal_is_not_employee_identity_and_terms_are_fixed_official_sources():
    passport = "https://api.erp321.com/erp/webapi/UserApi/WebLogin/Passport"
    assert auth_login_signal(passport, {"code": 0, "data": {"isTPWS": 0}}) == "authenticated"
    assert auth_login_signal(passport, {"code": 0, "data": {"idaasHasRisk": True}}) == "need_code"
    assert auth_login_signal(passport, {"code": 10003, "data": {}}) == "unsupported"
    assert LOGIN_TERMS == {"agreement_url": "https://app.jushuitan.com/doc/regUserAgreement.html",
                           "privacy_url": "https://app.jushuitan.com/doc/regPrivacy.html"}


@pytest.mark.parametrize("data,expected", [
    ({"isTPWS": 0, "hasRisk": False, "idaasHasRisk": False, "msg": "DUMMY-NOTICE"}, "login_notice"),
    ({"isTPWS": 1, "hasRisk": False, "idaasHasRisk": False, "msg": "DUMMY-NOTICE"}, "site_mismatch"),
    ({"isTPWS": 0.0, "hasRisk": False, "idaasHasRisk": False, "msg": "DUMMY-NOTICE"}, "login_notice"),
    ({"isTPWS": 1.0, "hasRisk": False, "idaasHasRisk": False, "msg": "DUMMY-NOTICE"}, "site_mismatch"),
    ({"isTPWS": 2, "hasRisk": False, "idaasHasRisk": False, "msg": "DUMMY-NOTICE"}, "login_notice"),
    ({"isTPWS": False, "hasRisk": False, "idaasHasRisk": False, "msg": "DUMMY-NOTICE"}, "login_notice"),
    ({"isTPWS": "1", "hasRisk": False, "idaasHasRisk": False, "msg": "DUMMY-NOTICE"}, "login_notice"),
    ({"isTPWS": 0, "hasRisk": False, "msg": "DUMMY-NOTICE"}, "notice_unverified"),
    ({"isTPWS": 0, "hasRisk": True, "idaasHasRisk": False, "msg": "DUMMY-NOTICE"}, "unsupported"),
])
def test_notice_signal_requires_precise_flags_and_matching_erp_site(data, expected):
    assert auth_login_signal("https://api.erp321.com/erp/webapi/UserApi/WebLogin/Passport", {"code": 0, "data": data}) == expected


@pytest.mark.parametrize("value,expected", [(0, "0"), (0.0, "0"), (1, "1"), (1.0, "1"),
                                           (2, "other_numeric"), (1.5, "other_numeric"),
                                           (False, None), (True, None), ("1", None), (None, None)])
def test_site_mode_diagnostics_expose_only_finite_enum_categories(value, expected):
    assert login_site_mode(value) == expected


@pytest.mark.asyncio
async def test_ordinary_notice_is_consumed_once_without_auth_permission_or_new_credentials(tmp_path):
    manager, vault, contexts, driver = make_manager(tmp_path, ("login_notice",))
    await begin(manager)
    status = await wait_for(manager, "identity_pending")
    assert driver.passwords == driver.notices == 1 and driver.sends == driver.codes == 0
    assert len(contexts) == 1 and not contexts[0].closed and vault.load_session(PROFILE) is None
    session = manager._sessions[PROFILE]
    assert session.auth_remaining == 0 and not session.auth_urls and session.auth_deadline == 0
    assert status["status"] != "connected"
    await manager.close()


@pytest.mark.parametrize("signal", ["login_notice", "notice_unverified", "site_mismatch"])
@pytest.mark.asyncio
async def test_unknown_notice_or_site_switch_keeps_same_context_without_repeating_auth(tmp_path, signal):
    manager, vault, contexts, driver = make_manager(tmp_path, (signal,))
    driver.notice_result = False
    await begin(manager, remember=True)
    status = await wait_for(manager, "notice_pending")
    await manager.close_idle()
    assert len(contexts) == 1 and not contexts[0].closed and not status["can_send_code"]
    assert driver.passwords == 1 and driver.sends == driver.codes == 0
    assert driver.notices == (1 if signal == "login_notice" else 0)
    assert vault.load_session(PROFILE) is None
    with pytest.raises(ConnectorError):
        await manager.send_login_code(PROFILE)
    await manager.cancel_login(PROFILE)
    assert contexts[0].closed


def test_risk_response_diagnostics_only_expose_types():
    assert auth_response_schema({"data": {"idaasHasRisk": True, "hasRisk": False}}) == {
        "data": {"idaasHasRisk": "boolean", "hasRisk": "boolean"}}


@pytest.mark.asyncio
async def test_password_and_sms_window_counts_cannot_be_reset_by_cancelling(tmp_path):
    manager, _, _, driver = make_manager(tmp_path, ["need_code", "code_sent"] * 3 + ["need_code"], send_cooldown=0)
    for _ in range(3):
        await begin(manager)
        await wait_for(manager, "need_code")
        await manager.send_login_code(PROFILE)
        for _ in range(100):
            if (await manager.login_status(PROFILE)).get("code_sent"):
                break
            await asyncio.sleep(0.002)
        await manager.cancel_login(PROFILE)
    await begin(manager)
    status = await wait_for(manager, "need_code")
    assert not status["can_send_code"] and status["retry_after_seconds"] > 0
    with pytest.raises(ConnectorError):
        await manager.send_login_code(PROFILE)
    assert driver.sends == 3
    await manager.cancel_login(PROFILE)
    driver.outcomes = iter(["unsupported"])
    await begin(manager)  # Fifth password submission in this profile/window.
    await wait_for(manager, "failed")
    await begin(manager)  # A sixth attempt is rejected before any new DOM submit.
    await wait_for(manager, "failed")
    assert driver.passwords == 5


@pytest.mark.asyncio
async def test_first_login_cas_rejects_another_process_creating_same_profile_before_commit(tmp_path):
    key = Fernet.generate_key()
    manager, vault, _, _ = make_manager(tmp_path, verifier=verified, key=key)
    other = Vault(tmp_path, key=key)
    save = vault.save_session
    raced = False

    def racing_save(profile, state, identity, credentials=None, *, expected_binding):
        nonlocal raced
        if not raced:
            raced = True
            other.save_session(profile, {"cookies": [], "origins": [], "other_process": True}, IDENTITY,
                               credentials={"username": "other", "password": "OTHER-DUMMY-ONLY"})
        save(profile, state, identity, credentials, expected_binding=expected_binding)

    vault.save_session = racing_save
    await begin(manager, remember=True)
    await wait_for(manager, "failed")
    assert raced and other.load_session(PROFILE)["state"]["other_process"] is True
    assert other.load_session(PROFILE)["credentials"]["password"] == "OTHER-DUMMY-ONLY"
    assert (await manager.status(PROFILE))["status"] == "saved_unverified"
    await manager.close()


@pytest.mark.asyncio
async def test_connected_flow_rechecks_after_idle_and_only_replays_remembered_password_when_expired(tmp_path):
    async def verifier(context):
        if not context.state.get("fresh"):
            raise ConnectorError("SESSION_EXPIRED", "测试服务端过期")
        return dict(IDENTITY)

    manager, vault, contexts, driver = make_manager(tmp_path, ["authenticated", "authenticated"], verifier=verifier)
    await begin(manager, remember=True)
    await wait_for(manager, "connected")
    await manager.close_idle()
    stored = vault.load_session(PROFILE)
    vault.save_session(PROFILE, {**stored["state"], "fresh": False}, IDENTITY, stored["credentials"])
    assert (await manager.login_status(PROFILE))["status"] == "starting"
    await wait_for(manager, "connected")
    assert driver.passwords == 2 and driver.sends == 0
    assert len(contexts) == 3  # Original, stale saved state, one fresh re-login context.
    await manager.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("notice_kind", [None, "ordinary", "ordinary_float", "ordinary_other", "spaced_label", "wrong_title", "extra_input", "extra_iframe", "extra_button", "site_mismatch", "site_mismatch_float"])
async def test_real_chromium_dom_to_single_auth_response_stays_on_loopback(tmp_path, monkeypatch, notice_kind):
    from playwright.async_api import async_playwright

    import jst_connector.browser as browser_module
    import jst_connector.login_flow as flow_module

    requests = []
    extra = {"extra_input": '<input type="password">', "extra_button": '<button>other</button>',
             "extra_iframe": "<iframe></iframe>"}.get(notice_kind, "")
    html = '''<!doctype html><html><head><meta charset="utf-8"></head><body>
      <input id="login_id"><input id="password" type="password">
      <div class="agreement-wrap___WYUPP"><input type="checkbox"></div>
      <button class="login-btn___AGd4D" onclick="submitLogin()">login</button>
      <script>async function submitLogin(){
        const result=await fetch('/erp/webapi/UserApi/WebLogin/Passport',
      {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({data:{
      account:document.querySelector('#login_id').value,password:document.querySelector('#password').value}})}).then(r=>r.json());
        if(result.data.msg){const modal=document.createElement('div');modal.setAttribute('role','dialog');
          modal.innerHTML='<div class="ant-modal-title">__TITLE__</div><p>本机虚构登录提示</p><button type="button">__LABEL__</button>__EXTRA__';
          modal.querySelector('button').onclick=()=>{window.location.href='/epaas'};document.body.appendChild(modal);
        }
      }</script></body></html>'''.replace("__EXTRA__", extra).replace("__TITLE__", "未知操作" if notice_kind == "wrong_title" else "提示").replace("__LABEL__", "确 定" if notice_kind == "spaced_label" else "确定").encode("utf-8")

    async def handler(reader, writer):
        headers = await reader.readuntil(b"\r\n\r\n")
        method, path, _ = headers.split(b"\r\n", 1)[0].split(b" ")
        requests.append((method, path))
        length = 0
        for header in headers.split(b"\r\n"):
            if header.lower().startswith(b"content-length:"):
                length = int(header.split(b":", 1)[1])
        if length:
            await reader.readexactly(length)  # Read and discard; never log submitted dummy credentials.
        data = {"isTPWS": 0}
        if notice_kind:
            mode = {"ordinary_float": 0.0, "ordinary_other": 2,
                    "site_mismatch": 1, "site_mismatch_float": 1.0}.get(notice_kind, 0)
            data.update(isTPWS=mode, hasRisk=False,
                        idaasHasRisk=False, msg="DUMMY-NEVER-RETURN-MSG", href=None)
        body = html if method == b"GET" and path == b"/login" else b"local entry" if method == b"GET" else json.dumps({"code": 0, "data": data}).encode()
        kind = b"text/html" if method == b"GET" else b"application/json"
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: " + kind + b"\r\nContent-Length: "
                     + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    origin = "http://127.0.0.1:" + str(server.sockets[0].getsockname()[1])
    login = origin + "/login"
    auth = origin + "/erp/webapi/UserApi/WebLogin/Passport"
    monkeypatch.setattr(browser_module, "LOGIN_URL", login)
    monkeypatch.setattr(browser_module, "ENTRY_URL", origin + "/epaas")
    monkeypatch.setattr(flow_module, "LOGIN_URL", login)
    monkeypatch.setattr(browser_module, "AUTH_POST_URLS", {auth})
    monkeypatch.setattr(flow_module, "AUTH_POST_URLS", {auth})
    async with async_playwright() as playwright:
        chromium = await playwright.chromium.launch(headless=True)

        async def factory(state):
            return await chromium.new_context(storage_state=state, service_workers="block")

        vault = Vault(tmp_path, key=Fernet.generate_key())
        manager = BrowserManager(vault, context_factory=factory)
        try:
            await begin(manager)
            expected = "identity_pending" if notice_kind in {None, "ordinary", "ordinary_float", "ordinary_other", "spaced_label"} else "notice_pending"
            await wait_for(manager, expected)
            if expected == "notice_pending":
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    state = await manager.login_status(PROFILE)
                    if "尚待核实" in state["message"] or "需要切换登录站点" in state["message"]:
                        break
                    await asyncio.sleep(0.01)
                assert "正在核对" not in state["message"]  # The production DOM guard has actually completed.
            expected_requests = [(b"GET", b"/login"), (b"POST", b"/erp/webapi/UserApi/WebLogin/Passport")]
            if notice_kind in {"ordinary", "ordinary_float", "ordinary_other", "spaced_label"}:
                expected_requests.append((b"GET", b"/epaas"))
            assert requests == expected_requests
            assert vault.load_session(PROFILE) is None
            events = await manager.network_events(PROFILE)
            assert ACCOUNT not in json.dumps(events) and PASSWORD not in json.dumps(events)
            assert "DUMMY-NEVER-RETURN-MSG" not in json.dumps(events)
            assert all(event.get("site_mode") in {None, "0", "1", "other_numeric"} for event in events["events"])
            assert len(chromium.contexts) == 1 and len(chromium.contexts[0].pages) == 1
        finally:
            await manager.close()
            await chromium.close()
            server.close()
            await server.wait_closed()
