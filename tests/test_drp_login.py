import base64
import hashlib
import json
import time
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

from jst_connector.browser import _Session
from jst_connector.drp import (
    _LOGIN_ASSETS,
    AUTH_BASE,
    ENCRYPT_KEY_URL,
    ERP_TOKEN_URL,
    LOGIN_URL,
    PASSWORD_URL,
    SEND_CODE_URL,
    SUBMIT_CODE_URL,
    TOKEN_COOKIE,
    USER_INFO_URL,
    DrpBrowserManager,
    DrpClient,
    DrpIdentityVerifier,
    DrpLoginDriver,
    _token_identity,
)
from jst_connector.errors import ConnectorError
from jst_connector.vault import Vault


def token(company="200", user="300", **extra):
    payload = {"user": {"coId": company, "uid": user}, **extra}
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return "fixture." + encoded + ".signature"


def cookie(value):
    return {"name": TOKEN_COOKIE, "value": value, "domain": ".scm121.com", "path": "/", "secure": True}


class Response:
    def __init__(self, url=USER_INFO_URL, value=None, status=200):
        self.url, self.status = url, status
        self.value = value if value is not None else {"success": True, "data": {
            "coId": 200, "coName": "测试分销公司", "coCompanyUser": {"uid": 300, "userName": "测试员工"}}}
        self.disposed = False

    async def body(self):
        return json.dumps(self.value).encode()

    async def text(self):
        return json.dumps(self.value)

    async def dispose(self):
        self.disposed = True


class Context:
    def __init__(self, state=None):
        self.state = state or {"cookies": [], "origins": []}
        self.calls, self.closed, self.interceptor = [], False, None
        self.response = Response()
        self.page = SimpleNamespace(url="about:blank")
        self.page.goto = self.goto
        self.request = SimpleNamespace(get=self.get)

    async def get(self, url, **options):
        self.calls.append((url, options))
        return self.response

    async def cookies(self, urls):
        return list(self.state["cookies"])

    async def add_cookies(self, cookies):
        self.state["cookies"] = list(cookies)

    async def storage_state(self):
        return self.state

    async def new_page(self):
        return self.page

    async def goto(self, url, **options):
        self.page.url = url

    async def route(self, pattern, callback):
        self.interceptor = callback

    def on(self, name, callback):
        pass

    async def close(self):
        self.closed = True


def login_session():
    value = token()
    context = Context({"cookies": [cookie(value)], "origins": []})
    session = _Session(context, context.page, login=True, controlled_login=True)
    session.server_passport_receipted = True
    session.server_identity_candidate = {"company_id": "200", "user_id": "300"}
    session.server_identity_sources = {key: {"via": "authentication-response", "response_url": PASSWORD_URL,
                                            "method": "POST"} for key in session.server_identity_candidate}
    session.drp_receipt_digest = hashlib.sha256(value.encode()).hexdigest()
    return session


@pytest.fixture
def manager(tmp_path):
    vault = Vault(tmp_path, key=Fernet.generate_key())
    contexts = []
    async def factory(state):
        context = Context(state)
        contexts.append(context)
        return context
    browser = DrpBrowserManager(vault, context_factory=factory)
    return browser, contexts


async def test_drp_identity_is_checked_by_fixed_server_not_cookie_claims():
    session = login_session()
    result = await DrpIdentityVerifier().verify_session(session)
    assert result == {"company_id": "200", "user_id": "300", "company_name": "测试分销公司", "user_name": "测试员工"}
    url, options = session.context.calls[0]
    assert url == USER_INFO_URL and options["headers"]["Authorization"] == token()
    assert options["max_redirects"] == 0 and "coid" not in url.lower()
    assert session.context.response.disposed


@pytest.mark.parametrize("mutation", ["missing_receipt", "bad_provenance", "different_token", "changed_user", "changed_company",
                                      "failed_server", "redirect", "erp_cookie_only"])
async def test_drp_identity_rejects_unverified_or_changed_facts(mutation):
    session = login_session()
    if mutation == "missing_receipt":
        session.server_passport_receipted = False
    elif mutation == "bad_provenance":
        session.server_identity_sources = {}
    elif mutation == "different_token":
        session.context.state["cookies"] = [cookie(token("201"))]
    elif mutation == "changed_user":
        session.context.response.value["data"]["coCompanyUser"]["uid"] = 301
    elif mutation == "changed_company":
        session.context.response.value["data"]["coId"] = 201
    elif mutation == "failed_server":
        session.context.response.value = {"success": False, "code": "1006"}
    elif mutation == "redirect":
        session.context.response.status = 302
    else:
        session.context.state["cookies"] = [{"name": "u_sso_token", "value": "fixture-erp", "domain": ".erp321.com"}]
    with pytest.raises(ConnectorError):
        await DrpIdentityVerifier().verify_session(session)


async def test_drp_restore_requires_saved_binding_and_rechecks_actual_user():
    session = login_session()
    session.login = False
    session.identity = {"company_id": "200", "user_id": "300"}
    with pytest.raises(ConnectorError):
        await DrpIdentityVerifier().verify_session(session)
    session.vault_binding = "fixture-binding"
    assert (await DrpIdentityVerifier().verify_session(session))["user_id"] == "300"


async def test_erp_exchange_uses_new_drp_context_and_server_identity_without_equal_numeric_ids(manager):
    browser, contexts = manager
    result = await browser.accept_erp_token("codex", token(), {"company_id": "900", "user_id": "901"})
    assert result["status"] == "connected"
    assert result["identity"] == {"company_id": "200", "user_id": "300"}
    assert browser.vault.load_session("codex")["identity"] == result["identity"]
    assert result["_issued_binding"] == browser.vault.session_binding("codex")
    assert all(c["domain"] == ".scm121.com" for c in contexts[0].state["cookies"])
    assert browser._sessions["codex"].server_identity_sources["user_id"]["response_url"] == ERP_TOKEN_URL
    assert "900" not in json.dumps(contexts[0].calls)
    with pytest.raises(ConnectorError, match="已有分销账号"):
        await browser.accept_erp_token("codex", token("201"), {"company_id": "900", "user_id": "901"})
    await browser.logout("codex")
    assert contexts[0].closed and browser.vault.load_session("codex") is None


async def test_failed_exchange_does_not_persist_login(manager):
    browser, contexts = manager
    with pytest.raises(ConnectorError):
        await browser.accept_erp_token("codex", token("201"), {"company_id": "900", "user_id": "901"})
    assert contexts[0].closed and browser.vault.load_session("codex") is None
    assert "codex" not in browser._sessions


async def test_exchange_compare_and_swap_preserves_concurrent_saved_session(manager):
    browser, contexts = manager
    verifier = browser._verifier
    async def verify(session):
        result = await verifier.verify_session(session)
        browser.vault.save_session("codex", {}, {"company_id": "700", "user_id": "701"})
        return result
    browser._verifier = SimpleNamespace(verify_session=verify)
    with pytest.raises(ConnectorError):
        await browser.accept_erp_token("codex", token(), {"company_id": "900", "user_id": "901"})
    assert browser.vault.load_session("codex")["identity"]["company_id"] == "700"
    assert contexts[0].closed


async def test_dynamic_business_token_is_only_for_reviewed_drp_host(manager):
    browser, _contexts = manager
    session = login_session()
    session.login, session.verified = False, True
    session.identity = {"company_id": "200", "user_id": "300"}
    headers = await browser.business_headers(session, "https://gyl.scm121.com/api/drp/user/getLoginName")
    assert headers["Authorization"] == token()
    for url in ["https://api.erp321.com/erp/x", PASSWORD_URL, "https://evil.example/"]:
        with pytest.raises(ConnectorError):
            await browser.business_headers(session, url)
    session.context.state["cookies"] = [cookie(token("201"))]
    with pytest.raises(ConnectorError):
        await browser.business_headers(session, "https://gyl.scm121.com/api/drp/user/getLoginName")


class Route:
    def __init__(self, url, method="GET", value=None):
        self.request = SimpleNamespace(url=url, method=method, resource_type="xhr", post_data_json=value)
        self.response = Response(url, value)
        self.fetched = self.fulfilled = self.aborted = 0

    async def fetch(self, **options):
        assert options["max_redirects"] == 0
        self.fetched += 1
        return self.response

    async def fulfill(self, **options):
        self.fulfilled += 1

    async def abort(self, reason):
        self.aborted += 1


async def test_login_route_allows_one_explicit_password_and_separate_encrypt_key(manager):
    browser, _contexts = manager
    session = login_session()
    session.server_passport_receipted = False
    session.drp_login_name = "fixture-login"
    browser._grant_login_action(session, "password")
    key = Route(ENCRYPT_KEY_URL + "?username=fixture-login", "POST", {"success": True, "data": "fixture-key"})
    await browser._route(session, key)
    assert key.fulfilled == 1 and session.auth_remaining == 1
    again = Route(key.request.url, "POST")
    await browser._route(session, again)
    assert again.aborted == 1
    auth = Route(PASSWORD_URL, "POST", {"success": True, "data": {"access_token": token()}})
    await browser._route(session, auth)
    assert auth.fulfilled == 1 and session.auth_remaining == 0
    assert session.auth_signal == "authenticated" and session.server_passport_receipted
    repeat = Route(PASSWORD_URL, "POST", auth.response.value)
    await browser._route(session, repeat)
    assert repeat.aborted == 1


async def test_unknown_business_request_and_other_platform_assets_are_blocked_during_login(manager):
    browser, _contexts = manager
    session = login_session()
    browser._grant_login_action(session, "password")
    for url in ["https://gyl.scm121.com/api/company/order/update", "https://api.erp321.com/erp/webapi/UserApi/WebLogin/Passport",
                LOGIN_URL + "?redirect=https://evil.example/", AUTH_BASE + "/open/register/sendSmsCode"]:
        route = Route(url, "POST")
        await browser._route(session, route)
        assert route.aborted == 1 and not route.fetched
    asset = Route(next(iter(_LOGIN_ASSETS)))
    await browser._route(session, asset)
    assert asset.fulfilled == 1
    assert "fixture-login" not in json.dumps(list(session.events))


@pytest.mark.parametrize("replacement", ["gyl.scm121.com:444", "gyl.scm121.com:443",
                                          "fixture@gyl.scm121.com", "fixture:secret@gyl.scm121.com"])
@pytest.mark.parametrize("action,path,method,query", [
    ("password", "/open/getEncryptKey", "POST", "?username=fixture-login"),
    ("password", "/open/v2/login/gyl/accountLogin", "POST", ""),
    ("send", "/open/v2/login/gyl/getIdaasVerificationCode", "GET", "?loginName=fixture-login&fId=fixture"),
    ("code", "/open/v2/login/gyl/idaasVerificationLogin", "POST", ""),
])
async def test_login_cannot_normalize_alternate_authority_into_trusted_auth(manager, replacement, action, path, method, query):
    browser, _contexts = manager
    session = login_session()
    session.drp_login_name = "fixture-login"
    browser._grant_login_action(session, action)
    route = Route("https://" + replacement + "/api/auth" + path + query, method)
    await browser._route(session, route)
    assert route.aborted == 1 and route.fetched == 0
    assert session.auth_remaining == 1


@pytest.mark.parametrize("action,url,method", [
    ("password", ENCRYPT_KEY_URL + "?username=fixture-login#fragment", "POST"),
    ("password", PASSWORD_URL + "#fragment", "POST"),
    ("send", SEND_CODE_URL + "?loginName=fixture-login&fId=fixture#fragment", "GET"),
    ("code", SUBMIT_CODE_URL + "#fragment", "POST"),
    ("password", ENCRYPT_KEY_URL.replace("https://", "http://") + "?username=fixture-login", "POST"),
    ("send", SEND_CODE_URL.replace("https://", "http://") + "?loginName=fixture-login&fId=fixture", "GET"),
])
async def test_login_rejects_fragment_and_insecure_auth_urls(manager, action, url, method):
    browser, _contexts = manager
    session = login_session()
    session.drp_login_name = "fixture-login"
    browser._grant_login_action(session, action)
    route = Route(url, method)
    await browser._route(session, route)
    assert route.aborted == 1 and route.fetched == 0


@pytest.mark.parametrize("endpoint,method,value,signal", [
    (PASSWORD_URL, "POST", {"success": False, "code": "20002"}, "need_code"),
    (PASSWORD_URL, "POST", {"success": False, "code": "20001"}, "unsupported"),
    (SEND_CODE_URL + "?loginName=fixture-login&fId=fixture-fid", "GET", {"success": True, "data": {"fid": "fixture-new"}}, "code_sent"),
    (SUBMIT_CODE_URL, "POST", {"success": False}, "code_rejected"),
])
async def test_known_login_outcome_and_sms_do_not_invent_success(manager, endpoint, method, value, signal):
    browser, _contexts = manager
    session = login_session()
    session.drp_login_name = "fixture-login"
    action = "password" if endpoint == PASSWORD_URL else "code" if endpoint == SUBMIT_CODE_URL else "send"
    browser._grant_login_action(session, action)
    route = Route(endpoint, method, value)
    await browser._route(session, route)
    assert route.fulfilled == 1 and session.auth_signal == signal


def test_expired_or_opaque_token_cannot_be_called_erp_to_drp_login():
    for value in ["fixture-opaque", token(exp=time.time() - 10)]:
        with pytest.raises(ConnectorError):
            _token_identity(value)


async def test_drp_does_not_offer_erp_fixed_capabilities(manager):
    browser, _contexts = manager
    erp = DrpClient(browser)
    assert erp.catalog() == [] and browser.site_policy.platform == "drp"
    with pytest.raises(ConnectorError, match="通用"):
        await erp.query("codex", "Q02", {})
    with pytest.raises(ConnectorError, match="通用"):
        await erp.preview("codex", "W01", {})


async def test_real_chromium_drp_form_receipt_cookie_and_identity(monkeypatch, tmp_path):
    from playwright.async_api import async_playwright
    value = token()
    html = """<!doctype html><meta charset='utf-8'><form><input id='username'><input id='password' type='password'>
    <input type='checkbox'><button type='submit'>立即登录</button></form><script>
    document.querySelector('form').onsubmit=async event=>{event.preventDefault();
      const result=await fetch('""" + PASSWORD_URL + """',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({loginName:document.querySelector('#username').value,password:'fixture-ciphertext'})}).then(r=>r.json());
      document.cookie='DISTRYBUTION_TOKEN='+result.data.access_token+'; Domain=.scm121.com; Path=/; Secure';};
    </script>"""
    vault = Vault(tmp_path, key=Fernet.generate_key())
    manager = DrpBrowserManager(vault)
    errors, requests = [], []
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch()
        context = await browser.new_context()
        page = await context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        session = _Session(context, page, login=True, controlled_login=True)
        async def fixture_request(route):
            request = route.request
            requests.append((request.method, request.url))
            if request.url == LOGIN_URL and request.method == "GET":
                await route.fulfill(content_type="text/html", body=html)
            elif request.url == PASSWORD_URL and request.method == "OPTIONS":
                await route.fulfill(status=204, headers={"Access-Control-Allow-Origin": "https://account.scm121.com",
                                                        "Access-Control-Allow-Methods": "POST",
                                                        "Access-Control-Allow-Headers": "content-type"})
            elif request.url == PASSWORD_URL and request.method == "POST":
                response = Response(PASSWORD_URL, {"success": True, "data": {"access_token": value}})
                await manager._capture_drp_receipt(session, request, response)
                await route.fulfill(json=response.value, headers={"Access-Control-Allow-Origin": "https://account.scm121.com"})
            else:
                raise AssertionError("本测试不能访问夹具外的页面")
        await context.route("**/*", fixture_request)
        await page.goto(LOGIN_URL)
        driver = DrpLoginDriver(page)
        manager._grant_login_action(session, "password")
        await driver.password("fixture-personal-account", "fixture-personal-password", True)
        assert await driver.outcome(session, 0) == "authenticated"
        async def get_current_user(url, **options):
            assert url == USER_INFO_URL and options["headers"]["Authorization"] == value
            return Response()
        monkeypatch.setattr(context.request, "get", get_current_user)
        assert (await DrpIdentityVerifier().verify_session(session))["company_id"] == "200"
        assert sum(method == "POST" for method, _ in requests) == 1 and not errors
        await browser.close()
