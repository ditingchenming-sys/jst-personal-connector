"""真实 Chromium 验证平台身份授权页面；全部 HTTP 在夹具中截获。"""
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from playwright.sync_api import expect, sync_playwright

ORIGIN = "https://connector.example.com"
PLATFORM = "https://workbench.example.com/connector/authorize"
CONNECTION = "fixture-connection"
CODE = "fixture-browser-bound-once-code"
PREVIEW = "fixture-preview-1234567890"


@pytest.fixture
def browser_ui():
    directory = Path(__file__).resolve().parents[1] / "src" / "jst_connector"
    state = {"mode": "platform", "session": False, "callback_ok": True, "calls": [], "errors": [],
             "next": None, "callback_area": None, "status": "disconnected", "auth_options_hold": False,
             "held": [], "approved": False, "area_calls": [], "namespaces_visible": False}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context()
        page = context.new_page()
        page.on("pageerror", lambda error: state["errors"].append(str(error)))

        def user():
            result = {"ok": True, "username": "private-tenant-subject-value", "client": "private-client-value",
                      "connection_id": CONNECTION, "csrf": "fixture-csrf", "default_area": "erp", "areas": ["erp", "drp"],
                      "auth_method": state["mode"], "display_name": "平台授权用户"}
            if state["next"]:
                result["next"] = state["next"]
            if state["callback_area"]:
                result["area"] = state["callback_area"]
            return result

        def auth_options():
            return {"ok": True, "mode": state["mode"], "issuer": "private-issuer-id", "login_label": "返回平台继续授权"}

        def route_request(route):
            request = route.request
            parsed = urlsplit(request.url)
            path = parsed.path
            body = request.post_data_json if request.method == "POST" else None
            state["calls"].append((request.method, request.url, body))
            if request.url.startswith(PLATFORM):
                route.fulfill(content_type="text/html", body="<!doctype html><meta charset='utf-8'><p>平台授权夹具</p>")
                return
            assert request.url.startswith(ORIGIN + "/"), "页面不得访问测试来源之外的地址"
            if path == "/login":
                route.fulfill(content_type="text/html", body=(directory / "remote_login.html").read_text(encoding="utf-8"))
            elif path.startswith("/operations/"):
                route.fulfill(content_type="text/html", body=(directory / "remote_confirmation.html").read_text(encoding="utf-8"))
            elif path == "/portal/session":
                route.fulfill(json=user() if state["session"] else {"ok": False, "error": {"message": "本人授权已失效"}},
                              status=200 if state["session"] else 401)
            elif path == "/portal/auth-options":
                if state["auth_options_hold"]:
                    state["held"].append(route)
                else:
                    route.fulfill(json=auth_options())
            elif path == "/portal/platform-start":
                assert body["connection_id"] == CONNECTION
                assert request.headers.get("origin") == ORIGIN
                route.fulfill(json={"ok": True, "login_url": PLATFORM + "?challenge=fixture-browser-challenge&audience=fixture-audience"})
            elif path == "/portal/platform-login":
                assert body == {"code": CODE}
                assert "platform_code" not in page.url and CODE not in page.url
                assert request.headers.get("origin") == ORIGIN
                if state["callback_ok"]:
                    state["session"] = True
                    route.fulfill(json=user())
                else:
                    route.fulfill(status=401, json={"ok": False, "error": {"message": "测试回调失败；不可恢复旧身份"}})
            elif path == "/portal/login":
                assert state["mode"] == "password"
                state["session"] = True
                route.fulfill(json=user())
            elif path == "/portal/connection/login-options":
                selected = body.get("area", "erp")
                state["area_calls"].append(selected)
                route.fulfill(json={"ok": True, "area": selected, "platform": selected,
                                   "platform_name": "聚水潭分销" if selected == "drp" else "聚水潭ERP",
                                   "areas": ["erp", "drp"], "erp_sso_available": selected == "drp",
                                   "terms": {"agreement_url": "https://app.jushuitan.com/doc/regUserAgreement.html",
                                             "privacy_url": "https://app.jushuitan.com/doc/regPrivacy.html"}})
            elif path == "/portal/connection/status":
                route.fulfill(json={"ok": True, "connection": {"status": state["status"]}})
            elif path == "/portal/connection/login-status":
                route.fulfill(json={"ok": True, "login": {"status": state["status"]}})
            elif path in {"/portal/connection/login-from-erp", "/portal/connection/login-password"}:
                state["status"] = "connected"
                route.fulfill(json={"ok": True, "login": {"status": "connected"}})
            elif path == "/portal/operation":
                assert body["preview_id"] == PREVIEW and body["area"] == "drp"
                route.fulfill(json={"ok": True, "preview": {"preview_id": PREVIEW, "status": "ready",
                                                            "digest": "fixture-digest", "expires_at": 9999999999,
                                                            "payload": {"object": "fixture-only"}}})
            elif path == "/portal/approve":
                assert state["session"]
                state["approved"] = True
                route.fulfill(json={"ok": True, "preview": {"status": "approved"}})
            else:
                raise AssertionError("未声明的页面请求：" + path)

        context.route("**/*", route_request)
        yield context, page, state, auth_options
        assert not state["errors"]
        browser.close()


def test_platform_mode_hides_employee_password_and_starts_registered_platform(browser_ui):
    _context, page, state, _options = browser_ui
    page.goto(ORIGIN + "/login?connection=" + CONNECTION)
    expect(page.locator("#platform-card")).to_be_visible()
    expect(page.locator("#employee-card")).to_be_hidden()
    expect(page.locator("#employee-password")).to_be_hidden()
    expect(page.locator("#jst-card")).to_be_hidden()
    assert "private-issuer-id" not in page.locator("body").inner_text()
    screenshots = Path(__file__).resolve().parents[1] / "artifacts"
    screenshots.mkdir(exist_ok=True)
    page.screenshot(path=str(screenshots / "platform-login-continue.png"), full_page=True)
    page.get_by_role("button", name="返回平台继续授权", exact=True).click()
    expect(page).to_have_url(PLATFORM + "?challenge=fixture-browser-challenge&audience=fixture-audience")
    assert not any(urlsplit(url).path == "/portal/login" for _method, url, _body in state["calls"])


def test_password_form_never_flashes_before_auth_mode_is_known(browser_ui):
    _context, page, state, options = browser_ui
    state["auth_options_hold"] = True
    page.goto(ORIGIN + "/login?connection=" + CONNECTION)
    expect(page.locator("#employee-card")).to_be_hidden()
    expect(page.locator("#platform-card")).to_be_hidden()
    for _ in range(100):
        if state["held"]:
            break
        page.wait_for_timeout(10)
    assert state["held"]
    state["held"].pop().fulfill(json=options())
    expect(page.locator("#platform-card")).to_be_visible()
    expect(page.locator("#employee-password")).to_be_hidden()


def test_callback_success_clears_fragment_and_goes_straight_to_jst_form(browser_ui):
    context, page, state, _options = browser_ui
    page.goto(ORIGIN + "/login#platform_code=" + CODE)
    expect(page.locator("#jst-form")).to_be_visible()
    expect(page.locator("#employee-password")).to_be_hidden()
    assert page.url == ORIGIN + "/login?connection=" + CONNECTION + "&area=erp"
    paths = [urlsplit(url).path for _method, url, _body in state["calls"]]
    assert "/portal/platform-login" in paths and "/portal/session" not in paths and "/portal/login" not in paths
    assert page.evaluate("localStorage.length===0&&sessionStorage.length===0")
    assert "private-tenant-subject-value" not in page.locator("body").inner_text()
    assert "private-client-value" not in page.locator("body").inner_text()
    assert CODE not in page.locator("body").inner_text()
    screenshots = Path(__file__).resolve().parents[1] / "artifacts"
    screenshots.mkdir(exist_ok=True)
    page.screenshot(path=str(screenshots / "platform-login-authorized.png"), full_page=True)
    assert context.cookies() == []  # Only UI is tested here; challenge cookie validation is a backend test.


def test_existing_platform_session_reuses_authorization_without_employee_login(browser_ui):
    _context, page, state, _options = browser_ui
    state["session"] = True
    page.goto(ORIGIN + "/login?connection=" + CONNECTION)
    expect(page.locator("#jst-form")).to_be_visible()
    expect(page.locator("#employee-password")).to_be_hidden()
    paths = [urlsplit(url).path for _method, url, _body in state["calls"]]
    assert "/portal/session" in paths and "/portal/platform-start" not in paths and "/portal/auth-options" not in paths
    assert "private-tenant-subject-value" not in page.locator("body").inner_text()


def test_platform_callback_refresh_after_expiry_keeps_platform_authorization_mode(browser_ui):
    _context, page, state, _options = browser_ui
    page.goto(ORIGIN + "/login#platform_code=" + CODE)
    expect(page.locator("#jst-form")).to_be_visible()
    assert parse_qs(urlsplit(page.url).query)["connection"] == [CONNECTION]
    state["session"] = False
    page.reload()
    expect(page.locator("#platform-card")).to_be_visible()
    expect(page.locator("#employee-password")).to_be_hidden()
    lookups = [url for _method, url, _body in state["calls"] if urlsplit(url).path == "/portal/auth-options"]
    assert lookups and parse_qs(urlsplit(lookups[-1]).query)["connection"] == [CONNECTION]


def test_callback_failure_never_falls_back_to_old_session_or_password(browser_ui):
    _context, page, state, _options = browser_ui
    state["session"], state["callback_ok"] = True, False
    page.goto(ORIGIN + "/login#platform_code=" + CODE)
    expect(page.locator("#platform-card")).to_be_visible()
    expect(page.locator("#message")).to_contain_text("请返回原平台重新打开")
    expect(page.locator("#jst-card")).to_be_hidden()
    expect(page.locator("#employee-password")).to_be_hidden()
    assert page.url == ORIGIN + "/login"
    paths = [urlsplit(url).path for _method, url, _body in state["calls"]]
    assert paths.count("/portal/platform-login") == 1
    assert "/portal/session" not in paths and "/portal/auth-options" not in paths
    page.locator("#platform-continue").click()
    assert not any(urlsplit(url).path == "/portal/platform-start" for _method, url, _body in state["calls"])


def test_legacy_password_login_remains_available_only_in_password_mode(browser_ui):
    _context, page, state, _options = browser_ui
    state["mode"] = "password"
    page.goto(ORIGIN + "/login?connection=" + CONNECTION)
    expect(page.locator("#employee-card")).to_be_visible()
    expect(page.locator("#platform-card")).to_be_hidden()
    page.locator("#employee").fill("fixture-legacy-user")
    page.locator("#employee-password").fill("fixture-legacy-password")
    page.get_by_role("button", name="登录员工账号", exact=True).click()
    expect(page.locator("#jst-form")).to_be_visible()
    assert page.locator("#employee-password").input_value() == ""


def test_platform_callback_preserves_drp_under_same_connector_entry(browser_ui):
    _context, page, state, _options = browser_ui
    state["callback_area"] = "drp"
    page.goto(ORIGIN + "/login#platform_code=" + CODE)
    expect(page.locator("#business-area")).to_have_value("drp")
    expect(page.locator("#erp-connect")).to_be_visible()
    page.locator("#erp-connect").click()
    expect(page.locator("#complete")).to_be_visible()
    calls = [body for _method, url, body in state["calls"] if urlsplit(url).path == "/portal/connection/login-from-erp"]
    assert calls == [{"area": "drp"}]
    assert page.url == ORIGIN + "/login?connection=" + CONNECTION + "&area=drp"


def test_expired_confirmation_returns_through_same_platform_and_never_auto_approves(browser_ui):
    _context, page, state, _options = browser_ui
    next_path = "/operations/" + PREVIEW + "?connection=" + CONNECTION + "&area=drp"
    page.goto(ORIGIN + next_path)
    expect(page.locator("#login")).to_be_visible()
    href = page.locator("#login").get_attribute("href")
    query = parse_qs(urlsplit(href).query)
    assert query["connection"] == [CONNECTION] and query["next"] == [next_path]
    page.locator("#login").click()
    expect(page.locator("#platform-card")).to_be_visible()
    page.locator("#platform-continue").click()
    body = next(body for _method, url, body in state["calls"] if urlsplit(url).path == "/portal/platform-start")
    assert body["next"] == next_path and body["area"] == "drp"
    state["next"] = next_path
    page.goto(ORIGIN + "/login#platform_code=" + CODE)
    expect(page.locator("#ack")).to_be_enabled()
    expect(page.locator("#approve")).to_be_disabled()
    assert not state["approved"]
    assert "private-tenant-subject-value" not in page.locator("body").inner_text()


@pytest.mark.parametrize("next_path", ["https://evil.example/", "/operations/" + PREVIEW + "?connection=someone-else&area=drp",
                                       "/operations/" + PREVIEW + "?area=drp&area=erp"])
def test_platform_login_does_not_follow_or_forward_invalid_next(browser_ui, next_path):
    _context, page, state, _options = browser_ui
    from urllib.parse import urlencode
    page.goto(ORIGIN + "/login?" + urlencode({"connection": CONNECTION, "next": next_path}))
    expect(page.locator("#platform-card")).to_be_visible()
    page.locator("#platform-continue").click()
    body = next(body for _method, url, body in state["calls"] if urlsplit(url).path == "/portal/platform-start")
    assert "next" not in body
    assert not state["approved"]


def test_real_browser_challenge_cookie_and_actual_backend_platform_roundtrip(tmp_path):
    import hashlib
    import hmac
    import json
    import secrets
    import time
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from cryptography.fernet import Fernet
    from fastapi.testclient import TestClient

    from jst_connector.platform_auth import CHALLENGE_COOKIE, PlatformRegistry
    from jst_connector.remote import COOKIE, EmployeeStore, create_remote_app
    from jst_connector.service import ConnectorService
    from jst_connector.vault import Vault, _json

    secret = b"fixture-private-platform-key-at-least-32-bytes"
    issuer = "fixture-platform"
    platform_login = "https://workbench.example.com/connector/authorize"
    def signed(action, **extra):
        now = int(time.time())
        claims = {"version": 1, "issuer": issuer, "audience": ORIGIN, "action": action,
                  "tenant": "private-tenant", "subject": "private-subject", "client": "workbench",
                  "request_id": secrets.token_urlsafe(24), "issued_at": now, "expires_at": now + 90, **extra}
        return {"claims": claims, "signature": hmac.new(secret, _json(claims), hashlib.sha256).hexdigest()}

    vault = Vault(tmp_path, key=Fernet.generate_key())
    business = SimpleNamespace(status=AsyncMock(return_value={"status": "disconnected"}),
                               login_status=AsyncMock(return_value={"status": "disconnected"}),
                               close=AsyncMock(), close_idle=AsyncMock())
    service = ConnectorService(tmp_path, vault=vault, browser=business)
    employees = EmployeeStore(tmp_path, vault)
    registry = PlatformRegistry(tmp_path, vault, employees=employees)
    registry.register(issuer, platform_login, secret, ["private-tenant"])
    account = registry.integration(signed("provision"), ORIGIN)
    app = create_remote_app(service, ORIGIN, employees=employees)
    observations = {"exchange_cookie": False, "callback_cleared": False, "platform_visits": 0}
    errors = []
    with TestClient(app, base_url=ORIGIN) as client, sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context()
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        def route_request(route):
            request = route.request
            browser_headers = request.all_headers()
            if request.url.startswith(platform_login):
                observations["platform_visits"] += 1
                challenge = parse_qs(urlsplit(request.url).query)["challenge"][0]
                client.cookies.clear()
                authorized = client.post("/integration/platform", json=signed("authorize", challenge=challenge))
                assert authorized.status_code == 200
                # A fulfilled redirect is followed inside the intercepted
                # request chain and bypasses this in-memory ASGI transport.
                # A new top-level navigation preserves the same browser cookie
                # semantics while keeping every request in the fixture.
                route.fulfill(content_type="text/html", body="<!doctype html><script>location.replace(" +
                              json.dumps(authorized.json()["redirect_url"]) + ")</script>")
                return
            assert request.url.startswith(ORIGIN + "/")
            if urlsplit(request.url).path == "/portal/platform-login":
                observations["exchange_cookie"] = CHALLENGE_COOKIE + "=" in browser_headers.get("cookie", "")
                observations["callback_cleared"] = "platform_code" not in page.url
            # Forward only actual browser cookies. TestClient must not silently
            # repair a missing browser challenge/session cookie for this test.
            client.cookies.clear()
            response = client.request(request.method, request.url, headers=browser_headers, content=request.post_data)
            headers = dict(response.headers)
            cookies = response.headers.get_list("set-cookie")
            if cookies:
                # route.fulfill has a dictionary header API. Preserve the main
                # session cookie when redemption also deletes its challenge;
                # backend tests separately verify the deletion response.
                headers["set-cookie"] = next((value for value in cookies if value.startswith(COOKIE + "=")), cookies[0])
            route.fulfill(status=response.status_code, headers=headers, body=response.content)
        context.route("**/*", route_request)
        page.goto(ORIGIN + "/login?connection=" + account["connection_id"])
        expect(page.locator("#platform-card")).to_be_visible()
        expect(page.locator("#employee-password")).to_be_hidden()
        page.locator("#platform-continue").click()
        expect(page.locator("#jst-form")).to_be_visible()
        assert observations == {"exchange_cookie": True, "callback_cleared": True, "platform_visits": 1}
        assert parse_qs(urlsplit(page.url).query)["connection"] == [account["connection_id"]]
        browser_cookie = next(item for item in context.cookies() if item["name"] == COOKIE)
        assert browser_cookie["httpOnly"] and browser_cookie["secure"] and browser_cookie["sameSite"] == "Strict"
        assert "private-tenant" not in page.locator("body").inner_text()
        assert "private-subject" not in page.locator("body").inner_text()
        client.cookies.clear()
        restored = client.get("/portal/session", headers={"cookie": COOKIE + "=" + browser_cookie["value"]})
        assert restored.json()["auth_method"] == "platform"
        assert not vault.load_session(employees.bearer(account["access_token"])["profile"])
        assert not errors
        browser.close()
