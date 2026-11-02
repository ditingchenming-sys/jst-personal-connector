"""真实 Chromium 验证分销按需准备；全部请求在本机夹具截获。"""
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import expect, sync_playwright


@pytest.fixture(params=["local", "remote"])
def auto_ui(request):
    remote = request.param == "remote"
    origin = "https://connector.example.com" if remote else "http://127.0.0.1:19739"
    directory = Path(__file__).resolve().parents[1] / "src" / "jst_connector"
    state = {"calls": [], "errors": [], "erp": True, "auto": "connected", "held": [], "hold": False, "legacy": False, "fallback": True}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context()
        page = context.new_page()
        page.on("pageerror", lambda error: state["errors"].append(str(error)))

        def metadata():
            return {"status": state["auto"] if state["erp"] else "erp_unavailable",
                    "erp_available": state["erp"], "can_password_login": not state["erp"] or (state["fallback"] and state["auto"] in {"failed", "cooldown"}),
                    "retry_after_seconds": 15 if state["auto"] == "cooldown" else 0,
                    "message": "分销已自动连接。" if state["auto"] == "connected" else "分销自动连接暂未完成，请稍后重试。"}

        def options(area):
            result = {"ok": True, "area": area, "platform": area, "areas": ["erp", "drp"],
                      "erp_sso_available": area == "drp", "terms": {
                          "agreement_url": "https://example.com/agreement", "privacy_url": "https://example.com/privacy"}}
            if area == "drp" and not state["legacy"]:
                result["auto_connection"] = metadata()
            return result

        def handler(route):
            req = route.request
            assert req.url.startswith(origin + "/"), "不得发出外部认证请求"
            path = urlsplit(req.url).path
            if req.method == "GET" and path in {"/login", "/manage"}:
                filename = "remote_login.html" if remote else "management.html"
                route.fulfill(content_type="text/html", body=(directory / filename).read_text(encoding="utf-8"))
                return
            if path == "/portal/session":
                route.fulfill(json={"ok": True, "csrf": "fixture-csrf", "connection_id": "fixture-connection",
                                    "default_area": "erp", "areas": ["erp", "drp"], "auth_method": "platform"})
                return
            body = req.post_data_json
            area = body.get("area", "erp")
            action = path.rsplit("/", 1)[-1]
            state["calls"].append((action, area))
            if action == "login-options":
                if area == "drp" and state["hold"]:
                    state["held"].append(route)
                else:
                    route.fulfill(json=options(area))
            elif action in {"status", "login-status"}:
                connected = (area == "erp" and state["erp"]) or (area == "drp" and state["erp"] and state["auto"] == "connected")
                result = {"ok": True, "connection" if action == "status" else "login": {"status": "connected" if connected else "disconnected"}}
                if area == "drp" and not state["legacy"]:
                    result["auto_connection"] = metadata()
                route.fulfill(json=result)
            else:
                raise AssertionError("不得请求手动认证：" + action)

        context.route("**/*", handler)
        entry = origin + ("/login?connection=fixture-connection" if remote else "/manage#token=fixture-token&profile=codex")
        yield page, state, entry, options
        assert not state["errors"]
        browser.close()


def test_erp_page_is_lazy_then_drp_connects_without_manual_auth(auto_ui):
    page, state, entry, options = auto_ui
    page.goto(entry)
    expect(page.locator("#business-area")).to_be_enabled()
    assert all(area == "erp" for _, area in state["calls"])
    state["hold"] = True
    page.locator("#business-area").select_option("drp")
    form = page.locator("#jst-form, #account-form")
    expect(form).to_be_hidden()
    expect(page.locator("#progress, #login-progress")).to_contain_text("连接")
    expect(page.locator("#erp-connect")).to_be_hidden()
    page.wait_for_function("document.getElementById('business-area').disabled")
    assert state["held"]
    state["held"].pop().fulfill(json=options("drp"))
    expect(page.locator("#complete, #connected-area")).to_be_visible()
    expect(form).to_be_hidden()
    assert not any(action in {"login-from-erp", "login-password"} for action, _ in state["calls"])


@pytest.mark.parametrize("failure", ["cooldown", "failed"])
def test_auto_failure_keeps_password_hidden_and_check_connection_recovers(auto_ui, failure):
    page, state, entry, _options = auto_ui
    state["auto"] = failure
    page.goto(entry)
    expect(page.locator("#business-area")).to_be_enabled()
    page.locator("#business-area").select_option("drp")
    expect(page.locator("#message")).to_contain_text("分销自动连接暂未完成")
    expect(page.locator("#jst-form, #account-form")).to_be_hidden()
    expect(page.locator("#erp-connect")).to_be_hidden()
    state["auto"] = "connected"
    page.locator("#refresh").click()
    expect(page.locator("#complete, #connected-area")).to_be_visible()


def test_failure_password_fallback_requires_person_click_and_resets_on_area_change(auto_ui):
    page, state, entry, _options = auto_ui
    state["auto"] = "cooldown"
    page.goto(entry)
    expect(page.locator("#business-area")).to_be_enabled()
    page.locator("#business-area").select_option("drp")
    expect(page.locator("#password-fallback")).to_be_visible()
    expect(page.locator("#jst-form, #account-form")).to_be_hidden()
    page.locator("#password-fallback").click()
    expect(page.locator("#jst-form, #account-form")).to_be_visible()
    expect(page.locator("#password-fallback")).to_be_hidden()
    assert not any(action in {"login-from-erp", "login-password"} for action, _ in state["calls"])
    page.locator("#business-area").select_option("erp")
    expect(page.locator("#business-area")).to_be_enabled()
    page.locator("#business-area").select_option("drp")
    expect(page.locator("#jst-form, #account-form")).to_be_hidden()
    expect(page.locator("#password-fallback")).to_be_visible()


def test_failure_without_backend_permission_has_no_password_fallback(auto_ui):
    page, state, entry, _options = auto_ui
    state.update(auto="failed", fallback=False)
    page.goto(entry)
    expect(page.locator("#business-area")).to_be_enabled()
    page.locator("#business-area").select_option("drp")
    expect(page.locator("#message")).to_contain_text("分销自动连接暂未完成")
    expect(page.locator("#password-fallback")).to_be_hidden()
    expect(page.locator("#jst-form, #account-form")).to_be_hidden()


def test_no_erp_retains_independent_drp_password(auto_ui):
    page, state, entry, _options = auto_ui
    state["erp"] = False
    page.goto(entry)
    expect(page.locator("#business-area")).to_be_enabled()
    page.locator("#business-area").select_option("drp")
    expect(page.locator("#jst-form, #account-form")).to_be_visible()
    expect(page.locator("#erp-connect")).to_be_hidden()


def test_direct_drp_link_prepares_without_opening_password_form(auto_ui):
    page, state, entry, _options = auto_ui
    page.goto(entry + "&area=drp")
    expect(page.locator("#complete, #connected-area")).to_be_visible()
    expect(page.locator("#jst-form, #account-form")).to_be_hidden()
    assert all(area == "drp" for _, area in state["calls"])


def test_late_drp_options_cannot_replace_erp_screen(auto_ui):
    page, state, entry, options = auto_ui
    page.goto(entry)
    expect(page.locator("#business-area")).to_be_enabled()
    state["hold"] = True
    page.locator("#business-area").select_option("drp")
    page.wait_for_function("document.getElementById('business-area').disabled")
    assert state["held"]
    # Emulate a newly selected area while the first request remains in flight.
    page.evaluate("const s=document.getElementById('business-area');s.disabled=false;s.value='erp';s.dispatchEvent(new Event('change'))")
    expect(page.locator("#business-area")).to_have_value("erp")
    state["held"].pop().fulfill(json=options("drp"))
    expect(page.locator("#business-area")).to_have_value("erp")
    expect(page.locator("#complete, #connected-area")).to_be_visible()
    expect(page.locator("#message")).not_to_contain_text("分销已自动连接")


def test_legacy_standalone_without_auto_metadata_retains_original_login(auto_ui):
    page, state, entry, _options = auto_ui
    state.update(legacy=True, erp=False)
    page.goto(entry)
    expect(page.locator("#business-area")).to_be_enabled()
    page.locator("#business-area").select_option("drp")
    expect(page.locator("#jst-form, #account-form")).to_be_visible()
    expect(page.locator("#erp-connect")).to_be_visible()
