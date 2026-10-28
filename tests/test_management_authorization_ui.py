"""真实Chromium验证管理页的同标签临时授权；所有HTTP均在测试路由拦截。"""
import json
from pathlib import Path
from urllib.parse import urlencode

import pytest
from playwright.sync_api import sync_playwright

ORIGIN = "http://127.0.0.1:19731"
TOKENS = {"codex": "fixture-codex-management-grant", "workbuddy": "fixture-workbuddy-management-grant"}


@pytest.fixture
def management_browser():
    html = (Path(__file__).resolve().parents[1] / "src/jst_connector/management.html").read_text(encoding="utf-8")
    state = {"requests": [], "errors": [], "status": "disconnected", "reject": False, "interfaces": []}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context()
        context.on("page", lambda page: page.on("pageerror", lambda error: state["errors"].append(str(error))))

        def route_request(route):
            url = route.request.url
            if url == ORIGIN + "/ui":
                route.fulfill(status=200, content_type="text/html", body=html)
            elif url.startswith(ORIGIN + "/manage/"):
                payload = route.request.post_data_json
                authorization = route.request.headers.get("authorization")
                state["requests"].append((url.rsplit("/", 1)[-1], payload, authorization))
                expected = "Bearer " + TOKENS.get(payload.get("profile"), "invalid")
                if state["reject"] or authorization != expected:
                    route.fulfill(status=401, json={"ok": False, "error": {"message": "测试授权失效"}})
                elif url.endswith("/login-options"):
                    route.fulfill(json={"ok": True, "terms": {
                        "agreement_url": "https://app.jushuitan.com/doc/regUserAgreement.html",
                        "privacy_url": "https://app.jushuitan.com/doc/regPrivacy.html"}})
                elif url.endswith("/status"):
                    route.fulfill(json={"ok": True, "connection": {"status": "disconnected"}})
                elif url.endswith("/interface-list"):
                    route.fulfill(json={"ok": True, "interfaces": state["interfaces"]})
                elif url.endswith("/interface-approve"):
                    record = next(item for item in state["interfaces"] if item["interface_id"] == payload["interface_id"])
                    assert payload["digest"] == record["digest"]
                    record["status"] = "approved_pending_validation"
                    route.fulfill(json={"ok": True, "interface": record})
                else:
                    route.fulfill(json={"ok": True, "login": {"status": state["status"],
                                  "message": "本机虚构状态", "can_send_code": True}})
            else:
                raise AssertionError("测试管理页不得请求外部地址")

        context.route("**/*", route_request)
        yield context, state
        assert not state["errors"]
        browser.close()


def grant_url(profile="codex"):
    return ORIGIN + "/ui#" + urlencode({"profile": profile, "token": TOKENS[profile]})


def assert_locked(page):
    page.locator("#authorization-notice").wait_for(state="visible")
    assert "没有有效授权" in page.locator("#authorization-notice").inner_text()
    assert page.get_by_label("聚水潭账号", exact=True).is_disabled()
    assert page.get_by_label("密码", exact=True).is_disabled()
    assert page.evaluate("[...document.querySelectorAll('input,button')].every(element=>element.disabled)")
    assert "未指定" in page.locator("#client").inner_text()


@pytest.mark.parametrize("status", ["disconnected", "need_code", "identity_pending"])
def test_same_tab_refresh_restores_only_its_grant_and_current_login_state(management_browser, status):
    context, state = management_browser
    state["status"] = status
    page = context.new_page()
    page.goto(grant_url())
    page.wait_for_function("document.querySelector('#login-progress').textContent === '本机虚构状态'")
    initial_requests = len(state["requests"])
    assert page.url == ORIGIN + "/ui"
    reference = page.evaluate("history.state")
    assert list(reference) == ["managementGrant"]
    assert all(token not in json.dumps(reference) for token in TOKENS.values())
    page.reload()
    page.wait_for_function("document.querySelector('#login-progress').textContent === '本机虚构状态'")
    assert len(state["requests"]) > initial_requests
    assert page.evaluate("history.state") == reference
    assert page.locator("#authorization-notice").is_hidden()
    assert "codex" in page.locator("#client").inner_text()
    assert all(payload["profile"] == "codex" and header == "Bearer " + TOKENS["codex"]
               for _, payload, header in state["requests"])
    assert page.evaluate("Object.keys(localStorage).length") == 0
    assert all("token" not in url for url in [page.url])
    if status == "need_code":
        assert page.locator("#code-form").is_visible()
    elif status == "identity_pending":
        assert page.locator("#account-form").is_hidden()
    else:
        assert page.get_by_role("button", name="登录并连接", exact=True).is_enabled()
        screenshot = Path(__file__).resolve().parents[1] / "artifacts" / "management-authorized-preview.png"
        screenshot.parent.mkdir(exist_ok=True)
        page.screenshot(path=str(screenshot), full_page=True)


def test_naked_navigation_and_new_tab_do_not_search_prior_session_storage(management_browser):
    context, state = management_browser
    page = context.new_page()
    page.goto(grant_url())
    page.wait_for_function("document.querySelector('#password-submit').disabled === false")
    assert page.evaluate("sessionStorage.length") == 1
    previous = len(state["requests"])
    page.goto(ORIGIN + "/ui")
    assert_locked(page)
    page.reload()
    assert_locked(page)
    new_page = context.new_page()
    new_page.goto(ORIGIN + "/ui")
    assert_locked(new_page)
    assert len(state["requests"]) == previous


def test_profiles_remain_paired_with_their_own_grants_across_refresh(management_browser):
    context, state = management_browser
    page = context.new_page()
    for profile in TOKENS:
        page.goto(grant_url(profile))
        page.wait_for_function("profile=>document.querySelector('#client').textContent.endsWith(profile)&&!location.hash&&document.querySelector('#password-submit').disabled===false", arg=profile)
        page.reload()
        page.wait_for_function("document.querySelector('#password-submit').disabled === false")
        assert profile in page.locator("#client").inner_text()
    assert {payload["profile"] for _, payload, _ in state["requests"]} == set(TOKENS)
    assert all(header == "Bearer " + TOKENS[payload["profile"]] for _, payload, header in state["requests"])


@pytest.mark.parametrize("fragment", ["profile=workbuddy", "token=fixture-token-only", "profile=&token=fixture-token"])
def test_partial_fragment_never_falls_back_to_previous_profile(management_browser, fragment):
    context, state = management_browser
    page = context.new_page()
    page.goto(grant_url())
    page.wait_for_function("document.querySelector('#password-submit').disabled === false")
    previous = len(state["requests"])
    page.goto(ORIGIN + "/ui#" + fragment)
    assert_locked(page)
    assert page.url == ORIGIN + "/ui" and page.evaluate("history.state") is None
    assert len(state["requests"]) == previous


@pytest.mark.parametrize("failure", ["corrupt", "missing", "server_401"])
def test_unrecoverable_or_revoked_grant_disables_all_controls(management_browser, failure):
    context, state = management_browser
    page = context.new_page()
    page.goto(grant_url())
    page.wait_for_function("document.querySelector('#password-submit').disabled === false")
    if failure == "corrupt":
        page.evaluate("sessionStorage.setItem('jst-management-grant:'+history.state.managementGrant,'{broken')")
    elif failure == "missing":
        page.evaluate("sessionStorage.clear()")
    else:
        state["reject"] = True
    page.reload()
    assert_locked(page)
    assert page.evaluate("history.state") is None
    if failure == "server_401":
        assert page.evaluate("sessionStorage.length") == 0
        assert "授权已失效" in page.locator("#message").inner_text()
