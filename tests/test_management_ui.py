"""实际浏览器验证本机管理页面；不打开 ERP、不读取用户登录资料。"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

import httpx
import pytest
from cryptography.fernet import Fernet
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from jst_connector.vault import Vault


@pytest.mark.parametrize("requires_sms", [False, True])
def test_management_page_in_real_chromium_without_erp_requests(tmp_path, requires_sms):
    key = Fernet.generate_key()
    vault = Vault(tmp_path, key=key)
    vault.ensure_client("codex")
    env = {**os.environ, "JST_CONNECTOR_MASTER_KEY": key.decode(), "PYTHONUTF8": "1"}
    server = subprocess.Popen([sys.executable, "-m", "jst_connector", "serve", "--data-dir", str(tmp_path)],
                              env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(200):
            assert server.poll() is None
            state = tmp_path / "agent.json"
            if state.exists():
                url = json.loads(state.read_text(encoding="utf-8"))["url"]
                try:
                    if httpx.get(url + "/health", timeout=0.3, trust_env=False).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
            time.sleep(0.05)
        else:
            raise AssertionError("本机测试组件未能启动")
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            page.set_default_timeout(5000)
            page.set_default_navigation_timeout(5000)
            external_requests, console_errors, actions = [], [], []
            login_state = {"status": "disconnected", "message": "请连接本人账号。"}

            def route_request(route):
                nonlocal login_state
                if not route.request.url.startswith(url + "/"):
                    external_requests.append(route.request.url)
                    route.abort()
                elif "/manage/" in route.request.url:
                    action = route.request.url.rsplit("/", 1)[-1]
                    payload = route.request.post_data_json
                    if action == "login-options":
                        result = {"terms": {"agreement_url": "https://app.jushuitan.com/doc/regUserAgreement.html",
                                            "privacy_url": "https://app.jushuitan.com/doc/regPrivacy.html"}}
                    elif action == "status":
                        result = {"connection": {"status": "connected" if login_state["status"] == "connected"
                                                  else "disconnected",
                                                  "identity_display": {"company_name": "测试公司", "user_name": "测试员工"}}}
                    else:
                        if action != "login-status":
                            actions.append((action, payload))
                        if action == "login-password":
                            login_state = {"status": "need_code" if requires_sms else "connected",
                                           "message": "请查收本人手机短信。" if requires_sms else "已连接本人账号。",
                                           "masked_account": "fix****test", "can_send_code": requires_sms}
                        elif action == "login-send-code":
                            login_state = {**login_state, "can_send_code": False, "retry_after_seconds": 60,
                                           "code_sent": True}
                        elif action == "login-submit-code":
                            login_state = {"status": "connected", "message": "已连接本人账号。"}
                        elif action == "logout":
                            login_state = {"status": "disconnected", "message": "已退出。"}
                        result = {"login": login_state}
                    route.fulfill(status=200, json={"ok": True, **result})
                else:
                    route.continue_()
            page.route("**/*", route_request)
            page.on("pageerror", lambda error: console_errors.append(str(error)))
            page.goto(url + "/ui#" + urlencode({"profile": "codex", "token": vault.manager_token()}))
            # 先侦察 DOM/iframe，再依据已观察到的按钮定位；不猜截图坐标。
            state = page.evaluate("""() => ({title:document.title,iframes:[...document.querySelectorAll('iframe')].map(x=>({id:x.id,src:x.src})),buttons:[...document.querySelectorAll('button')].map(x=>({id:x.id,text:x.textContent}))})""")
            assert state["title"] == "聚水潭个人连接器"
            assert not state["iframes"]
            assert any(button["id"] == "refresh" and button["text"] == "检查连接" for button in state["buttons"])
            try:
                page.wait_for_function("document.querySelector('#message').textContent.includes('未连接')")
            except PlaywrightTimeoutError:
                raise AssertionError({"message": page.locator("#message").inner_text(),
                                      "console_errors": console_errors}) from None
            assert "token" not in page.url and "#" not in page.url
            page.locator("#refresh").click()
            page.wait_for_function("document.querySelector('#message').textContent.includes('未连接')")
            assert page.locator("#preview-id").count() == 0
            assert page.locator("#interfaces").count() == 0
            assert page.locator("#login-area").is_visible()
            assert page.locator("#code-form").is_hidden()
            assert not page.locator("#login-image").count()
            if not requires_sms:
                preview = Path(__file__).resolve().parents[1] / "artifacts" / "login-form-preview.png"
                preview.parent.mkdir(exist_ok=True)
                page.screenshot(path=str(preview), full_page=True)
            page.get_by_label("聚水潭账号", exact=True).fill("fixture@example.test")
            page.get_by_label("密码", exact=True).fill("fixture-password")
            page.locator("#terms").check()
            page.get_by_role("button", name="登录并连接", exact=True).click()
            page.wait_for_function("document.querySelector('#password').value === ''")
            if requires_sms:
                page.locator("#code-form").wait_for(state="visible")
                assert [action for action, _ in actions] == ["login-password"]
                page.get_by_role("button", name="发送验证码", exact=True).click()
                page.wait_for_function("document.querySelector('#send-code').disabled")
                page.get_by_label("短信验证码", exact=True).fill("123456")
                page.get_by_role("button", name="验证并继续", exact=True).click()
            page.locator("#login-area").wait_for(state="hidden")
            assert page.get_by_role("heading", name="连接授权完成", exact=True).is_visible()
            assert page.get_by_text("登录授权完成后可关闭本页，回到 AI 或业务系统继续使用。关闭页面不会退出账号。", exact=True).is_visible()
            page.wait_for_function("document.querySelector('#message').textContent.includes('测试公司') && document.querySelector('#message').textContent.includes('测试员工')")
            assert [action for action, _ in actions] == (["login-password", "login-send-code", "login-submit-code"]
                                                        if requires_sms else ["login-password"])
            assert actions[0][1]["terms_accepted"] is True
            assert actions[0][1]["remember"] is False
            assert page.locator("#code").input_value() == ""
            assert not external_requests
            assert not console_errors
            artifact = Path(__file__).resolve().parents[1] / "artifacts" / "management-preview.png"
            artifact.parent.mkdir(exist_ok=True)
            page.screenshot(path=str(artifact), full_page=True)
            browser.close()
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
