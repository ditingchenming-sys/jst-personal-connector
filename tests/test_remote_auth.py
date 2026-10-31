import json
import sqlite3
import time
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from jst_connector.cli import _store_employee_credential, _write_config
from jst_connector.errors import ConnectorError
from jst_connector.remote import COOKIE, EmployeeStore, create_remote_app
from jst_connector.remote_client import RemoteAgentClient, public_origin
from jst_connector.service import ConnectorService
from jst_connector.vault import Vault

ORIGIN = "https://connector.example.com"
PASSWORD = "fixture-personal-password"


class RemoteBrowser:
    def __init__(self, vault):
        self.vault, self.logins = vault, []

    async def status(self, profile):
        session = self.vault.load_session(profile)
        return {"status": "connected" if session else "disconnected", "identity": session and session["identity"]}

    async def password_login(self, profile, username, password, remember, terms_accepted):
        self.logins.append((profile, username, remember, terms_accepted))
        self.vault.save_session(profile, {"cookies": [{"name": "fixture", "value": "secret-cookie"}]},
                                {"company_id": "fixture-company", "user_id": username})
        return {"status": "connected", "message": "已连接"}

    async def login_status(self, profile):
        return {"status": "connected" if self.vault.load_session(profile) else "disconnected"}

    async def send_login_code(self, profile):
        return {"status": "need_code", "code_sent": True}

    async def submit_login_code(self, profile, code):
        return {"status": "connected"}

    async def cancel_login(self, profile):
        return {"status": "disconnected"}

    async def logout(self, profile):
        self.vault.clear_session(profile)

    async def close_idle(self):
        pass

    async def close(self):
        pass


@pytest.fixture
def remote(tmp_path):
    vault = Vault(tmp_path, key=Fernet.generate_key())
    service = ConnectorService(tmp_path, vault=vault, browser=RemoteBrowser(vault))
    store = EmployeeStore(tmp_path, vault)
    a = store.create_employee("alice", PASSWORD)
    b = store.create_employee("bob", PASSWORD)
    app = create_remote_app(service, ORIGIN, employees=store)
    return service, store, a, b, app


def login(client, account, *, password=PASSWORD):
    return client.post("/portal/login", json={"username": account["username"], "password": password,
                                               "connection_id": account["connection_id"]},
                       headers={"origin": ORIGIN})


def api(client, account, action, body=None):
    return client.post("/api/" + action, json=body or {},
                       headers={"authorization": "Bearer " + account["access_token"]})


def portal(client, csrf, action, body=None):
    return client.post("/portal/connection/" + action, json=body or {},
                       headers={"origin": ORIGIN, "x-csrf-token": csrf})


def test_remote_bearer_isolates_employee_and_rejects_identity_input(remote):
    service, store, a, b, app = remote
    identity_a = store.bearer(a["access_token"])
    identity_b = store.bearer(b["access_token"])
    service.vault.save_session(identity_a["profile"], {}, {"company_id": "company-a", "user_id": "user-a"})
    service.vault.save_session(identity_b["profile"], {}, {"company_id": "company-b", "user_id": "user-b"})
    with TestClient(app, base_url=ORIGIN) as client:
        assert api(client, a, "status").json()["connection"]["identity"]["company_id"] == "company-a"
        assert api(client, b, "status").json()["connection"]["identity"]["company_id"] == "company-b"
        assert api(client, a, "status", {"profile": identity_b["profile"]}).json()["error"]["code"] == "identity_parameter_rejected"
        assert client.post("/api/status", json={}).status_code == 401


def test_employee_browser_auth_and_jst_connection_are_separate(remote):
    service, store, a, b, app = remote
    with TestClient(app, base_url=ORIGIN) as client:
        response = login(client, a)
        assert response.status_code == 200
        assert response.json()["connection_id"] == a["connection_id"]
        assert "HttpOnly" in response.headers["set-cookie"] and "Secure" in response.headers["set-cookie"]
        assert "SameSite=strict" in response.headers["set-cookie"]
        assert api(client, a, "status").json()["connection"]["status"] == "disconnected"
        csrf = response.json()["csrf"]
        result = portal(client, csrf, "login-password", {"username": "jst-alice", "password": "fixture",
                                                         "terms_accepted": True, "remember": False})
        assert result.json()["login"]["status"] == "connected"
        assert service.browser.logins == [(store.bearer(a["access_token"])["profile"], "jst-alice", False, True)]
        assert api(client, b, "status").json()["connection"]["status"] == "disconnected"
        assert portal(client, csrf, "login-options").status_code == 200
        assert portal(client, csrf, "login-status").status_code == 200
        assert portal(client, csrf, "login-send-code").status_code == 200
        assert portal(client, csrf, "login-submit-code", {"code": "123456"}).status_code == 200
        assert portal(client, csrf, "login-cancel").status_code == 200
        assert portal(client, csrf, "logout").status_code == 200
        assert service.vault.load_session(store.bearer(a["access_token"])["profile"]) is None


def test_login_pages_never_embed_manager_or_access_tokens(remote):
    service, _store, a, _b, app = remote
    with TestClient(app, base_url=ORIGIN) as client:
        result = api(client, a, "open-manager").json()
        assert result["url"] == ORIGIN + "/login?connection=" + a["connection_id"]
        assert a["access_token"] not in json.dumps(result)
        assert service.vault.manager_token() not in json.dumps(result)
        html = client.get(result["url"]).text
        assert "员工账号" in html and "Cookie" in html
        assert "preview" not in html and "approve" not in html
        assert service.vault.manager_token() not in html


def test_browser_cannot_switch_other_employee_or_confirm_with_bearer(remote):
    _service, store, a, b, app = remote
    with TestClient(app, base_url=ORIGIN) as client:
        assert login(client, {**a, "connection_id": b["connection_id"]}).status_code == 401
        csrf = login(client, a).json()["csrf"]
        assert portal(client, csrf, "status", {"profile": store.bearer(b["access_token"])["profile"]}).status_code == 409
        assert api(client, a, "approve", {"preview_id": "fake"}).status_code == 409
        assert client.post("/portal/approve", json={}, headers={"origin": ORIGIN,
                           "authorization": "Bearer " + a["access_token"]}).status_code == 409


def test_strict_origin_host_and_csrf(remote):
    _service, _store, a, _b, app = remote
    with TestClient(app, base_url=ORIGIN) as client:
        assert client.get("/login", headers={"host": "evil.example"}).status_code == 403
        assert client.post("/portal/login", json={}).status_code == 403
        assert client.post("/portal/login", json={}, headers={"origin": "https://evil.example"}).status_code == 403
        csrf = login(client, a).json()["csrf"]
        assert client.post("/portal/connection/status", json={}, headers={"origin": ORIGIN}).status_code == 409
        assert client.post("/portal/connection/status", json={}, headers={"origin": ORIGIN, "x-csrf-token": "bad"}).status_code == 409
        assert portal(client, csrf, "status").status_code == 200
        assert api(client, a, "status").headers["cache-control"] == "no-store"
        assert client.get("/login").headers["x-frame-options"] == "DENY"


def test_multiple_ai_connections_have_independent_profiles(remote):
    _service, store, a, _b, app = remote
    second = store.issue_token("alice", "codex")
    assert store.bearer(a["access_token"])["profile"] != store.bearer(second["access_token"])["profile"]
    with TestClient(app, base_url=ORIGIN) as client:
        csrf = login(client, a).json()["csrf"]
        portal(client, csrf, "login-password", {"username": "jst-first", "password": "fixture", "terms_accepted": True})
        assert api(client, second, "status").json()["connection"]["status"] == "disconnected"
        assert client.get("/portal/session").json()["connection_id"] == a["connection_id"]


def test_token_rotation_and_employee_disable_revoke_authorization(remote):
    _service, store, a, b, app = remote
    with TestClient(app, base_url=ORIGIN) as client:
        login(client, a)
        next_token = store.issue_token("alice")
        assert api(client, a, "status").status_code == 401
        assert client.get("/portal/session").status_code == 401
        assert api(client, next_token, "status").status_code == 200
        login(client, next_token)
        store.disable("alice")
        assert api(client, next_token, "status").status_code == 401
        assert client.get("/portal/session").status_code == 401
        assert api(client, b, "status").status_code == 200


def test_session_expiry_and_browser_logout(remote):
    _service, store, a, _b, app = remote
    with TestClient(app, base_url=ORIGIN) as client:
        csrf = login(client, a).json()["csrf"]
        response = client.post("/portal/logout", json={}, headers={"origin": ORIGIN, "x-csrf-token": csrf})
        assert response.status_code == 200
        assert client.get("/portal/session").status_code == 401
        login(client, a)
        with sqlite3.connect(store.path) as conn:
            conn.execute("UPDATE browser_sessions SET expires=?", (time.time() - 1,))
        assert client.get("/portal/session").status_code == 401


def test_wrong_password_is_limited_and_other_employee_can_login(remote):
    _service, _store, a, b, app = remote
    with TestClient(app, base_url=ORIGIN) as client:
        for _ in range(8):
            assert login(client, a, password="incorrect").status_code == 401
        assert login(client, a).status_code == 429
        assert login(client, b).status_code == 200


def test_at_rest_contains_no_plaintext_credentials(remote):
    _service, store, a, _b, app = remote
    with TestClient(app, base_url=ORIGIN) as client:
        login(client, a)
        cookie = client.cookies.get(COOKIE)
    contents = store.path.read_bytes()
    assert PASSWORD.encode() not in contents
    assert a["access_token"].encode() not in contents
    assert cookie.encode() not in contents


def test_confirmation_uses_employee_browser_not_ai_token(remote):
    service, store, a, b, app = remote
    identity = {"company_id": "fixture-company", "user_id": "fixture-alice"}
    profile = store.bearer(a["access_token"])["profile"]
    service.vault.save_session(profile, {}, identity)
    preview = service.ledger.create_preview(profile, identity, {"object": "one"}, {"checked": True}, atomicity="verified")
    with TestClient(app, base_url=ORIGIN) as client:
        link = api(client, a, "open-confirmation", {"preview_id": preview["preview_id"], "digest": preview["digest"]}).json()
        assert "connection=" + a["connection_id"] in link["url"]
        assert a["access_token"] not in link["url"]
        assert client.get(link["url"]).status_code == 200
        csrf = login(client, b).json()["csrf"]
        assert client.post("/portal/operation", json={"preview_id": preview["preview_id"]},
                           headers={"origin": ORIGIN, "x-csrf-token": csrf}).status_code == 409
        csrf = login(client, a).json()["csrf"]
        body = {"preview_id": preview["preview_id"], "digest": preview["digest"]}
        result = client.post("/portal/approve", json=body, headers={"origin": ORIGIN, "x-csrf-token": csrf})
        assert result.json()["preview"]["status"] == "approved"


@pytest.mark.parametrize("value", ["http://connector.example.com", "https://user:secret@connector.example.com",
                                   "https://connector.example.com/path", "https://connector.example.com?token=a",
                                   "https://connector.example.com/#token", "https://connector.example.com:8765"])
def test_remote_origin_requires_clean_https(value):
    with pytest.raises(ConnectorError):
        public_origin(value)


def test_remote_client_only_sends_token_in_header_and_never_follows_redirect():
    seen = []
    token = "jst_remote_" + "a" * 43
    def transport(request):
        seen.append(request)
        if request.url.path == "/api/status":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(302, headers={"location": "https://elsewhere.example/"})
    client = RemoteAgentClient(ORIGIN, token, transport=httpx.MockTransport(transport))
    assert client.call("status") == {"ok": True}
    assert seen[0].headers["authorization"] == "Bearer " + token
    assert token not in str(seen[0].url)
    with pytest.raises(ConnectorError, match="重定向"):
        client.call("query")
    assert len(seen) == 2


def test_remote_config_has_no_secret_or_local_credential_dependency():
    config = _write_config(Path("fixture"), "codex", "codex", ORIGIN)
    assert "--remote-url" in config and ORIGIN in config
    assert "access_token" not in config and "Bearer" not in config


def test_employee_cli_outputs_credentials_only_to_protected_file(tmp_path, monkeypatch, capsys):
    from jst_connector.cli import main
    monkeypatch.setenv("JST_CONNECTOR_MASTER_KEY", Fernet.generate_key().decode())
    password_file = tmp_path / "fixture-password.txt"
    password_file.write_text(PASSWORD, encoding="utf-8")
    password_file.chmod(0o600)
    destination = tmp_path / "fixture-access.json"
    data_dir = tmp_path / "runtime"
    main(["employee-add", "--username", "alice", "--password-file", str(password_file),
          "--token-output", str(destination), "--data-dir", str(data_dir)])
    issued = json.loads(destination.read_text(encoding="utf-8"))
    output = capsys.readouterr()
    assert issued["access_token"] not in output.out + output.err
    assert PASSWORD not in output.out + output.err
    assert json.loads(output.out)["ok"] is True
    store = EmployeeStore(data_dir, Vault(data_dir))
    assert store.bearer(issued["access_token"])["username"] == "alice"
    main(["employee-disable", "--username", "alice", "--data-dir", str(data_dir)])
    with pytest.raises(ConnectorError):
        store.bearer(issued["access_token"])


def test_default_https_port_and_idna_are_canonical():
    assert public_origin("https://CONNECTOR.example.com:443/") == ORIGIN
    assert public_origin("https://例子.cn:443") == "https://xn--fsqu00a.cn"


def test_credential_output_failure_rolls_back_account_and_token(remote, tmp_path):
    _service, store, a, _b, _app = remote
    destination = tmp_path / "fixture-credential.json"
    def failure(_issued):
        raise OSError("fixture file failure")
    with pytest.raises(OSError):
        store.create_employee("charlie", PASSWORD, issue_sink=failure)
    with pytest.raises(ConnectorError):
        store.login("charlie", PASSWORD, None, "test")
    with pytest.raises(OSError):
        store.issue_token("alice", issue_sink=failure)
    assert store.bearer(a["access_token"])["username"] == "alice"
    issued = _store_employee_credential(destination, lambda sink: store.issue_token("alice", issue_sink=sink))
    assert json.loads(destination.read_text())["access_token"] == issued["access_token"]
    assert store.bearer(issued["access_token"])["username"] == "alice"
    with pytest.raises(FileExistsError):
        _store_employee_credential(destination, lambda sink: store.issue_token("alice", issue_sink=sink))
    assert store.bearer(issued["access_token"])["username"] == "alice"


def test_open_confirmation_rejects_digest_changes_and_already_confirmed(remote):
    service, store, a, _b, app = remote
    identity = {"company_id": "fixture-company", "user_id": "fixture-alice"}
    profile = store.bearer(a["access_token"])["profile"]
    service.vault.save_session(profile, {}, identity)
    preview = service.ledger.create_preview(profile, identity, {"object": "one"}, {}, atomicity="verified")
    with TestClient(app, base_url=ORIGIN) as client:
        assert api(client, a, "open-confirmation", {"preview_id": preview["preview_id"], "digest": "wrong"}).status_code == 409
        service.approve(profile, preview["preview_id"], preview["digest"])
        assert api(client, a, "open-confirmation", {"preview_id": preview["preview_id"], "digest": preview["digest"]}).status_code == 409


def test_remote_pages_in_real_chromium_without_external_network(remote):
    from playwright.sync_api import expect, sync_playwright
    service, store, a, _b, app = remote
    errors = []
    with TestClient(app, base_url=ORIGIN) as client, sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context()
        def route_request(route):
            assert route.request.url.startswith(ORIGIN + "/")
            response = client.request(route.request.method, route.request.url,
                                      headers=route.request.headers, content=route.request.post_data)
            route.fulfill(status=response.status_code, headers=dict(response.headers), body=response.content)
        context.route("**/*", route_request)
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(ORIGIN + "/login?connection=" + a["connection_id"])
        page.locator("#employee").fill("alice")
        page.locator("#employee-password").fill(PASSWORD)
        page.get_by_role("button", name="登录员工账号", exact=True).click()
        page.locator("#jst-card").wait_for(state="visible")
        assert page.locator("#employee-password").input_value() == ""
        assert context.cookies()[0]["httpOnly"] is True
        page.locator("#username").fill("fixture-jst-alice")
        page.locator("#password").fill("fixture-jst-secret")
        page.locator("#terms").check()
        page.get_by_role("button", name="登录并连接", exact=True).click()
        page.locator("#complete").wait_for(state="visible")
        assert page.locator("#password").input_value() == ""
        screenshot = Path(__file__).resolve().parents[1] / "artifacts" / "remote-authorized-preview.png"
        screenshot.parent.mkdir(exist_ok=True)
        page.screenshot(path=str(screenshot), full_page=True)
        profile = store.bearer(a["access_token"])["profile"]
        identity = service.vault.load_session(profile)["identity"]
        preview = service.ledger.create_preview(profile, identity, {"object": "fixture-only"}, {}, atomicity="verified")
        page.goto(ORIGIN + "/operations/" + preview["preview_id"] + "?connection=" + a["connection_id"])
        page.locator("#ack").wait_for(state="visible")
        expect(page.locator("#ack")).to_be_enabled()
        assert "fixture-only" in page.locator("#preview").inner_text()
        page.locator("#ack").check()
        page.get_by_role("button", name="确认这份预览", exact=True).click()
        expect(page.locator("#message")).to_contain_text("已确认")
        assert service.ledger.get_preview(profile, preview["preview_id"])["status"] == "approved"
        assert not errors
        browser.close()
