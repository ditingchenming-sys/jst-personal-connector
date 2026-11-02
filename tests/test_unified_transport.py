"""同一授权入口下按本人业务板块分派；所有 ERP/SCM 均为隔离夹具。"""
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from jst_connector.agent import create_app
from jst_connector.remote import EmployeeStore, create_remote_app
from jst_connector.service import ConnectorService

ORIGIN = "https://connector.example.com"
PASSWORD = "fixture-personal-password"


class AreaBrowser:
    def __init__(self, vault, area):
        self.vault, self.area, self.actions = vault, area, []

    async def status(self, profile):
        saved = self.vault.load_session(profile)
        return {"status": "connected" if saved else "disconnected", "identity": saved and saved["identity"]}

    async def login_status(self, profile):
        return {"status": "connected" if self.vault.load_session(profile) else "disconnected", "message": self.area}

    async def password_login(self, profile, username, password, remember, terms_accepted):
        self.actions.append(("password", profile, username))
        self.vault.save_session(profile, {}, {"company_id": self.area + "-company", "user_id": username})
        return {"status": "connected", "message": self.area}

    async def send_login_code(self, profile):
        self.actions.append(("send", profile))
        return {"status": "need_code"}

    async def submit_login_code(self, profile, code):
        self.actions.append(("code", profile))
        return {"status": "connected"}

    async def cancel_login(self, profile):
        self.actions.append(("cancel", profile))
        return {"status": "disconnected"}

    async def logout(self, profile):
        self.actions.append(("logout", profile))
        self.vault.clear_session(profile)

    async def close_idle(self):
        pass

    async def close(self):
        pass


class AreaERP:
    def __init__(self, area):
        self.area, self.executions = area, []

    def catalog(self):
        return [{"id": self.area + "-fixture", "name": self.area}]

    async def query(self, profile, capability_id, parameters):
        return {"area": self.area, "actor": profile}

    async def revalidate(self, profile, payload):
        return True

    async def execute(self, profile, payload):
        self.executions.append(profile)
        return {"verified": True, "area": self.area}


@pytest.fixture
def unified(tmp_path, monkeypatch):
    monkeypatch.setenv("JST_CONNECTOR_MASTER_KEY", Fernet.generate_key().decode())
    root = ConnectorService(tmp_path)
    root.browser, root.erp = AreaBrowser(root.vault, "erp"), AreaERP("erp")
    child = root.area_service("drp")
    child.browser, child.erp = AreaBrowser(child.vault, "drp"), AreaERP("drp")
    root.vault.save_session("codex", {}, {"company_id": "erp-company", "user_id": "erp-person"})
    child.vault.save_session("codex", {}, {"company_id": "drp-company", "user_id": "drp-person"})
    return root, child


def preview(service, profile="codex"):
    return service.ledger.create_preview(profile, service.vault.load_session(profile)["identity"],
                                         {"object": "fixture-" + service.platform}, {}, atomicity="verified")


def call_local(client, token, action, body=None):
    return client.post("/api/" + action, json=body or {}, headers={"authorization": "Bearer " + token})


def test_one_local_authorization_dispatches_areas_without_other_profile_or_platform(unified):
    root, child = unified
    token = root.vault.ensure_client("codex")
    foreign = child.vault.ensure_client("codex")
    with TestClient(create_app(root)) as client:
        assert call_local(client, token, "status").json()["connection"]["identity"]["company_id"] == "erp-company"
        assert call_local(client, token, "status", {"area": "drp"}).json()["connection"]["identity"]["company_id"] == "drp-company"
        assert call_local(client, foreign, "status", {"area": "drp"}).status_code == 401
        assert call_local(client, token, "query", {"area": "drp", "capability_id": "fixture"}).json()["result"]["area"] == "drp"
        hinted = call_local(client, token, "status", {"area": "drp", "profile": "another", "company_id": "other"}).json()
        assert hinted["connection"]["identity"]["user_id"] == "drp-person"
        assert client.post("/api/status", json={"area": "drp"}, headers={"authorization": "Bearer " + token,
                            "x-jst-platform": "drp"}).status_code == 409


@pytest.mark.parametrize("area", ["", "scm", "ERP", True, [], {}])
def test_invalid_area_is_rejected_before_business_dispatch(unified, area):
    root, _child = unified
    with TestClient(create_app(root)) as client:
        response = call_local(client, root.vault.ensure_client("codex"), "status", {"area": area})
        assert response.status_code == 409 and response.json()["error"]["code"] == "invalid_area"


def test_manager_is_one_page_and_local_confirmation_pins_area(unified):
    root, child = unified
    opened = []
    erp_preview, drp_preview = preview(root), preview(child)
    with TestClient(create_app(root, opener=lambda url: opened.append(url) or True)) as client:
        token = root.vault.ensure_client("codex")
        assert call_local(client, token, "open-manager", {"area": "drp"}).json()["ok"]
        fragment = parse_qs(urlsplit(opened[-1]).fragment)
        assert urlsplit(opened[-1]).path == "/ui" and fragment["area"] == ["drp"]
        assert fragment["token"] == [root.vault.manager_token()]
        assert call_local(client, token, "open-confirmation", {"area": "drp", "preview_id": drp_preview["preview_id"],
                                                               "digest": drp_preview["digest"]}).json()["ok"]
        confirmation = urlsplit(opened[-1])
        grant = parse_qs(confirmation.fragment)["grant"][0]
        assert parse_qs(confirmation.query)["area"] == ["drp"]
        headers = {"authorization": "Bearer " + grant}
        assert client.post("/confirmation/status", headers=headers).json()["area"] == "drp"
        assert client.post("/confirmation/status", json={"area": "erp"}, headers=headers).status_code == 409
        loaded = client.post("/confirmation/status", json={"area": "drp"}, headers=headers).json()
        assert loaded["preview"]["preview_id"] == drp_preview["preview_id"]
        assert client.post("/confirmation/approve", json={"area": "erp", "digest": drp_preview["digest"]}, headers=headers).status_code == 409
        assert client.post("/confirmation/approve", json={"area": "drp", "digest": drp_preview["digest"]}, headers=headers).json()["ok"]
        assert root.ledger.get_preview("codex", erp_preview["preview_id"])["status"] == "ready"
        result = call_local(client, token, "execute", {"area": "drp", "preview_id": drp_preview["preview_id"], "digest": drp_preview["digest"]})
        assert result.json()["ok"] and child.erp.executions == ["codex"] and root.erp.executions == []


def test_read_and_write_proposals_consume_only_top_level_area_metadata(unified, monkeypatch):
    root, child = unified
    received = []
    async def propose(profile, body):
        assert "area" not in body
        assert body["parameters"]["area"] == "business-region"
        received.append((profile, body))
        return {"ok": True, "interface": {"name": body["name"]}}
    monkeypatch.setattr(child, "propose_read_interface", propose)
    monkeypatch.setattr(child, "propose_write_interface", propose)
    token = root.vault.ensure_client("codex")
    with TestClient(create_app(root)) as client:
        for action in ("interface-propose", "write-propose"):
            result = call_local(client, token, action, {"area": "drp", "name": "fixture-proposal",
                                                        "parameters": {"area": "business-region"}})
            assert result.json()["ok"]
    assert len(received) == 2 and all(profile == "codex" for profile, _ in received)


def test_manager_login_actions_only_change_selected_area(unified, monkeypatch):
    root, child = unified
    sso = []
    async def connect(profile, area="drp"):
        sso.append((profile, area))
        return {"ok": True, "login": {"status": "connected"}}
    monkeypatch.setattr(root, "connect_area_from_erp", connect)
    headers = {"authorization": "Bearer " + root.vault.manager_token()}
    with TestClient(create_app(root)) as client:
        options = client.post("/manage/login-options", headers=headers, json={"profile": "codex"}).json()
        assert options["area"] == "erp" and options["areas"] == ["erp", "drp"]
        for action in ["login-send-code", "login-submit-code", "login-cancel"]:
            assert client.post("/manage/" + action, headers=headers, json={"profile": "codex", "area": "drp", "code": "123456"}).status_code == 200
        assert client.post("/manage/login-from-erp", headers=headers, json={"profile": "codex", "area": "drp"}).json()["ok"]
        assert sso == [("codex", "drp")]
        assert client.post("/manage/login-from-erp", headers=headers, json={"profile": "codex", "area": "drp", "source_profile": "another"}).status_code == 409
        assert client.post("/manage/logout", headers=headers, json={"profile": "codex", "area": "drp"}).json()["ok"]
        assert child.vault.load_session("codex") is None and root.vault.load_session("codex") is not None
        assert all(action[1] == "codex" for action in child.browser.actions) and root.browser.actions == []


def remote_login(client, account):
    return client.post("/portal/login", json={"username": account["username"], "password": PASSWORD,
                                               "connection_id": account["connection_id"]}, headers={"origin": ORIGIN}).json()


def remote_api(client, account, action, body=None):
    return client.post("/api/" + action, json=body or {}, headers={"authorization": "Bearer " + account["access_token"]})


def test_one_remote_domain_token_and_employee_session_handle_both_areas(unified):
    root, child = unified
    employees = EmployeeStore(root.root, root.vault)
    alice, bob = employees.create_employee("alice", PASSWORD), employees.create_employee("bob", PASSWORD)
    profile = employees.bearer(alice["access_token"])["profile"]
    for service in (root, child):
        service.vault.save_session(profile, {}, {"company_id": service.platform + "-alice", "user_id": "alice"})
    drp_preview = preview(child, profile)
    with TestClient(create_remote_app(root, ORIGIN, employees=employees), base_url=ORIGIN) as client:
        assert remote_api(client, alice, "status").json()["connection"]["identity"]["company_id"] == "erp-alice"
        assert remote_api(client, alice, "status", {"area": "drp"}).json()["connection"]["identity"]["company_id"] == "drp-alice"
        assert remote_api(client, bob, "status", {"area": "drp"}).json()["connection"]["status"] == "disconnected"
        link = remote_api(client, alice, "open-manager", {"area": "drp"}).json()["url"]
        assert urlsplit(link).netloc == urlsplit(ORIGIN).netloc and parse_qs(urlsplit(link).query)["area"] == ["drp"]
        confirmation = remote_api(client, alice, "open-confirmation", {"area": "drp", "preview_id": drp_preview["preview_id"], "digest": drp_preview["digest"]}).json()["url"]
        assert parse_qs(urlsplit(confirmation).query)["area"] == ["drp"]
        session = remote_login(client, alice)
        headers = {"origin": ORIGIN, "x-csrf-token": session["csrf"]}
        assert session["default_area"] == "erp" and session["areas"] == ["erp", "drp"]
        assert client.post("/portal/operation", headers=headers, json={"area": "erp", "preview_id": drp_preview["preview_id"]}).status_code == 409
        assert client.post("/portal/approve", headers=headers, json={"area": "drp", "preview_id": drp_preview["preview_id"], "digest": drp_preview["digest"]}).json()["ok"]
        assert client.post("/portal/connection/logout", headers=headers, json={"area": "drp"}).json()["ok"]
        assert root.vault.load_session(profile) is not None and child.vault.load_session(profile) is None
        assert remote_api(client, alice, "approve", {"area": "drp"}).status_code == 409


def test_remote_child_never_accepts_other_employee_or_source_parameters(unified):
    root, _child = unified
    employees = EmployeeStore(root.root, root.vault)
    alice = employees.create_employee("alice", PASSWORD)
    with TestClient(create_remote_app(root, ORIGIN, employees=employees), base_url=ORIGIN) as client:
        session = remote_login(client, alice)
        headers = {"origin": ORIGIN, "x-csrf-token": session["csrf"]}
        for key in ("profile", "company_id", "source_profile", "source_identity", "erp_data_dir", "token", "platform"):
            assert remote_api(client, alice, "status", {"area": "drp", key: "other"}).status_code == 409
            assert client.post("/portal/connection/login-from-erp", headers=headers,
                               json={"area": "drp", key: "other"}).status_code == 409
        assert client.post("/portal/connection/status", headers=headers, json={"area": "unknown"}).status_code == 409


def test_default_login_options_does_not_create_drp_or_trigger_sso(tmp_path, monkeypatch):
    monkeypatch.setenv("JST_CONNECTOR_MASTER_KEY", Fernet.generate_key().decode())
    root = ConnectorService(tmp_path)
    root.browser, root.erp = AreaBrowser(root.vault, "erp"), AreaERP("erp")
    with TestClient(create_app(root)) as client:
        headers = {"authorization": "Bearer " + root.vault.manager_token()}
        assert client.post("/manage/login-options", headers=headers, json={"profile": "codex"}).json()["area"] == "erp"
        assert root._area_children == {} and not (tmp_path / "modules" / "drp").exists()


def test_one_local_login_page_switches_area_and_uses_same_actor_erp_connection(unified, monkeypatch):
    from playwright.sync_api import expect, sync_playwright
    root, child = unified
    child.vault.clear_session("codex")
    requests, opened, connections, errors = [], [], [], []
    async def connect(profile, area="drp"):
        connections.append((profile, area))
        child.vault.save_session(profile, {}, {"company_id": "drp-company", "user_id": "drp-person"})
        return {"ok": True, "login": {"status": "connected"}}
    monkeypatch.setattr(root, "connect_area_from_erp", connect)
    with TestClient(create_app(root, opener=lambda url: opened.append(url) or True), base_url="http://127.0.0.1:19739") as client, sync_playwright() as playwright:
        call_local(client, root.vault.ensure_client("codex"), "open-manager")
        browser = playwright.chromium.launch()
        context = browser.new_context()
        def route_request(route):
            request = route.request
            assert request.url.startswith("http://127.0.0.1:19739/")
            if request.method == "POST":
                requests.append((urlsplit(request.url).path, request.post_data_json))
            response = client.request(request.method, request.url, headers=request.headers, content=request.post_data)
            route.fulfill(status=response.status_code, headers=dict(response.headers), body=response.content)
        context.route("**/*", route_request)
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(opened[-1])
        expect(page.locator("#business-area")).to_have_value("erp")
        expect(page.locator("#business-area")).to_be_enabled()
        expect(page.locator("#connected-area")).to_be_visible()
        screenshots = Path(__file__).resolve().parents[1] / "artifacts"
        screenshots.mkdir(exist_ok=True)
        page.screenshot(path=str(screenshots / "unified-connector-erp.png"), full_page=True)
        assert connections == []
        page.locator("#business-area").select_option("drp")
        expect(page.locator("#erp-connect")).to_be_visible()
        page.locator("#erp-connect").click()
        expect(page.locator("#connected-area")).to_be_visible()
        page.screenshot(path=str(screenshots / "unified-connector-drp.png"), full_page=True)
        assert connections == [("codex", "drp")]
        assert all(body.get("profile") == "codex" for _path, body in requests)
        assert all(body["area"] == "drp" for path, body in requests if path.endswith("login-from-erp"))
        assert "分销连接器" not in page.locator(".brand-name").inner_text()
        assert not errors
        browser.close()


@pytest.mark.parametrize("late_error", [False, True])
def test_remote_browser_switch_stale_logout_does_not_clear_new_area_inputs(unified, late_error):
    from playwright.sync_api import expect, sync_playwright
    root, child = unified
    employees = EmployeeStore(root.root, root.vault)
    alice = employees.create_employee("alice", PASSWORD)
    actor = employees.bearer(alice["access_token"])["profile"]
    root.vault.save_session(actor, {}, {"company_id": "erp-alice", "user_id": "alice"})
    delayed, errors, actions = [], [], []
    with TestClient(create_remote_app(root, ORIGIN, employees=employees), base_url=ORIGIN) as client, sync_playwright() as playwright:
        remote_login(client, alice)
        browser = playwright.chromium.launch()
        context = browser.new_context()
        for item in client.cookies.jar:
            context.add_cookies([{"name": item.name, "value": item.value, "domain": item.domain,
                                  "path": item.path, "secure": True, "httpOnly": True, "sameSite": "Strict"}])
        def route_request(route):
            request = route.request
            assert request.url.startswith(ORIGIN + "/")
            if request.method == "POST":
                body = request.post_data_json
                actions.append((urlsplit(request.url).path, body))
                if request.url.endswith("/portal/connection/logout"):
                    delayed.append(route)
                    return
            response = client.request(request.method, request.url, headers=request.headers, content=request.post_data)
            route.fulfill(status=response.status_code, headers=dict(response.headers), body=response.content)
        context.route("**/*", route_request)
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("dialog", lambda dialog: dialog.accept())
        page.goto(ORIGIN + "/login?connection=" + alice["connection_id"])
        expect(page.locator("#business-area")).to_have_value("erp")
        expect(page.locator("#jst-logout")).to_be_enabled()
        page.locator("#jst-logout").click()
        page.locator("#business-area").select_option("drp")
        expect(page.locator("#jst-form")).to_be_visible()
        page.locator("#username").fill("fixture-new-drp-person")
        page.locator("#remember").check()
        assert delayed
        delayed.pop().fulfill(status=409 if late_error else 200,
                              json={"ok": False, "error": {"message": "fixture-old-area-error"}} if late_error else {"ok": True})
        expect(page.locator("#username")).to_have_value("fixture-new-drp-person")
        expect(page.locator("#remember")).to_be_checked()
        expect(page.locator("#message")).not_to_contain_text("fixture-old-area-error")
        assert child.vault.load_session(actor) is None
        assert not any(path.endswith("login-from-erp") for path, _ in actions)
        assert not errors
        browser.close()


@pytest.mark.parametrize("late_action", ["login-password", "login-from-erp"])
def test_remote_late_password_or_sso_error_does_not_replace_other_area_state(unified, late_action):
    from playwright.sync_api import expect, sync_playwright
    root, _child = unified
    employees = EmployeeStore(root.root, root.vault)
    alice = employees.create_employee("alice", PASSWORD)
    actor = employees.bearer(alice["access_token"])["profile"]
    if late_action == "login-from-erp":
        root.vault.save_session(actor, {}, {"company_id": "erp-alice", "user_id": "alice"})
    delayed = []
    with TestClient(create_remote_app(root, ORIGIN, employees=employees), base_url=ORIGIN) as client, sync_playwright() as playwright:
        remote_login(client, alice)
        browser = playwright.chromium.launch()
        context = browser.new_context()
        for item in client.cookies.jar:
            context.add_cookies([{"name": item.name, "value": item.value, "domain": item.domain,
                                  "path": item.path, "secure": True, "httpOnly": True, "sameSite": "Strict"}])
        def route_request(route):
            request = route.request
            assert request.url.startswith(ORIGIN + "/")
            if request.url.endswith("/portal/connection/" + late_action):
                delayed.append(route)
                return
            response = client.request(request.method, request.url, headers=request.headers, content=request.post_data)
            route.fulfill(status=response.status_code, headers=dict(response.headers), body=response.content)
        context.route("**/*", route_request)
        page = context.new_page()
        page.goto(ORIGIN + "/login?connection=" + alice["connection_id"])
        expect(page.locator("#business-area")).to_be_enabled()
        if late_action == "login-from-erp":
            page.locator("#business-area").select_option("drp")
            expect(page.locator("#erp-connect")).to_be_visible()
            page.locator("#erp-connect").click()
            destination = "erp"
        else:
            expect(page.locator("#jst-form")).to_be_visible()
            page.locator("#username").fill("fixture-old-person")
            page.locator("#password").fill("fixture-old-password")
            page.locator("#terms").check()
            page.locator("#jst-submit").click()
            destination = "drp"
        page.locator("#business-area").select_option(destination)
        expect(page.locator("#business-area")).to_have_value(destination)
        if destination == "erp":
            expect(page.locator("#complete")).to_be_visible()
        else:
            expect(page.locator("#jst-form")).to_be_visible()
            page.locator("#username").fill("fixture-new-person")
        assert delayed
        delayed.pop().fulfill(status=409, json={"ok": False, "error": {"message": "fixture-old-auth-error"}})
        expect(page.locator("#message")).not_to_contain_text("fixture-old-auth-error")
        if destination == "drp":
            expect(page.locator("#username")).to_have_value("fixture-new-person")
        browser.close()
