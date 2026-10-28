import asyncio
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from jst_connector.agent import create_app
from jst_connector.client import validate_agent_url
from jst_connector.errors import ConnectorError
from jst_connector.service import ConnectorService
from jst_connector.vault import Vault


class BrowserFixture:
    def __init__(self, vault):
        self.vault = vault

    async def status(self, profile):
        session = self.vault.load_session(profile)
        return {"status": "connected" if session else "disconnected", "identity": session and session["identity"]}

    async def close_idle(self):
        pass

    async def close(self):
        pass

    async def logout(self, profile):
        self.vault.clear_session(profile)


class ERPFixture:
    """只存在于测试包中的受控 ERP；发布包不包含此适配器。"""
    def __init__(self):
        self.executions = 0
        self.current = True
        self.lose_response = False

    def catalog(self):
        return [{"id": "Q02", "name": "商品查询", "status": "test_only"}]

    async def query(self, profile, capability_id, parameters):
        return {"rows": [{"sku_id": "fixture-sku"}], "complete": True, "has_more": False}

    async def preview(self, profile, capability_id, parameters):
        return {"source_verified": True, "atomicity": "verified", "payload": {"id": "fixture-document"},
                "checks": {"remote_fixture": "checked"}}

    async def revalidate(self, profile, payload):
        return self.current

    async def execute(self, profile, payload):
        self.executions += 1
        if self.lose_response:
            raise TimeoutError("fixture timeout")
        return {"verified": True, "document_id": "fixture-document"}


@pytest.fixture
def service(tmp_path):
    vault = Vault(tmp_path, key=Fernet.generate_key())
    vault.save_session("codex", {"cookies": []}, {"company_id": "fixture-company", "user_id": "fixture-user"})
    return ConnectorService(tmp_path, vault=vault, browser=BrowserFixture(vault), erp=ERPFixture())


def test_client_cannot_confirm_or_self_report_identity(service):
    token = service.vault.ensure_client("codex")
    app = create_app(service, opener=lambda url: True)
    with TestClient(app) as client:
        body = {"profile": "workbuddy", "confirmed": True, "company_id": "another-company"}
        assert client.post("/manage/approve", json=body, headers={"Authorization": "Bearer " + token}).status_code == 401
        assert client.post("/api/approve", json=body, headers={"Authorization": "Bearer " + token}).status_code == 409
        response = client.post("/api/status", json=body, headers={"Authorization": "Bearer " + token})
        assert response.json()["client"] == "codex"
        assert response.json()["connection"]["identity"]["company_id"] == "fixture-company"


def test_new_interface_approval_is_not_available_to_mcp_client(service):
    token = service.vault.ensure_client("codex")
    body = {"profile": "workbuddy", "interface_id": "fixture-interface", "digest": "fixture-digest"}
    with TestClient(create_app(service)) as client:
        assert client.post("/manage/interface-approve", json=body,
                           headers={"Authorization": "Bearer " + token}).status_code == 401
        assert client.post("/api/interface-approve", json=body,
                           headers={"Authorization": "Bearer " + token}).status_code == 409


def test_cross_origin_and_dns_rebinding_rejected(service):
    with TestClient(create_app(service)) as client:
        assert client.post("/api/status", json={}, headers={"Origin": "https://untrusted.example"}).status_code == 403
        assert client.get("/health", headers={"Host": "untrusted.example"}).status_code == 403


def test_open_manager_does_not_return_management_secret(service):
    opened = []
    token = service.vault.ensure_client("codex")
    with TestClient(create_app(service, opener=lambda url: opened.append(url) or True)) as client:
        response = client.post("/api/open-manager", json={}, headers={"Authorization": "Bearer " + token})
        assert response.status_code == 200
        assert opened and "#profile=codex&token=" in opened[0]
        assert service.vault.manager_token() not in response.text
        assert response.headers["cache-control"] == "no-store"


def test_management_ui_requires_no_erp_or_secret_to_render(service):
    with TestClient(create_app(service)) as client:
        response = client.get("/ui")
        assert response.status_code == 200
        assert "聚水潭个人连接器" in response.text
        assert service.vault.manager_token() not in response.text


def test_password_and_sms_actions_are_manager_only(service):
    calls = []

    async def password_login(profile, username, password, **options):
        calls.append(("password", profile, username, password, options))
        return {"status": "logging_in", "message": "正在登录。"}

    async def login_status(profile):
        return {"status": "need_code", "can_send_code": True}

    async def send_login_code(profile):
        calls.append(("send", profile))
        return {"status": "need_code", "can_send_code": False}

    async def submit_login_code(profile, code):
        calls.append(("code", profile, code))
        return {"status": "verifying"}

    async def cancel_login(profile):
        calls.append(("cancel", profile))
        return {"status": "cancelled"}

    for method in (password_login, login_status, send_login_code, submit_login_code, cancel_login):
        setattr(service.browser, method.__name__, method)
    manager = {"Authorization": "Bearer " + service.vault.manager_token()}
    caller = {"Authorization": "Bearer " + service.vault.ensure_client("codex")}
    body = {"profile": "codex", "username": "fixture@example.test", "password": "fixture-password",
            "remember": True, "terms_accepted": True, "code": "123456"}
    with TestClient(create_app(service)) as client:
        for action in ("login-password", "login-status", "login-send-code", "login-submit-code", "login-cancel"):
            assert client.post("/manage/" + action, json=body, headers=caller).status_code == 401
            assert client.post("/api/" + action, json=body, headers=caller).status_code == 409
        assert calls == []
        assert client.post("/manage/identity-evidence", json=body, headers=caller).status_code == 401
        assert client.post("/api/identity-evidence", json=body, headers=caller).status_code == 409
        for action in ("login-password", "login-status", "login-send-code", "login-submit-code", "login-cancel"):
            result = client.post("/manage/" + action, json=body, headers=manager)
            assert result.status_code == 200
            assert "fixture-password" not in result.text and "123456" not in result.text
        assert calls[0] == ("password", "codex", "fixture@example.test", "fixture-password",
                            {"remember": True, "terms_accepted": True})
        assert calls[1:] == [("send", "codex"), ("code", "codex", "123456"), ("cancel", "codex")]
        for action in ("login-start", "login-view", "login-action", "login-finish"):
            assert client.post("/manage/" + action, json=body, headers=manager).status_code == 409


def test_execute_only_after_trusted_confirmation_and_no_duplicate(service):
    async def scenario():
        preview = (await service.preview("codex", "W-test", {}))["preview"]
        with pytest.raises(ConnectorError, match="确认"):
            await service.execute("codex", preview["preview_id"], preview["digest"])
        service.approve("codex", preview["preview_id"], preview["digest"])
        assert (await service.execute("codex", preview["preview_id"], preview["digest"]))["ok"]
        repeated = await service.execute("codex", preview["preview_id"], preview["digest"])
        assert repeated["preview"]["status"] == "succeeded"
        assert service.erp.executions == 1
    asyncio.run(scenario())


def test_changed_source_blocks_before_any_write(service):
    async def scenario():
        preview = (await service.preview("codex", "W-test", {}))["preview"]
        service.approve("codex", preview["preview_id"], preview["digest"])
        service.erp.current = False
        with pytest.raises(ConnectorError) as failure:
            await service.execute("codex", preview["preview_id"], preview["digest"])
        assert failure.value.code == "preview_stale"
        assert service.erp.executions == 0
    asyncio.run(scenario())


def test_timeout_marks_unknown_and_never_resubmits(service):
    async def scenario():
        preview = (await service.preview("codex", "W-test", {}))["preview"]
        service.approve("codex", preview["preview_id"], preview["digest"])
        service.erp.lose_response = True
        with pytest.raises(ConnectorError) as failure:
            await service.execute("codex", preview["preview_id"], preview["digest"])
        assert failure.value.code == "result_unknown"
        result = await service.execute("codex", preview["preview_id"], preview["digest"])
        assert result["preview"]["status"] == "unknown"
        assert service.erp.executions == 1
    asyncio.run(scenario())


@pytest.mark.parametrize("url", ["https://example.com", "http://127.0.0.1:80@evil.example", "http://localhost:1000",
                                     "http://127.0.0.1:1000/path", "file:///tmp/state", "http://127.0.0.1:bad"])
def test_agent_address_cannot_leak_client_token(url):
    with pytest.raises(ConnectorError):
        validate_agent_url(url)


def test_config_has_no_credentials_and_parses_as_toml(tmp_path):
    import tomllib

    from jst_connector.cli import _write_config
    content = _write_config(Path(tmp_path), "codex", "codex")
    parsed = tomllib.loads(content)
    assert parsed["mcp_servers"]["jushuitan"]["args"][3:5] == ["--client", "codex"]
    assert "token" not in content.lower()

