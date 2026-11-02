"""安装配置平台固定，两个连接器条目不能混用运行资料或远程调用。"""
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from jst_connector.agent import create_app
from jst_connector.cli import _write_config
from jst_connector.client import AgentClient
from jst_connector.config import data_directory
from jst_connector.errors import ConnectorError
from jst_connector.platform_policy import get_policy
from jst_connector.platform_store import ensure_platform
from jst_connector.remote import EmployeeStore, create_remote_app
from jst_connector.remote_client import RemoteAgentClient
from jst_connector.service import ConnectorService
from jst_connector.vault import Vault


def test_platform_stores_are_independent_but_config_has_one_connector_name(tmp_path, monkeypatch):
    monkeypatch.setenv("JST_CONNECTOR_DATA_DIR", str(tmp_path))
    assert data_directory(platform="erp") == tmp_path
    assert data_directory(platform="drp") == tmp_path / "drp"
    assert data_directory(tmp_path / "explicit", platform="drp") == tmp_path / "explicit"
    config = json.loads(_write_config(tmp_path / "drp", "codex", "generic", platform="drp"))
    assert set(config["mcpServers"]) == {"jushuitan"}
    args = config["mcpServers"]["jushuitan"]["args"]
    assert args[args.index("--platform") + 1] == "drp"
    assert args[args.index("--data-dir") + 1] == str(tmp_path / "drp")
    assert "jushuitan" in json.loads(_write_config(tmp_path, "codex", "generic"))["mcpServers"]


@pytest.mark.parametrize("filename", ["vault.enc", "masterkey.dpapi", "interfaces.sqlite3", "write-interfaces.sqlite3",
                                      "ledger.sqlite3", "employees.sqlite3", "agent.json", "sso-links.sqlite3"])
def test_existing_unmarked_erp_artifacts_cannot_be_reinterpreted_as_drp(tmp_path, filename):
    (tmp_path / filename).write_bytes(b"old-erp-artifact")
    with pytest.raises(ConnectorError, match="ERP"):
        ensure_platform(tmp_path, "drp")
    assert not (tmp_path / ".platform.json").exists()


def test_platform_pin_is_checked_before_vault_read_and_never_changes(tmp_path):
    ensure_platform(tmp_path, "erp")
    (tmp_path / "vault.enc").write_bytes(b"invalid-encrypted-erp-store")
    with pytest.raises(ConnectorError) as raised:
        ConnectorService(tmp_path, platform="drp")
    assert raised.value.code == "platform_mismatch"
    assert json.loads((tmp_path / ".platform.json").read_text())["platform"] == "erp"


def test_wrong_platform_doctor_never_constructs_vault(tmp_path, monkeypatch, capsys):
    import jst_connector.vault as vault_module
    from jst_connector.cli import main

    ensure_platform(tmp_path, "erp")
    (tmp_path / "vault.enc").write_bytes(b"fixture-erp-store")
    monkeypatch.setattr(vault_module, "Vault", lambda *args, **kwargs: pytest.fail("must not read ERP vault"))
    with pytest.raises(SystemExit) as raised:
        main(["doctor", "--platform", "drp", "--data-dir", str(tmp_path)])
    assert raised.value.code == 1 and "platform_mismatch" in capsys.readouterr().err


def service_for(root, platform, monkeypatch):
    monkeypatch.setenv("JST_CONNECTOR_MASTER_KEY", Fernet.generate_key().decode())
    ensure_platform(root, platform)
    vault = Vault(root)
    browser = SimpleNamespace(site_policy=get_policy(platform), close=AsyncMock(), close_idle=AsyncMock())
    service = ConnectorService(root, platform=platform, vault=vault, browser=browser)
    return service


@pytest.mark.parametrize("platform,other", [("erp", "drp"), ("drp", "erp")])
def test_local_and_remote_reject_wrong_platform_before_tool_dispatch(tmp_path, monkeypatch, platform, other):
    service = service_for(tmp_path, platform, monkeypatch)
    with TestClient(create_app(service)) as client:
        assert client.post("/api/query", json={}, headers={"X-JST-Platform": other}).json()["error"]["code"] == "platform_mismatch"
        assert client.get("/health").json()["platform"] == platform
    store = EmployeeStore(tmp_path, service.vault)
    app = create_remote_app(service, "https://connector.example.com", employees=store)
    with TestClient(app, base_url="https://connector.example.com") as client:
        result = client.post("/api/execute", json={}, headers={"X-JST-Platform": other})
        assert result.json()["error"]["code"] == "platform_mismatch"


def test_drp_client_rejects_legacy_erp_agent_state_before_health_probe(tmp_path, monkeypatch):
    monkeypatch.setenv("JST_CONNECTOR_MASTER_KEY", Fernet.generate_key().decode())
    client = AgentClient(tmp_path, "codex", platform="drp", auto_start=False)
    (tmp_path / "agent.json").write_text(json.dumps({"url": "http://127.0.0.1:12345"}))
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: pytest.fail("must not contact ERP agent"))
    assert client._running_url() is None


def test_remote_client_transmits_fixed_platform_header():
    observed = []
    def handle(request):
        observed.append(request.headers["x-jst-platform"])
        return httpx.Response(200, json={"ok": True})
    client = RemoteAgentClient("https://connector.example.com", "jst_remote_" + "a" * 43,
                               platform="drp", transport=httpx.MockTransport(handle))
    assert client.call("status")["ok"] is True and observed == ["drp"]
