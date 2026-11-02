"""一个授权入口下的ERP/分销按需板块；只使用离线身份与响应。"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

import pytest
from cryptography.fernet import Fernet

import jst_connector.erp_sso as sso_module
from jst_connector.errors import ConnectorError
from jst_connector.platform_store import ensure_platform
from jst_connector.service import ConnectorService
from jst_connector.vault import Vault

ALICE_ERP = {"company_id": "100", "user_id": "201"}
BOB_ERP = {"company_id": "100", "user_id": "202"}
ALICE_DRP = {"company_id": "900", "user_id": "901"}


class Browser:
    def __init__(self, vault):
        self.vault = vault
        self.status_calls = []
        self.scope_calls = []
        self.idle_calls = 0
        self.close_calls = 0
        self.discarded = []
        self.fail_scope_exit = False

    async def status(self, profile):
        self.status_calls.append(profile)
        saved = self.vault.load_session(profile)
        return {"status": "connected" if saved else "disconnected", "identity": saved and saved["identity"]}

    @asynccontextmanager
    async def verified_scope(self, profile):
        self.scope_calls.append(profile)
        saved = self.vault.load_session(profile)
        if saved is None:
            raise ConnectorError("LOGIN_REQUIRED", "请先登录本人账号。")
        yield saved["identity"]
        if self.fail_scope_exit:
            raise ConnectorError("QUERY_SESSION_CHANGED", "来源账号在退出核验时变化。")

    async def close_idle(self):
        self.idle_calls += 1

    async def close(self):
        self.close_calls += 1

    async def discard_if_binding(self, profile, binding):
        self.discarded.append((profile, binding))
        if self.vault.session_binding(profile) == binding:
            self.vault.clear_session(profile)


class Adapter:
    def __init__(self, label):
        self.label = label
        self.executions = []

    def catalog(self):
        return [{"id": "fixture", "name": self.label}]

    async def preview(self, profile, capability, parameters):
        return {"source_verified": True, "atomicity": "verified", "payload": {"id": self.label},
                "checks": {"fixture": "only"}}

    async def revalidate(self, profile, payload):
        return True

    async def execute(self, profile, payload):
        self.executions.append((profile, payload))
        return {"verified": True, "id": self.label}


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("JST_CONNECTOR_MASTER_KEY", Fernet.generate_key().decode())
    store = tmp_path / "connector"
    vault = Vault(store)
    return ConnectorService(store, vault=vault, browser=Browser(vault), erp=Adapter("erp"))


def child_fixture(root):
    child = root.area_service("drp")
    child.browser = Browser(child.vault)
    child.erp = Adapter("drp")
    return child


async def test_default_erp_options_status_catalog_and_cleanup_do_not_load_drp(root):
    assert root.area_service() is root and root.area_service("erp") is root
    options = root.area_login_options("alice")
    assert options["area"] == "erp" and options["default_area"] == "erp" and options["areas"] == ["erp", "drp"]
    assert not root._area_children and not (root.root / "modules").exists()
    status = await root.status("alice")
    assert status["modules"]["drp"] == {"area": "drp", "initialized": False, "live_checked": False, "status": "not_loaded"}
    assert root.catalog()["capabilities"][0]["name"] == "erp"
    await root.close_idle()
    await root.close()
    assert root.browser.idle_calls == 1 and root.browser.close_calls == 1
    assert not root._area_children and not (root.root / "modules").exists()


def test_drp_is_lazy_isolated_and_reuses_no_root_tool_credentials(root):
    token = root.vault.ensure_client("alice")
    root.vault.save_session("alice", {"cookies": [{"value": "ERP-ONLY"}]}, ALICE_ERP)
    child = root.area_service("drp")
    assert child is root.area_service("drp")
    assert child.root == root.root / "modules" / "drp" and child.platform == "drp"
    assert child.vault.load_session("alice") is None
    assert child.vault.client_for_token(token) is None
    assert root.authenticate(token) == "alice"
    assert child.browser._browser is None
    assert child.vault._read()["clients"] == {}


def test_parallel_area_selection_creates_only_one_internal_drp_service(root):
    with ThreadPoolExecutor(max_workers=4) as executor:
        children = list(executor.map(lambda _: root.area_service("drp"), range(12)))
    assert all(child is children[0] for child in children)
    assert list(root._area_children) == ["drp"]


@pytest.mark.parametrize("area", ["", "other", "../drp", "drp/alice", {"profile": "bob"}, ["erp"], 1, True])
def test_unknown_area_cannot_select_an_actor_or_directory(root, area):
    with pytest.raises(ConnectorError, match="业务板块"):
        root.area_service(area)
    assert not root._area_children


def test_legacy_standalone_drp_keeps_default_and_does_not_jump_to_an_erp_root(root):
    legacy_root = root.root.parent / "old-drp"
    ensure_platform(legacy_root, "drp")
    vault = Vault(legacy_root)
    legacy = ConnectorService(legacy_root, platform="drp", vault=vault, browser=Browser(vault), erp=Adapter("drp"))
    assert legacy.area_service() is legacy and legacy.area_service("drp") is legacy
    assert legacy.area_login_options("alice")["areas"] == ["drp"]
    with pytest.raises(ConnectorError, match="历史独立分销"):
        legacy.area_service("erp")
    assert not legacy._area_children


async def test_legacy_standalone_explicit_erp_link_remains_usable(root, monkeypatch):
    root.vault.save_session("alice", {"cookies": []}, ALICE_ERP)
    legacy_root = root.root.parent / "old-drp"
    ensure_platform(legacy_root, "drp")
    vault = Vault(legacy_root)
    legacy = ConnectorService(legacy_root, platform="drp", vault=vault, browser=Browser(vault), erp=Adapter("drp"))
    links = sso_module.ErpLinks(legacy.root, legacy.vault)
    links.pair("old-ai", root.root, "alice")
    prior = links.get("old-ai")
    calls = []

    async def exchange(target, profile):
        calls.append((target, profile))
        return {"ok": True, "login": {"status": "connected"}}

    monkeypatch.setattr(sso_module, "connect_from_erp", exchange)
    assert (await legacy.connect_area_from_erp("old-ai"))["ok"]
    assert calls == [(legacy, "old-ai")]
    assert links.get("old-ai") == prior and not legacy._area_children


def test_unified_drp_does_not_adopt_or_delete_existing_standalone_store(root):
    legacy_root = root.root / "drp"
    ensure_platform(legacy_root, "drp")
    old = Vault(legacy_root)
    old.ensure_client("old-profile")
    old.save_session("old-profile", {"cookies": [{"value": "OLD-DRP-ONLY"}]}, ALICE_DRP)
    before = (legacy_root / "vault.enc").read_bytes()
    child = root.area_service("drp")
    assert child.root != legacy_root and child.vault.load_session("old-profile") is None
    assert (legacy_root / "vault.enc").read_bytes() == before


async def test_light_module_status_and_idle_cleanup_do_not_restore_drp_browser(root):
    child = child_fixture(root)
    child.vault.save_session("alice", {"cookies": []}, ALICE_DRP)
    status = await root.status("alice")
    assert status["modules"]["drp"]["status"] == "saved_session"
    assert status["modules"]["drp"]["live_checked"] is False
    assert child.browser.status_calls == []
    assert (await root.status("bob"))["modules"]["drp"]["status"] == "disconnected"
    await root.close_idle()
    assert root.browser.idle_calls == child.browser.idle_calls == 1
    await root.close()
    assert root.browser.close_calls == child.browser.close_calls == 1


async def test_profiles_and_preview_approval_execute_are_isolated_by_area(root):
    root.vault.save_session("alice", {"cookies": []}, ALICE_ERP)
    child = child_fixture(root)
    child.vault.save_session("alice", {"cookies": []}, ALICE_DRP)
    child.vault.save_session("bob", {"cookies": []}, {"company_id": "900", "user_id": "902"})
    erp_preview = (await root.preview("alice", "fixture", {}))["preview"]
    drp_preview = (await child.preview("alice", "fixture", {}))["preview"]
    with pytest.raises(ConnectorError):
        child.approve("alice", erp_preview["preview_id"], erp_preview["digest"])
    with pytest.raises(ConnectorError):
        await root.execute("alice", drp_preview["preview_id"], drp_preview["digest"])
    with pytest.raises(ConnectorError):
        child.approve("bob", drp_preview["preview_id"], drp_preview["digest"])
    with pytest.raises(ConnectorError):
        await root.reconcile_operation("alice", drp_preview["preview_id"])
    assert root.erp.executions == child.erp.executions == []
    child.approve("alice", drp_preview["preview_id"], drp_preview["digest"])
    assert (await child.execute("alice", drp_preview["preview_id"], drp_preview["digest"]))["ok"]
    assert len(child.erp.executions) == 1 and root.erp.executions == []


def test_area_options_offer_same_actor_erp_source_without_launching_or_pairing(root):
    root.vault.save_session("alice", {"cookies": []}, ALICE_ERP)
    options = root.area_login_options("alice", "drp")
    child = root.area_service("drp")
    assert options["platform"] == options["area"] == "drp"
    assert options["erp_sso_available"] and options["erp_sso_source"] == "same_connector"
    assert not root.area_login_options("bob", "drp")["erp_sso_available"]
    assert root.browser.scope_calls == [] and child.browser._browser is None
    assert not (child.root / "sso-links.sqlite3").exists()


async def test_internal_sso_pairing_can_only_use_root_same_authenticated_profile(root, monkeypatch):
    root.vault.save_session("alice", {"cookies": [{"value": "ERP-ONLY"}]}, ALICE_ERP)
    root.vault.save_session("bob", {"cookies": [{"value": "BOB-ERP-ONLY"}]}, BOB_ERP)
    child = child_fixture(root)
    calls = []

    async def exchange(target, profile, *, include_binding=False):
        paired = sso_module.ErpLinks(target.root, target.vault).get(profile)
        calls.append((target, profile, paired))
        assert target is child and profile == "alice"
        assert paired["source_profile"] == "alice" and paired["source_identity"] == ALICE_ERP
        assert paired["source_root"] == str(root.root.resolve())
        assert target.vault.load_session(profile) is None
        target.vault.save_session(profile, {"cookies": [{"value": "DRP-ONLY"}]}, ALICE_DRP)
        assert include_binding is True
        return {"ok": True, "login": {"status": "connected"}, "_issued_binding": target.vault.session_binding(profile)}

    monkeypatch.setattr(sso_module, "connect_from_erp", exchange)
    result = await root.connect_area_from_erp("alice", "drp")
    assert result["ok"] and result["area"] == "drp" and len(calls) == 1
    assert root.browser.scope_calls == ["alice"]
    assert child.vault.load_session("bob") is None
    assert child.vault.load_session("alice")["state"]["cookies"] == [{"value": "DRP-ONLY"}]
    with pytest.raises(TypeError):
        await root.connect_area_from_erp("alice", "drp", source_profile="bob")


async def test_sso_missing_current_actor_does_not_fall_back_to_another_erp(root, monkeypatch):
    root.vault.save_session("bob", {"cookies": []}, BOB_ERP)
    called = []

    async def exchange(*args):
        called.append(args)

    monkeypatch.setattr(sso_module, "connect_from_erp", exchange)
    with pytest.raises(ConnectorError, match="先连接本人的ERP"):
        await root.connect_area_from_erp("alice", "drp")
    assert called == [] and root.vault.load_session("bob")["identity"] == BOB_ERP


@pytest.mark.parametrize("source_change", ["binding", "exit_verification"])
async def test_sso_source_change_revokes_only_the_new_drp_binding(root, monkeypatch, source_change):
    root.vault.save_session("alice", {"cookies": []}, ALICE_ERP)
    child = child_fixture(root)
    child.vault.save_session("bob", {"cookies": []}, {"company_id": "900", "user_id": "902"})
    if source_change == "exit_verification":
        root.browser.fail_scope_exit = True

    async def exchange(target, profile, *, include_binding=False):
        target.vault.save_session(profile, {"cookies": []}, ALICE_DRP)
        if source_change == "binding":
            root.vault.clear_session(profile)
        assert include_binding is True
        return {"ok": True, "login": {"status": "connected"}, "_issued_binding": target.vault.session_binding(profile)}

    monkeypatch.setattr(sso_module, "connect_from_erp", exchange)
    with pytest.raises(ConnectorError):
        await root.connect_area_from_erp("alice", "drp")
    assert child.vault.load_session("alice") is None
    assert child.vault.load_session("bob") is not None and len(child.browser.discarded) == 1


async def test_later_drp_login_is_not_revoked_when_erp_scope_fails(root, monkeypatch):
    root.vault.save_session("alice", {"cookies": []}, ALICE_ERP)
    child = child_fixture(root)
    root.browser.fail_scope_exit = True
    issued = []

    async def exchange(target, profile, *, include_binding=False):
        target.vault.save_session(profile, {"cookies": []}, ALICE_DRP)
        original = target.vault.session_binding(profile)
        issued.append(original)
        # Another process completed a different login after this exchange issued.
        target.vault.clear_session(profile)
        target.vault.save_session(profile, {"cookies": [{"value": "NEWER-LOGIN"}]}, ALICE_DRP)
        return {"ok": True, "login": {"status": "connected"}, "_issued_binding": original}

    monkeypatch.setattr(sso_module, "connect_from_erp", exchange)
    with pytest.raises(ConnectorError):
        await root.connect_area_from_erp("alice", "drp")
    assert child.browser.discarded == [("alice", issued[0])]
    assert child.vault.load_session("alice")["state"]["cookies"] == [{"value": "NEWER-LOGIN"}]
