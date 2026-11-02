"""分销首次业务按需接续；只使用受控登录回执，不连接真实ERP。"""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from test_unified_service import ALICE_DRP, ALICE_ERP, BOB_ERP, Adapter, Browser
from test_unified_service import root as root_fixture

import jst_connector.erp_sso as sso_module
from jst_connector.agent import create_app, dispatch_action
from jst_connector.errors import ConnectorError
from jst_connector.remote import EmployeeStore, create_remote_app
from jst_connector.service import ConnectorService
from jst_connector.vault import Vault

root = root_fixture
ORIGIN = "https://connector.example.com"


class Flows:
    def __init__(self):
        self.busy = set()
        self.locks = {}

    def active(self, profile):
        return profile in self.busy

    def _lock(self, profile):
        return self.locks.setdefault(profile, asyncio.Lock())


class AutoBrowser(Browser):
    def __init__(self, vault):
        super().__init__(vault)
        self._password_flows = Flows()
        self.identity_calls = []
        self.identity_error = None
        self.before_discard = None

    async def identity(self, profile):
        self.identity_calls.append(profile)
        if self.identity_error is not None:
            raise self.identity_error
        saved = self.vault.load_session(profile)
        if not saved:
            raise ConnectorError("LOGIN_REQUIRED", "分销尚未连接。")
        if saved["state"].get("expired"):
            raise ConnectorError("ERP_SESSION_REJECTED", "原分销登录态已由服务器明确拒绝。")
        return saved["identity"]

    async def status(self, profile):
        self.status_calls.append(profile)
        if self._password_flows.active(profile):
            return {"status": "login_pending"}
        if not self.vault.load_session(profile):
            return {"status": "disconnected"}
        try:
            return {"status": "connected", "identity": await self.identity(profile)}
        except ConnectorError:
            return {"status": "saved_unverified"}

    async def discard_if_binding(self, profile, binding):
        self.discarded.append((profile, binding))
        if self.before_discard is not None:
            await self.before_discard(profile, binding)
        return self.vault.clear_session(profile, expected_binding=binding)

    async def network_events(self, profile):
        return {"events": [{"classification": "blocked", "message": "仅此员工的脱敏诊断"}]}


class AutoAdapter(Adapter):
    async def query(self, profile, capability, parameters):
        return {"profile": profile, "area": "drp", "rows": []}


@pytest.fixture
def auto_env(root, monkeypatch):
    target = root.area_service("drp")
    target.browser = AutoBrowser(target.vault)
    target.erp = AutoAdapter("drp")
    env = SimpleNamespace(root=root, target=target, calls=[], fail=None, exchange_hook=None)

    async def exchange(service, profile, *, include_binding=False):
        env.calls.append(profile)
        await asyncio.sleep(0.01)
        if env.fail is not None:
            raise env.fail
        link = sso_module.ErpLinks(service.root, service.vault).get(profile)
        source = link["source_identity"]
        assert link["source_profile"] == profile and service is target
        identity = {"company_id": str(int(source["company_id"]) + 800), "user_id": str(int(source["user_id"]) + 700)}
        target.vault.save_session(profile, {"cookies": [{"value": "DRP-ONLY"}]}, identity)
        issued = target.vault.session_binding(profile)
        if env.exchange_hook is not None:
            await env.exchange_hook(profile)
        result = {"ok": True, "login": {"status": "connected", "identity": identity}}
        if include_binding:
            result["_issued_binding"] = issued
        return result

    monkeypatch.setattr(sso_module, "connect_from_erp", exchange)
    return env


def source(env, profile="alice", identity=ALICE_ERP):
    env.root.vault.save_session(profile, {"cookies": [{"value": "ERP-ONLY"}]}, identity)


async def test_default_erp_requests_never_create_or_connect_drp(root):
    assert not root._area_children
    await root.prepare_area("alice")
    await dispatch_action(root, "alice", "status", {})
    await dispatch_action(root, "alice", "catalog", {})
    await root.close_idle()
    assert not root._area_children and not (root.root / "modules").exists()


async def test_first_drp_use_is_single_flight_and_success_is_reused(auto_env):
    env = auto_env
    source(env)
    targets = await asyncio.gather(*(env.root.prepare_area("alice", "drp", required=True) for _ in range(8)))
    assert all(target is env.target for target in targets)
    assert env.calls == ["alice"]
    assert env.root.auto_connection("alice", "drp")["status"] == "connected"
    assert not env.root.auto_connection("alice", "drp")["can_password_login"]
    receipt = env.root._auto_receipt(env.target, "alice")
    assert receipt["source_binding"] == env.root.vault.session_binding("alice")
    assert receipt["target_binding"] == env.target.vault.session_binding("alice")
    assert receipt["target_binding"].encode() not in (env.target.root / "sso-links.sqlite3").read_bytes()


async def test_profiles_are_independently_prepared_without_source_fallback(auto_env):
    env = auto_env
    source(env, "alice", ALICE_ERP)
    source(env, "bob", BOB_ERP)
    await asyncio.gather(env.root.prepare_area("alice", "drp", required=True), env.root.prepare_area("bob", "drp", required=True))
    assert sorted(env.calls) == ["alice", "bob"]
    assert env.target.vault.load_session("alice")["identity"]["user_id"] == "901"
    assert env.target.vault.load_session("bob")["identity"]["user_id"] == "902"
    await env.root.prepare_area("charlie", "drp")
    assert env.target.vault.load_session("charlie") is None and len(env.calls) == 2


async def test_existing_independent_or_legacy_drp_is_verified_and_never_overwritten(auto_env):
    env = auto_env
    source(env)
    independent = {"company_id": "444", "user_id": "555"}
    env.target.vault.save_session("alice", {"cookies": [{"value": "MANUAL-ONLY"}]}, independent)
    binding = env.target.vault.session_binding("alice")
    await env.root.prepare_area("alice", "drp", required=True)
    env.root.vault.clear_session("alice")
    await env.root.prepare_area("alice", "drp", required=True)
    assert env.target.vault.session_binding("alice") == binding
    assert env.calls == [] and env.target.browser.discarded == []
    assert env.root._auto_receipt(env.target, "alice") is None


@pytest.mark.parametrize("error_code", ["IDENTITY_UNVERIFIED", "IDENTITY_CHANGED"])
async def test_uncertain_or_conflicting_existing_drp_is_not_cleared_or_replaced(auto_env, error_code):
    env = auto_env
    source(env)
    env.target.vault.save_session("alice", {"cookies": []}, ALICE_DRP)
    binding = env.target.vault.session_binding("alice")
    env.target.browser.identity_error = ConnectorError(error_code, "受控不可核验响应")
    await env.root.prepare_area("alice", "drp")
    with pytest.raises(ConnectorError):
        await env.root.prepare_area("alice", "drp", required=True)
    assert env.calls == [] and env.target.browser.discarded == []
    assert env.target.vault.session_binding("alice") == binding


async def test_confirmed_expired_drp_is_cas_removed_then_reconnected(auto_env):
    env = auto_env
    source(env)
    erp_binding = env.root.vault.session_binding("alice")
    env.target.vault.save_session("alice", {"expired": True}, ALICE_DRP)
    rejected = env.target.vault.session_binding("alice")
    await env.root.prepare_area("alice", "drp", required=True)
    assert env.target.browser.discarded == [("alice", rejected)]
    assert env.target.vault.session_binding("alice") != rejected and env.calls == ["alice"]
    assert env.root.vault.session_binding("alice") == erp_binding


async def test_failed_exchange_has_cooldown_and_binding_change_reevaluates_immediately(auto_env):
    env = auto_env
    source(env)
    env.fail = ConnectorError("erp_sso_unavailable", "受控换票失败")
    await env.root.prepare_area("alice", "drp")
    for _ in range(4):
        await env.root.prepare_area("alice", "drp")
    state = env.root.auto_connection("alice", "drp")
    assert state["status"] == "cooldown" and state["retry_after_seconds"] > 0 and state["can_password_login"]
    assert env.calls == ["alice"] and env.root.vault.load_session("alice")
    env.root.vault.clear_session("alice")
    source(env)
    env.fail = None
    await env.root.prepare_area("alice", "drp", required=True)
    assert env.calls == ["alice", "alice"]


@pytest.mark.parametrize("source_change", ["logout", "switch"])
async def test_prior_auto_drp_is_revoked_when_erp_source_binding_changes(auto_env, source_change):
    env = auto_env
    source(env)
    await env.root.prepare_area("alice", "drp", required=True)
    previous = env.target.vault.session_binding("alice")
    env.root.vault.clear_session("alice")
    if source_change == "switch":
        source(env, identity={"company_id": "200", "user_id": "301"})
    await env.root.prepare_area("alice", "drp")
    assert ("alice", previous) in env.target.browser.discarded
    if source_change == "logout":
        assert env.target.vault.load_session("alice") is None and env.calls == ["alice"]
    else:
        assert env.target.vault.load_session("alice")["identity"] == {"company_id": "1000", "user_id": "1001"}
        assert env.calls == ["alice", "alice"]


async def test_auto_ownership_survives_restart_without_reinterpreting_manual_sessions(auto_env):
    env = auto_env
    source(env)
    await env.root.prepare_area("alice", "drp", required=True)
    old = env.target.vault.session_binding("alice")
    env.root.vault.clear_session("alice")
    vault = Vault(env.root.root)
    restarted = ConnectorService(env.root.root, vault=vault, browser=Browser(vault), erp=Adapter("erp"))
    target = restarted.area_service("drp")
    target.browser = AutoBrowser(target.vault)
    await restarted.prepare_area("alice", "drp")
    assert target.browser.discarded == [("alice", old)] and target.vault.load_session("alice") is None


async def test_newer_manual_login_replacing_auto_is_not_revoked_on_source_change(auto_env):
    env = auto_env
    source(env)
    await env.root.prepare_area("alice", "drp", required=True)
    env.target.vault.clear_session("alice")
    env.target.vault.save_session("alice", {"cookies": [{"value": "NEW-MANUAL"}]}, {"company_id": "444", "user_id": "555"})
    manual = env.target.vault.session_binding("alice")
    env.root.vault.clear_session("alice")
    await env.root.prepare_area("alice", "drp", required=True)
    assert env.target.vault.session_binding("alice") == manual
    assert env.target.browser.discarded == [] and env.calls == ["alice"]


async def test_password_flow_is_not_overwritten_even_when_old_auto_source_changes(auto_env):
    env = auto_env
    source(env)
    await env.root.prepare_area("alice", "drp", required=True)
    saved = env.target.vault.session_binding("alice")
    env.root.vault.clear_session("alice")
    env.target.browser._password_flows.busy.add("alice")
    await env.root.prepare_area("alice", "drp")
    state = env.root.auto_connection("alice", "drp")
    assert state["status"] == "login_pending" and not state["can_password_login"]
    assert env.target.vault.session_binding("alice") == saved and env.target.browser.discarded == []


async def test_metadata_storage_failure_revokes_only_this_issued_target(auto_env, monkeypatch):
    env = auto_env
    source(env)
    source_binding = env.root.vault.session_binding("alice")
    monkeypatch.setattr(env.root, "_store_auto_receipt", lambda *args: (_ for _ in ()).throw(OSError("fixture: metadata cannot persist")))
    with pytest.raises(ConnectorError):
        await env.root.prepare_area("alice", "drp", required=True)
    assert env.target.vault.load_session("alice") is None
    assert env.root.vault.session_binding("alice") == source_binding
    assert len(env.target.browser.discarded) == 1


@pytest.mark.parametrize(("action", "method", "body"), [
    ("query", "query", {"capability_id": "fixture"}), ("discovery-start", "start_discovery", {}),
    ("write-preview", "preview_write_interface", {"interface_id": "fixture"}),
    ("execute", "execute", {"preview_id": "fixture", "digest": "fixture"}),
    ("operation-recheck", "reconcile_operation", {"preview_id": "fixture"}),
])
async def test_business_dispatch_prepares_before_actual_area_action(auto_env, monkeypatch, action, method, body):
    env = auto_env
    source(env)
    handler = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(env.target, method, handler)
    await dispatch_action(env.root, "alice", action, {"area": "drp", **body})
    assert env.calls == ["alice"] and handler.await_args.args[0] == "alice"


async def test_failed_prepare_does_not_send_business_request_or_hide_diagnostics(auto_env, monkeypatch):
    env = auto_env
    source(env)
    env.fail = ConnectorError("erp_sso_unavailable", "受控换票拒绝")
    handler = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(env.target, "query", handler)
    with pytest.raises(ConnectorError):
        await dispatch_action(env.root, "alice", "query", {"area": "drp", "capability_id": "fixture"})
    handler.assert_not_awaited()
    assert env.calls == ["alice"]
    events = await dispatch_action(env.root, "alice", "network", {"area": "drp"})
    assert events["events"]["events"][0]["classification"] == "blocked" and env.calls == ["alice"]


async def test_legacy_standalone_prepare_never_uses_another_erp_root(auto_env):
    env = auto_env
    assert await env.target.prepare_area("alice", "drp", required=True) is env.target
    assert env.calls == [] and env.target._area_children == {}


def test_local_api_and_authorization_page_drp_status_trigger_same_actor_auto(auto_env):
    env = auto_env
    source(env)
    token = env.root.vault.ensure_client("alice")
    with TestClient(create_app(env.root), base_url="http://testserver") as client:
        headers = {"authorization": "Bearer " + token}
        response = client.post("/api/status", json={"area": "drp"}, headers=headers)
        assert response.status_code == 200 and response.json()["connection"]["status"] == "connected"
        assert response.json()["auto_connection"]["status"] == "connected"
        manager = {"authorization": "Bearer " + env.root.vault.manager_token()}
        options = client.post("/manage/login-options", json={"profile": "alice", "area": "drp"}, headers=manager)
        assert options.status_code == 200 and options.json()["auto_connection"]["status"] == "connected"
    assert env.calls == ["alice"]


def test_remote_api_and_portal_drp_options_use_root_employee_actor(auto_env):
    env = auto_env
    employees = EmployeeStore(env.root.root, env.root.vault)
    account = employees.create_employee("remote-alice", "fixture-long-password")
    profile = employees.bearer(account["access_token"])["profile"]
    source(env, profile)
    app = create_remote_app(env.root, ORIGIN, employees=employees)
    with TestClient(app, base_url=ORIGIN) as client:
        login = client.post("/portal/login", json={"username": account["username"], "password": "fixture-long-password",
                                                   "connection_id": account["connection_id"]}, headers={"origin": ORIGIN})
        csrf = login.json()["csrf"]
        options = client.post("/portal/connection/login-options", json={"area": "drp"},
                              headers={"origin": ORIGIN, "x-csrf-token": csrf})
        assert options.status_code == 200 and options.json()["auto_connection"]["status"] == "connected"
        status = client.post("/api/status", json={"area": "drp"}, headers={"authorization": "Bearer " + account["access_token"]})
        assert status.status_code == 200 and status.json()["connection"]["status"] == "connected"
        assert status.json()["client"] == profile
    assert env.calls == [profile]
