"""可信后端签名到浏览器授权的隔离验证；没有钉钉、ERP或生产写入。"""
import copy
import hashlib
import hmac
import json
import math
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from jst_connector.errors import ConnectorError
from jst_connector.platform_auth import CHALLENGE_COOKIE, PlatformRegistry
from jst_connector.remote import COOKIE, EmployeeStore, create_remote_app
from jst_connector.service import ConnectorService
from jst_connector.vault import Vault, _json

ORIGIN = "https://connector.example.com"
ISSUER = "trusted-platform"
LOGIN_URL = "https://platform.example.com/auth/connector?app=example"
SECRET = b"fixture-platform-signing-secret-32-bytes-only"
PASSWORD = "legacy-local-password-fixture"


def proof(action="provision", *, secret=SECRET, **changes):
    now = int(time.time())
    claims = {"version": 1, "issuer": ISSUER, "audience": ORIGIN, "action": action,
              "tenant": "tenant-a", "subject": "subject-alice", "client": "workbench",
              "request_id": secrets.token_urlsafe(24), "issued_at": now, "expires_at": now + 90, **changes}
    return {"claims": claims, "signature": hmac.new(secret, _json(claims), hashlib.sha256).hexdigest()}


@pytest.fixture
def env(tmp_path):
    vault = Vault(tmp_path, key=Fernet.generate_key())
    browser = SimpleNamespace(status=AsyncMock(return_value={"status": "disconnected"}), close=AsyncMock(), close_idle=AsyncMock())
    service = ConnectorService(tmp_path, vault=vault, browser=browser)
    employees = EmployeeStore(tmp_path, vault)
    registry = PlatformRegistry(tmp_path, vault, employees=employees)
    registry.register(ISSUER, LOGIN_URL, SECRET, ["tenant-a", "tenant-b"])
    return SimpleNamespace(root=tmp_path, vault=vault, service=service, employees=employees, registry=registry,
                           app=create_remote_app(service, ORIGIN, employees=employees))


def integrate(client, action="provision", **changes):
    return client.post("/integration/platform", json=proof(action, **changes))


def provision(env, **changes):
    return env.registry.integration(proof(**changes), ORIGIN)


def start(client, account, **changes):
    result = client.post("/portal/platform-start", json={"connection_id": account["connection_id"], **changes}, headers={"origin": ORIGIN})
    assert result.status_code == 200, result.text
    challenge = parse_qs(urlsplit(result.json()["login_url"]).query)["challenge"][0]
    return challenge, result


def authorize(client, challenge, **changes):
    result = integrate(client, "authorize", challenge=challenge, **changes)
    assert result.status_code == 200, result.text
    return parse_qs(urlsplit(result.json()["redirect_url"]).fragment)["platform_code"][0], result


def redeem(client, code):
    return client.post("/portal/platform-login", json={"code": code}, headers={"origin": ORIGIN})


def test_passwordless_platform_roundtrip_browser_binding_and_separate_business_auth(env):
    with TestClient(env.app, base_url=ORIGIN) as client:
        issued = integrate(client).json()
        assert issued["ok"] and issued["auth_method"] == "platform"
        account = env.employees.bearer(issued["access_token"])
        with env.employees._connection() as conn:
            saved = env.employees._employee(conn, issued["username"])
        assert "salt" not in saved and "password_hash" not in saved
        options = client.get("/portal/auth-options", params={"connection": issued["connection_id"]}).json()
        assert options == {"ok": True, "mode": "platform", "issuer": ISSUER, "login_label": "返回平台继续授权"}
        next_path = "/operations/" + "x" * 24 + "?connection=" + issued["connection_id"] + "&area=drp"
        challenge, opening = start(client, issued, next=next_path, area="drp")
        assert "HttpOnly" in opening.headers["set-cookie"] and "SameSite=lax" in opening.headers["set-cookie"]
        assert CHALLENGE_COOKIE in client.cookies
        assert parse_qs(urlsplit(opening.json()["login_url"]).query)["audience"] == [ORIGIN]
        code, authorized = authorize(client, challenge)
        assert authorized.json()["redirect_url"].startswith(ORIGIN + "/login#platform_code=")
        assert issued["access_token"] not in authorized.text
        assert client.get("/portal/session").status_code == 401
        result = redeem(client, code)
        assert result.status_code == 200, result.text
        body = result.json()
        assert body["auth_method"] == body["auth_mode"] == "platform"
        assert body["display_name"] == "平台授权用户" and body["next"] == next_path and body["area"] == "drp"
        assert body["connection_id"] == issued["connection_id"] and "csrf" in body
        assert "SameSite=strict" in result.headers.get_list("set-cookie")[0]
        assert client.get("/portal/session").json()["auth_method"] == "platform"
        assert env.vault.load_session(account["profile"]) is None
        assert client.post("/portal/approve", json={"preview_id": "fake", "digest": "fake"},
                           headers={"origin": ORIGIN}).status_code == 409
        assert redeem(client, code).status_code == 401
        assert client.get("/portal/session").status_code == 401


def test_external_identity_never_merges_local_username_or_other_namespaces(env):
    local = env.employees.create_employee("alice", PASSWORD)
    first = provision(env, subject="alice")
    same_text_other_tenant = provision(env, subject="alice", tenant="tenant-b")
    env.registry.register("another-platform", LOGIN_URL, b"another-platform-signing-key-different-32bytes", ["tenant-a"])
    other_issuer = env.registry.integration(proof(issuer="another-platform", subject="alice", secret=b"another-platform-signing-key-different-32bytes"), ORIGIN)
    records = [env.employees.bearer(item["access_token"])["profile"] for item in (local, first, same_text_other_tenant, other_issuer)]
    assert len(set(records)) == 4
    assert first["username"] != "alice"


@pytest.mark.parametrize("password", ["", PASSWORD, "anything"])
def test_platform_employee_cannot_password_fallback(env, password):
    account = provision(env)
    with TestClient(env.app, base_url=ORIGIN) as client:
        response = client.post("/portal/login", json={"username": account["username"], "password": password,
                                                       "connection_id": account["connection_id"]}, headers={"origin": ORIGIN})
        assert response.status_code == 401
        assert client.get("/portal/session").status_code == 401


def test_browser_or_api_token_cannot_self_provision_or_authorize(env):
    account = provision(env)
    with TestClient(env.app, base_url=ORIGIN) as client:
        envelope = proof(subject="new-subject")
        assert client.post("/integration/platform", json=envelope, headers={"origin": ORIGIN}).status_code == 403
        assert client.post("/integration/platform", json=envelope, headers={"origin": "https://platform.example.com"}).status_code == 403
        forged = copy.deepcopy(envelope)
        forged["signature"] = "0" * 64
        assert client.post("/integration/platform", json=forged, headers={"authorization": "Bearer " + account["access_token"]}).status_code == 409
        assert client.post("/portal/platform-start", json={"connection_id": account["connection_id"]}).status_code == 403


def test_replay_is_atomic_across_concurrent_registry_instances(env):
    envelope = proof()

    def consume(_):
        registry = PlatformRegistry(env.root, env.vault, employees=env.employees)
        try:
            return registry.integration(copy.deepcopy(envelope), ORIGIN)
        except ConnectorError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=4) as executor:
        outcomes = list(executor.map(consume, range(4)))
    assert sum(isinstance(item, dict) for item in outcomes) == 1
    assert outcomes.count("platform_replay") == 3


@pytest.mark.parametrize("changes", [
    {"version": True}, {"audience": "https://connector.example.com.evil"}, {"tenant": "not-allowed"},
    {"issued_at": True}, {"expires_at": float("nan")}, {"issued_at": 1.5},
    lambda: {"issued_at": int(time.time()) + 30, "expires_at": int(time.time()) + 60},
    lambda: {"issued_at": int(time.time()) - 200, "expires_at": int(time.time()) - 100},
    lambda: {"expires_at": int(time.time()) + 3600}, {"request_id": "short"}, {"subject": "bad\nsubject"},
    {"client": "../other"}, {"action": ["provision"]}, {"confirmed": True}, {"profile": "alice"},
])
def test_proof_schema_audience_time_and_identity_are_strict(env, changes):
    if callable(changes):
        changes = changes()
    envelope = proof(**changes) if not any(isinstance(value, float) and not math.isfinite(value) for value in changes.values()) else {
        "claims": {**proof()["claims"], **changes}, "signature": "0" * 64}
    with pytest.raises(ConnectorError):
        env.registry.integration(envelope, ORIGIN)


def test_code_cannot_login_a_different_browser_or_subject(env):
    account = provision(env)
    provision(env, subject="subject-bob")
    with TestClient(env.app, base_url=ORIGIN) as alice, TestClient(env.app, base_url=ORIGIN) as another:
        challenge, _ = start(alice, account)
        wrong = integrate(alice, "authorize", challenge=challenge, subject="subject-bob")
        assert wrong.status_code == 409
        code, _ = authorize(alice, challenge)
        assert redeem(another, code).status_code == 401
        assert redeem(alice, code).status_code == 200


def test_provision_rotates_only_matching_connection_and_invalidates_pending_code(env):
    account = provision(env)
    other_client = provision(env, client="codex")
    profile = env.employees.bearer(account["access_token"])["profile"]
    with TestClient(env.app, base_url=ORIGIN) as browser:
        challenge, _ = start(browser, account)
        code, _ = authorize(browser, challenge)
        updated = provision(env)
        assert updated["connection_id"] == account["connection_id"]
        assert env.employees.bearer(updated["access_token"])["profile"] == profile
        with pytest.raises(ConnectorError):
            env.employees.bearer(account["access_token"])
        assert env.employees.bearer(other_client["access_token"])
        assert redeem(browser, code).status_code == 401


def test_provision_rotation_revokes_logged_browser_session(env):
    account = provision(env)
    with TestClient(env.app, base_url=ORIGIN) as browser:
        challenge, _ = start(browser, account)
        code, _ = authorize(browser, challenge)
        assert redeem(browser, code).status_code == 200
        provision(env)
        assert browser.get("/portal/session").status_code == 401


def test_registry_rotation_revokes_all_old_authorizations_but_preserves_profiles(env):
    account = provision(env)
    profile = env.employees.bearer(account["access_token"])["profile"]
    env.vault.save_session(profile, {"cookies": [{"value": "ERP-PRIVATE-STATE"}]}, {"company_id": "100", "user_id": "201"})
    old_proof = proof(subject="another")
    with TestClient(env.app, base_url=ORIGIN) as browser:
        challenge, _ = start(browser, account)
        code, _ = authorize(browser, challenge)
        new_secret = b"brand-new-platform-signature-key-never-reused"
        env.registry.register(ISSUER, LOGIN_URL, new_secret, ["tenant-a"])
        with pytest.raises(ConnectorError):
            env.registry.integration(old_proof, ORIGIN)
        with pytest.raises(ConnectorError):
            env.employees.bearer(account["access_token"])
        assert redeem(browser, code).status_code == 401
        replacement = env.registry.integration(proof(secret=new_secret), ORIGIN)
        assert env.employees.bearer(replacement["access_token"])["profile"] == profile
        assert env.vault.load_session(profile)["state"]["cookies"] == [{"value": "ERP-PRIVATE-STATE"}]
    for issuer in (ISSUER, "other-issuer"):
        with pytest.raises(ConnectorError, match="密钥不能重复启用"):
            env.registry.register(issuer, LOGIN_URL, SECRET, ["tenant-a"])
    assert SECRET not in env.registry.path.read_bytes()


@pytest.mark.parametrize("method", ["administrator", "issuer", "signed_subject"])
def test_disablement_revokes_tokens_and_sessions_and_does_not_auto_revive(env, method):
    account = provision(env)
    other = provision(env, subject="subject-bob")
    with TestClient(env.app, base_url=ORIGIN) as browser:
        challenge, _ = start(browser, account)
        code, _ = authorize(browser, challenge)
        assert redeem(browser, code).status_code == 200
        if method == "administrator":
            env.employees.disable(account["username"])
        elif method == "issuer":
            env.registry.disable(ISSUER)
        else:
            assert env.registry.integration(proof("disable"), ORIGIN)["ok"]
        with pytest.raises(ConnectorError):
            env.employees.bearer(account["access_token"])
        assert browser.get("/portal/session").status_code == 401
        with pytest.raises(ConnectorError):
            provision(env)
        if method != "issuer":
            assert env.employees.bearer(other["access_token"])


@pytest.mark.parametrize("next_path", ["//evil.example/", "https://evil.example/", "/api/status", "/operations/" + "x" * 24 + "#fragment",
                                      "/operations/" + "x" * 24 + "?connection=another", "/operations/" + "x" * 24 + "?area=drp&area=erp"])
def test_start_rejects_open_redirects_and_wrong_connection_next(env, next_path):
    account = provision(env)
    with TestClient(env.app, base_url=ORIGIN) as browser:
        response = browser.post("/portal/platform-start", json={"connection_id": account["connection_id"], "next": next_path}, headers={"origin": ORIGIN})
        assert response.status_code == 409


def test_failed_callback_revokes_and_clears_existing_legacy_employee_cookie(env):
    account = env.employees.create_employee("legacy-alice", PASSWORD)
    with TestClient(env.app, base_url=ORIGIN) as browser:
        assert browser.post("/portal/login", json={"username": account["username"], "password": PASSWORD,
                                                   "connection_id": account["connection_id"]}, headers={"origin": ORIGIN}).status_code == 200
        old_cookie = browser.cookies[COOKIE]
        result = redeem(browser, "invalid-code")
        assert result.status_code == 401 and "Max-Age=0" in result.headers.get_list("set-cookie")[0]
        assert COOKIE not in browser.cookies
        with pytest.raises(ConnectorError):
            env.employees.session(old_cookie)
        assert browser.get("/portal/session").status_code == 401


def test_auth_options_keeps_legacy_and_never_falls_back_for_invalid_connection(env):
    local = env.employees.create_employee("local-alice", PASSWORD)
    with TestClient(env.app, base_url=ORIGIN) as browser:
        assert browser.get("/portal/auth-options").json()["mode"] == "password"
        assert browser.get("/portal/auth-options", params={"connection": local["connection_id"]}).json()["mode"] == "password"
        assert browser.get("/portal/auth-options", params={"connection": "not-a-valid-connection"}).status_code == 409
        assert browser.get("/portal/auth-options", params={"connection": ""}).status_code == 409


def test_browser_callback_consumption_is_atomic(env):
    account = provision(env)
    payload, cookie = env.registry.start(account["connection_id"], ORIGIN, peer="fixture")
    challenge = parse_qs(urlsplit(payload["login_url"]).query)["challenge"][0]
    authorized = env.registry.integration(proof("authorize", challenge=challenge), ORIGIN)
    code = parse_qs(urlsplit(authorized["redirect_url"]).fragment)["platform_code"][0]

    def consume(_):
        try:
            return env.registry.login(code, cookie, ORIGIN)
        except ConnectorError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=3) as executor:
        outcomes = list(executor.map(consume, range(3)))
    assert sum(isinstance(item, tuple) for item in outcomes) == 1
    assert outcomes.count("platform_code_invalid") == 2


@pytest.mark.parametrize("envelope", [None, [], {}, {"claims": None, "signature": "0" * 64},
                                      {"claims": {"action": []}, "signature": "0" * 64},
                                      {"claims": {"action": {}}, "signature": "0" * 64},
                                      {"claims": {"action": "provision", "issued_at": float("nan")}, "signature": "0" * 64}])
def test_malformed_envelopes_return_chinese_contract_error_not_internal_failure(env, envelope):
    with TestClient(env.app, base_url=ORIGIN) as client:
        response = client.post("/integration/platform", content=json.dumps(envelope), headers={"content-type": "application/json"})
        assert response.status_code == 409
        assert "error" in response.json() and response.json()["error"]["code"] != "internal_error"


@pytest.mark.parametrize("login_url", ["https://platform.example.com/login?challenge=", "https://platform.example.com/login?audience=",
                                       "https://platform.example.com/login?challenge=x&challenge="])
def test_registration_cannot_preload_callback_query_keys_even_empty(env, login_url):
    with pytest.raises(ConnectorError):
        env.registry.register("new-issuer", login_url, secrets.token_bytes(32), ["tenant-a"])
