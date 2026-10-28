"""临时目录下独立验证加密、会话隔离及执行账本，不使用任何真实账号资料。"""

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet

import jst_connector.ledger as ledger_module
import jst_connector.vault as vault_module
from jst_connector.errors import ConnectorError
from jst_connector.ledger import Ledger
from jst_connector.vault import Vault


@pytest.fixture
def storage(tmp_path):
    key = Fernet.generate_key()
    vault = Vault(tmp_path / "vault", key=key)
    identity = {"company_id": "隔离测试公司甲", "user_id": "测试员工甲"}
    vault.save_session("codex", {"cookies": [{"value": "isolated-cookie"}]}, identity,
                       credentials={"password": "isolated-password"})
    return vault, Ledger(tmp_path / "ledger", vault), identity, key


def make_preview(storage, *, atomicity="verified", ttl=300):
    _, ledger, identity, _ = storage
    return ledger.create_preview("codex", identity, {"document_id": "offline-test-1"},
                                 {"all_targets_checked": True}, atomicity=atomicity, ttl=ttl)


def assert_code(code, callback):
    with pytest.raises(ConnectorError) as error:
        callback()
    assert error.value.code == code


def test_first_login_requires_absent_session_atomically(tmp_path):
    key = Fernet.generate_key()
    first, second = Vault(tmp_path, key=key), Vault(tmp_path, key=key)
    identity = {"company_id": "fixture-company", "user_id": "fixture-user"}
    second.save_session("codex", {"cookies": ["newer-session"]}, identity, expected_binding=None)
    binding = second.session_binding("codex")
    assert_code("session_changed", lambda: first.save_session(
        "codex", {"cookies": ["stale-first-login"]}, identity, expected_binding=None))
    assert first.load_session("codex")["state"]["cookies"] == ["newer-session"]
    first.save_session("codex", {"cookies": ["bound-update"]}, identity, expected_binding=binding)
    assert second.load_session("codex")["state"]["cookies"] == ["bound-update"]
    first.clear_session("codex")
    assert_code("session_changed", lambda: second.save_session(
        "codex", {"cookies": ["stale-restoration"]}, identity, expected_binding=binding))


@pytest.mark.skipif(os.name != "nt", reason="仅 Windows 可实测当前用户 DPAPI")
def test_windows_dpapi_real_temporary_key_roundtrip_and_tamper(tmp_path, monkeypatch):
    monkeypatch.delenv("JST_CONNECTOR_MASTER_KEY", raising=False)
    root = tmp_path / "dpapi-only-temporary"
    vault = Vault(root)
    token = vault.seal({"temporary": "仅测试"})
    protected_key = (root / "masterkey.dpapi").read_bytes()
    assert protected_key
    assert len(protected_key) > len(Fernet.generate_key())
    assert Vault(root).unseal(token) == {"temporary": "仅测试"}
    modified = bytearray(protected_key)
    modified[-1] ^= 1
    (root / "masterkey.dpapi").write_bytes(modified)
    assert_code("key_protection_failed", lambda: Vault(root))


def test_non_windows_requires_external_key_and_does_not_generate_local_key(tmp_path, monkeypatch):
    # Probe only key resolution; replacing this module's OS reference avoids changing pathlib's OS.
    instance = object.__new__(Vault)
    instance.root = tmp_path
    instance._path = tmp_path / "vault.enc"
    monkeypatch.setattr(vault_module, "os", SimpleNamespace(name="posix", environ={}))
    assert_code("master_key_required", instance._load_key)
    key = Fernet.generate_key()
    vault_module.os.environ["JST_CONNECTOR_MASTER_KEY"] = key.decode("ascii")
    assert instance._load_key() == key
    assert not (tmp_path / "masterkey.dpapi").exists()


def test_vault_encryption_wrong_key_ciphertext_tamper_and_restart(storage):
    vault, _, identity, key = storage
    raw = (vault.root / "vault.enc").read_bytes()
    assert b"isolated-cookie" not in raw
    assert b"isolated-password" not in raw
    assert identity["company_id"].encode() not in raw
    restored = Vault(vault.root, key=key)
    assert restored.load_session("codex")["identity"] == identity
    assert_code("encrypted_data_invalid", lambda: Vault(vault.root, key=Fernet.generate_key()))
    token = vault.seal({"value": "test"})
    assert_code("encrypted_data_invalid", lambda: vault.unseal(token[:-2] + "AA"))
    (vault.root / "vault.enc").write_bytes(raw[:-8] + b"tampered")
    assert_code("encrypted_data_invalid", lambda: Vault(vault.root, key=key))


def test_clients_profiles_credentials_logout_and_session_binding(storage):
    vault, _, identity, key = storage
    codex_token = vault.ensure_client("codex")
    other_token = vault.ensure_client("workbuddy")
    manager = vault.manager_token()
    assert len({codex_token, other_token, manager}) == 3
    assert vault.client_for_token(codex_token) == "codex"
    assert vault.client_for_token(other_token) == "workbuddy"
    assert vault.client_for_token(manager) is None
    assert vault.client_for_token("伪造凭据") is None
    assert vault.load_session("workbuddy") is None
    binding = vault.session_binding("codex")
    vault.save_session("codex", {"refreshed": True}, identity)
    assert vault.session_binding("codex") == binding
    other_identity = {"company_id": "隔离测试公司乙", "user_id": "测试员工乙"}
    assert_code("account_switch_requires_logout", lambda: vault.save_session("codex", {}, other_identity))
    vault.save_session("workbuddy", {}, other_identity)
    vault.clear_session("codex")
    assert vault.load_session("codex") is None
    assert vault.session_binding("codex") is None
    assert vault.load_session("workbuddy")["identity"] == other_identity
    vault.save_session("codex", {}, identity)
    assert vault.session_binding("codex") != binding
    restored = Vault(vault.root, key=key)
    assert restored.ensure_client("codex") == codex_token
    assert restored.manager_token() == manager
    assert restored.load_session("codex")["credentials"] is None


@pytest.mark.parametrize("identity", [{}, {"company_id": True, "user_id": "u"},
                                      {"company_id": "c", "user_id": ""}])
def test_invalid_identity_rejected(tmp_path, identity):
    vault = Vault(tmp_path, key=Fernet.generate_key())
    assert_code("invalid_identity", lambda: vault.save_session("codex", {}, identity))


def test_ledger_default_atomicity_is_blocked_and_requires_approval(storage):
    _, ledger, identity, _ = storage
    preview = make_preview(storage, atomicity="unverified")
    assert_code("atomicity_unverified", lambda: ledger.approve(
        "codex", preview["preview_id"], preview["digest"], actor="authenticated-test-event"))
    assert_code("atomicity_unverified", lambda: ledger.claim(
        "codex", preview["preview_id"], preview["digest"], identity))
    ready = make_preview(storage)
    assert_code("preview_not_approved", lambda: ledger.claim(
        "codex", ready["preview_id"], ready["digest"], identity))


def test_ledger_expiry_digest_profile_and_identity_rejected(storage, monkeypatch):
    _, ledger, identity, _ = storage
    preview = make_preview(storage, ttl=5)
    preview_id, digest = preview["preview_id"], preview["digest"]
    assert_code("digest_mismatch", lambda: ledger.approve("codex", preview_id, "wrong", actor="test"))
    assert_code("preview_not_found", lambda: ledger.get_preview("workbuddy", preview_id))
    assert_code("identity_changed", lambda: ledger.claim(
        "codex", preview_id, digest, {**identity, "company_id": "另一个测试公司"}))
    monkeypatch.setattr(ledger_module.time, "time", lambda: preview["expires_at"])
    assert_code("preview_expired", lambda: ledger.approve("codex", preview_id, digest, actor="test"))


def test_logout_and_relogin_same_identity_invalidates_old_approval(storage):
    vault, ledger, identity, _ = storage
    preview = make_preview(storage)
    ledger.approve("codex", preview["preview_id"], preview["digest"], actor="test")
    vault.clear_session("codex")
    vault.save_session("codex", {}, identity)
    assert_code("identity_changed", lambda: ledger.claim(
        "codex", preview["preview_id"], preview["digest"], identity))


def test_atomic_claim_once_and_restart_result_unknown_never_reexecutes(storage):
    vault, ledger, identity, key = storage
    preview = make_preview(storage)
    preview_id, digest = preview["preview_id"], preview["digest"]
    ledger.approve("codex", preview_id, digest, actor="test-authenticated-confirmation")

    def claim(_):
        try:
            return ledger.claim("codex", preview_id, digest, identity)["status"]
        except ConnectorError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=8) as workers:
        attempts = list(workers.map(claim, range(16)))
    assert attempts.count("executing") == 1
    assert attempts.count("preview_not_approved") == 15
    restored = Ledger(ledger.root, Vault(vault.root, key=key))
    assert restored.get_preview("codex", preview_id)["status"] == "executing"
    assert_code("preview_not_approved", lambda: restored.claim("codex", preview_id, digest, identity))
    restored.finish("codex", preview_id, "unknown", {"needs_reconciliation": True})
    again = Ledger(ledger.root, Vault(vault.root, key=key))
    assert again.get_preview("codex", preview_id)["result"] == {"needs_reconciliation": True}
    assert_code("preview_not_approved", lambda: again.claim("codex", preview_id, digest, identity))
    assert_code("execution_not_claimed", lambda: again.finish("codex", preview_id, "succeeded", {}))


@pytest.mark.parametrize("status", ["succeeded", "failed"])
def test_finished_preview_never_reexecutes_or_overwrites(storage, status):
    _, ledger, identity, _ = storage
    preview = make_preview(storage)
    pid, digest = preview["preview_id"], preview["digest"]
    ledger.approve("codex", pid, digest, actor="test")
    ledger.claim("codex", pid, digest, identity)
    ledger.finish("codex", pid, status, {"test": True})
    assert_code("preview_not_approved", lambda: ledger.claim("codex", pid, digest, identity))
    assert_code("preview_not_ready", lambda: ledger.approve("codex", pid, digest, actor="test"))
    assert_code("execution_not_claimed", lambda: ledger.finish("codex", pid, status, {"test": True}))


def test_ledger_persisted_payload_encrypted_and_plain_status_tamper_detected(storage):
    _, ledger, _, _ = storage
    preview = make_preview(storage)
    assert b"offline-test-1" not in ledger.path.read_bytes()
    with sqlite3.connect(ledger.path) as database:
        database.execute("UPDATE previews SET status='approved' WHERE preview_id=?", (preview["preview_id"],))
    assert_code("preview_invalid", lambda: ledger.get_preview("codex", preview["preview_id"]))


def test_non_ascii_digest_returns_structured_error(storage):
    _, ledger, _, _ = storage
    preview = make_preview(storage)
    assert_code("digest_mismatch", lambda: ledger.approve(
        "codex", preview["preview_id"], "伪造摘要", actor="test"))


def test_vault_corrupt_non_ascii_ciphertext_returns_structured_error(storage):
    vault, _, _, key = storage
    (vault.root / "vault.enc").write_bytes(b"\xff\x00damaged")
    assert_code("encrypted_data_invalid", lambda: Vault(vault.root, key=key))


def test_switch_company_blocks_access_to_previous_company_preview(storage):
    vault, ledger, _, _ = storage
    preview = make_preview(storage)
    vault.clear_session("codex")
    vault.save_session("codex", {}, {"company_id": "隔离测试公司乙", "user_id": "测试员工乙"})
    with pytest.raises(ConnectorError):
        ledger.get_preview("codex", preview["preview_id"])
