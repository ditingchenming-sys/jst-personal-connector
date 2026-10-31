"""本地加密执行账本：可信确认后原子占用，执行结果未知时禁止重试。"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .errors import ConnectorError
from .vault import Vault, _identity, _json, _profile


class Ledger:
    def __init__(self, root: Path, vault: Vault):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.root / "ledger.sqlite3"
        self.vault = vault
        with self._connection() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS previews (
                preview_id TEXT PRIMARY KEY, profile TEXT NOT NULL,
                status TEXT NOT NULL, encrypted TEXT NOT NULL)""")
            connection.execute("""CREATE TABLE IF NOT EXISTS operation_keys (
                operation_key TEXT PRIMARY KEY, profile TEXT NOT NULL, preview_id TEXT NOT NULL)""")
        self.path.chmod(0o600)

    @contextmanager
    def _connection(self, *, write=False):
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            if write:
                connection.execute("BEGIN IMMEDIATE")
            yield connection
            if write:
                connection.commit()
        except BaseException:
            if write:
                connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _digest(record: dict) -> str:
        fields = ("preview_id", "profile", "identity", "payload", "checks", "atomicity",
                  "created_at", "expires_at", "session_binding")
        values = {field: record[field] for field in fields}
        if "execution_boundary" in record:
            values["execution_boundary"] = record["execution_boundary"]
        return hashlib.sha256(_json(values)).hexdigest()

    def _read(self, connection, profile: str, preview_id: str) -> dict:
        row = connection.execute("SELECT * FROM previews WHERE preview_id=? AND profile=?",
                                 (preview_id, _profile(profile))).fetchone()
        if row is None:
            raise ConnectorError("preview_not_found", "找不到当前调用端的预览。")
        record = self.vault.unseal(row["encrypted"])
        try:
            valid = (record["preview_id"] == preview_id and record["profile"] == profile
                     and record["status"] == row["status"]
                     and secrets.compare_digest(record["digest"], self._digest(record)))
        except (KeyError, TypeError):
            valid = False
        if not valid:
            raise ConnectorError("preview_invalid", "预览资料完整性验证失败。")
        return record

    @staticmethod
    def _public(record: dict) -> dict:
        return {key: value for key, value in record.items() if key != "session_binding"}

    def _session(self, profile: str, identity: dict | None = None) -> tuple[dict, str]:
        session = self.vault.load_session(profile)
        if session is None:
            raise ConnectorError("login_required", "请本人先登录聚水潭账号。")
        current = _identity(session["identity"])
        if identity is not None and current != _identity(identity):
            raise ConnectorError("identity_changed", "当前公司或员工身份与预览不一致，请重新预览。")
        return current, self.vault.session_binding(profile)

    def _validate(self, record: dict, digest: str, identity: dict | None = None) -> None:
        if not isinstance(digest, str) or not secrets.compare_digest(record["digest"].encode(), digest.encode()):
            raise ConnectorError("digest_mismatch", "确认摘要与当前预览不一致。")
        if time.time() >= record["expires_at"]:
            raise ConnectorError("preview_expired", "预览已过期，请重新预览并确认。")
        current, binding = self._session(record["profile"], identity or record["identity"])
        if current != record["identity"] or binding != record["session_binding"]:
            raise ConnectorError("identity_changed", "登录状态已变更，请重新预览并确认。")
        if record["atomicity"] != "verified" and record.get("execution_boundary") != "single_object_request":
            raise ConnectorError("atomicity_unverified", "尚未核实整批原子提交保证，不能执行。")

    def _write(self, connection, record: dict) -> None:
        connection.execute("UPDATE previews SET status=?, encrypted=? WHERE preview_id=? AND profile=?",
                           (record["status"], self.vault.seal(record), record["preview_id"], record["profile"]))

    def create_preview(self, profile, identity, payload, checks, atomicity="unverified", ttl=300,
                       *, execution_boundary=None, operation_key=None, verified_reissue=False) -> dict:
        profile = _profile(profile)
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not 0 < ttl <= 86400:
            raise ConnectorError("invalid_ttl", "预览有效期必须大于零且不超过一天。")
        if atomicity not in ("unverified", "verified"):
            raise ConnectorError("invalid_atomicity", "原子性验证状态无效。")
        if execution_boundary not in (None, "single_object_request"):
            raise ConnectorError("invalid_boundary", "执行边界无效。")
        if operation_key is not None and (not isinstance(operation_key, str) or len(operation_key) != 64
                                           or any(char not in "0123456789abcdef" for char in operation_key)):
            raise ConnectorError("invalid_operation_key", "业务防重复标识无效。")
        with self.vault._lock:
            current, binding = self._session(profile, identity)
            created = time.time()
            record = {"preview_id": secrets.token_urlsafe(24), "profile": profile, "identity": current,
                      "payload": payload, "checks": checks, "atomicity": atomicity,
                      "created_at": created, "expires_at": created + ttl,
                      "session_binding": binding, "status": "ready", "approval": None, "result": None}
            if execution_boundary is not None:
                record["execution_boundary"] = execution_boundary
            record["digest"] = self._digest(record)
            encrypted = self.vault.seal(record)
            with self._connection(write=True) as connection:
                if operation_key is not None:
                    prior = connection.execute("SELECT profile, preview_id FROM operation_keys WHERE operation_key=?",
                                               (operation_key,)).fetchone()
                    if prior is not None:
                        previous = self._read(connection, prior["profile"], prior["preview_id"])
                        if previous["identity"]["company_id"] != current["company_id"]:
                            raise ConnectorError("identity_changed", "原任务不属于当前公司或员工。")
                        if (verified_reissue and previous["status"] in {"ready", "approved"}
                                and isinstance(previous["payload"].get("before_digest"), str)
                                and isinstance(payload.get("before_digest"), str)
                                and previous["payload"]["before_digest"] != payload["before_digest"]):
                            # The fresh ERP precheck invalidates an older preview
                            # and its approval; no in-flight/unknown task is freed.
                            previous.update(status="superseded", superseded_at=created)
                            self._write(connection, previous)
                        terminal_block = {"executing", "unknown"} | (set() if verified_reissue else {"succeeded"})
                        active = (previous["status"] in terminal_block
                                  or previous["expires_at"] > created and previous["status"] in {"ready", "approved"})
                        if prior["profile"] != profile and active:
                            code, message = ("operation_result_unknown", "同公司此操作已有结果未知的提交，须先核对，不能重复执行。") if previous["status"] == "unknown" else (
                                ("operation_already_submitted", "同公司此操作已经提交，请核对业务系统结果，不能重复执行。") if previous["status"] == "succeeded" else
                                ("operation_in_progress", "同公司此操作已由其他调用端处理，请等待或核对原任务。"))
                            raise ConnectorError(code, message)
                        if prior["profile"] == profile and (previous["status"] in terminal_block
                                or previous["status"] in {"ready", "approved"} and previous["session_binding"] == binding
                                and previous["expires_at"] > created):
                            return self._public(previous)
                connection.execute("INSERT INTO previews VALUES (?, ?, ?, ?)",
                                   (record["preview_id"], profile, "ready", encrypted))
                if operation_key is not None:
                    connection.execute("INSERT INTO operation_keys VALUES (?,?,?) ON CONFLICT(operation_key) DO UPDATE SET profile=excluded.profile, preview_id=excluded.preview_id",
                                       (operation_key, profile, record["preview_id"]))
            return self._public(self.vault.unseal(encrypted))

    def get_preview(self, profile, preview_id) -> dict:
        with self.vault._lock, self._connection() as connection:
            record = self._read(connection, profile, preview_id)
            # 同一调用端换公司后，旧公司的业务内容也不能继续回读。
            # 同一身份重新登录仍可查看历史结果以核对未知任务，但不能复用旧执行授权。
            self._session(profile, record["identity"])
            return self._public(record)

    def approve(self, profile, preview_id, digest, actor) -> dict:
        """仅由经过认证的管理界面或验签系统调用；绝不注册为 AI 工具。"""
        if not isinstance(actor, (str, dict)) or not actor:
            raise ConnectorError("approval_actor_required", "可信确认必须记录实际确认人。")
        with self.vault._lock, self._connection(write=True) as connection:
            record = self._read(connection, profile, preview_id)
            self._validate(record, digest)
            if record["status"] != "ready":
                raise ConnectorError("preview_not_ready", "预览已被确认、占用或执行，不能重复确认。")
            record["status"] = "approved"
            record["approval"] = {"actor": actor, "digest": digest, "approved_at": time.time()}
            self._write(connection, record)
            return self._public(record)

    def claim(self, profile, preview_id, digest, identity) -> dict:
        with self.vault._lock, self._connection(write=True) as connection:
            record = self._read(connection, profile, preview_id)
            self._validate(record, digest, identity)
            if record["status"] != "approved" or not record["approval"]:
                raise ConnectorError("preview_not_approved", "预览尚未可信确认，或已经占用及执行。")
            if record["approval"].get("digest") != digest:
                raise ConnectorError("digest_mismatch", "可信确认不对应当前预览。")
            record["status"] = "executing"
            record["claimed_at"] = time.time()
            self._write(connection, record)
            return self._public(record)

    def finish(self, profile, preview_id, status, result) -> dict:
        if status not in ("succeeded", "failed", "unknown"):
            raise ConnectorError("invalid_execution_status", "执行只能结束为成功、失败或结果未知。")
        with self._connection(write=True) as connection:
            record = self._read(connection, profile, preview_id)
            if record["status"] != "executing":
                raise ConnectorError("execution_not_claimed", "预览未处于执行状态，不能覆盖执行结果。")
            record.update(status=status, result=result, finished_at=time.time())
            self._write(connection, record)
            return self._public(record)

    def reconcile_unknown(self, profile, preview_id, digest, result) -> dict:
        """Apply server-produced readback evidence without reopening submission."""
        with self.vault._lock, self._connection(write=True) as connection:
            record = self._read(connection, profile, preview_id)
            self._session(profile, record["identity"])
            if not isinstance(digest, str) or not secrets.compare_digest(record["digest"], digest):
                raise ConnectorError("digest_mismatch", "回查对象与原预览不一致。")
            if record["status"] != "unknown":
                return self._public(record)
            if not isinstance(result, dict) or result.get("source") != "current_erp_read" or type(result.get("verified")) is not bool:
                raise ConnectorError("recheck_unverified", "未取得服务端实际只读回查依据，不能更新原操作状态。")
            record["last_recheck"] = {"checked_at": time.time(), "result": result}
            if result["verified"]:
                record.update(status="succeeded", result=result, reconciled_at=time.time())
            self._write(connection, record)
            return self._public(record)
