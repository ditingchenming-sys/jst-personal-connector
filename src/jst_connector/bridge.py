"""签名任务及持久化领取协议；本地事务仅防重复，不代表 ERP 原子提交。"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path

from .errors import ConnectorError


def canonical(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ConnectorError("invalid_task", "任务必须是有效的 JSON 数据") from exc


@dataclass(frozen=True)
class Binding:
    """仅由已验证的应用认证及明确的连接器配对映射产生。profile 即指定调用端。"""

    company_id: str
    user_id: str
    profile: str

    def __post_init__(self):
        if any(not isinstance(v, str) or not v.strip() for v in asdict(self).values()):
            raise ConnectorError("invalid_binding", "缺少已验证的公司、员工或连接器绑定")


class TaskSigner:
    """密钥由可信后端/员工安全存储注入，不应暴露给 MCP 工具。"""

    def __init__(self, secret: bytes, *, clock: Callable[[], float] = time.time):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ConnectorError("invalid_key", "任务签名密钥至少需要 32 字节")
        self._secret = secret
        self.clock = clock

    def issue(self, binding: Binding, preview_id: str, digest: str, payload: dict, *,
              ttl: int = 300, task_id: str | None = None, confirmation_id: str) -> dict:
        if not 0 < ttl <= 3600:
            raise ConnectorError("invalid_expiry", "任务有效期须在 1 到 3600 秒之间")
        now = self.clock()
        task = {"version": 1, "task_id": task_id or secrets.token_urlsafe(24), **asdict(binding),
                "preview_id": preview_id, "digest": digest, "payload": payload,
                "confirmation_id": confirmation_id, "issued_at": now, "expires_at": now + ttl}
        self._validate(task)
        # Round-trip detaches mutable business parameters from the signed snapshot.
        task = json.loads(canonical(task))
        signature = hmac.new(self._secret, canonical(task).encode(), hashlib.sha256).hexdigest()
        return {"task": task, "signature": signature}

    @staticmethod
    def _validate(task: dict):
        fields = {"version", "task_id", "company_id", "user_id", "profile", "preview_id", "digest",
                  "payload", "confirmation_id", "issued_at", "expires_at"}
        if not isinstance(task, dict) or set(task) != fields or task["version"] != 1:
            raise ConnectorError("invalid_task", "任务协议或字段不正确")
        Binding(task["company_id"], task["user_id"], task["profile"])
        if (any(not isinstance(task[k], str) or not task[k] for k in
                ("task_id", "preview_id", "digest", "confirmation_id")) or not isinstance(task["payload"], dict)):
            raise ConnectorError("invalid_task", "任务缺少预览、确认或具体执行内容")
        if any(type(task[k]) not in (int, float) for k in ("issued_at", "expires_at")):
            raise ConnectorError("invalid_task", "任务时间格式不正确")
        if not 0 < task["expires_at"] - task["issued_at"] <= 3600:
            raise ConnectorError("invalid_expiry", "任务有效期不正确")
        canonical(task)

    def verify(self, envelope: dict, binding: Binding | None = None, *, allow_expired: bool = False) -> dict:
        if not isinstance(envelope, dict) or set(envelope) != {"task", "signature"}:
            raise ConnectorError("invalid_task", "签名任务格式不正确")
        task, signature = envelope["task"], envelope["signature"]
        self._validate(task)
        expected = hmac.new(self._secret, canonical(task).encode(), hashlib.sha256).hexdigest()
        if not isinstance(signature, str) or not hmac.compare_digest(expected.encode(), signature.encode()):
            raise ConnectorError("invalid_signature", "任务签名无效，内容可能已被修改")
        if binding and any(task[k] != v for k, v in asdict(binding).items()):
            raise ConnectorError("identity_mismatch", "任务与当前公司、员工或连接器不匹配")
        now = self.clock()
        if task["issued_at"] > now + 30:
            raise ConnectorError("invalid_expiry", "任务签发时间超出允许范围")
        if not allow_expired and task["expires_at"] <= now:
            raise ConnectorError("task_expired", "任务已过期，请重新核对并确认预览")
        return json.loads(canonical(task))


class TaskQueue:
    """每次操作独立 SQLite 连接，BEGIN IMMEDIATE 使并发领取只成功一次。

    claimed 永不因超时或重启重排队：可能已经调用 ERP，必须先回查。
    此库保存业务任务，部署者应将路径置于仅服务账户可读写的私有目录。
    """

    def __init__(self, path: Path | str, signer: TaskSigner):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.signer = signer
        with self._transaction() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS bridge_tasks (
                task_id TEXT PRIMARY KEY, company_id TEXT NOT NULL, user_id TEXT NOT NULL,
                profile TEXT NOT NULL, envelope TEXT NOT NULL, state TEXT NOT NULL,
                claim_token TEXT, result TEXT, created_at REAL NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS bridge_preview_keys (
                company_id TEXT NOT NULL, user_id TEXT NOT NULL, profile TEXT NOT NULL,
                preview_id TEXT NOT NULL, task_id TEXT NOT NULL UNIQUE,
                PRIMARY KEY (company_id,user_id,profile,preview_id))""")
            # Upgrade earlier queues without discarding execution evidence. Existing duplicates
            # require reconciliation; choosing one automatically could hide an ERP execution.
            legacy = db.execute("SELECT task_id,envelope FROM bridge_tasks WHERE task_id NOT IN "
                                "(SELECT task_id FROM bridge_preview_keys)").fetchall()
            for row in legacy:
                task = self.signer.verify(json.loads(row["envelope"]), allow_expired=True)
                try:
                    self._register_preview(db, task)
                except sqlite3.IntegrityError as exc:
                    raise ConnectorError("queue_upgrade_requires_review", "旧任务存在重复预览，请先核对执行记录") from exc

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.path, timeout=20, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def enqueue(self, envelope: dict) -> dict:
        task = self.signer.verify(envelope)
        snapshot = canonical(envelope)
        with self._transaction() as db:
            row = db.execute("SELECT * FROM bridge_tasks WHERE task_id=?", (task["task_id"],)).fetchone()
            if row:
                if self._business_content(json.loads(row["envelope"])["task"]) != self._business_content(task):
                    raise ConnectorError("task_conflict", "同一任务编号不能更换内容、身份或预览")
                return {"task_id": task["task_id"], "status": row["state"], "duplicate": True}
            row = db.execute("SELECT tasks.* FROM bridge_preview_keys AS keys JOIN bridge_tasks AS tasks "
                             "ON tasks.task_id=keys.task_id WHERE keys.company_id=? AND keys.user_id=? "
                             "AND keys.profile=? AND keys.preview_id=?",
                             (task["company_id"], task["user_id"], task["profile"], task["preview_id"])).fetchone()
            if row:
                if self._business_content(json.loads(row["envelope"])["task"]) != self._business_content(task):
                    raise ConnectorError("preview_conflict", "同一预览不能更换摘要或内容，请创建新预览并确认")
                return {"task_id": row["task_id"], "status": row["state"], "duplicate": True}
            db.execute("INSERT INTO bridge_tasks VALUES (?,?,?,?,?,'queued',NULL,NULL,?)",
                       (task["task_id"], task["company_id"], task["user_id"], task["profile"], snapshot,
                        self.signer.clock()))
            self._register_preview(db, task)
        return {"task_id": task["task_id"], "status": "queued", "duplicate": False}

    @staticmethod
    def _business_content(task: dict) -> str:
        # Confirmation retries, changed delivery IDs and renewed expiry never create another
        # executable instance of an immutable preview. First confirmation remains authoritative.
        return canonical({key: task[key] for key in
                          ("company_id", "user_id", "profile", "preview_id", "digest", "payload")})

    @staticmethod
    def _register_preview(db, task: dict):
        db.execute("INSERT INTO bridge_preview_keys VALUES (?,?,?,?,?)",
                   (task["company_id"], task["user_id"], task["profile"], task["preview_id"], task["task_id"]))

    def envelope(self, binding: Binding, task_id: str) -> dict:
        """读取首次签发的快照；不延长有效期，也不改变领取或执行状态。"""
        with self._transaction() as db:
            row = self._bound_row(db, binding, task_id)
            envelope = json.loads(row["envelope"])
            self.signer.verify(envelope, binding, allow_expired=True)
            return envelope

    def claim(self, binding: Binding, *, task_id: str | None = None) -> dict | None:
        with self._transaction() as db:
            rows = db.execute("SELECT * FROM bridge_tasks WHERE company_id=? AND user_id=? AND profile=? "
                              "AND state='queued' AND (? IS NULL OR task_id=?) ORDER BY created_at,task_id",
                              (binding.company_id, binding.user_id, binding.profile, task_id, task_id)).fetchall()
            for row in rows:
                envelope = json.loads(row["envelope"])
                try:
                    self.signer.verify(envelope, binding)
                except ConnectorError as exc:
                    if exc.code != "task_expired":
                        raise
                    db.execute("UPDATE bridge_tasks SET state='expired' WHERE task_id=?", (row["task_id"],))
                    continue
                claim_token = secrets.token_urlsafe(32)
                db.execute("UPDATE bridge_tasks SET state='claimed',claim_token=? WHERE task_id=?",
                           (claim_token, row["task_id"]))
                return {"task": envelope, "claim_token": claim_token}
        return None

    @staticmethod
    def _bound_row(db, binding: Binding, task_id: str):
        row = db.execute("SELECT * FROM bridge_tasks WHERE task_id=? AND company_id=? AND user_id=? AND profile=?",
                         (task_id, binding.company_id, binding.user_id, binding.profile)).fetchone()
        if row is None:
            raise ConnectorError("task_not_found", "当前身份没有此任务")
        return row

    def report(self, binding: Binding, task_id: str, claim_token: str, status: str, result: dict) -> dict:
        if status not in {"succeeded", "failed", "unknown"} or not isinstance(result, dict):
            raise ConnectorError("invalid_result", "任务结果状态或内容不正确")
        snapshot = canonical(result)
        with self._transaction() as db:
            row = self._bound_row(db, binding, task_id)
            if not isinstance(claim_token, str) or not hmac.compare_digest(
                    (row["claim_token"] or "").encode(), claim_token.encode()):
                raise ConnectorError("claim_mismatch", "任务领取凭据无效")
            if row["state"] in {"succeeded", "failed", "unknown"}:
                if row["state"] != status or row["result"] != snapshot:
                    raise ConnectorError("result_conflict", "任务已有结果，需先人工核对，不能覆盖或重新执行")
                return {"task_id": task_id, "status": status, "duplicate": True}
            if row["state"] != "claimed":
                raise ConnectorError("task_not_claimed", "任务尚未领取，不能回传执行结果")
            db.execute("UPDATE bridge_tasks SET state=?,result=? WHERE task_id=?", (status, snapshot, task_id))
        return {"task_id": task_id, "status": status, "duplicate": False}

    def get(self, binding: Binding, task_id: str) -> dict:
        with self._transaction() as db:
            row = self._bound_row(db, binding, task_id)
            return {"task_id": task_id, "status": row["state"],
                    "requires_reconciliation": row["state"] in {"claimed", "unknown"},
                    "result": json.loads(row["result"]) if row["result"] else None}
