"""可信系统任务的员工执行泵；由已配对的受信配置组装，不注册为 AI 确认工具。"""

from __future__ import annotations

import asyncio
import hashlib
import os
import tempfile
from dataclasses import asdict
from weakref import WeakValueDictionary

from filelock import FileLock, Timeout

from .bridge import Binding, canonical
from .errors import ConnectorError


class SystemRunner:
    def __init__(self, service, guard, binding: Binding, remote_client=None):
        self.service = service
        self.guard = guard
        self.binding = binding
        self.remote_client = remote_client
        self._inflight: WeakValueDictionary[str, asyncio.Lock] = WeakValueDictionary()
        binding_key = hashlib.sha256(canonical(asdict(binding)).encode()).hexdigest()[:32]
        base = guard.queue.path.parent / (guard.queue.path.name + ".outbox")
        base.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._outbox = base / binding_key
        self._outbox.mkdir(exist_ok=True, mode=0o700)
        if os.name != "nt":
            base.chmod(0o700)
            self._outbox.chmod(0o700)

    def _check_identity(self):
        session = self.service.vault.load_session(self.binding.profile)
        if session is None:
            raise ConnectorError("login_required", "请本人先登录聚水潭并核验身份")
        if any(str(session["identity"].get(key)) != getattr(self.binding, key)
               for key in ("company_id", "user_id")):
            raise ConnectorError("identity_mismatch", "当前聚水潭身份与已配对系统员工不一致")

    def _delivery_path(self, preview_id):
        # 128-bit opaque names keep Windows paths short; signed full identities are still
        # checked after decryption, so a filename collision can never grant another binding.
        key = hashlib.sha256(preview_id.encode()).hexdigest()[:32]
        return self._outbox / (key + ".delivery.enc")

    def _result_path(self, preview_id):
        return self._delivery_path(preview_id).with_name(
            self._delivery_path(preview_id).name.replace(".delivery.enc", ".result.enc"))

    def _write_encrypted(self, path, value):
        encrypted = self.service.vault.seal(value).encode("ascii")
        descriptor, temporary = tempfile.mkstemp(prefix=".pending-", dir=self._outbox)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encrypted)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _remember_delivery(self, delivery, task):
        path = self._delivery_path(task["preview_id"])
        if path.exists():
            try:
                saved = self.service.vault.unseal(path.read_text(encoding="ascii"))
            except UnicodeError as exc:
                raise ConnectorError("outbox_invalid", "待回传记录损坏，请核对本地执行记录") from exc
            previous, _ = self._verified_preview(saved)
            fields = ("preview_id", "digest", "payload")
            if canonical({k: previous[k] for k in fields}) != canonical({k: task[k] for k in fields}):
                raise ConnectorError("outbox_conflict", "同一预览已有不同待回传任务，请先核对")
            return saved  # Preserve the first server claim receipt; never overwrite it with a retry.
        self._write_encrypted(path, delivery)
        return delivery

    def _freeze_outcome(self, delivery, status, result):
        task = delivery["task"]["task"]
        context = {"binding": asdict(self.binding), "task_id": task["task_id"],
                   "preview_id": task["preview_id"], "digest": task["digest"]}
        path = self._result_path(task["preview_id"])
        if path.exists():
            try:
                saved = self.service.vault.unseal(path.read_text(encoding="ascii"))
            except UnicodeError as exc:
                raise ConnectorError("outbox_invalid", "待回传执行结果损坏，请先核对") from exc
            if (not isinstance(saved, dict) or saved.get("context") != context
                    or saved.get("status") not in {"succeeded", "failed", "unknown"}
                    or not isinstance(saved.get("result"), dict)):
                raise ConnectorError("outbox_invalid", "待回传执行结果损坏，请先核对")
            return saved["status"], saved["result"]
        self._write_encrypted(path, {"context": context, "status": status, "result": result})
        return status, result

    def _verified_preview(self, delivery: dict):
        if not isinstance(delivery, dict) or set(delivery) != {"task", "claim_token"}:
            raise ConnectorError("invalid_delivery", "系统任务投递格式不正确")
        if not isinstance(delivery["claim_token"], str) or not delivery["claim_token"]:
            raise ConnectorError("invalid_delivery", "缺少系统任务领取凭据")
        task = self.guard.queue.signer.verify(delivery["task"], self.binding, allow_expired=True)
        self._check_identity()
        preview = self.service.ledger.get_preview(self.binding.profile, task["preview_id"])
        if preview["digest"] != task["digest"] or canonical(preview["payload"]) != canonical(task["payload"]):
            raise ConnectorError("preview_mismatch", "签名任务与本地真实预览内容不一致")
        return task, preview

    def _outcome(self, task, *, error: ConnectorError | None = None):
        preview = self.service.ledger.get_preview(self.binding.profile, task["preview_id"])
        state = preview["status"]
        status = state if state in {"succeeded", "failed", "unknown"} else (
            "unknown" if state == "executing" else "failed")
        result = {"preview_id": task["preview_id"], "digest": task["digest"],
                  "execution_status": state, "evidence": preview["result"]}
        if error:
            result["error"] = error.as_dict()["error"]
        if status == "unknown":
            result["notice"] = "执行结果未知或任务已占用，须先回查，禁止重新执行。"
        return status, result

    async def _deliver(self, delivery, status, result, *, duplicate=False):
        status, result = self._freeze_outcome(delivery, status, result)
        response = {"ok": status == "succeeded", "task_id": delivery["task"]["task"]["task_id"],
                    "status": status, "result": result, "duplicate": duplicate,
                    "delivery_status": "result_delivery_pending"}
        if self.remote_client is not None:
            try:
                acknowledgement = await self.remote_client.report(
                    task_id=response["task_id"], claim_token=delivery["claim_token"], status=status, result=result)
                if (not isinstance(acknowledgement, dict) or acknowledgement.get("task_id") != response["task_id"]
                        or acknowledgement.get("status") != status):
                    raise ConnectorError("result_delivery_unconfirmed", "业务系统尚未确认收到同一任务结果")
                self._delivery_path(delivery["task"]["task"]["preview_id"]).unlink(missing_ok=True)
                self._result_path(delivery["task"]["task"]["preview_id"]).unlink(missing_ok=True)
                response["delivery_status"] = "reported"
            except Exception:  # noqa: BLE001 -- report failures retain the durable result, never retry ERP writes
                # Local outcome was persisted first. A lost report must never reissue an ERP write.
                response["notice"] = "结果已本地保留，系统回传待核对；不得重复执行。"
        else:
            response["notice"] = "执行结果已本地保留，尚未配置系统回传通道。"
        return response

    async def handle_delivery(self, delivery: dict) -> dict:
        try:
            task, _ = self._verified_preview(delivery)
        except ConnectorError as exc:
            return {"ok": False, "status": "rejected", "error": exc.as_dict()["error"]}
        # An active local execution owns result reporting. A duplicate must not finalize the
        # server task as unknown while that execution is still submitting or reading back.
        lock = self._inflight.get(task["preview_id"])
        if lock is None:
            lock = asyncio.Lock()
            self._inflight[task["preview_id"]] = lock
        if lock.locked():
            return {"ok": False, "task_id": task["task_id"], "status": "in_progress", "duplicate": True,
                    "delivery_status": "result_delivery_pending", "notice": "本人任务正在执行及回查，请等待原执行结果。"}
        async with lock:
            process_lock = FileLock(str(self._delivery_path(task["preview_id"]).with_suffix(".lock")),
                                    timeout=0, mode=0o600)
            try:
                process_lock.acquire(timeout=0)
            except Timeout:
                return {"ok": False, "task_id": task["task_id"], "status": "in_progress", "duplicate": True,
                        "delivery_status": "result_delivery_pending", "notice": "本人任务由另一执行进程处理，请等待原结果。"}
            try:
                delivery = self._remember_delivery(delivery, task)
                return await self._handle_delivery(delivery)
            except ConnectorError as exc:
                return {"ok": False, "status": "rejected", "error": exc.as_dict()["error"]}
            except OSError:
                return {"ok": False, "status": "unknown", "delivery_status": "result_delivery_pending",
                        "notice": "无法保存或读取本地任务记录，请先核对，禁止重新执行。"}
            finally:
                process_lock.release()

    async def _handle_delivery(self, delivery: dict) -> dict:
        try:
            task, preview = self._verified_preview(delivery)
        except ConnectorError as exc:
            return {"ok": False, "status": "rejected", "error": exc.as_dict()["error"]}

        # A task which already reached a Ledger terminal state can be reported after expiry.
        # It must not be re-approved or executed, even if local delivery bookkeeping was lost.
        try:
            known = self.guard.queue.get(self.binding, task["task_id"])
            stored = self.guard.queue.envelope(self.binding, task["task_id"])["task"]
            fields = ("preview_id", "digest", "payload")
            if canonical({k: stored[k] for k in fields}) != canonical({k: task[k] for k in fields}):
                raise ConnectorError("task_conflict", "同一任务编号不能更换执行内容")
        except ConnectorError as exc:
            if exc.code != "task_not_found":
                return {"ok": False, "status": "rejected", "error": exc.as_dict()["error"]}
            known = None
        if known and known["status"] in {"succeeded", "failed", "unknown"}:
            return await self._deliver(delivery, known["status"], known["result"], duplicate=True)
        if preview["status"] in {"succeeded", "failed", "unknown", "executing"}:
            status, result = self._outcome(task)
            return await self._deliver(delivery, status, result, duplicate=True)

        try:
            claim = self.guard.accept(delivery["task"], self.binding, preview_id=task["preview_id"],
                                      digest=preview["digest"], payload=preview["payload"])
        except ConnectorError as exc:
            if exc.code == "task_expired":
                status, result = self._outcome(task, error=exc)
                return await self._deliver(delivery, status, result)
            return {"ok": False, "status": "rejected", "error": exc.as_dict()["error"]}
        if claim is None:
            accepted = self.guard.queue.enqueue(delivery["task"])
            previous = self.guard.queue.get(self.binding, accepted["task_id"])
            if previous["status"] in {"succeeded", "failed", "unknown"}:
                status, result = previous["status"], previous["result"]
            else:
                status, result = "unknown", {"preview_id": task["preview_id"], "digest": task["digest"],
                                             "execution_status": preview["status"], "evidence": None,
                                             "notice": "任务已占用且结果待核对，禁止重新执行。"}
            return await self._deliver(delivery, status, result, duplicate=True)

        error = None
        cancelled = False
        try:
            if preview["status"] == "ready":
                self.service.ledger.approve(self.binding.profile, task["preview_id"], task["digest"], actor={
                    "source": "trusted_system", "company_id": self.binding.company_id,
                    "user_id": self.binding.user_id, "confirmation_id": task["confirmation_id"],
                    "task_id": task["task_id"],
                })
            await self.service.execute(self.binding.profile, task["preview_id"], task["digest"])
        except asyncio.CancelledError:
            cancelled = True
        except ConnectorError as exc:
            error = exc
        except Exception:  # noqa: BLE001 -- unexpected execution failures must still preserve the local outcome
            error = ConnectorError("execution_interrupted", "执行流程中断，请核对本地记录及原系统结果")
        status, result = self._outcome(task, error=error)
        self.guard.queue.report(self.binding, task["task_id"], claim["claim_token"], status, result)
        if cancelled:
            raise asyncio.CancelledError
        return await self._deliver(delivery, status, result)

    async def poll_once(self) -> dict:
        try:
            self._check_identity()
            # Resume the original encrypted receipt before claiming another task. Result
            # reporting can recover across process restarts without recovering an ERP write.
            for path in sorted(self._outbox.glob("*.delivery.enc")):
                pending = self.service.vault.unseal(path.read_text(encoding="ascii"))
                return await self.handle_delivery(pending)
        except UnicodeError:
            return {"ok": False, "status": "rejected", "error": {
                "code": "outbox_invalid", "message": "待回传记录损坏，请先核对本地执行记录", "details": {}}}
        except ConnectorError as exc:
            return {"ok": False, "status": "rejected", "error": exc.as_dict()["error"]}
        if self.remote_client is None:
            raise ConnectorError("system_channel_required", "尚未配置已认证的业务系统任务通道")
        delivery = await self.remote_client.claim()
        if delivery is None:
            return {"ok": True, "status": "idle", "notice": "尚无本人待执行任务。"}
        return await self.handle_delivery(delivery)
