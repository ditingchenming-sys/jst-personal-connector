"""业务系统的可信后端 SDK；不得直接作为 AI 可调用的确认接口暴露。"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Callable
from urllib.parse import urlsplit

import httpx

from .bridge import Binding, TaskQueue, canonical
from .errors import ConnectorError


class SystemSDK:
    """两个 resolver 都必须接真实应用认证，拒绝从普通业务参数取 actor。

    preview_loader(session, preview_id) 读取可信预览存储，返回 id/digest/payload。
    confirmation_verifier(session, receipt, preview) 必须验证后端持久化的本人点击事件，
    同时核对公司、员工、指定 profile、完整预览摘要及有效期；不能简单读取 confirmed=true。
    SDK 不判断 ERP 原子性或预览正确性，员工执行器仍须逐项复核。
    """

    def __init__(self, queue: TaskQueue, *, actor_resolver: Callable[[object], Binding],
                 preview_loader: Callable[[object, str], dict],
                 confirmation_verifier: Callable[[object, object, dict], bool]):
        self.queue = queue
        self.actor_resolver = actor_resolver
        self.preview_loader = preview_loader
        self.confirmation_verifier = confirmation_verifier

    def binding(self, authenticated_session: object) -> Binding:
        actor = self.actor_resolver(authenticated_session)
        if not isinstance(actor, Binding):
            raise ConnectorError("unauthenticated", "业务系统未提供已验证的员工及连接器绑定")
        return actor

    def create_task(self, authenticated_session: object, *, preview_id: str, confirmation: object,
                    ttl: int = 300, task_id: str | None = None) -> dict:
        binding = self.binding(authenticated_session)
        preview = json.loads(canonical(self.preview_loader(authenticated_session, preview_id)))
        if not isinstance(preview, dict) or preview.get("id") != preview_id:
            raise ConnectorError("invalid_preview", "未找到当前员工的可信预览")
        # Verifier receives the exact frozen snapshot which will be signed.
        if self.confirmation_verifier(authenticated_session, confirmation, preview) is not True:
            raise ConnectorError("confirmation_required", "须由本人在业务系统查看完整预览并确认")
        # Stable IDs derive only from the authenticated binding and server-loaded immutable
        # preview, after a trusted confirmation has been verified. Never hash repr(receipt):
        # receipts may be opaque framework objects and different events can confirm one preview.
        business_key = hashlib.sha256(canonical({"company_id": binding.company_id, "user_id": binding.user_id,
                                                "profile": binding.profile, "preview_id": preview_id,
                                                "digest": preview.get("digest")}).encode()).hexdigest()
        envelope = self.queue.signer.issue(binding, preview_id, preview.get("digest"), preview.get("payload"),
                                          ttl=ttl, task_id=task_id or "task_" + business_key,
                                          confirmation_id="confirmation_" + business_key)
        accepted = self.queue.enqueue(envelope)
        return self.queue.envelope(binding, accepted["task_id"])

    def claim(self, authenticated_session: object) -> dict | None:
        return self.queue.claim(self.binding(authenticated_session))

    def report(self, authenticated_session: object, *, task_id: str, claim_token: str,
               status: str, result: dict) -> dict:
        return self.queue.report(self.binding(authenticated_session), task_id, claim_token, status, result)

    def get(self, authenticated_session: object, task_id: str) -> dict:
        return self.queue.get(self.binding(authenticated_session), task_id)


class EmployeeTaskGuard:
    """员工执行前独立校验任务并持久化防重；只返回一次可执行任务。

    调用者必须先使用 ERP 已验证会话产生 binding，并确认 preview_id/digest/payload
    与当前 Ledger 预览完全一致。返回 None 表示已登记，不得再次执行。
    """

    def __init__(self, queue: TaskQueue):
        self.queue = queue

    def accept(self, envelope: dict, binding: Binding, *, preview_id: str, digest: str, payload: dict):
        task = self.queue.signer.verify(envelope, binding)
        if (task["preview_id"] != preview_id or task["digest"] != digest
                or canonical(task["payload"]) != canonical(payload)):
            raise ConnectorError("preview_mismatch", "任务内容与当前已核对的预览不一致，须重新确认")
        inserted = self.queue.enqueue(envelope)
        if inserted["duplicate"]:
            return None
        return self.queue.claim(binding, task_id=task["task_id"])


def validate_system_url(url: str, *, allow_loopback_test: bool = False) -> str:
    try:
        parsed = urlsplit(url)
        port = parsed.port
        del port
    except ValueError as exc:
        raise ConnectorError("invalid_system_url", "业务系统地址不正确") from exc
    if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
        raise ConnectorError("invalid_system_url", "业务系统地址不能含凭据、查询参数或片段")
    loopback = parsed.hostname.lower() == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        pass
    if parsed.scheme != "https" and not (allow_loopback_test and loopback and parsed.scheme == "http"):
        raise ConnectorError("insecure_system_url", "业务系统必须使用 HTTPS；仅隔离测试允许回环 HTTP")
    return url.rstrip("/")


class EmployeeTaskClient:
    """员工主动领取，不暴露本机公网入口；网络身份由系统签发的员工配对凭据确定。"""

    def __init__(self, base_url: str, token: str, *, allow_loopback_test: bool = False,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.base_url = validate_system_url(base_url, allow_loopback_test=allow_loopback_test)
        if not isinstance(token, str) or not token:
            raise ConnectorError("unauthenticated", "缺少业务系统签发的员工配对凭据")
        self._token = token
        self._transport = transport

    async def _post(self, path: str, payload: dict):
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=False, transport=self._transport,
                                         trust_env=False) as client:
                response = await client.post(self.base_url + path, json=payload,
                                             headers={"Authorization": "Bearer " + self._token})
                if 300 <= response.status_code < 400:
                    raise ConnectorError("system_redirect", "业务系统发生重定向，已停止以保护配对凭据")
                response.raise_for_status()
                return response.json()
        except ConnectorError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise ConnectorError("system_unavailable", "无法核实业务系统响应；执行结果未知时请先回查") from exc

    async def claim(self):
        return await self._post("/connector/tasks/claim", {})

    async def report(self, *, task_id: str, claim_token: str, status: str, result: dict):
        return await self._post("/connector/tasks/report", {"task_id": task_id, "claim_token": claim_token,
                                                           "status": status, "result": result})
