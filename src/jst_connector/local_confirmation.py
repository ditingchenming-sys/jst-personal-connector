"""仅向本人浏览器交付的单次业务确认；不在登录页承载业务操作。"""
from __future__ import annotations

import asyncio
import secrets
import time
from pathlib import Path
from urllib.parse import urlencode

from fastapi import Request
from fastapi.responses import HTMLResponse

from .errors import ConnectorError


class LocalConfirmation:
    def __init__(self, service, opener):
        self.service, self.opener = service, opener
        self.grants = {}

    async def open(self, profile, preview_id, digest, base_url):
        preview = self.service.ledger.get_preview(profile, preview_id)
        if preview["status"] != "ready" or preview["digest"] != digest:
            raise ConnectorError("confirmation_invalid", "预览已变化或已确认，请先查询同一操作状态。")
        if time.time() >= preview["expires_at"]:
            raise ConnectorError("preview_expired", "预览已过期，请重新预览。")
        self.grants = {k: v for k, v in self.grants.items() if v["expires_at"] > time.time()}
        token = secrets.token_urlsafe(32)
        self.grants[token] = {"profile": profile, "preview_id": preview_id, "digest": digest,
                              "expires_at": min(preview["expires_at"], time.time() + 300)}
        opened = await asyncio.to_thread(self.opener, base_url.rstrip("/") + "/operation-confirmation#" +
                                        urlencode({"grant": token}))
        if not opened:
            self.grants.pop(token, None)
        return {"ok": bool(opened), "preview_id": preview_id,
                "message": "已请求打开此操作的独立确认页；请本人核对后确认，再回到AI执行同一预览。"}

    def _grant(self, request):
        authorization = request.headers.get("authorization", "")
        token = authorization[7:] if authorization.startswith("Bearer ") else ""
        grant = self.grants.get(token)
        if grant is None or grant["expires_at"] <= time.time():
            self.grants.pop(token, None)
            raise ConnectorError("management_authorization_required", "确认入口无效或已过期，请重新打开此操作的确认页。")
        return token, grant

    def install(self, app):
        @app.get("/operation-confirmation", response_class=HTMLResponse)
        async def page():
            return Path(__file__).with_name("operation_confirmation.html").read_text(encoding="utf-8")

        @app.post("/confirmation/status")
        async def status(request: Request):
            _, grant = self._grant(request)
            preview = self.service.ledger.get_preview(grant["profile"], grant["preview_id"])
            return {"ok": True, "preview": preview}

        @app.post("/confirmation/approve")
        async def approve(request: Request):
            token, grant = self._grant(request)
            body = await request.json()
            if not isinstance(body, dict) or body.get("digest") != grant["digest"]:
                raise ConnectorError("digest_mismatch", "确认内容与原预览不一致，请重新核对。")
            result = self.service.approve(grant["profile"], grant["preview_id"], grant["digest"])
            self.grants.pop(token, None)
            return result
