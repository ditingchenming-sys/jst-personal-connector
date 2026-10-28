"""仅监听回环地址的员工组件与人工管理入口。"""
from __future__ import annotations

import asyncio
import json
import secrets
import socket
import time
import webbrowser
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlencode

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from filelock import FileLock, Timeout

from . import __version__
from .config import profile_name
from .errors import ConnectorError
from .service import ConnectorService
from .vault import _atomic_write


def _bearer(request: Request) -> str:
    value = request.headers.get("authorization", "")
    return value[7:] if value.startswith("Bearer ") else ""


def create_app(service: ConnectorService, *, opener=webbrowser.open) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        async def idle_cleanup():
            while True:
                await asyncio.sleep(30)
                await service.browser.close_idle()
        cleanup = asyncio.create_task(idle_cleanup())
        try:
            yield
        finally:
            cleanup.cancel()
            try:
                await cleanup
            except asyncio.CancelledError:
                pass
            await service.close()

    app = FastAPI(title="聚水潭个人连接器", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        host = request.headers.get("host", "").split(":")[0]
        if host not in ("127.0.0.1", "localhost", "testserver"):
            return JSONResponse({"ok": False, "error": {"code": "invalid_host", "message": "仅允许本机组件地址。"}}, status_code=403)
        origin = request.headers.get("origin")
        expected = str(request.base_url).rstrip("/")
        if origin and origin != expected:
            return JSONResponse({"ok": False, "error": {"code": "invalid_origin", "message": "拒绝来自其他网站的组件请求。"}}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.exception_handler(ConnectorError)
    async def connector_error(request, error):
        status = 401 if error.code in ("unauthorized", "management_authorization_required") else 409
        return JSONResponse(error.as_dict(), status_code=status)

    @app.exception_handler(Exception)
    async def unexpected_error(request, error):
        return JSONResponse({"ok": False, "error": {"code": "internal_error", "message": "组件内部异常，请查看脱敏诊断并核对任务状态。"}}, status_code=500)

    @app.get("/health")
    async def health():
        return {"ok": True, "version": __version__}

    @app.get("/ui", response_class=HTMLResponse)
    async def ui():
        return Path(__file__).with_name("management.html").read_text(encoding="utf-8")

    @app.post("/api/{action}")
    async def api(action: str, request: Request):
        profile = service.authenticate(_bearer(request))
        body = await request.json()
        if not isinstance(body, dict):
            raise ConnectorError("invalid_request", "请求必须是 JSON 对象。")
        if action == "status":
            return await service.status(profile)
        if action == "catalog":
            return service.catalog(body.get("query", ""), profile=profile)
        if action == "query":
            return await service.query(profile, body["capability_id"], body.get("parameters", {}))
        if action == "inspect":
            return {"ok": True, "page": await service.browser.inspect_page(profile, body["url"])}
        if action == "network":
            return {"ok": True, "events": await service.browser.network_events(profile)}
        if action == "discovery-start":
            return await service.start_discovery(profile, body.get("url", ""), body.get("purpose", "查看聚水潭页面"))
        if action == "discovery-inspect":
            return await service.inspect_discovery(profile, body["discovery_id"], body.get("kind", "page"),
                                                   body.get("reference", ""), body.get("search", ""), body.get("offset", 0))
        if action == "discovery-interact":
            return await service.interact_discovery(profile, body["discovery_id"], body["element_ref"],
                                                    body["action"], body.get("value", ""))
        if action == "interface-propose":
            return await service.propose_read_interface(profile, body)
        if action == "interface-validate":
            return await service.validate_read_interface(profile, body["interface_id"], body.get("parameters", {}))
        if action == "interface-call":
            return await service.call_saved_interface(profile, body["interface_id"], body.get("parameters", {}))
        if action == "interface-list":
            return await service.list_interfaces(profile, body.get("query", ""))
        if action == "preview":
            return await service.preview(profile, body["capability_id"], body.get("parameters", {}))
        if action == "preview-status":
            return {"ok": True, "preview": service.ledger.get_preview(profile, body["preview_id"])}
        if action == "execute":
            return await service.execute(profile, body["preview_id"], body["digest"])
        if action == "open-manager":
            fragment = urlencode({"profile": profile, "token": service.vault.manager_token()})
            # 管理能力只交给用户浏览器，不返回 AI 工具结果或请求日志。
            opened = await asyncio.to_thread(opener, str(request.base_url) + "ui#" + fragment)
            return {"ok": bool(opened), "message": "已请求打开本人登录授权页；连接完成后可关闭，回到AI或业务系统继续使用。"}
        raise ConnectorError("unsupported_action", "不支持此组件动作。")

    @app.post("/manage/{action}")
    async def manage(action: str, request: Request):
        service.authenticate_manager(_bearer(request))
        body = await request.json()
        if not isinstance(body, dict):
            raise ConnectorError("invalid_request", "请求必须是 JSON 对象。")
        profile = profile_name(body.get("profile", ""))
        if action == "status":
            return await service.status(profile)
        if action == "login-options":
            from .adapters.login import LOGIN_TERMS
            return {"ok": True, "terms": LOGIN_TERMS}
        if action == "identity-evidence":
            from .identity_probe import inspect_identity_sources
            return {"ok": True, "evidence": await inspect_identity_sources(service.browser, profile)}
        if action == "current-user-evidence":
            from .identity_probe import inspect_current_user_source
            return {"ok": True, "evidence": await inspect_current_user_source(service.browser, profile)}
        if action == "login-password":
            login = await service.browser.password_login(
                profile, body.get("username", ""), body.get("password", ""),
                remember=body.get("remember") is True, terms_accepted=body.get("terms_accepted") is True,
            )
            return {"ok": True, "login": login}
        if action == "login-status":
            return {"ok": True, "login": await service.browser.login_status(profile)}
        if action == "login-send-code":
            return {"ok": True, "login": await service.browser.send_login_code(profile)}
        if action == "login-submit-code":
            return {"ok": True, "login": await service.browser.submit_login_code(profile, body.get("code", ""))}
        if action == "login-cancel":
            return {"ok": True, "login": await service.browser.cancel_login(profile)}
        if action == "logout":
            await service.browser.logout(profile)
            return {"ok": True, "message": "已退出该调用端账号并清除其登录资料。"}
        if action == "preview-status":
            return {"ok": True, "preview": service.ledger.get_preview(profile, body["preview_id"])}
        if action == "approve":
            return service.approve(profile, body["preview_id"], body["digest"])
        raise ConnectorError("unsupported_action", "不支持此管理动作。")

    return app


def serve(root: Path, *, port: int = 0):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        with FileLock(str(root / ".agent-process.lock"), timeout=0, mode=0o600):
            _serve_locked(root, port=port)
    except Timeout:
        raise ConnectorError("agent_already_running", "此资料目录的组件已经运行，不允许启动第二个实例。") from None


def _serve_locked(root: Path, *, port: int):
    root = Path(root)
    service = ConnectorService(root)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", port))
    listener.listen(128)
    actual_port = listener.getsockname()[1]
    nonce = secrets.token_urlsafe(16)
    state_path = root / "agent.json"
    _atomic_write(state_path, json.dumps({"url": f"http://127.0.0.1:{actual_port}", "instance": nonce,
                                       "started_at": time.time()}, ensure_ascii=False).encode())
    server = uvicorn.Server(uvicorn.Config(create_app(service), log_level="critical", access_log=False))
    try:
        server.run(sockets=[listener])
    finally:
        listener.close()
        if state_path.exists():
            try:
                if json.loads(state_path.read_text())["instance"] == nonce:
                    state_path.unlink()
            except (OSError, ValueError, KeyError):
                pass

