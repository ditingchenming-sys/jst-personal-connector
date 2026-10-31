"""远程员工授权服务；部署在 HTTPS 反向代理后，不暴露本机管理令牌。"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from urllib.parse import quote, urlsplit

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from filelock import FileLock, Timeout

from . import __version__
from .config import profile_name
from .errors import ConnectorError
from .remote_client import public_origin
from .service import ConnectorService
from .vault import Vault

COOKIE = "__Host-jst-employee"
SESSION_TTL = 8 * 3600
_USERNAME = re.compile(r"[a-z0-9][a-z0-9_.@+-]{2,127}")


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _password(value, salt):
    return hashlib.scrypt(value.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()


def _username(value):
    if not isinstance(value, str) or not _USERNAME.fullmatch(value.lower()):
        raise ConnectorError("invalid_employee", "员工账号须为3至128位字母、数字或 ._@+-。")
    return value.lower()


class EmployeeStore:
    """盐化密码、独立连接令牌、浏览器会话和限流；业务会话仍由 Vault 隔离。"""
    def __init__(self, root: Path, vault: Vault):
        self.path = Path(root) / "employees.sqlite3"
        self.vault = vault
        with self._connection() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS employees (username TEXT PRIMARY KEY, encrypted TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS browser_sessions (id TEXT PRIMARY KEY, encrypted TEXT NOT NULL, expires REAL NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS login_limits (id TEXT PRIMARY KEY, count INTEGER NOT NULL, expires REAL NOT NULL)")
        self.path.chmod(0o600)

    @contextmanager
    def _connection(self, write=False):
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            if write:
                conn.execute("BEGIN IMMEDIATE")
            yield conn
            if write:
                conn.commit()
        except BaseException:
            if write:
                conn.rollback()
            raise
        finally:
            conn.close()

    def _employee(self, conn, username):
        row = conn.execute("SELECT encrypted FROM employees WHERE username=?", (username,)).fetchone()
        return self.vault.unseal(row[0]) if row else None

    def _save(self, conn, employee):
        conn.execute("INSERT OR REPLACE INTO employees VALUES (?,?)",
                     (employee["username"], self.vault.seal(employee)))

    @staticmethod
    def _connection_record(client):
        client = profile_name(client)
        token = "jst_remote_" + secrets.token_urlsafe(32)
        record = {"connection_id": secrets.token_urlsafe(18), "client": client,
                  "profile": "employee-" + secrets.token_hex(18), "token_hash": _hash(token),
                  "created_at": time.time()}
        return record, token

    def create_employee(self, username, password, client="workbench", *, issue_sink=None):
        username = _username(username)
        if not isinstance(password, str) or not 12 <= len(password) <= 1024:
            raise ConnectorError("invalid_password", "员工登录密码须为12至1024个字符。")
        connection, token = self._connection_record(client)
        salt = secrets.token_hex(16)
        employee = {"username": username, "salt": salt, "password_hash": _password(password, salt),
                    "connections": [connection], "enabled": True}
        with self._connection(write=True) as conn:
            if self._employee(conn, username):
                raise ConnectorError("employee_exists", "员工账号已存在，未覆盖。")
            self._save(conn, employee)
            if issue_sink:
                issue_sink(self._issued(employee, connection, token))
        return self._issued(employee, connection, token)

    @staticmethod
    def _issued(employee, connection, token):
        return {"username": employee["username"], "client": connection["client"],
                "connection_id": connection["connection_id"], "access_token": token}

    def issue_token(self, username, client="workbench", *, issue_sink=None):
        """本机管理员新增调用端或轮换其令牌；同时撤销该调用端的浏览器会话。"""
        username, client = _username(username), profile_name(client)
        with self._connection(write=True) as conn:
            employee = self._employee(conn, username)
            if not employee or not employee["enabled"]:
                raise ConnectorError("employee_not_found", "找不到已启用的员工账号。")
            connection = next((c for c in employee["connections"] if c["client"] == client), None)
            if connection is None:
                connection, token = self._connection_record(client)
                employee["connections"].append(connection)
            else:
                token = "jst_remote_" + secrets.token_urlsafe(32)
                connection["token_hash"] = _hash(token)
            self._save(conn, employee)
            self._revoke_sessions(conn, username)
            if issue_sink:
                issue_sink(self._issued(employee, connection, token))
        return self._issued(employee, connection, token)

    def disable(self, username):
        username = _username(username)
        with self._connection(write=True) as conn:
            employee = self._employee(conn, username)
            if not employee:
                raise ConnectorError("employee_not_found", "找不到员工账号。")
            employee["enabled"] = False
            self._save(conn, employee)
            self._revoke_sessions(conn, username)

    def _revoke_sessions(self, conn, username):
        for row in conn.execute("SELECT id,encrypted FROM browser_sessions").fetchall():
            if self.vault.unseal(row["encrypted"])["username"] == username:
                conn.execute("DELETE FROM browser_sessions WHERE id=?", (row["id"],))

    def bearer(self, token):
        if not isinstance(token, str) or not re.fullmatch(r"jst_remote_[A-Za-z0-9_-]{43}", token):
            raise ConnectorError("unauthorized", "员工调用授权无效或已撤销。")
        target = _hash(token)
        with self._connection() as conn:
            for row in conn.execute("SELECT encrypted FROM employees"):
                employee = self.vault.unseal(row[0])
                if employee["enabled"]:
                    for connection in employee["connections"]:
                        if hmac.compare_digest(connection["token_hash"], target):
                            return {"username": employee["username"], **connection}
        raise ConnectorError("unauthorized", "员工调用授权无效或已撤销。")

    def _limit(self, conn, key, maximum, window):
        key = _hash(key)
        now = time.time()
        row = conn.execute("SELECT count,expires FROM login_limits WHERE id=?", (key,)).fetchone()
        if row and row["expires"] > now:
            if row["count"] >= maximum:
                raise ConnectorError("login_rate_limited", "登录尝试过于频繁，请稍后再试。")
            conn.execute("UPDATE login_limits SET count=count+1 WHERE id=?", (key,))
        else:
            conn.execute("INSERT OR REPLACE INTO login_limits VALUES (?,?,?)", (key, 1, now + window))
        conn.execute("DELETE FROM login_limits WHERE expires < ?", (now,))

    def login(self, username, password, connection_id, peer):
        # Invalid names still take the same hash path and count toward peer limits.
        username = username.lower() if isinstance(username, str) else ""
        if not isinstance(password, str) or len(password) > 1024 or len(username) > 128:
            raise ConnectorError("unauthorized", "员工账号、密码或连接无效。")
        with self._connection(write=True) as conn:
            self._limit(conn, "peer:" + peer, 120, 300)
            self._limit(conn, "account:" + username, 8, 300)
        with self._connection(write=True) as conn:
            employee = self._employee(conn, username)
            salt = employee["salt"] if employee else "0" * 32
            checked = _password(password, salt)
            if not employee or not employee["enabled"] or not hmac.compare_digest(checked, employee["password_hash"]):
                raise ConnectorError("unauthorized", "员工账号、密码或连接无效。")
            connection = next((c for c in employee["connections"] if c["connection_id"] == connection_id), None)
            if connection_id is None and len(employee["connections"]) == 1:
                connection = employee["connections"][0]
            if connection is None:
                raise ConnectorError("unauthorized", "请通过本调用端提供的登录网址打开，员工账号须与该连接匹配。")
            token = secrets.token_urlsafe(32)
            record = {"username": username, "connection_id": connection["connection_id"],
                      "profile": connection["profile"], "client": connection["client"],
                      "csrf": secrets.token_urlsafe(32), "expires_at": time.time() + SESSION_TTL}
            conn.execute("DELETE FROM browser_sessions WHERE expires < ?", (time.time(),))
            conn.execute("INSERT INTO browser_sessions VALUES (?,?,?)",
                         (_hash(token), self.vault.seal(record), record["expires_at"]))
        return token, record

    def session(self, token):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            raise ConnectorError("employee_login_required", "请先登录本人的员工账号。")
        with self._connection() as conn:
            row = conn.execute("SELECT encrypted,expires FROM browser_sessions WHERE id=?", (_hash(token),)).fetchone()
            if row and row["expires"] > time.time():
                record = self.vault.unseal(row["encrypted"])
                employee = self._employee(conn, record["username"])
                if employee and employee["enabled"]:
                    return record
        raise ConnectorError("employee_login_required", "员工登录已失效，请重新登录。")

    def logout(self, token):
        with self._connection(write=True) as conn:
            conn.execute("DELETE FROM browser_sessions WHERE id=?", (_hash(token),))


def create_remote_app(service: ConnectorService, origin: str, *, employees=None, dispatcher=None):
    origin = public_origin(origin)
    employees = employees or EmployeeStore(service.root, service.vault)
    authority = urlsplit(origin).netloc

    @asynccontextmanager
    async def lifespan(app):
        async def cleanup():
            while True:
                await asyncio.sleep(30)
                await service.browser.close_idle()
        task = asyncio.create_task(cleanup())
        try:
            yield
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            await service.close()

    app = FastAPI(title="聚水潭员工连接", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

    @app.middleware("http")
    async def boundary(request, call_next):
        if request.headers.get("host", "").lower() != authority:
            return JSONResponse({"ok": False, "error": {"code": "invalid_host", "message": "远程服务域名不匹配。"}}, status_code=403)
        supplied = request.headers.get("origin")
        if ((supplied is not None and supplied != origin)
                or (request.method not in {"GET", "HEAD"} and request.url.path.startswith("/portal/") and supplied != origin)):
            return JSONResponse({"ok": False, "error": {"code": "invalid_origin", "message": "拒绝来自其他网站的授权请求。"}}, status_code=403)
        length = request.headers.get("content-length")
        if length is not None and (not length.isdecimal() or int(length) > 2_000_000):
            return JSONResponse({"ok": False, "error": {"code": "request_too_large", "message": "请求内容过大。"}}, status_code=413)
        response = await call_next(request)
        response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                                 "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
                                 "Strict-Transport-Security": "max-age=31536000",
                                 "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"})
        return response

    @app.exception_handler(ConnectorError)
    async def error_handler(request, error):
        status = 401 if error.code in {"unauthorized", "employee_login_required"} else 429 if error.code == "login_rate_limited" else 409
        return JSONResponse(error.as_dict(), status_code=status)

    @app.exception_handler(Exception)
    async def unexpected(request, error):
        return JSONResponse({"ok": False, "error": {"code": "internal_error", "message": "远程组件内部异常，请核对连接或原任务状态。"}}, status_code=500)

    async def body_json(request):
        try:
            raw = await request.body()
            if len(raw) > 2_000_000:
                raise ValueError
            body = json.loads(raw)
        except (ValueError, UnicodeError):
            raise ConnectorError("invalid_request", "请求须为有效的 JSON 对象。") from None
        if not isinstance(body, dict):
            raise ConnectorError("invalid_request", "请求须为 JSON 对象。")
        if any(key in body for key in ("profile", "company_id", "user_id", "employee_id")):
            raise ConnectorError("identity_parameter_rejected", "操作身份由员工授权解析，不能通过请求指定。")
        return body

    def employee_session(request, *, csrf=False):
        session = employees.session(request.cookies.get(COOKIE, ""))
        if csrf and not hmac.compare_digest(session["csrf"], request.headers.get("x-csrf-token", "")):
            raise ConnectorError("csrf_invalid", "页面授权校验失败，请刷新后重试。")
        return session

    @app.get("/health")
    async def health():
        return {"ok": True, "version": __version__, "mode": "remote"}

    @app.get("/login", response_class=HTMLResponse)
    async def login_page():
        return Path(__file__).with_name("remote_login.html").read_text(encoding="utf-8")

    @app.post("/portal/login")
    async def login(request: Request):
        body = await body_json(request)
        peer = request.client.host if request.client else "unknown"
        token, session = await asyncio.to_thread(employees.login, body.get("username", ""),
                                                body.get("password", ""), body.get("connection_id"), peer)
        # Replace any prior browser authorization rather than leaving an unnoticed account active.
        if request.cookies.get(COOKIE):
            employees.logout(request.cookies[COOKIE])
        response = JSONResponse({"ok": True, "username": session["username"], "client": session["client"],
                                 "connection_id": session["connection_id"], "csrf": session["csrf"]})
        response.set_cookie(COOKIE, token, max_age=SESSION_TTL, secure=True, httponly=True, samesite="strict", path="/")
        return response

    @app.get("/portal/session")
    async def session_status(request: Request):
        session = employee_session(request)
        return {"ok": True, "username": session["username"], "client": session["client"], "csrf": session["csrf"],
                "connection_id": session["connection_id"]}

    @app.post("/portal/logout")
    async def employee_logout(request: Request):
        employee_session(request, csrf=True)
        employees.logout(request.cookies[COOKIE])
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE, secure=True, httponly=True, samesite="strict", path="/")
        return response

    @app.post("/portal/connection/{action}")
    async def connection(action: str, request: Request):
        session = employee_session(request, csrf=True)
        profile = session["profile"]
        body = await body_json(request)
        if action == "status":
            return await service.status(profile)
        if action == "login-options":
            from .adapters.login import LOGIN_TERMS
            return {"ok": True, "terms": LOGIN_TERMS}
        if action == "login-password":
            result = await service.browser.password_login(profile, body.get("username", ""), body.get("password", ""),
                                                          remember=body.get("remember") is True,
                                                          terms_accepted=body.get("terms_accepted") is True)
        elif action == "login-status":
            result = await service.browser.login_status(profile)
        elif action == "login-send-code":
            result = await service.browser.send_login_code(profile)
        elif action == "login-submit-code":
            result = await service.browser.submit_login_code(profile, body.get("code", ""))
        elif action == "login-cancel":
            result = await service.browser.cancel_login(profile)
        elif action == "logout":
            await service.browser.logout(profile)
            return {"ok": True, "message": "已清除本员工本调用端的聚水潭登录资料。"}
        else:
            raise ConnectorError("unsupported_action", "此页面只提供本人登录授权与连接管理。")
        return {"ok": True, "login": result}

    @app.get("/operations/{preview_id}", response_class=HTMLResponse)
    async def operation_page(preview_id: str):
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,80}", preview_id):
            raise ConnectorError("preview_not_found", "预览编号无效。")
        # Page has no data until the logged-in employee's session is checked.
        return Path(__file__).with_name("remote_confirmation.html").read_text(encoding="utf-8")

    @app.post("/portal/operation")
    async def operation(request: Request):
        session = employee_session(request, csrf=True)
        body = await body_json(request)
        return {"ok": True, "preview": service.ledger.get_preview(session["profile"], body.get("preview_id", ""))}

    @app.post("/portal/approve")
    async def approve(request: Request):
        session = employee_session(request, csrf=True)
        body = await body_json(request)
        return service.approve(session["profile"], body.get("preview_id", ""), body.get("digest", ""))

    @app.post("/api/{action}")
    async def api(action: str, request: Request):
        header = request.headers.get("authorization", "")
        identity = employees.bearer(header[7:] if header.startswith("Bearer ") else "")
        body = await body_json(request)
        profile = identity["profile"]
        if action == "open-manager":
            url = origin + "/login?connection=" + quote(identity["connection_id"], safe="")
            return {"ok": True, "url": url, "message": "请在自己的浏览器打开此网址，登录本人员工账号后连接聚水潭。完成后可关闭。"}
        if action == "open-confirmation":
            record = service.ledger.get_preview(profile, body.get("preview_id", ""))
            if record["status"] != "ready" or record["digest"] != body.get("digest"):
                raise ConnectorError("confirmation_invalid", "预览已变化或已确认，请先查询同一操作状态。")
            if time.time() >= record["expires_at"]:
                raise ConnectorError("preview_expired", "预览已过期，请重新预览。")
            return {"ok": True, "url": origin + "/operations/" + quote(record["preview_id"], safe="")
                    + "?connection=" + quote(identity["connection_id"], safe=""),
                    "message": "请在本人已登录的浏览器核对完整预览并确认，确认后回到 AI 执行。"}
        if action in {"approve", "login-password", "login-send-code", "login-submit-code", "logout"}:
            raise ConnectorError("unsupported_action", "此动作须由本人授权页面或可信系统执行。")
        handler = dispatcher
        if handler is None:
            from .agent import dispatch_action
            handler = dispatch_action
        return await handler(service, profile, action, body, manager_opener=None, base_url=origin)

    return app


def serve_remote(root: Path, *, origin: str, port=8765):
    origin = public_origin(origin)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ConnectorError("invalid_port", "远程服务端口须为1至65535。")
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        with FileLock(str(root / ".agent-process.lock"), timeout=0, mode=0o600):
            service = ConnectorService(root)
            uvicorn.run(create_remote_app(service, origin), host="127.0.0.1", port=port,
                        proxy_headers=False, access_log=False, log_level="warning")
    except Timeout:
        raise ConnectorError("agent_already_running", "此资料目录已有组件在运行，请使用独立的远程服务资料目录。") from None
