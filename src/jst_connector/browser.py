"""个人浏览器上下文。默认拒绝未知请求，不信任 Cookie 自报的身份。"""
from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from collections import deque
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit, urlunsplit
from uuid import uuid4

from playwright.async_api import Error as PlaywrightError

from .adapters import FMS_READS, ITEM_URL, ORDER_URL, PURCHASE_URL
from .adapters.login import AUTH_POST_URLS, CAPTCHA_URL, ENTRY_URL, LOGIN_URL, is_login_asset
from .auth_receipt import PASSPORT_URL, identity_cookie_receipt
from .errors import ConnectorError
from .login_flow import ACTIVE, PasswordLoginFlows, auth_login_signal, login_site_mode

ERP_HOSTS = {"www.erp321.com", "src.erp321.com", "api.erp321.com", "apiweb.erp321.com"}
SECRET_KEY = re.compile(r"pass|pwd|cookie|authorization|token|secret|credential|session|viewstate|u_cid", re.IGNORECASE)
AUTH_SCHEMA_KEYS = {
    "code", "data", "result", "success", "issuccess", "status", "message", "msg", "error",
    "islogin", "loggedin", "istpws", "idaashasrisk", "hasrisk", "needverification", "href", "url", "user", "company",
    "currentuser", "currentcompany", "userid", "user_id", "uid", "u_id", "coid", "co_id",
    "u_co_id", "companyid", "company_id", "username", "user_name", "companyname", "company_name",
    "account", "accounts", "companies", "id", "name",
}


def redact(value: Any) -> Any:
    """结构化响应只删除凭据；不把任意 ERP 原文或 URL 参数写入错误。"""
    if isinstance(value, dict):
        return {str(k): "[已脱敏]" if SECRET_KEY.search(str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def safe_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.hostname or "", parts.path, "", ""))


def auth_response_schema(value: Any, depth: int = 0) -> Any:
    """认证诊断只保留受限字段名和类型；任何标量值都不返回。"""
    if isinstance(value, dict):
        if depth >= 3:
            return "object"
        return {key: auth_response_schema(item, depth + 1)
                for key, item in list(value.items())[:50]
                if isinstance(key, str) and key.lower() in AUTH_SCHEMA_KEYS
                and not SECRET_KEY.search(key)}
    if isinstance(value, list):
        return "array"  # 不采样记录，避免动态字段名或个人数据进入诊断。
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return "string" if isinstance(value, str) else "other"


def _valid_erp_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
        return (parts.scheme == "https" and parts.hostname in ERP_HOSTS and parts.port in (None, 443)
                and not parts.username and not parts.password and not parts.fragment)
    except ValueError:
        return False


def approved_request(method: str, url: str, payload: Any = None) -> bool:
    """按完整端点及回调方法审核，不能以 GET 或方法名猜测读写。"""
    if not _valid_erp_url(url):
        return False
    parts = urlsplit(url)
    base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    query = parse_qs(parts.query, keep_blank_values=True)
    if method == "GET":
        return base in {PURCHASE_URL, ORDER_URL} and not parts.query and payload is None
    if method != "POST" or not isinstance(payload, dict):
        return False
    if url in FMS_READS:
        return not (set(payload) - {"ip", "coid", "uid", "data", "page"})
    if base == ITEM_URL:
        return (set(query) <= {"__from", "owner_co_id", "authorize_co_id"}
                and not (set(payload) - {"page", "data"}))
    methods = {PURCHASE_URL: "LoadDataToJSON", ORDER_URL: "ReloadOrdersWithFlds"}
    if base in methods and query == {"am___": [methods[base]]}:
        try:
            callback = json.loads(payload.get("__CALLBACKPARAM", ""))
            return (payload.get("__CALLBACKID") == "JTable1" and isinstance(callback, dict)
                    and callback.get("Method") == methods[base]
                    and set(callback) <= {"Method", "Args", "CallControl"})
        except (ValueError, TypeError):
            return False
    return False


@dataclass
class _Session:
    context: Any
    page: Any
    profile: str = ""
    login: bool = False
    identity: dict | None = None
    identity_display: dict = field(default_factory=dict)
    verified: bool = False
    binding: str = field(default_factory=lambda: uuid4().hex)
    vault_binding: str | None = None
    touched: float = field(default_factory=time.monotonic)
    events: deque = field(default_factory=lambda: deque(maxlen=100))
    controlled_login: bool = False
    auth_revision: int = 0
    auth_signal: str = ""
    auth_urls: set = field(default_factory=set)
    auth_remaining: int = 0
    auth_deadline: float = 0
    server_identity_candidate: dict = field(default_factory=dict, repr=False)
    server_identity_sources: dict = field(default_factory=dict, repr=False)
    server_passport_receipted: bool = field(default=False, repr=False)
    server_identity_conflicted: bool = field(default=False, repr=False)


class BrowserManager:
    def __init__(self, vault, *, context_factory=None, identity_verifier=None, idle_seconds=300):
        self.vault = vault
        self._factory = context_factory
        # Only a trusted installed verifier may supply identities. No protocol parameter sets this.
        self._verifier = identity_verifier
        self._idle_seconds = idle_seconds
        self._sessions: dict[str, _Session] = {}
        self._login_diagnostics: dict[str, list[dict]] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._playwright = None
        self._browser = None
        self._launch_lock = asyncio.Lock()
        self._scope: ContextVar[tuple | None] = ContextVar("erp_verified_scope", default=None)
        self._password_flows = PasswordLoginFlows(self)
        self._profile_cleanup = []

    def add_profile_cleanup(self, callback):
        self._profile_cleanup.append(callback)

    async def _cleanup_profile(self, profile):
        for callback in self._profile_cleanup:
            await callback(profile)

    def _lock(self, profile):
        return self._locks.setdefault(profile, asyncio.Lock())

    async def _new_context(self, state=None):
        if self._factory is not None:
            return await self._factory(state)
        from playwright.async_api import async_playwright
        async with self._launch_lock:
            if self._browser is None:
                try:
                    self._playwright = await async_playwright().start()
                    self._browser = await self._playwright.chromium.launch(headless=True)
                except (PlaywrightError, OSError):
                    if self._playwright:
                        await self._playwright.stop()
                        self._playwright = None
                    raise ConnectorError("BROWSER_UNAVAILABLE", "浏览器组件未就绪，请运行安装命令安装 Chromium。") from None
        return await self._browser.new_context(
            storage_state=state, viewport={"width": 1280, "height": 800}, service_workers="block",
        )

    async def _open(self, profile, *, login=False):
        session = self._sessions.get(profile)
        if session:
            session.touched = time.monotonic()
            return session
        before = None if login else self.vault.session_binding(profile)
        stored = None if login else self.vault.load_session(profile)
        after = None if login else self.vault.session_binding(profile)
        if before != after:
            raise ConnectorError("QUERY_SESSION_CHANGED", "个人账号会话正在变更，请重新发起查询。")
        if not login and not stored:
            raise ConnectorError("LOGIN_REQUIRED", "请先在管理页面登录本人的聚水潭账号。")
        context = await self._new_context(stored["state"] if stored else None)
        page = await context.new_page()
        session = _Session(context, page, profile=profile, login=login, vault_binding=after)
        self._sessions[profile] = session
        await context.route("**/*", lambda route: self._route(session, route))
        context.on("response", lambda response: self._observe(session, response))
        return session

    async def _observe(self, session, response):
        value = None
        event = {"method": response.request.method, "url": safe_url(response.url),
                 "status": response.status, "classification": "observed_only",
                 "message": "仅为接口线索，未据此判断可读写；不保存请求头和请求体。"}
        if session.login and response.url in AUTH_POST_URLS and response.request.method == "POST":
            try:
                body = await response.body()
                if len(body) <= 262144:
                    value = json.loads(body)
                    event["response_schema"] = auth_response_schema(value)
                    if isinstance(value, dict):
                        code = value.get("code")
                        if type(code) is int and abs(code) <= 1_000_000:
                            event["auth_result_code"] = code
                        data = value.get("data")
                        if isinstance(data, dict):
                            event["risk_flags"] = {key: data[key] for key in
                                                   ("idaasHasRisk", "hasRisk", "isTPWS")
                                                   if type(data.get(key)) is bool}
                            event["risk_message_present"] = bool(data.get("msg"))
                            site_mode = login_site_mode(data.get("isTPWS"))
                            if site_mode is not None:
                                event["site_mode"] = site_mode
                    if getattr(session, "controlled_login", False) and response.status == 200:
                        signal = auth_login_signal(response.url, value)
                        if signal:
                            session.auth_revision += 1
                            session.auth_signal = signal
            except (PlaywrightError, ValueError, UnicodeError):
                pass
        session.events.append(event)

    def _receipt_active(self, session):
        profile = getattr(session, "profile", None)
        attempt = self._password_flows.attempts.get(profile)
        return bool(getattr(session, "login", False) and getattr(session, "controlled_login", False)
                    and self._sessions.get(profile) is session and attempt
                    and attempt.session is session and not attempt.cancelled and attempt.status in ACTIVE
                    and time.monotonic() < attempt.deadline)

    @staticmethod
    def _clear_server_identity_receipt(session):
        getattr(session, "server_identity_candidate", {}).clear()
        getattr(session, "server_identity_sources", {}).clear()
        getattr(session, "identity_display", {}).clear()
        session.server_passport_receipted = False
        session.server_identity_conflicted = False

    async def _capture_server_identity_receipt(self, session, request, response):
        """Read the upstream APIResponse, never the browser's synthesized response or jar."""
        if not self._receipt_active(session):
            return
        method = request.method
        passport = request.url == PASSPORT_URL and method == "POST"
        entry = request.url == ENTRY_URL and method == "GET" and session.server_passport_receipted
        if not (passport or entry) or response.url != request.url:
            return
        code = None
        if passport:
            try:
                body = await response.body() if response.status == 200 else b""
                value = json.loads(body) if len(body) <= 262144 else None
                code = value.get("code") if isinstance(value, dict) else None
            except (PlaywrightError, ValueError, UnicodeError):
                code = None
            if not self._receipt_active(session):
                return
            if response.status != 200 or type(code) is not int or code != 0:
                self._clear_server_identity_receipt(session)
                return
            session.server_passport_receipted = True
        # APIResponse.headers_array is a synchronous property. Browser Response's
        # async header_values API is deliberately not used for upstream provenance.
        header_array = response.headers_array
        if not isinstance(header_array, list) or len(header_array) > 256:
            return
        headers = [item["value"] for item in header_array if isinstance(item, dict)
                   and isinstance(item.get("name"), str) and item["name"].lower() == "set-cookie"
                   and isinstance(item.get("value"), str)]
        receipt = identity_cookie_receipt(response.url, method, response.status, headers,
                                          active=self._receipt_active(session), passport_code=code,
                                          passport_succeeded=session.server_passport_receipted)
        if receipt is None or not self._receipt_active(session):
            return
        event = {"method": method, "url": safe_url(response.url), "status": response.status,
                 "classification": "upstream_identity_receipt",
                 "server_identity_cookie_source": "upstream_http_response"}
        event["server_identity_cookie_fields"] = sorted(source["cookie_name"] for source in receipt.sources.values())
        session.events.append(event)
        if receipt.rejected_fields:
            names = {"user_id": "u_id", "company_id": "u_co_id"}
            event["server_identity_cookie_rejected_fields"] = sorted(names[name] for name in receipt.rejected_fields)
            session.server_identity_candidate.clear()
            session.server_identity_sources.clear()
            session.server_identity_conflicted = True
            return
        if session.server_identity_conflicted:
            return
        if any(name in session.server_identity_candidate and session.server_identity_candidate[name] != candidate
               for name, candidate in receipt.candidates.items()):
            session.server_identity_candidate.clear()
            session.server_identity_sources.clear()
            session.server_identity_conflicted = True
            return
        session.server_identity_candidate.update(receipt.candidates)
        for name, source in receipt.sources.items():
            session.server_identity_sources.setdefault(name, source)

    @staticmethod
    def _request_structure(request):
        """诊断只留字段名，绝不留认证字段值、验证码、完整请求体。"""
        query_keys = [k if not SECRET_KEY.search(k) else "[凭据字段]"
                      for k in parse_qs(urlsplit(request.url).query, keep_blank_values=True)]
        fields = []
        try:
            body = request.post_data_json
            if isinstance(body, dict):
                fields = [str(k) if not SECRET_KEY.search(str(k)) else "[凭据字段]" for k in body]
        except (ValueError, PlaywrightError):
            fields = []  # 非 JSON 请求体不保留内容，避免诊断意外记录密码或验证码。
        return {"query_fields": query_keys[:50], "body_fields": fields[:50],
                "resource_type": request.resource_type}

    async def _route(self, session, route):
        request = route.request
        # Human login actions cannot issue business requests, even through SPA scripts.
        initial = request.method == "GET" and request.url in {LOGIN_URL, ENTRY_URL}
        # Exact assets actually referenced by the public login HTML. Resource type is untrusted.
        static = request.method == "GET" and is_login_asset(request.url)
        auth = (session.login and request.method in {"POST", "OPTIONS"}
                and request.url in AUTH_POST_URLS)
        if auth and session.controlled_login:
            auth = (session.auth_remaining > 0 and time.monotonic() < session.auth_deadline
                    and request.url in session.auth_urls)
            if auth and request.method == "POST":
                session.auth_remaining -= 1  # One explicit action permits at most one authentication POST.
        parts = urlsplit(request.url)
        captcha_query = parse_qs(parts.query, keep_blank_values=True)
        captcha = (session.login and request.method == "GET" and safe_url(request.url) == CAPTCHA_URL
                   and _valid_erp_url(request.url) and not parts.fragment
                   and set(captcha_query) == {"channel", "id", "t"}
                   and captcha_query["channel"] == ["login"]
                   and all(len(values) == 1 and 0 < len(values[0]) <= 200 for values in captcha_query.values()))
        if initial or static or auth or captcha:
            # Never let an approved asset or auth URL redirect outside this audit boundary.
            # Fetch with redirects disabled instead of inheriting trust through continue_().
            response = None
            try:
                response = await route.fetch(max_redirects=0, timeout=30000)
                if 300 <= response.status < 400:
                    session.events.append({"method": request.method, "url": safe_url(request.url),
                                           "classification": "blocked_redirect",
                                           "message": "已审核端点返回重定向，目标尚未重新审核，已阻断。"})
                    await route.abort("blockedbyclient")
                else:
                    await self._capture_server_identity_receipt(session, request, response)
                    await route.fulfill(response=response)
            except (PlaywrightError, OSError):
                session.events.append({"method": request.method, "url": safe_url(request.url),
                                       "classification": "request_failed",
                                       "message": "登录页面请求失败，请检查网络或查看被阻断的请求线索。"})
                await route.abort("failed")
            finally:
                if response:
                    await response.dispose()
        else:
            session.events.append({"method": request.method, "url": safe_url(request.url),
                                   "classification": "blocked_unreviewed",
                                   **self._request_structure(request),
                                   "message": "该请求端点缺少源码或公开页面证据，已阻断。需核实登录XHR端点、认证用途和响应身份字段后适配。"})
            await route.abort("blockedbyclient")

    async def start_login(self, profile):
        async with self._lock(profile):
            if self.vault.load_session(profile):
                raise ConnectorError("ACCOUNT_ALREADY_CONNECTED", "该调用端已有账号，请先退出再切换账号。")
            existing = self._sessions.get(profile)
            session = await self._open(profile, login=True)
            if existing is None:
                try:
                    await session.page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=30000)
                except (PlaywrightError, OSError):
                    self._sessions.pop(profile, None)
                    self._clear_server_identity_receipt(session)
                    await session.context.close()
                    raise ConnectorError("LOGIN_PAGE_UNAVAILABLE", "登录入口尚未加载成功，请检查网络或浏览器组件。") from None
            return {"status": "login_pending", "url": safe_url(session.page.url),
                    "message": "请本人在官方页面完成登录；可信公司及员工身份验证仍待适配。",
                    "login_transport": "已核实的账号密码/短信认证端点可用；未知风控及第三方扫码请求阻断并保留脱敏线索",
                    "identity_verification": "configured" if self._verifier else "unadapted"}

    def _login_session(self, profile):
        session = self._sessions.get(profile)
        if not session or not session.login:
            raise ConnectorError("LOGIN_NOT_STARTED", "请先开启本人登录页面。")
        session.touched = time.monotonic()
        return session

    async def login_view(self, profile):
        async with self._lock(profile):
            session = self._login_session(profile)
            if safe_url(session.page.url).rstrip("/") != LOGIN_URL:
                raise ConnectorError("LOGIN_FLOW_ENDED", "当前已离开核准登录入口，请结束登录验证。")
            # Mask password controls even if the site displays them as text.
            shot = await session.page.screenshot(type="png", mask=[
                session.page.locator("input[type=password],input[autocomplete=current-password],"
                                     "input[name*=password i],input[name*=pwd i]")])
            return {"image_base64": base64.b64encode(shot).decode("ascii"), "mime_type": "image/png",
                    "url": safe_url(session.page.url), "width": 1280, "height": 800,
                    "message": "登录画面仅供本人操作；密码框已遮蔽。"}

    async def login_action(self, profile, action):
        async with self._lock(profile):
            session = self._login_session(profile)
            if safe_url(session.page.url).rstrip("/") != LOGIN_URL:
                raise ConnectorError("LOGIN_FLOW_ENDED", "当前页面已离开登录入口，已停止交互。")
            if not isinstance(action, dict):
                raise ConnectorError("INVALID_LOGIN_ACTION", "登录操作格式无效。")
            kind = action.get("type")
            if kind == "click" and set(action) == {"type", "x", "y"}:
                x, y = action["x"], action["y"]
                if (type(x) not in (int, float) or type(y) not in (int, float)
                        or not 0 <= x < 1280 or not 0 <= y < 800):
                    raise ConnectorError("INVALID_LOGIN_ACTION", "点击坐标超出登录画面。")
                await session.page.mouse.click(x, y)
            elif kind == "type" and set(action) == {"type", "text"}:
                if not isinstance(action["text"], str) or len(action["text"]) > 1024:
                    raise ConnectorError("INVALID_LOGIN_ACTION", "输入文本格式或长度无效。")
                await session.page.keyboard.insert_text(action["text"])
            elif kind == "press" and set(action) == {"type", "key"}:
                if action["key"] not in {"Enter", "Tab", "Backspace", "Delete", "Escape", "Space"}:
                    raise ConnectorError("INVALID_LOGIN_ACTION", "仅允许登录表单使用的按键。")
                await session.page.keyboard.press(action["key"])
            else:
                raise ConnectorError("INVALID_LOGIN_ACTION", "仅支持登录画面点击、文本输入和表单按键。")
            return {"status": "login_pending", "message": "操作已传入登录画面，请查看最新画面。"}

    async def _verify(self, session):
        session.verified = False
        session.identity_display.clear()
        if self._verifier is None:
            raise ConnectorError("IDENTITY_UNVERIFIED", "尚未核实聚水潭当前公司和员工的可信身份来源，业务调用已阻断。")
        session_verifier = getattr(self._verifier, "verify_session", None)
        identity = await session_verifier(session) if callable(session_verifier) else await self._verifier(session.context)
        if (not isinstance(identity, dict) or any(not isinstance(identity.get(k), str) or not identity[k]
                                                for k in ("company_id", "user_id"))):
            raise ConnectorError("IDENTITY_UNVERIFIED", "聚水潭身份验证未返回明确的公司和员工，业务调用已阻断。")
        stored = session.identity
        if stored and any(identity[k] != stored[k] for k in ("company_id", "user_id")):
            session.identity = None
            raise ConnectorError("IDENTITY_CHANGED", "聚水潭当前账号或公司发生变化，请退出后重新连接。")
        session.identity = {k: identity[k] for k in ("company_id", "user_id")}
        session.identity_display = {key: identity[key] for key in ("company_name", "user_name")
                                    if isinstance(identity.get(key), str)}
        session.verified = True
        return dict(session.identity)

    async def finish_login(self, profile, remember=False):
        async with self._lock(profile):
            session = self._login_session(profile)
            identity = await self._verify(session)
            self.vault.save_session(profile, await session.context.storage_state(), identity)
            session.vault_binding = self.vault.session_binding(profile)
            session.login = False
            return {"status": "connected", "identity": identity, "remember_password": False,
                    "message": "登录态已加密保存。" + ("密码保存尚未适配，本次未保存密码。" if remember else "")}

    async def password_login(self, profile, username, password, remember=False, terms_accepted=False):
        return await self._password_flows.password_login(profile, username, password, remember, terms_accepted)

    async def login_status(self, profile):
        return await self._password_flows.login_status(profile)

    async def send_login_code(self, profile):
        return await self._password_flows.send_login_code(profile)

    async def submit_login_code(self, profile, code):
        return await self._password_flows.submit_login_code(profile, code)

    async def cancel_login(self, profile):
        result = await self._password_flows.cancel_login(profile)
        self._login_diagnostics.pop(profile, None)
        return result

    @staticmethod
    def _grant_login_action(session, action):
        suffixes = {
            "password": ("/Passport",),
            "send": ("/SendIdaasVerification",),
            "code": ("/IdaasVerification",),
        }[action]
        session.auth_urls = {url for url in AUTH_POST_URLS if url.endswith(suffixes)}
        session.auth_remaining = 1
        session.auth_deadline = time.monotonic() + 30

    async def _begin_password_login(self, profile, attempt):
        async with self._lock(profile):
            self._login_diagnostics.pop(profile, None)
            old = self._sessions.pop(profile, None)
            if old:
                await self._cleanup_profile(profile)
                self._clear_server_identity_receipt(old)
                await old.context.close()
            session = await self._open(profile, login=True)
            attempt.session = session  # Assigned before navigation so cancellation can always close it.
            session.controlled_login = True
            await session.page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=30000)
            return session

    async def _discard_password_login(self, profile, session):
        if session is None:
            return
        async with self._lock(profile):
            if self._sessions.get(profile) is session and session.login:
                attempt = self._password_flows.attempts.get(profile)
                if attempt and attempt.status in {"failed", "expired"}:
                    self._login_diagnostics[profile] = list(session.events)
                self._sessions.pop(profile, None)
                self._clear_server_identity_receipt(session)
                await session.context.close()

    async def _finish_password_login(self, profile, attempt, credentials):
        async with self._lock(profile):
            session = self._sessions.get(profile)
            if (attempt.cancelled or self._password_flows.attempts.get(profile) is not attempt
                    or session is not attempt.session or not session.login):
                raise ConnectorError("LOGIN_CANCELLED", "本次后台登录已失效，未保存登录资料。")
            identity = await self._verify(session)
            state = await session.context.storage_state()
            if (attempt.cancelled or time.monotonic() >= attempt.deadline
                    or self.vault.session_binding(profile) != attempt.original_binding):
                raise ConnectorError("LOGIN_CANCELLED", "登录核验期间账号资料发生变化，未保存本次资料。")
            self.vault.save_session(profile, state, identity, credentials=credentials,
                                    expected_binding=attempt.original_binding)
            session.vault_binding = self.vault.session_binding(profile)
            session.login = False
            attempt.status = "connected"

    async def status(self, profile):
        async with self._lock(profile):
            stored = self.vault.load_session(profile)
            session = self._sessions.get(profile)
            verification_message = None
            if (stored and not (session and session.login)
                    and callable(getattr(self._verifier, "verify_session", None))):
                try:
                    session = await self._open(profile)
                    if session.identity is None:
                        session.identity = dict(stored["identity"])
                    identity = await self._verify(session)
                    self._assert_scope(profile, session, identity)
                except ConnectorError as error:
                    if session:
                        session.verified = False
                        session.identity_display.clear()
                    verification_message = ("保存的登录态已过期或被聚水潭拒绝，请本人重新登录。"
                                            if error.code == "ERP_SESSION_REJECTED" else
                                            "保存的会话尚未通过当前用户核验，请稍后检查连接；业务调用保持阻断。")
            verified = (stored and session and session.verified and not session.login and session.identity == stored["identity"]
                        and session.vault_binding == self.vault.session_binding(profile))
            return {"status": "connected" if verified else "login_pending" if session and session.login else "saved_unverified" if stored else "disconnected",
                    "identity": stored["identity"] if stored else None,
                    "identity_display": dict(session.identity_display) if verified else {},
                    "message": verification_message or ("本人账号已可信核验。" if verified else "保存的会话仍须重新核实当前 ERP 身份。" if stored else "尚未连接本人账号。"),
                    "identity_verification": "configured" if self._verifier else "unadapted"}

    async def identity(self, profile):
        async with self._lock(profile):
            session = await self._open(profile)
            if session.login:
                raise ConnectorError("LOGIN_REQUIRED", "请先完成本人账号验证。")
            if session.identity is None:
                session.identity = dict(self.vault.load_session(profile)["identity"])
            identity = await self._verify(session)
            self._assert_scope(profile, session, identity)
            return identity

    def _assert_scope(self, profile, session, identity=None):
        persisted = self.vault.session_binding(profile)
        if session is not None and not session.login and session.vault_binding != persisted:
            raise ConnectorError("QUERY_SESSION_CHANGED", "个人账号会话已由其他进程退出或重新连接，本次结果已作废。")
        scope = self._scope.get()
        if scope is not None:
            expected_profile, binding, expected_identity, persisted_binding = scope
            if (profile != expected_profile or session is None or session.binding != binding
                    or persisted != persisted_binding or (identity is not None and identity != expected_identity)):
                raise ConnectorError("QUERY_SESSION_CHANGED", "查询期间账号会话发生变化，本次全部结果已作废，请重新查询。")

    @asynccontextmanager
    async def verified_scope(self, profile):
        """Bind an entire multi-request query to one verified account AND one context generation."""
        async with self._lock(profile):
            session = await self._open(profile)
            if session.login:
                raise ConnectorError("LOGIN_REQUIRED", "请先完成本人账号验证。")
            if session.identity is None:
                session.identity = dict(self.vault.load_session(profile)["identity"])
            identity = await self._verify(session)
            self._assert_scope(profile, session, identity)
            binding = session.binding
            persisted_binding = session.vault_binding
        token = self._scope.set((profile, binding, identity, persisted_binding))
        try:
            yield dict(identity)
            async with self._lock(profile):
                session = self._sessions.get(profile)
                self._assert_scope(profile, session)
                current = await self._verify(session)
                self._assert_scope(profile, session, current)
        finally:
            self._scope.reset(token)

    async def request(self, profile, method, url, payload=None):
        method = str(method).upper()
        if not approved_request(method, url, payload):
            raise ConnectorError("REQUEST_NOT_APPROVED", "该请求不在已审核只读端点中，已阻断。")
        async with self._lock(profile):
            self._assert_scope(profile, self._sessions.get(profile))
            session = await self._open(profile)
            if session.login:
                raise ConnectorError("LOGIN_REQUIRED", "请先完成本人账号验证。")
            if session.identity is None:
                session.identity = dict(self.vault.load_session(profile)["identity"])
            identity = await self._verify(session)
            self._assert_scope(profile, session, identity)
            # Identity fields are always overwritten from the verified session, never from caller input.
            body = dict(payload) if payload else None
            headers = {"Referer": "https://src.erp321.com/"}
            if url in FMS_READS:
                body.update(coid=identity["company_id"], uid=identity["user_id"], ip="")
                headers["Action-Name"] = FMS_READS[url]
            if urlsplit(url).path == urlsplit(ITEM_URL).path:
                query = parse_qs(urlsplit(url).query)
                for name in ("owner_co_id", "authorize_co_id"):
                    if query.get(name) != [identity["company_id"]]:
                        raise ConnectorError("IDENTITY_MISMATCH", "商品查询公司与已验证账号不一致，已阻断。")
            form = urlsplit(url).path in {urlsplit(PURCHASE_URL).path, urlsplit(ORDER_URL).path}
            if method == "POST" and form:
                headers.update({"Referer": safe_url(url), "X-Requested-With": "XMLHttpRequest"})
                for cookie in await session.context.cookies([safe_url(url)]):
                    if cookie["name"] == "u_cid":
                        body["__ajax_token"] = "1." + cookie["value"] + "-"
            options = {"method": method, "headers": headers, "timeout": 30000, "max_redirects": 0}
            if body is not None:
                options["form" if form else "data"] = body
            try:
                response = await session.context.request.fetch(url, **options)
                try:
                    if response.status in (301, 302, 303, 307, 308, 401, 403):
                        raise ConnectorError("ERP_SESSION_REJECTED", "聚水潭拒绝当前会话或权限，请本人重新登录核实。")
                    if response.status != 200:
                        raise ConnectorError("ERP_HTTP_ERROR", "聚水潭读取未成功。", details={"status": response.status})
                    text = await response.text()
                    if len(text) > 8_000_000:
                        raise ConnectorError("ERP_RESPONSE_TOO_LARGE", "单页结果超出安全返回范围，请缩小查询条件。")
                    current = await self._verify(session)
                    self._assert_scope(profile, session, current)
                    return {"status": response.status, "text": text}
                finally:
                    await response.dispose()
            except ConnectorError:
                raise
            except (PlaywrightError, OSError, UnicodeError):
                raise ConnectorError("ERP_REQUEST_FAILED", "聚水潭读取失败或超时，请稍后重试。") from None

    async def inspect_page(self, profile, url):
        # Only audited pages are inspected, through a GET that cannot navigate to arbitrary business URLs.
        response = await self.request(profile, "GET", url)
        from html.parser import HTMLParser

        class Structure(HTMLParser):
            def __init__(self):
                super().__init__()
                self.elements = []

            def handle_starttag(self, tag, attrs):
                if tag in {"form", "input", "button", "iframe", "table"} and len(self.elements) < 150:
                    attrs = dict(attrs)
                    self.elements.append({"tag": tag, "type": attrs.get("type"),
                                          "name": "[已脱敏]" if SECRET_KEY.search(attrs.get("name", ""))
                                          else attrs.get("name"), "has_value": "value" in attrs})

        parser = Structure()
        parser.feed(response["text"])
        return {"url": safe_url(url), "elements": parser.elements,
                "message": "仅返回页面结构，不返回隐藏字段值、内联脚本或认证资料。"}

    async def network_events(self, profile):
        session = self._sessions.get(profile)
        return {"events": list(session.events) if session else list(self._login_diagnostics.get(profile, [])),
                "message": "未知接口仅作待审核线索，不自动执行或猜测读写。",
                "required_evidence": ["登录XHR完整端点及官方域来源", "端点仅认证的证据", "当前公司和员工身份响应字段及其可信校验"]}

    async def logout(self, profile):
        attempt = self._password_flows.attempts.get(profile)
        await self._password_flows.cancel_login(profile)
        async with self._lock(profile):
            self._login_diagnostics.pop(profile, None)
            session = self._sessions.pop(profile, None)
            self.vault.clear_session(profile)
            await self._cleanup_profile(profile)
            if session:
                self._clear_server_identity_receipt(session)
                await session.context.close()
            if self._password_flows.attempts.get(profile) is attempt:
                self._password_flows.attempts.pop(profile, None)
            return {"status": "disconnected", "message": "本调用端的登录态及可选密码已清除。"}

    async def _save_current_state(self, profile, session):
        if (not session.login and session.identity
                and self.vault.session_binding(profile) == session.vault_binding):
            state = await session.context.storage_state()
            stored = self.vault.load_session(profile)
            try:
                self.vault.save_session(profile, state, session.identity,
                                        credentials=stored.get("credentials") if stored else None,
                                        expected_binding=session.vault_binding)
            except ConnectorError as error:
                if error.code != "session_changed":
                    raise
                # Another process logged out while storage_state was awaited; discard stale state.

    async def close_idle(self):
        for profile in list(self._sessions):
            async with self._lock(profile):
                session = self._sessions.get(profile)
                if self._password_flows.active(profile):
                    continue
                if session and time.monotonic() - session.touched >= self._idle_seconds:
                    await self._cleanup_profile(profile)
                    await self._save_current_state(profile, session)
                    self._clear_server_identity_receipt(session)
                    await session.context.close()
                    self._sessions.pop(profile, None)
        if not self._sessions:
            await self._close_browser()

    async def _close_browser(self):
        async with self._launch_lock:
            if self._browser:
                await self._browser.close()
                self._browser = None
            if self._playwright:
                await self._playwright.stop()
                self._playwright = None

    async def close(self):
        await self._password_flows.close()
        for profile in list(self._sessions):
            async with self._lock(profile):
                session = self._sessions.pop(profile)
                await self._cleanup_profile(profile)
                self._clear_server_identity_receipt(session)
                await self._save_current_state(profile, session)
                await session.context.close()
        await self._close_browser()
