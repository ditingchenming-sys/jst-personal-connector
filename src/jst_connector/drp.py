"""聚水潭分销独立登录与身份核验；不把 ERP Cookie 当成分销授权。

协议来源（2026-11-02 匿名核实）：account.scm121.com/user/login、
assets.sursung.com/prod/account/umi.5fac74bd.js 与
p__Account__Login.69f4a2fc.async.js；sc.scm121.com 的 PROJECT_CONFIG。
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import time
from urllib.parse import parse_qs, unquote, urlsplit

from playwright.async_api import Error as PlaywrightError

from .browser import BrowserManager, redact, safe_url
from .errors import ConnectorError
from .identity import _display_name, _identity_id
from .login_flow import PasswordLoginFlows
from .platform_policy import get_policy

ENTRY_URL = "https://sc.scm121.com/"
LOGIN_URL = "https://account.scm121.com/user/login"
LOGIN_TERMS = {"agreement_url": "https://app.jushuitan.com/doc/regUserAgreement.html",
               "privacy_url": "https://app.jushuitan.com/doc/regPrivacy.html"}
AUTH_BASE = "https://gyl.scm121.com/api/auth"
PASSWORD_URL = AUTH_BASE + "/open/v2/login/gyl/accountLogin"
ENCRYPT_KEY_URL = AUTH_BASE + "/open/getEncryptKey"
SEND_CODE_URL = AUTH_BASE + "/open/v2/login/gyl/getIdaasVerificationCode"
SUBMIT_CODE_URL = AUTH_BASE + "/open/v2/login/gyl/idaasVerificationLogin"
_AUTH_ORIGINS = frozenset({"https://gyl.scm121.com", "https://account.scm121.com"})
_AUTH_ENDPOINTS = (PASSWORD_URL, ENCRYPT_KEY_URL, SEND_CODE_URL, SUBMIT_CODE_URL)
_AUTH_CANONICAL = {url.replace("https://gyl.scm121.com", origin, 1): url
                   for origin in _AUTH_ORIGINS for url in _AUTH_ENDPOINTS}
USER_INFO_URL = "https://gyl.scm121.com/api/drp/user/supplier/getUserInfo?supplierType=shop&terminalName=SUPPLIER"
TOKEN_COOKIE = "DISTRYBUTION_TOKEN"
ERP_TOKEN_URL = "https://api.erp321.com/usercenterapi/SupplyChain/GetRedirectTokenV2"
_TOKEN = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_MAX_BODY = 262144


def _canonical_auth_url(value):
    """Only the four observed endpoints may use either official auth proxy."""
    try:
        parts = urlsplit(value)
        if (parts.scheme != "https" or "https://" + parts.netloc not in _AUTH_ORIGINS
                or parts.netloc != parts.hostname or parts.port is not None
                or parts.username or parts.password or parts.fragment or "#" in value or "\\" in value
                or any(character.isspace() or ord(character) < 32 for character in value)):
            return None
        return _AUTH_CANONICAL.get("https://" + parts.netloc + parts.path)
    except (ValueError, TypeError):
        return None

# These are actually requested by the anonymous account login build. They have no
# SCM cookies and never grant business requests or authentication redirects.
_LOGIN_ASSETS = frozenset("https://assets.sursung.com/" + path for path in (
    "pkg/jmx@0.0.2.min.js", "activity/20231102/jst_core.min.js", "pkg/dialog.jmx.min.js",
    "prod/account/antdStyle.ccf6f722.css", "prod/account/thirdParty.b07eb885.css",
    "prod/account/umi.c58cf163.css", "prod/account/unCompatible.js", "prod/account/proxyStorage.js",
    "pkg/react@17.0.2.production.min.js", "pkg/react-dom@17.0.2.production.min.js",
    "pkg/moment@2.25.3.min.js", "pkg/moment@2.25.3.zh-cn.min.js", "pkg/fingerprintjs@3.3.3.min.js",
    "pkg/antd_custom_2_4.11.2.min.js", "prod/account/polyfill.fbdad50b.js",
    "prod/account/antdStyle.5f8784e5.js", "prod/account/thirdParty.c5a91e2c.js",
    "prod/account/runtime.34ab8756.js", "prod/account/umi.5fac74bd.js",
    "prod/account/vendors.1a432ac7.async.js",
    "activity/20231206/1D5EB80F61FD4195AB642C84EE2FA8ED1701858295717.js",
    "prod/account/961.6190f149.async.js", "prod/account/layouts__RootLayout.69ce7609.chunk.css",
    "prod/account/layouts__RootLayout.ac38535f.async.js", "prod/account/wrappers.4d8cfe4a.chunk.css",
    "prod/account/wrappers.9cf9d1c4.async.js",
    "activity/20260112/73507E905E9042B7A1F896AB444C68891768198100275.js",
    "prod/account/728.ff1e7b13.async.js", "prod/account/p__Account__Login.a704a725.chunk.css",
    "prod/account/p__Account__Login.69f4a2fc.async.js",
    "activity/20240125/A9A274FB1ED144739C7E5D5EA4EFF6981706154739463.png",
    "activity/20240125/0DD4C225D0E1462AB1126C697A95D81F1706154519445.jpg",
    "activity/2024_imgs/dis/1/20221028/front/B4143A451D25406BAA058417F98D836A1666942856559.png",
    "activity/2024_imgs/dis/1/20221117/front/4AE0555CF87C49FAAF4D232F96E76A151668670714393.png",
    "activity/20240529/51AA7ABCC0D64D6C8A4533B8F4EFDD941716966342698.ico",
))


def _token_identity(token):
    """Untrusted JWT fields are only a comparison target for a server-validated token."""
    if not isinstance(token, str) or len(token) > 32768 or _TOKEN.fullmatch(token) is None:
        raise ConnectorError("IDENTITY_UNVERIFIED", "分销认证令牌格式尚未通过核验。")
    try:
        payload = token.split(".")[1]
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        expiry = data.get("exp")
        if expiry is not None and (type(expiry) not in (int, float) or expiry <= time.time()):
            raise ConnectorError("ERP_SESSION_REJECTED", "分销认证令牌已过期，请本人重新连接。")
        user = data["user"]
        return {"company_id": _identity_id(user["coId"]), "user_id": _identity_id(user["uid"])}
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise ConnectorError("IDENTITY_UNVERIFIED", "分销认证回执缺少已核实的公司和员工字段。") from None


async def _session_token(session):
    tokens = [unquote(cookie["value"]) for cookie in await session.context.cookies(["https://gyl.scm121.com/"])
              if cookie.get("name") == TOKEN_COOKIE and cookie.get("domain", "").lstrip(".") == "scm121.com"
              and isinstance(cookie.get("value"), str)]
    if len(tokens) != 1:
        raise ConnectorError("ERP_SESSION_REJECTED", "当前分销登录态缺失或有歧义，请本人重新连接分销账号。")
    _token_identity(tokens[0])
    return tokens[0]


class DrpIdentityVerifier:
    """固定供应商当前用户接口核验；首次对照受控认证回执，恢复对照 Vault。"""
    async def verify_session(self, session):
        token = await _session_token(session)
        token_identity = _token_identity(token)
        if session.login:
            sources = session.server_identity_sources
            provenance = all(isinstance(sources.get(key), dict)
                             and (sources[key].get("via"), sources[key].get("response_url"), sources[key].get("method"))
                             in ({("authentication-response", url, "POST") for url, canonical in _AUTH_CANONICAL.items()
                                  if canonical in {PASSWORD_URL, SUBMIT_CODE_URL}}
                                 | {("trusted-erp-exchange", ERP_TOKEN_URL, "POST")})
                             for key in ("company_id", "user_id"))
            if (not session.controlled_login or not session.server_passport_receipted
                    or session.server_identity_conflicted or not provenance
                    or getattr(session, "drp_receipt_digest", None) != hashlib.sha256(token.encode()).hexdigest()
                    or session.server_identity_candidate != token_identity):
                raise ConnectorError("IDENTITY_UNVERIFIED", "本次分销认证回执缺失或与当前登录态不一致。")
            expected = dict(session.server_identity_candidate)
        else:
            if not session.vault_binding or not isinstance(session.identity, dict):
                raise ConnectorError("IDENTITY_UNVERIFIED", "保存的分销身份缺少会话绑定。")
            expected = {key: _identity_id(session.identity.get(key)) for key in ("company_id", "user_id")}
        if token_identity != expected:
            raise ConnectorError("IDENTITY_CHANGED", "分销登录态的公司或员工与已绑定身份不一致。")
        response = None
        try:
            response = await session.context.request.get(
                USER_INFO_URL, headers={"Authorization": token, "appCode": "main", "Referer": ENTRY_URL},
                timeout=15000, max_redirects=0,
            )
            if response.url != USER_INFO_URL:
                raise ConnectorError("IDENTITY_UNVERIFIED", "分销当前用户接口响应来源发生变化。")
            if response.status in {301, 302, 303, 307, 308, 401, 403}:
                raise ConnectorError("ERP_SESSION_REJECTED", "分销系统未接受当前登录态，请本人重新连接。")
            if response.status != 200:
                raise ConnectorError("IDENTITY_UNVERIFIED", "分销当前用户读取未成功，业务调用已阻断。")
            body = await response.body()
            if len(body) > _MAX_BODY:
                raise ConnectorError("IDENTITY_UNVERIFIED", "分销当前用户响应超出已核实范围。")
            value = json.loads(body)
            if not isinstance(value, dict) or value.get("success") is not True:
                if isinstance(value, dict) and str(value.get("code")) == "1006":
                    raise ConnectorError("ERP_SESSION_REJECTED", "分销登录已失效，请本人重新连接。")
                raise ConnectorError("IDENTITY_UNVERIFIED", "分销服务器当前用户核验未通过。")
            data = value.get("data")
            user = data.get("coCompanyUser") if isinstance(data, dict) else None
            if not isinstance(user, dict):
                raise ConnectorError("IDENTITY_UNVERIFIED", "分销当前用户结构发生变化。")
            actual = {"company_id": _identity_id(data.get("coId")), "user_id": _identity_id(user.get("uid"))}
            if actual != expected or await _session_token(session) != token:
                raise ConnectorError("IDENTITY_CHANGED", "分销当前公司或员工与本次授权不一致。")
            return {**actual, "company_name": _display_name(data.get("coName")),
                    "user_name": _display_name(user.get("userName"))}
        except (PlaywrightError, OSError, TimeoutError, ValueError, UnicodeError):
            raise ConnectorError("IDENTITY_UNVERIFIED", "分销当前用户核验请求未完成，未自动重新登录。") from None
        finally:
            if response is not None:
                try:
                    await response.dispose()
                except (PlaywrightError, OSError, TimeoutError):
                    raise ConnectorError("IDENTITY_UNVERIFIED", "分销身份响应未能安全完成，业务调用已阻断。") from None


class DrpLoginDriver:
    """选择器来自官方登录 DOM 和固定 Login chunk；密码加密交给官方页面。"""
    def __init__(self, page):
        self.page = page

    def _official_page(self):
        if self.page.url != LOGIN_URL:
            raise ConnectorError("LOGIN_FORM_UNADAPTED", "当前已离开已核实的分销登录表单。")

    async def password(self, username, password, terms_accepted):
        self._official_page()
        if terms_accepted is not True:
            raise ConnectorError("TERMS_REQUIRED", "请本人阅读并同意聚水潭用户协议和隐私政策。")
        account = self.page.locator("input#username")
        secret = self.page.locator("input#password[type=password]")
        agreement = self.page.locator("input[type=checkbox]")
        await account.wait_for(state="visible", timeout=15000)
        if await account.count() != 1 or await secret.count() != 1 or await agreement.count() != 1:
            raise ConnectorError("LOGIN_FORM_UNADAPTED", "分销官方登录表单结构发生变化。")
        await account.fill(username)
        await secret.fill(password)
        await agreement.check()
        await self.page.get_by_role("button", name="立即登录", exact=True).click(timeout=5000)

    async def sms_supported(self):
        region = self.page.locator("form#SecondAuth")
        return (await region.count() == 1 and await region.is_visible()
                and await region.locator("input#SecondAuth_smsCode").count() == 1)

    async def send(self):
        self._official_page()
        if not await self.sms_supported():
            raise ConnectorError("SMS_FLOW_UNADAPTED", "当前不是已核实的分销二次短信验证步骤。")
        await self.page.locator("form#SecondAuth").get_by_text("获取验证码", exact=True).click(timeout=5000)

    async def code(self, code):
        self._official_page()
        if not await self.sms_supported():
            raise ConnectorError("SMS_FLOW_UNADAPTED", "分销短信验证表单尚未通过结构核对。")
        await self.page.locator("form#SecondAuth input#SecondAuth_smsCode").fill(code)
        await self.page.locator("form#SecondAuth").get_by_role("button", name="确定", exact=True).click(timeout=5000)

    async def notice(self):
        return False

    async def outcome(self, session, revision):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if session.auth_revision > revision:
                signal = session.auth_signal
                if signal == "authenticated":
                    try:
                        token = await _session_token(session)
                        if hashlib.sha256(token.encode()).hexdigest() != getattr(session, "drp_receipt_digest", None):
                            await asyncio.sleep(0.1)
                            continue
                    except ConnectorError:
                        await asyncio.sleep(0.1)
                        continue
                if signal != "need_code" or await self.sms_supported():
                    return signal
            await asyncio.sleep(0.1)
        return "timeout"


class DrpBrowserManager(BrowserManager):
    def __init__(self, vault, *, context_factory=None, identity_verifier=None, idle_seconds=300):
        super().__init__(vault, context_factory=context_factory, identity_verifier=identity_verifier or DrpIdentityVerifier(),
                         idle_seconds=idle_seconds)
        self.site_policy = get_policy("drp")
        self.platform = "drp"
        self._password_flows = PasswordLoginFlows(self, driver_factory=DrpLoginDriver)

    async def business_headers(self, session, url):
        if not self.site_policy.business_url(url):
            raise ConnectorError("INTERFACE_INVALID", "此地址不属于已核实的分销业务接口。")
        token = await _session_token(session)
        if session.login or not session.verified or _token_identity(token) != session.identity:
            raise ConnectorError("IDENTITY_CHANGED", "分销当前授权与已核实身份不一致，未发出业务请求。")
        return {"Authorization": token, "appCode": "main"}

    async def accept_erp_token(self, profile, token, source_identity):
        """仅由安装代码中的已验证 ERP 换票链调用，绝不注册为模型工具参数。"""
        candidate = _token_identity(token)
        if not isinstance(source_identity, dict):
            raise ConnectorError("IDENTITY_UNVERIFIED", "缺少已验证的ERP换票来源。")
        for key in ("company_id", "user_id"):
            _identity_id(source_identity.get(key))
        async with self._lock(profile):
            original = self.vault.session_binding(profile)
            if self.vault.load_session(profile):
                raise ConnectorError("ACCOUNT_ALREADY_CONNECTED", "本调用端已有分销账号，请先退出后再切换登录来源。")
            if self._password_flows.active(profile):
                raise ConnectorError("LOGIN_IN_PROGRESS", "本人分销登录正在进行，请完成或取消后再接续ERP授权。")
            old = self._sessions.pop(profile, None)
            if old:
                await self._cleanup_profile(profile)
                self._clear_server_identity_receipt(old)
                await old.context.close()
            session = await self._open(profile, login=True)
            try:
                session.controlled_login = True
                session.server_passport_receipted = True
                session.server_identity_candidate = candidate
                session.drp_receipt_digest = hashlib.sha256(token.encode()).hexdigest()
                session.server_identity_sources = {key: {"via": "trusted-erp-exchange", "response_url": ERP_TOKEN_URL,
                                                         "method": "POST"} for key in candidate}
                await session.context.add_cookies([{"name": TOKEN_COOKIE, "value": token, "domain": ".scm121.com",
                                                    "path": "/", "secure": True, "httpOnly": False, "sameSite": "Lax"}])
                identity = await self._verify(session)
                state = await session.context.storage_state()
                # Keep the newly issued binding and the CAS write under one process
                # lock, so a concurrent relogin cannot be mistaken for this exchange.
                with self.vault._lock:
                    self.vault.save_session(profile, state, identity, expected_binding=original)
                    session.vault_binding = self.vault.session_binding(profile)
                session.login = False
                return {"status": "connected", "identity": identity, "identity_display": dict(session.identity_display),
                        "_issued_binding": session.vault_binding,
                        "message": "已通过本人ERP服务器换发分销授权，并核实分销当前公司和员工；分销登录态独立加密保存。"}
            except BaseException:
                self._sessions.pop(profile, None)
                self._clear_server_identity_receipt(session)
                await session.context.close()
                raise

    async def _begin_password_login(self, profile, attempt):
        async with self._lock(profile):
            self._login_diagnostics.pop(profile, None)
            old = self._sessions.pop(profile, None)
            if old:
                await self._cleanup_profile(profile)
                self._clear_server_identity_receipt(old)
                await old.context.close()
            session = await self._open(profile, login=True)
            attempt.session = session
            session.controlled_login = True
            session.drp_login_name = attempt.username
            await session.page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=30000)
            return session

    @staticmethod
    def _grant_login_action(session, action):
        endpoint = {"password": PASSWORD_URL, "send": SEND_CODE_URL, "code": SUBMIT_CODE_URL}[action]
        session.auth_urls = {url for url, canonical in _AUTH_CANONICAL.items() if canonical == endpoint}
        session.auth_remaining = 1
        session.drp_key_remaining = 1 if action == "password" else 0
        session.auth_deadline = time.monotonic() + 30

    async def _capture_drp_receipt(self, session, request, response):
        if (not session.login or not session.controlled_login or response.url != request.url
                or time.monotonic() >= session.auth_deadline):
            return
        base = safe_url(request.url)
        canonical = _canonical_auth_url(request.url)
        if ((canonical, request.method) not in {(PASSWORD_URL, "POST"), (SEND_CODE_URL, "GET"), (SUBMIT_CODE_URL, "POST")}
                or (canonical != SEND_CODE_URL and request.url != base)):
            return
        body = await response.body() if response.status == 200 else b""
        try:
            value = json.loads(body) if len(body) <= _MAX_BODY else None
        except (ValueError, UnicodeError):
            value = None
        success = isinstance(value, dict) and value.get("success") is True
        signal = "rejected" if canonical == PASSWORD_URL else "send_rejected" if canonical == SEND_CODE_URL else "code_rejected"
        if canonical == SEND_CODE_URL and success:
            signal = "code_sent"
        elif canonical == PASSWORD_URL and isinstance(value, dict) and value.get("code") == "20002":
            signal = "need_code"
        elif canonical == PASSWORD_URL and isinstance(value, dict) and value.get("code") == "20001":
            signal = "unsupported"
        elif success:
            data = value.get("data")
            token = data.get("access_token") if isinstance(data, dict) else None
            try:
                identity = _token_identity(token)
            except ConnectorError:
                signal = "unsupported"
            else:
                digest = hashlib.sha256(token.encode()).hexdigest()
                if session.server_passport_receipted and session.server_identity_candidate != identity:
                    session.server_identity_conflicted = True
                    signal = "unsupported"
                else:
                    session.server_passport_receipted = True
                    session.server_identity_candidate = identity
                    session.drp_receipt_digest = digest
                    session.server_identity_sources = {key: {"via": "authentication-response", "response_url": base,
                                                             "method": request.method} for key in identity}
                    signal = "authenticated"
        session.auth_signal = signal
        session.auth_revision += 1

    async def _observe(self, session, response):
        session.events.append({"method": response.request.method, "url": safe_url(response.url),
                               "status": response.status, "classification": "observed_only",
                               "message": "分销请求线索；不保存请求头、请求体、认证令牌或原始响应。"})

    @staticmethod
    async def _abort_route(route, reason="blockedbyclient"):
        try:
            await route.abort(reason)
        except PlaywrightError:
            pass  # Cancellation/context shutdown may already have disposed the route.

    async def _route(self, session, route):
        request = route.request
        try:
            parts = urlsplit(request.url)
            base = safe_url(request.url)
            # safe_url only redacts diagnostic URLs. The fixed endpoint mapper
            # validates the original authority before considering a proxy alias.
            canonical = _canonical_auth_url(request.url)
        except (ValueError, TypeError):
            await self._abort_route(route)
            return
        fresh = (canonical is not None and session.login and session.controlled_login
                 and time.monotonic() < session.auth_deadline)
        auth = (fresh and canonical in {PASSWORD_URL, SUBMIT_CODE_URL} and base in session.auth_urls and session.auth_remaining > 0
                and request.url == base and request.method in {"POST", "OPTIONS"})
        send = (fresh and canonical == SEND_CODE_URL and base in session.auth_urls and session.auth_remaining > 0
                and request.method in {"GET", "OPTIONS"}
                and set(parse_qs(parts.query, keep_blank_values=True)) <= {"loginName", "fId"}
                and parse_qs(parts.query).get("loginName") == [getattr(session, "drp_login_name", "")])
        key = (fresh and canonical == ENCRYPT_KEY_URL and request.method in {"POST", "OPTIONS"}
               and getattr(session, "drp_key_remaining", 0) > 0
               and parse_qs(parts.query) == {"username": [getattr(session, "drp_login_name", "")]})
        initial = request.method == "GET" and request.url in {LOGIN_URL, ENTRY_URL}
        static = request.method == "GET" and request.url in _LOGIN_ASSETS
        if not (initial or static or auth or send or key):
            session.events.append({"method": request.method, "url": base, "classification": "blocked_unreviewed",
                                   **self._request_structure(request), "message": "分销登录期间未审核请求已阻断。"})
            await self._abort_route(route)
            return
        if request.method != "OPTIONS":
            if auth or send:
                session.auth_remaining -= 1
            if key:
                session.drp_key_remaining -= 1
        response = None
        try:
            response = await route.fetch(max_redirects=0, timeout=30000)
            if 300 <= response.status < 400:
                await self._abort_route(route)
                return
            if auth or send:
                await self._capture_drp_receipt(session, request, response)
            await route.fulfill(response=response)
        except (PlaywrightError, OSError):
            session.events.append({"method": request.method, "url": base, "classification": "request_failed",
                                   "message": "分销登录请求未完成，请检查网络与脱敏诊断。"})
            await self._abort_route(route, "failed")
        finally:
            if response is not None:
                try:
                    await response.dispose()
                except (PlaywrightError, OSError, TimeoutError):
                    if auth or send:
                        self._clear_server_identity_receipt(session)
                        session.auth_signal = "unsupported"
                        session.auth_revision += 1

    async def request(self, profile, method, url, payload=None):
        from .discovery_browser import _public_destination
        from .drp_read_policy import approved_request, validate_response
        page_read = method == "GET" and payload is None and self.site_policy.page_url(url)
        if not page_read and not approved_request(method, url, payload):
            raise ConnectorError("CAPABILITY_UNADAPTED", "分销功能请通过通用页面探索与接口契约调用，不使用ERP专用接口。")
        await _public_destination(url, policy=self.site_policy)
        async with self._lock(profile):
            session = await self._open(profile)
            if session.login:
                raise ConnectorError("LOGIN_REQUIRED", "请先完成本人的分销登录授权。")
            if session.identity is None:
                session.identity = dict(self.vault.load_session(profile)["identity"])
            identity = await self._verify(session)
            self._assert_scope(profile, session, identity)
            headers = {} if page_read else await self.business_headers(session, url)
            self._assert_scope(profile, session, identity)
            response = await session.context.request.fetch(url, method=method, data=payload,
                                                           headers=headers, timeout=30000, max_redirects=0)
            try:
                if response.url != url or response.status != 200:
                    raise ConnectorError("ERP_SESSION_REJECTED", "分销页面读取未成功，请核实本人连接。")
                body = await response.text()
                if len(body) > 8_000_000:
                    raise ConnectorError("ERP_RESPONSE_TOO_LARGE", "页面结果过大，请使用通用探索分段读取。")
                self._assert_scope(profile, session, await self._verify(session))
                result = {"status": 200, "text": body, "content_type": response.headers.get("content-type", "")}
                pagination = validate_response(method, url, payload, result)
                if pagination is not None:
                    result["pagination"] = pagination
                return result
            finally:
                try:
                    await response.dispose()
                except (PlaywrightError, OSError, TimeoutError):
                    raise ConnectorError("ERP_REQUEST_FAILED", "分销页面响应未能安全完成。") from None


class DrpClient:
    def __init__(self, browser):
        self.browser = browser

    def catalog(self):
        return [{"id": "DRP_SUPPLIER_OPTIONS", "name": "分销已关联供应商选项", "kind": "query",
                 "status": "adapted_pending_live_validation", "verification": "官方静态协议及隔离测试通过，待连接器真实账号验收",
                 "adapted_scope": "读取当前账号有权选择的供应商；不是本公司商品管理列表", "parameters": {}},
                {"id": "DRP_SUPPLIER_GOODS", "name": "分销供应商商品价格及库存", "kind": "query",
                 "status": "adapted_pending_live_validation", "verification": "官方静态协议及隔离测试通过，待连接器真实账号验收",
                 "adapted_scope": "按已选supplierCoId读取当前页SKU价格库存；大供应商异步链须另经通用探索核对",
                 "parameters": {"supplierCoId": "从供应商选项中选择的supplierCoId业务编号，必填",
                                "pageNum": "页码，默认1", "pageSize": "每页条数，默认20，最大500"}}]

    async def query(self, profile, capability_id, parameters):
        from .drp_read_policy import (
            SUPPLIER_GOODS_PATH,
            SUPPLIER_OPTIONS_PATH,
            approved_request,
            validate_response,
        )
        if capability_id not in {"DRP_SUPPLIER_OPTIONS", "DRP_SUPPLIER_GOODS"}:
            raise ConnectorError("CAPABILITY_UNADAPTED", "分销功能不受固定清单限制，请先通过通用探索定位对应页面，保存并调用当前账号的查询契约。")
        if not isinstance(parameters, dict):
            raise ConnectorError("INVALID_PARAMETERS", "查询条件必须是对象。")
        allowed = set() if capability_id == "DRP_SUPPLIER_OPTIONS" else {"supplierCoId", "pageNum", "pageSize"}
        if set(parameters) - allowed:
            raise ConnectorError("UNSUPPORTED_PARAMETERS", "存在尚未核实的查询条件，未执行查询；其它条件可通过通用接口契约复用。")
        payload, method, path = None, "GET", SUPPLIER_OPTIONS_PATH
        if capability_id == "DRP_SUPPLIER_GOODS":
            supplier = parameters.get("supplierCoId")
            if isinstance(supplier, bool) or not isinstance(supplier, (int, str)) or not re.fullmatch(r"[0-9]{1,24}", str(supplier)) or int(supplier) <= 0:
                raise ConnectorError("INVALID_PARAMETERS", "请从供应商选项中选择有效的supplierCoId业务编号。")
            payload = {"supplierCoId": supplier, "pageNum": parameters.get("pageNum", 1), "pageSize": parameters.get("pageSize", 20)}
            method, path = "POST", SUPPLIER_GOODS_PATH
        url = "https://gyl.scm121.com" + path
        if not approved_request(method, url, payload):
            raise ConnectorError("INVALID_PARAMETERS", "分页条件无效：页码须为正整数，每页条数须为1至500。")
        async with self.browser.verified_scope(profile) as identity:
            response = await self.browser.request(profile, method, url, payload)
            pagination = validate_response(method, url, payload, response)
            data = json.loads(response["text"])
            return redact({"capability_id": capability_id, "identity": identity, "filters": dict(parameters),
                           "data": data["data"], "total": pagination["total"], "pageNum": pagination["page"],
                           "pageSize": pagination["page_size"], "has_more": pagination["has_more"], "complete": False,
                           "scope": "supplier_options" if payload is None else "current_page",
                           "verification": "本次返回已通过本人身份和业务成功信封核验；仅当前页或所返回选项，不代表全量。"})

    async def preview(self, profile, capability_id, parameters):
        raise ConnectorError("CAPABILITY_UNADAPTED", "分销写入请从实际请求形成通用写契约，再预览、本人确认、执行及回查。")
