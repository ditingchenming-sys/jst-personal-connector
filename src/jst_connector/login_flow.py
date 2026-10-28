"""后台账密与按需短信中继；不把网页跳转或Cookie当作可信员工身份。"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from playwright.async_api import Error as PlaywrightError

from .adapters.login import AUTH_POST_URLS, LOGIN_URL
from .errors import ConnectorError

ACTIVE = {"starting", "logging_in", "need_code", "verifying", "identity_pending", "notice_pending"}


def login_site_mode(value):
    """Match JavaScript Number equality without publishing arbitrary server numeric values."""
    if type(value) not in (int, float):
        return None
    if value == 0:
        return "0"
    if value == 1:
        return "1"
    return "other_numeric"


def auth_login_signal(url, value):
    """仅提取审核认证响应的有限控制信号；不保留手机号、错误原文或认证值。"""
    if url not in AUTH_POST_URLS or not isinstance(value, dict) or type(value.get("code")) is not int:
        return None
    path = urlsplit(url).path
    if path == "/erp/webapi/UserApi/WebLogin/Passport":
        if value["code"] != 0:
            return "unsupported" if value["code"] == 10003 else "rejected"
        data = value.get("data")
        if not isinstance(data, dict):
            return "unsupported"
        if login_site_mode(data.get("isTPWS")) == "1":
            return "site_mismatch"  # The installed login page is ERP; never approve a WMS switch.
        if data.get("idaasHasRisk") is True:
            return "need_code"
        if data.get("hasRisk"):
            return "unsupported"
        if data.get("msg"):
            if (data.get("hasRisk") is False and data.get("idaasHasRisk") is False
                    and isinstance(data["msg"], str)):
                return "login_notice"
            return "notice_unverified"
        return "authenticated"
    if path in {"/erp/webapi/UserApi/WebLogin/SendIdaasVerification", "/usercenter/UnionApi/SendIdaasVerification"}:
        return "code_sent" if value["code"] == 0 else "send_rejected"
    if path in {"/erp/webapi/UserApi/WebLogin/IdaasVerification", "/usercenter/UnionApi/IdaasVerification"}:
        return "authenticated" if value["code"] == 0 else "code_rejected"
    return None


class DomLoginDriver:
    """选择器来自公开登录chunk；只操作账号密码表单和明确的IDAAS短信区。"""
    SMS = ".idaas-verify-warp___uNDx8"

    def __init__(self, page):
        self.page = page
        self.notice_consumed = False

    def _official_page(self):
        if self.page.url != LOGIN_URL:
            raise ConnectorError("LOGIN_PAGE_CHANGED", "当前已离开已核实的登录表单，已停止自动填写。")

    async def password(self, username, password, terms_accepted):
        self._official_page()
        if terms_accepted is not True:
            raise ConnectorError("TERMS_REQUIRED", "请本人阅读并勾选聚水潭用户协议及隐私政策。")
        account = self.page.locator("input#login_id")
        secret = self.page.locator("input#password[type=password]")
        agreement = self.page.locator(".agreement-wrap___WYUPP input[type=checkbox]")
        await account.wait_for(state="visible", timeout=15000)
        if await account.count() != 1 or await secret.count() != 1 or await agreement.count() != 1:
            raise ConnectorError("LOGIN_FORM_UNADAPTED", "官方登录表单结构发生变化，已停止填写。")
        await account.fill(username)
        await secret.fill(password)
        await agreement.check()  # Only after explicit terms_accepted=True from the personal UI.
        await self.page.locator("button.login-btn___AGd4D").click(timeout=5000)

    async def sms_supported(self):
        region = self.page.locator(self.SMS)
        return (await region.count() == 1 and await region.is_visible()
                and await region.locator("input[placeholder*='验证码'][maxlength='6']").count() == 1
                and await region.get_by_role("button", name="确定", exact=True).count() == 1)

    async def send(self):
        self._official_page()
        if not await self.sms_supported():
            raise ConnectorError("SMS_FLOW_UNADAPTED", "当前不是已核实的短信验证步骤，未发送短信。")
        await self.page.locator(self.SMS).get_by_role("link", name="获取验证码", exact=True).click(timeout=5000)

    async def code(self, code):
        self._official_page()
        if not await self.sms_supported():
            raise ConnectorError("SMS_FLOW_UNADAPTED", "短信验证表单已变化，未提交验证码。")
        region = self.page.locator(self.SMS)
        await region.locator("input[placeholder*='验证码'][maxlength='6']").fill(code)
        await region.get_by_role("button", name="确定", exact=True).click(timeout=5000)

    async def notice(self):
        """One known informational dialog only; never read/return its message or grant auth requests."""
        if self.page.url != LOGIN_URL:  # Exact login.aspx has no refer/query to select another destination.
            return False
        if self.notice_consumed:
            return False
        dialogs = self.page.locator('[role="dialog"]:visible')
        try:
            await dialogs.first.wait_for(state="visible", timeout=3000)
            if await dialogs.count() != 1:
                return False
            dialog = dialogs.first
            title = dialog.locator(".ant-modal-title")
            if await title.count() != 1 or (await title.inner_text()).strip() != "提示":
                return False
            if await dialog.locator("input,iframe,textarea,select,form,a,[contenteditable=true]").count():
                return False
            button = dialog.get_by_role("button", name=re.compile(r"^确\s*定$"))
            if await dialog.locator("button,[role=button]").count() != 1 or await button.count() != 1:
                return False
            self.notice_consumed = True  # Even a timeout after dispatch must not cause another click.
            await button.click(timeout=3000)
            return True
        except PlaywrightError:
            return False

    async def outcome(self, session, revision, timeout=25):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if session.auth_revision > revision and session.auth_signal:
                signal = session.auth_signal
                if signal == "need_code" and not await self.sms_supported():
                    await asyncio.sleep(0.2)
                    continue
                return signal
            # A four-character picture captcha is NOT a request to send an SMS.
            image_code = self.page.locator("input#verify_code")
            if await image_code.count() and await image_code.is_visible():
                return "unsupported"
            await asyncio.sleep(0.2)
        return "timeout"


@dataclass
class _Attempt:
    username: str = field(repr=False)
    password: str = field(repr=False)
    remember: bool = False
    terms_accepted: bool = False
    profile: str = ""
    status: str = "starting"
    message: str = "正在核验已有登录状态。"
    error_code: str | None = None
    masked_account: str = ""
    deadline: float = 0
    task: asyncio.Task | None = field(default=None, repr=False)
    session: object = field(default=None, repr=False)
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=1), repr=False)
    last_send: float = float("-inf")
    last_code: float = float("-inf")
    sends: int = 0
    guesses: int = 0
    sent: bool = False
    busy: bool = False
    cancelled: bool = False
    original_binding: str | None = None
    connected_binding: str | None = None
    recovery_only: bool = False


class PasswordLoginFlows:
    def __init__(self, browser, *, driver_factory=DomLoginDriver, ttl=600, send_cooldown=60, code_cooldown=5,
                 password_cooldown=3):
        self.browser = browser
        self.driver_factory = driver_factory
        self.ttl = ttl
        self.send_cooldown = send_cooldown
        self.code_cooldown = code_cooldown
        self.password_cooldown = password_cooldown
        self.attempts = {}
        self.locks = {}
        self.sent_at = {}
        self.submitted_at = {}
        self.password_history = {}
        self.send_history = {}
        self.code_history = {}

    def _lock(self, profile):
        return self.locks.setdefault(profile, asyncio.Lock())

    @staticmethod
    def _history(table, profile, window):
        cutoff = time.monotonic() - window
        recent = [stamp for stamp in table.get(profile, []) if stamp > cutoff]
        table[profile] = recent
        return recent

    def _snapshot(self, attempt):
        retry = int(max(0, self.send_cooldown - (time.monotonic() - attempt.last_send) + 0.999))
        code_retry = int(max(0, self.code_cooldown - (time.monotonic() - attempt.last_code) + 0.999))
        sends = self._history(self.send_history, attempt.profile, 600)
        guesses = self._history(self.code_history, attempt.profile, 300)
        if len(sends) >= 3:
            retry = max(retry, int(sends[0] + 600 - time.monotonic() + 0.999))
        if len(guesses) >= 5:
            code_retry = max(code_retry, int(guesses[0] + 300 - time.monotonic() + 0.999))
        return {"status": attempt.status, "message": attempt.message, "masked_account": attempt.masked_account,
                "error_code": attempt.error_code,
                "can_send_code": attempt.status == "need_code" and not attempt.busy and retry == 0 and len(sends) < 3,
                "retry_after_seconds": retry, "code_retry_after_seconds": code_retry,
                "code_sent": attempt.sent, "remember_password": attempt.remember and attempt.status == "connected"}

    def active(self, profile):
        attempt = self.attempts.get(profile)
        return bool(attempt and attempt.status in ACTIVE and attempt.task and not attempt.task.done())

    async def password_login(self, profile, username, password, remember=False, terms_accepted=False):
        async with self._lock(profile):
            existing = self.attempts.get(profile)
            if self.active(profile):
                return self._snapshot(existing)
            if (not isinstance(username, str) or not username.strip() or len(username) > 128
                    or not isinstance(password, str) or not password or len(password) > 1024
                    or type(remember) is not bool or type(terms_accepted) is not bool):
                raise ConnectorError("INVALID_LOGIN_PARAMETERS", "请填写有效的账号和密码，登录选项必须是明确的勾选状态。")
            if terms_accepted is not True:
                raise ConnectorError("TERMS_REQUIRED", "请本人先阅读并勾选聚水潭用户协议及隐私政策。")
            username = username.strip()
            masked = username[0] + "***" + username[-1] if len(username) > 2 else "***"
            attempt = _Attempt(username, password, remember, terms_accepted, profile=profile, masked_account=masked,
                               deadline=time.monotonic() + self.ttl,
                               last_send=self.sent_at.get(profile, float("-inf")),
                               last_code=self.submitted_at.get(profile, float("-inf")))
            self.attempts[profile] = attempt
            attempt.task = asyncio.create_task(self._run(profile, attempt))
            return self._snapshot(attempt)

    async def login_status(self, profile):
        attempt = self.attempts.get(profile)
        if attempt and attempt.status == "connected":
            session = self.browser._sessions.get(profile)
            if (session is None or not session.verified or session.login
                    or self.browser.vault.session_binding(profile) != attempt.connected_binding):
                async with self._lock(profile):
                    if self.attempts.get(profile) is attempt:
                        self.attempts.pop(profile)
                # Re-enter only after releasing the flow lock; recovery is another single-flight task.
                return await self.login_status(profile)
        if not attempt:
            stored = self.browser.vault.load_session(profile)
            if stored:
                if self.browser._verifier is None:
                    return {"status": "identity_pending", "message": "已保存登录资料；可信身份核验尚未适配，未要求重填密码或重新发送短信。",
                            "masked_account": "已保存账号", "can_send_code": False, "retry_after_seconds": 0,
                            "code_retry_after_seconds": 0}
                async with self._lock(profile):
                    attempt = self.attempts.get(profile)
                    if attempt is None:
                        attempt = _Attempt("", "", profile=profile, recovery_only=True, deadline=time.monotonic() + self.ttl)
                        self.attempts[profile] = attempt
                        attempt.task = asyncio.create_task(self._run(profile, attempt))
                return self._snapshot(attempt)
            return {"status": "disconnected", "message": "尚未开始本人的后台登录。", "masked_account": "",
                    "can_send_code": False, "retry_after_seconds": 0, "code_retry_after_seconds": 0}
        return self._snapshot(attempt)

    async def send_login_code(self, profile):
        async with self._lock(profile):
            attempt = self.attempts.get(profile)
            if not attempt or not self.active(profile) or attempt.status != "need_code":
                raise ConnectorError("SMS_NOT_REQUIRED", "ERP当前没有明确要求短信验证，不能发送验证码。")
            if not self._snapshot(attempt)["can_send_code"]:
                raise ConnectorError("LOGIN_RATE_LIMITED", "请等待短信发送冷却结束；每个调用端10分钟内最多发送三次。")
            attempt.last_send = time.monotonic()
            self.sent_at[profile] = attempt.last_send
            self._history(self.send_history, profile, 600).append(attempt.last_send)
            attempt.sends += 1
            attempt.busy = True
            attempt.queue.put_nowait(("send", None))
            return self._snapshot(attempt)

    async def submit_login_code(self, profile, code):
        if not isinstance(code, str) or re.fullmatch(r"[0-9]{6}", code) is None:
            raise ConnectorError("INVALID_LOGIN_CODE", "请输入收到的6位数字短信验证码。")
        async with self._lock(profile):
            attempt = self.attempts.get(profile)
            if not attempt or not self.active(profile) or attempt.status != "need_code" or not attempt.sent:
                raise ConnectorError("SMS_NOT_REQUIRED", "请仅在ERP要求并已发送短信后提交验证码。")
            if attempt.busy or self._snapshot(attempt)["code_retry_after_seconds"]:
                raise ConnectorError("LOGIN_RATE_LIMITED", "验证码提交过于频繁或已达到五分钟五次上限；取消重开不会重置限制。")
            attempt.last_code = time.monotonic()
            self.submitted_at[profile] = attempt.last_code
            self._history(self.code_history, profile, 300).append(attempt.last_code)
            attempt.guesses += 1
            attempt.busy = True
            attempt.status, attempt.message = "verifying", "正在校验本人提交的短信验证码。"
            attempt.queue.put_nowait(("code", code))
            return self._snapshot(attempt)

    async def cancel_login(self, profile):
        async with self._lock(profile):
            attempt = self.attempts.get(profile)
            if not attempt:
                return {"status": "cancelled", "message": "没有进行中的后台登录，已连接账号保持不变。",
                        "masked_account": "", "can_send_code": False, "retry_after_seconds": 0}
            if attempt.status == "connected":
                return self._snapshot(attempt)
            attempt.cancelled = True
            attempt.status, attempt.message = "cancelled", "本次后台登录已取消，未退出已连接账号。"
            task = attempt.task
            if task and not task.done():
                task.cancel()
        if task and not task.done():
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._clear(attempt)
        return self._snapshot(attempt)

    def _clear(self, attempt):
        attempt.username = attempt.password = ""
        while not attempt.queue.empty():
            attempt.queue.get_nowait()

    async def _run(self, profile, attempt):
        try:
            await asyncio.wait_for(self._work(profile, attempt), timeout=self.ttl)
        except TimeoutError:
            attempt.status, attempt.message = "expired", "本次登录已超时，请重新开始；未自动重发短信。"
            attempt.error_code = "LOGIN_EXPIRED"
        except asyncio.CancelledError:
            attempt.status, attempt.message = "cancelled", "本次后台登录已取消。"
            attempt.error_code = "LOGIN_CANCELLED"
            raise
        except ConnectorError as error:
            messages = {
                "LOGIN_FLOW_UNADAPTED": "ERP要求当前未适配的验证，已停止；不会自动发短信或反复提交账号密码。",
                "LOGIN_FORM_UNADAPTED": "官方登录表单已变化，当前未适配，已停止填写。",
                "SMS_FLOW_UNADAPTED": "ERP当前短信验证步骤尚未适配，已停止；没有自动重发。",
                "LOGIN_AUTH_REJECTED": "ERP未通过本次账号密码认证，请核对后手动重试。",
                "LOGIN_FLOW_TIMEOUT": "未收到已核实的认证结果，已停止本次提交；不会自动重试。",
            }
            attempt.status = "cancelled" if attempt.cancelled else "failed"
            attempt.error_code = "LOGIN_CANCELLED" if attempt.cancelled else error.code if error.code in messages else "LOGIN_VERIFICATION_FAILED"
            attempt.message = "本次后台登录已取消。" if attempt.cancelled else messages.get(
                error.code, "当前身份核验或登录资料状态未通过，已停止；请核实后再操作。")
        except Exception:  # noqa: BLE001 - credential tasks must never publish raw exceptions or tracebacks.
            if attempt.cancelled:
                attempt.status, attempt.message = "cancelled", "本次后台登录已取消。"
                attempt.error_code = "LOGIN_CANCELLED"
            else:
                attempt.status, attempt.message = "failed", "后台登录未完成，请核对账号、密码或当前ERP验证要求后重试。"
                attempt.error_code = "LOGIN_FAILED"
        finally:
            self._clear(attempt)
            if attempt.status != "connected":
                await self.browser._discard_password_login(profile, attempt.session)

    async def _finish(self, profile, attempt):
        if self.browser._verifier is None:
            attempt.status, attempt.message = "identity_pending", "ERP认证已通过，当前公司及员工的可信核验仍待适配，业务调用保持阻断。"
            # Retain only in-memory browser progress until the explicit login timeout/cancellation.
            await asyncio.Future()
        credentials = {"username": attempt.username, "password": attempt.password,
                       "terms_accepted": True} if attempt.remember else None
        await self.browser._finish_password_login(profile, attempt, credentials)
        attempt.connected_binding = self.browser.vault.session_binding(profile)
        attempt.status, attempt.message = "connected", "本人账号已可信核验，登录态已加密保存。"

    async def _work(self, profile, attempt):
        attempt.original_binding = self.browser.vault.session_binding(profile)
        stored = self.browser.vault.load_session(profile)
        if self.browser.vault.session_binding(profile) != attempt.original_binding:
            raise ConnectorError("QUERY_SESSION_CHANGED", "个人账号资料正在变化，请稍后重试。")
        if stored:
            if self.browser._verifier is None:
                attempt.status, attempt.message = "identity_pending", "已保存登录资料，但当前可信身份核验尚未适配；未重新提交账号密码或发送短信。"
                await asyncio.Future()
            try:
                identity = await self.browser.identity(profile)
                if (identity != stored["identity"]
                        or self.browser.vault.session_binding(profile) != attempt.original_binding):
                    raise ConnectorError("QUERY_SESSION_CHANGED", "个人账号资料已变化，需要重新核验。")
                attempt.status, attempt.message = "connected", "已复用并可信核验现有会话，无需重新登录或短信验证。"
                attempt.remember = bool(stored.get("credentials"))
                attempt.masked_account = "已连接账号"
                attempt.connected_binding = self.browser.vault.session_binding(profile)
                return
            except ConnectorError as error:
                if error.code == "IDENTITY_UNVERIFIED":
                    attempt.status, attempt.message = "identity_pending", "原登录资料的可信身份尚待核验，未重新提交密码或发送短信。"
                    await asyncio.Future()
                if error.code not in {"ERP_SESSION_REJECTED", "SESSION_EXPIRED", "LOGIN_REQUIRED"}:
                    raise
            if attempt.recovery_only:
                credentials = stored.get("credentials")
                if (not isinstance(credentials, dict) or credentials.get("terms_accepted") is not True
                        or not isinstance(credentials.get("username"), str) or not credentials["username"]
                        or not isinstance(credentials.get("password"), str) or not credentials["password"]):
                    attempt.status, attempt.message = "failed", "原会话已过期，请在本页重新登录；没有自动发送短信。"
                    return
                attempt.username, attempt.password = credentials["username"], credentials["password"]
                attempt.remember, attempt.terms_accepted = True, True
        attempt.status, attempt.message = "logging_in", "正在后台使用本人账号密码登录；仅ERP要求时才需要短信。"
        starts = self._history(self.password_history, profile, 300)
        if len(starts) >= 5 or (starts and time.monotonic() - starts[-1] < self.password_cooldown):
            attempt.status, attempt.message = "failed", "账号密码提交过于频繁，请稍后重试；取消后重开不会重置限制。"
            attempt.error_code = "LOGIN_RATE_LIMITED"
            return
        starts.append(time.monotonic())
        session = await self.browser._begin_password_login(profile, attempt)
        driver = self.driver_factory(session.page)
        revision = session.auth_revision
        self.browser._grant_login_action(session, "password")
        await driver.password(attempt.username, attempt.password, attempt.terms_accepted)
        if not attempt.remember:
            attempt.username = attempt.password = ""
        signal = await driver.outcome(session, revision)
        session.auth_remaining = 0
        while True:
            if signal == "authenticated":
                await self._finish(profile, attempt)
                return
            if signal in {"login_notice", "notice_unverified", "site_mismatch"}:
                attempt.status = "notice_pending"
                attempt.message = "ERP返回登录提示，正在核对已知的普通提示结构；不会重登、发短信或修改密码。"
                attempt.error_code = "LOGIN_NOTICE_PENDING"
                session.auth_remaining = 0
                session.auth_urls.clear()
                session.auth_deadline = 0
                if signal == "login_notice" and await driver.notice():
                    attempt.status, attempt.message = "verifying", "已确认普通登录提示，正在核验当前公司及员工。"
                    attempt.error_code = None
                    signal = "authenticated"
                    continue
                attempt.message = ("ERP提示需要切换登录站点，当前没有自动确认；本次会话暂存，等待核实。"
                                   if signal == "site_mismatch" else
                                   "ERP登录提示结构尚待核实；已暂存本次会话，不会重复提交密码、发短信或修改密码。")
                await asyncio.Future()  # Existing ten-minute attempt timeout/cancel owns cleanup.
            if signal not in {"need_code", "code_rejected", "code_sent", "send_rejected"}:
                code = "LOGIN_AUTH_REJECTED" if signal == "rejected" else "LOGIN_FLOW_TIMEOUT" if signal == "timeout" else "LOGIN_FLOW_UNADAPTED"
                raise ConnectorError(code, "ERP登录未通过或要求尚未适配的验证。")
            attempt.status = "need_code"
            attempt.message = "ERP明确要求短信验证，请本人点击发送并填写手机收到的验证码。"
            if signal == "code_sent":
                attempt.sent = True
                attempt.message = "ERP已确认验证码发送，请本人填写收到的短信。"
            elif signal == "code_rejected":
                attempt.message = "验证码未通过，请核对后手动重试；未自动重发短信。"
            elif signal == "send_rejected":
                attempt.sent = False
                attempt.message = "ERP未确认短信发送，请等待冷却后手动重试。"
            attempt.busy = False
            kind, code = await attempt.queue.get()
            revision = session.auth_revision
            if kind == "send":
                self.browser._grant_login_action(session, "send")
                await driver.send()
            else:
                try:
                    self.browser._grant_login_action(session, "code")
                    await driver.code(code)
                finally:
                    code = None
            signal = await driver.outcome(session, revision)
            session.auth_remaining = 0

    async def close(self):
        for profile in list(self.attempts):
            await self.cancel_login(profile)
