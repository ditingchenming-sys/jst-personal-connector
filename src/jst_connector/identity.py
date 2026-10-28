"""固定服务器当前用户核验；首次对照认证回执，恢复对照加密保存的身份。"""
from __future__ import annotations

import json
import re

from playwright.async_api import Error as PlaywrightError

from .adapters.login import ENTRY_URL
from .auth_receipt import PASSPORT_URL
from .errors import ConnectorError

GET_USER_INFO_URL = "https://api.erp321.com/erp/webapi/UserApi/Passport/GetUserInfo"
_POSITIVE_ID = re.compile(r"[1-9][0-9]{0,19}")
_MAX_BODY = 262144


def _identity_id(value):
    if type(value) not in (int, str) or _POSITIVE_ID.fullmatch(str(value)) is None:
        raise ConnectorError("IDENTITY_UNVERIFIED", "服务器身份字段格式未通过核验，业务调用已阻断。")
    return str(value)


def _expected_identity(session):
    if session.login:
        if (not session.controlled_login or not session.server_passport_receipted
                or session.server_identity_conflicted):
            raise ConnectorError("IDENTITY_UNVERIFIED", "本次认证回执缺失或有冲突，不能绑定公司和员工。")
        identity = session.server_identity_candidate
        for key, cookie in (("company_id", "u_co_id"), ("user_id", "u_id")):
            source = session.server_identity_sources.get(key, {})
            if (source.get("via") != "set-cookie" or source.get("cookie_name") != cookie
                    or (source.get("response_url"), source.get("method"))
                    not in {(PASSPORT_URL, "POST"), (ENTRY_URL, "GET")}):
                raise ConnectorError("IDENTITY_UNVERIFIED", "本次服务器签发的身份来源不完整，不能绑定账号。")
    else:
        if not isinstance(session.vault_binding, str) or not session.vault_binding:
            raise ConnectorError("IDENTITY_UNVERIFIED", "保存的身份缺少会话绑定，请重新核验。")
        identity = session.identity
    if not isinstance(identity, dict):
        raise ConnectorError("IDENTITY_UNVERIFIED", "缺少本次认证或加密保存的身份，业务调用已阻断。")
    return {key: _identity_id(identity.get(key)) for key in ("company_id", "user_id")}


def _display_name(value):
    if (not isinstance(value, str) or not value.strip() or len(value) > 512
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ConnectorError("IDENTITY_UNVERIFIED", "服务器当前用户资料格式未通过核验，业务调用已阻断。")
    return value.strip()


class ServerIdentityVerifier:
    """Installed-code-only adapter; accepts no model-supplied endpoint or identity."""

    async def verify_session(self, session):
        expected = _expected_identity(session)
        response = None
        try:
            response = await session.context.request.post(
                GET_USER_INFO_URL,
                data={"data": {}, "uid": int(expected["user_id"]), "coid": int(expected["company_id"])},
                headers={"Content-Type": "application/json", "Referer": ENTRY_URL},
                max_redirects=0, timeout=15000,
            )
            if response.url != GET_USER_INFO_URL:
                raise ConnectorError("IDENTITY_UNVERIFIED", "身份接口响应来源发生变化，业务调用已阻断。")
            if response.status in {301, 302, 303, 307, 308, 401, 403}:
                raise ConnectorError("ERP_SESSION_REJECTED", "聚水潭未接受当前登录态，请本人重新登录核实。")
            if response.status != 200:
                raise ConnectorError("IDENTITY_UNVERIFIED", "聚水潭当前用户接口读取未成功，业务调用已阻断。")
            body = await response.body()
            if len(body) > _MAX_BODY:
                raise ConnectorError("IDENTITY_UNVERIFIED", "身份接口响应超出已核实范围，业务调用已阻断。")
            value = json.loads(body)
            if (not isinstance(value, dict) or type(value.get("code")) is not int or value["code"] != 0
                    or type(value.get("act")) is not int or value["act"] != 0
                    or not isinstance(value.get("data"), dict)):
                raise ConnectorError("IDENTITY_UNVERIFIED", "服务器当前用户核验未通过，业务调用已阻断。")
            data = value["data"]
            if any(type(data.get(key)) is not int for key in ("coId", "uid")):
                raise ConnectorError("IDENTITY_UNVERIFIED", "服务器当前用户身份格式发生变化，业务调用已阻断。")
            actual = {"company_id": _identity_id(data.get("coId")), "user_id": _identity_id(data.get("uid"))}
            if actual != expected or _expected_identity(session) != expected:
                raise ConnectorError("IDENTITY_CHANGED", "聚水潭当前公司或员工与已绑定身份不一致，请退出后重新连接。")
            return {**actual, "company_name": _display_name(data.get("companyName")),
                    "user_name": _display_name(data.get("userName"))}
        except (PlaywrightError, OSError, TimeoutError, ValueError, UnicodeError):
            raise ConnectorError("IDENTITY_UNVERIFIED", "当前用户核验请求未完成，请稍后重新核验；未自动重新登录。") from None
        finally:
            if response is not None:
                try:
                    await response.dispose()
                except (PlaywrightError, OSError, TimeoutError):
                    raise ConnectorError("IDENTITY_UNVERIFIED", "身份核验响应未能安全完成，业务调用已阻断。") from None
