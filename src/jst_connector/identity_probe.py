"""本人管理端的固定只读身份来源取证；仅输出结构，不返回页面原文或身份值。"""
from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from playwright.async_api import Error as PlaywrightError

from .adapters import ORDER_URL, PURCHASE_URL
from .auth_receipt import _cookie, _identity_fields_in_header
from .browser import auth_response_schema
from .errors import ConnectorError

IDENTITY_FIELDS = {"uid", "u_id", "userid", "user_id", "coid", "co_id", "companyid", "company_id",
                   "u_co_id", "currentuser", "currentcompany", "userinfo", "user", "company"}
CONTEXT_FIELDS = IDENTITY_FIELDS | {"ownercoid", "owner_co_id", "authorizecoid", "authorize_co_id",
                                    "usercoid", "currentcoid", "username", "companyname", "coname",
                                    "authcoid", "maincoid", "logincoid", "usercompanyid"}
SCOPE_KEYS = {"userid", "ownercoid", "authorizecoid", "authcoid", "coid", "companyid", "maincoid",
              "usercoid", "currentcoid", "logincoid", "usercompanyid"}
STRUCTURE_IDENTIFIERS = CONTEXT_FIELDS | {"var", "let", "const", "function", "return", "if", "else",
                                         "true", "false", "null", "undefined", "this", "new", "window",
                                         "document", "cookie", "cookies", "getcookie", "readcookie", "get",
                                         "parseint", "number", "decodeuricomponent", "json", "parse"}
PUBLIC_SCRIPT_HOSTS = {"www.erp321.com", "src.erp321.com", "cdn.erp321.cn", "cdn-static.erp321.cn",
                       "g.alicdn.com"}
AUTH_COOKIE_NAMES = {"u_sso_token", "u_cid", ".ASPXAUTH", "ASP.NET_SessionId"}
CURRENT_USER_URL = "https://api.erp321.com/erp/webapi/UserApi/Passport/GetUserInfo"
CURRENT_USER_FIELDS = {"companyName", "isAdmin", "apps", "userName", "loginName", "id", "uid", "u_id",
                       "userId", "user_id", "coid", "coId", "co_id", "companyId", "company_id",
                       "name", "user", "company", "userInfo", "currentUser", "currentCompany"}


async def inspect_current_user_source(browser, profile):
    """Read the official header's fixed current-user endpoint; return schema only."""
    async with browser._lock(profile):
        session = browser._sessions.get(profile)
        attempt = browser._password_flows.attempts.get(profile)
        if (not session or not session.login or not attempt or attempt.session is not session
                or attempt.cancelled or attempt.status != "identity_pending"
                or time.monotonic() >= attempt.deadline):
            raise ConnectorError("IDENTITY_EVIDENCE_NOT_READY", "请先完成本人认证，再读取当前用户信息来源。")
        receipt = dict(session.server_identity_candidate)
        if (session.server_identity_conflicted or not session.server_passport_receipted
                or set(receipt) != {"company_id", "user_id"}
                or any(not isinstance(value, str) or not value.isdecimal() or int(value) <= 0
                       for value in receipt.values())):
            raise ConnectorError("IDENTITY_EVIDENCE_NOT_READY", "本次认证回执不完整，未调用当前用户信息接口。")
        response = None
        try:
            response = await session.context.request.post(
                CURRENT_USER_URL, data={"data": {}, "uid": int(receipt["user_id"]),
                                        "coid": int(receipt["company_id"])},
                timeout=10000, max_redirects=0)
            if (attempt.cancelled or attempt.status != "identity_pending"
                    or time.monotonic() >= attempt.deadline
                    or browser._sessions.get(profile) is not session):
                raise ConnectorError("LOGIN_CANCELLED", "本人会话已变化，未返回取证结果。")
            result = {"url": CURRENT_USER_URL, "http_status": response.status, "verified": False}
            raw = await response.body()
            if (attempt.cancelled or attempt.status != "identity_pending"
                    or time.monotonic() >= attempt.deadline
                    or browser._sessions.get(profile) is not session
                    or browser._password_flows.attempts.get(profile) is not attempt):
                raise ConnectorError("LOGIN_CANCELLED", "本人会话已变化，未返回取证结果。")
            if response.status != 200 or len(raw) > 262144:
                return result
            value = json.loads(raw)
            if not isinstance(value, dict):
                return result
            result["code_zero"] = type(value.get("code")) is int and value["code"] == 0
            result["act_zero"] = type(value.get("act")) is int and value["act"] == 0
            data = value.get("data")
            if isinstance(data, dict):
                result["data_schema"] = {
                    key: ("boolean" if type(item) is bool else "number" if isinstance(item, (int, float))
                          else "string" if isinstance(item, str) else "object" if isinstance(item, dict)
                          else "array" if isinstance(item, list) else "null")
                    for key, item in list(data.items())[:48]
                    if isinstance(key, str) and key in CURRENT_USER_FIELDS}
                result["ids_match_receipt"] = {
                    key: str(item) == receipt["user_id" if key.casefold() in {"uid", "u_id", "userid", "user_id"}
                                              else "company_id"]
                    for key, item in data.items()
                    if isinstance(key, str) and key.casefold() in
                    {"uid", "u_id", "userid", "user_id", "coid", "co_id", "companyid", "company_id"}
                    and type(item) in (int, str)}
            return result
        except (PlaywrightError, OSError, UnicodeError, ValueError):
            raise ConnectorError("IDENTITY_EVIDENCE_FAILED", "当前用户信息取证未完成，未返回原始响应。") from None
        finally:
            if response:
                await response.dispose()


def _receipt_matches(scope, receipt):
    result = {}
    for key, value in scope.items():
        field = "user_id" if key.casefold() == "userid" else "company_id"
        result[key] = value == receipt[field] if field in receipt else None
    return result


def _script_origin(src, base):
    try:
        parts = urlsplit(urljoin(base, src))
        if (parts.scheme == "https" and parts.hostname in PUBLIC_SCRIPT_HOSTS and parts.port in (None, 443)
                and not parts.username and not parts.password):
            return "https://" + parts.hostname
    except ValueError:
        pass
    return "[未核实脚本来源]"


def _structure_gap(gap):
    tokens = re.finditer(r"(?P<identifier>(?:[^\W\d]|\$)[\w$]*)|(?P<space>[ \t\r\n]+)|(?P<punct>[{}()\[\].,;:=+*!?&|<>%~^\-])|(?P<other>.)", gap, re.DOTALL)
    projected = []
    for token in tokens:
        if token.lastgroup == "identifier":
            projected.append(token[0] if token[0].casefold() in STRUCTURE_IDENTIFIERS else "[identifier]")
        elif token.lastgroup in {"space", "punct"}:
            projected.append(token[0])
        else:
            return None
    return "".join(projected)


def _redacted_identity_contexts(script):
    if any(marker in script for marker in ("`", "<!--", "-->")):
        return []
    pattern = r'''(?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(?P<comment>//[^\r\n]*|/\*.*?\*/)|(?P<number>\d+(?:\.\d+)?)'''
    pieces, previous = [], 0
    for match in re.finditer(pattern, script, re.DOTALL):
        gap = script[previous:match.start()]
        if any(marker in gap for marker in ('"', "'", "/")):
            return []  # An incomplete string is not safe to publish as a code fragment.
        projected = _structure_gap(gap)
        if projected is None:
            return []
        pieces.append(projected)
        if match.lastgroup == "string":
            value = match[0][1:-1]
            pieces.append(match[0] if value.casefold() in CONTEXT_FIELDS else '"[literal]"')
        elif match.lastgroup == "number":
            pieces.append("[number]")
        else:
            pieces.append(" ")
        previous = match.end()
    tail = script[previous:]
    if any(marker in tail for marker in ('"', "'", "/")):
        return []
    projected = _structure_gap(tail)
    if projected is None:
        return []
    text = "".join(pieces) + projected
    windows = []
    for match in re.finditer(r"\b(?:[A-Za-z_$]*(?:UserId|CoId|CompanyId|co_id|user_id|u_id|u_co_id|UserInfo|CurrentUser)[A-Za-z_$]*)\b", text, re.IGNORECASE):
        windows.append(text[max(0, match.start() - 180):match.end() + 230])
        if len(windows) >= 12:
            break
    return windows


def page_identity_structure(html: str, url: str) -> dict:
    class Structure(HTMLParser):
        def __init__(self):
            super().__init__()
            self.sources, self.controls, self.scripts = [], [], []
            self.in_script = False

        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            if tag == "script":
                self.in_script = True
                if attrs.get("src") and len(self.sources) < 60:
                    self.sources.append(_script_origin(attrs["src"], url))
            if tag == "input":
                name = attrs.get("id") or attrs.get("name") or ""
                if name.casefold() in IDENTITY_FIELDS and len(self.controls) < 30:
                    kind = attrs.get("type", "text")
                    self.controls.append({"name": name, "type": kind if kind in {"hidden", "text", "number"}
                                          else "other",
                                          "has_value": "value" in attrs})

        def handle_endtag(self, tag):
            if tag == "script":
                self.in_script = False

        def handle_data(self, data):
            if self.in_script and len(self.scripts) < 100 and len(data) <= 100000:
                self.scripts.append(data)

    parser = Structure()
    parser.feed(html)
    candidates, contexts = [], []
    for script in parser.scripts:
        if len(contexts) < 12:
            contexts.extend(_redacted_identity_contexts(script)[:12 - len(contexts)])
        for match in re.finditer(r"(?:var|let|const|window\.)\s*([A-Za-z_$][\w$]{0,63})\s*=\s*(\{[^;]{1,20000}\})\s*;", script):
            try:
                value = json.loads(match[2])
            except ValueError:
                continue
            if isinstance(value, dict) and {str(key).casefold() for key in value} & IDENTITY_FIELDS:
                candidates.append({"kind": "server_script_object", "schema": auth_response_schema(value)})
                if len(candidates) >= 30:
                    break
        for match in re.finditer(r"(?:var|let|const|window\.)\s*([A-Za-z_$][\w$]{0,63})\s*=\s*(-?\d+|\"[^\"\r\n]*\"|'[^'\r\n]*')\s*;", script):
            if match[1].casefold() in IDENTITY_FIELDS and len(candidates) < 30:
                candidates.append({"kind": "server_script_scalar", "name": match[1],
                                   "type": "string" if match[2][0] in "\"'" else "number"})
    return {"script_sources": parser.sources, "identity_controls": parser.controls,
            "identity_candidates": candidates[:30], "redacted_identity_contexts": contexts}


def _private_bootstrap_scopes(html):
    """Candidate numbers stay internal; this does not assert their business meaning."""
    results = []
    for match in re.finditer(r"(?:var|let|const|window\.)\s*[A-Za-z_$][\w$]{0,63}\s*=\s*(\{[^;]{1,20000}\})\s*;", html):
        try:
            value = json.loads(match[1])
        except ValueError:
            continue
        if not isinstance(value, dict) or len(value) > 32 or "UserId" not in value or "OwnerCoId" not in value:
            continue
        if any(type(item) not in (int, float, list) for item in value.values()):
            continue
        fields = {key: str(number) for key, number in value.items() if key.casefold() in SCOPE_KEYS
                  and type(number) is int and number >= 0}
        if fields and len(results) < 8:
            results.append(fields)
    return results


async def _set_cookie_headers(response):
    if hasattr(response, "header_values"):
        return await response.header_values("set-cookie")
    headers = getattr(response, "headers_array", [])
    return [header["value"] for header in headers if header.get("name", "").casefold() == "set-cookie"]


async def _session_grant_contrasts(browser, session, attempt, original_scopes=None):
    """Fixed GETs in disposable contexts; never mutate the actual login or publish cookie values."""
    expected = getattr(session, "server_identity_candidate", {})
    if (not getattr(session, "server_passport_receipted", False)
            or getattr(session, "server_identity_conflicted", False)
            or not hasattr(session.context, "cookies") or not hasattr(browser, "_new_context")):
        return {"ready": False, "reason": "同一次受控认证授权链尚未取得。"}
    cookies = await session.context.cookies([PURCHASE_URL])
    if len({cookie.get("name") for cookie in cookies}) != len(cookies):
        return {"ready": False, "reason": "当前凭证集合存在作用域歧义，未进行对照。"}
    selected = [cookie for cookie in cookies
                if cookie.get("name") in {"u_sso_token", "u_cid", "u_id", "u_co_id"}]
    fields = {cookie["name"]: cookie for cookie in selected}
    if len(fields) != len(selected):
        return {"ready": False, "reason": "当前授权字段存在作用域歧义，未进行对照。"}
    if not fields.get("u_sso_token", {}).get("value"):
        return {"ready": False, "reason": "已知SSO凭证字段尚未取得。"}
    if any(fields.get(cookie, {}).get("value") != expected[field]
           for cookie, field in (("u_id", "user_id"), ("u_co_id", "company_id")) if field in expected):
        return {"ready": False, "reason": "当前身份字段与认证回执不一致，未进行对照。"}
    variants = (("identity_only", {"u_id", "u_co_id"}), ("sso_only", {"u_sso_token"}),
                ("opaque_only", {"u_sso_token", "u_cid"}),
                ("opaque_and_identity", {"u_sso_token", "u_cid", "u_id", "u_co_id"}),
                ("grant_without_identity", {cookie["name"] for cookie in cookies} - {"u_id", "u_co_id"}),
                ("full_grant", {cookie["name"] for cookie in cookies}))
    results = []
    for kind, names in variants:
        if (attempt.cancelled or attempt.status != "identity_pending"
                or time.monotonic() >= getattr(attempt, "deadline", float("inf"))):
            raise ConnectorError("LOGIN_CANCELLED", "认证状态已变化，未继续只读对照。")
        context, response = None, None
        try:
            context = await browser._new_context({"cookies": [dict(cookie) for cookie in cookies
                                                              if cookie["name"] in names], "origins": []})
            if (attempt.cancelled or attempt.status != "identity_pending"
                    or time.monotonic() >= getattr(attempt, "deadline", float("inf"))):
                raise ConnectorError("LOGIN_CANCELLED", "认证状态已变化，未发起新的只读对照。")
            response = await context.request.get(PURCHASE_URL, timeout=5000, max_redirects=0)
            result = {"kind": kind, "http_status": response.status}
            issued, duplicate, rejected = {}, False, False
            if response.status == 200:
                text = await response.text()
                result["legacy_form_present"] = (len(text) <= 2_000_000 and "__VIEWSTATE" in text
                                                  and "JTable1" in text)
                scopes = _private_bootstrap_scopes(text) if len(text) <= 2_000_000 else []
                result["bootstrap_scope_fields"] = [sorted(scope) for scope in scopes]
                result["bootstrap_matches_original"] = (scopes == original_scopes) if scopes and original_scopes else None
                result["bootstrap_positive_fields"] = [sorted(key for key, value in scope.items()
                                                                if int(value) > 0) for scope in scopes]
                result["bootstrap_matches_auth_receipt"] = [
                    _receipt_matches(scope, expected) for scope in scopes] if expected else None
                for header in await _set_cookie_headers(response):
                    receipt = _cookie(header, PURCHASE_URL, datetime.now(UTC))
                    if receipt:
                        field, value, _ = receipt
                        if field in issued:
                            duplicate = True
                        issued[field] = value
                    elif _identity_fields_in_header(header):
                        rejected = True
            result["server_identity_cookie_fields"] = sorted(issued)
            result["server_receipt_matches_login"] = (not duplicate and not rejected and issued == {
                "u_id": expected["user_id"], "u_co_id": expected["company_id"]}) if issued and set(expected) == {"company_id", "user_id"} else None
            results.append(result)
        except (PlaywrightError, OSError, UnicodeError):
            results.append({"kind": kind, "message": "固定只读对照未取得响应。"})
        finally:
            try:
                if response:
                    await response.dispose()
            finally:
                if context:
                    await context.close()
    return {"ready": True, "results": results, "verified": False}


async def inspect_identity_sources(browser, profile: str) -> dict:
    async with browser._lock(profile):
        session = browser._sessions.get(profile)
        attempt = browser._password_flows.attempts.get(profile)
        if (not session or not session.login or not attempt or attempt.session is not session
                or attempt.cancelled or attempt.status != "identity_pending"):
            raise ConnectorError("IDENTITY_EVIDENCE_NOT_READY", "请先完成本人认证，再核对当前身份来源。")
        results, original_scopes = [], []
        for url in (PURCHASE_URL, ORDER_URL):
            response = None
            try:
                response = await session.context.request.get(url, timeout=10000, max_redirects=0)
                if attempt.cancelled or attempt.status != "identity_pending":
                    raise ConnectorError("LOGIN_CANCELLED", "本人认证已取消，未返回身份取证结果。")
                result = {"url": url, "http_status": response.status}
                headers = await _set_cookie_headers(response)
                result["identity_cookie_header_names"] = sorted({header.partition("=")[0].strip()
                                                                     for header in headers
                                                                     if header.partition("=")[0].strip()
                                                                     in {"u_id", "u_co_id"}})
                if response.status == 200:
                    text = await response.text()
                    if len(text) <= 2_000_000:
                        result.update(page_identity_structure(text, url))
                        if url == PURCHASE_URL:
                            original_scopes = _private_bootstrap_scopes(text)
                            result["bootstrap_scope_fields"] = [sorted(scope) for scope in original_scopes]
                            result["bootstrap_positive_fields"] = [sorted(key for key, value in scope.items()
                                                                          if int(value) > 0) for scope in original_scopes]
                            receipt_ids = getattr(session, "server_identity_candidate", {})
                            result["bootstrap_matches_auth_receipt"] = [
                                _receipt_matches(scope, receipt_ids) for scope in original_scopes] if receipt_ids else None
                    else:
                        result["message"] = "页面过大，仅保留状态，未返回页面内容。"
                results.append(result)
            except (PlaywrightError, OSError, UnicodeError):
                results.append({"url": url, "message": "固定只读页面未取得，未转发请求或返回页面原文。"})
            finally:
                if response:
                    await response.dispose()
        if (attempt.cancelled or attempt.status != "identity_pending"
                or browser._sessions.get(profile) is not session
                or browser._password_flows.attempts.get(profile) is not attempt):
            raise ConnectorError("LOGIN_CANCELLED", "本人认证会话已变化，身份取证结果已作废。")
        auth_names = []
        if hasattr(session.context, "cookies"):
            cookies = await session.context.cookies(["https://www.erp321.com/epaas"])
            auth_names = sorted({cookie.get("name") for cookie in cookies if cookie.get("name") in AUTH_COOKIE_NAMES})
        if attempt.cancelled or attempt.status != "identity_pending":
            raise ConnectorError("LOGIN_CANCELLED", "本人认证已取消，身份取证结果已作废。")
        receipt = getattr(session, "server_identity_candidate", {})
        contrasts = await _session_grant_contrasts(browser, session, attempt, original_scopes)
        if attempt.cancelled or attempt.status != "identity_pending":
            raise ConnectorError("LOGIN_CANCELLED", "认证状态已变化，对照结果已作废。")
        return {"sources": results, "verified": False, "auth_cookie_presence": auth_names,
                "server_receipt_field_presence": sorted(name for name in ("company_id", "user_id") if name in receipt),
                "server_receipt_conflicted": bool(getattr(session, "server_identity_conflicted", False)),
                "grant_contrasts": contrasts,
                "message": "仅为服务器页面身份来源线索，未据此设置账号或公司身份。"}
