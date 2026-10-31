"""隔离、受限的ERP页面探索；未知请求只截获，模板执行仅供已审核注册器内部调用。"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import ipaddress
import json
import re
import socket
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit, urlunsplit
from uuid import uuid4

import httpx
from playwright.async_api import Error as PlaywrightError

from .adapters import ORDER_URL, PURCHASE_URL
from .adapters.login import ENTRY_URL
from .browser import ERP_HOSTS, approved_request, safe_url
from .errors import ConnectorError
from .interface_registry import _AUTH_PATH, _operation_kind

_ASSET_HOSTS = {"src.erp321.com", "cdn.erp321.cn", "cdn-static.erp321.cn"}
_ASSET_SUFFIX = re.compile(r"\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf)$", re.IGNORECASE)
_SECRET = re.compile(r"pass|pwd|cookie|authorization|token|secret|credential|session|viewstate|eventvalidation|nonce|csrf|xsrf|captcha|ticket|signature|api.?key", re.IGNORECASE)
_IDENTITIES = {"uid": "user_id", "user_id": "user_id", "userid": "user_id", "u_id": "user_id",
               "coid": "company_id", "co_id": "company_id", "company_id": "company_id", "companyid": "company_id", "u_co_id": "company_id",
               "owner_co_id": "company_id", "authorize_co_id": "company_id", "ownercoid": "company_id", "authorizecoid": "company_id"}
_HEADERS = {"content-type": "Content-Type", "x-requested-with": "X-Requested-With", "action-name": "Action-Name"}
_NAVIGATION = {ENTRY_URL, PURCHASE_URL, ORDER_URL}
_SYNTHETIC_PROXY = ipaddress.ip_network("198.18.0.0/15")


def _error(code="DISCOVERY_REJECTED", message="探索请求不在已审核范围内，已阻断。", *, details=None):
    return ConnectorError(code, message, details=details)


def _erp_url(url):
    if not isinstance(url, str):
        return False
    try:
        parts = urlsplit(url)
        return bool(isinstance(url, str) and parts.scheme == "https" and parts.netloc in ERP_HOSTS
                    and parts.hostname == parts.netloc and not parts.username and not parts.password
                    and parts.port is None and not parts.fragment and parts.path.startswith("/")
                    and "\\" not in parts.path and "%" not in parts.path and ".." not in parts.path.split("/"))
    except (ValueError, TypeError):
        return False


def _page_url(url):
    if not _erp_url(url):
        return False
    parts = urlsplit(url)
    if (_AUTH_PATH.search(parts.path) or re.search(r"logout|logoff|signout|signoff", parts.path, re.IGNORECASE)
            or any(_operation_kind(part.split(".", 1)[0]) == "write" for part in parts.path.split("/") if part)):
        return False
    return (not parts.query and (url in _NAVIGATION or parts.path.lower().endswith((".aspx", ".html", ".htm"))))


def _asset_url(url):
    try:
        parts = urlsplit(url)
        return bool(parts.scheme == "https" and parts.netloc in _ASSET_HOSTS and not parts.fragment
                    and (parts.netloc != "cdn-static.erp321.cn" or parts.path.startswith("/cdn/"))
                    and not parts.username and not parts.password and _ASSET_SUFFIX.search(parts.path)
                    and "\\" not in parts.path and ".." not in parts.path.split("/")
                    and all(not _SECRET.search(key) for key in parse_qs(parts.query)))
    except (ValueError, TypeError):
        return False


def _text(value, limit=5000):
    value = str(value)[:limit]
    value = re.sub(r"(?i)(?:bearer\s+)[A-Za-z0-9._~-]+", "[已脱敏]", value)
    return re.sub(r'''(?i)(["']?(?:password|cookie|authorization|token|secret|u_cid|u_sso_token)["']?\s*[:=]\s*)["'][^"'\r\n]*["']''', r'\1"[已脱敏]"', value)


def _pointer(name):
    return str(name).replace("~", "~0").replace("/", "~1")


def _scrub(value, path, bindings, removed, *, depth=0):
    if depth > 10:
        raise _error(message="请求结构过深，需单独适配。")
    if isinstance(value, dict):
        if len(value) > 100:
            raise _error(message="请求字段过多，需缩小探索范围。")
        result = {}
        for key, item in value.items():
            key = str(key)
            target = path + "/" + _pointer(key)
            kind = _IDENTITIES.get(key.lower())
            if key == "__ajax_token":
                bindings.append({"path": target, "kind": "u_cid_ajax", "value_type": "string"})
                result[key] = None
            elif kind:
                if isinstance(item, list):
                    result[key] = [None]
                    target += "/0"
                    item = item[0] if item else ""
                else:
                    result[key] = None
                bindings.append({"path": target, "kind": kind, "value_type": "number" if type(item) is int else "string"})
            elif _SECRET.search(key):
                removed.append(target)
            else:
                result[key] = _scrub(item, target, bindings, removed, depth=depth + 1)
        return result
    if isinstance(value, list):
        if len(value) > 100:
            raise _error(message="请求数组过长，需缩小探索范围。")
        return [_scrub(item, path + "/" + str(index), bindings, removed, depth=depth + 1)
                for index, item in enumerate(value)]
    if value is None or type(value) in (bool, int, float, str):
        if isinstance(value, str) and len(value) > 10000:
            raise _error(message="请求字段超出已核实范围，需单独适配。")
        if isinstance(value, str):
            try:
                serialized = json.loads(value)
            except ValueError:
                serialized = None
            if isinstance(serialized, (dict, list)):
                removed.append(path)
                return None  # Only the explicitly decoded __CALLBACKPARAM encoding is supported.
        return value
    raise _error(message="请求编码尚未适配。")


def _schema(value):
    if isinstance(value, dict):
        return {key: _schema(item) for key, item in value.items()}
    if isinstance(value, list):
        return "array"
    return "null" if value is None else "boolean" if type(value) is bool else "number" if type(value) in (int, float) else "string"


def _safe_headers(headers):
    result = {}
    for key, value in headers.items():
        target = _HEADERS.get(key.lower())
        if not target or not isinstance(value, str) or len(value) > 128 or "\r" in value or "\n" in value:
            continue
        if target == "Content-Type" and value.split(";", 1)[0].lower() not in {"application/json", "application/x-www-form-urlencoded"}:
            continue
        if target != "Content-Type" and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,99}", value) is None:
            continue
        result[target] = value
    return result


async def _public_destination(url):
    if not (_erp_url(url) or _asset_url(url)):
        raise _error(message="目标不属于固定官方HTTPS域名，已阻断。",
                     details={"stage": "dns_policy", "dns_policy": "host_not_allowed"})
    try:
        records = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
            urlsplit(url).hostname, 443, type=socket.SOCK_STREAM), timeout=5)
        addresses = [ipaddress.ip_address(record[4][0]) for record in records]
        # This fixed range is a DNS synthetic mapping used by the deployment's
        # HTTPS proxy. Keep the original audited hostname/SNI and TLS verification.
        if not addresses or any(not address.is_global and address not in _SYNTHETIC_PROXY for address in addresses):
            raise _error(message="目标解析到不允许的网络地址，已阻断。",
                         details={"stage": "dns_policy", "dns_policy": "rejected_address"})
        return "synthetic_proxy" if any(address in _SYNTHETIC_PROXY for address in addresses) else "public"
    except (OSError, ValueError, TimeoutError):
        raise _error(message="目标网络地址未能验证，已阻断。",
                     details={"stage": "dns_policy", "dns_policy": "resolution_failed"}) from None


class _References(HTMLParser):
    def __init__(self, base):
        super().__init__()
        self.base, self.pages = base, set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        target = urljoin(self.base, attrs.get("src" if tag == "iframe" else "href", ""))
        if tag in {"iframe", "a"} and _page_url(target):
            self.pages.add(target)


@dataclass
class _Discovery:
    discovery_id: str
    profile: str
    context: object
    page: object
    identity: dict
    binding: str
    persisted_binding: str
    pages: set = field(default_factory=set)
    refs: dict = field(default_factory=dict, repr=False)
    requests: dict = field(default_factory=dict, repr=False)
    sources: dict = field(default_factory=dict, repr=False)
    diagnostics: list = field(default_factory=list, repr=False)
    source_bytes: int = 0
    touched: float = field(default_factory=time.monotonic)


class DiscoveryBrowser:
    def __init__(self, browser, *, anonymous_fetch=None):
        self.browser = browser
        self._discoveries = {}
        self._anonymous_fetch = anonymous_fetch or self._fetch_public
        browser.add_profile_cleanup(self.close_profile)

    def _check(self, discovery):
        session = self.browser._sessions.get(discovery.profile)
        if (self._discoveries.get(discovery.discovery_id) is not discovery or session is None or not session.verified
                or session.binding != discovery.binding or session.identity != discovery.identity
                or self.browser.vault.session_binding(discovery.profile) != discovery.persisted_binding):
            raise _error("DISCOVERY_SESSION_CHANGED", "探索期间账号会话发生变化，请重新开始；旧结果已失效。")

    @asynccontextmanager
    async def _scope(self, profile, discovery_id):
        discovery = self._discoveries.get(discovery_id)
        if discovery is None or discovery.profile != profile:
            raise _error("DISCOVERY_NOT_FOUND", "探索编号无效或不属于当前调用端。")
        try:
            async with self.browser.verified_scope(profile):
                self._check(discovery)
                discovery.touched = time.monotonic()
                yield discovery
                self._check(discovery)
        except ConnectorError as error:
            if error.code in {"DISCOVERY_SESSION_CHANGED", "QUERY_SESSION_CHANGED", "IDENTITY_CHANGED", "LOGIN_REQUIRED", "ERP_SESSION_REJECTED"}:
                await self.close_profile(profile)
            raise

    async def start(self, profile, url=ENTRY_URL, *, entry_approved=False, expected_binding=None):
        if not _page_url(url) or (url not in _NAVIGATION and entry_approved is not True):
            raise _error("DISCOVERY_ENTRY_APPROVAL_REQUIRED", "该页面入口尚未批准，请先由本人在管理页确认精确入口。")
        try:
            async with self.browser.verified_scope(profile) as identity:
                session = self.browser._sessions[profile]
                if ((expected_binding is not None and expected_binding != session.vault_binding)
                        or (url not in _NAVIGATION and not expected_binding)):
                    raise _error("DISCOVERY_SESSION_CHANGED", "入口审批对应的账号会话已变化，请重新批准。")
                await self.close_profile(profile)
                state = await session.context.storage_state()
                self.browser._assert_scope(profile, session, identity)
                context = await self.browser._new_context(state)
                if context is session.context:
                    raise _error(message="探索必须使用独立上下文，不能复用主登录页面。")
                page = await context.new_page()
                discovery = _Discovery(uuid4().hex, profile, context, page, dict(identity), session.binding,
                                       session.vault_binding, pages={url})
                self._discoveries[discovery.discovery_id] = discovery
                phase = "route_setup"
                try:
                    self._check(discovery)
                    await context.route("**/*", lambda route: self._route(discovery, route))
                    await context.route_web_socket("**/*", lambda socket: socket.close(code=1008, reason="探索模式禁止WebSocket"))
                    context.on("page", lambda popup: popup.close() if popup is not page else None)
                    page.on("download", lambda download: download.cancel())
                    phase = "navigate"
                    await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                    phase = "snapshot"
                    result = await self._snapshot(discovery)
                    self._check(discovery)
                    return result
                except ConnectorError:
                    self._discoveries.pop(discovery.discovery_id, None)
                    await context.close()
                    raise
                except (PlaywrightError, OSError):
                    self._discoveries.pop(discovery.discovery_id, None)
                    await context.close()
                    details = {"stage": phase, "diagnostics": list(discovery.diagnostics)}
                    dns = next((item for item in reversed(discovery.diagnostics) if item.get("stage") == "dns_policy"), None)
                    if dns:
                        details.update(stage="dns_policy", dns_policy=dns["dns_policy"])
                    raise _error("DISCOVERY_PAGE_FAILED", "探索页面未能安全呈现，请查看安全诊断中的失败阶段。", details=details) from None
        except ConnectorError:
            await self.close_profile(profile)
            raise

    def _capture(self, discovery, request, *, blocked):
        if len(discovery.requests) >= 100:
            return
        parts = urlsplit(request.url)
        headers = _safe_headers(request.headers)
        encoding, body, json_fields = "none", None, []
        raw = request.post_data
        if raw:
            if len(raw) > 262144:
                return
            content_type = headers.get("Content-Type", "").split(";", 1)[0].lower()
            try:
                if content_type == "application/json":
                    body, encoding = json.loads(raw), "json"
                elif content_type == "application/x-www-form-urlencoded":
                    body = {key: items[0] if len(items) == 1 else items for key, items in parse_qs(raw, keep_blank_values=True).items()}
                    encoding = "form"
                    if "__CALLBACKPARAM" in body:
                        body["__CALLBACKPARAM"] = json.loads(body["__CALLBACKPARAM"])
                        json_fields.append("/body/__CALLBACKPARAM")
                else:
                    return
            except (ValueError, TypeError):
                return
        if body is not None and not isinstance(body, dict):
            return
        bindings, removed = [], []
        try:
            query = _scrub(parse_qs(parts.query, keep_blank_values=True), "/query", bindings, removed)
            body = _scrub(body, "/body", bindings, removed)
        except ConnectorError:
            return
        request_id = uuid4().hex[:16]
        discovery.requests[request_id] = {"request_id": request_id,
            "url": urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")), "method": request.method,
            "encoding": encoding, "query": query, "body": body, "headers": headers,
            "source": {"page_url": safe_url(request.frame.url), "discovery_id": discovery.discovery_id,
                       "resource_type": request.resource_type, "blocked": blocked, "credential_fields": removed},
            "identity_bindings": bindings, "json_fields": json_fields}
        discovery.requests[request_id]["_scope"] = {"profile": discovery.profile, "identity": dict(discovery.identity),
                                                    "session_binding": discovery.persisted_binding}

    @staticmethod
    async def _fetch_public(url):
        await _public_destination(url)
        async with (httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=15) as client,
                    client.stream("GET", url, headers={"Accept": "*/*"}) as response):
                if response.status_code != 200 or str(response.url) != url:
                    raise _error(message="公开资源读取未成功，未跟随重定向。")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 2000000:
                        raise _error(message="公开资源超出本次取证范围。")
                content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
        return {"status": response.status_code, "url": str(response.url), "body": bytes(body), "content_type": content_type}

    async def _asset(self, discovery, url):
        if not _asset_url(url):
            raise _error(message="该地址不是已核实公共静态资源域及文件。")
        if url in discovery.sources:
            return discovery.sources[url]
        if len(discovery.sources) >= 32 or discovery.source_bytes >= 8000000:
            raise _error(message="公开资源取证已达本次上限，请缩小页面范围。")
        response = await self._anonymous_fetch(url)
        body, content_type = response["body"], response["content_type"]
        if (response.get("status") != 200 or response.get("url") != url or not isinstance(body, bytes)
                or len(body) > 2000000 or discovery.source_bytes + len(body) > 8000000):
            raise _error(message="公开静态响应超出已核实范围。")
        suffix = urlsplit(url).path.lower()
        if ((suffix.endswith(".js") and content_type not in {"application/javascript", "text/javascript"})
                or (suffix.endswith(".css") and content_type != "text/css")
                or (not suffix.endswith((".js", ".css")) and not content_type.startswith(("image/", "font/", "application/font", "application/octet-stream")))):
            raise _error(message="公开资源类型与已核实静态文件不符，已阻断。")
        source = {"source_id": uuid4().hex[:16], "url": url, "body": bytes(body),
                  "content_type": content_type, "sha256": hashlib.sha256(body).hexdigest()}
        discovery.sources[url] = source
        discovery.source_bytes += len(body)
        return source

    async def _route(self, discovery, route):
        request = route.request
        response = None
        phase = "scope_check"
        try:
            self._check(discovery)
            if request.method == "GET" and _asset_url(request.url):
                phase = "anonymous_asset"
                source = await self._asset(discovery, request.url)
                self._check(discovery)
                await route.fulfill(status=200, body=source["body"], content_type=source["content_type"],
                                    headers={"Access-Control-Allow-Origin": "*"})
            elif request.method == "GET" and request.resource_type == "document" and request.url in discovery.pages:
                phase = "document_policy"
                if not _page_url(request.url):
                    raise _error(message="认证、登出或已知写动作不能作为探索页面。")
                await _public_destination(request.url)
                self._check(discovery)
                phase = "document_fetch"
                response = await route.fetch(max_redirects=0, timeout=30000)
                phase = "document_response"
                if (response.status != 200 or response.url != request.url
                        or "text/html" not in response.headers.get("content-type", "").lower()
                        or "attachment" in response.headers.get("content-disposition", "").lower()):
                    raise _error(message="页面响应不符合已批准HTML入口，已阻断。")
                body = await response.body()
                if len(body) > 2000000:
                    raise _error(message="探索页面超出本次范围。")
                parser = _References(request.url)
                parser.feed(body.decode("utf-8", errors="replace"))
                discovery.pages.update(parser.pages)
                self._check(discovery)
                await route.fulfill(response=response)
            else:
                phase = "request_capture"
                payload = None
                try:
                    payload = request.post_data_json
                except (PlaywrightError, ValueError):
                    if request.post_data:
                        payload = {key: values[0] for key, values in parse_qs(request.post_data).items()}
                approved = approved_request(request.method, request.url, payload)
                self._capture(discovery, request, blocked=not approved)
                if approved:
                    result = await self.browser.request(discovery.profile, request.method, request.url, payload)
                    self._check(discovery)
                    await route.fulfill(status=result["status"], body=result["text"], content_type="application/json")
                else:
                    await route.abort("blockedbyclient")
        except (ConnectorError, PlaywrightError, OSError, httpx.HTTPError) as error:
            diagnostic = {"stage": phase,
                          "url": safe_url(request.url) if _erp_url(request.url) or _asset_url(request.url) else "[未审核地址]",
                          "failure": "policy_rejected" if isinstance(error, ConnectorError) else "transport_failed"}
            if isinstance(error, ConnectorError) and error.details.get("stage") == "dns_policy":
                diagnostic.update(stage="dns_policy", dns_policy=error.details["dns_policy"])
            if response is not None:
                diagnostic["http_status"] = response.status
            discovery.diagnostics.append(diagnostic)
            discovery.diagnostics[:] = discovery.diagnostics[-30:]
            await route.abort("blockedbyclient")
        finally:
            if response is not None:
                await response.dispose()

    async def _snapshot(self, discovery):
        old_handles = [reference[0] for reference in discovery.refs.values()]
        discovery.refs.clear()
        await asyncio.gather(*(handle.dispose() for handle in old_handles), return_exceptions=True)
        frames = []
        for frame in discovery.page.frames[:12]:
            if not _page_url(frame.url):
                continue
            elements = []
            locator = frame.locator("a,button,input,select,textarea,[role=button],[role=menuitem],[role=tab],[onclick],iframe,script[src]")
            for index in range(min(await locator.count(), 150)):
                element = await locator.nth(index).element_handle(timeout=500)
                tag = await element.evaluate("element=>element.tagName.toLowerCase()")
                kind = (await element.get_attribute("type") or "").lower()
                name = await element.get_attribute("name") or ""
                if tag == "script":
                    url = urljoin(frame.url, await element.get_attribute("src") or "")
                    source = discovery.sources.get(url)
                    if source:
                        elements.append({"tag": tag, "source_id": source["source_id"], "url": safe_url(url), "sha256": source["sha256"]})
                    await element.dispose()
                    continue
                if kind in {"hidden", "password", "file"} or _SECRET.search(name) or not await element.is_visible():
                    await element.dispose()
                    continue
                reference = uuid4().hex[:12]
                target = urljoin(frame.url, await element.get_attribute("src" if tag == "iframe" else "href") or "") if tag in {"a", "iframe"} else ""
                metadata = {"tag": tag, "type": kind, "name": name, "frame_url": frame.url, "target": target}
                discovery.refs[reference] = (element, frame, metadata, time.monotonic() + 60)
                item = {"element_ref": reference, "tag": tag, "type": kind, "name": name,
                        "label": _text(await element.get_attribute("aria-label") or await element.get_attribute("placeholder")
                                       or (await element.inner_text() if tag not in {"input", "textarea", "iframe"} else ""), 200)}
                if tag == "select":
                    item["options"] = [_text(await option.text_content() or "", 100)
                                       for option in (await element.query_selector_all("option"))[:50]]
                if tag in {"a", "iframe"} and _page_url(target):
                    item["url"] = target
                    discovery.pages.add(target)
                elements.append(item)
            frames.append({"url": safe_url(frame.url), "text": _text(await frame.locator("body").inner_text(timeout=2000)), "elements": elements})
        return {"discovery_id": discovery.discovery_id, "url": safe_url(discovery.page.url), "frames": frames,
                "request_count": len(discovery.requests), "message": "未知请求已先行拦截；元素引用60秒有效，更新页面后需重新读取。"}

    async def inspect(self, profile, discovery_id, kind="page", reference="", search="", offset=0):
        if type(offset) is not int or offset < 0 or not isinstance(search, str) or len(search) > 100:
            raise _error(message="探索分页或搜索条件无效。")
        async with self._scope(profile, discovery_id) as discovery:
            if kind == "page":
                return await self._snapshot(discovery)
            if kind == "requests":
                requests = [{"request_id": item["request_id"], "url": safe_url(item["url"]), "method": item["method"],
                             "encoding": item["encoding"], "query_schema": _schema(item["query"]), "body_schema": _schema(item["body"]),
                             "header_names": sorted(item["headers"]),
                             "source": item["source"], "identity_bindings": item["identity_bindings"]}
                            for item in discovery.requests.values()]
                requests = [item for item in requests if search.lower() in json.dumps(item, ensure_ascii=False).lower()]
                return {"requests": requests[offset:offset + 30], "total": len(requests), "has_more": offset + 30 < len(requests)}
            if kind == "source":
                if not reference:
                    sources = [{"source_id": item["source_id"], "url": safe_url(item["url"]), "sha256": item["sha256"],
                                "bytes": len(item["body"])} for item in discovery.sources.values()
                               if urlsplit(item["url"]).path.lower().endswith(".js") and search.lower() in item["url"].lower()]
                    return {"sources": sources[offset:offset + 30], "total": len(sources), "has_more": offset + 30 < len(sources)}
                source = next((item for item in discovery.sources.values() if item["source_id"] == reference), None)
                if source is None or not urlsplit(source["url"]).path.lower().endswith(".js"):
                    raise _error(message="公开脚本引用无效；不能输入任意URL读取。")
                text = _text(source["body"].decode("utf-8", errors="replace"), 2000000)
                if search:
                    offset = text.lower().find(search.lower(), offset)
                    if offset < 0:
                        return {"source_id": reference, "found": False, "sha256": source["sha256"]}
                return {"source_id": reference, "url": source["url"], "sha256": source["sha256"], "offset": offset,
                        "text": text[offset:offset + 4000], "has_more": offset + 4000 < len(text)}
            raise _error(message="仅支持page、requests、source三种探索视图。")

    async def interact(self, profile, discovery_id, element_ref, action, value=""):
        if not isinstance(value, str) or len(value) > 1000:
            raise _error(message="探索输入格式或长度无效。")
        async with self._scope(profile, discovery_id) as discovery:
            reference = discovery.refs.get(element_ref)
            if reference is None or time.monotonic() >= reference[3]:
                raise _error("DISCOVERY_REF_EXPIRED", "元素引用已失效，请重新读取页面。")
            element, frame, metadata, _ = reference
            if frame.url != metadata["frame_url"] or not await element.is_visible():
                raise _error("DISCOVERY_REF_EXPIRED", "页面结构已变化，请重新读取页面。")
            try:
                if action == "navigate" or (action == "click" and metadata["tag"] == "a"):
                    if metadata["tag"] not in {"a", "iframe"} or not _page_url(metadata["target"]):
                        raise _error(message="该引用不是已观察到的无参数ERP页面入口。")
                    discovery.pages.add(metadata["target"])
                    await discovery.page.goto(metadata["target"], wait_until="domcontentloaded", timeout=30000)
                elif action == "fill" and metadata["tag"] in {"input", "textarea"} and metadata["type"] not in {"checkbox", "radio"}:
                    await element.fill(value, timeout=3000)
                elif action == "select" and metadata["tag"] == "select":
                    await element.select_option(label=value, timeout=3000)
                elif action == "check" and metadata["type"] in {"checkbox", "radio"} and value in {"true", "false"}:
                    await element.set_checked(value == "true", timeout=3000)
                elif action == "click" and metadata["tag"] in {"button", "input", "div", "span"}:
                    await element.click(timeout=3000, no_wait_after=True)
                else:
                    raise _error(message="该元素不支持此操作；不能执行任意脚本、按键或URL。")
                return await self._snapshot(discovery)
            except PlaywrightError:
                raise _error("DISCOVERY_ACTION_FAILED", "页面操作未完成，请重新读取页面及被拦截请求。") from None

    async def get_request(self, profile, discovery_id, request_id):
        async with self._scope(profile, discovery_id) as discovery:
            item = discovery.requests.get(request_id)
            if item is None:
                raise _error(message="请求引用无效。")
            return copy.deepcopy(item)

    async def execute_read(self, profile, descriptor):
        """只读注册器调用固定契约；不作为任意HTTP工具暴露。"""
        return await self._execute_contract(profile, descriptor)

    async def execute_write(self, profile, descriptor):
        """仅由完成可信确认并占用账本的写入注册器调用。"""
        return await self._execute_contract(profile, descriptor)

    async def _execute_contract(self, profile, descriptor):
        descriptor = copy.deepcopy(descriptor)
        if not isinstance(descriptor, dict):
            raise _error(message="接口描述格式无效。")
        url, method = descriptor.get("url"), descriptor.get("method")
        if not _erp_url(url) or urlsplit(url).query or method not in {"GET", "POST"}:
            raise _error(message="已批准接口的地址或方法无效。")
        if descriptor.get("source", {}).get("credential_fields"):
            raise _error("DISCOVERY_ENCODING_UNADAPTED", "候选包含未适配认证或隐藏页面状态，需专门适配，不能沿用旧值。")
        headers = descriptor.get("headers", {})
        if not isinstance(headers, dict) or _safe_headers(headers) != headers:
            raise _error(message="接口包含未审核请求头，已阻断。")
        source = descriptor.get("source", {}).get("page_url", "")
        headers["Referer"] = source if _page_url(source) else ENTRY_URL
        async with self.browser.verified_scope(profile) as identity:
            session = self.browser._sessions[profile]
            expected = descriptor.get("_scope")
            if (not isinstance(expected, dict) or expected.get("profile") != profile
                    or expected.get("identity") != identity or expected.get("session_binding") != session.vault_binding):
                raise _error("DISCOVERY_SESSION_CHANGED", "接口批准时的账号范围已变化，请重新审核。")
            bindings, removed = [], []
            for part in ("query", "body"):
                _scrub(descriptor.get(part), "/" + part, bindings, removed)
            if removed:
                raise _error(message="接口包含凭据字段，不能执行或保存旧凭据。")
            for binding in descriptor.get("identity_bindings", []):
                keys = [key.replace("~1", "/").replace("~0", "~") for key in binding["path"].split("/")[1:]]
                if not keys or keys[0] not in {"body", "query"}:
                    raise _error(message="身份槽位置无效。")
                parent = descriptor
                for key in keys[:-1]:
                    parent = parent[int(key)] if isinstance(parent, list) else parent[key]
                name = keys[-2] if keys[-1].isdigit() else keys[-1]
                kind = "u_cid_ajax" if name == "__ajax_token" else _IDENTITIES.get(name.lower())
                if kind != binding.get("kind"):
                    raise _error(message="身份槽不能修改业务参数。")
                if kind == "u_cid_ajax":
                    cookies = await session.context.cookies([url])
                    tokens = [cookie["value"] for cookie in cookies if cookie["name"] == "u_cid"]
                    if len(tokens) != 1:
                        raise _error(message="当前会话缺少唯一CSRF来源，请重新核验。")
                    current = "1." + tokens[0] + "-"
                else:
                    current = int(identity[kind]) if binding.get("value_type") == "number" else identity[kind]
                if isinstance(parent, list):
                    parent[int(keys[-1])] = current
                else:
                    parent[keys[-1]] = current
            # Missing bindings must never retain an old identity supplied by a template.
            if {item["path"] for item in bindings} != {item["path"] for item in descriptor.get("identity_bindings", [])}:
                raise _error(message="接口身份槽不完整，需重新审核。")
            for path in descriptor.get("json_fields", []):
                if path != "/body/__CALLBACKPARAM" or descriptor.get("encoding") != "form":
                    raise _error(message="嵌套编码尚未适配。")
                descriptor["body"]["__CALLBACKPARAM"] = json.dumps(descriptor["body"]["__CALLBACKPARAM"], ensure_ascii=False)
            query = descriptor.get("query", {})
            target = url + ("?" + urlencode(query, doseq=True) if query else "")
            await _public_destination(target)
            self.browser._assert_scope(profile, session, identity)
            options = {"method": method, "headers": headers, "max_redirects": 0, "timeout": 30000}
            encoding = descriptor.get("encoding")
            if encoding in {"json", "form"} and isinstance(descriptor.get("body"), dict):
                options["data" if encoding == "json" else "form"] = descriptor["body"]
            elif encoding != "none" or descriptor.get("body") is not None:
                raise _error(message="接口编码尚未适配。")
            response = None
            try:
                response = await session.context.request.fetch(target, **options)
                if response.status != 200 or response.url != target:
                    raise _error("DISCOVERY_READ_FAILED", "试读未成功或发生重定向，未跟随目标。")
                text = await response.text()
                if len(text) > 8000000:
                    raise _error(message="接口结果过大，请缩小查询范围。")
                return {"status": response.status, "text": text, "content_type": response.headers.get("content-type", "")}
            except (PlaywrightError, OSError, UnicodeError):
                raise _error("DISCOVERY_READ_FAILED", "接口读取失败或超时，未自动重试。") from None
            finally:
                if response is not None:
                    await response.dispose()

    async def close_profile(self, profile):
        for discovery_id, discovery in list(self._discoveries.items()):
            if discovery.profile == profile:
                self._discoveries.pop(discovery_id, None)
                await discovery.context.close()

    async def close(self):
        for profile in {item.profile for item in self._discoveries.values()}:
            await self.close_profile(profile)
