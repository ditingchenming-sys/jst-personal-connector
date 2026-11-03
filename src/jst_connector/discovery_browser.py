"""隔离、受限的ERP页面探索；未知请求只截获，模板执行仅供已审核注册器内部调用。"""
from __future__ import annotations

import asyncio
import base64
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
from urllib.parse import parse_qs, quote, urldefrag, urlencode, urljoin, urlsplit, urlunsplit
from uuid import uuid4

import httpx
from playwright.async_api import Error as PlaywrightError

from .adapters import ORDER_URL, PURCHASE_URL
from .adapters.login import ENTRY_URL
from .browser import ERP_HOSTS, approved_request, safe_url
from .errors import ConnectorError
from .interface_registry import _AUTH_PATH, _operation_kind, _safe_data, _source_page_allowed
from .platform_policy import get_policy, passive_page_query

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
    return (passive_page_query(parts.query) and (urldefrag(url)[0].split("?", 1)[0] in _NAVIGATION
                                               or parts.path.lower().endswith((".aspx", ".html", ".htm"))))


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


async def _public_destination(url, *, policy=None, page=False):
    allowed = (policy.business_url(url) or policy.asset_url(url)
               or page and callable(getattr(policy, "candidate_page_url", None)) and policy.candidate_page_url(url)) if policy is not None else (_erp_url(url) or _asset_url(url))
    if not allowed:
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
    def __init__(self, base, page_allowed=None):
        super().__init__()
        self.base, self.pages = base, set()
        self.page_allowed = page_allowed or _page_url

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        target = quote(urljoin(self.base, attrs.get("src" if tag == "iframe" else "href", "")), safe=":/?#[]@!$&'()*+,;=%~-._")
        if tag in {"iframe", "a"} and self.page_allowed(target):
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
    page_sources: dict = field(default_factory=dict, repr=False)
    refs: dict = field(default_factory=dict, repr=False)
    requests: dict = field(default_factory=dict, repr=False)
    sources: dict = field(default_factory=dict, repr=False)
    diagnostics: list = field(default_factory=list, repr=False)
    source_bytes: int = 0
    touched: float = field(default_factory=time.monotonic)


class DiscoveryBrowser:
    def __init__(self, browser, *, anonymous_fetch=None):
        self.browser = browser
        self.site_policy = getattr(browser, "site_policy", None) or get_policy(getattr(browser, "platform", "erp"))
        self._discoveries = {}
        self._anonymous_fetch = anonymous_fetch or self._fetch_public
        browser.add_profile_cleanup(self.close_profile)

    def _business_url(self, url):
        return _erp_url(url) if self.site_policy.platform == "erp" else self.site_policy.business_url(url)

    def _page_url(self, url):
        return _page_url(url) if self.site_policy.platform == "erp" else self.site_policy.page_url(url)

    def _asset_url(self, url):
        return _asset_url(url) if self.site_policy.platform == "erp" else self.site_policy.asset_url(url)

    @property
    def _navigation(self):
        return _NAVIGATION if self.site_policy.platform == "erp" else self.site_policy.navigation_urls

    async def _destination(self, url):
        if self.site_policy.platform == "erp":
            return await _public_destination(url)
        return await _public_destination(url, policy=self.site_policy)

    def _candidate_page(self, url):
        candidate = getattr(self.site_policy, "candidate_page_url", None)
        return self._page_url(url) or callable(candidate) and candidate(url)

    def _page_allowed(self, discovery, url):
        return self._page_url(url) or url in discovery.pages and self._candidate_page(url)

    def _adopt_page(self, discovery, target, chain):
        if not self._candidate_page(target) or not chain or len(chain) >= 12:
            return False
        for url in {target, urldefrag(target)[0]}:
            discovery.pages.add(url)
            discovery.page_sources.setdefault(url, [safe_url(target), *chain])
        return True

    def _exploration_state(self, state, identity=None):
        if self.site_policy.platform != "drp":
            return state
        # Public frontend code rewrites tokens to the parent domain and passes
        # them through JMX. No real browser credential may enter this context.
        # The non-authenticating UI placeholder carries verified IDs; every
        # real business request is authenticated by the separate primary broker.
        identity = identity or {}
        payload = {"user": {"coId": identity.get("company_id"), "uid": identity.get("user_id")},
                   "jst_connector_discovery": True, "aud": "jst-connector-public-page-discovery"}
        def segment(value):
            return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")
        placeholder = segment({"alg": "JST_DISCOVERY_ONLY", "typ": "JWT"}) + "." + segment(payload) + ".DISCOVERY_NOT_A_SIGNATURE"
        return {"cookies": [{"name": "DISTRYBUTION_TOKEN", "value": placeholder, "domain": host, "path": "/",
                             "expires": -1, "httpOnly": False, "secure": True, "sameSite": "Lax"}
                            for host in self.site_policy.page_hosts], "origins": []}

    def _frame_chain(self, discovery, frame):
        chain = []
        for _ in range(12):
            if frame is None or not self._page_allowed(discovery, frame.url) or frame.page is not discovery.page:
                return None
            chain.append(safe_url(frame.url))
            if frame is discovery.page.main_frame:
                if self._page_url(frame.url):
                    return chain
                evidence = discovery.page_sources.get(frame.url, [])
                combined = [*chain, *evidence[1:]]
                return combined if evidence and len(combined) <= 12 else None
            frame = frame.parent_frame
        return None

    async def _observe_iframe(self, discovery, request):
        """Adopt only a real iframe reference under this discovery's trusted parent chain."""
        frame = getattr(request, "frame", None)
        parent = frame.parent_frame if frame is not None else None
        if not parent or not self._candidate_page(request.url) or not self._frame_chain(discovery, parent):
            return False
        element = None
        try:
            parent_url = parent.url
            element = await frame.frame_element()
            source = await element.get_attribute("src")
            target = quote(urljoin(parent_url, source or ""), safe=":/?#[]@!$&'()*+,;=%~-._")
            if (not source or urldefrag(target)[0] != request.url or parent.url != parent_url
                    or not self._frame_chain(discovery, parent)):
                return False
            self._check(discovery)
            return self._adopt_page(discovery, target, self._frame_chain(discovery, parent))
        except PlaywrightError:
            return False
        finally:
            if element is not None:
                await element.dispose()

    def _cors(self, discovery, request):
        if not self._frame_chain(discovery, request.frame):
            raise _error(message="请求不是来自本次已观察的可信页面父链，已阻断。")
        parts = urlsplit(request.frame.url)
        origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        if request.headers.get("origin", origin) != origin:
            raise _error(message="请求来源与本次实际页面不一致，已阻断。")
        return {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true", "Vary": "Origin"}

    def _approved_page_read(self, discovery, request, payload):
        if self.site_policy.platform == "erp":
            return approved_request(request.method, request.url, payload)
        from .drp_read_policy import approved_request as drp_read
        return (self._frame_chain(discovery, request.frame) is not None and self._business_url(request.url)
                and not any(key.casefold() == "action-name" for key in request.headers)
                and drp_read(request.method, request.url, payload))

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

    async def start(self, profile, url=None, *, entry_approved=False, expected_binding=None):
        url = self.site_policy.entry_url if url is None else url
        if not self._page_url(url) or (url not in self._navigation and entry_approved is not True):
            raise _error("DISCOVERY_ENTRY_APPROVAL_REQUIRED", "该页面入口尚未批准，请先由本人在管理页确认精确入口。")
        try:
            async with self.browser.verified_scope(profile) as identity:
                session = self.browser._sessions[profile]
                if ((expected_binding is not None and expected_binding != session.vault_binding)
                        or (url not in self._navigation and not expected_binding)):
                    raise _error("DISCOVERY_SESSION_CHANGED", "入口审批对应的账号会话已变化，请重新批准。")
                await self.close_profile(profile)
                state = self._exploration_state(await session.context.storage_state(), identity)
                self.browser._assert_scope(profile, session, identity)
                context = await self.browser._new_context(state)
                if context is session.context:
                    raise _error(message="探索必须使用独立上下文，不能复用主登录页面。")
                page = await context.new_page()
                discovery = _Discovery(uuid4().hex, profile, context, page, dict(identity), session.binding,
                                       session.vault_binding, pages={url, urldefrag(url)[0]})
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

    def _capture(self, discovery, request, *, blocked, read_authorized=False):
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
        discovery.requests[request_id]["_scope"] = {"profile": discovery.profile, "platform": self.site_policy.platform, "identity": dict(discovery.identity),
                                                    "session_binding": discovery.persisted_binding}
        if self.site_policy.platform == "drp":
            chain = self._frame_chain(discovery, request.frame)
            if chain:
                discovery.requests[request_id]["source"]["page_chain"] = chain
        if read_authorized:
            discovery.requests[request_id]["source"].update(read_authorized=True, frame_chain=self._frame_chain(discovery, request.frame))
        return request_id

    @staticmethod
    def _observed_response(discovery, request_id, result):
        if not request_id or request_id not in discovery.requests:
            return
        summary = {"status": result.get("status"), "content_type": result.get("content_type", "")}
        raw = result.get("text")
        if isinstance(raw, str) and len(raw) <= 2_000_000:
            try:
                value = json.loads(raw)
                summary["schema"] = _schema(_safe_data(value))
                if isinstance(value, dict) and type(value.get("success")) is bool:
                    summary["business_success"] = value["success"]
            except ValueError:
                summary["schema"] = "unavailable"
        if isinstance(result.get("pagination"), dict):
            summary["pagination"] = copy.deepcopy(result["pagination"])
        discovery.requests[request_id]["observed_response"] = summary

    async def _fetch_public(self, url, *, page=False):
        if page:
            await _public_destination(url, policy=self.site_policy, page=True)
        else:
            await self._destination(url)
        async with (httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=15) as client,
                    client.stream("GET", url, headers={"Accept": "*/*"}) as response):
                if response.status_code != 200 or str(response.url) != url:
                    raise _error(message="公开资源读取未成功，未跟随重定向。")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self._asset_limits()[1]:
                        raise _error(message="公开资源超出本次取证范围。")
                content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
        return {"status": response.status_code, "url": str(response.url), "body": bytes(body), "content_type": content_type}

    def _asset_limits(self):
        # Official DRP initialization alone exceeds 12 MB, including a 6.4 MB
        # shared chunk. Keep ERP's existing bounds and DRP's larger bounds finite.
        return (64, 8 * 1024 * 1024, 32 * 1024 * 1024) if self.site_policy.platform == "drp" else (32, 2000000, 8000000)

    async def _asset(self, discovery, url):
        if not self._asset_url(url):
            raise _error(message="该地址不是已核实公共静态资源域及文件。")
        if url in discovery.sources:
            return discovery.sources[url]
        count_limit, file_limit, total_limit = self._asset_limits()
        if len(discovery.sources) >= count_limit or discovery.source_bytes >= total_limit:
            raise _error(message="公开资源取证已达本次上限，请缩小页面范围。")
        response = await self._anonymous_fetch(url)
        # Concurrent page chunks may have filled the budget while fetching.
        if url in discovery.sources:
            return discovery.sources[url]
        body, content_type = response["body"], response["content_type"]
        if (response.get("status") != 200 or response.get("url") != url or not isinstance(body, bytes)
                or len(discovery.sources) >= count_limit or len(body) > file_limit or discovery.source_bytes + len(body) > total_limit):
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
            if request.method == "GET" and self._asset_url(request.url):
                phase = "anonymous_asset"
                source = await self._asset(discovery, request.url)
                self._check(discovery)
                await route.fulfill(status=200, body=source["body"], content_type=source["content_type"],
                                    headers={"Access-Control-Allow-Origin": "*"})
            elif (request.method == "GET" and request.resource_type == "document"
                  and (request.url in discovery.pages or await self._observe_iframe(discovery, request))):
                phase = "document_policy"
                if not self._page_allowed(discovery, request.url):
                    raise _error(message="认证、登出或已知写动作不能作为探索页面。")
                frame = getattr(request, "frame", None)
                if (frame is not None and (frame.page is not discovery.page
                        or frame.parent_frame is not None and not await self._observe_iframe(discovery, request))):
                    raise _error(message="页面不属于本次已观察的主页面或iframe父链，已阻断。")
                if not self._page_url(request.url):
                    await _public_destination(request.url, policy=self.site_policy, page=True)
                else:
                    await self._destination(request.url)
                self._check(discovery)
                phase = "document_fetch"
                if self.site_policy.platform == "drp":
                    # Public DRP shells are anonymous, including known frontends.
                    # Never let document Set-Cookie widen the isolated cookie jar.
                    document = await self._fetch_public(request.url, page=True)
                    if document["content_type"] != "text/html" or document["status"] != 200:
                        raise _error(message="新模块入口未返回普通HTML页面，已阻断。")
                    body = document["body"]
                else:
                    response = await route.fetch(max_redirects=0, timeout=30000)
                    body = await response.body()
                phase = "document_response"
                if response is not None and (response.status != 200 or response.url != request.url
                        or "text/html" not in response.headers.get("content-type", "").lower()
                        or "attachment" in response.headers.get("content-disposition", "").lower()):
                    raise _error(message="页面响应不符合已批准HTML入口，已阻断。")
                if len(body) > 2000000:
                    raise _error(message="探索页面超出本次范围。")
                parser = _References(request.url, self._candidate_page)
                parser.feed(body.decode("utf-8", errors="replace"))
                chain = discovery.page_sources.get(request.url, [safe_url(request.url)])
                for target in parser.pages:
                    self._adopt_page(discovery, target, chain)
                self._check(discovery)
                if response is not None:
                    await route.fulfill(response=response)
                else:
                    await route.fulfill(status=200, body=body, content_type="text/html")
            else:
                phase = "request_capture"
                if (self.site_policy.platform == "drp" and request.method == "OPTIONS"
                        and self._business_url(request.url)):
                    # Local CORS negotiation has no upstream side effect. The
                    # actual request still needs the complete installed read rule.
                    headers = self._cors(discovery, request)
                    headers.update({"Access-Control-Allow-Methods": "GET, POST", "Access-Control-Allow-Headers":
                                    "authorization, content-type, appcode, source, app-version, x-requested-with, action-name"})
                    await route.fulfill(status=204, headers=headers, body="")
                    return
                payload = None
                try:
                    payload = request.post_data_json
                except (PlaywrightError, ValueError):
                    if request.post_data:
                        payload = {key: values[0] for key, values in parse_qs(request.post_data).items()}
                approved = self._approved_page_read(discovery, request, payload)
                request_id = self._capture(discovery, request, blocked=not approved,
                                           read_authorized=approved and self.site_policy.platform == "drp")
                if approved:
                    if self.site_policy.platform == "drp":
                        if not request_id or discovery.requests[request_id]["source"].get("credential_fields"):
                            raise _error(message="已核查询仍含未适配编码或认证字段，未发出请求。")
                        await self._destination(request.url)
                        self._check(discovery)
                        headers = self._cors(discovery, request)
                    else:
                        headers = {}
                    result = await self.browser.request(discovery.profile, request.method, request.url, payload)
                    self._check(discovery)
                    self._observed_response(discovery, request_id, result)
                    await route.fulfill(status=result["status"], body=result["text"], content_type="application/json", headers=headers)
                else:
                    await route.abort("blockedbyclient")
        except (ConnectorError, PlaywrightError, OSError, httpx.HTTPError) as error:
            diagnostic = {"stage": phase,
                          "url": safe_url(request.url) if self._business_url(request.url) or self._asset_url(request.url) else "[未审核地址]",
                          "failure": "policy_rejected" if isinstance(error, ConnectorError) else "transport_failed"}
            if isinstance(error, ConnectorError):
                diagnostic["error_code"] = error.code
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
            if not self._frame_chain(discovery, frame):
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
                target = quote(urljoin(frame.url, await element.get_attribute("src" if tag == "iframe" else "href") or ""), safe=":/?#[]@!$&'()*+,;=%~-._") if tag in {"a", "iframe"} else ""
                metadata = {"tag": tag, "type": kind, "name": name, "frame_url": frame.url, "target": target}
                discovery.refs[reference] = (element, frame, metadata, time.monotonic() + 60)
                item = {"element_ref": reference, "tag": tag, "type": kind, "name": name,
                        "label": _text(await element.get_attribute("aria-label") or await element.get_attribute("placeholder")
                                       or (await element.inner_text() if tag not in {"input", "textarea", "iframe"} else ""), 200)}
                if tag == "select":
                    item["options"] = [_text(await option.text_content() or "", 100)
                                       for option in (await element.query_selector_all("option"))[:50]]
                if tag in {"a", "iframe"} and self._adopt_page(discovery, target, self._frame_chain(discovery, frame)):
                    item["url"] = target
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
                             "source": item["source"], "identity_bindings": item["identity_bindings"],
                             **({"observed_response": copy.deepcopy(item["observed_response"])} if "observed_response" in item else {})}
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
                text = _text(source["body"].decode("utf-8", errors="replace"), self._asset_limits()[1])
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
                    if metadata["tag"] not in {"a", "iframe"} or not self._page_allowed(discovery, metadata["target"]):
                        raise _error(message="该引用不是本次已观察到的安全页面入口。")
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
        return await self._execute_contract(profile, descriptor, read_only=True)

    async def execute_write(self, profile, descriptor):
        """仅由完成可信确认并占用账本的写入注册器调用。"""
        return await self._execute_contract(profile, descriptor)

    async def _execute_contract(self, profile, descriptor, *, read_only=False):
        descriptor = copy.deepcopy(descriptor)
        if not isinstance(descriptor, dict):
            raise _error(message="接口描述格式无效。")
        url, method = descriptor.get("url"), descriptor.get("method")
        if not self._business_url(url) or urlsplit(url).query or method not in {"GET", "POST"}:
            raise _error(message="已批准接口的地址或方法无效。")
        if read_only and self.site_policy.platform == "drp":
            from .drp_read_policy import approved_request as drp_read
            from .drp_read_policy import known_read_url
            query = descriptor.get("query", {})
            target = url + ("?" + urlencode(query, doseq=True) if query else "")
            if known_read_url(target) and (any(str(key).casefold() == "action-name" for key in descriptor.get("headers", {}))
                                          or not drp_read(method, target, descriptor.get("body"))):
                raise _error("DISCOVERY_NOT_READONLY", "当前商品查询参数或调度已超出已核只读边界，未发出请求。")
        if descriptor.get("source", {}).get("credential_fields"):
            raise _error("DISCOVERY_ENCODING_UNADAPTED", "候选包含未适配认证或隐藏页面状态，需专门适配，不能沿用旧值。")
        headers = descriptor.get("headers", {})
        if not isinstance(headers, dict) or _safe_headers(headers) != headers:
            raise _error(message="接口包含未审核请求头，已阻断。")
        source = descriptor.get("source", {}).get("page_url", "")
        source_allowed = self._page_url(source) or (self.site_policy.platform == "drp"
                                                  and _source_page_allowed(self.site_policy, descriptor.get("source", {})))
        headers["Referer"] = source if source_allowed else self.site_policy.entry_url
        async with self.browser.verified_scope(profile) as identity:
            session = self.browser._sessions[profile]
            expected = descriptor.get("_scope")
            if (not isinstance(expected, dict) or expected.get("profile") != profile
                    or expected.get("platform", "erp") != self.site_policy.platform
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
                    if self.site_policy.csrf_cookie != "u_cid":
                        raise _error("DISCOVERY_ENCODING_UNADAPTED", "当前平台未核实该认证字段的重建方式，不能套用ERP令牌。")
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
            await self._destination(target)
            if self.site_policy.platform != "erp":
                prepare_headers = getattr(self.browser, "business_headers", None)
                if not callable(prepare_headers):
                    raise _error("DISCOVERY_ENCODING_UNADAPTED", "当前平台业务授权头尚未适配，未发出请求。")
                trusted_headers = await prepare_headers(session, target)
                if (not isinstance(trusted_headers, dict)
                        or any(not isinstance(key, str) or key.casefold() not in {"authorization", "app-version", "source", "appcode"}
                               or not isinstance(value, str) or not value or len(value) > 16384 or "\r" in value or "\n" in value
                               for key, value in trusted_headers.items())
                        or not any(key.casefold() == "authorization" for key in trusted_headers)):
                    raise _error("DISCOVERY_ENCODING_UNADAPTED", "当前平台业务授权头未通过核验，未发出请求。")
                headers.update(trusted_headers)
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
                result = {"status": response.status, "text": text, "content_type": response.headers.get("content-type", "")}
                if read_only and self.site_policy.platform == "drp":
                    from .drp_read_policy import validate_response
                    pagination = validate_response(method, target, descriptor.get("body"), result)
                    if pagination is not None:
                        result["pagination"] = pagination
                return result
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
