"""安装时固定的平台边界；业务域、认证域和匿名资产域不混用。"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, parse_qsl, urlsplit

from .adapters import ORDER_URL, PURCHASE_URL
from .adapters.login import ENTRY_URL, LOGIN_URL
from .errors import ConnectorError

_ASSET_SUFFIX = re.compile(r"\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf)$", re.IGNORECASE)
_SECRET_QUERY = re.compile(r"pass|pwd|cookie|authorization|token|secret|credential|session|viewstate|eventvalidation|nonce|captcha|csrf|xsrf|ticket|signature|api.?key|^ucid$", re.IGNORECASE)
_AUTH_ROUTE = re.compile(r"(?:^|/)(?:login|logout|logoff|signout|signoff|passport|oauth|authentication|verification|captcha|auth)(?:[/.]|$)", re.IGNORECASE)
_WRITE_ROUTE = re.compile(r"^(?:save|create|insert|update|delete|remove|submit|approve|audit|cancel|reset|send|execute|commit|modify|pay|publish)|(?:and|then)(?:save|create|update|delete|submit|approve|audit|send|pay|commit|publish)", re.IGNORECASE)
_PAGE_CONTROL = re.compile(r"^(?:action(?:name)?|method(?:name)?|operation(?:name)?|command|rpc|callback(?:id|param)?|callcontrol|am|requests?|batch|transaction|"
                           r"redirect(?:uri|url)?|return(?:url|to)|url|endpoint|coid|uid|userid|companyid|employeeid|profile|identity|"
                           r"sourceprofile|sourceidentity|confirmed|otp|verificationcode|verifycode|logincode|authcode|ucoid|ownercoid|authorizecoid|"
                           r"proto|prototype|constructor|auth|authentication|security|oauth|sso|idp)$", re.IGNORECASE)
_AUTH_HOST = re.compile(r"(?:^|[.-])(?:account|auth|login|logout|passport|oauth|security|sso|idp|jstlogin)(?:[.-]|$)", re.IGNORECASE)


def _passive_query_value(value, depth=0):
    if depth > 6:
        return False
    if isinstance(value, dict):
        return len(value) <= 100 and all(_passive_query_key(key) and _passive_query_value(item, depth + 1)
                                        for key, item in value.items())
    if isinstance(value, list):
        return len(value) <= 100 and all(_passive_query_value(item, depth + 1) for item in value)
    if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        try:
            return _passive_query_value(json.loads(value, object_pairs_hook=_unique_json_object), depth + 1)
        except (ValueError, RecursionError):
            return False
    return value is None or isinstance(value, (str, int, float, bool))


def _passive_query_key(key):
    if not isinstance(key, str) or not key or len(key) > 100 or any(ord(char) < 32 or ord(char) == 127 for char in key):
        return False
    segments = [segment for segment in re.split(r"[.\[\]]+", key) if segment]
    if len(segments) > 6:
        return False
    for segment in segments:
        normalized = re.sub(r"[\W_]", "", segment)
        if not normalized or _SECRET_QUERY.search(normalized) or _PAGE_CONTROL.fullmatch(normalized):
            return False
    return bool(segments)


def _passive_page_query(query):
    """Bound passive filters by structure, not by a business-field catalog."""
    if not query:
        return True
    if len(query) > 4096 or ";" in query or re.search(r"%(?![0-9a-fA-F]{2})", query):
        return False
    try:
        pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=100, encoding="utf-8", errors="strict")
        if not pairs or len({key for key, _ in pairs}) != len(pairs):
            return False
        for key, value in pairs:
            if (not _passive_query_key(key) or re.sub(r"[^a-zA-Z0-9]", "", key).lower() == "code"
                    or any(ord(char) < 32 or ord(char) == 127 for char in value)):
                return False
            try:
                decoded = json.loads(value, object_pairs_hook=_unique_json_object)
            except (_DuplicateQueryField, RecursionError):
                return False
            except ValueError:
                if value.lstrip().startswith(("{", "[")):
                    return False
                continue
            if not _passive_query_value(decoded):
                return False
        return True
    except (ValueError, UnicodeError):
        return False


class _DuplicateQueryField(ValueError):
    pass


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateQueryField
        result[key] = value
    return result


passive_page_query = _passive_page_query


def _strict_parts(value):
    if (not isinstance(value, str) or len(value) > 8192 or "#" in value
            or any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value)):
        return None
    try:
        parts = urlsplit(value)
        if (parts.scheme != "https" or parts.netloc != parts.hostname or parts.port is not None
                or parts.username or parts.password or parts.fragment or not parts.path.startswith("/")
                or "\\" in parts.path or "%" in parts.path or "//" in parts.path
                or any(segment in {".", ".."} for segment in parts.path.split("/"))):
            return None
        return parts
    except (TypeError, ValueError):
        return None


def _page_parts(value):
    """UI hash routes are not API fragments or authentication token carriers."""
    if not isinstance(value, str):
        return None
    network, separator, fragment = value.partition("#")
    parts = _strict_parts(network)
    if not parts:
        return None
    routes = [parts]
    if separator:
        if not fragment.startswith("/") or "#" in fragment or len(value) > 8192:
            return None
        route = _strict_parts("https://route.invalid" + fragment)
        if not route:
            return None
        routes.append(route)
    for route in routes:
        if (_AUTH_ROUTE.search(route.path) or route.path.lower() == "/api" or route.path.lower().startswith("/api/")
                or not _passive_page_query(route.query)
                or any(_WRITE_ROUTE.search(segment.split(".", 1)[0]) or segment.lower() in {"add", "publish"}
                       for segment in route.path.split("/") if segment)):
            return None
    return parts


@dataclass(frozen=True)
class SitePolicy:
    platform: str
    display_name: str
    entry_url: str
    login_url: str
    business_hosts: frozenset[str]
    auth_hosts: frozenset[str]
    asset_hosts: frozenset[str]
    navigation_urls: frozenset[str]
    business_paths: tuple[tuple[str, tuple[str, ...]], ...] = ()
    asset_paths: tuple[tuple[str, tuple[str, ...]], ...] = ()
    page_hosts: frozenset[str] = frozenset()
    csrf_cookie: str | None = None
    asset_urls: frozenset[str] = frozenset()

    @staticmethod
    def _path_allowed(host, path, declarations):
        restrictions = dict(declarations).get(host)
        return restrictions is None or any(path == prefix.rstrip("/") or path.startswith(prefix) for prefix in restrictions)

    def business_url(self, value):
        parts = _strict_parts(value)
        return bool(parts and parts.hostname in self.business_hosts
                    and not _AUTH_ROUTE.search(parts.path)
                    and self._path_allowed(parts.hostname, parts.path, self.business_paths))

    def page_url(self, value):
        parts = _page_parts(value) if self.platform == "drp" else _strict_parts(value)
        network = value.partition("#")[0] if isinstance(value, str) else value
        if (not parts or parts.hostname not in self.page_hosts
                or not self.business_url(network) or _AUTH_ROUTE.search(parts.path)):
            return False
        if parts.path.lower() == "/api" or parts.path.lower().startswith("/api/"):
            return False
        if parts.query and not passive_page_query(parts.query):
            return False
        if (self.platform == "erp" and network.partition("?")[0] not in self.navigation_urls
                and not parts.path.lower().endswith((".aspx", ".html", ".htm"))):
            return False
        return not any(_WRITE_ROUTE.search(segment.split(".", 1)[0]) for segment in parts.path.split("/") if segment)

    def candidate_page_url(self, value):
        """A candidate needs current trusted page-source evidence before use.

        This never grants business/API/Authorization or asset-host access.
        Discovery owns per-actor, per-session admission and public DNS checks.
        """
        if self.platform != "drp":
            return self.page_url(value)
        parts = _page_parts(value)
        if (not parts or not parts.hostname or not parts.hostname.endswith(".scm121.com")
                or parts.hostname in self.auth_hosts or parts.hostname in self.business_hosts - self.page_hosts
                or _AUTH_HOST.search(parts.hostname) or _AUTH_ROUTE.search(parts.path)
                or parts.path.lower() == "/api" or parts.path.lower().startswith("/api/")
                or not _passive_page_query(parts.query)):
            return False
        return not any(_WRITE_ROUTE.search(segment.split(".", 1)[0]) for segment in parts.path.split("/") if segment)

    def asset_url(self, value):
        parts = _strict_parts(value)
        return bool(parts and parts.hostname in self.asset_hosts and _ASSET_SUFFIX.search(parts.path)
                    and (value in self.asset_urls or self._path_allowed(parts.hostname, parts.path, self.asset_paths))
                    and (self.platform != "drp" or _passive_page_query(parts.query))
                    and not any(_SECRET_QUERY.search(key) for key in parse_qs(parts.query)))


ERP = SitePolicy(
    platform="erp", display_name="聚水潭ERP", entry_url=ENTRY_URL,
    login_url=LOGIN_URL,
    business_hosts=frozenset({"www.erp321.com", "src.erp321.com", "api.erp321.com", "apiweb.erp321.com"}),
    auth_hosts=frozenset({"www.erp321.com", "api.erp321.com"}),
    asset_hosts=frozenset({"src.erp321.com", "cdn.erp321.cn", "cdn-static.erp321.cn"}),
    navigation_urls=frozenset({ENTRY_URL, PURCHASE_URL, ORDER_URL}),
    asset_paths=(("cdn-static.erp321.cn", ("/cdn/",)),),
    page_hosts=frozenset({"www.erp321.com", "src.erp321.com"}), csrf_cookie="u_cid",
)

# Hosts and API prefixes are declared by the public sc.scm121.com application;
# authentication remains excluded from the reusable business-request channel.
DRP = SitePolicy(
    platform="drp", display_name="聚水潭分销", entry_url="https://sc.scm121.com/",
    login_url="https://account.scm121.com/user/login",
    business_hosts=frozenset({"sc.scm121.com", "goods.scm121.com", "gyl.scm121.com", "innerapi.scm121.com"}),
    auth_hosts=frozenset({"account.scm121.com", "gyl.scm121.com"}),
    asset_hosts=frozenset({"assets.sursung.com", "files.erp321.com", "cdn.erp321.cn"}), navigation_urls=frozenset({"https://sc.scm121.com/"}),
    business_paths=(("gyl.scm121.com", ("/api/drp/", "/api/company/", "/api/goods/", "/api/goodsbasic/")),
                    ("innerapi.scm121.com", ("/api/innerdrp/", "/api/inner/", "/api/aftersale/"))),
    asset_paths=(("assets.sursung.com", ("/prod/", "/pkg/")),
                 ("files.erp321.com", ("/cdn/webbox/load-config/",)), ("cdn.erp321.cn", ("/webbox/",))),
    page_hosts=frozenset({"sc.scm121.com", "goods.scm121.com"}),
    asset_urls=frozenset({"https://files.erp321.com/cdn/webbox/load-config/gyl-home/url.config.js",
                          "https://files.erp321.com/cdn/webbox/load-config/gyl-home/webbox-config.prod.js",
                          "https://cdn.erp321.cn/cdn/expire-1-Y/webbox/0.0.23-alpha.0/webbox-web.min.js",
                          "https://cdn.erp321.cn/cdn/expire-5-m/jst-jmx/0.0.2/umd/jmx.min.js"}),
)


def get_policy(platform="erp"):
    if platform == "erp":
        return ERP
    if platform == "drp":
        return DRP
    raise ConnectorError("invalid_platform", "平台必须为 erp 或 drp，不能通过业务请求更换连接平台。")
