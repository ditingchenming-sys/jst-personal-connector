"""安装时固定的平台边界；业务域、认证域和匿名资产域不混用。"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

from .adapters import ORDER_URL, PURCHASE_URL
from .adapters.login import ENTRY_URL, LOGIN_URL
from .errors import ConnectorError

_ASSET_SUFFIX = re.compile(r"\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf)$", re.IGNORECASE)
_SECRET_QUERY = re.compile(r"pass|pwd|cookie|authorization|token|secret|credential|session|csrf|xsrf|ticket|signature|api.?key", re.IGNORECASE)
_AUTH_ROUTE = re.compile(r"(?:^|/)(?:login|logout|logoff|signout|signoff|passport|oauth|authentication|verification|captcha|auth)(?:[/.]|$)", re.IGNORECASE)
_WRITE_ROUTE = re.compile(r"^(?:save|create|insert|update|delete|remove|submit|approve|audit|cancel|reset|send|execute|commit|modify|pay)|(?:and|then)(?:save|create|update|delete|submit|approve|audit|send|pay|commit)", re.IGNORECASE)


def _strict_parts(value):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(character) < 32 for character in value):
        return None
    try:
        parts = urlsplit(value)
        if (parts.scheme != "https" or parts.netloc != parts.hostname or parts.port is not None
                or parts.username or parts.password or parts.fragment or not parts.path.startswith("/")
                or "\\" in parts.path or "%" in parts.path or ".." in parts.path.split("/")):
            return None
        return parts
    except (TypeError, ValueError):
        return None


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
        parts = _strict_parts(value)
        if (not parts or parts.hostname not in self.page_hosts or parts.query
                or not self.business_url(value) or _AUTH_ROUTE.search(parts.path)):
            return False
        return not any(_WRITE_ROUTE.search(segment.split(".", 1)[0]) for segment in parts.path.split("/") if segment)

    def asset_url(self, value):
        parts = _strict_parts(value)
        return bool(parts and parts.hostname in self.asset_hosts and _ASSET_SUFFIX.search(parts.path)
                    and self._path_allowed(parts.hostname, parts.path, self.asset_paths)
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
    business_hosts=frozenset({"sc.scm121.com", "gyl.scm121.com", "innerapi.scm121.com"}),
    auth_hosts=frozenset({"account.scm121.com", "gyl.scm121.com"}),
    asset_hosts=frozenset({"assets.sursung.com"}), navigation_urls=frozenset({"https://sc.scm121.com/"}),
    business_paths=(("gyl.scm121.com", ("/api/drp/", "/api/company/", "/api/goods/", "/api/goodsbasic/")),
                    ("innerapi.scm121.com", ("/api/innerdrp/", "/api/inner/", "/api/aftersale/"))),
    asset_paths=(("assets.sursung.com", ("/prod/account/", "/prod/gylsc/", "/pkg/")),),
    page_hosts=frozenset({"sc.scm121.com"}),
)


def get_policy(platform="erp"):
    if platform == "erp":
        return ERP
    if platform == "drp":
        return DRP
    raise ConnectorError("invalid_platform", "平台必须为 erp 或 drp，不能通过业务请求更换连接平台。")
