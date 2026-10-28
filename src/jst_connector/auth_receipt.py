"""仅从审核响应的Set-Cookie提取私有候选；不读cookie jar，不据此验证员工。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from http.cookies import CookieError, SimpleCookie
from urllib.parse import urlsplit

from .adapters.login import ENTRY_URL

PASSPORT_URL = "https://api.erp321.com/erp/webapi/UserApi/WebLogin/Passport"
IDENTITY_COOKIE_FIELDS = {"u_id": "user_id", "u_co_id": "company_id"}
POSITIVE_ID = re.compile(r"[1-9][0-9]{0,19}")


@dataclass
class IdentityCookieReceipt:
    candidates: dict = field(default_factory=dict, repr=False)
    sources: dict = field(default_factory=dict, repr=False)
    rejected_fields: set = field(default_factory=set, repr=False)


def _identity_fields_in_header(header):
    if not isinstance(header, str):
        return set()
    names = re.findall(r"(?:^|[;,\r\n])\s*(?:Set-Cookie:\s*)?(u_id|u_co_id)\s*=", header,
                       flags=re.IGNORECASE)
    return {IDENTITY_COOKIE_FIELDS[name] for name in names if name in IDENTITY_COOKIE_FIELDS}


def _scope(morsel, response_url):
    source = urlsplit(response_url)
    raw_domain = morsel["domain"].strip().lower()
    if raw_domain:
        if (raw_domain.startswith("..") or raw_domain.endswith(".")
                or not re.fullmatch(r"\.?[a-z0-9]+(?:[.-][a-z0-9]+)*", raw_domain)):
            return None
        domain = raw_domain.removeprefix(".")
        if domain not in {source.hostname, "erp321.com"}:
            return None
        if source.hostname != domain and not source.hostname.endswith("." + domain):
            return None
    else:
        domain = source.hostname  # Host-only is derived from this exact server response, not a jar.
    path = morsel["path"]
    if not path:
        path = source.path.rsplit("/", 1)[0] or "/"
    if not path.startswith("/") or "\\" in path:
        return None
    if source.path != path and not (source.path.startswith(path)
                                   and (path.endswith("/") or source.path[len(path):].startswith("/"))):
        return None
    return {"cookie_domain": domain, "cookie_path": path, "host_only": not bool(raw_domain)}


def _cookie(header, response_url, now):
    if not isinstance(header, str) or len(header) > 8192 or "\r" in header or "\n" in header:
        return None
    attributes = set()
    for part in header.split(";")[1:]:
        name = part.partition("=")[0].strip().lower()
        if name in attributes:
            return None
        attributes.add(name)
    try:
        parsed = SimpleCookie()
        parsed.load(header)
        if len(parsed) != 1:
            return None  # A folded or ambiguous Set-Cookie header is not provenance evidence.
        name, morsel = next(iter(parsed.items()))
        if name not in IDENTITY_COOKIE_FIELDS or POSITIVE_ID.fullmatch(morsel.value) is None:
            return None
        if "max-age" in attributes and re.fullmatch(r"[1-9][0-9]*", morsel["max-age"]) is None:
            return None
        if "expires" in attributes:
            expires = parsedate_to_datetime(morsel["expires"])
            if expires is None:
                return None
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            if expires <= now:
                return None
        scope = _scope(morsel, response_url)
        if scope is None:
            return None
        return name, morsel.value, scope
    except (CookieError, ValueError, TypeError, OverflowError):
        return None


def identity_cookie_receipt(response_url, method, status, set_cookie_headers, *, active,
                            passport_code=None, passport_succeeded=False, now=None):
    """Private helper: return candidates only for the exact authenticated-response chain.

    Values are never safe to serialize. Public diagnostics may use only the cookie field names.
    This records server issuance, not verified identity or authorization.
    """
    if active is not True or type(status) is not int or status != 200:
        return None
    passport = (response_url == PASSPORT_URL and method == "POST"
                and type(passport_code) is int and passport_code == 0)
    entry = response_url == ENTRY_URL and method == "GET" and passport_succeeded is True
    if not passport and not entry:
        return None
    if not isinstance(set_cookie_headers, (list, tuple)) or len(set_cookie_headers) > 32:
        return None
    now = now or datetime.now(UTC)
    receipt = IdentityCookieReceipt()
    for header in set_cookie_headers:
        result = _cookie(header, response_url, now)
        if result is None:
            receipt.rejected_fields.update(_identity_fields_in_header(header))
            continue
        name, value, scope = result
        field_name = IDENTITY_COOKIE_FIELDS[name]
        if field_name in receipt.candidates or field_name in receipt.rejected_fields:
            receipt.rejected_fields.add(field_name)
            receipt.candidates.pop(field_name, None)
            receipt.sources.pop(field_name, None)
            continue
        receipt.candidates[field_name] = value
        receipt.sources[field_name] = {"response_url": response_url, "method": method,
                                      "via": "set-cookie", "cookie_name": name, **scope}
    for field_name in receipt.rejected_fields:
        receipt.candidates.pop(field_name, None)
        receipt.sources.pop(field_name, None)
    return receipt
