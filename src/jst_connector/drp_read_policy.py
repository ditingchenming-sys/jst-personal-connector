"""官方商品列表的启动只读策略；其它请求仍经通用契约核验。"""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qs

from .errors import ConnectorError
from .platform_policy import _strict_parts

# goods umi.5697886d.js (217083: V7l / dC0); the two functions POST to
# dedicated list endpoints, separate from remove/update/publish functions.
GOODS_LIST_PATHS = frozenset({"/api/goods/supplier/goods/list", "/api/goods/myself/rapidly/goods/list"})
SUPPLIER_GOODS_PATH = "/api/goods/buyer/supplier/queryDisErpGoodsDataV2"
SUPPLIER_LIST_PATH = "/api/drp/mySupplier/queryMySupplier"
SUPPLIER_OPTIONS_PATH = "/api/drp/partner/channel/queryMySupplierByOptionals"
_POST_LIST_PATHS = GOODS_LIST_PATHS | {SUPPLIER_GOODS_PATH, SUPPLIER_LIST_PATH}
GOODS_READ_HOSTS = frozenset({"gyl.scm121.com", "sc.scm121.com", "goods.scm121.com"})
_CONTROL = re.compile(r"^(?:action(?:name)?|method(?:name)?|operation(?:name)?|command|requests?|batch|transaction|url|endpoint|api|coid|uid|userid|companyid|profile|employeeid|sourceprofile|identity)$|pass|pwd|cookie|authorization|token|secret|credential|session|csrf|xsrf|ticket|signature", re.IGNORECASE)


def known_read_url(url: str) -> bool:
    parts = _strict_parts(url)
    return bool(parts and ((parts.hostname in GOODS_READ_HOSTS and parts.path in _POST_LIST_PATHS | {SUPPLIER_OPTIONS_PATH})
                           or (parts.hostname == "gyl.scm121.com" and parts.path == "/api/drp/user/supplier/getUserInfo")))


def _filters(value, depth=0):
    if depth > 8:
        return False
    if isinstance(value, str):
        if len(value) > 4096:
            return False
        try:
            return not isinstance(json.loads(value), (dict, list))
        except ValueError:
            return True
    if value is None or isinstance(value, (bool, int, float)):
        return True
    if isinstance(value, list):
        return len(value) <= 1000 and all(_filters(item, depth + 1) for item in value)
    if isinstance(value, dict):
        return len(value) <= 150 and all(isinstance(key, str) and not _CONTROL.search(re.sub(r"[_-]", "", key))
                                         and _filters(item, depth + 1) for key, item in value.items())
    return False


def approved_request(method: str, url: str, payload=None) -> bool:
    """Only exact, dedicated official reads; no verb/name-based inference."""
    parts = _strict_parts(url)
    if not parts or parts.hostname not in GOODS_READ_HOSTS:
        return False
    if method == "GET" and parts.path == SUPPLIER_OPTIONS_PATH:
        return payload is None and not parts.query
    if (method == "GET" and parts.hostname == "gyl.scm121.com"
            and parts.path == "/api/drp/user/supplier/getUserInfo" and payload is None):
        return parse_qs(parts.query, keep_blank_values=True) == {"supplierType": ["shop"], "terminalName": ["SUPPLIER"]}
    if method != "POST" or parts.path not in _POST_LIST_PATHS or parts.query or not isinstance(payload, dict):
        return False
    if not _filters(payload):
        return False
    try:
        if len(json.dumps(payload, allow_nan=False)) > 65536:
            return False
    except (TypeError, ValueError):
        return False
    for key, maximum in (("pageNum", 1000000), ("pageSize", 500)):
        value = payload.get(key)
        if value is not None and (isinstance(value, bool) or not str(value).isdecimal() or not 1 <= int(value) <= maximum):
            return False
    if "searchType" in payload and (type(payload["searchType"]) is not int or payload["searchType"] not in (1, 2)):
        return False
    return "checkHasData" not in payload or isinstance(payload["checkHasData"], bool)


def validate_response(method: str, url: str, payload, result):
    """Validate known list envelopes before a contract selects data/rows.

    Returns page metadata for known lists, None for other protocols. The official
    UI handles total=-1 (not yet counted); it must remain unknown, never zero.
    """
    parts = _strict_parts(url)
    if (not parts or parts.hostname not in GOODS_READ_HOSTS
            or not ((method == "POST" and parts.path in _POST_LIST_PATHS) or (method == "GET" and parts.path == SUPPLIER_OPTIONS_PATH))):
        return None
    invalid = ConnectorError("DRP_READ_RESPONSE_INVALID", "分销商品查询未返回已核实的成功列表，请检查本人权限和查询响应；不能视为空列表。")
    if not isinstance(result, dict) or result.get("status") != 200:
        raise invalid
    try:
        data = json.loads(result["text"])
    except (KeyError, TypeError, ValueError):
        raise invalid from None
    if isinstance(data, dict) and parts.path == SUPPLIER_GOODS_PATH and str(data.get("code")) == "202":
        raise ConnectorError("DRP_ASYNC_READ_UNADAPTED", "该供应商商品查询需要异步分页读取，当前快捷查询尚未适配；未继续提交或返回空列表，请使用通用探索核对该查询链。")
    if not isinstance(data, dict) or data.get("success") is not True or not isinstance(data.get("data"), list):
        raise invalid
    if parts.path == SUPPLIER_OPTIONS_PATH:
        return {"page": None, "page_size": None, "returned": len(data["data"]), "total": None, "has_more": None}
    if type(data.get("total")) is not int or data["total"] < -1:
        raise invalid
    payload = payload if isinstance(payload, dict) else {}
    page, size = payload.get("pageNum"), payload.get("pageSize")
    page = int(page) if not isinstance(page, bool) and str(page).isdecimal() and int(page) > 0 else None
    size = int(size) if not isinstance(size, bool) and str(size).isdecimal() and int(size) > 0 else None
    total = data["total"] if data["total"] >= 0 else None
    return {"page": page, "page_size": size, "returned": len(data["data"]), "total": total,
            "has_more": page * size < total if page is not None and size is not None and total is not None else None}
