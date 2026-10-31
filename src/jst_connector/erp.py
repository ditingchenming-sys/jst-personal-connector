"""有源码依据的 ERP 只读适配，所有生产能力仍待本人真实验收。"""
from __future__ import annotations

import json
import re
from datetime import date
from html.parser import HTMLParser
from urllib.parse import urlencode

from .adapters import FMS_BASE, ITEM_URL, ORDER_URL, PURCHASE_URL, QUERY_NAMES, WRITE_NAMES
from .browser import redact
from .errors import ConnectorError

ADAPTED = {"Q02", "Q04", "Q09", "Q10", "Q11", "Q13"}
PARAMETERS = {
    "Q02": {"style_ids": "款号列表", "unique_code": "唯一码（精确筛选）", "include_related": "展开同唯一码关联款",
            "max_pages": "最多读取页数，默认20，最大200"},
    "Q04": {"supplier_ids": "供应商编号列表", "statuses": "采购单状态列表", "max_pages": "最多读取页数"},
    "Q09": {"supplier_id": "供应商编号", "purchase_ids": "可选采购单号列表", "max_pages": "最多读取页数"},
    "Q10": {"kind": "headers/items/paid/invoices，默认headers", "payable_ids": "应付单号列表",
            "begin_date": "付款记录开始日期", "end_date": "付款记录结束日期", "max_pages": "最多读取页数"},
    "Q11": {"kind": "payments/detail/prepay_items/undeducted，默认payments", "supplier_id": "供应商编号",
            "payment_id": "付款单号", "max_pages": "最多读取页数"},
    "Q13": {"order_id": "单个精确ERP内部订单号"},
}


class _Hidden(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("type", "").lower() == "hidden" and attrs.get("name"):
            self.fields[attrs["name"]] = attrs.get("value", "")


def _fail(message, code="ERP_RESPONSE_INVALID"):
    raise ConnectorError(code, message)


def _json(text):
    try:
        result = json.loads(text)
    except (ValueError, TypeError):
        _fail("聚水潭返回格式异常，不能据此判定业务结果。")
    if not isinstance(result, dict):
        _fail("聚水潭未返回预期的结构化对象。")
    return result


def _id(value, label):
    if isinstance(value, bool) or not isinstance(value, (str, int)) or not re.fullmatch(r"[0-9]+", str(value)):
        _fail(f"{label}必须是单个非空数字编号。", "INVALID_PARAMETERS")
    return str(value)


def _ids(value, label):
    if not isinstance(value, list) or not value or len(value) > 100:
        _fail(f"{label}须为1至100个编号的列表。", "INVALID_PARAMETERS")
    result = [_id(v, label) for v in value]
    if len(set(result)) != len(result):
        _fail(f"{label}不能包含重复编号。", "INVALID_PARAMETERS")
    return result


def _strings(value, label):
    if (not isinstance(value, list) or not value or len(value) > 100
            or any(not isinstance(v, str) or not v.strip() or "," in v or len(v) > 100 for v in value)):
        _fail(f"{label}须为1至100个非空文本的列表，单项不能含逗号。", "INVALID_PARAMETERS")
    return list(dict.fromkeys(v.strip() for v in value))


def _integer(value, label, minimum=0):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        _fail(f"{label}格式无效。")
    try:
        number = int(value)
    except ValueError:
        _fail(f"{label}格式无效。")
    if number < minimum:
        _fail(f"{label}超出有效范围。")
    return number


def _callback(text):
    match = re.match(r"^(\d{1,5})\|", text)
    if match:
        remainder = text[match.end():].encode("utf-16-le")
        try:
            text = remainder[int(match.group(1)) * 2:].decode("utf-16-le")
        except UnicodeError:
            _fail("聚水潭页面回调编码异常。")
    result = _json(text)
    if result.get("GotoLogin") or result.get("IsSuccess") is not True:
        _fail("聚水潭页面查询未成功，请核对本人登录与查看权限。", "ERP_SESSION_REJECTED")
    raw = result.get("ReturnValue")
    if not isinstance(raw, str):
        _fail("聚水潭页面回调缺少查询结果。")
    try:
        return json.loads(raw)
    except ValueError:
        _fail("聚水潭页面查询结果格式异常。")


class ErpClient:
    def __init__(self, browser):
        self.browser = browser

    def catalog(self):
        scopes = {"Q02": "商品档案及同唯一码关联款；固定返回i_id/sku_id/other_1/properties_value/brand",
                  "Q04": "采购单表头列表；商品明细待适配", "Q09": "单个供应商的清算明细",
                  "Q10": "按应付单号查表头、明细、付款和发票记录", "Q11": "付款单列表/详情及预付款抵扣记录",
                  "Q13": "单个订单号精确回查线上单号和卖家备注"}
        return [{"id": key, "name": name, "kind": "query", "status": "adapted_pending_live_validation"
                 if key in ADAPTED else "included_unadapted",
                 "verification": "款号精确查询已通过真实单账号样例验证；关联查询及其他条件仍待验证" if key == "Q02" else "待真实聚水潭验证",
                 "identity_requirement": "生产组件使用固定服务器当前用户接口核实公司及员工；每次业务调用必须通过核验",
                 "adapted_scope": scopes.get(key, "已确认收录，当前尚未适配"),
                 "parameters": PARAMETERS.get(key, {})} for key, name in QUERY_NAMES.items()] + [
            {"id": key, "name": name, "kind": "write", "status": "shortcut_unadapted_use_discovery",
             "verification": "此预置快捷方式尚未适配；可从实际页面发现写请求并使用通用写入契约预览、确认与执行。", "parameters": {}}
            for key, name in WRITE_NAMES.items()]

    async def query(self, profile, capability_id, parameters):
        if capability_id not in QUERY_NAMES:
            _fail("未找到该查询能力；写入操作不能通过查询入口执行。", "UNKNOWN_CAPABILITY")
        if capability_id not in ADAPTED:
            _fail("该能力已确认收录，但当前尚未适配；不能返回模拟业务数据。", "CAPABILITY_UNADAPTED")
        if not isinstance(parameters, dict):
            _fail("查询条件必须是对象。", "INVALID_PARAMETERS")
        unknown = set(parameters) - set(PARAMETERS[capability_id])
        if unknown:
            raise ConnectorError("UNSUPPORTED_PARAMETERS", "存在尚未适配的查询条件，未执行查询。",
                                 details={"parameters": sorted(unknown)})
        pages = parameters.get("max_pages", 20)
        if type(pages) is not int or not 1 <= pages <= 200:
            _fail("最多读取页数必须是1至200的整数。", "INVALID_PARAMETERS")
        async with self.browser.verified_scope(profile) as identity:
            handler = getattr(self, f"_{capability_id.lower()}")
            result = await handler(profile, identity, parameters, pages)
            result.update(capability_id=capability_id, identity=identity, filters=dict(parameters),
                          verification="待真实聚水潭验证")
        return redact(result)

    async def preview(self, profile, capability_id, parameters):
        if capability_id not in WRITE_NAMES:
            _fail("未找到该写入能力。", "UNKNOWN_CAPABILITY")
        _fail("此预置快捷方式尚未适配，请从实际页面发现请求并使用通用写入契约预览；不是业务类型限制。", "WRITE_SHORTCUT_UNADAPTED")

    async def _request_json(self, profile, url, payload):
        response = await self.browser.request(profile, "POST", url, payload)
        result = _json(response["text"])
        if result.get("code") != 0:
            _fail("聚水潭查询未成功，请核对本人会话及查看权限。", "ERP_QUERY_REJECTED")
        return result

    def _check_rows(self, rows, identity, seen, key=None):
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            _fail("聚水潭缺少预期的明细列表。")
        for row in rows:
            for field in ("co_id", "coId", "companyId"):
                if row.get(field) not in (None, "") and str(row[field]) != identity["company_id"]:
                    _fail("聚水潭返回了当前公司范围外的数据，已阻断。", "TENANT_MISMATCH")
            if key:
                row_id = str(row.get(key) or "")
                if not row_id or row_id in seen:
                    _fail("聚水潭分页出现空主键或重复记录，完整性无法确认。", "PAGINATION_INVALID")
                seen.add(row_id)
            else:
                fingerprint = json.dumps(row, ensure_ascii=False, sort_keys=True)
                if fingerprint in seen:
                    _fail("聚水潭分页返回重复记录，不能确认完整性。", "PAGINATION_INVALID")
                seen.add(fingerprint)

    async def _items(self, profile, identity, filters, max_pages):
        url = ITEM_URL + "?" + urlencode({"__from": "web_component", "owner_co_id": identity["company_id"],
                                        "authorize_co_id": identity["company_id"]})
        rows, seen, total = [], set(), None
        for number in range(1, max_pages + 1):
            result = await self._request_json(profile, url, {
                "page": {"currentPage": number, "pageSize": 50, "pageAction": 1},
                "data": {"sku_type": 1, "enabled": "1,0", "c_id": "", "orderBy": "", "isMainDB": True,
                         **filters, "queryFlds": ["i_id", "sku_id", "other_1", "properties_value", "brand"]}})
            part = result.get("data")
            info = result.get("page") or {}
            if not isinstance(info, dict):
                _fail("商品查询分页结构异常。")
            if "pageSize" in info and _integer(info["pageSize"], "分页大小", 1) != 50:
                _fail("商品查询分页大小发生变化。", "PAGINATION_INVALID")
            if "currentPage" in info and _integer(info["currentPage"], "当前页", 1) != number:
                _fail("商品查询页码与请求不一致。", "PAGINATION_INVALID")
            count = info.get("count")
            if count is not None and count not in (-1, "-1"):
                count = _integer(count, "商品总数")
                if total is not None and total != count:
                    _fail("商品总数在读取期间变化。", "PAGINATION_INVALID")
                total = count
            self._check_rows(part, identity, seen, "sku_id")
            if any(not row.get("i_id") for row in part) or len(part) > 50:
                _fail("商品查询缺少款号或超过单页范围。")
            rows.extend(part)
            if len(part) < 50:
                if total is not None and len(rows) != total:
                    _fail("商品查询提前结束，总数与实取数量不一致。", "PAGINATION_INVALID")
                return {"rows": rows, "total": total, "complete": True, "has_more": False,
                        "pages_read": number, "completeness_evidence": "按源码约定逐页读取至不足50行，校验主键及总数"}
        return {"rows": rows, "total": total, "complete": False, "has_more": True,
                "pages_read": max_pages, "completeness_evidence": "达到调用方页数上限，结果尚未完整"}

    async def _q02(self, profile, identity, p, max_pages):
        if ("style_ids" in p) == ("unique_code" in p):
            _fail("请提供款号列表或单个唯一码，两者选一。", "INVALID_PARAMETERS")
        if "include_related" in p and type(p["include_related"]) is not bool:
            _fail("关联商品选项必须是布尔值。", "INVALID_PARAMETERS")
        if p.get("style_ids"):
            styles = _strings(p["style_ids"], "款号")
            result = await self._items(profile, identity, {"i_id": ",".join(styles)}, max_pages)
            if any(str(row["i_id"]) not in styles for row in result["rows"]):
                _fail("商品查询返回了指定款号范围外的数据。", "ERP_FILTER_MISMATCH")
        else:
            code = p["unique_code"]
            if not isinstance(code, str) or not code.strip() or len(code) > 100:
                _fail("唯一码必须是1至100字的非空文本。", "INVALID_PARAMETERS")
            result = await self._items(profile, identity, {"other_1": code.strip()}, max_pages)
            result["rows"] = [row for row in result["rows"] if str(row.get("other_1") or "").strip() == code.strip()]
            result["source_total"] = result.pop("total")
            result["total"] = len(result["rows"]) if result["complete"] else None
        if p.get("include_related"):
            if not result["complete"]:
                _fail("初始商品结果尚不完整，不能展开关联款。", "PAGINATION_INCOMPLETE")
            merged = {str(row["sku_id"]): row for row in result["rows"]}
            codes = {str(row.get("other_1") or "").strip() for row in result["rows"]} - {""}
            for code in sorted(codes):
                related = await self._items(profile, identity, {"other_1": code}, max_pages)
                if not related["complete"]:
                    _fail("关联款结果超出页数上限，不能当作完整关联。", "PAGINATION_INCOMPLETE")
                selected = [row for row in related["rows"] if str(row.get("other_1") or "").strip() == code]
                if not {str(row["sku_id"]) for row in merged.values() if str(row.get("other_1") or "").strip() == code}.issubset(
                        {str(row["sku_id"]) for row in selected}):
                    _fail("关联查询未覆盖原始商品，无法确认完整性。")
                merged.update({str(row["sku_id"]): row for row in selected})
            result.update(rows=list(merged.values()), total=len(merged))
        result["fields"] = ["i_id", "sku_id", "other_1", "properties_value", "brand"]
        return result

    async def _hidden(self, profile, url):
        response = await self.browser.request(profile, "GET", url)
        parser = _Hidden()
        parser.feed(response["text"])
        if "__VIEWSTATE" not in parser.fields:
            _fail("聚水潭页面缺少查询凭据，请核实本人登录与权限。", "ERP_SESSION_REJECTED")
        return parser.fields

    async def _page_callback(self, profile, url, form, method, args):
        body = {**form, "__CALLBACKID": "JTable1", "__CALLBACKPARAM": json.dumps(
            {"Method": method, "Args": args, "CallControl": "{page}"}, ensure_ascii=False)}
        response = await self.browser.request(profile, "POST", url + "?" + urlencode({"am___": method}), body)
        return _callback(response["text"])

    async def _q04(self, profile, identity, p, max_pages):
        filters = []
        suppliers = _ids(p["supplier_ids"], "供应商编号") if "supplier_ids" in p else None
        statuses = _strings(p["statuses"], "采购状态") if "statuses" in p else None
        if suppliers:
            filters.append({"k": "seller_id", "v": ",".join(suppliers), "c": "@=", "t": ""})
        if statuses:
            filters.append({"k": "status", "v": ",".join(statuses), "c": "@=", "t": ""})
        form = await self._hidden(profile, PURCHASE_URL)
        rows, seen, total = [], set(), None
        for number in range(1, max_pages + 1):
            result = await self._page_callback(profile, PURCHASE_URL, form, "LoadDataToJSON",
                                               [str(number), json.dumps(filters), "{}"])
            if not isinstance(result, dict) or not isinstance(result.get("dp"), dict):
                _fail("采购单返回缺少分页信息。")
            info, part = result["dp"], result.get("datas")
            count = _integer(info.get("DataCount"), "采购单总数")
            if total is not None and total != count:
                _fail("采购单总数在读取期间变化。", "PAGINATION_INVALID")
            total = count
            self._check_rows(part, identity, seen, "po_id")
            if suppliers and any(str(row.get("seller_id")) not in suppliers for row in part):
                _fail("采购单供应商与查询条件不一致。", "ERP_FILTER_MISMATCH")
            if statuses and any(str(row.get("status_v")) not in statuses for row in part):
                _fail("采购单状态与查询条件不一致。", "ERP_FILTER_MISMATCH")
            rows.extend(part)
            if len(rows) > total:
                _fail("采购单实取数量超过总数。", "PAGINATION_INVALID")
            if len(rows) == total:
                return {"rows": rows, "total": total, "complete": True, "has_more": False,
                        "pages_read": number, "scope": "采购表头列表，未包含商品明细"}
            if not part or info.get("IsLast") or ("PageCount" in info and number >= _integer(info["PageCount"], "总页数")):
                _fail("采购单分页提前结束，完整性校验失败。", "PAGINATION_INVALID")
        return {"rows": rows, "total": total, "complete": False, "has_more": True,
                "pages_read": max_pages, "scope": "采购表头列表，未包含商品明细"}

    async def _fms(self, profile, identity, path, action, data, max_pages, key, primary=None, supplier=None):
        rows, seen, total = [], set(), None
        for number in range(1, max_pages + 1):
            result = await self._request_json(profile, f"{FMS_BASE}/{path}?{action}", {
                "data": data, "page": {"currentPage": number, "pageSize": 100, "pageAction": 0}})
            payload = result.get("data")
            part = payload.get(key) if key and isinstance(payload, dict) else payload if not key else None
            self._check_rows(part, identity, seen, primary)
            if supplier and any(str(row.get("sellerId")) != supplier for row in part):
                _fail("返回记录的供应商与查询条件不一致。", "ERP_FILTER_MISMATCH")
            info = result.get("page")
            if not isinstance(info, dict):
                _fail("财务查询缺少分页信息，不能确认完整性。", "PAGINATION_INVALID")
            count = _integer(info.get("count"), "财务记录总数")
            current = _integer(info.get("currentPage"), "当前页", 1)
            if current != number or (total is not None and total != count):
                _fail("财务查询页码或总数发生变化。", "PAGINATION_INVALID")
            total = count
            rows.extend(part)
            if len(rows) > total:
                _fail("财务记录实取数量超过总数。", "PAGINATION_INVALID")
            if len(rows) == total:
                return {"rows": rows, "total": total, "complete": True, "has_more": False, "pages_read": number}
            if not part or ("pages" in info and number >= _integer(info["pages"], "总页数")):
                _fail("财务查询分页提前结束，完整性校验失败。", "PAGINATION_INVALID")
        return {"rows": rows, "total": total, "complete": False, "has_more": True, "pages_read": max_pages}

    async def _q09(self, profile, identity, p, max_pages):
        supplier = _id(p.get("supplier_id"), "供应商编号")
        data = {"sellerIds": [int(supplier)], "poIds": [], "ioIds": [], "dateType": 0,
                "skuCategoryIds": [], "iIds": [], "propertiesValues": [], "writeOffStatus": [0, 1, 2],
                "remark": "", "aggTypes": [], "skuSns": [], "mergeSoIds": [], "outIoIds": [], "agingDaysType": 0}
        if "purchase_ids" in p:
            data["poIds"] = [int(v) for v in _ids(p["purchase_ids"], "采购单号")]
        result = await self._fms(profile, identity, "supplierclear", "getSupplierClearInoutList", data,
                                 max_pages, "data", "ioiId", supplier)
        if data["poIds"] and any(str(row.get("poId")) not in {str(v) for v in data["poIds"]} for row in result["rows"]):
            _fail("供应商清算返回了指定采购单范围外的数据。", "ERP_FILTER_MISMATCH")
        result["date_scope"] = "未设置日期筛选，按ERP当前可见清算记录返回"
        return result

    async def _q10(self, profile, identity, p, max_pages):
        ids = _ids(p.get("payable_ids"), "应付单号")
        data = {"pinvIds": [int(v) for v in ids]}
        kind = p.get("kind", "headers")
        if kind != "paid" and {"begin_date", "end_date"} & set(p):
            _fail("当前日期条件仅适用于应付付款记录查询。", "UNSUPPORTED_PARAMETERS")
        if kind == "items":
            result = await self._request_json(profile, f"{FMS_BASE}/common?getPayableItemList", {"data": data})
            rows = result.get("data")
            self._check_rows(rows, identity, set())
            return {"rows": rows, "total": None, "complete": False, "has_more": None,
                    "message": "原接口未证明明细总数及截断约定，当前仅返回已取得明细。"}
        variants = {"headers": ("payable", "getPayableList", "pageData"),
                    "paid": ("payablereport", "getPayablePaidTransactionReport", "list"),
                    "invoices": ("payablereport", "getPayableInvoiceReport", "list")}
        if kind not in variants:
            _fail("应付查询种类仅支持headers/items/paid/invoices。", "INVALID_PARAMETERS")
        if kind == "paid":
            try:
                begin, end = date.fromisoformat(p["begin_date"]), date.fromisoformat(p["end_date"])
                if begin > end:
                    raise ValueError()
            except (KeyError, ValueError, TypeError):
                _fail("应付付款记录须提供有效的起止日期，格式为年-月-日。", "INVALID_PARAMETERS")
            data.update(beginDate=begin.isoformat(), endDate=end.isoformat())
        path, action, key = variants[kind]
        result = await self._fms(profile, identity, path, action, data, max_pages, key)
        if any(str(row.get("pinvId") or row.get("pinv_id") or "") not in ids for row in result["rows"]):
            _fail("应付查询未能确认返回记录属于指定应付单，已阻断。", "ERP_FILTER_MISMATCH")
        return result

    async def _q11(self, profile, identity, p, max_pages):
        kind = p.get("kind", "payments")
        supplier = _id(p.get("supplier_id"), "供应商编号")
        if kind == "payments":
            if "payment_id" in p:
                _fail("付款单列表尚未适配单号条件，请使用detail查询。", "UNSUPPORTED_PARAMETERS")
            data = {k: [] for k in ("sellerIds", "payIds", "pinvIds", "perPayIds", "poIds", "inIoIds",
                                         "feeIds", "accountIds", "includeLabels", "excludeLabels")}
            data["sellerIds"] = [int(supplier)]
            return await self._fms(profile, identity, "payment", "getPaymentList", data, max_pages,
                                   "pageData", "payId", supplier)
        payment = _id(p.get("payment_id"), "付款单号")
        if kind == "detail":
            result = await self._request_json(profile, f"{FMS_BASE}/payment?getPayment", {"data": {"payid": int(payment)}})
            row = result.get("data")
            self._check_rows([row], identity, set())
            if str(row.get("payId") or row.get("payid")) != payment or str(row.get("sellerId")) != supplier:
                _fail("付款单详情的单号或供应商与查询条件不一致。", "ERP_FILTER_MISMATCH")
            return {"rows": [row], "total": 1, "complete": True, "has_more": False}
        if kind == "prepay_items":
            # Verify supplier ownership before querying a child endpoint that only accepts payId.
            await self._q11(profile, identity, {"kind": "detail", "supplier_id": supplier, "payment_id": payment}, max_pages)
            return await self._fms(profile, identity, "payment", "getPrepayItemList", {"payId": int(payment)},
                                   max_pages, "pageData", "payItemId")
        if kind == "undeducted":
            result = await self._fms(profile, identity, "payment", "getPrepayUnDeductedList",
                                     {"sellerIds": [int(supplier)], "deductedPayId": 0, "payIds": [int(payment)]},
                                     max_pages, None, "payId", supplier)
            if any(str(row.get("payId")) != payment for row in result["rows"]):
                _fail("预付款未抵扣查询返回了指定付款单范围外的数据。", "ERP_FILTER_MISMATCH")
            return result
        _fail("付款查询种类仅支持payments/detail/prepay_items/undeducted。", "INVALID_PARAMETERS")

    async def _q13(self, profile, identity, p, max_pages):
        requested = _id(p.get("order_id"), "ERP内部订单号")
        form = await self._hidden(profile, ORDER_URL)
        rows = await self._page_callback(profile, ORDER_URL, form, "ReloadOrdersWithFlds", [requested, "o_id,so_id,remark"])
        self._check_rows(rows, identity, set(), "o_id")
        if len(rows) != 1 or str(rows[0].get("o_id")) != requested:
            _fail("聚水潭未返回唯一的指定订单，不能确认备注结果。", "ERP_FILTER_MISMATCH")
        row = rows[0]
        if "remark" not in row or (row["remark"] is not None and not isinstance(row["remark"], str)):
            _fail("聚水潭订单备注字段缺失或格式异常。")
        online = row.get("so_id")
        if online is not None and (isinstance(online, bool) or not isinstance(online, (str, int))):
            _fail("聚水潭线上单号字段格式异常。")
        return {"rows": [{"o_id": requested, "so_id": str(online) if online is not None else None,
                          "remark": row["remark"]}], "total": 1, "complete": True, "has_more": False}
