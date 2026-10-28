"""按当前连接的只读授权保存和验证接口契约；发现本身不发送业务请求。"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import math
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from .adapters import ORDER_URL, PURCHASE_URL
from .adapters.login import ENTRY_URL
from .errors import ConnectorError
from .vault import _json

_HOSTS = {"www.erp321.com", "src.erp321.com", "api.erp321.com", "apiweb.erp321.com"}
_BUILTINS = {ENTRY_URL, ORDER_URL, PURCHASE_URL}
_SECRET = re.compile(r"pass|pwd|cookie|authorization|token|secret|credential|session|viewstate|eventvalidation|nonce|csrf|xsrf|captcha|ticket|signature|api.?key|u_cid", re.IGNORECASE)
_IDENTITY = {"uid", "user_id", "userid", "coid", "co_id", "company_id", "companyid", "u_id", "u_co_id",
             "owner_co_id", "authorize_co_id", "ownercoid", "authorizecoid"}
_WRITE = re.compile(r"^(?:save|create|insert|update|delete|remove|submit|approve|audit|cancel|logout|signoff|reset|send|export|execute|commit|modify)", re.IGNORECASE)
_READ = re.compile(r"^(?:get|query|search|list|load|find|fetch|read|select|lookup|count|report|reload|查询|搜索|查找)", re.IGNORECASE)
_TYPES = {"object", "array", "string", "integer", "number", "boolean", "null"}
_BINDINGS = {"user_id", "company_id", "u_cid_ajax"}
_HEADER = {"content-type", "x-requested-with", "action-name", "referer"}
_AUTH_PATH = re.compile(r"passport|login|oauth|usercenter|authentication|verification|captcha", re.IGNORECASE)
_ACTION_FIELDS = {"method", "action", "operation", "am___", "__callbackid", "__callbackparam", "callcontrol"}
_SERIALIZED_CONTAINERS = {"data", "payload", "params", "parameters", "request", "args", "body", "__callbackparam"}
_IMMUTABLE = ("interface_id", "profile", "identity", "session_binding", "kind", "url", "name", "purpose",
              "descriptor", "parameters", "response_rules", "read_evidence", "created_at")


def _operation_kind(value):
    value = str(value)
    # Querying GetPayment/GetAuditList/GetUpdateLog is not a payment/audit/update.
    # An explicit combined dispatch such as GetAndSubmit is still a write action.
    if re.search(r"(?:And|Then)(?:Save|Create|Update|Delete|Submit|Approve|Audit|Send|Pay|Commit)", value, re.IGNORECASE):
        return "write"
    if _READ.search(value):
        return "query"
    if (_WRITE.search(value) or re.fullmatch(r"(?:save|create|insert|update|delete|remove|submit|approve|audit|cancel|logout|signoff|reset|send|export|execute|commit|modify|pay)(?:[_-].*)?", value, re.IGNORECASE)
            or re.match(r"^pay[A-Z]", value, re.IGNORECASE)):
        return "write"
    return "unclassified"


def _fail(message, code="INTERFACE_INVALID"):
    raise ConnectorError(code, message)


def _url(value, *, entry=False):
    if not isinstance(value, str) or len(value) > 2048:
        _fail("接口或页面地址无效。")
    try:
        p = urlsplit(value)
        valid = (p.scheme == "https" and p.hostname in _HOSTS and p.port in (None, 443)
                 and not p.username and not p.password and not p.fragment and p.path.startswith("/"))
    except ValueError:
        valid = False
    if not valid or "\\" in value or any(ord(c) < 32 for c in value):
        _fail("仅支持已知聚水潭HTTPS域内的明确地址，不跟随重定向。")
    if entry:
        if p.query:
            _fail("本轮页面探索入口暂不支持查询串，请使用明确的无查询串页面入口。")
        if (_AUTH_PATH.search(p.path) or re.search(r"logout|logoff|signout|signoff", p.path, re.IGNORECASE)
                or any(_operation_kind(part.split(".", 1)[0]) == "write" for part in p.path.split("/") if part)
                or not (value in _BUILTINS or p.path.lower().endswith((".aspx", ".html", ".htm")))):
            _fail("该地址不是可读取的普通ERP页面入口。")
    elif p.query:
        _fail("接口地址不得夹带查询串，查询字段须保存在固定请求结构中。")
    return value


def _parts(path):
    if not isinstance(path, str) or (path and not path.startswith("/")) or len(path) > 512:
        _fail("字段路径必须是JSON pointer。")
    result = [] if not path else path[1:].split("/")
    if any(re.search(r"~(?![01])", p) for p in result):
        _fail("字段路径转义无效。")
    return [p.replace("~1", "/").replace("~0", "~") for p in result]


def _at(value, path):
    for part in _parts(path):
        try:
            value = value[int(part)] if isinstance(value, list) and part.isdecimal() else value[part]
        except (KeyError, IndexError, TypeError):
            _fail("请求或响应缺少约定字段。", "INTERFACE_SHAPE_CHANGED")
    return value


def _put(value, path, item):
    parts = _parts(path)
    if not parts:
        _fail("不能替换整个请求。")
    parent = _at(value, "/" + "/".join(p.replace("~", "~0").replace("/", "~1") for p in parts[:-1])) if len(parts) > 1 else value
    key = parts[-1]
    if isinstance(parent, list) and key.isdecimal():
        parent[int(key)] = item
    elif isinstance(parent, dict) and key in parent:
        parent[key] = item
    else:
        _fail("可变字段必须已存在于观察到的请求中。")


def _type(value):
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is float:
        return "number"
    return "string" if isinstance(value, str) else "array" if isinstance(value, list) else "object" if isinstance(value, dict) else "unknown"


def _shape(value):
    if isinstance(value, dict):
        return {k: _shape(v) for k, v in value.items()}
    if isinstance(value, list):
        shapes = {_json(_shape(v)).decode() for v in value}
        return {"type": "array", "items": sorted(shapes)}
    return "number" if _type(value) == "integer" else _type(value)


def _shape_matches(expected, actual):
    if isinstance(expected, dict) and isinstance(actual, dict):
        if expected.get("type") == actual.get("type") == "array":
            old, new = expected["items"], actual["items"]
            return not old or not new or all(any(_shape_matches(json.loads(a), json.loads(b)) for a in old) for b in new)
        return set(expected) == set(actual) and all(_shape_matches(expected[k], actual[k]) for k in expected)
    return expected == actual


def _safe_data(value):
    if isinstance(value, dict):
        return {key: _safe_data(item) for key, item in value.items() if not _SECRET.search(str(key))}
    if isinstance(value, list):
        return [_safe_data(item) for item in value]
    return value


def _reject_serialized_container(value):
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return
        if isinstance(parsed, (dict, list)):
            _fail("请求含尚未解码的结构化字符串，须先适配固定编码，不能把内部动作或凭据作为业务文本。")


class InterfaceRegistry:
    def __init__(self, root, vault, browser, discovery):
        self.root, self.vault, self.browser, self.discovery = Path(root), vault, browser, discovery
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.root / "interfaces.sqlite3"
        self._locks = {}
        with self._connection() as c:
            c.execute("CREATE TABLE IF NOT EXISTS interfaces (id TEXT PRIMARY KEY,profile TEXT NOT NULL,encrypted TEXT NOT NULL)")
        self.path.chmod(0o600)

    @contextmanager
    def _connection(self, write=False):
        c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            if write:
                c.execute("BEGIN IMMEDIATE")
            yield c
            if write:
                c.commit()
        except BaseException:
            if write:
                c.rollback()
            raise
        finally:
            c.close()

    @staticmethod
    def _digest(record):
        return hashlib.sha256(_json({k: record.get(k) for k in _IMMUTABLE})).hexdigest()

    def _session(self, profile):
        before = self.vault.session_binding(profile)
        saved = self.vault.load_session(profile)
        binding = self.vault.session_binding(profile)
        if before != binding:
            _fail("账号资料正在变化，请重新核验。", "INTERFACE_SESSION_CHANGED")
        if not saved or not binding:
            _fail("请先连接并核实本人账号。", "LOGIN_REQUIRED")
        return saved["identity"], binding

    def _assert_current(self, record):
        identity, binding = self._session(record["profile"])
        if identity != record["identity"] or binding != record["session_binding"]:
            _fail("接口契约所绑定的账号会话已变化，请重新发现并审核。", "INTERFACE_SESSION_CHANGED")

    def _read(self, c, profile, identifier):
        row = c.execute("SELECT encrypted FROM interfaces WHERE id=? AND profile=?", (identifier, profile)).fetchone()
        if row is None:
            _fail("找不到当前调用端的接口或入口契约。", "INTERFACE_NOT_FOUND")
        record = self.vault.unseal(row[0])
        if (not isinstance(record, dict) or record.get("interface_id") != identifier or record.get("profile") != profile
                or not secrets.compare_digest(str(record.get("digest", "")), self._digest(record))):
            _fail("接口契约完整性校验失败。")
        return record

    def _write(self, c, record):
        c.execute("INSERT INTO interfaces VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET encrypted=excluded.encrypted",
                  (record["interface_id"], record["profile"], self.vault.seal(record)))

    def _new(self, profile, kind, **values):
        identity, binding = self._session(profile)
        record = {"interface_id": secrets.token_urlsafe(18), "profile": profile, "identity": identity,
                  "session_binding": binding, "kind": kind, "created_at": time.time(), **values}
        record["digest"] = self._digest(record)
        with self._connection(True) as c:
            self._write(c, record)
        return self._public(record)

    @staticmethod
    def _public(record):
        result = {k: copy.deepcopy(v) for k, v in record.items() if k != "session_binding"}
        if result["kind"] == "entry":
            result["entry_id"] = result["interface_id"]
        return result

    def get(self, profile, identifier):
        with self._connection() as c:
            record = self._read(c, profile, identifier)
        identity, binding = self._session(profile)
        if identity != record["identity"]:
            _fail("找不到当前账号的接口或入口契约。", "INTERFACE_NOT_FOUND")
        if binding != record["session_binding"]:
            return {"interface_id": identifier, "entry_id": identifier if record["kind"] == "entry" else None,
                    "kind": record["kind"], "name": record.get("name", ""), "status": "invalidated",
                    "reason": "原账号会话已变化，请重新发现并审核。"}
        return self._public(record)

    def list(self, profile, query=""):
        if not isinstance(query, str) or len(query) > 2000:
            _fail("接口搜索条件必须是短文本。")
        try:
            before = self._session(profile)
        except ConnectorError:
            return []
        with self._connection() as c:
            ids = [r[0] for r in c.execute("SELECT id FROM interfaces WHERE profile=?", (profile,))]
        records = []
        for identifier in ids:
            try:
                records.append(self.get(profile, identifier))
            except ConnectorError as error:
                if error.code not in {"INTERFACE_NOT_FOUND", "LOGIN_REQUIRED", "INTERFACE_SESSION_CHANGED"}:
                    raise
        try:
            if self._session(profile) != before:
                return []
        except ConnectorError:
            return []
        return [r for r in records if not query or query.casefold() in (r.get("name", "")+r.get("purpose", "")+r["interface_id"]).casefold()]

    async def request_entry(self, profile, url, purpose):
        identity = await self.browser.identity(profile)
        current, _ = self._session(profile)
        if identity != current:
            _fail("账号已变化，未创建页面入口。", "INTERFACE_SESSION_CHANGED")
        url = _url(url, entry=True)
        self._text(purpose, "探索用途")
        return {"entry_id": None, "interface_id": None, "kind": "entry", "status": "builtin" if url in _BUILTINS else "connection_read_authorized",
                "url": url, "digest": None}

    def entry_allowed(self, profile, url):
        try:
            self._session(profile)
            _url(url, entry=True)
        except ConnectorError:
            return False
        return True

    @staticmethod
    def _text(value, label):
        if not isinstance(value, str) or not value.strip() or len(value) > 2000:
            _fail(label+"必须是明确的非空文字。")
        return value.strip()

    def approve(self, profile, identifier, digest):
        with self._connection(True) as c:
            record = self._read(c, profile, identifier)
            self._assert_current(record)
            if not isinstance(digest, str) or not secrets.compare_digest(digest, record["digest"]):
                _fail("审核内容已变化，请重新读取后确认。", "INTERFACE_DIGEST_MISMATCH")
            if record["kind"] not in {"entry", "query"} or record["status"] not in {"pending_approval", "approved", "ready_for_validation", "approved_pending_validation", "ready"}:
                _fail("该候选未形成可确认的只读契约，不能批准。", "INTERFACE_NOT_READONLY")
            if record["status"] == "pending_approval":
                record.update(status="approved" if record["kind"] == "entry" else "approved_pending_validation", approved_at=time.time())
                self._write(c, record)
            return self._public(record)

    @staticmethod
    def _descriptor(value):
        if not isinstance(value, dict):
            _fail("候选请求格式无效。")
        d = copy.deepcopy(value)
        _url(d.get("url"))
        if _AUTH_PATH.search(urlsplit(d["url"]).path) or _SECRET.search(urlsplit(d["url"]).path):
            _fail("认证和凭据接口不能保存为业务查询。")
        if d.get("method") not in {"GET", "POST"} or d.get("encoding") not in {"json", "form", "none"}:
            _fail("本轮只支持有明确结构的GET和POST只读请求。")
        if not isinstance(d.get("query"), dict) or d.get("body") is not None and not isinstance(d["body"], dict):
            _fail("候选请求查询或正文结构无效。")
        if ((d["method"] == "GET" or d["encoding"] == "none") and d.get("body") is not None
                or d["encoding"] in {"json", "form"} and not isinstance(d.get("body"), dict)):
            _fail("请求方法、编码和正文不一致，不能静默忽略已审核条件。")
        if not isinstance(d.get("headers"), dict) or any(k.casefold() not in _HEADER for k in d["headers"]):
            _fail("候选请求包含未允许保存的请求头。")
        source = d.get("source", {})
        if not isinstance(source, dict) or source.get("credential_fields"):
            _fail("候选请求有尚不能安全重建的凭据字段，不能保存。")
        if (source.get("blocked") is not True or not isinstance(d.get("request_id"), str) or not d["request_id"]
                or not isinstance(source.get("discovery_id"), str) or not source["discovery_id"]):
            _fail("缺少实际探索捕获的请求来源，不能形成只读契约。")
        _url(source.get("page_url"), entry=True)
        bindings = d.get("identity_bindings", [])
        if not isinstance(bindings, list):
            _fail("身份字段映射无效。")
        paths = set()
        for binding in bindings:
            if not isinstance(binding, dict) or binding.get("kind") not in _BINDINGS or binding.get("path") in paths:
                _fail("身份字段映射无效。")
            path = binding["path"]
            if not path.startswith(("/body/", "/query/")) or _at(d, path) is not None:
                _fail("身份和凭据原值不得进入接口契约。")
            paths.add(path)
        def protected_value(item, path):
            if isinstance(item, dict):
                return all(protected_value(v, path+"/"+str(k).replace("~", "~0").replace("/", "~1")) for k, v in item.items())
            if isinstance(item, list):
                return bool(item) and all(protected_value(v, path+"/"+str(i)) for i, v in enumerate(item))
            return item is None and path in paths
        def check(item, path=""):
            if isinstance(item, dict):
                for key, child in item.items():
                    child_path = path+"/"+str(key).replace("~", "~0").replace("/", "~1")
                    if (_SECRET.search(str(key)) or str(key).casefold() in _IDENTITY) and not protected_value(child, child_path):
                        _fail("身份或认证字段必须由当前组件重建，不能保存固定原值。")
                    check(child, child_path)
            elif isinstance(item, list):
                for i, child in enumerate(item):
                    check(child, path+"/"+str(i))
            else:
                _reject_serialized_container(item)
        check(d.get("query"), "/query")
        check(d.get("body"), "/body")
        return d

    @staticmethod
    def _rules(rules):
        if not isinstance(rules, dict) or set(rules)-{"success", "required", "data_path"}:
            _fail("响应规则格式无效。")
        rules = copy.deepcopy(rules)
        if not isinstance(rules.get("required"), list) or not rules["required"] or len(rules["required"]) > 32:
            _fail("至少声明一个响应字段及其类型，避免把失败当空数据。")
        for rule in rules["required"]:
            if not isinstance(rule, dict) or set(rule) != {"path", "type"} or rule["type"] not in _TYPES:
                _fail("响应必需字段规则无效。")
            _parts(rule["path"])
        assertions = rules.setdefault("success", [])
        if not isinstance(assertions, list) or len(assertions) > 16:
            _fail("响应成功规则无效。")
        for rule in assertions:
            if not isinstance(rule, dict) or set(rule) != {"path", "equals"} or isinstance(rule["equals"], (dict, list)):
                _fail("响应成功规则只支持明确标量相等。")
            _parts(rule["path"])
        _parts(rules.setdefault("data_path", ""))
        return rules

    @staticmethod
    def _parameters(parameters, descriptor):
        if not isinstance(parameters, list) or len(parameters) > 32:
            _fail("参数定义须为最多32项的列表。")
        result, names, paths = [], set(), set()
        for p in copy.deepcopy(parameters):
            if (not isinstance(p, dict) or set(p)-{"name", "path", "type", "required", "default", "max_length", "minimum", "maximum", "item_type", "max_items"}
                    or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", str(p.get("name", "")))
                    or p.get("type") not in {"string", "integer", "number", "boolean", "array"}
                    or p["name"] in names or p.get("path") in paths):
                _fail("业务参数定义无效或重复。")
            parts = _parts(p.get("path"))
            if (len(parts) < 2 or parts[0] not in {"body", "query"}
                    or any(_SECRET.search(x) or x.casefold() in _IDENTITY for x in parts)
                    or any(x.casefold() in _ACTION_FIELDS-{"__callbackparam"} for x in parts)
                    or parts[-1].casefold() == "__callbackparam"):
                _fail("业务参数不能更改地址、请求头、身份或凭据。")
            if p["type"] == "string" and parts[-1].casefold() in _SERIALIZED_CONTAINERS:
                _fail("结构化容器不能整体作为字符串业务参数。")
            for bound in descriptor.get("identity_bindings", []):
                if bound["path"].startswith(p["path"]+"/") or p["path"].startswith(bound["path"]+"/") or bound["path"] == p["path"]:
                    _fail("业务参数不能覆盖身份映射。")
            original_type = _type(_at(descriptor, p["path"]))
            if original_type not in {p["type"], "null"} and not (p["type"] == "number" and original_type == "integer"):
                _fail("业务参数类型必须与已观察请求中的字段一致。")
            if p["type"] == "array" and p.get("item_type") not in {"string", "integer", "number", "boolean"}:
                _fail("数组业务参数必须声明基础元素类型。")
            for key, limit in (("max_length", 2000), ("max_items", 100)):
                if key in p and (type(p[key]) is not int or not 1 <= p[key] <= limit):
                    _fail("业务参数大小限制无效。")
            if "required" in p and type(p["required"]) is not bool:
                _fail("参数required必须是布尔值。")
            for key in ("minimum", "maximum"):
                if key in p and (type(p[key]) not in (int, float) or not math.isfinite(p[key])):
                    _fail("参数数值范围必须是有限数值。")
            if p.get("minimum", -1_000_000_000) > p.get("maximum", 1_000_000_000):
                _fail("参数最小值不能大于最大值。")
            if "default" in p:
                InterfaceRegistry._parameter_value(p, p["default"])
            names.add(p["name"]); paths.add(p["path"]); result.append(p)
        return result

    @staticmethod
    def _classify(descriptor, read_evidence):
        if not isinstance(read_evidence, dict) or set(read_evidence)-{"source_url", "description", "query_action"}:
            _fail("只读依据须包含来源地址和具体说明。")
        InterfaceRegistry._text(read_evidence.get("description"), "只读依据")
        if read_evidence.get("source_url") != descriptor["source"]["page_url"]:
            _fail("只读依据必须来自本次实际探索的官方页面。")
        selectors = [urlsplit(descriptor["url"]).path.rsplit("/", 1)[-1], *descriptor["query"].keys()]
        for key, values in descriptor["query"].items():
            if key.casefold() in _ACTION_FIELDS:
                selectors.extend(str(v) for v in values if isinstance(v, str))
        selectors += [str(v) for k, v in descriptor["headers"].items() if k.casefold() == "action-name"]
        def actions(v):
            if isinstance(v, dict):
                return [str(x) for k, x in v.items() if str(k).casefold() in {"method", "action", "operation"} and isinstance(x, str)] + [x for child in v.values() for x in actions(child)]
            if isinstance(v, list):
                return [x for child in v for x in actions(child)]
            return []
        selectors += actions(descriptor.get("body"))
        writing = any(_operation_kind(v) == "write" for v in selectors)
        reading = any(_operation_kind(v) == "query" for v in selectors)
        return "write" if writing else "query" if reading else "unclassified"

    def _recheck_contract(self, record):
        descriptor = self._descriptor(record["descriptor"])
        parameters = self._parameters(record["parameters"], descriptor)
        rules = self._rules(record["response_rules"])
        if self._classify(descriptor, record["read_evidence"]) != "query":
            _fail("保存契约缺少明确只读依据，不能根据历史查询标签执行。", "INTERFACE_NOT_READONLY")
        if (_json(descriptor) != _json(record["descriptor"]) or _json(parameters) != _json(record["parameters"])
                or _json(rules) != _json(record["response_rules"])):
            _fail("保存契约结构已变化，请重新探索并验证。", "INTERFACE_INVALID")

    async def propose(self, profile, discovery_id, request_id, name, purpose, read_evidence, parameters, response_rules):
        identity = await self.browser.identity(profile)
        before = self._session(profile)
        if identity != before[0]:
            _fail("账号会话已变化。", "INTERFACE_SESSION_CHANGED")
        descriptor = self.discovery.get_request(profile, discovery_id, request_id)
        if hasattr(descriptor, "__await__"):
            descriptor = await descriptor
        descriptor = self._descriptor(descriptor)
        if descriptor["request_id"] != request_id or descriptor["source"]["discovery_id"] != discovery_id:
            _fail("实际捕获来源与当前请求编号不一致。", "INTERFACE_INVALID")
        parameters, rules = self._parameters(parameters, descriptor), self._rules(response_rules)
        kind = self._classify(descriptor, read_evidence)
        if self._session(profile) != before:
            _fail("探索期间账号会话已变化。", "INTERFACE_SESSION_CHANGED")
        return self._new(profile, kind, url=descriptor["url"], name=self._text(name, "接口名称"),
                         purpose=self._text(purpose, "接口用途"), descriptor=descriptor, parameters=parameters,
                         response_rules=rules, read_evidence=copy.deepcopy(read_evidence),
                         status="discovered_write" if kind == "write" else "ready_for_validation" if kind == "query" else "needs_evidence")

    @staticmethod
    def _parameter_value(p, value):
        kind = p["type"]
        if _type(value) != kind and not (kind == "number" and _type(value) == "integer"):
            _fail("业务参数类型与契约定义不符。", "INVALID_PARAMETERS")
        if kind == "string" and len(value) > p.get("max_length", 2000):
            _fail("业务参数文本过长。", "INVALID_PARAMETERS")
        if kind == "string":
            _reject_serialized_container(value)
        if kind in {"number", "integer"} and (value < p.get("minimum", -1_000_000_000) or value > p.get("maximum", 1_000_000_000)):
            _fail("业务参数数值超出契约范围。", "INVALID_PARAMETERS")
        if kind == "array":
            if len(value) > p.get("max_items", 100):
                _fail("业务参数数组过长。", "INVALID_PARAMETERS")
            for child in value:
                InterfaceRegistry._parameter_value({"type": p["item_type"]}, child)
        _json(value)

    def _build(self, record, values):
        if not isinstance(values, dict) or set(values)-{p["name"] for p in record["parameters"]}:
            _fail("调用包含契约未声明的业务参数。", "INVALID_PARAMETERS")
        descriptor = copy.deepcopy(record["descriptor"])
        for p in record["parameters"]:
            if p["name"] in values:
                value = values[p["name"]]
            elif "default" in p:
                value = p["default"]
            elif p.get("required"):
                _fail("缺少已声明的必填业务参数。", "INVALID_PARAMETERS")
            else:
                continue
            self._parameter_value(p, value)
            _put(descriptor, p["path"], value)
        descriptor["_scope"] = {"profile": record["profile"], "identity": copy.deepcopy(record["identity"]),
                                "session_binding": record["session_binding"]}
        return descriptor

    async def _execute(self, profile, identifier, values, validating):
        async with self._locks.setdefault((profile, identifier), asyncio.Lock()):
            identity = await self.browser.identity(profile)
            with self._connection() as c:
                record = self._read(c, profile, identifier)
            self._assert_current(record)
            if identity != record["identity"]:
                _fail("当前公司员工与接口契约不一致。", "INTERFACE_SESSION_CHANGED")
            expected = {"ready_for_validation", "pending_approval", "approved_pending_validation", "ready"} if validating else {"ready"}
            if record["kind"] != "query" or record["status"] not in expected:
                _fail("接口尚未形成并验证明确只读契约，未发出请求。", "INTERFACE_NOT_READY")
            self._recheck_contract(record)
            descriptor = self._build(record, values)
            result = await self.discovery.execute_read(profile, descriptor)
            self._assert_current(record)
            try:
                if not isinstance(result, dict) or result.get("status") != 200 or "json" not in result.get("content_type", "").lower():
                    _fail("接口未返回约定的JSON成功响应。", "INTERFACE_RESPONSE_INVALID")
                raw = result.get("text")
                if not isinstance(raw, str) or len(raw) > 2_000_000:
                    _fail("接口响应过大或格式无效，请收窄范围。", "INTERFACE_RESPONSE_INVALID")
                value = json.loads(raw)
                for assertion in record["response_rules"]["success"]:
                    actual = _at(value, assertion["path"])
                    if type(actual) is not type(assertion["equals"]) or actual != assertion["equals"]:
                        _fail("接口返回失败或成功条件不符，不能当作空结果。", "INTERFACE_RESPONSE_INVALID")
                for rule in record["response_rules"]["required"]:
                    actual = _type(_at(value, rule["path"]))
                    if actual != rule["type"] and not (rule["type"] == "number" and actual == "integer"):
                        _fail("接口响应结构已变化，请重新审核。", "INTERFACE_SHAPE_CHANGED")
                data = _at(value, record["response_rules"]["data_path"])
                shape = _shape(value)
                fingerprint = hashlib.sha256(_json(shape)).hexdigest()
                if record.get("response_shape") and not _shape_matches(record["response_shape"], shape):
                    _fail("接口响应字段结构已变化，原契约已失效。", "INTERFACE_SHAPE_CHANGED")
            except (ValueError, UnicodeError):
                _fail("接口未返回有效JSON，不能当作查询成功。", "INTERFACE_RESPONSE_INVALID")
            except ConnectorError as error:
                if error.code == "INTERFACE_SHAPE_CHANGED":
                    with self._connection(True) as c:
                        latest = self._read(c, profile, identifier)
                        if latest["digest"] == record["digest"]:
                            latest.update(status="invalidated", reason="响应结构变化，请重新发现并审核。")
                            self._write(c, latest)
                raise
            if validating:
                with self._connection(True) as c:
                    latest = self._read(c, profile, identifier)
                    self._assert_current(latest)
                    if latest["digest"] != record["digest"] or latest["status"] not in expected:
                        _fail("验证期间契约状态已变化，未保存结果。", "INTERFACE_CHANGED")
                    latest.update(status="ready", response_fingerprint=fingerprint, response_shape=shape, validated_at=time.time())
                    self._write(c, latest)
            return {"ok": True, "interface_id": identifier, "status": "ready", "data": _safe_data(data),
                    "complete": None, "has_more": None,
                    "notice": "仅返回本次请求结果，未自动翻页；完整性需按接口分页字段继续核实。"}

    async def validate(self, profile, interface_id, parameters=None):
        return await self._execute(profile, interface_id, {} if parameters is None else parameters, True)

    async def call(self, profile, interface_id, parameters=None):
        return await self._execute(profile, interface_id, {} if parameters is None else parameters, False)
