"""由实际页面请求形成的通用写契约；预览、可信确认和回查分别执行。"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import secrets
import sqlite3
import time
from pathlib import Path

from .errors import ConnectorError
from .interface_registry import _IDENTITY, _SECRET, InterfaceRegistry, _at, _parts, _safe_data, _type
from .vault import _json


def _fail(message, code="WRITE_CONTRACT_INVALID"):
    raise ConnectorError(code, message)


class WriteRegistry:
    """只保存结构和业务条件；Cookie、身份和认证字段由当前会话重建。

    单对象单请求是执行边界，不是 ERP 原子性的证明。跨对象批量和多请求
    工作流不能通过把 atomicity 设置为 verified 来放行。
    """

    def __init__(self, root, vault, browser, discovery, reads, ledger):
        self.root, self.vault, self.browser = Path(root), vault, browser
        self.discovery, self.reads, self.ledger = discovery, reads, ledger
        self.path = self.root / "write-interfaces.sqlite3"
        with sqlite3.connect(self.path) as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS writes (id TEXT PRIMARY KEY, profile TEXT NOT NULL, encrypted TEXT NOT NULL)")
        self.path.chmod(0o600)

    def _save(self, record):
        with sqlite3.connect(self.path) as connection:
            connection.execute("INSERT INTO writes VALUES (?,?,?)", (record["interface_id"], record["profile"], self.vault.seal(record)))

    def _get(self, profile, identifier):
        with sqlite3.connect(self.path) as connection:
            row = connection.execute("SELECT encrypted FROM writes WHERE id=? AND profile=?", (identifier, profile)).fetchone()
        if row is None:
            _fail("找不到当前调用端的写入契约。", "WRITE_INTERFACE_NOT_FOUND")
        record = self.vault.unseal(row[0])
        if (record.get("profile") != profile or record.get("interface_id") != identifier
                or not secrets.compare_digest(record.get("digest", ""), self._digest(record))):
            _fail("写入契约完整性校验失败。")
        self.reads._assert_current(record)
        return record

    @staticmethod
    def _digest(record):
        return hashlib.sha256(_json({key: value for key, value in record.items() if key != "digest"})).hexdigest()

    @staticmethod
    def _public(record):
        return {key: copy.deepcopy(value) for key, value in record.items() if key not in {"session_binding", "descriptor"}}

    def list(self, profile, query=""):
        if not isinstance(query, str) or len(query) > 2000:
            _fail("接口搜索条件须为短文本。")
        with sqlite3.connect(self.path) as connection:
            identifiers = [row[0] for row in connection.execute("SELECT id FROM writes WHERE profile=?", (profile,))]
        records = []
        for identifier in identifiers:
            try:
                item = self._public(self._get(profile, identifier))
            except ConnectorError as error:
                if error.code in {"INTERFACE_SESSION_CHANGED", "LOGIN_REQUIRED"}:
                    continue
                raise
            if not query or query.casefold() in _json(item).decode().casefold():
                records.append(item)
        return records

    @staticmethod
    def _single_object(descriptor, subject_path):
        """Refuse ambiguous object sets; one scalar subject must be bound to the query.

        Arrays with several elements need an adapter that proves their execution
        boundary; a transport wrapper cannot silently exempt business objects.
        """
        parts = _parts(subject_path)
        if len(parts) < 2 or parts[0] not in {"body", "query"}:
            _fail("操作对象必须绑定已捕获请求的明确业务字段。")
        subject = _at(descriptor, subject_path)
        if type(subject) not in (str, int) or isinstance(subject, str) and (not subject or len(subject) > 200 or any(c in subject for c in ",;\r\n")):
            _fail("本次执行必须是单个明确对象；对象集合须核实提交边界。", "WRITE_BATCH_BOUNDARY_UNVERIFIED")

        def check(value, path=""):
            if isinstance(value, dict):
                for key, child in value.items():
                    if ((str(key).casefold() == "ids" or str(key).casefold().endswith("_ids")
                            or re.search(r"[a-z]Ids$", str(key))) and isinstance(child, str)
                            and any(separator in child for separator in (",", ";", "\r", "\n", "|"))):
                        _fail("请求含多个对象选择器，须先核实整批提交边界。", "WRITE_BATCH_BOUNDARY_UNVERIFIED")
                    check(child, path + "/" + str(key))
            elif isinstance(value, list):
                if len(value) > 1:
                    _fail("请求含多个业务对象，尚未证明整批提交边界，未开放该批执行。", "WRITE_BATCH_BOUNDARY_UNVERIFIED")
                for index, child in enumerate(value):
                    check(child, path + "/" + str(index))
        check(descriptor.get("body"), "/body")
        check(descriptor.get("query"), "/query")
        return subject

    @staticmethod
    def _target(target, descriptor, reads, profile):
        if (not isinstance(target, dict) or set(target) - {"request_path", "read_interface_id", "read_parameters", "read_target_path", "allow_missing_before", "allow_missing_after"}
                or not isinstance(target.get("read_interface_id"), str) or not isinstance(target.get("read_parameters"), dict)
                or not target["read_parameters"]):
            _fail("必须声明操作对象、已验证的真实回查契约及参数映射。")
        target = copy.deepcopy(target)
        WriteRegistry._single_object(descriptor, target.get("request_path"))
        _parts(target.get("read_target_path"))
        if any(key in target and type(target[key]) is not bool for key in ("allow_missing_before", "allow_missing_after")):
            _fail("创建前缺失规则必须是布尔值。")
        query = reads.get(profile, target["read_interface_id"])
        if query.get("kind") != "query" or query.get("status") != "ready":
            _fail("预览与回查必须使用当前账号已验证的只读契约。")
        parameter_paths = {parameter["name"]: parameter["path"] for parameter in query["parameters"]}
        if set(target["read_parameters"]) - parameter_paths.keys():
            _fail("回查参数不在只读契约中。")
        bound = False
        for path in target["read_parameters"].values():
            if not isinstance(path, str) or not path.startswith(("/body/", "/query/")):
                _fail("回查参数必须来自本次已捕获的业务请求。")
            value = _at(descriptor, path)
            if isinstance(value, (dict, list)):
                _fail("回查参数映射须为明确的基础业务字段。")
            # At least one query parameter must select the actual operation object.
            bound = bound or path == target["request_path"]
        if not bound:
            _fail("回查条件必须绑定同一个操作对象，不能用无关查询作为校验。")
        return target

    @staticmethod
    def _conditions(conditions, *, expected, descriptor):
        if not isinstance(conditions, list) or len(conditions) > 32 or expected and not conditions:
            _fail("至少声明一项可回查的预期结果，条件最多32项。")
        conditions = copy.deepcopy(conditions)
        for condition in conditions:
            if not isinstance(condition, dict):
                _fail("业务校验条件必须为对象。")
            allowed = {"path", "request_path"} if "request_path" in condition else {"path", "equals"}
            if set(condition) != allowed or not expected and "request_path" in condition:
                _fail("校验规则须声明响应字段与固定期望，或预期写入字段映射。")
            _parts(condition["path"])
            if "request_path" in condition:
                if not isinstance(condition["request_path"], str) or not condition["request_path"].startswith(("/body/", "/query/")):
                    _fail("预期值必须来自已确认业务请求。")
                value = _at(descriptor, condition["request_path"])
            else:
                value = condition["equals"]
            if len(_json(value)) > 10000:
                _fail("校验规则过大，请收窄范围。")
        return conditions

    async def propose(self, profile, body):
        allowed = {"discovery_id", "request_id", "name", "purpose", "parameters", "response_rules", "target", "preconditions", "expected"}
        if not isinstance(body, dict) or set(body) - allowed:
            _fail("写入契约含未声明字段，不能自报身份、确认或原子性。")
        identity = await self.browser.identity(profile)
        before = self.reads._session(profile)
        if identity != before[0]:
            _fail("账号会话已变化。", "INTERFACE_SESSION_CHANGED")
        descriptor = self.discovery.get_request(profile, body.get("discovery_id"), body.get("request_id"))
        if hasattr(descriptor, "__await__"):
            descriptor = await descriptor
        descriptor = InterfaceRegistry._descriptor(descriptor)
        if descriptor["request_id"] != body.get("request_id") or descriptor["source"]["discovery_id"] != body.get("discovery_id"):
            _fail("写入契约必须来自本次真实捕获请求。")
        # A query-shaped request may still have side effects. Explicitly placing it
        # in the write lane always requires trusted per-operation confirmation.
        parameters = InterfaceRegistry._parameters(body.get("parameters", []), descriptor)
        rules = InterfaceRegistry._rules(body.get("response_rules"))
        if not rules["success"]:
            _fail("写入响应必须声明明确的业务成功条件，HTTP成功不足以判定。")
        target = self._target(body.get("target"), descriptor, self.reads, profile)
        preconditions = self._conditions(body.get("preconditions", []), expected=False, descriptor=descriptor)
        expected = self._conditions(body.get("expected"), expected=True, descriptor=descriptor)
        selector_paths = {target["request_path"]}
        verified_paths = {condition["request_path"] for condition in expected if "request_path" in condition}
        changed_paths = {parameter["path"] for parameter in parameters} - selector_paths
        if changed_paths - verified_paths:
            _fail("每个可变写入字段都必须声明对应的结果回查映射，不能只检查无关状态。")
        if self.reads._session(profile) != before:
            _fail("探索期间账号会话已变化。", "INTERFACE_SESSION_CHANGED")
        record = {"interface_id": "write_" + secrets.token_urlsafe(18), "kind": "write", "status": "ready_for_preview",
                  "profile": profile, "identity": identity, "session_binding": before[1], "created_at": time.time(),
                  "name": InterfaceRegistry._text(body.get("name"), "操作名称"),
                  "purpose": InterfaceRegistry._text(body.get("purpose"), "操作用途"),
                  "descriptor": descriptor, "parameters": parameters, "response_rules": rules,
                  "target": target, "preconditions": preconditions, "expected": expected,
                  "execution_boundary": "single_object_request", "atomicity": "unverified"}
        record["digest"] = self._digest(record)
        self._save(record)
        return self._public(record)

    @staticmethod
    def _matches(value, rules):
        try:
            return all(type(_at(value, rule["path"])) is type(rule["equals"]) and _at(value, rule["path"]) == rule["equals"] for rule in rules)
        except ConnectorError:
            return False

    @staticmethod
    def _target_matches(value, record, subject):
        try:
            actual = _at(value, record["target"]["read_target_path"])
            return type(actual) in (str, int) and str(actual) == str(subject)
        except ConnectorError:
            return False

    def _build(self, record, parameters):
        descriptor = self.reads._build(record, parameters)
        self._single_object(descriptor, record["target"]["request_path"])
        return descriptor

    async def _read_target(self, profile, record, descriptor):
        target = record["target"]
        values = {name: copy.deepcopy(_at(descriptor, path)) for name, path in target["read_parameters"].items()}
        result = await self.reads.call(profile, target["read_interface_id"], values)
        self.reads._assert_current(record)
        return result["data"]

    async def prepare(self, profile, identifier, parameters):
        record = self._get(profile, identifier)
        descriptor = self._build(record, parameters)
        subject = self._single_object(descriptor, record["target"]["request_path"])
        current = await self._read_target(profile, record, descriptor)
        missing = current is None or current == [] or current == {}
        if not (missing and record["target"].get("allow_missing_before")) and not self._target_matches(current, record, subject):
            _fail("实际回查对象与请求对象不同，不能执行。", "WRITE_TARGET_MISMATCH")
        if not self._matches(current, record["preconditions"]):
            _fail("当前聚水潭数据不符合操作前置条件，未生成可执行预览。", "WRITE_PRECONDITION_FAILED")
        expected = [{"path": condition["path"], "equals": copy.deepcopy(_at(descriptor, condition["request_path"]))
                     if "request_path" in condition else copy.deepcopy(condition["equals"])} for condition in record["expected"]]
        if self._matches(current, expected):
            _fail("当前聚水潭数据已经符合预期结果，未重复提交。", "WRITE_ALREADY_APPLIED")
        payload = {"kind": "saved_write", "interface_id": identifier, "contract_digest": record["digest"],
                   "parameters": copy.deepcopy(parameters),
                   "request": {**_safe_data({key: descriptor[key] for key in ("url", "method", "encoding", "query", "body", "headers", "json_fields")}),
                               "source_page": descriptor["source"]["page_url"]},
                   "subject": subject, "before": _safe_data(current), "before_digest": hashlib.sha256(_json(current)).hexdigest(),
                   "expected": expected, "name": record["name"], "purpose": record["purpose"],
                   "target": copy.deepcopy(record["target"])}
        checks = {"source": "current_erp_read", "read_interface_id": record["target"]["read_interface_id"],
                  "target_matched": True, "preconditions": record["preconditions"],
                  "execution_boundary": "single_object_request", "atomicity": "unverified",
                  "erp_business_validation": "not_declared",
                  "notice": "已读取当前ERP数据并核对声明的前置条件；未调用ERP试算或业务预校验接口，不能据此宣称全部业务规则已验证。本次仅执行一个对象的一次请求，未承诺跨对象或多步骤整体事务。"}
        # Contract IDs and preview IDs are deliberately absent: rediscovering the
        # same request must not bypass a previous unknown/executing submission.
        def canonical(value):
            if isinstance(value, dict):
                return {key: canonical(item) for key, item in value.items()
                        if str(key).casefold() not in _IDENTITY and not _SECRET.search(str(key))}
            return [canonical(item) for item in value] if isinstance(value, list) else value
        operation_key = hashlib.sha256(_json({"company_id": record["identity"]["company_id"],
                                             "request": canonical(payload["request"])})).hexdigest()
        return self.ledger.create_preview(profile, record["identity"], payload, checks,
                                          execution_boundary="single_object_request", operation_key=operation_key,
                                          verified_reissue=True)

    async def revalidate(self, profile, payload):
        record = self._get(profile, payload["interface_id"])
        if payload.get("contract_digest") != record["digest"]:
            return False
        descriptor = self._build(record, payload["parameters"])
        current = await self._read_target(profile, record, descriptor)
        return (hashlib.sha256(_json(current)).hexdigest() == payload["before_digest"]
                and self._matches(current, record["preconditions"]))

    @staticmethod
    def _response(result, rules):
        if not isinstance(result, dict) or result.get("status") != 200:
            _fail("写入响应未成功，必须回查原系统，不能自动重试。", "WRITE_RESPONSE_UNVERIFIED")
        raw = result.get("text")
        if not isinstance(raw, str) or len(raw) > 2_000_000:
            _fail("写入响应过大或无效，须回查。", "WRITE_RESPONSE_UNVERIFIED")
        # Legacy callback responses use a UTF-16 character-count prefix and an
        # embedded JSON ReturnValue. Decode the fixed wire format, never eval.
        from .erp import _callback
        try:
            if raw.lstrip().startswith("{"):
                value = json.loads(raw)
                if isinstance(value, dict) and "IsSuccess" in value:
                    value = _callback(raw)
            else:
                value = _callback(raw)
        except (ValueError, TypeError, UnicodeError):
            _fail("无法解析写入响应，须回查原系统。", "WRITE_RESPONSE_UNVERIFIED")
        if not WriteRegistry._matches(value, rules["success"]):
            _fail("写入业务成功条件未满足，须核对原系统。", "WRITE_RESPONSE_UNVERIFIED")
        for requirement in rules["required"]:
            actual_type = _type(_at(value, requirement["path"]))
            if actual_type != requirement["type"] and not (actual_type == "integer" and requirement["type"] == "number"):
                _fail("写入响应结构已变化，须核对原系统。", "WRITE_RESPONSE_UNVERIFIED")
        return value

    async def execute(self, profile, payload):
        record = self._get(profile, payload["interface_id"])
        if payload.get("contract_digest") != record["digest"]:
            _fail("写入契约已变化，请重新预览。")
        descriptor = self._build(record, payload["parameters"])
        transport = getattr(self.discovery, "execute_write", None)
        if transport is None:
            _fail("通用写入传输尚未接线，未发出请求。", "WRITE_TRANSPORT_UNAVAILABLE")
        response = await transport(profile, descriptor)
        self.reads._assert_current(record)
        self._response(response, record["response_rules"])
        return await self._verify_result(profile, record, descriptor, payload)

    async def _verify_result(self, profile, record, descriptor, payload):
        after = await self._read_target(profile, record, descriptor)
        same_target = self._target_matches(after, record, payload["subject"])
        # Deletion and state-filtered operations may make a precise query empty.
        # The confirmed preview must explicitly allow this AND assert absence of
        # the whole result; another object's matching fields never suffice.
        deletion_absence = (record["target"].get("allow_missing_after") and (after is None or after == [] or after == {})
                            and any(rule["path"] == "" and rule["equals"] in (None, [], {}) for rule in payload["expected"]))
        verified = bool((same_target or deletion_absence) and self._matches(after, payload["expected"]))
        return {"verified": verified, "interface_id": payload["interface_id"], "subject": payload["subject"],
                "data": _safe_data(after), "expected": payload["expected"], "source": "current_erp_read",
                "notice": "已提交并回查预期字段。" if verified else "已提交但回查尚未符合预期，结果未知；禁止重复提交。"}

    async def reconcile(self, profile, payload):
        """Only read the original operation's result; never invoke write transport."""
        record = self._get(profile, payload["interface_id"])
        if payload.get("contract_digest") != record["digest"]:
            _fail("原写入契约已变化，不能使用新契约冒充原提交结果。")
        descriptor = self._build(record, payload["parameters"])
        result = await self._verify_result(profile, record, descriptor, payload)
        result["notice"] = "已通过只读回查核实原操作的预期结果，没有重发写请求。" if result["verified"] else "只读回查尚未证实原操作结果，继续保持未知，没有重发写请求。"
        return result
