"""隔离验证通用写入闭环；不连接聚水潭、不使用真实业务数据。"""
import asyncio
import copy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet

from jst_connector.adapters.login import ENTRY_URL
from jst_connector.errors import ConnectorError
from jst_connector.interface_registry import InterfaceRegistry
from jst_connector.service import ConnectorService
from jst_connector.vault import Vault
from jst_connector.write_registry import WriteRegistry

IDENTITY = {"company_id": "100", "user_id": "200"}
RULES = {"success": [{"path": "/code", "equals": 0}], "required": [{"path": "/data", "type": "object"}], "data_path": "/data"}


def descriptor(identifier, action, body):
    return {"request_id": identifier, "url": "https://api.erp321.com/test/" + action,
            "method": "POST", "encoding": "json", "query": {}, "body": body,
            "headers": {"Content-Type": "application/json"}, "identity_bindings": [], "json_fields": [],
            "source": {"page_url": ENTRY_URL, "discovery_id": "discovery", "resource_type": "xhr", "blocked": True}}


def response(value):
    return {"status": 200, "content_type": "application/json", "text": json.dumps({"code": 0, "data": value})}


@pytest.fixture
async def env(tmp_path):
    vault = Vault(tmp_path, key=Fernet.generate_key())
    vault.ensure_client("codex")
    vault.save_session("codex", {"cookies": [], "origins": []}, IDENTITY)
    state = {"id": 7, "note": "before", "status": "draft"}
    captured = {"read": descriptor("read", "GetDocument", {"id": 7}),
                "write": descriptor("write", "SaveDocument", {"document_id": 7, "note": "after"})}

    async def read_transport(profile, contract):
        assert contract["body"]["id"] == 7
        return response(copy.deepcopy(state))

    async def write_transport(profile, contract):
        await asyncio.sleep(0)
        assert contract["body"]["document_id"] == 7
        state["note"] = contract["body"]["note"]
        return response({"id": 7})

    discovery = SimpleNamespace(get_request=lambda profile, discovery_id, request_id: copy.deepcopy(captured[request_id]),
                                execute_read=AsyncMock(side_effect=read_transport), execute_write=AsyncMock(side_effect=write_transport))
    browser = SimpleNamespace(identity=AsyncMock(return_value=copy.deepcopy(IDENTITY)))
    service = ConnectorService(tmp_path, vault=vault, browser=browser)
    reads = InterfaceRegistry(tmp_path, vault, browser, discovery)
    service._discovery, service._interfaces = discovery, reads
    query = await reads.propose("codex", "discovery", "read", "单据回查", "精确回查同一单据",
                                {"source_url": ENTRY_URL, "description": "官方页面读取单据"},
                                [{"name": "id", "path": "/body/id", "type": "integer", "required": True}], RULES)
    await reads.validate("codex", query["interface_id"], {"id": 7})
    body = {"discovery_id": "discovery", "request_id": "write", "name": "维护单据", "purpose": "修改本人权限内单据备注",
            "parameters": [{"name": "note", "path": "/body/note", "type": "string", "required": True}],
            "response_rules": RULES,
            "target": {"request_path": "/body/document_id", "read_interface_id": query["interface_id"],
                       "read_parameters": {"id": "/body/document_id"}, "read_target_path": "/id"},
            "preconditions": [{"path": "/status", "equals": "draft"}],
            "expected": [{"path": "/note", "request_path": "/body/note"}]}
    return SimpleNamespace(service=service, vault=vault, browser=browser, discovery=discovery,
                           reads=reads, body=body, state=state, captured=captured, root=tmp_path)


async def preview(env, **parameters):
    proposal = await env.service.propose_write_interface("codex", copy.deepcopy(env.body))
    result = await env.service.preview_write_interface("codex", proposal["interface"]["interface_id"], parameters or {"note": "after"})
    return proposal["interface"], result["preview"]


async def test_captured_write_real_precheck_confirm_execute_readback_and_reuse(env):
    interface, record = await preview(env)
    assert record["atomicity"] == "unverified"
    assert record["execution_boundary"] == "single_object_request"
    assert record["checks"]["source"] == "current_erp_read"
    assert record["payload"]["before"]["note"] == "before"
    env.discovery.execute_write.assert_not_called()
    with pytest.raises(ConnectorError, match="确认"):
        await env.service.execute("codex", record["preview_id"], record["digest"])
    env.service.approve("codex", record["preview_id"], record["digest"])
    result = await env.service.execute("codex", record["preview_id"], record["digest"])
    assert result["ok"] and result["preview"]["result"]["data"]["note"] == "after"
    assert env.discovery.execute_write.await_count == 1
    replay = await env.service.execute("codex", record["preview_id"], record["digest"])
    assert replay["ok"] and env.discovery.execute_write.await_count == 1
    restored = WriteRegistry(env.root, env.vault, env.browser, env.discovery, env.reads, env.service.ledger)
    assert restored.list("codex")[0]["interface_id"] == interface["interface_id"]
    next_record = await restored.prepare("codex", interface["interface_id"], {"note": "another"})
    assert next_record["status"] == "ready" and next_record["preview_id"] != record["preview_id"]
    assert "before" not in restored.path.read_bytes().decode("latin1")


async def test_same_content_new_preview_and_new_contract_cannot_duplicate_unknown(env):
    _, record = await preview(env)
    env.discovery.execute_write.side_effect = TimeoutError("offline fixture")
    env.service.approve("codex", record["preview_id"], record["digest"])
    with pytest.raises(ConnectorError, match="未知"):
        await env.service.execute("codex", record["preview_id"], record["digest"])
    _, repeated = await preview(env)
    assert repeated["preview_id"] == record["preview_id"] and repeated["status"] == "unknown"
    await env.service.execute("codex", repeated["preview_id"], repeated["digest"])
    assert env.discovery.execute_write.await_count == 1


async def test_unknown_result_reconciles_by_reading_without_resubmission(env):
    _, record = await preview(env)

    async def applied_then_timeout(profile, contract):
        env.state["note"] = contract["body"]["note"]
        raise TimeoutError("offline: upstream applied but response was lost")

    env.discovery.execute_write.side_effect = applied_then_timeout
    env.service.approve("codex", record["preview_id"], record["digest"])
    with pytest.raises(ConnectorError, match="未知"):
        await env.service.execute("codex", record["preview_id"], record["digest"])
    checked = await env.service.reconcile_operation("codex", record["preview_id"])
    assert checked["ok"] and checked["preview"]["status"] == "succeeded"
    assert checked["preview"]["result"]["source"] == "current_erp_read"
    assert env.discovery.execute_write.await_count == 1
    again = await env.service.reconcile_operation("codex", record["preview_id"])
    assert again["ok"] and env.discovery.execute_write.await_count == 1


async def test_unproven_reconciliation_keeps_unknown_and_shared_business_lock(env):
    _, record = await preview(env)
    env.discovery.execute_write.side_effect = TimeoutError("fixture: no observed result")
    env.service.approve("codex", record["preview_id"], record["digest"])
    with pytest.raises(ConnectorError):
        await env.service.execute("codex", record["preview_id"], record["digest"])
    checked = await env.service.reconcile_operation("codex", record["preview_id"])
    assert not checked["ok"] and checked["preview"]["status"] == "unknown"
    assert checked["preview"]["last_recheck"]["result"]["verified"] is False
    _, same = await preview(env)
    assert same["preview_id"] == record["preview_id"] and same["status"] == "unknown"
    assert env.discovery.execute_write.await_count == 1


async def test_reconciliation_does_not_race_an_executing_operation(env):
    _, record = await preview(env)
    env.service.approve("codex", record["preview_id"], record["digest"])
    env.service.ledger.claim("codex", record["preview_id"], record["digest"], IDENTITY)
    count = env.discovery.execute_read.await_count
    checked = await env.service.reconcile_operation("codex", record["preview_id"])
    assert checked["preview"]["status"] == "executing" and not checked["ok"]
    assert env.discovery.execute_read.await_count == count
    env.discovery.execute_write.assert_not_called()


async def test_reconciliation_rejects_other_object_matching_fields(env):
    _, record = await preview(env)
    env.discovery.execute_write.side_effect = TimeoutError("fixture")
    env.service.approve("codex", record["preview_id"], record["digest"])
    with pytest.raises(ConnectorError):
        await env.service.execute("codex", record["preview_id"], record["digest"])
    env.state.update(id=8, note="after")
    checked = await env.service.reconcile_operation("codex", record["preview_id"])
    assert checked["preview"]["status"] == "unknown"
    assert env.discovery.execute_write.await_count == 1


async def test_concurrent_execution_sends_once(env):
    _, record = await preview(env)
    env.service.approve("codex", record["preview_id"], record["digest"])
    results = await asyncio.gather(*(env.service.execute("codex", record["preview_id"], record["digest"]) for _ in range(2)))
    assert env.discovery.execute_write.await_count == 1
    assert any(result["ok"] for result in results)


async def test_changed_erp_state_requires_new_confirmation(env):
    _, record = await preview(env)
    env.service.approve("codex", record["preview_id"], record["digest"])
    env.state["note"] = "changed elsewhere"
    with pytest.raises(ConnectorError, match="变化"):
        await env.service.execute("codex", record["preview_id"], record["digest"])
    env.discovery.execute_write.assert_not_called()


async def test_fresh_preview_supersedes_stale_approval_without_waiting_for_expiry(env):
    interface, record = await preview(env)
    env.service.approve("codex", record["preview_id"], record["digest"])
    env.state["note"] = "changed elsewhere"
    fresh = (await env.service.preview_write_interface("codex", interface["interface_id"], {"note": "after"}))["preview"]
    assert fresh["status"] == "ready" and fresh["preview_id"] != record["preview_id"]
    assert fresh["payload"]["before"]["note"] == "changed elsewhere"
    assert env.service.ledger.get_preview("codex", record["preview_id"])["status"] == "superseded"
    with pytest.raises(ConnectorError, match="旧预览"):
        await env.service.execute("codex", record["preview_id"], record["digest"])
    env.service.approve("codex", fresh["preview_id"], fresh["digest"])
    assert (await env.service.execute("codex", fresh["preview_id"], fresh["digest"]))["ok"]


async def test_success_can_be_reissued_after_real_state_changes_back(env):
    interface, record = await preview(env)
    env.service.approve("codex", record["preview_id"], record["digest"])
    assert (await env.service.execute("codex", record["preview_id"], record["digest"]))["ok"]
    with pytest.raises(ConnectorError, match="已经符合"):
        await env.service.preview_write_interface("codex", interface["interface_id"], {"note": "after"})
    env.state["note"] = "before"
    another = (await env.service.preview_write_interface("codex", interface["interface_id"], {"note": "after"}))["preview"]
    assert another["status"] == "ready" and another["preview_id"] != record["preview_id"]
    assert env.service.ledger.get_preview("codex", record["preview_id"])["status"] == "succeeded"
    env.service.approve("codex", another["preview_id"], another["digest"])
    assert (await env.service.execute("codex", another["preview_id"], another["digest"]))["ok"]
    assert env.discovery.execute_write.await_count == 2


@pytest.mark.parametrize("same_company", [True, False])
async def test_business_dedup_is_shared_within_company_but_not_across_companies(env, same_company):
    await preview(env)
    other_identity = {"company_id": IDENTITY["company_id"] if same_company else "another-company", "user_id": "another-user"}
    env.vault.save_session("another", {"cookies": []}, other_identity)
    env.browser.identity.side_effect = lambda profile: env.vault.load_session(profile)["identity"]
    query = await env.reads.propose("another", "discovery", "read", "单据回查", "精确回查同一单据",
                                   {"source_url": ENTRY_URL, "description": "官方页面读取单据"},
                                   [{"name": "id", "path": "/body/id", "type": "integer", "required": True}], RULES)
    await env.reads.validate("another", query["interface_id"], {"id": 7})
    other_body = copy.deepcopy(env.body)
    other_body["target"]["read_interface_id"] = query["interface_id"]
    proposed = await env.service.propose_write_interface("another", other_body)
    if same_company:
        with pytest.raises(ConnectorError, match="同公司此操作") as error:
            await env.service.preview_write_interface("another", proposed["interface"]["interface_id"], {"note": "after"})
        assert not error.value.details
    else:
        result = await env.service.preview_write_interface("another", proposed["interface"]["interface_id"], {"note": "after"})
        assert result["preview"]["status"] == "ready"
    env.discovery.execute_write.assert_not_called()


async def test_changed_field_requires_its_own_readback_mapping(env):
    env.body["expected"] = [{"path": "/status", "equals": "approved"}]
    with pytest.raises(ConnectorError, match="每个可变写入字段"):
        await env.service.propose_write_interface("codex", env.body)


async def test_calling_changed_field_a_read_filter_does_not_skip_verification(env):
    # The fake registry is used only to supply a ready query with this optional
    # filter; adding a field to read_parameters must not reclassify a write value.
    env.captured["read"]["body"]["note"] = "before"
    query = await env.reads.propose("codex", "discovery", "read", "带过滤的回查", "回查当前对象",
                                   {"source_url": ENTRY_URL, "description": "官方页面读取对象"},
                                   [{"name": "id", "path": "/body/id", "type": "integer", "required": True},
                                    {"name": "note", "path": "/body/note", "type": "string"}], RULES)
    await env.reads.validate("codex", query["interface_id"], {"id": 7})
    env.body["target"]["read_interface_id"] = query["interface_id"]
    env.body["target"]["read_parameters"]["note"] = "/body/note"
    env.body["expected"] = [{"path": "/status", "equals": "approved"}]
    with pytest.raises(ConnectorError, match="每个可变写入字段"):
        await env.service.propose_write_interface("codex", env.body)


async def test_dispatch_header_is_visible_and_distinguishes_business_operation(env):
    env.captured["write"]["headers"]["Action-Name"] = "SaveDocument"
    _, first = await preview(env)
    assert first["payload"]["request"]["headers"]["Action-Name"] == "SaveDocument"
    env.captured["write"]["headers"]["Action-Name"] = "AuditDocument"
    _, second = await preview(env)
    assert second["preview_id"] != first["preview_id"]
    assert second["payload"]["request"]["headers"]["Action-Name"] == "AuditDocument"


async def test_readback_mismatch_is_unknown_and_never_retried(env):
    _, record = await preview(env)
    env.discovery.execute_write.side_effect = None
    env.discovery.execute_write.return_value = response({"id": 7})
    env.service.approve("codex", record["preview_id"], record["digest"])
    result = await env.service.execute("codex", record["preview_id"], record["digest"])
    assert not result["ok"] and result["preview"]["status"] == "unknown"
    await env.service.execute("codex", record["preview_id"], record["digest"])
    assert env.discovery.execute_write.await_count == 1


async def test_readback_different_object_cannot_look_like_success(env):
    _, record = await preview(env)

    async def wrong_object(profile, contract):
        env.state.update(id=8, note="after")
        return response({"id": 7})

    env.discovery.execute_write.side_effect = wrong_object
    env.service.approve("codex", record["preview_id"], record["digest"])
    result = await env.service.execute("codex", record["preview_id"], record["digest"])
    assert not result["ok"] and result["preview"]["status"] == "unknown"


async def test_http_success_with_business_failure_not_claimed_success(env):
    _, record = await preview(env)
    env.discovery.execute_write.side_effect = None
    env.discovery.execute_write.return_value = {"status": 200, "text": '{"code":9,"data":{}}'}
    env.service.approve("codex", record["preview_id"], record["digest"])
    with pytest.raises(ConnectorError):
        await env.service.execute("codex", record["preview_id"], record["digest"])
    assert env.service.ledger.get_preview("codex", record["preview_id"])["status"] == "unknown"


async def test_session_change_invalidates_contract_and_confirmed_preview(env):
    interface, record = await preview(env)
    env.service.approve("codex", record["preview_id"], record["digest"])
    env.vault.clear_session("codex")
    env.vault.save_session("codex", {"cookies": []}, IDENTITY)
    with pytest.raises(ConnectorError):
        await env.service.execute("codex", record["preview_id"], record["digest"])
    assert env.service._write_registry().list("codex") == []
    with pytest.raises(ConnectorError):
        await env.service.preview_write_interface("codex", interface["interface_id"], {"note": "after"})
    env.discovery.execute_write.assert_not_called()


async def test_different_profile_cannot_access_write_contract_or_preview(env):
    interface, record = await preview(env)
    env.vault.ensure_client("another")
    env.vault.save_session("another", {"cookies": []}, IDENTITY)
    with pytest.raises(ConnectorError):
        await env.service.preview_write_interface("another", interface["interface_id"], {"note": "after"})
    with pytest.raises(ConnectorError):
        env.service.ledger.get_preview("another", record["preview_id"])
    assert env.service._write_registry().list("another") == []


@pytest.mark.parametrize("extra", ["confirmed", "atomicity", "identity", "url", "profile"])
async def test_self_reported_authorization_and_arbitrary_requests_rejected(env, extra):
    env.body[extra] = True
    with pytest.raises(ConnectorError):
        await env.service.propose_write_interface("codex", env.body)
    env.discovery.execute_write.assert_not_called()


@pytest.mark.parametrize("change", ["array", "query_array", "callback_array", "ids_string", "subject_list", "mismatch", "unbound_query", "unobserved", "secret", "mutable_action"])
async def test_ambiguous_batch_subject_and_fake_sources_rejected(env, change):
    if change == "array":
        env.captured["write"]["body"]["documents"] = [7, 8]
    elif change == "query_array":
        env.captured["write"]["query"]["ids"] = [7, 8]
    elif change == "callback_array":
        env.captured["write"].update(encoding="form", json_fields=["/body/__CALLBACKPARAM"])
        env.captured["write"]["body"]["__CALLBACKPARAM"] = {"Method": "Save", "Args": [{"id": 7}, {"id": 8}]}
    elif change == "ids_string":
        env.captured["write"]["body"]["document_ids"] = "7,8"
    elif change == "subject_list":
        env.captured["write"]["body"]["document_id"] = "7,8"
    elif change == "mismatch":
        env.state["id"] = 8
    elif change == "unbound_query":
        env.body["target"]["read_parameters"] = {"id": "/body/note"}
    elif change == "unobserved":
        env.captured["write"]["source"]["blocked"] = False
    elif change == "secret":
        env.captured["write"]["body"]["password"] = "not-a-real-password"
    elif change == "mutable_action":
        env.captured["write"]["body"]["action"] = "Save"
        env.body["parameters"] = [{"name": "action", "path": "/body/action", "type": "string"}]
    with pytest.raises(ConnectorError):
        await preview(env)
    env.discovery.execute_write.assert_not_called()


async def test_preconditions_failed_and_already_applied_do_not_send(env):
    env.state["status"] = "approved"
    with pytest.raises(ConnectorError, match="前置条件"):
        await preview(env)
    env.state.update(status="draft", note="after")
    with pytest.raises(ConnectorError, match="已经符合"):
        await preview(env)
    env.discovery.execute_write.assert_not_called()


async def test_form_callback_payload_preserves_encoding_and_action(env):
    env.captured["write"].update(encoding="form", headers={"Content-Type": "application/x-www-form-urlencoded"},
                                body={"__CALLBACKID": "Table", "__CALLBACKPARAM": {"Method": "SaveDocument", "Args": [{"document_id": 7, "note": "after"}]}},
                                json_fields=["/body/__CALLBACKPARAM"])
    prefix = "/body/__CALLBACKPARAM/Args/0"
    env.body["parameters"][0]["path"] = prefix + "/note"
    env.body["target"].update(request_path=prefix + "/document_id", read_parameters={"id": prefix + "/document_id"})
    env.body["expected"][0]["request_path"] = prefix + "/note"
    _, record = await preview(env)

    async def callback_transport(profile, contract):
        assert contract["encoding"] == "form" and contract["json_fields"] == ["/body/__CALLBACKPARAM"]
        assert contract["body"]["__CALLBACKPARAM"]["Method"] == "SaveDocument"
        env.state["note"] = contract["body"]["__CALLBACKPARAM"]["Args"][0]["note"]
        return {"status": 200, "text": json.dumps({"IsSuccess": True, "ReturnValue": json.dumps({"code": 0, "data": {"id": 7}})})}

    env.discovery.execute_write.side_effect = callback_transport
    env.service.approve("codex", record["preview_id"], record["digest"])
    assert (await env.service.execute("codex", record["preview_id"], record["digest"]))["ok"]


@pytest.mark.parametrize("operation", ["CreateDocument", "DeleteDocument"])
async def test_create_and_delete_use_same_generic_lane_with_precise_query(env, operation):
    exists = operation == "DeleteDocument"
    env.captured["read_list"] = descriptor("read_list", "GetDocumentList", {"id": 7})

    async def read_list(profile, contract):
        return response([copy.deepcopy(env.state)] if exists else [])

    env.discovery.execute_read.side_effect = read_list
    array_rules = {**RULES, "required": [{"path": "/data", "type": "array"}]}
    query = await env.reads.propose("codex", "discovery", "read_list", "精确对象回查", "精确查询同一业务对象",
                                   {"source_url": ENTRY_URL, "description": "官方页面精确对象查询"},
                                   [{"name": "id", "path": "/body/id", "type": "integer", "required": True}], array_rules)
    await env.reads.validate("codex", query["interface_id"], {"id": 7})
    env.captured["write"]["url"] = "https://api.erp321.com/test/" + operation
    env.body["target"].update(read_interface_id=query["interface_id"], read_target_path="/0/id", allow_missing_before=not exists, allow_missing_after=exists)
    env.body["preconditions"] = []
    env.body["expected"] = ([{"path": "", "equals": []}] if exists else [{"path": "/0/note", "request_path": "/body/note"}])
    if exists:
        env.body["parameters"] = []

    async def mutate(profile, contract):
        nonlocal exists
        exists = operation == "CreateDocument"
        env.state["note"] = contract["body"]["note"]
        return response({"id": 7})

    env.discovery.execute_write.side_effect = mutate
    proposal = await env.service.propose_write_interface("codex", copy.deepcopy(env.body))
    result = await env.service.preview_write_interface("codex", proposal["interface"]["interface_id"], {} if operation == "DeleteDocument" else {"note": "after"})
    record = result["preview"]
    env.service.approve("codex", record["preview_id"], record["digest"])
    result = await env.service.execute("codex", record["preview_id"], record["digest"])
    assert result["ok"] and env.discovery.execute_write.await_count == 1


@pytest.mark.parametrize("condition", [None, 1, [], {"path": "/note", "confirmed": True}])
async def test_malformed_conditions_return_connector_errors(env, condition):
    env.body["expected"] = [condition]
    with pytest.raises(ConnectorError):
        await env.service.propose_write_interface("codex", env.body)
