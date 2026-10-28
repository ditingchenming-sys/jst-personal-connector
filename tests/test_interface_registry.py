"""通用只读契约的连接授权、隔离及真实试读状态机；只使用离线假响应。"""
import copy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet

from jst_connector.adapters.login import ENTRY_URL
from jst_connector.errors import ConnectorError
from jst_connector.interface_registry import InterfaceRegistry
from jst_connector.vault import Vault

IDENTITY = {"company_id": "101", "user_id": "201"}
RULES = {"success": [{"path": "/code", "equals": 0}], "required": [{"path": "/data", "type": "array"}], "data_path": "/data"}
PARAMS = [{"name": "style", "path": "/body/data/style", "type": "string", "required": True},
          {"name": "page", "path": "/body/page", "type": "integer", "minimum": 1, "maximum": 100, "default": 1}]


def response(data=None):
    return {"status": 200, "content_type": "application/json", "text": json.dumps({"code": 0, "data": [{"sku": "A"}] if data is None else data})}


@pytest.fixture
def setup(tmp_path):
    vault = Vault(tmp_path, key=Fernet.generate_key())
    vault.ensure_client("codex")
    vault.save_session("codex", {"cookies": [], "origins": []}, IDENTITY)
    descriptor = {"request_id": "request-one", "url": "https://api.erp321.com/test/GetPageList", "method": "POST", "encoding": "json",
                  "query": {"coid": [None]}, "body": {"data": {"style": "PRIVATE-FILTER"}, "page": 1, "uid": None},
                  "headers": {"Content-Type": "application/json"},
                  "source": {"page_url": ENTRY_URL, "discovery_id": "discovery-one", "resource_type": "xhr", "blocked": True},
                  "identity_bindings": [{"path": "/body/uid", "kind": "user_id", "value_type": "number"},
                                        {"path": "/query/coid/0", "kind": "company_id", "value_type": "string"}], "json_fields": []}
    discovery = SimpleNamespace(get_request=lambda *args: copy.deepcopy(descriptor), execute_read=AsyncMock(return_value=response()))
    browser = SimpleNamespace(identity=AsyncMock(return_value=copy.deepcopy(IDENTITY)))
    registry = InterfaceRegistry(tmp_path, vault, browser, discovery)
    return registry, vault, descriptor, discovery, browser


async def propose(setup, **kwargs):
    registry = setup[0]
    return await registry.propose("codex", "discovery-one", "request-one", "商品查询", "按款筛选商品", 
                                  {"source_url": ENTRY_URL, "description": "官方页面搜索按钮调用此列表接口"},
                                  kwargs.get("parameters", PARAMS), kwargs.get("rules", RULES))


@pytest.mark.asyncio
async def test_connection_grant_trial_save_and_reuse_without_per_interface_approval(setup):
    registry, vault, _, discovery, _ = setup
    draft = await propose(setup)
    assert draft["status"] == "ready_for_validation" and "session_binding" not in draft
    assert "PRIVATE-FILTER" not in registry.path.read_bytes().decode("latin1")
    with pytest.raises(ConnectorError, match="内容已变化"):
        registry.approve("codex", draft["interface_id"], "wrong")
    with pytest.raises(ConnectorError):
        await registry.call("codex", draft["interface_id"], {"style": "A"})
    discovery.execute_read.assert_not_called()
    first = await registry.validate("codex", draft["interface_id"], {"style": "A"})
    assert first["data"] == [{"sku": "A"}] and first["complete"] is None
    assert discovery.execute_read.call_args.args[1]["body"]["data"]["style"] == "A"
    assert discovery.execute_read.call_args.args[1]["body"]["uid"] is None
    assert registry.get("codex", draft["interface_id"])["status"] == "ready"
    restored = InterfaceRegistry(registry.root, vault, setup[4], discovery)
    discovery.execute_read.return_value = response([])
    assert (await restored.call("codex", draft["interface_id"], {"style": "B", "page": 2}))["data"] == []
    assert discovery.execute_read.call_args.args[1]["body"]["page"] == 2
    assert restored.get("codex", draft["interface_id"])["status"] == "ready"


@pytest.mark.asyncio
async def test_connection_grant_allows_strict_page_entry_without_extra_approval(setup):
    registry, vault, *_ = setup
    assert registry.entry_allowed("codex", ENTRY_URL)
    page = "https://www.erp321.com/app/product/list.aspx"
    entry = await registry.request_entry("codex", page, "查看商品筛选页面")
    assert entry["status"] == "connection_read_authorized" and entry["entry_id"] is None
    assert registry.entry_allowed("codex", page)
    assert not registry.entry_allowed("codex", page+"?other=1")
    vault.clear_session("codex")
    assert not registry.entry_allowed("codex", page)
    vault.save_session("codex", {"cookies": []}, IDENTITY)
    assert registry.entry_allowed("codex", page)
    with pytest.raises(ConnectorError, match="不支持查询串"):
        await registry.request_entry("codex", page+"?id=1", "查看页面")
    assert registry.list("codex") == []


@pytest.mark.parametrize("url", [ENTRY_URL, "https://www.erp321.com/app/product/list.aspx",
                                  "https://www.erp321.com/app/product/list.aspx?id=1",
                                  "https://www.erp321.com/deleteorder/list.aspx",
                                  "https://www.erp321.com/app/logout/list.aspx",
                                  "https://www.erp321.com/login.aspx",
                                  "https://www.erp321.com/epaas/unlisted-route",
                                  "https://api.erp321.com/test/GetPageList"])
def test_registry_entry_grant_matches_discovery_document_policy(setup, url):
    from jst_connector.discovery_browser import _page_url
    assert setup[0].entry_allowed("codex", url) is _page_url(url)


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/headers/Action-Name", "/url", "/body", "/body/uid", "/query/coid/0", "/body/data/Method", "/query/am___/0"])
async def test_parameters_cannot_replace_request_identity_or_action(setup, path):
    setup[2]["body"]["data"]["Method"] = "GetList"
    setup[2]["query"]["am___"] = ["LoadDataToJSON"]
    with pytest.raises(ConnectorError):
        await propose(setup, parameters=[{"name": "override", "path": path, "type": "string"}])


@pytest.mark.asyncio
@pytest.mark.parametrize("url", ["https://api.erp321.com/test/DeleteList", "https://api.erp321.com/test/SaveList", "https://api.erp321.com/test/GetAndSubmit"])
async def test_write_candidate_is_recorded_but_never_approved_or_called(setup, url):
    setup[2]["url"] = url
    draft = await propose(setup)
    assert draft["kind"] == "write" and draft["status"] == "discovered_write"
    with pytest.raises(ConnectorError):
        setup[0].approve("codex", draft["interface_id"], draft["digest"])
    with pytest.raises(ConnectorError):
        await setup[0].validate("codex", draft["interface_id"], {"style": "A"})
    setup[3].execute_read.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["deleteorder", "DELETEORDER", "getandsubmit", "GETANDSUBMIT", "payorder", "PAYORDER"])
async def test_write_dispatch_is_case_insensitive_even_under_query_endpoint(setup, action):
    setup[2]["body"]["action"] = action
    draft = await propose(setup)
    assert draft["kind"] == "write" and draft["status"] == "discovered_write"
    with pytest.raises(ConnectorError):
        setup[0].approve("codex", draft["interface_id"], draft["digest"])
    setup[3].execute_read.assert_not_called()


@pytest.mark.asyncio
async def test_unknown_get_does_not_become_readonly_from_method_alone(setup):
    setup[2].update(url="https://api.erp321.com/test/Inventory", method="GET", encoding="none", body=None,
                    query={}, identity_bindings=[])
    draft = await propose(setup, parameters=[])
    assert draft["status"] == "needs_evidence"
    with pytest.raises(ConnectorError):
        setup[0].approve("codex", draft["interface_id"], draft["digest"])


@pytest.mark.asyncio
async def test_nullable_filter_can_declare_approved_scalar_type(setup):
    setup[2]["body"]["data"]["style"] = None
    draft = await propose(setup)
    setup[0].approve("codex", draft["interface_id"], draft["digest"])
    await setup[0].validate("codex", draft["interface_id"], {"style": "A"})
    assert setup[3].execute_read.call_args.args[1]["body"]["data"]["style"] == "A"


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["GetAuditList", "GetPayment", "GetUpdateLog"])
async def test_querying_write_related_business_records_is_still_query(setup, operation):
    setup[2]["url"] = "https://api.erp321.com/test/"+operation
    draft = await propose(setup)
    assert draft["kind"] == "query" and draft["status"] == "ready_for_validation"


@pytest.mark.asyncio
async def test_authentication_endpoint_cannot_be_saved_as_business_query(setup):
    setup[2]["url"] = "https://api.erp321.com/Passport/GetUserToken"
    with pytest.raises(ConnectorError, match="凭据接口"):
        await propose(setup)
    assert setup[0].list("codex") == []


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ['{"method":"DeleteOrder"}', '{"uid":999}', '{"password":"PRIVATE-PASSWORD"}'])
async def test_serialized_json_cannot_hide_dispatch_identity_or_secret_in_constant(setup, value):
    setup[2]["body"]["data"] = value
    with pytest.raises(ConnectorError, match="结构化字符串"):
        await propose(setup, parameters=[])
    assert setup[0].list("codex") == []


@pytest.mark.asyncio
async def test_serialized_container_cannot_be_approved_as_mutable_string(setup):
    setup[2]["body"]["data"] = "initial-query"
    with pytest.raises(ConnectorError, match="容器不能整体"):
        await propose(setup, parameters=[{"name": "payload", "path": "/body/data", "type": "string"}])


@pytest.mark.asyncio
async def test_scalar_filter_cannot_be_replaced_by_serialized_write_during_call(setup):
    draft = await propose(setup)
    setup[0].approve("codex", draft["interface_id"], draft["digest"])
    with pytest.raises(ConnectorError, match="结构化字符串"):
        await setup[0].validate("codex", draft["interface_id"], {"style": '{"method":"DeleteOrder","uid":999}'})
    setup[3].execute_read.assert_not_called()


@pytest.mark.asyncio
async def test_decoded_callback_business_filter_can_vary_but_method_cannot(setup):
    setup[2]["body"] = {"__CALLBACKID": "JTable1", "__CALLBACKPARAM": {"Method": "LoadDataToJSON", "Args": [{"style": "A"}]}}
    setup[2]["identity_bindings"] = []
    setup[2]["query"] = {}
    setup[2]["json_fields"] = ["/body/__CALLBACKPARAM"]
    parameters = [{"name": "style", "path": "/body/__CALLBACKPARAM/Args/0/style", "type": "string", "required": True}]
    draft = await propose(setup, parameters=parameters)
    setup[0].approve("codex", draft["interface_id"], draft["digest"])
    await setup[0].validate("codex", draft["interface_id"], {"style": "B"})
    body = setup[3].execute_read.call_args.args[1]["body"]
    assert body["__CALLBACKPARAM"]["Args"][0]["style"] == "B"
    assert body["__CALLBACKPARAM"]["Method"] == "LoadDataToJSON"
    parameters[0].update(path="/body/__CALLBACKPARAM/Method")
    with pytest.raises(ConnectorError):
        await propose(setup, parameters=parameters)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["password", "unknown_auth", "identity_value", "header"])
async def test_credentials_or_fixed_identity_never_enter_saved_contract(setup, change):
    descriptor = setup[2]
    if change == "password":
        descriptor["body"]["password"] = "PRIVATE-PASSWORD"
    elif change == "unknown_auth":
        descriptor["source"]["credential_fields"] = ["custom_token"]
    elif change == "identity_value":
        descriptor["body"]["uid"] = 201
    else:
        descriptor["headers"]["Authorization"] = "PRIVATE-AUTH"
    with pytest.raises(ConnectorError):
        await propose(setup)
    assert setup[0].list("codex") == []
    setup[3].execute_read.assert_not_called()


@pytest.mark.asyncio
async def test_unknown_missing_or_wrong_parameters_do_not_issue_request(setup):
    draft = await propose(setup)
    setup[0].approve("codex", draft["interface_id"], draft["digest"])
    for values in ({"style": "A", "extra": "B"}, {}, {"style": 123}, {"style": "A", "page": 1000}):
        with pytest.raises(ConnectorError):
            await setup[0].validate("codex", draft["interface_id"], values)
    setup[3].execute_read.assert_not_called()


@pytest.mark.asyncio
async def test_shape_drift_invalidates_saved_contract_and_failure_is_not_empty(setup):
    registry, _, _, discovery, _ = setup
    draft = await propose(setup)
    registry.approve("codex", draft["interface_id"], draft["digest"])
    await registry.validate("codex", draft["interface_id"], {"style": "A"})
    discovery.execute_read.return_value = {"status": 200, "content_type": "application/json", "text": '{"code":1,"data":[]}'}
    with pytest.raises(ConnectorError, match="不能当作空结果"):
        await registry.call("codex", draft["interface_id"], {"style": "B"})
    discovery.execute_read.return_value = response([{"different": "schema"}])
    with pytest.raises(ConnectorError, match="结构已变化"):
        await registry.call("codex", draft["interface_id"], {"style": "C"})
    assert registry.get("codex", draft["interface_id"])["status"] == "invalidated"


@pytest.mark.asyncio
async def test_profile_and_concurrent_account_change_discard_result(setup):
    registry, vault, _, discovery, _ = setup
    draft = await propose(setup)
    vault.ensure_client("workbuddy")
    vault.save_session("workbuddy", {"cookies": []}, IDENTITY)
    with pytest.raises(ConnectorError):
        registry.get("workbuddy", draft["interface_id"])
    assert registry.list("workbuddy") == []
    registry.approve("codex", draft["interface_id"], draft["digest"])
    async def changed(*args):
        vault.clear_session("codex")
        vault.save_session("codex", {"cookies": []}, IDENTITY)
        return response()
    discovery.execute_read.side_effect = changed
    with pytest.raises(ConnectorError, match="账号会话已变化"):
        await registry.validate("codex", draft["interface_id"], {"style": "A"})
    assert registry.get("codex", draft["interface_id"])["status"] == "invalidated"


@pytest.mark.asyncio
async def test_same_profile_cannot_read_previous_company_or_employee_contracts(setup):
    registry, vault, *_ = setup
    draft = await propose(setup)
    vault.clear_session("codex")
    assert registry.list("codex") == []
    with pytest.raises(ConnectorError):
        registry.get("codex", draft["interface_id"])
    vault.save_session("codex", {"cookies": []}, {"company_id": "999", "user_id": "888"})
    assert registry.list("codex") == []
    with pytest.raises(ConnectorError, match="当前账号"):
        registry.get("codex", draft["interface_id"])
    vault.clear_session("codex")
    vault.save_session("codex", {"cookies": []}, IDENTITY)
    stale = registry.get("codex", draft["interface_id"])
    assert stale["status"] == "invalidated"
    assert not {"descriptor", "read_evidence", "parameters", "identity", "digest"} & set(stale)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["pending_approval", "approved_pending_validation"])
async def test_historical_query_draft_can_validate_under_current_connection_grant(setup, status):
    registry = setup[0]
    draft = await propose(setup)
    with registry._connection(True) as c:
        record = registry._read(c, "codex", draft["interface_id"])
        record["status"] = status
        registry._write(c, record)
    result = await registry.validate("codex", draft["interface_id"], {"style": "A"})
    assert result["status"] == "ready"


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["write", "opaque", "parameters", "rules", "source", "evidence", "digest"])
async def test_stored_query_label_never_substitutes_for_rechecking_the_actual_contract(setup, mutation):
    registry = setup[0]
    draft = await propose(setup)
    with registry._connection(True) as c:
        record = registry._read(c, "codex", draft["interface_id"])
        record["status"] = "pending_approval"
        if mutation == "write":
            record["descriptor"]["body"]["action"] = "DELETEORDER"
        elif mutation == "opaque":
            record["descriptor"]["body"]["data"] = '{"method":"DeleteOrder"}'
        elif mutation == "parameters":
            record["parameters"][0]["path"] = "/body/uid"
        elif mutation == "rules":
            record["response_rules"]["required"] = []
        elif mutation == "source":
            record["descriptor"]["source"]["blocked"] = False
        elif mutation == "evidence":
            record["read_evidence"]["source_url"] = "https://www.erp321.com/app/fake/list.aspx"
        else:
            record["descriptor"]["url"] = "https://api.erp321.com/test/GetOtherList"
        if mutation != "digest":
            # Emulate an old installed version having sealed this contract as query.
            record["digest"] = registry._digest(record)
        registry._write(c, record)
    with pytest.raises(ConnectorError):
        await registry.validate("codex", draft["interface_id"], {"style": "A"})
    setup[3].execute_read.assert_not_called()


@pytest.mark.asyncio
async def test_proposal_must_refer_to_the_same_actual_capture_identifiers(setup):
    setup[2]["request_id"] = "different-request"
    with pytest.raises(ConnectorError, match="请求编号不一致"):
        await propose(setup)
    assert setup[0].list("codex") == []
