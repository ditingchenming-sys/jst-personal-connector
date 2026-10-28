"""全部离线：不解析或请求真实 ERP 域，不读取任何已有凭据。"""
import asyncio
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from uuid import uuid4

import pytest

from jst_connector.adapters import FMS_BASE, ORDER_URL, PURCHASE_URL
from jst_connector.adapters.login import AUTH_POST_URLS, LOGIN_ASSETS, is_login_asset
from jst_connector.browser import LOGIN_URL, BrowserManager, approved_request, redact, safe_url
from jst_connector.erp import ErpClient
from jst_connector.errors import ConnectorError

IDENTITY = {"company_id": "101", "user_id": "201"}


class MemoryVault:
    def __init__(self):
        self.sessions = {}
        self.bindings = {}

    def load_session(self, profile):
        return self.sessions.get(profile)

    def save_session(self, profile, state, identity, credentials=None, *, expected_binding=None):
        if expected_binding is not None and self.bindings.get(profile) != expected_binding:
            raise ConnectorError("session_changed", "当前会话绑定已变更。")
        self.bindings.setdefault(profile, uuid4().hex)
        self.sessions[profile] = {"state": state, "identity": dict(identity), "credentials": credentials}

    def session_binding(self, profile):
        return self.bindings.get(profile)

    def clear_session(self, profile):
        self.sessions.pop(profile, None)
        self.bindings.pop(profile, None)


class FakeResponse:
    status = 200

    def __init__(self, value):
        self.value = value
        self.disposed = False

    async def text(self):
        return self.value if isinstance(self.value, str) else json.dumps(self.value)

    async def dispose(self):
        self.disposed = True


class FakeContext:
    def __init__(self, state):
        self.state = state or {"cookies": [], "origins": []}
        self.closed = False
        self.calls = []
        self.request = self
        self.result = {"code": 0, "data": []}
        self.page = FakePage()

    async def new_page(self):
        return self.page

    async def route(self, pattern, handler):
        self.route_handler = handler

    def on(self, event, callback):
        pass

    async def storage_state(self):
        return self.state

    async def cookies(self, urls):
        return [{"name": "u_cid", "value": "sensitive-csrf"}]

    async def fetch(self, url, **options):
        self.calls.append((url, options))
        return FakeResponse(self.result)

    async def close(self):
        self.closed = True


class FakePage:
    url = LOGIN_URL

    async def goto(self, url, **kwargs):
        self.url = url

    async def screenshot(self, **kwargs):
        return b"offline-image"

    def locator(self, selector):
        return selector


class OfflineBrowser:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    async def identity(self, profile):
        return dict(IDENTITY)

    @asynccontextmanager
    async def verified_scope(self, profile):
        yield dict(IDENTITY)

    async def request(self, profile, method, url, payload=None):
        self.calls.append((profile, method, url, payload))
        assert approved_request(method, url, payload), "adapter escaped the audited request list"
        value = next(self.responses)
        return {"status": 200, "text": value if isinstance(value, str) else json.dumps(value)}


def callback(value):
    return "0|" + json.dumps({"GotoLogin": False, "IsSuccess": True, "ReturnValue": json.dumps(value)})


def fms(rows, total, current=1, pages=1, key="pageData"):
    return {"code": 0, "data": {key: rows} if key else rows,
            "page": {"count": total, "currentPage": current, "pages": pages}}


@pytest.mark.asyncio
async def test_identity_is_not_inferred_from_cookie_or_item_record():
    vault = MemoryVault()
    contexts = []

    async def factory(state):
        context = FakeContext({"cookies": [{"name": "u_co_id", "value": "101"},
                                            {"name": "u_id", "value": "201"}]})
        contexts.append(context)
        return context

    manager = BrowserManager(vault, context_factory=factory)
    await manager.start_login("codex")
    with pytest.raises(ConnectorError, match="可信身份来源") as error:
        await manager.finish_login("codex")
    assert error.value.code == "IDENTITY_UNVERIFIED"
    assert vault.load_session("codex") is None
    await manager.close()
    assert contexts[0].closed


@pytest.mark.asyncio
async def test_profiles_are_isolated_and_idle_close_keeps_only_verified_state():
    vault, contexts = MemoryVault(), []

    async def factory(state):
        result = FakeContext(state)
        contexts.append(result)
        return result

    async def verifier(context):
        return dict(IDENTITY)

    manager = BrowserManager(vault, context_factory=factory, identity_verifier=verifier, idle_seconds=0)
    await manager.start_login("codex")
    result = await manager.finish_login("codex", remember=True)
    assert not result["remember_password"]
    assert "未保存密码" in result["message"]
    assert (await manager.status("workbuddy"))["status"] == "disconnected"
    with pytest.raises(ConnectorError) as error:
        await manager.identity("workbuddy")
    assert error.value.code == "LOGIN_REQUIRED"
    await manager.close_idle()
    assert contexts[0].closed and vault.load_session("codex")
    assert await manager.identity("codex") == IDENTITY
    assert len(contexts) == 2 and contexts[1].state == vault.load_session("codex")["state"]
    await manager.logout("codex")
    assert not vault.load_session("codex") and contexts[1].closed


@pytest.mark.asyncio
async def test_saved_identity_change_is_blocked_and_not_silently_rebound():
    vault = MemoryVault()
    vault.save_session("codex", {"cookies": [], "origins": []}, IDENTITY)

    async def verifier(context):
        return {"company_id": "other-company", "user_id": "201"}

    manager = BrowserManager(vault, context_factory=lambda state: _context(state), identity_verifier=verifier)
    for _ in range(2):
        with pytest.raises(ConnectorError) as error:
            await manager.identity("codex")
        assert error.value.code == "IDENTITY_CHANGED"
    assert vault.load_session("codex")["identity"] == IDENTITY


async def _context(state):
    return FakeContext(state)


@pytest.mark.asyncio
async def test_login_action_stops_after_business_navigation_and_has_no_js_escape():
    manager = BrowserManager(MemoryVault(), context_factory=_context)
    await manager.start_login("codex")
    manager._sessions["codex"].page.url = PURCHASE_URL
    with pytest.raises(ConnectorError) as error:
        await manager.login_action("codex", {"type": "click", "x": 1, "y": 1})
    assert error.value.code == "LOGIN_FLOW_ENDED"
    manager._sessions["codex"].page.url = LOGIN_URL
    for action in ({"type": "evaluate", "script": "arbitrary-js"}, {"type": "press", "key": "Control+L"},
                   {"type": "click", "x": 9999, "y": 10}):
        with pytest.raises(ConnectorError) as error:
            await manager.login_action("codex", action)
        assert error.value.code == "INVALID_LOGIN_ACTION"


@pytest.mark.parametrize("method,url,payload", [
    ("GET", "https://evil.example/read", None),
    ("POST", f"{FMS_BASE}/payablebegin?syncPayableData", {"data": {}}),
    ("POST", f"{FMS_BASE}/payment?savePayment", {"data": {}}),
    ("GET", PURCHASE_URL + "?delete=1", None),
    ("GET", PURCHASE_URL.replace("www.erp321.com", "www.erp321.com.evil.example"), None),
    ("GET", PURCHASE_URL.replace("https://", "https://user:pass@"), None),
    ("POST", ORDER_URL + "?am___=ReloadOrdersWithFlds", {"__CALLBACKID": "JTable1",
       "__CALLBACKPARAM": json.dumps({"Method": "Save", "Args": []})}),
])
def test_unknown_requests_are_denied(method, url, payload):
    assert not approved_request(method, url, payload)


@pytest.mark.asyncio
async def test_request_replaces_identity_and_disables_redirects():
    vault = MemoryVault()
    vault.save_session("codex", {"cookies": [], "origins": []}, IDENTITY)

    async def verifier(context):
        return dict(IDENTITY)

    manager = BrowserManager(vault, context_factory=_context, identity_verifier=verifier)
    result = await manager.request("codex", "POST", f"{FMS_BASE}/payment?getPaymentList",
                                   {"coid": "other", "uid": "other", "data": {}})
    assert result["status"] == 200
    options = manager._sessions["codex"].context.calls[0][1]
    assert options["data"]["coid"] == "101" and options["data"]["uid"] == "201"
    assert options["max_redirects"] == 0
    assert "Cookie" not in options["headers"]


def test_secret_redaction_and_url_query_removal():
    assert redact({"password": "secret", "nested": [{"authorization": "secret"}], "amount": 3}) == {
        "password": "[已脱敏]", "nested": [{"authorization": "[已脱敏]"}], "amount": 3}
    assert safe_url("https://user:secret@api.erp321.com/path?token=secret#password") == "https://api.erp321.com/path"


@pytest.mark.asyncio
async def test_login_network_diagnostics_store_only_field_names_and_block_unknown_auth():
    manager = BrowserManager(MemoryVault(), context_factory=_context)
    await manager.start_login("codex")
    request = SimpleNamespace(method="POST", url="https://api.erp321.com/unknown?token=secret&client=private",
                              resource_type="xhr", post_data_json={"password": "private", "phone": "private"})

    class Route:
        def __init__(self):
            self.request = request
            self.aborted = False

        async def abort(self, reason):
            self.aborted = True

    route = Route()
    await manager._route(manager._sessions["codex"], route)
    result = await manager.network_events("codex")
    assert route.aborted
    assert "secret" not in json.dumps(result) and "private" not in json.dumps(result)
    assert result["events"][0]["body_fields"] == ["[凭据字段]", "phone"]
    assert result["required_evidence"]


@pytest.mark.asyncio
async def test_q02_unknown_total_keeps_reading_and_exact_unique_code_filters():
    first = [{"sku_id": str(i), "i_id": "S", "other_1": "W11"} for i in range(50)]
    second = [{"sku_id": "last", "i_id": "S", "other_1": "W1"}]
    browser = OfflineBrowser([{"code": 0, "data": first, "page": {"count": -1, "pages": 0}},
                              {"code": 0, "data": second, "page": {"count": -1, "pages": 0}}])
    result = await ErpClient(browser).query("codex", "Q02", {"unique_code": "W1"})
    assert result["rows"] == second and result["complete"] and result["has_more"] is False
    assert len(browser.calls) == 2
    assert "owner_co_id=101" in browser.calls[0][2]


@pytest.mark.asyncio
async def test_q02_page_limit_is_explicitly_incomplete():
    rows = [{"sku_id": str(i), "i_id": "S"} for i in range(50)]
    result = await ErpClient(OfflineBrowser([{"code": 0, "data": rows}])).query(
        "codex", "Q02", {"style_ids": ["S"], "max_pages": 1})
    assert result["complete"] is False and result["has_more"] is True and result["total"] is None


@pytest.mark.asyncio
async def test_repeated_page_is_not_reported_as_complete():
    rows = [{"sku_id": str(i), "i_id": "S"} for i in range(50)]
    browser = OfflineBrowser([{"code": 0, "data": rows}, {"code": 0, "data": rows}])
    with pytest.raises(ConnectorError) as error:
        await ErpClient(browser).query("codex", "Q02", {"style_ids": ["S"]})
    assert error.value.code == "PAGINATION_INVALID"


@pytest.mark.asyncio
async def test_q04_multpage_uses_count_and_rejects_company_mismatch():
    hidden = '<input type="hidden" name="__VIEWSTATE" value="private-state">'
    page1 = {"dp": {"DataCount": 2, "PageCount": 2}, "datas": [{"po_id": "1", "co_id": "101"}]}
    page2 = {"dp": {"DataCount": 2, "IsLast": True}, "datas": [{"po_id": "2", "co_id": "101"}]}
    browser = OfflineBrowser([hidden, callback(page1), callback(page2)])
    result = await ErpClient(browser).query("codex", "Q04", {})
    assert result["total"] == 2 and result["complete"] and len(browser.calls) == 3
    assert "private-state" not in json.dumps(result)
    page1["datas"][0]["co_id"] = "other"
    with pytest.raises(ConnectorError) as error:
        await ErpClient(OfflineBrowser([hidden, callback(page1)])).query("codex", "Q04", {})
    assert error.value.code == "TENANT_MISMATCH"


@pytest.mark.asyncio
async def test_q09_supplier_pages_have_verified_completeness():
    a = {"ioiId": "1", "sellerId": "301", "coId": "101"}
    b = {"ioiId": "2", "sellerId": "301", "coId": "101"}
    browser = OfflineBrowser([fms([a], 2, 1, 2, "data"), fms([b], 2, 2, 2, "data")])
    result = await ErpClient(browser).query("codex", "Q09", {"supplier_id": "301"})
    assert result["complete"] and result["total"] == 2
    assert browser.calls[0][3]["data"]["sellerIds"] == [301]


@pytest.mark.asyncio
async def test_fms_premature_end_and_changing_count_fail():
    for responses in ([fms([], 1, key="data")],
                      [fms([{"ioiId": "1", "sellerId": "301"}], 2, 1, 2, "data"),
                       fms([{"ioiId": "2", "sellerId": "301"}], 3, 2, 2, "data")]):
        with pytest.raises(ConnectorError) as error:
            await ErpClient(OfflineBrowser(responses)).query("codex", "Q09", {"supplier_id": "301"})
        assert error.value.code == "PAGINATION_INVALID"


@pytest.mark.asyncio
async def test_q10_items_does_not_claim_unproven_completeness():
    browser = OfflineBrowser([{"code": 0, "data": [{"pinvId": "11", "amount": 3}]}])
    result = await ErpClient(browser).query("codex", "Q10", {"kind": "items", "payable_ids": ["11"]})
    assert result["complete"] is False and result["total"] is None and result["has_more"] is None


@pytest.mark.asyncio
async def test_q11_prepay_items_checks_parent_supplier_before_child_request():
    browser = OfflineBrowser([{"code": 0, "data": {"payId": "11", "sellerId": "other"}}])
    with pytest.raises(ConnectorError) as error:
        await ErpClient(browser).query("codex", "Q11", {"kind": "prepay_items", "supplier_id": "301", "payment_id": "11"})
    assert error.value.code == "ERP_FILTER_MISMATCH" and len(browser.calls) == 1


@pytest.mark.asyncio
async def test_q13_precise_read_discards_unrequested_buyer_details():
    browser = OfflineBrowser(['<input type="hidden" name="__VIEWSTATE" value="private-state">',
                              callback([{"o_id": 123, "so_id": "online", "remark": "", "buyer": "private"}])])
    result = await ErpClient(browser).query("codex", "Q13", {"order_id": "123"})
    assert result["rows"] == [{"o_id": "123", "so_id": "online", "remark": ""}]
    assert result["complete"] and "buyer" not in json.dumps(result)


@pytest.mark.asyncio
async def test_unsupported_filters_and_unadapted_capabilities_never_issue_request():
    browser = OfflineBrowser([])
    client = ErpClient(browser)
    for capability, parameters, code in [("Q02", {"company_id": "other"}, "UNSUPPORTED_PARAMETERS"),
                                           ("Q01", {}, "CAPABILITY_UNADAPTED"),
                                           ("W01", {}, "UNKNOWN_CAPABILITY")]:
        with pytest.raises(ConnectorError) as error:
            await client.query("codex", capability, parameters)
        assert error.value.code == code
    with pytest.raises(ConnectorError) as error:
        await client.preview("codex", "W01", {"atomicity": "proven"})
    assert error.value.code == "ATOMICITY_UNVERIFIED" and not browser.calls


def test_catalog_distinguishes_included_adapted_and_blocked():
    catalog = {item["id"]: item for item in ErpClient(None).catalog()}
    assert len(catalog) == 21
    assert catalog["Q01"]["status"] == "included_unadapted"
    assert catalog["Q02"]["status"] == "adapted_pending_live_validation"
    assert catalog["W01"]["status"] == "blocked_atomicity_unverified"


class OfflineRoute:
    def __init__(self, method, url, resource_type="image"):
        self.request = SimpleNamespace(method=method, url=url, resource_type=resource_type, post_data_json={})
        self.allowed = False
        self.aborted = False
        self.response_status = 200

    async def continue_(self):
        self.allowed = True

    async def fetch(self, **options):
        assert options["max_redirects"] == 0
        response = FakeResponse({})
        response.status = self.response_status
        return response

    async def fulfill(self, response):
        self.allowed = True

    async def abort(self, reason):
        self.aborted = True


@pytest.mark.asyncio
async def test_login_routes_only_allow_evidenced_exact_assets_and_authentication():
    manager = BrowserManager(MemoryVault(), context_factory=_context)
    await manager.start_login("codex")
    session = manager._sessions["codex"]
    for url in LOGIN_ASSETS:
        route = OfflineRoute("GET", url, "script")
        await manager._route(session, route)
        assert route.allowed and not route.aborted
    for url in AUTH_POST_URLS:
        for method in ("POST", "OPTIONS"):
            route = OfflineRoute(method, url, "xhr")
            await manager._route(session, route)
            assert route.allowed
        route = OfflineRoute("GET", url, "image")
        await manager._route(session, route)
        assert route.aborted
    route = OfflineRoute("GET", "https://www.erp321.com/ValidCode.aspx?channel=login&id=anonymous&t=123")
    await manager._route(session, route)
    assert route.allowed
    session.login = False
    route = OfflineRoute("POST", next(iter(AUTH_POST_URLS)), "xhr")
    await manager._route(session, route)
    assert route.aborted


@pytest.mark.parametrize("url", [
    "https://g.alicdn.com/sd/pointman/js/pt2.js?_=498222",
    "https://g.alicdn.com/sj/securesdk/0.0.3/securesdk_v2.js?timestamp=1793145600000",
])
@pytest.mark.asyncio
async def test_security_sdk_allows_only_evidenced_numeric_cache_parameters(url):
    assert is_login_asset(url)
    manager = BrowserManager(MemoryVault(), context_factory=_context)
    await manager.start_login("codex")
    route = OfflineRoute("GET", url, "image")
    await manager._route(manager._sessions["codex"], route)
    assert route.allowed
    post = OfflineRoute("POST", url, "script")
    await manager._route(manager._sessions["codex"], post)
    assert post.aborted


@pytest.mark.parametrize("url", [
    "https://g.alicdn.com/sd/pointman/js/pt2.js?_=498222&action=write",
    "https://g.alicdn.com/sd/pointman/js/pt2.js?_=498222&_=498223",
    "https://g.alicdn.com/sd/pointman/js/pt2.js?_=https://evil.example",
    "https://g.alicdn.com/sd/pointman/js/pt2.js?_=-1",
    "https://g.alicdn.com/sd/pointman/js/pt2.js",
    "https://g.alicdn.com/sd/pointman/js/pt2.js?_=498222#fragment",
    "https://g.alicdn.com.evil.example/sd/pointman/js/pt2.js?_=498222",
    "https://user:password@g.alicdn.com/sd/pointman/js/pt2.js?_=498222",
    "https://g.alicdn.com:444/sd/pointman/js/pt2.js?_=498222",
    "http://g.alicdn.com/sd/pointman/js/pt2.js?_=498222",
    "https://g.alicdn.com/sj/securesdk/0.0.3/securesdk_v2.js?timestamp=1793145600000&action=write",
    "https://g.alicdn.com/sj/securesdk/0.0.3/securesdk_v2.js?timestamp=123",
    "https://src.erp321.com/erp-login-react/122.40c8559d.async.js?_=498222",
    "https://src.erp321.com/erp-login-react/122.unreviewed.async.js",
    "https://gias.jd.com/js/td.js?redirect=business",
    "https://cdn.erp321.cn/cdn/expire-1-Y/fingerprintjs/3.3.3/umd/fingerprintjs.min.js?operation=write",
    "https://g.alicdn.com/AWSC/WebUMID/1.88.4/um.js?callback=unreviewed",
    "https://acjs.aliyun.com/error?v=1&e=example&stack=example",
])
def test_asset_query_exceptions_do_not_expand_host_path_or_query_permissions(url):
    assert not is_login_asset(url)


@pytest.mark.parametrize("url", [
    "https://api.erp321.com/fms/api/payment?savePayment",
    "https://www.erp321.com/app/order/order/delete.aspx",
    "https://src.erp321.com/erp-login-react/unreviewed.js",
    "https://src.erp321.com/erp-login-react/umi.a8efe1b1.js?delete=1",
    "https://src.erp321.com/erp-login-react/umi.a8efe1b1.js#action",
    "https://src.erp321.com.evil.example/erp-login-react/umi.a8efe1b1.js",
    "http://src.erp321.com/erp-login-react/umi.a8efe1b1.js",
    "https://www.erp321.com/login.aspx?redirect=/business-write",
    "https://www.erp321.com/ValidCode.aspx?channel=login&id=anonymous&t=123&delete=1",
    "https://user:secret@www.erp321.com/ValidCode.aspx?channel=login&id=anonymous&t=123",
    "https://api.erp321.com/erp/webapi/UserApi/WebLogin/Passport?operation=delete",
])
@pytest.mark.asyncio
async def test_image_resource_type_cannot_bypass_login_request_policy(url):
    manager = BrowserManager(MemoryVault(), context_factory=_context)
    await manager.start_login("codex")
    route = OfflineRoute("GET", url, "image")
    await manager._route(manager._sessions["codex"], route)
    assert route.aborted and not route.allowed


@pytest.mark.asyncio
async def test_redirect_from_audited_asset_cannot_reach_unreviewed_target():
    manager = BrowserManager(MemoryVault(), context_factory=_context)
    await manager.start_login("codex")
    asset = OfflineRoute("GET", "https://src.erp321.com/erp-login-react/umi.a8efe1b1.js", "script")
    asset.response_status = 302
    await manager._route(manager._sessions["codex"], asset)
    # The original endpoint's redirect is rejected before any redirect target is sent.
    redirected = OfflineRoute("GET", "https://evil.example/redirected.js", "script")
    await manager._route(manager._sessions["codex"], redirected)
    assert asset.aborted and not asset.allowed and redirected.aborted


@pytest.mark.parametrize("new_identity", [
    {"company_id": "999", "user_id": "888"},
    IDENTITY,  # Even re-login to the same account changes the session binding.
])
@pytest.mark.asyncio
async def test_actual_vault_browser_rejects_account_relogin_between_finance_pages(tmp_path, new_identity):
    from cryptography.fernet import Fernet

    from jst_connector.vault import Vault

    vault = Vault(tmp_path, key=Fernet.generate_key())
    active, contexts = dict(IDENTITY), []

    async def factory(state):
        context = FakeContext(state)
        context.verified_identity = dict(active)
        context.result = fms([{"ioiId": str(len(contexts) + 1), "sellerId": "301"}], 2,
                             len(contexts) + 1, 2, "data")
        contexts.append(context)
        return context

    async def verifier(context):
        return dict(context.verified_identity)

    manager = BrowserManager(vault, context_factory=factory, identity_verifier=verifier)
    await manager.start_login("codex")
    await manager.finish_login("codex")

    class SwitchingClient(ErpClient):
        switched = False

        async def _request_json(self, profile, url, payload):
            result = await super()._request_json(profile, url, payload)
            if not self.switched:
                self.switched = True
                await manager.logout(profile)
                active.clear()
                active.update(new_identity)
                await manager.start_login(profile)
                await manager.finish_login(profile)
            return result

    with pytest.raises(ConnectorError) as error:
        await SwitchingClient(manager).query("codex", "Q09", {"supplier_id": "301"})
    assert error.value.code == "QUERY_SESSION_CHANGED"
    assert sum(len(context.calls) for context in contexts) == 1
    await manager.close()


@pytest.mark.asyncio
async def test_verified_query_scope_checks_final_binding_before_return(tmp_path):
    from cryptography.fernet import Fernet

    from jst_connector.vault import Vault

    vault = Vault(tmp_path, key=Fernet.generate_key())

    async def verifier(context):
        return dict(IDENTITY)

    manager = BrowserManager(vault, context_factory=_context, identity_verifier=verifier)
    await manager.start_login("codex")
    await manager.finish_login("codex")

    class SwitchingClient(ErpClient):
        async def _q13(self, profile, identity, parameters, max_pages):
            await manager.logout(profile)
            await manager.start_login(profile)
            await manager.finish_login(profile)
            return {"rows": [], "complete": True, "has_more": False, "total": 0}

    with pytest.raises(ConnectorError) as error:
        await SwitchingClient(manager).query("codex", "Q13", {"order_id": "123"})
    assert error.value.code == "QUERY_SESSION_CHANGED"
    await manager.close()


@pytest.mark.parametrize("replacement", [None, {"company_id": "999", "user_id": "888"}, IDENTITY])
@pytest.mark.asyncio
async def test_other_process_vault_rebinding_invalidates_query_and_cannot_resurrect_on_close(tmp_path, replacement):
    from cryptography.fernet import Fernet

    from jst_connector.vault import Vault

    key = Fernet.generate_key()
    vault = Vault(tmp_path, key=key)
    other_process = Vault(tmp_path, key=key)

    async def verifier(context):
        return dict(IDENTITY)

    manager = BrowserManager(vault, context_factory=_context, identity_verifier=verifier)
    await manager.start_login("codex")
    await manager.finish_login("codex")
    context = manager._sessions["codex"].context
    context.result = fms([{"ioiId": "1", "sellerId": "301"}], 2, 1, 2, "data")

    class ExternalSwitchClient(ErpClient):
        async def _request_json(self, profile, url, payload):
            result = await super()._request_json(profile, url, payload)
            other_process.clear_session(profile)
            if replacement:
                other_process.save_session(profile, {"cookies": [], "origins": []}, replacement)
            return result

    with pytest.raises(ConnectorError) as error:
        await ExternalSwitchClient(manager).query("codex", "Q09", {"supplier_id": "301"})
    assert error.value.code == "QUERY_SESSION_CHANGED" and len(context.calls) == 1
    await manager.close()
    stored = other_process.load_session("codex")
    assert stored is None if replacement is None else stored["identity"] == replacement


@pytest.mark.parametrize("close_method", ["close", "close_idle"])
@pytest.mark.asyncio
async def test_cas_refresh_does_not_resurrect_logout_during_state_snapshot(tmp_path, close_method):
    from cryptography.fernet import Fernet

    from jst_connector.vault import Vault

    key = Fernet.generate_key()
    vault, other_process = Vault(tmp_path, key=key), Vault(tmp_path, key=key)

    async def verifier(context):
        return dict(IDENTITY)

    manager = BrowserManager(vault, context_factory=_context, identity_verifier=verifier, idle_seconds=0)
    await manager.start_login("codex")
    await manager.finish_login("codex")
    context = manager._sessions["codex"].context

    async def state_snapshot_racing_with_external_logout():
        other_process.clear_session("codex")
        return {"cookies": [], "origins": []}

    context.storage_state = state_snapshot_racing_with_external_logout
    await getattr(manager, close_method)()
    assert context.closed and other_process.load_session("codex") is None


@pytest.mark.asyncio
async def test_real_chromium_route_redirect_stays_on_controlled_loopback_server(monkeypatch):
    from playwright.async_api import async_playwright

    import jst_connector.browser as browser_module

    paths = []

    async def handler(reader, writer):
        header = await reader.readuntil(b"\r\n\r\n")
        path = header.split(b" ")[1].decode("ascii")
        paths.append(path)
        if path == "/login":
            body = b'<html><script src="/asset.js"></script><body>local login test</body></html>'
            response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
        elif path == "/asset.js":
            response = b"HTTP/1.1 302 Found\r\nLocation: /business-write\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        else:
            response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        writer.write(response)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    origin = "http://127.0.0.1:" + str(server.sockets[0].getsockname()[1])
    monkeypatch.setattr(browser_module, "LOGIN_URL", origin + "/login")
    monkeypatch.setattr(browser_module, "is_login_asset", lambda url: url == origin + "/asset.js")
    async with async_playwright() as playwright:
        chromium = await playwright.chromium.launch(headless=True)

        async def factory(state):
            return await chromium.new_context(storage_state=state, service_workers="block")

        manager = BrowserManager(MemoryVault(), context_factory=factory)
        try:
            await manager.start_login("controlled-local")
            assert paths == ["/login", "/asset.js"]
            events = await manager.network_events("controlled-local")
            assert any(event["classification"] == "blocked_redirect" for event in events["events"])
        finally:
            await manager.close()
            await chromium.close()
            server.close()
            await server.wait_closed()
