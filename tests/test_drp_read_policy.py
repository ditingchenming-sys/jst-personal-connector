"""官方固定商品列表协议的只读边界与响应信封。"""
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from jst_connector.drp import DrpBrowserManager, DrpClient
from jst_connector.drp_read_policy import approved_request, known_read_url, validate_response
from jst_connector.errors import ConnectorError

URL = "https://goods.scm121.com/api/goods/myself/rapidly/goods/list"
PAYLOAD = {"pageNum": 1, "pageSize": 20, "searchType": 1, "checkHasData": True,
           "itemCodes": "fixture-item", "sort": {"code": "created", "order": "desc"}}


@pytest.mark.parametrize("host", ["goods.scm121.com", "sc.scm121.com", "gyl.scm121.com"])
@pytest.mark.parametrize("path", ["supplier/goods/list", "myself/rapidly/goods/list"])
def test_only_fixed_official_list_posts_are_readable(host, path):
    url = "https://" + host + "/api/goods/" + path
    assert known_read_url(url) and approved_request("POST", url, PAYLOAD)
    assert not approved_request("GET", url, PAYLOAD)
    assert not approved_request("DELETE", url, PAYLOAD)


@pytest.mark.parametrize("url", [URL + "?action=delete", URL + "#", URL + "#fragment", URL.replace("https:", "http:"),
                                 URL.replace("goods.scm121.com", "goods.scm121.com:443"),
                                 URL.replace("goods.scm121.com", "user@goods.scm121.com"),
                                 URL.replace("goods.scm121.com", "goods.scm121.com.evil.test"),
                                 URL.replace("/list", "/remove"), URL.replace("/list", "/publish"),
                                 URL.replace("/list", "/queryUnknown"), URL.replace("/api/goods/", "/api/auth/"), "\x00" + URL])
def test_aliases_auth_writes_and_url_tricks_are_blocked(url):
    assert not approved_request("POST", url, PAYLOAD)


@pytest.mark.parametrize("extra", [{"action": "Delete"}, {"filter": {"method": "Publish"}}, {"requests": []},
                                  {"batch": []}, {"coId": "other"}, {"token": "private"},
                                  {"pageSize": 501}, {"pageNum": 0}, {"searchType": "delete"},
                                  {"checkHasData": "false"}, {"pageSize": True}, {"searchType": True}, {"co_id": "other"},
                                  {"user_id": "other"}, {"company_id": "other"}, {"action_name": "Publish"}, {"profile": "other"},
                                  {"filter": '{"action":"Save"}'}, {"filter": '[{"uid":"other"}]'}])
def test_dispatch_identity_and_malformed_paging_are_not_passive_filters(extra):
    assert known_read_url(URL)
    assert not approved_request("POST", URL, {**PAYLOAD, **extra})


def result(value):
    return {"status": 200, "text": json.dumps(value), "content_type": "application/json"}


@pytest.mark.parametrize("body", [{"success": False, "data": [], "total": 0}, {"success": True, "data": {}, "total": 0},
                                 {"success": True, "data": []}, {"success": True, "data": [], "total": False},
                                 {"success": True, "data": [], "total": -2}, {"code": 0, "data": [], "total": 0}])
def test_business_failure_or_wrong_shape_cannot_look_like_empty_list(body):
    with pytest.raises(ConnectorError, match="不能视为空列表"):
        validate_response("POST", URL, PAYLOAD, result(body))


def test_current_page_total_and_unknown_count_are_preserved():
    envelope = result({"success": True, "data": [{"itemCode": "fixture-item"}], "total": 41})
    assert validate_response("POST", URL, PAYLOAD, envelope) == {"page": 1, "page_size": 20, "returned": 1, "total": 41, "has_more": True}
    unknown = result({"success": True, "data": [], "total": -1})
    assert validate_response("POST", URL, PAYLOAD, unknown)["total"] is None
    assert validate_response("POST", URL, PAYLOAD, unknown)["has_more"] is None
    assert validate_response("POST", "https://gyl.scm121.com/api/drp/other/query", {}, result({"custom": True})) is None


def test_current_identity_is_only_the_fixed_supplier_read():
    url = "https://gyl.scm121.com/api/drp/user/supplier/getUserInfo?supplierType=shop&terminalName=SUPPLIER"
    assert approved_request("GET", url)
    assert not approved_request("GET", url + "&token=private")
    assert not approved_request("POST", url, {})
    assert known_read_url(url + "&token=private")


def test_supplier_reads_are_distinct_from_own_product_management():
    from jst_connector.drp_read_policy import SUPPLIER_GOODS_PATH, SUPPLIER_LIST_PATH, SUPPLIER_OPTIONS_PATH
    for path in (SUPPLIER_GOODS_PATH, SUPPLIER_LIST_PATH):
        url = "https://gyl.scm121.com" + path
        assert approved_request("POST", url, {"supplierCoId": "300", "pageNum": 1, "pageSize": 20})
        assert validate_response("POST", url, PAYLOAD, result({"success": True, "data": [], "total": 0}))["total"] == 0
    options = "https://sc.scm121.com" + SUPPLIER_OPTIONS_PATH
    assert approved_request("GET", options)
    assert not approved_request("POST", options, {})
    assert not approved_request("GET", options + "?action=delete")
    assert validate_response("GET", options, None, result({"success": True, "data": []}))["total"] is None
    with pytest.raises(ConnectorError, match="异步"):
        validate_response("POST", "https://gyl.scm121.com" + SUPPLIER_GOODS_PATH, PAYLOAD,
                          result({"success": True, "code": "202", "data": {"queryId": "fixture-only"}}))


@pytest.fixture
def shortcut():
    @asynccontextmanager
    async def scope(profile):
        assert profile == "alice"
        yield {"company_id": "actor-company", "user_id": "actor-user"}
    browser = SimpleNamespace(verified_scope=scope, request=AsyncMock(return_value=result({
        "success": True, "data": [{"supplierCoId": "300", "token": "must-not-leak"}], "total": 40})))
    return DrpClient(browser), browser


async def test_supplier_shortcuts_preserve_actor_and_page_scope(shortcut):
    client, browser = shortcut
    options = await client.query("alice", "DRP_SUPPLIER_OPTIONS", {})
    assert options["scope"] == "supplier_options" and options["total"] is None
    assert "must-not-leak" not in json.dumps(options)
    page = await client.query("alice", "DRP_SUPPLIER_GOODS", {"supplierCoId": "300", "pageNum": 2})
    assert page["identity"]["company_id"] == "actor-company"
    assert page["pageNum"] == 2 and page["pageSize"] == 20 and page["total"] == 40
    assert page["has_more"] is False and page["complete"] is False
    assert browser.request.await_args.args[-1] == {"supplierCoId": "300", "pageNum": 2, "pageSize": 20}


@pytest.mark.parametrize("parameters", [{}, {"supplierCoId": "abc"}, {"supplierCoId": True},
                                        {"supplierCoId": "300", "company_id": "other"},
                                        {"supplierCoId": "300", "pageSize": 501}])
async def test_shortcut_invalid_conditions_never_reach_network(shortcut, parameters):
    client, browser = shortcut
    with pytest.raises(ConnectorError):
        await client.query("alice", "DRP_SUPPLIER_GOODS", parameters)
    browser.request.assert_not_awaited()


async def test_drp_read_transport_injects_only_trusted_auth_and_verifies_before_and_after(monkeypatch):
    import asyncio
    monkeypatch.setattr("jst_connector.discovery_browser._public_destination", AsyncMock(return_value="public"))
    identity = {"company_id": "actor-company", "user_id": "actor-user"}
    response = SimpleNamespace(url=URL, status=200, headers={"content-type": "application/json"},
                               text=AsyncMock(return_value=json.dumps({"success": True, "data": [], "total": 0})),
                               dispose=AsyncMock())
    fetch = AsyncMock(return_value=response)
    session = SimpleNamespace(login=False, identity=identity, context=SimpleNamespace(request=SimpleNamespace(fetch=fetch)))
    from jst_connector.platform_policy import get_policy
    browser = SimpleNamespace(site_policy=get_policy("drp"), _lock=lambda _profile: asyncio.Lock(),
                              _open=AsyncMock(return_value=session), _verify=AsyncMock(return_value=identity),
                              _assert_scope=lambda *_args: None, business_headers=AsyncMock(return_value={"Authorization": "trusted-private"}))
    output = await DrpBrowserManager.request(browser, "alice", "POST", URL, PAYLOAD)
    assert output["pagination"]["total"] == 0
    assert fetch.await_args.kwargs["headers"] == {"Authorization": "trusted-private"}
    assert fetch.await_args.kwargs["max_redirects"] == 0
    assert browser._verify.await_count == 2
    assert "trusted-private" not in json.dumps(output)
    response.dispose.assert_awaited_once()
    fetch.reset_mock()
    with pytest.raises(ConnectorError):
        await DrpBrowserManager.request(browser, "alice", "POST", URL.replace("/list", "/remove"), PAYLOAD)
    fetch.assert_not_awaited()


async def test_shortcut_transport_blocks_private_dns_before_open_or_fetch(monkeypatch):
    import asyncio
    import socket

    from jst_connector.platform_policy import get_policy
    resolver = AsyncMock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))])
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolver)
    browser = SimpleNamespace(site_policy=get_policy("drp"), _open=AsyncMock())
    with pytest.raises(ConnectorError, match="网络地址"):
        await DrpBrowserManager.request(browser, "alice", "POST", URL, PAYLOAD)
    browser._open.assert_not_awaited()


@pytest.mark.parametrize("host", ["goods.scm121.com", "sc.scm121.com"])
@pytest.mark.parametrize("path", ["/api/company/deactivate", "//api/company/deactivate", "/./api/company/deactivate", "/.//api/company/deactivate"])
async def test_unknown_get_api_cannot_bypass_read_guard_as_document(host, path):
    from jst_connector.platform_policy import get_policy
    browser = SimpleNamespace(site_policy=get_policy("drp"), _open=AsyncMock())
    with pytest.raises(ConnectorError):
        await DrpBrowserManager.request(browser, "alice", "GET", "https://" + host + path)
    browser._open.assert_not_awaited()
