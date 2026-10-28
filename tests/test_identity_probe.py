"""身份来源取证只读固定页面且只返回结构，不可冒充账号核验。"""
import asyncio
import json
from types import SimpleNamespace

import pytest

from jst_connector.adapters import ORDER_URL, PURCHASE_URL
from jst_connector.errors import ConnectorError
from jst_connector.identity_probe import (
    _receipt_matches,
    _session_grant_contrasts,
    inspect_identity_sources,
    page_identity_structure,
)


def test_missing_receipt_field_is_unknown_rather_than_mismatch():
    scope = {"UserId": "123", "OwnerCoId": "456"}
    assert _receipt_matches(scope, {"user_id": "123"}) == {"UserId": True, "OwnerCoId": None}
    assert _receipt_matches(scope, {"user_id": "789", "company_id": "456"}) == {
        "UserId": False, "OwnerCoId": True}


def test_identity_structure_omits_actual_values_and_query_secrets():
    html = '''<input id="co_id" type="hidden" value="PRIVATE-CO">
      <input id="password" value="PRIVATE-PASSWORD">
      <input id="user_id" type="PRIVATE-ATTRIBUTE" value="PRIVATE-USER">
      <script src="https://src.erp321.com/current.js?token=PRIVATE-TOKEN"></script>
      <script src="data:text/javascript,PRIVATE-TOKEN"></script>
      <script src="javascript:PRIVATE-TOKEN"></script>
      <script src="https://PRIVATE-ACCOUNT@src.erp321.com/PRIVATE-TOKEN.js"></script>
      <script src="https://unknown.example/PRIVATE-TOKEN.js"></script>
      <script>var CurrentUser = {"company_id":"PRIVATE-CO","user_id":"PRIVATE-USER","token":"PRIVATE-TOKEN"};
      window.uid = 123456789; var password = "PRIVATE-PASSWORD";</script>'''
    result = page_identity_structure(html, PURCHASE_URL)
    assert result["identity_controls"] == [{"name": "co_id", "type": "hidden", "has_value": True},
                                           {"name": "user_id", "type": "other", "has_value": True}]
    assert result["script_sources"] == ["https://src.erp321.com"] + ["[未核实脚本来源]"] * 4
    assert result["identity_candidates"][0]["schema"] == {"company_id": "string", "user_id": "string"}
    serialized = json.dumps(result)
    assert "PRIVATE" not in serialized and "123456789" not in serialized


def test_identity_contexts_redact_complete_literals_comments_and_reject_incomplete_scripts():
    source = '''<script>var CurrentUser = {"user_id": 123456789, "name": "PRIVATE-NAME"};
      var co_id = GetCookie("u_co_id"); var message="https://example.test/PRIVATE-TOKEN";
      // PRIVATE-COMMENT user_id = 56789
      /* PRIVATE-OTHER */ var password="PRIVATE-PASSWORD";</script>'''
    result = page_identity_structure(source, PURCHASE_URL)
    contexts = " ".join(result["redacted_identity_contexts"])
    assert "CurrentUser" in contexts and "GetCookie" in contexts and '"u_co_id"' in contexts
    assert "PRIVATE" not in contexts and "123456789" not in contexts and "56789" not in contexts
    assert page_identity_structure('<script>var user_id="PRIVATE-UNFINISHED</script>', PURCHASE_URL)["redacted_identity_contexts"] == []
    assert page_identity_structure('<script>var user_id=`PRIVATE-TEMPLATE`;</script>', PURCHASE_URL)["redacted_identity_contexts"] == []
    assert page_identity_structure('<script>/* user_id=PRIVATE-COMMENT</script>', PURCHASE_URL)["redacted_identity_contexts"] == []
    for tail in ('var pattern=/PRIVATE_NAME_ABC/;', '<!-- PRIVATE_LEGACY_COMMENT'):
        result = page_identity_structure('<script>var user_id=123;' + tail + '</script>', PURCHASE_URL)
        assert result["redacted_identity_contexts"] == []
    result = page_identity_structure('<script>var user_id=123; var PRIVATE_ACCOUNT_NAME=true;</script>', PURCHASE_URL)
    assert "PRIVATE" not in json.dumps(result) and "123" not in json.dumps(result)
    result = page_identity_structure('<script>var user_id=123; var 王某账户=true;</script>', PURCHASE_URL)
    assert "王某账户" not in json.dumps(result, ensure_ascii=False)


@pytest.mark.asyncio
async def test_probe_only_after_authentication_and_only_fixed_gets():
    calls, disposed = [], []

    class Response:
        status = 200

        async def text(self):
            return '<script>var user_id = 987654;</script>'

        async def dispose(self):
            disposed.append(True)

        async def header_values(self, name):
            return ['u_id=PRIVATE-HEADER', 'u_co_id=PRIVATE-HEADER', 'other=PRIVATE-HEADER']

    async def get(url, **options):
        calls.append((url, options))
        return Response()

    async def cookies(urls):
        return [{"name": "u_sso_token", "value": "PRIVATE-SSO"},
                {"name": "PRIVATE-NAME", "value": "PRIVATE-VALUE"}]

    session = SimpleNamespace(login=True, context=SimpleNamespace(request=SimpleNamespace(get=get), cookies=cookies),
                              server_identity_candidate={"company_id": "111222", "user_id": "333444"})
    attempt = SimpleNamespace(session=session, cancelled=False, status="need_code")
    lock = asyncio.Lock()
    browser = SimpleNamespace(_sessions={"codex": session}, _lock=lambda profile: lock,
                              _password_flows=SimpleNamespace(attempts={"codex": attempt}))
    with pytest.raises(ConnectorError):
        await inspect_identity_sources(browser, "codex")
    assert calls == []
    attempt.status = "identity_pending"
    result = await inspect_identity_sources(browser, "codex")
    assert not result["verified"]
    assert [url for url, _ in calls] == [PURCHASE_URL, ORDER_URL]
    assert all(options["max_redirects"] == 0 for _, options in calls)
    assert len(disposed) == 2
    assert "987654" not in json.dumps(result)
    assert result["auth_cookie_presence"] == ["u_sso_token"]
    assert result["server_receipt_field_presence"] == ["company_id", "user_id"]
    assert result["sources"][0]["identity_cookie_header_names"] == ["u_co_id", "u_id"]
    assert all(value not in json.dumps(result) for value in ("PRIVATE", "111222", "333444"))


@pytest.mark.asyncio
async def test_disposable_cookie_contrasts_use_fixed_gets_without_mutating_original_or_returning_values():
    original = [{"name": "u_sso_token", "value": "PRIVATE-SSO"},
                {"name": "u_cid", "value": "PRIVATE-CONTEXT"},
                {"name": "u_id", "value": "123456"}, {"name": "u_co_id", "value": "654321"}]
    closed, variants = [], []

    class Response:
        def __init__(self, authenticated):
            self.status = 200 if authenticated else 302

        async def text(self):
            return '<input name="__VIEWSTATE"><table id="JTable1"></table>'

        @property
        def headers_array(self):
            return [{"name": "Set-Cookie", "value": 'u_id=123456; Domain=.erp321.com; Path=/'},
                    {"name": "Set-Cookie", "value": 'u_co_id=654321; Domain=.erp321.com; Path=/'}]

        async def dispose(self):
            pass

    async def new_context(state):
        names = {cookie["name"] for cookie in state["cookies"]}
        variants.append(names)

        async def get(url, **options):
            assert url == PURCHASE_URL and options["max_redirects"] == 0
            return Response("u_sso_token" in names)

        async def close():
            closed.append(True)

        return SimpleNamespace(request=SimpleNamespace(get=get), close=close)

    async def cookies(urls):
        return original

    session = SimpleNamespace(context=SimpleNamespace(cookies=cookies), server_identity_conflicted=False,
                              server_passport_receipted=True,
                              server_identity_candidate={"user_id": "123456", "company_id": "654321"})
    result = await _session_grant_contrasts(SimpleNamespace(_new_context=new_context), session,
                                            SimpleNamespace(cancelled=False, status="identity_pending"))
    assert variants == [{"u_id", "u_co_id"}, {"u_sso_token"}, {"u_sso_token", "u_cid"},
                        {"u_sso_token", "u_cid", "u_id", "u_co_id"}, {"u_sso_token", "u_cid"},
                        {"u_sso_token", "u_cid", "u_id", "u_co_id"}]
    assert [item["http_status"] for item in result["results"]] == [302, 200, 200, 200, 200, 200]
    assert result["results"][1]["server_receipt_matches_login"] is True
    assert len(closed) == 6 and original[0]["value"] == "PRIVATE-SSO"
    assert all(value not in json.dumps(result) for value in ("PRIVATE", "123456", "654321"))


@pytest.mark.asyncio
async def test_contrasts_reject_ambiguous_or_mismatched_identity_without_creating_context():
    original = [{"name": "u_sso_token", "value": "PRIVATE-SSO"},
                {"name": "u_id", "value": "123456"}, {"name": "u_co_id", "value": "654321"}]
    created = []

    async def cookies(urls):
        return original

    async def new_context(state):
        created.append(True)

    session = SimpleNamespace(context=SimpleNamespace(cookies=cookies), server_identity_conflicted=False,
                              server_passport_receipted=True,
                              server_identity_candidate={"user_id": "123456", "company_id": "654321"})
    browser = SimpleNamespace(_new_context=new_context)
    attempt = SimpleNamespace(cancelled=False, status="identity_pending")
    original.append(dict(original[1], path="/another"))
    assert not (await _session_grant_contrasts(browser, session, attempt))["ready"]
    original.pop()
    original[1]["value"] = "999999"
    assert not (await _session_grant_contrasts(browser, session, attempt))["ready"]
    assert created == []
