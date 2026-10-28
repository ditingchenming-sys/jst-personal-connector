"""认证诊断必须足够定位协议，同时不把任何实际登录值交给调用端。"""
import json
from collections import deque
from types import SimpleNamespace

import pytest

from jst_connector.adapters.login import AUTH_POST_URLS
from jst_connector.browser import BrowserManager, auth_response_schema


def test_auth_schema_omits_credentials_values_dynamic_names_and_records():
    value = {"code": 0, "data": {"coId": 123, "userId": "actual-user", "password": "secret",
                                "accessToken": "secret", "accounts": [{"name": "private-name"}],
                                "private@example.com": "sensitive"}, "message": "private-name"}
    schema = auth_response_schema(value)
    assert schema == {"code": "number", "data": {"coId": "number", "userId": "string",
                                                  "accounts": "array"}, "message": "string"}
    encoded = json.dumps(schema)
    for secret in ("actual-user", "secret", "123", "private-name", "private@example.com"):
        assert secret not in encoded
    assert auth_response_schema({"data": {"ActualEmployeeName": "private",
                                          "AccountABC123": {"coId": 123}}}) == {"data": {}}
    assert auth_response_schema({"data": {"result": {"user": {"name": "value"}}}})["data"]["result"]["user"] == "object"


@pytest.mark.asyncio
async def test_response_schema_only_for_exact_auth_post_while_logging_in():
    manager = BrowserManager(None)
    session = SimpleNamespace(login=True, events=deque())
    read_calls = []

    async def body():
        read_calls.append(True)
        return b'{"data":{"userId":"private-user","token":"secret"}}'

    response = SimpleNamespace(url=next(iter(AUTH_POST_URLS)), request=SimpleNamespace(method="POST"),
                               status=200, body=body)
    await manager._observe(session, response)
    assert session.events[-1]["response_schema"] == {"data": {"userId": "string"}}
    session.login = False
    await manager._observe(session, response)
    session.login = True
    response.url += "?credential=secret"
    await manager._observe(session, response)
    response.url = next(iter(AUTH_POST_URLS))
    response.request.method = "GET"
    await manager._observe(session, response)
    assert len(read_calls) == 1
    assert all("response_schema" not in event for event in list(session.events)[1:])
    assert "secret" not in json.dumps(list(session.events))


@pytest.mark.asyncio
async def test_reopen_login_preserves_in_progress_form():
    navigations = []

    class Page:
        url = "about:blank"

        async def goto(self, url, **kwargs):
            self.url = url
            navigations.append(url)

    page = Page()

    class Context:
        async def new_page(self):
            return page

        async def route(self, *args):
            pass

        def on(self, *args):
            pass

    async def factory(state):
        return Context()

    manager = BrowserManager(SimpleNamespace(load_session=lambda profile: None), context_factory=factory)
    await manager.start_login("codex")
    page.form_progress = "verification-in-progress"
    await manager.start_login("codex")
    assert len(navigations) == 1
    assert page.form_progress == "verification-in-progress"


@pytest.mark.asyncio
async def test_auth_result_keeps_only_bounded_error_code_and_fixed_boolean_controls():
    session = SimpleNamespace(login=True, controlled_login=False, events=deque())

    async def body():
        return json.dumps({"code": 10003, "data": {"hasRisk": True, "idaasHasRisk": False,
                          "msg": "PRIVATE-MESSAGE-PASSWORD", "account": "PRIVATE-ACCOUNT"}}).encode()

    response = SimpleNamespace(url=next(iter(AUTH_POST_URLS)), request=SimpleNamespace(method="POST"),
                               status=200, body=body)
    await BrowserManager(None)._observe(session, response)
    event = session.events[-1]
    assert event["auth_result_code"] == 10003
    assert event["risk_flags"] == {"hasRisk": True, "idaasHasRisk": False}
    assert event["risk_message_present"] is True
    assert "PRIVATE" not in json.dumps(event)


@pytest.mark.asyncio
async def test_failed_login_retains_only_its_own_memory_diagnostics_and_cancel_clears():
    manager = BrowserManager(None)
    closed = []

    async def close():
        closed.append(True)

    event = {"method": "POST", "url": next(iter(AUTH_POST_URLS)), "auth_result_code": 10003}
    session = SimpleNamespace(login=True, context=SimpleNamespace(close=close), events=deque([event]))
    manager._sessions["codex"] = session
    manager._password_flows.attempts["codex"] = SimpleNamespace(status="failed")
    await manager._discard_password_login("codex", session)
    assert closed and "codex" not in manager._sessions
    assert (await manager.network_events("codex"))["events"] == [event]
    assert (await manager.network_events("workbuddy"))["events"] == []

    async def cancel(profile):
        return {"status": "cancelled"}

    manager._password_flows.cancel_login = cancel
    await manager.cancel_login("codex")
    assert (await manager.network_events("codex"))["events"] == []
