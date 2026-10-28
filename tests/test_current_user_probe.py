import asyncio
import json
import time
from types import SimpleNamespace

import pytest

from jst_connector.errors import ConnectorError
from jst_connector.identity_probe import CURRENT_USER_URL, inspect_current_user_source


@pytest.mark.asyncio
async def test_current_user_probe_uses_own_receipt_and_returns_only_schema():
    calls, disposed = [], []
    cancel_during_body = False

    class Response:
        status = 200

        async def body(self):
            if cancel_during_body:
                attempt.cancelled = True
            return json.dumps({"code": 0, "act": 0, "data": {
                "companyName": "PRIVATE-COMPANY", "userId": 123, "coId": 456,
                "token": "PRIVATE-TOKEN", "ActualEmployeeName": "PRIVATE-NAME",
                "apps": ["PRIVATE-APP"]}}).encode()

        async def dispose(self):
            disposed.append(True)

    async def post(url, **kwargs):
        calls.append((url, kwargs))
        return Response()

    session = SimpleNamespace(login=True, server_identity_candidate={"user_id": "123", "company_id": "456"},
                              server_identity_conflicted=False, server_passport_receipted=True,
                              context=SimpleNamespace(request=SimpleNamespace(post=post)))
    attempt = SimpleNamespace(session=session, cancelled=False, status="identity_pending", deadline=time.monotonic()+60)
    lock = asyncio.Lock()
    browser = SimpleNamespace(_lock=lambda profile: lock, _sessions={"codex": session},
                              _password_flows=SimpleNamespace(attempts={"codex": attempt}))
    result = await inspect_current_user_source(browser, "codex")
    assert calls == [(CURRENT_USER_URL, {"data": {"data": {}, "uid": 123, "coid": 456},
                                         "timeout": 10000, "max_redirects": 0})]
    assert result["ids_match_receipt"] == {"userId": True, "coId": True}
    assert result["code_zero"] and result["act_zero"] and not result["verified"]
    assert "PRIVATE" not in json.dumps(result) and disposed == [True]
    assert "ActualEmployeeName" not in json.dumps(result)
    attempt.deadline = time.monotonic()-1
    with pytest.raises(ConnectorError):
        await inspect_current_user_source(browser, "codex")
    assert len(calls) == 1
    attempt.deadline = time.monotonic()+60
    cancel_during_body = True
    with pytest.raises(ConnectorError, match="会话已变化"):
        await inspect_current_user_source(browser, "codex")
    assert len(calls) == 2 and disposed == [True, True]


@pytest.mark.asyncio
async def test_current_user_probe_does_not_call_without_active_own_login():
    browser = SimpleNamespace(_lock=lambda profile: asyncio.Lock(), _sessions={},
                              _password_flows=SimpleNamespace(attempts={}))
    with pytest.raises(ConnectorError):
        await inspect_current_user_source(browser, "codex")
