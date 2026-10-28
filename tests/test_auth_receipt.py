"""仅离线验证服务器签发候选；不访问真实账号、Cookie或ERP。"""
import asyncio
import json
import time
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from jst_connector.adapters.login import ENTRY_URL
from jst_connector.auth_receipt import PASSPORT_URL, identity_cookie_receipt
from jst_connector.browser import BrowserManager, _Session
from jst_connector.errors import ConnectorError

NOW = datetime(2030, 1, 1, tzinfo=UTC)
HEADERS = ["u_id=111111; Domain=.erp321.com; Path=/; Secure; HttpOnly",
           "u_co_id=222222; Domain=.erp321.com; Path=/; Secure"]


def receipt(headers=HEADERS, **options):
    arguments = {"response_url": PASSPORT_URL, "method": "POST", "status": 200,
                 "set_cookie_headers": headers, "active": True, "passport_code": 0, "now": NOW}
    arguments.update(options)
    return identity_cookie_receipt(**arguments)


def test_exact_passport_receipt_extracts_private_positive_ids_without_printable_values():
    result = receipt()
    assert result.candidates == {"user_id": "111111", "company_id": "222222"}
    assert "111111" not in repr(result) and "222222" not in repr(result)
    assert result.sources["user_id"] == {
        "response_url": PASSPORT_URL, "method": "POST", "via": "set-cookie", "cookie_name": "u_id",
        "cookie_domain": "erp321.com", "cookie_path": "/", "host_only": False}


@pytest.mark.parametrize("options", [
    {"active": False}, {"active": "true"}, {"status": 302}, {"status": 401}, {"status": 500},
    {"method": "GET"}, {"passport_code": 1}, {"passport_code": 10003}, {"passport_code": False},
    {"passport_code": "0"}, {"passport_code": None},
    {"response_url": PASSPORT_URL.replace("https:", "http:")},
    {"response_url": PASSPORT_URL.replace("api.erp321.com", "api.erp321.com.evil.example")},
    {"response_url": PASSPORT_URL.replace("https://", "https://user:secret@")},
    {"response_url": PASSPORT_URL + "?user_id=111111"}, {"response_url": PASSPORT_URL + "#fragment"},
    {"response_url": PASSPORT_URL.replace("api.erp321.com", "api.erp321.com:443")},
    {"response_url": ENTRY_URL, "method": "GET", "passport_succeeded": False},
    {"response_url": ENTRY_URL, "method": "POST", "passport_succeeded": True},
])
def test_wrong_source_phase_method_status_or_code_is_never_evidence(options):
    assert receipt(**options) is None


def test_entry_receipt_requires_same_session_passport_success_and_matching_scope():
    result = receipt(response_url=ENTRY_URL, method="GET", passport_succeeded=True)
    assert result.candidates == {"user_id": "111111", "company_id": "222222"}
    host_only = receipt(["u_id=111111"], response_url=ENTRY_URL, method="GET", passport_succeeded=True)
    assert host_only.sources["user_id"]["cookie_domain"] == "www.erp321.com"
    assert host_only.sources["user_id"]["cookie_path"] == "/" and host_only.sources["user_id"]["host_only"]


@pytest.mark.parametrize("header", [
    "u_id=111111; Domain=.evil.example; Path=/", "u_id=111111; Domain=.com; Path=/",
    "u_id=111111; Domain=www.erp321.com; Path=/", "u_id=111111; Domain=.erp321.com.evil.example; Path=/",
    "u_id=111111; Domain=..erp321.com; Path=/", "u_id=111111; Domain=erp321.com.; Path=/",
    "u_id=111111; Path=/different", "u_id=111111; Path=/er", "u_id=111111; Path=relative",
    "u_id=0; Path=/", "u_id=-1; Path=/", "u_id=1.0; Path=/", "u_id=000111; Path=/",
    "u_id=１１１１１１; Path=/", "u_id=; Path=/", "u_id=111%31; Path=/",
    "u_id=111111; Max-Age=0; Path=/", "u_id=111111; Max-Age=-1; Path=/",
    "u_id=111111; Max-Age=invalid; Path=/", "u_id=111111; Max-Age=; Path=/",
    "u_id=111111; Expires=Wed, 01 Jan 2020 00:00:00 GMT; Path=/",
    "u_id=111111; Expires=invalid; Path=/",
    "u_id=111111; Domain=.erp321.com; Domain=.evil.example; Path=/",
    "u_id=111111; Path=/; Path=/different", "u_id=111111; u_co_id=222222; Path=/",
    "u_id=111111\r\nSet-Cookie: u_co_id=222222", "unrelated_token=DO-NOT-KEEP; Path=/",
])
def test_invalid_foreign_deleted_ambiguous_or_non_numeric_cookie_is_not_a_candidate(header):
    assert not receipt([header]).candidates


def test_duplicate_cookie_names_are_not_silently_resolved_by_last_value():
    result = receipt([HEADERS[0], "u_id=333333; Domain=.erp321.com; Path=/", HEADERS[1]])
    assert result.candidates == {"company_id": "222222"}
    assert result.rejected_fields == {"user_id"}


def test_explicit_valid_future_expiry_and_positive_max_age_are_accepted():
    result = receipt(["u_id=111111; Domain=.erp321.com; Path=/; Max-Age=60; Expires=Wed, 01 Jan 2031 00:00:00 GMT"])
    assert result.candidates == {"user_id": "111111"}


def test_default_and_explicit_path_follow_response_path_boundary():
    result = receipt(["u_id=111111", "u_co_id=222222; Domain=ERP321.COM; Path=/erp"])
    assert result.sources["user_id"]["cookie_path"] == "/erp/webapi/UserApi/WebLogin"
    assert result.sources["company_id"]["cookie_path"] == "/erp"
    assert not receipt(["u_id=111111; Path=/epa"], response_url=ENTRY_URL,
                       method="GET", passport_succeeded=True).candidates


class Response:
    def __init__(self, url=PASSPORT_URL, method="POST", status=200, code=0, headers=HEADERS):
        self.url = url
        self.request = SimpleNamespace(method=method, url=url)
        self.status = status
        self.value = {"code": code, "data": {"msg": "DUMMY-NOTICE-NOT-FOR-OUTPUT"}}
        self.headers = headers
        self.header_calls = 0

    async def body(self):
        return json.dumps(self.value).encode()

    @property
    def headers_array(self):
        self.header_calls += 1
        return [{"name": "Set-Cookie", "value": value} for value in self.headers]


async def capture(manager, session, response):
    await manager._capture_server_identity_receipt(session, response.request, response)


def manager_and_session():
    vault = SimpleNamespace(load_session=lambda profile: None, session_binding=lambda profile: None,
                            save_session=Mock())
    manager = BrowserManager(vault)
    context = SimpleNamespace(close=AsyncMock(), cookies=AsyncMock(side_effect=AssertionError("cookie jar must not be read")))
    session = _Session(context, SimpleNamespace(), profile="codex", login=True, controlled_login=True)
    manager._sessions["codex"] = session
    attempt = SimpleNamespace(status="identity_pending", cancelled=False, session=session,
                              deadline=time.monotonic() + 600)
    manager._password_flows.attempts["codex"] = attempt
    return manager, session, attempt


@pytest.mark.asyncio
async def test_upstream_collector_keeps_candidates_private_without_setting_verified_connected_or_saving():
    manager, session, _ = manager_and_session()
    await capture(manager, session, Response())
    assert session.server_identity_candidate == {"user_id": "111111", "company_id": "222222"}
    assert session.identity is None and not session.verified and manager._verifier is None
    assert manager.vault.save_session.call_count == session.context.cookies.call_count == 0
    assert (await manager.status("codex"))["status"] == "login_pending"
    with pytest.raises(ConnectorError):
        await manager.identity("codex")
    diagnostics = json.dumps(await manager.network_events("codex"))
    assert "111111" not in diagnostics and "222222" not in diagnostics and "DUMMY-NOTICE" not in diagnostics
    assert session.events[-1]["server_identity_cookie_fields"] == ["u_co_id", "u_id"]
    assert "111111" not in repr(session)


@pytest.mark.asyncio
async def test_entry_is_ignored_before_passport_and_conflicts_cannot_replace_private_candidate():
    manager, session, _ = manager_and_session()
    early = Response(ENTRY_URL, "GET")
    await capture(manager, session, early)
    assert early.header_calls == 0 and not session.server_identity_candidate
    await capture(manager, session, Response())
    await capture(manager, session, Response(ENTRY_URL, "GET", headers=["u_id=333333; Domain=.erp321.com; Path=/"]))
    assert session.server_identity_conflicted and not session.server_identity_candidate
    await capture(manager, session, Response(ENTRY_URL, "GET"))
    assert not session.server_identity_candidate


@pytest.mark.asyncio
async def test_same_session_entry_can_complete_partial_receipt_without_replacing_first_source():
    manager, session, _ = manager_and_session()
    await capture(manager, session, Response(headers=[HEADERS[0]]))
    await capture(manager, session, Response(ENTRY_URL, "GET", headers=HEADERS))
    assert session.server_identity_candidate == {"user_id": "111111", "company_id": "222222"}
    assert session.server_identity_sources["user_id"]["response_url"] == PASSPORT_URL
    assert session.server_identity_sources["company_id"]["response_url"] == ENTRY_URL
    assert session.identity is None and not session.verified and manager.vault.save_session.call_count == 0


@pytest.mark.parametrize("headers", [
    ["u_id=0; Domain=.erp321.com; Path=/"],
    ["u_id=111111; Domain=.erp321.com; Path=/; Max-Age=0"],
    ["u_id=111111; Domain=.erp321.com; Path=/; Expires=Wed, 01 Jan 2020 00:00:00 GMT"],
    ["u_id=111111; Domain=.erp321.com; Path=/", "u_id=333333; Domain=.erp321.com; Path=/"],
    ["u_id=111111, u_co_id=222222; Domain=.erp321.com; Path=/"],
    ["u_id=111111; Domain=.evil.example; Path=/"],
])
@pytest.mark.asyncio
async def test_later_identity_cookie_deletion_rejection_or_ambiguity_invalidates_entire_old_chain(headers):
    manager, session, _ = manager_and_session()
    await capture(manager, session, Response())
    await capture(manager, session, Response(ENTRY_URL, "GET", headers=headers))
    assert session.server_identity_conflicted
    assert not session.server_identity_candidate and not session.server_identity_sources
    assert "u_id" in session.events[-1]["server_identity_cookie_rejected_fields"]
    await capture(manager, session, Response(ENTRY_URL, "GET"))
    assert not session.server_identity_candidate  # A later value cannot silently revive the old chain.
    diagnostics = json.dumps(await manager.network_events("codex"))
    assert all(value not in diagnostics for value in ("111111", "222222", "333333"))


@pytest.mark.asyncio
async def test_wrong_passport_result_clears_previous_receipt_and_disables_entry_receipt():
    manager, session, _ = manager_and_session()
    await capture(manager, session, Response())
    await capture(manager, session, Response(code=10003))
    assert not session.server_passport_receipted and not session.server_identity_candidate
    entry = Response(ENTRY_URL, "GET")
    await capture(manager, session, entry)
    assert entry.header_calls == 0


@pytest.mark.asyncio
async def test_synthesized_browser_observer_cannot_recollect_or_clear_upstream_receipt():
    manager, session, _ = manager_and_session()
    await capture(manager, session, Response())
    synthesized = Response(headers=["u_id=0; Path=/"])
    await manager._observe(session, synthesized)
    assert synthesized.header_calls == 0
    assert session.server_identity_candidate == {"user_id": "111111", "company_id": "222222"}
    assert session.events[0]["server_identity_cookie_source"] == "upstream_http_response"


@pytest.mark.asyncio
async def test_upstream_response_url_cannot_be_substituted_for_original_request():
    manager, session, _ = manager_and_session()
    response = Response()
    response.url = ENTRY_URL
    await capture(manager, session, response)
    assert not session.server_identity_candidate and response.header_calls == 0


@pytest.mark.parametrize("inactive", ["cancelled", "failed", "expired", "unmapped", "uncontrolled"])
@pytest.mark.asyncio
async def test_inactive_context_never_reads_or_accepts_identity_headers(inactive):
    manager, session, attempt = manager_and_session()
    if inactive == "cancelled":
        attempt.cancelled = True
    elif inactive == "failed":
        attempt.status = "failed"
    elif inactive == "expired":
        attempt.deadline = time.monotonic() - 1
    elif inactive == "unmapped":
        manager._sessions.pop("codex")
    else:
        session.controlled_login = False
    response = Response()
    await capture(manager, session, response)
    assert response.header_calls == 0 and not session.server_identity_candidate


@pytest.mark.asyncio
async def test_cancel_during_upstream_body_read_cannot_repopulate_destroyed_private_receipt():
    manager, session, _ = manager_and_session()
    entered, release = asyncio.Event(), asyncio.Event()
    response = Response()

    async def slow_body():
        entered.set()
        await release.wait()
        return json.dumps(response.value).encode()

    response.body = slow_body
    task = asyncio.create_task(capture(manager, session, response))
    await entered.wait()
    await manager._discard_password_login("codex", session)
    release.set()
    await task
    assert not session.server_identity_candidate and not session.server_identity_sources
    assert not session.server_passport_receipted
    session.context.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_real_chromium_collects_upstream_http_headers_before_fulfill_without_reading_jar(monkeypatch):
    from playwright.async_api import async_playwright

    import jst_connector.auth_receipt as receipt_module
    import jst_connector.browser as browser_module

    requests = []
    html = b"""<!doctype html><script>
      fetch('/erp/webapi/UserApi/WebLogin/Passport',{method:'POST'})
        .then(r=>r.json()).then(()=>{location.href='/epaas'});
      </script>"""

    async def handler(reader, writer):
        headers = await reader.readuntil(b"\r\n\r\n")
        method, path, _ = headers.split(b"\r\n", 1)[0].split(b" ")
        requests.append((method, path))
        length = next((int(line.split(b":", 1)[1]) for line in headers.split(b"\r\n")
                       if line.lower().startswith(b"content-length:")), 0)
        if length:
            await reader.readexactly(length)
        cookie = b""
        kind = b"text/html"
        body = html
        if method == b"POST":
            body = b'{"code":0,"data":{"hasRisk":false,"idaasHasRisk":false}}'
            kind = b"application/json"
            cookie = b"Set-Cookie: u_id=111111; Path=/; HttpOnly\r\n"
        elif path == b"/epaas":
            body = b"local protected entry"
            cookie = b"Set-Cookie: u_co_id=222222; Path=/; HttpOnly\r\n"
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: " + kind + b"\r\n" + cookie
                     + b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    origin = "http://127.0.0.1:" + str(server.sockets[0].getsockname()[1])
    passport, entry, login = origin + "/erp/webapi/UserApi/WebLogin/Passport", origin + "/epaas", origin + "/login"
    # Only this isolated test remaps the exact reviewed sources to loopback. Production
    # constants remain HTTPS ERP URLs and production routing is never broadened.
    monkeypatch.setattr(receipt_module, "PASSPORT_URL", passport)
    monkeypatch.setattr(receipt_module, "ENTRY_URL", entry)
    monkeypatch.setattr(browser_module, "PASSPORT_URL", passport)
    monkeypatch.setattr(browser_module, "ENTRY_URL", entry)
    monkeypatch.setattr(browser_module, "LOGIN_URL", login)
    monkeypatch.setattr(browser_module, "AUTH_POST_URLS", {passport})
    manager, session, _ = manager_and_session()
    async with async_playwright() as playwright:
        chromium = await playwright.chromium.launch(headless=True)
        context = await chromium.new_context(service_workers="block")
        await context.add_cookies([{"name": "u_id", "value": "999999", "url": origin}])
        context.cookies = AsyncMock(side_effect=AssertionError("jar must not supply identity evidence"))
        session.context, session.page = context, await context.new_page()
        session.auth_urls, session.auth_remaining, session.auth_deadline = {passport}, 1, time.monotonic() + 60
        await context.route("**/*", lambda route: manager._route(session, route))
        session.page.on("response", lambda response: manager._observe(session, response))
        try:
            await session.page.goto(login)
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and len(session.server_identity_candidate) < 2:
                await asyncio.sleep(0.01)
            assert session.server_identity_candidate == {"user_id": "111111", "company_id": "222222"}
            assert requests == [(b"GET", b"/login"), (b"POST", b"/erp/webapi/UserApi/WebLogin/Passport"),
                                (b"GET", b"/epaas")]
            context.cookies.assert_not_awaited()
            assert manager.vault.save_session.call_count == 0 and session.identity is None and not session.verified
            events = (await manager.network_events("codex"))["events"]
            receipts = [event for event in events if event.get("classification") == "upstream_identity_receipt"]
            assert [event["server_identity_cookie_fields"] for event in receipts] == [["u_id"], ["u_co_id"]]
            assert all(event["server_identity_cookie_source"] == "upstream_http_response" for event in receipts)
            assert all(value not in json.dumps(events) for value in ("111111", "222222", "999999", "Set-Cookie"))
        finally:
            await context.close()
            await chromium.close()
            server.close()
            await server.wait_closed()
