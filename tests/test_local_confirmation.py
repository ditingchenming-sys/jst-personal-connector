"""确认能力只交付本人浏览器，AI调用令牌不能替代本人确认。"""
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from test_auto_drp_service import (
    auto_env,  # noqa: F401 -- shared isolated exchange fixture
    source,
)
from test_auto_drp_service import root as auto_root
from test_service_api import service  # noqa: F401 -- reuse isolated fixtures

from jst_connector.agent import create_app

root = auto_root


@pytest.mark.parametrize("action", ["status", "approve"])
@pytest.mark.parametrize("source_change", ["logout", "switch"])
def test_drp_confirmation_rejects_old_auto_identity_after_erp_source_changes(auto_env, action, source_change):  # noqa: F811
    env = auto_env
    source(env)
    opened = []
    with TestClient(create_app(env.root, opener=lambda url: opened.append(url) or True)) as client:
        headers = {"Authorization": "Bearer " + env.root.vault.ensure_client("alice")}
        prepared = client.post("/api/preview", json={"area": "drp", "capability_id": "fixture", "parameters": {}}, headers=headers)
        assert prepared.status_code == 200
        preview = prepared.json()["preview"]
        result = client.post("/api/open-confirmation", json={"area": "drp", "preview_id": preview["preview_id"],
                                                             "digest": preview["digest"]}, headers=headers)
        assert result.json()["ok"]
        grant = parse_qs(urlsplit(opened[-1]).fragment)["grant"][0]
        assert env.calls == ["alice"]
        env.root.vault.clear_session("alice")
        if source_change == "switch":
            source(env, identity={"company_id": "200", "user_id": "301"})
        response = client.post("/confirmation/" + action,
                               json={"area": "drp", "digest": preview["digest"]},
                               headers={"Authorization": "Bearer " + grant})
        assert response.status_code == 409
        assert response.json()["error"]["code"] == ("identity_changed" if source_change == "switch" else "auto_drp_unavailable")
        assert env.target.erp.executions == []


def test_local_confirmation_is_scoped_single_use_and_not_returned_to_ai(service):  # noqa: F811
    import asyncio
    preview = asyncio.run(service.preview("codex", "W03", {}))["preview"]
    opened = []
    token = service.vault.ensure_client("codex")
    headers = {"Authorization": "Bearer " + token}
    with TestClient(create_app(service, opener=lambda url: opened.append(url) or True)) as client:
        response = client.post("/api/open-confirmation", json={
            "preview_id": preview["preview_id"], "digest": preview["digest"]}, headers=headers)
        assert response.json()["ok"] is True
        grant = parse_qs(urlsplit(opened[0]).fragment)["grant"][0]
        assert grant not in response.text and service.vault.manager_token() not in response.text
        assert client.post("/confirmation/approve", json={"digest": preview["digest"]}, headers=headers).status_code == 401
        human = {"Authorization": "Bearer " + grant}
        status = client.post("/confirmation/status", headers=human).json()
        assert status["preview"]["preview_id"] == preview["preview_id"]
        assert client.post("/confirmation/approve", json={"digest": "changed"}, headers=human).status_code == 409
        approved = client.post("/confirmation/approve", json={"digest": preview["digest"]}, headers=human)
        assert approved.json()["preview"]["status"] == "approved"
        assert client.post("/confirmation/approve", json={"digest": preview["digest"]}, headers=human).status_code == 401
        assert client.post("/api/execute", json={"preview_id": preview["preview_id"],
                           "digest": preview["digest"]}, headers=headers).json()["ok"] is True
        assert service.erp.executions == 1


def test_local_confirmation_never_returns_other_profiles_preview(service):  # noqa: F811
    import asyncio
    preview = asyncio.run(service.preview("codex", "W03", {}))["preview"]
    token = service.vault.ensure_client("other-ai")
    opened = []
    with TestClient(create_app(service, opener=lambda url: opened.append(url) or True)) as client:
        response = client.post("/api/open-confirmation", json={
            "preview_id": preview["preview_id"], "digest": preview["digest"]},
            headers={"Authorization": "Bearer " + token})
        assert response.status_code == 409
        assert not opened


def test_local_confirmation_page_requires_human_click_in_real_chromium(service):  # noqa: F811
    import asyncio

    from playwright.sync_api import expect, sync_playwright

    preview = asyncio.run(service.preview("codex", "W03", {}))["preview"]
    opened = []
    headers = {"Authorization": "Bearer " + service.vault.ensure_client("codex")}
    with TestClient(create_app(service, opener=lambda url: opened.append(url) or True)) as client, sync_playwright() as playwright:
        client.post("/api/open-confirmation", json={"preview_id": preview["preview_id"],
                    "digest": preview["digest"]}, headers=headers)
        browser = playwright.chromium.launch()
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))

        def controlled(route):
            assert route.request.url.startswith("http://testserver/")
            response = client.request(route.request.method, route.request.url,
                                      headers=route.request.headers, content=route.request.post_data)
            route.fulfill(status=response.status_code, headers=dict(response.headers), body=response.content)

        page.route("**/*", controlled)
        page.goto(opened[0])
        assert page.locator("iframe").count() == 0
        expect(page.locator("#approve")).to_be_enabled()
        assert "fixture-company" in page.locator("#summary").inner_text()
        assert "grant=" not in page.url
        assert service.ledger.get_preview("codex", preview["preview_id"])["status"] == "ready"
        page.get_by_role("button", name="确认此预览", exact=True).click()
        expect(page.locator("#message")).to_contain_text("已确认此预览")
        assert service.ledger.get_preview("codex", preview["preview_id"])["status"] == "approved"
        assert not errors
        browser.close()
