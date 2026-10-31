"""确认能力只交付本人浏览器，AI调用令牌不能替代本人确认。"""
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient
from test_service_api import service  # noqa: F401 -- reuse isolated fixtures

from jst_connector.agent import create_app


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
