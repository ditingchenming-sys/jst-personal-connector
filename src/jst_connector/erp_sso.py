"""由可信安装配置配对的ERP→分销官方换发；票据和Cookie不交给模型。"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from playwright.async_api import Error as PlaywrightError

from .config import profile_name
from .errors import ConnectorError
from .platform_store import ensure_platform
from .vault import Vault

REDIRECT_TOKEN_URL = "https://api.erp321.com/usercenterapi/SupplyChain/GetRedirectTokenV2"


class ErpLinks:
    def __init__(self, root, vault):
        self.root, self.vault = Path(root), vault
        self.path = self.root / "sso-links.sqlite3"

    def get(self, profile):
        if not self.path.exists():
            return None
        with sqlite3.connect(self.path) as connection:
            row = connection.execute("SELECT encrypted FROM links WHERE profile=?", (profile,)).fetchone()
        return self.vault.unseal(row[0]) if row else None

    def pair(self, profile, source_root, source_profile):
        # Called only by native CLI / trusted administrator, never by an AI tool or web body.
        profile, source_profile = profile_name(profile), profile_name(source_profile)
        source_root = Path(source_root).expanduser().resolve()
        if source_root == self.root.resolve() or not (source_root / "vault.enc").is_file():
            raise ConnectorError("erp_link_invalid", "请指定已登录ERP的独立运行目录。")
        ensure_platform(source_root, "erp")
        source = Vault(source_root)
        saved = source.load_session(source_profile)
        if saved is None:
            raise ConnectorError("erp_login_required", "来源ERP调用端尚未登录，请先本人连接ERP再配对。")
        record = {"profile": profile, "source_root": str(source_root), "source_profile": source_profile,
                  "source_identity": saved["identity"], "source_platform": "erp", "target_platform": "drp"}
        with sqlite3.connect(self.path) as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS links (profile TEXT PRIMARY KEY,encrypted TEXT NOT NULL)")
            connection.execute("INSERT INTO links VALUES (?,?) ON CONFLICT(profile) DO UPDATE SET encrypted=excluded.encrypted",
                               (profile, self.vault.seal(record)))
        self.path.chmod(0o600)
        return {"ok": True, "message": "已配对本人的ERP来源；在分销授权页可免填密码接续，执行时仍核验实际身份。"}


async def connect_from_erp(service, profile, *, source_factory=None, include_binding=False):
    if service.platform != "drp":
        raise ConnectorError("platform_mismatch", "此接续入口仅用于分销平台。")
    record = ErpLinks(service.root, service.vault).get(profile)
    if (not isinstance(record, dict) or record.get("profile") != profile or record.get("source_platform") != "erp"
            or record.get("target_platform") != "drp"):
        raise ConnectorError("erp_link_required", "尚未配对本人的ERP来源，可直接登录分销，或由管理员配置ERP接续。")
    if service.vault.load_session(profile):
        raise ConnectorError("ACCOUNT_ALREADY_CONNECTED", "分销调用端已有账号，请先检查连接；换账号须先退出。")
    if source_factory is None:
        from .service import ConnectorService
        source_factory = ConnectorService
    source = source_factory(Path(record["source_root"]), platform="erp")
    response = None
    issued_binding = None
    try:
        async with source.browser.verified_scope(record["source_profile"]) as identity:
            if identity != record["source_identity"]:
                raise ConnectorError("erp_identity_changed", "配对的ERP账号或公司已变化，请重新核对配对；未接续。")
            session = source.browser._sessions[record["source_profile"]]
            binding = source.vault.session_binding(record["source_profile"])
            response = await session.context.request.post(REDIRECT_TOKEN_URL,
                data={"data": {}, "uid": int(identity["user_id"]), "coid": int(identity["company_id"])},
                headers={"Content-Type": "application/json", "Referer": "https://www.erp321.com/epaas"},
                max_redirects=0, timeout=15000)
            if response.url != REDIRECT_TOKEN_URL or response.status != 200:
                raise ConnectorError("erp_sso_unavailable", "ERP官方分销接续请求未成功，可使用分销独立登录。")
            body = await response.body()
            if len(body) > 262144:
                raise ConnectorError("erp_sso_unavailable", "ERP接续响应无法核验，请使用分销独立登录。")
            value = json.loads(body)
            if (not isinstance(value, dict) or type(value.get("code")) is not int or value["code"] != 0
                    or type(value.get("act")) is not int or value["act"] != 0):
                raise ConnectorError("erp_sso_unavailable", "ERP未签发分销接续授权，可使用分销独立登录。")
            token = value.get("data", {}).get("details", {}).get("access_token")
            if not isinstance(token, str) or not 8 <= len(token) <= 8192 or any(c.isspace() for c in token):
                raise ConnectorError("erp_sso_unavailable", "未取得可核验的分销接续授权，可使用分销独立登录。")
            source.browser._assert_scope(record["source_profile"], session, identity)
            result = await service.browser.accept_erp_token(profile, token, identity)
            issued_binding = result.pop("_issued_binding")
            token = None
            if source.vault.session_binding(record["source_profile"]) != binding:
                raise ConnectorError("erp_identity_changed", "ERP会话在接续时变化，已撤销本次分销连接，请重新核验。")
        # verified_scope rechecks its identity on exit; do not return before it completes.
        response_value = {"ok": True, "login": result}
        if include_binding:
            # Installed aggregation code removes this before returning any public response.
            response_value["_issued_binding"] = issued_binding
        return response_value
    except (PlaywrightError, OSError, ValueError, TypeError, AttributeError):
        if issued_binding is not None:
            await service.browser.discard_if_binding(profile, issued_binding)
        raise ConnectorError("erp_sso_unavailable", "ERP接续未完成；未复制ERP Cookie，可直接使用分销账号登录。") from None
    except BaseException:
        if issued_binding is not None:
            await service.browser.discard_if_binding(profile, issued_binding)
        raise
    finally:
        try:
            if response is not None:
                await response.dispose()
        finally:
            await source.close()
