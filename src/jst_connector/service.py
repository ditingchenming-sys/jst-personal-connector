"""员工执行核心；AI 工具与可信管理界面共用业务入口，权限分开。"""
from __future__ import annotations

import asyncio
import secrets
import threading
from pathlib import Path

from .browser import BrowserManager
from .erp import ErpClient
from .errors import ConnectorError
from .identity import ServerIdentityVerifier
from .ledger import Ledger
from .platform_store import ensure_platform
from .vault import Vault


class ConnectorService:
    def __init__(self, root: Path, *, vault=None, browser=None, erp=None, platform="erp"):
        self.root = Path(root)
        self.platform = ensure_platform(self.root, platform)
        self.vault = vault or Vault(self.root)
        if self.platform == "drp":
            from .drp import DrpBrowserManager, DrpClient
            self.browser = browser or DrpBrowserManager(self.vault)
            self.erp = erp or DrpClient(self.browser)
        else:
            self.browser = browser or BrowserManager(self.vault, identity_verifier=ServerIdentityVerifier())
            self.erp = erp or ErpClient(self.browser)
        self.ledger = Ledger(self.root, self.vault)
        self._discovery = None
        self._interfaces = None
        self._writes = None
        self._area_children = {}
        self._area_lock = threading.RLock()

    def area_service(self, area=None):
        """Select this actor's business area without changing authorization.

        The public connector owns authentication. Its optional DRP service has
        its own cookies, verifier, contracts and ledger, but receives the same
        already-authenticated profile from the transport layer.
        """
        area = self.platform if area is None else area
        if not isinstance(area, str) or area not in {"erp", "drp"}:
            raise ConnectorError("invalid_area", "业务板块须为 erp（聚水潭ERP）或 drp（分销）。")
        if area == self.platform:
            return self
        if self.platform != "erp" or area != "drp":
            raise ConnectorError("area_unavailable", "此历史独立分销连接只管理自身分销授权，不能转用其他ERP连接。")
        with self._area_lock:
            if area not in self._area_children:
                # Do not adopt a previous standalone DRP store or EmployeeStore:
                # its separate actor bindings remain untouched and still usable.
                self._area_children[area] = ConnectorService(self.root / "modules" / area, platform=area)
            return self._area_children[area]

    def area_login_options(self, profile, area=None):
        target = self.area_service(area)
        result = target.login_options(profile)
        if self.platform == "erp" and target.platform == "drp":
            # Availability only means a saved source can be checked on demand;
            # opening login options does not launch an ERP browser or exchange.
            result["erp_sso_available"] = self.vault.load_session(profile) is not None
            result["erp_sso_source"] = "same_connector"
        return {**result, "area": target.platform, "default_area": self.platform,
                "areas": ["erp", "drp"] if self.platform == "erp" else ["drp"]}

    async def connect_area_from_erp(self, profile, area="drp"):
        target = self.area_service(area)
        if target.platform != "drp":
            raise ConnectorError("area_unavailable", "ERP接续入口仅用于当前员工的分销板块。")
        from .erp_sso import ErpLinks, connect_from_erp
        if self.platform == "drp":
            # Preserve explicitly paired 0.4 standalone installations.
            return await connect_from_erp(target, profile)
        if target.vault.load_session(profile):
            raise ConnectorError("ACCOUNT_ALREADY_CONNECTED", "本调用端已有分销账号，请先检查连接；换账号须先退出分销。")
        if self.vault.load_session(profile) is None:
            raise ConnectorError("erp_login_required", "请先连接本人的ERP账号，再按需接续分销；也可独立登录分销。")
        issued_binding = None
        try:
            async with self.browser.verified_scope(profile) as identity:
                binding = self.vault.session_binding(profile)
                saved = self.vault.load_session(profile)
                if saved is None or saved["identity"] != identity or not binding:
                    raise ConnectorError("erp_identity_changed", "当前ERP账号已变化，请重新核验本人连接。")
                # Both profiles and source root come from installed service state;
                # no model/web body can nominate another employee or directory.
                links = ErpLinks(target.root, target.vault)
                links.pair(profile, self.root, profile)
                paired = links.get(profile)
                if (paired.get("source_identity") != identity or paired.get("source_profile") != profile
                        or paired.get("source_root") != str(self.root.resolve())):
                    raise ConnectorError("erp_identity_changed", "ERP接续配对未绑定当前员工的本人来源。")
                result = await connect_from_erp(target, profile, include_binding=True)
                issued_binding = result.pop("_issued_binding", None)
                if not isinstance(issued_binding, str) or not issued_binding:
                    raise ConnectorError("erp_sso_unavailable", "本次分销接续缺少可核实的签发绑定，不能据此确认连接。")
                if self.vault.session_binding(profile) != binding:
                    raise ConnectorError("erp_identity_changed", "ERP会话在接续期间变化，本次分销连接已撤销，请重新核验。")
            return {**result, "area": "drp"}
        except BaseException:
            if issued_binding is not None:
                await target.browser.discard_if_binding(profile, issued_binding)
            raise

    def _generic(self):
        if self._interfaces is None:
            from .discovery_browser import DiscoveryBrowser
            from .interface_registry import InterfaceRegistry
            self._discovery = DiscoveryBrowser(self.browser)
            self._interfaces = InterfaceRegistry(self.root, self.vault, self.browser, self._discovery)
        return self._discovery, self._interfaces

    def _write_registry(self):
        if self._writes is None:
            from .write_registry import WriteRegistry
            discovery, interfaces = self._generic()
            self._writes = WriteRegistry(self.root, self.vault, self.browser, discovery, interfaces, self.ledger)
        return self._writes

    async def propose_write_interface(self, profile, body):
        return {"ok": True, "interface": await self._write_registry().propose(profile, body)}

    async def preview_write_interface(self, profile, interface_id, parameters=None):
        record = await self._write_registry().prepare(profile, interface_id, {} if parameters is None else parameters)
        return {"ok": True, "preview": record, "executable": record["status"] in {"ready", "approved"},
                "notice": "请本人或可信系统确认同一预览后执行。" if record["status"] in {"ready", "approved"}
                else "已存在同内容任务，仅返回原记录，不能重复提交。"}

    async def start_discovery(self, profile, url="", purpose="查看当前账号可访问的聚水潭页面"):
        from .adapters.login import ENTRY_URL
        await self.browser.identity(profile)
        discovery, interfaces = self._generic()
        policy = getattr(self.browser, "site_policy", None)
        url = url or (policy.entry_url if policy else ENTRY_URL)
        binding = self.vault.session_binding(profile)
        if not interfaces.entry_allowed(profile, url):
            raise ConnectorError("DISCOVERY_ENTRY_REJECTED", "该地址不符合当前连接可探查的聚水潭普通页面范围，未访问。")
        return {"ok": True, "discovery": await discovery.start(
            profile, url, entry_approved=True, expected_binding=binding)}

    async def inspect_discovery(self, profile, discovery_id, kind="page", reference="", search="", offset=0):
        discovery, _ = self._generic()
        return {"ok": True, "discovery": await discovery.inspect(
            profile, discovery_id, kind=kind, reference=reference, search=search, offset=offset)}

    async def interact_discovery(self, profile, discovery_id, element_ref, action, value=""):
        discovery, _ = self._generic()
        return {"ok": True, "discovery": await discovery.interact(
            profile, discovery_id, element_ref, action, value)}

    async def propose_read_interface(self, profile, body):
        _, interfaces = self._generic()
        result = await interfaces.propose(
            profile, body["discovery_id"], body["request_id"], body["name"], body["purpose"],
            body["read_evidence"], body.get("parameters", []), body["response_rules"])
        return {"ok": True, "interface": result}

    async def validate_read_interface(self, profile, interface_id, parameters=None):
        _, interfaces = self._generic()
        return {"ok": True, "result": await interfaces.validate(profile, interface_id, parameters or {})}

    async def call_saved_interface(self, profile, interface_id, parameters=None):
        _, interfaces = self._generic()
        return {"ok": True, "result": await interfaces.call(profile, interface_id, parameters or {})}

    async def list_interfaces(self, profile, query=""):
        await self.browser.identity(profile)
        _, interfaces = self._generic()
        return {"ok": True, "interfaces": interfaces.list(profile, query),
                "write_interfaces": self._write_registry().list(profile, query)}

    def authenticate(self, token: str) -> str:
        profile = self.vault.client_for_token(token)
        if profile is None:
            raise ConnectorError("unauthorized", "连接器调用授权无效，请重新配置此调用端。")
        return profile

    def authenticate_manager(self, token: str) -> None:
        if not token or not secrets.compare_digest(token.encode(), self.vault.manager_token().encode()):
            raise ConnectorError("management_authorization_required", "此操作仅限本人管理页面或可信系统授权。")

    async def status(self, profile: str) -> dict:
        connection = await self.browser.status(profile)
        modules = {self.platform: {"area": self.platform, "initialized": True, "live_checked": True,
                                   "connection": connection}}
        if self.platform == "erp":
            child = self._area_children.get("drp")
            modules["drp"] = {"area": "drp", "initialized": child is not None, "live_checked": False,
                              "status": "not_loaded"}
            if child is not None:
                try:
                    modules["drp"]["status"] = "saved_session" if child.vault.load_session(profile) else "disconnected"
                except ConnectorError:
                    modules["drp"]["status"] = "needs_check"
        return {"ok": True, "client": profile, "platform": self.platform, "area": self.platform,
                "connection": connection, "modules": modules}

    def login_options(self, profile=None):
        if self.platform == "drp":
            from .drp import LOGIN_TERMS
            from .erp_sso import ErpLinks
            sso_available = bool(profile and ErpLinks(self.root, self.vault).get(profile))
        else:
            from .adapters.login import LOGIN_TERMS
            sso_available = False
        return {"ok": True, "platform": self.platform, "terms": LOGIN_TERMS,
                "erp_sso_available": sso_available,
                "platform_name": "聚水潭分销平台" if self.platform == "drp" else "聚水潭ERP"}

    def catalog(self, query: str = "", profile: str | None = None) -> dict:
        catalog = self.erp.catalog()
        if query:
            words = query.casefold().split()
            catalog = [item for item in catalog if all(
                word in str(item).casefold() for word in words)]
        saved, saved_writes = [], []
        if profile and self.vault.load_session(profile):
            _, interfaces = self._generic()
            saved = interfaces.list(profile, query)
            saved_writes = self._write_registry().list(profile, query)
        return {"ok": True, "capabilities": catalog, "saved_interfaces": saved, "saved_writes": saved_writes,
                "notice": "预置接口仅为快捷入口；本人账号权限内的查询与操作均可按需探索、形成契约并复用。写入须真实预览、可信确认与结果回查，跨对象多步骤整批保证须单独核实。"}

    async def query(self, profile: str, capability_id: str, parameters: dict) -> dict:
        return {"ok": True, "client": profile, "capability_id": capability_id,
                "result": await self.erp.query(profile, capability_id, parameters)}

    async def preview(self, profile: str, capability_id: str, parameters: dict) -> dict:
        session = self.vault.load_session(profile)
        if session is None:
            raise ConnectorError("login_required", "请本人先登录并完成身份核验。")
        preview = getattr(self.erp, "preview", None)
        if preview is None:
            raise ConnectorError("preview_adapter_pending", "此操作的真实预览适配尚未完成，不能以展示参数冒充校验通过。")
        prepared = await preview(profile, capability_id, parameters)
        if not isinstance(prepared, dict) or not prepared.get("source_verified"):
            raise ConnectorError("preview_unverified", "未取得真实数据与原系统校验结果，不能生成可执行预览。")
        # 原子性由受信任适配器决定，绝不从 parameters 接收。
        record = self.ledger.create_preview(
            profile, session["identity"],
            {"capability_id": capability_id, "parameters": parameters, "prepared": prepared["payload"]},
            prepared["checks"], atomicity=prepared.get("atomicity", "unverified"),
        )
        return {"ok": True, "preview": record, "executable": record["atomicity"] == "verified"}

    def approve(self, profile: str, preview_id: str, digest: str) -> dict:
        session = self.vault.load_session(profile)
        if session is None:
            raise ConnectorError("login_required", "当前账号已退出，请重新登录并预览。")
        actor = {"source": "local_management", **session["identity"]}
        return {"ok": True, "preview": self.ledger.approve(profile, preview_id, digest, actor)}

    async def reconcile_operation(self, profile: str, preview_id: str) -> dict:
        current = self.ledger.get_preview(profile, preview_id)
        if current["status"] != "unknown":
            return {"ok": current["status"] == "succeeded", "preview": current,
                    "notice": "仅结果未知的原操作可回查更新；执行中的请求不会被并发改写。"}
        if current["payload"].get("kind") != "saved_write":
            raise ConnectorError("recheck_adapter_pending", "该历史操作尚未提供只读结果核对适配，未重新执行。")
        result = await self._write_registry().reconcile(profile, current["payload"])
        record = self.ledger.reconcile_unknown(profile, preview_id, current["digest"], result)
        return {"ok": record["status"] == "succeeded", "preview": record, "notice": result["notice"]}

    async def execute(self, profile: str, preview_id: str, digest: str) -> dict:
        current = self.ledger.get_preview(profile, preview_id)
        if current["status"] == "superseded":
            raise ConnectorError("preview_stale", "业务数据已变化，旧预览和确认已失效，请使用重新生成的预览。")
        if current["status"] in ("succeeded", "failed", "unknown", "executing"):
            return {"ok": current["status"] == "succeeded", "preview": current, "replayed": False,
                    "notice": "任务已执行或已占用，仅返回原记录，不重新提交。"}
        generic = current["payload"].get("kind") == "saved_write"
        adapter = self._write_registry() if generic else self.erp
        executor = getattr(adapter, "execute", None)
        revalidate = getattr(adapter, "revalidate", None)
        if executor is None or revalidate is None:
            raise ConnectorError("write_adapter_pending", "当前没有已验证整批提交保证的执行适配器，未发出业务写请求。")
        session = self.vault.load_session(profile)
        if session is None:
            raise ConnectorError("login_required", "当前账号已退出，请重新登录。")
        if current["status"] != "approved":
            raise ConnectorError("confirmation_required", "请本人或可信系统先确认同一预览。")
        if not await revalidate(profile, current["payload"]):
            raise ConnectorError("preview_stale", "原系统数据或业务状态已变化，请重新预览并确认；未执行。")
        try:
            claimed = self.ledger.claim(profile, preview_id, digest, session["identity"])
        except ConnectorError as error:
            if generic and error.code == "preview_not_approved":
                latest = self.ledger.get_preview(profile, preview_id)
                if latest["status"] in {"executing", "succeeded", "failed", "unknown"}:
                    return {"ok": latest["status"] == "succeeded", "preview": latest, "replayed": False}
            raise
        try:
            result = await executor(profile, claimed["payload"])
        except asyncio.CancelledError:
            self.ledger.finish(profile, preview_id, "unknown", {
                "message": "执行连接被取消，结果未知，须先回查。"})
            raise
        except Exception:  # noqa: BLE001 -- 占用后的任意异常都须记为未知，且不向调用方泄露底层异常内容。
            # 已占用之后的异常均保守记为未知，绝不自动判为无副作用失败后重试。
            self.ledger.finish(profile, preview_id, "unknown", {
                "message": "请求中断，结果未知；须先回查，禁止自动重试。"})
            raise ConnectorError("result_unknown", "请求中断，业务结果未知；须先回查，不能重新提交。") from None
        if not isinstance(result, dict) or not result.get("verified"):
            record = self.ledger.finish(profile, preview_id, "unknown", {
                "message": "提交后的业务结果尚未完整回查，请核对原系统，不可重复提交。"})
        else:
            record = self.ledger.finish(profile, preview_id, "succeeded", result)
        return {"ok": record["status"] == "succeeded", "preview": record}

    async def close_idle(self):
        for child in tuple(self._area_children.values()):
            await child.close_idle()
        cleanup = getattr(self.browser, "close_idle", None)
        if callable(cleanup):
            await cleanup()

    async def close(self):
        try:
            for child in tuple(self._area_children.values()):
                await child.close()
        finally:
            if self._discovery is not None:
                await self._discovery.close()
            await self.browser.close()

