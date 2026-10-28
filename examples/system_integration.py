"""业务系统集成接口示例，不启动服务、不登录 ERP、不生成虚假员工身份。

生产接入必须提供真实应用认证、私有预览存储及确认记录验证。
密钥、配对凭据应由系统密钥存储管理，不能写入源码或发给 AI。
员工领取/结果接口从已认证的配对会话取得身份，不能从 JSON 的 actor 字段取身份。
"""

from collections.abc import Callable
from pathlib import Path

from jst_connector.bridge import Binding, TaskQueue, TaskSigner
from jst_connector.system_sdk import SystemSDK


def build_system_sdk(*, private_queue_path: Path, signing_key: bytes,
                     resolve_authenticated_employee: Callable[[object], Binding],
                     load_verified_preview: Callable[[object, str], dict],
                     verify_employee_confirmation: Callable[[object, object, dict], bool]) -> SystemSDK:
    """回调应连接业务系统现有认证模块，不能用默认管理员或请求自报的身份替代。

    resolve: 将应用已验证会话映射到本人公司、员工和已授权连接器 profile。
    load: 读取该员工可见且由 ERP 真实数据校验过的完整预览，返回 id/digest/payload。
    verify: 读取服务端确认记录，核对本人点击、预览摘要、profile、有效期，拒绝重放或伪造。
    系统须用稳定 task_id 做业务防重复，已经领取或结果未知时先回查，不新建重试任务。
    员工端执行还须核验 ERP 会话身份、Ledger 预览与整批原子提交能力。
    """
    queue = TaskQueue(private_queue_path, TaskSigner(signing_key))
    return SystemSDK(queue, actor_resolver=resolve_authenticated_employee,
                     preview_loader=load_verified_preview,
                     confirmation_verifier=verify_employee_confirmation)


def confirm_execution(sdk: SystemSDK, *, authenticated_application_session: object,
                      preview_id: str, server_confirmation_receipt: object, stable_business_task_id: str):
    """仅在真实应用认证、CSRF 校验及本人确认事件成功后由业务后端调用。"""
    return sdk.create_task(authenticated_application_session, preview_id=preview_id,
                           confirmation=server_confirmation_receipt, task_id=stable_business_task_id)
