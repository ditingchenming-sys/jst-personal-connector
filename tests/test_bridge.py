import asyncio
import copy
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from jst_connector.bridge import Binding, TaskQueue, TaskSigner
from jst_connector.errors import ConnectorError
from jst_connector.system_sdk import EmployeeTaskClient, EmployeeTaskGuard, SystemSDK, validate_system_url


@pytest.fixture
def setup(tmp_path):
    clock = [1000.0]
    signer = TaskSigner(b"t" * 32, clock=lambda: clock[0])
    binding = Binding("公司甲", "员工甲", "codex")
    task = signer.issue(binding, "preview-1", "digest-1", {"操作": "测试"}, confirmation_id="receipt-1")
    return clock, signer, binding, task, tmp_path


def test_signature_tamper_and_binding(setup):
    _, signer, binding, envelope, _ = setup
    assert signer.verify(envelope, binding)["payload"] == {"操作": "测试"}
    invalid_signature = {**envelope, "signature": "伪造签名"}
    with pytest.raises(ConnectorError, match="签名无效"):
        signer.verify(invalid_signature, binding)
    for key, value in [("payload", {"操作": "支付"}), ("digest", "changed"), ("profile", "workbuddy"),
                       ("company_id", "公司乙"), ("user_id", "员工乙"), ("expires_at", 9999)]:
        changed = copy.deepcopy(envelope)
        changed["task"][key] = value
        with pytest.raises(ConnectorError):
            signer.verify(changed, binding)
    for wrong in [Binding("公司乙", binding.user_id, binding.profile),
                  Binding(binding.company_id, "员工乙", binding.profile),
                  Binding(binding.company_id, binding.user_id, "workbuddy")]:
        with pytest.raises(ConnectorError, match="不匹配"):
            signer.verify(envelope, wrong)


def test_expiry_and_same_id_changed_payload(setup):
    clock, signer, binding, task, path = setup
    queue = TaskQueue(path / "queue.db", signer)
    assert not queue.enqueue(task)["duplicate"]
    assert queue.enqueue(task)["duplicate"]
    changed = signer.issue(binding, "preview-1", "digest-1", {"操作": "变更"},
                           confirmation_id="receipt-1", task_id=task["task"]["task_id"])
    with pytest.raises(ConnectorError, match="不能更换"):
        queue.enqueue(changed)
    clock[0] = 1300
    with pytest.raises(ConnectorError, match="过期"):
        signer.verify(task, binding)
    assert queue.claim(binding) is None
    assert queue.get(binding, task["task"]["task_id"])["status"] == "expired"


def test_concurrent_claim_restart_and_idempotent_report(setup):
    _, signer, binding, task, path = setup
    queue = TaskQueue(path / "queue.db", signer)
    queue.enqueue(task)
    with ThreadPoolExecutor(max_workers=8) as workers:
        claims = list(workers.map(lambda _: queue.claim(binding), range(16)))
    claims = [claim for claim in claims if claim]
    assert len(claims) == 1
    claim = claims[0]
    restarted = TaskQueue(path / "queue.db", signer)
    task_id = task["task"]["task_id"]
    assert restarted.claim(binding) is None
    assert restarted.get(binding, task_id)["requires_reconciliation"]
    wrong = Binding(binding.company_id, "员工乙", binding.profile)
    assert restarted.claim(wrong) is None
    with pytest.raises(ConnectorError, match="没有此任务"):
        restarted.get(wrong, task_id)
    with pytest.raises(ConnectorError, match="凭据无效"):
        restarted.report(binding, task_id, "wrong", "unknown", {})
    assert not restarted.report(binding, task_id, claim["claim_token"], "unknown", {"需回查": True})["duplicate"]
    assert restarted.report(binding, task_id, claim["claim_token"], "unknown", {"需回查": True})["duplicate"]
    with pytest.raises(ConnectorError, match="不能覆盖"):
        restarted.report(binding, task_id, claim["claim_token"], "succeeded", {})
    assert TaskQueue(path / "queue.db", signer).claim(binding) is None


def test_sdk_requires_trusted_session_confirmation_and_preview(setup):
    _, signer, binding, _, path = setup
    authenticated_session = object()
    receipt = object()
    preview = {"id": "p", "digest": "verified-digest", "payload": {"操作": "测试"}}

    def resolve(session):
        if session is not authenticated_session:
            raise ConnectorError("unauthenticated", "请登录业务系统")
        return binding

    sdk = SystemSDK(TaskQueue(path / "system.db", signer), actor_resolver=resolve,
                    preview_loader=lambda session, preview_id: preview,
                    confirmation_verifier=lambda session, proof, frozen: proof is receipt and frozen == preview)
    with pytest.raises(ConnectorError, match="登录"):
        sdk.create_task({"company_id": "公司甲", "user_id": "员工甲"}, preview_id="p", confirmation=receipt)
    with pytest.raises(ConnectorError, match="本人"):
        sdk.create_task(authenticated_session, preview_id="p", confirmation={"confirmed": True})
    task = sdk.create_task(authenticated_session, preview_id="p", confirmation=receipt)
    assert signer.verify(task, binding)["payload"] == preview["payload"]
    assert sdk.claim(authenticated_session)["task"] == task


def test_employee_guard_preserves_replay_record_across_restart(setup):
    _, signer, binding, task, path = setup
    guard = EmployeeTaskGuard(TaskQueue(path / "employee.db", signer))
    with pytest.raises(ConnectorError, match="预览不一致"):
        guard.accept(task, binding, preview_id="preview-1", digest="changed", payload={"操作": "测试"})
    claim = guard.accept(task, binding, preview_id="preview-1", digest="digest-1", payload={"操作": "测试"})
    assert claim["task"] == task
    guard = EmployeeTaskGuard(TaskQueue(path / "employee.db", signer))
    assert guard.accept(task, binding, preview_id="preview-1", digest="digest-1", payload={"操作": "测试"}) is None


def make_sdk(queue, binding, preview):
    return SystemSDK(queue, actor_resolver=lambda session: binding,
                     preview_loader=lambda session, preview_id: preview,
                     confirmation_verifier=lambda session, receipt, frozen: receipt in {"verified-1", "verified-2"})


def test_sdk_duplicate_confirmation_and_new_receipt_keep_first_task(setup):
    clock, signer, binding, _, path = setup
    preview = {"id": "p", "digest": "digest", "payload": {"操作": "测试"}}
    sdk = make_sdk(TaskQueue(path / "system.db", signer), binding, preview)
    first = sdk.create_task(None, preview_id="p", confirmation="verified-1")
    clock[0] += 2
    assert sdk.create_task(None, preview_id="p", confirmation="verified-1") == first
    assert sdk.create_task(None, preview_id="p", confirmation="verified-2", task_id="different-delivery") == first
    # Reusing an explicit business ID is idempotent despite a later issuance timestamp.
    assert sdk.create_task(None, preview_id="p", confirmation="verified-2",
                           task_id=first["task"]["task_id"]) == first
    restarted = make_sdk(TaskQueue(path / "system.db", signer), binding, preview)
    assert restarted.create_task(None, preview_id="p", confirmation="verified-1") == first
    assert restarted.claim(None)["task"] == first
    assert restarted.claim(None) is None


def test_sdk_concurrent_confirmation_creates_only_one_claim(setup):
    _, signer, binding, _, path = setup
    preview = {"id": "p", "digest": "digest", "payload": {"操作": "测试"}}
    sdk = make_sdk(TaskQueue(path / "system.db", signer), binding, preview)
    with ThreadPoolExecutor(max_workers=8) as workers:
        tasks = list(workers.map(lambda i: sdk.create_task(None, preview_id="p",
                                                         confirmation="verified-1", task_id=f"delivery-{i}"),
                                 range(16)))
    assert all(task == tasks[0] for task in tasks)
    with ThreadPoolExecutor(max_workers=8) as workers:
        claims = list(workers.map(lambda _: sdk.claim(None), range(16)))
    assert len([claim for claim in claims if claim]) == 1


def test_same_preview_content_change_is_rejected_even_with_fresh_confirmation(setup):
    _, signer, binding, _, path = setup
    preview = {"id": "p", "digest": "digest", "payload": {"操作": "测试"}}
    sdk = make_sdk(TaskQueue(path / "system.db", signer), binding, preview)
    sdk.create_task(None, preview_id="p", confirmation="verified-1")
    preview["payload"] = {"操作": "不同内容"}
    with pytest.raises(ConnectorError):
        sdk.create_task(None, preview_id="p", confirmation="verified-2")
    preview["digest"] = "new-digest"
    with pytest.raises(ConnectorError, match="同一预览不能更换"):
        sdk.create_task(None, preview_id="p", confirmation="verified-2")


def test_employee_guard_deduplicates_reissued_ids_and_unknown_after_restart(setup):
    _, signer, binding, first, path = setup
    queue = TaskQueue(path / "employee.db", signer)
    guard = EmployeeTaskGuard(queue)
    claim = guard.accept(first, binding, preview_id="preview-1", digest="digest-1", payload={"操作": "测试"})
    queue.report(binding, first["task"]["task_id"], claim["claim_token"], "unknown", {"需回查": True})
    restarted = EmployeeTaskGuard(TaskQueue(path / "employee.db", signer))
    fresh = signer.issue(binding, "preview-1", "digest-1", {"操作": "测试"},
                          task_id="reissued-id", confirmation_id="different-receipt")
    assert restarted.accept(fresh, binding, preview_id="preview-1", digest="digest-1",
                             payload={"操作": "测试"}) is None
    assert restarted.queue.claim(binding) is None
    assert restarted.queue.get(binding, first["task"]["task_id"])["status"] == "unknown"


def test_employee_guard_concurrent_different_delivery_ids_claims_once(setup):
    _, signer, binding, _, path = setup
    guard = EmployeeTaskGuard(TaskQueue(path / "employee.db", signer))

    def accept(i):
        envelope = signer.issue(binding, "same-preview", "same-digest", {"operation": "test"},
                                 task_id=f"delivery-{i}", confirmation_id=f"receipt-{i}")
        return guard.accept(envelope, binding, preview_id="same-preview", digest="same-digest",
                            payload={"operation": "test"})

    with ThreadPoolExecutor(max_workers=8) as workers:
        claims = list(workers.map(accept, range(16)))
    assert len([claim for claim in claims if claim]) == 1


def test_sdk_unknown_task_reconfirmation_does_not_requeue_or_extend_expiry(setup):
    clock, signer, binding, _, path = setup
    preview = {"id": "p", "digest": "digest", "payload": {"操作": "测试"}}
    sdk = make_sdk(TaskQueue(path / "system.db", signer), binding, preview)
    original = sdk.create_task(None, preview_id="p", confirmation="verified-1", ttl=10)
    claimed = sdk.claim(None)
    sdk.report(None, task_id=original["task"]["task_id"], claim_token=claimed["claim_token"],
               status="unknown", result={"需回查": True})
    clock[0] += 20
    restarted = make_sdk(TaskQueue(path / "system.db", signer), binding, preview)
    assert restarted.create_task(None, preview_id="p", confirmation="verified-2", ttl=300) == original
    assert restarted.claim(None) is None
    assert restarted.get(None, original["task"]["task_id"])["requires_reconciliation"]


def test_legacy_queue_builds_business_index_and_rejects_existing_duplicates(setup):
    _, signer, binding, first, path = setup
    database_path = path / "legacy.db"
    queue = TaskQueue(database_path, signer)
    queue.enqueue(first)
    # Prior format has the same task ledger without the new business-key registry.
    with sqlite3.connect(database_path) as database:
        database.execute("DROP TABLE bridge_preview_keys")
    upgraded = TaskQueue(database_path, signer)
    assert upgraded.envelope(binding, first["task"]["task_id"]) == first
    second = signer.issue(binding, "preview-1", "digest-1", {"操作": "测试"},
                           task_id="legacy-duplicate", confirmation_id="second-receipt")
    with sqlite3.connect(database_path) as database:
        database.execute("DROP TABLE bridge_preview_keys")
        database.execute("INSERT INTO bridge_tasks SELECT ?,company_id,user_id,profile,?,'queued',NULL,NULL,created_at "
                         "FROM bridge_tasks WHERE task_id=?",
                         ("legacy-duplicate", json.dumps(second), first["task"]["task_id"]))
    with pytest.raises(ConnectorError, match="重复预览"):
        TaskQueue(database_path, signer)


@pytest.mark.parametrize("url", ["http://example.com", "http://localhost.evil", "https://u:p@example.com",
                               "https://example.com?token=secret", "file:///tmp/test"])
def test_system_url_policy(url):
    with pytest.raises(ConnectorError):
        validate_system_url(url, allow_loopback_test=True)


def test_controlled_loopback_only():
    assert validate_system_url("http://127.0.0.1:9999", allow_loopback_test=True).startswith("http:")
    with pytest.raises(ConnectorError):
        validate_system_url("http://127.0.0.1:9999")


def test_network_client_never_follows_redirect_with_token():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={"location": "https://other.example/capture"})

    client = EmployeeTaskClient("https://system.example", "test-pairing-token",
                                transport=httpx.MockTransport(handler))
    with pytest.raises(ConnectorError, match="重定向"):
        asyncio.run(client.claim())
    assert len(requests) == 1
    assert requests[0].url.host == "system.example"
