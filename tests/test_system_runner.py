"""系统确认到员工回查回传的离线集成；ERP 夹具仅存在于测试中。"""

import asyncio
import copy

import pytest
from cryptography.fernet import Fernet

from jst_connector.bridge import Binding, TaskQueue, TaskSigner
from jst_connector.service import ConnectorService
from jst_connector.system_runner import SystemRunner
from jst_connector.system_sdk import EmployeeTaskGuard, SystemSDK
from jst_connector.vault import Vault


class ControlledERP:
    def __init__(self, *, atomicity="verified", timeout=False):
        self.atomicity = atomicity
        self.timeout = timeout
        self.executions = 0
        self.readbacks = 0
        self.started = asyncio.Event()
        self.release = None

    async def preview(self, profile, capability_id, parameters):
        return {"source_verified": True, "payload": {"validated_document": "offline-1"},
                "checks": {"current_erp_state": "valid"}, "atomicity": self.atomicity}

    async def revalidate(self, profile, payload):
        return True

    async def execute(self, profile, payload):
        self.executions += 1
        self.started.set()
        if self.release is not None:
            await self.release.wait()
        await asyncio.sleep(0)  # Exercise duplicate arrival while an ERP request is in flight.
        if self.timeout:
            raise TimeoutError("controlled ERP response lost")
        self.readbacks += 1
        return {"verified": True, "document_id": "offline-result-1", "readback": "effective"}


class SDKRemote:
    def __init__(self, sdk, authenticated_session):
        self.sdk = sdk
        self.session = authenticated_session
        self.fail_reports = False
        self.reports = 0
        self.claims = 0

    async def claim(self):
        self.claims += 1
        return self.sdk.claim(self.session)

    async def report(self, **arguments):
        self.reports += 1
        if self.fail_reports:
            raise TimeoutError("controlled reporting outage")
        return self.sdk.report(self.session, **arguments)


async def prepare(tmp_path, *, atomicity="verified", timeout=False):
    vault = Vault(tmp_path / "private", key=Fernet.generate_key())
    identity = {"company_id": "isolated-company", "user_id": "isolated-employee"}
    binding = Binding(**identity, profile="system-paired-client")
    vault.save_session(binding.profile, {"cookies": []}, identity)
    erp = ControlledERP(atomicity=atomicity, timeout=timeout)
    service = ConnectorService(tmp_path / "employee", vault=vault, browser=object(), erp=erp)
    preview = (await service.preview(binding.profile, "TEST_ONLY_WRITE", {"document": "offline-1"}))["preview"]
    signer = TaskSigner(b"isolated-pairing-secret-only-test" * 2)
    system_queue = TaskQueue(tmp_path / "system.sqlite", signer)
    local_queue = TaskQueue(tmp_path / "local.sqlite", signer)
    session, receipt = object(), object()

    def resolve(authenticated_session):
        assert authenticated_session is session
        return binding

    sdk = SystemSDK(system_queue, actor_resolver=resolve,
                    preview_loader=lambda current, pid: {"id": preview["preview_id"], "digest": preview["digest"],
                                                         "payload": preview["payload"]},
                    confirmation_verifier=lambda current, proof, frozen: current is session and proof is receipt)
    envelope = sdk.create_task(session, preview_id=preview["preview_id"], confirmation=receipt)
    remote = SDKRemote(sdk, session)
    runner = SystemRunner(service, EmployeeTaskGuard(local_queue), binding, remote)
    return runner, sdk, remote, erp, preview, envelope, tmp_path


@pytest.mark.asyncio
async def test_confirm_execute_readback_report_and_duplicate_once(tmp_path):
    runner, sdk, remote, erp, preview, envelope, _ = await prepare(tmp_path)
    delivery = await remote.claim()
    response = await runner.handle_delivery(delivery)
    assert response["status"] == "succeeded"
    assert response["delivery_status"] == "reported"
    assert erp.executions == erp.readbacks == 1
    record = runner.service.ledger.get_preview(runner.binding.profile, preview["preview_id"])
    assert record["approval"]["actor"]["source"] == "trusted_system"
    assert record["approval"]["actor"]["confirmation_id"] == envelope["task"]["confirmation_id"]
    system_result = sdk.get(remote.session, envelope["task"]["task_id"])
    assert system_result["status"] == "succeeded"
    assert system_result["result"]["evidence"]["readback"] == "effective"
    duplicate = await runner.handle_delivery(delivery)
    assert duplicate["duplicate"]
    assert duplicate["delivery_status"] == "reported"
    assert erp.executions == 1


@pytest.mark.asyncio
async def test_wrong_current_employee_or_company_rejected(tmp_path):
    runner, _, remote, erp, _, _, _ = await prepare(tmp_path)
    delivery = await remote.claim()
    runner.service.vault.clear_session(runner.binding.profile)
    runner.service.vault.save_session(runner.binding.profile, {},
                                     {"company_id": "other-company", "user_id": "other-employee"})
    response = await runner.handle_delivery(delivery)
    assert response["status"] == "rejected"
    assert response["error"]["code"] == "identity_mismatch"
    assert erp.executions == remote.reports == 0


@pytest.mark.asyncio
async def test_signature_tamper_and_signed_preview_mismatch_rejected(tmp_path):
    runner, _, remote, erp, preview, envelope, _ = await prepare(tmp_path)
    delivery = await remote.claim()
    tampered = copy.deepcopy(delivery)
    tampered["task"]["task"]["payload"] = {"changed": True}
    response = await runner.handle_delivery(tampered)
    assert response["error"]["code"] == "invalid_signature"
    changed = runner.guard.queue.signer.issue(runner.binding, preview["preview_id"], preview["digest"],
                                              {"changed": True}, confirmation_id="verified-other-receipt")
    response = await runner.handle_delivery({"task": changed, "claim_token": delivery["claim_token"]})
    assert response["error"]["code"] == "preview_mismatch"
    assert erp.executions == 0
    assert runner.service.ledger.get_preview(runner.binding.profile, envelope["task"]["preview_id"])["status"] == "ready"


@pytest.mark.asyncio
async def test_erp_timeout_unknown_is_persisted_reported_and_not_reexecuted(tmp_path):
    runner, sdk, remote, erp, _, envelope, _ = await prepare(tmp_path, timeout=True)
    delivery = await remote.claim()
    response = await runner.handle_delivery(delivery)
    assert response["status"] == "unknown"
    assert response["delivery_status"] == "reported"
    assert runner.guard.queue.get(runner.binding, envelope["task"]["task_id"])["status"] == "unknown"
    assert sdk.get(remote.session, envelope["task"]["task_id"])["status"] == "unknown"
    duplicate = await runner.handle_delivery(delivery)
    assert duplicate["duplicate"]
    assert duplicate["delivery_status"] == "reported"
    assert erp.executions == 1


@pytest.mark.asyncio
async def test_report_failure_then_restart_and_redelivery_only_reports(tmp_path):
    runner, sdk, remote, erp, _, envelope, _ = await prepare(tmp_path)
    delivery = await remote.claim()
    remote.fail_reports = True
    response = await runner.handle_delivery(delivery)
    assert response["status"] == "succeeded"
    assert response["delivery_status"] == "result_delivery_pending"
    assert sdk.get(remote.session, envelope["task"]["task_id"])["status"] == "claimed"
    remote.fail_reports = False
    restarted_guard = EmployeeTaskGuard(TaskQueue(runner.guard.queue.path, runner.guard.queue.signer))
    restarted = SystemRunner(runner.service, restarted_guard, runner.binding, remote)
    response = await restarted.handle_delivery(delivery)
    assert response["duplicate"]
    assert response["delivery_status"] == "reported"
    assert sdk.get(remote.session, envelope["task"]["task_id"])["status"] == "succeeded"
    assert erp.executions == erp.readbacks == 1


@pytest.mark.asyncio
async def test_unverified_atomicity_is_blocked_without_erp_submission(tmp_path):
    runner, sdk, remote, erp, preview, envelope, _ = await prepare(tmp_path, atomicity="unverified")
    response = await runner.poll_once()
    assert response["status"] == "failed"
    assert response["result"]["error"]["code"] == "atomicity_unverified"
    assert response["delivery_status"] == "reported"
    assert erp.executions == 0
    assert runner.service.ledger.get_preview(runner.binding.profile, preview["preview_id"])["status"] == "ready"
    assert sdk.get(remote.session, envelope["task"]["task_id"])["status"] == "failed"
    assert (await runner.poll_once())["status"] == "idle"


@pytest.mark.asyncio
async def test_claimed_before_crash_does_not_execute_again(tmp_path):
    runner, _, remote, erp, preview, _, _ = await prepare(tmp_path)
    delivery = await remote.claim()
    assert runner.guard.accept(delivery["task"], runner.binding, preview_id=preview["preview_id"],
                               digest=preview["digest"], payload=preview["payload"])
    restarted = SystemRunner(runner.service, EmployeeTaskGuard(TaskQueue(
        runner.guard.queue.path, runner.guard.queue.signer)), runner.binding, remote)
    response = await restarted.handle_delivery(delivery)
    assert response["status"] == "unknown"
    assert response["duplicate"]
    assert erp.executions == 0


@pytest.mark.asyncio
async def test_concurrent_redelivery_never_reexecutes(tmp_path):
    runner, _, remote, erp, _, _, _ = await prepare(tmp_path)
    delivery = await remote.claim()
    responses = await asyncio.gather(*(runner.handle_delivery(delivery) for _ in range(8)))
    assert sum(response["status"] == "succeeded" for response in responses) == 1
    assert all(response["status"] in {"succeeded", "in_progress"} for response in responses)
    assert erp.executions == 1


@pytest.mark.asyncio
async def test_active_duplicate_never_reports_unknown_before_original_finishes(tmp_path):
    runner, sdk, remote, erp, preview, envelope, _ = await prepare(tmp_path)
    delivery = await remote.claim()
    erp.release = asyncio.Event()
    original = asyncio.create_task(runner.handle_delivery(delivery))
    await asyncio.wait_for(erp.started.wait(), timeout=2)
    try:
        duplicate = await runner.handle_delivery(delivery)
        assert duplicate["status"] == "in_progress"
        assert duplicate["duplicate"]
        assert remote.reports == 0
        assert sdk.get(remote.session, envelope["task"]["task_id"])["status"] == "claimed"
        other_runner = SystemRunner(runner.service, EmployeeTaskGuard(TaskQueue(
            runner.guard.queue.path, runner.guard.queue.signer)), runner.binding, remote)
        cross_instance = await other_runner.handle_delivery(delivery)
        assert cross_instance["status"] == "in_progress"
        assert remote.reports == 0
    finally:
        erp.release.set()
    result = await asyncio.wait_for(original, timeout=2)
    assert result["status"] == "succeeded"
    assert result["delivery_status"] == "reported"
    assert sdk.get(remote.session, envelope["task"]["task_id"])["status"] == "succeeded"
    assert erp.executions == erp.readbacks == remote.reports == 1
    # A signed, trusted retry with another delivery ID cannot escape the Ledger preview guard.
    reissued = runner.guard.queue.signer.issue(runner.binding, preview["preview_id"], preview["digest"],
                                               preview["payload"], task_id="another-delivery",
                                               confirmation_id="another-trusted-confirmation")
    response = await runner.handle_delivery({"task": reissued, "claim_token": "controlled-server-claim"})
    assert response["duplicate"]
    assert response["status"] == "succeeded"
    assert erp.executions == 1


@pytest.mark.asyncio
async def test_unconfirmed_report_ack_is_pending_and_cannot_reexecute(tmp_path):
    runner, _, remote, erp, _, _, _ = await prepare(tmp_path)
    delivery = await remote.claim()

    class MissingAcknowledgement:
        async def report(self, **arguments):
            return {"accepted": True}

    runner.remote_client = MissingAcknowledgement()
    response = await runner.handle_delivery(delivery)
    assert response["delivery_status"] == "result_delivery_pending"
    response = await runner.handle_delivery(delivery)
    assert response["duplicate"]
    assert erp.executions == 1


@pytest.mark.asyncio
async def test_encrypted_outbox_recovers_only_via_new_runner_poll_after_expiry(tmp_path):
    runner, sdk, remote, erp, preview, envelope, _ = await prepare(tmp_path)
    delivery = await remote.claim()
    server_receipt = delivery["claim_token"]
    remote.fail_reports = True
    response = await runner.handle_delivery(delivery)
    assert response["delivery_status"] == "result_delivery_pending"
    files = list(runner._outbox.glob("*.enc"))
    assert len(files) == 2
    assert all(server_receipt.encode() not in path.read_bytes() for path in files)
    assert server_receipt not in str(response)
    saved_delivery = runner.service.vault.unseal(runner._delivery_path(preview["preview_id"]).read_text("ascii"))
    assert saved_delivery == delivery
    # Discard all delivery objects. A new runner must recover from disk without another claim.
    del delivery, saved_delivery
    remote.fail_reports = False
    runner.guard.queue.signer.clock = lambda: envelope["task"]["expires_at"] + 100
    restarted = SystemRunner(runner.service, EmployeeTaskGuard(TaskQueue(
        runner.guard.queue.path, runner.guard.queue.signer)), runner.binding, remote)
    recovered = await restarted.poll_once()
    assert recovered["status"] == "succeeded"
    assert recovered["delivery_status"] == "reported"
    assert remote.claims == 1
    assert erp.executions == erp.readbacks == 1
    assert sdk.get(remote.session, envelope["task"]["task_id"])["status"] == "succeeded"
    assert not list(restarted._outbox.glob("*.enc"))


@pytest.mark.asyncio
async def test_outbox_cannot_flush_after_company_switch_and_resumes_for_original_employee(tmp_path):
    runner, _, remote, erp, _, _, _ = await prepare(tmp_path)
    remote.fail_reports = True
    await runner.poll_once()
    remote.fail_reports = False
    original = {"company_id": runner.binding.company_id, "user_id": runner.binding.user_id}
    runner.service.vault.clear_session(runner.binding.profile)
    runner.service.vault.save_session(runner.binding.profile, {},
                                     {"company_id": "other-company", "user_id": "other-employee"})
    restarted = SystemRunner(runner.service, runner.guard, runner.binding, remote)
    blocked = await restarted.poll_once()
    assert blocked["error"]["code"] == "identity_mismatch"
    assert remote.reports == 1
    assert list(restarted._outbox.glob("*.delivery.enc"))
    runner.service.vault.clear_session(runner.binding.profile)
    runner.service.vault.save_session(runner.binding.profile, {}, original)
    recovered = await restarted.poll_once()
    assert recovered["delivery_status"] == "reported"
    assert erp.executions == 1


@pytest.mark.asyncio
async def test_pending_original_receipt_is_not_overwritten_by_reissued_delivery(tmp_path):
    runner, _, remote, erp, preview, envelope, _ = await prepare(tmp_path)
    delivery = await remote.claim()
    remote.fail_reports = True
    await runner.handle_delivery(delivery)
    reissued = runner.guard.queue.signer.issue(runner.binding, preview["preview_id"], preview["digest"],
                                               preview["payload"], task_id="new-task-id",
                                               confirmation_id="new-trusted-confirmation")
    response = await runner.handle_delivery({"task": reissued, "claim_token": "different-server-receipt"})
    assert response["task_id"] == envelope["task"]["task_id"]
    saved = runner.service.vault.unseal(runner._delivery_path(preview["preview_id"]).read_text("ascii"))
    assert saved == delivery
    remote.fail_reports = False
    recovered = await SystemRunner(runner.service, runner.guard, runner.binding, remote).poll_once()
    assert recovered["delivery_status"] == "reported"
    assert erp.executions == 1


@pytest.mark.asyncio
async def test_cancelled_execution_retains_receipt_for_new_runner_unknown_report(tmp_path):
    runner, sdk, remote, erp, _, envelope, _ = await prepare(tmp_path)
    erp.release = asyncio.Event()
    execution = asyncio.create_task(runner.poll_once())
    await asyncio.wait_for(erp.started.wait(), timeout=2)
    execution.cancel()
    with pytest.raises(asyncio.CancelledError):
        await execution
    assert remote.reports == 0
    restarted = SystemRunner(runner.service, EmployeeTaskGuard(TaskQueue(
        runner.guard.queue.path, runner.guard.queue.signer)), runner.binding, remote)
    result = await restarted.poll_once()
    assert result["status"] == "unknown"
    assert result["delivery_status"] == "reported"
    assert sdk.get(remote.session, envelope["task"]["task_id"])["status"] == "unknown"
    assert erp.executions == 1
    assert remote.claims == 1


@pytest.mark.asyncio
async def test_server_recorded_result_but_lost_ack_retries_original_report_only(tmp_path):
    runner, sdk, remote, erp, _, envelope, _ = await prepare(tmp_path)

    class LostAcknowledgement:
        async def report(self, **arguments):
            await remote.report(**arguments)
            raise TimeoutError("controlled lost acknowledgement")

    delivery = await remote.claim()
    runner.remote_client = LostAcknowledgement()
    response = await runner.handle_delivery(delivery)
    assert response["delivery_status"] == "result_delivery_pending"
    assert sdk.get(remote.session, envelope["task"]["task_id"])["status"] == "succeeded"
    recovered = await SystemRunner(runner.service, runner.guard, runner.binding, remote).poll_once()
    assert recovered["delivery_status"] == "reported"
    assert remote.reports == 2
    assert erp.executions == 1
