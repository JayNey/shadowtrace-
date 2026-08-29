"""Sangfor DispositionAdapter gates (alignment plan Layer 5–6d)."""

from __future__ import annotations

import inspect
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from httpx import ASGITransport

from app.adapters.sangfor.client import SangforXdrClient
from app.adapters.sangfor.disposition import (
    BLOCK_ENDPOINT_PATH,
    BLOCK_LIST_PATH,
    BLOCK_NETWORK_PATH,
    DEALSTATUS_LIST_PATH,
    DEALSTATUS_WRITE_PATH,
    DISPOSE_FILE_PATH,
    SCAN_ACTION,
    SCAN_SOURCE,
    TICKET_ACTION,
    TICKET_CREATE_PATH,
    TICKET_LIST_PATH,
    TICKET_TEMPLATE_DEFAULT,
    UNBLOCK_PATH,
    UNISOLATE_PATH,
    VIRUS_SCAN_CREATE_PATH,
    SangforBlockConfig,
    SangforDispositionAdapter,
    block_status_would_verify,
    compensation_is_partial,
    dealstatus_readback_would_confirm,
    map_outbound_deal_status,
    rename_blockdevice_item,
    scan_task_would_verify,
)
from app.adapters.sangfor.wire_mock import (
    SangforWireConfig,
    create_sangfor_wire_app,
    dealstatus_writeback_would_confirm,
)
from app.api.v1 import deps
from app.core.config import Settings
from app.core.errors import WritebackUnsupportedError
from app.models.disposition import (
    DispositionCommand,
    RecordCompensationParams,
    SetEventDispositionParams,
    SourceObjectLocator,
    SubmitEntityActionParams,
)
from app.models.enums import (
    CapabilityState,
    ConfirmationEvidence,
    ConnectorStatus,
    DispositionIntentKind,
    ExecutionOwner,
    SourceDisposition,
    SourceObjectKind,
    WritebackStatus,
)
from app.services.disposition_sync_service import DispositionSyncService
from tests.test_adapters.conftest import event_disposition_command

_REPO_ROOT = Path(__file__).resolve().parents[3]
_VECTORS = json.loads(
    (_REPO_ROOT / "contracts" / "vendor" / "sangfor_xdr" / "signing_vectors.json").read_text(
        encoding="utf-8"
    )
)

_INCIDENTS_LIST = "/api/xdr/v1/incidents/list"
_ISOLATE_CREATE_INVENTED = "/api/xdr/v1/responses/host/isolate"
_AF_DEVICE = {"devId": 12346, "devName": "AF_011", "devType": "AF"}
_EDR_DEVICE = {"devId": "edr-1", "devName": "EDR_011", "devType": "EDR"}
_TICKET_ASSIGNEE = "fx-user-4d54fbcb5b41406da20e2a"
_TICKET_WORKFLOW_ID = "adf0014e-cd48-11ed-a8b1-563793be7763"


class RecordingTransport(httpx.AsyncBaseTransport):
    def __init__(self, app: Any) -> None:
        self._inner = ASGITransport(app=app)
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return await self._inner.handle_async_request(request)


def _paths(transport: RecordingTransport) -> list[str]:
    return [httpx.URL(item.url).path for item in transport.requests]


def _json_body(request: httpx.Request) -> dict[str, Any]:
    if not request.content:
        return {}
    payload = json.loads(request.content.decode("utf-8"))
    return payload if isinstance(payload, dict) else {}


def _request_for(transport: RecordingTransport, path: str) -> httpx.Request:
    return next(item for item in transport.requests if httpx.URL(item.url).path == path)


def _client(http: httpx.AsyncClient) -> SangforXdrClient:
    return SangforXdrClient(
        str(http.base_url),
        access_key=_VECTORS["ak"],
        secret_key=_VECTORS["sk"],
        client=http,
    )


@asynccontextmanager
async def _adapter(
    config: SangforWireConfig | None = None,
    *,
    block_config: SangforBlockConfig | None = None,
) -> AsyncIterator[tuple[SangforDispositionAdapter, RecordingTransport]]:
    transport = RecordingTransport(create_sangfor_wire_app(config=config))
    http = httpx.AsyncClient(transport=transport, base_url="http://sangfor-wire")
    adapter = SangforDispositionAdapter(_client(http), block_config=block_config)
    try:
        yield adapter, transport
    finally:
        await http.aclose()


def _entity_command(
    *,
    entity_action_code: str = "isolate_host",
    canonical_target: str = "host:PC-FIN-023",
    disposition_id: str = "disp-entity-1",
) -> DispositionCommand:
    return DispositionCommand(
        disposition_id=disposition_id,
        action_id="act-entity-1",
        closure_cycle=1,
        intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT,
        source_locator=SourceObjectLocator(
            source_product="sangfor_xdr",
            source_tenant_id="tenant-demo",
            connector_id="conn-disposition",
            source_kind=SourceObjectKind.INCIDENT,
            source_object_id="incident-wire-001",
        ),
        operation_code="submit_entity_action",
        operation_params=SubmitEntityActionParams(
            entity_action_code=entity_action_code,
            canonical_target=canonical_target,
        ),
        operator_id="analyst-1",
        idempotency_key="idem-entity-1",
        execution_owner=ExecutionOwner.XDR_MANAGED,
    )


def test_contained_outbound_is_tmg_70_and_inbound_b_6_agrees_with_layer3() -> None:
    assert map_outbound_deal_status(SourceDisposition.CONTAINED) == 70
    assert map_outbound_deal_status(SourceDisposition.UNKNOWN) is None
    assert (
        dealstatus_readback_would_confirm(
            write_code="Success",
            succeeded_num=1,
            total=1,
            list_deal_status=6,
            target=SourceDisposition.CONTAINED,
        )
        is True
    )
    assert (
        dealstatus_writeback_would_confirm(
            write_code="Success",
            succeeded_num=1,
            total=1,
            list_deal_status=6,
        )
        is True
    )
    for bad_status in (2, 70, 30):
        assert (
            dealstatus_readback_would_confirm(
                write_code="Success",
                succeeded_num=1,
                total=1,
                list_deal_status=bad_status,
                target=SourceDisposition.CONTAINED,
            )
            is False
        )
        assert (
            dealstatus_writeback_would_confirm(
                write_code="Success",
                succeeded_num=1,
                total=1,
                list_deal_status=bad_status,
            )
            is False
        )
    assert (
        dealstatus_readback_would_confirm(
            write_code="Success",
            succeeded_num=1,
            total=2,
            list_deal_status=6,
            target=SourceDisposition.CONTAINED,
        )
        is False
    )
    assert (
        dealstatus_writeback_would_confirm(
            write_code="Success",
            succeeded_num=1,
            total=1,
            list_deal_status=6,
            used_incidents_list=True,
        )
        is False
    )


def test_capabilities_event_and_block_entity_readback_no_cas_token() -> None:
    adapter = SangforDispositionAdapter(
        SangforXdrClient(
            "http://sangfor-wire",
            access_key=_VECTORS["ak"],
            secret_key=_VECTORS["sk"],
        )
    )
    caps = adapter.capabilities()
    assert caps.intents[DispositionIntentKind.EVENT_STATUS_UPDATE] is CapabilityState.SUPPORTED
    assert caps.operations["set_event_disposition"] is CapabilityState.SUPPORTED
    assert caps.intents[DispositionIntentKind.ENTITY_ACTION_SUBMIT] is CapabilityState.SUPPORTED
    assert caps.operations["submit_entity_action"] is CapabilityState.SUPPORTED
    assert caps.intents[DispositionIntentKind.COMPENSATION_RECORD] is CapabilityState.SUPPORTED
    assert caps.operations["record_compensation"] is CapabilityState.SUPPORTED
    assert caps.supports_concurrency_token is False
    assert caps.supports_entity_effect_readback is True
    assert caps.supports_readback_confirmation is True
    assert caps.supports_idempotency is False
    assert adapter.allows_safe_retry() is False
    assert adapter.name == "sangfor_xdr"


@pytest.mark.asyncio
async def test_health_check_is_unknown_without_extra_uri() -> None:
    async with _adapter() as (adapter, _transport):
        assert await adapter.health_check() is ConnectorStatus.UNKNOWN


@pytest.mark.asyncio
async def test_write_70_list_6_confirms_contained() -> None:
    command = event_disposition_command(object_id="incident-wire-001")
    async with _adapter() as (adapter, transport):
        submitted = await adapter.submit(command)
        confirmed = await adapter.confirm_readback(command)

    assert submitted.status is WritebackStatus.ACCEPTED
    assert submitted.simulated is False
    assert submitted.confirmation_evidence is None
    assert confirmed is not None
    assert confirmed.status is WritebackStatus.CONFIRMED
    assert confirmed.confirmation_evidence is ConfirmationEvidence.READBACK_VERIFIED
    assert confirmed.simulated is False

    paths = _paths(transport)
    assert DEALSTATUS_WRITE_PATH in paths
    assert DEALSTATUS_LIST_PATH in paths
    assert _INCIDENTS_LIST not in paths
    assert _ISOLATE_CREATE_INVENTED not in paths

    write_body = _json_body(_request_for(transport, DEALSTATUS_WRITE_PATH))
    assert write_body["uuIds"] == ["incident-wire-001"]
    assert write_body["dealStatus"] == 70
    assert isinstance(write_body["dealStatus"], int)
    assert "dealComment" not in write_body
    assert find_analysis_keys(write_body) == []

    list_body = _json_body(_request_for(transport, DEALSTATUS_LIST_PATH))
    assert list_body == {"ids": ["incident-wire-001"]}
    assert "uuIds" not in list_body


def find_analysis_keys(body: dict[str, Any]) -> list[str]:
    from app.mock_xdr.state import find_forbidden_analysis_keys

    return find_forbidden_analysis_keys(body)


@pytest.mark.asyncio
async def test_whitelist_comment_is_the_only_deal_comment_sent() -> None:
    command = event_disposition_command(object_id="incident-wire-001")
    command = command.model_copy(
        update={
            "operation_params": SetEventDispositionParams(
                target_disposition=SourceDisposition.CONTAINED,
                comment_code="shadowtrace:closed",
            )
        }
    )
    async with _adapter() as (adapter, transport):
        await adapter.submit(command)
    body = _json_body(_request_for(transport, DEALSTATUS_WRITE_PATH))
    assert body["dealComment"] == "shadowtrace:closed"
    assert body["dealStatus"] == 70


@pytest.mark.asyncio
async def test_non_whitelist_comment_is_omitted() -> None:
    command = event_disposition_command(object_id="incident-wire-001")
    command = command.model_copy(
        update={
            "operation_params": SetEventDispositionParams(
                target_disposition=SourceDisposition.CONTAINED,
                comment_code="full analyst report and decision_trace",
            )
        }
    )
    async with _adapter() as (adapter, transport):
        await adapter.submit(command)
    body = _json_body(_request_for(transport, DEALSTATUS_WRITE_PATH))
    assert "dealComment" not in body


@pytest.mark.asyncio
async def test_list_still_processing_2_must_not_confirm() -> None:
    command = event_disposition_command(object_id="incident-wire-001")
    async with _adapter(SangforWireConfig(dealstatus_list_status=2)) as (adapter, transport):
        submitted = await adapter.submit(command)
        confirmed = await adapter.confirm_readback(command)
    assert submitted.status is WritebackStatus.ACCEPTED
    assert confirmed is None
    assert _INCIDENTS_LIST not in _paths(transport)


@pytest.mark.asyncio
async def test_list_tmg_70_must_not_confirm() -> None:
    command = event_disposition_command(object_id="incident-wire-001")
    async with _adapter(SangforWireConfig(dealstatus_list_status=70)) as (adapter, _transport):
        submitted = await adapter.submit(command)
        confirmed = await adapter.confirm_readback(command)
    assert submitted.status is WritebackStatus.ACCEPTED
    assert confirmed is None


@pytest.mark.asyncio
async def test_partial_succeeded_num_must_not_confirm() -> None:
    command = event_disposition_command(object_id="incident-wire-001")
    async with _adapter(SangforWireConfig(partial_dealstatus=True)) as (adapter, transport):
        submitted = await adapter.submit(command)
        confirmed = await adapter.confirm_readback(command)
    assert submitted.status is WritebackStatus.ACCEPTED
    assert confirmed is None
    assert DEALSTATUS_LIST_PATH in _paths(transport)


@pytest.mark.asyncio
async def test_unknown_target_does_not_send_http() -> None:
    command = event_disposition_command(object_id="incident-wire-001")
    command = command.model_copy(
        update={
            "operation_params": SetEventDispositionParams(
                target_disposition=SourceDisposition.UNKNOWN,
            )
        }
    )
    async with _adapter() as (adapter, transport):
        with pytest.raises(WritebackUnsupportedError):
            adapter.validate_command(command)
        with pytest.raises(WritebackUnsupportedError):
            await adapter.submit(command)
    assert _paths(transport) == []


@pytest.mark.asyncio
async def test_entity_submit_unsupported_does_not_invent_isolate_create() -> None:
    command = _entity_command()
    async with _adapter() as (adapter, transport):
        with pytest.raises(WritebackUnsupportedError):
            adapter.validate_command(command)
        with pytest.raises(WritebackUnsupportedError):
            await adapter.submit(command)
        completion = await adapter.read_entity_effect_completion(
            command,
            (await _accepted_placeholder(adapter, command)),
        )
    assert completion is None
    paths = _paths(transport)
    assert DEALSTATUS_WRITE_PATH not in paths
    assert _ISOLATE_CREATE_INVENTED not in paths


async def _accepted_placeholder(
    adapter: SangforDispositionAdapter,
    command: DispositionCommand,
):
    from datetime import UTC, datetime

    from app.models.disposition import DispositionReceipt

    now = datetime.now(UTC)
    _ = adapter
    return DispositionReceipt(
        writeback_id="s4-wbk-unused",
        sequence=1,
        disposition_id=command.disposition_id,
        action_id=command.action_id,
        source_record_id=command.source_locator.source_object_id,
        status=WritebackStatus.ACCEPTED,
        submitted_at=now,
        observed_at=now,
        simulated=False,
    )


@pytest.mark.asyncio
async def test_confirm_without_submit_snapshot_is_fail_closed() -> None:
    command = event_disposition_command(object_id="incident-wire-001")
    async with _adapter() as (adapter, transport):
        confirmed = await adapter.confirm_readback(command)
    assert confirmed is None
    assert DEALSTATUS_LIST_PATH not in _paths(transport)


@pytest.mark.asyncio
async def test_concurrency_token_is_not_required() -> None:
    command = event_disposition_command(object_id="incident-wire-001", token=None)
    assert command.source_concurrency_token is None
    async with _adapter() as (adapter, _transport):
        adapter.validate_command(command)
        submitted = await adapter.submit(command)
    assert submitted.status is WritebackStatus.ACCEPTED


def test_factory_default_kind_still_registers_only_mock_disposition() -> None:
    from app.adapters.factory import build_disposition_adapter_registry

    deps_src = inspect.getsource(deps._get_adapter_registry)
    assert "build_disposition_adapter_registry" in deps_src
    assert "wire_mock" not in deps_src
    assert "create_sangfor_wire_app" not in deps_src
    settings = Settings()
    registry = build_disposition_adapter_registry(settings)
    assert registry.list_names() == ["mock_xdr"]
    assert Settings.model_fields["disposition_adapter_kind"].default == "mock"
    assert Settings.model_fields["disposition_adapter_kind"].default != "sangfor_xdr"
    assert not hasattr(SangforXdrClient, "create_virusscantask")
    assert not hasattr(SangforXdrClient, "get_virusscantask")
    assert not hasattr(SangforXdrClient, "create_orders")
    assert not hasattr(SangforXdrClient, "list_orders")
    assert not hasattr(SangforXdrClient, "unblock")
    assert not hasattr(SangforXdrClient, "unisolate")
    assert not hasattr(SangforXdrClient, "disposefilerule")


def test_adapter_does_not_import_tool_provider_for_blockip() -> None:
    import app.adapters.sangfor.disposition as disposition_mod

    source = inspect.getsource(disposition_mod)
    assert "ToolProvider" not in source
    assert "mock_provider" not in source
    assert "providers.tools" not in source


def test_rename_blockdevice_skips_offline_and_renames_ids() -> None:
    online = rename_blockdevice_item(
        {
            "deviceId": 12346,
            "deviceName": "AF_011",
            "deviceType": "AF",
            "deviceStatus": "online",
            "deviceVersion": "8.0.15",
        }
    )
    assert online == {
        "devId": 12346,
        "devName": "AF_011",
        "devType": "AF",
        "devVersion": "8.0.15",
    }
    assert rename_blockdevice_item({"deviceId": 1, "deviceStatus": "offline"}) is None
    assert rename_blockdevice_item({"deviceId": 1, "deviceStatus": "not_active"}) is None


def test_block_status_literals_only_block_success_verifies() -> None:
    assert block_status_would_verify("block success") is True
    assert block_status_would_verify("block ip in deal") is False
    assert block_status_would_verify("part block success") is False
    assert block_status_would_verify("block failed") is False
    assert block_status_would_verify("unblocked") is False


def test_dss_entity_effect_gate_is_capability_only() -> None:
    gate = inspect.getsource(DispositionSyncService._entity_effect_readback_enabled)
    maybe = inspect.getsource(DispositionSyncService._maybe_complete_entity_effect)
    assert not hasattr(DispositionSyncService, "_mock_entity_effect_readback_enabled")
    assert "supports_entity_effect_readback" in gate
    assert "disposition_mode" not in gate
    assert "settings.simulation_enabled" not in gate
    assert 'adapter.name != "mock_xdr"' not in gate
    assert "receipt.simulated" not in gate
    assert "_entity_effect_readback_enabled" in maybe
    assert "_mock_entity_effect_readback_enabled" not in maybe

    from datetime import UTC, datetime

    from app.models.disposition import DispositionReceipt

    now = datetime.now(UTC)
    adapter = SangforDispositionAdapter(
        SangforXdrClient(
            "http://sangfor-wire",
            access_key=_VECTORS["ak"],
            secret_key=_VECTORS["sk"],
        )
    )
    receipt = DispositionReceipt(
        writeback_id="s4-wbk-live",
        sequence=1,
        disposition_id="disp-live",
        action_id="act-live",
        source_record_id="incident-wire-001",
        status=WritebackStatus.ACCEPTED,
        submitted_at=now,
        observed_at=now,
        simulated=False,
    )
    assert adapter.capabilities().supports_entity_effect_readback is True
    assert DispositionSyncService._entity_effect_readback_enabled(adapter, receipt) is True


@pytest.mark.asyncio
async def test_network_block_ip_accepted_then_list_block_success_verifies() -> None:
    command = _entity_command(
        entity_action_code="block_ip",
        canonical_target="ip:203.0.113.88",
    )
    block_config = SangforBlockConfig(block_channel="network", devices=(_AF_DEVICE,))
    async with _adapter(block_config=block_config) as (adapter, transport):
        submitted = await adapter.submit(command)
        completion = await adapter.read_entity_effect_completion(command, submitted)

    assert submitted.status is WritebackStatus.ACCEPTED
    assert submitted.simulated is False
    assert submitted.confirmation_evidence is None
    assert isinstance(submitted.raw_result.get("ids"), list)
    assert submitted.raw_result["ids"]
    assert completion is not None
    assert completion.verified is True
    assert completion.applied_status == "blocked"
    assert completion.target_type == "ip"
    assert completion.target == "203.0.113.88"
    assert completion.entity_action_code == "block_ip"

    paths = _paths(transport)
    assert BLOCK_NETWORK_PATH in paths
    assert BLOCK_ENDPOINT_PATH not in paths
    assert BLOCK_LIST_PATH in paths
    assert _ISOLATE_CREATE_INVENTED not in paths
    write_body = _json_body(_request_for(transport, BLOCK_NETWORK_PATH))
    assert write_body["blockIpRule"]["type"] == "DST_IP"
    assert write_body["blockIpRule"]["view"] == ["203.0.113.88"]
    assert isinstance(write_body["blockIpRule"]["view"], list)
    assert write_body["devices"][0]["devId"] == 12346
    assert "dealStatus" not in write_body
    list_body = _json_body(_request_for(transport, BLOCK_LIST_PATH))
    assert list_body["pageSize"] == 10
    assert list_body["pageSize"] != 5
    assert "ids" in list_body


@pytest.mark.asyncio
async def test_endpoint_block_ip_uses_plug_list_and_string_direction() -> None:
    command = _entity_command(
        entity_action_code="block_ip",
        canonical_target="ip:203.0.113.88",
    )
    block_config = SangforBlockConfig(block_channel="endpoint", devices=(_EDR_DEVICE,))
    async with _adapter(block_config=block_config) as (adapter, transport):
        submitted = await adapter.submit(command)
    assert submitted.status is WritebackStatus.ACCEPTED
    paths = _paths(transport)
    assert BLOCK_ENDPOINT_PATH in paths
    assert BLOCK_NETWORK_PATH not in paths
    body = _json_body(_request_for(transport, BLOCK_ENDPOINT_PATH))
    assert body["plugIpList"] == ["203.0.113.88"]
    assert body["direction"] == "DST_IP"
    assert isinstance(body["direction"], str)
    assert body["direction"] not in {1, 2, 3}
    assert "blockIpRule" not in body


@pytest.mark.asyncio
async def test_block_domain_is_network_dns() -> None:
    command = _entity_command(
        entity_action_code="block_domain",
        canonical_target="domain:unknown-upload-example.com",
    )
    block_config = SangforBlockConfig(block_channel="network", devices=(_AF_DEVICE,))
    async with _adapter(block_config=block_config) as (adapter, transport):
        submitted = await adapter.submit(command)
        completion = await adapter.read_entity_effect_completion(command, submitted)
    assert submitted.status is WritebackStatus.ACCEPTED
    assert completion is not None
    assert completion.verified is True
    assert completion.applied_status == "blocked"
    assert completion.target_type == "domain"
    body = _json_body(_request_for(transport, BLOCK_NETWORK_PATH))
    assert body["blockIpRule"]["type"] == "DNS"
    assert body["blockIpRule"]["view"] == ["unknown-upload-example.com"]
    assert BLOCK_ENDPOINT_PATH not in _paths(transport)


@pytest.mark.asyncio
async def test_endpoint_channel_sends_zero_http_for_block_domain() -> None:
    command = _entity_command(
        entity_action_code="block_domain",
        canonical_target="domain:unknown-upload-example.com",
    )
    block_config = SangforBlockConfig(block_channel="endpoint", devices=(_AF_DEVICE,))
    async with _adapter(block_config=block_config) as (adapter, transport):
        with pytest.raises(WritebackUnsupportedError):
            adapter.validate_command(command)
        with pytest.raises(WritebackUnsupportedError):
            await adapter.submit(command)
    assert _paths(transport) == []


@pytest.mark.asyncio
async def test_empty_devices_sends_zero_http_for_block_ip() -> None:
    command = _entity_command(
        entity_action_code="block_ip",
        canonical_target="ip:203.0.113.88",
    )
    async with _adapter() as (adapter, transport):
        with pytest.raises(WritebackUnsupportedError):
            await adapter.submit(command)
    assert _paths(transport) == []


def test_scan_task_completed_without_host_failure_verifies() -> None:
    assert scan_task_would_verify("completed", []) is True
    assert scan_task_would_verify("completed", [{"scanStatus": "scanCompleted"}]) is True
    assert scan_task_would_verify("completed", [{"scanStatus": "scanFailed"}]) is False
    assert scan_task_would_verify("partialCompleted", []) is False
    assert scan_task_would_verify("sending", []) is False
    assert scan_task_would_verify("distributionFailed", []) is False
    assert scan_task_would_verify("taskInit", []) is False


@pytest.mark.asyncio
async def test_wire_scan_empty_code_is_failed() -> None:
    command = _entity_command(
        entity_action_code=SCAN_ACTION,
        canonical_target="host:PC-FIN-023",
    )
    block_config = SangforBlockConfig(devices=(_EDR_DEVICE,), scan_source_name="shadowtrace")
    async with _adapter(block_config=block_config) as (adapter, transport):
        submitted = await adapter.submit(command)
        completion = await adapter.read_entity_effect_completion(command, submitted)

    assert submitted.status is WritebackStatus.FAILED
    assert completion is None

    paths = _paths(transport)
    assert VIRUS_SCAN_CREATE_PATH in paths
    assert all("/virusscantask/" not in path or path.endswith("/virusscantask") for path in paths)
    assert _ISOLATE_CREATE_INVENTED not in paths
    assert BLOCK_NETWORK_PATH not in paths

    create = _request_for(transport, VIRUS_SCAN_CREATE_PATH)
    assert create.method == "POST"
    body = _json_body(create)
    assert body["source"] == SCAN_SOURCE
    assert body["source"] != "GPT_AUTO"
    assert body["sourceName"] == "shadowtrace"
    assert body["scanType"] == "fast"
    assert body["scanMode"] == "adaptive"
    assert body["devices"]
    assert body["devices"][0]["devId"] == "edr-1"


@pytest.mark.asyncio
async def test_scan_missing_device_identity_sends_zero_http() -> None:
    command = _entity_command(
        entity_action_code=SCAN_ACTION,
        canonical_target="host:PC-FIN-023",
    )
    block_config = SangforBlockConfig(devices=({"devName": "no-id"},))
    async with _adapter(block_config=block_config) as (adapter, transport):
        with pytest.raises(WritebackUnsupportedError):
            adapter.validate_command(command)
        with pytest.raises(WritebackUnsupportedError):
            await adapter.submit(command)
    assert _paths(transport) == []


@pytest.mark.asyncio
async def test_scan_empty_create_code_is_failed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path.endswith("/virusscantask"):
            return httpx.Response(
                200,
                json={"code": "", "message": "", "data": {"taskId": "task-empty"}},
            )
        raise AssertionError(f"unexpected {request.method} {path}")

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforDispositionAdapter(
        _client(http),
        block_config=SangforBlockConfig(devices=(_EDR_DEVICE,)),
    )
    command = _entity_command(
        entity_action_code=SCAN_ACTION,
        canonical_target="host:PC-FIN-023",
    )
    submitted = await adapter.submit(command)
    await http.aclose()
    assert submitted.status is WritebackStatus.FAILED


@pytest.mark.asyncio
async def test_scan_completed_without_host_failure_verifies() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        path = request.url.path
        if request.method == "POST" and path.endswith("/virusscantask"):
            return httpx.Response(
                200,
                json={"code": "Success", "message": "", "data": {"taskId": "task-ok-1"}},
            )
        if request.method == "GET" and path.endswith("/virusscantask/task-ok-1"):
            return httpx.Response(
                200,
                json={
                    "code": "",
                    "message": "ok",
                    "data": {
                        "taskId": "task-ok-1",
                        "status": "completed",
                        "item": [{"scanStatus": "scanCompleted", "scanResult": "exist"}],
                    },
                },
            )
        raise AssertionError(f"unexpected {request.method} {path}")

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforDispositionAdapter(
        _client(http),
        block_config=SangforBlockConfig(devices=(_EDR_DEVICE,)),
    )
    command = _entity_command(
        entity_action_code=SCAN_ACTION,
        canonical_target="host:PC-FIN-023",
    )
    submitted = await adapter.submit(command)
    completion = await adapter.read_entity_effect_completion(command, submitted)
    await http.aclose()
    assert submitted.status is WritebackStatus.ACCEPTED
    assert completion is not None
    assert completion.verified is True
    assert completion.applied_status == "completed"
    assert completion.target == "PC-FIN-023"
    assert all(":taskId" not in httpx.URL(item.url).path for item in captured)
    assert captured[1].url.path.endswith("/virusscantask/task-ok-1")


@pytest.mark.asyncio
async def test_scan_completed_with_host_failure_is_not_verified() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path.endswith("/virusscantask"):
            return httpx.Response(
                200,
                json={"code": "Success", "data": {"taskId": "task-host-fail"}},
            )
        return httpx.Response(
            200,
            json={
                "code": "",
                "data": {
                    "taskId": "task-host-fail",
                    "status": "completed",
                    "item": [{"scanStatus": "scanFailed"}],
                },
            },
        )

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforDispositionAdapter(
        _client(http),
        block_config=SangforBlockConfig(devices=(_EDR_DEVICE,)),
    )
    command = _entity_command(
        entity_action_code=SCAN_ACTION,
        canonical_target="host:PC-FIN-023",
    )
    submitted = await adapter.submit(command)
    completion = await adapter.read_entity_effect_completion(command, submitted)
    await http.aclose()
    assert submitted.status is WritebackStatus.ACCEPTED
    assert completion is not None
    assert completion.verified is False
    assert completion.provider_code != "effect_not_applied"


@pytest.mark.asyncio
async def test_scan_partial_completed_is_not_verified() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path.endswith("/virusscantask"):
            return httpx.Response(
                200,
                json={"code": "Success", "data": {"taskId": "task-partial"}},
            )
        return httpx.Response(
            200,
            json={
                "code": "",
                "data": {"taskId": "task-partial", "status": "partialCompleted", "item": []},
            },
        )

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforDispositionAdapter(
        _client(http),
        block_config=SangforBlockConfig(devices=(_EDR_DEVICE,)),
    )
    command = _entity_command(
        entity_action_code=SCAN_ACTION,
        canonical_target="host:PC-FIN-023",
    )
    submitted = await adapter.submit(command)
    completion = await adapter.read_entity_effect_completion(command, submitted)
    await http.aclose()
    assert submitted.status is WritebackStatus.ACCEPTED
    assert completion is not None
    assert completion.verified is False
    assert completion.provider_code == "partialCompleted"


@pytest.mark.asyncio
async def test_scan_invalid_parameter_does_not_accept() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"code": "InvalidParameter", "message": "bad", "data": None},
        )

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforDispositionAdapter(
        _client(http),
        block_config=SangforBlockConfig(devices=(_EDR_DEVICE,)),
    )
    command = _entity_command(
        entity_action_code=SCAN_ACTION,
        canonical_target="host:PC-FIN-023",
    )
    submitted = await adapter.submit(command)
    await http.aclose()
    assert submitted.status is WritebackStatus.FAILED
    assert submitted.confirmation_evidence is None


def _ticket_config(**overrides: Any) -> SangforBlockConfig:
    payload: dict[str, Any] = {
        "process_template_id": TICKET_TEMPLATE_DEFAULT,
        "next_assignee_ids": (_TICKET_ASSIGNEE,),
        "ticket_title": "shadowtrace",
        "business_data_type": "INCIDENT",
    }
    payload.update(overrides)
    return SangforBlockConfig(**payload)


def _ticket_command() -> DispositionCommand:
    return _entity_command(
        entity_action_code=TICKET_ACTION,
        canonical_target="ticket:incident-wire-001",
        disposition_id="disp-ticket-1",
    )


async def _run_ticket(
    handler: Any,
    *,
    block_config: SangforBlockConfig | None = None,
) -> tuple[Any, Any, list[httpx.Request]]:
    captured: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return handler(request)

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(wrapped),
        base_url="https://xdr.example.com",
    )
    adapter = SangforDispositionAdapter(
        _client(http),
        block_config=block_config or _ticket_config(),
    )
    command = _ticket_command()
    submitted = await adapter.submit(command)
    completion = None
    if submitted.status is WritebackStatus.ACCEPTED:
        completion = await adapter.read_entity_effect_completion(command, submitted)
    await http.aclose()
    return submitted, completion, captured


def _ticket_create_ok_handler(
    *,
    list_status: str = "unfinished",
    list_code: str = "Success",
    list_order_id: int | str | None = None,
) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "GET" and path.endswith("/orders/list"):
            raise AssertionError("GET /orders/list is forbidden")
        if (
            request.method == "POST"
            and path.endswith("/orders")
            and not path.endswith("/orders/list")
        ):
            return httpx.Response(
                200,
                json={
                    "code": "Success",
                    "message": "操作成功",
                    "data": {"orderId": 212},
                },
            )
        if request.method == "POST" and path.endswith("/orders/list"):
            item: dict[str, Any] = {
                "workflowId": _TICKET_WORKFLOW_ID,
                "orderStatus": list_status,
            }
            if list_order_id is not None:
                item["orderId"] = list_order_id
            return httpx.Response(
                200,
                json={
                    "code": list_code,
                    "message": "",
                    "data": {"item": [item]},
                },
            )
        raise AssertionError(f"unexpected {request.method} {path}")

    return handler


@pytest.mark.asyncio
async def test_ticket_success_order_id_accepted_and_list_mismatch_is_unverified() -> None:
    submitted, completion, captured = await _run_ticket(_ticket_create_ok_handler())
    assert submitted.status is WritebackStatus.ACCEPTED
    assert submitted.simulated is False
    assert submitted.confirmation_evidence is None
    assert submitted.raw_result.get("orderId") == 212
    assert completion is not None
    assert completion.verified is False
    assert completion.applied_status == "created"
    assert completion.target_type == "ticket"
    assert completion.target == "incident-wire-001"
    assert completion.provider_record_id == "212"

    paths = [httpx.URL(item.url).path for item in captured]
    assert TICKET_CREATE_PATH in paths
    assert TICKET_LIST_PATH in paths
    assert all(item.method == "POST" for item in captured if item.url.path.endswith("/orders/list"))
    assert all(
        item.method != "GET" or not item.url.path.endswith("/orders/list") for item in captured
    )
    assert _ISOLATE_CREATE_INVENTED not in paths
    assert BLOCK_NETWORK_PATH not in paths

    create = next(item for item in captured if item.url.path == TICKET_CREATE_PATH)
    body = _json_body(create)
    assert body["processTemplateId"] == TICKET_TEMPLATE_DEFAULT
    assert body["nextAssigneeIds"] == [_TICKET_ASSIGNEE]
    assert body["title"] == "shadowtrace"
    assert body["businessData"]["type"] == "INCIDENT"
    assert body["businessData"]["ids"] == ["incident-wire-001"]
    list_req = next(item for item in captured if item.url.path == TICKET_LIST_PATH)
    list_body = _json_body(list_req)
    assert "orderId" not in list_body
    assert list_body["page"] == 1
    assert list_body["pageSize"] == 10
    assert _TICKET_WORKFLOW_ID != "212"


@pytest.mark.asyncio
async def test_ticket_list_containing_order_id_is_verified() -> None:
    submitted, completion, captured = await _run_ticket(
        _ticket_create_ok_handler(list_order_id=212),
    )
    assert submitted.status is WritebackStatus.ACCEPTED
    assert completion is not None
    assert completion.verified is True
    assert any(item.url.path == TICKET_LIST_PATH for item in captured)


@pytest.mark.asyncio
async def test_ticket_list_unfinished_does_not_wait_for_resolved() -> None:
    submitted, completion, _captured = await _run_ticket(
        _ticket_create_ok_handler(list_status="unfinished", list_code=""),
    )
    assert submitted.status is WritebackStatus.ACCEPTED
    assert completion is not None
    assert completion.verified is False
    assert completion.applied_status == "created"


@pytest.mark.asyncio
async def test_ticket_lowercase_incident_type_accepted() -> None:
    submitted, completion, captured = await _run_ticket(
        _ticket_create_ok_handler(),
        block_config=_ticket_config(business_data_type="incident"),
    )
    assert submitted.status is WritebackStatus.ACCEPTED
    assert completion is not None
    assert completion.verified is False
    create = next(item for item in captured if item.url.path == TICKET_CREATE_PATH)
    assert _json_body(create)["businessData"]["type"] == "incident"


@pytest.mark.asyncio
async def test_ticket_missing_template_sends_zero_http() -> None:
    command = _ticket_command()
    block_config = _ticket_config(process_template_id="")
    async with _adapter(block_config=block_config) as (adapter, transport):
        with pytest.raises(WritebackUnsupportedError):
            adapter.validate_command(command)
        with pytest.raises(WritebackUnsupportedError):
            await adapter.submit(command)
    assert _paths(transport) == []


@pytest.mark.asyncio
async def test_ticket_missing_assignee_sends_zero_http() -> None:
    command = _ticket_command()
    block_config = _ticket_config(next_assignee_ids=())
    async with _adapter(block_config=block_config) as (adapter, transport):
        with pytest.raises(WritebackUnsupportedError):
            adapter.validate_command(command)
        with pytest.raises(WritebackUnsupportedError):
            await adapter.submit(command)
    assert _paths(transport) == []


@pytest.mark.asyncio
async def test_ticket_empty_create_code_is_failed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"code": "", "message": "", "data": {"orderId": 212}},
        )

    submitted, completion, captured = await _run_ticket(handler)
    assert submitted.status is WritebackStatus.FAILED
    assert completion is None
    assert all(not item.url.path.endswith("/orders/list") for item in captured)


@pytest.mark.asyncio
async def test_ticket_missing_order_id_is_failed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"code": "Success", "message": "ok", "data": {}},
        )

    submitted, _completion, captured = await _run_ticket(handler)
    assert submitted.status is WritebackStatus.FAILED
    assert all(not item.url.path.endswith("/orders/list") for item in captured)


@pytest.mark.asyncio
async def test_ticket_invalid_parameter_is_failed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"code": "InvalidParameter", "message": "bad", "data": None},
        )

    submitted, _completion, captured = await _run_ticket(handler)
    assert submitted.status is WritebackStatus.FAILED
    assert submitted.confirmation_evidence is None
    assert all(not item.url.path.endswith("/orders/list") for item in captured)


@pytest.mark.asyncio
async def test_ticket_list_failure_is_not_verified() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if (
            request.method == "POST"
            and path.endswith("/orders")
            and not path.endswith("/orders/list")
        ):
            return httpx.Response(
                200,
                json={"code": "Success", "data": {"orderId": 212}},
            )
        if request.method == "POST" and path.endswith("/orders/list"):
            return httpx.Response(500, json={"code": "Failed", "message": "down"})
        raise AssertionError(f"unexpected {request.method} {path}")

    submitted, completion, captured = await _run_ticket(handler)
    assert submitted.status is WritebackStatus.ACCEPTED
    assert completion is not None
    assert completion.verified is False
    assert any(item.url.path == TICKET_LIST_PATH for item in captured)


_POLICY_ID = "6542fb0b8b6ed6004a2d96a3"
_ISOLATE_POLICY_ID = "6331608847b7f05800a6d8ac"


def _compensation_command() -> DispositionCommand:
    return DispositionCommand(
        disposition_id="disp-comp-1",
        action_id="act-comp-1",
        closure_cycle=1,
        intent_kind=DispositionIntentKind.COMPENSATION_RECORD,
        source_locator=SourceObjectLocator(
            source_product="sangfor_xdr",
            source_tenant_id="tenant-demo",
            connector_id="conn-disposition",
            source_kind=SourceObjectKind.INCIDENT,
            source_object_id="incident-wire-001",
        ),
        operation_code="record_compensation",
        operation_params=RecordCompensationParams(summary_code="success"),
        operator_id="analyst-1",
        idempotency_key="idem-comp-1",
        execution_owner=ExecutionOwner.XDR_MANAGED,
        parent_disposition_id="disp-entity-1",
    )


def test_compensation_part_success_is_partial_not_confirmed() -> None:
    assert (
        compensation_is_partial(
            business_code="Part Success",
            data={"fail": 1, "success": 1},
        )
        is True
    )
    assert compensation_is_partial(business_code="Success", data={"fail": 1}) is True
    assert compensation_is_partial(business_code="Success", data={"fail": 0}) is False
    assert compensation_is_partial(business_code="Success", data={}) is False


@pytest.mark.asyncio
async def test_wire_unblock_part_success_is_partial_not_confirmed() -> None:
    command = _compensation_command()
    block_config = SangforBlockConfig(
        compensation_kind="unblock",
        compensation_ids=(_POLICY_ID,),
    )
    async with _adapter(block_config=block_config) as (adapter, transport):
        submitted = await adapter.submit(command)
        confirmed = await adapter.confirm_readback(command)
    assert submitted.status is WritebackStatus.PARTIAL
    assert submitted.status is not WritebackStatus.CONFIRMED
    assert submitted.confirmation_evidence is None
    assert submitted.raw_result.get("failIds")
    assert confirmed is None
    paths = _paths(transport)
    assert UNBLOCK_PATH in paths
    assert _ISOLATE_CREATE_INVENTED not in paths
    body = _json_body(_request_for(transport, UNBLOCK_PATH))
    assert body["ids"] == [_POLICY_ID]
    assert isinstance(body["ids"], list)


@pytest.mark.asyncio
async def test_unblock_success_is_accepted_not_confirmed() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={"code": "Success", "message": "成功", "data": {"success": 1, "fail": 0}},
        )

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforDispositionAdapter(
        _client(http),
        block_config=SangforBlockConfig(
            compensation_kind="unblock",
            compensation_ids=(_POLICY_ID,),
        ),
    )
    submitted = await adapter.submit(_compensation_command())
    await http.aclose()
    assert submitted.status is WritebackStatus.ACCEPTED
    assert submitted.status is not WritebackStatus.CONFIRMED
    assert captured[0].method == "POST"
    assert captured[0].url.path == UNBLOCK_PATH
    assert _json_body(captured[0])["ids"] == [_POLICY_ID]


@pytest.mark.asyncio
async def test_unisolate_sends_ids_array_not_string() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={"code": "Success", "data": {"success": 1, "fail": 0}},
        )

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforDispositionAdapter(
        _client(http),
        block_config=SangforBlockConfig(
            compensation_kind="unisolate",
            compensation_ids=(_ISOLATE_POLICY_ID,),
        ),
    )
    submitted = await adapter.submit(_compensation_command())
    await http.aclose()
    assert submitted.status is WritebackStatus.ACCEPTED
    body = _json_body(captured[0])
    assert captured[0].url.path == UNISOLATE_PATH
    assert body["ids"] == [_ISOLATE_POLICY_ID]
    assert isinstance(body["ids"], list)
    assert not isinstance(body["ids"], str)


@pytest.mark.asyncio
async def test_unisolate_hostname_sends_zero_http() -> None:
    command = _compensation_command()
    for bad_id in ("PC-FIN-023", "host:PC-FIN-023"):
        block_config = SangforBlockConfig(
            compensation_kind="unisolate",
            compensation_ids=(bad_id,),
        )
        async with _adapter(block_config=block_config) as (adapter, transport):
            with pytest.raises(WritebackUnsupportedError):
                adapter.validate_command(command)
            with pytest.raises(WritebackUnsupportedError):
                await adapter.submit(command)
        assert _paths(transport) == []


@pytest.mark.asyncio
async def test_disposefilerule_part_success_is_partial() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "code": "Part Success",
                "message": "部分成功",
                "data": {
                    "success": 1,
                    "fail": 1,
                    "successIds": ["ok-1"],
                    "failIds": ["fail-1"],
                },
            },
        )

    http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://xdr.example.com",
    )
    adapter = SangforDispositionAdapter(
        _client(http),
        block_config=SangforBlockConfig(
            compensation_kind="disposefilerule",
            compensation_ids=(_POLICY_ID,),
        ),
    )
    submitted = await adapter.submit(_compensation_command())
    await http.aclose()
    assert submitted.status is WritebackStatus.PARTIAL
    assert submitted.status is not WritebackStatus.CONFIRMED
    assert submitted.raw_result.get("successIds") == ["ok-1"]
    assert submitted.raw_result.get("failIds") == ["fail-1"]
    assert captured[0].url.path == DISPOSE_FILE_PATH


@pytest.mark.asyncio
async def test_compensation_missing_kind_or_ids_sends_zero_http() -> None:
    command = _compensation_command()
    async with _adapter() as (adapter, transport):
        with pytest.raises(WritebackUnsupportedError):
            await adapter.submit(command)
    assert _paths(transport) == []
    block_config = SangforBlockConfig(compensation_kind="unblock", compensation_ids=())
    async with _adapter(block_config=block_config) as (adapter, transport):
        with pytest.raises(WritebackUnsupportedError):
            await adapter.submit(command)
    assert _paths(transport) == []
