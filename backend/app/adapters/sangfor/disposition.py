"""Sangfor XDR DispositionAdapter — dealStatus through ticket plus L6d compensation.

Not wired into DISPOSITION_ADAPTER_KIND / the adapter factory. Agents must
not import this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from app.adapters._util import sanitize_disposition_receipt, sanitize_raw_result
from app.adapters.disposition.base import (
    BaseDispositionAdapter,
    DispositionAdapterCapabilities,
)
from app.adapters.sangfor.client import SangforXdrClient
from app.core.errors import ValidationError as ShadowTraceValidationError
from app.core.errors import WritebackUnsupportedError
from app.mock_xdr.state import find_forbidden_analysis_keys
from app.models.disposition import (
    DispositionCommand,
    DispositionReceipt,
    EntityEffectCompletion,
    RecordCompensationParams,
    SetEventDispositionParams,
    SubmitEntityActionParams,
    parse_entity_effect_target,
)
from app.models.enums import (
    CapabilityState,
    ConfirmationEvidence,
    ConnectorStatus,
    DispositionIntentKind,
    SourceDisposition,
    WritebackStatus,
)

SOURCE_PRODUCT = "sangfor_xdr"
DEALSTATUS_WRITE_PATH = "/api/xdr/v1/incidents/dealstatus"
DEALSTATUS_LIST_PATH = "/api/xdr/v1/incidents/dealstatus/list"
BLOCK_NETWORK_PATH = "/api/xdr/v1/responses/blockiprule/network"
BLOCK_ENDPOINT_PATH = "/api/xdr/v1/responses/blockiprule/endpoint"
BLOCK_LIST_PATH = "/api/xdr/v1/responses/blockiprule/list"
VIRUS_SCAN_CREATE_PATH = "/api/xdr/v1/responses/virusscantask"
VIRUS_SCAN_STATUS_PATH = "/api/xdr/v1/responses/virusscantask/:taskId"
TICKET_CREATE_PATH = "/api/xdr/v1/orders"
TICKET_LIST_PATH = "/api/xdr/v1/orders/list"
UNBLOCK_PATH = "/api/xdr/v1/responses/blockiprule/unblock"
UNISOLATE_PATH = "/api/xdr/v1/responses/host/unisolate"
DISPOSE_FILE_PATH = "/api/xdr/v1/responses/disposefilerule"
DEAL_COMMENT_ALLOWLIST = frozenset({"shadowtrace:closed"})
BLOCK_LIST_PAGE_SIZE = 10
TICKET_LIST_PAGE_SIZE = 10
BLOCK_SUCCESS_STATUS = "block success"
BLOCK_IN_DEAL_STATUS = "block ip in deal"
SCAN_ACTION = "scan_host_for_virus"
TICKET_ACTION = "create_ticket"
SCAN_SOURCE = "GPT_MANUAL"
SCAN_TYPE_DEFAULT = "fast"
SCAN_MODE_DEFAULT = "adaptive"
SCAN_SOURCE_NAME_DEFAULT = "shadowtrace"
TICKET_TEMPLATE_DEFAULT = "incidentBulletin"
TICKET_TITLE_DEFAULT = "shadowtrace"
TICKET_TYPE_DEFAULT = "INCIDENT"
TICKET_APPLIED_STATUS = "created"
TICKET_TARGET_TYPE = "ticket"
_OFFLINE_DEVICE_STATUS = frozenset({"offline", "not_active"})
_BLOCK_ACTIONS = frozenset({"block_ip", "block_domain"})
_ENTITY_ACTIONS = _BLOCK_ACTIONS | {SCAN_ACTION, TICKET_ACTION}
_EXPLICIT_FAIL_CODES = frozenset({"Failed", "InvalidParameter"})
PART_SUCCESS_CODE = "Part Success"
COMP_UNBLOCK = "unblock"
COMP_UNISOLATE = "unisolate"
COMP_DISPOSE_FILE = "disposefilerule"
_COMPENSATION_KINDS = frozenset({COMP_UNBLOCK, COMP_UNISOLATE, COMP_DISPOSE_FILE})
_COMPENSATION_PATHS = {
    COMP_UNBLOCK: UNBLOCK_PATH,
    COMP_UNISOLATE: UNISOLATE_PATH,
    COMP_DISPOSE_FILE: DISPOSE_FILE_PATH,
}
_SCAN_PENDING_STATUS = frozenset(
    {
        "taskInit",
        "underDistribution",
        "distributed",
        "sending",
        "scanning",
    }
)
_SCAN_PARTIAL_STATUS = frozenset({"partialCompleted", "partialDistribution"})
_SCAN_FAILED_STATUS = frozenset({"distributionFailed", "timeout", "dataAnomaly"})
_HOST_FAIL_SCAN_STATUS = frozenset({"scanFailed", "sendingFailed"})
_DEFAULT_IP_TYPE = "DST_IP"
_DEFAULT_ENDPOINT_DIRECTION = "DST_IP"

# §2.2 outbound TMG codes. 20 is forbidden. unknown does not send HTTP.
_OUTBOUND_TMG: dict[SourceDisposition, int] = {
    SourceDisposition.PENDING: 0,
    SourceDisposition.PROCESSING: 10,
    SourceDisposition.COMPLETED: 40,
    SourceDisposition.SUSPENDED: 50,
    SourceDisposition.IGNORED: 60,
    SourceDisposition.CONTAINED: 70,
}

# §2.2 inbound B library codes on dealstatus/list (not incidents/list TMG).
_INBOUND_B: dict[int, SourceDisposition] = {
    1: SourceDisposition.PENDING,
    2: SourceDisposition.PROCESSING,
    3: SourceDisposition.COMPLETED,
    4: SourceDisposition.SUSPENDED,
    5: SourceDisposition.IGNORED,
    6: SourceDisposition.CONTAINED,
}

_EXPECTED_LIBRARY: dict[SourceDisposition, int] = {
    disposition: code for code, disposition in _INBOUND_B.items()
}
_OUTBOUND_TMG_TO_DISPOSITION: dict[int, SourceDisposition] = {
    code: disposition for disposition, code in _OUTBOUND_TMG.items()
}


@dataclass(frozen=True)
class SangforBlockConfig:
    """Constructor-injected block/scan/ticket fields. Factory fills from Settings."""

    block_channel: str = "network"
    devices: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    scan_source_name: str = SCAN_SOURCE_NAME_DEFAULT
    process_template_id: str = TICKET_TEMPLATE_DEFAULT
    next_assignee_ids: tuple[str, ...] = field(default_factory=tuple)
    ticket_title: str = TICKET_TITLE_DEFAULT
    business_data_type: str = TICKET_TYPE_DEFAULT
    compensation_kind: str = ""
    compensation_ids: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class _WriteSnapshot:
    write_code: str | None
    succeeded_num: int | None
    total: int | None
    target: SourceDisposition
    source_object_id: str
    used_incidents_list: bool = False


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.lstrip("-").isdigit():
            return int(text)
    return None


def map_outbound_deal_status(target: SourceDisposition) -> int | None:
    """Return TMG write code, or None when HTTP must not be sent."""
    return _OUTBOUND_TMG.get(target)


def source_disposition_from_outbound_tmg(deal_status: int) -> SourceDisposition | None:
    """Map an outbound TMG integer back to SourceDisposition. Unknown codes are None."""
    return _OUTBOUND_TMG_TO_DISPOSITION.get(deal_status)


def map_inbound_b(deal_status: int | None) -> SourceDisposition:
    if deal_status is None:
        return SourceDisposition.UNKNOWN
    return _INBOUND_B.get(deal_status, SourceDisposition.UNKNOWN)


def dealstatus_readback_would_confirm(
    *,
    write_code: str | None,
    succeeded_num: int | None,
    total: int | None,
    list_deal_status: int | None,
    target: SourceDisposition,
    used_incidents_list: bool = False,
) -> bool:
    """CONFIRMED iff write Success, full succeededNum, and inbound B matches target.

    For ``contained`` this is the same contract as Layer 3
    ``dealstatus_writeback_would_confirm`` (library code 6, never TMG 70).
    """
    if used_incidents_list:
        return False
    if write_code != "Success":
        return False
    if succeeded_num is None or total is None or succeeded_num != total:
        return False
    expected = _EXPECTED_LIBRARY.get(target)
    if expected is None:
        return False
    return list_deal_status == expected


def rename_blockdevice_item(item: dict[str, Any]) -> dict[str, Any] | None:
    """§2.3.1: blockdevice/list fields → create ``devices[]``. Skip offline."""
    status = str(item.get("deviceStatus") or "").strip().lower()
    if status in _OFFLINE_DEVICE_STATUS:
        return None
    dev_id = item.get("devId", item.get("deviceId"))
    if dev_id is None or str(dev_id).strip() == "":
        return None
    renamed: dict[str, Any] = {
        "devId": dev_id,
        "devName": item.get("devName", item.get("deviceName")),
        "devType": item.get("devType", item.get("deviceType")),
    }
    version = item.get("devVersion", item.get("deviceVersion"))
    if version is not None and str(version).strip() != "":
        renamed["devVersion"] = version
    return renamed


def block_status_would_verify(status: str | None) -> bool:
    """Job-effect verified only for the exact list/detail literal ``block success``."""
    return status == BLOCK_SUCCESS_STATUS


def _as_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def scan_device_item(item: dict[str, Any]) -> dict[str, Any] | None:
    """Scan devices need gatewayId or devId or agentId (§2.3.2). Skip offline."""
    status = str(item.get("deviceStatus") or "").strip().lower()
    if status in _OFFLINE_DEVICE_STATUS:
        return None
    gateway_id = item.get("gatewayId")
    agent_id = item.get("agentId")
    dev_id = item.get("devId", item.get("deviceId"))
    has_gateway = _as_text(gateway_id) is not None
    has_agent = _as_text(agent_id) is not None
    has_dev = _as_text(dev_id) is not None
    if not (has_gateway or has_agent or has_dev):
        return None
    row: dict[str, Any] = {}
    if has_gateway:
        row["gatewayId"] = gateway_id
    if has_dev:
        row["devId"] = dev_id
    if has_agent:
        row["agentId"] = agent_id
    name = item.get("devName", item.get("deviceName"))
    if name is not None:
        row["devName"] = name
    dtype = item.get("devType", item.get("deviceType"))
    if dtype is not None:
        row["devType"] = dtype
    return row


def _host_scan_failed(items: list[dict[str, Any]]) -> bool:
    for item in items:
        scan_status = _as_text(item.get("scanStatus"))
        if scan_status in _HOST_FAIL_SCAN_STATUS:
            return True
    return False


def scan_task_would_verify(
    status: str | None,
    items: list[dict[str, Any]] | None = None,
) -> bool:
    """CONFIRMED only for task ``completed`` with no partial/host failure."""
    if status != "completed":
        return False
    return not _host_scan_failed(items or [])


def _ticket_target(canonical_target: str) -> tuple[str, str] | None:
    """Parse ``ticket:<id>`` without ENTITY_ACTION_EFFECT_SPECS."""
    prefix, separator, target = canonical_target.partition(":")
    if not separator or prefix != TICKET_TARGET_TYPE or not target:
        return None
    return prefix, target


def _order_id_from(data: Any) -> int | str | None:
    if not isinstance(data, dict):
        return None
    raw = data.get("orderId")
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    text = str(raw).strip()
    return text or None


def _assignee_ids(raw: tuple[str, ...]) -> list[str]:
    return [item.strip() for item in raw if item.strip()]


def _compensation_ids(raw: tuple[str, ...]) -> list[str]:
    return [item.strip() for item in raw if item.strip()]


def _is_hex_policy_id(value: str) -> bool:
    text = value.strip()
    return bool(text) and all(char in "0123456789abcdefABCDEF" for char in text)


def _id_list_field(data: Any, key: str) -> list[str]:
    if not isinstance(data, dict):
        return []
    raw = data.get(key)
    if raw is None:
        return []
    if isinstance(raw, str):
        text = raw.strip()
        return [text] if text else []
    if not isinstance(raw, list):
        return []
    return [str(item).strip() for item in raw if item is not None and str(item).strip()]


def compensation_is_partial(*, business_code: str | None, data: Any) -> bool:
    """§2.3.3: Part Success (with space) or data.fail > 0 is never whole-order CONFIRMED."""
    if business_code == PART_SUCCESS_CODE:
        return True
    fail = _int_field(data, "fail")
    return fail is not None and fail > 0


def _explicit_business_failure(business_code: str | None) -> bool:
    return (business_code or "") in _EXPLICIT_FAIL_CODES


def _http_ok(status: int) -> bool:
    return 200 <= status < 300


def _ticket_list_contains(data: Any, order_id: str) -> bool:
    if not isinstance(data, dict):
        return False
    items = data.get("item") or data.get("list") or []
    if not isinstance(items, list):
        return False
    for item in items:
        if isinstance(item, dict) and _as_text(item.get("orderId")) == order_id:
            return True
    return False


def _task_id_from(data: Any) -> str | None:
    if not isinstance(data, dict):
        return None
    return _as_text(data.get("taskId"))


def _int_field(data: Any, key: str) -> int | None:
    if not isinstance(data, dict):
        return None
    return _as_int(data.get(key))


def _list_status_for(data: Any, object_id: str) -> int | None:
    if not isinstance(data, dict):
        return None
    items = data.get("item") or []
    if not isinstance(items, list):
        return None
    for item in items:
        if isinstance(item, dict) and str(item.get("uuId")) == object_id:
            return _as_int(item.get("dealStatus"))
    if len(items) == 1 and isinstance(items[0], dict):
        return _as_int(items[0].get("dealStatus"))
    return None


def _rule_ids_from(data: Any) -> list[str]:
    if not isinstance(data, dict):
        return []
    raw = data.get("ids") or []
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw if item is not None and str(item).strip() != ""]


def _block_items(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    items = data.get("item") or []
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


class SangforDispositionAdapter(BaseDispositionAdapter):
    """Event dealStatus, entity writes, tickets, and compensation."""

    name = SOURCE_PRODUCT

    def __init__(
        self,
        client: SangforXdrClient,
        *,
        block_config: SangforBlockConfig | None = None,
    ) -> None:
        self._client = client
        self._block = block_config or SangforBlockConfig()
        self._writes: dict[str, _WriteSnapshot] = {}

    def capabilities(self) -> DispositionAdapterCapabilities:
        supported = CapabilityState.SUPPORTED
        unsupported = CapabilityState.UNSUPPORTED
        return DispositionAdapterCapabilities(
            intents={
                DispositionIntentKind.EVENT_STATUS_UPDATE: supported,
                DispositionIntentKind.ENTITY_ACTION_SUBMIT: supported,
                DispositionIntentKind.EXECUTION_RESULT_RECORD: unsupported,
                DispositionIntentKind.COMPENSATION_RECORD: supported,
            },
            operations={
                "set_event_disposition": supported,
                "submit_entity_action": supported,
                "record_execution_result": unsupported,
                "record_compensation": supported,
                "blockip": unsupported,
                "blockiprule": unsupported,
            },
            supports_idempotency=False,
            supports_status_query=False,
            supports_concurrency_token=False,
            supports_lookup_by_idempotency=False,
            supports_readback_confirmation=True,
            supports_entity_effect_readback=True,
        )

    def _block_channel(self) -> str:
        return (self._block.block_channel or "network").strip().lower()

    def _usable_devices(self) -> list[dict[str, Any]]:
        usable: list[dict[str, Any]] = []
        for raw in self._block.devices:
            renamed = rename_blockdevice_item(raw) if "deviceId" in raw else dict(raw)
            if renamed is None:
                continue
            if renamed.get("devId") is None or str(renamed.get("devId")).strip() == "":
                continue
            usable.append(
                {
                    key: renamed[key]
                    for key in ("devId", "devName", "devType", "devVersion")
                    if key in renamed and renamed[key] is not None
                }
            )
        return usable

    def _usable_scan_devices(self) -> list[dict[str, Any]]:
        usable: list[dict[str, Any]] = []
        for raw in self._block.devices:
            row = scan_device_item(raw)
            if row is not None:
                usable.append(row)
        return usable

    def _ticket_ready(self) -> bool:
        template = _as_text(self._block.process_template_id)
        return template is not None and bool(_assignee_ids(self._block.next_assignee_ids))

    def _compensation_kind(self) -> str | None:
        kind = (self._block.compensation_kind or "").strip().lower()
        return kind if kind in _COMPENSATION_KINDS else None

    def _usable_compensation_ids(self) -> list[str]:
        ids = _compensation_ids(self._block.compensation_ids)
        if self._compensation_kind() != COMP_UNISOLATE:
            return ids
        return [item for item in ids if _is_hex_policy_id(item)]

    def validate_command(self, command: DispositionCommand) -> None:
        DispositionCommand.model_validate(command.model_dump(mode="json"))
        forbidden = find_forbidden_analysis_keys(command.model_dump(mode="json"))
        if forbidden:
            raise ShadowTraceValidationError(
                "analysis fields forbidden on disposition command",
                error_code="unauthorized_field",
                details={"paths": forbidden},
            )
        caps = self.capabilities()
        intent_state = caps.intents.get(command.intent_kind, CapabilityState.UNKNOWN)
        if intent_state is not CapabilityState.SUPPORTED:
            raise WritebackUnsupportedError(
                f"intent {command.intent_kind.value} unsupported",
                details={"intent_kind": command.intent_kind.value},
            )
        op_state = caps.operations.get(command.operation_code, CapabilityState.UNKNOWN)
        if op_state is not CapabilityState.SUPPORTED:
            raise WritebackUnsupportedError(
                f"operation {command.operation_code} not supported",
                details={"operation_code": command.operation_code},
            )
        if command.intent_kind is DispositionIntentKind.EVENT_STATUS_UPDATE:
            params = command.operation_params
            if not isinstance(params, SetEventDispositionParams):
                raise WritebackUnsupportedError(
                    "EVENT_STATUS_UPDATE requires set_event_disposition params",
                    details={"operation_code": command.operation_code},
                )
            if map_outbound_deal_status(params.target_disposition) is None:
                raise WritebackUnsupportedError(
                    "unknown or illegal disposition does not send HTTP",
                    details={"target_disposition": params.target_disposition.value},
                )
            return
        if command.intent_kind is DispositionIntentKind.ENTITY_ACTION_SUBMIT:
            self._validate_entity_command(command)
            return
        if command.intent_kind is DispositionIntentKind.COMPENSATION_RECORD:
            self._validate_compensation_command(command)
            return
        raise WritebackUnsupportedError(
            f"intent {command.intent_kind.value} unsupported this layer",
            details={"intent_kind": command.intent_kind.value},
        )

    def _validate_entity_command(self, command: DispositionCommand) -> None:
        params = command.operation_params
        if not isinstance(params, SubmitEntityActionParams):
            raise WritebackUnsupportedError(
                "ENTITY_ACTION_SUBMIT requires submit_entity_action params",
                details={"operation_code": command.operation_code},
            )
        code = params.entity_action_code
        if code not in _ENTITY_ACTIONS:
            raise WritebackUnsupportedError(
                f"entity action {code} unsupported this layer",
                details={"entity_action_code": code},
            )
        if code == "block_domain" and self._block_channel() == "endpoint":
            raise WritebackUnsupportedError(
                "block_domain cannot use endpoint channel",
                details={"block_channel": "endpoint", "entity_action_code": code},
            )
        if code in _BLOCK_ACTIONS and not self._usable_devices():
            raise WritebackUnsupportedError(
                "no devices; block create is not sent",
                details={"entity_action_code": code},
            )
        if code == SCAN_ACTION and not self._usable_scan_devices():
            raise WritebackUnsupportedError(
                "no devices; scan create is not sent",
                details={"entity_action_code": code},
            )
        if code == TICKET_ACTION and not self._ticket_ready():
            raise WritebackUnsupportedError(
                "no processTemplateId or nextAssigneeIds; ticket create is not sent",
                details={"entity_action_code": code},
            )
        if code == TICKET_ACTION:
            if _ticket_target(params.canonical_target) is None:
                raise WritebackUnsupportedError(
                    "canonical_target must be ticket:<non-empty-target>",
                    details={"canonical_target": params.canonical_target},
                )
            return
        try:
            parse_entity_effect_target(code, params.canonical_target)
        except ValueError as exc:
            raise WritebackUnsupportedError(
                str(exc),
                details={"canonical_target": params.canonical_target},
            ) from exc

    def _validate_compensation_command(self, command: DispositionCommand) -> None:
        params = command.operation_params
        if not isinstance(params, RecordCompensationParams):
            raise WritebackUnsupportedError(
                "COMPENSATION_RECORD requires record_compensation params",
                details={"operation_code": command.operation_code},
            )
        kind = self._compensation_kind()
        if kind is None:
            raise WritebackUnsupportedError(
                "compensation kind missing; compensate is not sent",
                details={"compensation_kind": self._block.compensation_kind},
            )
        ids = _compensation_ids(self._block.compensation_ids)
        if not ids:
            raise WritebackUnsupportedError(
                "no vendor policy ids; compensate is not sent",
                details={"compensation_kind": kind},
            )
        if kind == COMP_UNISOLATE and not self._usable_compensation_ids():
            raise WritebackUnsupportedError(
                "unisolate ids must be policy ids, not hostname",
                details={"compensation_kind": kind},
            )

    async def submit(self, command: DispositionCommand) -> DispositionReceipt:
        self.validate_command(command)
        if command.intent_kind is DispositionIntentKind.ENTITY_ACTION_SUBMIT:
            params = command.operation_params
            assert isinstance(params, SubmitEntityActionParams)
            if params.entity_action_code == TICKET_ACTION:
                return await self._submit_ticket(command)
            if params.entity_action_code == SCAN_ACTION:
                return await self._submit_scan(command)
            return await self._submit_block(command)
        if command.intent_kind is DispositionIntentKind.COMPENSATION_RECORD:
            return await self._submit_compensation(command)
        return await self._submit_event(command)

    async def _submit_event(self, command: DispositionCommand) -> DispositionReceipt:
        params = command.operation_params
        assert isinstance(params, SetEventDispositionParams)
        deal_status = map_outbound_deal_status(params.target_disposition)
        assert deal_status is not None
        object_id = command.source_locator.source_object_id
        body: dict[str, Any] = {
            "uuIds": [object_id],
            "dealStatus": deal_status,
        }
        comment = params.comment_code
        if comment in DEAL_COMMENT_ALLOWLIST:
            body["dealComment"] = comment

        try:
            result = await self._client.request(
                "POST",
                DEALSTATUS_WRITE_PATH,
                json_body=body,
            )
        except (httpx.TimeoutException, httpx.TransportError):
            return self._receipt(
                command,
                WritebackStatus.UNKNOWN,
                provider_code="unknown_delivery",
                raw={"lost_response": True},
            )

        snapshot = _WriteSnapshot(
            write_code=result.business_code,
            succeeded_num=_int_field(result.data, "succeededNum"),
            total=_int_field(result.data, "total"),
            target=params.target_disposition,
            source_object_id=object_id,
        )
        self._writes[command.disposition_id] = snapshot

        if result.http_status >= 500:
            return self._receipt(
                command,
                WritebackStatus.UNKNOWN,
                provider_code=result.business_code or "unknown_delivery",
                raw={"http_status": result.http_status, "body": result.raw_text},
            )
        if result.http_status >= 400 or result.business_code != "Success":
            return self._receipt(
                command,
                WritebackStatus.FAILED,
                provider_code=result.business_code,
                provider_message=result.message,
                raw={"http_status": result.http_status, "data": result.data},
            )
        return self._receipt(
            command,
            WritebackStatus.ACCEPTED,
            provider_code=result.business_code,
            provider_message=result.message,
            raw={
                "http_status": result.http_status,
                "succeededNum": snapshot.succeeded_num,
                "total": snapshot.total,
            },
        )

    async def _submit_block(self, command: DispositionCommand) -> DispositionReceipt:
        params = command.operation_params
        assert isinstance(params, SubmitEntityActionParams)
        path, body = self._block_create_request(command, params)
        try:
            result = await self._client.request("POST", path, json_body=body)
        except (httpx.TimeoutException, httpx.TransportError):
            return self._receipt(
                command,
                WritebackStatus.UNKNOWN,
                provider_code="unknown_delivery",
                raw={"lost_response": True},
            )
        writeback_id = f"s4-wbk-{command.disposition_id}"
        ids = _rule_ids_from(result.data)
        if result.http_status >= 500:
            return self._receipt(
                command,
                WritebackStatus.UNKNOWN,
                provider_code=result.business_code or "unknown_delivery",
                raw={"http_status": result.http_status, "body": result.raw_text},
                writeback_id=writeback_id,
            )
        if result.http_status >= 400 or result.business_code != "Success" or not ids:
            return self._receipt(
                command,
                WritebackStatus.FAILED,
                provider_code=result.business_code,
                provider_message=result.message,
                raw={"http_status": result.http_status, "data": result.data},
                writeback_id=writeback_id,
            )
        return self._receipt(
            command,
            WritebackStatus.ACCEPTED,
            provider_code=result.business_code,
            provider_message=result.message,
            raw={
                "http_status": result.http_status,
                "ids": ids,
                "provider_writeback_id": writeback_id,
            },
            writeback_id=writeback_id,
        )

    def _block_create_request(
        self,
        command: DispositionCommand,
        params: SubmitEntityActionParams,
    ) -> tuple[str, dict[str, Any]]:
        _target_type, target, _status = parse_entity_effect_target(
            params.entity_action_code,
            params.canonical_target,
        )
        devices = self._usable_devices()
        if params.entity_action_code == "block_domain":
            return BLOCK_NETWORK_PATH, {
                "name": command.action_id,
                "timeType": "forever",
                "blockIpRule": {
                    "type": "DNS",
                    "mode": "in",
                    "view": [target],
                },
                "devices": devices,
            }
        if self._block_channel() == "endpoint":
            return BLOCK_ENDPOINT_PATH, {
                "name": command.action_id,
                "timeType": "forever",
                "direction": _DEFAULT_ENDPOINT_DIRECTION,
                "plugIpList": [target],
                "devices": devices,
            }
        return BLOCK_NETWORK_PATH, {
            "name": command.action_id,
            "timeType": "forever",
            "blockIpRule": {
                "type": _DEFAULT_IP_TYPE,
                "mode": "in",
                "view": [target],
            },
            "devices": devices,
        }

    def _scan_create_request(self) -> dict[str, Any]:
        source_name = _as_text(self._block.scan_source_name) or SCAN_SOURCE_NAME_DEFAULT
        return {
            "scanType": SCAN_TYPE_DEFAULT,
            "scanMode": SCAN_MODE_DEFAULT,
            "devices": self._usable_scan_devices(),
            "source": SCAN_SOURCE,
            "sourceName": source_name,
        }

    async def _submit_scan(self, command: DispositionCommand) -> DispositionReceipt:
        body = self._scan_create_request()
        try:
            result = await self._client.request(
                "POST",
                VIRUS_SCAN_CREATE_PATH,
                json_body=body,
            )
        except (httpx.TimeoutException, httpx.TransportError):
            return self._receipt(
                command,
                WritebackStatus.UNKNOWN,
                provider_code="unknown_delivery",
                raw={"lost_response": True},
            )
        writeback_id = f"s4-wbk-{command.disposition_id}"
        task_id = _task_id_from(result.data)
        if result.http_status >= 500:
            return self._receipt(
                command,
                WritebackStatus.UNKNOWN,
                provider_code=result.business_code or "unknown_delivery",
                raw={"http_status": result.http_status, "body": result.raw_text},
                writeback_id=writeback_id,
            )
        create_ok = (
            _http_ok(result.http_status)
            and result.business_code == "Success"
            and task_id is not None
        )
        if not create_ok:
            return self._receipt(
                command,
                WritebackStatus.FAILED,
                provider_code=result.business_code,
                provider_message=result.message,
                raw={"http_status": result.http_status, "data": result.data},
                writeback_id=writeback_id,
            )
        return self._receipt(
            command,
            WritebackStatus.ACCEPTED,
            provider_code=result.business_code,
            provider_message=result.message,
            raw={
                "http_status": result.http_status,
                "taskId": task_id,
                "provider_writeback_id": writeback_id,
            },
            writeback_id=writeback_id,
        )

    def _ticket_create_request(self, command: DispositionCommand) -> dict[str, Any]:
        template = _as_text(self._block.process_template_id) or TICKET_TEMPLATE_DEFAULT
        title = _as_text(self._block.ticket_title) or TICKET_TITLE_DEFAULT
        data_type = _as_text(self._block.business_data_type) or TICKET_TYPE_DEFAULT
        return {
            "title": title,
            "processTemplateId": template,
            "nextAssigneeIds": _assignee_ids(self._block.next_assignee_ids),
            "businessData": {
                "type": data_type,
                "ids": [command.source_locator.source_object_id],
            },
        }

    async def _submit_ticket(self, command: DispositionCommand) -> DispositionReceipt:
        body = self._ticket_create_request(command)
        try:
            result = await self._client.request(
                "POST",
                TICKET_CREATE_PATH,
                json_body=body,
            )
        except (httpx.TimeoutException, httpx.TransportError):
            return self._receipt(
                command,
                WritebackStatus.UNKNOWN,
                provider_code="unknown_delivery",
                raw={"lost_response": True},
            )
        writeback_id = f"s4-wbk-{command.disposition_id}"
        order_id = _order_id_from(result.data)
        if result.http_status >= 500:
            return self._receipt(
                command,
                WritebackStatus.UNKNOWN,
                provider_code=result.business_code or "unknown_delivery",
                raw={"http_status": result.http_status, "body": result.raw_text},
                writeback_id=writeback_id,
            )
        create_ok = (
            _http_ok(result.http_status)
            and result.business_code == "Success"
            and order_id is not None
        )
        if not create_ok:
            return self._receipt(
                command,
                WritebackStatus.FAILED,
                provider_code=result.business_code,
                provider_message=result.message,
                raw={"http_status": result.http_status, "data": result.data},
                writeback_id=writeback_id,
            )
        return self._receipt(
            command,
            WritebackStatus.ACCEPTED,
            provider_code=result.business_code,
            provider_message=result.message,
            raw={
                "http_status": result.http_status,
                "orderId": order_id,
                "provider_writeback_id": writeback_id,
            },
            writeback_id=writeback_id,
        )

    async def _submit_compensation(self, command: DispositionCommand) -> DispositionReceipt:
        kind = self._compensation_kind()
        assert kind is not None
        path = _COMPENSATION_PATHS[kind]
        ids = self._usable_compensation_ids()
        body = {"ids": ids}
        try:
            result = await self._client.request("POST", path, json_body=body)
        except (httpx.TimeoutException, httpx.TransportError):
            return self._receipt(
                command,
                WritebackStatus.UNKNOWN,
                provider_code="unknown_delivery",
                raw={"lost_response": True},
            )
        writeback_id = f"s4-wbk-{command.disposition_id}"
        raw = {
            "http_status": result.http_status,
            "data": result.data,
            "successIds": _id_list_field(result.data, "successIds"),
            "failIds": _id_list_field(result.data, "failIds"),
        }
        if result.http_status >= 500:
            return self._receipt(
                command,
                WritebackStatus.UNKNOWN,
                provider_code=result.business_code or "unknown_delivery",
                raw={"http_status": result.http_status, "body": result.raw_text},
                writeback_id=writeback_id,
            )
        if result.http_status >= 400 or _explicit_business_failure(result.business_code):
            return self._receipt(
                command,
                WritebackStatus.FAILED,
                provider_code=result.business_code,
                provider_message=result.message,
                raw=raw,
                writeback_id=writeback_id,
            )
        if compensation_is_partial(business_code=result.business_code, data=result.data):
            return self._receipt(
                command,
                WritebackStatus.PARTIAL,
                provider_code=result.business_code,
                provider_message=result.message,
                raw=raw,
                writeback_id=writeback_id,
            )
        if not _http_ok(result.http_status) or result.business_code != "Success":
            return self._receipt(
                command,
                WritebackStatus.FAILED,
                provider_code=result.business_code,
                provider_message=result.message,
                raw=raw,
                writeback_id=writeback_id,
            )
        return self._receipt(
            command,
            WritebackStatus.ACCEPTED,
            provider_code=result.business_code,
            provider_message=result.message,
            raw=raw,
            writeback_id=writeback_id,
        )

    async def confirm_readback(self, command: DispositionCommand) -> DispositionReceipt | None:
        snapshot = self._writes.get(command.disposition_id)
        if snapshot is None:
            return None
        object_id = command.source_locator.source_object_id
        try:
            result = await self._client.request(
                "POST",
                DEALSTATUS_LIST_PATH,
                json_body={"ids": [object_id]},
            )
        except (httpx.TimeoutException, httpx.TransportError):
            return None

        list_status = _list_status_for(result.data, object_id)
        if not dealstatus_readback_would_confirm(
            write_code=snapshot.write_code,
            succeeded_num=snapshot.succeeded_num,
            total=snapshot.total,
            list_deal_status=list_status,
            target=snapshot.target,
            used_incidents_list=snapshot.used_incidents_list,
        ):
            return None
        now = datetime.now(UTC)
        return sanitize_disposition_receipt(
            DispositionReceipt(
                writeback_id=f"s4-wbk-{command.disposition_id}",
                sequence=2,
                disposition_id=command.disposition_id,
                action_id=command.action_id,
                source_record_id=object_id,
                status=WritebackStatus.CONFIRMED,
                confirmation_evidence=ConfirmationEvidence.READBACK_VERIFIED,
                provider_record_id=object_id,
                provider_code=result.business_code,
                provider_message=result.message,
                submitted_at=now,
                confirmed_at=now,
                observed_at=now,
                raw_result=sanitize_raw_result(
                    {
                        "http_status": result.http_status,
                        "dealStatus": list_status,
                        "mapped": map_inbound_b(list_status).value,
                    }
                ),
                simulated=False,
            )
        )

    async def read_entity_effect_completion(
        self,
        command: DispositionCommand,
        receipt: DispositionReceipt,
    ) -> EntityEffectCompletion | None:
        if command.intent_kind is not DispositionIntentKind.ENTITY_ACTION_SUBMIT:
            return None
        if receipt.status is not WritebackStatus.ACCEPTED:
            return None
        params = command.operation_params
        if not isinstance(params, SubmitEntityActionParams):
            return None
        if params.entity_action_code == TICKET_ACTION:
            return await self._ticket_effect_completion(command, receipt, params)
        if params.entity_action_code == SCAN_ACTION:
            return await self._scan_effect_completion(command, receipt, params)
        if params.entity_action_code not in _BLOCK_ACTIONS:
            return None
        try:
            target_type, target, applied_status = parse_entity_effect_target(
                params.entity_action_code,
                params.canonical_target,
            )
        except ValueError:
            return None
        ids = receipt.raw_result.get("ids")
        rule_ids = [str(item) for item in ids] if isinstance(ids, list) else []
        if not rule_ids:
            return None
        try:
            result = await self._client.request(
                "POST",
                BLOCK_LIST_PATH,
                json_body={
                    "page": 1,
                    "pageSize": BLOCK_LIST_PAGE_SIZE,
                    "ids": rule_ids,
                },
            )
        except (httpx.TimeoutException, httpx.TransportError):
            return None
        items = _block_items(result.data)
        status: str | None = None
        record_id = rule_ids[0]
        for item in items:
            item_id = str(item.get("id") or "")
            if item_id in rule_ids or len(items) == 1:
                raw_status = item.get("status")
                status = str(raw_status) if raw_status is not None else None
                if item_id:
                    record_id = item_id
                break
        provider_writeback_id = receipt.raw_result.get("provider_writeback_id")
        if not isinstance(provider_writeback_id, str) or not provider_writeback_id:
            provider_writeback_id = receipt.writeback_id
        verified = block_status_would_verify(status)
        if status == BLOCK_IN_DEAL_STATUS:
            provider_code = "effect_not_applied"
        elif verified:
            provider_code = result.business_code
        else:
            provider_code = status or "block_effect_unverified"
        return EntityEffectCompletion(
            verified=verified,
            disposition_id=command.disposition_id,
            writeback_id=receipt.writeback_id,
            provider_writeback_id=provider_writeback_id,
            action_id=command.action_id,
            entity_action_code=params.entity_action_code,
            canonical_target=params.canonical_target,
            target_type=target_type,
            target=target,
            applied_status=applied_status,
            provider_record_id=record_id,
            observed_version=1,
            provider_code=provider_code,
            provider_message=result.message,
        )

    async def _scan_effect_completion(
        self,
        command: DispositionCommand,
        receipt: DispositionReceipt,
        params: SubmitEntityActionParams,
    ) -> EntityEffectCompletion | None:
        try:
            target_type, target, applied_status = parse_entity_effect_target(
                params.entity_action_code,
                params.canonical_target,
            )
        except ValueError:
            return None
        task_id = _as_text(receipt.raw_result.get("taskId"))
        if task_id is None:
            return None
        try:
            result = await self._client.request(
                "GET",
                VIRUS_SCAN_STATUS_PATH,
                path_params={"taskId": task_id},
            )
        except (httpx.TimeoutException, httpx.TransportError):
            return None
        if not _http_ok(result.http_status) or _explicit_business_failure(result.business_code):
            return None
        data = result.data if isinstance(result.data, dict) else None
        status = _as_text(data.get("status")) if data is not None else None
        if status is None:
            return None
        items = _block_items(data)
        provider_writeback_id = receipt.raw_result.get("provider_writeback_id")
        if not isinstance(provider_writeback_id, str) or not provider_writeback_id:
            provider_writeback_id = receipt.writeback_id
        verified = scan_task_would_verify(status, items)
        if status in _SCAN_PENDING_STATUS:
            provider_code = "effect_not_applied"
        elif verified:
            provider_code = result.business_code or status
        elif status in _SCAN_PARTIAL_STATUS or _host_scan_failed(items):
            provider_code = status
        elif status in _SCAN_FAILED_STATUS:
            provider_code = status
        else:
            provider_code = "effect_not_applied"
        return EntityEffectCompletion(
            verified=verified,
            disposition_id=command.disposition_id,
            writeback_id=receipt.writeback_id,
            provider_writeback_id=provider_writeback_id,
            action_id=command.action_id,
            entity_action_code=params.entity_action_code,
            canonical_target=params.canonical_target,
            target_type=target_type,
            target=target,
            applied_status=applied_status,
            provider_record_id=task_id,
            observed_version=1,
            provider_code=provider_code,
            provider_message=result.message,
        )

    async def _ticket_effect_completion(
        self,
        command: DispositionCommand,
        receipt: DispositionReceipt,
        params: SubmitEntityActionParams,
    ) -> EntityEffectCompletion | None:
        parsed = _ticket_target(params.canonical_target)
        if parsed is None:
            return None
        target_type, target = parsed
        order_id = receipt.raw_result.get("orderId")
        record_id = _as_text(order_id)
        if record_id is None:
            return None
        list_message: str | None = None
        listed_ok = False
        try:
            listed = await self._client.request(
                "POST",
                TICKET_LIST_PATH,
                json_body={"page": 1, "pageSize": TICKET_LIST_PAGE_SIZE},
            )
            list_message = listed.message
            listed_ok = (
                _http_ok(listed.http_status)
                and listed.business_code == "Success"
                and _ticket_list_contains(listed.data, record_id)
            )
        except (httpx.TimeoutException, httpx.TransportError):
            listed_ok = False
        provider_writeback_id = receipt.raw_result.get("provider_writeback_id")
        if not isinstance(provider_writeback_id, str) or not provider_writeback_id:
            provider_writeback_id = receipt.writeback_id
        return EntityEffectCompletion(
            verified=listed_ok,
            disposition_id=command.disposition_id,
            writeback_id=receipt.writeback_id,
            provider_writeback_id=provider_writeback_id,
            action_id=command.action_id,
            entity_action_code=params.entity_action_code,
            canonical_target=params.canonical_target,
            target_type=target_type,
            target=target,
            applied_status=TICKET_APPLIED_STATUS,
            provider_record_id=record_id,
            observed_version=1,
            provider_code=receipt.provider_code or "Success",
            provider_message=list_message or receipt.provider_message,
        )

    async def health_check(self) -> ConnectorStatus:
        """No extra vendor URI; write/readback are the only probes this layer has."""
        return ConnectorStatus.UNKNOWN

    async def observe_verification(
        self,
        tool_name: str,
        params: dict[str, Any],
    ) -> dict[str, Any] | None:
        from app.adapters.sangfor.verify_observation import observe_sangfor_verification

        return await observe_sangfor_verification(tool_name, params, client=self._client)

    def _receipt(
        self,
        command: DispositionCommand,
        status: WritebackStatus,
        *,
        provider_code: str | None = None,
        provider_message: str | None = None,
        raw: dict[str, Any] | None = None,
        writeback_id: str | None = None,
    ) -> DispositionReceipt:
        now = datetime.now(UTC)
        return sanitize_disposition_receipt(
            DispositionReceipt(
                writeback_id=writeback_id or f"s4-wbk-{command.disposition_id}",
                sequence=1,
                disposition_id=command.disposition_id,
                action_id=command.action_id,
                source_record_id=command.source_locator.source_object_id,
                status=status,
                provider_record_id=command.source_locator.source_object_id,
                provider_code=provider_code,
                provider_message=provider_message,
                submitted_at=now,
                observed_at=now,
                raw_result=sanitize_raw_result(raw or {}),
                simulated=False,
            )
        )
