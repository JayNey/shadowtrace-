"""ISSUE-274 unit tests: operator-retry lookup decisions (no DB required)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from app.adapters.disposition.base import DispositionAdapterCapabilities
from app.models.disposition import (
    DispositionCommand,
    DispositionReceipt,
    SourceObjectLocator,
    SubmitEntityActionParams,
)
from app.models.enums import (
    ConfirmationEvidence,
    DispositionIntentKind,
    ExecutionOwner,
    OutboxDeliveryStatus,
    SourceObjectKind,
    WritebackStatus,
)
from app.services.disposition_sync_service import (
    DispositionSyncService,
    _OperatorRetryAction,
)


def _command_payload(*, idempotency_key: str = "idem-1") -> dict[str, Any]:
    command = DispositionCommand(
        disposition_id="disp-1",
        action_id="act-1",
        closure_cycle=1,
        intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT,
        source_locator=SourceObjectLocator(
            source_product="mock_xdr",
            source_tenant_id="tenant-1",
            connector_id="conn-1",
            source_kind=SourceObjectKind.INCIDENT,
            source_object_type="incident",
            source_object_id="obj-1",
        ),
        operation_code="submit_entity_action",
        operation_params=SubmitEntityActionParams(
            entity_action_code="block",
            canonical_target="obj-1",
        ),
        target_results=[],
        operator_id="op-1",
        idempotency_key=idempotency_key,
        source_concurrency_token=None,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        parent_disposition_id=None,
        supersedes_disposition_id=None,
    )
    return command.model_dump(mode="json")


def _outbox(*, idempotency_key: str = "idem-1") -> Any:
    return SimpleNamespace(
        writeback_id="wbk-1",
        command_payload=_command_payload(idempotency_key=idempotency_key),
        delivery_status=OutboxDeliveryStatus.PAUSED.value,
        latest_writeback_status=WritebackStatus.FAILED.value,
    )


def _service(adapter: Any) -> DispositionSyncService:
    return DispositionSyncService(
        session_factory=AsyncMock(),  # type: ignore[arg-type]
        context_store=AsyncMock(),  # type: ignore[arg-type]
        adapter_registry=SimpleNamespace(get=lambda _name: adapter),  # type: ignore[arg-type]
        outbound_guard=AsyncMock(),  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_evaluate_never_accepted_requires_idempotency_lookup() -> None:
    class _StatusOnlyAdapter:
        name = "status_only"

        def capabilities(self) -> DispositionAdapterCapabilities:
            return DispositionAdapterCapabilities(
                supports_idempotency=True,
                supports_status_query=True,
                supports_lookup_by_idempotency=False,
            )

        def allows_safe_retry(self) -> bool:
            return False

        async def lookup_submission(self, *args: Any, **kwargs: Any) -> None:
            raise AssertionError("idempotency lookup must not run")

        async def get_status(self, *args: Any, **kwargs: Any) -> None:
            return None

    session = SimpleNamespace(scalar=AsyncMock(return_value=None))
    decision = await _service(_StatusOnlyAdapter())._evaluate_operator_retry_lookup(
        session,
        _outbox(),
    )
    assert decision.action is _OperatorRetryAction.BLOCKED
    assert "idempotency lookup" in decision.reason


@pytest.mark.asyncio
async def test_evaluate_idempotency_none_re_enqueues_when_safe_retry() -> None:
    class _SafeAdapter:
        name = "safe"

        def capabilities(self) -> DispositionAdapterCapabilities:
            return DispositionAdapterCapabilities(
                supports_idempotency=True,
                supports_status_query=True,
                supports_lookup_by_idempotency=True,
            )

        def allows_safe_retry(self) -> bool:
            return True

        async def lookup_submission(self, *args: Any, **kwargs: Any) -> None:
            return None

    session = SimpleNamespace(scalar=AsyncMock(return_value=None))
    decision = await _service(_SafeAdapter())._evaluate_operator_retry_lookup(
        session,
        _outbox(),
    )
    assert decision.action is _OperatorRetryAction.RE_ENQUEUE
    assert decision.lookup_never_accepted is True
    assert decision.adapter_allows_safe_retry is True


@pytest.mark.asyncio
async def test_evaluate_terminal_receipt_reconciles() -> None:
    receipt = DispositionReceipt(
        writeback_id="wbk-1",
        sequence=2,
        disposition_id="disp-1",
        action_id="act-1",
        source_record_id="src-1",
        status=WritebackStatus.CONFIRMED,
        confirmation_evidence=ConfirmationEvidence.READBACK_VERIFIED,
    )

    class _FoundAdapter:
        name = "found"

        def capabilities(self) -> DispositionAdapterCapabilities:
            return DispositionAdapterCapabilities(
                supports_idempotency=True,
                supports_lookup_by_idempotency=True,
            )

        def allows_safe_retry(self) -> bool:
            return True

        async def lookup_submission(self, *args: Any, **kwargs: Any) -> DispositionReceipt:
            return receipt

    decision = await _service(_FoundAdapter())._evaluate_operator_retry_lookup(
        AsyncMock(),
        _outbox(),
    )
    assert decision.action is _OperatorRetryAction.RECONCILE_TERMINAL
    assert decision.target_status is WritebackStatus.CONFIRMED
