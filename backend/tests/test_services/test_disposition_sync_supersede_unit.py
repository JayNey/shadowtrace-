"""ISSUE-219 unit tests: enqueue_command supersede lineage (no DB required).

The supersede logic lives inside ``DispositionSyncService.enqueue_command``:
before inserting a new active EVENT_STATUS_UPDATE head it must mark the
previous active head for the same ``(event_id, closure_cycle, logical_slot)``
as superseded, in the same transaction, and propagate the lineage onto the
wire payload (``supersedes_disposition_id``).  These tests drive the method
with a fake session so the behavior is verifiable without PostgreSQL.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from app.db import models as orm
from app.models.disposition import (
    DispositionCommand,
    SetEventDispositionParams,
    SourceDisposition,
    SourceObjectLocator,
    SubmitEntityActionParams,
)
from app.models.enums import (
    DispositionIntentKind,
    ExecutionOwner,
    SourceObjectKind,
)
from app.services.disposition_sync_service import DispositionSyncService


def _command(
    *,
    intent_kind: DispositionIntentKind,
    disposition_id: str = "disp-new",
    closure_cycle: int = 1,
) -> DispositionCommand:
    if intent_kind is DispositionIntentKind.EVENT_STATUS_UPDATE:
        params: Any = SetEventDispositionParams(target_disposition=SourceDisposition.CONTAINED)
        operation_code = "set_event_disposition"
    else:
        params = SubmitEntityActionParams(
            entity_action_code="block",
            canonical_target="obj-1",
        )
        operation_code = "submit_entity_action"
    return DispositionCommand(
        disposition_id=disposition_id,
        action_id="act-1",
        closure_cycle=closure_cycle,
        intent_kind=intent_kind,
        source_locator=SourceObjectLocator(
            source_product="mock_xdr",
            source_tenant_id="tenant-1",
            connector_id="conn-1",
            source_kind=SourceObjectKind.INCIDENT,
            source_object_type="incident",
            source_object_id="obj-1",
        ),
        operation_code=operation_code,
        operation_params=params,
        target_results=[],
        operator_id="op-1",
        idempotency_key="idem-1",
        source_concurrency_token=None,
        execution_owner=ExecutionOwner.XDR_MANAGED,
        parent_disposition_id=None,
        supersedes_disposition_id=None,
    )


def _prior_head(disposition_id: str = "disp-prior") -> orm.DispositionOutbox:
    return orm.DispositionOutbox(
        outbox_id="ob-prior",
        writeback_id="wbk-prior",
        disposition_id=disposition_id,
        action_id="act-0",
        event_id="evt-1",
        closure_cycle=1,
        source_record_id="src-1",
        source_locator_hash="hash",
        source_sequence=1,
        intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE.value,
        logical_slot="terminal",
        supersedes_disposition_id=None,
        superseded_by_disposition_id=None,
        idempotency_key="idem-prior",
        command_payload={"op": "set_event_disposition"},
        command_payload_sha256="sha",
    )


class _FakeResult:
    def one(self) -> tuple[int]:
        return (1,)


class _FakeSession:
    """Records enqueue_command interactions; only prior-head query returns a row."""

    def __init__(self, source_row: Any, prior_head: orm.DispositionOutbox | None) -> None:
        self.source_row = source_row
        self.prior_head = prior_head
        self.added: list[Any] = []
        self.flush_count = 0
        self.scalar_calls = 0

    async def get(
        self,
        model: Any,
        pk: Any,
        *,
        with_for_update: bool = False,
    ) -> Any:
        return self.source_row

    async def scalar(self, stmt: Any) -> Any:
        # First scalar is the prior active-head lookup; journal lookups (later)
        # return nothing.
        self.scalar_calls += 1
        if self.scalar_calls == 1:
            return self.prior_head
        return None

    async def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> _FakeResult:
        return _FakeResult()

    async def flush(self) -> None:
        self.flush_count += 1

    def add(self, obj: Any) -> None:
        self.added.append(obj)


def _service() -> DispositionSyncService:
    return DispositionSyncService(
        session_factory=AsyncMock(),  # type: ignore[arg-type]
        context_store=AsyncMock(),  # type: ignore[arg-type]
        adapter_registry=AsyncMock(),  # type: ignore[arg-type]
        outbound_guard=AsyncMock(),  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_enqueue_supersedes_prior_event_status_update_head() -> None:
    """ISSUE-219: a new EVENT_STATUS_UPDATE head marks the prior active head
    of the same (event_id, closure_cycle, logical_slot) as superseded."""
    source_row = SimpleNamespace(next_outbox_sequence=7)
    prior = _prior_head()
    session = _FakeSession(source_row, prior)
    service = _service()

    record = await service.enqueue_command(
        session,
        command=_command(intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE),
        event_id="evt-1",
        source_record_id="src-1",
        logical_slot="terminal",
    )

    # Old head lineage: superseded by the new head's disposition_id.
    assert prior.superseded_by_disposition_id == record.disposition_id
    # New head lineage + wire payload carry the supersede contract.
    assert record.supersedes_disposition_id == "disp-prior"
    added_outbox = session.added[0]
    assert added_outbox.supersedes_disposition_id == "disp-prior"
    assert added_outbox.command_payload["supersedes_disposition_id"] == "disp-prior"
    # Prior-head lookup ran exactly once (the later context-journal lookup is
    # the only other scalar call in enqueue_command).
    assert session.scalar_calls == 2


@pytest.mark.asyncio
async def test_enqueue_without_prior_head_keeps_command_unchanged() -> None:
    """ISSUE-219: with no prior active head nothing is superseded."""
    source_row = SimpleNamespace(next_outbox_sequence=1)
    session = _FakeSession(source_row, prior_head=None)
    service = _service()

    record = await service.enqueue_command(
        session,
        command=_command(intent_kind=DispositionIntentKind.EVENT_STATUS_UPDATE),
        event_id="evt-1",
        source_record_id="src-1",
        logical_slot="terminal",
    )

    assert record.supersedes_disposition_id is None
    added_outbox = session.added[0]
    assert added_outbox.supersedes_disposition_id is None
    assert added_outbox.command_payload.get("supersedes_disposition_id") is None


@pytest.mark.asyncio
async def test_enqueue_entity_action_submit_never_supersedes() -> None:
    """ISSUE-219: supersede is EVENT_STATUS_UPDATE-only; other intents are
    untouched and never query/supersede an active head."""
    source_row = SimpleNamespace(next_outbox_sequence=1)
    # A prior EVENT_STATUS_UPDATE head exists, but an ENTITY_ACTION_SUBMIT
    # command must not supersede it.
    session = _FakeSession(source_row, prior_head=_prior_head())
    service = _service()

    record = await service.enqueue_command(
        session,
        command=_command(intent_kind=DispositionIntentKind.ENTITY_ACTION_SUBMIT),
        event_id="evt-1",
        source_record_id="src-1",
        logical_slot="terminal",
    )

    assert record.supersedes_disposition_id is None
    added_outbox = session.added[0]
    assert added_outbox.supersedes_disposition_id is None
    # The prior head must not be marked superseded by a non-terminal intent.
    assert session.prior_head.superseded_by_disposition_id is None
