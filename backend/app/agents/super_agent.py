"""SuperAgent — LangGraph-driven investigation orchestrator (ISSUE-054).

SuperAgent is the top-level orchestrator that wraps the LangGraph investigation
workflow. It manages:
- Distributed lease acquisition/renewal/release via ``EventLease``
- Graph construction via ``build_investigation_graph``
- Checkpoint persistence via ``RedisCheckpointer``
- ReAct engine integration when ``REACT_ENABLED=true``
- Degraded-flag surfacing and error handling

Design authority:
- ``agent_name = "super_agent"`` (README §4.4 agent #1)
- Input: ``SuperAgentInput``, Output: ``InvestigationResult``
- State machine: ``SuperAgentStatus`` (IDLE → PLANNING → EXECUTING →
  REFLECTING → REPLANNING → FINISHED / FAILED)
- Never writes back to XDR — that is ISSUE-062 territory
- Analysis-only gate: ``ORCHESTRATION_MODE=analysis_only`` preserves
  ``AnalysisOnlyPipeline`` path; ``graph`` mode (default) uses this class
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.orchestration.workflow_graph import CompiledInvestigationGraph

from app.agents.base import BaseAgent
from app.core.config import Settings, get_settings
from app.core.errors import (
    ConfigurationError,
    DependencyUnavailableError,
    ShadowTraceError,
)
from app.models.agent_io import InvestigationResult, SuperAgentInput
from app.models.enums import (
    DispositionPolicy,
    EventStatus,
    FinalVerdict,
    SuperAgentStatus,
    WritebackReadiness,
)
from app.orchestration.checkpointer import RedisCheckpointer, build_checkpointer
from app.orchestration.graph_state import InvestigationState
from app.orchestration.lease import DEFAULT_LEASE_TTL_SECONDS, RENEW_INTERVAL_SECONDS, EventLease

# Lazy imports to avoid circular dependency:
#   agents.__init__ → super_agent → workflow_graph → agents.planner_agent → agents.__init__
# These are resolved inside methods that need them.
#   CompiledInvestigationGraph = TypeAlias used in annotations (quoted)
#   build_investigation_graph = called in _build_graph()
#   invoke_investigation_graph = called in investigate()

logger = logging.getLogger(__name__)

_SUPER_AGENT_OPERATOR = "SuperAgent"


class _Sentinel:
    """Unique sentinel for unset optional values."""


_UNSET = _Sentinel()


async def _noop_renew(event_id: str) -> bool:
    """No-op renew when lease is not active (e.g. memory-fallback mode)."""
    return True


class SuperAgent(BaseAgent[SuperAgentInput, InvestigationResult]):
    """Top-level investigation orchestrator.

    Does NOT replace ``build_investigation_graph`` — it wraps the graph with
    lease lifecycle, checkpoint persistence, and error handling.
    """

    agent_name = "super_agent"

    def __init__(
        self,
        *,
        # ── Graph services (required) ──────────────────────────────
        state_machine: Any,
        event_service: Any,
        workflow_runtime: Any,
        degraded_flags: Any,
        context_store: Any,
        # ── Graph agents (required) ────────────────────────────────
        triage_agent: Any,
        planner_agent: Any,
        evidence_agent: Any,
        risk_agent: Any,
        report_agent: Any,
        rag_agent: Any | None = None,
        # ── Lease + checkpoint infrastructure ──────────────────────
        redis_client: Any = None,
        checkpointer: RedisCheckpointer | None = None,
        # ── ReAct integration ──────────────────────────────────────
        react_executor: Any = None,
        # ── Config ─────────────────────────────────────────────────
        settings: Settings | None = None,
        session_factory: Any = None,
        **base_kwargs: Any,
    ) -> None:
        super().__init__(**base_kwargs)

        # Services
        self._state_machine = state_machine
        self._event_service = event_service
        self._workflow_runtime = workflow_runtime
        self._degraded_flags = degraded_flags
        self._ctx_store = context_store

        # Agents
        self._triage_agent = triage_agent
        self._planner_agent = planner_agent
        self._evidence_agent = evidence_agent
        self._risk_agent = risk_agent
        self._report_agent = report_agent
        self._rag_agent = rag_agent

        # Infrastructure
        self._redis_client = redis_client
        self._checkpointer: RedisCheckpointer | None = checkpointer
        self._session_factory = session_factory

        # ReAct (ISSUE-053)
        self._react_executor = react_executor

        # Config
        self._settings = settings or get_settings()

        # Lazy-initialized
        self._lease: EventLease | None = None
        self._status: SuperAgentStatus = SuperAgentStatus.IDLE

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    @property
    def status(self) -> SuperAgentStatus:
        return self._status

    async def investigate(self, event_id: str) -> InvestigationResult:
        """Run the full investigation graph for *event_id*.

        This is the canonical entry point called by the API layer. It manages
        the lease lifecycle, graph construction, execution, and error handling.
        """
        self._status = SuperAgentStatus.IDLE

        # ── Gate: analysis_only mode rejects graph orchestration ──
        if self._settings.orchestration_mode == "analysis_only":
            raise ConfigurationError(
                "SuperAgent.investigate requires ORCHESTRATION_MODE=graph, got analysis_only",
                error_code="configuration_error",
                details={
                    "orchestration_mode": self._settings.orchestration_mode,
                    "event_id": event_id,
                },
            )

        # ── Gate: REACT_ENABLED but no ReAct executor ──
        if self._settings.react_enabled and self._react_executor is None:
            raise ConfigurationError(
                "REACT_ENABLED=true but no ReadOnlyReActExecutor is registered "
                "(ISSUE-053). Set REACT_ENABLED=false or deploy ISSUE-053.",
                error_code="configuration_error",
                details={"react_enabled": True, "event_id": event_id},
            )

        # ── 1. Acquire distributed lease ───────────────────────────
        lease = await self._get_lease()
        if not await lease.acquire(event_id):
            raise ShadowTraceError(
                f"Investigation already in progress for event {event_id}",
                error_code="investigation_in_progress",
                details={"event_id": event_id},
            )

        self._status = SuperAgentStatus.PLANNING
        logger.info(
            "SuperAgent investigation started event=%s owner=%s",
            event_id,
            lease.owner_id,
        )

        renew_task: asyncio.Task[None] | None = None
        try:
            # ── 2. Build checkpointer ────────────────────────────
            checkpointer = await self._get_checkpointer()

            # ── 3. Build investigation graph ─────────────────────
            graph = self._build_graph(checkpointer)

            # ── 4. Initialize state ──────────────────────────────
            initial_state = await self._build_initial_state(event_id)

            # ── 5. Start background lease renewal ────────────────
            renew_task = asyncio.create_task(
                self._renew_loop(event_id, lease), name=f"lease-renew-{event_id}"
            )

            # ── 6. Invoke graph ──────────────────────────────────
            self._status = SuperAgentStatus.EXECUTING
            from app.orchestration.workflow_graph import invoke_investigation_graph

            config = {"configurable": {"thread_id": event_id}}
            final_state = await invoke_investigation_graph(graph, initial_state, config)

            # ── 7. Build result ──────────────────────────────────
            self._status = SuperAgentStatus.FINISHED
            result = await self._build_result(event_id, final_state)

            logger.info(
                "SuperAgent investigation complete event=%s status=%s verdict=%s",
                event_id,
                result.final_status.value,
                result.final_verdict.value,
            )
            return result

        except asyncio.CancelledError:
            logger.warning("SuperAgent cancelled for event=%s", event_id)
            self._status = SuperAgentStatus.FAILED
            raise

        except ShadowTraceError:
            self._status = SuperAgentStatus.FAILED
            raise

        except Exception as exc:
            self._status = SuperAgentStatus.FAILED
            logger.exception(
                "SuperAgent investigation failed event=%s: %s",
                event_id,
                exc,
            )
            try:
                await self._state_machine.transition(
                    event_id,
                    EventStatus.FAILED,
                    operator=_SUPER_AGENT_OPERATOR,
                    reason=f"super_agent:error:{type(exc).__name__}:{exc!s}"[:500],
                )
            except Exception:
                logger.exception(
                    "Failed to mark event=%s as FAILED after SuperAgent error",
                    event_id,
                )
            raise

        finally:
            # ── 8. Cleanup ───────────────────────────────────────
            if renew_task is not None:
                renew_task.cancel()
                try:
                    await renew_task
                except asyncio.CancelledError:
                    pass
            await lease.release(event_id)
            logger.debug("SuperAgent cleanup complete event=%s", event_id)

    # ------------------------------------------------------------------ #
    # BaseAgent contract
    # ------------------------------------------------------------------ #

    async def _run(self, input: SuperAgentInput) -> InvestigationResult:
        """Delegates to ``investigate`` — the BaseAgent template wraps budget,
        hooks, guardrails, and tracing around it.
        """
        return await self.investigate(input.event_id)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    async def _get_lease(self) -> EventLease:
        """Return or lazily create the EventLease from Redis."""
        if self._lease is None:
            if self._redis_client is None:
                raise DependencyUnavailableError(
                    "SuperAgent requires a Redis client for EventLease",
                    error_code="dependency_unavailable",
                    details={"dependency": "redis_client"},
                )
            self._lease = EventLease(
                self._redis_client.get_client(),
                ttl_s=DEFAULT_LEASE_TTL_SECONDS,
            )
        return self._lease

    async def _get_checkpointer(self) -> RedisCheckpointer:
        """Return or lazily build the RedisCheckpointer."""
        if self._checkpointer is None:
            if self._redis_client is None:
                raise DependencyUnavailableError(
                    "SuperAgent requires a Redis client for RedisCheckpointer",
                    error_code="dependency_unavailable",
                    details={"dependency": "redis_client"},
                )
            self._checkpointer = await build_checkpointer(self._redis_client)
        return self._checkpointer

    def _build_graph(
        self,
        checkpointer: RedisCheckpointer | None,
    ) -> CompiledInvestigationGraph:
        """Construct the LangGraph investigation graph."""
        from app.orchestration.workflow_graph import build_investigation_graph

        agents: dict[str, Any] = {
            "triage_agent": self._triage_agent,
            "planner_agent": self._planner_agent,
            "evidence_agent": self._evidence_agent,
            "risk_agent": self._risk_agent,
            "report_agent": self._report_agent,
        }
        if self._rag_agent is not None:
            agents["rag_agent"] = self._rag_agent

        services: dict[str, Any] = {
            "state_machine": self._state_machine,
            "event_service": self._event_service,
            "workflow_runtime": self._workflow_runtime,
            "degraded_flags": self._degraded_flags,
            "context_store": self._ctx_store,
        }

        return build_investigation_graph(
            agents,
            services,
            checkpointer=checkpointer,
        )

    async def _build_initial_state(self, event_id: str) -> InvestigationState:
        """Hydrate the initial graph state from the event record."""
        event = await self._event_service.get_event(event_id)
        if event is None:
            raise ShadowTraceError(
                f"event {event_id} not found",
                error_code="event_not_found",
                details={"event_id": event_id},
            )

        # Transition from NEW → TRIAGING to lock the event into the graph
        if event.status is EventStatus.NEW:
            await self._state_machine.transition(
                event_id,
                EventStatus.TRIAGING,
                operator=_SUPER_AGENT_OPERATOR,
                reason="super_agent:investigation_start",
            )

        readiness = WritebackReadiness.NOT_REQUIRED
        try:
            readiness = await self._workflow_runtime.get_event_status_update_readiness(event_id)
        except Exception:
            logger.debug(
                "event_status_update_readiness lookup failed event=%s, defaulting to NOT_REQUIRED",
                event_id,
                exc_info=True,
            )

        def _to_severity_str(raw: Any) -> str:
            if raw is None:
                return "medium"
            if hasattr(raw, "value"):
                return str(raw.value)
            return str(raw)

        def _to_policy_str(raw: Any) -> str:
            if raw is None:
                return DispositionPolicy.NOT_REQUIRED.value
            if hasattr(raw, "value"):
                return str(raw.value)
            return str(raw)

        state: InvestigationState = {
            "event_id": event_id,
            "event_status": EventStatus.TRIAGING.value,
            "disposition_policy": _to_policy_str(getattr(event, "disposition_policy", None)),
            "severity": _to_severity_str(getattr(event, "severity", None)),
            "final_verdict": None,
            "confidence": 0.0,
            "need_investigation": None,
            "triage_result": None,
            "false_positive_match": None,
            "source_snapshot": None,
            "disposition_only_intent": False,
            "execution_substate": "none",
            "execution_plan": None,
            "event_status_update_readiness": readiness.value,
            "degraded_flags": [],
            "node_trace": [],
            "halted": False,
            "error": None,
            "verify_need_manual_resolution": False,
            "verify_need_writeback_recovery": False,
            "verify_need_action_replan": False,
            "include_rag": self._rag_agent is not None,
            "evidence_output": None,
            "rag_output": None,
            "risk_assessment": None,
            "report_generated": False,
            "needs_approval_wait": False,
        }
        return state

    async def _build_result(
        self,
        event_id: str,
        state: InvestigationState,
    ) -> InvestigationResult:
        """Convert final graph state into an InvestigationResult.

        The graph state is the authoritative record post-execution; the event
        service row is consulted only as a fallback.
        """
        event = await self._event_service.get_event(event_id)

        # ── Final status: state first, then event service ───────
        final_status = EventStatus.REPORTING
        if state.get("event_status"):
            try:
                final_status = EventStatus(state["event_status"])
            except ValueError:
                final_status = EventStatus.REPORTING
        elif event is not None:
            final_status = event.status

        # ── Final verdict: state first, then event service ──────
        final_verdict = FinalVerdict.NONE
        if state.get("final_verdict"):
            try:
                final_verdict = FinalVerdict(state["final_verdict"])
            except ValueError:
                final_verdict = FinalVerdict.NONE
        elif event is not None and event.final_verdict is not None:
            final_verdict = (
                FinalVerdict(event.final_verdict)
                if isinstance(event.final_verdict, str)
                else event.final_verdict
            )

        # ── Disposition policy: state first, then event service ─
        policy = DispositionPolicy.NOT_REQUIRED
        if state.get("disposition_policy"):
            try:
                policy = DispositionPolicy(state["disposition_policy"])
            except ValueError:
                policy = DispositionPolicy.NOT_REQUIRED
        elif event is not None and hasattr(event, "disposition_policy"):
            policy = event.disposition_policy

        writeback_required = policy is DispositionPolicy.REQUIRED

        return InvestigationResult(
            event_id=event_id,
            final_status=final_status,
            final_verdict=final_verdict,
            escalated=False,
            external_unsynced=False,
            report_id=None,
            writeback_required=writeback_required,
            writeback_readiness=(
                WritebackReadiness.NOT_REQUIRED
                if not writeback_required
                else WritebackReadiness.CAPABILITY_UNKNOWN
            ),
        )

    async def _renew_loop(self, event_id: str, lease: EventLease) -> None:
        """Background task that renews the lease every ``RENEW_INTERVAL_SECONDS``."""
        while True:
            await asyncio.sleep(RENEW_INTERVAL_SECONDS)
            ok = await lease.renew(event_id)
            if not ok:
                logger.error(
                    "Lease renewal failed for event=%s; investigation may be orphaned",
                    event_id,
                )
                # Continue anyway — the graph is still running and will
                # eventually release.  If the lease expired, another worker
                # could have started, which would be a split-brain situation
                # that the release Lua script prevents from compounding.


__all__ = ["SuperAgent"]
