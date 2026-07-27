"""Tests for FalsePositiveMatcher, FPMatchResult, and FalsePositiveMatcherHook (ISSUE-078)."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

from app.models.entities import (
    AccountEntity,
    DomainEntity,
    EntitySet,
    FileEntity,
    HostEntity,
    IPEntity,
    ProcessEntity,
)
from app.models.knowledge import RetrievedChunk
from app.models.workflow import FP_HIGH_THRESHOLD, FP_LOW_THRESHOLD
from app.services.case_kb_service import CaseKBService
from app.services.false_positive_matcher import (
    FalsePositiveMatcher,
    FalsePositiveMatcherHook,
    FPMatchResult,
    _build_alert_text,
    _entities_from_triage_result,
    _no_match,
    _recommendation_for,
)

# --------------------------------------------------------------------------- #
# Unit: _build_alert_text
# --------------------------------------------------------------------------- #


def test_build_alert_text_full_snapshot() -> None:
    snapshot: dict[str, Any] = {
        "alert_type": "account_anomaly",
        "title": "Bulk login from ops account",
        "description": "Multiple logins detected from ops account during change window",
        "scenario": "account_anomaly_fp",
        "signature": "ops_change_window_bulk_login",
        "severity": "low",
    }
    text = _build_alert_text(snapshot, EntitySet())
    assert "alert_type=account_anomaly" in text
    assert "Bulk login from ops account" in text
    assert "scenario=account_anomaly_fp" in text
    assert "signature=ops_change_window_bulk_login" in text
    assert "severity=low" in text


def test_build_alert_text_with_entities() -> None:
    snapshot: dict[str, Any] = {"alert_type": "data_exfiltration"}
    entities = EntitySet(
        accounts=[AccountEntity(entity_id="a-1", username="ops-bot")],
        hosts=[HostEntity(entity_id="h-1", hostname="PC-OPS-JUMP-01")],
        ips=[IPEntity(entity_id="ip-1", address="10.0.0.1", scope="internal")],
        processes=[ProcessEntity(entity_id="p-1", name="ssh")],
    )
    text = _build_alert_text(snapshot, entities)
    assert "account=ops-bot" in text
    assert "host=PC-OPS-JUMP-01" in text
    assert "ip=10.0.0.1 scope=internal" in text
    assert "process=ssh" in text


def test_build_alert_text_with_raw_alert_snapshot_fallback() -> None:
    snapshot: dict[str, Any] = {
        "alert_type": "suspicious_domain",
        "raw_alert_snapshot": {
            "title": "Raw title from file",
            "description": "Extra description not in top-level",
        },
    }
    text = _build_alert_text(snapshot, EntitySet())
    assert "Raw title from file" in text
    assert "Extra description not in top-level" in text


def test_build_alert_text_empty_snapshot() -> None:
    text = _build_alert_text({}, EntitySet())
    assert text == "{}"


def test_build_alert_text_with_domains_and_files() -> None:
    entities = EntitySet(
        domains=[DomainEntity(entity_id="d-1", fqdn="evil.example.com")],
        files=[FileEntity(entity_id="f-1", name="malware.exe", path="/tmp/malware.exe")],
    )
    text = _build_alert_text({}, entities)
    assert "domain=evil.example.com" in text
    assert "file=malware.exe" in text


# --------------------------------------------------------------------------- #
# Unit: _recommendation_for
# --------------------------------------------------------------------------- #


def test_recommendation_close_as_fp() -> None:
    assert _recommendation_for(FP_HIGH_THRESHOLD) == "close_as_fp"
    assert _recommendation_for(0.95) == "close_as_fp"
    assert _recommendation_for(1.0) == "close_as_fp"


def test_recommendation_investigate_with_flag() -> None:
    assert _recommendation_for(FP_LOW_THRESHOLD) == "investigate_with_flag"
    assert _recommendation_for(0.8) == "investigate_with_flag"
    assert _recommendation_for(0.89) == "investigate_with_flag"


def test_recommendation_no_match() -> None:
    assert _recommendation_for(0.0) == "no_match"
    assert _recommendation_for(0.5) == "no_match"
    assert _recommendation_for(FP_LOW_THRESHOLD - 0.01) == "no_match"


# --------------------------------------------------------------------------- #
# Unit: _no_match
# --------------------------------------------------------------------------- #


def test_no_match_result() -> None:
    result = _no_match()
    assert result.matched is False
    assert result.max_score == 0.0
    assert result.recommendation == "no_match"
    assert result.matched_case_id is None
    assert result.matched_pattern is None


# --------------------------------------------------------------------------- #
# Unit: FPMatchResult model
# --------------------------------------------------------------------------- #


def test_fp_match_result_defaults() -> None:
    result = FPMatchResult(matched=True, max_score=0.95, recommendation="close_as_fp")
    assert result.matched is True
    assert result.max_score == 0.95
    assert result.matched_case_id is None
    assert result.matched_pattern is None
    assert result.recommendation == "close_as_fp"


def test_fp_match_result_full() -> None:
    result = FPMatchResult(
        matched=True,
        max_score=0.99,
        matched_case_id="case-00000001",
        matched_pattern="运维账号在变更窗口内批量登录跳板机",
        recommendation="close_as_fp",
    )
    assert result.model_dump() == {
        "matched": True,
        "max_score": 0.99,
        "matched_case_id": "case-00000001",
        "matched_pattern": "运维账号在变更窗口内批量登录跳板机",
        "recommendation": "close_as_fp",
    }


def test_fp_match_result_extra_forbidden() -> None:
    with pytest.raises(ValidationError):
        FPMatchResult(
            matched=False,
            max_score=0.0,
            recommendation="no_match",
            extra_field="should not be here",  # type: ignore[call-arg]
        )


# --------------------------------------------------------------------------- #
# FalsePositiveMatcher tests with mocked CaseKBService
# --------------------------------------------------------------------------- #


@pytest.fixture
def mock_case_kb() -> Any:  # MagicMock for CaseKBService
    """Return a CaseKBService mock whose search_fp_cases is an AsyncMock."""
    kb: Any = MagicMock(spec=CaseKBService)
    kb.search_fp_cases = AsyncMock()
    return kb


@pytest.fixture
def matcher(mock_case_kb: Any) -> FalsePositiveMatcher:
    return FalsePositiveMatcher(case_kb_service=mock_case_kb)


def _chunk(case_id: str, score: float, pattern: str = "") -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=f"chk-{case_id[-8:]}",
        kb_name="fp_case_kb",
        content=f"FP case {case_id}",
        metadata={
            "case_id": case_id,
            "pattern_summary": pattern or f"Pattern for {case_id}",
        },
        score=score,
        retrieval_method="hybrid",
    )


# --- Match: high score → close_as_fp ---


@pytest.mark.asyncio
async def test_matcher_high_score_close_as_fp(
    matcher: FalsePositiveMatcher, mock_case_kb: Any
) -> None:
    mock_case_kb.search_fp_cases.return_value = [_chunk("case-00000001", 0.95, "运维账号批量登录")]
    snapshot: dict[str, Any] = {
        "alert_type": "account_anomaly",
        "title": "Bulk login from ops account",
        "scenario": "account_anomaly_fp",
    }
    result = await matcher.match(snapshot, EntitySet())

    assert result.matched is True
    assert result.max_score == 0.95
    assert result.matched_case_id == "case-00000001"
    assert result.matched_pattern == "运维账号批量登录"
    assert result.recommendation == "close_as_fp"


@pytest.mark.asyncio
async def test_matcher_exact_threshold_close_as_fp(
    matcher: FalsePositiveMatcher, mock_case_kb: Any
) -> None:
    mock_case_kb.search_fp_cases.return_value = [_chunk("case-00000001", FP_HIGH_THRESHOLD)]
    result = await matcher.match({"alert_type": "test"}, EntitySet())
    assert result.recommendation == "close_as_fp"
    assert result.matched is True


# --- Match: medium score → investigate_with_flag ---


@pytest.mark.asyncio
async def test_matcher_medium_score_investigate_with_flag(
    matcher: FalsePositiveMatcher, mock_case_kb: Any
) -> None:
    mock_case_kb.search_fp_cases.return_value = [_chunk("case-00000002", 0.78, "夜间备份流量")]
    snapshot: dict[str, Any] = {"alert_type": "data_exfiltration", "title": "Night backup traffic"}
    result = await matcher.match(snapshot, EntitySet())

    assert result.matched is True
    assert result.max_score == 0.78
    assert result.recommendation == "investigate_with_flag"
    assert result.matched_case_id == "case-00000002"


@pytest.mark.asyncio
async def test_matcher_low_threshold_investigate(
    matcher: FalsePositiveMatcher, mock_case_kb: Any
) -> None:
    mock_case_kb.search_fp_cases.return_value = [_chunk("case-00000003", FP_LOW_THRESHOLD)]
    result = await matcher.match({"alert_type": "test"}, EntitySet())
    assert result.recommendation == "investigate_with_flag"


# --- Match: low score → no_match ---


@pytest.mark.asyncio
async def test_matcher_low_score_no_match(matcher: FalsePositiveMatcher, mock_case_kb: Any) -> None:
    mock_case_kb.search_fp_cases.return_value = [_chunk("case-00000003", 0.5)]
    result = await matcher.match({"alert_type": "test"}, EntitySet())

    assert result.matched is False
    assert result.max_score == 0.5
    assert result.recommendation == "no_match"
    assert result.matched_case_id is None
    assert result.matched_pattern is None


# --- Match: empty results → no_match ---


@pytest.mark.asyncio
async def test_matcher_empty_results_no_match(
    matcher: FalsePositiveMatcher, mock_case_kb: Any
) -> None:
    mock_case_kb.search_fp_cases.return_value = []
    result = await matcher.match({"alert_type": "malicious_process"}, EntitySet())

    assert result.matched is False
    assert result.max_score == 0.0
    assert result.recommendation == "no_match"


# --- Match: KB exception → no_match (degradation) ---


@pytest.mark.asyncio
async def test_matcher_kb_exception_returns_no_match(
    matcher: FalsePositiveMatcher, mock_case_kb: Any
) -> None:
    mock_case_kb.search_fp_cases.side_effect = RuntimeError("KB unavailable")
    result = await matcher.match({"alert_type": "test"}, EntitySet())

    assert result.matched is False
    assert result.max_score == 0.0
    assert result.recommendation == "no_match"


@pytest.mark.asyncio
async def test_matcher_kb_timeout_returns_no_match(
    matcher: FalsePositiveMatcher, mock_case_kb: Any
) -> None:
    mock_case_kb.search_fp_cases.side_effect = TimeoutError("timeout")
    result = await matcher.match({"alert_type": "test"}, EntitySet())

    assert result.recommendation == "no_match"


# --- Match: with entities enriches search ---


@pytest.mark.asyncio
async def test_matcher_with_entities_passed_to_search(
    matcher: FalsePositiveMatcher, mock_case_kb: Any
) -> None:
    mock_case_kb.search_fp_cases.return_value = [_chunk("case-00000001", 0.92, "Ops change window")]
    entities = EntitySet(
        accounts=[AccountEntity(entity_id="a-1", username="ops-change-bot")],
        hosts=[HostEntity(entity_id="h-1", hostname="PC-OPS-JUMP-01")],
    )
    snapshot: dict[str, Any] = {
        "alert_type": "account_anomaly",
        "title": "Bulk login detected",
        "signature": "ops_change_window_bulk_login",
    }
    result = await matcher.match(snapshot, entities)

    assert result.matched is True
    # Verify the search was called with entity-enriched text
    call_args = mock_case_kb.search_fp_cases.call_args
    assert call_args is not None
    alert_text = call_args[0][0]
    assert "ops-change-bot" in alert_text
    assert "PC-OPS-JUMP-01" in alert_text


# --------------------------------------------------------------------------- #
# FalsePositiveMatcherHook tests
# --------------------------------------------------------------------------- #


class _FakeBoundWorkingMemory:
    """Minimal fake BoundWorkingMemory for hook tests."""

    def __init__(self, writer_name: str = "FalsePositiveMatcher") -> None:
        self.writer_name = writer_name
        self._store: dict[str, dict[str, Any]] = {}
        self._reads: list[str] = []
        self._writes: list[tuple[str, str, Any]] = []

    async def read(self, event_id: str, key: str) -> Any:
        self._reads.append(key)
        return self._store.get(f"{event_id}:{key}")

    async def write(self, event_id: str, key: str, value: Any) -> None:
        self._writes.append((event_id, key, value))
        self._store[f"{event_id}:{key}"] = value


@pytest.fixture
def fake_agent_wm() -> _FakeBoundWorkingMemory:
    return _FakeBoundWorkingMemory("TriageAgent")


@pytest.fixture
def fake_hook_wm() -> _FakeBoundWorkingMemory:
    return _FakeBoundWorkingMemory("FalsePositiveMatcher")


@pytest.fixture
def fake_agent(fake_agent_wm: _FakeBoundWorkingMemory) -> MagicMock:
    agent = MagicMock()
    agent.working_memory = fake_agent_wm
    return agent


@pytest.fixture
def fake_input() -> MagicMock:
    inp = MagicMock()
    inp.event_id = "evt-test-001"
    return inp


def _make_matcher_returning(recommendation: str, score: float = 0.95) -> FalsePositiveMatcher:
    """Build a matcher whose match() returns a fixed FPMatchResult."""
    m = MagicMock(spec=CaseKBService)
    m.search_fp_cases = AsyncMock()
    matcher = FalsePositiveMatcher(case_kb_service=m)
    matcher.match = AsyncMock(  # type: ignore[method-assign]
        return_value=FPMatchResult(
            matched=recommendation != "no_match",
            max_score=score,
            matched_case_id="case-00000001" if recommendation != "no_match" else None,
            matched_pattern="Test pattern" if recommendation != "no_match" else None,
            recommendation=recommendation,
        )
    )
    return matcher


# --- Hook: happy path ---


@pytest.mark.asyncio
async def test_hook_writes_close_as_fp(
    fake_agent: MagicMock,
    fake_hook_wm: _FakeBoundWorkingMemory,
    fake_input: MagicMock,
    fake_agent_wm: _FakeBoundWorkingMemory,
) -> None:
    snapshot: dict[str, Any] = {
        "alert_type": "account_anomaly",
        "title": "Bulk login from ops account",
        "scenario": "account_anomaly_fp",
        "signature": "ops_change_window_bulk_login",
    }
    triage_result: dict[str, Any] = {
        "entities": {
            "accounts": [{"entity_id": "acct-1", "username": "ops-bot"}],
            "ips": [{"entity_id": "ip-1", "address": "10.0.0.1", "scope": "internal"}],
        }
    }
    fake_agent_wm._store["evt-test-001:source_snapshot"] = snapshot
    fake_agent_wm._store["evt-test-001:triage_result"] = triage_result

    matcher = _make_matcher_returning("close_as_fp", 0.96)
    hook = FalsePositiveMatcherHook(matcher=matcher, working_memory=fake_hook_wm)  # type: ignore[arg-type]

    await hook(fake_agent, fake_input)

    assert len(fake_hook_wm._writes) == 1
    event_id, key, value = fake_hook_wm._writes[0]
    assert event_id == "evt-test-001"
    assert key == "false_positive_match"
    assert value["matched"] is True
    assert value["max_score"] == 0.96
    assert value["recommendation"] == "close_as_fp"
    assert value["source"] == "FalsePositiveMatcher"
    assert "matched_at" in value


@pytest.mark.asyncio
async def test_hook_writes_investigate_with_flag(
    fake_agent: MagicMock,
    fake_hook_wm: _FakeBoundWorkingMemory,
    fake_input: MagicMock,
    fake_agent_wm: _FakeBoundWorkingMemory,
) -> None:
    fake_agent_wm._store["evt-test-001:source_snapshot"] = {"alert_type": "data_exfiltration"}
    fake_agent_wm._store["evt-test-001:triage_result"] = {"entities": {}}
    matcher = _make_matcher_returning("investigate_with_flag", 0.78)
    hook = FalsePositiveMatcherHook(matcher=matcher, working_memory=fake_hook_wm)  # type: ignore[arg-type]

    await hook(fake_agent, fake_input)

    value = fake_hook_wm._writes[0][2]
    assert value["recommendation"] == "investigate_with_flag"
    assert value["matched"] is True


@pytest.mark.asyncio
async def test_hook_writes_no_match(
    fake_agent: MagicMock,
    fake_hook_wm: _FakeBoundWorkingMemory,
    fake_input: MagicMock,
    fake_agent_wm: _FakeBoundWorkingMemory,
) -> None:
    """no_match → skip write entirely (zero impact degradation)."""
    fake_agent_wm._store["evt-test-001:source_snapshot"] = {"alert_type": "malicious_process"}
    fake_agent_wm._store["evt-test-001:triage_result"] = {"entities": {}}
    matcher = _make_matcher_returning("no_match", 0.0)
    hook = FalsePositiveMatcherHook(matcher=matcher, working_memory=fake_hook_wm)  # type: ignore[arg-type]

    await hook(fake_agent, fake_input)

    # no_match → skip write (zero impact — no trace left in EventContext)
    assert len(fake_hook_wm._writes) == 0


# --- Hook: no-op when missing dependencies ---


@pytest.mark.asyncio
async def test_hook_no_working_memory_noop(
    fake_agent: MagicMock,
    fake_input: MagicMock,
) -> None:
    matcher = _make_matcher_returning("close_as_fp")
    hook = FalsePositiveMatcherHook(matcher=matcher, working_memory=None)  # type: ignore[arg-type]
    # Should not raise
    await hook(fake_agent, fake_input)


@pytest.mark.asyncio
async def test_hook_agent_no_working_memory_noop(
    fake_hook_wm: _FakeBoundWorkingMemory,
    fake_input: MagicMock,
) -> None:
    matcher = _make_matcher_returning("close_as_fp")
    hook = FalsePositiveMatcherHook(matcher=matcher, working_memory=fake_hook_wm)  # type: ignore[arg-type]

    agent_no_wm = MagicMock()
    agent_no_wm.working_memory = None
    # Should not raise
    await hook(agent_no_wm, fake_input)

    assert len(fake_hook_wm._writes) == 0


@pytest.mark.asyncio
async def test_hook_no_source_snapshot_noop(
    fake_agent: MagicMock,
    fake_hook_wm: _FakeBoundWorkingMemory,
    fake_input: MagicMock,
) -> None:
    matcher = _make_matcher_returning("close_as_fp")
    hook = FalsePositiveMatcherHook(matcher=matcher, working_memory=fake_hook_wm)  # type: ignore[arg-type]
    # No source_snapshot in fake_agent_wm
    await hook(fake_agent, fake_input)

    assert len(fake_hook_wm._writes) == 0


@pytest.mark.asyncio
async def test_hook_none_source_snapshot_noop(
    fake_agent: MagicMock,
    fake_hook_wm: _FakeBoundWorkingMemory,
    fake_input: MagicMock,
    fake_agent_wm: _FakeBoundWorkingMemory,
) -> None:
    fake_agent_wm._store["evt-test-001:source_snapshot"] = None  # type: ignore[assignment]
    matcher = _make_matcher_returning("close_as_fp")
    hook = FalsePositiveMatcherHook(matcher=matcher, working_memory=fake_hook_wm)  # type: ignore[arg-type]
    await hook(fake_agent, fake_input)

    assert len(fake_hook_wm._writes) == 0


# --- Hook: true positive not affected (no_match) ---


@pytest.mark.asyncio
async def test_hook_true_positive_returns_no_match(
    fake_agent: MagicMock,
    fake_hook_wm: _FakeBoundWorkingMemory,
    fake_input: MagicMock,
    fake_agent_wm: _FakeBoundWorkingMemory,
) -> None:
    """Main scenario (true positive) must not be killed by FP matcher — skip write."""
    fake_agent_wm._store["evt-test-001:source_snapshot"] = {
        "alert_type": "host_compromise",
        "title": "Ransomware detected on production server",
        "description": "Encrypted files and ransom note found on PROD-WEB-01",
    }
    fake_agent_wm._store["evt-test-001:triage_result"] = {"entities": {}}
    matcher = _make_matcher_returning("no_match", 0.0)
    hook = FalsePositiveMatcherHook(matcher=matcher, working_memory=fake_hook_wm)  # type: ignore[arg-type]

    await hook(fake_agent, fake_input)

    # True positive → no_match → skip write (zero impact)
    assert len(fake_hook_wm._writes) == 0


# --- Hook: degradation — hook catches matcher exception ---


@pytest.mark.asyncio
async def test_hook_matcher_exception_does_not_crash(
    fake_agent: MagicMock,
    fake_hook_wm: _FakeBoundWorkingMemory,
    fake_input: MagicMock,
    fake_agent_wm: _FakeBoundWorkingMemory,
) -> None:
    """Hook catches matcher exceptions internally — investigation continues normally."""
    fake_agent_wm._store["evt-test-001:source_snapshot"] = {"alert_type": "test"}
    fake_agent_wm._store["evt-test-001:triage_result"] = {"entities": {}}
    matcher = MagicMock()
    matcher.match = AsyncMock(side_effect=RuntimeError("Vector store down"))
    hook = FalsePositiveMatcherHook(matcher=matcher, working_memory=fake_hook_wm)  # type: ignore[arg-type]

    # Hook catches exceptions internally → no propagation, no write.
    await hook(fake_agent, fake_input)
    assert len(fake_hook_wm._writes) == 0


# --------------------------------------------------------------------------- #
# Unit: _entities_from_triage_result
# --------------------------------------------------------------------------- #


def test_entities_from_triage_result_full() -> None:
    triage_result: dict[str, Any] = {
        "entities": {
            "accounts": [{"entity_id": "acct-1", "username": "ops-bot"}],
            "hosts": [{"entity_id": "host-1", "hostname": "PC-JUMP-01"}],
            "ips": [{"entity_id": "ip-1", "address": "10.0.0.1", "scope": "internal"}],
            "domains": [{"entity_id": "dom-1", "fqdn": "evil.example.com"}],
            "processes": [{"entity_id": "proc-1", "name": "ssh.exe"}],
            "files": [{"entity_id": "file-1", "name": "malware.exe", "path": "/tmp/malware.exe"}],
        }
    }
    entities = _entities_from_triage_result(triage_result)
    assert len(entities.accounts) == 1
    assert entities.accounts[0].username == "ops-bot"
    assert len(entities.hosts) == 1
    assert entities.hosts[0].hostname == "PC-JUMP-01"
    assert len(entities.ips) == 1
    assert entities.ips[0].address == "10.0.0.1"
    assert len(entities.domains) == 1
    assert entities.domains[0].fqdn == "evil.example.com"
    assert len(entities.processes) == 1
    assert entities.processes[0].name == "ssh.exe"
    assert len(entities.files) == 1
    assert entities.files[0].name == "malware.exe"


def test_entities_from_triage_result_none() -> None:
    assert _entities_from_triage_result(None) == EntitySet()


def test_entities_from_triage_result_not_dict() -> None:
    assert _entities_from_triage_result("not a dict") == EntitySet()


def test_entities_from_triage_result_empty_dict() -> None:
    assert _entities_from_triage_result({}) == EntitySet()


def test_entities_from_triage_result_no_entities_key() -> None:
    assert _entities_from_triage_result({"event_type": "test"}) == EntitySet()


def test_entities_from_triage_result_entities_not_dict() -> None:
    assert _entities_from_triage_result({"entities": "not a dict"}) == EntitySet()


# --------------------------------------------------------------------------- #
# Hook: rule-based hook already matched → vector hook skips
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_hook_skips_when_rule_hook_already_close_as_fp(
    fake_agent: MagicMock,
    fake_hook_wm: _FakeBoundWorkingMemory,
    fake_input: MagicMock,
    fake_agent_wm: _FakeBoundWorkingMemory,
) -> None:
    """When rule-based hook already wrote close_as_fp, vector hook must skip."""
    fake_agent_wm._store["evt-test-001:false_positive_match"] = {
        "matched": True,
        "recommendation": "close_as_fp",
        "source": "RuleBasedFalsePositiveHook",
        "max_score": 1.0,
    }
    fake_agent_wm._store["evt-test-001:source_snapshot"] = {"alert_type": "account_anomaly"}

    matcher = _make_matcher_returning("close_as_fp", 0.96)
    hook = FalsePositiveMatcherHook(matcher=matcher, working_memory=fake_hook_wm)  # type: ignore[arg-type]

    await hook(fake_agent, fake_input)

    # Deterministic rule already authoritative → vector hook skips entirely.
    assert len(fake_hook_wm._writes) == 0


@pytest.mark.asyncio
async def test_hook_merges_with_rule_hook_investigate_with_flag(
    fake_agent: MagicMock,
    fake_hook_wm: _FakeBoundWorkingMemory,
    fake_input: MagicMock,
    fake_agent_wm: _FakeBoundWorkingMemory,
) -> None:
    """Rule hook wrote investigate_with_flag — vector close_as_fp upgrades it."""
    fake_agent_wm._store["evt-test-001:false_positive_match"] = {
        "matched": True,
        "recommendation": "investigate_with_flag",
        "source": "RuleBasedFalsePositiveHook",
        "max_score": 0.78,
        "matched_rule": "ops_change_window_bulk_login",
    }
    fake_agent_wm._store["evt-test-001:source_snapshot"] = {"alert_type": "account_anomaly"}
    fake_agent_wm._store["evt-test-001:triage_result"] = {"entities": {}}

    matcher = _make_matcher_returning("close_as_fp", 0.96)
    hook = FalsePositiveMatcherHook(matcher=matcher, working_memory=fake_hook_wm)  # type: ignore[arg-type]

    await hook(fake_agent, fake_input)

    assert len(fake_hook_wm._writes) == 1
    value = fake_hook_wm._writes[0][2]
    # Vector hook's stronger recommendation wins.
    assert value["recommendation"] == "close_as_fp"
    assert value["max_score"] == 0.96
    # Rule hook's metadata is preserved.
    assert value["matched_rule"] == "ops_change_window_bulk_login"


# --------------------------------------------------------------------------- #
# Integration: VerdictResolver consumes FPMatchResult correctly
# --------------------------------------------------------------------------- #


def test_verdict_resolver_consumes_close_as_fp() -> None:
    """VerdictResolver priority 1: close_as_fp → false_positive."""
    from app.agents.verdict_resolver import VerdictResolver
    from app.models.agent_io import RiskAssessment, ScoringMode
    from app.models.enums import FinalVerdict, Severity

    resolver = VerdictResolver()
    assessment = RiskAssessment(
        risk_score=95,
        severity=Severity.CRITICAL,
        confidence=0.9,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    fp_match: dict[str, Any] = {
        "matched": True,
        "max_score": 0.96,
        "matched_case_id": "case-00000001",
        "matched_pattern": "Ops change window bulk login",
        "recommendation": "close_as_fp",
        "source": "FalsePositiveMatcher",
    }
    verdict = resolver.resolve(assessment, false_positive_match=fp_match)
    assert verdict is FinalVerdict.FALSE_POSITIVE


def test_verdict_resolver_consumes_investigate_with_flag() -> None:
    """VerdictResolver: medium FP → possible_false_positive."""
    from app.agents.verdict_resolver import VerdictResolver
    from app.models.agent_io import RiskAssessment, ScoringMode
    from app.models.enums import FinalVerdict, Severity

    resolver = VerdictResolver()
    assessment = RiskAssessment(
        risk_score=50,
        severity=Severity.MEDIUM,
        confidence=0.7,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    fp_match: dict[str, Any] = {
        "matched": True,
        "max_score": 0.78,
        "matched_case_id": "case-00000002",
        "recommendation": "investigate_with_flag",
        "source": "FalsePositiveMatcher",
    }
    verdict = resolver.resolve(assessment, false_positive_match=fp_match)
    assert verdict is FinalVerdict.POSSIBLE_FALSE_POSITIVE


def test_verdict_resolver_consumes_no_match() -> None:
    """VerdictResolver: no_match → normal path (confirmed_threat for high risk)."""
    from app.agents.verdict_resolver import VerdictResolver
    from app.models.agent_io import RiskAssessment, ScoringMode
    from app.models.enums import FinalVerdict, Severity

    resolver = VerdictResolver()
    assessment = RiskAssessment(
        risk_score=85,
        severity=Severity.HIGH,
        confidence=0.8,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    fp_match: dict[str, Any] = {
        "matched": False,
        "max_score": 0.0,
        "recommendation": "no_match",
        "source": "FalsePositiveMatcher",
    }
    verdict = resolver.resolve(assessment, false_positive_match=fp_match)
    assert verdict is FinalVerdict.CONFIRMED_THREAT


def test_verdict_resolver_no_fp_match_uses_risk() -> None:
    """VerdictResolver: None fp_match → falls through to risk-based path."""
    from app.agents.verdict_resolver import VerdictResolver
    from app.models.agent_io import RiskAssessment, ScoringMode
    from app.models.enums import FinalVerdict, Severity

    resolver = VerdictResolver()
    assessment = RiskAssessment(
        risk_score=55,
        severity=Severity.MEDIUM,
        confidence=0.6,
        scoring_mode=ScoringMode.RULE_ONLY,
    )
    verdict = resolver.resolve(assessment, false_positive_match=None)
    assert verdict is FinalVerdict.NONE


# --------------------------------------------------------------------------- #
# build_fp_close_reason
# --------------------------------------------------------------------------- #


def test_build_fp_close_reason_includes_case_id() -> None:
    from app.services.false_positive_matcher import build_fp_close_reason

    reason = build_fp_close_reason(
        {
            "recommendation": "close_as_fp",
            "matched_case_id": "case-00000001",
            "matched_pattern": "ops-change-bot pattern",
        }
    )
    assert "case-00000001" in reason
    assert "ops-change-bot pattern" in reason


def test_build_fp_close_reason_uses_matched_rule_when_no_case_id() -> None:
    from app.services.false_positive_matcher import build_fp_close_reason

    reason = build_fp_close_reason(
        {
            "recommendation": "close_as_fp",
            "matched_rule": "ops_change_window_bulk_login",
        }
    )
    assert "ops_change_window_bulk_login" in reason


def test_build_fp_close_reason_default_when_not_fp() -> None:
    from app.services.false_positive_matcher import build_fp_close_reason

    assert build_fp_close_reason(None) == "investigation:close"
    assert (
        build_fp_close_reason({"recommendation": "no_match"}, default="custom:close")
        == "custom:close"
    )
