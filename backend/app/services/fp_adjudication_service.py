"""Context-gated false-positive adjudication after evidence collection.

Close is derived from an evidence-qualification ladder (0–4), not a nested
AND of early returns. Organizational allow-facts never override ENDPOINT /
DLP / TI / encoded-PowerShell conflict evidence.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.models.agent_io import EvidenceOutput, OrgContextMatch, TriageResult
from app.models.enums import EvidenceSource
from app.models.evidence import Evidence
from app.models.fp_adjudication import ChangeWindowBaseline, FpAdjudicationResult
from app.services.change_window_baseline_loader import (
    load_change_window_baseline,
    resolve_tenant_id,
)
from app.services.org_context_matcher import is_exact_org_context_match

# Allow-kinds recorded as org_context_exact_hit after a window close.
# person_status and deny-style data_handling hits remain RAG evidence only.
_FP_ORG_CONTEXT_CLOSE_KINDS = frozenset(
    {
        "allowed_destination",
        "allowed_source",
        "account_role",
        "time_window",
    }
)

logger = logging.getLogger(__name__)

# Minimum confidence persisted on post-evidence close_as_fp for disposition-only approval.
_DISPOSITION_FP_SCORE_FLOOR = 0.88

_MALICIOUS_CONFLICT_SOURCES = frozenset(
    {
        EvidenceSource.ENDPOINT,
        EvidenceSource.DATA_SECURITY,
        EvidenceSource.THREAT_INTEL,
    }
)

_MALICIOUS_RAW_KEYS = (
    "malicious",
    "malware",
    "malware_detected",
    "dlp_blocked",
    "ti_malicious",
    "blocked",
)

_MALICIOUS_VERDICT_VALUES = frozenset({"malicious", "blocked", "critical", "high_risk"})

_ENCODED_POWERSHELL_PROCESSES = frozenset({"powershell.exe", "powershell", "pwsh.exe", "pwsh"})
_ENCODED_POWERSHELL_CMDLINE = re.compile(
    r"(?i)(?:-enc(?:odedcommand)?(?:\s|=|:|$)|frombase64string|downloadstring|"
    r"\biex\b|invoke-expression)"
)

ARBITRATION_NO_CONTRADICTION = "no_contradiction"
ARBITRATION_MALICIOUS_OVERRIDES = "malicious_overrides_allowance"


@dataclass(frozen=True, slots=True)
class _WindowFactors:
    window: ChangeWindowBaseline | None
    time_match: bool
    identity_scope_match: bool
    action_scope_match: bool
    asset_scope_match: bool

    @property
    def full_match(self) -> bool:
        return (
            self.window is not None
            and self.time_match
            and self.identity_scope_match
            and self.action_scope_match
            and self.asset_scope_match
        )


class PostEvidenceFpAdjudicator:
    """Run typed FP decision after evidence collection.

    Qualification level 4 (authorization + time + scope, no conflict) is the
    only close_as_fp path. Absence of malicious evidence alone never closes.
    """

    def __init__(self, *, baseline_path: str | None = None) -> None:
        self._baseline_path = baseline_path

    def adjudicate(
        self,
        *,
        event_id: str,
        evidence_output: EvidenceOutput,
        triage_result: TriageResult,
        source_snapshot: dict[str, Any] | None = None,
        occurred_at: datetime | None = None,
        org_context_matches: list[OrgContextMatch] | None = None,
    ) -> FpAdjudicationResult:
        """Return a structured post-evidence FP recommendation."""
        now = datetime.now(UTC).isoformat()
        tenant_id = resolve_tenant_id(source_snapshot)
        if tenant_id is None:
            return FpAdjudicationResult(
                recommendation="no_fp_signal",
                missing_conditions=["tenant_id"],
                qualification_level=0,
                adjudicated_at=now,
            )
        baseline = load_change_window_baseline(self._baseline_path).get(tenant_id)
        if baseline is None or not baseline.change_windows:
            return FpAdjudicationResult(
                recommendation="no_fp_signal",
                missing_conditions=["org_baseline_available"],
                qualification_level=0,
                adjudicated_at=now,
            )

        auth_evidence = _authorization_evidence(evidence_output.evidence_list)
        conflicts = _malicious_conflicts(evidence_output)
        qualifying = _qualifying_org_context_matches(org_context_matches)
        org_exact = bool(qualifying)
        has_auth = bool(auth_evidence)

        matched_conditions = _matched_authorization_labels(auth_evidence)
        if org_exact:
            matched_conditions.append("org_context_exact_hit")

        if not has_auth:
            missing = ["change_window_authorization_evidence"]
            if conflicts:
                missing.append("no_malicious_conflicts")
            return FpAdjudicationResult(
                recommendation="no_fp_signal",
                supporting_evidence_ids=[],
                matched_conditions=matched_conditions,
                missing_conditions=missing,
                conflicts=conflicts,
                qualification_level=1 if org_exact else 0,
                arbitration=(ARBITRATION_MALICIOUS_OVERRIDES if conflicts and org_exact else None),
                adjudicated_at=now,
            )

        event_time = _resolve_event_time(auth_evidence, occurred_at)
        accounts = _collect_accounts(triage_result, auth_evidence)
        actions = _collect_actions(triage_result, auth_evidence)
        asset_groups = _collect_asset_groups(evidence_output.evidence_list)
        factors = _evaluate_windows(
            baseline.change_windows,
            event_time=event_time,
            accounts=accounts,
            actions=actions,
            asset_groups=asset_groups,
        )

        missing_conditions = _missing_from_factors(factors, has_conflicts=bool(conflicts))
        matched_conditions.extend(_matched_from_factors(factors, has_conflicts=bool(conflicts)))
        level = _qualification_level(
            has_auth=True,
            org_exact=org_exact,
            factors=factors,
            has_conflicts=bool(conflicts),
        )
        arbitration = _arbitration(has_conflicts=bool(conflicts), org_exact=org_exact, level=level)
        recommendation = "close_as_fp" if level == 4 else "investigate"
        window_id = factors.window.window_id if factors.full_match else None
        if recommendation == "close_as_fp":
            logger.info(
                "PostEvidenceFpAdjudicator: close_as_fp event=%s window=%s evidence=%d org=%d",
                event_id,
                window_id,
                len(auth_evidence),
                len(qualifying),
            )
        return FpAdjudicationResult(
            recommendation=recommendation,
            supporting_evidence_ids=[item.evidence_id for item in auth_evidence],
            matched_conditions=matched_conditions,
            missing_conditions=missing_conditions,
            conflicts=conflicts,
            matched_window_id=window_id,
            max_score=(
                _derive_adjudication_score(auth_evidence)
                if recommendation == "close_as_fp"
                else None
            ),
            qualification_level=level,
            arbitration=arbitration,
            adjudicated_at=now,
        )


def evidence_has_conflict(evidence_output: EvidenceOutput | None) -> bool:
    """True when evidence carries malicious / contradictory attack signals."""
    if evidence_output is None:
        return False
    return bool(_malicious_conflicts(evidence_output))


def _qualification_level(
    *,
    has_auth: bool,
    org_exact: bool,
    factors: _WindowFactors,
    has_conflicts: bool,
) -> int:
    if factors.full_match and has_auth and not has_conflicts:
        return 4
    if factors.full_match and has_auth and has_conflicts:
        return 3
    if has_auth and factors.time_match:
        return 2
    if has_auth or org_exact:
        return 1
    return 0


def _arbitration(*, has_conflicts: bool, org_exact: bool, level: int) -> str | None:
    if has_conflicts:
        return ARBITRATION_MALICIOUS_OVERRIDES
    if level == 4:
        return ARBITRATION_NO_CONTRADICTION
    _ = org_exact
    return None


def _authorization_evidence(evidence_list: list[Evidence]) -> list[Evidence]:
    """Identity evidence with explicit change-window authorization flag."""
    authorized: list[Evidence] = []
    for item in evidence_list:
        if item.source is not EvidenceSource.IDENTITY:
            continue
        raw = item.raw_data or {}
        if raw.get("change_window") in (True, "true", "True", 1, "1"):
            authorized.append(item)
    return authorized


def _malicious_conflicts(evidence_output: EvidenceOutput) -> list[str]:
    conflicts: list[str] = []
    for conflict in evidence_output.conflicts:
        conflicts.append(conflict.description or conflict.conflict_id)
    for item in evidence_output.evidence_list:
        if item.is_conflicting:
            conflicts.append(f"conflicting_evidence:{item.evidence_id}")
            continue
        if item.source not in _MALICIOUS_CONFLICT_SOURCES:
            continue
        if _is_encoded_powershell(item):
            conflicts.append(f"encoded_powershell:{item.evidence_id}")
            continue
        if _is_malicious_evidence(item):
            conflicts.append(f"malicious_evidence:{item.evidence_id}:{item.source.value}")
    return conflicts


def _is_malicious_evidence(item: Evidence) -> bool:
    raw = item.raw_data or {}
    for key in _MALICIOUS_RAW_KEYS:
        value = raw.get(key)
        if value is True:
            return True
        if isinstance(value, str) and value.strip().lower() in _MALICIOUS_VERDICT_VALUES:
            return True
    verdict = raw.get("verdict") or raw.get("severity") or raw.get("risk_label")
    if isinstance(verdict, str) and verdict.strip().lower() in _MALICIOUS_VERDICT_VALUES:
        return True
    return False


def _is_encoded_powershell(item: Evidence) -> bool:
    """ENDPOINT PowerShell with encoded / IEX tradecraft — not bare powershell.exe."""
    if item.source is not EvidenceSource.ENDPOINT:
        return False
    raw = item.raw_data or {}
    process = str(raw.get("process") or raw.get("process_name") or "").strip().lower()
    process_base = process.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    if process_base not in _ENCODED_POWERSHELL_PROCESSES:
        return False
    cmdline = str(raw.get("cmdline") or raw.get("command_line") or item.description or "")
    return bool(_ENCODED_POWERSHELL_CMDLINE.search(cmdline))


def _resolve_event_time(
    auth_evidence: list[Evidence],
    occurred_at: datetime | None,
) -> datetime | None:
    timestamps = [item.timestamp for item in auth_evidence if item.timestamp is not None]
    if timestamps:
        return min(timestamps)
    return occurred_at


def _collect_accounts(triage_result: TriageResult, auth_evidence: list[Evidence]) -> set[str]:
    accounts: set[str] = set()
    for account in triage_result.entities.accounts:
        for value in (account.username, account.display_name, account.entity_id):
            if value:
                accounts.add(str(value).lower())
    for item in auth_evidence:
        raw_account = (item.raw_data or {}).get("account")
        if raw_account:
            accounts.add(str(raw_account).lower())
    return accounts


def _collect_actions(_triage_result: TriageResult, auth_evidence: list[Evidence]) -> set[str]:
    """Collect observed actions from authorization evidence only (ISSUE-114)."""
    actions: set[str] = set()
    for item in auth_evidence:
        for key in ("event_type", "action"):
            value = (item.raw_data or {}).get(key)
            if value:
                actions.add(str(value).lower())
        if item.evidence_type:
            actions.add(str(item.evidence_type).lower())
    return actions


def _collect_asset_groups(evidence_list: list[Evidence]) -> set[str]:
    groups: set[str] = set()
    for item in evidence_list:
        if item.source is not EvidenceSource.ASSET:
            continue
        raw = item.raw_data or {}
        group = raw.get("asset_group") or raw.get("group")
        if group:
            groups.add(str(group).lower())
    return groups


def _evaluate_one_window(
    window: ChangeWindowBaseline,
    *,
    event_time: datetime,
    accounts: set[str],
    actions: set[str],
    asset_groups: set[str],
) -> _WindowFactors | None:
    try:
        start = datetime.fromisoformat(window.valid_from)
        end = datetime.fromisoformat(window.valid_until)
    except ValueError:
        return None
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    time_match = start <= event_time <= end
    authorized_accounts = {value.lower() for value in window.authorized_accounts}
    identity_ok = not authorized_accounts or not accounts.isdisjoint(authorized_accounts)
    authorized_actions = {value.lower() for value in window.authorized_actions}
    action_ok = not authorized_actions or not actions.isdisjoint(authorized_actions)
    authorized_groups = {value.lower() for value in window.authorized_asset_groups}
    asset_ok = not authorized_groups or (
        bool(asset_groups) and not asset_groups.isdisjoint(authorized_groups)
    )
    return _WindowFactors(
        window=window,
        time_match=time_match,
        identity_scope_match=identity_ok,
        action_scope_match=action_ok,
        asset_scope_match=asset_ok,
    )


def _evaluate_windows(
    windows: list[ChangeWindowBaseline],
    *,
    event_time: datetime | None,
    accounts: set[str],
    actions: set[str],
    asset_groups: set[str],
) -> _WindowFactors:
    empty = _WindowFactors(
        window=None,
        time_match=False,
        identity_scope_match=False,
        action_scope_match=False,
        asset_scope_match=False,
    )
    if event_time is None:
        return empty
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=UTC)

    best: _WindowFactors | None = None
    best_score = (-1, -1, -1, -1)
    for window in windows:
        factors = _evaluate_one_window(
            window,
            event_time=event_time,
            accounts=accounts,
            actions=actions,
            asset_groups=asset_groups,
        )
        if factors is None:
            continue
        if factors.full_match:
            return factors
        score = (
            int(factors.time_match),
            int(factors.identity_scope_match),
            int(factors.action_scope_match),
            int(factors.asset_scope_match),
        )
        if score > best_score:
            best = factors
            best_score = score
    return best or empty


def _matched_from_factors(factors: _WindowFactors, *, has_conflicts: bool) -> list[str]:
    matched: list[str] = []
    if factors.time_match:
        matched.append("time_match")
    if factors.identity_scope_match:
        matched.append("identity_scope_match")
    if factors.action_scope_match:
        matched.append("action_scope_match")
    if factors.asset_scope_match:
        matched.append("asset_scope_match")
    if factors.full_match:
        matched.append("baseline_window_match")
    if not has_conflicts:
        matched.append("no_malicious_conflicts")
    return matched


def _missing_from_factors(factors: _WindowFactors, *, has_conflicts: bool) -> list[str]:
    missing: list[str] = []
    if not factors.full_match:
        missing.append("baseline_window_match")
        if not factors.time_match:
            missing.append("time_match")
        else:
            if not factors.identity_scope_match:
                missing.append("identity_scope_match")
            if not factors.action_scope_match:
                missing.append("action_scope_match")
            if not factors.asset_scope_match:
                missing.append("asset_scope_match")
    if has_conflicts:
        missing.append("no_malicious_conflicts")
    return missing


def _derive_adjudication_score(auth_evidence: list[Evidence]) -> float:
    """Confidence for disposition-only approval from authorization evidence."""
    scores: list[float] = []
    for item in auth_evidence:
        try:
            scores.append(max(0.0, min(1.0, float(item.confidence))))
        except (TypeError, ValueError):
            continue
    derived = max(scores) if scores else 0.0
    return max(derived, _DISPOSITION_FP_SCORE_FLOOR)


def _qualifying_org_context_matches(
    matches: list[OrgContextMatch] | None,
) -> list[OrgContextMatch]:
    if not matches:
        return []
    return [
        match
        for match in matches
        if match.kind in _FP_ORG_CONTEXT_CLOSE_KINDS
        and is_exact_org_context_match(match.match_type)
    ]


def _matched_authorization_labels(auth_evidence: list[Evidence]) -> list[str]:
    if not auth_evidence:
        return []
    return ["change_window_authorization_present"]


__all__ = ["PostEvidenceFpAdjudicator", "evidence_has_conflict"]
