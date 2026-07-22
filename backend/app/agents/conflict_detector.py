"""ConflictDetector: three fixed evidence-conflict rules (ISSUE-034)."""

from __future__ import annotations

import logging
from typing import Any

from app.models.enums import EvidenceSource
from app.models.evidence import Evidence, EvidenceConflict
from app.models.ids import new_conflict_id

logger = logging.getLogger(__name__)

CONFLICT_PENALTY_FACTOR = 0.7

RULE_IAM_ABSENT_BUT_EDR_ACTIVE = "iam_absent_but_edr_active"
RULE_NETWORK_SILENT_BUT_DLP_UPLOAD = "network_silent_but_dlp_upload"
RULE_ASSET_ISOLATED_BUT_EDR_ACTIVE = "asset_isolated_but_edr_active"

_ABSENT_LOGIN_RESULTS = frozenset(
    {
        "no_record",
        "failure",
        "failed",
        "denied",
        "absent",
        "not_found",
    }
)
_SUCCESS_LOGIN_RESULTS = frozenset({"success", "ok", "allowed"})
_UPLOAD_ACTIONS = frozenset({"upload", "exfil", "send", "transfer"})
_ISOLATED_ASSET_STATUSES = frozenset(
    {
        "isolated",
        "quarantined",
        "offline",
        "not_installed",
        "disconnected",
        "containment",
    }
)


class ConflictDetector:
    """Detect cross-source contradictions and apply confidence penalties."""

    def detect(self, evidence_list: list[Evidence]) -> list[EvidenceConflict]:
        """Return conflicts for *evidence_list* without mutating inputs."""
        if not evidence_list:
            return []
        event_id = evidence_list[0].event_id
        by_source = self._group_by_source(evidence_list)
        conflicts: list[EvidenceConflict] = []
        conflicts.extend(self._rule_iam_absent_but_edr_active(event_id, by_source))
        conflicts.extend(self._rule_network_silent_but_dlp_upload(event_id, by_source))
        conflicts.extend(self._rule_asset_isolated_but_edr_active(event_id, by_source))
        return conflicts

    def apply_penalties(
        self,
        evidence_list: list[Evidence],
        conflicts: list[EvidenceConflict],
    ) -> list[Evidence]:
        """Mark conflicting evidence and multiply confidence by 0.7 (once per item)."""
        penalized_ids: set[str] = set()
        for conflict in conflicts:
            penalized_ids.update(conflict.evidence_ids)
        if not penalized_ids:
            return evidence_list

        updated: list[Evidence] = []
        for item in evidence_list:
            if item.evidence_id not in penalized_ids:
                updated.append(item)
                continue
            new_confidence = min(1.0, max(0.0, item.confidence * CONFLICT_PENALTY_FACTOR))
            updated.append(
                item.model_copy(
                    update={
                        "confidence": new_confidence,
                        "is_conflicting": True,
                    }
                )
            )
        return updated

    def detect_and_penalize(
        self,
        evidence_list: list[Evidence],
    ) -> tuple[list[Evidence], list[EvidenceConflict]]:
        """Detect conflicts then return (penalized evidence, conflicts)."""
        conflicts = self.detect(evidence_list)
        return self.apply_penalties(evidence_list, conflicts), conflicts

    @staticmethod
    def _group_by_source(
        evidence_list: list[Evidence],
    ) -> dict[EvidenceSource, list[Evidence]]:
        grouped: dict[EvidenceSource, list[Evidence]] = {}
        for item in evidence_list:
            grouped.setdefault(item.source, []).append(item)
        return grouped

    def _rule_iam_absent_but_edr_active(
        self,
        event_id: str,
        by_source: dict[EvidenceSource, list[Evidence]],
    ) -> list[EvidenceConflict]:
        identity = by_source.get(EvidenceSource.IDENTITY, [])
        endpoint = by_source.get(EvidenceSource.ENDPOINT, [])
        if not identity or not endpoint:
            return []

        absent_by_account: dict[str, list[Evidence]] = {}
        success_accounts: set[str] = set()
        for item in identity:
            account = self._account_from_evidence(item)
            if not account:
                continue
            if self._is_successful_login(item):
                success_accounts.add(account.lower())
            elif self._is_absent_login(item):
                absent_by_account.setdefault(account.lower(), []).append(item)

        conflicts: list[EvidenceConflict] = []
        for item in endpoint:
            if not self._is_process_activity(item):
                continue
            account = self._account_from_evidence(item)
            if not account:
                continue
            key = account.lower()
            if key in success_accounts:
                continue
            absent_rows = absent_by_account.get(key)
            if not absent_rows:
                continue
            involved = [*absent_rows, item]
            conflicts.append(
                self._make_conflict(
                    event_id=event_id,
                    rule_name=RULE_IAM_ABSENT_BUT_EDR_ACTIVE,
                    severity="high",
                    evidence_list=involved,
                    description=(
                        f"IAM 无成功登录记录（账号 {account}），但 EDR 观察到该账号的进程活动"
                    ),
                )
            )
        return conflicts

    def _rule_network_silent_but_dlp_upload(
        self,
        event_id: str,
        by_source: dict[EvidenceSource, list[Evidence]],
    ) -> list[EvidenceConflict]:
        network = by_source.get(EvidenceSource.NETWORK_FLOW, [])
        dlp = by_source.get(EvidenceSource.DATA_SECURITY, [])
        if not dlp:
            return []

        uploads = [item for item in dlp if self._is_upload(item)]
        if not uploads:
            return []

        # "network silent" = no external outbound flows present.
        has_external = any(self._is_external_flow(item) for item in network)
        if has_external:
            return []

        silent_markers = [item for item in network if self._is_silent_marker(item)]
        involved = [*silent_markers, *uploads] if silent_markers else list(uploads)
        # If network source returned only non-external or empty, still conflict with uploads.
        if network and not silent_markers:
            involved = [*network, *uploads]

        return [
            self._make_conflict(
                event_id=event_id,
                rule_name=RULE_NETWORK_SILENT_BUT_DLP_UPLOAD,
                severity="medium",
                evidence_list=involved,
                description="网络侧无明显外联，但 DLP/数据安全侧检测到上传行为",
            )
        ]

    def _rule_asset_isolated_but_edr_active(
        self,
        event_id: str,
        by_source: dict[EvidenceSource, list[Evidence]],
    ) -> list[EvidenceConflict]:
        assets = by_source.get(EvidenceSource.ASSET, [])
        endpoint = by_source.get(EvidenceSource.ENDPOINT, [])
        if not assets or not endpoint:
            return []

        isolated_assets = [item for item in assets if self._is_isolated_asset(item)]
        if not isolated_assets:
            return []

        active_endpoint = [item for item in endpoint if self._is_process_activity(item)]
        if not active_endpoint:
            return []

        conflicts: list[EvidenceConflict] = []
        for asset in isolated_assets:
            host_keys = {value.lower() for value in self._host_keys(asset)}
            if not host_keys:
                continue
            matched_endpoint = [
                item
                for item in active_endpoint
                if host_keys.intersection({value.lower() for value in self._host_keys(item)})
            ]
            if not matched_endpoint:
                continue
            conflicts.append(
                self._make_conflict(
                    event_id=event_id,
                    rule_name=RULE_ASSET_ISOLATED_BUT_EDR_ACTIVE,
                    severity="high",
                    evidence_list=[asset, *matched_endpoint],
                    description="资产标记为隔离/离线，但 EDR 仍观察到进程活动",
                )
            )
        return conflicts

    def _make_conflict(
        self,
        *,
        event_id: str,
        rule_name: str,
        severity: str,
        evidence_list: list[Evidence],
        description: str,
    ) -> EvidenceConflict:
        # ISSUE-005 locks EvidenceConflict fields; rule_name/severity live in detail.
        evidence_ids = []
        seen: set[str] = set()
        for item in evidence_list:
            if item.evidence_id in seen:
                continue
            seen.add(item.evidence_id)
            evidence_ids.append(item.evidence_id)
        sources: list[EvidenceSource] = []
        for item in evidence_list:
            if item.source not in sources:
                sources.append(item.source)
        return EvidenceConflict(
            conflict_id=new_conflict_id(),
            event_id=event_id,
            description=description,
            evidence_ids=evidence_ids,
            sources=sources,
            detail={
                "rule_name": rule_name,
                "severity": severity,
            },
        )

    @staticmethod
    def _raw(item: Evidence) -> dict[str, Any]:
        return item.raw_data if isinstance(item.raw_data, dict) else {}

    def _account_from_evidence(self, item: Evidence) -> str | None:
        raw = self._raw(item)
        for key in ("account", "username", "user"):
            value = raw.get(key)
            if value:
                return str(value)
        for value in item.related_entities:
            # Heuristic: usernames rarely contain dots like FQDNs/IPs.
            if value and "." not in value and not self._looks_ip(value):
                return value
        return None

    def _is_absent_login(self, item: Evidence) -> bool:
        raw = self._raw(item)
        result = str(raw.get("result") or "").lower()
        event_type = str(raw.get("event_type") or item.evidence_type or "").lower()
        if result in _ABSENT_LOGIN_RESULTS:
            return True
        if "no_record" in event_type or "absent" in event_type:
            return True
        return False

    def _is_successful_login(self, item: Evidence) -> bool:
        raw = self._raw(item)
        result = str(raw.get("result") or "").lower()
        return result in _SUCCESS_LOGIN_RESULTS

    def _is_process_activity(self, item: Evidence) -> bool:
        raw = self._raw(item)
        action = str(raw.get("action") or item.evidence_type or "").lower()
        if raw.get("process") or raw.get("cmdline"):
            return True
        return action in {
            "process_create",
            "process",
            "file_access",
            "process_event",
        }

    def _is_upload(self, item: Evidence) -> bool:
        raw = self._raw(item)
        action = str(raw.get("action") or item.evidence_type or "").lower()
        return action in _UPLOAD_ACTIONS or "upload" in action

    def _is_external_flow(self, item: Evidence) -> bool:
        raw = self._raw(item)
        if raw.get("dst_ip") or raw.get("domain"):
            dst = str(raw.get("dst_ip") or "")
            # Treat RFC5737 / public-looking destinations as external; private as not.
            if dst.startswith(("10.", "192.168.", "172.")):
                return False
            if dst.startswith("192.0.2."):  # TEST-NET noise
                return False
            return True
        return False

    def _is_silent_marker(self, item: Evidence) -> bool:
        raw = self._raw(item)
        marker = str(raw.get("result") or raw.get("status") or item.evidence_type or "").lower()
        return marker in {"silent", "no_flow", "no_record", "empty"}

    def _is_isolated_asset(self, item: Evidence) -> bool:
        raw = self._raw(item)
        status = str(
            raw.get("agent_status")
            or raw.get("isolation_status")
            or raw.get("status")
            or item.evidence_type
            or ""
        ).lower()
        if status in _ISOLATED_ASSET_STATUSES:
            return True
        if raw.get("isolated") is True:
            return True
        return "isolat" in status or "quarant" in status

    def _host_keys(self, item: Evidence) -> list[str]:
        raw = self._raw(item)
        keys: list[str] = []
        for key in ("hostname", "host_id", "ip", "host"):
            value = raw.get(key)
            if value:
                keys.append(str(value))
        keys.extend(str(value) for value in item.related_entities if value)
        return keys

    @staticmethod
    def _looks_ip(value: str) -> bool:
        parts = value.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
