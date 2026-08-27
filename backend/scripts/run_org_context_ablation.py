"""Engineering ablation for org-context FP gates and RAG rewrite skip.

This is mock-mode engineering validation, not prize accuracy. Do not cite
these numbers as production precision or full-loop speedup.

Usage::

    cd backend && python -m scripts.run_org_context_ablation
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.models.agent_io import (
    CollectionStatus,
    EvidenceOutput,
    OrgContextMatch,
    TriageResult,
)
from app.models.entities import AccountEntity, DomainEntity, EntitySet
from app.models.enums import EventType, EvidenceSource, Severity
from app.models.evidence import Evidence
from app.models.knowledge import (
    ListedKnowledgeChunk,
    RetrievalMetrics,
    RetrievedChunk,
)
from app.rag.context import RetrievalContext
from app.rag.pipeline import RetrievalPipeline
from app.rag.query_rewrite_policy import should_skip_query_rewrite
from app.rag.reranker import MockReranker
from app.services.fp_adjudication_service import PostEvidenceFpAdjudicator

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_BASELINE = _REPO_ROOT / "data" / "organization" / "change_windows.json"
_BANNER = (
    "engineering_validation_only: mock embeddings / stub rewriter; "
    "not prize accuracy; RAG-segment metrics only"
)


class _DelayedRewriter:
    def __init__(self, delay_s: float = 0.05) -> None:
        self.delay_s = delay_s
        self.calls = 0

    async def rewrite(self, query: str, *, context: RetrievalContext) -> list[str]:
        self.calls += 1
        time.sleep(self.delay_s)
        return [query, f"{query} rewritten"]


class _FixedRetriever:
    def __init__(self, chunks: list[RetrievedChunk]) -> None:
        self._chunks = chunks
        self.calls = 0

    async def retrieve(self, *args: object, **kwargs: object) -> list[list[RetrievedChunk]]:
        self.calls += 1
        return [list(self._chunks), list(self._chunks)]


class _FakeOrgContextStore:
    def __init__(self, chunks: list[ListedKnowledgeChunk]) -> None:
        self._chunks = chunks

    async def list_chunks(self, **kwargs: object) -> list[ListedKnowledgeChunk]:
        return list(self._chunks)


class _ExactOnlyRetriever:
    """Lists org-context rows; hybrid retrieve must not run on exact hit."""

    def __init__(self, listed: list[ListedKnowledgeChunk]) -> None:
        self._store = _FakeOrgContextStore(listed)
        self.calls = 0

    async def retrieve(self, *args: object, **kwargs: object) -> list[list[RetrievedChunk]]:
        self.calls += 1
        raise AssertionError("hybrid must not run when exact org-context matching applies")


def _auth_evidence(*, occurred_at: datetime, account: str = "ops-change-bot") -> Evidence:
    return Evidence(
        evidence_id="evd-auth-ablation",
        event_id="evt-ablation",
        source=EvidenceSource.IDENTITY,
        evidence_type="login",
        description="ops login",
        confidence=0.9,
        timestamp=occurred_at,
        raw_data={
            "account": account,
            "change_window": True,
            "action": "login",
            "result": "success",
        },
    )


def _asset_evidence() -> Evidence:
    return Evidence(
        evidence_id="evd-asset-ablation",
        event_id="evt-ablation",
        source=EvidenceSource.ASSET,
        evidence_type="host",
        description="ops host",
        confidence=0.88,
        timestamp=datetime(2024, 6, 15, 9, 30, tzinfo=UTC),
        raw_data={"asset_group": "ops", "hostname": "PC-OPS-JUMP-01"},
    )


def _org_match() -> OrgContextMatch:
    return OrgContextMatch(
        kind="account_role",
        matched_value="ops-change-bot",
        explanation="approved change-window service account",
        citation_id="cit-0c00ab01",
        chunk_id="chk-orgacct",
        match_type="account_exact",
    )


def _encoded_powershell_evidence() -> Evidence:
    return Evidence(
        evidence_id="evd-ps-ablation",
        event_id="evt-ablation",
        source=EvidenceSource.ENDPOINT,
        evidence_type="process",
        description="encoded powershell",
        confidence=0.9,
        timestamp=datetime(2024, 6, 15, 9, 35, tzinfo=UTC),
        raw_data={
            "process": "powershell.exe",
            "cmdline": "powershell.exe -EncodedCommand SQBFAFgA",
        },
    )


def _dlp_evidence() -> Evidence:
    return Evidence(
        evidence_id="evd-dlp-ablation",
        event_id="evt-ablation",
        source=EvidenceSource.DATA_SECURITY,
        evidence_type="file_access",
        description="dlp blocked sensitive upload",
        confidence=0.92,
        timestamp=datetime(2024, 6, 15, 9, 36, tzinfo=UTC),
        raw_data={"dlp_blocked": True, "file_name": "payroll.xlsx"},
    )


def _ti_evidence() -> Evidence:
    return Evidence(
        evidence_id="evd-ti-ablation",
        event_id="evt-ablation",
        source=EvidenceSource.THREAT_INTEL,
        evidence_type="indicator",
        description="ti malicious ip",
        confidence=0.91,
        timestamp=datetime(2024, 6, 15, 9, 37, tzinfo=UTC),
        raw_data={"ti_malicious": True, "indicator": "203.0.113.50"},
    )


def _cases() -> list[dict[str, Any]]:
    inside = datetime(2024, 6, 15, 9, 30, tzinfo=UTC)
    outside = datetime(2024, 6, 15, 18, 0, tzinfo=UTC)
    return [
        {
            "name": "account_anomaly_fp",
            "label": "benign_close",
            "occurred_at": inside,
            "org": [_org_match()],
            "fp_vector": 0.91,
            "llm_close": True,
            "extra": [],
        },
        {
            "name": "suspicious_domain_access",
            "label": "benign_close",
            "occurred_at": inside,
            "org": [
                OrgContextMatch(
                    kind="allowed_destination",
                    matched_value="cdn.corp.internal",
                    explanation="approved internal CDN",
                    citation_id="cit-0c00ab02",
                    chunk_id="chk-orgcdn",
                    match_type="domain_exact",
                )
            ],
            "fp_vector": 0.88,
            "llm_close": True,
            "extra": [],
        },
        {
            "name": "exfil_outside_window",
            "label": "threat_keep_open",
            "occurred_at": outside,
            "org": [_org_match()],
            "fp_vector": 0.93,
            "llm_close": True,
            "extra": [],
        },
        {
            "name": "encoded_powershell_inside_window",
            "label": "threat_keep_open",
            "occurred_at": inside,
            "org": [_org_match()],
            "fp_vector": 0.9,
            "llm_close": True,
            "extra": [_encoded_powershell_evidence()],
        },
        {
            "name": "dlp_inside_window",
            "label": "threat_keep_open",
            "occurred_at": inside,
            "org": [_org_match()],
            "fp_vector": 0.89,
            "llm_close": True,
            "extra": [_dlp_evidence()],
        },
        {
            "name": "ti_inside_window",
            "label": "threat_keep_open",
            "occurred_at": inside,
            "org": [_org_match()],
            "fp_vector": 0.9,
            "llm_close": True,
            "extra": [_ti_evidence()],
        },
    ]


def _evidence_for(case: dict[str, Any], *, include_extra: bool) -> EvidenceOutput:
    items = [_auth_evidence(occurred_at=case["occurred_at"]), _asset_evidence()]
    if include_extra:
        items.extend(list(case.get("extra") or []))
    return EvidenceOutput(
        evidence_list=items,
        collection_status=CollectionStatus.COMPLETED,
        overall_confidence=0.8,
        success_sources=["identity", "asset"],
    )


def _triage() -> TriageResult:
    return TriageResult(
        event_type=EventType.ACCOUNT_ANOMALY,
        severity=Severity.MEDIUM,
        need_investigation=True,
        entities=EntitySet(
            accounts=[
                AccountEntity(
                    entity_id="acct-1",
                    entity_type="account",
                    username="ops-change-bot",
                )
            ],
            domains=[
                DomainEntity(entity_id="dom-1", fqdn="cdn.corp.internal"),
            ],
        ),
    )


def _accuracy_arms(baseline_path: Path) -> dict[str, Any]:
    adjudicator = PostEvidenceFpAdjudicator(baseline_path=str(baseline_path))
    rows: list[dict[str, Any]] = []
    for case in _cases():
        triage = _triage()
        window_only = adjudicator.adjudicate(
            event_id=f"evt-{case['name']}-window",
            evidence_output=_evidence_for(case, include_extra=False),
            triage_result=triage,
            source_snapshot={"source_tenant_id": "tenant-demo"},
            occurred_at=case["occurred_at"],
            org_context_matches=case["org"],
        )
        full = adjudicator.adjudicate(
            event_id=f"evt-{case['name']}",
            evidence_output=_evidence_for(case, include_extra=True),
            triage_result=triage,
            source_snapshot={"source_tenant_id": "tenant-demo"},
            occurred_at=case["occurred_at"],
            org_context_matches=case["org"],
        )
        expected_close = case["label"] == "benign_close"
        rows.append(
            {
                "case": case["name"],
                "label": case["label"],
                "injected_vector_rag_close": case["fp_vector"] >= 0.85,
                "injected_llm_close": bool(case["llm_close"]),
                "exact_only_close": bool(case["org"]),
                "exact_window_close": window_only.recommendation == "close_as_fp",
                "full_method_close": full.recommendation == "close_as_fp",
                "qualification_level": full.qualification_level,
                "expected_close": expected_close,
            }
        )

    def _score(key: str) -> dict[str, int]:
        benign_ok = sum(1 for row in rows if row["label"] == "benign_close" and row[key] is True)
        threat_miss = sum(
            1 for row in rows if row["label"] == "threat_keep_open" and row[key] is True
        )
        return {"benign_correct_close": benign_ok, "threat_miss_close": threat_miss}

    return {
        "banner": _BANNER,
        "cases": rows,
        "injected_vector_rag": _score("injected_vector_rag_close"),
        "injected_llm_close": _score("injected_llm_close"),
        "exact_only": _score("exact_only_close"),
        "exact_window": _score("exact_window_close"),
        "full_method": _score("full_method_close"),
    }


async def _latency_arms(*, repeats: int) -> dict[str, Any]:
    query = (
        "Event type: account_anomaly. Alert severity: medium. "
        "Account:ops-change-bot Host:PC-OPS-JUMP-01"
    )
    chunks = [
        RetrievedChunk(
            chunk_id=f"chk-{index:08x}",
            kb_name="attack_kb",
            content="valid accounts change window bulk login",
            score=0.8,
            retrieval_method="vector",
        )
        for index in range(1, 6)
    ]
    context = RetrievalContext(
        tenant_id="local",
        principal="investigation:ablation",
        event_id="evt-ablation-latency",
        trace_id="evt:ablation-latency",
    )

    async def _run(*, skip_rewrite: bool, top_k: int) -> dict[str, float | int | bool]:
        rewriter = _DelayedRewriter()
        pipeline = RetrievalPipeline(
            rewriter=rewriter,  # type: ignore[arg-type]
            retriever=_FixedRetriever(chunks),  # type: ignore[arg-type]
            reranker=MockReranker(),
        )
        started = time.perf_counter()
        if skip_rewrite:
            # Structured query skip is production behavior.
            assert should_skip_query_rewrite(query) is True
        result = await pipeline.retrieve(query, ["attack_kb"], top_k=top_k, context=context)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        metrics = result.retrieval_metrics or RetrievalMetrics()
        ids = [chunk.chunk_id for chunk in result.chunks[:5]]
        return {
            "total_ms": elapsed_ms,
            "llm_rewrite_calls": metrics.llm_rewrite_calls if skip_rewrite else rewriter.calls,
            "chunk_ids": ids,
        }

    # Force rewrite arm by using a short unstructured query.
    short_query = "login"

    async def _run_rewrite(top_k: int) -> dict[str, Any]:
        rewriter = _DelayedRewriter()
        pipeline = RetrievalPipeline(
            rewriter=rewriter,  # type: ignore[arg-type]
            retriever=_FixedRetriever(chunks),  # type: ignore[arg-type]
            reranker=MockReranker(),
        )
        started = time.perf_counter()
        result = await pipeline.retrieve(short_query, ["attack_kb"], top_k=top_k, context=context)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        metrics = result.retrieval_metrics or RetrievalMetrics()
        return {
            "total_ms": elapsed_ms,
            "llm_rewrite_calls": rewriter.calls or metrics.llm_rewrite_calls,
            "chunk_ids": [chunk.chunk_id for chunk in result.chunks[:5]],
        }

    listed_org = [
        ListedKnowledgeChunk(
            chunk_id="chk-0000000a",
            kb_name="org_context_kb",
            content="ops-change-bot is an approved change-window service account.",
            metadata={
                "kind": "account_role",
                "accounts": ["ops-change-bot"],
                "matched_value": "ops-change-bot",
            },
            created_at=datetime(2024, 6, 15, 9, 30, tzinfo=UTC),
        )
    ]

    async def _run_exact_org() -> dict[str, Any]:
        rewriter = _DelayedRewriter()
        retriever = _ExactOnlyRetriever(listed_org)
        pipeline = RetrievalPipeline(
            rewriter=rewriter,  # type: ignore[arg-type]
            retriever=retriever,  # type: ignore[arg-type]
            reranker=MockReranker(),
        )
        started = time.perf_counter()
        result = await pipeline.retrieve(query, ["org_context_kb"], top_k=5, context=context)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        metrics = result.retrieval_metrics or RetrievalMetrics()
        return {
            "total_ms": elapsed_ms,
            "llm_rewrite_calls": rewriter.calls,
            "chunk_ids": [chunk.chunk_id for chunk in result.chunks[:5]],
            "org_context_exact_hit": metrics.org_context_exact_hit,
            "hybrid_calls": retriever.calls,
        }

    async def _collect(factory, repeats: int) -> dict[str, Any]:
        samples: list[dict[str, Any]] = []
        for _ in range(repeats):
            samples.append(await factory())
        totals = [float(item["total_ms"]) for item in samples]
        totals.sort()
        p95_index = min(len(totals) - 1, max(0, int(round(0.95 * (len(totals) - 1)))))
        payload: dict[str, Any] = {
            "n": repeats,
            "p50_ms": statistics.median(totals),
            "p95_ms": totals[p95_index],
            "mean_llm_rewrite_calls": statistics.mean(
                float(item["llm_rewrite_calls"]) for item in samples
            ),
            "top5": samples[0]["chunk_ids"],
        }
        if "org_context_exact_hit" in samples[0]:
            payload["org_context_exact_hit"] = all(
                bool(item.get("org_context_exact_hit")) for item in samples
            )
            payload["hybrid_calls"] = samples[0]["hybrid_calls"]
        return payload

    current = await _collect(lambda: _run_rewrite(5), repeats)
    skip = await _collect(lambda: _run(skip_rewrite=True, top_k=5), repeats)
    exact = await _collect(_run_exact_org, repeats)
    topk3 = await _collect(lambda: _run(skip_rewrite=True, top_k=3), repeats)

    def _jaccard(left: list[str], right: list[str]) -> float:
        a, b = set(left), set(right)
        if not a and not b:
            return 1.0
        return len(a & b) / len(a | b)

    return {
        "banner": _BANNER,
        "arms": {
            "current_rewrite": current,
            "skip_rewrite": skip,
            "exact_only_org_context": exact,
            "top_k_3": topk3,
        },
        "top5_jaccard_skip_vs_current": _jaccard(current["top5"], skip["top5"]),
        "p95_drop_pct_skip_vs_current": (
            (current["p95_ms"] - skip["p95_ms"]) / current["p95_ms"] * 100.0
            if current["p95_ms"]
            else 0.0
        ),
    }


def _write_summary(payload: dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "summary.json"
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline",
        type=Path,
        default=_DEFAULT_BASELINE,
        help="change_windows.json path",
    )
    parser.add_argument("--repeats", type=int, default=8)
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output directory (default artifacts/org-context-ablation/<utc>)",
    )
    args = parser.parse_args()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = args.out or (_REPO_ROOT / "artifacts" / "org-context-ablation" / stamp)

    import asyncio

    accuracy = _accuracy_arms(args.baseline)
    latency = asyncio.run(_latency_arms(repeats=max(3, args.repeats)))
    summary = {
        "banner": _BANNER,
        "created_at": datetime.now(UTC).isoformat(),
        "accuracy": accuracy,
        "latency": latency,
    }
    path = _write_summary(summary, out_dir)
    print(_BANNER)
    print(f"wrote {path}")
    print(json.dumps({"accuracy": accuracy, "latency": latency["arms"]}, indent=2, default=str))


if __name__ == "__main__":
    main()
