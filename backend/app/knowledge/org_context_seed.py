"""Python-only org_context_kb seed. Production stays empty; mock/demo gets a few rows."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from app.core.config import Settings, is_mock_source_mode
from app.models.knowledge import GLOBAL_KB_TENANT_ID, ORG_CONTEXT_KB_NAME, KnowledgeChunk

logger = logging.getLogger(__name__)

OrgContextKind = Literal[
    "allowed_destination",
    "allowed_source",
    "time_window",
    "account_role",
    "person_status",
    "data_handling",
    "security_product",
]

ORG_CONTEXT_KINDS: frozenset[str] = frozenset(
    {
        "allowed_destination",
        "allowed_source",
        "time_window",
        "account_role",
        "person_status",
        "data_handling",
        "security_product",
    }
)


@dataclass(frozen=True, slots=True)
class OrgContextRecord:
    """One operational fact. ``content`` is the analyst-facing explanation sentence."""

    record_id: str
    kind: OrgContextKind
    content: str
    domains: tuple[str, ...] = ()
    cidrs: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    accounts: tuple[str, ...] = ()
    window_start: str | None = None
    window_end: str | None = None
    role: str | None = None
    status: str | None = None
    data_class: str | None = None
    allowed_channels: tuple[str, ...] = field(default_factory=tuple)

    def metadata(self) -> dict[str, Any]:
        meta: dict[str, Any] = {
            "kind": self.kind,
            "record_id": self.record_id,
        }
        if self.domains:
            meta["domains"] = list(self.domains)
        if self.cidrs:
            meta["cidrs"] = list(self.cidrs)
        if self.ips:
            meta["ips"] = list(self.ips)
        if self.hosts:
            meta["hosts"] = list(self.hosts)
        if self.accounts:
            meta["accounts"] = list(self.accounts)
        if self.window_start:
            meta["window_start"] = self.window_start
        if self.window_end:
            meta["window_end"] = self.window_end
        if self.role:
            meta["role"] = self.role
        if self.status:
            meta["status"] = self.status
        if self.data_class:
            meta["data_class"] = self.data_class
        if self.allowed_channels:
            meta["allowed_channels"] = list(self.allowed_channels)
        return meta

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> OrgContextRecord:
        kind = str(raw.get("kind") or "")
        if kind not in ORG_CONTEXT_KINDS:
            raise ValueError(f"unsupported org_context kind: {kind!r}")
        return cls(
            record_id=str(raw["record_id"]),
            kind=kind,  # type: ignore[arg-type]
            content=str(raw.get("content") or ""),
            domains=_as_str_tuple(raw.get("domains")),
            cidrs=_as_str_tuple(raw.get("cidrs")),
            ips=_as_str_tuple(raw.get("ips")),
            hosts=_as_str_tuple(raw.get("hosts")),
            accounts=_as_str_tuple(raw.get("accounts")),
            window_start=_optional_str(raw.get("window_start")),
            window_end=_optional_str(raw.get("window_end")),
            role=_optional_str(raw.get("role")),
            status=_optional_str(raw.get("status")),
            data_class=_optional_str(raw.get("data_class")),
            allowed_channels=_as_str_tuple(raw.get("allowed_channels")),
        )


def org_context_chunk_id(record_id: str) -> str:
    digest = hashlib.sha256(f"{ORG_CONTEXT_KB_NAME}:{record_id}".encode()).hexdigest()
    return f"chk-{digest[:8]}"


def records_to_chunks(records: list[OrgContextRecord]) -> list[KnowledgeChunk]:
    chunks: list[KnowledgeChunk] = []
    for record in records:
        metadata = record.metadata()
        metadata.setdefault("tenant_id", GLOBAL_KB_TENANT_ID)
        chunks.append(
            KnowledgeChunk(
                chunk_id=org_context_chunk_id(record.record_id),
                kb_name=ORG_CONTEXT_KB_NAME,
                content=record.content,
                metadata=metadata,
            )
        )
    return chunks


async def seed_org_context_store(store: Any, settings: Settings | None = None) -> int:
    """Upsert seed rows. Call from bootstrap/fixtures, never from the FP hot path."""
    chunks = records_to_chunks(records_for_settings(settings))
    if chunks:
        await store.upsert_chunks(ORG_CONTEXT_KB_NAME, chunks)
    return len(chunks)


def production_org_context_records() -> list[OrgContextRecord]:
    """Customer production ships zero business-policy rows until they seed their own."""
    return []


def mock_org_context_records() -> list[OrgContextRecord]:
    """Small Mock XDR / demo facts. Not enterprise policy text."""
    return [
        OrgContextRecord(
            record_id="org-dest-files-corp-internal",
            kind="allowed_destination",
            content="files.corp.internal 是集团批准的内部文件服务器对端，业务同步可传到该域名。",
            domains=("files.corp.internal",),
        ),
        OrgContextRecord(
            record_id="org-src-vuln-scanner",
            kind="allowed_source",
            content="vuln-scanner-01（10.20.0.15）是批准的漏洞扫描源主机，其探测流量属于预期扫描。",
            hosts=("vuln-scanner-01",),
            ips=("10.20.0.15",),
            cidrs=("10.20.0.0/24",),
        ),
        OrgContextRecord(
            record_id="org-window-nightly-backup",
            kind="time_window",
            content=(
                "每日 02:00-04:00 UTC 为批准的夜间备份窗口，"
                "该时段 svc-backup 对 files.corp.internal 的批量传输常见于备份作业。"
            ),
            domains=("files.corp.internal",),
            accounts=("svc-backup",),
            window_start="02:00",
            window_end="04:00",
        ),
        OrgContextRecord(
            record_id="org-acct-svc-backup",
            kind="account_role",
            content="svc-backup 是备份服务账号，非交互式登录与批量文件复制属该角色预期行为。",
            accounts=("svc-backup",),
            role="service",
        ),
        OrgContextRecord(
            record_id="org-sec-carbonblack",
            kind="security_product",
            content="carbonblack.corp.internal 是已知安全产品通信对端，终端管理流量可出现该域名。",
            domains=("carbonblack.corp.internal",),
        ),
        OrgContextRecord(
            record_id="org-person-contractor-temp",
            kind="person_status",
            content="contractor-temp 在演示切片中标记为已离职，其账号继续活动需要人工核对。",
            accounts=("contractor-temp",),
            status="departed",
        ),
        OrgContextRecord(
            record_id="org-data-confidential-fileshare",
            kind="data_handling",
            content=(
                "机密级数据的批准通道是集团内部文件服务器 files.corp.internal，"
                "不表示可发往任意外网。"
            ),
            domains=("files.corp.internal",),
            data_class="confidential",
            allowed_channels=("files.corp.internal",),
        ),
        OrgContextRecord(
            record_id="org-acct-ops-change-bot",
            kind="account_role",
            content=(
                "ops-change-bot 是变更窗口内的运维改密服务账号，"
                "经跳板机 PC-OPS-JUMP-01 批量登录属该角色预期行为。"
            ),
            accounts=("ops-change-bot",),
            hosts=("PC-OPS-JUMP-01",),
            role="service",
        ),
        OrgContextRecord(
            record_id="org-src-ops-jump",
            kind="allowed_source",
            content=(
                "PC-OPS-JUMP-01 是批准的运维跳板机，"
                "ops-change-bot 从该主机发起的改密登录属于预期运维。"
            ),
            hosts=("PC-OPS-JUMP-01",),
            accounts=("ops-change-bot",),
        ),
        OrgContextRecord(
            record_id="org-dest-unknown-upload-unapproved",
            kind="data_handling",
            content=(
                "unknown-upload-example.com 不是批准外发对端；财务压缩包 finance_report.zip "
                "不得发往该域名，批准通道仍是 files.corp.internal。"
            ),
            domains=("unknown-upload-example.com",),
            data_class="confidential",
            allowed_channels=("files.corp.internal",),
        ),
        OrgContextRecord(
            record_id="org-dest-cdn-corp-internal",
            kind="allowed_destination",
            content="cdn.corp.internal 是已登记内部内容分发对端。",
            domains=("cdn.corp.internal",),
        ),
        OrgContextRecord(
            record_id="org-dest-cdn-unapproved",
            kind="data_handling",
            content=(
                "brand-new-cdn-example.net 不是已登记内容分发对端；"
                "批准内部 CDN 仍是 cdn.corp.internal。"
            ),
            domains=("brand-new-cdn-example.net",),
            allowed_channels=("cdn.corp.internal",),
        ),
    ]


def records_for_settings(settings: Settings | None = None) -> list[OrgContextRecord]:
    cfg = settings or Settings()
    file_records = _load_seed_path(cfg.org_context_seed_path)
    if is_mock_source_mode(cfg.source_mode):
        return _merge_records(mock_org_context_records(), file_records)
    return file_records or production_org_context_records()


def _load_seed_path(raw_path: str) -> list[OrgContextRecord]:
    path_text = (raw_path or "").strip()
    if not path_text:
        return []
    path = Path(path_text)
    if not path.is_file():
        logger.warning("ORG_CONTEXT_SEED_PATH is not a file: %s", path)
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("ORG_CONTEXT_SEED_PATH could not be read: %s", exc)
        return []
    rows = payload.get("records") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        logger.warning("ORG_CONTEXT_SEED_PATH must be a list or {records: [...]}")
        return []
    records: list[OrgContextRecord] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        try:
            records.append(OrgContextRecord.from_mapping(item))
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("Skipping invalid org_context seed row: %s", exc)
    return records


def _merge_records(
    base: list[OrgContextRecord],
    extra: list[OrgContextRecord],
) -> list[OrgContextRecord]:
    by_id = {record.record_id: record for record in base}
    for record in extra:
        by_id[record.record_id] = record
    return list(by_id.values())


def _as_str_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,) if value.strip() else ()
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value if str(item).strip())
    return ()


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
