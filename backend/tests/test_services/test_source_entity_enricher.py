"""Tests for SourceEntityEnricher (ISSUE-099)."""

from __future__ import annotations

from datetime import UTC, datetime

from app.models.enums import SourceObjectKind
from app.models.source import SourceReference
from app.services.source_entity_enricher import SourceEntityEnricher


def _ref(kind: SourceObjectKind, object_id: str) -> SourceReference:
    return SourceReference(
        source_kind=kind,
        source_product="mock_xdr",
        source_tenant_id="tenant-1",
        connector_id="conn-test",
        source_object_id=object_id,
        ingested_at=datetime.now(UTC),
    )


def test_enrich_asset_and_log_normalized_fields() -> None:
    asset_ref = _ref(SourceObjectKind.ASSET, "asset-120012")
    log_ref = _ref(SourceObjectKind.LOG, "log-880012")
    enrichment = SourceEntityEnricher.enrich_from_sources(
        [
            (
                asset_ref,
                {
                    "hostname": "DEV-WKS-012",
                    "ip": "10.60.1.10",
                    "owner": "dev-user-012",
                    "channel": "asset",
                },
            ),
            (
                log_ref,
                {
                    "hostname": "DEV-WKS-012",
                    "account": "dev-user-012",
                    "process": "ransomware_stage.exe",
                    "channel": "endpoint",
                },
            ),
        ]
    )
    hosts = {h.hostname for h in enrichment.entity_set.hosts}
    accounts = {a.username for a in enrichment.entity_set.accounts}
    processes = {p.name for p in enrichment.entity_set.processes}
    assert "DEV-WKS-012" in hosts
    assert "dev-user-012" in accounts
    assert "ransomware_stage.exe" in processes
    assert enrichment.provenance_summary


def test_enrich_secondary_host_and_domain() -> None:
    incident_ref = _ref(SourceObjectKind.INCIDENT, "INC-325")
    enrichment = SourceEntityEnricher.enrich_from_sources(
        [
            (
                incident_ref,
                {
                    "hostname": "WKS-DATA-031",
                    "secondary_host": "SRV-DB-STG-02",
                    "domain": "storage-sync-cdn.example",
                    "account": "svc-analytics-47",
                    "src_ip": "198.51.100.44",
                },
            ),
        ]
    )
    hostnames = {host.hostname for host in enrichment.entity_set.hosts if host.hostname}
    domains = {domain.fqdn for domain in enrichment.entity_set.domains if domain.fqdn}
    assert hostnames == {"WKS-DATA-031", "SRV-DB-STG-02"}
    assert "storage-sync-cdn.example" in domains
    assert "svc-analytics-47" in {acct.username for acct in enrichment.entity_set.accounts}
    assert "198.51.100.44" in {ip.address for ip in enrichment.entity_set.ips}


def test_enrich_fqdn_only_key() -> None:
    """ISSUE-325: domain seed must accept fqdn when domain key is absent."""
    incident_ref = _ref(SourceObjectKind.INCIDENT, "INC-325-fqdn")
    enrichment = SourceEntityEnricher.enrich_from_sources(
        [
            (
                incident_ref,
                {
                    "hostname": "WKS-DATA-031",
                    "fqdn": "storage-sync-cdn.example",
                },
            ),
        ]
    )
    domains = {domain.fqdn for domain in enrichment.entity_set.domains if domain.fqdn}
    assert domains == {"storage-sync-cdn.example"}


def test_enrich_does_not_duplicate_ip_on_host_and_ips() -> None:
    asset_ref = _ref(SourceObjectKind.ASSET, "asset-dedupe")
    enrichment = SourceEntityEnricher.enrich_from_sources(
        [
            (
                asset_ref,
                {
                    "hostname": "DEV-WKS-012",
                    "ip": "10.60.1.10",
                    "owner": "dev-user-012",
                },
            ),
        ]
    )
    host_ips = {h.ip for h in enrichment.entity_set.hosts if h.ip}
    ip_addresses = {ip.address for ip in enrichment.entity_set.ips}
    assert "10.60.1.10" in host_ips
    assert "10.60.1.10" not in ip_addresses
