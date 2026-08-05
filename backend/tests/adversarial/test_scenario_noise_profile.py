"""Unit checks for adversarial scenario shape (no Postgres required)."""

from __future__ import annotations

from tests.adversarial.scenario_credential_db_staging_exfil import (
    ALERT_STORM_DUPLICATES,
    DECOY_INCIDENT_COUNT,
    GROUND_TRUTH,
    INCIDENT_ID,
    NETWORK_NOISE_COUNT,
    build_adversarial_credential_db_staging_exfil,
)


def test_adversarial_scenario_has_high_noise_profile() -> None:
    scenario = build_adversarial_credential_db_staging_exfil()
    assert len(scenario.incidents) == DECOY_INCIDENT_COUNT + 1
    assert len(scenario.alerts) >= DECOY_INCIDENT_COUNT + ALERT_STORM_DUPLICATES

    noise_rows = sum(1 for row in scenario.telemetry_timeline if row.get("is_noise"))
    key_rows = sum(1 for row in scenario.telemetry_timeline if row.get("is_key_event"))
    assert noise_rows >= NETWORK_NOISE_COUNT
    assert key_rows >= 17
    assert scenario.expected_outcome["true_positive_incident_id"] == INCIDENT_ID
    assert len(scenario.expected_outcome["decoy_incident_ids"]) == DECOY_INCIDENT_COUNT
    assert GROUND_TRUTH["noise_profile"]["decoy_incidents"] == DECOY_INCIDENT_COUNT
