"""Export ISSUE-086 minimal scenario packs to ``data/scenarios/``."""

from __future__ import annotations

from pathlib import Path

from app.data_generators.scenarios import (
    SCENARIO_BUILDERS,
    build_scenario,
    write_scenario_artifacts,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_ROOT = REPO_ROOT / "data" / "scenarios"

NEW_SCENARIO_IDS = (
    "host_compromise",
    "malicious_process",
    "insider_privilege_abuse",
    "lateral_movement",
    "other_unclassified",
)


def main() -> None:
    for scenario_id in NEW_SCENARIO_IDS:
        if scenario_id not in SCENARIO_BUILDERS:
            raise SystemExit(f"missing builder for {scenario_id}")
        scenario = build_scenario(scenario_id, seed=42)
        target = OUT_ROOT / scenario_id
        written = write_scenario_artifacts(scenario, target, write_scenario_json=True)
        print(f"Wrote {len(written)} files under {target}")


if __name__ == "__main__":
    main()
