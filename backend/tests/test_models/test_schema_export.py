"""Schema export test (ISSUE-002 acceptance 2).

Compares the model registry to the set of exported schema files (no fixed count).
"""

from __future__ import annotations

# Import the export helper from scripts/export_schemas.py.
import importlib.util
import json
from pathlib import Path

from app.models import MODEL_REGISTRY

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "export_schemas.py"
_spec = importlib.util.spec_from_file_location("export_schemas", _SCRIPT)
assert _spec and _spec.loader
export_schemas_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(export_schemas_mod)


def test_export_writes_one_schema_per_model(tmp_path: Path) -> None:
    written = export_schemas_mod.export_schemas(tmp_path)

    model_names = set(MODEL_REGISTRY.keys())
    file_names = {p.stem for p in tmp_path.glob("*.json")}
    assert file_names == model_names, {
        "missing_files": model_names - file_names,
        "unexpected_files": file_names - model_names,
    }
    assert len(written) == len(model_names)


def test_exported_schemas_are_valid_json(tmp_path: Path) -> None:
    export_schemas_mod.export_schemas(tmp_path)
    for path in tmp_path.glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(data, dict)
        assert "properties" in data or "$ref" in data or "type" in data


def test_action_embedded_impact_assessment_matches_standalone_schema() -> None:
    """Action.json must embed the current ImpactAssessment schema (ISSUE-079)."""
    repo_root = Path(__file__).resolve().parents[3]
    action_path = repo_root / "contracts/schemas/Action.json"
    standalone_path = repo_root / "contracts/schemas/ImpactAssessment.json"
    action_schema = json.loads(action_path.read_text(encoding="utf-8"))
    standalone = json.loads(standalone_path.read_text(encoding="utf-8"))
    embedded = action_schema["$defs"]["ImpactAssessment"]
    embedded_props = embedded.get("properties", {})
    standalone_props = standalone.get("properties", {})
    assert set(embedded_props) == set(standalone_props)
    assert embedded.get("required") == standalone.get("required")
    assert "impact_level" not in embedded_props
    assert "notes" not in embedded_props
    assert "action_id" in embedded_props
    assert "business_disruption" in embedded_props
