"""Validation and adapter tests for the normative resource-map seam."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from tests.cli_helpers import PlainCliRunner

from asago_scenario_generator.cli import app
from asago_scenario_generator.models.system_resource_map import (
    SystemResourceMap,
    SystemResourceMapValidation,
    compute_control_structure_digest,
)
from asago_scenario_generator.pipeline.system_resource_map import (
    validate_system_resource_map,
)
from tests.system_resource_map_support import (
    ENTRY_POINT,
    TOOL,
    make_control_structure,
    make_link,
    make_map,
    make_snapshot,
)

runner = PlainCliRunner()


def _write_inputs(directory: Path, resource_map: SystemResourceMap) -> tuple[Path, ...]:
    """Write typed CLI inputs in the same formats the public adapter reads."""
    snapshot = make_snapshot()
    control = make_control_structure()
    map_path = directory / "system-resource-map.yaml"
    snapshot_path = directory / "capability-fact-snapshot.yaml"
    control_path = directory / "control-structure.yaml"
    map_path.write_text(resource_map.to_yaml(), encoding="utf-8")
    snapshot_path.write_text(
        yaml.safe_dump(snapshot.model_dump(mode="json"), sort_keys=True),
        encoding="utf-8",
    )
    control_path.write_text(
        yaml.safe_dump(control.model_dump(mode="json"), sort_keys=True),
        encoding="utf-8",
    )
    return map_path, snapshot_path, control_path


def test_valid_map_has_no_violations_or_correspondence_side_effects() -> None:
    snapshot = make_snapshot()
    control = make_control_structure()
    result = validate_system_resource_map(make_map(), snapshot, control)

    assert result.is_valid
    assert result.violations == ()
    assert result.warnings == ()
    assert result.canonical_map == make_map()
    assert result.entry_point_completeness == "inferred_partial"
    assert result.tool_inventory_completeness == "inferred_partial"
    assert result.network_calls == 0
    assert result.model_calls == 0
    assert set(result.model_dump(mode="json")) == {
        "is_valid",
        "violations",
        "warnings",
        "canonical_map",
        "entry_point_completeness",
        "tool_inventory_completeness",
        "network_calls",
        "model_calls",
    }

    with pytest.raises(ValueError, match="inventory completeness"):
        SystemResourceMapValidation(is_valid=True, canonical_map=make_map())
    SystemResourceMapValidation(is_valid=True)
    SystemResourceMapValidation(is_valid=False, canonical_map=make_map())
    with pytest.raises(ValueError, match="inventory completeness"):
        SystemResourceMapValidation(
            is_valid=True,
            canonical_map=make_map(),
            entry_point_completeness="inferred_partial",
        )
    with pytest.raises(ValueError, match="inventory completeness"):
        SystemResourceMapValidation(
            is_valid=True,
            canonical_map=make_map(),
            tool_inventory_completeness="inferred_partial",
        )


@pytest.mark.parametrize(
    ("field", "expected_code"),
    [
        ("semantic_digest", "semantic_digest_mismatch"),
        ("capability_snapshot_digest", "capability_snapshot_digest_mismatch"),
        ("control_structure_digest", "control_structure_digest_mismatch"),
    ],
)
def test_digest_pin_substitution_fails_closed(field: str, expected_code: str) -> None:
    resource_map = make_map()
    changed = resource_map.model_copy(update={field: "f" * 64})

    result = validate_system_resource_map(
        changed,
        make_snapshot(),
        make_control_structure(),
    )

    assert not result.is_valid
    assert expected_code in {issue.code for issue in result.violations}


def test_snapshot_integrity_substitution_is_reported_without_repair() -> None:
    snapshot = make_snapshot().model_copy(update={"snapshot_digest": "f" * 64})

    result = validate_system_resource_map(
        make_map(), snapshot, make_control_structure()
    )

    codes = {issue.code for issue in result.violations}
    assert "invalid_capability_snapshot" in codes
    assert "capability_snapshot_digest_mismatch" in codes
    assert result.canonical_map is None


def test_unknown_capability_and_control_references_are_typed_violations() -> None:
    snapshot = make_snapshot()
    control = make_control_structure()

    unknown_resource = make_map(
        make_link(
            capability_resource_ref={
                "kind": "tool",
                "tool_id": "tool:v1:" + "f" * 32,
            }
        )
    )
    result = validate_system_resource_map(unknown_resource, snapshot, control)
    assert "unknown_capability_resource" in {issue.code for issue in result.violations}
    assert result.unresolved == ("srm:v1:1",)

    unknown_control = make_map(
        make_link(control_structure_ref={"kind": "CA", "id": "CA-9-9"})
    )
    result = validate_system_resource_map(unknown_control, snapshot, control)
    assert "unknown_control_structure_reference" in {
        issue.code for issue in result.violations
    }


def test_invalid_control_namespace_is_rejected_by_closed_model() -> None:
    with pytest.raises(ValidationError):
        make_link(control_structure_ref={"kind": "CA", "id": "CP-1"})


def test_relation_compatibility_is_validated_independently_of_endpoint_existence() -> (
    None
):
    link = make_link(
        relation_kind="coordinates_via",
        control_structure_ref={"kind": "CA", "id": "CA-1-1"},
        capability_resource_ref={"kind": "entry_point", "entry_point_id": ENTRY_POINT},
    )
    result = validate_system_resource_map(
        make_map(link), make_snapshot(), make_control_structure()
    )

    assert "incompatible_relation_kind" in {issue.code for issue in result.violations}


def test_authority_requires_evidence_and_rejects_model_proposals() -> None:
    snapshot = make_snapshot()
    control = make_control_structure()

    no_evidence = make_map(make_link(evidence_refs=()))
    result = validate_system_resource_map(no_evidence, snapshot, control)
    assert "authoritative_link_without_evidence" in {
        issue.code for issue in result.violations
    }

    model_authoritative = make_map(make_link(provenance="model_proposed"))
    result = validate_system_resource_map(model_authoritative, snapshot, control)
    assert "model_proposed_authoritative" in {issue.code for issue in result.violations}


def test_model_proposed_advisory_link_is_preserved_and_valid() -> None:
    resource_map = make_map(
        make_link(
            provenance="model_proposed",
            authority_status="advisory",
            evidence_refs=(),
        )
    )

    result = validate_system_resource_map(
        resource_map, make_snapshot(), make_control_structure()
    )

    assert result.is_valid
    assert result.links_by_authority == {"advisory": ("srm:v1:1",)}


def test_duplicate_semantic_links_and_unstable_ids_are_rejected() -> None:
    duplicate = make_map(
        make_link(link_id="srm:v1:1"),
        make_link(link_id="srm:v1:2"),
    )
    result = validate_system_resource_map(
        duplicate, make_snapshot(), make_control_structure()
    )
    assert "duplicate_semantic_link" in {issue.code for issue in result.violations}

    unstable = make_map(make_link(link_id="idx-0"))
    result = validate_system_resource_map(
        unstable, make_snapshot(), make_control_structure()
    )
    assert "unstable_identifier" in {issue.code for issue in result.violations}


def test_declared_represents_cardinality_rejects_conflicting_targets() -> None:
    conflicting = make_map(
        make_link(
            link_id="srm:v1:2",
            relation_kind="represents",
            control_structure_ref={"kind": "CP", "id": "CP-1"},
            capability_resource_ref={
                "kind": "entry_point",
                "entry_point_id": ENTRY_POINT,
            },
        ),
        make_link(
            link_id="srm:v1:3",
            relation_kind="represents",
            control_structure_ref={"kind": "CP", "id": "CP-1"},
            capability_resource_ref={"kind": "tool", "tool_id": TOOL},
        ),
    )

    result = validate_system_resource_map(
        conflicting, make_snapshot(), make_control_structure()
    )

    assert "contradictory_authoritative_link" in {
        issue.code for issue in result.violations
    }


def test_validator_rejects_non_typed_inputs_at_the_public_seam() -> None:
    with pytest.raises(TypeError):
        validate_system_resource_map(  # type: ignore[arg-type]
            {},
            make_snapshot(),
            make_control_structure(),
        )
    with pytest.raises(TypeError):
        validate_system_resource_map(  # type: ignore[arg-type]
            make_map(),
            {},
            make_control_structure(),
        )


def test_cli_writes_typed_diagnostics_and_canonical_artifact(tmp_path: Path) -> None:
    map_path, snapshot_path, control_path = _write_inputs(tmp_path, make_map())
    output_dir = tmp_path / "output"

    result = runner.invoke(
        app,
        [
            "validate-system-resource-map",
            "--map",
            str(map_path),
            "--capability-snapshot",
            str(snapshot_path),
            "--control-structure",
            str(control_path),
            "--output-dir",
            str(output_dir),
            "--format",
            "both",
        ],
    )

    assert result.exit_code == 0, result.stdout
    diagnostic = yaml.safe_load(
        (output_dir / "system-resource-map-validation.yaml").read_text(encoding="utf-8")
    )
    assert diagnostic["is_valid"] is True
    assert diagnostic["violations"] == []
    assert (output_dir / "system-resource-map-validation.json").is_file()
    assert (output_dir / "system-resource-map.yaml").is_file()


def test_cli_reports_invalid_map_without_publishing_canonical_artifact(
    tmp_path: Path,
) -> None:
    invalid = make_map(
        make_link(
            capability_resource_ref={
                "kind": "tool",
                "tool_id": "tool:v1:" + "f" * 32,
            }
        )
    )
    map_path, snapshot_path, control_path = _write_inputs(tmp_path, invalid)
    output_dir = tmp_path / "output"

    result = runner.invoke(
        app,
        [
            "validate-system-resource-map",
            "--map",
            str(map_path),
            "--capability-snapshot",
            str(snapshot_path),
            "--control-structure",
            str(control_path),
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 1
    diagnostic = yaml.safe_load(
        (output_dir / "system-resource-map-validation.yaml").read_text(encoding="utf-8")
    )
    assert diagnostic["is_valid"] is False
    assert any(
        issue["code"] == "unknown_capability_resource"
        for issue in diagnostic["violations"]
    )
    assert not (output_dir / "system-resource-map.yaml").exists()


def test_cli_accepts_json_inputs_and_json_diagnostics(tmp_path: Path) -> None:
    resource_map = make_map()
    snapshot = make_snapshot()
    control = make_control_structure()
    map_path = tmp_path / "system-resource-map.json"
    snapshot_path = tmp_path / "capability-fact-snapshot.json"
    control_path = tmp_path / "control-structure.json"
    map_path.write_text(resource_map.to_json(), encoding="utf-8")
    snapshot_path.write_text(
        json.dumps(snapshot.model_dump(mode="json")), encoding="utf-8"
    )
    control_path.write_text(
        json.dumps(control.model_dump(mode="json")), encoding="utf-8"
    )

    output_dir = tmp_path / "output"
    result = runner.invoke(
        app,
        [
            "validate-system-resource-map",
            "--map",
            str(map_path),
            "--capability-snapshot",
            str(snapshot_path),
            "--control-structure",
            str(control_path),
            "--output-dir",
            str(output_dir),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.stdout
    diagnostic = json.loads(
        (output_dir / "system-resource-map-validation.json").read_text(encoding="utf-8")
    )
    assert diagnostic["is_valid"] is True
    assert not (output_dir / "system-resource-map-validation.yaml").exists()


def test_cli_rejects_invalid_format_and_missing_inputs(tmp_path: Path) -> None:
    map_path, snapshot_path, control_path = _write_inputs(tmp_path, make_map())
    invalid_format = runner.invoke(
        app,
        [
            "validate-system-resource-map",
            "--map",
            str(map_path),
            "--capability-snapshot",
            str(snapshot_path),
            "--control-structure",
            str(control_path),
            "--output-dir",
            str(tmp_path / "format"),
            "--format",
            "xml",
        ],
    )
    assert invalid_format.exit_code != 0
    assert "yaml" in (invalid_format.stdout + invalid_format.stderr).lower()

    missing_snapshot = tmp_path / "missing-snapshot.yaml"
    missing = runner.invoke(
        app,
        [
            "validate-system-resource-map",
            "--map",
            str(map_path),
            "--capability-snapshot",
            str(missing_snapshot),
            "--control-structure",
            str(control_path),
            "--output-dir",
            str(tmp_path / "missing"),
        ],
    )
    assert missing.exit_code != 0
    assert "capability snapshot not found" in (missing.stdout + missing.stderr).lower()


def test_control_structure_digest_is_order_independent_for_nested_collections() -> None:
    first = make_control_structure()
    second = make_control_structure()
    second.responsibilities[0].process_model_parts.reverse()
    second.responsibilities[0].control_actions.reverse()

    assert compute_control_structure_digest(first) == compute_control_structure_digest(
        second
    )
