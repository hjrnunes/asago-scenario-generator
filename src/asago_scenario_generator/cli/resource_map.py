"""Optional file adapter for the typed system-resource-map validator."""

from __future__ import annotations

import json
from pathlib import Path

import typer
import yaml

from asago_scenario_generator.cli._app import app
from asago_scenario_generator.cli._shared import (
    _abort,
    _load_payload,
    _print_banner,
    _requested_formats,
    _validate_file,
)
from asago_scenario_generator.models.system_resource_map import SystemResourceMap
from asago_scenario_generator.pipeline.projection_contracts import (
    CapabilityFactSnapshot,
)
from asago_scenario_generator.pipeline.system_resource_map import (
    validate_system_resource_map,
)
from asago_scenario_generator.pipeline.system_resource_map_persistence import (
    write_system_resource_map,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure


def _dump_result(payload: dict, fmt: str) -> str:
    """Serialize diagnostics with a deterministic standard writer."""
    if fmt == "json":
        return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    return yaml.dump(
        payload,
        default_flow_style=False,
        sort_keys=True,
        allow_unicode=True,
    )


def _load_resource_map(path: Path) -> SystemResourceMap:
    """Read a resource map through its closed model contract."""
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return SystemResourceMap.from_json(text)
    return SystemResourceMap.from_yaml(text)


def _write_diagnostics(
    output_dir: Path, payload: dict, formats: tuple[str, ...]
) -> list[Path]:
    """Publish validation diagnostics in requested formats."""
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for fmt in formats:
        path = output_dir / f"system-resource-map-validation.{fmt}"
        path.write_text(_dump_result(payload, fmt), encoding="utf-8")
        written.append(path)
    return written


@app.command(name="validate-system-resource-map")
def validate_system_resource_map_cmd(
    resource_map: Path = typer.Option(
        ...,
        "--map",
        help="system-resource-map-v1 YAML or JSON file.",
    ),
    capability_snapshot: Path = typer.Option(
        ...,
        "--capability-snapshot",
        "--snapshot",
        help="Complete CapabilityFactSnapshot YAML or JSON file.",
    ),
    control_structure: Path = typer.Option(
        ...,
        "--control-structure",
        help="STPA ControlStructure YAML or JSON file.",
    ),
    output_dir: Path = typer.Option(
        ...,
        help="Directory for validation diagnostics and canonical map artifact.",
    ),
    format: str = typer.Option(
        "yaml",
        "--format",
        help="Diagnostic format: yaml, json, or both.",
    ),
) -> None:
    """Validate and optionally publish one typed resource-map sidecar."""
    _print_banner("validate-system-resource-map")
    _validate_file(resource_map, "system resource map")
    _validate_file(capability_snapshot, "capability snapshot")
    _validate_file(control_structure, "control structure")
    formats = _requested_formats(format)
    try:
        resource_map_model = _load_resource_map(resource_map)
        capability_model = CapabilityFactSnapshot.model_validate(
            _load_payload(capability_snapshot, "capability snapshot")
        )
        control_model = ControlStructure.model_validate(
            _load_payload(control_structure, "control structure")
        )
        result = validate_system_resource_map(
            resource_map_model, capability_model, control_model
        )
        payload = result.model_dump(mode="json", exclude={"canonical_map"})
        written = _write_diagnostics(output_dir, payload, formats)
        if result.is_valid:
            written.append(write_system_resource_map(output_dir, result.canonical_map))
    except Exception as exc:  # noqa: BLE001 - CLI validation boundary
        _abort(exc)
    for path in written:
        typer.echo(f"System resource map artifact written to {path}")
    typer.echo(f"  Valid:         {result.is_valid}")
    typer.echo(f"  Violations:    {len(result.violations)}")
    typer.echo(f"  Network calls: {result.network_calls}")
    typer.echo(f"  Model calls:   {result.model_calls}")
    if not result.is_valid:
        raise typer.Exit(code=1)


__all__ = ["validate_system_resource_map_cmd"]
