"""Offline file-to-file system resource map validator command."""

from __future__ import annotations

import json
from pathlib import Path

import typer
import yaml

from asago_scenario_generator.cli._app import app
from asago_scenario_generator.cli._shared import _abort, _print_banner, _validate_file


def _load_payload(path: Path, label: str) -> dict:
    """Parse a snapshot or map with a standard JSON or YAML reader."""
    text = path.read_text(encoding="utf-8")
    payload = (
        json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
    )
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON or YAML object")
    return payload


def _requested_formats(fmt: str) -> tuple[str, ...]:
    """Return the published artifact formats requested by the user."""
    normalized = fmt.lower()
    if normalized == "yaml":
        return ("yaml",)
    if normalized == "json":
        return ("json",)
    if normalized == "both":
        return ("yaml", "json")
    raise typer.BadParameter("must be 'yaml', 'json', or 'both'", param_hint="--format")


def _dump_result(payload: dict, fmt: str) -> str:
    """Serialize a validation result with a standard JSON or YAML writer."""
    if fmt == "json":
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"
    return yaml.dump(
        payload,
        default_flow_style=False,
        sort_keys=True,
        allow_unicode=True,
    )


def _normalized_hint(context_hint: str | None) -> str | None:
    """Treat a blank context hint as omitted."""
    if context_hint is None:
        return None
    stripped = context_hint.strip()
    return stripped or None


def _write_artifact(path: Path, text: str, written: list[Path]) -> None:
    """Write one published artifact and record its path."""
    path.write_text(text, encoding="utf-8")
    written.append(path)


def _publish_validation(
    output_dir: Path, payload: dict, formats: tuple[str, ...]
) -> list[Path]:
    """Publish the validation result in the requested formats."""
    written: list[Path] = []
    names = {
        "yaml": "resource-map-validation.yaml",
        "json": "resource-map-validation.json",
    }
    for fmt in formats:
        _write_artifact(output_dir / names[fmt], _dump_result(payload, fmt), written)
    return written


def _publish_canonical(
    output_dir: Path, canonical, formats: tuple[str, ...]
) -> list[Path]:
    """Publish the canonical map when validation succeeds."""
    written: list[Path] = []
    if canonical is None:
        return written
    if "yaml" in formats:
        _write_artifact(output_dir / "resource-map.yaml", canonical.to_yaml(), written)
    if "json" in formats:
        _write_artifact(output_dir / "resource-map.json", canonical.to_json(), written)
    return written


def _announce(result, written: list[Path]) -> None:
    """Print published paths and call counts, then fail closed when invalid."""
    for path in written:
        typer.echo(f"Resource map artifact written to {path}")
    typer.echo(f"  Valid:         {result.is_valid}")
    typer.echo(f"  Errors:        {len(result.errors)}")
    typer.echo(f"  Warnings:      {len(result.warnings)}")
    typer.echo(f"  Network calls: {result.network_calls}")
    typer.echo(f"  Model calls:   {result.model_calls}")
    if not result.is_valid:
        raise typer.Exit(code=1)


@app.command(name="validate-resource-map")
def validate_resource_map_cmd(
    snapshot: Path = typer.Option(
        ...,
        help="Pinned resource-map snapshot JSON or YAML file.",
    ),
    resource_map: Path = typer.Option(
        ...,
        "--map",
        help="SystemResourceMap JSON or YAML file to validate.",
    ),
    output_dir: Path = typer.Option(
        ...,
        help="Directory for published validation and canonical map artifacts.",
    ),
    format: str = typer.Option(
        "both",
        "--format",
        help="Published artifact format: yaml, json, or both.",
    ),
    context_hint: str | None = typer.Option(
        None,
        "--context-hint",
        help="Optional validation context hint (for example dangling_reference).",
    ),
) -> None:
    """Validate a SystemResourceMap against a pinned snapshot.

    This is a file-to-file user-interface affordance. It is not generate
    or stpa-run and it makes no network or model calls.
    """
    from asago_scenario_generator.pipeline.system_resource_map import (
        validate_resource_map,
    )

    _print_banner("validate-resource-map")
    _validate_file(snapshot, "resource-map snapshot")
    _validate_file(resource_map, "resource map")
    formats = _requested_formats(format)
    try:
        result = validate_resource_map(
            _load_payload(resource_map, "resource map"),
            _load_payload(snapshot, "resource-map snapshot"),
            context_hint=_normalized_hint(context_hint),
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        payload = result.model_dump(mode="json")
        payload.pop("canonical_map", None)
        written = _publish_validation(output_dir, payload, formats)
        written.extend(_publish_canonical(output_dir, result.canonical_map, formats))
    except Exception as exc:  # noqa: BLE001 - CLI validation boundary
        _abort(exc)
    _announce(result, written)
