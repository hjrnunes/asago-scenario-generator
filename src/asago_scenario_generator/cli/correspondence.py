"""Offline YAML adapters for typed correspondence proposals and decisions."""

from __future__ import annotations

from pathlib import Path

import typer

from asago_scenario_generator.cli._app import app
from asago_scenario_generator.cli._shared import (
    _abort,
    _load_payload,
    _print_banner,
    _requested_formats,
    _validate_file,
)

_ZERO_CALLS = 0


def _load_resource_map(path: Path):
    """Parse and integrity-check the normative resource-map artifact."""
    from asago_scenario_generator.models.system_resource_map import SystemResourceMap

    if path.suffix.lower() == ".json":
        return SystemResourceMap.from_json(path.read_bytes())
    return SystemResourceMap.from_yaml(path.read_bytes())


def _validated_resource_map(
    resource_map: Path,
    capability_snapshot: Path,
    control_structure: Path,
):
    """Validate a map against exact capability and control authorities."""
    from asago_scenario_generator.pipeline.projection_contracts import (
        CapabilityFactSnapshot,
    )
    from asago_scenario_generator.pipeline.system_resource_map import (
        validate_system_resource_map,
    )
    from asago_scenario_generator.stpa.models.control_structure import ControlStructure

    snapshot = CapabilityFactSnapshot.model_validate(
        _load_payload(capability_snapshot, "capability snapshot")
    )
    control = ControlStructure.model_validate(
        _load_payload(control_structure, "control structure")
    )
    return validate_system_resource_map(
        _load_resource_map(resource_map), snapshot, control
    )


def _load_proposals(path: Path):
    """Parse one canonical YAML or JSON proposal artifact."""
    from asago_scenario_generator.models.correspondence import ProposalSet

    loader = {".json": ProposalSet.from_json}.get(
        path.suffix.lower(), ProposalSet.from_yaml
    )
    return loader(path.read_bytes())


def _load_adjudications(path: Path | None):
    """Parse an optional typed adjudication artifact."""
    if path is None:
        return None
    from asago_scenario_generator.models.correspondence import AdjudicationSet

    _validate_file(path, "adjudications")
    payload = _load_payload(path, "adjudications")
    return AdjudicationSet.model_validate(payload)


def _publish(
    output_dir: Path,
    *,
    yaml_name: str,
    json_name: str,
    yaml_text: str,
    json_text: str,
    formats: tuple[str, ...],
) -> list[Path]:
    """Write the requested YAML and JSON artifacts."""
    written: list[Path] = []
    names = {"yaml": yaml_name, "json": json_name}
    texts = {"yaml": yaml_text, "json": json_text}
    for fmt in formats:
        path = output_dir / names[fmt]
        path.write_text(texts[fmt], encoding="utf-8")
        written.append(path)
    return written


def _echo_paths(label: str, written: list[Path]) -> None:
    """Print each published artifact path."""
    for path in written:
        typer.echo(f"{label} written to {path}")


def _echo_call_counts() -> None:
    """Print the pinned zero network and model call counts."""
    typer.echo(f"  Network calls: {_ZERO_CALLS}")
    typer.echo(f"  Model calls:   {_ZERO_CALLS}")


def _announce_proposal(proposal_set, written: list[Path]) -> None:
    """Print published proposal paths and call counts."""
    _echo_paths("Proposal set", written)
    typer.echo(f"  Proposals:     {len(proposal_set.proposals)}")
    _echo_call_counts()


def _announce_reconciliation(result, written: list[Path]) -> None:
    """Print published reconciliation paths and fail closed when invalid."""
    _echo_paths("Reconciliation result", written)
    typer.echo(f"  Valid:         {result.is_valid}")
    typer.echo(f"  Proposals:     {len(result.proposals)}")
    typer.echo(f"  Errors:        {len(result.errors)}")
    _echo_call_counts()
    if not result.is_valid:
        raise typer.Exit(code=1)


@app.command(name="propose-correspondence")
def propose_correspondence_cmd(
    resource_map: Path = typer.Option(
        ...,
        "--map",
        help="SystemResourceMap JSON or YAML file.",
    ),
    artifacts: Path = typer.Option(
        ...,
        "--artifacts",
        help="Source-artifact JSON or YAML file with evidence items.",
    ),
    capability_snapshot: Path = typer.Option(
        ...,
        "--capability-snapshot",
        help="Exact CapabilityFactSnapshot JSON or YAML authority.",
    ),
    control_structure: Path = typer.Option(
        ...,
        "--control-structure",
        help="Exact STPA ControlStructure JSON or YAML authority.",
    ),
    output_dir: Path = typer.Option(
        ...,
        help="Directory for published YAML and JSON proposal-set artifacts.",
    ),
    format: str = typer.Option(
        "both",
        "--format",
        help="Published artifact format: yaml, json, or both.",
    ),
) -> None:
    """Publish a deterministic correspondence proposal set.

    This is a file-to-file user-interface affordance. It is not generate
    or stpa-run and it makes no network or model calls.
    """
    from asago_scenario_generator.pipeline.correspondence import propose_correspondence

    _print_banner("propose-correspondence")
    _validate_file(resource_map, "resource map")
    _validate_file(artifacts, "source artifacts")
    _validate_file(capability_snapshot, "capability snapshot")
    _validate_file(control_structure, "control structure")
    formats = _requested_formats(format)
    try:
        proposal_set = propose_correspondence(
            _validated_resource_map(
                resource_map, capability_snapshot, control_structure
            ),
            source_artifacts=_load_payload(artifacts, "source artifacts"),
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        from asago_scenario_generator.pipeline.correspondence_persistence import (
            write_correspondence_proposals,
        )

        written = []
        if "yaml" in formats:
            written.append(write_correspondence_proposals(output_dir, proposal_set))
        if "json" in formats:
            written.extend(
                _publish(
                    output_dir,
                    yaml_name="correspondence-proposals.yaml",
                    json_name="correspondence-proposals.json",
                    yaml_text=proposal_set.to_yaml(),
                    json_text=proposal_set.to_json(),
                    formats=("json",),
                )
            )
    except Exception as exc:  # noqa: BLE001 - CLI validation boundary
        _abort(exc)
    _announce_proposal(proposal_set, written)


@app.command(name="reconcile-correspondence")
def reconcile_correspondence_cmd(
    resource_map: Path = typer.Option(
        ...,
        "--map",
        help="SystemResourceMap JSON or YAML file.",
    ),
    proposals: Path = typer.Option(
        ...,
        "--proposals",
        help="ProposalSet JSON or YAML file.",
    ),
    capability_snapshot: Path = typer.Option(
        ...,
        "--capability-snapshot",
        help="Exact CapabilityFactSnapshot JSON or YAML authority.",
    ),
    control_structure: Path = typer.Option(
        ...,
        "--control-structure",
        help="Exact STPA ControlStructure JSON or YAML authority.",
    ),
    output_dir: Path = typer.Option(
        ...,
        help="Directory for published YAML and JSON reconciliation artifacts.",
    ),
    adjudications: Path | None = typer.Option(
        None,
        "--adjudications",
        help="Optional JSON or YAML AdjudicationSet envelope with decisions[].",
    ),
    format: str = typer.Option(
        "both",
        "--format",
        help="Published artifact format: yaml, json, or both.",
    ),
) -> None:
    """Publish a deterministic correspondence reconciliation result.

    This is a file-to-file user-interface affordance. It is not generate
    or stpa-run and it makes no network or model calls. Confirmation is
    never inferred from proposal strength.
    """
    from asago_scenario_generator.pipeline.correspondence import (
        reconcile_correspondence,
    )

    _print_banner("reconcile-correspondence")
    _validate_file(resource_map, "resource map")
    _validate_file(proposals, "proposal set")
    _validate_file(capability_snapshot, "capability snapshot")
    _validate_file(control_structure, "control structure")
    formats = _requested_formats(format)
    try:
        result = reconcile_correspondence(
            _validated_resource_map(
                resource_map, capability_snapshot, control_structure
            ),
            _load_proposals(proposals),
            adjudications=_load_adjudications(adjudications),
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        from asago_scenario_generator.pipeline.correspondence_persistence import (
            write_correspondence_reconciliation,
        )

        written = []
        if "yaml" in formats:
            written.append(write_correspondence_reconciliation(output_dir, result))
        if "json" in formats:
            written.extend(
                _publish(
                    output_dir,
                    yaml_name="correspondence-reconciliation.yaml",
                    json_name="correspondence-reconciliation.json",
                    yaml_text=result.to_yaml(),
                    json_text=result.to_json(),
                    formats=("json",),
                )
            )
    except Exception as exc:  # noqa: BLE001 - CLI validation boundary
        _abort(exc)
    _announce_reconciliation(result, written)
