"""Offline file-to-file correspondence proposal and reconciliation commands."""

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
_MAP_COLLECTIONS = (
    "system_resources",
    "control_actions",
    "loss_links",
    "trust_boundaries",
    "actor_controllers",
    "controlled_processes",
)


def _typed_resource_map(payload: dict):
    """Return a typed map when the payload carries map collections."""
    from asago_scenario_generator.models.system_resource_map import SystemResourceMap

    if any(key in payload for key in _MAP_COLLECTIONS):
        return SystemResourceMap.model_validate(payload)
    return payload


def _load_resource_map(path: Path):
    """Parse a resource map or snapshot fixture from JSON or YAML."""
    return _typed_resource_map(_load_payload(path, "resource map"))


def _load_adjudications(path: Path | None) -> dict[str, str]:
    """Parse an optional proposal-id to adjudication mapping."""
    if path is None:
        return {}
    _validate_file(path, "adjudications")
    payload = _load_payload(path, "adjudications")
    return {str(key): str(value) for key, value in payload.items()}


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
    formats = _requested_formats(format)
    try:
        proposal_set = propose_correspondence(
            _load_resource_map(resource_map),
            source_artifacts=_load_payload(artifacts, "source artifacts"),
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        written = _publish(
            output_dir,
            yaml_name="proposal-set.yaml",
            json_name="proposal-set.json",
            yaml_text=proposal_set.to_yaml(),
            json_text=proposal_set.to_json(),
            formats=formats,
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
    output_dir: Path = typer.Option(
        ...,
        help="Directory for published YAML and JSON reconciliation artifacts.",
    ),
    adjudications: Path | None = typer.Option(
        None,
        "--adjudications",
        help="Optional JSON or YAML mapping of proposal id to adjudication.",
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
    from asago_scenario_generator.models.correspondence import ProposalSet
    from asago_scenario_generator.pipeline.correspondence import (
        reconcile_correspondence,
    )

    _print_banner("reconcile-correspondence")
    _validate_file(resource_map, "resource map")
    _validate_file(proposals, "proposal set")
    formats = _requested_formats(format)
    try:
        result = reconcile_correspondence(
            _load_resource_map(resource_map),
            ProposalSet.model_validate(_load_payload(proposals, "proposal set")),
            adjudications=_load_adjudications(adjudications),
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        written = _publish(
            output_dir,
            yaml_name="reconciliation-result.yaml",
            json_name="reconciliation-result.json",
            yaml_text=result.to_yaml(),
            json_text=result.to_json(),
            formats=formats,
        )
    except Exception as exc:  # noqa: BLE001 - CLI validation boundary
        _abort(exc)
    _announce_reconciliation(result, written)
