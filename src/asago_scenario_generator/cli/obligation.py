"""Thin file adapter for the authoritative taxonomy obligation planner."""

from __future__ import annotations

from pathlib import Path

import typer

from asago_scenario_generator.cli._app import app
from asago_scenario_generator.cli._shared import (
    _abort,
    _load_payload,
    _print_banner,
    _validate_file,
)
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.pipeline.obligation_contracts import (
    TaxonomyObligationInputs,
)
from asago_scenario_generator.pipeline.obligation_persistence import (
    write_taxonomy_obligation_plan,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)


def run_plan_obligations(
    snapshot_path: Path,
    output_dir: Path,
    format_name: str = "yaml",
) -> tuple[TaxonomyObligationPlan, list[Path]]:
    """Load complete typed inputs, plan, and publish one validated YAML artifact."""
    _validate_file(snapshot_path, "obligation inputs")
    if format_name.lower() != "yaml":
        raise ValueError(
            "Phase 1 persistence publishes only taxonomy-obligation-plan.yaml"
        )
    payload = _load_payload(snapshot_path, "obligation inputs")
    inputs = TaxonomyObligationInputs.model_validate(payload)
    plan = plan_taxonomy_obligations(inputs)
    return plan, [write_taxonomy_obligation_plan(output_dir, plan)]


@app.command(name="plan-obligations")
def plan_obligations_cmd(
    snapshot: Path = typer.Option(
        ...,
        help="Complete typed taxonomy-obligation input JSON or YAML file.",
    ),
    output_dir: Path = typer.Option(
        ...,
        help="Directory for the published YAML plan artifact.",
    ),
    format: str = typer.Option(
        "yaml",
        "--format",
        help="Published artifact format (only yaml is supported).",
    ),
) -> None:
    """Publish a deterministic obligation plan from complete typed inputs."""
    _print_banner("plan-obligations")
    try:
        plan, written = run_plan_obligations(snapshot, output_dir, format)
    except Exception as exc:  # noqa: BLE001 - CLI validation boundary
        _abort(exc)
    for path in written:
        typer.echo(f"Obligation plan written to {path}")
    typer.echo(f"  Obligations:   {len(plan.obligations)}")
    typer.echo("  Network calls: 0")
    typer.echo("  Model calls:   0")


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-28T14:19:21Z","module_hash":"a0a57bfc4c15c58a3ce60058fc07eb534dff21ffbdc5a81d8c47499f8c15b28d","source_sha256":"ad76ceedc1f33355b30f00e0eb99ebd8e1849a6a1aa96a46cda978f096cbbda6","functions":[{"id":"func/run_plan_obligations","name":"run_plan_obligations","line":28,"end_line":42,"hash":"22e8bc5835a711687194fb9a63d282ad2af3299c49e8813b904f9e6444fe1c24"},{"id":"func/plan_obligations_cmd","name":"plan_obligations_cmd","line":46,"end_line":71,"hash":"0ec604a882f8022c88c248c04322da4607c3df2d7214ba9c7cbc7c9eaea22746"}]}
# mutate4py-manifest-end
