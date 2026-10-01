"""Acceptance of scanner profiles at the product CLI boundary."""

from __future__ import annotations

import builtins
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests.cli_helpers import PlainCliRunner

from asago_scenario_generator.cli import app


_ROOT = Path(__file__).parents[2]
_PROFILE = (
    _ROOT
    / "data"
    / "contracts"
    / "stpa-execution"
    / "target-profile-v1"
    / "valid"
    / "minimal.json"
)


def _result(output_dir: Path) -> SimpleNamespace:
    plan = output_dir / "taxonomy-obligation-plan.yaml"
    plan.parent.mkdir(parents=True, exist_ok=True)
    plan.write_text("schema_version: acceptance\n", encoding="utf-8")
    return SimpleNamespace(
        output_dir=output_dir,
        artifact_paths={"taxonomy-obligation-plan.yaml": plan},
        report_path=None,
        phase2_verification=SimpleNamespace(status="awaiting_evidence"),
        run_status="no_candidates",
    )


def test_product_run_loads_scanner_profile_without_mcp_transport(
    tmp_path: Path,
) -> None:
    """A persisted profile is strict-loaded without rescanning or MCP imports."""
    risk_extraction = tmp_path / "risk-extraction.json"
    qualification_facts = tmp_path / "qualification-facts.json"
    sssom = tmp_path / "mapping.tsv"
    output_dir = tmp_path / "run"
    for path, content in (
        (risk_extraction, "{}"),
        (qualification_facts, "{}"),
        (sssom, ""),
    ):
        path.write_text(content, encoding="utf-8")

    captured: dict[str, object] = {}

    def fake_run(inputs, adapters):  # type: ignore[no-untyped-def]
        captured["inputs"] = inputs
        return _result(output_dir)

    real_import = builtins.__import__

    def reject_mcp_transport(name, *args, **kwargs):  # type: ignore[no-untyped-def]
        if name == "mcp" or name.startswith(
            "asago_scenario_generator.target_discovery.transport"
        ):
            raise AssertionError("product run must not import MCP transport")
        return real_import(name, *args, **kwargs)

    with (
        patch(
            "asago_scenario_generator.data.loaders.load_reviewed_risk_extraction",
            return_value=(),
        ),
        patch(
            "asago_scenario_generator.pipeline.synthesis.run_synthesis",
            side_effect=fake_run,
        ),
        patch("builtins.__import__", side_effect=reject_mcp_transport),
    ):
        result = PlainCliRunner().invoke(
            app,
            [
                "run",
                "--use-case",
                "a deterministic system",
                "--risk-extraction",
                str(risk_extraction),
                "--qualification-facts",
                str(qualification_facts),
                "--sssom",
                str(sssom),
                "--output-dir",
                str(output_dir),
                "--target-profile",
                str(_PROFILE),
            ],
        )

    assert result.exit_code == 0, result.output
    inputs = captured["inputs"]
    profile = inputs.execution_target_profile
    assert profile.target_id == "fixture-target"
    assert profile.source_protocol.value == "mcp"
    assert profile.inventory_authority.value == "observed"
    assert profile.semantic_authority.value == "inferred"
