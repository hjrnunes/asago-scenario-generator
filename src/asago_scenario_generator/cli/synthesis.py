"""CLI adapter for the obligation-aware STPA product workflow."""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import Any

import typer
import yaml

from asago_scenario_generator.cli._app import app
from asago_scenario_generator.cli._shared import (
    _abort,
    _load_payload,
    _resolve_use_case,
    _validate_file,
)
from asago_scenario_generator.data.paths import DATA_ROOT

_DEFAULT_LLM_PATTERN_TABLE = (
    DATA_ROOT / "taxonomies" / "mappings" / "llm-to-attack-pattern.yaml"
)


@app.command(name="generate")
def generate_cmd(
    use_case: str = typer.Option(..., help="Use-case description or @file.txt."),
    risk_extraction: Path = typer.Option(
        ..., help="Path to policy-mapper risk-extraction.json."
    ),
    qualification_facts: Path = typer.Option(
        ..., help="Path to explicit authoritative qualification facts YAML/JSON."
    ),
    output_dir: Path = typer.Option(..., help="Directory for synthesis artifacts."),
    sssom: Path = typer.Option(
        ..., help="Reviewed risk-to-OWASP-LLM SSSOM TSV mapping file."
    ),
    execution_target_profile: Path | None = typer.Option(
        None,
        "--target-profile",
        "--execution-target-profile",
        help=(
            "Optional verified execution target/simulation profile JSON or YAML. "
            "The run publishes its canonical copy as enrichment evidence; it "
            "does not select a generation algorithm."
        ),
    ),
    target_observations: Path | None = typer.Option(
        None,
        "--target-observations",
        help=(
            "Optional normalized target runtime-context JSON/YAML containing "
            "state/read observations paired with --target-profile."
        ),
    ),
    observation_contract: Path | None = typer.Option(
        None,
        "--observation-contract",
        help=(
            "Target-agnostic observation contract YAML. Standalone callers may "
            "omit it to use the frozen live qualification contract; orchestration "
            "supplies it explicitly."
        ),
    ),
    loss_analysis: Path | None = typer.Option(
        None,
        "--loss-analysis",
        help=(
            "Optional pinned loss-analysis.yaml. Stage 1a runs its offline "
            "gates on the supplied graph with zero model calls and no "
            "revision; a failing gate is fatal."
        ),
    ),
    profile: str | None = typer.Option(None, help="Default model profile name."),
    profiles_file: Path = typer.Option(
        Path("config/model-profiles.yaml"), help="Model profiles YAML file."
    ),
    max_workers: int = typer.Option(1, help="Maximum workers for model adapters."),
    replay_calls: Path | None = typer.Option(
        None,
        "--replay-calls",
        help=(
            "Directory holding a prior run's provider-calls.jsonl. Serve every "
            "model request from that record, matched by request digest, "
            "instead of contacting an endpoint."
        ),
    ),
    replay_fill: bool = typer.Option(
        False,
        "--replay-fill",
        help=(
            "With --replay-calls, serve the requests the record holds and send "
            "the others live through --profile. This run contacts the model "
            "endpoint, so the private live-model approval applies. Requires "
            "--max-live-requests."
        ),
    ),
    live_stage: list[str] | None = typer.Option(
        None,
        "--live-stage",
        help=(
            "Repeatable. Send every request whose identity stage is NAME live "
            "even when the record holds it. Requires --replay-fill."
        ),
    ),
    max_live_requests: int | None = typer.Option(
        None,
        "--max-live-requests",
        min=0,
        help=(
            "Budget of live requests, transport retries included. The request "
            "that would exceed it is not sent and the run ends in an error. "
            "Requires --replay-fill."
        ),
    ),
) -> None:
    """Run taxonomy-obligation planning, STPA scenarios, and verification."""
    _validate_input_files(
        risk_extraction=risk_extraction,
        qualification_facts=qualification_facts,
        sssom=sssom,
        profile=profile,
        profiles_file=profiles_file,
        execution_target_profile=execution_target_profile,
        target_observations=target_observations,
        observation_contract=observation_contract,
        loss_analysis=loss_analysis,
    )
    if max_workers < 1:
        raise typer.BadParameter("must be positive", param_hint="--max-workers")
    fill_policy = _replay_fill_policy(
        replay_fill=replay_fill,
        live_stage=live_stage,
        max_live_requests=max_live_requests,
        replay_calls=replay_calls,
        profile=profile,
    )

    try:
        from asago_scenario_generator.pipeline.synthesis import (
            PLAN_FILENAME,
            SynthesisAdapters,
            run_synthesis,
        )

        inputs = _synthesis_inputs(
            use_case=use_case,
            risk_extraction=risk_extraction,
            qualification_facts=qualification_facts,
            output_dir=output_dir,
            execution_target_profile=execution_target_profile,
            target_observations=target_observations,
            observation_contract=observation_contract,
            loss_analysis=loss_analysis,
            profile=profile,
            profiles_file=profiles_file,
            max_workers=max_workers,
            replay_calls=replay_calls,
            replay_fill=fill_policy,
        )
        adapter = SynthesisAdapters(
            build_taxonomy_inputs=partial(
                build_taxonomy_inputs,
                sssom_path=sssom,
                llm_pattern_path=_DEFAULT_LLM_PATTERN_TABLE,
            )
        )
        result = run_synthesis(inputs, adapter)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        _abort(exc)

    _report_generate_result(result, PLAN_FILENAME)


def _replay_fill_policy(
    *,
    replay_fill: bool,
    live_stage: list[str] | None,
    max_live_requests: int | None,
    replay_calls: Path | None,
    profile: str | None,
) -> Any:
    """Return the replay-fill policy, or None; reject an incomplete combination."""
    if not replay_fill:
        _require(not live_stage, "--live-stage", "requires --replay-fill")
        _require(
            max_live_requests is None, "--max-live-requests", "requires --replay-fill"
        )
        return None
    _require(replay_calls is not None, "--replay-fill", "requires --replay-calls")
    _require(
        profile is not None, "--replay-fill", "requires --profile for the live requests"
    )
    _require(max_live_requests is not None, "--max-live-requests", "is required")
    from asago_scenario_generator.stpa.infra.provider_record import ReplayFill

    return ReplayFill(
        max_live_requests=max_live_requests or 0,
        live_stages=frozenset(live_stage or ()),
    )


def _require(condition: bool, flag: str, reason: str) -> None:
    if not condition:
        raise typer.BadParameter(reason, param_hint=flag)


def _validate_input_files(
    *,
    risk_extraction: Path,
    qualification_facts: Path,
    sssom: Path,
    profile: str | None,
    profiles_file: Path,
    execution_target_profile: Path | None,
    target_observations: Path | None,
    observation_contract: Path | None,
    loss_analysis: Path | None,
) -> None:
    """Check every required file and each supplied optional file."""
    _validate_file(risk_extraction, "risk-extraction file")
    _validate_file(qualification_facts, "qualification facts file")
    _validate_file(sssom, "SSSOM file")
    # Model resolution reads the profiles file only for a named profile, so a
    # run configured through flags and environment needs no local file.
    if profile is not None:
        _validate_file(profiles_file, "model profiles file")
    if execution_target_profile is not None:
        _validate_file(execution_target_profile, "execution target profile file")
    if target_observations is not None:
        _validate_file(target_observations, "target observations file")
    if observation_contract is not None:
        _validate_file(observation_contract, "observation contract file")
    if loss_analysis is not None:
        _validate_file(loss_analysis, "loss analysis file")


def _synthesis_inputs(
    *,
    use_case: str,
    risk_extraction: Path,
    qualification_facts: Path,
    output_dir: Path,
    execution_target_profile: Path | None,
    target_observations: Path | None,
    observation_contract: Path | None,
    loss_analysis: Path | None,
    profile: str | None,
    profiles_file: Path,
    max_workers: int,
    replay_calls: Path | None,
    replay_fill: Any = None,
) -> Any:
    """Load and check the input files, then build the synthesis request."""
    from asago_scenario_generator.data.loaders import (
        load_reviewed_risk_extraction,
    )
    from asago_scenario_generator.pipeline.obligation_contracts import (
        QualificationFactsInput,
    )
    from asago_scenario_generator.pipeline.synthesis import SynthesisInputs
    from asago_scenario_generator.stpa.observation_contract import (
        load_observation_contract,
    )

    # The product workflow preserves every reviewed taxonomy record because
    # the typed snapshot pins the complete risk set.
    risks = tuple(load_reviewed_risk_extraction(risk_extraction))
    facts = QualificationFactsInput.model_validate(
        _load_payload(qualification_facts, "qualification facts")
    )
    execution_target_profile_value = _load_execution_target_profile(
        execution_target_profile
    )
    target_observations_value = _load_target_observations(
        target_observations, execution_target_profile_value
    )
    observation_contract_value = (
        load_observation_contract(observation_contract)
        if observation_contract is not None
        else None
    )
    if loss_analysis is not None:
        from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis

        # Fail fast on a malformed pinned graph before any run work.
        LossAnalysis.model_validate(_load_payload(loss_analysis, "loss analysis"))
    return SynthesisInputs(
        use_case=_resolve_use_case(use_case),
        risk_cards=risks,
        qualification_facts=facts,
        output_dir=output_dir,
        execution_target_profile=execution_target_profile_value,
        target_observations=target_observations_value,
        observation_contract=observation_contract_value,
        risk_extraction_path=risk_extraction,
        qualification_facts_path=qualification_facts,
        loss_analysis_path=loss_analysis,
        profiles_file=profiles_file,
        profile=profile,
        max_workers=max_workers,
        replay_calls_dir=replay_calls,
        replay_fill=replay_fill,
    )


def _load_execution_target_profile(path: Path | None) -> Any:
    """Return the verified execution target profile, or None when absent."""
    if path is None:
        return None
    from asago_scenario_generator.stpa.models.execution_classification import (
        ExecutionTargetProfile,
    )

    target_payload = _load_payload(path, "execution target profile")
    if "semantic_digest" not in target_payload:
        raise ValueError("execution target profile must include semantic_digest")
    value = ExecutionTargetProfile.model_validate(target_payload)
    value.assert_integrity()
    return value


def _load_target_observations(path: Path | None, target_profile: Any) -> Any:
    """Return the observations pinned to the target profile, or None."""
    if path is None:
        return None
    from asago_scenario_generator.stpa.scenario_prod.target_observations import (
        TargetObservationSnapshot,
    )

    if target_profile is None:
        raise ValueError("--target-observations requires --target-profile")
    value = TargetObservationSnapshot.from_runtime_context(
        _load_payload(path, "target observations")
    )
    if value.target_profile_digest != target_profile.semantic_digest:
        raise ValueError(
            "target observations profile pin does not match target profile"
        )
    return value


def _report_generate_result(result: Any, plan_filename: str) -> None:
    """Print the artifact locations and exit 1 when generation failed."""
    typer.echo(f"Synthesis artifacts written to: {result.output_dir}")
    typer.echo(f"  Plan: {result.artifact_paths[plan_filename]}")
    if result.report_path is not None:
        typer.echo(f"  Report: {result.report_path}")
    status = result.run_status
    typer.echo(f"  Scenario generation: {status}")
    if status == "failed":
        typer.echo(
            "Error: scenario generation published no scenarios after "
            "attempting candidates; diagnostic artifacts were preserved.",
            err=True,
        )
        raise typer.Exit(code=1)


def build_taxonomy_inputs(
    *,
    capability_profile: Any,
    capability_snapshot: Any,
    risk_cards: Any,
    qualification_facts: Any,
    sssom_path: Path,
    llm_pattern_path: Path,
    **_: Any,
) -> Any:
    """Load the reviewed mapping files and build the closed planner graph.

    This typed CLI adapter keeps the composition root executing the planner
    itself; it never accepts a preassembled plan as a bypass.
    """
    from asago_scenario_generator.data.sssom import load_sssom
    from asago_scenario_generator.pipeline.taxonomy_inputs import (
        bundled_attack_pattern_catalog,
        taxonomy_obligation_inputs,
    )

    if capability_profile is None or not hasattr(capability_profile, "kc_subcodes"):
        raise TypeError(
            "production taxonomy adapter requires a typed capability profile"
        )
    catalog, catalog_pin = bundled_attack_pattern_catalog()
    sssom_mappings = load_sssom(sssom_path)
    return taxonomy_obligation_inputs(
        capability_profile=capability_profile,
        capability_snapshot=capability_snapshot,
        risk_cards=risk_cards,
        qualification_facts=qualification_facts,
        catalog=catalog,
        catalog_pin=catalog_pin,
        sssom_mappings=sssom_mappings,
        llm_pattern_table=yaml.safe_load(
            Path(llm_pattern_path).read_text(encoding="utf-8")
        ),
    )


__all__ = ["build_taxonomy_inputs", "generate_cmd"]
