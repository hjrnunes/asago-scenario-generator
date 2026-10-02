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

_DEFAULT_CROSS_TAXONOMY = (
    DATA_ROOT / "taxonomies" / "mappings" / "cross-taxonomy-mappings.yaml"
)


@app.command(name="run")
def run_cmd(
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
    requested_environment_basis: str | None = typer.Option(
        None,
        "--basis",
        "--requested-environment-basis",
        help="Explicit execution basis; only target_profile is accepted.",
    ),
    profile: str | None = typer.Option(None, help="Default model profile name."),
    sp1_profile: str | None = typer.Option(None, help="SP1 model profile override."),
    sp2_profile: str | None = typer.Option(None, help="SP2 model profile override."),
    sp3_profile: str | None = typer.Option(None, help="SP3 model profile override."),
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
) -> None:
    """Run taxonomy-obligation planning, STPA scenarios, and verification."""
    _validate_file(risk_extraction, "risk-extraction file")
    _validate_file(qualification_facts, "qualification facts file")
    _validate_file(sssom, "SSSOM file")
    # Model resolution reads the profiles file only for a named profile, so a
    # run configured through flags and environment needs no local file.
    if any(
        name is not None for name in (profile, sp1_profile, sp2_profile, sp3_profile)
    ):
        _validate_file(profiles_file, "model profiles file")
    if execution_target_profile is not None:
        _validate_file(execution_target_profile, "execution target profile file")
    if target_observations is not None:
        _validate_file(target_observations, "target observations file")
    if observation_contract is not None:
        _validate_file(observation_contract, "observation contract file")
    if loss_analysis is not None:
        _validate_file(loss_analysis, "loss analysis file")
    if max_workers < 1:
        raise typer.BadParameter("must be positive", param_hint="--max-workers")

    try:
        from asago_scenario_generator.data.loaders import (
            load_reviewed_risk_extraction,
        )
        from asago_scenario_generator.pipeline.obligation_contracts import (
            QualificationFactsInput,
        )
        from asago_scenario_generator.pipeline.synthesis import (
            PLAN_FILENAME,
            SynthesisAdapters,
            SynthesisInputs,
            run_synthesis,
        )
        from asago_scenario_generator.stpa.models.execution_classification import (
            ExecutionTargetProfile,
            RequestedEnvironmentBasis,
        )
        from asago_scenario_generator.stpa.scenario_prod.target_observations import (
            TargetObservationSnapshot,
        )
        from asago_scenario_generator.stpa.observation_contract import (
            load_observation_contract,
        )

        # The product workflow preserves every reviewed taxonomy record because
        # the typed snapshot pins the complete risk set.
        risks = tuple(load_reviewed_risk_extraction(risk_extraction))
        facts = QualificationFactsInput.model_validate(
            _load_payload(qualification_facts, "qualification facts")
        )
        execution_target_profile_value = None
        if execution_target_profile is not None:
            target_payload = _load_payload(
                execution_target_profile, "execution target profile"
            )
            if "semantic_digest" not in target_payload:
                raise ValueError(
                    "execution target profile must include semantic_digest"
                )
            execution_target_profile_value = ExecutionTargetProfile.model_validate(
                target_payload
            )
            execution_target_profile_value.assert_integrity()
        target_observations_value = None
        if target_observations is not None:
            if execution_target_profile_value is None:
                raise ValueError("--target-observations requires --target-profile")
            target_observations_value = TargetObservationSnapshot.from_runtime_context(
                _load_payload(target_observations, "target observations")
            )
            if (
                target_observations_value.target_profile_digest
                != execution_target_profile_value.semantic_digest
            ):
                raise ValueError(
                    "target observations profile pin does not match target profile"
                )
        observation_contract_value = (
            load_observation_contract(observation_contract)
            if observation_contract is not None
            else None
        )
        requested_basis = None
        if loss_analysis is not None:
            from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis

            # Fail fast on a malformed pinned graph before any run work.
            LossAnalysis.model_validate(_load_payload(loss_analysis, "loss analysis"))
        if requested_environment_basis is not None:
            if requested_environment_basis != RequestedEnvironmentBasis.target_profile:
                raise ValueError("requested environment basis must be target_profile")
            requested_basis = RequestedEnvironmentBasis.target_profile
        inputs = SynthesisInputs(
            use_case=_resolve_use_case(use_case),
            risk_cards=risks,
            qualification_facts=facts,
            output_dir=output_dir,
            execution_target_profile=execution_target_profile_value,
            target_observations=target_observations_value,
            observation_contract=observation_contract_value,
            requested_environment_basis=requested_basis,
            risk_extraction_path=risk_extraction,
            qualification_facts_path=qualification_facts,
            loss_analysis_path=loss_analysis,
            profiles_file=profiles_file,
            profile=profile,
            sp1_profile=sp1_profile,
            sp2_profile=sp2_profile,
            sp3_profile=sp3_profile,
            max_workers=max_workers,
            replay_calls_dir=replay_calls,
        )
        adapter = SynthesisAdapters(
            build_taxonomy_inputs=partial(
                build_taxonomy_inputs,
                sssom_path=sssom,
                cross_taxonomy_path=_DEFAULT_CROSS_TAXONOMY,
            )
        )
        result = run_synthesis(inputs, adapter)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        _abort(exc)

    typer.echo(f"Synthesis artifacts written to: {result.output_dir}")
    typer.echo(f"  Plan: {result.artifact_paths[PLAN_FILENAME]}")
    if result.report_path is not None:
        typer.echo(f"  Report: {result.report_path}")
    status = _synthesis_run_status(result)
    typer.echo(f"  Scenario generation: {status}")
    typer.echo(
        "  Phase 2 verification: "
        f"{getattr(result.phase2_verification, 'status', 'failed')}"
    )
    assessment_path = result.artifact_paths.get("hybrid-coverage-assessment.yaml")
    if assessment_path is not None:
        typer.echo(f"  Phase 2 assessment: {assessment_path}")
    if status == "failed":
        typer.echo(
            "Error: scenario generation published no scenarios after "
            "attempting candidates; diagnostic artifacts were preserved.",
            err=True,
        )
        raise typer.Exit(code=1)


def _synthesis_run_status(result: Any) -> str:
    """Read the stable product status without coupling the CLI to internals."""
    value = getattr(result, "run_status", None) or getattr(result, "status", None)
    if value is None:
        manifest = getattr(result, "manifest", None)
        if isinstance(manifest, dict):
            value = manifest.get("run_status") or manifest.get("status")
    return str(getattr(value, "value", value) or "unknown")


def build_taxonomy_inputs(
    *,
    capability_profile: Any,
    capability_snapshot: Any,
    risk_cards: Any,
    qualification_facts: Any,
    sssom_path: Path,
    cross_taxonomy_path: Path,
    **_: Any,
) -> Any:
    """Build the closed planner graph from reviewed files and bundled catalogs.

    This is the production equivalent of the one-off Phase 1 input builder,
    kept as a typed CLI adapter so the composition root always executes the
    planner itself and never accepts a preassembled plan as a bypass.
    """
    from asago_scenario_generator.data.loaders import load_attack_patterns
    from asago_scenario_generator.data.sssom import load_sssom, normalize_llm_id
    from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
    from asago_scenario_generator.data.threat_gating import determine_threat_scope
    from asago_scenario_generator.models.attack_pattern_validation import (
        validate_attack_pattern,
    )
    from asago_scenario_generator.pipeline.obligation_contracts import (
        TaxonomyObligationInputs,
        compute_mapping_bundle_digest,
    )
    from asago_scenario_generator.pipeline.projection_qualification import (
        compute_authoritative_catalog_pin,
    )

    if capability_profile is None or not hasattr(capability_profile, "kc_subcodes"):
        raise TypeError(
            "production taxonomy adapter requires a typed capability profile"
        )
    resolver = load_taxonomy_resolver()
    catalog_records = list(load_attack_patterns().values())
    catalog = tuple(validate_attack_pattern(item, resolver) for item in catalog_records)
    if not catalog:
        raise ValueError("bundled attack-pattern catalog is empty")
    context = catalog[0].canonical_chain.taxonomy_context
    catalog_pin = compute_authoritative_catalog_pin(catalog_records, resolver)

    sssom_records = [item.model_dump(mode="json") for item in load_sssom(sssom_path)]
    risk_ids = {str(item.risk_id) for item in risk_cards}
    closed_sssom = []
    for row in sssom_records:
        if row["subject_id"] not in risk_ids:
            continue
        if "owasp-llm" not in str(row["object_source"]):
            continue
        if "nomatch" in str(row["predicate_id"]).lower():
            continue
        row = dict(row)
        row["object_id"] = normalize_llm_id(str(row["object_id"]))
        closed_sssom.append(row)

    cross_raw = yaml.safe_load(Path(cross_taxonomy_path).read_text(encoding="utf-8"))
    if not isinstance(cross_raw, dict):
        raise ValueError("cross-taxonomy mapping file must contain an object")
    cross_edges = [
        {
            "source_id": item["target"],
            "target_id": item["source"],
            "relation": item.get("predicate", "related_match"),
            "evidence": ["cross-taxonomy-mappings.yaml:t_to_llm"],
        }
        for item in cross_raw.get("t_to_llm", ())
    ]
    scope = determine_threat_scope(capability_profile)
    cross_edges.extend(
        {
            "source_id": entry.threat_id,
            "target_id": pattern_id,
            "relation": "attacks_via",
            "evidence": ["owasp-agentic-threats-v1.1.yaml"],
        }
        for entry in scope.in_scope
        for pattern_id in entry.attack_pattern_ids
    )

    # Close the reviewed graph over risk → LLM → threat → attack-pattern paths.
    llm_edges = [item for item in cross_edges if str(item["target_id"]).startswith("T")]
    threat_edges = [
        item for item in cross_edges if str(item["target_id"]).startswith("AP-")
    ]
    kept_llm = [
        item
        for item in llm_edges
        if str(item["source_id"]) in {str(row["object_id"]) for row in closed_sssom}
    ]
    threat_ids = {str(item["target_id"]) for item in kept_llm}
    kept_threat = [
        item for item in threat_edges if str(item["source_id"]) in threat_ids
    ]
    ap_sources = {str(item["source_id"]) for item in kept_threat}
    kept_llm = [item for item in kept_llm if str(item["target_id"]) in ap_sources]
    llm_sources = {str(item["source_id"]) for item in kept_llm}
    closed_sssom = [row for row in closed_sssom if str(row["object_id"]) in llm_sources]
    cross_edges = kept_llm + kept_threat

    return TaxonomyObligationInputs(
        risk_cards=tuple(risk_cards),
        capability_snapshot=capability_snapshot,
        attack_pattern_catalog=catalog,
        cross_taxonomy_mappings=tuple(cross_edges),
        sssom_mappings=tuple(closed_sssom),
        catalog_pins={
            "atlas": {"release": context.atlas.release, "digest": catalog_pin}
        },
        mapping_pins={
            "sssom": {
                "release": context.atlas.release,
                "digest": context.mapping_set_digest,
            },
            "obligation_edges": {
                "release": "obligation-mapping-bundle-v1",
                "digest": compute_mapping_bundle_digest(cross_edges, closed_sssom),
            },
        },
        qualification_facts=qualification_facts,
    )


__all__ = ["build_taxonomy_inputs", "run_cmd"]
