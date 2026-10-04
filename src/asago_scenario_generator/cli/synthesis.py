"""CLI adapter for the obligation-aware STPA product workflow."""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import Any, Callable

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

    _report_generate_result(result, PLAN_FILENAME)


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
    cross_taxonomy_path: Path,
    **_: Any,
) -> Any:
    """Build the closed planner graph from reviewed files and bundled catalogs.

    This is the production equivalent of the one-off Phase 1 input builder,
    kept as a typed CLI adapter so the composition root always executes the
    planner itself and never accepts a preassembled plan as a bypass.
    """
    from asago_scenario_generator.pipeline.obligation_contracts import (
        TaxonomyObligationInputs,
        compute_mapping_bundle_digest,
    )

    if capability_profile is None or not hasattr(capability_profile, "kc_subcodes"):
        raise TypeError(
            "production taxonomy adapter requires a typed capability profile"
        )
    catalog, catalog_pin = _bundled_catalog()
    context = catalog[0].canonical_chain.taxonomy_context
    sssom_rows = _reviewed_owasp_llm_rows(sssom_path, risk_cards)
    cross_edges = _llm_threat_edges(cross_taxonomy_path)
    cross_edges.extend(_threat_pattern_edges(capability_profile))
    closed_sssom, cross_edges = _close_reviewed_graph(sssom_rows, cross_edges)

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


def _bundled_catalog() -> tuple[tuple[Any, ...], str]:
    """Return the validated bundled attack-pattern catalog and its pin."""
    from asago_scenario_generator.data.loaders import load_attack_patterns
    from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
    from asago_scenario_generator.models.attack_pattern_validation import (
        validate_attack_pattern,
    )
    from asago_scenario_generator.pipeline.projection_qualification import (
        compute_authoritative_catalog_pin,
    )

    resolver = load_taxonomy_resolver()
    catalog_records = list(load_attack_patterns().values())
    catalog = tuple(validate_attack_pattern(item, resolver) for item in catalog_records)
    if not catalog:
        raise ValueError("bundled attack-pattern catalog is empty")
    return catalog, compute_authoritative_catalog_pin(catalog_records, resolver)


def _reviewed_owasp_llm_rows(sssom_path: Path, risk_cards: Any) -> list[dict]:
    """Return reviewed risks' OWASP LLM matches with normalized LLM IDs."""
    from asago_scenario_generator.data.sssom import load_sssom, normalize_llm_id

    risk_ids = {str(item.risk_id) for item in risk_cards}
    rows = []
    for mapping in load_sssom(sssom_path):
        row = mapping.model_dump(mode="json")
        if row["subject_id"] not in risk_ids:
            continue
        if "owasp-llm" not in str(row["object_source"]):
            continue
        if "nomatch" in str(row["predicate_id"]).lower():
            continue
        row["object_id"] = normalize_llm_id(str(row["object_id"]))
        rows.append(row)
    return rows


def _llm_threat_edges(cross_taxonomy_path: Path) -> list[dict]:
    """Return the bundled LLM-to-threat edges of the cross-taxonomy file."""
    cross_raw = yaml.safe_load(Path(cross_taxonomy_path).read_text(encoding="utf-8"))
    if not isinstance(cross_raw, dict):
        raise ValueError("cross-taxonomy mapping file must contain an object")
    return [
        {
            "source_id": item["target"],
            "target_id": item["source"],
            "relation": item.get("predicate", "related_match"),
            "evidence": ["cross-taxonomy-mappings.yaml:t_to_llm"],
        }
        for item in cross_raw.get("t_to_llm", ())
    ]


def _threat_pattern_edges(capability_profile: Any) -> list[dict]:
    """Return the threat-to-attack-pattern edges of the in-scope threats."""
    from asago_scenario_generator.data.threat_gating import determine_threat_scope

    scope = determine_threat_scope(capability_profile)
    return [
        {
            "source_id": entry.threat_id,
            "target_id": pattern_id,
            "relation": "attacks_via",
            "evidence": ["owasp-agentic-threats-v1.1.yaml"],
        }
        for entry in scope.in_scope
        for pattern_id in entry.attack_pattern_ids
    ]


def _close_reviewed_graph(
    sssom_rows: list[dict], cross_edges: list[dict]
) -> tuple[list[dict], list[dict]]:
    """Keep only rows and edges on a risk -> LLM -> threat -> pattern path."""
    llm_edges = _edges_where(
        cross_edges, "target_id", lambda value: value.startswith("T")
    )
    threat_edges = _edges_where(
        cross_edges, "target_id", lambda value: value.startswith("AP-")
    )
    llm_objects = _field_values(sssom_rows, "object_id")
    kept_llm = _edges_where(llm_edges, "source_id", llm_objects.__contains__)
    threat_ids = _field_values(kept_llm, "target_id")
    kept_threat = _edges_where(threat_edges, "source_id", threat_ids.__contains__)
    ap_sources = _field_values(kept_threat, "source_id")
    kept_llm = _edges_where(kept_llm, "target_id", ap_sources.__contains__)
    llm_sources = _field_values(kept_llm, "source_id")
    closed_sssom = _edges_where(sssom_rows, "object_id", llm_sources.__contains__)
    return closed_sssom, kept_llm + kept_threat


def _field_values(rows: list[dict], key: str) -> set[str]:
    """Return the string form of one field across rows."""
    return {str(row[key]) for row in rows}


def _edges_where(rows: list[dict], key: str, keep: Callable[[str], bool]) -> list[dict]:
    """Return the rows whose field, as a string, satisfies *keep*."""
    return [row for row in rows if keep(str(row[key]))]


__all__ = ["build_taxonomy_inputs", "generate_cmd"]
