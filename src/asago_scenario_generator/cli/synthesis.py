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
    sssom: Path | None = typer.Option(
        None,
        help="Reviewed risk-to-OWASP-LLM SSSOM TSV mapping file (required without --taxonomy-inputs).",
    ),
    taxonomy_inputs: Path | None = typer.Option(
        None,
        help="Optional typed Phase 1 input snapshot; planning still executes and validates it.",
    ),
    cross_taxonomy: Path | None = typer.Option(
        None,
        help="Cross-taxonomy mapping YAML (defaults to the bundled catalog).",
    ),
    capability_profile: Path | None = typer.Option(
        None,
        help="Optional pre-built capability-profile.yaml; skips profile inference.",
    ),
    profile: str | None = typer.Option(None, help="Default model profile name."),
    sp1_profile: str | None = typer.Option(None, help="SP1 model profile override."),
    sp2_profile: str | None = typer.Option(None, help="SP2 model profile override."),
    sp3_profile: str | None = typer.Option(None, help="SP3 model profile override."),
    profiles_file: Path = typer.Option(
        Path("config/model-profiles.yaml"), help="Model profiles YAML file."
    ),
    max_workers: int = typer.Option(1, help="Maximum workers for model adapters."),
    max_batch_size: int | None = typer.Option(
        None, help="Maximum obligations in one consideration batch."
    ),
    resume: bool = typer.Option(
        False,
        help="Resume only from an intact Phase 1 checkpoint with matching pins.",
    ),
    temperature: float | None = typer.Option(
        None, help="Sampling temperature override for model adapters."
    ),
) -> None:
    """Run taxonomy-obligation planning, STPA scenarios, and verification."""
    _validate_file(risk_extraction, "risk-extraction file")
    _validate_file(qualification_facts, "qualification facts file")
    if sssom is not None:
        _validate_file(sssom, "SSSOM file")
    if sssom is not None and taxonomy_inputs is not None:
        raise typer.BadParameter(
            "choose one of --sssom or --taxonomy-inputs",
            param_hint="--sssom/--taxonomy-inputs",
        )
    if sssom is None and taxonomy_inputs is None:
        raise typer.BadParameter(
            "provide --sssom or --taxonomy-inputs",
            param_hint="--sssom/--taxonomy-inputs",
        )
    if taxonomy_inputs is not None:
        _validate_file(taxonomy_inputs, "typed taxonomy input snapshot")
    _validate_file(profiles_file, "model profiles file")
    if capability_profile is not None:
        _validate_file(capability_profile, "capability profile file")
    if cross_taxonomy is not None:
        _validate_file(cross_taxonomy, "cross-taxonomy file")
    if max_workers < 1:
        raise typer.BadParameter("must be positive", param_hint="--max-workers")
    if max_batch_size is not None and max_batch_size < 1:
        raise typer.BadParameter("must be positive", param_hint="--max-batch-size")

    try:
        from asago_scenario_generator.data.loaders import (
            load_reviewed_risk_extraction,
        )
        from asago_scenario_generator.pipeline.obligation_contracts import (
            QualificationFactsInput,
            TaxonomyObligationInputs,
        )
        from asago_scenario_generator.pipeline.synthesis import (
            PLAN_FILENAME,
            SynthesisAdapters,
            SynthesisInputs,
            run_synthesis,
        )
        from asago_scenario_generator.stpa.system_model.profile import (
            load_capability_profile,
        )

        # The product workflow preserves every reviewed taxonomy record because
        # the typed snapshot pins the complete risk set.
        risks = tuple(load_reviewed_risk_extraction(risk_extraction))
        facts = QualificationFactsInput.model_validate(
            _load_payload(qualification_facts, "qualification facts")
        )
        typed_inputs = (
            TaxonomyObligationInputs.model_validate(
                _load_payload(taxonomy_inputs, "typed taxonomy input snapshot")
            )
            if taxonomy_inputs is not None
            else None
        )
        profile_value = (
            load_capability_profile(capability_profile)
            if capability_profile is not None
            else None
        )
        if typed_inputs is not None:
            snapshot_profile = typed_inputs.capability_snapshot.profile
            if profile_value is None:
                # A supplied typed snapshot is the authoritative capability
                # identity for this run; do not derive or load another one.
                profile_value = snapshot_profile
            elif profile_value != snapshot_profile:
                raise ValueError(
                    "--capability-profile does not match the typed taxonomy "
                    "input snapshot capability profile"
                )
        checkpoint = None
        if resume:
            checkpoint_path = output_dir / PLAN_FILENAME
            _validate_file(checkpoint_path, "resume Phase 1 plan")
            from asago_scenario_generator.models.obligation_plan import (
                TaxonomyObligationPlan,
            )

            checkpoint = TaxonomyObligationPlan.from_yaml(
                checkpoint_path.read_text(encoding="utf-8")
            )
        inputs = SynthesisInputs(
            use_case=_resolve_use_case(use_case),
            risk_cards=risks,
            qualification_facts=facts,
            output_dir=output_dir,
            capability_profile=profile_value,
            capability_snapshot=(
                typed_inputs.capability_snapshot if typed_inputs is not None else None
            ),
            capability_profile_path=capability_profile,
            taxonomy_inputs=typed_inputs,
            risk_extraction_path=risk_extraction,
            qualification_facts_path=qualification_facts,
            profiles_file=profiles_file,
            profile=profile,
            sp1_profile=sp1_profile,
            sp2_profile=sp2_profile,
            sp3_profile=sp3_profile,
            max_workers=max_workers,
            max_batch_size=max_batch_size,
            resume=resume,
            prebuilt_plan=checkpoint,
            temperature=temperature,
        )
        adapter = SynthesisAdapters(
            build_taxonomy_inputs=(
                partial(
                    build_taxonomy_inputs,
                    sssom_path=sssom,
                    cross_taxonomy_path=cross_taxonomy or _DEFAULT_CROSS_TAXONOMY,
                )
                if typed_inputs is None
                else None
            )
        )
        result = run_synthesis(inputs, adapter)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        _abort(exc)

    typer.echo(f"Synthesis artifacts written to: {result.output_dir}")
    typer.echo(f"  Plan: {result.artifact_paths[PLAN_FILENAME]}")
    if result.report_path is not None:
        typer.echo(f"  Report: {result.report_path}")
    typer.echo(
        "  Phase 2 verification: "
        f"{getattr(result.phase2_verification, 'status', 'failed')}"
    )
    assessment_path = result.artifact_paths.get("hybrid-coverage-assessment.yaml")
    if assessment_path is not None:
        typer.echo(f"  Phase 2 assessment: {assessment_path}")


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
