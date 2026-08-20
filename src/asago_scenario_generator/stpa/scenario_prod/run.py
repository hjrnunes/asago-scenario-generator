"""SP3 run orchestration — Stage 5 → Stage 6 → Stage 7.

Orchestrates the full SP3 pipeline:
  Stage 5: BDI generation (1 LLM call per scenario)
  Stage 6: Narrative + attack tree + Gherkin (3 LLM calls per scenario, parallelizable)
  Stage 7: Validators + eval metrics + coverage gap analysis (0 LLM calls)

All LLM calls are logged to ``calls.jsonl``. A run manifest is written
at run end with stage summary, validation results, eval scorecard,
coverage gaps, input hashes, and prompt hashes.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call_raw
from asago_scenario_generator.stpa.infra.manifest_helpers import (
    count_calls_by_stage,
    hash_model,
)
from asago_scenario_generator.stpa.infra.templates import (
    TemplateLoader,
    hash_prompt_templates,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.enriched_threat_set import EnrichedThreatSet
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.models.scenario_envelope import (
    GherkinSpec,
    ScenarioEnvelope,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec

from ._constants import PROMPTS_DIR
from .assembly import assemble_envelope
from .attack_tree import build_attack_tree_prompts, parse_attack_tree
from .bdi_generation import (
    assemble_scenario_spec,
    generate_bdi,
    parse_ica_slot_id,
    populate_defender_bdi,
)
from .coverage import compute_coverage_gaps, write_coverage_gaps
from .eval_metrics import compute_eval_scorecard, write_eval_scorecard
from .gherkin import build_gherkin_prompts, find_security_constraint, parse_gherkin_spec
from .narrative import build_narrative_prompts
from .projection import (
    canonical_projection_data,
    export_projection_json,
    export_projection_yaml,
    project_execution,
)
from .prompt_alignment import render_projection_alignment_table
from .validators import (
    TraceabilityError,
    ValidationResult,
    validate_attack_tree_root_label,
    validate_bdi_grounding,
    validate_gherkin_structure,
    validate_loss_hazard_id_references,
    validate_traceability,
    validate_tree_branch_coverage,
    validate_tree_id_references,
    validate_vulnerability_completeness,
)

DEFAULT_TEMPERATURE = 0.4

__all__ = ["SP3RunResult", "run_sp3"]

_EMPTY_ATTACK_TREE: dict = {"root": "", "branches": [], "leaves": []}
_EMPTY_GHERKIN_SPEC = GherkinSpec(
    feature="",
    scenario="",
    given=[],
    when=[],
    then_expected=[],
    then_actual=[],
)


@dataclass
class SP3RunResult:
    """Result of a full SP3 run."""

    scenario_specs: list[ScenarioSpec] = field(default_factory=list)
    scenario_envelopes: list[ScenarioEnvelope] = field(default_factory=list)
    eval_scorecard: dict = field(default_factory=dict)
    coverage_gaps: dict = field(default_factory=dict)
    stage_errors: list[str] = field(default_factory=list)
    validation_errors: list[str] = field(default_factory=list)


def run_sp3(
    *,
    llm_client: LLMClient,
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    capability_profile: CapabilityProfile | None = None,
    max_workers: int = 1,
    temperature: float = DEFAULT_TEMPERATURE,
) -> SP3RunResult:
    """Run the full SP3 pipeline: Stage 5 → Stage 6 → Stage 7.

    Args:
        llm_client: LLM client for making completion calls.
        enriched_threat_set: SP2 enriched threat set.
        control_structure: SP1 control structure.
        loss_analysis: SP1 loss analysis.
        run_dir: Directory for output artifacts.
        capability_profile: Optional SP1 capability profile for Stage 5/6
            prompt grounding and envelope enrichment.  When provided,
            envelopes are enriched with ``system_context`` and
            ``consumer_hints`` blocks.
        max_workers: Maximum parallel workers for LLM calls.
        temperature: LLM temperature.

    Returns:
        An :class:`SP3RunResult` with artifacts and diagnostics.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    scenarios_dir = run_dir / "scenarios"
    scenarios_dir.mkdir(parents=True, exist_ok=True)
    loader = TemplateLoader(PROMPTS_DIR)

    stage_errors: list[str] = []
    validation_errors: list[str] = []
    scenario_specs: list[ScenarioSpec] = []
    scenario_envelopes: list[ScenarioEnvelope] = []

    # --- Stage 5: BDI generation (1 LLM call per scenario) ---
    for idx, threat in enumerate(enriched_threat_set.structural_threats):
        spec = _run_stage5_for_threat(
            llm_client,
            threat,
            control_structure,
            run_dir,
            idx,
            loader,
            temperature,
            stage_errors,
            capability_profile=capability_profile,
        )
        if spec is not None:
            scenario_specs.append(spec)

    # --- Stage 6: Concretization (3 LLM calls per scenario, parallelizable) ---
    for spec in scenario_specs:
        envelope, projection_doc = _run_stage6_for_spec(
            llm_client,
            spec,
            control_structure,
            loss_analysis,
            run_dir,
            loader,
            temperature,
            max_workers,
            stage_errors,
            capability_profile=capability_profile,
        )
        if envelope is not None:
            scenario_envelopes.append(envelope)
            _write_scenario_artifacts(envelope, scenarios_dir, projection_doc)

    # --- Stage 7: Validation + eval metrics + coverage gaps ---
    _run_stage7_validations(
        scenario_envelopes,
        scenario_specs,
        control_structure,
        loss_analysis,
        validation_errors,
    )

    trace_errors = validate_traceability(
        scenario_envelopes, enriched_threat_set, control_structure, loss_analysis
    )
    trace_error_msgs = _format_traceability_errors(trace_errors)
    all_validation_errors = validation_errors + trace_error_msgs

    coverage_gaps = compute_coverage_gaps(
        enriched_threat_set,
        control_structure,
        scenario_envelopes,
        loss_analysis,
        precomputed_trace_errors=trace_errors,
    )

    eval_scorecard = compute_eval_scorecard(
        scenario_envelopes,
        enriched_threat_set,
        control_structure,
        loss_analysis,
        stage_local_errors=validation_errors,
        traceability_errors=trace_error_msgs,
        coverage_gaps=coverage_gaps,
        precomputed_trace_errors=trace_errors,
    )

    # --- Write output artifacts ---
    write_eval_scorecard(eval_scorecard, run_dir)
    write_coverage_gaps(coverage_gaps, run_dir)

    # --- Write run manifest ---
    _write_manifest(
        run_dir=run_dir,
        llm_client=llm_client,
        enriched_threat_set=enriched_threat_set,
        control_structure=control_structure,
        loss_analysis=loss_analysis,
        scenario_envelopes=scenario_envelopes,
        validation_errors=all_validation_errors,
        max_workers=max_workers,
        stage_errors=stage_errors,
    )

    return SP3RunResult(
        scenario_specs=scenario_specs,
        scenario_envelopes=scenario_envelopes,
        eval_scorecard=eval_scorecard,
        coverage_gaps=coverage_gaps,
        stage_errors=stage_errors,
        validation_errors=all_validation_errors,
    )


def _format_traceability_errors(errors: list[TraceabilityError]) -> list[str]:
    """Format traceability errors as human-readable messages."""
    return [f"{e.scenario_id}: broken {e.broken_link}" for e in errors]


def _run_stage5_for_threat(
    llm_client: LLMClient,
    threat,
    control_structure: ControlStructure,
    run_dir: Path,
    scenario_index: int,
    loader: TemplateLoader,
    temperature: float,
    stage_errors: list[str],
    *,
    capability_profile: CapabilityProfile | None = None,
) -> ScenarioSpec | None:
    """Run Stage 5 BDI generation for a single threat."""
    slot_parts = parse_ica_slot_id(threat.ica_slot_id)
    target_resp_id = slot_parts["controller"]

    try:
        defender_bdi = populate_defender_bdi(control_structure, target_resp_id)
    except ValueError as e:
        stage_errors.append(f"Stage 5: {e}")
        return None

    llm_result, error = generate_bdi(
        llm_client,
        defender_bdi,
        threat,
        control_structure,
        run_dir,
        loader=loader,
        capability_profile=capability_profile,
        temperature=temperature,
    )

    if error is not None or llm_result is None:
        stage_errors.append(f"Stage 5 BDI generation failed: {error}")
        return None

    try:
        spec = assemble_scenario_spec(
            defender_bdi, llm_result, threat, control_structure, scenario_index
        )
    except ValueError as e:
        # Invalid causal-factor references (or any other assembly-level
        # reference error) stop this scenario before Stage 6: no narrative,
        # attack-tree, or Gherkin call is made and no artifact is written.
        stage_errors.append(f"Stage 5: {e}")
        return None
    _validate_stage5_spec(spec, control_structure, stage_errors)
    return spec


def _validate_stage5_spec(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    stage_errors: list[str],
) -> None:
    """Run stage-local validators for a Stage 5 scenario spec."""
    _extend_validation_errors(
        (
            validate_bdi_grounding(spec, control_structure),
            validate_vulnerability_completeness(spec),
        ),
        stage_errors,
    )


def _run_stage6_for_spec(
    llm_client: LLMClient,
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    max_workers: int,
    stage_errors: list[str],
    *,
    capability_profile: CapabilityProfile | None = None,
) -> tuple[ScenarioEnvelope | None, dict | None]:
    """Run Stage 6 concretization for a single scenario spec.

    The projection is derived once (deterministically, from the Stage 5
    declared factors) and its validator-derived alignment table is passed
    to every Stage 6 prompt, so the narrative, attack-tree, and Gherkin
    calls all receive the same projection.  The canonical projection
    document is returned with the envelope for artifact writing.

    Returns:
        A (envelope, projection_doc) pair; ``None`` envelope means the
        scenario was rejected (recorded in *stage_errors*) and no
        artifact is written.
    """
    try:
        projection = project_execution(spec, control_structure)
    except ValueError as e:
        stage_errors.append(f"Stage 6 projection failed for {spec.scenario_id}: {e}")
        return None, None
    projection_doc = canonical_projection_data(projection)
    projection_alignment = render_projection_alignment_table(projection_doc)

    prompts = _build_stage6_prompts(
        spec,
        control_structure,
        loss_analysis,
        loader,
        projection_alignment=projection_alignment,
        capability_profile=capability_profile,
    )

    results = _parallel_stage6_calls(
        llm_client=llm_client,
        run_dir=run_dir,
        prompts=prompts,
        temperature=temperature,
        max_workers=max_workers,
    )

    _collect_stage6_errors(spec.scenario_id, results, stage_errors)

    narrative_text, attack_tree, gherkin_spec, gherkin_raw = _parse_stage6_results(
        results
    )

    _validate_stage6_artifacts(
        attack_tree,
        gherkin_spec,
        gherkin_raw,
        control_structure,
        loss_analysis,
        spec,
        stage_errors,
    )

    envelope = assemble_envelope(
        scenario_id=spec.scenario_id,
        scenario_spec=spec,
        narrative=narrative_text,
        attack_tree=attack_tree,
        gherkin_spec=gherkin_spec,
        gherkin_raw=gherkin_raw,
        capability_profile=capability_profile,
        control_structure=control_structure,
    )
    return envelope, projection_doc


@dataclass
class _Stage6Prompts:
    """Container for the three Stage 6 prompt pairs."""

    narrative: tuple[str, str]
    attack_tree: tuple[str, str]
    gherkin: tuple[str, str]


def _build_stage6_prompts(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    loader: TemplateLoader,
    *,
    projection_alignment: str | None = None,
    capability_profile: CapabilityProfile | None = None,
) -> _Stage6Prompts:
    """Build system/user prompt pairs for all three Stage 6 calls.

    When a validated ``projection_alignment`` table is supplied, every
    Stage 6 prompt receives the same table; otherwise the prompts render
    without one (backward compatible default).
    """
    nar_prompts = build_narrative_prompts(
        spec,
        loader,
        capability_profile=capability_profile,
        projection_alignment=projection_alignment,
    )
    tree_prompts = build_attack_tree_prompts(
        spec, control_structure, loader, projection_alignment=projection_alignment
    )
    sc = find_security_constraint(spec, loss_analysis)
    ghk_prompts = build_gherkin_prompts(
        spec, sc, loss_analysis, loader, projection_alignment=projection_alignment
    )

    return _Stage6Prompts(
        narrative=nar_prompts,
        attack_tree=tree_prompts,
        gherkin=ghk_prompts,
    )


def _collect_stage6_errors(
    scenario_id: str,
    results: dict[str, tuple[Any | None, str | None]],
    stage_errors: list[str],
) -> None:
    """Append error messages from Stage 6 call results."""
    for step in ("narrative", "attack_tree", "gherkin"):
        _text, err = results[step]
        if err:
            stage_errors.append(f"Stage 6 {step} failed for {scenario_id}: {err}")


def _parse_stage6_results(
    results: dict[str, tuple[Any | None, str | None]],
) -> tuple[str, dict, GherkinSpec | None, str]:
    """Parse Stage 6 call results with fallbacks for missing artifacts."""
    narrative_raw, _ = results["narrative"]
    attack_tree_raw, _ = results["attack_tree"]
    gherkin_raw, _ = results["gherkin"]

    narrative_text = narrative_raw or ""
    gherkin_text = gherkin_raw or ""
    attack_tree = parse_attack_tree(attack_tree_raw) or dict(_EMPTY_ATTACK_TREE)

    gherkin_spec = parse_gherkin_spec(gherkin_text) or _EMPTY_GHERKIN_SPEC

    return narrative_text, attack_tree, gherkin_spec, gherkin_text


def _validate_stage6_artifacts(
    attack_tree: dict,
    gherkin_spec: GherkinSpec | None,
    gherkin_raw: str,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    spec: ScenarioSpec,
    stage_errors: list[str],
) -> None:
    """Run stage-local validators for Stage 6 artifacts."""
    _validate_stage6_tree(attack_tree, control_structure, spec, stage_errors)
    _validate_stage6_gherkin(gherkin_spec, gherkin_raw, loss_analysis, stage_errors)


def _validate_stage6_tree(
    attack_tree: dict,
    control_structure: ControlStructure,
    spec: ScenarioSpec,
    stage_errors: list[str],
) -> None:
    """Run tree-related validators for Stage 6 artifacts."""
    _extend_validation_errors(
        (
            validate_tree_branch_coverage(attack_tree),
            validate_tree_id_references(attack_tree, control_structure),
            validate_attack_tree_root_label(
                attack_tree,
                spec.ica_type.value,
                spec.target_control_action,
            ),
        ),
        stage_errors,
    )


def _validate_stage6_gherkin(
    gherkin_spec: GherkinSpec | None,
    gherkin_raw: str,
    loss_analysis: LossAnalysis,
    stage_errors: list[str],
) -> None:
    """Run Gherkin-related validators for Stage 6 artifacts."""
    gherkin_for_validation: GherkinSpec | str = (
        gherkin_spec if gherkin_spec is not None else gherkin_raw
    )
    ghk_result = validate_gherkin_structure(gherkin_for_validation)
    if not ghk_result.passed:
        stage_errors.extend(ghk_result.errors)

    if gherkin_raw:
        id_result = validate_loss_hazard_id_references(gherkin_raw, loss_analysis)
        if not id_result.passed:
            stage_errors.extend(id_result.errors)


def _parallel_stage6_calls(
    *,
    llm_client: LLMClient,
    run_dir: Path,
    prompts: _Stage6Prompts,
    temperature: float,
    max_workers: int,
) -> dict[str, tuple[str | None, str | None]]:
    """Execute the 3 Stage 6 calls, optionally in parallel.

    Uses :func:`safe_llm_call_raw` for each call to ensure proper call
    logging and error handling. The calls are independent and can be
    parallelized via ``ThreadPoolExecutor``.
    """
    call_specs = [
        ("narrative", prompts.narrative),
        ("attack_tree", prompts.attack_tree),
        ("gherkin", prompts.gherkin),
    ]

    def _run_call(
        step: str, prompt_pair: tuple[str, str]
    ) -> tuple[str | None, str | None]:
        sys_prompt, user_prompt = prompt_pair
        text, _result, error = safe_llm_call_raw(
            llm_client=llm_client,
            system_prompt=sys_prompt,
            user_prompt=user_prompt,
            run_dir=run_dir,
            stage="stage_6",
            step=step,
            temperature=temperature,
        )
        if error is not None:
            return None, error
        return text, None

    if max_workers > 1:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                step: executor.submit(_run_call, step, pair)
                for step, pair in call_specs
            }
            return {step: f.result() for step, f in futures.items()}
    else:
        return {step: _run_call(step, pair) for step, pair in call_specs}


def _run_stage7_validations(
    envelopes: list[ScenarioEnvelope],
    specs: list[ScenarioSpec],
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    validation_errors: list[str],
) -> None:
    """Run Stage 7 validations on all specs and envelopes."""
    for spec in specs:
        _validate_spec_stage7(spec, control_structure, validation_errors)

    for env in envelopes:
        _validate_envelope_stage7(env, loss_analysis, validation_errors)


def _validate_spec_stage7(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    validation_errors: list[str],
) -> None:
    """Run stage-local validators for a single spec in Stage 7."""
    _extend_validation_errors(
        (
            validate_bdi_grounding(spec, control_structure),
            validate_vulnerability_completeness(spec),
        ),
        validation_errors,
    )


def _validate_envelope_stage7(
    envelope: ScenarioEnvelope,
    loss_analysis: LossAnalysis,
    validation_errors: list[str],
) -> None:
    """Run stage-local validators for a single envelope in Stage 7."""
    _extend_validation_errors(
        (
            validate_tree_branch_coverage(envelope.attack_tree),
            validate_attack_tree_root_label(
                envelope.attack_tree,
                envelope.ica_type.value,
                envelope.scenario_spec.target_control_action,
            ),
        ),
        validation_errors,
    )

    ghk_for_validation: GherkinSpec | str = (
        envelope.gherkin_spec
        if isinstance(envelope.gherkin_spec, GherkinSpec)
        else envelope.gherkin_raw
    )
    ghk_result = validate_gherkin_structure(ghk_for_validation)
    if not ghk_result.passed:
        validation_errors.extend(ghk_result.errors)

    id_text = _envelope_gherkin_text(envelope)
    if id_text:
        id_result = validate_loss_hazard_id_references(id_text, loss_analysis)
        if not id_result.passed:
            validation_errors.extend(id_result.errors)


def _extend_validation_errors(
    results: tuple[ValidationResult, ...],
    errors: list[str],
) -> None:
    """Append errors from each failed ValidationResult to *errors*."""
    for result in results:
        if not result.passed:
            errors.extend(result.errors)


def _envelope_gherkin_text(envelope: ScenarioEnvelope) -> str:
    """Extract Gherkin feature text from an envelope.

    Prefers ``gherkin_spec.to_feature_text()`` when the spec was
    successfully parsed (non-empty ``feature`` name) — this is guaranteed
    valid Gherkin ``.feature`` syntax. Falls back to ``gherkin_raw`` (the
    raw LLM response, which may be YAML rather than Gherkin) only when
    spec parsing failed, or to an empty string when neither is available.
    """
    spec = envelope.gherkin_spec
    if isinstance(spec, GherkinSpec) and spec.feature:
        return spec.to_feature_text()
    return envelope.gherkin_raw or ""


def _write_scenario_artifacts(
    envelope: ScenarioEnvelope,
    scenarios_dir: Path,
    projection_doc: dict | None = None,
) -> None:
    """Write scenario YAML, .feature, and canonical projection artifacts.

    The canonical projection document (``stpa-execution-projection-v1``)
    is exported as standalone JSON and YAML under
    ``scenarios/canonical/`` beside the legacy scenario YAML and Gherkin
    feature, so legacy ``*.yaml`` readers keep seeing only envelope
    documents.  When no projection is supplied only the legacy artifacts
    are written (backward compatible default).
    """
    write_yaml(envelope, scenarios_dir / f"{envelope.scenario_id}.yaml")
    feature_text = _envelope_gherkin_text(envelope)
    (scenarios_dir / f"{envelope.scenario_id}.feature").write_text(
        feature_text, encoding="utf-8"
    )
    if projection_doc is not None:
        canonical_dir = scenarios_dir / "canonical"
        canonical_dir.mkdir(parents=True, exist_ok=True)
        (canonical_dir / f"{envelope.scenario_id}.projection.json").write_text(
            export_projection_json(projection_doc), encoding="utf-8"
        )
        (canonical_dir / f"{envelope.scenario_id}.projection.yaml").write_text(
            export_projection_yaml(projection_doc), encoding="utf-8"
        )


def _write_manifest(
    run_dir: Path,
    llm_client: LLMClient,
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
    scenario_envelopes: list[ScenarioEnvelope],
    validation_errors: list[str],
    max_workers: int,
    stage_errors: list[str],
) -> None:
    """Write the run manifest YAML."""
    input_hashes = {
        "enriched_threat_set": hash_model(enriched_threat_set),
        "control_structure": hash_model(control_structure),
        "loss_analysis": hash_model(loss_analysis),
    }
    prompt_hashes = hash_prompt_templates(PROMPTS_DIR)
    stage_summary = count_calls_by_stage(run_dir)

    manifest = {
        "run_id": f"sp3-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        "run_dir": str(run_dir),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model_config": {
            "model": llm_client.model,
            "base_url": llm_client.base_url,
            "temperature": llm_client.temperature,
        },
        "input_hashes": input_hashes,
        "prompt_hashes": prompt_hashes,
        "stage_summary": stage_summary,
        "scenario_count": len(scenario_envelopes),
        "validation_error_count": len(validation_errors),
        "validation_errors": validation_errors,
        "max_workers": max_workers,
        "stage_errors": stage_errors,
        "eval_scorecard_path": "eval-scorecard.yaml",
    }

    manifest_path = run_dir / "run-manifest.yaml"
    manifest_path.write_text(
        yaml.dump(
            manifest, default_flow_style=False, sort_keys=False, allow_unicode=True
        ),
        encoding="utf-8",
    )


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-14T09:07:58Z","module_hash":"200d0f548357a14ff330793ffda7333b770806361e688a68f84942629aef037c","functions":[{"id":"func/run_sp3","name":"run_sp3","line":88,"end_line":203,"hash":"7552e6af012dc19d157a33816fb9efcb12e765dd23033e49d832e8b6de288788"},{"id":"func/_format_traceability_errors","name":"_format_traceability_errors","line":206,"end_line":208,"hash":"d92abc2bf22d0b470d038eab787624373096550a906c2b05839c1975f9fe0058"},{"id":"func/_run_stage5_for_threat","name":"_run_stage5_for_threat","line":211,"end_line":248,"hash":"c559afdd919d498af53fd5ba10fdd96ea1ea0527ef0da2f95767f8a15d1094bb"},{"id":"func/_validate_stage5_spec","name":"_validate_stage5_spec","line":251,"end_line":263,"hash":"7afa5ce8b0cf509e1f1d27059af63c025a08def4d8cb8ef33951d6f018898146"},{"id":"func/_run_stage6_for_spec","name":"_run_stage6_for_spec","line":266,"end_line":314,"hash":"199cbf2f34634bd23455eb460ea5420bb359d26d3c26fed44351b7e0fee14494"},{"id":"func/_build_stage6_prompts","name":"_build_stage6_prompts","line":326,"end_line":348,"hash":"587cca71de56d0080642fbcd1ce31ec1ba58fa294aaa5dd52bebe0bdb64d3810"},{"id":"func/_collect_stage6_errors","name":"_collect_stage6_errors","line":351,"end_line":360,"hash":"09db95ead3f7b029c2c5c203281e27fe70f7cfa7361104d1585748a43ffbe574"},{"id":"func/_parse_stage6_results","name":"_parse_stage6_results","line":363,"end_line":377,"hash":"bf3111c3de5ef646cdf440dfdbce7c6691fb1e45b27259049b0f26ec6807ebe8"},{"id":"func/_validate_stage6_artifacts","name":"_validate_stage6_artifacts","line":380,"end_line":391,"hash":"43429a4a8327ddce0781eb8c836ed6599563cf324f12de3ceb318b4933c34673"},{"id":"func/_validate_stage6_tree","name":"_validate_stage6_tree","line":394,"end_line":410,"hash":"711c2ca2d4cdeedf9331b79e13b3107954aee67df4bab7365dca1baaa6dce3cd"},{"id":"func/_validate_stage6_gherkin","name":"_validate_stage6_gherkin","line":413,"end_line":428,"hash":"ba653b5b60a81191d51d7a4c3c2b6012748ef2818af05d8618337aa2174ea3d5"},{"id":"func/_parallel_stage6_calls","name":"_parallel_stage6_calls","line":431,"end_line":474,"hash":"3d0773dc97069fae22f58eb2f4cc3a4e57da05dde1a7229e7066508d23f09a44"},{"id":"func/_run_stage7_validations","name":"_run_stage7_validations","line":477,"end_line":489,"hash":"4dc9a726c1d3351fded9526f82ee983444f416689040ad720ead87cf105c83fe"},{"id":"func/_validate_spec_stage7","name":"_validate_spec_stage7","line":492,"end_line":504,"hash":"8bc376220e835c7abf658e394c76f149c5f83440354ff24812edfe4620208061"},{"id":"func/_validate_envelope_stage7","name":"_validate_envelope_stage7","line":507,"end_line":538,"hash":"594eb3d9b47eb3a515b0dbe0b1d4fbd33f9f19842fe000eec19a1c7fc8fcf07f"},{"id":"func/_extend_validation_errors","name":"_extend_validation_errors","line":541,"end_line":548,"hash":"94feb985e3b2c4070c96068ab39a4ecfa7c03c805b7363b6b22af01630a3b570"},{"id":"func/_envelope_gherkin_text","name":"_envelope_gherkin_text","line":551,"end_line":563,"hash":"c02bfffb48480620b2623796151943f7421d96f44840d0b8f0da5fd163813688"},{"id":"func/_write_scenario_artifacts","name":"_write_scenario_artifacts","line":566,"end_line":575,"hash":"d6e964176933855357f4a7ac3302d7a4b22d21c64ef7fc989b683b450bb5b68f"},{"id":"func/_write_manifest","name":"_write_manifest","line":578,"end_line":622,"hash":"70f35d02ff2a8f8daa12c688cd5412bccad3f28e74bc23095a1b09ddb1d36626"}]}
# mutate4py-manifest-end
