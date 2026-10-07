"""Production default adapters for the synthesis stage ports.

Each default resolves its model client through the run's ``ModelRuntime``;
the SP2 provider is bound once, after Phase 1 and the baseline, and shared by
routing, revision, recheck, and ICA filling.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

from asago_scenario_generator.pipeline.model_runtime import (
    ANALYSIS_DEADLINE_SECONDS,
    ANALYSIS_MAX_BATCH_SIZE,
    ModelRuntime,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.pipeline.synthesis_types import (
    SynthesisAdapters,
    SynthesisInputs,
)
from asago_scenario_generator.pipeline.synthesis_values import (
    _declared_capability_labels,
    _ordinary_icas,
    _semantic_digest,
)
from asago_scenario_generator.stpa.infra.llm import DEFAULT_TEMPERATURE
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservationSnapshot,
)


def _resolve_adapters(adapters: SynthesisAdapters | object | None) -> SynthesisAdapters:
    """Fill explicit adapter values with production defaults lazily."""
    explicit = (
        SynthesisAdapters()
        if adapters is None
        else SynthesisAdapters.from_object(adapters)
    )
    defaults = _production_defaults()
    values: dict[str, Any] = {}
    for field_name in SynthesisAdapters.__dataclass_fields__:
        supplied = getattr(explicit, field_name)
        values[field_name] = (
            supplied if supplied is not None else getattr(defaults, field_name)
        )
    return SynthesisAdapters(**values)


def _production_defaults() -> SynthesisAdapters:
    """Return production defaults without constructing a provider client."""
    # Planning is always local.  Provider-capable defaults are imported only
    # when the corresponding stage is reached, keeping Phase 1 provider-free.
    return SynthesisAdapters(
        plan_obligations=_default_plan,
        prepare_capability=_default_prepare_capability,
        build_briefs=_default_briefs,
        baseline=_default_baseline,
        consider=_default_consider,
        revise=_default_revision,
        recheck=_default_recheck,
        fill_icas=_default_fill_icas,
        target_realize=_default_target_realize,
        enrich_actions=_default_enrich_control_actions,
        scenarios=_default_scenarios,
        account=_default_account,
        realize=_default_realize,
        govern=_default_govern,
    )


def _default_govern(
    *,
    briefs: Any,
    paths: Any,
    loss_analysis: Any,
    control_structure: Any,
    inputs: SynthesisInputs,
    obligation_adapter: Any | None,
    output_dir: Path,
    **_: Any,
) -> Any:
    """Route governance risks with the shared SP2 adapter, when it has the stage."""
    if not callable(getattr(obligation_adapter, "route_governance", None)):
        return None
    from asago_scenario_generator.stpa.obligation_aware.governance_routing import (
        route_governance_rows,
    )

    return route_governance_rows(
        obligation_adapter,
        briefs=briefs,
        paths=paths,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        controls=_provider_controls(obligation_adapter, inputs),
    )


def _ensure_obligation_provider(
    adapters: SynthesisAdapters,
    inputs: SynthesisInputs,
    output_dir: Path,
) -> SynthesisAdapters:
    """Lazily bind one SP2 adapter after Phase 1 and SP1 have completed."""
    if adapters.obligation_adapter is not None:
        return adapters
    stages = (
        _default_consider,
        _default_revision,
        _default_recheck,
        _default_fill_icas,
    )
    if not any(
        any(getattr(adapters, name) is stage for stage in stages)
        for name in ("consider", "revise", "recheck", "fill_icas")
    ):
        return adapters
    return replace(
        adapters,
        obligation_adapter=_resolve_obligation_provider(
            inputs, output_dir, adapters.model_runtime
        ),
    )


def _default_prepare_capability(
    *,
    inputs: SynthesisInputs,
    model_runtime: ModelRuntime | None = None,
    **_: Any,
) -> Any:
    """Resolve a profile through the existing STPA profile adapter."""
    from asago_scenario_generator.stpa.system_model.profile import (
        derive_capability_profile,
    )
    from asago_scenario_generator.stpa.infra.templates import TemplateLoader
    from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR

    runtime = model_runtime or ModelRuntime.for_inputs(inputs)
    return derive_capability_profile(
        llm_client=runtime.client,
        use_case_text=inputs.use_case,
        run_dir=inputs.output_dir,
        template_loader=TemplateLoader(PROMPTS_DIR),
        temperature=runtime.temperature(),
    )


def _default_plan(*, taxonomy_inputs: Any, **_: Any) -> Any:
    """Invoke the pure planner after the composition root pins inputs."""
    return plan_taxonomy_obligations(taxonomy_inputs)


def _default_briefs(*, plan: Any, taxonomy_inputs: Any, **_: Any) -> Any:
    """Build neutral briefs from the exact plan/catalog input graph."""
    from asago_scenario_generator.stpa.obligation_aware import (
        build_neutral_obligation_briefs,
    )

    return build_neutral_obligation_briefs(
        plan=plan, attack_pattern_catalog=taxonomy_inputs.attack_pattern_catalog
    )


def _default_baseline(
    *,
    inputs: SynthesisInputs,
    capability_profile: Any,
    capability_profile_path: Path | None = None,
    loss_analysis_path: Path | None = None,
    output_dir: Path,
    execution_target_profile: ExecutionTargetProfile | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    model_runtime: ModelRuntime | None = None,
    **_: Any,
) -> Any:
    """Run ordinary SP1 using one resolved provider client.

    One unified analysis runs for every supplied input.  The observed
    execution target enters SP1 as evidence (owner decision, 2026-09-29
    STPA review): its inventory, state schema, session fields, and policy
    reads ground the Stage 1a hazards and constraints and every Stage 2
    call; they never select a different derivation.  A pinned loss analysis
    skips Stage 1a's model calls entirely.
    """
    from asago_scenario_generator.data.loaders import load_reviewed_risk_extraction
    from asago_scenario_generator.stpa.system_model.run import run_sp1
    from asago_scenario_generator.stpa.system_model.target_evidence import (
        build_target_evidence,
    )

    runtime = model_runtime or ModelRuntime.for_inputs(inputs)
    client, profile_name = runtime.client, runtime.profile_name
    risk_cards = list(inputs.risk_cards)
    if not risk_cards and inputs.risk_extraction_path is not None:
        risk_cards = load_reviewed_risk_extraction(inputs.risk_extraction_path)
    result = run_sp1(
        llm_client=client,
        use_case_text=inputs.use_case,
        risk_cards=risk_cards,
        run_dir=output_dir,
        profile_path=capability_profile_path,
        profile_name=profile_name,
        max_workers=inputs.max_workers,
        loss_analysis_path=loss_analysis_path or inputs.loss_analysis_path,
        # ``inputs`` is the target-blind view; the observed target arrives
        # only through the explicit keyword arguments.
        target_evidence=build_target_evidence(
            execution_target_profile, target_observations
        ),
    )
    return result


def _resolve_obligation_provider(
    inputs: SynthesisInputs,
    output_dir: Path,
    model_runtime: ModelRuntime | None = None,
) -> Any:
    """Resolve the one SP2 provider adapter shared by named STPA stages."""
    if inputs.obligation_adapter is not None:
        return inputs.obligation_adapter
    runtime = model_runtime or ModelRuntime.for_inputs(inputs)
    return runtime.obligation_adapter(Path(output_dir))


def _provider_controls(provider: Any, inputs: SynthesisInputs) -> Any:
    """Return provider controls, preserving explicit stage settings."""
    controls = getattr(provider, "controls", None)
    if controls is not None:
        return controls
    from asago_scenario_generator.stpa.obligation_aware.contracts import (
        AnalysisControls,
    )

    return AnalysisControls(
        model_profile=inputs.profile or "synthesis",
        model_name=str(getattr(provider, "model", None) or "caller-supplied"),
        deadline_seconds=ANALYSIS_DEADLINE_SECONDS,
        temperature=DEFAULT_TEMPERATURE,
        max_batch_size=ANALYSIS_MAX_BATCH_SIZE,
    )


def _default_consider(
    *,
    briefs: Any,
    loss_analysis: Any,
    control_structure: Any,
    inputs: SynthesisInputs,
    obligation_adapter: Any | None,
    output_dir: Path,
    **_: Any,
) -> Any:
    """Run one typed initial routing pass with the shared SP2 adapter."""
    from asago_scenario_generator.stpa.obligation_aware.routing import (
        route_obligations,
    )

    provider = obligation_adapter or _resolve_obligation_provider(inputs, output_dir)
    return route_obligations(
        provider,
        briefs=briefs,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        controls=_provider_controls(provider, inputs),
        purpose="initial",
    )


def _default_revision(
    *,
    gaps: tuple[Any, ...],
    plan: Any,
    loss_analysis: Any,
    control_structure: Any,
    inputs: SynthesisInputs,
    obligation_adapter: Any | None,
    output_dir: Path,
    **_: Any,
) -> Any:
    """Run the one typed additive revision attempt through SP2."""
    from asago_scenario_generator.models.obligation_consideration import (
        MissingStructuralConcept,
    )
    from asago_scenario_generator.stpa.obligation_aware.revision import (
        revise_structure_once,
    )

    provider = obligation_adapter or _resolve_obligation_provider(inputs, output_dir)
    routes = tuple(gaps or ())
    concepts: list[MissingStructuralConcept] = []
    trigger_ids: list[str] = []
    for value in routes:
        if isinstance(value, MissingStructuralConcept):
            concepts.append(value)
            if value.obligation_id is not None:
                trigger_ids.append(value.obligation_id)
            continue
        if value.obligation_id is not None:
            trigger_ids.append(value.obligation_id)
        concepts.extend(value.missing_concepts)
    return revise_structure_once(
        provider,
        gaps=concepts,
        trigger_obligation_ids=trigger_ids,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        controls=_provider_controls(provider, inputs),
        plan_digest=_semantic_digest(plan),
    )


def _default_recheck(
    *,
    briefs: Any,
    loss_analysis: Any,
    control_structure: Any,
    inputs: SynthesisInputs,
    obligation_adapter: Any | None,
    output_dir: Path,
    **_: Any,
) -> Any:
    """Run the sole complete post-revision routing pass through SP2."""
    from asago_scenario_generator.stpa.obligation_aware.routing import (
        recheck_obligations,
    )

    provider = obligation_adapter or _resolve_obligation_provider(inputs, output_dir)
    return recheck_obligations(
        provider,
        briefs=briefs,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        controls=_provider_controls(provider, inputs),
    )


def _default_fill_icas(
    *,
    briefs: Any,
    routes: Any,
    loss_analysis: Any,
    control_structure: Any,
    inputs: SynthesisInputs,
    obligation_adapter: Any | None,
    output_dir: Path,
    **_: Any,
) -> Any:
    """Fill final ICA slots with exact routed obligation evidence."""
    from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
        fill_synthesis_slots,
    )

    provider = obligation_adapter or _resolve_obligation_provider(inputs, output_dir)
    return fill_synthesis_slots(
        provider,
        briefs=briefs,
        routes=routes,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        controls=_provider_controls(provider, inputs),
    )


def _default_target_realize(
    *,
    loss_analysis: Any,
    control_structure: Any,
    ica_enumeration: Any,
    capability_profile: Any,
    execution_target_profile: ExecutionTargetProfile,
    inputs: SynthesisInputs,
    output_dir: Path,
    model_runtime: ModelRuntime | None = None,
    **_: Any,
) -> Any:
    """Run model-assisted target realization after systemic ICA completion."""
    from asago_scenario_generator.models.target_realization import (
        SystemicStpaBaseline,
    )
    from asago_scenario_generator.pipeline.target_realization import (
        realize_target_derived_icas,
        realize_target_operations,
    )
    from asago_scenario_generator.stpa.target_realization import (
        TargetDerivedICALlmFinder,
        TargetRealizationLlmInterpreter,
    )

    baseline = SystemicStpaBaseline.from_stpa(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        ica_enumeration=ica_enumeration,
        declared_capabilities=_declared_capability_labels(capability_profile),
    )
    runtime = model_runtime or ModelRuntime.for_inputs(inputs)
    interpreter = TargetRealizationLlmInterpreter(
        runtime.client,
        output_dir,
        temperature=runtime.temperature(),
        call_variant="target_realization",
    )
    mapped = realize_target_operations(
        baseline,
        execution_target_profile,
        lambda: interpreter,
    )
    finder = TargetDerivedICALlmFinder(
        runtime.client,
        output_dir,
        temperature=runtime.temperature(),
    )
    return realize_target_derived_icas(
        baseline,
        mapped,
        lambda: finder,
    )


def _default_enrich_control_actions(
    *,
    loss_analysis: Any,
    control_structure: Any,
    capability_profile: Any,
    execution_target_profile: ExecutionTargetProfile | None,
    inputs: SynthesisInputs,
    output_dir: Path,
    model_runtime: ModelRuntime | None = None,
    **_: Any,
) -> Any | None:
    """Run the pre-ICA enrichment grounding for an observed target profile.

    Owner decision (M2 unified path): known operations enrich the logical
    control actions; they never replace the control model with tool
    enumeration.  Without an observed profile, or for a simulation profile,
    there is nothing to ground and the analysis is returned unchanged.
    """
    from asago_scenario_generator.stpa.models.execution_classification import (
        ProfileBasis,
    )

    if execution_target_profile is None:
        return None
    if execution_target_profile.basis is ProfileBasis.simulation:
        return None
    from asago_scenario_generator.pipeline.control_action_enrichment import (
        enrich_control_actions,
    )
    from asago_scenario_generator.stpa.target_realization import (
        TargetRealizationLlmInterpreter,
    )

    runtime = model_runtime or ModelRuntime.for_inputs(inputs)
    interpreter = TargetRealizationLlmInterpreter(
        runtime.client,
        output_dir,
        temperature=runtime.temperature(),
        call_variant="control_action_enrichment",
    )
    return enrich_control_actions(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        profile=execution_target_profile,
        interpreter_factory=lambda: interpreter,
    )


def _default_scenarios(
    *,
    ica_enumeration: Any,
    control_structure: Any,
    loss_analysis: Any,
    inputs: SynthesisInputs,
    capability_profile: Any,
    output_dir: Path,
    execution_target_profile: ExecutionTargetProfile | None = None,
    target_realization: Any | None = None,
    target_observations: TargetObservationSnapshot | None = None,
    enriched_operations: Mapping[str, str] | None = None,
    briefs: tuple[Any, ...] = (),
    ica_considerations: tuple[Any, ...] = (),
    model_runtime: ModelRuntime | None = None,
    **_: Any,
) -> Any:
    """Run ordinary SP3 from the final ICA enumeration.

    The regular SP2 enrichment is deterministic and receives the final ICA
    model.  No taxonomy mechanism or Phase 4 graph is passed to SP3.
    ``enriched_operations`` is the verified operation view assembled from the
    run's ``control-action-enrichment.yaml`` sidecar and target-realization
    baseline rows; SP3 publishes those verified operation identities in each
    handoff's ``documented_operations``.
    """
    from asago_scenario_generator.stpa.scenario_prod.condition_family import (
        plan_family_candidates,
    )
    from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
    from asago_scenario_generator.stpa.threat_enum.catalog_enrichment import (
        enrich_threats,
    )

    client = (model_runtime or ModelRuntime.for_inputs(inputs)).client
    # ``fill_synthesis_slots`` returns a wrapper carrying both the ordinary
    # ICA enumeration and the exact obligation/slot evidence needed by
    # accounting.  SP3 consumes only the ordinary enumeration.
    ordinary_icas = _ordinary_icas(ica_enumeration)
    enriched = enrich_threats(ordinary_icas, control_structure)
    family_plan = plan_family_candidates(
        enriched.structural_threats, target_realization, target_observations
    )
    if len(family_plan.threats) != len(enriched.structural_threats):
        enriched = enriched.model_copy(
            update={"structural_threats": list(family_plan.threats)}
        )
    condition_families = family_plan.candidates
    scenario_contexts = _build_synthesis_scenario_contexts(
        enriched.structural_threats,
        control_structure,
        loss_analysis,
        briefs=briefs,
        ica_considerations=ica_considerations,
    )
    return run_sp3(
        llm_client=client,
        enriched_threat_set=enriched,
        control_structure=control_structure,
        loss_analysis=loss_analysis,
        run_dir=output_dir,
        capability_profile=capability_profile,
        max_workers=inputs.max_workers,
        scenario_contexts=scenario_contexts,
        execution_target_profile=execution_target_profile,
        target_realization=target_realization,
        target_observations=target_observations,
        observation_contract=inputs.observation_contract,
        enriched_operations=enriched_operations,
        # Finding A2: the published constraint authority derives from the
        # run's actual Stage 1a acceptance record, not from an asserted
        # reviewed stamp.
        stage_1a_source=(
            "pinned" if inputs.loss_analysis_path is not None else "derived"
        ),
        condition_families=condition_families,
    )


def _findings_by_ica(
    briefs: tuple[Any, ...],
    ica_considerations: tuple[Any, ...],
) -> dict[str, list[Any]]:
    """Project each ICA finding onto every ICA it names, in input order."""
    from asago_scenario_generator.stpa.models.scenario_context import (
        ScenarioObligationConsideration,
    )

    brief_by_id = {
        brief.obligation_id: brief
        for brief in briefs
        if getattr(brief, "obligation_id", None) is not None
    }
    by_ica: dict[str, list[ScenarioObligationConsideration]] = {}
    for pair in ica_considerations:
        if getattr(pair, "disposition", None) != "finding":
            continue
        brief = brief_by_id.get(pair.obligation_id)
        if brief is None:
            raise ValueError(
                f"ICA finding references unknown obligation {pair.obligation_id!r}"
            )
        projected = ScenarioObligationConsideration(
            obligation_id=pair.obligation_id,
            attack_pattern_id=brief.attack_pattern_id,
            attack_pattern_name=brief.attack_pattern_name,
            concise_concern=brief.attack_pattern_description,
            disposition="finding",
            rationale=pair.rationale
            or (
                "STPA identified this concern in the selected ICA after "
                "analyzing the routed control path."
            ),
            finding_ica_id=None,
        )
        for ica_id in pair.ica_ids:
            by_ica.setdefault(ica_id, []).append(
                projected.model_copy(update={"finding_ica_id": ica_id})
            )

    return by_ica


def _build_synthesis_scenario_contexts(
    threats: Iterable[Any],
    control_structure: Any,
    loss_analysis: Any,
    *,
    briefs: tuple[Any, ...],
    ica_considerations: tuple[Any, ...],
) -> dict[str, Any]:
    """Bind each Stage 5 candidate to the obligation findings its ICA carries.

    Contexts are keyed by scenario ID because one ICA can yield several
    candidates, one per condition family.
    """
    from asago_scenario_generator.stpa.scenario_prod.context import (
        build_scenario_generation_context,
    )

    by_ica = _findings_by_ica(briefs, ica_considerations)
    result: dict[str, Any] = {}
    for index, threat in enumerate(threats):
        if threat.ica_id is None:
            raise ValueError("synthesis scenario threat has no exact ICA identity")
        considerations = tuple(
            sorted(
                by_ica.get(threat.ica_id, ()),
                key=lambda item: item.obligation_id,
            )
        )
        scenario_id = f"SCN-{index + 1:03d}"
        try:
            result[scenario_id] = build_scenario_generation_context(
                threat,
                control_structure,
                loss_analysis,
                scenario_id=scenario_id,
                obligation_considerations=considerations,
            )
        except ValueError:
            # SP3 builds a missing supplied context again inside its per-threat
            # boundary.  Leaving this one out lets that boundary retain the
            # exact error for this ICA without erasing valid sibling contexts.
            continue
    return result


def _default_account(
    *,
    plan: Any,
    consideration: Any,
    ica_considerations: tuple[Any, ...],
    source_pins: tuple[Any, ...],
    ica_verification: Any | None,
    ica_enumeration: Any,
    **_: Any,
) -> Any:
    """Use the typed provisional accounting seam; never infer addressed rows."""
    from asago_scenario_generator.pipeline.obligation_consideration import (
        build_obligation_accounting,
    )

    return build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=ica_considerations,
        source_pins=source_pins,
        ica_verification=ica_verification,
        ica_enumeration=ica_enumeration,
    )


def _default_realize(
    *,
    accounting: Any,
    ica_considerations: tuple[Any, ...],
    ica_enumeration: Any,
    scenario_specs: tuple[Any, ...],
    **_: Any,
) -> Any:
    """Derive exact scenario realization without changing ICA accounting."""
    from asago_scenario_generator.pipeline.scenario_realization import (
        build_scenario_realization_assessment,
    )

    return build_scenario_realization_assessment(
        accounting=accounting,
        ica_considerations=ica_considerations,
        ica_enumeration=ica_enumeration,
        scenario_specs=scenario_specs,
    )
