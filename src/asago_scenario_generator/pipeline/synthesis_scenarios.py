"""Synthesis stages from the final structure to scenario realization.

Final ICA filling and verification, the target-realization lens, the
control-action enrichment, ordinary scenarios, accounting, and scenario
realization.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from asago_scenario_generator.pipeline.synthesis_types import (
    StageRun,
    SynthesisAdapters,
    SynthesisInputs,
    _systemic_inputs,
)
from asago_scenario_generator.pipeline.synthesis_values import (
    _declared_capability_labels,
    _dump,
    _ica_considerations,
    _ica_verification,
    _ordinary_icas,
    _semantic_digest,
)


def _run_ica(
    routes: tuple[Any, ...],
    briefs: tuple[Any, ...],
    plan: Any,
    loss_analysis: Any,
    control_structure: Any,
    profile: Any,
    inputs: SynthesisInputs,
    snapshot: Any,
    adapters: SynthesisAdapters,
) -> StageRun:
    """Run obligation-aware final ICA analysis over every final slot."""
    if adapters.fill_icas is None:
        raise ValueError("synthesis has no obligation-aware ICA adapter")
    result = adapters.fill_icas(
        routes=routes,
        briefs=briefs,
        plan=plan,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        capability_profile=profile,
        capability_snapshot=snapshot,
        inputs=_systemic_inputs(inputs),
        obligation_adapter=adapters.obligation_adapter,
        output_dir=inputs.output_dir,
        max_workers=inputs.max_workers,
    )
    if result is None:
        raise ValueError("obligation-aware ICA adapter returned no enumeration")
    verified = _run_ica_verification(
        result,
        adapters=adapters,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        inputs=_systemic_inputs(inputs),
    )
    return StageRun(verified, calls=("ica",))


def _run_ica_verification(
    result: Any,
    *,
    adapters: SynthesisAdapters,
    loss_analysis: Any,
    control_structure: Any,
    inputs: SynthesisInputs,
) -> Any:
    """Run the independent ICA verifier before ordinary Stage 5."""
    from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
        filter_ica_considerations,
        verify_final_ica_batch,
    )

    ordinary = result.ica_enumeration
    verifier = adapters.obligation_adapter
    if verifier is None or not callable(getattr(verifier, "verify_ica_hazards", None)):
        # Deterministic fakes that do not expose the provider boundary keep
        # their ordinary STPA behavior.
        return result
    filtered, batch = verify_final_ica_batch(
        verifier,
        ordinary,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        batch_id="synthesis-ica-hazard-verification",
    )

    pairs = _ica_considerations(result)
    if pairs:
        pairs = filter_ica_considerations(
            pairs,
            batch,
            enumeration=filtered,
        )
    return _attach_ica_verification(result, filtered, batch, pairs)


def _attach_ica_verification(
    result: Any,
    enumeration: Any,
    batch: Any,
    considerations: tuple[Any, ...],
) -> Any:
    """Return the slot-fill result with the verifier's evidence attached."""
    from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
        SlotFillRunResult,
    )

    updated = result.result.model_copy(
        update={
            "ica_enumeration": enumeration,
            "considerations": considerations,
            "ica_hazard_verification": batch,
        }
    )
    return SlotFillRunResult(result=updated)


def _run_target_realization(
    *,
    ica_enumeration: Any,
    loss_analysis: Any,
    control_structure: Any,
    capability_profile: Any,
    inputs: SynthesisInputs,
    adapters: SynthesisAdapters,
) -> StageRun:
    """Run the additive target lens only for an observed target profile."""
    from asago_scenario_generator.models.target_realization import (
        TargetRealizationResult,
    )
    from asago_scenario_generator.stpa.models.execution_classification import (
        ProfileBasis,
    )

    profile = inputs.execution_target_profile
    if profile is None or profile.basis is ProfileBasis.simulation:
        return StageRun(None)
    if adapters.target_realize is None:
        raise ValueError("synthesis has no target-realization adapter")
    ordinary_icas = ica_enumeration.ica_enumeration
    result = adapters.target_realize(
        model_runtime=adapters.model_runtime,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        ica_enumeration=ordinary_icas,
        capability_profile=capability_profile,
        execution_target_profile=profile,
        inputs=inputs,
        output_dir=inputs.output_dir,
    )
    if not isinstance(result, TargetRealizationResult):
        raise TypeError(
            "target-realization adapter must return TargetRealizationResult"
        )
    result.assert_integrity()
    if result.profile_digest != profile.semantic_digest:
        raise ValueError("target realization does not match execution target profile")
    return StageRun(result, calls=("target_realization",))


def _target_realized_stpa_inputs(
    *,
    target_realization: Any | None,
    loss_analysis: Any,
    control_structure: Any,
    ica_enumeration: Any,
    capability_profile: Any,
) -> tuple[Any, Any]:
    """Return the separately attested baseline-plus-target STPA union."""
    if target_realization is None or target_realization.effective_view is None:
        return control_structure, ica_enumeration

    from asago_scenario_generator.models.target_realization import (
        SystemicStpaBaseline,
    )
    from asago_scenario_generator.pipeline.target_realization import (
        project_target_realization_to_stpa,
    )

    ordinary_icas = ica_enumeration.ica_enumeration
    baseline = SystemicStpaBaseline.from_stpa(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        ica_enumeration=ordinary_icas,
        baseline_id=target_realization.baseline_id,
        declared_capabilities=_declared_capability_labels(capability_profile),
    )
    projection = project_target_realization_to_stpa(
        baseline,
        loss_analysis,
        control_structure,
        ordinary_icas,
        target_realization,
    )
    return projection.control_structure, projection.ica_enumeration


def _run_scenarios(
    ica_enumeration: Any,
    briefs: tuple[Any, ...],
    routes: tuple[Any, ...],
    plan: Any,
    loss_analysis: Any,
    control_structure: Any,
    profile: Any,
    inputs: SynthesisInputs,
    snapshot: Any,
    adapters: SynthesisAdapters,
    *,
    target_realization: Any | None = None,
    operation_enrichment: Any | None = None,
    slot_evidence: Any | None = None,
) -> StageRun:
    """Run ordinary STPA SP3 from final ICAs and structure.

    ``slot_evidence`` is the unprojected final ICA result; the obligation
    findings in each scenario context come from it, because a target
    projection keeps only the ICA enumeration.
    """
    if adapters.scenarios is None:
        raise ValueError("synthesis has no ordinary scenario adapter")
    evidence = ica_enumeration if slot_evidence is None else slot_evidence
    diagnostics: tuple[str, ...] = ()
    try:
        result = adapters.scenarios(
            model_runtime=adapters.model_runtime,
            ica_enumeration=ica_enumeration,
            briefs=briefs,
            routes=routes,
            ica_considerations=_ica_considerations(evidence),
            plan=plan,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
            capability_profile=profile,
            capability_snapshot=snapshot,
            execution_target_profile=inputs.execution_target_profile,
            target_realization=target_realization,
            target_observations=inputs.target_observations,
            enriched_operations=_verified_enriched_operations(
                operation_enrichment,
                target_realization,
            ),
            inputs=inputs,
            output_dir=inputs.output_dir,
            max_workers=inputs.max_workers,
        )
    except Exception as exc:  # noqa: BLE001 - scenario failure is non-fatal
        diagnostics = (f"scenario generation failed: {exc}",)
        result = _LocalScenarioFailure(stage_errors=(str(exc),))
    return StageRun(result, diagnostics, ("scenarios",))


@dataclass(frozen=True)
class _LocalScenarioFailure:
    """The scenario result the root records when the scenario port raises.

    It carries ``SP3RunResult``'s fields empty, and no candidate outcomes, so
    the manifest reports the candidate counts as unknown rather than zero.
    """

    stage_errors: tuple[str, ...]
    scenario_envelopes: tuple[Any, ...] = ()
    scenario_specs: tuple[Any, ...] = ()
    candidate_outcomes: None = None


def _accounting_source_pins(
    *,
    plan: Any,
    consideration: Any,
    final_loss: Any,
    final_control: Any,
    ica_enumeration: Any,
) -> tuple[Any, ...]:
    """Bind accounting to the exact final Phase 1/STPA authorities."""
    from asago_scenario_generator.models.canonical import compute_framed_digest

    values = (
        (
            "taxonomy-obligation-plan",
            "taxonomy-obligation-plan-v1",
            plan,
            _semantic_digest(plan),
        ),
        (
            "stpa-loss-analysis",
            "stpa-loss-analysis-v1",
            final_loss,
            None,
        ),
        (
            "stpa-control-structure",
            "stpa-control-structure-v1",
            final_control,
            None,
        ),
        (
            "ica-enumeration",
            "ica-enumeration-v1",
            _ordinary_icas(ica_enumeration),
            None,
        ),
    )
    supplied = tuple(consideration.source_pins)
    by_id = {pin.artifact_id: pin for pin in supplied}
    result = [
        _accounting_source_pin(
            artifact_id,
            schema,
            declared
            or compute_framed_digest(
                f"asago-scenario-generator:{artifact_id}:v1",
                _dump(value),
            ),
            by_id.get(artifact_id),
        )
        for artifact_id, schema, value, declared in values
    ]
    unknown = set(by_id) - {item[0] for item in values}
    if unknown:
        raise ValueError(
            "consideration source_pins contain unknown accounting authorities"
        )
    return tuple(result)


def _accounting_source_pin(
    artifact_id: str,
    schema: str,
    expected: str,
    current: Any,
) -> Any:
    """Reuse a supplied pin that matches the final authority, else build one."""
    from asago_scenario_generator.models.artifact_pin import ArtifactPin

    if current is None:
        return ArtifactPin(
            artifact_id=artifact_id,
            schema_version=schema,
            semantic_digest=expected,
        )
    if current.schema_version != schema or current.semantic_digest != expected:
        raise ValueError(f"source pin for {artifact_id} does not match final authority")
    return current


def _run_accounting(
    plan: Any,
    consideration: Any,
    routes: tuple[Any, ...],
    ica_enumeration: Any,
    scenario_result: Any,
    loss_analysis: Any,
    control_structure: Any,
    inputs: SynthesisInputs,
    snapshot: Any,
    adapters: SynthesisAdapters,
    source_pins: tuple[Any, ...] = (),
    slot_evidence: Any | None = None,
) -> StageRun:
    """Derive provisional accounting from the complete Phase 1 universe.

    ``slot_evidence`` is the unprojected final ICA result.  A target projection
    keeps only the ICA enumeration, so the obligation/slot pairs and hazard
    verdicts come from the result the projection started from.
    """
    ordinary_icas = _ordinary_icas(ica_enumeration)
    evidence = ica_enumeration if slot_evidence is None else slot_evidence
    pairs = _ica_considerations(evidence)
    verification = _ica_verification(evidence)
    if adapters.account is None:
        raise ValueError("synthesis has no obligation accounting adapter")
    result = adapters.account(
        plan=plan,
        consideration=consideration,
        routes=routes,
        ica_enumeration=ordinary_icas,
        ica_considerations=pairs,
        ica_verification=verification,
        source_pins=source_pins,
        scenario_result=scenario_result,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        inputs=inputs,
        capability_snapshot=snapshot,
        output_dir=inputs.output_dir,
    )
    if result is None:
        raise ValueError("obligation accounting adapter returned no artifact")
    return StageRun(result, calls=("account",))


def _run_realization(
    *,
    accounting: Any,
    ica_enumeration: Any,
    scenario_result: Any,
    adapters: SynthesisAdapters,
) -> StageRun:
    """Derive scenario realization separately from ICA-level accounting."""
    ordinary_icas = ica_enumeration.ica_enumeration
    pairs = _ica_considerations(ica_enumeration)
    scenario_specs = tuple(scenario_result.scenario_specs)
    if adapters.realize is None:
        raise ValueError("synthesis has no scenario realization adapter")
    result = adapters.realize(
        accounting=accounting,
        ica_considerations=pairs,
        ica_enumeration=ordinary_icas,
        scenario_specs=scenario_specs,
        scenario_result=scenario_result,
    )
    if result is None:
        raise ValueError("scenario realization adapter returned no artifact")
    return StageRun(result, calls=("realize",))


def _run_operation_enrichment(
    *,
    loss_analysis: Any,
    control_structure: Any,
    capability_profile: Any,
    inputs: SynthesisInputs,
    adapters: SynthesisAdapters,
) -> StageRun:
    """Run the enrichment grounding stage and persist its evidence sidecar."""
    from asago_scenario_generator.pipeline.control_action_enrichment import (
        CONTROL_ACTION_ENRICHMENT_FILENAME,
        ControlActionEnrichment,
    )
    from asago_scenario_generator.stpa.infra.yaml_io import write_yaml

    result = adapters.enrich_actions(
        model_runtime=adapters.model_runtime,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        capability_profile=capability_profile,
        execution_target_profile=inputs.execution_target_profile,
        inputs=inputs,
        output_dir=inputs.output_dir,
    )
    if result is None:
        return StageRun(None)
    if not isinstance(result, ControlActionEnrichment):
        raise TypeError(
            "enrichment adapter must return a ControlActionEnrichment value"
        )
    sidecar_path = Path(inputs.output_dir) / CONTROL_ACTION_ENRICHMENT_FILENAME
    write_yaml(result.record, sidecar_path)
    return StageRun(result, calls=("control_action_enrichment",))


def _verified_enriched_operations(
    enrichment: Any | None,
    target_realization: Any | None = None,
) -> dict[str, str]:
    """Map verified enrichment and target-realization actions to operations.

    The handoff publication seam consumes only verified views of the pre-ICA
    ``control-action-enrichment.yaml`` sidecar and the later target-realization
    artifact.  Enrichment rows win; target realization fills in the actions
    enrichment did not verify.
    """
    from asago_scenario_generator.models.target_realization import (
        verified_operations,
    )
    from asago_scenario_generator.pipeline.control_action_enrichment import (
        verified_enriched_operations,
    )

    verified = verified_enriched_operations(enrichment)
    for action_id, operation_id in verified_operations(target_realization).items():
        verified.setdefault(action_id, operation_id)
    return verified
