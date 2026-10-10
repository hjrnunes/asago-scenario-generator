"""Pure target-realization composition seam.

The target profile is an observed execution input, not a replacement for the
systemic STPA analysis.  This module therefore accepts one attested systemic
baseline and one attested profile, gives a provider only a bounded exact view
of observed operations, and compiles its response into closed rows.  No STPA
record is edited in this pass.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, NamedTuple

from asago_scenario_generator.models.target_realization import (
    CapabilityExposureDisposition,
    CapabilityExposureRow,
    CapabilityClaim,
    SystemicControlAction,
    SystemicControlStructureSnapshot,
    SystemicControlledProcess,
    SystemicICA,
    SystemicICAEnumerationSnapshot,
    SystemicICASlot,
    SystemicElementReference,
    SystemicResponsibility,
    TargetDerivedICAFinding,
    TargetDerivedICAOperationContext,
    TargetDerivedICAProviderResponse,
    TargetDerivedICARequest,
    TargetDerivedICASlotProposal,
    SystemicStpaBaseline,
    TargetDerivedICASlot,
    TargetOperationObservation,
    TargetOperationRecord,
    TargetOperationReference,
    TargetRealizationExtensionDisposition,
    TargetRealizationExtensionProviderResponse,
    TargetRealizationExtensionRequest,
    TargetRealizationDisposition,
    TargetRealizationEffectiveView,
    TargetRealizationDenominators,
    TargetRealizationProviderResponse,
    TargetRealizationResult,
    TargetRealizationRow,
    TargetRealizationVerification,
    canonical_effective_view,
    canonical_target_realization,
    target_operation_action_description,
    derive_summary,
    verified_pair_evidence_ref,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlActionTemporality,
    ControlStructure,
    ControlledProcess,
    ElementRef,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.threat_enum.slot_creation import (
    is_wrong_duration_eligible,
)


@dataclass(frozen=True)
class TargetRealizationStpaProjection:
    """Validated STPA view for downstream SP3 consumers.

    The target-realization artifact remains closed and immutable.  This
    outward value contains deep copies of the exact public STPA models so
    existing SP3 seams can consume the additive union without receiving the
    frozen snapshot internals or mutating the baseline authorities.
    """

    control_structure: ControlStructure
    ica_enumeration: ICAEnumeration


class _ExtensionResult(NamedTuple):
    """Target-derived additions and diagnostics from one extension attempt."""

    actions: tuple[SystemicControlAction, ...] = ()
    slots: tuple[TargetDerivedICASlot, ...] = ()
    processes: tuple[SystemicControlledProcess, ...] = ()
    diagnostics: tuple[str, ...] = ()


@dataclass
class _ExtensionCompilationState:
    """Mutable compiler bookkeeping for one bounded extension attempt."""

    observed_by_identity: Mapping[tuple[str, str], TargetOperationObservation]
    eligible_ids: set[tuple[str, str]]
    baseline_action_ids: set[str]
    baseline_slot_ids: set[str]
    baseline_process_ids: set[str]
    controller_ids: set[str]
    element_ids: set[tuple[str, str]]
    record_by_identity: Mapping[tuple[str, str], int]
    records: list[TargetOperationRecord]
    next_action_ordinal: dict[str, int]
    next_process_ordinal: int
    derived_actions: list[SystemicControlAction]
    derived_slots: list[TargetDerivedICASlot]
    derived_processes: list[SystemicControlledProcess]
    derived_action_ids: set[str]
    derived_slot_ids: set[str]
    derived_process_ids: set[str]
    diagnostics: list[str]


def realize_baseline_rows(
    baseline: SystemicStpaBaseline,
    observations: Sequence[TargetOperationObservation],
    interpreter: Any,
) -> tuple[list[TargetRealizationRow], list[str]]:
    """Match every baseline action to the observed operations; keep diagnostics."""
    observation_by_identity = {item.reference.identity: item for item in observations}
    operation_views = tuple(_operation_prompt_view(item) for item in observations)
    rows: list[TargetRealizationRow] = []
    diagnostics: list[str] = []
    for action in baseline.control_actions:
        response = _response_for_action(
            interpreter,
            action,
            operation_views,
            baseline.control_structure,
        )
        row, _candidates, diagnostic = _compile_row(
            action,
            response,
            observation_by_identity,
        )
        if diagnostic:
            diagnostics.append(diagnostic)
        rows.append(row)
    return rows, diagnostics


def _response_for_action(
    interpreter: Any,
    action: SystemicControlAction,
    operation_views: Sequence[Mapping[str, Any]],
    control_structure: SystemicControlStructureSnapshot,
) -> Any:
    if interpreter is None:
        return TargetRealizationProviderResponse(
            control_action_id=action.control_action_id,
            disposition=TargetRealizationDisposition.unmapped,
        )
    return _invoke_interpreter(
        interpreter,
        action=_action_prompt_view(action, control_structure),
        operations=operation_views,
    )


def _build_operation_records(
    observations: Sequence[TargetOperationObservation],
    rows: Sequence[TargetRealizationRow],
) -> list[TargetOperationRecord]:
    selected_by_operation: dict[tuple[str, str], list[str]] = {}
    candidates_by_operation: dict[tuple[str, str], set[str]] = {}
    statuses_by_operation: dict[tuple[str, str], set[TargetRealizationDisposition]] = {}
    evidence_by_operation: dict[tuple[str, str], set[str]] = {}
    for row in rows:
        _index_row_operations(
            row,
            selected_by_operation,
            candidates_by_operation,
            statuses_by_operation,
            evidence_by_operation,
        )
    return [
        _operation_record(
            observation,
            selected_by_operation,
            candidates_by_operation,
            statuses_by_operation,
            evidence_by_operation,
        )
        for observation in observations
    ]


def _index_row_operations(
    row: TargetRealizationRow,
    selected_by_operation: dict[tuple[str, str], list[str]],
    candidates_by_operation: dict[tuple[str, str], set[str]],
    statuses_by_operation: dict[tuple[str, str], set[TargetRealizationDisposition]],
    evidence_by_operation: dict[tuple[str, str], set[str]],
) -> None:
    if row.selected_operation is not None:
        selected_by_operation.setdefault(row.selected_operation.identity, []).append(
            row.control_action_id
        )
    for candidate in row.candidate_operations:
        candidates_by_operation.setdefault(candidate.identity, set()).add(
            row.control_action_id
        )
        statuses_by_operation.setdefault(candidate.identity, set()).add(row.disposition)
        evidence_by_operation.setdefault(candidate.identity, set()).update(
            row.evidence_refs
        )
    if row.selected_operation is not None:
        evidence_by_operation.setdefault(row.selected_operation.identity, set()).update(
            row.verifier.evidence_refs
        )


def _operation_record(
    observation: TargetOperationObservation,
    selected_by_operation: Mapping[tuple[str, str], Sequence[str]],
    candidates_by_operation: Mapping[tuple[str, str], set[str]],
    statuses_by_operation: Mapping[tuple[str, str], set[TargetRealizationDisposition]],
    evidence_by_operation: Mapping[tuple[str, str], set[str]],
) -> TargetOperationRecord:
    identity = observation.reference.identity
    selected_actions = selected_by_operation.get(identity, ())
    statuses = statuses_by_operation.get(identity, set())
    disposition = _operation_disposition(selected_actions, statuses)
    return TargetOperationRecord(
        operation=observation,
        disposition=disposition,
        baseline_control_action_ids=tuple(
            selected_actions or sorted(candidates_by_operation.get(identity, set()))
        ),
        evidence_refs=tuple(
            sorted(
                set(observation.evidence_refs)
                | evidence_by_operation.get(identity, set())
            )
        ),
    )


def _operation_disposition(
    selected_actions: Sequence[str],
    statuses: set[TargetRealizationDisposition],
) -> TargetRealizationDisposition:
    if selected_actions:
        return TargetRealizationDisposition.supported
    if TargetRealizationDisposition.contradictory in statuses:
        return TargetRealizationDisposition.contradictory
    if TargetRealizationDisposition.ambiguous in statuses:
        return TargetRealizationDisposition.ambiguous
    return TargetRealizationDisposition.unmapped


def _build_realization_result(
    *,
    baseline: SystemicStpaBaseline,
    profile: ExecutionTargetProfile,
    rows: Sequence[TargetRealizationRow],
    records: Sequence[TargetOperationRecord],
    capabilities: Sequence[CapabilityExposureRow],
    diagnostics: Sequence[str],
    derived_actions: Sequence[SystemicControlAction],
    derived_slots: Sequence[TargetDerivedICASlot],
    derived_processes: Sequence[SystemicControlledProcess],
) -> TargetRealizationResult:
    uncovered = tuple(
        item.operation_ref
        for item in records
        if item.disposition is not TargetRealizationDisposition.supported
    )
    summary = derive_summary(rows, records, capabilities, derived_actions)
    result = TargetRealizationResult(
        baseline_id=baseline.baseline_id,
        baseline_digest=baseline.baseline_digest or baseline.compute_baseline_digest(),
        profile_id=profile.target_id,
        profile_digest=profile.semantic_digest,
        rows=tuple(rows),
        operation_records=tuple(records),
        capability_reconciliation=capabilities,
        uncovered_operations=uncovered,
        diagnostics=tuple(diagnostics),
        target_derived_control_actions=tuple(derived_actions),
        target_derived_ica_slots=tuple(derived_slots),
        target_derived_controlled_processes=tuple(derived_processes),
        summary=summary,
    )
    return canonical_target_realization(result)


class BaselineRowsMismatchError(ValueError):
    """Supplied baseline rows do not cover exactly the baseline's control actions."""


def _require_rows_cover_baseline(
    baseline: SystemicStpaBaseline,
    rows: Sequence[TargetRealizationRow],
) -> None:
    expected = sorted(
        (action.control_action_id, action.controller_id)
        for action in baseline.control_actions
    )
    supplied = sorted((row.control_action_id, row.controller_id) for row in rows)
    if supplied == expected:
        return
    missing = sorted(set(expected) - set(supplied))
    unexpected = sorted(set(supplied) - set(expected))
    raise BaselineRowsMismatchError(
        "baseline rows do not cover exactly the baseline control actions: "
        f"missing={missing}, unexpected={unexpected}, "
        f"expected {len(expected)} rows and received {len(supplied)}"
    )


def realize_target_operations(
    baseline: SystemicStpaBaseline,
    profile: ExecutionTargetProfile,
    extension: Any,
    *,
    baseline_rows: Sequence[TargetRealizationRow],
) -> TargetRealizationResult:
    """Map exact observed operations to an immutable systemic baseline.

    ``profile`` is intentionally typed at the caller boundary by the shared
    execution-target model.  The implementation uses only its public
    ``resources -> operations`` observation seam, so producer revisions can
    add semantic interpretation fields without making this module infer new
    meaning.  A raw mapping or namespace is rejected before the provider is
    constructed.

    ``baseline_rows`` is the matching already made for exactly this
    baseline's control actions (the pre-ICA enrichment rows, built by
    :func:`realize_baseline_rows`).  The seam adopts those rows and makes no
    map or verify call, so a run matches each action to the target once.

    ``extension`` is the bounded extension adapter: an object whose
    ``extend(request)`` receives one ``TargetRealizationExtensionRequest``.
    The seam calls ``extend`` once, and only when an observed operation lacks
    a supported baseline row.  ``None`` or an adapter without a callable
    ``extend`` leaves each such operation diagnosed.  Accepted additions are
    compiled as target-derived records after the baseline rows.
    """
    _require_baseline(baseline)
    _require_profile(profile)
    baseline.assert_integrity()
    _assert_profile_integrity(profile)
    observations = observed_operations(profile)
    _require_rows_cover_baseline(baseline, baseline_rows)
    rows = list(baseline_rows)
    records = _build_operation_records(observations, rows)
    derived_actions, derived_slots, derived_processes, extension_diagnostics = (
        _run_bounded_target_extension(
            baseline=baseline,
            observations=observations,
            records=records,
            extension=extension,
        )
    )
    capabilities = _capability_rows(baseline, observations, rows, profile=profile)
    return _build_realization_result(
        baseline=baseline,
        profile=profile,
        rows=rows,
        records=records,
        capabilities=capabilities,
        diagnostics=tuple(extension_diagnostics),
        derived_actions=derived_actions,
        derived_slots=derived_slots,
        derived_processes=derived_processes,
    )


def realize_target_derived_icas(
    baseline: SystemicStpaBaseline,
    realization: TargetRealizationResult,
    finder: Any,
) -> TargetRealizationResult:
    """Compile verified target-derived ICA findings into an additive view.

    The seam is deliberately a second, pure step after
    :func:`realize_target_operations`.  It makes one provider attempt for all
    accepted target-derived slots, compiles the provider response immediately
    to the closed target-derived finding model, and returns a new immutable
    realization value.  The returned value carries ``effective_view`` with
    the baseline and target-derived control/ICA unions; the original baseline
    and the input realization are untouched.

    ``finder`` is the finding adapter: a callable that receives one
    ``TargetDerivedICARequest``.  A finder that is not callable, or that
    raises, becomes a ``target-derived ICA finding provider failed``
    diagnostic.

    A provider may return a finding only for a known target-derived slot and
    must use the exact slot-relative ICA identity; a finding for any other
    slot is dropped with a diagnostic.  Only findings carrying a
    ``verified`` verification status enter the effective candidate universe.
    Rejected or unverified findings leave their target slot visible as a
    traceable N/A slot and add a diagnostic, while invented identities or
    references fail closed.
    """
    _require_baseline(baseline)
    if not isinstance(realization, TargetRealizationResult):
        raise TypeError("realization must be a TargetRealizationResult")
    baseline.assert_integrity()
    realization.assert_integrity()
    _assert_realization_matches_baseline(baseline, realization)

    findings, diagnostics = _attempt_target_derived_ica_findings(
        baseline,
        realization,
        finder,
    )

    effective_view = _build_effective_view(
        baseline=baseline,
        realization=realization,
        findings=findings,
        diagnostics=diagnostics,
    )
    return _replace_realization_with_effective_view(
        realization,
        findings=findings,
        effective_view=effective_view,
        diagnostics=tuple(diagnostics),
    )


def _attempt_target_derived_ica_findings(
    baseline: SystemicStpaBaseline,
    realization: TargetRealizationResult,
    finder: Any,
) -> tuple[tuple[TargetDerivedICAFinding, ...], tuple[str, ...]]:
    derived_slots = realization.target_derived_ica_slots
    if not derived_slots:
        return (), ()
    if not realization.target_derived_control_actions:  # pragma: no cover
        raise ValueError("target-derived ICA slots require target-derived actions")
    request = TargetDerivedICARequest(
        baseline=baseline,
        target_derived_control_actions=realization.target_derived_control_actions,
        target_derived_ica_slots=derived_slots,
        target_operation_context=_target_operation_context(realization),
    )
    return _invoke_and_compile_target_derived_icas(
        finder,
        request,
        baseline,
        realization,
    )


def _target_operation_context(
    realization: TargetRealizationResult,
) -> tuple[TargetDerivedICAOperationContext, ...]:
    """Carry each accepted derived action's exact selected operation forward."""
    action_ids = {
        item.control_action_id for item in realization.target_derived_control_actions
    }
    contexts = [
        TargetDerivedICAOperationContext(
            control_action_id=record.target_derived_control_action_id,
            operation=record.operation,
        )
        for record in realization.operation_records
        if record.provenance.value == "target_derived"
        and record.target_derived_control_action_id in action_ids
    ]
    return tuple(sorted(contexts, key=lambda item: item.operation.reference.identity))


def _invoke_and_compile_target_derived_icas(
    finder: Any,
    request: TargetDerivedICARequest,
    baseline: SystemicStpaBaseline,
    realization: TargetRealizationResult,
) -> tuple[tuple[TargetDerivedICAFinding, ...], tuple[str, ...]]:
    try:
        response = _invoke_target_derived_ica_interpreter(finder, request)
    except Exception as exc:  # noqa: BLE001 - retain provider-boundary diagnostics
        return (), (
            f"target-derived ICA finding provider failed: {type(exc).__name__}: {exc}",
        )
    compiled = _compile_target_derived_ica_response(response)
    return _compile_target_derived_ica_findings(
        baseline=baseline,
        realization=realization,
        response=compiled,
    )


def project_target_realization_to_stpa(
    baseline: SystemicStpaBaseline,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    ica_enumeration: ICAEnumeration,
    realization: TargetRealizationResult,
) -> TargetRealizationStpaProjection:
    """Project one realized result into exact STPA models for downstream SP3.

    ``baseline`` is attested against the three exact typed authorities before
    any projection occurs.  The authority models are copied deeply, then the
    target-derived actions, controlled processes, slots, and verified ICAs of
    the realization's effective view are appended.  Baseline objects and the
    input realization are never modified.  A result that has not passed
    :func:`realize_target_derived_icas` carries no effective view and is
    rejected, so an SP3 caller cannot omit target-derived candidate findings.
    """
    _require_baseline(baseline)
    _require_projection_types(
        loss_analysis,
        control_structure,
        ica_enumeration,
        realization,
    )
    baseline.assert_integrity()
    realization.assert_integrity()
    _assert_realization_matches_baseline(baseline, realization)
    _assert_authorities_match_baseline(
        baseline,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        ica_enumeration=ica_enumeration,
    )
    view = _require_effective_view(realization)

    projected_control_structure = _project_control_structure_to_stpa(
        control_structure,
        view,
    )
    projected_ica_enumeration = _project_ica_enumeration_to_stpa(
        ica_enumeration,
        view,
    )
    projected_ica_enumeration.validate_against(
        loss_analysis,
        projected_control_structure,
    )
    return TargetRealizationStpaProjection(
        control_structure=projected_control_structure,
        ica_enumeration=projected_ica_enumeration,
    )


def _require_projection_types(
    loss_analysis: object,
    control_structure: object,
    ica_enumeration: object,
    realization: object,
) -> None:
    checks = (
        (loss_analysis, LossAnalysis, "loss_analysis"),
        (control_structure, ControlStructure, "control_structure"),
        (ica_enumeration, ICAEnumeration, "ica_enumeration"),
        (realization, TargetRealizationResult, "realization"),
    )
    for value, expected, name in checks:
        if not isinstance(value, expected):
            raise TypeError(f"{name} must be a typed {expected.__name__}")


def _require_effective_view(
    realization: TargetRealizationResult,
) -> TargetRealizationEffectiveView:
    if realization.effective_view is None:
        raise ValueError(
            "target realization must pass realize_target_derived_icas before SP3"
        )
    return realization.effective_view


def _assert_authorities_match_baseline(
    baseline: SystemicStpaBaseline,
    *,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    ica_enumeration: ICAEnumeration,
) -> None:
    """Ensure exact live authorities are the ones used to attest the baseline."""
    authority_baseline = SystemicStpaBaseline.from_stpa(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        ica_enumeration=ica_enumeration,
        baseline_id=baseline.baseline_id,
        prompt_hashes=baseline.prompt_hashes,
        reference_inventory=baseline.reference_inventory,
        source_pins=baseline.source_pins,
        declared_capabilities=baseline.declared_capabilities,
    )
    if authority_baseline.baseline_digest != baseline.baseline_digest:
        raise ValueError("typed STPA authorities do not match the attested baseline")


def _project_control_structure_to_stpa(
    control_structure: ControlStructure,
    view: TargetRealizationEffectiveView,
) -> ControlStructure:
    """Deep-copy the typed structure and append the view's target additions."""
    processes = list(control_structure.controlled_processes) + [
        ControlledProcess(cp_id=process.cp_id, description=process.description)
        for process in view.target_derived_controlled_processes
    ]
    process_ids = {item.cp_id for item in processes}
    added = _target_actions_by_controller(view)
    responsibilities = [
        responsibility.model_copy(
            update={
                "control_actions": [
                    item.model_copy(deep=True)
                    for item in responsibility.control_actions
                ]
                + [
                    _control_action_to_stpa(snapshot, process_ids)
                    for snapshot in added.get(responsibility.resp_id, ())
                ]
            },
            deep=True,
        )
        for responsibility in control_structure.responsibilities
    ]
    return ControlStructure.model_validate(
        {
            "responsibilities": responsibilities,
            "controlled_processes": processes,
            "coordination_links": control_structure.coordination_links,
        }
    )


def _target_actions_by_controller(
    view: TargetRealizationEffectiveView,
) -> dict[str, list[SystemicControlAction]]:
    """Return each controller's appended actions in effective-view order."""
    baseline_ids = set(view.baseline_control_action_ids)
    return {
        responsibility.resp_id: [
            action
            for action in responsibility.control_actions
            if action.control_action_id not in baseline_ids
        ]
        for responsibility in view.effective_control_structure.responsibilities
    }


def _control_action_to_stpa(
    snapshot: SystemicControlAction,
    controlled_process_ids: set[str],
) -> ControlAction:
    """Convert one deterministic closed action into a validated STPA action."""
    return ControlAction(
        ca_id=snapshot.control_action_id,
        description=snapshot.description,
        target=_project_action_target(snapshot, controlled_process_ids),
        effect_kind=(
            None
            if snapshot.effect_kind is None
            else ControlActionEffectKind(snapshot.effect_kind)
        ),
        temporality=_enum_temporality(snapshot.temporality),
    )


def _project_action_target(
    snapshot: SystemicControlAction,
    controlled_process_ids: set[str],
) -> ElementRef | None:
    target = snapshot.target
    if target is None:
        return None
    reference_type = _target_reference_type(target.type)
    _require_known_target_reference(reference_type, target.id, controlled_process_ids)
    return ElementRef(type=reference_type, id=target.id)


def _target_reference_type(value: str) -> ReferenceType:
    try:
        return ReferenceType(value)
    except ValueError as exc:
        raise ValueError(
            f"target-derived action target type is not a typed STPA reference: {value}"
        ) from exc


def _require_known_target_reference(
    reference_type: ReferenceType,
    target_id: str,
    controlled_process_ids: set[str],
) -> None:
    if (
        reference_type is ReferenceType.controlled_process
        and target_id not in controlled_process_ids
    ):
        raise ValueError(
            "target-derived action references an unknown controlled process: "
            f"{target_id}"
        )


def _enum_temporality(value: str | None) -> ControlActionTemporality | None:
    return None if value is None else ControlActionTemporality(value)


def _project_ica_enumeration_to_stpa(
    ica_enumeration: ICAEnumeration,
    view: TargetRealizationEffectiveView,
) -> ICAEnumeration:
    """Deep-copy baseline slots and append the view's target-derived slots."""
    baseline_slot_ids = set(view.baseline_ica_slot_ids)
    slots = [item.model_copy(deep=True) for item in ica_enumeration.slots]
    slots.extend(
        _ica_slot_to_stpa(slot)
        for slot in view.effective_ica_enumeration.slots
        if slot.slot_id not in baseline_slot_ids
    )
    return ICAEnumeration.model_validate({"slots": slots})


def _ica_slot_to_stpa(slot: SystemicICASlot) -> ICASlot:
    try:
        uca_type = UCAType(slot.uca_type)
    except ValueError as exc:
        raise ValueError(
            f"target-derived ICA slot has an unknown UCA type: {slot.uca_type}"
        ) from exc
    return ICASlot(
        slot_id=slot.slot_id,
        responsibility=slot.responsibility,
        coordination_link=slot.coordination_link,
        control_action=slot.control_action,
        action_temporality=_enum_temporality(slot.action_temporality),
        uca_type=uca_type,
        is_na=slot.is_na,
        icas=[
            ICA(
                ica_id=ica.ica_id,
                ica_text=ica.ica_text,
                deviation=ica.deviation,
                hazardous_context=ica.hazardous_context,
                loss_scenario=ica.loss_scenario,
                related_hazards=list(ica.related_hazards),
                related_constraints=list(ica.related_constraints),
                quality_warnings=list(ica.quality_warnings),
            )
            for ica in slot.icas
        ],
        na_justification=slot.na_justification,
        unresolved_reason=slot.unresolved_reason,
    )


def _assert_realization_matches_baseline(
    baseline: SystemicStpaBaseline,
    realization: TargetRealizationResult,
) -> None:
    """Verify that the effective-view input is pinned to this baseline."""
    if realization.baseline_id != baseline.baseline_id:
        raise ValueError("target realization baseline_id does not match baseline")
    if realization.baseline_digest != baseline.baseline_digest:
        raise ValueError("target realization baseline_digest does not match baseline")


def _invoke_target_derived_ica_interpreter(
    interpreter: Any,
    request: TargetDerivedICARequest,
) -> Any:
    """Invoke one target-derived ICA adapter with one exact typed request."""
    if not callable(interpreter):
        raise TypeError("target-derived ICA finder is not callable")
    return interpreter(request)


def _compile_target_derived_ica_response(
    response: Any,
) -> TargetDerivedICAProviderResponse:
    """Compile provider output before reading any candidate fields."""
    if isinstance(response, TargetDerivedICAProviderResponse):
        return response
    if isinstance(response, Mapping):
        return TargetDerivedICAProviderResponse.model_validate(response)
    raise TypeError(
        "target-derived ICA finder must return a "
        "TargetDerivedICAProviderResponse or exact response mapping"
    )


def _compile_target_derived_ica_findings(
    *,
    baseline: SystemicStpaBaseline,
    realization: TargetRealizationResult,
    response: TargetDerivedICAProviderResponse,
) -> tuple[tuple[TargetDerivedICAFinding, ...], tuple[str, ...]]:
    """Accept only verified findings for the exact accepted target slots."""
    slots = {item.slot_id: item for item in realization.target_derived_ica_slots}
    baseline_ica_ids, hazard_ids, constraint_ids = _target_ica_reference_sets(baseline)
    by_slot, diagnostics = _group_target_ica_findings(
        response.findings,
        slots,
        baseline_ica_ids,
        hazard_ids,
        constraint_ids,
    )
    accepted: list[TargetDerivedICAFinding] = []
    for slot_id in sorted(slots):
        slot_findings = by_slot.get(slot_id, [])
        verified, slot_diagnostics = _verified_slot_findings(slot_id, slot_findings)
        _require_contiguous_target_ica_ids(slot_id, verified)
        for finding in verified:
            compiled, diagnostic = _compile_owner_constraints_for_target_finding(
                baseline=baseline,
                realization=realization,
                slot=slots[slot_id],
                finding=finding,
            )
            if compiled is None:
                diagnostics.append(diagnostic)
            else:
                accepted.append(compiled)
        diagnostics.extend(slot_diagnostics)
    accepted.sort(key=lambda item: (item.slot_id, item.ica_id))
    return tuple(accepted), tuple(diagnostics)


def _compile_owner_constraints_for_target_finding(
    *,
    baseline: SystemicStpaBaseline,
    realization: TargetRealizationResult,
    slot: TargetDerivedICASlot,
    finding: TargetDerivedICAFinding,
) -> tuple[TargetDerivedICAFinding | None, str]:
    """Bind one verified target finding to its exact owner constraints.

    Target-derived ICA prose may omit constraint references, but the effective
    Stage 5 context cannot.  In that case the compiler derives references only
    from the selected action owner's existing ``security_constraint_refs`` and
    the finding's cited hazards.  A provider-supplied subset is retained only
    when every ID is known, owner-owned, and hazard-compatible.  No global
    constraint or description search is used.
    """
    owner, diagnostic = _target_finding_owner(
        baseline=baseline, realization=realization, slot=slot, finding=finding
    )
    if owner is None:
        return None, diagnostic

    constraints_by_id = {
        item.constraint_id: item for item in baseline.loss_analysis.security_constraints
    }
    owner_compatible = _owner_hazard_compatible_constraints(
        owner, constraints_by_id, finding
    )
    if not owner_compatible:
        return None, _target_constraint_diagnostic(
            finding,
            "no exact owner-compatible governing constraint exists for its cited hazards",
        )

    compatible_ids = set(owner_compatible)
    supplied_ids = tuple(finding.related_constraints)
    invalid_supplied = set(supplied_ids) - compatible_ids
    if invalid_supplied:
        return None, _target_constraint_diagnostic(
            finding,
            "it cites constraint(s) outside the exact owner/hazard set: "
            + ", ".join(sorted(invalid_supplied)),
        )

    selected_ids = supplied_ids or tuple(sorted(compatible_ids))
    # All selected IDs were looked up above or were validated at the provider
    # boundary; keep this check local so future changes cannot reintroduce a
    # dangling context reference.
    if any(constraint_id not in constraints_by_id for constraint_id in selected_ids):
        return None, _target_constraint_diagnostic(
            finding,
            "it retains an unknown governing constraint reference",
        )
    return finding.model_copy(update={"related_constraints": selected_ids}), ""


def _target_finding_owner(
    *,
    baseline: SystemicStpaBaseline,
    realization: TargetRealizationResult,
    slot: TargetDerivedICASlot,
    finding: TargetDerivedICAFinding,
) -> tuple[Responsibility | None, str]:
    """Return the one baseline responsibility owning the slot's action.

    When no single exact owner exists, return None and the diagnostic.
    """
    actions_by_id = {
        item.control_action_id: item
        for item in realization.target_derived_control_actions
    }
    action = actions_by_id.get(slot.control_action)
    if action is None:
        return None, _target_constraint_diagnostic(
            finding,
            "its target-derived control action is not present",
        )
    if slot.responsibility != action.controller_id:
        return None, _target_constraint_diagnostic(
            finding,
            "its slot responsibility does not match the action owner",
        )
    owners = [
        item
        for item in baseline.control_structure.responsibilities
        if item.resp_id == action.controller_id
    ]
    if len(owners) != 1:
        return None, _target_constraint_diagnostic(
            finding,
            "its action has no single exact baseline responsibility owner",
        )
    return owners[0], ""


def _owner_hazard_compatible_constraints(
    owner: Responsibility,
    constraints_by_id: Mapping[str, Any],
    finding: TargetDerivedICAFinding,
) -> list[str]:
    """Return the owner's known constraints that share a cited hazard."""
    cited_hazards = set(finding.related_hazards)
    owner_compatible: list[str] = []
    for constraint_id in owner.security_constraint_refs:
        constraint = constraints_by_id.get(constraint_id)
        if constraint is None:
            continue
        if set(constraint.related_hazards) & cited_hazards:
            owner_compatible.append(constraint_id)
    return owner_compatible


def _target_constraint_diagnostic(
    finding: TargetDerivedICAFinding,
    detail: str,
) -> str:
    """Describe why one verified target finding remains unresolved."""
    return f"target-derived ICA finding {finding.ica_id} is unresolved: {detail}"


def _target_ica_reference_sets(
    baseline: SystemicStpaBaseline,
) -> tuple[set[str], set[str], set[str]]:
    hazard_ids = {item.hazard_id for item in baseline.loss_analysis.hazards}
    constraint_ids = {
        item.constraint_id for item in baseline.loss_analysis.security_constraints
    }
    constraint_ids.update(
        item.rc_id
        for responsibility in baseline.control_structure.responsibilities
        for item in responsibility.responsibility_constraints
    )
    return set(baseline.ica_ids), hazard_ids, constraint_ids


def _group_target_ica_findings(
    findings: Sequence[TargetDerivedICAFinding],
    slots: Mapping[str, Any],
    baseline_ica_ids: set[str],
    hazard_ids: set[str],
    constraint_ids: set[str],
) -> tuple[dict[str, list[TargetDerivedICAFinding]], list[str]]:
    """Group findings by known slot; an unknown slot drops only its finding."""
    by_slot: dict[str, list[TargetDerivedICAFinding]] = {}
    diagnostics: list[str] = []
    for finding in findings:
        if finding.slot_id not in slots:
            diagnostics.append(
                _target_constraint_diagnostic(
                    finding, f"unknown slot {finding.slot_id}"
                )
            )
            continue
        _validate_target_ica_finding(
            finding,
            baseline_ica_ids,
            hazard_ids,
            constraint_ids,
        )
        by_slot.setdefault(finding.slot_id, []).append(finding)
    return by_slot, diagnostics


def _validate_target_ica_finding(
    finding: TargetDerivedICAFinding,
    baseline_ica_ids: set[str],
    hazard_ids: set[str],
    constraint_ids: set[str],
) -> None:
    if finding.ica_id in baseline_ica_ids:
        raise ValueError(
            f"target-derived ICA identity collides with baseline: {finding.ica_id}"
        )
    _require_known_references(finding, hazard_ids, constraint_ids)


def _require_known_references(
    finding: TargetDerivedICAFinding,
    hazard_ids: set[str],
    constraint_ids: set[str],
) -> None:
    unknown_hazards = set(finding.related_hazards) - hazard_ids
    if unknown_hazards:
        raise ValueError(
            "target-derived ICA references unknown hazard(s): "
            + ", ".join(sorted(unknown_hazards))
        )
    unknown_constraints = set(finding.related_constraints) - constraint_ids
    if unknown_constraints:
        raise ValueError(
            "target-derived ICA references unknown constraint(s): "
            + ", ".join(sorted(unknown_constraints))
        )


def _verified_slot_findings(
    slot_id: str,
    findings: Sequence[TargetDerivedICAFinding],
) -> tuple[list[TargetDerivedICAFinding], tuple[str, ...]]:
    verified = [item for item in findings if item.verification.status == "verified"]
    diagnostics: list[str] = [
        f"target-derived ICA finding {item.ica_id} was not independently verified "
        f"for slot {slot_id} ({item.verification.status}: "
        f"{item.verification.detail})"
        for item in findings
        if item.verification.status != "verified"
    ]
    if not findings:
        diagnostics.append(f"no target-derived ICA finding for accepted slot {slot_id}")
    return verified, tuple(diagnostics)


def _require_contiguous_target_ica_ids(
    slot_id: str,
    findings: Sequence[TargetDerivedICAFinding],
) -> None:
    indexes = sorted(int(item.ica_id[len(slot_id) + 1 :]) for item in findings)
    if indexes != list(range(1, len(indexes) + 1)):
        raise ValueError(
            f"target-derived ICA identities must be contiguous per slot: {slot_id}"
        )


def _replace_realization_with_effective_view(
    realization: TargetRealizationResult,
    *,
    findings: Sequence[TargetDerivedICAFinding],
    effective_view: TargetRealizationEffectiveView,
    diagnostics: Sequence[str],
) -> TargetRealizationResult:
    """Create a fresh content-addressed result carrying the effective view."""
    payload = realization.model_dump(
        mode="json",
        exclude={
            "semantic_digest",
            "target_derived_ica_findings",
            "effective_view",
            "diagnostics",
        },
    )
    payload["target_derived_ica_findings"] = tuple(
        item.model_dump(mode="json") for item in findings
    )
    payload["effective_view"] = effective_view.model_dump(mode="json")
    payload["diagnostics"] = tuple(
        sorted(set(realization.diagnostics) | set(diagnostics))
    )
    return canonical_target_realization(TargetRealizationResult.model_validate(payload))


def _build_effective_view(
    *,
    baseline: SystemicStpaBaseline,
    realization: TargetRealizationResult,
    findings: Sequence[TargetDerivedICAFinding],
    diagnostics: Sequence[str],
) -> TargetRealizationEffectiveView:
    """Assemble a closed baseline-plus-target union without mutating inputs."""
    derived_actions = tuple(realization.target_derived_control_actions)
    derived_slots = tuple(realization.target_derived_ica_slots)
    findings = tuple(findings)
    effective_control_structure = _combine_control_structure(
        baseline, derived_actions, realization.target_derived_controlled_processes
    )
    effective_ica_enumeration = _combine_ica_enumeration(
        baseline, derived_slots, findings
    )
    view = TargetRealizationEffectiveView(
        baseline_id=baseline.baseline_id,
        baseline_digest=baseline.baseline_digest or baseline.compute_baseline_digest(),
        profile_id=realization.profile_id,
        profile_digest=realization.profile_digest,
        baseline_control_action_ids=tuple(
            item.control_action_id for item in baseline.control_actions
        ),
        baseline_controlled_process_ids=tuple(
            item.cp_id for item in baseline.control_structure.controlled_processes
        ),
        baseline_ica_slot_ids=tuple(
            item.slot_id for item in baseline.ica_enumeration.slots
        ),
        baseline_ica_ids=baseline.ica_ids,
        effective_control_structure=effective_control_structure,
        effective_ica_enumeration=effective_ica_enumeration,
        target_derived_control_actions=derived_actions,
        target_derived_controlled_processes=realization.target_derived_controlled_processes,
        target_derived_ica_slots=derived_slots,
        target_derived_ica_findings=findings,
        denominators=TargetRealizationDenominators(
            baseline_control_actions=len(baseline.control_actions),
            target_derived_control_actions=len(derived_actions),
            baseline_ica_slots=len(baseline.ica_enumeration.slots),
            target_derived_ica_slots=len(derived_slots),
            baseline_ica_findings=len(baseline.ica_ids),
            target_derived_ica_findings=len(findings),
        ),
        diagnostics=tuple(diagnostics),
    )
    return canonical_effective_view(view)


def _combine_control_structure(
    baseline: SystemicStpaBaseline,
    derived_actions: Sequence[SystemicControlAction],
    derived_processes: Sequence[SystemicControlledProcess],
) -> SystemicControlStructureSnapshot:
    """Copy the baseline structure and append actions under existing controllers."""
    by_controller: dict[str, list[SystemicControlAction]] = {}
    responsibility_ids = {
        item.resp_id for item in baseline.control_structure.responsibilities
    }
    for action in derived_actions:
        if action.controller_id not in responsibility_ids:
            raise ValueError(
                "target-derived action controller is not in the baseline: "
                f"{action.controller_id}"
            )
        by_controller.setdefault(action.controller_id, []).append(action)
    responsibilities: list[SystemicResponsibility] = []
    for responsibility in baseline.control_structure.responsibilities:
        actions = tuple(responsibility.control_actions) + tuple(
            sorted(
                by_controller.get(responsibility.resp_id, []),
                key=lambda item: item.control_action_id,
            )
        )
        responsibility_payload = responsibility.model_dump(mode="python")
        responsibility_payload["control_actions"] = actions
        responsibilities.append(SystemicResponsibility(**responsibility_payload))
    return SystemicControlStructureSnapshot(
        responsibilities=tuple(responsibilities),
        controlled_processes=(
            tuple(baseline.control_structure.controlled_processes)
            + tuple(sorted(derived_processes, key=lambda item: item.cp_id))
        ),
        coordination_links=baseline.control_structure.coordination_links,
    )


def _combine_ica_enumeration(
    baseline: SystemicStpaBaseline,
    derived_slots: Sequence[TargetDerivedICASlot],
    findings: Sequence[TargetDerivedICAFinding],
) -> SystemicICAEnumerationSnapshot:
    """Copy baseline ICA slots and append target slots with verified ICAs."""
    findings_by_slot: dict[str, list[TargetDerivedICAFinding]] = {}
    for finding in findings:
        findings_by_slot.setdefault(finding.slot_id, []).append(finding)
    target_snapshots: list[SystemicICASlot] = []
    for slot in derived_slots:
        slot_findings = tuple(
            sorted(
                findings_by_slot.get(slot.slot_id, []),
                key=lambda item: item.ica_id,
            )
        )
        icas = tuple(_systemic_ica_from_target_finding(item) for item in slot_findings)
        target_snapshots.append(
            SystemicICASlot(
                slot_id=slot.slot_id,
                responsibility=slot.responsibility,
                coordination_link=None,
                control_action=slot.control_action,
                action_temporality=slot.action_temporality,
                uca_type=slot.uca_type,
                # No target-derived finding is a provider/verifier gap until
                # a caller supplies an explicit reviewed N/A decision.
                is_na=False,
                icas=icas,
                na_justification=None,
                unresolved_reason=(
                    None
                    if icas
                    else (
                        "target-derived ICA finding was not independently verified "
                        "or had no exact owner-compatible governing constraint"
                    )
                ),
            )
        )
    baseline_slots = tuple(baseline.ica_enumeration.slots)
    return SystemicICAEnumerationSnapshot(
        slots=baseline_slots + tuple(target_snapshots)
    )


def _systemic_ica_from_target_finding(
    finding: TargetDerivedICAFinding,
) -> SystemicICA:
    """Project one verified target finding into the closed ICA snapshot."""
    return SystemicICA(
        ica_id=finding.ica_id,
        ica_text=finding.ica_text,
        deviation=finding.deviation,
        hazardous_context=finding.hazardous_context,
        loss_scenario=finding.loss_scenario,
        related_hazards=finding.related_hazards,
        related_constraints=finding.related_constraints,
        quality_warnings=finding.quality_warnings,
    )


def reconcile_declared_observed_capabilities(
    declared: Sequence[str | CapabilityClaim],
    observed: Sequence[str | CapabilityClaim],
    *,
    verified_observed: Sequence[str] = (),
    inventory_complete: bool = False,
) -> tuple[CapabilityExposureRow, ...]:
    """Return the explicit declared-versus-observed capability matrix.

    The helper is pure and intentionally accepts only capability labels or
    typed records that expose a label.  It never treats a missing observed
    capability as evidence that a baseline risk is inapplicable.
    """
    declared_labels, declared_conflicts = _capability_labels(declared)
    observed_labels, observed_conflicts = _capability_labels(observed)
    verified_labels = set(verified_observed)
    labels = sorted(declared_labels | observed_labels)
    rows: list[CapabilityExposureRow] = []
    for label in labels:
        is_conflict = label in declared_conflicts or label in observed_conflicts
        disposition = _capability_row_disposition(
            is_conflict,
            declared=label in declared_labels,
            observed=label in observed_labels,
            verified=label in verified_labels,
            inventory_complete=inventory_complete,
        )
        rows.append(
            CapabilityExposureRow(
                capability=label,
                declared=label in declared_labels,
                observed=label in observed_labels,
                disposition=disposition,
                conflicting=is_conflict,
            )
        )
    return tuple(rows)


def _capability_row_disposition(
    conflicting: bool,
    *,
    declared: bool = False,
    observed: bool = False,
    verified: bool = False,
    inventory_complete: bool = False,
) -> CapabilityExposureDisposition:
    if conflicting:
        return CapabilityExposureDisposition.capability_conflict
    if declared and not observed and inventory_complete:
        # Absence from a complete observed inventory is a concrete matrix
        # result and does not require semantic interpretation.
        return CapabilityExposureDisposition.declared_not_observed
    # Exact operation presence/absence is established inventory evidence, but
    # a capability label is semantically comparable only when an existing
    # target-realization row independently verified that exact operation.
    if verified:
        if declared and observed:
            return CapabilityExposureDisposition.confirmed_exposure
        if declared:
            return CapabilityExposureDisposition.declared_not_observed
        return CapabilityExposureDisposition.undocumented_exposure
    return CapabilityExposureDisposition.not_comparable


def _require_baseline(value: Any) -> None:
    if not isinstance(value, SystemicStpaBaseline):
        raise TypeError("baseline must be an attested SystemicStpaBaseline")


def _require_profile(value: object) -> None:
    if not isinstance(value, ExecutionTargetProfile):
        raise TypeError("profile must be an ExecutionTargetProfile")


def _assert_profile_integrity(profile: ExecutionTargetProfile) -> None:
    checker = getattr(profile, "assert_integrity", None)
    if not callable(checker):
        raise TypeError("execution target profile must expose assert_integrity")
    checker()


def _invoke_interpreter(
    interpreter: Any,
    *,
    action: Mapping[str, Any],
    operations: Sequence[Mapping[str, Any]],
) -> Any:
    if not callable(interpreter):
        raise TypeError("target realization interpreter is not callable")
    return interpreter(action=action, operations=operations)


def _run_bounded_target_extension(
    *,
    baseline: SystemicStpaBaseline,
    observations: Sequence[TargetOperationObservation],
    records: list[TargetOperationRecord],
    extension: Any,
) -> _ExtensionResult:
    """Apply at most one additive extension attempt to uncovered operations."""
    eligible = _eligible_extension_operations(records)
    if not eligible:
        return _ExtensionResult()
    extend = getattr(extension, "extend", None)
    if not callable(extend):
        return _missing_extension_result(eligible)
    return _attempt_target_extension(baseline, observations, records, eligible, extend)


def _eligible_extension_operations(
    records: Sequence[TargetOperationRecord],
) -> tuple[TargetOperationObservation, ...]:
    return tuple(
        record.operation
        for record in records
        if record.disposition is not TargetRealizationDisposition.supported
    )


def _missing_extension_result(
    eligible: Sequence[TargetOperationObservation],
) -> _ExtensionResult:
    return _ExtensionResult(
        diagnostics=tuple(
            _extension_missing_diagnostic(item.reference) for item in eligible
        )
    )


def _attempt_target_extension(
    baseline: SystemicStpaBaseline,
    observations: Sequence[TargetOperationObservation],
    records: list[TargetOperationRecord],
    eligible: Sequence[TargetOperationObservation],
    extension: Any,
) -> _ExtensionResult:
    request = TargetRealizationExtensionRequest(baseline=baseline, operations=eligible)
    try:
        response = extension(request)
    except Exception as exc:  # noqa: BLE001 - retain provider-boundary diagnostics
        return _extension_failure_result(eligible, exc)
    return _compile_extension_response(
        baseline=baseline,
        observations=observations,
        records=records,
        eligible=eligible,
        response=response,
    )


def _extension_failure_result(
    eligible: Sequence[TargetOperationObservation],
    exc: Exception,
) -> _ExtensionResult:
    return _ExtensionResult(
        diagnostics=tuple(
            [f"bounded target extension failed: {type(exc).__name__}: {exc}"]
            + [_extension_missing_diagnostic(item.reference) for item in eligible]
        )
    )


def _compile_extension_response(
    *,
    baseline: SystemicStpaBaseline,
    observations: Sequence[TargetOperationObservation],
    records: list[TargetOperationRecord],
    eligible: Sequence[TargetOperationObservation],
    response: Any,
) -> _ExtensionResult:
    """Compile one exact extension response without changing baseline facts."""
    state = _extension_compilation_state(baseline, observations, eligible, records)
    compiled = _compile_extension_provider_response(response)
    state.diagnostics.extend(compiled.provider_diagnostics)
    for outcome in compiled.outcomes:
        _compile_extension_outcome(state, outcome)
    state.diagnostics.extend(
        _extension_missing_diagnostic(item.reference)
        for item in eligible
        if item.reference.identity
        not in {outcome.operation.identity for outcome in compiled.outcomes}
    )
    return _ExtensionResult(
        actions=tuple(state.derived_actions),
        slots=tuple(state.derived_slots),
        processes=tuple(state.derived_processes),
        diagnostics=tuple(state.diagnostics),
    )


def _extension_compilation_state(
    baseline: SystemicStpaBaseline,
    observations: Sequence[TargetOperationObservation],
    eligible: Sequence[TargetOperationObservation],
    records: list[TargetOperationRecord],
) -> _ExtensionCompilationState:
    controller_ids = _baseline_controller_ids(baseline)
    return _ExtensionCompilationState(
        observed_by_identity={item.reference.identity: item for item in observations},
        eligible_ids={item.reference.identity for item in eligible},
        baseline_action_ids={
            item.control_action_id for item in baseline.control_actions
        },
        baseline_slot_ids=set(baseline.ica_slots),
        baseline_process_ids=_baseline_process_ids(baseline),
        controller_ids=controller_ids,
        element_ids=_baseline_element_ids(baseline),
        record_by_identity={
            item.operation_ref.identity: index for index, item in enumerate(records)
        },
        records=records,
        next_action_ordinal=_next_action_ordinals(
            controller_ids, baseline.control_actions
        ),
        next_process_ordinal=_next_process_ordinal(
            baseline.control_structure.controlled_processes
        ),
        derived_actions=[],
        derived_slots=[],
        derived_processes=[],
        derived_action_ids=set(),
        derived_slot_ids=set(),
        derived_process_ids=set(),
        diagnostics=[],
    )


def _baseline_controller_ids(baseline: SystemicStpaBaseline) -> set[str]:
    return {item.resp_id for item in baseline.control_structure.responsibilities}


def _baseline_process_ids(baseline: SystemicStpaBaseline) -> set[str]:
    return {item.cp_id for item in baseline.control_structure.controlled_processes}


def _next_action_ordinals(
    controller_ids: set[str],
    actions: Sequence[SystemicControlAction],
) -> dict[str, int]:
    return {
        controller_id: _next_action_ordinal(controller_id, actions)
        for controller_id in controller_ids
    }


def _compile_extension_outcome(
    state: _ExtensionCompilationState,
    outcome: Any,
) -> None:
    identity = outcome.operation.identity
    _validate_extension_operation(identity, state)
    if outcome.disposition is TargetRealizationExtensionDisposition.rejected:
        state.diagnostics.append(
            "target extension rejected operation "
            f"{identity[0]}/{identity[1]}: {outcome.rationale or 'no rationale'}"
        )
        return
    if not _extension_outcome_is_verified(outcome):
        state.diagnostics.append(
            "target extension action-to-operation relationship was not "
            "independently verified for "
            f"{identity[0]}/{identity[1]}"
        )
        return
    hold_reason = _extension_target_hold_reason(outcome)
    if hold_reason is not None:
        state.diagnostics.append(
            f"target extension action held: {hold_reason}: {identity[0]}/{identity[1]}"
        )
        return
    action_id, action = _compile_target_extension_action(state, outcome)
    slots = _compile_target_extension_slots(
        state, outcome, action, action_id, action.controller_id
    )
    state.derived_actions.append(action)
    state.derived_action_ids.add(action_id)
    state.derived_slots.extend(slots)
    _record_target_extension_support(state, identity, outcome, action_id)


def _extension_outcome_is_verified(outcome: Any) -> bool:
    """Require the separate exact action/operation verifier attestation."""
    verification = outcome.verification
    return verification is not None and verification.status == "verified"


def _validate_extension_operation(
    identity: tuple[str, str],
    state: _ExtensionCompilationState,
) -> None:
    if identity not in state.observed_by_identity:
        raise ValueError(
            "target extension references an unobserved target operation: "
            f"{identity[0]}/{identity[1]}"
        )
    if identity not in state.eligible_ids:
        raise ValueError(
            "target extension operation is not an uncovered target "
            f"operation: {identity[0]}/{identity[1]}"
        )


def _extension_target_hold_reason(outcome: Any) -> str | None:
    """Return a typed hold reason for an unpairable extension target kind.

    The STPA domain model permits only ``agent_message`` effects on control
    actions whose target is a responsibility.  An accepted target extension
    is compiled from an observed operation as a discrete tool call by
    construction, so a proposal that targets a responsibility has no valid
    effect pairing.  Holding the extension with a typed diagnostic keeps the
    run deterministic and leaves the operation traceably uncovered instead of
    crashing action assembly downstream (R11).
    """
    proposal = outcome.control_action
    if proposal is None:  # pragma: no cover - closed outcome validation
        return None
    if proposal.target_new_controlled_process:
        return None
    target = proposal.target
    if target is not None and target.type == "responsibility":
        return (
            "responsibility-target action cannot compile as a tool call "
            f"(target {target.id})"
        )
    return None


def _compile_target_extension_action(
    state: _ExtensionCompilationState,
    outcome: Any,
) -> tuple[str, SystemicControlAction]:
    proposal = outcome.control_action
    if proposal is None:  # pragma: no cover - closed outcome validation
        raise ValueError("accepted target extension requires control_action")
    if proposal.controller_id not in state.controller_ids:
        raise ValueError(
            "target extension controller must be an existing responsibility: "
            f"{proposal.controller_id}"
        )
    target = _compile_target_extension_target(state, outcome)
    action_id = _next_target_control_action_id(
        proposal.controller_id,
        state.next_action_ordinal,
        state.baseline_action_ids,
        state.derived_action_ids,
    )
    state.next_action_ordinal[proposal.controller_id] = (
        _action_ordinal_from_id(action_id) + 1
    )
    operation = state.observed_by_identity[outcome.operation.identity]
    return action_id, SystemicControlAction(
        control_action_id=action_id,
        controller_id=proposal.controller_id,
        # The target operation is the semantic authority for an additive
        # action's meaning.  Provider prose remains a rationale/evidence
        # input, but cannot collapse a loan-renewal or fee-waiver operation into a generic
        # "authorize backend mutation" placeholder.
        description=target_operation_action_description(operation),
        target=target,
        # An accepted MCP inventory operation is, by construction, a discrete
        # tool invocation. These execution facts are compiler-owned rather
        # than optional prose-provider judgments.
        effect_kind="tool_call",
        temporality="instantaneous",
        provenance="target_derived",
    )


def _compile_target_extension_target(
    state: _ExtensionCompilationState,
    outcome: Any,
) -> dict[str, str] | None:
    proposal = outcome.control_action
    if proposal is None:  # pragma: no cover - closed outcome validation
        return None
    target = _extension_target_reference(state, proposal, outcome.controlled_process)
    return _validated_extension_target(state, target)


def _extension_target_reference(
    state: _ExtensionCompilationState,
    proposal: Any,
    process_proposal: Any,
) -> SystemicElementReference | None:
    if not proposal.target_new_controlled_process:
        return proposal.target
    process = _allocate_target_process(state, process_proposal)
    return SystemicElementReference(type="controlled_process", id=process.cp_id)


def _validated_extension_target(
    state: _ExtensionCompilationState,
    target: SystemicElementReference | None,
) -> dict[str, str] | None:
    if target is None:
        return None
    if not _target_in_effective_elements(state, target):
        raise ValueError(
            "target extension action target is not in the baseline control "
            f"structure: {target.type}/{target.id}"
        )
    return {"type": target.type, "id": target.id}


def _target_in_effective_elements(
    state: _ExtensionCompilationState,
    target: SystemicElementReference,
) -> bool:
    identity = (target.type, target.id)
    derived_process_refs = {
        ("controlled_process", item.cp_id) for item in state.derived_processes
    }
    return identity in state.element_ids or identity in derived_process_refs


def _allocate_target_process(
    state: _ExtensionCompilationState,
    proposal: Any,
) -> SystemicControlledProcess:
    if proposal is None:  # pragma: no cover - closed outcome validation
        raise ValueError("target extension requires a controlled-process proposal")
    process_id = _next_free_process_id(state)
    process = SystemicControlledProcess(
        cp_id=process_id,
        description=proposal.description,
        provenance="target_derived",
    )
    state.derived_processes.append(process)
    state.derived_process_ids.add(process_id)
    return process


def _next_free_process_id(state: _ExtensionCompilationState) -> str:
    ordinal = state.next_process_ordinal
    while _process_id_is_used(state, ordinal):
        ordinal += 1
    state.next_process_ordinal = ordinal + 1
    return f"CP-{ordinal}"


def _process_id_is_used(state: _ExtensionCompilationState, ordinal: int) -> bool:
    process_id = f"CP-{ordinal}"
    return (
        process_id in state.baseline_process_ids
        or process_id in state.derived_process_ids
    )


def _compile_target_extension_slots(
    state: _ExtensionCompilationState,
    outcome: Any,
    action: SystemicControlAction,
    action_id: str,
    controller_id: str,
) -> tuple[TargetDerivedICASlot, ...]:
    slots = []
    # Every slot takes the compiler-owned action timing, not the proposal's.
    temporality = action.temporality or "instantaneous"
    for proposal in _systematic_extension_slot_proposals(action.temporality):
        slot_id = _target_extension_slot_id(controller_id, action_id, proposal.uca_type)
        if slot_id in state.baseline_slot_ids:
            raise ValueError(
                f"target extension baseline ICA-slot identity collision: {slot_id}"
            )
        if slot_id in state.derived_slot_ids:
            raise ValueError(f"target extension duplicate ICA-slot identity: {slot_id}")
        state.derived_slot_ids.add(slot_id)
        slots.append(
            TargetDerivedICASlot(
                slot_id=slot_id,
                responsibility=controller_id,
                control_action=action_id,
                action_temporality=temporality,
                uca_type=proposal.uca_type,
            )
        )
    return tuple(slots)


def _systematic_extension_slot_proposals(
    action_temporality: str | None,
) -> tuple[TargetDerivedICASlotProposal, ...]:
    """Enumerate the ordinary UCA universe for one target tool action.

    Target extension is additive, but its slot denominator is still the same
    deterministic STPA universe as the systemic baseline.  Provider hints may
    explain applicability; they must not decide which categories exist.  A
    tool invocation is instantaneous, so ``WRONG_DURATION`` is excluded by the
    ordinary temporality rule unless a future typed action explicitly carries
    an eligible temporal shape.
    """
    proposals = [
        TargetDerivedICASlotProposal(
            uca_type=uca_type.value,
            action_temporality=action_temporality,
        )
        for uca_type in UCAType
        if uca_type is not UCAType.wrong_duration
        or is_wrong_duration_eligible(action_temporality)
    ]
    return tuple(
        sorted(
            proposals,
            key=lambda item: (item.uca_type, item.action_temporality or ""),
        )
    )


def _target_extension_slot_id(
    controller_id: str,
    action_id: str,
    uca_type: Any,
) -> str:
    """Return the canonical controller/action/UCA slot identity.

    Temporal shape is an independently typed slot fact. It must not become
    part of the structural identity consumed by execution projection.
    """
    return f"{controller_id}:{action_id}:{uca_type}"


def _record_target_extension_support(
    state: _ExtensionCompilationState,
    identity: tuple[str, str],
    outcome: Any,
    action_id: str,
) -> None:
    index = state.record_by_identity[identity]
    current = state.records[index]
    operation_evidence = set(current.operation.evidence_refs)
    operation_evidence.update(outcome.evidence_refs)
    if outcome.verification is not None:
        operation_evidence.update(outcome.verification.evidence_refs)
    operation_evidence.update(_exact_pair_evidence_refs(action_id, current.operation))
    state.records[index] = TargetOperationRecord(
        operation=current.operation,
        disposition=TargetRealizationDisposition.supported,
        baseline_control_action_ids=(),
        target_derived_control_action_id=action_id,
        evidence_refs=tuple(sorted(set(current.evidence_refs) | operation_evidence)),
        provenance="target_derived",
    )


def _next_action_ordinal(
    controller_id: str,
    actions: Sequence[SystemicControlAction],
) -> int:
    """Find the next ordinal for deterministic ``CA-<resp>-<ordinal>`` IDs."""
    controller_number = _controller_number(controller_id)
    prefix = f"CA-{controller_number}-"
    suffixes = [
        _action_ordinal_from_id(action.control_action_id)
        for action in actions
        if action.controller_id == controller_id
        and action.control_action_id.startswith(prefix)
        and _action_ordinal_from_id(action.control_action_id) is not None
    ]
    return max(suffixes, default=0) + 1


def _next_target_control_action_id(
    controller_id: str,
    next_ordinals: dict[str, int],
    baseline_ids: set[str],
    derived_ids: set[str],
) -> str:
    """Allocate a collision-free canonical target-derived action identity."""
    controller_number = _controller_number(controller_id)
    ordinal = next_ordinals[controller_id]
    while True:
        candidate = f"CA-{controller_number}-{ordinal}"
        if candidate not in baseline_ids and candidate not in derived_ids:
            return candidate
        ordinal += 1


def _controller_number(controller_id: str) -> str:
    match = re.fullmatch(r"RESP-(\d+)", controller_id)
    if match is None:
        raise ValueError(
            "target extension controller must use canonical RESP-N identity: "
            f"{controller_id}"
        )
    return match.group(1)


def _action_ordinal_from_id(action_id: str) -> int | None:
    match = re.fullmatch(r"CA-\d+-(\d+)", action_id)
    return int(match.group(1)) if match is not None else None


def _next_process_ordinal(
    processes: Sequence[SystemicControlledProcess],
) -> int:
    """Find the next canonical ``CP-N`` identity."""
    ordinals = []
    for process in processes:
        match = re.fullmatch(r"CP-(\d+)", process.cp_id)
        if match is not None:
            ordinals.append(int(match.group(1)))
    return max(ordinals, default=0) + 1


def _compile_extension_provider_response(
    response: Any,
) -> TargetRealizationExtensionProviderResponse:
    """Compile the one exact extension response before reading any fields."""
    if isinstance(response, TargetRealizationExtensionProviderResponse):
        return response
    if isinstance(response, Mapping):
        return TargetRealizationExtensionProviderResponse.model_validate(response)
    raise TypeError(
        "target extension interpreter must return a "
        "TargetRealizationExtensionProviderResponse or exact response mapping"
    )


def _baseline_element_ids(
    baseline: SystemicStpaBaseline,
) -> set[tuple[str, str]]:
    """Return every element identity that a derived action may reference."""
    references: set[tuple[str, str]] = {
        ("responsibility", item.resp_id)
        for item in baseline.control_structure.responsibilities
    }
    references.update(
        ("controlled_process", item.cp_id)
        for item in baseline.control_structure.controlled_processes
    )
    return references


def _extension_missing_diagnostic(reference: TargetOperationReference) -> str:
    """Describe an uncovered operation with no accepted extension outcome."""
    return (
        "no extension outcome for observed operation "
        f"{reference.resource_id}/{reference.operation_id}"
    )


def _compile_row(
    action: SystemicControlAction,
    response: Any,
    observed: Mapping[tuple[str, str], TargetOperationObservation],
) -> tuple[TargetRealizationRow, tuple[TargetOperationReference, ...], str | None]:
    provider_response = _compile_provider_response(response)
    candidates = provider_response.candidate_operations
    _validate_response_action(provider_response, action)
    _require_observed_candidates(candidates, observed)
    selected = _selected_observed_reference(
        provider_response.selected_operation, observed
    )
    evidence_refs = provider_response.evidence_refs
    selected_observation = observed[selected.identity] if selected is not None else None
    verifier = _compile_verifier(
        provider_response.verifier,
        evidence_refs,
        selected,
        selected_observation,
        action.control_action_id,
    )
    disposition, selected, diagnostic = _resolve_response_selection(
        provider_response.disposition,
        selected,
        verifier,
        action.control_action_id,
        provider_response.rationale,
    )
    row = TargetRealizationRow(
        control_action_id=action.control_action_id,
        controller_id=action.controller_id,
        disposition=disposition,
        candidate_operations=candidates,
        selected_operation=selected,
        evidence_refs=evidence_refs,
        rationale=provider_response.rationale,
        verifier=verifier,
    )
    return row, candidates, diagnostic


def _validate_response_action(
    response: TargetRealizationProviderResponse,
    action: SystemicControlAction,
) -> None:
    if response.control_action_id != action.control_action_id:
        raise ValueError("provider response control_action_id does not match action")


def _require_observed_candidates(
    candidates: Sequence[TargetOperationReference],
    observed: Mapping[tuple[str, str], TargetOperationObservation],
) -> None:
    if any(candidate.identity not in observed for candidate in candidates):
        raise ValueError(
            "target realization candidate is absent from the observed inventory"
        )


def _selected_observed_reference(
    selected: TargetOperationReference | None,
    observed: Mapping[tuple[str, str], TargetOperationObservation],
) -> TargetOperationReference | None:
    if selected is None:
        return None
    if selected.identity not in observed:
        raise ValueError(
            "selected target operation is absent from the observed inventory: "
            f"{selected.resource_id}/{selected.operation_id}"
        )
    return observed[selected.identity].reference


def _resolve_response_selection(
    disposition: TargetRealizationDisposition,
    selected: TargetOperationReference | None,
    verifier: TargetRealizationVerification,
    action_id: str,
    rationale: str,
) -> tuple[
    TargetRealizationDisposition,
    TargetOperationReference | None,
    str | None,
]:
    """Keep a selection only when it is supported and verified; else diagnose."""
    if disposition is not TargetRealizationDisposition.supported:
        selected = None
    elif selected is None:
        disposition = TargetRealizationDisposition.contradictory
    verifier_failed = selected is not None and not _verifier_supports_selection(
        verifier
    )
    if verifier_failed:
        disposition, selected = _unverified_selection_disposition(verifier), None
    unresolved = disposition in {
        TargetRealizationDisposition.ambiguous,
        TargetRealizationDisposition.contradictory,
    }
    diagnostic = (
        f"baseline action {action_id} did not produce a "
        "verifiable exact target operation"
        if unresolved and (verifier_failed or not rationale)
        else None
    )
    return disposition, selected, diagnostic


def _verifier_supports_selection(verifier: TargetRealizationVerification) -> bool:
    return verifier.status == "verified" and bool(verifier.evidence_refs)


def _unverified_selection_disposition(
    verifier: TargetRealizationVerification,
) -> TargetRealizationDisposition:
    return (
        TargetRealizationDisposition.contradictory
        if verifier.status == "rejected"
        else TargetRealizationDisposition.ambiguous
    )


def _compile_provider_response(response: Any) -> TargetRealizationProviderResponse:
    """Validate the one exact provider response before any field is read."""
    if isinstance(response, TargetRealizationProviderResponse):
        return response
    if isinstance(response, Mapping):
        return TargetRealizationProviderResponse.model_validate(response)
    raise TypeError(
        "target realization interpreter must return a TargetRealizationProviderResponse "
        "or an exact response mapping"
    )


def _compile_verifier(
    raw: TargetRealizationVerification | None,
    evidence_refs: tuple[str, ...],
    selected: TargetOperationReference | None,
    selected_observation: TargetOperationObservation | None,
    action_id: str,
) -> TargetRealizationVerification:
    if raw is None:
        return TargetRealizationVerification(
            status="unverified",
            detail=(
                "provider did not supply independent verification"
                if selected is not None
                else "provider did not supply verification"
            ),
            evidence_refs=evidence_refs,
        )
    if raw.status != "verified" or selected is None or selected_observation is None:
        return raw
    # The provider's semantic explanation may omit references even though the
    # exact pair was checked.  This deterministic attestation is deliberately
    # narrow: it proves only the selected action/operation identity, never an
    # approval, policy, or other semantic fact.
    pair_evidence = _exact_pair_evidence_refs(action_id, selected_observation)
    return raw.model_copy(
        update={
            "evidence_refs": tuple(sorted(set(raw.evidence_refs) | set(pair_evidence)))
        }
    )


def _exact_pair_evidence_refs(
    action_id: str,
    operation: TargetOperationObservation,
) -> tuple[str, ...]:
    """Return deterministic evidence for one exact verified mapping pair."""
    return (
        verified_pair_evidence_ref(
            action_id, operation.resource_id, operation.operation_id
        ),
    )


def observed_operations(
    profile: ExecutionTargetProfile,
) -> tuple[TargetOperationObservation, ...]:
    """Return the profile's exact observed operations in identity order."""
    interpretations = {item.resource_id: item for item in profile.interpretations}
    observations = [
        item
        for resource in profile.resources
        for item in _resource_observations(
            resource,
            interpretations,
            semantic_authority=_text_or_none(profile.semantic_authority),
        )
    ]
    _require_unique_observation_identities(observations)
    return tuple(sorted(observations, key=lambda item: item.reference.identity))


def _resource_observations(
    resource: Any,
    interpretations: Mapping[str, Any],
    *,
    semantic_authority: str | None = None,
) -> tuple[TargetOperationObservation, ...]:
    interpretation = interpretations.get(resource.resource_id)
    return tuple(
        _operation_observation(
            resource,
            operation,
            interpretation,
            semantic_authority=semantic_authority,
        )
        for operation in resource.operations
    )


def _operation_observation(
    resource: Any,
    operation: Any,
    interpretation: Any,
    *,
    semantic_authority: str | None = None,
) -> TargetOperationObservation:
    effect, state_effect = _interpretation_effects(interpretation)
    return TargetOperationObservation(
        reference=TargetOperationReference(
            resource_id=resource.resource_id,
            operation_id=operation.operation_id,
        ),
        description=resource.description or "",
        input_schema=resource.input_schema,
        argument_names=tuple(operation.argument_names),
        effect=effect,
        state_effect=state_effect,
        state_changing=_is_state_changing(effect, state_effect),
        semantic_authority=semantic_authority,
        interpretation_disposition=(
            _text_or_none(interpretation.disposition)
            if interpretation is not None
            else None
        ),
        interpreter_verifier_agreement=(
            _text_or_none(interpretation.interpreter_verifier_agreement)
            if interpretation is not None
            else None
        ),
        evidence_refs=_observation_evidence(resource, interpretation),
    )


def _interpretation_effects(
    interpretation: Any,
) -> tuple[str | None, str | None]:
    if interpretation is None:
        return None, None
    return (
        _text_or_none(interpretation.likely_effect),
        _text_or_none(interpretation.likely_state_effect),
    )


def _observation_evidence(resource: Any, interpretation: Any) -> tuple[str, ...]:
    interpretation_refs = () if interpretation is None else interpretation.evidence_refs
    return tuple(sorted(set(resource.evidence_refs) | set(interpretation_refs)))


def _require_unique_observation_identities(
    observations: Sequence[TargetOperationObservation],
) -> None:
    seen: set[tuple[str, str]] = set()
    for observation in observations:
        identity = observation.reference.identity
        if identity in seen:
            raise ValueError(
                "observed target inventory contains duplicate resource/operation "
                f"identity: {identity[0]}/{identity[1]}"
            )
        seen.add(identity)


def _is_state_changing(effect: str | None, state_effect: str | None) -> bool:
    values = {str(value).lower() for value in (effect, state_effect) if value}
    return bool(
        values
        & {
            "create",
            "update",
            "delete",
            "execute",
            "changes",
            "may_change",
            "state_change",
            "state-changing",
        }
    )


def _operation_prompt_view(observation: TargetOperationObservation) -> dict[str, Any]:
    # Pydantic's JSON mode converts the immutable FrozenDict/FrozenList values
    # carried by an attested target profile back to ordinary JSON containers.
    # The provider prompt boundary must not pass internal frozen containers to
    # PyYAML, while retaining the exact observed schema semantics.
    public = observation.model_dump(mode="json")
    return {
        "resource_id": public["reference"]["resource_id"],
        "operation_id": public["reference"]["operation_id"],
        "description": public["description"],
        "input_schema": public["input_schema"],
        "argument_names": public["argument_names"],
        "effect": public["effect"],
        "state_effect": public["state_effect"],
        "semantic_authority": public["semantic_authority"],
        "interpretation_disposition": public["interpretation_disposition"],
        "interpreter_verifier_agreement": public["interpreter_verifier_agreement"],
    }


def _action_prompt_view(
    action: SystemicControlAction,
    control_structure: SystemicControlStructureSnapshot,
) -> dict[str, Any]:
    return {
        "control_action_id": action.control_action_id,
        "controller_id": action.controller_id,
        "controller": control_structure.controller_prompt_view(action.controller_id),
        "description": action.description,
        "target": control_structure.target_prompt_view(action.target),
        "effect_kind": action.effect_kind,
        "temporality": action.temporality,
    }


def _capability_rows(
    baseline: SystemicStpaBaseline,
    observations: Sequence[TargetOperationObservation],
    rows: Sequence[TargetRealizationRow] = (),
    *,
    profile: ExecutionTargetProfile | None = None,
) -> tuple[CapabilityExposureRow, ...]:
    declared = baseline.declared_capabilities
    if not declared:
        return ()
    observed = tuple(item.operation_id for item in observations)
    verified_rows = tuple(row for row in rows if _is_verified_supported(row))
    verified_observed = tuple(
        row.selected_operation.operation_id for row in verified_rows
    )
    reconciled = reconcile_declared_observed_capabilities(
        declared,
        observed,
        verified_observed=verified_observed,
        inventory_complete=(
            profile is not None
            and profile.inventory_completeness.value == "observed_complete"
        ),
    )
    evidence_by_capability: dict[str, set[str]] = {}
    for row in verified_rows:
        evidence = evidence_by_capability.setdefault(
            row.selected_operation.operation_id, set()
        )
        evidence.update(row.evidence_refs)
        evidence.update(row.verifier.evidence_refs)
    return tuple(
        item.model_copy(
            update={
                "evidence_refs": tuple(
                    sorted(evidence_by_capability.get(item.capability, set()))
                )
            }
        )
        for item in reconciled
    )


def _is_verified_supported(row: TargetRealizationRow) -> bool:
    """True when a supported row selected an operation its verifier confirmed."""
    return (
        row.selected_operation is not None
        and row.disposition is TargetRealizationDisposition.supported
        and row.verifier.status == "verified"
    )


def _capability_labels(
    values: Sequence[str | CapabilityClaim],
) -> tuple[set[str], set[str]]:
    labels: set[str] = set()
    conflicts: set[str] = set()
    for value in values or ():
        label, conflicting = _capability_value(value)
        labels.add(label)
        if conflicting:
            conflicts.add(label)
    return labels, conflicts


def _capability_value(value: str | CapabilityClaim) -> tuple[str, bool]:
    if isinstance(value, str):
        return value, False
    if not isinstance(value, CapabilityClaim):
        raise TypeError("capabilities must contain strings or CapabilityClaim values")
    return value.capability, value.conflicting


def _text_or_none(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "value"):
        value = value.value
    text = str(value)
    return text if text else None


__all__ = [
    "TargetRealizationStpaProjection",
    "observed_operations",
    "reconcile_declared_observed_capabilities",
    "realize_baseline_rows",
    "realize_target_derived_icas",
    "realize_target_operations",
    "project_target_realization_to_stpa",
]
