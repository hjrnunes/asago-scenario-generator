"""Offline acceptance handlers for normative hybrid coverage assessment."""

from __future__ import annotations

import re
import socket
import tempfile
from pathlib import Path
from typing import Any, NamedTuple
from unittest.mock import patch

from runtime_shared import World
from runtime_obligation_fixture import (
    typed_input_model,
    typed_payload,
)

from asago_scenario_generator.models.correspondence import (
    AdjudicationSet,
    CandidateAuthorityRecord,
    CorrespondenceAdjudication,
    CorrespondenceAuthority,
    CorrespondenceEvidence,
    CorrespondenceSourceArtifacts,
    ObligationAuthorityRecord,
    ReconciliationResult,
    SourceArtifactPins,
    StructuralAuthorityRecord,
)
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.models.hybrid_coverage import (
    ArtifactPin,
    HybridCoverageAssessment,
    StpaCoverageInput,
    StpaScenarioObservation,
    StructuralInapplicabilityDecision,
    StructuralSlotObservation,
    TaxonomyCoverageInput,
    TaxonomyScenarioObservation,
)
from asago_scenario_generator.models.system_resource_map import (
    ResourceLink,
    SystemResourceMap,
    SystemResourceMapValidation,
    compute_control_structure_digest,
    compute_resource_map_semantic_digest,
)
from asago_scenario_generator.models.scenario import (
    ScenarioEnvelope as TaxonomyScenarioEnvelope,
)
from asago_scenario_generator.pipeline.correspondence import (
    propose_correspondence,
    reconcile_correspondence,
)
from asago_scenario_generator.pipeline.hybrid_coverage import assess_hybrid_coverage
from asago_scenario_generator.pipeline.hybrid_coverage_persistence import (
    HYBRID_COVERAGE_ASSESSMENT_FILENAME,
    write_hybrid_coverage_assessment,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.pipeline.system_resource_map import (
    validate_system_resource_map,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    ProcessModelPart,
    Responsibility,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.models.scenario_envelope import (
    ScenarioEnvelope as StpaScenarioEnvelope,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    ScenarioSpec as StpaScenarioSpec,
    ThreatSource,
)

FEATURE_ID = "hybrid_coverage_assessment"
ICA_SLOT = "RESP-1:CA-1-1:WRONG_TIMING"
ICA_ID = ICA_SLOT + ":1"
EXEC_ID = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"
ICA_PIN = ArtifactPin(
    artifact_id="ica-enumeration",
    schema_version="ica-enumeration-v1",
    semantic_digest="3" * 64,
)
STPA_PIN = ArtifactPin(
    artifact_id="stpa-scenarios",
    schema_version="stpa-scenarios-v1",
    semantic_digest="8" * 64,
)
TAXONOMY_PIN = ArtifactPin(
    artifact_id="taxonomy-scenarios",
    schema_version="taxonomy-scenarios-v1",
    semantic_digest="7" * 64,
)


def _state(world: World) -> dict[str, Any]:
    """Return isolated state for one generated acceptance scenario."""
    state = getattr(world, "hybrid_coverage_state", None)
    if state is None:
        state = {
            "plan": None,
            "resource_map": None,
            "reconciliation": None,
            "taxonomy": TaxonomyCoverageInput(),
            "stpa": StpaCoverageInput(inventory_status="complete"),
            "assessment": None,
            "ordered_assessment": None,
            "reordered_assessment": None,
            "round_trip": None,
            "envelope_authority": None,
            "assessment_error": None,
            "provider_calls": [],
        }
        world.hybrid_coverage_state = state
    return state


def _control_structure() -> ControlStructure:
    """Return the small typed STPA authority used by acceptance."""
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Payment controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="Payment state")
                ],
                control_actions=[
                    ControlAction(ca_id="CA-1-1", description="Authorize payment")
                ],
            )
        ],
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Payment process")
        ],
    )


def _plan_and_map(
    *, unrelated_resource: bool = False
) -> tuple[Any, SystemResourceMapValidation, Any]:
    """Create real Phase 1 and Task 2 artifacts through public interfaces."""
    inputs = typed_input_model(typed_payload())
    plan = plan_taxonomy_obligations(inputs)
    obligation = plan.obligations[0]
    candidate = next(
        item
        for item in obligation.candidate_records
        if item.projection_disposition == "projectable"
    )
    if unrelated_resource:
        entry_point = inputs.capability_snapshot.profile.entry_points[1]
        capability_ref: Any = {
            "kind": "entry_point",
            "entry_point_id": entry_point.entry_point_id,
        }
    else:
        capability_ref = next(
            binding.resource_ref
            for binding in candidate.resource_bindings
            if binding.resource_ref.kind == "tool"
        )
    control = _control_structure()
    link = ResourceLink(
        link_id="srm:v1:hybrid-acceptance",
        capability_resource_ref=capability_ref,
        control_structure_ref={"kind": "CA", "id": "CA-1-1"},
        relation_kind="acts_on",
        provenance="operator_declared",
        evidence_refs=("review:hybrid-acceptance",),
        confidence=1.0,
        authority_status="authoritative",
    )
    control_digest = compute_control_structure_digest(control)
    map_digest = compute_resource_map_semantic_digest(
        schema_version="system-resource-map-v1",
        capability_snapshot_digest=plan.capability_snapshot_digest,
        control_structure_digest=control_digest,
        links=(link,),
    )
    resource_map = SystemResourceMap(
        schema_version="system-resource-map-v1",
        semantic_digest=map_digest,
        capability_snapshot_digest=plan.capability_snapshot_digest,
        control_structure_digest=control_digest,
        links=(link,),
    )
    return (
        plan,
        validate_system_resource_map(resource_map, inputs.capability_snapshot, control),
        candidate,
    )


def _reconciliation(
    plan: Any,
    resource_map_validation: SystemResourceMapValidation,
    *,
    relation_kind: str,
    decision: str,
    resource_link_ids: tuple[str, ...] = ("srm:v1:hybrid-acceptance",),
) -> ReconciliationResult:
    """Produce and explicitly adjudicate one exact-evidence proposal."""
    resource_map = resource_map_validation.canonical_map
    assert resource_map is not None
    obligation = plan.obligations[0]
    selected_candidate = next(
        item
        for item in obligation.candidate_records
        if item.projection_disposition == "projectable"
    )
    pins = SourceArtifactPins(
        resource_map_semantic_digest=resource_map.semantic_digest,
        capability_snapshot_digest=resource_map.capability_snapshot_digest,
        obligation_plan_semantic_digest=plan.semantic_digest,
        control_structure_digest=resource_map.control_structure_digest,
        ica_enumeration_digest=ICA_PIN.semantic_digest,
        loss_analysis_digest="4" * 64,
        taxonomy_version=plan.schema_version,
        stpa_version="stpa-v1",
    )
    authority = CorrespondenceAuthority(
        source_pins=pins,
        obligations=(
            ObligationAuthorityRecord(
                obligation_id=obligation.obligation_id,
                risk_id=obligation.risk_ref.risk_id,
                attack_pattern_id=obligation.attack_pattern_id,
                taxonomy_candidate_ids=tuple(
                    item.candidate_id for item in obligation.candidate_records
                ),
                candidate_resource_refs=tuple(
                    binding.resource_ref
                    for item in obligation.candidate_records
                    for binding in item.resource_bindings
                ),
                candidates=tuple(
                    CandidateAuthorityRecord(
                        candidate_id=item.candidate_id,
                        resource_bindings=item.resource_bindings,
                        projection_disposition=item.projection_disposition,
                    )
                    for item in obligation.candidate_records
                ),
            ),
        ),
        structural_findings=(
            StructuralAuthorityRecord(
                ica_slot_id=ICA_SLOT,
                ica_id=ICA_ID,
                exec_candidate_id=EXEC_ID,
                hazard_ids=("H-1",),
                constraint_ids=("SC-1",),
                resource_link_ids=("srm:v1:hybrid-acceptance",),
            ),
        ),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
    )
    evidence = CorrespondenceEvidence(
        obligation_id=obligation.obligation_id,
        risk_id=obligation.risk_ref.risk_id,
        attack_pattern_id=obligation.attack_pattern_id,
        taxonomy_candidate_ids=tuple(
            item.candidate_id for item in obligation.candidate_records
        ),
        selected_candidate_id=selected_candidate.candidate_id,
        ica_slot_id=ICA_SLOT,
        ica_id=ICA_ID,
        exec_candidate_id=EXEC_ID,
        relation_kind=relation_kind,
        resource_link_ids=resource_link_ids,
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence_source="exact_id",
        evidence_refs=(
            f"candidate:{selected_candidate.candidate_id}",
            "id:obligation",
            "id:ica",
            f"kind:{relation_kind}",
        ),
        confidence=1.0,
        evidence_strength="high",
        proposer_id="exact-id-v1",
        proposer_version="1",
        source_pins=pins,
        rationale="exact reviewed identities",
    )
    proposals = propose_correspondence(
        resource_map_validation,
        CorrespondenceSourceArtifacts(authority=authority, evidence=(evidence,)),
    )
    proposal = proposals.proposals[0]
    return reconcile_correspondence(
        resource_map_validation,
        proposals,
        AdjudicationSet(
            decisions=(
                CorrespondenceAdjudication(
                    proposal_id=proposal.proposal_id,
                    status=decision,
                    reason="reviewed evidence",
                    adjudicated_by="operator-1",
                ),
            )
        ),
    )


def _ica_slot() -> StructuralSlotObservation:
    """Return one exact ICA-bearing UCA slot observation."""
    return StructuralSlotObservation(
        slot_id=ICA_SLOT,
        controller_id="RESP-1",
        control_action_id="CA-1-1",
        uca_type="WRONG_TIMING",
        ica_ids=(ICA_ID,),
        disposition="ica",
        evidence=("ica-enumeration.yaml#" + ICA_ID,),
        source_artifact=ICA_PIN,
        trace_refs=("ica-enumeration.yaml#" + ICA_SLOT,),
    )


def _matching_inputs(plan: Any, candidate: Any) -> tuple[Any, Any]:
    """Return matching legacy observations plus the complete structural slot."""
    taxonomy = TaxonomyCoverageInput(
        scenarios=(
            TaxonomyScenarioObservation(
                scenario_id="scenario:v2:" + "a" * 64,
                obligation_id=plan.obligations[0].obligation_id,
                candidate_id=candidate.candidate_id,
                source_artifact=TAXONOMY_PIN,
                trace_refs=("scenarios/taxonomy.yaml",),
            ),
        )
    )
    stpa = StpaCoverageInput(
        slots=(_ica_slot(),),
        scenarios=(
            StpaScenarioObservation(
                scenario_id="STPA-SCENARIO-1",
                ica_slot_id=ICA_SLOT,
                ica_id=ICA_ID,
                exec_candidate_id=EXEC_ID,
                source_artifact=STPA_PIN,
                trace_refs=("scenarios/stpa.yaml",),
            ),
        ),
        inventory_status="complete",
    )
    return taxonomy, stpa


def _prepare_relation(world: World, relation_kind: str, decision: str) -> None:
    """Prepare a real upstream graph and matching legacy observations."""
    state = _state(world)
    plan, resource_map, candidate = _plan_and_map()
    taxonomy, stpa = _matching_inputs(plan, candidate)
    state.update(
        {
            "plan": plan,
            "resource_map": resource_map,
            "reconciliation": _reconciliation(
                plan,
                resource_map,
                relation_kind=relation_kind,
                decision=decision,
            ),
            "taxonomy": taxonomy,
            "stpa": stpa,
            "assessment": None,
        }
    )


def _prepare_empty(world: World) -> Any:
    """Prepare valid artifacts with one slot and no correspondence proposal."""
    state = _state(world)
    plan, resource_map, candidate = _plan_and_map()
    canonical_map = resource_map.canonical_map
    assert canonical_map is not None
    state.update(
        {
            "plan": plan,
            "resource_map": resource_map,
            "reconciliation": ReconciliationResult(
                resource_map_semantic_digest=canonical_map.semantic_digest,
                capability_snapshot_digest=canonical_map.capability_snapshot_digest,
                is_valid=True,
            ),
            "taxonomy": TaxonomyCoverageInput(),
            "stpa": StpaCoverageInput(
                slots=(_ica_slot(),), inventory_status="complete"
            ),
            "assessment": None,
        }
    )
    return candidate


def _prepare_defective_proposal(world: World) -> None:
    """Prepare a rejected proposal with a dangling map-link identity."""
    state = _state(world)
    plan, resource_map, _candidate = _plan_and_map()
    state.update(
        {
            "plan": plan,
            "resource_map": resource_map,
            "reconciliation": _reconciliation(
                plan,
                resource_map,
                relation_kind="same_mechanism",
                decision="confirmed",
                resource_link_ids=("srm:v1:missing-link",),
            ),
            "taxonomy": TaxonomyCoverageInput(),
            "stpa": StpaCoverageInput(
                slots=(_ica_slot(),), inventory_status="complete"
            ),
            "assessment": None,
        }
    )


def _prepare_unrelated_map(world: World) -> None:
    """Prepare an authoritative map whose link is irrelevant to the obligation."""
    state = _state(world)
    plan, resource_map, _candidate = _plan_and_map(unrelated_resource=True)
    canonical_map = resource_map.canonical_map
    assert canonical_map is not None
    state.update(
        {
            "plan": plan,
            "resource_map": resource_map,
            "reconciliation": ReconciliationResult(
                resource_map_semantic_digest=canonical_map.semantic_digest,
                capability_snapshot_digest=canonical_map.capability_snapshot_digest,
                is_valid=True,
            ),
            "taxonomy": TaxonomyCoverageInput(),
            "stpa": StpaCoverageInput(
                slots=(_ica_slot(),), inventory_status="complete"
            ),
            "assessment": None,
        }
    )


def _assess(world: World) -> None:
    """Invoke the public seam under provider/socket construction guards."""
    state = _state(world)

    def forbidden(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        state["provider_calls"].append("forbidden")
        raise AssertionError("hybrid assessment attempted a provider/network call")

    with (
        patch("openai.OpenAI", side_effect=forbidden),
        patch.object(socket.socket, "connect", side_effect=forbidden),
    ):
        state["assessment"] = assess_hybrid_coverage(
            state["plan"],
            state["resource_map"],
            state["reconciliation"],
            state["taxonomy"],
            state["stpa"],
        )


class _EnvelopeAuthority(NamedTuple):
    """The plan and ICA enumeration that real scenario envelopes join against."""

    obligation_plan: TaxonomyObligationPlan
    ica_enumeration: ICAEnumeration


def _envelope_authority() -> _EnvelopeAuthority:
    """Build the exact obligation plan and ICA enumeration through public seams."""
    plan = plan_taxonomy_obligations(typed_input_model(typed_payload()))
    enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id=ICA_SLOT,
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.wrong_timing,
                is_na=False,
                icas=[
                    ICA(
                        ica_id=ICA_ID,
                        ica_text="Payment occurs at the wrong time",
                        hazardous_context="Payment pending",
                        loss_scenario="Payment is lost",
                        related_hazards=["H-1"],
                        related_constraints=["SC-1"],
                    )
                ],
            )
        ]
    )
    return _EnvelopeAuthority(obligation_plan=plan, ica_enumeration=enumeration)


def _register(api: Any) -> None:
    """Register Task 4 acceptance steps."""
    api.set_feature(FEATURE_ID)

    def completed(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare_empty(world)
        return True, ""

    def offline(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        assessment = state.get("assessment")
        return (
            not state["provider_calls"]
            and (
                assessment is None
                or (assessment.network_calls == 0 and assessment.model_calls == 0)
            ),
            "hybrid assessment must remain offline",
        )

    def confirmed(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare_relation(world, "same_mechanism", "confirmed")
        return True, ""

    def real_scenario_envelopes(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del text, examples
        inputs = _envelope_authority()
        obligation = inputs.obligation_plan.obligations[0]
        candidate = next(
            item
            for item in obligation.candidate_records
            if item.projection_disposition == "projectable"
        )
        taxonomy_envelope = TaxonomyScenarioEnvelope.model_construct(
            scenario_id="scenario:v2:" + "a" * 64,
            candidate_id=candidate.candidate_id,
        )
        stpa_envelope = StpaScenarioEnvelope.model_construct(
            scenario_id="SCN-001",
            scenario_spec=StpaScenarioSpec.model_construct(
                threat_source=ThreatSource(
                    ica_slot_id=ICA_SLOT,
                    ica_id=ICA_ID,
                    provenance="structural",
                )
            ),
        )
        _state(world).update(
            {
                "envelope_authority": inputs,
                "taxonomy_envelopes": (taxonomy_envelope,),
                "stpa_envelopes": (stpa_envelope,),
            }
        )
        return True, ""

    def adapt_real_scenario_envelopes(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        inputs = state["envelope_authority"]
        state["taxonomy"] = TaxonomyCoverageInput.from_scenario_envelopes(
            inputs.obligation_plan, state["taxonomy_envelopes"]
        )
        state["stpa"] = StpaCoverageInput.from_scenario_envelopes(
            inputs.ica_enumeration, state["stpa_envelopes"]
        )
        return True, ""

    def taxonomy_observation_count(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r"contain (\d+) exact obligation link", text)
        observations = _state(world)["taxonomy"].scenarios
        expected = int(match.group(1)) if match else -1
        valid = all(item.obligation_id and item.candidate_id for item in observations)
        return (
            len(observations) == expected and valid,
            f"taxonomy observations were {len(observations)}",
        )

    def stpa_observation_count(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r"contain (\d+) exact slot ICA and EXEC link", text)
        observations = _state(world)["stpa"].scenarios
        expected = int(match.group(1)) if match else -1
        valid = all(
            item.ica_slot_id and item.ica_id and item.exec_candidate_id
            for item in observations
        )
        return (
            len(observations) == expected and valid,
            f"STPA observations were {len(observations)}",
        )

    def proposal(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        match = re.search(r'one "([^"]+)" proposal is explicitly "([^"]+)"', text)
        if match is None:
            return False, "proposal step did not expose relation/decision"
        _prepare_relation(world, *match.groups())
        return True, ""

    def defective_proposal(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare_defective_proposal(world)
        return True, ""

    def unrelated_map(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare_unrelated_map(world)
        return True, ""

    def structural(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare_empty(world)
        na_slot = StructuralSlotObservation(
            slot_id="RESP-1:CA-1-1:WRONG_DURATION",
            controller_id="RESP-1",
            control_action_id="CA-1-1",
            uca_type="WRONG_DURATION",
            disposition="justified_na",
            evidence=("review:discrete-action",),
            source_artifact=ICA_PIN,
            trace_refs=("ica-enumeration.yaml#wrong-duration",),
        )
        unresolved_slot = StructuralSlotObservation(
            slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            controller_id="RESP-1",
            control_action_id="CA-1-1",
            uca_type="NOT_PROVIDED",
            disposition="unresolved",
            evidence=("gap:slot-not-reviewed",),
            source_artifact=ICA_PIN,
            trace_refs=("ica-enumeration.yaml#not-provided",),
        )
        _state(world)["stpa"] = StpaCoverageInput(
            slots=(_ica_slot(), na_slot, unresolved_slot),
            inventory_status="complete",
        )
        return True, ""

    def inapplicable(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare_empty(world)
        state = _state(world)
        decision_pin = ArtifactPin(
            artifact_id="correspondence-decisions",
            schema_version="correspondence-decisions-v1",
            semantic_digest="9" * 64,
        )
        decision = StructuralInapplicabilityDecision(
            decision_id="structural-na:1",
            obligation_id=state["plan"].obligations[0].obligation_id,
            rationale="No structural path reaches the required resource",
            evidence_refs=("review:resource-path:1",),
            other_authoritative_evidence_refs=("review:capability-inventory:1",),
            adjudicated_by="operator-1",
            inventory_status="complete",
            source_artifact=decision_pin,
            trace_refs=("decisions.yaml#structural-na:1",),
        )
        state["taxonomy"] = TaxonomyCoverageInput(
            structural_inapplicability_decisions=(decision,)
        )
        return True, ""

    def partial_capability_inapplicable(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r'over "([^"]+)" relevant capability inventory', text)
        expected = match.group(1) if match else ""
        _prepare_empty(world)
        state = _state(world)
        validation = state["resource_map"]
        actual = validation.tool_inventory_completeness
        decision = StructuralInapplicabilityDecision(
            decision_id="structural-na:partial-capability",
            obligation_id=state["plan"].obligations[0].obligation_id,
            rationale="No structural path reaches the required tool",
            evidence_refs=("review:resource-path:partial-capability",),
            adjudicated_by="operator-1",
            inventory_status="complete",
            source_artifact=ArtifactPin(
                artifact_id="correspondence-decisions",
                schema_version="correspondence-decisions-v1",
                semantic_digest="9" * 64,
            ),
            trace_refs=("decisions.yaml#structural-na:partial-capability",),
        )
        state["taxonomy"] = TaxonomyCoverageInput(
            structural_inapplicability_decisions=(decision,)
        )
        return (
            expected == "inferred_partial" and actual == expected,
            f"relevant tool inventory completeness was {actual}",
        )

    def assess_partial_capability(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        try:
            _assess(world)
        except ValueError as exc:
            state["assessment_error"] = str(exc)
            return True, ""
        return False, "inferred-partial structural inapplicability was accepted"

    def partial_capability_rejected(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r'for "([^"]+)" relevant capability inventory', text)
        expected = match.group(1) if match else ""
        error = _state(world)["assessment_error"] or ""
        return (
            expected == "inferred_partial"
            and "inferred-partial capability inventory" in error
            and "other authoritative evidence" in error,
            f"unexpected structural-inapplicability rejection: {error}",
        )

    def reordered(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare_relation(world, "same_mechanism", "confirmed")
        state = _state(world)
        taxonomy = state["taxonomy"]
        first_scenario = taxonomy.scenarios[0]
        second_scenario = first_scenario.model_copy(
            update={
                "scenario_id": "scenario:v2:" + "b" * 64,
                "trace_refs": ("scenarios/taxonomy-b.yaml",),
            }
        )
        na_slot = StructuralSlotObservation(
            slot_id="RESP-1:CA-1-1:WRONG_DURATION",
            controller_id="RESP-1",
            control_action_id="CA-1-1",
            uca_type="WRONG_DURATION",
            disposition="justified_na",
            evidence=("review:discrete-action",),
            source_artifact=ICA_PIN,
            trace_refs=("ica-enumeration.yaml#wrong-duration",),
        )
        state["taxonomy"] = TaxonomyCoverageInput(
            scenarios=(*taxonomy.scenarios, second_scenario)
        )
        state["stpa"] = StpaCoverageInput(
            slots=(*state["stpa"].slots, na_slot),
            scenarios=state["stpa"].scenarios,
            inventory_status="complete",
        )
        return True, ""

    def assess(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _assess(world)
        return True, ""

    def structural_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        expected = int(re.search(r"contains (\d+)", text).group(1))
        actual = len(_state(world)["assessment"].structural_consideration)
        return actual == expected, f"structural row count was {actual}"

    def taxonomy_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        match = re.search(r'contains (\d+).*disposition "([^"]+)"', text)
        if match is None:
            return False, "taxonomy count step did not expose count/disposition"
        expected, disposition = match.groups()
        rows = _state(world)["assessment"].taxonomy_correspondence
        return (
            len(rows) == int(expected)
            and rows[0].correspondence_disposition == disposition,
            "taxonomy correspondence count/disposition mismatch",
        )

    def realization_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        match = re.search(
            r'contains (\d+).*hybrid status "([^"]+)" and "([^"]+)"', text
        )
        if match is None:
            return False, "realization step did not expose count/statuses"
        expected, generation, admission = match.groups()
        rows = _state(world)["assessment"].scenario_realization
        return (
            len(rows) == int(expected)
            and all(row.hybrid_generation_status == generation for row in rows)
            and all(row.hybrid_admission_status == admission for row in rows),
            "scenario realization count/status mismatch",
        )

    def realization_only_count(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r"contains (\d+) accepted relations", text)
        rows = _state(world)["assessment"].scenario_realization
        return (
            match is not None and len(rows) == int(match.group(1)),
            f"scenario realization count was {len(rows)}",
        )

    def traceable(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        assessment = _state(world)["assessment"]
        values = (
            *assessment.structural_consideration,
            *assessment.taxonomy_correspondence,
            *assessment.scenario_realization,
            *assessment.proposal_outcomes,
            *assessment.findings,
        )
        return (
            all(item.source_pins and item.trace_refs for item in values),
            "a matrix row or diagnostic cell lacks source pins/traces",
        )

    def assess_substituted_capability_pin(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r'substituted "([^"]+)"', text)
        field = match.group(1) if match else ""
        state = _state(world)
        substituted = state["reconciliation"].model_copy(
            update={field: "f" * 64, "semantic_digest": None}
        )
        substituted = substituted.model_copy(
            update={"semantic_digest": substituted.compute_semantic_digest()}
        )
        try:
            assess_hybrid_coverage(
                state["plan"],
                state["resource_map"],
                substituted,
                state["taxonomy"],
                state["stpa"],
            )
        except Exception as exc:  # noqa: BLE001 - expected closed-contract failure
            state["substitution_field"] = field
            state["substitution_error"] = str(exc)
            return True, ""
        return False, "substituted reconciliation capability pin was accepted"

    def assert_substituted_capability_rejected(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r'substituted "([^"]+)"', text)
        expected = match.group(1) if match else ""
        state = _state(world)
        return (
            state.get("substitution_field") == expected
            and "capability snapshot" in state.get("substitution_error", ""),
            "hybrid assessment did not reject the substituted capability scope",
        )

    def dispositions(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        match = re.search(
            r'reports (\d+) "([^"]+)", (\d+) "([^"]+)", and (\d+) "([^"]+)"',
            text,
        )
        if match is None:
            return False, "structural disposition step did not expose counts"
        counts = {
            match.group(2): int(match.group(1)),
            match.group(4): int(match.group(3)),
            match.group(6): int(match.group(5)),
        }
        rows = _state(world)["assessment"].structural_consideration
        actual = {name: sum(row.disposition == name for row in rows) for name in counts}
        return actual == counts, f"structural dispositions were {actual}"

    def no_coverage_gap(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        match = re.search(r'gap "([^"]+)"', text)
        row = _state(world)["assessment"].taxonomy_correspondence[0]
        return (
            match is not None
            and not row.accepted_relation_ids
            and row.gap_reason == match.group(1),
            "noncoverage evidence became accepted coverage or changed gap",
        )

    def finding(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        match = re.search(r'finding "([^"]+)"', text)
        kinds = {item.kind for item in _state(world)["assessment"].findings}
        return match is not None and match.group(1) in kinds, "finding kind mismatch"

    def proposal_diagnostic(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r'one "([^"]+)" proposal diagnostic', text)
        outcomes = _state(world)["assessment"].proposal_outcomes
        if match is None or len(outcomes) != 1:
            return False, "proposal diagnostic count/status mismatch"
        outcome = outcomes[0]
        reconciliation_traces = {
            item.record_id
            for item in outcome.trace_refs
            if item.artifact_id == "correspondence-reconciliation"
        }
        return (
            outcome.status == match.group(1)
            and outcome.proposal_id in reconciliation_traces,
            "proposal diagnostic lost its reconciliation trace",
        )

    def realization_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        match = re.search(r'remains "([^"]+)" and "([^"]+)"', text)
        rows = _state(world)["assessment"].scenario_realization
        return (
            match is not None
            and bool(rows)
            and all(row.hybrid_generation_status == match.group(1) for row in rows)
            and all(row.hybrid_admission_status == match.group(2) for row in rows),
            "noncoverage realization changed normative hybrid status",
        )

    def taxonomy_disposition(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r'is "([^"]+)" with gap "([^"]+)"', text)
        row = _state(world)["assessment"].taxonomy_correspondence[0]
        return (
            match is not None
            and row.correspondence_disposition == match.group(1)
            and row.gap_reason == match.group(2),
            "structural inapplicability disposition/gap mismatch",
        )

    def publish(world: World, text: str, examples: dict) -> tuple[bool, str]:
        match = re.search(r'the assessment is published as "([^"]+)"', text)
        if match is None or match.group(1) != HYBRID_COVERAGE_ASSESSMENT_FILENAME:
            return False, "unexpected assessment artifact name"
        state = _state(world)
        ordered = assess_hybrid_coverage(
            state["plan"],
            state["resource_map"],
            state["reconciliation"],
            state["taxonomy"],
            state["stpa"],
        )
        reordered_taxonomy = TaxonomyCoverageInput(
            scenarios=tuple(reversed(state["taxonomy"].scenarios)),
            structural_inapplicability_decisions=tuple(
                reversed(state["taxonomy"].structural_inapplicability_decisions)
            ),
        )
        reordered_stpa = StpaCoverageInput(
            slots=tuple(reversed(state["stpa"].slots)),
            scenarios=tuple(reversed(state["stpa"].scenarios)),
            inventory_status=state["stpa"].inventory_status,
        )
        reordered_value = assess_hybrid_coverage(
            state["plan"],
            state["resource_map"],
            state["reconciliation"],
            reordered_taxonomy,
            reordered_stpa,
        )
        output = Path(tempfile.mkdtemp(prefix="hybrid-coverage-acceptance-"))
        path = write_hybrid_coverage_assessment(output, ordered)
        state.update(
            {
                "assessment": ordered,
                "ordered_assessment": ordered,
                "reordered_assessment": reordered_value,
                "round_trip": HybridCoverageAssessment.from_yaml(path.read_bytes()),
            }
        )
        return True, ""

    def identical(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        return (
            state["ordered_assessment"].to_yaml()
            == state["reordered_assessment"].to_yaml(),
            "reordered observations changed canonical bytes",
        )

    def round_trip(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        return state["round_trip"] == state["assessment"], "artifact round-trip changed"

    registrations = (
        (
            r"^completed typed hybrid coverage source artifacts are available$",
            completed,
        ),
        (r"^hybrid coverage assessment makes no provider calls$", offline),
        (
            r"^one confirmed coverage-bearing relation and matching legacy scenarios$",
            confirmed,
        ),
        (
            r"^real admitted taxonomy and STPA scenario envelopes are available$",
            real_scenario_envelopes,
        ),
        (
            r"^the real scenario envelopes are adapted for hybrid assessment$",
            adapt_real_scenario_envelopes,
        ),
        (
            r"^taxonomy observations contain \d+ exact obligation link$",
            taxonomy_observation_count,
        ),
        (
            r"^STPA observations contain \d+ exact slot ICA and EXEC link$",
            stpa_observation_count,
        ),
        (r'^one "[^"]+" proposal is explicitly "[^"]+"$', proposal),
        (
            r"^one proposal has a dangling resource-link identity$",
            defective_proposal,
        ),
        (
            r"^the authoritative map has only a link unrelated to the obligation resources$",
            unrelated_map,
        ),
        (
            r"^structural inventory has one ICA slot, one justified N/A slot, and one unresolved slot$",
            structural,
        ),
        (
            r"^one obligation has a reviewed structural inapplicability decision with other authoritative capability evidence$",
            inapplicable,
        ),
        (
            r'^one obligation has a structural inapplicability decision over "[^"]+" relevant capability inventory without other authoritative evidence$',
            partial_capability_inapplicable,
        ),
        (
            r"^structural inapplicability is assessed against capability inventory$",
            assess_partial_capability,
        ),
        (
            r'^structural inapplicability is rejected for "[^"]+" relevant capability inventory$',
            partial_capability_rejected,
        ),
        (
            r"^reordered structural and scenario observations produce two assessments$",
            reordered,
        ),
        (r"^hybrid coverage is assessed$", assess),
        (r"^structural consideration contains \d+ UCA slot row$", structural_count),
        (
            r'^taxonomy correspondence contains \d+ obligation row with disposition "[^"]+"$',
            taxonomy_count,
        ),
        (
            r'^scenario realization contains \d+ accepted relation with hybrid status "[^"]+" and "[^"]+"$',
            realization_count,
        ),
        (
            r'^hybrid coverage is attempted with substituted "[^"]+"$',
            assess_substituted_capability_pin,
        ),
        (
            r'^hybrid coverage rejects the substituted "[^"]+"$',
            assert_substituted_capability_rejected,
        ),
        (
            r"^scenario realization contains \d+ accepted relations$",
            realization_only_count,
        ),
        (r"^every hybrid matrix row and diagnostic cell is traceable$", traceable),
        (
            r'^structural consideration reports \d+ "[^"]+", \d+ "[^"]+", and \d+ "[^"]+"$',
            dispositions,
        ),
        (
            r'^taxonomy correspondence has no accepted coverage and gap "[^"]+"$',
            no_coverage_gap,
        ),
        (r'^the assessment retains finding "[^"]+"$', finding),
        (
            r'^the assessment retains one "[^"]+" proposal diagnostic$',
            proposal_diagnostic,
        ),
        (
            r'^scenario realization remains "[^"]+" and "[^"]+"$',
            realization_status,
        ),
        (
            r'^taxonomy correspondence disposition is "[^"]+" with gap "[^"]+"$',
            taxonomy_disposition,
        ),
        (r'^the assessment is published as "[^"]+"$', publish),
        (r"^both assessments have identical canonical bytes$", identical),
        (r"^the persisted assessment round-trips unchanged$", round_trip),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)


register = _register

__all__ = ["FEATURE_ID", "register"]
