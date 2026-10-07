"""Typed Phase 1 and STPA values for synthesis composition-root fakes.

Stage fakes return these values so ``run_synthesis`` takes the same typed path
as a production run: a planner-built obligation plan, typed STPA structures,
and typed obligation routes and revisions.
"""

from __future__ import annotations

from collections.abc import Sequence
from copy import deepcopy
from functools import cache
from pathlib import Path
from typing import Any, Literal

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.attack_pattern_digests import (
    compute_chain_semantic_digest,
)
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationCallEvidence,
    MissingStructuralConcept,
    NeutralObligationBrief,
    ObligationRoute,
)
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.pipeline.obligation_contracts import (
    TaxonomyObligationInputs,
    compute_mapping_bundle_digest,
)
from asago_scenario_generator.pipeline.projection_qualification import (
    compute_authoritative_catalog_pin,
)
from asago_scenario_generator.pipeline.synthesis import SynthesisInputs
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlledProcess,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ResponsibilityConstraint,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    DraftHazard,
    RevisionDraft,
    RevisionGapDecision,
    StructuralRevisionRequest,
    StructuralRevisionResponse,
    SynthesisSlotFillResult,
)
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    IcaHazardVerificationBatch,
)
from asago_scenario_generator.stpa.obligation_aware.revision import (
    RevisionRunResult,
    revise_structure_once,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    SlotFillRunResult,
)

from tests.helpers.obligation_factory import make_inputs
from tests.helpers.projection_factory import get_test_raw_pattern, get_test_resolver

SLOT_ID = "RESP-1:CA-1-1:NOT_PROVIDED"
HAZARD_ID = "H-1"
CONSTRAINT_ID = "SC-1"

RouteDisposition = Literal[
    "targeted", "proposed_not_applicable", "upstream_gap", "unresolved"
]
RevisionOutcome = Literal["applied", "rejected", "compile_failure"]


def _capability_gated_pattern(raw: dict) -> AttackPattern:
    """Return a second pattern whose capability requirement the profile lacks."""
    gated = deepcopy(raw)
    gated["id"] = "AP-T1-02"
    gated["canonical_chain"]["pattern_id"] = "AP-T1-02"
    gated["canonical_chain"]["chain_id"] = "chain.2"
    gated["prerequisite_capabilities"]["kc_requires"] = {"all": ["KC2.1"], "any": []}
    gated["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        gated["canonical_chain"]
    )
    return AttackPattern.model_validate(gated)


@cache
def synthesis_taxonomy_inputs() -> TaxonomyObligationInputs:
    """Return planner input that yields every plan scope disposition.

    ``risk-a`` and ``risk-b`` map to the shared applicable pattern, ``risk-c``
    maps to a capability-gated pattern, and ``risk-governance`` has no mapping.
    """
    pattern = AttackPattern.model_validate(deepcopy(get_test_raw_pattern()))
    gated = _capability_gated_pattern(get_test_raw_pattern())
    catalog = [pattern.model_dump(mode="json"), gated.model_dump(mode="json")]
    mappings = [
        {
            "source_id": risk_id,
            "target_id": target_id,
            "relation": "exact_match",
            "confidence": 1.0,
        }
        for risk_id, target_id in (
            ("risk-a", pattern.id),
            ("risk-b", pattern.id),
            ("risk-c", gated.id),
        )
    ]
    payload = make_inputs(
        risk_ids=("risk-a", "risk-b", "risk-c", "risk-governance"),
        include_mapping=False,
    ).model_dump(mode="json")
    payload["attack_pattern_catalog"] = catalog
    payload["cross_taxonomy_mappings"] = mappings
    payload["catalog_pins"]["atlas"]["digest"] = compute_authoritative_catalog_pin(
        catalog, get_test_resolver()
    )
    payload["mapping_pins"]["obligation_edges"]["digest"] = (
        compute_mapping_bundle_digest(mappings, [])
    )
    return TaxonomyObligationInputs.model_validate(payload)


def synthesis_capability_profile() -> Any:
    """Return the capability profile that the planner input's snapshot pins."""
    return synthesis_taxonomy_inputs().capability_snapshot.profile


def synthesis_inputs(
    output_dir: Path,
    *,
    use_case: str = "A system that handles requests",
    **changes: Any,
) -> SynthesisInputs:
    """Return run inputs whose reviewed risks and facts match the plan input."""
    taxonomy_inputs = synthesis_taxonomy_inputs()
    return SynthesisInputs(
        use_case=use_case,
        risk_cards=taxonomy_inputs.risk_cards,
        qualification_facts=taxonomy_inputs.qualification_facts,
        output_dir=output_dir,
        **changes,
    )


def applicable_obligation_ids(plan: TaxonomyObligationPlan) -> tuple[str, ...]:
    """Return the plan's applicable obligation IDs in canonical order."""
    return tuple(
        sorted(
            row.obligation_id
            for row in plan.obligations
            if row.scope_disposition == "applicable"
        )
    )


def obligation_id_for(plan: TaxonomyObligationPlan, scope_disposition: str) -> str:
    """Return the single obligation ID with one non-applicable scope."""
    (match,) = (
        row.obligation_id
        for row in plan.obligations
        if row.scope_disposition == scope_disposition
    )
    return match


def baseline_loss_analysis() -> LossAnalysis:
    """Return a one-loss, one-hazard, one-constraint loss analysis."""
    return LossAnalysis(
        risk_card_losses=(
            Loss(
                loss_id="L-1",
                description="A protected operation is harmed.",
                provenance=LossProvenance.risk_card,
                source_risk_cards=("risk-a",),
            ),
        ),
        use_case_losses=(),
        hazards=(
            Hazard(
                hazard_id=HAZARD_ID,
                description="An unsafe request is accepted.",
                related_losses=("L-1",),
            ),
        ),
        security_constraints=(
            SecurityConstraint(
                constraint_id=CONSTRAINT_ID,
                rule="Requests must satisfy policy.",
                related_hazards=(HAZARD_ID,),
            ),
        ),
    )


def baseline_control_structure() -> ControlStructure:
    """Return one responsibility whose control action owns :data:`SLOT_ID`."""
    return ControlStructure(
        responsibilities=(
            Responsibility(
                resp_id="RESP-1",
                description="Validate incoming requests.",
                responsibility_constraints=(
                    ResponsibilityConstraint(
                        rc_id="RC-1-1", description="Requests must be validated."
                    ),
                ),
                process_model_parts=(
                    ProcessModelPart(pm_id="PM-1-1", description="Request state."),
                ),
                control_actions=(
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Validate request.",
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ),
                feedback_channels=(
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="Request feedback.",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ),
            ),
        ),
        controlled_processes=(
            ControlledProcess(cp_id="CP-1", description="Request process."),
        ),
        coordination_links=(),
    )


def obligation_route(
    obligation_id: str, disposition: RouteDisposition
) -> ObligationRoute:
    """Build one closed route against the baseline structure's identities."""
    fields: dict = {"obligation_id": obligation_id, "evidence": ("fixture-route",)}
    if disposition == "targeted":
        fields.update(
            slot_ids=(SLOT_ID,),
            hazard_ids=(HAZARD_ID,),
            constraint_ids=(CONSTRAINT_ID,),
        )
    elif disposition == "proposed_not_applicable":
        fields.update(
            slot_ids=(SLOT_ID,),
            rationale="The supplied structural inventory shows no applicable path.",
        )
    elif disposition == "upstream_gap":
        fields.update(
            rationale="The baseline lacks a structural concept needed for analysis.",
            missing_concepts=(
                MissingStructuralConcept(
                    concept_type="hazard",
                    description="The hazard is not explicit in the baseline.",
                    evidence_refs=("fixture-gap",),
                    obligation_id=obligation_id,
                ),
            ),
        )
    else:
        fields["rationale"] = "The available structural evidence is insufficient."
    return ObligationRoute(disposition=disposition, **fields)


def obligation_routes(
    briefs: Sequence[NeutralObligationBrief], disposition: RouteDisposition
) -> tuple[ObligationRoute, ...]:
    """Route every brief with the same disposition."""
    return tuple(obligation_route(item.obligation_id, disposition) for item in briefs)


class _ScriptedRevisionAdapter:
    """Answer the one revision request with a fixed, request-bound draft."""

    def __init__(self, outcome: RevisionOutcome) -> None:
        self.outcome = outcome

    def revise(self, request: StructuralRevisionRequest) -> StructuralRevisionResponse:
        handles = tuple(
            f"revision-gap-{index}" for index in range(1, len(request.gaps) + 1)
        )
        if self.outcome == "applied":
            draft = RevisionDraft(
                hazards=(
                    DraftHazard(
                        handle="hazard-1",
                        description="Request validation is bypassed.",
                        related_loss_ids=("L-1",),
                    ),
                ),
                gap_decisions=tuple(
                    RevisionGapDecision(
                        gap_handle=handle,
                        disposition="propose_addition",
                        rationale="The use case shows the missing hazard.",
                    )
                    for handle in handles
                ),
            )
        elif self.outcome == "rejected":
            draft = RevisionDraft(
                gap_decisions=tuple(
                    RevisionGapDecision(
                        gap_handle=handle,
                        disposition="dismiss_unsupported",
                        rationale="The supplied evidence does not support it.",
                    )
                    for handle in handles
                ),
            )
        else:
            draft = RevisionDraft(
                gap_decisions=(
                    RevisionGapDecision(
                        gap_handle="revision-gap-unknown",
                        disposition="propose_addition",
                        rationale="This handle is not in the request.",
                    ),
                ),
            )
        return StructuralRevisionResponse(
            adapter_kind="fake", request_digest=request.semantic_digest, draft=draft
        )


def structural_revision(
    gap_routes: Sequence[ObligationRoute],
    *,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    outcome: RevisionOutcome = "applied",
) -> RevisionRunResult:
    """Run the real one-round revision worker with a scripted response."""
    return revise_structure_once(
        _ScriptedRevisionAdapter(outcome),
        gaps=tuple(
            concept for route in gap_routes for concept in route.missing_concepts
        ),
        trigger_obligation_ids=tuple(route.obligation_id for route in gap_routes),
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )


def final_ica_result(
    *,
    call_evidence: Sequence[ConsiderationCallEvidence] = (),
    ica_hazard_verification: IcaHazardVerificationBatch | None = None,
) -> SlotFillRunResult:
    """Return a final ICA stage result over an empty slot enumeration."""
    return SlotFillRunResult(
        result=SynthesisSlotFillResult(
            ica_enumeration=ICAEnumeration(slots=[]),
            call_evidence=tuple(call_evidence),
            ica_hazard_verification=ica_hazard_verification,
        )
    )
