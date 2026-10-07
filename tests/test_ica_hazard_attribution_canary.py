"""Domain-neutral supported and mismatch attribution canaries."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccounting,
    ObligationAccountingRow,
    derive_obligation_accounting_summary,
)
from asago_scenario_generator.models.artifact_pin import ArtifactPin
from asago_scenario_generator.models.obligation_consideration import (
    ObligationIcaConsideration,
    ObligationRoute,
)
from asago_scenario_generator.pipeline.scenario_realization import (
    build_scenario_realization_assessment,
)
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_consideration_artifact,
    build_neutral_obligation_briefs,
    build_obligation_accounting,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
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
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
    ScenarioObligationConsideration,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    filter_ica_considerations,
    verify_final_ica_batch,
)
from tests.helpers.obligation_factory import make_inputs
from tests.helpers.governance import _accounting as realization_accounting
from tests.helpers.sp3_scenario_continuity import _contextual_spec

SLOT_ID = "RESP-1:CA-1-1:WRONG_TIMING"
ICA_ID = SLOT_ID + ":1"
EXEC_ID = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"


def _artifacts():
    """Return Phase 1 inputs, plan, loss analysis, ICAs, and one finding pair."""
    obligation_inputs = make_inputs()
    plan = plan_taxonomy_obligations(obligation_inputs)
    obligation = plan.obligations[0]
    loss = LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Payment loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=[obligation.risk_ref.risk_id],
            )
        ],
        use_case_losses=[],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Constrain payment",
                related_hazards=["H-1"],
            )
        ],
    )
    enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id=SLOT_ID,
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
    pair = ObligationIcaConsideration(
        route_id="route:review-candidate",
        obligation_id=obligation.obligation_id,
        slot_id=SLOT_ID,
        disposition="finding",
        ica_ids=(ICA_ID,),
        exec_candidate_ids=(EXEC_ID,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("synthesis:test",),
    )
    return obligation_inputs, plan, loss, enumeration, pair


def _control_structure() -> ControlStructure:
    """Return one minimal typed STPA control structure."""
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


def _replace(value: Any, replacements: dict[str, str]) -> Any:
    """Rewrite fixture identities while retaining the typed scenario shape."""
    if isinstance(value, str):
        for old, new in replacements.items():
            value = value.replace(old, new)
        return value
    if isinstance(value, list):
        return [_replace(item, replacements) for item in value]
    if isinstance(value, tuple):
        return tuple(_replace(item, replacements) for item in value)
    if isinstance(value, dict):
        return {key: _replace(item, replacements) for key, item in value.items()}
    return value


class _SupportsEveryICA:
    """Deterministic verifier used by the canary; no network is available."""

    def verify_ica_hazards(self, requests, *, correction_feedback=None):
        del correction_feedback
        return [
            {
                "ica_id": request.ica_id,
                "verdict": "supported",
                "rationale": "The selected action, hazard, constraint, and loss align.",
            }
            for request in requests
        ]


class _RejectsEveryICA:
    """Deterministic mismatch verifier used to prove credit is withheld."""

    def verify_ica_hazards(self, requests, *, correction_feedback=None):
        del correction_feedback
        return [
            {
                "ica_id": request.ica_id,
                "verdict": "contradictory",
                "rationale": "The selected action points away from the supplied hazard.",
            }
            for request in requests
        ]


class _DowngradesEveryICA:
    """Verifier whose every verdict lacks the evidence a hazardous absence needs."""

    def verify_ica_hazards(self, requests, *, correction_feedback=None):
        del correction_feedback
        return [
            {
                "ica_id": request.ica_id,
                "verdict": "insufficient_evidence",
                "downgrade_reason": "absence_evidence_missing",
                "rationale": "The absence names no loss it leads to.",
            }
            for request in requests
        ]


def _scenario_for_canary(plan, slot_id: str, ica_id: str) -> ScenarioSpec:
    """Adapt the shared structural scenario fixture to the canary identities."""
    source = _contextual_spec()
    old_slot = "RESP-1:CA-1-1:INCORRECT"
    old_ica = old_slot + ":1"
    payload = _replace(
        source.model_dump(mode="json"),
        {
            old_ica: ica_id,
            old_slot: slot_id,
            "H-MASS": "H-1",
            "SC-MASS": "SC-1",
            "L-MASS": "L-1",
            "INCORRECT": "WRONG_TIMING",
        },
    )
    context_payload = payload["scenario_context"]
    context_payload.pop("context_digest", None)
    context_payload["obligation_considerations"] = [
        ScenarioObligationConsideration(
            obligation_id=plan.obligations[0].obligation_id,
            attack_pattern_id="AP-BULK",
            attack_pattern_name="Automated mass-action abuse",
            concise_concern="One request triggers an unsafe bulk operation.",
            disposition="finding",
            rationale="The selected ICA exposes the same bulk-action concern.",
            finding_ica_id=ica_id,
        ).model_dump(mode="json")
    ]
    payload["scenario_context"] = ScenarioGenerationContext.create(**context_payload)
    payload["unsafe_outcome_hazard_refs"] = ["H-1"]
    payload["unsafe_outcome_constraint_refs"] = ["SC-1"]
    return ScenarioSpec.model_validate(payload)


def _realization_accounting(
    row: ObligationAccountingRow,
) -> ObligationAccounting:
    """Build realization authority for the exact addressed canary row."""
    source = realization_accounting()
    return ObligationAccounting(
        source_pins=source.source_pins,
        rows=(row,),
        summary=derive_obligation_accounting_summary((row,)),
    )


def _accounting_from_verified_consideration(
    inputs,
    plan,
    pair: Any,
    verified_pairs: tuple[Any, ...],
    verification: Any,
    enumeration: ICAEnumeration,
) -> ObligationAccounting:
    """Derive the canary row through the public accounting factory."""
    route = ObligationRoute(
        obligation_id=pair.obligation_id,
        disposition="targeted",
        slot_ids=(pair.slot_id,),
        hazard_ids=pair.hazard_ids,
        constraint_ids=pair.constraint_ids,
        evidence=("canary:verified-route",),
    )
    briefs = build_neutral_obligation_briefs(plan, inputs.attack_pattern_catalog)
    consideration = build_consideration_artifact(
        plan=plan,
        briefs=briefs,
        initial_routes=(route,),
        final_routes=(route,),
    )
    accounting_pairs = tuple(
        ObligationIcaConsideration.model_validate(
            {
                **item.model_dump(mode="python", exclude={"pair_id"}),
                "route_id": route.route_id,
            }
        )
        for item in verified_pairs
    )
    pins = (
        ArtifactPin(
            artifact_id="taxonomy-obligation-plan",
            schema_version="taxonomy-obligation-plan-v1",
            semantic_digest=plan.semantic_digest,
        ),
        ArtifactPin(
            artifact_id="stpa-loss-analysis",
            schema_version="stpa-loss-analysis-v1",
            semantic_digest="2" * 64,
        ),
        ArtifactPin(
            artifact_id="stpa-control-structure",
            schema_version="stpa-control-structure-v1",
            semantic_digest="3" * 64,
        ),
        ArtifactPin(
            artifact_id="ica-enumeration",
            schema_version="ica-enumeration-v1",
            semantic_digest="4" * 64,
        ),
    )
    return build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=accounting_pairs,
        source_pins=pins,
        ica_verification=verification,
        ica_enumeration=enumeration,
    )


def test_supported_ica_reaches_realization() -> None:
    """One supported path survives every provisional attribution boundary."""
    inputs, plan, loss, enumeration, pair = _artifacts()
    control_structure = _control_structure()
    filtered, verification = verify_final_ica_batch(
        _SupportsEveryICA(),
        enumeration,
        loss_analysis=loss,
        control_structure=control_structure,
    )
    filtered_pairs = filter_ica_considerations(
        (pair,), verification, enumeration=filtered
    )
    accounting = _accounting_from_verified_consideration(
        inputs, plan, pair, filtered_pairs, verification, filtered
    )

    assert verification.supported_count == 1
    assert filtered_pairs[0].disposition == "finding"
    assert accounting.rows[0].disposition == "addressed"

    # The realization helper uses the same typed evidence contract as the
    # product pipeline.  Adapt its domain-neutral scenario fixture to the
    # canary's exact Phase 1/ICA identities.
    scenario = _scenario_for_canary(plan, pair.slot_id, pair.ica_ids[0])
    realized = build_scenario_realization_assessment(
        accounting=_realization_accounting(
            accounting.rows[0].model_copy(update={"obligation_id": pair.obligation_id})
        ),
        ica_considerations=filtered_pairs,
        ica_enumeration=filtered,
        scenario_specs=(scenario,),
        requested_ica_ids=pair.ica_ids,
    )
    assert realized.summary.realized == 1
    assert realized.records[0].obligation_id == pair.obligation_id
    assert realized.records[0].ica_id == pair.ica_ids[0]


def test_a_downgraded_absence_is_accounted_under_its_own_stop_reason() -> None:
    """The row names the missing absence evidence, not generic insufficiency."""
    inputs, plan, loss, enumeration, pair = _artifacts()
    filtered, verification = verify_final_ica_batch(
        _DowngradesEveryICA(),
        enumeration,
        loss_analysis=loss,
        control_structure=_control_structure(),
    )
    filtered_pairs = filter_ica_considerations(
        (pair,), verification, enumeration=filtered
    )

    accounting = _accounting_from_verified_consideration(
        inputs, plan, pair, filtered_pairs, verification, filtered
    )

    (row,) = accounting.rows
    assert row.disposition == "unresolved"
    assert row.stop_reason == "ica_hazard_absence_evidence_missing"


def test_mismatched_ica_remains_accounted_but_cannot_realize() -> None:
    """A semantic mismatch retains typed evidence and receives no credit."""
    inputs, plan, loss, enumeration, pair = _artifacts()
    control_structure = _control_structure()
    filtered, verification = verify_final_ica_batch(
        _RejectsEveryICA(),
        enumeration,
        loss_analysis=loss,
        control_structure=control_structure,
    )
    filtered_pairs = filter_ica_considerations(
        (pair,), verification, enumeration=filtered
    )
    accounting = _accounting_from_verified_consideration(
        inputs, plan, pair, filtered_pairs, verification, filtered
    )
    # A failed semantic verification is not a reviewed N/A decision.  Keep
    # the slot unresolved so the failed path remains visible to accounting
    # while the supported sibling/realization paths receive no credit.
    assert filtered.slots[0].is_na is False
    assert filtered.slots[0].unresolved_reason
    assert filtered_pairs[0].disposition == "unresolved"
    assert any(
        item.code == "ica_hazard_correction_exhausted"
        for item in filtered_pairs[0].diagnostics
    )

    unresolved_row = accounting.rows[0]
    assert unresolved_row.disposition == "unresolved"
    unresolved_accounting = _realization_accounting(
        unresolved_row.model_copy(update={"obligation_id": pair.obligation_id})
    )
    realized = build_scenario_realization_assessment(
        accounting=unresolved_accounting,
        ica_considerations=filtered_pairs,
        ica_enumeration=filtered,
        scenario_specs=(),
    )
    assert realized.records == ()
