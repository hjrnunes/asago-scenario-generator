"""Domain-neutral supported and mismatch attribution canaries."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccounting,
    ObligationAccountingRow,
    derive_obligation_accounting_summary,
)
from asago_scenario_generator.models.hybrid_coverage import ArtifactPin
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
from asago_scenario_generator.pipeline.synthesis_phase2 import (
    run_synthesis_phase2_verification,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
    ScenarioObligationConsideration,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    filter_ica_considerations,
    verify_final_ica_batch,
)
from tests.system_resource_map_support import make_control_structure
from tests.test_scenario_realization import (
    _accounting as realization_accounting,
)
from tests.stpa.test_sp3_scenario_continuity import _contextual_spec
from tests.test_synthesis_phase2 import _artifacts


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
        return {
            key: _replace(item, replacements) for key, item in value.items()
        }
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


def _scenario_for_phase2(plan, slot_id: str, ica_id: str) -> ScenarioSpec:
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
    payload["scenario_context"] = ScenarioGenerationContext.create(
        **context_payload
    )
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
    briefs = build_neutral_obligation_briefs(
        plan, inputs.attack_pattern_catalog
    )
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


def test_supported_ica_reaches_realization_and_unreviewed_phase2_proposal(
    tmp_path,
) -> None:
    """One supported path survives every provisional attribution boundary."""
    inputs, plan, loss, enumeration, pair, _accounting_row = _artifacts()
    control_structure = make_control_structure()
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
    scenario = _scenario_for_phase2(plan, pair.slot_id, pair.ica_ids[0])
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

    phase2 = run_synthesis_phase2_verification(
        obligation_plan=plan,
        capability_snapshot=inputs.capability_snapshot,
        loss_analysis=loss,
        control_structure=control_structure,
        ica_enumeration=filtered,
        ica_considerations=filtered_pairs,
        accounting_rows=(accounting.rows[0],),
        output_dir=tmp_path,
    )
    assert phase2.status == "awaiting_evidence"
    assert phase2.proposals.proposals
    assert all(
        item.relation_kind == "mechanism_enables_ica"
        for item in phase2.proposals.proposals
    )


def test_mismatched_ica_remains_accounted_but_cannot_realize_or_propose(
    tmp_path,
) -> None:
    """A semantic mismatch retains typed evidence and receives no credit."""
    inputs, plan, loss, enumeration, pair, _addressed_row = _artifacts()
    control_structure = make_control_structure()
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
    assert filtered.slots[0].is_na is True
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

    phase2 = run_synthesis_phase2_verification(
        obligation_plan=plan,
        capability_snapshot=inputs.capability_snapshot,
        loss_analysis=loss,
        control_structure=control_structure,
        ica_enumeration=filtered,
        ica_considerations=filtered_pairs,
        accounting_rows=(accounting.rows[0],),
        output_dir=tmp_path,
    )
    assert phase2.proposals.proposals == ()
