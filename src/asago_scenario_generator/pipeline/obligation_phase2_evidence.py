"""Offline Phase 2 proposal evidence from provisional STPA accounting.

This adapter is intentionally one directional.  It turns exact identities
already present in the Phase 1 plan and provisional STPA accounting into
reviewable Phase 2 evidence, but it does not invoke the proposer or
reconciler and cannot create an accepted relation or a reviewed decision.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from asago_scenario_generator.models.correspondence import (
    CorrespondenceEvidence,
    RelationKind,
    SourceArtifactPins,
)
from asago_scenario_generator.models.hybrid_coverage import ArtifactPin
from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccounting,
    ObligationAccountingRow,
)
from asago_scenario_generator.models.obligation_consideration import (
    ObligationIcaConsideration,
    ObligationPhase2Evidence,
    ObligationRoute,
    ProposedStructuralNonApplicabilityEvidence,
)
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan


_REQUIRED_PROPOSAL_PIN_FIELDS = (
    "resource_map_semantic_digest",
    "capability_snapshot_digest",
    "obligation_plan_semantic_digest",
    "control_structure_digest",
    "ica_enumeration_digest",
    "loss_analysis_digest",
    "taxonomy_version",
    "stpa_version",
)


def _require_plan(value: Any) -> TaxonomyObligationPlan:
    """Require one intact typed Phase 1 plan."""
    if not isinstance(value, TaxonomyObligationPlan):
        raise TypeError("plan must be a TaxonomyObligationPlan")
    value.assert_integrity()
    return value


def _require_accounting(
    value: Any, plan: TaxonomyObligationPlan
) -> ObligationAccounting:
    """Require accounting for exactly the supplied Phase 1 obligation universe."""
    if not isinstance(value, ObligationAccounting):
        raise TypeError("accounting must be an ObligationAccounting")
    value.assert_integrity()
    plan_pin = tuple(
        pin
        for pin in value.source_pins
        if pin.artifact_id == "taxonomy-obligation-plan"
    )
    if (
        len(plan_pin) != 1
        or plan_pin[0].schema_version != "taxonomy-obligation-plan-v1"
    ):
        raise ValueError("accounting must contain one Phase 1 plan source pin")
    if plan_pin[0].semantic_digest != plan.semantic_digest:
        raise ValueError("accounting is pinned to a different Phase 1 plan")
    expected_ids = {row.obligation_id for row in plan.obligations}
    actual_ids = {row.obligation_id for row in value.rows}
    if actual_ids != expected_ids:
        raise ValueError("accounting rows must match the complete Phase 1 plan")
    return value


def _require_proposal_pins(
    value: Any, plan: TaxonomyObligationPlan
) -> SourceArtifactPins:
    """Require complete exact source pins needed by Phase 2 proposals."""
    if not isinstance(value, SourceArtifactPins):
        raise TypeError("source_pins must be a SourceArtifactPins")
    missing = tuple(
        name for name in _REQUIRED_PROPOSAL_PIN_FIELDS if not getattr(value, name)
    )
    if missing:
        raise ValueError(
            "Phase 2 proposal evidence requires complete source pins: "
            + ", ".join(missing)
        )
    if value.obligation_plan_semantic_digest != plan.semantic_digest:
        raise ValueError("proposal source pins use a different Phase 1 plan")
    if value.taxonomy_version != plan.schema_version:
        raise ValueError("proposal source pins use a different taxonomy schema")
    return value


def _typed_pairs(
    values: Iterable[ObligationIcaConsideration],
) -> tuple[ObligationIcaConsideration, ...]:
    """Require exact ICA consideration records, never loose payloads."""
    if isinstance(values, (str, bytes, dict)):
        raise TypeError("ica_considerations must be an iterable of typed records")
    try:
        pairs = tuple(values)
    except TypeError as exc:
        raise TypeError(
            "ica_considerations must be an iterable of typed records"
        ) from exc
    if any(not isinstance(item, ObligationIcaConsideration) for item in pairs):
        raise TypeError(
            "ica_considerations must contain only ObligationIcaConsideration values"
        )
    keys = tuple((item.obligation_id, item.slot_id) for item in pairs)
    if len(keys) != len(set(keys)):
        raise ValueError("ICA considerations must contain unique obligation/slot pairs")
    return tuple(sorted(pairs, key=lambda item: (item.obligation_id, item.slot_id)))


def _route_index(
    consideration: Any, plan: TaxonomyObligationPlan
) -> dict[str, ObligationRoute]:
    """Index optional exact final routes for rationale and route validation."""
    if consideration is None:
        return {}
    if not hasattr(consideration, "final_routes"):
        raise TypeError("consideration must be an ObligationConsideration")
    from asago_scenario_generator.models.obligation_consideration import (
        ObligationConsideration,
    )

    if not isinstance(consideration, ObligationConsideration):
        raise TypeError("consideration must be an ObligationConsideration")
    consideration.assert_integrity()
    if any(brief.plan_digest != plan.semantic_digest for brief in consideration.briefs):
        raise ValueError("consideration uses a different Phase 1 plan")
    return {route.obligation_id: route for route in consideration.final_routes}


def _deduplicate(values: Iterable[str]) -> tuple[str, ...]:
    """Return deterministic unique evidence references."""
    return tuple(sorted(set(values)))


def _row_pairs(
    pairs: tuple[ObligationIcaConsideration, ...], obligation_id: str
) -> tuple[ObligationIcaConsideration, ...]:
    """Return exact pair records for one obligation."""
    return tuple(item for item in pairs if item.obligation_id == obligation_id)


def _validate_pair_rows(
    pairs: tuple[ObligationIcaConsideration, ...],
    accounting: ObligationAccounting,
) -> None:
    """Reject ICA evidence that cannot resolve to an accounting row."""
    rows = {row.obligation_id: row for row in accounting.rows}
    for pair in pairs:
        row = rows.get(pair.obligation_id)
        if row is None:
            raise ValueError("ICA consideration references an unknown accounting row")
        if row.disposition not in {"addressed", "proposed_not_applicable"}:
            raise ValueError(
                "ICA consideration references a non-routable accounting disposition"
            )


def _check_pair_against_row(
    row: ObligationAccountingRow,
    pair: ObligationIcaConsideration,
    route: ObligationRoute | None,
) -> None:
    """Ensure an ICA pair is an exact witness retained by accounting."""
    if pair.disposition != "finding":
        raise ValueError("addressed accounting requires finding ICA evidence")
    if pair.slot_id not in row.slot_ids:
        raise ValueError("ICA pair slot is absent from its addressed accounting row")
    if not set(pair.ica_ids) <= set(row.ica_ids):
        raise ValueError("ICA pair identity is absent from its addressed row")
    if not set(pair.exec_candidate_ids) <= set(row.exec_candidate_ids):
        raise ValueError("EXEC identity is absent from its addressed row")
    if not set(pair.hazard_ids) <= set(row.hazard_ids):
        raise ValueError("hazard identity is absent from its addressed row")
    if not set(pair.constraint_ids) <= set(row.constraint_ids):
        raise ValueError("constraint identity is absent from its addressed row")
    if route is not None:
        if pair.route_id != route.route_id:
            raise ValueError("ICA pair is pinned to a different final route")
        if pair.slot_id not in route.slot_ids:
            raise ValueError("ICA pair names a slot outside its final route")
    if pair.route_id not in row.route_refs:
        raise ValueError("ICA pair route is absent from its addressed accounting row")


def _addressed_witnesses(
    row: ObligationAccountingRow,
    pairs: tuple[ObligationIcaConsideration, ...],
    route: ObligationRoute | None,
) -> tuple[
    tuple[str, str, str, tuple[str, ...], tuple[str, ...], tuple[str, ...]], ...
]:
    """Return exact slot/ICA/EXEC/hazard/constraint witnesses for a row."""
    row_pairs = _row_pairs(pairs, row.obligation_id)
    if row_pairs:
        for pair in row_pairs:
            _check_pair_against_row(row, pair, route)
        witnesses = []
        for pair in row_pairs:
            if len(pair.ica_ids) != 1 or len(pair.exec_candidate_ids) != 1:
                raise ValueError(
                    "each addressed ICA pair must identify one ICA and one EXEC"
                )
            witnesses.append(
                (
                    pair.slot_id,
                    pair.ica_ids[0],
                    pair.exec_candidate_ids[0],
                    pair.hazard_ids,
                    pair.constraint_ids,
                    pair.evidence,
                )
            )
        return tuple(witnesses)
    if (
        len(row.slot_ids) != 1
        or len(row.ica_ids) != 1
        or len(row.exec_candidate_ids) != 1
        or len(row.route_refs) != 1
    ):
        raise ValueError(
            "addressed rows with multiple findings require exact ICA considerations"
        )
    return (
        (
            row.slot_ids[0],
            row.ica_ids[0],
            row.exec_candidate_ids[0],
            row.hazard_ids,
            row.constraint_ids,
            (),
        ),
    )


def _candidate_ids(row: Any) -> tuple[str, ...]:
    """Return all exact Phase 1 candidate IDs for one applicable row."""
    return tuple(candidate.candidate_id for candidate in row.candidate_records)


def _projectable_candidate_ids(row: Any) -> tuple[str, ...]:
    """Return projectable candidates eligible for a Phase 2 proposal seed."""
    return tuple(
        candidate.candidate_id
        for candidate in row.candidate_records
        if candidate.projection_disposition == "projectable"
    )


def _proposal_evidence_for_row(
    obligation: Any,
    row: ObligationAccountingRow,
    accounting: ObligationAccounting,
    route: ObligationRoute | None,
    pairs: tuple[ObligationIcaConsideration, ...],
    source_pins: SourceArtifactPins,
    *,
    proposer_id: str,
    proposer_version: str,
    relation_kind: RelationKind,
) -> tuple[CorrespondenceEvidence, ...]:
    """Turn one addressed row into exact, unaccepted proposal evidence."""
    if obligation.scope_disposition != "applicable":
        raise ValueError("only applicable obligations can produce proposal evidence")
    candidates = _projectable_candidate_ids(obligation)
    if not candidates:
        raise ValueError(
            "addressed obligation has no projectable Phase 1 candidate for Phase 2"
        )
    witnesses = _addressed_witnesses(row, pairs, route)
    result = []
    for (
        slot_id,
        ica_id,
        exec_id,
        hazard_ids,
        constraint_ids,
        pair_evidence,
    ) in witnesses:
        for candidate_id in candidates:
            refs = _deduplicate(
                (
                    f"obligation-accounting:{accounting.semantic_digest}",
                    f"obligation:{row.obligation_id}",
                    f"route:{row.route_refs[0]}",
                    f"slot:{slot_id}",
                    f"ica:{ica_id}",
                    f"candidate:{candidate_id}",
                    *row.evidence,
                    *pair_evidence,
                )
            )
            result.append(
                CorrespondenceEvidence(
                    obligation_id=row.obligation_id,
                    risk_id=obligation.risk_ref.risk_id,
                    attack_pattern_id=obligation.attack_pattern_id,
                    taxonomy_candidate_ids=_candidate_ids(obligation),
                    selected_candidate_id=candidate_id,
                    ica_slot_id=slot_id,
                    ica_id=ica_id,
                    exec_candidate_id=exec_id,
                    relation_kind=relation_kind,
                    hazard_ids=hazard_ids,
                    constraint_ids=constraint_ids,
                    evidence_source="exact_id",
                    evidence_refs=refs,
                    confidence=1.0,
                    evidence_strength="medium",
                    proposer_id=proposer_id,
                    proposer_version=proposer_version,
                    source_pins=source_pins,
                    rationale=(
                        "Provisional STPA accounting supplies exact identities for a "
                        "reviewable Phase 2 proposal; no correspondence or coverage "
                        "is established without independent evidence and adjudication."
                    ),
                )
            )
    return tuple(result)


def build_phase2_proposal_evidence(
    plan: TaxonomyObligationPlan,
    accounting: ObligationAccounting,
    *,
    source_pins: SourceArtifactPins,
    consideration: Any | None = None,
    ica_considerations: Iterable[ObligationIcaConsideration] = (),
    proposer_id: str = "obligation-accounting-v1",
    proposer_version: str = "1",
    relation_kind: RelationKind = "same_mechanism",
) -> tuple[CorrespondenceEvidence, ...]:
    """Build exact nonaccepted correspondence proposal evidence offline.

    Addressed accounting rows are expanded once for each projectable Phase 1
    candidate and exact ICA pair.  Rows with any other disposition are not
    turned into correspondence evidence.
    """
    plan = _require_plan(plan)
    accounting = _require_accounting(accounting, plan)
    source_pins = _require_proposal_pins(source_pins, plan)
    routes = _route_index(consideration, plan)
    pairs = _typed_pairs(ica_considerations)
    _validate_pair_rows(pairs, accounting)
    result: list[CorrespondenceEvidence] = []
    for row in accounting.rows:
        if row.disposition != "addressed":
            continue
        obligation = next(
            item for item in plan.obligations if item.obligation_id == row.obligation_id
        )
        result.extend(
            _proposal_evidence_for_row(
                obligation,
                row,
                accounting,
                routes.get(row.obligation_id),
                pairs,
                source_pins,
                proposer_id=proposer_id,
                proposer_version=proposer_version,
                relation_kind=relation_kind,
            )
        )
    return tuple(
        sorted(
            result,
            key=lambda item: item.model_dump_json(),
        )
    )


def _phase2_source_pins(
    accounting: ObligationAccounting, plan: TaxonomyObligationPlan
) -> tuple[ArtifactPin, ...]:
    """Build exact generic pins for proposal-only structural evidence."""
    return (
        ArtifactPin(
            artifact_id="taxonomy-obligation-plan",
            schema_version="taxonomy-obligation-plan-v1",
            semantic_digest=plan.semantic_digest,
        ),
        ArtifactPin(
            artifact_id="obligation-accounting",
            schema_version="stpa-obligation-accounting-v1",
            semantic_digest=accounting.semantic_digest,
        ),
    )


def build_phase2_structural_evidence(
    plan: TaxonomyObligationPlan,
    accounting: ObligationAccounting,
    *,
    consideration: Any | None = None,
    ica_considerations: Iterable[ObligationIcaConsideration] = (),
    inventory_status: str = "complete",
) -> tuple[ProposedStructuralNonApplicabilityEvidence, ...]:
    """Build reviewable structural evidence without a reviewed decision."""
    plan = _require_plan(plan)
    accounting = _require_accounting(accounting, plan)
    routes = _route_index(consideration, plan)
    pairs = _typed_pairs(ica_considerations)
    _validate_pair_rows(pairs, accounting)
    if inventory_status not in {"complete", "partial", "unknown"}:
        raise ValueError("inventory_status must be complete, partial, or unknown")
    source_pins = _phase2_source_pins(accounting, plan)
    by_id = {item.obligation_id: item for item in plan.obligations}
    result = []
    for row in accounting.rows:
        if row.disposition != "proposed_not_applicable":
            continue
        route = routes.get(row.obligation_id)
        if route is not None:
            if route.disposition != "proposed_not_applicable":
                raise ValueError("accounting N/A row does not match its final route")
            if tuple(route.slot_ids) != tuple(row.slot_ids):
                raise ValueError("accounting N/A slots do not match the final route")
        row_pairs = _row_pairs(pairs, row.obligation_id)
        effective_status = inventory_status
        if row_pairs:
            if {pair.slot_id for pair in row_pairs} != set(row.slot_ids):
                raise ValueError(
                    "N/A evidence must cover every routed slot exactly once"
                )
            if any(pair.disposition != "proposed_not_applicable" for pair in row_pairs):
                raise ValueError("N/A accounting requires N/A evidence for every slot")
            if any(not pair.structural_inventory_complete for pair in row_pairs):
                effective_status = "unknown"
            elif effective_status == "unknown":
                effective_status = "unknown"
        obligation = by_id[row.obligation_id]
        rationale = (
            route.rationale
            if route is not None and route.rationale
            else "Provisional structural non-applicability requires independent review."
        )
        refs = _deduplicate(
            (
                f"obligation-accounting:{accounting.semantic_digest}",
                f"obligation:{row.obligation_id}",
                *row.route_refs,
                *row.evidence,
                *(item for pair in row_pairs for item in pair.evidence),
            )
        )
        result.append(
            ProposedStructuralNonApplicabilityEvidence(
                obligation_id=obligation.obligation_id,
                slot_ids=row.slot_ids,
                route_refs=row.route_refs,
                rationale=rationale,
                evidence_refs=refs,
                inventory_status=effective_status,
                source_pins=source_pins,
            )
        )
    return tuple(sorted(result, key=lambda item: item.evidence_id or ""))


def build_phase2_evidence_from_accounting(
    plan: TaxonomyObligationPlan,
    accounting: ObligationAccounting,
    *,
    source_pins: SourceArtifactPins,
    consideration: Any | None = None,
    ica_considerations: Iterable[ObligationIcaConsideration] = (),
    proposer_id: str = "obligation-accounting-v1",
    proposer_version: str = "1",
    relation_kind: RelationKind = "same_mechanism",
    inventory_status: str = "complete",
) -> ObligationPhase2Evidence:
    """Build one immutable proposal-only Phase 2 evidence bundle."""
    proposals = build_phase2_proposal_evidence(
        plan,
        accounting,
        source_pins=source_pins,
        consideration=consideration,
        ica_considerations=ica_considerations,
        proposer_id=proposer_id,
        proposer_version=proposer_version,
        relation_kind=relation_kind,
    )
    structural = build_phase2_structural_evidence(
        plan,
        accounting,
        consideration=consideration,
        ica_considerations=ica_considerations,
        inventory_status=inventory_status,
    )
    return ObligationPhase2Evidence(
        source_pins=source_pins,
        proposal_evidence=proposals,
        structural_evidence=structural,
    )


derive_phase2_evidence_from_accounting = build_phase2_evidence_from_accounting


__all__ = [
    "build_phase2_evidence_from_accounting",
    "build_phase2_proposal_evidence",
    "build_phase2_structural_evidence",
    "derive_phase2_evidence_from_accounting",
]
