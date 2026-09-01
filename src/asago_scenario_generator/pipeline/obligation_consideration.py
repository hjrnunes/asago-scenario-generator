"""Pure deterministic builders and validators for STPA consideration.

This module is the inward seam used by synthesis orchestration.  It accepts
only validated Phase 1 and attack-pattern models, performs no provider or
filesystem work, and leaves structural/STPA authority with the caller's
typed adapters.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccounting,
    ObligationAccountingRow,
    validate_obligation_accounting_source_pins,
)
from asago_scenario_generator.models.obligation_consideration import (
    BoundedStructuralRevision,
    ConsiderationDiagnostic,
    NeutralObligationBrief,
    ObligationConsideration,
    ObligationIcaConsideration,
    ObligationRoute,
)
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan


def _require_plan(value: Any) -> TaxonomyObligationPlan:
    """Require the exact closed Phase 1 plan model at the boundary."""
    if not isinstance(value, TaxonomyObligationPlan):
        raise TypeError("plan must be a TaxonomyObligationPlan")
    value.assert_integrity()
    return value


def _typed_patterns(value: Iterable[AttackPattern]) -> tuple[AttackPattern, ...]:
    """Validate and canonicalize an iterable of authoritative patterns."""
    if isinstance(value, (str, bytes, dict)):
        raise TypeError("patterns must be an iterable of AttackPattern values")
    try:
        patterns = tuple(value)
    except TypeError as exc:
        raise TypeError("patterns must be an iterable of AttackPattern values") from exc
    if any(not isinstance(item, AttackPattern) for item in patterns):
        raise TypeError("patterns must contain only AttackPattern values")
    ids = tuple(item.id for item in patterns)
    if len(ids) != len(set(ids)):
        raise ValueError("attack-pattern records must have unique IDs")
    return tuple(sorted(patterns, key=lambda item: item.id))


def _typed_briefs(
    value: Iterable[NeutralObligationBrief],
) -> tuple[NeutralObligationBrief, ...]:
    """Validate and canonicalize a brief collection at a pure seam."""
    if isinstance(value, (str, bytes, dict)):
        raise TypeError("briefs must be an iterable of NeutralObligationBrief values")
    try:
        briefs = tuple(value)
    except TypeError as exc:
        raise TypeError(
            "briefs must be an iterable of NeutralObligationBrief values"
        ) from exc
    if any(not isinstance(item, NeutralObligationBrief) for item in briefs):
        raise TypeError("briefs must contain only NeutralObligationBrief values")
    ordered = tuple(sorted(briefs, key=lambda item: item.obligation_id))
    ids = tuple(item.obligation_id for item in ordered)
    if len(ids) != len(set(ids)):
        raise ValueError("briefs must have unique obligation IDs")
    for brief in ordered:
        brief.assert_integrity()
    return ordered


def build_neutral_obligation_briefs(
    plan: TaxonomyObligationPlan,
    attack_pattern_catalog: Iterable[AttackPattern],
) -> tuple[NeutralObligationBrief, ...]:
    """Build one neutral brief for every applicable Phase 1 obligation.

    Qualification and projection dispositions intentionally do not filter the
    result.  Capability-excluded and governance-only rows remain in Phase 1
    accounting but are not attack-pattern questions and therefore produce no
    brief.
    """
    plan = _require_plan(plan)
    patterns = _typed_patterns(attack_pattern_catalog)
    by_id = {pattern.id: pattern for pattern in patterns}
    briefs: list[NeutralObligationBrief] = []
    for row in plan.obligations:
        if row.scope_disposition != "applicable":
            continue
        if row.attack_pattern_id is None or row.attack_pattern_semantic_digest is None:
            raise ValueError(
                f"applicable obligation {row.obligation_id} lacks attack-pattern identity"
            )
        pattern = by_id.get(row.attack_pattern_id)
        if pattern is None:
            raise ValueError(
                f"obligation {row.obligation_id} references an unknown attack pattern"
            )
        if (
            pattern.canonical_chain.semantic_digest
            != row.attack_pattern_semantic_digest
        ):
            raise ValueError(
                f"obligation {row.obligation_id} substituted its attack-pattern digest"
            )
        resources = tuple(
            binding.resource_ref
            for candidate in row.candidate_records
            for binding in candidate.resource_bindings
        )
        resource_bytes = {item.model_dump_json(): item for item in resources}
        briefs.append(
            NeutralObligationBrief(
                obligation_id=row.obligation_id,
                risk_ref=row.risk_ref,
                attack_pattern_id=pattern.id,
                attack_pattern_name=pattern.name,
                attack_pattern_description=pattern.description,
                attack_pattern_semantic_digest=pattern.canonical_chain.semantic_digest,
                taxonomy_chain=row.taxonomy_chain,
                prerequisite_capabilities=pattern.prerequisite_capabilities,
                qualification_disposition=row.qualification_disposition,
                applicability_evidence=row.evidence,
                resource_references=tuple(resource_bytes.values()),
                candidate_ids=tuple(
                    candidate.candidate_id for candidate in row.candidate_records
                ),
                plan_digest=plan.semantic_digest,
                catalog_pins=plan.catalog_pins,
                mapping_pins=plan.mapping_pins,
            )
        )
    return tuple(sorted(briefs, key=lambda item: item.obligation_id))


# The shorter name is useful in the STPA adapter while retaining the full
# name for callers that want to emphasize the Phase 1 provenance.
build_neutral_briefs = build_neutral_obligation_briefs


def batch_neutral_obligation_briefs(
    briefs: Iterable[NeutralObligationBrief],
    max_batch_size: int,
) -> tuple[tuple[NeutralObligationBrief, ...], ...]:
    """Partition briefs by canonical obligation identity and fixed batch size."""
    if type(max_batch_size) is not int:
        raise TypeError("max_batch_size must be an integer")
    if max_batch_size <= 0:
        raise ValueError("max_batch_size must be positive")
    ordered = _typed_briefs(briefs)
    return tuple(
        ordered[index : index + max_batch_size]
        for index in range(0, len(ordered), max_batch_size)
    )


create_obligation_batches = batch_neutral_obligation_briefs


def validate_obligation_routes(
    briefs: Iterable[NeutralObligationBrief],
    routes: Iterable[ObligationRoute],
) -> tuple[ObligationRoute, ...]:
    """Require exactly one route result for each supplied applicable brief."""
    expected = _typed_briefs(briefs)
    if isinstance(routes, (str, bytes, dict)):
        raise TypeError("routes must be an iterable of ObligationRoute values")
    try:
        values = tuple(routes)
    except TypeError as exc:
        raise TypeError("routes must be an iterable of ObligationRoute values") from exc
    if any(not isinstance(item, ObligationRoute) for item in values):
        raise TypeError("routes must contain only ObligationRoute values")
    ordered = tuple(sorted(values, key=lambda item: item.obligation_id))
    ids = tuple(item.obligation_id for item in ordered)
    expected_ids = tuple(item.obligation_id for item in expected)
    if len(ids) != len(set(ids)):
        raise ValueError("route results contain duplicate obligation IDs")
    if len(ids) < len(expected_ids):
        raise ValueError("route results must account for every obligation exactly once")
    if set(ids) - set(expected_ids):
        raise ValueError("route results contain additional obligation IDs")
    if ids != expected_ids:
        raise ValueError("route results must account for every obligation exactly once")
    return ordered


validate_routes = validate_obligation_routes


def _plan_pin(plan: TaxonomyObligationPlan):
    """Build the exact plan pin required by both synthesis sidecars."""
    from asago_scenario_generator.models.hybrid_coverage import ArtifactPin

    return ArtifactPin(
        artifact_id="taxonomy-obligation-plan",
        schema_version="taxonomy-obligation-plan-v1",
        semantic_digest=plan.semantic_digest,
    )


def build_consideration_artifact(
    *,
    plan: TaxonomyObligationPlan,
    briefs: Iterable[NeutralObligationBrief],
    initial_routes: Iterable[ObligationRoute],
    final_routes: Iterable[ObligationRoute],
    revision: BoundedStructuralRevision | None = None,
    rechecked_routes: Iterable[ObligationRoute] = (),
    source_pins: Iterable[Any] = (),
    diagnostics: Iterable[ConsiderationDiagnostic] = (),
) -> ObligationConsideration:
    """Construct and validate one closed consideration artifact.

    The Phase 1 pin is inserted when omitted, which keeps the public factory
    narrow while ensuring every published artifact remains source-pinned.
    """
    plan = _require_plan(plan)
    typed_briefs = _typed_briefs(briefs)
    typed_initial = tuple(initial_routes)
    typed_final = tuple(final_routes)
    typed_rechecked = tuple(rechecked_routes)
    validate_obligation_routes(typed_briefs, typed_initial)
    validate_obligation_routes(typed_briefs, typed_final)
    if revision is None:
        revision = BoundedStructuralRevision()
    if not isinstance(revision, BoundedStructuralRevision):
        raise TypeError("revision must be a BoundedStructuralRevision")
    if any(not isinstance(item, ConsiderationDiagnostic) for item in diagnostics):
        raise TypeError("diagnostics must contain only ConsiderationDiagnostic values")
    pins = tuple(source_pins)
    from asago_scenario_generator.models.hybrid_coverage import ArtifactPin

    if any(not isinstance(item, ArtifactPin) for item in pins):
        raise TypeError("source_pins must contain only ArtifactPin values")
    if not any(item.artifact_id == "taxonomy-obligation-plan" for item in pins):
        pins = (_plan_pin(plan), *pins)
    else:
        plan_pins = tuple(
            item for item in pins if item.artifact_id == "taxonomy-obligation-plan"
        )
        if any(
            item.schema_version != "taxonomy-obligation-plan-v1"
            or item.semantic_digest != plan.semantic_digest
            for item in plan_pins
        ):
            raise ValueError("source_pins contain a substituted Phase 1 plan pin")
    return ObligationConsideration(
        source_pins=pins,
        briefs=typed_briefs,
        initial_routes=typed_initial,
        revision=revision,
        rechecked_routes=typed_rechecked,
        final_routes=typed_final,
        diagnostics=tuple(diagnostics),
    )


def _phase1_evidence(row: Any) -> tuple[str, ...]:
    """Copy Phase 1 evidence into provisional accounting text references."""
    return tuple(f"phase1:{item.kind}:{item.detail}" for item in row.evidence) or (
        "phase1:obligation-row",
    )


def _pair_results_for(
    pair_results: tuple[ObligationIcaConsideration, ...],
    obligation_id: str,
) -> tuple[ObligationIcaConsideration, ...]:
    """Return canonical pair results for one exact obligation."""
    return tuple(
        sorted(
            (item for item in pair_results if item.obligation_id == obligation_id),
            key=lambda item: item.slot_id,
        )
    )


def _account_evidence(
    route: ObligationRoute,
    pairs: tuple[ObligationIcaConsideration, ...],
) -> tuple[str, ...]:
    """Combine route and pair evidence into one stable set."""
    return tuple(
        sorted(
            {
                item
                for values in (
                    route.evidence,
                    *(pair.evidence for pair in pairs),
                )
                for item in values
            }
        )
    )


def _account_route_row(
    row: Any,
    route: ObligationRoute,
    *,
    disposition: str,
    evidence: tuple[str, ...],
    diagnostics: list[ConsiderationDiagnostic],
    **fields: Any,
) -> ObligationAccountingRow:
    """Build a route-backed row while keeping common fields identical."""
    return ObligationAccountingRow(
        obligation_id=row.obligation_id,
        disposition=disposition,
        slot_ids=route.slot_ids,
        route_refs=(route.route_id,),
        evidence=evidence,
        diagnostics=tuple(diagnostics),
        **fields,
    )


def _account_proposed_not_applicable(
    row: Any,
    route: ObligationRoute,
    pairs: tuple[ObligationIcaConsideration, ...],
    evidence: tuple[str, ...],
    diagnostics: list[ConsiderationDiagnostic],
) -> ObligationAccountingRow:
    """Retain proposed N/A only when every routed slot has evidence."""
    if not pairs or any(
        item.disposition != "proposed_not_applicable" for item in pairs
    ):
        diagnostics.append(
            ConsiderationDiagnostic(
                code="incomplete_non_applicability",
                detail="every routed slot must have explicit structural N/A evidence",
                obligation_ids=(row.obligation_id,),
                refs=(route.route_id,),
            )
        )
        return _account_route_row(
            row,
            route,
            disposition="unresolved",
            evidence=evidence,
            diagnostics=diagnostics,
        )
    return _account_route_row(
        row,
        route,
        disposition="proposed_not_applicable",
        evidence=evidence,
        diagnostics=diagnostics,
    )


def _account_unresolved_ica(
    row: Any,
    route: ObligationRoute,
    evidence: tuple[str, ...],
    diagnostics: list[ConsiderationDiagnostic],
) -> ObligationAccountingRow:
    """Retain unresolved routed slots as unresolved accounting."""
    diagnostics.append(
        ConsiderationDiagnostic(
            code="unresolved_ica_consideration",
            detail="at least one routed slot remains analytically unresolved",
            obligation_ids=(row.obligation_id,),
            refs=(route.route_id,),
        )
    )
    return _account_route_row(
        row,
        route,
        disposition="unresolved",
        evidence=evidence or ("route:targeted",),
        diagnostics=diagnostics,
    )


def _account_missing_ica(
    row: Any,
    route: ObligationRoute,
    evidence: tuple[str, ...],
    diagnostics: list[ConsiderationDiagnostic],
) -> ObligationAccountingRow:
    """Retain a targeted route with no exact finding as unresolved."""
    diagnostics.append(
        ConsiderationDiagnostic(
            code="missing_ica_consideration",
            detail="targeted route lacks an exact ICA finding",
            obligation_ids=(row.obligation_id,),
            refs=(route.route_id,),
        )
    )
    return _account_route_row(
        row,
        route,
        disposition="unresolved",
        evidence=evidence or ("route:targeted",),
        diagnostics=diagnostics,
    )


def _account_findings(
    row: Any,
    route: ObligationRoute,
    findings: tuple[ObligationIcaConsideration, ...],
    evidence: tuple[str, ...],
    diagnostics: list[ConsiderationDiagnostic],
) -> ObligationAccountingRow:
    """Build an addressed row from exact finding pairs."""
    return _account_route_row(
        row,
        route,
        disposition="addressed",
        evidence=evidence,
        diagnostics=diagnostics,
        ica_ids=tuple(ica_id for item in findings for ica_id in item.ica_ids),
        exec_candidate_ids=tuple(
            candidate_id
            for item in findings
            for candidate_id in item.exec_candidate_ids
        ),
        hazard_ids=tuple(
            hazard_id for item in findings for hazard_id in item.hazard_ids
        ),
        constraint_ids=tuple(
            constraint_id for item in findings for constraint_id in item.constraint_ids
        ),
    )


def _account_applicable(
    row: Any,
    route: ObligationRoute,
    pairs: tuple[ObligationIcaConsideration, ...],
) -> ObligationAccountingRow:
    """Derive one accounting row for an applicable obligation."""
    evidence = _account_evidence(route, pairs)
    diagnostics: list[ConsiderationDiagnostic] = [*route.diagnostics]
    if route.disposition in {"upstream_gap", "unresolved"}:
        return _account_route_row(
            row,
            route,
            disposition=route.disposition,
            evidence=evidence,
            diagnostics=diagnostics,
        )
    if route.disposition == "proposed_not_applicable":
        return _account_proposed_not_applicable(
            row, route, pairs, evidence, diagnostics
        )
    if any(item.disposition == "unresolved" for item in pairs):
        return _account_unresolved_ica(row, route, evidence, diagnostics)
    findings = tuple(item for item in pairs if item.disposition == "finding")
    if not findings:
        return _account_missing_ica(row, route, evidence, diagnostics)
    return _account_findings(row, route, findings, evidence, diagnostics)


def _validate_accounting_pairs(
    plan: TaxonomyObligationPlan,
    consideration: ObligationConsideration,
    pairs: tuple[ObligationIcaConsideration, ...],
) -> dict[str, ObligationRoute]:
    """Validate exact pair identities against the final route universe."""
    if any(not isinstance(item, ObligationIcaConsideration) for item in pairs):
        raise TypeError(
            "ica_considerations must contain only ObligationIcaConsideration values"
        )
    pair_keys = tuple((item.obligation_id, item.slot_id) for item in pairs)
    if len(pair_keys) != len(set(pair_keys)):
        raise ValueError("ICA considerations must contain unique obligation/slot pairs")
    routes = {route.obligation_id: route for route in consideration.final_routes}
    for pair in pairs:
        route = routes.get(pair.obligation_id)
        if route is None or pair.route_id != route.route_id:
            raise ValueError("ICA consideration does not resolve to its final route")
        if pair.slot_id not in route.slot_ids:
            raise ValueError("ICA consideration names a slot outside its final route")
    return routes


def _accounting_row_for(
    obligation: Any,
    routes: dict[str, ObligationRoute],
    pairs: tuple[ObligationIcaConsideration, ...],
) -> ObligationAccountingRow:
    """Derive one row while retaining every Phase 1 scope disposition."""
    if obligation.scope_disposition == "capability_excluded":
        return ObligationAccountingRow(
            obligation_id=obligation.obligation_id,
            disposition="capability_excluded",
            evidence=_phase1_evidence(obligation),
        )
    if obligation.scope_disposition == "governance_only":
        return ObligationAccountingRow(
            obligation_id=obligation.obligation_id,
            disposition="governance_only",
            evidence=_phase1_evidence(obligation),
        )
    route = routes.get(obligation.obligation_id)
    if route is None:
        return ObligationAccountingRow(
            obligation_id=obligation.obligation_id,
            disposition="unresolved",
            evidence=("consideration:missing-final-route",),
            diagnostics=(
                ConsiderationDiagnostic(
                    code="missing_final_route",
                    detail="applicable obligation has no final structural route",
                    obligation_ids=(obligation.obligation_id,),
                ),
            ),
        )
    return _account_applicable(
        obligation,
        route,
        _pair_results_for(pairs, obligation.obligation_id),
    )


def _accounting_rows(
    plan: TaxonomyObligationPlan,
    routes: dict[str, ObligationRoute],
    pairs: tuple[ObligationIcaConsideration, ...],
) -> tuple[ObligationAccountingRow, ...]:
    """Derive exactly one accounting row per Phase 1 obligation."""
    return tuple(
        _accounting_row_for(obligation, routes, pairs)
        for obligation in plan.obligations
    )


def _accounting_summary(rows: tuple[ObligationAccountingRow, ...]) -> dict[str, int]:
    """Derive all provisional counts from rows, never from caller input."""
    return {
        "total": len(rows),
        "addressed": sum(row.disposition == "addressed" for row in rows),
        "proposed_not_applicable": sum(
            row.disposition == "proposed_not_applicable" for row in rows
        ),
        "unresolved": sum(row.disposition == "unresolved" for row in rows),
        "upstream_gap": sum(row.disposition == "upstream_gap" for row in rows),
        "capability_excluded": sum(
            row.disposition == "capability_excluded" for row in rows
        ),
        "governance_only": sum(row.disposition == "governance_only" for row in rows),
    }


def _validated_accounting_pins(
    source_pins: Iterable[Any],
    plan: TaxonomyObligationPlan,
) -> tuple[Any, ...]:
    """Validate source authorities and pin them to the exact Phase 1 plan."""
    pins = validate_obligation_accounting_source_pins(source_pins)
    plan_pin = next(
        item for item in pins if item.artifact_id == "taxonomy-obligation-plan"
    )
    if plan_pin.semantic_digest != plan.semantic_digest:
        raise ValueError("source_pins contain a substituted Phase 1 plan pin")
    return pins


def build_obligation_accounting(
    *,
    plan: TaxonomyObligationPlan,
    consideration: ObligationConsideration,
    ica_considerations: Iterable[ObligationIcaConsideration] = (),
    source_pins: Iterable[Any] = (),
) -> ObligationAccounting:
    """Derive one provisional row per Phase 1 obligation.

    This function never accepts caller-supplied summary counts and never
    emits a correspondence or coverage disposition.
    """
    plan = _require_plan(plan)
    if not isinstance(consideration, ObligationConsideration):
        raise TypeError("consideration must be an ObligationConsideration")
    consideration.assert_integrity()
    if any(brief.plan_digest != plan.semantic_digest for brief in consideration.briefs):
        raise ValueError("consideration briefs do not use the supplied Phase 1 plan")
    pairs = tuple(ica_considerations)
    routes = _validate_accounting_pairs(plan, consideration, pairs)
    rows = _accounting_rows(plan, routes, pairs)
    pins = _validated_accounting_pins(source_pins, plan)
    return ObligationAccounting(
        source_pins=pins,
        rows=rows,
        summary=_accounting_summary(rows),
    )


derive_obligation_accounting = build_obligation_accounting


__all__ = [
    "batch_neutral_obligation_briefs",
    "build_consideration_artifact",
    "build_neutral_briefs",
    "build_neutral_obligation_briefs",
    "build_obligation_accounting",
    "create_obligation_batches",
    "derive_obligation_accounting",
    "validate_obligation_routes",
    "validate_routes",
]
