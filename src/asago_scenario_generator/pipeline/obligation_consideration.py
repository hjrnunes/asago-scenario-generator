"""Pure deterministic builders and validators for STPA consideration.

This module is the inward seam used by synthesis orchestration.  It accepts
only validated Phase 1 and attack-pattern models, performs no provider or
filesystem work, and leaves structural/STPA authority with the caller's
typed adapters.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from asago_scenario_generator.models.obligation_accounting import (
    GOVERNANCE_ROUTED_NO_FINDING,
    OUT_OF_SCOPE,
    RISK_OUT_OF_SCOPE,
    SCOPE_EXEMPT_DISPOSITIONS,
    ObligationAccounting,
    ObligationAccountingRow,
    validate_obligation_accounting_source_pins,
)
from asago_scenario_generator.models.obligation_consideration import (
    ROUTING_RECORD_VALIDATION_FAILED,
    ROUTING_VALIDATION_FAILED,
    SLOT_PROMPT_BUDGET_EXCEEDED,
    SLOT_PROVIDER_CONTRACT_FAILED,
    BoundedStructuralRevision,
    ConsiderationDiagnostic,
    NeutralObligationBrief,
    ObligationConsideration,
    ObligationIcaConsideration,
    ObligationRoute,
)
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.models.slot_hazard_offer import SlotHazardOfferReport
from asago_scenario_generator.pipeline.scenario_realization import (
    account_generation_failures,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from asago_scenario_generator.stpa.obligation_aware.briefs import (
    build_neutral_briefs,
    create_obligation_batches as _chunk_briefs,
    require_batch_size,
)


def _require_plan(value: Any) -> TaxonomyObligationPlan:
    """Require the exact closed Phase 1 plan model at the boundary."""
    if not isinstance(value, TaxonomyObligationPlan):
        raise TypeError("plan must be a TaxonomyObligationPlan")
    value.assert_integrity()
    return value


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


GOVERNANCE_BRIEF_INSTRUCTION = (
    "Treat this governance risk as a hypothesis for structural STPA analysis. "
    "No attack pattern covers it, and it is not a mandatory mechanism, ordered "
    "attack sequence, or coverage claim. Identify the unsafe control actions "
    "through which the risk could come about in this system, or report that no "
    "control action bears on it."
)


def build_governance_briefs(
    plan: TaxonomyObligationPlan,
    risk_ids: Iterable[str],
) -> tuple[NeutralObligationBrief, ...]:
    """Build one pattern-free brief for each named governance-only risk.

    The caller decides which risks are worth routing; rows that resolved to a
    pattern or to a capability exclusion never produce a governance brief.
    """
    plan = _require_plan(plan)
    wanted = frozenset(risk_ids)
    briefs = [
        _governance_brief(plan, row)
        for row in plan.obligations
        if row.scope_disposition == "governance_only" and row.risk_ref.risk_id in wanted
    ]
    return tuple(sorted(briefs, key=lambda item: item.obligation_id))


def _governance_brief(plan: TaxonomyObligationPlan, row: Any) -> NeutralObligationBrief:
    """Build the brief for one governance-only row."""
    return NeutralObligationBrief(
        kind="governance",
        obligation_id=row.obligation_id,
        risk_ref=row.risk_ref,
        qualification_disposition=row.qualification_disposition,
        applicability_evidence=row.evidence,
        plan_digest=plan.semantic_digest,
        catalog_pins=plan.catalog_pins,
        mapping_pins=plan.mapping_pins,
        instruction=GOVERNANCE_BRIEF_INSTRUCTION,
    )


def out_of_scope_obligation_ids(
    plan: TaxonomyObligationPlan,
    risk_scopes: Mapping[str, str],
) -> frozenset[str]:
    """Return the applicable obligations whose risk scope is out of scope.

    These obligations are never sent to structural routing.  Governance-only
    and capability-excluded rows are not applicable and are never named.
    """
    plan = _require_plan(plan)
    return frozenset(
        row.obligation_id
        for row in plan.obligations
        if row.scope_disposition == "applicable"
        and risk_scopes.get(row.risk_ref.risk_id) in OUT_OF_SCOPE
    )


def batch_neutral_obligation_briefs(
    briefs: Iterable[NeutralObligationBrief],
    max_batch_size: int,
) -> tuple[tuple[NeutralObligationBrief, ...], ...]:
    """Partition briefs into fixed-size batches in ``obligation_order_key`` order.

    Each brief is checked first; the batches then follow risk and pattern, as
    ``create_obligation_batches`` orders every model-facing batch, not the
    obligation ID.
    """
    require_batch_size(max_batch_size)
    return _chunk_briefs(_typed_briefs(briefs), max_batch_size)


def validate_obligation_routes(
    briefs: Iterable[NeutralObligationBrief],
    routes: Iterable[ObligationRoute],
) -> tuple[ObligationRoute, ...]:
    """Require exactly one route result for each supplied applicable brief."""
    expected = _typed_briefs(briefs)
    ordered = _typed_routes(routes)
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


def _typed_routes(value: Iterable[ObligationRoute]) -> tuple[ObligationRoute, ...]:
    """Validate a route collection and order it by obligation identity."""
    if isinstance(value, (str, bytes, dict)):
        raise TypeError("routes must be an iterable of ObligationRoute values")
    try:
        values = tuple(value)
    except TypeError as exc:
        raise TypeError("routes must be an iterable of ObligationRoute values") from exc
    if any(not isinstance(item, ObligationRoute) for item in values):
        raise TypeError("routes must contain only ObligationRoute values")
    return tuple(sorted(values, key=lambda item: item.obligation_id))


def _plan_pin(plan: TaxonomyObligationPlan):
    """Build the exact plan pin required by both synthesis sidecars."""
    from asago_scenario_generator.models.artifact_pin import ArtifactPin

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
    return ObligationConsideration(
        source_pins=_consideration_pins(plan, source_pins),
        briefs=typed_briefs,
        initial_routes=typed_initial,
        revision=revision,
        rechecked_routes=typed_rechecked,
        final_routes=typed_final,
        diagnostics=tuple(diagnostics),
    )


def _consideration_pins(
    plan: TaxonomyObligationPlan, source_pins: Iterable[Any]
) -> tuple[Any, ...]:
    """Insert the Phase 1 plan pin when omitted; reject a substituted one."""
    from asago_scenario_generator.models.artifact_pin import ArtifactPin

    pins = tuple(source_pins)
    if any(not isinstance(item, ArtifactPin) for item in pins):
        raise TypeError("source_pins must contain only ArtifactPin values")
    plan_pins = tuple(
        item for item in pins if item.artifact_id == "taxonomy-obligation-plan"
    )
    if not plan_pins:
        return (_plan_pin(plan), *pins)
    if any(
        item.schema_version != "taxonomy-obligation-plan-v1"
        or item.semantic_digest != plan.semantic_digest
        for item in plan_pins
    ):
        raise ValueError("source_pins contain a substituted Phase 1 plan pin")
    return pins


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
    stop_reason: str,
    evidence: tuple[str, ...],
    diagnostics: list[ConsiderationDiagnostic],
    **fields: Any,
) -> ObligationAccountingRow:
    """Build a route-backed row while keeping common fields identical."""
    return ObligationAccountingRow(
        obligation_id=row.obligation_id,
        disposition=disposition,
        stop_reason=stop_reason,
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
            stop_reason="not_applicable_evidence_incomplete",
            evidence=evidence,
            diagnostics=diagnostics,
        )
    return _account_route_row(
        row,
        route,
        disposition="proposed_not_applicable",
        stop_reason="not_applicable_proven",
        evidence=evidence,
        diagnostics=diagnostics,
    )


_ICA_VERIFICATION_STOP_REASONS = (
    "ica_hazard_contradictory",
    "ica_hazard_insufficient_evidence",
    "ica_hazard_absence_evidence_missing",
    "ica_hazard_verification_provider_failure",
    "ica_hazard_correction_exhausted",
    "unsafe_outcome_lineage_incomplete",
)


# The pair code slot filling writes on a routed slot its request never had
# analyzed, and the stop reason it gives, in order of precedence.
_UNANALYZED_SLOT_STOPS = (
    (SLOT_PROMPT_BUDGET_EXCEEDED, "prompt_budget_exceeded"),
    (SLOT_PROVIDER_CONTRACT_FAILED, "provider_contract_failure"),
)


def _unanalyzed_stop_reason(
    pairs: tuple[ObligationIcaConsideration, ...],
) -> str | None:
    """Name the stop of a row whose every unresolved routed slot went unanalyzed.

    A slot whose request its prompt budget rejected, or whose request ended in
    a provider contract failure, was never analyzed. When another routed slot
    stayed analytically unresolved, that slot explains the stop whatever the
    unanalyzed slot would have held, and this returns ``None``. A budget
    rejection comes before a lost reply, as on a route.
    """
    unresolved = [item for item in pairs if item.disposition == "unresolved"]
    reasons: set[str] = set()
    for item in unresolved:
        codes = {diagnostic.code for diagnostic in item.diagnostics}
        reason = next(
            (reason for code, reason in _UNANALYZED_SLOT_STOPS if code in codes),
            None,
        )
        if reason is None:
            return None
        reasons.add(reason)
    return next(
        (reason for _, reason in _UNANALYZED_SLOT_STOPS if reason in reasons), None
    )


def _unresolved_ica_diagnostic(
    obligation_id: str, route_id: str
) -> ConsiderationDiagnostic:
    """Return the diagnostic of a row a slot left analytically unresolved."""
    return ConsiderationDiagnostic(
        code="unresolved_ica_consideration",
        detail="at least one routed slot remains analytically unresolved",
        obligation_ids=(obligation_id,),
        refs=(route_id,),
    )


def _account_unresolved_ica(
    row: Any,
    route: ObligationRoute,
    pairs: tuple[ObligationIcaConsideration, ...],
    evidence: tuple[str, ...],
    diagnostics: list[ConsiderationDiagnostic],
) -> ObligationAccountingRow:
    """Retain unresolved routed slots as unresolved accounting.

    A verification stop reason comes first. A row whose every unresolved slot
    went unanalyzed stops at that slot's reason: ``prompt_budget_exceeded``
    for a request its budget rejected, ``provider_contract_failure`` for a
    reply that broke its contract. Any other row stops at
    ``ica_consideration_unresolved``.
    """
    diagnostic_codes = {item.code for item in diagnostics}
    stop_reason = next(
        (code for code in _ICA_VERIFICATION_STOP_REASONS if code in diagnostic_codes),
        None,
    )
    unanalyzed = None if stop_reason is not None else _unanalyzed_stop_reason(pairs)
    if unanalyzed is not None:
        return _account_route_row(
            row,
            route,
            disposition="unresolved",
            stop_reason=unanalyzed,
            evidence=evidence or ("route:targeted",),
            diagnostics=diagnostics,
        )
    stop_reason = stop_reason or "ica_consideration_unresolved"
    diagnostics.append(_unresolved_ica_diagnostic(row.obligation_id, route.route_id))
    return _account_route_row(
        row,
        route,
        disposition="unresolved",
        stop_reason=stop_reason,
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
        stop_reason="ica_consideration_unresolved",
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
    """Build an addressed row from exact finding pairs.

    An ID that several findings cite appears once on the row.
    """
    return _account_route_row(
        row,
        route,
        disposition="addressed",
        stop_reason="addressed",
        evidence=evidence,
        diagnostics=diagnostics,
        ica_ids=_gather_unique(findings, "ica_ids"),
        exec_candidate_ids=_gather_unique(findings, "exec_candidate_ids"),
        hazard_ids=_gather_unique(findings, "hazard_ids"),
        constraint_ids=_gather_unique(findings, "constraint_ids"),
    )


RISK_PATTERN_MISMATCH = "risk_pattern_mismatch"
MECHANISM_ABSENT = "mechanism_absent"
MECHANISM_PATH_UNSUBSTANTIATED = "mechanism_path_unsubstantiated"
# The stop reasons the route's semantic assessment decides, in the order
# accounting applies them; the risk scope outranks all three.
SEMANTIC_STOP_REASONS = (
    RISK_PATTERN_MISMATCH,
    MECHANISM_ABSENT,
    MECHANISM_PATH_UNSUBSTANTIATED,
)


def _semantic_credit_stop(
    row: Any,
    route: ObligationRoute,
    evidence: tuple[str, ...],
    diagnostics: list[ConsiderationDiagnostic],
) -> ObligationAccountingRow | None:
    """Withhold obligation credit while preserving the ordinary STPA route.

    The row carries exactly one diagnostic of its stop reason and none of the
    semantic reasons it outranks or yields to. A route that already carries
    the stop's diagnostic, such as the mechanism verifier's, keeps its first
    copy and gains none.
    """
    assessment = route.semantic_assessment
    stop = _semantic_stop_detail(route.disposition, assessment)
    if stop is None:
        return None
    code, detail = stop
    return _account_route_row(
        row,
        route,
        disposition="unresolved",
        stop_reason=code,
        evidence=evidence or (f"route:{code.replace('_', '-')}",),
        diagnostics=_one_semantic_diagnostic(
            diagnostics,
            ConsiderationDiagnostic(
                code=code,
                detail=detail,
                obligation_ids=(row.obligation_id,),
                refs=(route.route_id,),
            ),
        ),
    )


def _one_semantic_diagnostic(
    diagnostics: list[ConsiderationDiagnostic], selected: ConsiderationDiagnostic
) -> list[ConsiderationDiagnostic]:
    """Keep the other diagnostics and one of *selected*'s code, the first held.

    A diagnostic of another semantic stop reason is dropped; *selected* is
    appended only when no diagnostic of its code is held.
    """
    result: list[ConsiderationDiagnostic] = []
    for item in diagnostics:
        if item.code == selected.code and all(
            kept.code != selected.code for kept in result
        ):
            result.append(item)
        elif item.code not in SEMANTIC_STOP_REASONS:
            result.append(item)
    if all(item.code != selected.code for item in result):
        result.append(selected)
    return result


def _semantic_stop_detail(disposition: str, assessment: Any) -> tuple[str, str] | None:
    """Classify the semantic reason that withholds obligation credit.

    Alignment comes before mechanism: a pair whose mechanism would not realize
    the risk stops at ``risk_pattern_mismatch`` whatever the mechanism
    judgement. A pair not judged misaligned (``supported`` or
    ``insufficient_evidence``) whose mechanism the system lacks stops at
    ``mechanism_absent``; a targeted route whose path does not establish the
    mechanism stops at ``mechanism_path_unsubstantiated``.
    """
    if assessment is None:
        return None
    if assessment.risk_alignment == "mismatch":
        return (
            RISK_PATTERN_MISMATCH,
            "the routed mechanism may support an ordinary STPA finding but does "
            "not realize the reviewed risk",
        )
    if assessment.mechanism_assessment == "absent_from_system":
        return (
            MECHANISM_ABSENT,
            "the attack pattern is not misaligned with the reviewed risk, but "
            "the system lacks the surface its mechanism needs",
        )
    if (
        disposition == "targeted"
        and assessment.mechanism_assessment != "plausible_in_system"
    ):
        return (
            MECHANISM_PATH_UNSUBSTANTIATED,
            "the ordinary STPA finding is retained, but the selected path does "
            "not establish the taxonomy mechanism",
        )
    return None


def _account_applicable(
    row: Any,
    route: ObligationRoute,
    pairs: tuple[ObligationIcaConsideration, ...],
) -> ObligationAccountingRow:
    """Derive one accounting row for an applicable obligation."""
    evidence = _account_evidence(route, pairs)
    diagnostics: list[ConsiderationDiagnostic] = [*route.diagnostics]
    diagnostics.extend(diagnostic for pair in pairs for diagnostic in pair.diagnostics)
    semantic_stop = _semantic_credit_stop(row, route, evidence, diagnostics)
    if semantic_stop is not None:
        return semantic_stop
    if route.disposition in {"upstream_gap", "unresolved"}:
        return _account_route_row(
            row,
            route,
            disposition=route.disposition,
            stop_reason=_route_stop_reason(route),
            evidence=evidence,
            diagnostics=diagnostics,
        )
    if route.disposition == "proposed_not_applicable":
        return _account_proposed_not_applicable(
            row, route, pairs, evidence, diagnostics
        )
    return _account_targeted(row, route, pairs, evidence, diagnostics)


def _account_targeted(
    row: Any,
    route: ObligationRoute,
    pairs: tuple[ObligationIcaConsideration, ...],
    evidence: tuple[str, ...],
    diagnostics: list[ConsiderationDiagnostic],
) -> ObligationAccountingRow:
    """Account a targeted route from its exact ICA pair results."""
    if any(item.disposition == "unresolved" for item in pairs):
        return _account_unresolved_ica(row, route, pairs, evidence, diagnostics)
    findings = tuple(item for item in pairs if item.disposition == "finding")
    if not findings:
        return _account_missing_ica(row, route, evidence, diagnostics)
    return _account_findings(row, route, findings, evidence, diagnostics)


def _governance_route_map(
    plan: TaxonomyObligationPlan,
    consideration: ObligationConsideration,
    governance_routes: tuple[ObligationRoute, ...],
) -> dict[str, ObligationRoute]:
    """Index governance routes, each for one governance-only plan row."""
    governance_ids = {
        row.obligation_id
        for row in plan.obligations
        if row.scope_disposition == "governance_only"
    }
    pattern_ids = {route.obligation_id for route in consideration.final_routes}
    result: dict[str, ObligationRoute] = {}
    for route in governance_routes:
        if route.obligation_id not in governance_ids:
            raise ValueError(
                f"governance route {route.obligation_id} is not a governance-only row"
            )
        if route.obligation_id in pattern_ids or route.obligation_id in result:
            raise ValueError(
                f"governance route {route.obligation_id} duplicates another final route"
            )
        result[route.obligation_id] = route
    return result


def _validate_accounting_pairs(
    plan: TaxonomyObligationPlan,
    consideration: ObligationConsideration,
    pairs: tuple[ObligationIcaConsideration, ...],
    governance_routes: tuple[ObligationRoute, ...] = (),
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
    routes.update(_governance_route_map(plan, consideration, governance_routes))
    for pair in pairs:
        route = routes.get(pair.obligation_id)
        if route is None or pair.route_id != route.route_id:
            raise ValueError("ICA consideration does not resolve to its final route")
        if pair.slot_id not in route.slot_ids:
            raise ValueError("ICA consideration names a slot outside its final route")
    return routes


def _account_governance(
    obligation: Any,
    route: ObligationRoute | None,
    pairs: tuple[ObligationIcaConsideration, ...],
) -> ObligationAccountingRow:
    """Credit a governance-only row whose every routed slot has a finding.

    The row keeps its governance-only disposition and carries the finding's
    identities; an ID that several findings cite appears once. A targeted
    route whose slots produced no finding is recorded on the row with its own
    stop reason. A row with no route, a declined route, or a mix of findings
    and other slot outcomes stays bare, as it was before governance rows were
    routed.
    """
    evidence = _phase1_evidence(obligation)
    findings = tuple(item for item in pairs if item.disposition == "finding")
    if route is not None and not findings and route.disposition == "targeted":
        return _account_governance_without_finding(obligation, route, pairs, evidence)
    if route is None or not _credits_governance(route, findings, pairs):
        return ObligationAccountingRow(
            obligation_id=obligation.obligation_id,
            disposition="governance_only",
            evidence=evidence,
        )
    return ObligationAccountingRow(
        obligation_id=obligation.obligation_id,
        disposition="governance_only",
        slot_ids=route.slot_ids,
        route_refs=(route.route_id,),
        ica_ids=_gather_unique(findings, "ica_ids"),
        exec_candidate_ids=_gather_unique(findings, "exec_candidate_ids"),
        hazard_ids=_gather_unique(findings, "hazard_ids"),
        constraint_ids=_gather_unique(findings, "constraint_ids"),
        evidence=(*evidence, *_account_evidence(route, findings)),
        diagnostics=_gather((route, *findings), "diagnostics"),
    )


def _account_governance_without_finding(
    obligation: Any,
    route: ObligationRoute,
    pairs: tuple[ObligationIcaConsideration, ...],
    evidence: tuple[str, ...],
) -> ObligationAccountingRow:
    """Record the route of a governance row whose routed slots found nothing.

    The row stops at ``governance_routed_no_finding`` whatever its slots
    held: not applicable, left unresolved on the analysis, or never analyzed
    because the prompt budget rejected the request or its reply broke its
    contract.  This is deliberate.  The unanalyzed-slot stop reasons belong
    to the applicable funnel, where a row's stop reason is its terminal
    reason; a governance-only row stays outside that funnel, keeps its own
    outcome whatever the risk scope, and has one uncredited outcome.  The
    synthesis manifest counts no governance-only row among the terminal
    reasons.  Each pair's diagnostic is copied onto the row, so a
    budget-rejected or lost slot stays named there.
    """
    return ObligationAccountingRow(
        obligation_id=obligation.obligation_id,
        disposition="governance_only",
        stop_reason=GOVERNANCE_ROUTED_NO_FINDING,
        slot_ids=route.slot_ids,
        route_refs=(route.route_id,),
        evidence=(*evidence, *_account_evidence(route, pairs)),
        diagnostics=_gather((route, *pairs), "diagnostics"),
    )


def _credits_governance(
    route: ObligationRoute,
    findings: tuple[ObligationIcaConsideration, ...],
    pairs: tuple[ObligationIcaConsideration, ...],
) -> bool:
    """Tell whether a targeted route has a finding and no other slot outcome."""
    return (
        route.disposition == "targeted"
        and bool(findings)
        and len(findings) == len(pairs)
    )


def _gather(items: Iterable[Any], field_name: str) -> tuple[Any, ...]:
    """Concatenate one tuple field across items, in order."""
    return tuple(value for item in items for value in getattr(item, field_name))


def _gather_unique(items: Iterable[Any], field_name: str) -> tuple[Any, ...]:
    """Gather one ID field across items, keeping each value once in first-seen order.

    One obligation has a finding for each routed slot, and two findings may cite
    the same hazard, constraint, ICA, or execution candidate. A repeat across
    findings is one citation; a repeat inside one finding is still rejected by
    the finding's own model.
    """
    return tuple(dict.fromkeys(_gather(items, field_name)))


def _accounting_row_for(
    obligation: Any,
    routes: dict[str, ObligationRoute],
    pairs: tuple[ObligationIcaConsideration, ...],
    scope: str | None = None,
) -> ObligationAccountingRow:
    """Derive one row while retaining every Phase 1 scope disposition.

    An applicable obligation without a final route whose risk ``scope`` is out
    of scope was withheld from routing; any other one lost its route.
    """
    if obligation.scope_disposition == "capability_excluded":
        return ObligationAccountingRow(
            obligation_id=obligation.obligation_id,
            disposition="capability_excluded",
            evidence=_phase1_evidence(obligation),
        )
    if obligation.scope_disposition == "governance_only":
        return _account_governance(
            obligation,
            routes.get(obligation.obligation_id),
            _pair_results_for(pairs, obligation.obligation_id),
        )
    route = routes.get(obligation.obligation_id)
    if route is None and scope in OUT_OF_SCOPE:
        return _account_withheld(obligation, scope)
    if route is None:
        return ObligationAccountingRow(
            obligation_id=obligation.obligation_id,
            disposition="unresolved",
            stop_reason="no_structural_route",
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


def _account_withheld(obligation: Any, scope: str) -> ObligationAccountingRow:
    """Record an applicable obligation that routing withheld for its scope."""
    return ObligationAccountingRow(
        obligation_id=obligation.obligation_id,
        disposition="unresolved",
        stop_reason=RISK_OUT_OF_SCOPE,
        scope=scope,
        evidence=_phase1_evidence(obligation),
        diagnostics=(
            ConsiderationDiagnostic(
                code=RISK_OUT_OF_SCOPE,
                detail=(
                    f"the risk's scope is {scope}, so the obligation was not "
                    "sent to structural routing"
                ),
                obligation_ids=(obligation.obligation_id,),
            ),
        ),
    )


def _route_stop_reason(route: ObligationRoute) -> str:
    """Explain why a routed obligation stopped before ICA resolution."""
    codes = {item.code for item in route.diagnostics}
    if "prompt_budget_exceeded" in codes:
        return "prompt_budget_exceeded"
    if codes & {ROUTING_VALIDATION_FAILED, ROUTING_RECORD_VALIDATION_FAILED}:
        return "provider_contract_failure"
    return "no_structural_route"


def _accounting_rows(
    plan: TaxonomyObligationPlan,
    routes: dict[str, ObligationRoute],
    pairs: tuple[ObligationIcaConsideration, ...],
    risk_scopes: Mapping[str, str],
) -> tuple[ObligationAccountingRow, ...]:
    """Derive exactly one accounting row per Phase 1 obligation."""
    return tuple(
        _accounting_row_for(
            obligation, routes, pairs, risk_scopes.get(obligation.risk_ref.risk_id)
        )
        for obligation in plan.obligations
    )


def _scoped_rows(
    plan: TaxonomyObligationPlan,
    rows: tuple[ObligationAccountingRow, ...],
    risk_scopes: Mapping[str, str],
) -> tuple[ObligationAccountingRow, ...]:
    """Record each row's risk scope; an out-of-scope scope sets the stop reason.

    A row whose risk class no action of this system can produce stops at
    ``risk_out_of_scope`` whatever stop reason it had, capability-excluded rows
    included, so ``risk_pattern_mismatch`` and the other reasons count in-scope
    misses only. Such a row keeps no diagnostic of the semantic reason it
    replaced. Addressed and governance-only rows keep their own outcome. A
    risk without a decision leaves its rows unchanged.
    """
    risk_of = {item.obligation_id: item.risk_ref.risk_id for item in plan.obligations}
    return tuple(
        _scoped_row(row, risk_scopes.get(risk_of[row.obligation_id])) for row in rows
    )


def _scoped_row(
    row: ObligationAccountingRow, scope: str | None
) -> ObligationAccountingRow:
    """Return *row* with *scope* recorded and its precedence applied."""
    if scope is None:
        return row
    values = {**row.model_dump(), "scope": scope}
    if scope in OUT_OF_SCOPE and row.disposition not in SCOPE_EXEMPT_DISPOSITIONS:
        values["stop_reason"] = RISK_OUT_OF_SCOPE
        values["diagnostics"] = tuple(
            item for item in row.diagnostics if item.code not in SEMANTIC_STOP_REASONS
        )
    return ObligationAccountingRow.model_validate(values)


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
        "generation_failed": sum(
            row.disposition == "generation_failed" for row in rows
        ),
        "governance_credited": sum(
            row.disposition == "governance_only" and bool(row.ica_ids) for row in rows
        ),
        "governance_routed_no_finding": sum(
            row.stop_reason == GOVERNANCE_ROUTED_NO_FINDING for row in rows
        ),
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
    ica_verification: Any | None = None,
    ica_enumeration: Any | None = None,
    governance_routes: Iterable[ObligationRoute] = (),
    hazard_offers: SlotHazardOfferReport | None = None,
    risk_scopes: Mapping[str, str] | None = None,
    scenario_specs: Iterable[ScenarioSpec] | None = None,
    functional_test_specs: Iterable[ScenarioSpec] = (),
) -> ObligationAccounting:
    """Derive one provisional row per Phase 1 obligation.

    This function never accepts caller-supplied summary counts and never
    emits a correspondence or coverage disposition. Governance routes are the
    final routes of governance-only rows; a row with a finding on each routed
    slot is credited without leaving the governance-only disposition.
    ``hazard_offers`` is the run's slot hazard offer report; accounting
    carries its summary. ``risk_scopes`` maps a risk ID to its Stage 1a scope
    decision; each row records the scope of its risk, and an applicable row
    of an out-of-scope risk without a final route was withheld from routing
    and stops at ``risk_out_of_scope``. ``scenario_specs`` and
    ``functional_test_specs`` are the run's written scenarios; when given, an
    addressed row that none of them carries becomes ``generation_failed``.
    Without them the rows stay provisional.
    """
    plan = _require_plan(plan)
    if not isinstance(consideration, ObligationConsideration):
        raise TypeError("consideration must be an ObligationConsideration")
    consideration.assert_integrity()
    if any(brief.plan_digest != plan.semantic_digest for brief in consideration.briefs):
        raise ValueError("consideration briefs do not use the supplied Phase 1 plan")
    pairs = tuple(ica_considerations)
    if ica_verification is not None:
        from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
            filter_ica_considerations,
        )

        pairs = filter_ica_considerations(
            pairs,
            ica_verification,
            enumeration=ica_enumeration,
        )
    routes = _validate_accounting_pairs(
        plan, consideration, pairs, tuple(governance_routes)
    )
    scopes = risk_scopes or {}
    rows = _scoped_rows(plan, _accounting_rows(plan, routes, pairs, scopes), scopes)
    pins = _validated_accounting_pins(source_pins, plan)
    accounting = ObligationAccounting(
        source_pins=pins,
        rows=rows,
        summary=_accounting_summary(rows),
        slot_hazard_offers=hazard_offers.summary if hazard_offers else None,
    )
    if scenario_specs is None:
        return accounting
    return account_generation_failures(
        accounting,
        scenario_specs=scenario_specs,
        functional_test_specs=functional_test_specs,
    )


__all__ = [
    "batch_neutral_obligation_briefs",
    "build_consideration_artifact",
    "build_governance_briefs",
    "build_neutral_briefs",
    "build_obligation_accounting",
    "out_of_scope_obligation_ids",
    "validate_obligation_routes",
]
