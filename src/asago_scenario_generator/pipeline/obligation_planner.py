"""Pure, deterministic Phase 1 taxonomy-obligation planning."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_plan import (
    CandidateRecord,
    EvidenceRecord,
    FactEvaluationEvidence,
    QualificationFactEvidence,
    RiskReference,
    TaxonomyChainEntry,
    TaxonomyObligation,
    TaxonomyObligationPlan,
    derive_obligation_summary,
)
from asago_scenario_generator.models.canonical import compute_framed_digest
import asago_scenario_generator.pipeline.obligation_contracts as _contracts
from asago_scenario_generator.pipeline.projection_authoritative import (
    project_authoritative_candidate_observations,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    CapabilityFactSnapshot,
    canonical_json_bytes,
    required_fact_references,
)
from asago_scenario_generator.pipeline.projection_qualification import (
    compute_authoritative_catalog_pin,
)


_OBLIGATION_ID_DOMAIN = "asago-scenario-generator:taxonomy-obligation:v1"


def _canonical_text(value: Any) -> str:
    """Return repository-canonical JSON for deterministic evidence text."""
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return canonical_json_bytes(value).decode("utf-8")


@dataclass(frozen=True)
class _MappingEdge:
    """One deterministic graph edge used only during planning."""

    source_id: str
    target_id: str
    relation: str
    evidence: tuple[str, ...]
    source: str


def _require_catalog(patterns: tuple[AttackPattern, ...]) -> tuple[AttackPattern, ...]:
    """Require a nonempty authoritative catalog for resolver construction."""
    if not patterns:
        raise ValueError("a catalog resolver requires at least one pattern")
    return patterns


def _shared_taxonomy_context(patterns: tuple[AttackPattern, ...]) -> Any:
    """Return the one taxonomy context shared by all catalog patterns."""
    contexts = {
        _canonical_text(pattern.canonical_chain.taxonomy_context)
        for pattern in patterns
    }
    if len(contexts) != 1:
        raise ValueError(
            "all authoritative attack patterns must share one taxonomy context"
        )
    return patterns[0].canonical_chain.taxonomy_context


def _pattern_mappings(pattern: AttackPattern) -> tuple[Any, ...]:
    """Flatten chain- and step-level mapping decisions for one pattern."""
    chain = pattern.canonical_chain
    return tuple(chain.mappings) + tuple(
        mapping for step in chain.steps for mapping in step.mappings
    )


def _catalog_identifiers(
    patterns: tuple[AttackPattern, ...],
) -> dict[str, set[str]]:
    """Index every typed catalog identifier by taxonomy."""
    identifiers: dict[str, set[str]] = {}
    for pattern in patterns:
        for mapping in _pattern_mappings(pattern):
            identifiers.setdefault(str(mapping.taxonomy), set()).update(
                str(identifier) for identifier in getattr(mapping, "ids", ())
            )
    return identifiers


class _CatalogResolver:
    """No-I/O resolver assembled from the already typed catalog entries."""

    def __init__(self, patterns: tuple[AttackPattern, ...]) -> None:
        catalog = _require_catalog(patterns)
        self._taxonomy_context = _shared_taxonomy_context(catalog)
        self._identifiers = _catalog_identifiers(catalog)

    @property
    def taxonomy_context(self) -> Any:
        """Expose the context required by the existing qualification boundary."""
        return self._taxonomy_context

    def contains(self, taxonomy: str, identifier: str) -> bool:
        """Resolve only identifiers present in the typed authoritative catalog."""
        return identifier in self._identifiers.get(str(taxonomy), set())


def _chain_entries(pattern: AttackPattern) -> tuple[TaxonomyChainEntry, ...]:
    """Extract the ordered, duplicate-free taxonomy chain from a pattern."""
    entries: list[TaxonomyChainEntry] = []
    seen: set[tuple[str, str]] = set()
    chain = pattern.canonical_chain
    mappings = [*chain.mappings]
    mappings.extend(mapping for step in chain.steps for mapping in step.mappings)
    for mapping in mappings:
        taxonomy = str(mapping.taxonomy)
        for identifier in getattr(mapping, "ids", ()):
            key = (taxonomy, str(identifier))
            if key not in seen:
                seen.add(key)
                entries.append(TaxonomyChainEntry(taxonomy=key[0], id=key[1]))
    return tuple(entries)


def _snapshot_digest(snapshot: CapabilityFactSnapshot) -> str:
    """Verify and return the authoritative capability/fact snapshot digest."""
    snapshot.assert_integrity()
    return snapshot.snapshot_digest


def _pattern_lookup(
    catalog: tuple[AttackPattern, ...],
) -> dict[str, AttackPattern]:
    """Index typed catalog entries by attack-pattern identity."""
    return {item.id: item for item in catalog}


def _mapping_edges(
    inputs: _contracts.TaxonomyObligationInputs,
) -> tuple[_MappingEdge, ...]:
    """Convert cross-taxonomy and SSSOM rows into one sorted graph edge set."""
    edges = [
        _MappingEdge(
            source_id=item.source_id,
            target_id=item.target_id,
            relation=item.relation,
            evidence=tuple(sorted(item.evidence)),
            source="cross-taxonomy",
        )
        for item in inputs.cross_taxonomy_mappings
    ]
    edges.extend(
        _MappingEdge(
            source_id=item.subject_id,
            target_id=item.object_id,
            relation=item.predicate_id,
            evidence=(item.mapping_justification,),
            source="sssom",
        )
        for item in inputs.sssom_mappings
    )
    unique: dict[tuple[Any, ...], _MappingEdge] = {}
    for edge in edges:
        key = (
            edge.source_id,
            edge.target_id,
            edge.relation,
            edge.evidence,
            edge.source,
        )
        unique[key] = edge
    return tuple(
        sorted(
            unique.values(),
            key=lambda edge: (
                edge.source_id,
                edge.target_id,
                edge.relation,
                edge.source,
                edge.evidence,
            ),
        )
    )


def _mapping_adjacency(
    edges: tuple[_MappingEdge, ...],
) -> dict[str, list[_MappingEdge]]:
    """Build sorted adjacency lists for all reviewed mapping edges."""
    adjacency: dict[str, list[_MappingEdge]] = {}
    for edge in edges:
        adjacency.setdefault(edge.source_id, []).append(edge)
    for values in adjacency.values():
        values.sort(
            key=lambda edge: (
                edge.target_id,
                edge.relation,
                edge.source,
                edge.evidence,
            )
        )
    return adjacency


def _visit_mapping_paths(
    node: str,
    pattern_ids: set[str],
    adjacency: dict[str, list[_MappingEdge]],
    visited: frozenset[str],
    path: tuple[_MappingEdge, ...],
    found: dict[str, set[tuple[_MappingEdge, ...]]],
) -> None:
    """Collect every simple path reaching a catalog pattern."""
    if node in pattern_ids:
        found.setdefault(node, set()).add(path)
        return
    for edge in adjacency.get(node, ()):
        if edge.target_id in visited:
            continue
        _visit_mapping_paths(
            edge.target_id,
            pattern_ids,
            adjacency,
            visited | {edge.target_id},
            path + (edge,),
            found,
        )


def _sorted_mapping_paths(
    found: dict[str, set[tuple[_MappingEdge, ...]]],
) -> dict[str, tuple[tuple[_MappingEdge, ...], ...]]:
    """Return collected paths in canonical pattern/path order."""
    return {
        pattern_id: tuple(
            sorted(
                paths,
                key=lambda path: tuple(
                    (item.source_id, item.target_id, item.relation, item.source)
                    for item in path
                ),
            )
        )
        for pattern_id, paths in sorted(found.items())
    }


def _mapping_paths(
    risk_id: str,
    pattern_ids: set[str],
    edges: tuple[_MappingEdge, ...],
) -> dict[str, tuple[tuple[_MappingEdge, ...], ...]]:
    """Traverse every simple path from a risk to each catalog pattern."""
    adjacency = _mapping_adjacency(edges)
    found: dict[str, set[tuple[_MappingEdge, ...]]] = {}
    if risk_id in pattern_ids:
        found[risk_id] = {()}
    else:
        _visit_mapping_paths(
            risk_id,
            pattern_ids,
            adjacency,
            frozenset({risk_id}),
            (),
            found,
        )
    return _sorted_mapping_paths(found)


def _path_evidence(
    paths: tuple[tuple[_MappingEdge, ...], ...],
) -> tuple[EvidenceRecord, ...]:
    """Retain every distinct mapping path as deterministic evidence."""
    records: list[EvidenceRecord] = []
    for path in paths:
        records.append(
            EvidenceRecord(
                kind="mapping",
                source=path[-1].source if path else "direct-catalog-identity",
                detail=_canonical_text(
                    {
                        "path": [
                            {
                                "source_id": edge.source_id,
                                "target_id": edge.target_id,
                                "relation": edge.relation,
                                "source": edge.source,
                                "evidence": list(edge.evidence),
                            }
                            for edge in path
                        ]
                    }
                ),
            )
        )
    return tuple(records)


def _risk_reference(card: Any) -> RiskReference:
    """Convert a typed input risk card into immutable persisted provenance."""
    return RiskReference.model_validate(card.model_dump(mode="json"))


def _identity_digest(
    risk_id: str,
    pattern: AttackPattern | None,
    inputs: _contracts.TaxonomyObligationInputs,
) -> str:
    """Derive the version-framed identity for one risk-pattern obligation."""
    payload = {
        "risk_id": risk_id,
        "attack_pattern_id": pattern.id if pattern else None,
        "attack_pattern_semantic_digest": (
            pattern.canonical_chain.semantic_digest if pattern else None
        ),
        "capability_snapshot_digest": _snapshot_digest(inputs.capability_snapshot),
        "catalog_pins": {
            key: value.model_dump(mode="json")
            for key, value in sorted(inputs.catalog_pins.items())
        },
        "mapping_pins": {
            key: value.model_dump(mode="json")
            for key, value in sorted(inputs.mapping_pins.items())
        },
    }
    return "ob:v1:" + compute_framed_digest(_OBLIGATION_ID_DOMAIN, payload)


def _pattern_fact_keys(pattern: AttackPattern) -> frozenset[str]:
    """Return canonical fact references required by one authoritative pattern."""
    return frozenset(
        canonical_json_bytes(reference.model_dump(mode="json")).decode("utf-8")
        for reference in required_fact_references((pattern,))
    )


def _qualification_facts_state(
    pattern: AttackPattern,
    facts: _contracts.QualificationFactsInput,
) -> Literal["complete", "missing", "contradictory"]:
    """Classify required readings with contradictory status taking precedence."""
    statuses = {
        getattr(facts.facts.get(key), "status", "absent")
        for key in _pattern_fact_keys(pattern)
    }
    if "contradictory" in statuses:
        return "contradictory"
    if statuses - {"present"}:
        return "missing"
    return "complete"


def _issue_evidence(issue: Any) -> EvidenceRecord:
    """Convert one authoritative projection issue to typed evidence."""
    return EvidenceRecord(
        kind="projection",
        source=issue.code,
        detail=issue.detail,
        fact_evaluations=tuple(
            _condition_fact_evaluation(result, rationale=issue.detail)
            for result in issue.condition_results
        )
        + tuple(
            _precondition_fact_evaluation(result, rationale=issue.detail)
            for result in issue.precondition_results
        ),
    )


def _limitation_evidence(limitation: Any) -> EvidenceRecord:
    """Convert one bounded projection limitation to typed evidence."""
    return EvidenceRecord(
        kind="projection",
        source=limitation.code,
        detail=(
            f"emitted {limitation.emitted_bindings} of "
            f"{limitation.total_compatible_bindings} compatible bindings"
        ),
    )


def _projection_issue_evidence(
    batch: Any, pattern_id: str
) -> tuple[EvidenceRecord, ...]:
    """Return issue evidence for one pattern in stable source order."""
    return tuple(
        _issue_evidence(issue)
        for issue in batch.infeasibilities
        if issue.pattern_id == pattern_id
    )


def _projection_limitation_evidence(
    batch: Any, pattern_id: str
) -> tuple[EvidenceRecord, ...]:
    """Return bounded limitation evidence for one pattern."""
    return tuple(
        _limitation_evidence(limitation)
        for limitation in batch.limitations
        if limitation.pattern_id == pattern_id
    )


def _projection_evidence(batch: Any, pattern_id: str) -> tuple[EvidenceRecord, ...]:
    """Convert authoritative projection outcomes into bounded plan evidence."""
    return _projection_issue_evidence(
        batch, pattern_id
    ) + _projection_limitation_evidence(batch, pattern_id)


_PROJECTION_QUALIFICATION_PRIORITY = {
    "incompatible_profile": 0,
    "unresolved_condition": 1,
    "unresolved_precondition": 1,
    "precondition_not_satisfied": 2,
    "unsupported_requirement_derivation": 3,
    "missing_compatible_resource": 3,
    "source_influence_relation_infeasible": 3,
    "inapplicable_projection": 3,
}
_PROJECTION_QUALIFICATION_OUTCOMES = {
    "incompatible_profile": (
        "capability_excluded",
        "profile is incompatible with prerequisites",
    ),
    "unresolved_condition": (
        "missing_evidence",
        "authoritative qualification fact is unresolved",
    ),
    "unresolved_precondition": (
        "missing_evidence",
        "authoritative qualification fact is unresolved",
    ),
    "precondition_not_satisfied": (
        "contradictory_evidence",
        "authoritative precondition is not satisfied",
    ),
    "unsupported_requirement_derivation": (
        "structurally_infeasible",
        "authoritative projection is infeasible",
    ),
    "missing_compatible_resource": (
        "structurally_infeasible",
        "authoritative projection is infeasible",
    ),
    "source_influence_relation_infeasible": (
        "structurally_infeasible",
        "authoritative projection is infeasible",
    ),
    "inapplicable_projection": (
        "structurally_infeasible",
        "authoritative projection is infeasible",
    ),
}
_QUALIFICATION_FACT_OUTCOMES = {
    "missing": ("missing_evidence", "authoritative qualification fact is absent"),
    "contradictory": (
        "contradictory_evidence",
        "authoritative qualification fact is contradictory",
    ),
}


def _qualification_from_codes(
    codes: set[str], has_limitation: bool
) -> tuple[str, str | None]:
    """Select a typed outcome from projection issue codes by precedence."""
    selected = min(
        filter(_PROJECTION_QUALIFICATION_PRIORITY.__contains__, codes),
        key=_PROJECTION_QUALIFICATION_PRIORITY.__getitem__,
        default=None,
    )
    fallback = (
        ("ready", None)
        if has_limitation
        else ("structurally_infeasible", "no projectable candidate was produced")
    )
    return _PROJECTION_QUALIFICATION_OUTCOMES.get(selected, fallback)


def _projection_issue_codes(batch: Any, pattern_id: str) -> set[str]:
    """Collect projection issue codes for one pattern."""
    return {
        item.code for item in batch.infeasibilities if item.pattern_id == pattern_id
    }


def _has_projection_limitation(batch: Any, pattern_id: str) -> bool:
    """Report whether bounded projection retained a limitation for a pattern."""
    return any(item.pattern_id == pattern_id for item in batch.limitations)


def _qualification_without_candidates(
    batch: Any, pattern_id: str
) -> tuple[str, str | None]:
    """Classify a pattern when projection emitted no candidate records."""
    if batch is None:
        return "ready", None
    return _qualification_from_codes(
        _projection_issue_codes(batch, pattern_id),
        _has_projection_limitation(batch, pattern_id),
    )


def _qualification_from_projection(
    batch: Any,
    pattern_id: str,
    has_candidates: bool,
    qualification_facts_state: Literal["complete", "missing", "contradictory"],
) -> tuple[str, str | None]:
    """Translate gates, giving capability exclusion precedence over fact gaps."""
    if not has_candidates:
        without_candidates = _qualification_without_candidates(batch, pattern_id)
        if without_candidates[0] == "capability_excluded":
            return without_candidates
    fact_outcome = _QUALIFICATION_FACT_OUTCOMES.get(qualification_facts_state)
    if fact_outcome:
        return fact_outcome
    if has_candidates:
        return "ready", None
    return _qualification_without_candidates(batch, pattern_id)


def _catalog_records(
    inputs: _contracts.TaxonomyObligationInputs,
) -> list[dict[str, Any]]:
    """Serialize the validated catalog for the projection seam."""
    return [
        pattern.model_dump(mode="json") for pattern in inputs.attack_pattern_catalog
    ]


def _verify_catalog_pin(
    records: list[dict[str, Any]],
    resolver: _CatalogResolver,
    pins: dict[str, Any],
) -> None:
    """Require the computed catalog content to be one declared pin."""
    computed = compute_authoritative_catalog_pin(records, resolver)
    if computed not in {pin.digest for pin in pins.values()}:
        raise ValueError(
            "authoritative attack-pattern catalog does not match catalog pin"
        )


def _group_candidates_by_pattern(
    candidates: tuple[Any, ...],
) -> dict[str, tuple[Any, ...]]:
    """Group authoritative projection candidates by pattern identity."""
    grouped: dict[str, list[Any]] = {}
    for candidate in candidates:
        grouped.setdefault(candidate.pattern_id, []).append(candidate)
    return {key: tuple(value) for key, value in grouped.items()}


def _build_projection_batch(
    inputs: _contracts.TaxonomyObligationInputs,
) -> tuple[
    Any,
    dict[str, tuple[Any, ...]],
    frozenset[str],
    dict[str, Any],
    dict[str, tuple[Any, ...]],
]:
    """Observe one bounded authoritative run and group every derived identity."""
    records = _catalog_records(inputs)
    if not records:
        return None, {}, frozenset(), {}, {}
    resolver = _CatalogResolver(inputs.attack_pattern_catalog)
    _verify_catalog_pin(records, resolver, inputs.catalog_pins)
    observation = project_authoritative_candidate_observations(
        records,
        resolver,
        inputs.capability_snapshot,
        budget=inputs.projection_budget,
    )
    all_candidates = observation.batch.candidates + observation.deferred_candidates
    deferred_ids = frozenset(
        candidate.candidate_id for candidate in observation.deferred_candidates
    )
    return (
        observation.batch,
        _group_candidates_by_pattern(all_candidates),
        deferred_ids,
        {trace.pattern_id: trace for trace in observation.qualification_traces},
        _group_candidates_by_pattern(observation.rejected_candidates),
    )


def _candidate_records(
    candidates: tuple[Any, ...], deferred_ids: frozenset[str]
) -> tuple[CandidateRecord, ...]:
    """Persist only concrete projected identities, bindings, and budget outcomes."""
    return tuple(
        CandidateRecord(
            candidate_id=candidate.candidate_id,
            canonical_ingress=candidate.canonical_ingress,
            resource_bindings=tuple(candidate.projection.bindings),
            projection_disposition=(
                "budget_deferred"
                if candidate.candidate_id in deferred_ids
                else "projectable"
            ),
            reason=(
                "authoritative candidate exceeded the projection candidate budget"
                if candidate.candidate_id in deferred_ids
                else ""
            ),
        )
        for candidate in candidates
    )


def _rejected_candidate_records(
    candidates: tuple[Any, ...],
) -> tuple[CandidateRecord, ...]:
    """Persist projection rejects with their deterministic typed evidence."""
    return tuple(
        CandidateRecord(
            candidate_id=candidate.candidate_id,
            canonical_ingress=candidate.canonical_ingress,
            resource_bindings=candidate.resource_bindings,
            projection_disposition="projection_infeasible",
            reason=candidate.reason,
            evidence=(_issue_evidence(candidate.issue),),
        )
        for candidate in candidates
    )


def _pattern_disposition(
    pattern: AttackPattern,
    inputs: _contracts.TaxonomyObligationInputs,
    batch: Any,
    candidates: tuple[Any, ...],
    deferred_ids: frozenset[str],
    rejected_candidates: tuple[Any, ...],
) -> tuple[str, str, tuple[CandidateRecord, ...], str | None]:
    """Resolve scope, qualification, and candidate children for a pattern."""
    qualification, reason = _qualification_from_projection(
        batch,
        pattern.id,
        bool(candidates),
        _qualification_facts_state(pattern, inputs.qualification_facts),
    )
    if qualification == "capability_excluded":
        return "capability_excluded", "not_attempted", (), reason
    records = (
        _candidate_records(candidates, deferred_ids)
        + _rejected_candidate_records(rejected_candidates)
        if qualification in {"ready", "structurally_infeasible"}
        else ()
    )
    return "applicable", qualification, records, reason


def _qualification_evidence(reason: str | None) -> tuple[EvidenceRecord, ...]:
    """Return one typed qualification record when a reason was derived."""
    if reason is None:
        return ()
    return (
        EvidenceRecord(
            kind="qualification",
            source="authoritative-projection",
            detail=reason,
        ),
    )


def _condition_fact_evaluation(
    result: Any,
    *,
    rationale: str = "authoritative condition evaluation",
) -> FactEvaluationEvidence:
    """Persist one authoritative step-condition result with its typed fact readings."""
    return FactEvaluationEvidence(
        evaluation_type="condition",
        step_id=result.condition_step_id,
        result=result.result,
        facts=result.evidence,
        rationale=rationale,
    )


def _precondition_fact_evaluation(
    result: Any,
    *,
    rationale: str = "authoritative precondition evaluation",
) -> FactEvaluationEvidence:
    """Persist one selected-step precondition result with its fact readings."""
    return FactEvaluationEvidence(
        evaluation_type="precondition",
        step_id=result.step_id,
        condition_id=result.condition_id,
        result=result.result,
        facts=result.evidence,
        rationale=rationale,
    )


def _qualification_trace_evidence(trace: Any) -> tuple[EvidenceRecord, ...]:
    """Retain typed condition and precondition facts for successful qualification."""
    if trace is None or not (trace.condition_results or trace.precondition_results):
        return ()
    return (
        EvidenceRecord(
            kind="qualification",
            source="authoritative-projection",
            detail="authoritative qualification fact evaluations",
            fact_evaluations=tuple(
                _condition_fact_evaluation(result) for result in trace.condition_results
            )
            + tuple(
                _precondition_fact_evaluation(result)
                for result in trace.precondition_results
            ),
        ),
    )


def _unready_fact_status(
    reading: _contracts.QualificationFact | None,
) -> Literal["absent", "unknown", "contradictory"]:
    """Map an unusable typed reading to persisted evidence vocabulary."""
    if reading is None:
        return "absent"
    if reading.status in ("absent", "unknown", "contradictory"):
        return reading.status
    return "absent"


def _missing_qualification_facts(
    pattern: AttackPattern,
    inputs: _contracts.TaxonomyObligationInputs,
) -> tuple[QualificationFactEvidence, ...]:
    """Collect required facts that are missing or not usable for readiness."""
    missing: list[QualificationFactEvidence] = []
    for reference in required_fact_references((pattern,)):
        key = canonical_json_bytes(reference.model_dump(mode="json")).decode("utf-8")
        reading = inputs.qualification_facts.facts.get(key)
        if reading is None or reading.status != "present":
            missing.append(
                QualificationFactEvidence(
                    fact=reference,
                    status=_unready_fact_status(reading),
                    value=None,
                )
            )
    return tuple(missing)


def _missing_qualification_evidence(
    pattern: AttackPattern,
    inputs: _contracts.TaxonomyObligationInputs,
    qualification: str,
) -> tuple[EvidenceRecord, ...]:
    """Retain unusable typed facts as explicit, non-ready evidence."""
    if qualification not in {"missing_evidence", "contradictory_evidence"}:
        return ()
    missing = _missing_qualification_facts(pattern, inputs)
    if not missing:
        return ()
    rationale = (
        "authoritative qualification fact is contradictory"
        if qualification == "contradictory_evidence"
        else "authoritative qualification fact is absent"
    )
    return (
        EvidenceRecord(
            kind="qualification",
            source="qualification-facts",
            detail=rationale,
            fact_evaluations=(
                FactEvaluationEvidence(
                    evaluation_type="qualification_fact",
                    step_id=pattern.id,
                    result="unknown",
                    facts=missing,
                    rationale=rationale,
                ),
            ),
        ),
    )


def _advisory_evidence(
    evidence: tuple[EvidenceRecord, ...],
) -> tuple[EvidenceRecord, ...]:
    """Keep a nonempty evidence set for a directly resolved pattern."""
    if evidence:
        return evidence
    return (
        EvidenceRecord(
            kind="advisory",
            source="obligation-planner",
            detail="authoritative mapping path retained",
        ),
    )


def _obligation_evidence(
    paths: tuple[tuple[_MappingEdge, ...], ...],
    batch: Any,
    pattern_id: str,
    qualification_reason: str | None,
    qualification_trace: Any,
) -> tuple[EvidenceRecord, ...]:
    """Combine mapping, projection, and qualification provenance."""
    mapping = _path_evidence(paths)
    projection = _projection_evidence(batch, pattern_id) if batch else ()
    evidence = (
        mapping
        + projection
        + _qualification_evidence(qualification_reason)
        + _qualification_trace_evidence(qualification_trace)
    )
    return _advisory_evidence(evidence)


def _build_governance_obligation(
    card: Any,
    inputs: _contracts.TaxonomyObligationInputs,
) -> TaxonomyObligation:
    """Build the visible row for a risk without a resolved pattern."""
    return TaxonomyObligation(
        obligation_id=_identity_digest(card.risk_id, None, inputs),
        risk_ref=_risk_reference(card),
        taxonomy_chain=(),
        scope_disposition="governance_only",
        qualification_disposition="not_attempted",
        candidate_records=(),
        correspondence_disposition="not_assessed",
        evidence=(
            EvidenceRecord(
                kind="governance",
                source="obligation-planner",
                detail="reviewed risk did not resolve to an authoritative attack pattern",
            ),
        ),
    )


def _build_pattern_obligation(
    card: Any,
    pattern: AttackPattern,
    paths: tuple[tuple[_MappingEdge, ...], ...],
    inputs: _contracts.TaxonomyObligationInputs,
    batch: Any,
    candidates_by_pattern: dict[str, tuple[Any, ...]],
    deferred_ids: frozenset[str],
    qualification_traces: dict[str, Any],
    rejected_by_pattern: dict[str, tuple[Any, ...]],
) -> TaxonomyObligation:
    """Build one row for a resolved pattern and its authoritative projection."""
    scope, qualification, candidate_records, qualification_reason = (
        _pattern_disposition(
            pattern,
            inputs,
            batch,
            candidates_by_pattern.get(pattern.id, ()),
            deferred_ids,
            rejected_by_pattern.get(pattern.id, ()),
        )
    )
    return TaxonomyObligation(
        obligation_id=_identity_digest(card.risk_id, pattern, inputs),
        risk_ref=_risk_reference(card),
        taxonomy_chain=_chain_entries(pattern),
        attack_pattern_id=pattern.id,
        attack_pattern_semantic_digest=pattern.canonical_chain.semantic_digest,
        scope_disposition=scope,
        qualification_disposition=qualification,
        candidate_records=candidate_records,
        correspondence_disposition="not_assessed",
        evidence=(
            _obligation_evidence(
                paths,
                batch,
                pattern.id,
                qualification_reason,
                qualification_traces.get(pattern.id),
            )
            + _missing_qualification_evidence(pattern, inputs, qualification)
        ),
    )


def _build_obligation(
    card: Any,
    pattern: AttackPattern | None,
    paths: tuple[tuple[_MappingEdge, ...], ...],
    inputs: _contracts.TaxonomyObligationInputs,
    batch: Any,
    candidates_by_pattern: dict[str, tuple[Any, ...]],
    deferred_ids: frozenset[str],
    qualification_traces: dict[str, Any],
    rejected_by_pattern: dict[str, tuple[Any, ...]],
) -> TaxonomyObligation:
    """Build one complete obligation row from typed planner inputs."""
    if pattern is None:
        return _build_governance_obligation(card, inputs)
    return _build_pattern_obligation(
        card,
        pattern,
        paths,
        inputs,
        batch,
        candidates_by_pattern,
        deferred_ids,
        qualification_traces,
        rejected_by_pattern,
    )


def _validate_planner_inputs(inputs: Any) -> None:
    """Reject adapter payloads at the typed planner seam."""
    if not isinstance(inputs, _contracts.TaxonomyObligationInputs):
        raise TypeError(
            "plan_taxonomy_obligations requires TaxonomyObligationInputs; "
            "file paths and adapter payloads belong at the adapter boundary"
        )


def _rows_for_risk(
    card: Any,
    patterns: dict[str, AttackPattern],
    edges: tuple[_MappingEdge, ...],
    inputs: _contracts.TaxonomyObligationInputs,
    batch: Any,
    candidates_by_pattern: dict[str, tuple[Any, ...]],
    deferred_ids: frozenset[str],
    qualification_traces: dict[str, Any],
    rejected_by_pattern: dict[str, tuple[Any, ...]],
) -> tuple[TaxonomyObligation, ...]:
    """Build all rows reachable from one reviewed risk card."""
    paths_by_pattern = _mapping_paths(card.risk_id, set(patterns), edges)
    if not paths_by_pattern:
        return (
            _build_obligation(
                card,
                None,
                (),
                inputs,
                batch,
                candidates_by_pattern,
                deferred_ids,
                qualification_traces,
                rejected_by_pattern,
            ),
        )
    return tuple(
        _build_obligation(
            card,
            patterns[pattern_id],
            paths,
            inputs,
            batch,
            candidates_by_pattern,
            deferred_ids,
            qualification_traces,
            rejected_by_pattern,
        )
        for pattern_id, paths in paths_by_pattern.items()
    )


def _build_obligation_rows(
    inputs: _contracts.TaxonomyObligationInputs,
    patterns: dict[str, AttackPattern],
    edges: tuple[_MappingEdge, ...],
    batch: Any,
    candidates_by_pattern: dict[str, tuple[Any, ...]],
    deferred_ids: frozenset[str],
    qualification_traces: dict[str, Any],
    rejected_by_pattern: dict[str, tuple[Any, ...]],
) -> tuple[TaxonomyObligation, ...]:
    """Build and canonically order the complete obligation ledger."""
    obligations: list[TaxonomyObligation] = []
    for card in sorted(inputs.risk_cards, key=lambda item: item.risk_id):
        obligations.extend(
            _rows_for_risk(
                card,
                patterns,
                edges,
                inputs,
                batch,
                candidates_by_pattern,
                deferred_ids,
                qualification_traces,
                rejected_by_pattern,
            )
        )
    obligations.sort(
        key=lambda row: (
            row.risk_ref.risk_id,
            row.attack_pattern_id or "",
            row.obligation_id,
        )
    )
    return tuple(obligations)


def _finalize_plan(
    rows: tuple[TaxonomyObligation, ...],
    inputs: _contracts.TaxonomyObligationInputs,
) -> TaxonomyObligationPlan:
    """Construct, digest, and integrity-check the immutable plan."""
    provisional = TaxonomyObligationPlan(
        schema_version="taxonomy-obligation-plan-v1",
        semantic_digest="0" * 64,
        capability_snapshot_digest=_snapshot_digest(inputs.capability_snapshot),
        catalog_pins=dict(inputs.catalog_pins),
        mapping_pins=dict(inputs.mapping_pins),
        qualification_facts_digest=inputs.qualification_facts.semantic_digest
        or "0" * 64,
        obligations=rows,
        summary=derive_obligation_summary(rows),
    )
    plan = provisional.model_copy(
        update={"semantic_digest": provisional.compute_semantic_digest()}
    )
    plan.assert_integrity()
    return plan


def plan_taxonomy_obligations(
    inputs: _contracts.TaxonomyObligationInputs,
) -> TaxonomyObligationPlan:
    """Return the complete deterministic obligation ledger for typed inputs."""
    _validate_planner_inputs(inputs)
    patterns = _pattern_lookup(inputs.attack_pattern_catalog)
    edges = _mapping_edges(inputs)
    (
        batch,
        candidates_by_pattern,
        deferred_ids,
        qualification_traces,
        rejected_by_pattern,
    ) = _build_projection_batch(inputs)
    rows = _build_obligation_rows(
        inputs,
        patterns,
        edges,
        batch,
        candidates_by_pattern,
        deferred_ids,
        qualification_traces,
        rejected_by_pattern,
    )
    return _finalize_plan(rows, inputs)


__all__ = ["plan_taxonomy_obligations"]
