"""Shared contracts and pure helpers for authoritative projection.

This module is the dependency-inward boundary for the projection package.
It deliberately has no imports from projection implementation modules, so
resource, qualification, candidate, and relation adapters can depend on the
same contracts without importing the public projection façade.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Iterable
from typing import Annotated, Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from asago_scenario_generator.models.attack_pattern_chain import (
    AttackPattern,
    CanonicalAttackChain,
    ResourceSlot,
)
from asago_scenario_generator.models.attack_pattern_contracts import (
    AllCondition,
    AnyCondition,
    AuthoritativeFactReference,
    Condition,
    ConditionEvaluationResult,
    EvaluatedFactEvidence,
    ExecutionRequirement,
    MappingDecision,
    NotCondition,
    evaluate_condition,
)
from asago_scenario_generator.models.attack_pattern_projection import (
    AgentInternalResourceReference,
    CanonicalResourceReference,
    EntryPointResourceReference,
    IntegrationResourceReference,
    OutputSurfaceResourceReference,
    ProjectionSnapshot,
    ToolResourceReference,
    TrustBoundaryResourceReference,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    is_attacker_accessible_ingress,
)

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ProjectionModel(BaseModel):
    """Base model for immutable, closed projection contracts."""

    model_config = ConfigDict(extra="forbid", frozen=True)


def canonical_json_bytes(value: Any) -> bytes:
    """Encode values using the projection digest contract's canonical JSON."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    value = _normalize_unicode(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_json(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def _normalize_unicode(value: Any) -> Any:
    """Apply the canonical contract's NFC rule to values and mapping keys."""
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return _normalized_mapping(value)
    if isinstance(value, (list, tuple)):
        normalized = [_normalize_unicode(item) for item in value]
        return normalized if isinstance(value, list) else tuple(normalized)
    return value


def _normalized_sequence(
    value: list[Any] | tuple[Any, ...],
) -> list[Any]:
    """Normalize every item of a sequence under the canonical NFC rule."""
    return [_normalize_unicode(item) for item in value]


def _normalized_mapping(value: dict[str, Any]) -> dict[str, Any]:
    """Normalize mapping keys and values under the canonical NFC rule."""
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise TypeError("canonical JSON mapping keys must be strings")
        normalized_key = unicodedata.normalize("NFC", key)
        if normalized_key in normalized:
            raise ValueError(
                "canonical JSON mapping keys collide after NFC normalization"
            )
        normalized[normalized_key] = _normalize_unicode(item)
    return normalized


def _digest(domain: str, value: Any) -> str:
    payload = domain.encode() + b"\0" + _canonical_json(value).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


EXECUTION_REQUIREMENTS_DIGEST_DOMAIN = (
    "asago-scenario-generator:execution-requirements:v1"
)
DERIVATION_CONTEXT_DIGEST_DOMAIN = "asago-scenario-generator:derivation-context:v1"


def compute_execution_requirements_digest(requirements: Any) -> str:
    """Compute the canonical digest for a sequence of execution requirements."""
    payloads: list[Any] = []
    for item in requirements:
        payloads.append(
            item.model_dump(mode="json") if hasattr(item, "model_dump") else item
        )
    return _digest(EXECUTION_REQUIREMENTS_DIGEST_DOMAIN, payloads)


def compute_derivation_context_digest(
    projection_digest: str,
    pattern_id: str,
    ingress_controllability: str,
) -> str:
    """Compute the digest binding projection identity and controllability."""
    return _digest(
        DERIVATION_CONTEXT_DIGEST_DOMAIN,
        {
            "projection_digest": projection_digest,
            "pattern_id": pattern_id,
            "ingress_controllability": ingress_controllability,
        },
    )


def _fact_key(reference: AuthoritativeFactReference) -> str:
    return _canonical_json(reference.model_dump(mode="json"))


def _resource_key(reference: CanonicalResourceReference) -> str:
    return _canonical_json(reference.model_dump(mode="json"))


def _resource_checker_for(
    reference: CanonicalResourceReference,
    checkers: tuple[tuple[type, Callable], ...],
) -> Callable | None:
    """Return the first checker whose reference type matches the instance."""
    for ref_type, checker in checkers:
        if isinstance(reference, ref_type):
            return checker
    return None


def _resolved_resource_contained(
    profile: CapabilityProfile,
    resolver: Callable[[str], Any],
    identifier: str,
) -> bool:
    """Return whether a profile resolver contains the requested identifier."""
    return resolver(identifier) is not None


_RESOLVED_RESOURCE_FIELDS: tuple[tuple[type, str, str], ...] = (
    (EntryPointResourceReference, "resolve_entry_point", "entry_point_id"),
    (ToolResourceReference, "resolve_tool", "tool_id"),
    (IntegrationResourceReference, "resolve_integration", "integration_id"),
    (TrustBoundaryResourceReference, "resolve_trust_boundary", "trust_boundary_id"),
    (OutputSurfaceResourceReference, "resolve_output_surface", "entry_point_id"),
)


def _resource_contained(
    reference: CanonicalResourceReference, profile: CapabilityProfile
) -> bool:
    for ref_type, resolver_name, identifier_name in _RESOLVED_RESOURCE_FIELDS:
        if isinstance(reference, ref_type):
            return _resolved_resource_contained(
                profile,
                getattr(profile, resolver_name),
                getattr(reference, identifier_name),
            )
    return isinstance(reference, AgentInternalResourceReference) and (
        "reasoning" in profile.zones_active
    )


def _restriction_blocks(value: str, allowed_values: tuple[str, ...]) -> bool:
    """True when a slot restriction excludes the concrete value."""
    if not allowed_values:
        return False
    return value not in allowed_values


def _resource_id_allowed(
    reference: CanonicalResourceReference, allowed_resource_ids: set[str]
) -> bool:
    """True when the reference id passes the slot's id allow-list."""
    if not allowed_resource_ids:
        return True
    return _resource_id(reference) in allowed_resource_ids


def _integration_matches_slot(
    reference: IntegrationResourceReference,
    slot: ResourceSlot,
    snapshot: CapabilityFactSnapshot,
) -> bool:
    """True when the integration satisfies the slot's typed constraints."""
    integration = snapshot.profile.resolve_integration(reference.integration_id)
    if integration is None:
        return False
    return not _restriction_blocks(
        integration.integration_type.value, slot.allowed_integration_types
    )


def _entry_point_matches_slot(
    reference: EntryPointResourceReference,
    slot: ResourceSlot,
    snapshot: CapabilityFactSnapshot,
) -> bool:
    """True when the entry point satisfies the slot's typed constraints."""
    entry_point = snapshot.profile.resolve_entry_point(reference.entry_point_id)
    if entry_point is None:
        return False
    constraints = (
        (entry_point.entry_point_type, slot.allowed_entry_point_types),
        (entry_point.direction, slot.allowed_entry_point_directions),
        (entry_point.controllability, slot.allowed_entry_point_controllability),
        (entry_point.effective_ingress_zone, slot.allowed_entry_point_ingress_zones),
    )
    return all(
        not _restriction_blocks(value, allowed) for value, allowed in constraints
    )


def _trust_boundary_matches_slot(
    reference: TrustBoundaryResourceReference,
    slot: ResourceSlot,
    snapshot: CapabilityFactSnapshot,
) -> bool:
    """True when the trust boundary satisfies the slot's typed constraints."""
    boundary = snapshot.profile.resolve_trust_boundary(reference.trust_boundary_id)
    if boundary is None:
        return False
    if _restriction_blocks(boundary.from_zone, slot.allowed_trust_boundary_from_zones):
        return False
    if _restriction_blocks(boundary.to_zone, slot.allowed_trust_boundary_to_zones):
        return False
    return True


def _slot_reference_compatible(
    reference: CanonicalResourceReference,
    slot: ResourceSlot,
    snapshot: CapabilityFactSnapshot,
) -> bool:
    """True when the reference satisfies the slot's typed constraints."""
    if isinstance(reference, IntegrationResourceReference):
        return _integration_matches_slot(reference, slot, snapshot)
    if isinstance(reference, EntryPointResourceReference):
        return _entry_point_matches_slot(reference, slot, snapshot)
    if isinstance(reference, TrustBoundaryResourceReference):
        return _trust_boundary_matches_slot(reference, slot, snapshot)
    return True


def _entry_point_eligible_for_slot(
    reference: EntryPointResourceReference,
    slot: ResourceSlot,
    snapshot: CapabilityFactSnapshot,
) -> bool:
    """True when the entry point survives the slot's accessibility filter."""
    item = snapshot.profile.resolve_entry_point(reference.entry_point_id)
    if item is None:
        return False
    initial_ingress = slot.purpose == "initial_ingress"
    attacker_influence_required = slot.purpose == "supporting"
    if initial_ingress or attacker_influence_required:
        return is_attacker_accessible_ingress(item, set(snapshot.profile.zones_active))
    return True


def _resource_kind_matches_slot(
    reference: CanonicalResourceReference, slot: ResourceSlot
) -> bool:
    """True when the reference discriminator matches the slot kind."""
    return getattr(reference, "kind", None) == slot.kind


def _resource_matches_slot(
    reference: CanonicalResourceReference,
    slot: ResourceSlot,
    snapshot: CapabilityFactSnapshot,
) -> bool:
    """True when the reference is an allowed, compatible binding for the slot."""
    if not _resource_kind_matches_slot(reference, slot):
        return False
    if not _resource_contained(reference, snapshot.profile):
        return False
    if not _resource_id_allowed(reference, set(slot.allowed_resource_ids)):
        return False
    if not _slot_reference_compatible(reference, slot, snapshot):
        return False
    if isinstance(reference, EntryPointResourceReference):
        return _entry_point_eligible_for_slot(reference, slot, snapshot)
    return True


def _snapshot_resource_payload(profile: CapabilityProfile) -> dict[str, Any]:
    return {
        "zones_active": sorted(set(profile.zones_active)),
        "kc_subcodes": sorted(set(profile.kc_subcodes)),
        "entry_points": _sorted_by(profile.entry_points, "entry_point_id"),
        "tools": _sorted_by(profile.tool_inventory or (), "tool_id"),
        "tool_types": _sorted_canonical(profile.tool_types or ()),
        "integrations": _sorted_by(
            profile.external_integrations or (), "integration_id"
        ),
        "trust_boundaries": _sorted_by(
            profile.trust_boundaries or (), "trust_boundary_id"
        ),
    }


def _sorted_by(items: Iterable[Any], key_field: str) -> list[dict[str, Any]]:
    return sorted(
        (item.model_dump(mode="json") for item in items),
        key=lambda item: item[key_field],
    )


def _sorted_canonical(items: Iterable[Any]) -> list[dict[str, Any]]:
    return sorted(
        (item.model_dump(mode="json") for item in items),
        key=lambda item: _canonical_json(item),
    )


def _compute_snapshot_digest(
    profile: CapabilityProfile, facts: tuple[EvaluatedFactEvidence, ...]
) -> str:
    return _digest(
        "asago-scenario-generator:capability-fact-snapshot:v1",
        {
            "profile": _snapshot_resource_payload(profile),
            "facts": [item.model_dump(mode="json") for item in facts],
        },
    )


def _assert_snapshot_facts_uniquely_sorted(
    facts: tuple[EvaluatedFactEvidence, ...],
) -> None:
    keys = [_fact_key(item.fact) for item in facts]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise ValueError("snapshot facts must be uniquely sorted by reference")


class CapabilityFactSnapshot(ProjectionModel):
    """One immutable, content-addressed pre-LLM profile/fact reading."""

    profile: CapabilityProfile
    facts: tuple[EvaluatedFactEvidence, ...]
    snapshot_digest: Digest

    @property
    def capability_fact_snapshot_digest(self) -> str:
        self.assert_integrity()
        return self.snapshot_digest

    def assert_integrity(self) -> None:
        if self.snapshot_digest != _compute_snapshot_digest(self.profile, self.facts):
            raise ValueError("capability/fact snapshot changed after capture")

    def fact(
        self, reference: AuthoritativeFactReference
    ) -> EvaluatedFactEvidence | None:
        self.assert_integrity()
        return {_fact_key(item.fact): item for item in self.facts}.get(
            _fact_key(reference)
        )

    def contains_resource(self, reference: CanonicalResourceReference) -> bool:
        self.assert_integrity()
        return _resource_contained(reference, self.profile)

    def resource_matches_slot(
        self, reference: CanonicalResourceReference, slot: ResourceSlot
    ) -> bool:
        self.assert_integrity()
        return _resource_matches_slot(reference, slot, self)

    @model_validator(mode="after")
    def coherent_digest(self) -> "CapabilityFactSnapshot":
        _assert_snapshot_facts_uniquely_sorted(self.facts)
        if self.snapshot_digest != _compute_snapshot_digest(self.profile, self.facts):
            raise ValueError("snapshot_digest does not match capability/fact content")
        return self


def capture_capability_snapshot(
    profile: CapabilityProfile,
    facts: Iterable[EvaluatedFactEvidence] = (),
) -> CapabilityFactSnapshot:
    """Capture a deterministic resolver snapshot before any LLM stage."""
    by_reference: dict[str, EvaluatedFactEvidence] = {}
    for item in facts:
        key = _fact_key(item.fact)
        previous = by_reference.get(key)
        if previous is not None and previous != item:
            raise ValueError("conflicting authoritative readings for one fact")
        by_reference[key] = item
    ordered = tuple(by_reference[key] for key in sorted(by_reference))
    captured_profile = profile.model_copy(deep=True)
    return CapabilityFactSnapshot(
        profile=captured_profile,
        facts=ordered,
        snapshot_digest=_compute_snapshot_digest(captured_profile, ordered),
    )


_SEMANTICALLY_UNORDERED_FIELDS = {
    "allowed_entry_point_controllability",
    "allowed_entry_point_directions",
    "allowed_entry_point_ingress_zones",
    "allowed_entry_point_types",
    "allowed_integration_types",
    "allowed_trust_boundary_from_zones",
    "allowed_trust_boundary_to_zones",
    "bindings",
    "condition_results",
    "consumed",
    "distinct_from_slot_ids",
    "evidence",
    "ids",
    "mappings",
    "min_zones",
    "observable_postconditions",
    "observable_outcome_links",
    "omissions",
    "operands",
    "preconditions",
    "produced",
    "references",
    "resource_links",
    "resource_slots",
    "values",
}


def _normalize_semantic_order(value: Any, field_name: str | None = None) -> Any:
    value = _normalize_unicode(value)
    if isinstance(value, dict):
        return {
            key: _normalize_semantic_order(item, key) for key, item in value.items()
        }
    if isinstance(value, list):
        items = [_normalize_semantic_order(item) for item in value]
        if field_name in _SEMANTICALLY_UNORDERED_FIELDS:
            items.sort(key=_canonical_json)
        return items
    return value


class ProjectionBudget(ProjectionModel):
    """Explicit global expansion bound."""

    max_candidates: int = Field(default=256, gt=0)
    max_derivation_work: int = Field(default=4096, gt=0)


class PreconditionEvaluationResult(ProjectionModel):
    step_id: str
    condition_id: str
    result: Literal["true", "false", "unknown"]
    evidence: tuple[EvaluatedFactEvidence, ...] = Field(min_length=1)


class ProjectionIssue(ProjectionModel):
    code: Literal[
        "unresolved_condition",
        "precondition_not_satisfied",
        "missing_compatible_resource",
        "incompatible_profile",
        "unsupported_requirement_derivation",
        "inapplicable_projection",
        "source_influence_relation_infeasible",
    ]
    pattern_id: str
    detail: str
    step_id: str | None = None
    slot_id: str | None = None
    condition_results: tuple[ConditionEvaluationResult, ...] = ()
    precondition_results: tuple[PreconditionEvaluationResult, ...] = ()
    source_id: str | None = None
    boundary_id: str | None = None
    target_ingress_id: str | None = None
    canonical_ingress_id: str | None = None
    expected_target_zone: str | None = None
    actual_boundary_zones: str | None = None
    expected_source_kind: str | None = None
    actual_binding_kind: str | None = None
    guidance: str | None = None


class ProjectionLimitation(ProjectionModel):
    """A bounded projection result that was not fully expanded."""

    code: Literal["candidate_budget_exhausted", "derivation_work_exhausted"]
    pattern_id: str
    total_compatible_bindings: int = Field(ge=0)
    emitted_bindings: int = Field(ge=0)


class ProjectionBatch(ProjectionModel):
    """Complete deterministic result, including typed non-candidate outcomes."""

    capability_fact_snapshot_digest: Digest
    candidates: tuple["ProjectedCandidate", ...]
    infeasibilities: tuple[ProjectionIssue, ...]
    limitations: tuple[ProjectionLimitation, ...]
    unreserved_coverage_targets: tuple[str, ...] = ()
    infeasible_coverage_targets: tuple[str, ...] = ()


class ProjectedMapping(ProjectionModel):
    scope: Literal["chain", "step"]
    step_id: str | None = None
    mapping: MappingDecision

    @model_validator(mode="after")
    def scope_matches_step(self) -> "ProjectedMapping":
        if (self.scope == "step") != (self.step_id is not None):
            raise ValueError("step mappings require step_id; chain mappings forbid it")
        return self


class CandidateComplexityInputs(ProjectionModel):
    """Policy-free inputs reserved for the future complexity policy."""

    selected_step_count: int = Field(ge=1)
    attacker_controlled_step_count: int = Field(ge=1)
    boundary_crossing_step_count: int = Field(ge=0)
    selected_conditional_step_count: int = Field(ge=0)
    concrete_binding_count: int = Field(ge=1)
    execution_requirement_count: int = Field(ge=1)


class ProjectedCandidate(ProjectionModel):
    """Sole candidate-v2 contract intended for future generation stages."""

    candidate_id: str = Field(pattern=r"^cand:v2:[0-9a-f]{32}$")
    pattern_id: str
    chain_id: str
    chain_semantic_revision: int = Field(gt=0)
    chain_semantic_digest: Digest
    projection: ProjectionSnapshot
    canonical_ingress: EntryPointResourceReference
    ingress_controllability: Literal["direct", "indirect"]
    projected_mappings: tuple[ProjectedMapping, ...]
    precondition_results: tuple[PreconditionEvaluationResult, ...]
    execution_requirements: tuple[ExecutionRequirement, ...]
    requirement_derivation_version: Literal["1"]
    execution_requirements_digest: Digest
    complexity_inputs: CandidateComplexityInputs

    @model_validator(mode="after")
    def verifiable_identity_and_derivation(self) -> "ProjectedCandidate":
        _require_unique_requirement_ids(self.execution_requirements)
        _verify_chain_identity(
            self.pattern_id,
            self.chain_id,
            self.chain_semantic_revision,
            self.chain_semantic_digest,
            self.projection.source_chain,
        )
        _verify_canonical_ingress(
            self.projection, self.projection.source_chain, self.canonical_ingress
        )
        _verify_execution_requirements_digest(
            self.execution_requirements, self.execution_requirements_digest
        )
        _verify_candidate_identity(self.candidate_id, self.pattern_id, self.projection)
        expected_preconditions = _expected_precondition_key_map(
            self.projection.source_chain, self.projection.selected_step_ids
        )
        _verify_precondition_results(expected_preconditions, self.precondition_results)
        _verify_projected_mappings(
            self.projected_mappings,
            self.projection.source_chain,
            self.projection.selected_step_ids,
        )
        _verify_complexity_inputs(
            self.complexity_inputs,
            self.projection.source_chain,
            self.projection,
            self.execution_requirements,
        )
        return self


def _require_unique_requirement_ids(
    execution_requirements: tuple[ExecutionRequirement, ...],
) -> None:
    req_ids = [item.requirement_id for item in execution_requirements]
    if len(req_ids) != len(set(req_ids)):
        raise ValueError("execution requirement IDs must be unique")


def _verify_chain_identity(
    pattern_id: str,
    chain_id: str,
    chain_semantic_revision: int,
    chain_semantic_digest: str,
    chain: CanonicalAttackChain,
) -> None:
    if (
        pattern_id != chain.pattern_id
        or chain_id != chain.chain_id
        or chain_semantic_revision != chain.semantic_revision
        or chain_semantic_digest != chain.semantic_digest
    ):
        raise ValueError("candidate chain identity does not match its projection")


def _verify_canonical_ingress(
    projection: ProjectionSnapshot,
    chain: CanonicalAttackChain,
    canonical_ingress: EntryPointResourceReference,
) -> None:
    ingress = next(
        binding.resource_ref
        for binding in projection.bindings
        if binding.slot_id == chain.initial_ingress_slot_id
    )
    if ingress != canonical_ingress:
        raise ValueError("canonical_ingress does not match the projection binding")


def _verify_execution_requirements_digest(
    execution_requirements: tuple[ExecutionRequirement, ...],
    execution_requirements_digest: str,
) -> None:
    if execution_requirements_digest != compute_execution_requirements_digest(
        execution_requirements
    ):
        raise ValueError("execution_requirements_digest does not match requirements")


def _verify_candidate_identity(
    candidate_id: str, pattern_id: str, projection: ProjectionSnapshot
) -> None:
    if candidate_id != _candidate_v2_id(pattern_id, projection):
        raise ValueError("candidate_id does not match candidate-v2 identity inputs")


def _expected_precondition_key_map(
    chain: CanonicalAttackChain, selected_step_ids: tuple[str, ...]
) -> dict[tuple[str, str], Condition]:
    selected = set(selected_step_ids)
    return {
        (step.step_id, precondition.condition_id): precondition.condition
        for step in chain.steps
        if step.step_id in selected
        for precondition in step.preconditions
    }


def _verify_precondition_true(condition: Condition, supplied: Any) -> None:
    if (
        supplied.result != "true"
        or evaluate_condition(condition, supplied.evidence) != "true"
    ):
        raise ValueError("projected candidate preconditions must evaluate true")


def _verify_precondition_results(
    expected_preconditions: dict[tuple[str, str], Condition],
    precondition_results: tuple[PreconditionEvaluationResult, ...],
) -> None:
    supplied_preconditions = {
        (item.step_id, item.condition_id): item for item in precondition_results
    }
    if len(supplied_preconditions) != len(precondition_results):
        raise ValueError("precondition result keys must be unique")
    if set(expected_preconditions) != set(supplied_preconditions):
        raise ValueError("precondition results must exactly cover selected steps")
    for key, condition in expected_preconditions.items():
        _verify_precondition_true(condition, supplied_preconditions[key])


def _verify_projected_mappings(
    projected_mappings: tuple[ProjectedMapping, ...],
    chain: CanonicalAttackChain,
    selected_step_ids: tuple[str, ...],
) -> None:
    if projected_mappings != _projected_mappings(chain, selected_step_ids):
        raise ValueError("projected mappings are incomplete or non-authoritative")


def _selected_steps_for_projection(
    chain: CanonicalAttackChain, selected_step_ids: tuple[str, ...]
) -> list[Any]:
    selected = set(selected_step_ids)
    return [step for step in chain.steps if step.step_id in selected]


def _expected_complexity_inputs(
    selected_steps: list[Any],
    projection: ProjectionSnapshot,
    execution_requirements: tuple[ExecutionRequirement, ...],
) -> CandidateComplexityInputs:
    return CandidateComplexityInputs(
        selected_step_count=len(selected_steps),
        attacker_controlled_step_count=sum(
            step.attacker_controlled for step in selected_steps
        ),
        boundary_crossing_step_count=sum(
            step.boundary_position == "crossing" for step in selected_steps
        ),
        selected_conditional_step_count=sum(
            step.requirement == "conditional" for step in selected_steps
        ),
        concrete_binding_count=len(projection.bindings),
        execution_requirement_count=len(execution_requirements),
    )


def _verify_complexity_inputs(
    complexity_inputs: CandidateComplexityInputs,
    chain: CanonicalAttackChain,
    projection: ProjectionSnapshot,
    execution_requirements: tuple[ExecutionRequirement, ...],
) -> None:
    expected = _expected_complexity_inputs(
        _selected_steps_for_projection(chain, projection.selected_step_ids),
        projection,
        execution_requirements,
    )
    if complexity_inputs != expected:
        raise ValueError("complexity inputs do not match projected candidate")


def _entry_point_resource_id(reference: EntryPointResourceReference) -> str:
    return reference.entry_point_id


def _integration_resource_id(reference: IntegrationResourceReference) -> str:
    return reference.integration_id


def _trust_boundary_resource_id(
    reference: TrustBoundaryResourceReference,
) -> str:
    return reference.trust_boundary_id


def _tool_resource_id(reference: ToolResourceReference) -> str:
    return reference.tool_id


def _output_surface_resource_id(reference: OutputSurfaceResourceReference) -> str:
    return reference.entry_point_id


def _agent_internal_resource_id(
    reference: AgentInternalResourceReference,
) -> str:
    return "agent_internal:reasoning"


_RESOURCE_ID_EXTRACTORS: tuple[tuple[type, Callable], ...] = (
    (EntryPointResourceReference, _entry_point_resource_id),
    (IntegrationResourceReference, _integration_resource_id),
    (TrustBoundaryResourceReference, _trust_boundary_resource_id),
    (ToolResourceReference, _tool_resource_id),
    (OutputSurfaceResourceReference, _output_surface_resource_id),
    (AgentInternalResourceReference, _agent_internal_resource_id),
)


def _resource_id(reference: CanonicalResourceReference) -> str:
    extractor = _resource_checker_for(reference, _RESOURCE_ID_EXTRACTORS)
    if extractor is None:
        raise TypeError(f"unsupported canonical resource reference: {reference!r}")
    return extractor(reference)


def _condition_facts(
    condition: Condition,
) -> tuple[AuthoritativeFactReference, ...]:
    items = _condition_fact_items(condition)
    by_key = {_fact_key(item): item for item in items}
    return tuple(by_key[key] for key in sorted(by_key))


def _dedupe_sorted_facts(
    items: list[AuthoritativeFactReference] | tuple[AuthoritativeFactReference, ...],
) -> tuple[AuthoritativeFactReference, ...]:
    """Deduplicate fact references by key and order them canonically."""
    by_key = {_fact_key(item): item for item in items}
    return tuple(by_key[key] for key in sorted(by_key))


def _condition_fact_items(condition: Condition) -> list[AuthoritativeFactReference]:
    if isinstance(condition, (AllCondition, AnyCondition)):
        return [
            fact
            for operand in condition.operands
            for fact in _condition_fact_items(operand)
        ]
    if isinstance(condition, NotCondition):
        return _condition_fact_items(condition.operand)
    return [condition.fact]


def _evaluate_projection_conditions(
    pattern: AttackPattern, snapshot: Any
) -> tuple[ConditionEvaluationResult, ...]:
    results: list[ConditionEvaluationResult] = []
    for step in pattern.canonical_chain.steps:
        if step.condition is None:
            continue
        evidence = tuple(
            snapshot.fact(reference)
            or EvaluatedFactEvidence(fact=reference, status="unknown", value=None)
            for reference in _condition_facts(step.condition)
        )
        results.append(
            ConditionEvaluationResult(
                condition_step_id=step.step_id,
                result=evaluate_condition(step.condition, evidence),
                evidence=evidence,
            )
        )
    return tuple(results)


def _evaluate_preconditions(
    pattern: AttackPattern,
    selected_step_ids: tuple[str, ...],
    snapshot: Any,
) -> tuple[PreconditionEvaluationResult, ...]:
    selected = set(selected_step_ids)
    return tuple(
        _evaluate_precondition(step, precondition, snapshot)
        for step in pattern.canonical_chain.steps
        if step.step_id in selected
        for precondition in step.preconditions
    )


def _evaluate_precondition(
    step: Any, precondition: Any, snapshot: Any
) -> PreconditionEvaluationResult:
    evidence = tuple(
        snapshot.fact(reference)
        or EvaluatedFactEvidence(fact=reference, status="unknown", value=None)
        for reference in _condition_facts(precondition.condition)
    )
    return PreconditionEvaluationResult(
        step_id=step.step_id,
        condition_id=precondition.condition_id,
        result=evaluate_condition(precondition.condition, evidence),
        evidence=evidence,
    )


def _content_pin(domain: str, value: Any) -> str:
    return _digest(domain, value)


def _chain_atlas_mappings(
    chain: CanonicalAttackChain,
) -> Iterable[ProjectedMapping]:
    """Project the chain-level ATLAS mappings of the authoritative chain."""
    return (
        ProjectedMapping(scope="chain", mapping=mapping)
        for mapping in chain.mappings
        if mapping.taxonomy == "ATLAS"
    )


def _step_atlas_mappings(step: Any) -> Iterable[ProjectedMapping]:
    """Project the ATLAS mappings declared on one selected step."""
    return (
        ProjectedMapping(scope="step", step_id=step.step_id, mapping=mapping)
        for mapping in step.mappings
        if mapping.taxonomy == "ATLAS"
    )


def _projected_mappings(
    chain: CanonicalAttackChain, selected_step_ids: tuple[str, ...]
) -> tuple[ProjectedMapping, ...]:
    """Project the chain and selected-step ATLAS mappings."""
    mappings = list(_chain_atlas_mappings(chain))
    selected = set(selected_step_ids)
    for step in chain.steps:
        if step.step_id in selected:
            mappings.extend(_step_atlas_mappings(step))
    return tuple(mappings)


def _candidate_v2_id(pattern_id: str, projection: ProjectionSnapshot) -> str:
    """Compute the stable candidate identity from projection content."""
    chain = projection.source_chain
    bindings = sorted(
        (item.model_dump(mode="json") for item in projection.bindings),
        key=lambda item: (item["slot_id"], _canonical_json(item["resource_ref"])),
    )
    ingress = next(
        item["resource_ref"]
        for item in bindings
        if item["slot_id"] == chain.initial_ingress_slot_id
    )
    identity = {
        "pattern_id": pattern_id,
        "chain_id": chain.chain_id,
        "chain_semantic_revision": chain.semantic_revision,
        "chain_semantic_digest": chain.semantic_digest,
        "projection_digest": projection.projection_digest,
        "taxonomy_context": chain.taxonomy_context.model_dump(mode="json"),
        "canonical_ingress": ingress,
        "bindings": bindings,
    }
    return f"cand:v2:{_digest('asago-scenario-generator:candidate:v2', identity)[:32]}"


def _pattern_pin(pattern: AttackPattern) -> str:
    prerequisites = pattern.prerequisite_capabilities
    return _content_pin(
        "asago-scenario-generator:authoritative-pattern:v1",
        {
            "id": pattern.id,
            "threat_id": pattern.threat_id,
            "name": pattern.name,
            "description": pattern.description,
            "nist_classification": (
                pattern.nist_classification.model_dump(mode="json")
                if pattern.nist_classification
                else None
            ),
            "min_zones": sorted(set(prerequisites.min_zones)),
            "kc_requires": {
                "all": sorted(set(prerequisites.kc_requires.all)),
                "any": sorted(set(prerequisites.kc_requires.any)),
            }
            if prerequisites.kc_requires
            else None,
            "chain_semantic_digest": pattern.canonical_chain.semantic_digest,
        },
    )
