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
from collections.abc import Iterable, Sequence
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
    ResourceBinding,
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


class RejectedProjectionCandidate(ProjectionModel):
    """One concrete or aggregate projection rejection retained for planning."""

    candidate_id: str = Field(pattern=r"^cand:v2:[0-9a-f]{32}$")
    pattern_id: str = Field(min_length=1)
    canonical_ingress: EntryPointResourceReference | None = None
    resource_bindings: tuple[ResourceBinding, ...] = ()
    projection_disposition: Literal["projection_infeasible"] = "projection_infeasible"
    reason: str = Field(min_length=1)
    issue: ProjectionIssue

    @model_validator(mode="after")
    def ingress_binding_is_coherent(self) -> "RejectedProjectionCandidate":
        """Require any retained ingress to be represented in its bindings."""
        if self.canonical_ingress is not None and not any(
            binding.resource_ref == self.canonical_ingress
            for binding in self.resource_bindings
        ):
            raise ValueError("rejected candidate ingress must be a resource binding")
        return self


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


class ProjectionQualificationTrace(ProjectionModel):
    """Authoritative fact evaluations retained for one qualified pattern."""

    pattern_id: str
    condition_results: tuple[ConditionEvaluationResult, ...] = ()
    precondition_results: tuple[PreconditionEvaluationResult, ...] = ()


class AuthoritativeProjectionObservation(ProjectionModel):
    """Projection output plus truthful, bounded planning observations.

    ``batch`` is byte-for-byte the established generation-facing result.
    ``deferred_candidates`` contains only candidates actually derived and
    validated before ``max_derivation_work`` was exhausted; it never infers
    identities from aggregate compatible-binding counts.
    """

    batch: ProjectionBatch
    deferred_candidates: tuple[ProjectedCandidate, ...] = ()
    rejected_candidates: tuple[RejectedProjectionCandidate, ...] = ()
    qualification_traces: tuple[ProjectionQualificationTrace, ...] = ()


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


def _pattern_fact_conditions(pattern: AttackPattern) -> Iterable[Condition]:
    """Yield every condition whose facts participate in qualification."""
    for step in pattern.canonical_chain.steps:
        if step.condition is not None:
            yield step.condition
        yield from (item.condition for item in step.preconditions)


def required_fact_references(
    patterns: Sequence[AttackPattern],
) -> tuple[AuthoritativeFactReference, ...]:
    """Return the canonical condition/precondition fact inventory."""
    references = {
        _fact_key(reference): reference
        for pattern in patterns
        for condition in _pattern_fact_conditions(pattern)
        for reference in _condition_facts(condition)
    }
    return tuple(references[key] for key in sorted(references))


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


def _rejected_candidate_v2_id(
    pattern_id: str,
    issue: ProjectionIssue,
    resource_bindings: tuple[ResourceBinding, ...] = (),
) -> str:
    """Compute a stable identity for one rejected projection combination."""
    bindings = sorted(
        (item.model_dump(mode="json") for item in resource_bindings),
        key=lambda item: (item["slot_id"], _canonical_json(item["resource_ref"])),
    )
    return (
        "cand:v2:"
        + _digest(
            "asago-scenario-generator:candidate-infeasible:v1",
            {
                "pattern_id": pattern_id,
                "issue": issue.model_dump(mode="json"),
                "resource_bindings": bindings,
            },
        )[:32]
    )


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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-28T16:19:02Z","module_hash":"3dd5490bc8a4e3f73e152b6ddbecb5b6a9fdb5b1d8d18783735365adbdfd147b","source_sha256":"b557b864e807383d0bf6c775341cb56e6ba34cfe17c78ea848d428150601279a","functions":[{"id":"func/canonical_json_bytes","name":"canonical_json_bytes","line":61,"end_line":72,"hash":"a219d15020b2ac3683b0f2fd59510eba8f89f77d7aba2eab8f718741371029c1"},{"id":"func/_canonical_json","name":"_canonical_json","line":75,"end_line":76,"hash":"b227e266a077dc2baba8fec5dbc32ee3a5addfa16b8fb119677eb51b6ce649a4"},{"id":"func/_normalize_unicode","name":"_normalize_unicode","line":79,"end_line":88,"hash":"ad0f0cd93c5fd3ca0dc26f0268ed73186e471c4016b5e6ba51353c3a7123b0b2"},{"id":"func/_normalized_sequence","name":"_normalized_sequence","line":91,"end_line":95,"hash":"32b5c39552196996733fd89525b6d65585fd8991b6755a13176322287da9583c"},{"id":"func/_normalized_mapping","name":"_normalized_mapping","line":98,"end_line":110,"hash":"1656571587dbb3beb551f14b0604672db380c651a5e66aa672c75317d548e41c"},{"id":"func/_digest","name":"_digest","line":113,"end_line":115,"hash":"9b4fd801921a45725f9b439b6312bb9b71bda5ab6b5523d7893afab0fdac1e87"},{"id":"func/compute_execution_requirements_digest","name":"compute_execution_requirements_digest","line":124,"end_line":131,"hash":"15efa62292af3ba11e3aac2fac480e04049fd46b10fb6baf51008ed552d0186e"},{"id":"func/compute_derivation_context_digest","name":"compute_derivation_context_digest","line":134,"end_line":147,"hash":"0497d35668ec0bf1f0fb573e53ffcbdaea0eb065495d3302b60627c2122f956e"},{"id":"func/_fact_key","name":"_fact_key","line":150,"end_line":151,"hash":"16f1c4b278b6ba219901b1bd3e396e4d871373e8d7e85f85cb1fc7c9f1d05623"},{"id":"func/_resource_key","name":"_resource_key","line":154,"end_line":155,"hash":"a67a135da3e01007e02081bf013672332bf9b2c441ab57d0e38976f936218b2e"},{"id":"func/_resource_checker_for","name":"_resource_checker_for","line":158,"end_line":166,"hash":"1580bb0e453389797bf281312603f68f3f053efabaa9d2bc68fedf22497b2fa5"},{"id":"func/_resolved_resource_contained","name":"_resolved_resource_contained","line":169,"end_line":175,"hash":"d3b4d7c3f71e17c22fd82e1f4e81c4e539abeac8b47c1cbb5b95e9f344846994"},{"id":"func/_resource_contained","name":"_resource_contained","line":187,"end_line":199,"hash":"25c648666ec9b714119254d4997487b4961511a2cff8cfde017e1b226689bb94"},{"id":"func/_restriction_blocks","name":"_restriction_blocks","line":202,"end_line":206,"hash":"c60225f1cc45971e7351c4ed7761bb9cf35d807b77e5a864a00b2d70b09e456c"},{"id":"func/_resource_id_allowed","name":"_resource_id_allowed","line":209,"end_line":215,"hash":"d4103149e0b9bf053749b069876fa36433605f5305512d10819937fb89dcb616"},{"id":"func/_integration_matches_slot","name":"_integration_matches_slot","line":218,"end_line":229,"hash":"a48db74158f151134b6b0482d01c2e95c853561c49836300f8d33e043f323183"},{"id":"func/_entry_point_matches_slot","name":"_entry_point_matches_slot","line":232,"end_line":249,"hash":"5d6974c3ed67c133995c8bf3b6c15b4ca1e30acc6ff80a6c2758bda415c372f4"},{"id":"func/_trust_boundary_matches_slot","name":"_trust_boundary_matches_slot","line":252,"end_line":265,"hash":"26364e40535426ad7e820f5661abb4421098162b677515b3942750996ce3e2ad"},{"id":"func/_slot_reference_compatible","name":"_slot_reference_compatible","line":268,"end_line":280,"hash":"8a682a2cfd3319a2c5057146f9e50dd731a443a517b646135ea53ed5778850b7"},{"id":"func/_entry_point_eligible_for_slot","name":"_entry_point_eligible_for_slot","line":283,"end_line":296,"hash":"d0a63963ec652a0db7959b8fed23b707b3da51018466513990ea220beaefc4ff"},{"id":"func/_resource_kind_matches_slot","name":"_resource_kind_matches_slot","line":299,"end_line":303,"hash":"6dbb01c13ac997915698992faf7f63cd8a7d44fb91fe855a0363662dbf135945"},{"id":"func/_resource_matches_slot","name":"_resource_matches_slot","line":306,"end_line":322,"hash":"0ab798b60f70679ee21c8fb356d7c728c87df054c62e6d7b4da04ae79a76f23b"},{"id":"func/_snapshot_resource_payload","name":"_snapshot_resource_payload","line":325,"end_line":338,"hash":"bd95e143a1e82b6b080c50d20fe0706f267cc630c0f6b9dae45fb5ea9086f8f7"},{"id":"func/_sorted_by","name":"_sorted_by","line":341,"end_line":345,"hash":"64010e2e50bca781d3fbdf6aa850cbe7ee6547f9fe8b362a3edd1f41a9f791d9"},{"id":"func/_sorted_canonical","name":"_sorted_canonical","line":348,"end_line":352,"hash":"c536551168c526ccbc228c7d05e012abb7363a2ea2372a92dbafc3365e8cd78c"},{"id":"func/_compute_snapshot_digest","name":"_compute_snapshot_digest","line":355,"end_line":364,"hash":"a17faa81a49a433da85ac9c71ca22b9280900ed09699b33a941fb4195477192d"},{"id":"func/_assert_snapshot_facts_uniquely_sorted","name":"_assert_snapshot_facts_uniquely_sorted","line":367,"end_line":372,"hash":"9e08449753230d2d0efa6a823a005c1c8bb8b1a4eee2a096fd259b6f1a9cc439"},{"id":"func/CapabilityFactSnapshot.capability_fact_snapshot_digest","name":"capability_fact_snapshot_digest","line":383,"end_line":385,"hash":"894782d715cef236d6c32b7df4fab2d5481d2f88de716f0f9313a57e09321d32"},{"id":"func/CapabilityFactSnapshot.assert_integrity","name":"assert_integrity","line":387,"end_line":389,"hash":"75afad310caf2922de5b831d32e2f96066c79f39bc7eecbb151d566753bf8e37"},{"id":"func/CapabilityFactSnapshot.fact","name":"fact","line":391,"end_line":397,"hash":"228582583d3cfab8a76278fe160ea22486b0bf3b12a2c17ad6eda58ee2be6222"},{"id":"func/CapabilityFactSnapshot.contains_resource","name":"contains_resource","line":399,"end_line":401,"hash":"66e1392ead3181e146868a36a92df88be00f56cd203773d2535835ce895b69a7"},{"id":"func/CapabilityFactSnapshot.resource_matches_slot","name":"resource_matches_slot","line":403,"end_line":407,"hash":"46125ccb3f461c80aa87ee6608ca402e73a1c2d4d0dc650e926b3ebffe11dffe"},{"id":"func/CapabilityFactSnapshot.coherent_digest","name":"coherent_digest","line":410,"end_line":414,"hash":"9c8391eeb7851544c1724bc4e4737c2fc452e444c8846216d002cdd9a36b8364"},{"id":"func/capture_capability_snapshot","name":"capture_capability_snapshot","line":417,"end_line":435,"hash":"9309a3e31cbfbf757e27e494c44b44053e4d335287a4ec401291ce170efc4007"},{"id":"func/_normalize_semantic_order","name":"_normalize_semantic_order","line":467,"end_line":478,"hash":"43c9a4500f66cc53d085c97a8663bb79abd5544476faf5449f689828490d21d8"},{"id":"func/RejectedProjectionCandidate.ingress_binding_is_coherent","name":"ingress_binding_is_coherent","line":534,"end_line":541,"hash":"8dc055d8793df17494354377525202531ebe33463f95a423fd22fb2e89229012"},{"id":"func/ProjectedMapping.scope_matches_step","name":"scope_matches_step","line":570,"end_line":573,"hash":"10c144791767a15f83629d2da4a27772cd04435279878cb771d4e88016976bb1"},{"id":"func/ProjectedCandidate.verifiable_identity_and_derivation","name":"verifiable_identity_and_derivation","line":606,"end_line":637,"hash":"3c0d7ed833515cde2af785188c29ba0f0bea4eef526c79aafb2c33c9789b4f38"},{"id":"func/_require_unique_requirement_ids","name":"_require_unique_requirement_ids","line":663,"end_line":668,"hash":"6ce2d585d0651deb1cc10db84c0844fe15af4ddde37737e90d125af5736039ab"},{"id":"func/_verify_chain_identity","name":"_verify_chain_identity","line":671,"end_line":684,"hash":"68178532d05942f7f2b5be6d9ee4bfc8577f24a54adbb4dc3f7acf4311be328e"},{"id":"func/_verify_canonical_ingress","name":"_verify_canonical_ingress","line":687,"end_line":698,"hash":"f05bcd59bf0b8887563a3f66c22539e977d6e0faa84e5258df58f8c25de10e0a"},{"id":"func/_verify_execution_requirements_digest","name":"_verify_execution_requirements_digest","line":701,"end_line":708,"hash":"6930a5e22d13a6bb5145ae1543efa07371a12a00ca0bfc22c5acaea330e20431"},{"id":"func/_verify_candidate_identity","name":"_verify_candidate_identity","line":711,"end_line":715,"hash":"f5e92e01ff0c4182d0fd6603d18af7121d50160a27cd01a9787cece3a8d7f099"},{"id":"func/_expected_precondition_key_map","name":"_expected_precondition_key_map","line":718,"end_line":727,"hash":"af8eeff70a65ea6372ed8ced1587fbea4d12c6a32404010ef022b4af814ecb01"},{"id":"func/_verify_precondition_true","name":"_verify_precondition_true","line":730,"end_line":735,"hash":"bfebf617b38eed4f10ce153796fd224d2d9a9367c3b995ec14021a4c23d43064"},{"id":"func/_verify_precondition_results","name":"_verify_precondition_results","line":738,"end_line":750,"hash":"facd60e1139d03520a226b39306ef907514c9289b3a8311b793e6ddd08e9ab51"},{"id":"func/_verify_projected_mappings","name":"_verify_projected_mappings","line":753,"end_line":759,"hash":"dd4cd57f115a815218fd8fdf42bd9fb9864f14dbe383efc7f8ce71de3d360dd1"},{"id":"func/_selected_steps_for_projection","name":"_selected_steps_for_projection","line":762,"end_line":766,"hash":"cb9599762376eba3fe36f681d18d729734323538348cc08442c2e2ae156dd02e"},{"id":"func/_expected_complexity_inputs","name":"_expected_complexity_inputs","line":769,"end_line":787,"hash":"964ad3319bbcfb2da14360f3d939811b8d19d244ec1aed4d59224fbe4fbb2cab"},{"id":"func/_verify_complexity_inputs","name":"_verify_complexity_inputs","line":790,"end_line":802,"hash":"08f0b29ea76b2c1a589159139395e7c4fd2a910f0a1cd6184ec6a7d63d5c928e"},{"id":"func/_entry_point_resource_id","name":"_entry_point_resource_id","line":805,"end_line":806,"hash":"4d7cc7f08a896cdee7a6ba64fa294793b65234c89dba11f8a3f98d1215d3ffea"},{"id":"func/_integration_resource_id","name":"_integration_resource_id","line":809,"end_line":810,"hash":"194beb2ddad088ed82ee6178ff60809bd8330b4102bac738ae670e38cc694a12"},{"id":"func/_trust_boundary_resource_id","name":"_trust_boundary_resource_id","line":813,"end_line":816,"hash":"ec03d231e0bfbc5a5965add390bec32f802b86007bfbd3b3e47c7d1770218906"},{"id":"func/_tool_resource_id","name":"_tool_resource_id","line":819,"end_line":820,"hash":"6fcdd665343e41d8244f066956c0db766eceef7aaa9a89d35302c3fa45669be8"},{"id":"func/_output_surface_resource_id","name":"_output_surface_resource_id","line":823,"end_line":824,"hash":"7b8f3b243d567fceb0db5d4a78d878f6e5c7023c29f8e352d95bc852d9aa9bd8"},{"id":"func/_agent_internal_resource_id","name":"_agent_internal_resource_id","line":827,"end_line":830,"hash":"8782b94c9641b40e276355b60779741db00d8adcf7429e018f993379bf96a343"},{"id":"func/_resource_id","name":"_resource_id","line":843,"end_line":847,"hash":"da33bb7827a1662fc24a334920d48d92e909a9d28e860d47e4202b04fe51c926"},{"id":"func/_condition_facts","name":"_condition_facts","line":850,"end_line":855,"hash":"69e6009b9711da6636a0f23013a0f4116a23aa63359f6c0076ec41777460345e"},{"id":"func/_pattern_fact_conditions","name":"_pattern_fact_conditions","line":858,"end_line":863,"hash":"49930899448891136560609f2ed236442655e006fd6edece9804ad6c9276c406"},{"id":"func/required_fact_references","name":"required_fact_references","line":866,"end_line":876,"hash":"0fbcf8ab407fd950678563acdf6067831cf949b799387c643c61fa86b71316b1"},{"id":"func/_dedupe_sorted_facts","name":"_dedupe_sorted_facts","line":879,"end_line":884,"hash":"4bbb92637b8613d05eba887a2a87d18fd6e92bcd2195c44b2cc42fccc4aae947"},{"id":"func/_condition_fact_items","name":"_condition_fact_items","line":887,"end_line":896,"hash":"4fcf51ea9cbe43fa84066fa540f14c86f496b9f5ff225ff4cf7f3e6a2ce2ab11"},{"id":"func/_evaluate_projection_conditions","name":"_evaluate_projection_conditions","line":899,"end_line":918,"hash":"68ee50d680dee34f9612bb07cf4af83580ddc511054234d168f3c1f577ab5b2d"},{"id":"func/_evaluate_preconditions","name":"_evaluate_preconditions","line":921,"end_line":932,"hash":"da75fd2be04c9aa9be2d0f06e1f38943ae53c03a7a12ac8daacf05e8d1c0bcf0"},{"id":"func/_evaluate_precondition","name":"_evaluate_precondition","line":935,"end_line":948,"hash":"24523c9d145f5d986530b51133e40accba201a6563bbf3b9db39948d27bbb059"},{"id":"func/_content_pin","name":"_content_pin","line":951,"end_line":952,"hash":"c04b16b0c1deb90fffab0e3c95f8390047fafe9c9f4c520a11eaeca4e466b0cf"},{"id":"func/_chain_atlas_mappings","name":"_chain_atlas_mappings","line":955,"end_line":963,"hash":"2a2867d70df848d25d42d3bb6189d48f24807cc4ec0e9616b0027fee889549ab"},{"id":"func/_step_atlas_mappings","name":"_step_atlas_mappings","line":966,"end_line":972,"hash":"a63771fec5755f66a55b90c4847a80fc9b6ff6a0a2e573c76a8ea525ae9b2d2d"},{"id":"func/_projected_mappings","name":"_projected_mappings","line":975,"end_line":984,"hash":"833a9527c0aefc832fd5b3554f23317ae0eb8fd2e0badfa770929e4f34ae454f"},{"id":"func/_candidate_v2_id","name":"_candidate_v2_id","line":987,"end_line":1009,"hash":"dc1c9b5fcc647ca01f6fe1cc64a61cd0a5df1398f4e9ac4f1c8d3a97dd3739ff"},{"id":"func/_rejected_candidate_v2_id","name":"_rejected_candidate_v2_id","line":1012,"end_line":1032,"hash":"17a65a024ebc7fc8f8da97bf1c2771fcfb92f0856adb1663dbdf869ee1a3ac34"},{"id":"func/_pattern_pin","name":"_pattern_pin","line":1035,"end_line":1058,"hash":"c9e5e25c24dd8503dc9213d089faf20ecde0c506a8bcda261e8c8e29a86c6478"}]}
# mutate4py-manifest-end
