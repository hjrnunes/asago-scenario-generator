"""Deterministic authoritative-chain projection and candidate-v2 expansion.

This module is an explicit migration seam. It does not consume
``ScenarioSeed`` or the legacy attack-pattern catalogue shape. The generation
runner uses its readiness gate before crossing into authoritative projection,
and generation stages consume only :class:`ProjectedCandidate` instances from
this boundary.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from itertools import product
from typing import Annotated, Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from asago_scenario_generator.models.attack_pattern import (
    AgentInternalResourceReference,
    AllCondition,
    AnyCondition,
    AttackPattern,
    AuthoritativeFactReference,
    CanonicalAttackChain,
    CanonicalResourceReference,
    Condition,
    ConditionEvaluationResult,
    DirectInputControlRequirement,
    EntryPointResourceReference,
    EvaluatedFactEvidence,
    ExecutionRequirement,
    IntegrationResourceReference,
    MappingDecision,
    NotCondition,
    ObservationRequirement,
    OutputSurfaceResourceReference,
    ProjectionSnapshot,
    ResourceBinding,
    ResourceSlot,
    SecurityOutcomeAssertionRequirement,
    SourceInfluencePath,
    StateChangingToolFixtureRequirement,
    StepOmission,
    TaxonomyResolver,
    ToolResourceReference,
    TrustBoundaryResourceReference,
    UpstreamSourceInfluenceRequirement,
    compute_projection_digest,
    evaluate_condition,
    validate_attack_pattern,
    validate_projection_snapshot,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    is_attacker_accessible_ingress,
)

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ProjectionModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def canonical_json_bytes(value: Any) -> bytes:
    """Encode values using the projection digest contract's canonical JSON.

    Mapping keys and string values are recursively normalized to Unicode NFC;
    keys are sorted, separators are compact, non-ASCII text remains UTF-8,
    and non-finite floats are rejected.
    """
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
        normalized = _normalized_sequence(value)
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


#: Domain separator for execution-requirements digest computation.
EXECUTION_REQUIREMENTS_DIGEST_DOMAIN = (
    "asago-scenario-generator:execution-requirements:v1"
)

#: Domain separator for derivation context digest computation.
DERIVATION_CONTEXT_DIGEST_DOMAIN = "asago-scenario-generator:derivation-context:v1"


def compute_execution_requirements_digest(
    requirements: Any,
) -> str:
    """Compute the canonical digest for a sequence of execution requirements.

    Accepts model instances (with ``model_dump``) or pre-serialized dicts.
    """
    payloads: list[Any] = []
    for item in requirements:
        if hasattr(item, "model_dump"):
            payloads.append(item.model_dump(mode="json"))
        else:
            payloads.append(item)
    return _digest(EXECUTION_REQUIREMENTS_DIGEST_DOMAIN, payloads)


def compute_derivation_context_digest(
    projection_digest: str,
    pattern_id: str,
    ingress_controllability: str,
) -> str:
    """Compute the derivation context digest binding controllability.

    Binds projection_digest + pattern_id + ingress_controllability into a
    verified immutable digest so a caller cannot flip controllability and
    re-sign arbitrary requirements.
    """
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


def _requirement_id(prefix: str, *components: str) -> str:
    """Generate an injective, stable requirement ID from components.

    Composite requirement IDs must be collision-free even when individual
    components contain dots (e.g. step ``a`` + slot ``b.c`` vs step ``a.b``
    + slot ``c``).  Dot concatenation is ambiguous; hashing is not
    guaranteed injective.  Instead, each component is encoded as its full
    UTF-8 hexadecimal representation, and the encoded components are joined
    with ``:`` — a character that never appears in hexadecimal output.
    This makes the mapping ``(prefix, *components) → ID`` injective: the
    component list can be recovered by splitting on ``:`` and hex-decoding
    each segment, so distinct inputs always produce distinct IDs.

    IDs are **unbounded in length**: hex encoding doubles each component's
    byte length, so long step IDs or slot IDs produce long requirement IDs.
    Downstream persistence must use unbounded text columns or establish a
    future explicit bound.  No bounded consumer exists in candidate-v2.
    """
    encoded = ":".join(c.encode("utf-8").hex() for c in components)
    return f"{prefix}.{encoded}"


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


def _resource_checker_for(
    reference: CanonicalResourceReference,
    checkers: tuple[tuple[type, Callable], ...],
) -> Callable | None:
    """Return the first checker whose reference type matches the instance."""
    for ref_type, checker in checkers:
        if isinstance(reference, ref_type):
            return checker
    return None


def _entry_point_contained(
    reference: EntryPointResourceReference, profile: CapabilityProfile
) -> bool:
    """True when the entry point reference resolves in the profile."""
    return profile.resolve_entry_point(reference.entry_point_id) is not None


def _tool_contained(
    reference: ToolResourceReference, profile: CapabilityProfile
) -> bool:
    """True when the tool reference resolves in the profile."""
    return profile.resolve_tool(reference.tool_id) is not None


def _integration_contained(
    reference: IntegrationResourceReference, profile: CapabilityProfile
) -> bool:
    """True when the integration reference resolves in the profile."""
    return profile.resolve_integration(reference.integration_id) is not None


def _trust_boundary_contained(
    reference: TrustBoundaryResourceReference, profile: CapabilityProfile
) -> bool:
    """True when the trust-boundary reference resolves in the profile."""
    return profile.resolve_trust_boundary(reference.trust_boundary_id) is not None


def _output_surface_contained(
    reference: OutputSurfaceResourceReference, profile: CapabilityProfile
) -> bool:
    """True when the output-surface entry point resolves in the profile."""
    return profile.resolve_output_surface(reference.entry_point_id) is not None


def _agent_internal_contained(
    reference: AgentInternalResourceReference, profile: CapabilityProfile
) -> bool:
    """True when the profiled agent exposes its intrinsic working state.

    Every validated capability profile has the reasoning zone and therefore
    exactly one intrinsic agent working-state resource.  This remains a
    distinct typed binding: it is never substituted with a tool, integration,
    entry point, or trust boundary.
    """
    return "reasoning" in profile.zones_active


_RESOURCE_CONTAINED_CHECKERS: tuple[tuple[type, Callable], ...] = (
    (EntryPointResourceReference, _entry_point_contained),
    (ToolResourceReference, _tool_contained),
    (IntegrationResourceReference, _integration_contained),
    (TrustBoundaryResourceReference, _trust_boundary_contained),
    (OutputSurfaceResourceReference, _output_surface_contained),
    (AgentInternalResourceReference, _agent_internal_contained),
)


def _resource_contained(
    reference: CanonicalResourceReference, profile: CapabilityProfile
) -> bool:
    """Resolve whether the typed resource exists in the capability profile."""
    checker = _resource_checker_for(reference, _RESOURCE_CONTAINED_CHECKERS)
    return False if checker is None else checker(reference, profile)


def _assert_snapshot_facts_uniquely_sorted(
    facts: tuple[EvaluatedFactEvidence, ...],
) -> None:
    """Require snapshot facts to be uniquely sorted by fact reference."""
    keys = [_fact_key(item.fact) for item in facts]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise ValueError("snapshot facts must be uniquely sorted by reference")


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


class CapabilityFactSnapshot(ProjectionModel):
    """One immutable, content-addressed pre-LLM profile/fact reading."""

    profile: CapabilityProfile
    facts: tuple[EvaluatedFactEvidence, ...]
    snapshot_digest: Digest

    @property
    def capability_fact_snapshot_digest(self) -> str:
        """Implement the merged :class:`CapabilitySnapshotResolver` pin."""
        self.assert_integrity()
        return self.snapshot_digest

    def assert_integrity(self) -> None:
        """Fail closed if a nested mutable profile was changed after capture."""
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
        return reference in _references_for_slot(
            slot,
            self,
            initial_ingress=slot.purpose == "initial_ingress",
        )

    @model_validator(mode="after")
    def coherent_digest(self) -> CapabilityFactSnapshot:
        _assert_snapshot_facts_uniquely_sorted(self.facts)
        if self.snapshot_digest != _compute_snapshot_digest(self.profile, self.facts):
            raise ValueError("snapshot_digest does not match capability/fact content")
        return self


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
    """Dump items to JSON and order them by a stable top-level field."""
    return sorted(
        (item.model_dump(mode="json") for item in items),
        key=lambda item: item[key_field],
    )


def _sorted_canonical(items: Iterable[Any]) -> list[dict[str, Any]]:
    """Dump items to JSON and order them by canonical JSON bytes."""
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
    code: Literal["candidate_budget_exhausted", "derivation_work_exhausted"]
    pattern_id: str
    total_compatible_bindings: int = Field(ge=0)
    emitted_bindings: int = Field(ge=0)


class ProjectedMapping(ProjectionModel):
    scope: Literal["chain", "step"]
    step_id: str | None = None
    mapping: MappingDecision

    @model_validator(mode="after")
    def scope_matches_step(self) -> ProjectedMapping:
        if (self.scope == "step") != (self.step_id is not None):
            raise ValueError("step mappings require step_id; chain mappings forbid it")
        return self


class CandidateComplexityInputs(ProjectionModel):
    """Policy-free inputs reserved for the future cmps.7 complexity policy."""

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
    def verifiable_identity_and_derivation(self) -> ProjectedCandidate:
        chain = self.projection.source_chain
        _require_unique_requirement_ids(self.execution_requirements)
        _verify_chain_identity(
            self.pattern_id,
            self.chain_id,
            self.chain_semantic_revision,
            self.chain_semantic_digest,
            chain,
        )
        _verify_canonical_ingress(self.projection, chain, self.canonical_ingress)
        _verify_execution_requirements_digest(
            self.execution_requirements, self.execution_requirements_digest
        )
        _verify_candidate_identity(self.candidate_id, self.pattern_id, self.projection)
        expected_preconditions = _expected_precondition_key_map(
            chain, self.projection.selected_step_ids
        )
        _verify_precondition_results(expected_preconditions, self.precondition_results)
        _verify_projected_mappings(
            self.projected_mappings, chain, self.projection.selected_step_ids
        )
        _verify_complexity_inputs(
            self.complexity_inputs, chain, self.projection, self.execution_requirements
        )
        return self


def _require_unique_requirement_ids(
    execution_requirements: tuple[ExecutionRequirement, ...],
) -> None:
    """Require unique execution requirement IDs on the candidate."""
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
    """Require the candidate chain identity to match its projection."""
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
    """Require the canonical ingress to match the projection binding."""
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
    """Require the digest to match the execution requirements."""
    expected_requirements_digest = compute_execution_requirements_digest(
        execution_requirements
    )
    if execution_requirements_digest != expected_requirements_digest:
        raise ValueError("execution_requirements_digest does not match requirements")


def _verify_candidate_identity(
    candidate_id: str, pattern_id: str, projection: ProjectionSnapshot
) -> None:
    """Require the candidate ID to match its candidate-v2 identity inputs."""
    if candidate_id != _candidate_v2_id(pattern_id, projection):
        raise ValueError("candidate_id does not match candidate-v2 identity inputs")


def _expected_precondition_key_map(
    chain: CanonicalAttackChain, selected_step_ids: tuple[str, ...]
) -> dict[tuple[str, str], Condition]:
    """Build the expected precondition key map for the selected steps."""
    selected = set(selected_step_ids)
    return {
        (step.step_id, precondition.condition_id): precondition.condition
        for step in chain.steps
        if step.step_id in selected
        for precondition in step.preconditions
    }


def _verify_precondition_true(condition: Condition, supplied: Any) -> None:
    """Require one supplied precondition result to evaluate true."""
    if (
        supplied.result != "true"
        or evaluate_condition(condition, supplied.evidence) != "true"
    ):
        raise ValueError("projected candidate preconditions must evaluate true")


def _verify_precondition_results(
    expected_preconditions: dict[tuple[str, str], Condition],
    precondition_results: tuple[PreconditionEvaluationResult, ...],
) -> None:
    """Require unique, exactly-covering, true precondition results."""
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
    """Require the projected mappings to match the authoritative chain."""
    if projected_mappings != _projected_mappings(chain, selected_step_ids):
        raise ValueError("projected mappings are incomplete or non-authoritative")


def _selected_steps_for_projection(
    chain: CanonicalAttackChain, selected_step_ids: tuple[str, ...]
) -> list[Any]:
    """Collect the chain steps selected by the projection."""
    selected = set(selected_step_ids)
    return [step for step in chain.steps if step.step_id in selected]


def _expected_complexity_inputs(
    selected_steps: list[Any],
    projection: ProjectionSnapshot,
    execution_requirements: tuple[ExecutionRequirement, ...],
) -> CandidateComplexityInputs:
    """Compute the complexity inputs a candidate must carry."""
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
    """Require the complexity inputs to match the projected candidate."""
    selected_steps = _selected_steps_for_projection(chain, projection.selected_step_ids)
    expected_complexity = _expected_complexity_inputs(
        selected_steps, projection, execution_requirements
    )
    if complexity_inputs != expected_complexity:
        raise ValueError("complexity inputs do not match projected candidate")


def _entry_point_resource_id(reference: EntryPointResourceReference) -> str:
    """Extract the entry point id from an entry point reference."""
    return reference.entry_point_id


def _integration_resource_id(reference: IntegrationResourceReference) -> str:
    """Extract the integration id from an integration reference."""
    return reference.integration_id


def _trust_boundary_resource_id(
    reference: TrustBoundaryResourceReference,
) -> str:
    """Extract the trust-boundary id from a trust-boundary reference."""
    return reference.trust_boundary_id


def _tool_resource_id(reference: ToolResourceReference) -> str:
    """Extract the tool id from a tool reference."""
    return reference.tool_id


def _output_surface_resource_id(reference: OutputSurfaceResourceReference) -> str:
    """Extract the entry point id from an output-surface reference."""
    return reference.entry_point_id


def _agent_internal_resource_id(
    reference: AgentInternalResourceReference,
) -> str:
    """Return the intrinsic id of the agent working-state singleton."""
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


_SOURCE_RELATION_GUIDANCE = (
    "Review the explicit ingress_zone or trust-boundary declaration."
)


def _source_relation_issue(
    pattern_id: str,
    detail: str,
    *,
    source_id: str | None = None,
    boundary_id: str | None = None,
    target_ingress_id: str | None = None,
    canonical_ingress_id: str | None = None,
    expected_target_zone: str | None = None,
    actual_boundary_zones: str | None = None,
    expected_source_kind: str | None = None,
    actual_binding_kind: str | None = None,
) -> ProjectionIssue:
    """Build the consistent typed failure for an invalid source relation."""
    return ProjectionIssue(
        code="source_influence_relation_infeasible",
        pattern_id=pattern_id,
        detail=detail,
        source_id=source_id,
        boundary_id=boundary_id,
        target_ingress_id=target_ingress_id,
        canonical_ingress_id=canonical_ingress_id,
        expected_target_zone=expected_target_zone,
        actual_boundary_zones=actual_boundary_zones,
        expected_source_kind=expected_source_kind,
        actual_binding_kind=actual_binding_kind,
        guidance=_SOURCE_RELATION_GUIDANCE,
    )


def _source_influence_links(
    chain: CanonicalAttackChain, selected_ids: set[str]
) -> tuple[Any, ...]:
    """Collect the selected steps' source-influence links in chain order."""
    return tuple(
        link
        for step in chain.steps
        if step.step_id in selected_ids
        for link in step.resource_links
        if link.role == "source_influence"
    )


def _source_ingress_relation_guard(
    pattern_id: str,
    ingress: Any,
    ingress_ref: EntryPointResourceReference,
    links: tuple[Any, ...],
) -> tuple[tuple[SourceInfluencePath, ...], ProjectionIssue | None] | None:
    """Early-return guards for direct ingress and missing/ambiguous paths.

    Returns ``None`` when preflight continues to relation resolution.
    """
    # Preserve the legacy structural use of source-influence links on a
    # directly controlled ingress.  Relation preflight applies to indirect
    # ingress, where source provenance is the activation contract.
    if ingress.effective_controllability == "direct":
        return (), None
    if not links:
        return (), _source_relation_issue(
            pattern_id,
            "indirect canonical ingress has no selected source-influence path",
            target_ingress_id=ingress_ref.entry_point_id,
            canonical_ingress_id=ingress_ref.entry_point_id,
            expected_target_zone=ingress.effective_ingress_zone,
        )
    if len(links) != 1:
        return (), _source_relation_issue(
            pattern_id,
            (
                "candidate requires exactly one selected source-to-boundary-"
                f"to-ingress path, found {len(links)}"
            ),
            target_ingress_id=ingress_ref.entry_point_id,
            canonical_ingress_id=ingress_ref.entry_point_id,
            expected_target_zone=ingress.effective_ingress_zone,
        )
    return None


def _source_relation_refs(
    bindings_by_slot: dict[str, CanonicalResourceReference], link: Any
) -> tuple[Any, Any, Any]:
    """Resolve the source, boundary, and target bindings for one link."""
    return (
        bindings_by_slot.get(link.slot_id),
        bindings_by_slot.get(str(link.trust_boundary_slot_id)),
        bindings_by_slot.get(str(link.target_ingress_slot_id)),
    )


def _resource_id_or_none(reference: Any) -> str | None:
    """Resolve the stable resource id, mapping absence to None."""
    if reference is None:
        return None
    return _resource_id(reference)


def _source_influence_expected_kind(chain: CanonicalAttackChain, link: Any) -> str:
    """Resolve the declared source identity kind, falling back to the slot."""
    expected_kind = link.source_identity_kind
    if expected_kind is None:
        source_slot = next(
            slot for slot in chain.resource_slots if slot.slot_id == link.slot_id
        )
        expected_kind = source_slot.kind
    return expected_kind


def _source_relation_boundary(
    snapshot: CapabilityFactSnapshot, boundary_ref: Any
) -> Any | None:
    """Resolve the trust boundary only when the binding is typed."""
    if isinstance(boundary_ref, TrustBoundaryResourceReference):
        return snapshot.profile.resolve_trust_boundary(boundary_ref.trust_boundary_id)
    return None


def _boundary_zones_or_none(boundary: Any) -> str | None:
    """Format the boundary zone span, mapping absence to None."""
    if boundary is None:
        return None
    return f"{boundary.from_zone}->{boundary.to_zone}"


def _source_identity_kind_detail(
    actual_kind: str | None, expected_kind: str
) -> str | None:
    """Detail when the concrete binding kind does not match the link."""
    if actual_kind != expected_kind:
        return "source identity kind does not match the concrete binding"
    return None


def _source_binding_kind_detail(source_ref: Any) -> str | None:
    """Detail when the source binding is neither entry point nor integration."""
    if not isinstance(
        source_ref, (EntryPointResourceReference, IntegrationResourceReference)
    ):
        return "source binding is not an entry point or integration"
    return None


def _source_entry_point_detail(
    source_ref: Any,
    ingress_ref: EntryPointResourceReference,
    snapshot: CapabilityFactSnapshot,
) -> str | None:
    """Detail when the entry-point source is not influenceable or not distinct."""
    if not isinstance(source_ref, EntryPointResourceReference):
        return None
    source = snapshot.profile.resolve_entry_point(source_ref.entry_point_id)
    if source is None or not is_attacker_accessible_ingress(
        source, snapshot.profile.zones_active
    ):
        return "entry-point source is not attacker-influenceable"
    if source_ref.entry_point_id == ingress_ref.entry_point_id:
        return "source entry point must be distinct from target ingress"
    return None


def _source_boundary_detail(
    boundary: Any,
    expected_zone: str,
    target_id: str | None,
    ingress_id: str,
) -> str | None:
    """Detail when the boundary or target does not support the relation."""
    if boundary is None:
        return "source-influence boundary is absent from reviewed declarations"
    if boundary.confidence.value == "hypothesized":
        return "source-influence boundary is not a reviewed declaration"
    if boundary.to_zone != expected_zone:
        return "trust-boundary destination zone does not match target ingress"
    if target_id != ingress_id:
        return "source-influence target is not the canonical ingress binding"
    return None


def _source_relation_issue_detail(
    source_ref: Any,
    actual_kind: str | None,
    expected_kind: str,
    ingress_ref: EntryPointResourceReference,
    snapshot: CapabilityFactSnapshot,
    boundary: Any,
    target_id: str | None,
    ingress_id: str,
) -> str | None:
    """Combine the identity and boundary cascades, boundary cascade last."""
    detail = _source_identity_kind_detail(actual_kind, expected_kind)
    if detail is None:
        detail = _source_binding_kind_detail(source_ref)
    if detail is None:
        detail = _source_entry_point_detail(source_ref, ingress_ref, snapshot)
    boundary_detail = _source_boundary_detail(
        boundary,
        snapshot.profile.resolve_entry_point(
            ingress_ref.entry_point_id
        ).effective_ingress_zone,
        target_id,
        ingress_id,
    )
    if boundary_detail is not None:
        return boundary_detail
    return detail


def _source_relation_resolution(
    pattern_id: str,
    ingress: Any,
    ingress_ref: EntryPointResourceReference,
    link: Any,
    chain: CanonicalAttackChain,
    bindings_by_slot: dict[str, CanonicalResourceReference],
    snapshot: CapabilityFactSnapshot,
) -> tuple[tuple[SourceInfluencePath, ...], ProjectionIssue | None]:
    """Resolve the single source-influence path or return the typed issue."""
    source_ref, boundary_ref, target_ref = _source_relation_refs(bindings_by_slot, link)
    source_id = _resource_id_or_none(source_ref)
    boundary_id = _resource_id_or_none(boundary_ref)
    target_id = _resource_id_or_none(target_ref)
    expected_kind = _source_influence_expected_kind(chain, link)
    actual_kind = source_ref.kind if source_ref is not None else None
    boundary = _source_relation_boundary(snapshot, boundary_ref)
    actual_boundary_zones = _boundary_zones_or_none(boundary)
    issue_detail = _source_relation_issue_detail(
        source_ref,
        actual_kind,
        expected_kind,
        ingress_ref,
        snapshot,
        boundary,
        target_id,
        ingress_ref.entry_point_id,
    )
    if issue_detail is not None:
        return (), _source_relation_issue(
            pattern_id,
            detail=issue_detail,
            source_id=source_id,
            boundary_id=boundary_id,
            target_ingress_id=target_id,
            canonical_ingress_id=ingress_ref.entry_point_id,
            expected_target_zone=ingress.effective_ingress_zone,
            actual_boundary_zones=actual_boundary_zones,
            expected_source_kind=expected_kind,
            actual_binding_kind=actual_kind,
        )
    assert boundary is not None
    assert target_id is not None
    path = SourceInfluencePath(
        source_identity_kind=expected_kind,
        source_id=source_id,
        boundary_id=boundary_id,
        target_ingress_id=target_id,
        expected_target_zone=ingress.effective_ingress_zone,
        boundary_zones=actual_boundary_zones,
    )
    return (path,), None


def _source_influence_relation(
    pattern_id: str,
    chain: CanonicalAttackChain,
    selected: tuple[str, ...],
    bindings: tuple[ResourceBinding, ...],
    snapshot: CapabilityFactSnapshot,
) -> tuple[tuple[SourceInfluencePath, ...], ProjectionIssue | None]:
    """Resolve exactly one source relation from immutable projection bindings."""
    bindings_by_slot = {item.slot_id: item.resource_ref for item in bindings}
    links = _source_influence_links(chain, set(selected))
    ingress_ref = bindings_by_slot[chain.initial_ingress_slot_id]
    if not isinstance(ingress_ref, EntryPointResourceReference):
        return (), _source_relation_issue(
            pattern_id,
            "canonical ingress is not an entry-point binding",
            canonical_ingress_id=_resource_id(ingress_ref),
        )
    ingress = snapshot.profile.resolve_entry_point(ingress_ref.entry_point_id)
    assert ingress is not None

    guard = _source_ingress_relation_guard(pattern_id, ingress, ingress_ref, links)
    if guard is not None:
        return guard
    return _source_relation_resolution(
        pattern_id,
        ingress,
        ingress_ref,
        links[0],
        chain,
        bindings_by_slot,
        snapshot,
    )


def _validate_source_influence_paths(
    candidate: ProjectedCandidate,
    snapshot: CapabilityFactSnapshot,
) -> None:
    """Re-derive the authoritative relation at the persistence boundary.

    Projection generation and serialized-candidate validation must share the
    same relation rule.  Digest and candidate-identity checks prove that a
    payload is self-consistent, but they do not prove that its derived path
    matches the immutable bindings and profile.
    """
    expected_paths, issue = _source_influence_relation(
        candidate.pattern_id,
        candidate.projection.source_chain,
        candidate.projection.selected_step_ids,
        candidate.projection.bindings,
        snapshot,
    )
    if issue is not None:
        raise ValueError(
            f"candidate source-influence relation is infeasible: {issue.detail}"
        )
    if candidate.projection.source_influence_paths != expected_paths:
        raise ValueError(
            "candidate source-influence paths do not match authoritative "
            "bindings and profile"
        )


class ProjectionBatch(ProjectionModel):
    """Complete deterministic result, including typed non-candidate outcomes."""

    capability_fact_snapshot_digest: Digest
    candidates: tuple[ProjectedCandidate, ...]
    infeasibilities: tuple[ProjectionIssue, ...]
    limitations: tuple[ProjectionLimitation, ...]
    # Coverage targets that could not be reserved due to budget exhaustion
    # (cmps.4 blocker 3).  Empty when coverage_target_ids is not provided.
    unreserved_coverage_targets: tuple[str, ...] = ()
    # Coverage targets with no compatible projection at all (structural
    # infeasibility — distinct from budget-omitted).  Empty when
    # coverage_target_ids is not provided (cmps.4 blocker 3).
    infeasible_coverage_targets: tuple[str, ...] = ()


def _condition_facts(
    condition: Condition,
) -> tuple[AuthoritativeFactReference, ...]:
    """Flatten a condition tree into its uniquely sorted fact references."""
    return _dedupe_sorted_facts(_condition_fact_items(condition))


def _condition_fact_items(condition: Condition) -> list[AuthoritativeFactReference]:
    """Flatten a condition tree into fact references in traversal order."""
    if isinstance(condition, (AllCondition, AnyCondition)):
        return [
            fact
            for operand in condition.operands
            for fact in _condition_fact_items(operand)
        ]
    if isinstance(condition, NotCondition):
        return list(_condition_fact_items(condition.operand))
    return [condition.fact]


def _dedupe_sorted_facts(
    items: list[AuthoritativeFactReference] | tuple[AuthoritativeFactReference, ...],
) -> tuple[AuthoritativeFactReference, ...]:
    """Deduplicate fact references by key and order them canonically."""
    return tuple(
        {_fact_key(item): item for item in items}[key]
        for key in sorted({_fact_key(item): item for item in items})
    )


class ProjectionReadinessReport(ProjectionModel):
    """Preflight result for architecture and qualification evidence."""

    ready: bool
    required_resource_categories: tuple[str, ...] = ()
    missing_resource_categories: tuple[str, ...] = ()
    required_facts: tuple[str, ...] = ()
    missing_facts: tuple[str, ...] = ()
    pattern_ids: tuple[str, ...] = ()


class ProjectionReadinessError(ValueError):
    """Raised before projection when reviewed architecture evidence is absent."""

    def __init__(self, report: ProjectionReadinessReport) -> None:
        self.report = report
        details: list[str] = []
        if report.missing_resource_categories:
            details.append(
                "missing resource categories "
                + ", ".join(report.missing_resource_categories)
                + "; supply a reviewed architecture with '--profile'"
            )
        if report.missing_facts:
            details.append(
                "missing qualification facts "
                + ", ".join(report.missing_facts)
                + "; supply authoritative readings with '--qualification-facts'"
            )
        super().__init__(
            "Projection readiness failed before projection: "
            + "; ".join(details)
            + ". No architecture enrichment workflow was launched."
        )


_RESOURCE_CATEGORY_BY_KIND = {
    "entry_point": "entry_points",
    "tool": "tool_inventory",
    "integration": "external_integrations",
    "trust_boundary": "trust_boundaries",
    "output_surface": "output_surfaces",
    "agent_internal": "agent_internal",
}


def _required_resource_categories(
    patterns: Sequence[AttackPattern],
) -> tuple[str, ...]:
    required_kinds = {
        slot.kind
        for pattern in patterns
        for slot in pattern.canonical_chain.resource_slots
    }
    return tuple(sorted(_RESOURCE_CATEGORY_BY_KIND[kind] for kind in required_kinds))


def _available_resource_categories(
    profile: CapabilityProfile,
) -> dict[str, bool]:
    return {
        "entry_points": bool(profile.entry_points),
        "tool_inventory": bool(profile.tool_inventory),
        "external_integrations": bool(profile.external_integrations),
        "trust_boundaries": bool(profile.trust_boundaries),
        "output_surfaces": any(
            item.direction in ("output", "bidirectional")
            for item in profile.entry_points
        ),
        "agent_internal": "reasoning" in profile.zones_active,
    }


def _pattern_conditions(pattern: AttackPattern) -> Iterable[Condition]:
    for step in pattern.canonical_chain.steps:
        if step.condition is not None:
            yield step.condition
        yield from (precondition.condition for precondition in step.preconditions)


def _readiness_fact_references(
    patterns: Sequence[AttackPattern],
) -> dict[str, AuthoritativeFactReference]:
    fact_refs: dict[str, AuthoritativeFactReference] = {}
    for pattern in patterns:
        for condition in _pattern_conditions(pattern):
            for reference in _condition_facts(condition):
                fact_refs[_fact_key(reference)] = reference
    return fact_refs


def required_fact_references(
    patterns: Sequence[AttackPattern],
) -> tuple[AuthoritativeFactReference, ...]:
    """Return the complete canonical fact inventory used by readiness."""
    references = _readiness_fact_references(patterns)
    return tuple(references[key] for key in sorted(references))


def _required_fact_ids(
    fact_refs: dict[str, AuthoritativeFactReference],
) -> tuple[str, ...]:
    return tuple(sorted(reference.fact_id for reference in fact_refs.values()))


def _missing_fact_ids(
    fact_refs: dict[str, AuthoritativeFactReference],
    snapshot: CapabilityFactSnapshot,
) -> tuple[str, ...]:
    return tuple(
        sorted(
            reference.fact_id
            for reference in fact_refs.values()
            if (
                (evidence := snapshot.fact(reference)) is None
                or evidence.status == "unknown"
            )
        )
    )


def check_projection_readiness(
    patterns: Sequence[AttackPattern],
    snapshot: CapabilityFactSnapshot,
) -> ProjectionReadinessReport:
    """Check selected patterns against the immutable profile/fact snapshot."""
    required_categories = _required_resource_categories(patterns)
    available_by_category = _available_resource_categories(snapshot.profile)
    missing_categories = tuple(
        category
        for category in required_categories
        if not available_by_category[category]
    )
    fact_refs = _readiness_fact_references(patterns)
    required_facts = _required_fact_ids(fact_refs)
    missing_facts = _missing_fact_ids(fact_refs, snapshot)
    return ProjectionReadinessReport(
        ready=not missing_categories and not missing_facts,
        required_resource_categories=required_categories,
        missing_resource_categories=missing_categories,
        required_facts=required_facts,
        missing_facts=missing_facts,
        pattern_ids=tuple(sorted(pattern.id for pattern in patterns)),
    )


def ensure_projection_readiness(
    patterns: Sequence[AttackPattern],
    snapshot: CapabilityFactSnapshot,
) -> ProjectionReadinessReport:
    """Raise actionable guidance instead of converting missing evidence to zero candidates."""
    report = check_projection_readiness(patterns, snapshot)
    if not report.ready:
        raise ProjectionReadinessError(report)
    return report


def _evaluate_projection_conditions(
    pattern: AttackPattern, snapshot: CapabilityFactSnapshot
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
    snapshot: CapabilityFactSnapshot,
) -> tuple[PreconditionEvaluationResult, ...]:
    selected = set(selected_step_ids)
    results: list[PreconditionEvaluationResult] = []
    for step in pattern.canonical_chain.steps:
        if step.step_id not in selected:
            continue
        for precondition in step.preconditions:
            evidence = tuple(
                snapshot.fact(reference)
                or EvaluatedFactEvidence(fact=reference, status="unknown", value=None)
                for reference in _condition_facts(precondition.condition)
            )
            results.append(
                PreconditionEvaluationResult(
                    step_id=step.step_id,
                    condition_id=precondition.condition_id,
                    result=evaluate_condition(precondition.condition, evidence),
                    evidence=evidence,
                )
            )
    return tuple(results)


def _entry_point_reference_allowed(
    item: Any,
    active_zones: set[str],
    *,
    initial_ingress: bool,
    attacker_influence_required: bool,
) -> bool:
    """Filter entry points by the slot's attacker-accessibility requirement."""
    if initial_ingress or attacker_influence_required:
        return is_attacker_accessible_ingress(item, active_zones)
    return True


def _entry_point_references(
    profile: CapabilityProfile,
    *,
    initial_ingress: bool,
    attacker_influence_required: bool,
) -> list[CanonicalResourceReference]:
    """Build entry-point references, applying accessibility filtering."""
    active_zones = set(profile.zones_active)
    return [
        EntryPointResourceReference(
            kind="entry_point", entry_point_id=item.entry_point_id
        )
        for item in profile.entry_points
        if _entry_point_reference_allowed(
            item,
            active_zones,
            initial_ingress=initial_ingress,
            attacker_influence_required=attacker_influence_required,
        )
    ]


def _tool_references(
    profile: CapabilityProfile,
) -> list[CanonicalResourceReference]:
    """Build tool references from the inventory."""
    return [
        ToolResourceReference(kind="tool", tool_id=item.tool_id)
        for item in profile.tool_inventory or ()
    ]


def _integration_references(
    profile: CapabilityProfile,
) -> list[CanonicalResourceReference]:
    """Build integration references from the inventory."""
    return [
        IntegrationResourceReference(
            kind="integration", integration_id=item.integration_id
        )
        for item in profile.external_integrations or ()
    ]


def _output_surface_references(
    profile: CapabilityProfile,
) -> list[CanonicalResourceReference]:
    """Build output-surface references from the entry points."""
    return [
        OutputSurfaceResourceReference(
            kind="output_surface", entry_point_id=item.entry_point_id
        )
        for item in profile.entry_points
        if item.direction in ("output", "bidirectional")
    ]


def _agent_internal_references(
    profile: CapabilityProfile,
) -> list[CanonicalResourceReference]:
    """Build the intrinsic agent working-state reference, if present."""
    # Agent working state is an intrinsic singleton of every validated
    # profile (which must include the reasoning zone), not an adapter
    # inventory item.  Keep its reference typed and identity-free.
    if "reasoning" in profile.zones_active:
        return [AgentInternalResourceReference(kind="agent_internal")]
    return []


def _trust_boundary_references(
    profile: CapabilityProfile,
) -> list[CanonicalResourceReference]:
    """Build trust-boundary references from the inventory."""
    return [
        TrustBoundaryResourceReference(
            kind="trust_boundary", trust_boundary_id=item.trust_boundary_id
        )
        for item in profile.trust_boundaries or ()
    ]


_REFERENCE_BUILDERS: dict[str, Any] = {
    "entry_point": _entry_point_references,
    "tool": _tool_references,
    "integration": _integration_references,
    "output_surface": _output_surface_references,
    "agent_internal": _agent_internal_references,
}


def _references_for_kind(
    kind: str,
    snapshot: CapabilityFactSnapshot,
    *,
    initial_ingress: bool,
    attacker_influence_required: bool,
) -> tuple[CanonicalResourceReference, ...]:
    profile = snapshot.profile
    builder = _REFERENCE_BUILDERS.get(kind, _trust_boundary_references)
    if kind == "entry_point":
        refs = builder(
            profile,
            initial_ingress=initial_ingress,
            attacker_influence_required=attacker_influence_required,
        )
    else:
        refs = builder(profile)
    return tuple(sorted(refs, key=_resource_key))


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
    if integration is None:  # pragma: no cover - built from this snapshot
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
    if entry_point is None:  # pragma: no cover - built from this snapshot
        return False
    if _restriction_blocks(
        entry_point.entry_point_type, slot.allowed_entry_point_types
    ):
        return False
    if _restriction_blocks(entry_point.direction, slot.allowed_entry_point_directions):
        return False
    if _restriction_blocks(
        entry_point.controllability, slot.allowed_entry_point_controllability
    ):
        return False
    if _restriction_blocks(
        entry_point.effective_ingress_zone, slot.allowed_entry_point_ingress_zones
    ):
        return False
    return True


def _trust_boundary_matches_slot(
    reference: TrustBoundaryResourceReference,
    slot: ResourceSlot,
    snapshot: CapabilityFactSnapshot,
) -> bool:
    """True when the trust boundary satisfies the slot's typed constraints."""
    boundary = snapshot.profile.resolve_trust_boundary(reference.trust_boundary_id)
    if boundary is None:  # pragma: no cover - built from this snapshot
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


def _references_for_slot(
    slot: ResourceSlot,
    snapshot: CapabilityFactSnapshot,
    *,
    initial_ingress: bool,
) -> tuple[CanonicalResourceReference, ...]:
    """Resolve one slot using only its typed, adapter-neutral constraints."""
    allowed_resource_ids = set(slot.allowed_resource_ids)
    references = _references_for_kind(
        slot.kind,
        snapshot,
        initial_ingress=initial_ingress,
        attacker_influence_required=(
            slot.kind == "entry_point" and slot.purpose == "supporting"
        ),
    )
    return tuple(
        reference
        for reference in references
        if _resource_id_allowed(reference, allowed_resource_ids)
        and _slot_reference_compatible(reference, slot, snapshot)
    )


def _combination_satisfies_distinctness(
    slots: tuple[ResourceSlot, ...],
    resources: tuple[CanonicalResourceReference, ...],
) -> bool:
    resources_by_slot = {
        slot.slot_id: resource for slot, resource in zip(slots, resources, strict=True)
    }
    return all(
        resources_by_slot[slot.slot_id] != resources_by_slot[other_slot_id]
        for slot in slots
        for other_slot_id in slot.distinct_from_slot_ids
    )


def _iter_compatible_combinations(
    slots: tuple[ResourceSlot, ...],
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
) -> Iterable[tuple[CanonicalResourceReference, ...]]:
    for resources in _iter_coverage_first_combinations(options):
        if _combination_satisfies_distinctness(slots, resources):
            yield resources


def _count_compatible_combinations(
    slots: tuple[ResourceSlot, ...],
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
) -> int:
    """Count valid bindings without expanding unrelated Cartesian dimensions."""
    edges = _distinctness_edges(slots)
    constrained = _constrained_indexes(edges)
    total = _unconstrained_product(options, constrained)
    for component in _constrained_components(constrained, edges):
        total *= _count_component_assignments(component, edges, options)
    return total


def _distinctness_edges(
    slots: tuple[ResourceSlot, ...],
) -> set[frozenset[int]]:
    """Index slot pairs that must receive pairwise-distinct resources."""
    index_by_slot = {slot.slot_id: index for index, slot in enumerate(slots)}
    return {
        frozenset((index, index_by_slot[other_slot_id]))
        for index, slot in enumerate(slots)
        for other_slot_id in slot.distinct_from_slot_ids
    }


def _constrained_indexes(edges: set[frozenset[int]]) -> set[int]:
    """Return the slot indexes participating in any distinctness constraint."""
    return set().union(*edges) if edges else set()


def _unconstrained_product(
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
    constrained: set[int],
) -> int:
    """Multiply option counts for slots untouched by distinctness edges."""
    total = 1
    for index, slot_options in enumerate(options):
        if index not in constrained:
            total *= len(slot_options)
    return total


def _constrained_components(
    constrained: set[int], edges: set[frozenset[int]]
) -> list[set[int]]:
    """Partition constrained indexes into connected edge components."""
    remaining = set(constrained)
    components: list[set[int]] = []
    while remaining:
        component = {remaining.pop()}
        frontier = list(component)
        while frontier:
            current = frontier.pop()
            neighbors = {
                next(iter(edge - {current}))
                for edge in edges
                if current in edge and len(edge) == 2
            }
            new = neighbors & remaining
            remaining -= new
            component |= new
            frontier.extend(new)
        components.append(component)
    return components


def _assignment_conflicts(
    index: int,
    resource: CanonicalResourceReference,
    assigned: dict[int, CanonicalResourceReference],
    edges: set[frozenset[int]],
) -> bool:
    """True when assigning ``resource`` violates a distinctness edge."""
    return any(
        frozenset((index, other_index)) in edges and resource == other_resource
        for other_index, other_resource in assigned.items()
    )


def _count_component_assignments(
    component: set[int],
    edges: set[frozenset[int]],
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
) -> int:
    """Count valid assignments within one connected constrained component."""
    ordered = sorted(component)

    def count_at(offset: int, assigned: dict[int, CanonicalResourceReference]) -> int:
        if offset == len(ordered):
            return 1
        index = ordered[offset]
        count = 0
        for resource in options[index]:
            if _assignment_conflicts(index, resource, assigned, edges):
                continue
            assigned[index] = resource
            count += count_at(offset + 1, assigned)
            del assigned[index]
        return count

    return count_at(0, {})


def _iter_coverage_first_combinations(
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
) -> Iterable[tuple[CanonicalResourceReference, ...]]:
    """Lazily yield coverage-first combinations without materializing the product.

    Callers stop early when the budget is reached; the full Cartesian
    product is never materialized.

    Ordering:
    1. The baseline (slot[0] for every slot).
    2. Per-slot variant offsets (cover each slot's alternatives).
    3. Remaining Cartesian fill in ``product`` order.
    """
    seen: set[tuple[str, ...]] = set()
    baseline = _combination_baseline(options)
    seen.add(_combination_key(baseline))
    yield baseline
    yield from _variant_combinations(baseline, options, seen)
    yield from _cartesian_fill(options, seen)


def _combination_key(
    items: tuple[CanonicalResourceReference, ...],
) -> tuple[str, ...]:
    """Map a resource combination to its canonical deduplication key."""
    return tuple(_resource_key(item) for item in items)


def _combination_baseline(
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
) -> tuple[CanonicalResourceReference, ...]:
    """The first candidate combination: slot[0] for every slot."""
    return tuple(slot[0] for slot in options)


def _max_option_length(
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
) -> int:
    """The longest per-slot option list (one when options is empty)."""
    return max(len(slot) for slot in options) if options else 1


def _variant_combinations(
    baseline: tuple[CanonicalResourceReference, ...],
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
    seen: set[tuple[str, ...]],
) -> Iterable[tuple[CanonicalResourceReference, ...]]:
    """Yield per-slot variant offsets before any Cartesian fill."""
    max_len = _max_option_length(options)
    for offset in range(1, max_len):
        yield from _offset_variants(baseline, options, offset, seen)


def _offset_variants(
    baseline: tuple[CanonicalResourceReference, ...],
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
    offset: int,
    seen: set[tuple[str, ...]],
) -> Iterable[tuple[CanonicalResourceReference, ...]]:
    """Yield variants replacing one slot at a fixed alternative offset."""
    for slot_index, slot in enumerate(options):
        if offset >= len(slot):
            continue
        variant = list(baseline)
        variant[slot_index] = slot[offset]
        variant_t = tuple(variant)
        key = _combination_key(variant_t)
        if key in seen:
            continue
        seen.add(key)
        yield variant_t


def _cartesian_fill(
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
    seen: set[tuple[str, ...]],
) -> Iterable[tuple[CanonicalResourceReference, ...]]:
    """Yield remaining product combinations, skipping duplicates lazily."""
    for combination in product(*options):
        key = _combination_key(combination)
        if key in seen:
            continue
        seen.add(key)
        yield combination


def _derive_execution_requirements_core(
    pattern_id: str,
    chain: CanonicalAttackChain,
    projection: ProjectionSnapshot,
    ingress_controllability: Literal["direct", "indirect"],
) -> tuple[tuple[ExecutionRequirement, ...] | None, ProjectionIssue | None]:
    """Derive execution requirements from explicit canonical linkage only.

    Pure function over the embedded source chain, projection bindings, and
    the resolved ingress controllability.  No external snapshot is needed.
    No inference from action kind, name, prose, cardinality, taxonomy mapping,
    or catalog partition.  Every requirement is traced to an explicit
    ``resource_links`` or ``observable_outcome_links`` entry on a selected
    step.  Security-outcome assertions are derived only from postconditions
    that have an explicit observable outcome link, not from the
    ``security_relevant`` flag alone.
    """
    slots_by_id = {slot.slot_id: slot for slot in chain.resource_slots}
    selected_steps = _selected_steps_for_projection(chain, projection.selected_step_ids)
    requirements: list[ExecutionRequirement] = []

    for step in selected_steps:
        for link in step.resource_links:
            slot = slots_by_id[link.slot_id]
            derived, issue = _link_role_requirement(
                pattern_id, step, link, slot, ingress_controllability
            )
            if issue is not None:
                return None, issue
            requirements.extend(derived)

        # Build a set of postcondition IDs that have explicit outcome links.
        linked_pc_ids = _linked_postcondition_ids(step)
        requirements.extend(_observation_requirements(step))

        # Security-outcome assertions are derived ONLY from security-relevant
        # postconditions that have an explicit observable outcome link.
        # A security-relevant postcondition without an outcome link does not
        # produce a requirement: the security outcome cannot be asserted
        # without an explicit observation binding.
        requirements.extend(_security_outcome_requirements(step, linked_pc_ids))

    sorted_reqs = tuple(sorted(requirements, key=lambda item: item.requirement_id))
    return _require_unique_requirement_ids_or_issue(sorted_reqs, pattern_id)


def _source_identity_kind_for_link(link: Any, slot: ResourceSlot) -> str:
    """Resolve the declared source identity kind, falling back to the slot."""
    if link.source_identity_kind is not None:
        return link.source_identity_kind
    if slot.kind == "entry_point":
        return "entry_point"
    return "integration"


def _link_role_requirement(
    pattern_id: str,
    step: Any,
    link: Any,
    slot: ResourceSlot,
    ingress_controllability: Literal["direct", "indirect"],
) -> tuple[list[ExecutionRequirement], ProjectionIssue | None]:
    """Derive the requirement for one resource link by its role."""
    if link.role == "ingress":
        if ingress_controllability != "direct":
            return None, ProjectionIssue(
                code="unsupported_requirement_derivation",
                pattern_id=pattern_id,
                detail=(
                    "indirect ingress requires explicit upstream-source "
                    "and trust-boundary linkage"
                ),
            )
        return [
            DirectInputControlRequirement(
                schema_version="1",
                requirement_id=_requirement_id("req.direct-input", link.slot_id),
                kind="direct_input_control",
                entry_point_slot_id=link.slot_id,
            )
        ], None
    if link.role == "tool_fixture":
        return [
            StateChangingToolFixtureRequirement(
                schema_version="1",
                requirement_id=_requirement_id(
                    "req.tool-fixture", step.step_id, link.slot_id
                ),
                kind="state_changing_tool_fixture",
                tool_slot_id=link.slot_id,
            )
        ], None
    if link.role == "source_influence":
        return [
            UpstreamSourceInfluenceRequirement(
                schema_version="1",
                requirement_id=_requirement_id(
                    "req.source-influence",
                    step.step_id,
                    link.slot_id,
                    str(link.trust_boundary_slot_id),
                    str(link.target_ingress_slot_id),
                ),
                kind="upstream_source_influence",
                source_slot_id=link.slot_id,
                source_identity_kind=_source_identity_kind_for_link(link, slot),
                trust_boundary_slot_id=link.trust_boundary_slot_id,
                target_ingress_slot_id=link.target_ingress_slot_id,
            )
        ], None
    return [], None


def _linked_postcondition_ids(step: Any) -> set[str]:
    """Collect postcondition IDs with explicit observable outcome links."""
    return {ol.postcondition_id for ol in step.observable_outcome_links}


def _observation_requirements(step: Any) -> list[ExecutionRequirement]:
    """Derive observation requirements from the step's outcome links."""
    return [
        ObservationRequirement(
            schema_version="1",
            requirement_id=_requirement_id(
                "req.observation",
                step.step_id,
                outcome_link.postcondition_id,
            ),
            kind="observation",
            observation=outcome_link.observation,
            binding_slot_id=outcome_link.binding_slot_id,
        )
        for outcome_link in step.observable_outcome_links
    ]


def _security_outcome_requirements(
    step: Any, linked_pc_ids: set[str]
) -> list[ExecutionRequirement]:
    """Derive security-outcome assertions from linked postconditions only."""
    return [
        SecurityOutcomeAssertionRequirement(
            schema_version="1",
            requirement_id=_requirement_id(
                "req.security-outcome",
                step.step_id,
                postcondition.postcondition_id,
            ),
            kind="security_outcome_assertion",
            source_step_id=step.step_id,
            postcondition_id=postcondition.postcondition_id,
        )
        for postcondition in step.observable_postconditions
        if postcondition.security_relevant
        and postcondition.postcondition_id in linked_pc_ids
    ]


def _require_unique_requirement_ids_or_issue(
    sorted_reqs: tuple[ExecutionRequirement, ...],
    pattern_id: str,
) -> tuple[tuple[ExecutionRequirement, ...] | None, ProjectionIssue | None]:
    """Fail closed when derived requirement IDs collide."""
    req_ids = [item.requirement_id for item in sorted_reqs]
    if len(req_ids) != len(set(req_ids)):
        duplicates = sorted({rid for rid in req_ids if req_ids.count(rid) > 1})
        return None, ProjectionIssue(
            code="unsupported_requirement_derivation",
            pattern_id=pattern_id,
            detail=(
                f"derived requirement IDs collide: {duplicates}; "
                "requirement IDs must be unique"
            ),
        )
    return sorted_reqs, None


def _fail_closed_if_no_requirements(
    pattern_id: str,
    requirements: tuple[ExecutionRequirement, ...] | None,
    issue: ProjectionIssue | None,
) -> tuple[tuple[ExecutionRequirement, ...] | None, ProjectionIssue | None]:
    """Absent explicit linkage must fail closed, not produce an empty candidate."""
    if issue is not None:
        return requirements, issue
    if requirements is None or len(requirements) == 0:
        return None, ProjectionIssue(
            code="unsupported_requirement_derivation",
            pattern_id=pattern_id,
            detail=(
                "no explicit resource links or observable outcome links on any "
                "selected step; absent linkage fails closed"
            ),
        )
    return requirements, issue


def _derive_execution_requirements(
    pattern_id: str,
    chain: CanonicalAttackChain,
    projection: ProjectionSnapshot,
    snapshot: CapabilityFactSnapshot,
) -> tuple[tuple[ExecutionRequirement, ...] | None, ProjectionIssue | None]:
    """Derive execution requirements, resolving ingress controllability from snapshot.

    Backward-compatible wrapper around :func:`_derive_execution_requirements_core`
    that resolves the ingress controllability from the capability fact snapshot.
    """
    controllability = _resolve_ingress_controllability(chain, projection, snapshot)
    # No ingress link found — resolve to indirect (will fail closed).
    return _derive_execution_requirements_core(
        pattern_id, chain, projection, controllability
    )


def _selected_ingress_links(
    chain: CanonicalAttackChain, projection: ProjectionSnapshot
) -> list[Any]:
    """Collect the selected steps' ingress resource links in chain order."""
    selected = set(projection.selected_step_ids)
    return [
        link
        for step in chain.steps
        if step.step_id in selected
        for link in step.resource_links
        if link.role == "ingress"
    ]


def _ingress_controllability_for_link(
    bindings: dict[str, CanonicalResourceReference],
    link: Any,
    snapshot: CapabilityFactSnapshot,
) -> str:
    """Resolve the effective ingress controllability for one ingress link."""
    ingress_ref = bindings[link.slot_id]
    if not isinstance(ingress_ref, EntryPointResourceReference):
        raise TypeError(  # pragma: no cover - contract guard
            "ingress binding is not an entry point"
        )
    ingress = snapshot.profile.resolve_entry_point(ingress_ref.entry_point_id)
    if ingress is None:
        raise ValueError("canonical ingress is absent from snapshot")
    return ingress.effective_controllability


def _resolve_ingress_controllability(
    chain: CanonicalAttackChain,
    projection: ProjectionSnapshot,
    snapshot: CapabilityFactSnapshot,
) -> Literal["direct", "indirect"]:
    """Resolve ingress controllability from the first selected ingress link."""
    bindings = {item.slot_id: item.resource_ref for item in projection.bindings}
    for link in _selected_ingress_links(chain, projection):
        return _ingress_controllability_for_link(bindings, link, snapshot)
    return "indirect"


def _projected_mappings(
    chain: CanonicalAttackChain, selected_step_ids: tuple[str, ...]
) -> tuple[ProjectedMapping, ...]:
    mappings = list(_chain_atlas_mappings(chain))
    selected = set(selected_step_ids)
    for step in chain.steps:
        if step.step_id in selected:
            mappings.extend(_step_atlas_mappings(step))
    return tuple(mappings)


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


def _candidate_v2_id(pattern_id: str, projection: ProjectionSnapshot) -> str:
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


def _content_pin(domain: str, value: Any) -> str:
    return _digest(domain, value)


def validate_projected_candidate(
    candidate_dict: dict[str, Any],
    snapshot: CapabilityFactSnapshot,
    authoritative_record: dict[str, Any],
    taxonomy_resolver: TaxonomyResolver,
    *,
    expected_catalog_pin: Digest,
) -> ProjectedCandidate:
    """Qualify serialized candidate integrity against trusted authoritative inputs."""
    snapshot.assert_integrity()
    candidate = ProjectedCandidate.model_validate(candidate_dict)
    authoritative = validate_attack_pattern(authoritative_record, taxonomy_resolver)
    authoritative = AttackPattern.model_validate(
        _normalize_semantic_order(authoritative.model_dump(mode="json"))
    )
    _validate_chain_identity(candidate, authoritative)
    _validate_pattern_pins(candidate, authoritative, expected_catalog_pin)
    _validate_prerequisite_zones(
        authoritative.prerequisite_capabilities, snapshot.profile
    )
    _validate_prerequisite_kc(authoritative.prerequisite_capabilities, snapshot.profile)
    _validate_snapshot_digest_pin(candidate, snapshot)
    validate_projection_snapshot(candidate.projection.model_dump(mode="json"), snapshot)
    _validate_source_influence_paths(candidate, snapshot)
    _validate_precondition_evidence(candidate, snapshot)
    _validate_ingress_controllability(candidate, snapshot)
    _validate_bindings_against_snapshot(candidate, snapshot)
    _validate_derived_requirements(candidate, snapshot)
    return candidate


def _validate_chain_identity(
    candidate: ProjectedCandidate, authoritative: AttackPattern
) -> None:
    """Require the candidate chain and pattern id to match the authority."""
    if candidate.projection.source_chain != authoritative.canonical_chain:
        raise ValueError("candidate source chain does not match authoritative pattern")
    if candidate.pattern_id != authoritative.id:
        raise ValueError("candidate pattern id does not match authoritative pattern")


def _validate_pattern_pins(
    candidate: ProjectedCandidate,
    authoritative: AttackPattern,
    expected_catalog_pin: Digest,
) -> None:
    """Require the candidate pins to match the authority and trusted catalog."""
    if candidate.projection.pattern_pin != _pattern_pin(authoritative):
        raise ValueError("candidate pattern pin does not match authoritative pattern")
    if candidate.projection.catalog_pin != expected_catalog_pin:
        raise ValueError("candidate catalog pin does not match trusted catalog")


def _validate_prerequisite_zones(
    prerequisites: Any, profile: CapabilityProfile
) -> None:
    """Require the authoritative pattern zones to be active in the snapshot."""
    if not set(prerequisites.min_zones).issubset(profile.zones_active):
        raise ValueError("authoritative pattern zones are incompatible with snapshot")


def _kc_requires_compatible(kc_requires: Any, profile_kc: set[str]) -> bool:
    """True when the pattern's KC requirements are satisfied by the profile."""
    if not kc_requires:
        return True
    if not set(kc_requires.all).issubset(profile_kc):
        return False
    if kc_requires.any and not set(kc_requires.any).intersection(profile_kc):
        return False
    return True


def _validate_prerequisite_kc(prerequisites: Any, profile: CapabilityProfile) -> None:
    """Require the authoritative pattern KC requirements to be satisfiable."""
    profile_kc = set(profile.kc_subcodes)
    if not _kc_requires_compatible(prerequisites.kc_requires, profile_kc):
        raise ValueError("authoritative pattern KC requirements are incompatible")


def _validate_snapshot_digest_pin(
    candidate: ProjectedCandidate, snapshot: CapabilityFactSnapshot
) -> None:
    """Require the candidate's snapshot digest pin to match the resolver."""
    if candidate.projection.capability_fact_snapshot_digest != snapshot.snapshot_digest:
        raise ValueError("candidate capability snapshot digest pin does not match")


def _validate_precondition_evidence(
    candidate: ProjectedCandidate, snapshot: CapabilityFactSnapshot
) -> None:
    """Require precondition evidence to match the resolver reading."""
    for result in candidate.precondition_results:
        for evidence in result.evidence:
            if snapshot.fact(evidence.fact) != evidence:
                raise ValueError(
                    "precondition fact evidence does not match resolver reading"
                )


def _validate_ingress_controllability(
    candidate: ProjectedCandidate, snapshot: CapabilityFactSnapshot
) -> None:
    """Require the candidate's ingress controllability to match the snapshot."""
    ingress = snapshot.profile.resolve_entry_point(
        candidate.canonical_ingress.entry_point_id
    )
    if ingress is None or ingress.effective_controllability != (
        candidate.ingress_controllability
    ):
        raise ValueError("candidate ingress controllability does not match snapshot")


def _validate_bindings_against_snapshot(
    candidate: ProjectedCandidate, snapshot: CapabilityFactSnapshot
) -> None:
    """Require every binding to be compatible with the snapshot resources."""
    binding_by_slot = {
        binding.slot_id: binding.resource_ref
        for binding in candidate.projection.bindings
    }
    chain = candidate.projection.source_chain
    for slot in chain.resource_slots:
        allowed = _references_for_slot(
            slot,
            snapshot,
            initial_ingress=slot.slot_id == chain.initial_ingress_slot_id,
        )
        if binding_by_slot[slot.slot_id] not in allowed:
            raise ValueError("candidate binding is incompatible with snapshot resource")


def _validate_derived_requirements(
    candidate: ProjectedCandidate, snapshot: CapabilityFactSnapshot
) -> None:
    """Require the candidate's requirements to match the authoritative derivation."""
    requirements, issue = _derive_execution_requirements(
        candidate.pattern_id,
        candidate.projection.source_chain,
        candidate.projection,
        snapshot,
    )
    requirements, issue = _fail_closed_if_no_requirements(
        candidate.pattern_id, requirements, issue
    )
    if issue is not None or requirements != candidate.execution_requirements:
        raise ValueError("candidate execution requirements do not match derivation")


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


def compute_authoritative_catalog_pin(
    records: Sequence[dict[str, Any]], taxonomy_resolver: TaxonomyResolver
) -> Digest:
    """Compute the canonical pin for a complete trusted authoritative catalog.

    This is deliberately separate from bounded projection: validation of a
    persisted candidate must not depend on whether its binding variant would
    be rediscovered under an arbitrary projection budget.
    """
    qualified: dict[str, str] = {}
    for raw in records:
        pattern = validate_attack_pattern(raw, taxonomy_resolver)
        pattern = AttackPattern.model_validate(
            _normalize_semantic_order(pattern.model_dump(mode="json"))
        )
        pattern_pin = _pattern_pin(pattern)
        previous = qualified.get(pattern.id)
        if previous is not None and previous != pattern_pin:
            raise ValueError("conflicting authoritative records share one pattern id")
        qualified[pattern.id] = pattern_pin
    return _content_pin(
        "asago-scenario-generator:authoritative-catalog:v1",
        [qualified[pattern_id] for pattern_id in sorted(qualified)],
    )


@dataclass
class _PatternProjectionState:
    """Lazy per-pattern projection state for bounded candidate generation.

    Stores the pattern metadata and a lazy combination iterator so that
    candidates are built on demand during reservation and fill — never
    eagerly materializing the full Cartesian product.

    Attributes:
        pattern_id: The attack pattern ID.
        chain: The canonical attack chain.
        selected: Tuple of selected step IDs.
        condition_results: Projection condition evaluation results.
        omissions: Step omissions for conditional-false steps.
        option_sets: Tuple of per-slot resource options.
        total_bindings: Total Cartesian product size (for limitation
            accounting — never materialized).
        catalog_pin: Catalog content pin.
        pattern_pin: Pattern content pin.
        precondition_results: Precondition evaluation results.
        combination_iter: Lazy iterator over coverage-first combinations.
        snapshot: The capability fact snapshot.
        generated: List of candidates built so far (in iterator order).
        iterator_exhausted: True when the lazy iterator has been fully
            consumed (no more feasible combinations).
    """

    pattern_id: str
    chain: CanonicalAttackChain
    selected: tuple[str, ...]
    condition_results: tuple[ConditionEvaluationResult, ...]
    omissions: tuple[StepOmission, ...]
    option_sets: tuple[tuple[CanonicalResourceReference, ...], ...]
    total_bindings: int
    catalog_pin: str
    pattern_pin: str
    precondition_results: tuple[PreconditionEvaluationResult, ...]
    combination_iter: Iterable[tuple[CanonicalResourceReference, ...]]
    snapshot: CapabilityFactSnapshot
    generated: list[ProjectedCandidate] = field(default_factory=list)
    iterator_exhausted: bool = False
    _iter: Any = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self._iter is None:
            object.__setattr__(self, "_iter", iter(self.combination_iter))

    def next_candidate(self, issues: list | None = None) -> ProjectedCandidate | None:
        """Lazily build the next feasible candidate from the iterator.

        Returns None when the iterator is exhausted.  Combinations that
        fail execution requirements derivation are skipped; if an
        ``issues`` list is provided, the structural issue is appended to
        it.  The full Cartesian product is never materialized — only one
        combination is consumed per call.
        """
        if self.iterator_exhausted:
            return None
        for resources in self._iter:
            candidate, issue = _build_candidate_from_combination(
                self.pattern_id,
                self.chain,
                self.selected,
                self.condition_results,
                self.omissions,
                resources,
                self.catalog_pin,
                self.pattern_pin,
                self.precondition_results,
                self.snapshot,
            )
            if issue is not None and issues is not None:
                issues.append(issue)
            if candidate is not None:
                self.generated.append(candidate)
                return candidate
            # issue — skip this combination, continue iterating.
        # Iterator exhausted.
        self.iterator_exhausted = True
        return None

    @property
    def emitted(self) -> int:
        """Number of candidates built so far."""
        return len(self.generated)

    @property
    def feasible_remaining(self) -> bool:
        """True if the iterator may still yield more feasible candidates."""
        return not self.iterator_exhausted


def _bindings_for_combination(
    chain: CanonicalAttackChain,
    resources: tuple[CanonicalResourceReference, ...],
) -> tuple[ResourceBinding, ...]:
    """Pair every chain resource slot with its chosen resource reference."""
    return tuple(
        ResourceBinding(slot_id=slot.slot_id, resource_ref=resource)
        for slot, resource in zip(chain.resource_slots, resources, strict=True)
    )


def _projection_payloads(items: Iterable[Any]) -> list[dict[str, Any]]:
    """Dump projection sub-models to JSON payloads."""
    return [item.model_dump(mode="json") for item in items]


def _projection_data_for_combination(
    chain: CanonicalAttackChain,
    selected: tuple[str, ...],
    condition_results: tuple[ConditionEvaluationResult, ...],
    omissions: tuple[StepOmission, ...],
    bindings: tuple[ResourceBinding, ...],
    catalog_pin: str,
    pattern_pin: str,
    snapshot: CapabilityFactSnapshot,
    source_influence_paths: tuple[SourceInfluencePath, ...],
) -> dict[str, Any]:
    """Assemble and digest-address projection data for one combination."""
    projection_data = {
        "schema_version": "1",
        "source_chain": chain.model_dump(mode="json"),
        "selected_step_ids": selected,
        "condition_results": _projection_payloads(condition_results),
        "omissions": _projection_payloads(omissions),
        "bindings": _projection_payloads(bindings),
        "catalog_pin": catalog_pin,
        "pattern_pin": pattern_pin,
        "capability_fact_snapshot_digest": snapshot.snapshot_digest,
        "projection_digest": "0" * 64,
        "source_influence_paths": _projection_payloads(source_influence_paths),
    }
    projection_data["projection_digest"] = compute_projection_digest(projection_data)
    return projection_data


def _ingress_for_combination(
    bindings: tuple[ResourceBinding, ...],
    chain: CanonicalAttackChain,
    snapshot: CapabilityFactSnapshot,
) -> tuple[EntryPointResourceReference, Literal["direct", "indirect"]]:
    """Resolve the binding and controllability of the initial ingress slot."""
    ingress_ref = next(
        item.resource_ref
        for item in bindings
        if item.slot_id == chain.initial_ingress_slot_id
    )
    assert isinstance(ingress_ref, EntryPointResourceReference)
    ingress = snapshot.profile.resolve_entry_point(ingress_ref.entry_point_id)
    assert ingress is not None
    return ingress_ref, ingress.effective_controllability


def _selected_steps_from_chain(
    chain: CanonicalAttackChain, selected_step_ids: tuple[str, ...]
) -> list[Any]:
    """Return the chain steps selected for this candidate projection."""
    selected = set(selected_step_ids)
    return [step for step in chain.steps if step.step_id in selected]


def _count_selected_steps(
    selected_steps: list[Any], predicate: Callable[[Any], bool]
) -> int:
    """Count selected steps satisfying a boolean predicate."""
    return sum(predicate(step) for step in selected_steps)


def _candidate_complexity_inputs(
    selected_steps: list[Any],
    bindings: tuple[ResourceBinding, ...],
    requirements: tuple[ExecutionRequirement, ...],
) -> CandidateComplexityInputs:
    """Derive the complexity inputs recorded on each projected candidate."""
    return CandidateComplexityInputs(
        selected_step_count=len(selected_steps),
        attacker_controlled_step_count=_count_selected_steps(
            selected_steps, lambda step: step.attacker_controlled
        ),
        boundary_crossing_step_count=_count_selected_steps(
            selected_steps, lambda step: step.boundary_position == "crossing"
        ),
        selected_conditional_step_count=_count_selected_steps(
            selected_steps, lambda step: step.requirement == "conditional"
        ),
        concrete_binding_count=len(bindings),
        execution_requirement_count=len(requirements),
    )


def _build_candidate_from_combination(
    pattern_id: str,
    chain: CanonicalAttackChain,
    selected: tuple[str, ...],
    condition_results: tuple[ConditionEvaluationResult, ...],
    omissions: tuple[StepOmission, ...],
    resources: tuple[CanonicalResourceReference, ...],
    catalog_pin: str,
    pattern_pin: str,
    precondition_results: tuple[PreconditionEvaluationResult, ...],
    snapshot: CapabilityFactSnapshot,
) -> tuple[ProjectedCandidate | None, Any | None]:
    """Build a single ProjectedCandidate from one resource combination.

    Returns ``(candidate, issue)``.  When the combination fails execution
    requirements derivation (a structural rejection, not a budget limit),
    ``candidate`` is None and ``issue`` carries the typed ProjectionIssue.
    """
    bindings = _bindings_for_combination(chain, resources)
    source_influence_paths, relation_issue = _source_influence_relation(
        pattern_id, chain, selected, bindings, snapshot
    )
    if relation_issue is not None:
        return None, relation_issue
    projection_data = _projection_data_for_combination(
        chain,
        selected,
        condition_results,
        omissions,
        bindings,
        catalog_pin,
        pattern_pin,
        snapshot,
        source_influence_paths,
    )
    projection = validate_projection_snapshot(projection_data, snapshot)
    requirements, issue = _derive_execution_requirements(
        pattern_id, chain, projection, snapshot
    )
    requirements, issue = _fail_closed_if_no_requirements(
        pattern_id, requirements, issue
    )
    if issue is not None:
        return None, issue
    requirements_digest = compute_execution_requirements_digest(requirements)
    ingress_ref, ingress_controllability = _ingress_for_combination(
        bindings, chain, snapshot
    )
    selected_steps = _selected_steps_from_chain(chain, selected)
    candidate = ProjectedCandidate(
        candidate_id=_candidate_v2_id(pattern_id, projection),
        pattern_id=pattern_id,
        chain_id=chain.chain_id,
        chain_semantic_revision=chain.semantic_revision,
        chain_semantic_digest=chain.semantic_digest,
        projection=projection,
        canonical_ingress=ingress_ref,
        ingress_controllability=ingress_controllability,
        projected_mappings=_projected_mappings(chain, selected),
        precondition_results=precondition_results,
        execution_requirements=requirements,
        requirement_derivation_version="1",
        execution_requirements_digest=requirements_digest,
        complexity_inputs=_candidate_complexity_inputs(
            selected_steps, bindings, requirements
        ),
    )
    return candidate, None


def project_authoritative_candidates(
    records: Sequence[dict[str, Any]],
    taxonomy_resolver: TaxonomyResolver,
    snapshot: CapabilityFactSnapshot,
    *,
    budget: ProjectionBudget | None = None,
    coverage_target_ids: set[str] | None = None,
) -> ProjectionBatch:
    """Qualify, project, bind, and identify authoritative candidate-v2 records.

    Structurally parsed ``AttackPattern`` objects and legacy catalogue records are
    deliberately not accepted: every raw record crosses the merged qualification
    boundary in this call.

    When ``coverage_target_ids`` is provided, the global budget allocation is
    coverage-aware: one feasible candidate per coverage target is reserved
    before binding variants and secondary expansion.  This ensures every
    ingress target receives at least one projected candidate before the
    budget is exhausted.  If ``budget.max_candidates`` is below the number of
    feasible coverage targets, reservation is best-effort and the caller
    should emit a ``selection_limitation`` for uncovered targets.
    """
    _authoritative_records_type_check(records)
    budget = _resolve_projection_budget(budget)
    snapshot.assert_integrity()
    qualified = _qualify_authoritative_records(records, taxonomy_resolver)
    catalog_pin = _catalog_content_pin(qualified)
    candidate_groups: list[_PatternProjectionState] = []
    issues: list[ProjectionIssue] = []
    for pattern, pattern_pin in qualified:
        _project_authoritative_pattern(
            pattern, pattern_pin, snapshot, catalog_pin, candidate_groups, issues
        )
    allocator = _AuthoritativeCandidateAllocator(
        budget, candidate_groups, issues, coverage_target_ids
    )
    allocator.reserve_coverage_targets()
    allocator.emit_reserved_targets()
    allocator.emit_pending()
    allocator.fill_round_robin()
    allocator.probe_truncation()
    return ProjectionBatch(
        capability_fact_snapshot_digest=snapshot.snapshot_digest,
        candidates=_sorted_emitted_candidates(allocator.by_identity),
        infeasibilities=_sorted_infeasibilities(issues),
        limitations=_sorted_limitations(allocator.build_limitations()),
        unreserved_coverage_targets=allocator.unreserved_targets(),
        infeasible_coverage_targets=allocator.infeasible_coverage_targets(),
    )


# Authoritative projection, qualification, and allocation machinery lives
# in the sibling module pipeline.projection_authoritative; re-export it
# here so every existing import path keeps working.
from asago_scenario_generator.pipeline.projection_authoritative import (  # noqa: E402
    _resolve_projection_budget as _resolve_projection_budget,
    _catalog_content_pin as _catalog_content_pin,
    _sorted_emitted_candidates as _sorted_emitted_candidates,
    _infeasibility_key as _infeasibility_key,
    _sorted_infeasibilities as _sorted_infeasibilities,
    _limitation_key as _limitation_key,
    _sorted_limitations as _sorted_limitations,
    _authoritative_records_type_check as _authoritative_records_type_check,
    _qualify_authoritative_pattern as _qualify_authoritative_pattern,
    _resolve_qualified_patterns as _resolve_qualified_patterns,
    _qualify_authoritative_records as _qualify_authoritative_records,
    _profile_compatibility_gaps as _profile_compatibility_gaps,
    _incompatible_profile_issue as _incompatible_profile_issue,
    _profile_gate_failure_issue as _profile_gate_failure_issue,
    _results_contain_unknown as _results_contain_unknown,
    _results_contain_false as _results_contain_false,
    _unresolved_condition_issue as _unresolved_condition_issue,
    _unresolved_precondition_issue as _unresolved_precondition_issue,
    _false_precondition_issue as _false_precondition_issue,
    _inapplicable_projection_issue as _inapplicable_projection_issue,
    _select_conditionally_required_steps as _select_conditionally_required_steps,
    _projection_is_applicable as _projection_is_applicable,
    _omitted_conditional_steps as _omitted_conditional_steps,
    _precondition_results_or_none as _precondition_results_or_none,
    _profile_and_condition_gate as _profile_and_condition_gate,
    _qualified_condition_state as _qualified_condition_state,
    _ingress_slot_index as _ingress_slot_index,
    _gather_slot_options as _gather_slot_options,
    _source_influence_relation_links as _source_influence_relation_links,
    _relation_slot_ids as _relation_slot_ids,
    _source_influence_relation_state as _source_influence_relation_state,
    _check_simple_missing_slot as _check_simple_missing_slot,
    _slot_by_id as _slot_by_id,
    _source_influence_target_id as _source_influence_target_id,
    _source_influence_failure_issue as _source_influence_failure_issue,
    _record_missing_slot_issues as _record_missing_slot_issues,
    _direct_ingress_options as _direct_ingress_options,
    _has_source_influence_activation as _has_source_influence_activation,
    _has_direct_ingress_activation as _has_direct_ingress_activation,
    _no_activation_violation as _no_activation_violation,
    _resolve_ingress_activation as _resolve_ingress_activation,
    _zero_bindings_issue as _zero_bindings_issue,
    _assemble_pattern_state as _assemble_pattern_state,
    _project_authoritative_pattern as _project_authoritative_pattern,
    _target_ingress_reference as _target_ingress_reference,
    _dedupe_projection_issues as _dedupe_projection_issues,
    _AuthoritativeCandidateAllocator as _AuthoritativeCandidateAllocator,
)
