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
from math import prod
from typing import Annotated, Any, Literal

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
    if isinstance(value, list):
        return [_normalize_unicode(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_normalize_unicode(item) for item in value)
    return value


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
        if isinstance(reference, EntryPointResourceReference):
            return (
                self.profile.resolve_entry_point(reference.entry_point_id) is not None
            )
        if isinstance(reference, ToolResourceReference):
            return self.profile.resolve_tool(reference.tool_id) is not None
        if isinstance(reference, IntegrationResourceReference):
            return (
                self.profile.resolve_integration(reference.integration_id) is not None
            )
        if isinstance(reference, TrustBoundaryResourceReference):
            return (
                self.profile.resolve_trust_boundary(reference.trust_boundary_id)
                is not None
            )
        if isinstance(reference, OutputSurfaceResourceReference):
            return (
                self.profile.resolve_output_surface(reference.entry_point_id)
                is not None
            )
        if isinstance(reference, AgentInternalResourceReference):
            # Every validated capability profile has the reasoning zone and
            # therefore exactly one intrinsic agent working-state resource.
            # This remains a distinct typed binding: it is never substituted
            # with a tool, integration, entry point, or trust boundary.
            return "reasoning" in self.profile.zones_active
        return False

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
        keys = [_fact_key(item.fact) for item in self.facts]
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise ValueError("snapshot facts must be uniquely sorted by reference")
        if self.snapshot_digest != _compute_snapshot_digest(self.profile, self.facts):
            raise ValueError("snapshot_digest does not match capability/fact content")
        return self


def _snapshot_resource_payload(profile: CapabilityProfile) -> dict[str, Any]:
    return {
        "zones_active": sorted(set(profile.zones_active)),
        "kc_subcodes": sorted(set(profile.kc_subcodes)),
        "entry_points": sorted(
            (item.model_dump(mode="json") for item in profile.entry_points),
            key=lambda item: item["entry_point_id"],
        ),
        "tools": sorted(
            (item.model_dump(mode="json") for item in profile.tool_inventory or ()),
            key=lambda item: item["tool_id"],
        ),
        "tool_types": sorted(
            (item.model_dump(mode="json") for item in profile.tool_types or ()),
            key=lambda item: _canonical_json(item),
        ),
        "integrations": sorted(
            (
                item.model_dump(mode="json")
                for item in profile.external_integrations or ()
            ),
            key=lambda item: item["integration_id"],
        ),
        "trust_boundaries": sorted(
            (item.model_dump(mode="json") for item in profile.trust_boundaries or ()),
            key=lambda item: item["trust_boundary_id"],
        ),
    }


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
        req_ids = [item.requirement_id for item in self.execution_requirements]
        if len(req_ids) != len(set(req_ids)):
            raise ValueError("execution requirement IDs must be unique")
        if (
            self.pattern_id != chain.pattern_id
            or self.chain_id != chain.chain_id
            or self.chain_semantic_revision != chain.semantic_revision
            or self.chain_semantic_digest != chain.semantic_digest
        ):
            raise ValueError("candidate chain identity does not match its projection")
        ingress = next(
            binding.resource_ref
            for binding in self.projection.bindings
            if binding.slot_id == chain.initial_ingress_slot_id
        )
        if ingress != self.canonical_ingress:
            raise ValueError("canonical_ingress does not match the projection binding")
        expected_requirements_digest = compute_execution_requirements_digest(
            self.execution_requirements
        )
        if self.execution_requirements_digest != expected_requirements_digest:
            raise ValueError(
                "execution_requirements_digest does not match requirements"
            )
        if self.candidate_id != _candidate_v2_id(self.pattern_id, self.projection):
            raise ValueError("candidate_id does not match candidate-v2 identity inputs")
        expected_preconditions = {
            (step.step_id, precondition.condition_id): precondition.condition
            for step in chain.steps
            if step.step_id in set(self.projection.selected_step_ids)
            for precondition in step.preconditions
        }
        supplied_preconditions = {
            (item.step_id, item.condition_id): item
            for item in self.precondition_results
        }
        if len(supplied_preconditions) != len(self.precondition_results):
            raise ValueError("precondition result keys must be unique")
        if set(expected_preconditions) != set(supplied_preconditions):
            raise ValueError("precondition results must exactly cover selected steps")
        for key, condition in expected_preconditions.items():
            supplied = supplied_preconditions[key]
            if (
                supplied.result != "true"
                or evaluate_condition(condition, supplied.evidence) != "true"
            ):
                raise ValueError("projected candidate preconditions must evaluate true")
        if self.projected_mappings != _projected_mappings(
            chain, self.projection.selected_step_ids
        ):
            raise ValueError("projected mappings are incomplete or non-authoritative")
        selected_steps = [
            step
            for step in chain.steps
            if step.step_id in set(self.projection.selected_step_ids)
        ]
        expected_complexity = CandidateComplexityInputs(
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
            concrete_binding_count=len(self.projection.bindings),
            execution_requirement_count=len(self.execution_requirements),
        )
        if self.complexity_inputs != expected_complexity:
            raise ValueError("complexity inputs do not match projected candidate")
        return self


def _resource_id(reference: CanonicalResourceReference) -> str:
    if isinstance(reference, EntryPointResourceReference):
        return reference.entry_point_id
    if isinstance(reference, IntegrationResourceReference):
        return reference.integration_id
    if isinstance(reference, TrustBoundaryResourceReference):
        return reference.trust_boundary_id
    if isinstance(reference, ToolResourceReference):
        return reference.tool_id
    if isinstance(reference, OutputSurfaceResourceReference):
        return reference.entry_point_id
    if isinstance(reference, AgentInternalResourceReference):
        return "agent_internal:reasoning"
    raise TypeError(f"unsupported canonical resource reference: {reference!r}")


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


def _source_influence_relation(
    pattern_id: str,
    chain: CanonicalAttackChain,
    selected: tuple[str, ...],
    bindings: tuple[ResourceBinding, ...],
    snapshot: CapabilityFactSnapshot,
) -> tuple[tuple[SourceInfluencePath, ...], ProjectionIssue | None]:
    """Resolve exactly one source relation from immutable projection bindings."""
    bindings_by_slot = {item.slot_id: item.resource_ref for item in bindings}
    selected_ids = set(selected)
    links = [
        link
        for step in chain.steps
        if step.step_id in selected_ids
        for link in step.resource_links
        if link.role == "source_influence"
    ]
    ingress_ref = bindings_by_slot[chain.initial_ingress_slot_id]
    if not isinstance(ingress_ref, EntryPointResourceReference):
        return (), _source_relation_issue(
            pattern_id,
            "canonical ingress is not an entry-point binding",
            canonical_ingress_id=_resource_id(ingress_ref),
        )
    ingress = snapshot.profile.resolve_entry_point(ingress_ref.entry_point_id)
    assert ingress is not None

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

    link = links[0]
    source_ref = bindings_by_slot.get(link.slot_id)
    boundary_ref = bindings_by_slot.get(str(link.trust_boundary_slot_id))
    target_ref = bindings_by_slot.get(str(link.target_ingress_slot_id))
    source_id = _resource_id(source_ref) if source_ref is not None else None
    boundary_id = _resource_id(boundary_ref) if boundary_ref is not None else None
    target_id = _resource_id(target_ref) if target_ref is not None else None
    expected_kind = link.source_identity_kind
    if expected_kind is None:
        source_slot = next(
            slot for slot in chain.resource_slots if slot.slot_id == link.slot_id
        )
        expected_kind = source_slot.kind
    actual_kind = source_ref.kind if source_ref is not None else None
    boundary = (
        snapshot.profile.resolve_trust_boundary(boundary_ref.trust_boundary_id)
        if isinstance(boundary_ref, TrustBoundaryResourceReference)
        else None
    )
    actual_boundary_zones = (
        f"{boundary.from_zone}->{boundary.to_zone}" if boundary is not None else None
    )
    issue_detail: str | None = None
    if actual_kind != expected_kind:
        issue_detail = "source identity kind does not match the concrete binding"
    elif not isinstance(
        source_ref, (EntryPointResourceReference, IntegrationResourceReference)
    ):
        issue_detail = "source binding is not an entry point or integration"
    elif isinstance(source_ref, EntryPointResourceReference):
        source = snapshot.profile.resolve_entry_point(source_ref.entry_point_id)
        if source is None or not is_attacker_accessible_ingress(
            source, snapshot.profile.zones_active
        ):
            issue_detail = "entry-point source is not attacker-influenceable"
        elif source_ref.entry_point_id == ingress_ref.entry_point_id:
            issue_detail = "source entry point must be distinct from target ingress"
    if boundary is None:
        issue_detail = "source-influence boundary is absent from reviewed declarations"
    elif boundary.confidence.value == "hypothesized":
        issue_detail = "source-influence boundary is not a reviewed declaration"
    elif boundary.to_zone != ingress.effective_ingress_zone:
        issue_detail = "trust-boundary destination zone does not match target ingress"
    elif target_id != ingress_ref.entry_point_id:
        issue_detail = "source-influence target is not the canonical ingress binding"
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


def _condition_facts(condition: Condition) -> tuple[AuthoritativeFactReference, ...]:
    if isinstance(condition, (AllCondition, AnyCondition)):
        items = [
            fact for operand in condition.operands for fact in _condition_facts(operand)
        ]
    elif isinstance(condition, NotCondition):
        items = list(_condition_facts(condition.operand))
    else:
        items = [condition.fact]
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


def _references_for_kind(
    kind: str,
    snapshot: CapabilityFactSnapshot,
    *,
    initial_ingress: bool,
    attacker_influence_required: bool,
) -> tuple[CanonicalResourceReference, ...]:
    profile = snapshot.profile
    active_zones = set(profile.zones_active)
    if kind == "entry_point":
        entries = (
            item
            for item in profile.entry_points
            if not (initial_ingress or attacker_influence_required)
            or is_attacker_accessible_ingress(item, active_zones)
        )
        refs: list[CanonicalResourceReference] = [
            EntryPointResourceReference(
                kind="entry_point", entry_point_id=item.entry_point_id
            )
            for item in entries
        ]
    elif kind == "tool":
        refs = [
            ToolResourceReference(kind="tool", tool_id=item.tool_id)
            for item in profile.tool_inventory or ()
        ]
    elif kind == "integration":
        refs = [
            IntegrationResourceReference(
                kind="integration", integration_id=item.integration_id
            )
            for item in profile.external_integrations or ()
        ]
    elif kind == "output_surface":
        refs = [
            OutputSurfaceResourceReference(
                kind="output_surface", entry_point_id=item.entry_point_id
            )
            for item in profile.entry_points
            if item.direction in ("output", "bidirectional")
        ]
    elif kind == "agent_internal":
        # Agent working state is an intrinsic singleton of every validated
        # profile (which must include the reasoning zone), not an adapter
        # inventory item.  Keep its reference typed and identity-free.
        refs = (
            [AgentInternalResourceReference(kind="agent_internal")]
            if "reasoning" in profile.zones_active
            else []
        )
    else:
        refs = [
            TrustBoundaryResourceReference(
                kind="trust_boundary", trust_boundary_id=item.trust_boundary_id
            )
            for item in profile.trust_boundaries or ()
        ]
    return tuple(sorted(refs, key=_resource_key))


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
    compatible: list[CanonicalResourceReference] = []
    for reference in references:
        if allowed_resource_ids and _resource_id(reference) not in allowed_resource_ids:
            continue
        if isinstance(reference, IntegrationResourceReference):
            integration = snapshot.profile.resolve_integration(reference.integration_id)
            if integration is None:  # pragma: no cover - built from this snapshot
                continue
            if (
                slot.allowed_integration_types
                and integration.integration_type.value
                not in slot.allowed_integration_types
            ):
                continue
        elif isinstance(reference, EntryPointResourceReference):
            entry_point = snapshot.profile.resolve_entry_point(reference.entry_point_id)
            if entry_point is None:  # pragma: no cover - built from this snapshot
                continue
            if (
                slot.allowed_entry_point_types
                and entry_point.entry_point_type not in slot.allowed_entry_point_types
            ):
                continue
            if (
                slot.allowed_entry_point_directions
                and entry_point.direction not in slot.allowed_entry_point_directions
            ):
                continue
            if (
                slot.allowed_entry_point_controllability
                and entry_point.controllability
                not in slot.allowed_entry_point_controllability
            ):
                continue
            if (
                slot.allowed_entry_point_ingress_zones
                and entry_point.effective_ingress_zone
                not in slot.allowed_entry_point_ingress_zones
            ):
                continue
        elif isinstance(reference, TrustBoundaryResourceReference):
            boundary = snapshot.profile.resolve_trust_boundary(
                reference.trust_boundary_id
            )
            if boundary is None:  # pragma: no cover - built from this snapshot
                continue
            if (
                slot.allowed_trust_boundary_from_zones
                and boundary.from_zone not in slot.allowed_trust_boundary_from_zones
            ):
                continue
            if (
                slot.allowed_trust_boundary_to_zones
                and boundary.to_zone not in slot.allowed_trust_boundary_to_zones
            ):
                continue
        compatible.append(reference)
    return tuple(compatible)


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
    index_by_slot = {slot.slot_id: index for index, slot in enumerate(slots)}
    edges = {
        frozenset((index, index_by_slot[other_slot_id]))
        for index, slot in enumerate(slots)
        for other_slot_id in slot.distinct_from_slot_ids
    }
    constrained = set().union(*edges) if edges else set()
    total = prod(
        len(slot_options)
        for index, slot_options in enumerate(options)
        if index not in constrained
    )
    remaining = set(constrained)
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
        ordered = sorted(component)

        def count_at(
            offset: int, assigned: dict[int, CanonicalResourceReference]
        ) -> int:
            if offset == len(ordered):
                return 1
            index = ordered[offset]
            count = 0
            for resource in options[index]:
                if any(
                    frozenset((index, other_index)) in edges
                    and resource == other_resource
                    for other_index, other_resource in assigned.items()
                ):
                    continue
                assigned[index] = resource
                count += count_at(offset + 1, assigned)
                del assigned[index]
            return count

        total *= count_at(0, {})
    return total


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

    def _key(items: tuple[CanonicalResourceReference, ...]) -> tuple[str, ...]:
        return tuple(_resource_key(item) for item in items)

    baseline = tuple(slot[0] for slot in options)
    seen.add(_key(baseline))
    yield baseline

    max_len = max(len(slot) for slot in options) if options else 1
    for offset in range(1, max_len):
        for slot_index, slot in enumerate(options):
            if offset < len(slot):
                variant = list(baseline)
                variant[slot_index] = slot[offset]
                variant_t = tuple(variant)
                key = _key(variant_t)
                if key not in seen:
                    seen.add(key)
                    yield variant_t

    # Remaining Cartesian fill — lazy, one at a time.
    for combination in product(*options):
        key = _key(combination)
        if key not in seen:
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
    selected_ids = set(projection.selected_step_ids)
    selected_steps = [step for step in chain.steps if step.step_id in selected_ids]
    requirements: list[ExecutionRequirement] = []

    for step in selected_steps:
        for link in step.resource_links:
            slot = slots_by_id[link.slot_id]
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
                requirements.append(
                    DirectInputControlRequirement(
                        schema_version="1",
                        requirement_id=_requirement_id(
                            "req.direct-input", link.slot_id
                        ),
                        kind="direct_input_control",
                        entry_point_slot_id=link.slot_id,
                    )
                )
            elif link.role == "tool_fixture":
                requirements.append(
                    StateChangingToolFixtureRequirement(
                        schema_version="1",
                        requirement_id=_requirement_id(
                            "req.tool-fixture", step.step_id, link.slot_id
                        ),
                        kind="state_changing_tool_fixture",
                        tool_slot_id=link.slot_id,
                    )
                )
            elif link.role == "source_influence":
                source_identity_kind = link.source_identity_kind or (
                    "entry_point" if slot.kind == "entry_point" else "integration"
                )
                requirements.append(
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
                        source_identity_kind=source_identity_kind,
                        trust_boundary_slot_id=link.trust_boundary_slot_id,
                        target_ingress_slot_id=link.target_ingress_slot_id,
                    )
                )

        # Build a set of postcondition IDs that have explicit outcome links.
        linked_pc_ids = {ol.postcondition_id for ol in step.observable_outcome_links}
        for outcome_link in step.observable_outcome_links:
            requirements.append(
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
            )

        # Security-outcome assertions are derived ONLY from security-relevant
        # postconditions that have an explicit observable outcome link.
        # A security-relevant postcondition without an outcome link does not
        # produce a requirement: the security outcome cannot be asserted
        # without an explicit observation binding.
        for postcondition in step.observable_postconditions:
            if (
                postcondition.security_relevant
                and postcondition.postcondition_id in linked_pc_ids
            ):
                requirements.append(
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
                )

    sorted_reqs = tuple(sorted(requirements, key=lambda item: item.requirement_id))
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
    bindings = {item.slot_id: item.resource_ref for item in projection.bindings}
    for step in chain.steps:
        if step.step_id not in set(projection.selected_step_ids):
            continue
        for link in step.resource_links:
            if link.role == "ingress":
                ingress_ref = bindings[link.slot_id]
                if not isinstance(ingress_ref, EntryPointResourceReference):
                    raise TypeError(  # pragma: no cover - contract guard
                        "ingress binding is not an entry point"
                    )
                ingress = snapshot.profile.resolve_entry_point(
                    ingress_ref.entry_point_id
                )
                if ingress is None:
                    raise ValueError("canonical ingress is absent from snapshot")
                return _derive_execution_requirements_core(
                    pattern_id, chain, projection, ingress.effective_controllability
                )
    # No ingress link found — proceed with indirect (will fail closed).
    return _derive_execution_requirements_core(
        pattern_id, chain, projection, "indirect"
    )


def _projected_mappings(
    chain: CanonicalAttackChain, selected_step_ids: tuple[str, ...]
) -> tuple[ProjectedMapping, ...]:
    mappings = [
        ProjectedMapping(scope="chain", mapping=mapping)
        for mapping in chain.mappings
        if mapping.taxonomy == "ATLAS"
    ]
    selected = set(selected_step_ids)
    for step in chain.steps:
        if step.step_id in selected:
            mappings.extend(
                ProjectedMapping(scope="step", step_id=step.step_id, mapping=mapping)
                for mapping in step.mappings
                if mapping.taxonomy == "ATLAS"
            )
    return tuple(mappings)


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
    if candidate.projection.source_chain != authoritative.canonical_chain:
        raise ValueError("candidate source chain does not match authoritative pattern")
    if candidate.pattern_id != authoritative.id:
        raise ValueError("candidate pattern id does not match authoritative pattern")
    if candidate.projection.pattern_pin != _pattern_pin(authoritative):
        raise ValueError("candidate pattern pin does not match authoritative pattern")
    if candidate.projection.catalog_pin != expected_catalog_pin:
        raise ValueError("candidate catalog pin does not match trusted catalog")
    prerequisites = authoritative.prerequisite_capabilities
    if not set(prerequisites.min_zones).issubset(snapshot.profile.zones_active):
        raise ValueError("authoritative pattern zones are incompatible with snapshot")
    kc_requires = prerequisites.kc_requires
    profile_kc = set(snapshot.profile.kc_subcodes)
    if kc_requires and (
        not set(kc_requires.all).issubset(profile_kc)
        or (kc_requires.any and not set(kc_requires.any).intersection(profile_kc))
    ):
        raise ValueError("authoritative pattern KC requirements are incompatible")
    if candidate.projection.capability_fact_snapshot_digest != snapshot.snapshot_digest:
        raise ValueError("candidate capability snapshot digest pin does not match")
    validate_projection_snapshot(candidate.projection.model_dump(mode="json"), snapshot)
    _validate_source_influence_paths(candidate, snapshot)
    for result in candidate.precondition_results:
        for evidence in result.evidence:
            if snapshot.fact(evidence.fact) != evidence:
                raise ValueError(
                    "precondition fact evidence does not match resolver reading"
                )
    ingress = snapshot.profile.resolve_entry_point(
        candidate.canonical_ingress.entry_point_id
    )
    if ingress is None or ingress.effective_controllability != (
        candidate.ingress_controllability
    ):
        raise ValueError("candidate ingress controllability does not match snapshot")
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
    return candidate


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
    bindings = tuple(
        ResourceBinding(slot_id=slot.slot_id, resource_ref=resource)
        for slot, resource in zip(chain.resource_slots, resources, strict=True)
    )
    source_influence_paths, relation_issue = _source_influence_relation(
        pattern_id, chain, selected, bindings, snapshot
    )
    if relation_issue is not None:
        return None, relation_issue
    projection_data = {
        "schema_version": "1",
        "source_chain": chain.model_dump(mode="json"),
        "selected_step_ids": selected,
        "condition_results": [
            item.model_dump(mode="json") for item in condition_results
        ],
        "omissions": [item.model_dump(mode="json") for item in omissions],
        "bindings": [item.model_dump(mode="json") for item in bindings],
        "catalog_pin": catalog_pin,
        "pattern_pin": pattern_pin,
        "capability_fact_snapshot_digest": snapshot.snapshot_digest,
        "projection_digest": "0" * 64,
        "source_influence_paths": [
            item.model_dump(mode="json") for item in source_influence_paths
        ],
    }
    projection_data["projection_digest"] = compute_projection_digest(projection_data)
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
    ingress_ref = next(
        item.resource_ref
        for item in bindings
        if item.slot_id == chain.initial_ingress_slot_id
    )
    assert isinstance(ingress_ref, EntryPointResourceReference)
    ingress = snapshot.profile.resolve_entry_point(ingress_ref.entry_point_id)
    assert ingress is not None
    selected_steps = [step for step in chain.steps if step.step_id in set(selected)]
    candidate = ProjectedCandidate(
        candidate_id=_candidate_v2_id(pattern_id, projection),
        pattern_id=pattern_id,
        chain_id=chain.chain_id,
        chain_semantic_revision=chain.semantic_revision,
        chain_semantic_digest=chain.semantic_digest,
        projection=projection,
        canonical_ingress=ingress_ref,
        ingress_controllability=ingress.effective_controllability,
        projected_mappings=_projected_mappings(chain, selected),
        precondition_results=precondition_results,
        execution_requirements=requirements,
        requirement_derivation_version="1",
        execution_requirements_digest=requirements_digest,
        complexity_inputs=CandidateComplexityInputs(
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
            concrete_binding_count=len(bindings),
            execution_requirement_count=len(requirements),
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
