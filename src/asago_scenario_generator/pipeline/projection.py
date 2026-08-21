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
    elif (
        ingress.ingress_zone is not None
        and boundary.to_zone != ingress.effective_ingress_zone
    ):
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


def _coverage_first_combinations(
    options: tuple[tuple[CanonicalResourceReference, ...], ...], limit: int
) -> tuple[tuple[CanonicalResourceReference, ...], ...]:
    """Cover each slot's alternatives before bounded Cartesian fill."""
    seen: set[tuple[str, ...]] = set()
    ordered: list[tuple[CanonicalResourceReference, ...]] = []

    def add(items: tuple[CanonicalResourceReference, ...]) -> None:
        key = tuple(_resource_key(item) for item in items)
        if key not in seen and len(ordered) < limit:
            seen.add(key)
            ordered.append(items)

    baseline = tuple(slot[0] for slot in options)
    add(baseline)
    for offset in range(1, max(len(slot) for slot in options)):
        for slot_index, slot in enumerate(options):
            if offset < len(slot):
                variant = list(baseline)
                variant[slot_index] = slot[offset]
                add(tuple(variant))
    if len(ordered) < limit:
        for combination in product(*options):
            add(combination)
            if len(ordered) == limit:
                break
    return tuple(ordered)


def _iter_coverage_first_combinations(
    options: tuple[tuple[CanonicalResourceReference, ...], ...],
) -> Iterable[tuple[CanonicalResourceReference, ...]]:
    """Lazily yield coverage-first combinations without materializing the product.

    Identical ordering to :func:`_coverage_first_combinations` but yields
    one combination at a time so the caller can stop early when the budget
    is reached.  The full Cartesian product is never materialized.

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
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, dict)):
        raise TypeError("authoritative projection requires a sequence of raw records")
    budget = budget or ProjectionBudget()
    snapshot.assert_integrity()
    qualified: list[tuple[AttackPattern, str]] = []
    for raw in records:
        if not isinstance(raw, dict) or "canonical_chain" not in raw:
            raise ValueError(
                "authoritative projection requires qualified canonical-chain records; "
                "legacy catalogue records are isolated"
            )
        try:
            pattern = validate_attack_pattern(raw, taxonomy_resolver)
            pattern = AttackPattern.model_validate(
                _normalize_semantic_order(pattern.model_dump(mode="json"))
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"authoritative attack pattern qualification failed: {exc}"
            ) from exc
        qualified.append((pattern, _pattern_pin(pattern)))
    by_pattern: dict[str, tuple[AttackPattern, str]] = {}
    for item in qualified:
        pattern, pattern_pin = item
        previous = by_pattern.get(pattern.id)
        if previous is not None and previous[1] != pattern_pin:
            raise ValueError("conflicting authoritative records share one pattern id")
        by_pattern[pattern.id] = item
    qualified = [by_pattern[key] for key in sorted(by_pattern)]
    catalog_pin = _content_pin(
        "asago-scenario-generator:authoritative-catalog:v1",
        [pattern_pin for _, pattern_pin in qualified],
    )

    candidate_groups: list[tuple[str, int, list[ProjectedCandidate]]] = []
    issues: list[ProjectionIssue] = []
    limitations: list[ProjectionLimitation] = []

    for pattern, pattern_pin in qualified:
        chain = pattern.canonical_chain
        prerequisites = pattern.prerequisite_capabilities
        missing_zones = sorted(
            set(prerequisites.min_zones) - set(snapshot.profile.zones_active)
        )
        kc_requires = prerequisites.kc_requires
        profile_kc = set(snapshot.profile.kc_subcodes)
        missing_all = sorted(set(kc_requires.all) - profile_kc) if kc_requires else []
        any_satisfied = (
            not kc_requires
            or not kc_requires.any
            or bool(set(kc_requires.any) & profile_kc)
        )
        if missing_zones or missing_all or not any_satisfied:
            details = []
            if missing_zones:
                details.append(f"missing zones: {', '.join(missing_zones)}")
            if missing_all:
                details.append(f"missing required KC codes: {', '.join(missing_all)}")
            if not any_satisfied and kc_requires:
                details.append(
                    "requires any KC code from: " + ", ".join(sorted(kc_requires.any))
                )
            issues.append(
                ProjectionIssue(
                    code="incompatible_profile",
                    pattern_id=pattern.id,
                    detail="; ".join(details),
                )
            )
            continue

        condition_results = _evaluate_projection_conditions(pattern, snapshot)
        unknown = [item for item in condition_results if item.result == "unknown"]
        if unknown:
            issues.append(
                ProjectionIssue(
                    code="unresolved_condition",
                    pattern_id=pattern.id,
                    step_id=unknown[0].condition_step_id,
                    detail="one or more authoritative condition facts are unresolved",
                    condition_results=condition_results,
                )
            )
            continue
        result_by_step = {
            item.condition_step_id: item.result for item in condition_results
        }
        selected = tuple(
            step.step_id
            for step in chain.steps
            if step.requirement == "required" or result_by_step[step.step_id] == "true"
        )
        if chain.steps[-1].step_id not in selected or not any(
            step.attacker_controlled and step.step_id in set(selected)
            for step in chain.steps
        ):
            issues.append(
                ProjectionIssue(
                    code="inapplicable_projection",
                    pattern_id=pattern.id,
                    detail=(
                        "condition results omit the terminal outcome or every "
                        "attacker-controlled step"
                    ),
                    condition_results=condition_results,
                )
            )
            continue
        omissions = tuple(
            StepOmission(step_id=step.step_id, reason="condition_false")
            for step in chain.steps
            if step.requirement == "conditional"
            and result_by_step[step.step_id] == "false"
        )
        precondition_results = _evaluate_preconditions(pattern, selected, snapshot)
        unresolved_preconditions = [
            item for item in precondition_results if item.result == "unknown"
        ]
        if unresolved_preconditions:
            issues.append(
                ProjectionIssue(
                    code="unresolved_condition",
                    pattern_id=pattern.id,
                    step_id=unresolved_preconditions[0].step_id,
                    detail="one or more selected-step preconditions are unresolved",
                    condition_results=condition_results,
                    precondition_results=precondition_results,
                )
            )
            continue
        false_preconditions = [
            item for item in precondition_results if item.result == "false"
        ]
        if false_preconditions:
            issues.append(
                ProjectionIssue(
                    code="precondition_not_satisfied",
                    pattern_id=pattern.id,
                    step_id=false_preconditions[0].step_id,
                    detail="one or more selected-step preconditions are false",
                    condition_results=condition_results,
                    precondition_results=precondition_results,
                )
            )
            continue

        ingress_index = next(
            index
            for index, slot in enumerate(chain.resource_slots)
            if slot.slot_id == chain.initial_ingress_slot_id
        )
        option_sets: list[tuple[CanonicalResourceReference, ...]] = []
        missing_slots = []
        for slot in chain.resource_slots:
            options = _references_for_slot(
                slot,
                snapshot,
                initial_ingress=slot.slot_id == chain.initial_ingress_slot_id,
            )
            option_sets.append(options)
            if not options:
                missing_slots.append(slot)
        if missing_slots:
            relation_links = [
                link
                for step in chain.steps
                if step.step_id in set(selected)
                for link in step.resource_links
                if link.role == "source_influence"
            ]
            relation_slot_ids = (
                {link.slot_id for link in relation_links}
                | {str(link.trust_boundary_slot_id) for link in relation_links}
                | {str(link.target_ingress_slot_id) for link in relation_links}
            )
            relation_has_explicit_ids = any(
                item.allowed_resource_ids
                for item in chain.resource_slots
                if item.slot_id in relation_slot_ids
            )
            for slot in missing_slots:
                if (
                    slot.slot_id not in relation_slot_ids
                    or not relation_has_explicit_ids
                ):
                    issues.append(
                        ProjectionIssue(
                            code="missing_compatible_resource",
                            pattern_id=pattern.id,
                            slot_id=slot.slot_id,
                            detail=f"no compatible canonical {slot.kind} resource for slot",
                        )
                    )
                    continue
                link = relation_links[0]
                source_slot = next(
                    item
                    for item in chain.resource_slots
                    if item.slot_id == link.slot_id
                )
                ingress_options = option_sets[ingress_index] if option_sets else ()
                target_id = (
                    _resource_id(ingress_options[0])
                    if ingress_options
                    else next(
                        iter(
                            next(
                                (
                                    item.allowed_resource_ids
                                    for item in chain.resource_slots
                                    if item.slot_id == str(link.target_ingress_slot_id)
                                ),
                                (),
                            )
                        ),
                        None,
                    )
                )
                target = (
                    snapshot.profile.resolve_entry_point(target_id)
                    if isinstance(target_id, str)
                    else None
                )
                source_ids = source_slot.allowed_resource_ids
                boundary_slot = next(
                    item
                    for item in chain.resource_slots
                    if item.slot_id == str(link.trust_boundary_slot_id)
                )
                boundary_id = next(iter(boundary_slot.allowed_resource_ids), None)
                source_id = next(iter(source_ids), None)
                issues.append(
                    ProjectionIssue(
                        code="source_influence_relation_infeasible",
                        pattern_id=pattern.id,
                        slot_id=slot.slot_id,
                        detail="source-influence relation resource is not reviewed",
                        source_id=source_id,
                        boundary_id=boundary_id,
                        target_ingress_id=target_id,
                        canonical_ingress_id=target_id,
                        expected_target_zone=(
                            target.effective_ingress_zone
                            if target is not None
                            else None
                        ),
                        actual_boundary_zones="unreviewed",
                        expected_source_kind=(
                            link.source_identity_kind or source_slot.kind
                        ),
                        actual_binding_kind=source_slot.kind,
                        guidance=(
                            "Review the explicit ingress_zone or trust-boundary "
                            "declaration."
                        ),
                    )
                )
            continue

        direct_ingress_options = tuple(
            option
            for option in option_sets[ingress_index]
            if isinstance(option, EntryPointResourceReference)
            and snapshot.profile.resolve_entry_point(
                option.entry_point_id
            ).effective_controllability
            == "direct"
        )
        # A source-influence chain activates through an explicit
        # source-boundary → canonical-ingress edge, not direct ingress
        # control, so indirect ingress entry points are admissible.  A
        # direct-ingress chain still requires a directly controllable
        # ingress; indirect ingress there fails closed.
        # Activation is checked only over SELECTED steps: a conditional
        # activation step may be omitted, and the chain must still have
        # an activatable mechanism among the remaining selected steps.
        selected_set = set(selected)
        has_source_influence_activation = any(
            link.role == "source_influence"
            and link.target_ingress_slot_id == chain.initial_ingress_slot_id
            for step in chain.steps
            if step.step_id in selected_set
            for link in step.resource_links
        )
        has_direct_ingress_activation = any(
            link.role == "ingress" and link.slot_id == chain.initial_ingress_slot_id
            for step in chain.steps
            if step.step_id in selected_set
            for link in step.resource_links
        )
        if not has_source_influence_activation and not has_direct_ingress_activation:
            issues.append(
                ProjectionIssue(
                    code="unsupported_requirement_derivation",
                    pattern_id=pattern.id,
                    detail=(
                        "no activation mechanism (ingress or source_influence) "
                        "among selected steps"
                    ),
                )
            )
            continue
        if has_source_influence_activation and has_direct_ingress_activation:
            issues.append(
                ProjectionIssue(
                    code="unsupported_requirement_derivation",
                    pattern_id=pattern.id,
                    detail=(
                        "contradictory activation: selected steps contain both "
                        "direct ingress and source_influence links to the "
                        "initial ingress"
                    ),
                )
            )
            continue
        if has_source_influence_activation:
            if not option_sets[ingress_index]:
                continue
        else:
            if len(direct_ingress_options) != len(option_sets[ingress_index]):
                issues.append(
                    ProjectionIssue(
                        code="unsupported_requirement_derivation",
                        pattern_id=pattern.id,
                        detail=(
                            "indirect ingress requires explicit upstream-source and "
                            "trust-boundary linkage"
                        ),
                    )
                )
            if not direct_ingress_options:
                continue
            option_sets[ingress_index] = direct_ingress_options

        total_bindings = _count_compatible_combinations(
            chain.resource_slots, tuple(option_sets)
        )
        if total_bindings == 0:
            constrained_slot = next(
                slot for slot in chain.resource_slots if slot.distinct_from_slot_ids
            )
            issues.append(
                ProjectionIssue(
                    code="missing_compatible_resource",
                    pattern_id=pattern.id,
                    slot_id=constrained_slot.slot_id,
                    detail=(
                        "no concrete resource assignment satisfies explicit "
                        "per-slot distinctness constraints"
                    ),
                )
            )
            continue

        # cmps.4 blocker 3 (corrected): Do NOT eagerly materialize all
        # Cartesian combinations.  Store the lazy iterator and pattern
        # metadata so candidates are built on demand during reservation
        # and bounded variant fill.  The full product is never materialized.
        combination_iter = _iter_compatible_combinations(
            chain.resource_slots, tuple(option_sets)
        )
        pattern_state = _PatternProjectionState(
            pattern_id=pattern.id,
            chain=chain,
            selected=selected,
            condition_results=condition_results,
            omissions=omissions,
            option_sets=tuple(option_sets),
            total_bindings=total_bindings,
            catalog_pin=catalog_pin,
            pattern_pin=pattern_pin,
            precondition_results=precondition_results,
            combination_iter=combination_iter,
            snapshot=snapshot,
        )
        candidate_groups.append(pattern_state)

    # Bounded, lazy allocation.  Every derivation consumes exactly one work
    # unit, including structural rejects; no helper may scan an iterator.
    # Candidates discovered during target reservation are kept pending, so a
    # later variant fill cannot silently discard a feasible candidate.
    by_identity: dict[str, ProjectedCandidate] = {}
    pending: list[tuple[int, ProjectedCandidate]] = []
    emitted_by_group = [0] * len(candidate_groups)
    derived_candidate_ids: list[set[str]] = [set() for _ in candidate_groups]
    work_used = 0
    work_exhausted = False

    def derive_one(
        group_index: int, iterator: Any
    ) -> tuple[ProjectedCandidate | None, bool, bool]:
        """Derive at most one combination.

        Returns ``(candidate, is_unique, exhausted)``.  A candidate reached
        through both a target-pinned iterator and the generic iterator is
        one derived candidate, not two budget-truncated candidates.
        """
        nonlocal work_used, work_exhausted
        if work_used >= budget.max_derivation_work:
            work_exhausted = True
            return None, False, True
        try:
            resources = next(iterator)
        except StopIteration:
            return None, False, True
        work_used += 1
        state = candidate_groups[group_index]
        candidate, issue = _build_candidate_from_combination(
            state.pattern_id,
            state.chain,
            state.selected,
            state.condition_results,
            state.omissions,
            resources,
            state.catalog_pin,
            state.pattern_pin,
            state.precondition_results,
            state.snapshot,
        )
        if issue is not None:
            issues.append(issue)
        if candidate is not None:
            is_unique = candidate.candidate_id not in derived_candidate_ids[group_index]
            if is_unique:
                derived_candidate_ids[group_index].add(candidate.candidate_id)
                state.generated.append(candidate)
            return candidate, is_unique, False
        return None, False, False

    def emit(group_index: int, candidate: ProjectedCandidate) -> None:
        previous = by_identity.get(candidate.candidate_id)
        if previous is not None and previous != candidate:
            raise ValueError("candidate-v2 identity collision")
        if previous is None and len(by_identity) < budget.max_candidates:
            by_identity[candidate.candidate_id] = candidate
            emitted_by_group[group_index] += 1

    target_to_first_candidate: dict[str, tuple[int, ProjectedCandidate]] = {}
    unresolved_targets: set[str] = set()
    if coverage_target_ids:
        # Pin the ingress slot to each sorted target, then derive a
        # coverage-first baseline for the other slots.  This independently
        # reserves every target; a pattern with 3+ ingresses is not limited
        # by prior generic iterator passes.
        for target_id in sorted(coverage_target_ids):
            target_found = False
            for group_index, state in enumerate(candidate_groups):
                ingress_index = next(
                    index
                    for index, slot in enumerate(state.chain.resource_slots)
                    if slot.slot_id == state.chain.initial_ingress_slot_id
                )
                target_ref = next(
                    (
                        ref
                        for ref in state.option_sets[ingress_index]
                        if isinstance(ref, EntryPointResourceReference)
                        and ref.entry_point_id == target_id
                    ),
                    None,
                )
                if target_ref is None:
                    continue
                target_options = list(state.option_sets)
                target_options[ingress_index] = (target_ref,)
                target_iter = iter(
                    _iter_compatible_combinations(
                        state.chain.resource_slots, tuple(target_options)
                    )
                )
                while True:
                    candidate, is_unique, exhausted = derive_one(
                        group_index, target_iter
                    )
                    if work_exhausted:
                        break
                    if candidate is not None:
                        if is_unique:
                            pending.append((group_index, candidate))
                        target_to_first_candidate[target_id] = (group_index, candidate)
                        target_found = True
                        break
                    if exhausted:
                        break
                if target_found or work_exhausted:
                    break
            if not target_found:
                if work_exhausted:
                    unresolved_targets.add(target_id)
                else:
                    unresolved_targets.add(target_id)

        infeasible_coverage_targets = tuple(
            sorted(unresolved_targets) if not work_exhausted else ()
        )
        unknown_coverage_targets = set(unresolved_targets) if work_exhausted else set()
        for target_id in sorted(target_to_first_candidate):
            group_index, candidate = target_to_first_candidate[target_id]
            emit(group_index, candidate)
    else:
        infeasible_coverage_targets = ()
        unknown_coverage_targets: set[str] = set()

    # Emit every already-derived pending candidate before deriving variants.
    pending_index = 0
    while pending_index < len(pending) and len(by_identity) < budget.max_candidates:
        group_index, candidate = pending[pending_index]
        pending_index += 1
        emit(group_index, candidate)

    # Round-robin variant fill.  Each call derives one combination, so work
    # remains hard-bounded even for enormous structurally-rejected products.
    while len(by_identity) < budget.max_candidates and not work_exhausted:
        progressed = False
        for group_index, state in enumerate(candidate_groups):
            candidate, _, exhausted = derive_one(group_index, state._iter)
            if candidate is not None:
                emit(group_index, candidate)
                progressed = True
            elif not exhausted:
                progressed = True
            if len(by_identity) >= budget.max_candidates or work_exhausted:
                break
        if not progressed:
            break

    # A single bounded probe may establish a real candidate-output truncation;
    # it never scans the remaining Cartesian product.
    if len(by_identity) >= budget.max_candidates and not pending[pending_index:]:
        for group_index, state in enumerate(candidate_groups):
            candidate, is_unique, _ = derive_one(group_index, state._iter)
            if (candidate is not None and is_unique) or work_exhausted:
                break

    if coverage_target_ids:
        emitted_target_ids = {
            candidate.canonical_ingress.entry_point_id
            for candidate in by_identity.values()
        }
        unreserved_targets = tuple(
            sorted(
                (set(target_to_first_candidate) | unknown_coverage_targets)
                - emitted_target_ids
            )
        )
    else:
        unreserved_targets = ()

    for group_index, state in enumerate(candidate_groups):
        if state.emitted > emitted_by_group[group_index]:
            limitations.append(
                ProjectionLimitation(
                    code="candidate_budget_exhausted",
                    pattern_id=state.pattern_id,
                    total_compatible_bindings=state.total_bindings,
                    emitted_bindings=emitted_by_group[group_index],
                )
            )
    if work_exhausted:
        limitations.extend(
            ProjectionLimitation(
                code="derivation_work_exhausted",
                pattern_id=state.pattern_id,
                total_compatible_bindings=state.total_bindings,
                emitted_bindings=emitted_by_group[group_index],
            )
            for group_index, state in enumerate(candidate_groups)
        )
    unique_issues = {
        _canonical_json(issue.model_dump(mode="json")): issue for issue in issues
    }
    return ProjectionBatch(
        capability_fact_snapshot_digest=snapshot.snapshot_digest,
        candidates=tuple(by_identity[key] for key in sorted(by_identity)),
        infeasibilities=tuple(
            sorted(
                unique_issues.values(),
                key=lambda item: (
                    item.pattern_id,
                    item.code,
                    item.step_id or "",
                    item.slot_id or "",
                ),
            )
        ),
        limitations=tuple(
            sorted(limitations, key=lambda item: (item.pattern_id, item.code))
        ),
        unreserved_coverage_targets=unreserved_targets,
        infeasible_coverage_targets=infeasible_coverage_targets,
    )
