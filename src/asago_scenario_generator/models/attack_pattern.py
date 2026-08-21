"""Authoritative and legacy attack-pattern contracts.

The authoritative contract is intentionally independent from the YAML catalogue.
Catalogue records must be parsed explicitly with :class:`LegacyAttackPatternRecord`.
Generated JSON Schema describes the transport structure; Pydantic validators remain
authoritative for cross-field semantics, digests, and injected taxonomy resolution.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Annotated, Any, Literal, Protocol, TypeAlias

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

MAX_CONDITION_DEPTH = 4
MAX_CONDITION_NODES = 32
MAX_CONDITION_OPERANDS = 16
MAX_MEMBERSHIP_VALUES = 32
MAX_PROPERTY_PATH_SEGMENTS = 4

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Identifier = Annotated[
    str, Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
]
Scalar: TypeAlias = StrictStr | StrictInt | StrictBool


class ContractModel(BaseModel):
    """Common closed, immutable configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class EvidenceLink(ContractModel):
    source: str = Field(min_length=1)
    type: Literal["direct_demonstration", "variant", "enrichment"]


class CapabilityRequirements(ContractModel):
    all: tuple[str, ...] = ()
    any: tuple[str, ...] = ()


class PrerequisiteCapabilities(ContractModel):
    min_zones: tuple[str, ...]
    kc_requires: CapabilityRequirements | None = None


class NistClassification(ContractModel):
    attacker_goal: str
    attacker_knowledge: str
    learning_stage: str
    attack_class: str | None = None


class LegacyKillChainStep(ContractModel):
    step: str
    tactic: str = Field(pattern=r"^AML\.TA\d{4}$")
    techniques: tuple[Annotated[str, Field(pattern=r"^AML\.T")], ...] = Field(
        min_length=1
    )
    abstract_action: str


class LegacyPrerequisiteCapabilities(ContractModel):
    min_zones: tuple[str, ...]
    kc_requires: dict[str, tuple[str, ...]] | None = None


class LegacyAttackPatternRecord(ContractModel):
    id: str
    threat_id: str
    name: str
    description: str
    nist_classification: NistClassification | None = None
    prerequisite_capabilities: LegacyPrerequisiteCapabilities
    kill_chain: tuple[LegacyKillChainStep, ...] | None = None
    evidence: tuple[EvidenceLink, ...] | None = None


class TaxonomyPin(ContractModel):
    release: str = Field(min_length=1)
    digest: Digest


class TaxonomyContext(ContractModel):
    """Pinned taxonomy releases; LAAF is optional and non-authoritative for v1.

    An absent ``laaf`` pin means the context is ATLAS-only: any LAAF mapping
    decision in the chain then fails closed.  An explicit pin is meaningful
    only when the qualifying resolver pins the identical context and carries
    authoritative LAAF membership for every exact id.
    """

    atlas: TaxonomyPin
    laaf: TaxonomyPin | None = None
    mapping_set_digest: Digest


class TaxonomyResolver(Protocol):
    """Required no-I/O resolver used by the qualification helper."""

    @property
    def taxonomy_context(self) -> TaxonomyContext: ...

    def contains(self, taxonomy: Literal["ATLAS", "LAAF"], identifier: str) -> bool: ...


class CapabilitySnapshotResolver(Protocol):
    """No-I/O abstraction over one pinned capability/fact snapshot."""

    @property
    def capability_fact_snapshot_digest(self) -> Digest: ...

    def fact(
        self, reference: AuthoritativeFactReference
    ) -> EvaluatedFactEvidence | None: ...

    def contains_resource(self, reference: CanonicalResourceReference) -> bool: ...

    def resource_matches_slot(
        self, reference: CanonicalResourceReference, slot: ResourceSlot
    ) -> bool: ...


class TypedReference(ContractModel):
    ref_id: Identifier
    value_type: Literal["string", "integer", "boolean", "object", "bytes"]


class ArtifactReference(TypedReference):
    kind: Literal["artifact"]


class StateReference(TypedReference):
    kind: Literal["state"]


class EffectReference(TypedReference):
    kind: Literal["effect"]


OutputReference = Annotated[
    ArtifactReference | StateReference | EffectReference, Field(discriminator="kind")
]
InputReference = Annotated[
    ArtifactReference | StateReference, Field(discriminator="kind")
]


class AuthoritativeFactReference(ContractModel):
    """Reference to a pre-existing authoritative fact (never a generated artifact)."""

    namespace: Literal["system", "profile", "catalog", "runtime_state"]
    fact_id: Identifier
    value_type: Literal["string", "integer", "boolean"]
    property_path: tuple[Identifier, ...] = Field(max_length=MAX_PROPERTY_PATH_SEGMENTS)


def _validate_fact_scalar(fact: AuthoritativeFactReference, value: Scalar) -> None:
    expected = {"string": str, "integer": int, "boolean": bool}[fact.value_type]
    if type(value) is not expected:
        raise ValueError(f"value must exactly match fact value_type {fact.value_type}")


class EqualityCondition(ContractModel):
    op: Literal["equality"]
    schema_version: Literal["1"]
    fact: AuthoritativeFactReference
    value: Scalar

    @model_validator(mode="after")
    def matching_type(self) -> EqualityCondition:
        _validate_fact_scalar(self.fact, self.value)
        return self


class MembershipCondition(ContractModel):
    op: Literal["membership"]
    schema_version: Literal["1"]
    fact: AuthoritativeFactReference
    values: tuple[Scalar, ...] = Field(min_length=1, max_length=MAX_MEMBERSHIP_VALUES)

    @model_validator(mode="after")
    def unique_values(self) -> MembershipCondition:
        for value in self.values:
            _validate_fact_scalar(self.fact, value)
        if len({_canonical_json(v) for v in self.values}) != len(self.values):
            raise ValueError("membership values must be unique")
        return self


class ExistenceCondition(ContractModel):
    op: Literal["existence"]
    schema_version: Literal["1"]
    fact: AuthoritativeFactReference
    exists: StrictBool


class PropertyMatchCondition(ContractModel):
    op: Literal["property_match"]
    schema_version: Literal["1"]
    fact: AuthoritativeFactReference
    value: Scalar

    @model_validator(mode="after")
    def matching_type_and_path(self) -> PropertyMatchCondition:
        if not self.fact.property_path:
            raise ValueError("property_match requires a nonempty property path")
        _validate_fact_scalar(self.fact, self.value)
        return self


class AllCondition(ContractModel):
    op: Literal["all"]
    schema_version: Literal["1"]
    operands: tuple[Condition, ...] = Field(
        min_length=2, max_length=MAX_CONDITION_OPERANDS
    )

    @model_validator(mode="after")
    def bounded(self) -> AllCondition:
        _check_condition(self)
        return self


class AnyCondition(ContractModel):
    op: Literal["any"]
    schema_version: Literal["1"]
    operands: tuple[Condition, ...] = Field(
        min_length=2, max_length=MAX_CONDITION_OPERANDS
    )

    @model_validator(mode="after")
    def bounded(self) -> AnyCondition:
        _check_condition(self)
        return self


class NotCondition(ContractModel):
    op: Literal["not"]
    schema_version: Literal["1"]
    operand: Condition

    @model_validator(mode="after")
    def bounded(self) -> NotCondition:
        _check_condition(self)
        return self


Condition: TypeAlias = Annotated[
    EqualityCondition
    | MembershipCondition
    | ExistenceCondition
    | PropertyMatchCondition
    | AllCondition
    | AnyCondition
    | NotCondition,
    Field(discriminator="op"),
]


def _check_condition(condition: Condition) -> None:
    count = 0

    def walk(node: Condition, depth: int) -> None:
        nonlocal count
        count += 1
        if depth > MAX_CONDITION_DEPTH or count > MAX_CONDITION_NODES:
            raise ValueError("condition exceeds structural limits")
        children = (
            node.operands if isinstance(node, (AllCondition, AnyCondition)) else ()
        )
        if isinstance(node, NotCondition):
            children = (node.operand,)
        if children and len(
            {_canonical_json(c.model_dump(mode="json")) for c in children}
        ) != len(children):
            raise ValueError("duplicate condition operands")
        for child in children:
            walk(child, depth + 1)

    walk(condition, 1)


class EvaluatedFactEvidence(ContractModel):
    fact: AuthoritativeFactReference
    status: Literal["present", "absent", "unknown"]
    value: Scalar | None = None

    @model_validator(mode="after")
    def coherent(self) -> EvaluatedFactEvidence:
        if self.status in ("absent", "unknown"):
            if self.value is not None:
                raise ValueError("absent/unknown fact evidence requires a null value")
        elif self.value is None:
            raise ValueError("present fact evidence requires a value")
        else:
            _validate_fact_scalar(self.fact, self.value)
        return self


class ConditionEvaluationResult(ContractModel):
    condition_step_id: Identifier
    result: Literal["true", "false", "unknown"]
    evidence: tuple[EvaluatedFactEvidence, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_evidence_facts(self) -> ConditionEvaluationResult:
        facts = [
            _canonical_json(item.fact.model_dump(mode="json")) for item in self.evidence
        ]
        if len(facts) != len(set(facts)):
            raise ValueError("condition evidence facts must be unique")
        return self


class ProvenanceReference(ContractModel):
    reference_type: Literal["catalog", "publication", "observation", "design_record"]
    reference_id: str = Field(min_length=1)


class StepProvenance(ContractModel):
    tier: Literal["observed", "variant", "inferred", "designed"]
    references: tuple[ProvenanceReference, ...] = Field(min_length=1)
    confidence: StrictInt = Field(ge=0, le=100)
    adaptation_rationale: str = Field(min_length=1)

    @model_validator(mode="after")
    def unique_references(self) -> StepProvenance:
        keys = [
            (reference.reference_type, reference.reference_id)
            for reference in self.references
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("provenance references must be unique")
        return self


class ExactMapping(ContractModel):
    decision: Literal["exact"]
    taxonomy: Literal["ATLAS", "LAAF"]
    ids: tuple[Annotated[str, Field(min_length=1)], ...] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_ids(self) -> ExactMapping:
        if len(set(self.ids)) != len(self.ids):
            raise ValueError("exact mapping ids must be unique")
        return self


class NotApplicableMapping(ContractModel):
    decision: Literal["not_applicable"]
    taxonomy: Literal["ATLAS", "LAAF"]


class UnmappedMapping(ContractModel):
    decision: Literal["unmapped"]
    taxonomy: Literal["ATLAS", "LAAF"]
    rationale: str = Field(min_length=1)


MappingDecision: TypeAlias = Annotated[
    ExactMapping | NotApplicableMapping | UnmappedMapping,
    Field(discriminator="decision"),
]
ChainMappingDecision: TypeAlias = Annotated[
    ExactMapping | UnmappedMapping,
    Field(discriminator="decision"),
]


class StepPrecondition(ContractModel):
    condition_id: Identifier
    condition: Condition

    @model_validator(mode="after")
    def bounded(self) -> StepPrecondition:
        _check_condition(self.condition)
        return self


class ObservablePostcondition(ContractModel):
    postcondition_id: Identifier
    description: str = Field(min_length=1)
    security_relevant: StrictBool
    terminal: StrictBool


class StepResourceLink(ContractModel):
    """Explicit link from a step to a required resource slot.

    The ``role`` declares how the slot is used by the step, determining the
    execution-requirement derivation.  No inference from action kind, name,
    or cardinality is performed by the projection — the link is the sole
    authority for requirement derivation.

    For ``source_influence`` links the ``slot_id`` is the upstream source
    slot (an entry point or integration the attacker influences outside the
    trust boundary), ``trust_boundary_slot_id`` is the boundary the source
    content crosses, and ``target_ingress_slot_id`` is the canonical ingress
    entry point the influenced content flows into.  The target-ingress edge
    is explicit: the projection never assumes the chain's initial ingress
    implicitly supplies this relation.
    """

    slot_id: Identifier
    role: Literal["ingress", "tool_fixture", "source_influence"]
    trust_boundary_slot_id: Identifier | None = None
    target_ingress_slot_id: Identifier | None = None
    # Keep the declared relation kind separate from the bound slot kind so
    # qualification can reject a forged kind without substituting a resource.
    source_identity_kind: Literal["entry_point", "integration"] | None = None

    @model_validator(mode="after")
    def source_influence_fields_are_exclusive(self) -> StepResourceLink:
        if self.role == "source_influence":
            if self.trust_boundary_slot_id is None:
                raise ValueError(
                    "source_influence resource link requires a trust_boundary_slot_id"
                )
            if self.target_ingress_slot_id is None:
                raise ValueError(
                    "source_influence resource link requires a target_ingress_slot_id"
                )
        else:
            if self.trust_boundary_slot_id is not None:
                raise ValueError(
                    "trust_boundary_slot_id is only valid for source_influence links"
                )
            if self.target_ingress_slot_id is not None:
                raise ValueError(
                    "target_ingress_slot_id is only valid for source_influence links"
                )
            if self.source_identity_kind is not None:
                raise ValueError(
                    "source_identity_kind is only valid for source_influence links"
                )
        return self


class ObservableOutcomeLink(ContractModel):
    """Explicit link from a step's postcondition to an observable outcome.

    Declares that a postcondition is observable through a specific resource
    slot as a specific observation kind.  The derivation consumes this link
    to produce an :class:`ObservationRequirement`.
    """

    postcondition_id: Identifier
    observation: Literal[
        "model_context",
        "tool_invocation",
        "persistent_state",
        "rendered_output",
        "endpoint_receipt",
        "agent_state",
    ]
    binding_slot_id: Identifier


class DirectInputControlRequirement(ContractModel):
    schema_version: Literal["1"]
    requirement_id: Identifier
    kind: Literal["direct_input_control"]
    entry_point_slot_id: Identifier


class UpstreamSourceInfluenceRequirement(ContractModel):
    schema_version: Literal["1"]
    requirement_id: Identifier
    kind: Literal["upstream_source_influence"]
    source_slot_id: Identifier
    source_identity_kind: Literal["entry_point", "integration"]
    trust_boundary_slot_id: Identifier
    target_ingress_slot_id: Identifier


class StateChangingToolFixtureRequirement(ContractModel):
    schema_version: Literal["1"]
    requirement_id: Identifier
    kind: Literal["state_changing_tool_fixture"]
    tool_slot_id: Identifier


class ObservationRequirement(ContractModel):
    schema_version: Literal["1"]
    requirement_id: Identifier
    kind: Literal["observation"]
    observation: Literal[
        "model_context",
        "tool_invocation",
        "persistent_state",
        "rendered_output",
        "endpoint_receipt",
        "agent_state",
    ]
    binding_slot_id: Identifier


class SecurityOutcomeAssertionRequirement(ContractModel):
    schema_version: Literal["1"]
    requirement_id: Identifier
    kind: Literal["security_outcome_assertion"]
    source_step_id: Identifier
    postcondition_id: Identifier


class SourceInfluencePath(ContractModel):
    """One deterministic source-to-boundary-to-ingress relation."""

    source_identity_kind: Literal["entry_point", "integration"]
    source_id: str
    boundary_id: str
    target_ingress_id: str
    expected_target_zone: str
    boundary_zones: str


ExecutionRequirement: TypeAlias = Annotated[
    DirectInputControlRequirement
    | UpstreamSourceInfluenceRequirement
    | StateChangingToolFixtureRequirement
    | ObservationRequirement
    | SecurityOutcomeAssertionRequirement,
    Field(discriminator="kind"),
]


def _condition_fact_keys(condition: Condition) -> set[str]:
    if isinstance(condition, (AllCondition, AnyCondition)):
        return {
            fact
            for operand in condition.operands
            for fact in _condition_fact_keys(operand)
        }
    if isinstance(condition, NotCondition):
        return _condition_fact_keys(condition.operand)
    return {_canonical_json(condition.fact.model_dump(mode="json"))}


def evaluate_condition(
    condition: Condition, evidence: tuple[EvaluatedFactEvidence, ...]
) -> Literal["true", "false", "unknown"]:
    """Purely evaluate the closed condition AST against complete fact evidence."""
    keyed = {
        _canonical_json(item.fact.model_dump(mode="json")): item for item in evidence
    }
    if len(keyed) != len(evidence):
        raise ValueError("condition evidence facts must be unique")
    if set(keyed) != _condition_fact_keys(condition):
        raise ValueError("condition evidence must exactly cover condition facts")

    def evaluate(node: Condition) -> Literal["true", "false", "unknown"]:
        if isinstance(node, AllCondition):
            results = tuple(evaluate(item) for item in node.operands)
            return (
                "false"
                if "false" in results
                else "unknown"
                if "unknown" in results
                else "true"
            )
        if isinstance(node, AnyCondition):
            results = tuple(evaluate(item) for item in node.operands)
            return (
                "true"
                if "true" in results
                else "unknown"
                if "unknown" in results
                else "false"
            )
        if isinstance(node, NotCondition):
            result = evaluate(node.operand)
            return {"true": "false", "false": "true", "unknown": "unknown"}[result]

        item = keyed[_canonical_json(node.fact.model_dump(mode="json"))]
        if item.status == "unknown":
            return "unknown"
        if isinstance(node, ExistenceCondition):
            present = item.status == "present"
            return "true" if present == node.exists else "false"
        if item.status == "absent":
            return "false"
        if isinstance(node, MembershipCondition):
            matches = item.value in node.values
        else:
            matches = item.value == node.value
        return "true" if matches else "false"

    return evaluate(condition)


class CanonicalChainStep(ContractModel):
    step_id: Identifier
    requirement: Literal["required", "conditional"]
    condition: Condition | None = None
    executor_role: Literal["attacker", "system", "operator"]
    boundary_position: Literal["outside", "crossing", "inside"]
    action_kind: Literal[
        "prepare", "deliver", "invoke", "transform", "persist", "observe", "impact"
    ]
    consumed: tuple[InputReference, ...]
    produced: tuple[OutputReference, ...] = Field(min_length=1)
    preconditions: tuple[StepPrecondition, ...]
    observable_postconditions: tuple[ObservablePostcondition, ...] = Field(min_length=1)
    resource_links: tuple[StepResourceLink, ...] = ()
    observable_outcome_links: tuple[ObservableOutcomeLink, ...] = ()
    order: StrictInt = Field(gt=0)
    attacker_controlled: StrictBool
    provenance: StepProvenance
    mappings: tuple[MappingDecision, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def semantics(self) -> CanonicalChainStep:
        if (self.requirement == "conditional") != (self.condition is not None):
            raise ValueError(
                "conditional steps require a condition; required steps forbid it"
            )
        if self.condition is not None:
            _check_condition(self.condition)
        for collection, label, attribute in (
            (self.consumed, "consumed references", "ref_id"),
            (self.produced, "produced references", "ref_id"),
            (self.preconditions, "preconditions", "condition_id"),
            (
                self.observable_postconditions,
                "observable postconditions",
                "postcondition_id",
            ),
            (self.resource_links, "resource links", "slot_id"),
        ):
            ids = [getattr(item, attribute) for item in collection]
            if len(ids) != len(set(ids)):
                raise ValueError(f"duplicate ids in {label}")
        # One outcome link per postcondition: each postcondition may have
        # at most one observable outcome link.  Multiple observations of the
        # same postcondition would collide on requirement IDs and introduce
        # ambiguous observability semantics.
        outcome_pc_ids = [
            link.postcondition_id for link in self.observable_outcome_links
        ]
        if len(outcome_pc_ids) != len(set(outcome_pc_ids)):
            raise ValueError(
                "duplicate observable outcome links for the same postcondition"
            )
        postcondition_ids = {
            pc.postcondition_id for pc in self.observable_postconditions
        }
        for link in self.observable_outcome_links:
            if link.postcondition_id not in postcondition_ids:
                raise ValueError(
                    f"observable outcome link references absent postcondition "
                    f"{link.postcondition_id}"
                )
        # Outside steps are not system-observable: their postconditions are
        # attacker-side artifacts, not observable outcomes.  Outcome links on
        # outside steps are semantically invalid.
        if self.boundary_position == "outside" and self.observable_outcome_links:
            raise ValueError(
                f"step {self.step_id} at boundary_position 'outside' must not "
                "have observable outcome links; outside-step postconditions "
                "are not system-observable"
            )
        # Every security-relevant postcondition on a non-outside step must
        # have exactly one outcome link.  This ensures security assertions
        # are always traced to an explicit observable outcome, not inferred
        # from the security_relevant flag alone.
        if self.boundary_position != "outside":
            linked_pc_ids = {
                link.postcondition_id for link in self.observable_outcome_links
            }
            for pc in self.observable_postconditions:
                if pc.security_relevant and pc.postcondition_id not in linked_pc_ids:
                    raise ValueError(
                        f"step {self.step_id} security-relevant postcondition "
                        f"{pc.postcondition_id} lacks an observable outcome link"
                    )
        # Activation links (ingress / source_influence) on conditional steps
        # are forbidden: a conditional step may be omitted by condition
        # evaluation, and activation must be deterministic.  The canonical
        # chain model has no branch semantics, so a conditional activation
        # would admit non-deterministic candidate-v2 activation.
        if self.requirement == "conditional":
            for link in self.resource_links:
                if link.role in ("ingress", "source_influence"):
                    raise ValueError(
                        f"step {self.step_id} is conditional and must not "
                        f"carry an activation link (role={link.role}); "
                        "activation must be on a required step"
                    )
        taxonomies = [mapping.taxonomy for mapping in self.mappings]
        if len(set(taxonomies)) != len(taxonomies):
            raise ValueError("duplicate taxonomy decisions in step scope")
        if (self.executor_role == "attacker") != self.attacker_controlled:
            raise ValueError("executor role must agree with attacker control")
        if self.attacker_controlled:
            if any(isinstance(m, NotApplicableMapping) for m in self.mappings):
                raise ValueError(
                    "attacker mappings must be exact or rationalized unmapped"
                )
        elif any(not isinstance(m, NotApplicableMapping) for m in self.mappings):
            raise ValueError("non-attacker mappings must all be not_applicable")
        return self


class ResourceSlot(ContractModel):
    slot_id: Identifier
    kind: Literal[
        "entry_point",
        "tool",
        "integration",
        "trust_boundary",
        "output_surface",
        "agent_internal",
    ]
    purpose: Literal["initial_ingress", "intermediate", "target", "supporting"]
    allowed_integration_types: tuple[
        Literal[
            "api", "database", "message_queue", "file_system", "web_service", "other"
        ],
        ...,
    ] = ()
    allowed_entry_point_types: tuple[
        Literal[
            "user_input",
            "external_content",
            "configuration_load",
            "system_event",
            "inter_agent_message",
            "other",
        ],
        ...,
    ] = ()
    allowed_entry_point_directions: tuple[
        Literal["input", "output", "bidirectional"], ...
    ] = ()
    allowed_entry_point_controllability: tuple[
        Literal["direct", "indirect", "system"], ...
    ] = ()
    allowed_entry_point_ingress_zones: tuple[
        Literal["input", "reasoning", "tool_execution", "memory", "inter_agent"],
        ...,
    ] = ()
    allowed_trust_boundary_from_zones: tuple[
        Literal["input", "reasoning", "tool_execution", "memory", "inter_agent"],
        ...,
    ] = ()
    allowed_trust_boundary_to_zones: tuple[
        Literal["input", "reasoning", "tool_execution", "memory", "inter_agent"],
        ...,
    ] = ()
    allowed_resource_ids: tuple[Identifier, ...] = ()
    distinct_from_slot_ids: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def typed_constraints_match_kind(self) -> ResourceSlot:
        groups = {
            "integration": self.allowed_integration_types,
            "entry_point": (
                self.allowed_entry_point_types
                + self.allowed_entry_point_directions
                + self.allowed_entry_point_controllability
                + self.allowed_entry_point_ingress_zones
            ),
            "trust_boundary": (
                self.allowed_trust_boundary_from_zones
                + self.allowed_trust_boundary_to_zones
            ),
        }
        for constrained_kind, values in groups.items():
            if values and self.kind != constrained_kind:
                raise ValueError(
                    f"{constrained_kind} constraints require a {constrained_kind} slot"
                )
        constraint_groups = (
            self.allowed_integration_types,
            self.allowed_entry_point_types,
            self.allowed_entry_point_directions,
            self.allowed_entry_point_controllability,
            self.allowed_entry_point_ingress_zones,
            self.allowed_trust_boundary_from_zones,
            self.allowed_trust_boundary_to_zones,
            self.allowed_resource_ids,
        )
        if any(len(values) != len(set(values)) for values in constraint_groups):
            raise ValueError("each resource-slot constraint list must be unique")
        if len(self.distinct_from_slot_ids) != len(set(self.distinct_from_slot_ids)):
            raise ValueError("distinct resource-slot references must be unique")
        if self.slot_id in self.distinct_from_slot_ids:
            raise ValueError("resource slot cannot be distinct from itself")
        return self


class CanonicalAttackChain(ContractModel):
    schema_version: Literal["v1"]
    pattern_id: Identifier
    chain_id: Identifier
    semantic_revision: StrictInt = Field(gt=0)
    semantic_digest: Digest
    taxonomy_context: TaxonomyContext
    mappings: tuple[ChainMappingDecision, ...] = Field(min_length=1)
    steps: tuple[CanonicalChainStep, ...] = Field(min_length=1)
    earliest_attacker_controlled_step_id: Identifier
    resource_slots: tuple[ResourceSlot, ...] = Field(min_length=1)
    initial_ingress_slot_id: Identifier

    @model_validator(mode="after")
    def semantics(self) -> CanonicalAttackChain:
        taxonomies = [mapping.taxonomy for mapping in self.mappings]
        if len(taxonomies) != len(set(taxonomies)):
            raise ValueError("duplicate taxonomy decisions in chain scope")
        if not any(isinstance(mapping, ExactMapping) for mapping in self.mappings):
            raise ValueError("chain requires an exact ATLAS or LAAF mapping")
        if self.taxonomy_context.laaf is None and any(
            mapping.taxonomy == "LAAF"
            for scope in (self.mappings, *(step.mappings for step in self.steps))
            for mapping in scope
        ):
            raise ValueError(
                "LAAF mapping decisions require an explicit LAAF taxonomy pin"
            )
        if len({s.step_id for s in self.steps}) != len(self.steps):
            raise ValueError("step ids must be unique")
        if [s.order for s in self.steps] != list(range(1, len(self.steps) + 1)):
            raise ValueError("steps must be in total order 1..N")
        attacker = [s for s in self.steps if s.attacker_controlled]
        if not self.steps[0].attacker_controlled or (
            self.earliest_attacker_controlled_step_id != self.steps[0].step_id
        ):
            raise ValueError("earliest attacker-controlled step is incorrect")
        for step in self.steps[:-1]:
            if any(
                out.security_relevant and out.terminal
                for out in step.observable_postconditions
            ):
                raise ValueError(
                    "terminal security outcomes are only valid on the final step"
                )
        if not any(
            out.security_relevant and out.terminal
            for out in self.steps[-1].observable_postconditions
        ):
            raise ValueError(
                "final step requires an observable security-relevant terminal outcome"
            )
        if not any(
            any(isinstance(m, ExactMapping) for m in s.mappings) for s in attacker
        ):
            raise ValueError(
                "an attacker-controlled step requires an exact taxonomy mapping"
            )
        if len({slot.slot_id for slot in self.resource_slots}) != len(
            self.resource_slots
        ):
            raise ValueError("resource slot ids must be unique")
        ingress = [
            slot for slot in self.resource_slots if slot.purpose == "initial_ingress"
        ]
        if len(ingress) != 1 or ingress[0].slot_id != self.initial_ingress_slot_id:
            raise ValueError("exactly one referenced initial ingress slot is required")
        if ingress[0].kind != "entry_point":
            raise ValueError("initial ingress slot must be an entry_point")
        slot_ids = {slot.slot_id for slot in self.resource_slots}
        slots_by_id = {slot.slot_id: slot for slot in self.resource_slots}
        for slot in self.resource_slots:
            for distinct_slot_id in slot.distinct_from_slot_ids:
                distinct_slot = slots_by_id.get(distinct_slot_id)
                if distinct_slot is None:
                    raise ValueError(
                        f"resource slot {slot.slot_id} references absent distinct slot "
                        f"{distinct_slot_id}"
                    )
                if distinct_slot.kind != slot.kind:
                    raise ValueError(
                        "distinct resource-slot constraints require matching kinds"
                    )
        for step in self.steps:
            for link in step.resource_links:
                if link.slot_id not in slot_ids:
                    raise ValueError(
                        f"step {step.step_id} resource link references absent "
                        f"slot {link.slot_id}"
                    )
                slot = slots_by_id[link.slot_id]
                if link.role == "ingress":
                    if link.slot_id != self.initial_ingress_slot_id:
                        raise ValueError(
                            f"step {step.step_id} ingress link must reference "
                            "the initial ingress slot"
                        )
                    if step.boundary_position == "outside":
                        raise ValueError(
                            f"step {step.step_id} ingress link requires a "
                            "crossing or inside boundary position"
                        )
                    if slot.kind != "entry_point":
                        raise ValueError(
                            f"step {step.step_id} ingress link must reference "
                            "an entry_point slot"
                        )
                elif link.role == "tool_fixture":
                    if slot.kind != "tool":
                        raise ValueError(
                            f"step {step.step_id} tool_fixture link must "
                            "reference a tool slot"
                        )
                elif link.role == "source_influence":
                    if slot.kind not in ("entry_point", "integration"):
                        raise ValueError(
                            f"step {step.step_id} source_influence link must "
                            "reference an entry_point or integration slot"
                        )
                    if step.boundary_position == "outside":
                        raise ValueError(
                            f"step {step.step_id} source_influence link requires "
                            "a crossing or inside boundary position"
                        )
                    tb = link.trust_boundary_slot_id
                    if tb is None or tb not in slot_ids:
                        raise ValueError(
                            f"step {step.step_id} source_influence link "
                            "references an absent trust_boundary slot"
                        )
                    if slots_by_id[tb].kind != "trust_boundary":
                        raise ValueError(
                            f"step {step.step_id} source_influence link "
                            "trust_boundary_slot_id must reference a "
                            "trust_boundary slot"
                        )
                    tg = link.target_ingress_slot_id
                    if tg not in slot_ids:
                        raise ValueError(
                            f"step {step.step_id} source_influence link "
                            f"references an absent target_ingress slot {tg}"
                        )
                    if tg != self.initial_ingress_slot_id:
                        raise ValueError(
                            f"step {step.step_id} source_influence link "
                            "target_ingress_slot_id must reference the "
                            "initial ingress slot"
                        )
                    if slots_by_id[tg].kind != "entry_point":
                        raise ValueError(
                            f"step {step.step_id} source_influence link "
                            "target_ingress_slot_id must reference an "
                            "entry_point slot"
                        )
            for link in step.observable_outcome_links:
                if link.binding_slot_id not in slot_ids:
                    raise ValueError(
                        f"step {step.step_id} observable outcome link "
                        f"references absent slot {link.binding_slot_id}"
                    )
                slot = slots_by_id[link.binding_slot_id]
                expected_kind = {
                    "model_context": "entry_point",
                    "tool_invocation": "tool",
                    "persistent_state": "integration",
                    "rendered_output": "output_surface",
                    "endpoint_receipt": "integration",
                    "agent_state": "agent_internal",
                }[link.observation]
                if slot.kind != expected_kind:
                    raise ValueError(
                        f"step {step.step_id} observable outcome link "
                        f"observation {link.observation} requires a "
                        f"{expected_kind} slot, got {slot.kind}"
                    )
        ingress_links = [
            (step.step_id, link)
            for step in self.steps
            for link in step.resource_links
            if link.role == "ingress" and link.slot_id == self.initial_ingress_slot_id
        ]
        source_influence_links = [
            (step.step_id, link)
            for step in self.steps
            for link in step.resource_links
            if link.role == "source_influence"
            and link.target_ingress_slot_id == self.initial_ingress_slot_id
        ]
        if len(ingress_links) > 1:
            step_ids = ", ".join(sid for sid, _ in ingress_links)
            raise ValueError(
                f"chain has {len(ingress_links)} direct-ingress activation "
                f"links (steps: {step_ids}); at most one chain-wide "
                "activation link is permitted"
            )
        if len(source_influence_links) > 1:
            step_ids = ", ".join(sid for sid, _ in source_influence_links)
            raise ValueError(
                f"chain has {len(source_influence_links)} source-influence "
                f"activation links (steps: {step_ids}); at most one "
                "chain-wide activation link is permitted"
            )
        if ingress_links and source_influence_links:
            raise ValueError(
                "chain has both a direct ingress link and a source_influence "
                "link to the initial ingress; exactly one activation mechanism "
                "is permitted"
            )
        # Absence of both activation mechanisms is not a model validation
        # error: a chain may be structurally valid but not activatable for
        # candidate-v2 (e.g. prerequisite-based activation).  The projection
        # fails closed for such chains.
        if self.semantic_digest != compute_chain_semantic_digest(self):
            raise ValueError("semantic_digest does not match chain semantics")
        return self


class AttackPattern(ContractModel):
    """Structurally parsed pattern; taxonomy qualification is intentionally separate."""

    id: str
    threat_id: str
    name: str
    description: str
    nist_classification: NistClassification | None = None
    prerequisite_capabilities: PrerequisiteCapabilities
    canonical_chain: CanonicalAttackChain

    @model_validator(mode="after")
    def bind_chain(self) -> AttackPattern:
        if self.canonical_chain.pattern_id != self.id:
            raise ValueError("canonical chain pattern_id must match pattern id")
        return self


class EntryPointResourceReference(ContractModel):
    kind: Literal["entry_point"]
    entry_point_id: str = Field(pattern=r"^ep:v1:[0-9a-f]{32}$")


class ToolResourceReference(ContractModel):
    kind: Literal["tool"]
    tool_id: str = Field(pattern=r"^tool:v1:[0-9a-f]{32}$")


class IntegrationResourceReference(ContractModel):
    kind: Literal["integration"]
    integration_id: str = Field(pattern=r"^int:v1:[0-9a-f]{32}$")


class TrustBoundaryResourceReference(ContractModel):
    kind: Literal["trust_boundary"]
    trust_boundary_id: str = Field(pattern=r"^tb:v1:[0-9a-f]{32}$")


class OutputSurfaceResourceReference(ContractModel):
    """Canonical reference to an output-direction entry point.

    An output surface is the agent's rendered-response surface — the
    model's output that a client renders or fetches.  It is distinct from
    an input entry point (``EntryPointResourceReference``) even though
    both resolve to an :class:`EntryPoint` in the capability profile:
    only entry points with ``direction == "output"`` qualify as output
    surfaces.
    """

    kind: Literal["output_surface"]
    entry_point_id: str = Field(pattern=r"^ep:v1:[0-9a-f]{32}$")


class AgentInternalResourceReference(ContractModel):
    """Canonical reference to agent-internal state.

    Agent-internal state is data assembled or transformed within the
    agent's own working context — neither an external entry point, tool,
    integration, nor trust boundary.  It is the intrinsic singleton working
    state of the profiled agent, so it requires no adapter inventory identity.
    Candidate-v2 resolves exactly this typed singleton rather than laundering
    it through an unrelated tool or integration binding.
    """

    kind: Literal["agent_internal"]


CanonicalResourceReference: TypeAlias = Annotated[
    EntryPointResourceReference
    | ToolResourceReference
    | IntegrationResourceReference
    | TrustBoundaryResourceReference
    | OutputSurfaceResourceReference
    | AgentInternalResourceReference,
    Field(discriminator="kind"),
]


class ResourceBinding(ContractModel):
    slot_id: Identifier
    resource_ref: CanonicalResourceReference


class StepOmission(ContractModel):
    step_id: Identifier
    reason: Literal["condition_false"]


class ProjectionSnapshot(ContractModel):
    """Local structural/pure semantic parse; use qualification for external facts."""

    schema_version: Literal["1"]
    source_chain: CanonicalAttackChain
    selected_step_ids: tuple[Identifier, ...] = Field(min_length=1)
    condition_results: tuple[ConditionEvaluationResult, ...]
    omissions: tuple[StepOmission, ...]
    bindings: tuple[ResourceBinding, ...]
    catalog_pin: Digest
    pattern_pin: Digest
    capability_fact_snapshot_digest: Digest
    projection_digest: Digest
    source_influence_paths: tuple[SourceInfluencePath, ...] = ()

    @model_validator(mode="after")
    def semantics(self) -> ProjectionSnapshot:
        source_ids = [s.step_id for s in self.source_chain.steps]
        selected = list(self.selected_step_ids)
        omitted = [o.step_id for o in self.omissions]
        if len(set(selected)) != len(selected) or len(set(omitted)) != len(omitted):
            raise ValueError("selected and omitted step ids must be unique")
        if set(selected) & set(omitted) or set(selected) | set(omitted) != set(
            source_ids
        ):
            raise ValueError(
                "selected and omitted steps must exactly partition source steps"
            )
        if selected != [step_id for step_id in source_ids if step_id in set(selected)]:
            raise ValueError("selected steps must retain source chain order")
        if len({r.condition_step_id for r in self.condition_results}) != len(
            self.condition_results
        ):
            raise ValueError("condition result step ids must be unique")
        if len({b.slot_id for b in self.bindings}) != len(self.bindings):
            raise ValueError("slot bindings must be unique")
        slots = {slot.slot_id: slot for slot in self.source_chain.resource_slots}
        if set(slots) != {binding.slot_id for binding in self.bindings}:
            raise ValueError("bindings must exactly cover all source resource slots")
        for binding in self.bindings:
            slot = slots.get(binding.slot_id)
            if slot is None:
                raise ValueError("binding references an absent resource slot")
            if binding.resource_ref.kind != slot.kind:
                raise ValueError("binding resource kind must match its slot")
        bindings_by_slot = {
            binding.slot_id: binding.resource_ref for binding in self.bindings
        }
        for slot in slots.values():
            for distinct_slot_id in slot.distinct_from_slot_ids:
                if bindings_by_slot[slot.slot_id] == bindings_by_slot[distinct_slot_id]:
                    raise ValueError(
                        f"bindings for slots {slot.slot_id} and {distinct_slot_id} "
                        "must have distinct identities"
                    )
        ingress = [
            b
            for b in self.bindings
            if b.slot_id == self.source_chain.initial_ingress_slot_id
        ]
        if len(ingress) != 1 or not isinstance(
            ingress[0].resource_ref, EntryPointResourceReference
        ):
            raise ValueError(
                "ingress binding must be an entry-point canonical reference"
            )
        results = {r.condition_step_id: r.result for r in self.condition_results}
        conditional_ids = {
            s.step_id for s in self.source_chain.steps if s.requirement == "conditional"
        }
        if set(results) != conditional_ids:
            raise ValueError(
                "condition results must exactly cover conditional source steps"
            )
        if any(result == "unknown" for result in results.values()):
            raise ValueError("projection condition results cannot be unknown")
        conditional_steps = {
            step.step_id: step
            for step in self.source_chain.steps
            if step.requirement == "conditional"
        }
        for result in self.condition_results:
            condition = conditional_steps[result.condition_step_id].condition
            if condition is None:  # pragma: no cover - guaranteed by step validation
                raise ValueError("conditional source step requires a condition")
            evaluated = evaluate_condition(condition, result.evidence)
            if evaluated != result.result:
                raise ValueError("recorded condition result does not match evidence")
        expected_selected = [
            s.step_id
            for s in self.source_chain.steps
            if s.requirement == "required" or results[s.step_id] == "true"
        ]
        if selected != expected_selected:
            raise ValueError(
                "selected steps do not match source requirements and results"
            )
        expected_omitted = {
            step_id for step_id, result in results.items() if result == "false"
        }
        if set(omitted) != expected_omitted:
            raise ValueError("omissions must exactly identify false conditional steps")
        if self.source_chain.steps[-1].step_id not in selected:
            raise ValueError("source terminal final step must be selected")
        if self.projection_digest != compute_projection_digest(self):
            raise ValueError("projection_digest does not match projection semantics")
        return self


_UNORDERED_FIELDS = {
    "allowed_entry_point_controllability",
    "allowed_entry_point_directions",
    "allowed_entry_point_ingress_zones",
    "allowed_entry_point_types",
    "allowed_integration_types",
    "allowed_resource_ids",
    "allowed_trust_boundary_from_zones",
    "allowed_trust_boundary_to_zones",
    "consumed",
    "produced",
    "preconditions",
    "observable_postconditions",
    "references",
    "mappings",
    "ids",
    "resource_slots",
    "values",
    "evidence",
    "condition_results",
    "distinct_from_slot_ids",
    "omissions",
    "bindings",
    "requirements",
    "contributing_step_ids",
    "operands",
    "min_zones",
    "resource_links",
    "observable_outcome_links",
}


def _normalize(value: Any, field_name: str | None = None) -> Any:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="python")
    if isinstance(value, dict):
        return {
            unicodedata.normalize("NFC", str(k)): _normalize(v, str(k))
            for k, v in value.items()
        }
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (tuple, list)):
        items = [_normalize(item) for item in value]
        if field_name in _UNORDERED_FIELDS:
            items.sort(key=lambda item: _canonical_json(item).encode())
        return items
    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _semantic_digest(value: Any, digest_field: str, domain: str) -> str:
    payload = (
        value.model_dump(mode="python") if isinstance(value, BaseModel) else dict(value)
    )
    payload.pop(digest_field, None)
    encoded = domain.encode() + b"\0" + _canonical_json(payload).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def compute_chain_semantic_digest(chain: CanonicalAttackChain | dict[str, Any]) -> str:
    payload = (
        chain.model_dump(mode="python") if isinstance(chain, BaseModel) else dict(chain)
    )
    # Canonicalize the optional LAAF axis: an omitted ``laaf`` key in
    # ``taxonomy_context`` frames exactly like the explicit ``None`` that
    # model validation materializes, so a caller may sign a raw dict that
    # omits the key and still pass validation.  Never mutates ``chain``.
    context = payload.get("taxonomy_context")
    if isinstance(context, dict) and "laaf" not in context:
        payload["taxonomy_context"] = {**context, "laaf": None}
    # Empty resource constraints are unconstrained and were absent from
    # chains signed before these generic constraints existed. Keep omitted
    # and explicitly empty constraints byte-equivalent while signing every
    # non-empty constraint.
    resource_slots = payload.get("resource_slots")
    if isinstance(resource_slots, (list, tuple)):
        constraint_fields = (
            "allowed_integration_types",
            "allowed_entry_point_types",
            "allowed_entry_point_directions",
            "allowed_entry_point_controllability",
            "allowed_entry_point_ingress_zones",
            "allowed_trust_boundary_from_zones",
            "allowed_trust_boundary_to_zones",
            "allowed_resource_ids",
            "distinct_from_slot_ids",
        )
        payload["resource_slots"] = [
            {
                key: value
                for key, value in slot.items()
                if key not in constraint_fields or value
            }
            if isinstance(slot, dict)
            else slot
            for slot in resource_slots
        ]
    # Canonicalize optional linkage fields: a raw dict may omit
    # ``trust_boundary_slot_id`` / ``target_ingress_slot_id`` on a
    # resource link where model validation materializes ``None``, and may
    # omit ``resource_links`` / ``observable_outcome_links`` arrays where
    # model validation materializes empty tuples.  Frame omitted and
    # explicit-None/[] identically so callers can sign raw dicts that omit
    # the defaults.  Never mutates ``chain``.
    steps = payload.get("steps")
    if isinstance(steps, (list, tuple)):
        normalized_steps = []
        for step in steps:
            if not isinstance(step, dict):
                normalized_steps.append(step)
                continue
            # Ensure both link arrays are present; omitted → [].
            step = {
                **step,
                "resource_links": step.get("resource_links", []),
                "observable_outcome_links": step.get("observable_outcome_links", []),
            }
            # Canonicalize optional None fields within resource links.
            links = step["resource_links"]
            if isinstance(links, (list, tuple)):
                step = {
                    **step,
                    "resource_links": [
                        {
                            **{
                                key: value
                                for key, value in link.items()
                                if key != "source_identity_kind" or value is not None
                            },
                            "trust_boundary_slot_id": link.get(
                                "trust_boundary_slot_id"
                            ),
                            "target_ingress_slot_id": link.get(
                                "target_ingress_slot_id"
                            ),
                            **(
                                {"source_identity_kind": link["source_identity_kind"]}
                                if link.get("source_identity_kind") is not None
                                else {}
                            ),
                        }
                        if isinstance(link, dict)
                        else link
                        for link in links
                    ],
                }
            normalized_steps.append(step)
        payload["steps"] = normalized_steps
    return _semantic_digest(
        payload, "semantic_digest", "asago-scenario-generator:canonical-chain:v1"
    )


def compute_projection_digest(snapshot: ProjectionSnapshot | dict[str, Any]) -> str:
    payload = (
        snapshot.model_dump(mode="python")
        if isinstance(snapshot, BaseModel)
        else dict(snapshot)
    )
    source_chain = payload.get("source_chain")
    if isinstance(source_chain, dict):
        resource_slots = source_chain.get("resource_slots")
        if isinstance(resource_slots, (list, tuple)):
            constraint_fields = {
                "allowed_integration_types",
                "allowed_entry_point_types",
                "allowed_entry_point_directions",
                "allowed_entry_point_controllability",
                "allowed_entry_point_ingress_zones",
                "allowed_trust_boundary_from_zones",
                "allowed_trust_boundary_to_zones",
                "allowed_resource_ids",
                "distinct_from_slot_ids",
            }
            payload["source_chain"] = {
                **source_chain,
                "resource_slots": [
                    {
                        key: value
                        for key, value in slot.items()
                        if key not in constraint_fields or value
                    }
                    if isinstance(slot, dict)
                    else slot
                    for slot in resource_slots
                ],
            }
        steps = source_chain.get("steps")
        if isinstance(steps, (list, tuple)):
            payload["source_chain"] = {
                **payload["source_chain"],
                "steps": [
                    {
                        **step,
                        "resource_links": [
                            {
                                key: value
                                for key, value in link.items()
                                if key != "source_identity_kind" or value is not None
                            }
                            if isinstance(link, dict)
                            else link
                            for link in step.get("resource_links", ())
                        ],
                    }
                    if isinstance(step, dict)
                    else step
                    for step in steps
                ],
            }
    # Empty relation paths are the backwards-compatible direct-ingress
    # default.  Keep their digest equivalent to pre-relation snapshots while
    # binding a non-empty authoritative path into the new digest.
    if payload.get("source_influence_paths") == ():
        payload.pop("source_influence_paths", None)
    elif payload.get("source_influence_paths") == []:
        payload.pop("source_influence_paths", None)
    return _semantic_digest(
        payload, "projection_digest", "asago-scenario-generator:projection:v1"
    )


def validate_legacy_attack_pattern(
    pattern_dict: dict[str, Any],
) -> LegacyAttackPatternRecord:
    return LegacyAttackPatternRecord.model_validate(pattern_dict)


def validate_attack_pattern(
    pattern_dict: dict[str, Any], resolver: TaxonomyResolver
) -> AttackPattern:
    """Parse and qualify a pattern; ``AttackPattern.model_validate`` only parses."""
    pattern = AttackPattern.model_validate(pattern_dict)
    if resolver.taxonomy_context != pattern.canonical_chain.taxonomy_context:
        raise ValueError("taxonomy resolver pins do not match canonical chain pins")
    mapping_scopes = [
        pattern.canonical_chain.mappings,
        *(s.mappings for s in pattern.canonical_chain.steps),
    ]
    for mappings in mapping_scopes:
        for mapping in mappings:
            if isinstance(mapping, ExactMapping):
                for identifier in mapping.ids:
                    if not resolver.contains(mapping.taxonomy, identifier):
                        raise ValueError(f"unknown {mapping.taxonomy} id: {identifier}")
    return pattern


def validate_projection_snapshot(
    snapshot_dict: dict[str, Any], resolver: CapabilitySnapshotResolver
) -> ProjectionSnapshot:
    """Parse and externally qualify a projection against a mandatory pinned resolver."""
    snapshot = ProjectionSnapshot.model_validate(snapshot_dict)
    if (
        resolver.capability_fact_snapshot_digest
        != snapshot.capability_fact_snapshot_digest
    ):
        raise ValueError("capability snapshot resolver digest pin does not match")
    for result in snapshot.condition_results:
        for supplied in result.evidence:
            authoritative = resolver.fact(supplied.fact)
            if authoritative is None:
                raise ValueError("authoritative condition fact is missing")
            if authoritative != supplied:
                raise ValueError(
                    "condition fact evidence does not match resolver reading"
                )
    for binding in snapshot.bindings:
        if not resolver.contains_resource(binding.resource_ref):
            raise ValueError(f"missing {binding.resource_ref.kind} resource")
        slot = next(
            item
            for item in snapshot.source_chain.resource_slots
            if item.slot_id == binding.slot_id
        )
        if not resolver.resource_matches_slot(binding.resource_ref, slot):
            raise ValueError(
                f"{binding.resource_ref.kind} resource is incompatible with slot "
                f"{binding.slot_id}"
            )
    return snapshot


AllCondition.model_rebuild()
AnyCondition.model_rebuild()
NotCondition.model_rebuild()
