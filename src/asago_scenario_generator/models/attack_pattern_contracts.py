"""Foundational models for the authoritative attack-pattern contract."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Literal, Protocol, TypeAlias

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from .attack_pattern_digests import _canonical_json

if TYPE_CHECKING:
    from .attack_pattern_chain import ResourceSlot
    from .attack_pattern_projection import CanonicalResourceReference

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


def validate_fact_scalar(fact: AuthoritativeFactReference, value: Scalar) -> None:
    """Require a scalar value to match its authoritative fact's type."""
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
        validate_fact_scalar(self.fact, self.value)
        return self


def _membership_values_unique(values: tuple[Scalar, ...]) -> bool:
    """True when canonical membership values are pairwise distinct."""
    return len({_canonical_json(v) for v in values}) == len(values)


def _validate_membership_values(
    fact: AuthoritativeFactReference, values: tuple[Scalar, ...]
) -> None:
    """Membership values must match the fact type and be unique."""
    for value in values:
        validate_fact_scalar(fact, value)
    if not _membership_values_unique(values):
        raise ValueError("membership values must be unique")


class MembershipCondition(ContractModel):
    op: Literal["membership"]
    schema_version: Literal["1"]
    fact: AuthoritativeFactReference
    values: tuple[Scalar, ...] = Field(min_length=1, max_length=MAX_MEMBERSHIP_VALUES)

    @model_validator(mode="after")
    def unique_values(self) -> MembershipCondition:
        _validate_membership_values(self.fact, self.values)
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
        validate_fact_scalar(self.fact, self.value)
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


def _condition_children(node: Condition) -> tuple[Condition, ...]:
    """Immediate child conditions of a composite condition node."""
    if isinstance(node, NotCondition):
        return (node.operand,)
    if isinstance(node, (AllCondition, AnyCondition)):
        return node.operands
    return ()


def _check_duplicate_operands(children: tuple[Condition, ...]) -> None:
    """Composite children must be pairwise distinct."""
    if children and len(
        {_canonical_json(c.model_dump(mode="json")) for c in children}
    ) != len(children):
        raise ValueError("duplicate condition operands")


def _walk_condition(node: Condition, depth: int, counter: list[int]) -> None:
    """Depth-first structural limit and duplicate check over the AST."""
    counter[0] += 1
    if depth > MAX_CONDITION_DEPTH or counter[0] > MAX_CONDITION_NODES:
        raise ValueError("condition exceeds structural limits")
    children = _condition_children(node)
    _check_duplicate_operands(children)
    for child in children:
        _walk_condition(child, depth + 1, counter)


def _check_condition(condition: Condition) -> None:
    _walk_condition(condition, 1, [0])


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
            validate_fact_scalar(self.fact, self.value)
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
            _check_source_influence_fields(self)
        else:
            _check_non_influence_fields(self)
        return self


def _check_source_influence_fields(link: StepResourceLink) -> None:
    """Source-influence links require both boundary and target ingress."""
    if link.trust_boundary_slot_id is None:
        raise ValueError(
            "source_influence resource link requires a trust_boundary_slot_id"
        )
    if link.target_ingress_slot_id is None:
        raise ValueError(
            "source_influence resource link requires a target_ingress_slot_id"
        )


def _check_non_influence_fields(link: StepResourceLink) -> None:
    """Non-source-influence links forbid all source-influence-only fields."""
    if link.trust_boundary_slot_id is not None:
        raise ValueError(
            "trust_boundary_slot_id is only valid for source_influence links"
        )
    if link.target_ingress_slot_id is not None:
        raise ValueError(
            "target_ingress_slot_id is only valid for source_influence links"
        )
    if link.source_identity_kind is not None:
        raise ValueError(
            "source_identity_kind is only valid for source_influence links"
        )


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


def _all_verdict(
    results: tuple[Literal["true", "false", "unknown"], ...],
) -> Literal["true", "false", "unknown"]:
    """Kleene conjunction: false dominates, then unknown."""
    if "false" in results:
        return "false"
    if "unknown" in results:
        return "unknown"
    return "true"


def _any_verdict(
    results: tuple[Literal["true", "false", "unknown"], ...],
) -> Literal["true", "false", "unknown"]:
    """Kleene disjunction: true dominates, then unknown."""
    if "true" in results:
        return "true"
    if "unknown" in results:
        return "unknown"
    return "false"


def _not_verdict(
    result: Literal["true", "false", "unknown"],
) -> Literal["true", "false", "unknown"]:
    """Kleene negation."""
    return {"true": "false", "false": "true", "unknown": "unknown"}[result]


def _present_verdict(
    node: Condition, item: EvaluatedFactEvidence
) -> Literal["true", "false"]:
    """Verdict for a present fact against its leaf condition."""
    if isinstance(node, MembershipCondition):
        matches = item.value in node.values
    else:
        matches = item.value == node.value
    return "true" if matches else "false"


def _leaf_verdict(
    node: Condition, item: EvaluatedFactEvidence
) -> Literal["true", "false", "unknown"]:
    """Verdict for a leaf condition against its fact evidence."""
    if item.status == "unknown":
        return "unknown"
    if isinstance(node, ExistenceCondition):
        present = item.status == "present"
        return "true" if present == node.exists else "false"
    if item.status == "absent":
        return "false"
    return _present_verdict(node, item)


def _evaluate_node(
    node: Condition,
    keyed: dict[str, EvaluatedFactEvidence],
) -> Literal["true", "false", "unknown"]:
    """Evaluate one condition AST node against complete fact evidence."""
    if isinstance(node, AllCondition):
        return _all_verdict(
            tuple(_evaluate_node(item, keyed) for item in node.operands)
        )
    if isinstance(node, AnyCondition):
        return _any_verdict(
            tuple(_evaluate_node(item, keyed) for item in node.operands)
        )
    if isinstance(node, NotCondition):
        return _not_verdict(_evaluate_node(node.operand, keyed))
    return _leaf_verdict(
        node, keyed[_canonical_json(node.fact.model_dump(mode="json"))]
    )


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
    return _evaluate_node(condition, keyed)


AllCondition.model_rebuild()
AnyCondition.model_rebuild()
NotCondition.model_rebuild()
