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


def _membership_values_unique(values: tuple[Scalar, ...]) -> bool:
    """True when canonical membership values are pairwise distinct."""
    return len({_canonical_json(v) for v in values}) == len(values)


def _validate_membership_values(
    fact: AuthoritativeFactReference, values: tuple[Scalar, ...]
) -> None:
    """Membership values must match the fact type and be unique."""
    for value in values:
        _validate_fact_scalar(fact, value)
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
        _check_step_condition_agreement(self)
        _check_step_collections_unique(self)
        _check_outcome_link_duplicates(self)
        _check_outcome_link_targets(self)
        _check_outside_step_outcome_links(self)
        _check_security_outcome_links(self)
        _check_conditional_activation_links(self)
        _check_step_taxonomy_scope(self)
        _check_step_executor_agreement(self)
        _check_attacker_mappings(self)
        _check_system_mappings(self)
        return self


def _check_step_condition_agreement(step: CanonicalChainStep) -> None:
    """Conditional steps require a condition; required steps forbid it."""
    if (step.requirement == "conditional") != (step.condition is not None):
        raise ValueError(
            "conditional steps require a condition; required steps forbid it"
        )
    if step.condition is not None:
        _check_condition(step.condition)


def _check_step_collections_unique(step: CanonicalChainStep) -> None:
    """Each step collection is duplicate-free on its identity attribute."""
    for collection, label, attribute in (
        (step.consumed, "consumed references", "ref_id"),
        (step.produced, "produced references", "ref_id"),
        (step.preconditions, "preconditions", "condition_id"),
        (
            step.observable_postconditions,
            "observable postconditions",
            "postcondition_id",
        ),
        (step.resource_links, "resource links", "slot_id"),
    ):
        ids = [getattr(item, attribute) for item in collection]
        if len(ids) != len(set(ids)):
            raise ValueError(f"duplicate ids in {label}")


def _check_outcome_link_duplicates(step: CanonicalChainStep) -> None:
    """One outcome link per postcondition: requirement IDs must not collide."""
    outcome_pc_ids = [link.postcondition_id for link in step.observable_outcome_links]
    if len(outcome_pc_ids) != len(set(outcome_pc_ids)):
        raise ValueError(
            "duplicate observable outcome links for the same postcondition"
        )


def _check_outcome_link_targets(step: CanonicalChainStep) -> None:
    """Outcome links reference declared postconditions only."""
    postcondition_ids = {pc.postcondition_id for pc in step.observable_postconditions}
    for link in step.observable_outcome_links:
        if link.postcondition_id not in postcondition_ids:
            raise ValueError(
                f"observable outcome link references absent postcondition "
                f"{link.postcondition_id}"
            )


def _check_outside_step_outcome_links(step: CanonicalChainStep) -> None:
    """Outside steps are not system-observable: no outcome links allowed."""
    if step.boundary_position == "outside" and step.observable_outcome_links:
        raise ValueError(
            f"step {step.step_id} at boundary_position 'outside' must not "
            "have observable outcome links; outside-step postconditions "
            "are not system-observable"
        )


def _check_security_outcome_links(step: CanonicalChainStep) -> None:
    """Every security-relevant postcondition has exactly one outcome link."""
    if step.boundary_position != "outside":
        linked_pc_ids = {
            link.postcondition_id for link in step.observable_outcome_links
        }
        for pc in step.observable_postconditions:
            if pc.security_relevant and pc.postcondition_id not in linked_pc_ids:
                raise ValueError(
                    f"step {step.step_id} security-relevant postcondition "
                    f"{pc.postcondition_id} lacks an observable outcome link"
                )


def _check_conditional_activation_links(step: CanonicalChainStep) -> None:
    """Conditional steps must not carry deterministic activation links."""
    if step.requirement == "conditional":
        for link in step.resource_links:
            if link.role in ("ingress", "source_influence"):
                raise ValueError(
                    f"step {step.step_id} is conditional and must not "
                    f"carry an activation link (role={link.role}); "
                    "activation must be on a required step"
                )


def _check_step_taxonomy_scope(step: CanonicalChainStep) -> None:
    """Step mapping decisions cover distinct taxonomies."""
    taxonomies = [mapping.taxonomy for mapping in step.mappings]
    if len(set(taxonomies)) != len(taxonomies):
        raise ValueError("duplicate taxonomy decisions in step scope")


def _check_step_executor_agreement(step: CanonicalChainStep) -> None:
    """Executor role must agree with attacker control."""
    if (step.executor_role == "attacker") != step.attacker_controlled:
        raise ValueError("executor role must agree with attacker control")


def _check_attacker_mappings(step: CanonicalChainStep) -> None:
    """Attacker mappings must be exact or rationalized unmapped."""
    if step.attacker_controlled:
        if any(isinstance(m, NotApplicableMapping) for m in step.mappings):
            raise ValueError("attacker mappings must be exact or rationalized unmapped")


def _check_system_mappings(step: CanonicalChainStep) -> None:
    """Non-attacker mappings must all be not_applicable."""
    if not step.attacker_controlled:
        if any(not isinstance(m, NotApplicableMapping) for m in step.mappings):
            raise ValueError("non-attacker mappings must all be not_applicable")


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
        _check_slot_constraint_kinds(self)
        _check_slot_constraint_lists_unique(self)
        _check_slot_distinct_refs(self)
        return self


def _check_slot_constraint_kinds(slot: ResourceSlot) -> None:
    """Typed constraint families require a matching slot kind."""
    groups = {
        "integration": slot.allowed_integration_types,
        "entry_point": (
            slot.allowed_entry_point_types
            + slot.allowed_entry_point_directions
            + slot.allowed_entry_point_controllability
            + slot.allowed_entry_point_ingress_zones
        ),
        "trust_boundary": (
            slot.allowed_trust_boundary_from_zones
            + slot.allowed_trust_boundary_to_zones
        ),
    }
    for constrained_kind, values in groups.items():
        if values and slot.kind != constrained_kind:
            raise ValueError(
                f"{constrained_kind} constraints require a {constrained_kind} slot"
            )


def _check_slot_constraint_lists_unique(slot: ResourceSlot) -> None:
    """Each constraint list must be duplicate-free."""
    constraint_groups = (
        slot.allowed_integration_types,
        slot.allowed_entry_point_types,
        slot.allowed_entry_point_directions,
        slot.allowed_entry_point_controllability,
        slot.allowed_entry_point_ingress_zones,
        slot.allowed_trust_boundary_from_zones,
        slot.allowed_trust_boundary_to_zones,
        slot.allowed_resource_ids,
    )
    if any(len(values) != len(set(values)) for values in constraint_groups):
        raise ValueError("each resource-slot constraint list must be unique")


def _check_slot_distinct_refs(slot: ResourceSlot) -> None:
    """Distinct references must be unique and never self-referential."""
    if len(slot.distinct_from_slot_ids) != len(set(slot.distinct_from_slot_ids)):
        raise ValueError("distinct resource-slot references must be unique")
    if slot.slot_id in slot.distinct_from_slot_ids:
        raise ValueError("resource slot cannot be distinct from itself")


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
        _check_chain_taxonomy_scope(self)
        _check_step_ids_and_order(self)
        _check_earliest_attacker_step(self)
        _check_nonfinal_terminal_outcomes(self)
        _check_final_terminal_outcome(self)
        _check_attacker_exact_mapping(self)
        _check_slot_ids_unique(self)
        _check_initial_ingress_slot(self)
        _check_distinct_slot_references(self)
        _check_step_resource_links(self)
        _check_observable_outcome_links(self)
        _check_activation_mechanisms(self)
        _check_chain_digest(self)
        return self


def _chain_taxonomies(chain: CanonicalAttackChain) -> list[str]:
    """Taxonomies declared at chain scope."""
    return [mapping.taxonomy for mapping in chain.mappings]


def _chain_has_exact_mapping(chain: CanonicalAttackChain) -> bool:
    """True when a chain-scope mapping is exact."""
    return any(isinstance(mapping, ExactMapping) for mapping in chain.mappings)


def _chain_all_mappings(
    chain: CanonicalAttackChain,
) -> list[MappingDecision | ChainMappingDecision]:
    """Every mapping decision at chain and step scope."""
    return [
        mapping
        for scope in (chain.mappings, *(step.mappings for step in chain.steps))
        for mapping in scope
    ]


def _check_chain_laaf_pin(chain: CanonicalAttackChain) -> None:
    """LAAF decisions require an explicit LAAF taxonomy pin."""
    if chain.taxonomy_context.laaf is None:
        if any(mapping.taxonomy == "LAAF" for mapping in _chain_all_mappings(chain)):
            raise ValueError(
                "LAAF mapping decisions require an explicit LAAF taxonomy pin"
            )


def _check_chain_taxonomy_scope(chain: CanonicalAttackChain) -> None:
    """Chain mapping scope: unique taxonomies, an exact mapping, LAAF pin."""
    taxonomies = _chain_taxonomies(chain)
    if len(taxonomies) != len(set(taxonomies)):
        raise ValueError("duplicate taxonomy decisions in chain scope")
    if not _chain_has_exact_mapping(chain):
        raise ValueError("chain requires an exact ATLAS or LAAF mapping")
    _check_chain_laaf_pin(chain)


def _check_step_ids_and_order(chain: CanonicalAttackChain) -> None:
    """Step ids are unique and ordered 1..N."""
    if len({s.step_id for s in chain.steps}) != len(chain.steps):
        raise ValueError("step ids must be unique")
    if [s.order for s in chain.steps] != list(range(1, len(chain.steps) + 1)):
        raise ValueError("steps must be in total order 1..N")


def _check_earliest_attacker_step(chain: CanonicalAttackChain) -> None:
    """The first step is attacker-controlled and is the earliest one."""
    if not chain.steps[0].attacker_controlled or (
        chain.earliest_attacker_controlled_step_id != chain.steps[0].step_id
    ):
        raise ValueError("earliest attacker-controlled step is incorrect")


def _check_nonfinal_terminal_outcomes(chain: CanonicalAttackChain) -> None:
    """Terminal security outcomes are only valid on the final step."""
    for step in chain.steps[:-1]:
        if any(
            out.security_relevant and out.terminal
            for out in step.observable_postconditions
        ):
            raise ValueError(
                "terminal security outcomes are only valid on the final step"
            )


def _check_final_terminal_outcome(chain: CanonicalAttackChain) -> None:
    """The final step requires a security-relevant terminal outcome."""
    if not any(
        out.security_relevant and out.terminal
        for out in chain.steps[-1].observable_postconditions
    ):
        raise ValueError(
            "final step requires an observable security-relevant terminal outcome"
        )


def _attacker_steps(chain: CanonicalAttackChain) -> list[CanonicalChainStep]:
    """The attacker-controlled steps of a chain."""
    return [s for s in chain.steps if s.attacker_controlled]


def _step_has_exact_mapping(step: CanonicalChainStep) -> bool:
    """True when a step carries an exact taxonomy mapping."""
    return any(isinstance(m, ExactMapping) for m in step.mappings)


def _check_attacker_exact_mapping(chain: CanonicalAttackChain) -> None:
    """An attacker-controlled step requires an exact taxonomy mapping."""
    attacker = _attacker_steps(chain)
    if not any(_step_has_exact_mapping(s) for s in attacker):
        raise ValueError(
            "an attacker-controlled step requires an exact taxonomy mapping"
        )


def _check_slot_ids_unique(chain: CanonicalAttackChain) -> None:
    """Resource slot ids must be unique."""
    if len({slot.slot_id for slot in chain.resource_slots}) != len(
        chain.resource_slots
    ):
        raise ValueError("resource slot ids must be unique")


def _initial_ingress_slots(chain: CanonicalAttackChain) -> list[ResourceSlot]:
    """Slots declared with the initial-ingress purpose."""
    return [slot for slot in chain.resource_slots if slot.purpose == "initial_ingress"]


def _check_initial_ingress_slot(chain: CanonicalAttackChain) -> None:
    """Exactly one initial-ingress slot, matching the declared id."""
    ingress = _initial_ingress_slots(chain)
    if len(ingress) != 1 or ingress[0].slot_id != chain.initial_ingress_slot_id:
        raise ValueError("exactly one referenced initial ingress slot is required")
    if ingress[0].kind != "entry_point":
        raise ValueError("initial ingress slot must be an entry_point")


def _slots_by_id(chain: CanonicalAttackChain) -> dict[str, ResourceSlot]:
    """Resource slots indexed by slot id."""
    return {slot.slot_id: slot for slot in chain.resource_slots}


def _slot_ids(chain: CanonicalAttackChain) -> set[str]:
    """The declared resource slot ids."""
    return {slot.slot_id for slot in chain.resource_slots}


def _check_distinct_slot_references(chain: CanonicalAttackChain) -> None:
    """Distinct slot references exist and share the referencing kind."""
    slots_by_id = _slots_by_id(chain)
    for slot in chain.resource_slots:
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


def _check_step_resource_links(chain: CanonicalAttackChain) -> None:
    """Every step resource link resolves and matches its role contract."""
    slot_ids = _slot_ids(chain)
    slots_by_id = _slots_by_id(chain)
    for step in chain.steps:
        for link in step.resource_links:
            slot = _link_slot_or_raise(step, link, slot_ids, slots_by_id)
            _check_link_role(chain, step, link, slot, slots_by_id, slot_ids)


def _link_slot_or_raise(
    step: CanonicalChainStep,
    link: StepResourceLink,
    slot_ids: set[str],
    slots_by_id: dict[str, ResourceSlot],
) -> ResourceSlot:
    """The declared slot for a resource link, or a dangling-link error."""
    if link.slot_id not in slot_ids:
        raise ValueError(
            f"step {step.step_id} resource link references absent slot {link.slot_id}"
        )
    return slots_by_id[link.slot_id]


def _check_link_role(
    chain: CanonicalAttackChain,
    step: CanonicalChainStep,
    link: StepResourceLink,
    slot: ResourceSlot,
    slots_by_id: dict[str, ResourceSlot],
    slot_ids: set[str],
) -> None:
    """Dispatch a resource link to its role-specific contract."""
    if link.role == "ingress":
        _check_ingress_link(chain, step, link, slot)
    elif link.role == "tool_fixture":
        _check_tool_fixture_link(step, link, slot)
    elif link.role == "source_influence":
        _check_source_influence_link(chain, step, link, slots_by_id, slot_ids)


def _check_ingress_link(
    chain: CanonicalAttackChain,
    step: CanonicalChainStep,
    link: StepResourceLink,
    slot: ResourceSlot,
) -> None:
    """Ingress links reference the initial ingress on a crossing step."""
    if link.slot_id != chain.initial_ingress_slot_id:
        raise ValueError(
            f"step {step.step_id} ingress link must reference the initial ingress slot"
        )
    if step.boundary_position == "outside":
        raise ValueError(
            f"step {step.step_id} ingress link requires a "
            "crossing or inside boundary position"
        )
    if slot.kind != "entry_point":
        raise ValueError(
            f"step {step.step_id} ingress link must reference an entry_point slot"
        )


def _check_tool_fixture_link(
    step: CanonicalChainStep, link: StepResourceLink, slot: ResourceSlot
) -> None:
    """Tool-fixture links reference a tool slot."""
    if slot.kind != "tool":
        raise ValueError(
            f"step {step.step_id} tool_fixture link must reference a tool slot"
        )


def _check_source_influence_link(
    chain: CanonicalAttackChain,
    step: CanonicalChainStep,
    link: StepResourceLink,
    slots_by_id: dict[str, ResourceSlot],
    slot_ids: set[str],
) -> None:
    """Source-influence links satisfy role, boundary, and target contracts."""
    _check_source_influence_role(step, link, slots_by_id[link.slot_id])
    _check_source_influence_boundary(step, link, slot_ids, slots_by_id)
    _check_source_influence_target(chain, step, link, slot_ids, slots_by_id)


def _check_source_influence_role(
    step: CanonicalChainStep, link: StepResourceLink, slot: ResourceSlot
) -> None:
    """Source-influence slots are entry points or integrations, on a crossing step."""
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


def _check_source_influence_boundary(
    step: CanonicalChainStep,
    link: StepResourceLink,
    slot_ids: set[str],
    slots_by_id: dict[str, ResourceSlot],
) -> None:
    """The trust boundary exists and is a trust_boundary slot."""
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


def _check_source_influence_target(
    chain: CanonicalAttackChain,
    step: CanonicalChainStep,
    link: StepResourceLink,
    slot_ids: set[str],
    slots_by_id: dict[str, ResourceSlot],
) -> None:
    """The target ingress is the initial ingress entry point."""
    tg = link.target_ingress_slot_id
    if tg not in slot_ids:
        raise ValueError(
            f"step {step.step_id} source_influence link "
            f"references an absent target_ingress slot {tg}"
        )
    if tg != chain.initial_ingress_slot_id:
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


def _outcome_slot_kind(link: ObservableOutcomeLink) -> str:
    """The slot kind required by an observation kind."""
    return {
        "model_context": "entry_point",
        "tool_invocation": "tool",
        "persistent_state": "integration",
        "rendered_output": "output_surface",
        "endpoint_receipt": "integration",
        "agent_state": "agent_internal",
    }[link.observation]


def _check_observable_outcome_links(chain: CanonicalAttackChain) -> None:
    """Outcome links resolve to slots of the observation-appropriate kind."""
    slots_by_id = _slots_by_id(chain)
    for step in chain.steps:
        for link in step.observable_outcome_links:
            if link.binding_slot_id not in slots_by_id:
                raise ValueError(
                    f"step {step.step_id} observable outcome link "
                    f"references absent slot {link.binding_slot_id}"
                )
            expected_kind = _outcome_slot_kind(link)
            if slots_by_id[link.binding_slot_id].kind != expected_kind:
                raise ValueError(
                    f"step {step.step_id} observable outcome link "
                    f"observation {link.observation} requires a "
                    f"{expected_kind} slot, got {slots_by_id[link.binding_slot_id].kind}"
                )


def _is_ingress_activation(chain: CanonicalAttackChain, link: StepResourceLink) -> bool:
    """True for a direct ingress link on the initial ingress slot."""
    return link.role == "ingress" and link.slot_id == chain.initial_ingress_slot_id


def _is_source_activation(chain: CanonicalAttackChain, link: StepResourceLink) -> bool:
    """True for a source-influence link targeting the initial ingress."""
    return (
        link.role == "source_influence"
        and link.target_ingress_slot_id == chain.initial_ingress_slot_id
    )


def _ingress_activation_links(
    chain: CanonicalAttackChain,
) -> list[tuple[str, StepResourceLink]]:
    """Direct ingress activation links across the chain."""
    return [
        (step.step_id, link)
        for step in chain.steps
        for link in step.resource_links
        if _is_ingress_activation(chain, link)
    ]


def _source_activation_links(
    chain: CanonicalAttackChain,
) -> list[tuple[str, StepResourceLink]]:
    """Source-influence activation links across the chain."""
    return [
        (step.step_id, link)
        for step in chain.steps
        for link in step.resource_links
        if _is_source_activation(chain, link)
    ]


def _raise_too_many_ingress_links(
    ingress_links: list[tuple[str, StepResourceLink]],
) -> None:
    """At most one chain-wide direct-ingress activation link."""
    if len(ingress_links) > 1:
        step_ids = ", ".join(sid for sid, _ in ingress_links)
        raise ValueError(
            f"chain has {len(ingress_links)} direct-ingress activation "
            f"links (steps: {step_ids}); at most one chain-wide "
            "activation link is permitted"
        )


def _raise_too_many_source_links(
    source_influence_links: list[tuple[str, StepResourceLink]],
) -> None:
    """At most one chain-wide source-influence activation link."""
    if len(source_influence_links) > 1:
        step_ids = ", ".join(sid for sid, _ in source_influence_links)
        raise ValueError(
            f"chain has {len(source_influence_links)} source-influence "
            f"activation links (steps: {step_ids}); at most one "
            "chain-wide activation link is permitted"
        )


def _check_activation_mechanisms(chain: CanonicalAttackChain) -> None:
    """At most one activation mechanism; never both direct and influenced."""
    ingress_links = _ingress_activation_links(chain)
    source_influence_links = _source_activation_links(chain)
    _raise_too_many_ingress_links(ingress_links)
    _raise_too_many_source_links(source_influence_links)
    if ingress_links and source_influence_links:
        raise ValueError(
            "chain has both a direct ingress link and a source_influence "
            "link to the initial ingress; exactly one activation mechanism "
            "is permitted"
        )


def _check_chain_digest(chain: CanonicalAttackChain) -> None:
    """The signed semantic digest must match the current chain content."""
    if chain.semantic_digest != compute_chain_semantic_digest(chain):
        raise ValueError("semantic_digest does not match chain semantics")


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
        source_ids = _step_ids(self.source_chain)
        selected = list(self.selected_step_ids)
        omitted = _omitted_step_ids(self.omissions)
        _check_projection_partition(selected, omitted, source_ids)
        _check_condition_results_unique(self.condition_results)
        _check_bindings_unique(self.bindings)
        slots = _slots_by_id(self.source_chain)
        _check_binding_coverage(slots, self.bindings)
        _check_binding_kinds(slots, self.bindings)
        bindings_by_slot = _binding_refs_by_slot(self.bindings)
        _check_distinct_bindings(slots, bindings_by_slot)
        _check_ingress_binding(self.bindings, self.source_chain.initial_ingress_slot_id)
        results = _condition_results_map(self.condition_results)
        conditional_ids = _conditional_step_ids(self.source_chain)
        _check_condition_result_coverage(results, conditional_ids)
        _check_no_unknown_results(results)
        conditional_steps = _conditional_steps_map(self.source_chain)
        _check_recorded_results(self.condition_results, conditional_steps)
        _check_selected_matches_results(self.source_chain, selected, results)
        _check_omissions_match_results(omitted, results)
        _check_terminal_selected(self.source_chain, selected)
        _check_projection_digest(self)
        return self


def _check_partition_ids_unique(selected: list[str], omitted: list[str]) -> None:
    """Selected and omitted ids must each be duplicate-free."""
    if len(set(selected)) != len(selected) or len(set(omitted)) != len(omitted):
        raise ValueError("selected and omitted step ids must be unique")


def _check_partition_exact(
    selected: list[str], omitted: list[str], source_ids: list[str]
) -> None:
    """Selected and omitted must exactly partition the source steps."""
    if set(selected) & set(omitted) or set(selected) | set(omitted) != set(source_ids):
        raise ValueError(
            "selected and omitted steps must exactly partition source steps"
        )


def _check_selected_order(selected: list[str], source_ids: list[str]) -> None:
    """Selected steps must retain the source chain order."""
    if selected != [step_id for step_id in source_ids if step_id in set(selected)]:
        raise ValueError("selected steps must retain source chain order")


def _step_ids(chain: CanonicalAttackChain) -> list[str]:
    """Step ids in source order."""
    return [s.step_id for s in chain.steps]


def _omitted_step_ids(omissions: tuple[StepOmission, ...]) -> list[str]:
    """Omitted step ids."""
    return [o.step_id for o in omissions]


def _condition_results_map(
    results: tuple[ConditionEvaluationResult, ...],
) -> dict[str, str]:
    """Condition results indexed by step id."""
    return {r.condition_step_id: r.result for r in results}


def _conditional_step_ids(chain: CanonicalAttackChain) -> set[str]:
    """Ids of conditional steps."""
    return {s.step_id for s in chain.steps if s.requirement == "conditional"}


def _conditional_steps_map(
    chain: CanonicalAttackChain,
) -> dict[str, CanonicalChainStep]:
    """Conditional steps indexed by step id."""
    return {
        step.step_id: step for step in chain.steps if step.requirement == "conditional"
    }


def _binding_refs_by_slot(
    bindings: tuple[ResourceBinding, ...],
) -> dict[str, CanonicalResourceReference]:
    """Binding resource references indexed by slot id."""
    return {binding.slot_id: binding.resource_ref for binding in bindings}


def _check_projection_partition(
    selected: list[str], omitted: list[str], source_ids: list[str]
) -> None:
    """Selected and omitted ids are unique and exactly partition the steps."""
    _check_partition_ids_unique(selected, omitted)
    _check_partition_exact(selected, omitted, source_ids)
    _check_selected_order(selected, source_ids)


def _check_condition_results_unique(
    results: tuple[ConditionEvaluationResult, ...],
) -> None:
    """Condition result step ids must be unique."""
    if len({r.condition_step_id for r in results}) != len(results):
        raise ValueError("condition result step ids must be unique")


def _check_bindings_unique(bindings: tuple[ResourceBinding, ...]) -> None:
    """Slot bindings must be unique."""
    if len({b.slot_id for b in bindings}) != len(bindings):
        raise ValueError("slot bindings must be unique")


def _check_binding_coverage(
    slots: dict[str, ResourceSlot], bindings: tuple[ResourceBinding, ...]
) -> None:
    """Bindings must exactly cover all source resource slots."""
    if set(slots) != {binding.slot_id for binding in bindings}:
        raise ValueError("bindings must exactly cover all source resource slots")


def _check_binding_kinds(
    slots: dict[str, ResourceSlot], bindings: tuple[ResourceBinding, ...]
) -> None:
    """Binding resource kinds must match their slots."""
    for binding in bindings:
        slot = slots.get(binding.slot_id)
        if slot is None:
            raise ValueError("binding references an absent resource slot")
        if binding.resource_ref.kind != slot.kind:
            raise ValueError("binding resource kind must match its slot")


def _check_distinct_bindings(
    slots: dict[str, ResourceSlot],
    bindings_by_slot: dict[str, CanonicalResourceReference],
) -> None:
    """Distinct-slot constraints require distinct bound identities."""
    for slot in slots.values():
        for distinct_slot_id in slot.distinct_from_slot_ids:
            if bindings_by_slot[slot.slot_id] == bindings_by_slot[distinct_slot_id]:
                raise ValueError(
                    f"bindings for slots {slot.slot_id} and {distinct_slot_id} "
                    "must have distinct identities"
                )


def _ingress_bindings(
    bindings: tuple[ResourceBinding, ...], initial_ingress_slot_id: str
) -> list[ResourceBinding]:
    """Bindings on the initial ingress slot."""
    return [b for b in bindings if b.slot_id == initial_ingress_slot_id]


def _check_ingress_binding(
    bindings: tuple[ResourceBinding, ...], initial_ingress_slot_id: str
) -> None:
    """The ingress binding must be an entry-point canonical reference."""
    ingress = _ingress_bindings(bindings, initial_ingress_slot_id)
    if len(ingress) != 1 or not isinstance(
        ingress[0].resource_ref, EntryPointResourceReference
    ):
        raise ValueError("ingress binding must be an entry-point canonical reference")


def _check_condition_result_coverage(
    results: dict[str, str], conditional_ids: set[str]
) -> None:
    """Condition results must exactly cover conditional source steps."""
    if set(results) != conditional_ids:
        raise ValueError(
            "condition results must exactly cover conditional source steps"
        )


def _check_no_unknown_results(results: dict[str, str]) -> None:
    """Projection condition results cannot be unknown."""
    if any(result == "unknown" for result in results.values()):
        raise ValueError("projection condition results cannot be unknown")


def _check_recorded_results(
    condition_results: tuple[ConditionEvaluationResult, ...],
    conditional_steps: dict[str, CanonicalChainStep],
) -> None:
    """Recorded results must match the evidence evaluation."""
    for result in condition_results:
        condition = conditional_steps[result.condition_step_id].condition
        if condition is None:  # pragma: no cover - guaranteed by step validation
            raise ValueError("conditional source step requires a condition")
        evaluated = evaluate_condition(condition, result.evidence)
        if evaluated != result.result:
            raise ValueError("recorded condition result does not match evidence")


def _check_selected_matches_results(
    chain: CanonicalAttackChain,
    selected: list[str],
    results: dict[str, str],
) -> None:
    """Selected steps follow requirements and condition results."""
    expected_selected = [
        s.step_id
        for s in chain.steps
        if s.requirement == "required" or results[s.step_id] == "true"
    ]
    if selected != expected_selected:
        raise ValueError("selected steps do not match source requirements and results")


def _check_omissions_match_results(omitted: list[str], results: dict[str, str]) -> None:
    """Omissions must exactly identify false conditional steps."""
    expected_omitted = {
        step_id for step_id, result in results.items() if result == "false"
    }
    if set(omitted) != expected_omitted:
        raise ValueError("omissions must exactly identify false conditional steps")


def _check_terminal_selected(chain: CanonicalAttackChain, selected: list[str]) -> None:
    """The source terminal final step must be selected."""
    if chain.steps[-1].step_id not in selected:
        raise ValueError("source terminal final step must be selected")


def _check_projection_digest(snapshot: ProjectionSnapshot) -> None:
    """The signed projection digest must match the current content."""
    if snapshot.projection_digest != compute_projection_digest(snapshot):
        raise ValueError("projection_digest does not match projection semantics")


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


def _normalize_collection(value: tuple | list, field_name: str | None) -> list:
    """Normalize each item; unordered fields are sorted by canonical form."""
    items = [_normalize(item) for item in value]
    if field_name in _UNORDERED_FIELDS:
        items.sort(key=lambda item: _canonical_json(item).encode())
    return items


def _normalize_model(value: BaseModel) -> dict:
    """Python-mode dump of a model for canonicalization."""
    return value.model_dump(mode="python")


def _normalize(value: Any, field_name: str | None = None) -> Any:
    if isinstance(value, BaseModel):
        value = _normalize_model(value)
    if isinstance(value, dict):
        return {
            unicodedata.normalize("NFC", str(k)): _normalize(v, str(k))
            for k, v in value.items()
        }
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (tuple, list)):
        return _normalize_collection(value, field_name)
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


def _frame_laaf_axis(payload: dict[str, Any]) -> dict[str, Any]:
    """Frame the optional LAAF axis: omitted laaf equals explicit null."""
    context = payload.get("taxonomy_context")
    if isinstance(context, dict) and "laaf" not in context:
        payload["taxonomy_context"] = {**context, "laaf": None}
    return payload


_SLOT_CONSTRAINT_FIELDS = frozenset(
    {
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
)


def _keep_slot_constraint(key: str, value: Any) -> bool:
    """Keep non-constraint keys and every non-empty constraint value."""
    return key not in _SLOT_CONSTRAINT_FIELDS or bool(value)


def _strip_slot_dict(slot: dict) -> dict:
    """One slot dict with empty constraint fields removed."""
    return {
        key: value for key, value in slot.items() if _keep_slot_constraint(key, value)
    }


def _strip_slot_constraints(slots: Any) -> Any:
    """Drop empty constraint fields from slot dicts (never mutates input)."""
    if not isinstance(slots, (list, tuple)):
        return slots
    return [
        _strip_slot_dict(slot) if isinstance(slot, dict) else slot for slot in slots
    ]


def _frame_chain_slots(payload: dict[str, Any]) -> None:
    """Strip empty resource constraints when the payload carries slots."""
    slots = payload.get("resource_slots")
    if isinstance(slots, (list, tuple)):
        payload["resource_slots"] = _strip_slot_constraints(slots)


def _framed_link_entry(link: dict) -> dict:
    """One resource link with optional fields framed as model defaults."""
    return {
        **{
            key: value
            for key, value in link.items()
            if key != "source_identity_kind" or value is not None
        },
        "trust_boundary_slot_id": link.get("trust_boundary_slot_id"),
        "target_ingress_slot_id": link.get("target_ingress_slot_id"),
        **(
            {"source_identity_kind": link["source_identity_kind"]}
            if link.get("source_identity_kind") is not None
            else {}
        ),
    }


def _frame_chain_link_entries(links: list | tuple) -> list:
    """Frame optional None fields on one step's resource links."""
    entries = []
    for link in links:
        if not isinstance(link, dict):
            entries.append(link)
            continue
        entries.append(_framed_link_entry(link))
    return entries


def _frame_chain_step_list(steps: list | tuple) -> list:
    """Frame optional link arrays on each chain step dict."""
    normalized_steps = []
    for step in steps:
        if not isinstance(step, dict):
            normalized_steps.append(step)
            continue
        step = {
            **step,
            "resource_links": step.get("resource_links", []),
            "observable_outcome_links": step.get("observable_outcome_links", []),
        }
        links = step["resource_links"]
        if isinstance(links, (list, tuple)):
            step = {**step, "resource_links": _frame_chain_link_entries(links)}
        normalized_steps.append(step)
    return normalized_steps


def _frame_chain_steps(payload: dict[str, Any]) -> None:
    """Frame step link arrays when the payload carries steps."""
    steps = payload.get("steps")
    if isinstance(steps, (list, tuple)):
        payload["steps"] = _frame_chain_step_list(steps)


def compute_chain_semantic_digest(chain: CanonicalAttackChain | dict[str, Any]) -> str:
    payload = (
        chain.model_dump(mode="python") if isinstance(chain, BaseModel) else dict(chain)
    )
    # Canonicalize the optional LAAF axis: an omitted ``laaf`` key in
    # ``taxonomy_context`` frames exactly like the explicit ``None`` that
    # model validation materializes, so a caller may sign a raw dict that
    # omits the key and still pass validation.  Never mutates ``chain``.
    _frame_laaf_axis(payload)
    # Empty resource constraints are unconstrained and were absent from
    # chains signed before these generic constraints existed. Keep omitted
    # and explicitly empty constraints byte-equivalent while signing every
    # non-empty constraint.
    _frame_chain_slots(payload)
    # Canonicalize optional linkage fields: a raw dict may omit
    # ``trust_boundary_slot_id`` / ``target_ingress_slot_id`` on a
    # resource link where model validation materializes ``None``, and may
    # omit ``resource_links`` / ``observable_outcome_links`` arrays where
    # model validation materializes empty tuples.  Frame omitted and
    # explicit-None/[] identically so callers can sign raw dicts that omit
    # the defaults.  Never mutates ``chain``.
    _frame_chain_steps(payload)
    return _semantic_digest(
        payload, "semantic_digest", "asago-scenario-generator:canonical-chain:v1"
    )


def _stripped_link_entry(link: dict) -> dict:
    """One resource link with null source_identity_kind removed."""
    return {
        key: value
        for key, value in link.items()
        if key != "source_identity_kind" or value is not None
    }


def _frame_projection_link_entries(links: Any) -> list:
    """Strip source_identity_kind entries from one step's resource links."""
    entries = []
    for link in links:
        if not isinstance(link, dict):
            entries.append(link)
            continue
        entries.append(_stripped_link_entry(link))
    return entries


def _frame_projection_slots(source_chain: dict) -> dict:
    """The source chain with empty resource constraints stripped."""
    resource_slots = source_chain.get("resource_slots")
    if isinstance(resource_slots, (list, tuple)):
        return {
            **source_chain,
            "resource_slots": _strip_slot_constraints(resource_slots),
        }
    return source_chain


def _frame_projection_steps(source_chain: dict) -> dict:
    """The source chain with step link fields framed."""
    steps = source_chain.get("steps")
    if isinstance(steps, (list, tuple)):
        return {
            **source_chain,
            "steps": [
                {
                    **step,
                    "resource_links": _frame_projection_link_entries(
                        step.get("resource_links", ())
                    ),
                }
                if isinstance(step, dict)
                else step
                for step in steps
            ],
        }
    return source_chain


def _frame_projection_source(payload: dict[str, Any]) -> None:
    """Frame the embedded source chain: constraints and link fields."""
    source_chain = payload.get("source_chain")
    if not isinstance(source_chain, dict):
        return
    payload["source_chain"] = _frame_projection_steps(
        _frame_projection_slots(source_chain)
    )


def _drop_empty_relation_paths(payload: dict[str, Any]) -> None:
    """Frame empty relation paths as absent (backwards-compatible default)."""
    if payload.get("source_influence_paths") == ():
        payload.pop("source_influence_paths", None)
    elif payload.get("source_influence_paths") == []:
        payload.pop("source_influence_paths", None)


def compute_projection_digest(snapshot: ProjectionSnapshot | dict[str, Any]) -> str:
    payload = (
        snapshot.model_dump(mode="python")
        if isinstance(snapshot, BaseModel)
        else dict(snapshot)
    )
    # Empty resource constraints and optional link fields frame like the
    # model materialization.  Never mutates ``snapshot``.
    _frame_projection_source(payload)
    # Empty relation paths are the backwards-compatible direct-ingress
    # default.  Keep their digest equivalent to pre-relation snapshots while
    # binding a non-empty authoritative path into the new digest.
    _drop_empty_relation_paths(payload)
    return _semantic_digest(
        payload, "projection_digest", "asago-scenario-generator:projection:v1"
    )


def validate_legacy_attack_pattern(
    pattern_dict: dict[str, Any],
) -> LegacyAttackPatternRecord:
    return LegacyAttackPatternRecord.model_validate(pattern_dict)


def _check_resolver_pins(pattern: AttackPattern, resolver: TaxonomyResolver) -> None:
    """The resolver must pin the identical taxonomy context."""
    if resolver.taxonomy_context != pattern.canonical_chain.taxonomy_context:
        raise ValueError("taxonomy resolver pins do not match canonical chain pins")


def _check_mapping_membership(
    resolver: TaxonomyResolver,
    mappings: tuple[MappingDecision, ...] | tuple[ChainMappingDecision, ...],
) -> None:
    """Every exact mapping id must be resolvable in its taxonomy."""
    for mapping in mappings:
        if isinstance(mapping, ExactMapping):
            for identifier in mapping.ids:
                if not resolver.contains(mapping.taxonomy, identifier):
                    raise ValueError(f"unknown {mapping.taxonomy} id: {identifier}")


def validate_attack_pattern(
    pattern_dict: dict[str, Any], resolver: TaxonomyResolver
) -> AttackPattern:
    """Parse and qualify a pattern; ``AttackPattern.model_validate`` only parses."""
    pattern = AttackPattern.model_validate(pattern_dict)
    _check_resolver_pins(pattern, resolver)
    mapping_scopes = [
        pattern.canonical_chain.mappings,
        *(s.mappings for s in pattern.canonical_chain.steps),
    ]
    for mappings in mapping_scopes:
        _check_mapping_membership(resolver, mappings)
    return pattern


def _check_snapshot_digest_pin(
    resolver: CapabilitySnapshotResolver, snapshot: ProjectionSnapshot
) -> None:
    """The resolver must pin the identical capability snapshot digest."""
    if (
        resolver.capability_fact_snapshot_digest
        != snapshot.capability_fact_snapshot_digest
    ):
        raise ValueError("capability snapshot resolver digest pin does not match")


def _check_fact_evidence(
    resolver: CapabilitySnapshotResolver, snapshot: ProjectionSnapshot
) -> None:
    """Every supplied fact evidence must match the resolver reading."""
    for result in snapshot.condition_results:
        for supplied in result.evidence:
            authoritative = resolver.fact(supplied.fact)
            if authoritative is None:
                raise ValueError("authoritative condition fact is missing")
            if authoritative != supplied:
                raise ValueError(
                    "condition fact evidence does not match resolver reading"
                )


def _check_resource_bindings(
    resolver: CapabilitySnapshotResolver, snapshot: ProjectionSnapshot
) -> None:
    """Every binding resolves and matches its slot constraints."""
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


def validate_projection_snapshot(
    snapshot_dict: dict[str, Any], resolver: CapabilitySnapshotResolver
) -> ProjectionSnapshot:
    """Parse and externally qualify a projection against a mandatory pinned resolver."""
    snapshot = ProjectionSnapshot.model_validate(snapshot_dict)
    _check_snapshot_digest_pin(resolver, snapshot)
    _check_fact_evidence(resolver, snapshot)
    _check_resource_bindings(resolver, snapshot)
    return snapshot


AllCondition.model_rebuild()
AnyCondition.model_rebuild()
NotCondition.model_rebuild()
