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


AllCondition.model_rebuild()
AnyCondition.model_rebuild()
NotCondition.model_rebuild()


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T21:34:37Z","module_hash":"c22cb9ab828f5712682980042da34cc5e251ee079d7cabf3b05a4ec0213ba050","source_sha256":"91954d590101e83202936278120250453b0d0d23eef1c3b787f97b3f81de144a","functions":[{"id":"func/TaxonomyResolver.taxonomy_context","name":"taxonomy_context","line":112,"end_line":112,"hash":"e3680193f799a2fa159511e59743ae10ca13dcd2bcb65167c31c2df52cd05f8c"},{"id":"func/TaxonomyResolver.contains","name":"contains","line":114,"end_line":114,"hash":"0d2f7869faaca57b75a6a0d5be29f3930f9e04993d3929032801aa85888f08c9"},{"id":"func/CapabilitySnapshotResolver.capability_fact_snapshot_digest","name":"capability_fact_snapshot_digest","line":121,"end_line":121,"hash":"0ff17550a5c048d9aec01e26595f943eb61f285d256460e14c7cefe881e2a58f"},{"id":"func/CapabilitySnapshotResolver.fact","name":"fact","line":123,"end_line":125,"hash":"c6cc8bfefd2dcc704cbd787d2b304a9b1841116f1085b975c21904c32e9a3970"},{"id":"func/CapabilitySnapshotResolver.contains_resource","name":"contains_resource","line":127,"end_line":127,"hash":"a230f08bf29d30c6b92b0cecc61634e9ad1d225b72710bae2e0559a822c32ca6"},{"id":"func/CapabilitySnapshotResolver.resource_matches_slot","name":"resource_matches_slot","line":129,"end_line":131,"hash":"59e7e5380bbb7febbd2f73244fd6fa86db0da003daa1338e17d9d980509c893c"},{"id":"func/_validate_fact_scalar","name":"_validate_fact_scalar","line":168,"end_line":171,"hash":"4e5baa935ff1fcd85a20544597bda10d26fc2b3ea85d1295d85371b27d3ad7a2"},{"id":"func/EqualityCondition.matching_type","name":"matching_type","line":181,"end_line":183,"hash":"ee782d7fb60f1abde82e77cd49211914e0c1eaa252099ac961cbc9062cd7bc94"},{"id":"func/_membership_values_unique","name":"_membership_values_unique","line":186,"end_line":188,"hash":"457f5b6d26fa5f3830cedeb2615cc0686f3de98e98e27383569a194094cf29b5"},{"id":"func/_validate_membership_values","name":"_validate_membership_values","line":191,"end_line":198,"hash":"167d57618db81ced80bd9c1ad024c64f69c1b6031ecb69664527c1625788675e"},{"id":"func/MembershipCondition.unique_values","name":"unique_values","line":208,"end_line":210,"hash":"b82071e7fff1f11966e4e0415032224ac431db710bb68879a064d90992f1fa6f"},{"id":"func/PropertyMatchCondition.matching_type_and_path","name":"matching_type_and_path","line":227,"end_line":231,"hash":"85449ac16929818b095f65a6c6c19b5906f32655fa5d0e37f1dc5afb119790b1"},{"id":"func/AllCondition.bounded","name":"bounded","line":242,"end_line":244,"hash":"400a491d164abc0ed21ddffb6c06bfae7ada6866de73bbefd84bd09d07c1b3b8"},{"id":"func/AnyCondition.bounded","name":"bounded","line":255,"end_line":257,"hash":"84c4614ef3584d5244047a309697a7d8cd60adba2dd164e57a7698a8edb91307"},{"id":"func/NotCondition.bounded","name":"bounded","line":266,"end_line":268,"hash":"93ef5da84342d72236af6d234ca5fb4123a3e58b0c5032cc0ee050372d2432f4"},{"id":"func/_condition_children","name":"_condition_children","line":283,"end_line":289,"hash":"42c2cbdb06b93af9af8cda93ac794cdd63fb1bc85f39a127b7d7ed513b4e5e04"},{"id":"func/_check_duplicate_operands","name":"_check_duplicate_operands","line":292,"end_line":297,"hash":"46ee97caa357e698d8c9da9a00d03804aaec11ebc796870a5557f8a495d9e743"},{"id":"func/_walk_condition","name":"_walk_condition","line":300,"end_line":308,"hash":"6c63588c84c2e38b550db92e5d349205a8564afdd454ada0f38ce726b75197b4"},{"id":"func/_check_condition","name":"_check_condition","line":311,"end_line":312,"hash":"b919b054f62ad1f0e65ed6d642d522f8d6c60acd846a70c277f82b7884899568"},{"id":"func/EvaluatedFactEvidence.coherent","name":"coherent","line":321,"end_line":329,"hash":"f4726264396306f0efea5e660c25ddce12ca42ad4a3ad926496ab90dcab6c73e"},{"id":"func/ConditionEvaluationResult.unique_evidence_facts","name":"unique_evidence_facts","line":338,"end_line":344,"hash":"ba354e1d0b85b5c13f164f7695ad82c564161b3aea863421fedc763daeb99d73"},{"id":"func/StepProvenance.unique_references","name":"unique_references","line":359,"end_line":366,"hash":"8a122a105c7e238486d7074ad825c11721c581140b2bb6ee9f862d51e22d87d9"},{"id":"func/ExactMapping.unique_ids","name":"unique_ids","line":375,"end_line":378,"hash":"b9d068c5a999839ec03a2fb411b3673b6b486b41721e8f7922493cea31e81231"},{"id":"func/StepPrecondition.bounded","name":"bounded","line":407,"end_line":409,"hash":"c6b642ac1a59b39aa11264c90cad11b6b6df9869183ac0202139b6c62614c4d5"},{"id":"func/StepResourceLink.source_influence_fields_are_exclusive","name":"source_influence_fields_are_exclusive","line":445,"end_line":450,"hash":"15abe79be75e2cdd4a5a40942032ac9915add3f74fdc495f3b25ca0713f903a5"},{"id":"func/_check_source_influence_fields","name":"_check_source_influence_fields","line":453,"end_line":462,"hash":"f1074298373e83c009e6c60d3a4239578d458a8a5949b3d30a73af92b475e4cc"},{"id":"func/_check_non_influence_fields","name":"_check_non_influence_fields","line":465,"end_line":478,"hash":"df3d4cd9635d8e3fba7710a4e7352d21b649f8721a1934f7b5665d7147399753"},{"id":"func/_condition_fact_keys","name":"_condition_fact_keys","line":569,"end_line":578,"hash":"7e34aef92d07f73425b643ceccf925c56808beb142ce536958e6bc6b149cfeb4"},{"id":"func/_all_verdict","name":"_all_verdict","line":581,"end_line":589,"hash":"f92bbae7344a0300b88caeaa42cc59d36d6790619bee2b75a7f5f55de682560a"},{"id":"func/_any_verdict","name":"_any_verdict","line":592,"end_line":600,"hash":"ff6268634daed9776ec7dac28cd175bbef7cd0c379f1f102c80a7eccef897484"},{"id":"func/_not_verdict","name":"_not_verdict","line":603,"end_line":607,"hash":"6f3de72804aec9ec3b519c12ec50dba4fef97bba404ae08df90c42d9983b978d"},{"id":"func/_present_verdict","name":"_present_verdict","line":610,"end_line":618,"hash":"6dac688390aaa1e2d4931cfe7a6bc3869577b18d5a5aed13f97e605727cc53dc"},{"id":"func/_leaf_verdict","name":"_leaf_verdict","line":621,"end_line":632,"hash":"8332513b5322a477908630ea56b04ecffb7927cefe41517087a7b701496c7204"},{"id":"func/_evaluate_node","name":"_evaluate_node","line":635,"end_line":652,"hash":"2b737491ac0b9ae266002989162cb8cfb3bdf3a3aec37f4e53cf13f520f12518"},{"id":"func/evaluate_condition","name":"evaluate_condition","line":655,"end_line":666,"hash":"60d9c8453db72d621e42733485ce5d8223abc741e4d96afa6531f9a1fac7437d"}]}
# mutate4py-manifest-end
