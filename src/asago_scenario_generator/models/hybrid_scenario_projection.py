"""Closed, neutral contracts for the Phase 4 combined projection.

This module intentionally contains no knowledge of the taxonomy or STPA
pipeline implementations.  The pipeline adapter builds these values from
validated upstream artifacts; the values themselves are standalone, deeply
immutable records.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, Any, Literal, TypeAlias

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

from asago_scenario_generator.models.attack_pattern_chain import CanonicalChainStep
from asago_scenario_generator.models.attack_pattern_contracts import TaxonomyPin
from asago_scenario_generator.models.correspondence import (
    AcceptedCorrespondenceRelation,
    RelationKind as CorrespondenceRelationKind,
)
from asago_scenario_generator.models.attack_pattern_projection import (
    EntryPointResourceReference,
    ProjectionSnapshot,
    ResourceBinding,
)
from asago_scenario_generator.models.canonical import (
    compute_framed_digest,
    normalize_unicode,
    unique_sorted_strings,
)
from asago_scenario_generator.models.attack_pattern_contracts import (
    ExecutionRequirement,
)
from asago_scenario_generator.models.hybrid_coverage import ArtifactPin


Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
RelationId = Annotated[str, Field(pattern=r"^correlation:v1:[0-9a-f]{64}$")]
ObligationId = Annotated[str, Field(pattern=r"^ob:v1:[0-9a-f]{64}$")]
CandidateId = Annotated[str, Field(pattern=r"^cand:v2:[0-9a-f]{32}$")]
ExecCandidateId = Annotated[str, Field(pattern=r"^EXEC:[^:]+:[^:]+:[A-Z_]+$")]
Identifier = Annotated[str, Field(min_length=1)]

HYBRID_PROJECTION_INPUTS_SCHEMA_VERSION = "hybrid-projection-inputs-v1"
MECHANISM_PROJECTION_SCHEMA_VERSION = "taxonomy-mechanism-projection-v1"
CAUSAL_PROJECTION_SCHEMA_VERSION = "stpa-causal-projection-v1"
PINNED_STPA_PROJECTION_ATTESTATION_SCHEMA_VERSION = (
    "pinned-stpa-projection-attestation-v1"
)
HYBRID_CORRESPONDENCE_ATTESTATION_SCHEMA_VERSION = (
    "hybrid-correspondence-attestation-v1"
)
CONFIRMED_COVERAGE_REVIEW_SCHEMA_VERSION = "confirmed-coverage-review-v1"
HYBRID_BRIDGE_LINK_SCHEMA_VERSION = "hybrid-bridge-link-v1"
HYBRID_BRIDGE_EVIDENCE_SCHEMA_VERSION = "hybrid-bridge-evidence-v1"
CAPABILITY_FACT_ATTESTATION_SCHEMA_VERSION = "capability-fact-attestation-v1"

_MECHANISM_DIGEST_DOMAIN = "asago.taxonomy-mechanism-projection.v1"
_CAUSAL_DIGEST_DOMAIN = "asago.stpa-causal-projection.v1"
_STPA_ATTESTATION_DIGEST_DOMAIN = "asago.pinned-stpa-projection-attestation.v1"
_CORRESPONDENCE_ATTESTATION_DIGEST_DOMAIN = "asago.hybrid-correspondence-attestation.v1"
_REVIEW_DIGEST_DOMAIN = "asago.confirmed-coverage-review.v1"
_BRIDGE_EVIDENCE_DIGEST_DOMAIN = "asago.hybrid-bridge-evidence.v1"
_BRIDGE_LINK_DIGEST_DOMAIN = "asago.hybrid-bridge-link.v1"
_PROJECTION_DIGEST_DOMAIN = "asago.hybrid-scenario-projection.v1"
_PROJECTION_SET_DIGEST_DOMAIN = "asago.hybrid-scenario-projection-set.v1"
PHASE1_CANDIDATE_RECORD_DIGEST_DOMAIN = "asago.phase1-candidate-record.v1"
STPA_EXECUTION_PROJECTION_DIGEST_DOMAIN = "asago.stpa-execution-projection.v1"


class _ProjectionModel(BaseModel):
    """Common closed, immutable model configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def normalize_input(cls, value: Any) -> Any:
        """Normalize strings before identity or digest validation."""
        # ``normalize_unicode`` serializes every Pydantic model to a mapping.
        # That is correct for canonical digests, but it destroys the identity
        # of verified attestation instances (including their construction
        # boundary) when they are nested in another closed model.  Preserve
        # typed values at this seam; each nested model has already applied its
        # own canonical normalization and Pydantic will still validate its
        # declared type.
        return _normalize_input_preserving_models(value)


def _sorted_unique(values: Sequence[str], label: str) -> tuple[str, ...]:
    """Return a deterministic non-empty-safe set-like string collection."""
    return unique_sorted_strings(tuple(values), label) if values else ()


def _normalize_input_preserving_models(value: Any) -> Any:
    """NFC-normalize an input graph without serializing typed model leaves.

    The shared canonical normalizer intentionally turns nested Pydantic values
    into mappings.  At this boundary the nested values may be verified
    attestations, so retaining the instance is part of the construction
    contract (the resolver rejects caller-authored instances).  Raw mappings
    remain mappings and are validated/rejected by the closed envelope.
    """
    if isinstance(value, BaseModel):
        return value
    if isinstance(value, dict):
        return {
            normalize_unicode(key): _normalize_input_preserving_models(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_normalize_input_preserving_models(item) for item in value]
    return normalize_unicode(value)


def _dump_without(model: BaseModel, *fields: str) -> dict[str, Any]:
    """Dump one model while excluding fields used to derive its identity."""
    return model.model_dump(mode="json", exclude=set(fields))


def _derive_id(model: BaseModel, prefix: str, domain: str, id_field: str) -> str:
    """Derive one content-addressed ID without circular digest fields."""
    return prefix + compute_framed_digest(
        domain, _dump_without(model, id_field, "semantic_digest")
    )


def _semantic_digest(model: BaseModel, domain: str) -> str:
    """Hash complete model content except its semantic digest."""
    return compute_framed_digest(domain, _dump_without(model, "semantic_digest"))


def _validate_optional_derived_value(
    actual: str | None, expected: str, label: str
) -> None:
    """Reject a caller-supplied derived identity or digest that disagrees."""
    if actual and actual != expected:
        raise ValueError(f"{label} does not match content")


class ArtifactProjectionSourcePin(_ProjectionModel):
    """A role-labelled ordinary artifact pin retained by Phase 4."""

    kind: Literal["artifact"] = "artifact"
    role: Identifier = "artifact"
    pin: ArtifactPin

    @classmethod
    def from_artifact_pin(
        cls, value: ArtifactPin, *, role: str = "artifact"
    ) -> "ArtifactProjectionSourcePin":
        """Preserve an existing artifact pin without changing its identity."""
        if not isinstance(value, ArtifactPin):
            raise TypeError("value must be an ArtifactPin")
        return cls(role=role, pin=value)

    def as_artifact_pin(self) -> ArtifactPin:
        """Return the shared unlabelled pin for APIs that require it."""
        return self.pin

    @property
    def artifact_id(self) -> str:
        """Expose the inner pin identity for adapter ergonomics."""
        return self.pin.artifact_id

    @property
    def schema_version(self) -> str:
        """Expose the inner pin schema for adapter ergonomics."""
        return self.pin.schema_version

    @property
    def semantic_digest(self) -> str:
        """Expose the inner pin digest for adapter ergonomics."""
        return self.pin.semantic_digest


class TaxonomyProjectionSourcePin(_ProjectionModel):
    """A role-labelled Phase 1 taxonomy release pin.

    ``TaxonomyPin`` has release/digest semantics, not artifact-id/schema
    semantics.  Keeping it in its native shape prevents accidental identity
    substitution at the Phase 4 boundary.
    """

    kind: Literal["taxonomy"] = "taxonomy"
    role: Literal["catalog", "mapping"]
    taxonomy_id: Identifier
    pin: TaxonomyPin

    @classmethod
    def from_taxonomy_pin(cls, value: TaxonomyPin) -> "TaxonomyProjectionSourcePin":
        """Wrap one exact Phase 1 taxonomy pin."""
        if not isinstance(value, TaxonomyPin):
            raise TypeError("value must be a TaxonomyPin")
        return cls(role="catalog", taxonomy_id="taxonomy", pin=value)

    def as_taxonomy_pin(self) -> TaxonomyPin:
        """Return the original Phase 1 taxonomy pin shape."""
        return self.pin

    @property
    def release(self) -> str:
        """Expose the original Phase 1 release unchanged."""
        return self.pin.release

    @property
    def digest(self) -> str:
        """Expose the original Phase 1 digest unchanged."""
        return self.pin.digest


ProjectionSourcePin: TypeAlias = Annotated[
    ArtifactProjectionSourcePin | TaxonomyProjectionSourcePin,
    Field(discriminator="kind"),
]


def _source_pin_key(value: ProjectionSourcePin) -> tuple[str, ...]:
    """Return one canonical ordering key for either pin role."""
    if isinstance(value, ArtifactProjectionSourcePin):
        return (
            "artifact",
            value.role,
            value.pin.artifact_id,
            value.pin.schema_version,
            value.pin.semantic_digest,
        )
    return (
        "taxonomy",
        value.role,
        value.taxonomy_id,
        value.pin.release,
        value.pin.digest,
    )


class CapabilityFactAttestation(_ProjectionModel):
    """Neutral proof that the exact capability/fact snapshot was supplied."""

    schema_version: Literal[CAPABILITY_FACT_ATTESTATION_SCHEMA_VERSION] = (
        CAPABILITY_FACT_ATTESTATION_SCHEMA_VERSION
    )
    capability_snapshot_digest: Digest
    qualification_facts_digest: Digest
    source_pin: ArtifactPin
    semantic_digest: Digest | None = None

    @property
    def snapshot_digest(self) -> str:
        """Compatibility spelling for the capability snapshot digest."""
        return self.capability_snapshot_digest

    @model_validator(mode="after")
    def verify_digest(self) -> "CapabilityFactAttestation":
        expected = _semantic_digest(self, "asago.capability-fact-attestation.v1")
        _validate_optional_derived_value(
            self.semantic_digest,
            expected,
            "capability fact attestation digest",
        )
        object.__setattr__(self, "semantic_digest", expected)
        return self

    def assert_integrity(self) -> None:
        """Verify the neutral snapshot attestation content."""
        if self.semantic_digest != _semantic_digest(
            self, "asago.capability-fact-attestation.v1"
        ):
            raise ValueError("capability fact attestation digest mismatch")


class MechanismProjection(_ProjectionModel):
    """Complete mechanism projection using the existing canonical contract.

    ``ProjectionSnapshot`` already owns the authoritative canonical chain,
    typed condition AST, selected steps, and resource bindings.  Reusing it
    here avoids inventing a second operation/condition vocabulary at the
    synthesis boundary.  The outer adapter copies and revalidates the
    current ``ProjectedCandidate`` before constructing this neutral value.
    """

    schema_version: Literal[MECHANISM_PROJECTION_SCHEMA_VERSION] = (
        MECHANISM_PROJECTION_SCHEMA_VERSION
    )
    mechanism_projection_id: str = ""
    obligation_id: ObligationId
    risk_id: Identifier
    attack_pattern_id: Identifier
    selected_candidate_id: CandidateId
    projection: ProjectionSnapshot
    canonical_ingress: EntryPointResourceReference
    ingress_controllability: Literal["direct", "indirect"]
    execution_requirements: tuple[ExecutionRequirement, ...] = Field(min_length=1)
    execution_requirements_digest: Digest
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def validate_and_identify(self) -> "MechanismProjection":
        _validate_mechanism_contract(self)
        expected_id = _derive_id(
            self, "mech:v1:", _MECHANISM_DIGEST_DOMAIN, "mechanism_projection_id"
        )
        _validate_optional_derived_value(
            self.mechanism_projection_id, expected_id, "mechanism_projection_id"
        )
        object.__setattr__(self, "mechanism_projection_id", expected_id)
        expected_digest = _semantic_digest(self, _MECHANISM_DIGEST_DOMAIN)
        _validate_optional_derived_value(
            self.semantic_digest,
            expected_digest,
            "mechanism projection semantic_digest",
        )
        object.__setattr__(self, "semantic_digest", expected_digest)
        return self

    @property
    def steps(self) -> tuple[CanonicalChainStep, ...]:
        """Return the selected canonical chain steps in authority order."""
        selected = set(self.projection.selected_step_ids)
        return tuple(
            step
            for step in self.projection.source_chain.steps
            if step.step_id in selected
        )

    @property
    def conditions(self) -> tuple[Any, ...]:
        """Return the exact condition/precondition ASTs from the snapshot."""
        return tuple(
            step.condition for step in self.steps if step.condition is not None
        ) + tuple(
            precondition.condition
            for step in self.steps
            for precondition in step.preconditions
        )

    @property
    def ingress(self) -> tuple[EntryPointResourceReference, ...]:
        """Return the projection-owned canonical ingress as a one-item view."""
        return (self.canonical_ingress,)

    @property
    def resource_bindings(self) -> tuple[ResourceBinding, ...]:
        """Return the exact resource bindings from the projection snapshot."""
        return self.projection.bindings

    def compute_semantic_digest(self) -> str:
        """Compute this projection's current semantic digest."""
        return _semantic_digest(self, _MECHANISM_DIGEST_DOMAIN)

    def assert_integrity(self) -> None:
        """Raise when the projection has been modified."""
        if self.semantic_digest != self.compute_semantic_digest():
            raise ValueError("mechanism projection semantic digest mismatch")


def _validate_mechanism_contract(projection: MechanismProjection) -> None:
    """Validate cross-field mechanism identity and source requirements."""
    if projection.projection.source_chain.pattern_id != projection.attack_pattern_id:
        raise ValueError("mechanism projection pattern identity does not match chain")
    if projection.projection.capability_fact_snapshot_digest is None:
        raise ValueError("mechanism projection must retain capability snapshot digest")
    if projection.canonical_ingress != _projection_ingress(projection.projection):
        raise ValueError("mechanism canonical ingress does not match projection")
    _verify_execution_requirements_digest(
        projection.execution_requirements, projection.execution_requirements_digest
    )


class CausalNode(_ProjectionModel):
    """One node in the neutral STPA causal trace."""

    node_id: Identifier
    kind: Literal[
        "loss",
        "hazard",
        "constraint",
        "controller",
        "control_action",
        "coordination_link",
        "coordination_mechanism",
        "feedback",
        "process_model",
        "uca",
        "ica",
        "exec",
    ]
    ordinal: int = Field(ge=0)


class CausalEdge(_ProjectionModel):
    """One typed local causal edge."""

    edge_id: Identifier
    from_node_id: Identifier
    to_node_id: Identifier
    kind: Literal["causal", "control", "feedback", "projection"]


_PROJECTION_EDGE_KINDS: dict[str, set[tuple[str, str]]] = {
    "projection": {
        ("loss", "hazard"),
        ("hazard", "constraint"),
        ("constraint", "controller"),
        ("constraint", "control_action"),
        ("constraint", "coordination_link"),
        ("constraint", "coordination_mechanism"),
        ("controller", "uca"),
        ("control_action", "uca"),
        ("coordination_link", "uca"),
        ("coordination_mechanism", "uca"),
        ("uca", "ica"),
        ("ica", "exec"),
    },
    "control": {
        ("controller", "control_action"),
        ("control_action", "uca"),
        ("coordination_link", "coordination_mechanism"),
        ("coordination_mechanism", "uca"),
    },
    "feedback": {("feedback", "controller"), ("feedback", "process_model")},
    "causal": {
        ("process_model", "uca"),
        ("process_model", "ica"),
        ("feedback", "uca"),
        ("feedback", "ica"),
        ("control_action", "uca"),
        ("control_action", "ica"),
    },
}


class CausalProjection(_ProjectionModel):
    """Complete, neutral projection of one exact STPA causal path."""

    schema_version: Literal[CAUSAL_PROJECTION_SCHEMA_VERSION] = (
        CAUSAL_PROJECTION_SCHEMA_VERSION
    )
    causal_projection_id: str = ""
    loss_ids: tuple[Identifier, ...] = Field(min_length=1)
    hazard_ids: tuple[Identifier, ...] = Field(min_length=1)
    constraint_ids: tuple[Identifier, ...] = Field(min_length=1)
    controller_id: Identifier
    control_action_id: Identifier
    uca_slot_id: Identifier
    ica_id: Identifier
    exec_candidate_id: ExecCandidateId
    nodes: tuple[CausalNode, ...] = Field(min_length=1)
    edges: tuple[CausalEdge, ...] = Field(min_length=1)
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def validate_and_identify(self) -> "CausalProjection":
        nodes, edges = _canonical_causal_graph(self)
        nodes_by_id = {item.node_id: item for item in nodes}
        _require_causal_identity_nodes(self, nodes_by_id)
        _require_causal_edges(self, nodes, edges, nodes_by_id)
        _require_acyclic(edges)
        object.__setattr__(self, "nodes", nodes)
        object.__setattr__(self, "edges", edges)
        expected_id = _derive_id(
            self, "causal:v1:", _CAUSAL_DIGEST_DOMAIN, "causal_projection_id"
        )
        _validate_optional_derived_value(
            self.causal_projection_id, expected_id, "causal_projection_id"
        )
        object.__setattr__(self, "causal_projection_id", expected_id)
        expected_digest = _semantic_digest(self, _CAUSAL_DIGEST_DOMAIN)
        _validate_optional_derived_value(
            self.semantic_digest, expected_digest, "causal projection semantic_digest"
        )
        object.__setattr__(self, "semantic_digest", expected_digest)
        return self

    def compute_semantic_digest(self) -> str:
        """Compute this projection's current semantic digest."""
        return _semantic_digest(self, _CAUSAL_DIGEST_DOMAIN)

    def assert_integrity(self) -> None:
        """Raise when the causal projection has changed."""
        if self.semantic_digest != self.compute_semantic_digest():
            raise ValueError("causal projection semantic digest mismatch")


def _canonical_causal_graph(
    projection: CausalProjection,
) -> tuple[tuple[CausalNode, ...], tuple[CausalEdge, ...]]:
    """Canonicalize causal identities and reject duplicate graph members."""
    for field_name in ("loss_ids", "hazard_ids", "constraint_ids"):
        object.__setattr__(
            projection,
            field_name,
            _sorted_unique(getattr(projection, field_name), field_name),
        )
    nodes = tuple(
        sorted(projection.nodes, key=lambda item: (item.ordinal, item.node_id))
    )
    edges = tuple(sorted(projection.edges, key=lambda item: item.edge_id))
    _require_unique((item.node_id for item in nodes), "causal node IDs must be unique")
    _require_unique(
        (item.ordinal for item in nodes), "causal node ordinals must be unique"
    )
    _require_unique((item.edge_id for item in edges), "causal edge IDs must be unique")
    return nodes, edges


def _require_unique(values: Sequence[Any], message: str) -> None:
    """Reject duplicate identifiers in a closed collection."""
    values = tuple(values)
    if len(values) != len(set(values)):
        raise ValueError(message)


def _projection_ingress(
    projection: ProjectionSnapshot,
) -> EntryPointResourceReference:
    """Resolve the exact initial-ingress binding from a projection snapshot."""
    for binding in projection.bindings:
        if binding.slot_id == projection.source_chain.initial_ingress_slot_id:
            if not isinstance(binding.resource_ref, EntryPointResourceReference):
                raise ValueError("mechanism initial ingress must be an entry point")
            return binding.resource_ref
    raise ValueError("mechanism projection is missing its initial ingress binding")


def _verify_execution_requirements_digest(
    requirements: Sequence[ExecutionRequirement], supplied: str
) -> None:
    """Check the existing execution-requirement digest contract.

    The implementation intentionally uses the shared canonical/framed digest
    primitive.  The field is retained in the neutral value so an adapter can
    prove that the requirements were copied from the exact candidate record.
    """
    expected = compute_framed_digest(
        "asago-scenario-generator:execution-requirements:v1",
        [item.model_dump(mode="json") for item in requirements],
    )
    if supplied != expected:
        raise ValueError("execution_requirements_digest does not match requirements")


def _require_causal_identity_nodes(
    projection: CausalProjection, nodes_by_id: dict[str, CausalNode]
) -> None:
    """Require every exact STPA identity to have its declared node kind."""
    _require_causal_identity_group(
        projection.loss_ids, "loss", nodes_by_id, "causal loss identity"
    )
    _require_causal_identity_group(
        projection.hazard_ids, "hazard", nodes_by_id, "causal hazard identity"
    )
    _require_causal_identity_group(
        projection.constraint_ids,
        "constraint",
        nodes_by_id,
        "causal constraint identity",
    )
    controller_kind, action_kind = _causal_identity_kinds(projection)
    _require_causal_identity_group(
        (
            projection.controller_id,
            projection.control_action_id,
            projection.uca_slot_id,
            projection.ica_id,
            projection.exec_candidate_id,
        ),
        (controller_kind, action_kind, "uca", "ica", "exec"),
        nodes_by_id,
        "causal structural identity",
    )
    _require_single_exec_node(projection, nodes_by_id)


def _require_single_exec_node(
    projection: CausalProjection, nodes_by_id: dict[str, CausalNode]
) -> None:
    """Require exactly one EXEC node and the exact projected identity."""
    exec_nodes = [node for node in nodes_by_id.values() if node.kind == "exec"]
    if len(exec_nodes) != 1 or exec_nodes[0].node_id != projection.exec_candidate_id:
        raise ValueError("causal projection requires one exact exec node")


def _causal_identity_kinds(
    projection: CausalProjection,
) -> tuple[
    Literal["controller", "coordination_link"],
    Literal["control_action", "coordination_mechanism"],
]:
    """Select the structural node namespaces from the exact CL/CM identity."""
    coordination = projection.controller_id.startswith("CL-")
    mechanism = projection.control_action_id.startswith("CM-")
    if coordination != mechanism:
        raise ValueError("coordination identities must use CL/CM namespaces together")
    if coordination:
        return "coordination_link", "coordination_mechanism"
    return "controller", "control_action"


def _require_causal_identity_group(
    identifiers: Sequence[str],
    expected_kind: str | tuple[str, ...],
    nodes_by_id: dict[str, CausalNode],
    label: str,
) -> None:
    """Require a group of identities to resolve to their declared node kinds."""
    expected_kinds = _identity_kinds_for_group(expected_kind, len(identifiers))
    for identifier, expected in zip(identifiers, expected_kinds, strict=True):
        _require_identity_node(identifier, expected, nodes_by_id, label)


def _identity_kinds_for_group(
    expected_kind: str | tuple[str, ...], identifier_count: int
) -> tuple[str, ...]:
    """Expand one or many expected kinds to the identity-group length."""
    kinds = (expected_kind,) if isinstance(expected_kind, str) else expected_kind
    if len(kinds) not in {1, identifier_count}:
        raise ValueError("causal identity group has inconsistent kinds")
    return kinds * identifier_count if len(kinds) == 1 else kinds


def _require_identity_node(
    identifier: str,
    expected_kind: str,
    nodes_by_id: dict[str, CausalNode],
    label: str,
) -> None:
    """Require one exact node identity and kind."""
    node = nodes_by_id.get(identifier)
    if node is None or node.kind != expected_kind:
        raise ValueError(f"{label} is missing or wrong-kind")


def _require_causal_edges(
    projection: CausalProjection,
    nodes: Sequence[CausalNode],
    edges: Sequence[CausalEdge],
    nodes_by_id: dict[str, CausalNode],
) -> None:
    """Validate local edge endpoints, kinds, and authoritative order."""
    semantic: set[tuple[str, str, str]] = set()
    for edge in edges:
        _validate_causal_edge(edge, nodes_by_id, semantic)
    _require_terminal_exec(nodes, edges)
    trace_edges = {
        (
            nodes_by_id[edge.from_node_id].kind,
            nodes_by_id[edge.to_node_id].kind,
            edge.from_node_id,
            edge.to_node_id,
        )
        for edge in edges
    }
    _require_projection_trace(projection, nodes_by_id, trace_edges)


def _validate_causal_edge(
    edge: CausalEdge,
    nodes_by_id: dict[str, CausalNode],
    semantic: set[tuple[str, str, str]],
) -> None:
    """Validate one edge against local kinds, order, and uniqueness."""
    source = nodes_by_id.get(edge.from_node_id)
    target = nodes_by_id.get(edge.to_node_id)
    if source is None or target is None:
        raise ValueError("causal edge references a dangling node")
    if (source.kind, target.kind) not in _PROJECTION_EDGE_KINDS[edge.kind]:
        raise ValueError("causal edge has an invalid source/target kind")
    if source.ordinal >= target.ordinal:
        raise ValueError("causal edge reverses authoritative node order")
    key = (edge.from_node_id, edge.to_node_id, edge.kind)
    if key in semantic:
        raise ValueError("causal edges must be semantically unique")
    semantic.add(key)


def _require_terminal_exec(
    nodes: Sequence[CausalNode], edges: Sequence[CausalEdge]
) -> None:
    """Require that the single EXEC node has no outgoing edge."""
    outgoing = {edge.from_node_id for edge in edges}
    exec_ids = {node.node_id for node in nodes if node.kind == "exec"}
    if exec_ids & outgoing:
        raise ValueError("exec node must be terminal")


def _require_projection_trace(
    projection: CausalProjection,
    nodes_by_id: dict[str, CausalNode],
    edges: set[tuple[str, str, str, str]],
) -> None:
    """Require one loss-to-exec projection path through the exact identities."""
    structural_kinds = _causal_trace_kinds(nodes_by_id)
    _require_base_projection_trace(edges)
    _require_structural_projection_trace(edges, structural_kinds)
    _require_declared_context_paths(projection, edges)


def _require_declared_context_paths(
    projection: CausalProjection,
    edges: set[tuple[str, str, str, str]],
) -> None:
    """Require every declared loss-path identity to join the ordered trace."""
    forward = _causal_adjacency(edges)
    reverse = _causal_adjacency(edges, reverse=True)
    reaches_exec = _reachable_ids(projection.exec_candidate_id, reverse)
    reachable_from_loss: set[str] = set()
    for loss_id in projection.loss_ids:
        reachable_from_loss.update(_reachable_ids(loss_id, forward))
    _require_context_path_group(
        projection.loss_ids,
        reaches_exec,
        None,
        "loss",
    )
    _require_context_path_group(
        projection.hazard_ids,
        reaches_exec,
        reachable_from_loss,
        "hazard",
    )
    _require_context_path_group(
        projection.constraint_ids,
        reaches_exec,
        reachable_from_loss,
        "constraint",
    )


def _causal_adjacency(
    edges: set[tuple[str, str, str, str]],
    *,
    reverse: bool = False,
) -> dict[str, tuple[str, ...]]:
    """Build a deterministic node adjacency map from typed causal edges."""
    collected: dict[str, set[str]] = {}
    for _source_kind, _target_kind, source, target in edges:
        origin, destination = (target, source) if reverse else (source, target)
        collected.setdefault(origin, set()).add(destination)
    return {node_id: tuple(sorted(children)) for node_id, children in collected.items()}


def _reachable_ids(start: str, adjacency: dict[str, tuple[str, ...]]) -> set[str]:
    """Return all nodes reachable from one causal identity."""
    pending = [start]
    reached: set[str] = set()
    while pending:
        current = pending.pop()
        if current in reached:
            continue
        reached.add(current)
        pending.extend(adjacency.get(current, ()))
    return reached


def _require_context_path_group(
    identifiers: Sequence[str],
    reaches_exec: set[str],
    reachable_from_loss: set[str] | None,
    label: str,
) -> None:
    """Reject a declared context identity outside the ordered loss path."""
    for identifier in identifiers:
        if identifier not in reaches_exec or (
            reachable_from_loss is not None and identifier not in reachable_from_loss
        ):
            raise ValueError(
                f"declared {label} identity is not on the ordered causal path"
            )


def _require_base_projection_trace(
    edges: set[tuple[str, str, str, str]],
) -> None:
    """Require the invariant loss/hazard/constraint/UCA/ICA/EXEC chain."""
    required_pairs = (
        ("loss", "hazard"),
        ("hazard", "constraint"),
        ("uca", "ica"),
        ("ica", "exec"),
    )
    if any(
        not _has_causal_edge(edges, source, target) for source, target in required_pairs
    ):
        raise ValueError("causal projection is missing a complete loss-to-exec trace")


def _require_structural_projection_trace(
    edges: set[tuple[str, str, str, str]],
    structural_kinds: tuple[str, str],
) -> None:
    """Require the exact controller/action namespace path."""
    controller_kind, action_kind = structural_kinds
    if not _has_causal_edge(edges, "constraint", controller_kind):
        raise ValueError("causal projection is missing its structural controller trace")
    if not _has_control_action_trace(edges, controller_kind, action_kind):
        raise ValueError("causal projection is missing the control-action trace")


def _has_control_action_trace(
    edges: set[tuple[str, str, str, str]],
    controller_kind: str,
    action_kind: str,
) -> bool:
    """Accept either direct or controller-mediated action reachability."""
    action_reaches_uca = _has_causal_edge(edges, action_kind, "uca")
    direct = _has_causal_edge(edges, "constraint", action_kind)
    via_controller = _has_causal_edge(edges, controller_kind, action_kind)
    return action_reaches_uca and (direct or via_controller)


def _has_causal_edge(
    edges: set[tuple[str, str, str, str]], source_kind: str, target_kind: str
) -> bool:
    """Return whether the local graph includes a typed edge pair."""
    return any(
        source == source_kind and target == target_kind
        for source, target, _from, _to in edges
    )


def _causal_trace_kinds(
    nodes_by_id: dict[str, CausalNode],
) -> tuple[
    Literal["controller", "coordination_link"],
    Literal["control_action", "coordination_mechanism"],
]:
    """Resolve the one structural namespace pair present in a projection."""
    controller_kinds = {"controller", "coordination_link"}
    action_kinds = {"control_action", "coordination_mechanism"}
    present = {node.kind for node in nodes_by_id.values()}
    controller = tuple(sorted(present & controller_kinds))
    action = tuple(sorted(present & action_kinds))
    if len(controller) != 1 or len(action) != 1:
        raise ValueError(
            "causal projection must contain one controller/action namespace"
        )
    return controller[0], action[0]


def _require_acyclic(edges: Sequence[CausalEdge]) -> None:
    """Reject cycles in the local causal graph."""
    adjacency: dict[str, list[str]] = {}
    for edge in edges:
        adjacency.setdefault(edge.from_node_id, []).append(edge.to_node_id)
    visiting: set[str] = set()
    visited: set[str] = set()
    for node_id in adjacency:
        _visit_acyclic(node_id, adjacency, visiting, visited)


def _visit_acyclic(
    node_id: str,
    adjacency: dict[str, list[str]],
    visiting: set[str],
    visited: set[str],
) -> None:
    """Depth-first cycle check for one local causal node."""
    if node_id in visiting:
        raise ValueError("causal projection contains a cycle")
    if node_id in visited:
        return
    visiting.add(node_id)
    for child in adjacency.get(node_id, ()):
        _visit_acyclic(child, adjacency, visiting, visited)
    visiting.remove(node_id)
    visited.add(node_id)


def _canonical_stpa_projections(
    projections: Sequence[CausalProjection],
) -> tuple[CausalProjection, ...]:
    """Sort causal projections and reject duplicate projection identities."""
    ordered = tuple(
        sorted(
            projections,
            key=lambda item: (
                item.causal_projection_id,
                item.ica_id,
                item.exec_candidate_id,
            ),
        )
    )
    _require_unique(
        (item.causal_projection_id for item in ordered),
        "STPA projections must have unique causal projection identities",
    )
    return ordered


def _complete_stpa_source_pins(
    attestation: PinnedStpaProjectionAttestation,
) -> tuple[ProjectionSourcePin, ...]:
    """Retain every caller pin and add the four mandatory STPA leaf pins."""
    pins = tuple(sorted(attestation.source_pins, key=_source_pin_key))
    required = (
        attestation.loss_analysis_pin,
        attestation.control_structure_pin,
        attestation.ica_enumeration_pin,
        attestation.execution_projection_pin,
    )
    for pin in required:
        wrapped = ArtifactProjectionSourcePin.from_artifact_pin(pin)
        if wrapped not in pins:
            pins = tuple(sorted((*pins, wrapped), key=_source_pin_key))
    return pins


def _canonical_correspondence_relations(
    relations: Sequence[AcceptedCorrespondenceRelation],
) -> tuple[AcceptedCorrespondenceRelation, ...]:
    """Sort accepted relations and reject duplicate relation identities."""
    ordered = tuple(sorted(relations, key=lambda item: item.relation_id))
    _require_unique(
        (item.relation_id for item in ordered),
        "accepted correspondence relation IDs must be unique",
    )
    return ordered


class PinnedStpaProjectionAttestation(_ProjectionModel):
    """Verified wrapper around exact STPA projection authorities."""

    schema_version: Literal[PINNED_STPA_PROJECTION_ATTESTATION_SCHEMA_VERSION] = (
        PINNED_STPA_PROJECTION_ATTESTATION_SCHEMA_VERSION
    )
    loss_analysis_pin: ArtifactPin
    control_structure_pin: ArtifactPin
    ica_enumeration_pin: ArtifactPin
    execution_projection_pin: ArtifactPin
    projections: tuple[CausalProjection, ...] = ()
    source_pins: tuple[ProjectionSourcePin, ...] = Field(min_length=1)
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "PinnedStpaProjectionAttestation":
        projections = _canonical_stpa_projections(self.projections)
        pins = _complete_stpa_source_pins(self)
        object.__setattr__(self, "projections", projections)
        object.__setattr__(self, "source_pins", pins)
        _set_verified_digest(
            self,
            _STPA_ATTESTATION_DIGEST_DOMAIN,
            "STPA attestation semantic_digest",
        )
        return self

    def assert_integrity(self) -> None:
        """Verify every neutral projection and wrapper digest."""
        for projection in self.projections:
            projection.assert_integrity()
        if self.semantic_digest != _semantic_digest(
            self, _STPA_ATTESTATION_DIGEST_DOMAIN
        ):
            raise ValueError("STPA attestation semantic digest mismatch")


class HybridCorrespondenceAttestation(_ProjectionModel):
    """Verified Phase 2 accepted-relation authority."""

    schema_version: Literal[HYBRID_CORRESPONDENCE_ATTESTATION_SCHEMA_VERSION] = (
        HYBRID_CORRESPONDENCE_ATTESTATION_SCHEMA_VERSION
    )
    proposal_set_pin: ArtifactPin
    proposal_set_digest: Digest
    reconciliation_pin: ArtifactPin
    reconciliation_digest: Digest
    accepted_relations: tuple[AcceptedCorrespondenceRelation, ...] = ()
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "HybridCorrespondenceAttestation":
        relations = _canonical_correspondence_relations(self.accepted_relations)
        object.__setattr__(self, "accepted_relations", relations)
        _set_verified_digest(
            self,
            _CORRESPONDENCE_ATTESTATION_DIGEST_DOMAIN,
            "correspondence attestation semantic_digest",
        )
        return self

    def assert_integrity(self) -> None:
        """Verify the attestation content and every accepted relation."""
        for relation in self.accepted_relations:
            type(relation).model_validate(relation.model_dump(mode="python"))
        if self.semantic_digest != _semantic_digest(
            self, _CORRESPONDENCE_ATTESTATION_DIGEST_DOMAIN
        ):
            raise ValueError("correspondence attestation semantic digest mismatch")


class ConfirmedCoverageReview(_ProjectionModel):
    """Independent typed confirmation of one accepted relation."""

    schema_version: Literal[CONFIRMED_COVERAGE_REVIEW_SCHEMA_VERSION] = (
        CONFIRMED_COVERAGE_REVIEW_SCHEMA_VERSION
    )
    relation_id: RelationId
    adjudication: Literal["confirmed"] = "confirmed"
    reviewer_id: Identifier
    review_artifact_pin: ArtifactPin
    review_artifact_digest: Digest
    mechanism_evidence: "MechanismEvidenceAttestation"
    source_pins: tuple[ProjectionSourcePin, ...] = Field(min_length=1)
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "ConfirmedCoverageReview":
        _validate_review_artifact_pin(self)
        _validate_independent_mechanism_evidence(self)
        pins = _complete_review_source_pins(self)
        object.__setattr__(self, "source_pins", pins)
        _set_verified_digest(
            self, _REVIEW_DIGEST_DOMAIN, "confirmed review semantic_digest"
        )
        return self

    def assert_integrity(self) -> None:
        """Verify the independently pinned review record."""
        if self.semantic_digest != _semantic_digest(self, _REVIEW_DIGEST_DOMAIN):
            raise ValueError("confirmed review semantic digest mismatch")


def _validate_review_artifact_pin(review: ConfirmedCoverageReview) -> None:
    """Require the review wrapper to retain the pin's exact digest."""
    if review.review_artifact_pin.semantic_digest != review.review_artifact_digest:
        raise ValueError("review artifact pin and digest do not agree")


def _set_verified_digest(model: BaseModel, domain: str, label: str) -> None:
    """Validate and store one derived semantic digest on a model."""
    expected = _semantic_digest(model, domain)
    _validate_optional_derived_value(
        getattr(model, "semantic_digest", None), expected, label
    )
    object.__setattr__(model, "semantic_digest", expected)


def _validate_independent_mechanism_evidence(
    review: ConfirmedCoverageReview,
) -> None:
    """Require mechanism evidence to be independent from the review artifact."""
    if review.mechanism_evidence.artifact_pin == review.review_artifact_pin:
        raise ValueError("mechanism evidence must be independent of review evidence")


def _complete_review_source_pins(
    review: ConfirmedCoverageReview,
) -> tuple[ProjectionSourcePin, ...]:
    """Retain both independently required review source pins."""
    pins = tuple(sorted(review.source_pins, key=_source_pin_key))
    required = (
        ArtifactProjectionSourcePin.from_artifact_pin(
            review.review_artifact_pin, role="review"
        ),
        ArtifactProjectionSourcePin.from_artifact_pin(
            review.mechanism_evidence.artifact_pin, role="mechanism-evidence"
        ),
    )
    for pin in required:
        if pin not in pins:
            pins = tuple(sorted((*pins, pin), key=_source_pin_key))
    return pins


class MechanismEvidenceAttestation(_ProjectionModel):
    """Independent exact evidence used to support one confirmed review."""

    schema_version: Literal["mechanism-evidence-attestation-v1"] = (
        "mechanism-evidence-attestation-v1"
    )
    artifact_pin: ArtifactPin
    record_id: Identifier
    evidence_kind: Literal["exact_id", "curated_mechanism_mapping"]
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def verify_digest(self) -> "MechanismEvidenceAttestation":
        expected = _semantic_digest(self, "asago.mechanism-evidence-attestation.v1")
        _validate_optional_derived_value(
            self.semantic_digest,
            expected,
            "mechanism evidence attestation digest",
        )
        object.__setattr__(self, "semantic_digest", expected)
        return self

    def assert_integrity(self) -> None:
        """Verify the exact independent evidence attestation."""
        if self.semantic_digest != _semantic_digest(
            self, "asago.mechanism-evidence-attestation.v1"
        ):
            raise ValueError("mechanism evidence attestation digest mismatch")


ConfirmedCoverageReview.model_rebuild()


BridgeKind = Literal[
    "corrupts_process_model",
    "delays_feedback",
    "perturbs_control_action",
    "enables_unsafe_action",
    "realizes_unsafe_outcome",
]


class TaxonomyEndpoint(_ProjectionModel):
    """Closed taxonomy endpoint for a bridge link."""

    namespace: Literal["taxonomy"] = "taxonomy"
    kind: Literal["mechanism_step", "mechanism_precondition", "mechanism_postcondition"]
    record_id: Identifier


class StpaEndpoint(_ProjectionModel):
    """Closed STPA endpoint for a bridge link."""

    namespace: Literal["stpa"] = "stpa"
    kind: Literal[
        "process_model",
        "feedback",
        "control_action",
        "uca",
        "ica",
        "hazard",
        "loss",
    ]
    record_id: Identifier


class BridgeAuthorityIdentity(_ProjectionModel):
    """Reviewer or curator identity authorizing one bridge evidence record."""

    kind: Literal["reviewer", "curator"]
    id: Identifier


class BridgeEvidence(_ProjectionModel):
    """One exact reviewed/curated bridge evidence record."""

    schema_version: Literal[HYBRID_BRIDGE_EVIDENCE_SCHEMA_VERSION] = (
        HYBRID_BRIDGE_EVIDENCE_SCHEMA_VERSION
    )
    evidence_id: str = ""
    artifact_pin: ArtifactPin
    record_id: Identifier
    evidence_kind: Literal[
        "exact_taxonomy_record",
        "exact_stpa_record",
        "operator_bridge_review",
        "curated_bridge_mapping",
    ]
    provenance: Literal["operator_declared", "curated"]
    authority_identity: BridgeAuthorityIdentity
    rationale: str = Field(min_length=1)
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def verify_authority(self) -> "BridgeEvidence":
        _validate_bridge_authority(self.provenance, self.authority_identity.kind)
        _validate_bridge_evidence_kind(self.provenance, self.evidence_kind)
        expected_id = _derive_id(
            self, "bridge-evidence:v1:", _BRIDGE_EVIDENCE_DIGEST_DOMAIN, "evidence_id"
        )
        if self.evidence_id and self.evidence_id != expected_id:
            raise ValueError("bridge evidence ID does not match content")
        object.__setattr__(self, "evidence_id", expected_id)
        expected_digest = _semantic_digest(self, _BRIDGE_EVIDENCE_DIGEST_DOMAIN)
        if self.semantic_digest is not None and self.semantic_digest != expected_digest:
            raise ValueError("bridge evidence digest does not match content")
        object.__setattr__(self, "semantic_digest", expected_digest)
        return self

    def assert_integrity(self) -> None:
        """Verify that this bridge evidence has not been substituted."""
        if self.semantic_digest != _semantic_digest(
            self, _BRIDGE_EVIDENCE_DIGEST_DOMAIN
        ):
            raise ValueError("bridge evidence semantic digest mismatch")


def _validate_bridge_authority(provenance: str, authority_kind: str) -> None:
    """Require the authority identity appropriate for the evidence provenance."""
    expected = {"operator_declared": "reviewer", "curated": "curator"}[provenance]
    if authority_kind != expected:
        label = "operator-declared" if provenance == "operator_declared" else "curated"
        raise ValueError(f"{label} bridge evidence requires a {expected}")


def _validate_bridge_evidence_kind(provenance: str, evidence_kind: str) -> None:
    """Require an evidence kind allowed by its provenance."""
    allowed = {
        "operator_declared": {
            "operator_bridge_review",
            "exact_taxonomy_record",
            "exact_stpa_record",
        },
        "curated": {
            "curated_bridge_mapping",
            "exact_taxonomy_record",
            "exact_stpa_record",
        },
    }[provenance]
    if evidence_kind not in allowed:
        raise ValueError(
            f"{provenance.replace('_', '-')} evidence kind is not supported"
        )


class BridgeLink(_ProjectionModel):
    """Explicit taxonomy-to-STPA bridge accepted by the Task 1 boundary."""

    schema_version: Literal[HYBRID_BRIDGE_LINK_SCHEMA_VERSION] = (
        HYBRID_BRIDGE_LINK_SCHEMA_VERSION
    )
    bridge_id: str = ""
    relation_id: RelationId
    bridge_kind: BridgeKind
    taxonomy_endpoint: TaxonomyEndpoint
    stpa_endpoint: StpaEndpoint
    evidence: tuple[BridgeEvidence, ...] = Field(min_length=1)
    source_pins: tuple[ProjectionSourcePin, ...] = Field(min_length=1)
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def verify_and_identify(self) -> "BridgeLink":
        evidence = tuple(sorted(self.evidence, key=lambda item: item.evidence_id))
        _require_unique(
            (item.evidence_id for item in evidence),
            "bridge evidence IDs must be unique",
        )
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(
            self,
            "source_pins",
            tuple(sorted(self.source_pins, key=_source_pin_key)),
        )
        expected_id = _derive_id(
            self, "bridge:v1:", _BRIDGE_LINK_DIGEST_DOMAIN, "bridge_id"
        )
        if self.bridge_id and self.bridge_id != expected_id:
            raise ValueError("bridge ID does not match content")
        object.__setattr__(self, "bridge_id", expected_id)
        expected_digest = _semantic_digest(self, _BRIDGE_LINK_DIGEST_DOMAIN)
        if self.semantic_digest is not None and self.semantic_digest != expected_digest:
            raise ValueError("bridge link semantic_digest does not match content")
        object.__setattr__(self, "semantic_digest", expected_digest)
        return self

    @property
    def is_authorized(self) -> bool:
        """Return whether evidence contains an operator/curator bridge claim."""
        return any(
            item.evidence_kind in {"operator_bridge_review", "curated_bridge_mapping"}
            and item.provenance in {"operator_declared", "curated"}
            for item in self.evidence
        )

    def assert_integrity(self) -> None:
        """Verify the link and every nested evidence record."""
        for evidence in self.evidence:
            evidence.assert_integrity()
        if self.semantic_digest != _semantic_digest(self, _BRIDGE_LINK_DIGEST_DOMAIN):
            raise ValueError("bridge link semantic digest mismatch")


ExclusionReason = Literal[
    "relation_not_accepted",
    "relation_not_coverage",
    "related_but_not_coverage",
    "relation_unresolved",
    "relation_contradictory",
    "challenge_outcome_not_correspondence",
    "obligation_not_applicable",
    "candidate_materialization_missing",
    "candidate_not_projectable",
    "candidate_binding_mismatch",
    "stpa_identity_missing",
    "stpa_identity_mismatch",
    "resource_link_mismatch",
    "bridge_missing",
    "bridge_unreviewed",
    "bridge_not_authoritative",
    "bridge_invalid_endpoint",
    "bridge_duplicate",
    "ordering_cycle",
    "ordering_violation",
]


class ProjectionTraceReference(_ProjectionModel):
    """One exact source record retained by a projection or exclusion."""

    source_kind: Literal[
        "phase1_obligation",
        "phase1_candidate",
        "phase2_relation",
        "stpa_loss",
        "stpa_hazard",
        "stpa_constraint",
        "stpa_slot",
        "stpa_ica",
        "stpa_exec",
        "bridge_evidence",
    ]
    record_id: Identifier
    artifact_pin: ArtifactPin


class ProjectionExclusion(_ProjectionModel):
    """A typed relation-local omission, never a projection or coverage claim."""

    exclusion_id: str = ""
    relation_id: RelationId
    unit_identity: tuple[str, str, str, str, str]
    reason: ExclusionReason
    source_pins: tuple[ProjectionSourcePin, ...] = ()
    trace: tuple[ProjectionTraceReference, ...] = ()

    @model_validator(mode="after")
    def verify_and_identify(self) -> "ProjectionExclusion":
        if len(self.unit_identity) != 5:
            raise ValueError("exclusion unit identity must contain five members")
        if self.unit_identity[0] != self.relation_id:
            raise ValueError("exclusion unit identity must retain relation_id")
        object.__setattr__(
            self, "source_pins", tuple(sorted(self.source_pins, key=_source_pin_key))
        )
        expected = _derive_id(
            self, "exclusion:v1:", _PROJECTION_SET_DIGEST_DOMAIN, "exclusion_id"
        )
        if self.exclusion_id and self.exclusion_id != expected:
            raise ValueError("exclusion ID does not match content")
        object.__setattr__(self, "exclusion_id", expected)
        return self


class ProjectionDiagnostic(_ProjectionModel):
    """A traceable diagnostic that does not count as a projection."""

    diagnostic_id: str = ""
    relation_id: RelationId | None = None
    kind: Literal[
        "bridge_unreviewed",
        "bridge_not_authoritative",
        "challenge_outcome_not_correspondence",
    ]
    source_pins: tuple[ProjectionSourcePin, ...] = ()
    trace: tuple[ProjectionTraceReference, ...] = ()

    @model_validator(mode="after")
    def verify_and_identify(self) -> "ProjectionDiagnostic":
        object.__setattr__(
            self, "source_pins", tuple(sorted(self.source_pins, key=_source_pin_key))
        )
        expected = _derive_id(
            self, "diagnostic:v1:", _PROJECTION_SET_DIGEST_DOMAIN, "diagnostic_id"
        )
        if self.diagnostic_id and self.diagnostic_id != expected:
            raise ValueError("diagnostic ID does not match content")
        object.__setattr__(self, "diagnostic_id", expected)
        return self


class HybridProjectionUnit(_ProjectionModel):
    """One fully resolved, but not yet bridge-composed, projection unit.

    Task 1 returns these units as the result of exact authority resolution.
    The final ``HybridScenarioProjection`` is deliberately left to Task 2,
    which owns bridge validation and union-graph composition.
    """

    schema_version: Literal["hybrid-projection-unit-v1"] = "hybrid-projection-unit-v1"
    unit_id: str = ""
    relation_id: RelationId
    obligation_id: ObligationId
    risk_id: Identifier
    attack_pattern_id: Identifier
    selected_candidate_id: CandidateId
    ica_slot_id: Identifier
    ica_id: Identifier
    exec_candidate_id: ExecCandidateId
    relation_kind: CorrespondenceRelationKind
    evidence_class: Literal[
        "normative_bookkeeping_fixture", "reviewed_semantic_evidence"
    ]
    mechanism_projection: MechanismProjection
    causal_projection: CausalProjection
    confirmed_review: ConfirmedCoverageReview
    bridge_links: tuple[BridgeLink, ...] = ()
    source_pins: tuple[ProjectionSourcePin, ...] = Field(min_length=1)
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def verify_and_identify(self) -> "HybridProjectionUnit":
        _validate_unit_identity(self)
        _validate_unit_bridges(self)
        _canonical_unit_values(self)
        _set_unit_identity(self)
        _set_unit_digest(self)
        return self

    def assert_integrity(self) -> None:
        """Verify this resolved unit and all embedded neutral values."""
        self.mechanism_projection.assert_integrity()
        self.causal_projection.assert_integrity()
        self.confirmed_review.assert_integrity()
        if self.semantic_digest != _semantic_digest(self, _PROJECTION_DIGEST_DOMAIN):
            raise ValueError("hybrid unit semantic digest mismatch")


def _validate_unit_identity(unit: HybridProjectionUnit) -> None:
    """Require mechanism, causal, and review identities to agree."""
    _validate_unit_mechanism_identity(unit)
    _validate_unit_causal_identity(unit)
    if unit.confirmed_review.relation_id != unit.relation_id:
        raise ValueError("hybrid unit review does not match relation")


def _validate_unit_mechanism_identity(unit: HybridProjectionUnit) -> None:
    """Require mechanism and unit identities to agree."""
    mechanism = unit.mechanism_projection
    if any(
        expected != actual
        for expected, actual in (
            (unit.obligation_id, mechanism.obligation_id),
            (unit.attack_pattern_id, mechanism.attack_pattern_id),
            (unit.selected_candidate_id, mechanism.selected_candidate_id),
        )
    ):
        raise ValueError("hybrid unit mechanism identity does not match")


def _validate_unit_causal_identity(unit: HybridProjectionUnit) -> None:
    """Require causal slot/ICA/EXEC identities to agree with the unit."""
    causal = unit.causal_projection
    if any(
        expected != actual
        for expected, actual in (
            (unit.ica_slot_id, causal.uca_slot_id),
            (unit.ica_id, causal.ica_id),
            (unit.exec_candidate_id, causal.exec_candidate_id),
        )
    ):
        raise ValueError("hybrid unit causal identity does not match")


def _validate_unit_bridges(unit: HybridProjectionUnit) -> None:
    """Require every bridge in one unit to name its relation."""
    if any(item.relation_id != unit.relation_id for item in unit.bridge_links):
        raise ValueError("hybrid unit bridge does not match relation")


def _canonical_unit_values(unit: HybridProjectionUnit) -> None:
    """Canonicalize the ordered bridge and source-pin collections."""
    object.__setattr__(
        unit,
        "bridge_links",
        tuple(
            sorted(
                unit.bridge_links,
                key=lambda item: (item.bridge_kind, item.bridge_id),
            )
        ),
    )
    object.__setattr__(
        unit, "source_pins", tuple(sorted(unit.source_pins, key=_source_pin_key))
    )


def _set_unit_identity(unit: HybridProjectionUnit) -> None:
    """Derive and validate the content-addressed unit identity."""
    expected = _derive_id(unit, "unit:v1:", _PROJECTION_DIGEST_DOMAIN, "unit_id")
    if unit.unit_id and unit.unit_id != expected:
        raise ValueError("hybrid unit ID does not match content")
    object.__setattr__(unit, "unit_id", expected)


def _set_unit_digest(unit: HybridProjectionUnit) -> None:
    """Derive and validate the complete unit semantic digest."""
    expected = _semantic_digest(unit, _PROJECTION_DIGEST_DOMAIN)
    if unit.semantic_digest is not None and unit.semantic_digest != expected:
        raise ValueError("hybrid unit semantic digest does not match content")
    object.__setattr__(unit, "semantic_digest", expected)


class HybridProjectionResolution(_ProjectionModel):
    """Task 1 result: exact units plus typed relation-local omissions."""

    schema_version: Literal["hybrid-projection-resolution-v1"] = (
        "hybrid-projection-resolution-v1"
    )
    assessment_digest: Digest
    evidence_class: Literal[
        "normative_bookkeeping_fixture", "reviewed_semantic_evidence"
    ]
    source_pins: tuple[ProjectionSourcePin, ...] = Field(min_length=1)
    units: tuple[HybridProjectionUnit, ...] = ()
    exclusions: tuple[ProjectionExclusion, ...] = ()
    diagnostics: tuple[ProjectionDiagnostic, ...] = ()
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "HybridProjectionResolution":
        _canonical_resolution_values(self)
        _validate_resolution_collections(self)
        _set_resolution_digest(self)
        return self

    def assert_integrity(self) -> None:
        """Verify all resolved units and the enclosing digest."""
        for unit in self.units:
            unit.assert_integrity()
        if self.semantic_digest != _semantic_digest(
            self, "asago.hybrid-projection-resolution.v1"
        ):
            raise ValueError("hybrid projection resolution digest mismatch")


def _canonical_resolution_values(value: HybridProjectionResolution) -> None:
    """Canonicalize all ordered resolution collections and source pins."""
    units = tuple(
        sorted(
            value.units,
            key=lambda item: (
                item.relation_id,
                item.obligation_id,
                item.selected_candidate_id,
                item.ica_id,
                item.exec_candidate_id,
            ),
        )
    )
    exclusions = tuple(
        sorted(
            value.exclusions,
            key=lambda item: (item.relation_id, item.reason, item.exclusion_id),
        )
    )
    diagnostics = tuple(
        sorted(
            value.diagnostics,
            key=lambda item: (
                item.relation_id or "",
                item.kind,
                item.diagnostic_id,
            ),
        )
    )
    object.__setattr__(value, "units", units)
    object.__setattr__(value, "exclusions", exclusions)
    object.__setattr__(value, "diagnostics", diagnostics)
    object.__setattr__(
        value, "source_pins", tuple(sorted(value.source_pins, key=_source_pin_key))
    )


def _validate_resolution_collections(value: HybridProjectionResolution) -> None:
    """Require unique IDs and one evidence class across resolved units."""
    _validate_resolution_ids(value)
    _validate_resolution_evidence_classes(value)


def _validate_resolution_ids(value: HybridProjectionResolution) -> None:
    """Require unique IDs in each resolution collection."""
    _require_unique(
        (item.relation_id for item in value.units),
        "resolved units must have unique relation IDs",
    )
    _require_unique(
        (item.exclusion_id for item in value.exclusions),
        "resolved exclusions must have unique IDs",
    )
    _require_unique(
        (item.diagnostic_id for item in value.diagnostics),
        "resolved diagnostics must have unique IDs",
    )


def _validate_resolution_evidence_classes(
    value: HybridProjectionResolution,
) -> None:
    """Require every resolved unit to use the envelope evidence class."""
    if any(item.evidence_class != value.evidence_class for item in value.units):
        raise ValueError("resolved unit evidence classes must be homogeneous")


def _set_resolution_digest(value: HybridProjectionResolution) -> None:
    """Derive and validate the complete resolution semantic digest."""
    expected = _semantic_digest(value, "asago.hybrid-projection-resolution.v1")
    if value.semantic_digest is not None and value.semantic_digest != expected:
        raise ValueError("hybrid projection resolution digest does not match content")
    object.__setattr__(value, "semantic_digest", expected)


__all__ = [
    "ArtifactProjectionSourcePin",
    "BridgeAuthorityIdentity",
    "BridgeEvidence",
    "BridgeKind",
    "BridgeLink",
    "CandidateId",
    "CausalEdge",
    "CausalNode",
    "CausalProjection",
    "CapabilityFactAttestation",
    "ConfirmedCoverageReview",
    "ExecCandidateId",
    "HybridCorrespondenceAttestation",
    "HybridProjectionResolution",
    "HybridProjectionUnit",
    "MechanismProjection",
    "MechanismEvidenceAttestation",
    "ProjectionDiagnostic",
    "ProjectionExclusion",
    "ProjectionSourcePin",
    "ProjectionTraceReference",
    "PinnedStpaProjectionAttestation",
    "StpaEndpoint",
    "TaxonomyEndpoint",
    "TaxonomyProjectionSourcePin",
    "CAUSAL_PROJECTION_SCHEMA_VERSION",
    "CONFIRMED_COVERAGE_REVIEW_SCHEMA_VERSION",
    "HYBRID_BRIDGE_EVIDENCE_SCHEMA_VERSION",
    "HYBRID_BRIDGE_LINK_SCHEMA_VERSION",
    "HYBRID_CORRESPONDENCE_ATTESTATION_SCHEMA_VERSION",
    "MECHANISM_PROJECTION_SCHEMA_VERSION",
    "PHASE1_CANDIDATE_RECORD_DIGEST_DOMAIN",
    "PINNED_STPA_PROJECTION_ATTESTATION_SCHEMA_VERSION",
    "STPA_EXECUTION_PROJECTION_DIGEST_DOMAIN",
]
