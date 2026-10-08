"""Typed inputs for the authoritative taxonomy-obligation planner.

The planner consumes this module's immutable input graph.  Risk cards and
qualification facts validate directly into their persisted
:mod:`models.obligation_plan` records; this module adds the authoritative
pattern and capability objects needed to derive candidate records.
"""

from __future__ import annotations

from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.attack_pattern_contracts import (
    AuthoritativeFactReference,
    TaxonomyPin,
)
from asago_scenario_generator.models.obligation_plan import (
    QualificationFactEvidence,
    RiskReference,
)
from asago_scenario_generator.models.canonical import (
    FrozenDict,
    FrozenList,
    canonical_json_bytes,
    compute_framed_digest,
    normalize_unicode,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    CapabilityFactSnapshot,
    ProjectionBudget,
)


MAPPING_BUNDLE_DIGEST_DOMAIN = "asago-scenario-generator:obligation-mapping-bundle:v1"
_QUALIFICATION_FACTS_DIGEST_DOMAIN = "asago-scenario-generator:qualification-facts:v1"
_EXPECTED_MAPPING_PIN_KEYS = frozenset({"sssom", "obligation_edges"})


def _freeze_model_fields(value: BaseModel) -> BaseModel:
    """Freeze collections held by one already validated model."""
    for field_name in type(value).model_fields:
        current = getattr(value, field_name)
        frozen = _freeze_nested_collections(current)
        if frozen is not current:
            object.__setattr__(value, field_name, frozen)
    return value


def _freeze_mapping(value: dict[Any, Any]) -> FrozenDict:
    """Freeze one mapping and all values held by it."""
    return FrozenDict(
        {key: _freeze_nested_collections(item) for key, item in value.items()}
    )


def _freeze_sequence(
    value: list[Any] | tuple[Any, ...],
) -> FrozenList | tuple[Any, ...]:
    """Freeze one list or tuple while preserving its sequence shape."""
    frozen = tuple(_freeze_nested_collections(item) for item in value)
    return FrozenList(frozen) if isinstance(value, list) else frozen


def _freeze_set(value: set[Any] | frozenset[Any]) -> frozenset[Any]:
    """Freeze one set and all values held by it."""
    return frozenset(_freeze_nested_collections(item) for item in value)


def _freeze_nested_collections(value: Any) -> Any:
    """Recursively freeze collections in a validated snapshot copy."""
    if isinstance(value, (FrozenDict, FrozenList)):
        return value
    if isinstance(value, BaseModel):
        return _freeze_model_fields(value)
    if isinstance(value, dict):
        return _freeze_mapping(value)
    if isinstance(value, (list, tuple)):
        return _freeze_sequence(value)
    if isinstance(value, (set, frozenset)):
        return _freeze_set(value)
    return value


class _InputModel(BaseModel):
    """Common closed and immutable configuration for planner inputs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def normalize_input_strings(cls, value: Any) -> Any:
        """Apply the same NFC contract as persisted authoritative models."""
        return normalize_unicode(value, keep_models=True)


def _canonical_json(value: Any) -> str:
    """Use the neutral canonical encoder for typed fact normalization."""
    return canonical_json_bytes(value).decode("utf-8")


def _fact_item(value: Any, index: int) -> tuple[str, Any]:
    """Return the canonical key and payload for one qualification fact."""
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    if not isinstance(raw, dict):
        return str(index), raw
    reference = raw.get("fact")
    key = _canonical_json(reference) if reference is not None else str(index)
    return key, raw


def _facts_from_sequence(values: list[Any] | tuple[Any, ...]) -> dict[str, Any]:
    """Convert an evidence sequence into a unique canonical fact map."""
    facts: dict[str, Any] = {}
    for index, item in enumerate(values):
        key, raw = _fact_item(item, index)
        if key in facts:
            raise ValueError("qualification facts must be unique")
        facts[key] = raw
    return facts


def _normalize_fact_mapping(value: dict[str, Any]) -> dict[str, Any]:
    """Normalize mapping and sequence spellings accepted by the file adapter."""
    data = dict(value)
    if data.get("schema_version") == "1":
        data.pop("schema_version")
    raw_facts = data.get("facts")
    if isinstance(raw_facts, (list, tuple)):
        data["facts"] = _facts_from_sequence(raw_facts)
    elif "facts" not in data:
        data = {"facts": data}
    return data


def _input_mapping_edges(
    inputs: TaxonomyObligationInputs,
) -> list[tuple[str, str, str]]:
    """Return all canonical edge triples from both mapping vocabularies."""
    edges = [
        (item.source_id, item.target_id, item.relation)
        for item in inputs.cross_taxonomy_mappings
    ]
    edges.extend(
        (item.subject_id, item.object_id, item.predicate_id)
        for item in inputs.sssom_mappings
    )
    return edges


def _validate_unique_mapping_edges(edges: list[tuple[str, str, str]]) -> None:
    """Reject duplicate semantic edges regardless of their source vocabulary."""
    if len(edges) != len(set(edges)):
        raise ValueError("mapping edges must be semantically unique")


def _mapping_endpoints(
    edges: list[tuple[str, str, str]],
) -> tuple[set[str], set[str]]:
    """Return distinct sources and targets from one mapping graph."""
    return (
        {source for source, _target, _relation in edges},
        {target for _source, target, _relation in edges},
    )


def _raise_unknown_mapping_endpoints(
    label: str,
    values: set[str],
) -> None:
    """Reject a nonempty set of unknown mapping endpoint identifiers."""
    if values:
        raise ValueError(
            f"mapping {label} are not present in the authoritative graph: "
            + ", ".join(sorted(values))
        )


def _validate_mapping_targets(
    edges: list[tuple[str, str, str]],
    catalog_ids: set[str],
    risk_ids: set[str],
) -> None:
    """Reject mapping endpoints absent from the authoritative graph."""
    sources, targets = _mapping_endpoints(edges)
    _raise_unknown_mapping_endpoints(
        "sources", sources - (targets | risk_ids | catalog_ids)
    )
    _raise_unknown_mapping_endpoints(
        "targets", targets - (sources | risk_ids | catalog_ids)
    )


def _mapping_adjacency(
    edges: list[tuple[str, str, str]],
) -> dict[str, tuple[str, ...]]:
    """Build a deterministic adjacency map for graph validation."""
    adjacency: dict[str, tuple[str, ...]] = {}
    for source, target, _relation in edges:
        adjacency[source] = (*adjacency.get(source, ()), target)
    return adjacency


def _visit_mapping_graph(
    node: str,
    adjacency: dict[str, tuple[str, ...]],
    visiting: set[str],
    visited: set[str],
) -> None:
    """Visit one mapping graph node and reject recursion back-edges."""
    if node in visiting:
        raise ValueError("mapping graph must be acyclic")
    if node not in visited:
        visiting.add(node)
        for target in adjacency.get(node, ()):
            _visit_mapping_graph(target, adjacency, visiting, visited)
        visiting.remove(node)
        visited.add(node)


def _validate_acyclic_mapping_graph(edges: list[tuple[str, str, str]]) -> None:
    """Reject cycles in one combined cross-taxonomy/SSSOM graph."""
    adjacency = _mapping_adjacency(edges)
    visiting: set[str] = set()
    visited: set[str] = set()
    for node in sorted(adjacency):
        _visit_mapping_graph(node, adjacency, visiting, visited)


# The persisted provenance model is the planner's risk-card input: it accepts a
# reviewed ``RiskCard`` (dumped by its NFC validator) and freezes its scores.
RiskCardInput = RiskReference


class CrossTaxonomyMappingInput(_InputModel):
    """One typed edge in the reviewed risk/taxonomy mapping graph."""

    source_id: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    relation: str = Field(default="related_match", min_length=1)
    evidence: tuple[str, ...] = ()
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    source_taxonomy: str | None = None
    target_taxonomy: str | None = None


class SSSOMMappingInput(_InputModel):
    """Closed representation of one SSSOM mapping row."""

    subject_id: str = Field(min_length=1)
    object_id: str = Field(min_length=1)
    predicate_id: str = Field(min_length=1)
    subject_source: str = Field(min_length=1)
    object_source: str = Field(min_length=1)
    mapping_justification: str = Field(min_length=1)


def _canonical_cross_mapping(item: Any) -> dict[str, Any]:
    """Return one typed cross-taxonomy edge with set-like evidence for hashing."""
    mapping = (
        item
        if isinstance(item, CrossTaxonomyMappingInput)
        else CrossTaxonomyMappingInput.model_validate(item)
    )
    payload = mapping.model_dump(mode="json")
    payload["evidence"] = sorted(set(payload["evidence"]))
    return payload


def _canonical_sssom_mapping(item: Any) -> dict[str, Any]:
    """Return one complete typed SSSOM row for bundle hashing."""
    mapping = (
        item
        if isinstance(item, SSSOMMappingInput)
        else SSSOMMappingInput.model_validate(item)
    )
    return mapping.model_dump(mode="json")


def _sort_canonical_payloads(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort set-like mapping content by the neutral canonical encoder."""
    return sorted(items, key=canonical_json_bytes)


def compute_mapping_bundle_digest(
    cross_taxonomy_mappings: Any,
    sssom_mappings: Any,
) -> str:
    """Digest the complete supplied Phase 1 edge bundle.

    The NUL-framed v1 payload contains every typed cross-taxonomy edge including
    evidence/confidence/provenance and every typed SSSOM row.  Collections are
    canonical set-like collections, so presentation order cannot change the
    digest while any semantic edge drift must change it.  This edge-bundle pin
    is intentionally distinct from each authoritative taxonomy context's
    existing ``mapping_set_digest`` pin; inputs must declare both.
    """
    payload = {
        "cross_taxonomy_mappings": _sort_canonical_payloads(
            [_canonical_cross_mapping(item) for item in cross_taxonomy_mappings]
        ),
        "sssom_mappings": _sort_canonical_payloads(
            [_canonical_sssom_mapping(item) for item in sssom_mappings]
        ),
    }
    return compute_framed_digest(MAPPING_BUNDLE_DIGEST_DOMAIN, payload)


def _qualification_fact_key(reference: AuthoritativeFactReference) -> str:
    """Return the canonical map key for one authoritative fact reference."""
    return _canonical_json(reference.model_dump(mode="json"))


def _canonical_qualification_facts(
    facts: dict[str, QualificationFactEvidence],
) -> dict[str, Any]:
    """Serialize the typed fact map for its content-integrity digest."""
    return {key: facts[key].model_dump(mode="json") for key in sorted(facts)}


class QualificationFactsInput(_InputModel):
    """Immutable qualification facts and their content digest."""

    facts: dict[str, QualificationFactEvidence] = Field(default_factory=dict)
    semantic_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="before")
    @classmethod
    def normalize_fact_inputs(cls, value: Any) -> Any:
        """Accept an authoritative evidence sequence from the projection seam."""
        if isinstance(value, BaseModel):
            value = value.model_dump(mode="json")
        if isinstance(value, (list, tuple)):
            return {"facts": _facts_from_sequence(value)}
        if isinstance(value, dict):
            return _normalize_fact_mapping(value)
        return value

    @model_validator(mode="after")
    def derive_or_verify_digest(self) -> QualificationFactsInput:
        """Derive the digest when absent and reject a stale declared digest."""
        for key, item in self.facts.items():
            if key != _qualification_fact_key(item.fact):
                raise ValueError(
                    "qualification fact map keys must match canonical fact references"
                )
        object.__setattr__(self, "facts", FrozenDict(self.facts))
        expected = compute_framed_digest(
            _QUALIFICATION_FACTS_DIGEST_DOMAIN,
            _canonical_qualification_facts(self.facts),
        )
        if self.semantic_digest is None:
            object.__setattr__(self, "semantic_digest", expected)
        elif self.semantic_digest != expected:
            raise ValueError("qualification facts semantic_digest does not match facts")
        return self


class TaxonomyObligationInputs(_InputModel):
    """Complete immutable input value for ``plan_taxonomy_obligations``."""

    risk_cards: tuple[RiskCardInput, ...]
    capability_snapshot: CapabilityFactSnapshot
    attack_pattern_catalog: tuple[AttackPattern, ...] = ()
    cross_taxonomy_mappings: tuple[CrossTaxonomyMappingInput, ...] = ()
    sssom_mappings: tuple[SSSOMMappingInput, ...] = ()
    catalog_pins: dict[str, TaxonomyPin] = Field(min_length=1)
    mapping_pins: dict[str, TaxonomyPin] = Field(min_length=1)
    qualification_facts: QualificationFactsInput
    projection_budget: ProjectionBudget = Field(default_factory=ProjectionBudget)

    @model_validator(mode="before")
    @classmethod
    def normalize_catalog_sequence(cls, value: Any) -> Any:
        """Normalize catalog dictionaries while preserving their typed entries."""
        if not isinstance(value, dict):
            return value
        data = dict(value)
        catalog = data.get("attack_pattern_catalog")
        if isinstance(catalog, dict):
            data["attack_pattern_catalog"] = list(catalog.values())
        return data

    @model_validator(mode="after")
    def unique_catalog_ids(self) -> TaxonomyObligationInputs:
        """Reject duplicate authoritative pattern identities."""
        snapshot = CapabilityFactSnapshot.model_validate(
            self.capability_snapshot.model_dump(mode="json")
        )
        object.__setattr__(
            self, "capability_snapshot", _freeze_nested_collections(snapshot)
        )
        catalog_ids: set[str] = set()
        for pattern in self.attack_pattern_catalog:
            if pattern.id in catalog_ids:
                raise ValueError(
                    f"duplicate authoritative attack pattern id: {pattern.id}"
                )
            catalog_ids.add(pattern.id)
        self._validate_mapping_graph(catalog_ids)
        risk_ids = [card.risk_id for card in self.risk_cards]
        if len(risk_ids) != len(set(risk_ids)):
            raise ValueError("risk card IDs must be unique")
        self._validate_mapping_bundle_pin()
        self._validate_exact_mapping_pin_keys()
        object.__setattr__(self, "catalog_pins", FrozenDict(self.catalog_pins))
        object.__setattr__(self, "mapping_pins", FrozenDict(self.mapping_pins))
        return self

    def _validate_exact_mapping_pin_keys(self) -> None:
        """Require the two documented mapping authorities and no aliases."""
        if set(self.mapping_pins) != _EXPECTED_MAPPING_PIN_KEYS:
            raise ValueError(
                "mapping_pins must contain exactly 'sssom' and 'obligation_edges'"
            )

    def _validate_mapping_bundle_pin(self) -> None:
        """Require context ``mapping_set_digest`` pins and one edge-bundle pin."""
        declared = {pin.digest for pin in self.mapping_pins.values()}
        context_digests = {
            pattern.canonical_chain.taxonomy_context.mapping_set_digest
            for pattern in self.attack_pattern_catalog
        }
        if not context_digests.issubset(declared):
            raise ValueError(
                "authoritative taxonomy-context mapping set does not match mapping pin"
            )
        expected = compute_mapping_bundle_digest(
            self.cross_taxonomy_mappings,
            self.sssom_mappings,
        )
        if expected not in declared:
            raise ValueError(
                "authoritative mapping bundle does not match mapping bundle pin"
            )

    def _validate_mapping_graph(self, catalog_ids: set[str]) -> None:
        """Reject duplicate, cyclic, and obviously dangling mapping edges."""
        edges = _input_mapping_edges(self)
        _validate_unique_mapping_edges(edges)
        _validate_mapping_targets(
            edges,
            catalog_ids,
            {card.risk_id for card in self.risk_cards},
        )
        _validate_acyclic_mapping_graph(edges)


__all__ = [
    "CrossTaxonomyMappingInput",
    "QualificationFactsInput",
    "RiskCardInput",
    "SSSOMMappingInput",
    "TaxonomyObligationInputs",
    "compute_mapping_bundle_digest",
]
