"""Typed inputs for the authoritative taxonomy-obligation planner.

The planner consumes this module's immutable input graph.  It is intentionally
separate from :mod:`models.obligation_plan`: the latter is the persisted output
contract, while this module is allowed to carry the authoritative pattern and
capability objects needed to derive candidate records.
"""

from __future__ import annotations

import unicodedata
from typing import Any, Literal

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.attack_pattern_contracts import (
    AuthoritativeFactReference,
    TaxonomyPin,
    validate_fact_scalar,
)
from asago_scenario_generator.models.risk_card import (
    RiskCard,
)
from asago_scenario_generator.models.canonical import (
    FrozenDict,
    FrozenList,
    canonical_json_bytes,
    compute_framed_digest,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    CapabilityFactSnapshot,
    ProjectionBudget,
)


MAPPING_BUNDLE_DIGEST_DOMAIN = "asago-scenario-generator:obligation-mapping-bundle:v1"
_QUALIFICATION_FACTS_DIGEST_DOMAIN = "asago-scenario-generator:qualification-facts:v1"
_EXPECTED_MAPPING_PIN_KEYS = frozenset({"sssom", "obligation_edges"})


def _nfc(value: Any) -> Any:
    """Normalize input strings and mapping keys before typed validation."""
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return _normalize_input_mapping(value)
    if isinstance(value, (list, tuple)):
        return _normalize_input_sequence(value)
    return value


def _normalize_input_mapping(value: dict[Any, Any]) -> dict[str, Any]:
    """Normalize one input mapping and reject canonical-key collisions."""
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise TypeError("input mapping keys must be strings")
        normalized_key = unicodedata.normalize("NFC", key)
        if normalized_key in normalized:
            raise ValueError("input mapping keys collide after NFC normalization")
        normalized[normalized_key] = _nfc(item)
    return normalized


def _normalize_input_sequence(value: list[Any] | tuple[Any, ...]) -> list[Any]:
    """Normalize each item in one input collection."""
    return [_nfc(item) for item in value]


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

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_input_strings(cls, value: Any) -> Any:
        """Apply the same NFC contract as persisted authoritative models."""
        return _nfc(value)


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


def _mapping_alias_values(
    value: dict[str, Any], aliases: tuple[str, ...]
) -> tuple[Any, ...]:
    """Return supplied values from one alias family in declaration order."""
    return tuple(map(value.__getitem__, filter(value.__contains__, aliases)))


def _validate_mapping_alias_values(field: str, supplied: tuple[Any, ...]) -> None:
    """Reject one mapping field whose aliases disagree."""
    if supplied:
        first, *rest = supplied
        if any(item != first for item in rest):
            raise ValueError(f"conflicting aliases for mapping field {field}")


def _without_mapping_aliases(
    value: dict[str, Any], aliases: tuple[str, ...]
) -> dict[str, Any]:
    """Remove an alias family while preserving all unrelated input fields."""
    alias_keys = set(aliases)
    return {key: item for key, item in value.items() if key not in alias_keys}


def _collapse_mapping_aliases(
    value: dict[str, Any], field: str, aliases: tuple[str, ...]
) -> dict[str, Any]:
    """Collapse one reviewed alias family while retaining unknown fields."""
    supplied = _mapping_alias_values(value, aliases)
    _validate_mapping_alias_values(field, supplied)
    normalized = _without_mapping_aliases(value, aliases)
    if supplied:
        normalized[field] = supplied[0]
    return normalized


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


class RiskEvidenceInput(_InputModel):
    """Immutable evidence span copied from a reviewed risk card."""

    text: str = ""
    source: str | None = None
    relevance: float | None = Field(default=None, ge=0.0, le=1.0)


class MitigationInput(_InputModel):
    """Immutable mitigation reference copied from a reviewed risk card."""

    mitigation_id: str | None = None
    description: str = ""
    source: str | None = None


class RiskCardInput(_InputModel):
    """Closed immutable copy of the reviewed risk-card fields used in Phase 1."""

    risk_id: str = Field(min_length=1)
    risk_name: str = ""
    risk_description: str = ""
    taxonomy: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    grounding_confidence: Literal["high", "medium", "low"] = "low"
    evidence: tuple[RiskEvidenceInput, ...] = ()
    scores: dict[str, float] | None = None
    mitigations: tuple[MitigationInput, ...] = ()
    threat: str | None = None
    threat_source: str | None = None
    vulnerability: str | None = None
    consequence: str | None = None
    impact: str | None = None

    @model_validator(mode="before")
    @classmethod
    def accept_reviewed_risk_card(cls, value: Any) -> Any:
        """Adapt the existing reviewed ``RiskCard`` without importing its mutability."""
        if isinstance(value, RiskCard):
            return value.model_dump(mode="python")
        return value

    @model_validator(mode="after")
    def freeze_nested_mappings(self) -> RiskCardInput:
        """Prevent caller mutation of nested score values after validation."""
        if self.scores is not None:
            object.__setattr__(self, "scores", FrozenDict(self.scores))
        return self


class CrossTaxonomyMappingInput(_InputModel):
    """One typed edge in the reviewed risk/taxonomy mapping graph."""

    source_id: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    relation: str = Field(default="related_match", min_length=1)
    evidence: tuple[str, ...] = ()
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    source_taxonomy: str | None = None
    target_taxonomy: str | None = None

    @model_validator(mode="before")
    @classmethod
    def normalize_mapping_aliases(cls, value: Any) -> Any:
        """Collapse reviewed mapping spellings without hiding unknown fields."""
        if not isinstance(value, dict):
            return value
        normalized = _collapse_mapping_aliases(
            value, "source_id", ("source_id", "risk_id", "subject_id")
        )
        normalized = _collapse_mapping_aliases(
            normalized,
            "target_id",
            ("target_id", "pattern_id", "attack_pattern_id", "object_id"),
        )
        return _collapse_mapping_aliases(
            normalized, "relation", ("relation", "predicate", "predicate_id")
        )


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


QualificationFactScalar = StrictStr | StrictInt | StrictBool
QualificationFactStatus = Literal["present", "absent", "unknown", "contradictory"]


def _qualification_fact_key(reference: AuthoritativeFactReference) -> str:
    """Return the canonical map key for one authoritative fact reference."""
    return _canonical_json(reference.model_dump(mode="json"))


class QualificationFact(_InputModel):
    """One closed, typed authoritative qualification reading."""

    fact: AuthoritativeFactReference
    status: QualificationFactStatus
    value: QualificationFactScalar | None = None

    @model_validator(mode="after")
    def coherent_value(self) -> QualificationFact:
        """Require values only for unambiguous present readings."""
        if self.status == "present":
            if self.value is None:
                raise ValueError("present qualification facts require a value")
            validate_fact_scalar(self.fact, self.value)
        elif self.value is not None:
            raise ValueError(
                "absent, unknown, and contradictory qualification facts "
                "require a null value"
            )
        return self


def _canonical_qualification_facts(
    facts: dict[str, QualificationFact],
) -> dict[str, Any]:
    """Serialize the typed fact map for its content-integrity digest."""
    return {key: facts[key].model_dump(mode="json") for key in sorted(facts)}


class QualificationFactsInput(_InputModel):
    """Immutable qualification facts and their content digest."""

    facts: dict[str, QualificationFact] = Field(default_factory=dict)
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


class CompatibilityPolicyInput(_InputModel):
    """Explicitly named compatibility switches; no candidate override exists."""

    allow_legacy_keyword_matches: bool = False


class TaxonomyObligationInputs(_InputModel):
    """Complete immutable input value for ``plan_taxonomy_obligations``."""

    risk_cards: tuple[RiskCardInput, ...]
    capability_snapshot: CapabilityFactSnapshot = Field(
        validation_alias=AliasChoices("capability_snapshot", "capability_fact_snapshot")
    )
    attack_pattern_catalog: tuple[AttackPattern, ...] = Field(
        default=(),
        validation_alias=AliasChoices(
            "attack_pattern_catalog", "attack_patterns", "catalog"
        ),
    )
    cross_taxonomy_mappings: tuple[CrossTaxonomyMappingInput, ...] = Field(
        default=(),
        validation_alias=AliasChoices(
            "cross_taxonomy_mappings", "risk_pattern_mappings", "mappings"
        ),
    )
    sssom_mappings: tuple[SSSOMMappingInput, ...] = Field(
        default=(), validation_alias=AliasChoices("sssom_mappings", "sssom")
    )
    catalog_pins: dict[str, TaxonomyPin] = Field(
        min_length=1,
        validation_alias=AliasChoices("catalog_pins", "taxonomy_pins"),
    )
    mapping_pins: dict[str, TaxonomyPin] = Field(
        min_length=1,
        validation_alias=AliasChoices("mapping_pins", "mapping_set_pins"),
    )
    qualification_facts: QualificationFactsInput = Field(
        validation_alias=AliasChoices("qualification_facts", "qualification_evidence")
    )
    projection_budget: ProjectionBudget = Field(
        default_factory=ProjectionBudget,
        validation_alias=AliasChoices("projection_budget", "budget"),
    )
    compatibility_policy: CompatibilityPolicyInput = Field(
        default_factory=CompatibilityPolicyInput,
        validation_alias=AliasChoices("compatibility_policy", "compatibility"),
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_catalog_sequence(cls, value: Any) -> Any:
        """Normalize catalog dictionaries while preserving their typed entries."""
        if not isinstance(value, dict):
            return value
        data = dict(value)
        for key in ("attack_pattern_catalog", "attack_patterns", "catalog"):
            catalog = data.get(key)
            if isinstance(catalog, dict):
                data[key] = list(catalog.values())
                break
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
    "CompatibilityPolicyInput",
    "CrossTaxonomyMappingInput",
    "QualificationFact",
    "QualificationFactScalar",
    "QualificationFactsInput",
    "QualificationFactStatus",
    "RiskCardInput",
    "RiskEvidenceInput",
    "MitigationInput",
    "SSSOMMappingInput",
    "TaxonomyObligationInputs",
    "compute_mapping_bundle_digest",
]


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-28T16:51:36Z","module_hash":"d714717945e54d7f6f85578eba81a6f6e3c30d6705c89cbaf6226f9bca17dab7","source_sha256":"bfd2fce9631f3e1297b5d380ef3f562442aa708a215062e2a28551f163c65900","functions":[{"id":"func/_nfc","name":"_nfc","line":51,"end_line":59,"hash":"cb2335af2926071847537cc9ad5d80d95067b4910ecf7939458efe8ca584a24d"},{"id":"func/_normalize_input_mapping","name":"_normalize_input_mapping","line":62,"end_line":72,"hash":"5ce59f7eb9898cb7bc5b40456608cebf250edf7713621b9ef3311a2690094bcf"},{"id":"func/_normalize_input_sequence","name":"_normalize_input_sequence","line":75,"end_line":77,"hash":"b5b2567dfefad347bf0f8a0c6bcb725ce93bc683cba08a8b883b6dac5718348c"},{"id":"func/_freeze_model_fields","name":"_freeze_model_fields","line":80,"end_line":87,"hash":"20d7ce0a5b81fdc95f234c2325d27a286935fa214ce6aec688b930394e646331"},{"id":"func/_freeze_mapping","name":"_freeze_mapping","line":90,"end_line":94,"hash":"bea1333e339080e179be3d795e415c0b1031dd9f81760bf1f6b0445ff430f2d6"},{"id":"func/_freeze_sequence","name":"_freeze_sequence","line":97,"end_line":102,"hash":"74a60d7bfa9548c8e8dc0cf0c5a27e922d4e0083aab3a12eb04ec652ddaac2a7"},{"id":"func/_freeze_set","name":"_freeze_set","line":105,"end_line":107,"hash":"b58270f78ec190d5f2fff049b69886ade46fc22098a50c8f347313e8ffac0e00"},{"id":"func/_freeze_nested_collections","name":"_freeze_nested_collections","line":110,"end_line":122,"hash":"7dcb96cb270048c5cc6da4677f4c8b9a6d99a25cf7139fe784a0051fc7227a1e"},{"id":"func/_InputModel.normalize_input_strings","name":"normalize_input_strings","line":136,"end_line":138,"hash":"7d47bd02cec7b11fd4eac1f195571381d202507d6a6febb655fe91ae74703efc"},{"id":"func/_canonical_json","name":"_canonical_json","line":141,"end_line":143,"hash":"390c4b3ddc31c90e92a01b38561bdf8c85aede63f605c70d51ef6c6670563ab7"},{"id":"func/_fact_item","name":"_fact_item","line":146,"end_line":153,"hash":"033c33a53fc82deac0aab0a202411263854f92ee7ba7d7ff6f91326289c84a3f"},{"id":"func/_facts_from_sequence","name":"_facts_from_sequence","line":156,"end_line":164,"hash":"d8d6cf02792d1b203cf2dd0d8428b905a35e1fc594d634b7562b488f0bb85c8e"},{"id":"func/_normalize_fact_mapping","name":"_normalize_fact_mapping","line":167,"end_line":177,"hash":"d72d3279f52ea11378fa76280e22ad4e70488d8799c3be838883891b0a8ebdba"},{"id":"func/_mapping_alias_values","name":"_mapping_alias_values","line":180,"end_line":184,"hash":"9a83460d9f07ba23d58fd41962160d6d6b162ecb6f07c7da3263801d4b5192ea"},{"id":"func/_validate_mapping_alias_values","name":"_validate_mapping_alias_values","line":187,"end_line":192,"hash":"a12a74b7d94b7a6206b5f779f8943a25f9dcd704bf5cd1436b341639cf751408"},{"id":"func/_without_mapping_aliases","name":"_without_mapping_aliases","line":195,"end_line":200,"hash":"7be2937c5f98935c2f2409626c3c8a88af28cd5fe93b8538d47d681784ce40fb"},{"id":"func/_collapse_mapping_aliases","name":"_collapse_mapping_aliases","line":203,"end_line":212,"hash":"121cc6d5687e31ba7285c0612e73cd1364737e6c944bf428ac30e1cf14f00fc1"},{"id":"func/_input_mapping_edges","name":"_input_mapping_edges","line":215,"end_line":227,"hash":"4499074247bab3942de9af6fdfd6c6bc8122d6b29c7f938f802347445c598a0b"},{"id":"func/_validate_unique_mapping_edges","name":"_validate_unique_mapping_edges","line":230,"end_line":233,"hash":"d2fedf2a832eaacb511cf0256b0a1c6eb53aa81e3b7cc482b74cd507318d1c91"},{"id":"func/_mapping_endpoints","name":"_mapping_endpoints","line":236,"end_line":243,"hash":"609a28f432a8eed95c52be0dc00ce4737f1f223f95a38ec359e79d518099b943"},{"id":"func/_raise_unknown_mapping_endpoints","name":"_raise_unknown_mapping_endpoints","line":246,"end_line":255,"hash":"e27736b34cdac7058d41e2d6b2a3d269d653c2ad978526c39719bd1fd888ba09"},{"id":"func/_validate_mapping_targets","name":"_validate_mapping_targets","line":258,"end_line":270,"hash":"c70acea75586b7b0b0bcc00c6361b82ed5b23575dfe1f4f8f078c802c71a835b"},{"id":"func/_mapping_adjacency","name":"_mapping_adjacency","line":273,"end_line":280,"hash":"f8f402968342536c25ce62700b17f77cdf26aaba3fb9690b4b4adc461c5a4516"},{"id":"func/_visit_mapping_graph","name":"_visit_mapping_graph","line":283,"end_line":297,"hash":"548de84fee32c062f80de25def46635f409c22cf21cfc01e28e0e371afd51336"},{"id":"func/_validate_acyclic_mapping_graph","name":"_validate_acyclic_mapping_graph","line":300,"end_line":306,"hash":"b6dda6c27a64209b14480262a19bd57d1995ee8afa5808b34322e346ef0fd757"},{"id":"func/RiskCardInput.accept_reviewed_risk_card","name":"accept_reviewed_risk_card","line":345,"end_line":349,"hash":"6bc6a45e96daeaf21fb7f698b12f8d3cf22f77f7b9acbc6da3c2c09718bfb221"},{"id":"func/RiskCardInput.freeze_nested_mappings","name":"freeze_nested_mappings","line":352,"end_line":356,"hash":"6ba67f687c4300f5358a373b5b88e65b126ee8c7d96192701794878e87f782c3"},{"id":"func/CrossTaxonomyMappingInput.normalize_mapping_aliases","name":"normalize_mapping_aliases","line":372,"end_line":386,"hash":"f8dd83ba1cca0f570f449416800c6745479d2e56dc45af4c8e0c48e29191ee6e"},{"id":"func/_canonical_cross_mapping","name":"_canonical_cross_mapping","line":400,"end_line":409,"hash":"6c0a9a10d49996c89b1c4ba00cccbdb07c9c6f9eb974c718a32f887c850d1d31"},{"id":"func/_canonical_sssom_mapping","name":"_canonical_sssom_mapping","line":412,"end_line":419,"hash":"df2ad6427f3919c17583da99adc69bd6c13fbef3aafd6e0bc6107df8c32fa06a"},{"id":"func/_sort_canonical_payloads","name":"_sort_canonical_payloads","line":422,"end_line":424,"hash":"0c53a98add386eb454087845009cdcdb99db4d3cf714b9cece8eed6f1cec27ed"},{"id":"func/compute_mapping_bundle_digest","name":"compute_mapping_bundle_digest","line":427,"end_line":448,"hash":"8d493ddc1fd21436287c7c90b5d27ff6518fd98529c1148a8187455443793c30"},{"id":"func/_qualification_fact_key","name":"_qualification_fact_key","line":455,"end_line":457,"hash":"2bb03d559338051cd6bfe115d6bb50d0a0a9810f9004056cf08c3c6566ebf252"},{"id":"func/QualificationFact.coherent_value","name":"coherent_value","line":468,"end_line":479,"hash":"7492c6eed3e056ccfdbf1b41cdd68d69c134309557203fc63cda7c3187f86f67"},{"id":"func/_canonical_qualification_facts","name":"_canonical_qualification_facts","line":482,"end_line":486,"hash":"9060c3c41d53122692bf4133f4010561da0639c16729744d5e87ab4601ba1317"},{"id":"func/QualificationFactsInput.normalize_fact_inputs","name":"normalize_fact_inputs","line":497,"end_line":505,"hash":"a18aeb47a95226993a232957754ecbf40b1dd15e37bfa32d7f53c073def98c9d"},{"id":"func/QualificationFactsInput.derive_or_verify_digest","name":"derive_or_verify_digest","line":508,"end_line":524,"hash":"b6972ee5f9e1d3447e1d4f87438cf98ce4157290426ea50497306bdb6a915ef6"},{"id":"func/TaxonomyObligationInputs.normalize_catalog_sequence","name":"normalize_catalog_sequence","line":577,"end_line":587,"hash":"f0ed19383b524fc6f10317c09e6ca8244ea372701fc73b581b94bd08cd3b1604"},{"id":"func/TaxonomyObligationInputs.unique_catalog_ids","name":"unique_catalog_ids","line":590,"end_line":613,"hash":"b1195d3853915f2d17553f46561b26fe23e494822369ac7745f8dc192e8ffa81"},{"id":"func/TaxonomyObligationInputs._validate_exact_mapping_pin_keys","name":"_validate_exact_mapping_pin_keys","line":615,"end_line":620,"hash":"1b1de1f5608883cdec7bf7d762f1d5dca8ff9be06f5458b4da344beb02db481b"},{"id":"func/TaxonomyObligationInputs._validate_mapping_bundle_pin","name":"_validate_mapping_bundle_pin","line":622,"end_line":640,"hash":"de72cccb0671dfb1625d917e56364de20ee5b61bcc49fdc0f709fe21db50e66e"},{"id":"func/TaxonomyObligationInputs._validate_mapping_graph","name":"_validate_mapping_graph","line":642,"end_line":651,"hash":"e9085a0612b7bb3184eca3a7dac44dbc27be444f82b2d07e97503b3fb1b96f46"}]}
# mutate4py-manifest-end
