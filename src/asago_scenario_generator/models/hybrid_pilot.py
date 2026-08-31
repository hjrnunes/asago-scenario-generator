"""Closed contracts for the offline Phase 4 pilot-readiness gate.

The pilot gate is deliberately not a generation surface.  It records the
provenance and exact target accounting needed before a later, target-scoped
semantic run may be started.  The pipeline adapter owns cross-artifact
validation; these models only provide immutable, content-addressed values.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, Any, Literal
import weakref

from pydantic import BaseModel, ConfigDict, Field, model_validator

from asago_scenario_generator.models.canonical import (
    compute_framed_digest,
    normalize_unicode,
)
from asago_scenario_generator.models.candidate_materialization import (
    CandidateMaterializationSet,
)
from asago_scenario_generator.models.hybrid_coverage import (
    ArtifactPin,
    Digest,
    HybridCoverageAssessment,
)
from asago_scenario_generator.models.hybrid_scenario_projection import (
    ConfirmedCoverageReview,
    HybridCorrespondenceAttestation,
    HybridScenarioProjectionSet,
    PinnedStpaProjectionAttestation,
    RelationId,
)
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.models.scenario import ScenarioEnvelope
from asago_scenario_generator.models.system_resource_map import (
    SystemResourceMapValidation,
)


PILOT_PROVENANCE_SCHEMA_VERSION = "hybrid-pilot-provenance-v1"
HYBRID_PILOT_INPUTS_SCHEMA_VERSION = "hybrid-pilot-readiness-inputs-v1"
HYBRID_PILOT_RESULT_SCHEMA_VERSION = "hybrid-pilot-readiness-result-v1"
PILOT_PROVENANCE_DIGEST_DOMAIN = "asago.hybrid-pilot-provenance.v1"
HYBRID_PILOT_RESULT_DIGEST_DOMAIN = "asago.hybrid-pilot-readiness-result.v1"

CandidateId = Annotated[str, Field(pattern=r"^cand:v2:[0-9a-f]{32}$")]
RunId = Annotated[str, Field(min_length=1)]


class _PilotModel(BaseModel):
    """Immutable, closed pilot value with canonical Unicode input."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def normalize_input(cls, value: Any) -> Any:
        """Normalize scalar values while retaining typed authority leaves."""
        return _normalize_typed(value)


def _normalize_typed(value: Any) -> Any:
    """NFC-normalize raw values without flattening typed Pydantic leaves."""
    if isinstance(value, BaseModel):
        return value
    if isinstance(value, dict):
        return _normalize_mapping(value)
    if isinstance(value, (list, tuple)):
        return _normalize_sequence(value)
    return normalize_unicode(value)


def _normalize_mapping(value: dict[Any, Any]) -> dict[str, Any]:
    """Normalize a mapping while enforcing canonical string-key identity."""
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise TypeError("canonical JSON mapping keys must be strings")
        normalized_key = normalize_unicode(key)
        if normalized_key in normalized:
            raise ValueError("canonical mapping keys collide after NFC normalization")
        normalized[normalized_key] = _normalize_typed(item)
    return normalized


def _normalize_sequence(value: list[Any] | tuple[Any, ...]) -> list[Any]:
    """Normalize each item in a sequence without flattening typed leaves."""
    return [_normalize_typed(item) for item in value]


def _digest_without(value: BaseModel, field: str, domain: str) -> str:
    """Compute one digest after removing its derived digest field."""
    excluded = {field}
    if field == "evidence_digest":
        # The evidence digest is the content pin; it must not change when the
        # separately derived semantic digest is filled in.
        excluded.add("semantic_digest")
    return compute_framed_digest(
        domain,
        value.model_dump(mode="json", exclude=excluded),
    )


def _validate_optional_digest(supplied: str | None, expected: str, label: str) -> None:
    """Reject a caller-supplied derived digest that differs from content."""
    if supplied is not None and supplied != expected:
        raise ValueError(f"{label} does not match content")


class PilotTargetIdentity(_PilotModel):
    """One explicit relation/candidate target for a semantic pilot."""

    relation_id: RelationId
    selected_candidate_id: CandidateId

    @property
    def key(self) -> tuple[str, str]:
        """Return the exact target identity used for set comparisons."""
        return (self.relation_id, self.selected_candidate_id)


def _ordered_targets(
    targets: Sequence[PilotTargetIdentity], label: str
) -> tuple[PilotTargetIdentity, ...]:
    """Canonicalize a target collection and reject duplicate identities."""
    ordered = tuple(sorted(targets, key=lambda item: item.key))
    keys = tuple(item.key for item in ordered)
    if len(keys) != len(set(keys)):
        raise ValueError(f"{label} must contain unique relation/candidate targets")
    return ordered


class PilotExactJoinCounts(_PilotModel):
    """Exact accounting for one target-scoped pilot corpus."""

    expected: int = Field(ge=0, strict=True)
    generated: int = Field(ge=0, strict=True)
    admitted: int = Field(ge=0, strict=True)
    quarantined: int = Field(ge=0, strict=True)
    exact_joins: int = Field(ge=0, strict=True)

    @model_validator(mode="after")
    def reconcile_counts(self) -> "PilotExactJoinCounts":
        """Keep the exact-list counts internally coherent."""
        if self.generated > self.expected:
            raise ValueError("generated target count cannot exceed expected count")
        if self.admitted + self.quarantined > self.generated:
            raise ValueError("admitted and quarantined counts exceed generated count")
        if self.exact_joins > self.admitted:
            raise ValueError("exact joins cannot exceed admitted target count")
        return self


class ModelCallEvidence(_PilotModel):
    """Typed evidence that accounts for model calls in a pilot run.

    This record carries hashes and counts, never prompts, secrets, or provider
    payloads.  ``adapter_kind`` is descriptive: the readiness gate itself
    remains offline regardless of the later run's recorded call count.
    """

    schema_version: Literal["model-call-evidence-v1"] = "model-call-evidence-v1"
    adapter_kind: Literal["provider", "fake", "none"]
    model_calls: int = Field(ge=0, strict=True)
    provider_calls: int = Field(ge=0, strict=True)
    network_calls: int = Field(ge=0, strict=True)
    settings_digest: Digest
    model_profile_digest: Digest
    scenario_artifact_digests: tuple[Digest, ...] = ()
    evidence_digest: Digest
    semantic_digest: Digest | None = None

    @classmethod
    def create(
        cls,
        *,
        adapter_kind: Literal["provider", "fake", "none"],
        model_calls: int,
        provider_calls: int,
        network_calls: int,
        settings_digest: Digest,
        model_profile_digest: Digest,
        scenario_artifact_digests: Sequence[Digest] = (),
    ) -> "ModelCallEvidence":
        """Build evidence with canonical artifact ordering and its content pin."""
        canonical_artifacts = _canonical_model_call_artifact_digests(
            tuple(scenario_artifact_digests)
        )
        payload = {
            "schema_version": "model-call-evidence-v1",
            "adapter_kind": adapter_kind,
            "model_calls": model_calls,
            "provider_calls": provider_calls,
            "network_calls": network_calls,
            "settings_digest": settings_digest,
            "model_profile_digest": model_profile_digest,
            "scenario_artifact_digests": canonical_artifacts,
            "semantic_digest": None,
        }
        evidence_digest = compute_framed_digest(
            "asago.model-call-evidence.v1",
            {key: value for key, value in payload.items() if key != "semantic_digest"},
        )
        return cls(**payload, evidence_digest=evidence_digest)

    @model_validator(mode="after")
    def verify_digest(self) -> "ModelCallEvidence":
        """Verify the content digest and call-count relationship."""
        scenario_digests = _canonical_model_call_artifact_digests(
            self.scenario_artifact_digests
        )
        object.__setattr__(self, "scenario_artifact_digests", scenario_digests)
        _validate_model_call_counts(self)
        _require_digest_match(
            self.evidence_digest,
            _digest_without(self, "evidence_digest", "asago.model-call-evidence.v1"),
            "model-call evidence digest does not match content",
        )
        _set_model_call_semantic_digest(self)
        return self

    def assert_integrity(self) -> None:
        """Raise when the evidence was changed after construction."""
        expected_evidence = _digest_without(
            self, "evidence_digest", "asago.model-call-evidence.v1"
        )
        if self.evidence_digest != expected_evidence:
            raise ValueError("model-call evidence digest mismatch")
        expected = _digest_without(
            self, "semantic_digest", "asago.model-call-evidence.v1"
        )
        if self.semantic_digest != expected:
            raise ValueError("model-call evidence semantic digest mismatch")


def _canonical_model_call_artifact_digests(
    digests: Sequence[Digest],
) -> tuple[Digest, ...]:
    """Canonicalize and reject duplicate scenario artifact content pins."""
    canonical = tuple(sorted(set(digests)))
    if len(canonical) != len(digests):
        raise ValueError("model-call scenario artifact digests must be unique")
    return canonical


def _validate_model_call_counts(value: ModelCallEvidence) -> None:
    """Validate provider and adapter call-count relationships."""
    _require_provider_calls_within_model_calls(value)
    _require_none_adapter_is_zero(value)


def _require_provider_calls_within_model_calls(value: ModelCallEvidence) -> None:
    """Require provider calls to be included in total model calls."""
    if value.provider_calls > value.model_calls:
        raise ValueError("provider calls cannot exceed model calls")


def _require_none_adapter_is_zero(value: ModelCallEvidence) -> None:
    """Require a no-op adapter to report no model, provider, or network calls."""
    if value.adapter_kind != "none":
        return
    _require_zero_call_counts(value)


def _require_zero_call_counts(value: ModelCallEvidence) -> None:
    """Require a no-op adapter to report zero call counts."""
    if value.model_calls or value.provider_calls or value.network_calls:
        raise ValueError("none adapter call evidence must report zero calls")


def _require_digest_match(actual: Digest, expected: Digest, message: str) -> None:
    """Raise one stable error when a derived digest is inconsistent."""
    if actual != expected:
        raise ValueError(message)


def _set_model_call_semantic_digest(value: ModelCallEvidence) -> None:
    """Validate and set the semantic digest derived from call evidence."""
    expected = _digest_without(value, "semantic_digest", "asago.model-call-evidence.v1")
    _validate_optional_digest(
        value.semantic_digest, expected, "model-call evidence semantic_digest"
    )
    object.__setattr__(value, "semantic_digest", expected)


class PilotProvenanceBundle(_PilotModel):
    """Complete, typed provenance for one target-scoped future pilot."""

    schema_version: Literal[PILOT_PROVENANCE_SCHEMA_VERSION] = (
        PILOT_PROVENANCE_SCHEMA_VERSION
    )
    run_id: RunId
    generate_run_manifest_pin: ArtifactPin
    use_case_digest: Digest
    risk_extraction_digest: Digest
    sssom_digest: Digest
    cross_taxonomy_mapping_digest: Digest
    threats_digest: Digest
    corrected_nested_capability_profile_digest: Digest
    qualification_facts_digest: Digest
    catalog_digest: Digest
    mappings_digest: Digest
    settings_digest: Digest
    model_profile_digest: Digest
    scenario_artifact_pins: tuple[ArtifactPin, ...] = ()
    model_call_evidence: ModelCallEvidence
    expected_targets: tuple[PilotTargetIdentity, ...] = ()
    generated_targets: tuple[PilotTargetIdentity, ...] = ()
    admitted_targets: tuple[PilotTargetIdentity, ...] = ()
    quarantined_targets: tuple[PilotTargetIdentity, ...] = ()
    exact_join_counts: PilotExactJoinCounts
    semantic_digest: Digest | None = None

    @classmethod
    def from_verified_artifacts(
        cls,
        *,
        run_id: RunId,
        generate_run_manifest_pin: ArtifactPin,
        use_case_digest: Digest,
        risk_extraction_digest: Digest,
        sssom_digest: Digest,
        cross_taxonomy_mapping_digest: Digest,
        threats_digest: Digest,
        corrected_nested_capability_profile_digest: Digest,
        qualification_facts_digest: Digest,
        catalog_digest: Digest,
        mappings_digest: Digest,
        settings_digest: Digest,
        model_profile_digest: Digest,
        model_call_evidence: ModelCallEvidence,
        exact_join_counts: PilotExactJoinCounts,
        projection_set_digest: Digest | None = None,
        scenario_artifact_pins: Sequence[ArtifactPin] = (),
        expected_targets: Sequence[PilotTargetIdentity] = (),
        generated_targets: Sequence[PilotTargetIdentity] = (),
        admitted_targets: Sequence[PilotTargetIdentity] = (),
        quarantined_targets: Sequence[PilotTargetIdentity] = (),
    ) -> "PilotProvenanceBundle":
        """Create provenance through the exact-artifact verification seam.

        The process-local factory mark is intentionally not serialized.  A
        later gate therefore cannot treat a copied or relabelled digest as a
        verified live-run provenance record.
        """
        value = cls(
            run_id=run_id,
            generate_run_manifest_pin=generate_run_manifest_pin,
            use_case_digest=use_case_digest,
            risk_extraction_digest=risk_extraction_digest,
            sssom_digest=sssom_digest,
            cross_taxonomy_mapping_digest=cross_taxonomy_mapping_digest,
            threats_digest=threats_digest,
            corrected_nested_capability_profile_digest=corrected_nested_capability_profile_digest,
            qualification_facts_digest=qualification_facts_digest,
            catalog_digest=catalog_digest,
            mappings_digest=mappings_digest,
            settings_digest=settings_digest,
            model_profile_digest=model_profile_digest,
            scenario_artifact_pins=tuple(scenario_artifact_pins),
            model_call_evidence=model_call_evidence,
            expected_targets=tuple(expected_targets),
            generated_targets=tuple(generated_targets),
            admitted_targets=tuple(admitted_targets),
            quarantined_targets=tuple(quarantined_targets),
            exact_join_counts=exact_join_counts,
        )
        return _mark_verified_provenance(value, projection_set_digest)

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "PilotProvenanceBundle":
        """Canonicalize target/pin sets and reconcile exact accounting."""
        expected, generated, admitted, quarantined = (
            _ordered_targets(self.expected_targets, "expected_targets"),
            _ordered_targets(self.generated_targets, "generated_targets"),
            _ordered_targets(self.admitted_targets, "admitted_targets"),
            _ordered_targets(self.quarantined_targets, "quarantined_targets"),
        )
        _validate_provenance_target_sets(expected, generated, admitted, quarantined)
        _require_provenance_target_counts(
            self.exact_join_counts,
            expected,
            generated,
            admitted,
            quarantined,
        )
        object.__setattr__(self, "expected_targets", expected)
        object.__setattr__(self, "generated_targets", generated)
        object.__setattr__(self, "admitted_targets", admitted)
        object.__setattr__(self, "quarantined_targets", quarantined)
        scenario_pins = _ordered_pins(self.scenario_artifact_pins)
        object.__setattr__(
            self,
            "scenario_artifact_pins",
            scenario_pins,
        )
        _require_scenario_artifact_accounting(self.model_call_evidence, scenario_pins)
        self.model_call_evidence.assert_integrity()
        _set_provenance_semantic_digest(self)
        return self

    def assert_integrity(self) -> None:
        """Verify target accounting, model-call evidence, and digest."""
        type(self).model_validate(self.model_dump(mode="python"))


def _target_keys(targets: Sequence[PilotTargetIdentity]) -> set[tuple[str, str]]:
    """Return exact identity keys for one canonical target collection."""
    return {item.key for item in targets}


def _require_target_subset(
    subset: Sequence[PilotTargetIdentity],
    superset: Sequence[PilotTargetIdentity],
    message: str,
) -> None:
    """Require one target collection to be contained in another."""
    if not _target_keys(subset) <= _target_keys(superset):
        raise ValueError(message)


def _validate_provenance_target_sets(
    expected: Sequence[PilotTargetIdentity],
    generated: Sequence[PilotTargetIdentity],
    admitted: Sequence[PilotTargetIdentity],
    quarantined: Sequence[PilotTargetIdentity],
) -> None:
    """Require target subsets and mutually exclusive admission outcomes."""
    _require_target_subset(
        generated,
        expected,
        "generated targets must be a subset of expected targets",
    )
    _require_target_subset(
        admitted,
        generated,
        "admitted targets must be a subset of generated targets",
    )
    _require_target_subset(
        quarantined,
        generated,
        "quarantined targets must be a subset of generated targets",
    )
    if _target_keys(admitted) & _target_keys(quarantined):
        raise ValueError("a target cannot be both admitted and quarantined")


def _require_provenance_target_counts(
    counts: PilotExactJoinCounts,
    expected: Sequence[PilotTargetIdentity],
    generated: Sequence[PilotTargetIdentity],
    admitted: Sequence[PilotTargetIdentity],
    quarantined: Sequence[PilotTargetIdentity],
) -> None:
    """Require recorded target counts to match canonical target collections."""
    actual = (
        len(expected),
        len(generated),
        len(admitted),
        len(quarantined),
    )
    recorded = (
        counts.expected,
        counts.generated,
        counts.admitted,
        counts.quarantined,
    )
    if actual != recorded:
        raise ValueError("pilot target counts do not reconcile with exact lists")


def _require_scenario_artifact_accounting(
    evidence: ModelCallEvidence,
    pins: Sequence[ArtifactPin],
) -> None:
    """Require model-call evidence to account for each scenario artifact pin."""
    scenario_digests = tuple(sorted(pin.semantic_digest for pin in pins))
    if evidence.scenario_artifact_digests != scenario_digests:
        raise ValueError(
            "model-call evidence must account for every scenario artifact pin"
        )


def _set_provenance_semantic_digest(value: PilotProvenanceBundle) -> None:
    """Validate and set the provenance semantic digest."""
    expected = _digest_without(value, "semantic_digest", PILOT_PROVENANCE_DIGEST_DOMAIN)
    _validate_optional_digest(
        value.semantic_digest, expected, "pilot provenance semantic_digest"
    )
    object.__setattr__(value, "semantic_digest", expected)


_VERIFIED_PROVENANCE: dict[
    int, tuple[weakref.ReferenceType[PilotProvenanceBundle], str | None]
] = {}


def _mark_verified_provenance(
    value: PilotProvenanceBundle,
    projection_set_digest: str | None,
) -> PilotProvenanceBundle:
    """Mark one factory output without making the mark part of its digest."""
    key = id(value)

    def discard(
        _reference: weakref.ReferenceType[PilotProvenanceBundle],
        *,
        key: int = key,
    ) -> None:
        """Drop the mark when the factory output is collected."""
        _VERIFIED_PROVENANCE.pop(key, None)

    _VERIFIED_PROVENANCE[key] = (weakref.ref(value, discard), projection_set_digest)
    return value


def _is_verified_provenance(
    value: object, projection_set_digest: str | None = None
) -> bool:
    """Return whether this exact object and projection content were factory-bound."""
    metadata = _VERIFIED_PROVENANCE.get(id(value))
    if metadata is None:
        return False
    reference, bound_projection_digest = metadata
    return reference() is value and (
        projection_set_digest is None
        or bound_projection_digest == projection_set_digest
    )


def _ordered_pins(pins: Sequence[ArtifactPin]) -> tuple[ArtifactPin, ...]:
    """Canonicalize and reject duplicate scenario artifact pins."""
    ordered = tuple(
        sorted(
            pins,
            key=lambda item: (
                item.artifact_id,
                item.schema_version,
                item.semantic_digest,
            ),
        )
    )
    if len(ordered) != len(
        {
            (item.artifact_id, item.schema_version, item.semantic_digest)
            for item in ordered
        }
    ):
        raise ValueError("scenario artifact pins must be unique")
    return ordered


PilotBlockerCode = Literal[
    "old_klarna_taxonomy_envelopes",
    "old_nhs_taxonomy_envelopes",
    "corrected_assessment_without_coverage",
    "missing_corrected_plan_join",
    "missing_scenario_envelope",
    "missing_candidate_materialization",
    "missing_projection",
    "missing_stpa_identity",
    "missing_review_evidence",
    "normative_bookkeeping_fixture",
    "missing_model_call_evidence",
    "synthetic_evidence",
]


class PilotReadinessBlocker(_PilotModel):
    """One exact reason a semantic pilot cannot yet proceed."""

    code: PilotBlockerCode
    message: str = Field(min_length=1)
    target: PilotTargetIdentity | None = None


class HybridPilotReadinessResult(_PilotModel):
    """Immutable result of the deterministic pilot-readiness check."""

    schema_version: Literal[HYBRID_PILOT_RESULT_SCHEMA_VERSION] = (
        HYBRID_PILOT_RESULT_SCHEMA_VERSION
    )
    ready: bool
    blockers: tuple[PilotReadinessBlocker, ...] = ()
    expected_target_count: int = Field(ge=0, strict=True)
    generated_target_count: int = Field(ge=0, strict=True)
    admitted_target_count: int = Field(ge=0, strict=True)
    quarantined_target_count: int = Field(ge=0, strict=True)
    exact_join_count: int = Field(ge=0, strict=True)
    model_calls: Literal[0] = 0
    provider_calls: Literal[0] = 0
    network_calls: Literal[0] = 0
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def verify_result(self) -> "HybridPilotReadinessResult":
        """Require readiness to be exactly the absence of blockers."""
        if self.ready != (not self.blockers):
            raise ValueError("pilot readiness must reconcile with blockers")
        if self.exact_join_count > self.admitted_target_count:
            raise ValueError("exact joins cannot exceed admitted target count")
        expected = _digest_without(
            self, "semantic_digest", HYBRID_PILOT_RESULT_DIGEST_DOMAIN
        )
        _validate_optional_digest(
            self.semantic_digest, expected, "pilot readiness semantic_digest"
        )
        object.__setattr__(self, "semantic_digest", expected)
        return self

    def assert_integrity(self) -> None:
        """Verify the result semantic digest."""
        expected = _digest_without(
            self, "semantic_digest", HYBRID_PILOT_RESULT_DIGEST_DOMAIN
        )
        if self.semantic_digest != expected:
            raise ValueError("pilot readiness semantic digest mismatch")


class HybridPilotReadinessInputs(_PilotModel):
    """One closed graph of exact authorities for pilot readiness."""

    schema_version: Literal[HYBRID_PILOT_INPUTS_SCHEMA_VERSION] = (
        HYBRID_PILOT_INPUTS_SCHEMA_VERSION
    )
    provenance: PilotProvenanceBundle
    scenario_envelopes: tuple[ScenarioEnvelope, ...] = ()
    obligation_plan: TaxonomyObligationPlan | None = None
    candidate_materializations: CandidateMaterializationSet | None = None
    phase2_assessment: HybridCoverageAssessment | None = None
    correspondence: HybridCorrespondenceAttestation | None = None
    resource_map_validation: SystemResourceMapValidation | None = None
    stpa_projection_authority: PinnedStpaProjectionAttestation | None = None
    confirmed_reviews: tuple[ConfirmedCoverageReview, ...] = ()
    projection_set: HybridScenarioProjectionSet | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_untyped_authorities(cls, value: Any) -> Any:
        """Reject raw mappings at the one public typed input boundary."""
        if not isinstance(value, dict):
            return value
        _reject_mapping_authorities(value)
        _reject_mapping_collections(value)
        return value

    @model_validator(mode="after")
    def canonicalize(self) -> "HybridPilotReadinessInputs":
        """Canonicalize typed scenario and review collections."""
        _require_typed_input_collections(self)
        _require_unique_values(
            (item.scenario_id for item in self.scenario_envelopes),
            "scenario envelope IDs must be unique",
        )
        _require_unique_values(
            (item.relation_id for item in self.confirmed_reviews),
            "confirmed review relation IDs must be unique",
        )
        object.__setattr__(
            self,
            "scenario_envelopes",
            tuple(sorted(self.scenario_envelopes, key=lambda item: item.scenario_id)),
        )
        object.__setattr__(
            self,
            "confirmed_reviews",
            tuple(sorted(self.confirmed_reviews, key=lambda item: item.relation_id)),
        )
        return self


def _reject_mapping_authorities(value: dict[str, Any]) -> None:
    """Reject raw mappings for all typed authority fields."""
    for name in (
        "provenance",
        "obligation_plan",
        "candidate_materializations",
        "phase2_assessment",
        "correspondence",
        "resource_map_validation",
        "stpa_projection_authority",
        "projection_set",
    ):
        if isinstance(value.get(name), dict):
            raise TypeError(f"{name} must be a validated typed value")


def _reject_mapping_collections(value: dict[str, Any]) -> None:
    """Reject raw mappings nested in typed scenario/review collections."""
    _reject_scenario_mappings(value.get("scenario_envelopes", ()))
    _reject_review_mappings(value.get("confirmed_reviews", ()))


def _reject_scenario_mappings(values: Sequence[Any]) -> None:
    """Reject raw mappings in the scenario-envelope collection."""
    if any(isinstance(item, dict) for item in values):
        raise TypeError("scenario_envelopes must contain typed ScenarioEnvelope values")


def _reject_review_mappings(values: Sequence[Any]) -> None:
    """Reject raw mappings in the confirmed-review collection."""
    if any(isinstance(item, dict) for item in values):
        raise TypeError("confirmed_reviews must contain validated typed values")


def _require_typed_input_collections(value: HybridPilotReadinessInputs) -> None:
    """Require exact ScenarioEnvelope and ConfirmedCoverageReview leaves."""
    _require_scenario_values_typed(value.scenario_envelopes)
    _require_review_values_typed(value.confirmed_reviews)


def _require_scenario_values_typed(values: Sequence[Any]) -> None:
    """Require every scenario collection member to be a ScenarioEnvelope."""
    if any(not isinstance(item, ScenarioEnvelope) for item in values):
        raise TypeError("scenario_envelopes must contain ScenarioEnvelope values")


def _require_review_values_typed(values: Sequence[Any]) -> None:
    """Require every review collection member to be a confirmed review."""
    if any(not isinstance(item, ConfirmedCoverageReview) for item in values):
        raise TypeError("confirmed_reviews must contain ConfirmedCoverageReview values")


def _require_unique_values(values: Sequence[Any], message: str) -> None:
    """Reject duplicate values in an immutable input collection."""
    values = tuple(values)
    if len(values) != len(set(values)):
        raise ValueError(message)


__all__ = [
    "CandidateId",
    "HYBRID_PILOT_INPUTS_SCHEMA_VERSION",
    "HYBRID_PILOT_RESULT_SCHEMA_VERSION",
    "ModelCallEvidence",
    "PilotExactJoinCounts",
    "PilotProvenanceBundle",
    "PilotReadinessBlocker",
    "PilotTargetIdentity",
    "PILOT_PROVENANCE_SCHEMA_VERSION",
    "HybridPilotReadinessInputs",
    "HybridPilotReadinessResult",
]
