"""Closed contracts for obligation-aware STPA consideration.

The models in this module are deliberately inward-facing.  They carry the
exact Phase 1 obligation identity into the STPA completeness pass without
turning a taxonomy chain into a scenario-generation recipe.  Provider-facing
adapters and orchestration live outside this module; these values are
immutable, closed, and content addressed so those adapters can be replaced
without changing the durable evidence contract.
"""

from __future__ import annotations

import json
from typing import Any, Literal

import yaml
from pydantic import Field, model_validator

from asago_scenario_generator.models.attack_pattern_chain import (
    CanonicalChainStep,
    PrerequisiteCapabilities,
)
from asago_scenario_generator.models.attack_pattern_projection import (
    CanonicalResourceReference,
)
from asago_scenario_generator.models.attack_pattern_contracts import TaxonomyPin
from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    FrozenDict,
    canonical_json_bytes,
    canonical_json_text,
    compute_framed_digest,
    unique_sorted_strings,
)
from asago_scenario_generator.models.artifact_pin import (
    ArtifactPin,
    Digest,
    ObligationId,
    TraceReference,
)
from asago_scenario_generator.models.obligation_plan import (
    EvidenceRecord,
    ObligationQualificationDisposition,
    RiskReference,
    TaxonomyChainEntry,
)


OBLIGATION_CONSIDERATION_SCHEMA_VERSION = "stpa-obligation-consideration-v1"
OBLIGATION_CONSIDERATION_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-obligation-consideration:v1"
)
NEUTRAL_OBLIGATION_BRIEF_DIGEST_DOMAIN = (
    "asago-scenario-generator:neutral-obligation-brief:v1"
)
OBLIGATION_ROUTE_ID_DOMAIN = "asago-scenario-generator:obligation-route:v1"
OBLIGATION_GAP_ID_DOMAIN = "asago-scenario-generator:obligation-gap:v1"
ICA_CONSIDERATION_ID_DOMAIN = "asago-scenario-generator:obligation-ica-consideration:v1"
TAXONOMY_OBLIGATION_PLAN_ARTIFACT_ID = "taxonomy-obligation-plan"
OBLIGATION_ACCOUNTING_SCHEMA_VERSION = "stpa-obligation-accounting-v1"

ObligationRouteDisposition = Literal[
    "targeted", "proposed_not_applicable", "upstream_gap", "unresolved"
]
MechanismAssessment = Literal[
    "plausible_in_system", "absent_from_system", "insufficient_evidence"
]
RiskAlignment = Literal["supported", "mismatch", "insufficient_evidence"]
MappingStrength = Literal[
    "direct_curated_pair",
    "exact_then_category_expansion",
    "broad_category_expansion",
    "related_category_expansion",
]
StructuralConceptKind = Literal[
    "loss",
    "hazard",
    "constraint",
    "responsibility",
    "control_action",
    "process_model_part",
    "feedback_channel",
    "controlled_process",
    "coordination_link",
    "coordination_mechanism",
    "control_structure",
]
IcaConsiderationDisposition = Literal[
    "finding", "proposed_not_applicable", "unresolved"
]
RevisionStatus = Literal["not_required", "applied", "rejected", "technical_failure"]
DiagnosticSeverity = Literal["info", "warning", "error"]


class _ConsiderationModel(ClosedCanonicalModel):
    """Common closed and immutable configuration for consideration records."""


def _canonical_strings(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    """Return unique, stable strings for set-like contract fields."""
    return unique_sorted_strings(values, label)


def _canonical_pins(values: tuple[ArtifactPin, ...]) -> tuple[ArtifactPin, ...]:
    """Sort artifact pins and reject duplicate artifact identities."""
    ordered = tuple(
        sorted(
            values, key=lambda item: canonical_json_bytes(item.model_dump(mode="json"))
        )
    )
    identities = tuple(
        (item.artifact_id, item.schema_version, item.semantic_digest)
        for item in ordered
    )
    if len({item[0] for item in identities}) != len(identities):
        raise ValueError("source pins must contain unique artifact IDs")
    return ordered


def _canonical_pin_map(values: dict[str, TaxonomyPin], label: str) -> FrozenDict:
    """Freeze and canonicalize one taxonomy pin map."""
    if not values:
        raise ValueError(f"{label} must not be empty")
    return FrozenDict({key: values[key] for key in sorted(values)})


def _canonical_refs(
    values: tuple[CanonicalResourceReference, ...], label: str
) -> tuple[CanonicalResourceReference, ...]:
    """Sort typed resource references and reject duplicate identities."""
    ordered = tuple(
        sorted(
            values, key=lambda item: canonical_json_bytes(item.model_dump(mode="json"))
        )
    )
    identities = tuple(
        canonical_json_bytes(item.model_dump(mode="json")) for item in ordered
    )
    if len(identities) != len(set(identities)):
        raise ValueError(f"{label} must contain unique references")
    return ordered


class ConsiderationDiagnostic(_ConsiderationModel):
    """One retained diagnostic that does not silently erase an obligation."""

    code: str = Field(min_length=1)
    detail: str = Field(min_length=1)
    severity: DiagnosticSeverity = "warning"
    obligation_ids: tuple[ObligationId, ...] = ()
    gap_ids: tuple[str, ...] = ()
    refs: tuple[str, ...] = ()

    @model_validator(mode="after")
    def canonicalize(self) -> "ConsiderationDiagnostic":
        for field_name in ("obligation_ids", "gap_ids", "refs"):
            object.__setattr__(
                self,
                field_name,
                _canonical_strings(getattr(self, field_name), field_name),
            )
        return self


class ConsiderationCallEvidence(_ConsiderationModel):
    """Bounded model-call evidence retained by consideration or revision."""

    call_id: str = Field(min_length=1)
    request_digest: Digest | None = None
    response_digest: Digest | None = None
    model_profile: str | None = None
    model_name: str | None = None
    attempt_count: int = Field(default=1, ge=1, strict=True)
    outcome: Literal["accepted", "rejected", "unresolved", "technical_failure"]


class MissingStructuralConcept(_ConsiderationModel):
    """A typed upstream STPA concept needed for meaningful analysis."""

    concept_type: StructuralConceptKind
    description: str = Field(min_length=1)
    concept_id: str | None = None
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    obligation_id: ObligationId | None = None
    gap_id: str | None = None

    @model_validator(mode="after")
    def canonicalize_and_identify(self) -> "MissingStructuralConcept":
        object.__setattr__(
            self,
            "evidence_refs",
            _canonical_strings(self.evidence_refs, "evidence_refs"),
        )
        expected = compute_framed_digest(
            OBLIGATION_GAP_ID_DOMAIN,
            {
                "obligation_id": self.obligation_id,
                "concept_type": self.concept_type,
                "concept_id": self.concept_id,
                "description": self.description,
                "evidence_refs": self.evidence_refs,
            },
        )
        if self.gap_id is not None and self.gap_id != f"gap:v1:{expected}":
            raise ValueError("gap_id does not match the missing structural concept")
        object.__setattr__(self, "gap_id", f"gap:v1:{expected}")
        return self


class NeutralObligationBrief(_ConsiderationModel):
    """A non-prescriptive STPA question derived from one Phase 1 obligation."""

    obligation_id: ObligationId
    risk_ref: RiskReference
    attack_pattern_id: str = Field(min_length=1)
    attack_pattern_name: str = Field(min_length=1)
    attack_pattern_description: str = Field(min_length=1)
    attack_pattern_semantic_digest: Digest
    taxonomy_chain: tuple[TaxonomyChainEntry, ...] = Field(min_length=1)
    prerequisite_capabilities: PrerequisiteCapabilities
    qualification_disposition: ObligationQualificationDisposition
    applicability_evidence: tuple[EvidenceRecord, ...]
    resource_references: tuple[CanonicalResourceReference, ...] = ()
    candidate_ids: tuple[str, ...] = ()
    plan_digest: Digest
    catalog_pins: dict[str, TaxonomyPin]
    mapping_pins: dict[str, TaxonomyPin]
    instruction: str = (
        "Treat this taxonomy concern as a hypothesis for structural STPA analysis. "
        "It is not a mandatory mechanism, ordered attack sequence, or coverage claim. "
        "Identify the system-specific losses, hazards, constraints, and control path "
        "that make the concern applicable, or provide explicit structural evidence "
        "for non-applicability."
    )
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "NeutralObligationBrief":
        if self.mapping_pins.keys() != {"sssom", "obligation_edges"}:
            raise ValueError(
                "mapping_pins must contain exactly 'sssom' and 'obligation_edges'"
            )
        object.__setattr__(
            self, "catalog_pins", _canonical_pin_map(self.catalog_pins, "catalog_pins")
        )
        object.__setattr__(
            self, "mapping_pins", _canonical_pin_map(self.mapping_pins, "mapping_pins")
        )
        # Taxonomy chain order is semantic provenance, not a set-like
        # collection.  Preserve the exact Phase 1 order in the brief.
        object.__setattr__(
            self,
            "resource_references",
            _canonical_refs(self.resource_references, "resource_references"),
        )
        object.__setattr__(
            self,
            "candidate_ids",
            _canonical_strings(self.candidate_ids, "candidate_ids"),
        )
        if "hypothesis" not in self.instruction.lower():
            raise ValueError("neutral brief instruction must identify a hypothesis")
        if "mandatory" not in self.instruction.lower():
            raise ValueError(
                "neutral brief instruction must reject mandatory mechanisms"
            )
        expected = self.compute_semantic_digest()
        if self.semantic_digest is not None and self.semantic_digest != expected:
            raise ValueError("neutral obligation brief semantic_digest does not match")
        object.__setattr__(self, "semantic_digest", expected)
        return self

    @property
    def question(self) -> str:
        """The neutral instruction presented to a structural STPA adapter."""
        return self.instruction

    @property
    def prompt(self) -> str:
        """Compatibility alias for adapters that call the question a prompt."""
        return self.instruction

    @property
    def attack_pattern_steps(self) -> tuple[CanonicalChainStep, ...]:
        """Return no ordered steps: the neutral brief intentionally omits them."""
        return ()

    def _digest_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"semantic_digest"})

    def compute_semantic_digest(self) -> str:
        """Compute the version-framed brief digest."""
        return compute_framed_digest(
            NEUTRAL_OBLIGATION_BRIEF_DIGEST_DOMAIN, self._digest_payload()
        )

    def assert_integrity(self) -> None:
        """Raise when brief content or its digest has been altered."""
        if self.semantic_digest != self.compute_semantic_digest():
            raise ValueError("neutral obligation brief digest mismatch")


class ObligationSemanticAssessment(_ConsiderationModel):
    """Two independent judgements about a risk/pattern pair."""

    mechanism_assessment: MechanismAssessment
    risk_alignment: RiskAlignment
    mapping_strength: MappingStrength
    mechanism_rationale: str = Field(min_length=1)
    risk_alignment_rationale: str = Field(min_length=1)


class ObligationRoute(_ConsiderationModel):
    """STPA's provisional structural placement for one obligation."""

    route_id: str | None = None
    obligation_id: ObligationId
    disposition: ObligationRouteDisposition
    semantic_assessment: ObligationSemanticAssessment | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    slot_ids: tuple[str, ...] = ()
    controller_ids: tuple[str, ...] = ()
    control_action_ids: tuple[str, ...] = ()
    responsibility_ids: tuple[str, ...] = ()
    process_model_part_ids: tuple[str, ...] = ()
    feedback_channel_ids: tuple[str, ...] = ()
    controlled_process_ids: tuple[str, ...] = ()
    coordination_link_ids: tuple[str, ...] = ()
    hazard_ids: tuple[str, ...] = ()
    constraint_ids: tuple[str, ...] = ()
    missing_concepts: tuple[MissingStructuralConcept, ...] = ()
    rationale: str | None = None
    evidence: tuple[str, ...] = ()
    model_call_refs: tuple[str, ...] = ()
    trace_refs: tuple[TraceReference, ...] = ()
    diagnostics: tuple[ConsiderationDiagnostic, ...] = ()

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> "ObligationRoute":
        for field_name in (
            "slot_ids",
            "controller_ids",
            "control_action_ids",
            "responsibility_ids",
            "process_model_part_ids",
            "feedback_channel_ids",
            "controlled_process_ids",
            "coordination_link_ids",
            "hazard_ids",
            "constraint_ids",
            "evidence",
            "model_call_refs",
        ):
            object.__setattr__(
                self,
                field_name,
                _canonical_strings(getattr(self, field_name), field_name),
            )
        concepts = tuple(
            sorted(
                self.missing_concepts,
                key=lambda item: item.gap_id or "",
            )
        )
        if len({item.gap_id for item in concepts}) != len(concepts):
            raise ValueError("missing structural concepts must be unique")
        object.__setattr__(self, "missing_concepts", concepts)
        excluded = {"route_id"}
        if self.semantic_assessment is None:
            # Preserve the established route identity for compatibility
            # adapters that use the pre-assessment contract.
            excluded.add("semantic_assessment")
        route_payload = self.model_dump(mode="json", exclude=excluded)
        expected = f"route:v1:{compute_framed_digest(OBLIGATION_ROUTE_ID_DOMAIN, route_payload)}"
        if self.route_id is not None and self.route_id != expected:
            raise ValueError("route_id does not match route content")
        object.__setattr__(self, "route_id", expected)
        if not self.evidence:
            raise ValueError("obligation routes require evidence")
        if self.disposition == "targeted":
            if not self.slot_ids:
                raise ValueError("targeted routes require at least one slot")
            if not self.hazard_ids or not self.constraint_ids:
                raise ValueError(
                    "targeted routes require hazard and constraint references"
                )
            if self.missing_concepts:
                raise ValueError(
                    "targeted routes cannot retain missing structural concepts"
                )
        elif self.disposition == "proposed_not_applicable":
            if not self.rationale:
                raise ValueError("proposed non-applicable routes require a rationale")
            if self.missing_concepts:
                raise ValueError("non-applicable routes cannot retain upstream gaps")
        elif self.disposition == "upstream_gap":
            if not self.missing_concepts:
                raise ValueError(
                    "upstream-gap routes require missing structural concepts"
                )
            if not self.rationale:
                raise ValueError("upstream-gap routes require a rationale")
        elif not self.rationale:
            raise ValueError("unresolved routes require a rationale")
        return self


class RevisionAddition(_ConsiderationModel):
    """One request-local additive structural revision authored by an adapter."""

    addition_id: str = Field(min_length=1)
    concept_type: StructuralConceptKind
    description: str = Field(min_length=1)
    references: tuple[str, ...] = ()
    request_handle: str = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize(self) -> "RevisionAddition":
        object.__setattr__(
            self, "references", _canonical_strings(self.references, "references")
        )
        return self


class StructuralRevisionDelta(_ConsiderationModel):
    """Typed additive revision proposal/acceptance without mutable raw blobs."""

    additions: tuple[RevisionAddition, ...] = ()
    trigger_gap_ids: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()

    @model_validator(mode="after")
    def canonicalize(self) -> "StructuralRevisionDelta":
        object.__setattr__(
            self,
            "additions",
            tuple(sorted(self.additions, key=lambda item: item.addition_id)),
        )
        ids = tuple(item.addition_id for item in self.additions)
        if len(ids) != len(set(ids)):
            raise ValueError("revision additions must have unique IDs")
        object.__setattr__(
            self,
            "trigger_gap_ids",
            _canonical_strings(self.trigger_gap_ids, "trigger_gap_ids"),
        )
        object.__setattr__(
            self, "evidence", _canonical_strings(self.evidence, "evidence")
        )
        return self


RevisionDelta = StructuralRevisionDelta


class BoundedStructuralRevision(_ConsiderationModel):
    """The single bounded additive structural revision opportunity."""

    status: RevisionStatus = "not_required"
    baseline_pins: tuple[ArtifactPin, ...] = ()
    trigger_obligation_ids: tuple[ObligationId, ...] = ()
    trigger_gap_ids: tuple[str, ...] = ()
    proposed_delta: StructuralRevisionDelta | None = None
    accepted_delta: StructuralRevisionDelta | None = None
    rejected_additions: tuple[RevisionAddition, ...] = ()
    revised_pins: tuple[ArtifactPin, ...] = ()
    call_evidence: tuple[ConsiderationCallEvidence, ...] = ()

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> "BoundedStructuralRevision":
        object.__setattr__(self, "baseline_pins", _canonical_pins(self.baseline_pins))
        object.__setattr__(self, "revised_pins", _canonical_pins(self.revised_pins))
        object.__setattr__(
            self,
            "trigger_obligation_ids",
            _canonical_strings(self.trigger_obligation_ids, "trigger_obligation_ids"),
        )
        object.__setattr__(
            self,
            "trigger_gap_ids",
            _canonical_strings(self.trigger_gap_ids, "trigger_gap_ids"),
        )
        rejected = tuple(
            sorted(self.rejected_additions, key=lambda item: item.addition_id)
        )
        if len({item.addition_id for item in rejected}) != len(rejected):
            raise ValueError("rejected revision additions must have unique IDs")
        object.__setattr__(self, "rejected_additions", rejected)
        if self.status == "not_required":
            if (
                self.trigger_obligation_ids
                or self.trigger_gap_ids
                or self.proposed_delta
                or self.accepted_delta
                or self.rejected_additions
                or self.revised_pins
                or self.call_evidence
            ):
                raise ValueError(
                    "not_required revision cannot contain revision activity"
                )
        elif not self.trigger_obligation_ids or not self.trigger_gap_ids:
            raise ValueError("a revision outcome requires trigger obligations and gaps")
        if self.status == "applied":
            if self.proposed_delta is None or self.accepted_delta is None:
                raise ValueError(
                    "applied revision requires proposed and accepted deltas"
                )
            if not self.revised_pins:
                raise ValueError("applied revision requires revised artifact pins")
        elif self.accepted_delta is not None:
            raise ValueError("only an applied revision may retain an accepted delta")
        return self


class ObligationConsideration(_ConsiderationModel):
    """Content-addressed consideration artifact for every applicable brief."""

    schema_version: Literal[OBLIGATION_CONSIDERATION_SCHEMA_VERSION] = (
        OBLIGATION_CONSIDERATION_SCHEMA_VERSION
    )
    semantic_digest: Digest | None = None
    source_pins: tuple[ArtifactPin, ...] = Field(min_length=1)
    briefs: tuple[NeutralObligationBrief, ...]
    initial_routes: tuple[ObligationRoute, ...]
    revision: BoundedStructuralRevision = BoundedStructuralRevision()
    rechecked_routes: tuple[ObligationRoute, ...] = ()
    final_routes: tuple[ObligationRoute, ...]
    diagnostics: tuple[ConsiderationDiagnostic, ...] = ()

    @model_validator(mode="after")
    def canonicalize_validate_and_digest(self) -> "ObligationConsideration":
        object.__setattr__(self, "source_pins", _canonical_pins(self.source_pins))
        briefs = tuple(sorted(self.briefs, key=lambda item: item.obligation_id))
        brief_ids = tuple(item.obligation_id for item in briefs)
        if len(brief_ids) != len(set(brief_ids)):
            raise ValueError("neutral briefs must have unique obligation IDs")
        object.__setattr__(self, "briefs", briefs)
        for brief in briefs:
            brief.assert_integrity()
        expected_plan_digest = {brief.plan_digest for brief in briefs}
        if len(expected_plan_digest) > 1:
            raise ValueError("all briefs must use one Phase 1 plan digest")
        plan_pin = next(
            (
                pin
                for pin in self.source_pins
                if pin.artifact_id == TAXONOMY_OBLIGATION_PLAN_ARTIFACT_ID
            ),
            None,
        )
        if expected_plan_digest and (
            plan_pin is None or plan_pin.semantic_digest not in expected_plan_digest
        ):
            raise ValueError("source_pins must include the exact Phase 1 plan pin")
        initial = _canonical_routes(self.initial_routes, brief_ids, "initial_routes")
        final = _canonical_routes(self.final_routes, brief_ids, "final_routes")
        rechecked = _canonical_routes(
            self.rechecked_routes, brief_ids, "rechecked_routes", allow_empty=True
        )
        object.__setattr__(self, "initial_routes", initial)
        object.__setattr__(self, "final_routes", final)
        object.__setattr__(self, "rechecked_routes", rechecked)
        if self.revision.status == "applied":
            if tuple(item.obligation_id for item in rechecked) != brief_ids:
                raise ValueError(
                    "an applied revision must recheck every applicable obligation"
                )
            if final != rechecked:
                raise ValueError("final routes must be the applied revision recheck")
        elif rechecked:
            raise ValueError("rechecked routes require an applied structural revision")
        elif final != initial:
            raise ValueError(
                "without an applied revision final routes equal initial routes"
            )
        diagnostics = tuple(
            sorted(self.diagnostics, key=lambda item: (item.code, item.detail))
        )
        object.__setattr__(self, "diagnostics", diagnostics)
        expected = self.compute_semantic_digest()
        if self.semantic_digest is not None and self.semantic_digest != expected:
            raise ValueError("obligation consideration semantic_digest does not match")
        object.__setattr__(self, "semantic_digest", expected)
        return self

    def _digest_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"semantic_digest"})

    def compute_semantic_digest(self) -> str:
        """Compute the version-framed consideration digest."""
        return compute_framed_digest(
            OBLIGATION_CONSIDERATION_DIGEST_DOMAIN, self._digest_payload()
        )

    def assert_integrity(self) -> None:
        """Verify nested briefs and the artifact digest."""
        for brief in self.briefs:
            brief.assert_integrity()
        if self.semantic_digest != self.compute_semantic_digest():
            raise ValueError("obligation consideration digest mismatch")

    def to_yaml(self) -> str:
        """Serialize the closed artifact as canonical YAML."""
        self.assert_integrity()
        return yaml.dump(
            self.model_dump(mode="json"),
            default_flow_style=False,
            sort_keys=True,
            allow_unicode=True,
        )

    def to_json(self) -> str:
        """Serialize stable diagnostic JSON."""
        self.assert_integrity()
        return canonical_json_text(self.model_dump(mode="json"))

    @classmethod
    def from_yaml(cls, value: str | bytes) -> "ObligationConsideration":
        """Load a closed artifact and verify its schema and digest."""
        data = yaml.safe_load(value)
        if not isinstance(data, dict):
            raise ValueError("YAML data must be a dictionary")
        return cls._load_checked(data)

    @classmethod
    def from_json(cls, value: str | bytes) -> "ObligationConsideration":
        """Load a closed JSON artifact and verify its schema and digest."""
        try:
            data = json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid JSON obligation consideration: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON data must be a dictionary")
        return cls._load_checked(data)

    @classmethod
    def _load_checked(cls, data: dict[str, Any]) -> "ObligationConsideration":
        if data.get("schema_version") != OBLIGATION_CONSIDERATION_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported schema version: '{data.get('schema_version')}' is unsupported"
            )
        artifact = cls.model_validate(data)
        artifact.assert_integrity()
        return artifact


def _canonical_routes(
    values: tuple[ObligationRoute, ...],
    expected_ids: tuple[str, ...],
    label: str,
    *,
    allow_empty: bool = False,
) -> tuple[ObligationRoute, ...]:
    """Sort a route set and enforce exact one-per-brief identity."""
    if not values and allow_empty:
        return ()
    routes = tuple(sorted(values, key=lambda item: item.obligation_id))
    ids = tuple(item.obligation_id for item in routes)
    if len(ids) != len(set(ids)):
        raise ValueError(f"{label} contains duplicate obligation IDs")
    if ids != expected_ids:
        raise ValueError(f"{label} must contain exactly one route per applicable brief")
    return routes


class ObligationIcaConsideration(_ConsiderationModel):
    """One exact routed obligation/slot result from ICA analysis."""

    pair_id: str | None = None
    route_id: str = Field(min_length=1)
    obligation_id: ObligationId
    slot_id: str = Field(min_length=1)
    disposition: IcaConsiderationDisposition
    ica_ids: tuple[str, ...] = ()
    exec_candidate_ids: tuple[str, ...] = ()
    hazard_ids: tuple[str, ...] = ()
    constraint_ids: tuple[str, ...] = ()
    evidence: tuple[str, ...] = Field(min_length=1)
    model_call_refs: tuple[str, ...] = ()
    structural_inventory_complete: bool = False
    rationale: str | None = None
    diagnostics: tuple[ConsiderationDiagnostic, ...] = ()

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> "ObligationIcaConsideration":
        for field_name in (
            "ica_ids",
            "exec_candidate_ids",
            "hazard_ids",
            "constraint_ids",
            "evidence",
            "model_call_refs",
        ):
            object.__setattr__(
                self,
                field_name,
                _canonical_strings(getattr(self, field_name), field_name),
            )
        for candidate_id in self.exec_candidate_ids:
            if not candidate_id.startswith("EXEC:"):
                raise ValueError(
                    "execution candidate IDs must use canonical EXEC:* identity"
                )
        payload = self.model_dump(mode="json", exclude={"pair_id"})
        expected = (
            f"pair:v1:{compute_framed_digest(ICA_CONSIDERATION_ID_DOMAIN, payload)}"
        )
        if self.pair_id is not None and self.pair_id != expected:
            raise ValueError(
                "pair_id does not match obligation/slot consideration content"
            )
        object.__setattr__(self, "pair_id", expected)
        if self.disposition == "finding":
            if not self.ica_ids or not self.exec_candidate_ids:
                raise ValueError(
                    "finding considerations require ICA and EXEC identities"
                )
            if not self.hazard_ids or not self.constraint_ids:
                raise ValueError(
                    "finding considerations require hazard and constraint identities"
                )
        elif self.disposition == "proposed_not_applicable":
            if self.ica_ids or self.exec_candidate_ids:
                raise ValueError(
                    "non-applicable ICA considerations cannot retain findings"
                )
            if not self.structural_inventory_complete:
                raise ValueError(
                    "proposed non-applicability requires complete structural inventory"
                )
            if not self.rationale:
                raise ValueError("proposed non-applicability requires a rationale")
        elif self.ica_ids or self.exec_candidate_ids:
            raise ValueError("unresolved ICA considerations cannot retain findings")
        return self


__all__ = [
    "BoundedStructuralRevision",
    "ConsiderationCallEvidence",
    "ConsiderationDiagnostic",
    "DiagnosticSeverity",
    "IcaConsiderationDisposition",
    "MissingStructuralConcept",
    "MechanismAssessment",
    "MappingStrength",
    "NeutralObligationBrief",
    "OBLIGATION_ACCOUNTING_SCHEMA_VERSION",
    "OBLIGATION_CONSIDERATION_DIGEST_DOMAIN",
    "OBLIGATION_CONSIDERATION_SCHEMA_VERSION",
    "ObligationConsideration",
    "ObligationIcaConsideration",
    "ObligationRoute",
    "ObligationRouteDisposition",
    "ObligationSemanticAssessment",
    "RevisionAddition",
    "RevisionDelta",
    "RiskAlignment",
    "StructuralConceptKind",
    "StructuralRevisionDelta",
]
