"""Closed contracts for the normative observational hybrid assessment."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from asago_scenario_generator.models.canonical import (
    canonical_json_bytes,
    canonical_json_text,
    compute_framed_digest,
    normalize_unicode,
)

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
RelationId = Annotated[str, Field(pattern=r"^correlation:v1:[0-9a-f]{64}$")]
ProposalId = Annotated[str, Field(pattern=r"^corrp:v1:[0-9a-f]{64}$")]
ObligationId = Annotated[str, Field(pattern=r"^ob:v1:[0-9a-f]{64}$")]

HYBRID_COVERAGE_ASSESSMENT_SCHEMA_VERSION = "hybrid-coverage-assessment-v1"
HYBRID_COVERAGE_ASSESSMENT_DIGEST_DOMAIN = (
    "asago-scenario-generator:hybrid-coverage-assessment:v1"
)
ICA_ENUMERATION_DIGEST_DOMAIN = "asago-scenario-generator:ica-enumeration:v1"

InventoryStatus = Literal["complete", "partial", "unknown"]
UcaType = Literal[
    "NOT_PROVIDED",
    "INCORRECT",
    "WRONG_TIMING",
    "WRONG_DURATION",
]
StructuralDisposition = Literal["ica", "justified_na", "unresolved"]
CorrespondenceDisposition = Literal[
    "satisfied",
    "structurally_inapplicable",
    "unresolved_missing_resource_map",
    "unresolved_no_proposal",
    "unresolved_ambiguous",
    "unresolved_rejected_proposals",
    "governance_only",
    "capability_excluded",
]
GapReason = Literal[
    "phase1_not_applicable",
    "reviewed_structural_inapplicability",
    "missing_resource_map",
    "no_accepted_proposal",
    "ambiguous_proposals",
    "rejected_proposals",
    "contradictory_proposals",
    "related_but_not_coverage",
]
FindingKind = Literal[
    "related_but_not_coverage",
    "contradictory_proposals",
]


class _AssessmentModel(BaseModel):
    """Common closed, immutable configuration for persisted values."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def normalize_input(cls, value: Any) -> Any:
        """Normalize Unicode before validating identities or digests."""
        return normalize_unicode(value)


class ArtifactPin(_AssessmentModel):
    """Content-addressed identity of one upstream artifact."""

    artifact_id: str = Field(min_length=1)
    schema_version: str = Field(min_length=1)
    semantic_digest: Digest


class TraceReference(_AssessmentModel):
    """Reference to one exact record in a pinned artifact."""

    artifact_id: str = Field(min_length=1)
    schema_version: str = Field(min_length=1)
    semantic_digest: Digest
    record_id: str = Field(min_length=1)


class TaxonomyScenarioObservation(_AssessmentModel):
    """Legacy taxonomy scenario observed without changing its workflow."""

    scenario_id: str = Field(min_length=1)
    obligation_id: ObligationId
    candidate_id: str = Field(pattern=r"^cand:v2:[0-9a-f]{32}$")
    source_artifact: ArtifactPin
    trace_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize(self) -> "TaxonomyScenarioObservation":
        """Canonicalize and preserve exact legacy trace references."""
        object.__setattr__(
            self, "trace_refs", _unique_sorted(self.trace_refs, "trace_refs")
        )
        return self


class StructuralInapplicabilityDecision(_AssessmentModel):
    """Explicit reviewed decision that an obligation has no structural path."""

    decision_id: str = Field(min_length=1)
    obligation_id: ObligationId
    rationale: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    adjudicated_by: str = Field(min_length=1)
    inventory_status: InventoryStatus
    other_authoritative_evidence_refs: tuple[str, ...] = ()
    source_artifact: ArtifactPin
    trace_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_evidence(self) -> "StructuralInapplicabilityDecision":
        """Reject closed-world absence over incomplete evidence."""
        for field_name in (
            "evidence_refs",
            "other_authoritative_evidence_refs",
            "trace_refs",
        ):
            object.__setattr__(
                self,
                field_name,
                _unique_sorted(getattr(self, field_name), field_name),
            )
        if (
            self.inventory_status != "complete"
            and not self.other_authoritative_evidence_refs
        ):
            raise ValueError(
                "partial or unknown inventory requires other authoritative evidence"
            )
        return self


class TaxonomyCoverageInput(_AssessmentModel):
    """Typed legacy taxonomy observations and explicit absence decisions."""

    scenarios: tuple[TaxonomyScenarioObservation, ...] = ()
    structural_inapplicability_decisions: tuple[
        StructuralInapplicabilityDecision, ...
    ] = ()

    @model_validator(mode="after")
    def canonicalize(self) -> "TaxonomyCoverageInput":
        """Keep one scenario and at most one decision per exact identity."""
        scenarios = tuple(sorted(self.scenarios, key=lambda item: item.scenario_id))
        decisions = tuple(
            sorted(
                self.structural_inapplicability_decisions,
                key=lambda item: item.decision_id,
            )
        )
        _require_unique(
            tuple(item.scenario_id for item in scenarios),
            "taxonomy scenario IDs must be unique",
        )
        _require_unique(
            tuple(item.decision_id for item in decisions),
            "structural-inapplicability decision IDs must be unique",
        )
        _require_unique(
            tuple(item.obligation_id for item in decisions),
            "at most one structural-inapplicability decision is allowed per obligation",
        )
        object.__setattr__(self, "scenarios", scenarios)
        object.__setattr__(self, "structural_inapplicability_decisions", decisions)
        return self


class StpaScenarioObservation(_AssessmentModel):
    """Legacy STPA scenario linked to one exact slot and ICA."""

    scenario_id: str = Field(min_length=1)
    ica_slot_id: str = Field(min_length=1)
    ica_id: str = Field(min_length=1)
    exec_candidate_id: str = Field(pattern=r"^EXEC:[^:]+:[^:]+:[A-Z_]+$")
    source_artifact: ArtifactPin
    trace_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize(self) -> "StpaScenarioObservation":
        """Canonicalize exact legacy trace references."""
        object.__setattr__(
            self, "trace_refs", _unique_sorted(self.trace_refs, "trace_refs")
        )
        return self


class StructuralSlotObservation(_AssessmentModel):
    """One deterministic UCA slot in the complete structural universe."""

    slot_id: str = Field(min_length=1)
    controller_id: str = Field(min_length=1)
    control_action_id: str = Field(min_length=1)
    uca_type: UcaType
    ica_ids: tuple[str, ...] = ()
    disposition: StructuralDisposition
    evidence: tuple[str, ...] = Field(min_length=1)
    source_artifact: ArtifactPin
    trace_refs: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_disposition(self) -> "StructuralSlotObservation":
        """Require ICA presence to agree exactly with the slot disposition."""
        for field_name in ("ica_ids", "evidence", "trace_refs"):
            object.__setattr__(
                self,
                field_name,
                _unique_sorted(getattr(self, field_name), field_name),
            )
        has_icas = bool(self.ica_ids)
        if (self.disposition == "ica") != has_icas:
            raise ValueError("structural disposition 'ica' requires ICA identities")
        return self


class StpaCoverageInput(_AssessmentModel):
    """Complete structural denominator plus optional legacy STPA scenarios."""

    slots: tuple[StructuralSlotObservation, ...] = ()
    scenarios: tuple[StpaScenarioObservation, ...] = ()
    inventory_status: InventoryStatus

    @classmethod
    def from_ica_enumeration(
        cls,
        ica_enumeration: Any,
        *,
        artifact_id: str = "ica-enumeration",
        schema_version: str = "ica-enumeration-v1",
        scenarios: Sequence[StpaScenarioObservation] = (),
        inventory_status: InventoryStatus = "complete",
    ) -> "StpaCoverageInput":
        """Deterministically adapt a real ICAEnumeration with an exact pin."""
        from asago_scenario_generator.models.correspondence import (
            compute_ica_enumeration_digest,
        )
        from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration

        if not isinstance(ica_enumeration, ICAEnumeration):
            raise TypeError("ica_enumeration must be an ICAEnumeration")
        pin = ArtifactPin(
            artifact_id=artifact_id,
            schema_version=schema_version,
            semantic_digest=compute_ica_enumeration_digest(ica_enumeration),
        )
        slots = tuple(
            _slot_from_ica_enumeration(item, pin) for item in ica_enumeration.slots
        )
        return cls(
            slots=slots,
            scenarios=tuple(scenarios),
            inventory_status=inventory_status,
        )

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> "StpaCoverageInput":
        """Validate the complete slot/ICA/EXEC identity graph."""
        slots = _canonical_slots(self.slots)
        scenarios = _canonical_stpa_scenarios(self.scenarios)
        _require_one_slot_artifact(slots)
        _validate_stpa_scenarios(scenarios, slots)
        object.__setattr__(self, "slots", slots)
        object.__setattr__(self, "scenarios", scenarios)
        return self


def _canonical_slots(
    slots: Sequence[StructuralSlotObservation],
) -> tuple[StructuralSlotObservation, ...]:
    """Sort the slot denominator and reject duplicate identities."""
    ordered = tuple(sorted(slots, key=lambda item: item.slot_id))
    _require_unique(
        tuple(item.slot_id for item in ordered), "UCA slot IDs must be unique"
    )
    return ordered


def _canonical_stpa_scenarios(
    scenarios: Sequence[StpaScenarioObservation],
) -> tuple[StpaScenarioObservation, ...]:
    """Sort legacy scenario observations and reject duplicate identities."""
    ordered = tuple(sorted(scenarios, key=lambda item: item.scenario_id))
    _require_unique(
        tuple(item.scenario_id for item in ordered),
        "STPA scenario IDs must be unique",
    )
    return ordered


def _require_one_slot_artifact(slots: Sequence[StructuralSlotObservation]) -> None:
    """Require the structural denominator to come from one exact enumeration."""
    if len({item.source_artifact for item in slots}) > 1:
        raise ValueError("all UCA slots must come from one exact ICA enumeration")


def _validate_stpa_scenarios(
    scenarios: Sequence[StpaScenarioObservation],
    slots: Sequence[StructuralSlotObservation],
) -> None:
    """Validate each scenario against the canonical slot index."""
    slots_by_id = {item.slot_id: item for item in slots}
    for scenario in scenarios:
        _validate_scenario_observation(scenario, slots_by_id)


def _slot_from_ica_enumeration(
    value: Any, pin: ArtifactPin
) -> StructuralSlotObservation:
    """Project one real ICASlot without changing its structural meaning."""
    controller = value.responsibility or value.coordination_link
    if not controller:
        raise ValueError("ICA slot must identify a responsibility or coordination link")
    ica_ids = tuple(item.ica_id for item in value.icas)
    disposition, evidence = _ica_slot_disposition(value, ica_ids)
    return StructuralSlotObservation(
        slot_id=value.slot_id,
        controller_id=controller,
        control_action_id=value.control_action,
        uca_type=value.uca_type.value,
        ica_ids=ica_ids,
        disposition=disposition,
        evidence=evidence,
        source_artifact=pin,
        trace_refs=(value.slot_id,),
    )


def _ica_slot_disposition(
    value: Any, ica_ids: tuple[str, ...]
) -> tuple[StructuralDisposition, tuple[str, ...]]:
    """Project the mutually exclusive ICA versus justified-N/A state."""
    if value.is_na:
        return "justified_na", (value.na_justification,)
    return "ica", ica_ids


def _validate_scenario_observation(
    scenario: StpaScenarioObservation,
    slots_by_id: dict[str, StructuralSlotObservation],
) -> None:
    """Require one scenario to resolve to a slot, ICA, and canonical EXEC ID."""
    slot = slots_by_id.get(scenario.ica_slot_id)
    if slot is None:
        raise ValueError("STPA scenario references an unknown ICA slot")
    if scenario.ica_id not in slot.ica_ids:
        raise ValueError("STPA scenario references an unknown ICA")
    if scenario.exec_candidate_id != _exec_candidate_id(slot):
        raise ValueError("STPA scenario substituted the canonical EXEC identity")


def _exec_candidate_id(slot: StructuralSlotObservation) -> str:
    """Return the canonical execution-candidate identity for one slot."""
    return f"EXEC:{slot.controller_id}:{slot.control_action_id}:{slot.uca_type}"


class ProposalOutcome(_AssessmentModel):
    """Rejected or unresolved proposal retained outside all coverage credit."""

    proposal_id: ProposalId
    obligation_id: ObligationId
    risk_id: str = Field(min_length=1)
    attack_pattern_id: str = Field(min_length=1)
    taxonomy_candidate_ids: tuple[str, ...] = Field(min_length=1)
    ica_slot_id: str = Field(min_length=1)
    ica_id: str = Field(min_length=1)
    relation_kind: str = Field(min_length=1)
    status: Literal["rejected", "unresolved"]
    validation_result: Literal["accepted", "rejected", "unresolved"]
    validation_codes: tuple[str, ...] = ()
    source_pins: tuple[ArtifactPin, ...] = Field(min_length=3)
    trace_refs: tuple[TraceReference, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize(self) -> "ProposalOutcome":
        """Canonicalize proposal diagnostics and their exact traces."""
        for field_name in ("taxonomy_candidate_ids", "validation_codes"):
            object.__setattr__(
                self,
                field_name,
                _unique_sorted(getattr(self, field_name), field_name),
            )
        _canonicalize_traceable(self)
        return self


class CoverageFinding(_AssessmentModel):
    """Explicit non-satisfying cross-method finding."""

    finding_id: str = Field(pattern=r"^hcaf:v1:[0-9a-f]{64}$")
    kind: FindingKind
    detail: str = Field(min_length=1)
    relation_ids: tuple[RelationId, ...] = ()
    proposal_ids: tuple[ProposalId, ...] = ()
    source_pins: tuple[ArtifactPin, ...] = Field(min_length=3)
    trace_refs: tuple[TraceReference, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize(self) -> "CoverageFinding":
        """Canonicalize all evidence identities retained by the finding."""
        object.__setattr__(
            self, "relation_ids", _unique_sorted(self.relation_ids, "relation_ids")
        )
        object.__setattr__(
            self, "proposal_ids", _unique_sorted(self.proposal_ids, "proposal_ids")
        )
        if not self.relation_ids and not self.proposal_ids:
            raise ValueError("coverage finding must cite a relation or proposal")
        _canonicalize_traceable(self)
        return self


class StructuralConsiderationRow(_AssessmentModel):
    """One row per deterministic UCA slot (source spec §8.11)."""

    row_id: str = Field(pattern=r"^hca-struct:v1:[0-9a-f]{64}$")
    slot_id: str = Field(min_length=1)
    controller_id: str = Field(min_length=1)
    control_action_id: str = Field(min_length=1)
    uca_type: UcaType
    ica_ids: tuple[str, ...] = ()
    disposition: StructuralDisposition
    evidence: tuple[str, ...] = Field(min_length=1)
    source_pins: tuple[ArtifactPin, ...] = Field(min_length=3)
    trace_refs: tuple[TraceReference, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_row(self) -> "StructuralConsiderationRow":
        """Validate structural identity, disposition, pins, and evidence."""
        for field_name in ("ica_ids", "evidence"):
            object.__setattr__(
                self,
                field_name,
                _unique_sorted(getattr(self, field_name), field_name),
            )
        if self.row_id != compute_matrix_row_id("struct", self.slot_id):
            raise ValueError("structural consideration row_id does not match slot")
        if (self.disposition == "ica") != bool(self.ica_ids):
            raise ValueError("structural consideration disposition contradicts ICA IDs")
        _canonicalize_traceable(self)
        return self


class TaxonomyCorrespondenceRow(_AssessmentModel):
    """One row per Phase 1 taxonomy obligation (source spec §8.11)."""

    row_id: str = Field(pattern=r"^hca-tax:v1:[0-9a-f]{64}$")
    obligation_id: ObligationId
    risk_id: str = Field(min_length=1)
    attack_pattern_id: str | None = None
    attack_pattern_semantic_digest: Digest | None = None
    scope_disposition: Literal["applicable", "capability_excluded", "governance_only"]
    qualification_disposition: Literal[
        "ready",
        "missing_evidence",
        "contradictory_evidence",
        "structurally_infeasible",
        "not_attempted",
    ]
    taxonomy_candidate_ids: tuple[str, ...] = ()
    taxonomy_scenario_ids: tuple[str, ...] = ()
    accepted_relation_ids: tuple[RelationId, ...] = ()
    rejected_proposal_ids: tuple[ProposalId, ...] = ()
    unresolved_proposal_ids: tuple[ProposalId, ...] = ()
    finding_ids: tuple[str, ...] = ()
    structural_inapplicability_decision_ids: tuple[str, ...] = ()
    correspondence_disposition: CorrespondenceDisposition
    gap_reason: GapReason | None = None
    source_pins: tuple[ArtifactPin, ...] = Field(min_length=3)
    trace_refs: tuple[TraceReference, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_row(self) -> "TaxonomyCorrespondenceRow":
        """Validate the exact obligation roll-up and its evidence references."""
        for field_name in (
            "taxonomy_candidate_ids",
            "taxonomy_scenario_ids",
            "accepted_relation_ids",
            "rejected_proposal_ids",
            "unresolved_proposal_ids",
            "finding_ids",
            "structural_inapplicability_decision_ids",
        ):
            object.__setattr__(
                self,
                field_name,
                _unique_sorted(getattr(self, field_name), field_name),
            )
        if self.row_id != compute_matrix_row_id("tax", self.obligation_id):
            raise ValueError("taxonomy correspondence row_id does not match obligation")
        _validate_correspondence_rollup(self)
        _canonicalize_traceable(self)
        return self


class ScenarioRealizationRow(_AssessmentModel):
    """One row per accepted and confirmed relation (source spec §8.11)."""

    row_id: str = Field(pattern=r"^hca-real:v1:[0-9a-f]{64}$")
    relation_id: RelationId
    proposal_id: ProposalId
    obligation_id: ObligationId
    risk_id: str = Field(min_length=1)
    attack_pattern_id: str = Field(min_length=1)
    taxonomy_candidate_ids: tuple[str, ...] = Field(min_length=1)
    correspondence_relation_kind: Literal[
        "same_mechanism",
        "mechanism_enables_ica",
        "ica_specializes_mechanism",
        "mechanism_specializes_ica",
        "related_but_not_coverage",
    ]
    coverage_bearing: bool
    legacy_scenario_ids: tuple[str, ...] = ()
    hybrid_generation_status: Literal["not_attempted"] = "not_attempted"
    hybrid_admission_status: Literal["not_assessed"] = "not_assessed"
    source_pins: tuple[ArtifactPin, ...] = Field(min_length=3)
    trace_refs: tuple[TraceReference, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_row(self) -> "ScenarioRealizationRow":
        """Validate accepted-relation identity and noncoverage semantics."""
        for field_name in ("taxonomy_candidate_ids", "legacy_scenario_ids"):
            object.__setattr__(
                self,
                field_name,
                _unique_sorted(getattr(self, field_name), field_name),
            )
        if self.row_id != compute_matrix_row_id("real", self.relation_id):
            raise ValueError("scenario realization row_id does not match relation")
        expected_coverage = (
            self.correspondence_relation_kind != "related_but_not_coverage"
        )
        if self.coverage_bearing != expected_coverage:
            raise ValueError("scenario realization coverage_bearing is false")
        _canonicalize_traceable(self)
        return self


class HybridCoverageDiagnostics(_AssessmentModel):
    """Separate counts for review; never a blended rate or score."""

    structural_ica: int = Field(ge=0)
    structural_justified_na: int = Field(ge=0)
    structural_unresolved: int = Field(ge=0)
    taxonomy_satisfied: int = Field(ge=0)
    taxonomy_structurally_inapplicable: int = Field(ge=0)
    taxonomy_unresolved: int = Field(ge=0)
    taxonomy_not_applicable: int = Field(ge=0)
    unmatched_obligations: int = Field(ge=0)
    accepted_relations: int = Field(ge=0)
    coverage_bearing_relations: int = Field(ge=0)
    rejected_proposals: int = Field(ge=0)
    unresolved_proposals: int = Field(ge=0)
    contradictory_findings: int = Field(ge=0)


def _assessment_payload(assessment: "HybridCoverageAssessment") -> dict[str, Any]:
    """Return semantic content without the derived digest."""
    return {
        "schema_version": assessment.schema_version,
        "capability_snapshot_digest": assessment.capability_snapshot_digest,
        "source_pins": _dump_records(assessment.source_pins),
        "structural_inventory_status": assessment.structural_inventory_status,
        "structural_consideration": _dump_records(assessment.structural_consideration),
        "taxonomy_correspondence": _dump_records(assessment.taxonomy_correspondence),
        "scenario_realization": _dump_records(assessment.scenario_realization),
        "proposal_outcomes": _dump_records(assessment.proposal_outcomes),
        "findings": _dump_records(assessment.findings),
        "diagnostics": assessment.diagnostics.model_dump(mode="json"),
        "network_calls": assessment.network_calls,
        "model_calls": assessment.model_calls,
    }


def _dump_records(values: Sequence[BaseModel]) -> list[dict[str, Any]]:
    """Dump one canonical record collection for digest framing."""
    return [item.model_dump(mode="json") for item in values]


class HybridCoverageAssessment(_AssessmentModel):
    """Canonical three-matrix observational Phase 2 artifact."""

    schema_version: Literal[HYBRID_COVERAGE_ASSESSMENT_SCHEMA_VERSION] = (
        HYBRID_COVERAGE_ASSESSMENT_SCHEMA_VERSION
    )
    semantic_digest: Digest | None = None
    capability_snapshot_digest: Digest
    source_pins: tuple[ArtifactPin, ...] = Field(min_length=3)
    structural_inventory_status: InventoryStatus
    structural_consideration: tuple[StructuralConsiderationRow, ...]
    taxonomy_correspondence: tuple[TaxonomyCorrespondenceRow, ...]
    scenario_realization: tuple[ScenarioRealizationRow, ...]
    proposal_outcomes: tuple[ProposalOutcome, ...] = ()
    findings: tuple[CoverageFinding, ...] = ()
    diagnostics: HybridCoverageDiagnostics
    network_calls: Literal[0] = 0
    model_calls: Literal[0] = 0

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "HybridCoverageAssessment":
        """Canonicalize the artifact and reconcile all cross-matrix claims."""
        for field_name, identity in (
            ("structural_consideration", "slot_id"),
            ("taxonomy_correspondence", "obligation_id"),
            ("scenario_realization", "relation_id"),
            ("proposal_outcomes", "proposal_id"),
            ("findings", "finding_id"),
        ):
            values = tuple(
                sorted(
                    getattr(self, field_name), key=lambda item: getattr(item, identity)
                )
            )
            _require_unique(
                tuple(getattr(item, identity) for item in values),
                f"{field_name} identities must be unique",
            )
            object.__setattr__(self, field_name, values)
        pins = _ordered_models(self.source_pins)
        _require_unique_artifact_pins(pins)
        object.__setattr__(self, "source_pins", pins)
        _require_capability_snapshot_pin(self.capability_snapshot_digest, pins)
        self._validate_contract()
        expected = self.compute_semantic_digest()
        if self.semantic_digest is not None and self.semantic_digest != expected:
            raise ValueError("hybrid coverage semantic_digest does not match content")
        object.__setattr__(self, "semantic_digest", expected)
        return self

    def _validate_contract(self) -> None:
        """Reject incomplete traces, false credit, or divergent diagnostics."""
        traceables = (
            *self.structural_consideration,
            *self.taxonomy_correspondence,
            *self.scenario_realization,
            *self.proposal_outcomes,
            *self.findings,
        )
        _require_complete_source_pins(self.source_pins, traceables)
        _require_reconciled_relation_ids(
            self.taxonomy_correspondence, self.scenario_realization
        )
        _require_reconciled_diagnostics(
            self.diagnostics,
            self.structural_consideration,
            self.taxonomy_correspondence,
            self.scenario_realization,
            self.proposal_outcomes,
            self.findings,
        )

    def compute_semantic_digest(self) -> str:
        """Compute the framed digest over all three independent matrices."""
        return compute_framed_digest(
            HYBRID_COVERAGE_ASSESSMENT_DIGEST_DOMAIN,
            _assessment_payload(self),
        )

    def assert_integrity(self) -> None:
        """Raise when the artifact has been modified or substituted."""
        if self.semantic_digest != self.compute_semantic_digest():
            raise ValueError("hybrid coverage assessment digest mismatch")

    def to_yaml(self) -> str:
        """Serialize the assessment as deterministic YAML."""
        self.assert_integrity()
        return yaml.dump(
            self.model_dump(mode="json"),
            default_flow_style=False,
            sort_keys=True,
            allow_unicode=True,
        )

    def to_json(self) -> str:
        """Serialize stable diagnostic JSON using the shared canonical helper."""
        self.assert_integrity()
        return canonical_json_text(self.model_dump(mode="json"))

    @classmethod
    def from_yaml(cls, text: str | bytes) -> "HybridCoverageAssessment":
        """Load and verify one closed YAML assessment artifact."""
        return cls._load(yaml.safe_load(text))

    @classmethod
    def from_json(cls, text: str | bytes) -> "HybridCoverageAssessment":
        """Load and verify one closed JSON diagnostic artifact."""
        return cls._load(json.loads(text))

    @classmethod
    def _load(cls, data: Any) -> "HybridCoverageAssessment":
        """Apply mapping, schema-version, and digest checks in order."""
        if not isinstance(data, dict):
            raise ValueError("hybrid coverage artifact must be a mapping")
        if data.get("schema_version") != HYBRID_COVERAGE_ASSESSMENT_SCHEMA_VERSION:
            raise ValueError("unsupported hybrid coverage schema version")
        result = cls.model_validate(data)
        result.assert_integrity()
        return result


def _require_complete_source_pins(
    source_pins: Sequence[ArtifactPin], traceables: Sequence[Any]
) -> None:
    """Require every row and diagnostic to carry the artifact pin universe."""
    expected = set(source_pins)
    if any(set(item.source_pins) != expected for item in traceables):
        raise ValueError("every matrix row and cell must retain all source pins")


def _taxonomy_relation_ids(
    rows: Sequence[TaxonomyCorrespondenceRow],
) -> set[str]:
    """Return all coverage-bearing relation IDs claimed by obligations."""
    return {relation_id for row in rows for relation_id in row.accepted_relation_ids}


def _realization_relation_ids(rows: Sequence[ScenarioRealizationRow]) -> set[str]:
    """Return all coverage-bearing accepted relations in realization."""
    return {item.relation_id for item in rows if item.coverage_bearing}


def _require_reconciled_relation_ids(
    taxonomy: Sequence[TaxonomyCorrespondenceRow],
    realization: Sequence[ScenarioRealizationRow],
) -> None:
    """Require both relation-facing matrices to expose the same coverage IDs."""
    if _taxonomy_relation_ids(taxonomy) != _realization_relation_ids(realization):
        raise ValueError("coverage-bearing accepted relations must reconcile")


def _require_reconciled_diagnostics(
    diagnostics: HybridCoverageDiagnostics,
    structural: Sequence[StructuralConsiderationRow],
    taxonomy: Sequence[TaxonomyCorrespondenceRow],
    realization: Sequence[ScenarioRealizationRow],
    proposals: Sequence[ProposalOutcome],
    findings: Sequence[CoverageFinding],
) -> None:
    """Require separate counts to be a pure derivation of matrix content."""
    expected = derive_hybrid_coverage_diagnostics(
        structural, taxonomy, realization, proposals, findings
    )
    if diagnostics != expected:
        raise ValueError("hybrid coverage diagnostics do not reconcile")


def _validate_correspondence_rollup(row: TaxonomyCorrespondenceRow) -> None:
    """Require one taxonomy row's disposition to match its evidence."""
    if row.scope_disposition != "applicable":
        _validate_nonapplicable_rollup(row)
        return
    if row.correspondence_disposition == "satisfied":
        _validate_satisfied_rollup(row)
        return
    _validate_unsatisfied_rollup(row)


def _validate_unsatisfied_rollup(row: TaxonomyCorrespondenceRow) -> None:
    """Require an applicable unsatisfied row to expose a typed gap."""
    if row.accepted_relation_ids:
        raise ValueError("unsatisfied correspondence cannot retain accepted coverage")
    if row.correspondence_disposition == "structurally_inapplicable":
        _validate_structurally_inapplicable_rollup(row)
        return
    allowed_gaps = {
        "unresolved_missing_resource_map": {"missing_resource_map"},
        "unresolved_no_proposal": {"no_accepted_proposal"},
        "unresolved_ambiguous": {
            "ambiguous_proposals",
            "contradictory_proposals",
            "related_but_not_coverage",
        },
        "unresolved_rejected_proposals": {"rejected_proposals"},
    }
    expected = allowed_gaps.get(row.correspondence_disposition)
    if expected is None:
        raise ValueError(
            "applicable obligation requires a correspondence disposition from §8.10"
        )
    if row.gap_reason not in expected:
        raise ValueError(
            "applicable obligation disposition requires its matching typed gap reason"
        )


def _validate_nonapplicable_rollup(row: TaxonomyCorrespondenceRow) -> None:
    """Require exact preservation of a Phase 1 non-applicable disposition."""
    if row.correspondence_disposition != row.scope_disposition:
        raise ValueError(
            "non-applicable obligation must retain its Phase 1 disposition"
        )
    if row.gap_reason != "phase1_not_applicable":
        raise ValueError("non-applicable obligation requires phase1 gap reason")


def _validate_satisfied_rollup(row: TaxonomyCorrespondenceRow) -> None:
    """Require accepted relation evidence and no gap for satisfaction."""
    if not row.accepted_relation_ids or row.gap_reason is not None:
        raise ValueError(
            "satisfied correspondence requires accepted relations and no gap"
        )


def _validate_structurally_inapplicable_rollup(
    row: TaxonomyCorrespondenceRow,
) -> None:
    """Require the explicit reviewed decision and matching typed gap."""
    if not row.structural_inapplicability_decision_ids:
        raise ValueError("structurally inapplicable correspondence requires a decision")
    if row.gap_reason != "reviewed_structural_inapplicability":
        raise ValueError("structural inapplicability requires its reviewed gap reason")


def derive_hybrid_coverage_diagnostics(
    structural: Sequence[StructuralConsiderationRow],
    taxonomy: Sequence[TaxonomyCorrespondenceRow],
    realization: Sequence[ScenarioRealizationRow],
    proposals: Sequence[ProposalOutcome],
    findings: Sequence[CoverageFinding],
) -> HybridCoverageDiagnostics:
    """Derive exact counts without constructing any aggregate score."""
    unresolved_dispositions = {
        "unresolved_missing_resource_map",
        "unresolved_no_proposal",
        "unresolved_ambiguous",
        "unresolved_rejected_proposals",
    }
    return HybridCoverageDiagnostics(
        structural_ica=_count_equal(structural, "disposition", "ica"),
        structural_justified_na=_count_equal(structural, "disposition", "justified_na"),
        structural_unresolved=_count_equal(structural, "disposition", "unresolved"),
        taxonomy_satisfied=_count_equal(
            taxonomy, "correspondence_disposition", "satisfied"
        ),
        taxonomy_structurally_inapplicable=_count_equal(
            taxonomy, "correspondence_disposition", "structurally_inapplicable"
        ),
        taxonomy_unresolved=_count_in(
            taxonomy, "correspondence_disposition", unresolved_dispositions
        ),
        taxonomy_not_applicable=_count_in(
            taxonomy,
            "correspondence_disposition",
            {"governance_only", "capability_excluded"},
        ),
        unmatched_obligations=_count_equal(
            taxonomy, "correspondence_disposition", "unresolved_no_proposal"
        ),
        accepted_relations=len(realization),
        coverage_bearing_relations=_count_equal(realization, "coverage_bearing", True),
        rejected_proposals=_count_equal(proposals, "status", "rejected"),
        unresolved_proposals=_count_equal(proposals, "status", "unresolved"),
        contradictory_findings=_count_equal(
            findings, "kind", "contradictory_proposals"
        ),
    )


def _count_equal(values: Sequence[Any], field_name: str, expected: Any) -> int:
    """Count one exact closed-field value."""
    return sum(getattr(item, field_name) == expected for item in values)


def _count_in(values: Sequence[Any], field_name: str, expected: set[str]) -> int:
    """Count membership in one explicit closed value set."""
    return sum(getattr(item, field_name) in expected for item in values)


def compute_matrix_row_id(
    matrix: Literal["struct", "tax", "real"], identity: str
) -> str:
    """Compute a stable identity for one normative matrix row."""
    digest = compute_framed_digest(
        f"asago-scenario-generator:hybrid-coverage-row:{matrix}:v1",
        {"identity": identity},
    )
    return f"hca-{matrix}:v1:{digest}"


def _unique_sorted(values: Sequence[str], field_name: str) -> tuple[str, ...]:
    """Reject duplicate/empty set members and return canonical order."""
    result = tuple(values)
    if any(not item for item in result):
        raise ValueError(f"{field_name} must contain non-empty values")
    _require_unique(result, f"{field_name} must contain unique values")
    return tuple(sorted(result))


def _require_unique(values: Sequence[Any], message: str) -> None:
    """Reject duplicate identities with a stable diagnostic."""
    if len(values) != len(set(values)):
        raise ValueError(message)


def _ordered_models(values: Sequence[Any]) -> tuple[Any, ...]:
    """Return models in complete canonical JSON order."""
    return tuple(
        sorted(
            values,
            key=lambda item: canonical_json_bytes(item.model_dump(mode="json")),
        )
    )


def _require_unique_artifact_pins(pins: Sequence[ArtifactPin]) -> None:
    """Require one exact pin per stable artifact identity."""
    _require_unique(
        tuple(item.artifact_id for item in pins),
        "source pins must contain unique artifact IDs",
    )


def _require_capability_snapshot_pin(
    capability_snapshot_digest: str, pins: Sequence[ArtifactPin]
) -> None:
    """Require one explicit capability snapshot artifact pin for this assessment."""
    expected = ArtifactPin(
        artifact_id="capability-fact-snapshot",
        schema_version="capability-fact-snapshot-v1",
        semantic_digest=capability_snapshot_digest,
    )
    if expected not in pins:
        raise ValueError("assessment capability snapshot pin is missing or substituted")


def _canonicalize_traceable(value: Any) -> None:
    """Canonicalize pins/traces and require every trace to resolve exactly."""
    pins = _ordered_models(value.source_pins)
    traces = _ordered_models(value.trace_refs)
    _require_unique_artifact_pins(pins)
    _require_unique(
        tuple(_trace_identity(item) for item in traces),
        "trace references must be unique",
    )
    _require_resolved_traces(pins, traces)
    object.__setattr__(value, "source_pins", pins)
    object.__setattr__(value, "trace_refs", traces)


def _trace_identity(value: TraceReference) -> tuple[str, str, str, str]:
    """Return one complete trace identity."""
    return (
        value.artifact_id,
        value.schema_version,
        value.semantic_digest,
        value.record_id,
    )


def _artifact_pin_identity(value: ArtifactPin | TraceReference) -> tuple[str, str, str]:
    """Return the exact artifact identity shared by pins and traces."""
    return value.artifact_id, value.schema_version, value.semantic_digest


def _require_resolved_traces(
    pins: Sequence[ArtifactPin], traces: Sequence[TraceReference]
) -> None:
    """Require every trace to reference one exact source pin."""
    pin_keys = {_artifact_pin_identity(item) for item in pins}
    if any(_artifact_pin_identity(item) not in pin_keys for item in traces):
        raise ValueError("trace reference is not backed by an exact source pin")


__all__ = [
    "ArtifactPin",
    "CorrespondenceDisposition",
    "CoverageFinding",
    "GapReason",
    "HYBRID_COVERAGE_ASSESSMENT_SCHEMA_VERSION",
    "HybridCoverageAssessment",
    "HybridCoverageDiagnostics",
    "InventoryStatus",
    "ProposalOutcome",
    "ScenarioRealizationRow",
    "StpaCoverageInput",
    "StpaScenarioObservation",
    "StructuralConsiderationRow",
    "StructuralDisposition",
    "StructuralInapplicabilityDecision",
    "StructuralSlotObservation",
    "TaxonomyCorrespondenceRow",
    "TaxonomyCoverageInput",
    "TaxonomyScenarioObservation",
    "TraceReference",
    "compute_matrix_row_id",
    "derive_hybrid_coverage_diagnostics",
]
