"""Closed contracts for deterministic STPA/taxonomy correspondence.

Correspondence is deliberately split into two facts:

* a :class:`CorrespondenceProposal` is a provenance-bearing suggestion; and
* an :class:`AcceptedCorrespondenceRelation` is produced only after an
  explicit, typed adjudication passes deterministic validation.

The models in this module contain no prose matching or provider state. They
are the durable boundary consumed by proposer adapters, the reconciler, and
the persistence adapter.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from asago_scenario_generator.models.attack_pattern_projection import (
    CanonicalResourceReference,
    ResourceBinding,
)
from asago_scenario_generator.models.canonical import (
    canonical_json_bytes,
    canonical_json_text,
    compute_framed_digest,
    normalize_unicode,
)

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

CORRESPONDENCE_PROPOSALS_SCHEMA_VERSION = "correspondence-proposals-v1"
CORRESPONDENCE_RECONCILIATION_SCHEMA_VERSION = "correspondence-reconciliation-v1"
CORRESPONDENCE_DIGEST_DOMAIN = "asago-scenario-generator:correspondence:v1"
CORRESPONDENCE_RELATION_DIGEST_DOMAIN = (
    "asago-scenario-generator:correspondence-relation:v1"
)

RelationKind = Literal[
    "same_mechanism",
    "mechanism_enables_ica",
    "ica_specializes_mechanism",
    "mechanism_specializes_ica",
    "related_but_not_coverage",
]
EvidenceSource = Literal[
    "exact_id",
    "accepted_resource_link",
    "curated_mapping",
]
EvidenceStrength = Literal["high", "medium", "weak"]
AdjudicationStatus = Literal["confirmed", "rejected", "unresolved"]
ValidationResult = Literal["accepted", "rejected", "unresolved"]

_RESOURCE_LINK_RELATION_ERROR = (
    "accepted resource link evidence supports noncoverage only; "
    "coverage-bearing correspondence requires exact-ID or curated "
    "mechanism evidence"
)


def validate_evidence_relation_pair(
    evidence_source: EvidenceSource, relation_kind: RelationKind
) -> None:
    """Require shared-resource evidence to remain explicitly noncoverage."""
    if (
        evidence_source == "accepted_resource_link"
        and relation_kind != "related_but_not_coverage"
    ):
        raise ValueError(_RESOURCE_LINK_RELATION_ERROR)


def _set_selected_candidate_witness(model: Any, evidence_refs: Sequence[str]) -> None:
    """Fill a legacy unambiguous candidate witness without changing v1 identity."""
    if model.selected_candidate_id is not None:
        return
    referenced = _candidate_evidence_refs(evidence_refs)
    candidates = tuple(model.taxonomy_candidate_ids)
    if len(referenced) == 1:
        object.__setattr__(model, "selected_candidate_id", referenced[0])
        return
    if len(candidates) == 1:
        object.__setattr__(model, "selected_candidate_id", candidates[0])


def _candidate_evidence_refs(evidence_refs: Sequence[str]) -> tuple[str, ...]:
    """Return canonical candidate identities encoded by legacy evidence refs."""
    return tuple(
        sorted(
            {
                ref.removeprefix("candidate:")
                for ref in evidence_refs
                if ref.startswith("candidate:")
            }
        )
    )


def _load_canonical_artifact(
    cls: type[Any],
    text: str | bytes,
    *,
    schema_version: str,
    artifact_name: str,
    loader: Any,
) -> Any:
    """Load one closed artifact and verify its content digest."""
    data = loader(text)
    if not isinstance(data, dict):
        raise ValueError(f"{artifact_name} artifact must be a mapping")
    if data.get("schema_version") != schema_version:
        raise ValueError(f"unsupported {artifact_name} schema version")
    result = cls.model_validate(data)
    result.assert_integrity()
    return result


class _CorrespondenceModel(BaseModel):
    """Common closed, immutable configuration for correspondence records."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def normalize_input(cls, value: Any) -> Any:
        """Apply NFC normalization before any identity is interpreted."""
        return normalize_unicode(value)


def _canonical_unique_values(values: Sequence[str], field_name: str) -> tuple[str, ...]:
    """Return sorted unique values or reject duplicate identifiers."""
    values = tuple(values)
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} must contain unique identifiers")
    return tuple(sorted(values))


def _set_canonical_fields(model: Any, field_names: Sequence[str]) -> None:
    """Canonicalize named set-like tuple fields on one frozen model."""
    for name in field_names:
        object.__setattr__(
            model,
            name,
            _canonical_unique_values(getattr(model, name), name),
        )


def _require_unique_keys(values: Sequence[Any], key: Any, message: str) -> None:
    """Reject duplicate semantic keys in one record collection."""
    keys = tuple(key(item) for item in values)
    if len(keys) != len(set(keys)):
        raise ValueError(message)


class SourceArtifactPins(_CorrespondenceModel):
    """Content-addressed pins for authorities used by a proposal."""

    resource_map_semantic_digest: Digest
    capability_snapshot_digest: Digest
    obligation_plan_semantic_digest: Digest | None = None
    control_structure_digest: Digest | None = None
    ica_enumeration_digest: Digest | None = None
    loss_analysis_digest: Digest | None = None
    taxonomy_version: str | None = None
    stpa_version: str | None = None


class CandidateAuthorityRecord(_CorrespondenceModel):
    """One exact Phase 1 candidate and its projection bindings."""

    candidate_id: str = Field(pattern=r"^cand:v2:[0-9a-f]{32}$")
    resource_bindings: tuple[ResourceBinding, ...] = ()
    projection_disposition: Literal[
        "projectable", "projection_infeasible", "budget_deferred", "not_attempted"
    ] = "projectable"

    @model_validator(mode="after")
    def canonicalize_candidate_authority(self) -> "CandidateAuthorityRecord":
        """Keep each candidate's exact binding inventory deterministic."""
        bindings = tuple(
            sorted(
                self.resource_bindings,
                key=lambda item: canonical_json_bytes(item.model_dump(mode="json")),
            )
        )
        _require_unique_keys(
            bindings,
            lambda item: item.slot_id,
            "candidate authority bindings must have unique slot_id values",
        )
        object.__setattr__(self, "resource_bindings", bindings)
        return self


class ObligationAuthorityRecord(_CorrespondenceModel):
    """The subset of a Phase 1 obligation needed for reconciliation."""

    obligation_id: str = Field(pattern=r"^ob:v1:[0-9a-f]{64}$")
    risk_id: str = Field(min_length=1)
    attack_pattern_id: str | None = Field(default=None, min_length=1)
    taxonomy_candidate_ids: tuple[str, ...] = ()
    candidate_resource_refs: tuple[CanonicalResourceReference, ...] = ()
    candidates: tuple[CandidateAuthorityRecord, ...] = ()
    scope_disposition: Literal[
        "applicable", "capability_excluded", "governance_only"
    ] = "applicable"

    @model_validator(mode="after")
    def canonicalize_obligation_authority(self) -> "ObligationAuthorityRecord":
        """Canonicalize candidate identities and references."""
        object.__setattr__(
            self,
            "taxonomy_candidate_ids",
            _canonical_unique_values(
                self.taxonomy_candidate_ids, "taxonomy_candidate_ids"
            ),
        )
        refs = tuple(
            sorted(
                self.candidate_resource_refs,
                key=lambda ref: canonical_json_bytes(ref.model_dump(mode="json")),
            )
        )
        object.__setattr__(self, "candidate_resource_refs", refs)
        candidates = tuple(sorted(self.candidates, key=lambda item: item.candidate_id))
        _require_unique_keys(
            candidates,
            lambda item: item.candidate_id,
            "candidate authority records must have unique candidate_id values",
        )
        if candidates and tuple(item.candidate_id for item in candidates) != tuple(
            self.taxonomy_candidate_ids
        ):
            raise ValueError(
                "candidate authority records must match taxonomy_candidate_ids"
            )
        object.__setattr__(self, "candidates", candidates)
        return self


def _validated_artifacts(
    resource_map: Any,
    obligation_plan: Any,
    control_structure: Any,
    ica_enumeration: Any,
    loss_analysis: Any,
) -> tuple[Any, Any, Any, Any, Any]:
    """Revalidate exact closed artifact types, including model-copy inputs."""
    from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
    from asago_scenario_generator.models.system_resource_map import SystemResourceMap
    from asago_scenario_generator.stpa.models.control_structure import ControlStructure
    from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
    from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis

    typed = (
        (resource_map, SystemResourceMap, "resource_map"),
        (obligation_plan, TaxonomyObligationPlan, "obligation_plan"),
        (control_structure, ControlStructure, "control_structure"),
        (ica_enumeration, ICAEnumeration, "ica_enumeration"),
        (loss_analysis, LossAnalysis, "loss_analysis"),
    )
    validated = []
    for value, expected_type, name in typed:
        if not isinstance(value, expected_type):
            raise TypeError(f"{name} must be a {expected_type.__name__}")
        validated.append(expected_type.model_validate(value.model_dump(mode="python")))
    validated[0].assert_integrity()
    validated[1].assert_integrity()
    return tuple(validated)  # type: ignore[return-value]


def _validate_artifact_relationships(
    resource_map: Any,
    obligation_plan: Any,
    control_structure: Any,
    ica_enumeration: Any,
    loss_analysis: Any,
) -> None:
    """Reject digest substitutions and invalid cross-artifact identities."""
    from asago_scenario_generator.models.system_resource_map import (
        compute_control_structure_digest,
    )

    if (
        resource_map.capability_snapshot_digest
        != obligation_plan.capability_snapshot_digest
    ):
        raise ValueError(
            "resource-map capability snapshot digest does not match obligation plan"
        )
    control_digest = compute_control_structure_digest(control_structure)
    if resource_map.control_structure_digest != control_digest:
        raise ValueError(
            "resource-map control-structure digest does not match control structure"
        )
    ica_enumeration.validate_against(loss_analysis, control_structure)
    known_refs = _control_structure_reference_keys(control_structure)
    _validate_slot_control_references(ica_enumeration, known_refs)
    _validate_map_control_references(resource_map, known_refs)


def _validate_slot_control_references(
    ica_enumeration: Any, known_refs: set[tuple[str, str]]
) -> None:
    """Reject ICA slots whose controller path is absent from the structure."""
    for slot in ica_enumeration.slots:
        missing = _slot_reference_keys(slot) - known_refs
        if missing:
            identifiers = ", ".join(sorted(identifier for _, identifier in missing))
            raise ValueError(
                f"ICA slot {slot.slot_id} references unknown control identities: {identifiers}"
            )


def _validate_map_control_references(
    resource_map: Any, known_refs: set[tuple[str, str]]
) -> None:
    """Reject resource links with non-authoritative control identities."""
    for link in resource_map.links:
        key = (link.control_structure_ref.kind, link.control_structure_ref.id)
        if key not in known_refs:
            raise ValueError(
                f"resource link {link.link_id} references unknown control identity {key[1]}"
            )


def _control_structure_reference_keys(control_structure: Any) -> set[tuple[str, str]]:
    """Collect exact resource-map namespace/identity pairs."""
    keys: set[tuple[str, str]] = set()
    for responsibility in control_structure.responsibilities:
        keys.update(_responsibility_reference_keys(responsibility))
    keys.update(("CP", item.cp_id) for item in control_structure.controlled_processes)
    for link in control_structure.coordination_links:
        keys.add(("CL", link.link_id))
        keys.add(("CM", link.coordination_mechanism.cm_id))
    return keys


def _responsibility_reference_keys(responsibility: Any) -> set[tuple[str, str]]:
    """Collect the structural identities nested under one responsibility."""
    keys = {("RESP", responsibility.resp_id)}
    keys.update(("PM", item.pm_id) for item in responsibility.process_model_parts)
    keys.update(("CA", item.ca_id) for item in responsibility.control_actions)
    keys.update(("FB", item.fb_id) for item in responsibility.feedback_channels)
    return keys


def _slot_reference_keys(slot: Any) -> set[tuple[str, str]]:
    """Return the exact RESP/CA or CL/CM identities participating in a slot."""
    if slot.responsibility is not None:
        return _responsibility_slot_reference_keys(slot)
    return _coordination_slot_reference_keys(slot)


def _responsibility_slot_reference_keys(slot: Any) -> set[tuple[str, str]]:
    """Return and validate one RESP/CA slot path."""
    if slot.coordination_link is not None:
        raise ValueError(f"ICA slot {slot.slot_id} has ambiguous controller identity")
    expected = f"{slot.responsibility}:{slot.control_action}:{slot.uca_type.value}"
    _require_slot_identity(slot, expected)
    return {("RESP", slot.responsibility), ("CA", slot.control_action)}


def _coordination_slot_reference_keys(slot: Any) -> set[tuple[str, str]]:
    """Return and validate one CL/CM slot path."""
    if slot.coordination_link is None:
        raise ValueError(f"ICA slot {slot.slot_id} has no controller identity")
    expected = f"{slot.coordination_link}:{slot.control_action}:{slot.uca_type.value}"
    _require_slot_identity(slot, expected)
    return {("CL", slot.coordination_link), ("CM", slot.control_action)}


def _require_slot_identity(slot: Any, expected: str) -> None:
    """Reject a slot whose content does not match an exact supported identity."""
    temporality = getattr(slot, "action_temporality", None)
    temporal_text = getattr(temporality, "value", temporality) or "unknown"
    temporal_suffix = (
        re.sub(r"[^a-z0-9]+", "_", str(temporal_text).lower()).strip("_") or "unknown"
    )
    accepted = {expected, f"{expected}:{temporal_suffix}"}
    if slot.slot_id not in accepted:
        raise ValueError(
            f"ICA slot {slot.slot_id} does not match its controller/action/type identity"
        )


def _slot_resource_link_ids(resource_map: Any, slot: Any) -> tuple[str, ...]:
    """Project authoritative map links attached to the exact structural path."""
    path = _slot_reference_keys(slot)
    return tuple(
        sorted(
            link.link_id
            for link in resource_map.links
            if (
                link.control_structure_ref.kind,
                link.control_structure_ref.id,
            )
            in path
            and link.authority_status == "authoritative"
            and link.provenance != "model_proposed"
        )
    )


def _constraint_ids(control_structure: Any, loss_analysis: Any) -> tuple[str, ...]:
    """Collect both SC and responsibility-constraint identities."""
    ids = {item.constraint_id for item in loss_analysis.security_constraints}
    ids.update(
        constraint.rc_id
        for responsibility in control_structure.responsibilities
        for constraint in responsibility.responsibility_constraints
    )
    return tuple(sorted(ids))


def _canonical_ica_enumeration_payload(ica_enumeration: Any) -> dict[str, Any]:
    """Canonicalize set-like ICA collections before computing their pin."""
    payload = ica_enumeration.model_dump(mode="json")
    slots = []
    for slot in payload["slots"]:
        slot = dict(slot)
        # ``unresolved_reason`` was added as an explicit third structural
        # disposition.  Preserve the v1 digest for historical resolved/N/A
        # slots by omitting its null default; a non-null reason remains
        # semantic content and is therefore retained in the pin.
        if slot.get("unresolved_reason") is None:
            slot.pop("unresolved_reason", None)
        icas = []
        for ica in slot["icas"]:
            ica = dict(ica)
            # Human-facing style diagnostics are deliberately non-semantic.
            # They must not repin Phase 2 authority or hybrid projections.
            ica.pop("quality_warnings", None)
            ica["related_hazards"] = sorted(ica["related_hazards"])
            ica["related_constraints"] = sorted(ica["related_constraints"])
            icas.append(ica)
        slot["icas"] = sorted(icas, key=lambda item: item["ica_id"])
        slots.append(slot)
    payload["slots"] = sorted(slots, key=lambda item: item["slot_id"])
    return payload


def compute_ica_enumeration_digest(ica_enumeration: Any) -> str:
    """Compute the canonical source pin for one typed ICA enumeration."""
    from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration

    if not isinstance(ica_enumeration, ICAEnumeration):
        raise TypeError("ica_enumeration must be an ICAEnumeration")
    return compute_framed_digest(
        "asago-scenario-generator:ica-enumeration:v1",
        _canonical_ica_enumeration_payload(ica_enumeration),
    )


def _canonical_loss_analysis_payload(loss_analysis: Any) -> dict[str, Any]:
    """Canonicalize set-like loss-analysis collections before framing."""
    payload = loss_analysis.model_dump(mode="json")
    for field_name in ("risk_card_losses", "use_case_losses"):
        values = []
        for loss in payload[field_name]:
            loss = dict(loss)
            loss["source_risk_cards"] = sorted(loss["source_risk_cards"])
            values.append(loss)
        payload[field_name] = sorted(values, key=lambda item: item["loss_id"])
    hazards = []
    for hazard in payload["hazards"]:
        hazard = dict(hazard)
        hazard["related_losses"] = sorted(hazard["related_losses"])
        hazards.append(hazard)
    payload["hazards"] = sorted(hazards, key=lambda item: item["hazard_id"])
    constraints = []
    for constraint in payload["security_constraints"]:
        constraint = dict(constraint)
        constraint["related_hazards"] = sorted(constraint["related_hazards"])
        constraints.append(constraint)
    payload["security_constraints"] = sorted(
        constraints, key=lambda item: item["constraint_id"]
    )
    return payload


def compute_loss_analysis_digest(loss_analysis: Any) -> str:
    """Compute the order-independent source pin for one typed loss analysis."""
    from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis

    if not isinstance(loss_analysis, LossAnalysis):
        raise TypeError("loss_analysis must be a LossAnalysis")
    validated = LossAnalysis.model_validate(loss_analysis.model_dump(mode="python"))
    return compute_framed_digest(
        "asago-scenario-generator:loss-analysis:v1",
        _canonical_loss_analysis_payload(validated),
    )


def _obligation_authority_records(obligation_plan: Any) -> tuple[Any, ...]:
    """Project exact Phase 1 identities and candidate resource authority."""
    records = []
    for row in obligation_plan.obligations:
        candidates = tuple(row.candidate_records)
        records.append(
            ObligationAuthorityRecord(
                obligation_id=row.obligation_id,
                risk_id=row.risk_ref.risk_id,
                attack_pattern_id=row.attack_pattern_id,
                taxonomy_candidate_ids=tuple(item.candidate_id for item in candidates),
                candidate_resource_refs=tuple(
                    binding.resource_ref
                    for candidate in candidates
                    for binding in candidate.resource_bindings
                ),
                candidates=tuple(
                    CandidateAuthorityRecord(
                        candidate_id=candidate.candidate_id,
                        resource_bindings=candidate.resource_bindings,
                        projection_disposition=candidate.projection_disposition,
                    )
                    for candidate in candidates
                ),
                scope_disposition=row.scope_disposition,
            )
        )
    return tuple(records)


def _structural_authority_records(
    resource_map: Any, ica_enumeration: Any
) -> tuple[Any, ...]:
    """Project every exact slot/ICA identity and its structural resource path."""
    records = []
    for slot in ica_enumeration.slots:
        controller = slot.responsibility or slot.coordination_link
        exec_id = f"EXEC:{controller}:{slot.control_action}:{slot.uca_type.value}"
        path_links = _slot_resource_link_ids(resource_map, slot)
        records.extend(
            StructuralAuthorityRecord(
                ica_slot_id=slot.slot_id,
                ica_id=ica.ica_id,
                exec_candidate_id=exec_id,
                hazard_ids=tuple(ica.related_hazards),
                constraint_ids=tuple(ica.related_constraints),
                resource_link_ids=path_links,
            )
            for ica in slot.icas
        )
    return tuple(records)


class StructuralAuthorityRecord(_CorrespondenceModel):
    """One exact STPA slot/ICA/EXEC identity and its references."""

    ica_slot_id: str = Field(min_length=1)
    ica_id: str = Field(min_length=1)
    exec_candidate_id: str = Field(pattern=r"^EXEC:[^:]+:[^:]+:[A-Z_]+$")
    hazard_ids: tuple[str, ...] = ()
    constraint_ids: tuple[str, ...] = ()
    resource_link_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def canonicalize_structural_authority(self) -> "StructuralAuthorityRecord":
        """Canonicalize references while rejecting duplicates."""
        _set_canonical_fields(
            self, ("hazard_ids", "constraint_ids", "resource_link_ids")
        )
        return self


class CorrespondenceAuthority(_CorrespondenceModel):
    """Typed inventories against which proposals are reconciled.

    The authority is an identity projection rather than a copy of mutable
    source artifacts. It carries exact records and pins needed to reject
    dangling or stale claims without coupling reconciliation to storage.
    """

    source_pins: SourceArtifactPins
    obligations: tuple[ObligationAuthorityRecord, ...] = ()
    structural_findings: tuple[StructuralAuthorityRecord, ...] = ()
    hazard_ids: tuple[str, ...] = ()
    constraint_ids: tuple[str, ...] = ()
    inventory_complete: bool = True

    @classmethod
    def from_artifacts(
        cls,
        resource_map: Any,
        obligation_plan: Any,
        control_structure: Any,
        ica_enumeration: Any,
        loss_analysis: Any,
        *,
        inventory_complete: bool = True,
    ) -> "CorrespondenceAuthority":
        """Project validated Phase 1/STPA artifacts into typed identities.

        Imports are local on purpose: this model package remains a leaf and
        does not make the correspondence contract depend on STPA modules at
        import time. Every supplied artifact is revalidated, integrity-checked,
        and cross-checked before its identities are projected.
        """
        (
            resource_map,
            obligation_plan,
            control_structure,
            ica_enumeration,
            loss_analysis,
        ) = _validated_artifacts(
            resource_map,
            obligation_plan,
            control_structure,
            ica_enumeration,
            loss_analysis,
        )
        _validate_artifact_relationships(
            resource_map,
            obligation_plan,
            control_structure,
            ica_enumeration,
            loss_analysis,
        )
        pins = SourceArtifactPins(
            resource_map_semantic_digest=resource_map.semantic_digest,
            capability_snapshot_digest=resource_map.capability_snapshot_digest,
            obligation_plan_semantic_digest=getattr(
                obligation_plan, "semantic_digest", None
            ),
            control_structure_digest=resource_map.control_structure_digest,
            ica_enumeration_digest=compute_ica_enumeration_digest(ica_enumeration),
            loss_analysis_digest=compute_loss_analysis_digest(loss_analysis),
            taxonomy_version=obligation_plan.schema_version,
            stpa_version="stpa-foundation-v1",
        )
        return cls(
            source_pins=pins,
            obligations=_obligation_authority_records(obligation_plan),
            structural_findings=_structural_authority_records(
                resource_map, ica_enumeration
            ),
            hazard_ids=tuple(h.hazard_id for h in loss_analysis.hazards),
            constraint_ids=_constraint_ids(control_structure, loss_analysis),
            inventory_complete=inventory_complete,
        )

    @model_validator(mode="after")
    def canonicalize_authority(self) -> "CorrespondenceAuthority":
        """Sort inventories and reject duplicate authority identities."""
        obligations = tuple(
            sorted(self.obligations, key=lambda item: item.obligation_id)
        )
        findings = tuple(
            sorted(
                self.structural_findings,
                key=lambda item: (item.ica_slot_id, item.ica_id),
            )
        )
        _require_unique_keys(
            obligations,
            lambda item: item.obligation_id,
            "authority obligations must have unique obligation_id values",
        )
        _require_unique_keys(
            findings,
            lambda item: (item.ica_slot_id, item.ica_id),
            "authority structural findings must be unique",
        )
        object.__setattr__(self, "obligations", obligations)
        object.__setattr__(self, "structural_findings", findings)
        _set_canonical_fields(self, ("hazard_ids", "constraint_ids"))
        return self


class CorrespondenceEvidence(_CorrespondenceModel):
    """One deterministic, typed proposal seed.

    This is the only input accepted by the v1 proposer. It has no prose field
    and its evidence source is closed to exact IDs, accepted resource links,
    and curated mappings.
    """

    obligation_id: str = Field(pattern=r"^ob:v1:[0-9a-f]{64}$")
    risk_id: str = Field(min_length=1)
    attack_pattern_id: str = Field(min_length=1)
    taxonomy_candidate_ids: tuple[str, ...] = Field(min_length=1)
    selected_candidate_id: str | None = Field(
        default=None, pattern=r"^cand:v2:[0-9a-f]{32}$"
    )
    ica_slot_id: str = Field(min_length=1)
    ica_id: str = Field(min_length=1)
    exec_candidate_id: str = Field(pattern=r"^EXEC:[^:]+:[^:]+:[A-Z_]+$")
    relation_kind: RelationKind
    resource_link_ids: tuple[str, ...] = ()
    hazard_ids: tuple[str, ...] = ()
    constraint_ids: tuple[str, ...] = ()
    evidence_source: EvidenceSource
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_strength: EvidenceStrength = "medium"
    proposer_id: str = Field(min_length=1)
    proposer_version: str = Field(min_length=1)
    source_pins: SourceArtifactPins
    rationale: str = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize_evidence(self) -> "CorrespondenceEvidence":
        """Canonicalize references and keep shared-resource evidence advisory."""
        _set_canonical_fields(
            self,
            (
                "taxonomy_candidate_ids",
                "resource_link_ids",
                "hazard_ids",
                "constraint_ids",
                "evidence_refs",
            ),
        )
        validate_evidence_relation_pair(self.evidence_source, self.relation_kind)
        _set_selected_candidate_witness(self, self.evidence_refs)
        return self


class CorrespondenceSourceArtifacts(_CorrespondenceModel):
    """Typed proposer input: authoritative identities plus deterministic seeds."""

    authority: CorrespondenceAuthority
    evidence: tuple[CorrespondenceEvidence, ...] = ()

    @classmethod
    def from_artifacts(
        cls,
        resource_map: Any,
        obligation_plan: Any,
        control_structure: Any,
        ica_enumeration: Any,
        loss_analysis: Any,
        evidence: Sequence[CorrespondenceEvidence] = (),
        *,
        inventory_complete: bool = True,
    ) -> "CorrespondenceSourceArtifacts":
        """Build typed proposer input from validated upstream artifacts."""
        authority = CorrespondenceAuthority.from_artifacts(
            resource_map,
            obligation_plan,
            control_structure,
            ica_enumeration,
            loss_analysis,
            inventory_complete=inventory_complete,
        )
        return cls(authority=authority, evidence=tuple(evidence))

    @model_validator(mode="after")
    def canonicalize_source_artifacts(self) -> "CorrespondenceSourceArtifacts":
        """Sort evidence by semantic content, not authoring order."""
        ordered = tuple(
            sorted(
                self.evidence,
                key=lambda item: canonical_json_bytes(item.model_dump(mode="json")),
            )
        )
        object.__setattr__(self, "evidence", ordered)
        return self


class ProposalProvenance(_CorrespondenceModel):
    """Reviewable origin metadata for a proposal."""

    proposer_id: str = Field(min_length=1)
    proposer_version: str = Field(min_length=1)
    evidence_source: EvidenceSource
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    source_pins: SourceArtifactPins
    rationale: str = Field(min_length=1)

    @model_validator(mode="after")
    def canonicalize_provenance(self) -> "ProposalProvenance":
        """Keep evidence references deterministic and unique."""
        refs = tuple(self.evidence_refs)
        if len(refs) != len(set(refs)):
            raise ValueError("evidence_refs must contain unique identifiers")
        object.__setattr__(self, "evidence_refs", tuple(sorted(refs)))
        return self


def compute_proposal_id(
    *,
    obligation_id: str,
    ica_slot_id: str,
    ica_id: str,
    exec_candidate_id: str,
    relation_kind: RelationKind,
    resource_link_ids: Sequence[str],
    hazard_ids: Sequence[str],
    constraint_ids: Sequence[str],
    evidence_source: EvidenceSource,
    evidence_refs: Sequence[str],
) -> str:
    """Compute a stable semantic proposal identity."""
    digest = compute_framed_digest(
        CORRESPONDENCE_DIGEST_DOMAIN,
        {
            "obligation_id": obligation_id,
            "ica_slot_id": ica_slot_id,
            "ica_id": ica_id,
            "exec_candidate_id": exec_candidate_id,
            "relation_kind": relation_kind,
            "resource_link_ids": sorted(resource_link_ids),
            "hazard_ids": sorted(hazard_ids),
            "constraint_ids": sorted(constraint_ids),
            "evidence_source": evidence_source,
            "evidence_refs": sorted(evidence_refs),
        },
    )
    return f"corrp:v1:{digest}"


class CorrespondenceProposal(_CorrespondenceModel):
    """Explicit typed suggestion; it never carries an adjudication state."""

    proposal_id: str = ""
    obligation_id: str = Field(pattern=r"^ob:v1:[0-9a-f]{64}$")
    risk_id: str = Field(min_length=1)
    attack_pattern_id: str = Field(min_length=1)
    taxonomy_candidate_ids: tuple[str, ...] = Field(min_length=1)
    selected_candidate_id: str | None = Field(
        default=None, pattern=r"^cand:v2:[0-9a-f]{32}$"
    )
    ica_slot_id: str = Field(min_length=1)
    ica_id: str = Field(min_length=1)
    exec_candidate_id: str = Field(pattern=r"^EXEC:[^:]+:[^:]+:[A-Z_]+$")
    relation_kind: RelationKind
    resource_link_ids: tuple[str, ...] = ()
    hazard_ids: tuple[str, ...] = ()
    constraint_ids: tuple[str, ...] = ()
    provenance: ProposalProvenance
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_strength: EvidenceStrength = "medium"

    @model_validator(mode="after")
    def canonicalize_and_verify_identity(self) -> "CorrespondenceProposal":
        """Canonicalize references and reject substituted proposal IDs."""
        _set_canonical_fields(
            self,
            (
                "taxonomy_candidate_ids",
                "resource_link_ids",
                "hazard_ids",
                "constraint_ids",
            ),
        )
        validate_evidence_relation_pair(
            self.provenance.evidence_source, self.relation_kind
        )
        _set_selected_candidate_witness(self, self.provenance.evidence_refs)
        expected = compute_proposal_id(
            obligation_id=self.obligation_id,
            ica_slot_id=self.ica_slot_id,
            ica_id=self.ica_id,
            exec_candidate_id=self.exec_candidate_id,
            relation_kind=self.relation_kind,
            resource_link_ids=self.resource_link_ids,
            hazard_ids=self.hazard_ids,
            constraint_ids=self.constraint_ids,
            evidence_source=self.provenance.evidence_source,
            evidence_refs=self.provenance.evidence_refs,
        )
        if self.proposal_id and self.proposal_id != expected:
            raise ValueError("proposal_id does not match semantic proposal content")
        object.__setattr__(self, "proposal_id", expected)
        return self

    @classmethod
    def from_evidence(
        cls,
        evidence: CorrespondenceEvidence,
    ) -> "CorrespondenceProposal":
        """Build a proposal from exact reviewed evidence identities."""
        return cls(
            obligation_id=evidence.obligation_id,
            risk_id=evidence.risk_id,
            attack_pattern_id=evidence.attack_pattern_id,
            taxonomy_candidate_ids=evidence.taxonomy_candidate_ids,
            selected_candidate_id=evidence.selected_candidate_id,
            ica_slot_id=evidence.ica_slot_id,
            ica_id=evidence.ica_id,
            exec_candidate_id=evidence.exec_candidate_id,
            relation_kind=evidence.relation_kind,
            resource_link_ids=evidence.resource_link_ids,
            hazard_ids=evidence.hazard_ids,
            constraint_ids=evidence.constraint_ids,
            confidence=evidence.confidence,
            evidence_strength=evidence.evidence_strength,
            provenance=ProposalProvenance(
                proposer_id=evidence.proposer_id,
                proposer_version=evidence.proposer_version,
                evidence_source=evidence.evidence_source,
                evidence_refs=evidence.evidence_refs,
                source_pins=evidence.source_pins,
                rationale=evidence.rationale,
            ),
        )


def _canonical_proposals(
    proposals: Sequence[CorrespondenceProposal],
) -> tuple[Any, ...]:
    """Sort proposal records and reject duplicate semantic identities."""
    ordered = tuple(sorted(proposals, key=lambda item: item.proposal_id))
    _require_unique_keys(
        ordered,
        lambda item: item.proposal_id,
        "proposal IDs must be unique",
    )
    return ordered


def _verify_proposal_set_digest(proposal_set: Any) -> str:
    """Return the canonical digest or reject a substituted recorded digest."""
    expected = proposal_set.compute_semantic_digest()
    if (
        proposal_set.semantic_digest is not None
        and proposal_set.semantic_digest != expected
    ):
        raise ValueError("proposal-set semantic_digest does not match content")
    return expected


def _verify_proposal_authority_pin(proposal_set: Any) -> None:
    """Require retained authority to pin the exact map and capability scope."""
    if proposal_set.authority is None:
        return
    pins = proposal_set.authority.source_pins
    if pins.resource_map_semantic_digest != proposal_set.resource_map_semantic_digest:
        raise ValueError("proposal authority does not pin this resource map")
    if pins.capability_snapshot_digest != proposal_set.capability_snapshot_digest:
        raise ValueError("proposal authority does not pin this capability snapshot")


class ProposalSet(_CorrespondenceModel):
    """Canonical proposal artifact; no proposal is confirmed here."""

    schema_version: Literal[CORRESPONDENCE_PROPOSALS_SCHEMA_VERSION] = (
        CORRESPONDENCE_PROPOSALS_SCHEMA_VERSION
    )
    resource_map_semantic_digest: Digest
    capability_snapshot_digest: Digest
    authority: CorrespondenceAuthority | None = None
    proposals: tuple[CorrespondenceProposal, ...] = ()
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "ProposalSet":
        """Sort proposals, reject duplicate IDs, and verify optional digest."""
        object.__setattr__(self, "proposals", _canonical_proposals(self.proposals))
        object.__setattr__(self, "semantic_digest", _verify_proposal_set_digest(self))
        _verify_proposal_authority_pin(self)
        return self

    def compute_semantic_digest(self) -> str:
        """Compute the canonical digest over proposal content and authority."""
        payload = {
            "schema_version": self.schema_version,
            "resource_map_semantic_digest": self.resource_map_semantic_digest,
            "capability_snapshot_digest": self.capability_snapshot_digest,
            "authority": self.authority.model_dump(mode="json")
            if self.authority is not None
            else None,
            "proposals": [item.model_dump(mode="json") for item in self.proposals],
        }
        return compute_framed_digest(CORRESPONDENCE_DIGEST_DOMAIN, payload)

    def assert_integrity(self) -> None:
        """Raise when the proposal artifact has been modified."""
        expected = self.compute_semantic_digest()
        if self.semantic_digest != expected:
            raise ValueError(
                f"Digest mismatch: recorded '{self.semantic_digest}' != computed '{expected}'"
            )

    def to_yaml(self) -> str:
        """Serialize the canonical proposal artifact as YAML."""
        self.assert_integrity()
        return yaml.dump(
            self.model_dump(mode="json"),
            default_flow_style=False,
            sort_keys=True,
            allow_unicode=True,
        )

    @classmethod
    def from_yaml(cls, text: str | bytes) -> "ProposalSet":
        """Load and verify a canonical proposal artifact."""
        return _load_canonical_artifact(
            cls,
            text,
            schema_version=CORRESPONDENCE_PROPOSALS_SCHEMA_VERSION,
            artifact_name="proposal",
            loader=yaml.safe_load,
        )

    def to_json(self) -> str:
        """Serialize canonical JSON for diagnostics."""
        self.assert_integrity()
        return canonical_json_text(self.model_dump(mode="json"))

    @classmethod
    def from_json(cls, text: str | bytes) -> "ProposalSet":
        """Load and verify canonical JSON."""
        return _load_canonical_artifact(
            cls,
            text,
            schema_version=CORRESPONDENCE_PROPOSALS_SCHEMA_VERSION,
            artifact_name="proposal",
            loader=json.loads,
        )


class AdjudicationHistoryItem(_CorrespondenceModel):
    """One immutable audit event for a proposal decision."""

    status: AdjudicationStatus
    reason: str = Field(min_length=1)
    adjudicated_by: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = ()

    @model_validator(mode="after")
    def canonicalize_history(self) -> "AdjudicationHistoryItem":
        """Keep audit evidence references stable."""
        refs = tuple(self.evidence_refs)
        if len(refs) != len(set(refs)):
            raise ValueError("adjudication evidence_refs must be unique")
        object.__setattr__(self, "evidence_refs", tuple(sorted(refs)))
        return self


class CorrespondenceAdjudication(_CorrespondenceModel):
    """Explicit human decision input; never inferred from confidence."""

    proposal_id: str = Field(pattern=r"^corrp:v1:[0-9a-f]{64}$")
    status: AdjudicationStatus
    reason: str = Field(min_length=1)
    adjudicated_by: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = ()

    @model_validator(mode="after")
    def canonicalize_adjudication(self) -> "CorrespondenceAdjudication":
        """Canonicalize audit evidence references."""
        refs = tuple(self.evidence_refs)
        if len(refs) != len(set(refs)):
            raise ValueError("adjudication evidence_refs must be unique")
        object.__setattr__(self, "evidence_refs", tuple(sorted(refs)))
        return self


class AdjudicationSet(_CorrespondenceModel):
    """Closed collection of explicit decisions."""

    decisions: tuple[CorrespondenceAdjudication, ...] = ()

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> "AdjudicationSet":
        """Sort decisions and reject multiple decisions for one proposal."""
        ordered = tuple(sorted(self.decisions, key=lambda item: item.proposal_id))
        if len({item.proposal_id for item in ordered}) != len(ordered):
            raise ValueError("adjudications must contain one decision per proposal")
        object.__setattr__(self, "decisions", ordered)
        return self


def compute_relation_id(
    *,
    obligation_id: str,
    ica_slot_id: str,
    ica_id: str,
    exec_candidate_id: str,
    relation_kind: RelationKind,
    resource_link_ids: Sequence[str],
) -> str:
    """Compute the stable identity of an accepted relation."""
    digest = compute_framed_digest(
        CORRESPONDENCE_RELATION_DIGEST_DOMAIN,
        {
            "obligation_id": obligation_id,
            "ica_slot_id": ica_slot_id,
            "ica_id": ica_id,
            "exec_candidate_id": exec_candidate_id,
            "relation_kind": relation_kind,
            "resource_link_ids": sorted(resource_link_ids),
        },
    )
    return f"correlation:v1:{digest}"


def _verify_reconciled_proposal_identity(proposal: Any) -> None:
    """Reject a reconciled record detached from its proposal identity."""
    expected = compute_proposal_id(
        obligation_id=proposal.obligation_id,
        ica_slot_id=proposal.ica_slot_id,
        ica_id=proposal.ica_id,
        exec_candidate_id=proposal.exec_candidate_id,
        relation_kind=proposal.relation_kind,
        resource_link_ids=proposal.resource_link_ids,
        hazard_ids=proposal.hazard_ids,
        constraint_ids=proposal.constraint_ids,
        evidence_source=proposal.provenance.evidence_source,
        evidence_refs=proposal.provenance.evidence_refs,
    )
    if expected != proposal.proposal_id:
        raise ValueError("reconciled proposal_id does not match proposal content")


def _validate_reconciled_history(proposal: Any) -> None:
    """Require one explicit or system audit event for every outcome."""
    if proposal.adjudication_history:
        return
    if proposal.status == "confirmed":
        raise ValueError("confirmed adjudication history is required")
    raise ValueError("reconciled proposal requires adjudication history")


def _validate_confirmed_reconciliation(proposal: Any) -> None:
    """Reject confirmation without clean explicit adjudication evidence."""
    if proposal.status != "confirmed":
        return
    _require_clean_confirmation(proposal)
    if not _has_explicit_confirmation(proposal.adjudication_history):
        raise ValueError("confirmed adjudication history is required")


def _require_clean_confirmation(proposal: Any) -> None:
    """Require accepted validation with no defects for confirmation."""
    if proposal.validation_result != "accepted":
        raise ValueError("confirmed proposal must have zero validation defects")
    if proposal.validation_codes:
        raise ValueError("confirmed proposal must have zero validation defects")


def _has_explicit_confirmation(history: Sequence[Any]) -> bool:
    """Return whether decision history contains a non-system confirmation."""
    return any(_is_explicit_confirmation(item) for item in history)


def _is_explicit_confirmation(item: Any) -> bool:
    """Return whether one audit item is a non-system confirmation."""
    return item.status == "confirmed" and item.adjudicated_by != "system"


def _validate_rejected_reconciliation(proposal: Any) -> None:
    """Require typed codes whenever deterministic validation rejects a proposal."""
    if proposal.validation_result != "rejected":
        return
    if proposal.status != "rejected" or not proposal.validation_codes:
        raise ValueError(
            "rejected validation requires rejected status and validation codes"
        )


def _validate_unresolved_reconciliation(proposal: Any) -> None:
    """Keep unresolved validation and adjudication status aligned."""
    if proposal.validation_result == "unresolved" and proposal.status != "unresolved":
        raise ValueError("unresolved validation requires unresolved status")


class ReconciledProposal(_CorrespondenceModel):
    """One proposal with an explicit reconciliation state and audit history."""

    proposal_id: str = Field(pattern=r"^corrp:v1:[0-9a-f]{64}$")
    obligation_id: str = Field(pattern=r"^ob:v1:[0-9a-f]{64}$")
    risk_id: str = Field(min_length=1)
    attack_pattern_id: str = Field(min_length=1)
    taxonomy_candidate_ids: tuple[str, ...] = Field(min_length=1)
    selected_candidate_id: str | None = Field(
        default=None, pattern=r"^cand:v2:[0-9a-f]{32}$"
    )
    ica_slot_id: str = Field(min_length=1)
    ica_id: str = Field(min_length=1)
    exec_candidate_id: str = Field(pattern=r"^EXEC:[^:]+:[^:]+:[A-Z_]+$")
    relation_kind: RelationKind
    resource_link_ids: tuple[str, ...] = ()
    hazard_ids: tuple[str, ...] = ()
    constraint_ids: tuple[str, ...] = ()
    provenance: ProposalProvenance
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_strength: EvidenceStrength
    status: AdjudicationStatus
    validation_result: ValidationResult
    validation_codes: tuple[str, ...] = ()
    adjudication_history: tuple[AdjudicationHistoryItem, ...] = ()

    @model_validator(mode="after")
    def canonicalize_reconciled_proposal(self) -> "ReconciledProposal":
        """Canonicalize set-like decision content."""
        _set_canonical_fields(
            self,
            (
                "resource_link_ids",
                "hazard_ids",
                "constraint_ids",
                "taxonomy_candidate_ids",
                "validation_codes",
            ),
        )
        _verify_reconciled_proposal_identity(self)
        _set_selected_candidate_witness(self, self.provenance.evidence_refs)
        _validate_reconciled_history(self)
        _validate_confirmed_reconciliation(self)
        _validate_rejected_reconciliation(self)
        _validate_unresolved_reconciliation(self)
        return self


class AcceptedCorrespondenceRelation(_CorrespondenceModel):
    """A confirmed relation materialized only by successful reconciliation."""

    relation_id: str = Field(pattern=r"^correlation:v1:[0-9a-f]{64}$")
    proposal_id: str = Field(pattern=r"^corrp:v1:[0-9a-f]{64}$")
    obligation_id: str = Field(pattern=r"^ob:v1:[0-9a-f]{64}$")
    risk_id: str = Field(min_length=1)
    attack_pattern_id: str = Field(min_length=1)
    taxonomy_candidate_ids: tuple[str, ...] = Field(min_length=1)
    selected_candidate_id: str | None = Field(
        default=None, pattern=r"^cand:v2:[0-9a-f]{32}$"
    )
    ica_slot_id: str = Field(min_length=1)
    ica_id: str = Field(min_length=1)
    exec_candidate_id: str = Field(pattern=r"^EXEC:[^:]+:[^:]+:[A-Z_]+$")
    relation_kind: RelationKind
    resource_link_ids: tuple[str, ...] = ()
    hazard_ids: tuple[str, ...] = ()
    constraint_ids: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    source_pins: SourceArtifactPins
    validation_result: Literal["accepted"] = "accepted"

    @model_validator(mode="after")
    def verify_identity(self) -> "AcceptedCorrespondenceRelation":
        """Verify the content-addressed accepted relation identity."""
        _set_canonical_fields(
            self,
            (
                "taxonomy_candidate_ids",
                "resource_link_ids",
                "hazard_ids",
                "constraint_ids",
                "evidence_refs",
            ),
        )
        expected = compute_relation_id(
            obligation_id=self.obligation_id,
            ica_slot_id=self.ica_slot_id,
            ica_id=self.ica_id,
            exec_candidate_id=self.exec_candidate_id,
            relation_kind=self.relation_kind,
            resource_link_ids=self.resource_link_ids,
        )
        if expected != self.relation_id:
            raise ValueError("relation_id does not match accepted relation content")
        _set_selected_candidate_witness(self, self.evidence_refs)
        return self


class ReconciliationError(_CorrespondenceModel):
    """Typed diagnostic that prevents or explains a confirmation."""

    proposal_id: str = Field(pattern=r"^corrp:v1:[0-9a-f]{64}$")
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    field: str | None = None


def _reconciliation_payload(result: "ReconciliationResult") -> dict[str, Any]:
    """Return canonical semantic content for reconciliation identity."""
    return {
        "schema_version": result.schema_version,
        "resource_map_semantic_digest": result.resource_map_semantic_digest,
        "capability_snapshot_digest": result.capability_snapshot_digest,
        "proposals": [item.model_dump(mode="json") for item in result.proposals],
        "accepted_relations": [
            item.model_dump(mode="json") for item in result.accepted_relations
        ],
        "errors": [item.model_dump(mode="json") for item in result.errors],
    }


def _relation_matches_proposal(
    relation: AcceptedCorrespondenceRelation,
    proposal: ReconciledProposal,
) -> bool:
    """Return whether an accepted relation exactly materializes one proposal."""
    return _relation_support_key(relation) == _proposal_support_key(proposal)


def _relation_support_key(relation: AcceptedCorrespondenceRelation) -> tuple[Any, ...]:
    """Return complete accepted-relation support content."""
    return (
        relation.proposal_id,
        relation.obligation_id,
        relation.risk_id,
        relation.attack_pattern_id,
        relation.taxonomy_candidate_ids,
        relation.selected_candidate_id,
        relation.ica_slot_id,
        relation.ica_id,
        relation.exec_candidate_id,
        relation.relation_kind,
        relation.resource_link_ids,
        relation.hazard_ids,
        relation.constraint_ids,
        relation.evidence_refs,
        relation.source_pins,
    )


def _proposal_support_key(proposal: ReconciledProposal) -> tuple[Any, ...]:
    """Return proposal content that one accepted relation must retain."""
    return (
        proposal.proposal_id,
        proposal.obligation_id,
        proposal.risk_id,
        proposal.attack_pattern_id,
        proposal.taxonomy_candidate_ids,
        proposal.selected_candidate_id,
        proposal.ica_slot_id,
        proposal.ica_id,
        proposal.exec_candidate_id,
        proposal.relation_kind,
        proposal.resource_link_ids,
        proposal.hazard_ids,
        proposal.constraint_ids,
        proposal.provenance.evidence_refs,
        proposal.provenance.source_pins,
    )


def _require_unique_accepted_relation_ids(
    relations: tuple[AcceptedCorrespondenceRelation, ...],
) -> tuple[str, ...]:
    """Reject duplicate accepted relation and source-proposal identities."""
    _require_unique_keys(
        relations,
        lambda item: item.relation_id,
        "accepted relations must have unique relation IDs",
    )
    _require_unique_keys(
        relations,
        lambda item: item.proposal_id,
        "accepted relations must have unique proposal IDs",
    )
    return tuple(item.proposal_id for item in relations)


def _validate_accepted_relation_support(
    proposals: tuple[ReconciledProposal, ...],
    relations: tuple[AcceptedCorrespondenceRelation, ...],
) -> None:
    """Require an exact one-to-one relation for every confirmed proposal."""
    _require_unique_keys(
        proposals,
        lambda item: item.proposal_id,
        "reconciled proposals must have unique proposal IDs",
    )
    confirmed = {
        item.proposal_id: item for item in proposals if item.status == "confirmed"
    }
    proposal_ids = _require_unique_accepted_relation_ids(relations)
    if set(proposal_ids) != set(confirmed):
        raise ValueError(
            "every accepted relation requires one exact confirmed proposal"
        )
    for relation in relations:
        if not _relation_matches_proposal(relation, confirmed[relation.proposal_id]):
            raise ValueError("accepted relation does not match its confirmed proposal")


def _validate_reconciliation_errors(
    proposals: tuple[ReconciledProposal, ...],
    errors: tuple[ReconciliationError, ...],
) -> None:
    """Keep validation diagnostics attached to exact retained proposal records."""
    proposal_ids = {item.proposal_id for item in proposals}
    if any(item.proposal_id not in proposal_ids for item in errors):
        raise ValueError("reconciliation error references an unknown proposal")


def _validate_reconciliation_capability_pins(result: Any) -> None:
    """Require every retained correspondence record to name one capability scope."""
    proposal_pins = (
        item.provenance.source_pins.capability_snapshot_digest
        for item in result.proposals
        if item.status == "confirmed"
    )
    relation_pins = (
        item.source_pins.capability_snapshot_digest
        for item in result.accepted_relations
    )
    if any(
        digest != result.capability_snapshot_digest
        for digest in (*proposal_pins, *relation_pins)
    ):
        raise ValueError(
            "reconciliation capability snapshot pin does not match content"
        )


class ReconciliationResult(_CorrespondenceModel):
    """Complete deterministic reconciliation artifact."""

    schema_version: Literal[CORRESPONDENCE_RECONCILIATION_SCHEMA_VERSION] = (
        CORRESPONDENCE_RECONCILIATION_SCHEMA_VERSION
    )
    resource_map_semantic_digest: Digest
    capability_snapshot_digest: Digest
    is_valid: bool
    proposals: tuple[ReconciledProposal, ...] = ()
    accepted_relations: tuple[AcceptedCorrespondenceRelation, ...] = ()
    errors: tuple[ReconciliationError, ...] = ()
    semantic_digest: Digest | None = None
    network_calls: Literal[0] = 0
    model_calls: Literal[0] = 0

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "ReconciliationResult":
        """Sort the complete audit result and verify its optional digest."""
        object.__setattr__(
            self,
            "proposals",
            tuple(sorted(self.proposals, key=lambda item: item.proposal_id)),
        )
        object.__setattr__(
            self,
            "accepted_relations",
            tuple(sorted(self.accepted_relations, key=lambda item: item.relation_id)),
        )
        object.__setattr__(
            self,
            "errors",
            tuple(sorted(self.errors, key=lambda item: (item.proposal_id, item.code))),
        )
        _validate_accepted_relation_support(self.proposals, self.accepted_relations)
        _validate_reconciliation_errors(self.proposals, self.errors)
        _validate_reconciliation_capability_pins(self)
        if self.is_valid != (not self.errors):
            raise ValueError("is_valid must exactly reconcile with validation errors")
        expected = self.compute_semantic_digest()
        if self.semantic_digest is not None and self.semantic_digest != expected:
            raise ValueError("reconciliation semantic_digest does not match content")
        object.__setattr__(self, "semantic_digest", expected)
        return self

    def compute_semantic_digest(self) -> str:
        """Compute the canonical reconciliation digest."""
        return compute_framed_digest(
            CORRESPONDENCE_DIGEST_DOMAIN, _reconciliation_payload(self)
        )

    def assert_integrity(self) -> None:
        """Raise when the reconciliation artifact has been modified."""
        expected = self.compute_semantic_digest()
        if self.semantic_digest != expected:
            raise ValueError(
                f"Digest mismatch: recorded '{self.semantic_digest}' != computed '{expected}'"
            )

    def to_yaml(self) -> str:
        """Serialize canonical reconciliation YAML."""
        self.assert_integrity()
        return yaml.dump(
            self.model_dump(mode="json"),
            default_flow_style=False,
            sort_keys=True,
            allow_unicode=True,
        )

    @classmethod
    def from_yaml(cls, text: str | bytes) -> "ReconciliationResult":
        """Load and verify canonical reconciliation YAML."""
        return _load_canonical_artifact(
            cls,
            text,
            schema_version=CORRESPONDENCE_RECONCILIATION_SCHEMA_VERSION,
            artifact_name="reconciliation",
            loader=yaml.safe_load,
        )

    def to_json(self) -> str:
        """Serialize canonical reconciliation JSON for diagnostics."""
        self.assert_integrity()
        return canonical_json_text(self.model_dump(mode="json"))

    @classmethod
    def from_json(cls, text: str | bytes) -> "ReconciliationResult":
        """Load and verify canonical reconciliation JSON."""
        return _load_canonical_artifact(
            cls,
            text,
            schema_version=CORRESPONDENCE_RECONCILIATION_SCHEMA_VERSION,
            artifact_name="reconciliation",
            loader=json.loads,
        )


__all__ = [
    "AcceptedCorrespondenceRelation",
    "AdjudicationHistoryItem",
    "AdjudicationSet",
    "AdjudicationStatus",
    "CORRESPONDENCE_DIGEST_DOMAIN",
    "CORRESPONDENCE_PROPOSALS_SCHEMA_VERSION",
    "CORRESPONDENCE_RECONCILIATION_SCHEMA_VERSION",
    "CorrespondenceAdjudication",
    "CorrespondenceAuthority",
    "CorrespondenceEvidence",
    "CorrespondenceProposal",
    "CorrespondenceSourceArtifacts",
    "Digest",
    "EvidenceSource",
    "EvidenceStrength",
    "ObligationAuthorityRecord",
    "ProposalProvenance",
    "ProposalSet",
    "ReconciledProposal",
    "ReconciliationError",
    "ReconciliationResult",
    "RelationKind",
    "SourceArtifactPins",
    "StructuralAuthorityRecord",
    "compute_proposal_id",
    "compute_ica_enumeration_digest",
    "compute_loss_analysis_digest",
    "compute_relation_id",
]
