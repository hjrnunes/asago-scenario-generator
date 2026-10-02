"""Closed domain contracts for the Phase 2 system-resource map.

The resource map is deliberately a small, typed sidecar. It joins the
canonical capability-resource identities owned by the taxonomy pipeline to
the identifiers owned by the STPA control structure. It does not contain
scenario prose, correspondence decisions, or persistence-specific state.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Annotated, Any, Literal, TypeAlias

import yaml
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, model_validator

from asago_scenario_generator.models.attack_pattern_projection import (
    CanonicalResourceReference,
)
from asago_scenario_generator.models.capability_profile import InventoryCompleteness
from asago_scenario_generator.models.canonical import (
    canonical_json_bytes,
    compute_framed_digest,
    normalize_unicode,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
SYSTEM_RESOURCE_MAP_SCHEMA_VERSION = "system-resource-map-v1"
SYSTEM_RESOURCE_MAP_DIGEST_DOMAIN = "asago-scenario-generator:system-resource-map:v1"
CONTROL_STRUCTURE_DIGEST_DOMAIN = "asago-scenario-generator:control-structure:v1"


class ResourceMapModel(BaseModel):
    """Common closed and immutable configuration for map contracts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="before")
    @classmethod
    def normalize_input(cls, value: Any) -> Any:
        """Apply the repository's NFC rule before identity is interpreted."""
        return normalize_unicode(value)


class ResponsibilityReference(ResourceMapModel):
    """Reference to an STPA responsibility (``RESP-*``)."""

    kind: Literal["RESP", "resp", "responsibility"] = "RESP"
    id: str = Field(
        validation_alias=AliasChoices("id", "resp_id"), pattern=r"^RESP-\d+$"
    )

    @model_validator(mode="after")
    def canonical_kind(self) -> "ResponsibilityReference":
        object.__setattr__(self, "kind", "RESP")
        return self


class ProcessModelReference(ResourceMapModel):
    """Reference to an STPA process-model part (``PM-*``)."""

    kind: Literal["PM", "pm", "process_model", "process-model"] = "PM"
    id: str = Field(
        validation_alias=AliasChoices("id", "pm_id"), pattern=r"^PM-\d+-\d+$"
    )

    @model_validator(mode="after")
    def canonical_kind(self) -> "ProcessModelReference":
        object.__setattr__(self, "kind", "PM")
        return self


class ControlActionReference(ResourceMapModel):
    """Reference to an STPA control action (``CA-*``)."""

    kind: Literal["CA", "ca", "control_action", "control-action"] = "CA"
    id: str = Field(
        validation_alias=AliasChoices("id", "ca_id"), pattern=r"^CA-\d+-\d+$"
    )

    @model_validator(mode="after")
    def canonical_kind(self) -> "ControlActionReference":
        object.__setattr__(self, "kind", "CA")
        return self


class FeedbackPathReference(ResourceMapModel):
    """Reference to an STPA feedback channel (``FB-*``)."""

    kind: Literal["FB", "fb", "feedback_path", "feedback-path"] = "FB"
    id: str = Field(
        validation_alias=AliasChoices("id", "fb_id"), pattern=r"^FB-\d+-\d+$"
    )

    @model_validator(mode="after")
    def canonical_kind(self) -> "FeedbackPathReference":
        object.__setattr__(self, "kind", "FB")
        return self


class ControlledProcessReference(ResourceMapModel):
    """Reference to an STPA controlled process (``CP-*``)."""

    kind: Literal["CP", "cp", "controlled_process", "controlled-process"] = "CP"
    id: str = Field(validation_alias=AliasChoices("id", "cp_id"), pattern=r"^CP-\d+$")

    @model_validator(mode="after")
    def canonical_kind(self) -> "ControlledProcessReference":
        object.__setattr__(self, "kind", "CP")
        return self


class CoordinationLinkReference(ResourceMapModel):
    """Reference to an STPA coordination link (``CL-*``)."""

    kind: Literal["CL", "cl", "coordination_link", "coordination-link"] = "CL"
    id: str = Field(validation_alias=AliasChoices("id", "link_id"), pattern=r"^CL-\d+$")

    @model_validator(mode="after")
    def canonical_kind(self) -> "CoordinationLinkReference":
        object.__setattr__(self, "kind", "CL")
        return self


class CoordinationMechanismReference(ResourceMapModel):
    """Reference to an STPA coordination mechanism (``CM-*``)."""

    kind: Literal["CM", "cm", "coordination_mechanism", "coordination-mechanism"] = "CM"
    id: str = Field(validation_alias=AliasChoices("id", "cm_id"), pattern=r"^CM-\d+$")

    @model_validator(mode="after")
    def canonical_kind(self) -> "CoordinationMechanismReference":
        object.__setattr__(self, "kind", "CM")
        return self


# The STPA models use namespace-specific field names (``ca_id``, ``pm_id``,
# and so on), while the resource-map wire contract uses one discriminated
# reference shape.  Read-only aliases keep both representations ergonomic
# without adding duplicate serialized fields or weakening the closed schema.
def _reference_id_property(field_name: str) -> property:
    """Build a read-only namespace-specific ID view for a reference."""
    return property(lambda self: self.id, doc=f"Alias for ``id`` as ``{field_name}``.")


ResponsibilityReference.resp_id = _reference_id_property("resp_id")  # type: ignore[attr-defined]
ProcessModelReference.pm_id = _reference_id_property("pm_id")  # type: ignore[attr-defined]
ControlActionReference.ca_id = _reference_id_property("ca_id")  # type: ignore[attr-defined]
FeedbackPathReference.fb_id = _reference_id_property("fb_id")  # type: ignore[attr-defined]
ControlledProcessReference.cp_id = _reference_id_property("cp_id")  # type: ignore[attr-defined]
CoordinationLinkReference.link_id = _reference_id_property("link_id")  # type: ignore[attr-defined]
CoordinationMechanismReference.cm_id = _reference_id_property("cm_id")  # type: ignore[attr-defined]


ControlStructureReference: TypeAlias = Annotated[
    ResponsibilityReference
    | ProcessModelReference
    | ControlActionReference
    | FeedbackPathReference
    | ControlledProcessReference
    | CoordinationLinkReference
    | CoordinationMechanismReference,
    Field(discriminator="kind"),
]


RelationKind = Literal[
    "receives_from",
    "acts_on",
    "represents",
    "emits_to",
    "crosses",
    "coordinates_via",
]
LinkProvenance = Literal[
    "operator_declared",
    "deterministically_derived",
    "model_proposed",
]
AuthorityStatus = Literal["authoritative", "advisory", "rejected"]


class ResourceLink(ResourceMapModel):
    """One evidence-bearing capability-resource/STPA identity link."""

    link_id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    capability_resource_ref: CanonicalResourceReference
    control_structure_ref: ControlStructureReference
    relation_kind: RelationKind
    provenance: LinkProvenance
    evidence_refs: tuple[str, ...] = ()
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    authority_status: AuthorityStatus

    @model_validator(mode="after")
    def canonical_evidence(self) -> "ResourceLink":
        """Canonicalize set-like evidence references and reject duplicates."""
        refs = tuple(sorted(self.evidence_refs))
        if any(not ref for ref in refs):
            raise ValueError("evidence_refs must contain non-empty identifiers")
        if len(refs) != len(set(refs)):
            raise ValueError("evidence_refs must be unique")
        object.__setattr__(self, "evidence_refs", refs)
        return self


def _link_payload(link: ResourceLink | Mapping[str, Any]) -> dict[str, Any]:
    """Return the JSON representation used by map identity and digests."""
    if isinstance(link, ResourceLink):
        return link.model_dump(mode="json")
    return ResourceLink.model_validate(link).model_dump(mode="json")


def _canonical_link_payloads(
    links: Sequence[ResourceLink | Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Sort links by complete identity, independent of authoring order."""
    payloads = [_link_payload(link) for link in links]
    return sorted(payloads, key=canonical_json_bytes)


def compute_resource_map_semantic_digest(
    *,
    schema_version: str,
    capability_snapshot_digest: str,
    control_structure_digest: str,
    links: Sequence[ResourceLink | Mapping[str, Any]],
) -> str:
    """Compute the version-framed digest over semantic map content."""
    return compute_framed_digest(
        SYSTEM_RESOURCE_MAP_DIGEST_DOMAIN,
        {
            "schema_version": schema_version,
            "capability_snapshot_digest": capability_snapshot_digest,
            "control_structure_digest": control_structure_digest,
            "links": _canonical_link_payloads(links),
        },
    )


def _canonical_control_structure_payload(
    control_structure: ControlStructure | Mapping[str, Any],
) -> dict[str, Any]:
    """Normalize STPA collections before pinning their semantic content."""
    if isinstance(control_structure, ControlStructure):
        payload = control_structure.model_dump(mode="json")
    else:
        payload = ControlStructure.model_validate(control_structure).model_dump(
            mode="json"
        )

    responsibilities = []
    for responsibility in payload["responsibilities"]:
        responsibility = dict(responsibility)
        responsibility["security_constraint_refs"] = sorted(
            responsibility.get("security_constraint_refs", [])
        )
        for field, id_field in (
            ("responsibility_constraints", "rc_id"),
            ("process_model_parts", "pm_id"),
            ("control_actions", "ca_id"),
            ("feedback_channels", "fb_id"),
        ):
            responsibility[field] = sorted(
                responsibility.get(field, []), key=lambda item: item[id_field]
            )
        responsibilities.append(responsibility)
    payload["responsibilities"] = sorted(
        responsibilities, key=lambda item: item["resp_id"]
    )
    payload["controlled_processes"] = sorted(
        payload.get("controlled_processes", []), key=lambda item: item["cp_id"]
    )
    payload["coordination_links"] = sorted(
        payload.get("coordination_links", []), key=lambda item: item["link_id"]
    )
    return payload


def compute_control_structure_digest(
    control_structure: ControlStructure | Mapping[str, Any],
) -> str:
    """Compute the deterministic pin for one STPA control structure."""
    return compute_framed_digest(
        CONTROL_STRUCTURE_DIGEST_DOMAIN,
        _canonical_control_structure_payload(control_structure),
    )


class SystemResourceMap(ResourceMapModel):
    """The closed, immutable ``system-resource-map-v1`` sidecar."""

    schema_version: Literal["system-resource-map-v1"]
    semantic_digest: Digest
    capability_snapshot_digest: Digest
    control_structure_digest: Digest
    links: tuple[ResourceLink, ...]

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "SystemResourceMap":
        """Sort links and verify the content address before publication."""
        # ``model_copy(update=...)`` intentionally does not revalidate nested
        # values. Re-parse each link here so tampered in-memory models cannot
        # smuggle raw dictionaries past the closed link contract.
        validated_links = tuple(
            ResourceLink.model_validate(link.model_dump(mode="json"))
            for link in self.links
        )
        ordered = tuple(
            sorted(
                validated_links,
                key=lambda link: canonical_json_bytes(link.model_dump(mode="json")),
            )
        )
        object.__setattr__(self, "links", ordered)
        expected = compute_resource_map_semantic_digest(
            schema_version=self.schema_version,
            capability_snapshot_digest=self.capability_snapshot_digest,
            control_structure_digest=self.control_structure_digest,
            links=ordered,
        )
        if self.semantic_digest != expected:
            raise ValueError(
                "semantic_digest does not match system-resource-map content"
            )
        return self

    def compute_semantic_digest(self) -> str:
        """Compute the current semantic digest without modifying this map."""
        return compute_resource_map_semantic_digest(
            schema_version=self.schema_version,
            capability_snapshot_digest=self.capability_snapshot_digest,
            control_structure_digest=self.control_structure_digest,
            links=self.links,
        )

    def assert_integrity(self) -> None:
        """Raise when the content-addressed map has been tampered with."""
        expected = self.compute_semantic_digest()
        if self.semantic_digest != expected:
            raise ValueError(
                f"Digest mismatch: recorded '{self.semantic_digest}' != computed '{expected}'"
            )

    def to_yaml(self) -> str:
        """Serialize the map using deterministic, reviewable YAML."""
        self.assert_integrity()
        return yaml.dump(
            self.model_dump(mode="json"),
            default_flow_style=False,
            sort_keys=True,
            allow_unicode=True,
            default_style='"',
        )

    @classmethod
    def from_yaml(cls, text: str | bytes) -> "SystemResourceMap":
        """Load and integrity-check a YAML map."""
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise ValueError("YAML system resource map must be a mapping")
        return cls._load_checked(data)

    def to_json(self) -> str:
        """Serialize the map as deterministic diagnostic JSON."""
        self.assert_integrity()
        return (
            json.dumps(
                self.model_dump(mode="json"),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n"
        )

    @classmethod
    def from_json(cls, text: str | bytes) -> "SystemResourceMap":
        """Load and integrity-check a JSON map."""
        try:
            data = json.loads(text)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid JSON system resource map: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON system resource map must be a mapping")
        return cls._load_checked(data)

    @classmethod
    def _load_checked(cls, data: dict[str, Any]) -> "SystemResourceMap":
        """Apply the closed schema and content-address checks in order."""
        if data.get("schema_version") != SYSTEM_RESOURCE_MAP_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported system resource map schema version: {data.get('schema_version')!r}"
            )
        resource_map = cls.model_validate(data)
        resource_map.assert_integrity()
        return resource_map


class ResourceMapViolation(ResourceMapModel):
    """One deterministic validation violation or non-blocking warning."""

    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    link_id: str | None = None
    field: str | None = None


class SystemResourceMapValidation(ResourceMapModel):
    """Typed, side-effect-free result of validating one resource map."""

    is_valid: bool
    violations: tuple[ResourceMapViolation, ...] = ()
    warnings: tuple[ResourceMapViolation, ...] = ()
    canonical_map: SystemResourceMap | None = None
    entry_point_completeness: InventoryCompleteness | None = None
    tool_inventory_completeness: InventoryCompleteness | None = None
    network_calls: Literal[0] = 0
    model_calls: Literal[0] = 0

    @model_validator(mode="after")
    def require_inventory_attestation(self) -> "SystemResourceMapValidation":
        """Bind every successful canonical-map attestation to inventory authority."""
        has_successful_map = self.is_valid and self.canonical_map is not None
        missing_entry_points = self.entry_point_completeness is None
        missing_tools = self.tool_inventory_completeness is None
        if has_successful_map and (missing_entry_points or missing_tools):
            raise ValueError(
                "valid resource-map attestation requires capability inventory completeness"
            )
        return self

    @property
    def errors(self) -> tuple[ResourceMapViolation, ...]:
        """Compatibility spelling for callers that call violations errors."""
        return self.violations

    @property
    def issues(self) -> tuple[ResourceMapViolation, ...]:
        """Return violations under the common issue-oriented spelling."""
        return self.violations

    @property
    def unresolved(self) -> tuple[str, ...]:
        """Return identifiers reported as unresolved, in stable order."""
        return tuple(
            sorted(
                {
                    violation.link_id
                    for violation in self.violations + self.warnings
                    if violation.code.startswith("unknown_")
                    and violation.link_id is not None
                }
            )
        )

    @property
    def links_by_authority(self) -> dict[str, tuple[str, ...]]:
        """Summarize canonical link IDs by their declared authority status."""
        if self.canonical_map is None:
            return {}
        grouped: dict[str, list[str]] = {}
        for link in self.canonical_map.links:
            grouped.setdefault(link.authority_status, []).append(link.link_id)
        return {key: tuple(values) for key, values in sorted(grouped.items())}


__all__ = [
    "AuthorityStatus",
    "ControlActionReference",
    "ControlStructureReference",
    "CoordinationLinkReference",
    "CoordinationMechanismReference",
    "ControlledProcessReference",
    "Digest",
    "FeedbackPathReference",
    "LinkProvenance",
    "ProcessModelReference",
    "RelationKind",
    "ResourceLink",
    "ResourceMapModel",
    "ResourceMapViolation",
    "ResponsibilityReference",
    "SYSTEM_RESOURCE_MAP_DIGEST_DOMAIN",
    "SYSTEM_RESOURCE_MAP_SCHEMA_VERSION",
    "SystemResourceMap",
    "SystemResourceMapValidation",
    "compute_control_structure_digest",
    "compute_resource_map_semantic_digest",
]
