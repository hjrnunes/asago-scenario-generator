"""System resource map domain models and serialization contracts."""

from __future__ import annotations

import json
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

VALID_ENTITY_FAMILIES = frozenset(
    {
        "system-resource",
        "actor-controller",
        "controlled-process",
        "control-action",
        "feedback-path",
        "trust-boundary",
        "data-flow",
        "loss-link",
        "use-case-fact",
    }
)

VALID_RESOLUTION_STATUSES = frozenset({"unknown", "absent", "present", "resolved"})

VALID_PROVENANCE_KINDS = frozenset({"analyst", "imported-source"})

# Entity-family name -> SystemResourceMap collection attribute.
_FAMILY_ATTRIBUTES = (
    ("system-resource", "system_resources"),
    ("actor-controller", "actor_controllers"),
    ("controlled-process", "controlled_processes"),
    ("control-action", "control_actions"),
    ("feedback-path", "feedback_paths"),
    ("trust-boundary", "trust_boundaries"),
    ("data-flow", "data_flows"),
    ("loss-link", "loss_links"),
    ("use-case-fact", "use_case_facts"),
    ("assertion", "assertions"),
)


class SystemResourceEntry(BaseModel):
    """System resource definition or mapped component."""

    model_config = ConfigDict(extra="ignore")

    element_id: str
    name: str = ""
    description: str = ""
    taxonomy_ref: str | None = None
    entity_family: str = "system-resource"


class ActorControllerEntry(BaseModel):
    """STPA controller reference entry."""

    model_config = ConfigDict(extra="ignore")

    element_id: str
    name: str = ""
    description: str = ""
    entity_family: str = "actor-controller"


class ControlledProcessEntry(BaseModel):
    """STPA controlled process reference entry."""

    model_config = ConfigDict(extra="ignore")

    element_id: str
    name: str = ""
    description: str = ""
    entity_family: str = "controlled-process"


class ControlActionEntry(BaseModel):
    """STPA control action mapping entry."""

    model_config = ConfigDict(extra="ignore")

    element_id: str
    controller_id: str = ""
    process_id: str = ""
    action_name: str = ""
    entity_family: str = "control-action"


class FeedbackPathEntry(BaseModel):
    """STPA feedback path mapping entry."""

    model_config = ConfigDict(extra="ignore")

    element_id: str
    controller_id: str = ""
    process_id: str = ""
    feedback_name: str = ""
    entity_family: str = "feedback-path"


class TrustBoundaryEntry(BaseModel):
    """Trust boundary mapping entry."""

    model_config = ConfigDict(extra="ignore")

    element_id: str
    name: str = ""
    resource_ids: list[str] = Field(default_factory=list)
    taxonomy_ref: str | None = None
    entity_family: str = "trust-boundary"


class DataFlowEntry(BaseModel):
    """Data flow mapping entry."""

    model_config = ConfigDict(extra="ignore")

    element_id: str
    name: str = ""
    source_resource_id: str = ""
    target_resource_id: str = ""
    entity_family: str = "data-flow"


class LossLinkEntry(BaseModel):
    """STPA loss and hazard link entry."""

    model_config = ConfigDict(extra="ignore")

    element_id: str
    loss_id: str = ""
    hazard_id: str = ""
    entity_family: str = "loss-link"


class UseCaseFactEntry(BaseModel):
    """Use case fact entry with explicit resolution status and provenance."""

    model_config = ConfigDict(extra="ignore")

    element_id: str
    fact_key: str = ""
    resolution_status: str = "unknown"
    provenance_kind: str | None = None
    entity_family: str = "use-case-fact"


class ResourceAssertionEntry(BaseModel):
    """Analyst assertion with optional provenance."""

    model_config = ConfigDict(extra="ignore")

    element_id: str
    description: str = ""
    provenance_kind: str | None = None
    entity_family: str = "assertion"


class ResourceMapSnapshot(BaseModel):
    """Pinned resource map snapshot fixture."""

    model_config = ConfigDict(extra="ignore")

    schema_version: str | int = "1"
    stpa_version: str = "stpa-v1"
    taxonomy_version: str = "atlas-2026.05"
    stpa_identifiers: list[str] = Field(default_factory=list)
    taxonomy_identifiers: list[str] = Field(default_factory=list)
    facts: dict[str, Any] = Field(default_factory=dict)


class ResourceMapValidationIssue(BaseModel):
    """Validation error or warning issue."""

    model_config = ConfigDict(extra="ignore")

    code: str
    message: str
    element_id: str | None = None
    field: str | None = None


class ResourceMapValidationResult(BaseModel):
    """Outcome of validating a SystemResourceMap."""

    model_config = ConfigDict(extra="ignore")

    is_valid: bool = True
    errors: list[ResourceMapValidationIssue] = Field(default_factory=list)
    warnings: list[ResourceMapValidationIssue] = Field(default_factory=list)
    correspondence_relations: list[Any] = Field(default_factory=list)
    canonical_map: SystemResourceMap | None = None
    network_calls: int = 0
    model_calls: int = 0


class SystemResourceMap(BaseModel):
    """Typed, reviewable map from facts and STPA elements to taxonomy resources."""

    model_config = ConfigDict(extra="ignore")

    schema_version: str | int = "1"
    stpa_version: str
    taxonomy_version: str
    system_resources: list[SystemResourceEntry] = Field(default_factory=list)
    actor_controllers: list[ActorControllerEntry] = Field(default_factory=list)
    controlled_processes: list[ControlledProcessEntry] = Field(default_factory=list)
    control_actions: list[ControlActionEntry] = Field(default_factory=list)
    feedback_paths: list[FeedbackPathEntry] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundaryEntry] = Field(default_factory=list)
    data_flows: list[DataFlowEntry] = Field(default_factory=list)
    loss_links: list[LossLinkEntry] = Field(default_factory=list)
    use_case_facts: list[UseCaseFactEntry] = Field(default_factory=list)
    assertions: list[ResourceAssertionEntry] = Field(default_factory=list)
    aliases: dict[str, Any] = Field(default_factory=dict)

    def to_yaml(self) -> str:
        """Serialize resource map to deterministic YAML string."""
        data = self.model_dump(mode="json")
        # Double-quoted style is required for losslessness: PyYAML's plain,
        # single-quoted, and literal styles silently corrupt U+0085 (NEL)
        # values, which its reader treats as a line break.
        block_style = False
        sort_keys = True
        allow_unicode = True
        default_style = '"'
        return yaml.dump(
            data,
            default_flow_style=block_style,
            sort_keys=sort_keys,
            allow_unicode=allow_unicode,
            default_style=default_style,
        )

    @classmethod
    def from_yaml(cls, text: str | bytes) -> SystemResourceMap:
        """Deserialize resource map from YAML text or bytes."""
        data = yaml.safe_load(text)
        return cls.model_validate(data)

    def to_json(self) -> str:
        """Serialize resource map to deterministic JSON string."""
        data = self.model_dump(mode="json")
        return json.dumps(data, indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_json(cls, text: str | bytes) -> SystemResourceMap:
        """Deserialize resource map from JSON text or bytes."""
        data = json.loads(text)
        return cls.model_validate(data)

    def get_family(self, family: str) -> list[dict[str, Any]]:
        """Access entities for a specific entity family."""
        entries: list[Any] = []
        for family_name, attribute in _FAMILY_ATTRIBUTES:
            if family_name == family:
                entries = getattr(self, attribute)
                break
        return [entry.model_dump(mode="json") for entry in entries]


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-27T22:30:24Z","module_hash":"f9b56fc8aabbba5df8ad179a39485a9e90479351b6c23c6a88b16b07fc02f365","source_sha256":"c069640fb1f558ebdf04919dcf3bc4a3d29fbc22a135d22091e36668f074d0b8","functions":[{"id":"func/SystemResourceMap.to_yaml","name":"to_yaml","line":218,"end_line":234,"hash":"0fa413f815d62c7af1f8977bdad78376158fe46a682bf820acb54813f734f23b"},{"id":"func/SystemResourceMap.from_yaml","name":"from_yaml","line":237,"end_line":240,"hash":"c5794ac41833d3e0c00a28daf7355b3a13b3da710e4b7ca5b98b659fc25c102b"},{"id":"func/SystemResourceMap.to_json","name":"to_json","line":242,"end_line":245,"hash":"bbe1d0d5c111b9268abbdde28aac53719cabc504419ddbe363778022600db3af"},{"id":"func/SystemResourceMap.from_json","name":"from_json","line":248,"end_line":251,"hash":"cfa22da71398bcde730c41af92e9b19c2da45e1346ede7fa3e97a9000ecb7044"},{"id":"func/SystemResourceMap.get_family","name":"get_family","line":253,"end_line":260,"hash":"97d3b7c7d1bb67847f1568865fe22c30fb2c8da07428cfb7871bce427866d149"}]}
# mutate4py-manifest-end
