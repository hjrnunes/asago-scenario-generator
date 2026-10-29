"""Causal-factor kinds, namespaces, and boundary schema.

Neutral home for STPA causal-factor vocabulary shared by Stage 5
assembly and Stage 6 prompt derivation.  One kind-to-namespace map keys
the control-structure identifier prefix each kind must cite, so no
caller hand-authors a per-kind mapping that can drift from what strict
traceability accepts.

``CausalFactor`` is the boundary schema for one declared, evidence-backed
causal factor.  ``declared_timing`` is optional free-form Stage 5 evidence
text; ``temporal_condition`` carries the typed form of that evidence.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, model_validator

from asago_scenario_generator.stpa.models.semantic_conditions import SemanticCondition

if TYPE_CHECKING:
    from asago_scenario_generator.stpa.models.control_structure import (
        ControlStructure,
    )


class CausalFactorKind(str, Enum):
    """Kind of STPA causal factor."""

    process_model_flaw = "PROCESS_MODEL_FLAW"
    feedback_delay = "FEEDBACK_DELAY"
    sensor_anomaly = "SENSOR_ANOMALY"
    actuator_anomaly = "ACTUATOR_ANOMALY"
    # The controller's belief is right but its decision rule is wrong.
    inadequate_control_algorithm = "INADEQUATE_CONTROL_ALGORITHM"


def is_belief_flaw(kind: CausalFactorKind) -> bool:
    """Return whether a factor of ``kind`` explains the action by a flawed belief.

    A decision-rule factor explains it by the rule the controller applies to a
    correct belief, so it states no flawed belief.
    """
    return kind is not CausalFactorKind.inadequate_control_algorithm


class CausalEvidenceStatus(str, Enum):
    """Evidence basis for one Stage 5 causal factor.

    ``structural_failure`` describes a condition already present in the
    selected control loop; it does not grant an attacker an access path.
    ``reachable_capability`` is reserved for a capability and access path
    explicitly retained by :class:`ScenarioGenerationContext`.
    ``bounded_assumption`` makes an uncertain connection visible without
    promoting it to structural or capability evidence.
    """

    structural_failure = "structural_failure"
    reachable_capability = "reachable_capability"
    bounded_assumption = "bounded_assumption"

    @classmethod
    def _missing_(cls, value: object) -> "CausalEvidenceStatus | None":
        """Accept concise legacy spellings while serializing canonically."""
        aliases = {
            "structural": cls.structural_failure,
            "reachable": cls.reachable_capability,
            "assumption": cls.bounded_assumption,
        }
        return aliases.get(value)


def validate_causal_evidence_shape(
    status: CausalEvidenceStatus,
    capability_refs: Sequence[str],
    access_refs: Sequence[str],
    bounded_assumption: str | None,
) -> None:
    """Validate the evidence fields shared by drafts and compiled factors."""
    if status is CausalEvidenceStatus.reachable_capability:
        if not capability_refs:
            raise ValueError(
                "reachable_capability causal factor requires capability_refs"
            )
        if not access_refs:
            raise ValueError("reachable_capability causal factor requires access_refs")
    elif capability_refs or access_refs:
        raise ValueError(
            "capability_refs and access_refs require "
            "reachable_capability evidence status"
        )

    if status is CausalEvidenceStatus.bounded_assumption:
        if not bounded_assumption or not bounded_assumption.strip():
            raise ValueError(
                "bounded_assumption evidence requires bounded_assumption text"
            )
    elif bounded_assumption is not None:
        raise ValueError(
            "bounded_assumption text requires bounded_assumption evidence status"
        )


# Control-structure identifier prefixes that each kind of factor may cite.  A
# decision-rule factor cites the selected controller itself: its
# responsibility, or the coordination link of a coordination slot.
_NAMESPACES_BY_KIND: dict[CausalFactorKind, tuple[str, ...]] = {
    CausalFactorKind.process_model_flaw: ("PM",),
    CausalFactorKind.feedback_delay: ("FB",),
    CausalFactorKind.sensor_anomaly: ("FB",),
    CausalFactorKind.actuator_anomaly: ("CA",),
    CausalFactorKind.inadequate_control_algorithm: ("RESP", "CL"),
}


def namespaces_for(kind: CausalFactorKind) -> tuple[str, ...]:
    """Return the control-structure namespace prefixes for a factor kind."""
    return _NAMESPACES_BY_KIND[kind]


def namespace_for(kind: CausalFactorKind) -> str:
    """Name the control-structure namespace of a factor kind, for messages."""
    return " or ".join(namespaces_for(kind))


class ProcessModelVariable(BaseModel):
    """The process-model variable that holds a factor's stated flawed belief.

    ``pm_id`` names a variable of the selected control path; ``None`` records
    a gap, where ``description`` describes the variable the controller would
    need.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    pm_id: str | None
    description: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_pm_namespace(self) -> ProcessModelVariable:
        if self.pm_id is not None and not self.pm_id.startswith("PM-"):
            raise ValueError(
                f"process-model variable '{self.pm_id}' must use the PM namespace"
            )
        return self


class CausalFactor(BaseModel):
    """A structural causal factor explaining an unsafe control action.

    ``source_id`` is a stable control-structure identifier (PM-X-Y for
    process-model flaws, FB-X-Y for feedback delays and sensor
    anomalies, CA-X-Y for actuator anomalies, and the selected controller's
    RESP-X or CL-X for a decision-rule factor); ``description`` is the
    Stage 5 evidence text.  ``declared_timing`` carries optional
    declared timing evidence; ``temporal_condition`` carries its typed
    form.
    """

    model_config = ConfigDict(extra="forbid")

    kind: CausalFactorKind
    source_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    declared_timing: str | None = None
    evidence_status: CausalEvidenceStatus = CausalEvidenceStatus.structural_failure
    capability_refs: tuple[str, ...] = ()
    access_refs: tuple[str, ...] = ()
    bounded_assumption: str | None = None
    # Corrected Stage 5 responses carry the neutral typed semantic
    # condition leaf.  ``None`` explicitly means
    # that no separately supported temporal constraint was evidenced.
    temporal_condition: SemanticCondition | None = None
    # Set only by a Stage 5 request that asks for stated flawed beliefs, and
    # never for a factor whose kind is not a belief flaw; left out when unset
    # so earlier specs keep their bytes.
    flawed_belief: str | None = Field(
        default=None, min_length=1, exclude_if=lambda value: value is None
    )
    process_model_variable: ProcessModelVariable | None = Field(
        default=None, exclude_if=lambda value: value is None
    )

    @model_validator(mode="after")
    def validate_source_namespace(self) -> CausalFactor:
        prefixes = tuple(f"{item}-" for item in namespaces_for(self.kind))
        if not self.source_id.startswith(prefixes):
            raise ValueError(
                f"CausalFactor {self.kind.value} source_id "
                f"'{self.source_id}' must use the "
                f"{namespace_for(self.kind)} namespace; it is not a known "
                f"{namespace_for(self.kind)} identifier."
            )
        return self

    @model_validator(mode="after")
    def validate_evidence_shape(self) -> CausalFactor:
        """Keep evidence basis and supporting references internally coherent."""
        validate_causal_evidence_shape(
            self.evidence_status,
            self.capability_refs,
            self.access_refs,
            self.bounded_assumption,
        )
        return self


def collect_source_ids(
    control_structure: ControlStructure,
) -> dict[CausalFactorKind, set[str]]:
    """Collect valid source identifiers per causal factor kind.

    Returns:
        A mapping from each causal-factor kind to the set of control
        structure IDs its sources may reference.
    """
    pm_ids: set[str] = set()
    fb_ids: set[str] = set()
    ca_ids: set[str] = set()
    controller_ids = {link.link_id for link in control_structure.coordination_links}
    for responsibility in control_structure.responsibilities:
        pm_ids.update(pm.pm_id for pm in responsibility.process_model_parts)
        fb_ids.update(fb.fb_id for fb in responsibility.feedback_channels)
        ca_ids.update(ca.ca_id for ca in responsibility.control_actions)
        controller_ids.add(responsibility.resp_id)
    return {
        CausalFactorKind.process_model_flaw: pm_ids,
        CausalFactorKind.feedback_delay: fb_ids,
        CausalFactorKind.sensor_anomaly: fb_ids,
        CausalFactorKind.actuator_anomaly: ca_ids,
        CausalFactorKind.inadequate_control_algorithm: controller_ids,
    }


def validate_factor_sources(
    control_structure: ControlStructure,
    causal_factors: Sequence[CausalFactor],
) -> None:
    """Validate every causal-factor source against its structural namespace.

    Raises:
        ValueError: When a causal factor references an identifier that is
            not present in the control structure — a causal-factor
            reference validation error.
    """
    source_ids = collect_source_ids(control_structure)
    for factor in causal_factors:
        valid = source_ids[factor.kind]
        if factor.source_id not in valid:
            raise ValueError(
                f"Causal factor {factor.kind.value} source "
                f"'{factor.source_id}' is not a known "
                f"{namespace_for(factor.kind)} identifier in the control "
                "structure."
            )


__all__ = [
    "CausalFactor",
    "CausalEvidenceStatus",
    "CausalFactorKind",
    "ProcessModelVariable",
    "collect_source_ids",
    "is_belief_flaw",
    "namespace_for",
    "namespaces_for",
    "validate_causal_evidence_shape",
    "validate_factor_sources",
]
