"""Canonical per-kind causal-factor registry and boundary schema.

Neutral home for STPA causal-factor behavior shared by the execution
envelope models, Stage 5 assembly, and Stage 6 prompt derivation:
namespace prefix, temporal predicate, scenario-step kind, and step text
are all keyed by one registry so no caller hand-authors a per-kind
mapping that can drift from what strict traceability accepts.

``CausalFactor`` is the boundary schema for one declared, evidence-backed
causal factor.  ``declared_timing`` is optional free-form Stage 5 evidence
text; typed temporal constraints are derived deterministically from it
(``None`` timing or unknown phrasing yields no constraint and a binding
requirement, never a guessed value).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, model_validator

from asago_scenario_generator.stpa.models.semantic_conditions import SemanticCondition

if TYPE_CHECKING:
    from asago_scenario_generator.stpa.models.control_structure import (
        ControlStructure,
    )


class CausalFactorKind(str, Enum):
    """Kind of STPA causal factor mapped into an execution envelope."""

    process_model_flaw = "PROCESS_MODEL_FLAW"
    feedback_delay = "FEEDBACK_DELAY"
    sensor_anomaly = "SENSOR_ANOMALY"
    actuator_anomaly = "ACTUATOR_ANOMALY"


class CausalMechanism(str, Enum):
    """STPA-Sec mechanism by which an adversary realizes a causal factor.

    - ``none``: no adversarial mechanism; an ordinary control-loop failure;
    - ``accepted_untrusted_claim``: the controller accepts a claim the user
      or earlier conversation supplies (for example, an asserted identity or
      entitlement) as if it were verified feedback;
    - ``injected_instruction``: retrieved or tool-returned content carries an
      instruction the controller follows as if it came from its principal;
    - ``backend_non_enforcement``: the operation the controller invokes does
      not enforce the constraint itself, so an unsafe invocation takes effect.
    """

    none = "none"
    accepted_untrusted_claim = "accepted_untrusted_claim"
    injected_instruction = "injected_instruction"
    backend_non_enforcement = "backend_non_enforcement"


_MECHANISM_KINDS: dict["CausalMechanism", frozenset["CausalFactorKind"]] = {}

# Feedback source kinds (see ``FeedbackSourceKind``) each mechanism may use
# when the factor's feedback channel declares one.
MECHANISM_FEEDBACK_SOURCES: dict[CausalMechanism, frozenset[str]] = {
    CausalMechanism.accepted_untrusted_claim: frozenset(
        {"user_message", "conversation_history"}
    ),
    CausalMechanism.injected_instruction: frozenset({"retrieved_content"}),
}


def validate_mechanism_pairing(
    mechanism: CausalMechanism,
    kind: "CausalFactorKind",
    feedback_source_kind: str | None = None,
) -> None:
    """Reject a mechanism on a factor kind or feedback source it cannot explain."""
    allowed = _MECHANISM_KINDS[mechanism]
    if kind not in allowed:
        names = ", ".join(sorted(item.value for item in allowed))
        raise ValueError(
            f"mechanism {mechanism.value} requires a causal factor of kind "
            f"{names}; got {kind.value}"
        )
    sources = MECHANISM_FEEDBACK_SOURCES.get(mechanism)
    if (
        sources is not None
        and kind is not CausalFactorKind.process_model_flaw
        and feedback_source_kind is not None
        and feedback_source_kind not in sources
    ):
        raise ValueError(
            f"mechanism {mechanism.value} requires feedback from "
            f"{', '.join(sorted(sources))}; the selected channel carries "
            f"{feedback_source_kind}"
        )


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


class TemporalPredicate(str, Enum):
    """Executable predicate encoded by a temporal assertion."""

    model_flawed = "MODEL_FLAWED"
    feedback_delayed = "FEEDBACK_DELAYED"
    sensor_anomalous = "SENSOR_ANOMALOUS"
    actuator_anomalous = "ACTUATOR_ANOMALOUS"


class ScenarioStepKind(str, Enum):
    """Kind of a deterministic scenario step in the temporal vector."""

    process_model_flaw = "PROCESS_MODEL_FLAW"
    feedback_delay = "FEEDBACK_DELAY"
    sensor_anomaly = "SENSOR_ANOMALY"
    actuator_anomaly = "ACTUATOR_ANOMALY"
    unsafe_control_action = "UNSAFE_CONTROL_ACTION"


@dataclass(frozen=True)
class CausalFactorBehavior:
    """One canonical behavior entry for a causal-factor kind.

    ``step_text`` is a Jinja-style template with ``{source}`` and
    ``{action}`` placeholders used by the deterministic Stage 6 steps.
    """

    namespace: str
    predicate: TemporalPredicate
    step_kind: ScenarioStepKind
    step_text: str


_CAUSAL_FACTOR_BEHAVIOR: dict[CausalFactorKind, CausalFactorBehavior] = {
    CausalFactorKind.process_model_flaw: CausalFactorBehavior(
        namespace="PM",
        predicate=TemporalPredicate.model_flawed,
        step_kind=ScenarioStepKind.process_model_flaw,
        step_text=(
            "Process model part {source} is flawed before control action "
            "{action} is issued"
        ),
    ),
    CausalFactorKind.feedback_delay: CausalFactorBehavior(
        namespace="FB",
        predicate=TemporalPredicate.feedback_delayed,
        step_kind=ScenarioStepKind.feedback_delay,
        step_text=(
            "Feedback channel {source} is delayed before control action "
            "{action} is issued"
        ),
    ),
    CausalFactorKind.sensor_anomaly: CausalFactorBehavior(
        namespace="FB",
        predicate=TemporalPredicate.sensor_anomalous,
        step_kind=ScenarioStepKind.sensor_anomaly,
        step_text=(
            "Sensor reporting through {source} is anomalous before control "
            "action {action} is issued"
        ),
    ),
    CausalFactorKind.actuator_anomaly: CausalFactorBehavior(
        namespace="CA",
        predicate=TemporalPredicate.actuator_anomalous,
        step_kind=ScenarioStepKind.actuator_anomaly,
        step_text=(
            "Actuator {source} is anomalous before control action {action} is issued"
        ),
    ),
}


_MECHANISM_KINDS.update(
    {
        CausalMechanism.none: frozenset(CausalFactorKind),
        CausalMechanism.accepted_untrusted_claim: frozenset(
            {CausalFactorKind.process_model_flaw, CausalFactorKind.sensor_anomaly}
        ),
        CausalMechanism.injected_instruction: frozenset(
            {CausalFactorKind.sensor_anomaly}
        ),
        CausalMechanism.backend_non_enforcement: frozenset(
            {CausalFactorKind.actuator_anomaly}
        ),
    }
)


def behavior_for(kind: CausalFactorKind) -> CausalFactorBehavior:
    """Return the canonical behavior registry entry for a factor kind."""
    return _CAUSAL_FACTOR_BEHAVIOR[kind]


def predicate_for(kind: CausalFactorKind) -> TemporalPredicate:
    """Return the executable predicate canonically paired with a factor kind."""
    return behavior_for(kind).predicate


def step_kind_for(kind: CausalFactorKind) -> ScenarioStepKind:
    """Return the scenario-step kind canonically paired with a factor kind."""
    return behavior_for(kind).step_kind


def namespace_for(kind: CausalFactorKind) -> str:
    """Return the control-structure namespace prefix for a factor kind."""
    return behavior_for(kind).namespace


def step_text_for(kind: CausalFactorKind) -> str:
    """Return the canonical scenario-step text template for a factor kind."""
    return behavior_for(kind).step_text


class CausalFactor(BaseModel):
    """A structural causal factor explaining an unsafe control action.

    ``source_id`` is a stable control-structure identifier (PM-X-Y for
    process-model flaws, FB-X-Y for feedback delays and sensor
    anomalies, CA-X-Y for actuator anomalies); ``description`` is the
    Stage 5 evidence text.  ``declared_timing`` carries optional
    declared timing evidence; typed temporal constraints are derived
    from it deterministically at projection time.
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
    mechanism: CausalMechanism = Field(
        default=CausalMechanism.none,
        exclude_if=lambda value: value is CausalMechanism.none,
    )

    @model_validator(mode="after")
    def validate_mechanism(self) -> CausalFactor:
        """Keep the STPA-Sec mechanism paired with a compatible factor kind."""
        validate_mechanism_pairing(self.mechanism, self.kind)
        return self

    @model_validator(mode="after")
    def validate_source_namespace(self) -> CausalFactor:
        expected_prefix = f"{namespace_for(self.kind)}-"
        if not self.source_id.startswith(expected_prefix):
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
    for responsibility in control_structure.responsibilities:
        pm_ids.update(pm.pm_id for pm in responsibility.process_model_parts)
        fb_ids.update(fb.fb_id for fb in responsibility.feedback_channels)
        ca_ids.update(ca.ca_id for ca in responsibility.control_actions)
    return {
        CausalFactorKind.process_model_flaw: pm_ids,
        CausalFactorKind.feedback_delay: fb_ids,
        CausalFactorKind.sensor_anomaly: fb_ids,
        CausalFactorKind.actuator_anomaly: ca_ids,
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
    "CausalFactorBehavior",
    "CausalEvidenceStatus",
    "CausalFactorKind",
    "CausalMechanism",
    "MECHANISM_FEEDBACK_SOURCES",
    "ScenarioStepKind",
    "TemporalPredicate",
    "behavior_for",
    "collect_source_ids",
    "namespace_for",
    "predicate_for",
    "step_kind_for",
    "step_text_for",
    "validate_causal_evidence_shape",
    "validate_factor_sources",
    "validate_mechanism_pairing",
]
