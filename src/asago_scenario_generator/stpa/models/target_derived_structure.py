"""Closed artifacts for the target-derived Stage 2 control structure.

Phase 2 of the target-grounded scenario generation spec: when an observed
execution target profile is supplied and the capability profile says
``multi_agent: false``, the Stage 2 control structure is derived
deterministically from the target instead of being invented by model calls.

Two closed artifacts are produced:

- ``TargetDerivedStructure`` (``target-derived-structure.yaml``): the pinned
  record of what was derived, why each action exists, and the exact
  resource/operation binding per tool action.  The identity target-realization
  interpreter consumes these bindings with zero additional model calls.
- ``ConstraintActionRelevance`` (``constraint-action-relevance.yaml``): the
  per-constraint relevant-action table from spec 2.3, persisted for the later
  authoring phase.  It does not change the ICA slot universe.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    compute_framed_digest,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis

TARGET_DERIVED_STRUCTURE_FILENAME = "target-derived-structure.yaml"
CONSTRAINT_ACTION_RELEVANCE_FILENAME = "constraint-action-relevance.yaml"

TARGET_DERIVED_STRUCTURE_SCHEMA_VERSION = "target-derived-structure-v1"
TARGET_DERIVED_STRUCTURE_DIGEST_DOMAIN = (
    "asago-scenario-generator:target-derived-structure:v1"
)
CONSTRAINT_ACTION_RELEVANCE_SCHEMA_VERSION = "constraint-action-relevance-v1"
CONSTRAINT_ACTION_RELEVANCE_DIGEST_DOMAIN = (
    "asago-scenario-generator:constraint-action-relevance:v1"
)
CONTROL_STRUCTURE_DIGEST_DOMAIN = (
    "asago-scenario-generator:control-structure-content:v1"
)

ActionKind = Literal["tool_call", "model_output", "state_change", "environment_action"]
ProcessModelSource = Literal[
    "session_identity",
    "conversation_history",
    "retrieved_policy",
    "tool_result",
    "belief",
]


def control_structure_content_digest(control_structure: ControlStructure) -> str:
    """Return the version-framed content digest of one control structure."""
    return compute_framed_digest(
        CONTROL_STRUCTURE_DIGEST_DOMAIN,
        control_structure.model_dump(mode="json", exclude_none=True),
    )


LOSS_ANALYSIS_CONTENT_DIGEST_DOMAIN = (
    "asago-scenario-generator:loss-analysis-content:v1"
)


def loss_analysis_content_digest(loss_analysis: LossAnalysis) -> str:
    """Return the version-framed content digest of one loss analysis.

    The loss-analysis boundary model has no digest field of its own; the
    relevance table pins this computed content digest instead.
    """
    return compute_framed_digest(
        LOSS_ANALYSIS_CONTENT_DIGEST_DOMAIN,
        loss_analysis.model_dump(mode="json", exclude_none=True),
    )


class ActionBinding(ClosedCanonicalModel):
    """One derived control action and its exact observed binding.

    ``argument_names`` copies the observed operation's argument names
    verbatim so checkpoint review can check the schema without re-reading
    the execution target profile; it is empty for non-tool actions.
    """

    ca_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    kind: ActionKind
    resource_id: str | None = None
    operation_id: str | None = None
    argument_names: tuple[str, ...] = ()
    justification: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_binding(self) -> "ActionBinding":
        if (self.resource_id is None) != (self.operation_id is None):
            raise ValueError(
                f"action binding {self.ca_id} must carry both resource_id and "
                "operation_id or neither"
            )
        if self.kind == "tool_call" and self.resource_id is None:
            raise ValueError(
                f"tool_call action {self.ca_id} requires an exact operation binding"
            )
        if self.resource_id is None and self.argument_names:
            raise ValueError(
                f"action binding {self.ca_id} has no observed operation but "
                "carries argument names"
            )
        return self


class ControllerPurpose(ClosedCanonicalModel):
    """The single ASSISTANT controller description and its grounding evidence."""

    description: str = Field(min_length=1)
    source: Literal["grounded_model", "deterministic_fallback"]
    # For a grounded purpose: the observed grounding evidence (for example the
    # share of content words found in the use case).  For the fallback: the
    # reason the provider purpose was rejected.
    evidence: str | None = None


class ProcessModelRecord(ClosedCanonicalModel):
    """One derived process-model part and where its content came from."""

    pm_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    source: ProcessModelSource
    # Exact TARGET-STATE path backing session_identity, when observed.
    observed_path: tuple[str, ...] | None = None


class BeliefRecord(ClosedCanonicalModel):
    """One provider-named belief with its deterministic acceptance decision."""

    pm_id: str = Field(min_length=1)
    text: str = Field(min_length=1)
    accepted: bool
    reason: str | None = None
    # Feedback channel source for an accepted belief: the exact tool name whose
    # result updates the belief, or None for the customer-facing interface.
    feedback_tool: str | None = None

    @model_validator(mode="after")
    def validate_record(self) -> "BeliefRecord":
        if not self.accepted and not (self.reason and self.reason.strip()):
            raise ValueError(f"rejected belief {self.pm_id} requires a reason")
        return self


class TargetDerivedStructure(ClosedCanonicalModel):
    """Pinned sidecar record of the deterministic target-derived structure."""

    schema_version: Literal[TARGET_DERIVED_STRUCTURE_SCHEMA_VERSION] = (
        TARGET_DERIVED_STRUCTURE_SCHEMA_VERSION
    )
    semantic_digest: str | None = None
    target_id: str = Field(min_length=1)
    profile_digest: str = Field(min_length=1)
    control_structure_digest: str = Field(min_length=1)
    controller: ControllerPurpose
    actions: tuple[ActionBinding, ...] = Field(min_length=1)
    process_model: tuple[ProcessModelRecord, ...] = Field(min_length=1)
    beliefs: tuple[BeliefRecord, ...] = ()
    # Logical model calls for this stage, not provider wire attempts: one
    # beliefs call plus one relevance call in the steady state, and one more
    # bounded revision call after a failing relevance check (so at most
    # three).  Each logical call may make additional wire attempts
    # (json-decode/validation retries); every attempt is logged to
    # calls.jsonl and counted by the run manifest's count_calls_by_stage.
    model_call_count: int = Field(ge=0, le=3)
    warnings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def canonicalize_and_digest(self) -> "TargetDerivedStructure":
        object.__setattr__(self, "warnings", tuple(dict.fromkeys(self.warnings)))
        if self.semantic_digest is None:
            object.__setattr__(self, "semantic_digest", self.compute_digest())
        return self

    def payload(self) -> dict[str, Any]:
        """Return the sidecar content excluding its derived digest."""
        return self.model_dump(
            mode="json", exclude_none=True, exclude={"semantic_digest"}
        )

    def compute_digest(self) -> str:
        """Compute the version-framed identity of the sidecar."""
        return compute_framed_digest(
            TARGET_DERIVED_STRUCTURE_DIGEST_DOMAIN, self.payload()
        )

    def assert_integrity(self) -> None:
        """Raise when the sidecar content changed after construction."""
        if self.semantic_digest != self.compute_digest():
            raise ValueError("target-derived structure digest mismatch")

    def binding_for(self, ca_id: str) -> ActionBinding | None:
        """Return the exact recorded binding for one control action."""
        return next((item for item in self.actions if item.ca_id == ca_id), None)


class RelevantAction(ClosedCanonicalModel):
    """One action named relevant to one constraint, with its reason."""

    action: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    # "model" when the relevance call named the pair; "rule" when the
    # deterministic post-rule added it.
    origin: Literal["model", "rule"] = "model"


class UnconstrainedAction(ClosedCanonicalModel):
    """One action no constraint can violate, with the explicit reason."""

    action: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class ConstraintRelevanceRow(ClosedCanonicalModel):
    """The relevant actions for exactly one security constraint.

    An empty ``actions`` tuple is the typed honest outcome for a constraint
    no supplied action can violate (live evidence: third-party availability
    constraints match no behavior class and no post-rule); it requires an
    explicit ``no_relevant_action_reason`` and is only accepted for
    constraints whose behavior class is ``unclassified``.  A row with
    actions must not carry the reason.
    """

    constraint_id: str = Field(min_length=1)
    actions: tuple[RelevantAction, ...] = ()
    no_relevant_action_reason: str | None = None

    @model_validator(mode="after")
    def validate_row(self) -> "ConstraintRelevanceRow":
        if self.actions and self.no_relevant_action_reason is not None:
            raise ValueError(
                f"relevance row {self.constraint_id} names actions and must "
                "not carry no_relevant_action_reason"
            )
        if not self.actions and not (
            self.no_relevant_action_reason and self.no_relevant_action_reason.strip()
        ):
            raise ValueError(
                f"relevance row {self.constraint_id} has no action and "
                "requires a no_relevant_action_reason"
            )
        return self


class ConstraintActionRelevance(ClosedCanonicalModel):
    """Closed spec-2.3 relevance table pinned to its exact upstream artifacts."""

    schema_version: Literal[CONSTRAINT_ACTION_RELEVANCE_SCHEMA_VERSION] = (
        CONSTRAINT_ACTION_RELEVANCE_SCHEMA_VERSION
    )
    semantic_digest: str | None = None
    loss_analysis_digest: str = Field(min_length=1)
    control_structure_digest: str = Field(min_length=1)
    relevance: tuple[ConstraintRelevanceRow, ...] = Field(min_length=1)
    unconstrained_actions: tuple[UnconstrainedAction, ...] = ()
    # Logical relevance model calls (one steady-state call plus at most one
    # bounded revision), not provider wire attempts; see the stage-level
    # model_call_count note on TargetDerivedStructure.
    model_call_count: int = Field(ge=0, le=2)

    @model_validator(mode="after")
    def canonicalize_and_digest(self) -> "ConstraintActionRelevance":
        seen: set[str] = set()
        for row in self.relevance:
            if row.constraint_id in seen:
                raise ValueError(
                    f"relevance table repeats constraint {row.constraint_id}"
                )
            seen.add(row.constraint_id)
        if self.semantic_digest is None:
            object.__setattr__(self, "semantic_digest", self.compute_digest())
        return self

    def payload(self) -> dict[str, Any]:
        """Return the table content excluding its derived digest."""
        return self.model_dump(
            mode="json", exclude_none=True, exclude={"semantic_digest"}
        )

    def compute_digest(self) -> str:
        """Compute the version-framed identity of the table."""
        return compute_framed_digest(
            CONSTRAINT_ACTION_RELEVANCE_DIGEST_DOMAIN, self.payload()
        )

    def assert_integrity(self) -> None:
        """Raise when the table content changed after construction."""
        if self.semantic_digest != self.compute_digest():
            raise ValueError("constraint-action relevance digest mismatch")


__all__ = [
    "CONSTRAINT_ACTION_RELEVANCE_FILENAME",
    "CONSTRAINT_ACTION_RELEVANCE_SCHEMA_VERSION",
    "TARGET_DERIVED_STRUCTURE_FILENAME",
    "TARGET_DERIVED_STRUCTURE_SCHEMA_VERSION",
    "ActionBinding",
    "BeliefRecord",
    "ConstraintActionRelevance",
    "ConstraintRelevanceRow",
    "ControllerPurpose",
    "RelevantAction",
    "TargetDerivedStructure",
    "UnconstrainedAction",
    "control_structure_content_digest",
    "loss_analysis_content_digest",
]
