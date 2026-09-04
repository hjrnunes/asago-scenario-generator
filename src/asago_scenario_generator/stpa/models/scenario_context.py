"""Immutable source-of-truth context shared by SP3 Stage 5 and Stage 6."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalEvidenceStatus,
    CausalFactor,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
    ReferenceType,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType


Digest = str


class ScenarioContextModel(BaseModel):
    """Closed, immutable base for scenario context records."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ScenarioSourcePin(ScenarioContextModel):
    """Content pin for one authoritative input projected into the context."""

    source_kind: Literal[
        "structural_threat", "control_path", "loss_relationships", "capabilities"
    ]
    semantic_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class ScenarioIdentity(ScenarioContextModel):
    """Stable scenario and ICA identities copied by the deterministic compiler."""

    scenario_id: str = Field(min_length=1)
    ica_slot_id: str = Field(min_length=1)
    ica_id: str = Field(min_length=1)


class ScenarioICAContext(ScenarioContextModel):
    """Exact accepted unsafe-control-action meaning."""

    ica_id: str = Field(min_length=1)
    slot_id: str = Field(min_length=1)
    uca_type: UCAType
    uca_type_definition: str = Field(min_length=1)
    exact_ica_text: str = Field(min_length=1)
    unsafe_action: str = Field(min_length=1)
    hazardous_context: str = Field(min_length=1)
    loss_consequence: str = Field(min_length=1)


class DescribedElement(ScenarioContextModel):
    """One identified and described control-path element."""

    element_id: str = Field(min_length=1)
    description: str = Field(min_length=1)


class DescribedControlAction(ScenarioContextModel):
    """The selected control action and its exact target."""

    action_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    target_kind: ReferenceType | Literal["coordination_path", "unspecified"] = (
        "unspecified"
    )
    effect_kind: ControlActionEffectKind | None = None

    @model_validator(mode="after")
    def validate_responsibility_message(self) -> "DescribedControlAction":
        """Keep responsibility targets and message effects inseparable."""
        if (
            self.target_kind is ReferenceType.responsibility
            and self.effect_kind is not ControlActionEffectKind.agent_message
        ):
            raise ValueError(
                "a responsibility-targeted control action must have "
                "effect_kind='agent_message'"
            )
        return self


class ScenarioCoordinationPath(ScenarioContextModel):
    """The exact structural path represented by a coordination ICA slot.

    A coordination slot names a link and its mechanism (``CL-*``/``CM-*``),
    rather than a responsibility and control action (``RESP-*``/``CA-*``).
    The endpoint responsibilities and shared process-model state remain
    explicit so prompts can reason about the path without treating the link
    as an ordinary controller.
    """

    link_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    source: DescribedElement
    target: DescribedElement
    shared_process_model: DescribedElement
    coordination_mechanism: DescribedElement
    controlled_processes: tuple[DescribedElement, ...] = ()

    @property
    def coordination_link(self) -> DescribedElement:
        """Expose the link as a described element for prompt consumers."""
        return DescribedElement(element_id=self.link_id, description=self.description)

    @property
    def shared_pm(self) -> DescribedElement:
        """Expose the shared PM with the source model's compact vocabulary."""
        return self.shared_process_model

    @property
    def controlled_process(self) -> DescribedElement | None:
        """Return the sole endpoint process when the path has one."""
        return (
            self.controlled_processes[0]
            if len(self.controlled_processes) == 1
            else None
        )


class ScenarioControlPath(ScenarioContextModel):
    """The smallest described structural slice that owns the selected ICA."""

    controller: DescribedElement
    responsibility: DescribedElement | None = None
    coordination_path: ScenarioCoordinationPath | None = None
    control_action: DescribedControlAction
    controlled_process: DescribedElement | None = None
    process_model_parts: tuple[DescribedElement, ...]
    feedback: tuple[DescribedElement, ...]
    related_control_actions: tuple[DescribedControlAction, ...] = ()

    @model_validator(mode="after")
    def validate_owner_shape(self) -> "ScenarioControlPath":
        """Require exactly one responsibility or coordination owner."""
        has_responsibility = self.responsibility is not None
        has_coordination = self.coordination_path is not None
        if has_responsibility == has_coordination:
            raise ValueError(
                "scenario control path requires exactly one responsibility "
                "or coordination_path"
            )
        if (
            has_responsibility
            and self.controlled_process is None
            and self.control_action.target_kind is not ReferenceType.responsibility
        ):
            raise ValueError(
                "a responsibility control path requires either a controlled "
                "process or a responsibility-targeted agent message"
            )
        return self


class ScenarioLoss(ScenarioContextModel):
    """A selected loss reached by a selected hazard."""

    loss_id: str = Field(min_length=1)
    description: str = Field(min_length=1)


class ScenarioHazard(ScenarioContextModel):
    """A selected hazard with its exact loss relationships."""

    hazard_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    related_loss_ids: tuple[str, ...] = Field(min_length=1)


class ScenarioConstraint(ScenarioContextModel):
    """A selected governing constraint with exact hazard relationships."""

    constraint_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    related_hazard_ids: tuple[str, ...] = Field(min_length=1)


class ScenarioObligationConsideration(ScenarioContextModel):
    """One routed taxonomy concern already adjudicated at the selected ICA."""

    obligation_id: str = Field(min_length=1)
    attack_pattern_id: str = Field(min_length=1)
    attack_pattern_name: str = Field(min_length=1)
    concise_concern: str = Field(min_length=1)
    disposition: Literal["finding", "proposed_not_applicable", "unresolved"]
    rationale: str = Field(min_length=1)
    finding_ica_id: str | None = None


class ReachableCapability(ScenarioContextModel):
    """A capability with explicit evidence of reachability from this path."""

    capability_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    access_path: tuple[str, ...] = Field(min_length=1)


class ScenarioCatalogContext(ScenarioContextModel):
    """One catalog mapping selected on the source structural threat."""

    catalog: str = Field(min_length=1)
    entry_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    confidence: Literal["high", "medium", "low"]


class ScenarioGenerationContext(ScenarioContextModel):
    """Content-addressed authority carried unchanged through scenario production."""

    schema_version: Literal["scenario-generation-context-v1"] = (
        "scenario-generation-context-v1"
    )
    context_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_pins: tuple[ScenarioSourcePin, ...] = Field(min_length=3)
    scenario_identity: ScenarioIdentity
    ica: ScenarioICAContext
    target_control_path: ScenarioControlPath
    losses: tuple[ScenarioLoss, ...] = Field(min_length=1)
    hazards: tuple[ScenarioHazard, ...] = Field(min_length=1)
    constraints: tuple[ScenarioConstraint, ...] = Field(min_length=1)
    obligation_considerations: tuple[ScenarioObligationConsideration, ...] = ()
    reachable_capabilities: tuple[ReachableCapability, ...] = ()
    catalog_context: tuple[ScenarioCatalogContext, ...] = ()

    @classmethod
    def create(cls, **values: Any) -> "ScenarioGenerationContext":
        """Construct the context with its canonical semantic digest."""
        payload = {"schema_version": "scenario-generation-context-v1", **values}
        for field_name in (
            "obligation_considerations",
            "reachable_capabilities",
            "catalog_context",
        ):
            payload.setdefault(field_name, ())
        payload["context_digest"] = _context_digest(payload)
        return cls.model_validate(payload)

    @model_validator(mode="after")
    def validate_digest_and_relationships(self) -> "ScenarioGenerationContext":
        """Reject tamper and relationships that do not reach the selected ICA."""
        current_digest = _context_digest(self.model_dump(mode="json"))
        legacy_digest = _legacy_context_digest(self)
        if self.context_digest not in {current_digest, legacy_digest}:
            raise ValueError("context_digest does not match scenario context")
        if self.scenario_identity.ica_id != self.ica.ica_id:
            raise ValueError("scenario identity does not match ICA context")
        _validate_context_relationships(self)
        return self


def _legacy_context_digest(context: ScenarioGenerationContext) -> str:
    """Verify v1 contexts written before typed action semantics were added."""
    payload = context.model_dump(mode="json")
    path_payload = payload["target_control_path"]
    _drop_unset_action_semantics(
        path_payload["control_action"], context.target_control_path.control_action
    )
    for action_payload, action in zip(
        path_payload.get("related_control_actions", ()),
        context.target_control_path.related_control_actions,
        strict=True,
    ):
        _drop_unset_action_semantics(action_payload, action)
    return _context_digest(payload)


def _drop_unset_action_semantics(
    payload: dict[str, Any], action: DescribedControlAction
) -> None:
    """Remove only fields absent from a historical serialized action."""
    for field_name in ("target_kind", "effect_kind"):
        if field_name not in action.model_fields_set:
            payload.pop(field_name, None)


def _validate_context_relationships(context: ScenarioGenerationContext) -> None:
    hazard_ids = {item.hazard_id for item in context.hazards}
    loss_ids = {item.loss_id for item in context.losses}
    if any(not set(item.related_loss_ids) <= loss_ids for item in context.hazards):
        raise ValueError("selected hazard does not reach the selected losses")
    if any(
        not set(item.related_hazard_ids) & hazard_ids for item in context.constraints
    ):
        raise ValueError("selected constraint does not govern a selected hazard")
    for item in context.obligation_considerations:
        if item.disposition == "finding" and item.finding_ica_id != context.ica.ica_id:
            raise ValueError("obligation finding does not reference the selected ICA")


def validate_factor_evidence(
    context: ScenarioGenerationContext,
    causal_factors: Sequence[CausalFactor],
) -> None:
    """Validate capability/access evidence against one exact context.

    A factor may cite only capability records retained by the immutable
    scenario context. Each access reference must also occur in the selected
    capability's own access path; a path belonging to another capability is
    not interchangeable evidence.
    """
    capabilities = {item.capability_id: item for item in context.reachable_capabilities}
    for factor in causal_factors:
        if factor.evidence_status is not CausalEvidenceStatus.reachable_capability:
            continue
        selected = []
        for capability_id in factor.capability_refs:
            capability = capabilities.get(capability_id)
            if capability is None:
                raise ValueError(
                    f"causal factor references capability {capability_id!r} "
                    "not present in the exact scenario context"
                )
            selected.append(capability)
        allowed_access_refs = {
            access_ref
            for capability in selected
            for access_ref in capability.access_path
        }
        for access_ref in factor.access_refs:
            if access_ref not in allowed_access_refs:
                raise ValueError(
                    f"causal factor access reference {access_ref!r} is not "
                    "present in the selected capability access path"
                )


def semantic_digest(value: Any, *, frame: str) -> str:
    """Return a version-framed digest over canonical JSON content."""
    canonical = _canonical_json(value)
    return hashlib.sha256(frame.encode() + b"\0" + canonical).hexdigest()


def _context_digest(value: Any) -> str:
    payload = (
        value.model_dump(mode="json") if isinstance(value, BaseModel) else dict(value)
    )
    payload.pop("context_digest", None)
    return semantic_digest(
        payload, frame="asago-scenario-generator:scenario-generation-context:v1"
    )


def _canonical_json(value: Any) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(
        _normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _normalize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="json"))
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return {_normalize(key): _normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    return value
