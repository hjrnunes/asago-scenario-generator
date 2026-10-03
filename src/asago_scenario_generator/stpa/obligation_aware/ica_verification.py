"""Independent semantic verification of final STPA ICAs.

The verifier is intentionally a small, closed seam.  Its request contains
only the STPA control action, UCA category, ICA deviation, and the selected
hazard/constraint/loss context.  Taxonomy, routing, mechanism, capability,
and execution material never cross this boundary.
"""

from __future__ import annotations

import inspect
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, ClassVar, Literal, Sequence

from pydantic import AliasChoices, Field, field_validator, model_validator

from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    canonical_json_text,
    compute_framed_digest,
    unique_sorted_strings,
)
from asago_scenario_generator.models.hybrid_coverage import Digest
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationCallEvidence,
    ConsiderationDiagnostic,
    ObligationIcaConsideration,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
    ControlActionTemporality,
    ControlStructure,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis


ICA_HAZARD_VERIFICATION_REQUEST_SCHEMA_VERSION = (
    "stpa-ica-hazard-verification-request-v1"
)
ICA_HAZARD_VERIFICATION_BATCH_SCHEMA_VERSION = "stpa-ica-hazard-verification-batch-v1"
ICA_HAZARD_VERIFICATION_REQUEST_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-ica-hazard-verification-request:v1"
)
ICA_HAZARD_VERIFICATION_BATCH_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-ica-hazard-verification-batch:v1"
)

IcaHazardVerdictValue = Literal["supported", "contradictory", "insufficient_evidence"]
IcaHazardAttemptStatus = Literal[
    "semantic_verdict", "provider_failure", "protocol_failure"
]
IcaHazardRecordDisposition = Literal[
    "supported",
    "excluded",
    "provider_failure",
    "not_applicable",
    "unresolved",
]


class _VerificationModel(ClosedCanonicalModel):
    """Closed immutable base for all verifier records."""


class _VerificationDigestModel(_VerificationModel):
    """Immutable value with a deterministic semantic digest."""

    _digest_domain: ClassVar[str]
    semantic_digest: Digest | None = None

    def _semantic_payload(self) -> dict[str, Any]:
        raise NotImplementedError

    def compute_semantic_digest(self) -> str:
        """Compute the digest without the stored digest field."""
        return compute_framed_digest(self._digest_domain, self._semantic_payload())

    def assert_integrity(self) -> None:
        """Reject tampered content-addressed records."""
        if self.semantic_digest != self.compute_semantic_digest():
            raise ValueError("semantic digest does not match verifier record content")

    def to_json(self) -> str:
        """Return canonical JSON after validating the content digest."""
        self.assert_integrity()
        return canonical_json_text(self.model_dump(mode="json"))


def _ids(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    """Canonicalize a set-like ID collection."""
    return unique_sorted_strings(values, label)


class IcaHazardContext(_VerificationModel):
    """One selected hazard and its authoritative loss relationship."""

    hazard_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    related_loss_ids: tuple[str, ...] = Field(min_length=1)

    @field_validator("related_loss_ids")
    @classmethod
    def canonicalize_losses(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _ids(value, "related_loss_ids")


class IcaConstraintContext(_VerificationModel):
    """One selected security constraint and its governed hazards."""

    constraint_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    related_hazard_ids: tuple[str, ...] = Field(min_length=1)

    @field_validator("related_hazard_ids")
    @classmethod
    def canonicalize_hazards(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _ids(value, "related_hazard_ids")


class IcaLossContext(_VerificationModel):
    """One loss reachable from the selected hazard context."""

    loss_id: str = Field(min_length=1)
    description: str = Field(min_length=1)


class IcaHazardVerificationRequest(_VerificationDigestModel):
    """Narrow STPA-only context for one final non-N/A ICA."""

    schema_version: Literal[ICA_HAZARD_VERIFICATION_REQUEST_SCHEMA_VERSION] = (
        ICA_HAZARD_VERIFICATION_REQUEST_SCHEMA_VERSION
    )
    slot_id: str = Field(min_length=1)
    ica_id: str = Field(min_length=1)
    responsibility_id: str | None = Field(default=None, min_length=1)
    responsibility_description: str | None = Field(default=None, min_length=1)
    # ``controller_description`` is retained as an explicit synonym because
    # coordination and responsibility slots use the same provider concept.
    controller_description: str | None = Field(default=None, min_length=1)
    control_action_id: str = Field(
        validation_alias=AliasChoices("control_action_id", "action_id"),
        min_length=1,
    )
    control_action_description: str = Field(
        validation_alias=AliasChoices(
            "control_action_description", "action_description"
        ),
        min_length=1,
    )
    action_recipient: str | None = Field(
        default=None,
        validation_alias=AliasChoices("action_recipient", "control_action_recipient"),
        min_length=1,
        description=(
            "Plain description of the authoritative control-action recipient; "
            "this is compared with the recipient named by the source context."
        ),
    )
    action_direction: str | None = Field(
        default=None,
        validation_alias=AliasChoices("action_direction", "control_action_direction"),
        min_length=1,
        description=(
            "Plain semantic direction of the authoritative action (for example "
            "input, output, internal, state, or external)."
        ),
    )
    action_effect_kind: ControlActionEffectKind | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "action_effect_kind", "control_action_effect_kind"
        ),
        description="Typed observable effect of the authoritative control action.",
    )
    action_temporality: ControlActionTemporality | None = None
    uca_type: UCAType
    uca_definition: str = Field(
        validation_alias=AliasChoices("uca_definition", "uca_category_definition"),
        min_length=1,
    )
    deviation: str = Field(min_length=1)
    hazardous_context: str = Field(min_length=1)
    loss_consequence: str = Field(
        validation_alias=AliasChoices("loss_consequence", "loss_scenario"),
        min_length=1,
    )
    hazards: tuple[IcaHazardContext, ...] = Field(
        validation_alias=AliasChoices("hazards", "selected_hazards"),
        min_length=1,
    )
    constraints: tuple[IcaConstraintContext, ...] = Field(
        validation_alias=AliasChoices("constraints", "selected_constraints"),
        min_length=1,
    )
    losses: tuple[IcaLossContext, ...] = Field(
        validation_alias=AliasChoices("losses", "selected_losses"),
        min_length=1,
    )
    semantic_digest: Digest | None = None
    _digest_domain = ICA_HAZARD_VERIFICATION_REQUEST_DIGEST_DOMAIN

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> "IcaHazardVerificationRequest":
        responsibility = self.responsibility_description or self.controller_description
        if not responsibility:
            raise ValueError(
                "ICA hazard verification requires a controller/responsibility description"
            )
        object.__setattr__(self, "responsibility_description", responsibility)
        object.__setattr__(self, "controller_description", responsibility)

        hazards, constraints, losses = _ordered_request_context(self)
        _validate_request_context_links(hazards, constraints, losses)
        object.__setattr__(self, "hazards", hazards)
        object.__setattr__(self, "constraints", constraints)
        object.__setattr__(self, "losses", losses)
        _set_request_digest(self)
        return self

    def _semantic_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"semantic_digest"})


def _ordered_request_context(
    request: IcaHazardVerificationRequest,
) -> tuple[
    tuple[IcaHazardContext, ...],
    tuple[IcaConstraintContext, ...],
    tuple[IcaLossContext, ...],
]:
    return (
        tuple(sorted(request.hazards, key=lambda item: item.hazard_id)),
        tuple(sorted(request.constraints, key=lambda item: item.constraint_id)),
        tuple(sorted(request.losses, key=lambda item: item.loss_id)),
    )


def _validate_request_context_links(
    hazards: Sequence[IcaHazardContext],
    constraints: Sequence[IcaConstraintContext],
    losses: Sequence[IcaLossContext],
) -> None:
    """Require every context relationship to stay within the selected slice."""
    _require_unique_context_ids(hazards, "hazard_id", "hazard")
    _require_unique_context_ids(constraints, "constraint_id", "constraint")
    _require_unique_context_ids(losses, "loss_id", "loss")
    hazard_ids = {item.hazard_id for item in hazards}
    loss_ids = {item.loss_id for item in losses}
    _validate_hazard_loss_links(hazards, loss_ids)
    _validate_constraint_hazard_links(constraints, hazard_ids)


def _validate_hazard_loss_links(
    hazards: Sequence[IcaHazardContext],
    loss_ids: set[str],
) -> None:
    for hazard in hazards:
        if not set(hazard.related_loss_ids) <= loss_ids:
            raise ValueError(f"hazard {hazard.hazard_id} references an unselected loss")


def _validate_constraint_hazard_links(
    constraints: Sequence[IcaConstraintContext],
    hazard_ids: set[str],
) -> None:
    for constraint in constraints:
        if not set(constraint.related_hazard_ids) <= hazard_ids:
            raise ValueError(
                f"constraint {constraint.constraint_id} references an unselected hazard"
            )


def _require_unique_context_ids(
    values: Sequence[Any],
    id_attribute: str,
    context_name: str,
) -> None:
    ids = [getattr(item, id_attribute) for item in values]
    if len(set(ids)) != len(ids):
        raise ValueError(f"verification request has duplicate {context_name} IDs")


def _set_request_digest(request: IcaHazardVerificationRequest) -> None:
    expected = request.compute_semantic_digest()
    if request.semantic_digest is not None and request.semantic_digest != expected:
        raise ValueError("semantic digest does not match verifier request content")
    object.__setattr__(request, "semantic_digest", expected)


class IcaHazardVerificationVerdict(_VerificationModel):
    """Independent semantic judgement for exactly one ICA request."""

    ica_id: str = Field(min_length=1)
    request_digest: Digest | None = None
    verdict: IcaHazardVerdictValue = Field(
        validation_alias=AliasChoices("verdict", "decision")
    )
    rationale: str = Field(min_length=1, max_length=2000)


class IcaHazardVerificationCorrection(_VerificationModel):
    """Request-local bounded correction returned before a second judgement."""

    ica_id: str = Field(min_length=1)
    deviation: str | None = Field(default=None, min_length=1)
    hazardous_context: str | None = Field(default=None, min_length=1)
    loss_consequence: str | None = Field(default=None, min_length=1)
    hazard_ids: tuple[str, ...] | None = None
    constraint_ids: tuple[str, ...] | None = None
    disposition: Literal["revise", "not_applicable", "unresolved"] = "revise"
    rationale: str = Field(min_length=1, max_length=2000)

    @field_validator("hazard_ids", "constraint_ids")
    @classmethod
    def canonicalize_references(
        cls, value: tuple[str, ...] | None
    ) -> tuple[str, ...] | None:
        return None if value is None else _ids(value, "correction references")


class IcaHazardVerificationAttempt(_VerificationModel):
    """One provider/protocol attempt, bounded to the first call or correction."""

    attempt: int = Field(ge=1, le=2, strict=True)
    request_digest: Digest
    verdict: IcaHazardVerificationVerdict | None = None
    provider_status: IcaHazardAttemptStatus
    call_id: str | None = Field(default=None, min_length=1)
    error: str | None = Field(default=None, min_length=1)
    correction_applied: bool = False

    @model_validator(mode="after")
    def validate_status(self) -> "IcaHazardVerificationAttempt":
        _validate_attempt_status(self)
        _validate_attempt_verdict(self)
        return self


def _validate_attempt_status(attempt: IcaHazardVerificationAttempt) -> None:
    if attempt.provider_status == "semantic_verdict" and attempt.verdict is None:
        raise ValueError("semantic verification attempt requires a verdict")
    if attempt.provider_status != "semantic_verdict" and attempt.error is None:
        raise ValueError("failed verification attempt requires typed error")


def _validate_attempt_verdict(attempt: IcaHazardVerificationAttempt) -> None:
    if attempt.verdict is not None and attempt.verdict.request_digest not in (
        None,
        attempt.request_digest,
    ):
        raise ValueError("attempt verdict does not bind its request digest")


class IcaHazardVerificationRecord(_VerificationModel):
    """Durable original/correction attempts and the final ICA disposition."""

    ica_id: str = Field(min_length=1)
    slot_id: str = Field(min_length=1)
    request: IcaHazardVerificationRequest
    corrected_request: IcaHazardVerificationRequest | None = None
    correction: IcaHazardVerificationCorrection | None = None
    attempts: tuple[IcaHazardVerificationAttempt, ...] = Field(
        min_length=1, max_length=2
    )
    final_verdict: IcaHazardVerificationVerdict | None = None
    disposition: IcaHazardRecordDisposition = "excluded"
    quality_diagnostics: tuple[ConsiderationDiagnostic, ...] = ()

    @model_validator(mode="after")
    def validate_record(self) -> "IcaHazardVerificationRecord":
        _validate_record_identity(self)
        attempts = _ordered_record_attempts(self.attempts)
        valid_digests = _record_request_digests(self)
        _validate_record_attempt_bindings(self, attempts, valid_digests)
        _set_record_disposition(self)
        _validate_terminal_correction(self)
        _validate_second_record_attempt(self, attempts)
        object.__setattr__(self, "attempts", attempts)
        object.__setattr__(self, "quality_diagnostics", _ordered_diagnostics(self))
        return self


def _validate_record_identity(record: IcaHazardVerificationRecord) -> None:
    if (
        record.request.ica_id != record.ica_id
        or record.request.slot_id != record.slot_id
    ):
        raise ValueError("verification record identity does not match its request")
    if record.correction is not None and record.correction.ica_id != record.ica_id:
        raise ValueError("verification correction ICA identity changed")


def _ordered_record_attempts(
    attempts: Sequence[IcaHazardVerificationAttempt],
) -> tuple[IcaHazardVerificationAttempt, ...]:
    ordered = tuple(sorted(attempts, key=lambda item: item.attempt))
    numbers = tuple(item.attempt for item in ordered)
    if numbers != tuple(range(1, len(ordered) + 1)):
        raise ValueError("verification attempts must be contiguous from attempt 1")
    return ordered


def _record_request_digests(record: IcaHazardVerificationRecord) -> set[str]:
    valid_digests = {record.request.semantic_digest}
    corrected = record.corrected_request
    if corrected is None:
        return valid_digests
    if corrected.ica_id != record.ica_id:
        raise ValueError("corrected request ICA identity changed")
    if corrected.semantic_digest == record.request.semantic_digest:
        raise ValueError("corrected request must change ICA content")
    valid_digests.add(corrected.semantic_digest)
    return valid_digests


def _validate_record_attempt_bindings(
    record: IcaHazardVerificationRecord,
    attempts: Sequence[IcaHazardVerificationAttempt],
    valid_digests: set[str],
) -> None:
    for attempt in attempts:
        if attempt.request_digest not in valid_digests:
            raise ValueError("verification attempt references an unknown request")
        verdict = attempt.verdict
        if verdict is not None and verdict.ica_id != record.ica_id:
            raise ValueError("verification verdict ICA identity changed")


def _set_record_disposition(record: IcaHazardVerificationRecord) -> None:
    if record.final_verdict is not None:
        if record.final_verdict.ica_id != record.ica_id:
            raise ValueError("final verification verdict ICA identity changed")
        object.__setattr__(
            record,
            "disposition",
            "supported" if record.final_verdict.verdict == "supported" else "excluded",
        )
        return
    if record.disposition not in {"provider_failure", "not_applicable", "unresolved"}:
        raise ValueError(
            "record without a final verdict must be a typed terminal outcome"
        )


def _validate_terminal_correction(record: IcaHazardVerificationRecord) -> None:
    correction = record.correction
    if correction is None or correction.disposition == "revise":
        return
    if record.final_verdict is not None:
        raise ValueError("terminal correction cannot retain a final semantic verdict")
    if record.corrected_request is not None:
        raise ValueError(
            "terminal correction cannot retain a second verification request"
        )
    if record.disposition != correction.disposition:
        raise ValueError("record disposition must match its terminal correction")


def _validate_second_record_attempt(
    record: IcaHazardVerificationRecord,
    attempts: Sequence[IcaHazardVerificationAttempt],
) -> None:
    if len(attempts) != 2:
        return
    if record.corrected_request is None:
        raise ValueError("second verification attempt requires a corrected request")
    if attempts[1].request_digest != record.corrected_request.semantic_digest:
        raise ValueError("second verification attempt must bind the corrected request")


def _ordered_diagnostics(
    record: IcaHazardVerificationRecord,
) -> tuple[ConsiderationDiagnostic, ...]:
    return tuple(
        sorted(record.quality_diagnostics, key=lambda item: (item.code, item.detail))
    )


class IcaHazardVerificationBatch(_VerificationDigestModel):
    """Complete verification result for all final non-N/A ICAs in a batch."""

    schema_version: Literal[ICA_HAZARD_VERIFICATION_BATCH_SCHEMA_VERSION] = (
        ICA_HAZARD_VERIFICATION_BATCH_SCHEMA_VERSION
    )
    batch_id: str = Field(min_length=1)
    records: tuple[IcaHazardVerificationRecord, ...] = ()
    supported_count: int = 0
    unsupported_count: int = 0
    provider_failure_count: int = 0
    diagnostics: tuple[ConsiderationDiagnostic, ...] = ()
    call_evidence: tuple[ConsiderationCallEvidence, ...] = ()
    incomplete_ica_ids: tuple[str, ...] = ()
    semantic_digest: Digest | None = None
    _digest_domain = ICA_HAZARD_VERIFICATION_BATCH_DIGEST_DOMAIN

    @model_validator(mode="after")
    def canonicalize_and_count(self) -> "IcaHazardVerificationBatch":
        records = _ordered_batch_records(self.records)
        incomplete = _ids(self.incomplete_ica_ids, "incomplete_ica_ids")
        supported, failures, unsupported = _batch_counts(records, incomplete)
        _set_batch_counts(self, supported, unsupported, failures)
        object.__setattr__(self, "records", records)
        object.__setattr__(self, "incomplete_ica_ids", incomplete)
        object.__setattr__(
            self,
            "diagnostics",
            tuple(sorted(self.diagnostics, key=lambda item: (item.code, item.detail))),
        )
        object.__setattr__(
            self,
            "call_evidence",
            tuple(sorted(self.call_evidence, key=lambda item: item.call_id)),
        )
        expected_digest = self.compute_semantic_digest()
        if self.semantic_digest is not None and self.semantic_digest != expected_digest:
            raise ValueError(
                "semantic digest does not match verification batch content"
            )
        object.__setattr__(self, "semantic_digest", expected_digest)
        return self

    def _semantic_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"semantic_digest"})


def _ordered_batch_records(
    records: Sequence[IcaHazardVerificationRecord],
) -> tuple[IcaHazardVerificationRecord, ...]:
    ordered = tuple(sorted(records, key=lambda item: (item.slot_id, item.ica_id)))
    if len({item.ica_id for item in ordered}) != len(ordered):
        raise ValueError("verification batch has duplicate ICA IDs")
    return ordered


def _batch_counts(
    records: Sequence[IcaHazardVerificationRecord],
    incomplete_ica_ids: Sequence[str],
) -> tuple[int, int, int]:
    supported = sum(item.disposition == "supported" for item in records)
    failures = sum(item.disposition == "provider_failure" for item in records)
    unsupported = len(records) - supported - failures + len(incomplete_ica_ids)
    return supported, failures, unsupported


def _set_batch_counts(
    batch: IcaHazardVerificationBatch,
    supported: int,
    unsupported: int,
    failures: int,
) -> None:
    for field_name, expected in (
        ("supported_count", supported),
        ("unsupported_count", unsupported),
        ("provider_failure_count", failures),
    ):
        supplied = getattr(batch, field_name)
        if supplied not in (0, expected) and supplied != expected:
            raise ValueError(f"{field_name} does not match verification records")
        object.__setattr__(batch, field_name, expected)


def build_ica_hazard_verification_request(
    ica: ICA,
    slot: ICASlot,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> IcaHazardVerificationRequest:
    """Project one final ICA into the narrow STPA verification view."""
    if slot.is_na:
        raise ValueError("N/A ICA slots do not produce verification requests")
    (
        responsibility,
        action_description,
        action_temporality,
        action_recipient,
        action_direction,
        action_effect_kind,
    ) = _request_control_context(slot, control_structure)
    hazard_by_id, security_by_id, loss_by_id = _loss_context_indexes(loss_analysis)
    hazards = _hazard_contexts(ica, hazard_by_id)
    constraints = _constraint_contexts(
        ica,
        security_by_id,
        selected_hazard_ids={item.hazard_id for item in hazards},
        known_hazard_ids=set(hazard_by_id),
    )
    losses = _loss_contexts(hazards, loss_by_id)
    return IcaHazardVerificationRequest(
        slot_id=slot.slot_id,
        ica_id=ica.ica_id,
        responsibility_id=responsibility.resp_id if responsibility else None,
        responsibility_description=responsibility.description
        if responsibility
        else None,
        control_action_id=slot.control_action,
        control_action_description=action_description or slot.control_action,
        action_recipient=action_recipient,
        action_direction=action_direction,
        action_effect_kind=action_effect_kind,
        action_temporality=action_temporality,
        uca_type=slot.uca_type,
        uca_definition=_uca_definition(slot.uca_type),
        deviation=ica.deviation or ica.ica_text,
        hazardous_context=ica.hazardous_context,
        loss_consequence=ica.loss_scenario,
        hazards=tuple(hazards),
        constraints=tuple(constraints),
        losses=tuple(losses),
    )


def _request_control_context(
    slot: ICASlot,
    control_structure: ControlStructure,
) -> tuple[
    Any,
    str,
    ControlActionTemporality | None,
    str | None,
    str | None,
    ControlActionEffectKind | None,
]:
    """Resolve the responsibility and action description for a slot."""
    if slot.responsibility is not None:
        return _direct_control_context(slot, control_structure)
    return _coordination_control_context(slot, control_structure)


def _direct_control_context(
    slot: ICASlot,
    control_structure: ControlStructure,
) -> tuple[
    Any,
    str,
    ControlActionTemporality | None,
    str | None,
    str | None,
    ControlActionEffectKind | None,
]:
    responsibility = _responsibility_for_id(control_structure, slot.responsibility)
    if responsibility is None:
        raise ValueError(f"unknown responsibility {slot.responsibility}")
    action = _action_for_id(responsibility, slot.control_action)
    if action is None:
        raise ValueError(f"unknown control action {slot.control_action}")
    effect_kind = action.effect_kind
    return (
        responsibility,
        action.description,
        action.temporality or slot.action_temporality,
        _action_recipient(action.target, control_structure),
        _action_direction(effect_kind),
        effect_kind,
    )


def _coordination_control_context(
    slot: ICASlot,
    control_structure: ControlStructure,
) -> tuple[
    Any,
    str,
    ControlActionTemporality | None,
    str | None,
    str | None,
    ControlActionEffectKind | None,
]:
    link = _coordination_link_for_id(control_structure, slot.coordination_link)
    if link is None:
        raise ValueError(f"unknown coordination link {slot.coordination_link}")
    responsibility = _responsibility_for_id(control_structure, link.source)
    if responsibility is None:
        raise ValueError(f"unknown coordination source {link.source}")
    recipient = _responsibility_for_id(control_structure, link.target)
    return (
        responsibility,
        link.coordination_mechanism.description,
        slot.action_temporality,
        recipient.description if recipient is not None else link.target,
        "internal",
        ControlActionEffectKind.agent_message,
    )


def _action_recipient(
    target: Any | None,
    control_structure: ControlStructure,
) -> str | None:
    """Resolve the action target to its plain source-established description."""
    if target is None:
        return None
    target_type = getattr(target.type, "value", target.type)
    if target_type == "controlled_process":
        process = next(
            (
                item
                for item in control_structure.controlled_processes
                if item.cp_id == target.id
            ),
            None,
        )
        return process.description if process is not None else target.id
    if target_type == "responsibility":
        responsibility = _responsibility_for_id(control_structure, target.id)
        return responsibility.description if responsibility is not None else target.id
    return target.id


def _action_direction(
    effect_kind: ControlActionEffectKind | None,
) -> str | None:
    """Map the typed action effect to a plain semantic direction for review."""
    return {
        ControlActionEffectKind.model_output: "output",
        ControlActionEffectKind.tool_call: "input",
        ControlActionEffectKind.state_change: "state",
        ControlActionEffectKind.agent_message: "internal",
        ControlActionEffectKind.environment_action: "external",
    }.get(effect_kind)


def _responsibility_for_id(
    control_structure: ControlStructure,
    responsibility_id: str | None,
) -> Any | None:
    return next(
        (
            item
            for item in control_structure.responsibilities
            if item.resp_id == responsibility_id
        ),
        None,
    )


def _action_for_id(responsibility: Any, action_id: str | None) -> Any | None:
    return next(
        (item for item in responsibility.control_actions if item.ca_id == action_id),
        None,
    )


def _coordination_link_for_id(
    control_structure: ControlStructure,
    link_id: str | None,
) -> Any | None:
    return next(
        (
            item
            for item in control_structure.coordination_links
            if item.link_id == link_id
        ),
        None,
    )


def _loss_context_indexes(
    loss_analysis: LossAnalysis,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Index authoritative hazards, constraints, and losses once."""
    hazard_by_id = {item.hazard_id: item for item in loss_analysis.hazards}
    constraint_by_id = {
        item.constraint_id: item for item in loss_analysis.security_constraints
    }
    loss_by_id = {
        item.loss_id: item
        for item in (*loss_analysis.risk_card_losses, *loss_analysis.use_case_losses)
    }
    return hazard_by_id, constraint_by_id, loss_by_id


def _hazard_contexts(
    ica: ICA,
    hazard_by_id: Mapping[str, Any],
) -> list[IcaHazardContext]:
    contexts = []
    for hazard_id in ica.related_hazards:
        hazard = hazard_by_id.get(hazard_id)
        if hazard is None:
            raise ValueError(f"ICA {ica.ica_id} references unknown hazard {hazard_id}")
        contexts.append(
            IcaHazardContext(
                hazard_id=hazard.hazard_id,
                description=hazard.description,
                related_loss_ids=tuple(hazard.related_losses),
            )
        )
    return contexts


def _constraint_contexts(
    ica: ICA,
    constraint_by_id: Mapping[str, Any],
    *,
    selected_hazard_ids: set[str],
    known_hazard_ids: set[str],
) -> list[IcaConstraintContext]:
    contexts = []
    for constraint_id in ica.related_constraints:
        constraint = constraint_by_id.get(constraint_id)
        if constraint is None:
            raise ValueError(
                f"ICA {ica.ica_id} constraint {constraint_id} is not a security constraint"
            )
        constraint_hazard_ids = tuple(constraint.related_hazards)
        unknown_hazard_ids = set(constraint_hazard_ids) - known_hazard_ids
        if unknown_hazard_ids:
            raise ValueError(
                f"constraint {constraint_id} references unknown hazard(s): "
                + ", ".join(sorted(unknown_hazard_ids))
            )
        scoped_hazard_ids = tuple(
            hazard_id
            for hazard_id in constraint_hazard_ids
            if hazard_id in selected_hazard_ids
        )
        if not scoped_hazard_ids:
            raise ValueError(
                f"ICA {ica.ica_id} constraint {constraint_id} does not govern "
                "a selected hazard"
            )
        contexts.append(
            IcaConstraintContext(
                constraint_id=constraint.constraint_id,
                description=constraint.description,
                related_hazard_ids=scoped_hazard_ids,
            )
        )
    return contexts


def _loss_contexts(
    hazards: Sequence[IcaHazardContext],
    loss_by_id: Mapping[str, Any],
) -> list[IcaLossContext]:
    selected_loss_ids = tuple(
        sorted({loss_id for hazard in hazards for loss_id in hazard.related_loss_ids})
    )
    losses = []
    for loss_id in selected_loss_ids:
        loss = loss_by_id.get(loss_id)
        if loss is None:
            raise ValueError(f"hazard context references unknown loss {loss_id}")
        losses.append(
            IcaLossContext(loss_id=loss.loss_id, description=loss.description)
        )
    return losses


def apply_ica_hazard_verification_correction(
    request: IcaHazardVerificationRequest,
    correction: IcaHazardVerificationCorrection,
) -> IcaHazardVerificationRequest:
    """Apply one correction without permitting new structural evidence."""
    if correction.ica_id != request.ica_id:
        raise ValueError("ICA correction identity does not match its request")
    if correction.disposition != "revise":
        raise ValueError("non-revising correction has no second verification request")
    hazard_ids, constraint_ids = _correction_context_ids(request, correction)
    hazards = _select_hazard_context(request, hazard_ids)
    constraints = _select_constraint_context(request, constraint_ids)
    losses = _loss_contexts_for_correction(request, hazards)
    payload = _correction_payload(request, correction, hazards, constraints, losses)
    return IcaHazardVerificationRequest.model_validate(payload)


def _correction_context_ids(
    request: IcaHazardVerificationRequest,
    correction: IcaHazardVerificationCorrection,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    hazard_ids = (
        tuple(item.hazard_id for item in request.hazards)
        if correction.hazard_ids is None
        else correction.hazard_ids
    )
    constraint_ids = (
        tuple(item.constraint_id for item in request.constraints)
        if correction.constraint_ids is None
        else correction.constraint_ids
    )
    return hazard_ids, constraint_ids


def _select_hazard_context(
    request: IcaHazardVerificationRequest,
    hazard_ids: Sequence[str],
) -> tuple[IcaHazardContext, ...]:
    hazards_by_id = {item.hazard_id: item for item in request.hazards}
    if not set(hazard_ids) <= set(hazards_by_id):
        raise ValueError(
            "ICA correction selected a hazard outside the supplied request"
        )
    return tuple(hazards_by_id[item] for item in hazard_ids)


def _select_constraint_context(
    request: IcaHazardVerificationRequest,
    constraint_ids: Sequence[str],
) -> tuple[IcaConstraintContext, ...]:
    constraints_by_id = {item.constraint_id: item for item in request.constraints}
    if not set(constraint_ids) <= set(constraints_by_id):
        raise ValueError(
            "ICA correction selected a constraint outside the supplied request"
        )
    return tuple(constraints_by_id[item] for item in constraint_ids)


def _loss_contexts_for_correction(
    request: IcaHazardVerificationRequest,
    hazards: Sequence[IcaHazardContext],
) -> tuple[IcaLossContext, ...]:
    loss_ids = _loss_ids_for_hazards(hazards)
    losses_by_id = {item.loss_id: item for item in request.losses}
    if not set(loss_ids) <= set(losses_by_id):
        raise ValueError("ICA correction selected a loss outside the supplied request")
    return tuple(losses_by_id[item] for item in loss_ids)


def _loss_ids_for_hazards(
    hazards: Sequence[IcaHazardContext],
) -> tuple[str, ...]:
    return tuple(
        sorted({loss_id for hazard in hazards for loss_id in hazard.related_loss_ids})
    )


def _correction_payload(
    request: IcaHazardVerificationRequest,
    correction: IcaHazardVerificationCorrection,
    hazards: Sequence[IcaHazardContext],
    constraints: Sequence[IcaConstraintContext],
    losses: Sequence[IcaLossContext],
) -> dict[str, Any]:
    payload = request.model_dump(mode="python")
    payload.update(
        {
            "deviation": correction.deviation or request.deviation,
            "hazardous_context": correction.hazardous_context
            or request.hazardous_context,
            "loss_consequence": correction.loss_consequence or request.loss_consequence,
            "hazards": tuple(hazards),
            "constraints": tuple(constraints),
            "losses": tuple(losses),
            "semantic_digest": None,
        }
    )
    return payload


def _build_verification_requests(
    enumeration: ICAEnumeration,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
) -> tuple[
    tuple[IcaHazardVerificationRequest, ...],
    list[str],
    list[ConsiderationDiagnostic],
]:
    """Build all valid requests while retaining incomplete ICA diagnostics."""
    requests: list[IcaHazardVerificationRequest] = []
    incomplete_ica_ids: list[str] = []
    diagnostics: list[ConsiderationDiagnostic] = []
    for slot in enumeration.slots:
        if slot.is_na:
            continue
        for ica in slot.icas:
            try:
                requests.append(
                    build_ica_hazard_verification_request(
                        ica, slot, loss_analysis, control_structure
                    )
                )
            except (TypeError, ValueError) as exc:
                incomplete_ica_ids.append(ica.ica_id)
                diagnostics.append(
                    ConsiderationDiagnostic(
                        code="unsafe_outcome_lineage_incomplete",
                        detail=(
                            "final ICA could not be projected into complete typed "
                            f"STPA hazard/loss context: {exc}"
                        ),
                        refs=(ica.ica_id,),
                    )
                )
    return (
        tuple(sorted(requests, key=lambda item: (item.slot_id, item.ica_id))),
        sorted(incomplete_ica_ids),
        diagnostics,
    )


@dataclass(frozen=True)
class _CorrectionPreparation:
    """Result of one bounded author-correction call."""

    corrected_request: IcaHazardVerificationRequest | None = None
    correction: IcaHazardVerificationCorrection | None = None
    error: str | None = None


def _call_evidence(
    batch_id: str,
    suffix: str,
    outcome: str,
) -> ConsiderationCallEvidence:
    return ConsiderationCallEvidence(
        call_id=f"{batch_id}:{suffix}",
        attempt_count=1,
        outcome=outcome,
    )


def _collect_initial_results(
    requests: Sequence[IcaHazardVerificationRequest],
    verdicts: Sequence[IcaHazardVerificationVerdict],
) -> tuple[
    dict[str, IcaHazardVerificationRecord],
    list[tuple[IcaHazardVerificationRequest, IcaHazardVerificationVerdict]],
    list[ConsiderationDiagnostic],
]:
    records: dict[str, IcaHazardVerificationRecord] = {}
    unsupported: list[
        tuple[IcaHazardVerificationRequest, IcaHazardVerificationVerdict]
    ] = []
    diagnostics: list[ConsiderationDiagnostic] = []
    verdict_by_id = {item.ica_id: item for item in verdicts}
    for request in requests:
        _record_initial_result(
            request,
            verdict_by_id.get(request.ica_id),
            records,
            unsupported,
            diagnostics,
        )
    return records, unsupported, diagnostics


def _record_initial_result(
    request: IcaHazardVerificationRequest,
    verdict: IcaHazardVerificationVerdict | None,
    records: dict[str, IcaHazardVerificationRecord],
    unsupported: list[
        tuple[IcaHazardVerificationRequest, IcaHazardVerificationVerdict]
    ],
    diagnostics: list[ConsiderationDiagnostic],
) -> None:
    if verdict is None:
        records[request.ica_id] = _provider_failure_record(
            request,
            attempt=1,
            status="protocol_failure",
            error="provider omitted this ICA from the verification batch",
        )
        diagnostics.append(
            _verification_diagnostic(
                "ica_hazard_verification_provider_failure",
                request,
                "provider omitted the ICA from its exact verification batch",
            )
        )
        return
    first_attempt = _semantic_attempt(request, verdict, 1)
    if verdict.verdict == "supported":
        records[request.ica_id] = IcaHazardVerificationRecord(
            ica_id=request.ica_id,
            slot_id=request.slot_id,
            request=request,
            attempts=(first_attempt,),
            final_verdict=verdict,
        )
        return
    unsupported.append((request, verdict))


def _prepare_correction_requests(
    unsupported: Sequence[
        tuple[IcaHazardVerificationRequest, IcaHazardVerificationVerdict]
    ],
    correction_method: Any | None,
    *,
    batch_id: str,
    records: dict[str, IcaHazardVerificationRecord],
    diagnostics: list[ConsiderationDiagnostic],
) -> tuple[
    list[
        tuple[
            IcaHazardVerificationRequest,
            IcaHazardVerificationVerdict,
            IcaHazardVerificationRequest,
        ]
    ],
    list[ConsiderationCallEvidence],
]:
    correction_requests = []
    call_evidence = []
    for request, first_verdict in unsupported:
        first_attempt = _semantic_attempt(request, first_verdict, 1)
        preparation = _prepare_one_correction(correction_method, request, first_verdict)
        if preparation.error is not None:
            call_evidence.append(
                _call_evidence(
                    batch_id, f"correction:{request.ica_id}", "technical_failure"
                )
            )
            _retain_unsupported_record(
                records,
                diagnostics,
                request,
                first_verdict,
                (first_attempt,),
                preparation.error,
                provider_failure=correction_method is not None,
            )
            continue
        if preparation.correction is not None:
            call_evidence.append(
                _call_evidence(batch_id, f"correction:{request.ica_id}", "accepted")
            )
            correction = preparation.correction
            _retain_unsupported_record(
                records,
                diagnostics,
                request,
                None,
                (first_attempt,),
                correction.rationale,
                correction=correction,
                terminal_disposition=correction.disposition,
            )
            continue
        call_evidence.append(
            _call_evidence(batch_id, f"correction:{request.ica_id}", "accepted")
        )
        if preparation.corrected_request is not None:
            correction_requests.append(
                (request, first_verdict, preparation.corrected_request)
            )
    return correction_requests, call_evidence


def _prepare_one_correction(
    correction_method: Any | None,
    request: IcaHazardVerificationRequest,
    verdict: IcaHazardVerificationVerdict,
) -> _CorrectionPreparation:
    if correction_method is None:
        return _CorrectionPreparation(
            error="no bounded ICA correction capability was supplied"
        )
    try:
        correction_raw = _invoke_correction_method(correction_method, request, verdict)
        correction_value = _coerce_correction_value(correction_raw, request)
        if (
            isinstance(correction_value, IcaHazardVerificationCorrection)
            and correction_value.disposition != "revise"
        ):
            return _CorrectionPreparation(correction=correction_value)
        corrected_request = _coerced_corrected_request(request, correction_value)
        if corrected_request.semantic_digest == request.semantic_digest:
            raise ValueError(
                "bounded correction returned unchanged ICA request content"
            )
        return _CorrectionPreparation(corrected_request=corrected_request)
    except Exception as exc:  # noqa: BLE001 - retain typed first verdict
        return _CorrectionPreparation(
            error=f"bounded ICA correction failed: {type(exc).__name__}: {exc}"
        )


def _coerced_corrected_request(
    request: IcaHazardVerificationRequest,
    value: IcaHazardVerificationCorrection | IcaHazardVerificationRequest,
) -> IcaHazardVerificationRequest:
    if isinstance(value, IcaHazardVerificationCorrection):
        return apply_ica_hazard_verification_correction(request, value)
    return value


def _verify_correction_requests(
    method: Any,
    correction_requests: Sequence[
        tuple[
            IcaHazardVerificationRequest,
            IcaHazardVerificationVerdict,
            IcaHazardVerificationRequest,
        ]
    ],
    *,
    batch_id: str,
    records: dict[str, IcaHazardVerificationRecord],
    diagnostics: list[ConsiderationDiagnostic],
) -> list[ConsiderationCallEvidence]:
    if not correction_requests:
        return []
    correction_by_id: dict[str, IcaHazardVerificationVerdict] = {}
    call_evidence: list[ConsiderationCallEvidence] = []
    for index, group in enumerate(_correction_request_groups(correction_requests), 1):
        corrected_requests, feedback = _correction_verification_inputs(group)
        try:
            correction_by_id.update(
                _run_correction_verification(method, corrected_requests, feedback)
            )
            outcome = "accepted"
        except Exception as exc:  # noqa: BLE001 - retain first verdict and failure
            _record_correction_verification_failure(diagnostics, group, exc)
            outcome = "technical_failure"
        call_evidence.append(
            _call_evidence(batch_id, f"correction-verification:{index}", outcome)
        )
    for request, first_verdict, corrected_request in correction_requests:
        _record_correction_result(
            request,
            first_verdict,
            corrected_request,
            correction_by_id.get(request.ica_id),
            records,
            diagnostics,
        )
    return call_evidence


def _correction_request_groups(
    values: Sequence[
        tuple[
            IcaHazardVerificationRequest,
            IcaHazardVerificationVerdict,
            IcaHazardVerificationRequest,
        ]
    ],
) -> tuple[
    tuple[
        tuple[
            IcaHazardVerificationRequest,
            IcaHazardVerificationVerdict,
            IcaHazardVerificationRequest,
        ],
        ...,
    ],
    ...,
]:
    grouped: dict[
        str,
        list[
            tuple[
                IcaHazardVerificationRequest,
                IcaHazardVerificationVerdict,
                IcaHazardVerificationRequest,
            ]
        ],
    ] = {}
    for value in values:
        grouped.setdefault(_verification_group_key(value[2]), []).append(value)
    return tuple(tuple(grouped[key]) for key in sorted(grouped))


def _correction_verification_inputs(
    correction_requests: Sequence[
        tuple[
            IcaHazardVerificationRequest,
            IcaHazardVerificationVerdict,
            IcaHazardVerificationRequest,
        ]
    ],
) -> tuple[tuple[IcaHazardVerificationRequest, ...], dict[str, str]]:
    corrected_requests = tuple(item[2] for item in correction_requests)
    feedback = {
        request.ica_id: (
            "The ICA was corrected once after the first independent verdict: "
            f"{first_verdict.rationale}"
        )
        for request, first_verdict, _ in correction_requests
    }
    return corrected_requests, feedback


def _run_correction_verification(
    method: Any,
    corrected_requests: Sequence[IcaHazardVerificationRequest],
    feedback: Mapping[str, str],
) -> dict[str, IcaHazardVerificationVerdict]:
    correction_raw = _invoke_verification_method(
        method, tuple(corrected_requests), correction_feedback=feedback
    )
    correction_verdicts, _ = _coerce_provider_result(correction_raw, corrected_requests)
    return {item.ica_id: item for item in correction_verdicts}


def _record_correction_verification_failure(
    diagnostics: list[ConsiderationDiagnostic],
    correction_requests: Sequence[
        tuple[
            IcaHazardVerificationRequest,
            IcaHazardVerificationVerdict,
            IcaHazardVerificationRequest,
        ]
    ],
    error: Exception,
) -> None:
    diagnostics.append(
        ConsiderationDiagnostic(
            code="ica_hazard_verification_provider_failure",
            detail=(
                "bounded ICA correction verification failed: "
                f"{type(error).__name__}: {error}"
            ),
            refs=tuple(item[0].ica_id for item in correction_requests),
        )
    )


def _record_correction_result(
    request: IcaHazardVerificationRequest,
    first_verdict: IcaHazardVerificationVerdict,
    corrected_request: IcaHazardVerificationRequest,
    second_verdict: IcaHazardVerificationVerdict | None,
    records: dict[str, IcaHazardVerificationRecord],
    diagnostics: list[ConsiderationDiagnostic],
) -> None:
    first_attempt = _semantic_attempt(request, first_verdict, 1)
    if second_verdict is None:
        second_attempt = IcaHazardVerificationAttempt(
            attempt=2,
            request_digest=corrected_request.semantic_digest,
            provider_status="protocol_failure",
            error="corrected request received no exact verdict",
            call_id=_call_id(request, 2),
            correction_applied=True,
        )
        _retain_unsupported_record(
            records,
            diagnostics,
            request,
            first_verdict,
            (first_attempt, second_attempt),
            "one bounded correction was exhausted without a second verdict",
            corrected_request=corrected_request,
            provider_failure=True,
        )
        return
    second_attempt = IcaHazardVerificationAttempt(
        attempt=2,
        request_digest=corrected_request.semantic_digest,
        verdict=second_verdict,
        provider_status="semantic_verdict",
        call_id=_call_id(request, 2),
        correction_applied=True,
    )
    if second_verdict.verdict != "supported":
        _retain_unsupported_record(
            records,
            diagnostics,
            request,
            second_verdict,
            (first_attempt, second_attempt),
            "one bounded correction was exhausted without support",
            corrected_request=corrected_request,
        )
        return
    records[request.ica_id] = IcaHazardVerificationRecord(
        ica_id=request.ica_id,
        slot_id=request.slot_id,
        request=request,
        corrected_request=corrected_request,
        attempts=(first_attempt, second_attempt),
        final_verdict=second_verdict,
    )


def verify_final_ica_batch(
    adapter: Any,
    enumeration: ICAEnumeration,
    *,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    batch_id: str = "ica-hazard-verification",
) -> tuple[ICAEnumeration, IcaHazardVerificationBatch]:
    """Verify final ICAs and exclude only semantically unsupported findings.

    The adapter is called once for the initial batch and at most once more for
    the subset that received a non-supported verdict.  Provider/protocol
    failures remain typed records and do not erase ordinary STPA siblings.
    A correction failure cannot rehabilitate a previously rejected finding.
    """
    requests, incomplete_ica_ids, diagnostics = _build_verification_requests(
        enumeration, loss_analysis, control_structure
    )
    if not requests:
        batch = IcaHazardVerificationBatch(
            batch_id=batch_id,
            diagnostics=tuple(diagnostics),
            incomplete_ica_ids=tuple(incomplete_ica_ids),
        )
        return _exclude_unsupported_icas(enumeration, batch), batch
    method = _verification_method(adapter)
    if method is None:
        return enumeration, _failed_batch(
            batch_id,
            requests,
            "no ICA hazard verification adapter was supplied",
        )
    records, unsupported, initial_diagnostics, call_evidence = (
        _verify_initial_request_groups(method, requests, batch_id=batch_id)
    )
    diagnostics.extend(initial_diagnostics)

    if unsupported:
        correction_requests, correction_evidence = _prepare_correction_requests(
            unsupported,
            _correction_method(adapter),
            batch_id=batch_id,
            records=records,
            diagnostics=diagnostics,
        )
        call_evidence.extend(correction_evidence)

        call_evidence.extend(
            _verify_correction_requests(
                method,
                correction_requests,
                batch_id=batch_id,
                records=records,
                diagnostics=diagnostics,
            )
        )
    batch = IcaHazardVerificationBatch(
        batch_id=batch_id,
        records=tuple(records.values()),
        diagnostics=tuple(diagnostics),
        call_evidence=tuple(call_evidence),
        incomplete_ica_ids=tuple(incomplete_ica_ids),
    )
    corrected_enumeration = _apply_corrected_requests(enumeration, records)
    return _exclude_unsupported_icas(corrected_enumeration, batch), batch


def _verify_initial_request_groups(
    method: Any,
    requests: Sequence[IcaHazardVerificationRequest],
    *,
    batch_id: str,
) -> tuple[
    dict[str, IcaHazardVerificationRecord],
    list[tuple[IcaHazardVerificationRequest, IcaHazardVerificationVerdict]],
    list[ConsiderationDiagnostic],
    list[ConsiderationCallEvidence],
]:
    records: dict[str, IcaHazardVerificationRecord] = {}
    unsupported: list[
        tuple[IcaHazardVerificationRequest, IcaHazardVerificationVerdict]
    ] = []
    diagnostics: list[ConsiderationDiagnostic] = []
    call_evidence: list[ConsiderationCallEvidence] = []
    for index, group in enumerate(_verification_request_groups(requests), 1):
        try:
            raw = _invoke_verification_method(method, group)
            verdicts, _ = _coerce_provider_result(raw, group)
            group_records, group_unsupported, group_diagnostics = (
                _collect_initial_results(group, verdicts)
            )
            records.update(group_records)
            unsupported.extend(group_unsupported)
            diagnostics.extend(group_diagnostics)
            outcome = "accepted"
        except Exception as exc:  # noqa: BLE001 - isolate this target batch
            detail = (
                f"initial ICA hazard verification failed: {type(exc).__name__}: {exc}"
            )
            for request in group:
                records[request.ica_id] = _provider_failure_record(
                    request,
                    attempt=1,
                    status="provider_failure",
                    error=detail,
                )
                diagnostics.append(
                    _verification_diagnostic(
                        "ica_hazard_verification_provider_failure", request, detail
                    )
                )
            outcome = "technical_failure"
        call_evidence.append(_call_evidence(batch_id, f"initial:{index}", outcome))
    return records, unsupported, diagnostics, call_evidence


def _verification_request_groups(
    requests: Sequence[IcaHazardVerificationRequest],
) -> tuple[tuple[IcaHazardVerificationRequest, ...], ...]:
    grouped: dict[str, list[IcaHazardVerificationRequest]] = {}
    for request in requests:
        grouped.setdefault(_verification_group_key(request), []).append(request)
    return tuple(tuple(grouped[key]) for key in sorted(grouped))


def _verification_group_key(request: IcaHazardVerificationRequest) -> str:
    return request.responsibility_id or request.slot_id.split(":", 1)[0]


def _verification_method(adapter: Any) -> Any | None:
    """Return the adapter's batch ICA hazard verifier, if it has one."""
    method = getattr(adapter, "verify_ica_hazards", None)
    return method if callable(method) else None


def _correction_method(adapter: Any) -> Any | None:
    """Return the adapter's request-local ICA correction, if it has one."""
    method = getattr(adapter, "correct_ica_hazard", None)
    return method if callable(method) else None


def _invoke_correction_method(
    method: Any,
    request: IcaHazardVerificationRequest,
    verdict: IcaHazardVerificationVerdict,
) -> Any:
    """Invoke a singular or request-local bounded correction capability."""
    parameters = _method_parameters(method)
    if "requests" in parameters:
        return _invoke_batch_correction(method, request, verdict, parameters)
    return _invoke_single_correction(method, request, verdict, parameters)


def _method_parameters(method: Any) -> Mapping[str, inspect.Parameter]:
    try:
        return inspect.signature(method).parameters
    except (TypeError, ValueError):
        return {}


def _invoke_batch_correction(
    method: Any,
    request: IcaHazardVerificationRequest,
    verdict: IcaHazardVerificationVerdict,
    parameters: Mapping[str, inspect.Parameter],
) -> Any:
    return method(
        (request,),
        **_batch_correction_kwargs(request, verdict, parameters),
    )


def _batch_correction_kwargs(
    request: IcaHazardVerificationRequest,
    verdict: IcaHazardVerificationVerdict,
    parameters: Mapping[str, inspect.Parameter],
) -> dict[str, Any]:
    if "verdicts" in parameters:
        return {"verdicts": (verdict,)}
    if "correction_feedback" in parameters:
        return {"correction_feedback": {request.ica_id: verdict.rationale}}
    return {}


def _invoke_single_correction(
    method: Any,
    request: IcaHazardVerificationRequest,
    verdict: IcaHazardVerificationVerdict,
    parameters: Mapping[str, inspect.Parameter],
) -> Any:
    return method(request, **_single_correction_kwargs(verdict, parameters))


def _single_correction_kwargs(
    verdict: IcaHazardVerificationVerdict,
    parameters: Mapping[str, inspect.Parameter],
) -> dict[str, Any]:
    name = next(
        (
            name
            for name in ("verdict", "first_verdict", "verification_verdict")
            if name in parameters
        ),
        None,
    )
    return {} if name is None else {name: verdict}


def _coerce_correction_value(
    value: Any,
    request: IcaHazardVerificationRequest,
) -> IcaHazardVerificationCorrection | IcaHazardVerificationRequest:
    """Normalize a provider/compiler correction before terminal disposition handling."""
    if isinstance(value, (list, tuple)):
        if len(value) != 1:
            raise ValueError("ICA correction must return one request-local correction")
        value = value[0]
    value = _unwrap_correction_value(value)
    return _coerce_correction_model(value, request)


def _unwrap_correction_value(value: Any) -> Any:
    """Unwrap the supported provider envelope shapes once per layer."""
    while isinstance(value, Mapping):
        wrapped = next(
            (
                value[key]
                for key in (
                    "corrected_request",
                    "request",
                    "correction",
                    "corrected_ica",
                )
                if key in value
            ),
            None,
        )
        if wrapped is None:
            return value
        value = wrapped
    return value


def _coerce_correction_model(
    value: Any,
    request: IcaHazardVerificationRequest,
) -> IcaHazardVerificationCorrection | IcaHazardVerificationRequest:
    if isinstance(value, IcaHazardVerificationRequest):
        return _coerce_corrected_request_model(value, request)
    if isinstance(value, IcaHazardVerificationCorrection):
        return _coerce_correction_value_model(value, request)
    return _coerce_correction_leaf(value, request)


def _coerce_corrected_request_model(
    value: IcaHazardVerificationRequest,
    request: IcaHazardVerificationRequest,
) -> IcaHazardVerificationRequest:
    if value.ica_id != request.ica_id:
        raise ValueError("corrected request changed the ICA identity")
    _validate_corrected_request(request, value)
    return value


def _coerce_correction_value_model(
    value: IcaHazardVerificationCorrection,
    request: IcaHazardVerificationRequest,
) -> IcaHazardVerificationCorrection:
    if value.ica_id != request.ica_id:
        raise ValueError("ICA correction identity does not match its request")
    return value


def _coerce_correction_leaf(
    value: Any,
    request: IcaHazardVerificationRequest,
) -> IcaHazardVerificationCorrection:
    if isinstance(value, ICA):
        return _correction_from_ica(value, request)
    if isinstance(value, Mapping):
        return _correction_from_mapping(value, request)
    raise TypeError("ICA correction must return a corrected ICA or typed request")


def _correction_from_ica(
    value: ICA,
    request: IcaHazardVerificationRequest,
) -> IcaHazardVerificationCorrection:
    return IcaHazardVerificationCorrection(
        ica_id=request.ica_id,
        deviation=value.deviation or value.ica_text,
        hazardous_context=value.hazardous_context,
        loss_consequence=value.loss_scenario,
        hazard_ids=tuple(value.related_hazards),
        constraint_ids=tuple(value.related_constraints),
        rationale="bounded correction supplied by the ICA compiler",
    )


def _correction_from_mapping(
    value: Mapping[str, Any],
    request: IcaHazardVerificationRequest,
) -> IcaHazardVerificationCorrection:
    payload = dict(value)
    payload.setdefault("ica_id", request.ica_id)
    payload.setdefault("rationale", "bounded correction supplied by the ICA compiler")
    return IcaHazardVerificationCorrection.model_validate(payload)


def _validate_corrected_request(
    request: IcaHazardVerificationRequest,
    corrected: IcaHazardVerificationRequest,
) -> None:
    """Keep a full provider correction request-local and structure-preserving."""
    _validate_immutable_request_fields(request, corrected)
    _validate_preserved_context(request.hazards, corrected.hazards, "hazard")
    _validate_preserved_context(
        request.constraints, corrected.constraints, "constraint"
    )
    _validate_preserved_context(request.losses, corrected.losses, "loss")


def _validate_immutable_request_fields(
    request: IcaHazardVerificationRequest,
    corrected: IcaHazardVerificationRequest,
) -> None:
    """Reject changes to the slot's structural STPA authority."""
    immutable_fields = (
        "slot_id",
        "responsibility_id",
        "responsibility_description",
        "controller_description",
        "control_action_id",
        "control_action_description",
        "action_recipient",
        "action_direction",
        "action_effect_kind",
        "action_temporality",
        "uca_type",
        "uca_definition",
    )
    for field_name in immutable_fields:
        if getattr(corrected, field_name) != getattr(request, field_name):
            raise ValueError(
                f"ICA correction changed immutable request field {field_name}"
            )


def _validate_preserved_context(
    original: Sequence[Any],
    corrected: Sequence[Any],
    context_name: str,
) -> None:
    """Allow a correction to select, but not invent or rewrite, context."""
    original_by_id, corrected_by_id = _context_entries(
        original, corrected, context_name
    )
    _reject_new_context_entries(original_by_id, corrected_by_id, context_name)
    _reject_changed_context_entries(original_by_id, corrected_by_id, context_name)


def _context_entries(
    original: Sequence[Any],
    corrected: Sequence[Any],
    context_name: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    id_attribute = {
        "hazard": "hazard_id",
        "constraint": "constraint_id",
        "loss": "loss_id",
    }[context_name]
    return (
        {getattr(item, id_attribute): item for item in original},
        {getattr(item, id_attribute): item for item in corrected},
    )


def _reject_new_context_entries(
    original: Mapping[str, Any],
    corrected: Mapping[str, Any],
    context_name: str,
) -> None:
    if set(corrected) - set(original):
        raise ValueError(
            f"ICA correction selected a {context_name} outside the supplied request"
        )


def _reject_changed_context_entries(
    original: Mapping[str, Any],
    corrected: Mapping[str, Any],
    context_name: str,
) -> None:
    if any(original[key] != value for key, value in corrected.items()):
        raise ValueError(f"ICA correction changed supplied {context_name} context")


def _semantic_attempt(
    request: IcaHazardVerificationRequest,
    verdict: IcaHazardVerificationVerdict,
    attempt: int,
) -> IcaHazardVerificationAttempt:
    """Bind one verdict to the request that was actually judged."""
    bound = verdict.model_copy(update={"request_digest": request.semantic_digest})
    return IcaHazardVerificationAttempt(
        attempt=attempt,
        request_digest=request.semantic_digest,
        verdict=bound,
        provider_status="semantic_verdict",
        call_id=_call_id(request, attempt),
    )


def _retain_unsupported_record(
    records: dict[str, IcaHazardVerificationRecord],
    diagnostics: list[ConsiderationDiagnostic],
    request: IcaHazardVerificationRequest,
    final_verdict: IcaHazardVerificationVerdict | None,
    attempts: tuple[IcaHazardVerificationAttempt, ...],
    detail: str,
    *,
    corrected_request: IcaHazardVerificationRequest | None = None,
    provider_failure: bool = False,
    correction: IcaHazardVerificationCorrection | None = None,
    terminal_disposition: Literal["not_applicable", "unresolved"] | None = None,
) -> None:
    """Retain semantic history while distinguishing terminal/provider outcomes."""
    prior_verdict = _prior_verdict(final_verdict, attempts)
    _append_prior_verdict_diagnostic(diagnostics, request, prior_verdict)
    _append_terminal_diagnostic(
        diagnostics,
        request,
        detail,
        terminal_disposition,
        provider_failure,
        corrected_request,
    )
    _append_provider_failure_diagnostic(diagnostics, request, detail, provider_failure)
    records[request.ica_id] = _unsupported_record(
        request,
        prior_verdict,
        final_verdict,
        attempts,
        corrected_request,
        correction,
        terminal_disposition,
        provider_failure,
    )


def _prior_verdict(
    final_verdict: IcaHazardVerificationVerdict | None,
    attempts: Sequence[IcaHazardVerificationAttempt],
) -> IcaHazardVerificationVerdict | None:
    if final_verdict is not None:
        return final_verdict
    return next(
        (attempt.verdict for attempt in attempts if attempt.verdict is not None),
        None,
    )


def _append_prior_verdict_diagnostic(
    diagnostics: list[ConsiderationDiagnostic],
    request: IcaHazardVerificationRequest,
    prior_verdict: IcaHazardVerificationVerdict | None,
) -> None:
    if prior_verdict is None:
        return
    code = (
        "ica_hazard_contradictory"
        if prior_verdict.verdict == "contradictory"
        else "ica_hazard_insufficient_evidence"
    )
    diagnostics.append(_verification_diagnostic(code, request, prior_verdict.rationale))


def _append_terminal_diagnostic(
    diagnostics: list[ConsiderationDiagnostic],
    request: IcaHazardVerificationRequest,
    detail: str,
    terminal_disposition: Literal["not_applicable", "unresolved"] | None,
    provider_failure: bool,
    corrected_request: IcaHazardVerificationRequest | None,
) -> None:
    if terminal_disposition is not None:
        code = (
            "ica_hazard_not_applicable"
            if terminal_disposition == "not_applicable"
            else "ica_hazard_unresolved"
        )
        diagnostics.append(_verification_diagnostic(code, request, detail))
        return
    if not provider_failure or corrected_request is not None:
        diagnostics.append(
            _verification_diagnostic("ica_hazard_correction_exhausted", request, detail)
        )


def _append_provider_failure_diagnostic(
    diagnostics: list[ConsiderationDiagnostic],
    request: IcaHazardVerificationRequest,
    detail: str,
    provider_failure: bool,
) -> None:
    if provider_failure:
        diagnostics.append(
            _verification_diagnostic(
                "ica_hazard_verification_provider_failure", request, detail
            )
        )


def _unsupported_record(
    request: IcaHazardVerificationRequest,
    prior_verdict: IcaHazardVerificationVerdict | None,
    final_verdict: IcaHazardVerificationVerdict | None,
    attempts: tuple[IcaHazardVerificationAttempt, ...],
    corrected_request: IcaHazardVerificationRequest | None,
    correction: IcaHazardVerificationCorrection | None,
    terminal_disposition: Literal["not_applicable", "unresolved"] | None,
    provider_failure: bool,
) -> IcaHazardVerificationRecord:
    del prior_verdict
    return IcaHazardVerificationRecord(
        ica_id=request.ica_id,
        slot_id=request.slot_id,
        request=request,
        corrected_request=corrected_request,
        correction=correction,
        attempts=attempts,
        final_verdict=None if provider_failure else final_verdict,
        disposition=terminal_disposition
        or ("provider_failure" if provider_failure else "excluded"),
    )


def _invoke_verification_method(
    method: Any,
    requests: tuple[IcaHazardVerificationRequest, ...],
    *,
    correction_feedback: Mapping[str, str] | None = None,
) -> Any:
    """Call batch or singular fake adapters without hidden retries."""
    parameters = _method_parameters(method)
    accepts_feedback = _accepts_correction_feedback(parameters)
    if _is_singular_verifier(parameters):
        return _invoke_singular_verifier(
            method, requests, correction_feedback, accepts_feedback
        )
    return _invoke_batch_verifier(
        method, requests, correction_feedback, accepts_feedback
    )


def _accepts_correction_feedback(
    parameters: Mapping[str, inspect.Parameter],
) -> bool:
    return "correction_feedback" in parameters or any(
        item.kind is inspect.Parameter.VAR_KEYWORD for item in parameters.values()
    )


def _is_singular_verifier(parameters: Mapping[str, inspect.Parameter]) -> bool:
    return "request" in parameters and "requests" not in parameters


def _invoke_singular_verifier(
    method: Any,
    requests: Sequence[IcaHazardVerificationRequest],
    correction_feedback: Mapping[str, str] | None,
    accepts_feedback: bool,
) -> list[Any]:
    return [
        method(request, **_verification_kwargs(correction_feedback, accepts_feedback))
        for request in requests
    ]


def _invoke_batch_verifier(
    method: Any,
    requests: tuple[IcaHazardVerificationRequest, ...],
    correction_feedback: Mapping[str, str] | None,
    accepts_feedback: bool,
) -> Any:
    return method(
        requests,
        **_verification_kwargs(correction_feedback, accepts_feedback),
    )


def _verification_kwargs(
    correction_feedback: Mapping[str, str] | None,
    accepts_feedback: bool,
) -> dict[str, Any]:
    if not accepts_feedback:
        return {}
    return {"correction_feedback": correction_feedback}


def _coerce_provider_result(
    value: Any,
    requests: Sequence[IcaHazardVerificationRequest],
) -> tuple[
    tuple[IcaHazardVerificationVerdict, ...], dict[str, IcaHazardVerificationCorrection]
]:
    """Normalize provider/fake responses and bind verdicts to request digests."""
    values, corrections = _provider_values_and_corrections(value)
    values = _normalise_verdict_values(values)
    request_by_id = {item.ica_id: item for item in requests}
    verdicts = [_coerce_verdict(value, request_by_id) for value in values]
    if len(verdicts) != len(set(item.ica_id for item in verdicts)):
        raise ValueError("ICA hazard verifier returned duplicate ICA IDs")
    return tuple(verdicts), _coerce_corrections(corrections, request_by_id)


def _provider_values_and_corrections(value: Any) -> tuple[Any, Any]:
    if isinstance(value, IcaHazardVerificationBatch):
        values = [
            record.final_verdict for record in value.records if record.final_verdict
        ]
        return values, ()
    if isinstance(value, Mapping):
        return value.get("verdicts", value), value.get("corrections", ())
    return value, ()


def _normalise_verdict_values(value: Any) -> tuple[Any, ...]:
    if isinstance(value, IcaHazardVerificationVerdict):
        return (value,)
    if isinstance(value, Mapping):
        return tuple(_mapping_verdict_payload(key, item) for key, item in value.items())
    if not isinstance(value, (list, tuple)):
        raise TypeError("ICA hazard verifier must return a verdict sequence")
    return tuple(value)


def _mapping_verdict_payload(key: str, value: Any) -> dict[str, Any]:
    return {
        "ica_id": key,
        **(value if isinstance(value, Mapping) else {"verdict": value}),
    }


def _coerce_verdict(
    value: Any,
    request_by_id: Mapping[str, IcaHazardVerificationRequest],
) -> IcaHazardVerificationVerdict:
    payload = _verdict_payload(value)
    ica_id = payload.get("ica_id")
    if ica_id not in request_by_id:
        raise ValueError("ICA hazard verifier returned an unknown ICA ID")
    _bind_verdict_digest(payload, request_by_id[ica_id])
    return IcaHazardVerificationVerdict.model_validate(payload)


def _verdict_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, IcaHazardVerificationVerdict):
        return value.model_dump(mode="python")
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="python")
    if isinstance(value, Mapping):
        return dict(value)
    raise TypeError("ICA hazard verifier returned an invalid verdict")


def _bind_verdict_digest(
    payload: dict[str, Any],
    request: IcaHazardVerificationRequest,
) -> None:
    supplied_digest = payload.get("request_digest")
    expected_digest = request.semantic_digest
    if supplied_digest not in (None, expected_digest):
        raise ValueError("ICA hazard verifier returned a mismatched request digest")
    payload["request_digest"] = expected_digest


def _coerce_corrections(
    values: Any,
    request_by_id: Mapping[str, IcaHazardVerificationRequest],
) -> dict[str, IcaHazardVerificationCorrection]:
    result: dict[str, IcaHazardVerificationCorrection] = {}
    for value in values or ():
        correction = _coerce_one_correction(value)
        _require_known_correction_ica(correction, request_by_id)
        result[correction.ica_id] = correction
    return result


def _coerce_one_correction(value: Any) -> IcaHazardVerificationCorrection:
    if isinstance(value, IcaHazardVerificationCorrection):
        return value
    return IcaHazardVerificationCorrection.model_validate(value)


def _require_known_correction_ica(
    correction: IcaHazardVerificationCorrection,
    request_by_id: Mapping[str, IcaHazardVerificationRequest],
) -> None:
    if correction.ica_id not in request_by_id:
        raise ValueError("ICA correction returned an unknown ICA ID")


def _call_id(request: IcaHazardVerificationRequest, attempt: int) -> str:
    return f"memory://stpa-ica-hazard-verification/{request.ica_id}/attempt-{attempt}"


def _provider_failure_record(
    request: IcaHazardVerificationRequest,
    *,
    attempt: int,
    status: Literal["provider_failure", "protocol_failure"],
    error: str,
) -> IcaHazardVerificationRecord:
    return IcaHazardVerificationRecord(
        ica_id=request.ica_id,
        slot_id=request.slot_id,
        request=request,
        attempts=(
            IcaHazardVerificationAttempt(
                attempt=attempt,
                request_digest=request.semantic_digest,
                provider_status=status,
                error=error,
                call_id=_call_id(request, attempt),
            ),
        ),
        disposition="provider_failure",
    )


def _failed_batch(
    batch_id: str,
    requests: Sequence[IcaHazardVerificationRequest],
    error: str,
) -> IcaHazardVerificationBatch:
    diagnostics = tuple(
        _verification_diagnostic(
            "ica_hazard_verification_provider_failure", request, error
        )
        for request in requests
    )
    return IcaHazardVerificationBatch(
        batch_id=batch_id,
        records=tuple(
            _provider_failure_record(
                request,
                attempt=1,
                status="provider_failure",
                error=error,
            )
            for request in requests
        ),
        diagnostics=diagnostics,
        call_evidence=(
            ConsiderationCallEvidence(
                call_id=f"{batch_id}:initial",
                attempt_count=1,
                outcome="technical_failure",
            ),
        ),
    )


def _verification_diagnostic(
    code: str,
    request: IcaHazardVerificationRequest,
    detail: str,
) -> ConsiderationDiagnostic:
    return ConsiderationDiagnostic(code=code, detail=detail, refs=(request.ica_id,))


def _apply_corrected_requests(
    enumeration: ICAEnumeration,
    records: Mapping[str, IcaHazardVerificationRecord],
) -> ICAEnumeration:
    """Materialize a supported bounded correction into the final ICA text."""
    corrected_by_id = _corrected_requests_by_id(records)
    if not corrected_by_id:
        return enumeration
    return ICAEnumeration(
        slots=[
            _apply_corrected_slot(slot, corrected_by_id) for slot in enumeration.slots
        ]
    )


def _corrected_requests_by_id(
    records: Mapping[str, IcaHazardVerificationRecord],
) -> dict[str, IcaHazardVerificationRequest]:
    return {
        record.ica_id: record.corrected_request
        for record in records.values()
        if record.corrected_request is not None and record.disposition == "supported"
    }


def _apply_corrected_slot(
    slot: ICASlot,
    corrected_by_id: Mapping[str, IcaHazardVerificationRequest],
) -> ICASlot:
    if slot.is_na or slot.unresolved_reason is not None:
        return slot
    return slot.model_copy(
        update={
            "icas": [_apply_corrected_ica(ica, corrected_by_id) for ica in slot.icas]
        }
    )


def _apply_corrected_ica(
    ica: ICA,
    corrected_by_id: Mapping[str, IcaHazardVerificationRequest],
) -> ICA:
    corrected = corrected_by_id.get(ica.ica_id)
    if corrected is None:
        return ica
    return ica.model_copy(
        update={
            "ica_text": corrected.deviation,
            "deviation": corrected.deviation,
            "hazardous_context": corrected.hazardous_context,
            "loss_scenario": corrected.loss_consequence,
            "related_hazards": [item.hazard_id for item in corrected.hazards],
            "related_constraints": [
                item.constraint_id for item in corrected.constraints
            ],
        }
    )


def _exclude_unsupported_icas(
    enumeration: ICAEnumeration,
    batch: IcaHazardVerificationBatch,
) -> ICAEnumeration:
    """Remove only final non-supported ICAs; preserve valid slot siblings."""
    excluded = _final_excluded_ica_ids(batch)
    if not excluded:
        return enumeration
    terminal_na_reasons = {
        record.ica_id: record.correction.rationale
        for record in batch.records
        if record.disposition == "not_applicable" and record.correction is not None
    }
    return ICAEnumeration(
        slots=[
            _exclude_from_slot(
                slot,
                excluded,
                terminal_na_reasons=terminal_na_reasons,
            )
            for slot in enumeration.slots
        ]
    )


def _final_excluded_ica_ids(batch: IcaHazardVerificationBatch) -> set[str]:
    excluded = {
        record.ica_id for record in batch.records if _record_excludes_generation(record)
    }
    # A final ICA whose narrow request could not be constructed is still
    # retained in the batch diagnostics, but it cannot enter Stage 5 without
    # complete authoritative hazard/loss lineage.
    excluded.update(batch.incomplete_ica_ids)
    return excluded


def _record_excludes_generation(record: IcaHazardVerificationRecord) -> bool:
    if record.disposition != "provider_failure":
        return record.disposition != "supported"
    # A failed first review has no semantic verdict. A failed repair does:
    # keep that rejection effective without inventing a verdict on the repair.
    return any(
        attempt.verdict is not None and attempt.verdict.verdict != "supported"
        for attempt in record.attempts
    )


def _exclude_from_slot(
    slot: ICASlot,
    excluded: set[str],
    *,
    terminal_na_reasons: Mapping[str, str] | None = None,
) -> ICASlot:
    if slot.is_na:
        return slot
    kept = [ica for ica in slot.icas if ica.ica_id not in excluded]
    if kept:
        return slot.model_copy(update={"icas": kept})
    excluded_ids = {ica.ica_id for ica in slot.icas}
    terminal_na_reasons = terminal_na_reasons or {}
    if excluded_ids and excluded_ids <= terminal_na_reasons.keys():
        reasons = tuple(
            sorted(
                {
                    reason.strip()
                    for ica_id, reason in terminal_na_reasons.items()
                    if ica_id in excluded_ids and reason.strip()
                }
            )
        )
        if reasons:
            return _excluded_slot_as_na(slot, "; ".join(reasons))
    return _excluded_slot_as_unresolved(slot)


def _excluded_slot_as_na(slot: ICASlot, reason: str) -> ICASlot:
    """Materialize a slot whose every ICA was explicitly judged N/A."""
    return ICASlot.model_validate(
        {
            **slot.model_dump(mode="python"),
            "is_na": True,
            "icas": [],
            "na_justification": reason,
            "unresolved_reason": None,
        }
    )


def _excluded_slot_as_unresolved(slot: ICASlot) -> ICASlot:
    """Retain a fully excluded slot as unresolved, never justified N/A."""
    return ICASlot.model_validate(
        {
            **slot.model_dump(mode="python"),
            "is_na": False,
            "icas": [],
            "na_justification": None,
            "unresolved_reason": (
                "All final ICAs in this slot failed independent semantic "
                "hazard/loss verification."
            ),
        }
    )


def filter_ica_considerations(
    considerations: Sequence[ObligationIcaConsideration],
    batch: IcaHazardVerificationBatch,
    *,
    enumeration: ICAEnumeration | None = None,
) -> tuple[ObligationIcaConsideration, ...]:
    """Withhold attribution for excluded ICAs while retaining valid siblings."""
    excluded = _excluded_ica_ids(batch)
    if not excluded:
        return tuple(considerations)
    ica_by_id = _enumerated_icas(enumeration)
    records_by_id = {record.ica_id: record for record in batch.records}
    result = _filter_consideration_pairs(
        considerations,
        excluded=excluded,
        records_by_id=records_by_id,
        diagnostics=batch.diagnostics,
        ica_by_id=ica_by_id,
    )
    return tuple(sorted(result, key=lambda item: (item.obligation_id, item.slot_id)))


def _enumerated_icas(
    enumeration: ICAEnumeration | None,
) -> dict[str, ICA]:
    return {
        ica.ica_id: ica
        for slot in (enumeration.slots if enumeration is not None else ())
        for ica in slot.icas
    }


def _filter_consideration_pairs(
    considerations: Sequence[ObligationIcaConsideration],
    *,
    excluded: set[str],
    records_by_id: Mapping[str, IcaHazardVerificationRecord],
    diagnostics: Sequence[ConsiderationDiagnostic],
    ica_by_id: Mapping[str, ICA],
) -> list[ObligationIcaConsideration]:
    return [
        _filter_ica_consideration(
            pair,
            excluded=excluded,
            records_by_id=records_by_id,
            diagnostics=diagnostics,
            ica_by_id=ica_by_id,
        )
        for pair in considerations
    ]


def _excluded_ica_ids(batch: IcaHazardVerificationBatch) -> set[str]:
    excluded = {
        record.ica_id for record in batch.records if record.disposition != "supported"
    }
    # Projection failures have no record (there is no request digest to bind),
    # so carry their exact ICA identities separately into accounting.
    excluded.update(batch.incomplete_ica_ids)
    return excluded


def _filter_ica_consideration(
    pair: ObligationIcaConsideration,
    *,
    excluded: set[str],
    records_by_id: Mapping[str, IcaHazardVerificationRecord],
    diagnostics: Sequence[ConsiderationDiagnostic],
    ica_by_id: Mapping[str, ICA],
) -> ObligationIcaConsideration:
    if pair.disposition != "finding":
        return pair
    retained, affected = _partition_ica_ids(pair.ica_ids, excluded)
    if not affected:
        return pair
    affected_records = _affected_records(affected, records_by_id)
    terminal_not_applicable = _terminal_not_applicable(affected_records)
    code = _consideration_exclusion_code(affected, diagnostics, terminal_not_applicable)
    diagnostic = ConsiderationDiagnostic(
        code=code,
        detail="independent ICA hazard verification excluded " + ", ".join(affected),
        obligation_ids=(pair.obligation_id,),
        refs=affected,
    )
    payload = _filtered_consideration_payload(pair, diagnostic)
    return _complete_filtered_consideration(
        payload,
        retained,
        affected_records,
        terminal_not_applicable,
        ica_by_id,
    )


def _partition_ica_ids(
    ica_ids: Sequence[str],
    excluded: set[str],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    return (
        tuple(item for item in ica_ids if item not in excluded),
        tuple(item for item in ica_ids if item in excluded),
    )


def _affected_records(
    affected: Sequence[str],
    records_by_id: Mapping[str, IcaHazardVerificationRecord],
) -> tuple[IcaHazardVerificationRecord, ...]:
    return tuple(records_by_id[item] for item in affected if item in records_by_id)


def _complete_filtered_consideration(
    payload: dict[str, Any],
    retained: Sequence[str],
    affected_records: Sequence[IcaHazardVerificationRecord],
    terminal_not_applicable: bool,
    ica_by_id: Mapping[str, ICA],
) -> ObligationIcaConsideration:
    if not retained:
        _mark_fully_excluded_consideration(
            payload, affected_records, terminal_not_applicable
        )
    else:
        _retain_ica_siblings(payload, retained, ica_by_id)
    return ObligationIcaConsideration.model_validate(payload)


def _terminal_not_applicable(
    records: Sequence[IcaHazardVerificationRecord],
) -> bool:
    return bool(records) and all(
        record.disposition == "not_applicable" for record in records
    )


def _consideration_exclusion_code(
    affected: Sequence[str],
    diagnostics: Sequence[ConsiderationDiagnostic],
    terminal_not_applicable: bool,
) -> str:
    failure_codes = {
        diagnostic.code
        for diagnostic in diagnostics
        if any(ref in affected for ref in diagnostic.refs)
    }
    if "ica_hazard_verification_provider_failure" in failure_codes:
        return "ica_hazard_verification_provider_failure"
    if terminal_not_applicable:
        return "ica_hazard_not_applicable"
    return "ica_hazard_correction_exhausted"


def _filtered_consideration_payload(
    pair: ObligationIcaConsideration,
    diagnostic: ConsiderationDiagnostic,
) -> dict[str, Any]:
    payload = pair.model_dump(mode="python", exclude={"pair_id"})
    payload["diagnostics"] = (*pair.diagnostics, diagnostic)
    payload["rationale"] = (
        pair.rationale or "STPA finding"
    ) + "; excluded ICAs are not credited by semantic verification"
    return payload


def _mark_fully_excluded_consideration(
    payload: dict[str, Any],
    affected_records: Sequence[IcaHazardVerificationRecord],
    terminal_not_applicable: bool,
) -> None:
    payload.update(ica_ids=(), exec_candidate_ids=(), hazard_ids=(), constraint_ids=())
    if not terminal_not_applicable:
        payload["disposition"] = "unresolved"
        return
    payload.update(
        disposition="proposed_not_applicable",
        structural_inventory_complete=True,
        rationale=(
            affected_records[0].correction.rationale
            if affected_records[0].correction is not None
            else "The corrected ICA was explicitly marked not applicable."
        ),
    )


def _retain_ica_siblings(
    payload: dict[str, Any],
    retained: Sequence[str],
    ica_by_id: Mapping[str, ICA],
) -> None:
    payload["ica_ids"] = retained
    context_ids = _retained_context_ids(retained, ica_by_id)
    if context_ids is None:
        return
    payload["hazard_ids"], payload["constraint_ids"] = context_ids


def _retained_context_ids(
    retained: Sequence[str],
    ica_by_id: Mapping[str, ICA],
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    if not ica_by_id:
        return None
    retained_icas = [ica_by_id[item] for item in retained]
    return (
        _ica_context_refs(retained_icas, "related_hazards"),
        _ica_context_refs(retained_icas, "related_constraints"),
    )


def _ica_context_refs(icas: Sequence[ICA], field_name: str) -> tuple[str, ...]:
    """Collect one canonical ICA reference family without changing meaning."""
    refs: set[str] = set()
    for ica in icas:
        refs.update(getattr(ica, field_name))
    return tuple(sorted(refs))


def _uca_definition(uca_type: UCAType) -> str:
    """Return the STPA category meaning without mechanism or taxonomy prose."""
    definitions = {
        UCAType.not_provided: "The control action is not provided when it is needed.",
        UCAType.incorrect: "The control action is provided in an unsafe form.",
        UCAType.wrong_timing: "The control action is provided too early or too late.",
        UCAType.wrong_duration: "The control action is applied for an unsafe duration.",
    }
    return definitions[uca_type]


__all__ = [
    "ICA_HAZARD_VERIFICATION_BATCH_DIGEST_DOMAIN",
    "ICA_HAZARD_VERIFICATION_BATCH_SCHEMA_VERSION",
    "ICA_HAZARD_VERIFICATION_REQUEST_DIGEST_DOMAIN",
    "ICA_HAZARD_VERIFICATION_REQUEST_SCHEMA_VERSION",
    "IcaConstraintContext",
    "IcaHazardContext",
    "IcaHazardVerificationAttempt",
    "IcaHazardVerificationBatch",
    "IcaHazardVerificationCorrection",
    "IcaHazardVerificationRecord",
    "IcaHazardVerificationRequest",
    "IcaHazardVerificationVerdict",
    "IcaLossContext",
    "build_ica_hazard_verification_request",
    "apply_ica_hazard_verification_correction",
    "filter_ica_considerations",
    "verify_final_ica_batch",
]
