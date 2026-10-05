"""Target-agnostic observation capabilities and Stage 5 testability checks.

The producer owns scenario meaning, but it must not ask a downstream runtime
to prove an outcome that the runtime cannot observe.  This module is the
small, gold-free contract between those two concerns.  It describes the
evidence that the qualification adapter actually captures and classifies a
provider-authored outcome declaration without reading a target or a gold set.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    field_validator,
    model_validator,
)

OBSERVATION_CONTRACT_SCHEMA = "observation-contract-v1"
OBSERVATION_CONTRACT_DIGEST_DOMAIN = OBSERVATION_CONTRACT_SCHEMA
OBSERVATION_CONTRACT_FILENAME = "observation-contract.yaml"

ClaimLevel = Literal["command_attempt", "reply", "returned_result", "state_effect"]
ObservationEvidence = Literal[
    "assistant_message", "tool_call", "tool_result", "snapshot"
]
ObservationDisposition = Literal["executable", "analytical_only"]
_CLAIM_EVIDENCE = {
    "command_attempt": "tool_call",
    "reply": "assistant_message",
    "returned_result": "tool_result",
    "state_effect": "snapshot",
}


def _stripped_text(value: str, blank_message: str) -> str:
    """Return ``value`` without surrounding whitespace; reject a blank result."""
    value = value.strip()
    if not value:
        raise ValueError(blank_message)
    return value


class ObservationContractError(ValueError):
    """Raised when an observation contract is malformed or tampered."""


class ObservationContractModel(BaseModel):
    """Strict base for the producer-owned observation contract."""

    model_config = ConfigDict(extra="forbid")


class ObservationCapability(ObservationContractModel):
    """One capture primitive exposed by the qualification adapter."""

    kind: ObservationEvidence
    available: StrictBool
    complete_when: StrictStr
    description: StrictStr

    @field_validator("complete_when", "description")
    @classmethod
    def _require_text(cls, value: str) -> str:
        return _stripped_text(value, "observation capability text must not be blank")


class ObservationContract(ObservationContractModel):
    """Gold-free, target-agnostic description of runtime observations."""

    schema_version: Literal[OBSERVATION_CONTRACT_SCHEMA] = OBSERVATION_CONTRACT_SCHEMA
    contract_id: StrictStr = Field(min_length=1)
    supported_claim_levels: tuple[ClaimLevel, ...] = ()
    capture: tuple[ObservationCapability, ...] = ()
    unsupported_claims: tuple[StrictStr, ...] = ()
    content_digest: str = ""

    @field_validator("contract_id")
    @classmethod
    def _strip_contract_id(cls, value: str) -> str:
        return _stripped_text(value, "observation contract_id must not be blank")

    @field_validator("supported_claim_levels")
    @classmethod
    def _unique_claim_levels(
        cls, value: tuple[ClaimLevel, ...]
    ) -> tuple[ClaimLevel, ...]:
        if len(value) != len(set(value)):
            raise ValueError("supported_claim_levels must be unique")
        return value

    def canonical_payload(self) -> dict[str, Any]:
        """Return the digest-covered contract without its own digest."""

        payload = self.model_dump(mode="json", exclude_none=True)
        payload.pop("content_digest", None)
        return payload

    def finalize(self) -> "ObservationContract":
        """Return this contract with a deterministic content digest."""

        digest = observation_contract_digest(self.canonical_payload())
        if self.content_digest and self.content_digest != digest:
            raise ObservationContractError(
                "observation contract content_digest does not match its content"
            )
        return self.model_copy(update={"content_digest": digest})

    def verify_digest(self) -> None:
        """Fail closed when the recorded digest does not match the content."""

        expected = observation_contract_digest(self.canonical_payload())
        if self.content_digest != expected:
            raise ObservationContractError(
                "observation contract content_digest does not match its content"
            )

    def supports_evidence(self, evidence: str | None) -> bool:
        """Return whether the contract captures the requested evidence kind."""

        if evidence is None:
            return False
        return any(item.kind == evidence and item.available for item in self.capture)


class SafeObservableOutcome(ObservationContractModel):
    """One scenario-specific boundary for the expected safe behavior.

    The statement is semantic prose, while the remaining fields bind that
    prose to the exact evidence boundary supplied to Stage 5.  An
    ``analytical_only`` outcome is represented explicitly with
    ``observable=False`` and no claim, operation, record, or fact references.
    """

    observable: StrictBool
    statement: StrictStr = Field(min_length=1, max_length=600)
    claim_level: ClaimLevel | None = None
    evidence: ObservationEvidence | None = None
    operation_name: StrictStr | None = Field(default=None, min_length=1)
    record_refs: tuple[StrictStr, ...] = ()
    fact_refs: tuple[StrictStr, ...] = ()

    @field_validator("statement")
    @classmethod
    def _strip_statement(cls, value: str) -> str:
        return _stripped_text(
            value, "safe observable outcome statement must not be blank"
        )

    @field_validator("operation_name")
    @classmethod
    def _strip_operation_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _stripped_text(
            value, "safe observable outcome operation_name must not be blank"
        )

    @field_validator("record_refs", "fact_refs")
    @classmethod
    def _strip_references(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(value.strip() for value in values)
        if any(not value for value in normalized):
            raise ValueError("safe observable outcome references must not be blank")
        return normalized

    @model_validator(mode="after")
    def validate_boundary(self) -> "SafeObservableOutcome":
        """Require a complete, internally consistent evidence boundary."""

        for name in ("record_refs", "fact_refs"):
            references = getattr(self, name)
            if len(references) != len(set(references)):
                raise ValueError(f"safe observable outcome {name} must be unique")
        if self.observable:
            self._require_matching_evidence()
        elif self._has_evidence_boundary():
            raise ValueError(
                "analytical-only safe outcomes must omit claim, operation, "
                "record, and fact references"
            )
        return self

    def _require_matching_evidence(self) -> None:
        if self.claim_level is None or self.evidence is None:
            raise ValueError(
                "observable safe outcomes require claim_level and evidence"
            )
        expected = _CLAIM_EVIDENCE[self.claim_level]
        if self.evidence != expected:
            raise ValueError(
                "safe observable outcome evidence does not match claim_level: "
                f"{self.claim_level} requires {expected}"
            )

    def _has_evidence_boundary(self) -> bool:
        return (
            any(
                value is not None
                for value in (self.claim_level, self.evidence, self.operation_name)
            )
            or bool(self.record_refs)
            or bool(self.fact_refs)
        )


class ObservationCriterion(ObservationContractModel):
    """One provider-declared outcome and its requested evidence boundary."""

    criterion_id: StrictStr = Field(min_length=1)
    outcome: StrictStr = Field(min_length=1, max_length=600)
    observable: StrictBool
    claim_level: StrictStr | None = None
    evidence: StrictStr | None = None
    operation_name: StrictStr | None = Field(default=None, min_length=1)
    reason: StrictStr = Field(min_length=1, max_length=600)

    @field_validator("criterion_id", "outcome", "reason")
    @classmethod
    def _strip_criterion_text(cls, value: str) -> str:
        return _stripped_text(value, "observation criterion text must not be blank")

    @field_validator("claim_level", "evidence", "operation_name")
    @classmethod
    def _strip_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @model_validator(mode="after")
    def validate_observation_shape(self) -> "ObservationCriterion":
        """Require evidence fields only for observable claims."""

        if self.observable and (self.claim_level is None or self.evidence is None):
            raise ValueError(
                "observable observation criteria require claim_level and evidence"
            )
        if not self.observable and (
            self.claim_level is not None
            or self.evidence is not None
            or self.operation_name is not None
        ):
            raise ValueError(
                "analytical-only observation criteria must omit claim_level, "
                "evidence, and operation_name"
            )
        return self


class ObservationAssessment(ObservationContractModel):
    """Deterministic testability result persisted with a scenario."""

    disposition: ObservationDisposition
    reason: StrictStr = Field(min_length=1)
    supported_criteria: tuple[StrictStr, ...] = ()
    unsupported_criteria: tuple[StrictStr, ...] = ()

    @field_validator("reason")
    @classmethod
    def _strip_reason(cls, value: str) -> str:
        return _stripped_text(value, "observation assessment reason must not be blank")


def observation_contract_digest(payload: dict[str, Any]) -> str:
    """Return the framed digest for an observation contract payload."""

    from asago_scenario_generator.models.canonical import compute_framed_digest

    return compute_framed_digest(OBSERVATION_CONTRACT_DIGEST_DOMAIN, payload)


def observation_contract_from_payload(payload: Any) -> ObservationContract:
    """Validate and verify one JSON/YAML contract payload."""

    if not isinstance(payload, dict):
        raise ObservationContractError("observation contract must be an object")
    try:
        contract = ObservationContract.model_validate(payload)
    except ValueError as exc:
        raise ObservationContractError(str(exc)) from exc
    contract.verify_digest()
    return contract


def load_observation_contract(path: str | Path) -> ObservationContract:
    """Read and verify a caller-supplied observation contract."""

    source = Path(path)
    try:
        payload = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ObservationContractError(
            f"cannot read observation contract {source}: {exc}"
        ) from exc
    return observation_contract_from_payload(payload)


def write_observation_contract(contract: ObservationContract, path: str | Path) -> Path:
    """Write a verified observation contract as YAML."""

    contract.verify_digest()
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        yaml.safe_dump(
            contract.model_dump(mode="json", exclude_none=True),
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    return destination


def assess_observation_criteria(
    criteria: tuple[ObservationCriterion, ...] | list[ObservationCriterion],
    contract: ObservationContract,
) -> ObservationAssessment:
    """Classify provider criteria against the actual capture contract.

    A scenario is executable when at least one declared unsafe outcome is
    observable at a supported claim level.  Unsupported sibling criteria do
    not make that supported outcome disappear, but a scenario with no
    supported observable criterion is explicitly analytical-only.
    """

    if not criteria:
        return ObservationAssessment(
            disposition="analytical_only",
            reason="observation_criteria_missing",
        )

    supported: list[str] = []
    unsupported: list[str] = []
    unsupported_reasons: list[str] = []
    for criterion in criteria:
        if not criterion.observable:
            unsupported.append(criterion.criterion_id)
            continue
        gap = _unsupported_reason(criterion, contract)
        if gap is None:
            supported.append(criterion.criterion_id)
            continue
        unsupported.append(criterion.criterion_id)
        unsupported_reasons.append(gap)

    if supported:
        reason = "observable_outcome_supported"
        if unsupported_reasons:
            reason += ";" + ",".join(unsupported_reasons)
        return ObservationAssessment(
            disposition="executable",
            reason=reason,
            supported_criteria=tuple(supported),
            unsupported_criteria=tuple(unsupported),
        )

    reason = "no_observable_outcome"
    if unsupported_reasons:
        reason += ";" + ",".join(unsupported_reasons)
    return ObservationAssessment(
        disposition="analytical_only",
        reason=reason,
        unsupported_criteria=tuple(unsupported),
    )


def _unsupported_reason(
    criterion: ObservationCriterion, contract: ObservationContract
) -> str | None:
    """Return why the contract cannot support an observable criterion."""

    criterion_id = criterion.criterion_id
    evidence = criterion.evidence or "missing"
    if criterion.claim_level not in contract.supported_claim_levels:
        return (
            f"{criterion_id}:unsupported_claim_level:"
            f"{criterion.claim_level or 'missing'}"
        )
    expected_evidence = _CLAIM_EVIDENCE.get(criterion.claim_level)
    if expected_evidence is not None and criterion.evidence != expected_evidence:
        return (
            f"{criterion_id}:evidence_mismatch:{evidence}:expected:{expected_evidence}"
        )
    if not contract.supports_evidence(criterion.evidence):
        return f"{criterion_id}:evidence_not_captured:{evidence}"
    return None


def default_observation_contract() -> ObservationContract:
    """Return the contract implemented by the frozen live qualification path."""

    return ObservationContract(
        contract_id="qualification-live-v1",
        supported_claim_levels=("command_attempt", "reply"),
        capture=(
            ObservationCapability(
                kind="assistant_message",
                available=True,
                complete_when=(
                    "The transport returns the assistant message collection; "
                    "individual content may still be null."
                ),
                description="Captured assistant messages support reply-level claims.",
            ),
            ObservationCapability(
                kind="tool_call",
                available=True,
                complete_when=(
                    "tool_calls_capture.available and tool_calls_capture.complete "
                    "are both true."
                ),
                description=(
                    "Decoded tool-call names and arguments support command-attempt "
                    "claims."
                ),
            ),
            ObservationCapability(
                kind="tool_result",
                available=False,
                complete_when="No supported completion condition is defined.",
                description=(
                    "Decoded results are retained as evidence context but the live "
                    "dispatch does not publish a returned-result claim."
                ),
            ),
            ObservationCapability(
                kind="snapshot",
                available=False,
                complete_when="No live state-effect snapshot is attached.",
                description=(
                    "The current live dispatch does not establish backend state "
                    "effects or cross-channel ordering."
                ),
            ),
        ),
        unsupported_claims=(
            "internal_component_signal",
            "model_to_model_prompt",
            "internal_state_without_snapshot",
            "cross_channel_ordering",
            "absence_of_reply",
            "returned_result",
            "state_effect",
        ),
    ).finalize()


__all__ = [
    "ClaimLevel",
    "OBSERVATION_CONTRACT_DIGEST_DOMAIN",
    "OBSERVATION_CONTRACT_FILENAME",
    "OBSERVATION_CONTRACT_SCHEMA",
    "ObservationAssessment",
    "ObservationCapability",
    "ObservationContract",
    "ObservationContractError",
    "ObservationCriterion",
    "ObservationDisposition",
    "ObservationEvidence",
    "assess_observation_criteria",
    "default_observation_contract",
    "load_observation_contract",
    "observation_contract_digest",
    "observation_contract_from_payload",
    "write_observation_contract",
]
