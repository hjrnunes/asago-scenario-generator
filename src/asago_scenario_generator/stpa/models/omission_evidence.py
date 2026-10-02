"""Closed structured omission-evidence basis for tool-absent outcomes.

The basis separates the two meanings the compiled proposition used to mix:
the author's conditional trigger interpretation and the exact source-presence
evidence behind it.  Every quotation is provenance.  The basis never claims
that a reviewed obligation applies; applicability is code-owned and stays
unresolved in this version.

This leaf imports neither scenario_prod nor orchestration code.  It depends
only on the canonical digest helpers.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    model_validator,
)

from asago_scenario_generator.models.canonical import (
    canonical_json_bytes,
    compute_framed_digest,
)

SOURCE_ATTESTATION_FRAME = "stpa-omission-source-v1"
TRIGGER_DIGEST_FRAME = "stpa-omission-trigger-v1"
SHA256_PATTERN = r"^[0-9a-f]{64}$"
STIMULUS_ID_PATTERN = r"^STIM-\d+$"
TURN_ID_PATTERN = r"^T-\d+$"

# Hard bounds from the approved structured-evidence proposal
# (build/qualification/current-interface-followup-20260913/
# structured-evidence-proposal.md).  The limits bound an executable artifact;
# they are never permission to truncate an exact quotation.
MIN_EVIDENCE_ENTRIES = 1
MAX_EVIDENCE_ENTRIES = 4
MAX_TRIGGER_LENGTH = 256
MAX_QUOTE_LENGTH = 2048
MAX_MEANING_LENGTH = 512
MAX_PATH_SEGMENTS = 32
MAX_PATH_SEGMENT_LENGTH = 128
DIRECT_PROMPT_TURN_ORDINAL = 1
MAX_CONVERSATION_TURN_ORDINAL = 3
MAX_CARRIER_BYTES = 8192

# Canonical-byte reservation kept from the retired projection carrier, which
# wrapped a basis with 584 bytes of source pins and framing.  Keeping it keeps
# the set of accepted bases unchanged.
PINS_SERIALIZATION_ALLOWANCE = 584


class _ClosedFrozenModel(BaseModel):
    """Base for immutable closed wire records."""

    # Enum discriminators are canonical JSON strings.  Scalar fields below
    # use Strict* annotations so wire values are never coerced.
    model_config = ConfigDict(extra="forbid", frozen=True)


class OmissionSourceAttestation(_ClosedFrozenModel):
    """Producer-computed digest over one canonical selected source value.

    The attestation covers the canonical selected value only.  It does not
    identify the snapshot the value came from; the basis-level
    ``observation_snapshot_digest`` supplies that identity.
    """

    frame: Literal[SOURCE_ATTESTATION_FRAME] = SOURCE_ATTESTATION_FRAME
    digest: StrictStr = Field(pattern=SHA256_PATTERN)


class OmissionApplicability(_ClosedFrozenModel):
    """Code-owned applicability record; the basis cannot grant authority.

    ``unresolved`` and ``source_presence_only`` are the only v1 values.  A
    citation proves source presence; it never establishes that the reviewed
    obligation applies.
    """

    status: Literal["unresolved"]
    evidence_role: Literal["source_presence_only"]


class OmissionDelivery(_ClosedFrozenModel):
    """The one published stimulus route that stimulus citations resolve to."""

    stimulus_id: StrictStr = Field(pattern=STIMULUS_ID_PATTERN)
    delivery_class: Literal["direct_prompt", "conversation_context"]
    status: Literal["prepared"]
    prepared_user_text_digest: StrictStr | None = Field(
        default=None,
        pattern=SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="after")
    def validate_delivery(self) -> "OmissionDelivery":
        if self.delivery_class == "direct_prompt":
            if self.prepared_user_text_digest is None:
                raise ValueError(
                    "direct_prompt delivery requires prepared_user_text_digest"
                )
        elif self.prepared_user_text_digest is not None:
            raise ValueError(
                "conversation_context delivery must not carry prepared_user_text_digest"
            )
        return self


class StimulusOmissionEvidence(_ClosedFrozenModel):
    """One exact quotation copied from the published stimulus delivery."""

    source: Literal["stimulus"] = "stimulus"
    delivery_turn_ordinal: StrictInt = Field(ge=1)
    # Required only under conversation delivery; the basis validates the
    # coupling because a single entry cannot see the delivery class.
    turn_id: StrictStr | None = Field(
        default=None,
        pattern=TURN_ID_PATTERN,
        exclude_if=lambda value: value is None,
    )
    quote: StrictStr = Field(min_length=1, max_length=MAX_QUOTE_LENGTH)
    meaning: StrictStr | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_MEANING_LENGTH,
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="after")
    def validate_entry(self) -> "StimulusOmissionEvidence":
        _validate_non_blank(self.quote, "quote")
        if self.meaning is not None:
            _validate_non_blank(self.meaning, "meaning")
        return self


class StateFactOmissionEvidence(_ClosedFrozenModel):
    """One exact quotation copied from the observed target state."""

    source: Literal["state_fact"] = "state_fact"
    state_path: tuple[StrictStr, ...] = Field(
        min_length=1,
        max_length=MAX_PATH_SEGMENTS,
    )
    quote: StrictStr = Field(min_length=1, max_length=MAX_QUOTE_LENGTH)
    source_attestation: OmissionSourceAttestation
    meaning: StrictStr | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_MEANING_LENGTH,
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="after")
    def validate_entry(self) -> "StateFactOmissionEvidence":
        _validate_non_blank(self.quote, "quote")
        _validate_path_segments(self.state_path, "state_path")
        if self.meaning is not None:
            _validate_non_blank(self.meaning, "meaning")
        return self


class ObservationOmissionEvidence(_ClosedFrozenModel):
    """One exact quotation copied from a supplied policy observation."""

    source: Literal["observation"] = "observation"
    observation_ref: StrictStr = Field(min_length=1)
    observation_path: tuple[StrictStr, ...] | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_PATH_SEGMENTS,
        exclude_if=lambda value: value is None,
    )
    quote: StrictStr = Field(min_length=1, max_length=MAX_QUOTE_LENGTH)
    source_attestation: OmissionSourceAttestation
    meaning: StrictStr | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_MEANING_LENGTH,
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="after")
    def validate_entry(self) -> "ObservationOmissionEvidence":
        _validate_non_blank(self.quote, "quote")
        _validate_non_blank(self.observation_ref, "observation_ref")
        if self.observation_path is not None:
            _validate_path_segments(self.observation_path, "observation_path")
        if self.meaning is not None:
            _validate_non_blank(self.meaning, "meaning")
        return self


OmissionEvidenceEntry = Annotated[
    Union[
        StimulusOmissionEvidence,
        StateFactOmissionEvidence,
        ObservationOmissionEvidence,
    ],
    Field(discriminator="source"),
]


class OmissionEvidenceBasis(_ClosedFrozenModel):
    """Authoring-side omission evidence for one tool-absent outcome."""

    delivery: OmissionDelivery
    obligation_ref: StrictStr = Field(min_length=1)
    direction_authority: Literal["proposed", "reviewed"]
    trigger: StrictStr = Field(min_length=1, max_length=MAX_TRIGGER_LENGTH)
    trigger_digest: StrictStr = Field(pattern=SHA256_PATTERN)
    applicability: OmissionApplicability
    observation_snapshot_digest: StrictStr | None = Field(
        default=None,
        pattern=SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    evidence: tuple[OmissionEvidenceEntry, ...] = Field(
        min_length=MIN_EVIDENCE_ENTRIES,
        max_length=MAX_EVIDENCE_ENTRIES,
    )

    @model_validator(mode="after")
    def validate_basis(self) -> "OmissionEvidenceBasis":
        _validate_non_blank(self.trigger, "trigger")
        _validate_non_blank(self.obligation_ref, "obligation_ref")
        _check_trigger_binding(self.trigger, self.trigger_digest)
        _check_snapshot_coupling(self.observation_snapshot_digest, self.evidence)
        _check_delivery_coupling(self.delivery, self.evidence)
        _check_unique_locators(self.evidence)
        self._validate_basis_size()
        return self

    def _validate_basis_size(self) -> None:
        """Enforce the canonical size budget, including the pin reservation."""
        serialized = canonical_json_bytes(self.model_dump(mode="json"))
        if len(serialized) + PINS_SERIALIZATION_ALLOWANCE > MAX_CARRIER_BYTES:
            raise ValueError(
                "omission evidence basis exceeds the carrier budget: basis is "
                f"{len(serialized)} canonical bytes and the reserved source-pin "
                f"allowance is {PINS_SERIALIZATION_ALLOWANCE} of "
                f"{MAX_CARRIER_BYTES}"
            )


def _entry_locator(entry: OmissionEvidenceEntry) -> tuple[Any, ...]:
    """Return the hashable locator identity for one evidence entry."""
    if isinstance(entry, StimulusOmissionEvidence):
        return ("stimulus", entry.delivery_turn_ordinal, entry.turn_id)
    if isinstance(entry, StateFactOmissionEvidence):
        return ("state_fact", entry.state_path)
    return ("observation", entry.observation_ref, entry.observation_path)


def _check_trigger_binding(trigger: str, trigger_digest: str) -> None:
    """Require the recorded digest to match the canonical trigger text."""
    expected = compute_framed_digest(TRIGGER_DIGEST_FRAME, trigger)
    if trigger_digest != expected:
        raise ValueError("trigger_digest does not match carrier trigger")


def _check_snapshot_coupling(
    observation_snapshot_digest: str | None,
    evidence: tuple[OmissionEvidenceEntry, ...],
) -> None:
    """Require the snapshot digest exactly when state/observation is cited."""
    cites_snapshot = any(
        entry.source in ("state_fact", "observation") for entry in evidence
    )
    if cites_snapshot and observation_snapshot_digest is None:
        raise ValueError(
            "observation_snapshot_digest is required for state-fact or "
            "observation evidence"
        )
    if not cites_snapshot and observation_snapshot_digest is not None:
        raise ValueError(
            "observation_snapshot_digest is allowed only for state-fact or "
            "observation evidence"
        )


def _check_delivery_coupling(
    delivery: OmissionDelivery,
    evidence: tuple[OmissionEvidenceEntry, ...],
) -> None:
    """Bind stimulus entries to the selected delivery class."""
    for entry in evidence:
        if not isinstance(entry, StimulusOmissionEvidence):
            continue
        if delivery.delivery_class == "conversation_context":
            if entry.turn_id is None:
                raise ValueError(
                    "conversation delivery requires turn_id on every stimulus entry"
                )
            if entry.delivery_turn_ordinal > MAX_CONVERSATION_TURN_ORDINAL:
                raise ValueError(
                    "conversation stimulus entries cite turns one to three"
                )
        else:
            if entry.turn_id is not None:
                raise ValueError(
                    "direct_prompt stimulus entries must not carry turn_id"
                )
            if entry.delivery_turn_ordinal != DIRECT_PROMPT_TURN_ORDINAL:
                raise ValueError(
                    "direct_prompt stimulus entries must cite turn ordinal one"
                )


def _check_unique_locators(evidence: tuple[OmissionEvidenceEntry, ...]) -> None:
    """Reject two evidence entries that cite one locator."""
    seen: set[tuple[Any, ...]] = set()
    for entry in evidence:
        locator = _entry_locator(entry)
        if locator in seen:
            raise ValueError("evidence entries must carry unique locators")
        seen.add(locator)


def _validate_non_blank(value: str, field_name: str) -> None:
    if not value.strip():
        raise ValueError(f"{field_name} must not be blank")


def _validate_path_segments(path: tuple[str, ...], field_name: str) -> None:
    for segment in path:
        _validate_non_blank(segment, f"{field_name} segment")
        if len(segment) > MAX_PATH_SEGMENT_LENGTH:
            raise ValueError(
                f"{field_name} segments must be at most "
                f"{MAX_PATH_SEGMENT_LENGTH} characters"
            )


__all__ = [
    "DIRECT_PROMPT_TURN_ORDINAL",
    "MAX_CARRIER_BYTES",
    "MAX_CONVERSATION_TURN_ORDINAL",
    "MAX_EVIDENCE_ENTRIES",
    "MAX_MEANING_LENGTH",
    "MAX_PATH_SEGMENT_LENGTH",
    "MAX_PATH_SEGMENTS",
    "MAX_QUOTE_LENGTH",
    "MAX_TRIGGER_LENGTH",
    "MIN_EVIDENCE_ENTRIES",
    "PINS_SERIALIZATION_ALLOWANCE",
    "ObservationOmissionEvidence",
    "OmissionApplicability",
    "OmissionDelivery",
    "OmissionEvidenceBasis",
    "OmissionEvidenceEntry",
    "OmissionSourceAttestation",
    "SHA256_PATTERN",
    "SOURCE_ATTESTATION_FRAME",
    "STIMULUS_ID_PATTERN",
    "StateFactOmissionEvidence",
    "StimulusOmissionEvidence",
    "TRIGGER_DIGEST_FRAME",
    "TURN_ID_PATTERN",
]
