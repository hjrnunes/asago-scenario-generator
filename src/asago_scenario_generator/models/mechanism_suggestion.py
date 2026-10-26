"""Closed contracts for mechanism suggestions in ICA slot filling.

A mechanism suggestion is a library mechanism that the graph join proposed for
one slot and the mechanism verifier judged its path to carry.  Unlike an
obligation it carries no risk, makes no coverage claim, and never counts
toward obligation accounting.  Slot filling answers it with the outcomes an
obligation uses, recorded as a :class:`MechanismIcaConsideration`.
"""

from __future__ import annotations

from pydantic import Field, model_validator

from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    compute_framed_digest,
)
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationDiagnostic,
    IcaConsiderationDisposition,
    canonical_consideration_strings,
    validate_ica_consideration_disposition,
)
from asago_scenario_generator.stpa.mechanism_library import MechanismId

MECHANISM_SUGGESTION_ID_DOMAIN = "asago-scenario-generator:mechanism-suggestion:v1"
MECHANISM_CONSIDERATION_ID_DOMAIN = (
    "asago-scenario-generator:mechanism-ica-consideration:v1"
)
MECHANISM_SUGGESTION_ID_PREFIX = "msug:v1:"


class MechanismSuggestionPath(ClosedCanonicalModel):
    """One verified join path: the channel, the variable, and where it ends.

    ``end_id`` is the control action or coordination link that reads the
    variable.
    """

    feedback_channel_id: str = Field(min_length=1)
    process_model_part_id: str = Field(min_length=1)
    end_id: str = Field(min_length=1)


class MechanismSuggestion(ClosedCanonicalModel):
    """A verified mechanism suggestion for one ICA slot.

    ``paths`` are the join paths the verifier judged to carry the mechanism,
    in join order.  ``suggestion_id`` is derived from the other fields.
    """

    suggestion_id: str | None = None
    mechanism_id: MechanismId
    slot_id: str = Field(min_length=1)
    paths: tuple[MechanismSuggestionPath, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def identify(self) -> "MechanismSuggestion":
        payload = self.model_dump(mode="json", exclude={"suggestion_id"})
        expected = MECHANISM_SUGGESTION_ID_PREFIX + compute_framed_digest(
            MECHANISM_SUGGESTION_ID_DOMAIN, payload
        )
        if self.suggestion_id is not None and self.suggestion_id != expected:
            raise ValueError("suggestion_id does not match the mechanism suggestion")
        object.__setattr__(self, "suggestion_id", expected)
        return self


class MechanismIcaConsideration(ClosedCanonicalModel):
    """One mechanism suggestion's result on its slot.

    The fields and dispositions are those of an obligation/slot result,
    without the route and obligation: ``finding`` names the slot ICAs that
    express the mechanism, ``proposed_not_applicable`` attests a complete
    structural N/A, and ``unresolved`` retains no finding.
    """

    pair_id: str | None = None
    suggestion_id: str = Field(min_length=1)
    mechanism_id: MechanismId
    slot_id: str = Field(min_length=1)
    disposition: IcaConsiderationDisposition
    ica_ids: tuple[str, ...] = ()
    exec_candidate_ids: tuple[str, ...] = ()
    hazard_ids: tuple[str, ...] = ()
    constraint_ids: tuple[str, ...] = ()
    evidence: tuple[str, ...] = Field(min_length=1)
    model_call_refs: tuple[str, ...] = ()
    structural_inventory_complete: bool = False
    rationale: str | None = None
    diagnostics: tuple[ConsiderationDiagnostic, ...] = ()

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> "MechanismIcaConsideration":
        canonical_consideration_strings(self)
        payload = self.model_dump(mode="json", exclude={"pair_id"})
        expected = "mpair:v1:" + compute_framed_digest(
            MECHANISM_CONSIDERATION_ID_DOMAIN, payload
        )
        if self.pair_id is not None and self.pair_id != expected:
            raise ValueError("pair_id does not match mechanism/slot consideration")
        object.__setattr__(self, "pair_id", expected)
        validate_ica_consideration_disposition(self)
        return self


__all__ = [
    "MECHANISM_CONSIDERATION_ID_DOMAIN",
    "MECHANISM_SUGGESTION_ID_DOMAIN",
    "MechanismIcaConsideration",
    "MechanismSuggestion",
    "MechanismSuggestionPath",
]
