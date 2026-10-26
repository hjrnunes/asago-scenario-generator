"""Synthesis stage that proposes, verifies, and caps mechanism suggestions.

The graph join proposes library mechanisms for the final slots, the mechanism
verifier gates each proposed path, and at most
``MECHANISM_SUGGESTIONS_PER_SLOT`` survivors per slot go to ICA filling.
Nothing is routed: a suggestion never enters a routing prompt and never
counts toward obligation coverage.  A structure the join proposes nothing
for sends no request, and every later stage then runs unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from asago_scenario_generator.models.mechanism_suggestion import MechanismSuggestion
from asago_scenario_generator.pipeline.synthesis_types import (
    StageRun,
    SynthesisAdapters,
)
from asago_scenario_generator.stpa.obligation_aware.mechanism_suggestions import (
    MechanismProposal,
    MechanismSelection,
    SuggestionVerdict,
    SuggestionVerificationRequest,
    propose_mechanism_suggestions,
    select_mechanism_suggestions,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    final_slot_universe,
)

MECHANISM_SUGGESTION_STAGE = "mechanism_suggestions"


@dataclass(frozen=True)
class MechanismSuggestionStage:
    """What the join proposed, what the verifier said, and what survived."""

    proposal: MechanismProposal = field(default_factory=MechanismProposal)
    verdicts: tuple[SuggestionVerdict, ...] = ()
    selection: MechanismSelection = field(default_factory=MechanismSelection)
    failure: str | None = None

    @property
    def survivors(self) -> tuple[MechanismSuggestion, ...]:
        """The verified suggestions within the cap, for ICA filling."""
        return self.selection.survivors

    @property
    def verified(self) -> bool:
        """Whether the verifier was asked about any proposal."""
        return bool(self.verdicts) or self.failure is not None


def _run_mechanism_suggestions(
    *,
    loss_analysis: Any,
    control_structure: Any,
    adapters: SynthesisAdapters,
) -> StageRun:
    """Propose suggestions for the final slots and keep the verified ones.

    An adapter without ``verify_mechanism_suggestions`` gates nothing, so it
    gets no suggestion.  A verifier failure is reported and leaves every
    proposal without a verdict; it never stops the run.
    """
    proposal = propose_mechanism_suggestions(
        control_structure, final_slot_universe(control_structure)
    )
    verify = getattr(adapters.obligation_adapter, "verify_mechanism_suggestions", None)
    if not proposal.proposed or verify is None:
        return StageRun(MechanismSuggestionStage(proposal))
    request = SuggestionVerificationRequest(
        candidates=proposal.candidates(),
        control_structure=control_structure,
        loss_analysis=loss_analysis,
    )
    try:
        verdicts = tuple(verify(request))
    except Exception as exc:  # noqa: BLE001 - an additive stage must not end the run
        stage = MechanismSuggestionStage(proposal, failure=str(exc))
        return StageRun(
            stage,
            diagnostics=(f"mechanism suggestion verification failed: {exc}",),
            calls=(MECHANISM_SUGGESTION_STAGE,),
        )
    stage = MechanismSuggestionStage(
        proposal, verdicts, select_mechanism_suggestions(proposal, verdicts)
    )
    return StageRun(stage, calls=(MECHANISM_SUGGESTION_STAGE,))


__all__ = [
    "MECHANISM_SUGGESTION_STAGE",
    "MechanismSuggestionStage",
]
