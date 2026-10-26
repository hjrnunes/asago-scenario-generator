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

from asago_scenario_generator.models.mechanism_suggestion import (
    MechanismIcaConsideration,
    MechanismSuggestion,
    MechanismSuggestionPath,
)
from asago_scenario_generator.models.mechanism_suggestion_accounting import (
    MechanismPathVerdict,
    MechanismSuggestionAccounting,
    MechanismSuggestionRow,
    summarize_mechanism_rows,
)
from asago_scenario_generator.models.obligation_consideration import (
    SLOT_PROMPT_BUDGET_EXCEEDED,
)
from asago_scenario_generator.stpa.mechanism_library import bundled_mechanism_library
from asago_scenario_generator.pipeline.synthesis_types import (
    StageRun,
    SynthesisAdapters,
)
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    ICA_VERIFICATION_EXCLUSION_CODES,
)
from asago_scenario_generator.stpa.obligation_aware.mechanism_suggestions import (
    MechanismPath,
    MechanismProposal,
    MechanismSelection,
    SuggestionVerdict,
    SuggestionVerificationRequest,
    ProposedSuggestion,
    propose_mechanism_suggestions,
    select_mechanism_suggestions,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    MechanismCandidate,
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


def _mechanism_accounting(
    stage: MechanismSuggestionStage,
    control_structure: Any,
    considerations: tuple[MechanismIcaConsideration, ...],
) -> MechanismSuggestionAccounting | None:
    """Give every ``(mechanism, slot)`` pair one row; ``None`` if nothing was asked.

    *considerations* are the slot results after the independent ICA verifier.
    A run whose verifier was never asked writes no record, so a run without
    suggestions publishes exactly what it did before.
    """
    if not stage.verified:
        return None
    builder = _RowBuilder(stage, considerations)
    rows = tuple(
        builder.row(entry.id, slot.slot_id)
        for slot in final_slot_universe(control_structure)
        for entry in bundled_mechanism_library().mechanisms
    )
    return MechanismSuggestionAccounting(
        rows=rows, summary=summarize_mechanism_rows(rows)
    )


def _suggestion_path(path: MechanismPath) -> MechanismSuggestionPath:
    return MechanismSuggestionPath(
        feedback_channel_id=path[0], process_model_part_id=path[1], end_id=path[2]
    )


class _RowBuilder:
    """Decide each pair's stop reason from the stage's and the fill's records."""

    def __init__(
        self,
        stage: MechanismSuggestionStage,
        considerations: tuple[MechanismIcaConsideration, ...],
    ) -> None:
        self.stage = stage
        self.proposed = {
            (item.mechanism, item.slot_id): item for item in stage.proposal.proposed
        }
        self.structural = {
            (item.mechanism, item.slot_id) for item in stage.proposal.structural
        }
        self.verdicts = {item.candidate: item for item in stage.verdicts}
        selection = stage.selection
        self.survivors = {
            (item.mechanism_id, item.slot_id): item for item in selection.survivors
        }
        self.over_cap = {
            (item.mechanism_id, item.slot_id): item for item in selection.over_cap
        }
        self.results = {item.suggestion_id: item for item in considerations}

    def row(self, mechanism: Any, slot_id: str) -> MechanismSuggestionRow:
        key = (mechanism, slot_id)
        proposal = self.proposed.get(key)
        if proposal is not None:
            return self._proposed_row(proposal)
        if key in self.structural:
            return MechanismSuggestionRow(
                mechanism_id=mechanism, slot_id=slot_id, stop_reason="slot_not_analyzed"
            )
        reasons = self.stage.proposal.filtered.get(key)
        if reasons:
            return MechanismSuggestionRow(
                mechanism_id=mechanism,
                slot_id=slot_id,
                stop_reason="authority_filtered",
                detail=", ".join(reason.value for reason in reasons),
            )
        return MechanismSuggestionRow(
            mechanism_id=mechanism, slot_id=slot_id, stop_reason="not_proposed"
        )

    def _path_verdicts(
        self, proposal: ProposedSuggestion
    ) -> tuple[MechanismPathVerdict, ...]:
        values = []
        for path in proposal.paths:
            verdict = self.verdicts.get(MechanismCandidate(proposal.mechanism, path))
            values.append(
                MechanismPathVerdict(
                    path=_suggestion_path(path),
                    relationship=(
                        "no_verdict"
                        if verdict is None or verdict.relationship is None
                        else verdict.relationship
                    ),
                    rationale=(
                        self.stage.failure or "the verifier was not asked"
                        if verdict is None
                        else verdict.rationale
                    ),
                )
            )
        return tuple(values)

    def _proposed_row(self, proposal: ProposedSuggestion) -> MechanismSuggestionRow:
        key = (proposal.mechanism, proposal.slot_id)
        verdicts = self._path_verdicts(proposal)
        base = {
            "mechanism_id": proposal.mechanism,
            "slot_id": proposal.slot_id,
            "path_verdicts": verdicts,
        }
        relationships = {item.relationship for item in verdicts}
        if "mechanism_specific" not in relationships:
            reason = (
                "verifier_rejected"
                if relationships == {"adjacent_control"}
                else "verifier_unresolved"
            )
            return MechanismSuggestionRow(**base, stop_reason=reason)
        if key in self.over_cap:
            return MechanismSuggestionRow(
                **base,
                stop_reason="over_cap",
                suggestion_id=self.over_cap[key].suggestion_id,
            )
        suggestion = self.survivors[key]
        return self._slot_result_row(base, suggestion)

    def _slot_result_row(
        self, base: dict[str, Any], suggestion: MechanismSuggestion
    ) -> MechanismSuggestionRow:
        base = {**base, "suggestion_id": suggestion.suggestion_id}
        result = self.results.get(str(suggestion.suggestion_id))
        if result is None:
            return MechanismSuggestionRow(
                **base,
                stop_reason="slot_fill_unresolved",
                detail="slot filling returned no result for the suggestion",
            )
        codes = [item.code for item in result.diagnostics]
        excluded = [code for code in codes if code in ICA_VERIFICATION_EXCLUSION_CODES]
        if result.disposition == "finding":
            return MechanismSuggestionRow(
                **base, stop_reason="finding", ica_ids=result.ica_ids
            )
        if excluded:
            return MechanismSuggestionRow(
                **base, stop_reason="ica_verifier_rejected", detail=excluded[-1]
            )
        if result.disposition == "proposed_not_applicable":
            return MechanismSuggestionRow(
                **base, stop_reason="slot_fill_not_applicable", detail=result.rationale
            )
        if SLOT_PROMPT_BUDGET_EXCEEDED in codes:
            return MechanismSuggestionRow(
                **base, stop_reason="prompt_budget_exceeded", detail=codes[-1]
            )
        return MechanismSuggestionRow(
            **base,
            stop_reason="slot_fill_unresolved",
            detail=codes[-1] if codes else result.rationale,
        )


__all__ = [
    "MECHANISM_SUGGESTION_STAGE",
    "MechanismSuggestionStage",
]
