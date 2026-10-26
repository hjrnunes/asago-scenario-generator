"""Mechanism suggestion accounting: one stop reason per pair, apart from coverage."""

from __future__ import annotations

from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from asago_scenario_generator.models.mechanism_suggestion import (
    MechanismIcaConsideration,
)
from asago_scenario_generator.models.mechanism_suggestion_accounting import (
    MECHANISM_SUGGESTION_ACCOUNTING_FILENAME,
    STOP_REASONS,
    MechanismSuggestionAccounting,
)
from asago_scenario_generator.models.obligation_consideration import (
    SLOT_PROMPT_BUDGET_EXCEEDED,
    ConsiderationDiagnostic,
)
from asago_scenario_generator.pipeline.synthesis import run_synthesis
from asago_scenario_generator.pipeline.synthesis_mechanisms import (
    MechanismSuggestionStage,
    _mechanism_accounting,
    _run_mechanism_suggestions,
)
from asago_scenario_generator.pipeline.synthesis_types import SynthesisAdapters
from asago_scenario_generator.stpa.mechanism_library import (
    MechanismId,
    bundled_mechanism_library,
)
from asago_scenario_generator.stpa.obligation_aware.mechanism_suggestions import (
    MechanismProposal,
    ProposedSuggestion,
    SuggestionVerdict,
    select_mechanism_suggestions,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    SlotFillRunResult,
    final_slot_universe,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    SynthesisSlotFillResult,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    MechanismCandidate,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from tests.helpers.mechanism_suggestions import (
    ACTION_PATH,
    LINK_PATH,
    suggestion_structure,
)
from tests.helpers.obligation_aware import _control_structure, _loss_analysis
from tests.helpers.synthesis import _FakeAdapters, _inputs

_INCORRECT = "RESP-1:CA-1-1:INCORRECT"
_NOT_PROVIDED = "RESP-1:CA-1-1:NOT_PROVIDED"
_TIMING = "RESP-1:CA-1-1:WRONG_TIMING"
_LINK = "CL-1:CM-1:NOT_PROVIDED"


class _Verifier:
    def __init__(self, relationships: dict[tuple[str, tuple], str | None]) -> None:
        self.relationships = relationships

    def verify_mechanism_suggestions(self, request):
        return tuple(
            SuggestionVerdict(
                candidate,
                self.relationships.get(
                    (candidate.mechanism.value, candidate.path), "mechanism_specific"
                ),
                "r",
            )
            for candidate in request.candidates
        )


def _stage(relationships=None, structure=None) -> MechanismSuggestionStage:
    return _run_mechanism_suggestions(
        loss_analysis=_loss_analysis(),
        control_structure=structure or suggestion_structure(),
        adapters=SimpleNamespace(obligation_adapter=_Verifier(relationships or {})),
    ).value


def _result(stage, slot_id, mechanism="user_claim", **fields) -> Any:
    suggestion = next(
        item
        for item in stage.survivors
        if item.slot_id == slot_id and item.mechanism_id.value == mechanism
    )
    return MechanismIcaConsideration(
        suggestion_id=str(suggestion.suggestion_id),
        mechanism_id=suggestion.mechanism_id,
        slot_id=slot_id,
        evidence=("provider-structured-consideration",),
        **fields,
    )


def _rows(accounting) -> dict[tuple[str, str], Any]:
    return {(row.mechanism_id.value, row.slot_id): row for row in accounting.rows}


def test_every_mechanism_and_slot_pair_gets_one_row_and_the_summary_reconciles() -> (
    None
):
    stage = _stage()
    structure = suggestion_structure()

    accounting = _mechanism_accounting(stage, structure, ())

    slots = final_slot_universe(structure)
    mechanisms = bundled_mechanism_library().mechanisms
    assert len(accounting.rows) == len(slots) * len(mechanisms)
    assert accounting.summary.rows == len(accounting.rows)
    assert list(accounting.summary.stop_reasons) == list(STOP_REASONS)
    assert sum(accounting.summary.stop_reasons.values()) == len(accounting.rows)
    assert [row.mechanism_id for row in accounting.rows[: len(mechanisms)]] == [
        entry.id for entry in mechanisms
    ]


def test_each_stage_of_a_suggestion_has_its_stop_reason() -> None:
    stage = _stage({("user_claim", LINK_PATH): "adjacent_control"})
    results = (
        _result(
            stage,
            _INCORRECT,
            disposition="finding",
            ica_ids=("ICA-1",),
            exec_candidate_ids=("EXEC:RESP-1:CA-1-1:INCORRECT",),
            hazard_ids=("H-1",),
            constraint_ids=("SC-1",),
        ),
        _result(
            stage,
            _NOT_PROVIDED,
            disposition="proposed_not_applicable",
            structural_inventory_complete=True,
            rationale="The action has a complete structural guard.",
        ),
        _result(
            stage,
            _TIMING,
            disposition="unresolved",
            diagnostics=(
                ConsiderationDiagnostic(
                    code="ica_hazard_correction_exhausted", detail="excluded"
                ),
            ),
        ),
        _result(
            stage,
            _LINK,
            mechanism="delegated_authority",
            disposition="unresolved",
            diagnostics=(
                ConsiderationDiagnostic(code=SLOT_PROMPT_BUDGET_EXCEEDED, detail="x"),
            ),
        ),
    )

    rows = _rows(_mechanism_accounting(stage, suggestion_structure(), results))

    assert rows[("user_claim", _INCORRECT)].stop_reason == "finding"
    assert rows[("user_claim", _INCORRECT)].ica_ids == ("ICA-1",)
    assert rows[("user_claim", _NOT_PROVIDED)].stop_reason == "slot_fill_not_applicable"
    assert rows[("user_claim", _TIMING)].stop_reason == "ica_verifier_rejected"
    assert rows[("user_claim", _TIMING)].detail == "ica_hazard_correction_exhausted"
    assert rows[("delegated_authority", _LINK)].stop_reason == "prompt_budget_exceeded"
    assert rows[("user_claim", _LINK)].stop_reason == "verifier_rejected"
    assert rows[("user_claim", "RESP-1:CA-1-1:WRONG_DURATION")].stop_reason == (
        "slot_not_analyzed"
    )
    assert rows[("stale_history", _INCORRECT)].stop_reason == "not_proposed"
    assert rows[("delegated_authority", "CL-1:CM-1:INCORRECT")].stop_reason == (
        "slot_fill_unresolved"
    )


def test_insufficient_or_missing_verdicts_stop_as_unresolved_by_the_verifier() -> None:
    stage = _stage(
        {
            ("user_claim", ACTION_PATH): "insufficient_evidence",
            ("user_claim", LINK_PATH): None,
        }
    )

    rows = _rows(_mechanism_accounting(stage, suggestion_structure(), ()))

    action = rows[("user_claim", _INCORRECT)]
    link = rows[("user_claim", _LINK)]
    assert (action.stop_reason, link.stop_reason) == (
        "verifier_unresolved",
        "verifier_unresolved",
    )
    assert [item.relationship for item in link.path_verdicts] == ["no_verdict"]


def test_an_authority_filtered_pair_names_the_filter_reason() -> None:
    structure = suggestion_structure(authority="authoritative")
    verifier = _Verifier({})
    stage = MechanismSuggestionStage(
        _run_mechanism_suggestions(
            loss_analysis=_loss_analysis(),
            control_structure=structure,
            adapters=SimpleNamespace(obligation_adapter=verifier),
        ).value.proposal,
        failure="asked",
    )

    rows = _rows(_mechanism_accounting(stage, structure, ()))

    assert rows[("user_claim", _INCORRECT)].stop_reason == "authority_filtered"
    assert rows[("user_claim", _INCORRECT)].detail == "authoritative"


def test_a_verified_suggestion_past_the_cap_stops_over_the_cap() -> None:
    proposal = MechanismProposal(
        proposed=tuple(
            ProposedSuggestion(MechanismId(name), _INCORRECT, (ACTION_PATH,))
            for name in ("user_claim", "retrieved_instructions", "stale_history")
        )
    )
    verdicts = tuple(
        SuggestionVerdict(
            MechanismCandidate(item.mechanism, ACTION_PATH), "mechanism_specific", "r"
        )
        for item in proposal.proposed
    )
    stage = MechanismSuggestionStage(
        proposal, verdicts, select_mechanism_suggestions(proposal, verdicts)
    )

    rows = _rows(_mechanism_accounting(stage, suggestion_structure(), ()))

    assert rows[("stale_history", _INCORRECT)].stop_reason == "over_cap"
    assert rows[("user_claim", _INCORRECT)].stop_reason == "slot_fill_unresolved"


def test_no_record_exists_when_the_verifier_was_never_asked() -> None:
    stage = _stage(structure=_control_structure())

    assert _mechanism_accounting(stage, _control_structure(), ()) is None


def test_the_record_round_trips_through_its_yaml() -> None:
    accounting = _mechanism_accounting(_stage(), suggestion_structure(), ())

    assert MechanismSuggestionAccounting.from_yaml(accounting.to_yaml()) == accounting


# --- apart from obligation coverage ----------------------------------------


@dataclass
class _SuggestionFakes(_FakeAdapters):
    """Fake ports over a structure the join proposes suggestions for."""

    fill_kwargs: list[dict[str, Any]] | None = None
    account_kwargs: list[dict[str, Any]] | None = None

    def fill_icas(self, **kwargs) -> object:
        self.fill_kwargs.append(kwargs)
        pairs = tuple(
            MechanismIcaConsideration(
                suggestion_id=str(item.suggestion_id),
                mechanism_id=item.mechanism_id,
                slot_id=item.slot_id,
                disposition="unresolved",
                evidence=("provider-structured-consideration",),
                rationale="The supplied evidence cannot decide.",
            )
            for item in kwargs.get("mechanism_suggestions", ())
        )
        return SlotFillRunResult(
            result=SynthesisSlotFillResult(
                ica_enumeration=ICAEnumeration(slots=[]),
                mechanism_considerations=pairs,
            )
        )

    def account(self, **kwargs) -> object:
        self.account_kwargs.append(kwargs)
        return super().account(**kwargs)


def _synthesis(tmp_path, verifier) -> tuple[Any, _SuggestionFakes]:
    fakes = _SuggestionFakes(
        calls=[],
        control_structure=suggestion_structure(),
        fill_kwargs=[],
        account_kwargs=[],
    )
    adapters = replace(
        SynthesisAdapters.from_object(fakes), obligation_adapter=verifier
    )
    return run_synthesis(_inputs(tmp_path), adapters), fakes


def test_suggestions_never_reach_obligation_accounting(tmp_path) -> None:
    plain, plain_fakes = _synthesis(tmp_path / "plain", None)
    suggested, fakes = _synthesis(tmp_path / "suggested", _Verifier({}))

    assert "mechanism_suggestions" not in plain_fakes.fill_kwargs[0]
    assert fakes.fill_kwargs[0]["mechanism_suggestions"]
    (plain_account,) = plain_fakes.account_kwargs
    (account,) = fakes.account_kwargs
    assert set(account) == set(plain_account)
    assert account["ica_considerations"] == plain_account["ica_considerations"] == ()
    assert not any("mechanism" in name for name in account)
    for name in ("obligation-accounting.yaml", "obligation-consideration.yaml"):
        assert (tmp_path / "plain" / name).read_bytes() == (
            tmp_path / "suggested" / name
        ).read_bytes()


def test_the_record_is_published_only_when_the_verifier_was_asked(tmp_path) -> None:
    plain, _ = _synthesis(tmp_path / "plain", None)
    suggested, _ = _synthesis(tmp_path / "suggested", _Verifier({}))

    assert not (tmp_path / "plain" / MECHANISM_SUGGESTION_ACCOUNTING_FILENAME).exists()
    assert plain.mechanism_suggestion_accounting is None
    assert MECHANISM_SUGGESTION_ACCOUNTING_FILENAME not in plain.artifact_paths
    path = tmp_path / "suggested" / MECHANISM_SUGGESTION_ACCOUNTING_FILENAME
    assert suggested.artifact_paths[MECHANISM_SUGGESTION_ACCOUNTING_FILENAME] == path
    written = yaml.safe_load(path.read_text())
    counts = written["summary"]["stop_reasons"]
    assert counts["slot_fill_unresolved"] > 0
    assert counts["finding"] == 0
    assert suggested.mechanism_suggestion_accounting.summary.stop_reasons == counts


@pytest.mark.parametrize("reason", STOP_REASONS)
def test_every_stop_reason_is_documented(reason) -> None:
    from asago_scenario_generator.models import mechanism_suggestion_accounting

    assert f"``{reason}``" in mechanism_suggestion_accounting.__doc__
