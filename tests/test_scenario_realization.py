"""Public seam tests for scenario realization after ICA accounting."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccounting,
    ObligationAccountingRow,
    derive_obligation_accounting_summary,
)
from asago_scenario_generator.models.obligation_consideration import (
    ObligationIcaConsideration,
)
from asago_scenario_generator.models.scenario_realization import (
    ScenarioRealizationAssessment,
    ScenarioRealizationRecord,
    derive_scenario_realization_summary,
)
from asago_scenario_generator.pipeline.scenario_realization import (
    build_scenario_realization_assessment,
)
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _obligation_stop_reason_counts,
)
from asago_scenario_generator.pipeline.synthesis_scenarios import _run_realization
from asago_scenario_generator.report.synthesis import render_synthesis_report
from asago_scenario_generator.stpa.models.scenario_spec import (
    Adversary,
    AdversaryKind,
    ScenarioSpec,
)
from tests.helpers.governance import (
    _ICA_ID,
    _OBLIGATION_ID,
    _SLOT_ID,
    _accounting,
    _enumeration,
    _pair,
    _scenario,
)


def test_exact_obligation_context_produces_realized_record() -> None:
    result = build_scenario_realization_assessment(
        accounting=_accounting(),
        ica_considerations=(_pair(),),
        ica_enumeration=_enumeration(),
        scenario_specs=(_scenario(),),
        requested_ica_ids=(_ICA_ID,),
    )

    assert isinstance(result, ScenarioRealizationAssessment)
    assert result.summary.model_dump() == {
        "total": 1,
        "realized": 1,
        "unresolved": 0,
        "not_requested": 0,
    }
    assert result.records[0].status == "realized"
    assert result.records[0].scenario_ids == ("SCN-001",)
    assert result.records[0].context_digests == (
        _scenario().scenario_context.context_digest,
    )


def test_one_ica_with_family_siblings_maps_to_every_scenario() -> None:
    siblings = (_scenario(), _scenario(scenario_id="SCN-002"))
    result = build_scenario_realization_assessment(
        accounting=_accounting(),
        ica_considerations=(_pair(),),
        ica_enumeration=_enumeration(),
        scenario_specs=siblings,
        requested_ica_ids=(_ICA_ID,),
    )

    assert result.summary.realized == 1
    assert result.records[0].scenario_ids == ("SCN-001", "SCN-002")
    assert result.records[0].context_digests == tuple(
        item.scenario_context.context_digest for item in siblings
    )


def test_scenario_without_exact_obligation_context_is_unresolved() -> None:
    result = build_scenario_realization_assessment(
        accounting=_accounting(),
        ica_considerations=(_pair(),),
        ica_enumeration=_enumeration(),
        scenario_specs=(_scenario(include_obligation=False),),
        requested_ica_ids=(_ICA_ID,),
    )

    assert result.records[0].status == "unresolved"
    assert result.records[0].scenario_ids == ()


def test_unselected_ica_is_not_requested_not_unresolved() -> None:
    result = build_scenario_realization_assessment(
        accounting=_accounting(),
        ica_considerations=(_pair(),),
        ica_enumeration=_enumeration(),
        scenario_specs=(),
        requested_ica_ids=(),
    )

    assert result.records[0].status == "not_requested"
    assert result.summary.not_requested == 1


def test_partial_finding_for_unresolved_obligation_is_trace_only() -> None:
    unresolved_row = ObligationAccountingRow(
        obligation_id=_OBLIGATION_ID,
        disposition="unresolved",
        slot_ids=(_SLOT_ID,),
        route_refs=("route-1", "route-2"),
        evidence=("One routed slot produced a finding and another stayed unresolved.",),
    )
    accounting = ObligationAccounting(
        source_pins=_accounting().source_pins,
        rows=(unresolved_row,),
        summary=derive_obligation_accounting_summary((unresolved_row,)),
    )
    unresolved_pair = ObligationIcaConsideration(
        route_id="route-2",
        obligation_id=_OBLIGATION_ID,
        slot_id=_SLOT_ID,
        disposition="unresolved",
        evidence=("The second routed analysis could not resolve applicability.",),
    )

    result = build_scenario_realization_assessment(
        accounting=accounting,
        ica_considerations=(_pair(), unresolved_pair),
        ica_enumeration=_enumeration(),
        scenario_specs=(_scenario(),),
    )

    assert result.records == ()
    assert result.summary.model_dump() == {
        "total": 0,
        "realized": 0,
        "unresolved": 0,
        "not_requested": 0,
    }


def _record(**overrides: Any) -> ScenarioRealizationRecord:
    fields: dict[str, Any] = {
        "obligation_id": _OBLIGATION_ID,
        "consideration_pair_id": "pair-1",
        "route_id": "route-1",
        "slot_id": _SLOT_ID,
        "ica_id": _ICA_ID,
        "status": "unresolved",
        "stop_reason": "scenario_generation_failure",
        "scenario_ids": (),
        "context_digests": (),
        "evidence": ("evidence-a",),
    }
    fields.update(overrides)
    return ScenarioRealizationRecord(**fields)


def _realized(**overrides: Any) -> ScenarioRealizationRecord:
    fields: dict[str, Any] = {
        "status": "realized",
        "stop_reason": "scenario_realized",
        "scenario_ids": ("SCN-2", "SCN-1"),
        "context_digests": ("b" * 64, "a" * 64),
    }
    fields.update(overrides)
    return _record(**fields)


class TestScenarioRealizationRecordValidation:
    """The record canonicalizes its references and enforces status coherence."""

    def test_realized_record_sorts_pairs_and_evidence(self) -> None:
        record = _realized(evidence=("evidence-b", "evidence-a"))

        assert record.scenario_ids == ("SCN-1", "SCN-2")
        assert record.context_digests == ("a" * 64, "b" * 64)
        assert record.evidence == ("evidence-a", "evidence-b")

    def test_duplicate_evidence_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="evidence must contain unique"):
            _realized(evidence=("evidence-a", "evidence-a"))

    def test_record_id_is_derived_and_accepted_when_matching(self) -> None:
        derived = _realized()
        assert derived.record_id is not None
        assert derived.record_id.startswith("realization:v1:")

        again = _realized(record_id=derived.record_id)

        assert again.record_id == derived.record_id

    def test_record_id_must_match_content(self) -> None:
        with pytest.raises(ValidationError, match="record_id does not match"):
            _realized(record_id=f"realization:v1:{'0' * 64}")

    def test_scenario_ids_and_digests_must_stay_paired(self) -> None:
        with pytest.raises(ValidationError, match="must stay paired"):
            _realized(scenario_ids=("SCN-1", "SCN-2"), context_digests=("a" * 64,))

    def test_duplicate_references_are_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must be unique"):
            _realized(
                scenario_ids=("SCN-1", "SCN-1"),
                context_digests=("a" * 64, "a" * 64),
            )

    def test_realized_record_requires_references(self) -> None:
        with pytest.raises(ValidationError, match="require scenario IDs"):
            _realized(scenario_ids=(), context_digests=())

    def test_realized_record_requires_scenario_realized_reason(self) -> None:
        with pytest.raises(ValidationError, match="require scenario_realized"):
            _realized(stop_reason="scenario_generation_failure")

    @pytest.mark.parametrize(
        ("status", "stop_reason"),
        [
            ("unresolved", "scenario_generation_failure"),
            ("not_requested", "scenario_not_requested"),
        ],
    )
    def test_unrealized_record_cannot_claim_scenarios(
        self, status: str, stop_reason: str
    ) -> None:
        with pytest.raises(ValidationError, match="cannot claim realized"):
            _record(
                status=status,
                stop_reason=stop_reason,
                scenario_ids=("SCN-1",),
                context_digests=("a" * 64,),
            )

    def test_unresolved_record_requires_generation_failure_reason(self) -> None:
        with pytest.raises(
            ValidationError, match="require scenario_generation_failure"
        ):
            _record(status="unresolved", stop_reason="scenario_not_requested")

    def test_not_requested_record_requires_not_requested_reason(self) -> None:
        with pytest.raises(ValidationError, match="require scenario_not_requested"):
            _record(status="not_requested", stop_reason="scenario_generation_failure")

    def test_valid_unresolved_and_not_requested_records(self) -> None:
        unresolved = _record()
        not_requested = _record(
            status="not_requested", stop_reason="scenario_not_requested"
        )

        assert unresolved.scenario_ids == ()
        assert not_requested.scenario_ids == ()
        assert unresolved.record_id != not_requested.record_id


@pytest.mark.parametrize(
    ("pairs", "match"),
    [
        (
            (
                ObligationIcaConsideration.model_validate(
                    {
                        **_pair().model_dump(mode="json", exclude={"pair_id"}),
                        "obligation_id": f"ob:v1:{'2' * 64}",
                    }
                ),
            ),
            "finding consideration lacks accounting",
        ),
        ((), "addressed accounting and finding considerations do not reconcile"),
    ],
)
def test_findings_must_reconcile_with_addressed_accounting(pairs, match) -> None:
    with pytest.raises(ValueError, match=match):
        build_scenario_realization_assessment(
            accounting=_accounting(),
            ica_considerations=pairs,
            ica_enumeration=_enumeration(),
            scenario_specs=(_scenario(),),
        )


def _two_ica_inputs(pair_hazards: tuple[str, ...]):
    """One pair citing two ICAs of the slot that relate to different hazards."""
    second_id = f"{_SLOT_ID}:2"
    enumeration = _enumeration()
    slot = enumeration.slots[0]
    second = slot.icas[0].model_copy(
        update={
            "ica_id": second_id,
            "related_hazards": ["H-2"],
            "related_constraints": ["SC-2"],
        }
    )
    enumeration = enumeration.model_copy(
        update={"slots": [slot.model_copy(update={"icas": [*slot.icas, second]})]}
    )
    row = (
        _accounting()
        .rows[0]
        .model_copy(
            update={
                "ica_ids": (_ICA_ID, second_id),
                "hazard_ids": ("H-1", "H-2"),
                "constraint_ids": ("SC-1", "SC-2"),
            }
        )
    )
    accounting = ObligationAccounting(
        source_pins=_accounting().source_pins,
        rows=(row,),
        summary=derive_obligation_accounting_summary((row,)),
    )
    pair = ObligationIcaConsideration.model_validate(
        {
            **_pair().model_dump(mode="json", exclude={"pair_id"}),
            "ica_ids": [_ICA_ID, second_id],
            "hazard_ids": list(pair_hazards),
            "constraint_ids": ["SC-1", "SC-2"],
        }
    )
    return accounting, pair, enumeration


def test_a_finding_citing_icas_with_different_hazards_is_realized() -> None:
    accounting, pair, enumeration = _two_ica_inputs(("H-1", "H-2"))

    result = build_scenario_realization_assessment(
        accounting=accounting,
        ica_considerations=(pair,),
        ica_enumeration=enumeration,
        scenario_specs=(_scenario(),),
        requested_ica_ids=(_ICA_ID,),
    )

    assert result.summary.total == 2


def _functional(**overrides: Any) -> ScenarioSpec:
    """A scenario Stage 5 compiled as a functional test (no adversary gains)."""
    return _scenario(**overrides).model_copy(
        update={
            "adversary": Adversary(
                kind=AdversaryKind.none, gain="Nobody gains.", reaches_target_via=None
            )
        }
    )


def test_functional_test_candidate_is_not_a_generation_failure() -> None:
    functional = _functional(scenario_id="SCN-043")

    result = build_scenario_realization_assessment(
        accounting=_accounting(),
        ica_considerations=(_pair(),),
        ica_enumeration=_enumeration(),
        scenario_specs=(),
        functional_test_specs=(functional,),
        requested_ica_ids=(_ICA_ID,),
    )

    record = result.records[0]
    assert (record.status, record.stop_reason) == (
        "functional_test",
        "scenario_functional_test",
    )
    assert record.scenario_ids == ("SCN-043",)
    assert record.context_digests == (functional.scenario_context.context_digest,)
    assert result.summary.model_dump() == {
        "total": 1,
        "realized": 0,
        "unresolved": 0,
        "not_requested": 0,
        "functional_test": 1,
    }


def test_a_real_generation_failure_beside_a_functional_test_still_fails() -> None:
    accounting, pair, enumeration = _two_ica_inputs(("H-1", "H-2"))

    result = build_scenario_realization_assessment(
        accounting=accounting,
        ica_considerations=(pair,),
        ica_enumeration=enumeration,
        scenario_specs=(),
        functional_test_specs=(_functional(),),
    )

    outcomes = {item.ica_id: item.stop_reason for item in result.records}
    assert outcomes == {
        _ICA_ID: "scenario_functional_test",
        f"{_SLOT_ID}:2": "scenario_generation_failure",
    }
    assert (result.summary.functional_test, result.summary.unresolved) == (1, 1)


def test_an_adversarial_sibling_keeps_the_ica_realized() -> None:
    result = build_scenario_realization_assessment(
        accounting=_accounting(),
        ica_considerations=(_pair(),),
        ica_enumeration=_enumeration(),
        scenario_specs=(_scenario(),),
        functional_test_specs=(_functional(scenario_id="SCN-002"),),
        requested_ica_ids=(_ICA_ID,),
    )

    assert result.records[0].status == "realized"
    assert result.records[0].scenario_ids == ("SCN-001",)
    assert result.summary.functional_test == 0


def test_functional_test_without_the_obligation_context_is_still_a_failure() -> None:
    result = build_scenario_realization_assessment(
        accounting=_accounting(),
        ica_considerations=(_pair(),),
        ica_enumeration=_enumeration(),
        scenario_specs=(),
        functional_test_specs=(_functional(include_obligation=False),),
        requested_ica_ids=(_ICA_ID,),
    )

    assert result.records[0].stop_reason == "scenario_generation_failure"


def test_unselected_ica_is_not_requested_even_with_a_functional_test() -> None:
    result = build_scenario_realization_assessment(
        accounting=_accounting(),
        ica_considerations=(_pair(),),
        ica_enumeration=_enumeration(),
        scenario_specs=(),
        functional_test_specs=(_functional(),),
        requested_ica_ids=(),
    )

    assert result.records[0].status == "not_requested"


def test_scenario_ids_stay_unique_across_adversarial_and_functional_specs() -> None:
    with pytest.raises(ValueError, match="duplicate scenario IDs"):
        build_scenario_realization_assessment(
            accounting=_accounting(),
            ica_considerations=(_pair(),),
            ica_enumeration=_enumeration(),
            scenario_specs=(_scenario(),),
            functional_test_specs=(_functional(),),
        )


def test_functional_test_realization_round_trips_through_yaml() -> None:
    result = build_scenario_realization_assessment(
        accounting=_accounting(),
        ica_considerations=(_pair(),),
        ica_enumeration=_enumeration(),
        scenario_specs=(),
        functional_test_specs=(_functional(),),
    )

    assert ScenarioRealizationAssessment.from_yaml(result.to_yaml()) == result


def test_summary_without_functional_tests_serializes_as_before() -> None:
    summary = derive_scenario_realization_summary((_record(),))

    assert summary.functional_test == 0
    assert "functional_test" not in summary.model_dump()


class TestFunctionalTestRecordValidation:
    """A functional-test record carries its scenarios and its own stop reason."""

    def test_valid_record_sorts_pairs_like_a_realized_record(self) -> None:
        record = _realized(
            status="functional_test", stop_reason="scenario_functional_test"
        )

        assert record.scenario_ids == ("SCN-1", "SCN-2")

    def test_record_requires_references(self) -> None:
        with pytest.raises(ValidationError, match="require scenario IDs"):
            _record(status="functional_test", stop_reason="scenario_functional_test")

    def test_record_requires_its_stop_reason(self) -> None:
        with pytest.raises(ValidationError, match="require scenario_functional_test"):
            _realized(status="functional_test")

    def test_realized_status_rejects_the_functional_stop_reason(self) -> None:
        with pytest.raises(ValidationError, match="require scenario_realized"):
            _realized(stop_reason="scenario_functional_test")


def _realization_report(tmp_path: Path, **counts: int) -> str:
    """Render the report page for a realization with the given summary counts."""
    summary = derive_scenario_realization_summary(()).model_copy(update=counts)
    path = render_synthesis_report(
        tmp_path,
        manifest={},
        plan=None,
        consideration=None,
        accounting=None,
        realization=SimpleNamespace(summary=summary, records=()),
        scenario_result=None,
    )
    return path.read_text(encoding="utf-8")


def test_report_omits_a_zero_functional_test_row(tmp_path: Path) -> None:
    html = _realization_report(tmp_path, realized=2)

    assert "<tr><th>realized</th><td>2</td></tr>" in html
    assert "<th>functional_test</th>" not in html


def test_report_counts_functional_tests_apart_from_realized(tmp_path: Path) -> None:
    html = _realization_report(tmp_path, functional_test=22)

    assert "<tr><th>functional_test</th><td>22</td></tr>" in html
    assert "<tr><th>realized</th><td>0</td></tr>" in html


def _run_realization_stage(scenario_result: Any) -> dict[str, Any]:
    """Run the realization stage and return what the adapter received."""
    received: dict[str, Any] = {}

    def realize(**kwargs: Any) -> Any:
        received.update(kwargs)
        return SimpleNamespace()

    _run_realization(
        accounting=_accounting(),
        ica_enumeration=SimpleNamespace(
            ica_enumeration=_enumeration(),
            considerations=(),
            ica_hazard_verification=None,
        ),
        scenario_result=scenario_result,
        adapters=SimpleNamespace(realize=realize),
    )
    return received


def test_realization_stage_hands_the_functional_specs_to_the_adapter() -> None:
    functional = _functional()
    adversarial = _scenario(scenario_id="SCN-002")

    received = _run_realization_stage(
        SimpleNamespace(
            scenario_specs=[adversarial], functional_test_specs=[functional]
        )
    )

    assert received["scenario_specs"] == (adversarial,)
    assert received["functional_test_specs"] == (functional,)


def test_realization_stage_without_functional_specs_passes_an_empty_tuple() -> None:
    received = _run_realization_stage(SimpleNamespace(scenario_specs=[]))

    assert received["functional_test_specs"] == ()


def _terminal_reasons(realization: Any) -> dict[str, int]:
    """Count terminal reasons for one addressed obligation."""
    row = _accounting().rows[0].model_copy(update={"stop_reason": "addressed"})
    return _obligation_stop_reason_counts(SimpleNamespace(rows=(row,)), realization)


def _manifest_realization(*statuses: str) -> Any:
    """Realization records for one obligation, one per requested status."""
    by_status = {
        "realized": _realized(),
        "functional_test": _realized(
            status="functional_test", stop_reason="scenario_functional_test"
        ),
        "unresolved": _record(),
    }
    records = tuple(
        by_status[status].model_copy(update={"ica_id": f"ica-{index}"})
        for index, status in enumerate(statuses)
    )
    return SimpleNamespace(records=records)


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        (("functional_test",), "scenario_functional_test"),
        (("functional_test", "unresolved"), "scenario_functional_test"),
        (("functional_test", "realized"), "scenario_realized"),
        (("unresolved",), "scenario_generation_failure"),
    ],
)
def test_manifest_counts_one_terminal_reason_per_obligation(
    statuses: tuple[str, ...], expected: str
) -> None:
    assert _terminal_reasons(_manifest_realization(*statuses)) == {expected: 1}


@pytest.mark.parametrize("pair_hazards", [("H-1",), ("H-1", "H-2", "H-3")])
def test_finding_hazards_must_be_the_union_of_its_icas_hazards(pair_hazards) -> None:
    accounting, pair, enumeration = _two_ica_inputs(pair_hazards)

    with pytest.raises(ValueError, match="hazards do not match"):
        build_scenario_realization_assessment(
            accounting=accounting,
            ica_considerations=(pair,),
            ica_enumeration=enumeration,
            scenario_specs=(_scenario(),),
        )
