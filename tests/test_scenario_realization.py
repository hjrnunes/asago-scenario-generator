"""Public seam tests for scenario realization after ICA accounting."""

from __future__ import annotations

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
)
from asago_scenario_generator.pipeline.scenario_realization import (
    build_scenario_realization_assessment,
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
