"""Per-constraint reach of the scenarios sent to authoring."""

from __future__ import annotations

from asago_scenario_generator.stpa.discriminating_condition import (
    DiscriminatingCondition,
)
from asago_scenario_generator.stpa.scenario_prod.deduplication import (
    build_constraint_reach,
    build_testability_summary,
    deduplicate_scenario_specs,
    scenario_constraint_ids,
)
from tests.helpers.discriminating_condition import _ownership_condition
from tests.helpers.scenario_deduplication import _scenario

OWNERSHIP = DiscriminatingCondition.model_validate(_ownership_condition())
AMOUNT = DiscriminatingCondition.model_validate(
    {
        "statement": "The requested refund amount exceeds the captured amount.",
        "comparisons": [
            {
                "kind": "value",
                "left": {
                    "source": "argument",
                    "operation": "refund_payment",
                    "argument": "amount",
                },
                "op": "gt",
                "right": {"source": "literal", "value": 250},
            }
        ],
        "record_selection": {
            "status": "unavailable",
            "reason": "The amount is chosen by the request, not by a record.",
        },
    }
)


def _spec(
    scenario_id: str,
    constraints: list[str],
    *,
    condition: DiscriminatingCondition | None = None,
    analytical: bool = False,
    operation_name: str | None = "refund_payment",
):
    return _scenario(
        scenario_id, analytical=analytical, operation_name=operation_name
    ).model_copy(
        update={
            "unsafe_outcome_constraint_refs": constraints,
            "discriminating_condition": condition,
        }
    )


def _reach(constraint_ids: list[str], specs: list) -> dict:
    return build_constraint_reach(
        constraint_ids, specs, deduplicate_scenario_specs(specs)
    )


def test_scenario_constraint_ids_reads_the_governing_constraints() -> None:
    assert scenario_constraint_ids(_spec("SCN-001", ["SC-2", "SC-1"])) == (
        "SC-1",
        "SC-2",
    )


def test_counts_sent_scenarios_with_and_without_a_condition() -> None:
    reach = _reach(
        ["SC-1"],
        [
            _spec("SCN-001", ["SC-1"], condition=OWNERSHIP),
            _spec("SCN-002", ["SC-1"], condition=AMOUNT),
            _spec("SCN-003", ["SC-1"]),
        ],
    )

    assert reach["constraints"]["SC-1"] == {
        "scenarios": 3,
        "sent": 3,
        "sent_with_condition": 2,
        "sent_without_condition": 1,
        "duplicate": 0,
        "analytical_only": 0,
    }
    assert reach["reach_0"] == []
    assert reach["reach_1"] == []


def test_a_duplicate_is_not_sent() -> None:
    reach = _reach(
        ["SC-1"],
        [
            _spec("SCN-001", ["SC-1"], condition=OWNERSHIP),
            _spec("SCN-002", ["SC-1"], condition=OWNERSHIP),
        ],
    )

    row = reach["constraints"]["SC-1"]
    assert (row["scenarios"], row["sent"], row["duplicate"]) == (2, 1, 1)
    assert row["sent_with_condition"] == 1
    assert reach["reach_1"] == ["SC-1"]


def test_a_constraint_with_only_analytical_scenarios_is_lost_to_them() -> None:
    reach = _reach(
        ["SC-1", "SC-2"],
        [
            _spec("SCN-001", ["SC-1"], analytical=True),
            _spec("SCN-002", ["SC-2"], analytical=True),
            _spec("SCN-003", ["SC-2"], condition=OWNERSHIP),
        ],
    )

    assert reach["constraints"]["SC-1"]["analytical_only"] == 1
    assert reach["lost_to_analytical_only"] == ["SC-1"]
    assert reach["reach_0"] == ["SC-1"]
    assert reach["reach_1"] == ["SC-2"]


def test_a_constraint_no_scenario_reaches_has_reach_zero_but_is_not_lost() -> None:
    reach = _reach(["SC-1", "SC-9"], [_spec("SCN-001", ["SC-1"], condition=OWNERSHIP)])

    assert reach["constraints"]["SC-9"]["scenarios"] == 0
    assert reach["reach_0"] == ["SC-9"]
    assert reach["lost_to_analytical_only"] == []


def test_a_scenario_without_a_condition_does_not_reach_a_constraint() -> None:
    reach = _reach(["SC-1"], [_spec("SCN-001", ["SC-1"])])

    assert reach["constraints"]["SC-1"]["sent_without_condition"] == 1
    assert reach["reach_0"] == ["SC-1"]


def test_a_scenario_counts_for_every_constraint_it_governs() -> None:
    reach = _reach(
        ["SC-1", "SC-2"],
        [_spec("SCN-001", ["SC-1", "SC-2"], condition=OWNERSHIP)],
    )

    assert reach["constraints"]["SC-1"]["sent_with_condition"] == 1
    assert reach["constraints"]["SC-2"]["sent_with_condition"] == 1


def test_constraints_outside_the_listed_ones_are_ignored() -> None:
    reach = _reach(["SC-1"], [_spec("SCN-001", ["SC-1", "RC-7"])])

    assert list(reach["constraints"]) == ["SC-1"]


def test_totals_count_the_constraints_at_each_reach() -> None:
    reach = _reach(
        ["SC-1", "SC-2", "SC-3"],
        [
            _spec("SCN-001", ["SC-1"], condition=OWNERSHIP),
            _spec("SCN-002", ["SC-1"], condition=AMOUNT),
            _spec(
                "SCN-003",
                ["SC-2"],
                condition=OWNERSHIP,
                operation_name="close_account",
            ),
        ],
    )

    assert reach["summary"] == {"constraints": 3, "reach_0": 1, "reach_1": 1}
    assert reach["reach_0"] == ["SC-3"]
    assert reach["reach_1"] == ["SC-2"]


def test_testability_summary_carries_the_reach_only_when_given() -> None:
    specs = [_spec("SCN-001", ["SC-1"], condition=OWNERSHIP)]
    records = deduplicate_scenario_specs(specs)

    assert "constraint_reach" not in build_testability_summary(records)
    summary = build_testability_summary(
        records, constraint_reach=build_constraint_reach(["SC-1"], specs, records)
    )
    assert summary["constraint_reach"]["constraints"]["SC-1"]["sent"] == 1
