"""Process-model variables, context tables, and feedback trust."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.control_structure import (
    MAX_CONTEXT_ROWS_PER_ACTION,
    ControlAction,
    ControlStructure,
    ControlledProcess,
    ElementRef,
    FeedbackChannel,
    FeedbackSourceKind,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    control_action_context_rows,
    control_action_context_table,
    control_structure_context_tables,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    _finding_context,
)
from asago_scenario_generator.stpa.system_model.critic import (
    _carry_forward_context,
)

_TARGET = ElementRef(type=ReferenceType.controlled_process, id="CP-1")


def _responsibility(
    resp_id: str,
    *,
    pm_values: dict[str, list[str]],
    refs: list[str],
    source_kind: FeedbackSourceKind | None = None,
) -> Responsibility:
    number = resp_id.removeprefix("RESP-")
    return Responsibility(
        resp_id=resp_id,
        description="Move pallets",
        process_model_parts=[
            ProcessModelPart(pm_id=pm_id, description=pm_id, values=values)
            for pm_id, values in pm_values.items()
        ],
        control_actions=[
            ControlAction(
                ca_id=f"CA-{number}-1",
                description="Lift a pallet",
                target=_TARGET,
                operation="lift_pallet",
                process_model_refs=refs,
            )
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id=f"FB-{number}-1",
                description="Operator request",
                updates=next(iter(pm_values)),
                source=_TARGET,
                source_kind=source_kind,
            )
        ],
    )


def _structure(*responsibilities: Responsibility) -> ControlStructure:
    return ControlStructure(
        controlled_processes=[ControlledProcess(cp_id="CP-1", description="Forklift")],
        responsibilities=list(responsibilities),
    )


def test_context_rows_are_the_ordered_product_of_referenced_values() -> None:
    structure = _structure(
        _responsibility(
            "RESP-1",
            pm_values={
                "PM-1-1": ["clear", "occupied"],
                "PM-1-2": ["rated", "overweight"],
                "PM-1-3": [],
            },
            refs=["PM-1-1", "PM-1-2", "PM-1-3"],
        )
    )

    rows = control_action_context_rows(structure, "CA-1-1")

    assert [row.row_id for row in rows] == [f"CA-1-1:ctx-{n}" for n in range(1, 5)]
    assert rows[0].assignments == (("PM-1-1", "clear"), ("PM-1-2", "rated"))
    assert rows[3].assignments == (("PM-1-1", "occupied"), ("PM-1-2", "overweight"))


def _table_structure(pm_values: dict[str, list[str]], refs=None) -> ControlStructure:
    return _structure(
        _responsibility("RESP-1", pm_values=pm_values, refs=list(refs or pm_values))
    )


def _shown_values(rows) -> set[tuple[str, str]]:
    return {pair for row in rows for pair in row.assignments}


def _shown_pairs(rows) -> set[frozenset[tuple[str, str]]]:
    return {
        frozenset((left, right))
        for row in rows
        for index, left in enumerate(row.assignments)
        for right in row.assignments[index + 1 :]
    }


def test_context_rows_are_absent_without_values() -> None:
    bare = _structure(
        _responsibility("RESP-1", pm_values={"PM-1-1": []}, refs=["PM-1-1"])
    )

    assert control_action_context_rows(bare, "CA-1-1") == ()
    assert control_action_context_rows(bare, "CA-9-9") == ()
    assert control_action_context_table(bare, "CA-1-1") is None


def test_cut_table_shows_every_value_within_the_budget() -> None:
    structure = _table_structure({"PM-1-1": list("abcd"), "PM-1-2": list("wxyz")})

    rows = control_action_context_rows(structure, "CA-1-1")

    assert len(rows) == MAX_CONTEXT_ROWS_PER_ACTION
    assert len({row.assignments for row in rows}) == len(rows)
    assert _shown_values(rows) == {
        *(("PM-1-1", value) for value in "abcd"),
        *(("PM-1-2", value) for value in "wxyz"),
    }


@pytest.mark.parametrize(
    "sizes",
    [(2, 2, 2, 2), (2, 2, 2, 2, 2), (1, 1, 2, 2, 4), (1, 3, 3, 3), (12, 2)],
)
def test_cut_table_rows_are_distinct_and_show_every_value(sizes) -> None:
    values = {
        f"PM-1-{n}": [f"state {i}" for i in range(size)]
        for n, size in enumerate(sizes, start=1)
    }

    rows = control_action_context_rows(_table_structure(values), "CA-1-1")

    assert len(rows) == MAX_CONTEXT_ROWS_PER_ACTION
    assert len({row.row_id for row in rows}) == len(rows)
    assert len({row.assignments for row in rows}) == len(rows)
    assert _shown_values(rows) == {
        (pm_id, value) for pm_id, items in values.items() for value in items
    }


def test_cut_table_spends_spare_rows_on_uncovered_value_pairs() -> None:
    values = {
        pm_id: ["one", "two", "three"] for pm_id in ("PM-1-1", "PM-1-2", "PM-1-3")
    }
    structure = _table_structure(values)

    rows = control_action_context_rows(structure, "CA-1-1")

    assert len(rows) == MAX_CONTEXT_ROWS_PER_ACTION
    # 27 value pairs: the first-12 cut showed only 19 of them.
    assert len(_shown_pairs(rows)) == 27


def test_cut_table_row_ids_are_positions_in_the_full_product() -> None:
    values = {"PM-1-1": list("abc"), "PM-1-2": list("pqr"), "PM-1-3": list("xyz")}
    structure = _table_structure(values)

    rows = control_action_context_rows(structure, "CA-1-1")

    positions = []
    for row in rows:
        position = 0
        for pm_id, value in row.assignments:
            position = position * 3 + values[pm_id].index(value)
        positions.append(position + 1)
        assert row.row_id == f"CA-1-1:ctx-{position + 1}"
        assert [pm_id for pm_id, _ in row.assignments] == list(values)
    assert positions == sorted(positions)


def test_cut_table_selection_is_repeatable_and_ignores_reference_order() -> None:
    values = {
        "PM-1-1": ["clear", "occupied"],
        "PM-1-2": ["rated", "overweight", "unknown"],
        "PM-1-3": ["day", "night", "dusk", "dawn"],
    }
    forward = _table_structure(values)
    backward = _table_structure(values, refs=reversed(list(values)))

    def contexts(structure):
        return {
            frozenset(row.assignments)
            for row in control_action_context_rows(structure, "CA-1-1")
        }

    assert control_action_context_rows(forward, "CA-1-1") == (
        control_action_context_rows(forward, "CA-1-1")
    )
    assert contexts(forward) == contexts(backward)


def test_large_table_is_selected_without_enumerating_the_product() -> None:
    sizes = {f"PM-1-{n}": 3 for n in range(1, 6)} | {"PM-1-6": 10}
    values = {
        pm_id: [f"{pm_id} v{i}" for i in range(size)] for pm_id, size in sizes.items()
    }
    # 15 ten-valued variables: 10**15 combinations, beyond any enumeration.
    huge = {f"PM-1-{n}": [f"v{i}" for i in range(10)] for n in range(1, 16)}

    table = control_action_context_table(_table_structure(values), "CA-1-1")
    huge_table = control_action_context_table(_table_structure(huge), "CA-1-1")

    assert table is not None and huge_table is not None
    assert table.combinations == 2430
    assert len(table.rows) == MAX_CONTEXT_ROWS_PER_ACTION
    assert table.hidden_values == ()
    assert _shown_values(table.rows) == {
        (pm_id, value) for pm_id, items in values.items() for value in items
    }
    assert huge_table.combinations == 10**15
    assert len(huge_table.rows) == MAX_CONTEXT_ROWS_PER_ACTION
    assert huge_table.hidden_values == ()


def test_table_records_values_a_variable_has_beyond_the_budget() -> None:
    many = [f"state {n}" for n in range(1, 16)]
    structure = _table_structure({"PM-1-1": many, "PM-1-2": ["on", "off"]})

    table = control_action_context_table(structure, "CA-1-1")

    assert table is not None
    assert table.combinations == 30
    assert len(table.rows) == MAX_CONTEXT_ROWS_PER_ACTION
    assert {("PM-1-2", "on"), ("PM-1-2", "off")} <= _shown_values(table.rows)
    assert len(table.hidden_values) == len(many) - MAX_CONTEXT_ROWS_PER_ACTION
    assert set(table.hidden_values).isdisjoint(_shown_values(table.rows))
    assert {pm_id for pm_id, _ in table.hidden_values} == {"PM-1-1"}


def test_structure_lists_only_the_actions_that_have_a_table() -> None:
    structure = _structure(
        _responsibility("RESP-1", pm_values={"PM-1-1": []}, refs=["PM-1-1"]),
        _responsibility("RESP-2", pm_values={"PM-2-1": ["a", "b"]}, refs=["PM-2-1"]),
    )

    tables = control_structure_context_tables(structure)

    assert [table.control_action for table in tables] == ["CA-2-1"]
    assert tables[0].combinations == 2


def test_small_table_is_the_whole_product_with_nothing_hidden() -> None:
    structure = _table_structure({"PM-1-1": ["clear", "occupied"]})

    table = control_action_context_table(structure, "CA-1-1")

    assert table is not None
    assert table.combinations == 2
    assert table.rows == control_action_context_rows(structure, "CA-1-1")
    assert table.hidden_values == ()


def test_action_may_reference_only_its_own_controllers_variables() -> None:
    with pytest.raises(ValidationError, match="PM-2-1"):
        _structure(
            _responsibility("RESP-1", pm_values={"PM-1-1": ["a"]}, refs=["PM-2-1"]),
            _responsibility("RESP-2", pm_values={"PM-2-1": ["b"]}, refs=[]),
        )


def test_empty_context_fields_are_omitted_from_serialized_structure() -> None:
    structure = _structure(
        Responsibility(
            resp_id="RESP-1",
            description="Move pallets",
            process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="Bay")],
            control_actions=[
                ControlAction(ca_id="CA-1-1", description="Lift", target=_TARGET)
            ],
        )
    )

    dumped = structure.model_dump(mode="json")

    resp = dumped["responsibilities"][0]
    assert "values" not in resp["process_model_parts"][0]
    assert "evidence_refs" not in resp["process_model_parts"][0]
    assert "operation" not in resp["control_actions"][0]
    assert "process_model_refs" not in resp["control_actions"][0]


@pytest.mark.parametrize(
    ("kind", "untrusted"),
    [
        (FeedbackSourceKind.user_message, True),
        (FeedbackSourceKind.conversation_history, True),
        (FeedbackSourceKind.retrieved_content, True),
        (FeedbackSourceKind.operation_result, False),
        (FeedbackSourceKind.session_context, False),
        (None, False),
    ],
)
def test_feedback_trust_follows_its_source_kind(
    kind: FeedbackSourceKind | None, untrusted: bool
) -> None:
    resp = _responsibility(
        "RESP-1", pm_values={"PM-1-1": []}, refs=[], source_kind=kind
    )

    assert resp.feedback_channels[0].untrusted is untrusted


def test_revision_keeps_context_fields_a_restatement_omits() -> None:
    original = _responsibility(
        "RESP-1",
        pm_values={"PM-1-1": ["clear", "occupied"]},
        refs=["PM-1-1"],
        source_kind=FeedbackSourceKind.user_message,
    )
    original.process_model_parts[0].evidence_refs = ["state:bays.status"]
    revised = Responsibility(
        resp_id="RESP-1",
        description="Move pallets safely",
        process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="Bay")],
        control_actions=[
            ControlAction(ca_id="CA-1-1", description="Lift", target=_TARGET)
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-1-1", description="Request", updates="PM-1-1", source=_TARGET
            )
        ],
    )

    _carry_forward_context(original, revised)

    assert revised.process_model_parts[0].values == ["clear", "occupied"]
    assert revised.process_model_parts[0].evidence_refs == ["state:bays.status"]
    assert revised.control_actions[0].operation == "lift_pallet"
    assert revised.control_actions[0].process_model_refs == ["PM-1-1"]
    assert revised.feedback_channels[0].source_kind is FeedbackSourceKind.user_message


def test_finding_must_cite_a_row_of_its_own_action() -> None:
    structure = _structure(
        _responsibility(
            "RESP-1", pm_values={"PM-1-1": ["clear", "occupied"]}, refs=["PM-1-1"]
        ),
        _responsibility("RESP-2", pm_values={"PM-2-1": ["a"]}, refs=["PM-2-1"]),
    )
    slot = SimpleNamespace(control_action="CA-1-1")

    context = _finding_context(
        SimpleNamespace(context_row="CA-1-1:ctx-2"),
        slot=slot,
        control_structure=structure,
    )

    assert context == {"PM-1-1": "occupied"}
    assert (
        _finding_context(
            SimpleNamespace(context_row=None), slot=slot, control_structure=structure
        )
        is None
    )
    with pytest.raises(ValueError, match="CA-2-1:ctx-1"):
        _finding_context(
            SimpleNamespace(context_row="CA-2-1:ctx-1"),
            slot=slot,
            control_structure=structure,
        )
