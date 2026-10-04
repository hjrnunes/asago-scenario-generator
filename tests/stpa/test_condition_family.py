"""Tests for generic condition-family hints and their Stage 5 fan-out."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass

import pytest
import yaml

from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
    TargetOperationRecord,
    TargetOperationReference,
    TargetRealizationDisposition,
    TargetRealizationResult,
    TargetRealizationRow,
    TargetRealizationSummary,
)
from asago_scenario_generator.stpa.discriminating_condition import (
    DiscriminatingCondition,
)
from asago_scenario_generator.stpa.infra.prompt_preflight import (
    estimate_prompt_tokens,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.observation_contract import (
    default_observation_contract,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    _scenario_semantics_payload_type,
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.condition_check import (
    target_observation_fact_values,
)
from asago_scenario_generator.stpa.scenario_prod.condition_family import (
    CandidateFamilyPlan,
    ConditionFamily,
    FamilyCandidate,
    _bind_arguments,
    _prefix_domain,
    _schema_types,
    derive_condition_families,
    expand_family_candidates,
    family_honoured,
    plan_family_candidates,
)
from asago_scenario_generator.stpa.scenario_prod.condition_index import StateIndex
from asago_scenario_generator.stpa.scenario_prod.deduplication import (
    deduplicate_scenario_specs,
)
from asago_scenario_generator.stpa.scenario_prod.run import (
    _candidate_outcome_builders,
    _select_scenario_context,
    _write_condition_families,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservation,
    TargetObservationSnapshot,
)

from .condition_prompt_fixture import realistic_observations, realistic_profile
from .test_discriminating_condition import STAGE5_PROMPT_TOKEN_BUDGET
from .test_normal_authoring_wire import PROMPTS_DIR, _wrong_timing_context
from .test_scenario_deduplication import _scenario

# --- synthetic widget/owner target -----------------------------------------


def _state() -> dict:
    return {
        "authenticated_owner_id": "OW-1",
        "session_token": "tok",
        "widgets": {
            "W-1": {
                "owner_id": "OW-1",
                "locked": False,
                "price": 10.0,
                "stage": "draft",
                "label": "Blue thing",
            },
            "W-2": {
                "owner_id": "OW-2",
                "locked": True,
                "price": 20.0,
                "stage": "draft",
                "label": "Red thing",
            },
            "W-3": {
                "owner_id": "OW-1",
                "locked": False,
                "price": 30.0,
                "stage": "final",
                "label": "Green thing",
            },
        },
        "slots": {
            "SL-1": {"widget_id": "W-1", "capacity": 5},
            "SL-2": {"widget_id": "W-2", "capacity": 7},
        },
        "events": [],
    }


def _index(state: dict) -> StateIndex:
    snapshot = TargetObservationSnapshot.create(
        target_profile_digest="d" * 64,
        observations=(
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content=json.dumps(state),
            ),
        ),
    )
    return StateIndex.from_fact_values(target_observation_fact_values(snapshot))


def _op(
    name: str,
    arguments: dict[str, str],
    *,
    effect: str = "update",
    state_changing: bool = True,
) -> TargetOperationObservation:
    return TargetOperationObservation(
        reference=TargetOperationReference(
            resource_id=f"resource:{name}", operation_id=name
        ),
        input_schema={
            "type": "object",
            "properties": {arg: {"type": kind} for arg, kind in arguments.items()},
        },
        effect=effect,
        state_changing=state_changing,
    )


EDIT = _op("edit_widget", {"widget_id": "string", "price": "number"})
READ = _op("read_widget", {"widget_id": "string"}, effect="read", state_changing=False)
BOOK = _op("book_slot", {"slot_id": "string"})
NOTE = _op("write_note", {"owner_id": "string", "text": "string"})
OPS = (EDIT, READ, BOOK, NOTE)


def _families(operation, state=None, operations=OPS):
    return derive_condition_families(
        operation, operations, _index(state if state is not None else _state())
    )


def _kind(families, kind):
    return [family for family in families if family.kind == kind]


# --- ownership --------------------------------------------------------------


def test_keyed_ownership_lists_records_owned_by_another_subject() -> None:
    (family,) = _kind(_families(EDIT), "ownership")
    assert family.argument == "widget_id"
    assert family.argument_role == "record_key"
    assert family.binding == "field_name"
    assert family.collection == "widgets"
    assert family.field_paths == ("TARGET-STATE.widgets.<record_key>.owner_id",)
    assert family.candidates == (
        FamilyCandidate('"OW-2"', ("TARGET-STATE.widgets.W-2",)),
    )
    assert family.session_path == "TARGET-STATE.authenticated_owner_id"


def test_one_hop_ownership_follows_a_forward_link() -> None:
    (family,) = _kind(_families(BOOK), "ownership")
    assert family.argument == "slot_id"
    assert family.binding == "inferred_prefix"
    assert family.collection == "slots"
    assert family.field_paths == (
        "TARGET-STATE.slots.<record_key>.widget_id",
        "TARGET-STATE.widgets.<record_key>.owner_id",
    )
    assert family.candidate_record_paths == ("TARGET-STATE.slots.SL-2",)


def test_subject_argument_ownership_offers_other_values() -> None:
    (family,) = _kind(_families(NOTE), "ownership")
    assert family.argument == "owner_id"
    assert family.argument_role == "subject"
    assert family.binding == "field_name"
    assert family.field_paths == ("TARGET-STATE.widgets.<record_key>.owner_id",)
    assert family.candidates == (
        FamilyCandidate('"OW-2"', ("TARGET-STATE.widgets.W-2",)),
    )


def test_ownership_needs_an_observed_session_subject() -> None:
    state = _state()
    del state["authenticated_owner_id"]
    assert _kind(_families(EDIT, state), "ownership") == []
    assert _kind(_families(NOTE, state), "ownership") == []


def test_ownership_needs_a_record_owned_by_another_subject() -> None:
    state = _state()
    state["widgets"]["W-2"]["owner_id"] = "OW-1"
    state["slots"]["SL-2"]["widget_id"] = "W-1"
    assert _kind(_families(EDIT, state), "ownership") == []
    assert _kind(_families(BOOK, state), "ownership") == []


def test_list_valued_mapping_is_a_key_domain_with_subject_ownership() -> None:
    state = _state()
    state["notes"] = {"OW-1": [], "OW-2": ["kept"], "OW-3": []}
    index = _index(state)
    assert index.key_domains["notes"] == frozenset({"OW-1", "OW-2", "OW-3"})
    assert "notes" not in index.records
    assert index.links[("widgets", "owner_id")] == frozenset({"notes"})

    (family,) = _kind(_families(NOTE, state), "ownership")
    assert family.argument_role == "subject"
    assert family.binding == "field_name"
    assert family.collection == "notes"
    assert family.candidate_record_paths == (
        "TARGET-STATE.notes.OW-2",
        "TARGET-STATE.notes.OW-3",
    )


def test_prefix_binding_to_a_list_valued_key_domain() -> None:
    state = {
        "authenticated_member_id": "MEM-4",
        "files": {"MEM-1": [], "MEM-4": [], "MEM-7": ["x"]},
    }
    operation = _op("fetch_file", {"member_id": "string"})
    (family,) = derive_condition_families(operation, (operation,), _index(state))
    assert family.kind == "ownership"
    assert family.binding == "inferred_prefix"
    assert family.collection == "files"
    assert family.candidate_record_paths == (
        "TARGET-STATE.files.MEM-1",
        "TARGET-STATE.files.MEM-7",
    )


# --- flag, bound, state -------------------------------------------------------


def test_flag_lists_records_per_boolean_value() -> None:
    (family,) = _kind(_families(EDIT), "flag")
    assert family.field_paths == ("TARGET-STATE.widgets.<record_key>.locked",)
    assert family.candidates == (
        FamilyCandidate(
            "false", ("TARGET-STATE.widgets.W-1", "TARGET-STATE.widgets.W-3")
        ),
        FamilyCandidate("true", ("TARGET-STATE.widgets.W-2",)),
    )


def test_flag_needs_both_values_observed() -> None:
    state = _state()
    state["widgets"]["W-2"]["locked"] = False
    assert _kind(_families(EDIT, state), "flag") == []


def test_bound_pairs_a_numeric_argument_with_numeric_fields() -> None:
    (family,) = _kind(_families(EDIT), "bound")
    assert family.argument == "price"
    assert family.argument_role == "value"
    assert family.field_paths == ("TARGET-STATE.widgets.<record_key>.price",)
    assert family.candidates == ()


def test_bound_includes_numeric_fields_one_forward_link_away() -> None:
    operation = _op("resize_slot", {"slot_id": "string", "size": "integer"})
    (family,) = _kind(_families(operation), "bound")
    assert family.field_paths == (
        "TARGET-STATE.slots.<record_key>.capacity",
        "TARGET-STATE.widgets.<record_key>.price",
    )


def test_bound_needs_a_numeric_argument_and_a_numeric_field() -> None:
    assert _kind(_families(READ), "bound") == []
    state = _state()
    for record in state["widgets"].values():
        record["price"] = "unknown"
    assert _kind(_families(EDIT, state), "bound") == []


def test_state_lists_records_per_status_value() -> None:
    (family,) = _kind(_families(EDIT), "state")
    assert family.field_paths == ("TARGET-STATE.widgets.<record_key>.stage",)
    assert family.candidates == (
        FamilyCandidate(
            '"draft"', ("TARGET-STATE.widgets.W-1", "TARGET-STATE.widgets.W-2")
        ),
        FamilyCandidate('"final"', ("TARGET-STATE.widgets.W-3",)),
    )


@pytest.mark.parametrize(
    "stages",
    [
        ("draft", "draft", "draft"),  # one distinct value
        ("draft", "final", "void"),  # as many values as records
        ("in draft", "in draft", "final"),  # whitespace
        ("ST-1", "ST-1", "ST-2"),  # ID-shaped
        ("tok", "tok", "final"),  # a session value
        ("W-1", "W-1", "W-3"),  # record keys
    ],
    ids=["single", "unique", "whitespace", "id-shaped", "session", "keys"],
)
def test_state_rejects_fields_that_are_not_status_like(stages) -> None:
    state = _state()
    for record, stage in zip(state["widgets"].values(), stages, strict=True):
        record["stage"] = stage
    assert _kind(_families(EDIT, state), "state") == []


# --- prior read -------------------------------------------------------------


def test_prior_read_needs_a_read_operation_on_the_same_key_domain() -> None:
    (family,) = _kind(_families(EDIT), "prior_read")
    assert family.prior_operation == "read_widget"
    assert family.same_argument == "widget_id"
    assert family.collection == "widgets"
    assert _kind(_families(BOOK), "prior_read") == []


def test_prior_read_ignores_state_changing_readers() -> None:
    writer = _op("touch_widget", {"widget_id": "string"}, effect="read")
    assert _kind(_families(EDIT, operations=(EDIT, writer)), "prior_read") == []


# --- binding labels, determinism, rename invariance --------------------------


def test_binding_labels_distinguish_field_names_from_prefixes() -> None:
    labels = {
        family.argument: family.binding
        for operation in OPS
        for family in _families(operation)
    }
    assert labels == {
        "widget_id": "field_name",
        "price": "field_name",
        "slot_id": "inferred_prefix",
        "owner_id": "field_name",
    }


@pytest.mark.parametrize(
    ("schema", "types"),
    [
        ("not a mapping", set()),
        ({}, set()),
        ({"type": "string"}, {"string"}),
        ({"type": ["string", "null", 7]}, {"string"}),
        (
            {
                "anyOf": [{"type": "integer"}, {"type": "null"}],
                "oneOf": [{"type": "string"}],
            },
            {"integer", "string"},
        ),
    ],
)
def test_schema_types_collects_declared_and_alternative_types(schema, types) -> None:
    assert _schema_types(schema) == frozenset(types)


def test_argument_linked_to_two_collections_gets_no_binding() -> None:
    state = _state()
    state["notes_a"] = {"NA-1": {"ref_id": "W-1"}}
    state["notes_b"] = {"NB-1": {"ref_id": "SL-1"}}

    assert _bind_arguments(_op("ref_op", {"ref_id": "string"}), _index(state)) == ()


def test_prefix_domain_skips_empty_stems_and_domains_with_mixed_prefixes() -> None:
    state = _state()
    state["mixed"] = {"AA-1": {"x": 1}, "BB-2": {"x": 2}}
    index = _index(state)

    assert _prefix_domain("_id", index) is None
    assert _prefix_domain("aa_id", index) is None
    assert _prefix_domain("slot_id", index) == "slots"


def test_prefix_binding_needs_exactly_one_matching_domain() -> None:
    state = _state()
    state["slices"] = {"SL-9": {"widget_id": "W-1", "capacity": 1}}
    assert _families(BOOK, state) == ()


def test_derivation_is_deterministic() -> None:
    first = [_families(operation) for operation in OPS]
    second = [
        derive_condition_families(operation, tuple(reversed(OPS)), _index(_state()))
        for operation in OPS
    ]
    assert first == second


_RENAMES = (
    ("OW-", "HD-"),
    ("W-", "GZ-"),
    ("SL-", "BA-"),
    ("widget_id", "gizmo_id"),
    ("widgets", "gizmos"),
    ("slot_id", "bay_id"),
    ("slots", "bays"),
    ("owner_id", "holder_id"),
    ("stage", "phase"),
    ("locked", "sealed"),
    ("price", "cost"),
)


def _rename(text: str, reverse: bool = False) -> str:
    pairs = [(new, old) for old, new in reversed(_RENAMES)] if reverse else _RENAMES
    for old, new in pairs:
        text = text.replace(old, new)
    return text


def _renamed_op(operation: TargetOperationObservation) -> TargetOperationObservation:
    return _op(
        operation.operation_id,
        {
            _rename(name): schema["type"]
            for name, schema in operation.input_schema["properties"].items()
        },
        effect=operation.effect,
        state_changing=operation.state_changing,
    )


def _canonical(families) -> list[str]:
    return sorted(json.dumps(family.as_log(), sort_keys=True) for family in families)


def test_consistent_renames_yield_isomorphic_families() -> None:
    renamed_state = json.loads(_rename(json.dumps(_state())))
    renamed_ops = tuple(_renamed_op(operation) for operation in OPS)
    index = _index(renamed_state)
    for original, renamed in zip(OPS, renamed_ops, strict=True):
        expected = _canonical(_families(original))
        actual = [
            _rename(item, reverse=True)
            for item in _canonical(
                derive_condition_families(renamed, renamed_ops, index)
            )
        ]
        assert sorted(actual) == expected, original.operation_id


# --- fan-out ----------------------------------------------------------------


@dataclass(frozen=True)
class _Threat:
    ica_slot_id: str
    ica_id: str


def _threats(*slots: tuple[str, int]) -> list[_Threat]:
    return [
        _Threat(slot, f"{slot}:{number}")
        for slot, count in slots
        for number in range(1, count + 1)
    ]


def _family(kind: str, number: int = 0) -> ConditionFamily:
    return ConditionFamily(kind=kind, operation="edit_widget", argument=f"a{number}")


_SIX = tuple(
    _family(kind, number)
    for number, kind in enumerate(
        ("ownership", "ownership", "flag", "bound", "state", "state")
    )
) + (_family("prior_read", 9),)


def test_incorrect_slots_fan_out_round_robin_across_icas() -> None:
    threats = _threats(("RESP-1:CA-1-1:INCORRECT", 2))
    plan = expand_family_candidates(threats, lambda action: _SIX)

    assert [threat.ica_id for threat in plan.threats] == [
        "RESP-1:CA-1-1:INCORRECT:1",
        "RESP-1:CA-1-1:INCORRECT:1",
        "RESP-1:CA-1-1:INCORRECT:1",
        "RESP-1:CA-1-1:INCORRECT:2",
        "RESP-1:CA-1-1:INCORRECT:2",
        "RESP-1:CA-1-1:INCORRECT:2",
    ]
    assert [item.family for item in plan.candidates] == [
        _SIX[0],
        _SIX[2],
        _SIX[4],
        _SIX[1],
        _SIX[3],
        _SIX[5],
    ]
    assert all(item.capped_out == () for item in plan.candidates)


def test_each_ica_is_capped_and_logs_the_rest() -> None:
    threats = _threats(("RESP-1:CA-1-1:INCORRECT", 1))
    plan = expand_family_candidates(threats, lambda action: _SIX, cap=4)

    assert len(plan.threats) == 4
    assert [item.family for item in plan.candidates] == list(_SIX[:4])
    assert plan.candidates[0].capped_out == _SIX[4:6]
    assert all(item.capped_out == () for item in plan.candidates[1:])


def test_ica_without_an_assigned_family_keeps_one_plain_candidate() -> None:
    threats = _threats(("RESP-1:CA-1-1:INCORRECT", 3))
    plan = expand_family_candidates(threats, lambda action: _SIX[:2])
    assert [item.family for item in plan.candidates] == [_SIX[0], _SIX[1], None]
    assert len(plan.threats) == 3


def test_other_slots_do_not_fan_out() -> None:
    threats = _threats(
        ("RESP-1:CA-1-1:NOT_PROVIDED", 1),
        ("RESP-1:CA-1-1:WRONG_TIMING", 1),
        ("RESP-1:CA-1-1:WRONG_DURATION", 1),
    )
    second_read = _family("prior_read", 10)
    plan = expand_family_candidates(threats, lambda action: (*_SIX, second_read))

    assert list(plan.threats) == threats
    assert [item.family for item in plan.candidates] == [None, _SIX[-1], None]
    assert plan.candidates[1].capped_out == (second_read,)


def test_unrealized_actions_get_no_family() -> None:
    threats = _threats(("RESP-1:CA-1-1:INCORRECT", 2))
    plan = expand_family_candidates(threats, lambda action: ())
    assert list(plan.threats) == threats
    assert all(item.family is None for item in plan.candidates)


def test_expansion_keeps_scenario_numbering_contiguous() -> None:
    threats = _threats(
        ("RESP-1:CA-1-1:NOT_PROVIDED", 1),
        ("RESP-1:CA-1-1:INCORRECT", 1),
        ("RESP-2:CA-2-1:INCORRECT", 1),
    )
    plan = expand_family_candidates(
        threats, lambda action: _SIX if action == "CA-1-1" else ()
    )
    builders = _candidate_outcome_builders(list(plan.threats))

    assert len(builders) == len(plan.threats) == len(plan.candidates) == 6
    assert [builder.scenario_id for builder in builders] == [
        f"SCN-{index:03d}" for index in range(1, 7)
    ]
    assert [builder.ica_id for builder in builders] == [
        "RESP-1:CA-1-1:NOT_PROVIDED:1",
        *["RESP-1:CA-1-1:INCORRECT:1"] * 4,
        "RESP-2:CA-2-1:INCORRECT:1",
    ]


def _realization() -> TargetRealizationResult:
    records = []
    rows = []
    for action_id, operation in (("CA-1-1", EDIT), ("CA-2-1", READ)):
        records.append(
            TargetOperationRecord(
                operation=operation,
                disposition=TargetRealizationDisposition.supported,
                baseline_control_action_ids=(action_id,),
            )
        )
        rows.append(
            TargetRealizationRow(
                control_action_id=action_id,
                controller_id=f"RESP-{action_id[3]}",
                disposition=TargetRealizationDisposition.supported,
                candidate_operations=(operation.reference,),
                selected_operation=operation.reference,
            )
        )
    return TargetRealizationResult(
        baseline_id="baseline-fixture",
        baseline_digest="b" * 64,
        profile_id="profile-fixture",
        profile_digest="d" * 64,
        rows=tuple(rows),
        operation_records=tuple(records),
        summary=TargetRealizationSummary(
            baseline_control_actions=2,
            observed_operations=2,
            supported=2,
            ambiguous=0,
            unmapped=0,
            contradictory=0,
        ),
    )


def _snapshot() -> TargetObservationSnapshot:
    return TargetObservationSnapshot.create(
        target_profile_digest="d" * 64,
        observations=(
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content=json.dumps(_state()),
            ),
        ),
    )


def test_plan_resolves_realized_operations_by_action() -> None:
    threats = _threats(
        ("RESP-1:CA-1-1:INCORRECT", 1),
        ("RESP-1:CA-1-1:WRONG_TIMING", 1),
        ("RESP-2:CA-2-1:INCORRECT", 1),
        ("RESP-3:CA-3-1:INCORRECT", 1),
    )
    plan = plan_family_candidates(threats, _realization(), _snapshot())

    kinds = [
        (threat.ica_id, item.family.kind if item.family else None)
        for threat, item in zip(plan.threats, plan.candidates, strict=True)
    ]
    assert kinds == [
        ("RESP-1:CA-1-1:INCORRECT:1", "ownership"),
        ("RESP-1:CA-1-1:INCORRECT:1", "flag"),
        ("RESP-1:CA-1-1:INCORRECT:1", "bound"),
        ("RESP-1:CA-1-1:INCORRECT:1", "state"),
        ("RESP-1:CA-1-1:WRONG_TIMING:1", "prior_read"),
        ("RESP-2:CA-2-1:INCORRECT:1", "ownership"),
        ("RESP-2:CA-2-1:INCORRECT:1", "flag"),
        ("RESP-2:CA-2-1:INCORRECT:1", "state"),
        ("RESP-3:CA-3-1:INCORRECT:1", None),
    ]


def test_plan_without_target_facts_changes_nothing() -> None:
    threats = _threats(("RESP-1:CA-1-1:INCORRECT", 2))
    plan = plan_family_candidates(threats, None, None)
    assert list(plan.threats) == threats
    assert plan.candidates == (CandidateFamilyPlan(), CandidateFamilyPlan())


# --- context selection and the family sidecar --------------------------------


def test_scenario_id_context_wins_over_the_ica_context() -> None:
    threat = _Threat("RESP-1:CA-1-1:INCORRECT", "RESP-1:CA-1-1:INCORRECT:1")
    by_scenario, by_ica = object(), object()
    supplied = {"SCN-002": by_scenario, threat.ica_id: by_ica}
    assert _select_scenario_context(threat, None, None, 1, supplied) is by_scenario
    assert _select_scenario_context(threat, None, None, 0, supplied) is by_ica


def _ownership_condition(record: str = "W-2") -> DiscriminatingCondition:
    return DiscriminatingCondition.model_validate(
        {
            "statement": "The edited widget belongs to another owner.",
            "comparisons": [
                {
                    "kind": "value",
                    "left": {
                        "source": "fact",
                        "path": f"TARGET-STATE.widgets.{record}.owner_id",
                    },
                    "op": "ne",
                    "right": {
                        "source": "fact",
                        "path": "TARGET-STATE.authenticated_owner_id",
                    },
                }
            ],
            "record_selection": {
                "status": "observed",
                "record_path": f"TARGET-STATE.widgets.{record}",
                "argument_values": [
                    {
                        "operation": "edit_widget",
                        "argument": "widget_id",
                        "path": f"TARGET-STATE.widgets.{record}",
                    }
                ],
            },
        }
    )


def _price_condition(selection: str = "unavailable") -> DiscriminatingCondition:
    return DiscriminatingCondition.model_validate(
        {
            "statement": "The requested price exceeds the widget price.",
            "comparisons": [
                {
                    "kind": "value",
                    "left": {
                        "source": "argument",
                        "operation": "edit_widget",
                        "argument": "price",
                    },
                    "op": "gt",
                    "right": {"source": "literal", "value": 100},
                }
            ],
            "record_selection": (
                {"status": "unavailable", "reason": "The price is request-chosen."}
                if selection == "unavailable"
                else {
                    "status": "observed",
                    "record_path": "TARGET-STATE.widgets.W-1",
                    "argument_values": [],
                }
            ),
        }
    )


def test_honoured_diagnostic_per_family_kind() -> None:
    families = {family.kind: family for family in _families(EDIT)}
    ownership = _ownership_condition()
    assert family_honoured(families["ownership"], ownership) == "honoured"
    assert family_honoured(families["flag"], ownership) == "not_honoured"
    assert family_honoured(families["bound"], _price_condition()) == "honoured"
    assert family_honoured(families["state"], _price_condition()) == "declined"
    assert (
        family_honoured(families["state"], _price_condition("observed"))
        == "not_honoured"
    )
    assert family_honoured(families["flag"], None) == "no_condition"
    order = DiscriminatingCondition.model_validate(
        {
            "statement": "The widget is edited before it is read.",
            "comparisons": [
                {
                    "kind": "order",
                    "operation": "edit_widget",
                    "requires_prior": "read_widget",
                    "same_argument": "widget_id",
                }
            ],
            "record_selection": {"status": "unavailable", "reason": "Timing only."},
        }
    )
    assert family_honoured(families["prior_read"], order) == "honoured"
    assert family_honoured(families["prior_read"], ownership) == "not_honoured"


def test_sidecar_records_hint_capped_families_and_honoured(tmp_path) -> None:
    families = _families(EDIT)
    threats = _threats(("RESP-1:CA-1-1:INCORRECT", 1))
    plan = expand_family_candidates(threats, lambda action: families, cap=1)
    plans = (*plan.candidates, CandidateFamilyPlan())
    builders = _candidate_outcome_builders(
        [*plan.threats, _Threat("RESP-1:CA-1-1:NOT_PROVIDED", "x")]
    )
    spec = _scenario("SCN-001").model_copy(
        update={"discriminating_condition": _ownership_condition()}
    )

    _write_condition_families(tmp_path, builders, plans, [spec])

    payload = yaml.safe_load((tmp_path / "condition-families.yaml").read_text())
    assert payload["schema_version"] == "condition-families-v1"
    first, second = payload["scenarios"]
    assert first["scenario_id"] == "SCN-001"
    assert first["family"]["kind"] == "ownership"
    assert first["binding"] == "field_name"
    assert [item["kind"] for item in first["capped_out"]] == ["flag", "bound", "state"]
    assert first["honoured"] == "honoured"
    assert second == {
        "scenario_id": "SCN-002",
        "ica_id": "x",
        "family": None,
        "binding": None,
        "capped_out": [],
        "honoured": None,
    }


# --- prompt ------------------------------------------------------------------


def _request(family: ConditionFamily | None) -> tuple[str, str]:
    profile = realistic_profile()
    return build_context_bdi_prompts(
        _wrong_timing_context(),
        TemplateLoader(PROMPTS_DIR),
        execution_target_profile=profile,
        target_observations=realistic_observations(profile),
        execution_design=False,
        observation_contract=default_observation_contract(),
        condition_family=family,
    )


_HINT = ConditionFamily(
    kind="ownership",
    operation="update_gadget",
    argument="gadget_id",
    argument_role="record_key",
    binding="field_name",
    collection="gadgets",
    field_paths=("TARGET-STATE.gadgets.<record_key>.owner_id",),
    candidates=(
        FamilyCandidate('"M-2"', ("TARGET-STATE.gadgets.G-5",)),
        FamilyCandidate(
            '"M-9"',
            tuple(f"TARGET-STATE.gadgets.G-{n}" for n in (1, 2, 3, 4, 6)),
        ),
    ),
    session_path="TARGET-STATE.session_member_id",
)


def test_hint_renders_exact_operation_fields_and_candidates() -> None:
    _, user = _request(_HINT)
    rendered = " ".join(user.split())
    for phrase in (
        "Suggested condition family for this scenario",
        "`ownership` on `update_gadget`, argument `gadget_id`.",
        "subject other than the session subject (`TARGET-STATE.session_member_id`)",
        "Fields: `TARGET-STATE.gadgets.<record_key>.owner_id`.",
        '- "M-2": `TARGET-STATE.gadgets.G-5`',
        '- "M-9": `TARGET-STATE.gadgets.G-1`, `TARGET-STATE.gadgets.G-2`, '
        "`TARGET-STATE.gadgets.G-3`, `TARGET-STATE.gadgets.G-4` and 1 more",
        "You may decline it",
        '`{"status":"unavailable","reason":<why the family does not fit>}`',
    ):
        assert phrase in rendered, phrase
    assert user.index("Suggested condition family") < user.index(
        "Example with synthetic names"
    )


def test_prior_read_hint_renders_the_order_comparison() -> None:
    family = ConditionFamily(
        kind="prior_read",
        operation="update_gadget",
        argument="gadget_id",
        prior_operation="get_gadget",
        same_argument="gadget_id",
    )
    _, user = _request(family)
    assert (
        '`{"kind":"order","operation":"update_gadget","requires_prior":'
        '"get_gadget","same_argument":"gadget_id"}`'
    ) in " ".join(user.split())


def test_no_family_renders_no_hint() -> None:
    _, user = _request(None)
    assert "Suggested condition family" not in user


def test_hint_is_absent_without_the_condition_request() -> None:
    profile = realistic_profile()
    _, user = build_context_bdi_prompts(
        _wrong_timing_context(),
        TemplateLoader(PROMPTS_DIR),
        execution_target_profile=profile,
        target_observations=realistic_observations(profile),
        execution_design=False,
        observation_contract=None,
        condition_family=_HINT,
    )
    assert "Suggested condition family" not in user


def test_hinted_request_stays_within_the_token_budget() -> None:
    system, user = _request(_HINT)
    schema = _scenario_semantics_payload_type(
        4,
        duration_eligible=False,
        observation_criteria_required=True,
        condition_references_supplied=True,
    ).model_json_schema()
    total = estimate_prompt_tokens(system + user + json.dumps(schema))
    assert total <= STAGE5_PROMPT_TOKEN_BUDGET


# --- deduplication of family siblings ----------------------------------------


def test_family_siblings_deduplicate_by_their_comparisons() -> None:
    ownership = _ownership_condition()
    specs = [
        _scenario("SCN-001").model_copy(update={"discriminating_condition": ownership}),
        _scenario("SCN-002").model_copy(
            update={"discriminating_condition": _price_condition()}
        ),
        _scenario("SCN-003").model_copy(
            update={"discriminating_condition": copy.deepcopy(ownership)}
        ),
    ]
    assert len({spec.threat_source.ica_id for spec in specs}) == 1

    records = deduplicate_scenario_specs(specs)

    assert records["SCN-001"].status == "canonical"
    assert records["SCN-002"].status == "canonical"
    assert records["SCN-003"].status == "duplicate"
    assert records["SCN-003"].duplicate_of == "SCN-001"


def test_expand_family_candidates_rejects_a_cap_below_one() -> None:
    with pytest.raises(ValueError, match="cap must be at least 1"):
        expand_family_candidates(
            _threats(("RESP-1:CA-1-1:INCORRECT", 1)), lambda action: _SIX, cap=0
        )


def test_honoured_scans_past_an_unrelated_order_comparison() -> None:
    families = {family.kind: family for family in _families(EDIT)}
    price = _price_condition()
    condition = DiscriminatingCondition.model_validate(
        {
            "statement": "The widget is edited before an unrelated read.",
            "comparisons": [
                {
                    "kind": "order",
                    "operation": "edit_widget",
                    "requires_prior": "list_widgets",
                },
                price.comparisons[0].model_dump(mode="json"),
            ],
            "record_selection": {"status": "unavailable", "reason": "Request-chosen."},
        }
    )

    assert family_honoured(families["prior_read"], condition) == "declined"
    assert family_honoured(families["bound"], condition) == "honoured"
