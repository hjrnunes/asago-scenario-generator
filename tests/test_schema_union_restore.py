"""A flat reply is restored to its union branch before validation.

The request carries every union as one flat object, so a reply lists every
property and sets the ones its branch does not use to null.  Before the
reply is validated against its response type, each discriminated union
position keeps only the keys the selected branch defines and drops a null
that one of the branch's own optional fields rejects, so the field's default
applies.  A null in a field the branch requires stays, so validation reports
the null at that field.  Each drop that is not a foreign null is recorded with
its path, branch, and reason.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import jsonschema
import pytest
from pydantic import BaseModel, ValidationError

from asago_scenario_generator.request_schema import (
    flat_example_for,
    restore_flat_reply_for,
)
from asago_scenario_generator.schema_unions import (
    find_unions,
    flat_restore_drops,
    restore_flat_reply,
)
from asago_scenario_generator.stpa.infra.llm import (
    LLMResult,
    _json_schema_response_format,
    _locally_parse_response_content,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    _parse_structured_result,
    parse_llm_result,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    _routing_wire_examples,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    _routing_provider_payload_type,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    _parse_context_bdi_result,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.schema import (
    _scenario_semantics_payload_type,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    _ControlElementProviderSet,
)

_NULL = {"type": "null"}

_SCHEMA = {
    "type": "object",
    "properties": {
        "items": {
            "type": "array",
            "items": {
                "oneOf": [{"$ref": "#/$defs/A"}, {"$ref": "#/$defs/B"}],
                "discriminator": {
                    "propertyName": "kind",
                    "mapping": {"a": "#/$defs/A", "b": "#/$defs/B"},
                },
            },
        },
        "maybe": {
            "anyOf": [
                {
                    "oneOf": [{"$ref": "#/$defs/A"}, {"$ref": "#/$defs/B"}],
                    "discriminator": {
                        "propertyName": "kind",
                        "mapping": {"a": "#/$defs/A", "b": "#/$defs/B"},
                    },
                },
                _NULL,
            ]
        },
        "rows": {"type": "array", "prefixItems": [{"$ref": "#/$defs/Holder"}]},
    },
    "$defs": {
        "A": {
            "type": "object",
            "properties": {
                "kind": {"const": "a"},
                "n": {"type": "integer"},
                "opt": {"anyOf": [{"type": "string"}, _NULL]},
            },
        },
        "B": {
            "type": "object",
            "properties": {"kind": {"const": "b"}, "s": {"type": "string"}},
        },
        "Holder": {
            "type": "object",
            "properties": {
                "inner": {
                    "oneOf": [{"$ref": "#/$defs/A"}, {"$ref": "#/$defs/B"}],
                    "discriminator": {
                        "propertyName": "kind",
                        "mapping": {"a": "#/$defs/A", "b": "#/$defs/B"},
                    },
                }
            },
        },
    },
}


def test_restore_drops_only_null_keys_the_selected_branch_lacks() -> None:
    reply = {
        "items": [
            {"kind": "a", "n": 1, "opt": None, "s": None},
            {"kind": "b", "n": None, "opt": None, "s": "x"},
        ],
        "maybe": {"kind": "b", "n": None, "opt": None, "s": "y"},
        "rows": [{"inner": {"kind": "a", "n": 2, "opt": None, "s": None}}],
    }
    original = copy.deepcopy(reply)
    assert restore_flat_reply(reply, _SCHEMA) == {
        "items": [{"kind": "a", "n": 1, "opt": None}, {"kind": "b", "s": "x"}],
        "maybe": {"kind": "b", "s": "y"},
        "rows": [{"inner": {"kind": "a", "n": 2, "opt": None}}],
    }
    assert reply == original


def test_restore_drops_a_non_null_value_the_selected_branch_lacks() -> None:
    reply = {
        "items": [
            {"kind": "a", "n": 1, "s": "foreign"},
            {"kind": "b", "n": 7, "opt": "foreign", "s": "x"},
        ],
        "maybe": {"kind": "b", "n": 3, "s": "y"},
        "rows": [{"inner": {"kind": "a", "n": 2, "s": "foreign"}}],
    }
    assert restore_flat_reply(reply, _SCHEMA) == {
        "items": [{"kind": "a", "n": 1}, {"kind": "b", "s": "x"}],
        "maybe": {"kind": "b", "s": "y"},
        "rows": [{"inner": {"kind": "a", "n": 2}}],
    }


def test_restore_keeps_an_unknown_branch_and_a_missing_discriminator() -> None:
    reply = {
        "items": [
            {"kind": "c", "n": None, "s": "kept"},
            {"n": None, "s": "kept"},
            "not an object",
        ],
        "maybe": None,
    }
    assert restore_flat_reply(reply, _SCHEMA) == reply


_NULLABLE_FORMS = {
    "type": "object",
    "properties": {"top": {"$ref": "#/$defs/X"}},
    "$defs": {
        "Maybe": {"anyOf": [{"type": "string"}, _NULL]},
        "Plain": {"type": "object", "properties": {"v": {"type": "string"}}},
        "X": {
            "type": "object",
            "properties": {
                "kind": {"const": "x"},
                "plain_integer": {"type": "integer"},
                "plain_object": {"$ref": "#/$defs/Plain"},
                "plain_enum": {"enum": ["p", "q"]},
                "any_of_null": {"anyOf": [{"type": "string"}, _NULL]},
                "type_list": {"type": ["string", "null"]},
                "enum_null": {"enum": ["p", None]},
                "const_null": {"const": None},
                "ref_to_nullable": {"$ref": "#/$defs/Maybe"},
                "nullable_ref": {"anyOf": [{"$ref": "#/$defs/Plain"}, _NULL]},
                "untyped": {},
                "boolean_schema": True,
            },
        },
        "Y": {"type": "object", "properties": {"kind": {"const": "y"}}},
    },
}
_NULLABLE_FORMS["properties"]["top"] = {
    "oneOf": [{"$ref": "#/$defs/X"}, {"$ref": "#/$defs/Y"}],
    "discriminator": {
        "propertyName": "kind",
        "mapping": {"x": "#/$defs/X", "y": "#/$defs/Y"},
    },
}


def test_restore_drops_a_null_the_branch_field_rejects_and_keeps_the_others() -> None:
    nulls = dict.fromkeys(_NULLABLE_FORMS["$defs"]["X"]["properties"])
    reply = {"top": {**nulls, "kind": "x"}}
    kept = ["any_of_null", "type_list", "enum_null", "const_null"]
    kept += ["ref_to_nullable", "nullable_ref", "untyped", "boolean_schema"]
    assert restore_flat_reply(reply, _NULLABLE_FORMS) == {
        "top": {"kind": "x", **dict.fromkeys(kept)}
    }


def test_restore_drops_a_null_in_every_union_position() -> None:
    reply = {
        "maybe": {"kind": "a", "n": None, "opt": None},
        "items": [{"kind": "a", "n": None, "opt": "x"}],
        "rows": [{"inner": {"kind": "a", "n": None, "opt": None}}],
    }
    assert restore_flat_reply(reply, _SCHEMA) == {
        "maybe": {"kind": "a", "opt": None},
        "items": [{"kind": "a", "opt": "x"}],
        "rows": [{"inner": {"kind": "a", "opt": None}}],
    }


def test_restore_records_each_drop_by_path_branch_and_reason() -> None:
    reply = {
        "items": [
            {"kind": "a", "n": None, "opt": None, "s": "foreign", "a/b~c": 1},
            {"kind": "b", "n": None, "s": "x"},
        ],
        "maybe": {"kind": "b", "s": None, "n": 3},
        "rows": [{"inner": {"kind": "a", "n": None, "s": None}}],
    }
    drops: list[dict[str, str]] = []
    restored = restore_flat_reply(reply, _SCHEMA, drops)
    assert drops == [
        {"path": "/items/0/n", "branch": "a", "reason": "null_to_default"},
        {"path": "/items/0/s", "branch": "a", "reason": "foreign_value"},
        {"path": "/items/0/a~1b~0c", "branch": "a", "reason": "foreign_value"},
        {"path": "/maybe/s", "branch": "b", "reason": "null_to_default"},
        {"path": "/maybe/n", "branch": "b", "reason": "foreign_value"},
        {"path": "/rows/0/inner/n", "branch": "a", "reason": "null_to_default"},
    ]
    assert restored == restore_flat_reply(reply, _SCHEMA)


def test_restore_records_no_drop_for_a_reply_in_flat_form() -> None:
    reply = {"items": [{"kind": "a", "n": 1, "opt": None, "s": None}]}
    drops: list[dict[str, str]] = []
    restore_flat_reply(reply, _SCHEMA, drops)
    assert drops == []


def test_restore_leaves_keys_outside_a_union_alone() -> None:
    reply = {"rows": [{"inner": {"kind": "b", "s": "x"}, "extra": None}], "more": 1}
    assert restore_flat_reply(reply, _SCHEMA) == reply


_STAGE5 = _scenario_semantics_payload_type(
    3,
    duration_eligible=True,
    observation_criteria_required=True,
    condition_references_supplied=True,
)
_ROUTING = _routing_provider_payload_type(1)
_OB = "ob:v1:" + "0" * 64


def _stage5(**changes: Any) -> dict[str, Any]:
    reply: dict[str, Any] = {
        "adversary": {"kind": "malicious_customer", "gain": "Reads another order."},
        "attacker_bdi": {
            "beliefs": ["The assistant trusts the order number."],
            "desires": ["See another customer's order."],
            "intentions": [
                {
                    "description": "Ask for a foreign order.",
                    "source_handles": ["cause_1"],
                }
            ],
        },
        "causal_factors": [
            {
                "source_handle": "cause_1",
                "evidence": "The lookup does not check the owner.",
                "temporal_condition": None,
                "evidence_status": "structural_failure",
            }
        ],
        "unsafe_outcome": {
            "semantic_proposition": "The reply shows another customer's order.",
            "observation_criteria": [
                {
                    "criterion_id": "LEAK",
                    "outcome": "The reply names a foreign order.",
                    "observable": True,
                    "claim_level": "reply",
                    "evidence": "assistant_message",
                    "operation_name": None,
                    "reason": "The reply text shows the order.",
                }
            ],
            "safe_observable_outcome": {
                "observable": True,
                "statement": "The reply names no foreign order.",
                "claim_level": "reply",
                "evidence": "assistant_message",
                "operation_name": None,
            },
            "discriminating_condition": {
                "statement": "The order belongs to another customer.",
                "comparisons": [
                    {
                        "kind": "value",
                        "left": {
                            "source": "fact",
                            "path": "TARGET-STATE.orders.O-1.owner",
                        },
                        "op": "ne",
                        "right": {
                            "source": "fact",
                            "path": "TARGET-STATE.session.customer",
                        },
                    }
                ],
                "record_selection": {
                    "status": "observed",
                    "record_path": "TARGET-STATE.orders.O-1",
                    "argument_values": [],
                },
            },
        },
    }
    for path, value in changes.items():
        _set(reply, path.split("__"), value)
    return reply


def _set(node: Any, keys: list[str], value: Any) -> None:
    for key in keys[:-1]:
        node = node[int(key)] if isinstance(node, list) else node[key]
    if isinstance(node, list):
        node[int(keys[-1])] = value
    else:
        node[keys[-1]] = value


def _factor(status: str, temporal: Any = None, **extra: Any) -> list[dict[str, Any]]:
    return [
        {
            "source_handle": "cause_1",
            "evidence": "The lookup does not check the owner.",
            "temporal_condition": temporal,
            "evidence_status": status,
            **extra,
        }
    ]


def _comparison(**fields: Any) -> list[dict[str, Any]]:
    return [fields]


_CONDITION = "unsafe_outcome__discriminating_condition"

_STAGE5_REPLIES = {
    "adversary-attacker": _stage5(),
    "adversary-none": _stage5(
        adversary={"kind": "none"},
        attacker_bdi={"beliefs": [], "desires": [], "intentions": []},
    ),
    "factor-reachable": _stage5(
        causal_factors=_factor(
            "reachable_capability", capability_refs=["CAP-1"], access_refs=["ACC-1"]
        )
    ),
    "factor-bounded": _stage5(
        causal_factors=_factor("bounded_assumption", bounded_assumption="It may.")
    ),
    "temporal-ordering": _stage5(
        causal_factors=_factor(
            "structural_failure",
            {
                "type": "ordering",
                "reference_handle": "target_action",
                "relation": "before",
            },
        )
    ),
    "temporal-delay": _stage5(
        causal_factors=_factor(
            "structural_failure",
            {"type": "delay", "reference_handle": "target_action", "delay_ms": 500},
        )
    ),
    "temporal-duration": _stage5(
        causal_factors=_factor(
            "structural_failure",
            {
                "type": "duration",
                "reference_handle": "target_action",
                "duration_ms": 500,
            },
        )
    ),
    "temporal-window": _stage5(
        causal_factors=_factor(
            "structural_failure",
            {
                "type": "window",
                "reference_handle": "target_action",
                "window_from_ms": 0,
                "window_to_ms": 1000,
            },
        )
    ),
    "temporal-absence": _stage5(
        causal_factors=_factor(
            "structural_failure",
            {
                "type": "absence",
                "reference_handle": "cause_2",
                "until_step_handle": "target_action",
            },
        )
    ),
    "comparison-operands": _stage5(
        **{
            f"{_CONDITION}__comparisons": _comparison(
                kind="value",
                left={
                    "source": "argument",
                    "operation": "refund",
                    "argument": "amount",
                },
                op="gt",
                right={"source": "literal", "value": 100},
            )
        }
    ),
    "comparison-order": _stage5(
        **{
            f"{_CONDITION}__comparisons": _comparison(
                kind="order",
                operation="refund",
                requires_prior="verify",
                same_argument="order_id",
            )
        }
    ),
    "comparison-not-called": _stage5(
        **{
            f"{_CONDITION}__comparisons": _comparison(
                kind="not_called", operation="verify"
            )
        }
    ),
    "record-unavailable": _stage5(
        **{
            f"{_CONDITION}__record_selection": {
                "status": "unavailable",
                "reason": "No listed order matches.",
            }
        }
    ),
}


def _route(disposition: str, **fields: Any) -> dict[str, Any]:
    return {
        "routes": [
            {
                "obligation_id": _OB,
                "attack_pattern_id": "AP-T1-01",
                "semantic_assessment": {
                    "mechanism_assessment": "plausible_in_system",
                    "risk_alignment": "supported",
                    "mechanism_rationale": "The path exists.",
                    "risk_alignment_rationale": "It realizes the risk.",
                },
                "rationale": "Why this disposition.",
                "evidence": ["RESP-1 handles refunds."],
                "disposition": disposition,
                **fields,
            }
        ]
    }


_TARGETED_IDS = {
    name: []
    for name in (
        "controller_ids",
        "control_action_ids",
        "responsibility_ids",
        "process_model_part_ids",
        "feedback_channel_ids",
        "controlled_process_ids",
        "coordination_link_ids",
    )
}

_ROUTING_REPLIES = {
    "targeted": _route(
        "targeted",
        targeting={
            "slot_ids": ["RESP-1:CA-1-1:NOT_PROVIDED"],
            **_TARGETED_IDS,
            "hazard_ids": ["H-1"],
            "constraint_ids": ["SC-1"],
        },
    ),
    "proposed-not-applicable": _route("proposed_not_applicable"),
    "upstream-gap": _route(
        "upstream_gap",
        missing_concepts=[
            {
                "concept_type": "controlled_process",
                "description": "No payment process is modelled.",
                "concept_id": None,
                "evidence_refs": ["RESP-1"],
                "obligation_id": None,
            }
        ],
    ),
    "unresolved": _route("unresolved"),
}

_STAGE2_REPLY = {
    "control_actions": [
        {
            "ca_id": "CA-1-1",
            "description": "Ask the checker.",
            "target": {"type": "responsibility", "id": "RESP-2"},
            "effect_kind": "agent_message",
            "temporality": "discrete",
            "operation": None,
            "process_model_refs": ["PM-1-1"],
        },
        {
            "ca_id": "CA-1-2",
            "description": "Issue a refund.",
            "target": {"type": "controlled_process", "id": "CP-1"},
            "effect_kind": "tool_call",
            "temporality": "instantaneous",
            "operation": "refund",
            "process_model_refs": ["PM-1-1"],
        },
    ],
    "feedback": [
        {
            "fb_id": "FB-1-1",
            "description": "Refund result.",
            "updates": "PM-1-1",
            "source": {"type": "controlled_process", "id": "CP-1"},
            "source_kind": None,
        }
    ],
    "controlled_processes": [{"cp_id": "CP-1", "description": "Payments."}],
}

_CASES = [
    *((f"stage5-{k}", _STAGE5, v) for k, v in _STAGE5_REPLIES.items()),
    *((f"routing-{k}", _ROUTING, v) for k, v in _ROUTING_REPLIES.items()),
    ("stage2-both-forms", _ControlElementProviderSet, _STAGE2_REPLY),
]


def _flat_reply(value: Any, node: Any, defs: dict[str, Any]) -> Any:
    """Write ``value`` the way the flat request schema asks: every key present."""
    if isinstance(node, dict) and "$ref" in node:
        node = defs[node["$ref"].rsplit("/", 1)[-1]]
    if value is None or not isinstance(node, dict):
        return value
    if "anyOf" in node:
        objects = [o for o in node["anyOf"] if o != _NULL]
        return _flat_reply(value, objects[0], defs) if len(objects) == 1 else value
    if isinstance(value, list):
        return [_flat_reply(v, node.get("items"), defs) for v in value]
    if not isinstance(value, dict):
        return value
    properties = node.get("properties", {})
    return {
        name: _flat_reply(value[name], schema, defs) if name in value else None
        for name, schema in properties.items()
        if name in value or name in node.get("required", ())
    }


def _flat_case(model: type[BaseModel], reply: dict[str, Any]) -> dict[str, Any]:
    schema = _json_schema_response_format(model)["json_schema"]["schema"]
    flat = _flat_reply(reply, schema, schema.get("$defs", {}))
    jsonschema.Draft202012Validator(schema).validate(flat)
    return flat


@pytest.mark.parametrize(("name", "model", "reply"), _CASES, ids=[c[0] for c in _CASES])
def test_a_flat_reply_restores_and_validates_as_its_original(
    name: str, model: type[BaseModel], reply: dict[str, Any]
) -> None:
    expected = model.model_validate(reply)
    flat = _flat_case(model, reply)
    assert model.model_validate(restore_flat_reply_for(model, flat)) == expected


@pytest.mark.parametrize(
    "name",
    ["stage5-adversary-attacker", "stage5-temporal-window", "routing-upstream-gap"],
)
def test_a_flat_reply_needs_the_restore(name: str) -> None:
    _, model, reply = next(c for c in _CASES if c[0] == name)
    with pytest.raises(ValidationError):
        model.model_validate(_flat_case(model, reply))


_COND = "unsafe_outcome__discriminating_condition"
_FACTOR = "causal_factors__0"

# Each case fills fields its selected branch does not define with values.
_FOREIGN_VALUES = {
    "stage5-factor-reachable": {f"{_FACTOR}__bounded_assumption": "It may."},
    "stage5-temporal-window": {
        f"{_FACTOR}__temporal_condition__relation": "before",
        f"{_FACTOR}__temporal_condition__delay_ms": 500,
    },
    "stage5-comparison-operands": {
        f"{_COND}__comparisons__0__left__path": "TARGET-STATE.x",
        f"{_COND}__comparisons__0__right__operation": "refund",
        f"{_COND}__comparisons__0__requires_prior": "verify",
    },
    "stage5-record-unavailable": {
        f"{_COND}__record_selection__record_path": "TARGET-STATE.orders.O-1",
        f"{_COND}__record_selection__argument_values": [],
    },
    "routing-unresolved": {
        "routes__0__targeting": {
            "slot_ids": ["RESP-1:CA-1-1:NOT_PROVIDED"],
            "hazard_ids": ["H-1"],
            "constraint_ids": ["SC-1"],
        },
        "routes__0__missing_concepts": [],
    },
    "routing-targeted": {"routes__0__missing_concepts": []},
}


@pytest.mark.parametrize("name", list(_FOREIGN_VALUES))
def test_a_value_outside_the_selected_branch_is_dropped_before_validation(
    name: str,
) -> None:
    _, model, reply = next(c for c in _CASES if c[0] == name)
    flat = _flat_case(model, reply)
    for path, value in _FOREIGN_VALUES[name].items():
        _set(flat, path.split("__"), value)
    with pytest.raises(ValidationError, match="extra_forbidden"):
        model.model_validate(flat)
    assert model.model_validate(restore_flat_reply_for(model, flat)) == (
        model.model_validate(reply)
    )


def test_a_null_in_an_optional_field_of_the_branch_takes_its_default() -> None:
    _, model, reply = next(c for c in _CASES if c[0] == "stage5-adversary-attacker")
    flat = _flat_case(model, reply)
    selection = flat["unsafe_outcome"]["discriminating_condition"]["record_selection"]
    assert selection["argument_values"] == []
    selection["argument_values"] = None
    with pytest.raises(ValidationError, match="argument_values"):
        model.model_validate(flat)
    restored = model.model_validate(restore_flat_reply_for(model, flat))
    assert restored == model.model_validate(reply)


_TEMPORAL = "causal_factors__0__temporal_condition"

# Each case sets a field its selected branch requires, with no default, to null.
_REQUIRED_NULLS = [
    ("routing-upstream-gap", "routes__0__missing_concepts"),
    ("routing-targeted", "routes__0__targeting"),
    ("stage5-adversary-attacker", "adversary__gain"),
    ("stage5-temporal-ordering", f"{_TEMPORAL}__reference_handle"),
    ("stage5-temporal-ordering", f"{_TEMPORAL}__relation"),
    ("stage5-temporal-delay", f"{_TEMPORAL}__delay_ms"),
    ("stage5-temporal-window", f"{_TEMPORAL}__window_to_ms"),
    ("stage5-temporal-absence", f"{_TEMPORAL}__until_step_handle"),
    ("stage5-factor-reachable", "causal_factors__0__capability_refs"),
]


@pytest.mark.parametrize(("name", "path"), _REQUIRED_NULLS)
def test_a_null_in_a_required_field_of_the_branch_fails_as_a_null(
    name: str, path: str
) -> None:
    _, model, reply = next(c for c in _CASES if c[0] == name)
    flat = _flat_case(model, reply)
    keys = path.split("__")
    _set(flat, keys, None)
    restored = restore_flat_reply_for(model, flat)
    parent = restored
    for key in keys[:-1]:
        parent = parent[int(key)] if isinstance(parent, list) else parent[key]
    assert keys[-1] in parent and parent[keys[-1]] is None
    assert flat_restore_drops(model, flat) == []
    with pytest.raises(ValidationError) as caught:
        model.model_validate(restored)
    # A field of several value types fails once per type, each at the field.
    errors = caught.value.errors(include_url=False)
    assert errors
    for error in errors:
        assert keys[-1] in error["loc"]
        assert error["input"] is None
        assert error["type"] != "missing"


def test_a_null_in_a_field_with_a_default_still_takes_the_default() -> None:
    schema = {
        **_SCHEMA,
        "$defs": {**_SCHEMA["$defs"], "A": {**_SCHEMA["$defs"]["A"], "required": []}},
    }
    reply = {"items": [{"kind": "a", "n": None, "s": None}]}
    assert restore_flat_reply(reply, schema) == {"items": [{"kind": "a"}]}
    required = {**schema["$defs"]["A"], "required": ["kind", "n"]}
    schema["$defs"] = {**schema["$defs"], "A": required}
    assert restore_flat_reply(reply, schema) == {"items": [{"kind": "a", "n": None}]}


def test_the_drops_of_a_production_reply_name_the_selected_branch() -> None:
    flat = _flat_case(_ROUTING, _ROUTING_REPLIES["targeted"])
    route = flat["routes"][0]
    route["targeting"] = None
    route["missing_concepts"] = []
    drops = flat_restore_drops(_ROUTING, flat)
    assert drops == [
        {
            "path": "/routes/0/missing_concepts",
            "branch": "targeted",
            "reason": "foreign_value",
        },
    ]
    appended: list[dict[str, str]] = []
    restore_flat_reply_for(_ROUTING, flat, appended)
    assert appended == drops


def test_a_reply_with_nothing_to_drop_and_a_type_without_unions_record_none() -> None:
    flat = _flat_case(_ROUTING, _ROUTING_REPLIES["targeted"])
    assert flat_restore_drops(_ROUTING, flat) == []
    assert flat_restore_drops(_ControlElementProviderSet, _STAGE2_REPLY) == []
    assert flat_restore_drops(_ROUTING, "not an object") == []


def test_a_required_field_of_the_branch_set_to_null_still_fails() -> None:
    reply = _route("targeted", targeting=None)
    with pytest.raises(ValidationError, match="targeting"):
        _ROUTING.model_validate(restore_flat_reply_for(_ROUTING, reply))
    reply = _route(
        "targeted",
        targeting={"slot_ids": None, "hazard_ids": ["H-1"], "constraint_ids": ["SC-1"]},
    )
    with pytest.raises(ValidationError, match="slot_ids"):
        _ROUTING.model_validate(restore_flat_reply_for(_ROUTING, reply))


def test_the_stage_2_union_branches_share_their_fields() -> None:
    schema = _ControlElementProviderSet.model_json_schema()
    (pointer,) = find_unions(schema)
    assert pointer == "/properties/control_actions/items"
    union = schema["properties"]["control_actions"]["items"]
    assert "discriminator" not in union
    fields = [
        set(schema["$defs"][option["$ref"].rsplit("/", 1)[-1]]["properties"])
        for option in union["anyOf"]
    ]
    assert len(fields) == 2
    assert fields[0] == fields[1]


def test_a_type_without_a_discriminated_union_is_left_alone() -> None:
    reply = {"control_actions": [], "extra": None}
    assert restore_flat_reply_for(_ControlElementProviderSet, reply) is reply


def _flat_text(name: str) -> tuple[type[BaseModel], str, BaseModel]:
    _, model, reply = next(c for c in _CASES if c[0] == name)
    return model, json.dumps(_flat_case(model, reply)), model.model_validate(reply)


def test_parse_llm_result_restores_text_and_mapping_content() -> None:
    model, text, expected = _flat_text("routing-upstream-gap")
    assert parse_llm_result(LLMResult(content=text, duration_ms=0), model) == expected
    mapping = json.loads(text)
    assert (
        parse_llm_result(LLMResult(content=mapping, duration_ms=0), model) == expected
    )


def test_a_stage_parser_receives_the_restored_reply() -> None:
    model, text, expected = _flat_text("stage5-temporal-absence")
    result = LLMResult(content=text, duration_ms=0, raw_response=text)
    parsed = _parse_structured_result(
        result,
        model,
        response_parser=lambda value, _cleanup: _parse_context_bdi_result(value, model),
    )
    assert parsed == expected
    assert result.content == text


def test_the_strict_local_parse_restores_the_reply() -> None:
    model, text, expected = _flat_text("stage5-adversary-none")
    assert _locally_parse_response_content(text, model) == expected
    assert _locally_parse_response_content(json.loads(text), model) == expected


def test_flat_example_fills_every_absent_required_key_with_null() -> None:
    route = _ROUTING.model_validate(_ROUTING_REPLIES["unresolved"])
    example = flat_example_for(_ROUTING, route.model_dump(mode="json"))
    schema = _json_schema_response_format(_ROUTING)["json_schema"]["schema"]
    jsonschema.Draft202012Validator(schema).validate(example)
    (flat_route,) = example["routes"]
    assert flat_route["targeting"] is None
    assert flat_route["missing_concepts"] is None
    assert _ROUTING.model_validate(restore_flat_reply_for(_ROUTING, example)) == route


def test_the_routing_prompt_examples_are_flat_request_replies() -> None:
    schema = _json_schema_response_format(_ROUTING)["json_schema"]["schema"]
    for text in _routing_wire_examples():
        example = json.loads(text)
        jsonschema.Draft202012Validator(schema).validate(example)
        _ROUTING.model_validate(restore_flat_reply_for(_ROUTING, example))
