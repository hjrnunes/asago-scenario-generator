"""A restated element keeps its description when the reply only appends labels.

The fixtures are a reviewed Klarna control structure and the revision reply a
saved run merged into it.  The reply restates RESP-1 and RESP-4 and pastes the
prompt's typed-field labels into the restated descriptions: CA-1-1 comes back
as ``Generate natural language response to customer query (target:
controlled_process CP-1) (effect: model_output) (temporality: instantaneous)
(process-model refs: PM-1-1, ...)``.  The labels would reach every later prompt
that shows the action, so the merge keeps the reviewed description.  A
description that changes beyond the labels is a revision and stays.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
    ControlActionTemporality,
    ControlStructure,
    ElementRef,
    ReferenceType,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.critic import (
    _compute_next_ids,
    _merge_revision_delta,
    _revision_delta_from_wire,
    _validate_revision_wire,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "stpa"

_RESPONSE = "Generate natural language response to customer query"


def _reviewed() -> ControlStructure:
    return read_yaml(  # type: ignore[return-value]
        FIXTURES_DIR / "control_structure_reviewed_klarna.yaml", ControlStructure
    )


def _reply() -> dict:
    return json.loads(
        (FIXTURES_DIR / "revision_restated_actions_klarna.json").read_text(
            encoding="utf-8"
        )
    )


def _merge(
    reply: dict, reviewed: ControlStructure | None = None
) -> tuple[ControlStructure, list[str]]:
    _validate_revision_wire(reply)
    return _merge_revision_delta(
        reviewed or _reviewed(), _revision_delta_from_wire(reply)
    )


def _restated(reply: dict, key: str, element_id: str) -> dict:
    id_field = {
        "control_actions": "ca_id",
        "process_model_parts": "pm_id",
        "feedback_channels": "fb_id",
    }[key]
    return next(
        element
        for resp in reply["modified_responsibilities"]
        for element in resp[key]
        if element[id_field] == element_id
    )


def _descriptions(structure: ControlStructure) -> dict[str, str]:
    return {
        element_id: description
        for resp in structure.responsibilities
        for element_id, description in (
            *((pm.pm_id, pm.description) for pm in resp.process_model_parts),
            *((ca.ca_id, ca.description) for ca in resp.control_actions),
            *((fb.fb_id, fb.description) for fb in resp.feedback_channels),
        )
    }


def test_reply_pastes_the_typed_field_labels_into_the_action_description() -> None:
    assert _restated(_reply(), "control_actions", "CA-1-1")["description"] == (
        f"{_RESPONSE} (target: controlled_process CP-1) (effect: model_output) "
        "(temporality: instantaneous) (process-model refs: PM-1-1, PM-1-2, "
        "PM-1-3, PM-1-4, PM-1-5)"
    )


def test_merge_keeps_the_reviewed_description_and_the_typed_fields() -> None:
    merged, _ = _merge(_reply())

    response = merged.responsibilities[0].control_actions[0]
    assert response.ca_id == "CA-1-1"
    assert response.description == _RESPONSE
    assert response.target == ElementRef(
        type=ReferenceType.controlled_process, id="CP-1"
    )
    assert response.effect_kind is ControlActionEffectKind.model_output
    assert response.temporality is ControlActionTemporality.instantaneous


def test_every_restated_element_with_only_pasted_labels_keeps_its_description():
    reviewed = _descriptions(_reviewed())
    merged, _ = _merge(_reply())

    restored = _descriptions(merged)
    for element_id in (
        "PM-1-1",
        "PM-1-2",
        "PM-4-1",
        "CA-1-1",
        "CA-4-1",
        "CA-4-2",
        "FB-1-1",
        "FB-1-2",
        "FB-4-1",
    ):
        assert restored[element_id] == reviewed[element_id], element_id
    assert "(" not in restored["CA-4-1"]


def test_merge_reports_each_restored_description() -> None:
    _, warnings = _merge(_reply())

    assert (
        "Revision control action CA-1-1 of RESP-1 restated its description with "
        "typed-field labels appended; the original description is kept."
    ) in warnings
    assert (
        "Revision feedback channel FB-1-1 of RESP-1 restated its description "
        "with typed-field labels appended; the original description is kept."
    ) in warnings


def test_a_revised_description_with_pasted_labels_is_kept() -> None:
    reply = _reply()
    revised = (
        f"{_RESPONSE} after checking the session identity "
        "(target: controlled_process CP-1) (effect: model_output)"
    )
    _restated(reply, "control_actions", "CA-1-1")["description"] = revised

    merged, warnings = _merge(reply)

    assert merged.responsibilities[0].control_actions[0].description == revised
    assert not [w for w in warnings if "CA-1-1" in w]


def test_a_revised_description_without_labels_is_kept() -> None:
    reply = _reply()
    revised = "Generate a grounded natural language response to customer query"
    _restated(reply, "control_actions", "CA-1-1")["description"] = revised

    merged, _ = _merge(reply)

    assert merged.responsibilities[0].control_actions[0].description == revised


def _merged_description(
    key: str,
    element_id: str,
    restated: str,
    reviewed: ControlStructure | None = None,
) -> str:
    reply = _reply()
    _restated(reply, key, element_id)["description"] = restated
    merged, _ = _merge(reply, reviewed)
    return _descriptions(merged)[element_id]


@pytest.mark.parametrize(
    "restated",
    [
        f"{_RESPONSE} (effect: model_output)",
        f"{_RESPONSE}. (target: controlled_process CP-1)",
        f"  {_RESPONSE}\n  (effect_kind: model_output) (temporality: instantaneous) ",
        f"{_RESPONSE} (process_model_refs: PM-1-1, PM-1-3)",
        f"{_RESPONSE} (target: controlled_process CP-1, effect: model_output)",
    ],
)
def test_pasted_action_fields_are_removed(restated: str) -> None:
    assert _merged_description("control_actions", "CA-1-1", restated) == _RESPONSE


@pytest.mark.parametrize(
    ("key", "element_id", "suffix"),
    [
        (
            "process_model_parts",
            "PM-1-1",
            "(values: matches session identity; does not match session "
            "identity; unknown) (evidence_refs: session:authenticated_customer_id)",
        ),
        (
            "feedback_channels",
            "FB-1-1",
            "(updates: PM-1-1) (source: controlled_process CP-1) "
            "(source_kind: session_context)",
        ),
        ("control_actions", "CA-4-1", "(operation: process_refund)"),
    ],
)
def test_pasted_fields_of_each_element_kind_are_removed(
    key: str, element_id: str, suffix: str
) -> None:
    original = _descriptions(_reviewed())[element_id]

    merged = _merged_description(key, element_id, f"{original} {suffix}")

    assert merged == original


@pytest.mark.parametrize(
    "restated",
    [
        f"{_RESPONSE} (effect: clearer disclosure)",
        f"{_RESPONSE} (target: the customer)",
        f"{_RESPONSE} (temporality: discrete)",
        f"{_RESPONSE} (operation: answer_query)",
        f"{_RESPONSE} (process-model refs: the session identity)",
        f"{_RESPONSE} (for the authenticated customer)",
        f"{_RESPONSE} (effect: model_output) only for verified customers",
        f"{_RESPONSE}s (effect: model_output)",
        f"{_RESPONSE} (effect: model_output",
        f"Generate response (effect: model_output) {_RESPONSE}",
    ],
)
def test_a_genuine_revision_shaped_like_a_label_is_kept(restated: str) -> None:
    assert _merged_description("control_actions", "CA-1-1", restated) == restated


def test_a_pasted_value_with_nested_parentheses_is_removed() -> None:
    reviewed = _reviewed()
    reviewed.responsibilities[0].control_actions[0].operation = "lookup(order_id)"
    restated = f"{_RESPONSE} (effect: model_output) (operation: lookup(order_id))"

    merged = _merged_description("control_actions", "CA-1-1", restated, reviewed)

    assert merged == _RESPONSE


def test_only_the_text_appended_to_the_original_description_is_read() -> None:
    reviewed = _reviewed()
    original = f"{_RESPONSE} (effect: model_output)"
    reviewed.responsibilities[0].control_actions[0].description = original

    pasted = _merged_description(
        "control_actions",
        "CA-1-1",
        f"{original} (temporality: instantaneous)",
        reviewed,
    )
    shortened = _merged_description("control_actions", "CA-1-1", _RESPONSE, reviewed)

    assert pasted == original
    assert shortened == _RESPONSE


def _revision_system_prompt() -> str:
    structure = _reviewed()
    return TemplateLoader(PROMPTS_DIR).render_prompt(
        "revision_system.j2",
        control_structure=structure,
        **_compute_next_ids(structure),
    )


def test_revision_prompt_shows_typed_fields_apart_from_the_description() -> None:
    prompt = _revision_system_prompt()

    assert (
        f"    - CA-1-1: {_RESPONSE}\n"
        "      target: controlled_process CP-1\n"
        "      effect_kind: model_output\n"
        "      temporality: instantaneous\n"
        "      process_model_refs: PM-1-1, PM-1-2, PM-1-3\n"
    ) in prompt
    assert (
        "    - FB-1-1: Identify currently authenticated user from session\n"
        "      updates: PM-1-1\n"
        "      source: controlled_process CP-1\n"
        "      source_kind: session_context\n"
    ) in prompt
    for label in (
        "(target:",
        "(effect:",
        "(temporality:",
        "(operation:",
        "(process-model refs:",
        "(values:",
        "(evidence:",
        "(source:",
        "(updates:",
        "source kind:",
        "authority for update:",
        "authority basis:",
    ):
        assert label not in prompt, label
