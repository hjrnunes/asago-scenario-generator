"""Focused tests for recoverable SP1 normalization defects."""

from __future__ import annotations

import copy
import warnings

import pytest

from asago_scenario_generator.stpa.infra.unvalidated_decode import (
    construct_model_unvalidated,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    CoordinationLink,
    CoordinationMechanism,
    FeedbackChannel,
    ProcessModelPart,
    Responsibility,
    ResponsibilityConstraint,
)
from asago_scenario_generator.stpa.system_model.id_normalization import (
    normalize_control_structure_payload,
)


def _payload_with_references() -> dict:
    """Return a valid structure with recoverable malformed fields."""
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-9",
                "description": "",
                "responsibility_constraints": [{"rc_id": "RC-9-1", "description": ""}],
                "process_model_parts": [
                    {
                        "pm_id": "state-alpha",
                        "description": "",
                        "feedback_source": {
                            "type": "RESP-10",
                            "id": "RESP-10",
                        },
                    }
                ],
                "control_actions": [
                    {
                        "ca_id": "action-alpha",
                        "description": "",
                        "target": {
                            "type": "RESP-77",
                            "id": "CP-9",
                        },
                    }
                ],
                "feedback_channels": [
                    {
                        "fb_id": "feedback-alpha",
                        "description": "",
                        "updates": "state-alpha",
                        "source": {
                            "type": "CP-9",
                            "id": "CP-9",
                        },
                    }
                ],
            },
            {
                "resp_id": "RESP-10",
                "description": "Second controller",
                "responsibility_constraints": [],
                "process_model_parts": [],
                "control_actions": [],
                "feedback_channels": [],
            },
        ],
        "controlled_processes": [
            {"cp_id": "CP-8", "description": "First process"},
            {"cp_id": "CP-9", "description": ""},
        ],
        "coordination_links": [
            {
                "link_id": "link-alpha",
                "source": "RESP-9",
                "target": "RESP-10",
                "shared_pm": "state-alpha",
                "coordination_mechanism": {
                    "cm_id": "mechanism-alpha",
                    "description": "",
                    "payload": "state",
                },
                "description": "",
            }
        ],
    }


def test_normalization_infers_element_ref_types_before_rewriting_ids() -> None:
    result = normalize_control_structure_payload(_payload_with_references())

    responsibility = result.payload["responsibilities"][0]
    assert responsibility["process_model_parts"][0]["feedback_source"] == {
        "type": "responsibility",
        "id": "RESP-2",
    }
    assert responsibility["control_actions"][0]["target"] == {
        "type": "controlled_process",
        "id": "CP-2",
    }
    assert responsibility["feedback_channels"][0]["source"] == {
        "type": "controlled_process",
        "id": "CP-2",
    }
    ControlStructure.model_validate(result.payload)


def test_normalization_leaves_uninferable_element_ref_type_for_validation() -> None:
    payload = _payload_with_references()
    payload["responsibilities"][0]["control_actions"][0]["target"] = {
        "type": "process-alpha",
        "id": "process-alpha",
    }

    result = normalize_control_structure_payload(payload)

    assert result.payload["responsibilities"][0]["control_actions"][0]["target"] == {
        "type": "process-alpha",
        "id": "process-alpha",
    }
    with pytest.raises(ValueError, match="target"):
        ControlStructure.model_validate(result.payload)


def test_normalization_preserves_a_valid_reference_type() -> None:
    payload = _payload_with_references()
    payload["responsibilities"][0]["control_actions"][0]["target"] = {
        "type": "controlled_process",
        "id": "CP-9",
    }

    result = normalize_control_structure_payload(payload)

    assert result.payload["responsibilities"][0]["control_actions"][0]["target"] == {
        "type": "controlled_process",
        "id": "CP-2",
    }


@pytest.mark.parametrize(
    ("field", "source_id", "expected"),
    [
        (
            ("process_model_parts", "feedback_source"),
            "CP-9",
            {"type": "controlled_process", "id": "CP-2"},
        ),
        (
            ("control_actions", "target"),
            "RESP-10",
            {"type": "responsibility", "id": "RESP-2"},
        ),
        (
            ("feedback_channels", "source"),
            "CP-9",
            {"type": "controlled_process", "id": "CP-2"},
        ),
    ],
)
def test_normalization_wraps_bare_element_refs(
    field: tuple[str, str],
    source_id: str,
    expected: dict[str, str],
) -> None:
    payload = _payload_with_references()
    payload["responsibilities"][0][field[0]][0][field[1]] = source_id

    result = normalize_control_structure_payload(payload)

    assert result.payload["responsibilities"][0][field[0]][0][field[1]] == expected
    ControlStructure.model_validate(result.payload)


def test_normalization_leaves_unrecognized_bare_element_ref_for_validation() -> None:
    payload = _payload_with_references()
    payload["responsibilities"][0]["control_actions"][0]["target"] = "process-alpha"

    result = normalize_control_structure_payload(payload)

    assert result.payload["responsibilities"][0]["control_actions"][0]["target"] == (
        "process-alpha"
    )
    with pytest.raises(ValueError, match="target"):
        ControlStructure.model_validate(result.payload)


def test_normalization_preserves_null_element_refs() -> None:
    payload = _payload_with_references()
    payload["responsibilities"][0]["control_actions"][0]["target"] = None

    result = normalize_control_structure_payload(payload)

    assert result.payload["responsibilities"][0]["control_actions"][0]["target"] is None
    ControlStructure.model_validate(result.payload)


def test_normalization_converts_object_shaped_feedback_update_to_scalar() -> None:
    payload = _payload_with_references()
    payload["responsibilities"][0]["feedback_channels"][0]["updates"] = {
        "type": "process_model_part",
        "id": "state-alpha",
    }

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = normalize_control_structure_payload(
            construct_model_unvalidated(payload, ControlStructure)
        )

    assert not caught
    feedback = result.payload["responsibilities"][0]["feedback_channels"][0]
    assert feedback["updates"] == "PM-1-1"
    ControlStructure.model_validate(result.payload)


def test_normalization_leaves_ambiguous_object_feedback_update_for_validation() -> None:
    payload = _payload_with_references()
    payload["responsibilities"][0]["process_model_parts"].append(
        {"pm_id": "state-alpha", "description": "Second state"}
    )
    payload["responsibilities"][0]["feedback_channels"][0]["updates"] = {
        "type": "process_model_part",
        "id": "state-alpha",
    }

    result = normalize_control_structure_payload(
        construct_model_unvalidated(payload, ControlStructure)
    )

    feedback = result.payload["responsibilities"][0]["feedback_channels"][0]
    assert feedback["updates"] == {
        "type": "process_model_part",
        "id": "state-alpha",
    }
    with pytest.raises(ValueError) as exc_info:
        ControlStructure.model_validate(result.payload)
    assert "updates" in str(exc_info.value).lower()
    assert "unhashable" not in str(exc_info.value).lower()


@pytest.mark.parametrize(
    "updates",
    [
        {"type": "process_model_part", "id": "PM-UNKNOWN"},
        {"type": "control_action", "id": "CA-9-1"},
    ],
)
def test_normalization_leaves_unknown_feedback_update_shapes_for_validation(
    updates: dict[str, str],
) -> None:
    payload = _payload_with_references()
    payload["responsibilities"][0]["feedback_channels"][0]["updates"] = updates

    result = normalize_control_structure_payload(
        construct_model_unvalidated(payload, ControlStructure)
    )

    with pytest.raises(ValueError) as exc_info:
        ControlStructure.model_validate(result.payload)
    assert "updates" in str(exc_info.value).lower()
    assert "unhashable" not in str(exc_info.value).lower()


def test_namespace_resolves_id_shaped_element_ref_type() -> None:
    payload = _payload_with_references()
    payload["controlled_processes"][1]["cp_id"] = "process-alpha"
    payload["responsibilities"][0]["control_actions"][0]["target"] = {
        "type": "process-alpha",
        "id": "process-alpha",
    }
    payload["responsibilities"][0]["feedback_channels"][0]["source"] = {
        "type": "process-alpha",
        "id": "process-alpha",
    }

    result = normalize_control_structure_payload(payload)

    target = result.payload["responsibilities"][0]["control_actions"][0]["target"]
    assert target == {"type": "controlled_process", "id": "CP-2"}
    ControlStructure.model_validate(result.payload)


def test_normalization_repairs_empty_descriptions_from_canonical_context() -> None:
    result = normalize_control_structure_payload(_payload_with_references())
    payload = result.payload
    responsibility = payload["responsibilities"][0]

    assert responsibility["description"] == "Responsibility RESP-1"
    assert (
        responsibility["responsibility_constraints"][0]["description"]
        == "Responsibility constraint RC-1-1"
    )
    assert (
        responsibility["process_model_parts"][0]["description"]
        == "Process model part PM-1-1"
    )
    assert (
        responsibility["control_actions"][0]["description"] == "Control action CA-1-1"
    )
    assert (
        responsibility["feedback_channels"][0]["description"]
        == "Feedback from controlled process CP-2 updating process model part PM-1-1"
    )
    assert payload["controlled_processes"][1]["description"] == (
        "Controlled process CP-2"
    )
    assert payload["coordination_links"][0]["description"] == ("Coordination link CL-1")
    assert payload["coordination_links"][0]["coordination_mechanism"][
        "description"
    ] == ("Coordination mechanism CM-1")
    ControlStructure.model_validate(payload)


def test_empty_description_repair_preserves_nonempty_none_and_missing_values() -> None:
    payload = _payload_with_references()
    payload["responsibilities"][1]["description"] = None
    payload["responsibilities"][1]["process_model_parts"] = [{"pm_id": "state-beta"}]

    result = normalize_control_structure_payload(payload)

    second = result.payload["responsibilities"][1]
    assert second["description"] is None
    assert "description" not in second["process_model_parts"][0]
    assert result.payload["responsibilities"][0]["description"] == (
        "Responsibility RESP-1"
    )


def test_feedback_description_uses_fallbacks_for_missing_context() -> None:
    payload = _payload_with_references()
    feedback = payload["responsibilities"][0]["feedback_channels"][0]
    feedback["source"] = None
    feedback["description"] = ""
    result = normalize_control_structure_payload(payload)
    assert (
        result.payload["responsibilities"][0]["feedback_channels"][0]["description"]
        == "Feedback updating process model part PM-1-1"
    )

    no_update_payload = copy.deepcopy(payload)
    no_update_payload["responsibilities"][0]["feedback_channels"][0]["updates"] = ""
    no_update_result = normalize_control_structure_payload(no_update_payload)
    assert (
        no_update_result.payload["responsibilities"][0]["feedback_channels"][0][
            "description"
        ]
        == "Feedback channel FB-1-1"
    )


@pytest.mark.parametrize(
    ("model", "model_id_field", "source_id", "payload"),
    [
        (
            Responsibility,
            "resp_id",
            "RESP-9",
            {"id": "RESP-9", "description": "Controller"},
        ),
        (
            ResponsibilityConstraint,
            "rc_id",
            "RC-9-8",
            {"id": "RC-9-8", "description": "Constraint"},
        ),
        (
            ProcessModelPart,
            "pm_id",
            "PM-9-7",
            {"id": "PM-9-7", "description": "State"},
        ),
        (
            ControlAction,
            "ca_id",
            "CA-9-6",
            {"id": "CA-9-6", "description": "Action"},
        ),
        (
            FeedbackChannel,
            "fb_id",
            "FB-9-5",
            {"id": "FB-9-5", "description": "Feedback", "updates": "PM-9-7"},
        ),
        (
            ControlledProcess,
            "cp_id",
            "CP-4",
            {"id": "CP-4", "description": "Process"},
        ),
        (
            CoordinationLink,
            "link_id",
            "CL-3",
            {
                "id": "CL-3",
                "source": "RESP-1",
                "target": "RESP-2",
                "shared_pm": "PM-1-1",
                "coordination_mechanism": {
                    "id": "CM-3",
                    "description": "Mechanism",
                    "payload": "state",
                },
                "description": "Link",
            },
        ),
        (
            CoordinationMechanism,
            "cm_id",
            "CM-2",
            {"id": "CM-2", "description": "Mechanism", "payload": "state"},
        ),
    ],
)
def test_tolerant_decode_aliases_generic_id_for_required_element_ids(
    model: type,
    model_id_field: str,
    source_id: str,
    payload: dict,
) -> None:
    decoded = construct_model_unvalidated(payload, model)

    assert getattr(decoded, model_id_field) == source_id


def test_tolerant_decode_prefers_explicit_model_id_and_does_not_alias_description() -> (
    None
):
    decoded = construct_model_unvalidated(
        {"id": "ignored", "ca_id": "CA-7-2"},
        ControlAction,
    )

    assert decoded.ca_id == "CA-7-2"
    assert decoded.description == ""
