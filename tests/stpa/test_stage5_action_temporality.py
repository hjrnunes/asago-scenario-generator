"""The scenario context carries the control action's typed temporality.

Stage 5 offers a duration condition only for a ``continuous`` or
``bounded_duration`` action, and states the action's temporality in the
prompt. Both read the temporality from the described action in the scenario
context, so the context builder has to copy it from the control structure.
"""

from __future__ import annotations

import json

import pytest

from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionTemporality,
    ControlStructure,
)
from asago_scenario_generator.stpa.models.scenario_context import (
    DescribedControlAction,
    ScenarioGenerationContext,
)
from asago_scenario_generator.stpa.models.semantic_conditions import DurationCondition
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    _control_action_semantics,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.sources import (
    _action_duration_eligible,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.stage5_wire import normal_wire_queue
from tests.helpers.sp3_scenario_continuity import (
    _control_structure,
    _loss_analysis,
    _threat,
)

T = ControlActionTemporality


def _structure(temporality: ControlActionTemporality | None) -> ControlStructure:
    """The shared fixture structure with one action of the given temporality."""
    structure = _control_structure()
    responsibility = structure.responsibilities[0]
    action = responsibility.control_actions[0].model_copy(
        update={"temporality": temporality}
    )
    return structure.model_copy(
        update={
            "responsibilities": [
                responsibility.model_copy(update={"control_actions": [action]})
            ]
        }
    )


def _context(temporality: ControlActionTemporality | None) -> ScenarioGenerationContext:
    return build_scenario_generation_context(
        _threat(),
        _structure(temporality),
        _loss_analysis(),
        scenario_id="SCN-TEMPORALITY",
    )


@pytest.mark.parametrize("temporality", list(ControlActionTemporality))
def test_the_described_action_carries_the_structures_temporality(temporality) -> None:
    action = _context(temporality).target_control_path.control_action

    assert action.temporality is temporality


def test_a_structure_without_temporality_leaves_it_unset() -> None:
    action = _context(None).target_control_path.control_action

    assert action.temporality is None


@pytest.mark.parametrize(
    ("temporality", "eligible"),
    [
        (T.continuous, True),
        (T.bounded_duration, True),
        (T.instantaneous, False),
        (T.discrete, False),
        (T.unknown, False),
        (None, False),
    ],
)
def test_only_a_continuous_or_bounded_duration_action_is_duration_eligible(
    temporality, eligible
) -> None:
    action = _context(temporality).target_control_path.control_action

    assert _action_duration_eligible(action) is eligible


def test_the_prompt_states_the_actions_temporality_and_eligibility() -> None:
    action = _context(T.continuous).target_control_path.control_action

    semantics = _control_action_semantics(action)

    assert semantics["temporality"] == "continuous"
    assert semantics["duration_eligibility"] == "eligible"


def test_the_prompt_says_unknown_when_no_temporality_is_carried() -> None:
    action = _context(None).target_control_path.control_action

    semantics = _control_action_semantics(action)

    assert semantics["temporality"] == "unknown"
    assert semantics["duration_eligibility"] == "not_established"


def test_the_context_digest_survives_a_round_trip_with_temporality() -> None:
    context = _context(T.bounded_duration)

    restored = ScenarioGenerationContext.model_validate(context.model_dump(mode="json"))

    assert restored == context


def test_an_unset_temporality_is_left_out_of_the_serialized_action() -> None:
    action = DescribedControlAction(
        action_id="CA-1", description="Act", target_id="CP-1"
    )

    assert "temporality" not in action.model_dump(mode="json")


def test_a_context_digest_without_temporality_does_not_change() -> None:
    """A context whose action has no temporality keeps its serialized form."""
    context = _context(None)

    payload = context.model_dump(mode="json")

    assert "temporality" not in payload["target_control_path"]["control_action"]
    assert ScenarioGenerationContext.model_validate(payload) == context


def _duration_payload() -> dict:
    return {
        "adversary": {"kind": "malicious_customer", "gain": "Keeps access."},
        "attacker_bdi": {
            "beliefs": ["The authorization stays active."],
            "desires": ["Hold the action open."],
            "intentions": [
                {"description": "Keep the session open.", "source_handles": ["cause_1"]}
            ],
        },
        "causal_factors": [
            {
                "source_handle": "cause_1",
                "evidence": "The selected authorization state can remain stale.",
                "temporal_condition": {
                    "type": "duration",
                    "reference_handle": "cause_1",
                    "duration_ms": 5000,
                },
                "evidence_status": "structural_failure",
            }
        ],
        "unsafe_outcome": {
            "semantic_proposition": "The authorization stays active too long.",
        },
    }


def _schema_text(client: MockLLMClient) -> str:
    return json.dumps(client.calls[0].response_format.model_json_schema())


def test_a_continuous_action_accepts_a_duration_condition(tmp_path) -> None:
    client = MockLLMClient()
    client.set_response_queue(normal_wire_queue([_duration_payload()]))

    result, error = generate_bdi_for_context(client, _context(T.continuous), tmp_path)

    assert error is None
    assert result is not None
    assert '"duration"' in _schema_text(client)
    assert isinstance(result.causal_factors[0].temporal_condition, DurationCondition)


def test_an_instantaneous_action_offers_no_duration_condition(tmp_path) -> None:
    client = MockLLMClient()
    client.set_response_queue(normal_wire_queue([_duration_payload()]))

    result, error = generate_bdi_for_context(
        client, _context(T.instantaneous), tmp_path
    )

    assert result is None
    assert error is not None
    assert '"duration"' not in _schema_text(client)
