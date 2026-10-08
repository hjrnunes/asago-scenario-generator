"""A run publishes scenario-handoff-v4 with the shape the shape step produced.

The offline end-to-end tests drive ``run_sp3`` with a fake client: Stage 5
replies first, then one shape reply per adversarial scenario.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from asago_scenario_generator.stpa.models.attack_shape import (
    ShapeDowngradeReason,
    ShapeSource,
)
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    HANDOFF_SCHEMA_VERSION_V4,
    ScenarioHandoffV4,
    handoff_ownership_violations,
    verify_handoff_digest,
)
from asago_scenario_generator.stpa.scenario_prod.run import SP3RunResult, run_sp3
from asago_scenario_generator.stpa.scenario_prod.stage5.shape_step import (
    ForgedShapeProposal,
    ShapeProposal,
    ShapeStepConfig,
)
from tests.helpers.stpa_builders import make_cs, make_loss_analysis
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_scenario_handoff_publication import (
    _functional_payload,
    _normal_semantics_payload,
    _published_handoff,
)
from tests.stpa.test_shape_step_call import DIRECT_REPLY
from tests.helpers.sp3_run import _make_ets

SCHEMA = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "data/contracts/scenario-handoff/handoff-v4/schema.json"
    ).read_text(encoding="utf-8")
)


def publish(
    payloads: list[dict],
    run_dir: Path,
    *,
    shape_reply: object = DIRECT_REPLY,
    shape_error: Exception | None = None,
    **kwargs: object,
) -> tuple[SP3RunResult, MockLLMClient]:
    client = MockLLMClient()
    client.set_response_queue(payloads)
    client.set_response_for(ShapeProposal, shape_reply)
    if shape_error is not None:
        client.set_exception_for(ShapeProposal, shape_error)
    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=len(payloads)),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=run_dir,
        **kwargs,
    )
    return result, client


def assert_valid_v4(document: dict) -> ScenarioHandoffV4:
    errors = list(Draft202012Validator(SCHEMA).iter_errors(document))
    assert errors == []
    assert handoff_ownership_violations(document) == []
    handoff = ScenarioHandoffV4.model_validate(document)
    verify_handoff_digest(handoff)
    return handoff


def test_an_adversarial_run_publishes_v4_with_the_validated_shape(
    tmp_path: Path,
) -> None:
    result, client = publish([_normal_semantics_payload()], tmp_path)

    document = _published_handoff(tmp_path)
    assert document["schema_version"] == HANDOFF_SCHEMA_VERSION_V4
    handoff = assert_valid_v4(document)
    assert handoff.attack_shape is not None
    assert handoff.attack_shape.source is ShapeSource.STAGE5_VALIDATED
    assert handoff.attack_shape.turn_count == 2
    assert [call.response_format for call in client.calls][1:] == [ShapeProposal]
    assert client.call_count == 2
    assert result.stage_errors == []
    assert result.scenario_specs[0].attack_shape == handoff.attack_shape


def test_a_failing_shape_request_publishes_the_code_default(tmp_path: Path) -> None:
    result, client = publish(
        [_normal_semantics_payload()], tmp_path, shape_error=RuntimeError("transport")
    )

    handoff = assert_valid_v4(_published_handoff(tmp_path))
    shape = handoff.attack_shape
    assert shape is not None
    assert shape.source is ShapeSource.CODE_DEFAULT
    assert shape.downgrade_reason is ShapeDowngradeReason.SHAPE_CALL_FAILED
    assert shape.turn_count == 1
    assert client.call_count == 2
    assert result.stage_errors == []


def test_a_functional_scenario_publishes_a_null_shape_and_costs_no_request(
    tmp_path: Path,
) -> None:
    result, client = publish([_functional_payload()], tmp_path)

    document = _published_handoff(tmp_path)
    assert document["schema_version"] == HANDOFF_SCHEMA_VERSION_V4
    assert document["kind"] == "functional"
    assert "attack_shape" in document and document["attack_shape"] is None
    assert_valid_v4(document)
    assert client.call_count == 1
    assert result.functional_test_specs[0].attack_shape is None


def test_a_mixed_run_makes_one_shape_request_per_adversarial_scenario(
    tmp_path: Path,
) -> None:
    _, client = publish([_normal_semantics_payload(), _functional_payload()], tmp_path)

    assert client.call_count == 3
    adversarial = assert_valid_v4(_published_handoff(tmp_path, "SCN-001"))
    functional = assert_valid_v4(_published_handoff(tmp_path, "SCN-002"))
    assert adversarial.attack_shape is not None
    assert functional.attack_shape is None


def test_duplicates_keep_the_scenario_whose_shape_the_model_proposed(
    tmp_path: Path,
) -> None:
    invalid_reply = {**DIRECT_REPLY, "channel": "not_a_channel"}
    publish(
        [_normal_semantics_payload(), _normal_semantics_payload()],
        tmp_path,
        shape_reply=[invalid_reply, DIRECT_REPLY],
    )

    first = assert_valid_v4(_published_handoff(tmp_path, "SCN-001"))
    second = assert_valid_v4(_published_handoff(tmp_path, "SCN-002"))
    assert first.attack_shape.source is ShapeSource.CODE_DEFAULT
    assert second.attack_shape.source is ShapeSource.STAGE5_VALIDATED
    assert first.deduplication.status == "duplicate"
    assert first.deduplication.duplicate_of == "SCN-002"
    assert second.deduplication.status == "canonical"
    summary = yaml.safe_load((tmp_path / "testability.yaml").read_text())
    assert {
        row["scenario_id"]: (row["status"], row["duplicate_of"])
        for row in summary["scenarios"]
    } == {"SCN-001": ("duplicate", "SCN-002"), "SCN-002": ("canonical", None)}


def test_the_forged_channel_stays_off_unless_the_run_enables_it(
    tmp_path: Path,
) -> None:
    forged_reply = {
        "channel": "forged_transcript",
        "turn_count": 2,
        "turn_plan": [
            {"position": 1, "speaker": "forged_assistant", "purpose": "forged_history"},
            {"position": 2, "speaker": "attacker_user", "purpose": "request_action"},
        ],
        "indirect": None,
    }
    publish([_normal_semantics_payload()], tmp_path / "off", shape_reply=forged_reply)
    off = assert_valid_v4(_published_handoff(tmp_path / "off"))
    assert off.attack_shape.downgrade_reason is ShapeDowngradeReason.SHAPE_CALL_FAILED

    client = MockLLMClient()
    client.set_response_queue([_normal_semantics_payload()])
    client.set_response_for(ForgedShapeProposal, forged_reply)
    run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=1),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=tmp_path / "on",
        shape_config=ShapeStepConfig(allow_forged_transcript=True),
    )
    on = assert_valid_v4(_published_handoff(tmp_path / "on"))
    assert on.attack_shape.channel.value == "forged_transcript"
    assert on.attack_shape.threat_label == "forged_transcript_threat"


@pytest.mark.parametrize("scenario_count", [1, 2])
def test_the_request_count_is_stage5_plus_one_shape_request_per_adversary(
    scenario_count: int, tmp_path: Path
) -> None:
    _, client = publish(
        [_normal_semantics_payload() for _ in range(scenario_count)], tmp_path
    )

    assert client.call_count == 2 * scenario_count
