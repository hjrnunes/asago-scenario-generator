"""A run publishes scenario-handoff-v1 with the shape the shape step produced.

The offline end-to-end tests drive ``run_sp3`` with a fake client: Stage 5
replies first, then one shape reply per adversarial scenario. The counts
leave out the belief, narrate and Gherkin requests that follow Stage 5.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from asago_scenario_generator.stpa.models.attack_shape import (
    ItemController,
    ShapeDowngradeReason,
    ShapeSource,
)
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    HANDOFF_SCHEMA_VERSION,
    ScenarioHandoff,
    handoff_ownership_violations,
    verify_handoff_digest,
)
from asago_scenario_generator.stpa.scenario_prod.handoff_schema import handoff_schema
from asago_scenario_generator.stpa.scenario_prod.run import SP3RunResult, run_sp3
from asago_scenario_generator.stpa.scenario_prod.stage5.shape_step import (
    ShapeProposal,
)
from tests.helpers.stpa_builders import (
    make_capability_profile,
    make_cs,
    make_loss_analysis,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.shape_fixtures import profile_with_influence
from tests.helpers.scenario_handoff_publication import (
    _functional_payload,
    _normal_semantics_payload,
    _published_handoff,
)
from tests.helpers.shape_step_call import DIRECT_REPLY
from tests.helpers.sp3_run import _make_ets, stage5_and_shape_calls

SCHEMA = handoff_schema()

#: The shape reply for a third party that reaches the agent through content.
INDIRECT_REPLY = {
    "channel": "indirect",
    "turn_count": 2,
    "turn_plan": [
        {"position": 1, "speaker": "benign_user", "purpose": "establish_context"},
        {"position": 2, "speaker": "benign_user", "purpose": "ask_to_read_item"},
    ],
    "indirect": {
        "carrier_operation": "get_listing",
        "content_kind": "listing_content",
        "controller": "counterparty",
    },
}


def _indirect_payload() -> dict:
    """The normal-path wire with a third party that plants content."""
    payload = _normal_semantics_payload()
    payload["adversary"] = {
        "kind": "third_party_via_content",
        "gain": "Reads a record the assistant was not asked to read.",
    }
    return payload


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


def assert_valid(document: dict) -> ScenarioHandoff:
    errors = list(Draft202012Validator(SCHEMA).iter_errors(document))
    assert errors == []
    assert handoff_ownership_violations(document) == []
    handoff = ScenarioHandoff.model_validate(document)
    verify_handoff_digest(handoff)
    return handoff


def test_an_adversarial_run_publishes_the_validated_shape(
    tmp_path: Path,
) -> None:
    result, client = publish([_normal_semantics_payload()], tmp_path)

    document = _published_handoff(tmp_path)
    assert document["schema_version"] == HANDOFF_SCHEMA_VERSION
    handoff = assert_valid(document)
    assert handoff.attack_shape is not None
    assert handoff.attack_shape.source is ShapeSource.STAGE5_VALIDATED
    assert handoff.attack_shape.turn_count == 2
    calls = stage5_and_shape_calls(client)
    assert [call.response_format for call in calls][1:] == [ShapeProposal]
    assert len(calls) == 2
    assert result.stage_errors == []
    assert result.scenario_specs[0].attack_shape == handoff.attack_shape


def test_an_indirect_run_publishes_the_controlling_party_under_its_wire_name(
    tmp_path: Path,
) -> None:
    """A reader sees ``party_relation.controlling_party``; the schema accepts it."""

    publish(
        [_indirect_payload()],
        tmp_path,
        shape_reply=INDIRECT_REPLY,
        capability_profile=make_capability_profile(kc_subcodes=["KC6.3.3"]),
        execution_target_profile=profile_with_influence({"get_listing": "indirect"}),
    )

    document = _published_handoff(tmp_path)
    indirect = document["attack_shape"]["indirect"]
    assert indirect["party_relation"]["controlling_party"] == "counterparty"
    assert "controller" not in indirect["party_relation"]
    handoff = assert_valid(document)
    assert handoff.attack_shape is not None
    assert handoff.attack_shape.source is ShapeSource.STAGE5_VALIDATED
    assert handoff.attack_shape.indirect is not None
    assert (
        handoff.attack_shape.indirect.party_relation.controller
        is ItemController.COUNTERPARTY
    )


def test_a_failing_shape_request_publishes_the_code_default(tmp_path: Path) -> None:
    result, client = publish(
        [_normal_semantics_payload()], tmp_path, shape_error=RuntimeError("transport")
    )

    handoff = assert_valid(_published_handoff(tmp_path))
    shape = handoff.attack_shape
    assert shape is not None
    assert shape.source is ShapeSource.CODE_DEFAULT
    assert shape.downgrade_reason is ShapeDowngradeReason.SHAPE_CALL_FAILED
    assert shape.turn_count == 1
    assert len(stage5_and_shape_calls(client)) == 2
    assert result.stage_errors == []


def test_a_functional_scenario_publishes_a_null_shape_and_costs_no_request(
    tmp_path: Path,
) -> None:
    result, client = publish([_functional_payload()], tmp_path)

    document = _published_handoff(tmp_path)
    assert document["schema_version"] == HANDOFF_SCHEMA_VERSION
    assert document["kind"] == "functional"
    assert "attack_shape" in document and document["attack_shape"] is None
    assert_valid(document)
    assert len(stage5_and_shape_calls(client)) == 1
    assert result.functional_test_specs[0].attack_shape is None


def test_a_mixed_run_makes_one_shape_request_per_adversarial_scenario(
    tmp_path: Path,
) -> None:
    _, client = publish([_normal_semantics_payload(), _functional_payload()], tmp_path)

    assert len(stage5_and_shape_calls(client)) == 3
    adversarial = assert_valid(_published_handoff(tmp_path, "SCN-001"))
    functional = assert_valid(_published_handoff(tmp_path, "SCN-002"))
    assert adversarial.attack_shape is not None
    assert functional.attack_shape is None


def test_duplicates_keep_the_scenario_whose_shape_the_model_proposed(
    tmp_path: Path,
) -> None:
    invalid_reply = {**DIRECT_REPLY, "channel": "not_a_channel"}
    publish(
        [_normal_semantics_payload(), _normal_semantics_payload()],
        tmp_path,
        shape_reply=[invalid_reply, invalid_reply, DIRECT_REPLY],
    )

    first = assert_valid(_published_handoff(tmp_path, "SCN-001"))
    second = assert_valid(_published_handoff(tmp_path, "SCN-002"))
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


@pytest.mark.parametrize("scenario_count", [1, 2])
def test_the_request_count_is_stage5_plus_one_shape_request_per_adversary(
    scenario_count: int, tmp_path: Path
) -> None:
    _, client = publish(
        [_normal_semantics_payload() for _ in range(scenario_count)], tmp_path
    )

    assert len(stage5_and_shape_calls(client)) == 2 * scenario_count
