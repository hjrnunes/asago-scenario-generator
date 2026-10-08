"""The shape step's model request per adversarial scenario, and its one correction.

Every test uses a fake client. A reply that breaks a rule earns one correction
naming each broken rule; any other failure never repeats. Neither stops the
run: a scenario without a valid reply takes the single-turn direct default and
records why.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from asago_scenario_generator.stpa.infra.provider_record import ReplayMissError
from asago_scenario_generator.stpa.models.attack_shape import (
    AttackChannel,
    ShapeDowngradeReason,
    ShapeSource,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    Adversary,
    AdversaryKind,
    AdversaryReach,
    ScenarioSpec,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.shape_step import (
    ForgedShapeProposal,
    ShapeProposal,
    ShapeStepConfig,
    apply_shape_step,
)
from tests.stpa.helpers import make_scenario_spec
from tests.stpa.shape_fixtures import profile_with_influence
from tests.stpa.sp1_helpers import MockLLMClient
from tests.helpers.shape_step_call import DIRECT_REPLY

SNAPSHOTS = Path(__file__).parent / "shape_step_prompts"

REACH = {
    AdversaryKind.external_attacker: AdversaryReach.user_message,
    AdversaryKind.malicious_customer: AdversaryReach.user_message,
    AdversaryKind.third_party_via_content: AdversaryReach.retrieved_content,
    AdversaryKind.none: None,
}


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
        "record_ref": None,
        "controller": "counterparty",
    },
}


def spec_for(kind: AdversaryKind, scenario_id: str = "SCN-001") -> ScenarioSpec:
    adversary = Adversary(
        kind=kind,
        gain="Learns another customer's order.",
        reaches_target_via=REACH[kind],
    )
    return make_scenario_spec(scenario_id).model_copy(update={"adversary": adversary})


def run_step(
    client: MockLLMClient,
    specs: list[ScenarioSpec],
    tmp_path: Path,
    *,
    influence: dict[str, str] | None = None,
    config: ShapeStepConfig | None = None,
) -> list[ScenarioSpec]:
    return apply_shape_step(
        specs,
        llm_client=client,
        run_dir=tmp_path,
        execution_target_profile=profile_with_influence(
            influence or {"get_listing": "indirect", "refund": "unknown"}
        ),
        config=config or ShapeStepConfig(),
    )


def client_replying(reply: object, model: type = ShapeProposal) -> MockLLMClient:
    client = MockLLMClient()
    client.set_response_for(model, reply)
    return client


@pytest.mark.parametrize(
    "kind",
    [
        AdversaryKind.external_attacker,
        AdversaryKind.malicious_customer,
        AdversaryKind.third_party_via_content,
    ],
)
def test_each_adversary_kind_gets_one_request_with_a_pinned_prompt(
    kind: AdversaryKind, tmp_path: Path
) -> None:
    client = client_replying(
        INDIRECT_REPLY
        if kind is AdversaryKind.third_party_via_content
        else DIRECT_REPLY
    )

    run_step(client, [spec_for(kind)], tmp_path)

    assert len(client.calls) == 1
    call = client.calls[0]
    assert call.response_format is ShapeProposal
    rendered = f"{call.system_prompt}\n=====\n{call.user_prompt}\n"
    assert rendered == (SNAPSHOTS / f"{kind.value}.txt").read_text(encoding="utf-8")


def test_a_valid_direct_reply_becomes_the_specs_shape(tmp_path: Path) -> None:
    client = client_replying(DIRECT_REPLY)

    (spec,) = run_step(client, [spec_for(AdversaryKind.malicious_customer)], tmp_path)

    shape = spec.attack_shape
    assert shape is not None
    assert shape.source is ShapeSource.STAGE5_VALIDATED
    assert shape.turn_count == 2
    assert shape.channel is AttackChannel.DIRECT


def test_a_valid_indirect_reply_names_an_influenced_carrier(tmp_path: Path) -> None:
    client = client_replying(INDIRECT_REPLY)

    (spec,) = run_step(
        client, [spec_for(AdversaryKind.third_party_via_content)], tmp_path
    )

    assert spec.attack_shape is not None
    assert spec.attack_shape.source is ShapeSource.STAGE5_VALIDATED
    assert spec.attack_shape.indirect.carrier_operation == "get_listing"


NO_READ_REPLY = {
    **INDIRECT_REPLY,
    "turn_plan": [
        {"position": 1, "speaker": "benign_user", "purpose": "establish_context"},
        {"position": 2, "speaker": "benign_user", "purpose": "request_action"},
    ],
}


def correction_errors(client: MockLLMClient) -> str:
    """Return the itemized error a correction request carries."""
    prompt = client.calls[1].user_prompt
    assert prompt.startswith(client.calls[0].user_prompt)
    tail = prompt.split("Exact validation error from the prior response:\n", 1)[1]
    return tail.split("\n\n", 1)[0]


def test_a_reply_without_an_item_read_earns_one_correction_naming_the_rule(
    tmp_path: Path,
) -> None:
    client = client_replying([NO_READ_REPLY, INDIRECT_REPLY])

    (spec,) = run_step(
        client, [spec_for(AdversaryKind.third_party_via_content)], tmp_path
    )

    assert len(client.calls) == 2
    assert correction_errors(client) == (
        "ValueError: the reply breaks these rules:\n"
        "- R4: an indirect shape needs an ask_to_read_item turn\n"
        "Operations marked `outside content: yes`: `get_listing`."
    )
    assert '"purpose": "request_action"' in client.calls[1].user_prompt
    assert spec.attack_shape.source is ShapeSource.STAGE5_VALIDATED


def test_a_correction_names_every_rule_the_reply_breaks(tmp_path: Path) -> None:
    reply = {
        **INDIRECT_REPLY,
        "turn_plan": [
            {"position": 1, "speaker": "attacker_user", "purpose": "ask_to_read_item"},
            {"position": 3, "speaker": "benign_user", "purpose": "request_action"},
        ],
        "indirect": {**INDIRECT_REPLY["indirect"], "carrier_operation": "refund"},
    }
    client = client_replying([reply, INDIRECT_REPLY])

    run_step(client, [spec_for(AdversaryKind.third_party_via_content)], tmp_path)

    assert correction_errors(client) == (
        "ValueError: the reply breaks these rules:\n"
        "- R2: turn positions [1, 3] are not 1..2\n"
        "- R4: an indirect shape has only benign_user turns\n"
        "- R6: purpose ask_to_read_item belongs to benign_user\n"
        "- carrier_operation `refund` is not marked `outside content: yes`\n"
        "Operations marked `outside content: yes`: `get_listing`."
    )


def test_a_direct_correction_names_its_rules_without_the_operation_list(
    tmp_path: Path,
) -> None:
    reply = {
        **DIRECT_REPLY,
        "turn_plan": [
            {"position": 1, "speaker": "benign_user", "purpose": "establish_context"},
            {"position": 2, "speaker": "attacker_user", "purpose": "request_action"},
        ],
    }
    client = client_replying([reply, DIRECT_REPLY])

    (spec,) = run_step(client, [spec_for(AdversaryKind.malicious_customer)], tmp_path)

    assert correction_errors(client) == (
        "ValueError: the reply breaks these rules:\n"
        "- R3: a direct shape has only attacker_user turns"
    )
    assert spec.attack_shape.source is ShapeSource.STAGE5_VALIDATED


def test_a_disallowed_channel_earns_a_correction_naming_the_allowed_ones(
    tmp_path: Path,
) -> None:
    client = client_replying([INDIRECT_REPLY, DIRECT_REPLY])

    run_step(client, [spec_for(AdversaryKind.malicious_customer)], tmp_path)

    assert correction_errors(client) == (
        "ValueError: the reply breaks these rules:\n"
        "- channel `indirect` is not allowed for this scenario; allowed: `direct`"
    )


def test_an_unobserved_carrier_earns_a_correction(tmp_path: Path) -> None:
    unseen = {
        **INDIRECT_REPLY,
        "indirect": {**INDIRECT_REPLY["indirect"], "carrier_operation": "get_policy"},
    }
    client = client_replying([unseen, unseen])

    (spec,) = run_step(
        client, [spec_for(AdversaryKind.third_party_via_content)], tmp_path
    )

    assert correction_errors(client) == (
        "ValueError: the reply breaks these rules:\n"
        "- R8: carrier_operation `get_policy` is not an operation the target offers\n"
        "Operations marked `outside content: yes`: `get_listing`."
    )
    assert (
        spec.attack_shape.downgrade_reason is ShapeDowngradeReason.CARRIER_NOT_OBSERVED
    )


def test_a_valid_reply_earns_no_correction(tmp_path: Path) -> None:
    client = client_replying([INDIRECT_REPLY, INDIRECT_REPLY])

    run_step(client, [spec_for(AdversaryKind.third_party_via_content)], tmp_path)

    assert len(client.calls) == 1


def test_a_corrected_reply_that_still_fails_downgrades_with_its_reason(
    tmp_path: Path,
) -> None:
    client = client_replying([NO_READ_REPLY, NO_READ_REPLY, INDIRECT_REPLY])

    (spec,) = run_step(
        client, [spec_for(AdversaryKind.third_party_via_content)], tmp_path
    )

    assert len(client.calls) == 2
    assert spec.attack_shape.source is ShapeSource.CODE_DEFAULT
    assert (
        spec.attack_shape.downgrade_reason
        is ShapeDowngradeReason.SHAPE_VALIDATION_FAILED
    )


def test_an_uninfluenced_carrier_downgrades_after_one_correction(
    tmp_path: Path,
) -> None:
    client = client_replying([INDIRECT_REPLY, INDIRECT_REPLY, INDIRECT_REPLY])

    (spec,) = run_step(
        client,
        [spec_for(AdversaryKind.third_party_via_content)],
        tmp_path,
        influence={"get_listing": "unknown", "refund": "indirect"},
    )

    assert len(client.calls) == 2
    assert correction_errors(client) == (
        "ValueError: the reply breaks these rules:\n"
        "- carrier_operation `get_listing` is not marked `outside content: yes`\n"
        "Operations marked `outside content: yes`: `refund`."
    )
    assert spec.attack_shape.source is ShapeSource.CODE_DEFAULT
    assert (
        spec.attack_shape.downgrade_reason
        is ShapeDowngradeReason.NO_ATTACKER_INFLUENCED_OPERATION
    )


def test_an_indirect_only_scenario_without_an_influenced_operation_sends_no_request(
    tmp_path: Path,
) -> None:
    client = client_replying(INDIRECT_REPLY)

    (spec,) = run_step(
        client,
        [spec_for(AdversaryKind.third_party_via_content)],
        tmp_path,
        influence={"get_listing": "unknown"},
    )

    assert client.calls == []
    assert spec.attack_shape.source is ShapeSource.CODE_DEFAULT
    assert (
        spec.attack_shape.downgrade_reason
        is ShapeDowngradeReason.NO_ATTACKER_INFLUENCED_OPERATION
    )


def test_a_direct_scenario_without_an_influenced_operation_still_asks(
    tmp_path: Path,
) -> None:
    client = client_replying(DIRECT_REPLY)

    (spec,) = run_step(
        client,
        [spec_for(AdversaryKind.malicious_customer)],
        tmp_path,
        influence={"get_listing": "unknown"},
    )

    assert len(client.calls) == 1
    assert spec.attack_shape.source is ShapeSource.STAGE5_VALIDATED


def test_a_scenario_without_a_target_profile_cannot_confirm_its_carrier(
    tmp_path: Path,
) -> None:
    client = client_replying(INDIRECT_REPLY)

    (spec,) = apply_shape_step(
        [spec_for(AdversaryKind.third_party_via_content)],
        llm_client=client,
        run_dir=tmp_path,
        execution_target_profile=None,
        config=ShapeStepConfig(),
    )

    assert client.calls == []
    assert (
        spec.attack_shape.downgrade_reason is ShapeDowngradeReason.CARRIER_NOT_OBSERVED
    )


def failing_clients() -> dict[str, tuple[MockLLMClient, int]]:
    """Each failing client, and the requests it costs before the default."""
    raising = MockLLMClient()
    raising.set_exception_for(ShapeProposal, RuntimeError("transport"))
    missing = MockLLMClient()
    missing.set_exception_for(ShapeProposal, ReplayMissError("no recorded response"))
    unparseable = MockLLMClient()
    unparseable.set_invalid_response_for(ShapeProposal)
    schema_violation = {**DIRECT_REPLY, "text": "hello"}
    return {
        "exception": (raising, 1),
        "replay miss": (missing, 1),
        "not json": (unparseable, 1),
        "schema violation": (client_replying([schema_violation] * 3), 2),
        "empty reply": (MockLLMClient(), 1),
    }


@pytest.mark.parametrize("name", list(failing_clients()))
def test_a_failed_request_becomes_the_code_default(name: str, tmp_path: Path) -> None:
    client, requests = failing_clients()[name]

    (spec,) = run_step(client, [spec_for(AdversaryKind.malicious_customer)], tmp_path)

    assert len(client.calls) == requests
    assert spec.attack_shape.source is ShapeSource.CODE_DEFAULT
    assert spec.attack_shape.downgrade_reason is ShapeDowngradeReason.SHAPE_CALL_FAILED
    assert spec.attack_shape.turn_count == 1


def test_one_failure_does_not_disturb_the_next_scenario(tmp_path: Path) -> None:
    client = MockLLMClient()
    client.set_response_queue([{"channel": "nonsense"}] * 2 + [DIRECT_REPLY])
    specs = [
        spec_for(AdversaryKind.malicious_customer, "SCN-001"),
        spec_for(AdversaryKind.malicious_customer, "SCN-002"),
    ]

    failed, kept = run_step(client, specs, tmp_path)

    assert (
        failed.attack_shape.downgrade_reason is ShapeDowngradeReason.SHAPE_CALL_FAILED
    )
    assert kept.attack_shape.source is ShapeSource.STAGE5_VALIDATED


def test_a_functional_scenario_gets_no_shape_and_no_request(tmp_path: Path) -> None:
    client = client_replying(DIRECT_REPLY)
    functional = spec_for(AdversaryKind.none)

    (spec,) = run_step(client, [functional], tmp_path)

    assert client.calls == []
    assert spec.attack_shape is None


def test_the_request_log_names_the_stage_and_scenario(tmp_path: Path) -> None:
    client = client_replying(DIRECT_REPLY)

    run_step(client, [spec_for(AdversaryKind.malicious_customer)], tmp_path)

    logs = sorted(tmp_path.rglob("*.jsonl"))
    assert logs
    text = "\n".join(path.read_text(encoding="utf-8") for path in logs)
    assert "stage5_shape" in text
    assert "SCN-001" in text


def test_the_forged_flag_widens_the_response_model_and_the_prompt(
    tmp_path: Path,
) -> None:
    forged = {
        "channel": "forged_transcript",
        "turn_count": 2,
        "turn_plan": [
            {"position": 1, "speaker": "forged_assistant", "purpose": "forged_history"},
            {"position": 2, "speaker": "attacker_user", "purpose": "request_action"},
        ],
        "indirect": None,
    }
    client = client_replying(forged, ForgedShapeProposal)

    (spec,) = run_step(
        client,
        [spec_for(AdversaryKind.malicious_customer)],
        tmp_path,
        config=ShapeStepConfig(allow_forged_transcript=True),
    )

    assert client.calls[0].response_format is ForgedShapeProposal
    assert "forged_transcript" in client.calls[0].user_prompt
    assert spec.attack_shape.channel is AttackChannel.FORGED_TRANSCRIPT


def test_the_default_prompt_never_offers_the_forged_channel(tmp_path: Path) -> None:
    client = client_replying(DIRECT_REPLY)

    run_step(client, [spec_for(AdversaryKind.malicious_customer)], tmp_path)

    call = client.calls[0]
    assert "forged" not in call.system_prompt + call.user_prompt


def rendered_shape_request(
    kind: AdversaryKind, tmp_path: Path, config: ShapeStepConfig | None = None
) -> tuple[str, str]:
    config = config or ShapeStepConfig()
    model = ForgedShapeProposal if config.allow_forged_transcript else ShapeProposal
    reply = (
        INDIRECT_REPLY
        if kind is AdversaryKind.third_party_via_content
        else DIRECT_REPLY
    )
    client = client_replying(reply, model)
    run_step(client, [spec_for(kind)], tmp_path, config=config)
    call = client.calls[0]
    return call.system_prompt, call.user_prompt


@pytest.mark.parametrize(
    ("kind", "config"),
    [
        (AdversaryKind.external_attacker, ShapeStepConfig()),
        (AdversaryKind.malicious_customer, ShapeStepConfig()),
        (AdversaryKind.third_party_via_content, ShapeStepConfig()),
        (
            AdversaryKind.malicious_customer,
            ShapeStepConfig(allow_forged_transcript=True),
        ),
    ],
)
def test_the_indirect_field_text_leads_with_the_carrier_requirement(
    kind: AdversaryKind, config: ShapeStepConfig, tmp_path: Path
) -> None:
    system, _ = rendered_shape_request(kind, tmp_path, config)

    (field,) = [line for line in system.splitlines() if line.startswith("`indirect`:")]
    assert field.startswith("`indirect`: required when `channel` is `indirect`")
    assert "`null` otherwise" in field


@pytest.mark.parametrize(
    ("kind", "config"),
    [
        (AdversaryKind.external_attacker, ShapeStepConfig()),
        (AdversaryKind.malicious_customer, ShapeStepConfig()),
        (AdversaryKind.third_party_via_content, ShapeStepConfig()),
        (
            AdversaryKind.third_party_via_content,
            ShapeStepConfig(allow_forged_transcript=True),
        ),
    ],
)
def test_the_request_never_asks_for_a_record_reference(
    kind: AdversaryKind, config: ShapeStepConfig, tmp_path: Path
) -> None:
    system, user = rendered_shape_request(kind, tmp_path, config)

    assert "record_ref" not in system + user


@pytest.mark.parametrize(
    "kind", [AdversaryKind.external_attacker, AdversaryKind.malicious_customer]
)
@pytest.mark.parametrize("forged", [False, True])
def test_a_scenario_that_cannot_use_indirect_gets_no_carrier_instruction(
    kind: AdversaryKind, forged: bool, tmp_path: Path
) -> None:
    config = ShapeStepConfig(allow_forged_transcript=forged)

    _, user = rendered_shape_request(kind, tmp_path, config)

    assert "Choosing `indirect`" not in user


def test_a_scenario_that_allows_indirect_is_told_where_the_carrier_comes_from(
    tmp_path: Path,
) -> None:
    _, user = rendered_shape_request(AdversaryKind.third_party_via_content, tmp_path)

    assert (
        "Choosing `indirect` requires the `indirect` object, with `carrier_operation` "
        "copied from an operation marked `outside content: yes`."
    ) in user
