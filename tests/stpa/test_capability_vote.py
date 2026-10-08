"""Stage 1b decides KC sub-codes by a vote over several draws."""

from __future__ import annotations

import pytest
import yaml

from asago_scenario_generator.models.capability_profile import Stage1Profile
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.system_model.kc_decision import vote_kc_subcodes
from asago_scenario_generator.stpa.system_model.profile import (
    derive_capability_profile,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.stpa.sp1_helpers import MockLLMClient


def _draw(*codes: str, tool: str = "orders_api") -> dict:
    return {
        "entry_points": [
            {"name": "User chat messages", "direction": "input", "controllability": "direct"}
        ],
        "confidence": "medium",
        "kc_subcodes": ["KC1.1", *codes],
        "tool_inventory": [{"name": tool, "description": "Read orders"}],
    }


@pytest.mark.parametrize(
    ("draws", "kept"),
    [
        ([{"A"}, {"A"}, {"B"}], ["A", "B"]),
        ([{"A"}, {"A"}, {"A"}, {"B"}, set(), set()], ["A"]),
        ([{"A", "B"}, {"A"}, {"A"}, {"A"}, {"A"}, {"A"}], ["A"]),
        ([{"A"}, {"B"}, {"B"}, {"A"}, {"C"}, {"C"}, set(), set(), set()], []),
        ([{"A"}, {"B"}, {"B"}, {"A"}, {"C"}, {"A"}, set(), set(), set()], ["A"]),
    ],
)
def test_a_code_needs_a_third_of_the_draws(draws, kept) -> None:
    assert vote_kc_subcodes(draws) == kept


def test_vote_needs_a_draw() -> None:
    with pytest.raises(ValueError, match="at least one draw"):
        vote_kc_subcodes([])


def test_samples_send_one_request_each_and_vote_the_codes(tmp_path) -> None:
    client = MockLLMClient()
    client.set_response_for(
        Stage1Profile,
        [
            _draw("KC2.1", "KC6.1.2"),
            _draw("KC6.1.2", tool="ledger_api"),
            _draw("KC6.1.2", "KC4.1"),
            _draw("KC6.1.2", "KC2.1"),
            _draw("KC6.1.2"),
            _draw("KC6.1.2", "KC5.3"),
        ],
    )

    profile = derive_capability_profile(
        llm_client=client, use_case_text="Test use case", run_dir=tmp_path, samples=6
    )

    assert profile.kc_subcodes == ["KC1.1", "KC2.1", "KC6.1.2"]
    assert [entry.name for entry in profile.tool_inventory] == ["orders_api"]
    steps = [entry["step"] for entry in read_calls_jsonl(tmp_path)]
    assert steps == ["capability_profile"] + [
        f"capability_profile_vote_{i}" for i in range(2, 7)
    ]
    assert len({call.user_prompt for call in client.calls}) == 1
    record = yaml.safe_load((tmp_path / "capability-kc-decision.yaml").read_text())
    assert record["samples"] == 6
    assert record["draws"][1] == ["KC1.1", "KC6.1.2"]
    assert record["counts"]["KC2.1"] == 2
    assert record["kc_subcodes"] == ["KC1.1", "KC2.1", "KC6.1.2"]


def test_a_failed_draw_is_left_out_of_the_vote(tmp_path) -> None:
    client = MockLLMClient()
    # The second draw's response and its correction both fail validation.
    client.set_response_for(
        Stage1Profile,
        [_draw("KC2.1"), {"kc_subcodes": ["KC9"]}, {"kc_subcodes": ["KC9"]}, _draw()],
    )

    profile = derive_capability_profile(
        llm_client=client, use_case_text="Test use case", run_dir=tmp_path, samples=3
    )

    assert profile.kc_subcodes == ["KC1.1", "KC2.1"]
    record = yaml.safe_load((tmp_path / "capability-kc-decision.yaml").read_text())
    assert len(record["draws"]) == 2
    assert len(record["failed_draws"]) == 1


def test_every_draw_failing_ends_the_stage(tmp_path) -> None:
    client = MockLLMClient()
    client.set_invalid_response_for(Stage1Profile)

    with pytest.raises(StageError):
        derive_capability_profile(
            llm_client=client,
            use_case_text="Test use case",
            run_dir=tmp_path,
            samples=2,
        )
