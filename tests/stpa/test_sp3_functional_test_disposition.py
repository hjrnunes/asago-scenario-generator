"""Phase 3.2: deterministic disposition of ``kind: none`` candidates.

A functional test is persisted in the run for the owner's information but
never reaches Stage 7 or obligation realization.
"""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.stpa.models.scenario_spec import AdversaryKind
from asago_scenario_generator.stpa.scenario_prod.run import (
    SP3CandidateStatus,
    run_sp3,
)
from tests.helpers.stpa_builders import make_cs
from tests.stpa.sp1_helpers import MockLLMClient

from tests.helpers.sp3_run import _semantics_wire
from tests.stpa.test_sp3_run import _make_ets, _make_loss_analysis


def _functional_adversary() -> dict:
    return {
        "kind": "none",
        "gain": "The requested service completes as designed.",
    }


def _stage5_payload(i: int, adversary: dict) -> dict:
    attacker_bdi = (
        {"beliefs": [], "desires": [], "intentions": []}
        if adversary["kind"] == "none"
        else {
            "beliefs": [f"attacker belief {i + 1}"],
            "desires": ["induce ICA"],
            "intentions": [
                {
                    "description": "Exploit stale PM-1-1 state before CA-1-1.",
                    "source_handles": ["cause_1"],
                }
            ],
        }
    )
    return _semantics_wire(
        {
            "stimulus": {
                "category": "user_message",
                "description": "One user message is the typed test stimulus.",
            },
            "adversary": adversary,
            "attacker_bdi": attacker_bdi,
            "causal_factors": [
                {
                    "source_handle": "cause_1",
                    "evidence": f"The selected state can be stale ({i + 1}).",
                    "temporal_condition": None,
                    "evidence_status": "structural_failure",
                    "selected_for_route": True,
                }
            ],
            "unsafe_outcome": {
                "condition": {
                    "type": "action_presence",
                    "control_action_id": "CA-1-1",
                    "expected": "not_provided",
                },
                "semantic_proposition": (
                    "The response does not provide the requested action."
                ),
            },
            "execution_route": {
                "disposition": "executable_route",
                "action_kind": "model_output",
                "reason": "The selected structural factor supports the direct route.",
            },
        }
    )


_ADVERSARIAL = {
    "kind": "malicious_customer",
    "gain": "Learns another customer's order details.",
}


def _client_with_adversaries(adversaries: list[dict]) -> MockLLMClient:
    client = MockLLMClient()
    client.set_response_queue(
        [
            _stage5_payload(index, adversary)
            for index, adversary in enumerate(adversaries)
        ]
    )
    return client


def test_functional_test_candidate_is_persisted_for_the_owner(
    tmp_path: Path,
) -> None:
    client = _client_with_adversaries([_functional_adversary()])

    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=1),
        control_structure=make_cs(),
        loss_analysis=_make_loss_analysis(),
        run_dir=tmp_path,
    )

    assert client.call_count == 1
    assert result.scenario_specs == []
    assert len(result.functional_test_specs) == 1
    assert result.functional_test_specs[0].adversary is not None
    assert result.functional_test_specs[0].adversary.kind is AdversaryKind.none
    assert [outcome.status for outcome in result.candidate_outcomes] == [
        SP3CandidateStatus.functional_test
    ]
    assert (tmp_path / "scenarios" / "SCN-001.yaml").is_file(), (
        "functional test must be persisted for the owner"
    )
    assert (tmp_path / "scenarios" / "SCN-001.feature").is_file()
    assert result.stage_errors == []


def test_functional_test_accepts_empty_attacker_bdi_and_keeps_constraint_grounding(
    tmp_path: Path,
) -> None:
    payload = _stage5_payload(0, _functional_adversary())
    payload["attacker_bdi"] = {"beliefs": [], "desires": [], "intentions": []}

    client = _client_with_adversaries([])
    client.set_response_queue([payload])
    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=1),
        control_structure=make_cs(),
        loss_analysis=_make_loss_analysis(),
        run_dir=tmp_path,
    )

    assert result.stage_errors == []
    assert len(result.functional_test_specs) == 1
    spec = result.functional_test_specs[0]
    assert spec.attacker_bdi.model_dump(mode="json") == {
        "beliefs": [],
        "desires": [],
        "intentions": [],
    }
    assert [desire.constraint_id for desire in spec.defender_bdi.desires] == ["SC-1"]
    assert [desire.content for desire in spec.defender_bdi.desires] == ["Must validate"]


def test_mixed_run_publishes_both_candidates_with_distinct_status(
    tmp_path: Path,
) -> None:
    client = _client_with_adversaries([_ADVERSARIAL, _functional_adversary()])

    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=2),
        control_structure=make_cs(),
        loss_analysis=_make_loss_analysis(),
        run_dir=tmp_path,
    )

    assert [outcome.status for outcome in result.candidate_outcomes] == [
        SP3CandidateStatus.published,
        SP3CandidateStatus.functional_test,
    ]
    assert len(result.scenario_envelopes) == 1
    assert result.scenario_envelopes[0].scenario_id == "SCN-001"
    assert len(result.functional_test_specs) == 1
    assert (tmp_path / "scenarios" / "SCN-001.yaml").is_file()
    assert (tmp_path / "scenarios" / "SCN-002.yaml").is_file()
