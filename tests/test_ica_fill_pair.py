"""A fill finding lists every governing constraint-and-hazard pair it rests on."""

from __future__ import annotations

from typing import Any

import pytest

from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    LossAnalysis,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    SynthesisSlotRequest,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.obligation_aware import (
    _control_structure,
    _controls,
    _loss_analysis,
    current_fill_reply,
)
from tests.helpers.scripted_client import ScriptedClient


def _two_constraint_analysis() -> LossAnalysis:
    """SC-1 governs H-1; SC-2 governs H-2 and H-1."""
    base = _loss_analysis()
    return LossAnalysis(
        risk_card_losses=base.risk_card_losses,
        use_case_losses=base.use_case_losses,
        hazards=[
            *base.hazards,
            Hazard(
                hazard_id="H-2",
                description="An unsafe request is delayed.",
                related_losses=["L-1"],
            ),
        ],
        security_constraints=[
            *base.security_constraints,
            SecurityConstraint(
                constraint_id="SC-2",
                rule="Requests must be handled in time.",
                related_hazards=["H-2", "H-1"],
            ),
        ],
    )


def _request() -> SynthesisSlotRequest:
    slot = create_slots(_control_structure())[0]
    return SynthesisSlotRequest(
        target_id="RESP-1",
        target_kind="responsibility",
        slots=(slot,),
        loss_analysis=_two_constraint_analysis(),
        control_structure=_control_structure(),
        controls=_controls().model_copy(update={"validation_retries": 1}),
    )


def _reply(*pairs: str) -> dict[str, Any]:
    return {
        "filled_slots": [
            {
                "slot_id": _request().slots[0].slot_id,
                "is_na": False,
                "na_rationale": None,
                "findings": [
                    {
                        "deviation": "the request is accepted before it is reviewed",
                        "hazardous_context": "an unreviewed request reaches the process",
                        "loss_consequence": "the protected operation is harmed",
                        "governing_pairs": list(pairs),
                        "process_model_refs": [],
                        "feedback_refs": [],
                        "context_row": None,
                    }
                ],
                "consideration_results": {},
            }
        ]
    }


def _finding_schema(client: ScriptedClient) -> dict[str, Any]:
    schema = client.calls[0]["response_format"].model_json_schema()
    return next(
        item
        for item in schema["$defs"].values()
        if "deviation" in item.get("properties", {})
    )


def _fill(tmp_path, *replies: dict[str, Any]):
    client = ScriptedClient(list(replies), model="fill-pair")
    response = ObligationAwareLLMAdapter(
        client, run_dir=tmp_path, controls=_controls()
    ).fill(_request())
    return client, response


def test_the_schema_offers_an_array_of_unique_governing_pairs(tmp_path) -> None:
    client, _ = _fill(tmp_path, _reply("SC-1/H-1"))

    finding = _finding_schema(client)
    pairs = finding["properties"]["governing_pairs"]
    assert pairs["type"] == "array"
    assert pairs["items"]["enum"] == ["SC-1/H-1", "SC-2/H-2", "SC-2/H-1"]
    assert pairs["minItems"] == 1
    assert pairs["uniqueItems"] is True
    assert "governing_pair" not in finding["properties"]
    assert "related_hazard_ids" not in finding["properties"]
    assert "related_constraint_ids" not in finding["properties"]
    assert "governing_pairs" in finding["required"]


def test_code_splits_the_pairs_into_distinct_ids_in_written_order(tmp_path) -> None:
    _, response = _fill(tmp_path, _reply("SC-2/H-2", "SC-2/H-1", "SC-1/H-1"))

    ica = response.filled_slots[0].icas[0]
    assert ica.related_hazards == ["H-2", "H-1"]
    assert ica.related_constraints == ["SC-2", "SC-1"]


@pytest.mark.parametrize(
    ("pairs", "named"),
    [((), "governing_pairs"), (("SC-2/H-2", "SC-2/H-2"), "SC-2/H-2")],
)
def test_an_empty_or_repeated_pair_list_is_corrected(
    tmp_path, pairs: tuple[str, ...], named: str
) -> None:
    client, response = _fill(tmp_path, _reply(*pairs), _reply("SC-2/H-2"))

    assert [entry["success"] for entry in read_calls_jsonl(tmp_path)] == [
        False,
        True,
    ]
    assert named in client.prompts[1].split("Exact validation error")[1]
    assert response.filled_slots[0].icas[0].related_hazards == ["H-2"]


def test_a_pair_whose_constraint_governs_another_hazard_is_corrected(
    tmp_path,
) -> None:
    client, response = _fill(
        tmp_path, _reply("SC-2/H-2", "SC-1/H-2"), _reply("SC-2/H-2")
    )

    assert [entry["success"] for entry in read_calls_jsonl(tmp_path)] == [
        False,
        True,
    ]
    assert "governing_pairs" in client.prompts[1].split("Exact validation error")[1]
    assert response.filled_slots[0].icas[0].related_hazards == ["H-2"]


def test_the_prompt_explains_the_pairs() -> None:
    from asago_scenario_generator.stpa.obligation_aware.prompts import (
        PROMPT_TEMPLATES_DIR,
    )

    text = " ".join(
        (PROMPT_TEMPLATES_DIR / "synthesis_ica_system.j2")
        .read_text(encoding="utf-8")
        .split()
    )
    assert "`governing_pairs`" in text
    assert "lists every pair it rests on" in text
    assert "`governing_pair`" not in text
    assert "`related_hazard_ids`" not in text


def _recorded(constraints: list[str], hazards: list[str]) -> dict[str, Any]:
    finding = _reply("SC-1/H-1")["filled_slots"][0]["findings"][0]
    del finding["governing_pairs"]
    finding |= {"related_constraint_ids": constraints, "related_hazard_ids": hazards}
    slot = _reply("SC-1/H-1")["filled_slots"][0] | {"findings": [finding]}
    return {"filled_slots": [slot | {"consideration_results": []}]}


def _recast_pairs(constraints: list[str], hazards: list[str]) -> list[str]:
    recast = current_fill_reply(
        _recorded(constraints, hazards), loss_analysis=_two_constraint_analysis()
    )
    return recast["filled_slots"][0]["findings"][0]["governing_pairs"]


def test_a_recorded_finding_becomes_the_pairs_its_constraints_govern() -> None:
    assert _recast_pairs(["SC-1", "SC-2"], ["H-2", "H-1"]) == [
        "SC-1/H-1",
        "SC-2/H-2",
        "SC-2/H-1",
    ]


@pytest.mark.parametrize(
    ("constraints", "hazards"), [(["SC-1"], ["H-2"]), (["SC-1"], ["H-1", "H-2"])]
)
def test_a_recorded_id_no_listed_pair_covers_keeps_every_pair(
    constraints: list[str], hazards: list[str]
) -> None:
    assert _recast_pairs(constraints, hazards) == [
        f"{constraint}/{hazard}" for constraint in constraints for hazard in hazards
    ]
