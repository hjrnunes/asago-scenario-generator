"""A fill finding names one governing constraint-and-hazard pair."""

from __future__ import annotations

from typing import Any

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


def _reply(pair: str) -> dict[str, Any]:
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
                        "governing_pair": pair,
                        "process_model_refs": [],
                        "feedback_refs": [],
                        "context_row": None,
                    }
                ],
                "consideration_results": [],
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


def test_the_schema_offers_each_governing_pair_and_no_separate_ids(tmp_path) -> None:
    client = ScriptedClient([_reply("SC-1/H-1")], model="fill-pair")
    ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls()).fill(
        _request()
    )

    finding = _finding_schema(client)
    assert finding["properties"]["governing_pair"]["enum"] == [
        "SC-1/H-1",
        "SC-2/H-2",
        "SC-2/H-1",
    ]
    assert "related_hazard_ids" not in finding["properties"]
    assert "related_constraint_ids" not in finding["properties"]
    assert "governing_pair" in finding["required"]


def test_code_splits_the_pair_into_the_findings_hazard_and_constraint(
    tmp_path,
) -> None:
    client = ScriptedClient([_reply("SC-2/H-1")], model="fill-pair")

    response = ObligationAwareLLMAdapter(
        client, run_dir=tmp_path, controls=_controls()
    ).fill(_request())

    ica = response.filled_slots[0].icas[0]
    assert ica.related_hazards == ["H-1"]
    assert ica.related_constraints == ["SC-2"]


def test_a_pair_whose_constraint_governs_another_hazard_is_corrected(
    tmp_path,
) -> None:
    client = ScriptedClient([_reply("SC-1/H-2"), _reply("SC-2/H-2")], model="fill-pair")

    response = ObligationAwareLLMAdapter(
        client, run_dir=tmp_path, controls=_controls()
    ).fill(_request())

    assert [entry["success"] for entry in read_calls_jsonl(tmp_path)] == [
        False,
        True,
    ]
    assert "governing_pair" in client.prompts[1].split("Exact validation error")[1]
    assert response.filled_slots[0].icas[0].related_hazards == ["H-2"]


def test_the_prompt_explains_the_pair() -> None:
    from asago_scenario_generator.stpa.obligation_aware.prompts import (
        PROMPT_TEMPLATES_DIR,
    )

    text = " ".join(
        (PROMPT_TEMPLATES_DIR / "synthesis_ica_system.j2")
        .read_text(encoding="utf-8")
        .split()
    )
    assert "`governing_pair`" in text
    assert "`related_hazard_ids`" not in text
