"""Pin the repaired loss analysis and repair record of each Stage 1a repair class.

Each case runs one fixture through ``derive_loss_analysis`` with a fake
client and compares the merged analysis, the Stage 1a call steps, the repair
record, and the warnings with a saved snapshot.  A change to how repair
represents identities must leave every snapshot unchanged; only the repair
replies in this file name IDs the way the repair request shows them.

Reference repair has no recorded call, so its cases are synthetic.  To
rewrite the snapshots after a deliberate output change, run this module with
``ASAGO_WRITE_REPAIR_SNAPSHOTS=1`` and review the diff.
"""

from __future__ import annotations

import copy
import json
import os
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    DispositionRepairResponse,
    ObligationRepairResponse,
    ReferenceRepairResponse,
)
from tests.helpers.calls_log import stage1a_steps
from tests.helpers.stage1a_targeted_repair import (
    _USE_CASE,
    _attempt_two_response,
    _complete_risk_response,
    _disposition_repair_rows,
    _empty_gap_response,
    _gap_constraint_defect_response,
    _occiai_cards,
)
from tests.helpers.stpa_builders import make_risk_cards
from tests.stpa import test_stage1a_loss_presence_repair as loss_presence
from tests.stpa import test_stage1a_wire_error_reference_repair as klarna
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    valid_gap_draft_dict,
    valid_risk_draft_dict,
)
from tests.stpa.test_stage1a_unknown_reference_correction import (
    RECORDED_GAP_RESPONSE,
)

SNAPSHOTS = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "stpa"
    / "repair_characterization"
)

_MISPLACED_CHANNEL = {
    "obligation_id": "O1",
    "kind": "forbidden",
    "behavior": "including sensitive health data in a reply",
    "rule_span": "no sensitive health data is included in model outputs",
    "realized_by": "reply",
}
_CORRECTED_CHANNEL = {
    key: value for key, value in _MISPLACED_CHANNEL.items() if key != "realized_by"
} | {"violated_via": "reply"}


def _obligation_reply(constraint_id: str, entry: dict) -> dict:
    return {"constraints": [{"constraint_id": constraint_id, "obligations": [entry]}]}


def _risk_obligation_defect() -> dict:
    draft = _complete_risk_response()
    draft["security_constraints"][0]["obligations"] = [dict(_MISPLACED_CHANNEL)]
    return draft


def _klarna_rejected_reply() -> dict:
    reply = copy.deepcopy(klarna.REPLACE)
    reply["risk_dispositions"][0]["loss_ids"].append("L-99")
    return reply


def _disposition(client: MockLLMClient) -> dict:
    client.set_response_for(
        LossAnalysisDraft, [_attempt_two_response(), _empty_gap_response()]
    )
    client.set_response_for(
        DispositionRepairResponse, {"risk_dispositions": _disposition_repair_rows()}
    )
    return {"use_case_text": _USE_CASE, "risk_cards": _occiai_cards()}


def _obligation_risk(client: MockLLMClient) -> dict:
    client.set_response_for(
        LossAnalysisDraft, [_risk_obligation_defect(), _empty_gap_response()]
    )
    client.set_response_for(
        ObligationRepairResponse, _obligation_reply("SC-1", _CORRECTED_CHANNEL)
    )
    return {"use_case_text": _USE_CASE, "risk_cards": _occiai_cards()}


def _obligation_gap(client: MockLLMClient) -> dict:
    client.set_response_for(
        LossAnalysisDraft,
        [_complete_risk_response(), _gap_constraint_defect_response()],
    )
    entry = _gap_constraint_defect_response()["security_constraints"][0]["obligations"][
        0
    ]
    corrected = {k: v for k, v in entry.items() if k != "realized_by"}
    client.set_response_for(
        ObligationRepairResponse,
        _obligation_reply("SC-8", corrected | {"violated_via": "reply"}),
    )
    return {"use_case_text": _USE_CASE, "risk_cards": _occiai_cards()}


def _reference_risk(client: MockLLMClient) -> dict:
    client.set_response_for(
        LossAnalysisDraft, [json.dumps(klarna.RECORDED_REPLY), valid_gap_draft_dict()]
    )
    client.set_response_for(ReferenceRepairResponse, klarna.REPLACE)
    return {
        "use_case_text": "Test use case",
        "risk_cards": klarna._cards(klarna.RECORDED_REPLY),
    }


def _reference_drop(client: MockLLMClient) -> dict:
    client.set_response_for(
        LossAnalysisDraft, [json.dumps(klarna.RECORDED_REPLY), valid_gap_draft_dict()]
    )
    client.set_response_for(ReferenceRepairResponse, _klarna_rejected_reply())
    return {
        "use_case_text": "Test use case",
        "risk_cards": klarna._cards(klarna.RECORDED_REPLY),
    }


def _reference_gap(client: MockLLMClient) -> dict:
    client.set_response_for(
        LossAnalysisDraft, [valid_risk_draft_dict(), RECORDED_GAP_RESPONSE]
    )
    client.set_response_for(
        ReferenceRepairResponse,
        {
            "hazards": [],
            "security_constraints": [
                {"constraint_id": "SC-2", "related_hazards": ["H-2"]}
            ],
        },
    )
    return {"use_case_text": "Test use case", "risk_cards": make_risk_cards()}


def _feedback_correction(client: MockLLMClient) -> dict:
    client.set_response_for(
        LossAnalysisDraft,
        [
            loss_presence._EMPTY_REPLY,
            loss_presence._corrected_reply(),
            loss_presence._gap_reply(),
        ],
    )
    return {
        "use_case_text": "A neutralized lodging assistant answers guest questions.",
        "risk_cards": loss_presence._cards(),
    }


CASES: dict[str, tuple[Callable[[MockLLMClient], dict], type[MockLLMClient]]] = {
    "disposition": (_disposition, MockLLMClient),
    "obligation_risk": (_obligation_risk, MockLLMClient),
    "obligation_gap": (_obligation_gap, MockLLMClient),
    "reference_risk": (_reference_risk, MockLLMClient),
    "reference_drop": (_reference_drop, MockLLMClient),
    "reference_gap": (_reference_gap, MockLLMClient),
    "feedback_correction": (_feedback_correction, loss_presence._RawClient),
}


def _observed(case: str, tmp_path: Path) -> dict:
    configure, client_type = CASES[case]
    client = client_type()
    inputs = configure(client)
    warnings: list[str] = []
    analysis = derive_loss_analysis(
        llm_client=client, run_dir=tmp_path, normalization_warnings=warnings, **inputs
    )
    record = yaml.safe_load((tmp_path / "loss-analysis-repair.yaml").read_text())
    return {
        "steps": stage1a_steps(tmp_path),
        "analysis": analysis.model_dump(mode="json"),
        "records": record["records"],
        "warnings": warnings,
    }


@pytest.mark.parametrize("case", sorted(CASES))
def test_repaired_loss_analysis_matches_its_snapshot(case: str, tmp_path) -> None:
    observed = _observed(case, tmp_path)
    snapshot = SNAPSHOTS / f"{case}.json"
    if os.environ.get("ASAGO_WRITE_REPAIR_SNAPSHOTS") == "1":
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_text(
            json.dumps(observed, indent=1, sort_keys=True) + "\n", encoding="utf-8"
        )
    assert observed == json.loads(snapshot.read_text(encoding="utf-8"))


def test_every_case_reaches_its_repair(tmp_path) -> None:
    repaired = {
        case: [
            step
            for step in _observed(case, tmp_path / case)["steps"]
            if step.endswith("_repair")
        ]
        for case in CASES
    }

    assert repaired == {
        "disposition": ["risk_derivation_repair"],
        "obligation_risk": ["risk_derivation_repair"],
        "obligation_gap": ["gap_analysis_repair"],
        "reference_risk": ["risk_derivation_repair"],
        "reference_drop": ["risk_derivation_repair"],
        "reference_gap": ["gap_analysis_repair"],
        "feedback_correction": ["risk_derivation_repair"],
    }
