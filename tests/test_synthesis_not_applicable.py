"""Not-applicable candidates in the synthesis manifest, its status and the report.

Code routes an intent-type INCORRECT ICA before Stage 5. The run keeps its
candidate, counts it as not applicable with a reason code and a reason, and
treats it as resolved: it is neither a failure nor published yield.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from asago_scenario_generator.pipeline.synthesis import run_synthesis
from asago_scenario_generator.pipeline.synthesis_defaults import _default_scenarios
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _scenario_generation_status,
)
from asago_scenario_generator.pipeline.synthesis_types import (
    SynthesisAdapters,
    SynthesisRunStatus,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlStructure,
    ControlledProcess,
    ElementRef,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.scenario_prod.intent_reason import (
    INTENT_REASON_CODE,
)
from tests.helpers.generate_report_fixture import copy_run, edit_yaml, metrics
from tests.helpers.synthesis import _FakeAdapters, _inputs, _runtime
from tests.helpers.synthesis_fixture import baseline_loss_analysis

REASON = (
    "Not applicable: the reason 'the intent is unknown' is the user's intent, "
    "which no tool-call argument, TARGET-STATE or TARGET-READ fact represents."
)


def _outcome(index: int, status: str, **extra: object) -> SimpleNamespace:
    return SimpleNamespace(
        scenario_id=f"SCN-{index:03d}",
        ica_slot_id=f"RESP-{index}:CA-{index}-1:INCORRECT",
        ica_id=f"RESP-{index}:CA-{index}-1:INCORRECT:1",
        status=status,
        diagnostics=extra.pop("diagnostics", ()),
        reason_code=extra.pop("reason_code", None),
    )


def _run(tmp_path: Path, outcomes: tuple[SimpleNamespace, ...], envelopes: int):
    return run_synthesis(
        _inputs(tmp_path),
        SynthesisAdapters.from_object(
            _FakeAdapters(
                calls=[],
                scenario_envelopes=tuple(f"scenario-{n}" for n in range(envelopes)),
                candidate_outcomes=outcomes,
            )
        ),
    )


def test_the_manifest_counts_and_lists_not_applicable_candidates(
    tmp_path: Path,
) -> None:
    outcomes = (
        _outcome(1, "published"),
        _outcome(
            2,
            "not_applicable",
            reason_code=INTENT_REASON_CODE,
            diagnostics=(REASON,),
        ),
        _outcome(3, "generation_failed", diagnostics=("provider failure",)),
    )

    result = _run(tmp_path, outcomes, envelopes=1)

    counts = result.manifest["scenario_counts"]
    assert counts == {
        "generated": 1,
        "failed": 1,
        "requested": 3,
        "attempted": 2,
        "skipped": 0,
        "functional_test": 0,
        "not_applicable": 1,
        "diagnostic_count": 0,
    }
    # Candidates in = published + functional tests + not applicable + dropped.
    assert counts["requested"] == (
        counts["generated"]
        + counts["functional_test"]
        + counts["not_applicable"]
        + counts["failed"]
        + counts["skipped"]
    )
    listed = result.manifest["candidate_outcomes"]
    assert listed[1] == {
        "scenario_id": "SCN-002",
        "ica_slot_id": "RESP-2:CA-2-1:INCORRECT",
        "ica_id": "RESP-2:CA-2-1:INCORRECT:1",
        "status": "not_applicable",
        "reason_code": INTENT_REASON_CODE,
        "diagnostics": [REASON],
    }
    assert "reason_code" not in listed[0]
    assert "reason_code" not in listed[2]


def test_unknown_outcomes_leave_the_not_applicable_count_unknown(
    tmp_path: Path,
) -> None:
    result = run_synthesis(
        _inputs(tmp_path),
        SynthesisAdapters.from_object(_FakeAdapters(calls=[])),
    )

    assert result.manifest["scenario_counts"]["not_applicable"] is None


def test_a_run_whose_other_candidates_published_is_completed(tmp_path: Path) -> None:
    outcomes = (
        _outcome(1, "published"),
        _outcome(2, "not_applicable", reason_code=INTENT_REASON_CODE),
    )

    result = _run(tmp_path, outcomes, envelopes=1)

    assert result.manifest["run_status"] == "completed"
    assert result.manifest["run_status_reason"] == "all_requested_candidates_resolved"


@pytest.mark.parametrize(
    ("counts", "expected"),
    [
        (
            {"requested": 2, "attempted": 0, "generated": 0, "not_applicable": 2},
            (SynthesisRunStatus.COMPLETED, "all_requested_candidates_resolved"),
        ),
        (
            {"requested": 3, "attempted": 2, "generated": 2, "not_applicable": 1},
            (SynthesisRunStatus.COMPLETED, "all_requested_candidates_resolved"),
        ),
        (
            {"requested": 3, "attempted": 2, "generated": 0, "not_applicable": 1},
            (SynthesisRunStatus.FAILED, "zero_yield_after_attempts"),
        ),
        (
            {"requested": 3, "attempted": 2, "generated": 1, "not_applicable": 1},
            (SynthesisRunStatus.DEGRADED, "partial_candidate_yield"),
        ),
    ],
)
def test_not_applicable_candidates_are_resolved_but_not_yield(counts, expected) -> None:
    assert _scenario_generation_status(counts) == expected


def test_the_report_counts_not_applicable_candidates(tmp_path: Path) -> None:
    outcomes = (
        _outcome(1, "published"),
        _outcome(
            2,
            "not_applicable",
            reason_code=INTENT_REASON_CODE,
            diagnostics=(REASON,),
        ),
    )

    result = _run(tmp_path, outcomes, envelopes=1)

    report = result.report_path.read_text(encoding="utf-8")
    assert "1 not applicable" in report
    assert INTENT_REASON_CODE in report


# --- the report reads the testability record -------------------------------


def test_the_testability_section_lists_the_not_applicable_icas(tmp_path: Path) -> None:
    from asago_scenario_generator.report.run_data import load_run
    from asago_scenario_generator.report.testability_section import (
        testability_section,
    )

    output = copy_run(tmp_path)

    def add(testability: dict) -> None:
        testability["summary"]["not_applicable"] = 1
        testability["not_applicable"] = [
            {
                "scenario_id": "SCN-090",
                "ica_slot_id": "RESP-9:CA-9-1:INCORRECT",
                "ica_id": "RESP-9:CA-9-1:INCORRECT:1",
                "reason_code": INTENT_REASON_CODE,
                "basis": "reason_wording",
                "reason_variable": None,
                "reason": REASON,
            }
        ]

    edit_yaml(output / "testability.yaml", add)

    html = str(testability_section(load_run(output)))

    assert metrics(html)["testability.not_applicable"] == 1
    row = html.split('<tr id="not-applicable-SCN-090"')[1].split("</tr>")[0]
    assert "RESP-9:CA-9-1:INCORRECT:1" in row
    assert INTENT_REASON_CODE in row
    assert "the intent is unknown" in row


def test_a_testability_record_without_the_list_shows_no_table(tmp_path: Path) -> None:
    from asago_scenario_generator.report.run_data import load_run
    from asago_scenario_generator.report.testability_section import (
        testability_section,
    )

    html = str(testability_section(load_run(copy_run(tmp_path))))

    assert "not-applicable-" not in html


# --- the default scenario port routes before Stage 5 ------------------------


def _structure() -> ControlStructure:
    return ControlStructure(
        controlled_processes=[ControlledProcess(cp_id="CP-1", description="Payments")],
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Refund controller",
                process_model_parts=[
                    ProcessModelPart(
                        pm_id="PM-1-1",
                        description="The alignment between the requested "
                        "operation and the customer's authorized intent.",
                        values=[
                            "matches authorized intent",
                            "does not match authorized intent",
                        ],
                    )
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Issue a refund",
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                        effect_kind=ControlActionEffectKind.tool_call,
                        operation="process_refund",
                        process_model_refs=["PM-1-1"],
                    )
                ],
            )
        ],
    )


def _enumeration() -> ICAEnumeration:
    slot = "RESP-1:CA-1-1:INCORRECT"

    def ica(index: int, deviation: str) -> ICA:
        return ICA(
            ica_id=f"{slot}:{index}",
            ica_text=f"Issue a refund is unsafe because {deviation}.",
            deviation=deviation,
            hazardous_context="Context",
            loss_scenario="Scenario",
            related_hazards=["H-1"],
            related_constraints=["SC-1"],
        )

    return ICAEnumeration(
        slots=[
            ICASlot(
                slot_id=slot,
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.incorrect,
                is_na=False,
                icas=[
                    ica(1, "the actor is unauthorized"),
                    ica(
                        2, "the request does not match the customer's authorized intent"
                    ),
                ],
            )
        ]
    )


def test_the_default_scenario_port_hands_sp3_the_routed_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.scenario_prod.run.run_sp3",
        lambda **kwargs: captured.update(kwargs) or "sp3",
    )

    result = _default_scenarios(
        ica_enumeration=_enumeration(),
        control_structure=_structure(),
        loss_analysis=baseline_loss_analysis(),
        inputs=_inputs(tmp_path),
        capability_profile=None,
        output_dir=tmp_path,
        model_runtime=_runtime(object()),
    )

    assert result == "sp3"
    threats = captured["enriched_threat_set"].structural_threats
    plans = captured["condition_families"]
    routed = {
        threat.ica_id: plan.not_applicable
        for threat, plan in zip(threats, plans, strict=True)
    }
    assert routed["RESP-1:CA-1-1:INCORRECT:1"] is None
    disposition = routed["RESP-1:CA-1-1:INCORRECT:2"]
    assert disposition is not None
    assert disposition.reason_code == INTENT_REASON_CODE
