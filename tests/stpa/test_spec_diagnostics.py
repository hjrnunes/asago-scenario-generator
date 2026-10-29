"""Report-only specification checks on the final STPA artifacts."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml

from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.spec_diagnostics import (
    ICA_CHECKS,
    SPEC_DIAGNOSTICS_FILENAME,
    FindingDisposition,
    SpecCheck,
    SpecDiagnostics,
    SpecFinding,
    diagnose_final_artifacts,
    read_spec_diagnostics,
    write_spec_diagnostics,
)


def _loss(hazards: tuple[str, ...] = ("H-1",)) -> LossAnalysis:
    return LossAnalysis.model_validate(
        {
            "risk_card_losses": [],
            "use_case_losses": [
                {"loss_id": "L-1", "description": "Loss", "provenance": "use_case"}
            ],
            "hazards": [
                {
                    "hazard_id": h,
                    "description": f"Hazard {h}",
                    "related_losses": ["L-1"],
                }
                for h in hazards
            ],
            "security_constraints": [
                {"constraint_id": "SC-1", "rule": "Rule", "related_hazards": ["H-1"]}
            ],
        }
    )


def _cp(cp_id: str) -> dict[str, str]:
    return {"type": "controlled_process", "id": cp_id}


def _action(ca_id: str, target: str, refs: list[str]) -> dict[str, Any]:
    return {
        "ca_id": ca_id,
        "description": f"Action {ca_id}",
        "target": _cp(target),
        "effect_kind": "tool_call",
        "temporality": "discrete",
        "process_model_refs": refs,
    }


def _feedback(fb_id: str, source: str, updates: str) -> dict[str, Any]:
    return {
        "fb_id": fb_id,
        "description": f"Feedback {fb_id}",
        "updates": updates,
        "source": _cp(source),
    }


def _structure_data() -> dict[str, Any]:
    """RESP-1 acts on CP-1 and observes it; every relationship is present."""
    return {
        "responsibilities": [
            {
                "resp_id": "RESP-1",
                "description": "Controller",
                "process_model_parts": [
                    {"pm_id": "PM-1-1", "description": "State", "values": ["a", "b"]}
                ],
                "control_actions": [_action("CA-1-1", "CP-1", ["PM-1-1"])],
                "feedback_channels": [_feedback("FB-1-1", "CP-1", "PM-1-1")],
            }
        ],
        "controlled_processes": [
            {"cp_id": "CP-1", "description": "Process one"},
            {"cp_id": "CP-2", "description": "Process two"},
        ],
    }


def _structure(data: dict[str, Any] | None = None) -> ControlStructure:
    return ControlStructure.model_validate(data or _structure_data())


def _icas(*icas: dict[str, Any]) -> ICAEnumeration:
    return ICAEnumeration.model_validate(
        {
            "slots": [
                {
                    "slot_id": "RESP-1:CA-1-1:INCORRECT",
                    "responsibility": "RESP-1",
                    "control_action": "CA-1-1",
                    "uca_type": "INCORRECT",
                    "is_na": not icas,
                    "na_justification": None if icas else "Not applicable.",
                    "icas": list(icas),
                }
            ]
        }
    )


def _ica(
    n: int = 1,
    hazards: tuple[str, ...] = ("H-1",),
    constraints: tuple[str, ...] = ("SC-1",),
) -> dict[str, Any]:
    return {
        "ica_id": f"RESP-1:CA-1-1:INCORRECT:{n}",
        "ica_text": "Unsafe action",
        "hazardous_context": "Context",
        "loss_scenario": "Scenario",
        "related_hazards": list(hazards),
        "related_constraints": list(constraints),
    }


def _diagnose(
    structure: ControlStructure | None = None,
    icas: ICAEnumeration | None = None,
    loss: LossAnalysis | None = None,
) -> SpecDiagnostics:
    return diagnose_final_artifacts(
        loss_analysis=loss or _loss(),
        control_structure=structure or _structure(),
        ica_enumeration=icas if icas is not None else _icas(_ica()),
    )


def _found(result: SpecDiagnostics, check: SpecCheck) -> list[SpecFinding]:
    return [finding for finding in result.findings if finding.check is check]


def test_a_complete_model_has_no_finding_and_every_check_ran():
    result = _diagnose()

    assert result.findings == ()
    assert [s.check for s in result.checks] == list(SpecCheck)
    assert all(s.status == "run" and s.findings == 0 for s in result.checks)


# (a) and the controlled-process gap ------------------------------------------


def test_an_action_on_a_process_its_controller_does_not_observe_is_found():
    data = _structure_data()
    data["responsibilities"][0]["control_actions"].append(
        _action("CA-1-2", "CP-2", ["PM-1-1"])
    )

    [finding] = _found(
        _diagnose(_structure(data)), SpecCheck.controlled_process_without_feedback
    )

    assert finding.subject_ids == ("CP-2", "RESP-1", "CA-1-2")
    assert "none of its feedback channels has CP-2 as its source" in finding.message


def test_feedback_from_the_process_to_another_controller_does_not_count():
    data = _structure_data()
    data["responsibilities"].append(
        {
            "resp_id": "RESP-2",
            "description": "Second controller",
            "process_model_parts": [
                {"pm_id": "PM-2-1", "description": "State", "values": ["x"]}
            ],
            "control_actions": [_action("CA-2-1", "CP-1", ["PM-2-1"])],
            "feedback_channels": [],
        }
    )

    result = _diagnose(_structure(data))

    [finding] = _found(result, SpecCheck.controlled_process_without_feedback)
    assert finding.subject_ids == ("CP-1", "RESP-2", "CA-2-1")
    assert "RESP-1 observes CP-1" in finding.message
    assert _found(result, SpecCheck.controlled_process_unobserved) == []


def test_a_process_model_source_alone_is_named_but_not_feedback():
    data = _structure_data()
    part = data["responsibilities"][0]["process_model_parts"][0]
    part["feedback_source"] = _cp("CP-2")
    data["responsibilities"][0]["control_actions"].append(
        _action("CA-1-2", "CP-2", ["PM-1-1"])
    )

    [finding] = _found(
        _diagnose(_structure(data)), SpecCheck.controlled_process_without_feedback
    )

    assert "names CP-2 as its feedback_source" in finding.message


def test_a_targeted_process_no_channel_observes_is_unobserved():
    data = _structure_data()
    data["responsibilities"][0]["control_actions"].append(
        _action("CA-1-2", "CP-2", ["PM-1-1"])
    )

    [finding] = _found(
        _diagnose(_structure(data)), SpecCheck.controlled_process_unobserved
    )

    assert finding.subject_ids == ("CP-2", "CA-1-2")


def test_a_process_no_action_targets_is_neither_unobserved_nor_unfed():
    """CP-2 of the base model is declared, untargeted and unobserved."""
    result = _diagnose()

    assert _found(result, SpecCheck.controlled_process_unobserved) == []
    assert _found(result, SpecCheck.controlled_process_without_feedback) == []


# (b) hazard without ICA ------------------------------------------------------


def test_a_hazard_no_retained_ica_cites_is_found():
    [finding] = _found(
        _diagnose(loss=_loss(("H-1", "H-2"))), SpecCheck.hazard_without_ica
    )

    assert finding.subject_ids == ("H-2",)
    assert "of 1" in finding.message and "Hazard H-2" in finding.message


def test_a_hazard_cited_by_any_retained_ica_is_not_found():
    icas = _icas(_ica(1, ("H-1",)), _ica(2, ("H-2",)))

    result = _diagnose(icas=icas, loss=_loss(("H-1", "H-2")))

    assert _found(result, SpecCheck.hazard_without_ica) == []


def test_every_hazard_is_found_when_no_ica_was_retained():
    result = _diagnose(icas=_icas(), loss=_loss(("H-1", "H-2")))

    assert [f.subject_ids for f in _found(result, SpecCheck.hazard_without_ica)] == [
        ("H-1",),
        ("H-2",),
    ]


# (c) action without process-model refs ---------------------------------------


def test_an_action_without_process_model_refs_is_found():
    data = _structure_data()
    data["responsibilities"][0]["control_actions"][0]["process_model_refs"] = []

    [finding] = _found(
        _diagnose(_structure(data)), SpecCheck.action_without_process_model_refs
    )

    assert finding.subject_ids == ("CA-1-1", "RESP-1")


def test_an_action_with_process_model_refs_is_not_found():
    assert _found(_diagnose(), SpecCheck.action_without_process_model_refs) == []


# (d) referenced variable without values --------------------------------------


def test_a_referenced_variable_without_values_is_found():
    data = _structure_data()
    data["responsibilities"][0]["process_model_parts"][0]["values"] = []

    [finding] = _found(
        _diagnose(_structure(data)), SpecCheck.process_model_variable_without_values
    )

    assert finding.subject_ids == ("PM-1-1", "RESP-1", "CA-1-1")


def test_an_unreferenced_variable_without_values_is_not_found():
    data = _structure_data()
    data["responsibilities"][0]["process_model_parts"].append(
        {"pm_id": "PM-1-2", "description": "Unused state"}
    )

    result = _diagnose(_structure(data))

    assert _found(result, SpecCheck.process_model_variable_without_values) == []


# ICA without related constraints ---------------------------------------------


def test_an_ica_without_related_constraints_is_found():
    icas = _icas(_ica(1), _ica(2, constraints=()))

    [finding] = _found(_diagnose(icas=icas), SpecCheck.ica_without_related_constraints)

    assert finding.subject_ids == ("RESP-1:CA-1-1:INCORRECT:2",)


def test_an_ica_citing_a_constraint_is_not_found():
    assert _found(_diagnose(), SpecCheck.ica_without_related_constraints) == []


# Hazard without constraint --------------------------------------------------


def test_a_hazard_no_security_constraint_lists_is_found():
    [finding] = _found(
        _diagnose(loss=_loss(("H-1", "H-2"))), SpecCheck.hazard_without_constraint
    )

    assert finding.subject_ids == ("H-2",)
    assert "Hazard H-2" in finding.message


def test_a_hazard_a_constraint_lists_is_not_found():
    assert _found(_diagnose(), SpecCheck.hazard_without_constraint) == []


# No ICA enumeration ----------------------------------------------------------


def test_without_an_enumeration_the_ica_checks_are_recorded_as_not_run():
    result = diagnose_final_artifacts(
        loss_analysis=_loss(),
        control_structure=_structure(),
        ica_enumeration=None,
        ica_unavailable_reason="no enumeration here",
    )

    not_run = {s.check: s for s in result.checks if s.status == "not_run"}
    assert set(not_run) == set(ICA_CHECKS)
    assert all(s.reason == "no enumeration here" for s in not_run.values())
    assert not any(f.check in ICA_CHECKS for f in result.findings)


# Report only: no repair, no block, no disposition ----------------------------


def _every_gap() -> tuple[LossAnalysis, ControlStructure, ICAEnumeration]:
    data = _structure_data()
    resp = data["responsibilities"][0]
    resp["process_model_parts"][0]["values"] = []
    resp["control_actions"].append(_action("CA-1-2", "CP-2", []))
    return (
        _loss(("H-1", "H-2")),
        _structure(data),
        _icas(_ica(1, constraints=())),
    )


def test_findings_never_repair_or_change_the_inputs():
    loss, structure, icas = _every_gap()
    before = [copy.deepcopy(value.model_dump()) for value in (loss, structure, icas)]

    result = diagnose_final_artifacts(
        loss_analysis=loss, control_structure=structure, ica_enumeration=icas
    )

    assert {f.check for f in result.findings} == set(SpecCheck)
    assert [value.model_dump() for value in (loss, structure, icas)] == before


def test_findings_are_returned_not_raised_and_carry_no_disposition():
    loss, structure, icas = _every_gap()

    result = diagnose_final_artifacts(
        loss_analysis=loss, control_structure=structure, ica_enumeration=icas
    )

    assert result.findings
    assert all(f.disposition is None for f in result.findings)
    assert [s.findings for s in result.checks] == [
        len(_found(result, check)) for check in SpecCheck
    ]


def test_dispositions_are_exactly_the_three_human_judgements():
    assert [d.value for d in FindingDisposition] == [
        "fix the model",
        "accepted limitation",
        "causal scenario",
    ]


# Artifact writer -------------------------------------------------------------


def test_the_writer_round_trips_and_writes_an_unset_disposition_as_null(
    tmp_path: Path,
):
    loss, structure, icas = _every_gap()
    result = diagnose_final_artifacts(
        loss_analysis=loss, control_structure=structure, ica_enumeration=icas
    )

    path = write_spec_diagnostics(tmp_path / "out", result)

    assert path == tmp_path / "out" / SPEC_DIAGNOSTICS_FILENAME
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert document["schema_version"] == "stpa-spec-diagnostics-v1"
    assert all(
        "disposition" in f and f["disposition"] is None for f in document["findings"]
    )
    assert read_spec_diagnostics(path) == result


def test_a_recorded_disposition_is_read_back(tmp_path: Path):
    loss, structure, icas = _every_gap()
    path = write_spec_diagnostics(
        tmp_path,
        diagnose_final_artifacts(
            loss_analysis=loss, control_structure=structure, ica_enumeration=icas
        ),
    )
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["findings"][0]["disposition"] = "causal scenario"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    loaded = read_spec_diagnostics(path)

    assert loaded.findings[0].disposition is FindingDisposition.causal_scenario


def test_an_unknown_disposition_does_not_load(tmp_path: Path):
    path = write_spec_diagnostics(tmp_path, _diagnose(loss=_loss(("H-1", "H-2"))))
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    document["findings"][0]["disposition"] = "repaired"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    with pytest.raises(ValueError, match="disposition"):
        read_spec_diagnostics(path)
