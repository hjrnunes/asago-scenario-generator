"""One id index over a control structure and its loss analysis."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlledProcess,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    FeedbackChannel,
    ProcessModelPart,
    Responsibility,
    ResponsibilityConstraint,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    build_stpa_index,
)


def _structure() -> ControlStructure:
    def responsibility(number: int) -> Responsibility:
        return Responsibility(
            resp_id=f"RESP-{number}",
            description=f"Controller {number}",
            responsibility_constraints=[
                ResponsibilityConstraint(
                    rc_id=f"RC-{number}-1", description=f"Limit {number}"
                )
            ],
            process_model_parts=[
                ProcessModelPart(pm_id=f"PM-{number}-1", description=f"Belief {number}")
            ],
            control_actions=[
                ControlAction(
                    ca_id=f"CA-{number}-1",
                    description=f"Act {number}",
                    target={"type": "controlled_process", "id": "CP-1"},
                )
            ],
            feedback_channels=[
                FeedbackChannel(
                    fb_id=f"FB-{number}-1",
                    description=f"Signal {number}",
                    source={"type": "controlled_process", "id": "CP-1"},
                    updates=f"PM-{number}-1",
                )
            ],
        )

    return ControlStructure(
        responsibilities=[responsibility(1), responsibility(2)],
        controlled_processes=[ControlledProcess(cp_id="CP-1", description="Store")],
        coordination_links=[
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1", description="Handoff", payload="ticket"
                ),
                description="Controller 1 hands work to controller 2.",
            )
        ],
    )


def _loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(loss_id="L-1", description="Data loss", provenance="use_case")
        ],
        hazards=[
            Hazard(hazard_id="H-1", description="Unsafe write", related_losses=["L-1"])
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Check writes",
                description="Check writes",
                related_hazards=["H-1"],
            )
        ],
    )


def test_the_index_finds_every_record_by_its_id() -> None:
    structure, losses = _structure(), _loss_analysis()

    index = build_stpa_index(structure, losses)

    assert index.responsibilities["RESP-2"] is structure.responsibilities[1]
    assert set(index.responsibility_constraints) == {"RC-1-1", "RC-2-1"}
    assert set(index.process_model_parts) == {"PM-1-1", "PM-2-1"}
    assert set(index.control_actions) == {"CA-1-1", "CA-2-1"}
    assert set(index.feedback_channels) == {"FB-1-1", "FB-2-1"}
    assert index.controlled_processes["CP-1"].description == "Store"
    assert index.coordination_links["CL-1"].target == "RESP-2"
    assert index.coordination_mechanisms["CM-1"].description == "Handoff"
    assert index.hazards["H-1"].description == "Unsafe write"
    assert index.security_constraints["SC-1"].rule == "Check writes"
    assert index.losses["L-1"].description == "Data loss"


def test_an_action_is_found_only_under_the_responsibility_that_owns_it() -> None:
    index = build_stpa_index(_structure())

    assert index.owned_action("RESP-1", "CA-1-1").description == "Act 1"
    assert index.owned_action("RESP-2", "CA-1-1") is None
    assert index.owned_action(None, "CA-1-1") is None


def test_an_index_without_a_loss_analysis_has_no_loss_records() -> None:
    index = build_stpa_index(_structure())

    assert index.hazards == {}
    assert index.security_constraints == {}
    assert index.losses == {}


def test_the_first_record_wins_when_an_unvalidated_structure_repeats_an_id() -> None:
    structure = _structure()
    copy = structure.responsibilities[0].model_copy(update={"description": "Later"})
    structure = structure.model_copy(
        update={"responsibilities": [*structure.responsibilities, copy]}
    )

    index = build_stpa_index(structure)

    assert index.responsibilities["RESP-1"].description == "Controller 1"


def test_descriptions_cover_the_structure_then_the_loss_analysis() -> None:
    index = build_stpa_index(_structure(), _loss_analysis())

    assert index.structural_descriptions() == {
        "RESP-1": "Controller 1",
        "RC-1-1": "Limit 1",
        "PM-1-1": "Belief 1",
        "CA-1-1": "Act 1",
        "FB-1-1": "Signal 1",
        "RESP-2": "Controller 2",
        "RC-2-1": "Limit 2",
        "PM-2-1": "Belief 2",
        "CA-2-1": "Act 2",
        "FB-2-1": "Signal 2",
        "CP-1": "Store",
        "CL-1": "Controller 1 hands work to controller 2.",
        "CM-1": "Handoff",
    }
    assert index.loss_descriptions() == {
        "SC-1": "Check writes",
        "H-1": "Unsafe write",
        "L-1": "Data loss",
    }
