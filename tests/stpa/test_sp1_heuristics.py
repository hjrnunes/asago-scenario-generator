"""Tests for SP1 structural heuristics and solution-neutrality checks.

Covers SP1-HEUR-01 through SP1-HEUR-09 and SP1-NEUT-01 through SP1-NEUT-06.
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model.heuristics import (
    check_solution_neutrality,
    run_heuristics,
)


def _make_responsibility(
    resp_id: str = "RESP-1",
    description: str = "Controller",
    pm_count: int = 1,
    ca_count: int = 1,
    fb_count: int = 1,
) -> Responsibility:
    """Build a responsibility with configurable element counts.

    When pm_count or fb_count is 0, the feedback channels are adjusted
    to avoid referencing non-existent PMs (which would fail foundation
    validation before the heuristics can run).
    """
    num = resp_id[-1]
    pms = [
        ProcessModelPart(
            pm_id=f"PM-{num}-{i + 1}",
            description=f"PM part {i + 1}",
        )
        for i in range(pm_count)
    ]
    cas = [
        ControlAction(
            ca_id=f"CA-{num}-{i + 1}",
            description=f"CA {i + 1}",
        )
        for i in range(ca_count)
    ]
    # Only create FB channels that reference existing PMs
    actual_fb_count = min(fb_count, pm_count) if pm_count > 0 else 0
    fbs = []
    for i in range(actual_fb_count):
        pm_id = f"PM-{num}-{i + 1}"
        fbs.append(
            FeedbackChannel(
                fb_id=f"FB-{num}-{i + 1}",
                description=f"FB {i + 1}",
                updates=pm_id,
                source=ElementRef(type=ReferenceType.responsibility, id=resp_id),
            )
        )
    return Responsibility(
        resp_id=resp_id,
        description=description,
        process_model_parts=pms,
        control_actions=cas,
        feedback_channels=fbs,
    )


def _make_control_structure(
    responsibilities: list[Responsibility] | None = None,
    controlled_processes: list[ControlledProcess] | None = None,
) -> ControlStructure:
    if responsibilities is None:
        responsibilities = [_make_responsibility()]
    if controlled_processes is None:
        controlled_processes = []
    return ControlStructure(
        responsibilities=responsibilities,
        controlled_processes=controlled_processes,
    )


def _make_loss_analysis_for_hazard(
    constraint_id: str = "SC-1",
) -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"]),
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id=constraint_id,
                rule="Constraint",
                related_hazards=["H-1"],
            ),
        ],
    )


class TestStructuralHeuristics:
    """SP1-HEUR-01 through SP1-HEUR-06."""

    def test_heur_01_valid_cs_passes(self):
        """SP1-HEUR-01: valid control structure passes all heuristics."""
        cs = _make_control_structure()
        result = run_heuristics(cs)
        assert result.passed
        assert len(result.errors) == 0

    @pytest.mark.parametrize(
        "element_type,error_fragment,pm_count,ca_count,fb_count",
        [
            ("process_model_parts", "process model part", 0, 1, 1),
            ("control_actions", "control action", 1, 0, 1),
            ("feedback_channels", "feedback channel", 1, 1, 0),
        ],
    )
    def test_heur_02_missing_element_fails(
        self, element_type, error_fragment, pm_count, ca_count, fb_count
    ):
        """SP1-HEUR-02: responsibility missing an element type fails."""
        resp = _make_responsibility(
            pm_count=pm_count, ca_count=ca_count, fb_count=fb_count
        )
        cs = _make_control_structure(responsibilities=[resp])
        result = run_heuristics(cs)
        assert not result.passed
        assert any(error_fragment in e for e in result.errors)

    def test_heur_03_orphan_pm_produces_warning(self):
        """SP1-HEUR-03: orphan PM not updated by any feedback produces warning."""
        resp = _make_responsibility(pm_count=2, fb_count=1)
        # FB-1-1 updates PM-1-1, so PM-1-2 is orphan
        cs = _make_control_structure(responsibilities=[resp])
        result = run_heuristics(cs)
        assert any("PM-1-2" in w for w in result.warnings)

    def test_heur_04_orphan_controlled_process_fails(self):
        """SP1-HEUR-04: controlled process not referenced by any FB or CA fails."""
        resp = _make_responsibility()
        cp = ControlledProcess(cp_id="CP-1", description="Unreferenced process")
        cs = _make_control_structure(responsibilities=[resp], controlled_processes=[cp])
        result = run_heuristics(cs)
        assert not result.passed
        assert any("controlled process" in e.lower() for e in result.errors)

    def test_heur_05_hazard_not_traced_fails(self):
        """SP1-HEUR-05: hazard not traced to any responsibility fails."""
        la = _make_loss_analysis_for_hazard("SC-1")
        # Control structure with no responsibility referencing SC-1
        resp = _make_responsibility()
        cs = _make_control_structure(responsibilities=[resp])
        result = run_heuristics(cs, la)
        assert not result.passed
        assert any("hazard" in e.lower() for e in result.errors)

    def test_heur_06_hazard_traced_passes(self):
        """SP1-HEUR-06: hazard traced to a responsibility passes."""
        la = _make_loss_analysis_for_hazard("SC-1")
        resp = Responsibility(
            resp_id="RESP-1",
            description="Controller",
            security_constraint_refs=["SC-1"],
            process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
            control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
            feedback_channels=[
                FeedbackChannel(
                    fb_id="FB-1-1",
                    description="FB",
                    updates="PM-1-1",
                    source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                )
            ],
        )
        cs = _make_control_structure(responsibilities=[resp])
        result = run_heuristics(cs, la)
        assert result.passed
        assert len(result.errors) == 0


class TestSolutionNeutrality:
    """SP1-NEUT-01 through SP1-NEUT-06."""

    @pytest.mark.parametrize(
        "component_name",
        ["LLM", "proxy", "orchestrator", "guardrail", "prompt", "API"],
    )
    def test_neut_01_component_in_responsibility_description(self, component_name):
        """SP1-NEUT-01: component name in responsibility description produces warning."""
        resp = _make_responsibility(
            description=f"The {component_name} must validate requests"
        )
        cs = _make_control_structure(responsibilities=[resp])
        warnings = check_solution_neutrality(cs)
        assert any(component_name.lower() in w.lower() for w in warnings)

    @pytest.mark.parametrize(
        "component_name",
        ["LLM", "proxy", "orchestrator", "guardrail", "prompt", "API"],
    )
    def test_neut_02_component_in_pm_description(self, component_name):
        """SP1-NEUT-02: component name in PM description produces warning."""
        resp = Responsibility(
            resp_id="RESP-1",
            description="Controller",
            process_model_parts=[
                ProcessModelPart(
                    pm_id="PM-1-1",
                    description=f"State of the {component_name}",
                )
            ],
            control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
            feedback_channels=[
                FeedbackChannel(
                    fb_id="FB-1-1",
                    description="FB",
                    updates="PM-1-1",
                    source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                )
            ],
        )
        cs = _make_control_structure(responsibilities=[resp])
        warnings = check_solution_neutrality(cs)
        assert any(component_name.lower() in w.lower() for w in warnings)

    def test_neut_03_neutral_description_no_warning(self):
        """SP1-NEUT-03: solution-neutral description produces no warning."""
        resp = _make_responsibility(
            description="The system must validate that user requests are within authorized scope"
        )
        cs = _make_control_structure(responsibilities=[resp])
        warnings = check_solution_neutrality(cs)
        assert len(warnings) == 0

    def test_neut_04_case_insensitive(self):
        """SP1-NEUT-04: check is case-insensitive."""
        resp = _make_responsibility(description="The llm must validate requests")
        cs = _make_control_structure(responsibilities=[resp])
        warnings = check_solution_neutrality(cs)
        assert len(warnings) > 0

    def test_neut_05_scans_all_element_types(self):
        """SP1-NEUT-05: check scans all element types (CA description)."""
        resp = Responsibility(
            resp_id="RESP-1",
            description="Controller",
            process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
            control_actions=[
                ControlAction(
                    ca_id="CA-1-1",
                    description="The orchestrator sends commands",
                )
            ],
            feedback_channels=[
                FeedbackChannel(
                    fb_id="FB-1-1",
                    description="FB",
                    updates="PM-1-1",
                    source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
                )
            ],
        )
        cs = _make_control_structure(responsibilities=[resp])
        warnings = check_solution_neutrality(cs)
        assert any("CA-1-1" in w for w in warnings)
        assert any("orchestrator" in w.lower() for w in warnings)
