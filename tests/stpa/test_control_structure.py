"""Tests for ControlStructure boundary schema validation.

Covers ControlStructure-01 through ControlStructure-17 from the Gherkin feature file.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ControlledProcess,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ResponsibilityConstraint,
    check_structural_heuristics,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model.id_normalization import (
    validate_normalized_control_structure,
)


def _make_element_ref(type: ReferenceType, id: str) -> ElementRef:
    return ElementRef(type=type, id=id)


def _make_pm(
    pm_id: str = "PM-1-1",
    feedback_source: ElementRef | None = None,
) -> ProcessModelPart:
    return ProcessModelPart(
        pm_id=pm_id,
        description="Process model part",
        feedback_source=feedback_source,
    )


def _make_ca(
    ca_id: str = "CA-1-1",
    target: ElementRef | None = None,
) -> ControlAction:
    return ControlAction(ca_id=ca_id, description="Control action", target=target)


def _make_fb(
    fb_id: str = "FB-1-1",
    updates: str = "PM-1-1",
    source: ElementRef | None = None,
) -> FeedbackChannel:
    return FeedbackChannel(
        fb_id=fb_id,
        description="Feedback",
        updates=updates,
        source=source or _make_element_ref(ReferenceType.responsibility, "RESP-1"),
    )


def _make_resp(
    resp_id: str = "RESP-1",
    pms: list[ProcessModelPart] | None = None,
    cas: list[ControlAction] | None = None,
    fbs: list[FeedbackChannel] | None = None,
    constraints: list[ResponsibilityConstraint] | None = None,
    security_constraint_refs: list[str] | None = None,
) -> Responsibility:
    return Responsibility(
        resp_id=resp_id,
        description="Responsibility",
        process_model_parts=pms if pms is not None else [_make_pm()],
        control_actions=cas if cas is not None else [_make_ca()],
        feedback_channels=fbs if fbs is not None else [_make_fb()],
        responsibility_constraints=constraints or [],
        security_constraint_refs=security_constraint_refs or [],
    )


def _make_cs(
    responsibilities: list[Responsibility] | None = None,
    controlled_processes: list[ControlledProcess] | None = None,
    coordination_links: list[CoordinationLink] | None = None,
) -> ControlStructure:
    return ControlStructure(
        responsibilities=responsibilities or [_make_resp()],
        controlled_processes=controlled_processes or [],
        coordination_links=coordination_links or [],
    )


class TestControlStructureValidation:
    """ControlStructure cross-reference validation rules."""

    def test_cs_01_valid_control_structure_passes(self):
        """CS-01: valid control structure passes validation."""
        cs = _make_cs()
        assert cs is not None

    def test_empty_control_action_description_is_repaired_after_id_normalization(self):
        """Empty descriptions receive canonical placeholders after ID repair."""
        payload = {
            "responsibilities": [
                {
                    "resp_id": "source-responsibility",
                    "description": "Controller",
                    "process_model_parts": [
                        {"pm_id": "source-state", "description": "State"}
                    ],
                    "control_actions": [{"ca_id": "source-action", "description": ""}],
                    "feedback_channels": [],
                }
            ],
            "controlled_processes": [],
            "coordination_links": [],
        }

        control_structure = validate_normalized_control_structure(payload)

        assert (
            control_structure.responsibilities[0].control_actions[0].description
            == "Control action CA-1-1"
        )

    @pytest.mark.parametrize(
        "ref_type,bad_ref",
        [
            (ReferenceType.responsibility, "RESP-99"),
            (ReferenceType.controlled_process, "CP-99"),
        ],
    )
    def test_cs_02_pm_feedback_source_nonexistent_fails(self, ref_type, bad_ref):
        """CS-02: PM feedback_source referencing non-existent element fails."""
        with pytest.raises(ValidationError) as exc_info:
            _make_cs(
                responsibilities=[
                    _make_resp(
                        pms=[
                            _make_pm(
                                feedback_source=_make_element_ref(ref_type, bad_ref)
                            )
                        ],
                    )
                ]
            )
        assert "feedback_source" in str(exc_info.value)

    @pytest.mark.parametrize(
        "ref_type,bad_ref",
        [
            (ReferenceType.responsibility, "RESP-99"),
            (ReferenceType.controlled_process, "CP-99"),
        ],
    )
    def test_cs_03_ca_target_nonexistent_fails(self, ref_type, bad_ref):
        """CS-03: CA target referencing non-existent element fails."""
        with pytest.raises(ValidationError) as exc_info:
            _make_cs(
                responsibilities=[
                    _make_resp(
                        cas=[_make_ca(target=_make_element_ref(ref_type, bad_ref))],
                    )
                ]
            )
        assert "target" in str(exc_info.value)

    def test_cs_04_fb_updates_nonexistent_pm_fails(self):
        """CS-04: feedback channel updates referencing non-existent PM fails."""
        with pytest.raises(ValidationError) as exc_info:
            _make_cs(responsibilities=[_make_resp(fbs=[_make_fb(updates="PM-99-1")])])
        assert "updates" in str(exc_info.value)

    def test_cs_05_fb_updates_pm_in_different_resp_fails(self):
        """CS-05: feedback channel updates referencing PM in different responsibility fails."""
        resp1 = _make_resp(
            resp_id="RESP-1",
            pms=[_make_pm("PM-1-1")],
            cas=[_make_ca("CA-1-1")],
            fbs=[_make_fb(updates="PM-2-1")],
        )
        resp2 = _make_resp(
            resp_id="RESP-2",
            pms=[_make_pm("PM-2-1")],
            cas=[_make_ca("CA-2-1")],
            fbs=[
                _make_fb(
                    fb_id="FB-2-1",
                    updates="PM-2-1",
                    source=_make_element_ref(ReferenceType.responsibility, "RESP-2"),
                )
            ],
        )
        with pytest.raises(ValidationError) as exc_info:
            _make_cs(responsibilities=[resp1, resp2])
        assert "different" in str(exc_info.value)

    @pytest.mark.parametrize(
        "ref_type,bad_ref",
        [
            (ReferenceType.responsibility, "RESP-99"),
            (ReferenceType.controlled_process, "CP-99"),
        ],
    )
    def test_cs_06_fb_source_nonexistent_fails(self, ref_type, bad_ref):
        """CS-06: feedback channel source referencing non-existent element fails."""
        with pytest.raises(ValidationError) as exc_info:
            _make_cs(
                responsibilities=[
                    _make_resp(
                        fbs=[_make_fb(source=_make_element_ref(ref_type, bad_ref))],
                    )
                ]
            )
        assert "source" in str(exc_info.value)

    def test_cs_07_coordination_link_valid_source_target_passes(self):
        """CS-07: coordination link with valid source and target passes."""
        resp1 = _make_resp(
            resp_id="RESP-1",
            pms=[_make_pm("PM-1-1")],
            cas=[_make_ca("CA-1-1")],
        )
        resp2 = _make_resp(
            resp_id="RESP-2",
            pms=[_make_pm("PM-2-1")],
            cas=[_make_ca("CA-2-1")],
            fbs=[
                _make_fb(
                    fb_id="FB-2-1",
                    updates="PM-2-1",
                    source=_make_element_ref(ReferenceType.responsibility, "RESP-2"),
                )
            ],
        )
        link = CoordinationLink(
            link_id="CL-1",
            source="RESP-1",
            target="RESP-2",
            shared_pm="PM-1-1",
            coordination_mechanism=CoordinationMechanism(
                cm_id="CM-1",
                description="Coordination",
                payload="data",
            ),
            description="Link",
        )
        cs = _make_cs(responsibilities=[resp1, resp2], coordination_links=[link])
        assert cs is not None

    @pytest.mark.parametrize("field", ["source", "target"])
    def test_cs_08_coordination_link_nonexistent_resp_fails(self, field):
        """CS-08: coordination link referencing non-existent responsibility fails."""
        resp1 = _make_resp()
        link = CoordinationLink(
            link_id="CL-1",
            source="RESP-1" if field != "source" else "RESP-99",
            target="RESP-1" if field != "target" else "RESP-99",
            shared_pm="PM-1-1",
            coordination_mechanism=CoordinationMechanism(
                cm_id="CM-1", description="Coord", payload="data"
            ),
            description="Link",
        )
        # Need two responsibilities for valid target, but we only have RESP-1
        # The link references RESP-99 which doesn't exist
        with pytest.raises(ValidationError) as exc_info:
            _make_cs(responsibilities=[resp1], coordination_links=[link])
        assert field in str(exc_info.value)

    def test_cs_09_coordination_link_shared_pm_nonexistent_fails(self):
        """CS-09: coordination link shared_pm referencing non-existent PM fails."""
        resp1 = _make_resp()
        link = CoordinationLink(
            link_id="CL-1",
            source="RESP-1",
            target="RESP-1",
            shared_pm="PM-99-1",
            coordination_mechanism=CoordinationMechanism(
                cm_id="CM-1", description="Coord", payload="data"
            ),
            description="Link",
        )
        with pytest.raises(ValidationError) as exc_info:
            _make_cs(responsibilities=[resp1], coordination_links=[link])
        assert "shared_pm" in str(exc_info.value)

    @pytest.mark.parametrize(
        "id_field,dup_value",
        [
            ("resp_id", "RESP-1"),
            ("cp_id", "CP-1"),
            ("pm_id", "PM-1-1"),
            ("ca_id", "CA-1-1"),
            ("fb_id", "FB-1-1"),
            ("link_id", "CL-1"),
        ],
    )
    def test_cs_10_duplicate_ids_fail(self, id_field, dup_value):
        """CS-10: duplicate IDs fail validation."""
        with pytest.raises(ValidationError) as exc_info:
            if id_field == "resp_id":
                _make_cs(
                    responsibilities=[_make_resp(dup_value), _make_resp(dup_value)]
                )
            elif id_field == "cp_id":
                _make_cs(
                    controlled_processes=[
                        ControlledProcess(cp_id=dup_value, description="CP"),
                        ControlledProcess(cp_id=dup_value, description="CP"),
                    ]
                )
            elif id_field == "pm_id":
                _make_cs(
                    responsibilities=[
                        _make_resp(
                            pms=[_make_pm(dup_value), _make_pm(dup_value)],
                        )
                    ]
                )
            elif id_field == "ca_id":
                _make_cs(
                    responsibilities=[
                        _make_resp(
                            cas=[_make_ca(dup_value), _make_ca(dup_value)],
                        )
                    ]
                )
            elif id_field == "fb_id":
                _make_cs(
                    responsibilities=[
                        _make_resp(
                            fbs=[_make_fb(dup_value), _make_fb(dup_value)],
                        )
                    ]
                )
            elif id_field == "link_id":
                resp1 = _make_resp()
                link1 = CoordinationLink(
                    link_id=dup_value,
                    source="RESP-1",
                    target="RESP-1",
                    shared_pm="PM-1-1",
                    coordination_mechanism=CoordinationMechanism(
                        cm_id="CM-1", description="Coord", payload="data"
                    ),
                    description="Link",
                )
                link2 = CoordinationLink(
                    link_id=dup_value,
                    source="RESP-1",
                    target="RESP-1",
                    shared_pm="PM-1-1",
                    coordination_mechanism=CoordinationMechanism(
                        cm_id="CM-1", description="Coord", payload="data"
                    ),
                    description="Link",
                )
                _make_cs(responsibilities=[resp1], coordination_links=[link1, link2])
        assert "duplicate" in str(exc_info.value).lower()


class TestControlStructureHeuristics:
    """ControlStructure structural heuristic post-checks."""

    def test_cs_11_resp_no_pm_fails_heuristic(self):
        """CS-11: responsibility with zero PMs fails structural heuristic."""
        # A responsibility with zero PMs must also have no FBs (since FB.updates
        # references a PM). Both heuristic checks will fire.
        resp = Responsibility(
            resp_id="RESP-1",
            description="Controller",
            process_model_parts=[],
            control_actions=[_make_ca()],
            feedback_channels=[],
        )
        cs = ControlStructure(responsibilities=[resp])
        result = check_structural_heuristics(cs)
        assert not result.passed
        assert any("process model part" in e for e in result.errors)

    def test_cs_12_resp_no_ca_fails_heuristic(self):
        """CS-12: responsibility with zero CAs fails structural heuristic."""
        resp = Responsibility(
            resp_id="RESP-1",
            description="Controller",
            process_model_parts=[_make_pm()],
            control_actions=[],
            feedback_channels=[_make_fb()],
        )
        cs = ControlStructure(responsibilities=[resp])
        result = check_structural_heuristics(cs)
        assert not result.passed
        assert any("control action" in e for e in result.errors)

    def test_cs_13_resp_no_fb_fails_heuristic(self):
        """CS-13: responsibility with zero FBs fails structural heuristic."""
        resp = Responsibility(
            resp_id="RESP-1",
            description="Controller",
            process_model_parts=[_make_pm()],
            control_actions=[_make_ca()],
            feedback_channels=[],
        )
        cs = ControlStructure(responsibilities=[resp])
        result = check_structural_heuristics(cs)
        assert not result.passed
        assert any("feedback channel" in e for e in result.errors)

    def test_cs_14_orphan_pm_produces_warning(self):
        """CS-14: orphan PM not updated by any FB produces warning."""
        cs = _make_cs(
            responsibilities=[
                _make_resp(
                    pms=[_make_pm("PM-1-1"), _make_pm("PM-1-2")],
                    fbs=[_make_fb(updates="PM-1-1")],
                )
            ]
        )
        result = check_structural_heuristics(cs)
        assert result.passed  # warnings don't fail
        assert any("PM-1-2" in w for w in result.warnings)

    def test_cs_15_cp_not_referenced_fails_heuristic(self):
        """CS-15: controlled process not referenced fails structural heuristic."""
        cs = _make_cs(
            controlled_processes=[
                ControlledProcess(cp_id="CP-1", description="Process"),
            ]
        )
        result = check_structural_heuristics(cs)
        assert not result.passed
        assert any("controlled process" in e.lower() for e in result.errors)

    def test_cs_15a_cp_not_referenced_with_fb_source_none_fails(self):
        """CS-15a: CP not referenced when FB source is None still fails heuristic.

        This covers the case where feedback channels have no source set,
        ensuring _add_cps_from_feedback correctly skips them.
        """
        fb_no_source = FeedbackChannel(
            fb_id="FB-1-1",
            description="Feedback",
            updates="PM-1-1",
            source=None,
        )
        cs = _make_cs(
            responsibilities=[
                _make_resp(
                    pms=[_make_pm()],
                    cas=[_make_ca()],
                    fbs=[fb_no_source],
                )
            ],
            controlled_processes=[
                ControlledProcess(cp_id="CP-1", description="Process"),
            ],
        )
        result = check_structural_heuristics(cs)
        assert not result.passed
        assert any("controlled process" in e.lower() for e in result.errors)

    def test_cs_15b_cp_referenced_by_ca_target_passes(self):
        """CS-15b: controlled process referenced by CA target passes heuristic."""
        cs = _make_cs(
            responsibilities=[
                _make_resp(
                    cas=[
                        _make_ca(
                            target=_make_element_ref(
                                ReferenceType.controlled_process, "CP-1"
                            )
                        )
                    ],
                )
            ],
            controlled_processes=[
                ControlledProcess(cp_id="CP-1", description="Process"),
            ],
        )
        result = check_structural_heuristics(cs)
        assert result.passed

    def test_cs_15c_cp_referenced_by_feedback_source_passes(self):
        """CS-15c: controlled process referenced by feedback source passes heuristic."""
        cs = _make_cs(
            responsibilities=[
                _make_resp(
                    fbs=[
                        _make_fb(
                            source=_make_element_ref(
                                ReferenceType.controlled_process, "CP-1"
                            )
                        )
                    ],
                )
            ],
            controlled_processes=[
                ControlledProcess(cp_id="CP-1", description="Process"),
            ],
        )
        result = check_structural_heuristics(cs)
        assert result.passed

    def test_cs_16_hazard_not_traced_fails_heuristic(self):
        """CS-16: hazard not traced to any responsibility fails structural heuristic."""
        la = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[
                Loss(
                    loss_id="L-1",
                    description="Loss",
                    provenance=LossProvenance.use_case,
                )
            ],
            hazards=[
                Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])
            ],
            security_constraints=[
                SecurityConstraint(
                    constraint_id="SC-1",
                    rule="Constraint",
                    related_hazards=["H-1"],
                )
            ],
        )
        cs = _make_cs()
        result = check_structural_heuristics(cs, loss_analysis=la)
        assert not result.passed
        assert any("hazard" in e.lower() for e in result.errors)

    def test_cs_17_hazard_traced_to_resp_passes_heuristic(self):
        """CS-17: hazard traced to a responsibility passes structural heuristic."""
        la = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[
                Loss(
                    loss_id="L-1",
                    description="Loss",
                    provenance=LossProvenance.use_case,
                )
            ],
            hazards=[
                Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])
            ],
            security_constraints=[
                SecurityConstraint(
                    constraint_id="SC-1",
                    rule="Constraint",
                    related_hazards=["H-1"],
                )
            ],
        )
        # The hazard is traced via SC-1 -> responsibility.security_constraint_refs
        # containing SC-1 -> RESP-1.
        cs = _make_cs(
            responsibilities=[
                _make_resp(
                    constraints=[],
                    security_constraint_refs=["SC-1"],
                )
            ]
        )
        result = check_structural_heuristics(cs, loss_analysis=la)
        assert result.passed
