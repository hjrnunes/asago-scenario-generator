"""Unit tests for SP3 Stage 7 — Coverage gap analysis."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ControlledProcess,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import (
    CoverageAnalysis,
    EnrichedThreatSet,
    StructuralThreat,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_envelope import (
    GherkinSpec,
    ScenarioEnvelope,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.scenario_prod.coverage import (
    compute_coverage_gaps,
    write_coverage_gaps,
)
from tests.helpers.sp3_coverage import _make_loss_analysis


def _make_cs() -> ControlStructure:
    cps = [ControlledProcess(cp_id="CP-1", description="Interface")]
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="R1",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="S1"),
                    ProcessModelPart(pm_id="PM-1-2", description="S2"),
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="A",
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="F",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                    FeedbackChannel(
                        fb_id="FB-1-2",
                        description="F2",
                        updates="PM-1-2",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="R2",
                process_model_parts=[ProcessModelPart(pm_id="PM-2-1", description="S")],
                control_actions=[
                    ControlAction(
                        ca_id="CA-2-1",
                        description="A",
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1",
                        description="F",
                        updates="PM-2-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
            ),
        ],
        controlled_processes=cps,
    )


def _make_scenario_spec(scenario_id: str = "SCN-001") -> ScenarioSpec:
    return ScenarioSpec(
        scenario_id=scenario_id,
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            provenance="structural",
            ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=UCAType.not_provided,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(pm_id="PM-1-1", content="S", vulnerability="v")],
            desires=[DefenderDesire(resp_id="RESP-1", content="R")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="A")],
        ),
        attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        loss_scenario="Loss",
    )


def _make_envelope(spec: ScenarioSpec | None = None) -> ScenarioEnvelope:
    s = spec or _make_scenario_spec()
    return ScenarioEnvelope(
        scenario_id=s.scenario_id,
        scenario_spec=s,
        narrative="n",
        attack_tree={
            "root": "r",
            "branches": [
                {"category": "controller_side", "label": "l", "children": []},
                {"category": "path_side", "label": "l", "children": []},
            ],
            "leaves": [],
        },
        gherkin_spec=GherkinSpec(
            feature="T",
            scenario="T",
            given=["Given PM-1-1"],
            when=["When x"],
            then_expected=["Then should r"],
            then_actual=["But a"],
        ),
        target_responsibility="RESP-1",
        ica_type=UCAType.not_provided,
        provenance="structural",
    )


def _make_ets(
    structural_coverage: dict | None = None,
    by_ica_type: dict | None = None,
    by_controller: dict | None = None,
    catalog_correspondence: dict | None = None,
    uncovered_owasp: list[str] | None = None,
    uncovered_reason: str | None = None,
    na_flags: list[str] | None = None,
    threats: list[StructuralThreat] | None = None,
) -> EnrichedThreatSet:
    return EnrichedThreatSet(
        structural_threats=threats
        or [
            StructuralThreat(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                ica_text="ICA text referencing PM-1-1",
                hazardous_context="Context",
                loss_scenario="Loss",
                related_hazards=["H-1"],
                related_constraints=["SC-1"],
            ),
        ],
        coverage_analysis=CoverageAnalysis(
            structural_coverage=structural_coverage
            or {
                "total_slots": 40,
                "non_na": 32,
                "na": 8,
                "coverage_rate": 0.8,
            },
            by_ica_type=by_ica_type or {},
            by_controller=by_controller or {},
            catalog_correspondence=catalog_correspondence or {},
            uncovered_owasp_threats=uncovered_owasp or [],
            uncovered_reason=uncovered_reason,
            na_reconciliation_flags=na_flags or [],
        ),
    )


class TestCoverageGaps:
    """SP3-COV-01 through SP3-COV-11."""

    def test_structural_coverage_from_sp2(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(
            structural_coverage={
                "total_slots": 40,
                "non_na": 32,
                "na": 8,
                "coverage_rate": 0.8,
            }
        )
        envs = [_make_envelope()]
        result = compute_coverage_gaps(ets, cs, envs, la)
        assert result["structural_coverage"]["total_slots"] == 40
        assert result["structural_coverage"]["non_na"] == 32
        assert result["structural_coverage"]["na"] == 8

    def test_by_ica_type(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(by_ica_type={"NOT_PROVIDED": 15, "INCORRECT": 10})
        envs = [_make_envelope()]
        result = compute_coverage_gaps(ets, cs, envs, la)
        assert result["by_ica_type"]["NOT_PROVIDED"] == 15
        assert result["by_ica_type"]["INCORRECT"] == 10

    def test_by_controller(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(by_controller={"RESP-1": 12, "RESP-2": 8})
        envs = [_make_envelope()]
        result = compute_coverage_gaps(ets, cs, envs, la)
        assert result["by_controller"]["RESP-1"] == 12
        assert result["by_controller"]["RESP-2"] == 8

    def test_catalog_correspondence(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(
            catalog_correspondence={
                "structural_with_match": 10,
                "structural_unmapped": 5,
                "catalog_only_supplements": 0,
            }
        )
        envs = [_make_envelope()]
        result = compute_coverage_gaps(ets, cs, envs, la)
        assert result["catalog_correspondence"]["structural_with_match"] == 10
        assert result["catalog_correspondence"]["structural_unmapped"] == 5
        assert result["catalog_correspondence"]["catalog_only_supplements"] == 0

    def test_uncovered_owasp_threats(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(uncovered_owasp=["T10"], uncovered_reason="No match")
        envs = [_make_envelope()]
        result = compute_coverage_gaps(ets, cs, envs, la)
        assert "T10" in result["uncovered_owasp_threats"]
        assert result["uncovered_reason"] is not None

    def test_orphan_elements(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        # PM-1-2 is not referenced by any ICA text
        ets = _make_ets()
        envs = [_make_envelope()]
        result = compute_coverage_gaps(ets, cs, envs, la)
        assert "PM-1-2" in result["orphan_elements"]

    def test_orphan_icas(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        threats = [
            StructuralThreat(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                ica_id=f"RESP-1:CA-1-1:NOT_PROVIDED:{i}",
                ica_text="t",
                hazardous_context="c",
                loss_scenario="l",
                related_hazards=["H-1"],
                related_constraints=["SC-1"],
            )
            for i in range(1, 11)
        ]
        ets = _make_ets(threats=threats)
        # Only 7 scenarios produced
        envs = [
            _make_envelope(spec=_make_scenario_spec(scenario_id=f"SCN-{i + 1:03d}"))
            for i in range(7)
        ]
        # But all specs reference ica_id :1, so we need different ica_ids
        for i, env in enumerate(envs):
            env.scenario_spec.threat_source.ica_id = (
                f"RESP-1:CA-1-1:NOT_PROVIDED:{i + 1}"
            )
        result = compute_coverage_gaps(ets, cs, envs, la)
        assert len(result["orphan_icas"]) == 3

    def test_traceability_errors(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        threats = [
            StructuralThreat(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                ica_id=f"RESP-1:CA-1-1:NOT_PROVIDED:{i}",
                ica_text="t",
                hazardous_context="c",
                loss_scenario="l",
                related_hazards=["H-99"],  # broken hazard
                related_constraints=["SC-1"],
            )
            for i in range(1, 3)
        ]
        ets = _make_ets(threats=threats)
        envs = []
        for i in range(2):
            spec = _make_scenario_spec(scenario_id=f"SCN-{i + 1:03d}")
            spec.threat_source.ica_id = f"RESP-1:CA-1-1:NOT_PROVIDED:{i + 1}"
            envs.append(_make_envelope(spec=spec))
        result = compute_coverage_gaps(ets, cs, envs, la)
        assert len(result["traceability_errors"]) == 2

    def test_na_reconciliation_flags(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets(na_flags=["flag1", "flag2"])
        envs = [_make_envelope()]
        result = compute_coverage_gaps(ets, cs, envs, la)
        assert len(result["na_reconciliation_flags"]) == 2

    def test_written_to_json(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets()
        envs = [_make_envelope()]
        result = compute_coverage_gaps(ets, cs, envs, la)

        with TemporaryDirectory() as tmpdir:
            path = write_coverage_gaps(result, Path(tmpdir))
            assert path.exists()
            assert path.name == "coverage-gaps.json"
            data = json.loads(path.read_text())
            assert "structural_coverage" in data
            assert "orphan_elements" in data
            assert "orphan_icas" in data
            assert "traceability_errors" in data
