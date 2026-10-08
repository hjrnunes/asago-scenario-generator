"""Unit tests for SP3 Stage 7 — Eval metrics."""

from __future__ import annotations

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
from asago_scenario_generator.stpa.scenario_prod.eval_metrics import (
    compute_eval_scorecard,
    metric_bdi_grounding,
    metric_diversity,
    metric_na_quality,
    metric_structural_consideration,
    metric_traceability_depth,
    metric_tree_branch_coverage,
    write_eval_scorecard,
)
from tests.helpers.stpa_builders import make_loss_analysis


def _make_cs() -> ControlStructure:
    cps = [ControlledProcess(cp_id="CP-1", description="Interface")]
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="R1",
                process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="S")],
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


def _make_scenario_spec(
    scenario_id: str = "SCN-001",
    target_resp: str = "RESP-1",
    ica_type: UCAType = UCAType.not_provided,
    pm_id: str = "PM-1-1",
    ca_id: str = "CA-1-1",
    provenance: str = "structural",
) -> ScenarioSpec:
    return ScenarioSpec(
        scenario_id=scenario_id,
        threat_source=ThreatSource(
            ica_slot_id=f"{target_resp}:{ca_id}:{ica_type.value}",
            provenance=provenance,
            ica_id=f"{target_resp}:{ca_id}:{ica_type.value}:1",
        ),
        target_controller=target_resp,
        target_control_action=ca_id,
        ica_type=ica_type,
        defender_bdi=DefenderBDI(
            beliefs=[
                DefenderBelief(pm_id=pm_id, content="State", vulnerability="vuln")
            ],
            desires=[DefenderDesire(resp_id=target_resp, content="R")],
            intentions=[DefenderIntention(ca_id=ca_id, content="A")],
        ),
        attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        loss_scenario="Loss",
    )


def _make_envelope(
    spec: ScenarioSpec | None = None,
    attack_tree: dict | None = None,
    ica_type: UCAType = UCAType.not_provided,
    target_resp: str = "RESP-1",
) -> ScenarioEnvelope:
    s = spec or _make_scenario_spec(ica_type=ica_type, target_resp=target_resp)
    tree = attack_tree or {
        "root": "r",
        "branches": [
            {"category": "controller_side", "label": "l", "children": []},
            {"category": "path_side", "label": "l", "children": []},
        ],
        "leaves": ["mechanism1"],
    }
    return ScenarioEnvelope(
        scenario_id=s.scenario_id,
        scenario_spec=s,
        narrative="narrative",
        attack_tree=tree,
        gherkin_spec=GherkinSpec(
            feature="Test",
            scenario="Test",
            given=["Given PM-1-1 is valid"],
            when=["When x"],
            then_expected=["Then should reject"],
            then_actual=["But approves"],
        ),
        target_responsibility=s.target_controller,
        ica_type=s.ica_type,
        provenance="structural",
    )


def _make_enriched_threat_set(
    structural_consideration: dict | None = None,
    na_quality: dict | None = None,
) -> EnrichedThreatSet:
    return EnrichedThreatSet(
        structural_threats=[
            StructuralThreat(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                ica_text="t",
                hazardous_context="c",
                loss_scenario="l",
                related_hazards=["H-1"],
                related_constraints=["SC-1"],
            ),
        ],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={
                "total_slots": 40,
                "non_na": 32,
                "na": 8,
                "coverage_rate": 0.8,
            },
            structural_consideration=structural_consideration
            or {
                "total_slots": 40,
                "considered": 40,
                "rate": 1.0,
            },
            na_quality=na_quality
            or {
                "na_count": 5,
                "quality_count": 4,
                "quality_rate": 0.8,
            },
        ),
    )


class TestStructuralConsideration:
    """SP3-EVAL-01."""

    def test_imported_from_sp2(self):
        ets = _make_enriched_threat_set(
            structural_consideration={"total_slots": 40, "considered": 40, "rate": 1.0}
        )
        result = metric_structural_consideration(ets)
        assert result["total_slots"] == 40
        assert result["considered"] == 40
        assert result["rate"] == 1.0


class TestNAQuality:
    """SP3-EVAL-02."""

    def test_imported_from_sp2(self):
        ets = _make_enriched_threat_set(
            na_quality={"na_count": 5, "quality_count": 4, "quality_rate": 0.8}
        )
        result = metric_na_quality(ets)
        assert result["na_count"] == 5
        assert result["quality_count"] == 4
        assert result["quality_rate"] == 0.8


class TestBDIGrounding:
    """SP3-EVAL-03, SP3-EVAL-04."""

    def test_grounding_rates(self):
        cs = _make_cs()
        # 5 scenarios: 4 with valid PM, 1 with invalid
        envelopes = []
        for i in range(4):
            envelopes.append(
                _make_envelope(
                    spec=_make_scenario_spec(
                        scenario_id=f"SCN-{i + 1:03d}", pm_id="PM-1-1"
                    )
                )
            )
        envelopes.append(
            _make_envelope(
                spec=_make_scenario_spec(scenario_id="SCN-005", pm_id="PM-99-1")
            )
        )
        result = metric_bdi_grounding(envelopes, cs)
        assert result["belief_grounding_rate"] == 0.8  # 4/5
        assert result["desire_grounding_rate"] == 1.0
        assert result["intention_grounding_rate"] == 1.0

    def test_zero_scenarios(self):
        cs = _make_cs()
        result = metric_bdi_grounding([], cs)
        assert result["belief_grounding_rate"] == 0
        assert result["desire_grounding_rate"] == 0
        assert result["intention_grounding_rate"] == 0


class TestTreeBranchCoverage:
    """SP3-EVAL-05, SP3-EVAL-06."""

    def test_coverage_rate(self):
        # 5 scenarios: 3 with 2+ categories, 2 with 1
        envelopes = []
        for i in range(3):
            envelopes.append(
                _make_envelope(
                    spec=_make_scenario_spec(scenario_id=f"SCN-{i + 1:03d}"),
                    attack_tree={
                        "root": "r",
                        "branches": [
                            {
                                "category": "controller_side",
                                "label": "l",
                                "children": [],
                            },
                            {"category": "path_side", "label": "l", "children": []},
                        ],
                        "leaves": [],
                    },
                )
            )
        for i in range(2):
            envelopes.append(
                _make_envelope(
                    spec=_make_scenario_spec(scenario_id=f"SCN-{i + 4:03d}"),
                    attack_tree={
                        "root": "r",
                        "branches": [
                            {
                                "category": "controller_side",
                                "label": "l",
                                "children": [],
                            },
                        ],
                        "leaves": [],
                    },
                )
            )
        result = metric_tree_branch_coverage(envelopes)
        assert result["total_scenarios"] == 5
        assert result["scenarios_with_2plus_categories"] == 3
        assert result["coverage_rate"] == 0.6

    def test_zero_scenarios(self):
        result = metric_tree_branch_coverage([])
        assert result["total_scenarios"] == 0
        assert result["coverage_rate"] == 0


class TestTraceabilityDepth:
    """SP3-EVAL-07, SP3-EVAL-08."""

    def test_complete_chains(self):
        cs = _make_cs()
        la = make_loss_analysis()
        ets = _make_enriched_threat_set()
        # 5 scenarios with valid chains
        envelopes = [
            _make_envelope(spec=_make_scenario_spec(scenario_id=f"SCN-{i + 1:03d}"))
            for i in range(5)
        ]
        result = metric_traceability_depth(envelopes, ets, cs, la)
        assert result["total_scenarios"] == 5
        assert result["complete_chains"] == 5
        assert result["traceability_rate"] == 1.0

    def test_zero_scenarios(self):
        cs = _make_cs()
        la = make_loss_analysis()
        ets = _make_enriched_threat_set()
        result = metric_traceability_depth([], ets, cs, la)
        assert result["total_scenarios"] == 0
        assert result["complete_chains"] == 0
        assert result["traceability_rate"] == 0

    def test_single_scenario_computed(self):
        """A single scenario must be computed, not short-circuited."""
        cs = _make_cs()
        la = make_loss_analysis()
        ets = _make_enriched_threat_set()
        env = _make_envelope(spec=_make_scenario_spec())
        result = metric_traceability_depth([env], ets, cs, la)
        assert result["total_scenarios"] == 1
        assert result["complete_chains"] >= 0


class TestDiversity:
    """SP3-EVAL-09 through SP3-EVAL-14."""

    def test_by_responsibility(self):
        envelopes = []
        for i in range(3):
            envelopes.append(
                _make_envelope(
                    spec=_make_scenario_spec(
                        scenario_id=f"SCN-{i + 1:03d}", target_resp="RESP-1"
                    )
                )
            )
        for i in range(2):
            envelopes.append(
                _make_envelope(
                    spec=_make_scenario_spec(
                        scenario_id=f"SCN-{i + 4:03d}",
                        target_resp="RESP-2",
                        ca_id="CA-2-1",
                    )
                )
            )
        result = metric_diversity(envelopes)
        assert result["by_responsibility"]["RESP-1"] == 3
        assert result["by_responsibility"]["RESP-2"] == 2

    def test_by_ica_type(self):
        envelopes = []
        for i in range(3):
            envelopes.append(
                _make_envelope(
                    spec=_make_scenario_spec(
                        scenario_id=f"SCN-{i + 1:03d}", ica_type=UCAType.not_provided
                    )
                )
            )
        for i in range(2):
            envelopes.append(
                _make_envelope(
                    spec=_make_scenario_spec(
                        scenario_id=f"SCN-{i + 4:03d}", ica_type=UCAType.incorrect
                    )
                )
            )
        result = metric_diversity(envelopes)
        assert result["by_ica_type"]["NOT_PROVIDED"] == 3
        assert result["by_ica_type"]["INCORRECT"] == 2

    def test_by_branch_category(self):
        envelopes = []
        for i in range(4):
            envelopes.append(
                _make_envelope(
                    spec=_make_scenario_spec(scenario_id=f"SCN-{i + 1:03d}"),
                    attack_tree={
                        "root": "r",
                        "branches": [
                            {
                                "category": "controller_side",
                                "label": "l",
                                "children": [],
                            },
                            {"category": "path_side", "label": "l", "children": []},
                        ],
                        "leaves": [],
                    },
                )
            )
        for i in range(3):
            envelopes.append(
                _make_envelope(
                    spec=_make_scenario_spec(scenario_id=f"SCN-{i + 5:03d}"),
                    attack_tree={
                        "root": "r",
                        "branches": [
                            {
                                "category": "controller_side",
                                "label": "l",
                                "children": [],
                            },
                            {
                                "category": "coordination_gap",
                                "label": "l",
                                "children": [],
                            },
                        ],
                        "leaves": [],
                    },
                )
            )
        result = metric_diversity(envelopes)
        assert result["by_branch_category"]["controller_side"] == 7
        assert result["by_branch_category"]["path_side"] == 4
        assert result["by_branch_category"]["coordination_gap"] == 3

    def test_responsibility_diversity_is_float(self):
        envelopes = [
            _make_envelope(
                spec=_make_scenario_spec(
                    scenario_id=f"SCN-{i + 1:03d}",
                    target_resp="RESP-1" if i < 3 else "RESP-2",
                    ca_id="CA-1-1" if i < 3 else "CA-2-1",
                )
            )
            for i in range(5)
        ]
        result = metric_diversity(envelopes)
        assert isinstance(result["responsibility_diversity"], float)
        assert result["responsibility_diversity"] >= 0

    def test_ica_type_diversity_is_float(self):
        envelopes = [
            _make_envelope(
                spec=_make_scenario_spec(
                    scenario_id=f"SCN-{i + 1:03d}",
                    ica_type=UCAType.not_provided if i < 3 else UCAType.incorrect,
                )
            )
            for i in range(5)
        ]
        result = metric_diversity(envelopes)
        assert isinstance(result["ica_type_diversity"], float)
        assert result["ica_type_diversity"] >= 0

    def test_unique_attack_mechanisms(self):
        envelopes = []
        for i in range(4):
            envelopes.append(
                _make_envelope(
                    spec=_make_scenario_spec(scenario_id=f"SCN-{i + 1:03d}"),
                    attack_tree={
                        "root": "r",
                        "branches": [],
                        "leaves": [f"mechanism_{i + 1}"],
                    },
                )
            )
        envelopes.append(
            _make_envelope(
                spec=_make_scenario_spec(scenario_id="SCN-005"),
                attack_tree={
                    "root": "r",
                    "branches": [],
                    "leaves": ["mechanism_1"],
                },  # duplicate
            )
        )
        result = metric_diversity(envelopes)
        assert result["unique_attack_mechanisms"] == 4

    def test_unique_mechanisms_with_dict_leaves(self):
        """Dict leaves use 'label' key; fallback uses str()."""
        envelopes = [
            _make_envelope(
                spec=_make_scenario_spec(scenario_id="SCN-001"),
                attack_tree={
                    "root": "r",
                    "branches": [],
                    "leaves": [
                        {"label": "dict_mechanism"},
                    ],
                },
            ),
            _make_envelope(
                spec=_make_scenario_spec(scenario_id="SCN-002"),
                attack_tree={
                    "root": "r",
                    "branches": [],
                    "leaves": [
                        {"label": "dict_mechanism"},  # duplicate
                    ],
                },
            ),
        ]
        result = metric_diversity(envelopes)
        assert result["unique_attack_mechanisms"] == 1

    def test_unique_mechanisms_with_mixed_leaf_types(self):
        """Mixed str, dict-with-label, dict-without-label, and int leaves."""
        envelopes = [
            _make_envelope(
                spec=_make_scenario_spec(scenario_id="SCN-001"),
                attack_tree={
                    "root": "r",
                    "branches": [],
                    "leaves": [
                        "string_leaf",
                        {"label": "labeled_leaf"},
                        {"no_label": "x"},
                        42,
                    ],
                },
            ),
        ]
        result = metric_diversity(envelopes)
        assert result["unique_attack_mechanisms"] == 4


class TestEvalScorecard:
    """SP3-EVAL-16, SP3-EVAL-17."""

    def test_scorecard_written_to_file(self):
        cs = _make_cs()
        la = make_loss_analysis()
        ets = _make_enriched_threat_set()
        envelopes = [_make_envelope(spec=_make_scenario_spec())]

        scorecard = compute_eval_scorecard(
            envelopes,
            ets,
            cs,
            la,
            stage_local_errors=["err1", "err2"],
            traceability_errors=["trace_err1"],
        )

        with TemporaryDirectory() as tmpdir:
            path = write_eval_scorecard(scorecard, Path(tmpdir))
            assert path.exists()
            import yaml

            data = yaml.safe_load(path.read_text())
            assert "metrics" in data
            assert "structural_consideration" in data["metrics"]
            assert "na_quality" in data["metrics"]
            assert "bdi_grounding" in data["metrics"]
            assert "tree_branch_coverage" in data["metrics"]
            assert "traceability_depth" in data["metrics"]
            assert "diversity" in data["metrics"]
            assert "validation" in data
            assert len(data["validation"]["stage_local_errors"]) == 2
            assert len(data["validation"]["traceability_errors"]) == 1
