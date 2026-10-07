"""Stage 1a and Stage 2 evidence: one file name per version of an artifact.

The canonical ``loss-analysis.yaml`` and ``control-structure.yaml`` hold the
graph in force at the end of a stage.  Every intermediate version is written
under its own name, so a reader can tell which version a file holds, and the
canonical name is written once per stage boundary instead of after each step.
"""

from __future__ import annotations

from collections import Counter
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import yaml

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml as real_write_yaml
from asago_scenario_generator.stpa.system_model import control_structure as cs_module
from asago_scenario_generator.stpa.system_model import loss_analysis as la_module
from asago_scenario_generator.stpa.system_model import run as run_module
from asago_scenario_generator.stpa.system_model.control_structure import (
    CoordinationAnalysis,
)
from asago_scenario_generator.stpa.system_model.run import run_sp1
from tests.stpa.sp1_helpers import (
    setup_sp1_mock_client,
    valid_empty_coordination_analysis_dict,
)

CANONICAL = ("loss-analysis.yaml", "control-structure.yaml")


def _risk_cards() -> list[RiskCard]:
    return [
        RiskCard(
            risk_id="atlas-001",
            risk_name="atlas-001",
            risk_description="Risk atlas-001",
            taxonomy="test",
            confidence=0.9,
            grounding_confidence="high",
        )
    ]


def _load(run_dir: Path, name: str) -> dict:
    return yaml.safe_load((run_dir / name).read_text())


def _unresolved_review() -> dict:
    payload = valid_empty_coordination_analysis_dict(
        constraint_ids=("SC-1", "SC-2"),
        hazard_ids=("H-1", "H-2"),
    )
    row = payload["semantic_review"]["constraints"][1]
    row["disposition"] = "unresolved"
    row["missing_fact"] = "The supplied sources do not ground this wording."
    row["related_hazards"] = []
    return payload


def _hazards_by_constraint(document: dict) -> list[list[str]]:
    return [sc["related_hazards"] for sc in document["security_constraints"]]


def _spy_canonical_writes(writes: Counter):
    """Return patches that count canonical writes by the module that made them."""
    patches = []
    for label, module in (
        ("loss_analysis", la_module),
        ("control_structure", cs_module),
        ("run", run_module),
    ):

        def spy(value, path, *args, _label=label, **kwargs):
            if Path(path).name in CANONICAL:
                writes[(_label, Path(path).name)] += 1
            return real_write_yaml(value, path, *args, **kwargs)

        patches.append(patch.object(module, "write_yaml", side_effect=spy))
    return patches


class TestReviewedLossAnalysisVersions:
    def test_review_is_kept_under_its_own_name_and_canonical_holds_it(self, tmp_path):
        client = setup_sp1_mock_client()
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(),
            run_dir=tmp_path,
        )

        assert result.loss_analysis is not None
        reviewed = (tmp_path / "loss-analysis-reviewed.yaml").read_bytes()
        assert reviewed == (tmp_path / "loss-analysis.yaml").read_bytes()
        assert not (tmp_path / "loss-analysis-reviewed-corrected.yaml").exists()

    def test_failed_recheck_leaves_the_graph_in_force_in_the_canonical_name(
        self, tmp_path
    ):
        client = setup_sp1_mock_client()
        client.set_response_for(CoordinationAnalysis, _unresolved_review())
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(),
            run_dir=tmp_path,
        )

        assert result.control_structure is None
        reviewed = _load(tmp_path, "loss-analysis-reviewed.yaml")
        assert _hazards_by_constraint(reviewed) == [["H-1"], []]
        # The one correction round repeated the unresolved decision, so the
        # corrected version equals the reviewed one and canonical follows it.
        corrected = _load(tmp_path, "loss-analysis-reviewed-corrected.yaml")
        assert corrected == reviewed
        assert _load(tmp_path, "loss-analysis.yaml") == corrected
        assert _hazards_by_constraint(_load(tmp_path, "loss-analysis-draft.yaml")) == [
            ["H-1"],
            ["H-2"],
        ]

    def test_correction_is_a_separate_version_and_canonical_follows_it(self, tmp_path):
        corrected = valid_empty_coordination_analysis_dict(
            constraint_ids=("SC-1", "SC-2"),
            hazard_ids=("H-1", "H-2"),
        )
        client = setup_sp1_mock_client()
        client.set_response_for(CoordinationAnalysis, [_unresolved_review(), corrected])
        result = run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=_risk_cards(),
            run_dir=tmp_path,
        )

        assert result.stage_errors == []
        first = _load(tmp_path, "loss-analysis-reviewed.yaml")
        second = _load(tmp_path, "loss-analysis-reviewed-corrected.yaml")
        assert _hazards_by_constraint(first) == [["H-1"], []]
        assert _hazards_by_constraint(second) == [["H-1"], ["H-2"]]
        assert _load(tmp_path, "loss-analysis.yaml") == second

    def test_canonical_loss_analysis_is_written_once_per_stage(self, tmp_path):
        corrected = valid_empty_coordination_analysis_dict(
            constraint_ids=("SC-1", "SC-2"),
            hazard_ids=("H-1", "H-2"),
        )
        client = setup_sp1_mock_client()
        client.set_response_for(CoordinationAnalysis, [_unresolved_review(), corrected])
        writes: Counter = Counter()
        spies = _spy_canonical_writes(writes)
        with spies[0], spies[1], spies[2]:
            run_sp1(
                llm_client=client,
                use_case_text="Test use case",
                risk_cards=_risk_cards(),
                run_dir=tmp_path,
            )

        assert writes[("loss_analysis", "loss-analysis.yaml")] == 1
        assert writes[("control_structure", "loss-analysis.yaml")] == 1
        assert writes[("run", "loss-analysis.yaml")] == 0


class TestControlStructureVersions:
    @staticmethod
    def _tagged(tag):
        def step(control_structure, *_args, **_kwargs):
            changed = control_structure.model_copy(
                update={
                    "responsibilities": [
                        item.model_copy(
                            update={"description": f"{item.description} {tag}"}
                        )
                        for item in control_structure.responsibilities
                    ]
                }
            )
            return changed, [f"{tag} warning"]

        return step

    def _run(self, run_dir: Path, writes: Counter | None = None):
        base = "asago_scenario_generator.stpa.system_model.run."

        def revise(*, control_structure, **_kwargs):
            return self._tagged("revised")(control_structure)

        patches = [
            patch(base + "check_evidence_bindings", side_effect=self._tagged("bound")),
            patch(
                base + "attach_to_sole_reply_responsibility",
                side_effect=self._tagged("placed"),
            ),
            patch(base + "has_unjustified_gaps", return_value=True),
            patch(base + "run_revision", side_effect=revise),
        ]
        if writes is not None:
            patches.extend(_spy_canonical_writes(writes))
        with ExitStack() as stack:
            for item in patches:
                stack.enter_context(item)
            return run_sp1(
                llm_client=setup_sp1_mock_client(),
                use_case_text="Test use case",
                risk_cards=_risk_cards(),
                run_dir=run_dir,
            )

    @staticmethod
    def _description(run_dir: Path, name: str) -> str:
        return _load(run_dir, name)["responsibilities"][0]["description"]

    def test_each_step_keeps_its_own_version(self, tmp_path):
        self._run(tmp_path)

        reviewed = self._description(tmp_path, "control-structure-reviewed.yaml")
        bound = self._description(tmp_path, "control-structure-evidence-bound.yaml")
        revised = self._description(tmp_path, "control-structure-revised.yaml")
        placed = self._description(tmp_path, "control-structure-placed.yaml")
        assert not reviewed.endswith(("bound", "revised", "placed"))
        assert bound == f"{reviewed} bound"
        assert revised == f"{bound} revised bound"
        assert placed == f"{revised} placed"

    def test_canonical_holds_the_final_version(self, tmp_path):
        result = self._run(tmp_path)

        assert self._description(tmp_path, "control-structure.yaml") == (
            self._description(tmp_path, "control-structure-placed.yaml")
        )
        assert result.control_structure.responsibilities[0].description.endswith(
            "revised bound placed"
        )

    def test_canonical_control_structure_is_written_by_derivation_and_stage_end(
        self, tmp_path
    ):
        writes: Counter = Counter()
        self._run(tmp_path, writes)

        assert writes[("control_structure", "control-structure.yaml")] == 1
        assert writes[("run", "control-structure.yaml")] == 1

    def test_unchanged_steps_write_no_extra_version(self, tmp_path):
        run_sp1(
            llm_client=setup_sp1_mock_client(),
            use_case_text="Test use case",
            risk_cards=_risk_cards(),
            run_dir=tmp_path,
        )

        assert (tmp_path / "control-structure-reviewed.yaml").exists()
        assert (tmp_path / "control-structure.yaml").read_bytes() == (
            tmp_path / "control-structure-reviewed.yaml"
        ).read_bytes()
        for name in (
            "control-structure-evidence-bound.yaml",
            "control-structure-revised.yaml",
            "control-structure-placed.yaml",
        ):
            assert not (tmp_path / name).exists()
