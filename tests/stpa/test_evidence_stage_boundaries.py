"""Stage 1a and Stage 2 evidence: one file name per version of an artifact.

The canonical ``loss-analysis.yaml`` and ``control-structure.yaml`` hold the
graph in force at the end of a stage, written once per stage boundary.  Each
intermediate version keeps its own name and is written only when it differs
from the next version, so an absent version equals the next one on disk.
"""

from __future__ import annotations

from collections import Counter
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import yaml

from asago_scenario_generator.stpa.infra.yaml_io import VersionChain
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml as real_write_yaml
from asago_scenario_generator.stpa.system_model import control_structure as cs_module
from asago_scenario_generator.stpa.system_model import loss_analysis as la_module
from asago_scenario_generator.stpa.system_model import run as run_module
from asago_scenario_generator.stpa.system_model.control_structure import (
    CoordinationAnalysis,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    RevisionOutcome,
)
from asago_scenario_generator.stpa.system_model.run import run_sp1
from tests.helpers.stpa_builders import make_risk_cards
from tests.stpa.sp1_helpers import (
    setup_sp1_mock_client,
    valid_empty_coordination_analysis_dict,
)

CANONICAL = ("loss-analysis.yaml", "control-structure.yaml")


def _load(run_dir: Path, name: str) -> dict:
    return yaml.safe_load((run_dir / name).read_text())


def _run_sp1(client, tmp_path):
    return run_sp1(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=make_risk_cards(),
        run_dir=tmp_path,
    )


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
    """Return patches that count canonical writes by the code that made them."""
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
    real_publish = VersionChain.publish

    def publish(chain, model, name):
        writes[("chain", name)] += 1
        return real_publish(chain, model, name)

    patches.append(patch.object(VersionChain, "publish", publish))
    return patches


def _absent(run_dir: Path, *names: str) -> None:
    for name in names:
        assert not (run_dir / name).exists(), name


class TestReviewedLossAnalysisVersions:
    def test_an_unchanging_review_writes_no_copy_of_the_canonical(self, tmp_path):
        client = setup_sp1_mock_client()
        result = _run_sp1(client, tmp_path)

        assert result.loss_analysis is not None
        assert (tmp_path / "loss-analysis.yaml").exists()
        _absent(
            tmp_path,
            "loss-analysis-draft.yaml",
            "loss-analysis-reviewed.yaml",
            "loss-analysis-reviewed-corrected.yaml",
        )

    def test_failed_recheck_leaves_the_graph_in_force_in_the_canonical_name(
        self, tmp_path
    ):
        client = setup_sp1_mock_client()
        client.set_response_for(CoordinationAnalysis, _unresolved_review())
        result = _run_sp1(client, tmp_path)

        assert result.control_structure is None
        # The one correction round repeated the unresolved decision, so the
        # reviewed and corrected versions equal the canonical graph.
        assert _hazards_by_constraint(_load(tmp_path, "loss-analysis.yaml")) == [
            ["H-1"],
            [],
        ]
        _absent(
            tmp_path,
            "loss-analysis-reviewed.yaml",
            "loss-analysis-reviewed-corrected.yaml",
        )
        assert _hazards_by_constraint(_load(tmp_path, "loss-analysis-draft.yaml")) == [
            ["H-1"],
            ["H-2"],
        ]

    def test_a_replaced_review_keeps_its_own_version(self, tmp_path):
        corrected = valid_empty_coordination_analysis_dict(
            constraint_ids=("SC-1", "SC-2"),
            hazard_ids=("H-1", "H-2"),
        )
        client = setup_sp1_mock_client()
        client.set_response_for(CoordinationAnalysis, [_unresolved_review(), corrected])
        result = _run_sp1(client, tmp_path)

        assert result.stage_errors == []
        first = _load(tmp_path, "loss-analysis-reviewed.yaml")
        assert _hazards_by_constraint(first) == [["H-1"], []]
        canonical = _load(tmp_path, "loss-analysis.yaml")
        assert _hazards_by_constraint(canonical) == [["H-1"], ["H-2"]]
        # The draft equals the corrected graph, but not the reviewed one it
        # precedes, so it is kept; the corrected version equals the canonical.
        assert _load(tmp_path, "loss-analysis-draft.yaml") == canonical
        _absent(tmp_path, "loss-analysis-reviewed-corrected.yaml")

    def test_canonical_loss_analysis_is_written_once_per_stage(self, tmp_path):
        corrected = valid_empty_coordination_analysis_dict(
            constraint_ids=("SC-1", "SC-2"),
            hazard_ids=("H-1", "H-2"),
        )
        client = setup_sp1_mock_client()
        client.set_response_for(CoordinationAnalysis, [_unresolved_review(), corrected])
        writes: Counter = Counter()
        with ExitStack() as stack:
            for item in _spy_canonical_writes(writes):
                stack.enter_context(item)
            _run_sp1(client, tmp_path)

        assert writes[("loss_analysis", "loss-analysis.yaml")] == 1
        assert writes[("chain", "loss-analysis.yaml")] == 1
        assert writes[("control_structure", "loss-analysis.yaml")] == 0
        assert writes[("run", "loss-analysis.yaml")] == 0

    def test_a_failed_review_call_keeps_the_drafts(self, tmp_path):
        client = setup_sp1_mock_client()
        client.set_exception_for(CoordinationAnalysis, RuntimeError("call 3 down"))
        result = _run_sp1(client, tmp_path)

        assert result.control_structure is None
        assert (tmp_path / "loss-analysis-draft.yaml").exists()
        assert (tmp_path / "control-structure-draft.yaml").exists()
        _absent(tmp_path, "control-structure.yaml")


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

    @staticmethod
    def _unchanged(control_structure, *_args, **_kwargs):
        return control_structure, []

    def _run(
        self, run_dir: Path, writes: Counter | None = None, *, bind=None, feed=None
    ):
        base = "asago_scenario_generator.stpa.system_model.run."

        def revise(*, control_structure, **_kwargs):
            # The revision step binds its own output; run.py publishes it.
            structure, warnings = self._tagged("revised")(control_structure)
            return RevisionOutcome(structure, warnings, applied=True)

        patches = [
            patch(
                base + "check_evidence_bindings",
                side_effect=bind or self._tagged("bound"),
            ),
            patch(
                base + "attach_to_sole_reply_responsibility",
                side_effect=self._tagged("placed"),
            ),
            patch(
                base + "run_completeness_critic",
                return_value=CriticFindings(
                    gaps=[
                        CriticGap(
                            gap_type="missing_feedback",
                            description="Missing feedback",
                            related_attack_path="Attack path",
                            suggested_remedy="Add feedback",
                        )
                    ]
                ),
            ),
            patch(base + "revise_control_structure", side_effect=revise),
        ]
        if feed is not None:
            patches.append(
                patch(base + "add_operation_result_feedback", side_effect=feed)
            )
        if writes is not None:
            patches.extend(_spy_canonical_writes(writes))
        with ExitStack() as stack:
            for item in patches:
                stack.enter_context(item)
            return _run_sp1(setup_sp1_mock_client(), run_dir)

    @staticmethod
    def _description(run_dir: Path, name: str) -> str:
        return _load(run_dir, name)["responsibilities"][0]["description"]

    def test_each_changing_step_keeps_the_version_before_it(self, tmp_path):
        self._run(tmp_path)

        reviewed = self._description(tmp_path, "control-structure-reviewed.yaml")
        bound = self._description(tmp_path, "control-structure-evidence-bound.yaml")
        revised = self._description(tmp_path, "control-structure-revised.yaml")
        assert not reviewed.endswith(("bound", "revised", "placed"))
        assert bound == f"{reviewed} bound"
        assert revised == f"{bound} revised"
        # Placement is the last step: its version is the canonical file.
        _absent(tmp_path, "control-structure-placed.yaml")

    def test_operation_result_feedback_follows_revision_and_precedes_placement(
        self, tmp_path
    ):
        def feed(control_structure, *_args, **_kwargs):
            structure, _warnings = self._tagged("fed")(control_structure)
            return structure

        result = self._run(tmp_path, feed=feed)

        revised = self._description(tmp_path, "control-structure-revised.yaml")
        assert revised.endswith("bound revised")
        assert self._description(
            tmp_path, "control-structure-operation-feedback.yaml"
        ) == (f"{revised} fed")
        assert self._description(tmp_path, "control-structure.yaml") == (
            f"{revised} fed placed"
        )
        assert result.control_structure.responsibilities[0].description.endswith(
            "revised fed placed"
        )

    def test_canonical_holds_the_final_version(self, tmp_path):
        result = self._run(tmp_path)

        assert self._description(tmp_path, "control-structure.yaml") == (
            self._description(tmp_path, "control-structure-revised.yaml") + " placed"
        )
        assert result.control_structure.responsibilities[0].description.endswith(
            "revised placed"
        )

    def test_an_absent_version_equals_the_next_version_on_disk(self, tmp_path):
        self._run(tmp_path, bind=self._unchanged)

        # Evidence binding changed nothing, so the reviewed version equals
        # the evidence-bound one and only the latter is written.
        _absent(tmp_path, "control-structure-reviewed.yaml")
        bound = self._description(tmp_path, "control-structure-evidence-bound.yaml")
        assert self._description(tmp_path, "control-structure-revised.yaml") == (
            f"{bound} revised"
        )

    def test_canonical_control_structure_is_written_once_at_stage_end(self, tmp_path):
        writes: Counter = Counter()
        self._run(tmp_path, writes)

        assert writes[("chain", "control-structure.yaml")] == 1
        assert writes[("control_structure", "control-structure.yaml")] == 0
        assert writes[("run", "control-structure.yaml")] == 0

    def test_unchanged_steps_write_no_extra_version(self, tmp_path):
        _run_sp1(setup_sp1_mock_client(), tmp_path)

        assert (tmp_path / "control-structure.yaml").exists()
        _absent(
            tmp_path,
            "control-structure-reviewed.yaml",
            "control-structure-evidence-bound.yaml",
            "control-structure-revised.yaml",
            "control-structure-operation-feedback.yaml",
            "control-structure-placed.yaml",
        )
