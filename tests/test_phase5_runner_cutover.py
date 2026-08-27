"""Production source and lifecycle regressions for cmps.5 Phase 6."""

from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest

from asago_scenario_generator.pipeline.coverage_planning import (
    CoveragePlan,
    CoveragePlanEntry,
)
from asago_scenario_generator.pipeline.finalization import GeneratedStage
from asago_scenario_generator.pipeline.generate.stages import StageAttemptFailure
from asago_scenario_generator.pipeline.runner import run_pipeline
from asago_scenario_generator.pipeline.runner_finalization import (
    resume_completion_length_counts,
    strict_v3_coverage_plan,
)
from tests.test_phase4_persistence import (
    ENTRY_POINT_ID,
    FALLBACK_ID,
    PRIMARY_ID,
    _choice,
)


def _stage_record(stage: GeneratedStage, *codes: str) -> SimpleNamespace:
    return SimpleNamespace(
        stage=stage,
        violations=[SimpleNamespace(code=code) for code in codes],
    )


def test_resume_length_counts_authorize_only_a_latest_length_failure() -> None:
    records = [
        _stage_record(GeneratedStage.actor),
        _stage_record(
            GeneratedStage.actor,
            StageAttemptFailure.COMPLETION_LENGTH_CODE,
        ),
    ]

    counts = resume_completion_length_counts(records)

    assert counts == {
        GeneratedStage.actor: 1,
        GeneratedStage.narrative: 0,
        GeneratedStage.tree: 0,
        GeneratedStage.behavior: 0,
    }


def test_resume_length_counts_stay_zero_without_a_latest_length_failure() -> None:
    records = [
        _stage_record(
            GeneratedStage.actor,
            StageAttemptFailure.COMPLETION_LENGTH_CODE,
        ),
        _stage_record(GeneratedStage.actor),
    ]

    assert resume_completion_length_counts(records) == {
        GeneratedStage.actor: 0,
        GeneratedStage.narrative: 0,
        GeneratedStage.tree: 0,
        GeneratedStage.behavior: 0,
    }


def test_resume_length_counts_are_zero_for_an_empty_trace() -> None:
    assert resume_completion_length_counts([]) == {
        GeneratedStage.actor: 0,
        GeneratedStage.narrative: 0,
        GeneratedStage.tree: 0,
        GeneratedStage.behavior: 0,
    }


def test_strict_v3_plan_is_primary_first_and_all_choices_start_available() -> None:
    fallback = _choice(FALLBACK_ID, 7).model_dump(mode="json")
    primary = _choice(PRIMARY_ID, 9).model_dump(mode="json")
    legacy = CoveragePlan(
        schema_version="1",
        completeness="not_applicable",
        evidence_refs=[],
        targets=[
            CoveragePlanEntry(
                target_id="candidate-target:primary",
                entry_point_id=ENTRY_POINT_ID,
                entry_point_name="input",
                ordered_choices=[fallback, primary],
                primary_candidate_id=PRIMARY_ID,
                primary_state="selected",
                fallback_available=[fallback],
            )
        ],
    )

    plan = strict_v3_coverage_plan(legacy)
    target = plan.targets[0]

    assert plan.schema_version == "2"
    assert [item.candidate_id for item in target.ordered_choices] == [
        PRIMARY_ID,
        FALLBACK_ID,
    ]
    assert [item.rank for item in target.ordered_choices] == [0, 1]
    assert target.fallback_available == target.ordered_choices
    assert target.attempted_candidate_ids == []
    assert target.target_id == "candidate-target:primary"
    assert target.entry_point_id == ENTRY_POINT_ID


def test_strict_v3_plan_marks_structural_empty_target_exhausted() -> None:
    legacy = CoveragePlan(
        schema_version="1",
        completeness="not_applicable",
        evidence_refs=[],
        targets=[
            CoveragePlanEntry(
                entry_point_id=ENTRY_POINT_ID,
                entry_point_name="input",
                ordered_choices=[],
                primary_candidate_id=None,
                primary_state="uncovered",
                fallback_available=[],
            )
        ],
    )

    target = strict_v3_coverage_plan(legacy).targets[0]

    assert target.target_state.value == "exhausted"
    assert target.primary_candidate_id is None
    assert target.fallback_available == []


def test_v3_runner_contains_no_legacy_generation_or_mutation_lifecycle() -> None:
    source = inspect.getsource(run_pipeline)

    assert "run_target_finalization(" in source
    assert "return _complete_v3_run(" in source
    for forbidden in (
        "generate_scenario(",
        "write_scenario_outputs(",
        "replace_scenario_outputs(",
        "write_call_log(",
        "validate_phantom_capabilities(",
        "enforce_parsimony(",
        "_iter_leaves(",
        "_assert_entry_point_ownership(",
        "_run_early_access_gate(",
        "_compute_gap_attributions(",
        "_reconcile_artifacts(",
        "_reserve_attempt(",
        "_finalize_attempt(",
        "_build_run_inventory(",
        "compute_artifact_hash(",
    ):
        assert forbidden not in source

    # V3 records lifecycle in the finalization inventory. The runner must not
    # reconstruct or publish the retired v2 manifest mirrors.
    for legacy_write in (
        "failed_manifest.attempts =",
        "failed_manifest.funnel =",
        "failed_manifest.stage_records =",
        "failed_manifest.rule_verdicts =",
        "failed_manifest.artifacts =",
        "failed_manifest.phantom_validation =",
        "failed_manifest.structural_validation =",
        "failed_manifest.semantic_validation =",
        "failed_manifest.leaf_technique_provenance =",
        "failed_manifest.parsimony =",
        "failed_manifest.scenarios_generated =",
        "failed_manifest.scenarios_failed =",
        "derive_funnel_from_attempts(",
        "validate_attempt_equations(",
        '"phantom_validation":',
        '"structural_validation":',
        '"semantic_validation":',
        '"parsimony":',
    ):
        assert legacy_write not in source


class TestRunnerFinalizationHelpers:
    """Direct coverage for the decomposed v3 finalization helpers."""

    @staticmethod
    def _legacy_plan() -> CoveragePlan:
        fallback = _choice(FALLBACK_ID, 7).model_dump(mode="json")
        primary = _choice(PRIMARY_ID, 9).model_dump(mode="json")
        return CoveragePlan(
            schema_version="1",
            completeness="not_applicable",
            evidence_refs=[],
            targets=[
                CoveragePlanEntry(
                    target_id="candidate-target:primary",
                    entry_point_id=ENTRY_POINT_ID,
                    entry_point_name="input",
                    ordered_choices=[fallback, primary],
                    primary_candidate_id=PRIMARY_ID,
                    primary_state="selected",
                    fallback_available=[fallback],
                )
            ],
        )

    @staticmethod
    def _empty_inventory():
        return SimpleNamespace(
            admitted_inventory=[],
            quarantine_inventory=[],
        )

    def test_ranked_choices_places_primary_first(self):
        from asago_scenario_generator.pipeline.runner_finalization import (
            _ranked_choices,
        )

        choices = _ranked_choices(self._legacy_plan().targets[0])

        assert [item.candidate_id for item in choices] == [PRIMARY_ID, FALLBACK_ID]
        assert [item.rank for item in choices] == [0, 1]

    def test_ranked_choices_without_primary_keeps_queue_order(self):
        from asago_scenario_generator.pipeline.runner_finalization import (
            _ranked_choices,
        )

        plan = self._legacy_plan()
        plan.targets[0].primary_candidate_id = None

        choices = _ranked_choices(plan.targets[0])

        assert [item.candidate_id for item in choices] == [FALLBACK_ID, PRIMARY_ID]
        assert [item.rank for item in choices] == [0, 1]

    def test_strict_target_entry_selected_and_exhausted(self):
        from asago_scenario_generator.pipeline.coverage_planning import (
            CoveragePlanEntry,
        )
        from asago_scenario_generator.pipeline.runner_finalization import (
            _strict_target_entry,
        )

        entry = _strict_target_entry(self._legacy_plan().targets[0])
        assert entry.target_state.value == "selected"
        assert entry.primary_candidate_id == PRIMARY_ID
        assert entry.attempted_candidate_ids == []

        empty = CoveragePlanEntry(
            entry_point_id=ENTRY_POINT_ID,
            entry_point_name="input",
            ordered_choices=[],
            primary_candidate_id=None,
            primary_state="uncovered",
            fallback_available=[],
        )
        exhausted = _strict_target_entry(empty)
        assert exhausted.target_state.value == "exhausted"
        assert exhausted.primary_candidate_id is None
        assert exhausted.fallback_available == []

    def test_add_inventory_artifact_required_and_optional(self, tmp_path):
        from asago_scenario_generator.manifest import ArtifactRole
        from asago_scenario_generator.pipeline.runner_finalization import (
            _add_inventory_artifact,
        )

        entries = []
        _add_inventory_artifact(
            entries, tmp_path, ArtifactRole.USE_CASE, "use-case.txt", required=False
        )
        assert entries == []

        (tmp_path / "use-case.txt").write_text("uc")
        _add_inventory_artifact(
            entries, tmp_path, ArtifactRole.USE_CASE, "use-case.txt"
        )
        assert len(entries) == 1
        assert entries[0].role is ArtifactRole.USE_CASE

        with pytest.raises(FileNotFoundError, match="threat-surface.yaml"):
            _add_inventory_artifact(
                entries, tmp_path, ArtifactRole.THREAT_SURFACE, "threat-surface.yaml"
            )

    def test_support_artifacts_respects_include_flags(self, tmp_path):
        from asago_scenario_generator.manifest import ArtifactRole
        from asago_scenario_generator.pipeline.runner_finalization import (
            _support_artifacts,
        )

        for name in (
            "use-case.txt",
            "capability-profile.yaml",
            "threat-surface.yaml",
            "planning-checkpoint.json",
            "coverage-gaps.json",
            "coverage-plan.json",
            "finalization-inventory.json",
            "calls.jsonl",
            "candidate-filter-quarantine.json",
            "eval-scorecard.yaml",
            "report.html",
            "pipeline.log",
        ):
            (tmp_path / name).write_text("x")

        base = _support_artifacts(tmp_path, True, False, False, False)
        base_roles = {item.role for item in base}
        assert ArtifactRole.USE_CASE in base_roles
        assert ArtifactRole.COVERAGE_REPORT in base_roles
        assert ArtifactRole.EVAL_SCORECARD not in base_roles
        assert ArtifactRole.REPORT not in base_roles
        assert ArtifactRole.PIPELINE_LOG not in base_roles
        plan = next(item for item in base if item.role is ArtifactRole.COVERAGE_PLAN)
        assert plan.schema_version == "2"

        full = _support_artifacts(tmp_path, False, True, True, True)
        full_roles = {item.role for item in full}
        assert ArtifactRole.COVERAGE_REPORT not in full_roles
        assert ArtifactRole.EVAL_SCORECARD in full_roles
        assert ArtifactRole.REPORT in full_roles
        assert ArtifactRole.PIPELINE_LOG in full_roles

    def test_finalization_receipts_and_full_inventory(self, tmp_path):
        from asago_scenario_generator.manifest import ArtifactRole
        from asago_scenario_generator.pipeline.runner_finalization import (
            _finalization_receipts,
            build_v3_inventory,
        )

        admitted = SimpleNamespace(
            role=ArtifactRole.SCENARIO_YAML,
            path="scenarios/a.yaml",
            sha256="ab" * 32,
            scenario_id="sc-1",
            candidate_id="cand-1",
        )
        quarantined = SimpleNamespace(
            role=ArtifactRole.SCENARIO_FEATURE,
            path="scenarios/b.feature",
            sha256="cd" * 32,
            scenario_id="sc-2",
            candidate_id="cand-2",
        )
        inventory = SimpleNamespace(
            admitted_inventory=[admitted],
            quarantine_inventory=[quarantined],
        )

        only_admitted = _finalization_receipts(inventory, include_quarantine=False)
        assert [item.path for item in only_admitted] == ["scenarios/a.yaml"]
        both = _finalization_receipts(inventory, include_quarantine=True)
        assert [item.path for item in both] == [
            "scenarios/a.yaml",
            "scenarios/b.feature",
        ]
        assert both[0].candidate_id == "cand-1"
        assert both[1].role is ArtifactRole.SCENARIO_FEATURE

        for name in (
            "use-case.txt",
            "capability-profile.yaml",
            "threat-surface.yaml",
            "planning-checkpoint.json",
            "coverage-plan.json",
            "finalization-inventory.json",
            "calls.jsonl",
            "candidate-filter-quarantine.json",
        ):
            (tmp_path / name).write_text("x")
        built = build_v3_inventory(
            tmp_path, inventory, include_coverage=False, include_quarantine=True
        )
        paths = [item.path for item in built]
        assert "scenarios/a.yaml" in paths
        assert "scenarios/b.feature" in paths
        assert ArtifactRole.USE_CASE in {item.role for item in built}

        with pytest.raises(FileNotFoundError):
            build_v3_inventory(tmp_path, self._empty_inventory())

    def test_authorized_length_retry_helpers(self):
        from asago_scenario_generator.pipeline.runner_finalization import (
            _authorized_length_retry,
            _has_completion_length_violation,
        )

        record = _stage_record(
            GeneratedStage.actor,
            StageAttemptFailure.COMPLETION_LENGTH_CODE,
        )
        assert _has_completion_length_violation(record) is True
        assert _authorized_length_retry(GeneratedStage.actor, record) == 1
        assert _authorized_length_retry(GeneratedStage.narrative, record) == 0
        assert _authorized_length_retry(GeneratedStage.actor, None) == 0
        assert (
            _authorized_length_retry(
                GeneratedStage.actor, _stage_record(GeneratedStage.actor, "other")
            )
            == 0
        )
