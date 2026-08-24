"""Branch coverage for the helpers extracted by the validation-wall split.

The validation-wall split (crap-validation-walls) decomposed ten CRAP-
dominated functions into thin facades plus named helpers.  Every helper
was kept at CC <= 5, but several were not yet exercised on every branch,
which left their CRAP score above the slice-6 gate (CRAP <= 6 on the
extracted helpers).  These tests pin the helper contracts at branch
level without changing any behavior.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from asago_scenario_generator.eval.versioned_metrics import _load_v3_scorecard_models
from asago_scenario_generator.llm.client import LLMResult
from asago_scenario_generator.manifest import (
    MANIFEST_V3,
    ArtifactRole,
    ManifestInventoryResolver,
    ManifestIntegrityError,
    RunManifest,
    RunStatus,
    _check_completed_scenario_pairing,
    _check_completed_scorecard_counts,
    _v3_scorecard_counts,
    build_artifact_entry,
)
from asago_scenario_generator.models.attack_pattern import (
    EntryPointResourceReference,
    IntegrationResourceReference,
)
from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    ImpactAction,
    IntegrationInteractionAction,
    ToolInvocationAction,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
)
from asago_scenario_generator.models.projection_envelope import (
    ProjectionTraceabilityStage,
    ProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.models.scenario import CallMetadata, CallName
from asago_scenario_generator.pipeline import runner_run as runner_run_module
from asago_scenario_generator.pipeline.runner_run import (
    _expansion_record,
    _immutable_roles_by_role,
    _log_cap_summary,
    _projection_event_for_fseed,
    _record_filter_rejections,
    _record_projection_events,
    _support_published,
    _support_validation_result,
)
from asago_scenario_generator.pipeline.finalization import GeneratedStage
from asago_scenario_generator.pipeline.coverage_planning import GenerationMode
from asago_scenario_generator.pipeline.persistence import (
    ArtifactReceipt,
    CandidateAttemptRecord,
    _check_gate_violations_match_terminal,
    _check_v3_completed_status,
    _check_v3_fallback_attempts,
    canonical_sha256,
)
from asago_scenario_generator.pipeline.persistence_validation import (
    _causal_stage_artifacts,
    _has_accepted_tree_repair,
    _require_input_bound_tree,
)
from asago_scenario_generator.pipeline.projection import (
    ProjectionBudget,
    _AuthoritativeCandidateAllocator,
    _source_influence_target_id,
)
from asago_scenario_generator.pipeline.projection_semantics import (
    _check_leaf_integration_binding,
    _check_leaf_sourced_tool_binding,
)
from asago_scenario_generator.pipeline.runner import (
    PipelineResult,
    QualificationFactsV1,
    _apply_zone_filter,
    _authoritative_products_ready,
    _ordinary_completion_succeeded,
    _readable_evidence_file,
    _rule_rejection_reasons,
    _scorecard_qualification_passed,
    _stage2_threat_surface,
    _strip_entry_point_zone_tags,
    _strip_inter_agent_kc_codes,
    _strip_memory_kc_codes,
    _strip_zone_kc_codes,
    _validate_requested_zones,
    _validate_resume_manifest_identity,
    _validate_run_pipeline_options,
)
from asago_scenario_generator.pipeline.runner_resume import (
    _resolve_resume_directory,
    _resolved_resume_base_url,
    _resolved_resume_model,
    _validate_resume_endpoint_override,
    _validate_resume_model_override,
)
from asago_scenario_generator.pipeline.runner_finalization import (
    _adopt_successful_stage_result,
    _drop_downstream_evidence,
    _with_resumed_candidate_first,
)
from asago_scenario_generator.pipeline.validation import (
    _expected_scope_classifications,
    _is_consequence_leaf,
    _semantic_gherkin_text,
    check_seed_mechanism_fidelity,
)
from tests.helpers.projection_factory import get_test_profile, make_behavior_spec
from tests.test_versioned_scorecard import _Resolver

RUN_ID = "20260101T000000_abcdef0123456789abcdef0123456789"
_EP_ID = "ep:v1:" + "a" * 32
_INT_ID = "int:v1:" + "1" * 32
_INT_ID_OTHER = "int:v1:" + "2" * 32


def _zone_profile(
    kc_subcodes: list[str],
    entry_points: list[EntryPoint],
) -> CapabilityProfile:
    """Build a capability profile whose zones derive from the KC codes."""
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=entry_points,
        confidence=ConfidenceLevel.medium,
        kc_subcodes=kc_subcodes,
    )


# ---------------------------------------------------------------------------
# runner.py: zone option helpers
# ---------------------------------------------------------------------------


class TestValidateRequestedZones:
    def test_parses_and_trims_valid_zones(self) -> None:
        assert _validate_requested_zones(" input , memory ") == ["input", "memory"]

    def test_rejects_unknown_zone_with_valid_ones_present(self) -> None:
        with pytest.raises(ValueError, match="Unknown zone"):
            _validate_requested_zones("input,bogus")

    def test_rejects_empty_input(self) -> None:
        with pytest.raises(ValueError, match="Unknown zone"):
            _validate_requested_zones("")


class TestStripZoneKcCodes:
    def test_memory_filtered_keeps_memory_codes(self) -> None:
        codes = ["KC1.1", "KC4.3", "KCX-PMEM"]
        assert _strip_memory_kc_codes(codes, ["memory"]) == codes

    def test_memory_excluded_strips_memory_codes(self) -> None:
        stripped = _strip_memory_kc_codes(
            ["KC1.1", "KC4.3", "KC4.4", "KC4.5", "KC4.6", "KCX-PMEM", "KC2.3"],
            ["input", "reasoning"],
        )
        assert stripped == ["KC1.1", "KC2.3"]

    def test_inter_agent_filtered_keeps_agent_codes(self) -> None:
        codes = ["KC1.1", "KC2.3", "KCX-MAGENT"]
        assert _strip_inter_agent_kc_codes(codes, ["inter_agent"]) == codes

    def test_inter_agent_excluded_strips_agent_codes(self) -> None:
        assert _strip_inter_agent_kc_codes(
            ["KC1.1", "KC2.3", "KCX-MAGENT"], ["input"]
        ) == ["KC1.1"]

    def test_composed_strip_excludes_both_zones(self) -> None:
        codes = ["KC1.1", "KC4.3", "KC2.3", "KCX-PMEM", "KCX-MAGENT"]
        assert _strip_zone_kc_codes(codes, []) == ["KC1.1"]

    def test_composed_strip_keeps_codes_when_both_filtered(self) -> None:
        codes = ["KC1.1", "KC4.3", "KC2.3"]
        assert _strip_zone_kc_codes(codes, ["memory", "inter_agent"]) == codes


class TestStripEntryPointZoneTags:
    def test_strips_tag_for_excluded_zone(self) -> None:
        profile = _zone_profile(
            ["KC1.1", "KC4.3"],
            [EntryPoint(name="Chat (memory)", direction="input")],
        )
        updates = _strip_entry_point_zone_tags(profile, ["input", "reasoning"])
        assert updates["entry_points"][0].name == "Chat"

    def test_keeps_tag_for_included_zone(self) -> None:
        profile = _zone_profile(
            ["KC1.1", "KC4.3"],
            [EntryPoint(name="Chat (memory)", direction="input")],
        )
        assert _strip_entry_point_zone_tags(profile, ["input", "memory"]) == {}

    def test_untagged_entry_points_are_unchanged(self) -> None:
        profile = _zone_profile(
            ["KC1.1"],
            [EntryPoint(name="Chat", direction="input")],
        )
        assert _strip_entry_point_zone_tags(profile, ["input", "reasoning"]) == {}

    def test_stripped_duplicates_are_deduplicated(self) -> None:
        profile = _zone_profile(
            ["KC1.1", "KC4.3"],
            [
                EntryPoint(name="Chat (memory)", direction="input"),
                EntryPoint(name="Chat", direction="input"),
            ],
        )
        updates = _strip_entry_point_zone_tags(profile, ["input", "reasoning"])
        assert len(updates["entry_points"]) == 1


class TestApplyZoneFilter:
    def test_none_zones_is_noop(self) -> None:
        profile = get_test_profile()
        assert _apply_zone_filter(profile, None) is profile

    def test_invalid_zones_raise(self) -> None:
        with pytest.raises(ValueError, match="Unknown zone"):
            _apply_zone_filter(get_test_profile(), "bogus")

    def test_filters_zones_and_strips_dependent_kc_codes(self) -> None:
        profile = _zone_profile(
            ["KC1.1", "KC4.3", "KC2.3", "KCX-PMEM"],
            [EntryPoint(name="Chat (memory)", direction="input")],
        )
        filtered = _apply_zone_filter(profile, "inter_agent")
        assert filtered.zones_active == ["inter_agent"]
        assert "KC4.3" not in filtered.kc_subcodes
        assert "KCX-PMEM" not in filtered.kc_subcodes
        assert "KC2.3" in filtered.kc_subcodes
        assert filtered.entry_points[0].name == "Chat"

    def test_keeps_codes_and_tags_for_requested_zones(self) -> None:
        profile = _zone_profile(
            ["KC1.1", "KC4.3"],
            [EntryPoint(name="Chat (memory)", direction="input")],
        )
        filtered = _apply_zone_filter(profile, "memory,input")
        assert filtered.zones_active == ["memory", "input"]
        assert filtered.kc_subcodes == ["KC1.1", "KC4.3"]
        assert filtered.entry_points[0].name == "Chat (memory)"


# ---------------------------------------------------------------------------
# runner.py: rule rejection reasons and stage-2 threat surface
# ---------------------------------------------------------------------------


class TestRuleRejectionReasons:
    def test_default_reason_without_matching_verdicts(self) -> None:
        candidate = SimpleNamespace(candidate_id="c1")
        assert _rule_rejection_reasons(candidate, []) == (
            "Rejected by deterministic rule filter"
        )

    def test_ignores_verdicts_for_other_candidates(self) -> None:
        verdict = SimpleNamespace(
            candidate_id="other", rationale="x", removal_decisions=[]
        )
        assert (
            _rule_rejection_reasons(SimpleNamespace(candidate_id="c1"), [verdict])
            == "Rejected by deterministic rule filter"
        )

    def test_joins_removal_decision_summaries(self) -> None:
        verdict = SimpleNamespace(
            candidate_id="c1",
            rationale="fallback",
            removal_decisions=[
                SimpleNamespace(rule="r1", reason="x"),
                SimpleNamespace(rule="r2", reason="y"),
            ],
        )
        assert (
            _rule_rejection_reasons(SimpleNamespace(candidate_id="c1"), [verdict])
            == "r1: x; r2: y"
        )

    def test_falls_back_to_rationale_without_removals(self) -> None:
        verdict = SimpleNamespace(
            candidate_id="c1", rationale="fallback", removal_decisions=[]
        )
        assert (
            _rule_rejection_reasons(SimpleNamespace(candidate_id="c1"), [verdict])
            == "fallback"
        )


class TestStage2ThreatSurface:
    def _patch_stage2(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        has_warnings: bool,
        entries: list[Any],
    ) -> None:
        # ``_stage2_threat_surface`` resolves its dependencies through the
        # sibling orchestration module where it now lives.
        monkeypatch.setattr(
            runner_run_module,
            "load_risk_extraction",
            lambda path: [{"risk_id": "r1"}],
        )
        monkeypatch.setattr(
            runner_run_module,
            "validate_risk_card_coherence",
            lambda use_case, cards: SimpleNamespace(
                has_warnings=has_warnings,
                flagged_cards=[SimpleNamespace(risk_id="r1", risk_name="R1")],
            ),
        )
        monkeypatch.setattr(
            runner_run_module,
            "determine_threat_surface",
            lambda *args: SimpleNamespace(
                entries=entries, governance_only=["governed"]
            ),
        )

    def test_records_coherence_warnings_and_unions_in_scope_threats(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_stage2(
            monkeypatch,
            has_warnings=True,
            entries=[
                SimpleNamespace(agentic_threat_ids={"t1", "t2"}),
                SimpleNamespace(agentic_threat_ids={"t2", "t3"}),
            ],
        )
        notes: list[str] = []
        surface, actionable, governance, in_scope = _stage2_threat_surface(
            "use case",
            Path("risk"),
            Path("sssom"),
            Path("ct"),
            None,
            object(),
            notes,  # type: ignore[arg-type]
        )
        assert notes == [
            "Risk card r1 (R1) may describe a different system "
            "(0 keyword overlap with use case)."
        ]
        assert actionable == 2
        assert governance == 1
        assert in_scope == {"t1", "t2", "t3"}
        assert surface is not None

    def test_without_warnings_or_entries(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_stage2(monkeypatch, has_warnings=False, entries=[])
        notes: list[str] = []
        _, actionable, governance, in_scope = _stage2_threat_surface(
            "use case",
            Path("risk"),
            Path("sssom"),
            Path("ct"),
            None,
            object(),
            notes,  # type: ignore[arg-type]
        )
        assert notes == []
        assert actionable == 0
        assert governance == 1
        assert in_scope == set()


# ---------------------------------------------------------------------------
# validation.py: scenario classification helpers
# ---------------------------------------------------------------------------


class TestSemanticGherkinText:
    def test_returns_behavior_spec_gherkin_text(self) -> None:
        behavior_spec = make_behavior_spec()
        scenario = SimpleNamespace(behavior_spec=behavior_spec)
        assert _semantic_gherkin_text(scenario) == behavior_spec.gherkin_text
        assert _semantic_gherkin_text(scenario)

    def test_returns_raw_string_behavior_spec(self) -> None:
        scenario = SimpleNamespace(behavior_spec="Feature: raw")
        assert _semantic_gherkin_text(scenario) == "Feature: raw"

    def test_no_behavior_spec_returns_empty(self) -> None:
        assert _semantic_gherkin_text(SimpleNamespace(behavior_spec=None)) == ""

    def test_unrecognized_behavior_spec_returns_empty(self) -> None:
        assert (
            _semantic_gherkin_text(SimpleNamespace(behavior_spec={"not": "a spec"}))
            == ""
        )


class TestExpectedScopeClassifications:
    def test_prefers_pinned_technique_ids(self) -> None:
        scenario = SimpleNamespace(
            candidate_filter={"pinned_technique_ids": ["t1", "t2", "t1"]},
            scenario_seed_metadata=None,
        )
        assert _expected_scope_classifications(scenario) == ["t1", "t2"]

    def test_falls_back_to_seed_metadata(self) -> None:
        scenario = SimpleNamespace(
            candidate_filter={},
            scenario_seed_metadata={"atlas_technique_ids": ["t3", "t4"]},
        )
        assert _expected_scope_classifications(scenario) == ["t3", "t4"]

    def test_empty_seed_metadata_yields_empty_list(self) -> None:
        scenario = SimpleNamespace(
            candidate_filter=None,
            scenario_seed_metadata={"atlas_technique_ids": []},
        )
        assert _expected_scope_classifications(scenario) == []

    def test_no_evidence_returns_none(self) -> None:
        scenario = SimpleNamespace(candidate_filter={}, scenario_seed_metadata=None)
        assert _expected_scope_classifications(scenario) is None


# ---------------------------------------------------------------------------
# manifest.py: completed-inventory helpers
# ---------------------------------------------------------------------------


def _write_artifact(
    tmp_path: Path,
    role: ArtifactRole,
    rel_path: str,
    scenario_id: str | None = None,
) -> Any:
    """Write a small artifact file and build its inventory entry."""
    full = tmp_path / rel_path
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text("content\n", encoding="utf-8")
    return build_artifact_entry(
        role=role,
        run_dir=tmp_path,
        rel_path=rel_path,
        scenario_id=scenario_id,
        candidate_id=f"cand:v2:{scenario_id}" if scenario_id else None,
    )


def _manifest(
    tmp_path: Path,
    *,
    yaml_ids: tuple[str, ...] = (),
    feature_ids: tuple[str, ...] = (),
    status: RunStatus = RunStatus.STARTED,
    extra_entries: tuple[Any, ...] = (),
) -> RunManifest:
    inventory: list[Any] = list(extra_entries)
    for sid in yaml_ids:
        inventory.append(
            _write_artifact(
                tmp_path, ArtifactRole.SCENARIO_YAML, f"scenarios/{sid}.yaml", sid
            )
        )
    for sid in feature_ids:
        inventory.append(
            _write_artifact(
                tmp_path, ArtifactRole.SCENARIO_FEATURE, f"scenarios/{sid}.feature", sid
            )
        )
    return RunManifest(
        manifest_version=MANIFEST_V3,
        status=status,
        run_id=RUN_ID,
        timestamp_start="2026-01-01T00:00:00+00:00",
        inventory=inventory,
    )


class TestCheckCompletedScenarioPairing:
    def test_matching_yaml_and_feature_ids_pass(self, tmp_path: Path) -> None:
        manifest = _manifest(tmp_path, yaml_ids=("a",), feature_ids=("a",))
        _check_completed_scenario_pairing(manifest)

    def test_yaml_without_feature_raises(self, tmp_path: Path) -> None:
        manifest = _manifest(tmp_path, yaml_ids=("a", "b"), feature_ids=("a",))
        with pytest.raises(ManifestIntegrityError, match="YAML without feature"):
            _check_completed_scenario_pairing(manifest)

    def test_feature_without_yaml_raises(self, tmp_path: Path) -> None:
        manifest = _manifest(tmp_path, yaml_ids=("a",), feature_ids=("a", "b"))
        with pytest.raises(ManifestIntegrityError, match="feature without YAML"):
            _check_completed_scenario_pairing(manifest)

    def test_both_sides_reported_together(self, tmp_path: Path) -> None:
        manifest = _manifest(tmp_path, yaml_ids=("a",), feature_ids=("b",))
        with pytest.raises(
            ManifestIntegrityError,
            match="YAML without feature: .*a.*feature without YAML: .*b",
        ):
            _check_completed_scenario_pairing(manifest)

    def test_duplicate_scenario_id_in_role_raises(self, tmp_path: Path) -> None:
        manifest = _manifest(tmp_path, yaml_ids=("a",))
        manifest.inventory.append(
            _write_artifact(
                tmp_path, ArtifactRole.SCENARIO_YAML, "scenarios/a-dup.yaml", "a"
            )
        )
        with pytest.raises(ManifestIntegrityError, match="Duplicate scenario_id"):
            _check_completed_scenario_pairing(manifest)

    def test_unrelated_roles_are_ignored(self, tmp_path: Path) -> None:
        manifest = _manifest(
            tmp_path,
            yaml_ids=("a",),
            feature_ids=("a",),
            extra_entries=(
                _write_artifact(tmp_path, ArtifactRole.PIPELINE_LOG, "pipeline.log"),
            ),
        )
        _check_completed_scenario_pairing(manifest)


class TestV3ScorecardCounts:
    @staticmethod
    def _scorecard_raw() -> dict[str, Any]:
        from asago_scenario_generator.eval.versioned_metrics import (
            evaluate_v3_scorecard,
        )

        return evaluate_v3_scorecard(_Resolver()).model_dump(mode="json")  # type: ignore[arg-type]

    @staticmethod
    def _manifest_stub(status: RunStatus) -> SimpleNamespace:
        return SimpleNamespace(run_id=RUN_ID, status=status)

    def test_accepts_valid_matching_scorecard(self) -> None:
        counts = _v3_scorecard_counts(
            self._scorecard_raw(), self._manifest_stub(RunStatus.STARTED)
        )
        assert counts == (0, 0)

    def test_rejects_non_dict_schema_under_strict_v1(self) -> None:
        with pytest.raises(ManifestIntegrityError, match="violates strict v1 schema"):
            _v3_scorecard_counts(
                {"not": "a scorecard"}, self._manifest_stub(RunStatus.STARTED)
            )

    def test_rejects_run_id_mismatch(self) -> None:
        manifest = SimpleNamespace(run_id="other-run", status=RunStatus.STARTED)
        with pytest.raises(ManifestIntegrityError, match="does not match"):
            _v3_scorecard_counts(self._scorecard_raw(), manifest)

    def test_completed_manifest_requires_passing_qualification(self) -> None:
        with pytest.raises(
            ManifestIntegrityError, match="requires passing scorecard qualification"
        ):
            _v3_scorecard_counts(
                self._scorecard_raw(), self._manifest_stub(RunStatus.COMPLETED)
            )


class TestCheckCompletedScorecardCounts:
    def test_count_mismatch_raises(self, tmp_path: Path) -> None:
        manifest = _manifest(tmp_path, yaml_ids=("a",))
        with pytest.raises(
            ManifestIntegrityError, match="Scenario YAML/feature count mismatch"
        ):
            _check_completed_scorecard_counts(manifest, None)

    def test_no_scorecard_entry_is_noop(self, tmp_path: Path) -> None:
        manifest = _manifest(tmp_path, yaml_ids=("a",), feature_ids=("a",))
        _check_completed_scorecard_counts(manifest, None)

    def test_verifiable_scorecard_entry_validates(self, tmp_path: Path) -> None:
        from asago_scenario_generator.eval.versioned_metrics import (
            evaluate_v3_scorecard,
        )

        scorecard_entry = _write_artifact(
            tmp_path, ArtifactRole.EVAL_SCORECARD, "eval-scorecard.yaml"
        )
        manifest = _manifest(
            tmp_path, status=RunStatus.STARTED, extra_entries=(scorecard_entry,)
        )
        resolver = SimpleNamespace(
            read_yaml=lambda entry: evaluate_v3_scorecard(_Resolver()).model_dump(  # type: ignore[arg-type,no-any-return]
                mode="json"
            )
        )
        _check_completed_scorecard_counts(manifest, resolver)


class TestLoadV3ScorecardModels:
    def test_requires_authoritative_manifest_v3(self) -> None:
        resolver = SimpleNamespace(manifest=SimpleNamespace(manifest_version="2"))
        with pytest.raises(ValueError, match="authoritative manifest v3"):
            _load_v3_scorecard_models(resolver)

    def test_requires_plan_finalization_and_profile_entries(self) -> None:
        resolver = SimpleNamespace(
            manifest=SimpleNamespace(manifest_version="3"),
            entry_by_role=lambda role: None,
        )
        with pytest.raises(
            ValueError, match="requires plan, finalization, and profile"
        ):
            _load_v3_scorecard_models(resolver)


# ---------------------------------------------------------------------------
# runner_finalization.py: resume replay helpers
# ---------------------------------------------------------------------------


class TestWithResumedCandidateFirst:
    def test_moves_resumed_candidate_to_head(self) -> None:
        available_refs = [
            {"candidate_id": "primary", "rank": 0},
            {"candidate_id": "resumed", "rank": 1},
        ]
        ref_by_id = {
            "resumed": SimpleNamespace(
                model_dump=lambda **kw: {"candidate_id": "resumed", "rank": 1}
            )
        }
        target = SimpleNamespace(primary_candidate_id="primary")
        ordered = _with_resumed_candidate_first(
            available_refs, target, "resumed", ref_by_id
        )
        assert [ref["candidate_id"] for ref in ordered] == ["resumed", "primary"]

    def test_noop_when_resumed_is_primary(self) -> None:
        available_refs = [{"candidate_id": "primary", "rank": 0}]
        target = SimpleNamespace(primary_candidate_id="primary")
        assert (
            _with_resumed_candidate_first(available_refs, target, "primary", {})
            is available_refs
        )

    def test_noop_without_resume_candidate(self) -> None:
        available_refs = [{"candidate_id": "primary", "rank": 0}]
        target = SimpleNamespace(primary_candidate_id="primary")
        assert (
            _with_resumed_candidate_first(available_refs, target, None, {})
            is available_refs
        )


class TestDropDownstreamEvidence:
    def test_drops_resume_stage_and_downstream(self) -> None:
        evidence = {
            GeneratedStage.actor: "actor",
            GeneratedStage.narrative: "narrative",
            GeneratedStage.tree: "tree",
            GeneratedStage.behavior: "behavior",
        }
        _drop_downstream_evidence(GeneratedStage.tree, "cand", {"cand": evidence})
        assert evidence == {
            GeneratedStage.actor: "actor",
            GeneratedStage.narrative: "narrative",
        }

    def test_drops_everything_from_actor(self) -> None:
        evidence = {GeneratedStage.actor: "actor", GeneratedStage.behavior: "behavior"}
        _drop_downstream_evidence(GeneratedStage.actor, "cand", {"cand": evidence})
        assert evidence == {}

    def test_missing_candidate_is_noop(self) -> None:
        _drop_downstream_evidence(GeneratedStage.behavior, "missing", {})


class TestAdoptSuccessfulStageResult:
    @staticmethod
    def _record(**overrides: Any) -> SimpleNamespace:
        fields: dict[str, Any] = {
            "stage": GeneratedStage.behavior,
            "result": None,
            "violations": [],
            "call": None,
        }
        fields.update(overrides)
        return SimpleNamespace(**fields)

    def test_none_result_is_noop(self) -> None:
        latest: dict[GeneratedStage, Any] = {}
        evidence_by_id: dict[str, dict[GeneratedStage, Any]] = {}
        _adopt_successful_stage_result(
            self._record(), "cand", evidence_by_id, latest, {}
        )
        assert latest == {}
        assert evidence_by_id == {}

    def test_violated_record_is_noop(self) -> None:
        latest: dict[GeneratedStage, Any] = {}
        evidence_by_id: dict[str, dict[GeneratedStage, Any]] = {}
        record = self._record(
            result=make_behavior_spec(), violations=[SimpleNamespace()]
        )
        _adopt_successful_stage_result(record, "cand", evidence_by_id, latest, {})
        assert latest == {}

    def test_missing_call_is_noop(self) -> None:
        latest: dict[GeneratedStage, Any] = {}
        evidence_by_id: dict[str, dict[GeneratedStage, Any]] = {}
        record = self._record(result=make_behavior_spec())
        _adopt_successful_stage_result(record, "cand", evidence_by_id, latest, {})
        assert latest == {}

    def test_clean_record_adopts_artifact_and_evidence(self) -> None:
        behavior_spec = make_behavior_spec()
        call = SimpleNamespace(
            call_name=CallName.behavior_spec,
            semantic_evidence=None,
            result=LLMResult(
                content={"stage": "behavior"},
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt="system",
                user_prompt="user",
            ),
            metadata=CallMetadata(
                call=CallName.behavior_spec,
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
            ),
        )
        record = self._record(result=behavior_spec, call=call)
        latest: dict[GeneratedStage, Any] = {}
        evidence_by_id: dict[str, dict[GeneratedStage, Any]] = {}
        _adopt_successful_stage_result(
            record,
            "cand",
            evidence_by_id,
            latest,
            {GeneratedStage.behavior: type(behavior_spec)},
        )
        assert latest[GeneratedStage.behavior] == behavior_spec
        evidence = evidence_by_id["cand"][GeneratedStage.behavior]
        assert evidence.call_name is CallName.behavior_spec
        assert evidence.semantic_evidence is None


# ---------------------------------------------------------------------------
# projection.py: authoritative candidate allocation helpers
# ---------------------------------------------------------------------------


class TestReserveTargetIteration:
    @staticmethod
    def _allocator() -> _AuthoritativeCandidateAllocator:
        return _AuthoritativeCandidateAllocator(ProjectionBudget(), [], [], None)

    def test_stops_when_work_exhausted(self) -> None:
        allocator = self._allocator()
        allocator.work_exhausted = True
        allocator.derive_one = lambda group_index, target_iter: (None, False, False)
        assert allocator._reserve_target_iteration("t", 0, iter(())) == (True, False)

    def test_keeps_unique_candidate_pending_and_found(self) -> None:
        allocator = self._allocator()
        candidate = object()
        allocator.derive_one = lambda group_index, target_iter: (candidate, True, False)
        assert allocator._reserve_target_iteration("t", 3, None) == (True, True)
        assert allocator.pending == [(3, candidate)]
        assert allocator.target_to_first_candidate["t"] == (3, candidate)

    def test_records_non_unique_candidate_without_pending(self) -> None:
        allocator = self._allocator()
        candidate = object()
        allocator.derive_one = lambda group_index, target_iter: (
            candidate,
            False,
            False,
        )
        assert allocator._reserve_target_iteration("t", 1, None) == (True, True)
        assert allocator.pending == []
        assert allocator.target_to_first_candidate["t"] == (1, candidate)

    def test_stops_when_iterator_exhausted(self) -> None:
        allocator = self._allocator()
        allocator.derive_one = lambda group_index, target_iter: (None, False, True)
        assert allocator._reserve_target_iteration("t", 0, None) == (True, False)
        assert "t" not in allocator.target_to_first_candidate

    def test_continues_without_candidate_or_exhaustion(self) -> None:
        allocator = self._allocator()
        allocator.derive_one = lambda group_index, target_iter: (None, False, False)
        assert allocator._reserve_target_iteration("t", 0, None) == (False, False)


class TestSourceInfluenceTargetId:
    @staticmethod
    def _link(target_ingress_slot_id: str = "slot") -> SimpleNamespace:
        return SimpleNamespace(target_ingress_slot_id=target_ingress_slot_id)

    @staticmethod
    def _chain(*slots: Any) -> SimpleNamespace:
        return SimpleNamespace(resource_slots=list(slots))

    def test_uses_first_ingress_option(self) -> None:
        ref = EntryPointResourceReference(kind="entry_point", entry_point_id=_EP_ID)
        chain = self._chain()
        assert _source_influence_target_id(self._link(), chain, ((ref,),), 0) == _EP_ID

    def test_uses_explicit_allowed_ids_without_options(self) -> None:
        allowed = ("int:v1:" + "b" * 32,)
        chain = self._chain(
            SimpleNamespace(slot_id="slot", allowed_resource_ids=allowed)
        )
        assert (
            _source_influence_target_id(self._link("slot"), chain, (), 0) == allowed[0]
        )

    def test_empty_option_set_falls_back_to_allowed_ids(self) -> None:
        allowed = ("int:v1:" + "b" * 32,)
        chain = self._chain(
            SimpleNamespace(slot_id="slot", allowed_resource_ids=allowed)
        )
        assert (
            _source_influence_target_id(self._link("slot"), chain, ((),), 0)
            == allowed[0]
        )

    def test_returns_none_without_allowed_ids(self) -> None:
        chain = self._chain(SimpleNamespace(slot_id="slot", allowed_resource_ids=()))
        assert _source_influence_target_id(self._link("slot"), chain, (), 0) is None

    def test_returns_none_when_no_slot_matches(self) -> None:
        chain = self._chain(
            SimpleNamespace(slot_id="other", allowed_resource_ids=("x",))
        )
        assert _source_influence_target_id(self._link("slot"), chain, (), 0) is None


# ---------------------------------------------------------------------------
# projection_semantics.py: leaf binding checks
# ---------------------------------------------------------------------------


class TestLeafBindingChecks:
    def _check_bindings(self, *, action: Any, ref: Any, role: str) -> list[Any]:
        leaf = SimpleNamespace(id="leaf-1")
        step = SimpleNamespace(step_id="step-1")
        link = SimpleNamespace(role=role, slot_id="slot-1")
        violations: list[Any] = []
        _check_leaf_integration_binding(leaf, action, step, link, ref, violations)
        _check_leaf_sourced_tool_binding(leaf, action, step, link, ref, violations)
        return violations

    def test_non_binding_actions_are_ignored(self) -> None:
        violations = self._check_bindings(
            action=AiSystemAction(), ref=None, role="integration"
        )
        assert violations == []

    def test_integration_binding_flags_mismatch_for_integration_role(self) -> None:
        action = IntegrationInteractionAction(integration_id=_INT_ID)
        ref = IntegrationResourceReference(
            kind="integration", integration_id=_INT_ID_OTHER
        )
        for role in ("integration", "downstream"):
            violations = self._check_bindings(action=action, ref=ref, role=role)
            assert len(violations) == 1
            violation = violations[0]
            assert (
                violation.code
                is ProjectionTraceabilityViolationCode.incorrect_resource_binding
            )
            assert violation.stage is ProjectionTraceabilityStage.attack_tree
            assert "leaf-1" in violation.detail
            assert _INT_ID in violation.detail

    def test_integration_binding_accepts_matching_integration(self) -> None:
        action = IntegrationInteractionAction(integration_id=_INT_ID)
        ref = IntegrationResourceReference(kind="integration", integration_id=_INT_ID)
        assert self._check_bindings(action=action, ref=ref, role="integration") == []

    def test_integration_binding_ignores_non_integration_role(self) -> None:
        action = IntegrationInteractionAction(integration_id=_INT_ID)
        ref = IntegrationResourceReference(
            kind="integration", integration_id=_INT_ID_OTHER
        )
        assert self._check_bindings(action=action, ref=ref, role="resource") == []

    def test_tool_binding_flags_mismatched_integration(self) -> None:
        action = ToolInvocationAction(
            tool_id="tool:v1:" + "c" * 32, integration_id=_INT_ID
        )
        ref = IntegrationResourceReference(
            kind="integration", integration_id=_INT_ID_OTHER
        )
        violations = self._check_bindings(action=action, ref=ref, role="integration")
        assert len(violations) == 1
        assert (
            violations[0].code
            is ProjectionTraceabilityViolationCode.incorrect_resource_binding
        )

    def test_tool_binding_accepts_matching_integration(self) -> None:
        action = ToolInvocationAction(
            tool_id="tool:v1:" + "c" * 32, integration_id=_INT_ID
        )
        ref = IntegrationResourceReference(kind="integration", integration_id=_INT_ID)
        assert self._check_bindings(action=action, ref=ref, role="integration") == []

    def test_tool_binding_without_integration_id_is_ignored(self) -> None:
        action = ToolInvocationAction(tool_id="tool:v1:" + "c" * 32)
        ref = IntegrationResourceReference(
            kind="integration", integration_id=_INT_ID_OTHER
        )
        assert self._check_bindings(action=action, ref=ref, role="integration") == []

    def test_tool_binding_ignores_non_integration_role(self) -> None:
        action = ToolInvocationAction(
            tool_id="tool:v1:" + "c" * 32, integration_id=_INT_ID
        )
        ref = IntegrationResourceReference(
            kind="integration", integration_id=_INT_ID_OTHER
        )
        assert self._check_bindings(action=action, ref=ref, role="resource") == []


# ---------------------------------------------------------------------------
# persistence.py: v3 inventory helpers
# ---------------------------------------------------------------------------


class TestCheckV3FallbackAttempts:
    @staticmethod
    def _attempt(
        candidate_id: str, *, rank: int, is_primary: bool = False, sequence: int = 0
    ) -> CandidateAttemptRecord:
        return CandidateAttemptRecord(
            event_id="0" * 64,
            payload_sha256="0" * 64,
            sequence=sequence,
            attempt_id=f"attempt-{candidate_id}",
            candidate_id=candidate_id,
            target_entry_point_id="ep:v1:test",
            queue_rank=rank,
            is_primary=is_primary,
            stage_attempt_ids=[],
        )

    def test_empty_attempts_pass(self) -> None:
        _check_v3_fallback_attempts([], set())

    def test_valid_fallback_order_passes(self) -> None:
        attempts = [
            self._attempt("primary", rank=0, is_primary=True),
            self._attempt("fallback-1", rank=1),
            self._attempt("fallback-2", rank=2),
        ]
        _check_v3_fallback_attempts(attempts, set())

    def test_non_increasing_ranks_raise(self) -> None:
        attempts = [
            self._attempt("primary", rank=1, is_primary=True),
            self._attempt("fallback", rank=1),
        ]
        with pytest.raises(ManifestIntegrityError, match="increasing queue rank"):
            _check_v3_fallback_attempts(attempts, set())

    def test_primary_not_first_raises(self) -> None:
        attempts = [
            self._attempt("other", rank=0),
            self._attempt("primary", rank=1, is_primary=True),
        ]
        with pytest.raises(
            ManifestIntegrityError, match="Primary candidate must be attempted"
        ):
            _check_v3_fallback_attempts(attempts, set())

    def test_later_primary_attempt_raises(self) -> None:
        attempts = [
            self._attempt("primary", rank=0, is_primary=True),
            self._attempt("duplicate-primary", rank=1, is_primary=True),
        ]
        with pytest.raises(
            ManifestIntegrityError, match="Only the first target attempt may be primary"
        ):
            _check_v3_fallback_attempts(attempts, set())

    def test_fallback_after_admission_raises(self) -> None:
        attempts = [
            self._attempt("admitted", rank=0, is_primary=True),
            self._attempt("fallback", rank=1),
        ]
        with pytest.raises(
            ManifestIntegrityError, match="Fallback attempted after target admission"
        ):
            _check_v3_fallback_attempts(attempts, {"admitted"})


class TestCheckV3CompletedStatus:
    def test_quarantine_requires_completed_with_errors(self) -> None:
        resolver = SimpleNamespace(manifest=SimpleNamespace(status=RunStatus.COMPLETED))
        with pytest.raises(
            ManifestIntegrityError, match="requires completed_with_errors"
        ):
            _check_v3_completed_status(resolver, {"quarantined-candidate"})

    def test_no_quarantine_requires_completed_status(self) -> None:
        resolver = SimpleNamespace(manifest=SimpleNamespace(status=RunStatus.STARTED))
        with pytest.raises(ManifestIntegrityError, match="requires a completed status"):
            _check_v3_completed_status(resolver, set())

    def test_completed_with_errors_and_quarantine_passes(self) -> None:
        resolver = SimpleNamespace(
            manifest=SimpleNamespace(status=RunStatus.COMPLETED_WITH_ERRORS)
        )
        _check_v3_completed_status(resolver, {"quarantined-candidate"})

    def test_completed_without_quarantine_passes(self) -> None:
        resolver = SimpleNamespace(manifest=SimpleNamespace(status=RunStatus.COMPLETED))
        _check_v3_completed_status(resolver, set())


class TestCheckGateViolationsMatchTerminal:
    @staticmethod
    def _decision(gate_results: list[Any], violations: list[Any]) -> SimpleNamespace:
        return SimpleNamespace(gate_results=gate_results, violations=violations)

    def test_without_gate_results_passes(self) -> None:
        _check_gate_violations_match_terminal(self._decision([], []))

    def test_matching_gate_violations_pass(self) -> None:
        violation = SimpleNamespace(code="hard_failure", detail="boom")
        _check_gate_violations_match_terminal(
            self._decision([SimpleNamespace(violations=[violation])], [violation])
        )

    def test_mismatched_gate_violations_raise(self) -> None:
        with pytest.raises(ValueError, match="must match terminal violations"):
            _check_gate_violations_match_terminal(
                self._decision(
                    [SimpleNamespace(violations=[])],
                    [SimpleNamespace(code="hard_failure", detail="boom")],
                )
            )


# ---------------------------------------------------------------------------
# runner.py: remaining resume/option validation helpers
# ---------------------------------------------------------------------------


class TestValidateRunPipelineOptions:
    def test_accepts_valid_options(self) -> None:
        assert _validate_run_pipeline_options("allow", None, "exhaustive") is (
            GenerationMode.EXHAUSTIVE
        )
        assert _validate_run_pipeline_options("forbid", 3, "coverage") is (
            GenerationMode.COVERAGE
        )

    def test_rejects_invalid_presentation_fallback(self) -> None:
        with pytest.raises(ValueError, match="presentation_fallback must be"):
            _validate_run_pipeline_options("bogus", None, "exhaustive")

    def test_rejects_non_positive_max_scenarios(self) -> None:
        with pytest.raises(ValueError, match="positive integer"):
            _validate_run_pipeline_options("allow", 0, "exhaustive")

    def test_rejects_invalid_generation_mode(self) -> None:
        with pytest.raises(ValueError, match="generation_mode must be"):
            _validate_run_pipeline_options("allow", None, "bogus")


class TestValidateResumeManifestIdentity:
    @staticmethod
    def _manifest(**overrides: Any) -> SimpleNamespace:
        fields: dict[str, Any] = {
            "run_id": RUN_ID,
            "provenance": SimpleNamespace(run_id=RUN_ID),
        }
        fields.update(overrides)
        return SimpleNamespace(**fields)

    def test_valid_manifest_passes(self) -> None:
        _validate_resume_manifest_identity(Path(RUN_ID), self._manifest())

    def test_noncanonical_run_id_raises(self) -> None:
        manifest = self._manifest(run_id="not-a-run-id")
        with pytest.raises(ManifestIntegrityError, match="noncanonical run_id"):
            _validate_resume_manifest_identity(Path(RUN_ID), manifest)

    def test_directory_name_mismatch_raises(self) -> None:
        with pytest.raises(
            ManifestIntegrityError, match="does not match run directory"
        ):
            _validate_resume_manifest_identity(Path("other-run"), self._manifest())

    def test_missing_provenance_raises(self) -> None:
        manifest = self._manifest(provenance=None)
        with pytest.raises(ManifestIntegrityError, match="provenance run_id mismatch"):
            _validate_resume_manifest_identity(Path(RUN_ID), manifest)

    def test_provenance_run_id_mismatch_raises(self) -> None:
        manifest = self._manifest(provenance=SimpleNamespace(run_id="other-run"))
        with pytest.raises(ManifestIntegrityError, match="provenance run_id mismatch"):
            _validate_resume_manifest_identity(Path(RUN_ID), manifest)


class TestCausalStageArtifacts:
    @staticmethod
    def _tree(label: str) -> dict[str, str]:
        return {"tree": label}

    @classmethod
    def _behavior_record(cls, **overrides: Any) -> SimpleNamespace:
        visible_tree = cls._tree("visible")
        fields: dict[str, Any] = dict(
            sequence=1,
            stage=GeneratedStage.behavior,
            input=SimpleNamespace(
                candidate="candidate-1",
                visible_artifacts={GeneratedStage.tree.value: visible_tree},
            ),
            final_tree_snapshot_sha256=canonical_sha256(visible_tree),
            result=None,
            violations=[],
            call=None,
        )
        fields.update(overrides)
        return SimpleNamespace(**fields)

    @staticmethod
    def _repair(*, attempt_id: str = "attempt-1") -> SimpleNamespace:
        generated_tree = {"tree": "generated"}
        visible_tree = {"tree": "visible"}
        return SimpleNamespace(
            accepted=True,
            candidate_attempt_id=attempt_id,
            sequence=0,
            before_digest=canonical_sha256(generated_tree),
            after_digest=canonical_sha256(visible_tree),
        )

    def test_accepted_repair_links_digest_transition(self) -> None:
        generated_tree = self._tree("generated")
        visible_tree = self._tree("visible")
        tree_record = SimpleNamespace(
            sequence=0,
            stage=GeneratedStage.tree,
            input=SimpleNamespace(
                candidate="candidate-1",
                visible_artifacts={},
            ),
            final_tree_snapshot_sha256=None,
            result=generated_tree,
            violations=[],
            call=SimpleNamespace(),
        )
        behavior_record = self._behavior_record()
        frontier = _causal_stage_artifacts(
            [tree_record, behavior_record],
            candidate_attempt_id="attempt-1",
            repairs=[self._repair()],
        )
        assert frontier[GeneratedStage.tree] == visible_tree

    def test_unlinked_digest_transition_raises(self) -> None:
        generated_tree = self._tree("generated")
        tree_record = SimpleNamespace(
            sequence=0,
            stage=GeneratedStage.tree,
            input=SimpleNamespace(
                candidate="candidate-1",
                visible_artifacts={},
            ),
            final_tree_snapshot_sha256=None,
            result=generated_tree,
            violations=[],
            call=SimpleNamespace(),
        )
        with pytest.raises(ValueError, match="neither generated nor linked"):
            _causal_stage_artifacts(
                [tree_record, self._behavior_record()],
                candidate_attempt_id="attempt-1",
            )

    def test_repair_for_other_attempt_does_not_link(self) -> None:
        generated_tree = self._tree("generated")
        repair = self._repair(attempt_id="attempt-other")
        assert not _has_accepted_tree_repair(
            [repair],
            "attempt-1",
            1,
            canonical_sha256(generated_tree),
            canonical_sha256(self._tree("visible")),
        )

    def test_missing_generated_tree_raises(self) -> None:
        with pytest.raises(ValueError, match="has no causal generated tree"):
            _causal_stage_artifacts(
                [self._behavior_record()],
                candidate_attempt_id="attempt-1",
            )

    def test_pinned_durable_candidate_mismatch_raises(self) -> None:
        record = self._behavior_record(
            input=SimpleNamespace(
                candidate="candidate-other",
                visible_artifacts={},
            )
        )
        with pytest.raises(ValueError, match="differs from durable plan"):
            _causal_stage_artifacts(
                [record],
                candidate_attempt_id="attempt-1",
                durable_candidate={"candidate": "candidate-1"},
            )

    def test_visible_tree_hash_mismatch_raises(self) -> None:
        visible_tree = self._tree("visible")
        record = self._behavior_record(
            final_tree_snapshot_sha256=canonical_sha256(self._tree("other"))
        )
        with pytest.raises(ValueError, match="not bound to its final-tree input"):
            _require_input_bound_tree(record, visible_tree)


class TestResolveResumeDirectory:
    def test_rejects_missing_path(self, tmp_path: Path) -> None:
        with pytest.raises(ManifestIntegrityError, match="existing run directory"):
            _resolve_resume_directory(tmp_path / "missing")

    def test_rejects_non_directory_path(self, tmp_path: Path) -> None:
        file_path = tmp_path / "not-a-directory"
        file_path.write_text(".")
        with pytest.raises(ManifestIntegrityError, match="existing run directory"):
            _resolve_resume_directory(file_path)

    def test_accepts_existing_directory(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        assert _resolve_resume_directory(run_dir) == run_dir


class TestResumeOverrides:
    @staticmethod
    def _persisted(
        model: str = "persisted", base_url: str = "https://persisted"
    ) -> SimpleNamespace:
        return SimpleNamespace(model=model, base_url=base_url)

    def test_model_override_mismatch_raises(self) -> None:
        with pytest.raises(ManifestIntegrityError, match="model override conflicts"):
            _validate_resume_model_override("override", self._persisted())

    def test_matching_or_absent_model_override_passes(self) -> None:
        _validate_resume_model_override("persisted", self._persisted())
        _validate_resume_model_override(None, self._persisted())

    def test_endpoint_override_mismatch_raises(self) -> None:
        with pytest.raises(ManifestIntegrityError, match="endpoint override conflicts"):
            _validate_resume_endpoint_override("https://override", self._persisted())

    def test_matching_or_absent_endpoint_override_passes(self) -> None:
        _validate_resume_endpoint_override("https://persisted", self._persisted())
        _validate_resume_endpoint_override(None, self._persisted())

    def test_resolved_model_prefers_override_then_persisted(self) -> None:
        persisted = self._persisted()
        assert _resolved_resume_model("override", persisted) == "override"
        assert _resolved_resume_model(None, persisted) == "persisted"
        assert _resolved_resume_model(None, None) is None

    def test_resolved_base_url_prefers_override_then_persisted(self) -> None:
        persisted = self._persisted()
        assert (
            _resolved_resume_base_url("https://override", persisted)
            == "https://override"
        )
        assert _resolved_resume_base_url(None, persisted) == "https://persisted"
        assert _resolved_resume_base_url(None, None) is None


class TestRunnerCompletionPredicates:
    @staticmethod
    def _scorecard(status: str) -> dict:
        return {"qualification": {"status": status}}

    def test_scorecard_qualification_pass(self) -> None:
        assert _scorecard_qualification_passed(self._scorecard("pass")) is True
        assert _scorecard_qualification_passed(self._scorecard("rejected")) is False

    def test_authoritative_products_ready_requires_both(self) -> None:
        assert _authoritative_products_ready(True, True) is True
        assert _authoritative_products_ready(True, False) is False
        assert _authoritative_products_ready(False, True) is False

    def test_ordinary_completion_succeeded_requires_all(self) -> None:
        base = dict(
            terminal_processing_succeeded=True,
            had_quarantine=False,
            eval_enabled=True,
            eval_success=True,
            report_success=True,
            qualification_passed=True,
        )
        assert _ordinary_completion_succeeded(**base) is True
        for key in (
            "terminal_processing_succeeded",
            "eval_enabled",
            "eval_success",
            "report_success",
            "qualification_passed",
        ):
            assert _ordinary_completion_succeeded(**{**base, key: False}) is False
        assert (
            _ordinary_completion_succeeded(**{**base, "had_quarantine": True}) is False
        )

    def test_readable_evidence_file(self, tmp_path: Path) -> None:
        regular = tmp_path / "artifact.yaml"
        regular.write_text(".")
        assert _readable_evidence_file(regular) is True
        assert _readable_evidence_file(tmp_path) is False
        assert _readable_evidence_file(tmp_path / "missing") is False


class TestPipelineResultDefaults:
    def test_run_inventory_counts_default_to_zero(self) -> None:
        result = PipelineResult.model_construct()
        assert result.admitted_count == 0
        assert result.quarantined_count == 0
        assert result.failed_count == 0

    def test_qualification_facts_default_schema_version(self) -> None:
        assert QualificationFactsV1(facts=()).schema_version == "1"


class TestRunnerRunCompletionHelpers:
    @staticmethod
    def _fseed(
        entry: str = "ep-1", candidate: str = "c-1", seed_id: str = "p-1"
    ) -> SimpleNamespace:
        return SimpleNamespace(
            entry_point_id=entry, candidate_id=candidate, seed_id=seed_id
        )

    @staticmethod
    def _pc(entry: str = "ep-1") -> SimpleNamespace:
        return SimpleNamespace(
            canonical_ingress=SimpleNamespace(entry_point_id=entry),
            candidate_id="c-1",
            seed_id="p-1",
        )

    @staticmethod
    def _ledger() -> SimpleNamespace:
        return SimpleNamespace(calls=[])

    def test_validate_run_pipeline_options_accepts_max_one(self) -> None:
        resolved = _validate_run_pipeline_options("allow", 1, "coverage")
        assert resolved is GenerationMode.COVERAGE

    def test_immutable_roles_by_role_none_manifest_is_empty(self) -> None:
        assert _immutable_roles_by_role(None, {"use-case"}) == {}

    def test_support_published_none_false_and_matching_positive(self) -> None:
        assert _support_published(None, set()) is False
        manifest = SimpleNamespace(inventory=[SimpleNamespace(role="use-case")])
        assert _support_published(manifest, {"use-case"}) is True
        assert _support_published(manifest, {"use-case", "seed-index"}) is False

    def test_support_validation_result_unpublished_is_false(self) -> None:
        assert _support_validation_result(
            Path("."), None, set(), RuntimeError("boom")
        ) == (False, None)

    def test_support_validation_result_valid_and_corrupt(self, tmp_path: Path) -> None:
        empty_manifest = _manifest(tmp_path)
        assert _support_validation_result(
            tmp_path, empty_manifest, set(), RuntimeError("boom")
        ) == (True, None)
        manifest = _manifest(tmp_path, yaml_ids=("a",), feature_ids=("a",))
        (tmp_path / "scenarios" / "a.yaml").unlink()
        valid, message = _support_validation_result(
            tmp_path, manifest, set(), RuntimeError("boom")
        )
        assert valid is False
        assert "immutable support validation failed" in message

    def test_expansion_record_empty_defaults_and_tail(self) -> None:
        empty = _expansion_record([])
        assert empty.input_count == 0
        assert empty.output_count == 0
        assert empty.collapsed_count == 0
        last = SimpleNamespace(input_count=3, output_count=2, collapsed_count=1)
        assert _expansion_record([last]) is last

    def test_record_filter_rejections_skips_accepted_candidates(self) -> None:
        ledger = self._ledger()
        accepted = self._fseed(candidate="c-accepted")
        _record_filter_rejections(
            ledger,
            [
                SimpleNamespace(
                    candidate_id="c-accepted", entry_point_id="ep-1", seed_id="p-1"
                )
            ],
            [accepted],
            [],
        )
        assert ledger.calls == []

    def test_projection_event_no_candidates(self) -> None:
        ledger = self._ledger()
        fseed = self._fseed()
        ledger.record = lambda **kw: ledger.calls.append(kw)
        rejected, by_target = _projection_event_for_fseed(ledger, fseed, None)
        assert rejected == 1
        assert by_target == {"ep-1": ["c-1"]}

    def test_projection_event_no_matching_candidates(self) -> None:
        ledger = self._ledger()
        ledger.record = lambda **kw: ledger.calls.append(kw)
        fseed = self._fseed()
        rejected, by_target = _projection_event_for_fseed(
            ledger, fseed, [self._pc("ep-2")]
        )
        assert rejected == 1
        assert by_target == {"ep-1": ["c-1"]}

    def test_projection_event_matching_candidate_succeeds(self) -> None:
        ledger = self._ledger()
        ledger.record = lambda **kw: ledger.calls.append(kw)
        fseed = self._fseed()
        rejected, by_target = _projection_event_for_fseed(
            ledger, fseed, [self._pc("ep-1")]
        )
        assert rejected == 0
        assert by_target == {}

    def test_record_projection_events_empty_seeds(self) -> None:
        rejected, by_target = _record_projection_events(self._ledger(), [], {})
        assert rejected == 0
        assert by_target == {}

    def test_log_cap_summary_zero_is_silent_and_one_logs(self, caplog: Any) -> None:
        caplog.set_level("INFO")
        _log_cap_summary(GenerationMode.EXHAUSTIVE, 0)
        assert "capped" not in caplog.text
        caplog.clear()
        _log_cap_summary(GenerationMode.EXHAUSTIVE, 1)
        assert "1 candidate" in caplog.text and "capped" in caplog.text


# ---------------------------------------------------------------------------
# manifest.py: resolver lookup helper
# ---------------------------------------------------------------------------


class TestFeatureForScenario:
    @staticmethod
    def _resolver(*entries: Any) -> SimpleNamespace:
        return SimpleNamespace(entries_by_role=lambda role: list(entries))

    def test_returns_matching_feature_entry(self) -> None:
        first = SimpleNamespace(scenario_id="a")
        second = SimpleNamespace(scenario_id="b")
        resolver = self._resolver(first, second)
        assert (ManifestInventoryResolver.feature_for_scenario(resolver, "b")) is second

    def test_returns_none_when_absent(self) -> None:
        resolver = self._resolver(SimpleNamespace(scenario_id="a"))
        assert ManifestInventoryResolver.feature_for_scenario(resolver, "z") is None

    def test_returns_none_for_empty_role(self) -> None:
        assert (
            ManifestInventoryResolver.feature_for_scenario(self._resolver(), "a")
            is None
        )


# ---------------------------------------------------------------------------
# validation.py: leaf consequence heuristic and seed fidelity
# ---------------------------------------------------------------------------


class TestIsConsequenceLeaf:
    @staticmethod
    def _node(action: Any, label: str, description: str | None = None) -> Any:
        return SimpleNamespace(action=action, label=label, description=description)

    def test_impact_action_is_consequence(self) -> None:
        node = self._node(ImpactAction(boundary="internal", target="funds"), "send")
        assert _is_consequence_leaf(node)

    def test_non_impact_action_is_not_consequence(self) -> None:
        node = self._node(AiSystemAction(), "impact damage realized")
        assert not _is_consequence_leaf(node)

    def test_consequence_pattern_in_label(self) -> None:
        node = self._node(None, "victim transfers funds")
        assert _is_consequence_leaf(node)

    def test_consequence_pattern_in_description(self) -> None:
        node = self._node(None, "transfer step", description="data exfiltrated")
        assert _is_consequence_leaf(node)

    def test_plain_label_is_not_consequence(self) -> None:
        node = self._node(None, "attacker scans the network")
        assert not _is_consequence_leaf(node)


class TestSeedMechanismFidelity:
    def test_blank_name_skips_check(self) -> None:
        assert check_seed_mechanism_fidelity("", "anything") is None
        assert check_seed_mechanism_fidelity(None, "anything") is None

    def test_non_string_name_skips_check(self) -> None:
        assert check_seed_mechanism_fidelity(5, "anything") is None

    def test_stop_word_only_name_skips_check(self) -> None:
        assert check_seed_mechanism_fidelity("a of and", "anything") is None

    def test_matching_keyword_passes(self) -> None:
        assert (
            check_seed_mechanism_fidelity("Inject Malicious Payload", "payload") is None
        )

    def test_missing_keyword_returns_warning(self) -> None:
        warning = check_seed_mechanism_fidelity(
            "Inject Malicious Payload", "benign text"
        )
        assert warning is not None


# ---------------------------------------------------------------------------
# persistence.py: artifact receipt identity
# ---------------------------------------------------------------------------


class TestArtifactReceiptRoleIdentity:
    @staticmethod
    def _receipt(role: ArtifactRole, scenario_id: str | None) -> ArtifactReceipt:
        return ArtifactReceipt(
            candidate_id="candidate",
            role=role,
            path="scenarios/a.yaml",
            sha256="0" * 64,
            scenario_id=scenario_id,
        )

    def test_normal_scenario_receipt_requires_scenario_id(self) -> None:
        receipt = self._receipt(ArtifactRole.SCENARIO_YAML, "scenario-a")
        assert receipt._role_identity() is receipt

    def test_normal_scenario_receipt_without_scenario_id_raises(self) -> None:
        with pytest.raises(ValueError, match="require scenario_id"):
            self._receipt(ArtifactRole.SCENARIO_FEATURE, None)._role_identity()

    def test_quarantine_receipt_forbids_scenario_id(self) -> None:
        receipt = self._receipt(ArtifactRole.QUARANTINE_BUNDLE, None)
        assert receipt._role_identity() is receipt

    def test_quarantine_receipt_with_scenario_id_raises(self) -> None:
        with pytest.raises(ValueError, match="forbid scenario_id"):
            self._receipt(ArtifactRole.QUARANTINE_BUNDLE, "scenario-a")._role_identity()

    def test_unsupported_role_raises(self) -> None:
        with pytest.raises(ValueError, match="unsupported finalization artifact"):
            self._receipt(ArtifactRole.USE_CASE, None)._role_identity()
