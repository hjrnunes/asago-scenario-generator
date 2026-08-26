"""Mutation hardening tests for narrative.py leaf helpers.

Targets surviving mutants identified by mutate4py on the architect's
decomposed generate-stage orchestration.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from asago_scenario_generator.llm.client import LLMResult
from asago_scenario_generator.models.scenario import (
    ActorProfile,
    ActorAccessProvenance,
    NarrativeAccessRealization,
    NarrativeLayer,
    NarrativeStep,
    ProjectedStepRealization,
)
from asago_scenario_generator.pipeline.generate.narrative import (
    Call1Response,
    Call1Step,
    _access_provenance_block,
    _apply_projection_access_realization,
    _actor_grounding_section,
    _canonical_realizations_for_step,
    _enforce_narrative_zones,
    _entry_point_diversity_section,
    _goal_guidance_section,
    _is_latin_or_common,
    _map_call1_to_narrative,
    _normalize_legacy_step_ids,
    _novice_diversity_priority,
    _prior_titles_section,
    _prompt_text,
    _responsible_step_for,
    _sanitize_narrative,
    _sanitize_step,
    _selected_projection_steps_by_id,
    _single_source_path,
    _tool_inventory_list,
    _verify_full_projection_coverage,
    build_call1_response_model,
    _resolve_initial_entry_point_name,
    _resolve_narrative_access_names,
    _sanitize_non_latin,
)


# -- _is_latin_or_common --------------------------------------------------

class TestIsLatinOrCommon:
    def test_ascii_returns_true(self) -> None:
        assert _is_latin_or_common("a") is True

    def test_punctuation_returns_true(self) -> None:
        assert _is_latin_or_common(".") is True

    def test_latin_accented_returns_true(self) -> None:
        assert _is_latin_or_common("é") is True

    def test_non_latin_returns_false(self) -> None:
        assert _is_latin_or_common("中") is False

    def test_non_ascii_common_punctuation_returns_true(self) -> None:
        # The Unicode category's first character is the category family
        # (``P`` for punctuation).  Indexing the second character would
        # incorrectly reject this otherwise safe character.
        assert _is_latin_or_common("—") is True


# -- _sanitize_step -------------------------------------------------------

def _make_step(action: str = "probe", effect: str = "detected") -> NarrativeStep:
    return NarrativeStep(
        step_number=1, zone="input", action=action, effect=effect,
        projected_step_ids=("s1",),
    )


class TestSanitizeStep:
    def test_non_latin_action_is_sanitized(self) -> None:
        step = _make_step(action="攻击系统", effect="detected")
        result = _sanitize_step(step)
        assert result.action != step.action

    def test_non_latin_effect_is_sanitized(self) -> None:
        step = _make_step(action="probe", effect="检测到入侵")
        result = _sanitize_step(step)
        assert result.effect != step.effect

    def test_both_non_latin_is_sanitized(self) -> None:
        step = _make_step(action="攻击", effect="检测")
        result = _sanitize_step(step)
        assert result.action != step.action
        assert result.effect != step.effect

    def test_clean_step_returns_same_instance(self) -> None:
        step = _make_step()
        result = _sanitize_step(step)
        assert result is step


# -- _sanitize_narrative --------------------------------------------------

def _make_narrative(
    title: str = "Attack",
    summary: str = "Summary",
    action: str = "probe",
    effect: str = "detected",
) -> NarrativeLayer:
    return NarrativeLayer(
        title=title,
        summary=summary,
        entry_point="Chat interface",
        zone_sequence=["input"],
        steps=[_make_step(action=action, effect=effect)],
    )


class TestSanitizeNarrative:
    def test_non_latin_title_is_sanitized(self) -> None:
        narrative = _make_narrative(title="攻击路径")
        result = _sanitize_narrative(narrative)
        assert result.title != narrative.title

    def test_non_latin_summary_is_sanitized(self) -> None:
        narrative = _make_narrative(summary="这是一个摘要")
        result = _sanitize_narrative(narrative)
        assert result.summary != narrative.summary

    def test_non_latin_steps_are_sanitized(self) -> None:
        narrative = _make_narrative(action="攻击", effect="检测")
        result = _sanitize_narrative(narrative)
        assert result.steps[0].action != narrative.steps[0].action


def test_sanitize_non_latin_collapses_whitespace_left_by_removal() -> None:
    """Script removal must not leave doubled spaces or padded lines."""
    assert _sanitize_non_latin("probe  \t攻击  system\n  impact") == (
        "probe system\nimpact"
    )


# -- _single_source_path --------------------------------------------------

class TestSingleSourcePath:
    def test_empty_returns_none(self) -> None:
        assert _single_source_path([]) is None

    def test_single_path_returns_it(self) -> None:
        path = {"source_id": "s1"}
        assert _single_source_path([path]) is path

    def test_multiple_paths_raises(self) -> None:
        with pytest.raises(ValueError, match="multiple source-influence"):
            _single_source_path([{"a": 1}, {"b": 2}])


# -- _responsible_step_for ------------------------------------------------

class TestResponsibleStepFor:
    def test_none_current_returns_min(self) -> None:
        assert _responsible_step_for(None, {3, 1, 2}) == 1

    def test_valid_current_returns_current(self) -> None:
        current = NarrativeAccessRealization(
            initial_entry_point_id="ep1", responsible_step_number=2
        )
        assert _responsible_step_for(current, {1, 2, 3}) == 2

    def test_invalid_current_returns_min(self) -> None:
        current = NarrativeAccessRealization(
            initial_entry_point_id="ep1", responsible_step_number=99
        )
        assert _responsible_step_for(current, {1, 2, 3}) == 1


# -- _access_provenance_block ---------------------------------------------

class TestAccessProvenanceBlock:
    def test_none_actor_returns_empty(self) -> None:
        profile = SimpleNamespace()
        assert _access_provenance_block(None, profile) == ""

    def test_none_access_returns_empty(self) -> None:
        profile = SimpleNamespace()
        actor = ActorProfile(
            actor_type="cybercriminal",
            capability_level="novice",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resources=["r"],
        )
        assert _access_provenance_block(actor, profile) == ""

    def test_present_access_returns_authoritative_block(self) -> None:
        actor = ActorProfile(
            actor_type="cybercriminal",
            capability_level="novice",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resources=["r"],
            access=ActorAccessProvenance(
                initial_entry_point_id="ep1",
                ingress_mode="direct",
                access_class="public",
            ),
        )
        profile = SimpleNamespace(
            id_to_entry_point_name=lambda: {"ep1": "Chat"},
            id_to_integration_name=lambda: {},
            id_to_trust_boundary_name=lambda: {},
            id_to_tool_name=lambda: {},
        )
        result = _access_provenance_block(actor, profile)
        assert "Actor Access Provenance" in result
        assert "Chat" in result


# -- _tool_inventory_list -------------------------------------------------

class TestToolInventoryList:
    def test_empty_returns_empty(self) -> None:
        assert _tool_inventory_list([]) == []

    def test_non_empty_returns_copy(self) -> None:
        tools = ["hammer", "wirecut"]
        assert _tool_inventory_list(tools) == tools


# -- build_call1_response_model ------------------------------------------

class TestBuildCall1ResponseModel:
    def test_none_returns_base_class(self) -> None:
        assert build_call1_response_model(None) is Call1Response

    def test_zero_returns_model(self) -> None:
        model = build_call1_response_model(0)
        assert model is not Call1Response

    def test_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            build_call1_response_model(-1)


# -- _reject_duplicate_projected_step_ids ---------------------------------

class TestRejectDuplicateStepIds:
    def test_duplicates_raise(self) -> None:
        with pytest.raises(ValidationError, match="duplicate projected step ID"):
            Call1Step(
                step_number=1,
                zone="input",
                action="probe",
                effect="detected",
                projected_step_ids=("s1", "s1"),
            )


# -- _prior_titles_section ------------------------------------------------

class TestPriorTitlesSection:
    def test_none_returns_empty(self) -> None:
        assert _prior_titles_section(None) == ""

    def test_empty_list_returns_empty(self) -> None:
        assert _prior_titles_section([]) == ""

    def test_non_empty_returns_section(self) -> None:
        result = _prior_titles_section(["Title A", "Title B"])
        assert "Title A" in result
        assert "Title B" in result
        assert "  1. Title A" in result
        assert "  2. Title B" in result


# -- _entry_point_diversity_section --------------------------------------

class TestEntryPointDiversitySection:
    def test_preferred_only_returns_guidance(self) -> None:
        result = _entry_point_diversity_section(
            None, "Chat interface", None, None
        )
        assert "Preferred entry point" in result

    def test_excluded_only_returns_guidance(self) -> None:
        result = _entry_point_diversity_section(
            None, None, ["EP1", "EP2"], None
        )
        assert "Avoid these" in result


# -- _actor_grounding_section --------------------------------------------

class TestActorGroundingSection:
    def test_none_returns_empty(self) -> None:
        assert _actor_grounding_section(None) == ""

    def test_valid_actor_returns_section(self) -> None:
        actor = ActorProfile(
            actor_type="cybercriminal",
            capability_level="novice",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resources=["r"],
        )
        result = _actor_grounding_section(actor)
        assert "Actor Profile" in result
        assert "cybercriminal" in result


# -- _goal_guidance_section ----------------------------------------------

class TestGoalGuidanceSection:
    def test_none_returns_empty(self) -> None:
        assert _goal_guidance_section(None) == ""

    def test_no_goal_category_returns_empty(self) -> None:
        actor = ActorProfile(
            actor_type="cybercriminal",
            capability_level="novice",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resources=["r"],
        )
        assert _goal_guidance_section(actor) == ""


# -- _novice_diversity_priority ------------------------------------------

class TestNoviceDiversityPriority:
    def test_novice_appends_priority(self) -> None:
        actor = ActorProfile(
            actor_type="cybercriminal",
            capability_level="novice",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resources=["r"],
        )
        result = _novice_diversity_priority("base section", actor)
        assert "NOVICE" in result
        assert len(result) > len("base section")

    def test_non_novice_returns_unchanged(self) -> None:
        actor = ActorProfile(
            actor_type="cybercriminal",
            capability_level="expert",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resources=["r"],
        )
        assert _novice_diversity_priority("base section", actor) == "base section"


# -- _prompt_text ---------------------------------------------------------

class TestPromptText:
    def test_none_returns_empty(self) -> None:
        assert _prompt_text(None) == ""

    def test_non_empty_returns_feedback(self) -> None:
        assert _prompt_text("fix this") == "fix this"


# -- _selected_projection_steps_by_id ------------------------------------

class TestSelectedProjectionStepsById:
    def test_valid_steps_returns_dict(self) -> None:
        ctx = {"selected_steps": [{"step_id": "s1"}, {"step_id": "s2"}]}
        result = _selected_projection_steps_by_id(ctx)
        assert set(result.keys()) == {"s1", "s2"}

    def test_duplicate_step_id_raises(self) -> None:
        ctx = {"selected_steps": [{"step_id": "s1"}, {"step_id": "s1"}]}
        with pytest.raises(ValueError, match="duplicate projected step ID"):
            _selected_projection_steps_by_id(ctx)


# -- _canonical_realizations_for_step ------------------------------------

class TestCanonicalRealizationsForStep:
    def test_unknown_step_id_raises(self) -> None:
        step = Call1Step(
            step_number=1,
            zone="input",
            action="probe",
            effect="detected",
            projected_step_ids=("unknown",),
        )
        with pytest.raises(ValueError, match="unknown projected step ID"):
            _canonical_realizations_for_step(step, {})

    def test_missing_realization_raises(self) -> None:
        step = Call1Step(
            step_number=1,
            zone="input",
            action="probe",
            effect="detected",
            projected_step_ids=("s1",),
        )
        with pytest.raises(ValueError, match="missing canonical realization"):
            _canonical_realizations_for_step(step, {"s1": {}})

    def test_mismatched_realization_id_raises(self) -> None:
        step = Call1Step(
            step_number=1,
            zone="input",
            action="probe",
            effect="detected",
            projected_step_ids=("s1",),
        )
        realization = ProjectedStepRealization(
            projected_step_id="different",
            action_kind="observe",
            executor_role="system",
            boundary_position="inside",
            resource_ref_ids=(),
            consumed_ref_ids=(),
            produced_ref_ids=(),
            produced_effect_ids=(),
            outcome_link_pc_ids=(),
            postcondition_ids=(),
        )
        with pytest.raises(ValueError, match="semantically incompatible"):
            _canonical_realizations_for_step(
                step, {"s1": {"realization": realization.model_dump()}}
            )


# -- _verify_full_projection_coverage ------------------------------------

class TestVerifyFullProjectionCoverage:
    def test_missing_step_raises(self) -> None:
        steps = [_make_step()]
        steps[0] = NarrativeStep(
            step_number=1,
            zone="input",
            action="probe",
            effect="detected",
            projected_step_ids=("s1",),
        )
        ctx = {"selected_step_ids": ("s1", "s2")}
        with pytest.raises(ValueError, match="omitted projected step ID"):
            _verify_full_projection_coverage(steps, ctx)


# -- _map_call1_to_narrative ---------------------------------------------

class TestMapCall1ToNarrative:
    def test_without_projection_context_skips_validation(self) -> None:
        resp = Call1Response(
            title="Test",
            summary="Summary",
            entry_point="Chat",
            zone_sequence=["input"],
            steps=[
                Call1Step(
                    step_number=1,
                    zone="input",
                    action="probe",
                    effect="detected",
                    projected_step_ids=("s1",),
                )
            ],
        )
        result = _map_call1_to_narrative(resp, None)
        assert result.title == "Test"
        assert len(result.steps) == 1


class TestProjectionAccessHelpers:
    def test_none_projection_context_is_a_noop(self) -> None:
        narrative = _make_narrative()
        _apply_projection_access_realization(narrative, None)
        assert narrative.access_realization is None

    def test_missing_access_realization_is_created_from_projection(self) -> None:
        narrative = _make_narrative()
        context = {
            "canonical_ingress": {"entry_point_id": "ep1"},
            "source_influence_paths": [],
        }
        _apply_projection_access_realization(narrative, context)
        assert narrative.access_realization is not None
        assert narrative.access_realization.initial_entry_point_id == "ep1"
        assert narrative.access_realization.responsible_step_number == 1

    def test_none_context_keeps_legacy_step_ids_unchanged(self) -> None:
        response = Call1Response(
            title="Test",
            summary="Summary",
            entry_point="Chat",
            zone_sequence=["input"],
            steps=[
                Call1Step(
                    step_number=1,
                    zone="input",
                    action="probe",
                    effect="detected",
                    projected_step_ids=("legacy-id",),
                )
            ],
        )
        result = LLMResult(
            content=response,
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )
        _normalize_legacy_step_ids(result, None)
        assert result.content.steps[0].projected_step_ids == ("legacy-id",)

    def test_none_context_uses_bare_profile_zone_enforcement(self) -> None:
        narrative = _make_narrative()
        profile = SimpleNamespace(zones_active=["input"])
        with patch(
            "asago_scenario_generator.pipeline.generate.narrative._enforce_zones_narrative",
            return_value="bare-result",
        ) as bare:
            assert _enforce_narrative_zones(narrative, profile, None) == "bare-result"
        bare.assert_called_once_with(narrative, ["input"])


class TestEntryPointNameResolution:
    def test_resolved_name_replaces_human_readable_id(self) -> None:
        realization = SimpleNamespace(initial_entry_point_id="Chat")
        profile = SimpleNamespace()
        with patch(
            "asago_scenario_generator.pipeline.generate.names.resolve_name_to_entry_point_id",
            return_value="ep:v1:canonical",
        ):
            _resolve_initial_entry_point_name(realization, profile)
        assert realization.initial_entry_point_id == "ep:v1:canonical"

    def test_missing_access_realization_is_a_noop(self) -> None:
        _resolve_narrative_access_names(_make_narrative(), SimpleNamespace())
