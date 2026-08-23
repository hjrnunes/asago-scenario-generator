"""Tests for the validator-derived projection alignment table and prompt updates.

The compact per-step alignment table is derived from the projection
validation rules (action-kind and executor-role compatibility intersections)
and rendered in the narrative and attack-tree user prompts
(taxonomy projection prompt alignment).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.pipeline.generate.alignment import (
    derive_projection_alignment_row,
    derive_projection_alignment_rows,
)
from asago_scenario_generator.pipeline.generate.canonical_projection import (
    compatible_leaf_action_kinds_for_step,
)
from asago_scenario_generator.pipeline.projection_validation import (
    _EXECUTOR_ROLE_TO_LEAF_COMPAT,
    _STEP_TO_LEAF_ACTION_COMPAT,
)
from asago_scenario_generator.prompts import render_prompt

COLUMNS = [
    "canonical ID",
    "action",
    "executor",
    "boundary",
    "allowed narrative zone",
    "allowed tree kinds",
    "tree zone",
    "bound resources",
]


def _step(
    step_id: str,
    action: str,
    executor: str,
    boundary: str,
    resource_links: list | None = None,
) -> dict:
    return {
        "step_id": step_id,
        "action_kind": action,
        "executor_role": executor,
        "boundary_position": boundary,
        "attacker_controlled": executor == "attacker",
        "requirement": "required",
        "resource_links": resource_links or [],
    }


# ---------------------------------------------------------------------------
# Feature 02: row values are derived from validator rules
# ---------------------------------------------------------------------------


class TestRowDerivation:
    @pytest.mark.parametrize(
        (
            "canonical_id",
            "action",
            "executor",
            "boundary",
            "allowed_narrative_zone",
            "allowed_tree_kinds",
            "tree_zone",
            "bound_resources",
        ),
        [
            (
                "attacker.observe",
                "observe",
                "attacker",
                "outside",
                "outside",
                "external_precondition",
                "null",
                "none",
            ),
            (
                "attacker.deliver",
                "deliver",
                "attacker",
                "crossing",
                "active Schneider zone",
                "initial_ingress",
                "active Schneider zone",
                "entry_point/chat-interface",
            ),
            (
                "operator.impact",
                "impact",
                "operator",
                "inside",
                "active Schneider zone",
                "impact",
                "active Schneider zone",
                "effect/blocked-operation",
            ),
            (
                "operator.deliver",
                "deliver",
                "operator",
                "crossing",
                "active Schneider zone",
                "",
                "active Schneider zone",
                "entry_point/chat-interface",
            ),
        ],
    )
    def test_row_values_match_validator_rules(
        self,
        canonical_id,
        action,
        executor,
        boundary,
        allowed_narrative_zone,
        allowed_tree_kinds,
        tree_zone,
        bound_resources,
    ):
        step = _step(canonical_id, action, executor, boundary)
        if bound_resources == "entry_point/chat-interface":
            step["resource_links"] = [
                {
                    "role": "ingress",
                    "resource_ref": {
                        "kind": "entry_point",
                        "entry_point_id": "chat-interface",
                    },
                }
            ]
        elif bound_resources == "effect/blocked-operation":
            step["resource_links"] = [
                {
                    "role": "effect",
                    "resource_ref": {
                        "kind": "output_surface",
                        "entry_point_id": "blocked-operation",
                    },
                }
            ]
        row = derive_projection_alignment_row(step)
        assert row["canonical_id"] == canonical_id
        assert row["action"] == action
        assert row["executor"] == executor
        assert row["boundary"] == boundary
        assert row["allowed_narrative_zone"] == allowed_narrative_zone
        expected_kinds = (
            sorted(allowed_tree_kinds.split()) if allowed_tree_kinds else []
        )
        assert row["allowed_tree_kinds"] == expected_kinds
        assert row["tree_zone"] == tree_zone
        assert row["bound_resources"] == bound_resources


# ---------------------------------------------------------------------------
# Feature 03: stays synchronized with validator functions
# ---------------------------------------------------------------------------


class TestSynchronization:
    def test_tree_kinds_equal_canonical_ownership_compatibility(self):
        for action_kind in _STEP_TO_LEAF_ACTION_COMPAT:
            for executor_role in _EXECUTOR_ROLE_TO_LEAF_COMPAT:
                step = _step("step.x", action_kind, executor_role, "inside")
                row = derive_projection_alignment_row(step)
                expected = sorted(compatible_leaf_action_kinds_for_step(step))
                assert row["allowed_tree_kinds"] == expected

    def test_narrative_and_tree_zone_equal_stage_boundary_rules(self):
        for boundary in ("outside", "crossing", "inside"):
            row = derive_projection_alignment_row(
                _step("step.x", "observe", "attacker", boundary)
            )
            if boundary == "outside":
                assert row["allowed_narrative_zone"] == "outside"
                assert row["tree_zone"] == "null"
            else:
                assert row["allowed_narrative_zone"] == "active Schneider zone"
                assert row["tree_zone"] == "active Schneider zone"

    def test_empty_compatibility_intersection_is_an_empty_list(self):
        row = derive_projection_alignment_row(
            _step("operator.deliver", "deliver", "operator", "crossing")
        )
        assert row["allowed_tree_kinds"] == []

    def test_bound_resources_come_from_that_step_only(self):
        row = derive_projection_alignment_row(
            _step(
                "attacker.deliver",
                "deliver",
                "attacker",
                "crossing",
                resource_links=[
                    {
                        "role": "ingress",
                        "resource_ref": {
                            "kind": "entry_point",
                            "entry_point_id": "chat-interface",
                        },
                    }
                ],
            )
        )
        assert row["bound_resources"] == "entry_point/chat-interface"

    def test_rows_preserve_selected_step_order(self):
        rows = derive_projection_alignment_rows(
            [
                _step("attacker.observe", "observe", "attacker", "outside"),
                _step("attacker.deliver", "deliver", "attacker", "crossing"),
                _step("operator.impact", "impact", "operator", "inside"),
            ]
        )
        assert [r["canonical_id"] for r in rows] == [
            "attacker.observe",
            "attacker.deliver",
            "operator.impact",
        ]


# ---------------------------------------------------------------------------
# Feature 01: prompt renders one compact row per selected step
# ---------------------------------------------------------------------------


_PROMPT_CONTEXT = {
    "selected_step_ids": ["attacker.observe", "attacker.deliver", "operator.impact"],
    "selected_steps": [
        {
            "step_id": "attacker.observe",
            "action_kind": "observe",
            "executor_role": "attacker",
            "boundary_position": "outside",
            "attacker_controlled": True,
            "requirement": "required",
            "resource_links": [],
            "realization": {},
        },
        {
            "step_id": "attacker.deliver",
            "action_kind": "deliver",
            "executor_role": "attacker",
            "boundary_position": "crossing",
            "attacker_controlled": True,
            "requirement": "required",
            "resource_links": [
                {
                    "role": "ingress",
                    "resource_ref": {
                        "kind": "entry_point",
                        "entry_point_id": "chat-interface",
                    },
                }
            ],
            "realization": {},
        },
        {
            "step_id": "operator.impact",
            "action_kind": "impact",
            "executor_role": "operator",
            "boundary_position": "inside",
            "attacker_controlled": False,
            "requirement": "required",
            "resource_links": [],
            "realization": {},
        },
    ],
    "canonical_ingress": {"entry_point_id": "entry"},
    "ingress_controllability": "direct",
    "omitted_step_ids": [],
}


def _render_call1() -> str:
    seed = SimpleNamespace(
        seed_id="AP-T1-01",
        attack_pattern_name="pattern",
        attack_pattern_description="description",
        threat_name="threat",
        threat_description="description",
        kill_chain=[],
    )
    profile = SimpleNamespace(zones_active=["input"], entry_points=[])
    from asago_scenario_generator.pipeline.generate.alignment import (
        derive_projection_alignment_rows,
    )

    rows = derive_projection_alignment_rows(_PROMPT_CONTEXT["selected_steps"])
    return render_prompt(
        "call1_user.j2",
        use_case="use case",
        profile=profile,
        seed=seed,
        tool_inventory=[],
        kc_definitions="",
        owasp_llm_formatted="",
        ontology_context="",
        projection_context=_PROMPT_CONTEXT,
        projection_alignment_rows=rows,
        technique_context="",
        technique_framing="",
        actor_section="",
        access_provenance_block="",
        goal_section="",
        diversity_section="",
        pattern_section="",
        structural_section="",
        pinned_entry_point=None,
        pinned_entry_point_direction=None,
    )


def _render_call2() -> str:
    seed = SimpleNamespace(
        seed_id="AP-T1-01",
        attack_pattern_name="pattern",
        attack_pattern_description="description",
        threat_name="threat",
        threat_description="description",
        kill_chain=[],
    )
    narrative = SimpleNamespace(
        title="title",
        summary="summary",
        entry_point="entry",
        zone_sequence=[],
        steps=[],
    )
    from asago_scenario_generator.pipeline.generate.alignment import (
        derive_projection_alignment_rows,
    )

    rows = derive_projection_alignment_rows(_PROMPT_CONTEXT["selected_steps"])
    return render_prompt(
        "call2_user.j2",
        use_case="use case",
        ontology_context="",
        arch_section="",
        tool_inventory=[],
        seed=seed,
        kill_chain=[],
        actor_section="",
        access_provenance_block="",
        technique_context="",
        technique_constraint="",
        skeleton_section="",
        narrative=narrative,
        technique_count=0,
        leaf_budget=0,
        projection_context=_PROMPT_CONTEXT,
        projection_alignment_rows=rows,
        consistency_feedback="",
    )


class TestPromptTable:
    @pytest.mark.parametrize("render", [_render_call1, _render_call2])
    def test_renders_one_compact_row_per_selected_step_in_order(self, render):
        prompt = render()
        assert "Projection Alignment Table" in prompt
        for column in COLUMNS:
            assert column in prompt
        # One row per step, in canonical order.
        rows = [
            line
            for line in prompt.splitlines()
            if line.startswith("| attacker.observe ")
            or line.startswith("| attacker.deliver ")
            or line.startswith("| operator.impact ")
        ]
        assert len(rows) == 3
        assert "| attacker.observe |" in rows[0]
        assert "| attacker.deliver |" in rows[1]
        assert "| operator.impact |" in rows[2]

    @pytest.mark.parametrize("render", [_render_call1, _render_call2])
    def test_no_numeric_positional_id_and_semantic_warning(self, render):
        prompt = render()
        assert re_numeric_id(prompt) is None
        assert "semantic names, not positional labels" in prompt

    @pytest.mark.parametrize("render", [_render_call1, _render_call2])
    def test_empty_compatibility_rendered_as_empty_set(self, render):
        # operator.deliver is not selected in this context; derive a row for
        # a crossing operator step and assert template rendering of 'empty set'
        # by rendering the partial directly with a derived row.
        from asago_scenario_generator.pipeline.generate.alignment import (
            derive_projection_alignment_rows,
        )

        ctx = {
            **_PROMPT_CONTEXT,
            "selected_step_ids": ["operator.deliver"],
            "selected_steps": [
                {
                    "step_id": "operator.deliver",
                    "action_kind": "deliver",
                    "executor_role": "operator",
                    "boundary_position": "crossing",
                    "attacker_controlled": False,
                    "requirement": "required",
                    "resource_links": [],
                    "realization": {},
                }
            ],
        }
        rows = derive_projection_alignment_rows(ctx["selected_steps"])
        rendered = render_prompt(
            "_projection_alignment.j2",
            projection_context=ctx,
            projection_alignment_rows=rows,
        )
        assert "| operator.deliver |" in rendered
        assert "empty set" in rendered

    @pytest.mark.parametrize("render", [_render_call1, _render_call2])
    def test_no_hand_authored_compatibility_prose_duplicated(self, render):
        prompt = render()
        # The old hand-authored per-kind table is gone; the per-row table is
        # the only compatibility intersection prose.
        assert "#### Compatible leaf kinds" not in prompt


def re_numeric_id(prompt: str):
    import re

    return re.search(r"\|\s*\d+\s+\|", prompt)
