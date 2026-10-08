"""Tests for RevisionDelta pattern — RevisionDelta-01 through RevisionDelta-14.

The revision step now uses a RevisionDelta schema (only new/modified elements)
instead of full ControlStructure restate. The delta is merged programmatically
into the existing ControlStructure. The user prompt has a numbered per-finding
checklist, and the system prompt has ID format rules with next-available-ID
template variables.
"""

from __future__ import annotations

import re

import pytest

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ResponsibilityConstraint,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    RevisionDelta,
    _compute_next_ids,
    _extract_num,
    _is_responsibility_empty,
    _next_free_cm_id,
    _next_num_from,
    _renumber_colliding_cm_ids,
    run_revision,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.helpers.revision_delta import _make_control_structure


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_critic_findings() -> CriticFindings:
    return CriticFindings(
        gaps=[
            CriticGap(
                gap_type="missing_responsibility",
                description="Missing input validation",
                related_attack_path="Attacker sends crafted input",
                suggested_remedy="Add input validation responsibility",
            ),
            CriticGap(
                gap_type="missing_feedback",
                description="Missing outcome feedback",
                related_attack_path="Attacker exploits unchecked output",
                suggested_remedy="Add outcome verification feedback",
            ),
        ],
        checklist_results={
            "Outcome verification": "absent_unjustified",
        },
        taxonomy_probe_results={},
    )


def _make_revision_delta_dict(
    *,
    new_responsibilities: list | None = None,
    modified_responsibilities: list | None = None,
    new_controlled_processes: list | None = None,
    new_coordination_links: list | None = None,
) -> dict:
    delta: dict = {
        "new_responsibilities": new_responsibilities or [],
        "new_controlled_processes": new_controlled_processes or [],
        "new_coordination_links": new_coordination_links or [],
        "modified_responsibilities": modified_responsibilities or [],
    }
    return delta


def _load_template_text(name: str) -> str:
    path = PROMPTS_DIR / name
    return path.read_text(encoding="utf-8")


def _render_template(name: str, **kwargs) -> str:
    loader = TemplateLoader(PROMPTS_DIR)
    return loader.render_prompt(name, **kwargs)


# ---------------------------------------------------------------------------
# RevisionDelta-01: schema contains only delta fields
# ---------------------------------------------------------------------------


class TestRevisionDelta01Schema:
    """RevisionDelta-01: RevisionDelta schema contains only delta fields."""

    def test_model_has_delta_fields(self):
        fields = RevisionDelta.model_fields
        assert "new_responsibilities" in fields
        assert "new_controlled_processes" in fields
        assert "new_coordination_links" in fields
        assert "modified_responsibilities" in fields

    def test_model_does_not_have_full_structure_field(self):
        fields = RevisionDelta.model_fields
        assert "responsibilities" not in fields
        assert "controlled_processes" not in fields
        assert "coordination_links" not in fields


# ---------------------------------------------------------------------------
# RevisionDelta-02: run_revision produces RevisionDelta from LLM
# ---------------------------------------------------------------------------


class TestRevisionDelta02UsesRevisionDelta:
    """RevisionDelta-02: run_revision uses RevisionDelta as response format."""

    def test_revision_uses_revision_delta_format(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict(
            new_responsibilities=[
                {
                    "resp_id": "RESP-3",
                    "description": "Input validation controller",
                    "process_model_parts": [
                        {"pm_id": "PM-3-1", "description": "Input state"}
                    ],
                    "control_actions": [
                        {"ca_id": "CA-3-1", "description": "Validate input"}
                    ],
                    "feedback_channels": [
                        {
                            "fb_id": "FB-3-1",
                            "description": "Validation result",
                            "updates": "PM-3-1",
                            "source": {"type": "responsibility", "id": "RESP-3"},
                        }
                    ],
                }
            ]
        )
        client.set_response_for(RevisionDelta, delta)
        cs, warnings = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        # The LLM call used RevisionDelta as response_format
        assert client.calls[0].response_format == RevisionDelta
        # A revised ControlStructure was produced
        assert isinstance(cs, ControlStructure)


# ---------------------------------------------------------------------------
# RevisionDelta-03: new_responsibilities are merged
# ---------------------------------------------------------------------------


class TestRevisionDelta03MergeNewResponsibilities:
    """RevisionDelta-03: new_responsibilities are merged into existing CS."""

    def test_new_resp_merged(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict(
            new_responsibilities=[
                {
                    "resp_id": "RESP-3",
                    "description": "Input validation controller",
                    "process_model_parts": [
                        {"pm_id": "PM-3-1", "description": "Input state"}
                    ],
                    "control_actions": [
                        {"ca_id": "CA-3-1", "description": "Validate input"}
                    ],
                    "feedback_channels": [
                        {
                            "fb_id": "FB-3-1",
                            "description": "Validation result",
                            "updates": "PM-3-1",
                            "source": {"type": "responsibility", "id": "RESP-3"},
                        }
                    ],
                }
            ]
        )
        client.set_response_for(RevisionDelta, delta)
        cs, _ = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        resp_ids = {r.resp_id for r in cs.responsibilities}
        assert "RESP-1" in resp_ids
        assert "RESP-2" in resp_ids
        assert "RESP-3" in resp_ids


# ---------------------------------------------------------------------------
# RevisionDelta-04: modified_responsibilities replace by resp_id
# ---------------------------------------------------------------------------


class TestRevisionDelta04ModifiedReplace:
    """RevisionDelta-04: modified_responsibilities replace existing ones by resp_id."""

    def test_modified_resp_replaces_existing(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict(
            modified_responsibilities=[
                {
                    "resp_id": "RESP-1",
                    "description": "Updated controller description",
                    "process_model_parts": [
                        {"pm_id": "PM-1-1", "description": "Updated state"}
                    ],
                    "control_actions": [
                        {"ca_id": "CA-1-1", "description": "Updated action"}
                    ],
                    "feedback_channels": [
                        {
                            "fb_id": "FB-1-1",
                            "description": "Updated FB",
                            "updates": "PM-1-1",
                            "source": {"type": "responsibility", "id": "RESP-1"},
                        }
                    ],
                }
            ]
        )
        client.set_response_for(RevisionDelta, delta)
        cs, _ = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        resp1 = next(r for r in cs.responsibilities if r.resp_id == "RESP-1")
        assert resp1.description == "Updated controller description"
        # RESP-2 should be unchanged
        resp2 = next(r for r in cs.responsibilities if r.resp_id == "RESP-2")
        assert resp2.description == "Controller 2"


class TestRevisionDeltaModifiedMatchKey:
    """Modified responsibilities must retain their canonical match key."""

    def test_noncanonical_modified_resp_id_degrades_revision(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict(
            modified_responsibilities=[
                {
                    "resp_id": "renamed-controller",
                    "description": "Updated controller description",
                    "process_model_parts": [],
                    "control_actions": [],
                    "feedback_channels": [],
                }
            ]
        )
        client.set_response_for(RevisionDelta, delta)
        original = _make_control_structure()

        revised, warnings = run_revision(
            llm_client=client,
            control_structure=original,
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )

        assert revised == original
        assert any("degrad" in warning.lower() for warning in warnings)
        assert any("renamed-controller" in warning for warning in warnings)


# ---------------------------------------------------------------------------
# RevisionDelta-05: new_controlled_processes are merged
# ---------------------------------------------------------------------------


class TestRevisionDelta05MergeNewCps:
    """RevisionDelta-05: new_controlled_processes are merged into CS."""

    def test_new_cp_merged(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict(
            new_controlled_processes=[{"cp_id": "CP-2", "description": "New process"}]
        )
        client.set_response_for(RevisionDelta, delta)
        cs, _ = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        cp_ids = {cp.cp_id for cp in cs.controlled_processes}
        # The final payload is normalized by list position.  This fixture
        # starts without controlled processes, so the added process is CP-1.
        assert "CP-1" in cp_ids


# ---------------------------------------------------------------------------
# RevisionDelta-06: new_coordination_links are added
# ---------------------------------------------------------------------------


class TestRevisionDelta06MergeNewCoordLinks:
    """RevisionDelta-06: new_coordination_links are added to CS."""

    def test_new_cl_added(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict(
            new_coordination_links=[
                {
                    "link_id": "CL-2",
                    "source": "RESP-1",
                    "target": "RESP-2",
                    "shared_pm": "PM-1-1",
                    "coordination_mechanism": {
                        "cm_id": "CM-2",
                        "description": "New mechanism",
                        "payload": "Payload 2",
                    },
                    "description": "New coordination link",
                }
            ]
        )
        client.set_response_for(RevisionDelta, delta)
        cs, _ = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        cl_ids = {cl.link_id for cl in cs.coordination_links}
        assert "CL-2" in cl_ids


# ---------------------------------------------------------------------------
# RevisionDelta-07: revision_user.j2 contains numbered per-finding checklist
# ---------------------------------------------------------------------------


class TestRevisionDelta07UserPromptChecklist:
    """RevisionDelta-07: revision_user.j2 contains the add-or-dismiss per-finding checklist."""

    def test_template_contains_numbered_list_format(self):
        text = _load_template_text("revision_user.j2")
        # The numbered per-finding list (loop.index) is gone; the per-gap
        # rendering is now a simple for loop over critic_findings.gaps.
        assert "{% for gap in critic_findings.gaps %}" in text
        assert "gap_type" in text
        assert "suggested_remedy" in text


# ---------------------------------------------------------------------------
# RevisionDelta-09: next-available-ID template variables are computed from existing structure
# ---------------------------------------------------------------------------


class TestRevisionDelta09NextAvailableIds:
    """RevisionDelta-09: next-available-ID template variables are computed from existing structure."""

    def test_rendered_prompt_contains_next_numbers(self):
        cs = _make_control_structure()
        # The next-number guidance now lives in revision_system.j2 (not
        # revision_user.j2).  Render the system prompt with the computed
        # next-ID values and verify they appear.
        next_ids = _compute_next_ids(cs)
        rendered = _render_template(
            "revision_system.j2",
            control_structure=cs,
            **next_ids,
        )
        # next_resp_num: RESP-1/RESP-2 -> max=2, next=3
        assert "3" in rendered  # next available responsibility number
        # next_cl_num: CL-1 -> max=1, next=2
        assert "2" in rendered  # next available coordination link number
        # next_cm_num: CM-1 -> max=1, next=2 (lrya bead — unit-level guard)
        assert str(next_ids["next_cm_num"]) in rendered


# ---------------------------------------------------------------------------
# RevisionDelta-10: RevisionDelta merge validates the final ControlStructure
# ---------------------------------------------------------------------------


class TestRevisionDelta10ValidatesFinal:
    """RevisionDelta-10: RevisionDelta merge validates the final ControlStructure."""

    def test_merged_cs_passes_validation(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict(
            new_responsibilities=[
                {
                    "resp_id": "RESP-3",
                    "description": "Input validation controller",
                    "process_model_parts": [
                        {"pm_id": "PM-3-1", "description": "Input state"}
                    ],
                    "control_actions": [
                        {"ca_id": "CA-3-1", "description": "Validate input"}
                    ],
                    "feedback_channels": [
                        {
                            "fb_id": "FB-3-1",
                            "description": "Validation result",
                            "updates": "PM-3-1",
                            "source": {"type": "responsibility", "id": "RESP-3"},
                        }
                    ],
                }
            ]
        )
        client.set_response_for(RevisionDelta, delta)
        cs, _ = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        # If CS was constructed, it passed validation
        assert isinstance(cs, ControlStructure)
        assert len(cs.responsibilities) == 3


class TestRevisionDeltaIdNormalization:
    """Revision deltas are normalized after they are stitched."""

    def test_malformed_delta_ids_are_normalized_after_merge(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict(
            new_responsibilities=[
                {
                    "resp_id": "new-controller",
                    "description": "Added input validation controller",
                    "responsibility_constraints": [
                        {
                            "rc_id": "new-constraint",
                            "description": "Validate input",
                        }
                    ],
                    "process_model_parts": [
                        {
                            "pm_id": "new-state",
                            "description": "Input state",
                            "feedback_source": {
                                "type": "responsibility",
                                "id": "new-controller",
                            },
                        }
                    ],
                    "control_actions": [
                        {
                            "ca_id": "new-action",
                            "description": "Validate input",
                            "target": {
                                "type": "controlled_process",
                                "id": "new-process",
                            },
                        }
                    ],
                    "feedback_channels": [
                        {
                            "fb_id": "new-feedback",
                            "description": "Validation result",
                            "updates": "new-state",
                            "source": {
                                "type": "controlled_process",
                                "id": "new-process",
                            },
                        }
                    ],
                }
            ],
            new_controlled_processes=[
                {"cp_id": "new-process", "description": "Input boundary"}
            ],
            new_coordination_links=[
                {
                    "link_id": "new-link",
                    "source": "new-controller",
                    "target": "RESP-1",
                    "shared_pm": "new-state",
                    "coordination_mechanism": {
                        "cm_id": "new-mechanism",
                        "description": "Synchronize input state",
                        "payload": "input",
                    },
                    "description": "Input coordination",
                }
            ],
        )
        client.set_response_for(RevisionDelta, delta)

        cs, warnings = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )

        added_resp = cs.responsibilities[-1]
        assert added_resp.resp_id == "RESP-3"
        assert added_resp.responsibility_constraints[0].rc_id == "RC-3-1"
        assert added_resp.process_model_parts[0].pm_id == "PM-3-1"
        assert added_resp.control_actions[0].ca_id == "CA-3-1"
        assert added_resp.feedback_channels[0].fb_id == "FB-3-1"
        assert added_resp.process_model_parts[0].feedback_source.id == "RESP-3"
        assert added_resp.control_actions[0].target.id == "CP-1"
        assert added_resp.feedback_channels[0].updates == "PM-3-1"
        assert added_resp.feedback_channels[0].source.id == "CP-1"
        assert cs.controlled_processes[0].cp_id == "CP-1"
        assert cs.coordination_links[-1].link_id == "CL-2"
        assert cs.coordination_links[-1].source == "RESP-3"
        assert cs.coordination_links[-1].shared_pm == "PM-3-1"
        assert cs.coordination_links[-1].coordination_mechanism.cm_id == "CM-2"
        assert not any("failed" in warning.lower() for warning in warnings)
        assert not any("degrad" in warning.lower() for warning in warnings)


# ---------------------------------------------------------------------------
# RevisionDelta-11: strip_empty_responsibilities remains as safety net
# ---------------------------------------------------------------------------


class TestRevisionDelta11StripEmptySafetyNet:
    """RevisionDelta-11: strip_empty_responsibilities remains as safety net."""

    def test_empty_resp_stripped_after_merge(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict(
            new_responsibilities=[
                {
                    "resp_id": "RESP-4",
                    "description": "Empty responsibility",
                    "process_model_parts": [],
                    "control_actions": [],
                    "feedback_channels": [],
                }
            ]
        )
        client.set_response_for(RevisionDelta, delta)
        cs, warnings = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        resp_ids = {r.resp_id for r in cs.responsibilities}
        assert "RESP-4" not in resp_ids
        # A warning should be logged about the stripped empty responsibility
        warning_text = " ".join(warnings)
        assert "RESP-4" in warning_text or "empty" in warning_text.lower()


# ---------------------------------------------------------------------------
# RevisionDelta-12: empty delta preserves existing responsibilities
# ---------------------------------------------------------------------------


class TestRevisionDelta12EmptyDeltaPreserves:
    """RevisionDelta-12: empty delta preserves existing responsibilities."""

    def test_empty_delta_preserves_existing(self, tmp_path):
        client = MockLLMClient()
        delta = _make_revision_delta_dict()
        client.set_response_for(RevisionDelta, delta)
        cs, _ = run_revision(
            llm_client=client,
            control_structure=_make_control_structure(),
            critic_findings=_make_critic_findings(),
            use_case_text="Test",
            run_dir=tmp_path,
        )
        resp_ids = {r.resp_id for r in cs.responsibilities}
        assert "RESP-1" in resp_ids
        assert "RESP-2" in resp_ids
        assert len(cs.responsibilities) == 2


# ---------------------------------------------------------------------------
# RevisionDelta-13: revision_user.j2 checklist includes each gap with required action
# ---------------------------------------------------------------------------


class TestRevisionDelta13ChecklistEachGap:
    """RevisionDelta-13: revision_user.j2 checklist includes each gap with required action."""

    def test_rendered_checklist_includes_all_gaps(self):
        findings = _make_critic_findings()
        rendered = _render_template(
            "revision_user.j2",
            use_case_text="Test",
            control_structure=_make_control_structure(),
            critic_findings=findings,
        )
        assert "missing_responsibility" in rendered
        assert "missing_feedback" in rendered
        assert "Missing input validation" in rendered
        assert "Missing outcome feedback" in rendered
        assert "Add input validation responsibility" in rendered
        assert "Add outcome verification feedback" in rendered
        # Each gap's gap_type appears in the rendered output (per-gap
        # rendering is a for loop, not a numbered list)
        assert rendered.count("missing_responsibility") >= 1
        assert rendered.count("missing_feedback") >= 1


# ---------------------------------------------------------------------------
# Mutation hardening: _compute_next_ids / _next_num_from / _extract_num
# ---------------------------------------------------------------------------


class TestComputeNextIds:
    """Verify _compute_next_ids correctly computes next-available ID numbers."""

    def test_next_ids_from_populated_structure(self):
        """RESP-1/RESP-3 -> next_resp_num=4; CL-1 -> next_cl_num=2."""
        cs = _make_control_structure()
        # RESP-1, RESP-2 -> max=2, next=3
        # CL-1 -> max=1, next=2
        ids = _compute_next_ids(cs)
        assert ids["next_resp_num"] == 3
        assert ids["next_cl_num"] == 2
        # No controlled processes -> next_cp_num=1
        assert ids["next_cp_num"] == 1

    def test_next_ids_from_empty_structure(self):
        """Empty lists -> all next numbers are 1 (via _next_num_from directly)."""
        assert _next_num_from([], lambda x: x) == 1

    def test_next_ids_with_high_numbers(self):
        """RESP-10, RESP-25 -> next_resp_num=26."""
        cs = ControlStructure(
            responsibilities=[
                Responsibility(
                    resp_id="RESP-10",
                    description="A",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-10-1", description="S")
                    ],
                    control_actions=[ControlAction(ca_id="CA-10-1", description="A")],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-10-1",
                            description="F",
                            updates="PM-10-1",
                            source=ElementRef(
                                type=ReferenceType.responsibility, id="RESP-10"
                            ),
                        )
                    ],
                ),
                Responsibility(
                    resp_id="RESP-25",
                    description="B",
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-25-1", description="S")
                    ],
                    control_actions=[ControlAction(ca_id="CA-25-1", description="A")],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-25-1",
                            description="F",
                            updates="PM-25-1",
                            source=ElementRef(
                                type=ReferenceType.responsibility, id="RESP-25"
                            ),
                        )
                    ],
                ),
            ],
        )
        ids = _compute_next_ids(cs)
        assert ids["next_resp_num"] == 26


class TestNextNumFrom:
    """_next_num_from returns the largest numeric suffix plus one, or 1."""

    @pytest.mark.parametrize(
        ("ids", "expected"),
        [
            pytest.param(["X-1", "X-3", "X-2"], 4, id="numeric_ids"),
            pytest.param([], 1, id="empty_list"),
            pytest.param(["X-5", "FOO", "BAR"], 6, id="non_numeric_filtered"),
            pytest.param(["FOO", "BAR"], 1, id="all_non_numeric"),
            pytest.param(["X-7"], 8, id="single_item"),
        ],
    )
    def test_next_number(self, ids, expected):
        items = [{"id": item_id} for item_id in ids]
        assert _next_num_from(items, lambda item: item["id"]) == expected


class TestExtractNum:
    """_extract_num returns the first number in an ID, or None."""

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            pytest.param("RESP-3", 3, id="simple_id"),
            pytest.param("PM-1-2", 1, id="multi_part_takes_first"),
            pytest.param("FOO", None, id="no_number"),
            pytest.param("123abc", 123, id="number_at_start"),
            pytest.param("", None, id="empty_string"),
        ],
    )
    def test_extract(self, text, expected):
        assert _extract_num(text) == expected


# ---------------------------------------------------------------------------
# Mutation hardening: _is_responsibility_empty with partial responsibilities
# ---------------------------------------------------------------------------


class TestIsResponsibilityEmpty:
    """_is_responsibility_empty is True only when PM, CA and FB are all empty."""

    @pytest.mark.parametrize(
        ("with_pm", "with_ca", "with_fb", "with_rc", "expected"),
        [
            pytest.param(False, False, False, False, True, id="all_empty"),
            pytest.param(True, True, True, False, False, id="all_populated"),
            pytest.param(True, False, False, False, False, id="only_pm"),
            pytest.param(False, True, False, False, False, id="only_ca"),
            pytest.param(False, False, True, False, False, id="only_fb"),
            pytest.param(False, False, False, True, True, id="constraints_only"),
        ],
    )
    def test_empty_means_no_pm_ca_or_fb(
        self, with_pm, with_ca, with_fb, with_rc, expected
    ):
        resp = Responsibility(
            resp_id="RESP-1",
            description="Responsibility",
            responsibility_constraints=(
                [ResponsibilityConstraint(rc_id="RC-1-1", description="C")]
                if with_rc
                else []
            ),
            process_model_parts=(
                [ProcessModelPart(pm_id="PM-1-1", description="S")] if with_pm else []
            ),
            control_actions=(
                [ControlAction(ca_id="CA-1-1", description="A")] if with_ca else []
            ),
            feedback_channels=(
                [
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="F",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ]
                if with_fb
                else []
            ),
        )
        assert _is_responsibility_empty(resp) is expected


# ---------------------------------------------------------------------------
# CmDedup-01..14: Duplicate cm_id handling in revision delta merge
# ---------------------------------------------------------------------------


def _make_cs_with_two_cls() -> ControlStructure:
    """Build a CS with RESP-1/RESP-2 and two coordination links CL-1/CM-1, CL-2/CM-2."""
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller 1",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="State 1")
                ],
                control_actions=[ControlAction(ca_id="CA-1-1", description="Action 1")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="FB 1",
                        updates="PM-1-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        ),
                    )
                ],
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Controller 2",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-2-1", description="State 2")
                ],
                control_actions=[ControlAction(ca_id="CA-2-1", description="Action 2")],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1",
                        description="FB 2",
                        updates="PM-2-1",
                        source=ElementRef(
                            type=ReferenceType.responsibility, id="RESP-2"
                        ),
                    )
                ],
            ),
        ],
        coordination_links=[
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-2-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1",
                    description="Shared state",
                    payload="Payload",
                ),
                description="Coordination link 1",
            ),
            CoordinationLink(
                link_id="CL-2",
                source="RESP-2",
                target="RESP-1",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-2",
                    description="Shared state 2",
                    payload="Payload 2",
                ),
                description="Coordination link 2",
            ),
        ],
    )


def _cl_dict(
    link_id: str,
    cm_id: str,
    *,
    source: str = "RESP-1",
    target: str = "RESP-2",
    shared_pm: str = "PM-1-1",
    description: str = "shared validation",
    payload: str = "sync",
    mech_desc: str = "Shared state",
) -> dict:
    """Build a coordination link dict for RevisionDelta."""
    return {
        "link_id": link_id,
        "source": source,
        "target": target,
        "shared_pm": shared_pm,
        "coordination_mechanism": {
            "cm_id": cm_id,
            "description": mech_desc,
            "payload": payload,
        },
        "description": description,
    }


def _run_rev(tmp_path, delta_dict):
    """Helper: run revision with two-CL fixture and return (cs, warnings)."""
    client = MockLLMClient()
    client.set_response_for(RevisionDelta, delta_dict)
    return run_revision(
        llm_client=client,
        control_structure=_make_cs_with_two_cls(),
        critic_findings=_make_critic_findings(),
        use_case_text="Test",
        run_dir=tmp_path,
    )


def _make_degradation_delta() -> dict:
    """Build a delta whose new responsibility has an unresolved reference.

    The revision normalizer deliberately repairs duplicate source IDs, so
    an unresolved reference is used here to exercise the degradation guard
    after normalization.
    """
    return _make_revision_delta_dict(
        new_responsibilities=[
            {
                "resp_id": "RESP-3",
                "description": "Dup PM",
                "process_model_parts": [{"pm_id": "PM-3-1", "description": "State"}],
                "control_actions": [{"ca_id": "CA-3-1", "description": "Act"}],
                "feedback_channels": [
                    {
                        "fb_id": "FB-3-1",
                        "description": "FB",
                        "updates": "missing-pm",
                        "source": {"type": "responsibility", "id": "RESP-3"},
                    }
                ],
            }
        ]
    )


def _make_multi_collision_delta() -> dict:
    """Build a delta with two new links whose cm_ids collide with existing ones."""
    return _make_revision_delta_dict(
        new_coordination_links=[
            _cl_dict("CL-3", "CM-1"),
            _cl_dict(
                "CL-4", "CM-2", source="RESP-2", target="RESP-1", shared_pm="PM-2-1"
            ),
        ]
    )


def _cl_by_id(cs: ControlStructure, link_id: str) -> CoordinationLink:
    return next(cl for cl in cs.coordination_links if cl.link_id == link_id)


def _cm_ids(cs: ControlStructure) -> list[str]:
    return [cl.coordination_mechanism.cm_id for cl in cs.coordination_links]


class TestCmDedupRenumbering:
    """A new link whose cm_id collides is renumbered to the next free CM-N."""

    def test_airbnb_regression_new_link_reusing_cm1_is_renumbered(self, tmp_path):
        """CL-1/CM-1 and CL-2/CM-2 exist; the revision adds CL-3 with CM-1."""
        delta = _make_revision_delta_dict(
            new_coordination_links=[_cl_dict("CL-3", "CM-1")]
        )
        cs, _ = _run_rev(tmp_path, delta)

        assert isinstance(cs, ControlStructure)
        assert _cl_by_id(cs, "CL-1").coordination_mechanism.cm_id == "CM-1"
        assert _cl_by_id(cs, "CL-2").coordination_mechanism.cm_id == "CM-2"
        assert _cl_by_id(cs, "CL-3").coordination_mechanism.cm_id == "CM-3"
        assert len(_cm_ids(cs)) == len(set(_cm_ids(cs)))
        assert all(re.match(r"^CM-\d+$", cm_id) for cm_id in _cm_ids(cs))

    def test_renumbering_keeps_link_content_and_warns(self, tmp_path):
        delta = _make_revision_delta_dict(
            new_coordination_links=[_cl_dict("CL-3", "CM-1")]
        )
        cs, warnings = _run_rev(tmp_path, delta)

        cl3 = _cl_by_id(cs, "CL-3")
        assert cl3.source == "RESP-1"
        assert cl3.target == "RESP-2"
        assert cl3.shared_pm == "PM-1-1"
        assert cl3.description == "shared validation"
        assert cl3.coordination_mechanism.payload == "sync"
        wtext = " ".join(warnings)
        assert "CM-1" in wtext
        assert "CL-3" in wtext

    def test_multiple_collisions_are_each_renumbered(self, tmp_path):
        cs, _ = _run_rev(tmp_path, _make_multi_collision_delta())

        cm3 = _cl_by_id(cs, "CL-3").coordination_mechanism.cm_id
        cm4 = _cl_by_id(cs, "CL-4").coordination_mechanism.cm_id
        assert cm3 != "CM-1"
        assert cm4 != "CM-2"
        assert cm3 != cm4
        assert len(_cm_ids(cs)) == len(set(_cm_ids(cs)))

    def test_unique_cm_id_is_kept_without_warnings(self, tmp_path):
        delta = _make_revision_delta_dict(
            new_coordination_links=[_cl_dict("CL-3", "CM-3")]
        )
        cs, warnings = _run_rev(tmp_path, delta)

        assert _cl_by_id(cs, "CL-3").coordination_mechanism.cm_id == "CM-3"
        assert not any("Renumber" in w for w in warnings)
        assert not any("degrad" in w.lower() for w in warnings)


class TestCmDedupNestedPmIdCollision:
    """A merge that fails validation degrades to the pre-revision structure."""

    def test_nested_pm_id_collision_falls_back_and_warns(self, tmp_path):
        cs, warnings = _run_rev(tmp_path, _make_degradation_delta())

        assert isinstance(cs, ControlStructure)
        assert {r.resp_id for r in cs.responsibilities} == {"RESP-1", "RESP-2"}
        assert {cl.link_id for cl in cs.coordination_links} == {"CL-1", "CL-2"}
        wtext = " ".join(warnings)
        assert any("degrad" in w.lower() for w in warnings)
        assert "revision delta merge" in wtext.lower()
        assert "ValidationError" in wtext or "ValueError" in wtext


# ---------------------------------------------------------------------------
# Mutation hardening: direct unit tests for _next_free_cm_id
# ---------------------------------------------------------------------------


class TestNextFreeCmId:
    """_next_free_cm_id returns CM-(max numeric suffix + 1)."""

    @pytest.mark.parametrize(
        ("used", "expected"),
        [
            pytest.param(set(), "CM-1", id="empty_set"),
            pytest.param({"CM-1"}, "CM-2", id="single"),
            pytest.param({"CM-1", "CM-3", "CM-5"}, "CM-6", id="max_plus_one"),
            pytest.param({"FOO", "BAR"}, "CM-1", id="non_numeric_filtered"),
            pytest.param({"CM-2", "FOO"}, "CM-3", id="mixed"),
            pytest.param({"CM-99"}, "CM-100", id="high_number"),
        ],
    )
    def test_next_free(self, used, expected):
        assert _next_free_cm_id(used) == expected


# ---------------------------------------------------------------------------
# Mutation hardening: direct unit tests for _renumber_colliding_cm_ids
# ---------------------------------------------------------------------------


def _make_cl(link_id: str, cm_id: str) -> CoordinationLink:
    """Build a minimal CoordinationLink for renumber tests."""
    return CoordinationLink(
        link_id=link_id,
        source="RESP-1",
        target="RESP-2",
        shared_pm="PM-1-1",
        coordination_mechanism=CoordinationMechanism(
            cm_id=cm_id,
            description="Mechanism",
            payload="Payload",
        ),
        description="Link",
    )


class TestRenumberCollidingCmIds:
    """Direct unit tests for _renumber_colliding_cm_ids."""

    def test_existing_links_not_modified(self):
        """Existing links keep their cm_ids (the link_id membership guard)."""
        existing = [_make_cl("CL-1", "CM-1"), _make_cl("CL-2", "CM-2")]
        merged = [
            _make_cl("CL-1", "CM-1"),
            _make_cl("CL-2", "CM-2"),
            _make_cl("CL-3", "CM-3"),
        ]
        result, warnings = _renumber_colliding_cm_ids(existing, merged)
        cl1 = next(cl for cl in result if cl.link_id == "CL-1")
        cl2 = next(cl for cl in result if cl.link_id == "CL-2")
        assert cl1.coordination_mechanism.cm_id == "CM-1"
        assert cl2.coordination_mechanism.cm_id == "CM-2"
        assert warnings == []

    def test_new_link_with_duplicate_cm_id_is_renumbered(self):
        """New link whose cm_id collides with existing is renumbered."""
        existing = [_make_cl("CL-1", "CM-1")]
        merged = [_make_cl("CL-1", "CM-1"), _make_cl("CL-2", "CM-1")]
        result, warnings = _renumber_colliding_cm_ids(existing, merged)
        cl2 = next(cl for cl in result if cl.link_id == "CL-2")
        assert cl2.coordination_mechanism.cm_id == "CM-2"
        assert len(warnings) == 1
        assert "CM-1" in warnings[0]
        assert "CL-2" in warnings[0]

    def test_new_link_with_unique_cm_id_not_renumbered(self):
        """New link with unique cm_id is left unchanged."""
        existing = [_make_cl("CL-1", "CM-1")]
        merged = [_make_cl("CL-1", "CM-1"), _make_cl("CL-2", "CM-3")]
        result, warnings = _renumber_colliding_cm_ids(existing, merged)
        cl2 = next(cl for cl in result if cl.link_id == "CL-2")
        assert cl2.coordination_mechanism.cm_id == "CM-3"
        assert warnings == []

    def test_new_vs_new_collision_is_detected(self):
        """Two new links with the same cm_id: second one is renumbered.

        This exercises the else-branch ``used_cm_ids.add(cm_id)`` —
        the first new link's cm_id is added to used_cm_ids, so the
        second new link's same cm_id triggers renumbering.
        """
        existing = [_make_cl("CL-1", "CM-1")]
        merged = [
            _make_cl("CL-1", "CM-1"),
            _make_cl("CL-2", "CM-5"),
            _make_cl("CL-3", "CM-5"),
        ]
        result, warnings = _renumber_colliding_cm_ids(existing, merged)
        cl2 = next(cl for cl in result if cl.link_id == "CL-2")
        cl3 = next(cl for cl in result if cl.link_id == "CL-3")
        assert cl2.coordination_mechanism.cm_id == "CM-5"
        assert cl3.coordination_mechanism.cm_id != "CM-5"
        assert cl3.coordination_mechanism.cm_id == "CM-6"
        assert len(warnings) == 1
        assert "CL-3" in warnings[0]

    def test_multiple_collisions_each_renumbered_uniquely(self):
        """Multiple new links each colliding get unique renumbered cm_ids.

        This exercises the ``used_cm_ids.add(new_cm_id)`` after
        renumbering — without it, two colliding links could be
        renumbered to the same ID.
        """
        existing = [_make_cl("CL-1", "CM-1"), _make_cl("CL-2", "CM-2")]
        merged = [
            _make_cl("CL-1", "CM-1"),
            _make_cl("CL-2", "CM-2"),
            _make_cl("CL-3", "CM-1"),
            _make_cl("CL-4", "CM-1"),
        ]
        result, warnings = _renumber_colliding_cm_ids(existing, merged)
        cl3 = next(cl for cl in result if cl.link_id == "CL-3")
        cl4 = next(cl for cl in result if cl.link_id == "CL-4")
        assert cl3.coordination_mechanism.cm_id != "CM-1"
        assert cl4.coordination_mechanism.cm_id != "CM-1"
        assert cl3.coordination_mechanism.cm_id != cl4.coordination_mechanism.cm_id
        assert len(warnings) == 2

    def test_no_existing_links_all_new_unique(self):
        """No existing links, all new links have unique cm_ids -> no renumber."""
        existing: list[CoordinationLink] = []
        merged = [_make_cl("CL-1", "CM-1"), _make_cl("CL-2", "CM-2")]
        result, warnings = _renumber_colliding_cm_ids(existing, merged)
        cl1 = next(cl for cl in result if cl.link_id == "CL-1")
        cl2 = next(cl for cl in result if cl.link_id == "CL-2")
        assert cl1.coordination_mechanism.cm_id == "CM-1"
        assert cl2.coordination_mechanism.cm_id == "CM-2"
        assert warnings == []

    def test_no_existing_links_new_vs_new_collision(self):
        """No existing links but two new links share a cm_id -> second renumbered."""
        existing: list[CoordinationLink] = []
        merged = [_make_cl("CL-1", "CM-1"), _make_cl("CL-2", "CM-1")]
        result, warnings = _renumber_colliding_cm_ids(existing, merged)
        cl1 = next(cl for cl in result if cl.link_id == "CL-1")
        cl2 = next(cl for cl in result if cl.link_id == "CL-2")
        assert cl1.coordination_mechanism.cm_id == "CM-1"
        assert cl2.coordination_mechanism.cm_id == "CM-2"
        assert len(warnings) == 1
        assert "CL-2" in warnings[0]

    def test_renumbered_cm_id_conforms_to_format(self):
        """Renumbered cm_id matches ^CM-\\d+$."""
        existing = [_make_cl("CL-1", "CM-1")]
        merged = [_make_cl("CL-1", "CM-1"), _make_cl("CL-2", "CM-1")]
        result, _ = _renumber_colliding_cm_ids(existing, merged)
        cl2 = next(cl for cl in result if cl.link_id == "CL-2")
        assert re.match(r"^CM-\d+$", cl2.coordination_mechanism.cm_id)

    def test_non_cm_id_content_preserved_after_renumber(self):
        """Renumbering only changes cm_id, not other link fields."""
        existing = [_make_cl("CL-1", "CM-1")]
        new_cl = CoordinationLink(
            link_id="CL-2",
            source="RESP-2",
            target="RESP-1",
            shared_pm="PM-2-1",
            coordination_mechanism=CoordinationMechanism(
                cm_id="CM-1",
                description="Unique mechanism",
                payload="Unique payload",
            ),
            description="Unique link",
        )
        merged = [_make_cl("CL-1", "CM-1"), new_cl]
        result, _ = _renumber_colliding_cm_ids(existing, merged)
        cl2 = next(cl for cl in result if cl.link_id == "CL-2")
        assert cl2.source == "RESP-2"
        assert cl2.target == "RESP-1"
        assert cl2.shared_pm == "PM-2-1"
        assert cl2.description == "Unique link"
        assert cl2.coordination_mechanism.description == "Unique mechanism"
        assert cl2.coordination_mechanism.payload == "Unique payload"
        assert cl2.coordination_mechanism.cm_id != "CM-1"
