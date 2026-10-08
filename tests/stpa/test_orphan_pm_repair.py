"""Unit tests for SP1 orphan PM repair and PM-FB correspondence.

Covers SP1-PMFB-01 through SP1-PMFB-13. Tests verify that:
- The Call 2a system and user prompts enforce 1:1 PM-FB correspondence.
- ``repair_orphan_pms`` finds orphan PM parts (no FB referencing them)
  and auto-generates stub FB channels.
- Repair is called after Call 2a/2b assembly and before Call 3 in
  ``derive_control_structure``.
"""

from __future__ import annotations

from unittest.mock import patch

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    CoordinationAnalysis,
    RequirementSet,
    ResponsibilitySet,
    _extract_resp_num,
    repair_orphan_pms,
    derive_control_structure,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from tests.stpa.sp1_helpers import MockLLMClient, valid_empty_coordination_analysis_dict


# ---------------------------------------------------------------------------
# Prompt content tests (SP1-PMFB-01, SP1-PMFB-02, SP1-PMFB-03)
# ---------------------------------------------------------------------------


class TestCall2aPromptPMFBCorrespondence:
    """SP1-PMFB-01 through SP1-PMFB-03: prompt enforces PM-FB 1:1."""

    def test_pmfb_01_system_prompt_requires_pm_fb_correspondence(self):
        """SP1-PMFB-01: system prompt requires PM-FB correspondence."""
        loader = TemplateLoader(PROMPTS_DIR)
        text = loader.render_prompt("stage2_call2b_system.j2")
        assert (
            "Every process model part (PM-X-Y) MUST have at least one feedback channel"
            in text
        )
        assert "updates` field references that PM" in text
        assert "No orphan PMs" in text

    def test_pmfb_02_system_prompt_requires_n_fbs_for_n_pms(self):
        """SP1-PMFB-02: system prompt requires N FBs for N PMs."""
        loader = TemplateLoader(PROMPTS_DIR)
        text = loader.render_prompt("stage2_call2b_system.j2")
        assert (
            "If a responsibility has N process model parts, it must have at least N feedback channels"
            in text
        )

    def test_pmfb_03_user_prompt_strengthens_step_5(self):
        """SP1-PMFB-03: user prompt strengthens step 5 with one FB per PM."""
        loader = TemplateLoader(PROMPTS_DIR)
        text = loader.render_prompt(
            "stage2_call2b_user.j2",
            use_case_text="Test",
            responsibilities=[],
        )
        assert "Every PM-X-Y must appear in at least one FB" in text
        assert "every PM-X-Y listed above has at least one corresponding FB" in text


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------


def _make_resp(
    resp_id: str,
    pm_ids: list[str],
    fb_specs: list[tuple[str, str]] | None = None,
    with_ca: bool = True,
) -> Responsibility:
    """Build a responsibility with PMs and optional FB channels.

    Args:
        resp_id: e.g. "RESP-1".
        pm_ids: list of PM IDs, e.g. ["PM-1-1", "PM-1-2"].
        fb_specs: list of (fb_id, updates_pm_id) tuples. If None, no FBs.
        with_ca: add a single CA so validation passes.
    """
    num = resp_id.split("-")[-1]
    pms = [ProcessModelPart(pm_id=pid, description=f"State {pid}") for pid in pm_ids]
    cas = [ControlAction(ca_id=f"CA-{num}-1", description="Action")] if with_ca else []
    fbs = []
    if fb_specs:
        for fb_id, updates in fb_specs:
            fbs.append(
                FeedbackChannel(
                    fb_id=fb_id,
                    description=f"FB {fb_id}",
                    updates=updates,
                )
            )
    return Responsibility(
        resp_id=resp_id,
        description=f"Controller {num}",
        process_model_parts=pms,
        control_actions=cas,
        feedback_channels=fbs,
    )


def _make_cs(responsibilities: list[Responsibility]) -> ControlStructure:
    """Build a ControlStructure from a list of responsibilities."""
    return ControlStructure(responsibilities=responsibilities)


# ---------------------------------------------------------------------------
# repair_orphan_pms tests (SP1-PMFB-04 through SP1-PMFB-12)
# ---------------------------------------------------------------------------


class TestRepairOrphanPMs:
    """SP1-PMFB-04 through SP1-PMFB-12."""

    def test_pmfb_04_finds_orphan_pm_with_no_fb(self):
        """SP1-PMFB-04: orphan PM with no FB referencing it gets a stub FB."""
        resp = _make_resp(
            "RESP-1",
            ["PM-1-1", "PM-1-2"],
            fb_specs=[("FB-1-1", "PM-1-1")],
        )
        cs = _make_cs([resp])
        repaired, warnings = repair_orphan_pms(cs)
        r0 = repaired.responsibilities[0]
        updated_pms = {fb.updates for fb in r0.feedback_channels}
        assert "PM-1-2" in updated_pms

    def test_pmfb_05_generates_correct_fb_id(self):
        """SP1-PMFB-05: stub FB gets the next available FB number."""
        resp = _make_resp(
            "RESP-2",
            ["PM-2-1"],
            fb_specs=[("FB-2-1", "PM-2-1")],
        )
        # Add an orphan PM
        resp.process_model_parts.append(
            ProcessModelPart(pm_id="PM-2-2", description="Orphan")
        )
        cs = _make_cs([resp])
        repaired, _ = repair_orphan_pms(cs)
        r0 = repaired.responsibilities[0]
        fb_ids = {fb.fb_id for fb in r0.feedback_channels}
        assert "FB-2-2" in fb_ids

    def test_pmfb_06_description_indicates_auto_generation(self):
        """SP1-PMFB-06: stub FB description contains 'Auto-generated feedback for orphan PM'."""
        resp = _make_resp(
            "RESP-1", ["PM-1-1", "PM-1-3"], fb_specs=[("FB-1-1", "PM-1-1")]
        )
        cs = _make_cs([resp])
        repaired, _ = repair_orphan_pms(cs)
        r0 = repaired.responsibilities[0]
        stub = [fb for fb in r0.feedback_channels if fb.updates == "PM-1-3"][0]
        assert "Auto-generated feedback for orphan PM-1-3" in stub.description

    def test_pmfb_07_updates_references_orphan_pm(self):
        """SP1-PMFB-07: stub FB updates field equals the orphan PM id."""
        resp = _make_resp(
            "RESP-1", ["PM-1-1", "PM-1-2"], fb_specs=[("FB-1-1", "PM-1-1")]
        )
        cs = _make_cs([resp])
        repaired, _ = repair_orphan_pms(cs)
        r0 = repaired.responsibilities[0]
        stub = [fb for fb in r0.feedback_channels if fb.updates == "PM-1-2"][0]
        assert stub.updates == "PM-1-2"

    def test_pmfb_08_no_orphans_means_no_changes(self):
        """SP1-PMFB-08: no orphan PMs means no changes and no warnings."""
        resp = _make_resp(
            "RESP-1",
            ["PM-1-1", "PM-1-2"],
            fb_specs=[("FB-1-1", "PM-1-1"), ("FB-1-2", "PM-1-2")],
        )
        cs = _make_cs([resp])
        repaired, warnings = repair_orphan_pms(cs)
        assert len(warnings) == 0
        r0 = repaired.responsibilities[0]
        assert len(r0.feedback_channels) == 2

    def test_pmfb_09_returns_warning_for_each_orphan(self):
        """SP1-PMFB-09: repair returns a warning for each repaired orphan."""
        resp = _make_resp(
            "RESP-1",
            ["PM-1-1", "PM-1-2", "PM-1-3"],
            fb_specs=[("FB-1-1", "PM-1-1")],
        )
        cs = _make_cs([resp])
        repaired, warnings = repair_orphan_pms(cs)
        assert len(warnings) == 2
        for w in warnings:
            assert "PM-1-2" in w or "PM-1-3" in w

    def test_pmfb_10_multiple_orphans_get_sequential_fb_numbers(self):
        """SP1-PMFB-10: multiple orphans in same resp get sequential FB numbers."""
        resp = _make_resp("RESP-3", ["PM-3-1", "PM-3-2"], fb_specs=None)
        cs = _make_cs([resp])
        repaired, _ = repair_orphan_pms(cs)
        r0 = repaired.responsibilities[0]
        fb_ids = {fb.fb_id for fb in r0.feedback_channels}
        assert "FB-3-1" in fb_ids
        assert "FB-3-2" in fb_ids

    def test_pmfb_11_orphans_across_multiple_resps_all_repaired(self):
        """SP1-PMFB-11: orphans across multiple responsibilities are all repaired."""
        resp1 = _make_resp(
            "RESP-1", ["PM-1-1", "PM-1-2"], fb_specs=[("FB-1-1", "PM-1-1")]
        )
        resp2 = _make_resp("RESP-2", ["PM-2-1"], fb_specs=None)
        cs = _make_cs([resp1, resp2])
        repaired, _ = repair_orphan_pms(cs)
        r0 = repaired.responsibilities[0]
        r1 = repaired.responsibilities[1]
        updated_0 = {fb.updates for fb in r0.feedback_channels}
        updated_1 = {fb.updates for fb in r1.feedback_channels}
        assert "PM-1-2" in updated_0
        assert "PM-2-1" in updated_1

    def test_pmfb_12_repaired_set_has_no_orphan_pms(self):
        """SP1-PMFB-12: after repair, every PM is referenced by at least one FB."""
        resp1 = _make_resp(
            "RESP-1", ["PM-1-1", "PM-1-2"], fb_specs=[("FB-1-1", "PM-1-1")]
        )
        resp2 = _make_resp(
            "RESP-2", ["PM-2-1", "PM-2-2"], fb_specs=[("FB-2-1", "PM-2-1")]
        )
        cs = _make_cs([resp1, resp2])
        repaired, _ = repair_orphan_pms(cs)
        for resp in repaired.responsibilities:
            updated_pms = {fb.updates for fb in resp.feedback_channels}
            for pm in resp.process_model_parts:
                assert pm.pm_id in updated_pms

    def test_pmfb_12b_stub_fb_reuses_existing_source(self):
        """Stub FB reuses an existing feedback channel's source reference.

        Guards against the ``fb.source is not None`` → ``fb.source is None``
        mutation in ``_create_stub_fb``.
        """
        existing_source = ElementRef(type=ReferenceType.responsibility, id="RESP-1")
        resp = Responsibility(
            resp_id="RESP-1",
            description="Controller 1",
            process_model_parts=[
                ProcessModelPart(pm_id="PM-1-1", description="State 1"),
                ProcessModelPart(pm_id="PM-1-2", description="Orphan"),
            ],
            control_actions=[ControlAction(ca_id="CA-1-1", description="Action")],
            feedback_channels=[
                FeedbackChannel(
                    fb_id="FB-1-1",
                    description="FB 1",
                    updates="PM-1-1",
                    source=existing_source,
                ),
            ],
        )
        cs = _make_cs([resp])
        repaired, _ = repair_orphan_pms(cs)
        r0 = repaired.responsibilities[0]
        stub = [fb for fb in r0.feedback_channels if fb.updates == "PM-1-2"][0]
        assert stub.source is not None
        assert stub.source == existing_source

    def test_pmfb_12c_extract_resp_num_defaults_to_zero(self):
        """_extract_resp_num returns 0 (not 1) for a resp_id with no digits.

        Guards against the ``0 → 1`` default-value mutation.
        The ``else 0`` branch handles malformed resp_ids that bypass
        Pydantic validation (e.g. from deserialized JSON).
        """
        assert _extract_resp_num("RESP-abc") == 0
        assert _extract_resp_num("RESP-") == 0
        assert _extract_resp_num("") == 0


# ---------------------------------------------------------------------------
# Integration test (SP1-PMFB-13)
# ---------------------------------------------------------------------------


class TestRepairCalledInDeriveControlStructure:
    """SP1-PMFB-13: repair is called after Call 2a/2b assembly and before Call 3."""

    def test_pmfb_13_repair_called_between_call2_and_call3(self, tmp_path):
        """SP1-PMFB-13: repair_orphan_pms is called after assembly, before Call 3."""

        # Mock LLM responses for Call 1, Call 2a, Call 2b, Call 3
        client = MockLLMClient()

        # Call 1: Requirements
        client.set_response_for(
            RequirementSet,
            {
                "requirements": [
                    {
                        "req_id": "REQ-1",
                        "description": "Validate input",
                        "classification": "control",
                        "source_constraint": "SC-1",
                    }
                ]
            },
        )

        # Call 2a: Responsibilities with an orphan PM (no CAs/FBs)
        client.set_response_for(
            ResponsibilitySet,
            {
                "responsibilities": [
                    {
                        "resp_id": "RESP-1",
                        "description": "Controller 1",
                        "security_constraint_refs": [],
                        "process_model_parts": [
                            {"pm_id": "PM-1-1", "description": "State 1"},
                            {"pm_id": "PM-1-2", "description": "Orphan state"},
                        ],
                    }
                ],
            },
        )

        # Call 2b: strict responses must explicitly cover every PM, so the
        # repair hook is exercised as a no-op for this complete response.
        client.set_response_for(
            ControlElementSet,
            {
                "control_actions": [
                    {
                        "ca_id": "CA-1-1",
                        "description": "Action 1",
                        "target": {"type": "responsibility", "id": "RESP-1"},
                    }
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-1-1",
                        "description": "FB 1",
                        "updates": "PM-1-1",
                        "source": {"type": "responsibility", "id": "RESP-1"},
                    },
                    {
                        "fb_id": "FB-1-2",
                        "description": "FB 2",
                        "updates": "PM-1-2",
                        "source": {"type": "responsibility", "id": "RESP-1"},
                    },
                ],
                "controlled_processes": [],
            },
        )

        # Call 3: Empty coordination analysis
        client.set_response_for(
            CoordinationAnalysis,
            valid_empty_coordination_analysis_dict(),
        )

        loss_analysis = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=[
                Loss(
                    loss_id="L-1",
                    description="Loss",
                    provenance=LossProvenance.use_case,
                )
            ],
            hazards=[
                Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"]),
            ],
            security_constraints=[
                SecurityConstraint(
                    constraint_id="SC-1", rule="C", related_hazards=["H-1"]
                ),
            ],
        )

        with patch(
            "asago_scenario_generator.stpa.system_model.control_structure.repair_orphan_pms",
            wraps=repair_orphan_pms,
        ) as mock_repair:
            derive_control_structure(
                llm_client=client,
                use_case_text="Test use case",
                loss_analysis=loss_analysis,
                run_dir=tmp_path,
            )
            mock_repair.assert_called_once()
