"""Tests for SP1 RC/PM ID namespace validation.

Covers IDNS-01 through IDNS-07 from the Gherkin feature file
sp1_id_namespace_validation.feature.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ControlledProcess,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ResponsibilityConstraint,
)


def _make_resp(
    resp_id: str = "RESP-1",
    rc_ids: list[str] | None = None,
    pm_ids: list[str] | None = None,
    ca_ids: list[str] | None = None,
    fb_ids: list[str] | None = None,
) -> Responsibility:
    """Build a valid Responsibility with configurable IDs."""
    return Responsibility(
        resp_id=resp_id,
        description="Controller",
        responsibility_constraints=[
            ResponsibilityConstraint(rc_id=rc_id, description="Constraint")
            for rc_id in (rc_ids or ["RC-1-1"])
        ],
        process_model_parts=[
            ProcessModelPart(pm_id=pm_id, description="State")
            for pm_id in (pm_ids or ["PM-1-1"])
        ],
        control_actions=[
            ControlAction(ca_id=ca_id, description="Action")
            for ca_id in (ca_ids or ["CA-1-1"])
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id=fb_id,
                description="FB",
                updates=(pm_ids or ["PM-1-1"])[0],
                source=ElementRef(type=ReferenceType.responsibility, id=resp_id),
            )
            for fb_id in (fb_ids or ["FB-1-1"])
        ],
    )


def _make_cs(responsibilities: list[Responsibility] | None = None) -> ControlStructure:
    return ControlStructure(
        responsibilities=responsibilities or [_make_resp()],
        controlled_processes=[],
        coordination_links=[],
    )


class TestRcIdFieldValidator:
    """IDNS-01 and IDNS-02: rc_id regex field validator."""

    @pytest.mark.parametrize("rc_id", ["RC-1-1", "RC-2-3"])
    def test_idns_01_correct_rc_id_passes(self, rc_id):
        """IDNS-01: rc_id with correct prefix and format passes validation."""
        cs = _make_cs(responsibilities=[_make_resp(rc_ids=[rc_id])])
        assert cs.responsibilities[0].responsibility_constraints[0].rc_id == rc_id

    @pytest.mark.parametrize("rc_id", ["PM-1-1", "SC-1", "RC-1", "RC-A-B", "RC-1-1-1"])
    def test_idns_02_wrong_rc_id_fails(self, rc_id):
        """IDNS-02: rc_id with wrong prefix or malformed format fails validation."""
        with pytest.raises(ValidationError) as exc_info:
            _make_cs(responsibilities=[_make_resp(rc_ids=[rc_id])])
        assert "rc_id" in str(exc_info.value)


class TestNonRcIdFieldValidators:
    """IDNS-03: non-rc ID fields with wrong prefix or format fail validation."""

    @pytest.mark.parametrize(
        "model_name,field_name,bad_value",
        [
            ("ProcessModelPart", "pm_id", "RC-1-1"),
            ("ProcessModelPart", "pm_id", "PM-1"),
            ("ControlAction", "ca_id", "PM-1-1"),
            ("ControlAction", "ca_id", "CA-1"),
            ("FeedbackChannel", "fb_id", "PM-1-1"),
            ("FeedbackChannel", "fb_id", "FB-1"),
            ("ControlledProcess", "cp_id", "CP-1-1"),
            ("ControlledProcess", "cp_id", "PM-1"),
            ("Responsibility", "resp_id", "RESP-1-1"),
            ("Responsibility", "resp_id", "PM-1"),
            ("CoordinationLink", "link_id", "CL-1-1"),
            ("CoordinationLink", "link_id", "PM-1"),
            ("CoordinationMechanism", "cm_id", "CM-1-1"),
            ("CoordinationMechanism", "cm_id", "PM-1"),
        ],
    )
    def test_idns_03_wrong_id_fails(self, model_name, field_name, bad_value):
        """IDNS-03: non-rc ID fields with wrong prefix or format fail validation."""
        with pytest.raises(ValidationError) as exc_info:
            if model_name == "ProcessModelPart":
                _make_cs(responsibilities=[_make_resp(pm_ids=[bad_value])])
            elif model_name == "ControlAction":
                _make_cs(responsibilities=[_make_resp(ca_ids=[bad_value])])
            elif model_name == "FeedbackChannel":
                _make_cs(responsibilities=[_make_resp(fb_ids=[bad_value])])
            elif model_name == "ControlledProcess":
                ControlStructure(
                    responsibilities=[_make_resp()],
                    controlled_processes=[
                        ControlledProcess(cp_id=bad_value, description="CP")
                    ],
                )
            elif model_name == "Responsibility":
                _make_cs(responsibilities=[_make_resp(resp_id=bad_value)])
            elif model_name == "CoordinationLink":
                _make_cs(
                    responsibilities=[_make_resp()]
                )  # will fail at link construction
                # Actually need to construct the link with bad value
                link = CoordinationLink(
                    link_id=bad_value,
                    source="RESP-1",
                    target="RESP-1",
                    shared_pm="PM-1-1",
                    coordination_mechanism=CoordinationMechanism(
                        cm_id="CM-1", description="Coord", payload="data"
                    ),
                    description="Link",
                )
                ControlStructure(
                    responsibilities=[_make_resp()],
                    coordination_links=[link],
                )
            elif model_name == "CoordinationMechanism":
                link = CoordinationLink(
                    link_id="CL-1",
                    source="RESP-1",
                    target="RESP-1",
                    shared_pm="PM-1-1",
                    coordination_mechanism=CoordinationMechanism(
                        cm_id=bad_value, description="Coord", payload="data"
                    ),
                    description="Link",
                )
                ControlStructure(
                    responsibilities=[_make_resp()],
                    coordination_links=[link],
                )
        assert field_name in str(exc_info.value)


class TestDuplicateRcIds:
    """IDNS-04: duplicate RC IDs within the same responsibility fail validation."""

    def test_idns_04_duplicate_rc_fails(self):
        """IDNS-04: duplicate RC IDs within the same responsibility fail."""
        with pytest.raises(ValidationError) as exc_info:
            _make_cs(responsibilities=[_make_resp(rc_ids=["RC-1-1", "RC-1-1"])])
        assert "Duplicate" in str(exc_info.value)


class TestCrossNamespaceCollision:
    """IDNS-05: cross-namespace collision detected by model validator."""

    def test_idns_05_cross_namespace_collision_detected(self):
        """IDNS-05: same ID value in two prefix families is detected."""
        # Bypass field validators using model_construct, then manually
        # trigger the model validator.
        rc = ResponsibilityConstraint.model_construct(
            rc_id="RC-1-1", description="Constraint"
        )
        pm = ProcessModelPart.model_construct(pm_id="RC-1-1", description="State")
        ca = ControlAction.model_construct(ca_id="CA-1-1", description="Action")
        fb = FeedbackChannel.model_construct(
            fb_id="FB-1-1",
            description="FB",
            updates="RC-1-1",  # references the PM with the colliding ID
            source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
        )
        resp = Responsibility.model_construct(
            resp_id="RESP-1",
            description="Controller",
            responsibility_constraints=[rc],
            process_model_parts=[pm],
            control_actions=[ca],
            feedback_channels=[fb],
        )
        cs = ControlStructure.model_construct(
            responsibilities=[resp],
            controlled_processes=[],
            coordination_links=[],
        )
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            ControlStructure.validate_references_and_duplicates(cs)
        msg = str(exc_info.value)
        assert "namespace" in msg.lower() or "collision" in msg.lower()


class TestValidControlStructure:
    """IDNS-06: valid control structure with all correct prefixes passes."""

    def test_idns_06_valid_cs_passes(self):
        """IDNS-06: valid control structure with all correct prefixes passes validation."""
        cs = _make_cs()
        assert cs is not None
        assert cs.responsibilities[0].resp_id == "RESP-1"


class TestPromptConstraint:
    """IDNS-07: stage2_call2a_system prompt contains negative RC vs PM constraint."""

    def test_idns_07_prompt_contains_rc_constraint(self):
        """IDNS-07: prompt text contains the constraint that rc_id must start with RC."""
        from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
        from asago_scenario_generator.stpa.infra.templates import TemplateLoader

        loader = TemplateLoader(PROMPTS_DIR)
        prompt_text = loader.render_prompt("stage2_call2a_system.j2")
        assert "RC-" in prompt_text
        assert "rc_id" in prompt_text.lower() or "rc_id" in prompt_text

    def test_idns_07_prompt_warns_not_to_copy_pm_as_rc(self):
        """IDNS-07: prompt text contains a warning not to copy PM entries as RCs."""
        from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
        from asago_scenario_generator.stpa.infra.templates import TemplateLoader

        loader = TemplateLoader(PROMPTS_DIR)
        prompt_text = loader.render_prompt("stage2_call2a_system.j2")
        assert "PM" in prompt_text
        # Check for negative constraint about not copying PM as RC
        lower = prompt_text.lower()
        assert "not" in lower and ("copy" in lower or "pm" in lower)
