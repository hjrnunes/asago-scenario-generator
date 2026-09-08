"""Property-based tests for STPA-Sec boundary schemas using Hypothesis.

These tests verify invariants that should hold across broad input ranges:

- **YAML round-trip**: Any valid model instance, when serialized to YAML
  and reloaded, produces an equal instance.
- **Duplicate-ID rejection**: Duplicate IDs in any ID-bearing list always
  raise ValidationError.
- **Invalid-reference rejection**: References to non-existent IDs always
  raise ValidationError.
- **validate_against correctness**: Valid references pass, invalid ones
  are rejected.
- **Structural heuristic completeness**: A well-formed control structure
  passes all structural heuristics; removing required children produces
  errors.
- **ID format validation**: Valid ID formats are always accepted;
  wrong-prefix and wrong-structure IDs are always rejected; cross-namespace
  collisions are always detected even when field validators are bypassed.
- **KC sub-code display**: Display keys match input codes, values are
  non-empty strings, unknown codes fall back to themselves, and injection
  preserves the original kc_subcodes field.

Property tests complement the example-based unit tests by exploring a
broader input space than hand-written cases can cover.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st
from pydantic import BaseModel, ValidationError

from asago_scenario_generator.stpa.infra.yaml_io import read_yaml, write_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    check_structural_heuristics,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
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
from tests.stpa.helpers import (
    make_ica,
    make_ica_slot,
    make_minimal_control_structure,
    make_minimal_loss_analysis,
)

# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Unique-ID strategies: generate N unique IDs with a given prefix pattern.
st_loss_ids = st.lists(
    st.from_regex(r"L-[1-9][0-9]*", fullmatch=True),
    min_size=1,
    max_size=5,
    unique=True,
)
st_hazard_ids = st.lists(
    st.from_regex(r"H-[1-9][0-9]*", fullmatch=True),
    min_size=1,
    max_size=5,
    unique=True,
)
st_constraint_ids = st.lists(
    st.from_regex(r"SC-[1-9][0-9]*", fullmatch=True),
    min_size=1,
    max_size=5,
    unique=True,
)

# Exclude YAML 1.1 line-break characters (\x85 NEL, \u2028 LS, \u2029 PS)
# and control characters that PyYAML does not round-trip correctly.
st_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs", "Cc"),
        blacklist_characters=("\x85", "\u2028", "\u2029"),
    ),
    min_size=1,
    max_size=50,
)


# ---------------------------------------------------------------------------
# YAML round-trip property tests
# ---------------------------------------------------------------------------


def _yaml_round_trip(model: BaseModel, tmp_path: Path) -> BaseModel:
    """Serialize model to YAML, reload, and return the new instance."""
    path = tmp_path / "round_trip.yaml"
    write_yaml(model, path)
    return read_yaml(path, type(model))


class TestYamlRoundTrip:
    """Any valid model round-trips through YAML without loss."""

    @given(
        loss_ids=st_loss_ids,
        hazard_ids=st_hazard_ids,
        constraint_ids=st_constraint_ids,
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_loss_analysis_yaml_round_trip(
        self, tmp_path, loss_ids, hazard_ids, constraint_ids
    ):
        """LossAnalysis round-trips through YAML."""
        losses = [
            Loss(
                loss_id=lid,
                description=f"Loss {lid}",
                provenance=LossProvenance.use_case,
            )
            for lid in loss_ids
        ]
        hazards = [
            Hazard(
                hazard_id=hid,
                description=f"Hazard {hid}",
                related_losses=loss_ids[:1],
            )
            for hid in hazard_ids
        ]
        constraints = [
            SecurityConstraint(
                constraint_id=cid,
                rule=f"Constraint {cid}",
                related_hazards=hazard_ids[:1],
            )
            for cid in constraint_ids
        ]
        la = LossAnalysis(
            risk_card_losses=[],
            use_case_losses=losses,
            hazards=hazards,
            security_constraints=constraints,
        )
        result = _yaml_round_trip(la, tmp_path)
        assert result == la

    @given(
        n_resps=st.integers(min_value=1, max_value=3),
        n_pms=st.integers(min_value=1, max_value=3),
        n_cas=st.integers(min_value=1, max_value=3),
    )
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_control_structure_yaml_round_trip(self, tmp_path, n_resps, n_pms, n_cas):
        """ControlStructure round-trips through YAML."""
        responsibilities = []
        for i in range(1, n_resps + 1):
            resp_id = f"RESP-{i}"
            pms = [
                ProcessModelPart(pm_id=f"PM-{i}-{j}", description=f"PM {i}-{j}")
                for j in range(1, n_pms + 1)
            ]
            cas = [
                ControlAction(ca_id=f"CA-{i}-{j}", description=f"CA {i}-{j}")
                for j in range(1, n_cas + 1)
            ]
            fbs = [
                FeedbackChannel(
                    fb_id=f"FB-{i}-{j}",
                    description=f"FB {i}-{j}",
                    updates=f"PM-{i}-{j}",
                    source=ElementRef(type=ReferenceType.responsibility, id=resp_id),
                )
                for j in range(1, min(n_pms, n_cas) + 1)
            ]
            responsibilities.append(
                Responsibility(
                    resp_id=resp_id,
                    description=f"Controller {i}",
                    process_model_parts=pms,
                    control_actions=cas,
                    feedback_channels=fbs,
                )
            )
        cs = ControlStructure(responsibilities=responsibilities)
        result = _yaml_round_trip(cs, tmp_path)
        assert result == cs

    @given(
        slot_id=st.from_regex(r"RESP-1:CA-1-1:[A-Z_]+", fullmatch=True),
        ica_text=st_text,
    )
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_ica_enumeration_yaml_round_trip(self, tmp_path, slot_id, ica_text):
        """ICAEnumeration round-trips through YAML."""
        slot = ICASlot(
            slot_id=slot_id,
            responsibility="RESP-1",
            control_action="CA-1-1",
            uca_type=UCAType.not_provided,
            is_na=False,
            icas=[
                ICA(
                    ica_id=f"{slot_id}:1",
                    ica_text=ica_text,
                    hazardous_context="Context",
                    loss_scenario="Scenario",
                    related_hazards=["H-1"],
                    related_constraints=["SC-1"],
                )
            ],
        )
        enum = ICAEnumeration(slots=[slot])
        result = _yaml_round_trip(enum, tmp_path)
        assert result == enum


# ---------------------------------------------------------------------------
# Duplicate-ID rejection property tests
# ---------------------------------------------------------------------------


class TestDuplicateIdRejection:
    """Duplicate IDs in any ID-bearing list must always be rejected."""

    @given(dup_id=st.from_regex(r"L-[1-9][0-9]*", fullmatch=True))
    @settings(max_examples=20, deadline=None)
    def test_duplicate_loss_id_rejected(self, dup_id):
        """Duplicate loss_id in use_case_losses is always rejected."""
        with pytest.raises(ValidationError):
            LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[
                    Loss(
                        loss_id=dup_id,
                        description="A",
                        provenance=LossProvenance.use_case,
                    ),
                    Loss(
                        loss_id=dup_id,
                        description="B",
                        provenance=LossProvenance.use_case,
                    ),
                ],
                hazards=[
                    Hazard(hazard_id="H-1", description="H", related_losses=[dup_id]),
                ],
                security_constraints=[
                    SecurityConstraint(
                        constraint_id="SC-1", rule="C", related_hazards=["H-1"]
                    )
                ],
            )

    @given(dup_id=st.from_regex(r"H-[1-9][0-9]*", fullmatch=True))
    @settings(max_examples=20, deadline=None)
    def test_duplicate_hazard_id_rejected(self, dup_id):
        """Duplicate hazard_id is always rejected."""
        with pytest.raises(ValidationError):
            LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[
                    Loss(
                        loss_id="L-1",
                        description="A",
                        provenance=LossProvenance.use_case,
                    )
                ],
                hazards=[
                    Hazard(hazard_id=dup_id, description="A", related_losses=["L-1"]),
                    Hazard(hazard_id=dup_id, description="B", related_losses=["L-1"]),
                ],
                security_constraints=[
                    SecurityConstraint(
                        constraint_id="SC-1", rule="C", related_hazards=[dup_id]
                    )
                ],
            )

    @given(dup_id=st.from_regex(r"SC-[1-9][0-9]*", fullmatch=True))
    @settings(max_examples=20, deadline=None)
    def test_duplicate_constraint_id_rejected(self, dup_id):
        """Duplicate constraint_id is always rejected."""
        with pytest.raises(ValidationError):
            LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[
                    Loss(
                        loss_id="L-1",
                        description="A",
                        provenance=LossProvenance.use_case,
                    )
                ],
                hazards=[
                    Hazard(hazard_id="H-1", description="A", related_losses=["L-1"]),
                ],
                security_constraints=[
                    SecurityConstraint(
                        constraint_id=dup_id, rule="A", related_hazards=["H-1"]
                    ),
                    SecurityConstraint(
                        constraint_id=dup_id, rule="B", related_hazards=["H-1"]
                    ),
                ],
            )

    @given(dup_id=st.from_regex(r"RESP-[1-9][0-9]*", fullmatch=True))
    @settings(max_examples=20, deadline=None)
    def test_duplicate_resp_id_rejected(self, dup_id):
        """Duplicate resp_id in ControlStructure is always rejected."""
        with pytest.raises(ValidationError):
            ControlStructure(
                responsibilities=[
                    Responsibility(
                        resp_id=dup_id,
                        description="A",
                        process_model_parts=[
                            ProcessModelPart(pm_id="PM-1-1", description="PM"),
                        ],
                        control_actions=[
                            ControlAction(ca_id="CA-1-1", description="CA"),
                        ],
                        feedback_channels=[
                            FeedbackChannel(
                                fb_id="FB-1-1",
                                description="FB",
                                updates="PM-1-1",
                                source=ElementRef(
                                    type=ReferenceType.responsibility,
                                    id=dup_id,
                                ),
                            ),
                        ],
                    ),
                    Responsibility(
                        resp_id=dup_id,
                        description="B",
                        process_model_parts=[
                            ProcessModelPart(pm_id="PM-2-1", description="PM"),
                        ],
                        control_actions=[
                            ControlAction(ca_id="CA-2-1", description="CA"),
                        ],
                        feedback_channels=[
                            FeedbackChannel(
                                fb_id="FB-2-1",
                                description="FB",
                                updates="PM-2-1",
                                source=ElementRef(
                                    type=ReferenceType.responsibility,
                                    id=dup_id,
                                ),
                            ),
                        ],
                    ),
                ]
            )

    @given(dup_slot=st.from_regex(r"RESP-1:CA-1-1:[A-Z_]+", fullmatch=True))
    @settings(max_examples=20, deadline=None)
    def test_duplicate_slot_id_rejected(self, dup_slot):
        """Duplicate slot_id in ICAEnumeration is always rejected."""
        with pytest.raises(ValidationError):
            ICAEnumeration(
                slots=[
                    ICASlot(
                        slot_id=dup_slot,
                        responsibility="RESP-1",
                        control_action="CA-1-1",
                        uca_type=UCAType.not_provided,
                        is_na=False,
                        icas=[make_ica()],
                    ),
                    ICASlot(
                        slot_id=dup_slot,
                        responsibility="RESP-1",
                        control_action="CA-1-1",
                        uca_type=UCAType.incorrect,
                        is_na=False,
                        icas=[make_ica()],
                    ),
                ]
            )


# ---------------------------------------------------------------------------
# Invalid-reference rejection property tests
# ---------------------------------------------------------------------------


class TestInvalidReferenceRejection:
    """References to non-existent IDs must always be rejected."""

    @given(bad_ref=st.from_regex(r"L-[9][0-9]+", fullmatch=True))
    @settings(max_examples=15, deadline=None)
    def test_hazard_invalid_loss_ref_rejected(self, bad_ref):
        """Hazard referencing a non-existent loss is always rejected."""
        with pytest.raises(ValidationError):
            LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[
                    Loss(
                        loss_id="L-1",
                        description="A",
                        provenance=LossProvenance.use_case,
                    )
                ],
                hazards=[
                    Hazard(hazard_id="H-1", description="H", related_losses=[bad_ref]),
                ],
                security_constraints=[
                    SecurityConstraint(
                        constraint_id="SC-1", rule="C", related_hazards=["H-1"]
                    )
                ],
            )

    @given(bad_ref=st.from_regex(r"H-[9][0-9]+", fullmatch=True))
    @settings(max_examples=15, deadline=None)
    def test_constraint_invalid_hazard_ref_rejected(self, bad_ref):
        """Constraint referencing a non-existent hazard is always rejected."""
        with pytest.raises(ValidationError):
            LossAnalysis(
                risk_card_losses=[],
                use_case_losses=[
                    Loss(
                        loss_id="L-1",
                        description="A",
                        provenance=LossProvenance.use_case,
                    )
                ],
                hazards=[
                    Hazard(hazard_id="H-1", description="H", related_losses=["L-1"]),
                ],
                security_constraints=[
                    SecurityConstraint(
                        constraint_id="SC-1",
                        rule="C",
                        related_hazards=[bad_ref],
                    ),
                ],
            )


# ---------------------------------------------------------------------------
# validate_against property tests
# ---------------------------------------------------------------------------


class TestValidateAgainst:
    """Cross-artifact validation: valid references pass, invalid rejected."""

    @given(
        bad_pm_id=st.from_regex(r"PM-[9][0-9]-[0-9]+", fullmatch=True),
    )
    @settings(max_examples=15, deadline=None)
    def test_scenario_spec_invalid_belief_pm_rejected(self, bad_pm_id):
        """ScenarioSpec with invalid DefenderBelief.pm_id is rejected."""
        cs = make_minimal_control_structure()
        spec = ScenarioSpec(
            scenario_id="SCN-001",
            threat_source=ThreatSource(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                provenance="structural",
            ),
            target_controller="RESP-1",
            target_control_action="CA-1-1",
            ica_type=UCAType.not_provided,
            defender_bdi=DefenderBDI(
                beliefs=[
                    DefenderBelief(
                        pm_id=bad_pm_id,
                        content="Belief",
                        vulnerability="Vuln",
                    )
                ],
                desires=[
                    DefenderDesire(resp_id="RESP-1", content="Desire"),
                ],
                intentions=[
                    DefenderIntention(ca_id="CA-1-1", content="Intention"),
                ],
            ),
            attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
            loss_scenario="Scenario",
        )
        with pytest.raises(ValueError, match="pm_id"):
            spec.validate_against(cs)

    @given(
        bad_hazard_id=st.from_regex(r"H-[9][0-9]+", fullmatch=True),
    )
    @settings(max_examples=15, deadline=None)
    def test_ica_invalid_hazard_ref_rejected(self, bad_hazard_id):
        """ICA with invalid hazard reference is rejected by validate_against."""
        la = make_minimal_loss_analysis()
        cs = make_minimal_control_structure()
        slot = make_ica_slot(
            icas=[
                ICA(
                    ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                    ica_text="UCA",
                    hazardous_context="Ctx",
                    loss_scenario="Scenario",
                    related_hazards=[bad_hazard_id],
                    related_constraints=["SC-1"],
                )
            ],
        )
        enum = ICAEnumeration(slots=[slot])
        with pytest.raises(ValueError, match="hazard"):
            enum.validate_against(la, cs)


# ---------------------------------------------------------------------------
# Structural heuristic property tests
# ---------------------------------------------------------------------------


class TestStructuralHeuristics:
    """Structural heuristics: well-formed CS passes, malformed CS fails."""

    def test_minimal_cs_passes_heuristics(self):
        """A minimal valid control structure passes structural heuristics (no LA)."""
        cs = make_minimal_control_structure()
        result = check_structural_heuristics(cs)
        assert result.passed, f"Expected pass, got errors: {result.errors}"

    @given(
        remove_pms=st.booleans(),
        remove_cas=st.booleans(),
        remove_fbs=st.booleans(),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_missing_children_produce_errors(self, remove_pms, remove_cas, remove_fbs):
        """Removing any required child from a responsibility produces errors."""
        cs = make_minimal_control_structure()
        resp = cs.responsibilities[0]
        if remove_pms:
            resp.process_model_parts = []
        if remove_cas:
            resp.control_actions = []
        if remove_fbs:
            resp.feedback_channels = []
        result = check_structural_heuristics(cs)
        # At least one error should be present if any children were removed.
        if remove_pms or remove_cas or remove_fbs:
            assert result.errors, (
                f"Expected errors when removing children, got none. "
                f"remove_pms={remove_pms}, remove_cas={remove_cas}, "
                f"remove_fbs={remove_fbs}"
            )
        else:
            assert result.passed


# ---------------------------------------------------------------------------
# ID format validation property tests
# ---------------------------------------------------------------------------

from asago_scenario_generator.stpa.models.control_structure import (  # noqa: E402
    ControlledProcess,
    CoordinationLink,
    CoordinationMechanism,
    ResponsibilityConstraint,
)

# Regex strategies for each ID namespace.
# Two-segment IDs: RC-X-Y, PM-X-Y, CA-X-Y, FB-X-Y
st_two_seg_ids = st.from_regex(r"[A-Z]{2}-[1-9][0-9]*-[1-9][0-9]*", fullmatch=True)
# One-segment IDs: RESP-N, CP-N, CM-N, CL-N
st_one_seg_ids = st.from_regex(r"[A-Z]{2,4}-[1-9][0-9]*", fullmatch=True)

# Per-field valid-ID strategies (correct prefix + correct structure).
st_rc_ids = st.from_regex(r"RC-[1-9][0-9]*-[1-9][0-9]*", fullmatch=True)
st_pm_ids = st.from_regex(r"PM-[1-9][0-9]*-[1-9][0-9]*", fullmatch=True)
st_ca_ids = st.from_regex(r"CA-[1-9][0-9]*-[1-9][0-9]*", fullmatch=True)
st_fb_ids = st.from_regex(r"FB-[1-9][0-9]*-[1-9][0-9]*", fullmatch=True)
st_resp_ids = st.from_regex(r"RESP-[1-9][0-9]*", fullmatch=True)
st_cp_ids = st.from_regex(r"CP-[1-9][0-9]*", fullmatch=True)
st_cm_ids = st.from_regex(r"CM-[1-9][0-9]*", fullmatch=True)
st_cl_ids = st.from_regex(r"CL-[1-9][0-9]*", fullmatch=True)

# Wrong-prefix strategies: valid two-segment structure but a different prefix.
st_wrong_prefix_two_seg = st.sampled_from(["PM", "CA", "FB", "RC"]).flatmap(
    lambda prefix: st.from_regex(rf"{prefix}-[1-9][0-9]*-[1-9][0-9]*", fullmatch=True)
)

# Wrong-structure strategies: correct prefix but wrong number of segments.
st_rc_wrong_struct = st.from_regex(r"RC-[1-9][0-9]*", fullmatch=True)
st_pm_wrong_struct = st.from_regex(r"PM-[1-9][0-9]*", fullmatch=True)
st_ca_wrong_struct = st.from_regex(r"CA-[1-9][0-9]*", fullmatch=True)
st_fb_wrong_struct = st.from_regex(r"FB-[1-9][0-9]*", fullmatch=True)
st_resp_wrong_struct = st.from_regex(r"RESP-[1-9][0-9]*-[1-9][0-9]*", fullmatch=True)
st_cp_wrong_struct = st.from_regex(r"CP-[1-9][0-9]*-[1-9][0-9]*", fullmatch=True)
st_cm_wrong_struct = st.from_regex(r"CM-[1-9][0-9]*-[1-9][0-9]*", fullmatch=True)
st_cl_wrong_struct = st.from_regex(r"CL-[1-9][0-9]*-[1-9][0-9]*", fullmatch=True)


class TestIdFormatAcceptance:
    """Valid ID formats for each field type are always accepted."""

    @given(rc_id=st_rc_ids)
    @settings(max_examples=30, deadline=None)
    def test_valid_rc_id_accepted(self, rc_id):
        """Any RC-X-Y format ID passes rc_id field validation."""
        rc = ResponsibilityConstraint(rc_id=rc_id, description="C")
        assert rc.rc_id == rc_id

    @given(pm_id=st_pm_ids)
    @settings(max_examples=30, deadline=None)
    def test_valid_pm_id_accepted(self, pm_id):
        """Any PM-X-Y format ID passes pm_id field validation."""
        pm = ProcessModelPart(pm_id=pm_id, description="P")
        assert pm.pm_id == pm_id

    @given(ca_id=st_ca_ids)
    @settings(max_examples=30, deadline=None)
    def test_valid_ca_id_accepted(self, ca_id):
        """Any CA-X-Y format ID passes ca_id field validation."""
        ca = ControlAction(ca_id=ca_id, description="A")
        assert ca.ca_id == ca_id

    @given(fb_id=st_fb_ids)
    @settings(max_examples=30, deadline=None)
    def test_valid_fb_id_accepted(self, fb_id):
        """Any FB-X-Y format ID passes fb_id field validation."""
        fb = FeedbackChannel(fb_id=fb_id, description="F", updates="PM-1-1")
        assert fb.fb_id == fb_id

    @given(resp_id=st_resp_ids)
    @settings(max_examples=30, deadline=None)
    def test_valid_resp_id_accepted(self, resp_id):
        """Any RESP-N format ID passes resp_id field validation."""
        resp = Responsibility(resp_id=resp_id, description="R")
        assert resp.resp_id == resp_id

    @given(cp_id=st_cp_ids)
    @settings(max_examples=30, deadline=None)
    def test_valid_cp_id_accepted(self, cp_id):
        """Any CP-N format ID passes cp_id field validation."""
        cp = ControlledProcess(cp_id=cp_id, description="C")
        assert cp.cp_id == cp_id

    @given(cm_id=st_cm_ids)
    @settings(max_examples=30, deadline=None)
    def test_valid_cm_id_accepted(self, cm_id):
        """Any CM-N format ID passes cm_id field validation."""
        cm = CoordinationMechanism(cm_id=cm_id, description="C", payload="p")
        assert cm.cm_id == cm_id

    @given(cl_id=st_cl_ids)
    @settings(max_examples=30, deadline=None)
    def test_valid_cl_id_accepted(self, cl_id):
        """Any CL-N format ID passes link_id field validation."""
        link = CoordinationLink(
            link_id=cl_id,
            source="RESP-1",
            target="RESP-2",
            shared_pm="PM-1-1",
            coordination_mechanism=CoordinationMechanism(
                cm_id="CM-1", description="C", payload="p"
            ),
            description="L",
        )
        assert link.link_id == cl_id


class TestIdFormatPrefixRejection:
    """IDs with a valid structure but wrong prefix are always rejected.

    This is the key invariant that prevents cross-namespace ID confusion:
    an RC-formatted value must not be accepted as a pm_id, and vice versa.
    """

    @given(rc_id=st_wrong_prefix_two_seg)
    @settings(max_examples=30, deadline=None)
    def test_wrong_prefix_rc_id_rejected(self, rc_id):
        """A two-segment ID with a non-RC prefix is rejected by rc_id."""
        if rc_id.startswith("RC-"):
            return  # skip if hypothesis happens to generate an RC prefix
        with pytest.raises(ValidationError):
            ResponsibilityConstraint(rc_id=rc_id, description="C")

    @given(pm_id=st_wrong_prefix_two_seg)
    @settings(max_examples=30, deadline=None)
    def test_wrong_prefix_pm_id_rejected(self, pm_id):
        """A two-segment ID with a non-PM prefix is rejected by pm_id."""
        if pm_id.startswith("PM-"):
            return
        with pytest.raises(ValidationError):
            ProcessModelPart(pm_id=pm_id, description="P")

    @given(ca_id=st_wrong_prefix_two_seg)
    @settings(max_examples=30, deadline=None)
    def test_wrong_prefix_ca_id_rejected(self, ca_id):
        """A two-segment ID with a non-CA prefix is rejected by ca_id."""
        if ca_id.startswith("CA-"):
            return
        with pytest.raises(ValidationError):
            ControlAction(ca_id=ca_id, description="A")

    @given(fb_id=st_wrong_prefix_two_seg)
    @settings(max_examples=30, deadline=None)
    def test_wrong_prefix_fb_id_rejected(self, fb_id):
        """A two-segment ID with a non-FB prefix is rejected by fb_id."""
        if fb_id.startswith("FB-"):
            return
        with pytest.raises(ValidationError):
            FeedbackChannel(fb_id=fb_id, description="F", updates="PM-1-1")


class TestIdFormatStructureRejection:
    """IDs with the correct prefix but wrong segment count are always rejected.

    Two-segment fields (RC, PM, CA, FB) must reject single-segment values,
    and one-segment fields (RESP, CP, CM, CL) must reject two-segment values.
    """

    @given(rc_id=st_rc_wrong_struct)
    @settings(max_examples=20, deadline=None)
    def test_single_seg_rc_id_rejected(self, rc_id):
        """A single-segment RC-N value is rejected by rc_id (expects RC-X-Y)."""
        with pytest.raises(ValidationError):
            ResponsibilityConstraint(rc_id=rc_id, description="C")

    @given(pm_id=st_pm_wrong_struct)
    @settings(max_examples=20, deadline=None)
    def test_single_seg_pm_id_rejected(self, pm_id):
        """A single-segment PM-N value is rejected by pm_id (expects PM-X-Y)."""
        with pytest.raises(ValidationError):
            ProcessModelPart(pm_id=pm_id, description="P")

    @given(ca_id=st_ca_wrong_struct)
    @settings(max_examples=20, deadline=None)
    def test_single_seg_ca_id_rejected(self, ca_id):
        """A single-segment CA-N value is rejected by ca_id (expects CA-X-Y)."""
        with pytest.raises(ValidationError):
            ControlAction(ca_id=ca_id, description="A")

    @given(fb_id=st_fb_wrong_struct)
    @settings(max_examples=20, deadline=None)
    def test_single_seg_fb_id_rejected(self, fb_id):
        """A single-segment FB-N value is rejected by fb_id (expects FB-X-Y)."""
        with pytest.raises(ValidationError):
            FeedbackChannel(fb_id=fb_id, description="F", updates="PM-1-1")

    @given(resp_id=st_resp_wrong_struct)
    @settings(max_examples=20, deadline=None)
    def test_two_seg_resp_id_rejected(self, resp_id):
        """A two-segment RESP-X-Y value is rejected by resp_id (expects RESP-N)."""
        with pytest.raises(ValidationError):
            Responsibility(resp_id=resp_id, description="R")

    @given(cp_id=st_cp_wrong_struct)
    @settings(max_examples=20, deadline=None)
    def test_two_seg_cp_id_rejected(self, cp_id):
        """A two-segment CP-X-Y value is rejected by cp_id (expects CP-N)."""
        with pytest.raises(ValidationError):
            ControlledProcess(cp_id=cp_id, description="C")

    @given(cm_id=st_cm_wrong_struct)
    @settings(max_examples=20, deadline=None)
    def test_two_seg_cm_id_rejected(self, cm_id):
        """A two-segment CM-X-Y value is rejected by cm_id (expects CM-N)."""
        with pytest.raises(ValidationError):
            CoordinationMechanism(cm_id=cm_id, description="C", payload="p")

    @given(cl_id=st_cl_wrong_struct)
    @settings(max_examples=20, deadline=None)
    def test_two_seg_cl_id_rejected(self, cl_id):
        """A two-segment CL-X-Y value is rejected by link_id (expects CL-N)."""
        with pytest.raises(ValidationError):
            CoordinationLink(
                link_id=cl_id,
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1", description="C", payload="p"
                ),
                description="L",
            )


class TestCrossNamespaceCollisionProperty:
    """Cross-namespace collision: any shared ID value across two namespaces
    is always detected by the model validator, even when field validators
    are bypassed."""

    @given(
        colliding_id=st_rc_ids,
        target_field=st.sampled_from(["pm_id", "ca_id", "fb_id"]),
    )
    @settings(max_examples=30, deadline=None)
    def test_rc_collision_with_other_namespace_detected(
        self, colliding_id, target_field
    ):
        """An RC-X-Y value placed in a non-RC namespace is detected as a collision.

        Uses model_construct to bypass field validators so the cross-namespace
        collision check is the only thing that catches it.
        """
        # Build a responsibility with an RC ID and a colliding ID in another field.
        rc = ResponsibilityConstraint.model_construct(
            rc_id=colliding_id, description="C"
        )
        pm = ProcessModelPart.model_construct(
            pm_id=colliding_id if target_field == "pm_id" else "PM-1-1",
            description="P",
        )
        ca = ControlAction.model_construct(
            ca_id=colliding_id if target_field == "ca_id" else "CA-1-1",
            description="A",
        )
        fb = FeedbackChannel.model_construct(
            fb_id=colliding_id if target_field == "fb_id" else "FB-1-1",
            description="F",
            updates="PM-1-1",
            source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
        )
        resp = Responsibility.model_construct(
            resp_id="RESP-1",
            description="R",
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
        msg = str(exc_info.value).lower()
        assert "namespace" in msg or "collision" in msg

    @given(
        colliding_id=st_two_seg_ids,
    )
    @settings(max_examples=30, deadline=None)
    def test_cp_collision_with_two_seg_namespace_detected(self, colliding_id):
        """A two-segment ID value shared between a child namespace and CP is detected.

        Uses model_construct to bypass field validators.
        """
        rc = ResponsibilityConstraint.model_construct(
            rc_id=colliding_id, description="C"
        )
        pm = ProcessModelPart.model_construct(
            pm_id="PM-1-1",
            description="P",
        )
        ca = ControlAction.model_construct(
            ca_id="CA-1-1",
            description="A",
        )
        fb = FeedbackChannel.model_construct(
            fb_id="FB-1-1",
            description="F",
            updates="PM-1-1",
            source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
        )
        resp = Responsibility.model_construct(
            resp_id="RESP-1",
            description="R",
            responsibility_constraints=[rc],
            process_model_parts=[pm],
            control_actions=[ca],
            feedback_channels=[fb],
        )
        cp = ControlledProcess.model_construct(cp_id=colliding_id, description="CP")
        cs = ControlStructure.model_construct(
            responsibilities=[resp],
            controlled_processes=[cp],
            coordination_links=[],
        )
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            ControlStructure.validate_references_and_duplicates(cs)
        msg = str(exc_info.value).lower()
        assert "namespace" in msg or "collision" in msg

    @given(
        colliding_id=st_one_seg_ids,
    )
    @settings(max_examples=30, deadline=None)
    def test_resp_cp_collision_detected(self, colliding_id):
        """A one-segment ID shared between RESP and CP namespaces is detected.

        Uses model_construct to bypass field validators.
        """
        rc = ResponsibilityConstraint.model_construct(rc_id="RC-1-1", description="C")
        pm = ProcessModelPart.model_construct(
            pm_id="PM-1-1",
            description="P",
        )
        ca = ControlAction.model_construct(
            ca_id="CA-1-1",
            description="A",
        )
        fb = FeedbackChannel.model_construct(
            fb_id="FB-1-1",
            description="F",
            updates="PM-1-1",
            source=ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
        )
        resp = Responsibility.model_construct(
            resp_id=colliding_id,
            description="R",
            responsibility_constraints=[rc],
            process_model_parts=[pm],
            control_actions=[ca],
            feedback_channels=[fb],
        )
        cp = ControlledProcess.model_construct(cp_id=colliding_id, description="CP")
        cs = ControlStructure.model_construct(
            responsibilities=[resp],
            controlled_processes=[cp],
            coordination_links=[],
        )
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            ControlStructure.validate_references_and_duplicates(cs)
        msg = str(exc_info.value).lower()
        assert "namespace" in msg or "collision" in msg

    @given(
        n_resps=st.integers(min_value=1, max_value=3),
    )
    @settings(max_examples=20, deadline=None)
    def test_no_false_positive_cross_namespace_collision(self, n_resps):
        """Well-formed IDs with no cross-namespace sharing do NOT trigger collision.

        This is the negative case: distinct prefixes guarantee no collision
        is reported, regardless of how many responsibilities exist.
        """
        responsibilities = []
        for i in range(1, n_resps + 1):
            rc = ResponsibilityConstraint.model_construct(
                rc_id=f"RC-{i}-1", description="C"
            )
            pm = ProcessModelPart.model_construct(
                pm_id=f"PM-{i}-1",
                description="P",
            )
            ca = ControlAction.model_construct(
                ca_id=f"CA-{i}-1",
                description="A",
            )
            fb = FeedbackChannel.model_construct(
                fb_id=f"FB-{i}-1",
                description="F",
                updates=f"PM-{i}-1",
                source=ElementRef(type=ReferenceType.responsibility, id=f"RESP-{i}"),
            )
            resp = Responsibility.model_construct(
                resp_id=f"RESP-{i}",
                description="R",
                responsibility_constraints=[rc],
                process_model_parts=[pm],
                control_actions=[ca],
                feedback_channels=[fb],
            )
            responsibilities.append(resp)
        cps = [
            ControlledProcess.model_construct(cp_id=f"CP-{i}", description="CP")
            for i in range(1, n_resps + 1)
        ]
        cs = ControlStructure.model_construct(
            responsibilities=responsibilities,
            controlled_processes=cps,
            coordination_links=[],
        )
        # Should NOT raise — no cross-namespace collision.
        ControlStructure.validate_references_and_duplicates(cs)


class TestKcSubcodesDisplayProperty:
    """Property tests for KC sub-code display invariants.

    Verifies that build_kc_subcodes_display and inject_kc_subcodes_display
    preserve key invariants across broad input ranges.
    """

    @given(
        codes=st.lists(
            st.from_regex(r"KC[0-9]+\.[0-9]+", fullmatch=True),
            min_size=0,
            max_size=10,
            unique=True,
        )
    )
    @settings(max_examples=30, deadline=None)
    def test_display_keys_match_input_codes(self, codes):
        """Conservation: display dict keys exactly match input codes."""
        from asago_scenario_generator.models.capability_profile import (
            build_kc_subcodes_display,
        )

        result = build_kc_subcodes_display(codes)
        assert set(result.keys()) == set(codes)

    @given(
        codes=st.lists(
            st.from_regex(r"KC[0-9]+\.[0-9]+", fullmatch=True),
            min_size=0,
            max_size=10,
            unique=True,
        )
    )
    @settings(max_examples=30, deadline=None)
    def test_display_values_are_nonempty_strings(self, codes):
        """Type invariant: all display values are non-empty strings."""
        from asago_scenario_generator.models.capability_profile import (
            build_kc_subcodes_display,
        )

        result = build_kc_subcodes_display(codes)
        for val in result.values():
            assert isinstance(val, str)
            assert len(val) > 0

    @given(
        codes=st.lists(
            st.from_regex(r"KCX-[A-Z]+", fullmatch=True),
            min_size=1,
            max_size=10,
            unique=True,
        )
    )
    @settings(max_examples=20, deadline=None)
    def test_unknown_kcx_codes_fall_back_to_self(self, codes):
        """Fallback invariant: unknown KCX codes map to the code string itself."""
        from asago_scenario_generator.models.capability_profile import (
            KC_SUBCODE_NAMES,
            KCX_SUBCODES,
            build_kc_subcodes_display,
        )

        result = build_kc_subcodes_display(codes)
        for code in codes:
            if code not in KC_SUBCODE_NAMES and code not in KCX_SUBCODES:
                assert result[code] == code

    @given(
        codes=st.lists(
            st.from_regex(r"KC[0-9]+\.[0-9]+", fullmatch=True),
            min_size=0,
            max_size=10,
            unique=True,
        )
    )
    @settings(max_examples=20, deadline=None)
    def test_inject_preserves_kc_subcodes_field(self, codes):
        """Non-mutation: inject_kc_subcodes_display does not alter kc_subcodes."""
        from asago_scenario_generator.models.capability_profile import (
            inject_kc_subcodes_display,
        )

        data = {"kc_subcodes": codes}
        result = inject_kc_subcodes_display(data)
        assert result["kc_subcodes"] == codes
        assert "kc_subcodes_display" in result

    @given(
        codes=st.lists(
            st.from_regex(r"KC[0-9]+\.[0-9]+", fullmatch=True),
            min_size=1,
            max_size=10,
            unique=True,
        )
    )
    @settings(max_examples=20, deadline=None)
    def test_inject_display_consistent_with_build(self, codes):
        """Consistency: inject produces the same display dict as build."""
        from asago_scenario_generator.models.capability_profile import (
            build_kc_subcodes_display,
            inject_kc_subcodes_display,
        )

        data = {"kc_subcodes": codes}
        result = inject_kc_subcodes_display(data)
        assert result["kc_subcodes_display"] == build_kc_subcodes_display(codes)

    @given(
        data=st.dictionaries(
            keys=st.text(min_size=1, max_size=10),
            values=st.text(min_size=1, max_size=20),
            min_size=0,
            max_size=5,
        )
    )
    @settings(max_examples=20, deadline=None)
    def test_inject_without_kc_subcodes_is_noop(self, data):
        """Safety: inject on a dict without kc_subcodes leaves it unchanged."""
        from asago_scenario_generator.models.capability_profile import (
            inject_kc_subcodes_display,
        )

        original = dict(data)
        result = inject_kc_subcodes_display(data)
        assert result == original
        assert "kc_subcodes_display" not in result
