"""Property-based tests for Stage 2 restructure invariants.

These tests verify structural invariants that hold across broad input
ranges for the Stage 2 control-structure derivation pipeline:

- **Assembly conservation**: ``_assemble_control_structure`` preserves
  the count of responsibilities (from ``ResponsibilitySet``) and
  controlled processes (from ``ControlElementSet``).
- **Element assignment by ID prefix**: CAs and FBs are assigned to the
  responsibility whose numeric prefix matches (CA-X-Y → RESP-X,
  FB-X-Y → RESP-X).
- **Orphan PM repair completeness**: After ``repair_orphan_pms``, every
  PM part is updated by at least one feedback channel.
- **RC-vs-PM ID namespace distinction**: RC IDs (RC-X-Y) and PM IDs
  (PM-X-Y) never collide across namespaces in a valid ControlStructure.
- **Coordination-link reference validity**: CoordinationLink source and
  target reference existing responsibilities; shared_pm references an
  existing PM.
- **Call-log ordering**: The four Stage 2 calls execute in the order
  call_1 → call_2a → call_2b → call_3, and each uses the correct
  response_format type.
- **STAGE_2_CALL_COUNT constant**: The exported constant equals 4 and
  matches the actual number of LLM calls in ``derive_control_structure``.
"""

from __future__ import annotations

import json

from hypothesis import HealthCheck, given, settings, strategies as st

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
from asago_scenario_generator.stpa.system_model.control_structure import (
    ControlElementSet,
    CoordinationAnalysis,
    _CoordinationProviderEnvelope,
    RequirementSet,
    ResponsibilitySet,
    STAGE_2_CALL_COUNT,
    _assemble_control_structure,
    _extract_resp_num,
    derive_control_structure,
    repair_orphan_pms,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from tests.stpa.sp1_helpers import MockLLMClient, valid_empty_coordination_analysis_dict
import inspect
from asago_scenario_generator.stpa.system_model.run import _write_manifest


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

st_text = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters=(" ", "-", "_"),
    ),
    min_size=1,
    max_size=30,
)


def _make_responsibility(
    resp_num: int,
    n_pms: int = 1,
    n_rcs: int = 1,
) -> Responsibility:
    """Build a valid Responsibility with RCs and PMs (no CAs/FBs)."""
    return Responsibility(
        resp_id=f"RESP-{resp_num}",
        description=f"Controller {resp_num}",
        responsibility_constraints=[
            ResponsibilityConstraint(
                rc_id=f"RC-{resp_num}-{j}", description=f"RC {resp_num}-{j}"
            )
            for j in range(1, n_rcs + 1)
        ],
        process_model_parts=[
            ProcessModelPart(
                pm_id=f"PM-{resp_num}-{j}", description=f"PM {resp_num}-{j}"
            )
            for j in range(1, n_pms + 1)
        ],
    )


def _make_control_element_set(
    resp_nums: list[int],
    n_cps: int = 1,
) -> ControlElementSet:
    """Build a valid ControlElementSet with CAs, FBs, and CPs.

    For each responsibility number, creates one CA, one FB that updates
    PM-{num}-1, and a source ElementRef pointing to a controlled process
    (or self for the first resp).
    """
    control_actions: list[ControlAction] = []
    feedback_channels: list[FeedbackChannel] = []
    controlled_processes: list[ControlledProcess] = [
        ControlledProcess(cp_id=f"CP-{i}", description=f"Process {i}")
        for i in range(1, n_cps + 1)
    ]

    for num in resp_nums:
        control_actions.append(
            ControlAction(ca_id=f"CA-{num}-1", description=f"CA {num}-1")
        )
        source = (
            ElementRef(type=ReferenceType.controlled_process, id="CP-1")
            if controlled_processes
            else None
        )
        feedback_channels.append(
            FeedbackChannel(
                fb_id=f"FB-{num}-1",
                description=f"FB {num}-1",
                updates=f"PM-{num}-1",
                source=source,
            )
        )

    return ControlElementSet(
        control_actions=control_actions,
        feedback_channels=feedback_channels,
        controlled_processes=controlled_processes,
    )


def _make_coordination_analysis(
    resp_nums: list[int],
) -> CoordinationAnalysis:
    """Build a valid CoordinationAnalysis if there are >=2 responsibilities."""
    if len(resp_nums) < 2:
        return CoordinationAnalysis()

    s, t = resp_nums[0], resp_nums[1]
    return CoordinationAnalysis(
        coordination_links=[
            CoordinationLink(
                link_id="CL-1",
                source=f"RESP-{s}",
                target=f"RESP-{t}",
                shared_pm=f"PM-{t}-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1",
                    description="Shared state",
                    payload="State data",
                ),
                description="Coordination link",
            )
        ],
        integrity_findings=[],
    )


def _make_loss_analysis() -> LossAnalysis:
    return LossAnalysis(
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
            SecurityConstraint(constraint_id="SC-1", rule="C", related_hazards=["H-1"]),
        ],
    )


# ---------------------------------------------------------------------------
# Assembly conservation property tests
# ---------------------------------------------------------------------------


class TestAssemblyConservation:
    """_assemble_control_structure preserves responsibility and CP counts."""

    @given(
        n_resps=st.integers(min_value=1, max_value=5),
        n_pms=st.integers(min_value=1, max_value=3),
        n_cps=st.integers(min_value=1, max_value=3),
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_responsibility_count_preserved(self, n_resps, n_pms, n_cps):
        """Assembly preserves the number of responsibilities from ResponsibilitySet."""
        resp_nums = list(range(1, n_resps + 1))
        resp_set = ResponsibilitySet(
            responsibilities=[_make_responsibility(n, n_pms=n_pms) for n in resp_nums]
        )
        elem_set = _make_control_element_set(resp_nums, n_cps=n_cps)
        cs = _assemble_control_structure(resp_set, elem_set)
        assert len(cs.responsibilities) == n_resps

    @given(
        n_resps=st.integers(min_value=1, max_value=5),
        n_cps=st.integers(min_value=0, max_value=3),
    )
    @settings(
        max_examples=25,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_controlled_process_count_preserved(self, n_resps, n_cps):
        """Assembly preserves the number of controlled processes from ControlElementSet."""
        resp_nums = list(range(1, n_resps + 1))
        resp_set = ResponsibilitySet(
            responsibilities=[_make_responsibility(n) for n in resp_nums]
        )
        elem_set = _make_control_element_set(resp_nums, n_cps=n_cps)
        cs = _assemble_control_structure(resp_set, elem_set)
        assert len(cs.controlled_processes) == n_cps

    @given(
        n_resps=st.integers(min_value=1, max_value=5),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_resp_ids_preserved(self, n_resps):
        """Assembly preserves the resp_id set from ResponsibilitySet."""
        resp_nums = list(range(1, n_resps + 1))
        resp_set = ResponsibilitySet(
            responsibilities=[_make_responsibility(n) for n in resp_nums]
        )
        elem_set = _make_control_element_set(resp_nums)
        cs = _assemble_control_structure(resp_set, elem_set)
        cs_resp_ids = {r.resp_id for r in cs.responsibilities}
        original_ids = {f"RESP-{n}" for n in resp_nums}
        assert cs_resp_ids == original_ids


# ---------------------------------------------------------------------------
# Element assignment by ID prefix
# ---------------------------------------------------------------------------


class TestElementAssignmentByIdPrefix:
    """CAs and FBs are assigned to the responsibility by ID prefix."""

    @given(
        n_resps=st.integers(min_value=1, max_value=5),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_ca_assigned_to_correct_resp(self, n_resps):
        """Each CA-X-1 lands in responsibility RESP-X."""
        resp_nums = list(range(1, n_resps + 1))
        resp_set = ResponsibilitySet(
            responsibilities=[_make_responsibility(n) for n in resp_nums]
        )
        elem_set = _make_control_element_set(resp_nums)
        cs = _assemble_control_structure(resp_set, elem_set)
        for resp in cs.responsibilities:
            resp_num = _extract_resp_num(resp.resp_id)
            ca_ids = {ca.ca_id for ca in resp.control_actions}
            assert f"CA-{resp_num}-1" in ca_ids

    @given(
        n_resps=st.integers(min_value=1, max_value=5),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_fb_assigned_to_correct_resp(self, n_resps):
        """Each FB-X-1 lands in responsibility RESP-X."""
        resp_nums = list(range(1, n_resps + 1))
        resp_set = ResponsibilitySet(
            responsibilities=[_make_responsibility(n) for n in resp_nums]
        )
        elem_set = _make_control_element_set(resp_nums)
        cs = _assemble_control_structure(resp_set, elem_set)
        for resp in cs.responsibilities:
            resp_num = _extract_resp_num(resp.resp_id)
            fb_ids = {fb.fb_id for fb in resp.feedback_channels}
            assert f"FB-{resp_num}-1" in fb_ids


# ---------------------------------------------------------------------------
# Orphan PM repair completeness
# ---------------------------------------------------------------------------


class TestOrphanPmRepairCompleteness:
    """After repair_orphan_pms, every PM is updated by at least one FB."""

    @given(
        n_resps=st.integers(min_value=1, max_value=4),
        n_pms=st.integers(min_value=1, max_value=4),
        n_fbs=st.integers(min_value=0, max_value=3),
    )
    @settings(
        max_examples=40,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_all_pms_covered_after_repair(self, n_resps, n_pms, n_fbs):
        """Every PM part has at least one FB updating it after repair."""
        responsibilities = []
        for num in range(1, n_resps + 1):
            resp = Responsibility(
                resp_id=f"RESP-{num}",
                description=f"Controller {num}",
                process_model_parts=[
                    ProcessModelPart(pm_id=f"PM-{num}-{j}", description=f"PM {num}-{j}")
                    for j in range(1, n_pms + 1)
                ],
                control_actions=[
                    ControlAction(ca_id=f"CA-{num}-1", description=f"CA {num}-1")
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id=f"FB-{num}-{j}",
                        description=f"FB {num}-{j}",
                        updates=f"PM-{num}-1",  # always update PM-{num}-1
                        source=ElementRef(
                            type=ReferenceType.responsibility, id=f"RESP-{num}"
                        ),
                    )
                    for j in range(1, n_fbs + 1)
                ],
            )
            responsibilities.append(resp)

        cs = ControlStructure(responsibilities=responsibilities)
        repaired, warnings = repair_orphan_pms(cs)

        for resp in repaired.responsibilities:
            updated_pms = {fb.updates for fb in resp.feedback_channels}
            for pm in resp.process_model_parts:
                assert pm.pm_id in updated_pms, (
                    f"PM {pm.pm_id} in {resp.resp_id} not covered after repair. "
                    f"Updated PMs: {updated_pms}"
                )


# ---------------------------------------------------------------------------
# RC-vs-PM ID namespace distinction
# ---------------------------------------------------------------------------


class TestRcPmIdNamespaceDistinction:
    """RC IDs and PM IDs never collide across namespaces in a valid CS."""

    @given(
        n_resps=st.integers(min_value=1, max_value=5),
        n_pms=st.integers(min_value=1, max_value=3),
        n_rcs=st.integers(min_value=1, max_value=3),
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_rc_pm_no_cross_namespace_collision(self, n_resps, n_pms, n_rcs):
        """No RC ID value equals any PM ID value in a valid ControlStructure."""
        resp_nums = list(range(1, n_resps + 1))
        resp_set = ResponsibilitySet(
            responsibilities=[
                _make_responsibility(n, n_pms=n_pms, n_rcs=n_rcs) for n in resp_nums
            ]
        )
        elem_set = _make_control_element_set(resp_nums)
        cs = _assemble_control_structure(resp_set, elem_set)

        rc_ids: set[str] = set()
        pm_ids: set[str] = set()
        for resp in cs.responsibilities:
            rc_ids.update(rc.rc_id for rc in resp.responsibility_constraints)
            pm_ids.update(pm.pm_id for pm in resp.process_model_parts)

        # RC-X-Y and PM-X-Y have the same format but different prefixes,
        # so they should never collide unless the same number is reused
        # in both namespaces — which the format guarantees won't happen.
        assert rc_ids.isdisjoint(pm_ids), (
            f"Cross-namespace collision: {rc_ids & pm_ids}"
        )


# ---------------------------------------------------------------------------
# Coordination-link reference validity
# ---------------------------------------------------------------------------


class TestCoordinationLinkReferenceValidity:
    """CoordinationLink source/target/shared_pm reference valid elements."""

    @given(
        n_resps=st.integers(min_value=2, max_value=5),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_coordination_links_reference_valid_ids(self, n_resps):
        """CL source/target are valid resp_ids; shared_pm is a valid pm_id."""
        resp_nums = list(range(1, n_resps + 1))
        resp_set = ResponsibilitySet(
            responsibilities=[_make_responsibility(n) for n in resp_nums]
        )
        elem_set = _make_control_element_set(resp_nums)
        cs = _assemble_control_structure(resp_set, elem_set)

        resp_ids = {r.resp_id for r in cs.responsibilities}
        all_pm_ids: set[str] = set()
        for resp in cs.responsibilities:
            all_pm_ids.update(pm.pm_id for pm in resp.process_model_parts)

        coord = _make_coordination_analysis(resp_nums)
        for cl in coord.coordination_links:
            assert cl.source in resp_ids, (
                f"CL {cl.link_id} source {cl.source} not in {resp_ids}"
            )
            assert cl.target in resp_ids, (
                f"CL {cl.link_id} target {cl.target} not in {resp_ids}"
            )
            assert cl.shared_pm in all_pm_ids, (
                f"CL {cl.link_id} shared_pm {cl.shared_pm} not in {all_pm_ids}"
            )


# ---------------------------------------------------------------------------
# Call-log ordering: call_1 → call_2a → call_2b → call_3
# ---------------------------------------------------------------------------


class TestCallLogOrdering:
    """The four Stage 2 calls execute in the correct order with correct types."""

    def test_call_order_and_response_formats(self, tmp_path):
        """Calls happen in order call_1 → call_2a → call_2b → call_3."""
        client = MockLLMClient()
        client.set_response_for(
            RequirementSet,
            {
                "requirements": [
                    {
                        "req_id": "REQ-1",
                        "description": "R",
                        "classification": "control",
                        "source_constraint": "SC-1",
                    }
                ]
            },
        )
        client.set_response_for(
            ResponsibilitySet,
            {
                "responsibilities": [
                    {
                        "resp_id": "RESP-1",
                        "description": "C1",
                        "security_constraint_refs": ["SC-1"],
                        "process_model_parts": [
                            {"pm_id": "PM-1-1", "description": "S"}
                        ],
                    }
                ]
            },
        )
        client.set_response_for(
            ControlElementSet,
            {
                "control_actions": [
                    {
                        "ca_id": "CA-1-1",
                        "description": "A",
                        "target": {"type": "responsibility", "id": "RESP-1"},
                    }
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-1-1",
                        "description": "F",
                        "updates": "PM-1-1",
                        "source": {"type": "responsibility", "id": "RESP-1"},
                    }
                ],
                "controlled_processes": [],
            },
        )
        client.set_response_for(
            CoordinationAnalysis,
            valid_empty_coordination_analysis_dict(),
        )

        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )

        # Exactly 4 calls
        assert len(client.calls) == STAGE_2_CALL_COUNT

        # Verify ordering by response_format
        assert client.calls[0].response_format is RequirementSet
        assert client.calls[1].response_format is ResponsibilitySet
        assert issubclass(client.calls[2].response_format, ControlElementSet)
        assert issubclass(
            client.calls[3].response_format, _CoordinationProviderEnvelope
        )

        # Verify call-log step names in calls.jsonl
        calls_file = tmp_path / "calls.jsonl"
        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        stage2_entries = [e for e in entries if e.get("stage") == "stage_2"]
        steps = [e["step"] for e in stage2_entries]
        assert steps == [
            "call_1_requirements",
            "call_2a_responsibilities",
            "call_2b_control_elements",
            "call_3_coordination",
        ]

    def test_always_four_calls(self, tmp_path):
        """derive_control_structure always makes exactly STAGE_2_CALL_COUNT calls."""
        client = MockLLMClient()
        client.set_response_for(
            RequirementSet,
            {
                "requirements": [
                    {
                        "req_id": "REQ-1",
                        "description": "R",
                        "classification": "control",
                        "source_constraint": "SC-1",
                    }
                ]
            },
        )
        client.set_response_for(
            ResponsibilitySet,
            {
                "responsibilities": [
                    {
                        "resp_id": "RESP-1",
                        "description": "C1",
                        "security_constraint_refs": ["SC-1"],
                        "process_model_parts": [
                            {"pm_id": "PM-1-1", "description": "S"}
                        ],
                    }
                ]
            },
        )
        client.set_response_for(
            ControlElementSet,
            {
                "control_actions": [
                    {
                        "ca_id": "CA-1-1",
                        "description": "A",
                        "target": {"type": "responsibility", "id": "RESP-1"},
                    }
                ],
                "feedback_channels": [
                    {
                        "fb_id": "FB-1-1",
                        "description": "F",
                        "updates": "PM-1-1",
                        "source": {"type": "responsibility", "id": "RESP-1"},
                    }
                ],
                "controlled_processes": [],
            },
        )
        client.set_response_for(
            CoordinationAnalysis,
            valid_empty_coordination_analysis_dict(),
        )

        derive_control_structure(
            llm_client=client,
            use_case_text="Test",
            loss_analysis=_make_loss_analysis(),
            run_dir=tmp_path,
        )
        assert len(client.calls) == STAGE_2_CALL_COUNT


# ---------------------------------------------------------------------------
# STAGE_2_CALL_COUNT constant invariant
# ---------------------------------------------------------------------------


class TestStage2CallCountConstant:
    """The exported STAGE_2_CALL_COUNT constant equals 4."""

    def test_constant_is_four(self):
        """STAGE_2_CALL_COUNT == 4."""
        assert STAGE_2_CALL_COUNT == 4

    def test_constant_matches_run_py_usage(self):
        """run.py imports and uses STAGE_2_CALL_COUNT for manifest."""

        src = inspect.getsource(_write_manifest)
        assert "STAGE_2_CALL_COUNT" in src


# ---------------------------------------------------------------------------
# _extract_resp_num invariant
# ---------------------------------------------------------------------------


class TestExtractRespNum:
    """_extract_resp_num extracts the first integer from an element ID."""

    @given(
        num=st.integers(min_value=1, max_value=999),
        suffix=st.integers(min_value=1, max_value=99),
    )
    @settings(max_examples=30, deadline=None)
    def test_extract_from_ca_id(self, num, suffix):
        """CA-{num}-{suffix} → num."""
        assert _extract_resp_num(f"CA-{num}-{suffix}") == num

    @given(
        num=st.integers(min_value=1, max_value=999),
        suffix=st.integers(min_value=1, max_value=99),
    )
    @settings(max_examples=30, deadline=None)
    def test_extract_from_fb_id(self, num, suffix):
        """FB-{num}-{suffix} → num."""
        assert _extract_resp_num(f"FB-{num}-{suffix}") == num

    @given(num=st.integers(min_value=1, max_value=999))
    @settings(max_examples=20, deadline=None)
    def test_extract_from_resp_id(self, num):
        """RESP-{num} → num."""
        assert _extract_resp_num(f"RESP-{num}") == num

    def test_extract_no_number_returns_zero(self):
        """An ID with no digits returns 0."""
        assert _extract_resp_num("RESP-abc") == 0
