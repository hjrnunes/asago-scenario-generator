"""Unit tests for SP3 Stage 5 — BDI generation."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ControlledProcess,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import (
    CatalogMapping,
    StructuralThreat,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionActionKind,
    ExecutionDeliveryClass,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    BDIGenerationResult,
    CausalFactorDeclaration,
    assemble_scenario_spec,
    _temporal_step_reference,
    _validate_normal_provider_payload,
    _required_execution_role_handles,
    generate_bdi_for_context,
    generate_scenario_id,
    parse_ica_slot_id,
    populate_defender_bdi,
)
from asago_scenario_generator.stpa.models.causal_factor import CausalFactorKind
from tests.stpa.sp1_helpers import MockLLMClient

from .test_normal_authoring_wire import _wrong_timing_context


def _make_control_structure(
    resp1_desc: str = "Authorize payment operations",
    include_resp2: bool = False,
) -> ControlStructure:
    """Build a control structure with RESP-1 having 2 PMs, 2 CAs, 1 FB."""
    cps = [ControlledProcess(cp_id="CP-1", description="Interface")]
    resp1 = Responsibility(
        resp_id="RESP-1",
        description=resp1_desc,
        responsibility_constraints=[
            {"rc_id": "RC-1-1", "description": "Must validate"},
        ],
        process_model_parts=[
            ProcessModelPart(pm_id="PM-1-1", description="User intent state"),
            ProcessModelPart(pm_id="PM-1-2", description="Parameter schema status"),
        ],
        control_actions=[
            ControlAction(
                ca_id="CA-1-1",
                description="Select tool for request",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            ),
            ControlAction(
                ca_id="CA-1-2",
                description="Validate parameters",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            ),
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-1-1",
                description="User intent feedback",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            ),
        ],
    )
    responsibilities = [resp1]
    if include_resp2:
        responsibilities.append(
            Responsibility(
                resp_id="RESP-2",
                description="Second controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-2-1", description="State"),
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-2-1",
                        description="Action",
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1",
                        description="Feedback",
                        updates="PM-2-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
            )
        )
    return ControlStructure(responsibilities=responsibilities, controlled_processes=cps)


def _make_structural_threat(
    slot_id: str = "RESP-1:CA-1-1:NOT_PROVIDED",
    catalog_mappings: list[CatalogMapping] | None = None,
) -> StructuralThreat:
    return StructuralThreat(
        ica_slot_id=slot_id,
        provenance="structural",
        ica_id=f"{slot_id}:1",
        ica_text="The agent fails to select a tool for a request.",
        hazardous_context="A user requests a refund but the agent fails.",
        loss_scenario="The user believes a refund is being processed.",
        related_hazards=["H-1"],
        related_constraints=["SC-1"],
        catalog_mappings=catalog_mappings or [],
    )


def _causal_factors() -> list[CausalFactorDeclaration]:
    return [
        CausalFactorDeclaration(
            kind=CausalFactorKind.process_model_flaw,
            source_id="PM-1-1",
            evidence="The selected process-model state can be stale.",
        )
    ]


class TestPopulateDefenderBDI:
    """Tests for deterministic defender BDI pre-population."""

    def test_beliefs_from_process_model_parts(self):
        """SP3-BDI-01: beliefs derived from PM parts."""
        cs = _make_control_structure()
        bdi = populate_defender_bdi(cs, "RESP-1")
        assert len(bdi.beliefs) == 2
        assert bdi.beliefs[0].pm_id == "PM-1-1"
        assert bdi.beliefs[1].pm_id == "PM-1-2"
        assert bdi.beliefs[0].content == "User intent state"
        assert bdi.beliefs[1].content == "Parameter schema status"

    def test_desires_from_responsibility(self):
        """SP3-BDI-02: desires derived from responsibility."""
        cs = _make_control_structure(resp1_desc="Authorize payment operations")
        bdi = populate_defender_bdi(cs, "RESP-1")
        assert len(bdi.desires) >= 1
        assert all(d.resp_id == "RESP-1" for d in bdi.desires)
        assert all(d.content == "Authorize payment operations" for d in bdi.desires)

    def test_intentions_from_control_actions(self):
        """SP3-BDI-03: intentions derived from CAs."""
        cs = _make_control_structure()
        bdi = populate_defender_bdi(cs, "RESP-1")
        assert len(bdi.intentions) == 2
        assert bdi.intentions[0].ca_id == "CA-1-1"
        assert bdi.intentions[1].ca_id == "CA-1-2"
        assert bdi.intentions[0].content == "Select tool for request"
        assert bdi.intentions[1].content == "Validate parameters"

    def test_vulnerability_fields_empty(self):
        """SP3-BDI-04: vulnerability fields empty before LLM call."""
        cs = _make_control_structure()
        bdi = populate_defender_bdi(cs, "RESP-1")
        assert all(b.vulnerability == "" for b in bdi.beliefs)

    def test_invalid_resp_id_raises(self):
        """Passing a non-existent resp_id raises ValueError."""
        cs = _make_control_structure()
        try:
            populate_defender_bdi(cs, "RESP-99")
            assert False, "Should have raised"
        except ValueError as e:
            assert "RESP-99" in str(e)


class TestAssembleScenarioSpec:
    """Tests for ScenarioSpec assembly."""

    def test_threat_source_and_catalog_context(self):
        """SP3-BDI-09: ScenarioSpec assembled with threat source and catalog."""
        cs = _make_control_structure()
        bdi = populate_defender_bdi(cs, "RESP-1")
        threat = _make_structural_threat(
            catalog_mappings=[
                CatalogMapping(
                    catalog="OWASP_AGENTIC",
                    id="T1",
                    name="Prompt Injection",
                    confidence="low",
                )
            ]
        )
        llm_result = BDIGenerationResult(
            defender_vulnerabilities={"PM-1-1": "v1", "PM-1-2": "v2"},
            causal_factors=_causal_factors(),
            attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        )
        spec = assemble_scenario_spec(bdi, llm_result, threat, cs, scenario_index=0)
        assert spec.threat_source.ica_slot_id == "RESP-1:CA-1-1:NOT_PROVIDED"
        assert spec.threat_source.provenance == "structural"
        assert spec.target_controller == "RESP-1"
        assert spec.target_control_action == "CA-1-1"
        assert spec.ica_type == UCAType.not_provided
        assert len(spec.catalog_context) == 1

    def test_scenario_id_format(self):
        """SP3-BDI-10: scenario ID follows SCN-NNN format."""
        cs = _make_control_structure()
        bdi = populate_defender_bdi(cs, "RESP-1")
        threat = _make_structural_threat()
        llm_result = BDIGenerationResult(
            defender_vulnerabilities={"PM-1-1": "v", "PM-1-2": "v"},
            causal_factors=_causal_factors(),
            attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        )
        spec = assemble_scenario_spec(bdi, llm_result, threat, cs, scenario_index=0)
        assert spec.scenario_id == "SCN-001"
        spec2 = assemble_scenario_spec(bdi, llm_result, threat, cs, scenario_index=4)
        assert spec2.scenario_id == "SCN-005"

    def test_vulnerabilities_merged(self):
        """SP3-BDI-06: vulnerabilities merged into defender beliefs."""
        cs = _make_control_structure()
        bdi = populate_defender_bdi(cs, "RESP-1")
        threat = _make_structural_threat()
        llm_result = BDIGenerationResult(
            defender_vulnerabilities={
                "PM-1-1": "exploitable via injection",
                "PM-1-2": "schema bypass",
            },
            causal_factors=_causal_factors(),
            attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        )
        spec = assemble_scenario_spec(bdi, llm_result, threat, cs)
        assert spec.defender_bdi.beliefs[0].vulnerability == "exploitable via injection"
        assert spec.defender_bdi.beliefs[1].vulnerability == "schema bypass"

    def test_llm_altered_ids_replaced(self):
        """SP3-BDI-16: LLM-altered defender BDI IDs replaced with deterministic values."""
        cs = _make_control_structure()
        bdi = populate_defender_bdi(cs, "RESP-1")
        threat = _make_structural_threat()
        # LLM returns vulnerabilities with altered pm_id keys
        llm_result = BDIGenerationResult(
            defender_vulnerabilities={
                "PM-99-1": "wrong",
                "PM-1-1": "correct1",
                "PM-1-2": "correct2",
            },
            causal_factors=_causal_factors(),
            attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        )
        spec = assemble_scenario_spec(bdi, llm_result, threat, cs)
        # Original deterministic pm_ids are used, vulnerabilities matched by original pm_id
        assert spec.defender_bdi.beliefs[0].pm_id == "PM-1-1"
        assert spec.defender_bdi.beliefs[1].pm_id == "PM-1-2"
        assert spec.defender_bdi.beliefs[0].vulnerability == "correct1"
        assert spec.defender_bdi.beliefs[1].vulnerability == "correct2"


class TestParseICASlotId:
    """Tests for ICA slot ID parsing."""

    def test_responsibility_slot(self):
        result = parse_ica_slot_id("RESP-1:CA-1-1:NOT_PROVIDED")
        assert result["controller"] == "RESP-1"
        assert result["control_action"] == "CA-1-1"
        assert result["ica_type"] == "NOT_PROVIDED"

    def test_coordination_link_slot(self):
        result = parse_ica_slot_id("CL-1:CM-1:INCORRECT")
        assert result["controller"] == "CL-1"
        assert result["control_action"] == "CM-1"
        assert result["ica_type"] == "INCORRECT"

    def test_target_derived_slot_with_temporality(self):
        result = parse_ica_slot_id("RESP-1:CA-1-2:INCORRECT:instantaneous")
        assert result == {
            "controller": "RESP-1",
            "control_action": "CA-1-2",
            "ica_type": "INCORRECT",
        }

    def test_invalid_format_raises(self):
        try:
            parse_ica_slot_id("INVALID")
            assert False, "Should have raised"
        except ValueError:
            pass


class TestGenerateScenarioId:
    """Tests for scenario ID generation."""

    def test_format(self):
        assert generate_scenario_id(0) == "SCN-001"
        assert generate_scenario_id(9) == "SCN-010"
        assert generate_scenario_id(99) == "SCN-100"

    def test_default_index_is_zero(self):
        """Default index must be 0 so that the first scenario is SCN-001."""
        assert generate_scenario_id() == "SCN-001"


class TestContextEnvironmentInputs:
    """Stage 5 rejects mistyped environment inputs before any request."""

    @pytest.mark.parametrize(
        ("keyword", "message"),
        (
            (
                "target_operation",
                "target_operation must be a TargetOperationObservation",
            ),
            (
                "execution_target_profile",
                "execution_target_profile must be an ExecutionTargetProfile",
            ),
            (
                "target_observations",
                "target_observations must be a TargetObservationSnapshot",
            ),
        ),
    )
    def test_mistyped_environment_input_is_rejected(self, keyword, message, tmp_path):
        client = MockLLMClient()

        with pytest.raises(TypeError, match=message):
            generate_bdi_for_context(
                client,
                _wrong_timing_context(),
                tmp_path,
                execution_design=False,
                **{keyword: {"not": "typed"}},
            )
        assert client.calls == []


class TestNormalPayloadShape:
    """The normal-path validator names the missing draft part."""

    def test_missing_adversary_is_rejected(self):
        with pytest.raises(ValueError, match="adversary is required"):
            _validate_normal_provider_payload(
                SimpleNamespace(adversary=None), _wrong_timing_context()
            )


class TestTemporalStepReference:
    """Local step references resolve only to declared steps."""

    def test_named_steps_resolve_within_the_declared_range(self):
        order = {"cause_1": 1, "cause_2": 2}

        assert _temporal_step_reference("target_action", order, {}) == "S-3"
        assert _temporal_step_reference("cause_2", order, {}) == "S-2"
        assert _temporal_step_reference("step_3", order, {}) == "S-3"
        assert _temporal_step_reference("S-1", order, {}) == "S-1"

    @pytest.mark.parametrize(
        ("handle", "message"),
        (
            ("cause_9", "must name a declared causal factor"),
            ("step_x", "temporal step reference is malformed"),
            ("S-4", "must name target_action or a declared cause handle"),
            ("other", "must name target_action or a declared cause handle"),
        ),
    )
    def test_undeclared_steps_are_rejected(self, handle, message):
        with pytest.raises(ValueError, match=message):
            _temporal_step_reference(
                handle, {"cause_1": 1, "cause_2": 2}, {"cause_9": object()}
            )


class TestRequiredExecutionRoleHandles:
    """The derived roles follow the delivery class and the action kind."""

    def test_indirect_tool_call_requires_carrier_and_target_action(self):
        route = SimpleNamespace(action_kind=ExecutionActionKind.tool_call)

        assert _required_execution_role_handles(
            route,
            _wrong_timing_context(),
            SimpleNamespace(condition=None),
            delivery_class=ExecutionDeliveryClass.indirect_content,
        ) == {"role_target_action", "role_stimulus_carrier"}

    def test_direct_agent_message_requires_only_the_agent_channel(self):
        route = SimpleNamespace(action_kind=ExecutionActionKind.agent_message)

        assert _required_execution_role_handles(
            route,
            _wrong_timing_context(),
            SimpleNamespace(condition=None),
            delivery_class=ExecutionDeliveryClass.direct_prompt,
        ) == {"role_agent_channel"}

    def test_missing_delivery_class_is_rejected(self):
        route = SimpleNamespace(action_kind=ExecutionActionKind.tool_call)

        with pytest.raises(ValueError, match="requires its derived delivery class"):
            _required_execution_role_handles(
                route,
                _wrong_timing_context(),
                SimpleNamespace(condition=None),
            )
