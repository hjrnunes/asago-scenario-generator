"""Unit tests for SP3 Stage 5 — BDI generation."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

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
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    BDIGenerationResult,
    assemble_scenario_spec,
    generate_bdi,
    generate_scenario_id,
    parse_ica_slot_id,
    populate_defender_bdi,
)
from tests.stpa.sp1_helpers import MockCall, MockLLMClient, read_calls_jsonl


class LengthFinishReasonError(Exception):
    """Test stand-in for the OpenAI SDK completion-length exception."""


class _SequenceBDIClient(MockLLMClient):
    """Mock client with per-call outcomes for retry behavior."""

    def __init__(self, outcomes: list[object]) -> None:
        super().__init__()
        self._outcomes = list(outcomes)

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: type | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
    ) -> LLMResult:
        self.calls.append(
            MockCall(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_format=response_format,
                temperature=temperature,
                max_completion_tokens=max_completion_tokens,
            )
        )
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return LLMResult(
            content=outcome,
            prompt_tokens=100,
            completion_tokens=50,
            duration_ms=1,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )


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


class TestGenerateBDI:
    """Tests for the LLM call."""

    def test_one_llm_call(self):
        """SP3-BDI-05: exactly 1 LLM call made."""
        cs = _make_control_structure()
        bdi = populate_defender_bdi(cs, "RESP-1")
        threat = _make_structural_threat()
        llm_result = BDIGenerationResult(
            defender_vulnerabilities={"PM-1-1": "vuln1", "PM-1-2": "vuln2"},
            attacker_bdi=AttackerBDI(
                beliefs=["Knows PM-1-1 is exploitable"],
                desires=["Induce NOT_PROVIDED on CA-1-1"],
                intentions=["Poison PM-1-1 via FB-1-1"],
            ),
        )
        client = MockLLMClient()
        client.set_response_for(BDIGenerationResult, llm_result)

        with TemporaryDirectory() as tmpdir:
            result, error = generate_bdi(client, bdi, threat, cs, Path(tmpdir))
            assert error is None
            assert result is not None
            assert client.call_count == 1

    def test_call_logged_with_stage_5(self):
        """SP3-BDI-05/20: call labeled stage_5, step bdi_generation."""
        cs = _make_control_structure()
        bdi = populate_defender_bdi(cs, "RESP-1")
        threat = _make_structural_threat()
        llm_result = BDIGenerationResult(
            defender_vulnerabilities={"PM-1-1": "v", "PM-1-2": "v"},
            attacker_bdi=AttackerBDI(
                beliefs=["b"], desires=["d"], intentions=["i via PM-1-1"]
            ),
        )
        client = MockLLMClient()
        client.set_response_for(BDIGenerationResult, llm_result)

        with TemporaryDirectory() as tmpdir:
            generate_bdi(client, bdi, threat, cs, Path(tmpdir))
            calls = read_calls_jsonl(Path(tmpdir))
            assert len(calls) == 1
            assert calls[0]["stage"] == "stage_5"
            assert calls[0]["step"] == "bdi_generation"

    def test_attacker_bdi_structure(self):
        """SP3-BDI-07: attacker BDI has beliefs, desires, intentions."""
        cs = _make_control_structure()
        bdi = populate_defender_bdi(cs, "RESP-1")
        threat = _make_structural_threat()
        llm_result = BDIGenerationResult(
            defender_vulnerabilities={"PM-1-1": "v", "PM-1-2": "v"},
            attacker_bdi=AttackerBDI(
                beliefs=["b1", "b2", "b3"],
                desires=["d1", "d2"],
                intentions=["i1", "i2", "i3"],
            ),
        )
        client = MockLLMClient()
        client.set_response_for(BDIGenerationResult, llm_result)

        with TemporaryDirectory() as tmpdir:
            result, _ = generate_bdi(client, bdi, threat, cs, Path(tmpdir))
            assert len(result.attacker_bdi.beliefs) == 3
            assert len(result.attacker_bdi.desires) == 2
            assert len(result.attacker_bdi.intentions) == 3

    def test_user_prompt_contains_defender_bdi_and_ica(self):
        """SP3-BDI-17: user prompt contains defender BDI, ICA, control structure."""
        cs = _make_control_structure()
        bdi = populate_defender_bdi(cs, "RESP-1")
        threat = _make_structural_threat()
        llm_result = BDIGenerationResult(
            defender_vulnerabilities={"PM-1-1": "v", "PM-1-2": "v"},
            attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        )
        client = MockLLMClient()
        client.set_response_for(BDIGenerationResult, llm_result)

        with TemporaryDirectory() as tmpdir:
            generate_bdi(client, bdi, threat, cs, Path(tmpdir))
            call = client.calls[0]
            assert "PM-1-1" in call.user_prompt
            assert "User intent state" in call.user_prompt
            assert threat.ica_text in call.user_prompt
            assert threat.hazardous_context in call.user_prompt
            assert threat.loss_scenario in call.user_prompt
            assert "RESP-1" in call.user_prompt

    def test_system_prompt_contains_instructions(self):
        """SP3-BDI-18: system prompt defines dual-BDI interaction model."""
        cs = _make_control_structure()
        bdi = populate_defender_bdi(cs, "RESP-1")
        threat = _make_structural_threat()
        llm_result = BDIGenerationResult(
            defender_vulnerabilities={"PM-1-1": "v", "PM-1-2": "v"},
            attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        )
        client = MockLLMClient()
        client.set_response_for(BDIGenerationResult, llm_result)

        with TemporaryDirectory() as tmpdir:
            generate_bdi(client, bdi, threat, cs, Path(tmpdir))
            sys_prompt = client.calls[0].system_prompt
            assert "vulnerability" in sys_prompt.lower()
            assert "attacker" in sys_prompt.lower()
            assert "PM" in sys_prompt or "FB" in sys_prompt or "CA" in sys_prompt

    def test_length_failure_gets_one_concise_structured_retry(self):
        cs = _make_control_structure()
        bdi = populate_defender_bdi(cs, "RESP-1")
        threat = _make_structural_threat()
        llm_result = BDIGenerationResult(
            defender_vulnerabilities={"PM-1-1": "v", "PM-1-2": "v"},
            attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        )
        client = _SequenceBDIClient([LengthFinishReasonError("truncated"), llm_result])

        with TemporaryDirectory() as tmpdir:
            result, error = generate_bdi(client, bdi, threat, cs, Path(tmpdir))

        assert error is None
        assert result == llm_result
        assert len(client.calls) == 2
        retry = client.calls[1]
        assert retry.response_format is BDIGenerationResult
        assert retry.max_completion_tokens <= 2048
        assert "prior response was truncated" in retry.user_prompt
        assert "concise schema-matching response" in retry.user_prompt

    def test_exhausted_length_retry_is_reported(self):
        cs = _make_control_structure()
        bdi = populate_defender_bdi(cs, "RESP-1")
        threat = _make_structural_threat()
        client = _SequenceBDIClient(
            [LengthFinishReasonError("first"), LengthFinishReasonError("second")]
        )

        with TemporaryDirectory() as tmpdir:
            result, error = generate_bdi(client, bdi, threat, cs, Path(tmpdir))

        assert result is None
        assert len(client.calls) == 2
        assert error is not None
        assert "retry exhausted" in error.lower()
        assert "LengthFinishReasonError" in error


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
