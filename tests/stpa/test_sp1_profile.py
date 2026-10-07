"""Tests for SP1 Stage 1b — Capability Profile inference.

Covers SP1-CP-01 through SP1-CP-08 (adapted for the revised prompt
that removes loss-analysis context and boolean flag fields).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
    Stage1Profile,
    Stage1Profile as S1P,
    classify_entry_point,
)
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml, write_yaml
from asago_scenario_generator.stpa.system_model.profile import (
    derive_capability_profile,
    load_capability_profile,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.stpa.sp1_helpers import MockLLMClient
from asago_scenario_generator.stpa.system_model import PROMPTS_DIR


def _valid_stage1_profile_dict() -> dict:
    return {
        "entry_points": [
            {
                "name": "User chat messages",
                "direction": "input",
                "controllability": "direct",
            },
        ],
        "confidence": "medium",
        "kc_subcodes": ["KC1.1", "KC4.3", "KC6.1.1", "KC6.3.2"],
        "tool_inventory": [
            {"name": "payment_api", "description": "Execute payments"},
        ],
    }


class TestStage1bProfile:
    """SP1 Stage 1b capability profile inference (revised prompt)."""

    def test_cp_01_valid_response_produces_valid_profile(self, tmp_path):
        """A valid LLM response produces a valid CapabilityProfile."""
        client = MockLLMClient()
        client.set_response_for(Stage1Profile, _valid_stage1_profile_dict())
        result = derive_capability_profile(
            llm_client=client,
            use_case_text="Test use case",
            run_dir=tmp_path,
        )
        assert isinstance(result, CapabilityProfile)
        assert "input" in result.zones_active
        assert "reasoning" in result.zones_active
        assert result.entry_point_completeness.value == "inferred_partial"

    def test_cp_02_stage1_profile_promoted(self, tmp_path):
        """Stage1Profile is promoted via to_capability_profile."""
        client = MockLLMClient()
        client.set_response_for(Stage1Profile, _valid_stage1_profile_dict())
        result = derive_capability_profile(
            llm_client=client,
            use_case_text="Test use case",
            run_dir=tmp_path,
        )
        # zones_active derived from kc_subcodes
        assert "input" in result.zones_active
        assert "reasoning" in result.zones_active
        assert "tool_execution" in result.zones_active  # KC6.* implies tool_execution
        assert "memory" in result.zones_active  # KC4.3 implies memory
        # has_persistent_memory derived from kc_subcodes (KC4.3)
        assert result.has_persistent_memory is True

    def test_cp_02a_exact_duplicate_tool_operations_are_normalized(self, tmp_path):
        """Redundant operation labels from structured output do not abort Stage 1b."""
        response = _valid_stage1_profile_dict()
        response["tool_inventory"] = [
            {
                "name": "payment_api",
                "description": "Execute payments",
                "supported_operations": ["execute_code", "execute_code"],
            },
            {
                "name": "ledger_api",
                "description": "Read and update the ledger",
                "supported_operations": [
                    "transmit_data",
                    "retrieve_data",
                    "transmit_data",
                ],
            },
        ]
        client = MockLLMClient()
        client.set_response_for(Stage1Profile, response)

        result = derive_capability_profile(
            llm_client=client,
            use_case_text="Test use case",
            run_dir=tmp_path,
        )

        assert result.tool_inventory is not None
        assert result.tool_inventory[0].supported_operations == ("execute_code",)
        assert result.tool_inventory[1].supported_operations == (
            "retrieve_data",
            "transmit_data",
        )

    def test_cp_03_profile_flag_skips_llm_call(self, tmp_path):
        """Profile flag skips the LLM call."""
        # Write a pre-built profile
        profile = Stage1Profile(
            entry_points=[
                {
                    "name": "User chat",
                    "direction": "input",
                    "controllability": "direct",
                },
            ],
            confidence="medium",
            kc_subcodes=["KC1.1", "KC4.3", "KC6.1.1"],
            tool_inventory=[{"name": "tool1", "description": "A tool"}],
        ).to_capability_profile()
        profile_path = tmp_path / "capability-profile.yaml"
        write_yaml(profile, profile_path)

        loaded = load_capability_profile(profile_path)
        assert isinstance(loaded, CapabilityProfile)

    def test_cp_05_call_logged_with_stage_1b(self, tmp_path):
        """Call log entry has stage stage_1b."""
        client = MockLLMClient()
        client.set_response_for(Stage1Profile, _valid_stage1_profile_dict())
        derive_capability_profile(
            llm_client=client,
            use_case_text="Test use case",
            run_dir=tmp_path,
        )
        calls_file = tmp_path / "calls.jsonl"
        assert calls_file.exists()
        entries = read_calls_jsonl(tmp_path)
        assert len(entries) == 1
        assert entries[0]["stage"] == "stage_1b"
        assert entries[0]["step"] == "capability_profile"

    def test_cp_06_capability_profile_written_to_yaml(self, tmp_path):
        """capability-profile.yaml exists and contains valid model."""
        client = MockLLMClient()
        client.set_response_for(Stage1Profile, _valid_stage1_profile_dict())
        derive_capability_profile(
            llm_client=client,
            use_case_text="Test use case",
            run_dir=tmp_path,
        )
        yaml_file = tmp_path / "capability-profile.yaml"
        assert yaml_file.exists()
        loaded = read_yaml(yaml_file, CapabilityProfile)
        assert isinstance(loaded, CapabilityProfile)

    def test_cp_07_invalid_kc_subcodes_fail(self, tmp_path):
        """Invalid KC sub-codes in LLM response fail validation."""
        bad = _valid_stage1_profile_dict()
        bad["kc_subcodes"] = ["KC1.1", "KC9.9"]
        client = MockLLMClient()
        client.set_response_for(Stage1Profile, bad)
        with pytest.raises(
            (ValidationError, ValueError, StageError), match="(?i)Invalid KC sub-code"
        ):
            derive_capability_profile(
                llm_client=client,
                use_case_text="Test use case",
                run_dir=tmp_path,
            )

    def test_cp_08_no_loss_context_in_prompt(self, tmp_path):
        """The stage1b user prompt does not include loss-analysis context."""
        client = MockLLMClient()
        client.set_response_for(Stage1Profile, _valid_stage1_profile_dict())
        derive_capability_profile(
            llm_client=client,
            use_case_text="Test use case",
            run_dir=tmp_path,
        )
        assert len(client.calls) == 1
        user_prompt = client.calls[0].user_prompt
        assert "Loss Analysis Context" not in user_prompt
        assert "loss_analysis" not in user_prompt
        assert "all_losses" not in user_prompt
        assert "security_constraints" not in user_prompt

    def test_cp_09_kc_taxonomy_in_system_prompt(self):
        """The stage1b system prompt includes KC taxonomy markers."""
        content = (PROMPTS_DIR / "stage1b_system.j2").read_text()
        assert "KC1 — Language Models" in content
        assert "KC6 — Operational Environment" in content
        assert "KCX — Extended Capabilities" in content

    def test_cp_10_no_stpa_in_system_prompt(self):
        """The stage1b system prompt does not mention STPA."""
        content = (PROMPTS_DIR / "stage1b_system.j2").read_text()
        assert "STPA" not in content

    def test_cp_11_no_zones_active_in_system_prompt(self):
        """The stage1b system prompt does not request zones_active."""
        content = (PROMPTS_DIR / "stage1b_system.j2").read_text()
        assert "zones_active" not in content

    def test_cp_12_stage1_profile_no_bool_fields(self):
        """Stage1Profile model does not declare boolean capability fields."""
        field_names = set(S1P.model_fields.keys())
        assert "has_persistent_memory" not in field_names
        assert "multi_agent" not in field_names
        assert "hitl" not in field_names


class TestClassifyEntryPoint:
    """Truth table over controllability, direction and the name keywords."""

    @pytest.mark.parametrize(
        ("name", "direction", "controllability", "expected"),
        [
            # An explicit controllability wins over the name heuristic.
            ("RAG knowledge", "input", "direct", "direct"),
            ("user chat", "input", "indirect", "indirect"),
            # Direction decides before any keyword is read.
            ("alerts", "output", None, "system"),
            ("user response channel", "output", None, "system"),
            ("RAG knowledge-grounding", "bidirectional", None, "direct"),
            # Input direction: keywords, indirect then system, default direct.
            ("backend API", "input", None, "system"),
            ("user chat", "input", None, "direct"),
            ("RAG knowledge retrieval", "input", None, "indirect"),
            ("unknown channel", "input", None, "direct"),
        ],
    )
    def test_classification(self, name, direction, controllability, expected):
        assert classify_entry_point(name, direction, controllability) == expected

    def test_entry_point_is_frozen(self):
        entry_point = EntryPoint(name="test entry point", direction="input")
        with pytest.raises(ValidationError):
            entry_point.name = "changed name"
        with pytest.raises(ValidationError):
            entry_point.custom_field = "value"
