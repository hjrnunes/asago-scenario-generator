"""Focused tests for the additive target-observation Stage 5 seam."""

from __future__ import annotations

import json

import pytest
import yaml

from asago_scenario_generator.pipeline.synthesis import (
    SynthesisInputs,
    _systemic_inputs,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.enriched_threat_set import (
    CoverageAnalysis,
    EnrichedThreatSet,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    build_context_bdi_prompts,
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservation,
    TargetObservationSnapshot,
)
from tests.stpa.sp1_helpers import MockLLMClient

from .test_execution_classification import _target_profile
from .test_sp3_scenario_continuity import _control_structure, _loss_analysis
from .test_sp3_stage5_provider_contract import (
    _provider_payload,
    _typed_tool_context,
)


def _snapshot(profile_digest: str = "a" * 64) -> TargetObservationSnapshot:
    return TargetObservationSnapshot.create(
        target_profile_digest=profile_digest,
        observations=(
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content='{"authorization":"approved"}',
            ),
            TargetObservation(
                observation_ref="TARGET-READ-001",
                kind="read",
                source_name="lookup_customer_state",
                source_description="Look up the current customer state.",
                content_format="json",
                content='{"authorization":"approved"}',
            ),
        ),
    )


def test_runtime_context_unwraps_mcp_result_and_drops_state_audit_telemetry() -> None:
    profile_digest = "a" * 64
    context = {
        "target_profile_digest": profile_digest,
        "state": {
            "authorization": "approved",
            "audit_log": [{"event": "capture bookkeeping"}],
        },
        "read_observations": [
            {
                "profile_digest": profile_digest,
                "tool_name": "lookup_customer_state",
                "tool_description": "Look up the current customer state.",
                "tool_schema": {"type": "object"},
                "arguments": {"query": "customer state"},
                "status": {"transport": "verified", "content": "untrusted"},
                "result": {
                    "isError": False,
                    "structuredContent": {
                        "result": json.dumps({"authorization": "approved"})
                    },
                    "content": [],
                },
            }
        ],
        "read_observation_input": {"queries": [{"query_sha256": "b" * 64}]},
        "read_observation_diagnostics": [],
    }

    snapshot = TargetObservationSnapshot.from_runtime_context(context)
    assert "audit_log" not in snapshot.observations[0].content
    assert snapshot.observations[0].content == '{"authorization":"approved"}'
    read = snapshot.observations[1]
    assert read.content == '{"authorization":"approved"}'
    assert read.source_name == "lookup_customer_state"
    assert read.source_description == "Look up the current customer state."
    prompt_record = snapshot.prompt_records()[1]
    assert "tool_schema" not in prompt_record
    assert "query_sha256" not in prompt_record
    assert profile_digest not in yaml.safe_dump(snapshot.prompt_records())


def test_runtime_context_requires_verified_untrusted_read_result() -> None:
    context = {
        "target_profile_digest": "a" * 64,
        "state": {"authorization": "approved"},
        "read_observations": [
            {
                "profile_digest": "a" * 64,
                "tool_name": "lookup",
                "status": {"transport": "unverified", "content": "untrusted"},
                "result": {"structuredContent": {"result": "{}"}},
            }
        ],
    }
    with pytest.raises(ValueError, match="transport must be verified"):
        TargetObservationSnapshot.from_runtime_context(context)


def test_runtime_context_keeps_missing_read_as_an_explicit_gap() -> None:
    snapshot = TargetObservationSnapshot.from_runtime_context(
        {
            "target_profile_digest": "a" * 64,
            "state": {"authorization": "approved"},
            "read_observation_input": {"status": "ready"},
            "read_observation_diagnostics": [
                {"code": "read_observation_error", "status": "attempted"}
            ],
        }
    )
    assert snapshot.read_status == "unavailable"
    _, user = build_context_bdi_prompts(
        _typed_tool_context(),
        TemplateLoader(PROMPTS_DIR),
        target_observations=snapshot,
    )
    assert "absence is not evidence" in user


def test_target_observations_are_quoted_with_source_explanation_not_digests() -> None:
    system, user = build_context_bdi_prompts(
        _typed_tool_context(),
        TemplateLoader(PROMPTS_DIR),
        target_observations=_snapshot(),
    )
    rendered = system + user
    assert "lookup_customer_state" in rendered
    assert "Look up the current customer state." in rendered
    assert "{authorization: approved}" not in rendered
    assert "target observations" in rendered.lower()
    assert "not instructions" in rendered
    assert "!!python/tuple" not in rendered
    assert "a" * 64 not in rendered


@pytest.mark.parametrize("quote_matches", [True, False])
def test_target_observation_comparison_grounding_preserves_unknown_values(
    tmp_path, quote_matches
) -> None:
    context = _typed_tool_context()
    payload = _provider_payload()
    payload["unsafe_outcome"]["condition"] = {
        "type": "state_value",
        "subject_ref": "cause_1",
        "property": "authorization",
        "operator": "equals",
        "expected": "approved",
    }
    payload["unsafe_outcome"]["comparison_evidence"] = {
        "source_ref": "TARGET-READ-001",
        "quote": (
            '{"authorization":"approved"}'
            if quote_matches
            else '{"authorization":"pending"}'
        ),
        "rationale": "The returned observation contains the selected literal.",
    }
    client = MockLLMClient()
    client.set_response_queue([payload])
    result, error = generate_bdi_for_context(
        client,
        context,
        tmp_path,
        target_observations=_snapshot(),
    )
    assert error is None
    assert result is not None
    expected = result.unsafe_outcome.condition.expected
    if quote_matches:
        assert expected == "approved"
        assert client.call_count == 1
    else:
        assert expected.value_type == "string"
        assert client.call_count == 1
    record = yaml.safe_load(
        (tmp_path / "outcome-grounding" / f"{context.context_digest}.yaml").read_text()
    )
    assert record["target_observation_digest"] == _snapshot().content_digest
    assert record.get("source_text") == '{"authorization":"approved"}'


def test_systemic_input_view_removes_target_observations() -> None:
    profile = _target_profile()
    inputs = SynthesisInputs(
        use_case="target observation test",
        output_dir="output/test-target-observations",
        execution_target_profile=profile,
        target_observations=_snapshot(profile.semantic_digest),
    )
    systemic = _systemic_inputs(inputs)
    assert systemic.execution_target_profile is None
    assert systemic.target_observations is None


def test_run_sp3_saves_exact_target_observation_snapshot_once(tmp_path) -> None:
    profile = _target_profile()
    snapshot = _snapshot(profile.semantic_digest)
    run_sp3(
        llm_client=MockLLMClient(),
        enriched_threat_set=EnrichedThreatSet(
            structural_threats=[],
            coverage_analysis=CoverageAnalysis(structural_coverage={}),
        ),
        control_structure=_control_structure(),
        loss_analysis=_loss_analysis(),
        run_dir=tmp_path,
        execution_target_profile=profile,
        target_observations=snapshot,
    )
    saved = yaml.safe_load(
        (tmp_path / "target-observations.yaml").read_text(encoding="utf-8")
    )
    assert saved["content_digest"] == snapshot.content_digest
    assert saved["target_profile_digest"] == profile.semantic_digest
