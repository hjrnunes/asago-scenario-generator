"""Focused tests for the additive target-observation Stage 5 seam."""

from __future__ import annotations

import json

import pytest
import yaml

from asago_scenario_generator.pipeline.synthesis import SynthesisInputs
from asago_scenario_generator.pipeline.synthesis_types import _systemic_inputs
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.enriched_threat_set import (
    CoverageAnalysis,
    EnrichedThreatSet,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionSurface,
    TargetProfileOperation,
    TargetProfileResource,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservation,
    TargetObservationSnapshot,
)
from tests.stpa.sp1_helpers import MockLLMClient

from tests.helpers.execution_classification import (
    _simulation_profile,
    _simulation_resource,
    _target_profile,
)
from tests.helpers.sp3_scenario_continuity import _control_structure, _loss_analysis
from tests.helpers.sp3_stage5_provider_contract import _typed_tool_context


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


def test_runtime_context_rejects_non_string_argument_values() -> None:
    """Captured invocation arguments are a string mapping: a number, boolean,
    or nested value is a capture defect, never coerced into prompt text."""
    context = {
        "target_profile_digest": "a" * 64,
        "state": {"authorization": "approved"},
        "read_observations": [
            {
                "profile_digest": "a" * 64,
                "tool_name": "lookup",
                "arguments": {"query": 42},
                "status": {"transport": "verified", "content": "untrusted"},
                "result": {"structuredContent": {"result": "{}"}},
            }
        ],
    }
    with pytest.raises(ValueError, match="arguments must be a string mapping"):
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


def test_stage5_prompt_renders_complete_bound_operation_inventory() -> None:
    profile = _target_profile()
    system, user = build_context_bdi_prompts(
        _typed_tool_context(),
        TemplateLoader(PROMPTS_DIR),
        execution_target_profile=profile,
    )

    rendered = f"{system}\n{user}"
    assert "operation_name: retrieve-1" in rendered
    assert "description: Retrieve content for the model context." in rendered
    assert "argument_names: []" in rendered
    assert "input_schema:" in rendered
    assert "likely_effect: unknown" in rendered
    assert "likely_state_effect: unknown" in rendered
    assert "!!python" not in rendered


def test_stage5_prompt_renders_multiple_operations_and_interface_metadata() -> None:
    payload = _simulation_resource("sim:update-2").model_dump(mode="python")
    payload.update(
        {
            "description": "Update the selected order.",
            "input_schema": {
                "type": "object",
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
                "additionalProperties": False,
            },
            "output_schema": {
                "type": "object",
                "properties": {"status": {"type": "string"}},
            },
            "annotations": {
                "readOnlyHint": False,
                "destructiveHint": True,
            },
            "surfaces": (ExecutionSurface.tool_call, ExecutionSurface.tool_result),
            "operations": (
                TargetProfileOperation(
                    operation_id="update-2",
                    semantic_operation="update-2",
                    argument_names=("order_id",),
                ),
            ),
        }
    )
    update_resource = TargetProfileResource.model_validate(payload)
    profile = _simulation_profile(
        (_simulation_resource(), update_resource),
    )

    _, user = build_context_bdi_prompts(
        _typed_tool_context(),
        TemplateLoader(PROMPTS_DIR),
        execution_target_profile=profile,
    )

    assert "operation_name: retrieve-1" in user
    assert "operation_name: update-2" in user
    assert "resource_id: sim:update-2" in user
    assert "description: Update the selected order." in user
    assert "argument_names:" in user
    assert "  - order_id" in user
    assert "output_schema:" in user
    assert "annotations:" in user
    assert "destructiveHint: true" in user
    assert "surfaces:" in user
    assert "  - tool_call" in user
    assert "  - tool_result" in user
    assert "!!python" not in user


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


def _observation(ref: str, kind: str = "read") -> dict:
    return {
        "observation_ref": ref,
        "kind": kind,
        "content_format": "json",
        "content": '{"authorization":"approved"}',
    }


def _snapshot_payload(*observations: dict, **changes) -> dict:
    payload = {
        "target_profile_digest": "a" * 64,
        "observations": list(observations),
        "read_status": "observed",
        "content_digest": "b" * 64,
    }
    payload.update(changes)
    return payload


_STATE = _observation("TARGET-STATE", "state")
_READ_1 = _observation("TARGET-READ-001")
_READ_2 = _observation("TARGET-READ-002")


class TestTargetObservationSnapshotValidation:
    def test_created_snapshots_validate_with_and_without_reads(self) -> None:
        with_reads = _snapshot()
        state_only = TargetObservationSnapshot.create(
            target_profile_digest="a" * 64,
            observations=(TargetObservation.model_validate(_STATE),),
        )

        assert with_reads.read_status == "observed"
        assert state_only.read_status == "not_requested"
        assert TargetObservationSnapshot.model_validate(state_only.model_dump()) == (
            state_only
        )

    def test_unavailable_status_is_accepted_without_reads(self) -> None:
        snapshot = TargetObservationSnapshot.create(
            target_profile_digest="a" * 64,
            observations=(TargetObservation.model_validate(_STATE),),
            read_status="unavailable",
        )

        assert snapshot.read_status == "unavailable"

    def test_duplicate_references_are_rejected(self) -> None:
        payload = _snapshot_payload(_STATE, _READ_1, _READ_1)

        with pytest.raises(ValueError, match="references must be unique"):
            TargetObservationSnapshot.model_validate(payload)

    def test_missing_state_observation_is_rejected(self) -> None:
        payload = _snapshot_payload(_READ_1)

        with pytest.raises(ValueError, match="exactly one TARGET-STATE"):
            TargetObservationSnapshot.model_validate(payload)

    def test_two_state_observations_are_rejected(self) -> None:
        payload = _snapshot_payload(
            _STATE,
            _observation("TARGET-READ-001", "state"),
            read_status="not_requested",
        )

        with pytest.raises(ValueError, match="exactly one TARGET-STATE"):
            TargetObservationSnapshot.model_validate(payload)

    def test_read_references_must_follow_state_in_order(self) -> None:
        payload = _snapshot_payload(_STATE, _READ_2, _READ_1)

        with pytest.raises(ValueError, match="deterministic state/read order"):
            TargetObservationSnapshot.model_validate(payload)

    def test_observed_status_requires_a_read(self) -> None:
        payload = _snapshot_payload(_STATE, read_status="observed")

        with pytest.raises(ValueError, match="observed read_status requires"):
            TargetObservationSnapshot.model_validate(payload)

    @pytest.mark.parametrize("status", ["not_requested", "unavailable"])
    def test_reads_require_observed_status(self, status) -> None:
        payload = _snapshot_payload(_STATE, _READ_1, read_status=status)

        with pytest.raises(ValueError, match="require read_status=observed"):
            TargetObservationSnapshot.model_validate(payload)

    def test_wrong_content_digest_is_rejected(self) -> None:
        payload = _snapshot_payload(_STATE, _READ_1)

        with pytest.raises(ValueError, match="content_digest does not match"):
            TargetObservationSnapshot.model_validate(payload)


def _nested(depth: int) -> dict:
    value: dict = {}
    for _ in range(depth):
        value = {"k": value}
    return value


@pytest.mark.parametrize(
    ("state", "message"),
    (
        (_nested(9), r"state\.k\.k\.k\.k\.k\.k\.k\.k\.k exceeds JSON depth limit"),
        ({"items": list(range(300))}, r"state\.items\[\d+\] exceeds JSON node limit"),
        ({"items": {1: "a"}}, r"state\.items has a non-string JSON key"),
        ({"items": {"a", "b"}}, r"state\.items contains a non-JSON value"),
    ),
)
def test_runtime_context_rejects_unbounded_or_non_json_state(state, message) -> None:
    with pytest.raises(ValueError, match=message):
        TargetObservationSnapshot.from_runtime_context(
            {"target_profile_digest": "a" * 64, "state": state}
        )
