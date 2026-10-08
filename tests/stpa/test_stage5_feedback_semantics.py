"""Focused regressions for Stage 5 feedback interpretation guidance."""

from __future__ import annotations


from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservation,
    TargetObservationSnapshot,
)

from tests.helpers.sp3_stage5_provider_contract import (
    _provider_payload,
    _typed_tool_context,
)
from asago_scenario_generator.stpa.models.causal_factor import CausalEvidenceStatus
from tests.stpa.sp1_helpers import MockLLMClient
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    generate_bdi_for_context,
)
import pytest
from tests.stpa.stage5_wire import normal_wire_queue


def test_stage5_prompt_separates_negative_feedback_from_sensor_anomaly() -> None:
    """An accurate negative result misread by a controller is a PM flaw."""
    system, user = build_context_bdi_prompts(
        _typed_tool_context(), TemplateLoader(PROMPTS_DIR)
    )
    rendered = " ".join(f"{system}\n{user}".split())
    source_view = rendered.split("## Allowed Causal-Factor Sources", 1)[1].split(
        "## Allowed Stimulus Categories", 1
    )[0]

    assert "feedback itself misreports a known fact" in source_view
    assert (
        "interpretation of an accurate result belongs to the process-model"
        in source_view
    )


@pytest.mark.parametrize("status", tuple(item.value for item in CausalEvidenceStatus))
def test_stage5_rejects_status_only_evidence_and_retries(tmp_path, status: str) -> None:
    invalid = _provider_payload()
    invalid["causal_factors"][0]["evidence"] = status
    valid = _provider_payload()
    valid["causal_factors"][0]["evidence"] = (
        "The selected process-model state remains stale for this invocation."
    )
    client = MockLLMClient()
    client.set_response_queue(normal_wire_queue([invalid, valid]))

    result, error = generate_bdi_for_context(client, _typed_tool_context(), tmp_path)

    assert error is None
    assert result is not None
    assert client.call_count == 2


def test_stage5_allows_status_word_inside_explanatory_evidence(tmp_path) -> None:
    payload = _provider_payload()
    payload["causal_factors"][0]["evidence"] = (
        "The structural_failure status describes a stale process-model state."
    )
    client = MockLLMClient()
    client.set_response_queue(normal_wire_queue([payload]))

    result, error = generate_bdi_for_context(client, _typed_tool_context(), tmp_path)

    assert error is None
    assert result is not None
    assert result.causal_factors[0].evidence == payload["causal_factors"][0]["evidence"]


def test_stage5_observation_view_keeps_empty_read_as_quoted_feedback() -> None:
    """A neutral empty read is evidence to interpret, not an attack claim."""
    snapshot = TargetObservationSnapshot.create(
        target_profile_digest="a" * 64,
        observations=(
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content='{"status":"ready"}',
            ),
            TargetObservation(
                observation_ref="TARGET-READ-001",
                kind="read",
                source_name="lookup_records",
                source_description="Look up records for the supplied query.",
                content_format="json",
                content='{"items":[],"status":"not_found"}',
            ),
        ),
    )
    _system, user = build_context_bdi_prompts(
        _typed_tool_context(),
        TemplateLoader(PROMPTS_DIR),
        target_observations=snapshot,
    )
    rendered = " ".join(user.split())

    assert "TARGET-READ-001" in rendered
    assert '"items":[],"status":"not_found"' in rendered


def _route_payload(source_handle: str, stimulus_category: str) -> dict:
    payload = _provider_payload()
    payload["stimulus"] = {
        "category": stimulus_category,
        "description": "The supplied delivery carries the causal condition.",
    }
    payload["causal_factors"][0]["source_handle"] = source_handle
    payload["causal_factors"][0]["evidence"] = (
        "The selected source contributes to the unsafe action."
    )
    payload["attacker_bdi"]["intentions"][0]["source_handles"] = [source_handle]
    return payload
