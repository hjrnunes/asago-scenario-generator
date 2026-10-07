"""Focused regressions for Stage 5 feedback interpretation guidance."""

from __future__ import annotations

import pytest
import yaml

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.causal_factor import (
    CausalEvidenceStatus,
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionDeliveryClass,
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.stage5.sources import (
    _causal_source_choices,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    _context_source_choices_yaml,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservation,
    TargetObservationSnapshot,
)
from tests.stpa.sp1_helpers import MockLLMClient

from .test_sp3_stage5_provider_contract import (
    _provider_payload,
    _typed_tool_context,
)


def test_stage5_prompt_separates_negative_feedback_from_sensor_anomaly() -> None:
    """An accurate negative result misread by a controller is a PM flaw."""
    system, user = build_context_bdi_prompts(
        _typed_tool_context(), TemplateLoader(PROMPTS_DIR)
    )
    rendered = " ".join(f"{system}\n{user}".split())
    source_view = rendered.split("## Allowed Causal-Factor Sources", 1)[1].split(
        "## Allowed Stimulus Categories", 1
    )[0]

    assert "negative or empty feedback result can be valid" in rendered
    assert "misinterprets an accurate negative/empty result" in rendered
    assert "select the supplied `PROCESS_MODEL_FLAW` handle" in rendered
    assert (
        "Select `SENSOR_ANOMALY` only when the supplied context either establishes"
        in rendered
    )
    assert "prospective corruption/misreporting mechanism" in rendered
    assert "this is not proof that corruption already occurred" in rendered
    assert "infer attacker influence from a negative/empty result" in rendered
    assert "feedback itself misreports a known fact" in source_view
    assert (
        "interpretation of an accurate result belongs to the process-model"
        in source_view
    )
    assert rendered.count("A negative or empty feedback result can be valid") == 1


def test_tool_action_does_not_imply_tool_result_injection() -> None:
    system, user = build_context_bdi_prompts(
        _typed_tool_context(), TemplateLoader(PROMPTS_DIR)
    )
    rendered = " ".join(f"{system}\n{user}".split())
    assert "delivery is independent of the target action kind" in rendered
    assert "a user message can lead to a model output, tool call" in rendered
    assert "not the authored stimulus or an additional sensor fault" in rendered
    assert "For a model-output action, when that process-model flaw" not in rendered


def test_stage5_source_view_closes_factor_stimulus_choices() -> None:
    """The prompt exposes route compatibility without making factors routes."""
    system, user = build_context_bdi_prompts(
        _typed_tool_context(), TemplateLoader(PROMPTS_DIR)
    )
    rendered = " ".join(f"{system}\n{user}".split())
    context = _typed_tool_context()
    choices = yaml.safe_load(
        _context_source_choices_yaml(_causal_source_choices(context))
    )
    by_handle = {item["source_handle"]: item for item in choices}

    assert by_handle["cause_1"]["compatible_stimulus_categories"] == [
        "user_message",
        "conversation",
        "conversation_context",
        "retrieved_content",
        "tool_content",
    ]
    assert by_handle["cause_2"]["compatible_stimulus_categories"] == [
        "conversation",
        "conversation_context",
    ]
    assert by_handle["cause_3"]["compatible_stimulus_categories"] == [
        "retrieved_content",
        "tool_content",
    ]
    assert by_handle["cause_4"]["compatible_stimulus_categories"] == []
    assert by_handle["cause_4"]["route_instruction"].startswith("analytical_only")
    assert "factor source never selects the execution route" in rendered


def test_stage5_prompt_bounds_feedback_and_actuator_interpretation() -> None:
    system, user = build_context_bdi_prompts(
        _typed_tool_context(), TemplateLoader(PROMPTS_DIR)
    )
    rendered = " ".join(f"{system}\n{user}".split())

    assert "already wrong or stale process-model belief" in rendered
    assert "actual earlier authored turn or event that initiated the update" in rendered
    assert (
        "A message merely arriving before the target action is not an `ACTUATOR_ANOMALY`"
        in rendered
    )
    assert "A direct `user_message` must stand alone" in rendered


@pytest.mark.parametrize("status", tuple(item.value for item in CausalEvidenceStatus))
def test_stage5_rejects_status_only_evidence_and_retries(tmp_path, status: str) -> None:
    invalid = _provider_payload()
    invalid["causal_factors"][0]["evidence"] = status
    valid = _provider_payload()
    valid["causal_factors"][0]["evidence"] = (
        "The selected process-model state remains stale for this invocation."
    )
    client = MockLLMClient()
    client.set_response_queue([invalid, valid])

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
    client.set_response_queue([payload])

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
    assert "not an attacker-controlled stimulus by itself" in rendered
    assert "background evidence" in rendered
    assert "unchanged target returns" in rendered


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


@pytest.mark.parametrize("stimulus_category", ("retrieved_content", "tool_content"))
def test_accurate_background_read_cannot_establish_indirect_access(
    tmp_path, stimulus_category
):
    payload = _route_payload("cause_1", stimulus_category)
    payload["causal_factors"][0]["evidence"] = (
        "The trusted lookup accurately returns no match; the controller misreads it."
    )
    client = MockLLMClient()
    client.set_response_queue([payload, payload])
    result, error = generate_bdi_for_context(client, _typed_tool_context(), tmp_path)
    assert result is None
    assert "indirect stimulus requires" in error
    assert client.call_count == 2


@pytest.mark.parametrize(
    ("source_handle", "stimulus_category", "source_kind", "delivery_class"),
    (
        (
            "cause_1",
            "user_message",
            CausalFactorKind.process_model_flaw,
            ExecutionDeliveryClass.direct_prompt,
        ),
        (
            "cause_3",
            "retrieved_content",
            CausalFactorKind.sensor_anomaly,
            ExecutionDeliveryClass.indirect_content,
        ),
    ),
)
def test_stage5_public_compiler_preserves_supported_factor_delivery_pair(
    tmp_path,
    source_handle,
    stimulus_category,
    source_kind,
    delivery_class,
) -> None:
    """Valid PM/direct and true sensor/indirect routes remain executable."""
    client = MockLLMClient()
    payload = _route_payload(source_handle, stimulus_category)
    if stimulus_category == "retrieved_content":
        payload["causal_factors"][0].update(
            evidence_status="bounded_assumption",
            bounded_assumption="The supplied retrieval path permits test-controlled content.",
        )
    client.set_response_queue([payload])

    result, error = generate_bdi_for_context(
        client,
        _typed_tool_context(),
        tmp_path,
    )

    assert error is None
    assert result is not None
    assert result.causal_factors[0].kind is source_kind
    assert result.execution_contract is not None
    assert result.execution_contract.delivery is not None
    assert result.execution_contract.delivery.delivery_class is delivery_class
