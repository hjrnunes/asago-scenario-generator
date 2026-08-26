"""Mutation hardening for the typed generation-stage seam."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from asago_scenario_generator.pipeline.generate.actor_semantics import ActorDraftV2
from asago_scenario_generator.pipeline.generate.actor_semantics import (
    ActorSemanticDraftError,
)
from asago_scenario_generator.pipeline.generate.stages import (
    GenerationRequest,
    RetryDirective,
    _AttemptRecordingClient,
    _actor_handle_map,
    _bounded_completion_cap,
    _classify_stage_exception,
    _compact_schema_requested,
    _optional_list,
    _resolved_int_control,
    _resolved_temperature,
    prepare_generation,
)
from asago_scenario_generator.pipeline.generation_contracts import CausalRetryControl
from asago_scenario_generator.models.scenario import ActorProfile, CallName
from tests.helpers.projection_factory import (
    get_projected_candidate,
    get_test_snapshot,
)


def test_non_positive_transport_caps_do_not_lower_operation_cap() -> None:
    for transport_cap in (0, -1, None, "not-an-integer"):
        assert (
            _bounded_completion_cap(
                SimpleNamespace(max_completion_tokens=transport_cap), 4096
            )
            == 4096
        )
    assert _bounded_completion_cap(SimpleNamespace(max_completion_tokens=1), 4096) == 1


def test_optional_list_uses_none_only_for_empty_values() -> None:
    assert _optional_list(()) is None
    assert _optional_list(["one"]) == ["one"]


def test_resolved_integer_control_prefers_explicit_valid_values() -> None:
    client = SimpleNamespace(max_completion_tokens=17)
    assert _resolved_int_control(None, client, "max_completion_tokens") == 17
    assert _resolved_int_control(9, client, "max_completion_tokens") == 9
    assert _resolved_int_control("9", client, "max_completion_tokens") is None


def test_resolved_temperature_prefers_explicit_valid_values() -> None:
    client = SimpleNamespace(temperature=0.2)
    assert _resolved_temperature(None, client) == 0.2
    assert _resolved_temperature(0.7, client) == 0.7
    assert _resolved_temperature("0.7", client) is None


def test_recorder_starts_uninvoked_and_unstructured_flag_false() -> None:
    recorder = _AttemptRecordingClient(MagicMock())

    assert recorder.invoked is False
    assert recorder._unstructured_response is False


def test_actor_handle_map_requires_one_resource_for_each_handle() -> None:
    draft = ActorDraftV2.model_construct(
        actor_type_handle="actor",
        capability_level_handle="capability",
        resource_handles=["resource-one", "resource-two"],
    )
    actor = ActorProfile(
        actor_type="cybercriminal",
        capability_level="novice",
        beliefs=["observe"],
        desires=["access"],
        intentions=["inject"],
        resources=["resource-one"],
    )

    with pytest.raises(ValueError):
        _actor_handle_map(draft, actor)


def test_compact_schema_is_requested_only_by_a_matching_retry_control() -> None:
    assert _compact_schema_requested(None) is False
    assert _compact_schema_requested(RetryDirective()) is False
    assert (
        _compact_schema_requested(
            RetryDirective(
                causal_control=CausalRetryControl(
                    control_id="other-control",
                    field="max_completion_tokens",
                    initial_value=4096,
                    retry_value=2048,
                )
            )
        )
        is False
    )
    assert (
        _compact_schema_requested(
            RetryDirective(
                causal_control=CausalRetryControl(
                    control_id="schema-control",
                    field="response_schema",
                    initial_value="standard",
                    retry_value="compact-v1",
                )
            )
        )
        is True
    )


def test_prepare_generation_rejects_zero_attempt_before_provider_setup() -> None:
    candidate = get_projected_candidate()
    snapshot = get_test_snapshot()
    request = GenerationRequest(
        seed=cast(Any, SimpleNamespace(threat_id="T2")),
        profile=snapshot.profile,
        client=cast(Any, MagicMock()),
        use_case="fixture",
        pinned_entry_point_id=candidate.canonical_ingress.entry_point_id,
        projected_candidate=candidate,
        capability_snapshot=snapshot,
        run_id="20260101T000000_0123456789abcdef0123456789abcdef",
        attempt=0,
    )

    with (
        patch(
            "asago_scenario_generator.pipeline.generate.assembly."
            "_build_projection_context",
            return_value={},
        ),
        patch(
            "asago_scenario_generator.pipeline.generate.tree_semantics."
            "validate_tree_projection_realizability",
        ),
        patch(
            "asago_scenario_generator.pipeline.generate.assembly."
            "compute_scenario_id",
            return_value="scenario:test",
        ),
        pytest.raises(ValueError, match="attempt must be >= 1"),
    ):
        prepare_generation(request)

    with (
        patch(
            "asago_scenario_generator.pipeline.generate.assembly."
            "_build_projection_context",
            return_value={},
        ),
        patch(
            "asago_scenario_generator.pipeline.generate.tree_semantics."
            "validate_tree_projection_realizability",
        ),
        patch(
            "asago_scenario_generator.pipeline.generate.assembly."
            "compute_scenario_id",
            return_value="scenario:test",
        ),
    ):
        prepared = prepare_generation(replace(request, attempt=1))
    assert prepared.request.attempt == 1


def test_protocol_classification_keeps_provider_protocol_evidence() -> None:
    with pytest.raises(ValidationError) as raised:
        ActorDraftV2.model_validate({})

    recorder = _AttemptRecordingClient(MagicMock())
    recorder.invoked = True
    code, retryable, evidence = _classify_stage_exception(
        raised.value,
        call_name=CallName.actor_profile,
        compiler_name="compile_actor_draft:v3",
        recorder=recorder,
        handle_map={},
        semantic_error_type=ActorSemanticDraftError,
        draft_types=(ActorDraftV2,),
    )

    assert code == "semantic_draft_protocol_failed"
    assert retryable is True
    assert evidence is not None
    assert (
        evidence.attempts[0].validation_violations[0].code
        == "provider_protocol"
    )
