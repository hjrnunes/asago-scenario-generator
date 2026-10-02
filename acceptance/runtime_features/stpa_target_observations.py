"""Offline public Stage 5 acceptance for supplied target observations."""

import json
import re
from pathlib import Path
from tempfile import TemporaryDirectory

from runtime_shared import _make_sp3_cs, _make_sp3_loss_analysis, _make_sp3_threat

from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
    TargetOperationReference,
)
from asago_scenario_generator.pipeline.synthesis import SynthesisInputs
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.models.semantic_conditions import (
    SemanticBindingPlaceholder,
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    build_context_bdi_prompts,
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservationSnapshot,
)
from tests.stpa.sp1_helpers import MockLLMClient

from .stpa_execution_route import _route_payload


FEATURE_ID = "stpa_target_observations"


def _given_dispatch(world, step, examples):
    world.observation_mode = re.search(r'"([^"]+)"', step).group(1)
    structure = _make_sp3_cs()
    structure.responsibilities[0].description = "Control sample dispatch"
    structure.responsibilities[0].control_actions[0].description = "Dispatch samples"
    threat = _make_sp3_threat(slot_id="RESP-1:CA-1-1:INCORRECT")
    threat.ica_text = "Dispatch samples exceeding the available capacity."
    threat.hazardous_context = (
        "The requested quantity exceeds available dispatch capacity."
    )
    threat.loss_scenario = "Samples are damaged during dispatch."
    world.observation_context = build_scenario_generation_context(
        threat, structure, _make_sp3_loss_analysis(), scenario_id="SCN-001"
    )
    world.observation_before = world.observation_context.model_dump(mode="json")
    world.observation_snapshot = TargetObservationSnapshot.from_runtime_context(
        {
            "target_profile_digest": "a" * 64,
            "state": {"dispatch_capacity": 80},
            "read_observation_input": {"source_query": "PRIVATE-SOURCE-QUERY"},
        }
    )
    world.dispatch_operation = TargetOperationObservation(
        reference=TargetOperationReference(
            resource_id="dispatch-interface", operation_id="dispatch"
        ),
        description="Dispatch the requested quantity of samples.",
        input_schema={
            "type": "object",
            "properties": {"quantity": {"type": "integer"}},
            "required": ["quantity"],
        },
        effect="execute",
        state_effect="changes",
    )
    return True, ""


def _compile_dispatch(world, step, examples):
    payload = _route_payload(
        {
            "disposition": "executable_route",
            "action_kind": "tool_call",
            "reason": "Dispatch operation.",
        }
    )
    payload["unsafe_outcome"] = {
        "condition": {
            "type": "action_value",
            "control_action_id": "CA-1-1",
            "property": "quantity",
            "operator": "greater_than",
            "expected": 80,
        },
        "semantic_proposition": "The dispatched quantity exceeds the observed available capacity.",
        "comparison_evidence": {
            "source_ref": "TARGET-STATE",
            "quote": "81" if world.observation_mode == "wrong_quote" else "80",
            "rationale": "The supplied state records the capacity; rule interpretation remains a claim.",
        },
    }

    client = MockLLMClient(model="offline-observation-contract")
    client.set_response_queue([payload])

    observations = (
        None if world.observation_mode == "missing" else world.observation_snapshot
    )
    with TemporaryDirectory(prefix="target-observation-acceptance-") as directory:
        result, error = generate_bdi_for_context(
            client,
            world.observation_context,
            Path(directory),
            target_operation=world.dispatch_operation,
            target_observations=observations,
        )
    assert error is None, error
    assert result is not None
    assert client.call_count == 1
    world.dispatch_comparison = result.unsafe_outcome.condition.expected
    return True, ""


def _check_dispatch(world, step, examples):
    expected = re.search(r'"([^"]+)"', step).group(1)
    value = world.dispatch_comparison
    if expected == "literal":
        assert value == 80
    else:
        assert isinstance(value, SemanticBindingPlaceholder)
    assert world.observation_context.model_dump(mode="json") == world.observation_before
    return True, ""


def _render_dispatch(world, step, examples):
    prompts = build_context_bdi_prompts(
        world.observation_context,
        TemplateLoader(PROMPTS_DIR),
        target_operation=world.dispatch_operation,
        target_observations=world.observation_snapshot,
    )
    world.observation_prompts = "\n".join(prompts)
    return True, ""


def _check_prompt(world, step, examples):
    text = world.observation_prompts
    assert "TARGET-STATE" in text
    assert "dispatch_capacity" in text
    assert "80" in text
    assert "PRIVATE-SOURCE-QUERY" not in text
    assert world.observation_snapshot.content_digest not in text
    assert world.observation_snapshot.target_profile_digest not in text
    assert "observation" in text.lower()
    return True, ""


def _pair_other_target(world, step, examples):
    fixture = Path(__file__).resolve().parents[2] / (
        "data/contracts/target-profile/target-profile-v1/valid/minimal.json"
    )
    profile = ExecutionTargetProfile.model_validate(json.loads(fixture.read_text()))
    world.observation_pair_error = None
    with TemporaryDirectory(prefix="observation-pair-acceptance-") as directory:
        try:
            SynthesisInputs(
                use_case="Dispatch samples",
                risk_cards=(),
                qualification_facts={},
                output_dir=Path(directory),
                execution_target_profile=profile,
                target_observations=world.observation_snapshot,
            )
        except ValueError as error:
            world.observation_pair_error = str(error)
    return True, ""


def _check_pair_rejection(world, step, examples):
    assert world.observation_pair_error is not None
    assert "profile pin does not match" in world.observation_pair_error
    return True, ""


def register(api):
    api.register(
        r'^a dispatch scenario with target observation mode "[^"]+"$', _given_dispatch
    )
    api.register(
        r"^Stage 5 compiles the observed dispatch comparison$", _compile_dispatch
    )
    api.register(
        r'^the dispatch comparison is "[^"]+" and the systemic context is unchanged$',
        _check_dispatch,
    )
    api.register(
        r"^Stage 5 renders the target observation companion$", _render_dispatch
    )
    api.register(
        r"^the dispatch prompt explains the observations without their digest or source query$",
        _check_prompt,
    )
    api.register(
        r"^the dispatch observations are paired with a different target profile$",
        _pair_other_target,
    )
    api.register(
        r"^the product input rejects the target observation mismatch$",
        _check_pair_rejection,
    )
