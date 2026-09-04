"""Offline public-boundary acceptance for captured prompt-contract failures."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx
import yaml
from openai import OpenAI
from pydantic import BaseModel

from runtime_shared import (
    World,
    _make_sp3_contextual_scenario_spec,
    _make_sp3_cs,
    _make_sp3_loss_analysis,
    _make_sp3_threat,
)

from asago_scenario_generator.pipeline.synthesis import (
    SynthesisAdapters,
    SynthesisInputs,
    run_synthesis,
)
from asago_scenario_generator.stpa.infra.llm import LLMClient, LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_synthesis_slot_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from asago_scenario_generator.stpa.scenario_prod.gherkin import generate_gherkin
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    run_revision,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots

from .stpa_execution_route import _route_payload
from .synthesis import _FakeSynthesis

FEATURE_ID = "prompt_contract_recovery"


def _state(world: World) -> dict[str, Any]:
    if not hasattr(world, "prompt_recovery_state"):
        world.prompt_recovery_state = {}
    return world.prompt_recovery_state


class _Reply:
    model = "offline-recovery-fixture"

    def __init__(self, payloads: list[Any]) -> None:
        self.payloads = payloads
        self.requests: list[dict[str, Any]] = []

    def complete(self, **kwargs: Any) -> LLMResult:
        index = min(len(self.requests), len(self.payloads) - 1)
        self.requests.append(kwargs)
        return LLMResult(
            content=self.payloads[index],
            prompt_tokens=11,
            completion_tokens=7,
            duration_ms=1,
            system_prompt=kwargs["system_prompt"],
            user_prompt=kwargs["user_prompt"],
        )


def _revision_fixture(world: World, text: str, examples: dict) -> tuple[bool, str]:
    mode = re.findall(r'"([^"]+)"', text)[0]
    empty = {
        "new_responsibilities": [],
        "new_controlled_processes": [],
        "new_coordination_links": [],
        "modified_responsibilities": [],
        "dismissed_gaps": [],
    }
    malformed = {
        **empty,
        "new_coordination_links": [
            {"cl_id": "CL-1", "description": "Missing mechanism"}
        ],
    }
    _state(world)["provider"] = _Reply(
        [malformed, empty] if mode == "correct" else [malformed]
    )
    return True, ""


def _revision_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _state(world)
    baseline = _make_sp3_cs()
    with tempfile.TemporaryDirectory(prefix="prompt-recovery-revision-") as path:
        result, warnings = run_revision(
            llm_client=state["provider"],
            control_structure=baseline,
            critic_findings=CriticFindings(),
            use_case_text="An offline controlled process",
            run_dir=Path(path),
            loss_analysis=_make_sp3_loss_analysis(),
        )
    state.update(baseline=baseline, revised=result, warnings=warnings)
    return True, ""


def _revision_count(world: World, text: str, examples: dict) -> tuple[bool, str]:
    expected = int(re.search(r"uses (\d+)", text).group(1))
    state = _state(world)
    actual = len(state["provider"].requests)
    ok = actual == expected and state["revised"] == state["baseline"]
    return (
        ok,
        f"responses={actual}; baseline retained={state['revised'] == state['baseline']}",
    )


def _revision_no_crash(world: World, text: str, examples: dict) -> tuple[bool, str]:
    warnings = " ".join(_state(world)["warnings"])
    return "NoneType" not in warnings and "merge degraded" not in warnings, warnings


def _timing_fixture(world: World, text: str, examples: dict) -> tuple[bool, str]:
    payload = _make_sp3_cs().model_dump(mode="json")
    timing = re.findall(r'"([^"]+)"', text)[0]
    for action in payload["responsibilities"][0]["control_actions"]:
        action["temporality"] = timing
    _state(world)["structure"] = ControlStructure.model_validate(payload)
    return True, ""


def _ica_render(world: World, text: str, examples: dict) -> tuple[bool, str]:
    structure = _state(world)["structure"]
    system, user = build_synthesis_slot_prompts(
        target_id="RESP-1",
        slots=create_slots(structure),
        routed_briefs=(),
        routed_routes=(),
        loss_analysis=_make_sp3_loss_analysis(),
        control_structure=structure,
    )
    _state(world).update(ica_system=system, ica_user=user)
    return True, ""


def _ica_timing(world: World, text: str, examples: dict) -> tuple[bool, str]:
    expected = re.findall(r'"([^"]+)"', text)[0]
    user = _state(world)["ica_user"]
    return (
        f"action_temporality: {expected}" in user,
        "authoritative timing is absent from the user input",
    )


def _ica_example(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return "the supplied loss consequence occurs" not in _state(world)[
        "ica_system"
    ], "ICA example still contains placeholder prose"


def _route_fixture(world: World, text: str, examples: dict) -> tuple[bool, str]:
    stimulus, delivery, action = re.findall(r'"([^"]+)"', text)
    payload = _make_sp3_cs(include_resp2=True).model_dump(mode="json")
    target = payload["responsibilities"][0]["control_actions"][0]
    target["effect_kind"] = action
    if action == "agent_message":
        target["target"] = {"type": "responsibility", "id": "RESP-2"}
    context = build_scenario_generation_context(
        _make_sp3_threat(),
        ControlStructure.model_validate(payload),
        _make_sp3_loss_analysis(),
        scenario_id="SCN-001",
    )
    if stimulus in {"file_upload", "traffic_load"}:
        route = {
            "disposition": "analytical_only",
            "gaps": [
                {
                    "code": "delivery_path_missing",
                    "detail": "No supported execution primitive exists for this stimulus.",
                    "evidence_handles": ["cause_1"],
                }
            ],
            "reason": "The stimulus remains useful analysis but is not executable.",
        }
    else:
        route = {
            "disposition": "executable_route",
            "delivery_class": delivery,
            "selected_factor_handle": "cause_1",
            "action_kind": action,
            "reason": "The stated stimulus exercises the selected controller belief.",
        }
    response = _route_payload(route)
    response["stimulus"] = {
        "category": stimulus,
        "description": "Exercise the selected stale authorization belief through the stated input.",
    }
    _state(world).update(route_context=context, route_provider=_Reply([response]))
    return True, ""


def _route_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _state(world)
    with tempfile.TemporaryDirectory(prefix="prompt-recovery-route-") as path:
        result, error = generate_bdi_for_context(
            state["route_provider"], state["route_context"], Path(path)
        )
    state.update(route_result=result, route_error=error)
    return result is not None and error is None, str(error)


def _route_check(world: World, text: str, examples: dict) -> tuple[bool, str]:
    disposition, purposes = re.findall(r'"([^"]+)"', text)
    contract = _state(world)["route_result"].execution_contract
    actual = (
        ",".join(sorted(item.purpose.value for item in contract.resource_requirements))
        or "none"
    )
    return (
        contract.disposition == disposition and actual == purposes,
        f"{contract.disposition}: {actual}",
    )


def _sdk_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    class Expected(BaseModel):
        required: int

    raw = '{"required":"not-an-integer"}'

    def reply(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "offline-reply",
                "object": "chat.completion",
                "created": 1,
                "model": "offline",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": raw},
                    }
                ],
                "usage": {
                    "prompt_tokens": 11,
                    "completion_tokens": 7,
                    "total_tokens": 18,
                },
            },
        )

    with httpx.Client(transport=httpx.MockTransport(reply)) as http_client:
        sdk = OpenAI(
            api_key="offline-test",
            base_url="https://offline.invalid/v1",
            http_client=http_client,
        )
        with patch("asago_scenario_generator.stpa.infra.llm.OpenAI", return_value=sdk):
            client = LLMClient(
                api_key="offline-test",
                base_url="https://offline.invalid/v1",
                model="offline",
            )
        with tempfile.TemporaryDirectory(prefix="prompt-recovery-sdk-") as path:
            safe_llm_call(
                llm_client=client,
                system_prompt="Return the required integer.",
                user_prompt="Use one JSON object.",
                response_format=Expected,
                run_dir=Path(path),
                stage="stage_5",
                step="bdi_generation",
                scenario_id="SCN-001",
            )
            record = json.loads(
                (Path(path) / "calls.jsonl").read_text().splitlines()[-1]
            )
    _state(world).update(sdk_record=record, sdk_raw=raw)
    return True, ""


def _sdk_check(world: World, text: str, examples: dict) -> tuple[bool, str]:
    state = _state(world)
    record = state["sdk_record"]
    ok = (
        record["provider_response_received"]
        and not record["success"]
        and record["response_content"] == state["sdk_raw"]
        and record["prompt_tokens"] == 11
        and record["completion_tokens"] == 7
    )
    return ok, f"incomplete receipt evidence: {record}"


def _gherkin_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    spec = _make_sp3_contextual_scenario_spec()
    reply = yaml.safe_dump(
        {
            "feature": "Authorization",
            "scenario": "Missing required action",
            "given": ["Given a pending request"],
            "when": ["When the decision occurs"],
            "then_expected": ["Then the action should comply"],
            "then_actual": ["But the action does not occur"],
        }
    )
    with tempfile.TemporaryDirectory(prefix="prompt-recovery-gherkin-") as path:
        result, _, error = generate_gherkin(
            _Reply([reply]), spec, _make_sp3_loss_analysis(), Path(path)
        )
    _state(world).update(gherkin=result, gherkin_error=error)
    return result is not None and error is None, str(error)


def _gherkin_check(world: World, text: str, examples: dict) -> tuple[bool, str]:
    result = _state(world)["gherkin"]
    given = " ".join(result.given)
    outcome = " ".join(result.when + result.then_actual)
    return (
        "PM-1-1" in given and "CA-1-1" in outcome,
        "canonical state or selected action is missing",
    )


def _counts_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    class Adapters(_FakeSynthesis):
        def scenarios(self, **kwargs: Any) -> Any:
            return SimpleNamespace(
                scenario_envelopes=("scenario-1",),
                stage_errors=("one", "two", "three", "four"),
                candidate_outcomes=tuple(
                    SimpleNamespace(
                        scenario_id=f"SCN-{i:03d}",
                        ica_slot_id=f"RESP-{i}:CA-{i}-1:INCORRECT",
                        ica_id=f"ICA-{i}",
                        status=status,
                        diagnostics=(),
                    )
                    for i, status in enumerate(
                        (
                            "published",
                            "generation_failed",
                            "rendering_failed",
                            "skipped",
                        ),
                        1,
                    )
                ),
            )

    with tempfile.TemporaryDirectory(prefix="prompt-recovery-counts-") as path:
        inputs = SynthesisInputs(
            use_case="An offline authorization service",
            risk_cards=(SimpleNamespace(risk_id="risk-1"),),
            qualification_facts={"facts": []},
            output_dir=Path(path),
            capability_profile="profile",
            taxonomy_inputs="fixture",
        )
        result = run_synthesis(
            inputs, SynthesisAdapters.from_object(Adapters("not_required"))
        )
    _state(world)["counts"] = result.manifest["scenario_counts"]
    return True, ""


def _counts_check(world: World, text: str, examples: dict) -> tuple[bool, str]:
    expected = dict(
        zip(
            (
                "generated",
                "failed",
                "requested",
                "attempted",
                "skipped",
                "diagnostic_count",
            ),
            map(int, re.findall(r"\d+", text)),
        )
    )
    actual = _state(world)["counts"]
    return actual == expected, f"counts {actual} != {expected}"


def register(api: Any) -> None:
    registrations = (
        (r'^a recovery revision provider in "[^"]+" mode$', _revision_fixture),
        (r"^the public revision boundary is exercised$", _revision_run),
        (
            r"^revision recovery uses \d+ responses and retains the baseline$",
            _revision_count,
        ),
        (r"^revision recovery reports no missing-mechanism crash$", _revision_no_crash),
        (r'^a recovery control action with temporality "[^"]+"$', _timing_fixture),
        (r"^the public synthesis ICA prompt is rendered$", _ica_render),
        (r'^its supplied timing value is "[^"]+"$', _ica_timing),
        (
            r"^its causal example contains no placeholder loss consequence$",
            _ica_example,
        ),
        (
            r'^a recovery stimulus "[^"]+" with delivery "[^"]+" and action "[^"]+"$',
            _route_fixture,
        ),
        (
            r"^the public Stage 5 boundary is exercised without provider role guesses$",
            _route_run,
        ),
        (
            r'^the recovery contract disposition is "[^"]+" with resource purposes "[^"]+"$',
            _route_check,
        ),
        (r"^a recovery SDK response has malformed structured content$", _sdk_run),
        (
            r"^recovery call evidence retains the body and usage with response received$",
            _sdk_check,
        ),
        (r"^recovery Gherkin wording omits the process-model state$", _gherkin_run),
        (
            r"^the compiled recovery Gherkin retains the required state and exact target$",
            _gherkin_check,
        ),
        (
            r"^recovery synthesis has one published, two failed and one skipped candidates with four diagnostics$",
            _counts_run,
        ),
        (
            r"^recovery synthesis reports generated \d+, failed \d+, requested \d+, attempted \d+, skipped \d+ and diagnostics \d+$",
            _counts_check,
        ),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)


__all__ = ["FEATURE_ID", "register"]
