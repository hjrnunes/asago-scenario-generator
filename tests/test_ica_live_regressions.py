"""Captured regression tests for the NHS obligation-aware ICA provider path."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from asago_scenario_generator.models.obligation_consideration import ObligationRoute
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.prompt_preflight import PromptBudget
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionTemporality,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    IcaDeviationDraft,
    IcaFindingDraft,
    ObligationIcaDraft,
    SlotIcaDraft,
    SynthesisSlotRequest,
    SynthesisSlotResponse,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware import provider as provider_module
from asago_scenario_generator.stpa.obligation_aware import (
    slot_filling as slot_filling_module,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from asago_scenario_generator.stpa.obligation_aware.routing import build_neutral_briefs
from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.test_obligation_aware_stpa import (
    _control_structure,
    _controls,
    _loss_analysis,
    _provider_slot_request,
)
from asago_scenario_generator.stpa.models.loss_analysis import SecurityConstraint
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    fill_synthesis_slots,
)


_LIVE_FIXTURE = Path(__file__).parent / "fixtures" / "nhs-ica-live-regressions.yaml"


def test_captured_resp6_uses_nested_consideration_results(tmp_path) -> None:
    """RESP-6's valid-looking slots compile through the normative envelope."""
    captured = yaml.safe_load(_LIVE_FIXTURE.read_text(encoding="utf-8"))["targets"][
        "RESP-6"
    ]
    slot = create_slots(_control_structure())[0]
    assert captured["legacy_ica_id"].endswith(":NOT_PROVIDED")
    assert captured["canonical_ica_id"].endswith(":NOT_PROVIDED:1")
    canonical_ica_id = f"{slot.slot_id}:1"
    obligation_id = "ob:v1:" + "e" * 64
    route = ObligationRoute(
        obligation_id=obligation_id,
        disposition="targeted",
        slot_ids=(slot.slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("captured-resp-6",),
    )
    draft = SlotIcaDraft(
        slot_id=slot.slot_id,
        is_na=False,
        findings=(
            IcaFindingDraft(
                deviation=IcaDeviationDraft(
                    not_provided_context="the request is not reviewed"
                ),
                hazardous_context="the unreviewed request reaches the process",
                loss_consequence="the protected operation is harmed",
                related_hazard_ids=("H-1",),
                related_constraint_ids=("SC-1",),
            ),
        ),
        consideration_results=(
            ObligationIcaDraft(
                obligation_handle=obligation_id,
                disposition="finding",
                finding_indexes=(0,),
                rationale="The routed concern is addressed by this finding.",
            ),
        ),
    )
    calls = 0

    class Client:
        model = "captured-resp-6"

        def complete(self, **kwargs):
            nonlocal calls
            calls += 1
            content = {"filled_slots": [draft.model_dump(mode="json")]}
            return LLMResult(
                content=content,
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    provider = ObligationAwareLLMAdapter(
        Client(),
        run_dir=tmp_path,
        controls=_controls(),
    )
    response = provider.fill(_provider_slot_request(routed_routes=(route,)))

    assert calls == 1
    assert captured["normative_field"] == "consideration_results"
    assert captured["legacy_ica_id"] != captured["canonical_ica_id"]
    assert response.considerations[0].obligation_id == obligation_id
    assert response.considerations[0].ica_ids == (canonical_ica_id,)
    entries = [
        json.loads(line)
        for line in (tmp_path / "calls.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert entries[0]["success"] is True


def test_provider_retries_schema_valid_draft_when_compile_semantics_fail(
    tmp_path,
) -> None:
    """A typed draft with invalid UCA semantics is corrected at the retry seam."""
    slots = tuple(
        sorted(create_slots(_control_structure()), key=lambda item: item.slot_id)
    )
    slot = next(item for item in slots if item.uca_type.value == "WRONG_DURATION")
    slot = slot.model_copy(
        update={"action_temporality": ControlActionTemporality.continuous}
    )
    invalid = SlotIcaDraft(
        slot_id=slot.slot_id,
        is_na=False,
        findings=(
            IcaFindingDraft(
                deviation=IcaDeviationDraft(
                    duration_deviation="the action is applied incorrectly",
                ),
                hazardous_context="the action leaves the process unsafe",
                loss_consequence="the protected operation is harmed",
                related_hazard_ids=("H-404",),
                related_constraint_ids=("SC-1",),
            ),
        ),
    )
    corrected = invalid.model_copy(
        update={
            "findings": (
                invalid.findings[0].model_copy(
                    update={
                        "related_hazard_ids": ("H-1",),
                        "deviation": IcaDeviationDraft(
                            duration_deviation=(
                                "the continuous action continues too long after the session ends"
                            )
                        ),
                    }
                ),
            )
        }
    )
    calls = 0

    class Client:
        model = "captured-compile-retry"

        def complete(self, **kwargs):
            nonlocal calls
            calls += 1
            draft = invalid if calls == 1 else corrected
            return LLMResult(
                content={"filled_slots": [draft.model_dump(mode="json")]},
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    request = SynthesisSlotRequest(
        target_id=slot.responsibility or slot.coordination_link or "",
        target_kind="responsibility",
        slots=(slot,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=_controls().model_copy(update={"validation_retries": 1}),
    )
    provider = ObligationAwareLLMAdapter(
        Client(),
        run_dir=tmp_path,
        controls=request.controls,
    )

    result = provider.fill(request)

    assert calls == 2
    assert result.filled_slots[0].is_na is False
    entries = [
        json.loads(line)
        for line in (tmp_path / "calls.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert entries[0]["success"] is False
    assert "unknown hazards: H-404" in entries[0]["error"]
    assert entries[1]["success"] is True


def test_provider_compiles_strict_slot_draft_once_before_outer_fill(
    monkeypatch, tmp_path
):
    """A canonical provider slot must not re-enter the legacy compiler."""
    compile_calls: list[type] = []
    original_compile = slot_filling_module.compile_slot_provider_entry

    def counted_compile(value, **kwargs):
        compile_calls.append(type(value))
        return original_compile(value, **kwargs)

    # The adapter imports the compiler at module scope, while the outer seam
    # owns its own reference.  Patching both makes the assertion cover both
    # possible compilation sites without reaching into call internals.
    monkeypatch.setattr(provider_module, "compile_slot_provider_entry", counted_compile)
    monkeypatch.setattr(
        slot_filling_module, "compile_slot_provider_entry", counted_compile
    )

    # Use a tiny direct request so the provider response can be fed through
    # the outer seam without introducing a second target or unrelated routes.
    request = _provider_slot_request()

    class NAFakeClient:
        model = "captured-single-compile"

        def complete(self, **kwargs):
            slot_id = request.slots[0].slot_id
            return LLMResult(
                content={
                    "filled_slots": [
                        {
                            "slot_id": slot_id,
                            "is_na": True,
                            "na_rationale": "No finding applies to this slot.",
                            "findings": [],
                            "consideration_results": [],
                        }
                    ]
                },
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    provider = ObligationAwareLLMAdapter(
        NAFakeClient(),
        run_dir=tmp_path,
        controls=request.controls,
    )
    response = provider.fill(request)

    assert compile_calls == [SlotIcaDraft]
    diagnostics = []
    compiled, error = slot_filling_module._compile_response_slots(
        response,
        request=request,
        expected={slot.slot_id: slot for slot in request.slots},
        diagnostics=diagnostics,
        loss_analysis=request.loss_analysis,
        control_structure=request.control_structure,
    )
    assert error is None
    assert diagnostics == []
    assert tuple(compiled) == (request.slots[0].slot_id,)
    assert compile_calls == [SlotIcaDraft]


def test_local_ica_preflight_failure_is_recorded_before_provider_dispatch(
    tmp_path,
) -> None:
    """A target preflight rejection has durable, request-local call evidence."""
    request = _provider_slot_request()
    controls = request.controls.model_copy(
        update={"context_window": 2048, "maximum_completion_tokens": 4096}
    )
    request = request.model_copy(update={"controls": controls})
    calls: list[object] = []

    class Client:
        model = "captured-preflight"

        def complete(self, **kwargs):
            calls.append(kwargs)
            raise AssertionError("the rejected prompt must not be dispatched")

    provider = ObligationAwareLLMAdapter(
        Client(),
        run_dir=tmp_path,
        controls=controls,
    )

    try:
        provider.fill(request)
    except ValueError as exc:
        assert "prompt_budget_exceeded" in str(exc)
    else:  # pragma: no cover - assertion gives a clearer failure than pytest.raises
        raise AssertionError("expected target preflight rejection")

    assert calls == []
    entry = json.loads(
        (tmp_path / "calls.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert entry["success"] is False
    assert entry["stage"] == "synthesis_obligation_aware_icas"
    assert entry["step"] == request.target_id
    assert "prompt_budget_exceeded" in entry["error"]
    assert entry["prompt_preflight"]["provider_call_allowed"] is False


def test_captured_target_reference_contract_failure_is_recorded_precisely(
    tmp_path,
) -> None:
    """Stale embedded hazard IDs are recorded as contract failures, not budget."""
    captured = yaml.safe_load(_LIVE_FIXTURE.read_text(encoding="utf-8"))
    live_resp2 = captured["targets"]["RESP-2"]
    assert captured["source_run"].endswith("20260901-synthesis-nhs-prompt-contract-v3")
    assert live_resp2["preflight_input_tokens"] < live_resp2["usable_input_tokens"]
    request = _provider_slot_request()
    controls = request.controls.model_copy(
        update={
            "context_window": 32768,
            "maximum_completion_tokens": 8192,
        }
    )

    baseline = request.loss_analysis.security_constraints[0]
    stale_constraint = SecurityConstraint.model_validate(
        {
            **baseline.model_dump(),
            # Phase 1.3 as amended: the stale hazard reference lives in the
            # authored rule so the composed description carries it.
            "rule": "Requests must satisfy policy. (related hazards: H-2)",
            "applies_when": [],
        }
    )
    request = SynthesisSlotRequest(
        target_id=request.target_id,
        target_kind=request.target_kind,
        slots=request.slots,
        routed_briefs=request.routed_briefs,
        routed_routes=request.routed_routes,
        loss_analysis=request.loss_analysis.model_copy(
            update={"security_constraints": [stale_constraint]}
        ),
        control_structure=request.control_structure,
        controls=controls,
    )
    calls: list[object] = []

    class Client:
        model = "captured-reference-contract"

        def complete(self, **kwargs):
            calls.append(kwargs)
            raise AssertionError("the rejected prompt must not be dispatched")

    provider = ObligationAwareLLMAdapter(
        Client(),
        run_dir=tmp_path,
        controls=controls,
    )
    try:
        provider.fill(request)
    except ValueError as exc:
        assert live_resp2["expected_error_fragment"] in str(exc)
    else:  # pragma: no cover - assertion gives a clearer failure than pytest.raises
        raise AssertionError("expected target prompt contract rejection")

    assert calls == []
    entry = json.loads(
        (tmp_path / "calls.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert entry["success"] is False
    assert entry["error"].startswith("PromptContractError:")
    assert live_resp2["expected_error_fragment"] in entry["error"]
    assert entry["prompt_preflight"]["provider_call_allowed"] is False


def test_oversized_target_splits_routes_and_repeats_all_slots_deterministically():
    """Budgeted calls keep one slot while partitioning routed obligations."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(
        make_plan(risk_ids=tuple(f"risk-{index}" for index in range(30))),
        (pattern,),
    )
    structure = _control_structure()
    loss_analysis = _loss_analysis()
    target_slots = tuple(create_slots(structure))
    slot = target_slots[0]
    routes = tuple(
        ObligationRoute(
            obligation_id=brief.obligation_id,
            disposition="targeted",
            slot_ids=(slot.slot_id,),
            hazard_ids=("H-1",),
            constraint_ids=("SC-1",),
            evidence=("captured-budget-target",),
        )
        for brief in briefs
    )
    budget = PromptBudget(
        context_window=32768,
        maximum_completion_tokens=8192,
        safety_margin=0,
    )
    observed: list[tuple[str, tuple[str, ...]]] = []

    class Adapter:
        prompt_budget = budget

        def fill(self, request):
            assert len(request.slots) == 1
            observed.append(
                (
                    request.slots[0].slot_id,
                    tuple(route.obligation_id for route in request.routed_routes),
                )
            )
            drafts = []
            for target_slot in request.slots:
                if target_slot.slot_id == slot.slot_id:
                    drafts.append(
                        SlotIcaDraft(
                            slot_id=target_slot.slot_id,
                            is_na=False,
                            findings=(
                                IcaFindingDraft(
                                    deviation=IcaDeviationDraft(
                                        not_provided_context="the request is not reviewed"
                                    ),
                                    hazardous_context=(
                                        "the unreviewed request reaches the process"
                                    ),
                                    loss_consequence=(
                                        "the protected operation is harmed"
                                    ),
                                    related_hazard_ids=("H-1",),
                                    related_constraint_ids=("SC-1",),
                                ),
                            ),
                            consideration_results=tuple(
                                ObligationIcaDraft(
                                    obligation_handle=route.obligation_id,
                                    disposition="finding",
                                    finding_indexes=(0,),
                                    rationale=(
                                        "The routed concern is addressed by this finding."
                                    ),
                                )
                                for route in request.routed_routes
                            ),
                        )
                    )
                else:
                    drafts.append(
                        SlotIcaDraft(
                            slot_id=target_slot.slot_id,
                            is_na=True,
                            na_rationale="No routed concern applies.",
                        )
                    )
            return SynthesisSlotResponse(
                request_digest=request.semantic_digest,
                filled_slots=tuple(drafts),
            )

    result = fill_synthesis_slots(
        Adapter(),
        briefs=briefs,
        routes=routes,
        loss_analysis=loss_analysis,
        control_structure=structure,
        controls=_controls(),
    )

    assert len(observed) > 1
    assert all(len(request.slots) == 1 for request in result.result.requests)
    assert {slot_id for slot_id, _route_ids in observed} == {
        item.slot_id for item in target_slots
    }
    observed_pairs = sorted(
        (route_id, slot_id) for slot_id, route_ids in observed for route_id in route_ids
    )
    expected_pairs = sorted(
        (route.obligation_id, slot_id) for route in routes for slot_id in route.slot_ids
    )
    assert observed_pairs == expected_pairs
    assert len(result.considerations) == len(routes)


def test_target_route_batches_respect_analysis_batch_limit_without_budget_pressure():
    """Small prompts still bound each target call to the configured obligation limit."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(
        make_plan(risk_ids=tuple(f"risk-{index}" for index in range(5))),
        (pattern,),
    )
    structure = _control_structure()
    slot = create_slots(structure)[0]
    routes = tuple(
        ObligationRoute(
            obligation_id=brief.obligation_id,
            disposition="targeted",
            slot_ids=(slot.slot_id,),
            hazard_ids=("H-1",),
            constraint_ids=("SC-1",),
            evidence=("bounded-target",),
        )
        for brief in briefs
    )
    observed: list[tuple[str, tuple[str, ...]]] = []

    class Adapter:
        def fill(self, request):
            assert len(request.slots) == 1
            observed.append(
                (
                    request.slots[0].slot_id,
                    tuple(route.obligation_id for route in request.routed_routes),
                )
            )
            drafts = tuple(
                SlotIcaDraft(
                    slot_id=target_slot.slot_id,
                    is_na=True,
                    na_rationale="No finding applies to this test slot.",
                    consideration_results=tuple(
                        ObligationIcaDraft(
                            obligation_handle=route.obligation_id,
                            disposition="proposed_not_applicable",
                            rationale="The complete test structure excludes it.",
                        )
                        for route in request.routed_routes
                        if target_slot.slot_id in route.slot_ids
                    ),
                )
                for target_slot in request.slots
            )
            return SynthesisSlotResponse(
                request_digest=request.semantic_digest,
                filled_slots=drafts,
            )

    controls = _controls().model_copy(update={"max_batch_size": 2})
    result = fill_synthesis_slots(
        Adapter(),
        briefs=briefs,
        routes=routes,
        loss_analysis=_loss_analysis(),
        control_structure=structure,
        controls=controls,
    )

    assert [len(route_ids) for _slot_id, route_ids in observed if route_ids] == [
        2,
        2,
        1,
    ]
    assert all(
        len(route_ids) <= controls.max_batch_size for _slot_id, route_ids in observed
    )
    assert {slot_id for slot_id, _route_ids in observed} == {
        item.slot_id for item in create_slots(structure)
    }
    observed_pairs = sorted(
        (route_id, slot_id) for slot_id, route_ids in observed for route_id in route_ids
    )
    expected_pairs = sorted(
        (route.obligation_id, slot_id) for route in routes for slot_id in route.slot_ids
    )
    assert observed_pairs == expected_pairs
    assert len(result.considerations) == len(routes)
