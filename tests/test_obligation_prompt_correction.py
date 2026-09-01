"""Focused public-seam tests for the obligation prompt correction slices."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_consideration import (
    MissingStructuralConcept,
    ObligationRoute,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    IcaFindingDraft,
    IcaDeviationDraft,
    ObligationIcaDraft,
    StructuralRevisionRequest,
    SlotIcaDraft,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    audit_prompt_contract,
    build_structural_revision_prompts,
    build_structural_routing_prompts,
    build_synthesis_slot_prompts,
    project_control_structure_context,
    project_obligation_question,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    build_neutral_briefs,
    route_obligations,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    compile_ica_slot_draft,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.test_obligation_aware_stpa import (
    _control_structure,
    _controls,
    _loss_analysis,
    _provider_slot_request,
)


_PROMPT_REGRESSION_FIXTURE = (
    Path(__file__).parent / "fixtures" / "stpa-prompt-contract-regressions.yaml"
)


def _captured_duplicate_pair_loss_analysis() -> LossAnalysis:
    captured = yaml.safe_load(_PROMPT_REGRESSION_FIXTURE.read_text(encoding="utf-8"))[
        "routing_duplicate_hazard_constraint"
    ]["captured_relationship_records"]
    return LossAnalysis(
        risk_card_losses=(
            Loss(
                loss_id="L-3",
                description="The chatbot generates toxic content.",
                provenance=LossProvenance.risk_card,
                source_risk_cards=("risk-prompt-safety",),
            ),
        ),
        use_case_losses=(),
        hazards=tuple(Hazard.model_validate(item) for item in captured["hazards"]),
        security_constraints=tuple(
            SecurityConstraint.model_validate(
                {
                    **{
                        key: value
                        for key, value in item.items()
                        if key != "related_hazard_ids"
                    },
                    "related_hazards": item["related_hazard_ids"],
                }
            )
            for item in captured["constraints"]
        ),
    )


def test_provider_question_is_compact_and_explains_opaque_handle() -> None:
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan()
    brief = build_neutral_briefs(plan, (pattern,))[0]

    question = project_obligation_question(brief)
    assert question.obligation_handle == brief.obligation_id
    assert "copy unchanged" in question.model_dump_json().lower()
    payload = question.model_dump_json()
    assert brief.plan_digest not in payload
    assert brief.attack_pattern_semantic_digest not in payload
    assert "catalog_pins" not in payload
    assert "mapping_pins" not in payload
    assert "mitigations" not in payload
    assert "scores" not in payload

    _system, user = build_structural_routing_prompts(
        briefs=(brief,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        slots=create_slots(_control_structure()),
    )
    assert "copy unchanged" in user.lower()
    assert brief.plan_digest not in user
    assert brief.attack_pattern_semantic_digest not in user
    assert "mapping_pins" not in user


def test_routing_prompt_explains_each_structural_id_once() -> None:
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    brief = build_neutral_briefs(make_plan(), (pattern,))[0]
    structure = _control_structure()

    _system, user = build_structural_routing_prompts(
        briefs=(brief,),
        loss_analysis=_loss_analysis(),
        control_structure=structure,
        slots=create_slots(structure),
    )

    assert "ID glossary" in user
    assert user.count("Validate incoming requests.") == 1
    assert user.count("Validate request.") == 1
    assert user.count("Request process.") == 1
    assert "owner_id: RESP-1" in user
    assert "control_action_id: CA-1-1" in user
    assert "target_process_id: CP-1" in user


def test_prompt_audit_does_not_treat_ordinary_prose_as_internal_field() -> None:
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    brief = build_neutral_briefs(make_plan(), (pattern,))[0]
    question = project_obligation_question(brief)
    question = question.model_copy(
        update={
            "known_concern": question.known_concern.model_copy(
                update={"description": "Clinical triage scores are recorded."}
            )
        }
    )

    audit = audit_prompt_contract(
        question,
        system_prompt="Return JSON.",
        user_prompt="Copy the obligation handle unchanged. Review clinical scores.",
        opaque_handles=(question.obligation_handle,),
    )

    assert audit.valid
    assert audit.issues == ()


def test_target_prompt_contains_only_the_selected_structural_slice() -> None:
    structure = _control_structure()
    selected = create_slots(structure)[:4]
    context = project_control_structure_context(
        structure,
        slots=selected,
        target_id="RESP-1",
    )
    payload = context.model_dump_json()
    assert "RESP-1" in payload
    assert "CA-1-1" in payload
    assert "RESP-2" not in payload
    assert "complete control structure" not in payload.lower()

    system, user = build_synthesis_slot_prompts(
        target_id="RESP-1",
        slots=selected,
        routed_briefs=(),
        routed_routes=(),
        loss_analysis=_loss_analysis(),
        control_structure=structure,
    )
    assert "NOT_PROVIDED" in system
    assert "INCORRECT" in system
    assert "WRONG_TIMING" in system
    assert "WRONG_DURATION" in system
    assert "RESP-2" not in user


def test_target_index_retains_assigned_security_constraint_meaning() -> None:
    structure = _control_structure().model_copy(
        update={
            "responsibilities": (
                _control_structure()
                .responsibilities[0]
                .model_copy(update={"security_constraint_refs": ["SC-1"]}),
            )
        }
    )
    context = project_control_structure_context(
        structure,
        loss_analysis=_loss_analysis(),
        target_id="RESP-1",
    )
    responsibility = context.responsibilities[0]
    assert [item.id for item in responsibility.assigned_constraints] == ["SC-1"]
    assert responsibility.assigned_constraints[0].description == (
        "Requests must satisfy policy."
    )


def test_mismatched_hazard_constraint_route_is_unresolved_after_one_correction() -> (
    None
):
    loss_analysis = LossAnalysis(
        risk_card_losses=(
            Loss(
                loss_id="L-1",
                description="A protected operation is harmed.",
                provenance=LossProvenance.risk_card,
                source_risk_cards=("risk-a",),
            ),
        ),
        use_case_losses=(),
        hazards=(
            Hazard(
                hazard_id="H-1",
                description="An unsafe request is accepted.",
                related_losses=("L-1",),
            ),
            Hazard(
                hazard_id="H-2",
                description="An unsafe review is accepted.",
                related_losses=("L-1",),
            ),
        ),
        security_constraints=(
            SecurityConstraint(
                constraint_id="SC-1",
                description="Requests must satisfy policy.",
                related_hazards=("H-1",),
            ),
        ),
    )
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    brief = build_neutral_briefs(make_plan(), (pattern,))[0]
    route = ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="targeted",
        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
        hazard_ids=("H-2",),
        constraint_ids=("SC-1",),
        evidence=("mismatched-route",),
    )
    feedbacks: list[str | None] = []

    class InvalidAdapter:
        def route(self, request, *, correction_feedback=None):
            feedbacks.append(correction_feedback)
            return {"request_digest": request.semantic_digest, "routes": (route,)}

    result = route_obligations(
        InvalidAdapter(),
        briefs=(brief,),
        loss_analysis=loss_analysis,
        control_structure=_control_structure(),
        controls=_controls(),
    )
    assert result.routes[0].disposition == "unresolved"
    assert len(feedbacks) == 2
    assert feedbacks[1] is not None
    assert "does not govern" in feedbacks[1].lower()


def test_captured_nhs_routing_prompt_lists_exact_hazard_constraint_pairs() -> None:
    """Duplicate NHS descriptions must not decide the structural relationship."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    brief = build_neutral_briefs(make_plan(), (pattern,))[0]
    loss_analysis = _captured_duplicate_pair_loss_analysis()

    _system, user = build_structural_routing_prompts(
        briefs=(brief,),
        loss_analysis=loss_analysis,
        control_structure=_control_structure(),
        slots=create_slots(_control_structure()),
    )
    fixture = yaml.safe_load(_PROMPT_REGRESSION_FIXTURE.read_text(encoding="utf-8"))[
        "routing_duplicate_hazard_constraint"
    ]
    assert fixture["source_run"].endswith("20260901-synthesis-nhs-prompt-contract-v3")
    assert "AUTHORITATIVE HAZARD-CONSTRAINT PAIR LEDGER" in user
    assert "SC-2 -> H-10" in user
    assert "SC-10 -> H-10" in user
    assert "SC-2 -> H-2" not in user


def test_captured_nhs_route_error_and_feedback_explain_allowed_pair() -> None:
    """A rejected text-matched pair gets exact typed correction guidance."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    brief = build_neutral_briefs(make_plan(), (pattern,))[0]
    loss_analysis = _captured_duplicate_pair_loss_analysis()
    captured = yaml.safe_load(_PROMPT_REGRESSION_FIXTURE.read_text(encoding="utf-8"))[
        "routing_duplicate_hazard_constraint"
    ]["captured_route"]
    route = ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="targeted",
        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
        hazard_ids=tuple(captured["hazard_ids"]),
        constraint_ids=tuple(captured["constraint_ids"]),
        evidence=("captured-nhs-route",),
    )
    feedbacks: list[str | None] = []

    class InvalidAdapter:
        def route(self, request, *, correction_feedback=None):
            feedbacks.append(correction_feedback)
            return {"request_digest": request.semantic_digest, "routes": (route,)}

    result = route_obligations(
        InvalidAdapter(),
        briefs=(brief,),
        loss_analysis=loss_analysis,
        control_structure=_control_structure(),
        controls=_controls(),
    )
    fixture = yaml.safe_load(_PROMPT_REGRESSION_FIXTURE.read_text(encoding="utf-8"))[
        "routing_duplicate_hazard_constraint"
    ]
    diagnostic = result.routes[0].diagnostics[0].detail
    assert fixture["expected_error_fragment"] in diagnostic
    assert feedbacks[1] is not None
    assert fixture["expected_error_fragment"] in feedbacks[1]
    assert "do not infer pairings from descriptions" in feedbacks[1].lower()


def test_revision_prompt_uses_local_handles_and_three_gap_decisions() -> None:
    gap = MissingStructuralConcept(
        concept_type="responsibility",
        description="A reviewing responsibility is needed.",
        evidence_refs=("review-gap",),
    )
    system, user = build_structural_revision_prompts(
        gaps=(gap,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
    )
    combined = f"{system}\n{user}".lower()
    assert "gap_handle" in combined
    assert "propose_addition" in combined
    assert "dismiss_unsupported" in combined
    assert "unresolved" in combined
    assert "final stpa id" in combined
    assert '"gap_id"' not in user


def test_structured_ica_draft_compiles_authoritative_owner_and_action() -> None:
    structure = _control_structure()
    slot = create_slots(structure)[0]
    draft = SlotIcaDraft(
        slot_id=slot.slot_id,
        is_na=False,
        findings=(
            IcaFindingDraft(
                deviation=IcaDeviationDraft(
                    not_provided_context="the request contains an unreviewed operation"
                ),
                hazardous_context="the unreviewed operation reaches the process",
                loss_consequence="the protected operation is harmed",
                related_hazard_ids=("H-1",),
                related_constraint_ids=("SC-1",),
            ),
        ),
    )
    filled = compile_ica_slot_draft(
        draft,
        slot=slot,
        loss_analysis=_loss_analysis(),
        control_structure=structure,
    )
    ica = filled.icas[0]
    assert "Validate incoming requests." in ica.ica_text
    assert "Validate request." in ica.ica_text
    assert "unreviewed operation" in ica.ica_text
    assert ica.related_hazards == ["H-1"]
    assert ica.related_constraints == ["SC-1"]


def test_structured_ica_draft_rejects_safeguard_and_wrong_uca_type() -> None:
    structure = _control_structure()
    slot = create_slots(structure)[0]
    safeguard = SlotIcaDraft(
        slot_id=slot.slot_id,
        is_na=False,
        findings=(
            IcaFindingDraft(
                deviation=IcaDeviationDraft(
                    not_provided_context="Implement strong authentication"
                ),
                hazardous_context="the request is accepted",
                loss_consequence="the protected operation is harmed",
                related_hazard_ids=("H-1",),
                related_constraint_ids=("SC-1",),
            ),
        ),
    )
    with pytest.raises(ValueError, match="safeguard|unsafe control behavior"):
        compile_ica_slot_draft(
            safeguard,
            slot=slot,
            loss_analysis=_loss_analysis(),
            control_structure=structure,
        )

    wrong_type = SlotIcaDraft(
        slot_id=slot.slot_id,
        is_na=False,
        findings=(
            IcaFindingDraft(
                deviation=IcaDeviationDraft(
                    duration_deviation="the action continues for too long"
                ),
                hazardous_context="the request is accepted",
                loss_consequence="the protected operation is harmed",
                related_hazard_ids=("H-1",),
                related_constraint_ids=("SC-1",),
            ),
        ),
    )
    with pytest.raises(ValueError, match="WRONG_DURATION|deviation"):
        compile_ica_slot_draft(
            wrong_type,
            slot=slot,
            loss_analysis=_loss_analysis(),
            control_structure=structure,
        )


def test_provider_preflight_blocks_oversized_ica_before_dispatch(tmp_path) -> None:
    request = _provider_slot_request()
    controls = request.controls.model_copy(
        update={"context_window": 2048, "maximum_completion_tokens": 4096}
    )
    request = request.model_copy(update={"controls": controls})
    calls: list[object] = []

    class Client:
        model = "preflight-test"

        def complete(self, **kwargs):
            calls.append(kwargs)
            return LLMResult(
                content={},
                prompt_tokens=0,
                completion_tokens=0,
                duration_ms=0,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    provider = ObligationAwareLLMAdapter(
        Client(),
        run_dir=tmp_path,
        controls=controls,
    )
    with pytest.raises(ValueError, match="prompt_budget_exceeded"):
        provider.fill(request)
    assert calls == []


def test_routing_budget_exhaustion_is_typed_and_does_not_retry(tmp_path) -> None:
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    brief = build_neutral_briefs(make_plan(), (pattern,))[0]
    controls = _controls().model_copy(
        update={"context_window": 2048, "maximum_completion_tokens": 4096}
    )
    calls: list[object] = []

    class Client:
        model = "preflight-test"

        def complete(self, **kwargs):
            calls.append(kwargs)
            raise AssertionError("the oversized prompt must not be dispatched")

    provider = ObligationAwareLLMAdapter(
        Client(),
        run_dir=tmp_path,
        controls=controls,
    )
    result = route_obligations(
        provider,
        briefs=(brief,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=controls,
    )
    assert result.routes[0].disposition == "unresolved"
    assert result.routes[0].diagnostics[0].code == "prompt_budget_exceeded"
    assert result.call_evidence[0].attempt_count == 1
    assert calls == []


def test_routing_budget_splits_compact_batches_in_canonical_order() -> None:
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(
        make_plan(risk_ids=("risk-a", "risk-b")),
        (pattern,),
    )
    controls = _controls().model_copy(
        update={"context_window": 11_000, "maximum_completion_tokens": 8192}
    )
    observed: list[tuple[str, ...]] = []

    class Adapter:
        def route(self, request):
            observed.append(tuple(item.obligation_id for item in request.briefs))
            return {
                "request_digest": request.semantic_digest,
                "routes": tuple(
                    ObligationRoute(
                        obligation_id=item.obligation_id,
                        disposition="targeted",
                        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
                        hazard_ids=("H-1",),
                        constraint_ids=("SC-1",),
                        evidence=("budget-split",),
                    )
                    for item in request.briefs
                ),
            }

    result = route_obligations(
        Adapter(),
        briefs=briefs,
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=controls,
    )
    assert observed == [(briefs[0].obligation_id,), (briefs[1].obligation_id,)]
    assert [item.obligation_id for item in result.routes] == [
        item.obligation_id for item in briefs
    ]


def test_revision_provider_schema_uses_local_handles_without_final_gap_ids(
    tmp_path,
) -> None:
    gap = MissingStructuralConcept(
        concept_type="responsibility",
        description="A reviewing responsibility is needed.",
        evidence_refs=("review-gap",),
    )
    controls = _controls()
    request = StructuralRevisionRequest(
        gaps=(gap,),
        baseline_loss_analysis=_loss_analysis(),
        baseline_control_structure=_control_structure(),
        controls=controls,
    )
    response_formats: list[type] = []

    class Client:
        model = "revision-schema-test"

        def complete(self, **kwargs):
            response_formats.append(kwargs["response_format"])
            return LLMResult(
                content={
                    "draft": {},
                    "gap_decisions": [
                        {
                            "gap_handle": "revision-gap-1",
                            "disposition": "dismiss_unsupported",
                            "rationale": "The supplied evidence does not justify it.",
                        }
                    ],
                },
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    provider = ObligationAwareLLMAdapter(
        Client(),
        run_dir=tmp_path,
        controls=controls,
    )
    response = provider.revise(request)
    assert response.draft.gap_decisions[0].gap_handle == "revision-gap-1"
    schema = response_formats[0].model_json_schema()
    draft_fields = schema["$defs"]["_RevisionProviderDraft"]["properties"]
    assert "trigger_gap_ids" not in draft_fields
    assert "dismissed_gap_ids" not in draft_fields


def test_provider_accepts_nested_structured_ica_consideration_results(tmp_path) -> None:
    slot = create_slots(_control_structure())[0]
    obligation_id = "ob:v1:" + "d" * 64
    route = ObligationRoute(
        obligation_id=obligation_id,
        disposition="targeted",
        slot_ids=(slot.slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("provider-route",),
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
                rationale="The finding addresses the routed concern.",
            ),
        ),
    )

    class Client:
        model = "nested-ica-test"

        def complete(self, **kwargs):
            return LLMResult(
                content={"filled_slots": [draft.model_dump(mode="json")]},
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
    request = _provider_slot_request(routed_routes=(route,))
    response = provider.fill(request)
    assert response.considerations[0].disposition == "finding"
    assert response.considerations[0].obligation_id == obligation_id
    assert response.considerations[0].ica_ids == (f"{slot.slot_id}:1",)
