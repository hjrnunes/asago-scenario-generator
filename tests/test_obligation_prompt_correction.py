"""Focused public-seam tests for the obligation prompt correction slices."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_consideration import (
    MissingStructuralConcept,
    ObligationRoute,
)
from asago_scenario_generator.models.obligation_plan import EvidenceRecord
from asago_scenario_generator.models.artifact_pin import (
    compute_ica_enumeration_digest,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionTemporality,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    IcaFindingDraft,
    IcaDeviationDraft,
    ObligationIcaDraft,
    StructuralRevisionRequest,
    StructuralRoutingResponse,
    SlotIcaDraft,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    audit_prompt_contract,
    build_structural_revision_prompts,
    build_structural_routing_prompts,
    build_synthesis_slot_prompts,
    mapping_strength_for_brief,
    project_control_structure_context,
    project_obligation_question,
)
from asago_scenario_generator.stpa.obligation_aware import prompts as prompt_module
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
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
from tests.helpers.obligation_aware import (
    _control_structure,
    _controls,
    _loss_analysis,
    _provider_slot_request,
    provider_slot_payload,
    route_assessment,
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
                    "rule": item["description"],
                    "applies_when": [],
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
    assert question.mapping_strength.label == "direct_curated_pair"
    assert "discovery evidence" in question.mapping_strength.meaning
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


def test_routing_prompt_defines_repeated_concern_once_per_batch() -> None:
    """Repeated pattern context is a glossary entry, not duplicated prose."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    brief = build_neutral_briefs(make_plan(), (pattern,))[0]
    second = brief.model_copy(update={"obligation_id": brief.obligation_id + "-2"})

    _system, user = build_structural_routing_prompts(
        briefs=(brief, second),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        slots=create_slots(_control_structure()),
    )

    assert user.count(brief.attack_pattern_name) == 1
    assert user.count("known_concern_ref:") == 2
    assert "analyst_instruction:" not in user


@pytest.mark.parametrize(
    ("first_relation", "expected"),
    [
        ("skos:exactMatch", "exact_then_category_expansion"),
        ("skos:broadMatch", "broad_category_expansion"),
        ("skos:relatedMatch", "related_category_expansion"),
    ],
)
def test_mapping_strength_is_projected_without_raw_mapping_json(
    first_relation: str, expected: str
) -> None:
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan(
        mappings=[
            {
                "source_id": "risk-a",
                "target_id": "CATEGORY-1",
                "relation": first_relation,
            },
            {
                "source_id": "CATEGORY-1",
                "target_id": pattern.id,
                "relation": "attacks_via",
            },
        ]
    )
    question = project_obligation_question(build_neutral_briefs(plan, (pattern,))[0])

    assert question.mapping_strength.label == expected
    assert '"path"' not in question.model_dump_json()


def test_mapping_strength_rejects_missing_or_malformed_exact_evidence() -> None:
    """The plain label can only be compiled from an exact typed path."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    brief = build_neutral_briefs(make_plan(), (pattern,))[0]
    with pytest.raises(ValueError, match="requires mapping-path evidence"):
        mapping_strength_for_brief(
            brief.model_copy(update={"applicability_evidence": ()})
        )
    malformed = EvidenceRecord(kind="mapping", detail="{}")
    with pytest.raises(ValueError, match="not a typed mapping path"):
        mapping_strength_for_brief(
            brief.model_copy(update={"applicability_evidence": (malformed,)})
        )


def test_later_weak_edge_weakens_the_complete_mapping_path() -> None:
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan(
        mappings=[
            {
                "source_id": "risk-a",
                "target_id": "CATEGORY-1",
                "relation": "skos:exactMatch",
            },
            {
                "source_id": "CATEGORY-1",
                "target_id": pattern.id,
                "relation": "skos:relatedMatch",
            },
        ]
    )

    question = project_obligation_question(build_neutral_briefs(plan, (pattern,))[0])

    assert question.mapping_strength.label == "related_category_expansion"


def test_one_weaker_path_prevents_strongest_path_promotion() -> None:
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan(
        mappings=[
            {
                "source_id": "risk-a",
                "target_id": pattern.id,
                "relation": "skos:exactMatch",
            },
            {
                "source_id": "risk-a",
                "target_id": "CATEGORY-1",
                "relation": "skos:broadMatch",
            },
            {
                "source_id": "CATEGORY-1",
                "target_id": pattern.id,
                "relation": "attacks_via",
            },
        ]
    )

    question = project_obligation_question(build_neutral_briefs(plan, (pattern,))[0])

    assert question.mapping_strength.label == "broad_category_expansion"


@pytest.mark.parametrize(
    ("relation", "expected"),
    [
        ("skos:exactMatch", "direct_curated_pair"),
        ("skos:broadMatch", "broad_category_expansion"),
        ("skos:relatedMatch", "related_category_expansion"),
        ("unreviewed_relation", "related_category_expansion"),
    ],
)
def test_direct_pair_label_respects_the_declared_relation(
    relation: str, expected: str
) -> None:
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan(
        mappings=[
            {
                "source_id": "risk-a",
                "target_id": pattern.id,
                "relation": relation,
            }
        ]
    )

    question = project_obligation_question(build_neutral_briefs(plan, (pattern,))[0])

    assert question.mapping_strength.label == expected


def test_obligation_aware_provider_instructions_live_in_jinja_templates() -> None:
    """Prompt projectors stay in Python while provider prose lives in Jinja."""
    template_dir = Path(prompt_module.__file__).with_name("prompt_templates")
    expected = {
        "structural_routing_system.j2",
        "structural_routing_user.j2",
        "structural_revision_system.j2",
        "structural_revision_user.j2",
        "synthesis_ica_system.j2",
        "synthesis_ica_user.j2",
        "mechanism_verification_system.j2",
        "mechanism_verification_user.j2",
        "_uca_method.j2",
    }
    hashes = TemplateLoader(template_dir).hash_prompt_templates()
    assert expected <= set(hashes)
    assert all(len(hashes[name]) == 64 for name in expected)

    source = inspect.getsource(prompt_module)
    assert "You are performing structural STPA analysis" not in source
    assert "Fill every supplied STPA ICA slot" not in source


def test_target_prompt_view_deduplicates_losses_by_exact_identity() -> None:
    """Repeated upstream loss rows produce one provider-facing loss record."""
    loss_analysis = _loss_analysis()
    duplicate = loss_analysis.risk_card_losses[0]
    loss_analysis = loss_analysis.model_copy(
        update={"risk_card_losses": (duplicate, duplicate)}
    )

    context = project_control_structure_context(
        _control_structure(),
        slots=create_slots(_control_structure())[:4],
        target_id="RESP-1",
        loss_analysis=loss_analysis,
    )

    assert [item.id for item in context.losses] == ["L-1"]


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


def test_focused_verifier_retains_path_without_granting_mechanism_credit(
    tmp_path,
) -> None:
    """An adjacent-control verdict keeps the STPA route but removes its credit."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    brief = build_neutral_briefs(make_plan(), (pattern,))[0]
    slot = create_slots(_control_structure())[0]
    route = ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="targeted",
        semantic_assessment={
            "mechanism_assessment": "plausible_in_system",
            "risk_alignment": "supported",
            "mapping_strength": "direct_curated_pair",
            "mechanism_rationale": "A generic input surface is present.",
            "risk_alignment_rationale": "The risk is conceptually related.",
        },
        slot_ids=(slot.slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        rationale="The selected control path is relevant to the concern.",
        evidence=("provider-route",),
    )

    class Client:
        model = "focused-verifier-test"
        calls = 0
        prompts: list[str] = []

        def complete(self, **kwargs):
            self.calls += 1
            self.prompts.append(kwargs["user_prompt"])
            provider_route = route.model_dump(
                mode="json",
                exclude={
                    "route_id",
                    "missing_concepts",
                    "model_call_refs",
                    "trace_refs",
                    "diagnostics",
                },
            )
            provider_route["semantic_assessment"].pop("mapping_strength", None)
            content = (
                {"routes": [provider_route]}
                if self.calls == 1
                else {
                    "verdicts": [
                        {
                            "item_handle": "R1",
                            "relationship": "adjacent_control",
                            "rationale": (
                                "Input validation does not govern poisoned source "
                                "output being interpreted as a goal."
                            ),
                        }
                    ]
                }
            )
            return LLMResult(
                content=content,
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    client = Client()
    controls = _controls().model_copy(update={"max_batch_size": 1})
    result = route_obligations(
        ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=controls),
        briefs=(brief,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        slots=(slot,),
        controls=controls,
    )

    retained = result.routes[0]
    assert client.calls == 2
    assert retained.disposition == "targeted"
    assert retained.slot_ids == (slot.slot_id,)
    assert retained.semantic_assessment is not None
    assert retained.semantic_assessment.mechanism_assessment == "insufficient_evidence"
    assert retained.semantic_assessment.risk_alignment == "supported"
    assert retained.diagnostics[-1].code == "mechanism_path_unsubstantiated"
    verifier_prompt = client.prompts[1]
    assert "selected_structural_path:" in verifier_prompt
    assert "reviewed_risk:" not in verifier_prompt
    assert "mapping_strength:" not in verifier_prompt
    assert "applicability:" not in verifier_prompt


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

    _system, user = build_synthesis_slot_prompts(
        target_id="RESP-1",
        slots=selected,
        routed_briefs=(),
        routed_routes=(),
        loss_analysis=_loss_analysis(),
        control_structure=structure,
    )
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
                rule="Requests must satisfy policy.",
                related_hazards=("H-1",),
            ),
        ),
    )
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    brief = build_neutral_briefs(make_plan(), (pattern,))[0]
    route = ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="targeted",
        semantic_assessment=route_assessment(brief),
        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
        hazard_ids=("H-2",),
        constraint_ids=("SC-1",),
        evidence=("mismatched-route",),
    )
    feedbacks: list[str | None] = []

    class InvalidAdapter:
        def route(self, request, *, correction_feedback=None):
            feedbacks.append(correction_feedback)
            return StructuralRoutingResponse(
                adapter_kind="fake",
                request_digest=request.semantic_digest,
                routes=(route,),
            )

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
        semantic_assessment=route_assessment(brief),
        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
        hazard_ids=tuple(captured["hazard_ids"]),
        constraint_ids=tuple(captured["constraint_ids"]),
        evidence=("captured-nhs-route",),
    )
    feedbacks: list[str | None] = []

    class InvalidAdapter:
        def route(self, request, *, correction_feedback=None):
            feedbacks.append(correction_feedback)
            return StructuralRoutingResponse(
                adapter_kind="fake",
                request_digest=request.semantic_digest,
                routes=(route,),
            )

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
    assert ica.quality_warnings == []


def test_verbose_semantically_valid_ica_is_retained_with_quality_warning() -> None:
    """Presentation defects stay visible without deleting a valid finding."""
    structure = _control_structure()
    slot = create_slots(structure)[0]
    verbose_clause = (
        "the request contains an unreviewed operation and the request contains "
        "another unreviewed operation, such as an operation that remains pending "
        "while several unrelated checks continue and additional explanatory detail "
        "is supplied to the analyst"
    )
    draft = SlotIcaDraft(
        slot_id=slot.slot_id,
        is_na=False,
        findings=(
            IcaFindingDraft(
                deviation=IcaDeviationDraft(
                    not_provided_context=verbose_clause,
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

    assert len(filled.icas) == 1
    assert verbose_clause in filled.icas[0].ica_text
    assert "ica_prose_quality_warning" in filled.icas[0].quality_warnings
    assert "ica_deviation_over_32_words" in filled.icas[0].quality_warnings
    assert "ica_deviation_contains_example" in filled.icas[0].quality_warnings


def test_ica_style_warning_does_not_repin_structural_authority() -> None:
    """Presentation diagnostics stay outside the ICA authority digest."""
    slot = ICASlot(
        slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
        responsibility="RESP-1",
        control_action="CA-1-1",
        uca_type=UCAType.not_provided,
        is_na=False,
        icas=[
            ICA(
                ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                ica_text="Validation is not provided.",
                hazardous_context="An unreviewed request reaches the process.",
                loss_scenario="The protected operation is harmed.",
                related_hazards=["H-1"],
                related_constraints=["SC-1"],
            )
        ],
    )
    baseline = ICAEnumeration(slots=[slot])
    warned_ica = slot.icas[0].model_copy(
        update={"quality_warnings": ["ica_prose_quality_warning"]}
    )
    warned = baseline.model_copy(
        update={
            "slots": [
                slot.model_copy(update={"icas": [warned_ica]}),
            ]
        }
    )

    assert compute_ica_enumeration_digest(warned) == compute_ica_enumeration_digest(
        baseline
    )


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


def test_wrong_duration_uses_typed_temporality_not_prose() -> None:
    structure = _control_structure()
    slot = next(
        item
        for item in create_slots(structure)
        if item.uca_type is UCAType.wrong_duration
    )
    draft = SlotIcaDraft(
        slot_id=slot.slot_id,
        is_na=False,
        findings=(
            IcaFindingDraft(
                deviation=IcaDeviationDraft(
                    duration_deviation="the action continues for too long"
                ),
                hazardous_context="the unsafe state persists",
                loss_consequence="the protected operation is harmed",
                related_hazard_ids=("H-1",),
                related_constraint_ids=("SC-1",),
            ),
        ),
    )
    with pytest.raises(ValueError, match="action temporality"):
        compile_ica_slot_draft(
            draft,
            slot=slot,
            loss_analysis=_loss_analysis(),
            control_structure=structure,
        )

    eligible_slot = slot.model_copy(
        update={"action_temporality": ControlActionTemporality.continuous}
    )
    result = compile_ica_slot_draft(
        draft,
        slot=eligible_slot,
        loss_analysis=_loss_analysis(),
        control_structure=structure,
    )

    assert not result.is_na
    assert result.action_temporality is ControlActionTemporality.continuous


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
    assert result.call_evidence[0].attempt_count == 0
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
        def route(self, request, *, correction_feedback=None):
            observed.append(tuple(item.obligation_id for item in request.briefs))
            return StructuralRoutingResponse(
                adapter_kind="fake",
                request_digest=request.semantic_digest,
                routes=tuple(
                    ObligationRoute(
                        obligation_id=item.obligation_id,
                        disposition="targeted",
                        semantic_assessment=route_assessment(item),
                        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
                        hazard_ids=("H-1",),
                        constraint_ids=("SC-1",),
                        evidence=("budget-split",),
                    )
                    for item in request.briefs
                ),
            )

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


_RETRY_DECISION = {
    "gap_handle": "revision-gap-1",
    "disposition": "dismiss_unsupported",
    "rationale": "The supplied evidence does not justify it.",
}


@pytest.mark.parametrize(
    "first_reply",
    [
        {
            "draft": {},
            "gap_decisions": [{**_RETRY_DECISION, "disposition": "unknown"}],
        },
        {"draft": {}},
    ],
    ids=["unknown-disposition", "missing-gap-decisions"],
)
def test_revision_provider_reports_its_validation_retry_as_a_call(
    tmp_path, first_reply
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
    responses = [first_reply, {"draft": {}, "gap_decisions": [_RETRY_DECISION]}]
    sent: list[object] = []

    class Client:
        model = "revision-count-test"

        def complete(self, **kwargs):
            sent.append(kwargs)
            return LLMResult(
                content=responses.pop(0),
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    response = ObligationAwareLLMAdapter(
        Client(), run_dir=tmp_path, controls=controls
    ).revise(request)

    assert len(sent) == 2
    assert response.provider_calls == 2


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
                obligation_handle="R1",
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
                content={"filled_slots": [provider_slot_payload(draft)]},
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
