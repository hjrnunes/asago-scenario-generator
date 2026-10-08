"""Focused regressions for the bounded Stage 2 semantic review seam."""

from __future__ import annotations

from copy import deepcopy

import pytest
from jsonschema import Draft202012Validator

from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis, Obligation
from asago_scenario_generator.stpa.system_model.semantic_review import (
    ControlStructureSemanticReview,
    SourceEvidence,
    apply_control_structure_semantic_review,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model.control_structure import (
    PROMPTS_DIR,
    _call_3_coordination,
    _coordination_provider_schema,
    _validate_semantic_review_response,
    _Call3SourceExcerpt,
    _parse_call3_source_selection,
    derive_control_structure,
)
from tests.stpa.sp1_helpers import MockLLMClient
from asago_scenario_generator.stpa.infra.llm import LLMResult
from tests.helpers.sp1_control_structure import (
    _make_loss_analysis,
    _valid_control_element_set_dict,
    _valid_requirement_set_dict,
    _valid_responsibility_set_dict,
)


USE_CASE = "Chamber settings are validated before applying them."
_USE_CASE_EVIDENCE = {
    "source_ref": "USE_CASE",
    "quote": "validated before applying them",
    "meaning": "The use case authorizes validation before application.",
}


@pytest.mark.parametrize("field", ["quote", "meaning"])
def test_source_evidence_rejects_blank_text(field):
    value = {"source_ref": "L-1", "quote": "quoted", "meaning": "why"}
    value[field] = "  "
    with pytest.raises(ValueError, match="nonblank"):
        SourceEvidence.model_validate(value)


def test_source_evidence_rejects_non_loss_source_shape():
    with pytest.raises(ValueError, match="source_ref"):
        SourceEvidence.model_validate(
            {"source_ref": "H-1", "quote": "quoted", "meaning": "why"}
        )


def test_coordination_provider_schema_requires_the_complete_review(
    tmp_path,
):

    losses, structure = authorities()
    payload = response_payload(review_payload(losses, structure))
    client = MockLLMClient()
    client.set_response_queue([payload])
    _call_3_coordination(
        llm_client=client,
        use_case_text=USE_CASE,
        control_structure=structure,
        loss_analysis=losses,
        run_dir=tmp_path,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0,
    )
    validator = Draft202012Validator(
        client.calls[0].response_format.model_json_schema()
    )
    assert not list(validator.iter_errors(payload))
    assert list(validator.iter_errors({"coordination_links": []}))

    missing = deepcopy(payload)
    missing["semantic_review"]["hazards"].pop()
    assert list(validator.iter_errors(missing))
    missing = deepcopy(payload)
    missing["semantic_review"]["constraints"].pop()
    assert list(validator.iter_errors(missing))

    schema = _coordination_provider_schema(
        structure,
        losses,
        use_case_text=USE_CASE,
    ).model_json_schema()
    hazard_properties = schema["$defs"]["ProviderHazardSemanticReview"]["properties"]
    constraint_properties = schema["$defs"]["ProviderConstraintHazardReview"][
        "properties"
    ]
    assert {
        "hazard_id",
        "disposition",
        "revised_description",
        "missing_fact",
        "source_evidence",
        "rationale",
    } <= set(hazard_properties)
    assert {
        "constraint_id",
        "disposition",
        "revised_description",
        "missing_fact",
        "related_hazards",
        "source_evidence",
        "rationale",
    } <= set(constraint_properties)


def test_coordination_schema_allows_no_actions_only_when_none_exist():
    losses, structure = authorities()
    payload = {"semantic_review": review_payload(losses, structure)}
    structure.responsibilities[1].control_actions.clear()
    validator = Draft202012Validator(
        _coordination_provider_schema(structure, losses).model_json_schema()
    )
    assert list(validator.iter_errors(payload))
    payload["semantic_review"]["actions"] = []
    assert not list(validator.iter_errors(payload))


@pytest.mark.parametrize(
    "collection,field",
    [
        ("responsibilities", "responsibility_id"),
        ("actions", "control_action_id"),
    ],
)
def test_coordination_schema_does_not_offer_unknown_review_identities(
    collection, field
):
    losses, structure = authorities()
    payload = response_payload(review_payload(losses, structure))
    payload["semantic_review"][collection][0][field] = "UNKNOWN"
    validator = Draft202012Validator(
        _coordination_provider_schema(structure, losses).model_json_schema()
    )
    assert list(validator.iter_errors(payload))


def test_coordination_schema_avoids_xgrammar_unique_items_keyword():
    """The provider schema stays portable; semantic validation owns uniqueness."""
    losses, structure = authorities()
    loss_payload = losses.model_dump()
    loss_payload["hazards"].append(
        {
            "hazard_id": "H-2",
            "description": "Unstable chamber setting",
            "related_losses": ["L-1"],
        }
    )
    losses = LossAnalysis.model_validate(loss_payload)
    payload = response_payload(review_payload(losses, structure))
    payload["semantic_review"]["constraints"][0]["related_hazards"] = [
        "H-1",
        "H-1",
    ]
    schema = _coordination_provider_schema(structure, losses).model_json_schema()
    assert not _contains_schema_keyword(schema, "uniqueItems")
    assert not list(Draft202012Validator(schema).iter_errors(payload))
    with pytest.raises(ValueError, match="duplicate"):
        _validate_semantic_review_response(payload, structure, losses)


def test_coordination_schema_rejects_unknown_review_identities_and_keeps_edges_open():
    losses, structure = authorities()
    payload = response_payload(review_payload(losses, structure))
    validator = Draft202012Validator(
        _coordination_provider_schema(structure, losses).model_json_schema()
    )

    unknown = deepcopy(payload)
    unknown["semantic_review"]["hazards"][0]["hazard_id"] = "H-99"
    assert list(validator.iter_errors(unknown))

    duplicate = deepcopy(payload)
    duplicate["semantic_review"]["constraints"][0]["related_hazards"] = [
        "H-1",
        "H-1",
    ]
    # The portable provider schema deliberately does not use uniqueItems.
    assert not _contains_schema_keyword(validator.schema, "uniqueItems")
    # A one-hazard graph is still bounded to one edge slot; the semantic
    # validator remains the authority for duplicate detection in larger graphs.
    assert list(validator.iter_errors(duplicate))
    with pytest.raises(ValueError, match="duplicate"):
        _validate_semantic_review_response(duplicate, structure, losses)


def test_coordination_review_rejects_shared_state_outside_its_endpoints():
    losses, structure = authorities()
    payload = structure.model_dump()
    payload["responsibilities"].append(
        {
            "resp_id": "RESP-3",
            "description": "Independent logging",
            "process_model_parts": [{"pm_id": "PM-3-1", "description": "Log position"}],
        }
    )
    structure = ControlStructure.model_validate(payload)
    review = review_payload(losses, structure)
    response = response_payload(review)
    response["coordination_links"] = [
        {
            "link_id": "CL-1",
            "source": "RESP-1",
            "target": "RESP-2",
            "shared_pm": "PM-3-1",
            "description": "Settings coordination",
            "coordination_mechanism": {
                "cm_id": "CM-1",
                "description": "Settings handoff",
                "payload": "Settings",
            },
        }
    ]
    with pytest.raises(ValueError, match="exactly one endpoint"):
        _validate_semantic_review_response(response, structure, losses)


def test_coordination_ownership_error_names_every_bad_link_and_its_choices():
    """A retry needs the owner and the valid endpoint PMs for every bad link."""
    losses, structure = authorities()
    payload = structure.model_dump()
    payload["responsibilities"][0]["process_model_parts"] = [
        {"pm_id": "PM-1-1", "description": "Validated settings"}
    ]
    payload["responsibilities"][1]["process_model_parts"] = [
        {"pm_id": "PM-2-1", "description": "Selected settings"}
    ]
    payload["responsibilities"].append(
        {
            "resp_id": "RESP-3",
            "description": "Independent logging",
            "process_model_parts": [{"pm_id": "PM-3-1", "description": "Log position"}],
        }
    )
    structure = ControlStructure.model_validate(payload)
    response = response_payload(review_payload(losses, structure))
    response["coordination_links"] = [
        {
            "link_id": link_id,
            "source": "RESP-1",
            "target": "RESP-2",
            "shared_pm": shared_pm,
            "description": "Settings coordination",
            "coordination_mechanism": {
                "cm_id": f"CM-{index}",
                "description": "Settings handoff",
                "payload": "Settings",
            },
        }
        for index, (link_id, shared_pm) in enumerate(
            [("CL-1", "PM-3-1"), ("CL-2", "CP-1")], start=1
        )
    ]
    with pytest.raises(ValueError) as caught:
        _validate_semantic_review_response(response, structure, losses)
    message = str(caught.value)
    assert "'CL-1'" in message and "'CL-2'" in message
    assert "PM-3-1' belongs to RESP-3" in message
    assert "'CP-1' is not a process-model part" in message
    assert message.count("PM-1-1, PM-2-1") == 2


def test_coordination_prompts_state_the_endpoint_ownership_rule(tmp_path):

    losses, structure = authorities()
    client = MockLLMClient()
    client.set_response_queue([response_payload(review_payload(losses, structure))])
    _call_3_coordination(
        llm_client=client,
        use_case_text=USE_CASE,
        control_structure=structure,
        loss_analysis=losses,
        run_dir=tmp_path,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0,
    )
    normalized = " ".join(client.calls[0].user_prompt.split())
    assert "listed under the link's `source` or `target`" in normalized


def _with_obligation(losses, rule_span):
    losses.security_constraints[0].obligations = [
        Obligation(
            obligation_id="O1",
            kind="required",
            behavior="validate the settings",
            rule_span=rule_span,
        )
    ]
    return losses


def _revise_first_constraint(payload, revised_description):
    payload["constraints"][0].update(
        disposition="revise",
        revised_description=revised_description,
        source_evidence=[
            {
                "source_ref": "USE_CASE",
                "quote": "validated before applying them",
                "meaning": "The use case authorizes validation before application.",
            }
        ],
    )
    return payload


def test_constraint_revision_that_drops_an_obligation_phrase_names_it():
    """A revised rule must keep each obligation phrase; the error says which
    phrase went missing and how to correct the decision."""
    losses, draft = authorities()
    losses = _with_obligation(losses, "Validate settings")
    payload = _revise_first_constraint(
        review_payload(losses, draft),
        "Check every chamber setting against the loaded profile.",
    )

    with pytest.raises(ValueError) as error:
        apply_control_structure_semantic_review(
            draft,
            losses,
            ControlStructureSemanticReview.model_validate(payload),
            use_case_text=USE_CASE,
        )

    message = str(error.value)
    assert (
        "constraint SC-1 revise drops obligation phrase O1 'Validate settings'"
        in message
    )
    assert "keep each phrase unchanged inside revised_description" in message
    assert "or preserve SC-1" in message


def test_constraint_revision_that_keeps_obligation_phrases_is_applied():
    losses, draft = authorities()
    losses = _with_obligation(losses, "Validate settings")
    payload = _revise_first_constraint(
        review_payload(losses, draft),
        "validate settings against the loaded profile before applying them.",
    )

    result = apply_control_structure_semantic_review(
        draft,
        losses,
        ControlStructureSemanticReview.model_validate(payload),
        use_case_text=USE_CASE,
    )

    reviewed = result.loss_analysis.security_constraints[0]
    assert reviewed.rule.startswith("validate settings against")
    assert [entry.rule_span for entry in reviewed.obligations] == ["Validate settings"]


def test_call3_prompt_lists_obligation_phrases_a_revision_must_keep(tmp_path):

    losses, structure = authorities()
    losses = _with_obligation(losses, "Validate settings")
    client = MockLLMClient()
    client.set_response_queue([response_payload(review_payload(losses, structure))])
    _call_3_coordination(
        llm_client=client,
        use_case_text=USE_CASE,
        control_structure=structure,
        loss_analysis=losses,
        run_dir=tmp_path,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0,
    )

    user = " ".join(client.calls[0].user_prompt.split())
    assert (
        "Obligation phrases (a revised rule keeps each one verbatim): "
        '"Validate settings"' in user
    )
    assert "A revised rule must contain every listed obligation phrase" in user


def test_review_preserves_drafts_and_applies_hazard_then_constraint_changes():
    losses, draft = authorities()
    before_loss = losses.model_dump()
    before_structure = draft.model_dump()
    payload = review_payload(losses, draft)
    payload["hazards"][0].update(
        disposition="revise",
        revised_description=(
            "A chamber setting can damage samples when applied incorrectly."
        ),
        source_evidence=[
            {
                "source_ref": "L-1",
                "quote": "Damage to samples",
                "meaning": "The loss gives the reviewed hazard its consequence.",
            }
        ],
    )
    payload["constraints"][0].update(
        disposition="revise",
        revised_description="Validate chamber settings before applying them.",
        source_evidence=[
            {
                "source_ref": "USE_CASE",
                "quote": "validated before applying them",
                "meaning": "The use case authorizes validation before application.",
            }
        ],
    )
    result = apply_control_structure_semantic_review(
        draft,
        losses,
        ControlStructureSemanticReview.model_validate(payload),
        use_case_text=USE_CASE,
    )

    assert result.loss_analysis.hazards[0].description.startswith(
        "A chamber setting can damage"
    )
    assert (
        result.loss_analysis.security_constraints[0].description
        == "Validate chamber settings before applying them."
    )
    assert result.loss_analysis.hazards[0].related_losses == ["L-1"]
    assert losses.model_dump() == before_loss
    assert draft.model_dump() == before_structure


def test_conditional_constraint_revision_rewords_the_rule_once():
    """A reviewed rule correction keeps the authored conditions exactly once.

    Call 3 renders the authored rule with the applies-when conditions shown
    separately as fixed context, so the model's revised_description is the
    corrected rule.  The composed description must carry the conditions
    exactly once (Phase 1.3 as amended).
    """
    losses, draft = authorities()
    constraint = losses.security_constraints[0]
    constraint.applies_when = ["the chamber is loaded"]
    constraint.description = f"{constraint.rule} Applies when: the chamber is loaded."
    payload = review_payload(losses, draft)
    payload["constraints"][0].update(
        disposition="revise",
        revised_description=(
            "Validate every chamber setting against the loaded profile."
        ),
        source_evidence=[
            {
                "source_ref": "USE_CASE",
                "quote": "validated before applying them",
                "meaning": "The use case authorizes validation before application.",
            }
        ],
    )
    result = apply_control_structure_semantic_review(
        draft,
        losses,
        ControlStructureSemanticReview.model_validate(payload),
        use_case_text=USE_CASE,
    )
    reviewed = result.loss_analysis.security_constraints[0]
    assert reviewed.rule == (
        "Validate every chamber setting against the loaded profile."
    )
    assert reviewed.applies_when == ["the chamber is loaded"]
    assert reviewed.description == (
        "Validate every chamber setting against the loaded profile. "
        "Applies when: the chamber is loaded."
    )
    assert reviewed.description.count("Applies when:") == 1


def test_conditional_constraint_echoing_the_composed_text_is_preserved():
    """An unchanged echo of the rendered view must not reword the rule.

    The Call 3 parser compares the returned replacement against the
    authored rule; a row that echoes the composed display text unchanged
    is downgraded to preserve instead of composing the conditions twice.
    """
    losses, draft = authorities()
    constraint = losses.security_constraints[0]
    constraint.applies_when = ["the chamber is loaded"]
    constraint.description = f"{constraint.rule} Applies when: the chamber is loaded."
    payload = review_payload(losses, draft)
    payload["constraints"][0].update(
        disposition="revise",
        revised_description=constraint.description,
        source_evidence=[
            {
                "source_ref": "USE_CASE",
                "meaning": "The use case authorizes validation before application.",
            }
        ],
    )

    parsed = _parse_call3_source_selection(
        LLMResult(
            content=response_payload(payload),
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt="",
            user_prompt="",
        ),
        (
            _Call3SourceExcerpt(
                local_ref="USE_CASE",
                canonical_ref="USE_CASE",
                text="validated before applying them",
                meaning="The use case authorizes validation before application.",
            ),
        ),
        structure=draft,
        loss_analysis=losses,
    )
    row = next(
        item
        for item in parsed.semantic_review.constraints
        if item.constraint_id == "SC-1"
    )
    assert row.disposition == "preserve"
    assert row.revised_description is None


def test_review_repairs_ownership_and_internal_observation_without_mutating_draft():
    losses, draft = authorities()
    before = draft.model_dump()
    payload = review_payload(losses, draft)
    payload["responsibilities"][1]["constraint_refs"] = ["SC-1"]
    payload["actions"][0] = {
        "control_action_id": "CA-2-1",
        "effect_kind": "agent_message",
        "rationale": "The message is internal, not returned to the caller.",
    }
    reviewed = apply_control_structure_semantic_review(
        draft,
        losses,
        ControlStructureSemanticReview.model_validate(payload),
    ).control_structure
    assert reviewed.responsibilities[1].security_constraint_refs == ["SC-1"]
    assert (
        reviewed.responsibilities[1].control_actions[0].effect_kind.value
        == "agent_message"
    )
    assert draft.model_dump() == before
    assert reviewed.responsibilities[0] == draft.responsibilities[0]


@pytest.mark.parametrize(
    "change",
    ["missing_owner", "unknown_constraint", "missing_action", "duplicate_owner"],
)
def test_review_cannot_guess_or_silently_omit_identities(change):
    losses, draft = authorities()
    payload = review_payload(losses, draft)
    if change == "missing_owner":
        payload["responsibilities"].pop()
    elif change == "unknown_constraint":
        payload["responsibilities"][1]["constraint_refs"] = ["SC-99"]
    elif change == "missing_action":
        payload["actions"] = []
    else:
        payload["responsibilities"].append(payload["responsibilities"][0])
    with pytest.raises(ValueError):
        apply_control_structure_semantic_review(
            draft,
            losses,
            ControlStructureSemanticReview.model_validate(payload),
        )


def test_genuine_missing_constraint_and_unknown_effect_remain_explicit():
    losses, draft = authorities()
    payload = review_payload(losses, draft)
    payload["responsibilities"][1].update(
        constraint_refs=[],
        rationale="No supplied rule governs this function.",
    )
    payload["actions"][0].update(
        effect_kind=None,
        rationale="The use case does not establish where this action is observed.",
    )
    reviewed = apply_control_structure_semantic_review(
        draft,
        losses,
        ControlStructureSemanticReview.model_validate(payload),
    ).control_structure
    assert reviewed.responsibilities[1].security_constraint_refs == []
    assert reviewed.responsibilities[1].control_actions[0].effect_kind is None


def test_joint_review_corrects_constraint_hazard_edge_without_inventing_authority():
    losses, draft = authorities()
    before_loss = losses.model_dump()
    before_structure = draft.model_dump()
    payload = review_payload(losses, draft)
    payload["constraints"][0]["related_hazards"] = []
    payload["constraints"][0]["rationale"] = (
        "The supplied material does not establish this constraint-to-hazard edge."
    )
    result = apply_control_structure_semantic_review(
        draft,
        losses,
        ControlStructureSemanticReview.model_validate(payload),
    )
    assert result.loss_analysis.security_constraints[0].related_hazards == []
    assert result.control_structure.responsibilities[0].security_constraint_refs == [
        "SC-1"
    ]
    assert losses.model_dump() == before_loss
    assert draft.model_dump() == before_structure
    assert result.loss_analysis.hazards[0].description == "Incorrect chamber setting"


@pytest.mark.parametrize("edge_change", [["H-99"], ["H-1", "H-1"]])
def test_constraint_hazard_review_rejects_unknown_or_duplicate_edges(edge_change):
    losses, draft = authorities()
    payload = review_payload(losses, draft)
    payload["constraints"][0]["related_hazards"] = edge_change
    with pytest.raises(ValueError):
        apply_control_structure_semantic_review(
            draft,
            losses,
            ControlStructureSemanticReview.model_validate(payload),
        )


@pytest.mark.parametrize(
    "row_kind,disposition,updates,match",
    [
        (
            "hazards",
            "preserve",
            {"revised_description": "replacement"},
            "preserve",
        ),
        (
            "hazards",
            "revise",
            {"revised_description": "changed", "source_evidence": []},
            "source_evidence",
        ),
        (
            "hazards",
            "unresolved",
            {"missing_fact": "  "},
            "missing_fact",
        ),
        (
            "constraints",
            "preserve",
            {"missing_fact": "not allowed"},
            "preserve",
        ),
        (
            "constraints",
            "revise",
            {
                "revised_description": "changed",
                "source_evidence": [],
            },
            "source_evidence",
        ),
        ("hazards", "revise", {"revised_description": None}, "changed nonblank"),
        ("hazards", "revise", {"revised_description": "  "}, "changed nonblank"),
        (
            "hazards",
            "revise",
            {"revised_description": " Incorrect chamber setting "},
            "changed nonblank",
        ),
        (
            "hazards",
            "revise",
            {
                "revised_description": "changed",
                "missing_fact": "gap",
                "source_evidence": [_USE_CASE_EVIDENCE],
            },
            "revise cannot provide missing_fact",
        ),
        (
            "hazards",
            "unresolved",
            {"revised_description": "changed", "missing_fact": "gap"},
            "unresolved cannot provide revised_description",
        ),
        (
            "constraints",
            "unresolved",
            {"missing_fact": "gap"},
            "must have empty hazard edges",
        ),
    ],
)
def test_review_disposition_invariants_are_closed(
    row_kind,
    disposition,
    updates,
    match,
):
    losses, structure = authorities()
    payload = review_payload(losses, structure)
    row = payload[row_kind][0]
    row["disposition"] = disposition
    row.update(updates)
    with pytest.raises(ValueError, match=match):
        apply_control_structure_semantic_review(
            structure,
            losses,
            ControlStructureSemanticReview.model_validate(payload),
            use_case_text=USE_CASE,
        )


def test_review_is_required():
    losses, structure = authorities()
    with pytest.raises(ValueError, match="semantic_review is required"):
        apply_control_structure_semantic_review(structure, losses, None)


def test_review_rejects_bad_evidence_and_unresolved_links_or_ownership():
    losses, structure = authorities()

    bad_quote = review_payload(losses, structure)
    bad_quote["hazards"][0].update(
        disposition="revise",
        revised_description="A corrected chamber hazard.",
        source_evidence=[
            {
                "source_ref": "L-1",
                "quote": "not in loss",
                "meaning": "Unsupported quote.",
            }
        ],
    )
    with pytest.raises(ValueError, match="exact substring"):
        apply_control_structure_semantic_review(
            structure,
            losses,
            ControlStructureSemanticReview.model_validate(bad_quote),
        )

    unknown_source = review_payload(losses, structure)
    unknown_source["constraints"][0].update(
        disposition="revise",
        revised_description="A corrected chamber constraint.",
        source_evidence=[
            {
                "source_ref": "L-99",
                "quote": "anything",
                "meaning": "Unsupported source.",
            }
        ],
    )
    with pytest.raises(ValueError, match="source_ref"):
        apply_control_structure_semantic_review(
            structure,
            losses,
            ControlStructureSemanticReview.model_validate(unknown_source),
        )

    unresolved_hazard = review_payload(losses, structure)
    unresolved_hazard["hazards"][0].update(
        disposition="unresolved",
        missing_fact="The consequence path is not established.",
    )
    with pytest.raises(ValueError, match="unresolved hazard"):
        apply_control_structure_semantic_review(
            structure,
            losses,
            ControlStructureSemanticReview.model_validate(unresolved_hazard),
            use_case_text=USE_CASE,
        )

    unresolved_constraint = review_payload(losses, structure)
    unresolved_constraint["constraints"][0].update(
        disposition="unresolved",
        related_hazards=[],
        missing_fact="The governing condition is not supplied.",
    )
    with pytest.raises(ValueError, match="owns an unresolved constraint"):
        apply_control_structure_semantic_review(
            structure,
            losses,
            ControlStructureSemanticReview.model_validate(unresolved_constraint),
            use_case_text=USE_CASE,
        )

    unresolved_constraint["responsibilities"][0]["constraint_refs"] = []
    result = apply_control_structure_semantic_review(
        structure,
        losses,
        ControlStructureSemanticReview.model_validate(unresolved_constraint),
        use_case_text=USE_CASE,
    )
    assert result.loss_analysis.security_constraints[0].related_hazards == []


def test_run17_scope_corrections_preserve_authorized_output_and_input_direction():
    losses, structure = run17_authorities()
    payload = review_payload(losses, structure)
    use_case_text = (
        "The service returns authenticated payment-plan details to the requesting "
        "customer and sends request content to a third-party model for provider processing."
    )
    payload["hazards"][0].update(
        disposition="revise",
        revised_description=(
            "Payment-plan details must not be disclosed to an unauthorized or "
            "wrong-account recipient."
        ),
        source_evidence=[
            {
                "source_ref": "USE_CASE",
                "quote": (
                    "returns authenticated payment-plan details to the requesting "
                    "customer"
                ),
                "meaning": (
                    "The service is authorized to return the authenticated "
                    "customer's details."
                ),
            }
        ],
    )
    payload["constraints"][0].update(
        disposition="revise",
        revised_description=(
            "Do not disclose payment-plan details to an unauthorized or "
            "wrong-account recipient."
        ),
        source_evidence=payload["hazards"][0]["source_evidence"],
    )
    payload["hazards"][1].update(
        disposition="revise",
        revised_description="Do not send unauthorized secrets to a third-party model.",
        source_evidence=[
            {
                "source_ref": "USE_CASE",
                "quote": (
                    "sends request content to a third-party model for provider "
                    "processing"
                ),
                "meaning": "This source statement describes provider-input direction.",
            }
        ],
    )
    payload["constraints"][1].update(
        disposition="revise",
        revised_description="Do not send unauthorized secrets to a third-party model.",
        source_evidence=payload["hazards"][1]["source_evidence"],
    )
    result = apply_control_structure_semantic_review(
        structure,
        losses,
        ControlStructureSemanticReview.model_validate(payload),
        use_case_text=use_case_text,
    )
    assert (
        "unauthorized or wrong-account" in result.loss_analysis.hazards[0].description
    )
    assert result.loss_analysis.security_constraints[0].description.startswith(
        "Do not disclose payment-plan"
    )
    assert result.loss_analysis.security_constraints[1].description.startswith(
        "Do not send unauthorized secrets"
    )
    owners = result.control_structure.responsibilities
    assert owners[0].security_constraint_refs == ["SC-2"]
    assert owners[1].security_constraint_refs == ["SC-5"]


def test_call3_repairs_one_invalid_constraint_edge_once(tmp_path):

    losses, structure = authorities()
    invalid = response_payload(review_payload(losses, structure))
    invalid["semantic_review"]["constraints"][0]["related_hazards"] = ["H-99"]
    valid = response_payload(review_payload(losses, structure))
    client = MockLLMClient()
    client.set_response_queue([invalid, valid])
    result = _call_3_coordination(
        llm_client=client,
        use_case_text=USE_CASE,
        control_structure=structure,
        loss_analysis=losses,
        run_dir=tmp_path,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0,
    )
    assert result.semantic_review is not None
    assert len(client.calls) == 2
    assert "Exact USE_CASE source context" in client.calls[0].user_prompt


def test_normal_stage2_uses_existing_fourth_call_and_persists_review(tmp_path):

    loss_analysis = _make_loss_analysis()
    _, structure = authorities()
    normal_review = review_payload(loss_analysis, structure)
    normal_review["hazards"] = [
        preserve_hazard(hazard.hazard_id) for hazard in loss_analysis.hazards
    ]
    normal_review["constraints"] = [
        preserve_constraint(constraint.constraint_id, constraint.related_hazards)
        for constraint in loss_analysis.security_constraints
    ]
    normal_review["responsibilities"] = [
        {
            "responsibility_id": "RESP-1",
            "constraint_refs": ["SC-1"],
            "rationale": "The authorization controller enforces the constraint.",
        },
        {
            "responsibility_id": "RESP-2",
            "constraint_refs": ["SC-2"],
            "rationale": "The output controller enforces the constraint.",
        },
    ]
    normal_review["actions"] = [
        {
            "control_action_id": "CA-1-1",
            "effect_kind": "tool_call",
            "rationale": "An operation is invoked.",
        },
        {
            "control_action_id": "CA-2-1",
            "effect_kind": "agent_message",
            "rationale": "The action targets a responsibility.",
        },
    ]
    normal_client = MockLLMClient()
    normal_client.set_response_queue(
        [
            _valid_requirement_set_dict(),
            _valid_responsibility_set_dict(),
            _valid_control_element_set_dict(),
            response_payload(normal_review),
        ]
    )
    result = derive_control_structure(
        llm_client=normal_client,
        use_case_text="Apply and validate chamber settings.",
        loss_analysis=loss_analysis,
        run_dir=tmp_path / "normal",
    )
    assert len(normal_client.calls) == 4
    assert result.control_structure.responsibilities[1].security_constraint_refs == [
        "SC-2"
    ]
    assert (tmp_path / "normal" / "control-structure-review.yaml").is_file()


def authorities():
    losses = LossAnalysis.model_validate(
        {
            "risk_card_losses": [],
            "use_case_losses": [
                {
                    "loss_id": "L-1",
                    "description": "Damage to samples",
                    "provenance": "use_case",
                    "source_risk_cards": [],
                }
            ],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": "Incorrect chamber setting",
                    "related_losses": ["L-1"],
                }
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-1",
                    "rule": "Validate settings before applying them.",
                    "related_hazards": ["H-1"],
                    "applies_when": [],
                }
            ],
        }
    )
    structure = ControlStructure.model_validate(
        {
            "responsibilities": [
                {
                    "resp_id": "RESP-1",
                    "description": "Validate settings",
                    "security_constraint_refs": ["SC-1"],
                },
                {
                    "resp_id": "RESP-2",
                    "description": "Select and apply settings",
                    "security_constraint_refs": [],
                    "control_actions": [
                        {
                            "ca_id": "CA-2-1",
                            "description": "Prepare the internal settings message",
                            "effect_kind": "model_output",
                            "target": {"type": "controlled_process", "id": "CP-1"},
                        }
                    ],
                },
            ],
            "controlled_processes": [
                {"cp_id": "CP-1", "description": "Chamber controller"}
            ],
        }
    )
    return losses, structure


def run17_authorities():
    losses = LossAnalysis.model_validate(
        {
            "risk_card_losses": [],
            "use_case_losses": [
                {
                    "loss_id": "L-2",
                    "description": "Wrong-account payment-plan disclosure",
                    "provenance": "use_case",
                    "source_risk_cards": [],
                },
                {
                    "loss_id": "L-5",
                    "description": "Unauthorized provider-input secret disclosure",
                    "provenance": "use_case",
                    "source_risk_cards": [],
                },
            ],
            "hazards": [
                {
                    "hazard_id": "H-2",
                    "description": "Backend financial data never appears in responses.",
                    "related_losses": ["L-2"],
                },
                {
                    "hazard_id": "H-5",
                    "description": "Third-party-model prompts are never allowed.",
                    "related_losses": ["L-5"],
                },
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-2",
                    "rule": "Backend financial data must never appear in responses.",
                    "related_hazards": ["H-2"],
                    "applies_when": [],
                },
                {
                    "constraint_id": "SC-5",
                    "rule": "Third-party-model prompts must never be used.",
                    "related_hazards": ["H-5"],
                    "applies_when": [],
                },
            ],
        }
    )
    structure = ControlStructure.model_validate(
        {
            "responsibilities": [
                {
                    "resp_id": "RESP-1",
                    "description": "Return customer payment-plan details",
                    "security_constraint_refs": ["SC-2"],
                    "control_actions": [
                        {
                            "ca_id": "CA-1-1",
                            "description": "Return payment-plan details",
                            "target": {"type": "controlled_process", "id": "CP-1"},
                            "effect_kind": "model_output",
                        }
                    ],
                },
                {
                    "resp_id": "RESP-2",
                    "description": "Prepare provider-input request content",
                    "security_constraint_refs": ["SC-5"],
                    "control_actions": [
                        {
                            "ca_id": "CA-2-1",
                            "description": "Send request content to provider",
                            "target": {"type": "controlled_process", "id": "CP-2"},
                            "effect_kind": "tool_call",
                        }
                    ],
                },
            ],
            "controlled_processes": [
                {"cp_id": "CP-1", "description": "Customer response service"},
                {"cp_id": "CP-2", "description": "Third-party model service"},
            ],
        }
    )
    return losses, structure


def review_payload(losses, structure):
    """Build an explicit all-preserve review for the supplied identities."""
    return {
        "hazards": [preserve_hazard(hazard.hazard_id) for hazard in losses.hazards],
        "constraints": [
            preserve_constraint(constraint.constraint_id, constraint.related_hazards)
            for constraint in losses.security_constraints
        ],
        "responsibilities": [
            {
                "responsibility_id": resp.resp_id,
                "constraint_refs": list(resp.security_constraint_refs),
                "rationale": "The supplied responsibility has an explicit reviewed scope.",
            }
            for resp in structure.responsibilities
        ],
        "actions": [
            {
                "control_action_id": action.ca_id,
                "effect_kind": action.effect_kind,
                "rationale": "The supplied action has an explicit observable effect.",
            }
            for resp in structure.responsibilities
            for action in resp.control_actions
        ],
    }


def preserve_hazard(hazard_id):
    return {
        "hazard_id": hazard_id,
        "disposition": "preserve",
        "revised_description": None,
        "missing_fact": None,
        "source_evidence": [],
        "rationale": "The supplied hazard wording is retained.",
    }


def preserve_constraint(constraint_id, related_hazards):
    return {
        "constraint_id": constraint_id,
        "disposition": "preserve",
        "revised_description": None,
        "missing_fact": None,
        "related_hazards": list(related_hazards),
        "source_evidence": [],
        "rationale": "The supplied constraint wording and hazard relation are retained.",
    }


def response_payload(review):
    return {
        "coordination_links": [],
        "semantic_review": review,
    }


def _contains_schema_keyword(value, keyword):
    if isinstance(value, dict):
        return keyword in value or any(
            _contains_schema_keyword(item, keyword) for item in value.values()
        )
    if isinstance(value, list):
        return any(_contains_schema_keyword(item, keyword) for item in value)
    return False
