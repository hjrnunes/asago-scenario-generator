"""Focused regressions for the Call 3 source-selection wire."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model.control_structure import (
    PROMPTS_DIR,
    _build_call3_source_excerpts,
    _call3_source_ref_map,
    _call_3_coordination,
    _coordination_provider_schema,
    _deterministic_integrity_findings,
    _parse_call3_source_selection,
)


USE_CASE = (
    "A library member may retrieve their own loan records.\n\n"
    "A librarian may update catalog entries."
)


def _authorities() -> tuple[LossAnalysis, ControlStructure]:
    losses = LossAnalysis.model_validate(
        {
            "risk_card_losses": [],
            "use_case_losses": [
                {
                    "loss_id": "L-1",
                    "description": "A loan record is disclosed to another member.",
                    "provenance": "use_case",
                    "source_risk_cards": [],
                }
            ],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": "A member receives another member's record.",
                    "related_losses": ["L-1"],
                }
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-1",
                    "rule": "Return records only to the requesting member.",
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
                    "description": "Return loan records",
                    "security_constraint_refs": ["SC-1"],
                }
            ],
            "controlled_processes": [],
        }
    )
    return losses, structure


def _provider_payload(losses: LossAnalysis, structure: ControlStructure) -> dict:
    excerpts = _build_call3_source_excerpts(USE_CASE, losses)
    local = _call3_source_ref_map(excerpts)
    use_case_ref = next(
        ref for ref, excerpt in local.items() if excerpt.canonical_ref == "USE_CASE"
    )
    loss_ref = next(
        ref for ref, excerpt in local.items() if excerpt.canonical_ref == "L-1"
    )
    return {
        "coordination_links": [],
        "semantic_review": {
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "disposition": "preserve",
                    "revised_description": None,
                    "missing_fact": None,
                    "source_evidence": [
                        {
                            "source_ref": use_case_ref,
                            "meaning": "The use case states the permitted lookup.",
                        }
                    ],
                    "rationale": "The supplied hazard wording is retained.",
                }
            ],
            "constraints": [
                {
                    "constraint_id": "SC-1",
                    "disposition": "preserve",
                    "revised_description": None,
                    "missing_fact": None,
                    "related_hazards": ["H-1"],
                    "source_evidence": [
                        {
                            "source_ref": loss_ref,
                            "meaning": "The loss states the prohibited disclosure.",
                        }
                    ],
                    "rationale": "The supplied constraint wording is retained.",
                }
            ],
            "responsibilities": [
                {
                    "responsibility_id": "RESP-1",
                    "constraint_refs": ["SC-1"],
                    "rationale": "The responsibility owns the supplied constraint.",
                }
            ],
            "actions": [],
        },
    }


def test_source_excerpts_are_exact_and_have_stable_local_handles() -> None:
    losses, _ = _authorities()

    excerpts = _build_call3_source_excerpts(USE_CASE, losses)

    assert [item.local_ref for item in excerpts] == [
        "source_1",
        "source_2",
        "source_3",
    ]
    assert [item.canonical_ref for item in excerpts] == [
        "USE_CASE",
        "USE_CASE",
        "L-1",
    ]
    assert all(item.text in USE_CASE for item in excerpts[:2])
    assert excerpts[2].text == losses.use_case_losses[0].description
    assert "Exact supplied" in excerpts[0].meaning
    assert "Exact supplied" in excerpts[2].meaning


def test_provider_schema_offers_local_source_selection_without_quote() -> None:
    losses, structure = _authorities()
    schema = _coordination_provider_schema(
        structure,
        losses,
        use_case_text=USE_CASE,
    ).model_json_schema()
    source_schema = _find_source_schema(schema)

    assert set(source_schema["properties"]) == {"source_ref", "meaning"}
    assert "quote" not in source_schema["properties"]
    assert set(source_schema["properties"]["source_ref"]["enum"]) == {
        "source_1",
        "source_2",
        "source_3",
    }

    payload = _provider_payload(losses, structure)
    assert not list(Draft202012Validator(schema).iter_errors(payload))


def test_parser_copies_exact_excerpt_and_maps_to_final_source_reference() -> None:
    losses, structure = _authorities()
    excerpts = _build_call3_source_excerpts(USE_CASE, losses)
    payload = _provider_payload(losses, structure)

    parsed = _parse_call3_source_selection(
        LLMResult(content=payload, prompt_tokens=0, completion_tokens=0, duration_ms=0),
        excerpts,
    )

    assert parsed.semantic_review is not None
    hazard_evidence = parsed.semantic_review.hazards[0].source_evidence[0]
    constraint_evidence = parsed.semantic_review.constraints[0].source_evidence[0]
    assert hazard_evidence.source_ref == "USE_CASE"
    assert (
        hazard_evidence.quote == "A library member may retrieve their own loan records."
    )
    assert constraint_evidence.source_ref == "L-1"
    assert constraint_evidence.quote == losses.use_case_losses[0].description


def test_parser_handles_provider_model_at_real_client_boundary() -> None:
    losses, structure = _authorities()
    excerpts = _build_call3_source_excerpts(USE_CASE, losses)
    payload = _provider_payload(losses, structure)
    provider_schema = _coordination_provider_schema(
        structure,
        losses,
        use_case_text=USE_CASE,
        source_excerpts=excerpts,
    )
    provider_model = provider_schema.model_validate(payload)

    parsed = _parse_call3_source_selection(
        LLMResult(
            content=provider_model,
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        ),
        excerpts,
    )

    assert parsed.semantic_review is not None
    assert (
        parsed.semantic_review.constraints[0].source_evidence[0].quote
        == losses.use_case_losses[0].description
    )


def test_call3_closes_explicit_unresolved_constraint_after_provider_model_parse(
    tmp_path,
) -> None:
    from tests.stpa.sp1_helpers import MockLLMClient

    losses, structure = _authorities()
    excerpts = _build_call3_source_excerpts(USE_CASE, losses)
    payload = _provider_payload(losses, structure)
    payload["semantic_review"]["constraints"][0]["disposition"] = "unresolved"
    payload["semantic_review"]["constraints"][0]["missing_fact"] = (
        "The requesting member identity cannot be verified."
    )
    provider_schema = _coordination_provider_schema(
        structure,
        losses,
        use_case_text=USE_CASE,
        source_excerpts=excerpts,
    )
    provider_model = provider_schema.model_validate(payload)
    client = MockLLMClient()
    client.set_response_queue([provider_model])

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
    assert result.semantic_review.constraints[0].related_hazards == ()
    assert result.semantic_review.responsibilities[0].constraint_refs == ()
    raw_call = json.loads((tmp_path / "calls.jsonl").read_text().splitlines()[0])
    assert '"related_hazards": ["H-1"]' in raw_call["response_content"]
    assert '"constraint_refs": ["SC-1"]' in raw_call["response_content"]


def test_call3_parser_rejects_unknown_constraint_reference_before_closure() -> None:
    losses, structure = _authorities()
    excerpts = _build_call3_source_excerpts(USE_CASE, losses)
    payload = _provider_payload(losses, structure)
    payload["semantic_review"]["responsibilities"][0]["constraint_refs"] = ["SC-99"]
    provider_schema = _coordination_provider_schema(
        structure,
        losses,
        use_case_text=USE_CASE,
        source_excerpts=excerpts,
    )
    provider_model = provider_schema.model_validate(payload)

    with pytest.raises(ValueError, match="unknown constraint"):
        _parse_call3_source_selection(
            LLMResult(
                content=provider_model,
                prompt_tokens=0,
                completion_tokens=0,
                duration_ms=0,
            ),
            excerpts,
            structure=structure,
            loss_analysis=losses,
        )


def test_call3_normalizes_noop_revision_before_strict_public_apply(tmp_path) -> None:
    from tests.stpa.sp1_helpers import MockLLMClient

    losses, structure = _authorities()
    excerpts = _build_call3_source_excerpts(USE_CASE, losses)
    payload = _provider_payload(losses, structure)
    constraint = payload["semantic_review"]["constraints"][0]
    constraint["disposition"] = "revise"
    constraint["revised_description"] = losses.security_constraints[0].description
    provider_schema = _coordination_provider_schema(
        structure,
        losses,
        use_case_text=USE_CASE,
        source_excerpts=excerpts,
    )
    provider_model = provider_schema.model_validate(payload)
    client = MockLLMClient()
    client.set_response_queue([provider_model])

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
    normalized = result.semantic_review.constraints[0]
    assert normalized.disposition == "preserve"
    assert normalized.revised_description is None
    raw_call = json.loads((tmp_path / "calls.jsonl").read_text().splitlines()[0])
    assert '"disposition": "revise"' in raw_call["response_content"]


def test_call3_parser_retains_changed_revision() -> None:
    losses, structure = _authorities()
    excerpts = _build_call3_source_excerpts(USE_CASE, losses)
    payload = _provider_payload(losses, structure)
    payload["semantic_review"]["constraints"][0]["disposition"] = "revise"
    payload["semantic_review"]["constraints"][0]["revised_description"] = (
        "Return each record only to its requesting member."
    )
    provider_schema = _coordination_provider_schema(
        structure,
        losses,
        use_case_text=USE_CASE,
        source_excerpts=excerpts,
    )
    provider_model = provider_schema.model_validate(payload)

    parsed = _parse_call3_source_selection(
        LLMResult(
            content=provider_model,
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        ),
        excerpts,
        structure=structure,
        loss_analysis=losses,
    )

    assert parsed.semantic_review is not None
    normalized = parsed.semantic_review.constraints[0]
    assert normalized.disposition == "revise"
    assert normalized.revised_description == (
        "Return each record only to its requesting member."
    )


@pytest.mark.parametrize(
    "mutate,match",
    [
        (lambda item: item.update(source_ref="source_99"), "displayed local excerpts"),
        (lambda item: item.update(quote="A copied quote"), "unexpected field"),
    ],
)
def test_parser_rejects_unknown_or_transcribed_source_evidence(mutate, match) -> None:
    losses, structure = _authorities()
    excerpts = _build_call3_source_excerpts(USE_CASE, losses)
    payload = _provider_payload(losses, structure)
    mutate(payload["semantic_review"]["hazards"][0]["source_evidence"][0])

    with pytest.raises(ValueError, match=match):
        _parse_call3_source_selection(
            LLMResult(
                content=payload,
                prompt_tokens=0,
                completion_tokens=0,
                duration_ms=0,
            ),
            excerpts,
        )


def test_call3_prompt_places_meaning_next_to_exact_sources_without_duplication(
    tmp_path,
) -> None:
    losses, structure = _authorities()
    excerpts = _build_call3_source_excerpts(USE_CASE, losses)
    source_refs = {item.canonical_ref: item.local_ref for item in excerpts}
    rendered = TemplateLoader(PROMPTS_DIR).render_prompt(
        "stage2_call3_user.j2",
        use_case_text=USE_CASE,
        control_structure=structure,
        loss_analysis=losses,
        source_excerpts=excerpts,
        source_ref_by_canonical=source_refs,
    )

    assert rendered.count("A library member may retrieve their own loan records.") == 1
    assert "[source_1]" in rendered
    assert "Each `source_N` means one exact supplied USE_CASE paragraph" in rendered
    assert "**L-1** (source_3)" in rendered
    assert rendered.index("Each `source_N` means") < rendered.index("[source_1]")


def test_call3_compatibility_prompt_keeps_use_case_when_no_loss_graph() -> None:
    _, structure = _authorities()
    rendered = TemplateLoader(PROMPTS_DIR).render_prompt(
        "stage2_call3_user.j2",
        use_case_text=USE_CASE,
        control_structure=structure,
        loss_analysis=None,
        source_excerpts=(),
        source_ref_by_canonical={},
    )

    assert USE_CASE in rendered
    assert "[source_1]" not in rendered


def test_call3_preserves_raw_selection_in_call_log_and_returns_final_evidence(
    tmp_path,
) -> None:
    from tests.stpa.sp1_helpers import MockLLMClient

    losses, structure = _authorities()
    payload = _provider_payload(losses, structure)
    client = MockLLMClient()
    client.set_response_queue([payload])

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
    assert result.semantic_review.hazards[0].source_evidence[0].source_ref == "USE_CASE"
    assert result.integrity_findings == list(
        _deterministic_integrity_findings(structure, losses)
    )
    call_log = json.loads((tmp_path / "calls.jsonl").read_text().splitlines()[0])
    assert '"source_ref": "source_1"' in call_log["response_content"]
    assert '"quote"' not in call_log["response_content"]


def test_call3_review_distinguishes_loss_objectives_from_permitted_behavior() -> None:
    losses, structure = _authorities()
    excerpts = _build_call3_source_excerpts(USE_CASE, losses)
    loader = TemplateLoader(PROMPTS_DIR)
    system = loader.render_prompt("stage2_call3_system.j2")
    user = loader.render_prompt(
        "stage2_call3_user.j2",
        use_case_text=USE_CASE,
        control_structure=structure,
        loss_analysis=losses,
        source_excerpts=excerpts,
        source_ref_by_canonical={e.canonical_ref: e.local_ref for e in excerpts},
    )
    normalized = " ".join(system.split())
    assert system.index("## Final semantic review") < system.index(
        "## Coordination links"
    )
    assert "`preserve` is not the default decision" in normalized
    assert "normative analysis inputs, not deployment observations" in normalized
    assert "loss does not need a duplicate requirement in USE_CASE" in normalized
    assert "Code derives its empty hazard-edge list" in normalized
    assert "Missing implementation" in normalized
    assert user.count("Linked loss L-1 (source_3)") == 1
    assert user.count("What permitted behavior remains?") == 1
    assert user.index("Linked loss L-1") < user.index("**SC-1** proposed wording")


def test_call3_integrity_diagnostics_are_code_owned() -> None:
    losses, structure = _authorities()
    loader = TemplateLoader(PROMPTS_DIR)
    from asago_scenario_generator.stpa.system_model.control_structure import (
        _coordination_provider_schema,
    )

    provider_fields = _coordination_provider_schema(
        structure,
        losses,
        use_case_text=USE_CASE,
        source_excerpts=_build_call3_source_excerpts(USE_CASE, losses),
    ).model_json_schema()["properties"]
    assert "integrity_findings" not in provider_fields
    rendered = loader.render_prompt(
        "stage2_call3_user.j2",
        use_case_text=USE_CASE,
        control_structure=structure,
        loss_analysis=losses,
        source_excerpts=_build_call3_source_excerpts(USE_CASE, losses),
        source_ref_by_canonical={"USE_CASE": "source_1", "L-1": "source_3"},
        integrity_findings=("error: supplied diagnostic",),
    )
    assert "error: supplied diagnostic" in rendered
    assert "Do not author an" in rendered and "integrity finding" in rendered
    assert "Verify connection integrity:" not in rendered


def test_current_call3_rejects_provider_authored_integrity_findings() -> None:
    losses, structure = _authorities()
    payload = _provider_payload(losses, structure)
    payload["integrity_findings"] = ["Provider says every connection is valid."]
    with pytest.raises(ValueError, match="code-owned or unknown fields"):
        _parse_call3_source_selection(
            LLMResult(
                content=payload,
                prompt_tokens=0,
                completion_tokens=0,
                duration_ms=0,
            ),
            _build_call3_source_excerpts(USE_CASE, losses),
            structure=structure,
            loss_analysis=losses,
        )


def _find_source_schema(schema: dict) -> dict:
    """Find the dynamic provider evidence definition without naming its ref."""
    for definition in schema.get("$defs", {}).values():
        properties = definition.get("properties", {})
        if set(properties) == {"source_ref", "meaning"}:
            return definition
    raise AssertionError("provider source selection schema is missing")
