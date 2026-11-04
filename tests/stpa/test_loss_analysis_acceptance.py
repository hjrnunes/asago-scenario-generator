"""Acceptance of a Stage 1a draft: one order shared by all three paths.

A Stage 1a draft arrives by a first reply, by a deterministic cleanup, or by
a targeted repair.  Every path must accept it the same way: re-check the
row-level repair view, merge over the authority of an earlier call, normalize
the citation evidence, and then run the path's own validators.  These tests
pin that order, its observable result, and the required model that keeps the
re-check from becoming a no-op.  Every fixture is synthetic; no test contacts
a model endpoint or a target.
"""

from __future__ import annotations

import inspect
import json

import pytest

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    LossAnalysisDraft,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    DeterministicCleanup,
    _apply_deterministic_cleanup,
    _handle_repair_input,
    _merge_loss_analysis_correction,
    _ProviderSecurityConstraint,
    _Stage1aCall,
    _Stage1aGapProviderDraft,
    _Stage1aGapRepairDraft,
    _Stage1aRiskProviderDraft,
    _Stage1aRiskRepairDraft,
    normalize_disposition_citations,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_acceptance import (
    accept_stage1a_draft,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    UnsupportedRepair,
    _finish_merged_draft,
    _RepairValidation,
    run_targeted_repair,
    salvage_corrected_reply,
)
from tests.helpers.stpa_builders import make_risk_cards
from tests.stpa.sp1_helpers import MockLLMClient

ATLAS_001 = "atlas-001"
CARD_REASON = "Every executed payment is checked by the operator."


def _wire_graph() -> dict:
    """The risk wire body with local handles, one card, and one neutral row."""
    return {
        "risk_card_losses": [
            {
                "handle": "payment_loss",
                "description": "Unauthorized payment.",
                "provenance": "risk_card",
                "source_risk_cards": [ATLAS_001],
            }
        ],
        "use_case_losses": [],
        "hazards": [
            {
                "handle": "unintended_payment",
                "description": "The agent executes an unintended payment.",
                "related_losses": ["payment_loss"],
            }
        ],
        "security_constraints": [
            {
                "handle": "payment_confirmation",
                "rule": "The agent must confirm every unintended payment.",
                "applies_when": ["before execution"],
                "behavior_class": "unauthorized_write",
                "related_hazards": ["unintended_payment"],
                "obligations": [],
            }
        ],
        "risk_dispositions": [
            {
                "risk_ref": ATLAS_001,
                "disposition": "not_applicable",
                "loss_ids": [],
                "reason": CARD_REASON,
            }
        ],
    }


def _accepted_draft() -> LossAnalysisDraft:
    """The domain draft the risk wire materializes into, before normalization."""
    return LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [
                {
                    "loss_id": "L-1",
                    "description": "Unauthorized payment.",
                    "provenance": "risk_card",
                    "source_risk_cards": [ATLAS_001],
                }
            ],
            "use_case_losses": [],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": "The agent executes an unintended payment.",
                    "related_losses": ["L-1"],
                }
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-1",
                    "rule": "The agent must confirm every unintended payment.",
                    "applies_when": ["before execution"],
                    "behavior_class": "unauthorized_write",
                    "related_hazards": ["H-1"],
                }
            ],
            "risk_dispositions": [
                {
                    "risk_ref": ATLAS_001,
                    "disposition": "not_applicable",
                    "reason": CARD_REASON,
                }
            ],
        }
    )


def _risk_call(tmp_path, *, warnings: list[str] | None = None) -> _Stage1aCall:
    """Build the first-reply call state for the synthetic risk response."""
    return _Stage1aCall(
        llm_client=MockLLMClient(),
        loader=TemplateLoader(PROMPTS_DIR),
        run_dir=tmp_path,
        step="risk_derivation",
        temperature=0.4,
        response_format=_Stage1aRiskProviderDraft,
        allowed_loss_ids=set(),
        allowed_hazard_ids=set(),
        require_losses=True,
        require_complete_chain=False,
        require_risk_accounting=True,
        accounting_cards=make_risk_cards((ATLAS_001,)),
        authoritative_draft=None,
        normalization_warnings=warnings,
        repair_record=None,
        template_vars={},
    )


def _reply(content: dict | None = None) -> LLMResult:
    return LLMResult(
        content=json.dumps(content if content is not None else _wire_graph()),
        duration_ms=1,
    )


def _expected_flip_warning() -> str:
    return (
        f"risk accounting normalized: '{ATLAS_001}' was not_applicable but is "
        f"cited by L-1; the model's dropped reason was: {CARD_REASON}; flipped "
        "to cited from the response's own citation evidence"
    )


def test_accept_stage1a_draft_requires_the_repair_model() -> None:
    parameters = inspect.signature(accept_stage1a_draft).parameters

    assert "repair_model" in parameters
    assert parameters["repair_model"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["repair_model"].default is inspect.Parameter.empty
    assert "authority" in parameters
    assert "warnings" in parameters


def test_run_targeted_repair_requires_the_provider_draft_model() -> None:
    parameters = inspect.signature(run_targeted_repair).parameters

    assert parameters["provider_draft_model"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["provider_draft_model"].default is inspect.Parameter.empty


def test_a_schema_breaking_draft_is_rejected_before_the_merge() -> None:
    broken = LossAnalysisDraft.model_construct(
        risk_card_losses=[],
        use_case_losses=[],
        hazards=[
            Hazard(
                hazard_id=f"H-{index}",
                description="An unintended payment.",
                related_losses=["L-1"],
            )
            for index in range(17)
        ],
        security_constraints=[],
        risk_dispositions=[],
    )
    warned: list[str] = []
    merged = False

    def merge(draft: LossAnalysisDraft) -> LossAnalysisDraft:
        nonlocal merged
        merged = True
        return draft

    with pytest.raises(
        ValueError, match="no longer satisfies the original provider schema"
    ):
        accept_stage1a_draft(
            broken,
            repair_model=_Stage1aRiskRepairDraft,
            authority=merge,
            warnings=warned,
            step="risk_derivation",
        )

    assert merged is False
    assert warned == []


def test_the_merge_runs_before_citation_normalization() -> None:
    authority = _accepted_draft()
    # The reply repeats the authority graph exactly; the card row is the only
    # citation evidence, and the merge removes the cited loss.
    incoming = _accepted_draft()
    warned: list[str] = []

    def merge(draft: LossAnalysisDraft) -> LossAnalysisDraft:
        return _merge_loss_analysis_correction(
            LossAnalysisDraft(), draft, authoritative_draft=authority
        )

    # Normalize-first would flip the row and warn; the overlap is real.
    assert normalize_disposition_citations(incoming.model_copy(deep=True))

    accepted = accept_stage1a_draft(
        incoming,
        repair_model=_Stage1aRiskRepairDraft,
        authority=merge,
        warnings=warned,
        step="risk_derivation",
    )

    assert accepted.risk_card_losses == []
    assert accepted.hazards == []
    assert accepted.security_constraints == []
    [row] = accepted.risk_dispositions
    assert row.disposition == "not_applicable"
    assert row.loss_ids == []
    assert warned == []


def test_exact_repeats_are_removed_from_the_accepted_draft() -> None:
    authority = _accepted_draft()
    incoming = _accepted_draft().model_copy(deep=True)
    incoming.risk_dispositions = []

    accepted = accept_stage1a_draft(
        incoming,
        repair_model=_Stage1aRiskRepairDraft,
        authority=lambda draft: _merge_loss_analysis_correction(
            LossAnalysisDraft(), draft, authoritative_draft=authority
        ),
        warnings=None,
        step="risk_derivation",
    )

    assert accepted.risk_card_losses == []
    assert accepted.hazards == []
    assert accepted.security_constraints == []


def test_a_reused_identity_with_changed_content_is_rejected() -> None:
    authority = _accepted_draft()
    incoming = _accepted_draft().model_copy(deep=True)
    incoming.risk_card_losses[0] = incoming.risk_card_losses[0].model_copy(
        update={"description": "A different loss meaning."}
    )
    warned: list[str] = []

    with pytest.raises(ValueError, match="conflicting duplicate loss ID 'L-1'"):
        accept_stage1a_draft(
            incoming,
            repair_model=_Stage1aRiskRepairDraft,
            authority=lambda draft: _merge_loss_analysis_correction(
                LossAnalysisDraft(), draft, authoritative_draft=authority
            ),
            warnings=warned,
            step="risk_derivation",
        )

    assert warned == []


def test_the_three_paths_accept_the_same_draft_identically(tmp_path) -> None:
    first_call = _risk_call(tmp_path, warnings=[])
    first = first_call.parse_first_response(_reply(), [])
    first_call.validate_references(first)
    first_warnings = list(first_call.normalization_warnings or [])

    cleanup_call = _risk_call(tmp_path, warnings=[])
    cleaned = _apply_deterministic_cleanup(
        cleanup_call,
        DeterministicCleanup(draft=_accepted_draft(), warnings=(), removed_rows=()),
        _Stage1aRiskRepairDraft,
        "first error",
    )
    cleanup_warnings = list(cleanup_call.normalization_warnings or [])

    repair_warnings: list[str] = []
    repaired = _finish_merged_draft(
        _accepted_draft(),
        _RepairValidation(
            run_validators=lambda draft: None,
            normalizer=normalize_disposition_citations,
            authoritative_merge=None,
            normalization_warnings=repair_warnings,
            provider_draft_model=_Stage1aRiskRepairDraft,
        ),
        step="risk_derivation",
    )

    assert cleaned.model_dump(mode="json") == first.model_dump(mode="json")
    assert repaired.model_dump(mode="json") == first.model_dump(mode="json")
    assert cleanup_warnings == first_warnings
    assert repair_warnings == first_warnings
    assert first_warnings == [_expected_flip_warning()]
    [row] = first.risk_dispositions
    assert row.disposition == "cited"
    assert row.loss_ids == ["L-1"]


def test_a_gap_draft_keeps_no_dispositions_after_salvage(tmp_path) -> None:
    body = {
        "risk_card_losses": [],
        "use_case_losses": [
            {
                "handle": "trust_loss",
                "description": "Loss of trust.",
                "provenance": "use_case",
                "source_risk_cards": [],
            }
        ],
        "hazards": [
            {
                "handle": "unchecked_reply",
                "description": "The agent sends an unchecked reply.",
                "related_losses": ["trust_loss"],
            }
        ],
        "security_constraints": [
            {
                "handle": "reply_check",
                "rule": "The agent must check every reply.",
                "applies_when": [],
                "related_hazards": ["unchecked_reply"],
                "obligations": [],
            }
        ],
        # A malformed row from the risk wire is removed, never accepted.
        "risk_dispositions": [{"disposition": "cited"}],
    }
    call = _Stage1aCall(
        llm_client=MockLLMClient(),
        loader=TemplateLoader(PROMPTS_DIR),
        run_dir=tmp_path,
        step="gap_analysis",
        temperature=0.4,
        response_format=_Stage1aGapProviderDraft,
        allowed_loss_ids=set(),
        allowed_hazard_ids=set(),
        require_losses=False,
        require_complete_chain=False,
        require_risk_accounting=False,
        accounting_cards=(),
        authoritative_draft=None,
        normalization_warnings=[],
        repair_record=None,
        template_vars={},
    )
    prepared = _handle_repair_input(
        _reply(body), response_format=call.response_format, prior=None
    )
    assert prepared is not None

    salvaged = salvage_corrected_reply(
        prepared.result,
        constraint_wire_model=_ProviderSecurityConstraint,
        response_format=prepared.response_format,
        gap_wire=True,
        ids=prepared.ids,
    )

    assert not isinstance(salvaged, UnsupportedRepair)
    draft, report = salvaged
    assert draft.risk_dispositions == []
    assert report.dropped_dispositions
    _Stage1aGapRepairDraft.model_validate(draft.model_dump(mode="json"))
