"""Regression coverage for the bounded Stage 1a gap-reference repair."""

from __future__ import annotations


import pytest

from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    diagnose_loss_analysis_semantics,
    derive_loss_analysis,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.stpa.sp1_helpers import MockLLMClient, valid_risk_draft_dict, make_risk_cards


def _run14_invalid_gap_response() -> dict:
    """Return the exact missing-loss shape from the run-14 saved response."""
    return {
        "risk_card_losses": [],
        "use_case_losses": [],
        "hazards": [
            {
                "hazard_id": "H-7",
                "description": (
                    "The AI assistant provides generic, non-specific, or "
                    "unhelpful responses to complex or nuanced customer "
                    "inquiries, leading to a failure in the service intent."
                ),
                "related_losses": ["L-7"],
            }
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-7",
                "rule": (
                    "The system must identify complex or nuanced queries that "
                    "fall outside the scope of standard, structured intents "
                    "and trigger an immediate escalation to a human agent."
                ),
                "related_hazards": ["H-7"],
                "applies_when": [],
            }
        ],
    }


def _run15_risk_response() -> dict:
    """Return the authoritative risk response from the run-15 capture."""
    return {
        "risk_dispositions": [
            {
                "risk_ref": "atlas-001",
                "disposition": "cited",
                "loss_ids": ["L-1"],
                "reason": None,
            }
        ],
        "risk_card_losses": [
            {
                "loss_id": "L-1",
                "description": (
                    "Unauthorized exposure of customer Personally Identifiable "
                    "Information (PII) or sensitive personal data through AI "
                    "model outputs or service provider data breaches."
                ),
                "provenance": "risk_card",
                "source_risk_cards": [
                    "ai-risk-taxonomy-unauthorized-disclosure---pii-(personal-identifiable-information)",
                    "ai-risk-taxonomy-unauthorized-distribution---pii-(personal-identifiable-information)",
                    "atlas-data-privacy-rights",
                    "atlas-exposing-personal-information",
                    "atlas-personal-information-in-data",
                    "credo-risk-029",
                    "credo-risk-036",
                    "credo-risk-037",
                    "mit-ai-risk-subdomain-2.1",
                ],
            }
        ],
        "use_case_losses": [],
        "hazards": [
            {
                "hazard_id": "H-1",
                "description": (
                    "The conversational interface or RAG-style (retrieval-augmented "
                    "generation) knowledge-grounding system reveals customer PII or "
                    "sensitive personal data in responses to unauthorized or "
                    "unintended recipients."
                ),
                "related_losses": ["L-1"],
            }
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "rule": (
                    "The conversational interface must restrict the inclusion of "
                    "customer PII or sensitive personal data in model outputs to "
                    "only those users with an established, authenticated session "
                    "matching the data owner's identity."
                ),
                "related_hazards": ["H-1"],
                "applies_when": [],
            }
        ],
    }


def _run15_invalid_gap_response() -> dict:
    """Return the first invalid gap response from the run-15 capture."""
    return {
        "risk_card_losses": [
            {
                "loss_id": "L-2",
                "description": (
                    "Financial loss to customers or merchants due to incorrect "
                    "processing of refunds, payments, or transaction adjustments."
                ),
                "provenance": "use_case",
                "source_risk_cards": [],
            },
            {
                "loss_id": "L-3",
                "description": (
                    "Regulatory non-compliance or legal sanctions resulting from "
                    "inaccurate information provided regarding fees, policies, or "
                    "payment terms."
                ),
                "provenance": "use_case",
                "source_risk_cards": [],
            },
            {
                "loss_id": "L-4",
                "description": (
                    "Loss of customer trust and brand reputation due to the delivery "
                    "of generic, incorrect, or unhelpful automated service responses."
                ),
                "provenance": "use_case",
                "source_risk_cards": [],
            },
        ],
        "use_case_losses": [],
        "hazards": [
            {
                "hazard_id": "H-2",
                "description": (
                    "The AI Assistant performs unintended or incorrect write operations "
                    "(refunds, payment scheduling, or modifications) to the Klarna "
                    "Backend Systems."
                ),
                "related_losses": ["L-2"],
            }
        ],
        "security_constraints": [
            {
                "constraint_id": f"SC-{index}",
                "rule": f"Run-15 constraint {index}.",
                "related_hazards": [f"H-{index}"],
                "applies_when": [],
            }
            for index in range(2, 18)
        ],
    }


def _run15_correction_response() -> dict:
    """Return a neutralized, closed correction shaped like run-15."""
    return {
        "risk_card_losses": [],
        "use_case_losses": [],
        "hazards": [
            {
                "hazard_id": "H-1",
                "description": (
                    "The conversational interface or RAG-style (retrieval-augmented "
                    "generation) knowledge-grounding system reveals customer PII or "
                    "sensitive personal data in responses to unauthorized or "
                    "unintended recipients."
                ),
                "related_losses": ["L-1"],
            },
            *[
                {
                    "hazard_id": f"H-{index}",
                    "description": f"Run-15 hazard {index}.",
                    "related_losses": {
                        2: ["L-2"],
                        3: ["L-3"],
                        4: ["L-4"],
                        5: ["L-3"],
                        6: ["L-4"],
                        7: ["L-3"],
                        8: ["L-2", "L-1"],
                        9: ["L-3", "L-4"],
                        10: ["L-2"],
                    }[index],
                }
                for index in range(2, 11)
            ],
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "rule": (
                    "The conversational interface must restrict the inclusion of "
                    "customer PII or sensitive personal data in model outputs to "
                    "only those users with an established, authenticated session "
                    "matching the data owner's identity."
                ),
                "related_hazards": ["H-1"],
                "applies_when": [],
            },
            *[
                {
                    "constraint_id": f"SC-{index}",
                    "rule": f"Run-15 corrected constraint {index}.",
                    "related_hazards": {
                        2: ["H-2"],
                        3: ["H-3", "H-5"],
                        4: ["H-6"],
                        5: ["H-4"],
                        6: ["H-7"],
                        7: ["H-8"],
                        8: ["H-9"],
                        9: ["H-10"],
                        10: ["H-2", "H-8"],
                        11: ["H-9"],
                        12: ["H-6"],
                        13: ["H-8", "H-10"],
                        14: ["H-4", "H-9"],
                        15: ["H-2"],
                        16: ["H-2", "H-3"],
                    }[index],
                    "applies_when": [],
                }
                for index in range(2, 17)
            ],
        ],
    }


def _empty_gap_response() -> dict:
    """Return an explicitly empty, complete-gap response."""
    return {
        "risk_card_losses": [],
        "use_case_losses": [],
        "hazards": [],
        "security_constraints": [],
    }


def test_run15_gap_graph_merges_without_id_union_leakage(tmp_path):
    """Captured run-15 gap graph merges with exact-repeat deduplication.

    The captured run-15 invalid gap response (constraints referencing
    undeclared hazards) is a typed terminal failure under the targeted-repair
    contract, so the corrected closed graph is supplied directly as the gap
    response.  The authority merge removes the exact repeats of the risk
    draft's H-1/SC-1 and adds the new records without ID-union leakage.
    """
    gap = _run15_correction_response()
    # The current local-handle wire treats the risk-stage graph as authority;
    # carry forward its exact H-1/SC-1 records by omitting them from the gap
    # additions.  The gap may add only the remaining scoped records.
    gap["hazards"] = [row for row in gap["hazards"] if row.get("hazard_id") != "H-1"]
    gap["security_constraints"] = [
        row for row in gap["security_constraints"] if row.get("constraint_id") != "SC-1"
    ]
    gap["use_case_losses"] = [
        {
            "loss_id": "L-2",
            "description": (
                "Financial loss to customers or merchants due to incorrect "
                "processing of refunds, payments, or transaction adjustments."
            ),
            "provenance": "use_case",
            "source_risk_cards": [],
        },
        {
            "loss_id": "L-3",
            "description": (
                "Regulatory non-compliance or legal sanctions resulting from "
                "inaccurate information provided regarding fees, policies, or "
                "payment terms."
            ),
            "provenance": "use_case",
            "source_risk_cards": [],
        },
        {
            "loss_id": "L-4",
            "description": (
                "Loss of customer trust and brand reputation due to the delivery "
                "of generic, incorrect, or unhelpful automated service responses."
            ),
            "provenance": "use_case",
            "source_risk_cards": [],
        },
    ]
    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft,
        [_run15_risk_response(), gap],
    )

    result = derive_loss_analysis(
        llm_client=client,
        use_case_text="Klarna's assistant serves authenticated fintech customers.",
        risk_cards=make_risk_cards(),
        run_dir=tmp_path,
    )

    assert [loss.loss_id for loss in result.risk_card_losses] == ["L-1"]
    assert [loss.loss_id for loss in result.use_case_losses] == [
        "L-2",
        "L-3",
        "L-4",
    ]
    assert [hazard.hazard_id for hazard in result.hazards] == [
        f"H-{index}" for index in range(1, 11)
    ]
    assert [constraint.constraint_id for constraint in result.security_constraints] == [
        f"SC-{index}" for index in range(1, 17)
    ]
    assert (
        result.hazards[0].description
        == _run15_risk_response()["hazards"][0]["description"]
    )
    assert (
        result.security_constraints[0].description
        == _run15_risk_response()["security_constraints"][0]["rule"]
    )

    entries = read_calls_jsonl(tmp_path)
    stage1a_entries = [entry for entry in entries if entry["stage"] == "stage_1a"]
    assert [entry["success"] for entry in stage1a_entries] == [True, True]
    # The obsolete SC-17 record of the captured invalid response never lands.
    assert '"SC-17"' not in stage1a_entries[1]["response_content"]

    wire_schema = client.calls[0].response_format.model_json_schema()
    assert set(wire_schema["required"]) == {
        "risk_card_losses",
        "use_case_losses",
        "hazards",
        "security_constraints",
        "risk_dispositions",
    }
    for field in (
        "risk_card_losses",
        "use_case_losses",
        "hazards",
        "security_constraints",
    ):
        assert wire_schema["properties"][field]["maxItems"] == 16


def test_run15_invalid_gap_references_fail_typed(tmp_path):
    """The captured run-15 invalid gap response stops after its one correction."""
    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft,
        [_run15_risk_response(), _run15_invalid_gap_response()],
    )

    with pytest.raises(StageError) as exc_info:
        derive_loss_analysis(
            llm_client=client,
            use_case_text="Klarna's assistant serves authenticated fintech customers.",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )

    message = str(exc_info.value)
    assert "targeted repair failed" in message
    assert "draft_references failure class" in message
    entries = read_calls_jsonl(tmp_path)
    stage1a_entries = [entry for entry in entries if entry["stage"] == "stage_1a"]
    assert [entry["success"] for entry in stage1a_entries] == [True, False, False]
    # The captured invalid response is retained as call evidence.
    assert '"constraint_16"' in stage1a_entries[1]["response_content"]


def test_run16_canonicalizes_provenance_on_the_risk_draft(tmp_path):
    """A misplaced risk-card loss is classified by provenance without conflict.

    The captured run-16 shape placed a ``risk_card``-provenance loss in
    ``use_case_losses``.  Canonicalization moves it by typed provenance, so
    the final graph carries it in ``risk_card_losses`` with no false
    conflicting-duplicate diagnostic.
    """
    risk = {
        "risk_dispositions": [
            {
                "risk_ref": "atlas-001",
                "disposition": "cited",
                "loss_ids": ["L-1"],
                "reason": None,
            }
        ],
        "risk_card_losses": [
            {
                "loss_id": "L-1",
                "description": "Run-16 authoritative loss one.",
                "provenance": "risk_card",
                "source_risk_cards": ["atlas-001"],
            }
        ],
        "use_case_losses": [
            {
                "loss_id": "L-2",
                "description": "Run-16 financial-record loss wording.",
                "provenance": "risk_card",
                "source_risk_cards": ["atlas-002"],
            }
        ],
        "hazards": [
            {
                "hazard_id": "H-1",
                "description": "Run-16 authoritative hazard one.",
                "related_losses": ["L-1"],
            },
            {
                "hazard_id": "H-2",
                "description": (
                    "The system provides unreliable or unverified responses for "
                    "critical financial tasks, or experiences service failure due "
                    "to upstream dependency issues."
                ),
                "related_losses": ["L-2"],
            },
        ],
        "security_constraints": [
            {
                "constraint_id": "SC-1",
                "rule": "Run-16 authoritative constraint one.",
                "related_hazards": ["H-1"],
                "applies_when": [],
            },
            {
                "constraint_id": "SC-2",
                "rule": "Run-16 constraint two.",
                "related_hazards": ["H-2"],
                "applies_when": [],
            },
        ],
    }
    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft,
        [risk, _empty_gap_response()],
    )

    result = derive_loss_analysis(
        llm_client=client,
        use_case_text="A neutralized run-16 financial assistant.",
        risk_cards=make_risk_cards(),
        run_dir=tmp_path,
    )

    assert [loss.loss_id for loss in result.risk_card_losses] == ["L-1", "L-2"]
    assert result.use_case_losses == []
    assert result.risk_card_losses[1].description == (
        "Run-16 financial-record loss wording."
    )
    assert [hazard.hazard_id for hazard in result.hazards] == ["H-1", "H-2"]
    assert [constraint.constraint_id for constraint in result.security_constraints] == [
        "SC-1",
        "SC-2",
    ]
    diagnostics = diagnose_loss_analysis_semantics(result)
    assert not any(
        item.code == "hazard_not_system_state" and "H-2" in item.message
        for item in diagnostics
    )
    assert any(
        item.code == "hazard_cause_or_dependency" and "H-2" in item.message
        for item in diagnostics
    )

    entries = read_calls_jsonl(tmp_path)
    stage1a_entries = [entry for entry in entries if entry["stage"] == "stage_1a"]
    assert [entry["success"] for entry in stage1a_entries] == [True, True]
    assert (
        "Run-16 financial-record loss wording."
        in stage1a_entries[0]["response_content"]
    )


def test_run15_authority_merge_scopes_redeclared_ids_without_overwrite(tmp_path):
    """A gap redeclaration gets a new scoped ID and cannot overwrite authority."""
    gap = _run15_correction_response()
    gap["use_case_losses"] = []
    gap["hazards"] = [
        {
            "hazard_id": "H-1",
            "description": "Changed baseline hazard semantics.",
            "related_losses": ["L-1"],
        }
    ]
    gap["security_constraints"] = [
        {
            "constraint_id": "SC-1",
            "rule": "Run-15 redeclared constraint semantics.",
            "related_hazards": ["H-1"],
            "applies_when": [],
        }
    ]
    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft,
        [_run15_risk_response(), gap],
    )

    result = derive_loss_analysis(
        llm_client=client,
        use_case_text="Klarna's assistant serves authenticated fintech customers.",
        risk_cards=make_risk_cards(),
        run_dir=tmp_path,
    )

    assert result.hazards[0].hazard_id == "H-1"
    assert (
        result.hazards[0].description
        == _run15_risk_response()["hazards"][0]["description"]
    )
    assert any(
        hazard.description == "Changed baseline hazard semantics."
        for hazard in result.hazards
    )
    assert result.security_constraints[0].constraint_id == "SC-1"
    assert any(
        constraint.rule == "Run-15 redeclared constraint semantics."
        for constraint in result.security_constraints
    )

    entries = read_calls_jsonl(tmp_path)
    stage1a_entries = [entry for entry in entries if entry["stage"] == "stage_1a"]
    assert [entry["success"] for entry in stage1a_entries] == [True, True]


def test_gap_reference_failure_feedback_preserves_new_loss_guidance(tmp_path):
    """Run-14's H-7/L-7 response gets the actionable declaration guidance."""
    invalid_gap = _run14_invalid_gap_response()
    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft,
        [valid_risk_draft_dict(), invalid_gap],
    )

    with pytest.raises(StageError) as exc_info:
        derive_loss_analysis(
            llm_client=client,
            use_case_text=(
                "Customers complained about generic answers and inability to handle "
                "complicated, nuanced cases; the service began rehiring human agents."
            ),
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )

    message = str(exc_info.value).lower()
    assert "targeted repair failed" in message
    assert "missing loss declarations: l-7" in message
    assert (
        "for a genuinely new source-grounded use-case loss, declare l-7 in "
        "use_case_losses"
    ) in message
    assert "provenance: use_case" in message
    assert "source_risk_cards: []" in message
    assert "otherwise correct only a mistaken reference" in message
    entries = read_calls_jsonl(tmp_path)
    stage1a_entries = [entry for entry in entries if entry["stage"] == "stage_1a"]
    assert [entry["success"] for entry in stage1a_entries] == [True, False, False]
    assert len(client.calls) == 3


def test_a18_gap_valid_disposition_is_not_c1_cleanup(tmp_path):
    """A valid out-of-contract gap disposition fails closed.

    C1 cleanup is limited to malformed gap disposition rows.  A valid-looking
    row is still an extra collection on the current gap wire and cannot
    overwrite the risk-stage accounting or be silently discarded.
    """
    gap = _empty_gap_response()
    gap["risk_dispositions"] = [
        {
            "risk_ref": "atlas-001",
            "disposition": "not_applicable",
            "loss_ids": [],
            "reason": "A fully valid replacement reason authored at the gap stage.",
        }
    ]
    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft,
        [_run15_risk_response(), gap],
    )

    with pytest.raises(StageError, match="valid out-of-contract"):
        derive_loss_analysis(
            llm_client=client,
            use_case_text="Klarna's assistant serves authenticated fintech customers.",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )

    # The risk-stage response survives in call evidence; the valid extra row
    # is terminal and receives no cleanup or repair call.
    entries = read_calls_jsonl(tmp_path)
    stage1a_entries = [entry for entry in entries if entry["stage"] == "stage_1a"]
    assert [entry["success"] for entry in stage1a_entries] == [True, False]
    assert len(client.calls) == 2
    assert "not_applicable" in stage1a_entries[1]["response_content"]
