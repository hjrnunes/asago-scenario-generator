"""Targeted Stage 1a repair: contract tests on the two saved 2026-09-11 failures.

The fixtures are neutralized structural reproductions of the two saved
MiniOcciAI risk-derivation failures preserved under
``build/qualification/supplemental-target-baselines-20260911/derived/``:
collection sizes, card identities, disposition kinds, and the malformed
obligation-entry shape are exact; prose is neutralized per the repository's
captured-response fixture convention.  Attempt 1 failed the wire because one
forbidden obligation entry carried ``realized_by``; attempt 2 parsed but
omitted seven of the 112 risk-disposition entries.  Both are the two failure
classes the owner authorized for targeted repair (2026-09-11); every other
failure class must keep an explicit typed outcome with no additional call.

Synthetic successful repairs demonstrate the merge mechanics only; they are
not semantic-correctness claims about any target.  Every test uses a fake
client and contacts no network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    DispositionRepairResponse,
    ObligationRepairPlan,
    ObligationRepairResponse,
    build_repair_plan,
    run_targeted_repair,
)
from tests.stpa.sp1_helpers import MockLLMClient, read_calls_jsonl

# The exact supplied-card identities of the saved MiniOcciAI risk set, in the
# saved response's order.  The last seven are the cards whose dispositions
# the saved attempt 2 omitted.
_SAVED_CARD_IDS = (
    "mit-ai-risk-subdomain-7.4",
    "credo-risk-036",
    "credo-risk-004",
    "credo-risk-037",
    "credo-risk-041",
    "mit-ai-risk-subdomain-6.6",
    "atlas-impact-on-the-environment",
    "credo-risk-026",
    "credo-risk-010",
    "ai-risk-taxonomy-unauthorized-disclosure---pii-(personal-identifiable-information)",
    "ai-risk-taxonomy-unauthorized-disclosure---health-data",
    "ai-risk-taxonomy-unauthorized-disclosure---financial-records",
    "credo-risk-008",
    "mit-ai-risk-subdomain-2.2",
    "atlas-exposing-personal-information",
    "mit-ai-risk-subdomain-2.1",
    "atlas-personal-information-in-data",
    "ai-risk-taxonomy-unauthorized-inference/synthesis---pii-(personal-identifiable-information)",
    "ai-risk-taxonomy-unauthorized-inference/synthesis---biometric-data-(facial-recognition)",
    "ai-risk-taxonomy-unauthorized-inference/synthesis---financial-records",
    "credo-risk-021",
    "credo-risk-040",
    "credo-risk-007",
    "ai-risk-taxonomy-unauthorized-collection/gathering/stealing---pii-(personal-identifiable-information)",
    "ai-risk-taxonomy-unauthorized-collection/gathering/stealing---financial-records",
    "ai-risk-taxonomy-unauthorized-collection/gathering/stealing---biometric-data-(facial-recognition)",
    "ai-risk-taxonomy-unauthorized-collection/gathering/stealing---health-data",
    "atlas-revealing-confidential-information",
    "ai-risk-taxonomy-unauthorized-disclosure---biometric-data-(facial-recognition)",
    "credo-risk-023",
    "credo-risk-046",
    "ai-risk-taxonomy-unauthorized-processing---pii-(personal-identifiable-information)",
    "ai-risk-taxonomy-unauthorized-processing---financial-records",
    "ai-risk-taxonomy-unauthorized-processing---biometric-data-(facial-recognition)",
    "credo-risk-011",
    "mit-ai-risk-subdomain-1.3",
    "ai-risk-taxonomy-non-consensual-tracking/monitoring/stalking/spyware---pii-(personal-identifiable-information)",
    "ai-risk-taxonomy-non-consensual-tracking/monitoring/stalking/spyware---biometric-data-(facial-recognition)",
    "ai-risk-taxonomy-non-consensual-tracking/monitoring/stalking/spyware---financial-records",
    "atlas-hallucination",
    "ai-risk-taxonomy-unauthorized-processing---health-data",
    "credo-risk-038",
    "mit-ai-risk-subdomain-6.5",
    "ai-risk-taxonomy-unauthorized-generation---pii-(personal-identifiable-information)",
    "ai-risk-taxonomy-unauthorized-generation---health-data",
    "ai-risk-taxonomy-unauthorized-generation---financial-records",
    "atlas-legal-accountability",
    "atlas-data-privacy-rights",
    "credo-risk-017",
    "mit-ai-risk-subdomain-1.1",
    "ai-risk-taxonomy-unauthorized-distribution---pii-(personal-identifiable-information)",
    "ai-risk-taxonomy-unauthorized-distribution---health-data",
    "ai-risk-taxonomy-unauthorized-distribution---financial-records",
    "atlas-data-usage",
    "atlas-spreading-disinformation",
    "credo-risk-034",
    "atlas-attribute-inference-attack",
    "atlas-decision-bias",
    "credo-risk-009",
    "ai-risk-taxonomy-discrimination-in-employment,-benefits,-or-services---geographic-region",
    "ai-risk-taxonomy-discrimination-in-employment,-benefits,-or-services---social-behaviors",
    "credo-risk-025",
    "atlas-output-bias",
    "atlas-plagiarism",
    "atlas-data-acquisition",
    "credo-risk-027",
    "credo-risk-016",
    "credo-risk-013",
    "credo-risk-031",
    "mit-ai-risk-subdomain-4.3",
    "atlas-prompt-injection",
    "ai-risk-taxonomy-plagiarism",
    "atlas-personal-information-in-prompt",
    "mit-ai-risk-subdomain-4.2",
    "atlas-nonconsensual-use",
    "credo-risk-048",
    "mit-ai-risk-subdomain-4.1",
    "credo-risk-014",
    "credo-risk-035",
    "ai-risk-taxonomy-non-consensual-tracking/monitoring/stalking/spyware---health-data",
    "ai-risk-taxonomy-non-consensual-tracking/monitoring/stalking/spyware---communication-records",
    "atlas-data-bias",
    "ai-risk-taxonomy-promoting-academic-dishonesty",
    "credo-risk-039",
    "credo-risk-024",
    "mit-ai-risk-subdomain-5.1",
    "atlas-membership-inference-attack",
    "credo-risk-029",
    "credo-risk-028",
    "credo-risk-005",
    "atlas-data-transfer",
    "atlas-jailbreaking",
    "atlas-evasion-attack",
    "atlas-model-usage-rights",
    "atlas-data-transparency",
    "atlas-over-or-under-reliance",
    "atlas-harmful-output",
    "atlas-harmful-code-generation",
    "atlas-dangerous-use",
    "atlas-non-disclosure",
    "atlas-unexplainable-output",
    "mit-ai-risk-subdomain-7.3",
    "mit-ai-risk-subdomain-7.2",
    "atlas-prompt-priming",
    "atlas-social-hacking-attack",
    "atlas-confidential-data-in-prompt",
    "atlas-confidential-information-in-data",
    "atlas-ip-information-in-prompt",
    "atlas-data-usage-rights",
    "atlas-copyright-infringement",
    "atlas-incomplete-usage-definition",
    "ai-risk-taxonomy-characterization-of-identity---social-behaviors",
)

_SAVED_MISSING_SEVEN = _SAVED_CARD_IDS[-7:]

_USE_CASE = (
    "A neutralized clinic assistant answers patient questions, drafts "
    "education material, and escalates complex cases to clinicians."
)


def _occiai_cards() -> list[RiskCard]:
    """The 112 saved card identities with neutralized text."""
    return [
        RiskCard(
            risk_id=risk_id,
            risk_name=f"Neutralized risk {index}",
            risk_description=f"Neutralized description {index} for analysis.",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
            consequence=f"Neutralized consequence {index}.",
        )
        for index, risk_id in enumerate(_SAVED_CARD_IDS, start=1)
    ]


def _losses(count: int) -> list[dict]:
    """``count`` neutralized risk-card losses citing the card set."""
    return [
        {
            "loss_id": f"L-{number}",
            "description": f"Neutralized stakeholder loss {number}.",
            "provenance": "risk_card",
            "source_risk_cards": [
                _SAVED_CARD_IDS[(number - 1 + offset * 7) % len(_SAVED_CARD_IDS)]
                for offset in range(3)
            ],
        }
        for number in range(1, count + 1)
    ]


def _hazards(count: int) -> list[dict]:
    return [
        {
            "hazard_id": f"H-{number}",
            "description": f"The neutralized system reaches unsafe state {number}.",
            "related_losses": [f"L-{number}"],
        }
        for number in range(1, count + 1)
    ]


def _constraint(
    constraint_id: str,
    *,
    obligations: list[dict],
    applies_when: list[str] | None = None,
) -> dict:
    return {
        "constraint_id": constraint_id,
        "rule": (
            "The system must ensure that no sensitive health data is "
            "included in model outputs."
            if constraint_id == "SC-1"
            else f"The neutralized system must uphold control {constraint_id}."
        ),
        "applies_when": applies_when
        if applies_when is not None
        else ["a neutralized condition holds"],
        "related_hazards": ["H-1"],
        "obligations": obligations,
    }


_VALID_OBLIGATION = {
    "obligation_id": "O1",
    "kind": "forbidden",
    "behavior": "including sensitive health data in a reply",
    "rule_span": "no sensitive health data is included in model outputs",
    "violated_via": "reply",
}

# The exact malformed shape of the saved attempt 1: a forbidden entry that
# carried realized_by instead of violated_via.
_SAVED_MALFORMED_OBLIGATION = {
    "obligation_id": "O1",
    "kind": "forbidden",
    "behavior": "including sensitive health data in a reply",
    "rule_span": "no sensitive health data is included in model outputs",
    "realized_by": "reply",
}


def _dispositions(*, cited_count: int, total: int) -> list[dict]:
    """``total`` rows: the last ones not applicable, the rest cited."""
    rows: list[dict] = []
    not_applicable = total - cited_count
    for index, risk_id in enumerate(_SAVED_CARD_IDS[:total]):
        if index >= cited_count:
            rows.append(
                {
                    "risk_ref": risk_id,
                    "disposition": "not_applicable",
                    "loss_ids": [],
                    "reason": "Neutralized reason: the card does not ground here.",
                }
            )
        else:
            rows.append(
                {
                    "risk_ref": risk_id,
                    "disposition": "cited",
                    "loss_ids": [f"L-{(index % 6) + 1}"],
                    "reason": None,
                }
            )
    assert not_applicable >= 0
    return rows


def _attempt_one_response() -> dict:
    """The saved attempt 1 structure: 6/6/1 collections, 112 dispositions.

    The single constraint is otherwise preserved; its one obligation entry is
    the saved malformed forbidden-with-realized_by shape.
    """
    return {
        "risk_card_losses": _losses(6),
        "use_case_losses": [],
        "hazards": _hazards(6),
        "security_constraints": [
            _constraint(
                "SC-1",
                obligations=[dict(_SAVED_MALFORMED_OBLIGATION)],
                applies_when=[
                    "the assistant is answering a patient",
                    "data is transferred to the record system",
                ],
            )
        ],
        "risk_dispositions": _dispositions(cited_count=105, total=112),
    }


def _attempt_two_response() -> dict:
    """The saved attempt 2 structure: 7/7/7 collections, 105 dispositions.

    Every constraint carries one valid obligation entry, and the last seven
    supplied cards have no disposition row.
    """
    return {
        "risk_card_losses": _losses(7),
        "use_case_losses": [],
        "hazards": _hazards(7),
        "security_constraints": [
            _constraint(
                f"SC-{number}",
                obligations=[dict(_VALID_OBLIGATION)] if number == 1 else [],
            )
            for number in range(1, 8)
        ],
        "risk_dispositions": _dispositions(cited_count=67, total=105),
    }


def _complete_risk_response() -> dict:
    """The attempt 2 structure with all 112 disposition rows present."""
    draft = _attempt_two_response()
    draft["risk_dispositions"] = _dispositions(cited_count=105, total=112)
    return draft


def _empty_gap_response() -> dict:
    """A valid empty gap response: the first call's graph is complete."""
    return {
        "risk_card_losses": [],
        "use_case_losses": [],
        "hazards": [],
        "security_constraints": [],
        "risk_dispositions": [],
    }


def _obligation_repair_response() -> dict:
    """A corrected obligations collection for the selected constraint."""
    return {
        "constraints": [
            {
                "constraint_id": "SC-1",
                "obligations": [
                    {
                        "obligation_id": "O1",
                        "kind": "forbidden",
                        "behavior": "including sensitive health data in a reply",
                        "rule_span": (
                            "no sensitive health data is included in model outputs"
                        ),
                        "violated_via": "reply",
                    }
                ],
            }
        ]
    }


def _disposition_repair_rows(*, count: int = 7) -> list[dict]:
    """Corrected rows for the seven selected cards: four cited, three not applicable."""
    rows = []
    for index, risk_id in enumerate(_SAVED_MISSING_SEVEN[:count]):
        if index < 4:
            rows.append(
                {
                    "risk_ref": risk_id,
                    "disposition": "cited",
                    "loss_ids": [f"L-{index + 1}"],
                    "reason": None,
                }
            )
        else:
            rows.append(
                {
                    "risk_ref": risk_id,
                    "disposition": "not_applicable",
                    "loss_ids": [],
                    "reason": "Neutralized reason: no grounded loss here.",
                }
            )
    return rows


def _stage1a_entries(run_dir: Path) -> list[dict]:
    return [
        entry for entry in read_calls_jsonl(run_dir) if entry["stage"] == "stage_1a"
    ]


class TestSavedObligationFailure:
    """Attempt 1: malformed obligation entries inside a preserved constraint."""

    def test_repairs_within_the_preserved_constraint(self, tmp_path):
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [_attempt_one_response(), _empty_gap_response()],
        )
        client.set_response_for(ObligationRepairResponse, _obligation_repair_response())

        result = derive_loss_analysis(
            llm_client=client,
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards(),
            run_dir=tmp_path,
        )

        # The repaired entry lands; the constraint's own fields are intact.
        constraint = result.security_constraints[0]
        assert [entry.obligation_id for entry in constraint.obligations] == ["O1"]
        assert constraint.obligations[0].violated_via == "reply"
        assert constraint.obligations[0].realized_by is None
        assert constraint.rule == (
            "The system must ensure that no sensitive health data is "
            "included in model outputs."
        )
        assert constraint.applies_when == [
            "the assistant is answering a patient",
            "data is transferred to the record system",
        ]
        assert constraint.related_hazards == ["H-1"]
        # Untouched collections keep their exact sizes and payloads.
        assert len(result.risk_card_losses) == 6
        assert len(result.hazards) == 6
        assert len(result.security_constraints) == 1
        assert len(result.risk_dispositions) == 112
        assert {d.disposition for d in result.risk_dispositions} == {
            "cited",
            "not_applicable",
        }

        entries = _stage1a_entries(tmp_path)
        assert [entry["step"] for entry in entries] == [
            "risk_derivation",
            "risk_derivation_repair",
            "gap_analysis",
        ]
        assert [entry["success"] for entry in entries] == [False, True, True]
        repair_prompt = entries[1]["user_prompt_text"]
        assert "The system must ensure that no sensitive health data" in repair_prompt
        assert "the assistant is answering a patient" in repair_prompt
        assert "The neutralized system reaches unsafe state 1." in repair_prompt
        assert "Neutralized stakeholder loss 1." in repair_prompt
        assert "No obligation entries were preserved" in repair_prompt
        repair_system = entries[1]["system_prompt_text"]
        assert "kind-exclusive" in repair_system
        assert "not a rewrite" in repair_system

    def test_repair_wire_carries_no_constraint_fields(self, tmp_path):
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [_attempt_one_response(), _empty_gap_response()],
        )
        client.set_response_for(ObligationRepairResponse, _obligation_repair_response())
        derive_loss_analysis(
            llm_client=client,
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards(),
            run_dir=tmp_path,
        )
        repair_call = client.calls[1]
        assert repair_call.response_format is ObligationRepairResponse
        schema = repair_call.response_format.model_json_schema()
        constraint_schema = schema["$defs"]["RepairObligationConstraint"]
        assert set(constraint_schema["properties"]) == {"constraint_id", "obligations"}
        assert constraint_schema.get("additionalProperties") is False
        entry_schema = schema["$defs"]["RepairObligation"]
        assert entry_schema.get("additionalProperties") is False

    def test_rejects_an_unexpected_constraint_field_edit(self, tmp_path):
        repair = _obligation_repair_response()
        repair["constraints"][0]["rule"] = "A rewritten rule must not land."
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [_attempt_one_response()])
        client.set_response_for(ObligationRepairResponse, repair)

        with pytest.raises(StageError, match="targeted repair failed"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        # The failed first attempt and the rejected repair, and nothing else.
        assert len(client.calls) == 2
        assert [entry["success"] for entry in _stage1a_entries(tmp_path)] == [
            False,
            False,
        ]

    def test_rejects_an_out_of_scope_constraint(self, tmp_path):
        repair = _obligation_repair_response()
        repair["constraints"].append({"constraint_id": "SC-2", "obligations": []})
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [_attempt_one_response()])
        client.set_response_for(ObligationRepairResponse, repair)

        with pytest.raises(StageError, match="out-of-scope repair identity"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        assert len(client.calls) == 2

    def test_rejects_an_altered_preserved_entry(self, tmp_path):
        fixture = _attempt_one_response()
        # One valid entry survives salvage and must be preserved verbatim;
        # the malformed entry is the repair target.
        fixture["security_constraints"][0]["obligations"] = [
            dict(_VALID_OBLIGATION),
            dict(_SAVED_MALFORMED_OBLIGATION) | {"obligation_id": "O2"},
        ]
        repair = _obligation_repair_response()
        repair["constraints"][0]["obligations"] = [
            dict(_VALID_OBLIGATION)
            | {"behavior": "an edited behavior the model improved"},
            {
                "obligation_id": "O2",
                "kind": "forbidden",
                "behavior": "including sensitive health data in a reply",
                "rule_span": ("no sensitive health data is included in model outputs"),
                "violated_via": "reply",
            },
        ]
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [fixture])
        client.set_response_for(ObligationRepairResponse, repair)

        with pytest.raises(
            StageError, match="altered or dropped the preserved obligation entry"
        ):
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        assert len(client.calls) == 2


class TestSavedDispositionFailure:
    """Attempt 2: seven missing risk-disposition entries."""

    def test_repairs_with_identity_scoped_rows(self, tmp_path):
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [_attempt_two_response(), _empty_gap_response()],
        )
        client.set_response_for(
            DispositionRepairResponse,
            {"risk_dispositions": _disposition_repair_rows()},
        )

        result = derive_loss_analysis(
            llm_client=client,
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards(),
            run_dir=tmp_path,
        )

        assert len(result.risk_dispositions) == 112
        by_ref = {row.risk_ref: row for row in result.risk_dispositions}
        # The seven selected cards carry the repaired rows.
        for index, risk_id in enumerate(_SAVED_MISSING_SEVEN):
            row = by_ref[risk_id]
            if index < 4:
                assert row.disposition == "cited"
                assert row.loss_ids == [f"L-{index + 1}"]
            else:
                assert row.disposition == "not_applicable"
                assert row.reason == "Neutralized reason: no grounded loss here."
        # Every unselected row is preserved with its exact prior payload.
        prior_rows = {
            row["risk_ref"]: row for row in _attempt_two_response()["risk_dispositions"]
        }
        for risk_ref, prior in prior_rows.items():
            assert by_ref[risk_ref].model_dump(mode="json", exclude_none=True) == {
                key: value for key, value in prior.items() if value is not None
            }
        # Untouched collections keep their sizes and obligations.
        assert len(result.risk_card_losses) == 7
        assert len(result.hazards) == 7
        assert len(result.security_constraints) == 7
        assert result.security_constraints[0].obligations[0].violated_via == "reply"

        entries = _stage1a_entries(tmp_path)
        assert [entry["step"] for entry in entries] == [
            "risk_derivation",
            "risk_derivation_repair",
            "gap_analysis",
        ]
        repair_prompt = entries[1]["user_prompt_text"]
        for risk_id in _SAVED_MISSING_SEVEN:
            assert risk_id in repair_prompt
        assert "Neutralized description" in repair_prompt
        assert "Neutralized stakeholder loss 7." in repair_prompt
        assert (
            "no risk_dispositions entry was returned for this supplied card"
            in repair_prompt
        )

    def test_repair_wire_is_closed_to_disposition_fields(self, tmp_path):
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [_attempt_two_response(), _empty_gap_response()],
        )
        client.set_response_for(
            DispositionRepairResponse,
            {"risk_dispositions": _disposition_repair_rows()},
        )
        derive_loss_analysis(
            llm_client=client,
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards(),
            run_dir=tmp_path,
        )
        repair_call = client.calls[1]
        assert repair_call.response_format is DispositionRepairResponse
        schema = repair_call.response_format.model_json_schema()
        row_schema = schema["$defs"]["RepairRiskDisposition"]
        assert set(row_schema["properties"]) == {
            "risk_ref",
            "disposition",
            "loss_ids",
            "reason",
        }
        assert row_schema.get("additionalProperties") is False

    def test_rejects_duplicate_identities(self, tmp_path):
        rows = _disposition_repair_rows()
        rows.append(dict(rows[0]))
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [_attempt_two_response()])
        client.set_response_for(DispositionRepairResponse, {"risk_dispositions": rows})

        with pytest.raises(StageError, match="duplicate repair row"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        assert len(client.calls) == 2

    def test_rejects_unknown_identities(self, tmp_path):
        rows = _disposition_repair_rows()
        rows.append(
            {
                "risk_ref": "atlas-not-in-the-supplied-set",
                "disposition": "not_applicable",
                "loss_ids": [],
                "reason": "Neutralized reason.",
            }
        )
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [_attempt_two_response()])
        client.set_response_for(DispositionRepairResponse, {"risk_dispositions": rows})

        with pytest.raises(StageError, match="unknown or out-of-scope repair identity"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        assert len(client.calls) == 2

    def test_rejects_incomplete_repairs(self, tmp_path):
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [_attempt_two_response()])
        client.set_response_for(
            DispositionRepairResponse,
            {"risk_dispositions": _disposition_repair_rows(count=6)},
        )

        with pytest.raises(StageError, match="incomplete repair"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        assert len(client.calls) == 2

    def test_rejects_rows_citing_undeclared_losses(self, tmp_path):
        rows = _disposition_repair_rows()
        rows[0]["loss_ids"] = ["L-99"]
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [_attempt_two_response()])
        client.set_response_for(DispositionRepairResponse, {"risk_dispositions": rows})

        with pytest.raises(StageError, match="never declared: L-99"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        assert len(client.calls) == 2


class TestUnsupportedFailureClasses:
    """Every failure class outside the two approved scopes fails typed."""

    def test_reference_failures_make_no_repair_call(self, tmp_path):
        draft = _attempt_two_response()
        # A constraint referencing an undeclared hazard: reference class.
        draft["security_constraints"][6]["related_hazards"] = ["H-99"]
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [draft])

        with pytest.raises(StageError) as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        message = str(exc_info.value)
        assert "targeted repair unsupported" in message
        assert "draft_references failure class" in message
        assert "no repair call was made" in message
        # The actionable first-attempt feedback is retained in the record.
        assert "H-99" in message
        assert len(client.calls) == 1
        entries = _stage1a_entries(tmp_path)
        assert [entry["step"] for entry in entries] == ["risk_derivation"]

    def test_wire_failures_outside_the_repair_scope_fail_typed(self, tmp_path):
        draft = _attempt_two_response()
        # A hazard row missing its related_losses: outside both repair scopes.
        draft["hazards"][6] = {
            "hazard_id": "H-7",
            "description": "The neutralized system reaches unsafe state 7.",
        }
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [draft])

        with pytest.raises(StageError) as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        message = str(exc_info.value)
        assert "targeted repair unsupported" in message
        assert "wire violation outside the approved repair scope" in message
        assert len(client.calls) == 1

    def test_mixed_wire_failure_classes_are_unsupported(self, tmp_path):
        draft = _attempt_one_response()
        # The malformed obligation plus one malformed disposition row.
        draft["risk_dispositions"][0] = {
            "risk_ref": _SAVED_CARD_IDS[0],
            "disposition": "not_applicable",
            "loss_ids": [],
        }
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [draft])

        with pytest.raises(StageError) as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        assert "mixes obligation-entry and risk-disposition wire failures" in str(
            exc_info.value
        )
        assert len(client.calls) == 1

    def test_semantic_failures_make_no_repair_call(self, tmp_path):
        draft = _attempt_two_response()
        # A component-failure hazard: the semantic validator's error class.
        draft["hazards"][6]["description"] = (
            "The model fails and the service becomes unavailable."
        )
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [draft])

        with pytest.raises(StageError) as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        assert "draft_semantics failure class" in str(exc_info.value)
        assert len(client.calls) == 1


class TestDeterministicCleanup:
    """Failures that reduce to deterministic row removal need no model call."""

    def test_unknown_disposition_references_are_removed_without_a_repair(
        self, tmp_path
    ):
        draft = _complete_risk_response()
        # Every supplied card keeps a valid row; the only accounting problem
        # is one extra row referencing an unsupplied card.
        draft["risk_dispositions"].append(
            {
                "risk_ref": "atlas-typo-not-supplied",
                "disposition": "not_applicable",
                "loss_ids": [],
                "reason": "Neutralized typo row.",
            }
        )
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [draft, _empty_gap_response()],
        )
        warnings: list[str] = []

        result = derive_loss_analysis(
            llm_client=client,
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards(),
            run_dir=tmp_path,
            normalization_warnings=warnings,
        )

        assert len(result.risk_dispositions) == 112
        assert all(
            row.risk_ref != "atlas-typo-not-supplied"
            for row in result.risk_dispositions
        )
        assert any(
            "atlas-typo-not-supplied" in warning and "unsupplied" in warning
            for warning in warnings
        )
        # No repair call: the first attempt and the gap review, nothing else.
        assert len(client.calls) == 2
        entries = _stage1a_entries(tmp_path)
        assert [entry["step"] for entry in entries] == [
            "risk_derivation",
            "gap_analysis",
        ]
        assert not any(entry["step"].endswith("_repair") for entry in entries)

    def test_gap_disposition_rows_are_out_of_contract(self, tmp_path):
        risk = _complete_risk_response()
        gap = {
            "risk_card_losses": [],
            "use_case_losses": [],
            "hazards": [],
            "security_constraints": [],
            "risk_dispositions": [
                {"risk_ref": "L-1", "disposition": "not_applicable"},
            ],
        }
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [risk, gap])
        warnings: list[str] = []

        result = derive_loss_analysis(
            llm_client=client,
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards(),
            run_dir=tmp_path,
            normalization_warnings=warnings,
        )

        # Call 1's accounting survives; the gap's out-of-contract rows are
        # dropped deterministically and no repair call is made.
        assert len(result.risk_dispositions) == 112
        assert any("dropped malformed risk_dispositions" in w for w in warnings)
        gap_entries = [
            entry
            for entry in _stage1a_entries(tmp_path)
            if entry["step"] == "gap_analysis"
        ]
        assert [entry["success"] for entry in gap_entries] == [False]


class TestGapObligationRepair:
    """The gap call's obligation entries join the same repair scope."""

    def test_repairs_through_the_authority_merge(self, tmp_path):
        risk = _complete_risk_response()
        gap = {
            "risk_card_losses": [],
            "use_case_losses": [
                {
                    "loss_id": "L-8",
                    "description": "Neutralized use-case loss.",
                    "provenance": "use_case",
                    "source_risk_cards": [],
                }
            ],
            "hazards": [
                {
                    "hazard_id": "H-8",
                    "description": "The neutralized system reaches unsafe state 8.",
                    "related_losses": ["L-8"],
                }
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-8",
                    "rule": "The neutralized system must uphold control SC-8.",
                    "applies_when": ["a neutralized condition holds"],
                    "related_hazards": ["H-8"],
                    "obligations": [dict(_SAVED_MALFORMED_OBLIGATION)],
                }
            ],
        }
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [risk, gap])
        client.set_response_for(
            ObligationRepairResponse,
            {
                "constraints": [
                    {
                        "constraint_id": "SC-8",
                        "obligations": [
                            {
                                "obligation_id": "O1",
                                "kind": "required",
                                "behavior": "upholding control SC-8",
                                "rule_span": "must uphold control SC-8",
                                "realized_by": "reply",
                            }
                        ],
                    }
                ]
            },
        )

        result = derive_loss_analysis(
            llm_client=client,
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards(),
            run_dir=tmp_path,
        )

        # The risk draft's records survive the authority merge untouched.
        assert len(result.risk_card_losses) == 7
        assert len(result.security_constraints) == 8
        repaired = result.security_constraints[7]
        assert repaired.constraint_id == "SC-8"
        assert repaired.obligations[0].realized_by == "reply"
        assert repaired.obligations[0].kind == "required"
        assert result.risk_dispositions and len(result.risk_dispositions) == 112

        entries = _stage1a_entries(tmp_path)
        assert [entry["step"] for entry in entries] == [
            "risk_derivation",
            "gap_analysis",
            "gap_analysis_repair",
        ]
        assert [entry["success"] for entry in entries] == [True, False, True]


class _ConfiguredClient(MockLLMClient):
    """A fake client carrying the audited gemma4-oc budget numbers."""

    def __init__(self) -> None:
        super().__init__()
        self.context_window = 32768
        self.max_completion_tokens = 8192


class TestRepairPreflight:
    """The repair prompt is preflighted and fails closed before dispatch."""

    def test_oversized_repair_prompt_is_blocked_without_dispatch(self, tmp_path):
        from asago_scenario_generator.stpa.infra.templates import TemplateLoader
        from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
        from asago_scenario_generator.stpa.system_model.loss_analysis import (
            STAGE1A_MAX_COMPLETION_TOKENS,
            normalize_disposition_citations,
        )
        from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
            ObligationRepairPlan,
        )

        draft = LossAnalysisDraft.model_validate(_attempt_two_response())
        plan = ObligationRepairPlan(
            prior=draft,
            selected=("SC-1",),
            reasons=(
                (
                    "SC-1",
                    "the constraint is otherwise preserved; its malformed "
                    "obligation entries were dropped and must be returned "
                    "corrected",
                ),
            ),
        )
        huge_use_case = "Neutralized use-case sentence. " * 4200
        client = _ConfiguredClient()

        with pytest.raises(StageError, match="targeted repair failed"):
            run_targeted_repair(
                plan,
                llm_client=client,
                loader=TemplateLoader(PROMPTS_DIR),
                run_dir=tmp_path,
                step="risk_derivation",
                temperature=0.4,
                use_case_text=huge_use_case,
                risk_cards=_occiai_cards(),
                run_validators=lambda draft: None,
                normalizer=normalize_disposition_citations,
                max_completion_tokens=STAGE1A_MAX_COMPLETION_TOKENS,
            )

        # The preflight blocked the repair before any provider dispatch.
        assert client.calls == []
        entries = _stage1a_entries(tmp_path)
        assert [entry["step"] for entry in entries] == ["risk_derivation_repair"]
        assert entries[0]["terminal_error_codes"] == ["prompt_budget_exceeded"]
        preflight = entries[0]["prompt_preflight"]
        assert preflight["usable_input_tokens"] == 21299
        assert preflight["input_tokens"] > 21299

    def test_fitting_repair_prompt_is_audited_and_dispatched(self, tmp_path):
        client = _ConfiguredClient()
        client.set_response_for(
            LossAnalysisDraft,
            [_attempt_two_response(), _empty_gap_response()],
        )
        client.set_response_for(
            DispositionRepairResponse,
            {"risk_dispositions": _disposition_repair_rows()},
        )

        result = derive_loss_analysis(
            llm_client=client,
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards(),
            run_dir=tmp_path,
        )

        assert len(result.risk_dispositions) == 112
        entries = _stage1a_entries(tmp_path)
        assert [entry["step"] for entry in entries] == [
            "risk_derivation",
            "risk_derivation_repair",
            "gap_analysis",
        ]
        repair_preflight = entries[1]["prompt_preflight"]
        # The targeted repair fits the same budget the old whole-object
        # retry exceeded (22,490 estimated on the saved attempt 2).
        assert (
            repair_preflight["input_tokens"] <= repair_preflight["usable_input_tokens"]
        )
        assert entries[1]["success"] is True


class TestRepairPlanSelection:
    """Deterministic selection mirrors the accounting validator's problems."""

    def test_selection_names_missing_duplicates_and_undeclared_citations(
        self, tmp_path
    ):
        from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
            select_disposition_repairs,
        )

        draft = LossAnalysisDraft.model_validate(_attempt_two_response())
        # Duplicate one row and make another cite an undeclared loss.
        duplicated = draft.risk_dispositions[0].model_copy(deep=True)
        draft.risk_dispositions.append(duplicated)
        draft.risk_dispositions[1] = draft.risk_dispositions[1].model_copy(
            update={"loss_ids": ["L-99"]}
        )

        selected, reasons, removed_unknown = select_disposition_repairs(
            draft, _occiai_cards()
        )
        assert set(selected) == {
            *_SAVED_MISSING_SEVEN,
            duplicated.risk_ref,
            draft.risk_dispositions[1].risk_ref,
        }
        assert removed_unknown == ()
        reason_map = dict(reasons)
        assert "duplicate risk_dispositions entries" in reason_map[duplicated.risk_ref]
        assert "never declared: L-99" in reason_map[draft.risk_dispositions[1].risk_ref]

    def test_build_repair_plan_routes_the_saved_wire_failure_to_obligations(
        self, tmp_path
    ):
        from asago_scenario_generator.stpa.infra.llm import LLMResult
        from asago_scenario_generator.stpa.system_model.loss_analysis import (
            _ProviderSecurityConstraint,
            _Stage1aRiskProviderDraft,
        )

        fixture = json.dumps(_attempt_one_response())
        result = LLMResult(
            content=fixture,
            prompt_tokens=100,
            completion_tokens=50,
            duration_ms=1,
            system_prompt="s",
            user_prompt="u",
        )
        outcome = build_repair_plan(
            step="risk_derivation",
            response_format=_Stage1aRiskProviderDraft,
            first_result=result,
            first_parse_failed=True,
            failure_class="wire_schema",
            risk_cards=_occiai_cards(),
            require_risk_accounting=True,
            constraint_wire_model=_ProviderSecurityConstraint,
        )
        assert isinstance(outcome, ObligationRepairPlan)
        assert outcome.selected == ("SC-1",)
        assert len(outcome.prior.risk_dispositions) == 112
        assert outcome.prior.security_constraints[0].obligations == []
