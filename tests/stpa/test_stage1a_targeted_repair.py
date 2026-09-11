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

These tests verify the implemented corrected contract (specification
revision 2, owner implementation approval 2026-09-11): the salvage retains
malformed obligation entries verbatim, the repair relocates a known channel
value unchanged and never re-chooses a channel meaning, container-level wire
damage is a typed terminal failure before any salvage, and every
transformation is recorded in the cross-stage ``loss-analysis-repair.yaml``
artifact.  The build-directory verification harness
(``verification-hold-20260911``) additionally drives the exact saved
MiniOcciAI and Airbnb evidence objects through the same production paths.

Synthetic successful repairs demonstrate the merge mechanics only; they are
not semantic-correctness claims about any target.  Every test uses a fake
client and contacts no network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

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
    PermittedChange,
    RepairRecord,
    SelectedObligation,
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

_SC1_RULE = (
    "The system must ensure that no sensitive health data is "
    "included in model outputs."
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
    rule: str | None = None,
) -> dict:
    return {
        "constraint_id": constraint_id,
        "rule": rule
        if rule is not None
        else (
            _SC1_RULE
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


def _relocated_obligation_entry() -> dict:
    """The saved malformed entry with its channel value relocated unchanged."""
    return dict(_SAVED_MALFORMED_OBLIGATION) | {
        "violated_via": "reply",
        "realized_by": None,
    }


def _obligation_repair_response(*, obligations: list[dict] | None = None) -> dict:
    """A corrected obligations collection for the selected constraint."""
    return {
        "constraints": [
            {
                "constraint_id": "SC-1",
                "obligations": (
                    [_relocated_obligation_entry()]
                    if obligations is None
                    else list(obligations)
                ),
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


def _gap_constraint_defect_response() -> dict:
    """A gap response whose new constraint carries a malformed obligation entry."""
    return {
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
                "obligations": [
                    {
                        "obligation_id": "O1",
                        "kind": "forbidden",
                        "behavior": "including sensitive health data in a reply",
                        "rule_span": "must uphold control SC-8",
                        "realized_by": "reply",
                    }
                ],
            }
        ],
    }


def _gap_obligation_repair_response(*, entry: dict | None = None) -> dict:
    """A corrected obligations collection for the gap constraint."""
    return {
        "constraints": [
            {
                "constraint_id": "SC-8",
                "obligations": [
                    entry
                    if entry is not None
                    else {
                        "obligation_id": "O1",
                        "kind": "forbidden",
                        "behavior": "including sensitive health data in a reply",
                        "rule_span": "must uphold control SC-8",
                        "violated_via": "reply",
                    }
                ],
            }
        ]
    }


def _gap_malformed_disposition_response() -> dict:
    """A gap response whose only defect is one malformed disposition row."""
    return {
        "risk_card_losses": [],
        "use_case_losses": [],
        "hazards": [],
        "security_constraints": [],
        "risk_dispositions": [
            {"risk_ref": "credo-risk-004", "disposition": "not_applicable"},
        ],
    }


def _stage1a_entries(run_dir: Path) -> list[dict]:
    return [
        entry for entry in read_calls_jsonl(run_dir) if entry["stage"] == "stage_1a"
    ]


def _repair_record(run_dir: Path) -> dict:
    """Load the run-level repair record artifact."""
    return yaml.safe_load(
        (run_dir / "loss-analysis-repair.yaml").read_text(encoding="utf-8")
    )


def _record_tuples(record: dict) -> list[tuple]:
    """The record's entries as (stage, attempt, kind, identity, outcome) tuples."""
    return [
        (
            entry["stage"],
            entry["attempt"],
            entry["kind"],
            entry["identity"],
            entry["outcome"],
        )
        for entry in record["records"]
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
        assert constraint.obligations[0].behavior == (
            "including sensitive health data in a reply"
        )
        assert constraint.rule == _SC1_RULE
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
        assert _SC1_RULE in repair_prompt
        assert "the assistant is answering a patient" in repair_prompt
        assert "The neutralized system reaches unsafe state 1." in repair_prompt
        assert "Neutralized stakeholder loss 1." in repair_prompt
        # R1.6: the prompt carries the original entry verbatim, its exact
        # validation errors, and the permitted change stated as relocation.
        assert "Original entry, verbatim:" in repair_prompt
        assert "realized_by" in repair_prompt
        assert (
            "move `realized_by: reply` to `violated_via` unchanged"
            in repair_prompt
        )
        assert "forbidden but carries realized_by" in repair_prompt
        # The deleted permissions stay deleted.
        assert "from scratch" not in repair_prompt
        assert "Omit entries rather than guessing" not in repair_prompt
        repair_system = entries[1]["system_prompt_text"]
        assert "kind-exclusive" in repair_system
        assert "not a rewrite" in repair_system
        # R1.6: the system prompt anchors channel preservation.  The
        # sentence wraps across template lines, so assert both halves.
        assert "Never substitute" in repair_system
        assert "another channel and never drop a known channel" in repair_system

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

    def test_a5_repair_tampers_a_preserved_entry_is_rejected(self, tmp_path):
        """A5 (existing behavior, kept): an altered preserved entry rejects."""
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


class TestObligationRepairRejections:
    """A1-A8: identity and channel rejections with typed reasons, no second call."""

    @staticmethod
    def _rejected_run(tmp_path, repair_payload) -> tuple[StageError, MockLLMClient]:
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [_attempt_one_response()])
        client.set_response_for(ObligationRepairResponse, repair_payload)
        try:
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        except StageError as exc:
            return exc, client
        raise AssertionError("the repair must be rejected")

    def test_a1_repair_deleting_the_selected_entry_is_rejected(self, tmp_path):
        exc, client = self._rejected_run(
            tmp_path,
            {"constraints": [{"constraint_id": "SC-1", "obligations": []}]},
        )
        assert "repair_delete_forbidden" in str(exc)
        assert "SC-1/O1" in str(exc)
        assert len(client.calls) == 2

    def test_a2_repair_replacing_the_entry_is_rejected(self, tmp_path):
        replacement = {
            "obligation_id": "O99",
            "kind": "required",
            "behavior": "an unrelated rewritten behavior",
            "rule_span": "no sensitive health data is included in model outputs",
            "realized_by": "reply",
        }
        exc, client = self._rejected_run(
            tmp_path,
            _obligation_repair_response(obligations=[replacement]),
        )
        assert "repair_identity_unknown" in str(exc)
        assert "O99" in str(exc)
        assert len(client.calls) == 2

    def test_a3_repair_adding_an_entry_is_rejected(self, tmp_path):
        addition = {
            "obligation_id": "O99",
            "kind": "forbidden",
            "behavior": "an added behavior",
            "rule_span": "no sensitive health data is included in model outputs",
            "violated_via": "reply",
        }
        exc, client = self._rejected_run(
            tmp_path,
            _obligation_repair_response(
                obligations=[_relocated_obligation_entry(), addition]
            ),
        )
        assert "repair_identity_unknown" in str(exc)
        assert len(client.calls) == 2

    def test_a4_repair_rewriting_preserved_fields_is_rejected(self, tmp_path):
        rewritten = dict(_relocated_obligation_entry()) | {
            "behavior": "an improved behavior the model authored",
            "rule_span": "no health data leaks into model outputs",
        }
        exc, client = self._rejected_run(
            tmp_path,
            _obligation_repair_response(obligations=[rewritten]),
        )
        assert "repair_unrelated_field_edit" in str(exc)
        assert len(client.calls) == 2

    def test_a7_repair_replacing_the_channel_is_rejected(self, tmp_path):
        for replaced in ("state", "tool_call"):
            replaced_entry = dict(_relocated_obligation_entry()) | {
                "violated_via": replaced,
                "realized_by": None,
            }
            exc, client = self._rejected_run(
                tmp_path,
                _obligation_repair_response(obligations=[replaced_entry]),
            )
            assert "repair_channel_replaced" in str(exc)
            assert "'reply'" in str(exc)
            assert f"'{replaced}'" in str(exc)
            assert len(client.calls) == 2

    def test_a8_repair_omitting_the_known_channel_is_rejected(self, tmp_path):
        omitted = {
            "obligation_id": "O1",
            "kind": "forbidden",
            "behavior": "including sensitive health data in a reply",
            "rule_span": "no sensitive health data is included in model outputs",
        }
        exc, client = self._rejected_run(
            tmp_path,
            _obligation_repair_response(obligations=[omitted]),
        )
        assert "repair_channel_omitted" in str(exc)
        assert "dropped the known channel 'reply'" in str(exc)
        assert len(client.calls) == 2

    def test_a9_conflicting_channel_values_never_reach_a_repair_call(self, tmp_path):
        fixture = _attempt_one_response()
        fixture["security_constraints"][0]["obligations"] = [
            dict(_SAVED_MALFORMED_OBLIGATION) | {"violated_via": "state"}
        ]
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [fixture])

        with pytest.raises(StageError) as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        message = str(exc_info.value)
        assert "obligation repair scope is not deterministically definable" in message
        assert "conflicting channel values" in message
        assert len(client.calls) == 1

    def test_a10_unrepresentable_channel_relocation_never_reaches_a_call(self, tmp_path):
        fixture = _attempt_one_response()
        fixture["security_constraints"][0]["obligations"] = [
            {
                "obligation_id": "O1",
                "kind": "required",
                "behavior": "including sensitive health data in a reply",
                "rule_span": "no sensitive health data is included in model outputs",
                "violated_via": "state",
            }
        ]
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [fixture])

        with pytest.raises(StageError) as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        message = str(exc_info.value)
        assert "obligation repair scope is not deterministically definable" in message
        assert "unrepresentable channel relocation" in message
        assert len(client.calls) == 1

    def test_a11_source_outcome_without_proxy_never_reaches_a_call(self, tmp_path):
        fixture = _attempt_one_response()
        fixture["security_constraints"][0]["obligations"] = [
            {
                "obligation_id": "O1",
                "kind": "forbidden",
                "behavior": "including sensitive health data in a reply",
                "rule_span": "no sensitive health data is included in model outputs",
                "violated_via": "reply",
                "source_outcome": "The reply exposes PII.",
            }
        ]
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [fixture])

        with pytest.raises(StageError) as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        message = str(exc_info.value)
        assert "obligation repair scope is not deterministically definable" in message
        assert "source_outcome is present without observation_role: proxy" in message
        assert len(client.calls) == 1

    def test_a12_duplicate_obligation_ids_never_reach_a_repair_call(self, tmp_path):
        fixture = _attempt_one_response()
        fixture["security_constraints"][0]["obligations"] = [
            dict(_SAVED_MALFORMED_OBLIGATION),
            dict(_SAVED_MALFORMED_OBLIGATION),
        ]
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [fixture])

        with pytest.raises(StageError) as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        message = str(exc_info.value)
        assert "obligation repair scope is not deterministically definable" in message
        assert "duplicate obligation ids" in message
        assert len(client.calls) == 1


class TestChannelMeaningPreservation:
    """Positive relocation and removal cases from the R1.2 table."""

    @staticmethod
    def _repair_run(tmp_path, original_entry, corrected_entry):
        fixture = _attempt_one_response()
        fixture["security_constraints"][0]["obligations"] = [original_entry]
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [fixture, _empty_gap_response()],
        )
        client.set_response_for(
            ObligationRepairResponse,
            {
                "constraints": [
                    {"constraint_id": "SC-1", "obligations": [corrected_entry]}
                ]
            },
        )
        return derive_loss_analysis(
            llm_client=client,
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards(),
            run_dir=tmp_path,
        )

    def test_a6_the_saved_defect_repairs_by_relocation_only(self, tmp_path):
        result = self._repair_run(
            tmp_path,
            dict(_SAVED_MALFORMED_OBLIGATION),
            _relocated_obligation_entry(),
        )
        entry = result.security_constraints[0].obligations[0]
        assert entry.violated_via == "reply"
        assert entry.realized_by is None
        assert entry.behavior == "including sensitive health data in a reply"
        assert entry.rule_span == (
            "no sensitive health data is included in model outputs"
        )

    def test_row2_offending_field_with_same_value_destination_is_removed(self, tmp_path):
        original = dict(_SAVED_MALFORMED_OBLIGATION) | {"violated_via": "reply"}
        corrected = {
            "obligation_id": "O1",
            "kind": "forbidden",
            "behavior": "including sensitive health data in a reply",
            "rule_span": "no sensitive health data is included in model outputs",
            "violated_via": "reply",
        }
        result = self._repair_run(tmp_path, original, corrected)
        entry = result.security_constraints[0].obligations[0]
        assert entry.violated_via == "reply"
        assert entry.realized_by is None

    def test_row4_required_entry_relocates_a_representable_channel(self, tmp_path):
        original = {
            "obligation_id": "O1",
            "kind": "required",
            "behavior": "including sensitive health data in a reply",
            "rule_span": "no sensitive health data is included in model outputs",
            "violated_via": "reply",
        }
        corrected = {
            "obligation_id": "O1",
            "kind": "required",
            "behavior": "including sensitive health data in a reply",
            "rule_span": "no sensitive health data is included in model outputs",
            "realized_by": "reply",
        }
        result = self._repair_run(tmp_path, original, corrected)
        entry = result.security_constraints[0].obligations[0]
        assert entry.realized_by == "reply"
        assert entry.violated_via is None

    def test_row7_required_entry_foreign_fields_are_removed(self, tmp_path):
        original = {
            "obligation_id": "O1",
            "kind": "required",
            "behavior": "including sensitive health data in a reply",
            "rule_span": "no sensitive health data is included in model outputs",
            "observation_role": "source",
            "source_outcome": "The reply exposes PII.",
        }
        corrected = {
            "obligation_id": "O1",
            "kind": "required",
            "behavior": "including sensitive health data in a reply",
            "rule_span": "no sensitive health data is included in model outputs",
            "realized_by": "unknown",
        }
        result = self._repair_run(tmp_path, original, corrected)
        entry = result.security_constraints[0].obligations[0]
        assert entry.observation_role is None
        assert entry.source_outcome is None
        assert entry.realized_by == "unknown"

    def test_row8_forbidden_entry_completion_is_removed(self, tmp_path):
        original = dict(_SAVED_MALFORMED_OBLIGATION) | {
            "violated_via": "reply",
            "completion": "the reply completes the disclosure",
        }
        corrected = {
            "obligation_id": "O1",
            "kind": "forbidden",
            "behavior": "including sensitive health data in a reply",
            "rule_span": "no sensitive health data is included in model outputs",
            "violated_via": "reply",
        }
        result = self._repair_run(tmp_path, original, corrected)
        entry = result.security_constraints[0].obligations[0]
        assert entry.completion is None
        assert entry.violated_via == "reply"

    def test_row9_proxy_entry_sets_only_source_outcome(self, tmp_path):
        original = {
            "obligation_id": "O1",
            "kind": "forbidden",
            "behavior": "including sensitive health data in a reply",
            "rule_span": "no sensitive health data is included in model outputs",
            "violated_via": "reply",
            "observation_role": "proxy",
        }
        corrected = dict(original) | {
            "source_outcome": "The reply containing the PII is the proxy."
        }
        result = self._repair_run(tmp_path, original, corrected)
        entry = result.security_constraints[0].obligations[0]
        assert entry.source_outcome == "The reply containing the PII is the proxy."
        assert entry.observation_role == "proxy"
        assert entry.violated_via == "reply"

    def test_row11_rule_span_defect_repairs_by_verbatim_quote(self, tmp_path):
        original = dict(_VALID_OBLIGATION) | {
            "rule_span": "protect every reply from health data"
        }
        corrected = dict(_VALID_OBLIGATION)
        result = self._repair_run(tmp_path, original, corrected)
        entry = result.security_constraints[0].obligations[0]
        assert entry.rule_span == "no sensitive health data is included in model outputs"
        assert entry.behavior == "including sensitive health data in a reply"


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


class TestContainerErrorClassification:
    """A14-A17: container-level wire damage is a typed terminal failure.

    Container-presence, container-type, and container-bounds errors never
    reach the salvage, the cleanup, or a repair call, alone or mixed with
    record-level errors.
    """

    def test_a14_gap_string_use_case_losses_with_bad_row_is_terminal(self, tmp_path):
        gap = _gap_malformed_disposition_response() | {
            "use_case_losses": "not a list"
        }
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [_complete_risk_response(), gap],
        )

        with pytest.raises(StageError) as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        message = str(exc_info.value)
        assert "non-record wire errors are outside the approved repair scope" in message
        assert "container-type" in message
        assert "use_case_losses" in message
        # Zero repair or cleanup calls: the risk call and the failed gap call.
        assert len(client.calls) == 2
        assert not any(
            entry["step"].endswith("_repair")
            for entry in _stage1a_entries(tmp_path)
        )

    def test_a15_gap_missing_security_constraints_with_bad_row_is_terminal(
        self, tmp_path
    ):
        gap = _gap_malformed_disposition_response()
        del gap["security_constraints"]
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [_complete_risk_response(), gap],
        )

        with pytest.raises(StageError) as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        message = str(exc_info.value)
        assert "container-presence" in message
        assert "security_constraints" in message
        assert len(client.calls) == 2

    def test_a16_risk_missing_security_constraints_spends_no_repair_call(
        self, tmp_path
    ):
        risk = _complete_risk_response()
        del risk["security_constraints"]
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [risk])

        with pytest.raises(StageError) as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        message = str(exc_info.value)
        assert "container-presence" in message
        assert "security_constraints" in message
        assert len(client.calls) == 1

    def test_a17_container_bounds_violation_is_terminal(self, tmp_path):
        risk = _complete_risk_response()
        risk["hazards"] = _hazards(17)
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [risk])

        with pytest.raises(StageError) as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        message = str(exc_info.value)
        assert "container-bounds" in message
        assert len(client.calls) == 1

    def test_risk_missing_dispositions_collection_is_terminal(self, tmp_path):
        risk = _complete_risk_response()
        del risk["risk_dispositions"]
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [risk])

        with pytest.raises(StageError) as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        message = str(exc_info.value)
        assert "container-presence" in message
        assert "risk_dispositions" in message
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
        # The removal is recorded in the cross-stage record.
        record = _repair_record(tmp_path)
        assert _record_tuples(record) == [
            (
                "risk_derivation",
                "first",
                "cleanup",
                "atlas-typo-not-supplied",
                "removed",
            )
        ]

    def test_a13_gap_malformed_disposition_only_is_cleaned_with_no_call(
        self, tmp_path
    ):
        """A13: malformed gap disposition rows alone are a recorded cleanup."""
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
        # The removed row is recorded with its reason (approved policy C1).
        record = _repair_record(tmp_path)
        assert _record_tuples(record) == [
            ("gap_analysis", "first", "cleanup", "L-1", "removed")
        ]
        entry = record["records"][0]
        assert "not_applicable" in entry["reason"] or "reason" in entry["reason"]
        assert entry["proposed"] == {"removed_rows": ["L-1"]}
        assert entry["applied"] == {"removed_rows": ["L-1"]}

    def test_a19_repair_path_removal_of_unsupplied_rows_is_warned_and_recorded(
        self, tmp_path
    ):
        draft = _attempt_two_response()
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
        client.set_response_for(
            DispositionRepairResponse,
            {"risk_dispositions": _disposition_repair_rows()},
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
        # The repair path renders the same removal warning as the cleanup path.
        assert any(
            "atlas-typo-not-supplied" in warning and "unsupplied" in warning
            for warning in warnings
        )
        record = _repair_record(tmp_path)
        tuples = _record_tuples(record)
        assert (
            "risk_derivation",
            "repair",
            "cleanup",
            "atlas-typo-not-supplied",
            "removed",
        ) in tuples
        assert (
            "risk_derivation",
            "repair",
            "repair",
            _SAVED_MISSING_SEVEN[0],
            "repaired",
        ) in tuples


class TestGapObligationRepair:
    """The gap call's obligation entries join the same repair scope."""

    def test_repairs_through_the_authority_merge(self, tmp_path):
        risk = _complete_risk_response()
        gap = _gap_constraint_defect_response()
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [risk, gap])
        client.set_response_for(
            ObligationRepairResponse,
            _gap_obligation_repair_response(),
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
        # The corrected entry is the original with the channel relocated.
        assert repaired.obligations[0].violated_via == "reply"
        assert repaired.obligations[0].realized_by is None
        assert repaired.obligations[0].kind == "forbidden"
        assert repaired.obligations[0].behavior == (
            "including sensitive health data in a reply"
        )
        assert result.risk_dispositions and len(result.risk_dispositions) == 112

        entries = _stage1a_entries(tmp_path)
        assert [entry["step"] for entry in entries] == [
            "risk_derivation",
            "gap_analysis",
            "gap_analysis_repair",
        ]
        assert [entry["success"] for entry in entries] == [True, False, True]

    def test_a30_airbnb_gap_shape_repairs_only_the_rule_span(self, tmp_path):
        """The saved Airbnb first-gap-failure shape: an ellipsis rule_span.

        The saved run's first ``gap_analysis`` response failed record-level
        validation because SC-10/O1's ``rule_span`` quoted the rule with an
        ellipsis.  Under the corrected contract that is one rule-span defect
        (R1.2 row 11): the gap repair changes only the span, with the same
        call count the historical whole-object retry spent.
        """
        rule = (
            "The system must ensure LLM responses regarding policy and "
            "refunds are grounded in the retrieved policy and knowledge "
            "system data."
        )
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
                    "rule": rule,
                    "applies_when": ["a neutralized condition holds"],
                    "related_hazards": ["H-8"],
                    "obligations": [
                        {
                            "obligation_id": "O1",
                            "kind": "required",
                            "behavior": "ground responses in retrieved data",
                            "rule_span": (
                                "ensure LLM responses... are grounded in the "
                                "retrieved policy and knowledge system data"
                            ),
                            "realized_by": "unknown",
                        }
                    ],
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
                                "behavior": "ground responses in retrieved data",
                                "rule_span": (
                                    "responses regarding policy and refunds "
                                    "are grounded in the retrieved policy and "
                                    "knowledge system data"
                                ),
                                "realized_by": "unknown",
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

        entry = result.security_constraints[7].obligations[0]
        assert entry.rule_span == (
            "responses regarding policy and refunds are grounded in the "
            "retrieved policy and knowledge system data"
        )
        assert entry.behavior == "ground responses in retrieved data"
        assert entry.realized_by == "unknown"
        assert entry.kind == "required"
        # Same call count as the historical whole-object retry, narrower scope.
        entries = _stage1a_entries(tmp_path)
        assert [entry["step"] for entry in entries] == [
            "risk_derivation",
            "gap_analysis",
            "gap_analysis_repair",
        ]
        assert [entry["success"] for entry in entries] == [True, False, True]


class TestRepairRecord:
    """A20-A23: one run-level, cross-stage, accumulating record artifact."""

    def test_a20_risk_repair_then_gap_cleanup_accumulates(self, tmp_path):
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [_attempt_one_response(), _gap_malformed_disposition_response()],
        )
        client.set_response_for(ObligationRepairResponse, _obligation_repair_response())

        result = derive_loss_analysis(
            llm_client=client,
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards(),
            run_dir=tmp_path,
        )

        assert len(result.risk_dispositions) == 112
        record = _repair_record(tmp_path)
        assert record["schema_version"] == "loss-analysis-repair-record-v2"
        assert _record_tuples(record) == [
            ("risk_derivation", "first", "salvage", "SC-1/O1", "removed"),
            ("risk_derivation", "repair", "repair", "SC-1/O1", "repaired"),
            ("gap_analysis", "first", "cleanup", "credo-risk-004", "removed"),
        ]
        salvage = record["records"][0]
        assert "forbidden but carries realized_by" in salvage["reason"]
        assert salvage["proposed"] == {"dropped_entries": ["O1"]}
        assert salvage["applied"] == {"dropped_entries": ["O1"]}
        repaired = record["records"][1]
        assert "permitted correction" in repaired["reason"]
        assert repaired["proposed"] == {"entries": ["SC-1/O1"]}
        assert repaired["applied"] == {"entries": ["SC-1/O1"]}
        assert repaired["raw_step"] == "risk_derivation_repair"

    def test_a21_risk_repair_then_gap_repair_accumulates_per_stage(self, tmp_path):
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [_attempt_one_response(), _gap_constraint_defect_response()],
        )
        client.set_response_for(
            ObligationRepairResponse,
            [_obligation_repair_response(), _gap_obligation_repair_response()],
        )

        result = derive_loss_analysis(
            llm_client=client,
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards(),
            run_dir=tmp_path,
        )

        assert len(result.security_constraints) == 2
        record = _repair_record(tmp_path)
        assert _record_tuples(record) == [
            ("risk_derivation", "first", "salvage", "SC-1/O1", "removed"),
            ("risk_derivation", "repair", "repair", "SC-1/O1", "repaired"),
            ("gap_analysis", "first", "salvage", "SC-8/O1", "removed"),
            ("gap_analysis", "repair", "repair", "SC-8/O1", "repaired"),
        ]

    def test_a22_gap_repair_failure_preserves_the_risk_entries(self, tmp_path):
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [_attempt_one_response(), _gap_constraint_defect_response()],
        )
        # The gap repair replaces the channel: a typed rejection.
        client.set_response_for(
            ObligationRepairResponse,
            [
                _obligation_repair_response(),
                _gap_obligation_repair_response(
                    entry={
                        "obligation_id": "O1",
                        "kind": "forbidden",
                        "behavior": "including sensitive health data in a reply",
                        "rule_span": "must uphold control SC-8",
                        "violated_via": "state",
                    }
                ),
            ],
        )

        with pytest.raises(StageError, match="targeted repair failed"):
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )

        record = _repair_record(tmp_path)
        tuples = _record_tuples(record)
        # The earlier risk-stage success survives the later gap failure.
        assert (
            "risk_derivation",
            "repair",
            "repair",
            "SC-1/O1",
            "repaired",
        ) in tuples
        assert (
            "gap_analysis",
            "repair",
            "repair",
            "SC-8/O1",
            "rejected",
        ) in tuples
        rejected = record["records"][3]
        assert "repair_channel_replaced" in rejected["reason"]
        assert rejected["applied"] == {}
        assert rejected["proposed"] == {"entries": ["SC-8/O1"]}

    def test_a23_terminal_unsupported_response_still_writes_the_record(self, tmp_path):
        risk = _complete_risk_response() | {"use_case_losses": "not a list"}
        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [risk])

        with pytest.raises(StageError) as exc_info:
            derive_loss_analysis(
                llm_client=client,
                use_case_text=_USE_CASE,
                risk_cards=_occiai_cards(),
                run_dir=tmp_path,
            )
        assert "container-type" in str(exc_info.value)

        record = _repair_record(tmp_path)
        tuples = _record_tuples(record)
        assert (
            "risk_derivation",
            "first",
            "unsupported",
            "use_case_losses",
            "unsupported",
        ) in tuples
        unsupported = record["records"][0]
        assert "non-record wire errors" in unsupported["reason"]
        assert unsupported["proposed"] == {}
        assert unsupported["applied"] == {}

    def test_a_clean_run_writes_no_record(self, tmp_path):
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [_complete_risk_response(), _empty_gap_response()],
        )

        derive_loss_analysis(
            llm_client=client,
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards(),
            run_dir=tmp_path,
        )

        assert not (tmp_path / "loss-analysis-repair.yaml").exists()

    def test_the_run_manifest_gains_the_stage_1a_repair_block(self, tmp_path):
        from asago_scenario_generator.stpa.infra.templates import TemplateLoader
        from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
        from asago_scenario_generator.stpa.system_model.run import _write_manifest

        record = RepairRecord()
        record.add(
            stage="risk_derivation",
            attempt="repair",
            kind="repair",
            identity="SC-1/O1",
            reason="a neutralized reason",
            proposed={"entries": ["SC-1/O1"]},
            applied={"entries": ["SC-1/O1"]},
            outcome="repaired",
            raw_step="risk_derivation_repair",
        )
        _write_manifest(
            run_dir=tmp_path,
            llm_client=MockLLMClient(),
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards()[:1],
            loader=TemplateLoader(PROMPTS_DIR),
            critic_findings=None,
            temperature=0.4,
            profile_skipped=False,
        )
        # A manifest without a record carries no repair block.
        manifest = yaml.safe_load(
            (tmp_path / "run-manifest.yaml").read_text(encoding="utf-8")
        )
        assert "repair" not in manifest["stage_summary"]["stage_1a"]

        _write_manifest(
            run_dir=tmp_path,
            llm_client=MockLLMClient(),
            use_case_text=_USE_CASE,
            risk_cards=_occiai_cards()[:1],
            loader=TemplateLoader(PROMPTS_DIR),
            critic_findings=None,
            temperature=0.4,
            profile_skipped=False,
            stage_1a_repair=record,
        )
        manifest = yaml.safe_load(
            (tmp_path / "run-manifest.yaml").read_text(encoding="utf-8")
        )
        repair_block = manifest["stage_summary"]["stage_1a"]["repair"]
        assert repair_block["artifact"] == "loss-analysis-repair.yaml"
        assert repair_block["record_path"].endswith("loss-analysis-repair.yaml")
        assert repair_block["counts_by_stage"] == {
            "risk_derivation": {"repaired": 1}
        }


class _ConfiguredClient(MockLLMClient):
    """A fake client carrying the audited gemma4-oc budget numbers."""

    def __init__(self) -> None:
        super().__init__()
        self.context_window = 32768
        self.max_completion_tokens = 8192


def _saved_selected_obligation() -> SelectedObligation:
    """The saved attempt-1 entry as a deterministically selected repair pair."""
    return SelectedObligation(
        constraint_id="SC-1",
        obligation_id="O1",
        original_entry_raw=dict(_SAVED_MALFORMED_OBLIGATION),
        validation_errors=(
            "obligation: obligation 'O1' is forbidden but carries realized_by; "
            "forbidden entries name violated_via",
        ),
        permitted_changes=(
            PermittedChange(
                kind="relocate_channel",
                source_field="realized_by",
                destination_field="violated_via",
                value="reply",
            ),
        ),
        constraint_rule=_SC1_RULE,
    )


class TestRepairPreflight:
    """The repair prompt is preflighted and fails closed before dispatch."""

    def test_oversized_repair_prompt_is_blocked_without_dispatch(self, tmp_path):
        from asago_scenario_generator.stpa.infra.templates import TemplateLoader
        from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
        from asago_scenario_generator.stpa.system_model.loss_analysis import (
            STAGE1A_MAX_COMPLETION_TOKENS,
            normalize_disposition_citations,
        )

        draft = LossAnalysisDraft.model_validate(_attempt_two_response())
        plan = ObligationRepairPlan(
            prior=draft,
            selected=(_saved_selected_obligation(),),
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
        assert len(outcome.selected) == 1
        selected = outcome.selected[0]
        assert selected.constraint_id == "SC-1"
        assert selected.obligation_id == "O1"
        assert selected.original_entry_raw == dict(_SAVED_MALFORMED_OBLIGATION)
        assert selected.permitted_changes == (
            PermittedChange(
                kind="relocate_channel",
                source_field="realized_by",
                destination_field="violated_via",
                value="reply",
            ),
        )
        assert selected.correction_instruction == (
            "move `realized_by: reply` to `violated_via` unchanged"
        )
        assert len(outcome.prior.risk_dispositions) == 112
        assert outcome.prior.security_constraints[0].obligations == []
