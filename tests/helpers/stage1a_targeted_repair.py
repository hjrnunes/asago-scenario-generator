"""Shared test builders moved out of test modules."""

from __future__ import annotations

from pathlib import Path
import yaml
from asago_scenario_generator.models.risk_card import RiskCard
from tests.helpers.calls_log import read_calls_jsonl


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
    "The system must ensure that no sensitive health data is included in model outputs."
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
                "constraint_id": "SC-2",
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


def _stage1a_entries(run_dir: Path) -> list[dict]:
    return [
        entry for entry in read_calls_jsonl(run_dir) if entry["stage"] == "stage_1a"
    ]


def _repair_record(run_dir: Path) -> dict:
    """Load the run-level repair record artifact."""
    return yaml.safe_load(
        (run_dir / "loss-analysis-repair.yaml").read_text(encoding="utf-8")
    )
