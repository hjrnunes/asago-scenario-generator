"""Offline verification of the saved-context authoring replay tool.

These tests never contact a model endpoint.  They cover the two pure helpers
the reviewer relies on: the constraint override that swaps pinned texts while
keeping the candidate's binding, and the per-sample record that reports drafts
and the omission shape without adding a judgment.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

import replay_authoring_context as tool  # noqa: E402
from asago_scenario_generator.stpa.models.target_derived_structure import (
    ActionBinding,
)
from asago_scenario_generator.stpa.scenario_prod.authoring import (
    AuthoredScenarioDraft,
    AuthoringCandidate,
    CandidateAuthoringOutcome,
    ScenarioHazardLine,
    ScenarioRejection,
)


def _candidate() -> AuthoringCandidate:
    """Return one pinned (constraint, action) candidate."""
    return AuthoringCandidate(
        constraint_id="SC-8",
        rule="Pinned rule.",
        applies_when=("a refund is requested",),
        action_name="process_refund",
        action_description="Process a refund against an order.",
        action_binding=ActionBinding(
            ca_id="CA-1-2",
            name="process_refund",
            kind="tool_call",
            resource_id="mcp:target:mini:process_refund",
            operation_id="process_refund",
            argument_names=("amount", "order_id", "reason"),
            justification="observed operation",
        ),
        hazards=(ScenarioHazardLine("H-8", "Pinned hazard.", (("L-1", "Loss."),)),),
        constraint_text="Pinned constraint.",
    )


def _draft(kind: str, adversary_kind: str, gain: str) -> AuthoredScenarioDraft:
    """Return one minimal authored draft with the given oracle and adversary."""
    return AuthoredScenarioDraft.model_validate(
        {
            "adversary": {"kind": adversary_kind, "gain": gain},
            "stimulus": {"kind": "user_message", "text": "Refund ORD-104."},
            "unsafe_observation": {"kind": kind, "tool": "process_refund"},
        }
    )


def _write_override(path: Path, payload: dict) -> Path:
    path.write_text(yaml.dump(payload), encoding="utf-8")
    return path


def test_override_replaces_texts_and_keeps_binding(tmp_path: Path) -> None:
    override = _write_override(
        tmp_path / "override.yaml",
        {
            "constraint_id": "SC-4",
            "description": "Older description.",
            "rule": "Older rule.",
            "hazards": [
                {
                    "hazard_id": "H-2",
                    "description": "Older hazard.",
                    "losses": [{"loss_id": "L-3", "description": "Older loss."}],
                }
            ],
        },
    )

    replaced = tool._apply_override(_candidate(), override)

    assert replaced.constraint_id == "SC-4"
    assert replaced.rule == "Older rule."
    assert replaced.constraint_text == "Older description."
    assert replaced.applies_when == ()
    assert replaced.hazards == (
        ScenarioHazardLine("H-2", "Older hazard.", (("L-3", "Older loss."),)),
    )
    assert replaced.action_binding == _candidate().action_binding
    assert replaced.step_label == "SC-4:process_refund"


def test_override_rejects_missing_fields(tmp_path: Path) -> None:
    override = _write_override(
        tmp_path / "override.yaml", {"constraint_id": "SC-4", "rule": "r"}
    )

    with pytest.raises(ValueError, match="missing fields"):
        tool._apply_override(_candidate(), override)


def test_override_rejects_empty_hazards(tmp_path: Path) -> None:
    override = _write_override(
        tmp_path / "override.yaml",
        {"constraint_id": "SC-4", "description": "d", "rule": "r", "hazards": []},
    )

    with pytest.raises(ValueError, match="no hazards"):
        tool._apply_override(_candidate(), override)


def test_sample_record_reports_drafts_and_omission_shape() -> None:
    candidate = _candidate()
    omission = _draft("tool_absent", "malicious_customer", "an ineligible refund")
    rejected = _draft("tool_argument", "none", "none")
    outcome = CandidateAuthoringOutcome(
        candidate=candidate,
        rejected=(
            (omission, ScenarioRejection("unsupported_oracle", "detail one")),
            (rejected, ScenarioRejection("qualifier_dropped", "detail two")),
        ),
    )
    rows = [
        {"prompt_tokens": 100, "completion_tokens": 20},
        {"prompt_tokens": 100, "completion_tokens": 25},
    ]

    record = tool._sample_record(2, outcome, candidate, rows)

    assert record["sample"] == 2
    assert record["prompt_tokens"] == 200
    assert record["completion_tokens"] == 45
    assert record["omission_shape_drafted"] is True
    assert record["omission_drafts"] == [
        {"adversary_kind": "malicious_customer", "gain": "an ineligible refund"}
    ]
    assert record["no_scenario_reason"] is None
    assert "error" not in record
    assert [draft["accepted"] for draft in record["drafts"]] == [False, False]
    assert record["drafts"][0]["rejection_reason"] == "unsupported_oracle"
    assert record["drafts"][1]["adversary_kind"] == "none"
    assert record["drafts"][1]["rejection_detail"] == "detail two"


def test_sample_record_without_omission_shape_or_drafts() -> None:
    candidate = _candidate()
    outcome = CandidateAuthoringOutcome(
        candidate=candidate,
        no_scenario_reason="no supported check expresses the unsafe behavior",
        error="provider timeout",
    )

    record = tool._sample_record(1, outcome, candidate, [])

    assert record["drafts"] == []
    assert record["omission_shape_drafted"] is False
    assert record["omission_drafts"] == []
    assert record["no_scenario_reason"].startswith("no supported check")
    assert record["error"] == "provider timeout"


# Prompt addendum splice (replay-only; the production templates stay untouched)


PROMPT_WITH_OFFER = (
    "Guidance paragraph.\n\n"
    "A `conversation` stimulus carries `turns`, two to three user turns in "
    "order, and no `text`:\n\n"
    "```json\n" + tool._ADDENDUM_ANCHOR + "\n\nNext section."
)


def test_addendum_splices_once_after_the_shape_block() -> None:
    spliced = tool._splice_addendum(PROMPT_WITH_OFFER, "Grounding rule text.")

    assert (
        f"{tool._ADDENDUM_ANCHOR}\n\nGrounding rule text.\n\nNext section." in spliced
    )
    assert spliced.count("Grounding rule text.") == 1


def test_addendum_fails_closed_without_the_anchor() -> None:
    with pytest.raises(ValueError, match="anchor"):
        tool._splice_addendum("No conversation offer here.", "Grounding rule.")


def test_addendum_fails_closed_on_a_repeated_anchor() -> None:
    doubled = PROMPT_WITH_OFFER + "\n\n" + PROMPT_WITH_OFFER

    with pytest.raises(ValueError, match="anchor"):
        tool._splice_addendum(doubled, "Grounding rule.")


def test_addendum_rejects_empty_text() -> None:
    with pytest.raises(ValueError, match="empty"):
        tool._splice_addendum(PROMPT_WITH_OFFER, "  \n ")


def test_capture_without_addendum_hashes_the_untouched_prompt() -> None:
    capture = tool._PromptCapture(None)

    capture(system_prompt="system", user_prompt=PROMPT_WITH_OFFER)

    (record,) = capture.calls
    assert record["user_prompt"] == PROMPT_WITH_OFFER
    assert record["user_prompt_sha256"] == tool._sha256_text(PROMPT_WITH_OFFER)
    assert capture.addendum_record is None


def test_capture_splices_before_hashing_and_records_the_digest(
    tmp_path: Path,
) -> None:
    addendum_file = tmp_path / "addendum.md"
    addendum_file.write_text("Grounding rule text.\n", encoding="utf-8")
    capture = tool._PromptCapture(
        None, addendum="Grounding rule text.", addendum_file=addendum_file
    )

    capture(system_prompt="system", user_prompt=PROMPT_WITH_OFFER)

    (record,) = capture.calls
    expected = tool._splice_addendum(PROMPT_WITH_OFFER, "Grounding rule text.")
    assert record["user_prompt"] == expected
    assert record["user_prompt_sha256"] == tool._sha256_text(expected)
    assert capture.addendum_record == {
        "file": str(addendum_file),
        "sha256": tool._sha256_file(addendum_file),
    }
