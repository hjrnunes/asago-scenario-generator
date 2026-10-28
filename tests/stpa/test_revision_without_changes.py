"""A critic revision without effect leaves the structure unchanged.

The fixture is a reviewed control structure whose RESP-5 cites its security
constraints out of order (``SC-8`` before ``SC-6``).  A saved run answered the
critic's gaps with exactly ``{}``.  The reply validated, and merging it
re-normalized the structure, which sorts those citations; the sorted copy
compared unequal to the reviewed one, so the Stage 2 manifest reported
``critic_revision.status: applied`` although nothing was revised and the
critic's gaps stayed unresolved.  A reply that restates RESP-3 exactly as it
stands did the same.

Whether a reply has an effect is decided against the reviewed structure as
the merge normalizes it, so normalization alone is no revision.  A reply
without effect leaves the reviewed structure in force and the manifest
records ``unchanged``.  The revision step still strips a responsibility that
was already empty; that cleanup is reported by its own warning, not as a
revision.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    run_revision,
)
from asago_scenario_generator.stpa.system_model.run import (
    _critic_revision_record,
    _maybe_apply_revision,
)
from tests.stpa.helpers import make_minimal_loss_analysis
from tests.stpa.sp1_helpers import MockLLMClient

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "stpa"

USE_CASE = "A booking assistant manages reservations and listings."

_NO_CHANGE = (
    "Revision made no structural changes for explicit critic gaps; the "
    "baseline control structure was retained and those gaps remain unresolved."
)
_STRIPPED_EMPTY = (
    "Stripped empty responsibility RESP-6 (Confirms payment changes) after "
    "revision: no PM parts, control actions, or feedback channels."
)


def _reviewed() -> ControlStructure:
    return read_yaml(  # type: ignore[return-value]
        FIXTURES_DIR / "control_structure_unsorted_constraint_refs.yaml",
        ControlStructure,
    )


def _with_empty_responsibility() -> ControlStructure:
    reviewed = _reviewed()
    return reviewed.model_copy(
        update={
            "responsibilities": [
                *reviewed.responsibilities,
                Responsibility(
                    resp_id="RESP-6", description="Confirms payment changes"
                ),
            ]
        }
    )


def _findings() -> CriticFindings:
    return CriticFindings(
        gaps=[
            CriticGap(
                gap_type="missing_feedback",
                description="No feedback confirms the listing owner",
                related_attack_path="A guest edits a listing they do not host",
                suggested_remedy="Add listing ownership feedback",
            ),
            CriticGap(
                gap_type="missing_responsibility",
                description="No responsibility refuses a payment change",
                related_attack_path="A guest alters the payment of a booking",
                suggested_remedy="Add a payment-change refusal responsibility",
            ),
        ]
    )


def _client(reply: dict) -> MockLLMClient:
    client = MockLLMClient()
    client.set_response_queue([reply])
    return client


def _restated_resp_3() -> dict:
    """RESP-3 restated exactly as the reviewed structure holds it."""
    resp_3 = _reviewed().responsibilities[2]
    assert resp_3.resp_id == "RESP-3"
    return {
        "modified_responsibilities": [resp_3.model_dump(mode="json", exclude_none=True)]
    }


_DISMISSAL = {
    "dismissed_gaps": ["The listing owner is already confirmed by FB-5-1."],
}
_REPLIES = pytest.mark.parametrize(
    "reply",
    ({}, _DISMISSAL, _restated_resp_3()),
    ids=("empty", "dismissal", "restated-unchanged"),
)


def _apply(structure: ControlStructure, reply: dict, run_dir: Path):
    return _maybe_apply_revision(
        structure,
        critic_findings=_findings(),
        llm_client=_client(reply),  # type: ignore[arg-type]
        use_case_text=USE_CASE,
        run_dir=run_dir,
        loss_analysis=make_minimal_loss_analysis(),
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.0,
    )


def test_the_fixture_cites_constraints_out_of_order() -> None:
    resp_5 = _reviewed().responsibilities[4]

    assert resp_5.resp_id == "RESP-5"
    assert resp_5.security_constraint_refs == ["SC-8", "SC-6"]


@_REPLIES
def test_a_revision_without_effect_keeps_the_reviewed_structure(
    tmp_path: Path, reply: dict
) -> None:
    reviewed = _reviewed()

    revised, warnings = run_revision(
        llm_client=_client(reply),  # type: ignore[arg-type]
        control_structure=reviewed,
        critic_findings=_findings(),
        use_case_text=USE_CASE,
        run_dir=tmp_path,
        template_loader=TemplateLoader(PROMPTS_DIR),
    )

    assert revised is reviewed
    assert _NO_CHANGE in warnings


@_REPLIES
def test_a_revision_without_effect_is_recorded_unchanged(
    tmp_path: Path, reply: dict
) -> None:
    reviewed = _reviewed()

    structure, warnings, revised = _apply(reviewed, reply, tmp_path)

    assert revised is False
    assert structure == reviewed
    assert _critic_revision_record(_findings(), warnings, revised=revised) == {
        "status": "unchanged"
    }


@_REPLIES
def test_stripping_an_empty_responsibility_is_not_a_revision(
    tmp_path: Path, reply: dict
) -> None:
    structure, warnings, revised = _apply(_with_empty_responsibility(), reply, tmp_path)

    # The cleanup still runs, and its own warning reports it.
    assert [r.resp_id for r in structure.responsibilities] == [
        r.resp_id for r in _reviewed().responsibilities
    ]
    assert _STRIPPED_EMPTY in warnings
    assert revised is False
    assert _critic_revision_record(_findings(), warnings, revised=revised) == {
        "status": "unchanged"
    }


def test_a_revision_with_effect_is_still_applied(tmp_path: Path) -> None:
    reply = _restated_resp_3()
    restated = reply["modified_responsibilities"][0]
    restated["description"] = "Answers reservation questions for verified guests."

    structure, warnings, revised = _apply(_reviewed(), reply, tmp_path)

    assert revised is True
    assert structure.responsibilities[2].description == restated["description"]
    assert _critic_revision_record(_findings(), warnings, revised=revised) == {
        "status": "applied"
    }
