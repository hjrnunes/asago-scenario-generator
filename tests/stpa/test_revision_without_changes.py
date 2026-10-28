"""A critic revision that adds and restates nothing leaves the structure unchanged.

The fixture is a reviewed control structure whose RESP-5 cites its security
constraints out of order (``SC-8`` before ``SC-6``).  A saved run answered the
critic's gaps with exactly ``{}``.  The reply validated, and merging it
re-normalized the structure, which sorts those citations; the sorted copy
compared unequal to the reviewed one, so the Stage 2 manifest reported
``critic_revision.status: applied`` although nothing was revised and the
critic's gaps stayed unresolved.

A reply without additions or restated responsibilities is not merged: the
reviewed structure stays in force and the manifest records ``unchanged``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
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


def _reviewed() -> ControlStructure:
    return read_yaml(  # type: ignore[return-value]
        FIXTURES_DIR / "control_structure_unsorted_constraint_refs.yaml",
        ControlStructure,
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


_DISMISSAL = {
    "dismissed_gaps": ["The listing owner is already confirmed by FB-5-1."],
}


def test_the_fixture_cites_constraints_out_of_order() -> None:
    resp_5 = _reviewed().responsibilities[4]

    assert resp_5.resp_id == "RESP-5"
    assert resp_5.security_constraint_refs == ["SC-8", "SC-6"]


@pytest.mark.parametrize("reply", ({}, _DISMISSAL), ids=("empty", "dismissal"))
def test_a_revision_without_changes_keeps_the_reviewed_structure(
    tmp_path: Path, reply: dict
) -> None:
    reviewed = _reviewed()

    revised, warnings = run_revision(
        llm_client=_client(reply),
        control_structure=reviewed,
        critic_findings=_findings(),
        use_case_text=USE_CASE,
        run_dir=tmp_path,
        template_loader=TemplateLoader(PROMPTS_DIR),
    )

    assert revised is reviewed
    assert _NO_CHANGE in warnings


@pytest.mark.parametrize("reply", ({}, _DISMISSAL), ids=("empty", "dismissal"))
def test_a_revision_without_changes_is_recorded_unchanged(
    tmp_path: Path, reply: dict
) -> None:
    reviewed = _reviewed()

    structure, warnings, revised = _maybe_apply_revision(
        reviewed,
        critic_findings=_findings(),
        llm_client=_client(reply),
        use_case_text=USE_CASE,
        run_dir=tmp_path,
        loss_analysis=make_minimal_loss_analysis(),
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.0,
    )

    assert revised is False
    assert structure == reviewed
    assert _critic_revision_record(_findings(), warnings, revised=revised) == {
        "status": "unchanged"
    }
