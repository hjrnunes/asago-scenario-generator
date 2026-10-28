"""A revision delta that cannot be merged is rejected while it can be corrected.

The fixtures are a reviewed control structure with one responsibility and,
trimmed from a saved run's revision reply, a restatement of RESP-2, which the
structure does not have.  The reply passed every validation check, so the
call accepted it; the merge then refused the unknown responsibility and the
revision was discarded without the model ever seeing why.

Validation now merges the delta into the structure it revises, so a delta the
merge would refuse earns the one correction, which names the reason.  A
correction that still cannot be merged discards the revision as before.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    discarded_revision_reason,
    run_revision,
)
from tests.stpa.sp1_helpers import MockLLMClient

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "stpa"

USE_CASE = "A patient assistant answers questions from approved materials."

_ERROR_LABEL = "Exact validation error from the prior response:"
_UNKNOWN = (
    "Modified responsibility resp_id must match an existing canonical "
    "responsibility ID; unknown ID(s): RESP-2."
)


def _reviewed() -> ControlStructure:
    return read_yaml(  # type: ignore[return-value]
        FIXTURES_DIR / "control_structure_one_responsibility.yaml",
        ControlStructure,
    )


def _unmergeable() -> dict:
    return json.loads(
        (FIXTURES_DIR / "revision_modifies_unknown_responsibility.json").read_text(
            encoding="utf-8"
        )
    )


def _as_new_responsibility() -> dict:
    """The same responsibility proposed as an addition, which merges."""
    reply = copy.deepcopy(_unmergeable())
    return {"new_responsibilities": reply["modified_responsibilities"]}


def _findings() -> CriticFindings:
    return CriticFindings(
        gaps=[
            CriticGap(
                gap_type="missing_responsibility",
                description="No responsibility validates retrieved materials",
                related_attack_path="An unapproved document reaches the patient",
                suggested_remedy="Add a material validation responsibility",
            )
        ]
    )


def _revise(
    tmp_path: Path, *replies: dict
) -> tuple[MockLLMClient, ControlStructure, list[str]]:
    client = MockLLMClient()
    client.set_response_queue([json.dumps(reply) for reply in replies])
    revised, warnings = run_revision(
        llm_client=client,  # type: ignore[arg-type]
        control_structure=_reviewed(),
        critic_findings=_findings(),
        use_case_text=USE_CASE,
        run_dir=tmp_path,
        template_loader=TemplateLoader(PROMPTS_DIR),
    )
    return client, revised, warnings


def test_the_fixture_restates_a_responsibility_the_structure_lacks() -> None:
    assert [r.resp_id for r in _reviewed().responsibilities] == ["RESP-1"]
    assert [r["resp_id"] for r in _unmergeable()["modified_responsibilities"]] == [
        "RESP-2"
    ]


def test_an_unmergeable_delta_earns_the_correction(tmp_path: Path) -> None:
    client, revised, warnings = _revise(
        tmp_path, _unmergeable(), _as_new_responsibility()
    )

    assert len(client.calls) == 2
    correction = client.calls[1].user_prompt
    assert _UNKNOWN in correction.split(_ERROR_LABEL, 1)[1]
    assert discarded_revision_reason(warnings) is None
    assert [r.resp_id for r in revised.responsibilities] == ["RESP-1", "RESP-2"]


def test_an_unmergeable_correction_discards_the_revision(tmp_path: Path) -> None:
    reviewed = _reviewed()

    client, revised, warnings = _revise(tmp_path, _unmergeable(), _unmergeable())

    assert len(client.calls) == 2
    assert revised == reviewed
    reason = discarded_revision_reason(warnings)
    assert reason is not None
    assert reason.startswith("Revision failed: ")
    assert _UNKNOWN in reason
