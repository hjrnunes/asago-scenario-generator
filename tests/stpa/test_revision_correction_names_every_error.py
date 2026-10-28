"""The one revision correction names the merge error and every authority error.

A saved run's revision reply restated a feedback channel that updates another
responsibility's process-model part, which the merge refuses, and settled the
authority of three channels without citing the use case or an offered
evidence ref.  Validation merged the delta first and stopped at the merge
error, so a correction for such a reply named only the merge error, and a
reply fixed as asked still failed the authority checks with no request left.

The fixtures here have the same shape: a reviewed structure with one
responsibility and a reply restating RESP-2, which it does not have, whose
channel settles its authority on an uncited basis.  The one correction now
names both errors and carries the authority note; no request is added.
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
_MERGE = (
    "Modified responsibility resp_id must match an existing canonical "
    "responsibility ID; unknown ID(s): RESP-2."
)
_AUTHORITY = (
    "feedback channel FB-2-1 settled authority basis must cite the supplied "
    "use case or an exact target-evidence ref"
)


def _reviewed() -> ControlStructure:
    return read_yaml(  # type: ignore[return-value]
        FIXTURES_DIR / "control_structure_one_responsibility.yaml",
        ControlStructure,
    )


def _unmergeable_and_uncited() -> dict:
    """RESP-2 restated, and its channel settled on a basis citing nothing."""
    reply = json.loads(
        (FIXTURES_DIR / "revision_modifies_unknown_responsibility.json").read_text(
            encoding="utf-8"
        )
    )
    channel = reply["modified_responsibilities"][0]["feedback_channels"][0]
    channel["authority_for_update"]["basis"] = (
        "The assistant verifies that content is approved and specialty-matched."
    )
    return reply


def _corrected() -> dict:
    """The same responsibility proposed as an addition, its basis cited."""
    reply = copy.deepcopy(_unmergeable_and_uncited())
    channel = reply["modified_responsibilities"][0]["feedback_channels"][0]
    channel["authority_for_update"]["basis"] = (
        "Use case: the assistant must verify content is approved and specialty-matched."
    )
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


def _authority_note() -> str:
    return (
        TemplateLoader(PROMPTS_DIR)
        .render_prompt("revision_authority_correction.j2")
        .rstrip()
    )


def merge_and_authority_correction_request(run_dir: Path) -> str:
    """Return the revision correction after a merge and an authority error."""
    client, _, _ = _revise(run_dir, _unmergeable_and_uncited(), _corrected())
    return client.calls[1].user_prompt


def test_the_one_correction_names_the_merge_and_the_authority_error(
    tmp_path: Path,
) -> None:
    client, revised, warnings = _revise(
        tmp_path, _unmergeable_and_uncited(), _corrected()
    )

    assert len(client.calls) == 2
    error = client.calls[1].user_prompt.split(_ERROR_LABEL, 1)[1]
    assert _MERGE in error
    assert _AUTHORITY in error
    assert error.index(_MERGE) < error.index(_AUTHORITY)
    assert _authority_note() in error
    assert discarded_revision_reason(warnings) is None
    assert [r.resp_id for r in revised.responsibilities] == ["RESP-1", "RESP-2"]


def test_a_correction_with_both_errors_discards_the_revision_naming_both(
    tmp_path: Path,
) -> None:
    client, revised, warnings = _revise(
        tmp_path, _unmergeable_and_uncited(), _unmergeable_and_uncited()
    )

    assert len(client.calls) == 2
    assert revised == _reviewed()
    reason = discarded_revision_reason(warnings)
    assert reason is not None
    assert reason.startswith("Revision failed: ")
    assert _MERGE in reason
    assert _AUTHORITY in reason
