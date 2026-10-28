"""The revision correction shows the rejected delta it asks the model to fix.

The fixtures are a reviewed control structure with ten responsibilities and,
trimmed from a saved run's revision reply, the new RESP-11 it proposed.  Its
feedback channel FB-11-2 states a settled authority whose basis cites neither
the use case nor an offered evidence ref, so the reply is rejected and earns
the one correction.  That correction carried the exact error but not the
rejected delta: FB-11-2 appeared in it only inside the error, and the saved
run's replacement dropped the channel, leaving the process-model part it
updated without feedback.

The correction now shows the rejected delta, before the exact error, so the
model can correct it in place.
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
    run_revision,
)
from tests.stpa.sp1_helpers import MockLLMClient

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "stpa"

USE_CASE = "A booking assistant manages reservations and listings."

_PRIOR_LABEL = "Prior structured response to correct in place:"
_ERROR_LABEL = "Exact validation error from the prior response:"
_REASON = (
    "feedback channel FB-11-2 settled authority basis must cite the supplied "
    "use case or an exact target-evidence ref"
)


def _reviewed() -> ControlStructure:
    return read_yaml(  # type: ignore[return-value]
        FIXTURES_DIR / "control_structure_ten_responsibilities.yaml",
        ControlStructure,
    )


def _rejected_text() -> str:
    return (FIXTURES_DIR / "revision_uncited_new_channel.json").read_text(
        encoding="utf-8"
    )


def _corrected_text() -> str:
    reply = json.loads(_rejected_text())
    corrected = copy.deepcopy(reply)
    channel = corrected["new_responsibilities"][0]["feedback_channels"][1]
    channel["authority_for_update"]["basis"] = (
        "Use case: the assistant itself classifies whether a message is "
        "malformed or carries injection patterns."
    )
    return json.dumps(corrected)


def _findings() -> CriticFindings:
    return CriticFindings(
        gaps=[
            CriticGap(
                gap_type="missing_responsibility",
                description="No responsibility classifies incoming messages",
                related_attack_path="An injected message reaches tool selection",
                suggested_remedy="Add an intent and input-safety classifier",
            )
        ]
    )


def _revise(tmp_path: Path) -> tuple[MockLLMClient, ControlStructure, list[str]]:
    client = MockLLMClient()
    client.set_response_queue([_rejected_text(), _corrected_text()])
    revised, warnings = run_revision(
        llm_client=client,  # type: ignore[arg-type]
        control_structure=_reviewed(),
        critic_findings=_findings(),
        use_case_text=USE_CASE,
        run_dir=tmp_path,
        template_loader=TemplateLoader(PROMPTS_DIR),
    )
    return client, revised, warnings


def test_the_correction_carries_the_rejected_delta(tmp_path: Path) -> None:
    client, _, _ = _revise(tmp_path)

    first, correction = (call.user_prompt for call in client.calls)
    assert correction.startswith(first)
    added = correction.removeprefix(first)
    assert f"{_PRIOR_LABEL}\n```json\n{_rejected_text()}\n```" in added
    assert added.index(_PRIOR_LABEL) < added.index(_ERROR_LABEL)
    assert _REASON in added.split(_ERROR_LABEL, 1)[1]
    # The rejected channel's definition is in the request, not only its ID.
    assert '"description": "Input syntax/safety check"' in added


def test_the_corrected_delta_keeps_the_rejected_channel(tmp_path: Path) -> None:
    client, revised, _ = _revise(tmp_path)

    assert len(client.calls) == 2
    resp_11 = next(r for r in revised.responsibilities if r.resp_id == "RESP-11")
    assert [fb.fb_id for fb in resp_11.feedback_channels] == ["FB-11-1", "FB-11-2"]
    assert resp_11.feedback_channels[1].updates == "PM-11-2"
