"""Stage 1a obligation-entry prompt must match the production wire contract.

The shared ``_obligation_entries.j2`` paragraph teaches the channel fields a
provider may author on constraint obligation entries.  An earlier revision
offered ``provider_request`` as a ``realized_by`` value and omitted
``state``/``result`` from ``violated_via``, so the prompt permitted a
combination the wire rejects and hid two combinations the wire accepts.
These tests pin the prompt to the production :class:`Obligation` validators
so the two surfaces cannot drift again (independent audit, 2026-09-11).
"""

from __future__ import annotations

import re
from typing import get_args

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import (
    Obligation,
    ObligationChannel,
    RealizationChannel,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR

_INCLUDES = (
    "stage1a_risk_system.j2",
    "stage1a_gap_system.j2",
    "stage1a_graph_revision_system.j2",
)


def _rendered_paragraph() -> str:
    return TemplateLoader(PROMPTS_DIR).render_prompt("_obligation_entries.j2")


def _prompt_channels(text: str, field: str) -> set[str]:
    match = re.search(
        rf"`{field}` on (?:required|forbidden) entries, one of ([^;.]+)[;.]",
        text,
    )
    assert match is not None, f"prompt must list the channels for {field}"
    return set(re.findall(r"`([a-z_]+)`", match.group(1)))


def _entry(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "obligation_id": "O1",
        "behavior": "audit probe",
        "rule_span": "audit probe",
    }
    base.update(overrides)
    return base


def test_realized_by_channels_match_the_production_realization_contract() -> None:
    assert _prompt_channels(_rendered_paragraph(), "realized_by") == set(
        get_args(RealizationChannel)
    )


def test_violated_via_channels_match_the_production_violation_contract() -> None:
    assert _prompt_channels(_rendered_paragraph(), "violated_via") == set(
        get_args(ObligationChannel)
    )


def test_prompt_offered_realization_channels_all_validate() -> None:
    for channel in get_args(RealizationChannel):
        Obligation.model_validate(_entry(kind="required", realized_by=channel))


def test_prompt_offered_violation_channels_all_validate() -> None:
    for channel in get_args(ObligationChannel):
        Obligation.model_validate(_entry(kind="forbidden", violated_via=channel))


def test_required_entry_rejects_the_retired_provider_request_realization() -> None:
    with pytest.raises(ValidationError, match="realized_by"):
        Obligation.model_validate(
            _entry(kind="required", realized_by="provider_request")
        )


def test_channel_fields_stay_kind_exclusive() -> None:
    with pytest.raises(ValidationError, match="forbidden but carries realized_by"):
        Obligation.model_validate(
            _entry(kind="forbidden", realized_by="tool_call", violated_via=None)
        )
    with pytest.raises(ValidationError, match="required but carries violated_via"):
        Obligation.model_validate(_entry(kind="required", violated_via="tool_call"))


def test_proxy_requires_source_outcome_and_completion_stays_required_only() -> None:
    with pytest.raises(ValidationError, match="source_outcome"):
        Obligation.model_validate(
            _entry(kind="forbidden", violated_via="tool_call", observation_role="proxy")
        )
    Obligation.model_validate(
        _entry(
            kind="forbidden",
            violated_via="tool_call",
            observation_role="proxy",
            source_outcome="a rejected write is processed anyway",
        )
    )
    Obligation.model_validate(
        _entry(kind="required", realized_by="tool_call", completion="the write lands")
    )
    with pytest.raises(ValidationError, match="completion"):
        Obligation.model_validate(
            _entry(kind="forbidden", violated_via="tool_call", completion="lands")
        )


def test_paragraph_explains_attempt_effect_and_optional_fields() -> None:
    prompt = " ".join(_rendered_paragraph().split())
    assert "kind-exclusive" in prompt
    assert "an attempt, never the completed effect" in prompt
    assert "`observation_role`" in prompt
    assert "`source_outcome`" in prompt
    assert "`completion` the oracle does not observe" in prompt
    assert "`projection` and `residual`" in prompt
    assert "omit them rather than guessing a channel" in prompt
    assert "no compiled oracle kind observes it either" in prompt

def test_shared_paragraph_is_included_by_every_stage1a_system_template() -> None:
    for name in _INCLUDES:
        source = (PROMPTS_DIR / name).read_text(encoding="utf-8")
        assert '{% include "_obligation_entries.j2" %}' in source
