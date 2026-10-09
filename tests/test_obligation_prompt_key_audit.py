"""One prohibited-key scan feeds both prompt checks at the provider boundary."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, create_model

from asago_scenario_generator.stpa.obligation_aware import provider
from asago_scenario_generator.stpa.obligation_aware.contracts import AnalysisControls
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    PROHIBITED_PROMPT_KEYS,
    PROHIBITED_PROMPT_WORDS,
    audit_prompt_contract,
)

_EXACT_KEYS = (
    "semantic_digest",
    "plan_digest",
    "catalog_pins",
    "mapping_pins",
    "candidate_ids",
    "scores",
    "mitigations",
    "provider_call_id",
    "source_path",
    "artifact_path",
    "raw_mapping",
    "provider_call",
    "schema_name",
)
_FIELD_WORDS = ("digest", "pin", "score", "mitigation")


def test_the_lists_are_the_exact_keys_and_the_single_words() -> None:
    assert PROHIBITED_PROMPT_KEYS == _EXACT_KEYS
    assert PROHIBITED_PROMPT_WORDS == _FIELD_WORDS
    assert not set(PROHIBITED_PROMPT_KEYS) & set(PROHIBITED_PROMPT_WORDS)
    assert all("_" not in word for word in PROHIBITED_PROMPT_WORDS)


@pytest.mark.parametrize("key", (*_EXACT_KEYS, *_FIELD_WORDS))
def test_the_local_audit_still_rejects_each_listed_name(key: str) -> None:
    view = create_model("View", **{key: (str, ...)})(**{key: "x"})

    audit = audit_prompt_contract(view, system_prompt="Return JSON.")

    assert audit.issues == (f"prohibited prompt-view field leaked: {key}",)


class _View(BaseModel):
    description: str


def test_the_repository_preflight_receives_the_same_lists(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    received: dict[str, Any] = {}

    def capture(**kwargs: Any) -> None:
        received.update(kwargs)
        raise RuntimeError("captured")

    monkeypatch.setattr(provider, "preflight_prompt_contract", capture)
    with pytest.raises(RuntimeError, match="captured"):
        provider._preflight(
            view=_View(description="A view."),
            system_prompt="Return JSON.",
            user_prompt="Review the view.",
            stage="key-audit",
            handles=(),
            stage_max_completion_tokens=128,
            client=object(),
            controls=AnalysisControls(
                model_profile="synthesis",
                model_name="key-audit",
                deadline_seconds=30.0,
                temperature=0.0,
            ),
            configured_budget=None,
            output_schema=(),
            valid_example={},
            run_dir=tmp_path,
            call_stage="key-audit",
            step="key-audit",
        )

    assert received["prohibited_fields"] is PROHIBITED_PROMPT_WORDS
    assert received["prohibited_exact_keys"] is PROHIBITED_PROMPT_KEYS
