"""Call 2a rejects extra fields that carry content and ignores empty ones."""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model.control_structure import (
    PROMPTS_DIR,
    RequirementSet,
    ResponsibilitySet,
    _call_2a_responsibilities,
)

from tests.stpa.sp1_helpers import (
    MockLLMClient,
    valid_requirement_set_dict,
    valid_responsibility_set_dict,
)


def _payload_with(**extra: object) -> dict:
    payload = valid_responsibility_set_dict()
    for responsibility in payload["responsibilities"]:
        responsibility.update(extra)
    return payload


def _call(client: MockLLMClient, tmp_path) -> ResponsibilitySet:
    return _call_2a_responsibilities(
        llm_client=client,
        use_case_text="A clinic assistant answers patient questions.",
        requirement_set=RequirementSet.model_validate(valid_requirement_set_dict()),
        run_dir=tmp_path,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.0,
    )


@pytest.mark.parametrize("empty", [[], {}, None, ""])
def test_empty_extra_responsibility_field_is_ignored(tmp_path, empty) -> None:
    """An empty value carries no content, so dropping it loses nothing."""
    client = MockLLMClient()
    client.set_response_for(ResponsibilitySet, _payload_with(coordination=empty))

    result = _call(client, tmp_path)

    assert len(client.calls) == 1
    expected = valid_responsibility_set_dict()["responsibilities"]
    assert [item.resp_id for item in result.responsibilities] == [
        item["resp_id"] for item in expected
    ]


def test_extra_responsibility_field_with_content_fails_and_says_what_to_remove(
    tmp_path,
) -> None:
    client = MockLLMClient()
    client.set_response_for(
        ResponsibilitySet, _payload_with(coordination=[{"with": "RESP-2"}])
    )

    with pytest.raises(Exception) as error:
        _call(client, tmp_path)

    assert "coordination" in str(error.value)
    retry = " ".join(client.calls[1].user_prompt.split())
    assert (
        "unexpected responsibility collection field(s) at index 0: coordination"
        in retry
    )
    assert (
        "Remove them; each responsibility contains only resp_id, description, "
        "responsibility_constraints, security_constraint_refs, and "
        "process_model_parts" in retry
    )
