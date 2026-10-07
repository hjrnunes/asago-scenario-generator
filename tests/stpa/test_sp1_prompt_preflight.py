"""Pure model-aware prompt-contract and budget tests."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)
from asago_scenario_generator.stpa.infra.prompt_preflight import (
    PromptBudget,
    PromptBudgetExceeded,
    PromptContractError,
    audit_prompt_contract,
    resolve_adapter_prompt_budget,
)
from tests.helpers.calls_log import read_calls_jsonl


def test_prompt_budget_uses_the_greater_of_ten_percent_or_1024_margin() -> None:
    small = PromptBudget(context_window=8_000, maximum_completion_tokens=2_000)
    large = PromptBudget(context_window=32_000, maximum_completion_tokens=4_000)

    assert small.safety_margin == 1_024
    assert small.usable_input_tokens == 4_976
    assert large.safety_margin == 3_200
    assert large.usable_input_tokens == 24_800


def test_prompt_audit_records_digest_and_estimated_size() -> None:
    audit = audit_prompt_contract(
        stage="stage_2",
        prompt_view={"target": "CA-1-1"},
        system_prompt='Return JSON with ca_id and description. Example: {"ca_id": "CA-1-1"}',
        user_prompt="Copy-only handle: CA-1-1",
        input_handles=("CA-1-1",),
        accounted_handles=("CA-1-1",),
        selectable_references={"CA-1-1": "Authorize request"},
        output_schema=("ca_id", "description"),
        valid_example={"ca_id": "CA-1-1", "description": "Authorize request"},
        budget=PromptBudget(context_window=8_000, maximum_completion_tokens=1_000),
    )

    assert audit.ok
    assert len(audit.rendered_prompt_digest) == 64
    assert audit.input_tokens > 0
    assert audit.input_tokens_estimated is True
    assert audit.usable_input_tokens == 5_976


def test_prompt_audit_rejects_prohibited_metadata_and_local_paths() -> None:
    with pytest.raises(PromptContractError, match="digest|path"):
        audit_prompt_contract(
            stage="stage_2",
            prompt_view={"source_digest": "abc123"},
            system_prompt='Return JSON with ca_id. Example: {"ca_id": "CA-1-1"}',
            user_prompt="Read /Users/example/run/control.yaml",
            output_schema=("ca_id",),
            valid_example={"ca_id": "CA-1-1"},
            budget=PromptBudget(context_window=8_000, maximum_completion_tokens=1_000),
        )


def test_prompt_audit_requires_descriptions_for_selectable_ids() -> None:
    with pytest.raises(PromptContractError, match="description"):
        audit_prompt_contract(
            stage="stage_2",
            prompt_view={"target": "CA-1-1"},
            system_prompt='Return JSON with ca_id. Example: {"ca_id": "CA-1-1"}',
            user_prompt="Choose CA-1-1",
            selectable_references={"CA-1-1": ""},
            output_schema=("ca_id",),
            valid_example={"ca_id": "CA-1-1"},
            budget=PromptBudget(context_window=8_000, maximum_completion_tokens=1_000),
        )


def test_prompt_audit_fails_closed_when_input_handles_are_not_accounted_for() -> None:
    with pytest.raises(PromptContractError, match="handle"):
        audit_prompt_contract(
            stage="stage_2",
            prompt_view={"target": "CA-1-1"},
            system_prompt='Return JSON with ca_id. Example: {"ca_id": "CA-1-1"}',
            user_prompt="Copy-only handle: CA-1-1",
            input_handles=("CA-1-1", "CA-1-2"),
            accounted_handles=("CA-1-1",),
            output_schema=("ca_id",),
            valid_example={"ca_id": "CA-1-1"},
            budget=PromptBudget(context_window=8_000, maximum_completion_tokens=1_000),
        )


def test_prompt_audit_requires_an_accounting_set_for_input_handles() -> None:
    with pytest.raises(PromptContractError, match="accounted"):
        audit_prompt_contract(
            stage="stage_2",
            prompt_view={"target": "CA-1-1"},
            system_prompt='Return JSON with ca_id. Example: {"ca_id": "CA-1-1"}',
            user_prompt="Copy-only handle: CA-1-1",
            input_handles=("CA-1-1",),
            output_schema=("ca_id",),
            valid_example={"ca_id": "CA-1-1"},
        )


def test_prompt_audit_rejects_reference_outside_authoritative_slice() -> None:
    with pytest.raises(PromptContractError, match="authoritative"):
        audit_prompt_contract(
            stage="stage_2",
            prompt_view={"target": "CA-9-1"},
            system_prompt='Return JSON with ca_id. Example: {"ca_id": "CA-1-1"}',
            user_prompt="Select a control action.",
            authoritative_references={"CA-1-1": "Authorize request"},
            output_schema=("ca_id",),
            valid_example={"ca_id": "CA-1-1"},
        )


def test_prompt_audit_rejects_oversized_prompt_before_dispatch() -> None:
    with pytest.raises(PromptBudgetExceeded, match="prompt_budget_exceeded") as exc:
        audit_prompt_contract(
            stage="stage_2",
            prompt_view={"target": "CA-1-1"},
            system_prompt='Return JSON with ca_id. Example: {"ca_id": "CA-1-1"}',
            user_prompt="x" * 10_000,
            output_schema=("ca_id",),
            valid_example={"ca_id": "CA-1-1"},
            budget=PromptBudget(
                context_window=1_024,
                maximum_completion_tokens=128,
                safety_margin=128,
                token_counter=lambda value: len(value),
            ),
        )
    assert exc.value.code == "prompt_budget_exceeded"
    assert exc.value.provider_call_allowed is False


def test_prompt_audit_does_not_accept_raw_mapping_payload_as_view_text() -> None:
    raw_mapping = json.dumps({"source": "SC-1", "target": "H-1"})

    with pytest.raises(PromptContractError, match="mapping"):
        audit_prompt_contract(
            stage="stage_2",
            prompt_view={"mapping_json": raw_mapping},
            system_prompt='Return JSON with ca_id. Example: {"ca_id": "CA-1-1"}',
            user_prompt="Choose a route",
            output_schema=("ca_id",),
            valid_example={"ca_id": "CA-1-1"},
            budget=PromptBudget(context_window=8_000, maximum_completion_tokens=1_000),
        )


def test_configured_provider_is_not_called_when_rendered_prompt_exceeds_budget(
    tmp_path,
) -> None:
    class Response(BaseModel):
        value: str

    class Client:
        model = "budget-test"
        context_window = 128
        max_completion_tokens = 64
        safety_margin = 0

        def __init__(self) -> None:
            self.calls = 0

        def complete(self, **kwargs):
            del kwargs
            self.calls += 1
            return LLMResult(
                content={"value": "unexpected"},
                prompt_tokens=0,
                completion_tokens=0,
                duration_ms=0,
            )

    client = Client()
    outcome = call_with_policy(
        llm_client=client,
        system_prompt="contract",
        user_prompt="x" * 1024,
        response_format=Response,
        run_dir=tmp_path,
        stage="budget-stage",
        step="oversized",
        max_completion_tokens=64,
        policy=CorrectionPolicy(),
    )
    value, result, error = outcome.value, outcome.result, outcome.error

    assert value is None
    assert result is None
    assert error is not None and "prompt_budget_exceeded" in error
    assert client.calls == 0

    [record] = read_calls_jsonl(tmp_path)
    assert record["prompt_preflight"] == {
        "rendered_prompt_digest": record["rendered_prompt_digest"],
        "input_tokens": record["preflight_input_tokens"],
        "input_tokens_estimated": True,
        "context_window": 128,
        "maximum_completion_tokens": 64,
        "safety_margin": 0,
        "usable_input_tokens": 64,
        "provider_call_allowed": False,
        "errors": record["prompt_preflight"]["errors"],
    }
    assert record["preflight_input_tokens"] > 64
    assert "prompt_budget_exceeded" in record["prompt_preflight"]["errors"][0]


def test_configured_provider_logs_successful_preflight_budget(tmp_path) -> None:
    class Response(BaseModel):
        value: str

    class Client:
        model = "budget-test"
        context_window = 8_000
        max_completion_tokens = 1_000
        safety_margin = 1_024

        def complete(self, **kwargs):
            return LLMResult(
                content={"value": "ok"},
                prompt_tokens=23,
                completion_tokens=2,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    outcome = call_with_policy(
        llm_client=Client(),
        system_prompt="contract",
        user_prompt="small prompt",
        response_format=Response,
        run_dir=tmp_path,
        stage="budget-stage",
        step="within-budget",
        max_completion_tokens=1_000,
        policy=CorrectionPolicy(),
    )
    value, error = outcome.value, outcome.error

    assert value == Response(value="ok")
    assert error is None
    record = read_calls_jsonl(tmp_path)[0]
    assert record["prompt_preflight"]["provider_call_allowed"] is True
    assert record["prompt_preflight"]["context_window"] == 8_000
    assert record["preflight_input_tokens"] > 0


def _counter(text: str) -> int:
    return len(text.split())


class TestPromptBudgetFromProfile:
    """Budgets resolve from mappings or objects and fail closed when incomplete."""

    def test_mapping_with_normative_names(self) -> None:
        budget = PromptBudget.from_profile(
            {
                "context_window": 16_000,
                "maximum_completion_tokens": 2_000,
                "safety_margin": 500,
            },
            token_counter=_counter,
        )

        assert budget.context_window == 16_000
        assert budget.maximum_completion_tokens == 2_000
        assert budget.safety_margin == 500
        assert budget.token_counter is _counter

    def test_mapping_with_project_spelling_and_default_margin(self) -> None:
        budget = PromptBudget.from_profile(
            {"model_context_window": "8000", "max_completion_tokens": "1000"}
        )

        assert budget.context_window == 8_000
        assert budget.maximum_completion_tokens == 1_000
        assert budget.safety_margin == 1_024
        assert budget.token_counter is None

    def test_object_profile_prefers_normative_names(self) -> None:
        profile = SimpleNamespace(
            context_window=12_000,
            model_context_window=1,
            maximum_completion_tokens=3_000,
            max_completion_tokens=1,
        )

        budget = PromptBudget.from_profile(profile)

        assert budget.context_window == 12_000
        assert budget.maximum_completion_tokens == 3_000

    def test_missing_context_window_fails_closed(self) -> None:
        with pytest.raises(ValueError, match="must declare context_window"):
            PromptBudget.from_profile({"maximum_completion_tokens": 1_000})

    def test_missing_completion_limit_fails_closed(self) -> None:
        with pytest.raises(ValueError, match="maximum_completion_tokens or"):
            PromptBudget.from_profile({"context_window": 8_000})


_SYSTEM = 'Return JSON with ca_id. Example: {"ca_id": "CA-1-1"}'


def _errors(**overrides: Any) -> tuple[str, ...]:
    arguments: dict[str, Any] = {
        "stage": "stage_2",
        "prompt_view": {"target": "CA-1-1"},
        "system_prompt": _SYSTEM,
        "user_prompt": "Choose CA-1-1",
        "output_schema": ("ca_id",),
        "valid_example": {"ca_id": "CA-1-1"},
        "raise_on_error": False,
    }
    arguments.update(overrides)
    return audit_prompt_contract(**arguments).errors


class TestPromptViewContractErrors:
    def test_clean_prompt_has_no_errors(self) -> None:
        assert _errors() == ()

    def test_leaked_prohibited_value_is_reported_with_its_field(self) -> None:
        errors = _errors(
            prompt_view={"source_digest": "abc123"},
            user_prompt="Context abc123 is attached.",
        )

        assert errors == (
            "prohibited prompt-view field leaked: source_digest",
            "prohibited prompt-view value leaked: source_digest",
        )

    def test_custom_prohibited_fields_replace_the_defaults(self) -> None:
        assert (
            _errors(prompt_view={"source_digest": "abc123"}, prohibited_fields=()) == ()
        )
        assert _errors(
            prompt_view={"secret_note": "zzz"}, prohibited_fields=("secret",)
        ) == ("prohibited prompt-view field leaked: secret_note",)

    def test_raw_mapping_json_in_a_mapping_field_is_reported(self) -> None:
        errors = _errors(prompt_view={"raw_json": '{"a": 1}'})

        assert "raw mapping JSON is not allowed in prompt view: raw_json" in errors

    def test_workspace_relative_path_in_rendered_prompt_is_reported(self) -> None:
        errors = _errors(user_prompt="Read ./build/output.yaml for CA-1-1")

        assert errors == ("workspace-relative source path appears in rendered prompt",)

    def test_absolute_path_in_rendered_prompt_is_reported(self) -> None:
        errors = _errors(user_prompt="Read /Users/me/x.yaml for CA-1-1")

        assert errors == ("absolute local path appears in rendered prompt",)


class TestPromptOutputContractErrors:
    def test_schema_fields_missing_from_prompt_are_listed(self) -> None:
        errors = _errors(output_schema=("ca_id", "rationale", "severity"))

        assert errors == (
            "requested output schema is missing field(s): rationale, severity",
        )

    def test_mapping_example_fields_missing_from_prompt_are_listed(self) -> None:
        errors = _errors(valid_example={"ca_id": "CA-1-1", "confidence": 1})

        assert errors == ("valid output example is missing field(s): confidence",)

    def test_text_example_must_appear_in_the_prompt(self) -> None:
        errors = _errors(valid_example="CA-9-9")

        assert errors == ("valid output example is not present in rendered prompt",)

    def test_text_example_present_in_the_prompt_is_accepted(self) -> None:
        assert _errors(valid_example="CA-1-1") == ()

    def test_prompt_without_the_word_example_is_reported(self) -> None:
        errors = _errors(
            system_prompt='Return JSON with ca_id like {"ca_id": "CA-1-1"}'
        )

        assert errors == ("requested output schema must include one valid example",)

    def test_missing_valid_example_skips_the_example_checks(self) -> None:
        assert (
            _errors(valid_example=None, system_prompt="Return JSON with ca_id.") == ()
        )


class _CaModel(BaseModel):
    ca_id: str
    rationale: str


_MISSING_RATIONALE = ("requested output schema is missing field(s): rationale",)


@pytest.mark.parametrize(
    ("output_schema", "expected"),
    [
        (None, ()),
        ({"ca_id": "string", "rationale": "string"}, _MISSING_RATIONALE),
        ("rationale", _MISSING_RATIONALE),
        (_CaModel, _MISSING_RATIONALE),
        (int, ()),
        (frozenset({"ca_id", "rationale"}), _MISSING_RATIONALE),
        (5, ()),
    ],
    ids=["none", "mapping", "text", "model", "plain-type", "iterable", "scalar"],
)
def test_output_schema_field_names_come_from_each_supported_shape(
    output_schema: Any, expected: tuple[str, ...]
) -> None:
    assert _errors(output_schema=output_schema) == expected


@pytest.mark.parametrize(
    ("handles", "expected"),
    [
        (
            {"accounted_handles": ("CA-1-1",)},
            ("accounted handles cannot be supplied without input handles",),
        ),
        (
            {
                "input_handles": ["CA-1-1", "CA-1-1"],
                "accounted_handles": ["CA-1-1", "CA-1-1"],
            },
            ("input handles must be unique", "accounted handles must be unique"),
        ),
        (
            {
                "input_handles": ("CA-1-1", "CA-1-2"),
                "accounted_handles": ("CA-1-1", "CA-1-3"),
            },
            (
                "input handles are not fully accounted for: missing CA-1-2; unexpected CA-1-3",
            ),
        ),
        (
            {"input_handles": ("CA-1-1",), "accounted_handles": ("CA-1-1", "CA-1-3")},
            ("input handles are not fully accounted for: unexpected CA-1-3",),
        ),
        (
            {"input_handles": ("CA-1-1",)},
            ("input handles must be fully accounted for",),
        ),
    ],
    ids=[
        "accounted-only",
        "duplicates",
        "missing-and-unexpected",
        "unexpected",
        "unaccounted",
    ],
)
def test_input_handle_accounting_errors(
    handles: dict[str, Any], expected: tuple[str, ...]
) -> None:
    assert _errors(**handles) == expected


@pytest.mark.parametrize(
    ("selectable", "expected"),
    [
        (None, ()),
        ([("CA-1-1", "Authorize"), ("CA-1-2", 7)], ()),
        (["CA-1-1"], ("selectable ID 'CA-1-1' requires a description",)),
        (
            [("CA-1-1", None), ("CA-1-1", "Authorize")],
            (
                "selectable ID 'CA-1-1' requires a description",
                "selectable references must have unique IDs",
            ),
        ),
        (
            [("CA-1-1",)],
            ("selectable_references must contain (id, description) pairs",),
        ),
        ([5], ("selectable_references must contain (id, description) pairs",)),
    ],
    ids=["none", "pairs", "bare-id", "duplicate", "short-pair", "scalar"],
)
def test_selectable_reference_errors(
    selectable: Any, expected: tuple[str, ...]
) -> None:
    assert _errors(selectable_references=selectable) == expected


_REFERENCE_PAIR_ERROR = (
    "authoritative_references must contain IDs or (id, description) pairs"
)


@pytest.mark.parametrize(
    ("authority", "view", "handles", "expected"),
    [
        ("CA-1-1", {"target": "CA-1-1", "n": 3}, {}, ()),
        (["CA-1-1", ("CA-1-2", "Deny")], {"target": "CA-1-2"}, {}, ()),
        (
            [],
            {"target": "CA-1-1"},
            {"input_handles": ["CA-1-1"], "accounted_handles": ["CA-1-1"]},
            (),
        ),
        (
            [],
            {"target": "CA-1-1 and H-2"},
            {},
            (
                "prompt-view reference 'CA-1-1' is not in the authoritative slice (target)",
                "prompt-view reference 'H-2' is not in the authoritative slice (target)",
            ),
        ),
        (
            {"CA-1-1": ""},
            {"target": '["CA-1-1"]'},
            {},
            ("raw serialized mapping payload is not allowed: target",),
        ),
        ({"CA-1-1": ""}, {"target": "[CA-1-1 is not JSON"}, {}, ()),
        ([5], {"target": "CA-1-1"}, {}, (_REFERENCE_PAIR_ERROR,)),
    ],
    ids=["single-id", "mixed-list", "handle", "unknown", "json", "not-json", "invalid"],
)
def test_reference_contract_errors(
    authority: Any, view: Any, handles: dict[str, Any], expected: tuple[str, ...]
) -> None:
    assert (
        _errors(authoritative_references=authority, prompt_view=view, **handles)
        == expected
    )


def test_prompt_audit_counts_with_a_supplied_tokenizer() -> None:
    audit = audit_prompt_contract(
        stage="stage_2",
        prompt_view={"target": "CA-1-1"},
        system_prompt=_SYSTEM,
        user_prompt="Choose CA-1-1",
        context_window=8_000,
        maximum_completion_tokens=1_000,
        token_counter=_counter,
    )

    assert audit.input_tokens == _counter(f"{_SYSTEM}\nChoose CA-1-1")
    assert audit.input_tokens_estimated is False
    assert (audit.context_window, audit.safety_margin) == (8_000, 1_024)


def test_prompt_audit_rejects_non_text_prompts() -> None:
    with pytest.raises(TypeError, match="must be strings"):
        audit_prompt_contract(
            stage="stage_2", prompt_view={}, system_prompt=None, user_prompt=""
        )


def test_prompt_audit_raises_every_contract_error_together() -> None:
    with pytest.raises(PromptContractError) as exc:
        audit_prompt_contract(
            stage="stage_2",
            prompt_view={"target": "CA-1-1"},
            system_prompt="Return JSON.",
            user_prompt="Choose CA-1-1",
            output_schema=("ca_id",),
            input_handles=("CA-1-1",),
        )

    assert exc.value.errors == (
        "input handles must be fully accounted for",
        "requested output schema is missing field(s): ca_id",
    )


_CONFIGURED = PromptBudget(
    context_window=6_000, maximum_completion_tokens=500, safety_margin=300
)


@pytest.mark.parametrize(
    ("adapter", "controls", "expected"),
    [
        (SimpleNamespace(), SimpleNamespace(), None),
        (
            SimpleNamespace(llm_client=SimpleNamespace(context_window=None)),
            None,
            None,
        ),
        (
            SimpleNamespace(prompt_budget=_CONFIGURED),
            SimpleNamespace(maximum_completion_tokens=200),
            (6_000, 200, 300),
        ),
        (
            SimpleNamespace(
                llm_client=SimpleNamespace(model_context_window="4096", safety_margin=7)
            ),
            None,
            (4_096, 800, 7),
        ),
        (
            SimpleNamespace(
                prompt_budget=_CONFIGURED,
                llm_client=SimpleNamespace(context_window=1, safety_margin=1),
            ),
            SimpleNamespace(context_window=9_000, safety_margin=11),
            (9_000, 800, 11),
        ),
        (
            SimpleNamespace(llm_client=SimpleNamespace(context_window=10_000)),
            SimpleNamespace(maximum_completion_tokens=None),
            (10_000, 800, 1_024),
        ),
    ],
    ids=[
        "nothing",
        "client-without-window",
        "configured",
        "client",
        "controls",
        "default-margin",
    ],
)
def test_adapter_prompt_budget_resolution_precedence(
    adapter: Any, controls: Any, expected: tuple[int, int, int] | None
) -> None:
    budget = resolve_adapter_prompt_budget(
        adapter, controls, maximum_completion_tokens=800
    )

    if expected is None:
        assert budget is None
    else:
        assert budget is not None
        assert (
            budget.context_window,
            budget.maximum_completion_tokens,
            budget.safety_margin,
        ) == expected
