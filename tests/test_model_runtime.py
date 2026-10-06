"""One synthesis run resolves its model client once."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from asago_scenario_generator.pipeline.model_runtime import (
    ANALYSIS_DEADLINE_SECONDS,
    ANALYSIS_MAX_BATCH_SIZE,
    ModelRuntime,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)

_RESOLVER = "asago_scenario_generator.stpa.pipeline.llm_config.resolve_llm_client"


def _client(**fields: object) -> SimpleNamespace:
    return SimpleNamespace(model="model-x", temperature=0.2, **fields)


def test_the_client_is_resolved_once_on_first_use(monkeypatch) -> None:
    client = _client()
    resolutions: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        _RESOLVER, lambda *args: resolutions.append(args) or (client, "named")
    )
    runtime = ModelRuntime.for_inputs(
        SimpleNamespace(profile="named", profiles_file=Path("profiles.yaml"))
    )

    assert resolutions == []
    assert runtime.client is client
    assert runtime.profile_name == "named"
    assert runtime.temperature() == 0.2
    assert runtime.client is client
    assert resolutions == [("named", "profiles.yaml")]


def test_a_failed_resolution_is_retried_by_the_next_use(monkeypatch) -> None:
    attempts: list[object] = []

    def fail(*args: object) -> None:
        attempts.append(args)
        raise ValueError("No LLM endpoint configured.")

    monkeypatch.setattr(_RESOLVER, fail)
    runtime = ModelRuntime(profile=None, profiles_file="profiles.yaml")

    for _ in range(2):
        with pytest.raises(ValueError, match="No LLM endpoint"):
            runtime.client
    assert len(attempts) == 2


@pytest.mark.parametrize(
    ("profile_name", "expected"), [("named", "named"), (None, "environment")]
)
def test_obligation_adapter_uses_the_run_client_and_analysis_controls(
    monkeypatch, tmp_path, profile_name, expected
) -> None:
    client = _client()
    monkeypatch.setattr(_RESOLVER, lambda *args: (client, profile_name))
    runtime = ModelRuntime(profile=profile_name, profiles_file="profiles.yaml")

    adapter = runtime.obligation_adapter(tmp_path / "run")

    assert isinstance(adapter, ObligationAwareLLMAdapter)
    assert adapter.llm_client is client
    assert adapter.run_dir == tmp_path / "run"
    assert adapter.controls.model_profile == expected
    assert adapter.controls.model_name == "model-x"
    assert adapter.controls.temperature == 0.2
    assert adapter.controls.deadline_seconds == ANALYSIS_DEADLINE_SECONDS
    assert adapter.controls.max_batch_size == ANALYSIS_MAX_BATCH_SIZE
