"""Unit contracts for live-LLM acceptance opt-in and isolation."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
sys.path.insert(0, str(ROOT / "acceptance"))

from acceptance_runtime import execute_ir  # noqa: E402
from live_llm_opt_in import LIVE_LLM_SKIP_REASON  # noqa: E402


LIVE_MARKER = 'live LLM acceptance is enabled with ASAGO_SCENARIO_GENERATOR_QA_PIPELINE "1"'
LIVE_STEP = "acceptance fixture live step"


@pytest.fixture
def live_fixture_state():
    """Give the shared live fixture step an isolated observation record."""
    from runtime_features import acceptance_live_opt_in

    state = acceptance_live_opt_in._empty_fixture_state()
    acceptance_live_opt_in._FIXTURE_STATE_STACK.append(state)
    try:
        yield state
    finally:
        acceptance_live_opt_in._FIXTURE_STATE_STACK.pop()


def _write_ir(tmp_path: Path, scenarios: list[dict]) -> Path:
    ir_path = tmp_path / "fixture.json"
    ir_path.write_text(
        json.dumps(
            {
                "name": "Live opt-in fixture",
                "background": [],
                "scenarios": scenarios,
            }
        ),
        encoding="utf-8",
    )
    return ir_path


def _scenario(name: str, *steps: str) -> dict:
    return {
        "name": name,
        "steps": [{"keyword": "Given", "text": step} for step in steps],
        "examples": [],
    }


def test_default_execution_skips_marked_scenario_even_with_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE", raising=False)
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", "http://127.0.0.1:9/v1")

    passed, output = execute_ir(
        str(
            _write_ir(
                tmp_path,
                [
                    _scenario("deterministic"),
                    _scenario("live", LIVE_MARKER),
                ],
            )
        )
    )

    assert passed
    assert "PASS deterministic/example_1" in output
    assert f"SKIP live/example_1: {LIVE_LLM_SKIP_REASON}" in output
    assert "FAIL live/example_1" not in output


@pytest.mark.parametrize("value", ["0", "true", "yes"])
def test_only_exact_one_authorizes_marked_scenario(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE", value)

    passed, output = execute_ir(
        str(_write_ir(tmp_path, [_scenario("live", LIVE_MARKER)]))
    )

    assert passed
    assert "SKIP live/example_1" in output
    assert "PASS live/example_1" not in output


def test_opt_in_without_endpoint_attempts_and_fails_visibly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    live_fixture_state: dict,
) -> None:
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE", "1")
    for name in (
        "ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL",
        "OPENAI_BASE_URL",
        "OPENAI_API_KEY",
        "ASAGO_SCENARIO_GENERATOR_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    passed, output = execute_ir(
        str(
            _write_ir(
                tmp_path,
                [_scenario("live", LIVE_MARKER, LIVE_STEP)],
            )
        )
    )

    assert not passed
    assert "SKIP live/example_1" not in output
    assert "FAIL live/example_1" in output
    assert "LLM endpoint not configured" in output


def test_scenario_environment_does_not_leak_fake_endpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    live_fixture_state: dict,
) -> None:
    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE", "1")
    for name in (
        "ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL",
        "OPENAI_BASE_URL",
        "OPENAI_API_KEY",
        "ASAGO_SCENARIO_GENERATOR_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    ir_path = _write_ir(
        tmp_path,
        [
            _scenario(
                "configures endpoint",
                "environment variable ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL "
                "is set to http://fake.example/v1",
            ),
            _scenario("live", LIVE_MARKER, LIVE_STEP),
        ],
    )

    passed, output = execute_ir(str(ir_path))

    assert not passed
    assert "PASS configures endpoint/example_1" in output
    assert "LLM endpoint not configured" in output
    assert "http://fake.example/v1" not in os.environ.values()


def test_background_marker_skips_every_scenario_without_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE", raising=False)
    ir_path = tmp_path / "background.json"
    ir_path.write_text(
        json.dumps(
            {
                "name": "Background marker",
                "background": [{"keyword": "Given", "text": LIVE_MARKER}],
                "scenarios": [
                    _scenario("first"),
                    _scenario("second"),
                ],
            }
        ),
        encoding="utf-8",
    )

    passed, output = execute_ir(str(ir_path))

    assert passed
    assert f"SKIP first/example_1: {LIVE_LLM_SKIP_REASON}" in output
    assert f"SKIP second/example_1: {LIVE_LLM_SKIP_REASON}" in output
    assert "PASS" not in output


def test_casefold_marker_is_recognized_and_nearby_wording_is_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE", raising=False)
    passed, output = execute_ir(
        str(
            _write_ir(
                tmp_path,
                [
                    _scenario("cased", LIVE_MARKER.upper()),
                    _scenario(
                        "nearby",
                        f"{LIVE_MARKER} extra wording",
                    ),
                ],
            )
        )
    )

    assert not passed
    assert f"SKIP cased/example_1: {LIVE_LLM_SKIP_REASON}" in output
    assert "SKIP nearby/example_1" not in output
    assert "FAIL nearby/example_1: Unsupported step" in output


def test_nested_execute_ir_restores_feature_tag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import acceptance_runtime

    monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE", "1")
    monkeypatch.setattr(acceptance_runtime, "_CURRENT_EXECUTION_FEATURE", "outer")
    try:
        passed, _output = execute_ir(
            str(_write_ir(tmp_path, [_scenario("inner")]))
        )
        assert passed
        assert acceptance_runtime._CURRENT_EXECUTION_FEATURE == "outer"
    finally:
        acceptance_runtime._CURRENT_EXECUTION_FEATURE = None
