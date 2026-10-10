"""The optional ``repetition_penalty`` profile field.

A profile that sets the field sends it in ``extra_body`` next to the other
body entries. A profile that omits it keeps its request unchanged.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml
from pydantic import BaseModel

from asago_scenario_generator.model_profiles import load_profile
from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.pipeline.llm_config import (
    resolve_llm_client_from_profile,
)

_BASE: dict[str, Any] = {
    "base_url": "http://test.invalid/v1",
    "model": "m",
    "api_key": "k",
}


def _write(path: Path, profiles: dict[str, dict[str, Any]]) -> Path:
    path.write_text(yaml.safe_dump(profiles), encoding="utf-8")
    return path


def _client(tmp_path: Path, **fields: Any) -> LLMClient:
    profiles = _write(tmp_path / "profiles.yaml", {"p": {**_BASE, **fields}})
    with patch("asago_scenario_generator.stpa.infra.llm.OpenAI"):
        client, _ = resolve_llm_client_from_profile(str(profiles), "p")
    client._client = MagicMock()
    return client


class _Reply:
    def __init__(self, content: str) -> None:
        message = type("M", (), {"content": content})()
        self.choices = [type("C", (), {"message": message, "finish_reason": "stop"})()]
        self.usage = type("U", (), {"prompt_tokens": 1, "completion_tokens": 1})()


class _Out(BaseModel):
    val: int = 0


def _sent(client: LLMClient, *, structured: bool) -> dict[str, Any]:
    create = client._client.chat.completions.create
    create.return_value = _Reply('{"val": 1}')
    client.complete("s", "u", response_format=_Out if structured else None)
    return create.call_args.kwargs


class TestPenaltySet:
    def test_extra_body_holds_penalty_next_to_the_other_keys(self, tmp_path):
        client = _client(
            tmp_path,
            top_k=64,
            enable_thinking=False,
            repetition_penalty=1.05,
        )
        assert client._build_extra_kwargs(2048, 0.7)["extra_body"] == {
            "top_k": 64,
            "chat_template_kwargs": {"enable_thinking": False},
            "repetition_penalty": 1.05,
        }

    @pytest.mark.parametrize("structured", [True, False])
    def test_complete_sends_the_penalty_in_extra_body(self, tmp_path, structured):
        client = _client(tmp_path, top_k=20, repetition_penalty=1.05)
        sent = _sent(client, structured=structured)
        assert sent["extra_body"] == {"top_k": 20, "repetition_penalty": 1.05}
        assert "repetition_penalty" not in sent

    def test_penalty_alone_forms_the_extra_body(self, tmp_path):
        client = _client(tmp_path, repetition_penalty=1.1)
        assert client._build_extra_kwargs(None, 0.3) == {
            "temperature": 0.3,
            "extra_body": {"repetition_penalty": 1.1},
        }

    def test_integer_penalty_is_accepted(self, tmp_path):
        client = _client(tmp_path, repetition_penalty=2)
        assert client._build_extra_kwargs(None, 0.3)["extra_body"] == {
            "repetition_penalty": 2
        }

    def test_sampling_controls_false_omits_the_penalty(self, tmp_path):
        client = _client(tmp_path, repetition_penalty=1.05, sampling_controls=False)
        assert client._build_extra_kwargs(512, 0.3) == {"max_completion_tokens": 512}


class TestPenaltyAbsent:
    def test_full_kwargs_equal_the_pre_field_request(self, tmp_path):
        client = _client(tmp_path, top_k=64, top_p=0.9, enable_thinking=True)
        assert client._build_extra_kwargs(2048, 0.7) == {
            "temperature": 0.7,
            "top_p": 0.9,
            "max_completion_tokens": 2048,
            "extra_body": {
                "top_k": 64,
                "chat_template_kwargs": {"enable_thinking": True},
            },
        }

    def test_bare_profile_sends_no_extra_body(self, tmp_path):
        client = _client(tmp_path)
        assert client._build_extra_kwargs(2048, 0.7) == {
            "temperature": 0.7,
            "max_completion_tokens": 2048,
        }

    def test_complete_request_is_unchanged(self, tmp_path):
        client = _client(tmp_path, top_k=64)
        sent = _sent(client, structured=False)
        assert sent["extra_body"] == {"top_k": 64}


class TestBadValues:
    @pytest.mark.parametrize("value", [0, 0.0, -1, -0.5, "1.05", "high", True, [1.05]])
    def test_value_outside_a_positive_number_is_rejected(self, tmp_path, value):
        profiles = _write(
            tmp_path / "bad.yaml", {"p": {**_BASE, "repetition_penalty": value}}
        )
        with patch("asago_scenario_generator.stpa.infra.llm.OpenAI"):
            with pytest.raises(ValueError, match="repetition_penalty must"):
                resolve_llm_client_from_profile(str(profiles), "p")

    def test_null_means_absent(self, tmp_path):
        client = _client(tmp_path, repetition_penalty=None)
        assert "extra_body" not in client._build_extra_kwargs(None, 0.3)


class TestFrozenProfileFile:
    """A file that gains a penalty profile still loads for the other profiles."""

    def test_profile_without_the_field_loads_beside_one_with_it(self, tmp_path):
        profiles = _write(
            tmp_path / "two.yaml",
            {
                "gemma": {**_BASE, "top_k": 64},
                "glm": {**_BASE, "repetition_penalty": 1.05},
            },
        )
        assert load_profile(profiles, "gemma") == {**_BASE, "top_k": 64}
        with patch("asago_scenario_generator.stpa.infra.llm.OpenAI"):
            client, name = resolve_llm_client_from_profile(str(profiles), "gemma")
        assert name == "gemma"
        assert client._build_extra_kwargs(None, 0.3)["extra_body"] == {"top_k": 64}
