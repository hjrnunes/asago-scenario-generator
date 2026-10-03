"""Tests for LLMClient temperature/sampling control."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from asago_scenario_generator.llm.client import LLMClient


class TestTemperatureDefault:
    """Temperature defaults to 0.4 when no override is provided."""

    def test_default_temperature(self):
        with patch.dict("os.environ", {}, clear=False):
            # Remove env var if present
            import os

            os.environ.pop("ASAGO_SCENARIO_GENERATOR_TEMPERATURE", None)
            client = LLMClient(base_url="http://fake", api_key="k")
        assert client.temperature == 0.4

    def test_default_matches_class_constant(self):
        assert LLMClient.DEFAULT_TEMPERATURE == 0.4


class TestTemperatureConstructor:
    """Temperature can be set via the constructor."""

    def test_constructor_overrides_default(self):
        client = LLMClient(base_url="http://fake", api_key="k", temperature=0.9)
        assert client.temperature == 0.9

    def test_constructor_zero_is_valid(self):
        client = LLMClient(base_url="http://fake", api_key="k", temperature=0.0)
        assert client.temperature == 0.0


class TestTemperatureEnvVar:
    """Temperature can be set via ASAGO_SCENARIO_GENERATOR_TEMPERATURE env var."""

    def test_env_var_sets_temperature(self):
        with patch.dict("os.environ", {"ASAGO_SCENARIO_GENERATOR_TEMPERATURE": "0.7"}):
            client = LLMClient(base_url="http://fake", api_key="k")
        assert client.temperature == 0.7

    def test_constructor_overrides_env_var(self):
        with patch.dict("os.environ", {"ASAGO_SCENARIO_GENERATOR_TEMPERATURE": "0.7"}):
            client = LLMClient(base_url="http://fake", api_key="k", temperature=0.2)
        assert client.temperature == 0.2


class TestTemperaturePassedToAPI:
    """Temperature is forwarded to the underlying OpenAI SDK calls."""

    def _make_client(self, temperature: float | None = None) -> LLMClient:
        client = LLMClient(base_url="http://fake", api_key="k", temperature=temperature)
        client._client = MagicMock()
        return client

    def _mock_response(self):
        resp = MagicMock()
        resp.choices = [MagicMock()]
        resp.choices[0].message.content = "hello"
        resp.choices[0].message.parsed = None
        resp.usage.prompt_tokens = 10
        resp.usage.completion_tokens = 5
        return resp

    def test_default_temp_in_create_call(self):
        client = self._make_client()
        client._client.chat.completions.create.return_value = self._mock_response()

        client.complete(system_prompt="sys", user_prompt="usr")

        call_kwargs = client._client.chat.completions.create.call_args
        assert call_kwargs.kwargs["temperature"] == 0.4

    def test_constructor_temp_in_create_call(self):
        client = self._make_client(temperature=0.8)
        client._client.chat.completions.create.return_value = self._mock_response()

        client.complete(system_prompt="sys", user_prompt="usr")

        call_kwargs = client._client.chat.completions.create.call_args
        assert call_kwargs.kwargs["temperature"] == 0.8

    def test_per_call_temp_overrides_client_default(self):
        client = self._make_client(temperature=0.8)
        client._client.chat.completions.create.return_value = self._mock_response()

        client.complete(system_prompt="sys", user_prompt="usr", temperature=0.1)

        call_kwargs = client._client.chat.completions.create.call_args
        assert call_kwargs.kwargs["temperature"] == 0.1

    def test_per_call_zero_overrides_client_default(self):
        """temperature=0.0 per-call should not fall back to client default."""
        client = self._make_client(temperature=0.8)
        client._client.chat.completions.create.return_value = self._mock_response()

        client.complete(system_prompt="sys", user_prompt="usr", temperature=0.0)

        call_kwargs = client._client.chat.completions.create.call_args
        assert call_kwargs.kwargs["temperature"] == 0.0

    def test_temp_in_structured_parse_call(self):
        from pydantic import BaseModel

        class Dummy(BaseModel):
            value: str

        client = self._make_client(temperature=0.6)
        resp = self._mock_response()
        resp.choices[0].message.parsed = Dummy(value="x")
        client._client.beta.chat.completions.parse.return_value = resp

        client.complete(system_prompt="sys", user_prompt="usr", response_format=Dummy)

        call_kwargs = client._client.beta.chat.completions.parse.call_args
        assert call_kwargs.kwargs["temperature"] == 0.6
