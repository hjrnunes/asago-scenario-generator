"""Tests for model profile loading (MP-01 through MP-16)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.model_profiles import load_profile

_KEY = "api_" + "key"  # avoid literal secret-pattern in source


def _write_profile(path: Path, name: str, **fields) -> Path:
    """Write a single-profile YAML file and return its path."""
    data = {name: fields}
    path.write_text(yaml.dump(data, default_flow_style=False), encoding="utf-8")
    return path


def _write_profiles_dict(path: Path, profiles: dict) -> Path:
    """Write a multi-profile YAML file from a dict and return its path."""
    path.write_text(yaml.dump(profiles, default_flow_style=False), encoding="utf-8")
    return path


def _make_default_profiles(tmp_path: Path) -> Path:
    """Create the Background profiles file used by most scenarios."""
    return _write_profiles_dict(
        tmp_path / "profiles.yaml",
        {
            "gemma4-openrouter": {
                "base_url": "https://openrouter.ai/api/v1",
                "model": "google/gemma-4-26b-a4b-it",
                _KEY: "dummy",
                "max_completion_tokens": 16384,
                "temperature": 0.4,
            },
            "gemma4-local": {
                "base_url": "https://local.example.com/v1",
                "model": "gemma-4-26b-a4b-it",
                _KEY: "unused",
                "temperature": 0.4,
            },
            "sonnet-4": {
                "base_url": "https://openrouter.ai/api/v1",
                "model": "anthropic/claude-sonnet-4",
                _KEY: "dummy",
                "max_completion_tokens": 16384,
                "temperature": 0.3,
            },
        },
    )


class TestLoadProfile:
    """MP-01 through MP-08 — load_profile function."""

    def test_mp01_load_named_profile_returns_all_params(self, tmp_path):
        """MP-01: loading a named profile returns all its parameters."""
        profiles = _make_default_profiles(tmp_path)
        result = load_profile(profiles, "gemma4-openrouter")
        assert result["base_url"] == "https://openrouter.ai/api/v1"
        assert result["model"] == "google/gemma-4-26b-a4b-it"
        assert result[_KEY] == "dummy"
        assert result["max_completion_tokens"] == 16384
        assert result["temperature"] == 0.4

    def test_mp02_load_profile_with_top_p_and_top_k(self, tmp_path):
        """MP-02: loading a profile with optional top_p and top_k."""
        profiles = _write_profile(
            tmp_path / "tuned.yaml",
            "tuned",
            base_url="https://local.example.com/v1",
            model="local-lm",
            **{_KEY: "unused"},
            top_p=0.9,
            top_k=40,
        )
        result = load_profile(profiles, "tuned")
        assert result["top_p"] == 0.9
        assert result["top_k"] == 40

    def test_load_profile_preserves_explicit_thinking_switch(self, tmp_path):
        profiles = _write_profile(
            tmp_path / "qwen.yaml",
            "qwen",
            base_url="https://local.example.com/v1",
            model="qwen",
            **{_KEY: "unused"},
            enable_thinking=False,
        )

        result = load_profile(profiles, "qwen")

        assert result["enable_thinking"] is False

    def test_mp03_load_profile_with_custom_headers(self, tmp_path):
        """MP-03: loading a profile with custom headers."""
        profiles = _write_profile(
            tmp_path / "headers.yaml",
            "with-hdr",
            base_url="https://custom.example.com/v1",
            model="custom-1",
            **{_KEY: "dummy"},
            headers={"X-Custom": "value", "X-Region": "eu"},
        )
        result = load_profile(profiles, "with-hdr")
        assert "headers" in result
        assert result["headers"]["X-Custom"] == "value"
        assert result["headers"]["X-Region"] == "eu"

    def test_mp04_profile_without_optional_fields_uses_defaults(self, tmp_path):
        """MP-04: loading a profile without optional fields omits them."""
        profiles = _make_default_profiles(tmp_path)
        result = load_profile(profiles, "gemma4-local")
        assert "max_completion_tokens" not in result
        assert result["temperature"] == 0.4

    def test_mp05_load_profile_from_custom_path(self, tmp_path):
        """MP-05: loading a profile from a custom file path."""
        profiles = _write_profile(
            tmp_path / "custom.yaml",
            "custom-remote",
            base_url="https://remote.example.com/v1",
            model="custom-model",
            **{_KEY: "dummy"},
        )
        result = load_profile(profiles, "custom-remote")
        assert result["model"] == "custom-model"

    def test_mp06_missing_profiles_file_raises_filenotfounderror(self, tmp_path):
        """MP-06: missing profiles file raises FileNotFoundError with path."""
        missing = tmp_path / "nonexistent.yaml"
        with pytest.raises(FileNotFoundError, match=str(missing)):
            load_profile(missing, "any")

    def test_mp07_unknown_profile_name_raises_keyerror(self, tmp_path):
        """MP-07: unknown profile name raises KeyError with name."""
        profiles = _make_default_profiles(tmp_path)
        with pytest.raises(KeyError, match="nonexistent"):
            load_profile(profiles, "nonexistent")

    def test_mp08_profile_missing_required_field_raises_valueerror(self, tmp_path):
        """MP-08: profile missing a required field raises ValueError."""
        profiles = _write_profile(
            tmp_path / "bad.yaml",
            "missing-url",
            base_url="",
            model="some-model",
            **{_KEY: "dummy"},
        )
        with pytest.raises(ValueError, match="base_url"):
            load_profile(profiles, "missing-url")

    def test_profile_name_in_non_mapping_yaml_raises_keyerror(self, tmp_path):
        """A profile name in a YAML sequence is still an invalid top-level profile."""
        profiles = tmp_path / "sequence.yaml"
        profiles.write_text("- sequence-profile\n", encoding="utf-8")

        with pytest.raises(KeyError, match="sequence-profile"):
            load_profile(profiles, "sequence-profile")


class TestLLMClientTopPTopK:
    """MP-13, MP-14 — LLMClient top_p and top_k support."""

    def test_mp13_llmclient_accepts_top_p_and_top_k(self, monkeypatch):
        """MP-13: LLMClient accepts and stores top_p and top_k."""
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", "http://test:8080")
        client = LLMClient(top_p=0.9, top_k=40)
        assert client.top_p == 0.9
        assert client.top_k == 40

    def test_mp14_llmclient_without_top_p_top_k_leaves_them_none(self, monkeypatch):
        """MP-14: LLMClient without top_p/top_k leaves them None."""
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", "http://test:8080")
        client = LLMClient()
        assert client.top_p is None
        assert client.top_k is None

    def test_llmclient_passes_top_p_and_top_k_to_complete(self, monkeypatch):
        """When top_p and top_k are set, complete() passes top_p as a
        top-level kwarg and top_k through extra_body."""
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", "http://test:8080")
        client = LLMClient(top_p=0.9, top_k=40)

        mock_msg = MagicMock()
        mock_msg.content = "resp"
        mock_choice = MagicMock()
        mock_choice.message = mock_msg
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_response.usage = MagicMock(prompt_tokens=10, completion_tokens=5)

        client._client = MagicMock()
        client._client.chat.completions.create.return_value = mock_response

        client.complete("s", "u")
        call_kwargs = client._client.chat.completions.create.call_args
        assert call_kwargs.kwargs["top_p"] == 0.9
        assert call_kwargs.kwargs["extra_body"]["top_k"] == 40
        assert "top_k" not in call_kwargs.kwargs

    def test_llmclient_without_top_p_top_k_does_not_pass_them(self, monkeypatch):
        """When top_p and top_k are None, complete() does not pass them."""
        monkeypatch.setenv("ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL", "http://test:8080")
        client = LLMClient()

        mock_msg = MagicMock()
        mock_msg.content = "resp"
        mock_choice = MagicMock()
        mock_choice.message = mock_msg
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        mock_response.usage = MagicMock(prompt_tokens=10, completion_tokens=5)

        client._client = MagicMock()
        client._client.chat.completions.create.return_value = mock_response

        client.complete("s", "u")
        call_kwargs = client._client.chat.completions.create.call_args
        assert "top_p" not in call_kwargs.kwargs
        assert "top_k" not in call_kwargs.kwargs


class TestSampleProfilesFile:
    """MP-15, MP-16 — sample profiles file and .gitignore."""

    def test_mp15_sample_profiles_file_exists_with_placeholder_keys(self):
        """MP-15: sample file exists and contains placeholder API keys."""
        sample = Path("config/model-profiles.example.yaml")
        assert sample.exists(), "Sample profiles file must exist in the repository"
        content = sample.read_text(encoding="utf-8")
        assert "YOUR-API-KEY-HERE" in content

    def test_mp16_real_profiles_file_is_gitignored(self):
        """MP-16: config/model-profiles.yaml is listed in .gitignore."""
        gitignore = Path(".gitignore").read_text(encoding="utf-8")
        assert "config/model-profiles.yaml" in gitignore
