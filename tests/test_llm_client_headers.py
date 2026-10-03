"""Tests for LLMClient extra_headers and OpenRouter auto-detection."""

from __future__ import annotations

import json
from unittest.mock import patch

from asago_scenario_generator.llm.client import LLMClient


class TestExtraHeadersConstructor:
    """Explicit dict passed via constructor is stored on self.extra_headers."""

    def test_explicit_headers_stored(self):
        headers = {"X-Custom": "value1", "Authorization": "Bearer tok"}
        client = LLMClient(base_url="http://fake", api_key="k", extra_headers=headers)
        assert client.extra_headers == headers

    def test_single_header(self):
        client = LLMClient(
            base_url="http://fake", api_key="k", extra_headers={"X-Foo": "bar"}
        )
        assert client.extra_headers == {"X-Foo": "bar"}


class TestExtraHeadersEnvVar:
    """ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS JSON env var is parsed correctly."""

    def test_env_var_parsed(self):
        env_headers = {"HTTP-Referer": "https://example.com", "X-Title": "my-app"}
        with patch.dict(
            "os.environ",
            {"ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS": json.dumps(env_headers)},
        ):
            client = LLMClient(base_url="http://fake", api_key="k")
        assert client.extra_headers == env_headers

    def test_constructor_overrides_env_var(self):
        env_headers = {"X-Foo": "from-env"}
        explicit_headers = {"X-Foo": "from-constructor"}
        with patch.dict(
            "os.environ",
            {"ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS": json.dumps(env_headers)},
        ):
            client = LLMClient(
                base_url="http://fake", api_key="k", extra_headers=explicit_headers
            )
        assert client.extra_headers["X-Foo"] == "from-constructor"

    def test_env_and_constructor_merge(self):
        env_headers = {"X-Env": "env-val"}
        explicit_headers = {"X-Explicit": "explicit-val"}
        with patch.dict(
            "os.environ",
            {"ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS": json.dumps(env_headers)},
        ):
            client = LLMClient(
                base_url="http://fake", api_key="k", extra_headers=explicit_headers
            )
        assert client.extra_headers == {
            "X-Env": "env-val",
            "X-Explicit": "explicit-val",
        }


class TestOpenRouterAutoDetection:
    """When base_url contains openrouter.ai, default headers are auto-injected."""

    def test_auto_injects_defaults(self):
        client = LLMClient(base_url="https://openrouter.ai/api/v1", api_key="k")
        assert client.extra_headers is not None
        assert (
            client.extra_headers["HTTP-Referer"]
            == "https://github.com/asago-ai/asago-scenario-generator"
        )
        assert client.extra_headers["X-Title"] == "asago-scenario-generator"

    def test_auto_detection_with_subdomain(self):
        client = LLMClient(base_url="https://api.openrouter.ai/v1", api_key="k")
        assert client.extra_headers is not None
        assert "HTTP-Referer" in client.extra_headers
        assert "X-Title" in client.extra_headers

    def test_auto_detection_via_env_base_url(self):
        with patch.dict(
            "os.environ",
            {"ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL": "https://openrouter.ai/api/v1"},
        ):
            client = LLMClient(api_key="k")
        assert client.extra_headers is not None
        assert (
            client.extra_headers["HTTP-Referer"]
            == "https://github.com/asago-ai/asago-scenario-generator"
        )


class TestOpenRouterExplicitOverride:
    """Explicit extra_headers override auto-detected OpenRouter defaults."""

    def test_explicit_referer_overrides_default(self):
        client = LLMClient(
            base_url="https://openrouter.ai/api/v1",
            api_key="k",
            extra_headers={"HTTP-Referer": "https://custom.example.com"},
        )
        assert client.extra_headers["HTTP-Referer"] == "https://custom.example.com"
        # X-Title should still be auto-injected
        assert client.extra_headers["X-Title"] == "asago-scenario-generator"

    def test_explicit_title_overrides_default(self):
        client = LLMClient(
            base_url="https://openrouter.ai/api/v1",
            api_key="k",
            extra_headers={"X-Title": "my-custom-title"},
        )
        assert client.extra_headers["X-Title"] == "my-custom-title"
        # HTTP-Referer should still be auto-injected
        assert (
            client.extra_headers["HTTP-Referer"]
            == "https://github.com/asago-ai/asago-scenario-generator"
        )

    def test_env_var_overrides_openrouter_defaults(self):
        env_headers = {"HTTP-Referer": "https://env-override.example.com"}
        with patch.dict(
            "os.environ",
            {"ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS": json.dumps(env_headers)},
        ):
            client = LLMClient(base_url="https://openrouter.ai/api/v1", api_key="k")
        assert (
            client.extra_headers["HTTP-Referer"] == "https://env-override.example.com"
        )
        assert client.extra_headers["X-Title"] == "asago-scenario-generator"

    def test_explicit_overrides_both_env_and_auto(self):
        env_headers = {"HTTP-Referer": "https://env.example.com"}
        explicit_headers = {"HTTP-Referer": "https://explicit.example.com"}
        with patch.dict(
            "os.environ",
            {"ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS": json.dumps(env_headers)},
        ):
            client = LLMClient(
                base_url="https://openrouter.ai/api/v1",
                api_key="k",
                extra_headers=explicit_headers,
            )
        assert client.extra_headers["HTTP-Referer"] == "https://explicit.example.com"


class TestNoHeadersDefault:
    """When no headers specified and base_url is not OpenRouter, extra_headers is None."""

    def test_no_headers_is_none(self):
        client = LLMClient(base_url="http://fake", api_key="k")
        assert client.extra_headers is None

    def test_non_openrouter_url_no_auto_headers(self):
        client = LLMClient(base_url="https://api.together.xyz/v1", api_key="k")
        assert client.extra_headers is None

    def test_empty_env_var_no_headers(self):
        """Empty env var should not produce headers."""
        import os

        os.environ.pop("ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS", None)
        client = LLMClient(base_url="http://fake", api_key="k")
        assert client.extra_headers is None
