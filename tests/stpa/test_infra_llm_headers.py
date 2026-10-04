"""Header merging and telemetry conversion for the STPA infra LLM client."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from hypothesis import given, settings, strategies as st
from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm import LLMClient, _plain_value

_EXTRA_HEADERS_ENV = "ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS"
_BASE_URL_ENV = "ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL"
_OPENROUTER = "https://openrouter.ai/api/v1"
_DEFAULT_REFERER = "https://github.com/asago-ai/asago-scenario-generator"
_DEFAULT_TITLE = "asago-scenario-generator"


@pytest.fixture(autouse=True)
def _clean_header_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_EXTRA_HEADERS_ENV, raising=False)
    monkeypatch.delenv(_BASE_URL_ENV, raising=False)


def _client(**kwargs) -> LLMClient:
    kwargs.setdefault("base_url", "http://fake")
    return LLMClient(api_key="k", **kwargs)


class TestExtraHeadersSources:
    """Constructor and environment headers merge, constructor winning."""

    def test_explicit_headers_stored(self) -> None:
        headers = {"X-Custom": "value1", "Authorization": "Bearer tok"}
        assert _client(extra_headers=headers).extra_headers == headers

    def test_env_var_parsed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        env_headers = {"HTTP-Referer": "https://example.com", "X-Title": "my-app"}
        monkeypatch.setenv(_EXTRA_HEADERS_ENV, json.dumps(env_headers))
        assert _client().extra_headers == env_headers

    def test_constructor_overrides_env_var(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_EXTRA_HEADERS_ENV, json.dumps({"X-Foo": "from-env"}))
        client = _client(extra_headers={"X-Foo": "from-constructor"})
        assert client.extra_headers == {"X-Foo": "from-constructor"}

    def test_env_and_constructor_merge(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(_EXTRA_HEADERS_ENV, json.dumps({"X-Env": "env-val"}))
        client = _client(extra_headers={"X-Explicit": "explicit-val"})
        assert client.extra_headers == {
            "X-Env": "env-val",
            "X-Explicit": "explicit-val",
        }


class TestOpenRouterHeaders:
    """OpenRouter defaults fill gaps and never override supplied headers."""

    def test_defaults_injected(self) -> None:
        client = _client(base_url=_OPENROUTER)
        assert client.extra_headers == {
            "HTTP-Referer": _DEFAULT_REFERER,
            "X-Title": _DEFAULT_TITLE,
        }

    def test_defaults_injected_for_subdomain(self) -> None:
        client = _client(base_url="https://api.openrouter.ai/v1")
        assert client.extra_headers is not None
        assert {"HTTP-Referer", "X-Title"} <= set(client.extra_headers)

    def test_defaults_injected_from_env_base_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(_BASE_URL_ENV, _OPENROUTER)
        client = LLMClient(api_key="k")
        assert client.extra_headers is not None
        assert client.extra_headers["HTTP-Referer"] == _DEFAULT_REFERER

    def test_explicit_referer_keeps_default_title(self) -> None:
        client = _client(
            base_url=_OPENROUTER,
            extra_headers={"HTTP-Referer": "https://custom.example.com"},
        )
        assert client.extra_headers == {
            "HTTP-Referer": "https://custom.example.com",
            "X-Title": _DEFAULT_TITLE,
        }

    def test_explicit_title_keeps_default_referer(self) -> None:
        client = _client(
            base_url=_OPENROUTER, extra_headers={"X-Title": "my-custom-title"}
        )
        assert client.extra_headers == {
            "HTTP-Referer": _DEFAULT_REFERER,
            "X-Title": "my-custom-title",
        }

    def test_env_overrides_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            _EXTRA_HEADERS_ENV,
            json.dumps({"HTTP-Referer": "https://env-override.example.com"}),
        )
        client = _client(base_url=_OPENROUTER)
        assert client.extra_headers == {
            "HTTP-Referer": "https://env-override.example.com",
            "X-Title": _DEFAULT_TITLE,
        }

    def test_explicit_overrides_env_and_defaults(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(
            _EXTRA_HEADERS_ENV,
            json.dumps({"HTTP-Referer": "https://env.example.com"}),
        )
        client = _client(
            base_url=_OPENROUTER,
            extra_headers={"HTTP-Referer": "https://explicit.example.com"},
        )
        assert client.extra_headers is not None
        assert client.extra_headers["HTTP-Referer"] == "https://explicit.example.com"


class TestNoHeadersByDefault:
    """Without supplied headers or an OpenRouter URL, no headers are sent."""

    @pytest.mark.parametrize("base_url", ["http://fake", "https://api.together.xyz/v1"])
    def test_extra_headers_is_none(self, base_url: str) -> None:
        assert _client(base_url=base_url).extra_headers is None


_MAX_EXAMPLES = 60
_TEXT = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789 -._", min_size=0, max_size=24
)
_JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1000, max_value=1000),
    st.floats(min_value=-1000, max_value=1000, allow_nan=False, allow_infinity=False),
    _TEXT,
)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(value=_JSON_SCALARS)
def test_plain_value_leaves_json_scalars_unchanged(value: object) -> None:
    """JSON scalars remain themselves after telemetry conversion."""
    assert _plain_value(value) == value
    json.dumps(_plain_value(value))


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    items=st.lists(_JSON_SCALARS, max_size=5),
    mapping=st.dictionaries(
        st.integers(min_value=0, max_value=20), _JSON_SCALARS, max_size=4
    ),
    public=_TEXT,
    private=_TEXT,
)
def test_plain_value_is_json_serializable_and_drops_private_attrs(
    items: list[object],
    mapping: dict[int, object],
    public: str,
    private: str,
) -> None:
    """Containers become JSON data; private object attributes stay hidden."""
    obj = SimpleNamespace(public=public, _private=private)
    converted = _plain_value({"items": items, "map": mapping, "obj": obj})
    json.dumps(converted, sort_keys=True)
    assert converted["items"] == items
    assert converted["map"] == {str(key): item for key, item in mapping.items()}
    assert converted["obj"] == {"public": public}


def test_plain_value_dumps_models_and_stringifies_opaque_values() -> None:
    """Models become JSON data; values without attributes become text."""

    class Usage(BaseModel):
        total_tokens: int

    assert _plain_value([Usage(total_tokens=3), complex(1, 2)]) == [
        {"total_tokens": 3},
        "(1+2j)",
    ]
