"""Property tests for model-config precedence and secret-safe public controls.

These properties pin the CLI → profile → environment → default chain,
boolean literal parsing, and the rule that public controls never leak
secrets. They are offline and never contact an LLM endpoint.
"""

from __future__ import annotations

import json
from pathlib import Path

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.pipeline.model_configuration import (
    ConfigSource,
    _bool,
    _bool_string_value,
    _choose,
    _config_from_values,
    _headers,
)

_MAX_EXAMPLES = 60
_TRUE_LITERALS = ("true", "1", "yes")
_FALSE_LITERALS = ("false", "0", "no")
_FIELD_NAMES = st.from_regex(r"[A-Za-z][A-Za-z0-9_]{0,11}", fullmatch=True)
_VALUES = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-._",
    min_size=1,
    max_size=16,
)
_SECRETS = st.from_regex(r"secret-[A-Za-z0-9]{4,12}", fullmatch=True)
_HEADER_KEYS = st.from_regex(r"[A-Za-z][A-Za-z0-9-]{0,11}", fullmatch=True)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    explicit=st.one_of(st.none(), _VALUES),
    profile_value=st.one_of(st.none(), _VALUES),
    env_value=st.one_of(st.none(), st.just(""), _VALUES),
    default=_VALUES,
    field=_FIELD_NAMES,
    env_field=_FIELD_NAMES,
)
def test_choose_follows_cli_profile_env_default_precedence(
    explicit: str | None,
    profile_value: str | None,
    env_value: str | None,
    default: str,
    field: str,
    env_field: str,
) -> None:
    """CLI wins, then a present profile value, then a non-empty env, then default."""
    profile = {field: profile_value} if profile_value is not None else {}
    environ = {env_field: env_value} if env_value is not None else {}
    value, source = _choose(explicit, profile, field, environ, env_field, default)
    if explicit is not None:
        assert (value, source) == (explicit, ConfigSource.cli)
    elif profile_value is not None:
        assert (value, source) == (profile_value, ConfigSource.profile)
    elif env_value not in (None, ""):
        assert (value, source) == (env_value, ConfigSource.environment)
    else:
        assert (value, source) == (default, ConfigSource.application_default)
    assert _choose(explicit, profile, field, environ, env_field, default) == (
        value,
        source,
    )


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    literal=st.sampled_from(_TRUE_LITERALS + _FALSE_LITERALS),
    prefix=st.sampled_from(("", " ", "\t")),
    casing=st.sampled_from(("lower", "upper", "title")),
)
def test_known_bool_literals_are_case_insensitive(
    literal: str, prefix: str, casing: str
) -> None:
    """Known boolean strings parse the same regardless of case."""
    transformed = getattr(literal, casing)()
    expected = literal in _TRUE_LITERALS
    assert _bool_string_value(transformed) is expected
    assert _bool(transformed, "field") is expected
    if prefix:
        assert _bool_string_value(prefix + transformed) is None


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    model=_VALUES,
    api_key=_SECRETS,
    headers=st.dictionaries(_HEADER_KEYS, _SECRETS, max_size=3),
)
def test_public_controls_omit_secrets(
    model: str, api_key: str, headers: dict[str, str]
) -> None:
    """Manifest-safe controls never include the API key or header values."""
    values = {
        "model": model,
        "base_url": None,
        "api_key": api_key,
        "max_completion_tokens": None,
        "temperature": 0.4,
        "timeout": None,
        "top_p": None,
        "top_k": None,
        "use_guided_decoding": False,
        "headers": headers or None,
    }
    sources = {field: ConfigSource.cli for field in values}
    config = _config_from_values(values, sources, None, Path("unused.yaml"))
    public = config.public_controls()
    encoded = json.dumps(public, sort_keys=True)
    assert "api_key" not in public
    assert api_key not in encoded
    assert public["header_names"] == sorted(headers)
    for secret in headers.values():
        assert secret not in encoded
    assert dict(config.extra_headers or {}) == headers
    if headers:
        assert dict(_headers(headers) or {}) == headers
