"""Focused unit tests for the decomposed model configuration helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from asago_scenario_generator.pipeline.model_configuration import (
    ConfigSource,
    EffectiveModelConfig,
    _bool,
    _bool_string_value,
    _choose,
    _config_from_values,
    _has_env_value,
    _is_string_string_mapping,
    _optional_float,
    _optional_float_value,
    _optional_int,
    _optional_str,
    _profile_value,
    _resolution_specs,
    _resolve_values,
)


class TestBoolParsing:
    """Boolean coercion through _bool_string_value and _bool."""

    @pytest.mark.parametrize("literal", ["true", "True", "TRUE", "1", "yes", "YES"])
    def test_bool_string_value_true_literals(self, literal: str) -> None:
        assert _bool_string_value(literal) is True

    @pytest.mark.parametrize("literal", ["false", "False", "FALSE", "0", "no", "NO"])
    def test_bool_string_value_false_literals(self, literal: str) -> None:
        assert _bool_string_value(literal) is False

    def test_bool_string_value_none_for_non_string(self) -> None:
        assert _bool_string_value(1) is None
        assert _bool_string_value(True) is None

    def test_bool_string_value_none_for_unknown_string(self) -> None:
        assert _bool_string_value("maybe") is None

    def test_bool_passes_real_bools_through(self) -> None:
        assert _bool(True, "field") is True
        assert _bool(False, "field") is False

    @pytest.mark.parametrize("literal", ["true", "yes", "1", "false", "no", "0"])
    def test_bool_parses_string_literals(self, literal: str) -> None:
        assert isinstance(_bool(literal, "field"), bool)

    def test_bool_raises_for_unknown_string(self) -> None:
        with pytest.raises(ValueError, match="field must be a boolean"):
            _bool("maybe", "field")

    def test_bool_raises_for_other_types(self) -> None:
        with pytest.raises(ValueError, match="field must be a boolean"):
            _bool(1, "field")


class TestProfileAndEnvLookups:
    """Profile-field and environment-value presence checks."""

    def test_profile_value_returns_present_value(self) -> None:
        assert _profile_value({"model": "m"}, "model") == "m"

    def test_profile_value_none_when_key_absent(self) -> None:
        assert _profile_value({"model": "m"}, "missing") is None

    def test_profile_value_returns_none_value(self) -> None:
        assert _profile_value({"model": None}, "model") is None

    def test_has_env_value_true_for_non_empty(self) -> None:
        assert _has_env_value({"KEY": "v"}, "KEY") is True

    def test_has_env_value_false_when_empty(self) -> None:
        assert _has_env_value({"KEY": ""}, "KEY") is False

    def test_has_env_value_false_when_absent(self) -> None:
        assert _has_env_value({}, "KEY") is False


class TestChoose:
    """The CLI → profile → env → default precedence chain."""

    def test_explicit_wins(self) -> None:
        value, source = _choose("cli", {"f": "profile"}, "f", {"E": "env"}, "E", "d")
        assert (value, source) == ("cli", ConfigSource.cli)

    def test_profile_beats_environment(self) -> None:
        value, source = _choose(None, {"f": "profile"}, "f", {"E": "env"}, "E", "d")
        assert (value, source) == ("profile", ConfigSource.profile)

    def test_environment_beats_default(self) -> None:
        value, source = _choose(None, {}, "f", {"E": "env"}, "E", "d")
        assert (value, source) == ("env", ConfigSource.environment)

    def test_application_default_last(self) -> None:
        value, source = _choose(None, {}, "f", {}, "E", "d")
        assert (value, source) == ("d", ConfigSource.application_default)


class TestMappingChecks:
    """String-to-string mapping validation."""

    def test_is_string_string_mapping_true(self) -> None:
        assert _is_string_string_mapping({"A": "b"}) is True

    def test_is_string_string_mapping_false_for_non_mapping(self) -> None:
        assert _is_string_string_mapping(["A"]) is False
        assert _is_string_string_mapping("A") is False

    def test_is_string_string_mapping_false_for_non_string_key(self) -> None:
        assert _is_string_string_mapping({1: "b"}) is False

    def test_is_string_string_mapping_false_for_non_string_value(self) -> None:
        assert _is_string_string_mapping({"A": 1}) is False


class TestResolutionSpecs:
    """The per-field resolution table."""

    def test_resolution_specs_cover_all_fields(self) -> None:
        specs = _resolution_specs(
            None, None, None, None, None, None, None, None, None, None
        )
        assert set(specs) == {
            "base_url",
            "api_key",
            "model",
            "max_completion_tokens",
            "temperature",
            "timeout",
            "top_p",
            "top_k",
            "use_guided_decoding",
            "headers",
        }

    def test_resolution_specs_carry_env_names(self) -> None:
        specs = _resolution_specs(
            None, None, None, None, None, None, None, None, None, None
        )
        assert specs["model"][1] == "ASAGO_SCENARIO_GENERATOR_MODEL_NAME"
        assert specs["api_key"][2] == "unused"
        assert specs["temperature"][2] == 0.4


class TestResolveValues:
    """Resolving the full field set through the precedence chain."""

    def test_resolve_values_applies_chain_per_field(self) -> None:
        specs = {
            "a": ("explicit", "ENV_A", "default-a"),
            "b": (None, "ENV_B", "default-b"),
            "c": (None, "ENV_C", "default-c"),
        }
        values, sources = _resolve_values(specs, {"b": "profile-b"}, {"ENV_C": "env-c"})
        assert values == {"a": "explicit", "b": "profile-b", "c": "env-c"}
        assert sources == {
            "a": ConfigSource.cli,
            "b": ConfigSource.profile,
            "c": ConfigSource.environment,
        }


class TestConfigFromValues:
    """Building the effective config with type coercion."""

    def test_config_from_values_coerces_types(self) -> None:
        values = {
            "model": "m",
            "base_url": "http://x",
            "api_key": "k",
            "max_completion_tokens": "100",
            "temperature": "0.3",
            "timeout": "60.0",
            "top_p": "0.9",
            "top_k": "40",
            "use_guided_decoding": "true",
            "headers": None,
        }
        sources = {field: ConfigSource.cli for field in values}
        config = _config_from_values(values, sources, "profile", Path("p.yaml"))
        assert isinstance(config, EffectiveModelConfig)
        assert config.model == "m"
        assert config.max_completion_tokens == 100
        assert config.temperature == 0.3
        assert config.timeout == 60.0
        assert config.top_p == 0.9
        assert config.top_k == 40
        assert config.use_guided_decoding is True
        assert config.profile_name == "profile"
        assert config.profiles_file == Path("p.yaml")

    def test_config_from_values_tolerates_none_optional(self) -> None:
        values = {
            "model": "m",
            "base_url": None,
            "api_key": "k",
            "max_completion_tokens": None,
            "temperature": 0.4,
            "timeout": None,
            "top_p": None,
            "top_k": None,
            "use_guided_decoding": False,
            "headers": None,
        }
        sources = {field: ConfigSource.application_default for field in values}
        config = _config_from_values(values, sources, None, Path("p.yaml"))
        assert config.base_url is None
        assert config.max_completion_tokens is None
        assert config.timeout is None
        assert config.top_p is None
        assert config.top_k is None
        assert config.profile_name is None
        assert config.profiles_file is None


class TestOptionalCoercions:
    """Small optional-value coercions."""

    @pytest.mark.parametrize(
        ("coercer", "value", "expected"),
        [(_optional_int, "10", 10), (_optional_float, "0.5", 0.5)],
    )
    def test_positive_values_are_coerced(self, coercer, value, expected) -> None:
        assert coercer(value, "field") == expected

    @pytest.mark.parametrize("coercer", [_optional_int, _optional_float])
    def test_none_remains_none(self, coercer) -> None:
        assert coercer(None, "field") is None

    @pytest.mark.parametrize("value", [0, -1])
    def test_non_positive_values_are_rejected(self, value) -> None:
        with pytest.raises(ValueError, match="field must be positive"):
            _optional_int(value, "field")

    def test_optional_str(self) -> None:
        assert _optional_str("v") == "v"
        assert _optional_str(None) is None

    def test_optional_float_value(self) -> None:
        assert _optional_float_value("0.5") == 0.5
        assert _optional_float_value(None) is None
