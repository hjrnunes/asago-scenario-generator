"""Property-based tests for model profile loading.

These tests verify invariants that should hold across broad input ranges:

- **Profile round-trip**: Any valid profile dict, when written to YAML and
  loaded back, returns the same key-value pairs.
- **Required field conservation**: The result always contains all required
  fields that were present in the source.
- **Optional field omission**: Optional fields absent from the source are
  absent from the result; optional fields present are preserved.

Rejection of empty, missing and unknown values runs from the ``model-profile``
contract in ``test_model_profile_contract.py``.
"""

from __future__ import annotations


import yaml
from hypothesis import HealthCheck, given, settings, strategies as st

from asago_scenario_generator.model_profiles import (
    OPTIONAL_FIELDS,
    REQUIRED_FIELDS,
    load_profile,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

st_nonempty_str = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc")),
    min_size=1,
    max_size=50,
)

st_profile_name = st.from_regex(r"[a-z][a-z0-9_-]*", fullmatch=True)

st_optional_field_values = st.fixed_dictionaries(
    {},
    optional={
        "context_window": st.integers(min_value=1, max_value=1_000_000),
        "safety_margin": st.integers(min_value=0, max_value=100_000),
        "max_completion_tokens": st.integers(min_value=1, max_value=100000),
        "temperature": st.floats(min_value=0.0, max_value=2.0, allow_nan=False),
        "top_p": st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
        "top_k": st.integers(min_value=1, max_value=100),
        "headers": st.dictionaries(
            st_nonempty_str.filter(lambda name: name.strip()),
            st_nonempty_str,
            max_size=3,
        ),
    },
)


def _build_profile_dict(optionals: dict) -> dict:
    """Build a complete profile dict with fixed required fields + optionals."""
    profile = {
        "base_url": "https://example.com/v1",
        "model": "test-model",
        "api_key": "test-key",
    }
    profile.update(optionals)
    return profile


# ---------------------------------------------------------------------------
# Profile round-trip property tests
# ---------------------------------------------------------------------------


class TestProfileRoundTrip:
    """Any valid profile round-trips through YAML without loss."""

    @given(
        profile_name=st_profile_name,
        optionals=st_optional_field_values,
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_profile_round_trip(self, tmp_path, profile_name, optionals):
        """A valid profile written to YAML and loaded back returns identical values."""
        profile = _build_profile_dict(optionals)
        path = tmp_path / "profiles.yaml"
        path.write_text(
            yaml.dump({profile_name: profile}, default_flow_style=False),
            encoding="utf-8",
        )
        result = load_profile(path, profile_name)

        for field in REQUIRED_FIELDS:
            assert result[field] == profile[field], f"Required field '{field}' mismatch"

        for field in OPTIONAL_FIELDS:
            if field in optionals:
                assert result[field] == optionals[field], (
                    f"Optional field '{field}' mismatch"
                )
            else:
                assert field not in result, f"Optional field '{field}' should be absent"


# ---------------------------------------------------------------------------
# Required field conservation property tests
# ---------------------------------------------------------------------------


class TestRequiredFieldConservation:
    """The result always contains exactly the required fields from the source."""

    @given(profile_name=st_profile_name)
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_required_fields_always_present(self, tmp_path, profile_name):
        """All required fields are always in the loaded profile."""
        profile = _build_profile_dict({})
        path = tmp_path / "profiles.yaml"
        path.write_text(
            yaml.dump({profile_name: profile}, default_flow_style=False),
            encoding="utf-8",
        )
        result = load_profile(path, profile_name)
        for field in REQUIRED_FIELDS:
            assert field in result, f"Required field '{field}' missing from result"


# ---------------------------------------------------------------------------
# Empty required field rejection property tests
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Unknown profile name rejection property tests
# ---------------------------------------------------------------------------
