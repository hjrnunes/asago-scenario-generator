"""Property tests for attack-tree YAML transport sanitization.

These properties pin ``_sanitize_yaml_colons`` in
``pipeline.generate.tree_transport``: already-quoted or colon-free values
stay put, and sanitization is idempotent. They are offline and never
contact an LLM endpoint.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.pipeline.generate.tree_transport import (
    _sanitize_yaml_colons,
)

_MAX_EXAMPLES = 60
_KEYS = st.from_regex(r"[A-Za-z_][A-Za-z0-9_]{0,11}", fullmatch=True)
_VALUES = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P", "Zs"),
        blacklist_characters="\n\r\"'",
    ),
    min_size=1,
    max_size=24,
).filter(lambda value: value == value.strip())


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(key=_KEYS, value=_VALUES)
def test_yaml_colon_sanitization_is_idempotent(key: str, value: str) -> None:
    """Unquoted values with colons are quoted once; other lines stay put."""
    raw = f"{key}: {value}"
    sanitized = _sanitize_yaml_colons(raw)
    assert _sanitize_yaml_colons(sanitized) == sanitized
    if ":" in value:
        assert sanitized == f'{key}: "{value}"'
    else:
        assert sanitized == raw
