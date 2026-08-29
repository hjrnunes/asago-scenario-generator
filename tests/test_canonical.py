"""Public tests for neutral canonical serialization helpers."""

from __future__ import annotations

from asago_scenario_generator.models.canonical import canonical_json_text


def test_canonical_json_text_preserves_diagnostic_json_contract() -> None:
    """Pretty canonical JSON remains sorted, UTF-8-readable, and newline-ended."""
    assert canonical_json_text({"zeta": "café", "alpha": [1, 2]}) == (
        '{\n  "alpha": [\n    1,\n    2\n  ],\n  "zeta": "café"\n}\n'
    )
