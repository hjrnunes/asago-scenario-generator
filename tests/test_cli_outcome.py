from __future__ import annotations

import pytest

from asago_scenario_generator.cli import _default_generate_exit_code


@pytest.mark.parametrize(
    ("status", "admitted", "expected"),
    [
        ("completed", 2, 0),
        ("completed_with_errors", 1, 1),
        ("completed", 0, 1),
    ],
)
def test_default_generate_exit_policy(
    status: str, admitted: int, expected: int
) -> None:
    assert _default_generate_exit_code(status, admitted) == expected
