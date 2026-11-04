"""The old package path still reaches the target-discovery scanner.

The scanner moved into the ``asago-target-discovery`` workspace member
(``asago_target_discovery``). ``asago_scenario_generator.target_discovery``
keeps the package-root names importable for one cycle; M9 removes it. New code
imports ``asago_target_discovery`` only.
"""

from __future__ import annotations

import importlib

import pytest

import asago_target_discovery

LEGACY = "asago_scenario_generator.target_discovery"


def test_the_legacy_path_lists_the_same_names() -> None:
    legacy = importlib.import_module(LEGACY)

    assert sorted(legacy.__all__) == sorted(asago_target_discovery.__all__)


@pytest.mark.parametrize("name", sorted(asago_target_discovery.__all__))
def test_the_legacy_path_reaches_the_same_object(name: str) -> None:
    legacy = importlib.import_module(LEGACY)

    assert getattr(legacy, name) is getattr(asago_target_discovery, name)


def test_the_legacy_path_is_not_the_implementation() -> None:
    legacy = importlib.import_module(LEGACY)

    assert legacy is not asago_target_discovery
