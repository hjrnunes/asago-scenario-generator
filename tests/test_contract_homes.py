"""Contracts live in the module that owns them.

Each row names a module and the public names it must define.
"""

from __future__ import annotations

import importlib
import inspect
from dataclasses import dataclass

import pytest

PACKAGE = "asago_scenario_generator"


@dataclass(frozen=True)
class Home:
    module: str
    names: tuple[str, ...]


HOMES = [
    Home(
        f"{PACKAGE}.models.attack_pattern_digests",
        ("_canonical_json", "compute_chain_semantic_digest"),
    ),
    Home(
        f"{PACKAGE}.pipeline.projection_contracts",
        ("ProjectedCandidate", "CapabilityFactSnapshot"),
    ),
]


@pytest.mark.parametrize("home", [pytest.param(h, id=h.module) for h in HOMES])
def test_module_defines_its_contracts(home: Home) -> None:
    module = importlib.import_module(home.module)
    for name in home.names:
        member = getattr(module, name)
        assert member is not None
        if inspect.isclass(member):
            assert member.__module__ == home.module, f"{name} is defined elsewhere"
