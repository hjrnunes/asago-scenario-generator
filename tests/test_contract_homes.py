"""Contracts live in the module that owns them.

Each row names a module and the public names it must define. A row can also
name modules that must not define the same classes (a contract that moved out
of an algorithm module must not grow back there).
"""

from __future__ import annotations

import ast
import importlib
import inspect
from dataclasses import dataclass
from pathlib import Path

import pytest

PACKAGE = "asago_scenario_generator"


@dataclass(frozen=True)
class Home:
    module: str
    names: tuple[str, ...]
    not_defined_in: tuple[str, ...] = ()


HOMES = [
    Home(
        f"{PACKAGE}.models.attack_pattern_digests",
        ("_canonical_json", "compute_chain_semantic_digest"),
    ),
    Home(
        f"{PACKAGE}.pipeline.projection_contracts",
        ("ProjectedCandidate", "CapabilityFactSnapshot"),
    ),
    Home(
        f"{PACKAGE}.models.threat_scope",
        ("ThreatScope", "ThreatScopeEntry", "OutOfScopeEntry"),
        not_defined_in=(f"{PACKAGE}.data.threat_gating",),
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


@pytest.mark.parametrize(
    "home", [pytest.param(h, id=h.module) for h in HOMES if h.not_defined_in]
)
def test_algorithm_modules_do_not_redefine_the_contracts(home: Home) -> None:
    for other in home.not_defined_in:
        path = Path(importlib.import_module(other).__file__)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        defined = {n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
        assert not defined & set(home.names), (
            f"{other} defines {defined & set(home.names)}"
        )
