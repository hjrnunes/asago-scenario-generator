"""The producer depends on no consumer package.

The dependency runs one way: the consumer resolves this checkout by path. A requirement,
a locked package or an import that names a consumer distribution would make the producer
need the consumer to install or to test.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECTS = (
    ROOT / "pyproject.toml",
    *sorted((ROOT / "packages").glob("*/pyproject.toml")),
)
SOURCES = (
    ROOT / "src",
    ROOT / "tests",
    ROOT / "scripts",
    *sorted((ROOT / "packages").glob("*/src")),
    *sorted((ROOT / "packages").glob("*/tests")),
)

# The distributions the consumer repository publishes, and the modules they install.
CONSUMER_DISTRIBUTIONS = frozenset(
    {
        "asago-artifact-generator",
        "asago-bundle-core",
        "asago-bundle-garak",
        "asago-injection-spec",
        "asago-package",
    }
)
CONSUMER_MODULES = frozenset(name.replace("-", "_") for name in CONSUMER_DISTRIBUTIONS)


def _distribution(requirement: str) -> str:
    match = re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", requirement)
    assert match, requirement
    return re.sub(r"[-_.]+", "-", match.group()).lower()


def _requirements(pyproject: Path) -> list[str]:
    project = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    declared = list(project.get("project", {}).get("dependencies", []))
    for extra in project.get("project", {}).get("optional-dependencies", {}).values():
        declared.extend(extra)
    for group in project.get("dependency-groups", {}).values():
        declared.extend(item for item in group if isinstance(item, str))
    return declared


def _imported_modules(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules.add(node.module.split(".")[0])
    return modules


def test_no_declared_requirement_names_a_consumer_distribution() -> None:
    named = {
        f"{pyproject.relative_to(ROOT)}: {requirement}"
        for pyproject in PYPROJECTS
        for requirement in _requirements(pyproject)
        if _distribution(requirement) in CONSUMER_DISTRIBUTIONS
    }

    assert named == set()


def test_the_lock_resolves_no_consumer_distribution() -> None:
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    locked = {_distribution(package["name"]) for package in lock["package"]}

    assert locked & CONSUMER_DISTRIBUTIONS == set()


def test_no_source_or_test_imports_a_consumer_module() -> None:
    importing = {
        str(path.relative_to(ROOT))
        for source in SOURCES
        for path in sorted(source.rglob("*.py"))
        if _imported_modules(path) & CONSUMER_MODULES
    }

    assert importing == set()
