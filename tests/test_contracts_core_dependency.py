"""Every package that imports the shared contracts core declares it by name.

``stpa/scenario_prod/handoff.py`` reads the handoff contract, the installed spec set
and the envelope writer from ``asago_contracts_core``. A package that imports it must
name it in ``project.dependencies`` with a version range, so the package installs it
directly instead of relying on another dependency's resolution; the editable path
stays in ``[tool.uv.sources]``. The core itself is the one package that does not
declare itself.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE = "asago-contracts-core"
CORE_RANGE = ">=0.1,<0.2"
PYPROJECTS = (
    ROOT / "pyproject.toml",
    *sorted((ROOT / "packages").glob("*/pyproject.toml")),
)


def _document(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _requirement_name(requirement: str) -> str:
    return re.split(r"[<>=!~;\[]", requirement, maxsplit=1)[0].strip().lower()


def _declared(document: dict) -> dict[str, str]:
    """Return the package's requirements by name, across every dependency group."""
    project = document.get("project", {})
    groups = [project.get("dependencies", [])]
    groups.extend(project.get("optional-dependencies", {}).values())
    groups.extend(document.get("dependency-groups", {}).values())
    return {
        _requirement_name(requirement): requirement
        for group in groups
        for requirement in group
    }


def _imports_core(path: Path) -> bool:
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            if any(
                alias.name.split(".")[0] == "asago_contracts_core"
                for alias in node.names
            ):
                return True
        elif (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and (node.module or "").split(".")[0] == "asago_contracts_core"
        ):
            return True
    return False


def _core_users(package: Path) -> list[Path]:
    sources = package / "src"
    if not sources.is_dir():
        return []
    return [path for path in sorted(sources.rglob("*.py")) if _imports_core(path)]


def test_the_app_depends_on_the_contracts_core_by_name_with_a_range() -> None:
    document = _document(ROOT / "pyproject.toml")

    assert _declared(document)[CORE] == f"{CORE}{CORE_RANGE}"
    assert document["tool"]["uv"]["sources"][CORE] == {"workspace": True}


def test_every_package_that_imports_the_contracts_core_declares_it() -> None:
    missing: list[str] = []
    for path in PYPROJECTS:
        document = _document(path)
        package = path.parent
        if document["project"]["name"] == CORE:
            continue
        users = _core_users(package)
        if not users:
            continue
        requirement = _declared(document).get(CORE, "")
        if ">=" not in requirement or "<" not in requirement:
            names = ", ".join(str(user.relative_to(package)) for user in users)
            missing.append(f"{package.name} (imports in {names})")

    assert missing == []


def test_the_scan_finds_the_app_import() -> None:
    users = _core_users(ROOT)

    assert any(user.name == "handoff.py" for user in users)
