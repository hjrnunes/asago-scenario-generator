"""asago-report-kit: one package, its data inside it, one declared surface."""

from __future__ import annotations

import ast
import json
import sys
import tomllib
from pathlib import Path

import asago_report_kit as kit

MEMBER = Path(__file__).resolve().parents[1]
PACKAGE = MEMBER / "src" / "asago_report_kit"
DATA = (
    "catalog.html",
    "kit.css",
    "kit.js",
    "stage-summary-v1.schema.json",
)


def _tree() -> ast.Module:
    return ast.parse((PACKAGE / "__init__.py").read_text(encoding="utf-8"))


def _defined_names() -> set[str]:
    names: set[str] = set()
    for node in _tree().body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return {name for name in names if not name.startswith("_")}


def test_the_member_declares_itself() -> None:
    project = tomllib.loads((MEMBER / "pyproject.toml").read_text(encoding="utf-8"))

    assert project["project"]["name"] == "asago-report-kit"
    assert project["project"]["version"] == "0.1.0"
    assert project["project"]["requires-python"] == ">=3.12"
    assert project["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == [
        "src/asago_report_kit"
    ]


def test_the_kit_ships_every_file_it_reads_inside_the_package() -> None:
    assert {path.name for path in PACKAGE.iterdir() if path.is_file()} == {
        "__init__.py",
        *DATA,
    }


def test_the_module_declares_every_public_definition() -> None:
    assert set(kit.__all__) == _defined_names()
    for name in kit.__all__:
        assert hasattr(kit, name), name


def test_the_stylesheet_and_script_are_the_packaged_files() -> None:
    assert kit.stylesheet() == (PACKAGE / "kit.css").read_text(encoding="utf-8")
    assert kit.script() == (PACKAGE / "kit.js").read_text(encoding="utf-8")


def test_the_summary_schema_is_the_packaged_file() -> None:
    schema = kit.stage_summary_schema()

    assert schema == PACKAGE / "stage-summary-v1.schema.json"
    document = json.loads(schema.read_text(encoding="utf-8"))
    assert document["$id"] == "stage-summary-v1.schema.json"
    assert (
        document["properties"]["schema_version"]["const"] == kit.STAGE_SUMMARY_VERSION
    )


def test_the_catalog_matches_its_golden_file() -> None:
    golden = (PACKAGE / "catalog.html").read_text(encoding="utf-8")

    assert golden == kit.render_catalog(), (
        "catalog.html is stale; regenerate it with "
        '`uv run python -c "from asago_report_kit import write_catalog; '
        'write_catalog()"`'
    )


def test_the_kit_imports_only_the_standard_library() -> None:
    modules: set[str] = set()
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            modules.add(node.module.split(".")[0])

    assert modules <= set(sys.stdlib_module_names), sorted(
        modules - set(sys.stdlib_module_names)
    )
