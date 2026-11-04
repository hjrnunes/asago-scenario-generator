"""report_kit: the old app path re-exports the ``asago-report-kit`` member."""

from __future__ import annotations

import tomllib
from pathlib import Path

import asago_report_kit as member
from asago_scenario_generator import report_kit as old

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "src" / "asago_scenario_generator" / "report"
OLD_DIR = ROOT / "src" / "asago_scenario_generator" / "report_kit"
OLD_IMPORT = "from asago_scenario_generator.report_kit import"
MEMBER_IMPORT = "from asago_report_kit import"


def test_the_old_path_re_exports_the_whole_member() -> None:
    assert list(old.__all__) == list(member.__all__)
    for name in member.__all__:
        assert getattr(old, name) is getattr(member, name), name


def test_the_producer_depends_on_the_member_by_name_with_a_range() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert "asago-report-kit>=0.1,<0.2" in project["project"]["dependencies"]
    assert project["tool"]["uv"]["sources"]["asago-report-kit"] == {"workspace": True}


def test_the_report_package_imports_the_member_not_the_old_path() -> None:
    offenders: list[str] = []
    users: list[str] = []
    for path in sorted(REPORT.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        if OLD_IMPORT in text:
            offenders.append(path.name)
        if MEMBER_IMPORT in text:
            users.append(path.name)

    assert offenders == []
    assert users


def test_the_old_directory_carries_no_kit_copy() -> None:
    assert {path.name for path in OLD_DIR.iterdir() if path.is_file()} == {
        "__init__.py"
    }
