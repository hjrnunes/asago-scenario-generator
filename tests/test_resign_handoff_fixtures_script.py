"""The script that signs the report fixtures' handoffs under the current contract."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "resign_handoff_fixtures.py"


def _script() -> ModuleType:
    name = "resign_handoff_fixtures_script"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, _SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def test_the_report_fixtures_are_signed_under_the_current_contract() -> None:
    assert _script().main(["--check"]) == 0


def test_check_names_a_fixture_the_writer_would_change_and_write_restores_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    script = _script()
    root = tmp_path / "generate_report"
    shutil.copytree(script.FIXTURES / "miniklarna-1", root / "miniklarna-1")
    handoff = root / "miniklarna-1" / "scenarios" / "SCN-001.yaml"
    signed = handoff.read_text(encoding="utf-8")
    handoff.write_text(
        signed.replace("content_digest: ", "content_digest: f", 1), encoding="utf-8"
    )

    assert script.main(["--check", "--root", str(root)]) == 1
    assert f"differs: {handoff}" in capsys.readouterr().out
    assert script.main(["--write", "--root", str(root)]) == 0
    assert handoff.read_text(encoding="utf-8") == signed
    assert script.main(["--check", "--root", str(root)]) == 0


def test_an_empty_fixture_root_fails(tmp_path: Path) -> None:
    assert _script().main(["--check", "--root", str(tmp_path)]) == 1
