"""Unit contracts for scripts/check_acceptance_hygiene.py."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = next(
    path
    for path in Path(__file__).resolve().parents
    if (path / "pyproject.toml").is_file()
)
_SPEC = importlib.util.spec_from_file_location(
    "check_acceptance_hygiene", ROOT / "scripts" / "check_acceptance_hygiene.py"
)
assert _SPEC is not None and _SPEC.loader is not None
hygiene = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(hygiene)

_ENV = """\
SWARMFORGE_CRAP_CMD="crap4py src/ --lcov lcov.info --max-crap 6"
SWARMFORGE_DRY_CMD="drywall --threshold 0.82 ./src"
SWARMFORGE_MUTATION_CMD="mutate4py src/ --since-last-run"
"""

_WORKFLOW = """\
jobs:
  unit:
    name: Python
    steps:
      - run: ./scripts/quality.sh
      - run: uv run pytest tests/ -q

  acceptance:
    steps:
      - uses: actions/checkout@v7
        with:
          repository: unclebob/Acceptance-Pipeline-Specification
      - uses: DeLaGuardo/setup-clojure@v13
      - run: ./scripts/acceptance.sh
"""


def test_quality_script_runs_the_hygiene_check():
    body = (ROOT / "scripts" / "quality.sh").read_text(encoding="utf-8")

    assert "scripts/check_acceptance_hygiene.py" in body


def test_repository_satisfies_the_hygiene_rules():
    assert hygiene.main(ROOT) == 0


def test_configured_commands_target_src_only():
    assert hygiene.scope_problems(_ENV) == []


@pytest.mark.parametrize("name", ["CRAP", "DRY", "MUTATION"])
def test_a_command_that_reaches_acceptance_or_misses_src_is_reported(name: str):
    line = f'SWARMFORGE_{name}_CMD="tool acceptance/"'
    env = "\n".join(
        line if f"SWARMFORGE_{name}_CMD" in text else text for text in _ENV.splitlines()
    )

    problems = hygiene.scope_problems(env)

    assert any(f"{name} command includes acceptance" in p for p in problems)
    assert any(f"{name} command does not target src" in p for p in problems)


def test_a_missing_command_is_reported():
    env = "\n".join(_ENV.splitlines()[:2])

    assert hygiene.scope_problems(env) == ["MUTATION command is not configured"]


def _repository(tmp_path: Path, ignore: str) -> Path:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / ".gitignore").write_text(ignore, encoding="utf-8")
    return tmp_path


def test_ignored_untracked_generated_output_is_clean(tmp_path: Path):
    root = _repository(tmp_path, "build/acceptance/\n")

    assert hygiene.generated_output_problems(root) == []


def test_unignored_generated_output_is_reported(tmp_path: Path):
    root = _repository(tmp_path, "build/acceptance/ir/\n")

    problems = hygiene.generated_output_problems(root)

    assert "generated path is not ignored: build/acceptance/dry/example.txt" in problems
    assert not any("ir/example.json" in p for p in problems)


@pytest.mark.parametrize(
    "tracked",
    [
        "build/acceptance/ir/kept.json",
        "acceptance/ir/kept.json",
        "acceptance/generated/kept.py",
    ],
)
def test_tracked_generated_output_is_reported(tmp_path: Path, tracked: str):
    root = _repository(tmp_path, "build/acceptance/\n")
    path = root / tracked
    path.parent.mkdir(parents=True)
    path.write_text("{}\n", encoding="utf-8")
    subprocess.run(["git", "add", "-f", tracked], cwd=root, check=True)

    assert hygiene.generated_output_problems(root) == [
        f"generated file is tracked: {tracked}"
    ]


def test_job_body_stops_at_the_next_job():
    unit = hygiene.job_body(_WORKFLOW, "unit")

    assert "quality.sh" in unit
    assert "acceptance.sh" not in unit
    assert hygiene.job_body(_WORKFLOW, "missing") == ""


def test_separated_ci_jobs_are_clean():
    assert hygiene.ci_problems(_WORKFLOW) == []


@pytest.mark.parametrize(
    "word",
    [
        "refresh_snapshot",
        "acceptance.sh",
        "Acceptance-Pipeline-Specification",
        "setup-clojure",
    ],
)
def test_unit_job_that_uses_acceptance_prerequisites_is_reported(word: str):
    workflow = _WORKFLOW.replace(
        "      - run: uv run pytest tests/ -q", f"      - run: {word}", 1
    )

    assert f"unit CI job uses {word}" in hygiene.ci_problems(workflow)


def test_acceptance_job_must_provision_tools_before_generating():
    workflow = _WORKFLOW.replace(
        "          repository: unclebob/Acceptance-Pipeline-Specification\n", ""
    )
    reordered = _WORKFLOW.replace("      - run: ./scripts/acceptance.sh\n", "").replace(
        "  acceptance:\n    steps:\n",
        "  acceptance:\n    steps:\n      - run: ./scripts/acceptance.sh\n",
    )

    expected = [
        "acceptance CI job must provision the specification tools before generating"
    ]
    assert hygiene.ci_problems(workflow) == expected
    assert hygiene.ci_problems(reordered) == expected
