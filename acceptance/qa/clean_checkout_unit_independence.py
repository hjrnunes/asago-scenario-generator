#!/usr/bin/env python3
"""Executable QA for clean-checkout unit independence.

This is the command-line form of ``clean_checkout_unit_independence.md``.
It exercises only Git, uv, pytest, and repository files; it does not import
product or acceptance-runtime modules.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Mapping, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[2]
QA_ROOT = PROJECT_ROOT / "tmp" / "qa-clean-checkout"
UV = shutil.which("uv") or next(
    (
        path
        for path in ("/opt/homebrew/bin/uv", "/usr/local/bin/uv")
        if Path(path).is_file()
    ),
    "uv",
)
GENERATED_PATHS = (
    "build/acceptance",
    "acceptance/ir",
    "acceptance/generated",
)
APS_PATHS = (
    ".cache/acceptance-pipeline-specification",
    "tmp/Acceptance-Pipeline-Specification",
)
UNSET_ENV = (
    "ASAGO_SCENARIO_GENERATOR_APS_ROOT",
    "ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL",
    "ASAGO_SCENARIO_GENERATOR_QA_PIPELINE",
)


@dataclass
class Result:
    """One QA assertion."""

    name: str
    passed: bool
    detail: str = ""


RESULTS: list[Result] = []


def check(name: str, passed: bool, detail: str = "") -> None:
    """Record and print one assertion."""
    result = Result(name, bool(passed), detail)
    RESULTS.append(result)
    print(f"  [{'PASS' if result.passed else 'FAIL'}] {name}", flush=True)
    if detail:
        print(f"         {detail}", flush=True)


def child_env() -> dict[str, str]:
    """Return an offline child environment without acceptance prerequisites."""
    environment = dict(os.environ)
    for name in UNSET_ENV:
        environment.pop(name, None)
    return environment


def run_command(
    label: str,
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str] | None = None,
    timeout: int = 1800,
) -> subprocess.CompletedProcess[str]:
    """Run and capture one documented command-line operation."""
    result = subprocess.run(
        list(argv),
        cwd=cwd,
        env=dict(env) if env is not None else None,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    capture = RUN_ROOT / "captures" / label
    capture.mkdir(parents=True)
    (capture / "command.txt").write_text(shlex.join(argv) + "\n", encoding="utf-8")
    (capture / "stdout.txt").write_text(result.stdout, encoding="utf-8")
    (capture / "stderr.txt").write_text(result.stderr, encoding="utf-8")
    (capture / "exit.txt").write_text(f"{result.returncode}\n", encoding="utf-8")
    return result


def inventory(root: Path) -> dict[str, bool]:
    """Inventory generated-output and APS paths in one checkout."""
    return {path: (root / path).exists() for path in (*GENERATED_PATHS, *APS_PATHS)}


def write_inventory(label: str, root: Path) -> dict[str, bool]:
    """Persist and return a generated-path inventory."""
    found = inventory(root)
    target = RUN_ROOT / "inventories"
    target.mkdir(parents=True, exist_ok=True)
    (target / f"{label}.json").write_text(
        json.dumps(found, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return found


def source_checkout(name: str) -> Path:
    """Materialize committed source without ignored files or repository metadata."""
    target = RUN_ROOT / name
    target.mkdir(parents=True)
    archive = RUN_ROOT / f"{name}.tar"
    archived = run_command(
        f"{name}-git-archive",
        ["git", "archive", "--format=tar", f"--output={archive}", "HEAD"],
        cwd=PROJECT_ROOT,
    )
    if archived.returncode != 0:
        raise RuntimeError(f"git archive failed for {name}: {archived.stderr}")
    with tarfile.open(archive) as source:
        source.extractall(target, filter="data")
    archive.unlink()
    return target


def sync_checkout(name: str, checkout: Path) -> bool:
    """Install the locked environment for one fresh checkout."""
    result = run_command(
        f"{name}-uv-sync",
        [UV, "sync", "--locked"],
        cwd=checkout,
        env=child_env(),
    )
    return result.returncode == 0


def qa_cui_01() -> None:
    """Run the complete unit suite in committed source only."""
    checkout = source_checkout("cui-01")
    before = write_inventory("cui-01-before", checkout)
    check(
        "QA-CUI-01 generated output and APS are initially absent",
        not any(before.values()),
    )
    synced = sync_checkout("cui-01", checkout)
    check("QA-CUI-01 uv sync --locked succeeds", synced)
    result = run_command(
        "cui-01-unit-suite",
        [UV, "run", "pytest", "tests/", "-q"],
        cwd=checkout,
        env=child_env(),
    )
    check(
        "QA-CUI-01 complete unit suite succeeds",
        synced and result.returncode == 0,
        f"exit={result.returncode}",
    )
    after = write_inventory("cui-01-after", checkout)
    check("QA-CUI-01 unit suite creates no generated output", not any(after.values()))


def qa_cui_02() -> None:
    """Run acceptance infrastructure tests in both requested orders."""
    orders = (
        (
            "snapshot-then-harness",
            "tests/stpa/test_acceptance_snapshot.py",
            "tests/stpa/test_acceptance_harness_property.py",
        ),
        (
            "harness-then-snapshot",
            "tests/stpa/test_acceptance_harness_property.py",
            "tests/stpa/test_acceptance_snapshot.py",
        ),
    )
    for label, first, second in orders:
        checkout = source_checkout(f"cui-02-{label}")
        before = write_inventory(f"cui-02-{label}-before", checkout)
        synced = sync_checkout(f"cui-02-{label}", checkout)
        result = run_command(
            f"cui-02-{label}-tests",
            [UV, "run", "pytest", first, second, "-q"],
            cwd=checkout,
            env=child_env(),
        )
        after = write_inventory(f"cui-02-{label}-after", checkout)
        check(
            f"QA-CUI-02 {label} succeeds",
            synced and result.returncode == 0,
            f"sync={synced} exit={result.returncode}",
        )
        check(
            f"QA-CUI-02 {label} creates no generated output",
            not any(before.values()) and not any(after.values()),
        )


def qa_cui_03() -> None:
    """Inspect generated-output ignore and tracking boundaries."""
    representatives = (
        "build/acceptance/ir/example.json",
        "build/acceptance/dry/example.txt",
        "build/acceptance/generated/example_acceptance_test.py",
        "build/acceptance/generated/metadata/example.json",
    )
    ignored = run_command(
        "cui-03-check-ignore",
        ["git", "check-ignore", "-v", *representatives],
        cwd=PROJECT_ROOT,
    )
    ignored_paths = {
        line.rsplit("\t", 1)[-1] for line in ignored.stdout.splitlines() if "\t" in line
    }
    check(
        "QA-CUI-03 representative generated artifacts are ignored",
        ignored.returncode == 0 and ignored_paths == set(representatives),
        f"exit={ignored.returncode} ignored={sorted(ignored_paths)}",
    )
    tracked = run_command(
        "cui-03-ls-files",
        [
            "git",
            "ls-files",
            "--",
            "build/acceptance/",
            "acceptance/ir/",
            "acceptance/generated/",
        ],
        cwd=PROJECT_ROOT,
    )
    check(
        "QA-CUI-03 no generated acceptance artifact is tracked",
        tracked.returncode == 0 and not tracked.stdout.strip(),
        tracked.stdout.strip(),
    )


def qa_cui_04() -> None:
    """Confirm unit CI has no APS prerequisite and acceptance CI owns it."""
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    before_acceptance, separator, acceptance = workflow.partition("\n  acceptance:")
    revision = "accaa33d503340c56513ef387258f8da929ba902"
    check(
        "QA-CUI-04 unit and acceptance CI jobs are separate",
        bool(separator)
        and "uv run pytest tests/ -q" in before_acceptance
        and "./scripts/acceptance.sh" not in before_acceptance,
    )
    check(
        "QA-CUI-04 APS checkout is an acceptance-only prerequisite",
        "Acceptance-Pipeline-Specification" not in before_acceptance
        and "unclebob/Acceptance-Pipeline-Specification" in acceptance
        and revision in acceptance,
    )


def main() -> int:
    """Run all clean-checkout QA procedures."""
    print(f"QA evidence: {RUN_ROOT.relative_to(PROJECT_ROOT)}", flush=True)
    qa_cui_01()
    qa_cui_02()
    qa_cui_03()
    qa_cui_04()
    failed = sum(not result.passed for result in RESULTS)
    print(f"\nQA suite: {len(RESULTS) - failed} passed, {failed} failed", flush=True)
    return 1 if failed else 0


QA_ROOT.mkdir(parents=True, exist_ok=True)
RUN_ROOT = QA_ROOT / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")


if __name__ == "__main__":
    sys.exit(main())
