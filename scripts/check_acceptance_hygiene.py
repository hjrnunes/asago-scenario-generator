#!/usr/bin/env python3
"""Check the repository rules that keep acceptance output disposable.

Run by ``./scripts/quality.sh``. The checks read the repository layout, not
behavior, so they run in a clean checkout with no generated output and no
Acceptance Pipeline Specification tools.

* CRAP, DRY, and mutation commands target ``src`` and never ``acceptance``.
* Generated acceptance paths are git-ignored and no generated file is tracked.
* The unit CI job neither generates acceptance output nor needs its tools; the
  acceptance CI job provisions them before it generates.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

SCOPED_COMMANDS = ("CRAP", "DRY", "MUTATION")

GENERATED_EXAMPLES = (
    "build/acceptance/ir/example.json",
    "build/acceptance/dry/example.txt",
    "build/acceptance/generated/example_acceptance_test.py",
    "build/acceptance/generated/metadata/example.json",
)

GENERATED_ROOTS = ("build/acceptance", "acceptance/ir", "acceptance/generated")

UNIT_JOB_FORBIDDEN = (
    "refresh_snapshot",
    "acceptance.sh",
    "Acceptance-Pipeline-Specification",
    "setup-clojure",
)


def scope_problems(env_text: str) -> list[str]:
    """Report CRAP, DRY, or mutation commands that miss ``src`` or reach ``acceptance``."""
    commands = {
        match.group(1): match.group(2)
        for match in re.finditer(
            r'^SWARMFORGE_(CRAP|DRY|MUTATION)_CMD="(.*)"$', env_text, re.MULTILINE
        )
    }
    problems = [
        f"{name} command is not configured"
        for name in SCOPED_COMMANDS
        if name not in commands
    ]
    for name, command in commands.items():
        if "src" not in command:
            problems.append(f"{name} command does not target src: {command}")
        if "acceptance" in command:
            problems.append(f"{name} command includes acceptance: {command}")
    return problems


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=False
    )


def generated_output_problems(root: Path) -> list[str]:
    """Report generated acceptance paths that git does not ignore, or tracks."""
    problems = [
        f"generated path is not ignored: {path}"
        for path in GENERATED_EXAMPLES
        if _git(root, "check-ignore", "--no-index", path).returncode != 0
    ]
    listed = _git(root, "ls-files", *GENERATED_ROOTS)
    if listed.returncode != 0:
        return problems + [f"git ls-files failed: {listed.stderr.strip()}"]
    problems.extend(
        f"generated file is tracked: {line}"
        for line in listed.stdout.splitlines()
        if line.strip()
    )
    return problems


def job_body(workflow: str, job: str) -> str:
    """Return the text of one top-level job in a workflow, or an empty string."""
    match = re.search(rf"(?ms)^  {re.escape(job)}:.*?(?=^  [a-zA-Z_-]+:|\Z)", workflow)
    return match.group(0) if match else ""


def ci_problems(workflow: str) -> list[str]:
    """Report CI jobs that mix unit and acceptance prerequisites."""
    unit = job_body(workflow, "unit")
    acceptance = job_body(workflow, "acceptance")
    problems = []
    if not unit:
        problems.append("CI has no unit job")
    problems.extend(
        f"unit CI job uses {word}" for word in UNIT_JOB_FORBIDDEN if word in unit
    )
    provisioned = acceptance.find("Acceptance-Pipeline-Specification")
    generated = acceptance.find("./scripts/acceptance.sh")
    if provisioned < 0 or generated < provisioned:
        problems.append(
            "acceptance CI job must provision the specification tools before generating"
        )
    return problems


def main(root: Path) -> int:
    problems = scope_problems(
        (root / "config" / "swarmforge.env").read_text(encoding="utf-8")
    )
    problems.extend(generated_output_problems(root))
    problems.extend(
        ci_problems(
            (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        )
    )
    for problem in problems:
        print(f"acceptance hygiene: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(Path(__file__).resolve().parent.parent))
