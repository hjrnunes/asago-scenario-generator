#!/usr/bin/env python3
"""Race-free persistent runner adapter for `gherkin-mutator`.

The mutator starts one runner process per worker and sends mutation jobs over
stdin/stdout (see the Acceptance-Pipeline-Specification mutator spec):

    request:  {"id": "m1", "feature_json": "<mutated IR path>", "timeout": "30s", ...}
    response: {"id": "m1", "outcome": "test_success|test_failure|infrastructure_error",
               "output": "...", "error": "", "duration": <ns>}

Each runner process materializes a private scratch root that mirrors the
committed layout: ``pyproject.toml`` (real copy), every other top-level
entry as a symlink, and real copies of ``build/acceptance/ir/`` and
``build/acceptance/generated/``. Per job, the mutated IR is copied over the
scratch copy's IR file and the generated acceptance test is executed from
the scratch tree. The generated test resolves ``_PROJECT_ROOT`` from its own
``__file__``, so it reads the scratch IR; no shared ``build/acceptance/ir``
file is ever touched, which makes parallel workers race-free. A crashed job
also cannot leave a mutated IR behind in the real snapshot.

``FEATURE_STEM`` must name the feature under test, matching the generated test
``build/acceptance/generated/<stem>_acceptance_test.py``.

Outcome mapping: pytest exit 0 -> test_success (mutant survived), exit 1 ->
test_failure (mutant killed), any other exit or a timeout ->
infrastructure_error.
"""

from __future__ import annotations

import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MAX_OUTPUT = 20_000


def _infrastructure(job_id: str, error: str, output: str, duration_ns: int) -> dict:
    return {
        "id": job_id,
        "outcome": "infrastructure_error",
        "output": output[:MAX_OUTPUT],
        "error": error,
        "duration": duration_ns,
    }


def build_scratch_root(stem: str) -> Path:
    """Mirror the project root into a scratch tree with a private IR copy."""
    scratch = Path(tempfile.mkdtemp(prefix="gherkin-mutation-"))
    atexit.register(shutil.rmtree, scratch, ignore_errors=True)

    ir_dir = PROJECT_ROOT / "build" / "acceptance" / "ir"
    generated_dir = PROJECT_ROOT / "build" / "acceptance" / "generated"
    test_file = generated_dir / f"{stem}_acceptance_test.py"
    if not ir_dir.is_dir() or not test_file.is_file():
        raise SystemExit(
            f"runner adapter: missing snapshot artifacts for stem '{stem}'"
        )

    # Real file so the generated test's `next(p ... is_file())` walk stops here.
    shutil.copy2(PROJECT_ROOT / "pyproject.toml", scratch / "pyproject.toml")

    # Everything the runtime may read stays reachable through symlinks; only
    # `build` is materialized so the mutated IR stays process-private. The
    # pyproject.toml copy above stays a real file.
    for entry in PROJECT_ROOT.iterdir():
        if entry.name in ("build", "pyproject.toml") or entry.name.startswith("."):
            continue
        (scratch / entry.name).symlink_to(entry)
    venv = PROJECT_ROOT / ".venv"
    if venv.exists():
        (scratch / ".venv").symlink_to(venv)

    for source_dir in (ir_dir, generated_dir):
        target = scratch / "build" / "acceptance" / source_dir.name
        target.mkdir(parents=True)
        for path in source_dir.iterdir():
            if path.is_file() and path.suffix in (".json", ".py"):
                shutil.copy2(path, target / path.name)
    return scratch


def run_job(job: dict, scratch: Path, stem: str) -> dict:
    """Execute the generated test against the mutated IR in the scratch tree."""
    job_id = str(job.get("id", "unknown"))
    started = time.perf_counter_ns()
    mutated_ir = job.get("feature_json", "")
    if not mutated_ir or not Path(mutated_ir).is_file():
        return _infrastructure(
            job_id,
            f"mutated IR not found: {mutated_ir}",
            "",
            time.perf_counter_ns() - started,
        )

    scratch_ir = scratch / "build" / "acceptance" / "ir" / f"{stem}.json"
    shutil.copy2(mutated_ir, scratch_ir)

    timeout = 30.0
    raw_timeout = job.get("timeout", "30s")
    if isinstance(raw_timeout, str) and raw_timeout.endswith(("s", "m")):
        try:
            limit = float(raw_timeout[:-1])
            timeout = limit * (60 if raw_timeout.endswith("m") else 1)
        except ValueError:
            pass

    test_file = (
        scratch / "build" / "acceptance" / "generated" / f"{stem}_acceptance_test.py"
    )
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                str(test_file),
                "-q",
                "-p",
                "no:cacheprovider",
            ],
            cwd=scratch,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return _infrastructure(
            job_id, f"Timeout after {timeout:g}s", "", time.perf_counter_ns() - started
        )

    duration = time.perf_counter_ns() - started
    if completed.returncode == 0:
        outcome = "test_success"
        error = ""
    elif completed.returncode == 1:
        outcome = "test_failure"
        error = ""
    else:
        outcome = "infrastructure_error"
        error = completed.stderr or f"Exit code {completed.returncode}"
    return {
        "id": job_id,
        "outcome": outcome,
        "output": completed.stdout[:MAX_OUTPUT],
        "error": error,
        "duration": duration,
    }


def main() -> int:
    """Read jobs from stdin, write responses to stdout (one JSON per line)."""
    stem = os.environ.get("FEATURE_STEM", "")
    if not stem:
        print("runner adapter: FEATURE_STEM is required", file=sys.stderr)
        return 2
    scratch = build_scratch_root(stem)
    print(f"runner adapter: ready (scratch={scratch})", file=sys.stderr, flush=True)

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            job = json.loads(line)
        except json.JSONDecodeError as exc:
            response = _infrastructure("unknown", f"Invalid JSON: {exc}", "", 0)
        else:
            response = (
                run_job(job, scratch, stem)
                if isinstance(job, dict)
                else _infrastructure("unknown", "Job must be a JSON object", "", 0)
            )
        print(json.dumps(response), flush=True)
        print(
            f"runner adapter: {response['id']} -> {response['outcome']}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
