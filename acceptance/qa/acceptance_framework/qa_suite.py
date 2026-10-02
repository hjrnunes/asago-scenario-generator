#!/usr/bin/env python3
"""End-to-end QA suite for the acceptance framework refactor.

Executable form of ``acceptance/qa/acceptance_framework/qa_suite.md``.
Exercises only checked-in command-line entrypoints and the mutation worker's
JSON-lines interface. Does not import project modules.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

QA_MODULES = Path(__file__).resolve().parents[1]
if str(QA_MODULES) not in sys.path:
    sys.path.insert(0, str(QA_MODULES))

from qa_harness import (  # noqa: E402
    PROJECT_ROOT,
    QARunner,
    child_env,
    run_command,
    write_capture as _write_capture,
)
from qa_suite_support import (  # noqa: E402
    parse_runtime_lines,
    write_ir,
)
from qa_suite_generation import (  # noqa: E402
    GenerationContext,
    qa_afr_01,
)

QA_ROOT = PROJECT_ROOT / "tmp" / "qa-acceptance-framework"
FEATURES_DIR = PROJECT_ROOT / "features"
ACCEPTANCE_SH = PROJECT_ROOT / "scripts" / "acceptance.sh"
QUALITY_SH = PROJECT_ROOT / "scripts" / "quality.sh"
CONFIG_SH = PROJECT_ROOT / "config" / "swarmforge.env"
RUNNER_ADAPTER = PROJECT_ROOT / "acceptance" / "runner_adapter.py"
AFR_TEST = (
    "build/acceptance/generated/acceptance_framework_refactor_acceptance_test.py"
    "::test_acceptance"
)
NESTED_TEST = (
    "build/acceptance/generated/stage1_ordering_acceptance_test.py::test_acceptance"
)
JPKW_FALLBACK = (
    "JPKW-07-FALLBACK .feature file uses gherkin_raw when structured "
    "Gherkin is unavailable"
)
AFR_EXPECTED = (
    "AFR-01",
    "AFR-02",
    "AFR-03",
    "AFR-04",
    "AFR-05",
    "AFR-06",
    "AFR-07",
    "AFR-08",
    "AFR-09",
)

GENERATION_CONTEXT = GenerationContext(
    project_root=PROJECT_ROOT,
    qa_root=QA_ROOT,
    features_dir=FEATURES_DIR,
    acceptance_script=ACCEPTANCE_SH,
    child_env=child_env,
    run_command=run_command,
    write_capture=_write_capture,
)


def qa_afr_02(runner: QARunner) -> subprocess.CompletedProcess[str]:
    env = child_env(
        ASAGO_SCENARIO_GENERATOR_QA_PIPELINE=None,
        ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL="http://127.0.0.1:9/v1",
    )
    result = run_command(
        [
            "env",
            "-u",
            "ASAGO_SCENARIO_GENERATOR_QA_PIPELINE",
            str(ACCEPTANCE_SH),
            "--test",
        ],
        env=env,
        timeout=1800,
    )
    _write_capture("qa-afr-02-test", result, root=QA_ROOT)
    combined = result.stdout + "\n" + result.stderr
    outcomes = parse_runtime_lines(combined)

    runner.check(
        "QA-AFR-02 quality gate runs before generated tests",
        "All checks passed!" in combined or "ruff" in combined.lower(),
        "expected ruff/quality output in --test logs",
    )
    script = ACCEPTANCE_SH.read_text()
    quality_at = script.find("scripts/quality.sh")
    pytest_at = script.find("exec uv run pytest")
    runner.check(
        "QA-AFR-02 acceptance.sh invokes quality before pytest",
        0 <= quality_at < pytest_at,
    )

    afr_lines = [
        line
        for status in outcomes.values()
        for line in status
        if "Acceptance framework refactor AFR-" in line or "AFR-0" in line
    ]
    afr_fails = [line for line in outcomes["FAIL"] if "AFR-0" in line]
    afr_passes = [line for line in outcomes["PASS"] if "AFR-0" in line]
    found_ids = {
        code for code in AFR_EXPECTED if any(code in line for line in afr_passes)
    }
    runner.check(
        "QA-AFR-02 AFR-01..09 report PASS",
        found_ids == set(AFR_EXPECTED) and not afr_fails,
        f"passed={sorted(found_ids)} fails={afr_fails} lines={len(afr_lines)}",
    )

    runner.check(
        "QA-AFR-02 unmarked deterministic scenarios execute",
        bool(outcomes["PASS"]),
        f"pass={len(outcomes['PASS'])} fail={len(outcomes['FAIL'])} skip={len(outcomes['SKIP'])}",
    )

    jpkw_pass = any(JPKW_FALLBACK in line for line in outcomes["PASS"])
    jpkw_fail = any(JPKW_FALLBACK in line for line in outcomes["FAIL"])
    runner.check(
        "QA-AFR-02 JPKW canonical/raw fallback retains PASS",
        jpkw_pass and not jpkw_fail,
        f"pass={jpkw_pass} fail={jpkw_fail}",
    )
    return result


def qa_afr_03(runner: QARunner) -> None:
    parent_before = dict(os.environ)
    env = child_env(ASAGO_SCENARIO_GENERATOR_QA_PIPELINE=None)
    first = run_command(
        [
            "uv",
            "run",
            "pytest",
            AFR_TEST,
            "-q",
            "-s",
        ],
        env=env,
        timeout=300,
    )
    _write_capture("qa-afr-03-first", first, root=QA_ROOT)
    second = run_command(
        [
            "uv",
            "run",
            "pytest",
            AFR_TEST,
            "-q",
            "-s",
        ],
        env=env,
        timeout=300,
    )
    _write_capture("qa-afr-03-second", second, root=QA_ROOT)
    parent_after = dict(os.environ)

    first_out = parse_runtime_lines(first.stdout + first.stderr)
    afr05 = [
        line for status in first_out.values() for line in status if "AFR-05" in line
    ]
    runner.check(
        "QA-AFR-03 AFR-05 passing-first and failing-first rows complete",
        first.returncode == 0 and len(afr05) >= 2,
        f"exit={first.returncode} rows={afr05}",
    )
    runner.check(
        "QA-AFR-03 parent environment is unchanged",
        parent_before == parent_after,
    )
    runner.check(
        "QA-AFR-03 rerun output does not depend on the preceding run",
        parse_runtime_lines(first.stdout) == parse_runtime_lines(second.stdout)
        and first.returncode == second.returncode,
    )


def qa_afr_04(runner: QARunner) -> None:
    env = child_env(ASAGO_SCENARIO_GENERATOR_QA_PIPELINE=None)
    env.pop("PYTHONPATH", None)
    result = run_command(
        ["uv", "run", "pytest", AFR_TEST, "-q", "-s"],
        env=env,
        timeout=300,
    )
    _write_capture("qa-afr-04-namespace", result, root=QA_ROOT)
    combined = result.stdout + result.stderr
    runner.check(
        "QA-AFR-04 AFR-07 namespaced manifest loading passes",
        result.returncode == 0 and "AFR-07" in combined and "FAIL" not in combined,
        f"exit={result.returncode}",
    )

    nested = run_command(
        ["uv", "run", "pytest", NESTED_TEST, "-q", "-s"],
        env=env,
        timeout=300,
    )
    _write_capture("qa-afr-04-nested", nested, root=QA_ROOT)
    generated = (
        PROJECT_ROOT / "build/acceptance/generated/stage1_ordering_acceptance_test.py"
    ).read_text()
    runner.check(
        "QA-AFR-04 nested feature resolves IR under project-root IR directory",
        nested.returncode == 0
        and "build/acceptance/ir/stage1-split-reorder/stage1_ordering.json"
        in generated,
        f"exit={nested.returncode}",
    )


def _worker_response(line: str) -> dict:
    return json.loads(line)


def qa_afr_05(runner: QARunner) -> None:
    fixtures = QA_ROOT / "worker"
    fixtures.mkdir(parents=True, exist_ok=True)
    passing = fixtures / "pass.json"
    failing = fixtures / "fail.json"
    write_ir(passing, "ok", "acceptance framework supported passing step")
    write_ir(failing, "bad", "this step is definitely unsupported xyzzy-12345")

    jobs = [
        json.dumps(
            {
                "id": "pass-1",
                "feature_json": str(passing),
                "timeout": "30s",
            }
        ),
        json.dumps(
            {
                "id": "fail-1",
                "feature_json": str(failing),
                "timeout": "30s",
            }
        ),
        "not-json",
        json.dumps(
            {
                "id": "pass-2",
                "feature_json": str(passing),
                "timeout": "30s",
            }
        ),
        json.dumps(
            {
                "id": "timeout-1",
                "feature_json": str(passing),
                "timeout": "0s",
            }
        ),
        json.dumps(
            {
                "id": "boom-1",
                "feature_json": str(passing),
                "timeout": "bogus",
            }
        ),
    ]
    payload = "\n".join(jobs) + "\n"
    env = child_env(ASAGO_SCENARIO_GENERATOR_QA_PIPELINE=None)
    result = run_command(
        [sys.executable, str(RUNNER_ADAPTER)],
        cwd=PROJECT_ROOT / "acceptance",
        env=env,
        input_text=payload,
        timeout=120,
    )
    _write_capture("qa-afr-05-worker", result, root=QA_ROOT)
    runner.check(
        "QA-AFR-05 ready appears on stderr, not stdout",
        "runner_adapter: ready" in result.stderr
        and "runner_adapter: ready" not in result.stdout,
        f"stderr={result.stderr.strip()!r}",
    )
    runner.check("QA-AFR-05 worker exits 0 after stdin close", result.returncode == 0)

    lines = [line for line in result.stdout.splitlines() if line.strip()]
    runner.check(
        "QA-AFR-05 one JSON response per input line",
        len(lines) == len(jobs),
        f"responses={len(lines)} jobs={len(jobs)} stdout={result.stdout!r}",
    )
    if len(lines) != len(jobs):
        return

    parsed = [_worker_response(line) for line in lines]
    pass_job, fail_job, bad_job, pass_again, timeout_job, boom_job = parsed

    runner.check(
        "QA-AFR-05 passing IR maps to test_success",
        pass_job["id"] == "pass-1"
        and pass_job["outcome"] == "test_success"
        and "output" in pass_job
        and "error" in pass_job
        and isinstance(pass_job["duration"], int)
        and pass_job["duration"] >= 0
        and "PASS" in pass_job["output"],
        json.dumps(pass_job)[:300],
    )
    runner.check(
        "QA-AFR-05 unsupported step maps to test_failure",
        fail_job["id"] == "fail-1" and fail_job["outcome"] == "test_failure",
        json.dumps(fail_job)[:300],
    )
    runner.check(
        "QA-AFR-05 malformed JSON stays in-band as unknown infrastructure_error",
        bad_job["id"] == "unknown"
        and bad_job["outcome"] == "infrastructure_error"
        and pass_again["id"] == "pass-2"
        and pass_again["outcome"] == "test_success",
        json.dumps({"bad": bad_job, "next": pass_again})[:400],
    )
    runner.check(
        "QA-AFR-05 timeout maps to infrastructure_error",
        timeout_job["id"] == "timeout-1"
        and timeout_job["outcome"] == "infrastructure_error",
        json.dumps(timeout_job)[:300],
    )
    runner.check(
        "QA-AFR-05 subprocess/worker exception maps to infrastructure_error",
        boom_job["id"] == "boom-1" and boom_job["outcome"] == "infrastructure_error",
        json.dumps(boom_job)[:300],
    )


def qa_afr_06(runner: QARunner) -> None:
    status = run_command(["git", "status", "--short", "--untracked-files=all"])
    _write_capture("qa-afr-06-status", status, root=QA_ROOT)
    tracked_generated = [
        line
        for line in status.stdout.splitlines()
        if not line.startswith("?")
        and (
            "build/acceptance/" in line
            or "build/acceptance-mutation" in line
            or line.endswith("lcov.info")
            or "tmp/qa-acceptance-framework/" in line
        )
    ]
    runner.check(
        "QA-AFR-06 generated and temporary QA artifacts are untracked",
        not tracked_generated,
        "; ".join(tracked_generated[:8]),
    )

    config = CONFIG_SH.read_text()
    runner.check(
        "QA-AFR-06 permanent CRAP/DRY/mutation stay scoped to src/",
        'SWARMFORGE_CRAP_CMD="crap4py src/' in config
        and 'SWARMFORGE_DRY_CMD="drywall --threshold 0.82 ./src"' in config
        and "mutate4py src/" in config,
    )
    quality = QUALITY_SH.read_text()
    runner.check(
        "QA-AFR-06 quality.sh still checks src and acceptance",
        "uv run ruff check src acceptance" in quality
        and "uv run ruff format --check src acceptance" in quality,
    )
    src_diff = run_command(["git", "diff", "--name-only", "799f5a9", "--", "src"])
    runner.check(
        "QA-AFR-06 no production src/ change for this refactor",
        src_diff.stdout.strip() == "",
        src_diff.stdout.strip(),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-generate",
        action="store_true",
        help="skip QA-AFR-01 full generation against temporary output trees",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    QA_ROOT.mkdir(parents=True, exist_ok=True)
    runner = QARunner()
    print("End-to-end QA: acceptance framework refactor", flush=True)
    if not args.skip_generate:
        qa_afr_01(runner, GENERATION_CONTEXT)
    else:
        runner.record("QA-AFR-01 skipped by --skip-generate", True)
    qa_afr_02(runner)
    qa_afr_03(runner)
    qa_afr_04(runner)
    qa_afr_05(runner)
    qa_afr_06(runner)
    return runner.summary()


if __name__ == "__main__":
    sys.exit(main())
