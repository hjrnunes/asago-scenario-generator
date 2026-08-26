#!/usr/bin/env python3
"""Executable end-to-end QA suite for acceptance live-LLM opt-in.

Mirrors ``live_llm_opt_in.md`` (QA-ALO-01..05).  Drives only
``./scripts/acceptance.sh`` in child processes and inspects stdout,
stderr, exit status, parent environment, git status, and
``config/swarmforge.env``.  Never imports project modules and never
mutates the parent shell.

Pinned live contract (reported, not silently bent)
  1. QA-ALO-01/02's procedure sets an unreachable loopback
     ``MODEL_BASE_URL``.  APP/CUI Gherkin fail-closed when any model
     endpoint is configured, so a loopback URL makes ``acceptance.sh``
     exit 1 even while live scenarios skip.  The suite omits the
     loopback on those default/non-authorizing runs; skip is decided
     before any model call.
  2. QA-ALO-03's procedure asks for a working LLM endpoint and a full
     ``acceptance.sh`` run.  This environment has no live model, and
     opting the whole suite in against a loopback URL would invoke
     ``stpa-run`` with a 600s timeout per marked scenario.  The suite
     therefore opts in only the isolated ALO generated test.
  3. QA-ALO-04 still runs full ``acceptance.sh`` with opt-in and no
     endpoint variables, so marked STPA scenarios fail closed with
     ``LLM endpoint not configured``.
  4. Isolated ALO Gherkin mutates child-process environment inside
     restored scenario context.  Full-suite skip/fail assertions key
     off the live-LLM skip reason and the endpoint-not-configured
     diagnostic, not a private runtime API.
  5. Hardender ALO-03 outline now observes the exact opt-in value
     (``0`` / ``true`` / ``yes``).  The suite still drives those values
     through ``acceptance.sh`` as QA-ALO-02.

Run with::

    uv run python acceptance/qa/live_llm_opt_in.py

Exit status is 0 only when every pinned assertion passes.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class CheckResult:
    """One recorded QA check and its optional diagnostic detail."""

    name: str
    passed: bool
    detail: str = ""
    status: str | None = None

    def __str__(self) -> str:
        status = self.status or ("PASS" if self.passed else "FAIL")
        text = f"  [{status}] {self.name}"
        if self.detail:
            text += f"\n         {self.detail}"
        return text


class QARunner:
    """Record checks once, emit them in order, and return a stable exit code."""

    def __init__(self) -> None:
        self.results: list[CheckResult] = []

    def record(self, name: str, passed: bool, detail: str = "") -> CheckResult:
        result = CheckResult(name, bool(passed), detail)
        self.results.append(result)
        print(result, flush=True)
        return result

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        self.record(name, passed, detail)
        return bool(passed)

    def skip(self, name: str, reason: str) -> CheckResult:
        """Record a visible skip without treating it as a failure."""
        result = CheckResult(name, True, reason, "SKIP")
        self.results.append(result)
        print(result, flush=True)
        return result

    def summary(self) -> int:
        passed = sum(
            result.passed and result.status != "SKIP" for result in self.results
        )
        failed = sum(
            not result.passed and result.status != "SKIP" for result in self.results
        )
        print(f"\nQA suite: {passed} passed, {failed} failed", flush=True)
        return 0 if failed == 0 else 1


def child_env(
    base: dict[str, str] | None = None,
    **updates: str | None,
) -> dict[str, str]:
    """Copy the parent environment and apply child-only updates."""
    environment = dict(os.environ if base is None else base)
    for key, value in updates.items():
        if value is None:
            environment.pop(key, None)
        else:
            environment[key] = value
    return environment


def run_command(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int | float | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a child command with separate text streams and exit capture."""
    return subprocess.run(
        list(argv),
        cwd=str(cwd or PROJECT_ROOT),
        env=dict(env) if env is not None else None,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def _fresh_capture_dir(label: str, *, root: Path) -> Path:
    """Create an empty capture directory for one labeled child run."""
    target = Path(root) / "captures" / label
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    return target


def write_capture(
    label: str,
    result: subprocess.CompletedProcess[str],
    *,
    root: Path,
) -> Path:
    """Write stdout, stderr, and exit status into a fresh capture directory."""
    target = _fresh_capture_dir(label, root=root)
    (target / "stdout.txt").write_text(result.stdout, encoding="utf-8")
    (target / "stderr.txt").write_text(result.stderr, encoding="utf-8")
    (target / "exit.txt").write_text(f"{result.returncode}\n", encoding="utf-8")
    return target


RUN_ROOT = (
    PROJECT_ROOT
    / "tmp"
    / "qa-live-llm-opt-in"
    / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
)
ACCEPTANCE_SH = PROJECT_ROOT / "scripts" / "acceptance.sh"
CONFIG_ENV = PROJECT_ROOT / "config" / "swarmforge.env"
ALO_TEST = (
    PROJECT_ROOT
    / "build"
    / "acceptance"
    / "generated"
    / "acceptance_live_llm_opt_in_acceptance_test.py"
)
_APS_CANDIDATES = (
    PROJECT_ROOT / ".cache" / "acceptance-pipeline-specification",
    PROJECT_ROOT.parents[1] / ".cache" / "acceptance-pipeline-specification",
)
APS_ROOT = next((path for path in _APS_CANDIDATES if path.is_dir()), _APS_CANDIDATES[0])
OPT_IN = "ASAGO_SCENARIO_GENERATOR_QA_PIPELINE"
ENDPOINT_VARS = (
    "ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL",
    "OPENAI_BASE_URL",
    "OPENAI_API_KEY",
    "ASAGO_SCENARIO_GENERATOR_API_KEY",
)
WATCHED_VARS = (OPT_IN, *ENDPOINT_VARS)
LOOPBACK = "http://127.0.0.1:9/v1"
SKIP_REASON = 'live LLM acceptance requires ASAGO_SCENARIO_GENERATOR_QA_PIPELINE "1"'
ENDPOINT_DIAGNOSTIC = "LLM endpoint not configured"
TRACKED_GENERATED = (
    "build/acceptance/",
    "acceptance/ir/",
    "acceptance/generated/",
)
OUTCOME_RE = re.compile(r"^(PASS|FAIL|SKIP) .+")


def _snapshot_parent() -> dict[str, str | None]:
    return {name: os.environ.get(name) for name in WATCHED_VARS}


def _acceptance_env(**updates: str | None) -> dict[str, str]:
    environment = child_env(
        ASAGO_SCENARIO_GENERATOR_APS_ROOT=str(APS_ROOT),
        **updates,
    )
    return environment


def _run_acceptance(
    label: str, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    result = run_command(
        [str(ACCEPTANCE_SH)],
        cwd=PROJECT_ROOT,
        env=env,
        timeout=1800,
    )
    write_capture(label, result, root=RUN_ROOT)
    return result


def _combined(result: subprocess.CompletedProcess[str]) -> str:
    return f"{result.stdout}\n{result.stderr}"


def _outcomes(text: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {"PASS": [], "FAIL": [], "SKIP": []}
    for raw in text.splitlines():
        line = raw.strip()
        match = OUTCOME_RE.match(line)
        if match is None:
            continue
        found[match.group(1)].append(line)
    return found


def _live_skips(outcomes: dict[str, list[str]]) -> list[str]:
    return [line for line in outcomes["SKIP"] if SKIP_REASON in line]


_ISOLATED_LIVE_RE = re.compile(r"^SKIP live(?:-\d+)?/example_")


def _marked_feature_skips(outcomes: dict[str, list[str]]) -> list[str]:
    """Skip lines for marked STPA features, excluding nested ALO fixtures."""
    return [line for line in _live_skips(outcomes) if not _ISOLATED_LIVE_RE.match(line)]


def _live_passes(outcomes: dict[str, list[str]]) -> list[str]:
    return [line for line in outcomes["PASS"] if SKIP_REASON in line]


def _live_fails(outcomes: dict[str, list[str]]) -> list[str]:
    return [
        line
        for line in outcomes["FAIL"]
        if SKIP_REASON in line or ENDPOINT_DIAGNOSTIC in line
    ]


def _fixture_paths(text: str) -> list[str]:
    return re.findall(r"fixture=(\S+)", text)


def _output_paths(text: str) -> list[str]:
    found: list[str] = []
    for match in re.finditer(r"output=(\S+)", text):
        value = match.group(1)
        if value != "none":
            found.extend(part for part in value.split(",") if part)
    return found


def _assert_parent_unchanged(
    runner: QARunner, case: str, before: dict[str, str | None]
) -> None:
    after = _snapshot_parent()
    runner.check(
        f"{case} parent environment unchanged",
        after == before,
        f"before={before} after={after}",
    )


def qa_alo_01(runner: QARunner, before: dict[str, str | None]) -> list[str]:
    """QA-ALO-01: default execution skips marked live work."""
    case = "QA-ALO-01"
    env = _acceptance_env(**{OPT_IN: None})
    result = _run_acceptance("alo-01-default", env)
    combined = _combined(result)
    outcomes = _outcomes(combined)
    skips = _live_skips(outcomes)
    runner.check(f"{case} exit status 0", result.returncode == 0, combined[-400:])
    runner.check(
        f"{case} deterministic scenarios passed",
        bool(outcomes["PASS"]),
        f"pass={len(outcomes['PASS'])}",
    )
    runner.check(
        f"{case} marked live scenarios skipped with opt-in reason",
        bool(skips) and all(SKIP_REASON in line for line in skips),
        f"skip={len(skips)} sample={skips[:2]}",
    )
    runner.check(
        f"{case} marked live scenarios are not passed or failed",
        not _live_passes(outcomes) and not _live_fails(outcomes),
        f"pass={_live_passes(outcomes)[:2]} fail={_live_fails(outcomes)[:2]}",
    )
    _assert_parent_unchanged(runner, case, before)
    runner.record(
        f"{case} note",
        True,
        "loopback MODEL_BASE_URL omitted: APP/CUI Gherkin fail-closed when "
        "any endpoint is configured, while live skip is decided first",
    )
    return skips


def qa_alo_02(runner: QARunner, before: dict[str, str | None]) -> None:
    """QA-ALO-02: non-authorizing values keep the default skip behavior."""
    for value in ("0", "true", "yes"):
        case = f"QA-ALO-02 value={value}"
        env = _acceptance_env(**{OPT_IN: value})
        result = _run_acceptance(f"alo-02-{value}", env)
        combined = _combined(result)
        outcomes = _outcomes(combined)
        skips = _live_skips(outcomes)
        runner.check(
            f"{case} exit status 0",
            result.returncode == 0,
            combined[-400:],
        )
        runner.check(
            f"{case} marked live scenarios skipped",
            bool(skips) and not _live_passes(outcomes) and not _live_fails(outcomes),
            f"skip={len(skips)} pass={_live_passes(outcomes)[:1]} "
            f"fail={_live_fails(outcomes)[:1]}",
        )
        _assert_parent_unchanged(runner, case, before)
    runner.record(
        "QA-ALO-02 note",
        True,
        "loopback MODEL_BASE_URL omitted for the same APP/CUI fail-closed reason",
    )


def qa_alo_03(runner: QARunner, before: dict[str, str | None]) -> None:
    """QA-ALO-03: explicit opt-in executes marked scenarios instead of skipping."""
    case = "QA-ALO-03"
    env = _acceptance_env(
        **{
            OPT_IN: "1",
            "ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL": LOOPBACK,
            "ASAGO_SCENARIO_GENERATOR_API_KEY": "qa-unused",
        }
    )
    result = run_command(
        ["uv", "run", "pytest", str(ALO_TEST), "-q", "-s"],
        cwd=PROJECT_ROOT,
        env=env,
        timeout=300,
    )
    write_capture("alo-03-isolated-alo", result, root=RUN_ROOT)
    combined = _combined(result)
    outcomes = _outcomes(combined)
    skips = _live_skips(outcomes)
    runner.check(f"{case} isolated ALO test exists", ALO_TEST.is_file(), str(ALO_TEST))
    runner.check(
        f"{case} isolated ALO test exits 0 under opt-in",
        result.returncode == 0,
        combined[-400:],
    )
    runner.check(
        f"{case} marked live scenarios are not skipped",
        not skips,
        f"skip={skips[:3]} output={combined[-400:]}",
    )
    runner.check(
        f"{case} ALO-02 opt-in scenario is reported as passed",
        any(
            "ALO-02 explicit opt-in executes live work" in line
            for line in outcomes["PASS"]
        ),
        f"pass={outcomes['PASS'][:5]}",
    )
    _assert_parent_unchanged(runner, case, before)
    runner.record(
        f"{case} note",
        True,
        "full acceptance.sh opt-in is not run against a live model; "
        "isolated ALO generated test is the UI surface",
    )


def qa_alo_04(runner: QARunner, before: dict[str, str | None]) -> str:
    """QA-ALO-04: opted in without an endpoint fails visibly."""
    case = "QA-ALO-04"
    env = _acceptance_env(
        **{
            OPT_IN: "1",
            "ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL": None,
            "OPENAI_BASE_URL": None,
            "OPENAI_API_KEY": None,
            "ASAGO_SCENARIO_GENERATOR_API_KEY": None,
        }
    )
    result = _run_acceptance("alo-04-no-endpoint", env)
    combined = _combined(result)
    outcomes = _outcomes(combined)
    skips = _marked_feature_skips(outcomes)
    fails = [line for line in outcomes["FAIL"] if ENDPOINT_DIAGNOSTIC in line]
    runner.check(
        f"{case} at least one marked scenario fails with endpoint diagnostic",
        bool(fails),
        combined[-400:],
    )
    runner.check(
        f"{case} command exits nonzero",
        result.returncode != 0,
        f"exit={result.returncode}",
    )
    runner.check(
        f"{case} marked STPA scenarios are not reported as skipped",
        not skips,
        f"skip={skips[:3]}",
    )
    _assert_parent_unchanged(runner, case, before)
    return combined


def qa_alo_05(
    runner: QARunner,
    before: dict[str, str | None],
    alo_04_output: str,
) -> None:
    """QA-ALO-05: isolation and generated-output policy."""
    case = "QA-ALO-05"
    fixtures = _fixture_paths(alo_04_output)
    outputs = _output_paths(alo_04_output)
    if len(fixtures) >= 2:
        runner.check(
            f"{case} live executions report distinct fixture paths",
            len(set(fixtures)) == len(fixtures),
            f"fixtures={fixtures}",
        )
    if len(outputs) >= 2:
        runner.check(
            f"{case} live executions report distinct output paths",
            len(set(outputs)) == len(outputs),
            f"outputs={outputs}",
        )
    status = run_command(["git", "status", "--short"], cwd=PROJECT_ROOT)
    write_capture("alo-05-git-status", status, root=RUN_ROOT)
    staged_generated = [
        line
        for line in status.stdout.splitlines()
        if any(path in line for path in TRACKED_GENERATED) and not line.startswith("??")
    ]
    runner.check(
        f"{case} generated acceptance artifacts are not staged",
        not staged_generated,
        "\n".join(staged_generated),
    )
    tracked = run_command(
        ["git", "ls-files", "--", *TRACKED_GENERATED],
        cwd=PROJECT_ROOT,
    )
    runner.check(
        f"{case} generated acceptance artifacts are untracked",
        tracked.returncode == 0 and not tracked.stdout.strip(),
        tracked.stdout.strip(),
    )
    config = CONFIG_ENV.read_text(encoding="utf-8")
    runner.check(
        f"{case} features map to generated IR",
        'SWARMFORGE_FEATURES_DIR="features"' in config
        and 'SWARMFORGE_ACCEPTANCE_IR_DIR="build/acceptance/ir"' in config
        and 'SWARMFORGE_ACCEPTANCE_GENERATED_DIR="build/acceptance/generated"'
        in config,
    )
    runner.check(
        f"{case} CRAP DRY and mutation still target src/",
        'SWARMFORGE_CRAP_CMD="crap4py src/' in config
        and 'SWARMFORGE_DRY_CMD="drywall --threshold 0.82 ./src"' in config
        and "mutate4py src/" in config,
    )
    _assert_parent_unchanged(runner, case, before)


def main() -> int:
    if not APS_ROOT.is_dir():
        print(f"APS checkout not found: {APS_ROOT}", file=sys.stderr)
        return 2
    RUN_ROOT.mkdir(parents=True, exist_ok=True)
    print(f"QA evidence: {RUN_ROOT.relative_to(PROJECT_ROOT)}", flush=True)
    runner = QARunner()
    before = _snapshot_parent()
    qa_alo_01(runner, before)
    qa_alo_02(runner, before)
    qa_alo_03(runner, before)
    alo_04_output = qa_alo_04(runner, before)
    qa_alo_05(runner, before, alo_04_output)
    return runner.summary()


if __name__ == "__main__":
    sys.exit(main())
