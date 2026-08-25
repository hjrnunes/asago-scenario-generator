#!/usr/bin/env python3
"""Parallel runner for the executable end-to-end QA suites.

Suites under ``acceptance/qa/`` each drive the real CLI against a
deterministic loopback endpoint (or read-only project files). They are
independent: every mock server binds an ephemeral port
(``ThreadingHTTPServer(("127.0.0.1", 0))``), every CLI run uses its own
temporary output directory, and each suite manages its own child
environment. That independence means the selected suites can run
concurrently instead of sequentially.

Usage::

    uv run python acceptance/qa/run_suites.py [--serial PATH ...] [--max-parallel N] [--run-root DIR] PATH [PATH ...]

- ``--serial`` suites run first, one at a time (defaults to the
  clean-checkout unit-independence suite, which is heavy: git archive +
  ``uv sync --locked`` + full pytest in a scratch copy).
- The remaining positional suites run concurrently with at most
  ``--max-parallel`` workers (default: one per suite, capped at the
  CPU count).
- Each suite's output goes to ``tmp/qa-run-<timestamp>/<name>.log``.
- Exit status is nonzero if any suite failed; failing suites never kill
  their siblings.

The clean-checkout suite belongs in the serial bucket: it re-syncs and
re-runs pytest inside a fresh clone, and running it inside the pool
would contend with the pool's own pytest/uv invocations for no gain.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
QA_ROOT = Path("acceptance/qa")
DEFAULT_SERIAL = ("clean_checkout_unit_independence.py",)


def _resolve_suite(root: Path, suite: str) -> Path:
    """Resolve a suite path relative to the repo root or the QA directory."""
    candidate = Path(suite)
    if candidate.is_absolute():
        return candidate
    for base in (root, root / QA_ROOT):
        path = base / candidate
        if path.is_file():
            return path
    raise FileNotFoundError(f"QA suite not found: {suite}")


def _run_one(root: Path, suite: Path, log_path: Path) -> dict:
    """Run one suite as ``uv run python <suite>`` and record its outcome."""
    started = time.monotonic()
    try:
        with log_path.open("w", encoding="utf-8") as log:
            completed = subprocess.run(
                ["uv", "run", "python", str(suite)],
                cwd=root,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=7200,
            )
        return {
            "suite": suite,
            "exit": completed.returncode,
            "ok": completed.returncode == 0,
            "seconds": time.monotonic() - started,
            "log": log_path,
        }
    except subprocess.TimeoutExpired:
        return {
            "suite": suite,
            "exit": 124,
            "ok": False,
            "seconds": time.monotonic() - started,
            "log": log_path,
        }


def _print_report(results: list[dict], total_seconds: float) -> int:
    failed = 0
    print("\nQA SUITE RUN SUMMARY")
    print("=" * 78)
    for result in sorted(results, key=lambda r: r["suite"].name):
        status = "PASS" if result["ok"] else "FAIL"
        seconds = f"{result['seconds']:7.1f}s"
        print(f"  {status}  {seconds}  {result['suite']}")
        if not result["ok"]:
            failed += 1
            print(f"         log: {result['log']}")
    print(f"  wall: {total_seconds:7.1f}s  suites: {len(results)}  failed: {failed}")
    print("=" * 78)
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--serial",
        nargs="+",
        default=list(DEFAULT_SERIAL),
        help="Suites to run first, one at a time (default: clean-checkout "
        "unit-independence).",
    )
    parser.add_argument(
        "--no-serial",
        action="store_true",
        help="Skip the serial bucket entirely (pool suites only).",
    )
    parser.add_argument(
        "--max-parallel",
        type=int,
        default=0,
        help="Maximum concurrently running pool suites (default: CPU count).",
    )
    parser.add_argument(
        "--run-root",
        type=Path,
        default=None,
        help="Directory for per-suite logs (default: tmp/qa-run-<timestamp>).",
    )
    parser.add_argument("suites", nargs="*", help="Pool suites to run concurrently.")
    args = parser.parse_args(argv)

    pool_paths = [_resolve_suite(PROJECT_ROOT, s) for s in args.suites]
    if args.no_serial:
        serial_paths = []
    else:
        serial_paths = [_resolve_suite(PROJECT_ROOT, s) for s in args.serial]

    run_root = args.run_root or (
        PROJECT_ROOT
        / "tmp"
        / f"qa-run-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S.%fZ')}"
    )
    run_root.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []
    started_wall = time.monotonic()

    # --- serial bucket (clean-checkout baseline) ---
    for suite in serial_paths:
        log_path = run_root / f"{suite.name}.log"
        results.append(_run_one(PROJECT_ROOT, suite, log_path))

    # --- parallel pool ---
    max_workers = args.max_parallel or max(1, os.cpu_count() or 2)
    max_workers = min(max_workers, len(pool_paths)) if pool_paths else 0
    if pool_paths:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    _run_one, PROJECT_ROOT, suite, run_root / f"{suite.name}.log"
                ): suite
                for suite in pool_paths
            }
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                if not result["ok"]:
                    print(
                        f"[run_suites] suite failed: {result['suite']} "
                        f"(see {result['log']})",
                        file=sys.stderr,
                    )
                else:
                    print(
                        f"[run_suites] completed: {result['suite']} "
                        f"in {result['seconds']:.1f}s"
                    )

    return _print_report(results, time.monotonic() - started_wall)


if __name__ == "__main__":
    sys.exit(main())
