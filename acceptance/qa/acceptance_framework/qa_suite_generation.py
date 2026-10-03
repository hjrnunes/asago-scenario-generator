"""Generation checks for the acceptance-framework QA suite."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from qa_suite_support import (
    collect_generated,
    feature_paths,
    file_digest_map,
    metadata_has_absolute_paths,
    slug,
)


@dataclass(frozen=True)
class GenerationContext:
    """External operations and paths needed by the generation check."""

    project_root: Path
    qa_root: Path
    features_dir: Path
    acceptance_script: Path
    child_env: Callable[..., dict[str, str]]
    run_command: Callable[..., subprocess.CompletedProcess[str]]
    write_capture: Callable[..., Path]


def _qa_layout(context: GenerationContext) -> dict[str, Path]:
    return {
        "ir": context.qa_root / "ir",
        "dry": context.qa_root / "dry",
        "generated": context.qa_root / "generated",
        "mutation": context.qa_root / "mutation",
    }


def _generation_env(context: GenerationContext) -> dict[str, str]:
    layout = _qa_layout(context)
    return context.child_env(
        SWARMFORGE_FEATURES_DIR="features",
        SWARMFORGE_ACCEPTANCE_IR_DIR=str(
            layout["ir"].relative_to(context.project_root)
        ),
        SWARMFORGE_ACCEPTANCE_DRY_DIR=str(
            layout["dry"].relative_to(context.project_root)
        ),
        SWARMFORGE_ACCEPTANCE_GENERATED_DIR=str(
            layout["generated"].relative_to(context.project_root)
        ),
        SWARMFORGE_ACCEPTANCE_MUTATION_DIR=str(
            layout["mutation"].relative_to(context.project_root)
        ),
        ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL="http://127.0.0.1:9/v1",
    )


def qa_afr_01(runner: Any, context: GenerationContext) -> None:
    layout = _qa_layout(context)
    for path in layout.values():
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True)

    first = context.run_command(
        [str(context.acceptance_script)],
        env=_generation_env(context),
        timeout=2400,
    )
    context.write_capture("qa-afr-01-generate", first, root=context.qa_root)
    runner.check(
        "QA-AFR-01 generate completes",
        first.returncode in {0, 1},
        f"exit={first.returncode}",
    )
    first_ir = collect_generated(layout["ir"], "*.json")
    first_tests = collect_generated(layout["generated"], "*_acceptance_test.py")
    first_meta = collect_generated(layout["generated"] / "metadata", "*.json")
    first_contents = {
        "ir": file_digest_map(layout["ir"], "*.json"),
        "tests": file_digest_map(layout["generated"], "*_acceptance_test.py"),
        "meta": file_digest_map(layout["generated"] / "metadata", "*.json"),
    }

    missing: list[str] = []
    for feature in feature_paths(context.features_dir):
        rel = feature.relative_to(context.features_dir)
        ir = layout["ir"] / rel.with_suffix(".json")
        dry = layout["dry"] / rel.with_suffix(".txt")
        test = layout["generated"] / f"{feature.stem}_acceptance_test.py"
        meta = layout["generated"] / "metadata" / f"{slug(feature.stem)}.json"
        for artifact in (ir, dry, test, meta):
            if not artifact.is_file():
                missing.append(str(artifact.relative_to(context.project_root)))
    runner.check(
        "QA-AFR-01 every feature has nested IR/DRY and flat test/metadata",
        not missing,
        f"missing={missing[:8]}",
    )

    abs_problems: list[str] = []
    for meta in (layout["generated"] / "metadata").glob("*.json"):
        abs_problems.extend(metadata_has_absolute_paths(meta, context.project_root))
    runner.check(
        "QA-AFR-01 metadata paths are repo-relative",
        not abs_problems,
        "; ".join(abs_problems[:6]),
    )

    stale_ir = layout["ir"] / "stale-orphan.json"
    stale_test = layout["generated"] / "stale_orphan_acceptance_test.py"
    stale_meta = layout["generated"] / "metadata" / "stale-orphan.json"
    unrelated = layout["generated"] / "keep-me.txt"
    stale_ir.write_text("{}\n")
    stale_test.write_text("# stale\n")
    stale_meta.write_text("{}\n")
    unrelated.write_text("keep\n")

    second = context.run_command(
        [str(context.acceptance_script)],
        env=_generation_env(context),
        timeout=2400,
    )
    context.write_capture("qa-afr-01-refresh", second, root=context.qa_root)
    runner.check(
        "QA-AFR-01 stale mapped artifacts are removed",
        not stale_ir.exists() and not stale_test.exists() and not stale_meta.exists(),
        f"ir={stale_ir.exists()} test={stale_test.exists()} meta={stale_meta.exists()}",
    )
    runner.check(
        "QA-AFR-01 unrelated file is preserved",
        unrelated.is_file() and unrelated.read_text() == "keep\n",
    )

    third = context.run_command(
        [str(context.acceptance_script)],
        env=_generation_env(context),
        timeout=2400,
    )
    context.write_capture("qa-afr-01-repeat", third, root=context.qa_root)
    after_ir = collect_generated(layout["ir"], "*.json")
    after_tests = collect_generated(layout["generated"], "*_acceptance_test.py")
    after_meta = collect_generated(layout["generated"] / "metadata", "*.json")
    after_contents = {
        "ir": file_digest_map(layout["ir"], "*.json"),
        "tests": file_digest_map(layout["generated"], "*_acceptance_test.py"),
        "meta": file_digest_map(layout["generated"] / "metadata", "*.json"),
    }
    runner.check(
        "QA-AFR-01 third refresh is deterministic",
        after_ir == first_ir
        and after_tests == first_tests
        and after_meta == first_meta
        and after_contents == first_contents,
        f"ir_delta={sorted(after_ir ^ first_ir)[:6]} "
        f"test_delta={sorted(after_tests ^ first_tests)[:6]}",
    )


__all__ = ["GenerationContext", "qa_afr_01"]
