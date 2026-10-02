"""End-to-end QA suite for the acceptance staleness refresh (beads er9q + in8d).

This QA suite verifies that the acceptance specification corpus is consistent
with the shipped Stage 1 and Stage 2 implementations. It operates entirely at
the user interface — the filesystem artifacts a user or QA agent can inspect
(feature files, parser IR, generated entry points, prompt templates). It never
imports the project's Python API.

The refresh has three observable outcomes:

1. **No stale symbol survives.** No feature file, no parser IR, and no prompt
   template still names a symbol, template, or call-log step that the Stage 1
   split-reorder or the Stage 2 restructure deleted.
2. **Every replacement is present.** The renamed templates, renamed call-log
   steps, and new internal models are all named by at least one feature.
3. **Every feature has current generated artifacts.** Each feature file has a
   parser IR, each IR has a generated entry point, and no IR contains text
   that its feature file no longer contains (the staleness that caused the
   original 25 failures).

The suite runs static checks only and needs no LLM endpoint.

Usage::

    uv run python acceptance/qa/snapshot_consistency.py --static

Exit codes:
    0 — all checks passed
    1 — one or more checks failed
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path


QA_MODULES = Path(__file__).resolve().parent
if str(QA_MODULES) not in sys.path:
    sys.path.insert(0, str(QA_MODULES))

from qa_harness import (  # noqa: E402
    PROJECT_ROOT,
    QARunner,
)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROMPTS_DIR = (
    PROJECT_ROOT
    / "src"
    / "asago_scenario_generator"
    / "stpa"
    / "system_model"
    / "prompts"
)
LEGACY_FEATURES_DIR = PROJECT_ROOT / "tests" / "stpa" / "features"
REFRESH_FEATURES_DIR = PROJECT_ROOT / "features" / "acceptance-refresh"
IR_DIR = PROJECT_ROOT / "build" / "acceptance" / "ir"
GENERATED_DIR = PROJECT_ROOT / "build" / "acceptance" / "generated"


# ---------------------------------------------------------------------------
# Stale / replacement vocabulary
#
# A stale symbol is one that the Stage 1 split-reorder (beads tgs3+82t5) or the
# Stage 2 restructure (bead w5tp) deleted. Any acceptance artifact that still
# names one is asserting behavior the system no longer has.
# ---------------------------------------------------------------------------

# Templates deleted by the two restructures.
STALE_TEMPLATES = [
    "stage1a_system.j2",
    "stage1a_user.j2",
    "stage2_call2_system.j2",
    "stage2_call2_user.j2",
]

# Templates that replaced them.
REPLACEMENT_TEMPLATES = [
    "stage1a_risk_system.j2",
    "stage1a_risk_user.j2",
    "stage1a_gap_system.j2",
    "stage1a_gap_user.j2",
    "stage2_call2a_system.j2",
    "stage2_call2a_user.j2",
    "stage2_call2b_system.j2",
    "stage2_call2b_user.j2",
]

# Templates untouched by either restructure — present before and after.
STABLE_TEMPLATES = [
    "stage1b_system.j2",
    "stage1b_user.j2",
    "stage2_call1_system.j2",
    "stage2_call1_user.j2",
    "stage2_call3_system.j2",
    "stage2_call3_user.j2",
    "critic_system.j2",
    "critic_user.j2",
    "revision_system.j2",
    "revision_user.j2",
]

# Removed classes and functions.
STALE_SYMBOLS = [
    "ConnectionSet",
    "connection_assignments",
    "merge_connection_set",
    "_merge_with_fallback",
]

# Classes and functions that replaced them.
REPLACEMENT_SYMBOLS = [
    "CoordinationAnalysis",
    "ControlElementSet",
    "coordination_links",
    "integrity_findings",
]

# Call-log step names deleted by the restructures.

# Call-log step names that replaced them.
REPLACEMENT_STEPS = [
    "risk_derivation",
    "gap_analysis",
    "capability_profile",
    "call_1_requirements",
    "call_2a_responsibilities",
    "call_2b_control_elements",
    "call_3_coordination",
]

# Stage 2 fallback steps that replaced the single merge_connection_set step.
FALLBACK_STEPS = [
    "assemble_control_structure",
    "add_coordination_links",
]

# Prompt content deleted by the Stage 1b rewrite. The five-category
# entry-point checklist and the security-constraint caveat are gone; entry
# points are now derived from the KC taxonomy.
STALE_PROMPT_CONTENT = [
    "User input surfaces",
    "RAG/retrieval data sources",
    "Tool execution results",
    "External data feeds",
    "Admin/config interfaces",
    "Security constraints describe what SHOULD exist",
    "Do not infer tools from security constraints",
    "## Schneider zones",
    "## Emphasis",
]

# Features retired by this refresh because their mechanism was deleted.
RETIRED_FEATURES = [
    "sp1_entry_point_checklist",
    "sp1_security_constraints_contamination",
    "sp1_connection_set_merge",
    "sp1_merge_fallback_degradation",
]

# Features added by this refresh to replace them.
REPLACEMENT_FEATURES = [
    "stage1b-entry-point-guidance",
    "stage1b-grounding",
    "stage2-coordination-analysis",
    "stage2-assembly-fallback",
]

EXPECTED_STAGE2_CALL_COUNT = 4


# ---------------------------------------------------------------------------
# Corpus helpers
# ---------------------------------------------------------------------------


def _strip_manifest_comments(text: str) -> str:
    """Drop leading '#' comment lines from a feature file.

    Mutation stamps and mutation manifests are stored as '#' comments and
    embed historical feature text, including symbol names that the feature
    body no longer asserts. Scanning them would report false staleness.
    """
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


FEATURE_ROOTS = [
    LEGACY_FEATURES_DIR,
    PROJECT_ROOT / "features",
]

# Negation markers that make an assertion a *negative* one. A retired symbol
# named inside a negative assertion is correct — that assertion is what keeps
# the symbol from coming back.
_NEGATION_RE = re.compile(
    r"\b(?:no|not|never|without|absent|retired|removed|omits|excludes)\b",
    re.IGNORECASE,
)


def _feature_files() -> list[Path]:
    """All feature files in the acceptance corpus, across every feature root."""
    files: list[Path] = []
    for root in FEATURE_ROOTS:
        if root.is_dir():
            files += sorted(root.rglob("*.feature"))
    return sorted(set(files))


def _feature_bodies() -> dict[Path, str]:
    """Feature file bodies with mutation-manifest comments stripped."""
    return {
        p: _strip_manifest_comments(p.read_text(encoding="utf-8"))
        for p in _feature_files()
    }


def _ir_files() -> list[Path]:
    """Executable parser IR files.

    Excludes '*_dry.json', which are DRY-checker reports rather than IR the
    acceptance runtime executes.
    """
    return sorted(p for p in IR_DIR.rglob("*.json") if not p.stem.endswith("_dry"))


def _ir_assertions(ir: dict) -> list[tuple[str, bool]]:
    """Flatten an IR to (text, is_negative) pairs.

    Each step contributes its own text, and each example value is paired with
    the polarity of the step that consumes it. A retired symbol supplied as an
    example value to 'the prompts directory does not contain <x>' is therefore
    correctly recognized as a negative assertion rather than staleness.
    """
    pairs: list[tuple[str, bool]] = []
    for section in ("background", "scenarios"):
        node = ir.get(section)
        if node is None:
            continue
        scenarios = node if isinstance(node, list) else [node]
        for scenario in scenarios:
            if not isinstance(scenario, dict):
                continue
            name = str(scenario.get("name", ""))
            steps = [str(s.get("text", "")) for s in scenario.get("steps", []) or []]
            pairs.append((name, bool(_NEGATION_RE.search(name))))
            for step in steps:
                pairs.append((step, bool(_NEGATION_RE.search(step))))
            # An example value is only as affirmative as the steps that
            # actually consume its placeholder. Judging it against every step
            # in the scenario would mis-read a value used solely by a negative
            # assertion whenever some unrelated step is affirmative.
            for example in scenario.get("examples", []) or []:
                if not isinstance(example, dict):
                    continue
                for key, value in example.items():
                    consumers = [s for s in steps if f"<{key}>" in s]
                    negative = bool(consumers) and all(
                        _NEGATION_RE.search(s) for s in consumers
                    )
                    pairs.append((str(value), negative))
    return pairs


def _scenario_blocks(body: str) -> list[str]:
    """Split a feature body into per-scenario blocks.

    Example-table rows carry no negation word of their own, so they must be
    judged against the scenario that contains them. The Feature narrative is
    excluded: it is documentation, and it legitimately names retired symbols
    when explaining what replaced them.
    """
    parts = re.split(r"\n(?=\s*(?:Scenario|Scenario Outline|Background)\b)", body)
    return [p for p in parts[1:] if p.strip()]


def _whole_word(needle: str, haystack: str) -> bool:
    """Match *needle* only at identifier boundaries.

    Prevents 'loss_analysis' from matching inside 'derive_loss_analysis' and
    prevents 'call_2_responsibilities' from matching 'call_2a_responsibilities'.
    """
    return (
        re.search(rf"(?<![A-Za-z0-9_]){re.escape(needle)}(?![A-Za-z0-9_])", haystack)
        is not None
    )


# ---------------------------------------------------------------------------
# Static checks
# ---------------------------------------------------------------------------


def check_templates_on_disk(runner: QARunner) -> None:
    """Prompt templates: stale ones deleted, replacements and stable ones present."""
    for tmpl in STALE_TEMPLATES:
        runner.check(
            f"template: retired {tmpl} is absent from the prompts directory",
            not (PROMPTS_DIR / tmpl).exists(),
        )
    for tmpl in REPLACEMENT_TEMPLATES + STABLE_TEMPLATES:
        runner.check(
            f"template: {tmpl} is present in the prompts directory",
            (PROMPTS_DIR / tmpl).exists(),
        )


def check_prompt_content(runner: QARunner) -> None:
    """Prompt content deleted by the Stage 1b rewrite has not returned."""
    all_prompts = {
        p.name: p.read_text(encoding="utf-8") for p in sorted(PROMPTS_DIR.glob("*.j2"))
    }
    for fragment in STALE_PROMPT_CONTENT:
        offenders = [name for name, body in all_prompts.items() if fragment in body]
        runner.check(
            f"prompt content: retired text {fragment!r} is absent from every template",
            not offenders,
            f"present in: {offenders}" if offenders else "",
        )

    # The KC-driven entry-point guidance that replaced the checklist.
    stage1b = all_prompts.get("stage1b_system.j2", "")
    for fragment in (
        "## Entry Points",
        "KC6.3.3 (RAG) implies an indirect entry point",
        "A component can appear in both tool_inventory and entry_points",
        "Do not invent tools based on what a system like this might have",
    ):
        runner.check(
            f"prompt content: stage1b_system.j2 states {fragment!r}",
            fragment in stage1b,
        )

    # Stage 1b no longer receives any loss-analysis context, which is what
    # made security-constraint contamination possible in the first place.
    stage1b_user = all_prompts.get("stage1b_user.j2", "")
    for fragment in (
        "Security Constraints",
        "Loss Analysis",
        "loss_analysis",
        "all_losses",
    ):
        runner.check(
            f"prompt content: stage1b_user.j2 carries no {fragment!r} context",
            fragment not in stage1b_user,
        )


def check_features_free_of_stale_symbols(runner: QARunner) -> None:
    """No feature file asserts a deleted template, symbol, or step name."""
    bodies = _feature_bodies()
    runner.check(
        "corpus: feature files were discovered",
        len(bodies) > 0,
        f"searched {LEGACY_FEATURES_DIR} and {REFRESH_FEATURES_DIR}",
    )

    # A retired symbol is allowed inside a negative assertion — that is the
    # assertion that keeps it from coming back. Only affirmative uses are
    # staleness, and polarity is a property of the whole scenario block
    # because example rows carry no negation word of their own.
    stale_needles = (
        STALE_TEMPLATES
        + STALE_SYMBOLS
        + [
            "call_2_responsibilities",
            "call_3_connections",
        ]
    )
    for needle in stale_needles:
        offenders = []
        for path, body in bodies.items():
            for block in _scenario_blocks(body):
                if not _whole_word(needle, block):
                    continue
                if _NEGATION_RE.search(block):
                    continue
                first = block.strip().splitlines()[0][:60]
                offenders.append(f"{path.name} :: {first}")
        runner.check(
            f"features: retired symbol {needle!r} is only ever asserted absent",
            not offenders,
            "; ".join(offenders[:4]) if offenders else "",
        )


def check_features_name_replacements(runner: QARunner) -> None:
    """Every replacement template, symbol, and step is asserted somewhere."""
    corpus = "\n".join(_feature_bodies().values())
    for needle in (
        REPLACEMENT_TEMPLATES + REPLACEMENT_SYMBOLS + REPLACEMENT_STEPS + FALLBACK_STEPS
    ):
        runner.check(
            f"features: some feature asserts replacement {needle!r}",
            _whole_word(needle, corpus),
        )


def check_retired_and_replacement_features(runner: QARunner) -> None:
    """Retired features are gone; replacement features exist with IR."""
    for name in RETIRED_FEATURES:
        runner.check(
            f"retirement: feature {name}.feature is removed",
            not (LEGACY_FEATURES_DIR / f"{name}.feature").exists(),
        )
        runner.check(
            f"retirement: IR {name}.json is removed",
            not (IR_DIR / f"{name}.json").exists(),
        )
        runner.check(
            f"retirement: entry point {name}_acceptance_test.py is removed",
            not (GENERATED_DIR / f"{name}_acceptance_test.py").exists(),
        )

    for name in REPLACEMENT_FEATURES:
        runner.check(
            f"replacement: feature {name}.feature exists",
            (REFRESH_FEATURES_DIR / f"{name}.feature").exists(),
        )
        ir_candidates = list(IR_DIR.rglob(f"{name}.json"))
        runner.check(
            f"replacement: IR for {name} exists",
            bool(ir_candidates),
        )
        entry_candidates = list(
            GENERATED_DIR.glob(f"*{name.replace('-', '_')}*_acceptance_test.py")
        )
        entry_candidates += list(GENERATED_DIR.glob(f"*{name}*_acceptance_test.py"))
        runner.check(
            f"replacement: generated entry point for {name} exists",
            bool(entry_candidates),
        )


def check_ir_free_of_stale_symbols(runner: QARunner) -> None:
    """No parser IR carries a deleted template, symbol, or step name.

    This is the specific defect that produced most of the original failures:
    a feature file was updated in place but its IR was never regenerated, so
    the executed IR still asserted the pre-restructure behavior.
    """
    ir_files = _ir_files()
    runner.check(
        "corpus: parser IR files were discovered",
        len(ir_files) > 0,
        f"searched {IR_DIR}",
    )

    parsed: list[tuple[Path, list[tuple[str, bool]]]] = []
    for path in ir_files:
        try:
            parsed.append(
                (path, _ir_assertions(json.loads(path.read_text(encoding="utf-8"))))
            )
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue

    needles = (
        STALE_TEMPLATES
        + STALE_SYMBOLS
        + [
            "call_2_responsibilities",
            "call_3_connections",
        ]
    )
    for needle in needles:
        offenders = []
        for path, pairs in parsed:
            for text, negative in pairs:
                if negative or not _whole_word(needle, text):
                    continue
                offenders.append(f"{path.name} :: {text[:60]}")
                break
        runner.check(
            f"IR: retired symbol {needle!r} is only ever asserted absent",
            not offenders,
            "; ".join(offenders[:4]) if offenders else "",
        )


def check_ir_matches_features(runner: QARunner) -> None:
    """Each IR's scenario names are present in a feature file of the same name.

    Catches the IR-behind-feature drift directly: if a scenario name appears
    in the IR but in no feature file, the IR was generated from an older
    revision of that feature.
    """
    feature_corpus = "\n".join(_feature_bodies().values())
    for path in _ir_files():
        try:
            ir = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        missing = [
            s.get("name", "")
            for s in ir.get("scenarios", []) or []
            if s.get("name") and s["name"] not in feature_corpus
        ]
        runner.check(
            f"IR: every scenario in {path.name} is present in a feature file",
            not missing,
            f"orphan scenarios: {missing[:3]}" if missing else "",
        )


def _entry_point_ir_refs(path: Path) -> list[str]:
    """Return JSON path literals embedded in a generated entry point.

    The generator has emitted both ``Path(r"...json")`` and
    ``_PROJECT_ROOT / "...json"`` forms over its lifetime. Parsing string
    constants keeps these checks independent of either spelling.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError):
        return []
    return sorted(
        {
            node.value
            for node in ast.walk(tree)
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value.endswith(".json")
            )
        }
    )


def _resolve_entry_point_ir_ref(reference: str) -> Path:
    """Resolve a generated entry point's repo-relative or absolute IR path."""
    path = Path(reference)
    return path if path.is_absolute() else PROJECT_ROOT / path


def check_entry_points_resolve(runner: QARunner) -> None:
    """Every generated entry point points at an IR file that exists."""
    entry_points = sorted(GENERATED_DIR.glob("*_acceptance_test.py"))
    runner.check(
        "corpus: generated entry points were discovered",
        len(entry_points) > 0,
        f"searched {GENERATED_DIR}",
    )
    for path in entry_points:
        refs = _entry_point_ir_refs(path)
        missing = [
            reference
            for reference in refs
            if not _resolve_entry_point_ir_ref(reference).exists()
        ]
        runner.check(
            f"entry point: {path.name} references an existing IR file",
            bool(refs) and not missing,
            f"missing IR: {missing}"
            if missing
            else ("no IR reference found" if not refs else ""),
        )


def check_entry_points_cover_ir(runner: QARunner) -> None:
    """Every IR file is executed by exactly one generated entry point."""
    referenced: dict[str, int] = {}
    for path in GENERATED_DIR.glob("*_acceptance_test.py"):
        for reference in _entry_point_ir_refs(path):
            resolved = _resolve_entry_point_ir_ref(reference).resolve().as_posix()
            referenced[resolved] = referenced.get(resolved, 0) + 1

    for ir_path in _ir_files():
        key = ir_path.resolve().as_posix()
        runner.check(
            f"coverage: IR {ir_path.name} is executed by a generated entry point",
            referenced.get(key, 0) >= 1,
        )


def check_entry_points_canonical_ir_location(runner: QARunner) -> None:
    """Every entry point references IR in the canonical build/acceptance/ir/ directory.

    Non-canonical IR locations (tmp/, acceptance/) are how IR drift
    stayed hidden in the original staleness incident: the QA suite's
    ``_ir_files()`` only scans ``IR_DIR``, so IR files outside it were
    invisible to the stale-symbol and IR-matches-features checks.
    """
    entry_points = sorted(GENERATED_DIR.glob("*_acceptance_test.py"))
    for path in entry_points:
        refs = _entry_point_ir_refs(path)
        non_canonical = []
        for reference in refs:
            try:
                _resolve_entry_point_ir_ref(reference).resolve().relative_to(
                    IR_DIR.resolve()
                )
            except ValueError:
                non_canonical.append(reference)
        runner.check(
            f"canonical: {path.name} references IR in {IR_DIR.name}/",
            not non_canonical,
            f"non-canonical: {non_canonical}" if non_canonical else "",
        )


def run_static_checks(runner: QARunner) -> None:
    """Run every check that needs only the filesystem."""
    check_templates_on_disk(runner)
    check_prompt_content(runner)
    check_features_free_of_stale_symbols(runner)
    check_features_name_replacements(runner)
    check_retired_and_replacement_features(runner)
    check_ir_free_of_stale_symbols(runner)
    check_ir_matches_features(runner)
    check_entry_points_resolve(runner)
    check_entry_points_cover_ir(runner)
    check_entry_points_canonical_ir_location(runner)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="End-to-end QA suite for the acceptance staleness refresh."
    )
    parser.add_argument(
        "--static",
        action="store_true",
        help="Run the static checks (the only mode; accepted for compatibility).",
    )
    parser.parse_args()

    runner = QARunner()
    print("=== Static checks (no LLM required) ===")
    run_static_checks(runner)
    return runner.summary()


if __name__ == "__main__":
    sys.exit(main())
