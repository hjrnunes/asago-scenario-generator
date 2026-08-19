"""End-to-end QA suite for the SP1 critic/revision fix.

Covers beads ``asago-scenario-generator-fmn4`` (SP1: revise critic/revision prompts
and fix revision failure) and ``asago-scenario-generator-lrya`` (expose
``next_cm_num`` to the revision prompt), which fmn4 closes.

The change set is confined to
``src/asago_scenario_generator/stpa/system_model/critic.py`` and its four Jinja2
templates (``critic_system.j2``, ``critic_user.j2``,
``revision_system.j2``, ``revision_user.j2``), plus the one-line call-site
wiring in ``run.py`` that supplies the critic's new ``loss_analysis``
context.

Behaviors verified here
-----------------------
1. ``REVISION_MAX_COMPLETION_TOKENS`` is 8192 and is forwarded to the LLM
   client. All three 2026-08-10 production runs died with
   ``LengthFinishReasonError`` at exactly 4096 completion tokens.
2. ``has_unjustified_gaps`` triggers revision from any of the three critic
   probes — ``checklist_results``, ``taxonomy_probe_results``, and the
   adversarial ``gaps`` list — not from ``checklist_results`` alone.
3. ``_compute_next_ids`` returns ``next_cm_num`` derived from the nested
   ``coordination_mechanism.cm_id`` values, and ``revision_system.j2``
   states it. (``lrya``.)
4. ``RevisionDelta`` carries a ``dismissed_gaps`` list and dismissals are
   surfaced in the warnings returned by ``run_revision``.
5. The critic and revision prompts render nested element descriptions,
   the loss analysis, and optional coordination-analysis warnings — not
   bare identifier lists.

Execution modes
---------------
``--static``
    AST and source-text assertions over ``critic.py`` and the four
    templates. No LLM, no imports of the pipeline beyond parsing.

``--dynamic``
    Behavioral assertions driven by direct invocation with a stub LLM
    client that never reaches a network endpoint: ``_compute_next_ids``,
    ``has_unjustified_gaps``, ``RevisionDelta``, ``run_revision``,
    ``run_completeness_critic``, and template rendering. Also executes
    the acceptance IR for this feature set when it has been generated.

``--pipeline``
    Checks that can only be answered by a real model call against a live
    endpoint. These are NOT executed by ``--static``/``--dynamic``/``--all``
    and are NOT silently passed: without ``ASAGO_SCENARIO_GENERATOR_QA_PIPELINE=1``
    and ``--run-dir``, each one is reported as ``SKIP`` and counted
    separately in the summary.

Usage::

    uv run python acceptance/qa/sp1_critic_revision.py --static
    uv run python acceptance/qa/sp1_critic_revision.py --dynamic
    uv run python acceptance/qa/sp1_critic_revision.py --all

    # After a real pipeline run against a live endpoint:
    ASAGO_SCENARIO_GENERATOR_QA_PIPELINE=1 uv run python \\
        acceptance/qa/sp1_critic_revision.py \\
        --pipeline --run-dir output/<run>

Exit codes:
    0 — all executed checks passed (skipped pipeline checks do not fail)
    1 — one or more executed checks failed
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

QA_MODULES = Path(__file__).resolve().parent
if str(QA_MODULES) not in sys.path:
    sys.path.insert(0, str(QA_MODULES))

from qa_harness import (  # noqa: E402
    PROJECT_ROOT,
    CheckResult,
    QARunner,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SRC_ROOT = PROJECT_ROOT / "src"
SYSTEM_MODEL_DIR = SRC_ROOT / "asago_scenario_generator" / "stpa" / "system_model"
CRITIC_FILE = SYSTEM_MODEL_DIR / "critic.py"
RUN_FILE = SYSTEM_MODEL_DIR / "run.py"
PROMPTS_DIR = SYSTEM_MODEL_DIR / "prompts"

CRITIC_SYSTEM = PROMPTS_DIR / "critic_system.j2"
CRITIC_USER = PROMPTS_DIR / "critic_user.j2"
REVISION_SYSTEM = PROMPTS_DIR / "revision_system.j2"
REVISION_USER = PROMPTS_DIR / "revision_user.j2"

ACCEPTANCE_DIR = PROJECT_ROOT / "acceptance"
ACCEPTANCE_RUNTIME = ACCEPTANCE_DIR / "acceptance_runtime.py"
FEATURE_DIR = PROJECT_ROOT / "features" / "critic-revision-fix"
IR_DIR = PROJECT_ROOT / "build" / "acceptance" / "ir" / "critic-revision-fix"

FEATURE_STEMS = [
    "critic-gap-detection",
    "critic-prompt-context",
    "revision-gap-dismissal",
    "revision-all-dismissed-warning",
    "revision-next-cm-id",
    "revision-prompt-context",
    "revision-token-ceiling",
]

EXPECTED_TOKEN_CEILING = 8192
OBSERVED_TRUNCATION_POINT = 4096


# ---------------------------------------------------------------------------
# Compatibility adapter
# ---------------------------------------------------------------------------


def _format_critic_revision_result(result: CheckResult) -> str:
    """Render a harness result with deferred detail rules."""
    status = result.status or ("PASS" if result.passed else "FAIL")
    text = f"  [{status}] {result.name}"
    # Detail explains a failure or a skip; on a pass it is stale advice.
    if result.detail and status != "PASS":
        text += f"\n         {result.detail}"
    return text


class CriticRevisionQARunner(QARunner):
    """Shared harness runner with this suite's deferred banner summary."""

    def record(self, name: str, passed: bool, detail: str = "") -> CheckResult:
        result = CheckResult(name, bool(passed), detail)
        self.results.append(result)
        return result

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        self.record(name, passed, detail)
        return bool(passed)

    def skip(self, name: str, reason: str) -> CheckResult:
        result = CheckResult(name, True, reason, "SKIP")
        self.results.append(result)
        return result

    def summary(self) -> int:
        passed = sum(
            result.passed and result.status != "SKIP" for result in self.results
        )
        failed = sum(
            not result.passed and result.status != "SKIP" for result in self.results
        )
        skipped = sum(result.status == "SKIP" for result in self.results)
        total = len(self.results)
        print()
        print("=" * 72)
        print(
            f"QA SUMMARY: {passed}/{total} passed, "
            f"{failed} failed, {skipped} skipped (not executed)"
        )
        print("=" * 72)
        for result in self.results:
            print(_format_critic_revision_result(result))
        if skipped:
            print(
                f"\n{skipped} PIPELINE-MODE CHECK(S) NOT EXECUTED — these need a "
                f"live LLM endpoint and a completed run; see --pipeline."
            )
        if failed > 0:
            print(f"\n{failed} CHECK(S) FAILED")
            return 1
        if passed == 0:
            print("\nNO CHECKS WERE EXECUTED")
            return 0
        print(f"\nALL {passed} EXECUTED CHECK(S) PASSED")
        return 0


def _temporary_run_dir(prefix: str) -> tempfile.TemporaryDirectory[str]:
    """Create a child-owned temp directory that is always removed."""
    return tempfile.TemporaryDirectory(prefix=prefix)


# ---------------------------------------------------------------------------
# Source helpers
# ---------------------------------------------------------------------------


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _parse(path: Path) -> ast.Module:
    return ast.parse(_read(path), filename=str(path))


def _find_function(tree: ast.Module, name: str) -> ast.FunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _find_class(tree: ast.Module, name: str) -> ast.ClassDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    return None


def _module_constant(tree: ast.Module, name: str) -> Any:
    """Return the literal value of a module-level assignment, or None."""
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    try:
                        return ast.literal_eval(node.value)
                    except ValueError:
                        return None
        if isinstance(node, ast.AnnAssign):
            target = node.target
            if isinstance(target, ast.Name) and target.id == name and node.value:
                try:
                    return ast.literal_eval(node.value)
                except ValueError:
                    return None
    return None


def _kwonly_default(func: ast.FunctionDef, param: str) -> tuple[bool, Any]:
    """Return (present, default_literal) for a keyword-only parameter."""
    args = func.args
    for name, default in zip(args.kwonlyargs, args.kw_defaults):
        if name.arg != param:
            continue
        if default is None:
            return True, "<required>"
        try:
            return True, ast.literal_eval(default)
        except ValueError:
            return True, "<non-literal>"
    for name in args.args:
        if name.arg == param:
            return True, "<positional>"
    return False, None


def _class_field_names(cls: ast.ClassDef) -> set[str]:
    names: set[str] = set()
    for node in cls.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id)
    return names


def _find_call_keywords(func: ast.FunctionDef, call_name: str) -> set[str]:
    """Return keyword-argument names passed to a named call inside *func*.

    Walks the function body for ``Call`` nodes whose target name matches
    *call_name* (either a bare ``Name`` or an ``Attribute.attr``), and
    collects the ``arg`` attribute of every keyword argument.
    """
    names: set[str] = set()
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        func_id: str | None = None
        if isinstance(node.func, ast.Name):
            func_id = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_id = node.func.attr
        if func_id == call_name:
            names.update(kw.arg for kw in node.keywords if kw.arg)
    return names


# ---------------------------------------------------------------------------
# Static checks
# ---------------------------------------------------------------------------


def run_static_checks(runner: QARunner) -> None:
    """AST and source-text assertions. No LLM, no pipeline execution."""

    tree = _parse(CRITIC_FILE)

    # --- Issue 1: token ceiling --------------------------------------------
    ceiling = _module_constant(tree, "REVISION_MAX_COMPLETION_TOKENS")
    runner.check(
        "crf-static-01: REVISION_MAX_COMPLETION_TOKENS is 8192",
        ceiling == EXPECTED_TOKEN_CEILING,
        f"Found {ceiling!r}; all three production runs truncated at "
        f"{OBSERVED_TRUNCATION_POINT}",
    )
    runner.check(
        "crf-static-02: the ceiling exceeds the observed truncation point",
        isinstance(ceiling, int) and ceiling > OBSERVED_TRUNCATION_POINT,
        f"Found {ceiling!r}, need > {OBSERVED_TRUNCATION_POINT}",
    )

    run_revision = _find_function(tree, "run_revision")
    runner.check(
        "crf-static-03: run_revision is defined",
        run_revision is not None,
    )
    if run_revision is not None:
        rev_src = ast.get_source_segment(_read(CRITIC_FILE), run_revision) or ""
        runner.check(
            "crf-static-04: run_revision forwards REVISION_MAX_COMPLETION_TOKENS "
            "to safe_llm_call",
            "max_completion_tokens=REVISION_MAX_COMPLETION_TOKENS" in rev_src,
            "The cap must be passed by name so raising the constant takes effect",
        )
        runner.check(
            "crf-static-05: run_revision does not hardcode a numeric token cap",
            str(OBSERVED_TRUNCATION_POINT) not in rev_src
            and str(EXPECTED_TOKEN_CEILING) not in rev_src,
            "The cap must come from the module constant, not a literal",
        )

    # --- Issue 3: has_unjustified_gaps reads all three probes ---------------
    hug = _find_function(tree, "has_unjustified_gaps")
    runner.check(
        "crf-static-06: has_unjustified_gaps is defined",
        hug is not None,
    )
    if hug is not None:
        hug_src = ast.get_source_segment(_read(CRITIC_FILE), hug) or ""
        for field in ("checklist_results", "taxonomy_probe_results", "gaps"):
            runner.check(
                f"crf-static-07[{field}]: has_unjustified_gaps reads findings.{field}",
                f"findings.{field}" in hug_src,
                "All three critic probes must be able to trigger revision",
            )

    # --- Issue 4 / lrya: next_cm_num ---------------------------------------
    cni = _find_function(tree, "_compute_next_ids")
    runner.check(
        "crf-static-08: _compute_next_ids is defined",
        cni is not None,
    )
    if cni is not None:
        cni_src = ast.get_source_segment(_read(CRITIC_FILE), cni) or ""
        runner.check(
            "crf-static-09: _compute_next_ids emits a next_cm_num key",
            "next_cm_num" in cni_src,
            "cm_id was the only identifier the revision model had to guess",
        )
        runner.check(
            "crf-static-10: next_cm_num is derived from nested "
            "coordination_mechanism.cm_id values",
            "coordination_mechanism" in cni_src and "cm_id" in cni_src,
            "It must come from the mechanisms, not from the link_id numbering",
        )
        for key in ("next_resp_num", "next_cl_num", "next_cp_num"):
            runner.check(
                f"crf-static-11[{key}]: _compute_next_ids still emits {key}",
                key in cni_src,
            )

    # --- Issue 7: RevisionDelta.dismissed_gaps ------------------------------
    delta_cls = _find_class(tree, "RevisionDelta")
    runner.check(
        "crf-static-12: RevisionDelta is defined",
        delta_cls is not None,
    )
    if delta_cls is not None:
        fields = _class_field_names(delta_cls)
        runner.check(
            "crf-static-13: RevisionDelta declares dismissed_gaps",
            "dismissed_gaps" in fields,
            f"Fields found: {sorted(fields)}",
        )
        for field in (
            "new_responsibilities",
            "new_controlled_processes",
            "new_coordination_links",
            "modified_responsibilities",
        ):
            runner.check(
                f"crf-static-14[{field}]: RevisionDelta still declares {field}",
                field in fields,
            )

    # --- Issue 6 / 9: critic accepts loss analysis and call-3 warnings ------
    critic_fn = _find_function(tree, "run_completeness_critic")
    runner.check(
        "crf-static-15: run_completeness_critic is defined",
        critic_fn is not None,
    )
    if critic_fn is not None:
        for param in ("loss_analysis", "call3_warnings"):
            present, default = _kwonly_default(critic_fn, param)
            runner.check(
                f"crf-static-16[{param}]: run_completeness_critic accepts "
                f"an optional {param}",
                present and default is None,
                f"present={present}, default={default!r}; must default to None "
                f"so existing callers keep working",
            )
        critic_src = ast.get_source_segment(_read(CRITIC_FILE), critic_fn) or ""
        # StrictUndefined: the template keys must always be supplied, even
        # when the caller passed nothing.
        for param in ("loss_analysis", "call3_warnings"):
            runner.check(
                f"crf-static-17[{param}]: {param} is passed into the "
                f"critic_user.j2 render call",
                f"{param}={param}" in critic_src.replace(" ", ""),
                "TemplateLoader uses StrictUndefined; every referenced key "
                "must be supplied on every render",
            )

    # --- Call-site wiring in run.py ----------------------------------------
    # Use AST to find the run_completeness_critic call inside _run_stage_2_block
    # and verify it receives the new context parameters. A source-text split
    # on "run_revision" is unreliable because "run_revision" appears in the
    # import block before any call site.
    run_tree = _parse(RUN_FILE)
    stage2_fn = _find_function(run_tree, "_run_stage_2_block")
    if stage2_fn is not None:
        critic_kw = _find_call_keywords(stage2_fn, "run_completeness_critic")
        runner.check(
            "crf-static-18: run.py passes loss_analysis to run_completeness_critic",
            "loss_analysis" in critic_kw,
            f"Keywords found: {sorted(critic_kw)}; without this the loss-analysis "
            f"section is dead code in real runs",
        )
        runner.check(
            "crf-static-18b: run.py passes call3_warnings to run_completeness_critic",
            "call3_warnings" in critic_kw,
            f"Keywords found: {sorted(critic_kw)}; without this the coordination "
            f"warnings section is dead code in real runs",
        )
    else:
        runner.check(
            "crf-static-18: _run_stage_2_block is defined in run.py",
            False,
            "Cannot verify call-site wiring without the function",
        )

    # --- Prompt content -----------------------------------------------------
    critic_user = _read(CRITIC_USER)
    critic_system = _read(CRITIC_SYSTEM)
    revision_system = _read(REVISION_SYSTEM)
    revision_user = _read(REVISION_USER)

    id_only_markers = [
        "map(attribute='pm_id')",
        "map(attribute='ca_id')",
        "map(attribute='fb_id')",
    ]
    for marker in id_only_markers:
        runner.check(
            f"crf-static-19[{marker}]: critic_user.j2 no longer renders "
            f"bare identifier lists",
            marker not in critic_user,
            "The critic must see element descriptions, not identifiers alone",
        )
        runner.check(
            f"crf-static-20[{marker}]: revision_system.j2 no longer renders "
            f"bare identifier lists",
            marker not in revision_system,
        )

    description_markers = [
        "{{ rc.rc_id }}: {{ rc.description }}",
        "{{ pm.pm_id }}: {{ pm.description }}",
        "{{ ca.ca_id }}: {{ ca.description }}",
        "{{ fb.fb_id }}: {{ fb.description }}",
    ]
    for marker in description_markers:
        runner.check(
            f"crf-static-21[{marker}]: critic_user.j2 renders it",
            marker in critic_user,
        )
        runner.check(
            f"crf-static-22[{marker}]: revision_system.j2 renders it",
            marker in revision_system,
        )

    for marker in (
        "{{ pm.feedback_source.type }}",
        "{{ ca.target.type }}",
        "{{ fb.source.type }}",
        "{{ fb.updates }}",
    ):
        runner.check(
            f"crf-static-23[{marker}]: revision_system.j2 shows the "
            f"reference a new element must connect to",
            marker in revision_system,
        )

    # Loss analysis section must use the real LossAnalysis field names.
    # LossAnalysis has risk_card_losses/use_case_losses (no `losses`),
    # Hazard.related_losses (no `loss_ids`), and
    # SecurityConstraint.constraint_id/related_hazards (no `sc_id`/`hazard_id`).
    for marker in (
        "{% if loss_analysis %}",
        "loss_analysis.risk_card_losses",
        "loss_analysis.use_case_losses",
        "loss_analysis.hazards",
        "related_losses",
        "loss_analysis.security_constraints",
        "sc.constraint_id",
        "related_hazards",
        "Loss analysis not available",
    ):
        runner.check(
            f"crf-static-24[{marker}]: critic_user.j2 renders the loss "
            f"analysis section",
            marker in critic_user,
        )
    for wrong in ("loss_analysis.losses", "loss.loss_ids", "sc.sc_id", "sc.hazard_id"):
        runner.check(
            f"crf-static-25[{wrong}]: critic_user.j2 does not reference the "
            f"non-existent field {wrong}",
            wrong not in critic_user,
            "These field names do not exist on LossAnalysis/Hazard/"
            "SecurityConstraint and would raise under StrictUndefined",
        )

    for marker in (
        "{% if call3_warnings %}",
        "Coordination Analysis Warnings",
        "{% for warning in call3_warnings %}",
    ):
        runner.check(
            f"crf-static-26[{marker}]: critic_user.j2 has the optional "
            f"coordination-warnings section",
            marker in critic_user,
        )

    for marker in (
        "New coordination mechanisms",
        "CM-{next_cm_num}",
        "{{ next_cm_num }}",
    ):
        runner.check(
            f"crf-static-27[{marker}]: revision_system.j2 states the "
            f"coordination-mechanism ID rule",
            marker in revision_system,
        )
    for marker in (
        "New controlled processes",
        "CP-{next_cp_num}",
        "{{ next_cp_num }}",
    ):
        runner.check(
            f"crf-static-27b[{marker}]: revision_system.j2 states the "
            f"controlled-process ID rule",
            marker in revision_system,
            "next_cp_num was already computed but never stated in the prompt",
        )

    runner.check(
        "crf-static-28: revision_user.j2 drops the mandatory-add directive",
        "You MUST add at least one element for EACH finding" not in revision_user,
    )
    for marker in (
        "dismiss it with a one-sentence justification",
        "dismissed_gaps",
    ):
        runner.check(
            f"crf-static-29[{marker}]: revision_user.j2 offers the "
            f"add-or-dismiss choice",
            marker in revision_user,
        )
    runner.check(
        "crf-static-30: revision_system.j2 documents the dismissal rule",
        "You may DISMISS a finding if you judge it to be a false positive"
        in revision_system
        and "dismissed_gaps" in revision_system,
    )

    runner.check(
        "crf-static-31: revision_user.j2 no longer duplicates the "
        "control-structure listing",
        "## Current Control Structure" not in revision_user
        and "control_structure.responsibilities" not in revision_user,
        "The listing lives in revision_system.j2 only",
    )
    runner.check(
        "crf-static-32: revision_user.j2 still excludes use_case_text",
        "use_case_text" not in revision_user,
        "Regression guard for the RevRunaway-02 contract",
    )

    for path, name in (
        (CRITIC_SYSTEM, "critic_system.j2"),
        (REVISION_SYSTEM, "revision_system.j2"),
    ):
        runner.check(
            f"crf-static-33[{name}]: the unexplained STPA-Sec framing is gone",
            "STPA-Sec" not in _read(path),
        )

    runner.check(
        "crf-static-34: critic_system.j2 states the false-positive guidance",
        "## False positive guidance" in critic_system
        and "Not every system needs every capability" in critic_system,
    )

    # Preserved contracts that earlier beads established.
    for marker in (
        "checklist_results",
        "taxonomy_probe_results",
        "absent_unjustified",
        "Do NOT suggest specific IDs",
        "{% if taxonomy_probes %}",
    ):
        runner.check(
            f"crf-static-35[{marker}]: critic_system.j2 preserves it",
            marker in critic_system,
        )
    for marker in (
        "## ID format rules",
        "RESP-{next_resp_num}",
        "CL-{next_cl_num}",
        "Do NOT restate the entire control structure",
        "modified_responsibilities list must contain ONLY responsibilities "
        "you are CHANGING",
        "solution-neutrality",
        "ElementRef references must be valid",
        "feedback channel updates must reference a PM in the same responsibility",
    ):
        runner.check(
            f"crf-static-36[{marker}]: revision_system.j2 preserves it",
            marker in revision_system,
        )

    # --- Acceptance feature files -------------------------------------------
    for stem in FEATURE_STEMS:
        feature = FEATURE_DIR / f"{stem}.feature"
        runner.check(
            f"crf-static-37[{stem}]: acceptance feature file exists",
            feature.is_file(),
            f"Missing: {feature}",
        )

    # --- All-dismissed warning (asago-scenario-generator-dy5n) ------------------------
    # The warning construction was extracted from run_revision into a helper;
    # inspect the helper so this contract remains stable across that refactor.
    all_dismissed_fn = _find_function(tree, "_all_dismissed_no_change_warning")
    all_dismissed_src = (
        ast.get_source_segment(_read(CRITIC_FILE), all_dismissed_fn) or ""
        if all_dismissed_fn is not None
        else ""
    )
    runner.check(
        "crf-static-38: all-dismissed helper checks no-change condition",
        "dismissed all findings" in all_dismissed_src
        and "_delta_has_changes" in all_dismissed_src,
        "A distinct deterministic warning must be emitted when all "
        "findings are dismissed and no changes are produced",
    )
    runner.check(
        "crf-static-39: the all-dismissed warning is emitted at most once",
        all_dismissed_src.count("dismissed all findings") <= 1,
        "The warning must appear at most once per revision call — no duplicates",
    )


# ---------------------------------------------------------------------------
# Dynamic checks — no LLM endpoint required
# ---------------------------------------------------------------------------


class _StubLLMClient:
    """Records calls and replays canned content. Never touches a network.

    ``responses`` maps a response_format class to either a dict/model to
    return or an ``Exception`` instance to raise.
    """

    def __init__(self, responses: dict[type, Any] | None = None) -> None:
        self.base_url = "http://qa-stub"
        self.model = "qa-stub-model"
        self.temperature = 0.4
        self.max_completion_tokens = None
        self.calls: list[dict[str, Any]] = []
        self._responses = responses or {}

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: type | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
    ) -> Any:
        from asago_scenario_generator.stpa.infra.llm import LLMResult

        self.calls.append(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "response_format": response_format,
                "max_completion_tokens": max_completion_tokens,
                "temperature": temperature,
            }
        )
        canned = self._responses.get(response_format)
        if isinstance(canned, Exception):
            raise canned
        if canned is None and response_format is not None:
            canned = response_format()
        return LLMResult(
            content=canned,
            prompt_tokens=100,
            completion_tokens=200,
            duration_ms=1,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )


def _qa_control_structure(**overrides: Any):
    """A two-responsibility control structure with one coordination link."""
    from asago_scenario_generator.stpa.models.control_structure import (
        ControlAction,
        ControlStructure,
        ControlledProcess,
        CoordinationLink,
        CoordinationMechanism,
        ElementRef,
        FeedbackChannel,
        ProcessModelPart,
        ReferenceType,
        Responsibility,
        ResponsibilityConstraint,
    )

    def resp(n: int, desc: str) -> Responsibility:
        return Responsibility(
            resp_id=f"RESP-{n}",
            description=desc,
            responsibility_constraints=[
                ResponsibilityConstraint(
                    rc_id=f"RC-{n}-1",
                    description=f"constraint on responsibility {n}",
                )
            ],
            process_model_parts=[
                ProcessModelPart(
                    pm_id=f"PM-{n}-1",
                    description=f"belief held by responsibility {n}",
                    feedback_source=ElementRef(
                        type=ReferenceType.controlled_process, id="CP-1"
                    ),
                )
            ],
            control_actions=[
                ControlAction(
                    ca_id=f"CA-{n}-1",
                    description=f"action issued by responsibility {n}",
                    target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
                )
            ],
            feedback_channels=[
                FeedbackChannel(
                    fb_id=f"FB-{n}-1",
                    description=f"signal observed by responsibility {n}",
                    updates=f"PM-{n}-1",
                    source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
                )
            ],
        )

    cs = ControlStructure(
        responsibilities=[resp(1, "First controller"), resp(2, "Second controller")],
        controlled_processes=[ControlledProcess(cp_id="CP-1", description="Process")],
        coordination_links=[
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1",
                    description="shared belief synchronisation",
                    payload="state",
                ),
                description="Link between the two controllers",
            )
        ],
    )
    return cs.model_copy(update=overrides) if overrides else cs


def _qa_loss_analysis():
    from asago_scenario_generator.stpa.models.loss_analysis import (
        Hazard,
        Loss,
        LossAnalysis,
        LossProvenance,
        SecurityConstraint,
    )

    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="Unauthorised disclosure of customer records",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(
                hazard_id="H-1",
                description="Retrieval returns records outside the session scope",
                related_losses=["L-1"],
            )
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                description="Retrieval must be scoped to the active session",
                related_hazards=["H-1"],
            )
        ],
    )


def _qa_capability_profile():
    from asago_scenario_generator.models.capability_profile import CapabilityProfile

    # has_persistent_memory / multi_agent / hitl are computed from
    # kc_subcodes and cannot be set directly. KC6.3.3 activates the
    # tool_execution zone, which the model requires a tool_inventory for.
    return CapabilityProfile.model_validate(
        {
            "zones_active": ["input", "reasoning", "tool_execution"],
            "kc_subcodes": ["KC6.3.3"],
            "confidence": "high",
            "entry_points": [{"name": "user chat", "direction": "input"}],
            "tool_inventory": [
                {"name": "record_search", "description": "Retrieves customer records"}
            ],
        }
    )


def _qa_findings(**kwargs: Any):
    from asago_scenario_generator.stpa.system_model.critic import CriticFindings

    return CriticFindings(**kwargs)


def _gap(description: str = "Missing input validation"):
    from asago_scenario_generator.stpa.system_model.critic import CriticGap

    return CriticGap(
        gap_type="missing_responsibility",
        description=description,
        related_attack_path="Attacker sends crafted input",
        suggested_remedy="Add an input validation responsibility",
    )


def run_dynamic_checks(runner: QARunner, ir_dir: Path = IR_DIR) -> None:
    """Behavioral assertions driven without any LLM endpoint."""

    sys.path.insert(0, str(SRC_ROOT))

    # --- D1: next_cm_num --------------------------------------------------
    try:
        from asago_scenario_generator.stpa.models.control_structure import (
            ControlStructure,
            CoordinationLink,
            CoordinationMechanism,
        )
        from asago_scenario_generator.stpa.system_model.critic import _compute_next_ids

        base = _qa_control_structure()

        def with_mechanisms(pairs: list[tuple[str, str]]) -> ControlStructure:
            links = [
                CoordinationLink(
                    link_id=link_id,
                    source="RESP-1",
                    target="RESP-2",
                    shared_pm="PM-1-1",
                    coordination_mechanism=CoordinationMechanism(
                        cm_id=cm_id, description="mechanism", payload="state"
                    ),
                    description="link",
                )
                for link_id, cm_id in pairs
            ]
            return base.model_copy(update={"coordination_links": links})

        ids = _compute_next_ids(base)
        runner.check(
            "crf-dynamic-01: _compute_next_ids returns a next_cm_num key",
            "next_cm_num" in ids,
            f"Keys: {sorted(ids)}",
        )

        cases: list[tuple[list[tuple[str, str]], int]] = [
            ([], 1),
            ([("CL-1", "CM-1")], 2),
            ([("CL-1", "CM-1"), ("CL-2", "CM-2")], 3),
            ([("CL-1", "CM-2"), ("CL-2", "CM-1")], 3),
            ([("CL-1", "CM-7")], 8),
            ([("CL-1", "CM-1"), ("CL-2", "CM-4"), ("CL-3", "CM-2")], 5),
        ]
        for pairs, expected in cases:
            got = _compute_next_ids(with_mechanisms(pairs)).get("next_cm_num")
            label = ", ".join(cm for _, cm in pairs) or "no links"
            runner.check(
                f"crf-dynamic-02[{label}]: next_cm_num is {expected}",
                got == expected,
                f"Got {got!r}",
            )

        # next_cm_num must not be derived from the link numbering.
        independent = with_mechanisms([("CL-6", "CM-1")])
        ids = _compute_next_ids(independent)
        runner.check(
            "crf-dynamic-03: next_cm_num is independent of next_cl_num",
            ids.get("next_cl_num") == 7 and ids.get("next_cm_num") == 2,
            f"next_cl_num={ids.get('next_cl_num')}, "
            f"next_cm_num={ids.get('next_cm_num')}",
        )

        for key, expected in (
            ("next_resp_num", 3),
            ("next_cl_num", 2),
            ("next_cp_num", 2),
        ):
            got = _compute_next_ids(base).get(key)
            runner.check(
                f"crf-dynamic-04[{key}]: the existing next-number is unchanged "
                f"({expected})",
                got == expected,
                f"Got {got!r}",
            )
    except Exception as exc:  # pragma: no cover - QA diagnostics
        import traceback

        runner.check(
            "crf-dynamic-01: next_cm_num computation",
            False,
            f"{exc}\n{traceback.format_exc()}",
        )

    # --- D2: has_unjustified_gaps over all three probes ---------------------
    try:
        from asago_scenario_generator.stpa.system_model.critic import (
            has_unjustified_gaps,
        )

        truth_table: list[tuple[str, dict[str, Any], bool]] = [
            (
                "checklist absent_unjustified",
                {"checklist_results": {"a": "absent_unjustified"}},
                True,
            ),
            (
                "checklist mixed with one absent_unjustified",
                {
                    "checklist_results": {
                        "a": "present",
                        "b": "absent_justified",
                        "c": "absent_unjustified",
                    }
                },
                True,
            ),
            (
                "taxonomy absent_unjustified",
                {
                    "checklist_results": {"a": "present"},
                    "taxonomy_probe_results": {"t": "absent_unjustified"},
                },
                True,
            ),
            (
                "taxonomy mixed with one absent_unjustified",
                {
                    "checklist_results": {"a": "present"},
                    "taxonomy_probe_results": {
                        "t1": "present",
                        "t2": "absent_unjustified",
                    },
                },
                True,
            ),
            (
                "adversarial gap only",
                {
                    "checklist_results": {"a": "present"},
                    "taxonomy_probe_results": {"t": "present"},
                    "gaps": [_gap()],
                },
                True,
            ),
            (
                "three adversarial gaps only",
                {"gaps": [_gap("one"), _gap("two"), _gap("three")]},
                True,
            ),
            (
                "all present",
                {
                    "checklist_results": {"a": "present"},
                    "taxonomy_probe_results": {"t": "present"},
                },
                False,
            ),
            (
                "all absent_justified",
                {
                    "checklist_results": {"a": "absent_justified"},
                    "taxonomy_probe_results": {"t": "absent_justified"},
                },
                False,
            ),
            ("empty findings", {}, False),
        ]
        for label, kwargs, expected in truth_table:
            got = has_unjustified_gaps(_qa_findings(**kwargs))
            runner.check(
                f"crf-dynamic-05[{label}]: revision trigger is {expected}",
                got is expected,
                f"Got {got!r}",
            )
    except Exception as exc:  # pragma: no cover
        import traceback

        runner.check(
            "crf-dynamic-05: has_unjustified_gaps truth table",
            False,
            f"{exc}\n{traceback.format_exc()}",
        )

    # --- D3: RevisionDelta.dismissed_gaps ----------------------------------
    try:
        from asago_scenario_generator.stpa.system_model.critic import RevisionDelta

        delta = RevisionDelta()
        runner.check(
            "crf-dynamic-06: RevisionDelta().dismissed_gaps defaults to []",
            getattr(delta, "dismissed_gaps", None) == [],
            f"Got {getattr(delta, 'dismissed_gaps', '<missing>')!r}",
        )
        populated = RevisionDelta(dismissed_gaps=["no multi-agent capability"])
        runner.check(
            "crf-dynamic-07: RevisionDelta accepts dismissal justifications",
            getattr(populated, "dismissed_gaps", None) == ["no multi-agent capability"],
        )
    except Exception as exc:  # pragma: no cover
        import traceback

        runner.check(
            "crf-dynamic-07b: RevisionDelta dismissed_gaps block executed",
            False,
            f"{exc}\n{traceback.format_exc()}",
        )

    # --- D4: run_revision token cap and dismissal reporting -----------------
    try:
        from asago_scenario_generator.stpa.system_model.critic import (
            REVISION_MAX_COMPLETION_TOKENS,
            RevisionDelta,
            run_revision,
        )

        cs = _qa_control_structure()
        findings = _qa_findings(
            checklist_results={"Input validation": "absent_unjustified"}
        )

        client = _StubLLMClient({RevisionDelta: RevisionDelta()})
        with _temporary_run_dir("qa_crf_cap_") as tmpdir:
            revised, warnings = run_revision(
                llm_client=client,
                control_structure=cs,
                critic_findings=findings,
                use_case_text="QA use case",
                run_dir=Path(tmpdir),
            )
        caps = [c["max_completion_tokens"] for c in client.calls]
        runner.check(
            "crf-dynamic-08: run_revision sends max_completion_tokens 8192",
            caps == [EXPECTED_TOKEN_CEILING],
            f"Caps observed: {caps}; constant is {REVISION_MAX_COMPLETION_TOKENS}",
        )
        runner.check(
            "crf-dynamic-09: an empty delta preserves both responsibilities",
            [r.resp_id for r in revised.responsibilities] == ["RESP-1", "RESP-2"],
            f"Got {[r.resp_id for r in revised.responsibilities]}",
        )

        # The rendered system prompt must carry the CM guidance; a
        # StrictUndefined miss would have raised before reaching here.
        system_prompt = client.calls[0]["system_prompt"]
        runner.check(
            "crf-dynamic-10: the revision system prompt states the next "
            "coordination-mechanism number",
            "CM-2" in system_prompt,
            "The fixture has CM-1, so the next available mechanism is CM-2. "
            f"Prompt head: {system_prompt[:160]!r}",
        )
        for token in (
            "belief held by responsibility 1",
            "action issued by responsibility 1",
            "signal observed by responsibility 1",
        ):
            runner.check(
                f"crf-dynamic-11[{token}]: the revision system prompt shows "
                f"the element description",
                token in system_prompt,
            )

        # Dismissal-only delta.
        client = _StubLLMClient(
            {
                RevisionDelta: RevisionDelta(
                    dismissed_gaps=["the system has no multi-agent capability"]
                )
            }
        )
        with _temporary_run_dir("qa_crf_dismiss_") as tmpdir:
            revised, warnings = run_revision(
                llm_client=client,
                control_structure=cs,
                critic_findings=findings,
                use_case_text="QA use case",
                run_dir=Path(tmpdir),
            )
        runner.check(
            "crf-dynamic-12: a dismissal-only revision leaves the structure intact",
            [r.resp_id for r in revised.responsibilities] == ["RESP-1", "RESP-2"],
            f"Got {[r.resp_id for r in revised.responsibilities]}",
        )
        runner.check(
            "crf-dynamic-13: the dismissal justification is reported in the warnings",
            any("the system has no multi-agent capability" in w for w in warnings),
            f"Warnings: {warnings}",
        )
        runner.check(
            "crf-dynamic-14: the dismissal warning is labelled as a dismissal",
            any("dismiss" in w.lower() for w in warnings),
            f"Warnings: {warnings}",
        )

        # No dismissals => no dismissal warning.
        client = _StubLLMClient({RevisionDelta: RevisionDelta()})
        with _temporary_run_dir("qa_crf_nodismiss_") as tmpdir:
            _, warnings = run_revision(
                llm_client=client,
                control_structure=cs,
                critic_findings=findings,
                use_case_text="QA use case",
                run_dir=Path(tmpdir),
            )
        runner.check(
            "crf-dynamic-15: a revision with no dismissals emits no dismissal warning",
            not any("dismiss" in w.lower() for w in warnings),
            f"Warnings: {warnings}",
        )
    except Exception as exc:  # pragma: no cover
        import traceback

        runner.check(
            "crf-dynamic-08: run_revision behavior",
            False,
            f"{exc}\n{traceback.format_exc()}",
        )

    # --- D4b: all-dismissed warning (asago-scenario-generator-dy5n) -------------------
    try:
        from asago_scenario_generator.stpa.system_model.critic import (
            RevisionDelta,
            run_revision,
        )

        cs = _qa_control_structure()

        # Findings with 2 unjustified items (1 gap + 1 checklist).
        findings_two = _qa_findings(
            gaps=[_gap()],
            checklist_results={"Input validation": "absent_unjustified"},
        )

        # All dismissed, no changes → distinct warning.
        delta_all = RevisionDelta(
            dismissed_gaps=[
                "gap 1 is a false positive",
                "checklist item is a false positive",
            ]
        )
        client = _StubLLMClient({RevisionDelta: delta_all})
        with _temporary_run_dir("qa_crf_alldis_") as tmpdir:
            _, warnings = run_revision(
                llm_client=client,
                control_structure=cs,
                critic_findings=findings_two,
                use_case_text="QA use case",
                run_dir=Path(tmpdir),
            )
        runner.check(
            "crf-dynamic-30: all findings dismissed + no changes emits an "
            "all-dismissed warning",
            any("dismissed all findings" in w for w in warnings),
            f"Warnings: {warnings}",
        )
        # Per-dismissal warnings are still present.
        runner.check(
            "crf-dynamic-31: per-dismissal warnings remain when all are dismissed",
            sum(1 for w in warnings if "Revision dismissed finding" in w) == 2,
            f"Expected 2 per-dismissal warnings, got: {warnings}",
        )
        # Exactly one all-dismissed warning (no duplicates).
        all_dismissed_count = sum(1 for w in warnings if "dismissed all findings" in w)
        runner.check(
            "crf-dynamic-32: exactly one all-dismissed warning is emitted",
            all_dismissed_count == 1,
            f"Expected 1, got {all_dismissed_count}: {warnings}",
        )

        # Partial dismissal (1 of 2) → no all-dismissed warning.
        delta_partial = RevisionDelta(dismissed_gaps=["gap 1 is a false positive"])
        client = _StubLLMClient({RevisionDelta: delta_partial})
        with _temporary_run_dir("qa_crf_partial_") as tmpdir:
            _, warnings = run_revision(
                llm_client=client,
                control_structure=cs,
                critic_findings=findings_two,
                use_case_text="QA use case",
                run_dir=Path(tmpdir),
            )
        runner.check(
            "crf-dynamic-33: partial dismissal does not emit all-dismissed warning",
            not any("dismissed all findings" in w for w in warnings),
            f"Warnings: {warnings}",
        )
        runner.check(
            "crf-dynamic-34: partial dismissal still emits per-dismissal warning",
            any("Revision dismissed finding" in w for w in warnings),
            f"Warnings: {warnings}",
        )

        # All dismissed + a new responsibility → warning suppressed.
        from asago_scenario_generator.stpa.models.control_structure import (
            ControlAction,
            ElementRef,
            FeedbackChannel,
            ProcessModelPart,
            ReferenceType,
            Responsibility,
            ResponsibilityConstraint,
        )

        delta_with_change = RevisionDelta(
            new_responsibilities=[
                Responsibility(
                    resp_id="RESP-3",
                    description="Input validation controller",
                    responsibility_constraints=[
                        ResponsibilityConstraint(rc_id="RC-3-1", description="Validate")
                    ],
                    process_model_parts=[
                        ProcessModelPart(pm_id="PM-3-1", description="Input state")
                    ],
                    control_actions=[
                        ControlAction(
                            ca_id="CA-3-1",
                            description="Validate",
                            target=ElementRef(
                                type=ReferenceType.controlled_process, id="CP-1"
                            ),
                        )
                    ],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-3-1",
                            description="Result",
                            updates="PM-3-1",
                            source=ElementRef(
                                type=ReferenceType.controlled_process, id="CP-1"
                            ),
                        )
                    ],
                )
            ],
            dismissed_gaps=[
                "gap 1 is a false positive",
                "checklist item is a false positive",
            ],
        )
        client = _StubLLMClient({RevisionDelta: delta_with_change})
        with _temporary_run_dir("qa_crf_chgsuppress_") as tmpdir:
            revised, warnings = run_revision(
                llm_client=client,
                control_structure=cs,
                critic_findings=findings_two,
                use_case_text="QA use case",
                run_dir=Path(tmpdir),
            )
        runner.check(
            "crf-dynamic-35: all dismissed + new responsibility suppresses "
            "all-dismissed warning",
            not any("dismissed all findings" in w for w in warnings),
            f"Warnings: {warnings}",
        )
        runner.check(
            "crf-dynamic-36: the new responsibility is present in the revised "
            "structure",
            any(r.resp_id == "RESP-3" for r in revised.responsibilities),
            f"Got {[r.resp_id for r in revised.responsibilities]}",
        )

        # All dismissed + a new controlled process → warning suppressed.
        delta_with_cp = RevisionDelta(
            new_controlled_processes=[{"cp_id": "CP-2", "description": "New process"}],
            dismissed_gaps=[
                "gap 1 is a false positive",
                "checklist item is a false positive",
            ],
        )
        client = _StubLLMClient({RevisionDelta: delta_with_cp})
        with _temporary_run_dir("qa_crf_cpsuppress_") as tmpdir:
            _, warnings = run_revision(
                llm_client=client,
                control_structure=cs,
                critic_findings=findings_two,
                use_case_text="QA use case",
                run_dir=Path(tmpdir),
            )
        runner.check(
            "crf-dynamic-37: all dismissed + new controlled process suppresses "
            "all-dismissed warning",
            not any("dismissed all findings" in w for w in warnings),
            f"Warnings: {warnings}",
        )

        # Empty findings + dismissed gaps → no all-dismissed warning.
        findings_empty = _qa_findings()
        delta_dismiss_empty = RevisionDelta(dismissed_gaps=["not applicable"])
        client = _StubLLMClient({RevisionDelta: delta_dismiss_empty})
        with _temporary_run_dir("qa_crf_emptyfind_") as tmpdir:
            _, warnings = run_revision(
                llm_client=client,
                control_structure=cs,
                critic_findings=findings_empty,
                use_case_text="QA use case",
                run_dir=Path(tmpdir),
            )
        runner.check(
            "crf-dynamic-38: empty findings does not emit all-dismissed warning",
            not any("dismissed all findings" in w for w in warnings),
            f"Warnings: {warnings}",
        )

        # All dismissed + modified responsibility → warning suppressed.
        delta_with_mod = RevisionDelta(
            modified_responsibilities=[
                Responsibility(
                    resp_id="RESP-1",
                    description="Updated authorization controller",
                    responsibility_constraints=[
                        ResponsibilityConstraint(
                            rc_id="RC-1-1", description="Must confirm"
                        )
                    ],
                    process_model_parts=[
                        ProcessModelPart(
                            pm_id="PM-1-1",
                            description="Updated user intent state",
                            feedback_source=ElementRef(
                                type=ReferenceType.controlled_process, id="CP-1"
                            ),
                        )
                    ],
                    control_actions=[
                        ControlAction(
                            ca_id="CA-1-1",
                            description="Execute action",
                            target=ElementRef(
                                type=ReferenceType.controlled_process, id="CP-1"
                            ),
                        )
                    ],
                    feedback_channels=[
                        FeedbackChannel(
                            fb_id="FB-1-1",
                            description="Action result",
                            updates="PM-1-1",
                            source=ElementRef(
                                type=ReferenceType.controlled_process, id="CP-1"
                            ),
                        )
                    ],
                )
            ],
            dismissed_gaps=[
                "gap 1 is a false positive",
                "checklist item is a false positive",
            ],
        )
        client = _StubLLMClient({RevisionDelta: delta_with_mod})
        with _temporary_run_dir("qa_crf_modsuppress_") as tmpdir:
            _, warnings = run_revision(
                llm_client=client,
                control_structure=cs,
                critic_findings=findings_two,
                use_case_text="QA use case",
                run_dir=Path(tmpdir),
            )
        runner.check(
            "crf-dynamic-39: all dismissed + modified responsibility "
            "suppresses all-dismissed warning",
            not any("dismissed all findings" in w for w in warnings),
            f"Warnings: {warnings}",
        )

        # RevisionDelta fields remain unchanged.
        runner.check(
            "crf-dynamic-40: RevisionDelta fields remain unchanged after "
            "all-dismissed warning feature",
            set(RevisionDelta.model_fields.keys())
            == {
                "new_responsibilities",
                "new_controlled_processes",
                "new_coordination_links",
                "modified_responsibilities",
                "dismissed_gaps",
            },
            f"Fields: {sorted(RevisionDelta.model_fields.keys())}",
        )
    except Exception as exc:  # pragma: no cover
        import traceback

        runner.check(
            "crf-dynamic-30: all-dismissed warning behavior",
            False,
            f"{exc}\n{traceback.format_exc()}",
        )

    # --- D5: truncation still degrades gracefully ---------------------------
    try:
        from asago_scenario_generator.stpa.system_model.critic import (
            RevisionDelta,
            run_revision,
        )

        class LengthFinishReasonError(Exception):
            """Stand-in with the same class name the OpenAI SDK raises."""

        cs = _qa_control_structure()
        findings = _qa_findings(
            checklist_results={"Input validation": "absent_unjustified"}
        )
        client = _StubLLMClient(
            {RevisionDelta: LengthFinishReasonError("Could not parse response")}
        )
        with _temporary_run_dir("qa_crf_trunc_") as tmpdir:
            revised, warnings = run_revision(
                llm_client=client,
                control_structure=cs,
                critic_findings=findings,
                use_case_text="QA use case",
                run_dir=Path(tmpdir),
            )
        runner.check(
            "crf-dynamic-16: a truncated revision returns the pre-revision "
            "control structure",
            [r.resp_id for r in revised.responsibilities] == ["RESP-1", "RESP-2"],
            f"Got {[r.resp_id for r in revised.responsibilities]}",
        )
        runner.check(
            "crf-dynamic-17: the truncation is reported as a warning",
            any("LengthFinishReasonError" in w for w in warnings),
            f"Warnings: {warnings}",
        )
    except Exception as exc:  # pragma: no cover
        import traceback

        runner.check(
            "crf-dynamic-16: truncation degradation",
            False,
            f"{exc}\n{traceback.format_exc()}",
        )

    # --- D6: critic prompt rendering ---------------------------------------
    # Each rendering path gets its own guard so an early failure cannot
    # silently swallow the checks that follow it.
    from asago_scenario_generator.stpa.infra.templates import TemplateLoader
    from asago_scenario_generator.stpa.system_model.critic import (
        CriticFindings,
        run_completeness_critic,
    )

    loader = TemplateLoader(PROMPTS_DIR)
    cs = _qa_control_structure()
    profile = _qa_capability_profile()

    try:
        # With full context.
        rendered = loader.render_prompt(
            "critic_user.j2",
            use_case_text="QA use case",
            control_structure=cs,
            capability_profile=profile,
            taxonomy_probes=[],
            loss_analysis=_qa_loss_analysis(),
            call3_warnings=["CL-2 shares a process model part outside its scope"],
        )
        for token in (
            "PM-1-1: belief held by responsibility 1",
            "CA-1-1: action issued by responsibility 1",
            "FB-1-1: signal observed by responsibility 1",
            "RC-1-1: constraint on responsibility 1",
            "shared belief synchronisation",
            # Bolded to avoid a substring match against CL-1 in the
            # coordination-links section.
            "**L-1**",
            "**H-1**",
            "**SC-1**",
            "Unauthorised disclosure of customer records",
            "Retrieval returns records outside the session scope",
            "Retrieval must be scoped to the active session",
            "Coordination Analysis Warnings",
            "CL-2 shares a process model part outside its scope",
        ):
            runner.check(
                f"crf-dynamic-18[{token}]: the critic user prompt contains it",
                token in rendered,
            )
        runner.check(
            "crf-dynamic-19: the critic user prompt has no unrendered Jinja expression",
            "{{" not in rendered and "{%" not in rendered,
        )
    except Exception as exc:  # pragma: no cover
        import traceback

        runner.check(
            "crf-dynamic-18: the critic user prompt renders with full context",
            False,
            f"{exc}\n{traceback.format_exc()}",
        )

    try:
        # Without optional context — StrictUndefined must not fire.
        bare = loader.render_prompt(
            "critic_user.j2",
            use_case_text="QA use case",
            control_structure=cs,
            capability_profile=profile,
            taxonomy_probes=[],
            loss_analysis=None,
            call3_warnings=None,
        )
        runner.check(
            "crf-dynamic-20: the critic user prompt renders without a loss analysis",
            "Loss analysis not available" in bare,
        )
        runner.check(
            "crf-dynamic-21: the coordination-warnings section is omitted when "
            "there are none",
            "Coordination Analysis Warnings" not in bare,
        )
    except Exception as exc:  # pragma: no cover
        import traceback

        runner.check(
            "crf-dynamic-20: the critic user prompt renders with no optional context",
            False,
            f"{exc}\n{traceback.format_exc()}",
        )

    try:
        # run_completeness_critic must forward the new context.
        client = _StubLLMClient({CriticFindings: CriticFindings()})
        with _temporary_run_dir("qa_crf_critic_") as tmpdir:
            run_completeness_critic(
                llm_client=client,
                control_structure=cs,
                capability_profile=profile,
                use_case_text="QA use case",
                run_dir=Path(tmpdir),
                loss_analysis=_qa_loss_analysis(),
                call3_warnings=["CL-2 shares a process model part outside its scope"],
            )
        user_prompt = client.calls[0]["user_prompt"]
        for token in (
            "**L-1**",
            "**H-1**",
            "**SC-1**",
            "CL-2 shares a process model part outside its scope",
        ):
            runner.check(
                f"crf-dynamic-22[{token}]: run_completeness_critic forwards it "
                f"into the user prompt",
                token in user_prompt,
            )
        runner.check(
            "crf-dynamic-23: the critic call carries no max_completion_tokens cap",
            client.calls[0]["max_completion_tokens"] is None,
            f"Got {client.calls[0]['max_completion_tokens']!r}",
        )

        # Default call site (no new context) must still render.
        client = _StubLLMClient({CriticFindings: CriticFindings()})
        with _temporary_run_dir("qa_crf_critic_bare_") as tmpdir:
            run_completeness_critic(
                llm_client=client,
                control_structure=cs,
                capability_profile=profile,
                use_case_text="QA use case",
                run_dir=Path(tmpdir),
            )
        runner.check(
            "crf-dynamic-24: run_completeness_critic works without the new "
            "context arguments",
            len(client.calls) == 1
            and "Loss analysis not available" in client.calls[0]["user_prompt"],
        )
    except Exception as exc:  # pragma: no cover
        import traceback

        runner.check(
            "crf-dynamic-22: run_completeness_critic forwards the new context",
            False,
            f"{exc}\n{traceback.format_exc()}",
        )

    # --- D7: revision system prompt renders with absent nested references ---
    try:
        from asago_scenario_generator.stpa.models.control_structure import (
            ProcessModelPart,
        )
        from asago_scenario_generator.stpa.system_model.critic import _compute_next_ids

        stripped = cs.responsibilities[0].model_copy(
            update={
                "process_model_parts": [
                    ProcessModelPart(
                        pm_id="PM-1-1", description="belief with no source"
                    )
                ]
            }
        )
        cs_no_ref = cs.model_copy(
            update={"responsibilities": [stripped, cs.responsibilities[1]]}
        )
        rendered = loader.render_prompt(
            "revision_system.j2",
            control_structure=cs_no_ref,
            **_compute_next_ids(cs_no_ref),
        )
        runner.check(
            "crf-dynamic-25: the revision system prompt renders when a PM has "
            "no feedback source",
            "PM-1-1: belief with no source" in rendered,
        )
        runner.check(
            "crf-dynamic-26: the revision system prompt has no unrendered "
            "Jinja expression",
            "{{" not in rendered and "{%" not in rendered,
        )
    except Exception as exc:  # pragma: no cover
        import traceback

        runner.check(
            "crf-dynamic-25: revision system prompt rendering",
            False,
            f"{exc}\n{traceback.format_exc()}",
        )

    # --- D8: acceptance IR execution ----------------------------------------
    if not ACCEPTANCE_RUNTIME.exists():
        runner.check(
            "crf-dynamic-27: acceptance runtime is available",
            False,
            f"Missing: {ACCEPTANCE_RUNTIME}",
        )
        return

    sys.path.insert(0, str(ACCEPTANCE_RUNTIME.parent))
    for stem in FEATURE_STEMS:
        ir = ir_dir / f"{stem}.json"
        if not ir.exists():
            runner.check(
                f"crf-dynamic-28[{stem}]: acceptance IR has been generated",
                False,
                f"Missing: {ir} — run the APS parser over "
                f"{FEATURE_DIR / (stem + '.feature')}",
            )
            continue
        try:
            from acceptance_runtime import execute_ir

            passed, output = execute_ir(str(ir))
            fail_lines = [
                line for line in output.splitlines() if line.startswith("FAIL")
            ]
            runner.check(
                f"crf-dynamic-29[{stem}]: all acceptance scenarios pass",
                passed,
                f"{len(fail_lines)} failing: {fail_lines[:5]}",
            )
        except Exception as exc:  # pragma: no cover
            runner.check(
                f"crf-dynamic-29[{stem}]: acceptance runtime executes",
                False,
                str(exc),
            )


# ---------------------------------------------------------------------------
# Pipeline-mode checks — require a live LLM endpoint and a completed run
# ---------------------------------------------------------------------------

_PIPELINE_CHECKS: list[tuple[str, str]] = [
    (
        "crf-pipeline-01: the revision call completes without LengthFinishReasonError",
        "Read calls.jsonl and assert the stage_2/revision entry has "
        "success=true and no LengthFinishReasonError. The 4096 ceiling "
        "produced this error on all three 2026-08-10 runs.",
    ),
    (
        "crf-pipeline-02: the revision completion stays under the 8192 ceiling",
        "Read calls.jsonl and assert the stage_2/revision entry's "
        "completion_tokens is strictly less than 8192; equality means the "
        "response was truncated again.",
    ),
    (
        "crf-pipeline-03: the revision produces a non-empty delta",
        "Compare control-structure.yaml against the pre-revision structure "
        "and assert at least one element was added or modified, or that "
        "dismissed_gaps explains why not.",
    ),
    (
        "crf-pipeline-04: cm_id renumber warnings become rare",
        "This is the lrya acceptance question, and the bead states it needs "
        "a run to validate the effect rather than unit tests. Count "
        "'Renumber cm_id' warnings across a set of runs and compare against "
        "the Airbnb baseline of 4 out of 4. Static tests can only prove "
        "next_cm_num is supplied, never that the model uses it.",
    ),
    (
        "crf-pipeline-05: the critic stops flagging capabilities the system "
        "does not have",
        "Prompt effectiveness. Review the stage_2/critic findings against "
        "the capability profile and count absent_unjustified results for "
        "capabilities the profile marks absent. Not decidable offline.",
    ),
    (
        "crf-pipeline-06: the critic's findings reference the loss analysis",
        "Prompt effectiveness. Review the critic gaps for references to "
        "hazards from loss-analysis.yaml. The prompt now carries them; "
        "whether the model uses them is a model-behavior question.",
    ),
    (
        "crf-pipeline-07: dismissals are used for genuine false positives",
        "Review the dismissal justifications surfaced in the run warnings "
        "and judge whether each declined finding really was a false "
        "positive rather than work the model avoided.",
    ),
    (
        "crf-pipeline-08: the all-dismissed/no-change warning surfaces in real runs",
        "Read the run warnings (run-manifest.yaml or calls.jsonl) and check "
        "whether the 'dismissed all findings' warning appears when the "
        "revision dismissed everything and produced no changes. A live LLM "
        "endpoint is needed to observe this behavior — no static test can "
        "determine whether the model actually dismisses all findings.",
    ),
]


def run_pipeline_checks(runner: QARunner, run_dir: Path | None) -> None:
    """Register pipeline-mode checks.

    These need a real model call. When the environment is not authorised
    for a pipeline run, each is recorded as SKIP — never as PASS — so a
    missing endpoint can never be mistaken for a verified behavior.
    """
    enabled = os.environ.get("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE") == "1"

    if not enabled or run_dir is None:
        reason = (
            "requires ASAGO_SCENARIO_GENERATOR_QA_PIPELINE=1 and --run-dir <completed run>; "
            "no live LLM endpoint in this environment"
        )
        for name, _how in _PIPELINE_CHECKS:
            runner.skip(name, reason)
        return

    if not run_dir.is_dir():
        for name, _how in _PIPELINE_CHECKS:
            runner.check(name, False, f"Run directory not found: {run_dir}")
        return

    calls_path = run_dir / "calls.jsonl"
    if not calls_path.is_file():
        for name, _how in _PIPELINE_CHECKS:
            runner.check(name, False, f"Missing call log: {calls_path}")
        return

    entries = []
    for line in calls_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            entries.append(json.loads(line))
    revision_entries = [
        e
        for e in entries
        if e.get("stage") == "stage_2" and e.get("step") == "revision"
    ]

    runner.check(
        _PIPELINE_CHECKS[0][0],
        bool(revision_entries)
        and all(
            e.get("success") is True
            and "LengthFinishReasonError" not in str(e.get("error") or "")
            for e in revision_entries
        ),
        f"{len(revision_entries)} revision entries: "
        f"{[(e.get('success'), e.get('error')) for e in revision_entries]}",
    )
    runner.check(
        _PIPELINE_CHECKS[1][0],
        bool(revision_entries)
        and all(
            int(e.get("completion_tokens") or 0) < EXPECTED_TOKEN_CEILING
            for e in revision_entries
        ),
        f"completion_tokens: {[e.get('completion_tokens') for e in revision_entries]}",
    )

    # The remaining checks are judgement calls over run artifacts and are
    # not auto-decidable; they stay skipped with their procedure printed.
    for name, how in _PIPELINE_CHECKS[2:]:
        runner.skip(name, f"manual review against {run_dir}: {how}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "QA suite for the SP1 critic/revision fix "
            "(asago-scenario-generator-fmn4, closes asago-scenario-generator-lrya)"
        ),
    )
    parser.add_argument("--static", action="store_true", help="Run static checks only")
    parser.add_argument(
        "--dynamic", action="store_true", help="Run dynamic checks only"
    )
    parser.add_argument(
        "--pipeline",
        action="store_true",
        help="Run (or list) checks that need a live LLM endpoint",
    )
    parser.add_argument(
        "--all", action="store_true", help="Run static and dynamic checks"
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help="Completed pipeline run directory, for --pipeline",
    )
    parser.add_argument(
        "--ir-dir",
        type=Path,
        default=IR_DIR,
        help="Acceptance IR directory; defaults to the generated snapshot",
    )
    args = parser.parse_args()

    if not any([args.static, args.dynamic, args.pipeline, args.all]):
        args.all = True

    runner = CriticRevisionQARunner()

    if args.static or args.all:
        print("--- Static checks (AST + prompt source) ---")
        run_static_checks(runner)

    if args.dynamic or args.all:
        print("--- Dynamic checks (direct invocation + acceptance runtime) ---")
        run_dynamic_checks(runner, args.ir_dir)

    if args.pipeline or args.all:
        print("--- Pipeline-mode checks (live LLM endpoint) ---")
        run_pipeline_checks(runner, args.run_dir)

    return runner.summary()


if __name__ == "__main__":
    sys.exit(main())
