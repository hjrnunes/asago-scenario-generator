"""End-to-end QA suite for SP3 prompt revision (bead asago-scenario-generator-072o).

Verifies the revised SP3 Stage 5, Stage 6a, Stage 6b, and Stage 6c
prompts through their actual rendering and deterministic interfaces —
no live LLM endpoint required.

Three execution modes
---------------------
``--static``
    Source-text assertions over the Jinja template files. No imports of
    the project.

``--dynamic``
    Imports the project, renders the actual templates through the
    SP3 prompt builders with minimal typed fixtures, and runs the
    anti-vacuity checks by mutating isolated copies.

``--all``
    Runs both --static and --dynamic.

Checks that require a live LLM endpoint (scenario generation success
rate, prompt quality against a real model) are SKIP — they are not
verifiable without an endpoint and must never be reported as PASS.

Usage::

    uv run python acceptance/qa/sp3_prompt_revision.py --static
    uv run python acceptance/qa/sp3_prompt_revision.py --dynamic
    uv run python acceptance/qa/sp3_prompt_revision.py --all

Exit codes:
    0 — all executed checks passed (skipped checks do not fail)
    1 — one or more executed checks failed
"""

from __future__ import annotations

import argparse
import os
import re
import sys
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
# Paths
# ---------------------------------------------------------------------------

PROMPTS_DIR = (
    PROJECT_ROOT
    / "src"
    / "asago_scenario_generator"
    / "stpa"
    / "scenario_prod"
    / "prompts"
)
STAGE5_SYSTEM = PROMPTS_DIR / "stage5_system.j2"
STAGE5_USER = PROMPTS_DIR / "stage5_user.j2"
STAGE6A_SYSTEM = PROMPTS_DIR / "stage6a_narrative_system.j2"
STAGE6A_USER = PROMPTS_DIR / "stage6a_narrative_user.j2"
STAGE6B_SYSTEM = PROMPTS_DIR / "stage6b_tree_system.j2"
STAGE6B_USER = PROMPTS_DIR / "stage6b_tree_user.j2"
STAGE6C_SYSTEM = PROMPTS_DIR / "stage6c_gherkin_system.j2"
STAGE6C_USER = PROMPTS_DIR / "stage6c_gherkin_user.j2"

# ---------------------------------------------------------------------------
# Compatibility adapter
# ---------------------------------------------------------------------------


def _format_072o_result(result: CheckResult) -> str:
    """Render a harness result with the 072o suite's deferred detail rules."""
    status = result.status or ("PASS" if result.passed else "FAIL")
    text = f"  [{status}] {result.name}"
    if result.detail and status != "PASS":
        text += f"\n         {result.detail}"
    return text


class SP3072oQARunner(QARunner):
    """Shared harness runner with the 072o suite's deferred banner summary."""

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
            print(_format_072o_result(result))
        if skipped:
            print(
                f"\n{skipped} CHECK(S) SKIPPED — live LLM endpoint or "
                f"pipeline run required; see --pipeline."
            )
        if failed > 0:
            print(f"\n{failed} CHECK(S) FAILED")
            return 1
        if passed == 0:
            print("\nNO CHECKS WERE EXECUTED")
            return 0
        print(f"\nALL {passed} EXECUTED CHECK(S) PASSED")
        return 0


# ---------------------------------------------------------------------------
# Source helpers
# ---------------------------------------------------------------------------


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _has_loss_id_restriction(text: str) -> bool:
    """Return True if text contains an explicit L-* only / not H-* instruction."""
    lower = text.lower()
    return any(
        phrase in lower
        for phrase in (
            "only l-* loss ids",
            "l-* loss ids only",
            "use only l-*",
            "only use l-*",
            "do not use h-*",
            "not h-*",
            "loss references use only l-*",
            "consequence references must not use h-*",
            "consequence references use only l-*",
            "h-* hazard ids are not valid",
        )
    )


def _has_code_fence_restriction(text: str) -> bool:
    """Return True if text directly forbids Markdown code fences."""
    lower = text.lower()
    return any(
        phrase in lower
        for phrase in (
            "do not wrap",
            "code fence",
            "code fences",
            "markdown code",
            "no code fences",
        )
    )


# ---------------------------------------------------------------------------
# Static checks — source-text assertions, no imports
# ---------------------------------------------------------------------------


def run_static_checks(runner: QARunner) -> None:
    """Source-text assertions over template files."""

    templates = {
        "Stage 5 system": STAGE5_SYSTEM,
        "Stage 5 user": STAGE5_USER,
        "Stage 6a system": STAGE6A_SYSTEM,
        "Stage 6a user": STAGE6A_USER,
        "Stage 6b system": STAGE6B_SYSTEM,
        "Stage 6b user": STAGE6B_USER,
        "Stage 6c system": STAGE6C_SYSTEM,
        "Stage 6c user": STAGE6C_USER,
    }

    srcs: dict[str, str] = {}
    for label, path in templates.items():
        runner.check(
            f"SP3-072o-static-01: {label} template exists",
            path.is_file(),
            f"Not found: {path}",
        )
        srcs[label] = _read(path) if path.is_file() else ""

    # --- Opener: no STPA-Sec in any system prompt ---------------------------
    for stage in ("Stage 5", "Stage 6a", "Stage 6b", "Stage 6c"):
        sys_src = srcs[f"{stage} system"]
        runner.check(
            f"SP3-072o-static-02: {stage} system prompt does not contain STPA-Sec",
            "STPA-Sec" not in sys_src,
            f"The {stage} system prompt opener must use task-oriented "
            "security-analyst framing, not STPA-Sec jargon.",
        )

    # --- Opener: security analyst framing -----------------------------------
    for stage in ("Stage 5", "Stage 6a", "Stage 6b", "Stage 6c"):
        sys_src = srcs[f"{stage} system"]
        runner.check(
            f"SP3-072o-static-03: {stage} system prompt contains "
            "security analyst framing",
            "security analyst" in sys_src.lower(),
            f"The {stage} system prompt must frame the task as a security "
            "analyst role.",
        )

    # --- Task framing in each system prompt ---------------------------------
    task_phrases = {
        "Stage 5": ("dual-BDI", "scenario specification"),
        "Stage 6a": ("7-step causal narrative",),
        "Stage 6b": ("attack tree",),
        "Stage 6c": ("Gherkin behavior specification",),
    }
    for stage, phrases in task_phrases.items():
        sys_src = srcs[f"{stage} system"].lower()
        all_present = all(phrase.lower() in sys_src for phrase in phrases)
        runner.check(
            f"SP3-072o-static-04: {stage} system prompt contains task framing "
            f"{phrases}",
            all_present,
            f"The {stage} system prompt must describe the task as {phrases}.",
        )

    # --- Stage 6c user prompt: loss IDs only, no hazard IDs -----------------
    usr_6c = srcs["Stage 6c user"]
    runner.check(
        "SP3-072o-static-05: Stage 6c user prompt template contains "
        "valid_loss_ids variable",
        "valid_loss_ids" in usr_6c,
        "The Stage 6c user prompt must pass the valid loss IDs to the model.",
    )
    runner.check(
        "SP3-072o-static-06: Stage 6c user prompt template does not contain "
        "valid_hazard_ids variable",
        "valid_hazard_ids" not in usr_6c,
        "Hazard IDs must not be listed in the Stage 6c user prompt.",
    )
    runner.check(
        "SP3-072o-static-07: Stage 6c user prompt template does not contain "
        "'Valid Hazard IDs' heading",
        "Valid Hazard IDs" not in usr_6c,
        "The Stage 6c user prompt must not have a heading for hazard IDs.",
    )
    runner.check(
        "SP3-072o-static-08: Stage 6c user prompt template restricts loss "
        "references to L-* IDs",
        _has_loss_id_restriction(usr_6c),
        "The Stage 6c user prompt must explicitly instruct the model to use "
        "only L-* loss IDs and not H-* hazard IDs.",
    )

    # --- Stage 6b system prompt: no Markdown code fences --------------------
    sys_6b = srcs["Stage 6b system"]
    runner.check(
        "SP3-072o-static-09: Stage 6b system prompt forbids Markdown code fences",
        _has_code_fence_restriction(sys_6b),
        "The Stage 6b system prompt must directly instruct the model not to "
        "use Markdown code fences.",
    )
    runner.check(
        "SP3-072o-static-10: Stage 6b system prompt still requires YAML output",
        "YAML" in sys_6b,
        "The Stage 6b system prompt must still require YAML output.",
    )

    # --- Variable preservation in user prompts ------------------------------
    required_vars = {
        "Stage 5 user": [
            "defender_bdi_yaml",
            "ica_text",
            "hazardous_context",
            "loss_scenario",
            "control_structure_yaml",
            "target_resp_id",
            "catalog_context",
        ],
        "Stage 6a user": [
            "scenario_spec_yaml",
            "ica_text",
            "loss_scenario",
        ],
        "Stage 6b user": [
            "scenario_spec_yaml",
            "control_structure_yaml",
            "ica_type",
            "control_action",
        ],
        "Stage 6c user": [
            "scenario_spec_yaml",
            "security_constraint",
            "ica_type",
            "control_action",
            "ica_text",
            "valid_loss_ids",
        ],
    }
    for label, vars in required_vars.items():
        usr_src = srcs[label]
        for var in vars:
            runner.check(
                f"SP3-072o-static-11: {label} template contains variable {var}",
                f"{{{{ {var}" in usr_src or f"{{{{{var}" in usr_src,
                f"Variable {var} is missing from the {label} template.",
            )

    # --- No unresolved placeholders in rendered examples ---------------------
    # The templates themselves contain example JSON/YAML with no Jinja
    # placeholders; any template-variable placeholder will be replaced
    # at render time. Static check only looks for stray variable syntax.
    for label, src in srcs.items():
        if not src:
            continue
        # Count actual Jinja variable usages (not examples in prose).
        # A template with required variables is allowed; the check is that
        # no variable looks malformed.
        malformed = re.findall(r"\{\{[^}]*\}\{[^}]*\}", src)
        runner.check(
            f"SP3-072o-static-12: {label} template has no malformed Jinja placeholders",
            len(malformed) == 0,
            f"Found malformed Jinja placeholders: {malformed}",
        )


# ---------------------------------------------------------------------------
# Dynamic checks — import, render, call deterministic builders
# ---------------------------------------------------------------------------


def _build_minimal_fixtures() -> dict[str, Any]:
    """Build minimal SP3 fixtures for prompt rendering."""
    from asago_scenario_generator.stpa.infra.templates import TemplateLoader
    from asago_scenario_generator.stpa.models.control_structure import (
        ControlAction,
        ControlStructure,
        ControlledProcess,
        ElementRef,
        FeedbackChannel,
        ProcessModelPart,
        ReferenceType,
        Responsibility,
        ResponsibilityConstraint,
    )
    from asago_scenario_generator.stpa.models.enriched_threat_set import (
        CatalogMapping,
        StructuralThreat,
    )
    from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
    from asago_scenario_generator.stpa.models.loss_analysis import (
        Hazard,
        Loss,
        LossAnalysis,
        LossProvenance,
        SecurityConstraint,
    )
    from asago_scenario_generator.stpa.models.scenario_spec import (
        AttackerBDI,
        DefenderBDI,
        DefenderBelief,
        DefenderDesire,
        DefenderIntention,
        ScenarioSpec,
        ThreatSource,
    )
    from asago_scenario_generator.stpa.scenario_prod._constants import (
        PROMPTS_DIR as SP3_PROMPTS_DIR,
    )

    resp = Responsibility(
        resp_id="RESP-1",
        description="Validate user input",
        responsibility_constraints=[
            ResponsibilityConstraint(rc_id="RC-1-1", description="Must validate")
        ],
        process_model_parts=[
            ProcessModelPart(pm_id="PM-1-1", description="User state")
        ],
        control_actions=[
            ControlAction(
                ca_id="CA-1-1",
                description="Validate user input",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            )
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-1-1",
                description="Validation feedback",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            )
        ],
    )
    control_structure = ControlStructure(
        responsibilities=[resp],
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="User process")
        ],
    )
    loss_analysis = LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Unauthorized access",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["atlas-001"],
            )
        ],
        use_case_losses=[],
        hazards=[
            Hazard(
                hazard_id="H-1",
                description="Hazardous state",
                related_losses=["L-1"],
            )
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                description="Reject revoked users",
                related_hazards=["H-1"],
            )
        ],
    )
    defender_bdi = DefenderBDI(
        beliefs=[
            DefenderBelief(
                pm_id="PM-1-1",
                content="User is authenticated",
                vulnerability="",
            )
        ],
        desires=[
            DefenderDesire(
                resp_id="RESP-1",
                content="Enforce access control",
            )
        ],
        intentions=[
            DefenderIntention(
                ca_id="CA-1-1",
                content="Validate user credentials",
            )
        ],
    )
    attacker_bdi = AttackerBDI(
        beliefs=["Defender trusts PM-1-1"],
        desires=["Induce unsafe validation"],
        intentions=["Poison FB-1-1 to corrupt PM-1-1"],
    )
    scenario_spec = ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            provenance="structural",
            ica_id="ICA-001",
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=UCAType.not_provided,
        defender_bdi=defender_bdi,
        attacker_bdi=attacker_bdi,
        catalog_context=[
            CatalogMapping(
                catalog="OWASP_AGENTIC",
                id="T-001",
                name="Prompt injection",
                confidence="high",
            )
        ],
        loss_scenario="A revoked user gains access",
    )
    threat = StructuralThreat(
        ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
        ica_text="Validation is not performed",
        hazardous_context="Revoked user is treated as active",
        loss_scenario="A revoked user gains access",
        related_hazards=["H-1"],
        related_constraints=["SC-1"],
        catalog_mappings=[
            CatalogMapping(
                catalog="OWASP_AGENTIC",
                id="T-001",
                name="Prompt injection",
                confidence="high",
            )
        ],
    )
    loader = TemplateLoader(SP3_PROMPTS_DIR)
    security_constraint = loss_analysis.security_constraints[0]
    return {
        "control_structure": control_structure,
        "loss_analysis": loss_analysis,
        "defender_bdi": defender_bdi,
        "attacker_bdi": attacker_bdi,
        "scenario_spec": scenario_spec,
        "threat": threat,
        "loader": loader,
        "security_constraint": security_constraint,
    }


def run_dynamic_checks(runner: QARunner) -> None:
    """Import project, render templates, call deterministic builders."""

    try:
        sys.path.insert(0, str(PROJECT_ROOT))
        from asago_scenario_generator.stpa.scenario_prod.attack_tree import (
            build_attack_tree_prompts,
        )
        from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
            build_bdi_prompts,
        )
        from asago_scenario_generator.stpa.scenario_prod.gherkin import (
            _extract_valid_hazard_ids,
            _extract_valid_loss_ids,
            build_gherkin_prompts,
        )
        from asago_scenario_generator.stpa.scenario_prod.narrative import (
            build_narrative_prompts,
        )
    except Exception as exc:
        runner.check(
            "SP3-072o-dynamic-00: project imports without error",
            False,
            str(exc),
        )
        return

    runner.check(
        "SP3-072o-dynamic-00: project imports without error",
        True,
    )

    fixtures = _build_minimal_fixtures()
    cs = fixtures["control_structure"]
    la = fixtures["loss_analysis"]
    defender_bdi = fixtures["defender_bdi"]
    threat = fixtures["threat"]
    spec = fixtures["scenario_spec"]
    loader = fixtures["loader"]
    sc = fixtures["security_constraint"]

    # Render prompts
    try:
        s5_sys, s5_usr = build_bdi_prompts(defender_bdi, threat, cs, "RESP-1", loader)
        s6a_sys, s6a_usr = build_narrative_prompts(spec, loader)
        s6b_sys, s6b_usr = build_attack_tree_prompts(spec, cs, loader)
        s6c_sys, s6c_usr = build_gherkin_prompts(spec, sc, la, loader)
        rendered = {
            "Stage 5 system": s5_sys,
            "Stage 5 user": s5_usr,
            "Stage 6a system": s6a_sys,
            "Stage 6a user": s6a_usr,
            "Stage 6b system": s6b_sys,
            "Stage 6b user": s6b_usr,
            "Stage 6c system": s6c_sys,
            "Stage 6c user": s6c_usr,
        }
        runner.check(
            "SP3-072o-dynamic-01: all SP3 prompts render without error",
            True,
        )
    except Exception as exc:
        runner.check(
            "SP3-072o-dynamic-01: all SP3 prompts render without error",
            False,
            str(exc),
        )
        return

    # --- No unresolved Jinja placeholders in rendered prompts ---------------
    for label, text in rendered.items():
        runner.check(
            f"SP3-072o-dynamic-02: {label} rendered prompt has no unresolved {{{{ }}}}",
            "{{" not in text and "}}" not in text,
            f"Unresolved Jinja placeholder found in {label}.",
        )

    # --- System prompts: no STPA-Sec and security analyst framing -----------
    for stage in ("Stage 5", "Stage 6a", "Stage 6b", "Stage 6c"):
        sys_text = rendered[f"{stage} system"]
        runner.check(
            f"SP3-072o-dynamic-03: {stage} rendered system prompt has no STPA-Sec",
            "STPA-Sec" not in sys_text,
            f"STPA-Sec must not appear in the {stage} rendered system prompt.",
        )
        runner.check(
            f"SP3-072o-dynamic-04: {stage} rendered system prompt has "
            "security analyst framing",
            "security analyst" in sys_text.lower(),
            f"The {stage} rendered system prompt must frame the task as a "
            "security analyst.",
        )

    # --- Stage 6c user prompt: loss IDs only ----------------------------------
    usr_6c = rendered["Stage 6c user"]
    valid_loss_ids = ", ".join(_extract_valid_loss_ids(la))
    valid_hazard_ids = ", ".join(_extract_valid_hazard_ids(la))
    runner.check(
        "SP3-072o-dynamic-05: Stage 6c rendered user prompt lists valid loss IDs",
        valid_loss_ids in usr_6c,
        f"Expected valid loss IDs '{valid_loss_ids}' in Stage 6c user prompt.",
    )
    runner.check(
        "SP3-072o-dynamic-06: Stage 6c rendered user prompt does not list "
        "valid hazard IDs",
        valid_hazard_ids not in usr_6c,
        f"Stage 6c user prompt should not contain hazard IDs '{valid_hazard_ids}'.",
    )
    runner.check(
        "SP3-072o-dynamic-07: Stage 6c rendered user prompt does not contain "
        "'Valid Hazard IDs' heading",
        "Valid Hazard IDs" not in usr_6c,
        "Stage 6c user prompt should not have a 'Valid Hazard IDs' heading.",
    )
    runner.check(
        "SP3-072o-dynamic-08: Stage 6c rendered user prompt contains an "
        "L-* only instruction",
        _has_loss_id_restriction(usr_6c),
        "Stage 6c user prompt must explicitly restrict consequence references "
        "to L-* loss IDs and not H-* hazard IDs.",
    )

    # --- Stage 6b system prompt: no Markdown code fences --------------------
    sys_6b = rendered["Stage 6b system"]
    runner.check(
        "SP3-072o-dynamic-09: Stage 6b rendered system prompt forbids "
        "Markdown code fences",
        _has_code_fence_restriction(sys_6b),
        "Stage 6b system prompt must instruct the model not to use Markdown "
        "code fences.",
    )
    runner.check(
        "SP3-072o-dynamic-10: Stage 6b rendered system prompt still requires "
        "YAML output",
        "YAML" in sys_6b,
        "Stage 6b system prompt must still require YAML output.",
    )

    # --- Anti-vacuity checks ------------------------------------------------
    _run_anti_vacuity_checks(runner, rendered, la)


# ---------------------------------------------------------------------------
# Anti-vacuity checks
# ---------------------------------------------------------------------------


def _run_anti_vacuity_checks(
    runner: QARunner, rendered: dict[str, str], loss_analysis: Any
) -> None:
    """Anti-vacuity: removing required elements must cause check failure."""

    # --- SP3-072o-40: Remove L-* only restriction from Stage 6c user prompt ----
    vacuous_6c = rendered["Stage 6c user"]
    for phrase in (
        "only L-* loss IDs",
        "L-* loss IDs only",
        "use only L-*",
        "only use L-*",
        "Do not use H-*",
        "not H-*",
        "loss references use only L-*",
        "consequence references must not use H-*",
        "consequence references use only L-*",
        "H-* hazard IDs are not valid",
    ):
        vacuous_6c = vacuous_6c.replace(phrase, "REMOVED")
    runner.check(
        "SP3-072o-dynamic-40: vacuous Stage 6c user prompt (L-* only removed) "
        "fails loss ID restriction",
        not _has_loss_id_restriction(vacuous_6c),
        "Removing the explicit L-* only restriction should make the check fail, "
        "but a restriction phrase was still found.",
    )

    # --- SP3-072o-41: Remove no-code-fences instruction from Stage 6b system prompt
    vacuous_6b = rendered["Stage 6b system"]
    for phrase in (
        "Do not wrap",
        "code fence",
        "code fences",
        "Markdown code",
        "no code fences",
    ):
        vacuous_6b = vacuous_6b.replace(phrase, "REMOVED")
    runner.check(
        "SP3-072o-dynamic-41: vacuous Stage 6b system prompt (no-code-fences "
        "removed) fails code-fence restriction",
        not _has_code_fence_restriction(vacuous_6b),
        "Removing the no-code-fences instruction should make the check fail, "
        "but it was still found.",
    )

    # --- SP3-072o-42: Insert STPA-Sec jargon into Stage 5 system prompt -----
    vacuous_s5 = rendered["Stage 5 system"].replace(
        "security analyst", "security analyst specializing in STPA-Sec"
    )
    has_stpa_sec = "STPA-Sec" in vacuous_s5
    runner.check(
        "SP3-072o-dynamic-42: Stage 5 system prompt with STPA-Sec jargon "
        "fails terminology requirement",
        has_stpa_sec,
        "Inserting STPA-Sec jargon should make the terminology check fail, "
        "but it was not found.",
    )

    # --- Extra: removing security-analyst framing from Stage 6c system prompt
    vacuous_s6c = rendered["Stage 6c system"].replace(
        "security analyst", "REMOVED_ROLE"
    )
    has_analyst = "security analyst" in vacuous_s6c.lower()
    runner.check(
        "SP3-072o-dynamic-43: vacuous Stage 6c system prompt (security "
        "analyst removed) fails framing requirement",
        not has_analyst,
        "Removing the security analyst framing should make the framing check "
        "fail, but it was still found.",
    )


# ---------------------------------------------------------------------------
# Pipeline-mode checks — require a live LLM endpoint
# ---------------------------------------------------------------------------

_PIPELINE_CHECKS: list[tuple[str, str]] = [
    (
        "SP3-072o-pipeline-01: scenario generation success rate remains "
        "unchanged with revised prompts",
        "Run the full SP3 pipeline with the revised prompts and verify that "
        "scenario generation succeeds for the same seeds as the baseline. "
        "Requires a live LLM endpoint.",
    ),
    (
        "SP3-072o-pipeline-02: revised prompts produce valid Gherkin specs "
        "with only L-* loss references",
        "Run the full SP3 pipeline and inspect generated Gherkin consequences; "
        "all loss references must be valid L-* IDs. Requires a live LLM "
        "endpoint.",
    ),
    (
        "SP3-072o-pipeline-03: known baseline preserved — unit 11 expected "
        "failures / ~5897 passed",
        "Run uv run pytest and verify the known-red baseline is unchanged. "
        "Prompt tests should add deterministic passes without changing the "
        "baseline.",
    ),
    (
        "SP3-072o-pipeline-04: known baseline preserved — acceptance 9 "
        "expected failures / 68 passed",
        "Run uv run pytest build/acceptance/generated/ and verify the known-red "
        "baseline is unchanged. Regenerate entrypoints if IR changed.",
    ),
    (
        "SP3-072o-pipeline-05: source ruff check remains clean",
        "Run ruff check src/ and verify no new lint issues.",
    ),
]


def run_pipeline_checks(runner: QARunner) -> None:
    """Register pipeline-mode checks as SKIP when no endpoint is available."""
    enabled = os.environ.get("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE") == "1"

    if not enabled:
        reason = (
            "requires ASAGO_SCENARIO_GENERATOR_QA_PIPELINE=1 and a live LLM endpoint; "
            "no endpoint in this environment"
        )
        for name, _how in _PIPELINE_CHECKS:
            runner.skip(name, reason)
        return

    for name, how in _PIPELINE_CHECKS:
        runner.skip(name, f"manual review: {how}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "QA suite for SP3 prompt revision (bead asago-scenario-generator-072o)"
        ),
    )
    parser.add_argument(
        "--static", action="store_true", help="Run static source-text checks only"
    )
    parser.add_argument(
        "--dynamic",
        action="store_true",
        help="Run dynamic import-and-render checks only",
    )
    parser.add_argument(
        "--pipeline",
        action="store_true",
        help="Run (or list) checks that need a live LLM endpoint",
    )
    parser.add_argument(
        "--all", action="store_true", help="Run static, dynamic, and regression checks"
    )
    args = parser.parse_args()

    if not any([args.static, args.dynamic, args.pipeline, args.all]):
        args.all = True

    runner = SP3072oQARunner()

    if args.static or args.all:
        print("--- Static checks (source text) ---")
        run_static_checks(runner)

    if args.dynamic or args.all:
        print("--- Dynamic checks (import + render + deterministic builders) ---")
        run_dynamic_checks(runner)

    if args.pipeline or args.all:
        print("--- Pipeline-mode checks (live LLM endpoint) ---")
        run_pipeline_checks(runner)

    return runner.summary()


if __name__ == "__main__":
    sys.exit(main())
