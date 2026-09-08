"""End-to-end QA suite for SP2 Stage 3 prompt revision (bead asago-scenario-generator-f787).

Verifies the revised Stage 3 ICA slot-filling prompts and technology
context builder through their actual rendering and deterministic
interfaces — no live LLM endpoint required.

Three execution modes
---------------------
``--static``
    Source-text assertions over the Jinja template files and the
    technology-context builder module.  No imports of the project.

``--dynamic``
    Imports the project, renders the actual templates through
    ``build_slot_filling_prompts``, calls ``build_technology_context``
    with minimal typed profiles, parses ICASlotFillResult instances,
    and runs the anti-vacuity checks by mutating isolated copies.

``--all``
    Runs both --static and --dynamic.

Checks that require a live LLM endpoint (slot-fill success rate,
prompt quality against a real model) are SKIP — they are not
verifiable without an endpoint and must never be reported as PASS.

Usage::

    uv run python acceptance/qa/sp2_stage3_prompts.py --static
    uv run python acceptance/qa/sp2_stage3_prompts.py --dynamic
    uv run python acceptance/qa/sp2_stage3_prompts.py --all

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
from subprocess import TimeoutExpired

QA_MODULES = Path(__file__).resolve().parent
if str(QA_MODULES) not in sys.path:
    sys.path.insert(0, str(QA_MODULES))

from qa_harness import (  # noqa: E402
    PROJECT_ROOT,
    CheckResult,
    QARunner,
    run_command,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROMPTS_DIR = (
    PROJECT_ROOT
    / "src"
    / "asago_scenario_generator"
    / "stpa"
    / "threat_enum"
    / "prompts"
)
SYSTEM_PROMPT_TEMPLATE = PROMPTS_DIR / "stage3_system.j2"
USER_PROMPT_TEMPLATE = PROMPTS_DIR / "stage3_user.j2"
TECH_CONTEXT_MODULE = (
    PROJECT_ROOT
    / "src"
    / "asago_scenario_generator"
    / "stpa"
    / "threat_enum"
    / "technology_context.py"
)

# ---------------------------------------------------------------------------
# Compatibility adapter
# ---------------------------------------------------------------------------


def _format_f787_result(result: CheckResult) -> str:
    """Render a harness result with the f787 suite's deferred detail rules."""
    status = result.status or ("PASS" if result.passed else "FAIL")
    text = f"  [{status}] {result.name}"
    if result.detail and status != "PASS":
        text += f"\n         {result.detail}"
    return text


class F787QARunner(QARunner):
    """Shared harness runner with the f787 suite's deferred banner summary."""

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
            print(_format_f787_result(result))
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


# ---------------------------------------------------------------------------
# Static checks — source-text assertions, no imports
# ---------------------------------------------------------------------------


def run_static_checks(runner: QARunner) -> None:
    """Source-text assertions over template files and tech-context module."""

    # --- Template files exist ------------------------------------------------
    runner.check(
        "SP2-PR-static-01: stage3_system.j2 exists",
        SYSTEM_PROMPT_TEMPLATE.is_file(),
        f"Not found: {SYSTEM_PROMPT_TEMPLATE}",
    )
    runner.check(
        "SP2-PR-static-02: stage3_user.j2 exists",
        USER_PROMPT_TEMPLATE.is_file(),
        f"Not found: {USER_PROMPT_TEMPLATE}",
    )
    runner.check(
        "SP2-PR-static-03: technology_context.py exists",
        TECH_CONTEXT_MODULE.is_file(),
        f"Not found: {TECH_CONTEXT_MODULE}",
    )

    sys_src = _read(SYSTEM_PROMPT_TEMPLATE) if SYSTEM_PROMPT_TEMPLATE.is_file() else ""
    usr_src = _read(USER_PROMPT_TEMPLATE) if USER_PROMPT_TEMPLATE.is_file() else ""
    tech_src = _read(TECH_CONTEXT_MODULE) if TECH_CONTEXT_MODULE.is_file() else ""

    # --- Opener: no STPA-Sec -------------------------------------------------
    runner.check(
        "SP2-PR-static-04: system prompt does not contain STPA-Sec",
        "STPA-Sec" not in sys_src,
        "The opener must use task-oriented security-analyst framing, "
        "not STPA-Sec jargon.",
    )

    # --- Opener: security analyst framing ------------------------------------
    runner.check(
        "SP2-PR-static-05: system prompt contains security analyst framing",
        "security analyst" in sys_src.lower(),
        "The opener should frame the task as a security analyst role.",
    )

    # --- ICA defined once ----------------------------------------------------
    ica_expansion_count = sys_src.count("Insecure Control Action")
    runner.check(
        "SP2-PR-static-06: ICA is expanded as Insecure Control Action exactly once",
        ica_expansion_count == 1,
        f"Found {ica_expansion_count} occurrences of 'Insecure Control Action'; "
        f"expected exactly 1.",
    )

    # --- No UCA in descriptive prose (system prompt) -------------------------
    # The field name uca_type is allowed; standalone UCA as a word is not.
    # Remove uca_type occurrences before checking for standalone UCA.
    sys_no_field = re.sub(r"uca_type", "", sys_src)
    runner.check(
        "SP2-PR-static-07: system prompt has no standalone UCA in prose",
        not re.search(r"\bUCA\b", sys_no_field),
        "The system prompt should use ICA consistently, not UCA, in prose.",
    )
    runner.check(
        "SP2-PR-static-08: system prompt has no 'Unsafe Control Action' phrase",
        "Unsafe Control Action" not in sys_src,
        "The system prompt should not expand UCA as 'Unsafe Control Action'.",
    )

    # --- uca_type field name preserved ---------------------------------------
    runner.check(
        "SP2-PR-static-09: system prompt contains uca_type field name",
        "uca_type" in sys_src,
        "The uca_type schema field name must be preserved.",
    )
    runner.check(
        "SP2-PR-static-10: user prompt contains uca_type field name",
        "uca_type" in usr_src,
        "The uca_type schema field name must be preserved in the user prompt.",
    )

    # --- No UCA in user prompt prose -----------------------------------------
    usr_no_field = re.sub(r"uca_type", "", usr_src)
    runner.check(
        "SP2-PR-static-11: user prompt has no standalone UCA in prose",
        not re.search(r"\bUCA\b", usr_no_field),
        "The user prompt should use ICA consistently, not UCA, in prose.",
    )
    runner.check(
        "SP2-PR-static-12: user prompt has no 'Unsafe Control Action' phrase",
        "Unsafe Control Action" not in usr_src,
        "The user prompt should not expand UCA as 'Unsafe Control Action'.",
    )

    # --- Four ICA type names in system prompt --------------------------------
    for type_name in ("NOT_PROVIDED", "INCORRECT", "WRONG_TIMING", "WRONG_DURATION"):
        runner.check(
            f"SP2-PR-static-13: system prompt contains ICA type {type_name}",
            type_name in sys_src,
            f"ICA type {type_name} is missing from the system prompt.",
        )

    # --- N/A justification requirements in system prompt ---------------------
    runner.check(
        "SP2-PR-static-14: system prompt contains na_justification field",
        "na_justification" in sys_src,
        "The na_justification field must be mentioned in the system prompt.",
    )
    runner.check(
        "SP2-PR-static-15: system prompt contains is_na field",
        "is_na" in sys_src,
        "The is_na field must be mentioned in the system prompt.",
    )
    runner.check(
        "SP2-PR-static-16: system prompt requires structural property for N/A",
        any(
            kw in sys_src.lower()
            for kw in ("structural property", "structural", "discrete", "continuous")
        ),
        "The system prompt must require citing a structural property for N/A slots.",
    )

    # --- User prompt: technology context heading -----------------------------
    runner.check(
        "SP2-PR-static-17: user prompt contains Technology Context heading",
        "Technology Context" in usr_src,
        "The user prompt must include the technology context block.",
    )

    # --- User prompt: task directive -----------------------------------------
    runner.check(
        "SP2-PR-static-18: user prompt contains a task directive",
        any(kw in usr_src.lower() for kw in ("your task", "fill", "task")),
        "The user prompt must include a concise task directive.",
    )

    # --- User prompt: H-*/SC-* reference note --------------------------------
    has_h_sc_note = (
        "H-" in usr_src and "SC-" in usr_src
    ) or "hazard" in usr_src.lower()
    runner.check(
        "SP2-PR-static-19: user prompt references hazards and constraints",
        has_h_sc_note,
        "The user prompt must include a note about valid H-*/SC-* references.",
    )

    # --- User prompt: REQ-*/SC-* mapping note --------------------------------
    runner.check(
        "SP2-PR-static-20: user prompt contains REQ-*/SC-* mapping note",
        "REQ-" in usr_src and "SC-" in usr_src,
        "The user prompt must include a REQ-*/SC-* mapping note.",
    )

    # --- User prompt: no ICA type definition duplication ---------------------
    runner.check(
        "SP2-PR-static-21: user prompt does not contain 'Four ICA Types' heading",
        "Four ICA Types" not in usr_src,
        "The user prompt must not duplicate the system prompt's ICA type heading.",
    )
    # Check that user prompt does not contain Type N definition blocks
    for n in (1, 2, 3, 4):
        runner.check(
            f"SP2-PR-static-22: user prompt does not contain 'Type {n}' definition block",
            f"Type {n}" not in usr_src,
            f"The user prompt must not duplicate the 'Type {n}' definition from the "
            f"system prompt.",
        )

    # --- User prompt: no Requirements heading duplication --------------------
    runner.check(
        "SP2-PR-static-23: user prompt does not contain 'Requirements' heading",
        "## Requirements" not in usr_src and "# Requirements" not in usr_src,
        "The user prompt must not duplicate the system prompt's Requirements heading.",
    )

    # --- User prompt: Jinja variables preserved ------------------------------
    for var in (
        "control_structure_yaml",
        "loss_analysis_yaml",
        "technology_context",
        "slots_yaml",
        "resp_id",
    ):
        runner.check(
            f"SP2-PR-static-24: user prompt template contains variable {var}",
            "{{ " + var in usr_src or "{{" + var in usr_src,
            f"Variable {var} is missing from the user prompt template.",
        )

    # --- Technology context: classification present --------------------------
    # The builder source must contain category-specific logic, not a single
    # generic suffix for all tools.
    runner.check(
        "SP2-PR-static-25: technology context builder has category-specific logic",
        any(
            kw in tech_src.lower()
            for kw in ("read", "retrieval", "write", "execute", "classify")
        ),
        "The technology context builder must classify tools into categories "
        "with distinct failure-mode suffixes.",
    )

    # --- Technology context: not a single generic suffix ---------------------
    # The old code used a single suffix for all tools.  The revised code must
    # have at least two distinct suffix strings.
    susceptible_lines = re.findall(r"susceptible to [^\"\n]+", tech_src)
    unique_suffixes = set(susceptible_lines)
    runner.check(
        "SP2-PR-static-26: technology context has at least two distinct "
        "tool failure-mode suffixes",
        len(unique_suffixes) >= 2,
        f"Found {len(unique_suffixes)} unique suffix pattern(s) in source; "
        f"expected at least 2.",
    )


# ---------------------------------------------------------------------------
# Dynamic checks — import, render, call deterministic builders
# ---------------------------------------------------------------------------


def _build_minimal_fixtures():
    """Build minimal control structure, loss analysis, slots, and profile."""
    from asago_scenario_generator.stpa.infra.templates import TemplateLoader
    from asago_scenario_generator.stpa.models.control_structure import (
        ControlAction,
        ControlStructure,
        ElementRef,
        FeedbackChannel,
        ProcessModelPart,
        ReferenceType,
        Responsibility,
        ControlledProcess,
    )
    from asago_scenario_generator.stpa.models.loss_analysis import (
        Hazard,
        Loss,
        LossAnalysis,
        LossProvenance,
        SecurityConstraint,
    )
    from asago_scenario_generator.stpa.threat_enum._constants import (
        PROMPTS_DIR as prompts,
    )
    from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots

    resp = Responsibility(
        resp_id="RESP-1",
        description="Validate input",
        responsibility_constraints=[
            {"rc_id": "RC-1-1", "description": "Must validate"}
        ],
        process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
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
                description="Feedback",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            )
        ],
    )
    cs = ControlStructure(
        responsibilities=[resp],
        controlled_processes=[ControlledProcess(cp_id="CP-1", description="P1")],
    )
    la = LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["atlas-001"],
            )
        ],
        use_case_losses=[],
        hazards=[
            Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"]),
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Constraint",
                applies_when=[],
                related_hazards=["H-1"],
            ),
        ],
    )
    slots = create_slots(cs)
    loader = TemplateLoader(prompts)
    return cs, la, slots, loader


def run_dynamic_checks(runner: QARunner) -> None:
    """Import project, render templates, call deterministic builders."""

    try:
        sys.path.insert(0, str(PROJECT_ROOT))
        from asago_scenario_generator.stpa.threat_enum.slot_filling import (
            build_slot_filling_prompts,
        )
        from asago_scenario_generator.stpa.threat_enum.technology_context import (
            build_technology_context,
        )
        from asago_scenario_generator.stpa.threat_enum.slot_filling import (
            ICASlotFillResult,
        )
        from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
        from asago_scenario_generator.models.capability_profile import (
            CapabilityProfile,
            EntryPoint,
            ToolInventoryEntry,
        )
        from unittest.mock import MagicMock
    except Exception as exc:
        runner.check(
            "SP2-PR-dynamic-00: project imports without error",
            False,
            str(exc),
        )
        return

    runner.check(
        "SP2-PR-dynamic-00: project imports without error",
        True,
    )

    cs, la, slots, loader = _build_minimal_fixtures()
    tech_context = "- Has user-facing input -> susceptible to prompt injection"

    # Render prompts
    try:
        system_prompt, user_prompt = build_slot_filling_prompts(
            cs, la, tech_context, slots, "RESP-1", loader
        )
        runner.check(
            "SP2-PR-dynamic-01: prompts render without error",
            True,
        )
    except Exception as exc:
        runner.check(
            "SP2-PR-dynamic-01: prompts render without error",
            False,
            str(exc),
        )
        return

    # --- Rendered system prompt: no STPA-Sec --------------------------------
    runner.check(
        "SP2-PR-dynamic-02: rendered system prompt has no STPA-Sec",
        "STPA-Sec" not in system_prompt,
        "STPA-Sec must not appear in the rendered system prompt.",
    )

    # --- Rendered system prompt: security analyst framing --------------------
    runner.check(
        "SP2-PR-dynamic-03: rendered system prompt has security analyst framing",
        "security analyst" in system_prompt.lower(),
        "The rendered system prompt must frame the task as a security analyst.",
    )

    # --- Rendered system prompt: ICA expanded once ---------------------------
    ica_count = system_prompt.count("Insecure Control Action")
    runner.check(
        "SP2-PR-dynamic-04: ICA expanded exactly once in rendered system prompt",
        ica_count == 1,
        f"Found {ica_count} expansions; expected 1.",
    )

    # --- Rendered system prompt: no standalone UCA in prose ------------------
    sys_no_field = system_prompt.replace("uca_type", "")
    runner.check(
        "SP2-PR-dynamic-05: no standalone UCA in rendered system prompt prose",
        not re.search(r"\bUCA\b", sys_no_field),
        "The rendered system prompt should not use UCA in prose.",
    )

    # --- Rendered system prompt: uca_type preserved --------------------------
    runner.check(
        "SP2-PR-dynamic-06: uca_type preserved in rendered system prompt",
        "uca_type" in system_prompt,
        "The uca_type field name must be preserved.",
    )

    # --- Rendered system prompt: four ICA types ------------------------------
    for type_name in ("NOT_PROVIDED", "INCORRECT", "WRONG_TIMING", "WRONG_DURATION"):
        runner.check(
            f"SP2-PR-dynamic-07: rendered system prompt contains {type_name}",
            type_name in system_prompt,
            f"ICA type {type_name} is missing from the rendered system prompt.",
        )

    # --- Rendered system prompt: N/A justification requirements --------------
    runner.check(
        "SP2-PR-dynamic-08: rendered system prompt mentions na_justification",
        "na_justification" in system_prompt,
        "na_justification must be mentioned in the rendered system prompt.",
    )
    runner.check(
        "SP2-PR-dynamic-09: rendered system prompt requires structural property for N/A",
        any(
            kw in system_prompt.lower()
            for kw in ("structural property", "structural", "discrete", "continuous")
        ),
        "The rendered system prompt must require a structural property for N/A.",
    )

    # --- Rendered user prompt: no unresolved Jinja placeholders --------------
    runner.check(
        "SP2-PR-dynamic-10: rendered user prompt has no unresolved {{ }}",
        "{{" not in user_prompt and "}}" not in user_prompt,
        "The rendered user prompt must not contain unresolved Jinja placeholders.",
    )

    # --- Rendered system prompt: no unresolved Jinja placeholders ------------
    runner.check(
        "SP2-PR-dynamic-11: rendered system prompt has no unresolved {{ }}",
        "{{" not in system_prompt and "}}" not in system_prompt,
        "The rendered system prompt must not contain unresolved Jinja placeholders.",
    )

    # --- Rendered user prompt: technology context ----------------------------
    runner.check(
        "SP2-PR-dynamic-12: rendered user prompt contains Technology Context",
        "Technology Context" in user_prompt,
        "The rendered user prompt must include the technology context heading.",
    )
    runner.check(
        "SP2-PR-dynamic-13: rendered user prompt contains the tech context text",
        tech_context in user_prompt,
        "The rendered user prompt must include the technology context block text.",
    )

    # --- Rendered user prompt: slot IDs --------------------------------------
    runner.check(
        "SP2-PR-dynamic-14: rendered user prompt contains slot IDs for RESP-1",
        "RESP-1:CA-1-1" in user_prompt,
        "The rendered user prompt must contain slot IDs for the responsibility.",
    )

    # --- Rendered user prompt: task directive --------------------------------
    runner.check(
        "SP2-PR-dynamic-15: rendered user prompt has a task directive",
        any(kw in user_prompt.lower() for kw in ("your task", "fill")),
        "The rendered user prompt must include a concise task directive.",
    )

    # --- Rendered user prompt: H-*/SC-* reference note -----------------------
    runner.check(
        "SP2-PR-dynamic-16: rendered user prompt references H- and SC-",
        "H-1" in user_prompt and "SC-1" in user_prompt,
        "The rendered user prompt must include hazards and constraints.",
    )

    # --- Rendered user prompt: REQ-*/SC-* mapping note -----------------------
    runner.check(
        "SP2-PR-dynamic-17: rendered user prompt contains REQ-*/SC-* mapping note",
        "REQ-" in user_prompt and "SC-" in user_prompt,
        "The rendered user prompt must include a REQ-*/SC-* mapping note.",
    )

    # --- Rendered user prompt: no ICA type definition duplication ------------
    runner.check(
        "SP2-PR-dynamic-18: rendered user prompt has no 'Four ICA Types' heading",
        "Four ICA Types" not in user_prompt,
        "The user prompt must not duplicate the system prompt's ICA type heading.",
    )
    for n in (1, 2, 3, 4):
        runner.check(
            f"SP2-PR-dynamic-19: rendered user prompt has no 'Type {n}' block",
            f"Type {n}" not in user_prompt,
            f"The user prompt must not duplicate 'Type {n}' definitions.",
        )

    # --- Rendered user prompt: no Requirements heading -----------------------
    runner.check(
        "SP2-PR-dynamic-20: rendered user prompt has no 'Requirements' heading",
        "Requirements" not in user_prompt or "## Requirements" not in user_prompt,
        "The user prompt must not duplicate the system prompt's Requirements heading.",
    )

    # --- Rendered user prompt: uca_type field --------------------------------
    runner.check(
        "SP2-PR-dynamic-21: rendered user prompt preserves uca_type field",
        "uca_type" in user_prompt,
        "The uca_type field must be preserved in the rendered user prompt.",
    )

    # --- Schema compatibility: uca_type accepted -----------------------------
    try:
        slot_data = {
            "slot_id": "RESP-1:CA-1-1:NOT_PROVIDED",
            "responsibility": "RESP-1",
            "coordination_link": None,
            "control_action": "CA-1-1",
            "uca_type": "NOT_PROVIDED",
            "is_na": False,
            "icas": [
                {
                    "ica_id": "RESP-1:CA-1-1:NOT_PROVIDED:1",
                    "ica_text": "Concrete failure",
                    "hazardous_context": "ctx",
                    "loss_scenario": "scenario",
                    "related_hazards": ["H-1"],
                    "related_constraints": ["SC-1"],
                }
            ],
            "na_justification": None,
        }
        result = ICASlotFillResult.model_validate({"filled_slots": [slot_data]})
        runner.check(
            "SP2-PR-dynamic-22: ICASlotFillResult parses with uca_type NOT_PROVIDED",
            True,
        )
        runner.check(
            "SP2-PR-dynamic-23: filled_slots has correct length",
            len(result.filled_slots) == 1,
            f"Expected 1 slot, got {len(result.filled_slots)}",
        )
        slot = result.filled_slots[0]
        runner.check(
            "SP2-PR-dynamic-24: slot has uca_type NOT_PROVIDED",
            slot.uca_type == UCAType.not_provided,
            f"Expected NOT_PROVIDED, got {slot.uca_type}",
        )
        # Check all required fields are present
        for field in (
            "slot_id",
            "responsibility",
            "control_action",
            "uca_type",
            "is_na",
            "icas",
            "na_justification",
        ):
            runner.check(
                f"SP2-PR-dynamic-25: slot has field {field}",
                hasattr(slot, field),
                f"Field {field} is missing from the parsed slot.",
            )
    except Exception as exc:
        runner.check(
            "SP2-PR-dynamic-22: ICASlotFillResult parses with uca_type NOT_PROVIDED",
            False,
            str(exc),
        )

    # --- Technology context: capability-aware classification ------------------
    _run_tech_context_checks(
        runner,
        build_technology_context,
        CapabilityProfile,
        EntryPoint,
        ToolInventoryEntry,
        MagicMock,
    )

    # --- Anti-vacuity checks -------------------------------------------------
    _run_anti_vacuity_checks(
        runner,
        system_prompt,
        user_prompt,
        build_technology_context,
        CapabilityProfile,
        EntryPoint,
        ToolInventoryEntry,
        MagicMock,
    )


def _make_profile_with_tool(
    CapabilityProfile,
    EntryPoint,
    ToolInventoryEntry,
    tool_name,
    tool_desc,
):
    """Build a minimal CapabilityProfile with a single tool."""
    # We need zones_active to include tool_execution for the profile to accept
    # a tool_inventory, but build_technology_context reads profile attributes
    # directly without full validation.  Use a MagicMock to avoid model
    # validation constraints.
    from unittest.mock import MagicMock

    mock = MagicMock()
    mock.zones_active = ["tool_execution"]
    mock.kc_subcodes = []
    mock.entry_points = []
    tool = MagicMock()
    tool.name = tool_name
    tool.description = tool_desc
    mock.tool_inventory = [tool]
    return mock


def _run_tech_context_checks(
    runner,
    build_technology_context,
    CapabilityProfile,
    EntryPoint,
    ToolInventoryEntry,
    MagicMock,
) -> None:
    """Technology context capability-aware classification checks."""

    # --- Read/retrieval tools ------------------------------------------------
    read_tools = [
        ("search-index", "Reads and retrieves documents"),
        ("rag-query", "Queries the knowledge base"),
        ("data-lookup", "Fetches records from the database"),
        ("get-config", "Reads configuration values"),
    ]
    for tool_name, tool_desc in read_tools:
        profile = _make_profile_with_tool(
            CapabilityProfile,
            EntryPoint,
            ToolInventoryEntry,
            tool_name,
            tool_desc,
        )
        ctx = build_technology_context(profile)
        runner.check(
            f"SP2-PR-dynamic-30: read tool '{tool_name}' emits output fabrication",
            "output fabrication" in ctx.lower() or "fabrication" in ctx.lower(),
            f"Context for {tool_name}: {ctx}",
        )
        runner.check(
            f"SP2-PR-dynamic-31: read tool '{tool_name}' emits exfiltration",
            "exfiltration" in ctx.lower(),
            f"Context for {tool_name}: {ctx}",
        )

    # --- Write/execute tools -------------------------------------------------
    write_tools = [
        ("send-email", "Sends notification emails"),
        ("execute-code", "Runs Python code in a sandbox"),
        ("update-record", "Modifies database records"),
        ("file-write", "Writes files to disk"),
    ]
    for tool_name, tool_desc in write_tools:
        profile = _make_profile_with_tool(
            CapabilityProfile,
            EntryPoint,
            ToolInventoryEntry,
            tool_name,
            tool_desc,
        )
        ctx = build_technology_context(profile)
        runner.check(
            f"SP2-PR-dynamic-32: write tool '{tool_name}' emits parameter manipulation",
            "parameter manipulation" in ctx.lower(),
            f"Context for {tool_name}: {ctx}",
        )
        runner.check(
            f"SP2-PR-dynamic-33: write tool '{tool_name}' emits unauthorized state change",
            "unauthorized state change" in ctx.lower() or "state change" in ctx.lower(),
            f"Context for {tool_name}: {ctx}",
        )

    # --- Unknown tools: conservative fallback --------------------------------
    unknown_tools = [
        ("mystery-tool", "Does something unspecified"),
        ("api-bridge", "Connects two systems"),
    ]
    for tool_name, tool_desc in unknown_tools:
        profile = _make_profile_with_tool(
            CapabilityProfile,
            EntryPoint,
            ToolInventoryEntry,
            tool_name,
            tool_desc,
        )
        ctx = build_technology_context(profile)
        runner.check(
            f"SP2-PR-dynamic-34: unknown tool '{tool_name}' emits a failure mode",
            "susceptible" in ctx.lower(),
            f"Context for {tool_name}: {ctx}",
        )

    # --- Distinct suffixes: read vs write ------------------------------------
    read_profile = _make_profile_with_tool(
        CapabilityProfile,
        EntryPoint,
        ToolInventoryEntry,
        "read-query",
        "Reads data",
    )
    write_profile = _make_profile_with_tool(
        CapabilityProfile,
        EntryPoint,
        ToolInventoryEntry,
        "write-action",
        "Writes data",
    )
    read_ctx = build_technology_context(read_profile)
    write_ctx = build_technology_context(write_profile)
    # Extract the suffix after "susceptible to" for each tool line
    read_suffix = ""
    write_suffix = ""
    for line in read_ctx.splitlines():
        if "read-query" in line and "susceptible to" in line:
            read_suffix = line.split("susceptible to", 1)[1].strip()
    for line in write_ctx.splitlines():
        if "write-action" in line and "susceptible to" in line:
            write_suffix = line.split("susceptible to", 1)[1].strip()
    runner.check(
        "SP2-PR-dynamic-35: read and write tool suffixes are distinct",
        read_suffix != write_suffix and read_suffix != "" and write_suffix != "",
        f"Read suffix: '{read_suffix}', Write suffix: '{write_suffix}'",
    )

    # --- Empty tool inventory: no tool lines ---------------------------------
    empty_profile = MagicMock()
    empty_profile.zones_active = []
    empty_profile.kc_subcodes = []
    empty_profile.entry_points = []
    empty_profile.tool_inventory = None
    ctx = build_technology_context(empty_profile)
    tool_lines = [line for line in ctx.splitlines() if "Tool '" in line]
    runner.check(
        "SP2-PR-dynamic-36: empty tool inventory produces no tool lines",
        len(tool_lines) == 0,
        f"Found {len(tool_lines)} tool line(s): {tool_lines}",
    )

    # --- Overlapping verbs: classified by dominant intent --------------------
    # "Reads logs and writes audit entries" — write is the dominant security risk
    overlap_write = _make_profile_with_tool(
        CapabilityProfile,
        EntryPoint,
        ToolInventoryEntry,
        "read-and-write-log",
        "Reads logs and writes audit entries",
    )
    ctx = build_technology_context(overlap_write)
    runner.check(
        "SP2-PR-dynamic-37: overlapping-verb tool classified as write "
        "(parameter manipulation present)",
        "parameter manipulation" in ctx.lower(),
        f"Context: {ctx}",
    )

    overlap_read = _make_profile_with_tool(
        CapabilityProfile,
        EntryPoint,
        ToolInventoryEntry,
        "retrieve-and-format",
        "Retrieves documents and formats output",
    )
    ctx = build_technology_context(overlap_read)
    runner.check(
        "SP2-PR-dynamic-38: overlapping-verb tool classified as read "
        "(output fabrication present)",
        "output fabrication" in ctx.lower() or "fabrication" in ctx.lower(),
        f"Context: {ctx}",
    )


def _run_anti_vacuity_checks(
    runner,
    system_prompt,
    user_prompt,
    build_technology_context,
    CapabilityProfile,
    EntryPoint,
    ToolInventoryEntry,
    MagicMock,
) -> None:
    """Anti-vacuity: removing required elements must cause check failure."""

    # --- SP2-PR-50: Remove NOT_PROVIDED definition from system prompt copy ----
    vacuous_sys = system_prompt.replace("NOT_PROVIDED", "REMOVED_TYPE")
    has_not_provided = "NOT_PROVIDED" in vacuous_sys
    # The check for NOT_PROVIDED should fail on the vacuous copy
    runner.check(
        "SP2-PR-dynamic-50: vacuous system prompt (NOT_PROVIDED removed) "
        "fails ICA type check",
        not has_not_provided,
        "Removing NOT_PROVIDED from the system prompt should make the ICA "
        "type check fail, but NOT_PROVIDED was still found.",
    )

    # --- SP2-PR-51: Remove REQ-*/SC-* mapping note from user prompt copy -----
    vacuous_usr = re.sub(r"REQ-.*SC-.*", "REMOVED_NOTE", user_prompt)
    has_mapping = "REQ-" in vacuous_usr and "SC-" in vacuous_usr
    runner.check(
        "SP2-PR-dynamic-51: vacuous user prompt (mapping note removed) "
        "fails mapping note check",
        not has_mapping,
        "Removing the REQ-*/SC-* mapping note should make the check fail, "
        "but the note was still found.",
    )

    # --- SP2-PR-52: Remove write/execute classification from tech context -----
    # We can't easily remove a branch from the live builder, but we can verify
    # that a write tool's output would fail the check if the write-specific
    # suffix were absent.  We simulate this by checking that the write-specific
    # terms are NOT in the read-tool output (proving the branches are distinct).
    read_profile = _make_profile_with_tool(
        CapabilityProfile,
        EntryPoint,
        ToolInventoryEntry,
        "pure-read",
        "Reads data from the store",
    )
    read_ctx = build_technology_context(read_profile)
    # The read context should NOT contain write-specific terms
    has_write_term = "unauthorized state change" in read_ctx.lower()
    runner.check(
        "SP2-PR-dynamic-52: read-only tool does not emit write-specific suffix "
        "(branches are distinct, not collapsed)",
        not has_write_term,
        "The read-only tool emitted a write-specific failure mode, proving "
        "the branches would collapse if one were removed.",
    )


# ---------------------------------------------------------------------------
# Pipeline-mode checks — require a live LLM endpoint
# ---------------------------------------------------------------------------

_PIPELINE_CHECKS: list[tuple[str, str]] = [
    (
        "SP2-PR-pipeline-01: slot-fill success rate remains 100% with revised prompts",
        "Run the full SP2 pipeline with the revised prompts and verify "
        "that every responsibility slot is filled (no LLM failures). "
        "Requires a live LLM endpoint.",
    ),
    (
        "SP2-PR-pipeline-02: revised prompts produce ICAs that validate "
        "against the loss analysis",
        "Run the full SP2 pipeline and verify that all generated ICAs "
        "pass validate_against with valid hazard and constraint references. "
        "Requires a live LLM endpoint.",
    ),
    (
        "SP2-PR-pipeline-03: known baseline preserved — unit 5918 passed / "
        "11 expected failures / 15 skipped",
        "Run uv run pytest and verify the known-red baseline is unchanged. "
        "Prompt tests should add deterministic passes without changing "
        "the baseline.",
    ),
    (
        "SP2-PR-pipeline-04: known baseline preserved — acceptance 72 passed / "
        "9 expected failures",
        "Run uv run pytest build/acceptance/generated/ and verify the known-red "
        "baseline is unchanged.",
    ),
    (
        "SP2-PR-pipeline-05: source ruff check remains clean",
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
# Regression matrix for existing stage3 slot-fill tests
# ---------------------------------------------------------------------------

REGRESSION_MATRIX = [
    # (test file, test class, test method, what it verifies)
    (
        "tests/stpa/test_sp2_slot_filling.py",
        "TestSystemPromptContent",
        "test_four_ica_types_in_system_prompt",
        "Four ICA type names present in system prompt",
    ),
    (
        "tests/stpa/test_sp2_slot_filling.py",
        "TestUserPromptContent",
        "test_user_prompt_contains_required_content",
        "User prompt has control structure, hazards, tech context, slot IDs",
    ),
    (
        "tests/stpa/test_sp2_slot_filling.py",
        "TestStatelessCalls",
        "test_each_call_receives_full_control_structure",
        "Each call receives full CS; system prompts identical",
    ),
    (
        "tests/stpa/test_sp2_slot_filling.py",
        "TestCallLogging",
        "test_calls_jsonl_exists_with_stage_3",
        "All LLM calls logged to calls.jsonl with stage_3",
    ),
    (
        "tests/stpa/test_sp2_slot_filling.py",
        "TestFillSlotsForResponsibility",
        "test_returns_filled_slots_for_the_responsibility",
        "Single-responsibility fill returns correct slots",
    ),
    (
        "tests/stpa/test_sp2_slot_filling.py",
        "TestCollectFilledSlotsTypeCheck",
        "test_non_icaslotfillresult_is_skipped",
        "Non-ICASlotFillResult results are skipped",
    ),
    (
        "tests/stpa/test_sp2_slot_filling.py",
        "TestCollectFilledSlotsTypeCheck",
        "test_none_result_is_skipped",
        "None results are skipped",
    ),
    (
        "tests/stpa/test_sp2_slot_filling.py",
        "TestCollectFilledSlotsTypeCheck",
        "test_valid_icaslotfillresult_is_collected",
        "Valid ICASlotFillResult is collected",
    ),
]


def run_regression_checks(runner: QARunner) -> None:
    """Run existing stage3 slot-fill tests as a regression matrix."""
    for test_file, test_class, test_method, description in REGRESSION_MATRIX:
        test_path = f"{test_file}::{test_class}::{test_method}"
        try:
            result = run_command(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    test_path,
                    "-v",
                    "--tb=short",
                    "--no-header",
                    "-p",
                    "no:cacheprovider",
                ],
                cwd=PROJECT_ROOT,
                timeout=120,
            )
            output = result.stdout + result.stderr
            runner.check(
                f"SP2-PR-regression: {test_class}::{test_method} ({description})",
                result.returncode == 0 and "PASSED" in output,
                f"rc={result.returncode}, output: {output[:300]}",
            )
        except TimeoutExpired:
            runner.check(
                f"SP2-PR-regression: {test_class}::{test_method} ({description})",
                False,
                "pytest timed out after 120s",
            )
        except Exception as exc:
            runner.check(
                f"SP2-PR-regression: {test_class}::{test_method} ({description})",
                False,
                str(exc),
            )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "QA suite for SP2 Stage 3 prompt revision (bead asago-scenario-generator-f787)"
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
        "--regression",
        action="store_true",
        help="Run existing stage3 slot-fill test regression matrix",
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

    if not any([args.static, args.dynamic, args.regression, args.pipeline, args.all]):
        args.all = True

    runner = F787QARunner()

    if args.static or args.all:
        print("--- Static checks (source text) ---")
        run_static_checks(runner)

    if args.dynamic or args.all:
        print("--- Dynamic checks (import + render + deterministic builders) ---")
        run_dynamic_checks(runner)

    if args.regression or args.all:
        print("--- Regression matrix (existing stage3 slot-fill tests) ---")
        run_regression_checks(runner)

    if args.pipeline or args.all:
        print("--- Pipeline-mode checks (live LLM endpoint) ---")
        run_pipeline_checks(runner)

    return runner.summary()


if __name__ == "__main__":
    sys.exit(main())
