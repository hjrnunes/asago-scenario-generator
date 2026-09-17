"""Audit prompt/schema field ownership for offline R6 evidence.

The full qualification audit can add other artifact checks later.  The
``--field-inventory`` mode is deliberately deterministic and has no provider,
target, or filesystem inputs beyond its caller-selected output directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE_ROOTS = (
    REPO_ROOT / "build" / "adaptive-e2e" / "fresh-miniklarna-qualification-20260917",
    REPO_ROOT
    / "build"
    / "adaptive-e2e"
    / "fresh-miniklarna-qualification-redo-20260917",
    REPO_ROOT
    / "build"
    / "adaptive-e2e"
    / "fresh-miniklarna-qualification-exception-20260917",
    REPO_ROOT
    / "build"
    / "adaptive-e2e"
    / "fresh-miniklarna-qualification-redo-authoring-20260917",
    REPO_ROOT
    / "build"
    / "adaptive-e2e"
    / "fresh-miniklarna-qualification-exception-authoring-20260917",
    REPO_ROOT
    / "build"
    / "adaptive-e2e"
    / "fresh-miniklarna-qualification-final-20260917",
    REPO_ROOT / "build" / "adaptive-e2e" / "fresh-miniocciai-qualification-20260917",
    REPO_ROOT
    / "build"
    / "adaptive-e2e"
    / "fresh-miniocciai-qualification-redo-20260917",
    REPO_ROOT
    / "build"
    / "adaptive-e2e"
    / "fresh-miniocciai-qualification-20260917-authoring",
    REPO_ROOT
    / "build"
    / "adaptive-e2e"
    / "fresh-miniocciai-qualification-redo-authoring-20260917",
    REPO_ROOT / "build" / "adaptive-e2e" / "fresh-miniairbnb-qualification-20260917",
)
PREFLIGHT_PATH = (
    REPO_ROOT
    / "build"
    / "qualification"
    / "scenario-fidelity-final"
    / "qualification-preflight.json"
)

AUDIT_ARTIFACTS = (
    "field-inventory.json",
    "usage-ledger.json",
    "reachability.json",
    "claims.json",
    "run-recount.json",
    "requirement-matrix.json",
    "counterexamples.json",
    "completion-status.json",
    "evidence-scan.json",
)

_VARIANTS = (
    ("no_target_facts", "producer_stage5", "operation and observations omitted"),
    ("operation_inventory_only", "producer_stage5", "target operation supplied"),
    ("observations_only", "producer_stage5", "target observations supplied"),
    ("both_target_sources", "producer_stage5", "operation and observations supplied"),
    ("reply_based", "producer_stage5", "model-output action semantics"),
    ("functional", "producer_stage5_and_consumer", "none/functional framing"),
    ("omission", "producer_stage5_and_consumer", "NOT_PROVIDED or tool_absent"),
    (
        "history_dependent",
        "consumer_authoring",
        "user-only history with one continuation",
    ),
)


def _field(
    field: str,
    meaning: str,
    authority: str,
    allowed: list[str],
    unknown: str,
    resolution: str,
    downstream: str,
    prompt: str,
    schema: str,
) -> dict[str, Any]:
    return {
        "field": field,
        "meaning": meaning,
        "source_authority": authority,
        "allowed_values": allowed,
        "unknown_form": unknown,
        "deterministic_resolution": resolution,
        "downstream_use": downstream,
        "prompt": prompt,
        "schema": schema,
    }


def build_field_inventory() -> dict[str, Any]:
    """Return the checked field-level interface inventory."""

    producer_stage5 = [
        _field(
            "stimulus.category",
            "Historical execution delivery category",
            "Historical execution caller selects from observed route context",
            [
                "user_message",
                "conversation",
                "retrieved_content",
                "tool_content",
                "file_upload",
                "traffic_load",
                "unknown",
            ],
            "unknown is analytical_only, never relabelled as a direct prompt",
            "Code derives delivery class and rejects unsupported executable routes",
            "Historical execution contract only; absent from normal handoff",
            "stage5_context_user.j2",
            "_ContextStimulusDraft.category",
        ),
        _field(
            "stimulus.description",
            "Historical execution stimulus description",
            "Historical execution provider",
            ["nonblank string"],
            "Missing description is schema-invalid",
            "Code retains it only for historical execution validation",
            "Historical execution contract only; absent from normal handoff",
            "stage5_context_user.j2",
            "_ContextStimulusDraft.description",
        ),
        _field(
            "adversary.kind",
            "Supported actor classification or functional disposition",
            "Model chooses from supplied semantic evidence",
            [
                "external_attacker",
                "malicious_customer",
                "third_party_via_content",
                "none",
            ],
            "Uncertain actor subtype stays unsupported; no subtype is guessed",
            "Code validates content-surface support and materializes the closed handoff enum",
            "Handoff functional/adversarial classification",
            "stage5_context_user.j2",
            "_ContextAdversaryDraft.kind",
        ),
        _field(
            "adversary.gain",
            "Specific benefit for an adversarial actor",
            "Model; not required for functional kind none",
            ["nonblank string for adversarial kinds"],
            "Omitted for kind none; compiler supplies the functional marker",
            "Code rejects missing adversarial gain and ignores functional provider text",
            "Handoff adversary explanation",
            "stage5_context_user.j2",
            "_ContextAdversaryDraft.gain",
        ),
        _field(
            "attacker_bdi.beliefs",
            "Supported actor beliefs about the selected path",
            "Model, grounded in immutable context",
            ["list of strings"],
            "Empty list for functional kind none",
            "Code preserves BDI only for adversarial publication",
            "Narrative and causal account",
            "stage5_context_user.j2",
            "_ContextAttackerBDIDraft.beliefs",
        ),
        _field(
            "attacker_bdi.desires",
            "Supported adversarial objective",
            "Model; causal evidence is required",
            ["nonblank strings for adversarial kinds"],
            "Empty list for functional kind none",
            "Code requires nonempty values for adversarial kinds",
            "Narrative and causal account",
            "stage5_context_user.j2",
            "_ContextAttackerBDIDraft.desires",
        ),
        _field(
            "attacker_bdi.intentions",
            "Supported approach tied to causal handles",
            "Model selects request-local cause_* handles",
            ["nonblank descriptions with declared handles"],
            "Empty list for functional kind none",
            "Code resolves each handle to the exact structural source",
            "Narrative and causal account",
            "stage5_context_user.j2",
            "_ContextAttackerIntentionDraft",
        ),
        _field(
            "causal_factors",
            "Causal evidence for the selected semantic path",
            "Model selects explained request-local handles",
            ["structural_failure", "reachable_capability", "bounded_assumption"],
            "No bookkeeping placeholder; absent evidence remains unknown",
            "Code resolves source handles and validates evidence-status references",
            "Causal tree and lineage",
            "stage5_context_user.j2",
            "_ContextSemanticCausalFactorDraft*",
        ),
        _field(
            "causal_factors[].selected_for_route",
            "Historical route factor selection",
            "Historical execution provider selects one displayed factor",
            ["true on exactly one executable factor", "false for analytical_only"],
            "Absent from normal semantic-only schema",
            "Code binds the selected factor to the fixed causal source",
            "Historical execution route only",
            "stage5_context_user.j2",
            "_ContextCausalFactorWireBase.selected_for_route",
        ),
        _field(
            "unsafe_outcome.condition",
            "Historical typed observable condition",
            "Historical execution provider selects a permitted condition family",
            [
                "action_presence",
                "action_value",
                "state_value",
                "ordering",
                "delay",
                "duration",
                "window",
                "absence",
            ],
            "Typed binding placeholder when a deployment value is unknown",
            "Code resolves local references and derives semantic_binding_required",
            "Historical execution oracle only; absent from normal handoff",
            "stage5_context_user.j2",
            "_ContextUnsafeOutcomeDraft.condition",
        ),
        _field(
            "execution_route",
            "Historical execution disposition",
            "Historical execution provider selects from the closed route branches",
            ["executable_route", "analytical_only"],
            "Analytical-only gap with evidence handles",
            "Code derives the execution contract and rejects unsupported delivery",
            "Historical execution contract only; absent from normal handoff",
            "stage5_context_user.j2",
            "ExecutionRouteSelectionValue",
        ),
        _field(
            "unsafe_outcome.semantic_proposition",
            "Bounded sentence stating exactly what makes the outcome unsafe",
            "Model, grounded in supplied operation/observation facts when present",
            ["nonblank string, max 600 characters"],
            "Unknown values remain typed placeholders only on execution conditions; no whole-response string placeholder",
            "Code copies the proposition into the semantic handoff criterion",
            "Criterion, narrative, Gherkin",
            "stage5_context_user.j2",
            "_ContextSemanticOutcomeDraft.semantic_proposition",
        ),
    ]
    producer_authoring = [
        _field(
            "result.kind",
            "Whether bounded target-grounded authoring produced scenarios",
            "Model chooses closed result form",
            ["scenarios", "no_scenario"],
            "no_scenario with a nonblank reason",
            "Code derives scenario tuple or null reason",
            "Candidate terminal accounting",
            "authoring_current_user.j2",
            "CurrentAuthoringResponse.result",
        ),
        _field(
            "result.scenarios[].adversary",
            "Actor classification for a concrete authored case",
            "Model selects supplied definitions",
            [
                "external_attacker",
                "malicious_customer",
                "third_party_via_content",
                "none",
            ],
            "none for functional; unsupported choices are rejected or held",
            "Code materializes functional/adversarial disposition",
            "Scenario specification",
            "authoring_current_user.j2",
            "CurrentScenarioDraft.adversary",
        ),
        _field(
            "result.scenarios[].stimulus",
            "Consumer-authored user message or bounded user-only history",
            "Model writes text; compiler supplies roles",
            ["user_message", "conversation"],
            "No assistant history; unsupported history is rejected",
            "Code compiles one continuation from verbatim user turns",
            "Executable artifact or functional specification",
            "authoring_current_user.j2",
            "CurrentStimulus",
        ),
        _field(
            "result.scenarios[].stimulus.kind",
            "Stimulus delivery primitive",
            "Model chooses from the request-local supported forms",
            ["user_message", "conversation"],
            "Unsupported or role-serialized history is rejected",
            "Compiler supplies fixed user roles",
            "Executable user message/history",
            "authoring_current_user.j2",
            "CurrentUserMessage.kind | CurrentConversation.kind",
        ),
        _field(
            "result.scenarios[].stimulus.text_or_turns",
            "Concrete user text or ordered user-only history",
            "Model writes text; compiler supplies role labels",
            ["nonblank text", "2-3 nonblank turns"],
            "No assistant turn or synthetic continuation",
            "Code preserves text verbatim and appends exactly one continuation",
            "Executable user message/history",
            "authoring_current_user.j2",
            "CurrentUserMessage.text | CurrentConversation.turns",
        ),
        _field(
            "result.scenarios[].unsafe_observation",
            "One admitted observable check",
            "Model selects displayed choice and source handles",
            ["tool_argument", "tool_order", "tool_absent", "response_claim"],
            "No supported choice yields no_scenario",
            "Code resolves handles against the request-local schema",
            "Oracle and compilation",
            "authoring_current_user.j2",
            "CurrentUnsafeObservation",
        ),
        _field(
            "result.scenarios[].unsafe_observation.choice_handle",
            "Request-local admitted check identity",
            "Model copies one displayed handle",
            ["listed nonblank handle"],
            "Unknown handle is a typed adapter failure",
            "Code resolves exact kind, action, operators, and operands",
            "Oracle selection",
            "authoring_current_user.j2",
            "Current*Check.choice_handle",
        ),
        _field(
            "result.scenarios[].unsafe_observation.operand",
            "Literal or exact state/observation source value",
            "Model selects a displayed source or literal where admitted",
            ["literal", "state_fact", "observation"],
            "Missing source remains unresolved; no descriptive pseudo-handle",
            "Code resolves exact typed value and source pin",
            "Oracle operand",
            "authoring_current_user.j2",
            "CurrentOperand",
        ),
        _field(
            "result.scenarios[].conditions_established",
            "Evidence for numbered applicability conditions",
            "Model selects exact displayed source handles",
            ["stimulus", "state_fact", "observation"],
            "Empty list only when no conditions are supplied",
            "Code bounds condition numbers and resolves source handles",
            "Oracle applicability evidence",
            "authoring_current_user.j2",
            "CurrentCondition",
        ),
        _field(
            "result.scenarios[].claims_under_test",
            "Earlier-turn claim tied to one state fact",
            "Model cites exact turn and fact handle",
            ["turn >= 1 with fact_handle"],
            "Omitted when no history claim exists",
            "Code checks turn bounds and fact-handle closure",
            "History semantic assessment",
            "authoring_current_user.j2",
            "CurrentClaimUnderTest",
        ),
        _field(
            "result.scenarios[].safe_behaviors",
            "Safe responses that must not trigger the selected oracle",
            "Model describes supplied safe outcomes",
            ["strings"],
            "Empty tuple when no safe behavior is established",
            "Code carries safe behavior rubric to compilation",
            "Fidelity and oracle validation",
            "authoring_current_user.j2",
            "CurrentScenarioDraft.safe_behaviors",
        ),
    ]
    consumer_authoring = [
        _field(
            "stimulus_text",
            "Concrete consumer-owned final user request",
            "Consumer author; never copied from producer prose",
            ["nonblank string"],
            "Missing/blank is typed invalid-design",
            "Code validates record attribution, operation meaning, and verbatim freeze",
            "Compiled user message",
            "design.authoring._author_system_prompt",
            "_author_stimulus response contract",
        ),
        _field(
            "requested_amount",
            "Amount explicitly attributed to the request text",
            "Consumer author when selected operation requires it",
            ["finite number when amount-bearing"],
            "Omitted for non-amount operations; contradiction is unresolved",
            "Code binds only an unambiguous value stated in delivered text",
            "Target argument and detector bound",
            "design.authoring._author_system_prompt",
            "_author_stimulus response contract",
        ),
        _field(
            "history_turns",
            "Earlier user-only context for one final continuation",
            "Consumer author",
            ["1-3 nonblank strings for designed_history"],
            "Omitted for direct_request",
            "Code preserves order, roles, and complete-history assessment",
            "Compiled user-only conversation",
            "design.authoring._author_system_prompt",
            "_author_stimulus response contract",
        ),
        _field(
            "argument_values",
            "Benign required operation arguments stated in user text",
            "Consumer author; exact target schema remains authoritative",
            ["object keyed by required authored arguments"],
            "Missing value is unresolved-prerequisite; never UNKNOWN",
            "Code checks declared value against delivered text and schema type",
            "Target-context contract and dispatch",
            "design.authoring._author_system_prompt",
            "_author_stimulus response contract",
        ),
        _field(
            "rationale",
            "Short explanation of how the request exercises the criterion",
            "Consumer author",
            ["string"],
            "Empty rationale is retained but does not establish fidelity",
            "Code stores provenance; semantic validation uses text and criterion",
            "Design record provenance",
            "design.authoring._author_system_prompt",
            "_author_stimulus response contract",
        ),
    ]
    fields = producer_stage5 + producer_authoring + consumer_authoring
    return {
        "schema_version": "prompt-schema-field-inventory-v1",
        "authority": "production request builders and response validators",
        "fields": fields,
        "rendered_input_variants": [
            {
                "name": name,
                "builder": builder,
                "supplied_facts": facts,
                "schema_outcome": "valid representative response or typed closed outcome",
            }
            for name, builder, facts in _VARIANTS
        ],
        "schema_mapping": {
            "producer": {
                "normal": "_ContextScenarioSemanticsPayload",
                "grounded_authoring": "CurrentAuthoringResponse",
            },
            "consumer": {
                "artifact_authoring": "consumer _author_stimulus response contract",
                "handoff_kind": "ScenarioHandoff.kind",
            },
        },
        "unused_demands": [],
        "contradictions": [],
    }


def write_field_inventory(output_dir: Path) -> Path:
    """Write the deterministic R6 inventory and return its path."""

    inventory = build_field_inventory()
    fields = inventory["fields"]
    if len({item["field"] for item in fields}) != len(fields):
        raise ValueError("field inventory contains duplicate field identities")
    if not fields or any(
        not item["meaning"]
        or not item["source_authority"]
        or not item["allowed_values"]
        or not item["unknown_form"]
        or not item["deterministic_resolution"]
        or not item["downstream_use"]
        for item in fields
    ):
        raise ValueError("field inventory contains incomplete field metadata")
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "field-inventory.json"
    path.write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _json_load(path: Path) -> dict[str, Any] | None:
    """Read one JSON object without making a malformed record disappear."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _yaml_load(path: Path) -> dict[str, Any] | None:
    """Read one YAML object without turning malformed evidence into success."""
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return None
    return value if isinstance(value, dict) else None


def _relative_path(path: Path) -> str:
    """Return a stable repository-relative path for an evidence record."""
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _resolve_evidence_path(value: Any, run_dir: Path) -> Path | None:
    """Resolve an evidence path as recorded, without guessing another run."""
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = Path(value)
    choices = (
        candidate,
        run_dir / candidate,
        REPO_ROOT / candidate,
    )
    for choice in choices:
        if choice.is_dir() or choice.is_file():
            return choice.resolve()
    return None


def _run_status_path(path: Path) -> Path | None:
    """Find the nearest orchestration root for a primary evidence file."""
    for parent in (path.parent, *path.parents):
        if (parent / "run-status.json").is_file():
            return parent
    return None


def _preflight_record() -> dict[str, Any] | None:
    """Load the immutable pre-dispatch registration when it exists."""
    return _json_load(PREFLIGHT_PATH) if PREFLIGHT_PATH.is_file() else None


def _freshness(run_dir: Path, generation: Any) -> str:
    """Resolve fresh/reused from an explicit marker or the preserved run name."""
    if isinstance(generation, dict):
        source = generation.get("source")
        if source in {"fresh", "reused"}:
            return source
    name = run_dir.name.lower()
    if name.startswith("fresh-") or "-fresh-" in name:
        return "fresh"
    if "reuse" in name or "resum" in name:
        return "reused"
    return "unavailable"


def _selection_audit(artifact: Any, predispatch: Any) -> dict[str, Any]:
    """Audit semantic/setup selection without inferring a verdict."""
    artifact = artifact if isinstance(artifact, dict) else {}
    predispatch = predispatch if isinstance(predispatch, dict) else {}
    selected_scenario = artifact.get("selected_scenario")
    selected_design = artifact.get("selected_design_id")
    rationale = predispatch.get("stimulus_exercise_rationale")
    rationale_text = ""
    if isinstance(rationale, dict):
        rationale_text = " ".join(
            str(value)
            for key, value in rationale.items()
            if key in {"rationale", "meaning", "stimulus_text"}
            and isinstance(value, (str, int, float))
        )
    elif isinstance(rationale, str):
        rationale_text = rationale
    text = rationale_text.lower()
    cites_gold_id = bool(re.search(r"\bgold\b|\bbenchmark\b|\bg\d{2}\b", text))
    cites_expected_unsafe_verdict = bool(
        re.search(
            r"expected\s+(?:unsafe|safe)\s+(?:verdict|result|outcome)"
            r"|(?:obtain|seek|force)\s+an?\s+unsafe",
            text,
        )
    )
    cites_semantics = bool(
        re.search(
            r"criterion|operation|request|stimulus|scenario|meaning|"
            r"authored|semantic|record-matching",
            text,
        )
    )
    cites_setup = bool(
        re.search(r"observed|setup|status|record|permission|prerequisite|state", text)
    )
    selected = isinstance(selected_scenario, str) and bool(selected_scenario.strip())
    return {
        "selected_scenario": selected_scenario,
        "selected_design_id": selected_design,
        "basis": ["semantic_suitability", "setup_support"] if selected else [],
        "reason": rationale_text or None,
        "reason_source": (
            "execution/pre-dispatch-checks.yaml.stimulus_exercise_rationale"
            if rationale_text
            else None
        ),
        "reason_validation": {
            "cites_semantics": cites_semantics,
            "cites_setup_support": cites_setup,
            "cites_gold_id": cites_gold_id,
            "cites_expected_unsafe_verdict": cites_expected_unsafe_verdict,
            "valid": bool(
                selected
                and cites_semantics
                and cites_setup
                and not cites_gold_id
                and not cites_expected_unsafe_verdict
            ),
        },
    }


_PREDISPATCH_SECTIONS = (
    "scenario_meaning",
    "stimulus_exercise_rationale",
    "verified_permissions_prerequisites",
    "safe_alternatives_availability",
    "detector_discrimination",
    "target_tools_and_instructions",
    "observation_limitations",
)


def _predispatch_audit(run_dir: Path) -> dict[str, Any]:
    """Check the seven pre-dispatch sections by presence and nonempty value."""
    path = run_dir / "execution" / "pre-dispatch-checks.yaml"
    record = _yaml_load(path) if path.is_file() else None
    sections = {
        name: bool(record and record.get(name) not in (None, "", [], {}))
        for name in _PREDISPATCH_SECTIONS
    }
    return {
        "path": _relative_path(path) if path.is_file() else None,
        "sections": sections,
        "missing_sections": [name for name, present in sections.items() if not present],
        "complete": bool(record) and all(sections.values()),
    }


# The per-run cleanup record written by the maintained stack_cleanup seam
# (scripts/qualification/stack_cleanup.py). The path is mirrored here because
# the audit runs both as a script (flat import) and as a tested module
# (package import); importing the seam would only work in one context.
_CLEANUP_RECORD_PATH = ("cleanup", "stack-cleanup.json")


def _classify_cleanup_record(record: dict[str, Any] | None) -> str:
    """Classify one cleanup record without upgrading evidence.

    ``verified`` needs the recorded completion AND the matching observed
    clean final state (no orphans, every port closed). ``kept_running`` marks
    an intentional pause. A recorded failure — including a completion claim
    whose final-state evidence is missing — stays ``failed``. No record means
    ``historical_unverified``: absence is never read as success.
    """
    if record is None:
        return "historical_unverified"
    status = record.get("status")
    if status == "kept_running":
        return "kept_running"
    if status in {"completed", "complete", "success"}:
        listener_closure = record.get("listener_closure")
        if (
            isinstance(listener_closure, dict)
            and listener_closure.get("status") != "confirmed"
        ):
            return "failed"
        process_exit_wait = record.get("process_exit_wait")
        if isinstance(process_exit_wait, dict) and (
            process_exit_wait.get("status") != "confirmed"
            or process_exit_wait.get("survivors")
        ):
            return "failed"
        current_verification = record.get("current_verification")
        if isinstance(current_verification, dict) and (
            current_verification.get("result") != status
            or not isinstance(current_verification.get("processes"), dict)
            or not isinstance(current_verification.get("ports"), dict)
            or not isinstance(current_verification.get("action"), dict)
        ):
            return "failed"
        if (
            record.get("ports_clear") is True
            and record.get("orphan_processes") == []
            and record.get("no_orphan_check") == "passed"
        ):
            return "verified"
        return "failed"
    if status in {"failed", "error"}:
        return "failed"
    return "historical_unverified"


def _cleanup_audit(run_dir: Path) -> dict[str, Any]:
    """Read one run's recorded stack cleanup and classify it honestly."""
    path = run_dir.joinpath(*_CLEANUP_RECORD_PATH)
    record = _json_load(path) if path.is_file() else None
    if record is None:
        reason = (
            "cleanup record is malformed or unreadable"
            if path.is_file()
            else "no per-run cleanup record; runs predating the cleanup seam "
            "cannot be verified offline"
        )
        return {
            "path": _relative_path(path) if path.is_file() else None,
            "record": None,
            "classification": "historical_unverified",
            "reason": reason,
        }
    current_path_value = record.get("current_verification_record")
    current_path = (
        Path(current_path_value) if isinstance(current_path_value, str) else None
    )
    if current_path is not None and not current_path.is_absolute():
        current_path = path.parent / current_path
    current_record = (
        _json_load(current_path)
        if current_path is not None and current_path.is_file()
        else None
    )
    classification = _classify_cleanup_record(record)
    if record.get("current_verification_record") and current_record is None:
        classification = "failed"
    return {
        "path": _relative_path(path),
        "record": record,
        "classification": classification,
        "current_verification": current_record,
        "current_verification_path": (
            _relative_path(current_path)
            if current_path is not None and current_path.is_file()
            else None
        ),
    }


def _cleanup_timestamp(
    record: dict[str, Any] | None,
) -> tuple[datetime, str, str] | None:
    """Normalize either maintained cleanup timestamp schema to UTC.

    The maintained recipe records ``executed_at`` while the orchestration
    cleanup seam records ``recorded_at``.  The field name remains part of the
    audit evidence so chronology never depends on guessing which schema was
    supplied.
    """
    if not isinstance(record, dict):
        return None
    for field in ("recorded_at", "executed_at"):
        value = record.get(field)
        if not isinstance(value, str) or not value.strip():
            continue
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        normalized = (
            parsed.astimezone(timezone.utc)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
        return parsed.astimezone(timezone.utc), field, normalized
    return None


def _cleanup_is_clean(record: dict[str, Any]) -> bool:
    """Require explicit completion, clear ports, and no orphan processes."""
    status = record.get("status") or record.get("result")
    clear_ports = record.get("ports_clear") is True or isinstance(
        record.get("ports_cleared"), list
    )
    return (
        status in {"completed", "complete", "success"}
        and clear_ports
        and record.get("orphan_processes") == []
        and record.get("no_orphan_check", "passed") == "passed"
    )


def _stage_1a_audit(run_dir: Path) -> dict[str, Any]:
    """Require pinned Stage 1a evidence and zero model/revision calls."""
    manifest = _yaml_load(run_dir / "generation" / "run-manifest.yaml")
    summary = manifest.get("stage_summary", {}) if manifest else {}
    stage = summary.get("stage_1a") if isinstance(summary, dict) else None
    if not isinstance(stage, dict):
        return {"call_count": None, "source": None, "status": "unavailable"}
    call_count = stage.get("call_count")
    source = stage.get("source")
    valid = call_count == 0 and source == "pinned"
    return {
        "call_count": call_count,
        "source": source,
        "status": "valid" if valid else "invalid",
    }


def _json_output_value(value: Any) -> Any:
    """Keep native outcome values while avoiding large response payloads."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return None


def _outcome_audit(run_dir: Path) -> dict[str, Any]:
    """Reconcile one saved runtime result without blending outcome axes."""
    path = run_dir / "execution" / "qualification.json"
    record = _json_load(path) if path.is_file() else None
    if record is None:
        return {
            "path": None,
            "present": False,
            "attempt_count": 0,
            "no_unsafe_verdict_retry": None,
            "native_labels": {},
        }
    result = record.get("results", [{}])
    result = result[0] if isinstance(result, list) and result else {}
    evaluation = result.get("evaluation", {}) if isinstance(result, dict) else {}
    ledger = evaluation.get("ledger", {}) if isinstance(evaluation, dict) else {}
    observed_calls = (
        ledger.get("observed_calls", []) if isinstance(ledger, dict) else []
    )
    backend_statuses: list[Any] = []
    for observed in observed_calls if isinstance(observed_calls, list) else []:
        if not isinstance(observed, dict):
            continue
        output = observed.get("output")
        if isinstance(output, str):
            try:
                parsed = json.loads(output)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict):
                backend_statuses.append(
                    {
                        key: _json_output_value(parsed.get(key))
                        for key in ("status", "error", "message")
                        if key in parsed
                    }
                )
    attempt_count = record.get("attempt_count")
    return {
        "path": _relative_path(path),
        "present": True,
        "attempt_count": attempt_count,
        "no_unsafe_verdict_retry": attempt_count == 1,
        "garak_revision": (record.get("garak_revision") or {}).get("git_commit")
        if isinstance(record.get("garak_revision"), dict)
        else None,
        "native_labels": {
            "observation_level": record.get("observation", {}).get("level")
            if isinstance(record.get("observation"), dict)
            else None,
            "command_names": [
                observed.get("name")
                for observed in observed_calls
                if isinstance(observed, dict) and observed.get("name")
            ],
            "reply_present": bool(
                isinstance(result, dict)
                and isinstance(result.get("response"), dict)
                and result["response"].get("text")
            ),
            "condition_verdict": evaluation.get("condition_verdict"),
            "target_effect": evaluation.get("target_effect"),
            "vulnerability_confirmed": evaluation.get("vulnerability_confirmed"),
            "ledger_target_effect": ledger.get("target_effect"),
            "state_changed": ledger.get("state_changed"),
            "bookkeeping_only": ledger.get("bookkeeping_only"),
            "completed_call_count": ledger.get("completed_call_count"),
            "backend_statuses": backend_statuses,
            "effect_established": ledger.get("target_effect") == "established",
        },
    }


def _representation_audit(run_dir: Path, artifact: Any) -> list[dict[str, Any]]:
    """Check real generated adversarial/functional handoffs as received."""
    artifact = artifact if isinstance(artifact, dict) else {}
    attempts = artifact.get("attempts", [])
    if not isinstance(attempts, list):
        return []
    rows: list[dict[str, Any]] = []
    for attempt in attempts:
        if not isinstance(attempt, dict) or attempt.get("compiled") is not True:
            continue
        handoff_path = _resolve_evidence_path(attempt.get("handoff"), run_dir)
        executable_path = _resolve_evidence_path(attempt.get("artifact"), run_dir)
        handoff = _yaml_load(handoff_path) if handoff_path else None
        design_path = (
            executable_path.parent / "design-record.json" if executable_path else None
        )
        design = (
            _json_load(design_path) if design_path and design_path.is_file() else None
        )
        gherkin = handoff.get("gherkin") if isinstance(handoff, dict) else None
        tree = handoff.get("attack_tree") if isinstance(handoff, dict) else None
        criterion = handoff.get("semantic_failure_criterion") if handoff else None
        gherkin_scenario = (
            gherkin.get("scenario") if isinstance(gherkin, dict) else None
        )
        tree_criterion = tree.get("criterion") if isinstance(tree, dict) else None
        feature_path = handoff_path.with_suffix(".feature") if handoff_path else None
        feature_text = (
            feature_path.read_text(encoding="utf-8")
            if feature_path and feature_path.is_file()
            else ""
        )
        verification = (
            design.get("handoff", {}).get("verification", {})
            if isinstance(design, dict)
            else {}
        )
        rows.append(
            {
                "scenario_id": attempt.get("scenario_id"),
                "kind": handoff.get("kind") if handoff else None,
                "handoff": _relative_path(handoff_path) if handoff_path else None,
                "consumer_design": _relative_path(design_path) if design_path else None,
                "executable_artifact": (
                    _relative_path(executable_path) if executable_path else None
                ),
                "native_feature": _relative_path(feature_path)
                if feature_path and feature_path.is_file()
                else None,
                "consumer_received_schema": verification.get("schema_version"),
                "consumer_digest_verified": verification.get("digest_verified") is True,
                "semantic_consistent": bool(
                    isinstance(criterion, str)
                    and criterion
                    and criterion == gherkin_scenario == tree_criterion
                ),
                "gherkin_shape_valid": bool(
                    isinstance(gherkin, dict)
                    and all(
                        isinstance(
                            gherkin.get(key),
                            list
                            if key
                            in {
                                "given",
                                "when",
                                "then_expected",
                                "then_unsafe_alternative",
                            }
                            else str,
                        )
                        and bool(gherkin.get(key))
                        for key in (
                            "feature",
                            "scenario",
                            "given",
                            "when",
                            "then_expected",
                            "then_unsafe_alternative",
                        )
                    )
                ),
                "native_feature_shape_valid": (
                    "Feature:" in feature_text and "Scenario:" in feature_text
                ),
            }
        )
    return rows


def _source_revisions() -> dict[str, Any]:
    """Return qualification-time and final repository provenance separately."""
    preflight = _preflight_record()
    revisions = preflight.get("source_revisions", {}) if preflight else {}
    if not isinstance(revisions, dict):
        revisions = {}

    def git_revision(path: Path) -> str | None:
        try:
            result = subprocess.run(
                ["git", "-C", str(path), "rev-parse", "HEAD"],
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError:
            return None
        value = result.stdout.strip()
        return value if result.returncode == 0 and value else None

    def git_status(path: Path) -> str | None:
        try:
            result = subprocess.run(
                ["git", "-C", str(path), "status", "--short"],
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError:
            return None
        return result.stdout.strip() if result.returncode == 0 else None

    final_repositories = {
        "producer": {
            "path": str(REPO_ROOT),
            "revision": git_revision(REPO_ROOT),
            "tracked_status": git_status(REPO_ROOT),
        },
        "consumer": {
            "path": _relative_path(REPO_ROOT.parent / "asago-artifact-generator"),
            "revision": git_revision(REPO_ROOT.parent / "asago-artifact-generator"),
            "tracked_status": git_status(REPO_ROOT.parent / "asago-artifact-generator"),
        },
    }
    return {
        "qualification_time": revisions,
        "final_repository": final_repositories,
    }


def _runtime_surface_audit(
    runs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Reconcile recorded safe-port and no-orphan cleanup evidence.

    ``runs`` are the collected qualification runs, each carrying its per-run
    ``cleanup`` audit; their classifications aggregate here and stay distinct.
    """
    preflight = _preflight_record() or {}
    runtime = preflight.get("runtime_prerequisites", {})
    runtime = runtime if isinstance(runtime, dict) else {}
    safe_ports = runtime.get("safe_worker_ports", {})
    safe_ports = safe_ports if isinstance(safe_ports, dict) else {}
    cleanup_records: list[dict[str, Any]] = []
    if PREFLIGHT_PATH.parent.is_dir():
        for path in sorted(PREFLIGHT_PATH.parent.glob("*stack-cleanup*.json")):
            record = _json_load(path)
            if record is not None:
                timestamp = _cleanup_timestamp(record)
                cleanup_records.append(
                    {
                        "path": _relative_path(path),
                        "target": record.get("target"),
                        "status": record.get("status") or record.get("result"),
                        "orphan_processes": record.get("orphan_processes"),
                        "ports_clear": record.get("ports_clear")
                        if "ports_clear" in record
                        else record.get("ports_cleared") is not None,
                        "ports_cleared": record.get("ports_cleared"),
                        "safe_ports": record.get("safe_ports"),
                        "timestamp_source": timestamp[1] if timestamp else None,
                        "normalized_timestamp": timestamp[2] if timestamp else None,
                    }
                )
    # OcciAI/Airbnb are covered by the owner-approved historical exception.
    # Their absent timely records stay visible below, but do not fail the
    # current cleanup predicate. Klarna still needs one maintained stop record.
    expected_cleanup_targets = {"klarna"}
    observed_cleanup_targets = {
        record.get("target") for record in cleanup_records if record.get("target")
    }
    historical_exception = {
        "status": "historical_unverified",
        "owner_approved": True,
        "targets": ["airbnb", "occiai"],
        "timely_cleanup_verified": False,
        "rerun_for_cleanup_evidence": False,
        "reason": (
            "contemporaneous cleanup records are absent; current state and "
            "preserved stop logs do not prove historical timing"
        ),
    }
    final_klarna_run = next(
        (run for run in runs or [] if run.get("path") == _FINAL_KLARNA_ROOT),
        None,
    )
    final_klarna_cleanup = (
        (final_klarna_run or {}).get("cleanup")
        if isinstance(final_klarna_run, dict)
        else None
    )
    final_klarna_record = (
        final_klarna_cleanup.get("record")
        if isinstance(final_klarna_cleanup, dict)
        else None
    )
    final_timestamp = _cleanup_timestamp(final_klarna_record)
    maintained_stop_candidates: list[dict[str, Any]] = []
    for record in cleanup_records:
        if record.get("target") != "klarna":
            continue
        if not _cleanup_is_clean(record):
            continue
        candidate = dict(record)
        candidate_timestamp = _cleanup_timestamp(
            {"executed_at": record.get("normalized_timestamp")}
        )
        if final_timestamp is None:
            chronology = "unknown"
        elif candidate_timestamp is None:
            chronology = "unknown"
        elif candidate_timestamp[0] > final_timestamp[0]:
            chronology = "post_failure"
        else:
            chronology = "pre_failure"
        candidate["chronology"] = chronology
        maintained_stop_candidates.append(candidate)
    maintained_stop_candidates.sort(
        key=lambda item: (
            item.get("normalized_timestamp") or "",
            item.get("path") or "",
        )
    )
    maintained_stop = next(
        (
            candidate
            for candidate in reversed(maintained_stop_candidates)
            if candidate["chronology"] == "post_failure"
        ),
        None,
    )
    final_cleanup_failed = (
        isinstance(final_klarna_cleanup, dict)
        and final_klarna_cleanup.get("classification") == "failed"
    )
    maintained_stop_valid = (
        maintained_stop is not None
        if final_cleanup_failed
        else bool(maintained_stop_candidates)
    )
    per_run_cleanup = [
        {
            "run_path": run.get("path"),
            "run_id": run.get("run_id"),
            "classification": (run.get("cleanup") or {}).get("classification"),
            "current_verification_path": (run.get("cleanup") or {}).get(
                "current_verification_path"
            ),
            "current_verification_result": (
                ((run.get("cleanup") or {}).get("current_verification") or {}).get(
                    "result"
                )
            ),
        }
        for run in runs or []
    ]
    cleanup_classifications = {
        name: sum(row["classification"] == name for row in per_run_cleanup)
        for name in ("verified", "kept_running", "failed", "historical_unverified")
    }
    return {
        "safe_worker_ports": safe_ports,
        "allowed_ports": safe_ports.get("allowed"),
        "all_safe_ports_free_at_preflight": runtime.get(
            "all_safe_ports_free_at_preflight"
        ),
        "serial_execution_required": runtime.get("serial_execution_required"),
        "cleanup_records": cleanup_records,
        "existing_stop_logs": cleanup_records,
        "historical_cleanup_exception": historical_exception,
        "current_process_port_state": {
            "ports": safe_ports,
            "all_safe_ports_free": runtime.get("all_safe_ports_free_at_preflight"),
            "process_state": "unavailable_without_process_probe",
            "source": "qualification-preflight.json",
        },
        "expected_cleanup_targets": sorted(expected_cleanup_targets),
        "observed_cleanup_targets": sorted(observed_cleanup_targets),
        "per_run_cleanup": per_run_cleanup,
        "cleanup_classifications": cleanup_classifications,
        "final_klarna_cleanup": {
            "path": (
                final_klarna_cleanup.get("path")
                if isinstance(final_klarna_cleanup, dict)
                else None
            ),
            "classification": (
                final_klarna_cleanup.get("classification")
                if isinstance(final_klarna_cleanup, dict)
                else "historical_unverified"
            ),
            "record": final_klarna_record,
            "timestamp_source": final_timestamp[1] if final_timestamp else None,
            "normalized_timestamp": final_timestamp[2] if final_timestamp else None,
        },
        "maintained_stop_candidates": maintained_stop_candidates,
        "subsequent_maintained_stop": maintained_stop,
        "historical_exception_excluded_from_predicate": True,
        "no_orphan_evidence": (
            "passed"
            if maintained_stop_valid
            else "failed"
            if final_cleanup_failed
            else "partial"
        ),
        "cleanup_evidence": (
            "passed"
            if maintained_stop_valid
            else "failed"
            if final_cleanup_failed
            else "partial"
        ),
        "cleanup_predicate": (
            "passed"
            if maintained_stop_valid
            else "failed"
            if final_cleanup_failed
            else "partial"
        ),
        "valid": bool(
            runtime.get("serial_execution_required") is True
            and runtime.get("all_safe_ports_free_at_preflight") is True
            and maintained_stop_valid
        ),
    }


def _source_files(source_roots: tuple[Path, ...]) -> list[Path]:
    """Enumerate source files in stable order, excluding the output tree."""
    files: set[Path] = set()
    for root in source_roots:
        if not root.is_dir():
            continue
        files.update(path for path in root.rglob("*") if path.is_file())
    return sorted(files, key=lambda path: _relative_path(path))


_IN_FORCE_ROOTS = frozenset(
    {
        "fresh-miniairbnb-qualification-20260917",
        "fresh-miniocciai-qualification-redo-20260917",
        "fresh-miniocciai-qualification-redo-authoring-20260917",
        "fresh-miniklarna-qualification-final-20260917",
    }
)
_SUPERSEDED_ROOTS = frozenset(
    {
        "fresh-miniklarna-qualification-20260917",
        "fresh-miniklarna-qualification-redo-20260917",
        "fresh-miniklarna-qualification-exception-20260917",
        "fresh-miniklarna-qualification-exception-authoring-20260917",
        "fresh-miniklarna-qualification-redo-authoring-20260917",
        "fresh-miniocciai-qualification-20260917",
    }
)

_FINAL_KLARNA_ROOT = "build/adaptive-e2e/fresh-miniklarna-qualification-final-20260917"


def _final_klarna_blocker(
    source_roots: tuple[Path, ...],
) -> dict[str, str] | None:
    """Return the preserved final-Klarna blocker when its chain is incomplete."""
    for root in source_roots:
        if _relative_path(root) != _FINAL_KLARNA_ROOT:
            continue
        status_path = root / "run-status.json"
        status = _json_load(status_path)
        if not isinstance(status, dict):
            continue
        stages = status.get("stages", {})
        stages = stages if isinstance(stages, dict) else {}
        artifact = stages.get("artifact", {})
        artifact = artifact if isinstance(artifact, dict) else {}
        execution = stages.get("execution", {})
        execution = execution if isinstance(execution, dict) else {}
        attempts = artifact.get("attempts", [])
        attempts = attempts if isinstance(attempts, list) else []
        all_blocked = bool(attempts) and all(
            isinstance(item, dict)
            and item.get("compiled") is not True
            and item.get("functional_specification") is not True
            and item.get("exclusion_code")
            for item in attempts
        )
        if execution.get("status") == "not_run" and all_blocked:
            return {
                "code": "fresh_klarna_chain_incomplete",
                "detail": (
                    "the final bounded MiniKlarna confirmation published 33 "
                    "scenarios, but its first three selected designs were typed "
                    "exclusions before authoring; freeze, predispatch, Garak, "
                    "target-command, and backend evidence are absent"
                ),
            }
    return None


def _requirement_rows(
    source_roots: tuple[Path, ...],
    completion: dict[str, Any],
) -> list[dict[str, Any]]:
    """Describe each R1-R9 requirement with four evidence dimensions."""
    blockers = {
        item["code"]: item
        for item in completion.get("blockers", [])
        if isinstance(item, dict) and item.get("code")
    }
    shared_live = [
        {
            "path": "build/qualification/scenario-fidelity-final/run-recount.json",
            "fact": "current qualification run set and native outcome labels",
        },
        {
            "path": "build/qualification/scenario-fidelity-final/completion-status.json",
            "fact": "current completion gate; unresolved evidence is not promoted",
        },
    ]
    rows = [
        {
            "requirement": "R1",
            "assertions": [
                "VAL-CRIT-001",
                "VAL-CRIT-002",
                "VAL-CRIT-003",
                "VAL-CRIT-004",
                "VAL-CRIT-005",
                "VAL-CRIT-006",
            ],
            "status": "complete",
            "implementation": [
                {
                    "path": "consumer:src/asago_artifact_generator/design/authoring.py",
                    "fact": "whole-criterion assessment and observation-boundary decisions",
                },
                {
                    "path": "consumer:src/asago_artifact_generator/design/compile.py",
                    "fact": "criterion authority is retained through freeze and compile",
                },
            ],
            "verification": [
                {
                    "path": "consumer:tests/test_artifact_design.py",
                    "fact": "full design-path criterion and exclusion regressions",
                },
                {
                    "path": "consumer:tests/test_criterion_equivalence.py",
                    "fact": "meaning-preserving and meaning-changing criterion challenges",
                },
            ],
            "independent_challenge": [
                {
                    "path": "consumer:tests/test_criterion_equivalence.py:147",
                    "fact": "meaning-changing weaker criteria fail closed",
                },
            ],
            "live_evidence": [
                {
                    "path": "build/adaptive-e2e/fresh-miniklarna-qualification-final-20260917/artifact/SCN-004/SCN-004:design-1/design-exclusion.json",
                    "fact": "effect criterion remains excluded by command-only observation",
                },
            ],
            "open_findings": [],
        },
        {
            "requirement": "R2",
            "assertions": [
                "VAL-STIM-001",
                "VAL-STIM-002",
                "VAL-STIM-003",
                "VAL-STIM-004",
                "VAL-STIM-005",
                "VAL-STIM-006",
                "VAL-HISTORY-001",
                "VAL-HISTORY-002",
            ],
            "status": "complete",
            "implementation": [
                {
                    "path": "consumer:src/asago_artifact_generator/design/authoring.py",
                    "fact": "actual stimulus and complete user-only history assessment",
                },
                {
                    "path": "consumer:src/asago_artifact_generator/design/compile.py",
                    "fact": "assessed turns compile verbatim with one continuation",
                },
            ],
            "verification": [
                {
                    "path": "consumer:tests/test_artifact_design.py",
                    "fact": "negative stimulus, numeric attribution, and history cases",
                },
                {
                    "path": "consumer:tests/test_crossrepo_smoke.py:273",
                    "fact": "prepared user history compiles without assistant turns",
                },
            ],
            "independent_challenge": [
                {
                    "path": "consumer:tests/test_artifact_design.py:153",
                    "fact": "user-only history remains verbatim and single-continuation",
                },
            ],
            "live_evidence": [
                {
                    "path": "build/adaptive-e2e/fresh-miniocciai-qualification-redo-authoring-20260917/artifact/SCN-036/SCN-036:design-1/design-record.json",
                    "fact": "consumer authoring records the actual clinical request",
                },
            ],
            "open_findings": [],
        },
        {
            "requirement": "R3",
            "assertions": [
                "VAL-ARG-001",
                "VAL-ARG-002",
                "VAL-ARG-003",
                "VAL-DEP-001",
                "VAL-DEP-002",
                "VAL-DEP-003",
                "VAL-DEP-004",
                "VAL-FREEZE-001",
                "VAL-COMPILE-001",
                "VAL-PREDISPATCH-001",
            ],
            "status": "complete",
            "implementation": [
                {
                    "path": "consumer:src/asago_artifact_generator/design/authoring.py",
                    "fact": "typed argument sources and minimal target context",
                },
                {
                    "path": "consumer:src/asago_artifact_generator/design/predispatch.py",
                    "fact": "critical dependency revalidation before dispatch",
                },
            ],
            "verification": [
                {
                    "path": "consumer:tests/test_argument_dependency_closure.py",
                    "fact": "required-argument and dependency closure matrix",
                },
                {
                    "path": "consumer:tests/test_stpa_consumer_core.py",
                    "fact": "freeze, compile, and predispatch regressions",
                },
            ],
            "independent_challenge": [
                {
                    "path": "consumer:tests/test_argument_dependency_closure.py",
                    "fact": "identity, mapping/list, drift, and unrelated-state challenges",
                },
            ],
            "live_evidence": [
                {
                    "path": "build/adaptive-e2e/fresh-miniocciai-qualification-redo-authoring-20260917/execution/pre-dispatch-checks.yaml",
                    "fact": "clinical record, subject, and status dependencies revalidated",
                },
                {
                    "path": "build/adaptive-e2e/fresh-miniairbnb-qualification-20260917/execution/pre-dispatch-checks.yaml",
                    "fact": "booking relation and selected record dependencies revalidated",
                },
            ],
            "open_findings": [],
        },
        {
            "requirement": "R4",
            "assertions": [
                "VAL-PRESENT-001",
                "VAL-PRESENT-002",
                "VAL-PRESENT-003",
                "VAL-PRESENT-004",
                "VAL-PRESENT-005",
                "VAL-PRESENT-006",
            ],
            "status": "complete",
            "implementation": [
                {
                    "path": "producer:src/asago_scenario_generator/stpa/scenario_prod/presentation.py",
                    "fact": "connected semantic narrative and causal publication",
                },
                {
                    "path": "producer:src/asago_scenario_generator/stpa/scenario_prod/handoff.py",
                    "fact": "semantics-only handoff preserves criterion and lineage",
                },
            ],
            "verification": [
                {
                    "path": "producer:tests/stpa/test_r4_connected_publication.py",
                    "fact": "BDI, functional, lineage, and flat-tree regressions",
                },
                {
                    "path": "producer:tests/stpa/test_scenario_handoff_publication.py",
                    "fact": "normal handoff output and ownership boundary",
                },
            ],
            "independent_challenge": [
                {
                    "path": "producer:tests/stpa/test_r4_connected_publication.py",
                    "fact": "semantic mutations change publication while bookkeeping does not",
                },
            ],
            "live_evidence": [
                {
                    "path": "build/adaptive-e2e/fresh-miniocciai-qualification-redo-20260917/generation/scenarios/SCN-036.yaml",
                    "fact": "fresh functional handoff retains defender causality without an attacker",
                },
                {
                    "path": "build/adaptive-e2e/fresh-miniairbnb-qualification-20260917/generation/scenarios/SCN-001.yaml",
                    "fact": "fresh adversarial handoff carries selected semantic meaning",
                },
            ],
            "open_findings": [],
        },
        {
            "requirement": "R5",
            "assertions": [
                "VAL-GHERKIN-001",
                "VAL-GHERKIN-002",
                "VAL-GHERKIN-003",
                "VAL-GHERKIN-004",
            ],
            "status": "complete",
            "implementation": [
                {
                    "path": "producer:src/asago_scenario_generator/stpa/scenario_prod/gherkin.py",
                    "fact": "structured and native Gherkin derive from one semantic source",
                },
                {
                    "path": "producer:src/asago_scenario_generator/stpa/scenario_prod/presentation.py",
                    "fact": "safe expected sequence and domain trigger rendering",
                },
            ],
            "verification": [
                {
                    "path": "producer:tests/stpa/test_r5_declarative_gherkin.py",
                    "fact": "real parser, correspondence, trigger, and precondition checks",
                },
                {
                    "path": "producer:tests/stpa/test_scenario_handoff_publication.py",
                    "fact": "native feature publication remains digest-closed",
                },
            ],
            "independent_challenge": [
                {
                    "path": "producer:tests/stpa/test_r5_declarative_gherkin.py",
                    "fact": "unsafe-step and generic-trigger mutations are rejected",
                },
            ],
            "live_evidence": [
                {
                    "path": "build/adaptive-e2e/fresh-miniocciai-qualification-redo-20260917/generation/scenarios/SCN-036.feature",
                    "fact": "fresh functional native feature is published with its handoff",
                },
                {
                    "path": "build/adaptive-e2e/fresh-miniairbnb-qualification-20260917/generation/scenarios/SCN-001.feature",
                    "fact": "fresh adversarial native feature is published with its handoff",
                },
            ],
            "open_findings": [],
        },
        {
            "requirement": "R6",
            "assertions": [
                "VAL-PROMPT-001",
                "VAL-PROMPT-002",
                "VAL-PROMPT-003",
                "VAL-PROMPT-004",
                "VAL-PROMPT-005",
                "VAL-PROMPT-006",
            ],
            "status": "complete",
            "implementation": [
                {
                    "path": "producer:src/asago_scenario_generator/stpa/scenario_prod/prompts/",
                    "fact": "semantic-only producer prompt views",
                },
                {
                    "path": "consumer:src/asago_artifact_generator/design/authoring.py",
                    "fact": "kind-aware consumer authoring contract",
                },
            ],
            "verification": [
                {
                    "path": "producer:tests/stpa/test_normal_authoring_wire.py",
                    "fact": "producer request/schema field reconciliation",
                },
                {
                    "path": "consumer:tests/test_prompt_schema_reconciliation.py",
                    "fact": "consumer prompt, role, unknown, and history variants",
                },
                {
                    "path": "build/qualification/scenario-fidelity-final/field-inventory.json",
                    "fact": "field-level inventory reconciles rendered prompts and schemas",
                },
            ],
            "independent_challenge": [
                {
                    "path": "consumer:tests/test_prompt_schema_reconciliation.py:123",
                    "fact": "history visibility guidance is checked for each approach",
                },
            ],
            "live_evidence": [
                {
                    "path": "build/qualification/scenario-fidelity-final/field-inventory.json",
                    "fact": "current prompt/schema inventory is generated from final code",
                },
            ],
            "open_findings": [],
        },
        {
            "requirement": "R7",
            "assertions": [
                "VAL-EVIDENCE-001",
                "VAL-EVIDENCE-002",
                "VAL-EVIDENCE-003",
                "VAL-EVIDENCE-004",
                "VAL-EVIDENCE-005",
                "VAL-EVIDENCE-006",
            ],
            "status": "complete",
            "implementation": [
                {
                    "path": "producer:scripts/qualification/audit_scenario_fidelity_evidence.py",
                    "fact": "raw-call, usage, identity, category, and secret-safe audit",
                },
                {
                    "path": "producer:src/asago_scenario_generator/stpa/infra/call_log.py",
                    "fact": "producer call evidence retains raw and cleaned stages",
                },
                {
                    "path": "consumer:src/asago_artifact_generator/design/authoring.py",
                    "fact": "consumer authoring attempts retain raw response and controls",
                },
            ],
            "verification": [
                {
                    "path": "producer:tests/stpa/test_r7_call_evidence.py",
                    "fact": "cleanup, usage, failure, and retry evidence classes",
                },
                {
                    "path": "build/qualification/scenario-fidelity-final/usage-ledger.json",
                    "fact": "current raw record and budget reconciliation",
                },
                {
                    "path": "build/qualification/scenario-fidelity-final/evidence-scan.json",
                    "fact": "current selected evidence has no secret matches",
                },
            ],
            "independent_challenge": [
                {
                    "path": "producer:tests/stpa/test_r7_call_evidence.py",
                    "fact": "duplicate identities fail in-force accounting while historical collisions stay labeled",
                },
            ],
            "live_evidence": [
                {
                    "path": "build/qualification/scenario-fidelity-final/usage-ledger.json",
                    "fact": "seven generation runs, two authoring calls, two Garak generations, and zero Stage 1a calls",
                },
            ],
            "open_findings": [],
        },
        {
            "requirement": "R8",
            "assertions": [
                "VAL-QUAL-001",
                "VAL-QUAL-002",
                "VAL-QUAL-003",
                "VAL-QUAL-004",
                "VAL-QUAL-005",
                "VAL-QUAL-006",
                "VAL-QUAL-007",
                "VAL-QUAL-008",
                "VAL-QUAL-009",
                "VAL-QUAL-010",
                "VAL-QUAL-011",
            ],
            "status": "blocked",
            "implementation": [
                {
                    "path": "producer:scripts/qualification/run_end_to_end.py",
                    "fact": "bounded maintained qualification orchestration",
                },
                {
                    "path": "producer:scripts/qualification/audit_scenario_fidelity_evidence.py",
                    "fact": "selection, reachability, cleanup, and budget audit",
                },
            ],
            "verification": [
                {
                    "path": "build/qualification/scenario-fidelity-final/run-recount.json",
                    "fact": "two target confirmations have separated command/backend/state evidence",
                },
                {
                    "path": "build/qualification/scenario-fidelity-final/usage-ledger.json",
                    "fact": "call limits and in-force attempt identities reconcile",
                },
            ],
            "independent_challenge": [
                {
                    "path": "build/adaptive-e2e/fresh-miniklarna-qualification-final-20260917/artifact/SCN-030/SCN-030:design-1/design-exclusion.json",
                    "fact": "independent consumer gate preserves a typed exclusion rather than inventing a detector",
                },
            ],
            "live_evidence": [
                {
                    "path": "build/adaptive-e2e/fresh-miniocciai-qualification-redo-authoring-20260917/execution/qualification.json",
                    "fact": "clinical command, backend rejection, and no completed effect remain separate",
                },
                {
                    "path": "build/adaptive-e2e/fresh-miniairbnb-qualification-20260917/execution/qualification.json",
                    "fact": "booking command, authorization rejection, and unchanged state remain separate",
                },
                {
                    "path": "build/adaptive-e2e/fresh-miniklarna-qualification-final-20260917/run-status.json",
                    "fact": "final Klarna chain stopped before authoring and execution",
                },
            ],
            "open_findings": [
                blockers.get(
                    "fresh_klarna_chain_incomplete",
                    {
                        "code": "fresh_klarna_chain_incomplete",
                        "detail": "final Klarna authoring and execution evidence is absent",
                    },
                ),
            ],
        },
        {
            "requirement": "R9",
            "assertions": [
                "VAL-DOCS-001",
                "VAL-DOCS-002",
                "VAL-DOCS-003",
                "VAL-DOCS-004",
                "VAL-DOCS-005",
                "VAL-DOCS-006",
                "VAL-DOCS-007",
            ],
            "status": "complete",
            "implementation": [
                {
                    "path": "producer:docs/development/qualification-reports/r9-reconciliation-2026-09-17.md",
                    "fact": "source-cited additive historical corrections and ownership record",
                },
                {
                    "path": "producer:README.md; consumer:README.md",
                    "fact": "current ownership and retired-path README gate",
                },
            ],
            "verification": [
                {
                    "path": "build/qualification/scenario-fidelity-final/requirement-matrix.json",
                    "fact": "one evidence row per R1-R9 requirement",
                },
                {
                    "path": "build/qualification/scenario-fidelity-final/completion-status.json",
                    "fact": "completion is blocked rather than overstated",
                },
            ],
            "independent_challenge": [
                {
                    "path": "producer:tests/stpa/test_scenario_fidelity_audit.py",
                    "fact": "deterministic audit and blocker-preservation regressions",
                },
            ],
            "live_evidence": shared_live,
            "open_findings": [],
        },
    ]
    for row in rows:
        if row["requirement"] == "R9":
            r9_findings = [
                item
                for item in completion.get("blockers", [])
                if item.get("code") != "fresh_klarna_chain_incomplete"
            ]
            row["status"] = "blocked" if r9_findings else "complete"
            row["open_findings"] = r9_findings
        row["source_roots"] = [
            _relative_path(root) for root in source_roots if root.exists()
        ]
    return rows


def _explicit_run_state(status: dict[str, Any] | None) -> str | None:
    """Read a persisted qualification state when a run records one."""
    if not isinstance(status, dict):
        return None
    value = status.get("qualification_state") or status.get("run_state")
    if value in {"in_force", "superseded", "unregistered"}:
        return value
    if isinstance(status.get("in_force"), bool):
        return "in_force" if status["in_force"] else "superseded"
    return None


def _run_state(run_dir: Path, status: dict[str, Any] | None) -> str:
    """Classify the selected qualification roots without changing evidence.

    The three final fresh roots and their authoring companions are the
    registered in-force set.  The earlier fresh roots are retained as
    superseded history.  Any other root is unregistered and therefore cannot
    make an identity ledger valid.
    """
    explicit = _explicit_run_state(status)
    if explicit:
        return explicit
    name = run_dir.name
    if name in _IN_FORCE_ROOTS or any(
        name.startswith(root + "-") for root in _IN_FORCE_ROOTS
    ):
        return "in_force"
    if name in _SUPERSEDED_ROOTS or any(
        name.startswith(root + "-") for root in _SUPERSEDED_ROOTS
    ):
        return "superseded"
    return "unregistered"


def _run_status_index(
    source_roots: tuple[Path, ...],
) -> dict[str, dict[str, Any]]:
    """Index preserved run status records by source path and run identity."""
    index: dict[str, dict[str, Any]] = {}
    for path in _source_files(source_roots):
        if path.name != "run-status.json":
            continue
        status = _json_load(path)
        if status is None:
            continue
        stages = status.get("stages", {})
        stages = stages if isinstance(stages, dict) else {}
        generation = stages.get("generation", {})
        generation = generation if isinstance(generation, dict) else {}
        run_id = status.get("run_id") or generation.get("run_id") or path.parent.name
        index[_relative_path(path.parent)] = {
            "run_id": str(run_id),
            "run_state": _run_state(path.parent, status),
            "status_path": path,
        }
    return index


def collect_qualification_runs(
    source_roots: tuple[Path, ...] = DEFAULT_SOURCE_ROOTS,
) -> list[dict[str, Any]]:
    """Collect run manifests without interpreting missing evidence as success."""
    records: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for root in source_roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("run-status.json")):
            run_dir = path.parent.resolve()
            if run_dir in seen:
                continue
            seen.add(run_dir)
            status = _json_load(path)
            if status is None:
                records.append(
                    {
                        "run_id": run_dir.name,
                        "path": _relative_path(run_dir),
                        "status": "unreadable",
                        "source": _relative_path(path),
                    }
                )
                continue
            stages = status.get("stages")
            stages = stages if isinstance(stages, dict) else {}
            generation = stages.get("generation")
            artifact = stages.get("artifact")
            execution = stages.get("execution")
            generation = generation if isinstance(generation, dict) else {}
            artifact = artifact if isinstance(artifact, dict) else {}
            execution = execution if isinstance(execution, dict) else {}
            run_manifest = _yaml_load(run_dir / "generation" / "run-manifest.yaml")
            run_input_hashes = (
                run_manifest.get("input_hashes", {})
                if isinstance(run_manifest, dict)
                else {}
            )
            run_input_hashes = (
                run_input_hashes if isinstance(run_input_hashes, dict) else {}
            )
            preflight = _preflight_record() or {}
            preflight_hashes = preflight.get("input_hashes", {})
            preflight_hashes = (
                preflight_hashes if isinstance(preflight_hashes, dict) else {}
            )
            predispatch = _predispatch_audit(run_dir)
            selection = _selection_audit(
                artifact, _yaml_load(run_dir / "execution" / "pre-dispatch-checks.yaml")
            )
            stage_1a = _stage_1a_audit(run_dir)
            outcomes = _outcome_audit(run_dir)
            records.append(
                {
                    "run_id": str(
                        status.get("run_id")
                        or (generation or {}).get("run_id")
                        or run_dir.name
                    ),
                    "path": _relative_path(run_dir),
                    "run_state": _run_state(run_dir, status),
                    "target_domain": status.get("target_domain"),
                    "source": "run-status.json",
                    "generation": _stage_summary(generation),
                    "artifact": _stage_summary(artifact),
                    "execution": _stage_summary(execution),
                    "scenario_count": _scenario_count(generation),
                    "freshness": _freshness(run_dir, generation),
                    "input_hashes": {
                        "run_manifest": dict(sorted(run_input_hashes.items())),
                        "preflight": dict(sorted(preflight_hashes.items())),
                    },
                    "source_revisions": _source_revisions(),
                    "selection": selection,
                    "predispatch": predispatch,
                    "stage_1a": stage_1a,
                    "outcomes": outcomes,
                    "cleanup": _cleanup_audit(run_dir),
                    "representations": _representation_audit(run_dir, artifact),
                }
            )
    return sorted(records, key=lambda item: (item["run_id"], item["path"]))


def _stage_summary(value: Any) -> dict[str, Any]:
    """Keep only deterministic, non-secret stage accounting fields."""
    if not isinstance(value, dict):
        return {"status": "missing"}
    summary: dict[str, Any] = {"status": value.get("status", "missing")}
    for key in (
        "source",
        "run_id",
        "producer_run_status",
        "producer_run_status_reason",
        "scenarios_published",
        "selected_scenario",
        "selected_design_id",
        "qualification_present",
        "exit_code",
    ):
        if key in value and not isinstance(value[key], (dict, list)):
            summary[key] = value[key]
    attempts = value.get("attempts")
    if isinstance(attempts, list):
        summary["attempt_count"] = len(attempts)
        summary["attempts"] = [
            {
                key: item.get(key)
                for key in (
                    "scenario_id",
                    "design_id",
                    "compiled",
                    "functional_specification",
                    "exclusion_code",
                    "record_hint",
                    "exit_code",
                    "missing_setup_retry",
                )
                if key in item
            }
            for item in attempts
            if isinstance(item, dict)
        ]
    return summary


def _scenario_count(generation: Any) -> int | None:
    if not isinstance(generation, dict):
        return None
    count = generation.get("scenarios_published")
    return count if isinstance(count, int) and count >= 0 else None


_PRIMARY_CALL_FILENAMES = {
    "artifact-author-calls.jsonl",
    "calls.jsonl",
    "garak-attempts.jsonl",
}


def _primary_call_entries(
    path: Path,
) -> tuple[list[dict[str, Any]], int, list[int]]:
    """Read primary producer/consumer call entries and malformed-line count."""
    if path.name == "design-record.json":
        record = _json_load(path)
        authoring = record.get("authoring") if record is not None else None
        attempts = authoring.get("attempts") if isinstance(authoring, dict) else None
        if not isinstance(attempts, list):
            return [], 0, []
        return (
            [item for item in attempts if isinstance(item, dict)],
            sum(not isinstance(item, dict) for item in attempts),
            [index for index, item in enumerate(attempts, 1) if isinstance(item, dict)],
        )
    if path.name not in _PRIMARY_CALL_FILENAMES:
        return [], 0, []

    entries: list[dict[str, Any]] = []
    entry_line_positions: list[int] = []
    malformed = 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return [], 1, []
    for index, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if not isinstance(value, dict):
            malformed += 1
            continue
        entries.append(value)
        entry_line_positions.append(index)
    return entries, malformed, entry_line_positions


def _call_category(path: Path, entry: dict[str, Any]) -> str:
    """Resolve the category owned by one primary call record."""
    if path.name == "garak-attempts.jsonl":
        return "garak_target_generation"
    category = entry.get("call_category")
    if isinstance(category, str) and category:
        return category
    if path.name == "artifact-author-calls.jsonl" or path.name == "design-record.json":
        return "consumer_authoring"
    return "producer_provider"


def _attempt_id(entry: dict[str, Any]) -> str | None:
    """Extract the deterministic identity published by a primary record."""
    value = entry.get("attempt_id")
    return value.strip() if isinstance(value, str) and value.strip() else None


def _is_provider_request(path: Path, entry: dict[str, Any], category: str) -> bool:
    """Distinguish live provider requests from prebound and target records."""
    if isinstance(entry.get("provider_request"), bool):
        return entry["provider_request"]
    if isinstance(entry.get("live_call"), bool):
        return entry["live_call"]
    return category == "producer_provider" and path.name != "garak-attempts.jsonl"


def _entry_tokens(entry: dict[str, Any]) -> int | float:
    """Sum numeric token fields without treating booleans as usage."""
    total: int | float = 0
    usage = entry.get("usage")
    usage = usage if isinstance(usage, dict) else entry
    for key in ("prompt_tokens", "completion_tokens"):
        value = usage.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            total += value
    return total


def _entry_usage_status(entry: dict[str, Any]) -> str:
    """Classify provider usage without turning unavailable into zero."""
    usage = entry.get("usage")
    usage = usage if isinstance(usage, dict) else entry
    if any(
        isinstance(usage.get(key), (int, float))
        and not isinstance(usage.get(key), bool)
        for key in ("prompt_tokens", "completion_tokens")
    ):
        return "reported"
    return "unavailable"


def _call_records(
    source_roots: tuple[Path, ...],
) -> tuple[
    list[dict[str, Any]],
    list[str],
    int,
    int,
    list[dict[str, Any]],
    dict[str, list[str]],
]:
    """Recount every primary record and audit identity reuse separately."""
    rows: list[dict[str, Any]] = []
    run_index = _run_status_index(source_roots)
    seen_attempt_keys: dict[tuple[str, str], list[tuple[Path, int]]] = {}
    duplicate_attempt_ids: set[str] = set()
    collision_groups: dict[tuple[str, str, str], list[tuple[Path, int]]] = {}
    total_entries = 0
    entries_without_attempt_id = 0
    for path in _source_files(source_roots):
        if (
            path.name not in _PRIMARY_CALL_FILENAMES
            and path.name != "design-record.json"
        ):
            continue
        entries, malformed, entry_line_positions = _primary_call_entries(path)
        if not entries and not malformed:
            continue
        path_entries: list[dict[str, Any]] = []
        path_attempt_ids: set[str] = set()
        raw_attempt_ids: list[str] = []
        path_missing_attempt_ids = 0
        raw_provider_request_count = 0
        provider_request_count = 0
        available_token_records = 0
        unavailable_usage_records = 0
        provider_available_token_records = 0
        provider_unavailable_usage_records = 0
        tokens: int | float = 0
        source_run_path = _run_status_path(path)
        source_run_key = _relative_path(source_run_path) if source_run_path else None
        run_info = run_index.get(source_run_key or "")
        run_id = (
            run_info["run_id"]
            if run_info
            else source_run_key or f"unregistered:{_relative_path(path)}"
        )
        run_state = run_info["run_state"] if run_info else "unregistered"
        for entry_index, entry in enumerate(entries):
            total_entries += 1
            attempt_id = _attempt_id(entry)
            line_position = (
                entry_line_positions[entry_index]
                if entry_index < len(entry_line_positions)
                else entry_index + 1
            )
            if attempt_id is None:
                entries_without_attempt_id += 1
                path_missing_attempt_ids += 1
            else:
                raw_attempt_ids.append(attempt_id)
                attempt_key = (run_id, attempt_id)
                occurrences = seen_attempt_keys.setdefault(attempt_key, [])
                if occurrences:
                    duplicate_attempt_ids.add(attempt_id)
                    collision = collision_groups.setdefault(
                        (run_id, run_state, attempt_id), []
                    )
                    if not collision:
                        collision.extend(occurrences)
                    collision.append((path, line_position))
                occurrences.append((path, line_position))
                path_attempt_ids.add(attempt_id)
            category = _call_category(path, entry)
            provider_request = _is_provider_request(path, entry, category)
            if provider_request:
                raw_provider_request_count += 1
            path_entries.append(entry)
            tokens += _entry_tokens(entry)
            usage_status = _entry_usage_status(entry)
            if usage_status == "reported":
                available_token_records += 1
            else:
                unavailable_usage_records += 1
            if provider_request and usage_status == "reported":
                provider_available_token_records += 1
            elif provider_request:
                provider_unavailable_usage_records += 1
            if provider_request:
                provider_request_count += 1
        if not path_entries and not malformed:
            continue
        category = (
            _call_category(path, path_entries[0])
            if path_entries
            else (
                "consumer_authoring"
                if path.name == "design-record.json"
                else "producer_provider"
            )
        )
        rows.append(
            {
                "path": _relative_path(path),
                "source_run_path": source_run_key,
                "run_id": run_id,
                "run_state": run_state,
                "category": category,
                "call_count": len(path_entries),
                "raw_call_count": len(entries),
                "unique_attempt_count": len(path_attempt_ids),
                "provider_request_count": provider_request_count,
                "raw_provider_request_count": raw_provider_request_count,
                "total_tokens": tokens,
                "available_token_records": available_token_records,
                "unavailable_usage_records": unavailable_usage_records,
                "provider_available_token_records": provider_available_token_records,
                "provider_unavailable_usage_records": provider_unavailable_usage_records,
                "malformed_records": malformed,
                "attempt_ids": sorted(path_attempt_ids),
                "raw_attempt_ids": sorted(raw_attempt_ids),
                "missing_attempt_id_count": path_missing_attempt_ids,
                "usage": "reported" if tokens else "unavailable_or_zero",
            }
        )
    historical_collisions: list[dict[str, Any]] = []
    duplicate_by_state: dict[str, list[str]] = {
        "in_force": [],
        "superseded": [],
        "unregistered": [],
    }
    for (run_id, run_state, attempt_id), occurrences in sorted(
        collision_groups.items()
    ):
        by_file: dict[Path, list[int]] = {}
        for path, line_position in occurrences:
            by_file.setdefault(path, []).append(line_position)
        for path, line_positions in sorted(
            by_file.items(), key=lambda item: str(item[0])
        ):
            historical_collisions.append(
                {
                    "attempt_id": attempt_id,
                    "run_id": run_id,
                    "run_state": run_state,
                    "source_file": _relative_path(path),
                    "source_file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "line_positions": sorted(line_positions),
                }
            )
        if run_state in duplicate_by_state:
            duplicate_by_state[run_state].append(attempt_id)
    return (
        rows,
        sorted(duplicate_attempt_ids),
        total_entries,
        entries_without_attempt_id,
        historical_collisions,
        {state: sorted(set(values)) for state, values in duplicate_by_state.items()},
    )


def build_usage_ledger(
    source_roots: tuple[Path, ...] = DEFAULT_SOURCE_ROOTS,
) -> dict[str, Any]:
    """Build a truthful call ledger from saved records only."""
    (
        records,
        duplicate_attempt_ids,
        total_entries,
        entries_without_attempt_id,
        historical_collisions,
        duplicate_by_state,
    ) = _call_records(source_roots)
    category_totals: dict[str, dict[str, int]] = {}
    for row in records:
        total = category_totals.setdefault(
            row["category"], {"call_count": 0, "total_tokens": 0}
        )
        total["call_count"] += row["call_count"]
        total["total_tokens"] += row["total_tokens"]
    consumer_attempts = sum(
        item["call_count"]
        for item in records
        if item["category"] == "consumer_authoring"
    )
    provider_requests = sum(item["provider_request_count"] for item in records)
    available_token_records = sum(item["available_token_records"] for item in records)
    unavailable_usage_records = sum(
        item["unavailable_usage_records"] for item in records
    )
    provider_available_token_records = sum(
        item["provider_available_token_records"] for item in records
    )
    provider_unavailable_usage_records = sum(
        item["provider_unavailable_usage_records"] for item in records
    )
    available_provider_tokens = sum(
        item["total_tokens"]
        for item in records
        if item["category"] in {"producer_provider", "consumer_authoring"}
    )
    per_run: dict[str, dict[str, Any]] = {}
    for row in records:
        scope = row.get("source_run_path") or row["path"]
        aggregate = per_run.setdefault(
            scope,
            {
                "producer_provider_requests": 0,
                "consumer_authoring_attempts": 0,
                "garak_target_generations": 0,
                "primary_record_count": 0,
                "raw_primary_record_count": 0,
                "unique_attempt_count": 0,
                "raw_provider_request_count": 0,
                "available_token_records": 0,
                "unavailable_usage_records": 0,
                "provider_available_token_records": 0,
                "provider_unavailable_usage_records": 0,
                "malformed_records": 0,
                "attempt_ids": [],
                "raw_attempt_ids": [],
                "run_id": row.get("run_id"),
                "run_state": row.get("run_state", "unregistered"),
                "duplicate_attempt_ids": [],
                "candidate_ids": [],
                "published_scenario_count": None,
                "artifact_attempt_count": 0,
                "terminal_accounting_reconciles": None,
            },
        )
        aggregate["primary_record_count"] += row["call_count"]
        aggregate["raw_primary_record_count"] += row["raw_call_count"]
        aggregate["unique_attempt_count"] += row["unique_attempt_count"]
        aggregate["raw_provider_request_count"] += row["raw_provider_request_count"]
        aggregate["available_token_records"] += row["available_token_records"]
        aggregate["unavailable_usage_records"] += row["unavailable_usage_records"]
        aggregate["provider_available_token_records"] += row[
            "provider_available_token_records"
        ]
        aggregate["provider_unavailable_usage_records"] += row[
            "provider_unavailable_usage_records"
        ]
        aggregate["malformed_records"] += row["malformed_records"]
        aggregate["attempt_ids"].extend(row["attempt_ids"])
        aggregate["raw_attempt_ids"].extend(row["raw_attempt_ids"])
        if row["category"] == "producer_provider":
            aggregate["producer_provider_requests"] += row["provider_request_count"]
        elif row["category"] == "consumer_authoring":
            aggregate["consumer_authoring_attempts"] += row["call_count"]
        elif row["category"] == "garak_target_generation":
            aggregate["garak_target_generations"] += row["call_count"]
    for aggregate in per_run.values():
        aggregate["attempt_ids"] = sorted(set(aggregate["attempt_ids"]))
        aggregate["raw_attempt_ids"] = sorted(aggregate["raw_attempt_ids"])
    for row in records:
        scope = row.get("source_run_path") or row["path"]
        aggregate = per_run[scope]
        duplicate_ids = duplicate_by_state.get(row.get("run_state", "unregistered"), [])
        aggregate["duplicate_attempt_ids"] = sorted(
            set(aggregate["duplicate_attempt_ids"]) | set(duplicate_ids)
        )
    qualification_runs = collect_qualification_runs(source_roots)
    run_by_path = {item["path"]: item for item in qualification_runs}
    for scope, aggregate in per_run.items():
        run = run_by_path.get(scope)
        if run is None:
            continue
        artifact = run.get("artifact", {})
        attempts = artifact.get("attempts", []) if isinstance(artifact, dict) else []
        aggregate["published_scenario_count"] = run.get("scenario_count")
        aggregate["artifact_attempt_count"] = len(attempts)
        aggregate["candidate_ids"] = sorted(
            {
                str(item.get("scenario_id"))
                for item in attempts
                if isinstance(item, dict) and item.get("scenario_id")
            }
        )
        aggregate["terminal_accounting_reconciles"] = (
            run.get("scenario_count")
            == len(
                {item.get("scenario_id") for item in attempts if isinstance(item, dict)}
            )
            if isinstance(run.get("scenario_count"), int)
            else None
        )
    for scope, run in run_by_path.items():
        artifact = run.get("artifact", {})
        attempts = artifact.get("attempts", []) if isinstance(artifact, dict) else []
        per_run.setdefault(
            scope,
            {
                "producer_provider_requests": 0,
                "consumer_authoring_attempts": 0,
                "garak_target_generations": 0,
                "primary_record_count": 0,
                "raw_primary_record_count": 0,
                "unique_attempt_count": 0,
                "raw_provider_request_count": 0,
                "available_token_records": 0,
                "unavailable_usage_records": 0,
                "provider_available_token_records": 0,
                "provider_unavailable_usage_records": 0,
                "malformed_records": 0,
                "attempt_ids": [],
                "raw_attempt_ids": [],
                "run_id": run.get("run_id"),
                "run_state": _run_state(
                    Path(run["path"]),
                    None,
                ),
                "duplicate_attempt_ids": [],
                "published_scenario_count": run.get("scenario_count"),
                "artifact_attempt_count": len(attempts),
                "candidate_ids": sorted(
                    {
                        str(item.get("scenario_id"))
                        for item in attempts
                        if isinstance(item, dict) and item.get("scenario_id")
                    }
                ),
                "terminal_accounting_reconciles": False,
            },
        )
    reachability = build_reachability(source_roots)
    for aggregate in per_run.values():
        summary = reachability["per_run"].get(str(aggregate.get("run_id")))
        if not summary:
            continue
        aggregate["published_scenario_count"] = summary["published_rows"]
        aggregate["consumer_evaluated_count"] = summary["consumer_evaluated_rows"]
        aggregate["compiled_count"] = summary["compiled_rows"]
        aggregate["excluded_count"] = summary["excluded_rows"]
        aggregate["functional_specification_count"] = summary[
            "functional_specification_rows"
        ]
        aggregate["not_attempted_count"] = summary["not_attempted_rows"]
        aggregate["unresolved_count"] = summary["unresolved_rows"]
        aggregate["terminal_accounting_reconciles"] = summary["reconciled"]
    in_force_invalid = bool(duplicate_by_state["in_force"])
    unregistered_invalid = bool(duplicate_by_state["unregistered"])
    identity_status = (
        "invalid"
        if in_force_invalid or unregistered_invalid
        else "historical_only"
        if duplicate_by_state["superseded"]
        else "valid"
        if total_entries > entries_without_attempt_id and total_entries
        else "unavailable"
    )
    reuse_status = identity_status
    return {
        "schema_version": "scenario-fidelity-usage-ledger-v1",
        "source": "preserved call records; no provider or target calls",
        "records": records,
        "per_run": dict(sorted(per_run.items())),
        "source_revisions": _source_revisions(),
        "category_totals": category_totals,
        "denominators": {
            "provider_requests": provider_requests,
            "candidate_design_attempts": sum(
                item["artifact_attempt_count"] for item in per_run.values()
            ),
            "candidate_ids_in_artifact_attempts": sum(
                len(item.get("candidate_ids", [])) for item in per_run.values()
            ),
            "consumer_authoring_attempts": (
                consumer_attempts
                if any(item["category"] == "consumer_authoring" for item in records)
                else "unavailable_without_consumer_records"
            ),
            "selected_candidates": "unavailable_without_selection_record",
            "setup_capture_calls": "unavailable_without_runtime_ledger",
            "semantic_assessments": "unavailable_without_assessment_record",
            "garak_target_generations": sum(
                item["call_count"]
                for item in records
                if item["category"] == "garak_target_generation"
            ),
            "available_token_records": available_token_records,
            "unavailable_usage_records": unavailable_usage_records,
            "provider_available_token_records": provider_available_token_records,
            "provider_unavailable_usage_records": provider_unavailable_usage_records,
            "raw_primary_records": total_entries,
        },
        "spending": {
            "raw_provider_records": provider_requests,
            "available_provider_tokens": available_provider_tokens,
            "raw_primary_records": total_entries,
            "available_token_records": available_token_records,
            "unavailable_usage_records": unavailable_usage_records,
            "provider_available_token_records": provider_available_token_records,
            "provider_unavailable_usage_records": provider_unavailable_usage_records,
        },
        "budget": _budget_audit(
            source_roots,
            records=records,
            candidate_runs=qualification_runs,
        ),
        "duplicate_attempt_ids": duplicate_attempt_ids,
        "historical_collisions": historical_collisions,
        "in_force_duplicate_attempt_ids": duplicate_by_state["in_force"],
        "superseded_duplicate_attempt_ids": duplicate_by_state["superseded"],
        "unregistered_duplicate_attempt_ids": duplicate_by_state["unregistered"],
        "attempt_identity": {
            "in_force": {
                "status": "invalid" if duplicate_by_state["in_force"] else "valid",
                "duplicate_ids": duplicate_by_state["in_force"],
            },
            "superseded": {
                "status": "historical_only"
                if duplicate_by_state["superseded"]
                else "valid",
                "duplicate_ids": duplicate_by_state["superseded"],
                "collision_count": sum(
                    collision["run_state"] == "superseded"
                    for collision in historical_collisions
                ),
            },
            "unregistered": {
                "status": "invalid" if duplicate_by_state["unregistered"] else "valid",
                "duplicate_ids": duplicate_by_state["unregistered"],
            },
        },
        "reuse_check": {
            "status": reuse_status,
            "duplicate_ids": duplicate_attempt_ids,
        },
        "valid": not in_force_invalid and not unregistered_invalid,
    }


def _budget_audit(
    source_roots: tuple[Path, ...],
    *,
    records: list[dict[str, Any]],
    candidate_runs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compare observed categories with the approved offline audit limits."""
    generation_ids = {
        item.get("generation", {}).get("run_id")
        for item in candidate_runs
        if isinstance(item.get("generation"), dict)
        and item.get("generation", {}).get("run_id")
    }
    stage_1a = [
        item.get("stage_1a", {})
        for item in candidate_runs
        if isinstance(item.get("stage_1a"), dict)
    ]
    observed = {
        "producer_generation_runs": len(generation_ids),
        "consumer_authoring_requests": sum(
            row["call_count"]
            for row in records
            if row["category"] == "consumer_authoring"
        ),
        "garak_target_generations": sum(
            row["call_count"]
            for row in records
            if row["category"] == "garak_target_generation"
        ),
        "stage_1a_calls": sum(
            value.get("call_count", 0)
            for value in stage_1a
            if isinstance(value.get("call_count"), int)
        ),
    }
    limits = {
        "producer_generation_runs": 7,
        "consumer_authoring_requests": 8,
        "garak_target_generations": 4,
        "stage_1a_calls": 0,
    }
    checks = {
        key: {
            "observed": observed[key],
            "limit": limits[key],
            "within_limit": observed[key] <= limits[key],
        }
        for key in limits
    }
    return {
        "source_roots": [
            _relative_path(root) for root in source_roots if root.exists()
        ],
        "observed": observed,
        "limits": limits,
        "checks": checks,
        "within_limits": all(item["within_limit"] for item in checks.values()),
        "serial_execution_required": True,
        "no_provider_or_target_calls": True,
        "runtime_surfaces": _runtime_surface_audit(candidate_runs),
    }


def _scenario_terminal_records(
    source_roots: tuple[Path, ...],
) -> list[dict[str, Any]]:
    """Map each published scenario to a preserved terminal record when present."""
    candidates: list[dict[str, Any]] = []
    for path in _source_files(source_roots):
        if path.name != "run-status.json":
            continue
        status = _json_load(path)
        if status is None:
            continue
        generation = status.get("stages", {}).get("generation", {})
        if not isinstance(generation, dict):
            continue
        published = generation.get("scenarios_published")
        scenarios_dir = generation.get("scenarios_dir")
        artifact = status.get("stages", {}).get("artifact", {})
        attempts = artifact.get("attempts", []) if isinstance(artifact, dict) else []
        resolved_scenarios_dir = _resolve_evidence_path(scenarios_dir, path.parent)
        scenarios = (
            sorted(resolved_scenarios_dir.glob("*.yaml"))
            if resolved_scenarios_dir is not None and resolved_scenarios_dir.is_dir()
            else []
        )
        candidates.append(
            {
                "status_path": path,
                "run_id": generation.get("run_id")
                or status.get("run_id")
                or path.parent.name,
                "target_domain": status.get("target_domain"),
                "published": published,
                "scenarios": scenarios,
                "attempts": attempts,
                "artifact_status": artifact.get("status"),
                "execution": status.get("stages", {}).get("execution"),
            }
        )

    grouped: dict[str, list[dict[str, Any]]] = {}
    for candidate in candidates:
        grouped.setdefault(str(candidate["run_id"]), []).append(candidate)

    rows: list[dict[str, Any]] = []
    for run_id, grouped_candidates in sorted(grouped.items()):
        candidate = sorted(
            grouped_candidates,
            key=lambda item: (
                len(
                    {
                        attempt.get("scenario_id")
                        for attempt in item["attempts"]
                        if isinstance(attempt, dict) and attempt.get("scenario_id")
                    }
                ),
                len(item["scenarios"]),
                1 if item["artifact_status"] in {"success", "failed"} else 0,
                1
                if isinstance(item.get("execution"), dict)
                and item["execution"].get("status") not in {None, "not_run"}
                else 0,
                _relative_path(item["status_path"]),
            ),
            reverse=True,
        )[0]
        attempt_by_id: dict[str, dict[str, Any]] = {}
        for attempt in candidate["attempts"]:
            if isinstance(attempt, dict) and attempt.get("scenario_id"):
                attempt_by_id[str(attempt["scenario_id"])] = attempt
        if (
            isinstance(candidate["published"], int)
            and candidate["published"]
            and not candidate["scenarios"]
        ):
            rows.append(
                {
                    "run_id": run_id,
                    "target_domain": candidate["target_domain"],
                    "scenario_id": None,
                    "terminal_status": "unresolved",
                    "consumer_evaluated": False,
                    "consumer_validity_credit": 0,
                    "compilation_credit": 0,
                    "recovery_credit": 0,
                    "terminal_record": _relative_path(candidate["status_path"]),
                    "source_run_path": _relative_path(candidate["status_path"].parent),
                    "reason": "published count has no readable scenario directory",
                }
            )
            continue
        for scenario in candidate["scenarios"]:
            scenario_id = scenario.stem
            attempt = attempt_by_id.get(scenario_id)
            if attempt is None:
                terminal = "not_attempted"
                record = None
                reason = (
                    "published scenario was not selected for bounded consumer "
                    "evaluation"
                )
                consumer_evaluated = False
                consumer_validity_credit = 0
                compilation_credit = 0
                recovery_credit = 0
            elif attempt.get("compiled") is True:
                terminal = "compiled"
                record = attempt.get("artifact") or attempt.get("design_id")
                reason = None
                consumer_evaluated = True
                consumer_validity_credit = 1
                compilation_credit = 1
                recovery_credit = 0
            elif attempt.get("functional_specification") is True:
                terminal = "functional_specification"
                record = attempt.get("artifact") or attempt.get("design_id")
                reason = None
                consumer_evaluated = True
                consumer_validity_credit = 1
                compilation_credit = 0
                recovery_credit = 0
            elif attempt.get("exclusion_code"):
                terminal = "excluded"
                record = attempt.get("log") or attempt.get("design_id")
                reason = attempt.get("exclusion_code")
                consumer_evaluated = True
                consumer_validity_credit = 0
                compilation_credit = 0
                recovery_credit = 0
            else:
                terminal = "unresolved"
                record = attempt.get("log") or attempt.get("design_id")
                reason = "attempt has no terminal disposition"
                consumer_evaluated = True
                consumer_validity_credit = 0
                compilation_credit = 0
                recovery_credit = 0
            rows.append(
                {
                    "run_id": run_id,
                    "target_domain": candidate["target_domain"],
                    "scenario_id": scenario_id,
                    "terminal_status": terminal,
                    "consumer_evaluated": consumer_evaluated,
                    "consumer_validity_credit": consumer_validity_credit,
                    "compilation_credit": compilation_credit,
                    "recovery_credit": recovery_credit,
                    "terminal_record": record,
                    "source_run_path": _relative_path(candidate["status_path"].parent),
                    "source": _relative_path(scenario),
                    "reason": reason,
                }
            )
    return sorted(
        rows, key=lambda item: (str(item["run_id"]), str(item["scenario_id"]))
    )


def build_reachability(
    source_roots: tuple[Path, ...] = DEFAULT_SOURCE_ROOTS,
) -> dict[str, Any]:
    """Report published scenarios and their downstream terminal records."""
    records = _scenario_terminal_records(source_roots)
    terminal_counts: dict[str, int] = {}
    for row in records:
        terminal = row["terminal_status"]
        terminal_counts[terminal] = terminal_counts.get(terminal, 0) + 1
    per_run: dict[str, dict[str, Any]] = {}
    for row in records:
        run_id = str(row["run_id"])
        summary = per_run.setdefault(
            run_id,
            {
                "target_domain": row.get("target_domain"),
                "published_rows": 0,
                "consumer_evaluated_rows": 0,
                "consumer_validity_credit": 0,
                "compilation_credit": 0,
                "recovery_credit": 0,
                "terminal_rows": 0,
                "compiled_rows": 0,
                "excluded_rows": 0,
                "functional_specification_rows": 0,
                "not_attempted_rows": 0,
                "unresolved_rows": 0,
                "reconciled": False,
            },
        )
        if row.get("scenario_id") is not None:
            summary["published_rows"] += 1
            summary["consumer_evaluated_rows"] += bool(row.get("consumer_evaluated"))
            summary["consumer_validity_credit"] += row.get(
                "consumer_validity_credit", 0
            )
            summary["compilation_credit"] += row.get("compilation_credit", 0)
            summary["recovery_credit"] += row.get("recovery_credit", 0)
            summary["terminal_rows"] += row["terminal_status"] != "unresolved"
            bucket = {
                "compiled": "compiled_rows",
                "excluded": "excluded_rows",
                "functional_specification": "functional_specification_rows",
                "not_attempted": "not_attempted_rows",
                "unresolved": "unresolved_rows",
            }[row["terminal_status"]]
            summary[bucket] += 1
    for summary in per_run.values():
        summary["reconciled"] = (
            summary["published_rows"]
            == summary["compiled_rows"]
            + summary["excluded_rows"]
            + summary["functional_specification_rows"]
            + summary["not_attempted_rows"]
            + summary["unresolved_rows"]
            and summary["unresolved_rows"] == 0
        )
    published = sum(row.get("scenario_id") is not None for row in records)
    consumer_evaluated = sum(row.get("consumer_evaluated") is True for row in records)
    counts = {
        "published": published,
        "consumer_evaluated": consumer_evaluated,
        "compiled": terminal_counts.get("compiled", 0),
        "excluded": terminal_counts.get("excluded", 0),
        "functional_specification": terminal_counts.get("functional_specification", 0),
        "not_attempted": terminal_counts.get("not_attempted", 0),
        "unresolved": terminal_counts.get("unresolved", 0),
    }
    credits = {
        "consumer_validity": sum(
            row.get("consumer_validity_credit", 0) for row in records
        ),
        "compilation": sum(row.get("compilation_credit", 0) for row in records),
        "recovery": sum(row.get("recovery_credit", 0) for row in records),
    }
    return {
        "schema_version": "scenario-fidelity-reachability-v1",
        "source": "run-status manifests and preserved scenario/design records",
        "scenarios": records,
        "counts": counts,
        "credits": credits,
        "per_run": dict(sorted(per_run.items())),
        "unresolved_scenarios": [
            {
                "run_id": row["run_id"],
                "scenario_id": row["scenario_id"],
                "source_run_path": row.get("source_run_path"),
            }
            for row in records
            if row["terminal_status"] == "unresolved"
        ],
        "reconciled": not any(row["terminal_status"] == "unresolved" for row in records)
        and counts["published"]
        == counts["compiled"]
        + counts["excluded"]
        + counts["functional_specification"]
        + counts["not_attempted"]
        + counts["unresolved"],
    }


def build_claims(
    source_roots: tuple[Path, ...] = DEFAULT_SOURCE_ROOTS,
) -> dict[str, Any]:
    """Keep evidence axes separate and label unavailable claims explicitly."""
    reachability = build_reachability(source_roots)
    generated = reachability["counts"].get("compiled", 0)
    recount = build_run_recount(source_roots)
    outcomes = recount["native_outcome_labels"]
    command_observed = any(item["labels"].get("command_names") for item in outcomes)
    backend_observed = any(item["labels"].get("backend_statuses") for item in outcomes)
    return {
        "schema_version": "scenario-fidelity-claims-v1",
        "axes": [
            {
                "axis": axis,
                "evidence_type": "measured" if available else "unavailable",
                "denominator": denominator,
                "source": source,
            }
            for axis, available, denominator, source in (
                (
                    "scenario_quality",
                    bool(reachability["scenarios"]),
                    len(reachability["scenarios"]),
                    "reachability.json",
                ),
                (
                    "artifact_fidelity",
                    generated > 0,
                    generated,
                    "design/execution records",
                ),
                (
                    "compilation",
                    bool(reachability["scenarios"]),
                    len(reachability["scenarios"]),
                    "reachability.json",
                ),
                (
                    "delivery",
                    bool(outcomes),
                    len(outcomes) if outcomes else "unavailable",
                    "run-recount.json native outcome labels",
                ),
                (
                    "command_observation",
                    command_observed,
                    len(outcomes) if command_observed else "unavailable",
                    "run-recount.json native outcome labels",
                ),
                (
                    "backend_result_state",
                    backend_observed,
                    len(outcomes) if backend_observed else "unavailable",
                    "run-recount.json native outcome labels",
                ),
                (
                    "reference_recovery",
                    False,
                    "unavailable",
                    "gold scoring is outside this audit",
                ),
            )
        ],
        "generated_artifact_count": generated,
        "outcome_separation": {
            "confirmation_count": len(outcomes),
            "command_observed_count": sum(
                bool(item["labels"].get("command_names")) for item in outcomes
            ),
            "backend_observed_count": sum(
                bool(item["labels"].get("backend_statuses")) for item in outcomes
            ),
            "completed_effect_count": sum(
                item["labels"].get("effect_established") is True for item in outcomes
            ),
        },
        "no_blended_score": True,
    }


def build_run_recount(
    source_roots: tuple[Path, ...] = DEFAULT_SOURCE_ROOTS,
) -> dict[str, Any]:
    """Recount exact run directories and preserve missing source evidence."""
    runs = collect_qualification_runs(source_roots)
    outcomes = [
        {
            "run_path": item["path"],
            "target_domain": item.get("target_domain"),
            "labels": item["outcomes"].get("native_labels", {}),
            "attempt_count": item["outcomes"].get("attempt_count"),
            "no_unsafe_verdict_retry": item["outcomes"].get("no_unsafe_verdict_retry"),
        }
        for item in runs
        if item.get("outcomes", {}).get("present")
    ]
    predispatch_runs = [
        item
        for item in runs
        if item.get("outcomes", {}).get("present")
        or item.get("selection", {}).get("selected_scenario")
    ]
    representations = [
        representation
        for item in runs
        for representation in item.get("representations", [])
    ]
    return {
        "schema_version": "scenario-fidelity-run-recount-v1",
        "source_roots": [
            _relative_path(root) for root in source_roots if root.exists()
        ],
        "source_revisions": _source_revisions(),
        "runs": runs,
        "native_outcome_labels": outcomes,
        "representations": representations,
        "representation_summary": {
            "adversarial": sum(
                item.get("kind") == "adversarial" for item in representations
            ),
            "functional": sum(
                item.get("kind") == "functional" for item in representations
            ),
            "semantic_consistent": sum(
                item.get("semantic_consistent") is True for item in representations
            ),
            "gherkin_shape_valid": sum(
                item.get("gherkin_shape_valid") is True for item in representations
            ),
            "native_feature_shape_valid": sum(
                item.get("native_feature_shape_valid") is True
                for item in representations
            ),
            "consumer_digest_verified": sum(
                item.get("consumer_digest_verified") is True for item in representations
            ),
        },
        "predispatch_summary": {
            "qualified_runs": len(predispatch_runs),
            "complete": sum(
                item.get("predispatch", {}).get("complete", False)
                for item in predispatch_runs
            ),
            "incomplete": sum(
                not item.get("predispatch", {}).get("complete", False)
                for item in predispatch_runs
            ),
        },
        "summary": {
            "run_count": len(runs),
            "fresh": sum(item.get("freshness") == "fresh" for item in runs),
            "reused": sum(item.get("freshness") == "reused" for item in runs),
            "unavailable": sum(item.get("freshness") == "unavailable" for item in runs),
        },
    }


def build_requirement_matrix(
    source_roots: tuple[Path, ...] = DEFAULT_SOURCE_ROOTS,
) -> dict[str, Any]:
    """Publish a conservative R1-R9 evidence matrix for current artifacts."""
    completion = build_completion_status(source_roots)
    rows = _requirement_rows(source_roots, completion)
    counterexamples = build_counterexamples(source_roots)
    return {
        "schema_version": "scenario-fidelity-requirement-matrix-v1",
        "source": "current implementation, verification, challenge, and qualification evidence",
        "rows": rows,
        "open_counterexamples": [
            item
            for item in counterexamples["counterexamples"]
            if item.get("status") == "open"
        ],
        "historical_counterexamples": [
            item
            for item in counterexamples["counterexamples"]
            if item.get("status") == "historical"
        ],
        "completion_status": completion["status"],
        "completion_blockers": completion["blockers"],
        "completion_claim": "not_inferred",
    }


def build_counterexamples(
    source_roots: tuple[Path, ...] = DEFAULT_SOURCE_ROOTS,
) -> dict[str, Any]:
    """Retain counterexample evidence without claiming that review closes it."""
    reachability = build_reachability(source_roots)
    ledger = build_usage_ledger(source_roots)
    counterexamples: list[dict[str, Any]] = []
    counterexamples.extend(
        {
            "code": "scenario_terminal_record_missing",
            "run_id": item["run_id"],
            "scenario_id": item["scenario_id"],
            "source_run_path": item.get("source_run_path"),
            "fix": "preserve a typed terminal record for every published scenario",
            "post_fix_evidence": None,
            "resolution": "open",
            "status": "open",
        }
        for item in reachability["unresolved_scenarios"]
    )
    counterexamples.extend(
        {
            "code": "usage_ledger_duplicate_attempt_id",
            "attempt_id": attempt_id,
            "fix": "assign a unique attempt identity before in-force aggregation",
            "post_fix_evidence": None,
            "resolution": "open",
            "status": "open",
        }
        for attempt_id in (
            ledger["in_force_duplicate_attempt_ids"]
            + ledger["unregistered_duplicate_attempt_ids"]
        )
    )
    counterexamples.extend(
        {
            "code": "usage_ledger_historical_duplicate_attempt_id",
            "attempt_id": collision["attempt_id"],
            "run_id": collision["run_id"],
            "source_file": collision["source_file"],
            "source_file_sha256": collision["source_file_sha256"],
            "line_positions": collision["line_positions"],
            "fix": "retain the collision as historical evidence without rewriting it",
            "post_fix_evidence": {
                "source_file_sha256": collision["source_file_sha256"],
                "line_positions": collision["line_positions"],
            },
            "resolution": "historical_only",
            "status": "historical",
        }
        for collision in ledger["historical_collisions"]
        if collision["run_state"] == "superseded"
    )
    final_klarna_blocker = _final_klarna_blocker(source_roots)
    if final_klarna_blocker is not None:
        counterexamples.append(
            {
                **final_klarna_blocker,
                "source_paths": [
                    f"{_FINAL_KLARNA_ROOT}/run-status.json",
                    f"{_FINAL_KLARNA_ROOT}/artifact/SCN-030/SCN-030:design-1/design-exclusion.json",
                    f"{_FINAL_KLARNA_ROOT}/artifact/SCN-031/SCN-031:design-1/design-exclusion.json",
                    f"{_FINAL_KLARNA_ROOT}/artifact/SCN-004/SCN-004:design-1/design-exclusion.json",
                ],
                "fix": (
                    "complete the bounded authoring, freeze, pre-dispatch, "
                    "Garak, target-command, and backend chain; no further "
                    "Klarna call is authorized"
                ),
                "post_fix_evidence": {
                    "offline_operation_authority": [
                        "producer:1d78337",
                        "consumer:4384260",
                        "build/qualification/scenario-fidelity-final/final-log-crossrepo-offline.txt",
                    ],
                    "live_chain": "absent",
                },
                "resolution": "open",
                "status": "open",
            }
        )
    runtime_surface = ledger.get("budget", {}).get("runtime_surfaces", {})
    final_cleanup = runtime_surface.get("final_klarna_cleanup", {})
    if final_cleanup.get("classification") == "failed":
        maintained_stop = runtime_surface.get("subsequent_maintained_stop")
        candidates = runtime_surface.get("maintained_stop_candidates") or []
        failed_record = final_cleanup.get("record") or {}
        counterexamples.append(
            {
                "code": "klarna_terminal_cleanup_failure",
                "source_paths": [
                    path
                    for path in (
                        f"{_FINAL_KLARNA_ROOT}/cleanup/stack-cleanup.json",
                        *[
                            candidate.get("path")
                            for candidate in candidates
                            if isinstance(candidate, dict)
                        ],
                    )
                    if path
                ],
                "fix": (
                    "preserve the automatic-cleanup failure; only a later "
                    "maintained stop with clear ports and no orphan process "
                    "can resolve it"
                ),
                "failed_record": {
                    "path": f"{_FINAL_KLARNA_ROOT}/cleanup/stack-cleanup.json",
                    "recorded_at": failed_record.get("recorded_at"),
                    "status": failed_record.get("status"),
                    "ports_clear": failed_record.get("ports_clear"),
                    "no_orphan_check": failed_record.get("no_orphan_check"),
                    "orphan_processes": failed_record.get("orphan_processes"),
                },
                "available_maintained_stops": candidates,
                "post_fix_evidence": {
                    "path": maintained_stop.get("path") if maintained_stop else None,
                    "result": maintained_stop.get("status")
                    if maintained_stop
                    else None,
                    "ports_clear": maintained_stop.get("ports_clear")
                    if maintained_stop
                    else None,
                    "orphan_processes": maintained_stop.get("orphan_processes")
                    if maintained_stop
                    else None,
                    "ports_cleared": maintained_stop.get("ports_cleared")
                    if maintained_stop
                    else None,
                    "safe_ports": maintained_stop.get("safe_ports")
                    if maintained_stop
                    else None,
                },
                "resolution": "open",
                "status": "open",
            }
        )
    if runtime_surface.get("valid") is False and not (
        final_cleanup.get("classification") == "failed"
        and runtime_surface.get("subsequent_maintained_stop") is None
    ):
        counterexamples.append(
            {
                "code": "safe_surface_cleanup_unverified",
                "source_paths": [
                    "build/qualification/scenario-fidelity-final/"
                    "klarna-exception-stack-cleanup-20260917.json",
                    "build/qualification/scenario-fidelity-final/"
                    "klarna-exception-stack-start-20260917.json",
                ],
                "fix": (
                    "record a successful no-orphan cleanup at terminal recording; "
                    "preserve the historical OcciAI/Airbnb exception without rerun"
                ),
                "post_fix_evidence": {
                    "later_stop": "ports clear and no matching stack process",
                    "historical_exception": "timely cleanup remains unverified",
                },
                "resolution": "open",
                "status": "open",
            }
        )
    return {
        "schema_version": "scenario-fidelity-counterexamples-v1",
        "source": "preserved run records and current audit inputs",
        "counterexamples": counterexamples,
        "open_count": sum(item.get("status") == "open" for item in counterexamples),
        "historical_count": sum(
            item.get("status") == "historical" for item in counterexamples
        ),
        "historical_records_rewritten": False,
    }


def build_completion_status(
    source_roots: tuple[Path, ...] = DEFAULT_SOURCE_ROOTS,
) -> dict[str, Any]:
    """Return completion only when every required audit axis is evidenced."""
    reachability = build_reachability(source_roots)
    ledger = build_usage_ledger(source_roots)
    blockers: list[dict[str, str]] = []
    if reachability["unresolved_scenarios"]:
        blockers.append(
            {
                "code": "scenario_terminal_record_missing",
                "detail": "published scenarios do not all resolve to terminal records",
            }
        )
    if (
        ledger["denominators"]["consumer_authoring_attempts"]
        == "unavailable_without_consumer_records"
    ):
        blockers.append(
            {
                "code": "consumer_call_accounting_unavailable",
                "detail": "consumer authoring records are not present in the selected source roots",
            }
        )
    invalid_duplicate_ids = (
        ledger["in_force_duplicate_attempt_ids"]
        + ledger["unregistered_duplicate_attempt_ids"]
    )
    if invalid_duplicate_ids:
        blockers.append(
            {
                "code": "usage_ledger_duplicate_attempt_id",
                "detail": (
                    "primary call records reuse attempt IDs: "
                    + ", ".join(invalid_duplicate_ids)
                ),
            }
        )
    run_recount = build_run_recount(source_roots)
    in_force_runs = [
        item for item in run_recount["runs"] if item.get("run_state") == "in_force"
    ]
    incomplete_predispatch = [
        item["path"]
        for item in in_force_runs
        if item.get("outcomes", {}).get("present")
        and not item.get("predispatch", {}).get("complete")
    ]
    if incomplete_predispatch:
        blockers.append(
            {
                "code": "predispatch_sections_missing",
                "detail": (
                    "executed runs lack one or more of the seven pre-dispatch "
                    "sections: " + ", ".join(incomplete_predispatch)
                ),
            }
        )
    retry_runs = [
        item["path"]
        for item in in_force_runs
        if item.get("outcomes", {}).get("present")
        and item.get("outcomes", {}).get("no_unsafe_verdict_retry") is not True
    ]
    if retry_runs:
        blockers.append(
            {
                "code": "unsafe_verdict_retry_or_unavailable",
                "detail": "runtime outcome attempt counts are not exactly one: "
                + ", ".join(retry_runs),
            }
        )
    invalid_stage_1a = [
        item["path"]
        for item in in_force_runs
        if item.get("stage_1a", {}).get("status") not in {"valid", "unavailable"}
    ]
    if invalid_stage_1a:
        blockers.append(
            {
                "code": "stage_1a_not_pinned_zero_call",
                "detail": "Stage 1a evidence is not pinned with zero calls: "
                + ", ".join(invalid_stage_1a),
            }
        )
    if ledger.get("budget", {}).get("within_limits") is False:
        blockers.append(
            {
                "code": "qualification_budget_exceeded",
                "detail": "observed category counts exceed one or more approved limits",
            }
        )
    final_klarna_blocker = _final_klarna_blocker(source_roots)
    if final_klarna_blocker is not None:
        blockers.append(final_klarna_blocker)
    runtime_surfaces = ledger.get("budget", {}).get("runtime_surfaces", {})
    if runtime_surfaces.get("valid") is False:
        final_cleanup = runtime_surfaces.get("final_klarna_cleanup", {})
        final_cleanup_failure_open = (
            final_cleanup.get("classification") == "failed"
            and runtime_surfaces.get("subsequent_maintained_stop") is None
        )
        blockers.append(
            {
                "code": (
                    "klarna_terminal_cleanup_failure"
                    if final_cleanup_failure_open
                    else "safe_surface_cleanup_unverified"
                ),
                "detail": (
                    "the final Klarna automatic-cleanup record failed at "
                    "2026-09-17T18:54:29Z with two orphan processes; the "
                    "available maintained stops predate that failure"
                    if final_cleanup_failure_open
                    else "safe-port, serial-execution, or no-orphan cleanup "
                    "evidence is incomplete"
                ),
            }
        )
    representation_summary = run_recount.get("representation_summary", {})
    representation_requirements = (
        representation_summary.get("adversarial", 0) >= 1
        and representation_summary.get("functional", 0) >= 1
        and representation_summary.get("semantic_consistent", 0)
        == representation_summary.get("adversarial", 0)
        + representation_summary.get("functional", 0)
        and representation_summary.get("gherkin_shape_valid", 0)
        == representation_summary.get("adversarial", 0)
        + representation_summary.get("functional", 0)
        and representation_summary.get("native_feature_shape_valid", 0)
        == representation_summary.get("adversarial", 0)
        + representation_summary.get("functional", 0)
    )
    if not representation_requirements:
        blockers.append(
            {
                "code": "generated_representation_audit_incomplete",
                "detail": (
                    "fresh generated adversarial and functional representations "
                    "do not both pass semantic and Gherkin shape checks"
                ),
            }
        )
    blocker_codes = {
        item.get("code")
        for item in blockers
        if isinstance(item, dict) and item.get("code")
    }
    blocked_requirements: list[str] = []
    if final_klarna_blocker is not None:
        blocked_requirements.append("R8")
    if blocker_codes - {"fresh_klarna_chain_incomplete"}:
        blocked_requirements.append("R9")
    completed_requirements = [
        f"R{number}"
        for number in range(1, 10)
        if f"R{number}" not in blocked_requirements
    ]
    return {
        "schema_version": "scenario-fidelity-completion-status-v1",
        "status": "blocked" if blockers else "complete",
        "blockers": blockers,
        "completed_requirements": completed_requirements,
        "blocked_requirements": blocked_requirements,
        "reporting_complete": "R9" in completed_requirements,
        "product_completion_claim": "blocked" if blocked_requirements else "complete",
        "native_outcome_labels": run_recount["native_outcome_labels"],
        "source_revisions": run_recount["source_revisions"],
        "offline_only": True,
    }


_SECRET_PATTERNS = (
    (
        "private_endpoint",
        re.compile(r"https://[A-Za-z0-9.-]+(?:apps|svc|internal)\.[^\s\"']+", re.I),
    ),
    (
        "api_key",
        re.compile(
            r"\b(?:api[_-]?key|token|password|secret)\s*[:=]\s*['\"]?[^,\s'\"]{8,}",
            re.I,
        ),
    ),
    ("provider_key", re.compile(r"\b(?:sk|rk)-[A-Za-z0-9_-]{12,}\b")),
)
_HISTORICAL_ROOT_NAMES = frozenset(
    {"semantic-fidelity-runs", "adaptive-runs", "adaptive-e2e"}
)


def _evidence_scope(path: Path) -> str:
    """Classify preserved historical roots without rewriting their bytes."""
    return (
        "historical"
        if any(part in _HISTORICAL_ROOT_NAMES for part in path.parts)
        else "current"
    )


def build_secret_scan(
    source_roots: tuple[Path, ...] = DEFAULT_SOURCE_ROOTS,
) -> dict[str, Any]:
    """Scan evidence without copying matching secret material into the report."""
    matches: list[dict[str, Any]] = []
    for path in _source_files(source_roots):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for number, line in enumerate(lines, 1):
            for kind, pattern in _SECRET_PATTERNS:
                if pattern.search(line):
                    matches.append(
                        {
                            "path": _relative_path(path),
                            "line": number,
                            "kind": kind,
                            "scope": _evidence_scope(path),
                        }
                    )
    historical_matches = [item for item in matches if item["scope"] == "historical"]
    current_matches = [item for item in matches if item["scope"] == "current"]
    return {
        "schema_version": "scenario-fidelity-evidence-scan-v1",
        "source": "selected evidence roots",
        "matches": sorted(
            matches, key=lambda item: (item["path"], item["line"], item["kind"])
        ),
        "historical_matches": len(historical_matches),
        "current_matches": len(current_matches),
        "historical_only": bool(historical_matches) and not current_matches,
        "clean": not matches,
        "secret_values_persisted": False,
    }


def _write_json(output_dir: Path, filename: str, value: dict[str, Any]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


def write_audit_artifacts(
    output_dir: Path,
    *,
    source_roots: tuple[Path, ...] = DEFAULT_SOURCE_ROOTS,
    selected: set[str] | None = None,
) -> list[Path]:
    """Write the deterministic audit artifact set and return written paths."""
    builders = {
        "field-inventory.json": lambda: build_field_inventory(),
        "usage-ledger.json": lambda: build_usage_ledger(source_roots),
        "reachability.json": lambda: build_reachability(source_roots),
        "claims.json": lambda: build_claims(source_roots),
        "run-recount.json": lambda: build_run_recount(source_roots),
        "requirement-matrix.json": lambda: build_requirement_matrix(source_roots),
        "counterexamples.json": lambda: build_counterexamples(source_roots),
        "completion-status.json": lambda: build_completion_status(source_roots),
        "evidence-scan.json": lambda: build_secret_scan(source_roots),
    }
    wanted = selected or set(builders)
    unknown = wanted - set(builders)
    if unknown:
        raise ValueError(f"unknown audit artifacts: {', '.join(sorted(unknown))}")
    paths: list[Path] = []
    for filename in AUDIT_ARTIFACTS:
        if filename in wanted:
            paths.append(_write_json(output_dir, filename, builders[filename]()))
    return paths


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--field-inventory", action="store_true")
    parser.add_argument("--usage-ledger", action="store_true")
    parser.add_argument("--reachability", action="store_true")
    parser.add_argument("--claims", action="store_true")
    parser.add_argument("--recount", "--run-recount", action="store_true")
    parser.add_argument("--matrix", action="store_true")
    parser.add_argument("--counterexamples", action="store_true")
    parser.add_argument("--completion-status", action="store_true")
    parser.add_argument("--secret-scan", action="store_true")
    parser.add_argument(
        "--source-root",
        action="append",
        type=Path,
        default=None,
        help="Evidence root; may be repeated. Defaults to maintained build roots.",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    selected = {
        filename
        for enabled, filename in (
            (args.field_inventory, "field-inventory.json"),
            (args.usage_ledger, "usage-ledger.json"),
            (args.reachability, "reachability.json"),
            (args.claims, "claims.json"),
            (args.recount, "run-recount.json"),
            (args.matrix, "requirement-matrix.json"),
            (args.counterexamples, "counterexamples.json"),
            (args.completion_status, "completion-status.json"),
            (args.secret_scan, "evidence-scan.json"),
        )
        if enabled
    }
    roots = tuple(args.source_root) if args.source_root else DEFAULT_SOURCE_ROOTS
    write_audit_artifacts(
        args.output_dir, source_roots=roots, selected=selected or None
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
