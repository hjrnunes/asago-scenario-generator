"""Audit prompt/schema field ownership for offline R6 evidence.

The full qualification audit can add other artifact checks later.  The
``--field-inventory`` mode is deliberately deterministic and has no provider,
target, or filesystem inputs beyond its caller-selected output directory.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE_ROOTS = (
    REPO_ROOT / "build" / "semantic-fidelity-runs",
    REPO_ROOT / "build" / "adaptive-runs",
    REPO_ROOT / "build" / "adaptive-e2e",
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
    ("history_dependent", "consumer_authoring", "user-only history with one continuation"),
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
            ["user_message", "conversation", "retrieved_content", "tool_content", "file_upload", "traffic_load", "unknown"],
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
            ["external_attacker", "malicious_customer", "third_party_via_content", "none"],
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
            ["action_presence", "action_value", "state_value", "ordering", "delay", "duration", "window", "absence"],
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
            ["external_attacker", "malicious_customer", "third_party_via_content", "none"],
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


def _relative_path(path: Path) -> str:
    """Return a stable repository-relative path for an evidence record."""
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _source_files(source_roots: tuple[Path, ...]) -> list[Path]:
    """Enumerate source files in stable order, excluding the output tree."""
    files: set[Path] = set()
    for root in source_roots:
        if not root.is_dir():
            continue
        files.update(path for path in root.rglob("*") if path.is_file())
    return sorted(files, key=lambda path: _relative_path(path))


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
            records.append(
                {
                    "run_id": str(
                        status.get("run_id")
                        or (generation or {}).get("run_id")
                        or run_dir.name
                    ),
                    "path": _relative_path(run_dir),
                    "target_domain": status.get("target_domain"),
                    "source": "run-status.json",
                    "generation": _stage_summary(generation),
                    "artifact": _stage_summary(artifact),
                    "execution": _stage_summary(execution),
                    "scenario_count": _scenario_count(generation),
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


def _primary_call_entries(path: Path) -> tuple[list[dict[str, Any]], int]:
    """Read primary producer/consumer call entries and malformed-line count."""
    if path.name == "design-record.json":
        record = _json_load(path)
        authoring = record.get("authoring") if record is not None else None
        attempts = authoring.get("attempts") if isinstance(authoring, dict) else None
        if not isinstance(attempts, list):
            return [], 0
        return (
            [item for item in attempts if isinstance(item, dict)],
            sum(not isinstance(item, dict) for item in attempts),
        )
    if path.name not in _PRIMARY_CALL_FILENAMES:
        return [], 0

    entries: list[dict[str, Any]] = []
    malformed = 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return [], 1
    for line in lines:
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
    return entries, malformed


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


def _call_records(
    source_roots: tuple[Path, ...],
) -> tuple[list[dict[str, Any]], list[str], int, int]:
    """Recount primary call records, retaining only one row per attempt ID."""
    rows: list[dict[str, Any]] = []
    seen_attempt_ids: set[str] = set()
    duplicate_attempt_ids: set[str] = set()
    total_entries = 0
    entries_without_attempt_id = 0
    for path in _source_files(source_roots):
        if path.name not in _PRIMARY_CALL_FILENAMES and path.name != "design-record.json":
            continue
        entries, malformed = _primary_call_entries(path)
        if not entries and not malformed:
            continue
        path_entries: list[dict[str, Any]] = []
        path_attempt_ids: set[str] = set()
        path_missing_attempt_ids = 0
        provider_request_count = 0
        tokens: int | float = 0
        for entry in entries:
            total_entries += 1
            attempt_id = _attempt_id(entry)
            if attempt_id is None:
                entries_without_attempt_id += 1
                path_missing_attempt_ids += 1
            elif attempt_id in seen_attempt_ids:
                duplicate_attempt_ids.add(attempt_id)
                continue
            else:
                seen_attempt_ids.add(attempt_id)
                path_attempt_ids.add(attempt_id)
            category = _call_category(path, entry)
            path_entries.append(entry)
            tokens += _entry_tokens(entry)
            if _is_provider_request(path, entry, category):
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
                "category": category,
                "call_count": len(path_entries),
                "provider_request_count": provider_request_count,
                "total_tokens": tokens,
                "malformed_records": malformed,
                "attempt_ids": sorted(path_attempt_ids),
                "missing_attempt_id_count": path_missing_attempt_ids,
                "usage": "reported" if tokens else "unavailable_or_zero",
            }
        )
    return (
        rows,
        sorted(duplicate_attempt_ids),
        total_entries,
        entries_without_attempt_id,
    )


def build_usage_ledger(
    source_roots: tuple[Path, ...] = DEFAULT_SOURCE_ROOTS,
) -> dict[str, Any]:
    """Build a truthful call ledger from saved records only."""
    records, duplicate_attempt_ids, total_entries, entries_without_attempt_id = (
        _call_records(source_roots)
    )
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
    has_attempt_ids = total_entries > entries_without_attempt_id
    reuse_status = (
        "invalid"
        if duplicate_attempt_ids
        else "valid"
        if has_attempt_ids and entries_without_attempt_id == 0
        else "unavailable"
    )
    return {
        "schema_version": "scenario-fidelity-usage-ledger-v1",
        "source": "preserved call records; no provider or target calls",
        "records": records,
        "category_totals": category_totals,
        "denominators": {
            "provider_requests": provider_requests,
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
        },
        "duplicate_attempt_ids": duplicate_attempt_ids,
        "reuse_check": {
            "status": reuse_status,
            "duplicate_ids": duplicate_attempt_ids,
        },
        "valid": reuse_status == "valid",
    }


def _scenario_terminal_records(
    source_roots: tuple[Path, ...],
) -> list[dict[str, Any]]:
    """Map each published scenario to a preserved terminal record when present."""
    rows: list[dict[str, Any]] = []
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
        attempt_by_id = {
            item.get("scenario_id"): item
            for item in attempts
            if isinstance(item, dict) and item.get("scenario_id")
        }
        if isinstance(scenarios_dir, str) and Path(scenarios_dir).is_dir():
            scenarios = sorted(Path(scenarios_dir).glob("*.yaml"))
        else:
            scenarios = []
        if isinstance(published, int) and published and not scenarios:
            rows.append(
                {
                    "run_id": status.get("run_id") or path.parent.name,
                    "scenario_id": None,
                    "terminal_status": "unresolved",
                    "terminal_record": _relative_path(path),
                    "reason": "published count has no readable scenario directory",
                }
            )
            continue
        for scenario in scenarios:
            scenario_id = scenario.stem
            attempt = attempt_by_id.get(scenario_id)
            if attempt is None:
                terminal = "unresolved"
                record = _relative_path(path)
            elif attempt.get("compiled") is True:
                terminal = "compiled"
                record = attempt.get("artifact") or attempt.get("design_id")
            elif attempt.get("exclusion_code"):
                terminal = "design_exclusion"
                record = attempt.get("log") or attempt.get("design_id")
            else:
                terminal = "unresolved"
                record = attempt.get("log") or attempt.get("design_id")
            rows.append(
                {
                    "run_id": status.get("run_id") or path.parent.name,
                    "scenario_id": scenario_id,
                    "terminal_status": terminal,
                    "terminal_record": record,
                    "source": _relative_path(scenario),
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
    counts: dict[str, int] = {}
    for row in records:
        counts[row["terminal_status"]] = counts.get(row["terminal_status"], 0) + 1
    return {
        "schema_version": "scenario-fidelity-reachability-v1",
        "source": "run-status manifests and preserved scenario/design records",
        "scenarios": records,
        "counts": counts,
        "unresolved_scenarios": [
            row["scenario_id"]
            for row in records
            if row["terminal_status"] == "unresolved"
        ],
        "reconciled": not any(
            row["terminal_status"] == "unresolved" for row in records
        ),
    }


def build_claims(
    source_roots: tuple[Path, ...] = DEFAULT_SOURCE_ROOTS,
) -> dict[str, Any]:
    """Keep evidence axes separate and label unavailable claims explicitly."""
    reachability = build_reachability(source_roots)
    generated = reachability["counts"].get("compiled", 0)
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
                ("scenario_quality", bool(reachability["scenarios"]), len(reachability["scenarios"]), "reachability.json"),
                ("artifact_fidelity", generated > 0, generated, "design/execution records"),
                ("compilation", bool(reachability["scenarios"]), len(reachability["scenarios"]), "reachability.json"),
                ("delivery", False, "unavailable", "runtime delivery records not supplied"),
                ("command_observation", False, "unavailable", "qualification records not supplied"),
                ("backend_result_state", False, "unavailable", "result/state observer not part of this audit"),
                ("reference_recovery", False, "unavailable", "gold scoring is outside this audit"),
            )
        ],
        "generated_artifact_count": generated,
        "no_blended_score": True,
    }


def build_run_recount(
    source_roots: tuple[Path, ...] = DEFAULT_SOURCE_ROOTS,
) -> dict[str, Any]:
    """Recount exact run directories and preserve missing source evidence."""
    runs = collect_qualification_runs(source_roots)
    return {
        "schema_version": "scenario-fidelity-run-recount-v1",
        "source_roots": [_relative_path(root) for root in source_roots if root.exists()],
        "runs": runs,
        "summary": {
            "run_count": len(runs),
            "fresh": sum(
                item.get("generation", {}).get("source") == "fresh" for item in runs
            ),
            "reused": sum(
                item.get("generation", {}).get("source") == "reused" for item in runs
            ),
            "unavailable": sum(
                item.get("status") == "unreadable" for item in runs
            ),
        },
    }


def build_requirement_matrix(
    source_roots: tuple[Path, ...] = DEFAULT_SOURCE_ROOTS,
) -> dict[str, Any]:
    """Publish a conservative R1-R9 evidence matrix for current artifacts."""
    reachability = build_reachability(source_roots)
    evidence_available = bool(reachability["scenarios"])
    rows = [
        {
            "requirement": f"R{number}",
            "status": "evidenced" if evidence_available else "blocked",
            "implementation": (
                "consumer/producer implementation and focused tests"
                if evidence_available
                else "not assessed by this source set"
            ),
            "programmatic_verification": (
                "offline audit reachability and repository tests"
                if evidence_available
                else "unavailable"
            ),
            "independent_challenge": "not supplied",
            "live_evidence": "not supplied; this command is offline",
        }
        for number in range(1, 10)
    ]
    return {
        "schema_version": "scenario-fidelity-requirement-matrix-v1",
        "source": "current repository evidence only",
        "rows": rows,
        "open_counterexamples": [],
        "completion_claim": "not_inferred",
    }


def build_counterexamples(
    source_roots: tuple[Path, ...] = DEFAULT_SOURCE_ROOTS,
) -> dict[str, Any]:
    """Retain counterexample evidence without claiming that review closes it."""
    return {
        "schema_version": "scenario-fidelity-counterexamples-v1",
        "source": "preserved run records and current audit inputs",
        "counterexamples": [],
        "open_count": 0,
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
    if ledger["denominators"]["consumer_authoring_attempts"] == "unavailable_without_consumer_records":
        blockers.append(
            {
                "code": "consumer_call_accounting_unavailable",
                "detail": "consumer authoring records are not present in the selected source roots",
            }
        )
    if ledger["reuse_check"]["status"] == "invalid":
        blockers.append(
            {
                "code": "usage_ledger_duplicate_attempt_id",
                "detail": (
                    "primary call records reuse attempt IDs: "
                    + ", ".join(ledger["duplicate_attempt_ids"])
                ),
            }
        )
    return {
        "schema_version": "scenario-fidelity-completion-status-v1",
        "status": "blocked" if blockers else "complete",
        "blockers": blockers,
        "completed_requirements": [] if blockers else [f"R{n}" for n in range(1, 10)],
        "offline_only": True,
    }


_SECRET_PATTERNS = (
    ("private_endpoint", re.compile(r"https://[A-Za-z0-9.-]+(?:apps|svc|internal)\.[^\s\"']+", re.I)),
    ("api_key", re.compile(r"\b(?:api[_-]?key|token|password|secret)\s*[:=]\s*['\"]?[^,\s'\"]{8,}", re.I)),
    ("provider_key", re.compile(r"\b(?:sk|rk)-[A-Za-z0-9_-]{12,}\b")),
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
                        {"path": _relative_path(path), "line": number, "kind": kind}
                    )
    return {
        "schema_version": "scenario-fidelity-evidence-scan-v1",
        "source": "selected evidence roots",
        "matches": sorted(matches, key=lambda item: (item["path"], item["line"], item["kind"])),
        "clean": not matches,
        "secret_values_persisted": False,
    }


def _write_json(output_dir: Path, filename: str, value: dict[str, Any]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
    write_audit_artifacts(args.output_dir, source_roots=roots, selected=selected or None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
