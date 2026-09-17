"""Audit prompt/schema field ownership for offline R6 evidence.

The full qualification audit can add other artifact checks later.  The
``--field-inventory`` mode is deliberately deterministic and has no provider,
target, or filesystem inputs beyond its caller-selected output directory.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--field-inventory", action="store_true")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.field_inventory:
        parser.error("this offline audit currently requires --field-inventory")
    write_field_inventory(args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
