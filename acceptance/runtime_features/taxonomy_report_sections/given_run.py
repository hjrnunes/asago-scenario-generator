"""Given step handlers for coverage, manifest, raw-file, and pipeline-call fixtures."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World


def _h_coverage_complete(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the coverage data confirms a complete inventory with no uncovered entry points, zones, threats, or attack patterns."""
    world.trpt_coverage_data = {
        "coverage_gaps": {
            "uncovered_entry_points": [],
            "uncovered_zones": [],
            "uncovered_threats": [],
            "uncovered_attack_patterns": [],
        },
        "coverage_universe": {"completeness": "confirmed_complete"},
    }
    return True, ""


def _h_coverage_evidence(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the coverage universe records the evidence reference "E"."""
    match = re.search(
        r'the coverage universe records the evidence reference "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse coverage-evidence step: {text}"
    world.trpt_coverage_data.setdefault("coverage_universe", {}).setdefault(
        "evidence_refs", []
    ).append(match.group(1))
    return True, ""


def _h_coverage_counts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the coverage data reports N uncovered entry points, M uncovered zone, and K uncovered threats."""
    match = re.search(
        r"the coverage data reports (\d+) uncovered entry points?, (\d+) "
        r"uncovered zones?, and (\d+) uncovered threats?$",
        text,
    )
    if not match:
        return False, f"Could not parse coverage-counts step: {text}"
    ep_count, zone_count, threat_count = (int(g) for g in match.groups())
    # Uncovered entry points beyond the first are synthesized as "ze-gap-N".
    eps = [{"name": "ze-query", "entry_point_id": "ze-query"}]
    eps += [
        {"name": f"ze-gap-{i}", "entry_point_id": f"ze-gap-{i}"}
        for i in range(max(ep_count - 1, 0))
    ]
    world.trpt_coverage_data = {
        "coverage_gaps": {
            "uncovered_entry_points": eps,
            "uncovered_zones": [f"zone-{i}" for i in range(zone_count)],
            "uncovered_threats": [f"T{i}" for i in range(1, threat_count + 1)],
            "uncovered_attack_patterns": [],
            "gap_attributions": {"entry_points": {}},
        },
        "coverage_universe": {"completeness": "not_applicable"},
    }
    return True, ""


def _h_coverage_no_patterns(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage data records no uncovered attack patterns."""
    world.trpt_coverage_data.setdefault("coverage_gaps", {})[
        "uncovered_attack_patterns"
    ] = []
    return True, ""


def _h_coverage_attribution(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage data attributes the uncovered entry point "E" to "R"."""
    match = re.search(
        r'the coverage data attributes the uncovered entry point "([^"]+)" to "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse coverage-attribution step: {text}"
    ep_id, reason = match.groups()
    gaps = world.trpt_coverage_data.setdefault("coverage_gaps", {})
    gaps.setdefault("gap_attributions", {}).setdefault("entry_points", {})[ep_id] = (
        reason
    )
    return True, ""


def _h_coverage_universe(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the coverage data records a coverage universe with N feasible targets and M excluded targets."""
    match = re.search(
        r"the coverage data records a coverage universe with (\d+) feasible "
        r"targets? and (\d+) excluded targets?",
        text,
    )
    if not match:
        return False, f"Could not parse coverage-universe step: {text}"
    feasible, excluded = (int(g) for g in match.groups())
    world.trpt_coverage_data["coverage_universe"] = {
        "completeness": "not_applicable",
        "feasible_targets": [
            {
                "name": f"ze-f{i}",
                "entry_point_id": f"ze-f{i}",
                "direction": "input",
                "controllability": "direct",
            }
            for i in range(feasible)
        ],
        "excluded_targets": [
            {
                "name": f"ze-x{i}",
                "entry_point_id": f"ze-x{i}",
                "reason": "out of scope",
            }
            for i in range(excluded)
        ],
    }
    return True, ""


def _h_manifest_funnel(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the run manifest records seeds generated N, candidates expanded M with S submitted and A accepted, G scenarios generated, and F failed."""
    match = re.search(
        r"the run manifest records seeds generated (\d+), candidates expanded "
        r"(\d+) with (\d+) submitted and (\d+) accepted, (\d+) scenarios "
        r"generated, and (\d+) failed",
        text,
    )
    if not match:
        return False, f"Could not parse manifest-funnel step: {text}"
    seeds, expanded, submitted, accepted, generated, failed = (
        int(g) for g in match.groups()
    )
    world.trpt_manifest_data.update(
        {
            "seeds_generated": seeds,
            "funnel": {
                "expanded_instances": expanded,
                "filter_submitted": submitted,
                "filter_accepted": accepted,
            },
            "scenarios_generated": generated,
            "scenarios_failed": failed,
        }
    )
    return True, ""


def _h_manifest_config(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the run manifest records model "M" with temperature T and timestamps "S" to "E"."""
    match = re.search(
        r'the run manifest records model "([^"]+)" with temperature ([0-9.]+) '
        r'and timestamps "([^"]+)" to "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse manifest-config step: {text}"
    model, temperature, start, end = match.groups()
    world.trpt_manifest_data.update(
        {
            "config": {"model": model, "temperature": float(temperature)},
            "timestamp_start": start,
            "timestamp_end": end,
        }
    )
    return True, ""


def _h_manifest_absent_values(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the run manifest records zero candidates expanded and no timestamps and no model."""
    world.trpt_manifest_data = {
        "seeds_generated": 0,
        "funnel": {},
        "scenarios_generated": 0,
        "scenarios_failed": 0,
        "config": {},
    }
    return True, ""


def _h_raw_files(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the run fixture carries raw files including a YAML file and a Gherkin file."""
    world.trpt_raw_files = {
        "capability-profile.yaml": (
            "# profile snippet\n"
            'completeness: "confirmed"\n'
            "count: 3\n"
            "enabled: true\n"
            "note: null\n"
        ),
        "scenario.feature": (
            "# smoke suite\n@smoke\nFeature: Demo\n"
            "  Background: setup\n"
            "  Given a precondition\n"
            "  When the event fires\n"
            "  And another step\n"
            "  But a guard holds\n"
        ),
    }
    return True, ""


def _h_pipeline_call_log(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the pipeline call log contains the accepted "A" call with P prompt tokens and the rejected "R" call with Q prompt tokens."""
    match = re.search(
        r'the pipeline call log contains the accepted "([^"]+)" call with (\d+) '
        r'prompt tokens and the rejected "([^"]+)" call with (\d+) prompt tokens',
        text,
    )
    if not match:
        return False, f"Could not parse pipeline-call-log step: {text}"
    accepted_call, accepted_prompt, rejected_call, rejected_prompt = match.groups()
    world.trpt_pipeline_call_logs = [
        {
            "call": accepted_call,
            "prompt_tokens": int(accepted_prompt),
            "completion_tokens": 40,
            "duration_ms": 25,
            "semantic_evidence": {
                "stage": accepted_call,
                "accepted_draft_digest": "accepted-draft-digest",
                "attempts": [{"result": "accepted"}],
                "warnings": ["presentation_fallback: raw JSON payload"],
            },
        },
        {
            "call": rejected_call,
            "prompt_tokens": int(rejected_prompt),
            "completion_tokens": 20,
            "duration_ms": 15,
            "semantic_evidence": {
                "stage": rejected_call,
                "attempts": [{"result": "invalid"}],
            },
        },
    ]
    return True, ""


def _h_pipeline_call_log_partial(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: ... and a "C" call with no duration telemetry (partial usage)."""
    match = re.search(
        r'the pipeline call log contains the accepted "([^"]+)" call with (\d+) '
        r'prompt tokens, the rejected "([^"]+)" call with (\d+) prompt tokens, '
        r'and a "([^"]+)" call with no duration telemetry',
        text,
    )
    if not match:
        return False, f"Could not parse partial-telemetry call-log step: {text}"
    accepted_call, accepted_prompt, rejected_call, rejected_prompt, partial_call = (
        match.groups()
    )
    # The partial entry keeps prompt/completion counts at the zero default and
    # explicitly reports unavailable duration telemetry (None).
    world.trpt_pipeline_call_logs = [
        {
            "call": accepted_call,
            "prompt_tokens": int(accepted_prompt),
            "completion_tokens": 40,
            "duration_ms": 25,
            "semantic_evidence": {
                "stage": accepted_call,
                "accepted_draft_digest": "accepted-draft-digest",
                "attempts": [{"result": "accepted"}],
            },
        },
        {
            "call": rejected_call,
            "prompt_tokens": int(rejected_prompt),
            "completion_tokens": 20,
            "duration_ms": 15,
            "semantic_evidence": {
                "stage": rejected_call,
                "attempts": [{"result": "invalid"}],
            },
        },
        {
            "call": partial_call,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "duration_ms": None,
        },
    ]
    return True, ""


def _h_coverage_not_confirmed(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the coverage data records no uncovered entry points, zones, threats, or attack patterns with an inventory completeness not confirmed."""
    world.trpt_coverage_data = {
        "coverage_gaps": {
            "uncovered_entry_points": [],
            "uncovered_zones": [],
            "uncovered_threats": [],
            "uncovered_attack_patterns": [],
        },
        "coverage_universe": {"completeness": "not_applicable"},
    }
    return True, ""


def _h_coverage_summary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the coverage data records a summary with <category> entries."""
    match = re.search(r"the coverage data records a summary with (.*)$", text)
    if not match:
        return False, f"Could not parse coverage-summary step: {text}"
    spec = match.group(1)
    summary: dict[str, Any] = {}

    covered = re.search(r'the covered feasible target "([^"]+)"', spec)
    if covered:
        summary["covered_feasible"] = [covered.group(1)]

    selection = re.search(
        r'a selection limitation for entry point "([^"]+)" with reason '
        r'"([^"]+)", detail "([^"]+)", and candidate "([^"]+)"',
        spec,
    )
    if selection:
        ep_id, reason, detail, candidate = selection.groups()
        summary["selection_limitations"] = [
            {
                "entry_point_id": ep_id,
                "reason": reason,
                "detail": detail,
                "candidate_ids": [candidate],
            }
        ]

    exclusion = re.search(
        r'a policy exclusion for entry point "([^"]+)" with reason "([^"]+)"',
        spec,
    )
    if exclusion:
        ep_id, reason = exclusion.groups()
        summary["policy_exclusions"] = [{"entry_point_id": ep_id, "reason": reason}]

    for key, label in (
        ("structural_gaps", "a structural gap"),
        ("runtime_generation_gaps", "a runtime generation gap"),
        ("quarantine_admission_failures", "a quarantine admission failure"),
        ("projection_limitations", "a projection limitation"),
    ):
        item = re.search(
            rf'{label} for entry point "([^"]+)" with reason "([^"]+)"', spec
        )
        if item:
            summary[key] = [{"entry_point_id": item.group(1), "reason": item.group(2)}]

    world.trpt_coverage_data.setdefault("coverage_summary", {}).update(summary)
    return True, ""


def _h_coverage_plan(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the coverage data records a coverage plan targeting entry point "E" with primary candidate "C", state "S", and ordered choices "A,B"."""
    match = re.search(
        r"the coverage data records a coverage plan targeting entry point "
        r'"([^"]+)" with primary candidate "([^"]+)", state "([^"]+)", and '
        r'ordered choices "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse coverage-plan step: {text}"
    ep_id, primary, state, choices_csv = match.groups()
    world.trpt_coverage_data["coverage_plan"] = {
        "schema_version": 1,
        "targets": [
            {
                "entry_point_id": ep_id,
                "entry_point_name": ep_id,
                "primary_candidate_id": primary,
                "primary_state": state,
                "ordered_choices": [
                    {"candidate_id": candidate.strip()}
                    for candidate in choices_csv.split(",")
                    if candidate.strip()
                ],
            }
        ],
    }
    return True, ""


def register(api: Any) -> None:
    # --- Coverage / manifest / raw / pipeline Given steps ---
    api.register(
        "the coverage data confirms a complete inventory with no uncovered entry points, zones, threats, or attack patterns",
        _h_coverage_complete,
        source_order=7050,
    )
    api.register(
        'the coverage universe records the evidence reference "([^"]+)"',
        _h_coverage_evidence,
        source_order=7051,
    )
    api.register(
        "the coverage data reports \\d+ uncovered entry points?, \\d+ uncovered zones?, and \\d+ uncovered threats?$",
        _h_coverage_counts,
        source_order=7052,
    )
    api.register(
        "the coverage data records no uncovered attack patterns",
        _h_coverage_no_patterns,
        source_order=7053,
    )
    api.register(
        'the coverage data attributes the uncovered entry point "([^"]+)" to "([^"]+)"',
        _h_coverage_attribution,
        source_order=7054,
    )
    api.register(
        "the coverage data records a coverage universe with \\d+ feasible targets? and \\d+ excluded targets?",
        _h_coverage_universe,
        source_order=7055,
    )
    api.register(
        "the run manifest records seeds generated \\d+, candidates expanded \\d+ with \\d+ submitted and \\d+ accepted, \\d+ scenarios generated, and \\d+ failed",
        _h_manifest_funnel,
        source_order=7056,
    )
    api.register(
        'the run manifest records model "([^"]+)" with temperature ([0-9.]+) and timestamps "([^"]+)" to "([^"]+)"',
        _h_manifest_config,
        source_order=7057,
    )
    api.register(
        "the run manifest records zero candidates expanded and no timestamps and no model",
        _h_manifest_absent_values,
        source_order=7058,
    )
    api.register(
        "the run fixture carries raw files including a YAML file and a Gherkin file",
        _h_raw_files,
        source_order=7059,
    )
    api.register(
        'the pipeline call log contains the accepted "([^"]+)" call with \\d+ prompt tokens and the rejected "([^"]+)" call with \\d+ prompt tokens',
        _h_pipeline_call_log,
        source_order=7060,
    )
    api.register(
        'the pipeline call log contains the accepted "([^"]+)" call with \\d+ prompt tokens, the rejected "([^"]+)" call with \\d+ prompt tokens, and a "([^"]+)" call with no duration telemetry',
        _h_pipeline_call_log_partial,
        source_order=7061,
    )
    api.register(
        "the coverage data records no uncovered entry points, zones, threats, or attack patterns with an inventory completeness not confirmed",
        _h_coverage_not_confirmed,
        source_order=7062,
    )
    api.register(
        "the coverage data records a summary with .*",
        _h_coverage_summary,
        source_order=7063,
    )
    api.register(
        'the coverage data records a coverage plan targeting entry point "([^"]+)" with primary candidate "([^"]+)", state "([^"]+)", and ordered choices "([^"]+)"',
        _h_coverage_plan,
        source_order=7064,
    )
