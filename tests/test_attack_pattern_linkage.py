"""Linkage invariants over the canonical attack-pattern YAML.

Tests pin step counts and focused regressions for ``resource_links`` and
``observable_outcome_links``; ``AttackPattern`` validation enforces the
structural linkage rules.  The ``fixtures/reviewed_linkage_decisions.yaml``
table provides reviewed semantic rationale for non-obvious linkage decisions
and is validated against the YAML.

Tests operate on raw YAML records before indexing so that uniqueness
collapses in the catalog index cannot mask divergent linkage.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from asago_scenario_generator.data.taxonomy_pins import load_taxonomy_resolver
from asago_scenario_generator.models.attack_pattern_validation import (
    validate_attack_pattern,
)

_BASE = (
    Path(__file__).resolve().parent.parent / "data" / "taxonomies" / "attack-patterns"
)
_REVIEWED_DECISIONS_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "reviewed_linkage_decisions.yaml"
)
REVIEWED_DECISIONS: list[dict[str, str]] = yaml.safe_load(
    _REVIEWED_DECISIONS_PATH.read_text(encoding="utf-8")
)
_FILES = [
    "attack-patterns-agentic-only.yaml",
    "attack-patterns-atlas-derived.yaml",
    "attack-patterns-comms-human-supply.yaml",
    "attack-patterns-halluc-intent.yaml",
    "attack-patterns-memory-tool.yaml",
]


def _load_raw_patterns() -> dict[str, dict[str, Any]]:
    """Load raw pattern dicts from YAML before any catalog indexing."""
    patterns: dict[str, dict[str, Any]] = {}
    for fn in _FILES:
        with open(_BASE / fn) as f:
            data = yaml.safe_load(f)
        for pid, p in data["patterns"].items():
            patterns[pid] = p
    return patterns


def test_canonical_yaml_has_292_steps() -> None:
    """The canonical YAML carries every step the linkage invariants cover."""
    raw = _load_raw_patterns()
    total = sum(len(p["canonical_chain"]["steps"]) for p in raw.values())
    assert total == 292


def test_canonical_yaml_has_77_outside_steps() -> None:
    """The canonical YAML carries 77 attacker-side steps outside the boundary."""
    raw = _load_raw_patterns()
    outside_count = sum(
        s.get("boundary_position") == "outside"
        for p in raw.values()
        for s in p["canonical_chain"]["steps"]
    )
    assert outside_count == 77


def test_ap_t2_04_craft_payload_has_no_outcome_links() -> None:
    """Regression: AP-T2-04 craft_payload is an outside attacker preparation
    step.  It must not have observable outcome links."""
    raw = _load_raw_patterns()
    step = next(
        s
        for s in raw["AP-T2-04"]["canonical_chain"]["steps"]
        if s["step_id"] == "craft_payload"
    )
    assert step["boundary_position"] == "outside"
    assert step["observable_outcome_links"] == []
    assert step["resource_links"] == []


def test_ap_t6_07_has_configuration_source_influence_activation() -> None:
    """The poisoned configuration is the typed upstream source that crosses
    the declared boundary into canonical ingress on future prompt loading."""
    raw = _load_raw_patterns()
    chain = raw["AP-T6-07"]["canonical_chain"]
    links = [
        (step["step_id"], link)
        for step in chain["steps"]
        for link in step.get("resource_links", [])
    ]
    assert links == [
        (
            "poisoned_prompt_activation",
            {
                "slot_id": "agent_config",
                "role": "source_influence",
                "trust_boundary_slot_id": "boundary",
                "target_ingress_slot_id": "ingress",
            },
        )
    ]
    resolver = load_taxonomy_resolver()
    validate_attack_pattern(raw["AP-T6-07"], resolver)


def test_ap_t6_07_config_modification_outcome_is_persistent_state() -> None:
    """AP-T6-07 config_modification persists to agent_config, not to the
    ingress.  Its outcome link must be persistent_state/agent_config."""
    raw = _load_raw_patterns()
    step = next(
        s
        for s in raw["AP-T6-07"]["canonical_chain"]["steps"]
        if s["step_id"] == "config_modification"
    )
    assert step["boundary_position"] == "inside"
    assert step["resource_links"] == []
    ol = step["observable_outcome_links"]
    assert len(ol) == 1
    assert ol[0]["observation"] == "persistent_state"
    assert ol[0]["binding_slot_id"] == "agent_config"


def test_ap_t6_03_goal_outcomes_are_intrinsic_agent_state() -> None:
    """Goal redirection is agent state, not fabricated external persistence."""
    raw = _load_raw_patterns()
    chain = raw["AP-T6-03"]["canonical_chain"]
    slots = {item["slot_id"]: item for item in chain["resource_slots"]}

    assert slots["agent_goal"]["kind"] == "agent_internal"
    for step_id in ("redirect_agent_goal", "execute_unintended_actions"):
        step = next(item for item in chain["steps"] if item["step_id"] == step_id)
        assert step["observable_outcome_links"] == [
            {
                "postcondition_id": f"post.{step_id}",
                "observation": "agent_state",
                "binding_slot_id": "agent_goal",
            }
        ]


def test_71_source_facts_and_49_live_ids_preserved() -> None:
    """The catalog lineage must still have 71 historical source records and
    49 resulting live pattern IDs."""
    with open(_BASE / "catalog-lineage.yaml") as f:
        lineage = yaml.safe_load(f)
    sources = lineage.get("sources", [])
    resulting = []
    for src in sources:
        resulting.extend(src.get("resulting_patterns", []))
    assert len(sources) == 71
    resulting_ids = [r["pattern_id"] for r in resulting]
    assert len(resulting_ids) == 49
    assert len(set(resulting_ids)) == 49


# ---------------------------------------------------------------------------
# Reviewed semantic decision table validation
# ---------------------------------------------------------------------------


def test_reviewed_decisions_match_yaml() -> None:
    """Every reviewed semantic decision must match the actual YAML linkage.

    The reviewed decisions table is a separate compact authority with
    independent rationale for non-obvious linkage decisions.  It must
    agree with the canonical YAML on observation kind and binding slot.
    """
    raw = _load_raw_patterns()
    for decision in REVIEWED_DECISIONS:
        if decision["step_id"] == "_chain":
            chain = raw[decision["pattern_id"]]["canonical_chain"]
            links = [
                link
                for step in chain["steps"]
                for link in step.get("resource_links", [])
                if link["role"] == decision["observation"]
                and link["slot_id"] == decision["binding_slot_id"]
            ]
            assert links == [
                {
                    "slot_id": decision["binding_slot_id"],
                    "role": decision["observation"],
                    "trust_boundary_slot_id": decision["trust_boundary_slot_id"],
                    "target_ingress_slot_id": decision["target_ingress_slot_id"],
                }
            ]
            continue

        pid = decision["pattern_id"]
        sid = decision["step_id"]
        pcid = decision["postcondition_id"]
        p = raw[pid]
        step = next(s for s in p["canonical_chain"]["steps"] if s["step_id"] == sid)
        ol = next(
            o
            for o in step.get("observable_outcome_links", [])
            if o["postcondition_id"] == pcid
        )
        assert ol["observation"] == decision["observation"], (
            f"{pid}/{sid}/{pcid}: observation {ol['observation']} != "
            f"reviewed {decision['observation']}"
        )
        assert ol["binding_slot_id"] == decision["binding_slot_id"], (
            f"{pid}/{sid}/{pcid}: slot {ol['binding_slot_id']} != "
            f"reviewed {decision['binding_slot_id']}"
        )


def test_reviewed_decisions_have_rationale() -> None:
    """Every reviewed decision must have non-empty rationale citing the
    postcondition description and causal mechanism."""
    for d in REVIEWED_DECISIONS:
        assert d["rationale"], f"{d['pattern_id']}/{d['step_id']} lacks rationale"
        assert len(d["rationale"]) > 30, (
            f"{d['pattern_id']}/{d['step_id']} rationale too short"
        )


# ---------------------------------------------------------------------------
# Focused regressions for independent-review false bindings (second review)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern_id", "step_id", "observation", "binding_slot_id"),
    [
        # 'request delivered to the agent as a direct prompt' is ingress or
        # context admission, not persistent_state in connected_service.
        pytest.param(
            "AP-T3-02",
            "deliver_request",
            "model_context",
            "ingress",
            id="ap_t3_02_deliver_request_is_model_context_ingress",
        ),
        # 'request submitted to the agent' carries the ingress activation
        # link; it is not persistent_state in external_api.
        pytest.param(
            "AP-T4-03",
            "deliver_request",
            "model_context",
            "ingress",
            id="ap_t4_03_deliver_request_is_model_context_ingress",
        ),
        # The delivery_tool performs the transmission, not the ingress.
        pytest.param(
            "AP-T2-02",
            "exfiltrate_data",
            "tool_invocation",
            "delivery_tool",
            id="ap_t2_02_exfiltrate_data_is_tool_invocation_delivery_tool",
        ),
        # F3: the client's fetch delivers data to the attacker endpoint; this
        # is delivery or receipt, not persisted state.
        pytest.param(
            "AP-T1-06",
            "impact",
            "endpoint_receipt",
            "exfil_endpoint",
            id="f3_ap_t1_06_impact_is_endpoint_receipt",
        ),
        # F4: the assistant has gathered sensitive data; this is
        # agent-internal assembled state, not state at the exfil_endpoint.
        pytest.param(
            "AP-T1-06",
            "data_collection",
            "agent_state",
            "agent_internal_state",
            id="f4_ap_t1_06_data_collection_is_agent_state",
        ),
        # F6: the receiving agent executes an unintended operation through
        # the receiving_agent tool; the protocol_endpoint integration is the
        # poisoned-content source.
        pytest.param(
            "AP-T16-02",
            "context_hijacking_impact",
            "tool_invocation",
            "receiving_agent",
            id="f6_ap_t16_02_context_hijacking_impact_is_tool_invocation",
        ),
    ],
)
def test_reviewed_step_has_single_outcome_link(
    pattern_id: str, step_id: str, observation: str, binding_slot_id: str
) -> None:
    """Regression: review findings pin each step's one outcome link."""
    raw = _load_raw_patterns()
    step = next(
        s
        for s in raw[pattern_id]["canonical_chain"]["steps"]
        if s["step_id"] == step_id
    )
    ol = step["observable_outcome_links"]
    assert len(ol) == 1
    assert ol[0]["observation"] == observation
    assert ol[0]["binding_slot_id"] == binding_slot_id


# ---------------------------------------------------------------------------
# Independent semantic audit (422o.3.2) regression tests — six confirmed
# defects.  Each test pins the corrected linkage for a specific finding;
# test_reviewed_step_has_single_outcome_link above covers F3, F4, and F6.
# ---------------------------------------------------------------------------


def test_f1_ap_t2_02_collect_data_binds_retrieval_tool() -> None:
    """F1: AP-T2-02/collect_data postcondition says 'the retrieval tool
    returns the sensitive records' — both tool_fixture and tool_invocation
    must bind retrieval_tool, not delivery_tool."""
    raw = _load_raw_patterns()
    step = next(
        s
        for s in raw["AP-T2-02"]["canonical_chain"]["steps"]
        if s["step_id"] == "collect_data"
    )
    # Resource link (tool_fixture) must reference retrieval_tool.
    rl = step["resource_links"]
    assert len(rl) == 1
    assert rl[0]["slot_id"] == "retrieval_tool"
    assert rl[0]["role"] == "tool_fixture"
    # Outcome link (tool_invocation) must reference retrieval_tool.
    ol = step["observable_outcome_links"]
    assert len(ol) == 1
    assert ol[0]["observation"] == "tool_invocation"
    assert ol[0]["binding_slot_id"] == "retrieval_tool"


def test_f2_ap_t1_06_rendered_output_is_rendered_output_surface() -> None:
    """F2: AP-T1-06/rendered_output_exfiltration postcondition says sensitive
    data is encoded in a rendered output element — the outcome is visible on
    the agent's output surface, not through the ingress entry point."""
    raw = _load_raw_patterns()
    step = next(
        s
        for s in raw["AP-T1-06"]["canonical_chain"]["steps"]
        if s["step_id"] == "rendered_output_exfiltration"
    )
    ol = step["observable_outcome_links"]
    assert len(ol) == 1
    assert ol[0]["observation"] == "rendered_output"
    assert ol[0]["binding_slot_id"] == "rendered_output"
    # The slot must be output_surface kind.
    slots = {
        s["slot_id"]: s for s in raw["AP-T1-06"]["canonical_chain"]["resource_slots"]
    }
    assert slots["rendered_output"]["kind"] == "output_surface"


def test_f5_ap_t5_02_exfiltrate_via_endpoints_is_endpoint_receipt() -> None:
    """F5: AP-T5-02/exfiltrate_via_endpoints postcondition says the agent
    emits a call to the attacker endpoint — this is endpoint receipt/
    transmission, not persisted state.  The produced reference is an effect,
    not a state."""
    raw = _load_raw_patterns()
    step = next(
        s
        for s in raw["AP-T5-02"]["canonical_chain"]["steps"]
        if s["step_id"] == "exfiltrate_via_endpoints"
    )
    # Produced reference must be an effect, not a state.
    produced = step.get("produced", [])
    assert any(p["kind"] == "effect" for p in produced), (
        "exfiltrate_via_endpoints must produce an effect, not state"
    )
    ol = step["observable_outcome_links"]
    assert len(ol) == 1
    assert ol[0]["observation"] == "endpoint_receipt"
    assert ol[0]["binding_slot_id"] == "attacker_endpoint"
