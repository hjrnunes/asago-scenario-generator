"""Acceptance step handlers for taxonomy threat-surface derivation.

Fixtures are built step-by-step in the world (risk-extraction entries,
SSSOM rows, cross-taxonomy sections, KC gating data, attack patterns)
and materialized to a temp directory when the threat surface is derived.
The When step drives the production ``determine_threat_surface`` with
fixture file paths — gating data is injected through its optional
``kc_mapping_path`` and ``attack_patterns_path`` parameters so each
scenario declares exactly the threats it wants in scope.
"""

from __future__ import annotations

import json
import tempfile

from runtime_shared import Path, World, re

import yaml

FEATURE_ID = "taxonomy_threat_surface"

# Causal-chain text written for the governance-only retention scenario.
_CAUSAL_CHAIN_TEXT = {
    "threat": "An adversary composes a crafted prompt that hijacks agent instructions.",
    "vulnerability": "The agent accepts instructions without validating their source.",
    "consequence": "The agent takes actions outside its design intent.",
    "impact": "Unauthorized actions harm the organization and its users.",
}

_DEFAULT_KC_MAPPING = {
    "kc_to_threats": {"KCX-TSDS": ["T6"], "KC6.4": []},
    "hitl": {"threat_ids": []},
}
_DEFAULT_KC_CODES = ["KCX-TSDS", "KC6.4"]

_SSSOM_HEADER = (
    "subject_id\tsubject_source\tpredicate_id\tobject_id"
    "\tobject_source\tmapping_justification"
)


def _init_state(world: World) -> None:
    """Reset per-example fixture state on the world."""
    world.tsds_fixture_dir = Path(tempfile.mkdtemp(prefix="tsds-fixture-"))
    world.tsds_risk_entries: list[dict] = []
    world.tsds_sssom_rows: list[tuple[str, str]] = []
    world.tsds_cross = {
        "t_to_llm": [],
        "t_to_atlas": [],
        "t_to_asi": [],
        "t_direct": [],
    }
    world.tsds_kc_mapping = dict(_DEFAULT_KC_MAPPING)
    world.tsds_kc_codes = list(_DEFAULT_KC_CODES)
    world.tsds_attack_patterns: dict[str, str] | None = None
    world.tsds_chain_text: dict[str, dict] = {}
    world.tsds_surface = None


def _split_csv(raw: str) -> list[str]:
    return [part.strip() for part in raw.split(",") if part.strip()]


def _ensure_risk_card(world: World, risk_id: str) -> dict:
    for entry in world.tsds_risk_entries:
        if entry["risk_id"] == risk_id:
            return entry
    entry = {
        "risk_id": risk_id,
        "risk_name": risk_id,
        "risk_description": f"Risk description for {risk_id}",
        "taxonomy": "ibm-risk-atlas",
        "confidence": 0.9,
        "grounding_confidence": "high",
    }
    world.tsds_risk_entries.append(entry)
    return entry


def _add_sssom_rows(world: World, risk_id: str, llm_ids: list[str]) -> str | None:
    """Append SSSOM rows for each LLM ID; returns an error message or None."""
    for llm_id in llm_ids:
        match = re.fullmatch(r"LLM(\d{2})", llm_id)
        if not match:
            return f"invalid OWASP LLM ID in scenario text: {llm_id!r}"
        row = (risk_id, f"llm{match.group(1)}-fixture")
        if row not in world.tsds_sssom_rows:
            world.tsds_sssom_rows.append(row)
    return None


def _add_t_to_atlas(world: World, t_id: str, atlas_ids: list[str]) -> None:
    for entry in world.tsds_cross["t_to_atlas"]:
        if entry["source"] == t_id:
            for atlas_id in atlas_ids:
                if atlas_id not in entry["targets"]:
                    entry["targets"].append(atlas_id)
            return
    world.tsds_cross["t_to_atlas"].append({"source": t_id, "targets": list(atlas_ids)})


def _add_direct(world: World, t_id: str, atlas_ids: list[str]) -> None:
    if not any(entry["source"] == t_id for entry in world.tsds_cross["t_direct"]):
        world.tsds_cross["t_direct"].append(
            {"source": t_id, "source_name": f"Direct-path {t_id}"}
        )
    _add_t_to_atlas(world, t_id, atlas_ids)


# ---------------------------------------------------------------------------
# Given steps
# ---------------------------------------------------------------------------


def _h_bg_inputs(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the risk-extraction, SSSOM, cross-taxonomy, and capability-profile inputs are available."""
    _init_state(world)
    return True, ""


def _h_risk_card(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the risk-extraction file contains risk card X with risk name Y."""
    m = re.search(r'contains risk card "([^"]+)" with risk name "([^"]+)"', text)
    if not m:
        return False, f"Could not parse risk card step: {text}"
    risk_id, risk_name = m.group(1), m.group(2)
    _ensure_risk_card(world, risk_id)["risk_name"] = risk_name
    return True, ""


def _h_zero_risk_cards(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the risk-extraction file contains zero risk cards."""
    world.tsds_risk_entries = []
    return True, ""


def _h_causal_chain(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the risk card X carries causal-chain threat, vulnerability, consequence, and impact text."""
    m = re.search(r'the risk card "([^"]+)" carries causal-chain', text)
    if not m:
        return False, f"Could not parse causal-chain step: {text}"
    risk_id = m.group(1)
    entry = _ensure_risk_card(world, risk_id)
    for field, value in _CAUSAL_CHAIN_TEXT.items():
        entry[field] = value
    world.tsds_chain_text[risk_id] = dict(_CAUSAL_CHAIN_TEXT)
    return True, ""


def _h_sssom_links(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the SSSOM mapping links risk card X to OWASP LLM entries A,B."""
    m = re.search(r'links risk card "([^"]+)" to OWASP LLM entries "([^"]+)"', text)
    if not m:
        return False, f"Could not parse SSSOM step: {text}"
    risk_id, llm_csv = m.group(1), m.group(2)
    _ensure_risk_card(world, risk_id)
    error = _add_sssom_rows(world, risk_id, _split_csv(llm_csv))
    return (True, "") if error is None else (False, error)


def _h_sssom_no_entry(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the SSSOM mapping has no entry for risk card X."""
    m = re.search(r'has no entry for risk card "([^"]+)"', text)
    if not m:
        return False, f"Could not parse SSSOM absence step: {text}"
    risk_id = m.group(1)
    if any(row[0] == risk_id for row in world.tsds_sssom_rows):
        return False, f"expected no SSSOM entry for {risk_id} but rows exist"
    return True, ""


def _h_llm_to_t(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the cross-taxonomy mapping links OWASP LLM entry X to T-threats A,B."""
    m = re.search(r'links OWASP LLM entry "([^"]+)" to T-threats "([^"]+)"', text)
    if not m:
        return False, f"Could not parse LLM->T step: {text}"
    llm_id = m.group(1)
    for t_id in _split_csv(m.group(2)):
        world.tsds_cross["t_to_llm"].append({"source": t_id, "target": llm_id})
    return True, ""


def _h_t_to_atlas(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the cross-taxonomy mapping links T-threat(s) X to ATLAS techniques A,B."""
    m = re.search(r'links T-threats? "([^"]+)" to ATLAS techniques "([^"]+)"', text)
    if not m:
        return False, f"Could not parse T->ATLAS step: {text}"
    for t_id in _split_csv(m.group(1)):
        _add_t_to_atlas(world, t_id, _split_csv(m.group(2)))
    return True, ""


def _h_no_atlas(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the cross-taxonomy mapping links no ATLAS techniques from any T-threat."""
    world.tsds_cross["t_to_atlas"] = []
    return True, ""


def _h_direct(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the cross-taxonomy mapping links direct-path T-threat(s) X to ATLAS techniques A,B."""
    m = re.search(
        r'links direct-path T-threats? "([^"]+)" to ATLAS techniques "([^"]+)"',
        text,
    )
    if not m:
        return False, f"Could not parse direct-path step: {text}"
    for t_id in _split_csv(m.group(1)):
        _add_direct(world, t_id, _split_csv(m.group(2)))
    return True, ""


def _h_asi(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the cross-taxonomy mapping links T-threat A to ASI entry X and T-threat B to ASI entry Y."""
    m = re.search(
        r'links T-threat "([^"]+)" to ASI entry "([^"]+)" '
        r'and T-threat "([^"]+)" to ASI entry "([^"]+)"',
        text,
    )
    if not m:
        return False, f"Could not parse ASI step: {text}"
    for t_index, asi_index in ((1, 2), (3, 4)):
        world.tsds_cross["t_to_asi"].append(
            {"source": m.group(t_index), "target": m.group(asi_index)}
        )
    return True, ""


def _h_gates_scope(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the capability profile gates T-threats A,B in scope."""
    m = re.search(r'gates T-threats "([^"]+)" in scope', text)
    if not m:
        return False, f"Could not parse gating step: {text}"
    scoped = _split_csv(m.group(1))
    world.tsds_kc_mapping = {
        "kc_to_threats": {"KCX-TSDS": scoped, "KC6.4": []},
        "hitl": {"threat_ids": []},
    }
    world.tsds_kc_codes = ["KCX-TSDS", "KC6.4"]
    return True, ""


def _h_gates_with_kc(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the capability profile gates T-threat X in scope with KC sub-codes A,B."""
    m = re.search(
        r'gates T-threat "([^"]+)" in scope with KC sub-codes "([^"]+)"', text
    )
    if not m:
        return False, f"Could not parse gating step: {text}"
    threat_id = m.group(1)
    codes = _split_csv(m.group(2))
    world.tsds_kc_mapping = {
        "kc_to_threats": {code: [threat_id] for code in codes},
        "hitl": {"threat_ids": []},
    }
    world.tsds_kc_codes = codes
    return True, ""


def _h_keeps_patterns(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the capability profile keeps attack patterns X for T-threat A and Y for T-threat B."""
    m = re.search(
        r'keeps attack patterns "([^"]+)" for T-threat "([^"]+)" '
        r'and "([^"]+)" for T-threat "([^"]+)"',
        text,
    )
    if not m:
        return False, f"Could not parse attack-pattern step: {text}"
    if world.tsds_attack_patterns is None:
        world.tsds_attack_patterns = {}
    for first, second in ((1, 2), (3, 4)):
        pattern_ids = _split_csv(m.group(first))
        threat_id = m.group(second)
        for pid in pattern_ids:
            # A pattern ID belongs to the first T-threat that keeps it.
            world.tsds_attack_patterns.setdefault(pid, threat_id)
    return True, ""


# ---------------------------------------------------------------------------
# When step
# ---------------------------------------------------------------------------


def _materialize_inputs(
    world: World,
) -> tuple[Path, Path, Path, Path, Path | None]:
    """Write the world's fixture state to its temp dir; return input paths."""
    fixture_dir = world.tsds_fixture_dir
    risk_path = fixture_dir / "risk-extraction.json"
    sssom_path = fixture_dir / "risk-atlas-llm.sssom.tsv"
    cross_path = fixture_dir / "cross-taxonomy-mappings.yaml"
    kc_path = fixture_dir / "kc-threat-mapping.yaml"

    risk_path.write_text(
        json.dumps({"risks": world.tsds_risk_entries}) + "\n", encoding="utf-8"
    )
    rows = [_SSSOM_HEADER]
    for risk_id, raw_llm_id in world.tsds_sssom_rows:
        rows.append(
            f"{risk_id}\tibm-risk-atlas\tskos:exactMatch\t{raw_llm_id}"
            "\towasp-llm-top10\tsemapv:ManualMappingCuration"
        )
    sssom_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    cross_path.write_text(
        yaml.safe_dump(world.tsds_cross, sort_keys=False), encoding="utf-8"
    )
    kc_path.write_text(
        yaml.safe_dump(world.tsds_kc_mapping, sort_keys=False), encoding="utf-8"
    )

    attack_patterns_path = None
    if world.tsds_attack_patterns is not None:
        attack_patterns_path = fixture_dir / "attack-patterns.yaml"
        patterns = {
            pid: {
                "id": pid,
                "threat_id": threat_id,
                "name": pid,
                "description": f"Fixture pattern {pid}",
            }
            for pid, threat_id in world.tsds_attack_patterns.items()
        }
        attack_patterns_path.write_text(
            yaml.safe_dump({"patterns": patterns}, sort_keys=False),
            encoding="utf-8",
        )

    return risk_path, sssom_path, cross_path, kc_path, attack_patterns_path


def _h_derive(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the threat surface is derived."""
    from asago_scenario_generator.data.loaders import load_risk_extraction
    from asago_scenario_generator.models import CapabilityProfile
    from asago_scenario_generator.models.capability_profile import (
        ToolInventoryEntry,
    )
    from asago_scenario_generator.pipeline.threats import (
        determine_threat_surface,
    )

    risk_path, sssom_path, cross_path, kc_path, attack_patterns_path = (
        _materialize_inputs(world)
    )

    kwargs = {}
    if any(
        code.startswith("KC5.") or code.startswith("KC6.")
        for code in world.tsds_kc_codes
    ):
        kwargs["tool_inventory"] = [
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ]
    profile = CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=["user input (zone 1)"],
        confidence="medium",
        kc_subcodes=world.tsds_kc_codes,
        **kwargs,
    )

    cards = load_risk_extraction(risk_path)
    world.tsds_surface = determine_threat_surface(
        profile,
        cards,
        sssom_path,
        cross_path,
        kc_mapping_path=kc_path,
        attack_patterns_path=attack_patterns_path,
    )
    return True, ""


# ---------------------------------------------------------------------------
# Then steps
# ---------------------------------------------------------------------------


def _single_entry(entries: list, risk_id: str, label: str):
    """Return the sole entry for risk_id, raising when absent or ambiguous."""
    matches = [e for e in entries if e.risk_card.risk_id == risk_id]
    if len(matches) != 1:
        raise AssertionError(
            f"expected exactly one {label} entry for {risk_id}, found {len(matches)}"
        )
    return matches[0]


def _actionable_entry(world: World, risk_id: str):
    if world.tsds_surface is None:
        raise AssertionError("the threat surface has not been derived")
    return _single_entry(world.tsds_surface.entries, risk_id, "actionable")


def _governance_entry(world: World, risk_id: str):
    if world.tsds_surface is None:
        raise AssertionError("the threat surface has not been derived")
    return _single_entry(world.tsds_surface.governance_only, risk_id, "governance-only")


def _sole_governance(world: World):
    """Return the single governance-only entry, or None when absent or ambiguous."""
    if world.tsds_surface is None or len(world.tsds_surface.governance_only) != 1:
        return None
    return world.tsds_surface.governance_only[0]


def _ids_empty(entry, fields: tuple[tuple[str, str], ...]) -> str | None:
    """Return an error message when any field is non-empty, else None."""
    for field, label in fields:
        value = getattr(entry, field)
        if value:
            return f"expected no {label}, got {value}"
    return None


def _check_ids(actual: list[str], expected: list[str], label: str) -> str | None:
    if actual != expected:
        return f"{label}: expected {expected}, got {actual}"
    return None


def _h_surface_counts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the surface contains N actionable entries and M governance-only entries."""
    m = re.search(
        r"contains (\d+) actionable entr(?:y|ies) and (\d+) governance-only", text
    )
    if not m:
        return False, f"Could not parse surface counts step: {text}"
    if world.tsds_surface is None:
        return False, "the threat surface has not been derived"
    expected_entries, expected_governance = int(m.group(1)), int(m.group(2))
    actual_entries = len(world.tsds_surface.entries)
    actual_governance = len(world.tsds_surface.governance_only)
    if (actual_entries, actual_governance) != (
        expected_entries,
        expected_governance,
    ):
        return (
            False,
            f"surface counts expected ({expected_entries}, {expected_governance}), "
            f"got ({actual_entries}, {actual_governance})",
        )
    return True, ""


def _h_actionable_llm_ids(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the actionable entry for risk card X lists OWASP LLM IDs A,B."""
    m = re.search(
        r'actionable entry for risk card "([^"]+)" lists OWASP LLM IDs "([^"]*)"', text
    )
    if not m:
        return False, f"Could not parse entry assertion step: {text}"
    entry = _actionable_entry(world, m.group(1))
    error = _check_ids(entry.owasp_llm_ids, _split_csv(m.group(2)), "OWASP LLM IDs")
    return (True, "") if error is None else (False, error)


def _h_actionable_no_atlas(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the actionable entry for risk card X lists no ATLAS techniques."""
    m = re.search(r'actionable entry for risk card "([^"]+)" lists no ATLAS', text)
    if not m:
        return False, f"Could not parse entry assertion step: {text}"
    entry = _actionable_entry(world, m.group(1))
    if entry.atlas_technique_ids:
        return False, f"expected no ATLAS techniques, got {entry.atlas_technique_ids}"
    return True, ""


def _h_actionable_in_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the actionable entry lists T-threats / ATLAS techniques / attack patterns / ASI entries in first-seen order."""
    m = re.search(
        r'actionable entry for risk card "([^"]+)" lists '
        r"(T-threats|ATLAS techniques|attack patterns|ASI entries) "
        r'"([^"]+)"(?: once each)? in first-seen order',
        text,
    )
    if not m:
        return False, f"Could not parse entry assertion step: {text}"
    risk_id, kind, expected = m.group(1), m.group(2), m.group(3)
    entry = _actionable_entry(world, risk_id)
    if kind == "T-threats":
        actual = entry.agentic_threat_ids
    elif kind == "ATLAS techniques":
        actual = entry.atlas_technique_ids
    elif kind == "attack patterns":
        actual = entry.attack_pattern_ids
    else:
        actual = entry.owasp_asi_ids
    error = _check_ids(actual, _split_csv(expected), kind)
    return (True, "") if error is None else (False, error)


def _h_governance_references(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the governance-only entry references risk card X with risk name Y."""
    m = re.search(
        r'governance-only entry references risk card "([^"]+)" with risk name "([^"]+)"',
        text,
    )
    if not m:
        return False, f"Could not parse governance assertion step: {text}"
    entry = _governance_entry(world, m.group(1))
    if entry.risk_card.risk_id != m.group(1):
        return False, f"governance entry references {entry.risk_card.risk_id}"
    if entry.risk_card.risk_name != m.group(2):
        return (
            False,
            f"governance risk name expected {m.group(2)!r}, "
            f"got {entry.risk_card.risk_name!r}",
        )
    return True, ""


def _h_governance_no_llm_t_patterns(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the governance-only entry lists no OWASP LLM IDs, no T-threats, and no attack-pattern IDs."""
    entry = _sole_governance(world)
    if entry is None:
        return False, "expected exactly one governance-only entry"
    error = _ids_empty(
        entry,
        (
            ("owasp_llm_ids", "OWASP LLM IDs"),
            ("agentic_threat_ids", "T-threats"),
            ("attack_pattern_ids", "attack-pattern IDs"),
        ),
    )
    return (True, "") if error is None else (False, error)


def _h_governance_no_t_patterns_atlas_asi(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the governance-only entry lists no T-threats, no attack-pattern IDs, no ATLAS techniques, and no ASI IDs."""
    entry = _sole_governance(world)
    if entry is None:
        return False, "expected exactly one governance-only entry"
    error = _ids_empty(
        entry,
        (
            ("agentic_threat_ids", "T-threats"),
            ("attack_pattern_ids", "attack-pattern IDs"),
            ("atlas_technique_ids", "ATLAS techniques"),
            ("owasp_asi_ids", "ASI IDs"),
        ),
    )
    return (True, "") if error is None else (False, error)


def _h_governance_no_direct(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the governance-only entry lists no direct-path T-threat."""
    entry = _sole_governance(world)
    if entry is None:
        return False, "expected exactly one governance-only entry"
    if entry.agentic_threat_ids:
        return (
            False,
            f"expected no direct-path T-threat, got {entry.agentic_threat_ids}",
        )
    return True, ""


def _h_governance_retains_chain(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the governance-only entry retains the causal-chain text of its risk card."""
    if world.tsds_surface is None or len(world.tsds_surface.governance_only) != 1:
        return False, "expected exactly one governance-only entry"
    entry = world.tsds_surface.governance_only[0]
    chain = world.tsds_chain_text.get(entry.risk_card.risk_id)
    if not chain:
        return False, "no causal-chain text recorded for this risk card"
    for field, expected in chain.items():
        if getattr(entry.risk_card, field) != expected:
            return (
                False,
                f"causal-chain {field}: expected {expected!r}, "
                f"got {getattr(entry.risk_card, field)!r}",
            )
    return True, ""


def _h_governance_llm_ids(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the governance-only entry for risk card X lists OWASP LLM IDs A,B."""
    m = re.search(
        r'governance-only entry for risk card "([^"]+)" lists OWASP LLM IDs "([^"]*)"',
        text,
    )
    if not m:
        return False, f"Could not parse governance assertion step: {text}"
    entry = _governance_entry(world, m.group(1))
    error = _check_ids(entry.owasp_llm_ids, _split_csv(m.group(2)), "OWASP LLM IDs")
    return (True, "") if error is None else (False, error)


def register(api: object) -> None:
    """Register taxonomy threat-surface handlers with regex-based extraction."""
    api.set_feature(None)
    api.register(
        "the risk-extraction, SSSOM, cross-taxonomy, and capability-profile inputs are available",
        _h_bg_inputs,
    )
    api.register(
        r'contains risk card "([^"]+)" with risk name "([^"]+)"',
        _h_risk_card,
    )
    # Tagged first-class registration: stage1_split registers the same raw
    # pattern globally with a no-op handler, so this feature-specific
    # handler must win within this feature's own scope only.
    api.set_feature("taxonomy_threat_surface")
    api.register_first(
        "the risk-extraction file contains zero risk cards",
        _h_zero_risk_cards,
    )
    api.set_feature(None)
    api.register(
        r'the risk card "([^"]+)" carries causal-chain threat, vulnerability, consequence, and impact text',
        _h_causal_chain,
    )
    api.register(
        r'links risk card "([^"]+)" to OWASP LLM entries "([^"]+)"',
        _h_sssom_links,
    )
    api.register(
        r'has no entry for risk card "([^"]+)"',
        _h_sssom_no_entry,
    )
    api.register(
        r'links OWASP LLM entry "([^"]+)" to T-threats "([^"]+)"',
        _h_llm_to_t,
    )
    api.register(
        r'links T-threats? "([^"]+)" to ATLAS techniques "([^"]+)"',
        _h_t_to_atlas,
    )
    api.register(
        "the cross-taxonomy mapping links no ATLAS techniques from any T-threat",
        _h_no_atlas,
    )
    api.register(
        r'links direct-path T-threats? "([^"]+)" to ATLAS techniques "([^"]+)"',
        _h_direct,
    )
    api.register(
        r'links T-threat "([^"]+)" to ASI entry "([^"]+)" and T-threat "([^"]+)" to ASI entry "([^"]+)"',
        _h_asi,
    )
    api.register(
        r'gates T-threats "([^"]+)" in scope',
        _h_gates_scope,
    )
    api.register(
        r'gates T-threat "([^"]+)" in scope with KC sub-codes "([^"]+)"',
        _h_gates_with_kc,
    )
    api.register(
        r'keeps attack patterns "([^"]+)" for T-threat "([^"]+)" and "([^"]+)" for T-threat "([^"]+)"',
        _h_keeps_patterns,
    )
    api.register("the threat surface is derived", _h_derive)
    api.register(
        r"contains (\d+) actionable entr(?:y|ies) and (\d+) governance-only",
        _h_surface_counts,
    )
    api.register(
        r'actionable entry for risk card "([^"]+)" lists OWASP LLM IDs "([^"]*)"',
        _h_actionable_llm_ids,
    )
    api.register(
        r'actionable entry for risk card "([^"]+)" lists no ATLAS techniques',
        _h_actionable_no_atlas,
    )
    api.register(
        r'actionable entry for risk card "([^"]+)" lists (T-threats|ATLAS techniques|attack patterns|ASI entries) "([^"]+)"(?: once each)? in first-seen order',
        _h_actionable_in_order,
    )
    api.register(
        r'governance-only entry references risk card "([^"]+)" with risk name "([^"]+)"',
        _h_governance_references,
    )
    api.register(
        "the governance-only entry lists no OWASP LLM IDs, no T-threats, and no attack-pattern IDs",
        _h_governance_no_llm_t_patterns,
    )
    api.register(
        "the governance-only entry lists no T-threats, no attack-pattern IDs, no ATLAS techniques, and no ASI IDs",
        _h_governance_no_t_patterns_atlas_asi,
    )
    api.register(
        "the governance-only entry lists no direct-path T-threat",
        _h_governance_no_direct,
    )
    api.register(
        "the governance-only entry retains the causal-chain text of its risk card",
        _h_governance_retains_chain,
    )
    api.register(
        r'governance-only entry for risk card "([^"]+)" lists OWASP LLM IDs "([^"]*)"',
        _h_governance_llm_ids,
    )
