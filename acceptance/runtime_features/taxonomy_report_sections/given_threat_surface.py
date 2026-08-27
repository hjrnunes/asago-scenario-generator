"""Given step handlers that assemble threat-surface fixtures."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World
from runtime_features.taxonomy_report import _split_csv


def _h_ts_actionable(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... lists the actionable entry for risk card "R" with risk name "N"[, confidence C][, OWASP LLM IDs "A"][, agentic threats "T"][, and attack patterns "P"]."""
    match = re.search(
        r'the threat surface lists the actionable entry for risk card "([^"]+)"'
        r'(?: with risk name "([^"]+)")?(?:, confidence ([0-9.]+))?'
        r'(?:, OWASP LLM IDs "([^"]*)")?(?:,? (?:with )?agentic threats "([^"]*)")?'
        r'(?:,? and attack patterns "([^"]*)")?',
        text,
    )
    if not match:
        return False, f"Could not parse actionable entry step: {text}"
    risk_id, risk_name, confidence, owasp, threats, patterns = match.groups()
    entry: dict[str, Any] = {
        "risk_card": {
            "risk_id": risk_id,
            "risk_name": risk_name or risk_id,
        },
        "owasp_llm_ids": _split_csv(owasp or "") if owasp is not None else [],
        "agentic_threat_ids": _split_csv(threats or "") if threats is not None else [],
        "attack_pattern_ids": _split_csv(patterns or "")
        if patterns is not None
        else [],
    }
    if confidence:
        entry["risk_card"]["confidence"] = float(confidence)
    world.trpt_threat_surface.setdefault("entries", []).append(entry)
    return True, ""


def _h_ts_governance(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: ... lists the governance-only entry for risk card "R" with risk name "N" and no mappings."""
    match = re.search(
        r"the threat surface lists the governance-only entry for risk card "
        r'"([^"]+)" with risk name "([^"]+)" and no mappings',
        text,
    )
    if not match:
        return False, f"Could not parse governance-only step: {text}"
    world.trpt_threat_surface.setdefault("governance_only", []).append(
        {
            "risk_card": {
                "risk_id": match.group(1),
                "risk_name": match.group(2),
            },
            "owasp_llm_ids": [],
            "agentic_threat_ids": [],
            "attack_pattern_ids": [],
            "governance_only": True,
        }
    )
    return True, ""


def _h_ts_empty(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the threat surface lists no actionable entries and no governance-only entries."""
    world.trpt_threat_surface = {"entries": [], "governance_only": []}
    return True, ""


def register(api: Any) -> None:
    # --- Threat surface Given steps ---
    api.register(
        'the threat surface lists the actionable entry for risk card "([^"]+)"(?: with risk name "([^"]+)")?(?:, confidence ([0-9.]+))?(?:, OWASP LLM IDs "([^"]*)")?(?:,? (?:with )?agentic threats "([^"]*)")?(?:,? and attack patterns "([^"]*)")?',
        _h_ts_actionable,
        source_order=7010,
    )
    api.register(
        'the threat surface lists the governance-only entry for risk card "([^"]+)" with risk name "([^"]+)" and no mappings',
        _h_ts_governance,
        source_order=7011,
    )
    api.register(
        "the threat surface lists no actionable entries and no governance-only entries",
        _h_ts_empty,
        source_order=7012,
    )
