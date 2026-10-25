"""Briefs whose concern is a bundled pattern that links known mechanisms."""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.data.loaders import load_attack_patterns


def linked_brief(brief: Any, pattern_id: str) -> Any:
    """*brief* with its concern replaced by the bundled pattern *pattern_id*.

    Only the concern's identity, name and description change, which is what
    the routing and verifier prompts read from a brief.
    """
    record = load_attack_patterns()[pattern_id]
    return brief.model_copy(
        update={
            "attack_pattern_id": pattern_id,
            "attack_pattern_name": record["name"],
            "attack_pattern_description": record["description"],
        }
    )
