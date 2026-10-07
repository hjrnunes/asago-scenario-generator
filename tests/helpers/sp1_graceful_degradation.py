"""Shared test builders moved out of test modules."""

from __future__ import annotations


def _valid_critic_findings_dict_with_unjustified() -> dict:
    return {
        "gaps": [
            {
                "gap_type": "missing_responsibility",
                "description": "Missing input validation",
                "related_attack_path": "Attacker sends crafted input",
                "suggested_remedy": "Add input validation",
            },
        ],
        "checklist_results": {
            "Input validation": "absent_unjustified",
            "Authorization": "present",
        },
        "taxonomy_probe_results": {},
    }
