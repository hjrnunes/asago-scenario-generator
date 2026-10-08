"""Shared test builders moved out of test modules."""

from __future__ import annotations


DIRECT_REPLY = {
    "channel": "direct",
    "turn_count": 2,
    "turn_plan": [
        {"position": 1, "speaker": "attacker_user", "purpose": "establish_context"},
        {"position": 2, "speaker": "attacker_user", "purpose": "request_action"},
    ],
    "indirect": None,
}
