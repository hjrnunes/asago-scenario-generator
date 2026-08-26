"""Shared LLM message helpers."""

from __future__ import annotations


def prompt_messages(system_prompt: str, user_prompt: str) -> list[dict[str, str]]:
    """The standard system + user message pair for one completion."""
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
