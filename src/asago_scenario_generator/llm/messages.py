"""Shared LLM message helpers."""

from __future__ import annotations


def prompt_messages(system_prompt: str, user_prompt: str) -> list[dict[str, str]]:
    """The standard system + user message pair for one completion."""
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T14:34:11Z","module_hash":"4f3b7c4b13be8e407dbef9aa0dbbf1ac2a996e0bd28159556410e3e27bf53515","source_sha256":"93ceb0bdb25eede98cb97ca7b4858fe30761a4f7d55dee0587dd323dbf7d2f2a","functions":[{"id":"func/prompt_messages","name":"prompt_messages","line":6,"end_line":11,"hash":"d88d51c07c8f5dfc69d6d0344a00788b97d6dc051fdbad3572e6b39e6507d894"}]}
# mutate4py-manifest-end
