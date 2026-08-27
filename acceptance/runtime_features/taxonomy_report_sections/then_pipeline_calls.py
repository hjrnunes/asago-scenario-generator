"""Then step handlers asserting the Pipeline LLM Calls section and per-scenario LLM calls."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World
from ._helpers import _html, _card_region, _section_region, _visible, _resolve


def _h_ts_pipeline_section(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the report contains a "Pipeline LLM Calls" section."""
    return _resolve(
        "<h2>Pipeline LLM Calls</h2>" in _html(world), "pipeline calls missing"
    )


def _h_ts_pipeline_summary(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the pipeline calls summary shows "A" with "B", "C", and "D"."""
    match = re.search(
        r'the pipeline calls summary shows "([^"]+)" with "([^"]+)", "([^"]+)", and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse pipeline summary: {text}"
    values = match.groups()
    region = _section_region(_html(world), "sec-pipeline-calls")
    ok = all(value in region for value in values)
    return _resolve(ok, f"pipeline summary={values}")


def _h_ts_pipeline_semantic_status(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the pipeline calls summary shows the semantic status "S"."""
    match = re.search(
        r'the pipeline calls summary shows the semantic status "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse semantic-status assertion: {text}"
    region = _section_region(_html(world), "sec-pipeline-calls")
    return _resolve(
        match.group(1) in _visible(region), f"semantic status={match.group(1)!r}"
    )


def _h_ts_llm_tab_entry(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the LLM Calls tab of scenario "S" shows the entry "E"."""
    match = re.search(
        r'the LLM Calls tab of scenario "([^"]+)" shows the entry "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse llm-call entry assertion: {text}"
    sid, entry = match.groups()
    return _resolve(entry in _card_region(_html(world), sid), f"entry={entry}")


def _h_ts_llm_tab_prompts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the LLM Calls tab of scenario "S" renders the system prompt "P" and the user prompt "Q"."""
    match = re.search(
        r'the LLM Calls tab of scenario "([^"]+)" renders the system prompt '
        r'"([^"]+)" and the user prompt "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse llm-call prompts assertion: {text}"
    sid, system_prompt, user_prompt = match.groups()
    region = _card_region(_html(world), sid)
    ok = system_prompt in region and user_prompt in region
    ok = ok and 'class="call-log-pre"' in region
    return _resolve(ok, f"prompts system={system_prompt} user={user_prompt}")


def _h_ts_pipeline_semantic_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the pipeline calls summary shows the semantic warning "W"."""
    match = re.search(
        r'the pipeline calls summary shows the semantic warning "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse semantic-warning assertion: {text}"
    region = _section_region(_html(world), "sec-pipeline-calls")
    ok = "Presentation fallback used:" in _visible(region)
    ok = ok and match.group(1) in _visible(region)
    return _resolve(ok, f"semantic warning={match.group(1)!r}")


def _h_ts_pipeline_unavailable_warning(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the pipeline calls summary shows the unavailable-metrics warning for call "C"."""
    match = re.search(
        r"the pipeline calls summary shows the unavailable-metrics warning "
        r'for call "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse unavailable-warning assertion: {text}"
    region = _section_region(_html(world), "sec-pipeline-calls")
    visible = _visible(region)
    ok = f"Warning: call {match.group(1)} has unavailable usage metrics" in visible
    ok = ok and "duration_ms" in visible
    return _resolve(ok, f"unavailable warning for call={match.group(1)!r}")


def _h_ts_pipeline_entry(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the pipeline calls summary shows the entry "E"."""
    match = re.search(r'the pipeline calls summary shows the entry "([^"]+)"', text)
    if not match:
        return False, f"Could not parse pipeline entry assertion: {text}"
    region = _section_region(_html(world), "sec-pipeline-calls")
    return _resolve(match.group(1) in region, f"pipeline entry={match.group(1)!r}")


def register(api: Any) -> None:
    # --- Pipeline calls / per-scenario LLM calls Then steps ---
    api.register(
        'the report contains a "Pipeline LLM Calls" section',
        _h_ts_pipeline_section,
        source_order=8072,
    )
    api.register(
        'the pipeline calls summary shows "([^"]+)" with "([^"]+)", "([^"]+)", and "([^"]+)"',
        _h_ts_pipeline_summary,
        source_order=8073,
    )
    api.register(
        'the pipeline calls summary shows the semantic status "([^"]+)"',
        _h_ts_pipeline_semantic_status,
        source_order=8074,
    )
    api.register(
        'the LLM Calls tab of scenario "([^"]+)" shows the entry "([^"]+)"',
        _h_ts_llm_tab_entry,
        source_order=8101,
    )
    api.register(
        'the LLM Calls tab of scenario "([^"]+)" renders the system prompt "([^"]+)" and the user prompt "([^"]+)"',
        _h_ts_llm_tab_prompts,
        source_order=8102,
    )
    api.register(
        'the pipeline calls summary shows the semantic warning "([^"]+)"',
        _h_ts_pipeline_semantic_warning,
        source_order=8103,
    )
    api.register(
        'the pipeline calls summary shows the unavailable-metrics warning for call "([^"]+)"',
        _h_ts_pipeline_unavailable_warning,
        source_order=8104,
    )
    api.register(
        'the pipeline calls summary shows the entry "([^"]+)"',
        _h_ts_pipeline_entry,
        source_order=8105,
    )
