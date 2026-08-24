"""Then step handlers asserting raw-data panels, scenario tabs, and pipeline calls."""

from __future__ import annotations

import re
from typing import Any
from runtime_world import World
from . import FEATURE_ID
from . import _html, _card_region, _section_region, _visible, _resolve


def _h_ts_yaml_panel(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the YAML panel shows a highlighted comment, key "K", number value N, boolean value B, and null value."""
    match = re.search(
        r'the YAML panel shows a highlighted comment, key "([^"]+)", number '
        r"value \d+, boolean value .*, and null value",
        text,
    )
    if not match:
        return False, f"Could not parse YAML panel assertion: {text}"
    key = match.group(1)
    region = _section_region(_html(world), "sec-raw")
    ok = 'class="yaml-comment"' in region
    ok = ok and f'class="yaml-key">{key}</span>' in region
    ok = ok and 'class="yaml-number">3</span>' in region
    ok = ok and 'class="yaml-bool">true</span>' in region
    ok = ok and 'class="yaml-null">null</span>' in region
    return _resolve(ok, f"YAML panel key={key}")


def _h_ts_yaml_quoted(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the YAML panel renders the quoted string "S" without a highlight class."""
    match = re.search(
        r'the YAML panel renders the quoted string "([^"]+)" without a highlight class',
        text,
    )
    if not match:
        return False, f"Could not parse YAML quoted-string assertion: {text}"
    region = _section_region(_html(world), "sec-raw")
    ok = f"&quot;{match.group(1)}&quot;" in region
    ok = ok and "yaml-string" not in region
    return _resolve(ok, f"quoted string {match.group(1)!r}")


def _h_ts_gherkin_panel(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Gherkin panel shows a highlighted comment, tag "T", and the keywords "Feature:" and "Given"."""
    match = re.search(
        r'the Gherkin panel shows a highlighted comment, tag "([^"]+)", and '
        r'the keywords "([^"]+)" and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse Gherkin panel assertion: {text}"
    tag, keyword1, keyword2 = match.groups()
    region = _section_region(_html(world), "sec-raw")
    ok = 'class="gherkin-comment"' in region
    ok = ok and f'class="gherkin-tag">@{tag}</span>' in region
    ok = ok and f'class="gherkin-keyword">{keyword1}</span>' in region
    ok = ok and f'class="gherkin-keyword">{keyword2} </span>' in region
    return _resolve(ok, f"gherkin tag={tag} keywords={keyword1} {keyword2}")


def _h_ts_gen_inputs_headers(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Generation Inputs tab of scenario "S" shows the call headers "H1" and "H2"."""
    match = re.search(
        r'the Generation Inputs tab of scenario "([^"]+)" shows the call '
        r'headers "([^"]+)" and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse gen-inputs headers: {text}"
    sid, header1, header2 = match.groups()
    region = _card_region(_html(world), sid)
    return _resolve(
        header1 in region and header2 in region, f"headers={header1} {header2}"
    )


def _h_ts_gen_inputs_row(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the Generation Inputs tab shows the row "L" with the value "V"."""
    match = re.search(
        r'the Generation Inputs tab shows the row "([^"]+)" with the value "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse gen-inputs row: {text}"
    label, value = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    ok = f">{label}</td>" in region and value in region
    return _resolve(ok, f"row label={label} value={value}")


def _h_ts_gen_inputs_em_dash(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Generation Inputs tab shows the row "Narrative summary" with the em dash "—"."""
    match = re.search(
        r'the Generation Inputs tab shows the row "([^"]+)" with the em dash "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse gen-inputs em-dash: {text}"
    label, dash = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    ok = f">{label}</td>" in region and f">{dash}</td>" in region
    return _resolve(ok, f"em-dash row label={label}")


def _h_ts_behavior_spec_steps(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Behavior Spec tab of scenario "S" shows the step keywords "Given", "When", and "Then" with the texts "A", "B", and "C"."""
    match = re.search(
        r'the Behavior Spec tab of scenario "([^"]+)" shows the step keywords '
        r'"Given", "When", and "Then" with the texts "([^"]+)", "([^"]+)", and "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse behavior-spec assertion: {text}"
    sid, text1, text2, text3 = match.groups()
    region = _card_region(_html(world), sid)
    ok = (
        'class="step-keyword">Given</span>' in region
        and 'class="step-keyword">When</span>' in region
        and 'class="step-keyword">Then</span>' in region
    )
    ok = ok and f'class="step-text">{text1}</span>' in region
    ok = ok and f'class="step-text">{text2}</span>' in region
    ok = ok and f'class="step-text">{text3}</span>' in region
    return _resolve(ok, f"behavior steps texts={text1} {text2} {text3}")


def _h_ts_behavior_spec_absent(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Behavior Spec tab of scenario "S" shows the message "M"."""
    match = re.search(
        r'the Behavior Spec tab of scenario "([^"]+)" shows the message "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse behavior-absent assertion: {text}"
    sid, message = match.groups()
    return _resolve(message in _card_region(_html(world), sid), f"message={message}")


def _h_ts_atlas_classifications(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the ATLAS Techniques tab of scenario "S" shows the heading "Scenario classifications" with the badge "B"."""
    match = re.search(
        r'the ATLAS Techniques tab of scenario "([^"]+)" shows the heading '
        r'"Scenario classifications" with the badge "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse atlas-classifications assertion: {text}"
    sid, badge = match.groups()
    region = _card_region(_html(world), sid)
    block = region[
        region.find("Scenario classifications") : region.find("Projected-step mappings")
    ]
    return _resolve(
        "Scenario classifications" in region and badge in block, f"badge={badge}"
    )


def _h_ts_atlas_none(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Handle: the ATLAS Techniques tab shows the heading "Projected-step mappings" with the placeholder "none"."""
    match = re.search(
        r'the ATLAS Techniques tab shows the heading "([^"]+)" with the '
        r'placeholder "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse atlas-none assertion: {text}"
    heading, placeholder = match.groups()
    html = _html(world)
    ok = heading in html
    ok = ok and f'class="prov-badge prov-badge-muted">{placeholder}</span>' in html
    return _resolve(ok, f"heading={heading} placeholder={placeholder}")


def _h_ts_complexity_heading(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Actor Profile tab of scenario "S" shows the heading "ATTACK COMPLEXITY (RULE V3):"."""
    match = re.search(
        r'the Actor Profile tab of scenario "([^"]+)" shows the heading "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse complexity-heading assertion: {text}"
    sid, heading = match.groups()
    return _resolve(heading in _card_region(_html(world), sid), f"heading={heading}")


def _h_ts_complexity_levels(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the attack complexity block shows "Candidate lower bound" as "L" and "Final required level" as "F"."""
    match = re.search(
        r'the attack complexity block shows "Candidate lower bound" as '
        r'"([^"]+)" and "Final required level" as "([^"]+)"',
        text,
    )
    if not match:
        return False, f"Could not parse complexity-levels assertion: {text}"
    lower, final = match.groups()
    region = _section_region(_html(world), "sec-scenarios")
    visible = _visible(region)
    ok = f"Candidate lower bound: {lower}" in visible
    ok = ok and f"Final required level: {final}" in visible
    return _resolve(ok, f"lower={lower} final={final}")


def _h_ts_complexity_reason(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the attack complexity block shows the reason line "R"."""
    match = re.search(
        r'the attack complexity block shows the reason line "([^"]+)"', text
    )
    if not match:
        return False, f"Could not parse complexity-reason assertion: {text}"
    region = _section_region(_html(world), "sec-scenarios")
    return _resolve(match.group(1) in _visible(region), f"reason={match.group(1)!r}")


def _h_ts_no_attack_complexity(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    """Handle: the Actor Profile tab of scenario "S" shows no attack complexity block."""
    match = re.search(
        r'the Actor Profile tab of scenario "([^"]+)" shows no attack complexity block',
        text,
    )
    if not match:
        return False, f"Could not parse no-complexity assertion: {text}"
    return _resolve(
        "ATTACK COMPLEXITY" not in _card_region(_html(world), match.group(1)),
        "attack complexity block rendered unexpectedly",
    )


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


def register(api: Any) -> None:
    # --- Raw panels / tabs / pipeline Then steps ---
    api.register(
        'the YAML panel shows a highlighted comment, key "([^"]+)", number value \\d+, boolean value .*, and null value',
        _h_ts_yaml_panel,
        source_order=8058,
    )
    api.register(
        'the YAML panel renders the quoted string "([^"]+)" without a highlight class',
        _h_ts_yaml_quoted,
        source_order=8059,
    )
    api.register(
        'the Gherkin panel shows a highlighted comment, tag "([^"]+)", and the keywords "([^"]+)" and "([^"]+)"',
        _h_ts_gherkin_panel,
        source_order=8060,
    )
    api.register(
        'the Generation Inputs tab of scenario "([^"]+)" shows the call headers "([^"]+)" and "([^"]+)"',
        _h_ts_gen_inputs_headers,
        source_order=8061,
    )
    api.register(
        'the Generation Inputs tab shows the row "([^"]+)" with the value "([^"]+)"',
        _h_ts_gen_inputs_row,
        source_order=8062,
    )
    api.register(
        'the Generation Inputs tab shows the row "([^"]+)" with the em dash "([^"]+)"',
        _h_ts_gen_inputs_em_dash,
        source_order=8063,
    )
    api.register(
        'the Behavior Spec tab of scenario "([^"]+)" shows the step keywords "Given", "When", and "Then" with the texts "([^"]+)", "([^"]+)", and "([^"]+)"',
        _h_ts_behavior_spec_steps,
        source_order=8064,
    )
    api.register(
        'the Behavior Spec tab of scenario "([^"]+)" shows the message "([^"]+)"',
        _h_ts_behavior_spec_absent,
        source_order=8065,
    )
    api.register(
        'the ATLAS Techniques tab of scenario "([^"]+)" shows the heading "Scenario classifications" with the badge "([^"]+)"',
        _h_ts_atlas_classifications,
        source_order=8066,
    )
    api.register(
        'the ATLAS Techniques tab shows the heading "([^"]+)" with the placeholder "([^"]+)"',
        _h_ts_atlas_none,
        source_order=8067,
    )
    api.register(
        'the Actor Profile tab of scenario "([^"]+)" shows the heading "([^"]+)"',
        _h_ts_complexity_heading,
        source_order=8068,
    )
    api.register(
        'the attack complexity block shows "Candidate lower bound" as "([^"]+)" and "Final required level" as "([^"]+)"',
        _h_ts_complexity_levels,
        source_order=8069,
    )
    api.register(
        'the attack complexity block shows the reason line "([^"]+)"',
        _h_ts_complexity_reason,
        source_order=8070,
    )
    api.register(
        'the Actor Profile tab of scenario "([^"]+)" shows no attack complexity block',
        _h_ts_no_attack_complexity,
        source_order=8071,
    )
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


__all__ = ["FEATURE_ID", "register"]
