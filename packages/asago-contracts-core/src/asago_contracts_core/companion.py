"""The Gherkin companion rule: a feature file holds the handoff's Gherkin block.

A handoff's ``gherkin`` block and its ``.feature`` companion are a writer-to-reader
pair. The block's feature line comes first, the scenario line appears once, the
``given``, ``when`` and ``then_expected`` steps follow in order, and each unsafe
alternative appears as one comment. The producer writes the text with
:func:`render_feature_text`; this module also reads it back.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .violation import Violation

#: The prefixes a line of the rendered text may start with and carry no step.
_STEPLESS_PREFIXES = ("Feature:", "Background:", "Scenario:", "#")


def render_feature_text(gherkin: Mapping[str, Any]) -> str:
    """Render the declarative Gherkin block, as the producer's writer does."""

    lines = [f"Feature: {gherkin['feature']}"]
    given = gherkin.get("given", ())
    if given:
        lines.append("  Background:")
        lines.extend(f"    {step}" for step in given)
    lines.append(f"  Scenario: {gherkin['scenario']}")
    lines.extend(
        f"    {step}"
        for step in [*gherkin.get("when", ()), *gherkin.get("then_expected", ())]
    )
    lines.extend(
        f"    # Unsafe alternative (non-executable): {step}"
        for step in gherkin.get("then_unsafe_alternative", ())
    )
    return "\n".join(lines) + "\n"


def feature_violations(gherkin: Mapping[str, Any], text: str) -> list[Violation]:
    """Report each rule a feature file breaks, or nothing when it holds the block."""

    lines = [stripped for line in text.splitlines() if (stripped := line.strip())]
    found: list[Violation] = []
    for rule in (_feature_rule, _scenario_rule, _steps_rule, _comments_rule):
        violation = rule(gherkin, lines)
        if violation is not None:
            found.append(violation)
    return found


def _feature_rule(gherkin: Mapping[str, Any], lines: list[str]) -> Violation | None:
    expected = f"Feature: {gherkin['feature']}"
    if lines[:1] == [expected]:
        return None
    return Violation(
        "feature_companion:feature_line",
        "gherkin.feature",
        f"Feature line: the first line is not '{expected}'",
    )


def _scenario_rule(gherkin: Mapping[str, Any], lines: list[str]) -> Violation | None:
    expected = f"Scenario: {gherkin['scenario']}"
    if expected in lines:
        return None
    return Violation(
        "feature_companion:scenario_line",
        "gherkin.scenario",
        f"Scenario line: no line reads '{expected}'",
    )


def _steps_rule(gherkin: Mapping[str, Any], lines: list[str]) -> Violation | None:
    steps = [line for line in lines if not line.startswith(_STEPLESS_PREFIXES)]
    expected = [
        step
        for key in ("given", "when", "then_expected")
        for step in gherkin.get(key, ())
    ]
    if steps == expected:
        return None
    return Violation(
        "feature_companion:steps",
        "gherkin",
        "steps: they differ from given, when and then_expected in order",
    )


def _comments_rule(gherkin: Mapping[str, Any], lines: list[str]) -> Violation | None:
    comments = sum(line.startswith("#") for line in lines)
    expected = len(gherkin.get("then_unsafe_alternative", ()))
    if comments == expected:
        return None
    return Violation(
        "feature_companion:comments",
        "gherkin.then_unsafe_alternative",
        f"comment count: {comments} comments, then_unsafe_alternative holds {expected}",
    )


__all__ = ["feature_violations", "render_feature_text"]
