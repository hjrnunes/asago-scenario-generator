"""Goal-narrative, gate-logic, and seed-fidelity checks."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from asago_scenario_generator.models.attack_tree import AttackTreeNode, GateType
from asago_scenario_generator.pipeline.validation_common import _semantic_gherkin_text

if TYPE_CHECKING:
    from asago_scenario_generator.models.scenario import ScenarioEnvelope

logger = logging.getLogger(__name__)

# Goal-narrative alignment validation (gmtc — Part C)
# ---------------------------------------------------------------------------

# Expected narrative keywords per goal sub-goal ID.  If a narrative contains
# zero keywords for its assigned goal, we flag a warning.  This is a heuristic
# signal, not a hard rejection.
_GOAL_NARRATIVE_KEYWORDS: dict[str, list[str]] = {
    # Availability
    "AV-1": ["denial", "unavailable", "service disruption", "outage", "downtime"],
    "AV-2": ["inhibit", "degrade capability", "disable", "impair"],
    "AV-3": ["performance", "slow", "latency", "degrade", "throughput"],
    "AV-4": ["alert", "saturation", "flood", "overwhelm", "fatigue"],
    "AV-5": ["cascading", "chain failure", "propagat", "domino"],
    # Integrity
    "IN-1": [
        "manipulat",
        "output corruption",
        "misleading",
        "incorrect output",
        "alter",
    ],
    "IN-2": ["disinformation", "misinformation", "false information", "propagat"],
    "IN-3": ["decision", "corrupt", "judgment", "misguide", "wrong choice"],
    "IN-4": ["goal manipulation", "intent", "redirect", "subvert purpose"],
    "IN-5": ["memory", "state poison", "persistent", "corrupt state", "taint"],
    "IN-6": ["trust", "relationship", "exploit trust", "trust abuse"],
    "IN-7": ["supply chain", "upstream", "dependency", "third-party", "vendor"],
    # Privacy
    "PR-1": ["exfiltrat", "leak", "data theft", "extract data", "expose data"],
    "PR-2": ["system prompt", "intellectual property", "prompt theft", "IP theft"],
    "PR-3": ["model extract", "model steal", "replicate model", "clone model"],
    "PR-4": ["inference", "membership", "property inference", "fingerprint"],
    "PR-5": ["cross-session", "session leak", "data leakage", "bleed"],
    "PR-6": ["credential", "identity theft", "steal identity", "authentication"],
    # Abuse
    "AB-1": [
        "jailbreak",
        "safety bypass",
        "guardrail",
        "restricted content",
        "content filter",
    ],
    "AB-2": ["malware", "malicious code", "code generation", "virus", "exploit code"],
    "AB-3": ["fraud", "financial", "unauthorized transaction", "scam", "fraudulent"],
    "AB-4": ["social engineer", "phishing", "deception", "impersonat", "lure"],
    "AB-5": ["human manipulation", "manipulat", "deceive", "psychological"],
    "AB-6": ["privilege", "escalat", "elevated access", "admin", "unauthorized access"],
    "AB-7": ["impersonat", "identity abuse", "spoof", "pose as", "pretend"],
    "AB-8": ["evidence", "anti-forensic", "destroy", "erase", "cover tracks"],
    "AB-9": [
        "resource hijack",
        "cost amplif",
        "compute abuse",
        "crypto",
        "resource consumption",
    ],
}


def check_goal_narrative_alignment(
    goal_id: str | None,
    narrative_text: str,
) -> str | None:
    """Check whether narrative text contains expected keywords for the goal.

    Args:
        goal_id: The assigned goal sub-goal ID (e.g. 'AB-4'), or None.
        narrative_text: Combined narrative text to check (title + summary + steps).

    Returns:
        A warning message if zero expected keywords are found, else None.
    """
    if not goal_id or goal_id not in _GOAL_NARRATIVE_KEYWORDS:
        return None

    keywords = _GOAL_NARRATIVE_KEYWORDS[goal_id]
    text_lower = narrative_text.lower()

    for kw in keywords:
        if kw.lower() in text_lower:
            return None

    return (
        f"Goal-narrative alignment warning: goal {goal_id} assigned but "
        f"narrative contains none of the expected keywords "
        f"{keywords!r}. The narrative may not reflect the assigned goal."
    )


# ---------------------------------------------------------------------------
# Seed mechanism fidelity check (gmtc — Part D)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Gate-logic consistency validation (var8)
# ---------------------------------------------------------------------------


def _has_or_gates(node: AttackTreeNode) -> bool:
    """Check whether an attack tree contains any OR gates."""
    if node.gate == GateType.OR:
        return True
    if node.children:
        return any(_has_or_gates(child) for child in node.children)
    return False


def _count_or_gates(node: AttackTreeNode) -> int:
    """Count OR gates in an attack tree."""
    count = 1 if node.gate == GateType.OR else 0
    if node.children:
        for child in node.children:
            count += _count_or_gates(child)
    return count


@dataclass
class GateLogicViolation:
    """OR-gate in tree but Gherkin lacks multiple Scenario blocks."""

    scenario_id: str
    or_gate_count: int
    gherkin_scenario_count: int
    reason: str


@dataclass
class GateLogicResult:
    """Result of gate-logic consistency validation across a batch."""

    clean_scenarios: list[ScenarioEnvelope] = field(default_factory=list)
    flagged_scenarios: list[tuple[ScenarioEnvelope, GateLogicViolation]] = field(
        default_factory=list
    )

    @property
    def flagged_count(self) -> int:
        return len(self.flagged_scenarios)

    @property
    def clean_count(self) -> int:
        return len(self.clean_scenarios)


# Regex to count Scenario: blocks in Gherkin text.
_GHERKIN_SCENARIO_RE = re.compile(r"^\s*Scenario:", re.MULTILINE)


def _gate_logic_violation(
    scenario: ScenarioEnvelope,
    or_gate_count: int,
    scenario_block_count: int,
) -> GateLogicViolation:
    """OR-gate/Gherkin scenario-count mismatch violation record."""
    return GateLogicViolation(
        scenario_id=scenario.scenario_id,
        or_gate_count=or_gate_count,
        gherkin_scenario_count=scenario_block_count,
        reason=(
            f"Attack tree has {or_gate_count} OR gate(s) but Gherkin "
            f"contains only {scenario_block_count} Scenario block(s). "
            f"OR branches should produce multiple Scenario blocks "
            f"(one per alternative path)."
        ),
    )


def validate_gate_logic_consistency(
    scenarios: list[ScenarioEnvelope],
) -> GateLogicResult:
    """Check that OR gates in attack trees are reflected as multiple Gherkin scenarios.

    Backstop validator: if the attack tree has OR gates, the Gherkin
    behavior_spec should contain multiple ``Scenario:`` blocks (one per
    alternative path).  A single ``Scenario:`` block in the presence of
    OR gates indicates a semantic inversion -- the Gherkin treats all
    OR-branch children as sequential steps (AND semantics) when the tree
    says ANY ONE path suffices.

    With the deterministic skeleton builder fixed to handle OR gates, new
    scenarios will always pass this check.  This validator catches
    regressions and legacy scenarios generated before the fix.

    Scenarios are never removed -- violations are recorded as warnings.
    """
    result = GateLogicResult()

    for scenario in scenarios:
        checked = _gate_logic_gherkin(scenario)
        if checked is None:
            result.clean_scenarios.append(scenario)
            continue

        gherkin, or_gate_count = checked
        scenario_block_count = len(_GHERKIN_SCENARIO_RE.findall(gherkin))

        if scenario_block_count <= 1:
            violation = _gate_logic_violation(
                scenario, or_gate_count, scenario_block_count
            )
            logger.warning(
                "Gate-logic consistency: %s has %d OR gate(s) but "
                "Gherkin has %d Scenario block(s)",
                scenario.scenario_id,
                or_gate_count,
                scenario_block_count,
            )
            result.flagged_scenarios.append((scenario, violation))
        else:
            result.clean_scenarios.append(scenario)

    return result


def _gate_logic_gherkin(
    scenario: ScenarioEnvelope,
) -> tuple[str, int] | None:
    """Gherkin text and OR-gate count when the scenario needs checking."""
    if not scenario.attack_tree or not scenario.attack_tree.root:
        return None
    or_gate_count = _count_or_gates(scenario.attack_tree.root)
    if or_gate_count == 0:
        return None
    gherkin = _semantic_gherkin_text(scenario)
    if not gherkin:
        return None
    return gherkin, or_gate_count


def _extract_mechanism_keywords(attack_pattern_name: str) -> list[str]:
    """Extract meaningful mechanism keywords from an attack pattern name.

    Splits on whitespace/punctuation and filters out stop words to produce
    keywords that characterise the seed's core mechanism.

    Args:
        attack_pattern_name: e.g. 'Identity Spoofing via Credential Theft'

    Returns:
        List of lowercase mechanism keywords (e.g. ['identity', 'spoofing',
        'credential', 'theft']).
    """
    _STOP_WORDS = frozenset(
        {
            "a",
            "an",
            "and",
            "at",
            "by",
            "for",
            "from",
            "in",
            "into",
            "of",
            "on",
            "or",
            "the",
            "to",
            "via",
            "with",
            "through",
            "using",
            "based",
            "attack",
            "against",
        }
    )

    # Split on non-alphanumeric characters
    tokens = re.split(r"[^a-zA-Z0-9]+", attack_pattern_name.lower())
    return [t for t in tokens if t and t not in _STOP_WORDS and len(t) > 2]


def check_seed_mechanism_fidelity(
    attack_pattern_name: str,
    narrative_text: str,
) -> str | None:
    """Check whether the narrative references the seed's core mechanism.

    Extracts mechanism keywords from the attack_pattern_name and checks
    whether at least one appears in the narrative text.  If none are found,
    returns a warning about potential attack pattern abandonment.

    Args:
        attack_pattern_name: The seed's attack_pattern_name field.
        narrative_text: Combined narrative text (title + summary + steps).

    Returns:
        A warning message if no mechanism keywords found, else None.
    """
    if not attack_pattern_name or not isinstance(attack_pattern_name, str):
        return None

    keywords = _extract_mechanism_keywords(attack_pattern_name)
    if not keywords:
        return None

    text_lower = narrative_text.lower()

    for kw in keywords:
        if kw in text_lower:
            return None

    return (
        f"Seed mechanism fidelity warning: attack pattern "
        f"'{attack_pattern_name}' keywords {keywords!r} not found in "
        f"narrative. Potential attack pattern abandonment."
    )
