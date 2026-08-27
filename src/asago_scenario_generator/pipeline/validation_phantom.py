"""Phantom-capability and typed-tool validation passes."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from asago_scenario_generator.models.attack_tree import AttackTreeNode
from asago_scenario_generator.models.scenario import (
    PhantomValidation,
    PhantomViolationRecord,
    ValidationBlock,
)
from asago_scenario_generator.pipeline.validation_common import (
    _collect_leaves,
    _collect_node_labels,
    _semantic_gherkin_text,
    _validation_passed,
)

if TYPE_CHECKING:
    from asago_scenario_generator.models.capability_profile import CapabilityProfile
    from asago_scenario_generator.models.scenario import ScenarioEnvelope

logger = logging.getLogger(__name__)

# Valid OWASP Agentic Threat IDs: T1 through T17.
_VALID_THREAT_IDS: frozenset[str] = frozenset(f"T{i}" for i in range(1, 18))


# ---------------------------------------------------------------------------
# Violation data structures
# ---------------------------------------------------------------------------


@dataclass
class PhantomViolation:
    """A single phantom capability violation detected in a scenario step."""

    step_number: int
    field: str  # "action" or "effect"
    category: (
        str  # e.g. "privilege_escalation", "credential_exposure", "code_execution"
    )
    matched_text: str  # the substring that triggered the match
    reason: str  # why this is phantom given the profile


@dataclass
class ValidationResult:
    """Result of phantom capability validation across a batch of scenarios."""

    valid_scenarios: list[ScenarioEnvelope] = field(default_factory=list)
    flagged_scenarios: list[tuple[ScenarioEnvelope, list[PhantomViolation]]] = field(
        default_factory=list
    )

    @property
    def flagged_count(self) -> int:
        return len(self.flagged_scenarios)

    @property
    def valid_count(self) -> int:
        return len(self.valid_scenarios)

    @property
    def violation_categories(self) -> list[str]:
        """Unique violation categories across all flagged scenarios."""
        cats: set[str] = set()
        for _scenario, violations in self.flagged_scenarios:
            for v in violations:
                cats.add(v.category)
        return sorted(cats)


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Privilege escalation: references to tiered privileges, elevated tokens,
# admin access, role escalation that the profile doesn't declare.
_PRIVILEGE_ESCALATION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\belevat(?:e|ed|es|ing)\b[^.]{0,30}\b(?:privil|token|access|role|permission)",
        r"\bprivil(?:ege|eged)\b[^.]{0,30}\b(?:escalat|tier|level|elevat)",
        r"\brole\s+escalat",
        r"\badmin(?:istrat(?:or|ive))?\s+(?:access|token|privil|credential|role)",
        r"\btier(?:ed)?\s+(?:privil|access|permission|token)",
        r"\belevated\s+token",
        r"\bescalat(?:e|ed|es|ing)\b[^.]{0,40}\b(?:privil|role|access|permission)",
        # v17 — escapee variants from QA-v16
        r"\bemergency\s+admin(?:istrat(?:or|ive))?\b",
        r"\badmin(?:istrat(?:or|ive))?\s+debug(?:ging)?\s+mode\b",
        r"\bself[- ](?:permission|elevat|escalat|privilege)",
        r"\bdynamic\s+privilege\b",
    ]
]

# Credential exposure: LLM outputting HTTP headers, auth tokens, API keys,
# credentials being exposed by the system.
_CREDENTIAL_EXPOSURE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\b(?:output|expos|leak|reveal|disclos|return|display|emit|dump|print|render)(?:s|ed|es|ing)?\b[^.]{0,40}\b(?:auth(?:orization)?\s+header|api[- _]?key|credential|secret|bearer\s+token|access[- _]?token)",
        r"\bhttp\s+(?:auth(?:orization)?|header)[^.]{0,30}\b(?:expos|leak|reveal|output|disclos)",
        r"\b(?:auth(?:orization)?\s+header|bearer\s+token)\b[^.]{0,30}\b(?:visible|plain|clear|expos|leak|output)",
        r"\binfrastructure\s+credential",
        # v17 — escapee variant: error messages leaking tokens/credentials
        r"\b(?:error|exception|diagnostic|debug)\s+messages?\b[^.]{0,40}\b(?:session\s+)?(?:token|credential|secret|api[- _]?key)",
    ]
]

# Code execution: generating or executing code (Python scripts, shell
# commands, etc.) when the profile lacks KC6.2.2 or KC6.5.
_CODE_EXECUTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\b(?:generat|creat|writ|execut|run|invok)(?:e|ed|es|ing)?\b[^.]{0,30}\bpython\s+(?:script|code|program)",
        r"\b(?:generat|creat|writ|execut|run|invok)(?:e|ed|es|ing)?\b[^.]{0,30}\bshell\s+(?:script|command|code)",
        r"\bexecut(?:e|ed|es|ing)\b[^.]{0,30}\b(?:arbitrary|malicious|crafted)\s+(?:code|script|command)",
        r"\b(?:run|execut)(?:s|ed|es|ing)?\s+(?:the\s+)?(?:python|bash|shell|powershell)\b",
        r"\bgenerat(?:e|ed|es|ing)\b[^.]{0,30}\b(?:executable|payload|script|code)\b",
        r"\b(?:arbitrary|remote)\s+code\s+execution\b",
        # v17 — escapee variant: execute/distribute malicious payloads
        r"\b(?:execut|distribut|deploy)\w*\b[^.]{0,40}\bmalicious\b[^.]{0,20}\bpayload",
        # v18 — code generation phrasing: noun-phrase generation references
        # Bare "(code|script) + generation noun" — e.g. "script synthesis"
        r"\b(?:code|script)\s+(?:generation|synthesis|assembly)\b",
        # Qualified noun + generation noun — e.g. "exploit code assembly",
        # "Python script generation", "obfuscated script synthesis"
        r"\b(?:exploit|malicious|obfuscated|weaponized|python|bash|shell|automated)\s+(?:code|script)\s+(?:generat|synthes|assembl|creat|construct)\w*",
        # Broader creation verbs + code/script/payload:
        # produce/craft/assemble/synthesize
        r"\b(?:produc|craft|assembl|synthesi[zs])(?:e|ed|es|ing)?\b[^.]{0,30}\b(?:code|script|payload)\b",
        # write/craft + script (without requiring language qualifier)
        r"\b(?:writ|craft)(?:e|ed|es|ing)?\b[^.]{0,30}\bscript\b",
        # produce + exploit
        r"\bproduc(?:e|ed|es|ing)?\b[^.]{0,30}\bexploit\b",
        # Qualified noun phrases implying code artifacts:
        # exploit/malicious/obfuscated/weaponized + code/script
        r"\b(?:exploit|malicious|obfuscated|weaponized)\s+(?:code|script)\b",
        # Language-specific or automated script references
        r"\b(?:python|automated)\s+script\b",
        # v19 — escapee variant: "automation script(s)"
        r"\bautomation\s+scripts?\b",
    ]
]

# Mass broadcasting: references to proactive mass communication, pushing
# notifications to all users, bulk messaging — phantom when the system is
# reactive (single-session, no persistent memory, no multi-agent).
_MASS_BROADCASTING_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bbroadcast\b",
        r"\bproactively\s+reach\s+out\b",
        r"\bpush\s+to\s+all\s+(?:users|customers|clients|accounts)\b",
        r"\bmass\s+(?:notification|message|communication|email)\b",
        r"\bsend\s+to\s+thousands\b",
        r"\bbulk\s+messag(?:e|es|ing)\b",
        r"\bnotify\s+all\s+(?:customers|users|clients|accounts)\b",
        r"\bsend\s+(?:alerts?|messages?|notifications?)\s+to\s+(?:all|every)\b",
        # v17 — escapee variants: mass phishing / mass distribution
        r"\bmass\s+phishing\b",
        r"\bmass\b[^.]{0,30}\bdistribut(?:e|ed|es|ing|ion)\b",
    ]
]

# Cross-session / cross-user access: references to accessing data or sessions
# belonging to other users — phantom when the system operates within a single
# authenticated session with no persistent memory.
_CROSS_SESSION_ACCESS_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bother\s+user(?:'?s?)?\b",
        r"\bdifferent\s+account\b",
        r"\bcross[- ]user\b",
        r"\banother\s+customer(?:'?s?)?\b",
        r"\btarget\s+victim\b",
        r"\baccess\b[^.]{0,30}\bother\b[^.]{0,30}\bsession",
        r"\bprocess\b[^.]{0,30}\bunauthorized\b[^.]{0,30}\buser",
        r"\bwrite\b[^.]{0,30}\bas\b[^.]{0,30}\bexternal\b",
        r"\baccess\b[^.]{0,30}\bother\b[^.]{0,30}\b(?:user|customer|account)",
        # v17 — escapee variant: across multiple sessions
        r"\bacross\b[^.]{0,30}\bsessions\b",
        # v19 — escapee variant: third-party user references
        r"\bthird[- ]party\s+(?:user|customer|account)(?:'?s?)?\b",
    ]
]

# Audit / monitoring write access: references to modifying audit trails,
# tampering with logs, suppressing alerts — almost always phantom since
# agents read from monitoring but don't write to it.
_AUDIT_MONITORING_WRITE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bmodify\s+audit\s+trail\b",
        r"\balter\s+(?:the\s+)?logs?\b",
        r"\btamper\b[^.]{0,30}\blogging\b",
        r"\bwrite\s+to\s+monitoring\b",
        r"\bcontrol\b[^.]{0,30}\baudit\b",
        r"\bmanipulat(?:e|ed|es|ing)\b[^.]{0,30}\blog\s+entr(?:y|ies)\b",
        r"\bsuppress\b[^.]{0,30}\balerts?\b",
        r"\bdisable\b[^.]{0,30}\bmonitoring\b",
        r"\berase\b[^.]{0,30}\b(?:audit|log)\b",
        r"\btamper\b[^.]{0,30}\baudit\b",
        r"\bmodify\b[^.]{0,30}\b(?:audit|log)\s+(?:record|entr|data)\b",
        # v17 — escapee variants from QA-v16
        r"\b(?:session|chat|conversation)\s+history\s+(?:reset|clear|delet|wip|purg)",
        r"\b(?:reset|clear|delet|wip|purg)\w*\b[^.]{0,20}\b(?:session|chat)\s+history\b",
        r"\b(?:generat|creat|fabricat)(?:e|ed|es|ing)?\b[^.\n]{0,30}\b(?:deceptive|false|fake|fraudulent|misleading)\s+(?:\w+\s+){0,2}(?:report|record|alert)",
        r"\btransaction\s+(?:description|record|detail|log)\s+(?:modif|alter|chang|edit|tamper)",
        r"\b(?:modif|alter|chang|tamper)\w*\b[^.]{0,20}\btransaction\s+(?:description|record|detail|log)",
        r"\boverwrite\b[^.]{0,20}\b(?:audit|log|session\s+history)\b",
        # v19 — escapee variant: overwrite with wider gap for transaction logs
        r"\boverwrite\b[^.]{0,50}\btransaction\s+logs?\b",
        r"\bpurg(?:e|ed|es|ing)\b[^.]{0,30}\b(?:sensitive\s+)?logs?\b",
    ]
]

# Session introspection: references to the agent accessing or extracting
# its own session tokens, API authorization headers, bearer tokens, or other
# infrastructure credentials — phantom because agents don't have access to
# their own authentication layer.  The platform handles auth transparently.
_SESSION_INTROSPECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bAPI\s+auth(?:orization|entication)\s+headers?\b",
        r"\bsession\s+(?:identity\s+)?tokens?\b",
        r"\bbearer\s+tokens?\b",
        r"\bidentity\s+tokens?\b",
        r"\bauth(?:entication)?\s+tokens?\b",
        r"\bsession\s+credentials?\b",
        r"\bsession\s+metadata\b",
        r"\bsession[- ]specific\s+(?:metadata|identifiers?)\b",
        r"\bauthenticat(?:ed|ion)\s+identifiers?\b",
    ]
]

# API response fabrication: scenarios assume backend APIs return data types
# not described in the profile — system metadata, prompt fragments,
# model configuration, internal system information.  The phantom tool
# invocation checker validates API *name* existence but not *return data*;
# this pattern catches fabricated return payloads.
_API_RESPONSE_FABRICATION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bsystem\s+metadata\b",
        r"\bsystem[- ]level\s+metadata\b",
        r"\binternal\s+system\s+information\b",
        r"\bprompt\s+fragments?\b",
        r"\bsystem\s+prompt\s+(?:content|text|fragment|data|detail)\b",
        r"\bmodel\s+configuration\b",
        r"\bmodel\s+weights?\b",
        r"\btraining\s+data\b",
        r"\bmodel\s+parameters?\b[^.]{0,30}\b(?:expos|leak|extract|access|retriev|obtain|return)",
        r"\b(?:expos|leak|extract|access|retriev|obtain|return)\w*\b[^.]{0,30}\bmodel\s+parameters?\b",
        r"\binternal\s+(?:configuration|state|architecture)\s+(?:data|detail|information)\b",
        r"\b(?:retriev|extract|obtain|access|return|expos|leak|disclos)\w*\b[^.]{0,30}\bsystem\s+(?:internals?|metadata)\b",
        r"\b(?:retriev|extract|obtain|access|return|expos|leak|disclos)\w*\b[^.]{0,30}\bprompt\s+(?:template|fragment|content)\b",
        r"\binfrastructure\s+(?:metadata|configuration|detail)\b",
        r"\braw\s+(?:system|model|infrastructure)\s+(?:data|state|configuration)\b",
    ]
]

# System prompt retrieval via API: scenarios assume the agent can retrieve
# its own system prompt or system configuration through API/tool calls.
# This is ALWAYS phantom — agents never have access to their own system
# prompt through tool execution.  The platform injects system prompts
# into the context opaquely; no API or tool endpoint exposes them.
_SYSTEM_PROMPT_RETRIEVAL_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        # "<type> API" used for system prompt / configuration retrieval
        r"\b(?:configuration|config|settings|admin)\s+API\b[^.]{0,40}\b(?:system\s+prompt|system\s+instruction|internal\s+instruction)",
        r"\b(?:system\s+prompt|system\s+instruction|internal\s+instruction)\b[^.]{0,40}\b(?:configuration|config|settings|admin)\s+API\b",
        # Diagnostic / introspection API or endpoint
        r"\bdiagnostic\s+(?:API|endpoint)\b",
        r"\bintrospection\s+(?:API|endpoint)\b",
        # Configuration / settings endpoint for prompt/instruction access
        r"\b(?:configuration|config|settings)\s+endpoint\b[^.]{0,40}\b(?:prompt|instruction)",
        r"\b(?:prompt|instruction)\b[^.]{0,40}\b(?:configuration|config|settings)\s+endpoint\b",
        # Direct system prompt retrieval / dump / extraction phrasing
        r"\b(?:retriev|dump|extract|access|obtain|fetch|read|quer[yi])\w*\b[^.]{0,30}\bsystem\s+prompt\b",
        r"\bsystem\s+prompt\s+(?:retriev|dump|extract)\w*\b",
        # Internal / system instructions via API
        r"\b(?:retriev|dump|extract|access|obtain|fetch|read|quer[yi])\w*\b[^.]{0,30}\b(?:internal|system)\s+instructions?\b",
        r"\b(?:internal|system)\s+instructions?\b[^.]{0,30}\bvia\s+(?:API|endpoint|tool)\b",
        # Diagnostic retrieval / configuration retrieval APIs (generic)
        r"\bdiagnostic\b[^.]{0,30}\bretrieval\b",
        r"\bconfiguration\s+retrieval\b[^.]{0,30}\b(?:API|endpoint)\b",
        # Identity management / auth token manipulation endpoints
        r"\bidentity\s+management\s+(?:API|endpoint)\b",
        r"\bauth(?:entication)?\s+token\s+manipulation\s+(?:API|endpoint)\b",
    ]
]


# Attacker-context heuristic: words that indicate the surrounding text
# describes attacker-side behavior rather than system capabilities.
# Used by _check_code_execution for tree_label/gherkin fields (dv72).
_ATTACKER_CONTEXT_RE = re.compile(
    r"\b(?:attacker|actor|adversary|threat\s+agent|red\s+team)\b",
    re.IGNORECASE,
)

# Gherkin step keywords that indicate attacker actions (Given/When/And).
# Then/But/* lines describe system outcomes and should still be checked.
_GHERKIN_ATTACKER_STEP_RE = re.compile(
    r"^\s*(?:Given|When|And)\b",
    re.IGNORECASE,
)
_GHERKIN_OUTCOME_STEP_RE = re.compile(
    r"^\s*(?:Then\b|But\b|\*)",
    re.IGNORECASE,
)


def _extract_gherkin_outcome_lines(gherkin_text: str) -> str:
    """Extract only Then/But/* lines from Gherkin text for checking.

    Given/When/And lines describe attacker actions and are excluded.
    Returns the concatenated outcome lines, or empty string if none.
    """
    outcome_lines: list[str] = []
    for line in gherkin_text.splitlines():
        if _GHERKIN_OUTCOME_STEP_RE.match(line):
            outcome_lines.append(line)
    return "\n".join(outcome_lines)


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------


def _first_pattern_match(patterns: list[re.Pattern[str]], text: str) -> str | None:
    """Return the first pattern match string, if any."""
    for pattern in patterns:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def _profile_has_admin_capability(profile: CapabilityProfile) -> bool:
    """True when the profile declares admin/role-management capability."""
    admin_entry = any(
        "admin" in ep.name.lower() or "role" in ep.name.lower()
        for ep in profile.entry_points
    )
    admin_kc = any(code.startswith(("KC6.4", "KC6.3")) for code in profile.kc_subcodes)
    return admin_entry or admin_kc


def _check_privilege_escalation(
    text: str,
    profile: CapabilityProfile,
    field_name: str = "",
    zone: str = "",
) -> str | None:
    """Return a match string if text references phantom privilege escalation.

    Privilege escalation is phantom when the profile's kc_subcodes and
    entry_points don't include any admin/role-management capabilities.
    """
    # If the profile explicitly declares admin-level entry points or
    # relevant KC subcodes, privilege references are legitimate.
    # KC6.4 = identity / auth management; KC6.3 = database (may include role tables)
    if _profile_has_admin_capability(profile):
        return None

    return _first_pattern_match(_PRIVILEGE_ESCALATION_PATTERNS, text)


def _profile_has_credential_capability(profile: CapabilityProfile) -> bool:
    """True when the profile declares raw HTTP credential handling."""
    api_kc = any(
        code.startswith(("KC6.1.2", "KC6.1.3")) for code in profile.kc_subcodes
    )
    api_entry = any(
        "api" in ep.name.lower() or "http" in ep.name.lower()
        for ep in profile.entry_points
    )
    return api_kc or api_entry


def _check_credential_exposure(
    text: str,
    profile: CapabilityProfile,
    field_name: str = "",
    zone: str = "",
) -> str | None:
    """Return a match string if text references phantom credential exposure.

    Credential exposure is phantom when the profile doesn't include
    capabilities that handle raw HTTP credentials (KC6.1.2 = extensive
    API access with auth details, or entry points mentioning API/HTTP).
    """
    # If profile declares extensive API access that handles auth, or
    # entry points involving APIs/HTTP, credential references may be legit.
    if _profile_has_credential_capability(profile):
        return None

    return _first_pattern_match(_CREDENTIAL_EXPOSURE_PATTERNS, text)


def _profile_has_code_execution(profile: CapabilityProfile) -> bool:
    """True when the profile declares code-execution capability."""
    return any(code.startswith(("KC6.2.2", "KC6.5")) for code in profile.kc_subcodes)


def _code_execution_field_skipped(field_name: str, zone: str) -> bool:
    """True when the field describes attacker-side behavior by definition."""
    if field_name == "action":
        return True
    if field_name == "tree_label" and zone == "input":
        return True
    return False


def _checked_code_execution_text(text: str, field_name: str) -> str:
    """Gherkin outcome lines only; Given/When/And describe attacker actions."""
    if field_name == "gherkin":
        text = _extract_gherkin_outcome_lines(text)
    return text


def _attacker_context_match(text: str, match: re.Match[str]) -> bool:
    """True when a tree/gherkin match is preceded by attacker-referencing words."""
    start = max(0, match.start() - 20)
    preceding = text[start : match.start()].lower()
    return bool(_ATTACKER_CONTEXT_RE.search(preceding))


def _check_code_execution(
    text: str,
    profile: CapabilityProfile,
    field_name: str = "",
    zone: str = "",
) -> str | None:
    """Return a match string if text references phantom code execution.

    Code execution is phantom when the profile's kc_subcodes don't include
    KC6.2.2 (extensive code execution) or KC6.5 (PC/filesystem operations).

    Field-awareness (dv72):
    - ``action`` fields describe attacker-side behavior (crafting payloads,
      writing scripts) — code references there are expected, not phantom.
    - ``tree_label`` and ``gherkin`` fields lack an action/effect split;
      matches preceded within 20 chars by attacker-referencing words
      (attacker, actor, adversary, threat agent, red team) are skipped
      as a heuristic to avoid false positives.

    Zone-awareness (lgws):
    - ``tree_label`` in ``input`` zone describes attacker injection by
      definition — code references there are expected, not phantom.

    Gherkin step-type awareness (3mal):
    - When ``field_name="gherkin"``, only Then/But/\\* lines (system
      outcome assertions) are checked.  Given/When/And lines describe
      attacker actions and are skipped.
    """
    # Action fields describe what the ATTACKER does — code references
    # there are expected behavior, not a phantom system capability.
    # Input-zone tree labels describe attacker injection — code references
    # describe attacker tooling, not system capabilities.
    if _code_execution_field_skipped(field_name, zone):
        return None

    if _profile_has_code_execution(profile):
        return None

    # For Gherkin, only check Then/But/* lines (system outcome assertions).
    # Given/When/And lines describe attacker actions (3mal).
    text = _checked_code_execution_text(text, field_name)
    if not text:
        return None

    return _code_execution_match(text, field_name)


def _code_execution_match(text: str, field_name: str) -> str | None:
    """First code-execution pattern match not attributed to attacker context."""
    for pattern in _CODE_EXECUTION_PATTERNS:
        m = pattern.search(text)
        if m and not (
            field_name in ("tree_label", "gherkin") and _attacker_context_match(text, m)
        ):
            return m.group(0)
    return None


def _check_mass_broadcasting(
    text: str,
    profile: CapabilityProfile,
    field_name: str = "",
    zone: str = "",
) -> str | None:
    """Return a match string if text references phantom mass broadcasting.

    Mass broadcasting is phantom when the system is reactive (single-session,
    no persistent memory, no multi-agent coordination).  A system that lacks
    both persistent memory and multi-agent capabilities operates within
    individual user sessions and cannot proactively push to many users.
    """
    # If the profile declares persistent memory or multi-agent, the system
    # may have infrastructure for mass communication.
    if profile.has_persistent_memory or profile.multi_agent:
        return None

    for pattern in _MASS_BROADCASTING_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def _check_cross_session_access(
    text: str,
    profile: CapabilityProfile,
    field_name: str = "",
    zone: str = "",
) -> str | None:
    """Return a match string if text references phantom cross-session access.

    Cross-session/cross-user access is phantom when the system operates
    within a single authenticated session.  The primary indicator is
    has_persistent_memory=False — without persistent state the system
    cannot reach across sessions or users.
    """
    if profile.has_persistent_memory:
        return None

    for pattern in _CROSS_SESSION_ACCESS_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def _check_session_introspection(
    text: str,
    profile: CapabilityProfile,
    field_name: str = "",
    zone: str = "",
) -> str | None:
    """Return a match string if text references phantom session introspection.

    Session introspection is ALWAYS phantom — agents never have access to
    their own session tokens, API authorization headers, or bearer tokens.
    The platform handles authentication transparently; even systems with
    KC6.1.2 (extensive API access) or API entry points use opaque
    credentials managed by the infrastructure, not by the LLM itself.

    Previously this check was suppressed when KC6.1.2 / KC6.1.3 was
    present or an entry point contained "api", conflating "the system
    calls APIs" with "the LLM can access auth tokens."  That suppression
    was removed — the check now always fires (el87).
    """
    for pattern in _SESSION_INTROSPECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def _check_audit_monitoring_write(
    text: str,
    profile: CapabilityProfile,
    field_name: str = "",
    zone: str = "",
) -> str | None:
    """Return a match string if text references phantom audit/monitoring writes.

    Audit/monitoring write access is almost always phantom — agents read
    from monitoring systems but do not have write access to audit trails.
    No KC subcode in the current taxonomy grants audit-write capability,
    so this check always fires regardless of profile.
    """
    # No profile-based suppression — audit-write is always phantom in the
    # current KC taxonomy.  If a future KC subcode is added for audit-write,
    # add suppression logic here.

    for pattern in _AUDIT_MONITORING_WRITE_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def _check_api_response_fabrication(
    text: str,
    profile: CapabilityProfile,
    field_name: str = "",
    zone: str = "",
) -> str | None:
    """Return a match string if text assumes APIs return fabricated data types.

    Scenarios sometimes assume that backend APIs return data types not
    described in the profile — system metadata, prompt fragments, model
    configuration, internal system information.  The phantom tool
    invocation checker validates API *name* existence but not *return
    data*; this check catches fabricated return payloads.

    Always fires regardless of profile — no KC subcode grants access to
    system internals via normal API responses.
    """
    for pattern in _API_RESPONSE_FABRICATION_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def _check_system_prompt_retrieval(
    text: str,
    profile: CapabilityProfile,
    field_name: str = "",
    zone: str = "",
) -> str | None:
    """Return a match string if text assumes the agent can retrieve its system prompt.

    System prompt retrieval via API/tool calls is ALWAYS phantom — agents
    never have access to their own system prompt through tool execution.
    The platform injects system prompts into the LLM context opaquely;
    no configuration API, diagnostic endpoint, or introspection tool
    exposes them.

    Always fires regardless of profile — no KC subcode grants access to
    system prompts via API.
    """
    for pattern in _SYSTEM_PROMPT_RETRIEVAL_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


# ---------------------------------------------------------------------------
# Main validation function
# ---------------------------------------------------------------------------

_CHECKERS = [
    (
        "privilege_escalation",
        _check_privilege_escalation,
        (
            "Profile lacks admin entry points and KC6.3/KC6.4 subcodes — "
            "dynamic privilege escalation is a phantom capability."
        ),
    ),
    (
        "credential_exposure",
        _check_credential_exposure,
        (
            "Profile lacks KC6.1.2/KC6.1.3 (extensive API access) and no "
            "API/HTTP entry points — infrastructure credential exposure "
            "is a phantom capability."
        ),
    ),
    (
        "code_execution",
        _check_code_execution,
        (
            "Profile lacks KC6.2.2 (code execution) and KC6.5 (filesystem) "
            "— arbitrary code execution is a phantom capability."
        ),
    ),
    (
        "mass_broadcasting",
        _check_mass_broadcasting,
        (
            "Profile lacks persistent memory and multi-agent capabilities "
            "— the system is reactive (single-session) and cannot broadcast "
            "to multiple users."
        ),
    ),
    (
        "cross_session_access",
        _check_cross_session_access,
        (
            "Profile lacks persistent memory — the system operates within "
            "a single authenticated session and cannot access other users' "
            "sessions or data."
        ),
    ),
    (
        "audit_monitoring_write",
        _check_audit_monitoring_write,
        (
            "No KC subcode grants audit/monitoring write access — agents "
            "read from monitoring systems but cannot modify audit trails "
            "or suppress alerts."
        ),
    ),
    (
        "session_introspection",
        _check_session_introspection,
        (
            "Agents never have access to their own session tokens, API "
            "authorization headers, or bearer tokens — the platform handles "
            "authentication transparently."
        ),
    ),
    (
        "api_response_fabrication",
        _check_api_response_fabrication,
        (
            "Scenario assumes APIs return data types not in the profile — "
            "system metadata, prompt fragments, model configuration, or "
            "internal system information are not returned by normal API "
            "endpoints."
        ),
    ),
    (
        "system_prompt_retrieval",
        _check_system_prompt_retrieval,
        (
            "Agents never have access to their own system prompt via "
            "API or tool calls — no configuration API, diagnostic endpoint, "
            "or introspection tool exposes system prompts.  The platform "
            "injects them opaquely."
        ),
    ),
]


def _phantom_step_violations(
    scenario: ScenarioEnvelope, profile: CapabilityProfile
) -> list[PhantomViolation]:
    """Check narrative action/effect fields for phantom capabilities."""
    violations: list[PhantomViolation] = []
    for step in scenario.narrative.steps:
        for field_name in ("action", "effect"):
            text = getattr(step, field_name)
            for category, checker, reason in _CHECKERS:
                matched = checker(text, profile, field_name=field_name)
                if matched is not None:
                    violations.append(
                        PhantomViolation(
                            step_number=step.step_number,
                            field=field_name,
                            category=category,
                            matched_text=matched,
                            reason=reason,
                        )
                    )
    return violations


def _phantom_label_check(
    label: str, zone: str, profile: CapabilityProfile
) -> list[PhantomViolation]:
    """Phantom violations from one attack-tree node label."""
    violations: list[PhantomViolation] = []
    for category, checker, reason in _CHECKERS:
        matched = checker(label, profile, field_name="tree_label", zone=zone)
        if matched is not None:
            violations.append(
                PhantomViolation(
                    step_number=0,
                    field="attack_tree",
                    category=category,
                    matched_text=matched,
                    reason=reason,
                )
            )
    return violations


def _phantom_tree_label_violations(
    scenario: ScenarioEnvelope, profile: CapabilityProfile
) -> list[PhantomViolation]:
    """Check attack-tree node labels for phantom capabilities."""
    violations: list[PhantomViolation] = []
    if scenario.attack_tree and scenario.attack_tree.root:
        for label, zone in _collect_node_labels(scenario.attack_tree.root):
            violations.extend(_phantom_label_check(label, zone, profile))
    return violations


def _phantom_gherkin_violations(
    scenario: ScenarioEnvelope, profile: CapabilityProfile
) -> list[PhantomViolation]:
    """Check Gherkin behavior_spec text for phantom capabilities."""
    violations: list[PhantomViolation] = []
    gherkin_text = _semantic_gherkin_text(scenario)
    if gherkin_text:
        for category, checker, reason in _CHECKERS:
            matched = checker(gherkin_text, profile, field_name="gherkin")
            if matched is not None:
                violations.append(
                    PhantomViolation(
                        step_number=0,
                        field="behavior_spec",
                        category=category,
                        matched_text=matched,
                        reason=reason,
                    )
                )
    return violations


def _phantom_tool_leaf_violation(
    leaf: AttackTreeNode, profile: CapabilityProfile
) -> PhantomViolation | None:
    """Violation when a tool-invocation leaf references an unknown tool."""
    if leaf.action is None or leaf.action.kind != "tool_invocation":
        return None
    if profile.resolve_tool(leaf.action.tool_id) is not None:
        return None
    return PhantomViolation(
        step_number=0,
        field="attack_tree",
        category="phantom_tool_invocation",
        matched_text=leaf.action.tool_id,
        reason=(
            f"Leaf node '{leaf.id}' references unknown tool_id '{leaf.action.tool_id}'"
        ),
    )


def _phantom_tool_violations(
    scenario: ScenarioEnvelope, profile: CapabilityProfile
) -> list[PhantomViolation]:
    """Check tool-invocation leaves for unknown tool ids."""
    violations: list[PhantomViolation] = []
    if scenario.attack_tree and scenario.attack_tree.root:
        for leaf in _collect_leaves(scenario.attack_tree.root):
            violation = _phantom_tool_leaf_violation(leaf, profile)
            if violation is not None:
                violations.append(violation)
    return violations


def _phantom_records(
    violations: list[PhantomViolation],
) -> list[PhantomViolationRecord]:
    """Typed phantom violation records for the validation block."""
    return [
        PhantomViolationRecord(
            step_number=v.step_number,
            field=v.field,
            category=v.category,
            matched_text=v.matched_text,
            reason=v.reason,
        )
        for v in violations
    ]


def _persist_phantom_block(
    scenario: ScenarioEnvelope, phantom_block: PhantomValidation
) -> None:
    """Write the phantom block and refresh the aggregate pass flag."""
    if scenario.validation is None:
        scenario.validation = ValidationBlock(phantom=phantom_block)
    else:
        scenario.validation.phantom = phantom_block
    # Update validation_passed to reflect current state.
    scenario.validation_passed = _validation_passed(scenario)


def validate_phantom_capabilities(
    scenarios: list[ScenarioEnvelope],
    profile: CapabilityProfile,
) -> ValidationResult:
    """Validate scenarios against the capability profile for phantom capabilities.

    Examines each scenario's narrative steps (action and effect fields),
    attack tree node labels, and the Gherkin behavior_spec text, flagging
    scenarios whose content references capabilities the system doesn't
    possess according to the profile.

    Returns a ``ValidationResult`` with valid and flagged scenarios.
    Also populates ``scenario.validation.phantom`` on each scenario
    (warn + mark, never drops).
    """
    result = ValidationResult()

    for scenario in scenarios:
        violations: list[PhantomViolation] = []

        # Also check attack tree node labels
        violations.extend(_phantom_step_violations(scenario, profile))
        violations.extend(_phantom_tree_label_violations(scenario, profile))
        violations.extend(_phantom_gherkin_violations(scenario, profile))

        # Resolve typed tool invocations regardless of inventory completeness.
        violations.extend(_phantom_tool_violations(scenario, profile))

        # Populate the validation.phantom block on the scenario.
        phantom_block = PhantomValidation(
            valid=len(violations) == 0,
            violations=_phantom_records(violations),
        )
        _persist_phantom_block(scenario, phantom_block)

        if violations:
            result.flagged_scenarios.append((scenario, violations))
        else:
            result.valid_scenarios.append(scenario)

    return result
