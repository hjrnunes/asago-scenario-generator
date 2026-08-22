"""Validation passes for generated scenarios.

Contains:
  1. Phantom capability validation — flags scenarios that reference
     capabilities the system does not possess.
  2. Structural validation — JSON Schema validation of scenario envelopes.
  3. Semantic validation — Python-based checks (technique existence, zone
     validity, threat-ID consistency, narrative technique orphan detection,
     scenario-level threat_id completeness, zone omission hard flags).
  4. Leaf technique provenance — flags attack-work leaf nodes that
     lack a technique_id annotation.
  5. Blank-leaf validation — structural safety net that flags any leaf
     node missing a technique_id (no consequence-leaf exemption).
  6. Parsimony pruning — trims excess unannotated leaf nodes from
     attack trees to satisfy the parsimony budget constraint.
"""

from __future__ import annotations

import copy
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import jsonschema

from asago_scenario_generator.models.attack_tree import (
    AttackTree,
    AttackTreeNode,
    GateType,
    _repair_node,
)
from asago_scenario_generator.pipeline.tree_utils import collect_tree_zones

if TYPE_CHECKING:
    from asago_scenario_generator.models.capability_profile import CapabilityProfile
    from asago_scenario_generator.models.scenario import (
        CorpusClaimApplicability,
        ScenarioEnvelope,
        SemanticValidation,
    )

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
    admin_entry = any(
        "admin" in ep.name.lower() or "role" in ep.name.lower()
        for ep in profile.entry_points
    )
    # KC6.4 = identity / auth management; KC6.3 = database (may include role tables)
    admin_kc = any(code.startswith(("KC6.4", "KC6.3")) for code in profile.kc_subcodes)
    if admin_entry or admin_kc:
        return None

    for pattern in _PRIVILEGE_ESCALATION_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


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
    api_kc = any(
        code.startswith(("KC6.1.2", "KC6.1.3")) for code in profile.kc_subcodes
    )
    api_entry = any(
        "api" in ep.name.lower() or "http" in ep.name.lower()
        for ep in profile.entry_points
    )
    if api_kc or api_entry:
        return None

    for pattern in _CREDENTIAL_EXPOSURE_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


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
    if field_name == "action":
        return None

    # Input-zone tree labels describe attacker injection — code references
    # describe attacker tooling, not system capabilities.
    if field_name == "tree_label" and zone == "input":
        return None

    has_code_exec = any(
        code.startswith(("KC6.2.2", "KC6.5")) for code in profile.kc_subcodes
    )
    if has_code_exec:
        return None

    # For Gherkin, only check Then/But/* lines (system outcome assertions).
    # Given/When/And lines describe attacker actions (3mal).
    if field_name == "gherkin":
        text = _extract_gherkin_outcome_lines(text)
        if not text:
            return None

    for pattern in _CODE_EXECUTION_PATTERNS:
        m = pattern.search(text)
        if m:
            # For tree labels (no action/effect split),
            # skip matches preceded by attacker-referencing words.
            if field_name in ("tree_label", "gherkin"):
                start = max(0, m.start() - 20)
                preceding = text[start : m.start()].lower()
                if _ATTACKER_CONTEXT_RE.search(preceding):
                    continue
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


def _collect_node_labels(node: AttackTreeNode) -> list[tuple[str, str]]:
    """Recursively collect all (label, zone) pairs from an attack tree."""
    labels: list[tuple[str, str]] = [(node.label, node.zone)]
    if node.children:
        for child in node.children:
            labels.extend(_collect_node_labels(child))
    return labels


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
    from asago_scenario_generator.models.scenario import (
        PhantomValidation,
        PhantomViolationRecord,
        ValidationBlock,
    )

    result = ValidationResult()

    for scenario in scenarios:
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

        # Also check attack tree node labels
        if scenario.attack_tree and scenario.attack_tree.root:
            for label, zone in _collect_node_labels(scenario.attack_tree.root):
                for category, checker, reason in _CHECKERS:
                    matched = checker(
                        label,
                        profile,
                        field_name="tree_label",
                        zone=zone,
                    )
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

        # Also check Gherkin behavior_spec text
        from asago_scenario_generator.models.scenario import (
            BehaviorSpec as _BehaviorSpec,
        )

        gherkin_text_for_phantom = ""
        if scenario.behavior_spec and isinstance(scenario.behavior_spec, _BehaviorSpec):
            gherkin_text_for_phantom = scenario.behavior_spec.gherkin_text
        elif scenario.behavior_spec and isinstance(scenario.behavior_spec, str):
            gherkin_text_for_phantom = scenario.behavior_spec
        if gherkin_text_for_phantom:
            for category, checker, reason in _CHECKERS:
                matched = checker(
                    gherkin_text_for_phantom, profile, field_name="gherkin"
                )
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

        # Resolve typed tool invocations regardless of inventory completeness.
        if scenario.attack_tree and scenario.attack_tree.root:
            leaves = _collect_leaves(scenario.attack_tree.root)
            for leaf in leaves:
                if leaf.action is None or leaf.action.kind != "tool_invocation":
                    continue
                if profile.resolve_tool(leaf.action.tool_id) is None:
                    violations.append(
                        PhantomViolation(
                            step_number=0,
                            field="attack_tree",
                            category="phantom_tool_invocation",
                            matched_text=leaf.action.tool_id,
                            reason=(
                                f"Leaf node '{leaf.id}' references unknown tool_id "
                                f"'{leaf.action.tool_id}'"
                            ),
                        )
                    )

        # Populate the validation.phantom block on the scenario.
        phantom_records = [
            PhantomViolationRecord(
                step_number=v.step_number,
                field=v.field,
                category=v.category,
                matched_text=v.matched_text,
                reason=v.reason,
            )
            for v in violations
        ]
        phantom_block = PhantomValidation(
            valid=len(violations) == 0,
            violations=phantom_records,
        )
        if scenario.validation is None:
            scenario.validation = ValidationBlock(phantom=phantom_block)
        else:
            scenario.validation.phantom = phantom_block
        # Update validation_passed to reflect current state.
        scenario.validation_passed = (
            scenario.validation.phantom.valid
            and scenario.validation.structural.valid
            and scenario.validation.semantic.valid
        )

        if violations:
            result.flagged_scenarios.append((scenario, violations))
        else:
            result.valid_scenarios.append(scenario)

    return result


# ---------------------------------------------------------------------------
# Insider access floor validation (cmps.6 — structured evidence)
# ---------------------------------------------------------------------------

# Insider actor types that require structured material insider advantage
# when using direct/public ingress.
_INSIDER_ACTOR_TYPES: frozenset[str] = frozenset(
    {"malicious-insider", "negligent-insider"}
)


@dataclass
class InsiderAccessViolation:
    """A malicious-insider scenario lacking structured insider advantage evidence."""

    scenario_id: str
    actor_type: str
    reason: str


@dataclass
class InsiderAccessResult:
    """Result of insider access floor validation across a batch."""

    clean_scenarios: list[ScenarioEnvelope] = field(default_factory=list)
    flagged_scenarios: list[tuple[ScenarioEnvelope, InsiderAccessViolation]] = field(
        default_factory=list
    )

    @property
    def flagged_count(self) -> int:
        return len(self.flagged_scenarios)

    @property
    def clean_count(self) -> int:
        return len(self.clean_scenarios)


def _has_insider_access_markers(text: str) -> bool:
    """Check whether text contains keywords indicating insider-specific access.

    Deprecated: retained for backward-compatible test compatibility only.
    The cmps.6 policy uses structured ``material_insider_advantage`` evidence
    instead of keyword matching.  See :func:`validate_insider_access_floor`.
    """
    # Kept as a no-op stub so legacy imports don't break; the real check
    # is now structured-evidence-based.
    return False


def validate_insider_access_floor(
    scenarios: list[ScenarioEnvelope],
) -> InsiderAccessResult:
    """Flag insider scenarios lacking structured material insider advantage.

    Replaces the former keyword-based check (cmps.6).  When the actor type
    is an insider (``malicious-insider`` or ``negligent-insider``) using
    direct ingress with ``public``/``authenticated`` access, the
    ``access.material_insider_advantage`` field must be present and
    nonblank.

    Scenarios without an ``access`` provenance block are flagged — the
    policy is authoritative, not optional.

    Returns an :class:`InsiderAccessResult` with clean and flagged scenarios.
    """
    result = InsiderAccessResult()

    for scenario in scenarios:
        actor = scenario.actor_profile
        if actor is None or actor.actor_type not in _INSIDER_ACTOR_TYPES:
            result.clean_scenarios.append(scenario)
            continue

        access = actor.access
        if access is None:
            violation = InsiderAccessViolation(
                scenario_id=scenario.scenario_id,
                actor_type=actor.actor_type,
                reason=(
                    f"Insider actor '{actor.actor_type}' has no typed access "
                    f"provenance — material_insider_advantage evidence is "
                    f"required (cmps.6)."
                ),
            )
            logger.warning(
                "Insider access floor: scenario %s actor_type='%s' has no "
                "access provenance",
                scenario.scenario_id,
                actor.actor_type,
            )
            result.flagged_scenarios.append((scenario, violation))
            continue

        # Direct ingress requires material insider advantage regardless
        # of access_class (enum choice is not evidence).  Indirect ingress
        # is validated via influence evidence in the shared access-policy
        # validator.
        if access.ingress_mode == "direct":
            advantage = access.material_insider_advantage
            if not advantage or not advantage.strip():
                violation = InsiderAccessViolation(
                    scenario_id=scenario.scenario_id,
                    actor_type=actor.actor_type,
                    reason=(
                        f"Insider actor '{actor.actor_type}' using "
                        f"direct ingress lacks structured "
                        f"material_insider_advantage evidence regardless "
                        f"of access_class '{access.access_class}' — enum "
                        f"choice is not evidence (cmps.6)."
                    ),
                )
                logger.warning(
                    "Insider access floor: scenario %s actor_type='%s' "
                    "using direct ingress without material_insider_advantage",
                    scenario.scenario_id,
                    actor.actor_type,
                )
                result.flagged_scenarios.append((scenario, violation))
            else:
                result.clean_scenarios.append(scenario)
        else:
            # Indirect ingress — validated via influence evidence /
            # access-policy validator, not here.
            result.clean_scenarios.append(scenario)

    return result


# ---------------------------------------------------------------------------
# Structural validation (JSON Schema) — rwv2
# ---------------------------------------------------------------------------

_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "schemas"
    / "scenario-envelope.schema.json"
)

_cached_schema: dict | None = None


def _load_envelope_schema() -> dict:
    """Load and cache the hand-maintained JSON Schema for ScenarioEnvelope."""
    global _cached_schema
    if _cached_schema is None:
        _cached_schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return _cached_schema


def validate_scenario_structure(
    scenarios: list[ScenarioEnvelope],
) -> None:
    """Run JSON Schema validation on each scenario envelope.

    Populates ``scenario.validation.structural`` with results.
    Scenarios are never removed -- violations are recorded as warnings.
    """
    from asago_scenario_generator.models.scenario import (
        StructuralValidation,
        ValidationBlock,
    )

    schema = _load_envelope_schema()
    validator = jsonschema.Draft202012Validator(schema)

    for scenario in scenarios:
        # Serialize the envelope to a dict for JSON Schema validation.
        envelope_dict = scenario.model_dump(mode="json")
        errors = list(validator.iter_errors(envelope_dict))

        structural = StructuralValidation(
            valid=len(errors) == 0,
            violations=[
                f"{'.'.join(str(p) for p in e.absolute_path)}: {e.message}"
                if e.absolute_path
                else e.message
                for e in errors
            ],
        )

        if scenario.validation is None:
            scenario.validation = ValidationBlock(structural=structural)
        else:
            scenario.validation.structural = structural

        # Update validation_passed.
        scenario.validation_passed = (
            scenario.validation.phantom.valid
            and scenario.validation.structural.valid
            and scenario.validation.semantic.valid
        )


# ---------------------------------------------------------------------------
# Cross-artifact consistency helpers (bv5s)
# ---------------------------------------------------------------------------

# Regex for technique IDs: bracketed [AML.T0054] and bare AML.T0054 references.
_NARRATIVE_TECHNIQUE_RE = re.compile(r"\[?(AML\.T\d{4}(?:\.\d{3})?)\]?")


def _extract_narrative_technique_ids(
    narrative: Any,
) -> set[str]:
    """Extract technique IDs mentioned in narrative steps and summary.

    Looks for both ``[AML.T0054]`` bracketed annotations and bare
    ``AML.T0054`` references in step action/effect text and the summary.
    """
    ids: set[str] = set()
    # Check summary
    if hasattr(narrative, "summary") and narrative.summary:
        for m in _NARRATIVE_TECHNIQUE_RE.finditer(narrative.summary):
            ids.add(m.group(1))
    # Check steps
    if hasattr(narrative, "steps"):
        for step in narrative.steps:
            for field_name in ("action", "effect"):
                text = getattr(step, field_name, "")
                if text:
                    for m in _NARRATIVE_TECHNIQUE_RE.finditer(text):
                        ids.add(m.group(1))
    return ids


def _collect_tree_node_threat_ids(node: AttackTreeNode) -> set[str]:
    """Recursively collect all non-None threat_id values from tree nodes."""
    ids: set[str] = set()
    if node.threat_id is not None:
        ids.add(node.threat_id)
    if node.children:
        for child in node.children:
            ids.update(_collect_tree_node_threat_ids(child))
    return ids


def _collect_tree_node_zones(node: AttackTreeNode) -> set[str]:
    """Recursively collect all zone values from attack tree nodes."""
    return collect_tree_zones(node, include_empty=False)


def _extract_gherkin_zones_for_validation(gherkin_text: str) -> set[str]:
    """Extract zone annotations from Gherkin text for validation.

    Supports:
    - ``# Zone reasoning`` comments
    - ``(zone_name)`` inline annotations in step text

    Reuses the same zone name resolution as the eval layer.
    """
    from asago_scenario_generator.models.capability_profile import (
        ZONE_DISPLAY_NAMES,
        ZONE_NAMES,
    )

    _INT_TO_NAME = dict(enumerate(ZONE_NAMES, 1))
    valid_zone_set = set(ZONE_NAMES)
    zones: set[str] = set()

    # Match "# Zone <word_or_number>"
    for match in re.finditer(r"#\s*[Zz]one\s+(\S+)", gherkin_text):
        token = match.group(1)
        if token.isdigit():
            name = _INT_TO_NAME.get(int(token))
            if name:
                zones.add(name)
        elif token in valid_zone_set:
            zones.add(token)
        else:
            for zn, display in ZONE_DISPLAY_NAMES.items():
                if token.lower() in display.lower():
                    zones.add(zn)
                    break

    # Match "(zone_name)" inline annotations
    for match in re.finditer(r"\((\w+)\)", gherkin_text):
        token = match.group(1)
        if token in valid_zone_set:
            zones.add(token)

    return zones


# ---------------------------------------------------------------------------
# Semantic validation (Python logic) — rwv2
# ---------------------------------------------------------------------------


def _validate_scenario_semantics_mutating(
    scenarios: list[ScenarioEnvelope],
    profile: CapabilityProfile,
) -> None:
    """Run semantic validation checks on each scenario envelope.

    Checks:
      1. ``technique_exists``: every technique_id in the attack tree exists
         in ``ATLAS_TECHNIQUE_NAMES``.
      2. ``zone_in_profile``: every active zone referenced in the narrative's
         zone_sequence is in the profile's ``zones_active``. The canonical
         ``outside`` boundary marker is valid narrative context, not an active
         Schneider zone.
      3. ``threat_id_range``: threat_id on attack tree nodes is in T1-T17.
      4. ``missing_scenario_threat_id``: at least one tree node carries the
         scenario's own threat_id from ``scenario_seed_metadata``.
      5. ``narrative_technique_orphan``: technique IDs mentioned in narrative
         text but absent from the attack tree.
      6. ``zone_omission_tree``: narrative zones missing from attack tree.
      7. ``zone_omission_gherkin``: narrative zones missing from Gherkin.
      8. Typed action IDs resolve to canonical profile resources, and
         tool_execution leaves carry tool_invocation actions.
      9. ``seed_technique_provenance``: at least one ATLAS provenance
         technique must appear in the attack tree. LAAF S/M identifiers are
         provenance in a different namespace and are not tree technique IDs.
     10. ``zone_coverage_dropout``: narrative zone absent from BOTH tree
         AND Gherkin — a hard consistency failure (cxy4).

    Populates ``scenario.validation.semantic`` with results.
    Scenarios are never removed -- violations are recorded as warnings.
    """
    from asago_scenario_generator.data.atlas import ATLAS_TECHNIQUE_NAMES
    from asago_scenario_generator.models.capability_profile import (
        is_attacker_accessible_ingress,
    )
    from asago_scenario_generator.models.scenario import (
        SemanticValidation,
        SemanticViolation,
        ValidationBlock,
    )

    valid_technique_ids = set(ATLAS_TECHNIQUE_NAMES.keys())
    valid_zones = {*profile.zones_active, "outside"}

    for scenario in scenarios:
        violations: list[SemanticViolation] = []

        # 1. Check technique_ids in attack tree.
        tree_technique_ids = scenario.attack_tree.collect_technique_ids()
        tree_technique_set = set(tree_technique_ids)
        for tid in tree_technique_ids:
            if tid not in valid_technique_ids:
                violations.append(
                    SemanticViolation(
                        rule="technique_exists",
                        message=f"{tid} not in pinned technique set",
                        severity="major",
                    )
                )

        # 2. Check zones against profile.
        for zone in scenario.narrative.zone_sequence:
            if zone not in valid_zones:
                violations.append(
                    SemanticViolation(
                        rule="zone_in_profile",
                        message=(
                            f"Zone '{zone}' in narrative zone_sequence "
                            f"is not in profile's zones_active: {sorted(valid_zones)}"
                        ),
                        severity="minor",
                    )
                )

        # 3. Check threat_id range on tree nodes.
        seed_metadata = scenario.scenario_seed_metadata
        if seed_metadata and "threat_id" in seed_metadata:
            expected_threat = seed_metadata["threat_id"]
            _check_tree_threat_ids(
                scenario.attack_tree.root,
                expected_threat,
                violations,
            )

            # 4. Check that at least one node carries the scenario's own
            #    threat_id (missing_scenario_threat_id — bv5s).
            all_tree_threat_ids = _collect_tree_node_threat_ids(
                scenario.attack_tree.root
            )
            if expected_threat not in all_tree_threat_ids:
                violations.append(
                    SemanticViolation(
                        rule="missing_scenario_threat_id",
                        message=(
                            f"No tree node carries the scenario's threat_id "
                            f"'{expected_threat}'; tree threat_ids are "
                            f"{sorted(all_tree_threat_ids)}"
                        ),
                        severity="major",
                    )
                )

        # 5. Narrative technique orphan detection (bv5s).
        narrative_technique_ids = _extract_narrative_technique_ids(scenario.narrative)
        orphan_techniques = narrative_technique_ids - tree_technique_set
        for orphan_tid in sorted(orphan_techniques):
            violations.append(
                SemanticViolation(
                    rule="narrative_technique_orphan",
                    message=(
                        f"Technique '{orphan_tid}' mentioned in narrative "
                        f"but absent from attack tree nodes"
                    ),
                    severity="minor",
                )
            )

        # 6. Zone omission checks (bv5s).
        narrative_zones = set(scenario.narrative.zone_sequence)
        # ``outside`` represents activity before crossing the assessed system
        # boundary. Tree leaves for those external preconditions intentionally
        # have zone=None, and Gherkin annotations cover active system zones.
        artifact_coverage_zones = narrative_zones - {"outside"}

        # 6a. Zone omission — tree.
        tree_zones = _collect_tree_node_zones(scenario.attack_tree.root)
        omitted_tree_zones = sorted(artifact_coverage_zones - tree_zones)
        zone_seq = scenario.narrative.zone_sequence
        terminal_zone = zone_seq[-1] if zone_seq else None
        compound_omission = len(omitted_tree_zones) >= 2
        for zone in omitted_tree_zones:
            is_terminal = zone == terminal_zone
            severity = "major" if is_terminal or compound_omission else "minor"
            violations.append(
                SemanticViolation(
                    rule="zone_omission_tree",
                    message=(
                        f"Zone '{zone}' in narrative zone_sequence "
                        f"but absent from attack tree nodes"
                    ),
                    severity=severity,
                )
            )

        # 6b. Zone omission — Gherkin.
        gherkin_text = ""
        from asago_scenario_generator.models.scenario import BehaviorSpec as _BS2

        if scenario.behavior_spec and isinstance(scenario.behavior_spec, _BS2):
            gherkin_text = scenario.behavior_spec.gherkin_text
        elif scenario.behavior_spec and isinstance(scenario.behavior_spec, str):
            gherkin_text = scenario.behavior_spec
        gherkin_zones: set[str] = set()
        if gherkin_text:
            gherkin_zones = _extract_gherkin_zones_for_validation(gherkin_text)
            for zone in sorted(artifact_coverage_zones - gherkin_zones):
                violations.append(
                    SemanticViolation(
                        rule="zone_omission_gherkin",
                        message=(
                            f"Zone '{zone}' in narrative zone_sequence "
                            f"but absent from Gherkin behavior_spec"
                        ),
                        severity="minor",
                    )
                )

        # 10. Zone coverage dropout — a zone present in narrative but absent
        #     from BOTH tree AND Gherkin is a hard consistency failure (cxy4).
        dropped_zones = artifact_coverage_zones - (tree_zones | gherkin_zones)
        for zone in sorted(dropped_zones):
            violations.append(
                SemanticViolation(
                    rule="zone_coverage_dropout",
                    message=(
                        f"Zone '{zone}' in narrative zone_sequence is absent "
                        f"from BOTH attack tree nodes AND Gherkin behavior_spec"
                    ),
                    severity="major",
                )
            )

        # 8. Typed action and canonical resource checks. Unknown emitted IDs
        #    fail even when the profile inventory is only inferred_partial.
        leaves = _collect_leaves(scenario.attack_tree.root)
        for leaf in leaves:
            action = leaf.action
            if leaf.zone == "tool_execution" and (
                action is None
                or action.kind not in {"tool_invocation", "integration_interaction"}
            ):
                violations.append(
                    SemanticViolation(
                        rule="untyped-tool-execution",
                        message=(
                            f"Leaf node '{leaf.id}' is in tool_execution zone "
                            "but does not have a tool_invocation or "
                            "integration_interaction action"
                        ),
                        severity="major",
                    )
                )
            if action is None:
                continue
            if action.kind == "initial_ingress":
                resolved_ep = profile.resolve_entry_point(action.entry_point_id)
                if resolved_ep is None:
                    violations.append(
                        SemanticViolation(
                            rule="unknown_entry_point_id",
                            message=(
                                f"Leaf node '{leaf.id}' references unknown "
                                f"entry_point_id '{action.entry_point_id}'"
                            ),
                            severity="major",
                        )
                    )
                elif not is_attacker_accessible_ingress(
                    resolved_ep,
                    set(profile.zones_active) if profile.zones_active else set(),
                ):
                    violations.append(
                        SemanticViolation(
                            rule="inaccessible_ingress_entry_point",
                            message=(
                                f"Leaf node '{leaf.id}' references entry "
                                f"point '{resolved_ep.name}' "
                                f"(entry_point_id '{action.entry_point_id}') "
                                f"which is not an attacker-accessible ingress "
                                f"route (output-only, system-controlled, or "
                                f"inactive ingress zone)."
                            ),
                            severity="major",
                        )
                    )
            elif action.kind == "tool_invocation":
                if profile.resolve_tool(action.tool_id) is None:
                    violations.append(
                        SemanticViolation(
                            rule="phantom_tool",
                            message=(
                                f"Leaf node '{leaf.id}' references unknown "
                                f"tool_id '{action.tool_id}'"
                            ),
                            severity="major",
                        )
                    )
                if (
                    action.integration_id is not None
                    and profile.resolve_integration(action.integration_id) is None
                ):
                    violations.append(
                        SemanticViolation(
                            rule="unknown_integration_id",
                            message=(
                                f"Leaf node '{leaf.id}' references unknown "
                                f"integration_id '{action.integration_id}'"
                            ),
                            severity="major",
                        )
                    )
            elif (
                action.kind == "integration_interaction"
                and profile.resolve_integration(action.integration_id) is None
            ):
                violations.append(
                    SemanticViolation(
                        rule="unknown_integration_id",
                        message=(
                            f"Leaf node '{leaf.id}' references unknown "
                            f"integration_id '{action.integration_id}'"
                        ),
                        severity="major",
                    )
                )

        # 9. Seed technique provenance. Attack-tree technique IDs use the
        #    ATLAS AML.* namespace. LAAF S*/M* IDs describe upstream
        #    provenance and cannot be directly compared to those tree IDs.
        #    Retain compatibility for legacy envelopes that incorrectly put
        #    AML.* identifiers in laaf_technique_ids.
        seed_techniques: set[str] = set()
        if seed_metadata:
            seed_techniques.update(seed_metadata.get("atlas_provenance_ids") or ())
            if not seed_techniques:
                seed_techniques.update(
                    technique_id
                    for technique_id in seed_metadata.get("laaf_technique_ids") or ()
                    if str(technique_id).startswith("AML.")
                )
        if seed_techniques:
            all_tree_techniques = _collect_technique_ids(scenario.attack_tree.root)
            if not seed_techniques & all_tree_techniques:
                violations.append(
                    SemanticViolation(
                        rule="seed_technique_provenance",
                        message=(
                            f"No seed techniques {sorted(seed_techniques)} "
                            f"appear in the attack tree. "
                            f"Tree contains {sorted(all_tree_techniques)}."
                        ),
                        severity="major",
                    )
                )

        # 11. Goal-category alignment — flag mismatches between goal_category
        #     and the actor type or attack mechanism (kum3).
        _goal_cat = (
            scenario.actor_profile.goal_category if scenario.actor_profile else None
        )
        if _goal_cat and isinstance(_goal_cat, str):
            _actor_type = (
                scenario.actor_profile.actor_type if scenario.actor_profile else None
            )

            # 11a. Supply-chain goal on non-supply-chain actor.
            _NON_SUPPLY_CHAIN_ACTORS = {
                "negligent-insider",
                "adversarial-user",
                "cybercriminal",
            }
            if _goal_cat.startswith("IN-7") and _actor_type in _NON_SUPPLY_CHAIN_ACTORS:
                violations.append(
                    SemanticViolation(
                        rule="goal_actor_mismatch",
                        message=(
                            f"Supply-chain goal '{_goal_cat}' assigned to "
                            f"actor_type '{_actor_type}' which is not a "
                            f"supply-chain actor"
                        ),
                        severity="moderate",
                    )
                )

            # 11b. Data exfiltration goal on financial fraud attack.
            if _goal_cat.startswith("PR-1"):
                _financial_keywords = [
                    "refund",
                    "payment",
                    "billing",
                    "transaction",
                ]
                leaves = _collect_leaves(scenario.attack_tree.root)
                _has_financial_tool_leaf = False
                for leaf in leaves:
                    if leaf.action is None or leaf.action.kind != "tool_invocation":
                        continue
                    resolved_tool = profile.resolve_tool(leaf.action.tool_id)
                    if resolved_tool is not None and any(
                        kw in resolved_tool.name.lower() for kw in _financial_keywords
                    ):
                        _has_financial_tool_leaf = True
                        break
                if _has_financial_tool_leaf:
                    violations.append(
                        SemanticViolation(
                            rule="goal_mechanism_mismatch",
                            message=(
                                f"Data exfiltration goal '{_goal_cat}' "
                                f"assigned but attack tree contains "
                                f"financial tool leaves (refund/payment/"
                                f"billing/transaction)"
                            ),
                            severity="minor",
                        )
                    )

            # 11c. Safety bypass goal on social engineering attack.
            if _goal_cat.startswith("AB-1"):
                _se_keywords = [
                    "phishing",
                    "credential",
                    "social engineering",
                    "impersonat",
                ]
                _narrative_text = " ".join(
                    [scenario.narrative.title, scenario.narrative.summary]
                    + [f"{s.action} {s.effect}" for s in scenario.narrative.steps]
                ).lower()
                _has_social_engineering = any(
                    kw in _narrative_text for kw in _se_keywords
                )
                if _has_social_engineering:
                    violations.append(
                        SemanticViolation(
                            rule="goal_mechanism_mismatch",
                            message=(
                                f"Safety bypass goal '{_goal_cat}' assigned "
                                f"but narrative describes a social "
                                f"engineering attack"
                            ),
                            severity="minor",
                        )
                    )

        # 12. Actor / access provenance validation (cmps.6).
        #     Uses the shared pure validator from generate.actor to avoid
        #     duplicating rule maps.  Adds tree-wide ID invariants that the
        #     pure validator cannot check (it has no tree context).
        _actor_type_12 = (
            scenario.actor_profile.actor_type if scenario.actor_profile else None
        )
        _access_12 = scenario.actor_profile.access if scenario.actor_profile else None
        _ingress_actions_12 = [
            (leaf.id, leaf.action)
            for leaf in leaves
            if leaf.action is not None and leaf.action.kind == "initial_ingress"
        ]

        if _actor_type_12 and _access_12 is None and _ingress_actions_12:
            violations.append(
                SemanticViolation(
                    rule="missing_access_provenance",
                    message=(
                        f"Actor '{_actor_type_12}' has no typed access "
                        f"provenance (cmps.6)."
                    ),
                    severity="moderate",
                )
            )

        if _actor_type_12 and _access_12 is not None:
            # 12a–12e: delegate to the shared pure access-policy validator.
            from asago_scenario_generator.pipeline.generate.actor import (
                validate_actor_access_provenance as _vap,
            )

            for _v in _vap(scenario.actor_profile, profile):
                violations.append(
                    SemanticViolation(
                        rule=_v.rule,
                        message=_v.message,
                        severity="major",
                    )
                )

            # 12f. Actor access initial_entry_point_id must match the
            #      scenario envelope.  Run even if tree has no ingress.
            _canonical_ep_id = scenario.initial_entry_point_id
            if _access_12.initial_entry_point_id != _canonical_ep_id:
                violations.append(
                    SemanticViolation(
                        rule="initial_entry_point_id_mismatch",
                        message=(
                            f"Actor access initial_entry_point_id "
                            f"'{_access_12.initial_entry_point_id}' does not "
                            f"match scenario envelope "
                            f"initial_entry_point_id '{_canonical_ep_id}'."
                        ),
                        severity="major",
                    )
                )

        # 12g. Tree-wide initial_entry_point_id invariant: every
        #      initial_ingress action must use exactly the same canonical
        #      ID as the top-level scenario envelope.  Run regardless of
        #      actor access presence (the tree invariant is independent).
        _canonical_ep_id = scenario.initial_entry_point_id
        for _leaf_id, _ingress_act in _ingress_actions_12:
            if _ingress_act.entry_point_id != _canonical_ep_id:
                violations.append(
                    SemanticViolation(
                        rule="initial_entry_point_id_mismatch",
                        message=(
                            f"Attack tree initial_ingress action "
                            f"'{_leaf_id}' uses entry_point_id "
                            f"'{_ingress_act.entry_point_id}' which "
                            f"diverges from canonical "
                            f"'{_canonical_ep_id}'."
                        ),
                        severity="major",
                    )
                )

        # 12h. Narrative access realization validation (cmps.6).
        #      Delegate to the shared pure validator from generate.narrative
        #      so semantic validation catches persistent realization
        #      mismatches after Call-1 retry exhaustion.  This ensures
        #      persistently invalid narrative realization is quarantined,
        #      not silently admitted.
        if _actor_type_12 and _access_12 is not None:
            from asago_scenario_generator.pipeline.generate.narrative import (
                validate_narrative_access_realization as _vnr,
            )

            for _v in _vnr(scenario.narrative, scenario.actor_profile):
                violations.append(
                    SemanticViolation(
                        rule=_v.rule,
                        message=_v.message,
                        severity="major",
                    )
                )

        # 13. Corpus-wide closed-world claim applicability (cmps.9 review)
        corpus_claims = check_corpus_claims_applicability(scenario, profile)

        semantic = SemanticValidation(
            valid=len(violations) == 0,
            violations=violations,
            corpus_claim_applicability=corpus_claims,
        )

        if scenario.validation is None:
            scenario.validation = ValidationBlock(semantic=semantic)
        else:
            scenario.validation.semantic = semantic

        # Update validation_passed.
        scenario.validation_passed = (
            scenario.validation.phantom.valid
            and scenario.validation.structural.valid
            and scenario.validation.semantic.valid
        )


def check_scenario_semantics(
    scenario: ScenarioEnvelope,
    profile: CapabilityProfile,
) -> SemanticValidation:
    """Run the legacy semantic checks on one copy without changing the input."""
    cloned = copy.deepcopy(scenario)
    _validate_scenario_semantics_mutating([cloned], profile)
    if cloned.validation is None or cloned.validation.semantic is None:
        raise RuntimeError("semantic validation did not produce a result")
    return copy.deepcopy(cloned.validation.semantic)


def validate_scenario_semantics(
    scenarios: list[ScenarioEnvelope],
    profile: CapabilityProfile,
) -> None:
    """Compatibility batch wrapper that persists pure per-envelope results."""
    from asago_scenario_generator.models.scenario import ValidationBlock

    for scenario in scenarios:
        semantic = check_scenario_semantics(scenario, profile)
        if scenario.validation is None:
            scenario.validation = ValidationBlock(semantic=semantic)
        else:
            scenario.validation.semantic = semantic
        scenario.validation_passed = (
            scenario.validation.phantom.valid
            and scenario.validation.structural.valid
            and scenario.validation.semantic.valid
        )


def check_corpus_claims_applicability(
    scenario: ScenarioEnvelope,
    profile: CapabilityProfile,
) -> list[CorpusClaimApplicability]:
    """Return typed category-specific closed-world corpus claim applicability.

    For each inventory category (entry_points, tool_inventory):
    - ``inferred_partial`` → ``not_applicable`` with a typed reason.
    - ``operator_confirmed_complete`` → ``applicable`` carrying evidence.

    This is independent of ``phantom.valid`` — unknown emitted IDs still
    fail regardless of completeness (cmps.9 review correction 2).
    """
    from asago_scenario_generator.models.scenario import (
        CorpusClaimApplicability,
        CorpusClaimCategory,
        CorpusClaimStatus,
    )

    del scenario
    records: list[CorpusClaimApplicability] = []

    # Entry-point inventory
    if profile.is_entry_point_inventory_complete:
        records.append(
            CorpusClaimApplicability(
                category=CorpusClaimCategory.entry_points,
                status=CorpusClaimStatus.applicable,
                reason=None,
                evidence=[e for e in profile.entry_point_evidence if e and e.strip()],
            )
        )
    else:
        records.append(
            CorpusClaimApplicability(
                category=CorpusClaimCategory.entry_points,
                status=CorpusClaimStatus.not_applicable,
                reason=(
                    "Entry-point inventory is inferred_partial, not "
                    "operator-confirmed complete — closed-world corpus "
                    "claims are not applicable."
                ),
            )
        )

    # Tool inventory
    if profile.is_tool_inventory_complete:
        records.append(
            CorpusClaimApplicability(
                category=CorpusClaimCategory.tool_inventory,
                status=CorpusClaimStatus.applicable,
                reason=None,
                evidence=[
                    e for e in profile.tool_inventory_evidence if e and e.strip()
                ],
            )
        )
    else:
        records.append(
            CorpusClaimApplicability(
                category=CorpusClaimCategory.tool_inventory,
                status=CorpusClaimStatus.not_applicable,
                reason=(
                    "Tool inventory is inferred_partial, not "
                    "operator-confirmed complete — closed-world corpus "
                    "claims are not applicable."
                ),
            )
        )

    return records


def validate_semantic(
    scenarios: list[ScenarioEnvelope],
    profile: CapabilityProfile,
) -> None:
    """Compatibility entry point for semantic scenario validation."""
    validate_scenario_semantics(scenarios, profile)


def _check_tree_threat_ids(
    node: AttackTreeNode,
    expected_threat: str,
    violations: list,
) -> None:
    """Recursively check threat_id on tree nodes against valid range.

    Per ``decision-t6-crossref-policy``, per-node ``threat_id`` may reflect
    the mechanism rather than the scenario-level threat.  This check therefore
    validates **range** (is it a real OWASP threat in T1-T17?) rather than
    requiring a match to *expected_threat*.
    """
    from asago_scenario_generator.models.scenario import SemanticViolation

    tid = node.threat_id
    if tid is not None and tid not in _VALID_THREAT_IDS:
        violations.append(
            SemanticViolation(
                rule="threat_id_range",
                message=(
                    f"Node '{node.id}' has invalid threat_id '{tid}'; "
                    f"valid range is T1-T17"
                ),
                severity="major",
            )
        )

    if node.children:
        for child in node.children:
            _check_tree_threat_ids(child, expected_threat, violations)


# ---------------------------------------------------------------------------
# Leaf technique provenance — data structures
# ---------------------------------------------------------------------------


@dataclass
class LeafTechniqueViolation:
    """Scenario-level provenance mismatch for leaf technique validation."""

    node_id: str
    label: str
    zone: str
    reason: str


@dataclass
class LeafTechniqueResult:
    """Result of leaf technique provenance validation across a batch."""

    clean_scenarios: list[ScenarioEnvelope] = field(default_factory=list)
    flagged_scenarios: list[tuple[ScenarioEnvelope, list[LeafTechniqueViolation]]] = (
        field(default_factory=list)
    )

    @property
    def flagged_count(self) -> int:
        return len(self.flagged_scenarios)

    @property
    def clean_count(self) -> int:
        return len(self.clean_scenarios)


# ---------------------------------------------------------------------------
# Leaf technique provenance — consequence heuristic
# ---------------------------------------------------------------------------

# Consequence / terminal-outcome patterns.  A leaf whose label (or
# description) matches one of these is a *consequence node* — it
# describes what happens as a result of the attack, not an active
# attack step.  Consequence nodes are exempt from the technique_id
# requirement.

_CONSEQUENCE_LEAF_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        # Victim / target performing an action as a result of manipulation
        r"\bvictim\s+\w+",
        (
            r"\btarget\s+(?:user|employee|operator|person|individual)\s+"
            r"(?:transfer|send|comply|reveal|disclose|provide|submit)\w*"
        ),
        # Data / asset terminal-outcome language
        (
            r"\b(?:data|credentials?|information|secrets?|funds?|assets?|money)"
            r"\s+(?:exfiltrated|stolen|harvested|captured|diverted|"
            r"compromised|lost|leaked|extracted|obtained)\b"
        ),
        # Exfiltration as terminal step
        r"\b(?:exfiltrate|siphon)\s",
        # Attack / breach completion
        (
            r"\b(?:attack|breach|compromise|infiltration|campaign|objective)"
            r"\s+(?:succeed|complet|achiev|accomplish|finalize)\w*"
        ),
        # Impact / damage realization
        (
            r"\b(?:impact|damage|loss|harm)"
            r"\s+(?:realiz|materializ|inflict|occur)\w*"
        ),
        # Goal achievement (allow intervening words)
        (
            r"\b(?:achieve|accomplish)\w*\b"
            r"[^.]{0,30}\b(?:goal|objective|purpose|aim)\b"
        ),
        # System state as terminal outcome
        (
            r"\b(?:system|account|network|infrastructure)"
            r"\s+(?:fully\s+)?(?:compromised|breached|corrupted|infected)\b"
        ),
        # Access gained as terminal outcome
        (
            r"\b(?:gain|obtain|establish|secure)\w*"
            r"\s+(?:persistent|unauthorized|full|complete|admin|root)\s+access\b"
        ),
    ]
]


def _is_consequence_leaf(node: AttackTreeNode) -> bool:
    """Heuristic: is this leaf a terminal consequence / effect node?

    Consequence nodes describe outcomes or effects (e.g. "victim
    transfers funds", "data exfiltrated") rather than active attack
    steps.  They are exempt from the ``technique_id`` requirement
    because they are not technique-driven actions.
    """
    if node.action is not None:
        return node.action.kind == "impact"

    text = node.label
    if node.description:
        text = f"{text} {node.description}"

    for pattern in _CONSEQUENCE_LEAF_PATTERNS:
        if pattern.search(text):
            return True
    return False


# ---------------------------------------------------------------------------
# Leaf technique provenance — main validation
# ---------------------------------------------------------------------------


def check_leaf_technique_provenance(
    scenarios: list[ScenarioEnvelope],
) -> LeafTechniqueResult:
    """Check that at least one leaf carries a seed provenance technique.

    For each scenario, extracts ``atlas_provenance_ids`` from the
    scenario's ``scenario_seed_metadata`` and checks whether at least
    one leaf node's ``technique_id`` appears in that provenance set.
    Leaves without a ``technique_id`` (unannotated prerequisite steps
    like "observe response") are excluded from the check entirely —
    they are legitimate attack steps not tied to a specific ATLAS
    technique.

    Per ``decision-technique-provenance-partial``, partial provenance
    (1 of N seed techniques) is accepted.

    A scenario is flagged when:
    - No leaf node carries any ``technique_id`` at all, or
    - Leaf nodes have ``technique_id`` values but none match the seed's
      ``atlas_provenance_ids``.

    Returns a :class:`LeafTechniqueResult` with clean and flagged
    scenarios.  The caller decides whether to log warnings or block.
    """
    result = LeafTechniqueResult()

    for scenario in scenarios:
        # Extract atlas_provenance_ids from seed metadata.
        provenance_ids: set[str] = set()
        if scenario.scenario_seed_metadata:
            raw = scenario.scenario_seed_metadata.get("atlas_provenance_ids") or []
            provenance_ids = set(raw)

        leaves = _collect_leaves(scenario.attack_tree.root)

        # Collect only leaves that carry a technique_id; unannotated
        # leaves (prerequisite steps) are excluded from the denominator.
        annotated_technique_ids = [
            leaf.technique_id for leaf in leaves if leaf.technique_id
        ]

        # Check if at least one annotated leaf matches the provenance set.
        has_provenance_match = any(
            tid in provenance_ids for tid in annotated_technique_ids
        )

        if has_provenance_match:
            result.clean_scenarios.append(scenario)
        else:
            # Build a descriptive violation.
            root = scenario.attack_tree.root
            if not annotated_technique_ids:
                reason = (
                    "No leaf nodes carry a technique_id; "
                    "cannot verify provenance against seed "
                    f"atlas_provenance_ids {sorted(provenance_ids)}."
                )
            else:
                found_ids = sorted(set(annotated_technique_ids))
                reason = (
                    f"Leaf technique_ids {found_ids} do not include any "
                    f"seed provenance technique from atlas_provenance_ids "
                    f"{sorted(provenance_ids)}."
                )

            violation = LeafTechniqueViolation(
                node_id=root.id,
                label=root.label,
                zone=root.zone,
                reason=reason,
            )
            result.flagged_scenarios.append((scenario, [violation]))

    return result


# ---------------------------------------------------------------------------
# Blank-leaf validation — structural safety net
# ---------------------------------------------------------------------------


@dataclass
class BlankLeafViolation:
    """A leaf node missing a ``technique_id`` annotation."""

    node_id: str
    label: str
    zone: str


@dataclass
class BlankLeafResult:
    """Result of blank-leaf validation across a batch of scenarios."""

    clean_scenarios: list[ScenarioEnvelope] = field(default_factory=list)
    flagged_scenarios: list[tuple[ScenarioEnvelope, list[BlankLeafViolation]]] = field(
        default_factory=list
    )

    @property
    def flagged_count(self) -> int:
        return len(self.flagged_scenarios)

    @property
    def clean_count(self) -> int:
        return len(self.clean_scenarios)


def validate_blank_leaves(
    scenarios: list[ScenarioEnvelope],
) -> BlankLeafResult:
    """Flag leaf nodes that lack a ``technique_id`` annotation.

    This is a structural safety net behind the prompt-level technique
    annotation floor.  It walks each scenario's attack tree and checks
    that every LEAF node (``gate == LEAF`` or no children) has a
    non-empty ``technique_id``.  AND/OR gate (structural connector)
    nodes are not checked.

    Returns a :class:`BlankLeafResult` with clean and flagged scenarios.
    """
    result = BlankLeafResult()

    for scenario in scenarios:
        violations: list[BlankLeafViolation] = []
        leaves = _collect_leaves(scenario.attack_tree.root)

        for leaf in leaves:
            if not leaf.technique_id:
                violations.append(
                    BlankLeafViolation(
                        node_id=leaf.id,
                        label=leaf.label,
                        zone=leaf.zone,
                    )
                )

        if violations:
            node_ids = [v.node_id for v in violations]
            logger.warning(
                "Scenario %s has %d leaf node(s) without technique_id: %s",
                scenario.scenario_id,
                len(violations),
                ", ".join(node_ids),
            )
            result.flagged_scenarios.append((scenario, violations))
        else:
            result.clean_scenarios.append(scenario)

    return result


# ---------------------------------------------------------------------------
# Parsimony pruning — data structures
# ---------------------------------------------------------------------------


@dataclass
class PrunedNode:
    """Record of a single pruned leaf node."""

    node_id: str
    label: str
    parent_gate: str  # "AND" or "OR"
    reason: str  # why it was safe to prune


@dataclass
class ParsimonyResult:
    """Result of parsimony pruning across a batch of scenarios."""

    compliant_scenarios: list[ScenarioEnvelope] = field(default_factory=list)
    pruned_scenarios: list[tuple[ScenarioEnvelope, list[PrunedNode]]] = field(
        default_factory=list
    )
    unprunable_scenarios: list[tuple[ScenarioEnvelope, int, int]] = field(
        default_factory=list
    )


# ---------------------------------------------------------------------------
# Parsimony pruning — helpers
# ---------------------------------------------------------------------------


def _collect_technique_ids(node: AttackTreeNode) -> set[str]:
    """Walk a tree and return the set of unique technique_ids."""
    ids: set[str] = set()
    if node.technique_id:
        ids.add(node.technique_id)
    if node.children:
        for child in node.children:
            ids.update(_collect_technique_ids(child))
    return ids


def _collect_leaves(node: AttackTreeNode) -> list[AttackTreeNode]:
    """Collect all LEAF nodes in the tree."""
    if node.gate == GateType.LEAF:
        return [node]
    leaves: list[AttackTreeNode] = []
    if node.children:
        for child in node.children:
            leaves.extend(_collect_leaves(child))
    return leaves


def _find_parent(root: AttackTreeNode, target_id: str) -> AttackTreeNode | None:
    """Find the parent of the node with the given id."""
    if root.children:
        for child in root.children:
            if child.id == target_id:
                return root
            result = _find_parent(child, target_id)
            if result is not None:
                return result
    return None


def _sibling_labels(parent: AttackTreeNode, node_id: str) -> list[str]:
    """Return labels of siblings (other children of the same parent)."""
    if not parent.children:
        return []
    return [c.label for c in parent.children if c.id != node_id]


def _token_overlap_ratio(label: str, siblings: list[str]) -> float:
    """Compute how much a label's tokens overlap with sibling labels.

    Higher ratio = more redundant = better pruning candidate.
    """
    if not siblings:
        return 0.0
    tokens = set(label.lower().split())
    if not tokens:
        return 0.0
    sibling_tokens: set[str] = set()
    for sib in siblings:
        sibling_tokens.update(sib.lower().split())
    overlap = tokens & sibling_tokens
    return len(overlap) / len(tokens)


def _pruning_priority(
    leaf: AttackTreeNode,
    parent: AttackTreeNode,
    siblings: list[str],
) -> tuple[int, float, int]:
    """Return a sort key for pruning priority.

    Lower values = prune first.
    Priority order:
      1. AND-gate children before OR-gate children (AND=0, OR=1)
      2. Higher token overlap with siblings (negate for ascending sort)
      3. Shorter labels (less semantic content)
    """
    gate_priority = 0 if parent.gate == GateType.AND else 1
    overlap = _token_overlap_ratio(leaf.label, siblings)
    return (gate_priority, -overlap, len(leaf.label))


def _remove_child(parent: AttackTreeNode, child_id: str) -> None:
    """Remove a child node from a parent's children list."""
    if parent.children:
        parent.children = [c for c in parent.children if c.id != child_id]


def _repair_tree_model(root_dict: dict[str, Any]) -> dict[str, Any]:
    """Apply _repair_node to collapse single-child gates after pruning."""
    return _repair_node(root_dict)


# ---------------------------------------------------------------------------
# Parsimony pruning — main function
# ---------------------------------------------------------------------------


def enforce_parsimony(
    scenarios: list[ScenarioEnvelope],
    max_leaf_factor: int = 2,
    max_leaf_offset: int = 2,
) -> ParsimonyResult:
    """Prune excess unannotated leaves from attack trees.

    For each scenario, computes a leaf budget based on the number of
    unique technique_ids in the tree using :func:`compute_leaf_budget`.

    The ``max_leaf_factor`` and ``max_leaf_offset`` parameters are
    deprecated and ignored -- the canonical formula lives in
    ``compute_leaf_budget()``.  They are retained for API compatibility.

    Leaves without a technique_id or typed action are pruning candidates.
    They are removed one at a time (most redundant first) until the leaf
    count is within budget, or no more safe candidates remain. Typed leaves
    are preserved even when that makes the scenario unprunable.

    After pruning, single-child AND/OR gates are collapsed via
    ``_repair_node`` and the resulting tree is re-validated with Pydantic.
    """
    from asago_scenario_generator.pipeline.generate.constants import compute_leaf_budget

    result = ParsimonyResult()

    for scenario in scenarios:
        tree = scenario.attack_tree
        technique_ids = _collect_technique_ids(tree.root)
        technique_count = len(technique_ids)

        budget = compute_leaf_budget(technique_count)

        leaves = _collect_leaves(tree.root)
        leaf_count = len(leaves)

        if leaf_count <= budget:
            result.compliant_scenarios.append(scenario)
            continue

        # Deep-copy so we don't mutate the original
        pruned_scenario = copy.deepcopy(scenario)
        pruned_root = pruned_scenario.attack_tree.root
        pruned_nodes: list[PrunedNode] = []

        while True:
            current_leaves = _collect_leaves(pruned_root)
            current_leaf_count = len(current_leaves)

            if current_leaf_count <= budget:
                break

            # Find pruning candidates: unannotated leaves
            candidates: list[tuple[AttackTreeNode, AttackTreeNode, list[str]]] = []
            for leaf in current_leaves:
                if leaf.technique_id:
                    continue  # never prune annotated leaves
                if leaf.action is not None:
                    continue  # never prune leaves with typed actions (cmps.9 review)
                parent = _find_parent(pruned_root, leaf.id)
                if parent is None:
                    continue  # root node, can't prune
                # Must not leave parent with fewer than 2 children
                # (we'll handle the collapse after removal, but we need
                # at least 2 children to remove one safely)
                if parent.children and len(parent.children) < 2:
                    continue  # already at minimum
                siblings = _sibling_labels(parent, leaf.id)
                candidates.append((leaf, parent, siblings))

            if not candidates:
                break  # no safe candidates remain

            # Sort by pruning priority
            candidates.sort(key=lambda x: _pruning_priority(x[0], x[1], x[2]))

            # Prune the best candidate
            leaf, parent, siblings = candidates[0]
            _remove_child(parent, leaf.id)
            pruned_nodes.append(
                PrunedNode(
                    node_id=leaf.id,
                    label=leaf.label,
                    parent_gate=parent.gate.value,
                    reason=(
                        f"Unannotated leaf under {parent.gate.value} gate; "
                        f"token overlap with siblings: "
                        f"{_token_overlap_ratio(leaf.label, siblings):.0%}"
                    ),
                )
            )

            # If parent now has exactly 1 child, collapse it
            if parent.children and len(parent.children) == 1:
                # Convert to dict, repair, convert back
                root_dict = pruned_root.model_dump()
                repaired_dict = _repair_tree_model(root_dict)
                pruned_root = AttackTreeNode.model_validate(repaired_dict)
                pruned_scenario.attack_tree = AttackTree(
                    id=pruned_scenario.attack_tree.id,
                    seed_id=pruned_scenario.attack_tree.seed_id,
                    goal=pruned_scenario.attack_tree.goal,
                    root=pruned_root,
                )

        # Re-validate the pruned tree
        final_leaves = _collect_leaves(pruned_root)
        final_leaf_count = len(final_leaves)

        if final_leaf_count <= budget:
            # Validate with Pydantic to ensure structural integrity
            try:
                pruned_scenario.attack_tree = AttackTree.model_validate(
                    pruned_scenario.attack_tree.model_dump()
                )
                result.pruned_scenarios.append((pruned_scenario, pruned_nodes))
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Pruned tree for %s failed Pydantic validation: %s",
                    scenario.scenario_id,
                    exc,
                )
                result.unprunable_scenarios.append((scenario, leaf_count, budget))
        else:
            result.unprunable_scenarios.append((scenario, final_leaf_count, budget))

    return result


# ---------------------------------------------------------------------------
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
        if not scenario.attack_tree or not scenario.attack_tree.root:
            result.clean_scenarios.append(scenario)
            continue

        or_gate_count = _count_or_gates(scenario.attack_tree.root)
        if or_gate_count == 0:
            result.clean_scenarios.append(scenario)
            continue

        # Tree has OR gates -- check that Gherkin has multiple Scenario blocks.
        from asago_scenario_generator.models.scenario import (
            BehaviorSpec as _BehaviorSpec,
        )

        gherkin = ""
        if scenario.behavior_spec and isinstance(scenario.behavior_spec, _BehaviorSpec):
            gherkin = scenario.behavior_spec.gherkin_text or ""
        if not gherkin:
            result.clean_scenarios.append(scenario)
            continue

        scenario_block_count = len(_GHERKIN_SCENARIO_RE.findall(gherkin))

        if scenario_block_count <= 1:
            violation = GateLogicViolation(
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
