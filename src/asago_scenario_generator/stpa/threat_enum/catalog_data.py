"""Catalog keyword sets and matching logic for Stage 4.

Deterministic keyword matching against ATLAS and OWASP Agentic catalog
entries. The matcher's precision/recall should be measured against
fixtures during development. An unmapped ICA is labeled "unmapped"
(not "novel") because a low-recall keyword matcher may miss valid
catalog correspondences.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.enriched_threat_set import CatalogMapping

__all__ = [
    "ATLAS_KEYWORDS",
    "ATLAS_TECHNIQUE_NAMES",
    "OWASP_AGENTIC_KEYWORDS",
    "OWASP_AGENTIC_NAMES",
    "OWASP_AGENTIC_THREAT_IDS",
    "match_catalog",
]

# ---------------------------------------------------------------------------
# ATLAS keyword sets
# ---------------------------------------------------------------------------

ATLAS_KEYWORDS: dict[str, list[str]] = {
    "AML.T0051.000": [
        "prompt injection",
        "direct prompt",
        "instruction override",
    ],
    "AML.T0051.001": [
        "indirect prompt",
        "retrieved content",
        "rag poisoning",
    ],
    "AML.T0053": [
        "tool invocation",
        "tool use",
        "api call",
        "unauthorized tool",
    ],
    "AML.T0054": [
        "jailbreak",
        "safety bypass",
        "guardrail bypass",
    ],
    "AML.T0056": [
        "system prompt extraction",
        "prompt leak",
        "system message leak",
    ],
    "AML.T0057": [
        "data leakage",
        "data exfiltration",
        "information disclosure",
    ],
    "AML.T0070": [
        "rag poisoning",
        "retrieval poisoning",
        "knowledge base poison",
    ],
    "atlas-prompt-injection": [
        "prompt injection",
        "instruction injection",
        "instruction override",
    ],
}

ATLAS_TECHNIQUE_NAMES: dict[str, str] = {
    "AML.T0051.000": "Prompt Injection (Direct)",
    "AML.T0051.001": "Prompt Injection (Indirect)",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0054": "Jailbreak: Few-shot",
    "AML.T0056": "LLM Prompt Extraction",
    "AML.T0057": "Data Exfiltration via ML Model",
    "AML.T0070": "Poisoning via RAG",
    "atlas-prompt-injection": "Prompt Injection",
}

# ---------------------------------------------------------------------------
# OWASP Agentic Top 10 keyword sets
# ---------------------------------------------------------------------------

OWASP_AGENTIC_KEYWORDS: dict[str, list[str]] = {
    "T1": [
        "prompt injection",
        "instruction injection",
        "instruction override",
        "direct prompt",
    ],
    "T2-T3": [
        "tool misuse",
        "tool use",
        "tool invocation",
        "api call",
        "unauthorized tool",
        "parameter injection",
    ],
    "T7a": [
        "excessive agency",
        "unauthorized action",
        "executes payment",
        "executes transaction",
        "unauthorized transaction",
    ],
    "T8": [
        "data poisoning",
        "poisoned data",
        "knowledge base poison",
        "retrieval poisoning",
        "rag poisoning",
    ],
    "T9": [
        "deceptive output",
        "misleading",
        "incorrect payment details",
        "misleading payment",
        "deceptive information",
    ],
    "T10": [
        "data leakage",
        "data exfiltration",
        "information disclosure",
        "pii leak",
        "unauthorized disclosure",
    ],
    "T15": [
        "supply chain",
        "third-party",
        "dependency",
        "external content",
        "indirect entry point",
    ],
}

OWASP_AGENTIC_NAMES: dict[str, str] = {
    "T1": "Prompt Injection",
    "T2-T3": "Agentic Tool Misuse",
    "T7a": "Excessive Agency",
    "T8": "Data Poisoning",
    "T9": "Deceptive Output",
    "T10": "Data Leakage",
    "T15": "Supply Chain",
}

# All OWASP Agentic threat IDs (for uncovered-threat analysis).
OWASP_AGENTIC_THREAT_IDS: list[str] = [
    "T1",
    "T2-T3",
    "T7a",
    "T8",
    "T9",
    "T10",
    "T15",
]


def match_catalog(ica_text: str, loss_scenario: str) -> list[CatalogMapping]:
    """Deterministic keyword matching against catalog entries.

    Combines ``ica_text`` and ``loss_scenario`` into a single lowercase
    string and checks for keyword matches against ATLAS and OWASP
    Agentic keyword sets.

    Confidence levels:
    - ``high``: 2 or more keywords matched
    - ``low``: exactly 1 keyword matched

    Args:
        ica_text: The ICA description text.
        loss_scenario: The loss scenario text.

    Returns:
        A list of :class:`CatalogMapping` objects, one per matched
        catalog entry. An empty list means the ICA is unmapped.
    """
    combined_text = (ica_text + " " + loss_scenario).lower()

    mappings = _match_keyword_set(
        combined_text, "ATLAS", ATLAS_KEYWORDS, ATLAS_TECHNIQUE_NAMES
    )
    mappings.extend(
        _match_keyword_set(
            combined_text, "OWASP_AGENTIC", OWASP_AGENTIC_KEYWORDS, OWASP_AGENTIC_NAMES
        )
    )
    return mappings


def _match_keyword_set(
    combined_text: str,
    catalog: str,
    keywords_by_id: dict[str, list[str]],
    names_by_id: dict[str, str],
) -> list[CatalogMapping]:
    """Match combined text against a single catalog's keyword sets.

    Args:
        combined_text: Lowercased text to search for keyword matches.
        catalog: Catalog label (e.g. ``"ATLAS"``).
        keywords_by_id: Mapping from entry ID to list of keywords.
        names_by_id: Mapping from entry ID to human-readable name.

    Returns:
        A list of :class:`CatalogMapping` objects for matched entries.
    """
    mappings: list[CatalogMapping] = []
    for entry_id, keywords in keywords_by_id.items():
        matches = sum(1 for kw in keywords if kw in combined_text)
        if matches > 0:
            confidence = "high" if matches >= 2 else "low"
            mappings.append(
                CatalogMapping(
                    catalog=catalog,
                    id=entry_id,
                    name=names_by_id.get(entry_id, entry_id),
                    confidence=confidence,
                )
            )
    return mappings
