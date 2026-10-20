"""Pinned risk-scheme vocabularies: OWASP LLM 2026, OWASP Agentic 2026, NIST AI 600-1.

Each vocabulary file declares its scheme and edition; a mismatch with this
module's expectation, an unknown scheme, or an object ID outside the
vocabulary raises ``ValueError``.  Nothing is skipped silently.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import yaml

from asago_scenario_generator.data.paths import DATA_ROOT

EDITION = "2026"
OWASP_LLM_SCHEME = "owasp-llm-2026"
OWASP_ASI_SCHEME = "owasp-asi-2026"
NIST_SCHEME = "nist-ai-rmf"
SCHEMES = (NIST_SCHEME, OWASP_ASI_SCHEME, OWASP_LLM_SCHEME)

_NIST_EDITION = "AI 600-1 (July 2024)"
_TAXONOMIES = DATA_ROOT / "taxonomies"
_FILES = {
    OWASP_LLM_SCHEME: _TAXONOMIES / "owasp-llm-top10" / "owasp-llm-top10-2026.yaml",
    OWASP_ASI_SCHEME: _TAXONOMIES
    / "owasp-agentic-top10"
    / "owasp-agentic-top10-2026.yaml",
    NIST_SCHEME: _TAXONOMIES / "nist-ai-600-1" / "nist-ai-600-1.yaml",
}
_EDITIONS = {
    OWASP_LLM_SCHEME: EDITION,
    OWASP_ASI_SCHEME: EDITION,
    NIST_SCHEME: _NIST_EDITION,
}
_LABEL_PREFIX = {
    OWASP_LLM_SCHEME: "OWASP",
    OWASP_ASI_SCHEME: "OWASP",
    NIST_SCHEME: "NIST AI 600-1",
}


@dataclass(frozen=True)
class SchemeEntry:
    scheme: str
    object_id: str
    code: str | None
    title: str


def _vocabulary_path(scheme: str) -> Path:
    try:
        return _FILES[scheme]
    except KeyError:
        raise ValueError(
            f"unknown risk scheme {scheme!r}; expected one of {sorted(_FILES)}"
        ) from None


@functools.lru_cache(maxsize=8)
def _load_cached(scheme: str, path_str: str) -> Mapping[str, SchemeEntry]:
    with open(path_str, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    for key, expected in (("scheme", scheme), ("edition", _EDITIONS[scheme])):
        if data.get(key) != expected:
            raise ValueError(
                f"{path_str} declares {key} {data.get(key)!r}; expected {expected!r}"
            )
    entries: dict[str, SchemeEntry] = {}
    for raw in data["entries"]:
        entry = SchemeEntry(scheme, raw["object_id"], raw["code"], raw["title"])
        if entry.object_id in entries:
            raise ValueError(f"{path_str} repeats {entry.object_id!r}")
        entries[entry.object_id] = entry
    return entries


def _load_vocabulary(
    scheme: str, path: str | Path | None = None
) -> Mapping[str, SchemeEntry]:
    default = _vocabulary_path(scheme)  # raises for an unknown scheme
    return _load_cached(scheme, str(path if path is not None else default))


def load_vocabulary(scheme: str) -> Mapping[str, SchemeEntry]:
    """Entries of ``scheme`` keyed by ``object_id``."""
    return _load_vocabulary(scheme)


def parse_object_id(scheme: str, object_id: str) -> SchemeEntry:
    """The vocabulary entry for ``object_id``; ``ValueError`` if it is not one."""
    try:
        return load_vocabulary(scheme)[object_id]
    except KeyError:
        raise ValueError(
            f"{object_id!r} is not an {scheme} entry; "
            f"this producer reads OWASP {EDITION} and NIST AI 600-1"
        ) from None


def scheme_label(scheme: str, object_id: str) -> str:
    """Human label: ``OWASP LLM03:2026 Excessive Agency`` and its siblings."""
    entry = parse_object_id(scheme, object_id)
    prefix = _LABEL_PREFIX[scheme]
    if entry.code is None:
        return f"{prefix} {entry.title}"
    return f"{prefix} {entry.code}:{EDITION} {entry.title}"


_FAMILY_WORD = re.compile(r"(?<![a-z])(asi|agentic|llm)")


def scheme_family(source: str) -> str | None:
    """The edition-bearing OWASP family ``source`` names, in any spelling.

    Case, ``-``/``_``/space separators and URLs do not matter:
    ``owasp-llm-2026``, ``OWASP-LLM-2.0``, ``owasp_llm_2025`` and
    ``https://genai.owasp.org/llm-top-10/2025`` all name ``owasp-llm``; an
    ``asi`` or ``agentic`` word names ``owasp-asi``. Any other source that
    mentions OWASP is the family ``owasp``; a source without OWASP is None.
    """
    text = source.lower()
    if "owasp" not in text:
        return None
    word = _FAMILY_WORD.search(text.replace("owasp", " "))
    if word is None:
        return "owasp"
    return "owasp-llm" if word.group(1) == "llm" else "owasp-asi"


def is_edition_scheme(source: str) -> bool:
    """Whether ``source`` names an edition-bearing OWASP scheme, in any spelling."""
    return scheme_family(source) is not None


def is_no_match(predicate_id: str) -> bool:
    """Whether a mapping predicate asserts that there is no match."""
    return "nomatch" in predicate_id.lower()
