#!/usr/bin/env python3
"""List permission qualifiers an ICA states that its failure criterion drops, offline.

The argument is a runs directory. Every
``<run>/stages/generate/output/scenarios/*.yaml`` handoff that carries a
``uca`` block (schema v5) is read; nothing is sent anywhere::

    uv run python scripts/permission_qualifier_sweep.py RUNS_DIR \
        [--run-glob 'PATTERN' ...] [--exclude-run-glob 'PATTERN' ...] \
        [--out DIR]

The unsafe control action is ``uca.statement`` plus ``uca.context``; the
Stage 5 outcome is ``semantic_failure_criterion`` (the authored
``semantic_proposition``, kept verbatim) plus
``discriminating_condition.statement``.

A qualifier is a phrase that restricts the unsafe action to a party or a
check, in one of three families (``FAMILIES`` holds the exact patterns):

- ``authorization``: unauthorized; not authorized for, by or to; without
  authorization, permission or consent; beyond the session scope.
- ``verification``: an unverified or unauthenticated principal; identity,
  ownership or authorization not verified, confirmed or validated, or
  unknown; acting without or before verifying them.
- ``other_party``: another, other or a different customer, user or other
  party; not the owner, guest or host; neither the owner, guest nor host;
  not owned by, not accessible to, not a party to, other than the
  authenticated; does not match, belong or pertain to the authenticated,
  session, owner or authorized party.

The lists leave out wording that usually restricts content rather than a
party: "not allowed" or "not permitted" (an eligibility flag), "third-party"
(authorship), "unverified" content, and "does not match" a value.

Each handoff is classified:

- ``no_qualifier``: the ICA states none.
- ``kept``: every ICA family appears in the outcome text.
- ``paraphrased``: the outcome states a qualifier of another family only,
  for example an unauthorized recipient restated as a customer who is not a
  party to the record. Usually the same restriction; review by hand.
- ``condition_only``: the outcome text states no qualifier, but a condition
  comparison is ``ne`` with an operand path naming the authenticated,
  session or current actor; the identity mismatch is carried structurally.
- ``dropped``: neither text nor condition carries a qualifier. A candidate
  drop, not a verdict: the pattern lists cannot see every paraphrase.

``--out`` writes ``rows.jsonl`` (one row per handoff with a qualifier) and
``summary.json``; without it the summary prints to stdout.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

SCENARIOS_GLOB = "*/stages/generate/output/scenarios/*.yaml"

_PARTY = (
    r"(?:customer|user|guest|host|account|person|patient|member|individual"
    r"|party|client|owner|principal)"
)
_ANCHOR = r"(?:authenticated|session|account holder|owner|guest|host|authori[sz]ed)"
_SUBJECT = r"(?:identity|ownership|owner|authori[sz]ation|membership)"

FAMILIES: Mapping[str, tuple[str, ...]] = {
    "authorization": (
        r"\bunauthori[sz]ed\b",
        r"\bnot (?:\w+ ){0,3}authori[sz]ed (?:for|by|to)\b",
        r"\bwithout (?:\w+ ){0,3}(?:authori[sz]ation|permission|consent)\b",
        r"\b(?:lacks?|no) (?:\w+ ){0,2}(?:authori[sz]ation|permission)\b",
        r"\bbeyond (?:\w+ ){0,2}(?:authori[sz]ation|permissions?|session scope)\b",
    ),
    "verification": (
        rf"\bunverified (?:\w+ )?{_PARTY}\b",
        r"\bunauthenticated\b",
        r"\bnot (?:been )?authenticated\b",
        rf"\b{_SUBJECT}\b[^.]{{0,40}}?\b(?:is|are|was|were|been) (?:not )?(?:yet )?"
        r"(?:verified|confirmed|validated|unknown)\b",
        rf"\b(?:without|before) (?:\w+ ){{0,2}}(?:verifying|confirming|validating"
        rf"|verification of)\b(?:\W+\w+){{0,4}}?\W+(?:{_SUBJECT}|authenticated)\b",
        rf"\bfails? to (?:verify|authenticate|confirm)\b(?:\W+\w+){{0,3}}?\W+{_SUBJECT}\b",
    ),
    "other_party": (
        rf"\b(?:another|other|a different|different) {_PARTY}(?:s|'s|_id)?\b",
        r"\bnot (?:the |a |its )?(?:account holder|owner|record owner|guest|host)\b",
        r"\bneither the (?:guest|host|owner)\b",
        r"\b(?:not owned by|does not own|do not own)\b",
        r"\bnot accessible to\b",
        r"\bnot (?:a |the )?part(?:y|ies) to\b",
        r"\bnot part of the (?:authenticated|session|current)\b",
        r"\bnot associated with\b",
        r"\bnot (?:their|his|her|its) own\b",
        r"\bsomeone else\b",
        r"\bother than the (?:authenticated|current|logged[- ]in|session)\b",
        r"\b(?:wrong|incorrect) (?:\w+ or )?(?:customer|user|account|recipient"
        r"|person|patient|party)\b",
        r"\b(?:differs?|different) from the (?:\w+ ){0,3}(?:session|authenticated"
        r"|identity)\b",
        rf"\b(?:not|no longer) (?:match|belong|pertain)\w*(?: to)?\b"
        rf"(?:\W+\w+){{0,3}}?\W+{_ANCHOR}\b",
    ),
}

_COMPILED = {
    family: tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)
    for family, patterns in FAMILIES.items()
}
_ACTOR_PATH = re.compile(r"authenticated|session|current_(?:user|actor)|actor_id")


def qualifier_hits(text: str) -> dict[str, list[str]]:
    """Return the matched phrases of each family found in ``text``."""
    hits: dict[str, list[str]] = {}
    for family, patterns in _COMPILED.items():
        found = [
            match.group(0) for pattern in patterns for match in pattern.finditer(text)
        ]
        if found:
            hits[family] = found
    return hits


def _operand_path(operand: Any) -> str:
    if isinstance(operand, Mapping):
        return str(operand.get("path") or "")
    return ""


def condition_names_actor_mismatch(condition: Any) -> bool:
    """Return whether a comparison is ``ne`` against the acting identity."""
    if not isinstance(condition, Mapping):
        return False
    for comparison in condition.get("comparisons") or ():
        if not isinstance(comparison, Mapping) or comparison.get("op") != "ne":
            continue
        paths = (
            _operand_path(comparison.get("left")),
            _operand_path(comparison.get("right")),
        )
        if any(_ACTOR_PATH.search(path) for path in paths):
            return True
    return False


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def classify(handoff: Mapping[str, Any]) -> dict[str, Any] | None:
    """Classify one handoff, or return None when it has no ``uca`` block."""
    uca = handoff.get("uca")
    if not isinstance(uca, Mapping):
        return None
    ica_text = " ".join(
        filter(None, (_text(uca.get("statement")), _text(uca.get("context"))))
    )
    condition = handoff.get("discriminating_condition")
    proposition = _text(handoff.get("semantic_failure_criterion"))
    condition_statement = (
        _text(condition.get("statement")) if isinstance(condition, Mapping) else ""
    )
    ica_hits = qualifier_hits(ica_text)
    outcome_hits = qualifier_hits(f"{proposition} {condition_statement}")
    missing = sorted(set(ica_hits) - set(outcome_hits))
    if not ica_hits:
        status = "no_qualifier"
    elif not missing:
        status = "kept"
    elif outcome_hits:
        status = "paraphrased"
    elif condition_names_actor_mismatch(condition):
        status = "condition_only"
    else:
        status = "dropped"
    return {
        "scenario_id": handoff.get("scenario_id"),
        "status": status,
        "ica_qualifiers": ica_hits,
        "outcome_qualifiers": outcome_hits,
        "missing_families": missing,
        "uca_statement": _text(uca.get("statement")),
        "uca_context": _text(uca.get("context")),
        "semantic_failure_criterion": proposition,
        "condition_statement": condition_statement,
    }


def _handoff_paths(
    runs_dir: Path, run_globs: Sequence[str], exclude_globs: Sequence[str]
) -> Iterable[Path]:
    for path in sorted(runs_dir.glob(SCENARIOS_GLOB)):
        run = path.relative_to(runs_dir).parts[0]
        if run_globs and not any(fnmatch.fnmatch(run, p) for p in run_globs):
            continue
        if any(fnmatch.fnmatch(run, p) for p in exclude_globs):
            continue
        yield path


def sweep(
    runs_dir: Path, run_globs: Sequence[str] = (), exclude_globs: Sequence[str] = ()
) -> tuple[list[dict], dict]:
    """Classify every handoff under ``runs_dir``; return rows and a summary."""
    rows: list[dict[str, Any]] = []
    statuses: Counter[str] = Counter()
    runs: set[str] = set()
    skipped = 0
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    for path in _handoff_paths(runs_dir, run_globs, exclude_globs):
        run = path.relative_to(runs_dir).parts[0]
        text = path.read_text(encoding="utf-8")
        # A handoff without a top-level uca block cannot be classified; skip
        # the parse.
        handoff = yaml.load(text, Loader=loader) if "\nuca:" in text else None
        row = classify(handoff) if isinstance(handoff, Mapping) else None
        if row is None:
            skipped += 1
            continue
        runs.add(run)
        statuses[row["status"]] += 1
        if row["status"] != "no_qualifier":
            rows.append({"run": run, "file": path.name, **row})
    scanned = sum(statuses.values())
    summary = {
        "runs": len(runs),
        "handoffs": scanned,
        "skipped_without_uca": skipped,
        "with_ica_qualifier": scanned - statuses["no_qualifier"],
        "status": dict(sorted(statuses.items())),
    }
    return rows, summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "List permission, verification and other-party qualifiers stated by "
            "a handoff's unsafe control action but absent from its failure "
            "criterion and condition. Reads saved handoffs only."
        )
    )
    parser.add_argument("runs_dir", type=Path, help="directory holding run folders")
    parser.add_argument(
        "--run-glob",
        action="append",
        default=[],
        help="only runs whose folder name matches this pattern (repeatable)",
    )
    parser.add_argument(
        "--exclude-run-glob",
        action="append",
        default=[],
        help="skip runs whose folder name matches this pattern (repeatable)",
    )
    parser.add_argument(
        "--out", type=Path, help="write rows.jsonl and summary.json here"
    )
    args = parser.parse_args(argv)
    if not args.runs_dir.is_dir():
        parser.error(f"not a directory: {args.runs_dir}")
    rows, summary = sweep(args.runs_dir, args.run_glob, args.exclude_run_glob)
    if args.out is not None:
        args.out.mkdir(parents=True, exist_ok=True)
        with (args.out / "rows.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        (args.out / "summary.json").write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8"
        )
    json.dump(summary, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
