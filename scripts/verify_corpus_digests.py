#!/usr/bin/env python3
"""Recompute every persisted digest the replay corpus manifest names.

Reads ``$ASAGO_REPLAY_CORPUS/MANIFEST.json``, recomputes each digest from the
recording (or, for a producer prompt template, from the template file at the
recorded producer commit) with the shared core's canonical-JSON and digest
functions, and prints a matched/total report per encoding.

A digest the stored evidence cannot reproduce is reported as unrecomputable
with the reason, so the report never hides an entry. The command exits 1 when a
recomputable digest differs from its recorded value.

Usage:
    ASAGO_REPLAY_CORPUS=/path/to/replay-corpus \\
        uv run python scripts/verify_corpus_digests.py
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from asago_contracts_core import CONSUMER_ENCODING, canonical_json_bytes, sha256_hex

PRODUCER = Path(__file__).resolve().parents[1]


@dataclass
class Outcome:
    """The recomputation result for one encoding."""

    matched: int = 0
    recorded_mismatch: int = 0
    mismatched: list[str] = field(default_factory=list)
    unrecomputable: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return (
            self.matched
            + self.recorded_mismatch
            + len(self.mismatched)
            + len(self.unrecomputable)
        )


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(value: bytes) -> str:
    return sha256_hex(value)


def _canonical_sha256(value: Any) -> str:
    return _sha256(canonical_json_bytes(value, encoding=CONSUMER_ENCODING))


def _base(corpus: Path, case: dict[str, Any]) -> Path:
    """Return the directory a case's ``source`` paths resolve against."""

    recording = corpus / case["recording"]
    if case["recording"].startswith("receipts/"):
        # The recording is the adapter item; its sources name the tool item
        # under the stage's output directory.
        return recording.parents[1]
    return recording


def _package_manifest_digest(manifest: dict[str, Any]) -> str:
    payload = {
        key: value for key, value in manifest.items() if key != "manifest_digest"
    }
    return _canonical_sha256(payload)


def _record(
    outcomes: dict[str, Outcome], encoding: str, label: str, expected: str, found: str
) -> None:
    outcome = outcomes.setdefault(encoding, Outcome())
    if expected == found:
        outcome.matched += 1
    else:
        outcome.mismatched.append(f"{label}: recorded {expected}, recomputed {found}")


def _skip(outcomes: dict[str, Outcome], encoding: str, label: str, reason: str) -> None:
    outcomes.setdefault(encoding, Outcome()).unrecomputable.append(f"{label}: {reason}")


def _template_paths(commit: str, cache: dict[str, list[str]]) -> list[str]:
    if commit not in cache:
        completed = subprocess.run(
            ["git", "-C", str(PRODUCER), "ls-tree", "-r", "--name-only", commit],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise SystemExit(f"git ls-tree {commit} failed: {completed.stderr.strip()}")
        cache[commit] = [
            path for path in completed.stdout.splitlines() if path.endswith(".j2")
        ]
    return cache[commit]


def _template_sha256s(
    commit: str, template: str, cache: dict[str, list[str]]
) -> set[str]:
    """Return every digest of a commit's template files with this basename."""

    digests: set[str] = set()
    for path in _template_paths(commit, cache):
        if path.rsplit("/", 1)[-1] != template:
            continue
        completed = subprocess.run(
            ["git", "-C", str(PRODUCER), "show", f"{commit}:{path}"],
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise SystemExit(f"git show {commit}:{path} failed")
        digests.add(_sha256(completed.stdout))
    return digests


def _authoring_attempts(path: Path) -> list[dict[str, Any]]:
    evidence = _load(path)
    return [
        attempt for attempt in evidence.get("attempts", []) if attempt.get("prompt")
    ]


def _check_prompt_hashes(
    corpus: Path,
    case: dict[str, Any],
    outcomes: dict[str, Outcome],
    templates: dict[str, list[str]],
) -> None:
    base = _base(corpus, case)
    commit = (case.get("commits") or {}).get("producer")
    for entry in case.get("prompt_hashes", []):
        encoding = entry["encoding"]
        label = (
            f"{case['id']} "
            f"{entry.get('role') or entry.get('template') or entry.get('version')}"
        )
        if encoding == "authoring-prompt-sha256-v1":
            item = entry.get("item") or Path(case["recording_item"]).name
            evidence = base / "output" / f"{item}.failure-evidence.json"
            attempts = _authoring_attempts(evidence)
            rendered = {
                _sha256(
                    "\0".join(
                        (
                            attempt["stage"],
                            attempt["prompt"]["version"],
                            attempt["prompt"]["system"],
                            attempt["prompt"]["user"],
                        )
                    ).encode("utf-8")
                )
                for attempt in attempts
                if attempt["prompt"].get("version") == entry["version"]
            }
            if entry["sha256"] in rendered:
                outcomes.setdefault(encoding, Outcome()).matched += 1
            else:
                outcomes.setdefault(encoding, Outcome()).mismatched.append(
                    f"{label}: recorded {entry['sha256']} is not in {sorted(rendered)}"
                )
        elif encoding == "producer-prompt-template-sha256-v1":
            if not commit:
                _skip(outcomes, encoding, label, "the case records no producer commit")
                continue
            found = _template_sha256s(commit, entry["template"], templates)
            if entry["sha256"] in found:
                outcomes.setdefault(encoding, Outcome()).matched += 1
            else:
                outcomes.setdefault(encoding, Outcome()).mismatched.append(
                    f"{label}: recorded {entry['sha256']} is not in {sorted(found)}"
                )
        elif encoding == "target-conversation-canonical-json-sha256-v1":
            receipt_path = base / entry["source"].split(" attempts")[0]
            request = _load(receipt_path)["attempts"][0]["turns"][0]["request"]
            _record(
                outcomes, encoding, label, entry["sha256"], _canonical_sha256(request)
            )
        elif encoding == "setup-request-canonical-json-sha256-v1":
            setup = _load(base / entry["source"])
            _record(
                outcomes, encoding, label, entry["sha256"], _canonical_sha256(setup)
            )
        elif encoding == "judge-request-sha256-v1":
            _skip(
                outcomes,
                encoding,
                label,
                "the judge reports the request digest; the corpus stores no request body",
            )
        else:
            _skip(outcomes, encoding, label, "unknown prompt encoding")


def _check_package_digests(
    corpus: Path, case: dict[str, Any], outcomes: dict[str, Outcome]
) -> None:
    base = _base(corpus, case)
    for entry in case.get("package_digests", []):
        encoding = entry["encoding"]
        label = f"{case['id']} {entry['source']}"
        source = entry["source"]
        if source.startswith("execution-receipt.json"):
            _skip(
                outcomes,
                encoding,
                label,
                "the sealed receipt carries the digest; the corpus stores no package manifest",
            )
            continue
        manifest_path = base / source.split(" manifest_digest")[0]
        _record(
            outcomes,
            encoding,
            label,
            entry["digest"],
            _package_manifest_digest(_load(manifest_path)),
        )


def _check_receipt_digests(
    corpus: Path, case: dict[str, Any], outcomes: dict[str, Outcome]
) -> None:
    for entry in case.get("receipt_digests", []):
        encoding = entry["encoding"]
        label = f"{case['id']} {entry['source']}"
        if entry.get("mismatch"):
            tool_scenario = "/".join(Path(case["recording"]).parts[-2:])
            summary = _load(_base(corpus, case) / "summary.json")
            recorded = next(
                (
                    item.get("receipt_sha256")
                    for item in summary.get("items", [])
                    if item.get("id") == tool_scenario
                ),
                None,
            )
            receipt = corpus / case["recording"] / case["recording_item"]
            actual = _sha256(receipt.read_bytes())
            if recorded == entry["digest"] and actual != recorded:
                outcomes.setdefault(encoding, Outcome()).recorded_mismatch += 1
            else:
                outcomes.setdefault(encoding, Outcome()).mismatched.append(
                    f"{label}: summary records {recorded}, the file is {actual}, "
                    f"the manifest names {entry['digest']}"
                )
            continue
        found = _sha256((corpus / entry["source"]).read_bytes())
        _record(outcomes, encoding, label, entry["digest"], found)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        type=Path,
        help="the replay corpus (defaults to $ASAGO_REPLAY_CORPUS)",
    )
    args = parser.parse_args(argv)

    corpus = args.corpus
    if corpus is None and os.environ.get("ASAGO_REPLAY_CORPUS"):
        corpus = Path(os.environ["ASAGO_REPLAY_CORPUS"])
    if corpus is None:
        print("error: set ASAGO_REPLAY_CORPUS or pass --corpus", file=sys.stderr)
        return 2
    if not (corpus / "MANIFEST.json").is_file():
        print(f"error: {corpus}/MANIFEST.json is missing", file=sys.stderr)
        return 2

    manifest = _load(corpus / "MANIFEST.json")
    outcomes: dict[str, Outcome] = {}
    templates: dict[str, list[str]] = {}
    for case in manifest["cases"]:
        _check_package_digests(corpus, case, outcomes)
        _check_prompt_hashes(corpus, case, outcomes, templates)
        _check_receipt_digests(corpus, case, outcomes)

    matched = mismatched = unrecomputable = recorded_mismatch = 0
    for encoding in sorted(outcomes):
        outcome = outcomes[encoding]
        matched += outcome.matched
        mismatched += len(outcome.mismatched)
        unrecomputable += len(outcome.unrecomputable)
        recorded_mismatch += outcome.recorded_mismatch
        print(
            f"{encoding}: {outcome.matched}/{outcome.total} matched, "
            f"{outcome.recorded_mismatch} recorded mismatches confirmed, "
            f"{len(outcome.mismatched)} mismatched, "
            f"{len(outcome.unrecomputable)} unrecomputable"
        )
        for detail in outcome.mismatched:
            print(f"  MISMATCH {detail}")
        for detail in outcome.unrecomputable:
            print(f"  UNRECOMPUTABLE {detail}")
    total = matched + recorded_mismatch + mismatched + unrecomputable
    print(
        f"total: {matched}/{total} matched, {recorded_mismatch} recorded mismatches "
        f"confirmed, {mismatched} mismatched, {unrecomputable} unrecomputable"
    )
    return 1 if mismatched else 0


if __name__ == "__main__":
    sys.exit(main())
