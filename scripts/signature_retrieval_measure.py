#!/usr/bin/env python3
"""Compare the filtered mechanism join with signature retrieval off and on.

    uv run --frozen python scripts/signature_retrieval_measure.py \\
        --units-tsv UNITS.tsv [--unit LABEL PATH ...] --out-dir DIR \\
        [--labels LABELS.jsonl ...] [--label-field label]

Offline: the script reads saved files, writes only to ``--out-dir``, and calls
no model.  Each unit is a label and a saved ``control-structure.yaml``; the
TSV holds one ``label<TAB>path`` per line, and labels must be non-blank and
unique.  A unit whose file is byte-identical to an earlier unit's names it in
``duplicate_of``; aggregates are reported over all loaded units and over
distinct structures.

Each unit runs the authority-filtered join (the one mechanism suggestions
use) twice: ``off`` as the pipeline runs it, and ``on`` with signature
retrieval.  Three numbers are reported per unit and mode, each on its own and
never combined:

- candidates: kept ``(mechanism, path)`` pairs, in total and per mechanism;
- verifier acceptance: from the recorded verifier replies only.  A unit's
  replies are the ``path_verdicts`` of the ``mechanism-suggestion-accounting.yaml``
  beside its structure.  A candidate's status is ``accepted``
  (``mechanism_specific``), ``rejected`` (``adjacent_control``),
  ``insufficient_evidence``, ``conflicting`` (different replies on different
  slots), or ``unverified`` (no reply, or ``no_verdict``).  Acceptance is
  accepted over candidates with a reply; with none it is unavailable;
- usefulness: from saved labels only.  ``--labels`` files hold JSONL rows with
  ``sha256`` (of the structure file), ``mechanism``, ``path`` and the label in
  ``--label-field``: ``correct`` is useful, ``incorrect`` is not, any other
  value is undecided, and a missing or empty one is unlabeled.  Precision is
  useful over useful plus not useful; with neither it is unavailable.

The earlier bar (at most 5 candidates per unit, precision at least 70%) is
printed as a reference line, not applied.

Outputs in ``--out-dir``:

- ``signature-retrieval-candidates.jsonl``: one row per (unit, mode, candidate);
- ``signature-retrieval-counts.json``: per-unit numbers, aggregates and the
  live check;
- ``signature-retrieval-summary.md``: the same as tables;
- ``live-check-candidates.jsonl``: the candidates only signature retrieval
  adds, on distinct structures, that have no recorded reply.  The verifier
  judges a run's candidates in batches of
  ``MECHANISM_SUGGESTION_BATCH_SIZE``, one request each, so a live check needs
  one request per started batch per structure, before any validation repair.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.models.mechanism_suggestion_accounting import (
    MECHANISM_SUGGESTION_ACCOUNTING_FILENAME,
    MECHANISM_SUGGESTION_ACCOUNTING_SCHEMA_VERSION,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.obligation_aware.mechanism_suggestion_provider import (  # noqa: E501
    MECHANISM_SUGGESTION_BATCH_SIZE,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    DroppedCandidate,
    KeptCandidate,
    MechanismCandidate,
    mechanism_join,
)

MODES = ("off", "on")
SMALL_UNIT = 5
"""Reference only: the earlier bar's most candidates per unit."""
PRECISION_BAR = 0.7
"""Reference only: the earlier bar's least precision."""
VERIFIER_STATUSES = (
    "accepted",
    "rejected",
    "insufficient_evidence",
    "conflicting",
    "unverified",
)
USEFULNESS_STATUSES = ("useful", "not_useful", "undecided", "unlabeled")
_RELATIONSHIP_STATUS = {
    "mechanism_specific": "accepted",
    "adjacent_control": "rejected",
    "insufficient_evidence": "insufficient_evidence",
}
_LABEL_STATUS = {"correct": "useful", "incorrect": "not_useful"}

Key = tuple[str, tuple[str, str, str]]
"""``(mechanism, path)``, comparable across typed and plain mechanism IDs."""


def _key(candidate: MechanismCandidate) -> Key:
    return (str(candidate.mechanism), tuple(candidate.path))  # type: ignore[return-value]


@dataclass
class ModeJoin:
    kept: tuple[KeptCandidate, ...] = ()
    dropped: tuple[DroppedCandidate, ...] = ()

    @property
    def candidates(self) -> tuple[MechanismCandidate, ...]:
        return tuple(item.candidate for item in self.kept)


@dataclass
class Unit:
    index: int
    label: str
    path: Path
    digest: str | None = None
    duplicate_of: int | None = None
    error: str | None = None
    modes: dict[str, ModeJoin] = field(default_factory=dict)
    replies: dict[Key, set[str]] | None = None
    """Recorded verifier relationships by candidate; ``None`` without a file."""
    replies_error: str | None = None
    labels: dict[Key, str] = field(default_factory=dict)

    @property
    def loaded(self) -> bool:
        return bool(self.modes)

    def new_candidates(self) -> tuple[MechanismCandidate, ...]:
        """The kept candidates only signature retrieval adds, in its order."""
        if not self.loaded:
            return ()
        off = {_key(item) for item in self.modes["off"].candidates}
        return tuple(
            item for item in self.modes["on"].candidates if _key(item) not in off
        )

    def verifier_status(self, candidate: MechanismCandidate) -> str:
        found = (self.replies or {}).get(_key(candidate), set()) - {"no_verdict"}
        if not found:
            return "unverified"
        if len(found) > 1:
            return "conflicting"
        return _RELATIONSHIP_STATUS.get(next(iter(found)), "unverified")

    def usefulness(self, candidate: MechanismCandidate) -> str:
        label = self.labels.get(_key(candidate))
        if not label:
            return "unlabeled"
        return _LABEL_STATUS.get(label, "undecided")


def _read_tsv(path: Path) -> list[tuple[str, Path]]:
    units = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        label, separator, file_path = line.partition("\t")
        if not separator:
            raise SystemExit(f"{path}:{number}: expected label<TAB>path")
        units.append((label, Path(file_path)))
    return units


def _check_labels(specs: list[tuple[str, Path]]) -> None:
    seen: dict[str, int] = {}
    for index, (label, path) in enumerate(specs):
        if not label.strip():
            raise SystemExit(f"unit {index} ({path}): blank label")
        if label in seen:
            raise SystemExit(
                f"unit {index} ({path}): label {label!r} repeats unit {seen[label]}"
            )
        seen[label] = index


def load_labels(paths: list[Path], label_field: str) -> dict[str, dict[Key, str]]:
    """Read saved labels by structure digest, then ``(mechanism, path)``."""
    labels: dict[str, dict[Key, str]] = {}
    for path in paths:
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            digest = row.get("sha256")
            if not digest:
                continue
            key = (str(row["mechanism"]), tuple(row["path"]))
            labels.setdefault(digest, {})[key] = row.get(label_field) or ""  # type: ignore[index]
    return labels


def _replies(folder: Path) -> tuple[dict[Key, set[str]] | None, str | None]:
    path = folder / MECHANISM_SUGGESTION_ACCOUNTING_FILENAME
    if not path.exists():
        return None, None
    try:
        data = yaml.safe_load(path.read_text())
        version = data.get("schema_version")
        if version != MECHANISM_SUGGESTION_ACCOUNTING_SCHEMA_VERSION:
            return None, f"unsupported schema_version {version!r}"
        replies: dict[Key, set[str]] = {}
        for row in data.get("rows") or ():
            for verdict in row.get("path_verdicts") or ():
                where = verdict["path"]
                key = (
                    str(row["mechanism_id"]),
                    (
                        where["feedback_channel_id"],
                        where["process_model_part_id"],
                        where["end_id"],
                    ),
                )
                replies.setdefault(key, set()).add(verdict["relationship"])
    except Exception as exc:  # noqa: BLE001 - reported per unit
        return None, f"{type(exc).__name__}: {exc}"
    return replies, None


def load_units(
    specs: list[tuple[str, Path]],
    *,
    labels: dict[str, dict[Key, str]] | None = None,
) -> list[Unit]:
    """Load every unit and run both joins, marking byte-identical copies."""
    _check_labels(specs)
    first_by_digest: dict[str, int] = {}
    units = []
    for index, (label, path) in enumerate(specs):
        unit = _load(index, label, path, labels or {})
        if unit.digest is not None:
            first = first_by_digest.setdefault(unit.digest, index)
            unit.duplicate_of = None if first == index else first
        units.append(unit)
    return units


def _load(
    index: int, label: str, path: Path, labels: dict[str, dict[Key, str]]
) -> Unit:
    unit = Unit(index, label, path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        unit.error = f"{type(exc).__name__}: {exc}"
        return unit
    unit.digest = hashlib.sha256(raw).hexdigest()
    try:
        structure = ControlStructure.model_validate(yaml.safe_load(raw))
    except Exception as exc:  # noqa: BLE001 - every failure is reported per unit
        unit.error = f"{type(exc).__name__}: {exc}"
        return unit
    for mode in MODES:
        join = mechanism_join(structure, signature_retrieval=mode == "on")
        unit.modes[mode] = ModeJoin(join.kept, join.dropped)
    unit.replies, unit.replies_error = _replies(path.parent)
    unit.labels = labels.get(unit.digest, {})
    return unit


def _rate(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else round(numerator / denominator, 4)


def _mode_counts(unit: Unit, candidates: tuple[MechanismCandidate, ...]) -> dict:
    verifier = Counter(unit.verifier_status(item) for item in candidates)
    useful = Counter(unit.usefulness(item) for item in candidates)
    replied = sum(verifier[status] for status in VERIFIER_STATUSES[:4])
    labelled = useful["useful"] + useful["not_useful"]
    return {
        "candidates": len(candidates),
        "by_mechanism": dict(Counter(str(item.mechanism) for item in candidates)),
        "verifier": {status: verifier[status] for status in VERIFIER_STATUSES},
        "acceptance": _rate(verifier["accepted"], replied),
        "usefulness": {status: useful[status] for status in USEFULNESS_STATUSES},
        "precision": _rate(useful["useful"], labelled),
    }


def unit_counts(unit: Unit, units: list[Unit]) -> dict[str, Any]:
    """One unit's numbers for each mode and for the candidates ``on`` adds."""
    row: dict[str, Any] = {
        "index": unit.index,
        "label": unit.label,
        "path": str(unit.path),
        "sha256": unit.digest,
        "duplicate_of": (
            None if unit.duplicate_of is None else units[unit.duplicate_of].label
        ),
        "duplicate_of_index": unit.duplicate_of,
        "loaded": unit.loaded,
        "error": unit.error,
    }
    if not unit.loaded:
        return row
    row["verifier_replies"] = (
        "unreadable"
        if unit.replies_error
        else "absent"
        if unit.replies is None
        else "recorded"
    )
    row["verifier_replies_error"] = unit.replies_error
    for mode in MODES:
        join = unit.modes[mode]
        row[mode] = _mode_counts(unit, join.candidates)
        row[mode]["dropped_by_reason"] = dict(
            Counter(item.reason.value for item in join.dropped)
        )
    row["new"] = _mode_counts(unit, unit.new_candidates())
    return row


def aggregate(rows: list[dict[str, Any]], mode: str) -> dict[str, Any]:
    """Sum one mode's numbers over loaded *rows*; rates from the sums."""
    if not rows:
        return {"units": 0}
    values = [row[mode]["candidates"] for row in rows]
    verifier = sum((Counter(row[mode]["verifier"]) for row in rows), Counter())
    useful = sum((Counter(row[mode]["usefulness"]) for row in rows), Counter())
    replied = sum(verifier[status] for status in VERIFIER_STATUSES[:4])
    return {
        "units": len(rows),
        "candidates": {
            "total": sum(values),
            "min": min(values),
            "median": statistics.median(values),
            "mean": round(statistics.mean(values), 2),
            "max": max(values),
            f"share_at_most_{SMALL_UNIT}": round(
                sum(value <= SMALL_UNIT for value in values) / len(values), 4
            ),
        },
        "by_mechanism": dict(
            sum((Counter(row[mode]["by_mechanism"]) for row in rows), Counter())
        ),
        "verifier": {status: verifier[status] for status in VERIFIER_STATUSES},
        "acceptance": _rate(verifier["accepted"], replied),
        "usefulness": {status: useful[status] for status in USEFULNESS_STATUSES},
        "precision": _rate(useful["useful"], useful["useful"] + useful["not_useful"]),
    }


def live_check(units: list[Unit]) -> dict[str, Any]:
    """The new candidates without a recorded reply, and the requests to judge them."""
    rows = []
    requests: dict[str, int] = {}
    for unit in units:
        if not unit.loaded or unit.duplicate_of is not None:
            continue
        pending = [
            item
            for item in unit.new_candidates()
            if unit.verifier_status(item) == "unverified"
        ]
        if pending:
            requests[unit.label] = math.ceil(
                len(pending) / MECHANISM_SUGGESTION_BATCH_SIZE
            )
        rows += [
            {
                "unit": unit.label,
                "file": str(unit.path),
                "sha256": unit.digest,
                "mechanism": str(item.mechanism),
                "path": list(item.path),
            }
            for item in pending
        ]
    return {
        "batch_size": MECHANISM_SUGGESTION_BATCH_SIZE,
        "candidates": rows,
        "by_mechanism": dict(Counter(row["mechanism"] for row in rows)),
        "requests": requests,
        "total_requests": sum(requests.values()),
    }


def _number(value: float | None, percent: bool = True) -> str:
    if value is None:
        return "unavailable"
    return f"{value:.0%}" if percent else str(value)


def _mechanisms(counts: dict[str, int]) -> str:
    return ", ".join(f"{name} {count}" for name, count in sorted(counts.items()))


def _statuses(counts: dict[str, int]) -> str:
    return " / ".join(str(count) for count in counts.values())


def summary(
    rows: list[dict[str, Any]],
    aggregates: dict[str, dict[str, Any]],
    check: dict[str, Any],
) -> str:
    verifier = " / ".join(VERIFIER_STATUSES)
    useful = " / ".join(USEFULNESS_STATUSES)
    lines = [
        "# Mechanism join: signature retrieval off vs on",
        "",
        "Authority-filtered join. Candidates, verifier acceptance and usefulness"
        " are separate numbers. Verifier statuses: "
        f"{verifier}. Usefulness statuses: {useful}.",
        "",
        f"Reference only, not an acceptance rule: the earlier bar was at most"
        f" {SMALL_UNIT} candidates per unit and precision at least"
        f" {PRECISION_BAR:.0%}.",
        "",
        "| Over | Mode | Units | Candidates total | min / median / mean / max "
        f"| Share <= {SMALL_UNIT} | By mechanism | Verifier {verifier} "
        f"| Acceptance | Usefulness {useful} | Precision |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for name, by_mode in aggregates.items():
        for mode, item in by_mode.items():
            if not item["units"]:
                lines.append(f"| {name} | {mode} | 0 | | | | | | | | |")
                continue
            count = item["candidates"]
            lines.append(
                f"| {name} | {mode} | {item['units']} | {count['total']} "
                f"| {count['min']} / {count['median']} / {count['mean']} "
                f"/ {count['max']} | {count[f'share_at_most_{SMALL_UNIT}']:.0%} "
                f"| {_mechanisms(item['by_mechanism'])} "
                f"| {_statuses(item['verifier'])} "
                f"| {_number(item['acceptance'])} "
                f"| {_statuses(item['usefulness'])} "
                f"| {_number(item['precision'])} |"
            )
    lines += [
        "",
        "| Unit | Duplicate of | Replies | Off | On | New | New by mechanism "
        "| Off verifier | On verifier | Off acceptance | On acceptance "
        "| Off precision | On precision |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- "
        "| --- | --- |",
    ]
    for row in rows:
        if not row["loaded"]:
            lines.append(f"| {row['label']} | | unloadable | | | | | | | | | | |")
            continue
        off, on, new = row["off"], row["on"], row["new"]
        lines.append(
            f"| {row['label']} | {row['duplicate_of'] or ''} "
            f"| {row['verifier_replies']} | {off['candidates']} "
            f"| {on['candidates']} | {new['candidates']} "
            f"| {_mechanisms(new['by_mechanism'])} "
            f"| {_statuses(off['verifier'])} | {_statuses(on['verifier'])} "
            f"| {_number(off['acceptance'])} | {_number(on['acceptance'])} "
            f"| {_number(off['precision'])} | {_number(on['precision'])} |"
        )
    unloadable = [row for row in rows if not row["loaded"]]
    lines += ["", f"Unloadable files: {len(unloadable)}."]
    lines += [f"- {row['label']} ({row['path']}): {row['error']}" for row in unloadable]
    lines += [
        "",
        "Live check (not run): the candidates only signature retrieval adds, on"
        f" distinct structures, with no recorded reply: {len(check['candidates'])}"
        f" ({_mechanisms(check['by_mechanism'])}), over"
        f" {len(check['requests'])} structures. At {check['batch_size']}"
        f" candidates per verifier request that is {check['total_requests']}"
        " requests, before any validation repair.",
        "",
    ]
    return "\n".join(lines)


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--units-tsv", type=Path, action="append", default=[])
    parser.add_argument(
        "--unit", nargs=2, action="append", default=[], metavar=("LABEL", "PATH")
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--labels", type=Path, action="append", default=[])
    parser.add_argument("--label-field", default="label")
    args = parser.parse_args()

    specs = [item for tsv in args.units_tsv for item in _read_tsv(tsv)]
    specs += [(label, Path(path)) for label, path in args.unit]
    if not specs:
        parser.error("give --units-tsv or --unit")

    units = load_units(specs, labels=load_labels(args.labels, args.label_field))
    rows = [unit_counts(unit, units) for unit in units]
    loaded = [row for row in rows if row["loaded"]]
    distinct = [row for row in loaded if row["duplicate_of_index"] is None]
    aggregates = {
        name: {mode: aggregate(group, mode) for mode in (*MODES, "new")}
        for name, group in (
            ("all loaded units", loaded),
            ("distinct structures", distinct),
        )
    }
    check = live_check(units)

    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    _write_jsonl(
        out / "signature-retrieval-candidates.jsonl",
        [
            {
                "unit": unit.label,
                "file": str(unit.path),
                "sha256": unit.digest,
                "mode": mode,
                "mechanism": str(item.candidate.mechanism),
                "path": list(item.candidate.path),
                "new": mode == "on" and item.candidate in unit.new_candidates(),
                "authority_status": item.authority.value,
                "verifier": unit.verifier_status(item.candidate),
                "usefulness": unit.usefulness(item.candidate),
            }
            for unit in units
            if unit.loaded
            for mode in MODES
            for item in unit.modes[mode].kept
        ],
    )
    counts = {
        "small_unit_threshold": SMALL_UNIT,
        "precision_bar": PRECISION_BAR,
        "labels": [str(path) for path in args.labels],
        "label_field": args.label_field,
        "units": rows,
        "aggregates": aggregates,
        "live_check": {
            key: value for key, value in check.items() if key != "candidates"
        },
    }
    (out / "signature-retrieval-counts.json").write_text(
        json.dumps(counts, indent=2, ensure_ascii=False) + "\n"
    )
    _write_jsonl(out / "live-check-candidates.jsonl", check["candidates"])
    text = summary(rows, aggregates, check)
    (out / "signature-retrieval-summary.md").write_text(text)
    print(text)


if __name__ == "__main__":
    main()
