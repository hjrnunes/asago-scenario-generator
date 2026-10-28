#!/usr/bin/env python3
"""Run the mechanism-candidate join over saved control structures, offline.

    uv run --frozen python scripts/graph_join_candidates.py \\
        --units-tsv UNITS.tsv [--unit LABEL PATH ...] --out-dir DIR \\
        [--sample-size 30] [--seed 20261024] [--suffix=-v2] [--authority-filter] \\
        [--signature-retrieval]

Each unit is a label and a saved ``control-structure.yaml``. The TSV holds one
``label<TAB>path`` per line. Labels must be non-blank and unique; the script
stops before reading any file otherwise. The script reads the files and never
writes them.
A file that is missing, is not YAML, or fails ``ControlStructure`` validation is
listed as unloadable with the reason; it contributes no candidates.

Every unit records the SHA-256 of its file bytes. A unit whose file is
byte-identical to an earlier unit's names the first such unit in
``duplicate_of`` (its label) and ``duplicate_of_index`` (its position in the
input), so the counts are reported over all loaded units and over distinct
structures.

Outputs in ``--out-dir``, each name with ``--suffix`` before its extension:

- ``join-candidates.jsonl``: one row per (unit, candidate);
- ``join-counts.json``: per-unit counts and the two aggregates;
- ``join-summary.md``: the same counts as tables;
- ``label-sample.jsonl``: candidates drawn from distinct structures with the
  records needed to judge each one, and empty ``label`` and ``note`` fields.

The sample takes one candidate from every distinct structure that has any, in
unit order, then draws the rest uniformly from the remaining candidates of
distinct structures. When more structures have candidates than the sample
holds, the seeded generator chooses which structures give one. Every draw uses
``random.Random(seed)``.

``--authority-filter`` runs ``mechanism_join`` instead: the candidates are the
ones it keeps, sampled the same way, and the outputs add what kept or dropped
each one. Every candidate row and sample row adds ``authority_status``
(``unknown`` when ``authority_for_update`` is absent), ``authority_recorded``
and ``reach_basis``; every unit adds the kept counts by authority (assessed:
``non_authoritative`` or ``conditional``; unknown: recorded ``unknown`` or
absent), the dropped counts by reason, the kept candidates the unfiltered join
lacks, and its channels by authority value (``missing`` when absent): all of
them, those whose ``source_kind`` is untrusted, and those that start a kept or
an authoritative-dropped candidate. ``join-dropped.jsonl`` lists the dropped
candidates. Without the flag every output is as before.

``--signature-retrieval`` runs both joins with signature retrieval on: every
channel is matched against each mechanism library entry's signature, so the
candidates, counts and sample cover every library mechanism. Without it every
output is as before.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import statistics
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    FeedbackAuthorityStatus,
    FeedbackChannel,
    Responsibility,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    DropReason,
    KeptCandidate,
    MechanismCandidate,
    MechanismJoin,
    StpaIndex,
    build_stpa_index,
    mechanism_candidates,
    mechanism_join,
)

SMALL_UNIT = 5
"""A unit with at most this many candidates counts as small."""


@dataclass
class Unit:
    index: int
    label: str
    path: Path
    digest: str | None = None
    duplicate_of: int | None = None
    """Index of the first unit whose file has the same bytes, if not this one."""
    structure: ControlStructure | None = None
    error: str | None = None
    candidates: tuple[MechanismCandidate, ...] = ()
    owners: dict[str, Responsibility] = field(default_factory=dict)
    join: MechanismJoin | None = None
    """The filtered join, when the script runs with ``--authority-filter``."""
    unfiltered: tuple[MechanismCandidate, ...] = ()
    """The unfiltered candidates, kept beside a filtered join for comparison."""


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


def load_units(
    specs: list[tuple[str, Path]],
    *,
    authority_filter: bool = False,
    signature_retrieval: bool = False,
) -> list[Unit]:
    """Load every unit, marking each byte-identical copy of an earlier one."""
    _check_labels(specs)
    first_by_digest: dict[str, int] = {}
    units = []
    for index, (label, path) in enumerate(specs):
        unit = _load(index, label, path, authority_filter, signature_retrieval)
        if unit.digest is not None:
            first = first_by_digest.setdefault(unit.digest, index)
            unit.duplicate_of = None if first == index else first
        units.append(unit)
    return units


def _load(
    index: int,
    label: str,
    path: Path,
    authority_filter: bool = False,
    signature_retrieval: bool = False,
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
    unit.structure = structure
    unit.candidates = mechanism_candidates(
        structure, signature_retrieval=signature_retrieval
    )
    if authority_filter:
        unit.join = mechanism_join(structure, signature_retrieval=signature_retrieval)
        unit.unfiltered = unit.candidates
        unit.candidates = tuple(item.candidate for item in unit.join.kept)
    unit.owners = _owners(structure)
    return unit


def _owners(structure: ControlStructure) -> dict[str, Responsibility]:
    """Map every child ID to the responsibility that lists it."""
    owners: dict[str, Responsibility] = {}
    for responsibility in structure.responsibilities:
        for children, identity in (
            (responsibility.process_model_parts, "pm_id"),
            (responsibility.control_actions, "ca_id"),
            (responsibility.feedback_channels, "fb_id"),
        ):
            for child in children:
                owners.setdefault(getattr(child, identity), responsibility)
    return owners


def _duplicate_label(unit: Unit, units: list[Unit]) -> str | None:
    return None if unit.duplicate_of is None else units[unit.duplicate_of].label


def _unit_counts(unit: Unit, units: list[Unit]) -> dict[str, Any]:
    row: dict[str, Any] = {
        "index": unit.index,
        "label": unit.label,
        "path": str(unit.path),
        "sha256": unit.digest,
        "duplicate_of": _duplicate_label(unit, units),
        "duplicate_of_index": unit.duplicate_of,
        "loaded": unit.structure is not None,
        "error": unit.error,
    }
    if unit.structure is None:
        return row
    channels = [
        channel
        for responsibility in unit.structure.responsibilities
        for channel in responsibility.feedback_channels
    ]
    row.update(
        candidates=len(unit.candidates),
        paths=len({item.path for item in unit.candidates}),
        link_paths=len({item.path for item in unit.candidates if _via_link(item)}),
        by_mechanism=dict(Counter(item.mechanism for item in unit.candidates)),
        feedback_channels=len(channels),
        untrusted_feedback_channels=sum(channel.untrusted for channel in channels),
        coordination_links=len(unit.structure.coordination_links),
    )
    if unit.join is not None:
        row.update(_filter_counts(unit, channels))
    return row


_AUTHORITY_VALUES = (*(status.value for status in FeedbackAuthorityStatus), "missing")


def _channel_authority(channel: FeedbackChannel) -> str:
    if channel.authority_for_update is None:
        return "missing"
    return channel.authority_for_update.status.value


def _by_authority(channels: list[FeedbackChannel]) -> dict[str, int]:
    counts = Counter(_channel_authority(channel) for channel in channels)
    return {value: counts[value] for value in _AUTHORITY_VALUES}


def _filter_counts(unit: Unit, channels: list[FeedbackChannel]) -> dict[str, Any]:
    assert unit.join is not None
    kept, dropped = unit.join.kept, unit.join.dropped
    joined = {item.candidate.path[0] for item in kept} | {
        item.candidate.path[0]
        for item in dropped
        if item.reason is DropReason.authoritative
    }
    unfiltered = set(unit.unfiltered)
    return {
        "unfiltered_candidates": len(unit.unfiltered),
        "kept_assessed": sum(item.authority_assessed for item in kept),
        "kept_unknown": sum(not item.authority_assessed for item in kept),
        "kept_unknown_missing": sum(not item.authority_recorded for item in kept),
        "kept_by_authority": dict(Counter(item.authority.value for item in kept)),
        "kept_by_reach": dict(Counter(item.reach.value for item in kept)),
        "kept_not_unfiltered": sum(item.candidate not in unfiltered for item in kept),
        "dropped": len(dropped),
        "dropped_by_reason": {
            reason.value: sum(item.reason is reason for item in dropped)
            for reason in DropReason
        },
        "channel_authority": _by_authority(channels),
        "untrusted_channel_authority": _by_authority(
            [channel for channel in channels if channel.untrusted]
        ),
        "joined_channels": len(joined),
        "joined_channel_authority": _by_authority(
            [channel for channel in channels if channel.fb_id in joined]
        ),
    }


def _via_link(candidate: MechanismCandidate) -> bool:
    return candidate.path[2].startswith("CL-")


def _aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {"units": 0}
    result: dict[str, Any] = {"units": len(rows)}
    for key in ("candidates", "paths"):
        values = [row[key] for row in rows]
        result[key] = {
            "total": sum(values),
            "min": min(values),
            "median": statistics.median(values),
            "max": max(values),
            f"share_at_most_{SMALL_UNIT}": round(
                sum(value <= SMALL_UNIT for value in values) / len(values), 4
            ),
        }
    result["by_mechanism"] = dict(
        sum((Counter(row["by_mechanism"]) for row in rows), Counter())
    )
    result["units_with_no_candidate"] = sum(row["candidates"] == 0 for row in rows)
    return result


def _model(record: Any) -> dict[str, Any]:
    return record.model_dump(mode="json", exclude_none=True)


def _responsibility(record: Responsibility | None) -> dict[str, str] | None:
    if record is None:
        return None
    return {"resp_id": record.resp_id, "description": record.description}


def _element(index: StpaIndex, ref: Any) -> dict[str, Any] | None:
    if ref is None:
        return None
    records = (
        index.responsibilities
        if ref.type.value == "responsibility"
        else index.controlled_processes
    )
    record = records.get(ref.id)
    return {
        "type": ref.type.value,
        "id": ref.id,
        "description": None if record is None else record.description,
    }


def _judging_record(unit: Unit, candidate: MechanismCandidate) -> dict[str, Any]:
    assert unit.structure is not None
    index = build_stpa_index(unit.structure)
    fb_id, pm_id, end_id = candidate.path
    channel = index.feedback_channels[fb_id]
    variable = index.process_model_parts[pm_id]
    row: dict[str, Any] = {
        "unit": unit.label,
        "file": str(unit.path),
        "sha256": unit.digest,
        "mechanism": candidate.mechanism,
        "path": list(candidate.path),
        "feedback_channel": {
            **_model(channel),
            "untrusted": channel.untrusted,
            "source": _element(index, channel.source),
            "controller": _responsibility(unit.owners.get(fb_id)),
        },
        "process_model_part": {
            **_model(variable),
            "controller": _responsibility(unit.owners.get(pm_id)),
        },
        "control_action": None,
        "coordination_link": None,
    }
    if _via_link(candidate):
        link = index.coordination_links[end_id]
        row["coordination_link"] = {
            **_model(link),
            "source": _responsibility(index.responsibilities.get(link.source)),
            "target": _responsibility(index.responsibilities.get(link.target)),
            # A link is directed: its target receives what its source issues.
            "receiving_controller": _responsibility(
                index.responsibilities.get(link.target)
            ),
        }
    else:
        action = index.control_actions[end_id]
        row["control_action"] = {
            **_model(action),
            "target": _element(index, action.target),
            "controller": _responsibility(unit.owners.get(end_id)),
        }
    row.update(_filter_fields(unit, candidate))
    row["label"] = ""
    row["note"] = ""
    return row


def _kept(unit: Unit, candidate: MechanismCandidate) -> KeptCandidate | None:
    if unit.join is None:
        return None
    return next(item for item in unit.join.kept if item.candidate == candidate)


def _filter_fields(unit: Unit, candidate: MechanismCandidate) -> dict[str, Any]:
    kept = _kept(unit, candidate)
    if kept is None:
        return {}
    return {
        "authority_status": kept.authority.value,
        "authority_recorded": kept.authority_recorded,
        "reach_basis": kept.reach.value,
    }


def _sample(
    distinct: list[Unit], size: int, seed: int
) -> list[tuple[Unit, MechanismCandidate, str]]:
    rng = random.Random(seed)
    eligible = [unit for unit in distinct if unit.candidates]
    choices = [rng.randrange(len(unit.candidates)) for unit in eligible]
    numbers = range(len(eligible))
    chosen = set(numbers if len(eligible) <= size else rng.sample(numbers, size))
    picked: list[tuple[Unit, MechanismCandidate, str]] = []
    rest: list[tuple[Unit, MechanismCandidate]] = []
    for number, (unit, choice) in enumerate(zip(eligible, choices, strict=True)):
        for position, candidate in enumerate(unit.candidates):
            if number in chosen and position == choice:
                picked.append((unit, candidate, "one_per_structure"))
            else:
                rest.append((unit, candidate))
    extra = rng.sample(rest, min(len(rest), size - len(picked)))
    picked.extend((unit, candidate, "uniform_remainder") for unit, candidate in extra)
    return picked


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _summary(
    rows: list[dict[str, Any]],
    aggregates: dict[str, dict[str, Any]],
    sample_note: str,
) -> str:
    lines = [
        "# Mechanism-candidate join",
        "",
        "Candidates are (mechanism, path) pairs; paths are distinct"
        " FB -> PM -> CA or FB -> PM -> CL triples.",
        "",
        "| Unit | sha256 | Duplicate of | Candidates | Paths | Via CL | By mechanism |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        digest = (row["sha256"] or "")[:12]
        if not row["loaded"]:
            lines.append(
                f"| {row['label']} | {digest} | {row['duplicate_of'] or ''} "
                "| unloadable | | | |"
            )
            continue
        mechanisms = ", ".join(
            f"{name} {count}" for name, count in sorted(row["by_mechanism"].items())
        )
        lines.append(
            f"| {row['label']} | {digest} | {row['duplicate_of'] or ''} "
            f"| {row['candidates']} | {row['paths']} | {row['link_paths']} "
            f"| {mechanisms} |"
        )
    lines += [
        "",
        "| Over | Units | Candidates min / median / max | "
        f"Share with <= {SMALL_UNIT} | Paths min / median / max | "
        f"Share with <= {SMALL_UNIT} paths | No candidate |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for name, aggregate in aggregates.items():
        if not aggregate["units"]:
            lines.append(f"| {name} | 0 | | | | | |")
            continue
        candidates, paths = aggregate["candidates"], aggregate["paths"]
        share = f"share_at_most_{SMALL_UNIT}"
        lines.append(
            f"| {name} | {aggregate['units']} "
            f"| {candidates['min']} / {candidates['median']} / {candidates['max']} "
            f"| {candidates[share]:.0%} "
            f"| {paths['min']} / {paths['median']} / {paths['max']} "
            f"| {paths[share]:.0%} | {aggregate['units_with_no_candidate']} |"
        )
    lines += _filter_summary(rows)
    unloadable = [row for row in rows if not row["loaded"]]
    lines += ["", f"Unloadable files: {len(unloadable)}."]
    lines += [f"- {row['label']} ({row['path']}): {row['error']}" for row in unloadable]
    lines += ["", sample_note, ""]
    return "\n".join(lines)


def _slashed(counts: dict[str, int]) -> str:
    return " / ".join(str(count) for count in counts.values())


def _filter_summary(rows: list[dict[str, Any]]) -> list[str]:
    filtered = [row for row in rows if "unfiltered_candidates" in row]
    if not filtered:
        return []
    statuses = " / ".join(_AUTHORITY_VALUES)
    lines = [
        "",
        "Authority filter: kept candidates whose authority is assessed"
        " (non_authoritative or conditional) or unknown (recorded unknown, or"
        " missing); dropped candidates by reason. Channels counts every"
        f" channel by authority ({statuses}); untrusted counts the channels"
        " whose source_kind is untrusted; joined counts the channels that"
        " start a kept or an authoritative-dropped candidate.",
        "",
        "| Unit | Unfiltered | Kept | Assessed | Unknown (missing) | Not unfiltered "
        "| Dropped authoritative | Dropped own controller "
        f"| Channels {statuses} | Untrusted {statuses} | Joined {statuses} |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in filtered:
        reasons = row["dropped_by_reason"]
        lines.append(
            f"| {row['label']} | {row['unfiltered_candidates']} "
            f"| {row['candidates']} | {row['kept_assessed']} "
            f"| {row['kept_unknown']} ({row['kept_unknown_missing']}) "
            f"| {row['kept_not_unfiltered']} | {reasons['authoritative']} "
            f"| {reasons['own_controller']} "
            f"| {_slashed(row['channel_authority'])} "
            f"| {_slashed(row['untrusted_channel_authority'])} "
            f"| {_slashed(row['joined_channel_authority'])} |"
        )
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--units-tsv", type=Path, action="append", default=[])
    parser.add_argument(
        "--unit", nargs=2, action="append", default=[], metavar=("LABEL", "PATH")
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--sample-size", type=int, default=30)
    parser.add_argument("--seed", type=int, default=20261024)
    parser.add_argument("--suffix", default="", help="added to every output name")
    parser.add_argument(
        "--authority-filter",
        action="store_true",
        help="run the join that drops authoritative and controller-sourced channels",
    )
    parser.add_argument(
        "--signature-retrieval",
        action="store_true",
        help="match every channel against each mechanism library signature",
    )
    args = parser.parse_args()

    specs = [item for tsv in args.units_tsv for item in _read_tsv(tsv)]
    specs += [(label, Path(path)) for label, path in args.unit]
    if not specs:
        parser.error("give --units-tsv or --unit")

    units = load_units(
        specs,
        authority_filter=args.authority_filter,
        signature_retrieval=args.signature_retrieval,
    )
    rows = [_unit_counts(unit, units) for unit in units]
    loaded = [row for row in rows if row["loaded"]]
    aggregates = {
        "all loaded units": _aggregate(loaded),
        "distinct structures": _aggregate(
            [row for row in loaded if row["duplicate_of_index"] is None]
        ),
    }

    distinct = [
        unit
        for unit in units
        if unit.structure is not None and unit.duplicate_of is None
    ]
    sample = _sample(distinct, args.sample_size, args.seed)
    copies: dict[int, list[str]] = {}
    for unit in units:
        if unit.duplicate_of is not None:
            copies.setdefault(unit.duplicate_of, []).append(unit.label)
    sample_rows = []
    for number, (unit, candidate, draw) in enumerate(sample, 1):
        record = _judging_record(unit, candidate)
        sample_rows.append(
            {
                "sample_id": f"S{number:02d}",
                "draw": draw,
                "same_structure_units": copies.get(unit.index, []),
                **record,
            }
        )
    strata = Counter(row["unit"] for row in sample_rows)
    sample_note = (
        f"Sample: {len(sample_rows)} candidates, seed {args.seed}, from "
        f"{len(strata)} of {len(distinct)} distinct structures "
        f"({sum(1 for unit in distinct if unit.candidates)} have candidates)."
    )

    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    _write_jsonl(
        out / f"join-candidates{args.suffix}.jsonl",
        [
            {
                "unit": unit.label,
                "file": str(unit.path),
                "sha256": unit.digest,
                "duplicate_of": _duplicate_label(unit, units),
                "mechanism": candidate.mechanism,
                "path": list(candidate.path),
                **_filter_fields(unit, candidate),
            }
            for unit in units
            for candidate in unit.candidates
        ],
    )
    if args.authority_filter:
        _write_jsonl(
            out / f"join-dropped{args.suffix}.jsonl",
            [
                {
                    "unit": unit.label,
                    "file": str(unit.path),
                    "sha256": unit.digest,
                    "duplicate_of": _duplicate_label(unit, units),
                    "mechanism": item.candidate.mechanism,
                    "path": list(item.candidate.path),
                    "reason": item.reason.value,
                }
                for unit in units
                if unit.join is not None
                for item in unit.join.dropped
            ],
        )
    counts = {
        "small_unit_threshold": SMALL_UNIT,
        "units": rows,
        "aggregates": aggregates,
        "sample": {
            "seed": args.seed,
            "size": len(sample_rows),
            "by_unit": dict(strata),
            "by_mechanism": dict(Counter(row["mechanism"] for row in sample_rows)),
            "by_draw": dict(Counter(row["draw"] for row in sample_rows)),
        },
    }
    (out / f"join-counts{args.suffix}.json").write_text(
        json.dumps(counts, indent=2, ensure_ascii=False) + "\n"
    )
    (out / f"join-summary{args.suffix}.md").write_text(
        _summary(rows, aggregates, sample_note)
    )
    _write_jsonl(out / f"label-sample{args.suffix}.jsonl", sample_rows)
    print(_summary(rows, aggregates, sample_note))


if __name__ == "__main__":
    main()
