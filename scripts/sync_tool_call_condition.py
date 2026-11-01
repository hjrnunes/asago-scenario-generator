#!/usr/bin/env python3
"""Verify or refresh copies of the ``tool-call-condition`` contract.

    python3 scripts/sync_tool_call_condition.py --check \\
        --consumer ../asago-artifact-generator --midojo ../midojo --garak ../garak
    python3 scripts/sync_tool_call_condition.py --write --garak ../garak

A copy is a byte copy of ``data/contracts/tool-call-condition`` inside another
checkout, at the directory named in ``COPIES``. The copy's ``CONTRACT.lock`` is
its reference: the lock names the version and records every file's digest.

``--check`` verifies the producer tree against its lock and each copy it is
given, writes nothing, and exits 1 on drift. ``--write`` replaces a copy with
the producer's files and then verifies it; it never edits the producer. Without
a checkout argument the script reads no directory outside the producer.

The script needs only the standard library. Run it from any interpreter.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

CONTRACT = "tool-call-condition"
REFERENCE = "CONTRACT.lock"
AUTHORITY = "asago-scenario-generator"

# The copy directory of each repository, relative to the checkout root.
COPIES = {
    "consumer": Path("contracts/tool-call-condition"),
    "midojo": Path("tests/fixtures/tool_call_condition"),
    "garak": Path("tests/_assets/detectors/tool_call_condition"),
}

ROOT = Path(__file__).resolve().parents[1] / "data/contracts" / CONTRACT


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _files(root: Path) -> dict[str, Path]:
    """Every contract file under ``root`` by relative path, the lock excluded."""

    return {
        path.relative_to(root).as_posix(): path
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != REFERENCE
    }


def _read_lock(path: Path) -> dict[str, object] | str:
    """The parsed lock, or a problem string when it cannot be used."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return f"{path.name} is unreadable: {exc}"
    if not isinstance(document, dict):
        return f"{path.name} is not a JSON object"
    if not isinstance(document.get("files"), dict):
        return f"{path.name} lists no files"
    version = document.get("version")
    if not isinstance(version, str) or not version:
        return f"{path.name} names no version"
    return document


def _version(document: dict[str, object]) -> str:
    return str(document["version"])


def producer_problems(root: Path = ROOT) -> list[str]:
    """Every way the producer tree disagrees with its own lock."""

    lock_path = root / REFERENCE
    if not lock_path.is_file():
        return [f"the reference {REFERENCE} is missing"]
    document = _read_lock(lock_path)
    if isinstance(document, str):
        return [document]
    problems: list[str] = []
    if document.get("contract") != CONTRACT:
        problems.append(
            f"{REFERENCE} names contract {document.get('contract')!r}, "
            f"the producer's is {CONTRACT!r}"
        )
    if document.get("authority") != AUTHORITY:
        problems.append(
            f"{REFERENCE} names authority {document.get('authority')!r}, "
            f"the producer's is {AUTHORITY!r}"
        )
    recorded = document["files"]
    assert isinstance(recorded, dict)
    on_disk = _files(root)
    for name in sorted(set(recorded) | set(on_disk)):
        if name not in on_disk:
            problems.append(f"{name} is missing")
        elif name not in recorded:
            problems.append(f"{name} is not in {REFERENCE}")
        elif _sha256(on_disk[name]) != recorded[name]:
            problems.append(
                f"{name} differs from {REFERENCE} "
                f"(recorded {recorded[name]}, found {_sha256(on_disk[name])})"
            )
    return problems


def copy_problems(name: str, checkout: Path, *, root: Path = ROOT) -> list[str]:
    """Every way one copy disagrees with the producer contract."""

    copy = checkout / COPIES[name]
    if not copy.is_dir():
        return [f"copy directory {COPIES[name]} is missing"]
    producer_lock = _read_lock(root / REFERENCE)
    if isinstance(producer_lock, str):
        return [f"the producer lock is unusable: {producer_lock}"]
    version = _version(producer_lock)
    problems: list[str] = []
    lock_path = copy / REFERENCE
    if not lock_path.is_file():
        problems.append(f"the reference is missing: {REFERENCE} is not in the copy")
    else:
        reference = _read_lock(lock_path)
        if isinstance(reference, str):
            problems.append(f"the reference is unusable: {reference}")
        else:
            if reference.get("contract") != CONTRACT:
                problems.append(
                    f"the reference names contract {reference.get('contract')!r}, "
                    f"the producer's is {CONTRACT!r}"
                )
            if _version(reference) != version:
                problems.append(
                    f"the reference names {_version(reference)}, "
                    f"the producer's version is {version}"
                )
    expected = {**_files(root), REFERENCE: root / REFERENCE}
    present = _files(copy)
    if lock_path.is_file():
        present[REFERENCE] = lock_path
    for rel in sorted(set(expected) | set(present)):
        if rel not in present:
            problems.append(f"{rel} is missing from the copy")
        elif rel not in expected:
            problems.append(f"{rel} is not in the producer's contract")
        elif _sha256(present[rel]) != _sha256(expected[rel]):
            if rel == REFERENCE:
                problems.append(
                    f"the reference {REFERENCE} differs from the producer's lock"
                )
            else:
                problems.append(
                    f"{rel} differs from the producer's file "
                    f"(expected {_sha256(expected[rel])}, "
                    f"found {_sha256(present[rel])})"
                )
    return problems


def refresh_copy(name: str, checkout: Path, *, root: Path = ROOT) -> list[str]:
    """Replace one copy with the producer's files, then return its problems."""

    copy = checkout / COPIES[name]
    expected = {**_files(root), REFERENCE: root / REFERENCE}
    for rel, path in _files(copy).items():
        if rel not in expected:
            path.unlink()
    copy.mkdir(parents=True, exist_ok=True)
    for rel, path in expected.items():
        target = copy / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
    for directory in sorted(
        (path for path in copy.rglob("*") if path.is_dir()), reverse=True
    ):
        if not any(directory.iterdir()):
            directory.rmdir()
    return copy_problems(name, checkout, root=root)


def _report(label: str, problems: list[str], detail: str, out) -> None:  # type: ignore[no-untyped-def]
    if problems:
        print(f"{label}: DIFFERS ({detail})", file=out)
        for problem in problems:
            print(f"  - {problem}", file=out)
    else:
        print(f"{label}: verified ({detail})", file=out)


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--check",
        action="store_true",
        help="verify the producer tree and every copy given (the default)",
    )
    modes.add_argument(
        "--write",
        action="store_true",
        help="replace each copy given with the producer's files",
    )
    for name in COPIES:
        parser.add_argument(
            f"--{name}",
            type=Path,
            metavar="CHECKOUT",
            help=f"{name}'s checkout root, which holds {COPIES[name]}",
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None, *, root: Path | None = None) -> int:
    root = ROOT if root is None else root
    args = _arguments(argv)
    producer = producer_problems(root)
    document = _read_lock(root / REFERENCE)
    version = _version(document) if isinstance(document, dict) else "unknown version"
    count = len(_files(root)) + 1
    _report(f"producer {root}", producer, f"{version}, {count} files", sys.stdout)
    given = [name for name in COPIES if getattr(args, name) is not None]
    if not given:
        print("no copies checked (pass --consumer, --midojo or --garak)")
        return 1 if producer else 0

    failed = bool(producer)
    for name in given:
        checkout = getattr(args, name)
        label = f"{name} copy {checkout / COPIES[name]}"
        if args.write:
            problems = refresh_copy(name, checkout, root=root)
            action = "refreshed" if not problems else "DIFFERS"
            if problems:
                failed = True
                print(f"{label}: {action} ({version})")
                for problem in problems:
                    print(f"  - {problem}")
            else:
                print(f"{label}: {action} ({version}, {count} files)")
            continue
        problems = copy_problems(name, checkout, root=root)
        failed = failed or bool(problems)
        _report(label, problems, f"{version}, {count} files", sys.stdout)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
