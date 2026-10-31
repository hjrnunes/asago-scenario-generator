"""Tests for ``scripts/sync_tool_call_condition.py``.

A copy is a byte copy of ``data/contracts/tool-call-condition`` in another
checkout. Its ``CONTRACT.lock`` is the reference: it names the version and
records every file's digest. ``--check`` verifies the producer tree and each
copy it is given, and writes nothing; ``--write`` refreshes a copy from the
producer. Without a checkout argument no directory outside the producer is
read or written.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

SYNC_PATH = Path(__file__).resolve().parents[2] / (
    "scripts/sync_tool_call_condition.py"
)
PRODUCER = Path(__file__).resolve().parents[2] / "data/contracts/tool-call-condition"
V2 = "tool-call-condition-v2"


def _load_sync() -> Any:
    spec = importlib.util.spec_from_file_location("sync_tool_call_condition", SYNC_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SYNC = _load_sync()


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def _checkout(tmp_path: Path, name: str) -> Path:
    """A checkout whose copy of the contract is the producer's, byte for byte."""

    checkout = tmp_path / name
    copy = checkout / SYNC.COPIES[name]
    shutil.copytree(PRODUCER, copy)
    return checkout


def _main(*argv: str) -> int:
    return SYNC.main(list(argv))


def test_the_committed_producer_tree_matches_its_lock() -> None:
    assert SYNC.producer_problems(PRODUCER) == []


def test_the_lock_names_the_contract_and_its_version() -> None:
    lock = json.loads((PRODUCER / "CONTRACT.lock").read_text(encoding="utf-8"))

    assert (lock["contract"], lock["version"]) == ("tool-call-condition", V2)


def test_check_passes_without_checkouts_and_reads_only_the_producer(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert _main("--check") == 0

    out = capsys.readouterr().out
    assert f"producer {PRODUCER}: verified ({V2}" in out
    assert "no copies checked" in out
    assert "copy" not in out.replace("no copies checked", "")


def test_check_verifies_every_copy_it_is_given(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    consumer = _checkout(tmp_path, "consumer")
    midojo = _checkout(tmp_path, "midojo")
    garak = _checkout(tmp_path, "garak")

    argv = (
        "--check",
        "--consumer",
        str(consumer),
        "--midojo",
        str(midojo),
        "--garak",
        str(garak),
    )
    assert _main(*argv) == 0

    out = capsys.readouterr().out
    for name, checkout in (
        ("consumer", consumer),
        ("midojo", midojo),
        ("garak", garak),
    ):
        assert f"{name} copy {checkout / SYNC.COPIES[name]}: verified ({V2}" in out


def test_check_fails_on_a_changed_vector_byte(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    garak = _checkout(tmp_path, "garak")
    vector = garak / SYNC.COPIES["garak"] / V2 / "vectors/evaluate.json"
    vector.write_bytes(
        vector.read_bytes().replace(b'"outcome": "detected"', b'"outcome": "x"', 1)
    )

    assert _main("--check", "--garak", str(garak)) == 1

    out = capsys.readouterr().out
    assert "garak copy" in out
    assert "differs from the producer's file" in out
    assert f"{V2}/vectors/evaluate.json" in out


def test_check_fails_when_a_copy_has_no_reference(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    consumer = _checkout(tmp_path, "consumer")
    (consumer / SYNC.COPIES["consumer"] / "CONTRACT.lock").unlink()

    assert _main("--check", "--consumer", str(consumer)) == 1

    out = capsys.readouterr().out
    assert "consumer copy" in out
    assert "reference is missing" in out
    assert "CONTRACT.lock" in out


def test_check_fails_when_the_reference_names_another_version(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    midojo = _checkout(tmp_path, "midojo")
    lock = midojo / SYNC.COPIES["midojo"] / "CONTRACT.lock"
    document = json.loads(lock.read_text(encoding="utf-8"))
    document["version"] = "tool-call-condition-v1"
    lock.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    assert _main("--check", "--midojo", str(midojo)) == 1

    out = capsys.readouterr().out
    assert "midojo copy" in out
    assert "reference names tool-call-condition-v1" in out
    assert V2 in out


def test_check_fails_on_a_missing_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    garak = _checkout(tmp_path, "garak")
    (garak / SYNC.COPIES["garak"] / V2 / "schema.json").unlink()

    assert _main("--check", "--garak", str(garak)) == 1

    out = capsys.readouterr().out
    assert "garak copy" in out
    assert f"{V2}/schema.json is missing" in out


def test_check_modifies_no_file(tmp_path: Path) -> None:
    consumer = _checkout(tmp_path, "consumer")
    vector = consumer / SYNC.COPIES["consumer"] / V2 / "vectors/validate.json"
    vector.write_bytes(vector.read_bytes() + b"\n")
    before = (_tree_digest(PRODUCER), _tree_digest(consumer))

    assert _main("--check", "--consumer", str(consumer)) == 1

    assert (_tree_digest(PRODUCER), _tree_digest(consumer)) == before


def test_write_refreshes_a_drifted_copy(tmp_path: Path) -> None:
    midojo = _checkout(tmp_path, "midojo")
    copy = midojo / SYNC.COPIES["midojo"]
    (copy / V2 / "vectors/validate.json").write_bytes(b"{}\n")
    (copy / "CONTRACT.lock").unlink()

    assert _main("--write", "--midojo", str(midojo)) == 0
    assert _main("--check", "--midojo", str(midojo)) == 0
    assert _tree_digest(copy) == _tree_digest(PRODUCER)


def test_write_removes_a_file_outside_the_contract(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    garak = _checkout(tmp_path, "garak")
    stray = garak / SYNC.COPIES["garak"] / "evaluate.json"
    stray.write_text("{}\n", encoding="utf-8")

    assert _main("--check", "--garak", str(garak)) == 1
    assert "garak copy" in capsys.readouterr().out

    assert _main("--write", "--garak", str(garak)) == 0
    assert not stray.exists()
    assert _main("--check", "--garak", str(garak)) == 0


def test_producer_drift_fails_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "tool-call-condition"
    shutil.copytree(PRODUCER, root)
    monkeypatch.setattr(SYNC, "ROOT", root)
    readme = root / V2 / "README.md"
    readme.write_bytes(readme.read_bytes() + b"\n")

    assert _main("--check") == 1

    out = capsys.readouterr().out
    assert f"producer {root}" in out
    assert f"{V2}/README.md differs from CONTRACT.lock" in out


def test_write_without_checkouts_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "tool-call-condition"
    shutil.copytree(PRODUCER, root)
    monkeypatch.setattr(SYNC, "ROOT", root)
    before = _tree_digest(root)

    assert _main("--write") == 0

    assert _tree_digest(root) == before


def test_write_never_edits_the_producer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The producer is the authority: --write never edits it, even when given.
    root = tmp_path / "tool-call-condition"
    shutil.copytree(PRODUCER, root)
    monkeypatch.setattr(SYNC, "ROOT", root)
    readme = root / V2 / "README.md"
    readme.write_bytes(readme.read_bytes() + b"\n")

    assert _main("--write") == 1
    assert readme.read_bytes().endswith(b"\n\n")


def test_check_and_write_are_mutually_exclusive() -> None:
    with pytest.raises(SystemExit):
        _main("--check", "--write")
