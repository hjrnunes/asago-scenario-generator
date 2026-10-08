"""Atomic artifact writes in ``asago_scenario_generator.manifest``."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from asago_scenario_generator import manifest


def test_atomic_write_bytes_replaces_the_file_and_leaves_no_temporary(
    tmp_path: Path,
) -> None:
    target = tmp_path / "nested" / "out.json"
    target.parent.mkdir()
    target.write_bytes(b"old")

    result = manifest.atomic_write_bytes(target, b"\x00new\r\n")

    assert result == target
    assert target.read_bytes() == b"\x00new\r\n"
    assert sorted(p.name for p in target.parent.iterdir()) == ["out.json"]


def test_atomic_write_bytes_creates_parent_directories(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b" / "out.bin"

    manifest.atomic_write_bytes(target, b"x")

    assert target.read_bytes() == b"x"


def test_atomic_write_bytes_removes_the_temporary_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "out.bin"
    target.write_bytes(b"old")

    def _fail(*_args: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(manifest.os, "replace", _fail)

    with pytest.raises(KeyboardInterrupt):
        manifest.atomic_write_bytes(target, b"new")

    assert target.read_bytes() == b"old"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["out.bin"]


def test_atomic_write_bytes_fsyncs_the_file_and_its_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    synced: list[int] = []
    real_fsync = os.fsync

    def _record(descriptor: int) -> None:
        synced.append(descriptor)
        real_fsync(descriptor)

    monkeypatch.setattr(manifest.os, "fsync", _record)

    manifest.atomic_write_bytes(tmp_path / "out.bin", b"x")

    assert len(synced) == 2


def test_atomic_write_text_encodes_and_delegates_to_atomic_write_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[Path, bytes]] = []

    def _record(path: Path, content: bytes) -> Path:
        calls.append((path, content))
        return path

    monkeypatch.setattr(manifest, "atomic_write_bytes", _record)
    target = tmp_path / "out.txt"

    assert manifest.atomic_write_text(target, "é\n", encoding="latin-1") == target
    assert calls == [(target, "é\n".encode("latin-1"))]
