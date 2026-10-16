"""Each replay-fill flag has one description, and the README warns of live requests."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FLAGS = ("--replay-fill", "--live-stage", "--max-live-requests")


def _documents() -> list[Path]:
    docs = [
        path
        for path in (ROOT / "docs").rglob("*.md")
        if "history" not in path.relative_to(ROOT).parts
    ]
    return [ROOT / "README.md", *docs]


@pytest.mark.parametrize("flag", FLAGS)
def test_each_flag_has_exactly_one_description(flag: str) -> None:
    pattern = re.compile(rf"^- `{re.escape(flag)}[ `]", re.MULTILINE)
    described = {
        path.relative_to(ROOT).as_posix(): len(
            pattern.findall(path.read_text(encoding="utf-8"))
        )
        for path in _documents()
    }

    assert {name: count for name, count in described.items() if count} == {
        "README.md": 1
    }


def test_the_readme_says_replay_fill_contacts_the_model_endpoint() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "A fill run contacts the model endpoint" in readme
