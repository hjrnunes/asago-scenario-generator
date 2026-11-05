"""Tests for the schema-diff check."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from asago_contracts_core import SchemaDiffError, diff_schemas
from asago_contracts_core.schema_diff import check_roots, main

_ROOT = Path(__file__).resolve().parent / "data" / "schema-diff"


def test_diff_schemas_reports_nothing_for_identical_schemas():
    schema = {"type": "object", "properties": {"name": {"type": "string"}}}

    assert diff_schemas(schema, schema) == ()


def test_diff_schemas_ignores_annotations():
    old = {"type": "string", "description": "old", "title": "Old"}
    new = {"type": "string", "description": "new", "title": "New", "examples": [1]}

    assert diff_schemas(old, new) == ()


@pytest.mark.parametrize(
    ("old", "new", "kind", "breaking"),
    [
        (
            {"type": "object", "properties": {"name": {"type": "string"}}},
            {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "note": {"type": "string"},
                },
            },
            "property-added",
            False,
        ),
        (
            {"type": "object", "properties": {"name": {"type": "string"}}},
            {"type": "object", "properties": {}},
            "property-removed",
            False,
        ),
        (
            {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "additionalProperties": False,
            },
            {"type": "object", "properties": {}, "additionalProperties": False},
            "property-removed",
            True,
        ),
        (
            {"type": "object", "properties": {"name": {"type": "string"}}},
            {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            },
            "required-added",
            True,
        ),
        (
            {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            },
            {"type": "object", "properties": {"name": {"type": "string"}}},
            "required-removed",
            False,
        ),
        ({"type": "string"}, {"type": "integer"}, "type-changed", True),
        ({"type": ["string", "null"]}, {"type": "string"}, "type-narrowed", True),
        ({"type": "string"}, {"type": ["string", "null"]}, "type-widened", False),
        ({"enum": ["a", "b"]}, {"enum": ["a"]}, "enum-removed", True),
        ({"enum": ["a"]}, {"enum": ["a", "b"]}, "enum-added", False),
        ({"const": "a"}, {"const": "b"}, "const-changed", True),
        (
            {"type": "object"},
            {"type": "object", "additionalProperties": False},
            "additional-properties-closed",
            True,
        ),
        (
            {"type": "object", "additionalProperties": False},
            {"type": "object"},
            "additional-properties-opened",
            False,
        ),
        (
            {"type": "integer"},
            {"type": "integer", "minimum": 1},
            "minimum-raised",
            True,
        ),
        (
            {"type": "integer", "minimum": 1},
            {"type": "integer", "minimum": 0},
            "minimum-lowered",
            False,
        ),
        (
            {"type": "integer", "maximum": 5},
            {"type": "integer", "maximum": 4},
            "maximum-lowered",
            True,
        ),
        (
            {"type": "string"},
            {"type": "string", "pattern": "^a"},
            "pattern-added",
            True,
        ),
        (
            {"type": "string", "pattern": "^a"},
            {"type": "string"},
            "pattern-removed",
            False,
        ),
        ({"type": "string"}, {"type": "string", "format": "uri"}, "format-added", True),
        (
            {"anyOf": [{"type": "string"}]},
            {"anyOf": [{"type": "string"}, {"type": "integer"}]},
            "alternatives-added",
            False,
        ),
        (
            {"anyOf": [{"type": "string"}, {"type": "integer"}]},
            {"anyOf": [{"type": "string"}]},
            "alternatives-removed",
            True,
        ),
        (
            {"type": "array"},
            {"type": "array", "items": {"type": "string"}},
            "items-added",
            True,
        ),
        (
            {"type": "array", "items": {"type": "string"}},
            {"type": "array"},
            "items-removed",
            False,
        ),
        ({"$ref": "#/$defs/a"}, {"$ref": "#/$defs/b"}, "reference-changed", True),
        (
            {"type": "object"},
            {"type": "object", "unevaluated": 1},
            "keyword-changed",
            True,
        ),
    ],
)
def test_diff_schemas_classifies_a_change(old, new, kind, breaking):
    changes = diff_schemas(old, new)

    assert [(c.kind, c.breaking) for c in changes] == [(kind, breaking)]
    assert changes[0].location


def test_diff_schemas_reads_a_closed_object_removal_from_the_narrowed_side():
    old = {"properties": {"note": {"type": "string"}}}
    new = {"properties": {}, "additionalProperties": False}

    changes = diff_schemas(old, new)

    assert {(c.kind, c.breaking) for c in changes} == {
        ("additional-properties-closed", True),
        ("property-removed", True),
    }


def test_check_roots_accepts_a_non_breaking_change_with_a_minor_bump():
    assert check_roots([_ROOT / "clean"]) == ()


def test_check_roots_refuses_a_breaking_change_without_a_major_bump():
    problems = check_roots([_ROOT / "breaking"])

    assert len(problems) == 1
    assert "example-v1.1.0" in problems[0]
    assert "property-removed" in problems[0]
    assert "major" in problems[0]


def test_check_roots_refuses_a_root_that_is_not_a_directory(tmp_path):
    with pytest.raises(SchemaDiffError):
        check_roots([tmp_path / "missing"])


def test_the_cli_exits_zero_for_a_clean_root(capsys):
    assert main([str(_ROOT / "clean")]) == 0

    out = capsys.readouterr()
    assert "no breaking changes" in out.out
    assert out.err == ""


def test_the_cli_exits_one_for_a_breaking_change(capsys):
    assert main([str(_ROOT / "breaking")]) == 1

    err = capsys.readouterr().err
    assert "example-v1.1.0" in err
    assert "major" in err


def test_the_cli_exits_two_for_a_missing_root(tmp_path, capsys):
    assert main([str(tmp_path / "missing")]) == 2

    assert "not a directory" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("fixture", "code"),
    [("clean", 0), ("breaking", 1)],
)
def test_the_documented_command_runs_the_check(fixture, code):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "asago_contracts_core.schema_diff_cli",
            str(_ROOT / fixture),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == code
    assert "RuntimeWarning" not in result.stderr
