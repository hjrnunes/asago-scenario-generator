"""Shared helpers for the asago-scenario-generator CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

import typer
import yaml


def _resolve_use_case(value: str) -> str:
    """If value starts with @, read from the referenced file; otherwise return as-is."""
    if value.startswith("@"):
        file_path = Path(value[1:])
        if not file_path.exists():
            typer.echo(f"Error: use-case file not found: {file_path}", err=True)
            raise typer.Exit(code=1)
        return file_path.read_text(encoding="utf-8").strip()
    return value


def _validate_file(path: Path, label: str) -> None:
    if not path.exists():
        typer.echo(f"Error: {label} not found: {path}", err=True)
        raise typer.Exit(code=1)


def _abort(exc: Exception) -> None:
    """Announce a command failure on stderr and exit with code 1."""
    msg = f"Error: {exc}"
    if exc.__cause__:
        msg += f"\n  Caused by: {exc.__cause__}"
    typer.echo(msg, err=True)
    raise typer.Exit(code=1)


def _load_payload(path: Path, label: str) -> dict:
    """Parse a snapshot or map with a standard JSON or YAML reader."""
    text = path.read_text(encoding="utf-8")
    payload = (
        json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
    )
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON or YAML object")
    return payload
