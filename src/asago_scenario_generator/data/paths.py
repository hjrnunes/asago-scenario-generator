"""Resolve taxonomy data in source checkouts and installed distributions."""

from __future__ import annotations

from pathlib import Path


def resolve_data_root(package_dir: Path | None = None) -> Path:
    """Return the packaged data root, falling back to a source checkout."""
    package = package_dir or Path(__file__).resolve().parents[1]
    bundled = package / "data" / "bundled"
    if (bundled / "taxonomies").is_dir():
        return bundled

    source = package.parents[1] / "data"
    if (source / "taxonomies").is_dir():
        return source

    return bundled


DATA_ROOT = resolve_data_root()
