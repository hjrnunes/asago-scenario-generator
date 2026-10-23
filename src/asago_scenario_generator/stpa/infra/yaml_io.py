"""YAML I/O helpers for the STPA pipeline — clean copy.

``write_yaml(model, path)`` serializes a Pydantic model to YAML.
``read_yaml(path, model_class)`` loads a YAML file and validates it
against a Pydantic model class.  ``VersionChain`` publishes the successive
versions of one artifact without writing identical copies.

This is the STPA pipeline's isolated YAML persistence boundary.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import yaml
from pydantic import BaseModel


def yaml_text(
    model: BaseModel,
    *,
    exclude_none: bool = True,
    post_process: Callable[[dict], dict] | None = None,
) -> str:
    """Return the YAML text that :func:`write_yaml` persists for *model*.

    Args:
        model: A Pydantic model instance.
        exclude_none: Drop ``None`` fields. Pass ``False`` for an artifact
            contract that requires explicit ``null`` values.
        post_process: Optional callable that receives the dumped dict
            and returns a (possibly modified) dict before YAML
            serialization.  Used by callers to inject companion display
            fields (e.g. ``kc_subcodes_display`` on CapabilityProfile).
    """
    data = model.model_dump(mode="json", exclude_none=exclude_none)
    if post_process is not None:
        data = post_process(data)
    return yaml.dump(
        data,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )


def write_yaml(
    model: BaseModel,
    path: Path,
    post_process: Callable[[dict], dict] | None = None,
) -> Path:
    """Serialize *model* to a YAML file at *path*.

    Args:
        model: A Pydantic model instance.
        path: Destination file path.
        post_process: Optional callable; see :func:`yaml_text`.

    Returns:
        The path that was written.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml_text(model, post_process=post_process), encoding="utf-8")
    return path


class VersionChain:
    """Publish the successive versions of one artifact, skipping identical ones.

    Each step of a stage names the version it leaves, e.g.
    ``control-structure-draft.yaml``; the canonical file holds the version in
    force when the chain ends.  A named version is written only when its YAML
    text differs from the text of the next version in the chain, so an absent
    named version equals the next version present on disk, ending with the
    canonical file.  A version still pending when the chain closes without a
    canonical publication (a failed stage) is the last one reached and is
    written as it is.
    """

    def __init__(self, run_dir: Path) -> None:
        self._run_dir = Path(run_dir)
        self._pending: tuple[str, str] | None = None

    def __enter__(self) -> VersionChain:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def add(self, model: BaseModel, name: str) -> None:
        """Record the version a step leaves under its own *name*."""
        text = yaml_text(model)
        self._settle(text)
        self._pending = (name, text)

    def publish(self, model: BaseModel, name: str) -> Path:
        """Write the canonical *name* with the version in force."""
        text = yaml_text(model)
        self._settle(text)
        return self._write(name, text)

    def close(self) -> None:
        """Write the version still pending, if any."""
        if self._pending is not None:
            self._write(*self._pending)

    def _settle(self, next_text: str) -> None:
        if self._pending is not None and self._pending[1] != next_text:
            self._write(*self._pending)
        self._pending = None

    def _write(self, name: str, text: str) -> Path:
        self._pending = None
        path = self._run_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path


def read_yaml(path: Path, model_class: type[BaseModel]) -> BaseModel:
    """Load a YAML file and validate it against *model_class*.

    Args:
        path: Source YAML file path.
        model_class: Pydantic model class to validate against.

    Returns:
        A validated model instance.

    Raises:
        pydantic.ValidationError: If the data does not satisfy the schema.
    """
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return model_class.model_validate(raw)
