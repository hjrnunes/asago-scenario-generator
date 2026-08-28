"""YAML I/O helpers for the STPA pipeline — clean copy.

``write_yaml(model, path)`` serializes a Pydantic model to YAML.
``read_yaml(path, model_class)`` loads a YAML file and validates it
against a Pydantic model class.

Follows the pattern in ``asago_scenario_generator.pipeline.io`` but decoupled.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import yaml
from pydantic import BaseModel


def write_yaml(
    model: BaseModel,
    path: Path,
    post_process: Callable[[dict], dict] | None = None,
) -> Path:
    """Serialize *model* to a YAML file at *path*.

    Args:
        model: A Pydantic model instance.
        path: Destination file path.
        post_process: Optional callable that receives the dumped dict
            and returns a (possibly modified) dict before YAML
            serialization.  Used by callers to inject companion display
            fields (e.g. ``kc_subcodes_display`` on CapabilityProfile).

    Returns:
        The path that was written.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = model.model_dump(mode="json", exclude_none=True)
    if post_process is not None:
        data = post_process(data)
    path.write_text(
        yaml.dump(
            data,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
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
