"""The optional ``repetition_penalty`` profile field in a shared profile file.

The ``model-profile`` contract cases (``test_model_profile_contract.py``) cover
the field's validity rule and its place in the request.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml

from asago_scenario_generator.model_profiles import load_profile
from asago_scenario_generator.stpa.pipeline.llm_config import (
    resolve_llm_client_from_profile,
)

_BASE: dict[str, Any] = {
    "base_url": "http://test.invalid/v1",
    "model": "m",
    "api_key": "k",
}


def _write(path: Path, profiles: dict[str, dict[str, Any]]) -> Path:
    path.write_text(yaml.safe_dump(profiles), encoding="utf-8")
    return path


class TestFrozenProfileFile:
    """A file that gains a penalty profile still loads for the other profiles."""

    def test_profile_without_the_field_loads_beside_one_with_it(self, tmp_path):
        profiles = _write(
            tmp_path / "two.yaml",
            {
                "gemma": {**_BASE, "top_k": 64},
                "glm": {**_BASE, "repetition_penalty": 1.05},
            },
        )
        assert load_profile(profiles, "gemma") == {**_BASE, "top_k": 64}
        with patch("asago_scenario_generator.stpa.infra.llm.OpenAI"):
            client, name = resolve_llm_client_from_profile(str(profiles), "gemma")
        assert name == "gemma"
        assert client._build_extra_kwargs(None, 0.3)["extra_body"] == {"top_k": 64}
