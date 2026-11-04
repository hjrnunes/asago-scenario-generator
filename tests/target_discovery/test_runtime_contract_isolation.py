"""The runtime-contract builder imports no model-facing module.

The builder runs in the producer's interpreter on a target's declaration, so it
needs only the neutral values and the consumer's schema. Importing it must not
load STPA, the LLM interpreter, the MCP transport or the prompt templates.

The probe runs in a fresh interpreter because the rest of this suite imports
those modules; ``sys.path`` puts this checkout's ``src`` first, so the probe
reads the tree under test rather than an editable install of another one.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILDER = "asago_scenario_generator.target_discovery.runtime_contract"
MODEL_FACING = ("llm_interpreter", "prompts", "transport")

_PROBE = f"""\
import json, sys
sys.path.insert(0, {str(ROOT / "src")!r})
import {BUILDER}
print(json.dumps({{
    "file": {BUILDER}.__file__,
    "modules": sorted(sys.modules),
}}))
"""


def _probe() -> dict:
    completed = subprocess.run(
        [sys.executable, "-c", _PROBE],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(completed.stdout)


def test_the_probe_reads_the_builder_in_this_checkout() -> None:
    assert Path(_probe()["file"]).resolve().is_relative_to(ROOT / "src")


def test_importing_the_builder_loads_no_model_facing_module() -> None:
    loaded = _probe()["modules"]

    assert BUILDER in loaded
    assert [
        name for name in loaded if name.startswith("asago_scenario_generator.stpa")
    ] == []
    assert [name for name in loaded if name.rpartition(".")[2] in MODEL_FACING] == []
    assert {name for name in loaded if name.startswith("asago_scenario_generator")} == {
        "asago_scenario_generator",
        "asago_scenario_generator.target_discovery",
        BUILDER,
    }
