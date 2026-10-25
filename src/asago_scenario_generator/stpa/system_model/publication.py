"""Publication of the canonical Stage 2 control structure.

Every writer of ``control-structure.yaml`` goes through
:func:`publish_control_structure`, so no path publishes a structure whose
control actions routing cannot read.
"""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.infra.yaml_io import VersionChain
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.system_model.heuristics import (
    untyped_control_actions,
)

CONTROL_STRUCTURE_FILENAME = "control-structure.yaml"
REFUSED_CONTROL_STRUCTURE_FILENAME = "control-structure-refused.yaml"


def publish_control_structure(
    versions: VersionChain, control_structure: ControlStructure, run_dir: Path
) -> Path:
    """Publish the canonical structure, or refuse one with an untyped action.

    A refused structure ends the chain as ``control-structure-refused.yaml``
    and no ``control-structure.yaml`` is left in *run_dir*: one an earlier
    attempt wrote there is removed, so a reader never takes it for this
    run's result.

    Raises:
        StageError: naming each control action that lacks a typed target or
            effect.
    """
    untyped = untyped_control_actions(control_structure)
    if not untyped:
        return versions.publish(control_structure, CONTROL_STRUCTURE_FILENAME)
    versions.publish(control_structure, REFUSED_CONTROL_STRUCTURE_FILENAME)
    (Path(run_dir) / CONTROL_STRUCTURE_FILENAME).unlink(missing_ok=True)
    raise StageError(
        stage="stage_2", step="typed_control_actions", message="; ".join(untyped)
    )
