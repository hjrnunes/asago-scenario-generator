"""SP1 — System Model (Stages 1a, 1b, 2).

Derives the control structure that is the pipeline's primary representation.
"""

from asago_scenario_generator.stpa.infra.llm_helpers import StageError  # noqa: E402
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (  # noqa: E402
    ControlElementSet,
    CoordinationAnalysis,
    Requirement,
    RequirementSet,
    ResponsibilitySet,
    derive_control_structure,
)
from asago_scenario_generator.stpa.system_model.id_normalization import (  # noqa: E402
    ControlStructureNormalization,
)
from asago_scenario_generator.stpa.system_model.critic import (  # noqa: E402
    CriticFindings,
    CriticGap,
    RevisionDelta,
    run_completeness_critic,
    run_revision,
)
from asago_scenario_generator.stpa.system_model.heuristics import (  # noqa: E402
    check_solution_neutrality,
    run_heuristics,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    derive_loss_analysis,
)  # noqa: E402
from asago_scenario_generator.stpa.system_model.profile import derive_capability_profile  # noqa: E402
from asago_scenario_generator.stpa.system_model.run import SP1RunResult, run_sp1  # noqa: E402

__all__ = [
    # constants
    "PROMPTS_DIR",
    # error types
    "StageError",
    # internal models
    "Requirement",
    "RequirementSet",
    "ResponsibilitySet",
    "ControlElementSet",
    "CoordinationAnalysis",
    "ControlStructureNormalization",
    "CriticFindings",
    "CriticGap",
    "RevisionDelta",
    # run result
    "SP1RunResult",
    # stage functions
    "derive_loss_analysis",
    "derive_capability_profile",
    "derive_control_structure",
    "run_completeness_critic",
    "run_revision",
    "run_heuristics",
    "check_solution_neutrality",
    "run_sp1",
]
