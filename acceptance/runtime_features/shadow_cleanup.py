"""Acceptance step handler that outlived the shadow_cleanup feature group.

The group's registration-priority, duplicate-assertion, and no-shadowing
contracts now live in ``tests/stpa/test_acceptance_framework_seams.py`` and
``tests/stpa/test_acceptance_harness_property.py``. The one handler below is
still bound by the ``sp1_capability_profile`` feature, and its binding id names
this module.
"""

from __future__ import annotations

from runtime_shared import Hazard, Loss, LossAnalysis, World
from registry import StepTable

step = StepTable()


@step("a use-case description and loss analysis are available")
def _h_sc_use_case_loss(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.sp1_use_case_text = "Test use case for Stage 2"
    world.loss_analysis = LossAnalysis(
        losses=[Loss(loss_id="L-1", description="Loss of confidentiality")],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", loss_ids=["L-1"])],
    )
    return True, ""


FEATURE_ID = "shadow_cleanup"


register = step.register


__all__ = ["FEATURE_ID", "register"]
