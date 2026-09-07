"""Related constraints must not multiply repeated authority descriptions."""

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model.control_structure import (
    PROMPTS_DIR,
    _build_call3_source_excerpts,
)
from tests.stpa.test_stage2_source_selection import USE_CASE, _authorities


def test_each_constraint_is_displayed_once_with_all_hazard_edges() -> None:
    losses, structure = _authorities()
    second_hazard = losses.hazards[0].model_copy(
        update={"hazard_id": "H-2", "description": "A loan record is lost."}
    )
    losses.hazards.append(second_hazard)
    original = losses.security_constraints[0]
    losses.security_constraints = [
        original.model_copy(
            update={
                "constraint_id": f"SC-{index}",
                "description": f"Constraint {index}: retain the authorized loan boundary.",
                "related_hazards": ["H-1", "H-2"],
            }
        )
        for index in range(1, 21)
    ]
    excerpts = _build_call3_source_excerpts(USE_CASE, losses)
    rendered = TemplateLoader(PROMPTS_DIR).render_prompt(
        "stage2_call3_user.j2",
        use_case_text=USE_CASE,
        control_structure=structure,
        loss_analysis=losses,
        source_excerpts=excerpts,
        source_ref_by_canonical={
            item.canonical_ref: item.local_ref for item in excerpts
        },
    )
    for constraint in losses.security_constraints:
        assert rendered.count(f"**{constraint.constraint_id}**") == 1
        assert rendered.count(constraint.description) == 1
    for hazard in losses.hazards:
        assert rendered.count(hazard.description) == 1
    assert rendered.count("All current hazard edges: H-1, H-2") == 20
    assert rendered.count(USE_CASE.split("\n\n")[0]) == 1
