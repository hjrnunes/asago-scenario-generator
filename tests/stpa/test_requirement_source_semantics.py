"""Requirements must not become evidence that a safeguard is installed."""

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR


def test_requirement_prompt_does_not_mandate_a_control_per_constraint() -> None:
    loader = TemplateLoader(PROMPTS_DIR)
    system = " ".join(loader.render_prompt("stage2_call1_system.j2").split())
    user = " ".join(
        loader.render_prompt(
            "stage2_call1_user.j2",
            use_case_text="A library assistant returns the authenticated patron's loans.",
            security_constraints=[],
        ).split()
    )

    assert "Do not manufacture a control requirement for every constraint" in system
    assert "normative requirements, not observations of installed functions" in system
    assert (
        "one control requirement with its associated constraint requirements"
        not in system
    )
    assert "A restriction-only requirement is a valid result" in user


def test_responsibility_prompt_labels_the_requirement_input_as_normative() -> None:
    rendered = TemplateLoader(PROMPTS_DIR).render_prompt(
        "stage2_call2a_user.j2",
        use_case_text="A library assistant returns the authenticated patron's loans.",
        requirements=[],
        capability_profile=None,
    )

    assert "Normative requirements (not an implementation inventory)" in rendered
