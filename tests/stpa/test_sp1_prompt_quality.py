"""Tests for Stage 1 prompt quality (updated for stage1a split + stage1b revision).

The fixed Stage 1a, Stage 1b and Stage 2 wording lives in the phrase tables
under ``tests/phrases/``; this module keeps the input-dependent checks, the
template-source checks and the rendering properties.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model import PROMPTS_DIR
from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossProvenance,
    SecurityConstraint,
)

_STAGE1A_RISK_USER = "stage1a_risk_user.j2"
_STAGE1A_GAP_USER = "stage1a_gap_user.j2"

# System templates that take zero template variables — they are pure
# static prompts whose rendered output equals their raw text.
_ZERO_VAR_SYSTEM_TEMPLATES = [
    "stage1a_risk_system.j2",
    "stage1a_gap_system.j2",
    "stage1b_system.j2",
    "stage2_call1_system.j2",
    "stage2_call2a_system.j2",
    "stage2_call2b_system.j2",
    "stage2_call3_system.j2",
]


def _text(template_name: str) -> str:
    return (PROMPTS_DIR / template_name).read_text()


def _render(template_name: str, **variables: object) -> str:
    return TemplateLoader(PROMPTS_DIR).render_prompt(template_name, **variables)


# ---------------------------------------------------------------------------
# stage1a_risk_user rendering and source checks
# ---------------------------------------------------------------------------


def test_pqf_06_stage1a_risk_user_renders_with_use_case_and_risk_cards() -> None:
    cards = [
        RiskCard(
            risk_id="R-1",
            risk_name="Test risk",
            risk_description="Test description",
            taxonomy="test",
            confidence=0.9,
            grounding_confidence="high",
        ),
    ]
    rendered = _render(
        _STAGE1A_RISK_USER,
        use_case_text="A patient chatbot integrated with EHR systems",
        risk_cards=cards,
    )
    assert "A patient chatbot integrated with EHR systems" in rendered
    assert "R-1" in rendered
    assert "Test risk" in rendered


def test_pqf_08_stage1a_risk_user_preserves_jinja_variables() -> None:
    text = _text(_STAGE1A_RISK_USER)
    assert "{{ use_case_text }}" in text
    assert "{% if risk_cards %}" in text
    assert "{{ card.risk_id }}" in text


# ---------------------------------------------------------------------------
# stage1a_gap_user rendering and source checks
# ---------------------------------------------------------------------------


def test_pqf_11_stage1a_gap_user_renders_with_existing_analysis() -> None:
    losses = [
        Loss(
            loss_id="L-1",
            description="Test loss",
            provenance=LossProvenance.risk_card,
            source_risk_cards=["R-1"],
        ),
    ]
    hazards = [
        Hazard(hazard_id="H-1", description="Test hazard", related_losses=["L-1"]),
    ]
    constraints = [
        SecurityConstraint(
            constraint_id="SC-1", rule="Test SC", related_hazards=["H-1"]
        ),
    ]
    rendered = _render(
        _STAGE1A_GAP_USER,
        use_case_text="Test use case",
        existing_losses=losses,
        existing_hazards=hazards,
        existing_constraints=constraints,
        kc_subcodes=["KC1.1", "KC6.3.3"],
    )
    assert "Test use case" in rendered
    assert "L-1" in rendered
    assert "H-1" in rendered
    assert "SC-1" in rendered
    assert "kc_subcodes" in rendered.lower() or "KC1.1" in rendered


def test_pqf_12_stage1a_gap_user_preserves_jinja_variables() -> None:
    text = _text(_STAGE1A_GAP_USER)
    assert "{{ use_case_text }}" in text
    assert "{% for loss in existing_losses %}" in text
    assert "{{ kc_subcodes" in text


# ---------------------------------------------------------------------------
# stage1b_user source checks
# ---------------------------------------------------------------------------


def test_pqf_17_stage1b_user_no_loss_context() -> None:
    text = (PROMPTS_DIR / "stage1b_user.j2").read_text()
    assert "loss_analysis" not in text
    assert "all_losses" not in text
    assert "security_constraints" not in text


def test_pqf_18_stage1b_user_preserves_use_case_variable() -> None:
    text = (PROMPTS_DIR / "stage1b_user.j2").read_text()
    assert "{{ use_case_text }}" in text


# ---------------------------------------------------------------------------
# Property-based tests for template rendering
# ---------------------------------------------------------------------------

_st_safe_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs",), blacklist_characters=("{", "}")
    ),
    min_size=1,
    max_size=200,
)


class TestTemplateRenderingProperties:
    """Property-based invariants for prompt template rendering."""

    @given(template_name=st.sampled_from(_ZERO_VAR_SYSTEM_TEMPLATES))
    @settings(max_examples=20, deadline=None)
    def test_pqp_01_zero_var_system_template_fully_renders(
        self,
        template_name: str,
    ) -> None:
        """A zero-variable system template resolves all shared method partials."""
        rendered = _render(template_name)
        assert rendered.strip()
        assert "{%" not in rendered
        assert "{{" not in rendered

    @given(template_name=st.sampled_from(_ZERO_VAR_SYSTEM_TEMPLATES))
    @settings(max_examples=20, deadline=None)
    def test_pqp_02_system_template_rendering_is_idempotent(
        self,
        template_name: str,
    ) -> None:
        """Rendering a system template twice produces identical output."""
        first = _render(template_name)
        second = _render(template_name)
        assert first == second

    @given(template_name=st.sampled_from(_ZERO_VAR_SYSTEM_TEMPLATES))
    @settings(max_examples=20, deadline=None)
    def test_pqp_03_no_unrendered_jinja_markers_in_system_templates(
        self,
        template_name: str,
    ) -> None:
        """Rendered system templates contain no ``{{`` or ``{%`` markers."""
        rendered = _render(template_name)
        assert "{{" not in rendered
        assert "{%" not in rendered

    @given(use_case_text=_st_safe_text)
    @settings(max_examples=50, deadline=None)
    def test_pqp_04_stage1a_risk_user_injects_use_case_text_verbatim(
        self,
        use_case_text: str,
    ) -> None:
        """stage1a_risk_user.j2 always includes the provided use_case_text verbatim."""
        rendered = _render(
            _STAGE1A_RISK_USER, use_case_text=use_case_text, risk_cards=[]
        )
        assert use_case_text in rendered

    @given(use_case_text=_st_safe_text)
    @settings(max_examples=20, deadline=None)
    def test_pqp_05_stage1a_risk_user_empty_risk_cards_shows_fallback(
        self,
        use_case_text: str,
    ) -> None:
        """stage1a_risk_user.j2 with empty risk_cards shows the fallback message."""
        rendered = _render(
            _STAGE1A_RISK_USER, use_case_text=use_case_text, risk_cards=[]
        )
        assert "No organizational risks provided" in rendered
