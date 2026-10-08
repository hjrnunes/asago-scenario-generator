"""Stage 2 Call 3 without a loss analysis asks for links only.

With no loss analysis there are no source excerpts and no semantic review:
the provider wire is the bare coordination envelope and the parsed analysis
carries only the links.
"""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    _call_3_coordination,
    _CoordinationProviderEnvelope,
)
from tests.helpers.revision_delta import _make_control_structure
from tests.stpa.sp1_helpers import MockLLMClient


def test_call3_without_loss_analysis_parses_the_bare_link_envelope(
    tmp_path: Path,
) -> None:
    structure = _make_control_structure()
    link = structure.coordination_links[0].model_dump(mode="json")
    structure.coordination_links = []
    client = MockLLMClient()
    client.set_response_queue([{"coordination_links": [link]}])

    analysis = _call_3_coordination(
        llm_client=client,
        use_case_text="Two controllers share one state.",
        control_structure=structure,
        run_dir=tmp_path,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0,
    )

    assert client.calls[0].response_format is _CoordinationProviderEnvelope
    assert [cl.link_id for cl in analysis.coordination_links] == ["CL-1"]
    assert analysis.semantic_review is None
