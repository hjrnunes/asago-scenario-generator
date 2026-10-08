"""Stage 1a prompt hardening for the derived-branch templates.

Four fresh OcciAI/Airbnb chains died at derived Stage 1a on provider output
quality (see the mission library m3-stage1a-blocker-diagnosis): the bounded
revision prompt lacked a concrete ``NEW-*`` handle example and any negative
example, so providers continued the reserved canonical numbering
(``H-7``/``SC-4``); the "quote the rule verbatim" instruction never said
character-for-character, so ``rule_span`` paraphrases survived the single
repair call; and no worked example showed a compliant addition for the
behavior-class check shape. Round 2 added a phantom edit target (``SC-11``
outside ``SC-1``..``SC-10``) and a byte-identical restatement of SC-3.

The fixed wording that answers these failures lives in the phrase tables
``tests/phrases/stage1a_graph_revision_system.yaml`` and
``tests/phrases/stage1a_obligation_repair_user.yaml``.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _LOCAL_HANDLE_RE,
)


def test_example_handles_are_wire_valid_local_handles() -> None:
    # The copied example handle must itself pass the production
    # request-local handle validator.
    for handle in ("NEW-1", "NEW-2", "NEW-3"):
        assert _LOCAL_HANDLE_RE.fullmatch(handle), handle
