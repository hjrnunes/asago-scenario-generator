"""Stage 1a prompt hardening for the derived-branch templates.

Four fresh OcciAI/Airbnb chains died at derived Stage 1a on provider output
quality (see the mission library m3-stage1a-blocker-diagnosis): the bounded
revision prompt lacked a concrete ``NEW-*`` handle example and any negative
example, so providers continued the reserved canonical numbering
(``H-7``/``SC-4``); the "quote the rule verbatim" instruction never said
character-for-character, so ``rule_span`` paraphrases survived the single
repair call; and no worked example showed a compliant addition for the
behavior-class check shape.  These tests pin the rendered prompts to the fix
design (prompt-side only; the deterministic typed rejections are untouched
backstops).

Round-2 failure classes pinned below: a well-formed NEW-handle addition
accompanied by a phantom edit targeting ``SC-11`` outside the presented
``SC-1``..``SC-10`` set (the whole revision was rejected as an unknown edit
target), and a byte-identical restatement of SC-3 instead of the worked-example
addition (the merged graph was unchanged, the density gate re-failed, and the
single revision call was spent).
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _LOCAL_HANDLE_RE,
)


def _render(name: str, **kwargs: object) -> str:
    return TemplateLoader(PROMPTS_DIR).render_prompt(name, **kwargs)


def _revision_system_prompt() -> str:
    return _render("stage1a_graph_revision_system.j2")


def _repair_user_prompt() -> str:
    return _render(
        "stage1a_obligation_repair_user.j2",
        use_case_text="Test use case",
        selected_constraints=[],
    )


def _obligation_entries_prompt() -> str:
    return _render("_obligation_entries.j2")


def _norm(text: str) -> str:
    return " ".join(text.split())


_CONTIGUOUS_SUBSTRING = "contiguous substring of its constraint's `rule`"

# Fragments the whitespace-normalised prompt must contain, keyed by test id.
_REVISION_REQUIRES = {
    "concrete_new_handles": "`NEW-1`, `NEW-2`, `NEW-3`",
    "reserved_spellings_forbidden": (
        "Never use `H-7`, `SC-4`, `L-8`, or any `H-*`/`SC-*`/`L-*`"
    ),
    "reserved_canonical": "reserved canonical",
    "reserved_rejection": "the response is rejected",
    "wildcard_spellings_render_literally": "`H-*`/`SC-*`/`L-*`",
    "no_canonical_continuation": "may not continue the canonical numbering",
    "behavior_class_shape": "behavior class",
    "behavior_class_new_hazard": "one new hazard with a `NEW-*` handle",
    "behavior_class_names_behavior": "names that class's behavior",
    "behavior_class_same_response_cover": "covering that handle in the same response",
    "addition_needs_constraint": (
        "Every `hazard_additions` entry must be covered in the same response "
        "by a constraint whose `related_hazards` includes the addition's handle."
    ),
    "addition_cover_options": (
        "Use either a `security_constraint_additions` entry or a "
        "`security_constraint_edits` entry that adds the handle to an existing "
        "constraint's `related_hazards`; follow the existing obligations rules "
        "for edits."
    ),
    "density_check_on_merged_graph": (
        "The full density check runs on the merged graph, so a repair that "
        "creates a new uncovered hazard fails."
    ),
    "edit_target_present": (
        "An edit target must be an ID present in the supplied graph."
    ),
    "invented_id_rejected": (
        "An invented ID (for example `SC-11` when the graph holds "
        "`SC-1`..`SC-10`) is rejected as an unknown target and the whole "
        "revision fails."
    ),
    "no_duplicate_edit": (
        "If an addition already fixes a check, do not also return an "
        "edit for the same fix"
    ),
    "addition_alone_is_complete": (
        "the addition alone is the complete response for that check"
    ),
    "noop_edit_fixes_nothing": (
        "An edit that restates an existing record's content unchanged fixes nothing"
    ),
    "noop_edit_spends_the_call": (
        "the merged graph is identical, the check re-fails, and the "
        "single revision call is spent"
    ),
    "edge_repair_over_noop": (
        "When a failing check names a record pair, edit one of the named "
        "records to repair that edge"
    ),
    "no_byte_identical_edit": (
        "never return a byte-identical edit or a disconnected addition"
    ),
    "smallest_edge_repair": (
        "choose the smallest repair that changes the failing edge"
    ),
    "edit_related_hazards": (
        "edit that constraint's `related_hazards` to the correct supplied hazard ID"
    ),
    "no_second_constraint_beside_wrong_edge": (
        "Do not add a second constraint while leaving the wrong edge"
    ),
    "unsupported_repair_rejected": (
        "relies on unsupported wording is not a repair and must not be returned"
    ),
    "recheck_after_merge": (
        "After mentally merging the delta, re-check every listed failure"
    ),
    "recheck_bad_edge": "leaves any listed bad edge intact",
    "recheck_unresolved_reference": "introduces an unresolved reference",
    "recheck_unsupported_wording": "unsupported wording",
}

_REVISION_FORBIDS = {
    "advisory_subject_phrase_check": "share no subject phrase",
    "advisory_wrong_subject_wording": "wrong subject wording",
}

_REPAIR_REQUIRES = {
    "contiguous_substring": _CONTIGUOUS_SUBSTRING,
    "case_insensitive_comparison": "compared case-insensitively",
    "backticks": "backticks",
    "no_rewording": "no ellipsis, omission, or rewording",
    "rejection_is_terminal": "rejected, and there is no second repair",
}

# Substrings that must appear in this order in the raw rendered revision prompt.
_REVISION_ORDER = {
    "worked_examples_after_response_format": (
        '"security_constraint_additions"',
        "## Worked examples",
    ),
    "edit_target_bullet_between_edits_and_additions": (
        "`security_constraint_edits` replaces",
        "An edit target must be an ID present in the supplied graph.",
        "`security_constraint_additions` declares",
    ),
    "noop_warning_closes_worked_examples": (
        "## Worked examples",
        "An edit that restates an existing record's content unchanged",
    ),
}


@pytest.mark.parametrize(
    "fragment", _REVISION_REQUIRES.values(), ids=_REVISION_REQUIRES
)
def test_revision_prompt_states(fragment: str) -> None:
    assert fragment in _norm(_revision_system_prompt())


@pytest.mark.parametrize("fragment", _REVISION_FORBIDS.values(), ids=_REVISION_FORBIDS)
def test_revision_prompt_omits(fragment: str) -> None:
    assert fragment not in _norm(_revision_system_prompt())


@pytest.mark.parametrize("markers", _REVISION_ORDER.values(), ids=_REVISION_ORDER)
def test_revision_prompt_section_order(markers: tuple[str, ...]) -> None:
    prompt = _revision_system_prompt()
    positions = [prompt.index(marker) for marker in markers]
    assert positions == sorted(positions)


def test_example_handles_are_wire_valid_local_handles() -> None:
    # The copied example handle must itself pass the production
    # request-local handle validator.
    for handle in ("NEW-1", "NEW-2", "NEW-3"):
        assert _LOCAL_HANDLE_RE.fullmatch(handle), handle


@pytest.mark.parametrize("fragment", _REPAIR_REQUIRES.values(), ids=_REPAIR_REQUIRES)
def test_repair_prompt_states(fragment: str) -> None:
    assert fragment in _norm(_repair_user_prompt())


def test_repair_prompt_replaced_the_verbatim_sentence() -> None:
    assert "Quote the rule verbatim" not in _norm(_repair_user_prompt())


def test_shared_obligation_paragraph_carries_the_substring_instruction() -> None:
    """Derivation and revision share the rule; ``test_rule_span_prose.py``
    pins that every system prompt renders it."""
    prompt = _norm(_obligation_entries_prompt())
    assert _CONTIGUOUS_SUBSTRING in prompt
    assert "Copy its words in order from `rule`" in prompt
