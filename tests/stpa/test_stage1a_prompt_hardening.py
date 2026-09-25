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
"""

from __future__ import annotations

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


class TestRevisionHandleExample:
    """The revision prompt carries a concrete request-local handle example."""

    def test_prompt_shows_concrete_new_handles(self) -> None:
        prompt = _norm(_revision_system_prompt())
        assert "`NEW-1`, `NEW-2`, `NEW-3`" in prompt

    def test_example_handles_are_wire_valid_local_handles(self) -> None:
        # The copied example handle must itself pass the production
        # request-local handle validator.
        for handle in ("NEW-1", "NEW-2", "NEW-3"):
            assert _LOCAL_HANDLE_RE.fullmatch(handle), handle


class TestRevisionReservedIdWarning:
    """The revision prompt names the reserved canonical spellings as forbidden."""

    def test_prompt_warns_against_reserved_canonical_spellings(self) -> None:
        prompt = _norm(_revision_system_prompt())
        assert "Never use `H-7`, `SC-4`, `L-8`, or any `H-*`/`SC-*`/`L-*`" in prompt
        assert "reserved canonical" in prompt
        assert "the response is rejected" in prompt

    def test_prompt_forbids_continuing_canonical_numbering(self) -> None:
        prompt = _norm(_revision_system_prompt())
        assert "may not continue the canonical numbering" in prompt


class TestRevisionWorkedExamples:
    """The revision prompt shows compliant repairs for the failing shapes."""

    def test_prompt_omits_the_advisory_subject_phrase_check(self) -> None:
        prompt = _norm(_revision_system_prompt())
        assert "share no subject phrase" not in prompt
        assert "wrong subject wording" not in prompt

    def test_prompt_works_the_behavior_class_check_shape(self) -> None:
        prompt = _norm(_revision_system_prompt())
        assert "behavior class" in prompt
        assert "one new hazard with a `NEW-*` handle" in prompt
        assert "names that class's behavior" in prompt

    def test_worked_examples_render_after_the_response_format_block(self) -> None:
        prompt = _revision_system_prompt()
        format_block = prompt.index('"security_constraint_additions"')
        worked = prompt.index("## Worked examples")
        assert format_block < worked


class TestRevisionUnknownEditTarget:
    """The revision prompt forbids invented edit targets and duplicate fixes.

    Round-2 failure class (airbnb reconfirmation): a well-formed NEW-handle
    addition was accompanied by a phantom edit targeting ``SC-11`` outside
    the presented ``SC-1``..``SC-10`` set, and the whole revision was
    rejected as an unknown edit target.
    """

    def test_prompt_requires_edit_targets_present_in_the_graph(self) -> None:
        prompt = _norm(_revision_system_prompt())
        assert "An edit target must be an ID present in the supplied graph." in prompt
        assert (
            "An invented ID (for example `SC-11` when the graph holds "
            "`SC-1`..`SC-10`) is rejected as an unknown target and the whole "
            "revision fails." in prompt
        )

    def test_prompt_forbids_an_edit_duplicating_a_sufficient_addition(self) -> None:
        prompt = _norm(_revision_system_prompt())
        assert (
            "If an addition already fixes a check, do not also return an "
            "edit for the same fix" in prompt
        )
        assert "the addition alone is the complete response for that check" in prompt

    def test_bullet_renders_after_the_security_constraint_edits_bullet(self) -> None:
        prompt = _revision_system_prompt()
        edits_bullet = prompt.index("`security_constraint_edits` replaces")
        new_bullet = prompt.index(
            "An edit target must be an ID present in the supplied graph."
        )
        addition_bullet = prompt.index("`security_constraint_additions` declares")
        assert edits_bullet < new_bullet < addition_bullet


class TestRevisionNoOpEditWarning:
    """The revision prompt warns that a byte-identical edit fixes nothing.

    Round-2 failure class (occiai reconfirmation): the model restated SC-3
    byte-identically instead of returning the worked-example addition; the
    merged graph was unchanged, the density gate re-failed, and the single
    revision call was spent.
    """

    def test_prompt_warns_that_a_noop_edit_fixes_nothing(self) -> None:
        prompt = _norm(_revision_system_prompt())
        assert (
            "An edit that restates an existing record's content unchanged "
            "fixes nothing" in prompt
        )
        assert (
            "the merged graph is identical, the check re-fails, and the "
            "single revision call is spent" in prompt
        )

    def test_prompt_demands_an_edge_repair_over_a_byte_identical_edit(self) -> None:
        prompt = _norm(_revision_system_prompt())
        assert (
            "When a failing check names a record pair, edit one of the named "
            "records to repair that edge" in prompt
        )
        assert "never return a byte-identical edit or a disconnected addition" in prompt

    def test_noop_warning_closes_the_worked_examples_section(self) -> None:
        prompt = _revision_system_prompt()
        worked = prompt.index("## Worked examples")
        warning = prompt.index(
            "An edit that restates an existing record's content unchanged"
        )
        assert worked < warning


class TestRevisionEdgeRepairGuidance:
    """The revision prompt requires changing the failing edge itself."""

    def test_prompt_requires_smallest_repair_that_changes_the_edge(self) -> None:
        prompt = _norm(_revision_system_prompt())
        assert "choose the smallest repair that changes the failing edge" in prompt
        assert (
            "edit that constraint's `related_hazards` to the correct supplied hazard ID"
            in prompt
        )
        assert "Do not add a second constraint while leaving the wrong edge" in prompt

    def test_prompt_rejects_unsupported_repairs(self) -> None:
        prompt = _norm(_revision_system_prompt())
        assert (
            "relies on unsupported wording is not a repair and must not be returned"
            in prompt
        )

    def test_prompt_closes_with_complete_graph_recheck(self) -> None:
        prompt = _norm(_revision_system_prompt())
        assert (
            "After mentally merging the delta, re-check every listed failure" in prompt
        )
        assert "leaves any listed bad edge intact" in prompt
        assert "introduces an unresolved reference" in prompt
        assert "unsupported wording" in prompt


class TestRepairExactCopyInstruction:
    """The repair user prompt demands an exact contiguous substring span."""

    def test_prompt_requires_character_for_character_copy(self) -> None:
        prompt = _norm(_repair_user_prompt())
        assert "character-for-character" in prompt
        assert "exact contiguous substring of the constraint's Rule text" in prompt
        assert "backticks included" in prompt

    def test_prompt_forbids_paraphrase_and_edits(self) -> None:
        prompt = _norm(_repair_user_prompt())
        assert "no paraphrase" in prompt
        assert "no punctuation or capitalization change" in prompt

    def test_prompt_states_the_rejection_is_terminal(self) -> None:
        prompt = _norm(_repair_user_prompt())
        assert "rejected, and there is no second repair" in prompt

    def test_old_verbatim_sentence_is_replaced(self) -> None:
        prompt = _norm(_repair_user_prompt())
        assert "Quote the rule verbatim" not in prompt


class TestSharedObligationParagraphExactCopy:
    """Derivation and revision carry the same character-for-character rule."""

    def test_paragraph_carries_exact_substring_instruction(self) -> None:
        prompt = _norm(_obligation_entries_prompt())
        assert "Copy that span character-for-character from `rule`" in prompt
        assert "an exact substring, never a paraphrase" in prompt

    def test_instruction_renders_through_the_revision_system_prompt(self) -> None:
        prompt = _norm(_revision_system_prompt())
        assert "Copy that span character-for-character from `rule`" in prompt

    def test_instruction_renders_through_the_repair_system_prompt(self) -> None:
        prompt = _norm(_render("stage1a_obligation_repair_system.j2"))
        assert "Copy that span character-for-character from `rule`" in prompt


class TestHandleSpellingSafety:
    """Reserved-ID prose spellings must not collide with Jinja delimiters."""

    def test_reserved_spellings_render_literally(self) -> None:
        prompt = _norm(_revision_system_prompt())
        # The wildcard spellings survive rendering as literal prose (a
        # Jinja-escaped form would have dropped or altered them).
        assert "`H-*`/`SC-*`/`L-*`" in prompt
