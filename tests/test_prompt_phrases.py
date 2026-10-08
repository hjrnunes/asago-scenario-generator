"""Check every phrase table against its template's rendered prompt."""

from __future__ import annotations

import pytest

from tests.phrase_tables import (
    CASES,
    KINDS,
    PhraseCheck,
    failures,
    load_table,
    phrase_checks,
    render,
    table_paths,
    template_path,
)

_CHECKS = phrase_checks()


@pytest.mark.parametrize("check", _CHECKS, ids=[check.id for check in _CHECKS])
def test_rendered_prompt_matches_its_phrase_table(check: PhraseCheck) -> None:
    broken = failures(check, render(check.template, check.case))
    assert not broken, "\n".join(broken)


@pytest.mark.parametrize("path", table_paths(), ids=lambda path: path.stem)
def test_phrase_table_is_well_formed(path) -> None:
    table = load_table(path)
    assert set(table) == {"template", "cases"}
    assert path.stem == template_path(table["template"]).stem
    assert set(table["cases"]) <= set(CASES)
    for kinds in table["cases"].values():
        assert kinds and set(kinds) <= set(KINDS)
        for kind, phrases in kinds.items():
            assert phrases and len(set(map(str, phrases))) == len(phrases)
            nested = kind == "ordered"
            assert all(isinstance(p, list) == nested for p in phrases)


def test_failures_name_the_table_case_and_phrase() -> None:
    check = PhraseCheck(
        table="t",
        template="x.j2",
        case="c",
        kind="required",
        phrases=("present", "absent  phrase"),
    )
    ordered = PhraseCheck(
        table="t", template="x.j2", case="c", kind="ordered", phrases=(("b", "a"),)
    )
    once = PhraseCheck(
        table="t", template="x.j2", case="c", kind="once", phrases=("a",)
    )
    forbidden = PhraseCheck(
        table="t", template="x.j2", case="c", kind="forbidden", phrases=("a",)
    )

    assert failures(check, "a present b") == ["t/c/required: missing 'absent phrase'"]
    assert failures(ordered, "a b") == ["t/c/ordered: out of order ['b', 'a']"]
    assert failures(ordered, "a") == ["t/c/ordered: missing 'b' (ordered ['b', 'a'])"]
    assert failures(ordered, "b a") == []
    assert failures(once, "a a") == ["t/c/once: expected once, found 2 times: 'a'"]
    assert failures(forbidden, "a") == ["t/c/forbidden: forbidden 'a'"]
