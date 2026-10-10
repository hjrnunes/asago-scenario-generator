"""Failed model requests group into chains, and each chain says what it cost."""

from __future__ import annotations

from collections import Counter
from dataclasses import replace
from pathlib import Path

from asago_scenario_generator.report.failures import failure_chains
from asago_scenario_generator.report.run_data import load_run
from asago_scenario_generator.report.slot_view import slot_views
from tests.helpers.generate_report_fixture import copy_run, edit_calls


def chains(output: Path):
    run = load_run(output)
    return failure_chains(run, slot_views(run))


def call(step: str, number: int, ok: bool, **extra) -> dict:
    return {
        "stage": "stage_5",
        "step": step,
        "scenario_id": extra.pop("scenario_id", None),
        "attempt_id": extra.pop("attempt_id", f"{step}:{number}:{ok}"),
        "attempt_number": number,
        "success": ok,
        "error": None if ok else "ValueError: bad",
        **extra,
    }


def test_every_failed_request_belongs_to_exactly_one_chain(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    run = load_run(output)

    found = chains(output)

    failed = [c.n for c in run.calls if not c.success]
    assert sorted(n for f in found for n in f.failed_numbers) == failed
    assert len(failed) == 10


def test_the_fixture_chains_split_by_outcome(tmp_path: Path) -> None:
    found = chains(copy_run(tmp_path))

    assert Counter(f.outcome for f in found) == {
        "recovered": 7,
        "degraded": 1,
        "lost": 1,
    }


def test_chains_list_lost_first_and_name_their_requests(tmp_path: Path) -> None:
    found = chains(copy_run(tmp_path))

    assert [f.outcome for f in found][:2] == ["lost", "degraded"]
    assert found[1].scenario == "SCN-023"
    assert found[1].failed_numbers == [155, 156]


def test_a_retry_that_succeeds_recovers_the_chain(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    edit_calls(
        output,
        lambda calls: calls.extend(
            [
                call("x", 1, False, scenario_id="SCN-001"),
                call("x", 2, True, scenario_id="SCN-001"),
            ]
        ),
    )

    chain = next(f for f in chains(output) if f.step == "x")

    assert (chain.outcome, chain.failed_numbers) == ("recovered", [162])
    assert chain.effect == "The retry succeeded."


def test_retry_of_links_attempts_that_interleave(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    edit_calls(
        output,
        lambda calls: calls.extend(
            [
                call("y", 1, False, attempt_id="a1"),
                call("y", 1, False, attempt_id="b1"),
                call("y", 2, True, attempt_id="a2", retry_of="a1"),
                call("y", 2, False, attempt_id="b2", retry_of="b1"),
            ]
        ),
    )

    found = [f for f in chains(output) if f.step == "y"]

    assert sorted(f.outcome for f in found) == ["lost", "recovered"]
    assert all(len(f.failed_numbers) <= 2 for f in found)


def test_a_repair_request_that_succeeds_repairs_the_chain(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    edit_calls(
        output,
        lambda calls: calls.extend(
            [call("draft", 1, False), call("draft_repair", 1, True)]
        ),
    )

    chain = next(f for f in chains(output) if f.step == "draft")

    assert chain.outcome == "repaired"


def test_a_slot_without_a_decision_makes_its_owners_failure_lost(
    tmp_path: Path,
) -> None:
    output = copy_run(tmp_path)
    edit_calls(
        output,
        lambda calls: calls.__delitem__(
            slice(88, 89)
        ),  # the retry that answered RESP-1
    )
    run = load_run(output)
    slots = [
        replace(v, decision="none") if v.slot_id == "RESP-1:CA-1-1:WRONG_TIMING" else v
        for v in slot_views(run)
    ]

    chain = next(f for f in failure_chains(run, slots) if f.step == "RESP-1")

    assert chain.outcome == "lost"
    assert "RESP-1:CA-1-1:WRONG_TIMING has no decision" in chain.effect


def test_an_analytical_only_scenario_whose_writing_failed_is_lost(
    tmp_path: Path,
) -> None:
    output = copy_run(tmp_path)

    def only_failures(calls: list[dict]) -> None:
        calls[:] = [
            c for c in calls if not (c.get("scenario_id") == "SCN-002" and c["success"])
        ]

    edit_calls(output, only_failures)

    chain = next(f for f in chains(output) if f.scenario == "SCN-002")

    assert chain.outcome == "lost"
    assert "analytical only" in chain.effect


def test_the_error_code_and_message_are_split_from_the_error_text(
    tmp_path: Path,
) -> None:
    found = chains(copy_run(tmp_path))

    degraded = next(f for f in found if f.outcome == "degraded")
    assert degraded.code == "discriminating_condition_check_failed"
    assert degraded.message.startswith("the discriminating condition must")
