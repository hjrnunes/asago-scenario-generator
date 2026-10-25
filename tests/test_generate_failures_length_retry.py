"""A Stage 5 concise retry joins the chain of the cut-off reply it repeats.

The fixture is trimmed from a recorded generate run: request 172 stopped at
its completion cap, and its concise retry, request 173, succeeded. The log
predates the retry naming its attempt, so neither entry has ``retry_of``.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from asago_scenario_generator.report.failures import failure_chains
from asago_scenario_generator.report.run_data import load_run
from asago_scenario_generator.report.slot_view import slot_views

FIXTURE = Path(__file__).parent / "fixtures" / "stage5_concise_retry"


def _copy(tmp_path: Path) -> Path:
    target = tmp_path / "output"
    shutil.copytree(FIXTURE, target)
    return target


def _chains(output: Path):
    run = load_run(output)
    return failure_chains(run, slot_views(run))


def _sequences(chain) -> list[int]:
    return [r.sequence for c in chain.calls for r in c.provider_requests]


def _rewrite_calls(output: Path, change) -> None:
    path = output / "calls.jsonl"
    calls = [json.loads(line) for line in path.read_text().splitlines()]
    change(calls)
    path.write_text("".join(json.dumps(c) + "\n" for c in calls))


def test_a_successful_concise_retry_recovers_the_cut_off_scenario(
    tmp_path: Path,
) -> None:
    (chain,) = _chains(_copy(tmp_path))

    assert chain.scenario == "SCN-012"
    assert _sequences(chain) == [172, 173]
    assert chain.outcome == "recovered"
    assert chain.effect == "The retry succeeded."


def test_a_linked_concise_retry_recovers_the_cut_off_scenario(
    tmp_path: Path,
) -> None:
    output = _copy(tmp_path)

    def link(calls: list[dict]) -> None:
        calls[1]["retry_of"] = calls[0]["attempt_id"]

    _rewrite_calls(output, link)

    (chain,) = _chains(output)

    assert (_sequences(chain), chain.outcome) == ([172, 173], "recovered")


def test_an_unlinked_request_after_a_complete_reply_starts_its_own_chain(
    tmp_path: Path,
) -> None:
    output = _copy(tmp_path)
    records = output / "provider-calls.jsonl"
    records.write_text(records.read_text().replace('"length"', '"stop"'))

    (chain,) = _chains(output)

    assert _sequences(chain) == [172]
    assert chain.outcome == "lost"


def test_a_request_for_another_slot_does_not_continue_the_chain(
    tmp_path: Path,
) -> None:
    output = _copy(tmp_path)

    def move(calls: list[dict]) -> None:
        calls[1]["slot_id"] = "CL-5:CM-5:NOT_PROVIDED"

    _rewrite_calls(output, move)

    (chain,) = _chains(output)

    assert (_sequences(chain), chain.outcome) == ([172], "lost")
