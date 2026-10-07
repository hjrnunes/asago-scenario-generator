"""The mechanism verifier names each request with a short local handle."""

from __future__ import annotations

import re

import yaml

from tests.helpers.mechanism_verifier_handles import (
    _VerifierClient,
    _route,
    _single_brief,
    _verdict,
)

_FULL_HANDLE = re.compile(r"ob:v1:[0-9a-f]{64}")


def test_verifier_prompt_names_the_item_with_a_short_handle(tmp_path) -> None:
    """The prompt carries R1, never the content-addressed obligation handle."""
    briefs = _single_brief()
    client = _VerifierClient(briefs, [[_verdict("R1")]])

    result = _route(client, briefs, tmp_path)

    prompt = client.verifier_prompts[0]
    body = prompt.split("Mechanism/path comparisons:\n", 1)[1].split("\nReturn a JSON")[
        0
    ]
    (item,) = yaml.safe_load(body)
    assert set(item) == {
        "item_handle",
        "distinctive_mechanism",
        "selected_structural_path",
    }
    assert "item_handle: R1" in prompt
    assert not _FULL_HANDLE.search(prompt)
    route = result.routes[0]
    assert route.semantic_assessment.mechanism_assessment == "plausible_in_system"


def test_verdict_for_an_unknown_handle_is_repaired_with_the_exact_handles(
    tmp_path,
) -> None:
    """A handle the prompt never showed earns one repair that names R-handles."""
    briefs = _single_brief()
    client = _VerifierClient(briefs, [[_verdict("R7")], [_verdict("R1")]])

    result = _route(client, briefs, tmp_path)

    assert len(client.verifier_prompts) == 2
    repair = client.verifier_prompts[1]
    assert "R7" in repair and "R1" in repair
    assert not _FULL_HANDLE.search(repair)
    assert result.routes[0].semantic_assessment.mechanism_assessment == (
        "plausible_in_system"
    )


def test_verdict_with_a_corrupted_handle_after_the_repair_fails_closed(
    tmp_path,
) -> None:
    """Two unusable answers leave the route without mechanism credit."""
    briefs = _single_brief()
    client = _VerifierClient(briefs, [[_verdict("R7")], [_verdict("R8")]])

    result = _route(client, briefs, tmp_path)

    assert len(client.verifier_prompts) == 2
    assert result.routes[0].semantic_assessment.mechanism_assessment == (
        "insufficient_evidence"
    )
