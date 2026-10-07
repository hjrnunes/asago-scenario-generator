"""Duplicate references in target-derived ICA drafts get one correction call.

A target-derived ICA draft that names the same hazard or constraint twice in
one finding gets exactly one correction request carrying the exact error and
the prior response (decision 47c, 2026-10-04).  An accepted correction goes
on to verification.  A correction that still repeats a reference, or a
correction call that fails, drops the derived findings with a
provider-failure diagnostic and the run continues; a duplicate never fails
the run.  Unknown references keep failing closed, with no correction call.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from asago_scenario_generator.pipeline.target_realization import (
    realize_target_derived_icas,
)
from asago_scenario_generator.stpa.target_realization import (
    TargetDerivedICALlmFinder,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.helpers.target_realization_provider import (
    _PAYMENT_SLOT,
    _payment_draft,
    _payment_ica_request,
    _supported,
)
from tests.helpers.target_realization import _baseline, _target_extended_result

_EXTENDED_SLOT = "RESP-1:CA-1-2:INCORRECT"
_DRAFT_STEP = "enumerate_target_derived_icas"
_CORRECTION_STEP = "enumerate_target_derived_icas_correction"
_VERIFY_STEP = "verify_target_derived_icas"


def _steps(run_dir: Path) -> list[str]:
    return [
        json.loads(line)["step"]
        for line in (run_dir / "calls.jsonl").read_text().splitlines()
    ]


def _draft_with(slot_id: str = _PAYMENT_SLOT, **references: list[str]) -> dict:
    draft = _payment_draft("The payment action is not provided.")
    draft["findings"][0]["slot_id"] = slot_id
    draft["findings"][0].update(references)
    return draft


class _FailingCorrectionClient(MockLLMClient):
    """Answer every call except the correction request, which fails."""

    def complete(self, system_prompt, user_prompt, *args, **kwargs):
        if "Correction request" in user_prompt:
            self.calls.append(None)
            raise RuntimeError("provider unavailable")
        return super().complete(system_prompt, user_prompt, *args, **kwargs)


class TestProviderCorrection:
    """The provider corrects a duplicate once before verification."""

    @pytest.mark.parametrize(
        "references",
        [
            pytest.param({"related_hazards": ["H-1", "H-1"]}, id="hazard"),
            pytest.param({"related_constraints": ["SC-1", "SC-1"]}, id="constraint"),
        ],
    )
    def test_accepted_correction_is_what_the_verifier_sees(
        self, tmp_path, references: dict
    ) -> None:
        client = MockLLMClient()
        client.set_response_queue(
            [_draft_with(**references), _draft_with(), _supported(1)]
        )
        finder = TargetDerivedICALlmFinder(client, tmp_path, temperature=0.4)

        response = finder(_payment_ica_request())

        assert _steps(tmp_path) == [_DRAFT_STEP, _CORRECTION_STEP, _VERIFY_STEP]
        verifier_prompt = client.calls[2].user_prompt
        assert "- H-1\n  - H-1" not in verifier_prompt
        assert "- SC-1\n  - SC-1" not in verifier_prompt
        [finding] = response.findings
        assert finding.related_hazards == ("H-1",)
        assert finding.related_constraints == ("SC-1",)
        assert finding.verification.status == "verified"

    def test_draft_without_duplicates_makes_no_correction_call(self, tmp_path) -> None:
        client = MockLLMClient()
        client.set_response_queue([_draft_with(), _supported(1)])
        finder = TargetDerivedICALlmFinder(client, tmp_path, temperature=0.4)

        finder(_payment_ica_request())

        assert _steps(tmp_path) == [_DRAFT_STEP, _VERIFY_STEP]

    def test_rendered_correction_request_carries_error_and_prior_response(
        self, tmp_path
    ) -> None:
        draft = _payment_draft(
            "The first payment finding is not provided.",
            "The second payment finding is not provided.",
        )
        draft["findings"][0]["related_constraints"] = ["SC-1", "SC-1"]
        draft["findings"][1]["related_hazards"] = ["H-2", "H-1", "H-2", "H-1"]
        corrected = _payment_draft(
            "The first payment finding is not provided.",
            "The second payment finding is not provided.",
        )
        client = MockLLMClient()
        client.set_response_queue([draft, corrected, _supported(1, 2)])
        finder = TargetDerivedICALlmFinder(client, tmp_path, temperature=0.4)

        finder(_payment_ica_request())

        first, correction = client.calls[0], client.calls[1]
        assert correction.system_prompt == first.system_prompt
        prompt = correction.user_prompt
        assert prompt.startswith(first.user_prompt)
        suffix = prompt[len(first.user_prompt) :]
        assert suffix.startswith(
            "\n\nCorrection request: the prior target-derived ICA response named "
            "the same reference more than once in one finding."
        )
        assert "Write each reference exactly as the frozen baseline" in suffix
        assert (
            "\n\nPrior structured response to correct in place:\n```json\n"
            + json.dumps(draft)
            + "\n```"
        ) in suffix
        assert suffix.endswith(
            "\n\nExact validation error from the prior response:\n"
            "ValueError: target-derived ICA draft repeats references:\n"
            f"findings[0] (ica_id 'provider-0', slot {_PAYMENT_SLOT}): "
            "related_constraints repeats SC-1\n"
            f"findings[1] (ica_id 'provider-1', slot {_PAYMENT_SLOT}): "
            "related_hazards repeats H-1, H-2"
            "\n\nReturn one JSON object matching the response schema already "
            "supplied."
        )


def _realize(tmp_path: Path, client: MockLLMClient, responses: list) -> object:
    client.set_response_queue(responses)
    finder = TargetDerivedICALlmFinder(client, tmp_path, temperature=0.4)
    return realize_target_derived_icas(
        _baseline(), _target_extended_result(), lambda: finder
    )


def _decision() -> dict:
    return {
        "decisions": [
            {
                "ica_id": f"{_EXTENDED_SLOT}:1",
                "action_state": "performed_unsafe",
                "hazard_path": "supported",
                "detail": "The exact slot and baseline references agree.",
            }
        ]
    }


class TestRealizationOutcomes:
    """A duplicate never fails the run; an unknown reference still does."""

    def test_accepted_correction_reaches_the_effective_view(self, tmp_path) -> None:
        enhanced = _realize(
            tmp_path,
            MockLLMClient(),
            [
                _draft_with(_EXTENDED_SLOT, related_hazards=["H-1", "H-1"]),
                _draft_with(_EXTENDED_SLOT),
                _decision(),
            ],
        )

        assert [item.ica_id for item in enhanced.target_derived_ica_findings] == [
            f"{_EXTENDED_SLOT}:1"
        ]
        assert _steps(tmp_path) == [_DRAFT_STEP, _CORRECTION_STEP, _VERIFY_STEP]

    def test_correction_that_still_repeats_drops_findings_and_continues(
        self, tmp_path
    ) -> None:
        duplicated = _draft_with(_EXTENDED_SLOT, related_hazards=["H-1", "H-1"])
        client = MockLLMClient()

        enhanced = _realize(tmp_path, client, [duplicated, duplicated, _decision()])

        assert enhanced.target_derived_ica_findings == ()
        assert (
            "target-derived ICA finding provider failed: ValueError: "
            "target-derived ICA correction still repeats references: "
            f"findings[0] (ica_id 'provider-0', slot {_EXTENDED_SLOT}): "
            "related_hazards repeats H-1"
        ) in enhanced.diagnostics
        assert len(client.calls) == 2
        assert _steps(tmp_path) == [_DRAFT_STEP, _CORRECTION_STEP]

    def test_failed_correction_call_drops_findings_and_continues(
        self, tmp_path
    ) -> None:
        client = _FailingCorrectionClient()

        enhanced = _realize(
            tmp_path,
            client,
            [_draft_with(_EXTENDED_SLOT, related_hazards=["H-1", "H-1"]), _decision()],
        )

        assert enhanced.target_derived_ica_findings == ()
        [diagnostic] = [
            item for item in enhanced.diagnostics if "provider failed" in item
        ]
        assert diagnostic.startswith(
            "target-derived ICA finding provider failed: ValueError: "
            "target-derived ICA correction failed: "
        )
        assert len(client.calls) == 2

    def test_unknown_reference_still_fails_closed_without_correction(
        self, tmp_path
    ) -> None:
        client = MockLLMClient()

        with pytest.raises(ValueError, match="references unknown hazard\\(s\\): H-9"):
            _realize(
                tmp_path,
                client,
                [_draft_with(_EXTENDED_SLOT, related_hazards=["H-9"]), _decision()],
            )

        assert _steps(tmp_path) == [_DRAFT_STEP, _VERIFY_STEP]
