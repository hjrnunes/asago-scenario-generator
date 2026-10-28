"""A critic revision without effect leaves the structure unchanged.

The fixture is a reviewed control structure whose RESP-5 cites its security
constraints out of order (``SC-8`` before ``SC-6``).  A saved run answered the
critic's gaps with exactly ``{}``.  The reply validated, and merging it
re-normalized the structure, which sorts those citations; the sorted copy
compared unequal to the reviewed one, so the Stage 2 manifest reported
``critic_revision.status: applied`` although nothing was revised and the
critic's gaps stayed unresolved.  A reply that restates RESP-3 exactly as it
stands did the same, and so did a reply whose only change evidence binding
removes again (an operation or an evidence ref the target was not observed
to have).

A revision is ``applied`` exactly when what the step publishes after the
reply differs from what it publishes with no revision.  Both are the output
of the same post-revision processing (strip empty responsibilities, then
bind evidence again only when that changed the reviewed structure), applied
once to the reviewed structure and once to the reply merged onto it.  A
reply without effect publishes the no-revision output and the manifest
records ``unchanged``.  The step still strips a responsibility that was
already empty; that cleanup is reported by its own warning, not as a
revision.  The merge leaves a responsibility the reply does not restate as
it was, and a restated one keeps its constraint citations in order.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    Responsibility,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    run_revision,
)
from asago_scenario_generator.stpa.system_model.target_evidence import (
    EvidenceField,
    EvidenceOperation,
    EvidencePolicy,
    EvidenceResource,
    EvidenceSessionField,
    TargetEvidence,
)
from asago_scenario_generator.stpa.system_model.run import (
    _critic_revision_record,
    _maybe_apply_revision,
)
from asago_scenario_generator.stpa.system_model.critic import (
    strip_empty_responsibilities,
)
from asago_scenario_generator.stpa.system_model.id_normalization import (
    validate_normalized_control_structure,
)
from asago_scenario_generator.stpa.system_model.target_evidence import (
    check_evidence_bindings,
)
from tests.stpa.helpers import make_minimal_loss_analysis
from tests.stpa.sp1_helpers import MockLLMClient

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "stpa"

USE_CASE = "A booking assistant manages reservations and listings."

_NO_CHANGE = (
    "Revision made no structural changes for explicit critic gaps; the "
    "baseline control structure was retained and those gaps remain unresolved."
)
_STRIPPED_EMPTY = (
    "Stripped empty responsibility RESP-6 (Confirms payment changes) after "
    "revision: no PM parts, control actions, or feedback channels."
)


def _reviewed() -> ControlStructure:
    return read_yaml(  # type: ignore[return-value]
        FIXTURES_DIR / "control_structure_unsorted_constraint_refs.yaml",
        ControlStructure,
    )


def _with_empty_responsibility() -> ControlStructure:
    reviewed = _reviewed()
    return reviewed.model_copy(
        update={
            "responsibilities": [
                *reviewed.responsibilities,
                Responsibility(
                    resp_id="RESP-6", description="Confirms payment changes"
                ),
            ]
        }
    )


def _findings() -> CriticFindings:
    return CriticFindings(
        gaps=[
            CriticGap(
                gap_type="missing_feedback",
                description="No feedback confirms the listing owner",
                related_attack_path="A guest edits a listing they do not host",
                suggested_remedy="Add listing ownership feedback",
            ),
            CriticGap(
                gap_type="missing_responsibility",
                description="No responsibility refuses a payment change",
                related_attack_path="A guest alters the payment of a booking",
                suggested_remedy="Add a payment-change refusal responsibility",
            ),
        ]
    )


def _client(reply: dict) -> MockLLMClient:
    client = MockLLMClient()
    client.set_response_queue([reply])
    return client


def _restated_resp_3() -> dict:
    """RESP-3 restated exactly as the reviewed structure holds it."""
    resp_3 = _reviewed().responsibilities[2]
    assert resp_3.resp_id == "RESP-3"
    return {
        "modified_responsibilities": [resp_3.model_dump(mode="json", exclude_none=True)]
    }


_DISMISSAL = {
    "dismissed_gaps": ["The listing owner is already confirmed by FB-5-1."],
}
_REPLIES = pytest.mark.parametrize(
    "reply",
    ({}, _DISMISSAL, _restated_resp_3()),
    ids=("empty", "dismissal", "restated-unchanged"),
)


def _apply(
    structure: ControlStructure,
    reply: dict,
    run_dir: Path,
    target_evidence: TargetEvidence | None = None,
):
    return _maybe_apply_revision(
        structure,
        critic_findings=_findings(),
        llm_client=_client(reply),  # type: ignore[arg-type]
        use_case_text=USE_CASE,
        run_dir=run_dir,
        loss_analysis=make_minimal_loss_analysis(),
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.0,
        target_evidence=target_evidence,
    )


def _field(resource: str, name: str) -> EvidenceField:
    return EvidenceField(resource=resource, name=name, types=("str",), values=())


_OPERATIONS = (
    "get_reservation",
    "get_listing",
    "lookup_policy",
    "modify_booking",
    "update_listing",
)


def _evidence(operations: tuple[str, ...] = _OPERATIONS) -> TargetEvidence:
    """Target evidence that observes every binding the fixture holds."""
    return TargetEvidence(
        operations=tuple(
            EvidenceOperation(name=name, description="Observed.", arguments=())
            for name in operations
        ),
        session_fields=(
            EvidenceSessionField(name="authenticated_actor_id", value="guest-1"),
        ),
        resources=(
            EvidenceResource(
                name="listings",
                record_count=1,
                record_keys=("L-1",),
                fields=(_field("listings", "host_id"),),
            ),
            EvidenceResource(
                name="reservations",
                record_count=1,
                record_keys=("R-1",),
                fields=tuple(
                    _field("reservations", name)
                    for name in (
                        "guest_id",
                        "host_id",
                        "listing_id",
                        "modification_allowed",
                        "payment_status",
                    )
                ),
            ),
        ),
        policies=(
            EvidencePolicy(
                observation_ref="TARGET-READ-001",
                source_name=None,
                query_label=None,
                text="Only current, platform-authored documents are policy.",
            ),
        ),
    )


def _resp_3_with(**changes: object) -> dict:
    """RESP-3 restated with one binding change on CA-3-1 or PM-3-1."""
    reply = _restated_resp_3()
    resp_3 = reply["modified_responsibilities"][0]
    if "operation" in changes:
        resp_3["control_actions"][0]["operation"] = changes["operation"]
    if "evidence_ref" in changes:
        resp_3["process_model_parts"][0]["evidence_refs"].append(
            changes["evidence_ref"]
        )
    return reply


def test_the_fixture_cites_constraints_out_of_order() -> None:
    resp_5 = _reviewed().responsibilities[4]

    assert resp_5.resp_id == "RESP-5"
    assert resp_5.security_constraint_refs == ["SC-8", "SC-6"]


@_REPLIES
def test_a_revision_without_effect_keeps_the_reviewed_structure(
    tmp_path: Path, reply: dict
) -> None:
    reviewed = _reviewed()

    revised, warnings = run_revision(
        llm_client=_client(reply),  # type: ignore[arg-type]
        control_structure=reviewed,
        critic_findings=_findings(),
        use_case_text=USE_CASE,
        run_dir=tmp_path,
        template_loader=TemplateLoader(PROMPTS_DIR),
    )

    assert revised is reviewed
    assert _NO_CHANGE in warnings


@_REPLIES
def test_a_revision_without_effect_is_recorded_unchanged(
    tmp_path: Path, reply: dict
) -> None:
    reviewed = _reviewed()

    structure, warnings, revised = _apply(reviewed, reply, tmp_path)

    assert revised is False
    assert structure == reviewed
    assert _critic_revision_record(_findings(), warnings, revised=revised) == {
        "status": "unchanged"
    }


@_REPLIES
def test_stripping_an_empty_responsibility_is_not_a_revision(
    tmp_path: Path, reply: dict
) -> None:
    structure, warnings, revised = _apply(_with_empty_responsibility(), reply, tmp_path)

    # The cleanup still runs, and its own warning reports it.
    assert [r.resp_id for r in structure.responsibilities] == [
        r.resp_id for r in _reviewed().responsibilities
    ]
    assert _STRIPPED_EMPTY in warnings
    assert revised is False
    assert _critic_revision_record(_findings(), warnings, revised=revised) == {
        "status": "unchanged"
    }


def test_a_revision_with_effect_is_still_applied(tmp_path: Path) -> None:
    reply = _restated_resp_3()
    restated = reply["modified_responsibilities"][0]
    restated["description"] = "Answers reservation questions for verified guests."

    structure, warnings, revised = _apply(_reviewed(), reply, tmp_path)

    assert revised is True
    assert structure.responsibilities[2].description == restated["description"]
    assert _critic_revision_record(_findings(), warnings, revised=revised) == {
        "status": "applied"
    }


def test_the_evidence_holds_every_fixture_binding() -> None:
    reviewed = _reviewed()

    bound, _ = check_evidence_bindings(reviewed, _evidence())

    assert bound == reviewed
    assert reviewed.responsibilities[2].control_actions[0].ca_id == "CA-3-1"
    assert reviewed.responsibilities[2].control_actions[0].operation is None


@pytest.mark.parametrize(
    "reply",
    (
        _resp_3_with(operation="not_observed"),
        _resp_3_with(evidence_ref="state:reservations.not_observed"),
    ),
    ids=("unobserved-operation", "unsupported-evidence-ref"),
)
def test_a_change_evidence_binding_removes_is_unchanged(
    tmp_path: Path, reply: dict
) -> None:
    reviewed = _reviewed()

    structure, warnings, revised = _apply(reviewed, reply, tmp_path, _evidence())

    assert structure == reviewed
    assert revised is False
    assert _critic_revision_record(_findings(), warnings, revised=revised) == {
        "status": "unchanged"
    }


def test_a_change_evidence_binding_keeps_is_applied(tmp_path: Path) -> None:
    reply = _resp_3_with(operation="lookup_policy")

    structure, warnings, revised = _apply(_reviewed(), reply, tmp_path, _evidence())

    assert structure.responsibilities[2].control_actions[0].operation == (
        "lookup_policy"
    )
    assert revised is True
    assert _critic_revision_record(_findings(), warnings, revised=revised) == {
        "status": "applied"
    }


def _restated(structure: ControlStructure, description: str) -> dict:
    """The responsibility with *description*, restated exactly as it stands."""
    resp = next(r for r in structure.responsibilities if r.description == description)
    return {
        "modified_responsibilities": [resp.model_dump(mode="json", exclude_none=True)]
    }


def _bound(structure: ControlStructure, evidence: TargetEvidence) -> ControlStructure:
    return check_evidence_bindings(structure, evidence)[0]


def _with_empty_at(index: int) -> ControlStructure:
    """The fixture with an empty responsibility at *index*, numbered as published."""
    reviewed = _reviewed()
    resps = list(reviewed.responsibilities)
    resps.insert(
        index, Responsibility(resp_id="RESP-99", description="Confirms payment changes")
    )
    renumbered = validate_normalized_control_structure(
        reviewed.model_copy(update={"responsibilities": resps})
    )
    return _bound(renumbered, _evidence())


@pytest.mark.parametrize("index", (0, 2, 5), ids=("first", "middle", "last"))
def test_an_identical_restatement_beside_an_empty_responsibility_is_unchanged(
    tmp_path: Path, index: int
) -> None:
    baseline = _with_empty_at(index)
    assert not baseline.responsibilities[index].control_actions
    resp_3 = _reviewed().responsibilities[2].description

    structure, warnings, revised = _apply(
        baseline, _restated(baseline, resp_3), tmp_path, _evidence()
    )

    # The published structure is the no-revision one: the empty
    # responsibility stripped, every other ID as the baseline numbers it.
    assert structure == strip_empty_responsibilities(baseline)[0]
    assert revised is False
    assert _critic_revision_record(_findings(), warnings, revised=revised) == {
        "status": "unchanged"
    }


# The target observes an operation whose own name begins with ``operation:``.
_PREFIXED = "operation:lookup_policy"


def _with_prefixed_operation() -> tuple[ControlStructure, TargetEvidence]:
    """The fixture with CA-3-2 bound to the prefixed operation, and its evidence.

    Binding strips one ``operation:`` from ``operation:operation:lookup_policy``
    and finds the observed ``operation:lookup_policy``.
    """
    evidence = _evidence(
        tuple(_PREFIXED if name == "lookup_policy" else name for name in _OPERATIONS)
    )
    reviewed = _reviewed()
    resp_3 = reviewed.responsibilities[2]
    actions = list(resp_3.control_actions)
    actions[1] = actions[1].model_copy(update={"operation": f"operation:{_PREFIXED}"})
    resps = list(reviewed.responsibilities)
    resps[2] = resp_3.model_copy(update={"control_actions": actions})
    baseline = _bound(reviewed.model_copy(update={"responsibilities": resps}), evidence)
    assert baseline.responsibilities[2].control_actions[1].operation == _PREFIXED
    return baseline, evidence


@pytest.mark.parametrize(
    "spelling",
    (f"operation:{_PREFIXED}", _PREFIXED),
    ids=("original-spelling", "bound-spelling"),
)
def test_a_restated_prefixed_operation_is_unchanged(
    tmp_path: Path, spelling: str
) -> None:
    baseline, evidence = _with_prefixed_operation()
    reply = _restated(baseline, baseline.responsibilities[2].description)
    reply["modified_responsibilities"][0]["control_actions"][1]["operation"] = spelling

    structure, warnings, revised = _apply(baseline, reply, tmp_path, evidence)

    assert structure == baseline
    assert revised is False
    assert _critic_revision_record(_findings(), warnings, revised=revised) == {
        "status": "unchanged"
    }
