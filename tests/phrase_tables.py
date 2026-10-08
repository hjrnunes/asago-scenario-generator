"""Phrase tables: fixed prompt wording checked against rendered prompts.

Each ``tests/phrases/<template stem>.yaml`` file holds the fixed phrases of one
prompt template. It names the template and, per rendering case, the phrases
of each kind:

- ``required``: the phrase appears.
- ``once``: the phrase appears exactly once.
- ``forbidden``: the phrase does not appear.
- ``ordered``: lists of phrases that appear, each list in its order.

A case renders the template the way a request does: through the template
loader for the Stage 1 and Stage 2 templates (whose builders pass the same
arguments to ``TemplateLoader.render_prompt``), and through
``build_context_bdi_prompts`` for the Stage 5 context templates, and through
the obligation-aware prompt builders (``OBLIGATION_AWARE_BUILDS``) for the
obligation-aware templates. Phrases and rendered text are compared with runs of
whitespace collapsed to one space, so template line wrapping does not matter.

Wording that depends on a test's input (an identifier, a value or a list from
its fixture) stays as a code assert next to that fixture.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from types import SimpleNamespace

import yaml

from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
    TargetOperationReference,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import (
    ControlledProcess,
    ProcessModelPart,
    Responsibility,
)
from asago_scenario_generator.stpa.observation_contract import (
    default_observation_contract,
)
from asago_scenario_generator.stpa.obligation_aware.context_coverage import (
    build_context_coverage_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.governance_prompts import (
    build_governance_routing_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    PROMPT_TEMPLATES_DIR as OBLIGATION_AWARE_PROMPTS_DIR,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_ica_hazard_verification_prompts,
    build_mechanism_verification_prompts,
    build_structural_routing_prompts,
    build_synthesis_slot_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    build_neutral_briefs,
)
from asago_scenario_generator.stpa.scenario_prod._constants import (
    PROMPTS_DIR as STAGE5_PROMPTS_DIR,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservation,
    TargetObservationSnapshot,
)
from asago_scenario_generator.stpa.system_model._constants import (
    PROMPTS_DIR as SYSTEM_MODEL_PROMPTS_DIR,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    UnknownReference,
)
from tests.helpers.normal_authoring_wire import (
    _record_observations,
    _target_operation,
    _wrong_timing_context,
)
from tests.stpa.condition_prompt_fixture import (
    realistic_observations,
    realistic_profile,
)
from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.governance import _setup as _governance_setup
from tests.helpers.ica_hazard_verification import _request as _verification_request
from tests.helpers.obligation_aware import (
    _control_structure as _obligation_structure,
)
from tests.helpers.obligation_aware import _loss_analysis as _obligation_losses
from tests.helpers.obligation_aware import _provider_slot_request
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern

PHRASES_DIR = Path(__file__).with_name("phrases")
KINDS = ("required", "once", "forbidden", "ordered")
PROMPT_DIRS = (
    SYSTEM_MODEL_PROMPTS_DIR,
    STAGE5_PROMPTS_DIR,
    OBLIGATION_AWARE_PROMPTS_DIR,
)

_STAGE5_TEMPLATES = ("stage5_context_system.j2", "stage5_context_user.j2")

# Stage 1a user templates take the use case and the existing records; the
# system templates ignore these arguments.
RECORDS_SERVICE = {
    "use_case_text": "A records service retrieves authorized account records.",
    "risk_cards": [],
    "existing_losses": [],
    "existing_hazards": [],
    "existing_constraints": [],
    "next_loss_num": 1,
    "next_hazard_num": 1,
    "next_sc_num": 1,
    "kc_subcodes": [],
}

NEUTRAL_STATUS = {
    "use_case_text": "A neutral assistant returns status information.",
    "requirements": [],
    "capability_profile": None,
    "responsibilities": [],
}

ONE_RESPONSIBILITY = {
    **NEUTRAL_STATUS,
    "responsibilities": [
        Responsibility(
            resp_id="RESP-1",
            description="Authorizes requests",
            process_model_parts=[
                ProcessModelPart(pm_id="PM-1-1", description="Request state")
            ],
        )
    ],
}

UNKNOWN_REFERENCES = {
    "unknown_references": [
        UnknownReference("control_actions[0].target", "RESP-9"),
        UnknownReference("control_actions[0].process_model_refs", "PM-2-1", "RESP-1"),
    ],
    "responsibilities": ONE_RESPONSIBILITY["responsibilities"],
    "controlled_processes": [
        ControlledProcess(cp_id="CP-1", description="Request processor")
    ],
    "process_model_owners": ONE_RESPONSIBILITY["responsibilities"],
}

EMPTY_STRUCTURE = {
    "control_structure": SimpleNamespace(
        responsibilities=[], controlled_processes=[], coordination_links=[]
    ),
    "next_resp_num": 1,
    "next_pm_num": 1,
    "next_ca_num": 1,
    "next_fb_num": 1,
    "next_cl_num": 1,
    "next_cm_num": 1,
    "next_cp_num": 1,
}

# The revision request after a critic that reported no gaps.
NO_FINDINGS = {
    "use_case_text": "Test use case",
    "control_structure": EMPTY_STRUCTURE["control_structure"],
    "critic_findings": SimpleNamespace(
        gaps=[], checklist_results={}, taxonomy_probe_results={}
    ),
}


def _archive_item_facts() -> dict[str, object]:
    operation = TargetOperationObservation(
        reference=TargetOperationReference(
            resource_id="items", operation_id="archive_item"
        ),
        description="Archive one item record.",
        input_schema={
            "type": "object",
            "properties": {"item_id": {"type": "string"}},
            "required": ["item_id"],
        },
    )
    observations = TargetObservationSnapshot.create(
        target_profile_digest="a" * 64,
        observations=(
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content='{"item_id":"ITEM-104","state":"PENDING"}',
            ),
        ),
    )
    return {"target_operation": operation, "target_observations": observations}


def _commit_operation_facts() -> dict[str, object]:
    return {
        "target_operation": TargetOperationObservation(
            reference=TargetOperationReference(
                resource_id="ehr", operation_id="commit_to_ehr"
            ),
            description="Commit a reviewed patient draft for a clinician.",
            input_schema={
                "type": "object",
                "properties": {"patient_id": {"type": "string"}},
            },
        )
    }


def _realistic_request_facts(tool_call: bool = True) -> dict[str, object]:
    """Return the six-operation synthetic target with the default captures."""
    contract = default_observation_contract()
    if not tool_call:
        contract = contract.model_copy(
            update={
                "capture": tuple(
                    item.model_copy(update={"available": False})
                    if item.kind == "tool_call"
                    else item
                    for item in contract.capture
                )
            }
        )
    profile = realistic_profile()
    return {
        "execution_target_profile": profile,
        "target_observations": realistic_observations(profile),
        "observation_contract": contract,
    }


def _routing_batch() -> tuple[str, str]:
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    structure = _obligation_structure()
    return build_structural_routing_prompts(
        briefs=build_neutral_briefs(make_plan(), (pattern,))[:1],
        loss_analysis=_obligation_losses(),
        control_structure=structure,
        slots=create_slots(structure),
    )


def _slot_request() -> tuple[str, str]:
    request = _provider_slot_request()
    return build_synthesis_slot_prompts(
        target_id=request.target_id,
        slots=request.slots,
        routed_briefs=request.routed_briefs,
        routed_routes=request.routed_routes,
        loss_analysis=request.loss_analysis,
        control_structure=request.control_structure,
    )


def _governance_rows() -> tuple[str, str]:
    briefs, _, losses, structure = _governance_setup("risk-b")
    return build_governance_routing_prompts(
        briefs=briefs,
        loss_analysis=losses,
        control_structure=structure,
        slots=create_slots(structure),
    )


MECHANISM_ITEM = {
    "item_handle": "R1",
    "distinctive_mechanism": {"name": "Pattern", "description": "Canonical"},
    "selected_structural_path": [{"id": "CP-1", "description": "Request process."}],
}

# Each obligation-aware case calls the builder a request uses and names the
# templates of the (system, user) pair it returns.
OBLIGATION_AWARE_BUILDS: dict[
    str, tuple[Callable[[], tuple[str, str]], tuple[str, str]]
] = {
    "routing-batch": (
        _routing_batch,
        ("structural_routing_system.j2", "structural_routing_user.j2"),
    ),
    "slot-request": (
        _slot_request,
        ("synthesis_ica_system.j2", "synthesis_ica_user.j2"),
    ),
    "verification-request": (
        lambda: build_ica_hazard_verification_prompts((_verification_request(),)),
        ("ica_hazard_verification_system.j2", "ica_hazard_verification_user.j2"),
    ),
    "mechanism-item": (
        lambda: build_mechanism_verification_prompts([MECHANISM_ITEM]),
        ("mechanism_verification_system.j2", "mechanism_verification_user.j2"),
    ),
    "governance-rows": (
        _governance_rows,
        ("governance_routing_system.j2", "governance_routing_user.j2"),
    ),
    "no-context-gaps": (
        lambda: build_context_coverage_prompts(
            target_id="RESP-1", gaps=(), filled_slots=(), request=None
        ),
        ("synthesis_ica_context_system.j2", "synthesis_ica_context_user.j2"),
    ),
}


def _obligation_aware(case: str) -> Callable[[str], str]:
    def render(template: str) -> str:
        build, templates = OBLIGATION_AWARE_BUILDS[case]
        return dict(zip(templates, build()))[template]

    return render


def _system_model(**variables: object) -> Callable[[str], str]:
    def render(template: str) -> str:
        loader = TemplateLoader(SYSTEM_MODEL_PROMPTS_DIR)
        return loader.render_prompt(template, **variables)

    return render


def _stage5(facts: Callable[[], dict[str, object]]) -> Callable[[str], str]:
    def render(template: str) -> str:
        system, user = build_context_bdi_prompts(
            _wrong_timing_context(), TemplateLoader(STAGE5_PROMPTS_DIR), **facts()
        )
        return dict(zip(_STAGE5_TEMPLATES, (system, user)))[template]

    return render


# A case renders one template; the table that names it supplies the template.
CASES: dict[str, Callable[[str], str]] = {
    "no-variables": _system_model(),
    "no-stated-rules": _system_model(stated_rules=False),
    "records-service": _system_model(**RECORDS_SERVICE),
    "neutral-status": _system_model(**NEUTRAL_STATUS),
    "one-responsibility": _system_model(**ONE_RESPONSIBILITY),
    "test-use-case": _system_model(
        use_case_text="Test use case", selected_constraints=[]
    ),
    "no-probes": _system_model(taxonomy_probes=[]),
    "empty-structure": _system_model(**EMPTY_STRUCTURE),
    "unknown-references": _system_model(**UNKNOWN_REFERENCES),
    "target-blind": _stage5(dict),
    "operation": _stage5(lambda: {"target_operation": _target_operation()}),
    "observations": _stage5(lambda: {"target_observations": _record_observations()}),
    "operation-and-observations": _stage5(
        lambda: {
            "target_operation": _target_operation(),
            "target_observations": _record_observations(),
        }
    ),
    "archive-item": _stage5(_archive_item_facts),
    "commit-operation": _stage5(_commit_operation_facts),
    "realistic-request": _stage5(_realistic_request_facts),
    "realistic-no-tool-call": _stage5(lambda: _realistic_request_facts(False)),
    "stated-rules": _system_model(stated_rules=True),
    "no-findings": _system_model(**NO_FINDINGS),
    **{case: _obligation_aware(case) for case in OBLIGATION_AWARE_BUILDS},
}


@dataclass(frozen=True)
class PhraseCheck:
    """One kind of check for one case of one table."""

    table: str
    template: str
    case: str
    kind: str
    phrases: tuple[str | tuple[str, ...], ...]

    @property
    def id(self) -> str:
        return f"{self.table}/{self.case}/{self.kind}"


def normalize(text: str) -> str:
    return " ".join(text.split())


def table_paths() -> list[Path]:
    return sorted(PHRASES_DIR.glob("*.yaml"))


@cache
def load_table(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def template_path(template: str) -> Path:
    """Return the one prompt file named ``template`` across the prompt dirs."""
    matches = [d / template for d in PROMPT_DIRS if (d / template).is_file()]
    if len(matches) != 1:
        raise LookupError(f"{template}: found in {len(matches)} prompt directories")
    return matches[0]


def phrase_checks() -> list[PhraseCheck]:
    checks = []
    for path in table_paths():
        table = load_table(path)
        for case, kinds in table["cases"].items():
            for kind, phrases in kinds.items():
                checks.append(
                    PhraseCheck(
                        table=path.stem,
                        template=table["template"],
                        case=case,
                        kind=kind,
                        phrases=tuple(
                            tuple(p) if isinstance(p, list) else p for p in phrases
                        ),
                    )
                )
    return checks


@cache
def render(template: str, case: str) -> str:
    return normalize(CASES[case](template))


def _ordered_failure(phrase: tuple[str, ...], rendered: str) -> str | None:
    markers = [normalize(marker) for marker in phrase]
    missing = [marker for marker in markers if marker not in rendered]
    if missing:
        return f"missing {missing[0]!r} (ordered {markers!r})"
    positions = [rendered.index(marker) for marker in markers]
    return None if positions == sorted(positions) else f"out of order {markers!r}"


def _count_failure(kind: str, phrase: str, rendered: str) -> str | None:
    text = normalize(phrase)
    count = rendered.count(text)
    if kind == "required" and count == 0:
        return f"missing {text!r}"
    if kind == "once" and count != 1:
        return f"expected once, found {count} times: {text!r}"
    if kind == "forbidden" and count:
        return f"forbidden {text!r}"
    return None


def failures(check: PhraseCheck, rendered: str) -> list[str]:
    """Return one message per phrase of ``check`` that ``rendered`` breaks."""
    if check.kind == "ordered":
        found = [_ordered_failure(phrase, rendered) for phrase in check.phrases]
    else:
        found = [_count_failure(check.kind, p, rendered) for p in check.phrases]
    return [f"{check.id}: {message}" for message in found if message]
