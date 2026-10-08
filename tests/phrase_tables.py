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
``build_context_bdi_prompts`` for the Stage 5 context templates. Phrases and
rendered text are compared with runs of whitespace collapsed to one space, so
template line wrapping does not matter.

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
from asago_scenario_generator.stpa.system_model import (
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

PHRASES_DIR = Path(__file__).with_name("phrases")
KINDS = ("required", "once", "forbidden", "ordered")
PROMPT_DIRS = (SYSTEM_MODEL_PROMPTS_DIR, STAGE5_PROMPTS_DIR)

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
