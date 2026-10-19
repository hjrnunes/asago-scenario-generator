"""The scenario-handoff-v5 fields beyond the shared envelope, from the spec.

Each field traces to a published vocabulary: the unsafe control action in the
STPA Handbook's form (Leveson and Thomas 2018, Table 2.3), the misuse case's
misuser and worst case threat (Sindre and Opdahl 2005), and the attack as an
ATLAS case-study procedure with tactic and technique IDs. Code derives every
value from data the producer already holds; no request depends on it. A
required source that is missing or blank fails the build instead of
publishing an empty value.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from asago_scenario_generator.stpa.models.attack_shape import (
    AttackShape,
    IndirectShape,
    default_attack_shape,
)
from asago_scenario_generator.stpa.models.causal_factor import CausalFactor
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)
from asago_scenario_generator.stpa.models.scenario_envelope import ScenarioEnvelope
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec

from .deduplication import ScenarioDeduplication
from .handoff import (
    HandoffActor,
    HandoffAtlasRef,
    HandoffCausalFactor,
    HandoffHazard,
    HandoffProcedureStep,
    HandoffProcessModelVariable,
    HandoffUca,
    ScenarioHandoffV5,
    Stage1aSource,
    finalize_handoff,
    scenario_handoff_fields,
)
from .attack_path import reduce_to_attack_path
from .narration import ATLAS_TACTICS, attack_steps, plain
from .presentation import ADVERSARY_WORDS, CONTROLLER_WORDS, item_kind

#: ``ica_slot_id`` suffix to the STPA Handbook's UCA type (Table 2.3 column).
UCA_TYPES = {
    "NOT_PROVIDED": "not-providing-causes-hazard",
    "INCORRECT": "providing-causes-hazard",
    "WRONG_TIMING": "too-early-too-late-or-out-of-order",
    "WRONG_DURATION": "stopped-too-soon-or-applied-too-long",
}


def build_scenario_handoff_v5(
    envelope: ScenarioEnvelope,
    *,
    loss_analysis: LossAnalysis | None = None,
    environment_bound: bool = False,
    enriched_operations: Mapping[str, str] | None = None,
    observed_operations: tuple[str, ...] | None = None,
    stage_1a_source: Stage1aSource | None = None,
    deduplication: ScenarioDeduplication | None = None,
) -> ScenarioHandoffV5:
    """Build the v5 handoff from one published scenario envelope.

    The narrative and Gherkin come from the envelope unchanged; the caller
    decides what the envelope's narrative holds. ``attack_path`` is the
    envelope's and-or tree reduced to this scenario's own path.

    The builder is deterministic and consumes only the producer's own
    scenario meaning. It never copies artifact-design content: the spec's
    ``unsafe_outcome_condition`` is deliberately not read.
    ``enriched_operations`` is the verified view of the run's
    ``control-action-enrichment.yaml`` sidecar (control-action id to
    documented operation identity); only those verified rows contribute an
    operation identity. ``observed_operations`` is the exact inventory from
    the run's observed target profile. A criterion token is binding only on an
    exact token match against that inventory; generic capability labels never
    contribute. ``stage_1a_source`` is the run's Stage 1a acceptance record;
    the published constraint authorities derive from it and from the actual
    loss-analysis constraint records instead of asserting reviewed status.
    """
    fields = scenario_handoff_fields(
        envelope,
        loss_analysis=loss_analysis,
        environment_bound=environment_bound,
        enriched_operations=enriched_operations,
        observed_operations=observed_operations,
        stage_1a_source=stage_1a_source,
        deduplication=deduplication,
    )
    fields["attack_path"] = reduce_to_attack_path(envelope.attack_tree)
    handoff = finalize_handoff(
        ScenarioHandoffV5(**fields, **v5_fields(envelope.scenario_spec))
    )
    assert isinstance(handoff, ScenarioHandoffV5)
    return handoff


def v5_fields(spec: ScenarioSpec) -> dict[str, Any]:
    """Return the six fields beyond the shared envelope, from one scenario spec."""
    context = _context(spec)
    if spec.is_functional_test:
        actor = None
        preconditions: list[str] = []
        procedure: list[HandoffProcedureStep] = []
    else:
        shape = spec.attack_shape or default_attack_shape(None)
        actor = _actor(spec)
        preconditions = shape_preconditions(shape, spec.attacker_bdi.beliefs)
        procedure = procedure_steps(shape, spec.scenario_id)
    return {
        "uca": _uca(spec, context),
        "actor": actor,
        "causal_factors": _causal_factors(spec),
        "preconditions": preconditions,
        "procedure": procedure,
        "worst_case_threat": _worst_case_threat(spec, context),
    }


def _context(spec: ScenarioSpec) -> ScenarioGenerationContext:
    if spec.scenario_context is None:
        raise ValueError(f"{spec.scenario_id}: a v5 handoff needs the scenario context")
    return spec.scenario_context


def _required(spec: ScenarioSpec, field: str, text: str) -> str:
    value = plain(text)
    if not value:
        raise ValueError(f"{spec.scenario_id}: the v5 field {field} has no source text")
    return value


def uca_type(ica_slot_id: str) -> str:
    """Map the ``ica_slot_id`` suffix to its UCA type; reject an unknown one."""
    suffix = ica_slot_id.rsplit(":", 1)[-1]
    if suffix not in UCA_TYPES:
        raise ValueError(f"unknown UCA type {suffix!r} in ica_slot_id {ica_slot_id!r}")
    return UCA_TYPES[suffix]


def _uca(spec: ScenarioSpec, context: ScenarioGenerationContext) -> HandoffUca:
    if not spec.target_controller:
        raise ValueError(f"{spec.scenario_id}: the v5 field uca.source has no source")
    return HandoffUca(
        source=spec.target_controller,
        type=uca_type(spec.threat_source.ica_slot_id),
        control_action=_required(
            spec,
            "uca.control_action",
            context.target_control_path.control_action.description,
        ),
        context=_required(spec, "uca.context", context.ica.hazardous_context),
        statement=_required(spec, "uca.statement", context.ica.exact_ica_text),
        hazards=[
            HandoffHazard(
                hazard_id=item.hazard_id,
                description=_required(spec, "uca.hazards", item.description),
            )
            for item in context.hazards
        ],
    )


def _actor(spec: ScenarioSpec) -> HandoffActor:
    adversary = spec.adversary
    if adversary is None:
        raise ValueError(
            f"{spec.scenario_id}: an adversarial v5 handoff needs an adversary"
        )
    profile = ADVERSARY_WORDS.get(adversary.kind.value)
    if profile is None:
        raise ValueError(
            f"{spec.scenario_id}: no misuser profile for adversary kind "
            f"{adversary.kind.value!r}"
        )
    return HandoffActor(
        profile=profile, goal=_required(spec, "actor.goal", adversary.gain)
    )


def shape_preconditions(shape: AttackShape, beliefs: Sequence[str]) -> list[str]:
    """Return what holds before the attack: the planted item, then the beliefs.

    An indirect shape states its planted item first and the benign user's
    actor when it names one; each attacker belief follows in plain words.
    Blank and repeated items are left out.
    """
    items: list[str] = []
    indirect = shape.indirect
    if indirect is not None:
        items.append(planted_item_statement(indirect))
        actor_ref = indirect.party_relation.benign_user_actor_ref
        if actor_ref:
            items.append(f"The benign user acts as {actor_ref}.")
    items.extend(plain(item) for item in beliefs)
    return list(dict.fromkeys(item for item in items if item))


def planted_item_statement(indirect: IndirectShape) -> str:
    """State the planted item the way the plant step names it, as a precondition."""
    item = indirect.data_item
    record = f" (record {item.record_ref})" if item.record_ref else ""
    controller = CONTROLLER_WORDS[indirect.party_relation.controller.value]
    text = (
        f"{controller} has planted {item_kind(item.content_kind.value)}{record} "
        f"in what {indirect.carrier_operation} returns."
    )
    return text[:1].upper() + text[1:]


def procedure_steps(shape: AttackShape, scenario_id: str) -> list[HandoffProcedureStep]:
    """Render the attack steps as an ATLAS procedure: S00, S01, ... in order."""
    steps = attack_steps(shape)
    ids = [f"S{index:02d}" for index in range(len(steps))]
    procedure = []
    for index, step in enumerate(steps):
        tactic = technique = None
        if step.technique is not None:
            technique_id, technique_name = step.technique
            if technique_id not in ATLAS_TACTICS:
                raise ValueError(
                    f"{scenario_id}: no ATLAS tactic for technique {technique_id}"
                )
            tactic_id, tactic_name = ATLAS_TACTICS[technique_id]
            tactic = HandoffAtlasRef(id=tactic_id, name=tactic_name)
            technique = HandoffAtlasRef(id=technique_id, name=technique_name)
        procedure.append(
            HandoffProcedureStep(
                step_id=ids[index],
                leads_to=ids[index + 1 : index + 2],
                tactic=tactic,
                technique=technique,
                description=step.text,
                channel=step.channel,
            )
        )
    return procedure


def _causal_factors(spec: ScenarioSpec) -> list[HandoffCausalFactor]:
    if not spec.causal_factors:
        raise ValueError(f"{spec.scenario_id}: a v5 handoff needs causal factors")
    beliefs = {belief.pm_id: belief for belief in spec.defender_bdi.beliefs}
    factors = []
    for factor in spec.causal_factors:
        if factor.flawed_belief:
            factors.append(_stated_causal_factor(spec, factor))
            continue
        belief = beliefs.get(factor.source_id)
        content = plain(belief.content) if belief is not None else ""
        factors.append(
            HandoffCausalFactor(
                source_id=factor.source_id,
                process_model_belief=content or None,
                flaw=_required(spec, "causal_factors.flaw", factor.description),
            )
        )
    return factors


def _stated_causal_factor(
    spec: ScenarioSpec, factor: CausalFactor
) -> HandoffCausalFactor:
    """Publish a factor's stated flawed belief and the variable that holds it."""
    variable = factor.process_model_variable
    return HandoffCausalFactor(
        source_id=factor.source_id,
        process_model_belief=_required(
            spec, "causal_factors.process_model_belief", factor.flawed_belief
        ),
        flaw=_required(spec, "causal_factors.flaw", factor.description),
        process_model_variable=(
            HandoffProcessModelVariable(
                id=variable.pm_id,
                description=_required(
                    spec,
                    "causal_factors.process_model_variable.description",
                    variable.description,
                ),
            )
            if variable is not None
            else None
        ),
    )


def _worst_case_threat(spec: ScenarioSpec, context: ScenarioGenerationContext) -> str:
    losses = [
        _required(spec, "worst_case_threat", item.description)
        for item in context.losses
    ]
    if not losses:
        raise ValueError(f"{spec.scenario_id}: the v5 worst_case_threat needs a loss")
    return " ".join(
        text if text.endswith((".", "!", "?")) else text + "." for text in losses
    )


__all__ = [
    "UCA_TYPES",
    "build_scenario_handoff_v5",
    "planted_item_statement",
    "procedure_steps",
    "shape_preconditions",
    "uca_type",
    "v5_fields",
]
