"""Attack Flow files: one STIX 2.1 attack tree per hazard.

``report/attack-flow/<hazard-id>.json`` holds the same tree as the hazard
view, as a bundle in the attack-tree scope of Attack Flow 2.0.0, in the shape
its renderers (``af graphviz`` and ``af mermaid``) read. Edges point from a
child to its parent, and an ``attack-operator`` has exactly one effect: the
``attack-action`` the renderers label AND or OR.

The hazard is the root action. An OR operator points at it, and each
scenario's action points at the OR. An AND operator points at each scenario's
action, and the scenario's ordered chain of steps, which ends in the unsafe
control action, points at that AND. Each condition node becomes a condition
whose ``on_true_refs`` names the scenario's action: the renderers fold an
operator into the action it points at and redirect only ``effect_refs``, so a
condition that named the operator would render detached from the tree.

The file is plain JSON. The producer depends on no STIX or Attack Flow
package, so these dictionaries follow the published schema by hand.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from pathlib import Path
from typing import Any

from asago_scenario_generator.report.common import kind_word
from asago_scenario_generator.report.hazard_view import (
    ATTACK_FLOW_DIR,
    HazardGroup,
    disposition,
    flow_file_name,
    hazard_groups,
    scenario_subtree,
    uca_parts,
)
from asago_scenario_generator.report.run_data import RunData

logger = logging.getLogger(__name__)

EXTENSION_ID = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4"
# The Attack Flow 2.0.0 extension definition and the identity that created
# it, copied verbatim from stix/attack-flow-example.json of
# center-for-threat-informed-defense/attack-flow (Apache License 2.0). The
# validator requires the definition in every bundle, and the identity makes
# its created_by_ref resolve.
EXTENSION_DEFINITION: dict[str, Any] = {
    "type": "extension-definition",
    "id": EXTENSION_ID,
    "spec_version": "2.1",
    "name": "Attack Flow",
    "description": "Extends STIX 2.1 with features to create Attack Flows.",
    "created": "2022-08-02T19:34:35.143Z",
    "modified": "2022-08-02T19:34:35.143Z",
    "created_by_ref": "identity--d673f8cb-c168-42da-8ed4-0cb26725f86c",
    "schema": (
        "https://center-for-threat-informed-defense.github.io/attack-flow/stix/"
        "attack-flow-schema-2.0.0.json"
    ),
    "version": "2.0.0",
    "extension_types": ["new-sdo"],
    "external_references": [
        {
            "source_name": "Documentation",
            "description": "Documentation for Attack Flow",
            "url": "https://center-for-threat-informed-defense.github.io/attack-flow",
        },
        {
            "source_name": "GitHub",
            "description": "Source code repository for Attack Flow",
            "url": "https://github.com/center-for-threat-informed-defense/attack-flow",
        },
    ],
}
EXTENSION_CREATOR: dict[str, Any] = {
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--d673f8cb-c168-42da-8ed4-0cb26725f86c",
    "created_by_ref": "identity--d673f8cb-c168-42da-8ed4-0cb26725f86c",
    "created": "2022-08-02T19:34:35.143Z",
    "modified": "2022-08-02T19:34:35.143Z",
    "name": "MITRE Center for Threat-Informed Defense",
    "identity_class": "organization",
}
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "urn:asago-scenario-generator:attack-flow")
PRODUCER_ID = f"identity--{uuid.uuid5(NAMESPACE, 'producer')}"
PRODUCER_NAME = "asago-scenario-generator"
# No timestamp in a generate output survives a strict replay: the manifest's
# created_at is wall-clock time. A fixed instant keeps two renders of the same
# run byte-identical; the bundle ids, not the timestamps, tell runs apart.
TIMESTAMP = "2026-01-01T00:00:00.000Z"
CONDITION_WORDS = {
    "situation": "Situation",
    "attacker_assumption": "Attacker assumption",
    "weak_point": "Weak point",
}


class _Ids:
    """Deterministic STIX ids: uuid5 of the run's scenario digests and a key."""

    def __init__(self, run: RunData, group: HazardGroup) -> None:
        digests = "\n".join(
            f"{s}:{run.scenarios[s].content_digest}" for s in group.scenario_ids
        )
        self._prefix = (
            hashlib.sha256(digests.encode("utf-8")).hexdigest(),
            group.hazard_id,
        )

    def __call__(self, kind: str, *key: str) -> str:
        name = "|".join((*self._prefix, *key))
        return f"{kind}--{uuid.uuid5(NAMESPACE, name)}"


def _sdo(kind: str, object_id: str, **fields: Any) -> dict[str, Any]:
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": object_id,
        "created": TIMESTAMP,
        "modified": TIMESTAMP,
        "created_by_ref": PRODUCER_ID,
        "extensions": {EXTENSION_ID: {"extension_type": "new-sdo"}},
        **fields,
    }


def _producer() -> dict[str, Any]:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": PRODUCER_ID,
        "created_by_ref": PRODUCER_ID,
        "created": TIMESTAMP,
        "modified": TIMESTAMP,
        "name": PRODUCER_NAME,
        "identity_class": "system",
    }


def _sentence(text: str) -> str:
    text = " ".join(str(text).split())
    return text if not text or text.endswith((".", "!", "?")) else text + "."


def _hazard_text(group: HazardGroup) -> str:
    losses = "; ".join(
        f"{loss_id}: {' '.join((text or '').split())}".rstrip(": ").rstrip(".")
        for loss_id, text in group.losses
    )
    hazard = _sentence(f"Hazard {group.hazard_id}: {group.description or ''}")
    return hazard + (f" Losses: {losses}." if losses else "")


def _children(node: dict, category: str) -> list[dict]:
    for child in node.get("children") or []:
        if isinstance(child, dict) and child.get("category") == category:
            return [c for c in child.get("children") or [] if isinstance(c, dict)]
    return []


def _child(node: dict, category: str) -> dict | None:
    for child in node.get("children") or []:
        if isinstance(child, dict) and child.get("category") == category:
            return child
    return None


def _condition_text(node: dict) -> str:
    word = CONDITION_WORDS.get(
        str(node.get("category")), str(node.get("category", "")).replace("_", " ")
    )
    ids = dict.fromkeys(
        i for i in [node.get("source_id"), *(node.get("source_ids") or [])] if i
    )
    source = "".join(f" {i}" for i in ids)
    text = _sentence(f"{word}{source}: {node.get('label', '')}")
    if node.get("belief"):
        text += f" Belief: {_sentence(node['belief'])}"
    return text


def _tactics(run: RunData, scenario_id: str, steps: list[dict]) -> list[str | None]:
    """Pair each tree step with the ATLAS tactic its handoff procedure names."""
    procedure = list(getattr(run.scenarios[scenario_id], "procedure", None) or [])
    if len(procedure) != len(steps):
        return [None] * len(steps)
    tactics: list[str | None] = []
    for step, item in zip(steps, procedure, strict=True):
        same = item.technique is not None and item.technique.id == step.get(
            "technique_id"
        )
        tactics.append(item.tactic.id if same and item.tactic is not None else None)
    return tactics


def _step(
    ids: _Ids, scenario_id: str, index: int, node: dict, tactic: str | None
) -> dict[str, Any]:
    technique = node.get("technique")
    name = f"{scenario_id} step {index}" + (f": {technique}" if technique else "")
    description = _sentence(node.get("label", ""))
    if node.get("asset"):
        description += f" Asset: {node['asset']}."
    extras: dict[str, Any] = {}
    if node.get("technique_id"):
        extras["technique_id"] = node["technique_id"]
    if tactic:
        extras["tactic_id"] = tactic
    return _sdo(
        "attack-action",
        ids("attack-action", scenario_id, str(node.get("node_id"))),
        name=name,
        description=description,
        **extras,
    )


def _unsafe_action(
    ids: _Ids, run: RunData, scenario_id: str, node: dict | None
) -> dict[str, Any]:
    source, _, action = uca_parts(run, scenario_id)
    label = (node or {}).get("label") or action
    violates = "; ".join(
        f"{item.get('source_id')}: {' '.join(str(item.get('label', '')).split())}"
        for item in (node or {}).get("violates") or []
        if isinstance(item, dict)
    )
    description = _sentence(label) + (
        f" Violates {violates.rstrip('.')}." if violates else ""
    )
    return _sdo(
        "attack-action",
        ids("attack-action", scenario_id, str((node or {}).get("node_id", "AT-UCA"))),
        name=f"{scenario_id} unsafe control action: {source} {action}",
        description=description,
    )


def _scenario_text(run: RunData, scenario_id: str, criterion: str) -> str:
    scenario = run.scenarios[scenario_id]
    source, kind, action = uca_parts(run, scenario_id)
    return " ".join(
        [
            f"Kind: {kind_word(scenario.kind)} ({scenario.kind}).",
            f"Deduplication: {disposition(run, scenario_id).label}.",
            f"Unsafe control action: {source} {kind}: {_sentence(action)}",
            f"Failure: {_sentence(criterion)}",
        ]
    )


def _scenario_objects(
    ids: _Ids, run: RunData, scenario_id: str, choice_id: str
) -> list[dict[str, Any]]:
    """Return a scenario's action, its AND, its conditions, and its step chain."""
    scenario = run.scenarios[scenario_id]
    node = scenario_subtree(scenario)
    criterion = str(node.get("label") or scenario.semantic_failure_criterion)
    and_id = ids("attack-operator", scenario_id, "AND")
    action = _sdo(
        "attack-action",
        ids("attack-action", scenario_id, str(node.get("node_id"))),
        name=f"{scenario_id}: {scenario.gherkin.scenario}",
        description=_scenario_text(run, scenario_id, criterion),
        effect_refs=[choice_id],
    )
    operator = _sdo(
        "attack-operator", and_id, operator="AND", effect_refs=[action["id"]]
    )
    conditions = [
        _sdo(
            "attack-condition",
            ids("attack-condition", scenario_id, str(item.get("node_id"))),
            description=_condition_text(item),
            on_true_refs=[action["id"]],
        )
        for item in _children(node, "conditions")
    ]
    steps = _children(node, "attack_steps") if scenario.kind == "adversarial" else []
    chain = [
        _step(ids, scenario_id, index, item, tactic)
        for index, (item, tactic) in enumerate(
            zip(steps, _tactics(run, scenario_id, steps), strict=True), 1
        )
    ]
    chain.append(_unsafe_action(ids, run, scenario_id, _child(node, "unsafe_action")))
    for current, following in zip(chain, chain[1:]):
        current["effect_refs"] = [following["id"]]
    chain[-1]["effect_refs"] = [and_id]
    return [action, operator, *conditions, *chain]


def _leaves(objects: list[dict[str, Any]]) -> list[str]:
    targets = {
        ref
        for item in objects
        for key in ("effect_refs", "on_true_refs", "on_false_refs")
        for ref in item.get(key) or []
    }
    return [
        item["id"]
        for item in objects
        if item["type"] in ("attack-action", "attack-condition")
        and item["id"] not in targets
    ]


def attack_flow_bundle(run: RunData, group: HazardGroup) -> dict[str, Any]:
    """Build the Attack Flow bundle of one hazard and the scenarios that reach it."""
    if not group.scenario_ids:
        raise ValueError(f"{group.hazard_id} has no published scenario")
    ids = _Ids(run, group)
    root = _sdo(
        "attack-action",
        ids("attack-action", "hazard"),
        name=f"{group.hazard_id}: {' '.join((group.description or '').split())}",
        description=_hazard_text(group),
    )
    choice = _sdo("attack-operator", ids("attack-operator", "OR"), operator="OR")
    choice["effect_refs"] = [root["id"]]
    tree = [root, choice]
    for scenario_id in group.scenario_ids:
        tree.extend(_scenario_objects(ids, run, scenario_id, choice["id"]))
    count = len(group.scenario_ids)
    flow = _sdo(
        "attack-flow",
        ids("attack-flow", "flow"),
        name=f"{group.hazard_id}: scenarios that reach the hazard",
        description=(
            f"{_hazard_text(group)} Any one of {count} published "
            f"scenario{'s' if count != 1 else ''} reaches the hazard; each is an "
            "ordered AND of its conditions and steps."
        ),
        scope="attack-tree",
        start_refs=_leaves(tree),
    )
    return {
        "type": "bundle",
        "id": ids("bundle", "bundle"),
        "objects": [EXTENSION_DEFINITION, EXTENSION_CREATOR, _producer(), flow, *tree],
    }


def write_attack_flows(run: RunData, report_dir: Path) -> dict[str, str]:
    """Write one Attack Flow file per hazard that has a published scenario.

    Returns the reason each hazard whose file could not be built failed; the
    other hazards' files are still written.
    """
    folder = report_dir / ATTACK_FLOW_DIR
    folder.mkdir(parents=True, exist_ok=True)
    failed: dict[str, str] = {}
    for group in hazard_groups(run):
        if not group.scenario_ids:
            continue
        try:
            bundle = attack_flow_bundle(run, group)
        except Exception as error:  # noqa: BLE001 - one hazard must not stop the rest
            failed[group.hazard_id] = " ".join(str(error).split())[:300]
            logger.warning("attack flow for %s failed: %s", group.hazard_id, error)
            continue
        text = json.dumps(bundle, indent=2, sort_keys=True, ensure_ascii=False)
        (folder / flow_file_name(group.hazard_id)).write_text(
            text + "\n", encoding="utf-8"
        )
    return failed
