"""The ``policy-coverage-v1`` document: which policy risks reached scenarios.

The producer owns the rule that maps a policy risk to its scenarios and
publishes the result once, so the run reports (this producer's, the
consumer's, and orch's) do not each re-derive it. A loss lists the risks it
came from (``source_risk_cards``) and a scenario cites losses, so a risk
reaches scenarios only through its harms.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from asago_scenario_generator.data.sssom import SSSOMMapping
from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.models.loss_analysis import (
    Loss,
    LossAnalysis,
    RiskDisposition,
)
from asago_scenario_generator.stpa.system_model.risk_actionability import (
    RiskActionabilityEntry,
    RiskActionabilityRecord,
)

SCHEMA_VERSION = "policy-coverage-v1"
FILENAME = "policy-coverage.json"
RULE = "loss-source-risk-cards"
TAG_SCHEMES = ("nist-ai-rmf", "owasp-llm-2.0")
# Best first: a merged risk takes the coverage of its best entry.
COVERAGE_ORDER = ("scenarios", "not_reached", "not_applicable", "outside_boundary")

_CITATION = re.compile(r"\s*\([^()]*\d{4}[^()]*\)\s*$")
_CLAUSE_BREAK = re.compile(r" due to |, such as | via | through ")
_WORDS = {"ai": "AI", "cbrn": "CBRN"}
_OWASP_ID = re.compile(r"llm(\d\d)(?:2025)?-(.*)")
_LOSS_NUMBER = re.compile(r"(\d+)$")


def display_name(name: str) -> str:
    """Drop a trailing literature citation such as ``(Slattery et al., 2024)``."""
    return _CITATION.sub("", name).strip()


def harm_title(description: str) -> str:
    """Return the description's first clause, the version 1 stand-in for a title."""
    return _CLAUSE_BREAK.split(description, maxsplit=1)[0].strip().rstrip(".")


def _words(text: str) -> str:
    parts = text.replace("-", " ").split()
    return " ".join(_WORDS.get(part, part) for part in parts).capitalize()


def tag_label(scheme: str, tag_id: str) -> str:
    """Return the reader's label for a NIST or OWASP mapping target."""
    if scheme == "nist-ai-rmf":
        return "NIST " + _words(tag_id.removeprefix("nist-"))
    match = _OWASP_ID.match(tag_id)
    if match:
        return f"OWASP LLM{match[1]} {_words(match[2])}"
    return tag_id


def _normalized(name: str) -> str:
    return " ".join(display_name(name).lower().split())


@dataclass
class _Risk:
    risk_id: str
    name: str
    description: str
    merged_ids: list[str]
    sources: list[str]
    tags: list[dict[str, str]]
    mitigations: list[dict[str, Any]]
    loss_ids: set[str]
    coverage: str
    reason: dict[str, str] | None
    extra: dict[str, Any] = field(default_factory=dict)


def _tags(sssom: Sequence[SSSOMMapping]) -> dict[str, list[dict[str, str]]]:
    found: dict[str, list[dict[str, str]]] = {}
    for mapping in sssom:
        if mapping.object_source not in TAG_SCHEMES:
            continue
        tag = {
            "scheme": mapping.object_source,
            "id": mapping.object_id,
            "label": tag_label(mapping.object_source, mapping.object_id),
        }
        known = found.setdefault(mapping.subject_id, [])
        if tag not in known:
            known.append(tag)
    return {
        rid: sorted(tags, key=lambda t: (t["scheme"], t["id"]))
        for rid, tags in found.items()
    }


def _reason(code: str, text: str, step: str) -> dict[str, str]:
    return {"code": code, "text": text, "step": step}


def _loss_cited_coverage(
    losses: Sequence[str], written: Mapping[str, Sequence[str]]
) -> tuple[str, dict[str, str] | None]:
    if any(written.get(loss_id) for loss_id in losses):
        return "scenarios", None
    return "not_reached", _reason(
        "scenario_writing:no_scenario",
        "A loss cites this risk, but no scenario was written for that loss.",
        "scenario_writing",
    )


def _uncited_coverage(
    disposition: RiskDisposition | None, decision: RiskActionabilityEntry | None
) -> tuple[str, dict[str, str]]:
    if disposition is not None and disposition.disposition == "not_applicable":
        return "not_applicable", _reason(
            "loss_analysis:not_applicable", disposition.reason or "", "loss_analysis"
        )
    if decision is not None and decision.decision.value in (
        "outside_boundary",
        "not_applicable",
    ):
        return decision.decision.value, _reason(
            f"boundary_decision:{decision.decision.value}",
            decision.reason,
            "boundary_decision",
        )
    return "not_reached", _reason(
        "loss_analysis:no_loss",
        "The boundary decision kept this risk, but loss analysis cited it in no loss.",
        "loss_analysis",
    )


def _entry_coverage(
    risk_id: str,
    cited: Mapping[str, list[str]],
    dispositions: Mapping[str, RiskDisposition],
    decisions: Mapping[str, RiskActionabilityEntry],
    written: Mapping[str, Sequence[str]],
) -> tuple[str, dict[str, str] | None]:
    if risk_id in cited:
        return _loss_cited_coverage(cited[risk_id], written)
    return _uncited_coverage(dispositions.get(risk_id), decisions.get(risk_id))


def _mitigations(card: RiskCard) -> list[dict[str, Any]]:
    return [
        {"id": item.mitigation_id, "source": item.source, "text": item.description}
        for item in card.mitigations
    ]


def _merge_into(base: _Risk, other: _Risk) -> None:
    base.merged_ids.extend(other.merged_ids)
    base.sources.extend(s for s in other.sources if s not in base.sources)
    base.tags.extend(t for t in other.tags if t not in base.tags)
    base.mitigations.extend(m for m in other.mitigations if m not in base.mitigations)
    base.loss_ids |= other.loss_ids
    if COVERAGE_ORDER.index(other.coverage) < COVERAGE_ORDER.index(base.coverage):
        base.coverage, base.reason = other.coverage, other.reason


def _risks(
    cards: Sequence[RiskCard],
    tags: Mapping[str, list[dict[str, str]]],
    cited: Mapping[str, list[str]],
    dispositions: Mapping[str, RiskDisposition],
    decisions: Mapping[str, RiskActionabilityEntry],
    written: Mapping[str, Sequence[str]],
) -> list[_Risk]:
    merged: dict[str, _Risk] = {}
    for card in cards:
        coverage, reason = _entry_coverage(
            card.risk_id, cited, dispositions, decisions, written
        )
        risk = _Risk(
            risk_id=card.risk_id,
            name=card.risk_name,
            description=card.risk_description,
            merged_ids=[card.risk_id],
            sources=[card.taxonomy],
            tags=list(tags.get(card.risk_id, [])),
            mitigations=_mitigations(card),
            loss_ids=set(cited.get(card.risk_id, [])),
            coverage=coverage,
            reason=reason,
        )
        key = _normalized(card.risk_name)
        if key in merged:
            _merge_into(merged[key], risk)
        else:
            merged[key] = risk
    return list(merged.values())


def _cited_losses(losses: Sequence[Loss]) -> dict[str, list[str]]:
    cited: dict[str, list[str]] = {}
    for loss in losses:
        for risk_id in loss.source_risk_cards:
            cited.setdefault(risk_id, []).append(loss.loss_id)
    return cited


def _loss_order(loss: Loss) -> tuple[int, str]:
    match = _LOSS_NUMBER.search(loss.loss_id)
    return (int(match[1]) if match else 0, loss.loss_id)


def _risk_json(risk: _Risk) -> dict[str, Any]:
    return {
        "risk_id": risk.risk_id,
        "merged_ids": risk.merged_ids,
        "sources": risk.sources,
        "name": risk.name,
        "display_name": display_name(risk.name),
        "description": risk.description,
        "tags": risk.tags,
        "coverage": risk.coverage,
        "reason": risk.reason,
        "loss_ids": sorted(risk.loss_ids, key=lambda x: (len(x), x)),
        "mitigations": risk.mitigations,
    }


def _harm_json(
    loss: Loss, alias: Mapping[str, str], written: Mapping[str, Sequence[str]]
) -> dict[str, Any]:
    risk_ids = list(
        dict.fromkeys(alias[rid] for rid in loss.source_risk_cards if rid in alias)
    )
    return {
        "loss_id": loss.loss_id,
        "title": harm_title(loss.description),
        "text": loss.description,
        "provenance": loss.provenance.value,
        "risk_ids": risk_ids,
        "scenario_ids": sorted(written.get(loss.loss_id, ())),
    }


def build_policy_coverage(
    *,
    cards: Sequence[RiskCard],
    sssom: Sequence[SSSOMMapping],
    actionability: RiskActionabilityRecord | None,
    loss_analysis: LossAnalysis,
    scenario_ids_by_loss: Mapping[str, Sequence[str]],
    source: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Return the ``policy-coverage-v1`` document for one generate run.

    ``coverage`` follows this order: a loss that cites the risk decides
    (``scenarios`` when a written scenario carries the loss, else
    ``not_reached``); otherwise a loss-analysis ``not_applicable`` disposition;
    otherwise the boundary decision. Risks that several taxonomies list under
    one normalized name merge into one entry that keeps every id and source.
    """
    losses = sorted(
        [*loss_analysis.risk_card_losses, *loss_analysis.use_case_losses],
        key=_loss_order,
    )
    cited = _cited_losses(losses)
    risks = _risks(
        cards,
        _tags(sssom),
        cited,
        {item.risk_ref: item for item in loss_analysis.risk_dispositions},
        {
            item.risk_id: item
            for item in (actionability.entries if actionability else ())
        },
        scenario_ids_by_loss,
    )
    alias = {rid: risk.risk_id for risk in risks for rid in risk.merged_ids}
    given = source or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "policy": {
            "risk_extraction": given.get("risk_extraction"),
            "digest": given.get("digest"),
            "documents": list(given.get("documents", ())),
            "entry_count": len(cards),
            "risk_count": len(risks),
        },
        "rule": RULE,
        "harms": [_harm_json(loss, alias, scenario_ids_by_loss) for loss in losses],
        "risks": [_risk_json(risk) for risk in risks],
    }
