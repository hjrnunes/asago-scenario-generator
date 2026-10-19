"""Process-model gaps: the beliefs no controller's process model holds.

A published v5 handoff may link each causal factor's flawed belief to a
process-model variable: ``causal_factors[].process_model_variable`` is
``{id, description}``, where ``id`` names the variable (``PM-3-2``) or is
``null`` for a gap, and then ``description`` is the variable the controller
would need. This module lists the gaps per controller in
``report/process-model-gaps.yaml`` and in the report.

The controller is the UCA's source. For a coordination link (``CL-n``),
Stage 5 offered the process-model variables of both endpoint
responsibilities, so the data cannot say which endpoint lacks the missing
variable; a link entry names both endpoints and the owner of the link's
shared variable instead.

It reads the handoff YAML as plain data, so the list does not depend on the
handoff model knowing the field. When no handoff carries the field it returns
nothing, and the report and its files are unchanged.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.report.common import code_id, natural_key, plural
from asago_scenario_generator.report.run_data import RunData
from asago_scenario_generator.report_kit import (
    Column,
    Markup,
    Row,
    esc,
    section,
    table,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    CoordinationLink,
    coordination_process_model_owner,
)

GAPS_FILE = "process-model-gaps.yaml"
GAPS_FORMAT = "process-model-gaps-v1"
FIELD = "process_model_variable"
QUESTION = (
    "Which flawed beliefs concern a variable no controller's process model holds? "
    "Each row is a causal factor whose belief the model linked to a missing variable."
)


def handoff_documents(output_dir: Path) -> dict[str, dict[str, Any]]:
    """Read every published handoff under *output_dir* as plain data."""
    folder = Path(output_dir) / "scenarios"
    paths = sorted(folder.glob("SCN-*.yaml")) if folder.is_dir() else []
    documents = {}
    for path in paths:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(document, dict):
            documents[path.stem] = document
    return documents


def _factors(document: dict[str, Any]) -> list[dict[str, Any]]:
    return [f for f in document.get("causal_factors") or [] if isinstance(f, dict)]


def _controller(document: dict[str, Any]) -> str:
    uca = document.get("uca")
    if isinstance(uca, dict) and uca.get("source"):
        return str(uca["source"])
    lineage = document.get("lineage") or {}
    return str(lineage.get("controller_id") or "unknown")


def _link_details(
    structure: ControlStructure, link: CoordinationLink
) -> dict[str, Any]:
    """Return a link's endpoints (source, then target) and its shared variable."""
    responsibilities = {
        item.resp_id: item.description for item in structure.responsibilities
    }
    try:
        owner: str | None = coordination_process_model_owner(structure, link).resp_id
    except ValueError:
        owner = None
    return {
        "endpoints": [
            {"id": endpoint, "description": responsibilities.get(endpoint)}
            for endpoint in (link.source, link.target)
        ],
        "shared_variable": {"id": link.shared_pm, "owner": owner},
    }


def _controller_entry(
    controller: str, structure: ControlStructure | None
) -> dict[str, Any]:
    """Return a controller's kind and description, with a link's details."""
    if structure is not None:
        for item in structure.responsibilities:
            if item.resp_id == controller:
                return {"kind": "responsibility", "description": item.description}
        for link in structure.coordination_links:
            if link.link_id == controller:
                return {
                    "kind": "coordination_link",
                    "description": link.description,
                    **_link_details(structure, link),
                }
        for process in structure.controlled_processes:
            if process.cp_id == controller:
                return {
                    "kind": "controlled_process",
                    "description": process.description,
                }
    return {"kind": "unknown", "description": None}


def process_model_gaps(
    run: RunData, documents: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    """Return the ``process-model-gaps-v1`` document, or None without the field.

    ``factors`` counts every causal factor of the published handoffs,
    ``linked`` those whose variable has an id, and ``gaps`` those whose
    variable id is null.
    """
    ordered = sorted(documents, key=natural_key)
    factors = [(s, f) for s in ordered for f in _factors(documents[s])]
    if not any(FIELD in factor for _, factor in factors):
        return None
    variables = [(s, f, f[FIELD]) for s, f in factors if isinstance(f.get(FIELD), dict)]
    gaps = [(s, f, v) for s, f, v in variables if v.get("id") is None]
    by_controller: dict[str, list[dict[str, Any]]] = {}
    for scenario_id, factor, variable in gaps:
        by_controller.setdefault(_controller(documents[scenario_id]), []).append(
            {
                "scenario_id": scenario_id,
                "source_id": factor.get("source_id"),
                "belief": factor.get("process_model_belief"),
                "missing_variable": variable.get("description"),
            }
        )
    return {
        "format": GAPS_FORMAT,
        "summary": {
            "factors": len(factors),
            "linked": sum(v.get("id") is not None for _, _, v in variables),
            "gaps": len(gaps),
        },
        "controllers": [
            {
                "controller": controller,
                **_controller_entry(controller, run.structure),
                "gaps": sorted(
                    by_controller[controller],
                    key=lambda gap: natural_key(gap["scenario_id"]),
                ),
            }
            for controller in sorted(by_controller, key=natural_key)
        ],
    }


def write_process_model_gaps(report_dir: Path, gaps: dict[str, Any]) -> Path:
    """Write the gap list as ``process-model-gaps.yaml`` in *report_dir*."""
    path = report_dir / GAPS_FILE
    path.write_text(
        yaml.safe_dump(gaps, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )
    return path


def _endpoint(endpoint: dict[str, Any]) -> str:
    described = f" ({esc(endpoint['description'])})" if endpoint["description"] else ""
    return f"{code_id(endpoint['id'])}{described}"


def _description_cell(entry: dict[str, Any]) -> Markup | str:
    """Describe a controller; a link names its endpoints and the variable owner."""
    description = entry["description"] or "not in control-structure.yaml"
    if entry.get("kind") != "coordination_link":
        return description
    source, target = entry["endpoints"]
    shared = entry["shared_variable"]
    owner = (
        f"owned by {code_id(shared['owner'])}"
        if shared["owner"]
        else "owned by no single endpoint"
    )
    return Markup(
        f"Link from {_endpoint(source)} to {_endpoint(target)}; shared variable "
        f"{code_id(shared['id'])} {owner}. {esc(description)}"
    )


def gaps_section(gaps: dict[str, Any]) -> Markup:
    """Render the gap list as a table with links to the scenarios."""
    summary = gaps["summary"]
    intro = Markup(
        f"<p>{plural(summary['factors'], 'causal factor')} in the published "
        f"handoffs: {summary['linked']} link their belief to a process-model "
        f"variable and {summary['gaps']} to a variable no process model holds. "
        f'The same list is in <a class="artifact" href="{GAPS_FILE}">{GAPS_FILE}</a>.'
        "</p>"
    )
    columns = [
        Column("Controller"),
        Column("Controller description", sortable=False),
        Column("Scenario"),
        Column("Factor"),
        Column("Flawed belief", sortable=False),
        Column("Missing variable", sortable=False),
    ]
    rows = [
        Row(
            [
                code_id(entry["controller"]),
                _description_cell(entry),
                Markup(
                    f'<a href="#{esc(gap["scenario_id"])}">{esc(gap["scenario_id"])}</a>'
                ),
                code_id(gap["source_id"]),
                gap["belief"] or "",
                gap["missing_variable"] or "",
            ]
        )
        for entry in gaps["controllers"]
        for gap in entry["gaps"]
    ]
    body = Markup(f"{intro}{table(columns, rows, 'gaps-table')}")
    return section("gaps", "Process-model gaps", QUESTION, body)
