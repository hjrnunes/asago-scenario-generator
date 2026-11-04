"""Run a handoff kit's conformance cases against the shared rules.

``handoff-v5/conformance-cases.json`` names, for each rule, the valid handoffs or
companions that must pass and the invalid ones that must be reported. The runner
reads the kit directory it is given, so it runs the producer's contract tree and
a consumer's mirror alike.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .companion import feature_violations
from .contract import KIT_V5, ContractError, load_contract
from .violation import Violation
from .violations import validate_handoff


@dataclass(frozen=True)
class ConformanceCase:
    """One manifest entry: a rule, whether the case holds, and the document it names."""

    rule: str
    kind: str
    valid: bool
    path: str
    handoff: dict[str, Any]
    text: str | None = None


@dataclass(frozen=True)
class ConformanceResult:
    """A case and the violations running it produced."""

    case: ConformanceCase
    violations: tuple[Violation, ...]

    @property
    def passed(self) -> bool:
        """Tell whether the case produced violations exactly when it must."""

        return (not self.violations) == self.case.valid


def load_conformance_cases(contract_dir: Path) -> list[ConformanceCase]:
    """Read a kit's manifest and every document it names."""

    kit_dir = Path(contract_dir) / KIT_V5
    manifest = _read_json(kit_dir / "conformance-cases.json", "conformance manifest")
    cases: list[ConformanceCase] = []
    for rule in manifest["rules"]:
        for valid, paths in ((True, rule["valid"]), (False, rule["invalid"])):
            for path in paths:
                cases.append(_case(rule, valid, path, kit_dir))
    return cases


def run_conformance(contract_dir: Path) -> list[ConformanceResult]:
    """Run every case a kit's manifest names against the shared rules."""

    contract = load_contract(contract_dir)
    results: list[ConformanceResult] = []
    for case in load_conformance_cases(contract_dir):
        if case.kind == "companion":
            violations = feature_violations(case.handoff["gherkin"], case.text or "")
        else:
            violations = validate_handoff(case.handoff, contract=contract)
        results.append(ConformanceResult(case, tuple(violations)))
    return results


def _case(
    rule: dict[str, Any], valid: bool, path: str, kit_dir: Path
) -> ConformanceCase:
    document = _read_json(kit_dir / path, f"{rule['name']} case")
    if rule["kind"] == "companion":
        handoff = _read_json(
            kit_dir / document["handoff"], f"{rule['name']} companion handoff"
        )
        return ConformanceCase(
            rule["name"], rule["kind"], valid, path, handoff, document["text"]
        )
    return ConformanceCase(rule["name"], rule["kind"], valid, path, document)


def _read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read {label} {path}: {exc}") from exc


__all__ = [
    "ConformanceCase",
    "ConformanceResult",
    "load_conformance_cases",
    "run_conformance",
]
