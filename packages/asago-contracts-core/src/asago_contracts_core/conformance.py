"""Run a handoff kit's conformance cases against the shared rules.

``scenario-handoff-v5/cases/conformance-cases.json`` names, for each rule, the
valid handoffs or companions that must pass, the invalid ones that must be
reported, and the violation codes the rule owns. An invalid case passes only
when one of its violations carries one of those codes, so a violation from
another rule cannot hide a case that no longer exercises the rule it names. The
runner reads the kit directory it is given, so it runs the producer's contract
tree and a consumer's mirror alike.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .companion import feature_violations
from .contract import CASES_NAME, KIT_V5, ContractError, load_contract
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
    codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ConformanceResult:
    """A case and the violations running it produced."""

    case: ConformanceCase
    violations: tuple[Violation, ...]

    @property
    def passed(self) -> bool:
        """Tell whether the case produced the violations it must.

        A valid case passes with none. An invalid case passes only when a
        violation carries a code the rule names; any other violation leaves it
        failing, because the case no longer shows what its rule forbids.
        """

        if self.case.valid:
            return not self.violations
        return any(
            violation.code.startswith(prefix)
            for violation in self.violations
            for prefix in self.case.codes
        )


def load_conformance_cases(contract_dir: Path) -> list[ConformanceCase]:
    """Read a kit's manifest and every document it names."""

    kit_dir = Path(contract_dir) / KIT_V5
    manifest = _read_json(
        kit_dir / CASES_NAME / "conformance-cases.json", "conformance manifest"
    )
    cases: list[ConformanceCase] = []
    for rule in manifest["rules"]:
        codes = _rule_codes(rule)
        for valid, paths in ((True, rule["valid"]), (False, rule["invalid"])):
            for path in paths:
                cases.append(_case(rule, valid, path, kit_dir / CASES_NAME, codes))
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


def _rule_codes(rule: dict[str, Any]) -> tuple[str, ...]:
    """Read the violation codes a rule owns, refusing an empty or malformed list."""

    codes = rule.get("codes")
    if (
        not isinstance(codes, list)
        or not codes
        or not all(isinstance(code, str) and code for code in codes)
    ):
        raise ContractError(
            f"conformance rule {rule.get('name')!r} must name a non-empty codes list"
        )
    return tuple(codes)


def _case(
    rule: dict[str, Any],
    valid: bool,
    path: str,
    kit_dir: Path,
    codes: tuple[str, ...],
) -> ConformanceCase:
    document = _read_json(kit_dir / path, f"{rule['name']} case")
    if rule["kind"] == "companion":
        handoff = _read_json(
            kit_dir / document["handoff"], f"{rule['name']} companion handoff"
        )
        return ConformanceCase(
            rule["name"], rule["kind"], valid, path, handoff, document["text"], codes
        )
    return ConformanceCase(
        rule["name"], rule["kind"], valid, path, document, codes=codes
    )


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
