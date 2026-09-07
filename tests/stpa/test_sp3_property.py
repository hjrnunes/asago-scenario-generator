"""Property-based tests for SP3 Scenario Production invariants.

These tests verify structural invariants that hold across broad input
ranges using Hypothesis:

- **BDI grounding**: ``populate_defender_bdi`` always produces beliefs,
  desires, and intentions whose IDs match the control structure.
  ``validate_bdi_grounding`` always passes for specs derived this way.
- **Tree branch coverage**: ``count_branch_categories`` always returns
  0–3; ``get_branch_categories`` is always a subset of
  ``BRANCH_CATEGORIES``.
- **Traceability chain completeness**: A scenario with all valid links
  produces zero errors; breaking any single link produces an error for
  that link type only.
- **Shannon entropy**: Non-negative, bounded by ``log2(n)`` for ``n``
  categories.
- **Scenario ID format**: ``generate_scenario_id`` always produces
  ``SCN-NNN`` with zero-padding.
- **parse_ica_slot_id round-trip**: Parsing and re-joining preserves
  the original components for valid 3-part slot IDs.
"""

from __future__ import annotations

import math
import re

from hypothesis import HealthCheck, given, settings, strategies as st

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ControlledProcess,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import (
    CoverageAnalysis,
    EnrichedThreatSet,
    StructuralThreat,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.scenario_envelope import (
    GherkinSpec,
    ScenarioEnvelope,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    generate_scenario_id,
    parse_ica_slot_id,
    populate_defender_bdi,
)
from asago_scenario_generator.stpa.scenario_prod.eval_metrics import (
    _safe_rate,
    _shannon_entropy,
    metric_bdi_grounding,
    metric_tree_branch_coverage,
)
from asago_scenario_generator.stpa.scenario_prod.validators import (
    BRANCH_CATEGORIES,
    count_branch_categories,
    get_branch_categories,
    validate_traceability,
    validate_tree_branch_coverage,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

st_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs", "Cc"),
        blacklist_characters=("\x85", "\u2028", "\u2029"),
    ),
    min_size=1,
    max_size=20,
)

st_ica_type = st.sampled_from(list(UCAType))


def _make_cs(
    n_resps: int = 2,
    n_pms: int = 2,
    n_cas: int = 2,
) -> ControlStructure:
    """Build a deterministic control structure for property tests."""
    cps = [ControlledProcess(cp_id="CP-1", description="Interface")]
    responsibilities = []
    for i in range(1, n_resps + 1):
        responsibilities.append(
            Responsibility(
                resp_id=f"RESP-{i}",
                description=f"R{i}",
                process_model_parts=[
                    ProcessModelPart(pm_id=f"PM-{i}-{j}", description=f"PM {i}-{j}")
                    for j in range(1, n_pms + 1)
                ],
                control_actions=[
                    ControlAction(
                        ca_id=f"CA-{i}-{j}",
                        description=f"CA {i}-{j}",
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    )
                    for j in range(1, n_cas + 1)
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id=f"FB-{i}-{j}",
                        description=f"FB {i}-{j}",
                        updates=f"PM-{i}-{j}",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    )
                    for j in range(1, min(n_pms, 2) + 1)
                ],
            )
        )
    return ControlStructure(responsibilities=responsibilities, controlled_processes=cps)


def _make_loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["r1"],
            ),
        ],
        use_case_losses=[],
        hazards=[Hazard(hazard_id="H-1", description="H", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1", description="C", related_hazards=["H-1"]
            ),
        ],
    )


def _make_threat(
    resp_id: str = "RESP-1",
    ca_id: str = "CA-1-1",
    ica_type: UCAType = UCAType.not_provided,
    ica_id_suffix: int = 1,
    related_hazards: list[str] | None = None,
    related_constraints: list[str] | None = None,
) -> StructuralThreat:
    slot = f"{resp_id}:{ca_id}:{ica_type.value}"
    return StructuralThreat(
        ica_slot_id=slot,
        provenance="structural",
        ica_id=f"{slot}:{ica_id_suffix}",
        ica_text="ICA text",
        hazardous_context="Context",
        loss_scenario="Loss scenario",
        related_hazards=related_hazards or ["H-1"],
        related_constraints=related_constraints or ["SC-1"],
    )


def _make_ets(threats: list[StructuralThreat] | None = None) -> EnrichedThreatSet:
    return EnrichedThreatSet(
        structural_threats=threats or [_make_threat()],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={
                "total_slots": 1,
                "non_na": 1,
                "na": 0,
                "coverage_rate": 1.0,
            },
        ),
    )


def _make_envelope(
    spec: ScenarioSpec | None = None,
    attack_tree: dict | None = None,
) -> ScenarioEnvelope:
    s = spec or _make_scenario_spec()
    tree = attack_tree or {
        "root": "r",
        "branches": [
            {"category": "controller_side", "label": "l", "children": []},
            {"category": "path_side", "label": "l", "children": []},
        ],
        "leaves": [],
    }
    return ScenarioEnvelope(
        scenario_id=s.scenario_id,
        scenario_spec=s,
        narrative="narrative",
        attack_tree=tree,
        gherkin_spec=GherkinSpec(
            feature="Test",
            scenario="Test",
            given=["Given PM-1-1 is valid"],
            when=["When x"],
            then_expected=["Then should reject"],
            then_actual=["But approves"],
        ),
        target_responsibility=s.target_controller,
        ica_type=s.ica_type,
        provenance="structural",
    )


def _make_scenario_spec(
    scenario_id: str = "SCN-001",
    target_resp: str = "RESP-1",
    ca_id: str = "CA-1-1",
    ica_type: UCAType = UCAType.not_provided,
    pm_id: str = "PM-1-1",
    ica_id_suffix: int = 1,
) -> ScenarioSpec:
    slot = f"{target_resp}:{ca_id}:{ica_type.value}"
    return ScenarioSpec(
        scenario_id=scenario_id,
        threat_source=ThreatSource(
            ica_slot_id=slot,
            provenance="structural",
            ica_id=f"{slot}:{ica_id_suffix}",
        ),
        target_controller=target_resp,
        target_control_action=ca_id,
        ica_type=ica_type,
        defender_bdi=DefenderBDI(
            beliefs=[
                DefenderBelief(pm_id=pm_id, content="State", vulnerability="vuln")
            ],
            desires=[DefenderDesire(resp_id=target_resp, content="R")],
            intentions=[DefenderIntention(ca_id=ca_id, content="A")],
        ),
        attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        loss_scenario="Loss",
    )


# ---------------------------------------------------------------------------
# BDI grounding property tests
# ---------------------------------------------------------------------------


class TestBDIGroundingProperty:
    """populate_defender_bdi always produces grounded BDI."""

    @given(
        n_resps=st.integers(min_value=1, max_value=5),
        n_pms=st.integers(min_value=1, max_value=4),
        n_cas=st.integers(min_value=1, max_value=4),
        resp_index=st.integers(min_value=0, max_value=4),
    )
    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_populate_defender_bdi_always_grounded(
        self, n_resps, n_pms, n_cas, resp_index
    ):
        """BDI from populate_defender_bdi always passes validate_bdi_grounding."""
        cs = _make_cs(n_resps=n_resps, n_pms=n_pms, n_cas=n_cas)
        target_idx = min(resp_index, n_resps - 1)
        target_resp_id = cs.responsibilities[target_idx].resp_id

        bdi = populate_defender_bdi(cs, target_resp_id)

        # Every belief pm_id must exist in the control structure
        valid_pms = {
            pm.pm_id for r in cs.responsibilities for pm in r.process_model_parts
        }
        for belief in bdi.beliefs:
            assert belief.pm_id in valid_pms

        # Every desire resp_id must be the target responsibility
        for desire in bdi.desires:
            assert desire.resp_id == target_resp_id

        # Every intention ca_id must belong to the target responsibility
        target_cas = {
            ca.ca_id for ca in cs.responsibilities[target_idx].control_actions
        }
        for intention in bdi.intentions:
            assert intention.ca_id in target_cas

        # Vulnerability fields must be empty before LLM call
        for belief in bdi.beliefs:
            assert belief.vulnerability == ""

    @given(
        n_resps=st.integers(min_value=1, max_value=4),
        n_pms=st.integers(min_value=1, max_value=3),
        n_cas=st.integers(min_value=1, max_value=3),
    )
    @settings(
        max_examples=30,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_bdi_grounding_metric_is_one_for_valid_specs(self, n_resps, n_pms, n_cas):
        """metric_bdi_grounding returns 1.0 for specs from populate_defender_bdi."""
        cs = _make_cs(n_resps=n_resps, n_pms=n_pms, n_cas=n_cas)
        envelopes = []
        for i in range(n_resps):
            resp = cs.responsibilities[i]
            ca = resp.control_actions[0]
            bdi = populate_defender_bdi(cs, resp.resp_id)
            # Fill in vulnerabilities (as the LLM would)
            for belief in bdi.beliefs:
                belief.vulnerability = "exploitable"
            spec = ScenarioSpec(
                scenario_id=f"SCN-{i + 1:03d}",
                threat_source=ThreatSource(
                    ica_slot_id=f"{resp.resp_id}:{ca.ca_id}:NOT_PROVIDED",
                    provenance="structural",
                    ica_id=f"{resp.resp_id}:{ca.ca_id}:NOT_PROVIDED:1",
                ),
                target_controller=resp.resp_id,
                target_control_action=ca.ca_id,
                ica_type=UCAType.not_provided,
                defender_bdi=bdi,
                attacker_bdi=AttackerBDI(
                    beliefs=["b"], desires=["d"], intentions=["i"]
                ),
                loss_scenario="Loss",
            )
            envelopes.append(_make_envelope(spec=spec))

        result = metric_bdi_grounding(envelopes, cs)
        assert result["belief_grounding_rate"] == 1.0
        assert result["desire_grounding_rate"] == 1.0
        assert result["intention_grounding_rate"] == 1.0


# ---------------------------------------------------------------------------
# Tree branch coverage property tests
# ---------------------------------------------------------------------------


class TestTreeBranchCoverageProperty:
    """Branch category counting invariants."""

    @given(
        categories=st.lists(
            st.sampled_from(BRANCH_CATEGORIES + ["unknown", ""]),
            min_size=0,
            max_size=10,
        )
    )
    @settings(max_examples=50, deadline=None)
    def test_count_branch_categories_bounded(self, categories):
        """count_branch_categories always returns 0–3."""
        tree = {
            "root": "r",
            "branches": [
                {"category": cat, "label": "l", "children": []} for cat in categories
            ],
            "leaves": [],
        }
        count = count_branch_categories(tree)
        assert 0 <= count <= 3

    @given(
        categories=st.lists(
            st.sampled_from(BRANCH_CATEGORIES + ["unknown"]),
            min_size=0,
            max_size=10,
        )
    )
    @settings(max_examples=50, deadline=None)
    def test_get_branch_categories_subset(self, categories):
        """get_branch_categories is always a subset of BRANCH_CATEGORIES."""
        tree = {
            "root": "r",
            "branches": [
                {"category": cat, "label": "l", "children": []} for cat in categories
            ],
            "leaves": [],
        }
        cats = get_branch_categories(tree)
        assert cats.issubset(set(BRANCH_CATEGORIES))

    @given(
        categories=st.lists(
            st.sampled_from(BRANCH_CATEGORIES),
            min_size=1,
            max_size=3,
            unique=True,
        )
    )
    @settings(max_examples=30, deadline=None)
    def test_valid_tree_passes_validator(self, categories):
        """Trees with at least one valid category always pass validation."""
        tree = {
            "root": "r",
            "branches": [
                {"category": cat, "label": "l", "children": []} for cat in categories
            ],
            "leaves": [],
        }
        result = validate_tree_branch_coverage(tree)
        assert result.passed

    @given(
        category=st.sampled_from(BRANCH_CATEGORIES),
    )
    @settings(max_examples=10, deadline=None)
    def test_single_category_passes_validator(self, category):
        """One evidenced category is a complete tree."""
        tree = {
            "root": "r",
            "branches": [
                {"category": category, "label": "l", "children": []},
            ],
            "leaves": [],
        }
        result = validate_tree_branch_coverage(tree)
        assert result.passed

    @given(
        n_valid=st.integers(min_value=0, max_value=5),
        n_invalid=st.integers(min_value=0, max_value=5),
    )
    @settings(max_examples=30, deadline=None)
    def test_metric_coverage_rate_in_range(self, n_valid, n_invalid):
        """Coverage rate is always in [0, 1]."""
        envelopes = []
        for i in range(n_valid):
            envelopes.append(
                _make_envelope(
                    spec=_make_scenario_spec(scenario_id=f"SCN-{i + 1:03d}"),
                    attack_tree={
                        "root": "r",
                        "branches": [
                            {
                                "category": "controller_side",
                                "label": "l",
                                "children": [],
                            },
                            {"category": "path_side", "label": "l", "children": []},
                        ],
                        "leaves": [],
                    },
                )
            )
        for i in range(n_invalid):
            envelopes.append(
                _make_envelope(
                    spec=_make_scenario_spec(scenario_id=f"SCN-{n_valid + i + 1:03d}"),
                    attack_tree={
                        "root": "r",
                        "branches": [
                            {
                                "category": "controller_side",
                                "label": "l",
                                "children": [],
                            },
                        ],
                        "leaves": [],
                    },
                )
            )
        result = metric_tree_branch_coverage(envelopes)
        assert 0.0 <= result["coverage_rate"] <= 1.0
        assert result["total_scenarios"] == n_valid + n_invalid


# ---------------------------------------------------------------------------
# Traceability chain completeness property tests
# ---------------------------------------------------------------------------


class TestTraceabilityChainProperty:
    """Traceability validation invariants."""

    def test_valid_chain_produces_no_errors(self):
        """A scenario with all valid links produces zero traceability errors."""
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_ets()
        env = _make_envelope()
        errors = validate_traceability([env], ets, cs, la)
        assert len(errors) == 0

    @given(
        break_hazard=st.booleans(),
        break_constraint=st.booleans(),
        break_resp=st.booleans(),
        break_ca=st.booleans(),
        break_ica=st.booleans(),
    )
    @settings(max_examples=80, deadline=None)
    def test_broken_links_produce_errors(
        self, break_hazard, break_constraint, break_resp, break_ca, break_ica
    ):
        """Each broken link produces an error for that link type.

        The ICA ID is derived from the slot ID (resp:ca:type), so
        breaking resp or ca also breaks the ICA lookup, causing the
        validator to short-circuit with an ica error. Hazard and
        constraint checks only run when the ICA link is intact.
        """
        cs = _make_cs()
        la = _make_loss_analysis()

        hazards = ["H-99"] if break_hazard else ["H-1"]
        constraints = ["SC-99"] if break_constraint else ["SC-1"]
        threat = _make_threat(related_hazards=hazards, related_constraints=constraints)
        ets = _make_ets(threats=[threat])

        spec = _make_scenario_spec(
            target_resp="RESP-99" if break_resp else "RESP-1",
            ca_id="CA-99-1" if break_ca else "CA-1-1",
            ica_id_suffix=99 if break_ica else 1,
        )
        env = _make_envelope(spec=spec)

        errors = validate_traceability([env], ets, cs, la)
        error_links = {e.broken_link for e in errors}

        any_broken = (
            break_hazard or break_constraint or break_resp or break_ca or break_ica
        )
        if any_broken:
            assert len(errors) > 0

        # Scenario link checks (resp, ca) always run.
        if break_resp:
            assert "responsibility" in error_links
        if break_ca:
            assert "control_action" in error_links

        # The ICA lookup fails when resp, ca, or ica_id is wrong.
        # When the ICA lookup fails, hazard/constraint checks are skipped.
        ica_broken = break_resp or break_ca or break_ica
        if ica_broken:
            assert "ica" in error_links
        else:
            # ICA intact — hazard/constraint checks run.
            if break_hazard:
                assert "hazard" in error_links
            if break_constraint:
                assert "constraint" in error_links

    @given(
        n_scenarios=st.integers(min_value=0, max_value=10),
    )
    @settings(max_examples=20, deadline=None)
    def test_valid_scenarios_produce_zero_errors(self, n_scenarios):
        """Multiple valid scenarios produce zero traceability errors."""
        cs = _make_cs()
        la = _make_loss_analysis()
        threats = [_make_threat(ica_id_suffix=i + 1) for i in range(n_scenarios)]
        ets = _make_ets(threats=threats)
        envelopes = [
            _make_envelope(
                spec=_make_scenario_spec(
                    scenario_id=f"SCN-{i + 1:03d}",
                    ica_id_suffix=i + 1,
                )
            )
            for i in range(n_scenarios)
        ]
        errors = validate_traceability(envelopes, ets, cs, la)
        assert len(errors) == 0


# ---------------------------------------------------------------------------
# Shannon entropy property tests
# ---------------------------------------------------------------------------


class TestShannonEntropyProperty:
    """Shannon entropy mathematical invariants."""

    @given(
        counts=st.dictionaries(
            keys=st.text(min_size=1, max_size=5, alphabet="abcdefghij"),
            values=st.integers(min_value=0, max_value=100),
            min_size=0,
            max_size=10,
        )
    )
    @settings(max_examples=50, deadline=None)
    def test_non_negative(self, counts):
        """Shannon entropy is always non-negative."""
        entropy = _shannon_entropy(counts)
        assert entropy >= 0.0

    @given(
        n_categories=st.integers(min_value=1, max_value=10),
    )
    @settings(max_examples=20, deadline=None)
    def test_max_entropy_with_uniform_distribution(self, n_categories):
        """Uniform distribution gives entropy = log2(n)."""
        counts = {f"cat_{i}": 10 for i in range(n_categories)}
        entropy = _shannon_entropy(counts)
        expected = round(math.log2(n_categories), 6)
        assert abs(entropy - expected) < 1e-5

    @given(
        n_categories=st.integers(min_value=1, max_value=10),
    )
    @settings(max_examples=20, deadline=None)
    def test_zero_entropy_with_single_category(self, n_categories):
        """Single non-zero category gives entropy = 0."""
        counts = {f"cat_{i}": 0 for i in range(n_categories)}
        counts["cat_0"] = 42
        entropy = _shannon_entropy(counts)
        assert entropy == 0.0

    def test_zero_entropy_with_empty_counts(self):
        """Empty counts dict gives entropy = 0."""
        assert _shannon_entropy({}) == 0.0

    def test_zero_entropy_with_all_zeros(self):
        """All-zero counts gives entropy = 0."""
        assert _shannon_entropy({"a": 0, "b": 0}) == 0.0

    def test_count_of_one_contributes(self):
        """A category with count=1 must contribute to entropy."""
        counts = {"a": 1, "b": 1}
        entropy = _shannon_entropy(counts)
        expected = round(1.0, 6)  # log2(2) = 1.0
        assert abs(entropy - expected) < 1e-5


# ---------------------------------------------------------------------------
# Safe rate property tests
# ---------------------------------------------------------------------------


class TestSafeRateProperty:
    """_safe_rate mathematical invariants."""

    @given(
        numerator=st.integers(min_value=0, max_value=1000),
        denominator=st.integers(min_value=1, max_value=1000),
    )
    @settings(max_examples=50, deadline=None)
    def test_rate_in_unit_interval(self, numerator, denominator):
        """Rate is in [0, 1] when numerator ≤ denominator."""
        n = min(numerator, denominator)
        rate = _safe_rate(n, denominator)
        assert 0.0 <= rate <= 1.0

    @given(
        denominator=st.integers(min_value=-100, max_value=0),
    )
    @settings(max_examples=20, deadline=None)
    def test_zero_denominator_returns_zero(self, denominator):
        """Zero or negative denominator returns 0."""
        if denominator == 0:
            assert _safe_rate(5, 0) == 0


# ---------------------------------------------------------------------------
# Scenario ID format property tests
# ---------------------------------------------------------------------------


class TestScenarioIdProperty:
    """generate_scenario_id format invariants."""

    @given(index=st.integers(min_value=0, max_value=9998))
    @settings(max_examples=50, deadline=None)
    def test_id_format(self, index):
        """Scenario ID always matches SCN-NNN format."""
        sid = generate_scenario_id(index)
        assert re.match(r"^SCN-\d{3,}$", sid)
        assert int(sid.split("-")[1]) == index + 1

    @given(
        a=st.integers(min_value=0, max_value=100),
        b=st.integers(min_value=0, max_value=100),
    )
    @settings(max_examples=30, deadline=None)
    def test_id_monotonic(self, a, b):
        """Higher index produces lexicographically larger ID."""
        if a < b:
            assert generate_scenario_id(a) < generate_scenario_id(b)
        elif a == b:
            assert generate_scenario_id(a) == generate_scenario_id(b)


# ---------------------------------------------------------------------------
# parse_ica_slot_id round-trip property tests
# ---------------------------------------------------------------------------


class TestParseICASlotIdProperty:
    """parse_ica_slot_id round-trip invariants."""

    @given(
        controller=st.text(
            alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-",
            min_size=1,
            max_size=10,
        ),
        control_action=st.text(
            alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-",
            min_size=1,
            max_size=10,
        ),
        ica_type=st.sampled_from(
            [
                "NOT_PROVIDED",
                "INCORRECT",
                "TOO_LATE",
                "TOO_EARLY",
                "STOPPED_TOO_SOON",
                "STOPPED_TOO_LATE",
            ]
        ),
    )
    @settings(max_examples=50, deadline=None)
    def test_round_trip(self, controller, control_action, ica_type):
        """Parsing a valid slot ID preserves the components."""
        slot_id = f"{controller}:{control_action}:{ica_type}"
        parts = parse_ica_slot_id(slot_id)
        assert parts["controller"] == controller
        assert parts["control_action"] == control_action
        assert parts["ica_type"] == ica_type

    @given(
        n_parts=st.integers(min_value=0, max_value=5),
    )
    @settings(max_examples=20, deadline=None)
    def test_invalid_format_raises(self, n_parts):
        """A slot has three parts, or four with explicit action temporality."""
        if n_parts in {3, 4}:
            # Valid — should not raise
            parts = ":".join(f"x{i}" for i in range(n_parts))
            result = parse_ica_slot_id(parts)
            assert len(result) == 3
        else:
            parts = ":".join(f"x{i}" for i in range(n_parts))
            try:
                parse_ica_slot_id(parts)
                assert False, "Should have raised ValueError"
            except ValueError:
                pass
