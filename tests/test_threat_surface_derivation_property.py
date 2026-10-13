"""Property test for the kc_requires gate of threat gating.

**Gating monotonicity**: adding KC sub-codes never drops an attack pattern
whose kc_requires gate previously passed.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.data.threat_gating import _kc_requires_met

_KC_POOL = ["KC1.1", "KC2.3", "KC4.3", "KC6.4"]


@settings(max_examples=50, deadline=None)
@given(
    any_codes=st.lists(st.sampled_from(_KC_POOL), max_size=3, unique=True),
    all_codes=st.lists(st.sampled_from(_KC_POOL), max_size=3, unique=True),
    base=st.lists(st.sampled_from(_KC_POOL), min_size=1, max_size=4, unique=True),
    extra=st.lists(st.sampled_from(_KC_POOL), max_size=2, unique=True),
)
def test_kc_requires_gate_is_monotone_in_profile_codes(
    any_codes: list[str], all_codes: list[str], base: list[str], extra: list[str]
):
    """Adding KC sub-codes never drops a pattern whose kc_requires passed."""
    pattern = {
        "prerequisite_capabilities": {
            "kc_requires": {"any": any_codes, "all": all_codes}
        }
    }
    if _kc_requires_met(pattern, set(base)):
        assert _kc_requires_met(pattern, set(base) | set(extra))
