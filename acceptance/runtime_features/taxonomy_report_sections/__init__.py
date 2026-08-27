"""Acceptance step handlers for taxonomy/risk HTML report section rendering.

Covers the section builders that still live in ``report/template.py``: the
capability profile, threat surface, coverage analysis, threat-technique
matrix, actor profile distribution, scenario cards (priority signals,
actor profile, attack tree, generation inputs, behavior spec, ATLAS
techniques, attack complexity), the run summary, pipeline call logs, and
raw-data syntax highlighting.  Fixtures are assembled step-by-step on the
world reusing the ``taxonomy_report`` vocabulary; the When step drives the
public report entry ``generate_report`` so the pinned behavior is
verified on the real rendered document.  All fixtures are offline.

The module is split into themed submodules (``given_*`` fixture handlers
and ``then_*`` assertion handlers); this package is a narrow facade.  Shared
extraction helpers live in the private ``_helpers`` submodule, each theme
owns its fixture or assertion handlers, and ``register`` delegates
registration in the original source-order groups.
"""

from __future__ import annotations

from typing import Any

from runtime_features.taxonomy_report import (
    _h_background,
    _h_generate_report,
)

from . import given_profile
from . import given_run
from . import given_scenarios
from . import given_threat_surface
from . import then_atlas
from . import then_behavior_spec
from . import then_cards
from . import then_coverage
from . import then_diversity
from . import then_matrix
from . import then_panels
from . import then_pipeline_calls
from . import then_profile
from . import then_scenarios
from . import then_summary
from . import then_threats

FEATURE_ID = "taxonomy_report_sections"


def register(api: Any) -> None:
    # Shared Background/When: register under this feature's scope so the
    # same public-report vocabulary drives the section-rendering scenarios.
    api.set_feature(FEATURE_ID)
    api.register_first(
        "an offline completed taxonomy-and-risk run fixture",
        _h_background,
        source_order=6000,
    )
    api.register_first(
        "the HTML report is generated",
        _h_generate_report,
        source_order=6100,
    )
    api.set_feature(None)

    given_profile.register(api)
    given_threat_surface.register(api)
    given_scenarios.register(api)
    given_run.register(api)
    then_profile.register(api)
    then_threats.register(api)
    then_coverage.register(api)
    then_matrix.register(api)
    then_diversity.register(api)
    then_cards.register(api)
    then_scenarios.register(api)
    then_summary.register(api)
    then_panels.register(api)
    then_behavior_spec.register(api)
    then_atlas.register(api)
    then_pipeline_calls.register(api)


__all__ = ["FEATURE_ID", "register"]
