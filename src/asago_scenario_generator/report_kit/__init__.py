"""The old import path for the report kit; M9 removes it.

The kit moved to the producer's ``asago-report-kit`` workspace member, which
installs as ``asago_report_kit``. This module re-exports every public name, so
``from asago_scenario_generator.report_kit import ...`` keeps working for one
cycle and returns the member's objects. New code imports ``asago_report_kit``.
"""

from __future__ import annotations

from asago_report_kit import *  # noqa: F401,F403
from asago_report_kit import __all__ as _member_all

__all__ = list(_member_all)
