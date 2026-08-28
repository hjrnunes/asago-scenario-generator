"""STPA façade for the shared named-profile loader.

The YAML shape and field policy live in
``asago_scenario_generator.model_profiles``. This module keeps the historical
STPA import path without owning the loader.
"""

from asago_scenario_generator.model_profiles import (
    OPTIONAL_FIELDS,
    REQUIRED_FIELDS,
    load_profile,
)

__all__ = [
    "OPTIONAL_FIELDS",
    "REQUIRED_FIELDS",
    "load_profile",
]
