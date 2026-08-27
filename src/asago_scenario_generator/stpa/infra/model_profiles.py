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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T11:34:31Z","module_hash":"4b7a309263ca8eb8f62afa69704a2e127785a97c9c4444370cf8a2c1616fb2d9","source_sha256":"ea4bf307b91c4763d38cfda3cff30ed3f1f2f3ccfc5da4dbb368cdead3f10dd6","functions":[]}
# mutate4py-manifest-end
