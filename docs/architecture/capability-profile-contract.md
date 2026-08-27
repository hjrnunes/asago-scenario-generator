# Capability profile: computed-boolean contract

*Decision record, resolves asago-ai/asago-scenario-generator#10.*

`has_persistent_memory`, `multi_agent`, and `hitl` on `CapabilityProfile`
are **computed fields** derived from `kc_subcodes`. This page pins the
input and output contracts so the deprecation story stays explicit.

## Input contract

- `kc_subcodes` is the single source of truth (required, non-empty).
- Legacy boolean fields (`has_persistent_memory`, `multi_agent`, `hitl`)
  are **accepted** from older YAML profiles and stripped by
  `CapabilityProfile.strip_legacy_bool_fields` before validation.
- Stripping emits a deprecation warning **only when the input value
  disagrees with the kc-derived value**. Values that already match the
  computed result (notably the project's own serialized output) are
  removed silently.
- Profiles without `kc_subcodes` are invalid; the legacy warning story
  exists only while an input carries both the legacy fields and valid
  KC evidence.

## Derivation

| Field | True when |
| --- | --- |
| `has_persistent_memory` | `kc_subcodes` intersects `KC4.3–KC4.6` or contains `KCX-PMEM` |
| `multi_agent` | `kc_subcodes` intersects `{KC2.3, KCX-MAGENT}` |
| `hitl` | `kc_subcodes` contains `KCX-HITL` |

The derivation lives in a single helper
(`_legacy_flag_values` in `models/capability_profile.py`) shared by the
computed fields and the input stripper, so the two cannot diverge.

## Output contract

- Serialized capability profiles (`capability-profile.yaml`,
  `model_dump(mode="json")`) **include** the computed booleans, matching
  the documented profile shape in `data-flow-diagrams.md`.
- Consumers (report rendering, threat gating) may read them directly.
- Loading the project's own output is a silent round trip: the included
  booleans are stripped without warning and recomputed from
  `kc_subcodes`, yielding identical values.

## Compatibility

- Older profiles containing the legacy fields remain readable during the
  compatibility period; conflicting values warn, matching values do not.
- Tests: `tests/test_kc_subcodes.py::TestBackwardCompatibility` covers
  legacy input, silent own-output round trips, and conflict warnings.
