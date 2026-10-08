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

## How Stage 1b decides `kc_subcodes`

The product path (`_default_prepare_capability`) decides each sub-code in
one of two ways, and `capability-kc-decision.yaml` records both:

1. **Observed facts.** If the run has an observed execution target profile,
   `target_kc_decision` (`stpa/system_model/kc_decision.py`) reads only
   interpretations with disposition `supported` and interpreter/verifier
   agreement `agree`. Each rule names its codes and gives a reason:

   | Fact | Present | Absent |
   | --- | --- | --- |
   | A verified tool with `likely_state_effect: changes` | `KC6.3.2` | `KC6.3.1` |
   | An `observed_complete` inventory whose every tool is verified with `likely_state_effect: none` | | `KC6.3.2` |
   | A verified tool with the `text_search` semantic role | `KC6.3.3` | |

   A fact-decided code overrides the vote. The target profile never enters
   the Stage 1b request; the request stays the use-case text alone.
2. **Model vote.** Every other code comes from the model. Stage 1b sends the
   same request `KC_VOTE_SAMPLES` (9) times and keeps a code that at least
   `KC_VOTE_SHARE` (one third) of the successful draws select. The threshold
   sits below a majority because a sampled draw omits a grounded code more
   often than it invents one. A draw that fails after its one correction is
   left out of the vote; the stage fails only when every draw fails. Entry
   points, tool inventory, and confidence come from the first successful
   draw, or from the first draw with a tool inventory when the decided codes
   activate tool execution.

No rule exists for a code whose catalog definition no observed fact settles
(for example `KC2.1`, `KC4.x`, `KC5.x`, `KCX-HITL`, `KCX-AUDIT`): an
escalation tool does not prove that a human reviews actions, and the
qualification facts carry no per-code definition.

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
- Consumers (STPA reporting, threat gating, and obligation qualification) may
  read them directly.
- Loading the project's own output is a silent round trip: the included
  booleans are stripped without warning and recomputed from
  `kc_subcodes`, yielding identical values.

## Compatibility

- Older profiles containing the legacy fields remain readable during the
  compatibility period; conflicting values warn, matching values do not.
- Tests: `tests/test_kc_subcodes.py::TestBackwardCompatibility` covers
  legacy input, silent own-output round trips, and conflict warnings.
