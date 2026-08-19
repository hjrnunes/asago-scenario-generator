# End-to-end QA: taxonomy projection prompt alignment

Drive only `uv run asago-scenario-generator generate` with a deterministic
local OpenAI-compatible fixture endpoint that records request bodies. Use a
fresh output collection and complete reviewed inputs. Inspect the fixture's
received narrative and attack-tree requests; do not import project modules or
render templates directly.

## QA-TPPA-01: prompts use semantic step identities

1. Select a projection containing semantic step IDs `attacker.observe` and
   `operator.impact`.
2. Run `generate` through the narrative and attack-tree calls.
3. Inspect both recorded user prompts.

**Expected in both prompts:** Every selected step is introduced by
`- step_id: <semantic-id>`. Neither step is introduced by a numeric list label
such as `1. step_id:`. An explicit warning says step IDs are semantic names,
not positional labels.

## QA-TPPA-02: prompts share current alignment rules

1. Inspect the same two recorded user prompts.
2. Locate the projection-alignment compatibility and normalization guidance.

**Expected in both prompts:** The guidance includes `observe` to
`external_precondition`, `prepare` to `external_precondition`, and `operator`
to `impact` compatibility, and says the action-kind and executor-role
compatibility sets must have a non-empty intersection. It also says:

- `external_precondition` has no zone and may map only outside-boundary steps,
  while inside-boundary and crossing-boundary instances stay unmapped;
- resource bindings come from the mapped canonical step; and
- technique IDs use an ATLAS or LAAF format, otherwise they are omitted.
