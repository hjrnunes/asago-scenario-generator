# End-to-end QA: taxonomy external impact transport

Drive only `uv run asago-scenario-generator generate` with a deterministic
local OpenAI-compatible fixture endpoint. Use fresh output collections and
complete reviewed inputs. Inspect CLI diagnostics, request counts, manifests,
quarantine evidence, and published scenario YAML; do not import modules.

## QA-TEIT-01: nested external impact zones are cleared

1. Select an outside-boundary canonical impact step.
2. Return a nested leaf with action kind `impact`, boundary `external`, the
   correct projected step ID, and transport zone `reasoning`.
3. Complete an otherwise valid run.

**Expected:** Strict model parsing succeeds without an attack-tree retry. The
published nested impact leaf has a null or absent zone, preserves its canonical
step ID, and has the canonical realization.

## QA-TEIT-02: valid internal impact zones survive

Select an inside impact step and return an internal impact leaf in active zone
`reasoning`.

**Expected:** The admitted leaf still has zone `reasoning`; external-impact
normalization does not alter internal impacts.

## QA-TEIT-03: external impact cannot hide a non-outside mapping

For inside and crossing projected impact steps, return an external impact leaf
with an active transport zone for all bounded attack-tree attempts.

**Expected:** Zone normalization happens before model parsing, but strict
projection validation still rejects the preserved step ID as a boundary
semantic violation. The ID is not silently removed or remapped, no defective
tree is published, and the run exits nonzero after bounded retries.

## QA-TEIT-04: external preconditions remain compatible

Return a zoned external-precondition leaf mapped to an outside step.

**Expected:** Its zone is cleared, its outside mapping and canonical
realization remain, and the valid scenario can be admitted.
