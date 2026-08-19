# End-to-end QA: taxonomy projection traceability contract

Drive only `uv run asago-scenario-generator generate` with a deterministic
local OpenAI-compatible fixture endpoint. Use fresh output collections and
reviewed profile, qualification, risk-extraction, SSSOM, and authoritative
pattern fixtures. Inspect CLI output, endpoint request logs, manifests,
quarantine evidence, and published scenario YAML; do not import project
modules.

## QA-TPTC-01: outside observe and prepare reach admission

1. Select an authoritative canonical chain containing semantic steps
   `attacker.observe`, `attacker.prepare`, and `operator.impact`. Configure
   the first two as attacker-executed, outside-boundary `observe` and
   `prepare` steps, and the third as an operator-executed, inside-boundary
   `impact` step with an observable effect.
2. Return an ordered attack tree whose first two leaves are
   `external_precondition` actions without zones and whose last leaf is an
   internal `impact` action. Map each leaf to its corresponding semantic step
   ID and omit model-authored realizations.
3. Run `generate` and inspect request counts, the manifest, and admitted
   scenario YAML.

**Expected:** No attack-tree retry is caused by an empty action/executor
compatibility intersection. All three leaves retain their mappings and gain
canonical realizations. Tree realization coverage is complete and ordered,
projection traceability has no violation, the manifest reports one admitted
candidate, and the command exits `0`.

## QA-TPTC-02: invalid external metadata is canonicalized

1. Use an outside-boundary `attacker.prepare` step.
2. Return its `external_precondition` leaf with the correct
   `projected_step_ids`, zone `input`, technique ID `not-a-technique`, and no
   realization records.
3. Run `generate` and inspect the admitted scenario YAML.

**Expected:** The published leaf has a null or absent zone and technique ID,
retains `attacker.prepare`, and has its canonical realization. Complete
coverage passes without an attack-tree retry.

## QA-TPTC-03: valid technique formats survive normalization

1. Repeat a valid run with mapped leaves carrying, in turn, allowed and
   projection-grounded technique IDs `AML.T0051`, `AML.T0051.001`, `S1`,
   `M2`, and `L3`.
2. Inspect the admitted scenario YAML after each run.

**Expected:** Each valid technique ID is preserved exactly. No valid ID is
stripped merely because transport normalization ran.

## QA-TPTC-04: inside and crossing external leaves stay unmapped

1. For each boundary position `inside` and `crossing`, select canonical step
   `system.observe`.
2. Return one `external_precondition` leaf that claims `system.observe`, plus
   a second compatible zoned leaf that maps the same step and keeps coverage
   complete.
3. Run `generate` and inspect the admitted scenario YAML.

**Expected:** The external-precondition leaf has empty
`projected_step_ids`, empty realizations, and no zone. The compatible zoned
leaf carries `system.observe` and its canonical realization, so coverage and
admission still pass.

## QA-TPTC-05: unknown semantic identity remains rejected

1. Use an otherwise valid outside-boundary external-precondition leaf but
   reference `step.unknown`.
2. Return the same unknown ID for all bounded attack-tree attempts.
3. Run `generate` and inspect stderr, request counts, manifest, quarantine
   evidence, and published scenarios.

**Expected:** Only the bounded attack-tree retry allowance is used. The
diagnostic identifies `step.unknown` as unknown, no tree containing it is
published, no candidate is admitted, and the command exits nonzero.
