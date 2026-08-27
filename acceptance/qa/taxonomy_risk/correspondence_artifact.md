# End-to-end QA: correspondence artifact

Drive a deterministic file-to-file correspondence proposer and
reconciler: a valid `SystemResourceMap` and source artifacts in,
published YAML and JSON proposal-set and reconciliation-result
artifacts out. That invocation is a user-interface affordance; it is
not `generate` or `stpa-run`, and it is not required as a new public
CLI subcommand. Inspect artifacts with standard JSON/YAML readers and
byte comparison. Do not import project modules, call
`propose_correspondence` or `reconcile_correspondence`, or contact an
LLM endpoint. Never set `ASAGO_SCENARIO_GENERATOR_QA_PIPELINE`.

Use a fresh output directory for every case.

## QA-CA-01: pinned source versions are copied into proposals

1. Author a resource map that pins STPA version `stpa-v1` and taxonomy
   version `atlas-2026.05`.
2. Produce correspondence proposals.
3. Inspect every proposal with a standard reader.

**Expected:** Every proposal records STPA version `stpa-v1` and
taxonomy version `atlas-2026.05`.

## QA-CA-02: YAML and JSON round-trip without semantic loss

1. Produce a reconciliation result that includes confirmed, rejected,
   and unresolved proposals with evidence provenance and adjudication
   history.
2. Serialize it as YAML, deserialize it with a standard YAML reader,
   and re-inspect identities, provenance, history, and relation types.
3. Repeat with JSON.

**Expected:** Proposal identities, evidence provenance, adjudication
history, and relation types are preserved in both formats.

## QA-CA-03: identical inputs are byte-stable

1. Serialize the same reconciliation result twice as YAML.
2. Serialize the same reconciliation result twice as JSON.
3. Compare the raw artifact bytes.

**Expected:** The two YAML artifacts are byte-identical. The two JSON
artifacts are byte-identical.

## QA-CA-04: identifiers and order ignore presentation order

1. Author two proposal sets with the same identities in opposite
   order: `P-1,P-2,P-3` versus `P-3,P-2,P-1`.
2. Reconcile and serialize each set.
3. Compare identities, canonical order, and serialized artifacts.

**Expected:** Both results have identical proposal identities and
identical canonical order. The serialized artifacts are canonically
equivalent.

## QA-CA-05: a new proposer can be added without changing reconciliation rules

1. Keep existing proposals `P-1` and `P-2` with their previous
   adjudications.
2. Add proposer `overlap-adapter` that emits the shared proposal
   contract as proposal `P-3`.
3. Reconcile and inspect.

**Expected:** `P-3` is retained with adjudication `unresolved`. `P-1`
and `P-2` keep their previous adjudications. Reconciliation rules are
unchanged: the new proposer only creates proposals and does not write
confirmed relations.

## QA-CA-06: coverage scores and blended method metrics are omitted

1. Produce a reconciliation result with confirmed, rejected, and
   unresolved proposals.
2. Serialize it as YAML and as JSON.
3. Search the published artifact bytes for a coverage score and a
   blended method metric.

**Expected:** Neither artifact contains a coverage score. Neither
artifact contains a blended method metric.
