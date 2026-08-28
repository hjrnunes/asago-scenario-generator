# End-to-end QA: taxonomy obligation plan artifact

Drive the public `plan-obligations` adapter with a YAML input file containing
complete serialized `AttackPattern` and `CapabilityFactSnapshot` authority.
Inspect the single published YAML artifact with standard readers and compare
raw bytes where determinism is required. Candidate records are derived by the
planner and are never supplied in the input.

Do not import the planner, call `plan_obligations`, invoke `generate` or
`stpa-run`, contact an LLM endpoint, or set
`ASAGO_SCENARIO_GENERATOR_QA_PIPELINE`. The acceptance runtime and unit
contract cover closed-model load/tamper checks; this external QA suite checks
the file adapter and publication boundary.

The persisted evidence contract retains typed condition and precondition
evaluations and explicit absent qualification facts. When projection is
bounded, only candidates actually derived and validated can be
`budget_deferred`; overflow is a typed limitation rather than a fabricated
candidate.

## QA-TOPA-01: metadata carries authoritative pins and digests

1. Publish a valid input built from the shared projection fixture.
2. Inspect the YAML top-level mapping.

Expected: the artifact is `taxonomy-obligation-plan-v1` with exactly the
closed metadata fields, the authoritative capability snapshot digest, the
domain-framed qualification facts digest, and the catalog/mapping pins. The
`mapping_pins` inventory is exactly `sssom` (the unchanged taxonomy-context
pin) and `obligation_edges` (release `obligation-mapping-bundle-v1`, covering
the supplied cross-taxonomy and SSSOM rows). All content digests are
64-character lowercase SHA-256 values.

## QA-TOPA-02: presentation order is canonicalized

1. Publish equivalent inputs with `risk-a`, `risk-b` and then `risk-b`,
   `risk-a` in the risk-card and mapping sequences.
2. Compare obligation IDs, plan semantic digests, and raw YAML bytes.

Expected: IDs, semantic digest, row order, and serialized bytes are identical.

## QA-TOPA-03: YAML round-trip preserves the closed plan

1. Publish a plan containing two risk-scoped rows and derived candidates.
2. Load the bytes with a standard YAML reader.
3. Inspect every row's closed field set, correspondence disposition, and
   derived candidate identity.

Expected: parsing produces the same mapping, every row has exactly the v1 row
fields, correspondence remains `not_assessed`, and derived candidate records
retain the authoritative candidate identity.

## QA-TOPA-04: identical typed inputs are byte-stable

1. Publish the same valid input twice into fresh directories.
2. Compare the raw YAML artifact bytes.

Expected: the artifacts are byte-identical and both use the exact filename
`taxonomy-obligation-plan.yaml`.

## QA-TOPA-05: malformed typed input fails before publication

Run the adapter with each of these otherwise valid inputs:

- unknown top-level `candidate_expansions` field;
- `projection_budget.max_candidates: 0`;
- a false qualification facts `semantic_digest`.

Expected: each invocation exits nonzero, identifies the offending field or
digest, and leaves no partial `taxonomy-obligation-plan.*` file. In particular,
`candidate_expansions` is not part of the typed input contract.

## QA-TOPA-06: publication is YAML-only and offline

1. Publish a valid typed plan and inspect the output and console.
2. Request `--format json` separately.

Expected: successful publication is YAML-only, atomic, and reports
`Network calls: 0` and `Model calls: 0`. A JSON publication request is rejected
without creating a partial artifact; no JSON output is expected from this
Phase 1 surface.

## QA-TOPA-07: summary reconciles from rows

1. Publish input containing two mapped risks and one reviewed risk without a
   mapping.
2. Recompute each summary counter from the emitted rows and candidate records.

Expected: the published summary equals the recomputation, retains all three
reviewed risks, and contains no taxonomy-correspondence or
scenario-realization rate. Persisted content tampering is rejected separately
by the closed plan loader.

## Completion evidence

The executable checks are in
`acceptance/qa/taxonomy_risk/obligation_plan_artifact.py`. A successful run
prints `Result: PASS` and leaves only untracked diagnostic evidence under
`tmp/`.
