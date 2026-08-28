# End-to-end QA: taxonomy obligation plan artifact

Drive a deterministic file-to-file obligation planner: a snapshot fixture
file in, published YAML and JSON plan artifacts out. That invocation is
a user-interface affordance; it is not `generate` or `stpa-run`, and it
is not required as a new public CLI subcommand. Inspect those files with
standard JSON/YAML readers and byte comparison. Do not import project
modules, call `plan_obligations`, or contact an LLM endpoint. Never set
`ASAGO_SCENARIO_GENERATOR_QA_PIPELINE`.

Use a fresh output directory for every case.

## QA-TOPA-01: closed schema metadata is computed from canonical content

1. Author a snapshot that pins catalog pin `atlas-2026.05`, mapping pin
   `sssom-v1`, capability snapshot content `profile-v1`, and
   qualification facts `facts-v1`.
2. Produce the obligation-plan artifact.
3. Inspect the published plan with a standard reader.

**Expected:** The plan records schema version
`taxonomy-obligation-plan-v1`, catalog pin `atlas-2026.05`, mapping pin
`sssom-v1`, and computed digests for capability snapshot, qualification
facts, generation inputs, and semantic content. Those digests are not
copied from caller-supplied digest fields.

## QA-TOPA-02: identifiers and digests ignore presentation order

1. Author two snapshots with the same two relationships in opposite
   order:
   `atlas-prompt-injection:AP-T6-01,atlas-memory-poisoning:AP-T1-01`
   versus
   `atlas-memory-poisoning:AP-T1-01,atlas-prompt-injection:AP-T6-01`.
2. Produce a plan from each snapshot.
3. Compare obligation identifiers, semantic digests, canonical ledger
   order, and serialized artifacts.

**Expected:** Both plans have identical obligation identifiers,
identical semantic digests, and identical canonical ledger order. The
serialized artifacts are canonically equivalent.

## QA-TOPA-03: YAML and JSON round-trip without semantic loss

1. Produce a plan that includes pins, closed dispositions, computed
   digests, qualification traces, candidate records, and summary
   counts.
2. Serialize it as YAML, deserialize it with a standard YAML reader,
   and re-inspect identity, schema version, pins, digests,
   dispositions, traces, candidate records, and summary counts.
3. Repeat with JSON.

**Expected:** Obligation identities, schema version, pins, computed
digests, scope/qualification/projection/correspondence dispositions,
qualification traces, candidate records, and summary counts are
preserved in both formats.

## QA-TOPA-04: identical inputs are byte-stable

1. Produce the same plan twice as YAML.
2. Produce the same plan twice as JSON.
3. Compare the raw artifact bytes.

**Expected:** The two YAML artifacts are byte-identical. The two JSON
artifacts are byte-identical.

## QA-TOPA-05: tampered persisted content is rejected

1. Publish a valid plan as YAML and as JSON.
2. Tamper `catalog_pins`, `mapping_pins`, or `obligations` without
   updating the semantic digest.
3. Load each tampered artifact through the same file-to-file
   publication path.

**Expected:** Loading is rejected. The result identifies a digest
mismatch. No silently accepted tampered plan is published.

## QA-TOPA-06: unknown fields are rejected

1. Persist otherwise valid plans that include unknown fields
   `extra_score` and `covered_rate`.
2. Load each artifact.

**Expected:** Loading is rejected. The result identifies the unknown
field.

## QA-TOPA-07: unsupported schema versions are rejected

1. Persist otherwise valid plans that declare schema version
   `taxonomy-obligation-plan-v0` and `taxonomy-obligation-plan-v2`.
2. Load each artifact.

**Expected:** Loading is rejected. The result identifies the schema
version as unsupported.

## QA-TOPA-08: caller-supplied false digests are ignored

1. Author snapshots that supply false values for
   `capability_snapshot_digest`, `semantic_digest`, and
   `qualification_facts_digest`:
   - `deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`
   - `cafebebecafebebecafebebecafebebecafebebecafebebecafebebecafebebe`
   - `0000000000000000000000000000000000000000000000000000000000000000`
2. Produce a plan from each snapshot.
3. Inspect the recorded digest of that kind.

**Expected:** The plan does not record the false caller-supplied value.
It records the digest computed from canonical content.

## QA-TOPA-09: YAML publication is atomic

1. Publish the plan as YAML.
2. Inspect the output directory and load the published file with a
   standard YAML reader.

**Expected:** The published artifact is named
`taxonomy-obligation-plan.yaml`. It loads as a complete closed plan.
No partial plan file remains.

## QA-TOPA-10: Phase 1 correspondence claims are rejected

1. Persist otherwise valid plans that set correspondence disposition
   to `covered`, `matched`, or `satisfied`.
2. Load each artifact.

**Expected:** Loading is rejected. The result identifies the
correspondence disposition as invalid.
