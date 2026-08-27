# End-to-end QA: taxonomy obligation plan artifact

Drive a deterministic file-to-file obligation planner: a snapshot fixture
file in, published YAML and JSON plan artifacts out. That invocation is
a user-interface affordance; it is not `generate` or `stpa-run`, and it
is not required as a new public CLI subcommand. Inspect those files with
standard JSON/YAML readers and byte comparison. Do not import project
modules, call `plan_obligations`, or contact an LLM endpoint. Never set
`ASAGO_SCENARIO_GENERATOR_QA_PIPELINE`.

Use a fresh output directory for every case.

## QA-TOPA-01: pinned snapshot versions are copied into the plan

1. Author a snapshot that pins taxonomy version `atlas-2026.05`, mapping
   version `sssom-v1`, qualification ruleset version
   `catalog-qualification-v1`, template version `scenario-envelope-v1`,
   and digest
   `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`.
2. Produce the obligation-plan artifact.
3. Inspect the published plan with a standard reader.

**Expected:** The plan records the same taxonomy version, mapping
version, qualification ruleset version, template version, and digest.

## QA-TOPA-02: identifiers and order ignore presentation order

1. Author two snapshots with the same two relationships in opposite
   order:
   `atlas-prompt-injection:AP-T6-01,atlas-memory-poisoning:AP-T1-01`
   versus
   `atlas-memory-poisoning:AP-T1-01,atlas-prompt-injection:AP-T6-01`.
2. Produce a plan from each snapshot.
3. Compare obligation identifiers, canonical ledger order, and
   serialized artifacts.

**Expected:** Both plans have identical obligation identifiers and
identical canonical ledger order. The serialized artifacts are
canonically equivalent.

## QA-TOPA-03: YAML and JSON round-trip without semantic loss

1. Produce a plan that includes pinned versions, terminal dispositions,
   qualification traces, and candidate evidence.
2. Serialize it as YAML, deserialize it with a standard YAML reader,
   and re-inspect identity, versions, dispositions, and evidence.
3. Repeat with JSON.

**Expected:** Obligation identities, pinned versions, terminal
dispositions, qualification traces, and candidate evidence are
preserved in both formats.

## QA-TOPA-04: identical inputs are byte-stable

1. Produce the same plan twice as YAML.
2. Produce the same plan twice as JSON.
3. Compare the raw artifact bytes.

**Expected:** The two YAML artifacts are byte-identical. The two JSON
artifacts are byte-identical.
