# End-to-end QA: system resource map validation

Drive a deterministic file-to-file resource-map validator: a snapshot
fixture and a `SystemResourceMap` YAML or JSON file in, a published
validation result and canonical map artifact out. That invocation is a
user-interface affordance; it is not `generate` or `stpa-run`, and it is
not required as a new public CLI subcommand. Inspect artifacts with
standard JSON/YAML readers, the console, and the filesystem. Do not
import project modules, call `validate_resource_map`, or contact an LLM
endpoint. Never set `ASAGO_SCENARIO_GENERATOR_QA_PIPELINE`.

Use a fresh output directory for every case. The snapshot pins STPA and
taxonomy source versions and supplies the identifiers the map may
reference. The map remains editable data; do not bury analyst assertions
in prompt text.

## QA-SRM-01: a representative valid map covers the v1 families

1. Author a snapshot that includes STPA identifiers
   `RESP-1`, `CP-2`, `CA-1-1`, `FB-1-1`, `L-1`, and `H-1`, plus taxonomy
   identifiers `ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` and
   `tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`.
2. Author a resource map covering families
   `system-resource`, `actor-controller`, `controlled-process`,
   `control-action`, `feedback-path`, `trust-boundary`, `data-flow`,
   `loss-link`, and `use-case-fact`, referencing those identifiers.
3. Validate the map against the snapshot.
4. Inspect the validation result with a standard reader.

**Expected:** Validation succeeds with 0 errors. The result contains no
correspondence relations. No network or model call is recorded.

## QA-SRM-02: duplicate and unstable identifiers fail closed

1. Duplicate identifier `SR-1` in an otherwise valid map.
2. Validate and inspect the result.
3. Repeat with unstable identifier `idx-0`.

**Expected:** Validation fails. Duplicate yields error code
`duplicate_identifier` identifying `SR-1`. Unstable yields
`unstable_identifier` identifying `idx-0`.

## QA-SRM-03: dangling STPA and taxonomy references fail closed

1. For each of `RESP-99`, `CP-99`, `CA-99-1`, `FB-99-1`, `L-99`,
   `H-99`, `ep:v1:ffffffffffffffffffffffffffffffff`, and
   `tb:v1:ffffffffffffffffffffffffffffffff`, author a map that
   references that identifier while the snapshot does not contain it.
2. Validate each case.

**Expected:** Each case fails with error code `dangling_reference`
identifying the missing identifier.

## QA-SRM-04: invalid enum and status values fail closed

1. Set `entity_family` to `correspondence`.
2. Set `resolution_status` to `confirmed-absent-as-unknown`.
3. Set `provenance_kind` to `inferred-match`.
4. Validate each case.

**Expected:** Each case fails with error code `invalid_enum`
identifying the named field.

## QA-SRM-05: source-version pins must match the snapshot

1. Pin the snapshot to STPA `stpa-v1` and taxonomy `atlas-2026.05`.
2. Author a map pinned to STPA `stpa-v9` with matching taxonomy.
3. Author another map pinned to taxonomy `atlas-1999.01` with matching
   STPA.
4. Validate each case.

**Expected:** Each case fails with error code
`source_version_mismatch`.

## QA-SRM-06: control actions require valid controller and process references

1. Author control action `CA-1-1` without a controller reference.
2. Author control action `CA-1-1` without a process reference.
3. Validate each case.

**Expected:** Each case fails with error code
`invalid_control_action_link` identifying `CA-1-1`.

## QA-SRM-07: data flows and trust boundaries cannot name unknown resources

1. Author data-flow `DF-1` that references unknown resource `SR-99`.
2. Author trust-boundary `TB-1` that references unknown resource
   `SR-99`.
3. Validate each case.

**Expected:** Each case fails with error code `unknown_resource_link`
identifying `DF-1` or `TB-1` respectively.

## QA-SRM-08: loss links cannot name unknown STPA losses or hazards

1. Author loss link `LL-1` referencing unknown loss `L-99`.
2. Author loss link `LL-1` referencing unknown hazard `H-99`.
3. Validate each case.

**Expected:** Each case fails with error code `unknown_loss_link`
identifying `L-99` or `H-99` respectively.

## QA-SRM-09: ambiguous aliases fail closed

1. Bind alias `payment-backend` to both `CP-2` and `CP-4`.
2. Validate the map.

**Expected:** Validation fails with error code `ambiguous_alias`
identifying `payment-backend`.

## QA-SRM-10: unknown is not confirmed absence

1. Author use-case fact `UF-1` with resolution status `unknown`.
2. Author use-case fact `UF-2` with resolution status `absent`.
3. Validate each case and inspect the recorded statuses.

**Expected:** Both maps validate. `UF-1` is recorded as `unknown` and
not treated as `absent`. `UF-2` is recorded as `absent` and not treated
as `unknown`.

## QA-SRM-11: provenance distinguishes analyst from imported source facts

1. Author assertion `A-1` with provenance `analyst`.
2. Author assertion `A-2` with provenance `imported-source`.
3. Validate each case.

**Expected:** Both maps validate. `A-1` is recorded as `analyst` and
not as `imported-source`. `A-2` is recorded as `imported-source` and
not as `analyst`.

## QA-SRM-12: missing optional provenance is a warning

1. Author otherwise-valid assertion `A-3` with provenance omitted.
2. Validate the map.

**Expected:** Validation succeeds with 0 errors. The result contains
warning code `missing_optional_provenance` identifying `A-3`.

## QA-SRM-13: validation infers no correspondence

1. Place STPA identifier `CA-1-1` and taxonomy identifier
   `ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` in the same valid map.
2. Include no analyst correspondence assertion.
3. Validate the map and inspect the result for inferred matches.

**Expected:** Validation succeeds. The result contains no
correspondence relations and records no lexical match for those
identifiers.
