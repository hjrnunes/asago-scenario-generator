# End-to-end QA: taxonomy source-influence provenance

Drive only `uv run asago-scenario-generator generate` against a deterministic
local OpenAI-compatible fixture endpoint. Use fresh output collections and
reviewed profile, qualification, risk-extraction, SSSOM, and authoritative
pattern inputs. Inspect CLI output, fixture request logs, run manifests,
published scenario YAML, and qualification metadata; do not import project
modules or call a project API.

## QA-TSIP-01: complete source influence reaches admission

1. Configure an authoritative projected chain with an indirect
   `attacker.deliver` ingress and one source-influence execution requirement.
   Pin a threat source `threat:T12`, mitigation `mitigation:M12`, and
   capability constraint `constraint:KCX-MAGENT`.
2. Return deterministic narrative and attack-tree responses that realize the
   projected step as leaf `n1.1` and narrative step `1`.
3. Run `generate` and inspect the admitted scenario YAML.

**Expected:** The command exits `0`. The envelope contains a typed
source-influence provenance block. Both `n1.1` and narrative step `1` resolve
to the declared threat, mitigation, and capability-constraint IDs. The
qualification status is `pass`, and no orphan or unreferenced finding is
reported.

## QA-TSIP-02: complete qualification metrics are persisted

1. Configure two source-influence projected steps, two projected leaves, and
   two narrative steps. Declare two threat sources, two mitigations, and two
   capability constraints, with every artifact link complete.
2. Run `generate` with deterministic valid responses.
3. Inspect the scenario envelope metadata and run qualification output.

**Expected:** Leaf coverage is `2/2`, narrative-step coverage is `2/2`,
source-reference coverage is `6/6`, orphaned-source count is `0`, and
unreferenced-artifact count is `0`. The persisted qualification status is
`pass`.

## QA-TSIP-03: shared source records are deduplicated

1. Configure two projected leaves and two narrative steps to use the same
   threat source, mitigation, and capability constraint IDs.
2. Run `generate` and inspect serialized provenance metadata.

**Expected:** Each of the three declared source records is serialized once.
All four artifact elements resolve to those same typed records, and source
reference coverage is `3/3`. Shared references do not create duplicate source
records or lower qualification.

## QA-TSIP-04: incomplete or unknown links fail closed

For each run below, use otherwise valid deterministic inputs and inspect the
exit status, bounded retry/quarantine evidence, and published scenarios:

1. Omit the threat-source link from one artifact.
2. Omit the mitigation link from one artifact.
3. Omit the capability-constraint link from one artifact.
4. Refer to unknown source `mitigation:M99`.
5. Claim projected step `attacker.observe` from an artifact that realizes
   `attacker.deliver`.

**Expected:** Each run exits nonzero, reports the corresponding typed
   violation (`missing_source_provenance`, `unknown_source_reference`, or
   `provenance_projected_step_mismatch`), and publishes no admitted scenario
   envelope. A diagnostic identifies the missing or invalid source/artifact
   identity.

## QA-TSIP-05: orphaned and unreferenced provenance fails qualification

1. Declare `mitigation:M99` in the source-influence provenance universe but
   do not link it from any projected leaf or narrative step.
2. In a separate run, configure two projected steps but emit provenance links
   only for the `attacker.deliver` leaf and narrative step.
3. Run `generate` for both cases and inspect metadata, metrics, and manifests.

**Expected:** The first run reports `orphaned_source_provenance`, identifies
`mitigation:M99`, records orphaned-source count `1`, and admits no scenario.
The second reports `unreferenced_source_influence_artifact`, identifies
`attacker.observe`, records leaf and narrative coverage of `1/2`, and admits
no scenario. Neither run silently drops the missing provenance.

## QA-TSIP-06: serialized metadata is independently inspectable

1. Complete a valid source-influence run with one projected step and one
   narrative step.
2. Open the published scenario YAML without project imports.
3. Verify every provenance reference exposes an explicit source type and
   stable source ID, and verify the qualification metrics and status are
   present under envelope metadata.

**Expected:** The serialized document retains typed source, mitigation, and
capability-constraint references, projected-leaf and narrative-step links,
coverage numerators and denominators, orphan/unreferenced counts, and
qualification status `pass`.
