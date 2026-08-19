# End-to-end QA: taxonomy attack-tree transport normalization

Drive only `uv run asago-scenario-generator generate` with a deterministic
local OpenAI-compatible fixture endpoint. Use complete reviewed architecture
and qualification inputs so projection is ready. Inspect CLI output, fixture
request counts, and published scenario YAML; do not import project modules.

## QA-TATT-01: Gemma-shaped omission is normalized

1. Configure the attack-tree response with valid leaves and valid
   `projected_step_ids`, but omit every `realizations` field.
2. Run `generate` with otherwise valid responses.
3. Inspect fixture request counts and the admitted scenario YAML.

**Expected:** The attack-tree stage is called once. The admitted tree contains
exactly one realization for every projected step ID on every mapped leaf, and
the realization values match the scenario's immutable projection block.

## QA-TATT-02: transport semantics cannot override projection

1. Return a tree that maps a leaf to `step.1` but supplies realization fields
   that conflict with the projection block.
2. Run `generate` and inspect the admitted scenario YAML.

**Expected:** The published realization for `step.1` is canonical and matches
the projection block; no conflicting model-supplied semantic value survives.

## QA-TATT-03: unknown projected identity is rejected

1. Return a tree whose security leaf references `step.unknown`.
2. Return the same defect for all bounded attack-tree retries.
3. Run `generate` and inspect stderr, request counts, the manifest, and
   quarantine evidence.

**Expected:** The attack-tree stage uses only its bounded retry allowance.
No scenario containing `step.unknown` is admitted. The evidence identifies
the unrecognized projected step, and the default degraded outcome exits
nonzero.

## QA-TATT-04: finalized strict contract remains closed

1. For each of missing, extra, duplicate, and projection-inconsistent
   realizations, provide a hash-consistent QA run directory whose finalized
   scenario YAML contains that defect.
2. Run `uv run asago-scenario-generator eval --output-dir <qa-run-dir>
   --allow-non-authoritative`.

**Expected for every fixture:** The public CLI exits nonzero because strict
scenario loading rejects the finalized tree and identifies the realization
defect.
