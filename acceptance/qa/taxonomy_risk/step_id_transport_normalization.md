# End-to-end QA: taxonomy step-ID transport normalization

Drive only `uv run asago-scenario-generator generate` with a deterministic
local OpenAI-compatible fixture endpoint. Use semantic canonical IDs including
`step.1`, `attacker.prepare`, and `system.transform`. Inspect recorded
requests, CLI diagnostics, manifests, quarantine evidence, and published
scenario YAML; do not import project modules.

## QA-TSIT-01: accepted echo shapes become canonical IDs

Across narrative and attack-tree responses, exercise exact strings, objects
shaped as `{"step_id": "<id>"}`, strings shaped as `step_id: <id>`, and
`step.<id>` strings. Include a mixed ordered list and the canonical ID
`step.1`.

**Expected:** The admitted artifacts contain only canonical string IDs in the
original order. `step.attacker.prepare` becomes `attacker.prepare`, while the
already-canonical `step.1` remains `step.1`. Canonical realizations match the
normalized IDs.

## QA-TSIT-02: duplicate canonical identities are rejected

Return `attacker.prepare` twice using two different accepted echo shapes for
all bounded attempts.

**Expected:** The run exits nonzero, publishes no defective artifact, and its
stable diagnostic identifies duplicate canonical ID `attacker.prepare`.
No diagnostic is a `TypeError`.

## QA-TSIT-03: unknown and ambiguous shapes fail predictably

Repeat bounded failing runs with an unknown exact ID, an unknown `step.`
suffix, nested prefixes, a non-string `step_id` value, an object with an
unknown key, a nested list, and a scalar number.

**Expected:** Every defect produces a stable `ValueError` diagnostic that
distinguishes unknown identity from unsupported or ambiguous shape. No run
leaks `TypeError`, and no defective scenario is published.

## QA-TSIT-04: prompts request plain canonical values

Inspect the recorded narrative and attack-tree user prompts.

**Expected:** Each prompt renders selected IDs as one plain quoted list in
canonical order and instructs the model to echo those exact values in
`projected_step_ids`. The list does not render records prefixed by
`- step_id:`.
