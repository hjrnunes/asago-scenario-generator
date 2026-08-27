# End-to-end QA: correspondence proposal

Drive a deterministic file-to-file correspondence proposer: a valid
`SystemResourceMap` and source-artifact fixtures in, a published
`ProposalSet` YAML or JSON artifact out. That invocation is a
user-interface affordance; it is not `generate` or `stpa-run`, and it is
not required as a new public CLI subcommand. Inspect artifacts with
standard JSON/YAML readers, the console, and the filesystem. Do not
import project modules, call `propose_correspondence`, or contact an LLM
endpoint. Never set `ASAGO_SCENARIO_GENERATOR_QA_PIPELINE`.

Use a fresh output directory for every case. The resource map pins STPA
and taxonomy source versions and supplies the identifiers proposals may
reference. A proposal is editable review data; it is not a confirmed
relation.

## QA-CP-01: exact-id and curated-map evidence stay unconfirmed

1. Author a valid resource map that includes STPA identifiers `CA-1-1`
   and `L-1`, plus taxonomy identifiers
   `ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` and `AP-T6-01`.
2. Author source artifacts with `exact-id` evidence linking `CA-1-1` to
   `ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`.
3. Author source artifacts with `curated-map` evidence linking `L-1` to
   `AP-T6-01`.
4. Produce the proposal-set artifact.
5. Inspect proposals `P-1` and `P-2` with a standard reader.

**Expected:** The set contains `P-1` with evidence source `exact-id`,
strength `high`, and relation type `supports`. The set contains `P-2`
with evidence source `curated-map`, strength `high`, and relation type
`addresses`. Neither proposal is confirmed. No network or model call is
recorded.

## QA-CP-02: weak resource overlap is distinct from high-strength evidence

1. Author source artifacts with `resource-overlap` evidence linking
   `CP-2` to `tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`.
2. Produce the proposal-set artifact.
3. Inspect proposal `P-3`.

**Expected:** `P-3` has evidence source `resource-overlap` and strength
`weak`. It is not classified as `exact-id` or `curated-map`. It is not
confirmed.

## QA-CP-03: typed proposal provenance is retained

1. Author proposer `exact-id-adapter` version `1` emitting a proposal
   for `CA-1-1` and `ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`.
2. Cite evidence references
   `CA-1-1,ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`.
3. Pin STPA version `stpa-v1` and taxonomy version `atlas-2026.05`.
4. Set rationale `exact identifier match`.
5. Produce the proposal-set artifact and inspect `P-1`.

**Expected:** `P-1` records left ref `CA-1-1`, right ref
`ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`, proposer `exact-id-adapter`
version `1`, those evidence references, STPA version `stpa-v1`, taxonomy
version `atlas-2026.05`, and rationale `exact identifier match`.

## QA-CP-04: heuristic and model-assisted adapters cannot confirm

1. Author proposer `heuristic-adapter` of kind `heuristic`.
2. Produce proposals and inspect every proposal from that proposer.
3. Repeat with proposer `model-assisted-adapter` of kind
   `model-assisted`.

**Expected:** Every proposal from `heuristic-adapter` has evidence
source `heuristic`. Every proposal from `model-assisted-adapter` has
evidence source `model-assisted`. Neither adapter writes a confirmed
relation. No LLM response auto-confirms a relation.

## QA-CP-05: proposal records zero network and model calls

1. Use any valid resource map and source artifacts that produce
   high-strength and weak proposals.
2. Produce the proposal set while capturing call logs, endpoint logs,
   and environment.
3. Confirm `ASAGO_SCENARIO_GENERATOR_QA_PIPELINE` is unset.

**Expected:** Proposal generation recorded 0 network calls and 0 model
calls. No LLM endpoint is contacted.
