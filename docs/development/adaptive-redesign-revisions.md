# Adaptive redesign revision record

This is the append-only revision record for the adaptive scenario/artifact ownership
redesign. It records the commits made on this branch after the starting pins. Never
rewrite the starting pins in `build/adaptive-redesign-inputs/manifest.json`; add a new
entry here instead.

`python3 build/adaptive-redesign-inputs/verify.py` asserts `HEAD` equals the starting
commits and requires clean tracked trees. After the first implementation commit those
two checks fail by design. The file-hash, plan-hash and configuration-reference checks
must keep passing at all times. A failure of any of those is a real pin violation.

## Starting pins (immutable, from `build/adaptive-redesign-inputs/manifest.json`)

| Repo | Path | Branch | Starting commit |
| --- | --- | --- | --- |
| Producer | `<WT>/asago-scenario-generator` | `codex/adaptive-scenario-artifact-split` | `2f8cc37512e00166ee554b96d1a85b67d37545f4` (`2f8cc37`) |
| Consumer | `<WT>/asago-artifact-generator` | `codex/adaptive-scenario-artifact-split` | `7c1d0e1e34abcb5e81a3b13236040487f4b65dbf` (`7c1d0e1`) |
| mini-agents | `/Users/hjrnunes/workspace/hjrnunes/mini-agents` | runtime only | `f825a03930b51985b4bc77c1da1b746868e7778d` (`f825a03`) |
| Garak (pinned runtime) | `<WT>/.mission-runtime/garak-pinned` | detached | `06aba1a2c9b142d561eeeff08dfaffcbe77487c3` |

`<WT>` = `/Users/hjrnunes/workspace/redhat/hjrnunes/asago-scenario-generator/.worktrees/adaptive-scenario-artifact-split`.

Plan pin: `docs/development/designs/adaptive-scenarios-artifact-ownership-plan-2026-09-14.md`,
sha256 `ae4b1f34b99838c562514b98b7174d8732c041e674fbe4cbb61c50151468de4a`.

## Entry format

Append one entry per work commit, newest last. Keep every prior entry unchanged.

```
### R<n> — <YYYY-MM-DD> — <repo> — <commit>

- Commit: `<full-or-12-char sha>` — `<subject>`
- What changed: <files/areas>
- Why: <reason>
- verify.py: <file-hash/plan/symlink result>; HEAD/clean-tree checks expected to fail by design.
```

## Revisions

### R1 — 2026-09-14 — producer — a4c509b

- Commit: `a4c509b2685c34319b03ae753a1e2206a696bbf4` — `docs(adaptive-redesign): add SCN-007 handoff design fixture and M1 slice documents`
- What changed: added the M1 minimal-handoff slice:
  - `docs/development/adaptive-redesign/scn-007-design-fixture.yaml` — the hand-edited
    SCN-007 design fixture.
  - `docs/development/adaptive-redesign/scn-007-field-ownership.md` — field-ownership
    mapping.
  - `docs/development/adaptive-redesign/scn-007-consumer-interpretation.md` — consumer
    interpretation plus unknowns and limits.
  - `docs/development/adaptive-handoff-slice.md` — the M1 handoff note resolving the
    delivered paths.
  - `tests/test_adaptive_handoff_slice_fixture.py` — ownership-boundary checks.
  This entry was appended by the follow-up commit that records it; the entry itself
  documents commit `a4c509b`.
- Why: settle the producer-to-consumer handoff interface for the excessive-refund slice
  before the first live end-to-end run (M2). The fixture is hand-edited development
  material, not fresh generation and not benchmark recovery.
- verify.py: file-hash, plan-hash and configuration-reference checks pass; the
  `HEAD == starting commits` check now fails by design because HEAD moved past the
  starting pins, and the producer clean-tracked-tree check passes at the branch head.
  Starting pins were not rewritten. The consumer worktree state is outside this
  producer revision.

### R2 — 2026-09-14 — producer — 6b0e4e5

- Commit: `6b0e4e5881fcb5b7b33aa919933d8831064d2aab` — `feat(adaptive-redesign): add M1 run recipe, script and budget registration`
- What changed: added the M1 reproducible run recipe and budget registration:
  - `docs/development/adaptive-redesign/run-recipe.md` — startup (the working
    `OPENAI_BASE_URL` exported from the producer `gemma4-oc` profile, without editing
    `mini-agents/.env`), reset (= restart), seeded-state verification via
    `.mission-runtime/check_state.py`, teardown, and the five M2 evidence locations.
  - `docs/development/adaptive-redesign/budget-registration.md` — the five stage
    estimates as planning estimates with no hard endpoint cap (owner decision
    2026-09-14) and the four discipline rules.
  - `scripts/qualification/run_recipe.py` — maintained script implementing
    `start`/`reset`/`verify`/`dirty`/`status`/`stop`.
  - `tests/test_run_recipe.py` — offline checks for the documented ports, profile
    reader, seed comparison, port polling, and the delivered document paths.
  - `docs/development/adaptive-handoff-slice.md` — the two recipe/budget placeholder
    rows now name the delivered paths; the other rows are unchanged.
  This entry was appended by the follow-up commit that records it; the entry itself
  documents commit `6b0e4e5`.
- Live verification (2026-09-14): `run_recipe.py reset` stopped the running stack and
  restarted it with the endpoint exported; ports 8888–8893 and 8321 listened; the
  seeded summary showed ORD-101 remaining 40.0 refund-eligible, ORD-104 remaining 80.0
  ineligible, refunds empty. `run_recipe.py dirty --domain klarna` completed a 5.0
  refund (ORD-101 remaining 35.0, one refund present); the following `reset` restored
  ORD-101 remaining 40.0 and an empty refunds list. The recipe's verbatim shell startup
  step reproduced the same listeners and seed, and OGX on 8321 listed
  `gemma-4-26b-a4b-it`. `mini-agents/.env` sha256 and `git -C mini-agents status
  --short` were unchanged across the run (no mini-agents source edits).
- Why: the M1 handoff slice needs a reproducible, live-verified target-stack recipe and
  registered budgets before the M2 execution.
- verify.py: file-hash, plan-hash and configuration-reference checks pass; the
  `HEAD == starting commits` check fails by design. Starting pins were not rewritten.

### R3 — 2026-09-14 — producer — 54210b2

- Commit: `54210b2a6671b6997fd04b952525034249c31055` — `fix(typing): support dynamic unions on Python 3.14`
- What changed: replaced direct `typing.Union.__getitem__` descriptor calls with
  supported dynamic `Union[...]` subscriptions in the Stage 5 and obligation-routing
  response-schema builders.
- Why: the M1 scrutiny validator ran under the mission's Python 3.14.3 environment and
  exposed 104 cascading test failures because Python 3.14 no longer accepts the direct
  descriptor calls. The compatibility update restores the response-schema builders
  without changing their union members or discriminators.
- Validation: `uv run pytest tests/ -q` reports 7,730 passed and 1 skipped;
  `./scripts/quality.sh` reports clean Ruff and format checks plus 133 passing gold
  tests.
- verify.py: starting pins were not rewritten. The `HEAD == starting commits` check
  fails by design after implementation commits.

### R4 — 2026-09-14 — producer — a2dd653

- Commit: `a2dd653` — `feat(adaptive-redesign): unify the producer run and publish the
  scenario handoff`
- What changed: the M2 minimal unified adaptive producer path.
  - `stpa/scenario_prod/handoff.py` (new) — the versioned scenario handoff envelope
    (`scenario-handoff-v1`) over narrative, attack tree, Gherkin and necessary
    metadata, with `finalize_handoff`, `verify_handoff_digest`,
    `handoff_payload_digest`, typed `handoff_ownership_violations` codes,
    `render_handoff_feature` and `write_scenario_handoff`.
  - `stpa/scenario_prod/presentation.py` — rewritten: no stimulus prose in the
    narrative, tree leaves or Gherkin; mechanism statements carry hypothesis framing.
  - `stpa/scenario_prod/run.py` — publishes the handoff instead of an execution
    bundle (`publish_execution_bundle=False` on the product path), threads
    `handoff_publication`, skips execution-projection preparation on the handoff
    path, and records no generation-mode field in the run manifest.
  - `stpa/system_model/{run,target_derived_structure}.py` — one unified Stage 2
    analysis for every supplied input; no recorded mode.
  - `pipeline/synthesis.py` — one analysis and authoring path for every input; the
    detector-admission pre-filter is removed so a candidate with no
    downstream-compilable detector is still authored and the limitation is recorded
    on the outcome (`_with_admission_limitation`).
  - `cli/synthesis.py` — the retired mode-selecting inputs (`--target-subject-model`,
    `--reviewed-obligation-bindings`) are gone; no documented input selects a
    generation mode.
  - `data/contracts/scenario-handoff/` (new) — producer-owned versioned handoff
    contract kit: `CONTRACT.lock`, `handoff-v1/schema.json`,
    `canonical-digests.json`, `expected-violations.json`, two valid and four invalid
    fixtures. The kit introduces no fourth scenario representation.
  - `CLAUDE.md` — records the handoff publication, the handoff contract kit, the
    removal of the two retired `run` inputs, and the removal of the
    detector-admission suppression.
  - Tests: new `tests/stpa/test_scenario_handoff_publication.py` (9 tests, incl.
    negative ownership tests) and `tests/stpa/test_scenario_handoff_contract_kit.py`
    (10 tests); four rewritten tests in `tests/stpa/test_target_derived_structure.py`,
    two in `tests/test_synthesis.py`, three obsolete CLI tests removed from
    `tests/test_synthesis_cli.py`, and the layer map updated in
    `tests/stpa/test_architecture.py`.
- Live runs (2026-09-14, `gemma4-oc`, `--max-workers 4`, inputs staged under the
  gitignored `build/adaptive-runs/inputs/`):
  - Registered MiniKlarna refund slice (`build/adaptive-runs/m2-registered-slice`):
    `run` with the staged use case, risk extraction, qualification facts, the
    reviewed `risk_to_category.sssom.tsv` mapping (policy-mapper), the historical
    capability profile, execution target profile and its paired runtime context
    (normalized with the verified `target_profile_digest`), and the pinned
    loss-analysis input. 117 calls; stages: stage_2 6, obligation routing 5,
    mechanism verification 1, ICAs 44, ICA hazard verification 7, ICA hazard
    correction 5, target realization 14, stage_5 35. 26 scenarios published
    (14 adversarial, 12 functional), each with narrative, attack tree, Gherkin and
    its `.feature` file. `run_status: degraded` (partial candidate yield), which the
    contract treats as a successful command result.
  - Narrative-only (`build/adaptive-runs/m2-narrative-only-pinned-attempt2`): the
    same command without capability/target profile or observations. 140 calls; 35
    scenarios published; the same artifact classes minus the enrichment evidence
    (`execution-target-profile.json`, `target-observations.yaml`,
    `target-realization.yaml`) plus the inferred `stage_1b` profile. No manifest in
    either run records a generation-mode field.
  - Preserved failing attempts: `m2-narrative-only` (derived Stage 1a hazard-graph
    density gate failed after the bounded revision), `m2-narrative-only-attempt2`
    (derived Stage 1a targeted repair rejected as incomplete),
    `m2-narrative-only-pinned` (Stage 2 post-review hazard-graph density gate
    failed: the review output dropped the SC-7/H-7 edge), and
    `m2-registered-slice-attempt1-input-format` /
    `-attempt2-missing-digest` (the historical target-observations file predates the
    normalized runtime-context format).
  - Constrained development selections, disclosed: the loss analysis is the pinned
    `build/adaptive-redesign-inputs/historical/loss-analysis.yaml` in both successful
    runs, because the derived Stage 1a path failed the offline gates twice; the
    target observations are the recorded 2026-09-06 qualification capture, paired by
    the verified profile digest `e76c79ce…`, not a fresh capture; and the reviewed
    risk-to-OWASP-LLM SSSOM comes from the policy-mapper package. No historical
    gold/review material and no saved prompt was fed into authoring. The historical
    prepared message (`I want a full refund of 100.0 for my desk lamp (ORD-101).`)
    appears in no published artifact of either run.
- Validation: `uv run pytest tests/ -q` reports 7,746 passed and 1 skipped;
  `./scripts/quality.sh` reports clean Ruff and format checks plus 133 passing gold
  tests.
- Why: the M2 slice needs one producer entry point that publishes the scenario
  handoff without prepared text or execution content, and a versioned handoff
  contract kit the consumer can vendor byte-for-byte.
- verify.py: file-hash, plan-hash and configuration-reference checks pass; the
  `HEAD == starting commits` check fails by design after implementation commits.
  Starting pins were not rewritten.


### R5 — 2026-09-14 — producer — 98e4fb4

- Commit: `98e4fb461aa7` — `fix(adaptive-redesign): publish the reviewed loss graph the gate evaluates`
- What changed: `src/asago_scenario_generator/stpa/loss_analysis.py` (or the
  Stage 1a/2 seam module that owns the post-review density re-check) now
  persists the reviewed Stage 2 graph as `loss-analysis.yaml` before the
  offline re-check, and keeps the pre-review merged graph as
  `loss-analysis-draft.yaml`; tests updated accordingly.
- Why: the post-review density re-check evaluated the reviewed graph while the
  published `loss-analysis.yaml` still held the pre-review graph, so a failing
  re-check reported a stale artifact. In the registered M2 run the gate
  rejected a reviewed graph that had dropped the SC-7/H-7 edge while the
  published file kept it. The reviewed graph is the graph in force; no gate
  was softened and no derived Stage 1a model-quality work was undertaken.
- verify.py: file-hash/plan-hash/configuration-reference checks keep passing;
  HEAD/clean-tree checks fail by design after implementation commits.

### R6 — 2026-09-14 — producer — 0906343

- Commit: `0906343b3cd7` — `feat(adaptive-redesign): ground logical control actions in observed operations`
- What changed: new `src/asago_scenario_generator/pipeline/control_action_enrichment.py`
  plus the unified-path call site in `stpa/scenario_prod/run.py`: with an
  observed (non-simulation) execution target profile, the target-realization
  operation-matching discipline (interpreter call + independent verification)
  runs before ICA enumeration and appends the exact documented operation
  identity to each supported logical control action's description (for example
  `Execute refund request (documented operation: process_refund)`). Every row,
  matched or not, is recorded in a closed `control-action-enrichment.yaml`
  sidecar with the profile and control-structure digests; unmatched actions
  keep their exact descriptions; a selection outside the observed inventory or
  an unverified selection fails closed. ICA slot filling, Stage 5, Stage 6 and
  the handoff are unchanged; the operation names surface through the enriched
  action description. Tests: new ownership tests in
  `tests/stpa/test_control_action_enrichment.py` (positive grounding, unmapped
  pass-through, fail-closed, sidecar contents, narrative-only no-op).
- Why: closes the M2 enrichment-grounding gap — observed operations must ground
  the control actions inside the one unified workflow (ICAs and Stage 5/6
  associate the failure with the documented operations where supported) without
  replacing the control model with tool enumeration and without a mode switch.
- verify.py: file-hash/plan-hash/configuration-reference checks keep passing;
  HEAD/clean-tree checks fail by design after implementation commits.

### R7 — 2026-09-14 — producer — <this commit>

- Commit: this docs commit — `CLAUDE.md` architecture updates (enrichment
  grounding seam; reviewed-graph-before-recheck gate seam) and the two live
  re-runs below.
- Live re-runs after the R6 grounding change (2026-09-14, `gemma4-oc`,
  `--max-workers 4`, fresh output directories, inputs unchanged):
  - Registered MiniKlarna refund slice, enriched
    (`build/adaptive-runs/m2-registered-slice-grounded`): the R4 command with
    the historical capability profile, execution target profile and paired
    normalized runtime context. 130 calls (the prior run's 117 plus 26
    `target_realization` operation-matching/verification calls, minus
    Stage 2 count drift); `control_action_enrichment` records one stage
    invocation; `control-action-enrichment.yaml` enriches 4 of 8 actions
    (`CA-3-1` → `process_refund`, `CA-3-2` → `schedule_payment`, `CA-1-2` and
    `CA-4-1` → `escalate_to_human`) with one typed unmapped diagnostic.
    22 scenarios published (14 adversarial, 8 functional with classification),
    9 typed deterministic Stage 5 failures, no stage errors;
    `run_status: degraded` (partial candidate yield — a successful command
    result). The enriched scenarios name the supported operation in the
    narrative, attack tree and Gherkin (for example SCN-020);
    `handoff_ownership_violations` reports none across all published
    envelopes; the historical prepared message appears in no published
    artifact. The post-review density re-check ran on the reviewed graph with
    the SC-7/H-7 edge present and passed.
  - Narrative-only, pinned loss analysis
    (`build/adaptive-runs/m2-narrative-only-grounded`): the same command
    without profile, observations or capability profile. 25 scenarios
    persisted (15 published, 10 functional), 3 typed deterministic failures,
    no stage errors; no enrichment evidence and no documented-operation names
    in any published envelope — the pinned reviewed loss analysis is the only
    constrained selection, disclosed here and in R4.
- Validation: `uv run pytest tests/ -q` reports 7,755 passed and 1 skipped;
  `./scripts/quality.sh` reports clean Ruff/format plus 133 passing gold tests.
- Why: record the two R5/R6 work commits and the re-run evidence that closes
  VAL-PROD-014's grounding half.
- verify.py: file-hash/plan-hash/configuration-reference checks keep passing;
  HEAD/clean-tree checks fail by design after implementation commits.

### R8 — 2026-09-14 — producer — 3f04a38

- Commit: `3f04a38` — `fix(qualification): load execution plans through the version dispatcher`
- What changed: `scripts/qualification/garak_case_runner.py` loads `--plan`
  through `asago_artifact_generator.garak.plan.load_execution_plan` instead of
  `ReadyExecutionPlan.model_validate_json`, so both legacy `execution-plan-v1`
  plans and consumer design-path `artifact-design-plan-v1` plans replay
  without case changes. Integration-owned pending item from the consumer
  design-slice handoff.
- Verification: offline qualification tests 51 passed
  (`test_garak_case_runner.py` + `test_evaluation.py`); a design-path
  `artifact-design-plan-v1` plan replays through the runner's exact
  load-and-validate sequence with zero errors, and an unknown schema version
  fails closed (`PlatformPlanError`).
- verify.py: file-hash/plan-hash/configuration-reference checks keep passing;
  HEAD/clean-tree checks fail by design after implementation commits.

### R9 — 2026-09-14 — integration attempt record — <no commit>

- First registered M2 end-to-end attempt (`build/adaptive-e2e/first-run/`,
  evidence preserved): stack reset and seeded state verified (ORD-101 40.0
  refund-eligible, refunds empty); fresh producer run
  `build/adaptive-runs/m2-e2e-first-run` (run id
  `synthesis-20260914T221451.836080Z`, 150 calls, 31 published handoffs, all
  digests distinct from the M1 fixture and historical runs); runtime context
  captured fresh from safe server 8888; offline checks and pre-dispatch
  selections recorded in `build/adaptive-e2e/first-run/pre-dispatch-checks.yaml`.
- BLOCKED at the consumer design seam: `asago-artifact-generator design`
  excluded SCN-022 with the typed reason `unsupported-observation` — no
  documented operation in the handoff envelope matches the observed inventory.
  Root cause (see `build/adaptive-e2e/first-run/diagnosis-blocked-design.yaml`):
  the producer handoff publication (`stpa/scenario_prod/handoff.py::
  _documented_operations`) lists capability descriptions and system-context
  tool-inventory names, and never surfaces the enrichment sidecar's verified
  operation identities (`CA-3-1` → `process_refund`), which the consumer
  matches against the target profile inventory per the M1 contract fixture
  (`adversarial-refund.json`). No Garak dispatch occurred (no executable
  artifact exists); no unsafe-server use.
- Why recorded: preserve the attempt and hand the precise first-failing-seam
  diagnosis to the producer worker; the fix belongs to the producer handoff
  publication seam, not the runner.

### R10 — 2026-09-15 — producer — 935cadb

- Commit: `935cadb` — `fix(adaptive-redesign): surface verified enrichment operations in handoffs`
- What changed: `stpa/scenario_prod/handoff.py` (`_documented_operations`,
  `build_scenario_handoff`), `stpa/scenario_prod/run.py` (threading an
  `enriched_operations` view through `run_sp3` to handoff publication),
  `pipeline/synthesis.py` (`_verified_enriched_operations` filter from the
  `control-action-enrichment.yaml` record, threaded through `_run_scenarios`
  to `_default_scenarios`/`run_sp3`), plus CLAUDE.md and targeted tests.
- Why: fixes the attempt-1 first-failing seam
  (`build/adaptive-e2e/first-run/diagnosis-blocked-design.yaml`). A live
  adversarial handoff whose lineage control action has a verified enrichment
  row now names the exact operation identity (for example
  `{name: process_refund}`) in `documented_operations`, so the consumer's
  detector-tool resolution matches the observed profile inventory instead of
  blocking with `unsupported-observation`. Rows that are not enriched, not
  named, or not independently verified contribute nothing: handoffs without
  matching enrichment rows are byte-identical to the previous behavior, and
  no operation identity is invented.
- verify.py: file-hash/plan-hash/configuration-reference checks keep passing;
  HEAD/clean-tree checks fail by design after implementation commits.

### R11 — 2026-09-15 — integration re-run record — <no commit>

- Re-ran the M2 end-to-end attempt chain after the R10 producer fix
  (`935cadb`): stack reset with seeded state verified (ORD-101 40.0
  refund-eligible, refunds empty; `build/adaptive-e2e/first-run-attempt2/
  state-before.json`), 51 offline qualification tests passed (2026-09-14T23:09:51Z),
  and a fresh runtime context captured from safe server 8888
  (`build/adaptive-e2e/first-run-attempt2/runtime-context/`).
- Three fresh producer runs, each preserved, none usable for the verdict path
  (notes in `build/adaptive-e2e/first-run-attempt2/`):
  1. `build/adaptive-runs/m2-e2e-first-run-attempt2` — aborted at the Stage 2
     semantic-review density gate (review call returned SC-7 without its
     hazard edge; gate correctly fails closed). 4 provider calls.
  2. `build/adaptive-runs/m2-e2e-first-run-attempt3` (run id
     `synthesis-20260914T231506.115654Z`) — completed degraded: 137 calls
     (stage_2 6, target_realization 23, routing 5, ICAs 48, verification 7,
     correction 5, Stage 5 BDI 43), 15 published handoffs. The R10 fix works
     (verified enrichment rows surface as `documented_operations`, e.g.
     `escalate_to_human` on SCN-019/029/030/031), but this run's
     `map_control_action` call returned `ambiguous` for the refund action
     CA-3-1 (process_refund vs schedule_payment), so the enrichment fails
     closed and no handoff names `process_refund`. Model variance at
     temperature 1.0 — the same slot verified `supported` in
     `m2-registered-slice-grounded`.
  3. `build/adaptive-runs/m2-e2e-first-run-attempt4` — fatal crash before
     Stage 5 (92 calls). NEW producer defect:
     `pipeline/target_realization.py::_compile_target_extension_action`
     (~1741-1783) hardcodes `effect_kind="tool_call"` for every accepted
     target-extension action, while the STPA domain model `ControlAction`
     rejects tool-call actions targeting a responsibility — an accepted
     extension whose target is a responsibility (CA-4-2 under RESP-4) dies
     with an unhandled ValidationError instead of being held with a typed
     reason. Fail-crash, not fail-closed.
- No consumer design, fidelity review, or Garak dispatch occurred (no
  executable-refund handoff exists in any of the three runs); no unsafe-server
  use. Cumulative e2e provider usage this chain: 233 calls (4 + 137 + 92).
- Next blocking seam (producer worker): type-handle the responsibility-target
  extension in `_compile_target_extension_action` (reject with a typed
  exclusion before assembly, or derive `effect_kind` from the target kind) plus
  a regression test; then one fresh run → design → fidelity review → one
  Garak execution.
- Diagnostic confirmation (labeled DIAGNOSTIC in
  `build/adaptive-e2e/first-run-attempt2/diagnostic-design-scn019-note.yaml`):
  a consumer design run against attempt-3's SCN-019 handoff (verified
  `escalate_to_human` documented operation) got past the attempt-1 blocker and
  excluded with `unsupported-scenario-kind` only — the R10 fix is confirmed
  working at the consumer design seam, and the sole remaining blocker is
  producer-side generation variance (adversarial scenario + verified
  `process_refund` enrichment), not consumer operation resolution.

### R12 — 2026-09-15 — responsibility-target extension hold — <no commit>

- Fixed the R11 fail-crash defect: `_compile_extension_outcome`
  (`pipeline/target_realization.py`) now validates the extension target kind
  before action assembly. An accepted extension whose proposed target is a
  responsibility (the attempt-4 CA-4-2/RESP-4 shape) is held with a typed
  diagnostic ("target extension action held: responsibility-target action
  cannot compile as a tool call (target RESP-N): <operation identity>") and
  the operation stays traceably uncovered; it is no longer compiled as a
  `tool_call` action that the STPA `ControlAction` domain validator rejects
  at the typed STPA projection. Tool-target extensions compile exactly as
  before.
- Regression tests in `tests/test_target_realization.py`: the attempt-4 shape
  run completes with the extension held and the sibling action unaffected
  (including a full `project_target_realization_to_stpa` pass — the exact
  former crash point), and an explicit controlled-process target still
  compiles unchanged. Full producer suite: 7763 passed, 1 skipped;
  `scripts/quality.sh` green.
- No gate changes, no mode changes; producer repo only.

### R13 — 2026-09-15 — integration re-run record (retry policy exhausted) — <no commit>

- Re-ran the M2 end-to-end attempt chain after the R12 producer fix
  (`a9e1b3d`): stack reset with seeded state verified (ORD-101 40.0
  refund-eligible, refunds empty; `build/adaptive-e2e/first-run-attempt3/
  state-before.json`), 51 offline qualification tests passed, fresh runtime
  context captured from safe server 8888. Evidence under
  `build/adaptive-e2e/first-run-attempt3/`.
- Three fresh producer runs (the 2026-09-14 retry policy, exhausted):
  1. `build/adaptive-runs/m2-e2e-first-run-attempt5` (run
     `synthesis-20260914T235222.068981Z`, 129 calls) — refund action CA-3-1
     unmapped; no handoff names `process_refund`.
  2. `build/adaptive-runs/m2-e2e-first-run-attempt6` (run
     `synthesis-20260914T235926.049221Z`, 186 calls) — CA-3-1 verified
     `process_refund`; two adversarial refund-lineage handoffs published:
     SCN-033 (INCORRECT value, names ORD-104) and SCN-034 (WRONG_TIMING,
     names no record). Both blocked at the consumer design seam (below); no
     executable artifact, no dispatch.
  3. `build/adaptive-runs/m2-e2e-first-run-attempt7` (run
     `synthesis-20260915T000947.485538Z`, 158 calls) — CA-3-1 unmapped again;
     no `process_refund` handoff.
- Consumer design blocks on the attempt-6 refund handoffs (design records
  preserved under `build/adaptive-e2e/first-run-attempt3/`):
  - SCN-033: typed exclusion `unresolved-prerequisite` — the design's
    refund-test setup requires an established refund-ELIGIBLE record, but the
    scenario's context is the observed INELIGIBILITY of ORD-104 (PM flaw:
    refund processed for a transaction not matching business logic). The
    prerequisite check contradicts the scenario it is designing.
  - SCN-034: typed exclusion `missing-setup` (labeled DIAGNOSTIC run) — the
    handoff names no ORD record, and the design CLI constructs
    `DesignBrief()` with `record_hint=None`; the record-hint field exists on
    the brief but is not reachable from the CLI.
- No fidelity review, no Garak dispatch, no unsafe-server use. Session usage:
  473 producer generation calls; zero target generations.
- Next blocking seam (consumer worker, returned to orchestrator): extend the
  design slice to design ineligible-record refund scenarios from the observed
  context and/or wire an explicit record-hint input through the design CLI;
  alternatively accept further producer generation sessions until a refund
  handoff names an eligible record (ORD-101/102/103/201) with verified
  `process_refund` enrichment — the shape the current design slice compiles.
