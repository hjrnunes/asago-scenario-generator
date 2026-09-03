# Session handoff: STPA-led taxonomy synthesis and Garak execution

Date: 2026-09-03
Primary repository: `/Users/hjrnunes/workspace/redhat/hjrnunes/asago-scenario-generator`
Consumer repository: `/Users/hjrnunes/workspace/redhat/hjrnunes/asago-artifact-generator`

## Resume here

The product direction is now:

1. Taxonomy creates systematic obligations.
2. STPA considers every applicable obligation but remains responsible for deciding whether the system supports an unsafe-control scenario.
3. STPA is the only normal scenario-generation workflow.
4. The scenario generator publishes typed execution projections and an atomic execution bundle.
5. The artifact generator verifies that bundle, binds target-independent or target-specific runtime details, evaluates readiness, and compiles supported cases into Garak executable-conversation artifacts.
6. Probe selection, campaign scheduling, and execution against targets remain outside the artifact generator.

The current cross-repository execution path works. A fresh Klarna run published 18 valid scenarios, and the artifact generator compiled 10 of them into validated Garak artifacts. The principal unresolved problem is earlier in Stage 5: 17 additional candidate scenarios were rejected, mostly because Gemma selected incompatible delivery-route and causal-factor combinations.

Do not address that by parsing control-action prose or adding keyword rules. The current `ControlAction` model does not contain enough structured information for deterministic action or delivery classification. The next design must establish typed execution-effect and attacker-entry facts earlier in the pipeline, with explicit authority and evidence.

## Repository and branch state

### Scenario generator

- Branch: `feature/stpa-synthesis`
- Current committed head: `4d1d7be` — `Classify and contextualize STPA execution routes`
- The working tree contains tested, uncommitted Garak-readiness corrections listed below.
- `output/`, `build/`, and most `ai/findings/` material are ignored.

Current intended uncommitted files:

```text
CLAUDE.md
README.md
acceptance/runtime_features/stpa_execution_route.py
docs/architecture/overview.md
features/stpa_execution_route_selection.feature
src/asago_scenario_generator/stpa/scenario_prod/bdi_generation.py
src/asago_scenario_generator/stpa/scenario_prod/prompts/stage5_context_system.j2
src/asago_scenario_generator/stpa/scenario_prod/prompts/stage5_context_user.j2
tests/stpa/test_sp3_scenario_continuity.py
```

The following current specifications are useful but ignored unless force-added:

```text
ai/findings/risk-to-pattern-crosswalk-correction-spec.md
ai/findings/stpa-scenario-atlas-technique-assessment-spec.md
ai/findings/stpa-garak-readiness-corrections-spec.md
ai/findings/session-handoff-stpa-taxonomy-garak-2026-09-03.md
```

### Artifact generator

- Branch: `feature/stpa-consumer`
- Current committed head: `9570a6f` — `Bind STPA scenarios into executable Garak cases`
- The working tree contains tested, uncommitted deterministic-default and Garak-readiness corrections.

Current intended uncommitted files:

```text
CLAUDE.md
README.md
docs/stpa-execution-consumer.md
src/asago_artifact_generator/cli.py
src/asago_artifact_generator/garak/__init__.py
src/asago_artifact_generator/garak/conversation.py
src/asago_artifact_generator/garak/default_bindings.py
src/asago_artifact_generator/planning/bind.py
tests/test_stpa_garak_platform.py
ai/findings/stpa-garak-readiness-corrections-spec.md
```

Unrelated local paths `.codex/` and `.coverage` must remain out of commits.

## What was completed

### Phases 1 and 2: taxonomy obligations and offline verification

Phase 1 was implemented as an observational obligation planner:

- Every reviewed risk remains accounted for.
- Qualified taxonomy patterns create typed obligation rows.
- Governance-only, excluded, applicable, deferred, and unresolved outcomes remain explicit.
- Candidate ingress, resources, qualification evidence, identities, and digests are closed and validated.
- The normative YAML artifact is written atomically.

Phase 2 was implemented as offline, observational verification:

- A typed system-resource map is validated against exact capability and control-structure identities.
- Correspondence proposals are separated from human adjudication.
- Only accepted, confirmed evidence can count as correspondence.
- Structural consideration, taxonomy correspondence, and scenario realization retain independent denominators.
- Product `run` invokes Phase 2 last and non-blockingly.
- Phase 2 makes no network or model calls.

Manual Klarna and NHS correspondence reviews were completed conversationally. The abandoned HTML review tool was removed. The retained review decisions are represented in:

```text
tests/fixtures/klarna-phase12-reviewed-adjudications.yaml
tests/fixtures/nhs-phase12-reviewed-adjudications.yaml
```

Relevant commits include:

```text
aaca0bc Implement typed taxonomy obligation planner
6be244a Implement typed observational Phase 2 synthesis
58f4ef8 Calibrate Phase 2 correspondence semantics
5ae7416 Correct obligation feasibility and correspondence evidence
```

The live Phase 1/2 assessment is in:

```text
ai/findings/phase12-live-run-klarna-nhs-2026-08-29.md
```

### Phases 3 and 4

Phase 3 added the deterministic challenge ledger, explicit single-attempt reconsideration, and closed-loop composition. It does not mutate Phase 2 evidence or silently turn challenges into coverage.

Phase 4 added:

- exact-authority hybrid projection resolution;
- pure taxonomy/STPA graph composition;
- DAG, bridge, trace, and source-pin closure;
- atomic YAML persistence;
- acceptance coverage and an offline pilot-readiness gate.

Relevant commits:

```text
baf195f Implement offline Phase 3 challenge ledger
0f79c33 Implement opt-in Phase 3 STPA analysis
3cc2904 Complete bounded Phase 3 STPA loop
f72cf6f Implement Phase 4 projection authority resolver
9fa9df4 Compose Phase 4 hybrid projection graph
5f6bf78 Persist Phase 4 hybrid projection sets
4d4c179 Complete Phase 4 acceptance and pilot gate
```

### Obligation-aware STPA synthesis

The normal product flow now runs taxonomy planning, obligation consideration, STPA, scenario generation, accounting, and Phase 2 verification together.

Important semantics:

- An obligation requires STPA consideration; it does not force an ICA or scenario.
- Provider prose cannot create structural authority.
- Every applicable obligation reaches a single terminal accounting reason.
- Risk/pattern mismatch and unsubstantiated mechanism paths do not receive coverage credit.
- Prompt inputs use closed views and Jinja templates rather than unstructured object dumps.
- Call evidence distinguishes response receipt, parsing, semantic validation, compilation, and publication.
- ICA category is compiler-owned; the provider supplies the deviation sentence.
- Stage 5 provider handles are local and explained; the compiler resolves them to canonical causal sources.

Relevant commits:

```text
f1ad502 Implement obligation-aware STPA synthesis
77c9f46 Tighten STPA synthesis prompt boundaries
45d530b Improve obligation-aware STPA semantics
e6078c6 Add automatic Phase 2 synthesis verification
```

### STPA-only product cutover

The legacy non-STPA product path was removed. The supported user-facing modes are:

- `run`: normal taxonomy-obligation plus STPA product workflow;
- `stpa-run`: advanced STPA-only diagnostic without obligation completeness.

Relevant commits:

```text
68036ed Make STPA synthesis the sole product workflow
7d1a027 Remove legacy non-STPA generation workflow
```

### Model profiles and prompt quality

- Qwen's `enable_thinking: false` is passed through as `chat_template_kwargs.enable_thinking=false`.
- Guided JSON uses `response_format: {type: json_schema, ...}` rather than ignored `guided_json` forms.
- Gemma compatibility is preserved.
- Both Klarna and NHS were exercised during the profile comparison work.
- ICA prose and prompt-context contracts were tightened, but live output remains more verbose than desired.

Relevant commits:

```text
02515bb Support Qwen no-thinking structured requests
43b4fea Specify STPA synthesis semantic quality improvements
a2cd447 Distinguish baseline from live quality results
```

### Risk-to-pattern and scenario-to-technique work

Two distinct mappings were separated:

1. Reviewed risk to taxonomy attack pattern: an upstream obligation-planning concern.
2. Generated STPA scenario to an existing taxonomy technique: a post-generation assessment concern.

The risk-to-pattern audit found substantial crosswalk inflation in the saved Klarna/NHS artifacts. Broad or related taxonomy paths were being treated too generously. The correction is specified but not implemented:

```text
ai/findings/risk-to-pattern-crosswalk-correction-spec.md
```

The post-generation scenario-to-technique assessment is also specified separately:

```text
ai/findings/stpa-scenario-atlas-technique-assessment-spec.md
```

Do not preselect a technique and force STPA to generate around it. Obligations may introduce a mechanism hypothesis, but the produced scenario must be assessed from its actual causal and execution content.

### Scenario-generator to artifact-generator contract

The scenario generator now publishes:

- closed `stpa-execution-projection-v2` documents;
- typed semantic conditions and placeholders;
- exact run/scenario/candidate/ICA/controller/action identities;
- exact source pins and byte hashes;
- execution requirements and classification;
- an atomic `stpa-execution-bundle-v1` index, replaced last;
- immutable content-addressed generations on bundle updates.

Producer-side commits:

```text
40249d3 Publish typed STPA execution bundles
8b54bc9 Add adversarial stimulus execution contracts
4d1d7be Classify and contextualize STPA execution routes
```

The artifact generator now:

- vendors the producer-owned contract kit byte-for-byte;
- verifies bundle, projection, scenario, identity, digest, and pairing integrity;
- converts projections to typed execution intents;
- resolves concrete, parameterized, simulated, analytical, or excluded cases;
- checks semantic, runtime, and platform readiness independently;
- supports direct prompt, indirect content/tool-result, and multi-turn conversation artifacts;
- keeps presentation-only model authoring behind deterministic planning;
- writes plan, validation, trace, receipt, and manifest sidecars.

Consumer-side commits:

```text
139a356 Consume typed STPA execution bundles
33b29c9 Compile STPA scenarios as executable conversations
9570a6f Bind STPA scenarios into executable Garak cases
```

The producer contract kit is pinned by the artifact generator's `contracts/stpa-execution/UPSTREAM.lock`.

### Garak scope decision

The artifact generator owns deterministic compilation, not campaign orchestration.

Supported artifact intents include:

- direct single-turn prompt attacks;
- indirect attacker-controlled content delivered through a tool result or similar carrier;
- multi-turn conversation context;
- exact target-profile tool operations when supplied.

Garak built-in probe selection, campaign composition, scheduling, target invocation, and result aggregation belong in a later orchestration component. That component should select probes from typed attack/delivery requirements and feed compiled custom conversations to a compatible Garak runner, including the functionality discussed in `trustyai-explainability/garak#11`.

### Current uncommitted readiness corrections

The scenario-generator working tree currently adds:

- route/factor compatibility checks;
- a literal semantic proposition requirement for model-output `action_value` outcomes;
- Stage 5 prompt guidance describing valid route/factor pairs;
- acceptance and unit coverage for the rules.

The artifact-generator working tree currently adds:

- deterministic default runtime bindings for routine direct and conversation cases;
- exact target-profile tool binding when a matching profile is supplied;
- provenance-only causal factors that do not require writable surfaces;
- model-output chat actions and semantic output observers;
- semantic-property judges instead of vague exact-response matching;
- CLI use of defaults before readiness evaluation.

These changes are tested but not committed.

## Verification completed

### Scenario generator current working tree

```text
Full unit suite: 6,496 passed, 1 skipped
Generated acceptance: 128 passed
Final focused execution-route suite: 53 passed
scripts/quality.sh: passed
git diff --check: passed
```

The latest changed functions were checked for CRAP and were at or below 5. Whole-module CRAP output still reports older untouched functions when focused coverage is used. Source mutation testing for this final readiness slice was deliberately deferred to preserve iteration speed.

### Artifact generator current working tree

```text
Full unit suite: 248 passed, 2 subtests passed
Final focused suite: 106 passed
scripts/quality.sh: passed
git diff --check: passed
```

Changed/new functions are at or below CRAP 6. Whole-module output can still include untouched legacy functions above the threshold. Source mutation testing for this final readiness slice was deliberately deferred.

## Exact full-run instructions

The commands below reproduce the current Klarna flow. They deliberately use absolute paths so the scenario and artifact repositories cannot be confused.

### 1. Prepare the scenario generator

```bash
cd /Users/hjrnunes/workspace/redhat/hjrnunes/asago-scenario-generator
uv sync --locked
```

`config/model-profiles.yaml` is local and ignored. It must contain a `gemma4-oc` profile pointing to the live OpenAI-compatible endpoint. Do not place credentials in committed configuration. The current OC deployment accepts the placeholder API key configured by the local profile.

### 2. Run Klarna through taxonomy obligations and STPA

Choose a new output directory; `run` will not use the previous live run as a hidden source.

```bash
cd /Users/hjrnunes/workspace/redhat/hjrnunes/asago-scenario-generator

ASAGO_KLARNA_RUN_DIR=/Users/hjrnunes/workspace/redhat/hjrnunes/asago-scenario-generator/output/runs/20260903-klarna-gemma4-oc-next

UV_CACHE_DIR=/tmp/asago-uv-cache \
uv run asago-scenario-generator run \
  --use-case @tmp/use-case-klarna-fs-isac-v36.txt \
  --risk-extraction tmp/risk-extraction-fs-isac.json \
  --qualification-facts tmp/migration-validation/klarna-qualification-facts.yaml \
  --sssom ../asago-policy-mapper/src/asago_policy_mapper/data/risk_to_category.sssom.tsv \
  --output-dir "$ASAGO_KLARNA_RUN_DIR" \
  --sp1-profile gemma4-oc \
  --sp2-profile gemma4-oc \
  --sp3-profile gemma4-oc \
  --max-workers 4
```

The command publishes these primary artifacts:

```text
$ASAGO_KLARNA_RUN_DIR/taxonomy-obligation-plan.yaml
$ASAGO_KLARNA_RUN_DIR/obligation-consideration.yaml
$ASAGO_KLARNA_RUN_DIR/obligation-accounting.yaml
$ASAGO_KLARNA_RUN_DIR/scenario-realization.yaml
$ASAGO_KLARNA_RUN_DIR/scenarios/
$ASAGO_KLARNA_RUN_DIR/execution-bundle.json
$ASAGO_KLARNA_RUN_DIR/synthesis-manifest.yaml
$ASAGO_KLARNA_RUN_DIR/synthesis-report.html
$ASAGO_KLARNA_RUN_DIR/system-resource-map.yaml
$ASAGO_KLARNA_RUN_DIR/correspondence-proposals.yaml
$ASAGO_KLARNA_RUN_DIR/correspondence-reconciliation.yaml
$ASAGO_KLARNA_RUN_DIR/hybrid-coverage-assessment.yaml
```

Phase 2 reporting `awaiting_evidence` is not a scenario-generation failure. It means no human-confirmed correspondence was supplied for that fresh run.

### 3. Run artifact readiness without model calls

This verifies the bundle, resolves each execution case, applies deterministic defaults, and reports blockers. It performs no presentation authoring and compiles no artifact.

```bash
cd /Users/hjrnunes/workspace/redhat/hjrnunes/asago-artifact-generator
uv sync --locked

ASAGO_KLARNA_RUN_DIR=/Users/hjrnunes/workspace/redhat/hjrnunes/asago-scenario-generator/output/runs/20260903-klarna-gemma4-oc-next
ASAGO_READINESS_DIR="$ASAGO_KLARNA_RUN_DIR/artifact-readiness-auto"

PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=src \
.venv/bin/python -m asago_artifact_generator.cli generate \
  --bundle "$ASAGO_KLARNA_RUN_DIR/execution-bundle.json" \
  --platform garak \
  --readiness-only \
  --output-dir "$ASAGO_READINESS_DIR"
```

Read the emitted path from the command output. The key file is:

```text
$ASAGO_READINESS_DIR/<run-id>/artifact-manifest.json
```

Interpretation:

- `ready`: deterministic structure and runtime bindings are complete; presentation text can be authored and compiled.
- `needs_semantic_binding`: a deployment- or policy-specific semantic value is missing.
- `needs_runtime_binding`: a surface, operation, observer, channel, or clock is missing.
- `unsupported`: Garak cannot realize a required behavior.
- `execution_case_excluded`: the scenario is valid but cannot claim executable readiness under the supplied environment evidence.
- `analytical_only`: useful analysis exists but no executable route was claimed.

### 4. Compile every ready case with Gemma-OC presentation authoring

The artifact generator currently uses its generic OpenAI-compatible client rather than the scenario generator's named profile file. Configure the same OC endpoint explicitly:

```bash
cd /Users/hjrnunes/workspace/redhat/hjrnunes/asago-artifact-generator

ASAGO_KLARNA_RUN_DIR=/Users/hjrnunes/workspace/redhat/hjrnunes/asago-scenario-generator/output/runs/20260903-klarna-gemma4-oc-next
ASAGO_GARAK_ARTIFACT_DIR="$ASAGO_KLARNA_RUN_DIR/artifacts-garak-gemma4-oc"

PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=src \
REDTEAM_PROVIDER=openai \
OPENAI_BASE_URL=https://gemma-4-26b-a4b-it-model-serving.apps.rosa.u7s1k8g5z8a0s2l.c3qf.p3.openshiftapps.com/v1 \
OPENAI_API_KEY=unused \
REDTEAM_MODEL=gemma-4-26b-a4b-it \
.venv/bin/python -m asago_artifact_generator.cli generate \
  --bundle "$ASAGO_KLARNA_RUN_DIR/execution-bundle.json" \
  --platform garak \
  --output-dir "$ASAGO_GARAK_ARTIFACT_DIR"
```

For each ready scenario, expect:

```text
bound-execution-case.json
execution-plan.json
executable-conversation.json
validation.json
artifact-trace.json
readiness.json
```

The aggregate result is:

```text
$ASAGO_GARAK_ARTIFACT_DIR/<run-id>/artifact-manifest.json
```

Do not use `--no-llm` for the current live bundle unless the conversation text slots have been explicitly pre-bound. `--no-llm` correctly refuses to invent the concrete adversarial prompt.

### 5. Run one exact scenario only

Use the exact published scenario ID:

```bash
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=src \
REDTEAM_PROVIDER=openai \
OPENAI_BASE_URL=https://gemma-4-26b-a4b-it-model-serving.apps.rosa.u7s1k8g5z8a0s2l.c3qf.p3.openshiftapps.com/v1 \
OPENAI_API_KEY=unused \
REDTEAM_MODEL=gemma-4-26b-a4b-it \
.venv/bin/python -m asago_artifact_generator.cli generate \
  --bundle "$ASAGO_KLARNA_RUN_DIR/execution-bundle.json" \
  --entry SCN-001 \
  --platform garak \
  --output-dir "$ASAGO_GARAK_ARTIFACT_DIR"
```

### 6. Include target-dependent tool-call cases

The same reviewed target profile must be supplied to both repositories. The scenario generator uses it for classification and source pinning; the artifact generator uses it for exact operation and surface binding.

```bash
ASAGO_TARGET_PROFILE=/absolute/path/to/klarna-execution-target-profile.yaml
```

Scenario-generator additions:

```text
--target-profile "$ASAGO_TARGET_PROFILE"
--basis target_profile
```

Artifact-generator addition:

```text
--target-profile "$ASAGO_TARGET_PROFILE"
```

The profile must contain its verified `semantic_digest` and conform to:

```text
/Users/hjrnunes/workspace/redhat/hjrnunes/asago-scenario-generator/data/contracts/stpa-execution/target-profile-v1/schema.json
```

The committed `valid/minimal.json` is a contract smoke fixture, not a Klarna deployment profile. Do not use it to claim that Klarna operations are executable.

## Latest fresh Klarna result

Scenario run:

```text
/Users/hjrnunes/workspace/redhat/hjrnunes/asago-scenario-generator/output/runs/20260903-klarna-gemma4-oc-readiness-corrections-v1
```

Run outcome:

```text
35 candidates reached Stage 5
18 scenarios published
17 Stage 5 candidates rejected
0 published-scenario validation errors
18 execution-bundle entries
12 concrete target-agnostic cases
6 parameterized target-dependent tool cases
```

The 17 Stage 5 failures were:

```text
7 direct_prompt + FEEDBACK_DELAY mismatches
3 direct_prompt + ACTUATOR_ANOMALY mismatches
2 unsafe-condition/UCA-family mismatches
1 model-output condition using a semantic placeholder instead of a proposition
1 invalid temporal structural reference
3 selected control actions without an exact controlled-process target
```

The published scenarios were structurally valid and generally coherent, but human-facing output remains verbose:

```text
Average narrative length: approximately 262 words
Maximum narrative length: 309 words
Average Gherkin length: approximately 129 words
Maximum Gherkin length: 159 words
```

Artifact-readiness result:

```text
10 ready
2 needing semantic/runtime timing bindings; Garak also reports real-clock support absent
6 excluded because no target profile was supplied
0 invalid
```

Compiled artifact result:

```text
10 Gemma-OC presentation calls succeeded
10 executable-conversation artifacts generated
10 validation sidecars reported ok=true with no errors
```

Manifest:

```text
/Users/hjrnunes/workspace/redhat/hjrnunes/asago-scenario-generator/output/runs/20260903-klarna-gemma4-oc-readiness-corrections-v1/artifacts-garak-gemma4-oc/synthesis-20260903T104847.542581Z/artifact-manifest.json
```

The previous comparison run was:

```text
output/runs/20260903-klarna-gemma4-oc-stage5-prompt-fix-v1
```

It published 24 scenarios with 3 Stage 5 errors. The new checks improved semantic honesty but caused a major yield regression because the provider still controls choices that deterministic code later rejects.

## Why the current deterministic discussion stalled

The current `ControlAction` model contains only:

```text
ca_id
description
target: responsibility | controlled_process | none
```

It does not say whether the action is an assistant response, tool/API operation, state mutation, inter-agent message, or environmental action. Those distinctions cannot be recovered deterministically from arbitrary prose.

Likewise, a causal-factor kind does not uniquely identify the attacker delivery path. A process-model flaw can be reached through direct input, conversation history, or attacker-controlled external content. A feedback delay describes the system failure, not necessarily how the adversarial stimulus entered.

Therefore:

- A fixed phrase-to-label map is not deterministic semantics.
- A keyword classifier merely hides another heuristic.
- A hard factor-to-delivery table is deterministic code but is not necessarily a correct causal model.

## Recommended next design

Add two structured facts before Stage 5:

### Typed control-action effect

```yaml
control_action_id: CA-3-1
effect:
  kind: operation_invocation
  operation_role: execute_transaction
  authority: target_profile
  evidence_refs:
    - target-operation:payments.execute
```

Closed effect kinds:

```text
assistant_output
operation_invocation
state_mutation
agent_message
environment_action
unknown
```

### Typed attacker entry

```yaml
entry_id: ENTRY-knowledge-document
kind: external_content
carrier_role: retrieved_document
authority: system_profile
evidence_refs:
  - requirement:knowledge-source
```

Closed entry kinds:

```text
direct_user_input
conversation_history
external_content
runtime_fault
none
unknown
```

Produce these facts using this authority order:

1. Exact reviewed target profile.
2. Explicit target-independent semantic system profile.
3. SP1 model proposal with evidence and `model_inferred` authority.
4. `unknown` when the use case does not support a claim.

Then make Stage 5 mechanics pure:

1. Resolve an action kind from the typed control-action effect.
2. Resolve possible delivery routes from typed attacker entries and any exact obligation mechanism constraint.
3. Produce stable route variants when more than one route is genuinely supported rather than asking the model to choose an arbitrary one.
4. Derive the allowed unsafe-condition family from the UCA type.
5. Fill canonical IDs and structural references in code.
6. Ask the model only for causal explanation, semantic property, attacker intent, and presentation content within the already-fixed option.
7. Classify exact target facts as concrete, semantic roles as parameterized, simulation resources as simulated, and insufficient facts as analytical-only.

The important boundary is not “no LLM anywhere.” SP1 may still infer system semantics from a use-case document. The boundary is that the inference occurs once, carries explicit evidence and authority, is pinned, and cannot be silently reinterpreted for every Stage 5 scenario.

## Completion criteria for the next slice

The next implementation slice is complete when:

1. No runtime action or delivery label is derived from free-text matching.
2. Stage 5 cannot return `action_kind` or `delivery_class` values independently of the structured system facts.
3. Every route is traceable to a typed action effect, typed attacker entry, and exact evidence source.
4. Unknown information produces parameterized or analytical outcomes instead of a guessed concrete route.
5. UCA-incompatible condition variants are impossible at the provider schema boundary.
6. The current 17 Klarna Stage 5 failures become either valid route variants or explicit non-executable outcomes rather than provider-contract failures.
7. A fresh Klarna run is repeated using the commands above, followed by artifact readiness and real artifact compilation.
8. Scenario and artifact manifests reconcile the same bundle entries and exact source digests.

Do not start source mutation hardening until the live path is working and the user has reviewed the new scenario yield and quality.
