# Asago Scenario Generator

### Constraint and observation review

The existing final Stage 2 call reviews hazard/constraint scope, every
responsibility's governing constraints and every action's observation type
before ICA enumeration and target realization. Evidence-backed wording
corrections preserve legitimate use-case functions and communication direction;
they cannot change losses, identities or hazard-to-loss links. A genuinely
unknown relationship remains explicit rather than becoming an invented rule.
`loss-analysis-draft.yaml`, `control-structure-draft.yaml` and
`control-structure-review.yaml` retain the drafts and explicit decisions.
Each later version keeps its own name: `loss-analysis-reviewed.yaml`,
`loss-analysis-reviewed-corrected.yaml`, `control-structure-reviewed.yaml`,
`control-structure-evidence-bound.yaml`, `control-structure-revised.yaml` and
`control-structure-placed.yaml`. A version exists only when its step ran:
a correction round, an evidence-binding change, a revision attempt or a
placement change. The normal loss-analysis and
control-structure files contain the version in force when the stage ends.
No extra model call or target inventory is added to this baseline.

After Stage 1a, deterministic offline gates verify the loss analysis before
Stage 2 runs: every supplied risk card is accounted for exactly once, and the
merged hazard graph is dense enough to distinguish scenarios (every loss has a
hazard, every constraint has a hazard, every hazard has a constraint, and every
behavior class that the model declares on a constraint owns a hazard).
Subject-phrase sharing is recorded as advisory evidence for reviewers. A graph with a failing structural check gets a
bounded revision call with the exact failing checks. A valid revision that
still fails gets one more round on the revised graph, with the checks the first
round introduced labelled as such; a failure after that round stops the run
and is recorded in the manifest. When the Stage 2 semantic review breaks a
structural check, the review gets one correction round scoped to the named
hazards and constraints; the gate stays fail-closed if the corrected review
still fails. `loss-analysis-gates.yaml` carries the recorded evidence,
including every revision and correction round.

After the gates pass on a derived analysis, one bounded advisory call reviews
the whole graph against the risk cards. For every card it records what the
graph protects, against whom or what, which constraints cover it, whether
coverage is full, partial, or none, and the specific missing protection, with
exact quotations from the cited records. The review writes
`loss-analysis-risk-coverage-review.yaml`; it never changes the graph, never
blocks a run, and is not a gate. Runs that pin a graph with `--loss-analysis`
skip it. Validation is per row: a row that fails a rule is recorded with its
typed reason and the valid rows beside it are kept, every planned batch is
issued, and the artifact reports `completed`, `partial`, or `unavailable`
together with valid, invalid, and missing row counts.

Stage 5 scalar comparisons cite supplied constraint/action text through
`comparison_evidence`. When no citation is supplied, exact typed JSON values
and keys in the supplied target observations can establish literal presence
deterministically, without another model call. An invalid explicit citation
does not use this fallback. A compatible argument type alone is not a reference
value: unsourced literals become typed parameters, keeping the scenario's
property, operator and criterion. Grounding records under
`outcome-grounding/<context-digest>.yaml` retain proposed/compiled conditions
and source evidence, including every matching observation reference and JSON
path. These checks establish source presence, not independent
verification of the model's interpretation. The fixed model-answer Boolean
predicate remains distinct from a tool argument's literal value.

Asago Scenario Generator creates structured adversarial scenarios for AI and
agentic systems through one STPA-led product workflow. Taxonomy supplies
systematic, reviewed obligations, and STPA alone produces scenarios.

> **Status:** Pre-alpha. Interfaces and schemas may change without notice.

## Primary delivery workflow

Run the producer from this repository root:

```bash
cd <producer-repo-root>
uv sync --locked
uv run asago-scenario-generator generate \
  --use-case @use-case.txt \
  --risk-extraction risk-extraction.json \
  --qualification-facts qualification-facts.yaml \
  --sssom risk-to-llm.sssom.tsv \
  --output-dir output/my-system \
  --profile <profile-name>
```

The consumer then authors and checks the producer's handoff from its own
repository root:

```bash
cd <consumer-repo-root>
uv sync --locked
uv run asago-artifact-generator generate <scenario-handoff-or-input.json> \
  --inventory <inventory.json> \
  --runtime-contract <runtime-contract.json> \
  --output-dir runs/authoring/<case-id>
uv run asago-artifact-generator check runs/authoring/<case-id>/<case-id> \
  --evidence <evidence.json>
```

The orchestration repository (`asago-orch`) owns qualification. Run the
pipeline from that repository with `uv run asago-orch run`, or invoke the
modules under `asago-orch/src/asago_orch/qualification/` as documented in
`asago-orch/docs/qualification.md`. The orch runtime loads the immutable
consumer package without authoring and owns live setup, execution, detector
evaluation, evidence, and cleanup.

Run one final broad gate after all required execution:

```bash
cd <producer-repo-root>
./scripts/quality.sh
export ASAGO_SCENARIO_GENERATOR_APS_ROOT=/absolute/path/to/Acceptance-Pipeline-Specification
./scripts/acceptance.sh
uv run pytest tests/ -q
```

The current `generate` command runs the STPA workflow. It reuses the name of
the retired taxonomy-led `generate` command and shares nothing else with it;
historical records of the retired command remain read-only. The workflow is
producer `generate` → consumer `generate` → consumer `check` → orch
qualification. Do not restore the retired command as a second semantic engine.

## Ownership and current workflow

The producer owns semantic scenario authority: STPA lineage, the selected
failure criterion, safe alternatives, supported causal hypotheses, and the
semantics-only `scenario-handoff-v4`. The producer does not publish concrete
messages, setup instructions, detector expressions, or harness bindings.

The consumer owns executable-artifact design through its target-free `generate`
command. `check` validates a frozen package against supplied evidence. The
runtime owns frozen delivery, pre-dispatch dependency checks, command/reply
receipts, and separate backend result/state observations.

Use `generate` as the producer's sole normal scenario-generation command. Use the
consumer's `generate` and `check` commands for artifact design and offline
validation. The
additive R9 reconciliation and exact evidence boundaries are recorded in
[`docs/development/qualification-reports/r9-reconciliation-2026-09-17.md`](docs/development/qualification-reports/r9-reconciliation-2026-09-17.md).

Qualification cleanup records current process existence, full command,
ancestry, owner, and mission path before signaling. A stale PID or pattern
match alone never authorizes a stop. After listener closure, the maintained
seam waits boundedly for every confirmed mission-owned process to exit; a
successful signal records only a signal match, and a timeout remains failed
with exact survivor evidence. Each terminal run writes
`cleanup/stack-cleanup.json` plus a timestamped
`stack-cleanup-current-verification-*.json` record. The current record is
distinct from the preserved `2026-09-17T18:54:29Z` Klarna cleanup failure.

## Install

Asago Scenario Generator requires Python 3.11 or newer. The lock file is the
authoritative development environment.

```bash
uv sync --locked
```

The installed command is `asago-scenario-generator` and the Python package is
`asago_scenario_generator`.

## Configure an LLM endpoint

Commands that call a model accept explicit CLI options or these environment
variables:

- `ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL`
- `ASAGO_SCENARIO_GENERATOR_API_KEY`
- `ASAGO_SCENARIO_GENERATOR_MODEL_NAME`
- `ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS`
- `ASAGO_SCENARIO_GENERATOR_TEMPERATURE`
- `ASAGO_SCENARIO_GENERATOR_TOP_P`
- `ASAGO_SCENARIO_GENERATOR_TOP_K`
- `ASAGO_SCENARIO_GENERATOR_USE_GUIDED_DECODING`
- `ASAGO_SCENARIO_GENERATOR_TIMEOUT`
- `ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS`

For named model profiles, copy
`config/model-profiles.example.yaml` to `config/model-profiles.yaml`. The real
file is ignored because it may contain credentials. `generate` accepts named
profiles. STPA sampling values use the same
precedence: an explicit Python argument, then the selected profile or
environment value, then the client default; `generate` has no sampling override.
Invalid numeric or
boolean environment values fail before the first model call.
Requests have a 300-second application default deadline. Named-profile
`timeout` and `ASAGO_SCENARIO_GENERATOR_TIMEOUT` values override that default.
The SDK's implicit retries are disabled so retry decisions remain bounded and
visible in pipeline evidence. The client itself retries a request once, after
a fixed one-second pause, when the provider answers HTTP 5xx or the connection
fails for a reason other than a timeout. It never retries a timeout, a 4xx
status (429 included), or an answer that fails parsing or validation. Both
attempts appear in `provider-calls.jsonl`, and both count as requests.

Every profile used for STPA synthesis must also declare `context_window` and
`max_completion_tokens`; `safety_margin` is optional and defaults to the
greater of 10 percent of the context window or 1,024 tokens. The fully rendered
system and user prompts are measured before dispatch. A prompt that does not
fit is rejected locally, and multi-obligation routing batches are split in a
stable order instead of truncating domain context.

Gemma 4 deployments used for structured generation need a compact JSON grammar
configuration to avoid valid-prefix responses stalling on whitespace. See the
[Gemma 4 vLLM runtime notes](docs/operations/gemma4-vllm-structured-output.md)
for the required serving argument and rollout guidance.

## Product workflow

`generate` is the sole normal scenario-generation command. It requires the use
case, complete reviewed risk extraction, explicit qualification facts, an
output directory, and a reviewed risk-to-OWASP-LLM SSSOM file. Planning
always uses the bundled LLM-to-attack-pattern table, infers the capability profile,
and routes obligations in batches of eight:

```bash
asago-scenario-generator generate \
  --use-case @use-case.txt \
  --risk-extraction risk-extraction.json \
  --qualification-facts qualification-facts.yaml \
  --sssom risk-to-llm.sssom.tsv \
  --output-dir output/my-system \
  --profile <profile-name>
```

The former taxonomy-led workflow, which also used the `generate` name, has been
retired. Taxonomy still
provides systematic risk discovery, mapping provenance, qualification, and
obligations; it no longer authors scenarios.

The final R1–R9 evidence matrix, counterexample ledger, completion gate, final
test logs, and frozen-evidence comparison are generated under
`build/qualification/scenario-fidelity-final/` and described in the
[final completion-gate report](docs/development/qualification-reports/final-completion-gate-2026-09-17.md).

The run prepares one capability/fact snapshot, always executes Phase 1
planning, runs the ordinary SP1 baseline, considers every applicable
obligation, and permits at most one structural revision. An applied revision
causes exactly one complete final recheck; rejected or failed revisions retain
the baseline and upstream gaps without a second pass. Final STPA ICA evidence
is accounted separately for applicable, capability-excluded, and
governance-only obligations before ordinary SP3 scenario realization.

The output contains atomically published
`taxonomy-obligation-plan.yaml`, `obligation-consideration.yaml`,
`obligation-accounting.yaml`, `scenario-realization.yaml`, and
`synthesis-manifest.yaml`, plus a report. `scenario-realization.yaml` records
whether each accepted ICA was actually carried into a generated scenario; it
does not change the separate obligation/STPA accounting result.

Each generated scenario is published as a versioned **scenario handoff**
under `scenarios/` (`SCN-*.yaml` plus a matching `.feature` companion): the
envelope over narrative, attack tree, Gherkin and necessary metadata defined
by [`data/contracts/scenario-handoff/`](data/contracts/scenario-handoff/)
(schema `scenario-handoff-v4`; the `handoff-v1`, `handoff-v2` and `handoff-v3` kits
stay unchanged for their readers). Version 3 adds `tool_call_condition_status`,
which says whether Stage 5 bound the discriminating condition to target facts,
and, when it did, the ready-to-evaluate `tool_call_condition`. Version 4 adds the
required `attack_shape` key (closed enums, turn count 1-4 and identifiers, never
attack text): an object for an adversarial scenario and `null` for a functional
one. The `stage5_shape` step fills it: after Stage 5 compiles an adversarial
scenario, one closed-vocabulary model request proposes the channel, the planned
turns and, for an attack through content, the carrier operation. Code validates
the proposal and replaces any failure with a single direct request that carries
the reason. The forged-transcript channel stays out of the request unless
`run_sp3` receives `ShapeStepConfig(allow_forged_transcript=True)`. The handoff retains the semantic failure
criterion, the safe alternative, lineage, identity, and hypothesis framing,
and publishes no prepared message, prepared history, delivery route, oracle
selection, detector expression, judge prompt, or executable setup. The
consumer's artifact-design path (see the
[adaptive redesign plan](docs/development/designs/adaptive-scenarios-artifact-ownership-plan-2026-09-14.md)
and the
[orchestration entry point](docs/development/adaptive-redesign/orchestration-entry-point.md))
reads the handoff plus an explicit environment and owns the concrete test
design.

### Execution meaning and target profiles

Stage 5 requests scenario semantics only. The provider response carries no
stimulus category, execution route, factor-route marker, or executable
condition, and the published scenario makes no delivery claim. The model
selects explained request-local handles for the causal factors; deterministic
code resolves them to the fixed STPA identities, and the typed control action
fixes the action kind. The `stage5_shape` step proposes the delivery channel
afterwards, and the consumer designs the concrete test.

A causal factor that rests on content an adversary controls needs exact
reachable-capability evidence or an explicit bounded assumption; a structural
failure alone does not establish attacker-controlled retrieval. Accurate empty
reads remain background facts. A scenario whose observable outcome the
observation contract cannot capture is published as analytical-only.

An optional `--execution-target-profile` (also available as `--target-profile`)
supplies an observed/inferred target or explicit simulation profile. The
profile's own `basis` field selects its meaning. A simulation
profile must be explicit and complete; missing target information never creates a mock.
Profiles contain semantic resource facts, not URLs, credentials, or secrets.
A simulation profile is not treated as target evidence: SP1 ignores its
operations, and the run skips control-action enrichment and target realization
for it.
Its basis only reaches scenario production, where a requested environment
basis must agree with it.

Metadata-free MCP targets are discovered independently with the optional
`asago-target-scan mcp` command. It performs `tools/list` only by default and
writes a self-contained `execution-target-profile.json` alongside its sanitized
inventory, manifest, and call log. Before publication, secret-like values in
descriptions, schema examples/defaults, and annotations are redacted; each
sanitized tool observation retains the SHA-256 of its original normalized row.
MCP profiles retain separate observed
inventory and inferred semantic authority; each resource and operation keeps
the exact MCP tool name. Product `generate` strictly loads that profile file and
does not rescan or import the MCP transport. The profile schema
(`execution-target-profile-v1`) and its fixtures live in
[`data/contracts/target-profile/`](data/contracts/target-profile/); the
artifact generator vendors the schema byte-for-byte.

```bash
uv sync --locked --extra target-discovery
uv run asago-target-scan mcp \
  --server-url http://localhost:8888/sse \
  --target-id my-agent \
  --authorization-scope local-test \
  --profile gemma4-oc \
  --output-dir build/target-discovery/my-agent

uv run asago-scenario-generator generate \
  ... \
  --execution-target-profile \
  build/target-discovery/my-agent/execution-target-profile.json
```

The ordinary STPA baseline is completed without the profile. The profile is
used only afterward by a separately attested target-realization step, which
may select exact observed operations and add narrowly verified target-specific
actions or ICAs without changing any baseline record. The target-realization
record pins the profile digest beside those exact choices.

For single-agent targets, a supplied target profile enriches the same
analysis pipeline: the enrichment-grounding seam matches logical control
actions against the observed operations, records every match in
`control-action-enrichment.yaml`, and the published scenario handoff names
the verified operation identity for the scenario's lineage control action in
its `documented_operations` with the
`verified_control_action_specialization` authority. When the authored semantic
failure criterion contains exactly one complete token matching the same
observed inventory, the handoff also publishes that operation with the
`criterion_observed_operation` authority. Generic capability or service labels,
ambiguous criterion matches, and names absent from the observed inventory
never enter `documented_operations`. No `generate` input selects a generation algorithm;
multi-agent targets and runs without a profile execute the identical stage
pipeline with fewer enrichment inputs.

`generate --target-observations PATH` optionally accepts normalized runtime-context
JSON from the standalone orch capture workflow documented in
`asago-orch/docs/qualification.md`.
It requires the exact matching target profile. Stage 5 receives bounded quoted
state/read evidence separately from its systemic context; baseline loss/control
analysis, obligation routing and ICA enumeration remain target-blind. Observed
values can support literal comparison quotations, while their interpretation is
still a model-authored claim. Missing evidence remains a typed parameter, not
an invented limit. The retained snapshot is saved as `target-observations.yaml`
and its digest accompanies outcome-grounding records. Use the same capture as
the artifact generator's `--runtime-context` input for subsequent authoring.

`generate --loss-analysis PATH` optionally pins the Stage 1a output instead of
deriving it. The supplied graph is validated, run through the same offline
risk-accounting and hazard-graph density gates with zero model calls and no
revision call, re-published as the canonical `loss-analysis.yaml`, and hashed
into the run manifest (`stage_1a.source: pinned`; the derived path records
`source: derived`). A failing gate is fatal. A constraint may carry
explicit obligation entries (a `required` behavior with a `realized_by`
channel, or a `forbidden` behavior with a `violated_via` channel, each
quoting its rule span verbatim). Deterministic code stamps every derived
graph's direction authority `proposed`; only a pinned graph carries
`reviewed` with its reviewer stamps.

No profile is a valid mode. Omission remains omission: without a profile the
producer names no operation, record, or permission it was not given. A caller
may state the requested environment basis (`target_profile` or
`simulation_profile`); a basis that disagrees with a supplied profile's own
basis is an error, and a basis without a profile creates no binding.

The action kind is typed at the control-structure boundary. `model_output` is
the externally returned text or structured value from the tested model or
agent; `agent_message` is an internal message to another responsibility or
agent; `tool_call`, `state_change`, and `environment_action` are the other
typed effects. Prose never relabels an explicitly typed effect.

The artifact generator receives the published scenario handoff and an
explicitly selected environment. It owns the concrete test design (stimulus,
delivery, setup, detector) and handles runtime readiness and platform
compilation; the consumer never chooses a target or simulation profile by
default.

At model boundaries, code retains control of structural identity. The ICA
provider returns one short deviation clause and code applies the supplied slot's
exact unsafe-control category. Scenario reasoning selects explained local
causal handles; code maps those handles to valid process-model, feedback, or
control-action sources. Code derives each defender-belief annotation from the
same exact process-model causal declaration, rather than asking the model for
a second potentially contradictory description. An undeclared belief is marked
as not selected in this scenario, not as free of vulnerabilities. The model
cannot publish a coordination/controller ID as a causal source or invent its
own factor kind. Stage 5 receives a purpose-built semantic view rather than the
serialized context artifact: integrity hashes, source pins, catalog labels,
and bookkeeping identities stay in deterministic code, while every remaining
reference is defined and tied to an output field. Placeholder presence, and
therefore `semantic_binding_required`, is also derived after the provider
response rather than requested from the model. For model-output `action_value`
cases, Stage 5 supplies an observable semantic proposition such as
`reveals_restricted_information equals true`; it does not defer an unknown
whole response as a string placeholder. Deployment-specific tool values and
timing thresholds remain typed placeholders. A scenario may describe an
adversary taking advantage of an
existing STPA failure even when no separate attacker capability was
enumerated. Exact capability and access-path claims remain structured
evidence: if supplied, they must resolve to the immutable context. Free-text
verb matching is not a publication gate. An obligation finding means STPA
found a related unsafe-control path; the taxonomy pattern name, concern, and
rationale remain analysis provenance rather than proof that its attack
mechanism occurred. ICA and scenario text may use that mechanism only when the
STPA structure or exact capability/access evidence independently supports it.
Attack-tree templates use neutral stale, missing, late, or inaccurate-state
causes so they do not seed poisoning or tool-fabrication claims.

The obligation-aware routing, revision, and ICA prompt bodies are Jinja
templates over closed prompt views. Their call evidence records hashes for the
top-level templates and included partials. Routing answers two separate typed
questions: whether the attack mechanism is plausible in the supplied system,
and whether that mechanism actually realizes the reviewed risk. A plausible
mechanism with a risk mismatch may still yield a useful ordinary STPA
scenario, but it cannot mark that risk obligation as addressed. A separate
compact verifier compares only the distinctive mechanism with the selected
structural path. If it finds an adjacent control or insufficient evidence, the
STPA route and scenario remain available while accounting records
`mechanism_path_unsubstantiated` and withholds obligation credit.

After final ICA filling, a separate STPA-only check compares every non-N/A ICA
with its exact control action, UCA category, hazard, governing constraint, and
reachable loss. The reviewer describes what happened to the action without
seeing the proposed category; code compares that description with the fixed
slot. This prevents a plausible harm from automatically validating the wrong
action or category. An unsupported ICA receives one bounded correction by the ICA
author and one independent recheck; it cannot reach Stage 5 unless the recheck
supports the corrected meaning. Sibling ICAs continue, and failures remain
explicit in obligation accounting. A failed correction or recheck keeps the
earlier rejection effective; it cannot restore eligibility. A first-review
outage without a semantic verdict remains a distinct technical failure.
Risk-to-pattern mapping strength is derived
from the pinned mapping path in code and is never accepted from model output.

The unsafe outcome published for an executable scenario carries both its
machine condition and a short human-readable semantic proposition. For model
output, the machine condition is fixed bookkeeping over that proposition; the
artifact generator must use the proposition itself as the response-judging
criterion. The same scenario, projection, and execution trace retain the exact
hazard, governing-constraint, and reachable-loss lineage.

Long but semantically valid ICA clauses remain publishable and carry an
`ica_prose_quality_warning`; style never becomes a reason to delete a valid
scenario. Accounting and scenario realization record a closed stop reason for
every applicable obligation. The synthesis manifest and report reconcile those
reasons against the full applicable-obligation denominator, while
`calls.jsonl` distinguishes a returned provider response from parsing,
semantic validation, compilation, and publication.

`generate` also writes `provider-calls.jsonl` to the output directory: one line per
provider request, with the request exactly as sent (messages, response format,
model, sampling controls), the raw response (body, `finish_reason`, usage,
response id and model), the stage, step, slot, scenario, and attempt that
issued it, a sequence number, and `request_sha256`, the SHA-256 of the
canonical request JSON. A provider failure is recorded with its redacted error,
and a response the client rejects locally carries the rejection. When the client
retries a request after a transport error, the failed attempt and the retry are
two lines with the same request digest, and the retry's line carries
`"retry_of": {"type": ..., "status_code": ...}`, the error class and HTTP
status (`null` for a connection error) of the failed attempt. Other lines have
no `retry_of` key. The record
never holds the endpoint, credential, or headers. Expect about 45 KB per call;
a 300-call run is about 14 MB.

Replay a recorded run without an endpoint by pointing `--replay-calls` at the
earlier output directory. Each request is served from that record by call
identity and request digest, in recorded order, and a recorded provider error
is raised again as its live class; the run fails if any request has no
recorded response. A replay retries after a transport error only when the
record holds that retry, so a recording made without the retry replays as
recorded:

```bash
asago-scenario-generator generate ... --output-dir output/replay \
  --replay-calls output/original
```

Replay needs the same inputs and model profile as the recorded run, because
the profile's controls are part of each request's digest.

When the code now sends requests the record lacks (a new pipeline step, or a
prompt you changed), fill the replay: serve what the record holds and send only
the rest live. A fill run contacts the model endpoint, so read
`docs/development/private-live-model-approval.md` first and set the budget from
the approved request allowance.

```bash
asago-scenario-generator generate ... --profile <profile> \
  --output-dir output/filled --replay-calls output/original \
  --replay-fill --max-live-requests 60
```

- `--replay-fill` sends a request with no recording through the normal client
  (same profile, limits, and the one recorded transport retry, with its pause
  and `retry_of`). Requires `--replay-calls`, `--profile`, and
  `--max-live-requests`. Without it, a missing recording still ends the run in
  an error.
- `--max-live-requests N` caps the requests that leave the machine, a transport
  retry included. The request that would exceed N is not sent. It gets a line
  with `"source": "refused"`, later live requests are refused the same way, and
  the run ends in `LiveRequestBudgetError`.
- `--live-stage NAME` (repeatable) sends every request whose call identity stage
  is NAME live, even when the record holds it; those recorded responses stay
  unused. Requires `--replay-fill`. NAME must be a stage in the record, so a
  misspelled name fails before any request.

In a fill run each line of `provider-calls.jsonl` carries `"source": "replay"`
or `"live"`; other runs have no `source` key. The synthesis manifest gains a
`provider_replay_fill` block with the replay source, forced stages, budget,
`served_requests`, `live_requests`, `live_requests_by_stage`,
`unused_recorded_responses`, and `refused_requests`. The fill run's own
`provider-calls.jsonl` replays with `--replay-calls` and no fill flags, with no
live request.

To check that a change leaves recorded runs unchanged, run the replay gate,
which replays offline and compares every output file
(see `docs/development/replay-gate.md`):

```bash
./scripts/replay-check.sh ../asago-orch/runs/<run-id>/stages/generate/output
```

`generate` plans the obligation ledger deterministically, without contacting an LLM
endpoint. The planner's external seam is typed:

```python
plan_taxonomy_obligations(
    inputs: TaxonomyObligationInputs,
) -> TaxonomyObligationPlan
```

`TaxonomyObligationInputs` contains reviewed risk cards, the immutable
capability/fact snapshot, authoritative attack-pattern catalog, pinned mapping
sets, qualification facts, a bounded projection budget, and the compatibility
policy. It does not accept file paths or an LLM client. Malformed, incomplete,
or contradictory global inputs fail before a partial plan is returned.

Reviewed tools and integrations may declare `supported_operations` using the
closed `retrieve_data`, `transmit_data`, and `execute_code` vocabulary.
Attack-pattern resource slots declare their `required_operations`. A missing
operation inventory is an evidence gap; a complete inventory that omits a
required operation is a structural mismatch. Slot kind, operation support, and
distinct-role constraints are checked separately, so an upload-only tool
cannot stand in for a retrieval tool or fill two roles that the pattern says
must be different.

The mapping pins have two distinct authorities: `mapping_pins.sssom` retains
the authoritative taxonomy-context `mapping_set_digest`, while
`mapping_pins.obligation_edges` uses release `obligation-mapping-bundle-v2` to
bind the complete typed LLM-to-pattern and SSSOM edge bundle. Both pins are
required; the supplied-edge bundle pin cannot substitute for the context pin.

Each published `taxonomy-obligation-plan-v1` row retains `risk_ref`,
`taxonomy_chain`, `attack_pattern_id`, `attack_pattern_semantic_digest`, the
scope and qualification dispositions, candidate records, and evidence. A risk
with no actionable pattern remains visible as `governance_only`; advisory
candidate filtering cannot remove the obligation row. Plan identity includes
the risk, pattern and its semantic digest, capability snapshot digest, and
catalog/mapping pins. Publication is atomic; the round-tripped YAML artifact is
validated against its semantic digest.

The planner crosses inward through
`pipeline.projection_authoritative.project_authoritative_candidate_observations`
to observe the existing projection result plus bounded qualification and
candidate observations. The public generation projection façade still returns
its `ProjectionBatch` with the default emission behavior unchanged. A
`budget_deferred` record is emitted only for a concrete candidate already
derived and validated before the bound; unvalidated overflow is a typed
limitation, not a synthesized identity. Row evidence retains typed condition
and precondition evaluations and explicit unknown/absent qualification-fact
readings.

There is no separate `validate-obligation-plan` CLI command. Consumers should
load a persisted artifact through the typed plan model/persistence adapter,
which enforces the closed schema and digest before accepting it.

The STPA source chain must preserve security-constraint ownership explicitly:
Stage 2 accepts one closed responsibility collection with exact constraint
references, and ICA enumeration stops if any loss-analysis constraint has no
responsible controller.

## STPA model configuration and stage behavior

Select a named model profile for the STPA stages with `--profile`:

```bash
asago-scenario-generator generate \
  --use-case @use-case.txt \
  --risk-extraction risk-extraction.json \
  --qualification-facts qualification-facts.yaml \
  --output-dir output/my-system \
  --profile gemma4-local
```

The same Gemma sampling behavior can be configured without a profile:

```bash
export ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL=https://your-endpoint.example.com/v1
export ASAGO_SCENARIO_GENERATOR_MODEL_NAME=gemma-4-26b-a4b-it
export ASAGO_SCENARIO_GENERATOR_API_KEY=unused
export ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS=16384
export ASAGO_SCENARIO_GENERATOR_TEMPERATURE=1.0
export ASAGO_SCENARIO_GENERATOR_TOP_P=0.95
export ASAGO_SCENARIO_GENERATOR_TOP_K=64
export ASAGO_SCENARIO_GENERATOR_USE_GUIDED_DECODING=false
export ASAGO_SCENARIO_GENERATOR_TIMEOUT=300

asago-scenario-generator generate \
  --use-case @use-case.txt \
  --risk-extraction risk-extraction.json \
  --qualification-facts qualification-facts.yaml \
  --output-dir output/my-system
```

The STPA run manifest records effective model name, base URL, token limit,
temperature, `top_p`, `top_k`, thinking control, guided-decoding state, and
request timeout. API keys and header values are never included. For Qwen on
vLLM, `enable_thinking: false` is sent inside
`chat_template_kwargs`, while guided decoding uses the standard top-level
`response_format: {type: json_schema, ...}` request shape. Profiles that omit
`enable_thinking`, including the Gemma examples, retain their existing request
body.

Stage 2 retries a semantically empty requirement or responsibility response
once with corrective feedback. Stage 3 likewise retries a schema-invalid slot
response once. ICA prompt views carry the authoritative action temporality used
for duration decisions; structural revision responses validate complete nested
objects before merge, so an attempted revision is not reported as applied when
its delta is rejected.
If Stage 5 reaches the completion-length limit on both its normal and concise
retry attempts, it records a fatal diagnostic and aborts the remaining threats
instead of repeating a likely deployment-level structured-output failure.

Stage 5 asks for a causal explanation and the scenario semantics; it asks for
no stimulus. The compiler derives the fixed action kind from the typed control
action. The synthesis manifest reports candidate outcomes once per exact
scenario/slot/ICA identity and reports diagnostic-message count separately.

Stage 5 also requires a closed adversary record on every candidate: who
attempts the unsafe behavior (`external_attacker`, `malicious_customer`,
`third_party_via_content`, or `none`) and what they gain. Deterministic code
sets the delivery channel (`reaches_target_via`) to retrieved content for a
`third_party_via_content` adversary and leaves it null otherwise, because the
response carries no stimulus. A `kind: none`
candidate is a functional test: it is persisted under `scenarios/` for the
owner's information but never prepared for execution. A `third_party_via_content` adversary additionally requires
typed capability-profile content-surface facts and is otherwise rejected as
`no_content_surface`. A gain that merely restates a governing constraint is
rejected.

The synthesis manifest also publishes a stable `run_status` whose completion
rule is candidate-terminal: `completed` when every requested candidate's
terminal outcome is `published` (publication succeeded) or
`functional_specification` (a functional specification persisted),
`no_candidates` when no eligible candidate was available, `failed` when
candidates were attempted but none was published or resolved, and `degraded`
for partial or not-yet-attempted yield (including `publication_failed`
candidates, which are attempted but never yielded: a compiled spec whose
handoff or artifact write failed is not `published`). Its `scenario_counts`
keeps three denominators independent: candidate counts (`requested`,
`attempted`, `unprocessable`, `published`, `functional_test`,
`publication_failed`), artifact counts (`generated` = published adversarial
artifacts only, `functional_specifications` = persisted functional
specifications), and draft counts (`drafts_returned`, `drafts_accepted`,
`drafts_rejected`, `drafts_held`) — all independent from the
diagnostic-message count. Artifact counts never stand in for `requested`:
two candidates that publish three artifacts are `completed`, not overcounted.
The product `generate`
command writes and reports all diagnostics and accounting artifacts before
returning a non-zero result for the attempted zero-yield `failed` case;
no-candidate analysis and partial yield remain successful command outcomes.

The product manifest and report retain baseline analysis and post-revision
warnings even after later stages finish. The report's Analysis diagnostics
section is separate from candidate yield: publication is not proof that known
analysis gaps were resolved.

STPA result and manifest diagnostics retain `stage_errors` for fatal stage
failures and add `stage_warnings` for recoverable normalization, stitching, and
repair diagnostics. This is an additive schema change. Existing consumers may
continue reading `stage_errors`, but successfully repaired SP1 diagnostics that
were historically misclassified there now appear only in `stage_warnings`.

Scenario publication renders narrative, attack-tree, and Gherkin summaries
deterministically; it makes no model calls after Stage 5. These summaries
describe test hypotheses, not observed outcomes.
Stage 5 derives tool predicates from observed argument schemas and timing
relationships from explained event handles. Missing quantitative facts stay
unknown rather than receiving illustrative values.

The artifact generator binds scenario meaning to a target during its own
test design, as the handoff flow below describes.

The normal product `generate` publishes the versioned **scenario handoff**: the envelope over narrative, attack tree, Gherkin and
necessary metadata defined by
[`data/contracts/scenario-handoff/`](data/contracts/scenario-handoff/)
(schema `scenario-handoff-v4`), written under `scenarios/` with its matching
`.feature` companion. The handoff retains the semantic failure criterion, the
safe alternative, lineage, identity, and hypothesis framing, and publishes no
prepared message, prepared history, delivery route, oracle selection, detector
expression, judge prompt, or executable setup. The artifact generator reads
that handoff plus an explicit environment (target profile and runtime
context) and owns the concrete test design: stimulus, setup, detector with a
distinguishing rationale, fidelity assessment, and freeze. See the
[adaptive redesign plan](docs/development/designs/adaptive-scenarios-artifact-ownership-plan-2026-09-14.md)
and the orch qualification runbook in
`asago-orch/docs/qualification.md` for the complete producer → consumer →
execution workflow.

## Gold set evaluation

The producer holds no gold cases and no scorer. The hand-authored gold sets
and gold scoring live in the orchestration repository (`asago-orch`), whose
score stage is the only reader of gold. That stage checks a package's detector
through `asago_orch.qualification.probe_detector`, as described in
`asago-orch/docs/qualification.md`, so the producer never receives gold
content.

## Development

```bash
./scripts/quality.sh
./scripts/acceptance.sh
uv run pytest tests/ -q
```

The unit and default acceptance suites are deterministic and do not require an
LLM endpoint.

Gherkin files under `features/` are committed source. Acceptance IR, DRY
reports, generated entrypoints, pipeline output, and harness state are ignored.
See [the development methodology](docs/development/swarmforge.md) and
[architecture overview](docs/architecture/overview.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).

Model-facing authoring and review interfaces separate semantic selections from
compiler-owned references and assembly; see [Model-facing interfaces](docs/architecture/model-facing-interfaces.md)
for the separate scenario/no-scenario response forms, evidence, compatibility,
and observation limits.
