# Asago Scenario Generator

### Constraint and observation review

The existing final Stage 2 call reviews hazard/constraint scope, every
responsibility's governing constraints and every action's observation type
before ICA enumeration and target realization. Evidence-backed wording
corrections preserve legitimate use-case functions and communication direction;
they cannot change losses, identities or hazard-to-loss links. A genuinely
unknown relationship remains explicit rather than becoming an invented rule.
`loss-analysis-draft.yaml`, `control-structure-draft.yaml` and
`control-structure-review.yaml` retain the drafts and explicit decisions;
the normal loss-analysis and control-structure files contain reviewed results.
No extra model call or target inventory is added to this baseline.

After Stage 1a, deterministic offline gates verify the loss analysis before
Stage 2 runs: every supplied risk card is accounted for exactly once, and the
merged hazard graph is dense enough to distinguish scenarios (every loss has a
hazard, every constraint has a hazard, every hazard has a constraint, and every
behavior class owns a hazard). Subject-phrase sharing is recorded as advisory
evidence for reviewers. A graph with a failing structural check gets a
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
systematic, reviewed obligations; STPA alone produces scenarios; Phase 2
verifies the resulting correspondence without changing those scenarios.

> **Status:** Pre-alpha. Interfaces and schemas may change without notice.

## Primary delivery workflow

Run the producer from this repository root:

```bash
cd <producer-repo-root>
uv sync --locked
uv run asago-scenario-generator run \
  --use-case @use-case.txt \
  --risk-extraction risk-extraction.json \
  --qualification-facts qualification-facts.yaml \
  --taxonomy-inputs obligation-inputs.yaml \
  --output-dir output/my-system \
  --sp1-profile <profile-name> --sp2-profile <profile-name> \
  --sp3-profile <profile-name>
```

The consumer then authors and checks the producer's handoff from its own
repository root:

```bash
cd <consumer-repo-root>
uv sync --locked
uv run asago-artifact-generator author <scenario-handoff-or-input.json> \
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

The former taxonomy-led `generate` command is retired from the primary
workflow. Historical `generate` compatibility records remain read-only;
migrate new work to `run` → consumer `author` → consumer `check` → orch
qualification. Do not restore the retired command as a second semantic engine.

## Ownership and current workflow

The producer owns semantic scenario authority: STPA lineage, the selected
failure criterion, safe alternatives, supported causal hypotheses, and the
semantics-only `scenario-handoff-v2`. The producer does not publish concrete
messages, setup instructions, detector expressions, or harness bindings.

The consumer owns executable-artifact design through its target-free `author`
command. `check` validates a frozen package against supplied evidence. The
runtime owns frozen delivery, pre-dispatch dependency checks, command/reply
receipts, and separate backend result/state observations.

Use `run` as the producer's sole normal scenario-generation command. Use the
consumer's `author` and `check` commands for artifact design and offline
validation. The producer's execution bundle/projection readers and the
consumer's legacy `generate` command are historical, read-only compatibility
paths. They are not inputs to the current producer-to-consumer workflow. The
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
file is ignored because it may contain credentials. Both `run` and the advanced
`stpa-run` diagnostic accept named profiles. STPA sampling values use the same
precedence: an explicit Python/CLI argument, then the selected profile or
environment value, then the client default. The CLI exposes
`--temperature` as the run-wide explicit sampling override. Invalid numeric or
boolean environment values fail before the first model call.
Requests have a 300-second application default deadline. Named-profile
`timeout` and `ASAGO_SCENARIO_GENERATOR_TIMEOUT` values override that default.
The SDK's implicit retries are disabled so retry decisions remain bounded and
visible in pipeline evidence.

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

`run` is the sole normal scenario-generation command. It requires the use
case, complete reviewed risk extraction, explicit qualification facts, an
output directory, and either a reviewed risk-to-OWASP-LLM SSSOM file or a
typed taxonomy-input snapshot:

```bash
asago-scenario-generator run \
  --use-case @use-case.txt \
  --risk-extraction risk-extraction.json \
  --qualification-facts qualification-facts.yaml \
  --taxonomy-inputs obligation-inputs.yaml \
  --output-dir output/my-system \
  --sp1-profile <profile-name> --sp2-profile <profile-name> \
  --sp3-profile <profile-name>
```

The former taxonomy-led `generate` workflow has been retired. Taxonomy still
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
`synthesis-manifest.yaml`, plus a report. It then runs offline Phase 2 and
publishes `system-resource-map.yaml`, `correspondence-proposals.yaml`,
`correspondence-reconciliation.yaml`, and
`hybrid-coverage-assessment.yaml`. `scenario-realization.yaml` records
whether each accepted ICA was actually carried into a generated scenario; it
does not change the separate obligation/STPA accounting result.
Phase 2 is non-blocking: failure or unresolved evidence never removes generated
scenarios. The automatic resource map begins as an exact, zero-link baseline,
and exact synthesis routes produce review candidates marked
`mechanism_enables_ica` only when synthesis accounting credited the exact
mechanism/path; non-credited structural joins remain
`related_but_not_coverage`. No candidate is automatically accepted. Human
review and an authoritative resource map are therefore required before the
assessment can claim confirmed taxonomy correspondence. The normal automatic
run reports `awaiting_evidence`; this does not prevent scenario generation.

Each generated scenario is published as a versioned **scenario handoff**
under `scenarios/` (`SCN-*.yaml` plus a matching `.feature` companion): the
envelope over narrative, attack tree, Gherkin and necessary metadata defined
by [`data/contracts/scenario-handoff/`](data/contracts/scenario-handoff/)
(schema `scenario-handoff-v2`; the `handoff-v1` kit stays unchanged for v1
readers). The handoff retains the semantic failure
criterion, the safe alternative, lineage, identity, and hypothesis framing,
and publishes no prepared message, prepared history, delivery route, oracle
selection, detector expression, judge prompt, or executable setup. The
consumer's artifact-design path (see the
[adaptive redesign plan](docs/development/designs/adaptive-scenarios-artifact-ownership-plan-2026-09-14.md)
and the
[orchestration entry point](docs/development/adaptive-redesign/orchestration-entry-point.md))
reads the handoff plus an explicit environment and owns the concrete test
design. The retired execution projection/bundle publication path survives
only as a read-only historical seam.

### Execution meaning and target profiles

Stage 5 fixes one execution route for each scenario: a direct prompt, content
carried indirectly into the model, or a conversation context. It also fixes
the causal factor, action kind, logical domain resources, and observable unsafe
outcome. The model may choose among the explained route choices, but
deterministic code resolves the choices and owns the scenario's meaning. The
selected factor must also fit the route: direct prompts exercise a
process-model flaw, conversation history may exercise a process-model flaw or
feedback delay, and indirect content may exercise a process-model flaw or
sensor anomaly. This prevents a direct prompt from being used as a default for
an unrelated internal timing or actuator failure.

On the provider wire, the stimulus category is the sole delivery input and an
executable response marks exactly one declared
`causal_factors[].selected_for_route` factor; an analytical-only response marks
none. The compiler derives delivery and maps that marker to the existing final
factor identity without adding evidence or retagging factors. The published
execution route and contract are unchanged.
Input delivery is independent of the downstream action: a user message can
exercise a tool call without changing the tool's returned content. An indirect
stimulus requires exact reachable-capability evidence or an explicit bounded
carrier/access hypothesis; a structural failure alone does not establish
attacker-controlled retrieval. Accurate empty reads remain background facts.

The producer then classifies the result. `concrete` means no domain resource is
needed or every required resource is already resolved. `parameterized` means
the route and oracle are complete but a resource still needs to be selected.
`analytical_only` means the execution meaning is incomplete and cannot be
compiled honestly. These classifications are separate from the environment
basis: `target_agnostic`, `target_profile`, `simulation_profile`, or `none`.

An optional `--execution-target-profile` (also available as `--target-profile`)
supplies an observed/inferred target or explicit simulation profile. Select its meaning
with `--requested-environment-basis` (or `--basis`). A simulation profile must
be explicit and complete; missing target information never creates a mock.
Profiles contain semantic resource facts, not URLs, credentials, or secrets.
That path is classified as a concrete simulated case, not as a real target
integration.

Metadata-free MCP targets are discovered independently with the optional
`asago-target-scan mcp` command. It performs `tools/list` only by default and
writes a self-contained `execution-target-profile.json` alongside its sanitized
inventory, manifest, and call log. Before publication, secret-like values in
descriptions, schema examples/defaults, and annotations are redacted; each
sanitized tool observation retains the SHA-256 of its original normalized row.
MCP profiles retain separate observed
inventory and inferred semantic authority; each resource and operation keeps
the exact MCP tool name. Product `run` strictly loads that profile file and
does not rescan or import the MCP transport.

```bash
uv sync --locked --extra target-discovery
uv run asago-target-scan mcp \
  --server-url http://localhost:8888/sse \
  --target-id my-agent \
  --authorization-scope local-test \
  --profile gemma4-oc \
  --output-dir build/target-discovery/my-agent

uv run asago-scenario-generator run \
  ... \
  --execution-target-profile \
  build/target-discovery/my-agent/execution-target-profile.json \
  --requested-environment-basis target_profile
```

The ordinary STPA baseline is completed without the profile. The profile is
used only afterward by a separately attested target-realization step, which
may select exact observed operations and add narrowly verified target-specific
actions or ICAs without changing any baseline record. Those exact choices and
both target digests are then pinned into the execution projection.

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
never enter `documented_operations`. No `run` input selects a generation algorithm;
multi-agent targets and runs without a profile execute the identical stage
pipeline with fewer enrichment inputs. The deterministic target-derived
structure and the grounded-authoring call (one per (constraint, action)
candidate, with deterministic validation of every fact, tool, argument, and
condition account against typed rejection reasons, the closed oracle
templates in `data/oracles/templates.yaml`, and no repair call) are internal
seams that no documented input selects. Obligation entries on a constraint
(see `--loss-analysis` below) gate which oracle kinds the internal admission
seam offers: drafts cite one entry in `obligation_ref`, a citation that
contradicts the cited entry's kind or channel is rejected, and an omission
oracle holds unless the constraint's direction is reviewed and the cited
required entry is realized by a tool call; such drafts persist as
specifications with a typed reason and are never compiled — a missing
downstream detector capability never suppresses a scenario. Omission drafts
also cite exact trigger evidence from a supplied user turn, a used state
fact, or a named observation. This validates the source, not the author's
claim that the rule requires the call; the omission check stays conditional
on independently establishing that duty. No `run` input accepts a
`reviewed-obligation-bindings-v1` file or a `target-subject-model-v1`
companion; both closed forms fail closed if supplied.

`run --target-observations PATH` optionally accepts normalized runtime-context
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

`run --loss-analysis PATH` optionally pins the Stage 1a output instead of
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

No profile is a valid mode. Omission remains omission: a resource-free route
can be `target_agnostic`, while a resource-bearing route remains
`parameterized` with environment basis `none` and a `needs_binding` profile
fit. A caller may state a future `target_profile` or `simulation_profile`
basis without supplying the profile; that records the requested basis and its
exact missing-profile diagnostic, but does not create a binding.

The action kind is typed at the control-structure boundary. `model_output` is
the externally returned text or structured value from the tested model or
agent and needs no domain resource; `agent_message` is an internal message to
another responsibility or agent and retains an `agent_channel` requirement.
`tool_call`, `state_change`, and `environment_action` likewise retain their
domain action requirements. Prose never relabels an explicitly typed effect.

The artifact generator receives the published scenario and, when the contract
needs environment resources, an explicitly selected profile. It creates one
bound execution case by matching the producer's logical requirements to exact
resources, then handles runtime readiness and platform compilation.
Target-agnostic model conversations need no profile. The consumer may not
change the delivery route, causal factor, operation, action, or oracle. An
analytical-only case stops before compilation; a parameterized case remains
pending until it is bound. For a parameterized contract whose request is
`null`, the consumer's caller must explicitly select a matching target or
simulation profile; the consumer never chooses one by default. Mixed bundles
keep each case's independent target-agnostic, pending, target-bound, or
simulation-bound state.

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

`run` also writes `provider-calls.jsonl` to the output directory: one line per
provider request, with the request exactly as sent (messages, response format,
model, sampling controls), the raw response (body, `finish_reason`, usage,
response id and model), the stage, step, slot, scenario, and attempt that
issued it, a sequence number, and `request_sha256`, the SHA-256 of the
canonical request JSON. A provider failure is recorded with its redacted error,
and a response the client rejects locally carries the rejection. The record
never holds the endpoint, credential, or headers. Expect about 45 KB per call;
a 300-call run is about 14 MB.

Replay a recorded run without an endpoint by pointing `--replay-calls` at the
earlier output directory. Each request is served from that record by call
identity and request digest, in recorded order, and a recorded provider error
is raised again as its live class; the run fails if any request has no
recorded response:

```bash
asago-scenario-generator run ... --output-dir output/replay \
  --replay-calls output/original
```

Replay needs the same inputs and model profile as the recorded run, because
the profile's controls are part of each request's digest.

To check that a change leaves recorded runs unchanged, run the replay gate,
which replays offline and compares every output file
(see `docs/development/replay-gate.md`):

```bash
./scripts/replay-check.sh ../asago-orch/runs/<run-id>/stages/generate/output
```

`run` plans the obligation ledger deterministically, without contacting an LLM
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
`mapping_pins.obligation_edges` uses release `obligation-mapping-bundle-v1` to
bind the complete typed cross-taxonomy and SSSOM edge bundle. Both pins are
required; the supplied-edge bundle pin cannot substitute for the context pin.

Each published `taxonomy-obligation-plan-v1` row retains `risk_ref`,
`taxonomy_chain`, `attack_pattern_id`, `attack_pattern_semantic_digest`, the
scope and qualification dispositions, candidate records, evidence, and
`correspondence_disposition: not_assessed`. A risk with no actionable pattern
remains visible as `governance_only`; advisory candidate filtering cannot remove
the obligation row. Plan identity includes the risk, pattern and its semantic
digest, capability snapshot digest, and catalog/mapping pins. Publication is
atomic; the round-tripped YAML artifact is validated against its semantic
digest.

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

The system-resource-map validator consumes the closed
`system-resource-map-v1` contract and checks both source digests and every
typed link against the exact capability fact snapshot and STPA control
structure. It never infers correspondence or contacts a model. Correspondence
proposal and reconciliation validate the map the same way before they run.

Reviewed decision files are historical records for the exact packet and proposal
set they name. Before applying one to reconciliation, convert it to an
`AdjudicationSet` only after supplying both exact recorded digests; a mismatch is
rejected, so decisions cannot silently be applied to a corrected run.
`summarize_correspondence_calibration(...)` keeps proposer evaluation outside
the coverage matrices. It reports exact confirmed, rejected, unresolved, and
unreviewed counts for coverage-bearing and noncoverage proposals. Precision is
retained as `confirmed / (confirmed + rejected)` with the exact numerator and
denominator; unresolved and unreviewed records are not silently scored.

The Phase 2 pure interfaces remain separate from both generation commands:

```python
resource_map_validation = validate_system_resource_map(
    resource_map,
    capability_snapshot,
    control_structure,
)
proposal_set = propose_correspondence(resource_map_validation, source_artifacts)
calibration = summarize_correspondence_calibration(
    proposal_set,
    reviewed_adjudications,
)
reconciliation = reconcile_correspondence(
    resource_map_validation,
    proposal_set,
    adjudications,
)
assessment = assess_hybrid_coverage(
    obligation_plan,
    resource_map_validation,
    reconciliation,
    taxonomy_coverage_input,
    stpa_coverage_input,
)
```

Proposals retain exact obligation, risk, attack-pattern, taxonomy-candidate,
ICA slot, ICA, execution-candidate, resource-link, hazard, constraint, evidence,
and source-pin identities. The proposal source pins, proposal artifact,
reconciliation artifact, and final assessment explicitly retain the exact
`capability_snapshot_digest` shared by the Phase 1 plan and validated resource
map; it is bound into each canonical artifact digest. Reconciliation
alone can materialize an accepted relation, and only a relation backed by an
accepted, confirmed proposal can establish hybrid coverage. Rejected,
unresolved, contradictory, and `related_but_not_coverage` evidence remains
visible without being promoted.

Every resource-link proposal also identifies the one selected projectable
candidate whose own resource binding supports the link. Reconciliation rejects
a missing, unknown, infeasible, or mismatched candidate/link witness.

`HybridCoverageAssessment` is the closed, immutable
`hybrid-coverage-assessment-v1` domain artifact. Its structural-consideration
matrix contains one row per deterministic UCA slot (`ica`, `justified_na`, or
`unresolved`). Its taxonomy-correspondence matrix contains one row per Phase 1
obligation with the exact scope, qualification, accepted-relation, disposition,
and typed-gap fields. Its scenario-realization matrix contains one row per
accepted relation and retains its exact supporting proposal, obligation, risk,
attack-pattern, and taxonomy-candidate identities. The public assessment seam
requires the successful `SystemResourceMapValidation` attestation, not a raw
map. Rejected and unresolved proposal diagnostics remain visible even when
their cross-artifact references are defective, but those records never receive
coverage credit. Missing resource-map evidence is evaluated against each
obligation's candidate resource references rather than global map presence.
`StpaCoverageInput.from_ica_enumeration(...)` is the
deterministic adapter from the real ICA enumeration into the complete
structural denominator; optional scenario observations must resolve to an
exact slot, ICA, and canonical `EXEC:*` identity.
`TaxonomyCoverageInput.from_scenario_envelopes(...)` and
`StpaCoverageInput.from_scenario_envelopes(...)` adapt the real admitted
scenario envelopes into content-pinned observations. Taxonomy scenarios join
only through exact projectable `cand:v2` identities and may realize several
risk obligations; STPA scenarios join only through exact slot/ICA/`EXEC:*`
identity. An unknown identity fails closed.

Rejected and unresolved proposals, contradictions, and noncoverage relations
remain separate traceable diagnostics and cannot satisfy an obligation.
In particular, `accepted_resource_link` evidence proves shared resource
identity only and is restricted to `related_but_not_coverage`. Coverage-bearing
relations require independently reviewed exact-ID or curated mechanism
evidence; sharing a resource map link is never sufficient.
Explicit structural inapplicability requires reviewed evidence and cannot be
inferred from an absent relation. The validated resource-map attestation
carries the capability snapshot's entry-point and tool inventory completeness;
when an obligation's candidate resources depend on an `inferred_partial`
inventory, structural inapplicability additionally requires explicit other
authoritative evidence. Every matrix row and diagnostic cell carries
exact upstream artifact pins and record traces. Existing STPA scenario links
remain explicitly legacy observations; hybrid generation is `not_attempted`
and hybrid admission is `not_assessed` in v1. The artifact exposes separate
counts for review but no rate or blended score.
Its pin universe includes an explicit `capability-fact-snapshot-v1` artifact
pin matching the top-level `capability_snapshot_digest`.

The persistence adapter atomically writes
`hybrid-coverage-assessment.yaml`. There is intentionally no assessment CLI command: callers
adapt completed typed artifacts at the Python seam. Assessment, proposal, and
reconciliation are deterministic and construct neither a model client nor a
network connection. Product `run` invokes this verification after scenario
generation; standalone diagnostic `stpa-run` remains independent of it.

The STPA source chain must preserve security-constraint ownership explicitly:
Stage 2 accepts one closed responsibility collection with exact constraint
references, and ICA enumeration stops if any loss-analysis constraint has no
responsible controller.

## Advanced standalone STPA

`stpa-run` is retained for diagnostics, prompt qualification, and comparison.
It does not consider taxonomy obligations and is not equivalent to the normal
product `run`.

```bash
asago-scenario-generator stpa-run \
  --use-case use-case.txt \
  --risk-extraction risk-extraction.json \
  --output-dir output/my-system-stpa \
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

asago-scenario-generator stpa-run \
  --use-case use-case.txt \
  --risk-extraction risk-extraction.json \
  --output-dir output/my-system-stpa
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

Stage 5 asks for a typed stimulus and causal explanation. The compiler derives
the fixed action kind, resource roles, and carrier bookkeeping from that typed
choice. A file upload or traffic/load scenario is retained as analytical when
the supported execution routes cannot represent it; it is not relabelled as a
single direct prompt. The synthesis manifest reports candidate outcomes once
per exact scenario/slot/ICA identity and reports diagnostic-message count
separately.

Stage 5 also requires a closed adversary record on every candidate: who
attempts the unsafe behavior (`external_attacker`, `malicious_customer`,
`third_party_via_content`, or `none`) and what they gain; deterministic code
derives the delivery channel (`reaches_target_via`) from the stimulus, and
an analytical-only stimulus persists a null reach. A `kind: none`
candidate is a functional test: it is persisted under `scenarios/` for the
owner's information but never prepared for execution and never enters the
execution bundle. A `third_party_via_content` adversary additionally requires
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
bundle or artifact write failed is not `published`). Its `scenario_counts`
keeps three denominators independent: candidate counts (`requested`,
`attempted`, `unprocessable`, `published`, `functional_test`,
`publication_failed`), artifact counts (`generated` = published adversarial
artifacts only, `functional_specifications` = persisted functional
specifications), and draft counts (`drafts_returned`, `drafts_accepted`,
`drafts_rejected`, `drafts_held`) — all independent from the
diagnostic-message count. Artifact counts never stand in for `requested`:
two candidates that publish three artifacts are `completed`, not overcounted.
The product `run`
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

The STPA pipeline runs SP1 through SP3 and writes the combined report. A report
can also be regenerated independently:

```bash
asago-scenario-generator stpa-report --output-dir output/my-system-stpa
```

Canonical Stage 6 projection artifacts (`stpa-execution-projection-v2`, or
`stpa-execution-projection-v3` for a structured-omission run) can be
checked through the public validation command without reconstructing project
objects. The historical v1 reader remains available for audit-only validation;
it is not a product-run input or publication path:

```bash
asago-scenario-generator validate-stpa-projection \
  output/my-system-stpa/scenarios/canonical/SCN-001.projection.json
```

The retained execution seam prepares each execution projection through the
typed `prepare_execution_projection(...)` seam. It requires one intact,
source-pinned `ScenarioGenerationContext` and one explicit non-empty
`ExecutionRunIdentity`; Stage 5 and Stage 6 cannot bypass this validation.
Unknown semantic values are represented as typed binding placeholders, so
`semantic_binding_required` is derived from the validated projection rather
than accepted as caller-controlled metadata. Literal single-controller
action-value scenarios remain executable without state observation, a
multi-agent adapter, or a real-clock adapter unless their typed conditions
require one.

Scenario publication uses deterministic summaries by default: it needs no
Stage 6 model calls for narrative, attack-tree, or Gherkin presentation.
These summaries describe test hypotheses, not observed outcomes. Python callers
may explicitly request the optional generative presentation with
`run_sp3(..., render_presentation=True)`; execution qualification does not need it.
Stage 5 derives tool predicates from observed argument schemas and timing
relationships from explained event handles. Missing quantitative facts stay
unknown rather than receiving illustrative values.

Each projection also publishes at least one platform-neutral adversarial
stimulus requirement and the exact causal-factor IDs through which that content
may be expressed, and Stage 5 records one semantic execution contract with its
deterministic classification. In the retired bundle flow the artifact
generator bound that fixed meaning to an explicitly supplied target or
simulation profile; the handoff flow below replaces it with downstream-owned
design.

The normal product `run` publishes the versioned **scenario handoff** instead
of an execution bundle: the envelope over narrative, attack tree, Gherkin and
necessary metadata defined by
[`data/contracts/scenario-handoff/`](data/contracts/scenario-handoff/)
(schema `scenario-handoff-v2`), written under `scenarios/` with its matching
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

The execution projection and bundle machinery below is the retained
historical seam: `publish_execution_bundle(...)` and the retired presentation
paths validate archived artifacts read-only and are no longer the normal
product publication path.

`publish_execution_bundle(...)` writes the closed
`stpa-execution-bundle-v1` envelope and canonical scenario/projection pairs
atomically. A structured-omission run instead publishes the homogeneous
`stpa-execution-bundle-v2` with `stpa-execution-projection-v3` entries whose
omission outcomes carry the closed `stpa-omission-evidence-v1` carrier; a
bundle never mixes projection versions, and a legacy run's bundle-v1 bytes
are unchanged. Structured omission preparation checks the complete canonical
proposition, including the bound tool and absence direction, and requires the
run's validated snapshot digest when evidence cites state or observations.
Persisted verification also checks that carrier source pins equal the
projection's trace pins. Offline readers without the original snapshot check
internal consistency; they do not authenticate that snapshot's contents.
Initial entries are written before the canonical
`execution-bundle.json` index; updates stage entries under a deterministic,
content-addressed generation and leave the currently indexed bytes untouched
until that index is replaced last. YAML mirrors are written before the index,
making the JSON index the completion marker. The producer-owned schemas,
fixtures, expected violations, canonical digests, and lock are under
[`data/contracts/stpa-execution`](data/contracts/stpa-execution/); the consumer
must vendor those files byte-for-byte before compiling the bundle.

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
LLM endpoint. Live-model acceptance is opt-in with
`ASAGO_SCENARIO_GENERATOR_QA_PIPELINE=1` and is expected to fail visibly when
the configured endpoint is unavailable.

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
