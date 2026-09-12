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
merged hazard graph is dense enough to distinguish scenarios (every loss has
a hazard, every constraint has a hazard, every hazard has a constraint, each
constraint/hazard pair shares a subject noun phrase, and every behavior class
owns a hazard). A failing graph
gets exactly one bounded revision call with the exact failing checks; a
second failure stops the run and is recorded in the manifest.
`loss-analysis-gates.yaml` carries the recorded evidence.

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

For single-agent targets, supplying a target profile also switches Stage 2:
instead of the model-authored control structure, `run` derives it
deterministically from the observed target (one assistant controller, one
action per observed tool operation, a reply action, and capability-driven
conditionals), spends at most two bounded model calls on grounded
controller-purpose beliefs and constraint-action relevance, and records the
exact tool binding per action in a pinned sidecar that target realization
replays with zero model calls. Multi-agent targets and runs without a
profile keep the ordinary target-blind Stage 2. In target-derived mode,
scenario synthesis also changes: one grounded authoring call per
(constraint, action) candidate replaces the ICA enumeration, ICA
verification and correction, and Stage 5 BDI generation. The call drafts
scenarios against the observed target state and policy observations;
deterministic code validates every fact, tool, argument, and condition
account against typed rejection reasons, owns the deviation category,
identifiers, lineage, and the closed oracle templates in
`data/oracles/templates.yaml`, and assembles the contract with no repair
call. Obligation entries on a constraint (see `--loss-analysis` below) gate
which oracle kinds are offered: drafts cite one entry in `obligation_ref`,
a citation that contradicts the cited entry's kind or channel is rejected,
and an omission oracle compiles only when the constraint's direction is
reviewed, the cited required entry is realized by a tool call, and an
optional `run --reviewed-obligation-bindings PATH` file
(`reviewed-obligation-bindings-v1`) connects that entry to the action;
otherwise the draft is held as a persisted specification with a typed
reason and never compiled. Omission drafts also cite exact trigger evidence
from a supplied user turn, a used state fact, or a named observation. This
validates the source, not the author's claim that the rule requires the call;
the omission check stays conditional on independently establishing that duty.
The target-blind path is unchanged.

`run --target-observations PATH` optionally accepts normalized runtime-context
JSON from the standalone [capture workflow](scripts/qualification/README.md).
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

Publish a deterministic obligation ledger from a pinned snapshot without
contacting an LLM endpoint:

```bash
asago-scenario-generator plan-obligations \
  --snapshot obligation-snapshot.yaml \
  --output-dir output/obligation-plan
```

The planner's external seam is typed and deterministic:

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

Validate an analyst-authored system-resource map against the exact capability
fact snapshot and STPA control structure without contacting an LLM endpoint:

```bash
asago-scenario-generator validate-system-resource-map \
  --capability-snapshot capability-fact-snapshot.yaml \
  --control-structure control-structure.yaml \
  --map system-resource-map.yaml \
  --output-dir output/system-resource-map
```

The validator consumes the closed `system-resource-map-v1` contract, checks
both source digests and every typed link, and publishes diagnostics plus the
canonical `system-resource-map.yaml` atomically when validation succeeds. It
never infers correspondence or contacts a model.

Propose and reconcile STPA-to-taxonomy correspondence from a resource map
and source artifacts without contacting an LLM endpoint:

```bash
asago-scenario-generator propose-correspondence \
  --map system-resource-map.yaml \
  --artifacts correspondence-artifacts.yaml \
  --capability-snapshot capability-snapshot.yaml \
  --control-structure control-structure.yaml \
  --output-dir output/correspondence

asago-scenario-generator reconcile-correspondence \
  --map system-resource-map.yaml \
  --proposals output/correspondence/correspondence-proposals.yaml \
  --adjudications correspondence-adjudications.yaml \
  --capability-snapshot capability-snapshot.yaml \
  --control-structure control-structure.yaml \
  --output-dir output/correspondence
```

Both adapters validate the map against the exact capability snapshot and
control structure before proposing or reconciling. The optional adjudication
file is a typed `AdjudicationSet` envelope with a `decisions` collection; both
JSON and YAML inputs are accepted according to the file suffix.

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

# The source-spec facade performs the same deterministic composition while
# binding proposals to the exact plan, loss, control, ICA, and map artifacts.
assessment = reconcile_taxonomy_and_stpa(hybrid_reconciliation_inputs)
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
a missing, unknown, infeasible, or mismatched candidate/link witness. The
deterministic `derive_resource_link_correspondence_evidence(...)` adapter emits
only `related_but_not_coverage`: it finds exact shared-resource associations
for review but never decides that the taxonomy and STPA mechanisms provide the
same coverage.

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
`HybridReconciliationInputs` is the closed, immutable orchestration envelope.
`reconcile_taxonomy_and_stpa(...)` verifies its exact proposal authority,
performs explicit deterministic reconciliation, adapts the real ICA
enumeration, and delegates matrix construction to `assess_hybrid_coverage`.
The lower-level proposal, reconciliation, and assessment seams remain public
for testing and staged workflows; the facade adds no inference, persistence,
provider, or network behavior.

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
`hybrid-coverage-assessment.yaml`, and
`report.hybrid_coverage.render_hybrid_coverage_report` renders only those domain
rows and traces. There is intentionally no assessment CLI command: callers
adapt completed typed artifacts at the Python seam. Assessment, proposal, and
reconciliation are deterministic and construct neither a model client nor a
network connection. Product `run` invokes this verification after scenario
generation; standalone diagnostic `stpa-run` remains independent of it.

### Phase 3 offline challenge ledger

The first Phase 3 slice records a bounded request for STPA to reconsider an
exact taxonomy-obligation/STPA-slot pair. It does not run the reconsideration.
`build_stpa_challenge_ledger(...)` consumes one intact
`HybridCoverageAssessment`, explicit `ChallengeEligibility` records, an
explicit non-negative budget, the fixed `explicit-priority-v1` policy, and an
artifact ID for the assessment. Smaller supplied priority values are selected
first, with obligation and slot identity as deterministic tie-breakers.

Every selected or budget-excluded record retains the original structural row,
ICA identities, disposition, evidence, traces, and all Phase 2 source pins.
The builder never derives eligibility from an unresolved row or prose. It
cannot create correspondence, coverage credit, or a hybrid scenario, and it
constructs no provider client. A budget-excluded target remains visible as
`not_selected_budget`; it is not relabelled as an unresolved STPA decision.

`write_stpa_challenge_ledger(...)` atomically publishes the closed,
digest-verified `stpa-obligation-challenge-ledger-v1` artifact as
`stpa-obligation-challenge-ledger.yaml`; `read_stpa_challenge_ledger(...)`
requires that normative filename and verifies the digest on load. Neither
product `run` nor diagnostic `stpa-run` reads or requires this Phase 3
artifact. Task 1 has no CLI and performs no STPA/model call.

The second Phase 3 slice adds the only provider-capable extension point:
`reconsider_stpa_challenge(...)`. It receives one selected ledger target, the
exact Phase 2 assessment, typed loss/control-structure authority, explicit
`ChallengeAnalysisControls`, and a caller-supplied adapter factory. When
`opted_in=False`, it returns before constructing the adapter. When enabled, it
makes one adapter attempt with zero automatic retries and validates one ICA,
justified N/A, or unresolved result.

An ICA is additive: it uses the next canonical slot-relative ICA identity,
retains the exact `EXEC:*` identity, and validates hazard/constraint references
through the existing STPA structural validator. Provider, protocol, or identity
failures are separate typed technical failures; they are never rewritten as an
STPA conclusion. The content-addressed
`stpa-obligation-challenge-analysis-v1` result retains the request/response
evidence, effective controls, and original decision while fixing
correspondence/coverage changes at zero and hybrid generation/admission at
`not_attempted`/`not_assessed`. Task 2 remains an internal Python seam: it adds
no CLI, report, run-directory policy, or change to ordinary `stpa-run`.

The final Phase 3 slice composes those boundaries through
`run_closed_loop_stpa(...)`. A caller supplies the exact assessment, explicit
eligibility, budget, opt-in, STPA authority, controls, and adapter factory. The
seam delegates selection to Task 1 and each selected attempt to Task 2. Opt-out
retains selected targets as pending without constructing an adapter. An exact
rerun may supply its prior `ClosedLoopStpaRun`; validated attempts are reused
and never retried.

`write_closed_loop_stpa_run(...)` atomically publishes the single canonical
`stpa-obligation-closed-loop-run.yaml` record in a caller-chosen directory.
That record contains the ledger, adjacent results, and separate exact counts;
it deliberately has no combined success/degraded score. It permits only zero
correspondence and coverage changes and retains hybrid generation/admission as
`not_attempted`/`not_assessed`. Phase 3 adds no CLI or report. The audited
Klarna/NHS fixture retains the old taxonomy IDs only as lineage evidence and
infers zero challenge targets from them.

### Phase 4 exact projection resolution and composition

Phase 4 starts with a deliberately narrow, offline resolver. It does not yet
build or run a combined scenario. `resolve_hybrid_projection_units(...)`
checks whether an already accepted Phase 2 relation has all of the exact
material needed for later composition: the Phase 1 obligation and projected
candidate, the matching STPA slot/ICA/`EXEC:*` path, the successful resource
map, the confirmed review, and independently pinned bridge evidence.

Callers first use the typed artifact factories in
`pipeline.hybrid_scenario_projection` to copy and pin those existing
authorities, then pass one closed `HybridProjectionInputs` value to the
resolver. A coverage-bearing relation either becomes one content-addressed
`HybridProjectionUnit` or one typed, traceable exclusion. A confirmed
`related_but_not_coverage` relation always remains a
`relation_not_coverage` exclusion. Cross-paired, substituted, malformed, or
unverified top-level authorities fail closed.

The in-memory Task 2 composition seam is
`build_hybrid_scenario_projection_set(...)`. It consumes the same closed input,
uses the Task 1 resolver, applies the fixed typed bridge table, and validates
the combined taxonomy, STPA, and bridge graph as one DAG. It returns
content-addressed projections alongside the unchanged typed exclusions and
diagnostics; it does not turn them into scores or execution decisions.

Task 2b provides the Python persistence seam:
`write_hybrid_scenario_projection_set(...)` and
`read_hybrid_scenario_projection_set(...)`. It atomically publishes the exact
`hybrid-scenario-projection-set.yaml` filename, reloads through the closed
model, and verifies the semantic digest, canonical bytes, and equality before
reporting success. Persistence remains offline and has no reporting, CLI,
model-call, or network behavior. Product `run` and diagnostic `stpa-run`
remain independent of Phase 4.

Task 3 proves that complete contract through deterministic Gherkin and an
independent YAML reader. The pure
`assess_hybrid_pilot_readiness(...)` seam separately checks whether an exact,
target-scoped future semantic pilot has fresh scenario identities, complete
Phase 1/2/STPA/review authority, and verified run provenance. It reports typed
blockers and exact counts; it never runs generation or contacts a provider.
The committed projection fixture is bookkeeping evidence only and cannot make
a pilot ready. The current Klarna and NHS evidence remains not ready because
the old taxonomy envelopes have zero corrected-plan joins and the corrected
assessments contain no accepted coverage-bearing relations. The required
future procedure is recorded in
`ai/findings/stpa-taxonomy-phase4-live-pilot-runbook.md`.

The STPA source chain must preserve security-constraint ownership explicitly:
Stage 2 accepts one closed responsibility collection with exact constraint
references, and ICA enumeration stops if any loss-analysis constraint has no
responsible controller. Phase 4 also verifies that each relation's constraint
is recorded on its selected causal controller; it never repairs or infers that
trace later.

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

Canonical Stage 6 projection artifacts (`stpa-execution-projection-v2`) can be
checked through the public validation command without reconstructing project
objects. The historical v1 reader remains available for audit-only validation;
it is not a product-run input or publication path:

```bash
asago-scenario-generator validate-stpa-projection \
  output/my-system-stpa/scenarios/canonical/SCN-001.projection.json
```

Product `run` prepares each execution projection through the typed
`prepare_execution_projection(...)` seam. It requires one intact,
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
may be expressed. Stage 5 also records one semantic execution contract and its
deterministic classification. The artifact generator later binds that fixed
meaning to an explicitly supplied target or simulation profile, then compiles
prompt-side history that ends before the target response.

`publish_execution_bundle(...)` writes the closed
`stpa-execution-bundle-v1` envelope and canonical scenario/projection pairs
atomically. Initial entries are written before the canonical
`execution-bundle.json` index; updates stage entries under a deterministic,
content-addressed generation and leave the currently indexed bytes untouched
until that index is replaced last. YAML mirrors are written before the index,
making the JSON index the completion marker. The producer-owned schemas,
fixtures, expected violations, canonical digests, and lock are under
[`data/contracts/stpa-execution`](data/contracts/stpa-execution/); the consumer
must vendor those files byte-for-byte before compiling the bundle.

## Target-Grounded Gold Set Evaluation (Phase 0)

Target-grounded scenario evaluation uses fixed, hand-authored gold sets to
measure pipeline recall deterministically against concrete targets. The
MiniKlarna reference set is in [`data/gold/miniklarna/gold-cases.yaml`](data/gold/miniklarna/gold-cases.yaml).
Runs are scored with `uv run python -m scripts.gold.score_run --run <run_dir>`
and reviewed with `uv run python -m scripts.gold.review_run`. See
[`scripts/gold/README.md`](scripts/gold/README.md) and
[`ai/findings/target-grounded-scenario-generation-spec-2026-09-07.md`](ai/findings/target-grounded-scenario-generation-spec-2026-09-07.md).

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
