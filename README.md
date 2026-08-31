# Asago Scenario Generator

Asago Scenario Generator creates structured adversarial scenarios for AI and
agentic systems. It supports two peer workflows:

- **Taxonomy and risk driven** — maps policy risk extraction through NIST,
  OWASP, and MITRE ATLAS data before generating scenarios, Gherkin behavior
  specifications, evaluation evidence, and an HTML report.
- **STPA based** — models losses, hazards, control structures, unsafe control
  actions, and enriched threats before producing scenarios and an STPA report.

Both workflows are supported product surfaces. Neither is a compatibility or
legacy mode.

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
file is ignored because it may contain credentials. Both `generate` and
`stpa-run` accept named profiles. STPA sampling values use the same precedence
through both routes: an explicit Python/CLI argument, then the selected profile
or environment value, then the client default. The CLI currently exposes
`--temperature` as the run-wide explicit sampling override. Invalid numeric or
boolean environment values fail before the first model call.
Requests have a 300-second application default deadline. Named-profile
`timeout` and `ASAGO_SCENARIO_GENERATOR_TIMEOUT` values override that default.
The SDK's implicit retries are disabled so retry decisions remain bounded and
visible in pipeline evidence.

Gemma 4 deployments used for structured generation need a compact JSON grammar
configuration to avoid valid-prefix responses stalling on whitespace. See the
[Gemma 4 vLLM runtime notes](docs/operations/gemma4-vllm-structured-output.md)
for the required serving argument and rollout guidance.

## Taxonomy and risk-driven generation

```bash
asago-scenario-generator generate \
  --use-case @use-case.txt \
  --risk-extraction risk-extraction.json \
  --sssom mappings.sssom.tsv \
  --output-dir output/my-system \
  --model-profile gemma4-local \
  --presentation-fallback allow
```

The pipeline profiles capabilities, determines the threat surface, qualifies
and projects candidates, generates scenario artifacts, evaluates them, and
writes an immutable run directory beneath the requested output collection.
Generation is exhaustive by default: every qualified projected candidate is
given an independent finalization target and can produce one admitted scenario.
Use `--generation-mode coverage` for a bounded smoke run that keeps one queue
of at most three candidates per feasible ingress and stops each queue after its
first admission.

`--max-scenarios-per-pattern N` applies after projection and deduplication. In
exhaustive mode it retains at most `N` qualified candidates per attack pattern,
round-robin across ingress points before taking a second candidate from one
ingress. Omitting the option means no pattern cap.

Run counts describe successive funnel stages: expanded candidates have not yet
passed filtering; qualified candidates have passed authoritative projection;
attempted candidates entered finalization; admitted candidates produced a
scenario; quarantined candidates exhausted generation or failed admission.

Automatic capability inference produces an `inferred_partial` Stage 1 profile.
Authoritative projection may also require operator-reviewed architecture data,
especially `trust_boundaries`, `external_integrations`, and explicit
qualification facts. For a substantive run, pass that reviewed profile with
`--profile` and, where applicable, fact readings with `--qualification-facts`.
An inferred-only run can finish with zero scenarios when the required
architecture evidence is unavailable.

Inspect the exact requirements without contacting an LLM endpoint:

```bash
asago-scenario-generator projection-preflight \
  --use-case @use-case.txt \
  --risk-extraction risk-extraction.json \
  --sssom mappings.sssom.tsv \
  --profile capability-profile.yaml \
  --qualification-facts qualification-facts.yaml \
  --facts-template qualification-facts.complete.yaml
```

The command reports every required resource and fact as structured JSON. Fact
states distinguish a missing reading (`absent`), an explicit undecided reading
(`unknown`), a supplied fact no longer required by the selected patterns
(`stale`), and incompatible readings for one fact (`contradictory`). A requested
facts template contains unknown values for operator review and is never allowed
to overwrite an existing file. If generation omits `--qualification-facts`, the
manifest records `qualification_facts_mode: omitted_compatibility`; command
output and the returned pipeline result also explain that unresolved conditions
are deferred to authoritative projection.

`--presentation-fallback` accepts `allow` (the default) or `forbid`. Allowing
fallback permits only cosmetic substitutions such as a missing narrative
title; it records a `presentation_fallback:` warning and produces
`completed_with_warnings`. It never synthesizes actor intent, narrative beats,
attack-tree topology, behavior interactions, or assertions.

Do not use process exit alone as the live-run success criterion. Inspect the
generated `run-manifest.yaml` and finalization inventory for admitted scenarios
and recorded errors. The manifest's `semantic_generation` block summarizes
whether every admitted candidate has accepted provider semantics for actor,
narrative, tree, and behavior; its `stage_records` retain the bounded
per-attempt evidence. The HTML report renders those stage outcomes and identifies
presentation fallback separately.

Useful companion commands include `projection-preflight`, `plan-obligations`,
`validate-system-resource-map`, `propose-correspondence`,
`reconcile-correspondence`, `profile`, `resume`, `eval`, `report`,
`qualify-catalog`, `validate-catalog-qualification`, and
`validate-stpa-projection`. Run `asago-scenario-generator --help` for the
complete interface.

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
network connection. `generate` and `stpa-run` continue to work independently
without any Phase 2 inputs or outputs.

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
requires that normative filename and verifies the digest on load. The normal
`generate` and `stpa-run` commands do not read or require this artifact. Task 1
has no CLI and performs no STPA/model call.

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
model-call, or network behavior. Ordinary `generate` and `stpa-run` remain
independent of Phase 4.

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

## STPA-based generation

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
temperature, `top_p`, `top_k`, guided-decoding state, and request timeout. API
keys and header values are never included.

Stage 2 retries a semantically empty requirement or responsibility response
once with corrective feedback. Stage 3 likewise retries a schema-invalid slot
response once.
If Stage 5 reaches the completion-length limit on both its normal and concise
retry attempts, it records a fatal diagnostic and aborts the remaining threats
instead of repeating a likely deployment-level structured-output failure.

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

Canonical Stage 6 projection artifacts (`stpa-execution-projection-v1`) can be
checked through the public validation command without reconstructing project
objects:

```bash
asago-scenario-generator validate-stpa-projection \
  output/my-system-stpa/scenarios/canonical/SCN-001.projection.json
```

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
