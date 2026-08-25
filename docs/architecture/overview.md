# Architecture overview

Asago Scenario Generator has one shared domain and two supported generation
workflows.

## Shared domain

Pydantic models define capability profiles, taxonomy evidence, projected
attack chains, attack trees, behavior specifications, scenario envelopes, and
run manifests. Shared LLM adapters, deterministic validators, evaluation, and
reporting sit around those contracts.

Generation lifecycle contracts (retry directives, causal provider controls,
stage call evidence, and typed attempt failures) live in
`pipeline.generation_contracts`. Stage adapters, lifecycle policy, and
persistence consume that boundary without importing one another's
implementation modules.

Authoritative projection contracts (candidate-v2 identity, digest helpers,
capability-fact snapshots, and slot-matching policy) live in
`pipeline.projection_contracts`. Resource matching, qualification, allocation,
and the public `pipeline.projection` façade depend inward on that leaf. The
envelope model imports the same contract leaf rather than the projection
façade, so persistence validation does not pull implementation modules.

Finalization lifecycle types, retry budgets, and choice-queue policy live in
`pipeline.finalization_contracts`. Admission, gate contracts, snapshots,
parsimony, prebehavior checks, and persistence adapters depend inward on that
leaf instead of the `pipeline.finalization` controller.
Durable encoding uses `projection_contracts.canonical_json_bytes`; inventory
validation depends on persistence record modules rather than the persistence
façade.

Candidate identity and filter wire models live in `pipeline.candidate_models`.
Expansion, rules, capping, coverage planning, and pipeline IO consume that
leaf rather than the `pipeline.candidates` façade.

Authoritative attack-pattern models are split by responsibility
(`attack_pattern_contracts`, `attack_pattern_chain`,
`attack_pattern_projection`, `attack_pattern_digests`,
`attack_pattern_validation`) behind the historical
`models.attack_pattern` façade. Catalog-lineage source-catalog pinning lives
in `data.catalog_lineage_snapshot` so normal lineage validation does not
consult the mutable live catalog.

Scenario validation is split by responsibility (`validation_common`,
structure, phantom, insider, provenance, parsimony, goal, and semantic
leaves) behind the historical `pipeline.validation` façade. Those leaves
do not import the façade or IO-near modules.

The taxonomy/risk workflow uses a semantic-author/compiler seam. The model
authors actor intent, narrative causality, attack-tree AND topology, and
concrete behavior interactions through request-local handles. Pure compilers
resolve those handles to projection-owned IDs, actions, zones, techniques,
realizations, postconditions, and Gherkin syntax. Semantic draft failure is a
candidate failure; deterministic code may replace presentation text but never
the required semantic structure. Finalization alone owns retries, and every
stage invocation makes exactly one provider call.
Accepted-draft evidence for all four stages persists the request and response
digests, request-local handle map, effective controls, validation result, and
any declared presentation fallback. A manifest can therefore distinguish a
fully model-authored scenario from a failed or cosmetically repaired draft.
Its `semantic_generation` summary states whether all four stages were accepted
and retains bounded `stage_records` evidence; the HTML report presents the same
semantic and presentation statuses separately.

## Taxonomy and risk-driven workflow

The `generate` workflow consumes a use-case description, policy risk
extraction, and SSSOM mappings. It derives a capability profile and threat
surface, expands and qualifies candidates, projects canonical chains, creates
scenario artifacts, and runs deterministic admission and evaluation gates.

Generation planning separates canonical ingress identity from durable
finalization-target identity. The default `exhaustive` policy creates one
one-choice target per qualified projected candidate, so an admission or
quarantine affects only that candidate and the remaining corpus continues.
The explicit `coverage` policy instead creates one bounded fallback queue per
feasible ingress and stops that target after its first admission. Coverage is
reported by canonical ingress in both modes; lifecycle transitions, persistence,
and resume are keyed by the distinct finalization target ID.

The grouped taxonomy path keeps failures local and observable. Candidate
filter responses use compact ordinals instead of canonical IDs. An
irreconcilable advisory filter retains all deterministic-rule-eligible
candidates with warning evidence; it cannot admit a scenario by itself.
Before authoritative projection, the immutable profile/fact snapshot is
checked for required architecture resources and qualification readings;
missing evidence stops generation with profile or qualification guidance.
The public `projection-preflight` command runs that readiness path and emits a
complete fact template without constructing a model client. Its fact inventory
distinguishes absent, explicitly unknown, stale, and contradictory readings
before the immutable snapshot is built. Omitted generation facts use an
explicit `omitted_compatibility` mode recorded in manifest configuration and
generation notes. The run manifest records status and admitted, quarantined,
and failed counts; the CLI returns nonzero for degraded completion or no
admitted scenarios.

## STPA workflow

The `stpa-run` workflow performs loss and hazard analysis, constructs the
control structure, enumerates unsafe control actions and threats, and produces
scenario, evaluation, and reporting artifacts. Its stages reuse shared
capability and infrastructure contracts while retaining STPA-specific models
and orchestration.

Post-SP3 execution projection exposes a platform-neutral
`CandidateExecutionEnvelope` for one unsafe control action. Its canonical
`EXEC:<controller>:<control-action>:<uca-type>` identity and UCA reference
retain structural traceability; causal factors use PM/FB/CA control-structure
IDs. An optional `TemporalActionVector` preserves input factor order with
canonical `TA-*` assertions and `S-*` steps, and empty factors produce no
temporal behavior. Assembly validates all factor namespaces against the
control structure before returning the envelope.

Stream B makes the projection contract executable. A deterministic
traceability validator (`stpa.scenario_prod.projection`) checks the canonical
projection document — schema version, candidate identity, UCA reference,
factor-to-assertion and factor-to-step mapping, canonical predicates, the
final unsafe-control-action step, and typed provenance — and returns typed
violations aligned with the taxonomy `projection_validation` contract.
Stage 6 narrative, attack-tree, and Gherkin prompts render the same
validator-derived projection alignment table (`stpa.scenario_prod.prompt_alignment`),
keyed by semantic structural IDs, when the optional `projection_alignment`
argument is supplied to their builders. The same canonical document is
exported as standalone JSON/YAML (`stpa-execution-projection-v1`) with stable
identifiers and typed provenance, and re-validated on load without project
objects. The public CLI command `validate-stpa-projection` applies that
standalone check to a JSON or YAML export and prints typed violations.

## Acceptance boundary

`features/` contains the behavior contract. `acceptance/refresh_snapshot.py`
uses the externally checked-out Acceptance Pipeline Specification tools to
create ignored JSON IR, DRY reports, and pytest entrypoints under
`build/acceptance/`. The committed runtime and handlers connect those generated
entrypoints to public project behavior.

Live LLM behavior is a separate opt-in boundary. Default unit and acceptance
gates must remain deterministic and offline.

## Persistence boundary

Generated product output is not source. Taxonomy/risk runs use immutable,
manifest-governed run directories. STPA runs persist stage artifacts and a
combined manifest/report in their requested output directory. Pre-rename output
is retained only in the archived source repository and is not accepted as a
compatibility contract.
