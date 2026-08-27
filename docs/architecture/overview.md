# Architecture overview

Asago Scenario Generator has one shared domain and two supported generation
workflows.

## Shared domain

Pydantic models define capability profiles, taxonomy evidence, projected
attack chains, attack trees, behavior specifications, scenario envelopes, and
run manifests. Shared LLM adapters, deterministic validators, evaluation, and
reporting sit around those contracts. Named model-profile loading lives in
`model_profiles` so generation configuration and STPA infrastructure both
depend inward on that leaf. The historical `stpa.infra.model_profiles`
import path remains a façade. Taxonomy prompt-message construction lives in
`llm.messages`. STPA keeps a structurally distinct local helper so the
clean-copy boundary stays intact.

The capability profile's computed boolean fields (`has_persistent_memory`,
`multi_agent`, `hitl`) follow the contract in
[capability-profile-contract.md](capability-profile-contract.md): they are
derived from `kc_subcodes`, included in serialized output, and legacy input
values warn only when they conflict with the derived result.

Generation lifecycle contracts (retry directives, causal provider controls,
stage call evidence, and typed attempt failures) live in
`pipeline.generation_contracts`. Stage adapters, lifecycle policy, and
persistence consume that boundary without importing one another's
implementation modules.

Authoritative projection contracts (candidate-v2 identity, digest helpers,
capability-fact snapshots, and slot-matching policy) live in
`pipeline.projection_contracts`. Resource matching, qualification, allocation,
and the public `pipeline.projection` façade depend inward on that leaf. The
envelope model and generate-stage orchestration import the same contract
leaf rather than the projection façade, so persistence validation and
stage adapters do not pull implementation modules. Projection drift,
realization, and semantic checks stay off that façade as well.

Finalization lifecycle types, retry budgets, and choice-queue policy live in
`pipeline.finalization_contracts`. Admission, gate contracts, snapshots,
parsimony, prebehavior checks, and persistence adapters depend inward on that
leaf instead of the `pipeline.finalization` controller.
Durable encoding uses `projection_contracts.canonical_json_bytes`; inventory
validation depends on persistence record modules rather than the persistence
façade.

Candidate identity, filter wire models, and origin canonicalization live in
`pipeline.candidate_models`. Expansion, rules, capping, coverage planning,
pipeline IO, preflight, and runner orchestration consume that leaf rather
than the `pipeline.candidates` façade. Coverage-universe construction and
min-cost assignment live in `pipeline.coverage_planning_universe` and
`pipeline.coverage_planning_flow`; those leaves stay off the candidates and
projection façades. Queue construction and plan persistence remain in
`pipeline.coverage_planning`.

Authoritative attack-pattern models are split by responsibility
(`attack_pattern_contracts`, `attack_pattern_chain`,
`attack_pattern_projection`, `attack_pattern_digests`,
`attack_pattern_validation`) behind the historical
`models.attack_pattern` façade. Projection, preflight, runner, catalog
qualification, taxonomy pins, and the behavior compiler consume those
leaves rather than the façade. Catalog-lineage source-catalog pinning lives
in `data.catalog_lineage_snapshot` so normal lineage validation does not
consult the mutable live catalog. Canonical realization derivation lives
in `models.realization`; the envelope block lives in
`models.projection_envelope`. Both consume attack-pattern leaves and
`pipeline.projection_contracts` rather than the attack-pattern or
projection façades.

Attack-complexity models and admission routing live in
`models.complexity`. The reviewed rule table and fail-closed admission
check live in `pipeline.complexity` and depend inward on those models
plus `pipeline.projection_contracts`, not the projection façade.

Scenario validation is split by responsibility (`validation_common`,
structure, phantom, insider, provenance, parsimony, goal, and semantic
leaves) behind the historical `pipeline.validation` façade. Those leaves
do not import the façade or IO-near modules. Narrative access-realization
and step-bound checks live in `pipeline.generate.narrative_access`;
narrative semantic draft contracts and compilation live in
`pipeline.generate.narrative_semantics`; actor draft compilation lives in
`pipeline.generate.actor_semantics`. Tests and acceptance import access
bounds, draft contracts, and zone-sequence derivation from those leaves
rather than the IO-near `generate.narrative` façade. Attack-tree transport, zone
enforcement, name resolution, and diversity helpers live in
`pipeline.generate.tree_transport`, `tree_validation`, `zones`, `names`,
and `diversity`; those leaves stay off the IO-near `generate.tree`
façade. Path enumeration, tool-execution grounding, and transport
normalization are imported from those leaves by tests and acceptance
rather than re-exported through `generate.tree`. Scenario versus
projected-step ATLAS identity lives in
`pipeline.technique_scopes`. Projection-envelope sidecars are
built by `pipeline.projection_block`. Validation, pre-behavior gates,
stage orchestration, and assembly consume those leaves instead of the
IO-near `generate.narrative`, `generate.actor`, and `generate.assembly`
façades.

Deterministic evaluation metrics (`consistency`, `diversity`, `gherkin`,
`grounding`, `plausibility`, `scorecard`, `versioned_metrics`) stay off
the persistence and finalization façades. Authoritative v3 scorecards
consume `persistence_plan`, `persistence_journal`, and
`finalization_gate_contracts`.

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

Tolerant SP1 response graphs remain raw until deterministic ID/reference
normalization produces valid typed artifacts; invalid intermediate Pydantic
objects are never serialized. Stage 1a classifies losses from either
intermediate container by typed provenance, deduplicates identical repeats,
and reports conflicting IDs as fatal stage errors. Stage 2 rejects empty
requirement/responsibility sets, and an exhausted fallback is fatal. The
STPA retry contract is bounded: Stage 2 retries a JSON-decoding failure or a
semantically empty requirement/responsibility result once, while Stage 1a
retries semantic dangling hazard/loss references once with concise validation
feedback. Each attempt is logged separately in
`calls.jsonl`; these retries do not change the manifest/result schemas or
logical stage call counts, and exhaustion remains fatal.
Stage 3 likewise retries a Pydantic-invalid slot response once with explicit
slot-consistency feedback. Stage 5 retains one concise retry for an isolated
completion-length failure; if that retry is also exhausted, the stage records a
fatal diagnostic and stops processing the remaining threats because repeating
the same structured-output deployment failure cannot improve the run.
public SP1 result and run-manifest schemas are unchanged: fatal diagnostics
use the existing `stage_errors` fields, while recoverable assembly repairs
remain in `stage_warnings`. STPA sampling resolves explicit arguments before
profile/environment values and defaults, and manifests persist the effective
non-secret settings.

Both workflows apply a 300-second request deadline by default, configurable via
the named-profile `timeout` field or `ASAGO_SCENARIO_GENERATOR_TIMEOUT`. Hidden
OpenAI SDK retries are disabled; all retry policy therefore remains explicit,
bounded, and observable in pipeline evidence.

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
