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

## Taxonomy obligation planning (observational Phase 1)

The obligation planner is a shared-domain boundary between reviewed taxonomy
inputs and the existing generation workflows. Its public seam is
`plan_taxonomy_obligations(TaxonomyObligationInputs)`. The input is a typed,
immutable value containing risk cards, one capability/fact snapshot, the
authoritative attack-pattern catalog, pinned cross-taxonomy/SSSOM mappings,
qualification facts, a bounded projection budget, and compatibility policy.
The planner does not accept paths, construct a provider client, or import
STPA implementation modules. The file/CLI adapter loads the input and writes
the plan; it is not part of the pure planner.

The input carries two distinct mapping authorities: `mapping_pins.sssom` is the
taxonomy-context `mapping_set_digest`; `mapping_pins.obligation_edges` is the
`obligation-mapping-bundle-v1` digest over the complete typed cross-taxonomy
and SSSOM rows. Both pins are required.

The planner owns risk-to-pattern traversal, capability scope, qualification,
candidate projection disposition, canonical ordering, identity derivation, and
row/summary reconciliation. It must retain every reviewed risk, including a
risk with no actionable pattern as `governance_only`, and it must not use the
advisory candidate filter as an obligation denominator. A Phase 1 row has the
closed fields `obligation_id`, `risk_ref`, `taxonomy_chain`,
`attack_pattern_id`, `attack_pattern_semantic_digest`,
`scope_disposition`, `qualification_disposition`, `candidate_records`,
`correspondence_disposition`, and `evidence`. Correspondence is always
`not_assessed` here; it is not a scenario or coverage claim.

Implementation crosses inward through
`pipeline.projection_authoritative.project_authoritative_candidate_observations`.
That seam returns the established `ProjectionBatch` plus bounded observation
tails; `pipeline.projection.project_authoritative_candidates` continues to
return the existing `ProjectionBatch` with default deferred retention disabled,
so public generation behavior is unchanged. `budget_deferred` candidate
records are only concrete candidates derived and validated before
`max_derivation_work` is exhausted; aggregate overflow is a typed limitation,
never a fabricated identity. Projection issues and qualification traces persist
typed condition and precondition evaluations. Missing or explicitly unknown
qualification inputs persist `qualification_fact` evidence with `result:
unknown` and their corresponding `status`; an explicitly contradictory
required input persists `status: contradictory` with the contradictory
qualification rationale and classifies the obligation as
`contradictory_evidence`. When readings are mixed, contradictory takes
precedence over absent/unknown, while capability exclusion still takes
precedence over qualification status.

Structural projection rejections are also retained as deterministic,
non-runnable candidate observations. A concrete attempted binding preserves
its canonical ingress and resource bindings; an aggregate failure such as no
compatible resource preserves the typed issue and reason without inventing a
resource identity. The planner maps these observations to
`projection_infeasible` candidate records with typed projection evidence, so
the summary count reconciles directly to persisted rows while `ProjectionBatch`
and its generation-facing candidates remain unchanged.

Obligation identity is separate from display names, candidate IDs, STPA slot
and ICA IDs, and scenario IDs. It is framed from the risk ID, attack-pattern
ID and semantic digest, capability snapshot digest, and catalog/mapping pins.
Every persisted plan
records the capability snapshot and qualification-facts digests as well as
catalog/mapping pins. `TaxonomyObligationPlan` canonicalizes set-like
collections, preserves semantic order, computes a versioned semantic digest,
and rejects unknown fields, unsupported versions, and digest mismatches on
load. The persistence adapter writes via an atomic temporary-file rename and
loads the written artifact back through the closed model before reporting
success; no partial file is a valid plan.

Canonical tool and integration resources carry an optional reviewed
`supported_operations` set. Canonical-chain slots carry a closed
`required_operations` set and may require resources to be distinct from named
sibling slots. Projection first validates resource kind and typed compatibility,
then operation support: absent operation metadata produces
`unknown_resource_operation`, while a complete set that omits a requirement
produces `unsupported_resource_operation`. The obligation planner retains the
former as `missing_evidence` and the latter as `structurally_infeasible`.

Phase 2 consumes the plan through its model interface and adds a separately
versioned `SystemResourceMap`, explicit evidence-bearing correspondence
proposals, and deterministic reconciliation. The resource map is the closed
`system-resource-map-v1` sidecar with `links[]`, exact capability and control
structure digest pins, typed `CanonicalResourceReference` and RESP/PM/CA/FB/
CP/CL/CM references, relation-kind compatibility, provenance, evidence, and
authority. `validate_system_resource_map` accepts the map, one immutable
`CapabilityFactSnapshot`, and one `ControlStructure`; it performs no repair or
inference. `model_proposed` links can remain advisory but can never be
authoritative, and incomplete inventories remain unresolved rather than
receiving fuzzy fallbacks. The persistence adapter writes the canonical
`system-resource-map.yaml` artifact atomically. The resource map does not
change STPA artifacts or infer correspondence from prose. This dependency
direction keeps taxonomy planning, STPA generation, persistence, and hybrid
reporting replaceable and prevents either workflow from importing the other
workflow's implementation.

Correspondence is split into reviewable `correspondence-proposals-v1` and
`correspondence-reconciliation-v1` artifacts. A proposal names exact obligation,
the selected projectable taxonomy candidate, ICA slot, ICA, canonical `EXEC:*`
candidate, resource-link, hazard, constraint, evidence, and upstream-pin
identities. Reconciliation verifies that every claimed link belongs to that
selected candidate's own canonical bindings; missing, unknown, infeasible, or
substituted candidate witnesses fail closed. Deterministic validation and
explicit adjudication are both required before reconciliation materializes an
accepted relation. The source-pin record, proposal set, and reconciliation result each
name the same `capability_snapshot_digest` as the validated resource map and
Phase 1 plan; the field participates in each artifact's canonical digest and
substitution fails closed. Duplicate confirmations that imply one semantic
relation remain rejected typed audit records rather than collapsing or
crashing. Prose, advisory links, rejected proposals, unresolved proposals, and
`related_but_not_coverage` never become coverage. The proposal and
reconciliation YAML adapters publish `correspondence-proposals.yaml` and
`correspondence-reconciliation.yaml` atomically.
An `accepted_resource_link` evidence source establishes only shared system
identity. The closed evidence model therefore permits that source only with
`related_but_not_coverage`; a coverage-bearing relation requires independently
reviewed exact-ID or curated mechanism evidence. This prevents resource-map
joins from becoming a Cartesian semantic-coverage claim.
`pipeline.correspondence_evidence.derive_resource_link_correspondence_evidence`
is the deterministic adapter for this narrow join. It emits one exact
candidate/link/path witness at a time, ignores advisory and model-proposed map
links, and can emit only `related_but_not_coverage`.
`pipeline.correspondence.summarize_correspondence_calibration` projects an
independent adjudication set into exact review buckets and a precision
numerator/denominator. It grants no coverage and deliberately excludes
unresolved and unreviewed proposals from that denominator.

Reviewed decision artifacts are historical records bound to their recorded
packet and proposal-set digests. The `as_adjudication_set` projection requires
callers to provide both exact pins and rejects either mismatch before dropping
those pins into the reconciliation-only `AdjudicationSet`.
`pipeline.hybrid_coverage.assess_hybrid_coverage` is the final observational
projection seam. It consumes an intact obligation plan, a successful typed
resource-map validation attestation, a reconciliation result, a typed taxonomy
observation bundle, and a typed STPA
coverage bundle. `StpaCoverageInput.from_ica_enumeration` deterministically
projects the real ICA enumeration and pins its exact content digest; legacy
scenario observations must resolve to a slot, ICA, and canonical `EXEC:*`
identity. The seam returns one closed `hybrid-coverage-assessment-v1` value
with the three independent matrices from the source specification:

1. Structural consideration retains every deterministic UCA slot with its
   controller, action, UCA type, ICA identities, evidence, and one of `ica`,
   `justified_na`, or `unresolved`.
2. Taxonomy correspondence retains every Phase 1 obligation with risk/pattern
   identity, scope and qualification dispositions, accepted relation IDs,
   normative correspondence disposition, and typed gap.
3. Scenario realization retains every accepted relation together with its
   exact supporting proposal, obligation, risk, attack-pattern, and taxonomy
   candidate identities, plus observed legacy STPA scenario IDs, while hybrid
   generation remains `not_attempted` and hybrid admission remains
   `not_assessed`.

Only an accepted relation with matching accepted/confirmed reconciliation
evidence satisfies a cross-method row. Contradictions and
`related_but_not_coverage` remain findings. Rejected and unresolved proposal
outcomes are retained outside all coverage credit, and structural
inapplicability requires an explicit eligible decision. The successful
resource-map validation attestation carries the exact entry-point and tool
inventory completeness from its capability snapshot. Candidate resource kinds
select the relevant inventory per obligation; `inferred_partial` cannot support
a closed-world inapplicability decision without explicit other authoritative
evidence. Every row and
diagnostic cell carries upstream schema/digest pins and record traces.
The assessment names that same capability snapshot digest and includes an
explicit `capability-fact-snapshot-v1` artifact pin in every traceable pin
universe; both participate in its canonical digest.
The second public argument is the closed, successful
`SystemResourceMapValidation` attestation; a raw or invalid map fails closed.
Strict cross-artifact resolution applies to accepted relations. Defective
rejected/unresolved proposals remain global reconciliation diagnostics and do
not create coverage. Resource-map gaps are evaluated per obligation against
the canonical resource references on its candidate records; unrelated
authoritative links cannot close the gap.
Canonicalization makes slot and scenario observation order irrelevant; the
persistence adapter atomically publishes `hybrid-coverage-assessment.yaml`.
The report adapter renders that assessment directly and calculates no parallel
status, rate, or blended score.

`TaxonomyCoverageInput.from_scenario_envelopes(...)` observes admitted taxonomy
envelopes through their exact `cand:v2` identity and expands one scenario into
each Phase 1 obligation that contains that projectable candidate. Unknown
candidates fail closed rather than receiving a pattern- or prose-based match.
`StpaCoverageInput.from_scenario_envelopes(...)` observes real STPA envelopes
through the exact slot, ICA, and canonically derived `EXEC:*` identity. Both
adapters content-pin the complete supplied envelope collection and retain
record traces; they do not change either generation workflow.

`pipeline.hybrid_reconciliation.reconcile_taxonomy_and_stpa` is the external
composition facade from source spec §8.7. Its closed
`HybridReconciliationInputs` envelope contains the exact obligation plan, loss
analysis, control structure, ICA enumeration, validated-map attestation,
proposal set, explicit adjudications, and optional scenario observations. The
facade recomputes the proposal authority from those artifacts and fails closed
on substitution. It then calls deterministic correspondence reconciliation,
adapts the ICA enumeration with the same canonical digest used by authority,
and delegates only matrix construction to `assess_hybrid_coverage`. The pure
proposal, reconciliation, and assessment seams remain independently usable.

The assessment module imports shared domain artifacts only. It does not import
either generation runner, construct a provider client, or perform IO. Existing
taxonomy coverage sections remain generation-workflow reports; they are not a
Phase 2 reconciliation surface and are not reused to infer hybrid coverage.

## Phase 3 offline challenge ledger

Phase 3 begins behind a separate deterministic boundary. The public
`pipeline.challenge_ledger.build_stpa_challenge_ledger` seam consumes an intact
`HybridCoverageAssessment`, explicit `ChallengeEligibility` values naming one
exact obligation/STPA-slot pair each, an explicit non-negative budget, the
versioned `explicit-priority-v1` policy, and the assessment artifact identity.
It never infers a target from prose, a missing relation, or a shared resource.

Selection orders the explicit records by ascending supplied priority and then
by exact obligation and slot identity. Each target is retained once. Selected
and budget-excluded records both snapshot the original Phase 2 structural row,
including its ICA/N/A/unresolved disposition, ICA identities, evidence, trace
references, assessment digest, and upstream source pins. The closed
`stpa-obligation-challenge-ledger-v1` model derives its diagnostics and target
IDs from those records and rejects forged selection state, duplicated targets,
substituted pins, and digest mismatches.

The pure builder imports no provider, network, filesystem, generation runner,
or STPA orchestration module. The separate persistence adapter atomically
publishes `stpa-obligation-challenge-ledger.yaml` and reloads it through the
closed model. This Task 1 artifact records future work only: it performs no
reconsideration, writes no challenge outcome, changes no Phase 2 matrix, and
creates no correspondence, coverage credit, projection, or scenario. Neither
`generate` nor ordinary `stpa-run` imports or requires it.

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
