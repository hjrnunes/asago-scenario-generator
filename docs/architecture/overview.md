# Architecture overview

Asago Scenario Generator has one shared domain and one supported product
workflow. Taxonomy supplies obligations to an STPA-led analysis; STPA is the
only scenario-generation authority.

## Shared domain

Pydantic models define capability profiles, reviewed taxonomy evidence,
projected attack-pattern candidates, STPA analysis artifacts, obligation
accounting, correspondence, and scenario realization. Named model-profile
loading lives in `model_profiles`; STPA provider construction remains behind
the STPA infrastructure boundary.

The capability profile's computed boolean fields (`has_persistent_memory`,
`multi_agent`, `hitl`) follow the contract in
[capability-profile-contract.md](capability-profile-contract.md): they are
derived from `kc_subcodes`, included in serialized output, and legacy input
values warn only when they conflict with the derived result.

Authoritative projection contracts (candidate-v2 identity, digest helpers,
capability-fact snapshots, and slot-matching policy) live in
`pipeline.projection_contracts`. Resource matching, qualification, allocation,
and the public `pipeline.projection` façade depend inward on that leaf.
Deterministic projection preflight and catalog qualification reuse the same
contracts without constructing a provider client.

Candidate identity, filter wire models, and origin canonicalization live in
`pipeline.candidate_models`. Expansion, rules, coverage planning, and
preflight consume that leaf rather than the `pipeline.candidates` façade.
Coverage-universe construction and
min-cost assignment live in `pipeline.coverage_planning_universe` and
`pipeline.coverage_planning_flow`; those leaves stay off the candidates and
projection façades. Queue construction and plan persistence remain in
`pipeline.coverage_planning` solely for read-only catalog qualification.

Authoritative attack-pattern models are split by responsibility
(`attack_pattern_contracts`, `attack_pattern_chain`,
`attack_pattern_projection`, `attack_pattern_digests`,
`attack_pattern_validation`) behind the historical
`models.attack_pattern` façade. Projection, preflight, catalog
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

The few neutral validation helpers still used by projection and catalog
qualification live directly under `pipeline` (`actor_access`,
`narrative_access`, `behavior_compiler`, and `leaf_budget`). They do not form a
scenario-authoring workflow and are not provider-capable.

The former taxonomy-led runner, generation stages, finalization controllers,
scenario-authoring prompts, reports, evaluation adapters, and their acceptance
surface have been deleted. A narrow read-only manifest-v3 audit seam remains
for catalog qualification and historical artifact inspection; it cannot write,
resume, or extend an old run. See
[legacy-taxonomy-generator-cleanup-inventory.md](legacy-taxonomy-generator-cleanup-inventory.md)
for the exact boundary.

## Taxonomy obligation planning (observational Phase 1)

The obligation planner is the shared-domain seam between reviewed taxonomy
inputs and the STPA product run. Its public interface is
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
reporting replaceable without reviving a second scenario-generation workflow.

## Obligation-aware synthesis composition

`pipeline.synthesis.run_synthesis` is the composition root for the product
run. `SynthesisInputs` carries the use case, complete
reviewed risks, typed qualification facts, one capability profile/snapshot,
and either a closed `TaxonomyObligationInputs` graph or its production
builder. Phase 1 planning always executes; a prebuilt plan is accepted only
as a resume checkpoint after the fresh plan and input pins validate.

The fixed order is capability preparation and snapshot pinning, Phase 1
planning, ordinary SP1 baseline, neutral-brief consideration, at most one
additive revision, one complete recheck only when that revision is `applied`,
final obligation-aware ICA filling, ordinary SP3 realization, and provisional
accounting, followed by offline Phase 2 verification. The shared provider adapter is constructed lazily after planning
and baseline preparation. An SP3 failure is recorded without discarding final
ICA or accounting evidence.

Provider prompts use closed, stage-specific views rendered by Jinja rather than serializing
durable artifacts into prose. Opaque IDs are accompanied by the exact local
meaning needed for the requested decision, while digests, paths, mapping
records, scores, and unrelated global context stay outside the prompt. A pure
preflight audits the final rendered prompt and its exact reference universe,
then checks it against the selected model profile's context window, reserved
completion, and safety margin. Oversized routing batches split canonically;
one oversized item becomes a typed local failure and is never silently
truncated. `calls.jsonl` and the synthesis manifest retain the prompt audit,
provider-reported usage, and the hashes of every obligation-aware top-level
template and included partial.

Each structural route carries independent typed mechanism-plausibility and
reviewed-risk-alignment decisions plus a plain mapping-strength label derived
from the exact mapping path. The raw mapping path never enters the prompt. A
plausible mechanism with `risk_alignment: mismatch` remains eligible for
ordinary STPA analysis, but accounting records `risk_pattern_mismatch` and
does not credit the obligation. Provider routes that would otherwise receive
credit pass through a compact mechanism/path verifier that sees only the
distinctive mechanism and exact selected structural descriptions. An adjacent
control or incomplete mechanism path remains a usable STPA route but records
`mechanism_path_unsubstantiated` and receives no obligation credit. ICA prose
length and repetition are
presentation diagnostics only: semantically valid findings remain available
with `ica_prose_quality_warning`.

Scenario generation receives one immutable `ScenarioGenerationContext` per
ICA. It contains only the selected loss, hazard, governing constraint, unsafe
action, obligation concern, and causal evidence. Stage 5 must retain the
selected concern and establish at least one causal factor. The model selects
only request-local causal handles; the deterministic adapter binds each handle
to its fixed factor kind and exact PM/FB/CA source. Coordination and controller
IDs remain explained context but cannot be published as causal-factor sources,
and every attacker intention must cite a handle with a declared factor.
Defender vulnerabilities use a second closed local-handle list with exact
cardinality, so the provider cannot omit a selected process-model belief or
replace its identity. All Stage 6 renderers consume that same context, so an
unrelated global constraint cannot leak into a scenario. An adversary may take
advantage of a declared structural failure without that prose being mistaken
for a new access path. Capability and access-path assertions are validated
through the typed causal evidence fields against the immutable context;
free-text verb matching is not a publication gate. Obligation pattern names,
concerns, and rationales are analysis provenance: `finding` means that STPA
found a related unsafe-control path, not that the taxonomy mechanism happened.
The ICA keeps the unsafe control condition mechanism-neutral unless the compact
STPA structure independently supplies that mechanism, and later scenario
renderers may use a mechanism only from exact causal or capability/access
evidence. The attack-tree hard template therefore starts from stale, missing,
late, or inaccurate state rather than pre-seeding poisoning, injection, or
fabricated-tool-result leaves.

Obligation-aware ICA filling follows the same ownership rule. The provider
returns one plain deviation sentence for a supplied slot; it does not choose a
deviation field or UCA category. The deterministic compiler applies the exact
`NOT_PROVIDED`, `INCORRECT`, `WRONG_TIMING`, or `WRONG_DURATION` category from
the authoritative slot before validating and publishing the ICA.

The root atomically publishes `taxonomy-obligation-plan.yaml`,
`obligation-consideration.yaml`, `obligation-accounting.yaml`,
`scenario-realization.yaml`, and `synthesis-manifest.yaml`. After scenario
realization it also projects the finished artifacts through the existing Phase
2 contracts and publishes `system-resource-map.yaml`,
`correspondence-proposals.yaml`, `correspondence-reconciliation.yaml`, and
`hybrid-coverage-assessment.yaml`. The automatic resource map is an exact
zero-link baseline pinned to the synthesis capability snapshot and final
control structure. An exact obligation/slot/ICA route becomes an unreviewed
`mechanism_enables_ica` proposal only when provisional synthesis accounting
credited its mechanism/path checks. Other exact route joins remain
`related_but_not_coverage`. Neither becomes an accepted relation without
separate explicit adjudication and the existing deterministic validation.
Phase 2 failure is retained as a final-stage diagnostic and cannot remove or
invalidate an admitted STPA scenario. Accounting joins
exact obligation/slot, ICA,
`EXEC:*`, hazard, and constraint evidence but makes no Phase 2 correspondence
or coverage claim. Scenario realization separately records whether that exact
ICA/obligation concern survived into an admitted scenario. Reporting keeps
structural findings separate from scenario realization and labels provisional
accounting separately from completed scenario generation. Accounting and
realization expose one closed terminal stop reason
per applicable obligation. The manifest/report replace the provisional
`addressed` marker with the later realized, generation-failed, or not-requested
outcome where scenario evidence exists, and show both the full applicable
denominator and survivor denominators. Provider call evidence separately
records response receipt, typed parsing, semantic validation, compilation,
publication, and terminal error codes; compatibility `success` is not the sole
stage-quality signal. Standalone diagnostic `stpa-run` does not import or
require synthesis artifacts.

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
product `run` nor standalone diagnostic `stpa-run` imports or requires it.

Task 2 adds the adjacent `pipeline.challenge_analysis.reconsider_stpa_challenge`
boundary. Its explicit boolean opt-in is evaluated before any adapter factory
is called. Offline preflight verifies the ledger, assessment digest/source
pins, selected challenge identity, prior-attempt set, exact taxonomy row, and
typed loss/control-structure authority. It then builds one content-addressed
`stpa-obligation-challenge-request-v1` containing the immutable original
decision, canonical `EXEC:*` identity, Phase 2 taxonomy context, and exact
loss, hazard, constraint, controller, and control-action context.

The caller-supplied adapter is the only provider-capable extension point. Its
effective controls name the profile, resolved model, positive deadline, and
temperature, with an attempt limit of one and zero automatic retries. A
completed response is exactly ICA, justified N/A, or unresolved. Additive ICA
validation reuses the STPA `ICAEnumeration.validate_against` seam and requires
the next canonical slot-relative ICA ID plus exact `EXEC:*`, hazard, and
constraint identities. Provider, protocol, and structural-validation failures
become a separate closed technical-failure result, never N/A or unresolved.

The canonical `stpa-obligation-challenge-analysis-v1` value retains exact
request/response digests and references, effective controls, call counts, and
the byte-equivalent original decision. Its schema permits zero correspondence
and coverage changes only and keeps hybrid generation/admission at
`not_attempted`/`not_assessed`. This Task 2 module performs no filesystem IO and
adds no CLI, report, run-directory placement, or import from ordinary
`stpa-run`.

Task 3 adds `pipeline.closed_loop_stpa.run_closed_loop_stpa` as the narrow
composition boundary. Its dependency direction is strictly Phase 2 assessment
to Task 1 ledger to Task 2 reconsideration. The caller supplies every policy
input and the adapter factory. Opt-out records selected targets as pending;
opt-in accounts for each selected target with one completed or technical Task
2 result. Exact resume accepts only a digest-valid prior run with the same
ledger, controls, loss analysis, and control structure, then reuses its results
without adapter construction.

The adjacent `stpa-obligation-closed-loop-run-v1` aggregate derives separate
selection, pending, attempt, outcome, technical-failure, and call counts. It
does not invent an overall status. The persistence leaf atomically writes one
`stpa-obligation-closed-loop-run.yaml` into a caller-chosen directory and
verifies it after reload. Neither the composition model nor seam imports a
generation runner, CLI, report, or persistence module. Product `run` and
diagnostic `stpa-run` remain unaware of all Phase 3 modules and artifacts.

## Phase 4 exact projection and composition boundary

Phase 4 Task 1 introduces the pure
`pipeline.hybrid_scenario_projection.resolve_hybrid_projection_units` seam.
It consumes one closed `HybridProjectionInputs` authority graph and resolves
only explicitly requested, already accepted Phase 2 relations. The seam does
not reconcile correspondence again and does not infer a relation from prose,
shared resources, counts, or taxonomy-row disposition.

The input graph keeps each source in its native identity scheme. Phase 1
taxonomy pins remain release/digest pins; ordinary artifacts use
artifact/schema/digest pins. Candidate materializations bind a complete
existing `ProjectionSnapshot` to the exact Phase 1 candidate-record digest.
Because one executable candidate can support several risk obligations, the
adapter emits one materialization per exact `(obligation_id, candidate_id)`
pair rather than treating `candidate_id` as globally unique in the plan.
The STPA attestation deep-copies and pins loss analysis, control structure,
ICA enumeration, and execution envelopes before they enter the neutral model.
Its source control structure must assign every loss-analysis security
constraint to at least one responsibility. Resolution additionally requires
the selected causal controller to carry every constraint named by the accepted
relation; absent ownership fails closed rather than being inferred from later
artifacts.
Correspondence comes only from a verified `ReconciliationResult`, paired with
the exact `ProposalSet` and `HybridCoverageAssessment`. Confirmed review and
bridge evidence are separately pinned and cannot reuse each other as
independent evidence.

For each requested relation, the resolver verifies the exact
scenario-realization row is coverage-bearing and matches the obligation and
selected candidate, then checks that the corresponding obligation row names
the same accepted relation. `related_but_not_coverage` is retained as the
typed `relation_not_coverage` exclusion. Missing or non-projectable
relation-local material also produces a typed exclusion; substituted or
malformed top-level authority fails closed.

The Task 1 result is a content-addressed collection of exact projection units
and exclusions. The pure
`pipeline.hybrid_scenario_projection.build_hybrid_scenario_projection_set`
seam then performs the in-memory Task 2 composition: it resolves through that
Task 1 boundary, applies the fixed bridge-kind/endpoint table, validates the
taxonomy, STPA, and bridge union as one directed acyclic graph, and returns
content-addressed projections with typed exclusions and diagnostics. Source
pins, trace references, and bridge evidence must close exactly over each
projection's authority set.

The composition seam does not render an artifact, add a CLI, make a model or
network call, assign a score, or decide execution readiness. Task 2b provides
the separate Python persistence adapter through
`write_hybrid_scenario_projection_set(...)` and
`read_hybrid_scenario_projection_set(...)`. It atomically publishes the exact
`hybrid-scenario-projection-set.yaml` filename and verifies the closed-model
reload, semantic digest, canonical bytes, and equality. Neither existing
generation workflow imports or requires the Phase 4 boundary.

Task 3 adds two independent offline checks. The acceptance path exercises the
complete projection and persistence behavior while an application-independent
reader recomputes artifact identities, digests, ordering, pin closure, and
typed exclusions. Separately,
`pipeline.hybrid_pilot.assess_hybrid_pilot_readiness` consumes one closed typed
authority graph and returns only exact readiness blockers and counts. Complete
semantic evidence must be bound through the verified provenance factory;
copying or relabelling the normative bookkeeping fixture cannot promote it.
The evaluator neither reads files nor creates provider or network clients.
Product `run` and diagnostic `stpa-run` remain unaware of both checks.

## STPA execution

The product `run` composes taxonomy-obligation planning with the STPA stages
described below. The advanced `stpa-run` command executes the same baseline
STPA stages without taxonomy-obligation completeness. Both paths construct
losses and hazards, the control structure, unsafe control actions, causal
factors, scenarios, evaluation, and reporting artifacts; only `run` is the
normal product workflow.

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

Generated product output is not source. Product runs persist the obligation,
STPA, accounting, realization, Phase 2, manifest, and report artifacts in their
requested output directory. Standalone diagnostic STPA persists its stage
artifacts and combined manifest/report. Retired taxonomy-generator output is
read-only historical data and is not accepted as a compatibility contract.
