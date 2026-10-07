# Architecture overview

Asago Scenario Generator has one shared domain and one supported product
workflow. Taxonomy supplies obligations to an STPA-led analysis; STPA is the
only scenario-generation authority.

## Shared domain

Pydantic models define capability profiles, reviewed taxonomy evidence,
projected attack-pattern candidates, STPA analysis artifacts, obligation
accounting, and scenario realization. Named model-profile
loading lives in `model_profiles`; STPA provider construction remains behind
the STPA infrastructure boundary.

The capability profile's computed boolean fields (`has_persistent_memory`,
`multi_agent`, `hitl`) follow the contract in
[capability-profile-contract.md](capability-profile-contract.md): they are
derived from `kc_subcodes`, included in serialized output, and legacy input
values warn only when they conflict with the derived result.

Authoritative projection contracts (candidate-v2 identity, digest helpers,
capability-fact snapshots, and slot-matching policy) live in
`pipeline.projection_contracts`. Resource matching, qualification, and
allocation depend inward on that leaf.

Authoritative attack-pattern models are split by responsibility
(`attack_pattern_contracts`, `attack_pattern_chain`,
`attack_pattern_projection`, `attack_pattern_digests`,
`attack_pattern_validation`) behind the historical
`models.attack_pattern` façade. Projection and taxonomy pins consume those
leaves rather than the façade.

The former taxonomy-led runner, generation stages, finalization controllers,
scenario-authoring prompts, reports, evaluation adapters, and their acceptance
surface have been deleted. Decision 52 also removed the read-only manifest-v3
audit seam and the `qualify-catalog` and `validate-catalog-qualification`
commands. See
[legacy-taxonomy-generator-cleanup-inventory.md](legacy-taxonomy-generator-cleanup-inventory.md)
for the exact boundary.

## Current ownership and historical seams

The normal producer `generate` publishes one semantics-only `scenario-handoff-v3`.
Version 2 added the Stage 5 `discriminating_condition`, its code-owned
`condition_check`, and an optional `condition_omitted_reason` for a scenario
published without its condition. Version 3 adds the binding of that condition
against the target-observation facts: the required `tool_call_condition_status`
(`bound`, or `not_executable` with a reason code and detail) and, only when
bound, the `tool_call_condition`, whose comparisons hold only `argument` and
`literal` operands. The `handoff-v1` and `handoff-v2` kits and digest domains
stay unchanged. `scripts/gen_handoff_kit.py` regenerates the v2 and v3 kits
and the lock; the v2 kit must come out byte-identical.
The producer owns STPA lineage, the selected semantic failure criterion, safe
alternatives, supported causal hypotheses, and the narrative, causal tree,
structured Gherkin, and native feature derived from that semantic account. It
does not own concrete user messages, target setup, detector expressions,
delivery configuration, or executable artifact compilation.

The consumer `generate` command owns concrete user text or user-only history,
target-context binding, required-argument delivery, setup, detector and
fidelity decisions, freezing, and compilation. The runtime owns delivery of
the frozen content, immediate pre-dispatch dependency checks, command/reply
receipts, and separate backend/state observations. A command-level detector
does not establish a completed backend effect.

The current workflow is producer `generate` → `scenario-handoff-v3` →
consumer `generate` → consumer `check`. The dated source-cited accounting
corrections and independent evidence axes are in
[the R9 reconciliation report](../development/qualification-reports/r9-reconciliation-2026-09-17.md).

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
`scope_disposition`, `qualification_disposition`, `candidate_records`, and
`evidence`. A row is not a scenario or coverage claim.

Implementation crosses inward through
`pipeline.projection_authoritative.project_authoritative_candidate_observations`.
That seam returns the capped `ProjectionBatch` plus bounded observation
tails. `budget_deferred` candidate
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

## Obligation-aware synthesis composition

`pipeline.synthesis.run_synthesis` is the composition root for the product
run. `SynthesisInputs` carries the use case, complete
reviewed risks and typed qualification facts. The `prepare_capability` and
`build_taxonomy_inputs` adapters in `SynthesisAdapters` derive the one
capability profile/snapshot and the closed `TaxonomyObligationInputs` graph.
Phase 1 planning always executes; a run never resumes from a prior plan.

The fixed order is capability preparation and snapshot pinning, Phase 1
planning, ordinary SP1 baseline, neutral-brief consideration, at most one
additive revision, one complete recheck only when that revision is `applied`,
final obligation-aware ICA filling, ordinary SP3 realization, and provisional
accounting. The shared provider adapter is constructed lazily after planning
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
The contextual provider supplies one causal statement per declared handle.
Defender-belief annotations are derived from that statement's exact PM source;
the provider does not separately rewrite it. An undeclared PM is marked as not
selected in this scenario, not as proven free of vulnerabilities. The public
BDI result retains complete belief annotations and the legacy non-contextual
provider seam is unchanged. The deterministic summary renderer consumes that
same context, so an unrelated global constraint cannot leak into a scenario. An adversary may take
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
the authoritative slot before validating and publishing the ICA. The prompt
view carries that slot's action temporality and a closed local reference slice;
the provider is never asked to infer a value that deterministic validation
already owns. Nested structural-revision objects are validated before merge,
and the run distinguishes a requested revision from one actually applied.

The root atomically publishes `taxonomy-obligation-plan.yaml`,
`obligation-consideration.yaml`, `obligation-accounting.yaml`,
`scenario-realization.yaml`, and `synthesis-manifest.yaml`. Accounting joins
exact obligation/slot, ICA,
`EXEC:*`, hazard, and constraint evidence but makes no correspondence
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
stage-quality signal. Scenario candidate outcomes are counted once by exact
scenario/slot/ICA identity, separately from their possibly multiple diagnostic
messages. An adapter without candidate outcomes reports those counts as
unknown rather than treating error strings as candidates.

The synthesis manifest derives a stable `run_status` from those candidate
records. Completion is candidate-terminal: `completed` means every requested
candidate resolved as `published` (its handoff/artifact publication succeeded)
or `functional_specification` (a functional specification persisted);
`no_candidates` is a valid analysis with no eligible candidates; `failed`
means candidates were attempted but produced zero published scenarios or
persisted functional specifications; and `degraded` records partial or
unattempted yield. A compiled adversarial spec whose publication failed is a
`publication_failed` candidate: attempted, never yielded, and never counted
in `generated`. Candidate counts, artifact counts (`generated`,
`functional_specifications`), and draft counts stay independent denominators.
The product `generate` persists and
reports its diagnostic/accounting sidecars before returning non-zero for the
attempted zero-yield status.

Baseline assembly, heuristic, solution-neutrality and post-revision findings
are retained with their source category in synthesis `stage_warnings` and the
report's Analysis diagnostics section. Later stage-manifest writes must not
erase them. These diagnostics do not change candidate counts or claim that a
known analysis gap was resolved merely because scenarios were published.

## STPA execution

Stage 2 runs the target-blind coordination call described below for every
input. A supplied execution target profile, single-agent or multi-agent,
never selects a different Stage 2 algorithm; the observed target enters
later as enrichment evidence through control-action enrichment and target
realization.

Security constraints may carry explicit obligation entries (owner ruling
Q30, 2026-09-10): a `required` entry names a mandated behavior, the rule
span it reads, and the channel that would realize it (`realized_by`); a
`forbidden` entry names a prohibited behavior, its span, and the channel a
violation would take (`violated_via`). The channel fields are
kind-exclusive, `unknown` is the permissive default, a forbidden entry may
be marked `observation_role: proxy` with the `source_outcome` it stands
for, and a required entry may record the `completion` an oracle does not
observe. A forbidden entry that names a `source_outcome` without the proxy
mark goes to the targeted obligation repair, which accepts exactly one of
two edits: declare the proxy and keep the outcome, or remove the outcome
and keep the role. A repaired entry that leaves out a channel field it
was not asked to change keeps the original channel; an explicit different
value is still rejected. The constraint's failure direction is computed from its entries
(`required`, `forbidden`, `mixed`, or `unresolved`) under a
`direction_authority` stamp: deterministic code restamps every derived or
revision-merged graph `proposed` and clears wire-carried reviewer marks, so
only a pinned graph carries `reviewed` with its reviewer stamp.

Omission trigger evidence is source-addressed: a particular prepared user turn,
a used state-fact path, or a uniquely named observation content record. Exact
quotation validation replaces the former reference-name substring check.
The trigger sentence remains an author interpretation of the cited obligation;
source validation does not authorize that interpretation. The scenario
specification keeps the validated `OmissionEvidenceBasis` beside a short
semantic proposition that holds the trigger sentence only; exact quotations,
locators, meanings, source attestations, the trigger digest, and the
unresolved applicability stamp stay in the typed basis, never mixed back into
the proposition. Conversation evidence binds each quotation to its authored
turn. State-fact and observation entries pin the target-observation snapshot
digest. Absence alone remains inconclusive without
independently established applicability, and citations establish source
presence only. Historical drafts without evidence stay readable but cannot
pass the current omission validator through the old substring fallback.
Evidence that exceeds the closed carrier limits (quotation, trigger, entry
count, or total size) holds as `trigger_evidence_unrepresentable` with the
trigger and exact citations retained in the authored record; a quotation the
delivery cannot attest holds as `delivery_evidence_mismatch`, and a missing
prepared text, unreferenced turn, or unavailable snapshot holds as
`delivery_evidence_unresolved`. No quotation is truncated, no weaker proxy is
substituted, and the six projection cross-checks (`omission_evidence_missing`,
`omission_evidence_unexpected`, `stimulus_delivery_mismatch`,
`prepared_text_mismatch`, `snapshot_digest_mismatch`,
`omission_evidence_invalid`) fail closed before publication. A `kind: none`
functional specification may retain a validated carrier for review, but it
never produces an executable v3 projection.

The short omission proposition must exactly equal the deterministic rendering
of the carrier trigger, the outcome's owned target-action operation, the absence
direction, and the fixed applicability caveat. A trigger substring or matching
hash alone is insufficient. Preparation requires the expected validated run
snapshot digest whenever the evidence cites state or an observation; absence
of that input and mismatched snapshots both fail closed. Stimulus-only evidence
does not require a snapshot. Persisted validation and bundle verification also
require equality between carrier source pins and projection trace source pins.
Standalone readers can check internal structure without the original snapshot,
but only a caller supplying the expected snapshot digest can verify that
particular input association.

Stage 2 derives use-case functions and their primary outputs before attaching
security safeguards. Its prompts keep functional duties separate from rules
governing them: filtering a response does not replace returning a response.
Existing independently required safeguards remain modeled. Bounded structural
response repairs preserve valid function descriptions and ownership rather than
inviting a wholesale redesign for an extra JSON field. These are generation
instructions, not a claim that schema validation proves functional completeness.

Systemic and target-derived ICA review share the pure
`models.ica_enumeration.classify_ica_semantics` rule. Providers must describe
the named action state and the supported/contradictory/unknown hazard path;
code compares those facts with the fixed UCA category. A target reviewer cannot
confirm a finding using only an aggregate positive label, and its prompt must
not invent an omitted prevention sequence to connect a missing operation to
unauthorized execution. Supported harmful omissions remain eligible; failure of
one action is not automatically harmful when an allowed alternative still
satisfies the constraint. The shared rule validates consistency of explicit
reviews, not their factual truth; inspection of live findings remains necessary.

The existing Stage 2 coordination call also returns a complete typed semantic
review, interpreted by `system_model.semantic_review`. It can reconcile each
hazard and constraint description against the supplied use case and losses,
each responsibility's exact governing constraint set and each action's effect kind,
but cannot rename/merge controllers, change action meaning/targets, invent
constraints, or produce ICAs. Unknown effects and empty constraint sets require
explicit rationales. Provider responses missing complete exact-ID decisions
use the existing bounded validation retry. The normal coordination call sends a
required review schema with exact hazard/constraint/responsibility/action ID choices and list
counts through structured output; the consumer additionally checks uniqueness.
It does not advertise an optional review and later reject its omission.
Hazard/constraint rows explicitly preserve, revise or leave meaning unresolved.
A revision requires a changed description and a verbatim source quotation from
the supplied use case or exact loss; source presence is validated separately
from the reviewer's interpretation. Losses, all identities, ordering and
hazard-to-loss links are immutable. Unresolved rows name the missing fact;
constraints cannot reference unresolved hazards, and unresolved constraints
cannot retain hazard edges or responsibility ownership. Both drafts are persisted
before the call; the successful review and resulting loss/control graphs are
separate artifacts. Legitimate source-authorized functions must remain possible,
and restrictions on provider-bound prompts must not silently become restrictions
on customer-bound output.
This occurs before target realization and receives no target inventory.
The later completeness revision preserves those established owner/constraint
links when replacing a responsibility; it cannot erase them by omitting the
field or returning an empty list. Its prompt displays the links explicitly as
copy-through provenance. Revoking ownership belongs to semantic review, not
an additive completeness repair.
Coordination links must place their shared process-model element at exactly one
endpoint responsibility. Stage 2 and scenario-context assembly use the same
`coordination_process_model_owner` resolver, so a defect can use the existing
Stage 2 correction instead of failing after scenario generation starts.

`scenario_prod.outcome_grounding` separates literal source presence from
semantic interpretation. For action/state value comparisons, Stage 5 may cite
an exact supplied constraint/action text and its verbatim literal quotation.
If citation evidence is absent, `resolve_outcome_grounding` may instead find
the exact typed scalar or object key in the supplied `TargetObservationSnapshot`
JSON observations. It retains all matching references and JSON paths; repeated
occurrences are still evidence of presence. It does not search schemas,
defaults, examples, or arbitrary prompt prose. An invalid explicit citation
remains unresolved and cannot trigger the absent-citation fallback. This
resolution is shared by materialization and its audit, with no citation-only
provider retry or additional model call.
Unmatched evidence retains the subject/property/operator but materializes a
typed unresolved reference value; it never derives policy from tool schemas.
The ordinary model-output Boolean proposition is exempt because it is a truth
predicate, not an argument reference value. Per-context grounding audit records
preserve the proposed and compiled conditions and cited source, explicitly
without independent interpretation verification. These are audit sidecars,
not runtime observations or an additional consumer input. The existing bundle
contract carries the resulting literal or placeholder unchanged.
Provider state-condition subjects use the explained local process-model handles,
just like temporal references. Compilation resolves the handle and checks it
against the declared causal factors; a provider never needs to reconstruct a
hidden process-model identifier. This does not establish runtime observability
of an internal state.

The product `generate` composes taxonomy-obligation planning with the STPA stages
described below. It constructs losses and hazards, the control structure,
unsafe control actions, causal factors, scenarios, evaluation, and reporting
artifacts.

### Execution classification and target profiles

Stage 5 fixes one semantic execution route per scenario: `direct_prompt`,
`indirect_content`, or `conversation_context`. The route includes the selected
causal factor, action kind, logical domain-resource requirements, and the
observable unsafe outcome. The model selects only explained request-local
handles; deterministic assembly resolves them to the fixed STPA identities and
resource-requirement templates. It does not ask the model to label a result
concrete or executable.

At the provider wire, the stimulus category is the sole delivery input and an
executable response marks exactly one declared
`causal_factors[].selected_for_route` factor; an analytical-only response marks
none. Deterministic compilation derives the delivery class and maps that marker
to the existing final factor identity. It does not add evidence or retag a
factor, and the published execution route and contract remain unchanged.
The selected ingress is independent of the target action kind: direct user input
may lead to a tool call as well as a model response. Indirect stimuli require the
selected factor's existing `reachable_capability` or `bounded_assumption` evidence
branch. `structural_failure` alone cannot establish attacker influence over a
tool/retrieval result and is rejected through the existing bounded response
correction. A prospective carrier remains a declared hypothesis, not an observed
attack. Accurate target returns are background evidence; a mistaken interpretation
belongs to the process model, not an additional sensor fault.

Delivery/factor fidelity is a closed structural check. Direct prompt accepts a
selected process-model flaw; conversation context accepts a process-model flaw
or feedback delay; and indirect content accepts a process-model flaw or sensor
anomaly. A different pairing receives the existing bounded Stage 5 correction
attempt and is not published as an executable route. Model-output value
conditions are semantic propositions with literal expected values rather than
unknown complete-response strings; the consumer may evaluate them with a
semantic response judge.

Final non-N/A ICAs cross an independent STPA attribution check before Stage 5.
Its closed prompt view contains the authoritative action, original deviation,
and selected hazard, constraint, and reachable-loss meaning. The proposed UCA
category and category-bearing ICA identity stay in code: the model describes
the action state using a request-local reference, and code compares that state
with the fixed slot. Previous verdicts are not supplied as semantic evidence
during the recheck. Optional original `ICA.deviation` avoids asking the reviewer
to extract a clause from compiler-rendered prose; absent values are omitted so
historical identities remain unchanged. Contradictory or
insufficient attribution permits one separate ICA-author correction followed
by one independent recheck; unchanged or still-unsupported material is retained
as an explicit exclusion while sibling ICAs proceed. A technical correction/recheck
failure retains its provider-failure disposition and original semantic attempt,
but cannot admit the rejected ICA. Unverified replacement prose is never
applied to the enumeration; only independently supported corrections are applied.
An initial provider outage with no semantic verdict remains distinguishable.
Taxonomy concepts and mapping evidence do not enter this verifier. Mapping strength is instead
derived deterministically from the complete pinned relation path.

Every executable unsafe outcome has a bounded semantic proposition as well as
its machine condition. A model-output condition uses the compiler-owned
`semantic_proposition equals true` shape; that label is bookkeeping, while the
proposition is the exact criterion passed to a downstream semantic judge. The
scenario specification, projection, bundle trace, and consumer must preserve
the exact hazard, governing-constraint, and reachable-loss references without
substitution or fallback expansion.

Stage 5 runs through `generate_bdi_for_context`, which validates local
handles and materializes the semantic execution contract.
Its provider prompt is a purpose-built view of the immutable context, not a
serialization of that artifact. It omits digests, source pins, scenario/ICA
bookkeeping identities, raw causal-source IDs, and catalog labels. Exact target
action, hazard, constraint, capability, and access references remain only when
the response has a named field that copies them, with their meanings stated in
the prompt. Deterministic assembly derives `semantic_binding_required` from
typed placeholder presence; the provider cannot declare that redundant flag.
Provider validation and materialization use the same explained-prose and temporal
normalization. Temporal placeholders have exact condition/field namespaces,
including separate causal-factor and outcome occurrences. Unknown time values
remain typed placeholders; explicit discrete temporality does not acquire a
duration merely because a finding requests the WRONG_DURATION category.

The producer classifies binding completeness as `concrete`, `parameterized`, or
`analytical_only`, independently of the environment basis
(`target_agnostic`, `target_profile`, `simulation_profile`, or `none`). A
target-agnostic direct or conversation case can be concrete without a profile.
An indirect or external-action route with complete semantics but unresolved
resources is parameterized. Missing route meaning or an observable oracle is
analytical-only and cannot reach compilation. Only domain resources influence
this classification; chat surfaces, clocks, observers, locators, credentials,
and endpoint details remain runtime-readiness concerns.

An omitted environment request remains omitted through contract materialization.
For a resource-bearing route, the contract therefore carries a null requested
basis and classification `parameterized / none / needs_binding /
no_execution_claim`; the diagnostic is `environment_profile_not_supplied`.
An explicit target or simulation request is retained and reports its exact
missing-profile diagnostic when no profile is supplied. A resource-free route
derives `target_agnostic` even when a global profile is available. The typed
action kind is equally independent of prose: `model_output` is the externally
returned model/agent response and needs no domain resource, whereas
`agent_message` is an internal coordination message that retains an
`agent_channel` requirement. Tool calls, state changes, and external actions
retain their corresponding domain resources.

`generate` may receive `--execution-target-profile`; the profile's own `basis`
field sets the environment basis. The profile is a content-addressed, closed
semantic inventory with no secrets or live connection details. Metadata-free
MCP profiles are produced independently by the optional `asago-target-scan
mcp` command: the default scan performs `tools/list` only and writes a
self-contained profile plus sanitized inventory, manifest, and call accounting.
Secret-like values are removed from prompt views and persisted discovery
artifacts while each sanitized tool row retains the SHA-256 of the original
normalized observation. Optional disposable-environment inspection may invoke
only verifier-agreed read/observe tools whose schema admits an empty argument
object, and remains bounded by the caller's explicit call limit.
MCP profiles retain separate `inventory_authority: observed` and
`semantic_authority: inferred|reviewed` fields, and each operation preserves
the exact MCP tool name as both `operation_id` and `semantic_operation`.
Product `generate` strictly loads the profile file and does not import or invoke
MCP transport. All systemic STPA stages, including baseline ICA enumeration,
receive a target-blind input view. Only after that baseline is complete does
the separately attested target-realization lens relate exact observed
operations to systemic control actions. It may add one bounded, independently
verified target-specific extension, but cannot alter or remove baseline
records. Stage 5 receives an exact target operation only from a supported
realization row; unresolved and ambiguous relationships remain visible and
cannot become execution requirements. That verified implementation can be a
tool call even when the systemic action relates conceptual responsibilities;
`execution_implementation_kind` specializes execution without changing the
baseline relationship. Operation-led extensions retain the observed description
and argument schema in code. The provider selects only the systemic association,
which the existing independent verifier checks against the selected controller
and governing constraints. Handoff alone is not evidence of completed approval.
Target-backed projections pin the
profile and realization digests as a required pair. A simulation profile is selected explicitly and supplies a
complete mock contract; the producer never invents one from missing target
information. With no profile, the producer retains exact logical requirements
for later binding. A complete simulation profile produces a concrete simulated
case, not a target-integrated claim.

Optional `--target-observations` is a separate Stage 5 companion loaded from a
normalized capture document. `TargetObservationSnapshot` in
`stpa.scenario_prod.target_observations` pairs bounded state/read text with the
exact profile digest and a content digest. It is stripped from systemic inputs,
does not alter `ScenarioGenerationContext`, and is persisted as
`target-observations.yaml`. Explained observation references may be cited by
`ComparisonEvidence`, or exact JSON presence may be resolved without a citation;
either validates source presence, not rule
interpretation or enforcement. Outcome-grounding records retain the companion
digest. The normal pipeline does not discover or call target tools to obtain it.

The artifact generator consumes the published contract and profile through its
own resolver. It creates one bound execution case, matching each logical role
to exact resources before runtime readiness and platform compilation. This
consumer step may supply endpoints, credentials, locators, observers, and
platform syntax, but it cannot change the producer's delivery route, causal
factor, operation, action, or oracle. Analytical-only cases are excluded from
compilation and parameterized cases remain pending until the caller explicitly
selects an exact target or simulation profile. For a null producer request,
the consumer may use either selected profile basis, but it never defaults an
internal agent channel, indirect carrier, target action, state store, external
action, or real clock to ordinary chat. Mixed bundles preserve each case's
independent target-agnostic, pending, target-bound, and simulation-bound
state.

Tolerant SP1 response graphs remain raw until deterministic ID/reference
normalization produces valid typed artifacts; invalid intermediate Pydantic
objects are never serialized. Stage 1a classifies losses from either
intermediate container by typed provenance, deduplicates identical repeats,
and reports conflicting IDs as fatal stage errors. Its provider wire requires
all four collections explicitly, bounded at 16 records each. A bounded repair
retains a collection when the correction is empty and replaces the collection
when the correction is nonempty; it does not union obsolete records by ID.
Exact repeats of the accepted risk baseline are removed, while changed reused
identities are rejected on both initial gap responses and corrections.
Stage 2 rejects empty
requirement/responsibility sets, and an exhausted fallback is fatal. The
STPA retry contract is bounded: Stage 2 retries a JSON-decoding failure or a
semantically empty requirement/responsibility result once, while Stage 1a
retries semantic dangling hazard/loss references once with concise validation
feedback. Each attempt is logged separately in
`calls.jsonl` and counts as one request in the stage's call count; these
retries do not change the manifest/result schemas, and exhaustion remains
fatal.
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

A producer call count is the number of requests actually sent to the model.
Retries and correction requests count; a request the prompt preflight blocks
does not. The count comes from the call helper's `CallOutcome.calls`. This rule
covers `revision_call_count` in `loss-analysis-gates.yaml`,
`graph_revision_call_count` and the Stage 1a and Stage 1b totals in the run
manifest, the stated-rule revision and risk-actionability `call_count` values,
the SP1 manifest's `stage_2.call_count` (Calls 1–3, the density correction, the
critic, and the revision), `provider_calls` on obligation-aware routing,
revision, and slot responses (a slot response includes its context-coverage
supplement), the `attempt_count` of every consideration call record, and the
`stage_summary` totals in the product run manifest. A stage total counts the
`calls.jsonl` entries that were sent: it skips an entry the prompt preflight
blocked and a failure logged before any dispatch. `provider_calls` is the only
request counter on a provider response. Earlier runs used per-site rules
instead: a fixed Stage 2 count of 4, a fixed Stage 1a count of 2 and Stage 1b
count of 1, one call per attempted step or revision, a constant 1 per provider
response, a routing attempt count, and a `stage_summary` total that counted
blocked entries. Do not compare counts from runs before and after this rule. A
`provider_failure` entry that call_with_policy logs before dispatch because the
client declares no `max_completion_tokens` looks like a transport failure in
`calls.jsonl` and still counts.

Stream B makes the projection contract executable. A deterministic
traceability validator (`stpa.scenario_prod.projection`) checks the canonical
projection document — schema version, candidate identity, UCA reference,
factor-to-assertion and factor-to-step mapping, canonical predicates, the
final unsafe-control-action step, and typed provenance — and returns typed
violations aligned with the taxonomy `projection_validation` contract.
Normal publication renders narrative, attack-tree and Gherkin summaries
deterministically through `render_scenario_summary`. They retain the selected
causal evidence and describe a hypothesis, not an observed test result.
The run makes no model calls to render them.
Stage 5 prompt views teach condition field semantics without supplying invented
request-specific values. Temporal outcomes reuse the factor-condition local
handle resolver, and target-backed action-value predicates must name an observed
input-schema argument.

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
STPA, accounting, realization, manifest, and report artifacts in their
requested output directory. Retired taxonomy-generator output is
read-only historical data and is not accepted as a compatibility contract.

## Model-facing interface ownership

[Model-facing interfaces](model-facing-interfaces.md) defines which choices
belong to model authors and which values, references, identities, joins and
validation steps belong to deterministic adapters. Consult it when changing
authoring, evidence review, graph correction, or presentation interfaces.
