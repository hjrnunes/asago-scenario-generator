# Asago Scenario Generator

Pre-alpha adversarial-scenario generation for AI systems. Taxonomy supplies
systematic obligations to one STPA-led product workflow; STPA alone generates
scenarios.

## Commands

```bash
uv sync --locked
./scripts/quality.sh
./scripts/acceptance.sh
uv run pytest tests/ -q
```

Generated acceptance artifacts live under `build/acceptance/` and remain
untracked. Live-model acceptance requires the explicit opt-in
`ASAGO_SCENARIO_GENERATOR_QA_PIPELINE=1`; deterministic tests must not contact
an LLM endpoint.

Before private Gemma OC discovery, generation, artifact authoring, or qualification,
read `docs/development/private-live-model-approval.md` and carry forward its
standing approval. An owner-supplied replacement endpoint does not require
re-approving the same scoped data use.

## Architecture

- `src/asago_scenario_generator/` contains shared domain models, the
  observational taxonomy-obligation planner, the STPA product pipeline, CLI,
  offline verification, and STPA reporting. The planner consumes typed inputs and must not
  import scenario-generation implementation.
- `data/` contains committed schemas, taxonomies, mappings, and qualification
  inputs.
- `features/` is the source of truth for acceptance behavior;
  `acceptance/` contains the portable generator, runtime, and handlers.
- `config/` contains sanitized examples and portable project configuration.

The Stage 6 execution interface is deliberately closed and typed. Normal
product execution crosses `prepare_execution_projection(...)` before any
Stage 6 call and publishes only through `publish_execution_bundle(...)`.
Normal publication renders hypothesis summaries deterministically. Generative
presentation is an explicit `run_sp3(render_presentation=True)` option, not an
execution prerequisite. Stage 5 condition values must come from the supplied
behavior and observed argument schema; quantitative unknowns remain typed
placeholders, while event ordering uses explained local reference handles.
Both seams require the explicit run identity and intact source pins; unknown
semantic values are typed binding placeholders, and their presence derives
`semantic_binding_required`. The paired contract kits in
`data/contracts/stpa-execution/` are producer-owned; consumers vendor them
byte-for-byte. A legacy run publishes the v2 projection through the v1
bundle; a structured-omission run publishes the v3 projection through the
homogeneous v2 bundle, and a mixed-version bundle is a publication error. A `conversation_context` route may carry `turns`, two to three
prepared user turns copied verbatim from the authored draft; the consumer
delivers them as ordered user history with no assistant reply between them.
An `ordering` condition may name a `reference_tool` and `reference_argument`
(both or neither); the condition is the unsafe observation, and the same
argument predicate applies to the target call and the reference call. Both
fields are omitted when absent, so existing projection digests hold.
Stage 5 fixes one delivery route, selected causal factor, action,
logical domain-resource requirements, and observable unsafe outcome. The
producer deterministically classifies binding completeness as `concrete`,
`parameterized`, or `analytical_only`, independently of
`target_agnostic`, `target_profile`, `simulation_profile`, or `none` basis.
The artifact generator later binds parameterized requirements to an explicitly
supplied target or simulation profile; it may add runtime details but cannot
change the route's meaning. `run` accepts optional
`--execution-target-profile` and `--requested-environment-basis` inputs.
Optional `--target-observations` supplies a profile-paired, content-pinned Stage 5
companion, not systemic baseline input. Optional `--loss-analysis` pins the
Stage 1a output: the supplied graph is validated, gated offline with zero
model calls and no revision, re-published as `loss-analysis.yaml`, and hashed
into the run manifest (`stage_1a.source: pinned`; the derived path records
`source: derived`). A security constraint may carry explicit `obligations`:
`required` entries naming a realization channel (`realized_by`) or
`forbidden` entries naming a violation channel (`violated_via`), each
quoting its rule span verbatim (owner ruling Q30, 2026-09-10). Channels are
kind-exclusive, `unknown` is the permissive default, a forbidden entry may
be marked `observation_role: proxy` with the `source_outcome` it stands
for, and a required entry may record the `completion` an oracle does not
observe. The constraint's failure direction is computed from its entries
under a `direction_authority` stamp: deterministic code restamps every
derived or revision-merged graph `proposed` and clears wire-carried
reviewer marks, so only a pinned graph carries `reviewed` with its
`reviewed_by`/`reviewed_on` stamps. Keep observed values separate from
interpreted rules; see the capture workflow in `scripts/qualification/README.md`.
Profiles contain semantic resource facts only: no URLs, credentials, or
secrets. Metadata-free MCP targets are scanned independently through the
optional `asago-target-scan mcp` entry point; the product run consumes only
the resulting closed profile and never imports MCP transport or performs a
scan. The systemic STPA baseline is always target-blind. When `run` receives
an observed (non-simulation) execution target profile with
`multi_agent: false`, Stage 2 switches to
the deterministic target-derived structure
(`system_model.target_derived_structure`): one ASSISTANT controller, one
tool action per observed operation, a `respond` action, and
capability-driven conditionals, with at most two bounded model calls
(grounded controller-purpose beliefs and constraint-action relevance, each
offline-validated) and a content-pinned `target-derived-structure.yaml`
sidecar recording the exact resource/operation binding per tool action;
target realization then replays those bindings through the zero-call
identity interpreter. Optional `--reviewed-obligation-bindings` supplies a
closed `reviewed-obligation-bindings-v1` file of reviewed
obligation-to-action connections; offline validation fails closed unless
each names a reviewed `required` entry realized by a tool call on a tool
action of the structure, and the exact set rides on the sidecar so it is
digest-covered. Optional `--target-subject-model` supplies a closed
`target-subject-model-v1` companion declaring the session-subject path,
argument roles, and record-subject relations for
`owner_differs_from_session`; it is consumed only when structurally valid
and accepted (reviewer `reviewed_by`/`reviewed_on` stamps, the exact
observation/profile digests, and a self-excluding framed content digest),
and a proposed, edited, or mismatched file fails closed with a typed
reason. Without it, the session subject is discovered from top-level
`authenticated_*_id` keys (two or more is ambiguous, never guessed), no
argument carries an owner role, and `owner_differs_from_session` is
withheld with a typed reason — always on `tool_order`
(`owner_differs_tool_order_deferred`), and on `tool_argument` unless the
identity conditions hold; a draft using a withheld operator is held as
`operator_unavailable`, not rejected and not a candidate-wide error. The
accepted model's digest and reviewer stamps ride on the
target-derived-structure sidecar and the run manifest. Without a profile,
or for multi-agent targets, the
target-blind Stage 2 and diagnostic `stpa-run` are unchanged. In
target-derived mode only, scenario synthesis replaces the ICA enumeration,
ICA verification and correction, and Stage 5 BDI generation with one
grounded authoring call per (constraint, action) candidate
(`scenario_prod.authoring`): the model drafts scenarios against the
observed target state and policy observations, and deterministic code owns
validation with typed rejection reasons, the deviation category,
identifiers, lineage, the closed oracle templates in
`data/oracles/templates.yaml`, synthesized enumeration slots, and contract
assembly, with no repair call. The obligation-direction admission seam
(`admit_oracle_kinds`) offers only oracle kinds that compile under the
constraint's direction authority; the prompt offers nothing else, and every
returned draft is re-judged against its own `obligation_ref` citation
(required when entries exist, rejected when unknown). Under proposed
authority the commission kinds compile permissively and an omission oracle
holds as `direction_unreviewed`; under reviewed authority a contradiction
with the cited entry's kind or channel rejects
(`oracle_direction_contradiction`, `oracle_channel_unsupported`), and an
omission oracle compiles only through a reviewed binding, otherwise holding
with a typed reason (`direction_unresolved`, `realization_unresolved`,
`binding_unreviewed`). Under reviewed authority a reply oracle against a
required entry compiles only when the entry is realized via reply; a
required `tool_call` realization rejects (`oracle_channel_unsupported`,
naming the omission oracle through a reviewed binding as the compilable
test) and an unknown realization holds `realization_unresolved` (owner
ruling Q31, 2026-09-10). A candidate with no compilable kind resolves before
the call (`specification_only` or `no_expressible_oracle`), and held drafts
persist as specification evidence that is never compiled or credited as
recovery. Omission drafts require exact trigger evidence from a particular
supplied user turn, used state fact, or uniquely named observation content.
Verify source presence separately from the author's trigger interpretation:
a valid citation never establishes the duty to call. A run with no evidenced
omission draft keeps the proposition-only projection-v2/bundle-v1 path
unchanged; a draft with source-validated evidence publishes the paired
projection-v3/bundle-v2, whose unsafe outcome carries the closed
`stpa-omission-evidence-v1` carrier beside a short trigger-only proposition,
upgrading every entry in that run's bundle to v3 so bundles stay homogeneous.
A direct-prompt carrier delivers the exact authored user text verbatim
(`prepared_user_text`). Before publication, verify the complete deterministic
proposition against its trigger and owned tool operation, and require the run's
validated snapshot digest for state/observation evidence. Persisted carrier
source pins must equal the projection trace pins. Evidence beyond the carrier bounds hold as
`trigger_evidence_unrepresentable` with the original evidence retained, and
unattestable or unresolved deliveries hold as `delivery_evidence_mismatch` /
`delivery_evidence_unresolved`. Absence alone stays inconclusive; a `kind:
none` functional specification may retain a validated carrier for review but
never produces an executable v3 projection. See the omission evidence boundary
in `docs/architecture/overview.md`.
Every accepted scenario carries `observes` (attempt, total
omission, or reply; no compiled kind measures an effect, and an
attempt-level or proxy stamp never supports an executed-safety claim) and
`compile_basis` stamps that travel to the compiled spec as
`oracle_observes`/`oracle_basis`, omitted when absent so existing
projection digests hold. The target-blind Stage 5 path is unchanged. After ICA completion,
an observed target profile may drive one separately attested additive target
realization: exact operation matches may specialize baseline actions, and one
bounded verified extension may add target-derived actions/ICAs without
rewriting baseline records. Exact target choices and both target authority
digests are retained through Stage 5 and the v2 execution projection.
Omission remains omission: resource-free model output may be
`target_agnostic`, while a resource-bearing contract retains a null request,
`parameterized` completeness, and `none` environment basis until its caller
selects a target or simulation profile. `agent_message` remains an internal
agent-channel requirement; it is not ordinary `model_output` chat. Bundle
publication is preflighted and atomic with the canonical
JSON index replaced last; updates use immutable content-addressed generations
so the live index never points at bytes being replaced. Historical v1 projection validation remains
read-only and must not grow execution or persistence dependencies.

Read `docs/architecture/overview.md` before changing cross-pipeline contracts.
Read `docs/architecture/model-facing-interfaces.md` when changing response
envelopes, authoring, evidence review, graph correction, or presentation interfaces. Model authors
select explained semantic choices; code owns exact source resolution, fixed
fields, reference joins, identities, and unchanged-record preservation.
Read `docs/development/swarmforge.md` when planning or executing feature work,
changing acceptance behavior, or running the quality sequence.

## Development

- Final Stage 2 semantic review stays target-blind and reuses Call 3. Preserve
  draft/review evidence and complete hazard/constraint/responsibility/action
  decisions. Permit source-quoted H/SC wording corrections while preserving
  losses, identities and hazard-to-loss links; retain legitimate use-case
  functions and communication direction. Keep genuine missing facts and unknown
  effects explicit. Stage 5 comparison grounding verifies literal source presence
  through quotations or exact observation JSON; retain unsourced values
  as typed parameters and never promote source presence into semantic proof.

- Gate the Stage 1a loss analysis deterministically. Every supplied risk card
  needs exactly one `risk_dispositions` entry (or a loss citing it), the
  provider wire must carry explicit `rule`/`applies_when` and
  `risk_dispositions` collections, and the merged hazard graph must pass the five offline density
  checks in `loss_analysis_gates.py` (every loss has a hazard, every
  constraint has a hazard, every hazard has a constraint,
  constraint/hazard share a fixed-rule subject noun
  phrase, every behavior class owns a hazard). A first-attempt validation
  failure receives one narrowly scoped targeted repair (owner authorization
  2026-09-11, corrected contract rev2 same day) for exactly two classes:
  missing or malformed `risk_dispositions` entries, and malformed
  obligation entries inside an otherwise preserved constraint. Deterministic
  code selects the repair identities, the closed repair wire carries nothing
  outside the repair scope, duplicate, unknown, out-of-scope, or partial
  responses are rejected with a typed reason, every unselected record and
  every preserved obligation entry stays byte-identical, and the merged
  draft is re-validated against the complete original inputs. Obligation
  repairs preserve channel meaning: a known channel value in the wrong
  kind-exclusive field relocates unchanged (for example `realized_by` to
  `violated_via`), and substituting a different channel, dropping a known
  channel to reach the default `unknown`, or an entry whose defect is
  outside the fixed permitted-change table (conflicting channel values, a
  required entry with `violated_via: state`, `source_outcome` without the
  proxy role) is a typed unsupported scope that reaches no repair call;
  `unknown` arises only from an original `unknown` value. Wire errors are
  classified completely before anything else runs: container-level defects
  (an absent, mistyped, or non-list collection) are typed terminal
  failures that authorize no cleanup and conceal nothing, while
  record-level defects are salvaged with every malformed obligation entry
  retained verbatim and its exact errors. Deterministic row cleanup is an
  explicit owner-approved policy with limits: only malformed
  `risk_dispositions` rows of the gap response (C1) and only rows
  referencing risk cards absent from the supplied set (C2) may be removed,
  with the original response preserved in `calls.jsonl`, every removed row
  and its reason recorded, the cleaned object re-validated against the
  original provider schema before the graph validators, and no cleanup
  when any container-level or unrelated error is present; neither policy
  removes a supplied risk or changes risk accounting, which comes from the
  risk-derivation draft only (gap dispositions never reach the final
  graph). Every Stage 1a transformation — salvage, cleanup, repair, or a
  typed unsupported scope — appends to one run-level, cross-stage,
  accumulating `loss-analysis-repair.yaml` that distinguishes proposed
  from applied changes, is flushed after each stage so a terminal failure
  preserves earlier entries, and is referenced by a `stage_1a.repair`
  block in the run manifest. The single repair call is preflighted, logged
  with a `_repair` step suffix, and never retried; every other failure
  class is a typed terminal failure with no second call. A failing graph
  receives one
  bounded revision call with the exact failing checks; a second failure is a
  fatal stage error recorded in the run manifest and
  `loss-analysis-gates.yaml`. The gates are offline and never soften a check.
  After the gates pass on a derived analysis, at most four capacity-sized
  advisory calls (batched up front from the per-row completion estimate,
  32 cards per batch at the 8,192 cap, in supplied card order; cards beyond
  four batches are recorded missing) review every newly generated graph
  for per-risk coverage, with
  quotation-validated verdicts written to
  `loss-analysis-risk-coverage-review.yaml`; the review is advisory (it never
  changes the graph, blocks a run, or acts as a gate), and pinned runs skip it.
  Validation is per row, not per response: an invalid row is recorded with its
  typed reason and the valid rows beside it are kept, every planned batch is
  issued, and the artifact records `completed`, `partial`, or `unavailable`
  with valid, invalid, and missing row counts. A provider that answered but
  whose answer failed stage-local validation is a semantic validation failure,
  not a call failure.

- Track durable work and specification approval in GitHub Issues and PRs.
- Keep `run` as the sole normal scenario-generation command. Taxonomy supplies
  obligations and STPA alone authors scenarios. `stpa-run` is an advanced
  baseline diagnostic without obligation completeness. Do not restore the
  retired `generate`, legacy `resume`, `synthesis-run`, `report`, or `eval`
  commands. The retained historical audit seam is read-only and must not grow
  new execution, persistence-writing, or provider dependencies.
- Keep Phase 1 obligation planning observational: it retains every reviewed
  risk, uses the exact closed row schema and typed dispositions, computes and
  verifies digests, and publishes atomically. Product `run` always consumes
  these obligations; standalone diagnostic `stpa-run` does not. Persistence validation belongs to
  the model/adapter seam; it is not a required `validate-obligation-plan` UI.
  `mapping_pins.sssom` remains the taxonomy-context pin while
  `mapping_pins.obligation_edges` binds the supplied typed edge bundle. The
  inward observation seam may retain only concrete, validated budget-deferred
  candidates and typed condition/precondition/missing-fact evidence; public
  generation projection remains `ProjectionBatch`-compatible. Keep resource
  feasibility typed: a missing tool/integration operation inventory is unknown
  evidence, an explicitly omitted required operation is structural
  infeasibility, and distinct pattern roles cannot share one resource.
- Keep Phase 2 observational and offline. Validate the closed
  `system-resource-map-v1` sidecar against exact capability/control-structure
  digests; produce correspondence only from typed authority/evidence and
  explicit adjudication; and derive `hybrid-coverage-assessment-v1` through
  the exact-artifact `reconcile_taxonomy_and_stpa` facade or its delegated pure
  `assess_hybrid_coverage` seam. Only accepted relations backed by accepted,
  confirmed proposals count as taxonomy correspondence. Preserve the three
  independent denominators exactly: one structural-consideration row per UCA
  slot, one taxonomy-correspondence row per obligation, and one
  scenario-realization row per accepted relation. Rejected, unresolved,
  contradictory, and noncoverage evidence stays in separate traceable
  diagnostics; never derive a blended score or rate. Structural
  inapplicability requires explicit reviewed evidence, and a relevant
  `inferred_partial` capability inventory requires explicit other authoritative
  evidence before an inapplicability decision is eligible. The assessment seam
  consumes only a successful `SystemResourceMapValidation` attestation;
  defective nonaccepted proposals remain global traceable diagnostics, and
  missing resource-map evidence is assessed against each obligation's exact
  candidate resource references. Treat `accepted_resource_link` evidence as
  shared identity only: it may produce `related_but_not_coverage`, never a
  coverage-bearing relation without independent exact-ID or curated mechanism
  evidence. Adapt legacy taxonomy and STPA scenario envelopes only through
  exact candidate and slot/ICA/`EXEC:*` identities; unknown identities fail
  closed. Resource-link evidence must retain the exact selected projectable
  candidate and each link must resolve to that candidate's own bindings. The
  deterministic resource-link adapter may propose association-only
  `related_but_not_coverage`; it must not infer mechanism equivalence. Keep
  proposer calibration separate from coverage and retain exact
  confirmed/rejected/unresolved/unreviewed counts rather than a score without
  its denominator. Publish the normative
  YAML artifacts atomically. Product `run` executes Phase 2 last and
  non-blockingly; standalone diagnostic `stpa-run` remains independent. Phase
  2 must not construct provider clients or contact endpoints.
- Keep the Phase 3 challenge ledger separate, deterministic, and offline. It
  consumes one intact Phase 2 assessment plus explicitly supplied exact
  obligation/STPA-slot pairs, an explicit non-negative budget, and the pinned
  `explicit-priority-v1` policy. Select smaller priorities first with exact-ID
  tie-breakers; retain selected and budget-excluded targets, their immutable
  original ICA/N/A/unresolved decisions, evidence, traces, assessment digest,
  and upstream pins. The ledger must not infer eligibility, call a provider,
  change Phase 2 matrices, create correspondence or coverage, generate a
  scenario, or alter product `run`/diagnostic `stpa-run`. Publish the closed
  `stpa-obligation-challenge-ledger-v1` YAML atomically through its adapter.
- Keep Phase 3 challenge analysis behind the explicit
  `reconsider_stpa_challenge` opt-in seam. It accepts only a selected exact
  ledger target, intact assessment, typed STPA authority, explicit named-model
  controls/deadline/temperature, and a caller-supplied adapter factory. Opt-out
  must return before adapter construction; opt-in permits one attempt and zero
  automatic retries. Validate ICA results as additive canonical slot/`EXEC:*`
  identities against authoritative hazards and constraints; require explicit
  evidence for justified N/A and a typed reason for unresolved. Record
  provider/protocol/identity failures separately from structural outcomes.
  Preserve the original decision and Phase 2 artifact, fix correspondence and
  coverage changes at zero, start no hybrid generation, add no Task 2 CLI or
  run placement, and leave diagnostic `stpa-run` unchanged.
- Keep Phase 3 composition at the typed internal `run_closed_loop_stpa` seam.
  It must delegate exact selection and each reconsideration to the Task 1 and
  Task 2 seams, respectively. Opt-out retains selected targets as pending and
  constructs no adapter. Resume may reuse only an intact prior run with the
  exact ledger, controls, loss analysis, and control structure; it must not
  retry prior attempts. Publish the single closed
  `stpa-obligation-closed-loop-run-v1` YAML atomically in a caller-chosen
  directory. Keep exact counts and typed outcomes separate rather than
  inventing an aggregate status. Add no Phase 3 CLI or report, infer no targets
  from the lineage audit, and leave product `run` and diagnostic `stpa-run`
  unaware of Phase 3.
- Keep obligation-aware synthesis advisory: every applicable obligation is
  considered, but it never forces an ICA or scenario. At provider boundaries,
  deterministic code owns structural categories and identities. ICA providers
  return one plain deviation sentence for each supplied slot; the compiler
  applies that slot's exact UCA category. Provider views must include the
  action temporality used to decide duration eligibility and a complete,
  explained reference slice. Stage 5 providers select only
  explained request-local causal handles, which the compiler binds to fixed
  PM/FB/CA sources and kinds. Derive defender-belief annotations from those same
  exact PM declarations; do not ask for a second provider-authored version.
  Mark undeclared beliefs as not selected in this scenario, not as vulnerability
  absence. Providers describe one typed test
  stimulus and select one compatible causal path; deterministic assembly owns
  the action kind, resource roles, carrier influence, contract, and
  classification. File-upload, load-generation, or otherwise unsupported
  stimuli remain explicit analytical findings rather than being relabelled as
  a direct prompt. A missing route is a provider failure, while explicit
  `analytical_only` remains outside compilation. Require the delivery class to
  fit the selected causal category:
  direct prompt to a process-model flaw, conversation context to a
  process-model flaw or feedback delay, and indirect content to a process-model
  flaw or sensor anomaly. Model-output value conditions are literal semantic
  propositions for a downstream response judge, not unknown whole-response
  string placeholders. Render Stage 5 from an actionable prompt view: include plain
  semantic facts and only references that a named response field copies;
  retain digests, source pins, catalog labels, and bookkeeping identities in
  deterministic code. Derive `semantic_binding_required` from typed
  placeholder presence after the provider response. Require the closed
  adversary record (`kind`/`gain`; deterministic code derives
  `reaches_target_via` from the stimulus delivery) on the corrected
  contextual Stage 5 wire: `kind: none` resolves the candidate as a
  functional test that is persisted under `scenarios/` but never prepared
  for execution, bundled, or credited as realization; `third_party_via_content`
  requires typed capability-profile content-surface facts (`no_content_surface`
  otherwise); a gain that restates a governing constraint is rejected.
  Controller, controlled-process, and local-handle identities must never be published as
  causal sources, and every intention handle must have an explicit
  causal-factor declaration. Validate capability and access-path claims from
  exact typed causal evidence. Do not treat ordinary adversarial wording, such
  as taking advantage of a timing gap, as proof of a new access path or use a
  free-text verb blacklist as a scenario-publication gate. Treat obligation
  pattern names, concerns, and rationales as analysis provenance, not causal
  evidence: a finding links the concern to an unsafe-control path but does not
  establish the taxonomy attack mechanism. Keep ICA text and attack-tree
  templates mechanism-neutral unless exact structural or capability/access
  evidence independently supports the mechanism.
  Maintain routing, bounded-revision, and ICA provider prose as strict Jinja
  templates over closed prompt views, and hash included partials with the
  top-level templates. Ask separately whether a taxonomy mechanism is
  plausible in the supplied system and whether it realizes the reviewed risk.
  A plausible mismatched mechanism may retain an ordinary STPA finding but
  must record `risk_pattern_mismatch` and cannot address the obligation. Check
  otherwise-creditable routes with a compact mechanism/path verifier that
  receives no capability, mapping, or proposed-rationale context. An adjacent
  control or unsubstantiated mechanism path keeps the ordinary STPA result but
  records `mechanism_path_unsubstantiated` and cannot address the obligation. ICA
  style warnings are non-blocking. Independently verify every final non-N/A ICA
  against its exact control action, UCA category, selected hazard, governing
  constraint, and reachable loss before Stage 5. One unsupported result may be
  corrected once by the ICA author and independently rechecked once; unchanged
  or still-unsupported material is retained as a typed exclusion while sibling
  ICAs continue. Do not send taxonomy or mapping context to this verifier, and
  derive mapping strength locally from the complete pinned mapping path rather
  than accepting it from provider output. Every executable unsafe outcome must
  carry a bounded semantic proposition and exact hazard/constraint/loss lineage;
  for model-output outcomes, use the fixed compiler-owned
  `semantic_proposition equals true` bookkeeping condition and give downstream
  judges the proposition itself. Reconcile one closed terminal stop reason
  per applicable obligation across accounting and scenario realization, and
  distinguish provider response receipt from parsing, semantic validation,
  compilation, and publication in call evidence. Finish product `run` with
  non-blocking offline Phase 2 verification. Start from an exact zero-link
  resource-map baseline. Only an exact route credited by synthesis accounting
  may become an unreviewed `mechanism_enables_ica` proposal; other route joins
  remain `related_but_not_coverage`. Never auto-confirm correspondence.
  Publish the four standard Phase 2 artifacts, and retain a verification
  failure without deleting or invalidating generated scenarios.
  Publish a stable synthesis `run_status` whose completion rule is
  candidate-terminal: `completed` when every requested candidate's terminal
  outcome is `published` (publication succeeded) or `functional_specification`,
  `no_candidates` for a valid run with no eligible candidates, `failed` only
  when requested candidates were attempted with zero published scenarios and
  zero persisted functional specifications, and `degraded` for partial or
  unattempted yield. A `publication_failed` candidate is attempted but never
  yielded and contributes zero to `generated`. Keep candidate counts, artifact
  counts (`generated`, `functional_specifications`), and draft counts as
  separate denominators, all distinct from diagnostic-message counts. Product `run` must publish its
  diagnostics and accounting artifacts before returning non-zero for the
  attempted zero-yield case; no-candidate and partial-yield outcomes remain
  successful command results.
- Keep Phase 4 Task 1 at the typed, offline
  `resolve_hybrid_projection_units` boundary. Accept one closed
  `HybridProjectionInputs` graph assembled only through exact artifact
  factories; preserve Phase 1 taxonomy pins without silently converting them,
  bind complete candidate projections to exact Phase 1 candidate records, and
  derive correspondence only from the paired `ProposalSet`,
  `ReconciliationResult`, and `HybridCoverageAssessment` authorities. Require
  the exact coverage-bearing scenario-realization row and matching
  obligation-row relation ID. Retain `related_but_not_coverage` and
  relation-local missing material as typed exclusions; reject substituted or
  unverified top-level authority. Require each accepted relation's security
  constraints to be owned by its selected causal controller; never infer that
  ownership during Phase 4. Task 1 must not compose the final graph,
  persist or render an artifact, add a CLI, contact a model or network, or
  change product `run` or diagnostic `stpa-run`.
- Keep Phase 4 in-memory composition at the pure
  `build_hybrid_scenario_projection_set` seam. Resolve exact units through the
  Task 1 boundary, apply only the fixed typed bridge endpoint table, validate
  the taxonomy/STPA/bridge union as one DAG, and require exact source-pin,
  trace, and bridge-evidence closure. Preserve typed exclusions and diagnostics
  without scores or execution decisions. Task 2b provides offline persistence
  through `write_hybrid_scenario_projection_set` and
  `read_hybrid_scenario_projection_set`, using the exact
  `hybrid-scenario-projection-set.yaml` filename and atomic verified reload.
  Task 3 acceptance must exercise the complete contract and independently
  verify the YAML identities, digests, ordering, pins, and exclusions. Keep
  `assess_hybrid_pilot_readiness` pure and target-scoped: accept one closed
  typed authority graph, require factory-verified run provenance and exact
  Phase 1/2/STPA/review evidence, and return typed blockers plus exact counts.
  Bookkeeping, copied, relabelled, shared-resource-only, or fake evidence must
  never make a semantic pilot ready. Reporting, CLI, model calls, network
  access, generation, and scenario finalization remain outside Phase 4.
- Target-grounded scenario evaluation uses the hand-authored reference gold sets
  in `data/gold/` and the deterministic scoring and review tools in
  `scripts/gold/` (`score_run.py`, `review_run.py`). See `scripts/gold/README.md`
  and `ai/findings/target-grounded-scenario-generation-spec-2026-09-07.md`.
  Benchmark revision 2 (`data/gold/miniklarna/benchmark-v2.yaml`,
  `--benchmark-version 2`) splits cases into adversarial and functional and
  reports compiled-test recovery and reviewed specification recovery
  separately; neither reports executed behavior; revision 3
  (`data/gold/miniklarna/benchmark-v3.yaml`) amends G08's `unsafe_when` and
  carries the revision 2 review forward except for amended cases; revision 4
  (`data/gold/miniklarna/benchmark-v4.yaml`) expresses G07 as record
  conditions, records the G11 lineage interpretation, and carries the
  revision 3 review forward except for amended cases.
  `docs/development/target-grounded-benchmark.md` states the benchmark in
  force, the recovery criteria, and the checkpoint requirements in one place.
- Keep harness installations and runtime state local; the repository owns only
  portable methodology, configuration, and scripts.
- Update `README.md`, this file, and linked documentation when an interface or
  workflow changes.
- `AGENTS.md` is a symlink to this file.
