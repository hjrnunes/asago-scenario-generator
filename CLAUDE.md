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
Both seams require the explicit run identity and intact source pins; unknown
semantic values are typed binding placeholders, and their presence derives
`semantic_binding_required`. The v2 projection and v1 bundle contract kit in
`data/contracts/stpa-execution/` is producer-owned; consumers vendor it
byte-for-byte. Stage 5 fixes one delivery route, selected causal factor, action,
logical domain-resource requirements, and observable unsafe outcome. The
producer deterministically classifies binding completeness as `concrete`,
`parameterized`, or `analytical_only`, independently of
`target_agnostic`, `target_profile`, `simulation_profile`, or `none` basis.
The artifact generator later binds parameterized requirements to an explicitly
supplied target or simulation profile; it may add runtime details but cannot
change the route's meaning. `run` accepts optional
`--execution-target-profile` and `--requested-environment-basis` inputs.
Profiles contain semantic resource facts only: no URLs, credentials, or
secrets. Omission remains omission: resource-free model output may be
`target_agnostic`, while a resource-bearing contract retains a null request,
`parameterized` completeness, and `none` environment basis until its caller
selects a target or simulation profile. `agent_message` remains an internal
agent-channel requirement; it is not ordinary `model_output` chat. Bundle
publication is preflighted and atomic with the canonical
JSON index replaced last; updates use immutable content-addressed generations
so the live index never points at bytes being replaced. Historical v1 projection validation remains
read-only and must not grow execution or persistence dependencies.

Read `docs/architecture/overview.md` before changing cross-pipeline contracts.
Read `docs/development/swarmforge.md` when planning or executing feature work,
changing acceptance behavior, or running the quality sequence.

## Development

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
  PM/FB/CA sources and kinds, and return exactly one vulnerability for every
  compiler-owned local defender-belief handle. They describe one typed test
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
  placeholder presence after the provider response.
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
  style warnings are non-blocking. Reconcile one closed terminal stop reason
  per applicable obligation across accounting and scenario realization, and
  distinguish provider response receipt from parsing, semantic validation,
  compilation, and publication in call evidence. Finish product `run` with
  non-blocking offline Phase 2 verification. Start from an exact zero-link
  resource-map baseline. Only an exact route credited by synthesis accounting
  may become an unreviewed `mechanism_enables_ica` proposal; other route joins
  remain `related_but_not_coverage`. Never auto-confirm correspondence.
  Publish the four standard Phase 2 artifacts, and retain a verification
  failure without deleting or invalidating generated scenarios.
  Publish a stable synthesis `run_status`: `completed` for full candidate
  yield, `no_candidates` for a valid run with no eligible candidates, `failed`
  only when requested candidates were attempted with zero published scenarios,
  and `degraded` for partial or unattempted yield. Keep candidate counts
  separate from diagnostic-message counts. Product `run` must publish its
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
- Keep harness installations and runtime state local; the repository owns only
  portable methodology, configuration, and scripts.
- Update `README.md`, this file, and linked documentation when an interface or
  workflow changes.
- `AGENTS.md` is a symlink to this file.
