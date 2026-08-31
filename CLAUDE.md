# Asago Scenario Generator

Pre-alpha adversarial-scenario generation for AI systems, with taxonomy/risk
and STPA workflows maintained as peer product surfaces.

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
  observational taxonomy-obligation planner, the taxonomy/risk pipeline, the
  STPA pipeline, CLI, evaluation, and reporting. The planner consumes typed
  inputs and must not import either generation workflow's implementation.
- `data/` contains committed schemas, taxonomies, mappings, and qualification
  inputs.
- `features/` is the source of truth for acceptance behavior;
  `acceptance/` contains the portable generator, runtime, and handlers.
- `config/` contains sanitized examples and portable project configuration.

Read `docs/architecture/overview.md` before changing cross-pipeline contracts.
Read `docs/development/swarmforge.md` when planning or executing feature work,
changing acceptance behavior, or running the quality sequence.

## Development

- Track durable work and specification approval in GitHub Issues and PRs.
- Preserve both generation approaches unless the issue explicitly changes
  their shared contract.
- Keep Phase 1 obligation planning observational: it retains every reviewed
  risk, uses the exact closed row schema and typed dispositions, computes and
  verifies digests, publishes atomically, and leaves `generate`/`stpa-run`
  prompts, counts, and artifacts unchanged. Persistence validation belongs to
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
  YAML artifacts atomically. Neither existing generation workflow may import
  or require Phase 2 artifacts, and Phase 2 must not construct provider clients
  or contact endpoints.
- Keep harness installations and runtime state local; the repository owns only
  portable methodology, configuration, and scripts.
- Update `README.md`, this file, and linked documentation when an interface or
  workflow changes.
- `AGENTS.md` is a symlink to this file.
