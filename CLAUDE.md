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
  generation projection remains `ProjectionBatch`-compatible.
- Keep harness installations and runtime state local; the repository owns only
  portable methodology, configuration, and scripts.
- Update `README.md`, this file, and linked documentation when an interface or
  workflow changes.
- `AGENTS.md` is a symlink to this file.
