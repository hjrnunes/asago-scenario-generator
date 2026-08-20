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
- `ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS`

For named STPA profiles, copy
`config/model-profiles.example.yaml` to `config/model-profiles.yaml`. The real
file is ignored because it may contain credentials.

## Taxonomy and risk-driven generation

```bash
asago-scenario-generator generate \
  --use-case @use-case.txt \
  --risk-extraction risk-extraction.json \
  --sssom mappings.sssom.tsv \
  --output-dir output/my-system
```

The pipeline profiles capabilities, determines the threat surface, qualifies
and projects candidates, generates scenario artifacts, evaluates them, and
writes an immutable run directory beneath the requested output collection.

Automatic capability inference produces an `inferred_partial` Stage 1 profile.
Authoritative projection may also require operator-reviewed architecture data,
especially `trust_boundaries`, `external_integrations`, and explicit
qualification facts. For a substantive run, pass that reviewed profile with
`--profile` and, where applicable, fact readings with `--qualification-facts`.
An inferred-only run can finish with zero scenarios when the required
architecture evidence is unavailable.

Do not use process exit alone as the live-run success criterion. Inspect the
generated `run-manifest.yaml` and finalization inventory for admitted scenarios
and recorded errors.

Useful companion commands include `profile`, `resume`, `eval`, `report`,
`qualify-catalog`, and `validate-catalog-qualification`. Run
`asago-scenario-generator --help` for the complete interface.

## STPA-based generation

```bash
asago-scenario-generator stpa-run \
  --use-case use-case.txt \
  --risk-extraction risk-extraction.json \
  --output-dir output/my-system-stpa \
  --profile gemma4-local
```

The STPA pipeline runs SP1 through SP3 and writes the combined report. A report
can also be regenerated independently:

```bash
asago-scenario-generator stpa-report --output-dir output/my-system-stpa
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
