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
- `ASAGO_SCENARIO_GENERATOR_TOP_P`
- `ASAGO_SCENARIO_GENERATOR_TOP_K`
- `ASAGO_SCENARIO_GENERATOR_USE_GUIDED_DECODING`
- `ASAGO_SCENARIO_GENERATOR_TIMEOUT`
- `ASAGO_SCENARIO_GENERATOR_EXTRA_HEADERS`

For named model profiles, copy
`config/model-profiles.example.yaml` to `config/model-profiles.yaml`. The real
file is ignored because it may contain credentials. Both `generate` and
`stpa-run` accept named profiles. STPA sampling values use the same precedence
through both routes: an explicit Python/CLI argument, then the selected profile
or environment value, then the client default. The CLI currently exposes
`--temperature` as the run-wide explicit sampling override. Invalid numeric or
boolean environment values fail before the first model call.
Requests have a 300-second application default deadline. Named-profile
`timeout` and `ASAGO_SCENARIO_GENERATOR_TIMEOUT` values override that default.
The SDK's implicit retries are disabled so retry decisions remain bounded and
visible in pipeline evidence.

Gemma 4 deployments used for structured generation need a compact JSON grammar
configuration to avoid valid-prefix responses stalling on whitespace. See the
[Gemma 4 vLLM runtime notes](docs/operations/gemma4-vllm-structured-output.md)
for the required serving argument and rollout guidance.

## Taxonomy and risk-driven generation

```bash
asago-scenario-generator generate \
  --use-case @use-case.txt \
  --risk-extraction risk-extraction.json \
  --sssom mappings.sssom.tsv \
  --output-dir output/my-system \
  --model-profile gemma4-local \
  --presentation-fallback allow
```

The pipeline profiles capabilities, determines the threat surface, qualifies
and projects candidates, generates scenario artifacts, evaluates them, and
writes an immutable run directory beneath the requested output collection.
Generation is exhaustive by default: every qualified projected candidate is
given an independent finalization target and can produce one admitted scenario.
Use `--generation-mode coverage` for a bounded smoke run that keeps one queue
of at most three candidates per feasible ingress and stops each queue after its
first admission.

`--max-scenarios-per-pattern N` applies after projection and deduplication. In
exhaustive mode it retains at most `N` qualified candidates per attack pattern,
round-robin across ingress points before taking a second candidate from one
ingress. Omitting the option means no pattern cap.

Run counts describe successive funnel stages: expanded candidates have not yet
passed filtering; qualified candidates have passed authoritative projection;
attempted candidates entered finalization; admitted candidates produced a
scenario; quarantined candidates exhausted generation or failed admission.

Automatic capability inference produces an `inferred_partial` Stage 1 profile.
Authoritative projection may also require operator-reviewed architecture data,
especially `trust_boundaries`, `external_integrations`, and explicit
qualification facts. For a substantive run, pass that reviewed profile with
`--profile` and, where applicable, fact readings with `--qualification-facts`.
An inferred-only run can finish with zero scenarios when the required
architecture evidence is unavailable.

Inspect the exact requirements without contacting an LLM endpoint:

```bash
asago-scenario-generator projection-preflight \
  --use-case @use-case.txt \
  --risk-extraction risk-extraction.json \
  --sssom mappings.sssom.tsv \
  --profile capability-profile.yaml \
  --qualification-facts qualification-facts.yaml \
  --facts-template qualification-facts.complete.yaml
```

The command reports every required resource and fact as structured JSON. Fact
states distinguish a missing reading (`absent`), an explicit undecided reading
(`unknown`), a supplied fact no longer required by the selected patterns
(`stale`), and incompatible readings for one fact (`contradictory`). A requested
facts template contains unknown values for operator review and is never allowed
to overwrite an existing file. If generation omits `--qualification-facts`, the
manifest records `qualification_facts_mode: omitted_compatibility`; command
output and the returned pipeline result also explain that unresolved conditions
are deferred to authoritative projection.

`--presentation-fallback` accepts `allow` (the default) or `forbid`. Allowing
fallback permits only cosmetic substitutions such as a missing narrative
title; it records a `presentation_fallback:` warning and produces
`completed_with_warnings`. It never synthesizes actor intent, narrative beats,
attack-tree topology, behavior interactions, or assertions.

Do not use process exit alone as the live-run success criterion. Inspect the
generated `run-manifest.yaml` and finalization inventory for admitted scenarios
and recorded errors. The manifest's `semantic_generation` block summarizes
whether every admitted candidate has accepted provider semantics for actor,
narrative, tree, and behavior; its `stage_records` retain the bounded
per-attempt evidence. The HTML report renders those stage outcomes and identifies
presentation fallback separately.

Useful companion commands include `projection-preflight`, `profile`, `resume`,
`eval`, `report`,
`qualify-catalog`, `validate-catalog-qualification`, and
`validate-stpa-projection`. Run `asago-scenario-generator --help` for the
complete interface.

## STPA-based generation

```bash
asago-scenario-generator stpa-run \
  --use-case use-case.txt \
  --risk-extraction risk-extraction.json \
  --output-dir output/my-system-stpa \
  --profile gemma4-local
```

The same Gemma sampling behavior can be configured without a profile:

```bash
export ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL=https://your-endpoint.example.com/v1
export ASAGO_SCENARIO_GENERATOR_MODEL_NAME=gemma-4-26b-a4b-it
export ASAGO_SCENARIO_GENERATOR_API_KEY=unused
export ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS=16384
export ASAGO_SCENARIO_GENERATOR_TEMPERATURE=1.0
export ASAGO_SCENARIO_GENERATOR_TOP_P=0.95
export ASAGO_SCENARIO_GENERATOR_TOP_K=64
export ASAGO_SCENARIO_GENERATOR_USE_GUIDED_DECODING=false
export ASAGO_SCENARIO_GENERATOR_TIMEOUT=300

asago-scenario-generator stpa-run \
  --use-case use-case.txt \
  --risk-extraction risk-extraction.json \
  --output-dir output/my-system-stpa
```

The STPA run manifest records effective model name, base URL, token limit,
temperature, `top_p`, `top_k`, guided-decoding state, and request timeout. API
keys and header values are never included.

Stage 2 retries a semantically empty requirement or responsibility response
once with corrective feedback. Stage 3 likewise retries a schema-invalid slot
response once.
If Stage 5 reaches the completion-length limit on both its normal and concise
retry attempts, it records a fatal diagnostic and aborts the remaining threats
instead of repeating a likely deployment-level structured-output failure.

STPA result and manifest diagnostics retain `stage_errors` for fatal stage
failures and add `stage_warnings` for recoverable normalization, stitching, and
repair diagnostics. This is an additive schema change. Existing consumers may
continue reading `stage_errors`, but successfully repaired SP1 diagnostics that
were historically misclassified there now appear only in `stage_warnings`.

The STPA pipeline runs SP1 through SP3 and writes the combined report. A report
can also be regenerated independently:

```bash
asago-scenario-generator stpa-report --output-dir output/my-system-stpa
```

Canonical Stage 6 projection artifacts (`stpa-execution-projection-v1`) can be
checked through the public validation command without reconstructing project
objects:

```bash
asago-scenario-generator validate-stpa-projection \
  output/my-system-stpa/scenarios/canonical/SCN-001.projection.json
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
