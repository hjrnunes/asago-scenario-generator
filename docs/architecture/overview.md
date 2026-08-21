# Architecture overview

Asago Scenario Generator has one shared domain and two supported generation
workflows.

## Shared domain

Pydantic models define capability profiles, taxonomy evidence, projected
attack chains, attack trees, behavior specifications, scenario envelopes, and
run manifests. Shared LLM adapters, deterministic validators, evaluation, and
reporting sit around those contracts.

Generation lifecycle contracts (retry directives, causal provider controls,
stage call evidence, and typed attempt failures) live in
`pipeline.generation_contracts`. Stage adapters, lifecycle policy, and
persistence consume that boundary without importing one another's
implementation modules.

## Taxonomy and risk-driven workflow

The `generate` workflow consumes a use-case description, policy risk
extraction, and SSSOM mappings. It derives a capability profile and threat
surface, expands and qualifies candidates, projects canonical chains, creates
scenario artifacts, and runs deterministic admission and evaluation gates.

The grouped taxonomy path keeps failures local and observable: malformed
candidate-filter responses are retried within their seed and then quarantined
with exact reconciliation evidence, while independent seeds continue. Before
authoritative projection, the immutable profile/fact snapshot is checked for
required architecture resources and qualification readings; missing evidence
stops the run with profile or qualification guidance and never launches an
enrichment workflow. Attack-tree transport may provide projected step IDs,
but canonical realizations are derived from the projection before strict
validation. The run manifest records status and admitted, quarantined, and
failed counts; the CLI returns nonzero for degraded completion or no admitted
scenarios.

## STPA workflow

The `stpa-run` workflow performs loss and hazard analysis, constructs the
control structure, enumerates unsafe control actions and threats, and produces
scenario, evaluation, and reporting artifacts. Its stages reuse shared
capability and infrastructure contracts while retaining STPA-specific models
and orchestration.

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
