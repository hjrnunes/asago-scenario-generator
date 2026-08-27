# End-to-end QA: taxonomy obligation planner

Drive a deterministic file-to-file obligation planner: a snapshot fixture
file in, a published YAML or JSON plan artifact out. That invocation is
a user-interface affordance; it is not `generate` or `stpa-run`, and it
is not required as a new public CLI subcommand. Inspect the artifact
with standard JSON/YAML readers, the console, and the filesystem. Do not
import project modules, call `plan_obligations`, or contact an LLM
endpoint. Never set `ASAGO_SCENARIO_GENERATOR_QA_PIPELINE`.

Use a fresh output directory for every case. The snapshot fixture pins
taxonomy version, mapping version, qualification ruleset version,
template version, and a deterministic digest. It must not require a
network or model client.

## QA-TOP-01: shared pattern keeps distinct risk-scoped obligations

1. Author a snapshot in which `atlas-prompt-injection` and
   `atlas-memory-poisoning` both map in-scope to `AP-T1-01`.
2. Produce the obligation-plan artifact.
3. Inspect the ledger with a standard YAML or JSON reader.

**Expected:** The ledger contains two obligations for `AP-T1-01`. Their
identifiers differ. Each obligation retains its own risk identity
(`atlas-prompt-injection` vs `atlas-memory-poisoning`). No network or
model call is recorded.

## QA-TOP-02: in-scope and out-of-scope relationships are both recorded

1. Author a snapshot in which `atlas-prompt-injection` has an in-scope
   mapping to `AP-T6-01` and an out-of-scope mapping to `AP-T11-01`.
2. Produce the obligation-plan artifact.
3. Inspect the scope decisions in the ledger.

**Expected:** The plan records an in-scope decision for
`atlas-prompt-injection`/`AP-T6-01` and an out-of-scope decision for
`atlas-prompt-injection`/`AP-T11-01`. Neither relationship is omitted.

## QA-TOP-03: every expected relationship has one terminal outcome

1. Author one snapshot with six expected relationships covering gated,
   governance-only, missing-template, infeasible, unsupported, and
   generated outcomes.
2. Produce the obligation-plan artifact.
3. Count ledger rows and terminal dispositions.

**Expected:** The ledger contains exactly six obligations. Every
obligation has exactly one terminal disposition. No expected
relationship is missing from the ledger.

## QA-TOP-04: pattern-bearing terminal dispositions are explicit

1. Author separate snapshot cases for:
   - gated threat `atlas-prompt-injection`/`AP-T11-01` (out-of-scope,
     disposition `gated`)
   - missing generation template `atlas-memory-poisoning`/`AP-T1-01`
     (in-scope, disposition `missing-template`)
   - projection infeasibility `atlas-memory-poisoning`/`AP-T1-02`
     (in-scope, disposition `infeasible`)
   - unsupported requirement `atlas-memory-poisoning`/`AP-T1-03`
     (in-scope, disposition `unsupported`)
   - qualified generable pattern `atlas-prompt-injection`/`AP-T6-01`
     (in-scope, disposition `generated`)
2. Produce a plan for each case.
3. Inspect the matching ledger row.

**Expected:** Each case publishes exactly one obligation for the named
risk and pattern, with the named scope and terminal disposition.

## QA-TOP-05: governance-only risks invent no pattern

1. Author a snapshot whose only risk is `atlas-orphan-risk` with no
   actionable attack pattern.
2. Produce the obligation-plan artifact.
3. Inspect the ledger row for that risk.

**Expected:** The ledger contains exactly one obligation for
`atlas-orphan-risk`. Its terminal disposition is `governance-only`. It
lists no attack-pattern ID.

## QA-TOP-06: qualification traces omit secrets

1. Put a configuration secret `sk-live-token` in the snapshot
   environment or configuration surface.
2. Make qualification applicable for `atlas-prompt-injection`/`AP-T6-01`
   with predicate `deployment.attacker_code_execution_on_agent_host`,
   facts `deployment.attacker_code_execution_on_agent_host=false`,
   result `false`, and reason `fact present and unequal`.
3. Produce the plan and inspect the qualification trace, then search
   the published artifact bytes for `sk-live-token`.

**Expected:** The trace records the predicate, facts, result, and
reason. The published artifact does not contain `sk-live-token`.

## QA-TOP-07: accepted and rejected candidates are retained

1. Make candidate expansion applicable for
   `atlas-prompt-injection`/`AP-T6-01`.
2. Include accepted candidate
   `cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` and rejected candidate
   `cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb` with reason
   `rule rejected combination`.
3. Produce the plan and inspect candidate evidence.

**Expected:** The obligation retains the accepted candidate ID and the
rejected candidate ID with its reason.

## QA-TOP-08: planning records zero network and model calls

1. Use any snapshot that contains in-scope and out-of-scope
   relationships.
2. Produce the plan while capturing call logs, endpoint logs, and
   environment.
3. Confirm `ASAGO_SCENARIO_GENERATOR_QA_PIPELINE` is unset.

**Expected:** Obligation planning recorded 0 network calls and 0 model
calls. No LLM endpoint is contacted.
