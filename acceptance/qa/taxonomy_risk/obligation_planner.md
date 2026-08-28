# End-to-end QA: taxonomy obligation planner

Drive a deterministic file-to-file obligation planner: a snapshot fixture
file in, a published YAML or JSON plan artifact out. That invocation is
a user-interface affordance; it is not `generate` or `stpa-run`, and it
is not required as a new public CLI subcommand. Inspect the artifact
with standard JSON/YAML readers, the console, and the filesystem. Do not
import project modules, call `plan_obligations`, or contact an LLM
endpoint. Never set `ASAGO_SCENARIO_GENERATOR_QA_PIPELINE`.

Use a fresh output directory for every case. The snapshot fixture pins
closed schema metadata, catalog and mapping pins, a capability snapshot,
qualification facts, and generation inputs. Digests must be computed
from canonical content. The snapshot must not require a network or model
client.

Inspect only published plan fields and qualification-trace values. Do
not assert that arbitrary words are absent from the whole serialized
schema.

## QA-TOP-01: shared pattern keeps distinct risk-scoped obligations

1. Author a snapshot in which `atlas-prompt-injection` and
   `atlas-memory-poisoning` both map as applicable to `AP-T1-01`.
2. Produce the obligation-plan artifact.
3. Inspect the ledger with a standard YAML or JSON reader.

**Expected:** The ledger contains two obligations for `AP-T1-01`. Their
identifiers differ. Each obligation retains its own risk identity
(`atlas-prompt-injection` vs `atlas-memory-poisoning`). No network or
model call is recorded.

## QA-TOP-02: applicable and capability-excluded relationships are both recorded

1. Author a snapshot in which `atlas-prompt-injection` has an
   applicable mapping to `AP-T6-01` and a capability-excluded mapping
   to `AP-T11-01`.
2. Produce the obligation-plan artifact.
3. Inspect the scope dispositions in the ledger.

**Expected:** The plan records scope disposition `applicable` for
`atlas-prompt-injection`/`AP-T6-01` and scope disposition
`capability_excluded` for `atlas-prompt-injection`/`AP-T11-01`. Neither
relationship is omitted.

## QA-TOP-03: every expected relationship has one closed disposition on every axis

1. Author one snapshot with six expected relationships covering
   capability-excluded, governance-only, missing-evidence,
   contradictory-evidence, structurally-infeasible, and ready
   outcomes.
2. Produce the obligation-plan artifact.
3. Count ledger rows and inspect each disposition axis.

**Expected:** The ledger contains exactly six obligations. Every
obligation has exactly one scope disposition, exactly one
qualification disposition, and correspondence disposition
`not_assessed`. No expected relationship is missing from the ledger.

## QA-TOP-04: closed scope and qualification dispositions are explicit

1. Author separate snapshot cases for:
   - capability-gated pattern `atlas-prompt-injection`/`AP-T11-01`
     (scope `capability_excluded`, qualification `not_attempted`,
     candidate projection `not_attempted`)
   - missing qualification facts `atlas-memory-poisoning`/`AP-T1-01`
     (scope `applicable`, qualification `missing_evidence`, candidate
     projection `not_attempted`)
   - contradictory facts `atlas-memory-poisoning`/`AP-T1-04` (scope
     `applicable`, qualification `contradictory_evidence`, candidate
     projection `not_attempted`)
   - structurally infeasible `atlas-memory-poisoning`/`AP-T1-03`
     (scope `applicable`, qualification `structurally_infeasible`,
     candidate projection `not_attempted`)
   - qualified projectable `atlas-prompt-injection`/`AP-T6-01` (scope
     `applicable`, qualification `ready`, candidate projection
     `projectable`)
2. Produce a plan for each case.
3. Inspect the matching ledger row.

**Expected:** Each case publishes exactly one obligation for the named
risk and pattern, with the named scope, qualification, correspondence
`not_assessed`, and candidate projection disposition, plus evidence
for that relationship kind.

## QA-TOP-05: governance-only risks invent no pattern

1. Author a snapshot whose only risk is `atlas-orphan-risk` with no
   actionable attack pattern.
2. Produce the obligation-plan artifact.
3. Inspect the ledger row for that risk.

**Expected:** The ledger contains exactly one obligation for
`atlas-orphan-risk`. Its scope disposition is `governance_only`. Its
qualification disposition is `not_attempted`. Its correspondence
disposition is `not_assessed`. It lists no attack-pattern ID.

## QA-TOP-06: qualification traces omit secrets from sensitive values

1. Put an unmistakable configuration secret `SECRET_live_token_END` in
   the snapshot environment or configuration surface.
2. Make qualification applicable for `atlas-prompt-injection`/`AP-T6-01`
   with predicate `deployment.attacker_code_execution_on_agent_host`,
   facts `deployment.attacker_code_execution_on_agent_host=false`,
   result `false`, and reason `fact present and unequal`.
3. Produce the plan and inspect the qualification-trace predicate,
   facts, result, and reason.

**Expected:** The trace records the predicate, facts, result, and
reason. None of those sensitive trace values contains
`SECRET_live_token_END`.

## QA-TOP-07: candidate records retain projection dispositions

1. Make candidate projection applicable for
   `atlas-prompt-injection`/`AP-T6-01`.
2. Include:
   - `cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` with projection
     disposition `projectable` and reason `qualified combination`
   - `cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb` with projection
     disposition `projection_infeasible` and reason
     `missing required resource`
   - `cand:v2:cccccccccccccccccccccccccccccccc` with projection
     disposition `budget_deferred` and reason
     `projection budget exhausted`
3. Produce the plan and inspect candidate records.

**Expected:** The obligation retains each candidate ID with its
projection disposition and reason.

## QA-TOP-08: planning records zero network and model calls

1. Use any snapshot that contains applicable and capability-excluded
   relationships.
2. Produce the plan while capturing call logs, endpoint logs, and
   environment.
3. Confirm `ASAGO_SCENARIO_GENERATOR_QA_PIPELINE` is unset.

**Expected:** Obligation planning recorded 0 network calls and 0 model
calls. No LLM endpoint is contacted.

## QA-TOP-09: identity-bearing input changes change obligation IDs

1. Author paired snapshots that otherwise share the remaining
   identity-bearing inputs but differ in one of:
   - risk ID `atlas-prompt-injection` versus `atlas-memory-poisoning`
   - pattern ID `AP-T6-01` versus `AP-T1-01`
   - capability snapshot `profile-v1` versus `profile-v2`
   - catalog pin `atlas-2026.05` versus `atlas-2026.06`
   - mapping pin `sssom-v1` versus `sssom-v2`
2. Produce a plan from each snapshot.
3. Compare obligation identifiers and semantic digests.

**Expected:** Each pair has different obligation identifiers and
different semantic digests.

## QA-TOP-10: ICA prose keyword changes do not change the plan

1. Author paired snapshots that share the same risks, patterns, and
   pins but include ICA prose `the agent injects a prompt` versus
   `the agent poisons memory`.
2. Produce a plan from each snapshot.
3. Compare obligation identifiers, semantic digests, and dispositions.

**Expected:** Both plans have identical obligation identifiers,
identical semantic digests, identical scope dispositions, and
identical qualification dispositions.

## QA-TOP-11: invalid scope and qualification combinations are rejected

1. Author snapshots that would combine:
   - scope `governance_only` with qualification `ready`
   - scope `capability_excluded` with qualification `missing_evidence`
   - scope `applicable` with qualification `not_attempted`
2. Attempt to produce a plan for each combination.
3. Inspect console output and the output directory.

**Expected:** Planning is rejected. No partial plan is published. The
result identifies the disposition combination as invalid.

## QA-TOP-12: summary counts are derived from obligation rows

1. Author a snapshot whose rows cover every summary category and
   produce six obligations: four applicable, one governance-only, one
   capability-excluded; among applicable rows, one ready, two
   missing-or-contradictory, one structurally infeasible; among
   candidate records, one projectable, one projection-infeasible, one
   budget-deferred.
2. Produce the plan and inspect the summary with a standard reader.
3. Recompute the same counts from the obligation rows.

**Expected:** The published summary matches those derived counts. The
summary does not include a taxonomy correspondence rate or a scenario
realization rate.
