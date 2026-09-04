# Klarna live prompt-contract recovery fixes

Status: implemented and live-qualified  
Date: 2026-09-04  
Evidence run: `output/runs/20260904-klarna-gemma4-oc-prompt-contract-recovery-v1`
Qualification run: `output/runs/20260904-klarna-gemma4-oc-wire-contract-recovery-v2`

Qualification outcome: 26 candidates were attempted, 25 scenarios and 25
execution-bundle entries were published, and one candidate failed during a
Stage 6 connection interruption. All routing responses included their required
branch fields; no Stage 5 response omitted `execution_route.disposition` or
`unsafe_outcome.condition.type`. One routing batch remained unresolved after
Gemma changed an opaque obligation identifier during its bounded correction.

## 1. Objective

Restore useful scenario yield without weakening the semantic checks added to
the STPA pipeline. Provider-facing JSON schemas, rendered instructions,
examples, retry feedback, and local validators must describe the same closed
contract. A provider response that follows the advertised schema must not fail
because a discriminator or conditionally required field was advertised as
optional.

The correction must preserve these existing boundaries:

- STPA remains the sole scenario-generation authority.
- Taxonomy obligations remain questions for STPA, not required mechanisms.
- The provider describes a test stimulus and chooses from request-local
  handles; deterministic code owns durable identities, resource roles,
  binding completeness, and publication.
- Unsupported or ungrounded routes remain analytical or fail closed.
- One bounded correction attempt remains the maximum.
- Missing fields are not silently inferred from prose.

## 2. Live evidence and diagnosis

### 2.1 Run outcome

The pipeline command completed and published its accounting artifacts, but no
scenario reached Stage 6:

| Measure | Result |
| --- | ---: |
| Taxonomy-plan rows | 76 |
| Governance-only rows | 43 |
| Applicable obligations | 33 |
| ICA scenario candidates | 38 |
| Stage 5 calls | 76 |
| Published scenarios | 0 |
| Failed candidates | 38 |
| Skipped candidates | 0 |

Every candidate received an initial Stage 5 attempt and one correction. No
execution bundle was published, so artifact-generator readiness could not run.

### 2.2 P0: structural-routing wire contract is inconsistent

The five routing batches each exhausted two attempts. Across the 66 returned
route objects:

- all 66 had `rationale: null` or an empty rationale;
- 33 were `unresolved` and 33 were `proposed_not_applicable`;
- no route was accepted because each batch contained at least one route whose
  disposition required a non-empty top-level rationale;
- one correction attempt also changed one opaque obligation ID by one
  character, which the existing exact-set check would correctly reject once
  parsing reaches it.

This is a contract defect:

- `_RoutingProviderRoute.rationale` is optional in the generated provider
  schema;
- `ObligationRoute` requires a non-empty rationale for unresolved,
  proposed-not-applicable, and upstream-gap routes;
- the routing prompt says to supply a rationale, but its advertised valid JSON
  example omits `rationale` and most of the listed route fields;
- the correction repeats the same schema and example.

The semantic content should not be discarded. The unique obligation
assessments returned by Gemma were predominantly conservative:

- 19 mechanisms assessed absent from the supplied system;
- 15 assessed as having insufficient evidence;
- 25 risk-pattern alignments assessed as mismatches;
- 9 assessed as having insufficient alignment evidence;
- all mappings were broad or related category expansions.

Those results are consistent with the known weak risk-to-pattern crosswalk.
They must remain visible as reviewed hypotheses after the wire contract is
fixed.

### 2.3 P0: Stage 5 route discriminator is omitted by design

All 76 Stage 5 responses omitted `execution_route.disposition`. The live
failure is deterministic and replayable from `calls.jsonl`.

The generated route schema contains a `disposition` property but does not list
it as required because the Pydantic variants give the field a default. The
prompt then explicitly says:

> The route itself contains only `delivery_class`,
> `selected_factor_handle`, `action_kind`, and a concise reason.

The parser uses `disposition` as the discriminated-union tag. The model did
exactly what the prompt and generated schema suggested and every response
failed before semantic route validation.

The correction attempt named the missing discriminator, but it retained the
contradictory route description and an optional discriminator in the response
schema. All 38 corrected responses omitted it again.

### 2.4 P0: semantic-condition discriminators are optional in the schema

The inward semantic-condition variants give their `type` discriminator a
default. Their generated schemas therefore expose `type` as a property but not
as a required field, while the discriminated union cannot parse an object
without it.

Observed Stage 5 results:

- initial responses missing `unsafe_outcome.condition.type`: 27 of 38;
- corrected responses still missing it: 12 of 38;
- the correction text repaired 15 cases, showing that the model can produce
  the field when the contract is explicit;
- the remaining ambiguity is created by the schema and prompt, not by an
  unavailable model capability.

### 2.5 P1: conditional temporal/evidence shapes are not represented

The provider temporal draft is one object with a required `type` and several
optional fields. A model can therefore satisfy the JSON schema while failing
the local condition validator. Among final corrected responses:

- 8 lacked `reference_handle`;
- 2 lacked `until_step_handle` for `absence`;
- 1 lacked `delay_ms` for `delay`;
- 1 declared `bounded_assumption` evidence without the required assumption
  text.

The prompt names the concepts but gives no complete request-local JSON shape
for each branch. These are conditional-schema failures, not reasons to relax
temporal or evidence integrity.

### 2.6 What already improved and must be retained

The live run demonstrates that several earlier corrections worked:

- all 38 final Stage 5 responses chose a delivery class consistent with their
  stimulus category: 12 direct prompts, 15 conversation-context routes, and
  11 indirect-content routes;
- provider responses no longer choose compiler-owned resource-role sets;
- all 38 ICA deviations were concise: 8–19 words, 14 words on average;
- ICA correction recovered two malformed constraint references;
- four semantically plausible but structurally invalid WRONG_DURATION drafts
  were corrected according to the action-temporality contract;
- Stage 2 recovered one malformed responsibility collection through its
  bounded retry;
- raw failed responses and token/receipt evidence were retained, making this
  diagnosis possible.

These contracts are not to be rolled back.

### 2.7 P1: upstream semantic consistency remains incomplete

Two non-yield issues remain visible:

1. Several Stage 1 hazards are written as causes, attacks, or component
   failures rather than system-level hazardous states. For example, one begins
   with an adversary manipulating an interface and another describes an
   integration being severed. The prompt already defines the distinction, but
   one unrelated contrast example was insufficient to make it reliable.
2. The Stage 2 critic returned `absent_unjustified` checklist results while its
   explicit `gaps` collection was empty. This triggered a revision call whose
   response was `{}`. The response was transport-valid and the baseline was
   correctly retained, but the call had no actionable revision request.

These should be corrected without adding an open-ended model loop.

## 3. Design decisions

### 3.1 Provider wire models are distinct from inward models

Provider schemas must describe what the provider must send. Inward models may
retain constructor defaults for trusted deterministic callers, but those
defaults must not make provider discriminators optional.

Create explicit provider-wire variants for routing, Stage 5 execution routes,
unsafe conditions, temporal conditions, and causal evidence. Each union tag is
a required field with no default. After strict wire parsing, deterministic
code constructs the existing inward types.

Do not repair a missing discriminator by inspecting prose or guessing from
neighbouring fields. A missing tag remains a provider-contract failure eligible
for the one correction attempt.

### 3.2 Conditional requirements belong in types

Use discriminated unions whose branches make their own meaningful fields
required and exclude fields belonging to other branches. Do not advertise one
wide object and rely only on an after-validator to express its real shape.

### 3.3 Prompt examples are executable contract fixtures

Every JSON example included in a provider prompt must be produced from, or
validated against, the exact provider-wire model used for that request. A
handwritten example may not omit required fields.

Only render the branch examples relevant to the current request. Do not paste
the complete global schema into the prose.

### 3.4 Retries correct one exact response

The retry remains one attempt. It receives:

- the same strict response schema;
- a compact field-specific repair list;
- the one relevant typed JSON skeleton;
- the original request-local choices and identities.

The retry does not receive a broader context, invent replacement identities,
or restart the stage.

## 4. Required implementation

### 4.1 Structural-routing provider contract

Refactor the provider-facing route in
`stpa/obligation_aware/provider.py` into a closed union keyed by required
`disposition`:

- `targeted`: non-empty structural path, hazard and constraint references,
  evidence, semantic assessment, and rationale;
- `proposed_not_applicable`: semantic assessment, non-empty rationale and
  evidence, with no missing concepts;
- `upstream_gap`: non-empty missing concepts, rationale and evidence;
- `unresolved`: non-empty rationale and evidence, without fabricated
  structural placement.

All branches must require the exact copied `obligation_id`. Common empty
collections may remain explicit defaults only in the inward compiled route;
the provider schema should expose only fields meaningful to its branch.

Update the structural-routing templates so that:

- `rationale` is defined plainly as the explanation for the selected route
  disposition;
- the semantic assessment rationales remain the two separate judgements about
  mechanism plausibility and risk alignment;
- the valid example is a complete typed object, including `rationale`;
- at least one complete targeted example and one complete unresolved example
  are rendered from validated domain-neutral fixtures;
- no example implies that category expansion is mechanism evidence.

Keep the exact identity-set check. A copied obligation ID that changes by one
character must cause the batch correction, not be normalized.

### 4.2 Stage 5 execution-route wire contract

In `stpa/scenario_prod/bdi_generation.py`, replace defaulted provider route
tags with strict provider-wire branches:

- executable route requires
  `disposition: "executable_route"`, `delivery_class`,
  `selected_factor_handle`, the exact request action kind, and `reason`;
- analytical route requires
  `disposition: "analytical_only"`, one or more typed gaps, and `reason`.

The executable-route prompt description must name all five fields. The compact
example for the current request must include `disposition`. The analytical
example must include its own disposition and complete gap shape.

The provider still does not return resource roles, attacker-influence flags,
binding completeness, or the materialized execution contract.

### 4.3 Provider-wire unsafe conditions

Keep `models/semantic_conditions.py` as the inward closed value model. Add a
provider-wire layer in the Stage 5 boundary in which every `type` tag is
required with no default.

Build the request-specific unsafe-condition union from the selected UCA and
available authority:

- `NOT_PROVIDED`: `action_presence` with exact target action and required
  `expected: "not_provided"`;
- `INCORRECT`: `action_value`, plus `state_value` only when an exact state
  subject is supplied;
- `WRONG_TIMING`: only the timing variants supported by supplied references;
- `WRONG_DURATION`: `duration` only when action temporality makes that slot
  eligible.

Each rendered prompt includes one small valid skeleton for its selected branch.
The provider must explicitly return `type`; deterministic code must not infer
it from `subject_ref`, `control_action_id`, or other fields.

### 4.4 Provider-wire temporal conditions

Replace `_ContextTemporalConditionDraft` with a strict request-local union:

- ordering: `type`, `reference_handle`, `relation`;
- delay: `type`, `reference_handle`, `delay_ms`;
- duration: `type`, `reference_handle`, `duration_ms`;
- window: `type`, `reference_handle`, `window_from_ms`, `window_to_ms`;
- absence: `type`, `reference_handle`, `until_step_handle`.

All other branch fields are forbidden. `null` remains the explicit value when
no separately supported temporal condition exists. The prompt renders only
the available local handles and a concise example for each permitted branch.

### 4.5 Provider-wire causal evidence

Express the evidence-status dependency in the provider schema:

- `structural_failure`: no capability/access references or assumption text;
- `reachable_capability`: exact non-empty capability and access references;
- `bounded_assumption`: non-empty bounded-assumption text and no capability or
  access claim.

Preserve the existing deterministic authority checks after parsing. This
change makes the schema teach the provider the same rule rather than weakening
the rule.

### 4.6 Field-specific correction prompt

Build correction feedback from stable validation codes rather than a raw
Pydantic paragraph alone. At minimum support:

- missing route disposition;
- missing unsafe-condition type;
- missing route rationale;
- missing temporal branch field;
- incomplete evidence-status branch;
- copied opaque identity mismatch.

The feedback names the exact missing or invalid field and supplies the relevant
validated skeleton. The raw error remains in call evidence but is not the only
instruction given to the provider.

### 4.7 Stage 1 hazard framing

Retain the existing loss-analysis method and greenhouse example. Add two short
domain-neutral cause-to-state contrasts, for example:

- cause: an attacker sends a spoofed command; hazardous state: a robot enters
  a human-occupied restricted area;
- cause: an upstream service fails; hazardous state: orders continue to be
  accepted while the system cannot fulfil or safely cancel them.

State explicitly that adversary action is selection context, not the grammar
of the hazard. The hazard begins from the unsafe system state; attack and
component-failure details belong in later causal analysis.

This is a semantic writing improvement, not a keyword rejection gate. Do not
reject hazards through a verb blacklist.

### 4.8 Critic and revision consistency

At the critic boundary, require every `absent_unjustified` checklist or
taxonomy result to be represented by at least one explicit gap that states the
missing concept and evidence. A response with unjustified absences and no gaps
gets the one bounded correction.

Only call revision when there is an explicit actionable gap. When gaps exist,
an empty revision delta is not a successful semantic revision: the provider
must add/modify structure or explicitly dismiss every supplied gap with a
reason. On exhaustion, retain the baseline and the original gaps exactly.

`revised` continues to mean that a validated change was applied, not that a
provider call occurred.

### 4.9 Zero-yield product status

The run must continue writing its diagnostic and accounting artifacts, but a
run with `requested > 0`, `attempted > 0`, and `generated == 0` is a failed
scenario-generation outcome. Expose a stable terminal status and return a
non-zero CLI result after safe publication of diagnostics.

A run with no eligible candidates is a valid analysis outcome and remains
distinct. A partial-yield run may complete as degraded while preserving each
candidate outcome.

Do not count diagnostic messages as failed candidates.

## 5. Acceptance contract

Add or extend normative Gherkin and runtime coverage for the following cases.

### Routing

1. The generated provider schema requires the disposition-specific rationale
   and evidence fields.
2. Every routing JSON example in the rendered prompt parses through the exact
   provider-wire model.
3. A complete unresolved route survives compilation and remains unresolved.
4. A route with `rationale: null` receives one focused correction.
5. A one-character change to an opaque obligation handle is rejected.
6. One malformed route does not erase the identities or diagnostics of its
   batch.

### Stage 5

7. Both route branches require an explicit `disposition` in the provider
   schema.
8. Every unsafe-condition branch requires an explicit `type`.
9. The request-specific schema exposes only condition families permitted for
   the selected UCA and authority.
10. Each temporal branch requires exactly its meaningful fields.
11. Each evidence-status branch requires exactly its supporting evidence.
12. Every rendered JSON skeleton parses through the exact request-specific
    provider model.
13. A response missing a discriminator fails; deterministic code does not add
    it.
14. The one correction can repair missing discriminators without changing the
    scenario, slot, action, hazard, or constraint identities.
15. Stimulus-to-delivery mapping and compiler-owned resource derivation remain
    unchanged.

### Upstream and run outcome

16. An unjustified critic checklist result without an explicit gap receives
    one correction and cannot trigger an empty revision.
17. An empty revision cannot resolve a non-empty gap set.
18. A concise ICA retains the compiler-owned UCA category and temporal
    eligibility behavior.
19. Positive attempted candidates with zero publications preserve artifacts
    and produce a failed CLI status.
20. Partial yield reports published, failed, and skipped candidates separately.

## 6. Direct regression fixtures

Create small sanitized fixtures from the structural shapes observed in this
run; do not commit Klarna prose as the regression input.

- routing response with valid semantic assessments but null route rationale;
- executable Stage 5 route missing `disposition`;
- unsafe condition missing `type`;
- absence condition missing `reference_handle` or `until_step_handle`;
- bounded-assumption evidence missing its explanation;
- opaque obligation handle changed by one character.

The tight deterministic replay must prove the exact live failure before the
fix and pass afterward without an endpoint.

## 7. Quality sequence

Implement in this order:

1. provider-wire types and schema assertions;
2. prompt examples generated from those types;
3. routing and Stage 5 regression replays;
4. correction feedback;
5. critic/revision consistency;
6. zero-yield CLI status;
7. reports and documentation.

Then run:

```bash
./scripts/quality.sh
./scripts/acceptance.sh
uv run pytest tests/ -q
```

Changed production functions must meet CRAP <= 6 with fresh branch coverage.
Keep source mutation out of the implementation loop until the complete
deterministic behavior is green; mutation hardening may follow as a separate
bounded pass.

## 8. Live qualification after deterministic completion

Run Klarna once with `gemma4-oc` only after all deterministic gates pass. The
qualification succeeds when:

- no routing batch exhausts because a required rationale was advertised as
  optional;
- no Stage 5 response fails for a missing `disposition` or `type` that the
  provider schema advertised as optional;
- every candidate has one exact terminal outcome;
- at least one valid scenario and execution-bundle entry are published;
- any remaining failures are specific semantic disagreements or unsupported
  routes, not universal wire-shape defects;
- the artifact generator can run readiness against the resulting non-empty
  execution bundle.

The exact scenario count is evidence, not a hard-coded acceptance number.
Compare it with the prior 18/35 and 24/27 Klarna results, and manually review
the published scenario meaning before making a quality claim.

## 9. Likely files

- `src/asago_scenario_generator/models/obligation_consideration.py`
- `src/asago_scenario_generator/stpa/obligation_aware/provider.py`
- `src/asago_scenario_generator/stpa/obligation_aware/routing.py`
- `src/asago_scenario_generator/stpa/obligation_aware/prompt_templates/structural_routing_system.j2`
- `src/asago_scenario_generator/stpa/obligation_aware/prompt_templates/structural_routing_user.j2`
- `src/asago_scenario_generator/stpa/scenario_prod/bdi_generation.py`
- `src/asago_scenario_generator/stpa/scenario_prod/prompts/stage5_context_system.j2`
- `src/asago_scenario_generator/stpa/scenario_prod/prompts/stage5_context_user.j2`
- `src/asago_scenario_generator/stpa/system_model/critic.py`
- `src/asago_scenario_generator/stpa/system_model/prompts/stage1a_risk_system.j2`
- `src/asago_scenario_generator/stpa/system_model/prompts/_loss_analysis_method.j2`
- `src/asago_scenario_generator/pipeline/synthesis.py`
- `src/asago_scenario_generator/cli/stpa_commands.py`
- `src/asago_scenario_generator/report/synthesis.py`
- corresponding unit, property, feature, acceptance-runtime, README, CONTEXT,
  and architecture documentation.

## 10. Completion criteria

The work is complete when every acceptance case above is green, all prompt
examples are mechanically schema-valid, all provider tags and conditional
fields are required in the advertised wire schema, candidate accounting and
zero-yield status are truthful, deterministic gates pass, and one fresh Klarna
run produces a non-empty bundle without either universal contract failure.
