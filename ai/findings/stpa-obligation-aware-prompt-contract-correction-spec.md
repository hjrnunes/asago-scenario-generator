# STPA obligation-aware prompt and scenario-continuity correction

**Status:** Implemented and live-qualified on 2026-09-01. See
[stpa-obligation-aware-prompt-contract-live-qualification-2026-09-01.md](stpa-obligation-aware-prompt-contract-live-qualification-2026-09-01.md).

**Parent specification:**
[stpa-taxonomy-obligation-aware-stpa-spec.md](stpa-taxonomy-obligation-aware-stpa-spec.md)

**Purpose:** Make the synthesis workflow preserve meaning across model calls.
Taxonomy continues to provide obligations for STPA to consider. STPA continues
to decide whether and how a concern appears in the system. The correction does
not turn taxonomy mechanisms into mandatory STPA scenarios.

This document is normative where it makes prompt contracts, validation,
context continuity, and scenario-realization rules more precise than the
parent specification. In particular, it supersedes the earlier requirement
that standalone `stpa-run` prompts remain byte-for-byte unchanged. Its public
command and artifact compatibility remains required, but the defective shared
prompt contracts described here must be corrected.

## 1. Plain-language decision

The synthesis design is still correct:

1. Taxonomy says, “this known concern must be considered.”
2. STPA examines the actual system and decides whether there is a credible
   unsafe-control path.
3. STPA may find one, explain why there is none, identify missing structure,
   or remain uncertain.
4. When STPA finds a path, ordinary scenario generation develops it into a
   causal scenario.
5. Phase 2 remains responsible for any later claim that the STPA finding and
   taxonomy mechanism are confirmed correspondence or coverage.

The live runs exposed a different problem: the information crossing those
steps is poorly shaped. Some prompts receive large internal records that are
not explained or useful, while later prompts lose the small amount of meaning
that is essential. Valid identifiers survive, but the concern, unsafe action,
hazard, constraint, and causal mechanism can change underneath them.

The correction therefore follows one rule:

> Give each model call only the information needed for its decision, explain
> every item it must use, and carry the exact accepted meaning into every
> later stage.

## 2. Observed failures

The evidence comes from these completed runs:

- Klarna:
  `output/runs/20260901-synthesis-klarna-gemma4-oc-live-v10`
- NHS:
  `output/runs/20260901-synthesis-nhs-gemma4-oc-live-v6-reused-baseline`

The runs produced 24 scenarios: 20 Klarna and 4 NHS. They proved that the
workflow executes, but not that its model-call contracts preserve meaning.

### 2.1 Control actions lost their descriptions and ownership

The Stage 2 call-2b prompt described “CA objects” but did not state the exact
required fields. Its example combined the control-action ID and description in
one string. The model followed that example and returned values such as:

```json
{"action": "CA-1-1 Mask sensitive identifiers in payload"}
```

The runtime expected separate `ca_id`, `description`, and `target` fields. A
tolerant decoder filled missing strings with empty values and discarded the
unknown `action` field. Later normalization replaced the lost descriptions
with text such as `Control action CA-1-1` and distributed actions without valid
ownership by list order.

All control-action descriptions in both final live control structures were
generic placeholders: 11 of 11 for Klarna and 6 of 6 for NHS. Meaningful
actions were also moved between responsibilities and controlled processes.

### 2.2 Obligation-routing prompts were large but under-explained

The provider-facing “neutral brief” retained most of the durable Phase 1
record. Prompts included values such as:

- semantic digests and artifact pins;
- absolute local source paths;
- retrieval and reranking scores;
- raw mapping JSON encoded as a string;
- long mitigation lists;
- unexplained capability codes;
- taxonomy and qualification identifiers without usage instructions.

Each batch also repeated the complete loss analysis, control structure, and
slot universe. The routing stage consumed approximately 396,851 prompt tokens
for Klarna and 321,664 for NHS. Individual calls commonly used 9,000–15,000
prompt tokens.

The validator proved that returned IDs existed, but not that a selected
constraint governed the selected hazard or that the target control path made
sense for the concern. The live outputs therefore contained structurally
valid but semantically incompatible routes.

### 2.3 The bounded-revision prompt forced bad gaps into additions

Revision requests exposed internal handles and malformed or unexplained
references. The instruction to “additively resolve these gaps” did not allow
the model to say that a proposed gap was unsupported or nonsensical. It also
did not clearly distinguish request-local handles from final STPA IDs.

The Klarna revision returned dangling references, including identifiers for
constraints and process-model parts it had not created, and ended as a
technical failure.

### 2.4 The obligation-aware ICA prompt discarded the established STPA method

The ordinary Stage 3 prompt already defines the four unsafe-control-action
types, gives examples, explains N/A, and requires an unsafe action in prose.
The synthesis-specific prompt did not carry those instructions forward. It
asked the model to fill slots and showed invalid-looking empty slot objects,
but did not explain what an ICA is or how each type differs.

As a result, safeguards and requirements were accepted as unsafe control
actions, for example “Implement strong authentication” and “Implement rate
limiting.” The model also populated the four types mechanically, with weak
timing and duration semantics.

The prompt rendered the complete control structure despite claiming to be
target-scoped. Three calls exceeded the 32k context window: Klarna RESP-3 and
RESP-4, and NHS RESP-2. Those responsibilities consequently contributed no
normal ICA results or scenarios.

### 2.5 Scenario generation changed the selected concern

Stage 5 received identifier-only values such as `Hazardous Context: H-6` and
`Loss Scenario: L-6`, but not the descriptions that give those IDs meaning. It
also received mitigation-shaped ICA text and a broad list of technologies
labelled susceptible whether or not they were reachable through the selected
control path.

One Klarna scenario began from an ICA about rate limiting and automated
mass-action abuse but was rewritten as a PII-classification and masking
bypass. The IDs still joined, while the subject of the scenario changed.

The Stage 5 response model supports causal factors, but the prompt's output
schema omitted them and the field defaulted to an empty list. None of the 24
generated scenarios contained typed causal factors.

### 2.6 Narrative, attack-tree, and Gherkin stages lost the original ICA

The scenario contract did not retain the original ICA statement, described
hazard, selected constraints, or obligation consideration. Later stages
reconstructed the source as only `ICA type: X on CA-Y`.

The Gherkin adapter selected the first global security constraint when it
could not resolve a local one. NHS EHR-integrity scenarios therefore received
the privacy constraint `SC-1` and faithfully rendered the wrong requirement.

The later prompts then invented causal detail because the exact accepted
context was no longer available.

### 2.7 Provisional accounting could be structurally true but misleading

Two Klarna obligations were linked to an ICA by exact IDs, so the accounting
correctly recorded that STPA had produced a finding. The downstream scenario,
however, no longer represented either obligation's concern.

This does not make the Phase 1 or accounting identities wrong. It means the
pipeline needs a separate scenario-realization result and must not infer it
from an obligation-to-ICA link alone.

### 2.8 Prompt-volume baseline

The call traces reported these approximate prompt-token totals:

| Stage | Klarna | NHS | Observed problem |
| --- | ---: | ---: | --- |
| Obligation routing | 396,851 | 321,664 | Repeated complete artifacts and audit-only fields |
| Obligation-aware ICA | 41,423 | 37,017 | Two Klarna and one NHS context-length failures |
| Structural revision | 6,057 | 6,641 | Unclear handles and forced invalid additions |
| Stage 5 scenario/BDI | 77,231 | 10,058 | Identifier-only context and empty causal factors |
| Stage 6 renderers | 147,978 | 23,802 | Exact ICA and constraint meaning already lost |
| **Total** | **669,540** | **399,182** | **1,068,722 tokens across both runs** |

These totals are a baseline for diagnosis, not a target quota. The corrected
system uses model-aware per-call budgets and semantic completeness rather than
optimizing a global token count.

## 3. Goals

The correction must:

- preserve meaningful control-action descriptions, targets, and ownership;
- replace raw durable records in prompts with small task-specific views;
- explain every identifier or mark it explicitly as an opaque value to echo;
- preserve the ordinary STPA method when obligations are introduced;
- keep obligation information advisory: it focuses analysis but does not
  dictate the result;
- make routing structurally coherent across target, action, hazard, loss, and
  constraint;
- keep one bounded, additive revision round and make bad gaps dismissible;
- prevent safeguards and mitigations from being accepted as ICAs;
- keep prompts within the selected model's context budget before making a
  call;
- carry the exact accepted ICA, hazard, loss, constraint, control path, and
  obligation consideration through scenario production;
- require declared causal factors for every generated causal scenario;
- fail closed on missing or ambiguous constraint selection;
- distinguish an ICA finding from successful scenario realization; and
- turn the observed failures into deterministic acceptance and QA fixtures.

## 4. Non-goals

This correction does not:

- require STPA to implement the taxonomy candidate mechanism;
- insert Phase 4 combined graphs into generation prompts;
- grant Phase 2 correspondence or coverage from a model response;
- use prose similarity as authority;
- ask the model to interpret digests, file paths, retrieval scores, or mapping
  implementation details;
- require one scenario per obligation;
- remove ordinary STPA discoveries that have no taxonomy obligation;
- add recursive structural revision;
- hide unresolved results by substituting generic text;
- make a large language model responsible for allocating authoritative IDs;
  or
- use verb matching as the sole semantic validator for an ICA.

## 5. Prompt-boundary design

### 5.1 Separate durable evidence from provider-facing context

Durable artifacts remain complete, typed, content-addressed, and suitable for
replay or audit. They retain digests, source pins, mapping evidence, exact
qualification evidence, and provider-call records.

A model prompt must not be built by serializing one of those artifacts and
removing a few fields. Each model-call adapter must instead construct a closed,
task-specific prompt view through a pure function.

```text
authoritative typed artifacts
             |
             v
   pure prompt-view projector
             |
             +----> complete evidence remains out of band
             |
             v
      small typed prompt view
             |
             v
         prompt renderer
             |
             v
        provider adapter
```

The prompt-view projector is the boundary that decides what the model needs.
Templates only render that view. Templates must not contain ad hoc artifact
traversal, hidden fallbacks, or field-removal logic.

### 5.2 Small interfaces

The implementation should expose a small internal interface resembling:

```text
project_control_structure_context(...)
project_obligation_routing_context(...)
project_revision_context(...)
project_ica_target_context(...)
build_scenario_generation_context(...)
audit_prompt_contract(...)
```

The exact names may follow local conventions. The important boundary is that
provider-capable modules receive prompt views, not arbitrary Phase 1, STPA, or
synthesis models.

The projector and auditor are pure. They do not construct a provider client,
read files, allocate final domain IDs, or mutate source artifacts.

### 5.3 Identifier rule

Every identifier shown to a model must be one of:

1. an opaque handle the model must copy unchanged, accompanied by that exact
   instruction;
2. a selectable reference paired with its plain-language name or description;
   or
3. a defined domain term whose meaning and permitted use are stated in the
   prompt.

An identifier alone is not context. `H-6`, `SC-1`, `KC-7`, `EXEC:*`, a digest,
or a request-local handle must never be presented as though its syntax explains
its meaning.

### 5.4 Fields prohibited from prompts by default

Provider-facing prompt views must not contain these values unless a particular
stage has an approved, tested reason to use one:

- semantic or file digests;
- catalog, mapping, or artifact pins;
- absolute or workspace-relative source paths;
- retrieval, BM25, embedding, or reranker scores;
- raw JSON or YAML stored as a string;
- complete mitigation lists copied from a taxonomy record;
- capability codes without descriptions and a stated decision role;
- provider-call IDs from earlier stages;
- internal schema names; or
- complete unrelated artifact collections.

These fields remain available in the audit record and source pins. Removing
them from the prompt does not remove them from provenance.

### 5.5 Prompt contract audit

Every provider call must pass a deterministic audit before dispatch. The audit
checks:

- the prompt view is the exact closed type for that stage;
- all input handles are unique and accounted for;
- every reference exists in the supplied authoritative slice;
- every selectable ID has a description;
- no prohibited audit-only field leaked into the view;
- no absolute local path appears in the rendered prompt;
- no raw serialized mapping payload appears as prose;
- the requested output schema and one valid example are present;
- the model-context budget is satisfied; and
- the actual rendered prompt digest is recorded.

An audit failure prevents the provider call and produces a typed technical
diagnostic. It must not silently delete fields or truncate text.

## 6. Model-aware prompt budgets

Every configured model profile must declare or resolve:

```text
context_window
maximum_completion_tokens
safety_margin
token_counter or conservative estimator
```

The usable input budget is:

```text
context_window - maximum_completion_tokens - safety_margin
```

The default safety margin is the greater of 10 percent of the context window
or 1,024 tokens. When the provider exposes the model tokenizer, the runtime
uses it. Otherwise it uses a documented conservative estimate and records that
the count is estimated.

The runtime must measure the fully rendered system and user prompts before
dispatch. If a multi-item routing batch does not fit, it is split
deterministically while preserving canonical order. If one item or one target
still does not fit, the call is not made and the affected result becomes
`prompt_budget_exceeded` with exact size evidence.

Semantic sections are never silently truncated. Compact projection, batching,
and target scoping are the supported ways to fit a prompt.

The run manifest records estimated or actual input size, reserved output,
context window, and provider-reported usage for every call. A successful live
qualification run must contain no provider-side context-length failure.

## 7. Stage 2 control-structure correction

### 7.1 Exact response contract

The control-action prompt must define the actual response fields and show a
valid example:

```json
{
  "control_actions": [
    {
      "ca_id": "CA-1-1",
      "description": "Mask sensitive identifiers before model processing",
      "target": "CP-1"
    }
  ],
  "feedback": [
    {
      "fb_id": "FB-1-1",
      "description": "Report masking outcome and validation failures",
      "source": "CP-1"
    }
  ]
}
```

The prompt must explain that:

- `ca_id` is the canonical identity and encodes the owning responsibility;
- `description` is the real system action and may not repeat only the ID;
- `target` is one of the supplied controlled-process IDs;
- feedback uses the exact corresponding fields; and
- the model must not combine an ID and description into an `action` string.

### 7.2 Validation and recovery

Missing semantic fields, unknown semantic carrier fields, or combined
`action` strings are invalid provider responses. They receive at most the
configured schema-correction retry with the exact validation error and schema.

The normative path must not use tolerant decoding to insert an empty control
action description or target. It must not discard an unknown field that
contains the only semantic description.

Identifier normalization may correct a syntactically malformed ID only when
the response still provides an explicit description, target, and unambiguous
ownership. It must not infer ownership by redistributing unmatched actions
across responsibilities by order.

When recovery is exhausted, the responsibility result is a typed failure. The
pipeline must not publish a successful control structure containing generic
`Control action CA-*` placeholders created from missing model data.

### 7.3 Required invariants

- Every action has a meaningful non-placeholder description.
- Every action has one explicit owning responsibility.
- Every target exists and is reachable from that responsibility.
- Reordering response arrays does not change ownership.
- The persisted description is exactly the validated semantic description,
  apart from documented whitespace normalization.
- Later stages use that description whenever they show the action ID.

## 8. Obligation-routing prompt

### 8.1 Provider-facing obligation question

The durable `NeutralObligationBrief` remains the complete traceable artifact.
The model receives a smaller `ProviderObligationQuestion` projected from it:

```text
obligation_handle          opaque; copy unchanged
known_concern
  attack_pattern_id
  name
  description
reviewed_risk
  risk_id
  name
  threat
  consequence
  impact
applicability
  conclusion
  relevant_facts[]         plain name, value, meaning, evidence status
  missing_or_conflicting_facts[]
known_system_resources[]   ID, type, description, relevance
analyst_instruction
```

The attack pattern is a known concern to investigate. The reviewed risk is
context, not proof that the risk and attack pattern share a system-specific
mechanism. If the mapping is broad or indirect, the prompt must say so plainly.

Qualification facts appear only when they change the routing decision. A
capability code may appear only with a description and an instruction stating
how its true, false, or unknown value affects the question.

### 8.2 Target context

The prompt receives a compact STPA index rather than complete artifacts:

- losses: ID and description;
- hazards: ID, description, and related loss IDs with descriptions;
- constraints: ID, description, and exact related hazard IDs;
- responsibilities: ID, description, assigned constraints, and controlled
  process;
- control actions: ID, description, owner, and target process;
- process-model parts, feedback, and coordination paths relevant to the
  candidate target;
- slot IDs with control-action description and the four type definitions.

The index must preserve graph relationships. It must not flatten a constraint
away from the hazards it governs.

### 8.3 Decision instructions

For each obligation the model must return exactly one disposition:

- `targeted`: a credible system-specific control path exists;
- `proposed_not_applicable`: explicit complete structure shows that the
  concern cannot occur through this system;
- `upstream_gap`: a named loss, hazard, constraint, responsibility, action,
  process-model part, feedback path, controlled process, or coordination path
  is missing and is needed before STPA can decide; or
- `unresolved`: the evidence is incomplete, contradictory, or too weak for
  any preceding conclusion.

The prompt must state that `targeted` does not mean “a matching identifier was
found.” It requires a short explanation connecting the concern to the selected
action and hazardous context. It must also state that the model is free to
reject the taxonomy hypothesis.

### 8.4 Deterministic route validation

A targeted route is valid only when:

- the responsibility owns the control action;
- the action targets the selected controlled process;
- every slot belongs to that responsibility/action pair;
- every selected hazard exists;
- every selected constraint explicitly references a selected hazard;
- every selected hazard references the selected loss when a loss is supplied;
- every optional process-model, feedback, or coordination reference is in the
  selected structural slice; and
- every required ID was present in the prompt view.

These checks establish structural coherence, not semantic equivalence. The
model's explanation remains provisional evidence and does not create Phase 2
correspondence.

An invalid route receives one bounded correction attempt. Exhaustion produces
an unresolved result for that obligation; the adapter must not substitute a
different global hazard or constraint.

## 9. Bounded structural-revision prompt

All validated `upstream_gap` results still form one additive revision request.
There is no recursive second round.

### 9.1 Revision item

Each provider-facing gap contains:

```text
gap_handle                 opaque; copy unchanged
trigger_obligation_handle
plain_description
why_the_concept_is_needed
expected_concept_kind
related_existing_context[]
```

It must not contain malformed internal references, unlabelled namespace
fragments, or final IDs the model is expected to invent.

### 9.2 Allowed response

For every gap the model chooses one:

- `propose_addition`, using request-local handles and the closed addition
  schema;
- `dismiss_unsupported`, with a reason that the requested gap is not justified
  by the supplied evidence; or
- `unresolved`, with the missing evidence.

The prompt must not imply that every gap is correct or must become structure.

Every reference in a proposed addition points either to a supplied existing
ID or to a declared request-local handle. The deterministic compiler, not the
model, allocates final STPA IDs.

### 9.3 Atomicity and diagnostics

The one revision delta remains atomic: it is applied only when the complete
compiled delta preserves the baseline and passes the parent specification's
validation. Validation reports rejected additions individually so the failure
is understandable, but the runtime must not apply an unreviewed partial
revision.

One schema/reference-correction retry may repair the same draft. It is not a
second revision round. If it fails, the baseline remains authoritative and
affected obligations retain typed gaps or unresolved results.

## 10. Obligation-aware ICA analysis

### 10.1 Reuse the ordinary method

The synthesis ICA prompt must be composed from the ordinary Stage 3 method,
not replace it. The common part defines:

- what an unsafe control action is;
- the four types and their differences;
- when a slot may be N/A;
- required hazard, constraint, process-model, and feedback references;
- output prose requirements; and
- the exact response schema.

Synthesis adds one separate section named **Obligation considerations for this
target**. It contains only obligations routed to the exact responsibility or
coordination target being filled. It tells the model to consider them, not to
manufacture findings for them.

### 10.2 Exact type definitions

The prompt must define the four slot types in plain language:

- `NOT_PROVIDED`: the required control action is absent when it is needed;
- `INCORRECT`: the action is provided, but its value, content, destination, or
  effect is unsafe;
- `WRONG_TIMING`: the action is provided too early, too late, or in an unsafe
  order;
- `WRONG_DURATION`: a continuous action stops too soon, continues too long, or
  is applied for an unsafe duration.

Timing and duration are not interchangeable. A one-shot action cannot receive
duration findings without an explicit continuing behavior.

### 10.3 Target-scoped prompt

One target prompt contains only:

- the target responsibility or coordination path;
- its controller and controlled process;
- its own control actions with meaningful descriptions;
- its assigned constraints;
- related hazards and losses;
- its process-model parts and feedback;
- its deterministic slots; and
- routed obligation questions.

It must not render the full control structure or unrelated responsibilities.
An ordinary target with no routed obligation is still analyzed through the
same STPA method, with an empty obligation section.

### 10.4 Structured ICA draft

The provider response should separate the parts that the compiler needs to
validate:

```text
slot_handle
is_na
na_rationale
findings[]
  deviation                      one plain non-empty sentence
  hazardous_context
  loss_consequence
  related_hazard_ids[]
  related_constraint_ids[]       exactly one supplied governing constraint
  process_model_refs[]
  feedback_refs[]
consideration_results[]
  obligation_handle
  disposition: finding | proposed_not_applicable | unresolved
  finding_indexes[]
  rationale
```

The model does not rewrite the selected controller or control action. The
deterministic compiler combines the slot's authoritative controller/action
description with the plain deviation, context, and consequence. The compiler
places that sentence into the one domain deviation field owned by the slot's
authoritative UCA category; the provider never selects the category.
It then allocates ICA IDs and constructs the final `ica_text`. This makes the
unsafe behavior a consequence of the selected slot rather than free-form
advice authored by the model. The obligation links remain separate accounting
evidence rather than fields that change the authoritative ICA identity.

### 10.5 ICA semantic rules

An ICA finding describes unsafe control behavior. A safeguard, recommendation,
policy, or requirement is not an ICA. Statements such as “implement MFA,”
“ensure validation,” or “add rate limiting” must be rejected or corrected when
they do not describe what the controller does unsafely.

Exactly one deviation sentence is required. The compiler maps it to the one
typed deviation field corresponding to the slot type. Validation uses that
compiled deviation, the authoritative action, context, and consequence. A
list of suspicious verbs may provide a diagnostic but cannot be the sole
decision rule.

A valid finding must:

- refer to the slot's exact action and owner;
- express behavior consistent with the slot type;
- state the circumstances that make it hazardous;
- state a consequence connected to at least one supplied hazard;
- select exactly one supplied constraint that governs those hazards;
- retain exact structural references; and
- avoid claiming that a taxonomy obligation is covered.

An obligation consideration is `finding` only when at least one validated ICA
actually addresses the concern stated in the provider-facing question. An
obligation may instead be proposed N/A or unresolved. The existence of a route
does not force an ICA finding.

## 11. Scenario-generation context continuity

### 11.1 One immutable context

Before Stage 5, a pure adapter builds one closed
`ScenarioGenerationContext` for each selected ICA. Stage 5 and all Stage 6
renderers consume that same context. No later stage reconstructs the ICA or
chooses a hazard, loss, or constraint from a global list.

The context contains:

```text
context_digest
source_pins
scenario_identity
ica
  ica_id
  slot_id
  uca_type and plain definition
  exact_ica_text
  unsafe_action
  hazardous_context
  loss_consequence
target_control_path
  controller
  responsibility or coordination path
  control_action with description
  controlled_process
  process_model_parts[]
  feedback[]
losses[]                     ID and description
hazards[]                    ID, description, related loss IDs
constraints[]                ID, description, related hazard IDs
obligation_considerations[]
  obligation_id
  attack-pattern ID, name, and concise concern
  consideration disposition
  exact rationale and finding reference
reachable_capabilities[]     ID, description, evidence, access path
catalog_context[]            only mappings selected for this scenario
```

All records are deep-copied and content-addressed when the context is built.
The builder fails if a selected constraint does not govern a selected hazard,
if a hazard does not reach a selected loss, or if an obligation finding does
not reference this ICA.

### 11.2 Persistence and compatibility

The exact source context must remain available in the final scenario artifact
or in a mandatory, content-addressed sidecar referenced by it. Keeping it only
in an ephemeral prompt is insufficient because later rendering, replay, and
review need the same evidence.

The preferred implementation is a closed nested source-evidence record on the
scenario specification. A compatibility adapter may construct it for ordinary
STPA scenarios from their existing `StructuralThreat` and authority artifacts.
It must not invent descriptions or select the first global constraint.

Existing public command names and main artifact filenames remain stable. Any
schema version change is explicit, and legacy artifacts that lack enough
context either load through a clearly labelled compatibility adapter or are
reported as unable to support the new renderers. They are never upgraded with
generic meanings.

## 12. Stage 5 causal scenario and BDI generation

### 12.1 Prompt content

Stage 5 receives only the exact `ScenarioGenerationContext` and the output
contract. The prompt must spell out the selected ICA, hazard, loss, constraint,
and control path using both IDs and descriptions.

Reachable technology or capability context is included only when the source
evidence shows how it is accessible from this control path. The prompt must not
label every system capability “susceptible.” An uncertain access path is
labelled as an assumption, not a fact.

When the ICA has obligation considerations, they are presented as reasons this
ICA was selected. They are not instructions to reproduce a taxonomy attack
chain. A scenario with no obligation remains a normal STPA scenario.

The obligation's pattern name, concise concern, and consideration rationale
are analysis provenance, not causal evidence. A `finding` means that STPA
found a related unsafe-control path. It does not establish that the taxonomy
mechanism occurred. The ICA deviation and hazardous context must describe the
unsafe control or system condition without copying mechanism-specific wording,
unless the compact STPA target evidence independently supplies that exact
mechanism or access path. The consideration rationale records why the concern
and ICA are related.

### 12.2 Required causal factors

The Stage 5 output schema must explicitly require `causal_factors`. Each factor
contains:

- one request-local causal-source handle whose kind and exact source are fixed
  by the compiler;
- plain description;
- evidence status; and
- any bounded assumption required to connect it to the ICA.

Only process-model, feedback, and control-action findings are selectable
causal sources. Responsibility, coordination, and controlled-process IDs stay
described context and cannot be published as causes. Defender vulnerabilities
likewise use one request-local belief handle per selected process-model part;
the closed schema requires every handle exactly once and the compiler restores
the authoritative `PM-*` identities.

A generated causal scenario requires at least one validated factor. An empty
default is not a successful scenario. If the model cannot establish a causal
factor from the supplied context, the result is typed unresolved evidence and
the pipeline does not manufacture a scenario.

### 12.3 Semantic continuity

The Stage 5 response is keyed by an opaque context handle. It returns BDI
content, causal factors, source references, and bounded assumptions. It does
not return replacement ICA, action, hazard, loss, constraint, target, or
obligation identities. The deterministic compiler copies those authoritative
values from the immutable context.

A Stage 5 draft is invalid if it nevertheless introduces a conflicting
structured reference or attempts to change any of these:

- the selected control action or UCA type;
- the unsafe behavior described by the ICA;
- the hazardous context;
- the selected hazard or loss;
- the governing constraints;
- the target controller, responsibility, or controlled process; or
- the concern of a claimed obligation realization.

The model may add concrete actors, conditions, and causal detail only when they
are compatible with the supplied context and declared as evidence or bounded
assumptions. Each causal factor includes a short explanation of how it leads to
the supplied ICA, and every cited source reference is validated.

The compiler can prevent identity substitution and unsupported source
references; it cannot establish arbitrary prose equivalence. Semantic drift in
free text is therefore also a required live-qualification and human-review
check, not a new source of automated correspondence authority. A response may
not replace mass-action abuse with a PII-masking scenario, for example, merely
because both occur in the same system. Such a live result blocks qualification
and remains unresolved rather than being published as realization.

## 13. Stage 6 narrative, attack tree, and Gherkin

### 13.1 Shared source of truth

Narrative, attack-tree, and Gherkin generation all consume:

- the validated Stage 5 result; and
- the exact `ScenarioGenerationContext` used to create it.

They must not reconstruct the ICA as `type + action ID`, scan global artifacts
for a convenient constraint, or receive broad unrelated technology context.

### 13.2 No new causal claims

Stage 6 may explain and organize the causal factors declared in Stage 5. It
must not introduce a new primary cause, action, hazard, loss, constraint,
target, or obligation mechanism. Any extra illustrative detail is explicitly
labelled as an assumption and cannot become structured evidence.

Capability and access-path claims are validated from typed causal evidence
against the immutable context. An adversary taking advantage of an existing
structural failure is not itself a claim of a new access path. Free-text verb
matching must therefore never decide whether a scenario is published. Prompt
guidance may flag a newly invented interface for correction, but admission is
based on the structured causal factor, its exact source, evidence status, and
any explicit capability/access references.

The attack tree's branches and leaves must map to declared causal-factor IDs or
to labelled assumptions. The root must express the exact selected unsafe
outcome. Its hard template must use mechanism-neutral structural labels for
stale, missing, late, inaccurate, or otherwise inadequate control-loop state.
It must not seed poisoning, injection, interception, spoofing, tool-result
fabrication, or another active mechanism as a default example; those labels
are allowed only when exact evidence supports them.

### 13.3 Exact constraint resolution

The Gherkin adapter selects constraints only from the context's validated
related constraints. Each selected constraint must govern one of the scenario's
hazards.

There is no “first global constraint” fallback. Missing, dangling, or
ambiguous constraint evidence produces a typed unresolved rendering result.
It must not silently generate a plausible but incorrect requirement.

### 13.4 Useful Gherkin

The generated Gherkin is an analyst scenario first, but it must be concrete:

- `Given` establishes an exact system state, control path, and relevant
  process-model or feedback condition;
- `When` states the missing, incorrect, mistimed, or mis-durationed control
  action using the action's real description;
- `Then` states an observable unsafe state or control failure;
- a constraint step names the exact governing constraint and hazard; and
- causal-factor references are preserved as traceable annotations or fields.

Vague steps such as “the attacker manipulates the system” are invalid when no
input, surface, state transition, or observable result is supplied.

A scenario may be labelled executable or assigned a nonzero automated-test
score only when it has a concrete reachable input, an operation or surface
binding, and an observable oracle. That assessment is derived from typed
bindings, not accepted merely because the model says the scenario is testable.

## 14. Accounting and scenario realization

The existing provisional accounting keeps its meaning:

- `targeted` means STPA found a structural place to examine the concern;
- `addressed` means STPA produced an exact validated ICA finding in response;
- neither means Phase 2 coverage.

The implementation publishes a closed, content-addressed
`scenario-realization.yaml` artifact (`stpa-scenario-realization-v1`) with one
record for each obligation-to-ICA finding:

- `realized`: a validated scenario was generated from the same immutable
  context and retained the selected concern and ICA meaning;
- `unresolved`: scenario generation or rendering failed, changed the meaning,
  or lacked causal evidence;
- `not_requested`: the finding was not selected for scenario production.

Realization is not inferred from a shared ICA or scenario ID alone. It is
derived from the exact context digest, obligation consideration reference,
ICA reference, and successful Stage 5/6 validations.

One ICA may still address several obligations. A single scenario may realize
several of those concerns only when its context contains each exact
consideration and the generated mechanism remains compatible with each one.
Otherwise the obligations retain separate realization outcomes.

The summary reports exact counts for considered obligations, ICA findings,
scenario realizations, unresolved results, proposed N/A results, upstream
gaps, capability exclusions, and governance-only rows. It publishes no blended
score and makes no confirmed correspondence claim.

The realization artifact is pinned to the exact obligation accounting,
ICA enumeration, scenario collection, and scenario-context digests. It is
derived after scenario production; callers do not supply realization counts or
statuses.

## 15. Provider response and retry policy

Every model-call contract has a strict draft model distinct from the final
domain model. The provider response is parsed into that draft, semantically
validated, and then compiled into authoritative IDs and records.

The following are never treated as a valid successful response:

- required strings filled with empty values;
- unknown fields containing the only useful semantics;
- missing records replaced by generic labels;
- dangling or globally substituted references;
- safeguards accepted as unsafe actions;
- a scenario with no causal factors;
- a response that exceeds the prompt's exact requested identity universe; or
- a response that changes the selected concern while retaining its IDs.

One bounded correction attempt may repair schema, reference, or explicit
semantic-contract errors for the same call. The correction prompt includes the
exact errors, exact schema, and original compact context. It does not add new
domain evidence.

Exhaustion produces a local typed unresolved or technical result as allowed by
the parent specification. It does not silently fall back to a permissive
decoder or erase other target results.

## 16. Call evidence and observability

Every provider call record must retain:

- stage and target identity;
- authoritative source digests;
- prompt-view schema and digest;
- rendered system/user prompt digests;
- deterministic batch membership;
- context-window, input-budget, reserved-output, and safety-margin values;
- estimated preflight input tokens and provider-reported usage;
- response digest;
- draft-validation and semantic-validation results;
- retry reason and count; and
- terminal outcome.

The actual prompt and response may remain in the existing run trace according
to current data-handling policy. Audit fields remain outside the provider-facing
prompt unless the stage contract explicitly includes them.

The report should present failures plainly, for example:

- “The model returned a control action without a description.”
- “This route selected SC-1, but SC-1 does not govern H-2.”
- “The ICA describes a safeguard rather than unsafe control behavior.”
- “The scenario changed from mass-action abuse to data masking.”
- “No causal factor was established, so no scenario was published.”

## 17. Acceptance and deterministic QA

Committed acceptance behavior must demonstrate at least the following.

### 17.1 Control structure

1. A valid response's action descriptions, targets, and owners survive exactly.
2. A combined `action` field with missing required fields is rejected and
   corrected, not silently emptied.
3. An action without an unambiguous owner is not distributed by array order.
4. A successful published control structure has no generated placeholder
   descriptions.

### 17.2 Prompt projection

5. Provider obligation questions omit digests, pins, local paths, ranking
   scores, raw mapping JSON, and unrelated mitigation lists.
6. Every selectable ID in a rendered prompt has a name or description.
7. Every opaque handle is explicitly described as copy-only.
8. Reordered set-like source data produces identical prompt views and batches.
9. Preflight splits oversized routing batches deterministically.
10. A single oversized item produces `prompt_budget_exceeded` without a
    provider call.

### 17.3 Routing and revision

11. A targeted route requires a real ownership/action/process path.
12. A selected constraint must govern the selected hazard.
13. A structurally valid but mismatched hazard/constraint route is rejected.
14. Revision gaps use request-local handles and no dangling final references.
15. The model may dismiss an unsupported gap without adding structure.
16. An invalid revision preserves the complete baseline.
17. Exactly one revision round remains possible.

### 17.4 ICA analysis

18. The synthesis prompt contains the ordinary four-type STPA definitions.
19. Only the exact target slice and its routed obligations are rendered.
20. Every slot is analyzed even when it has no obligation.
21. A safeguard or mitigation is rejected as an ICA.
22. Timing and duration findings satisfy their distinct semantic rules.
23. A finding includes unsafe action, hazardous context, consequence, hazards,
    and governing constraints.
24. A routed obligation may be proposed N/A or unresolved; it is not forced to
    become a finding.
25. A finding records the concern-to-ICA relationship without treating the
    taxonomy mechanism as established causal evidence.
26. ICA deviation and hazardous-context prose remain mechanism-neutral unless
    the compact STPA target independently supplies the mechanism.

### 17.5 Scenario continuity

27. Stage 5 receives the exact ICA statement and described loss, hazard, and
    constraints.
28. Stage 5 receives only capabilities reachable through the selected path.
29. A generated scenario contains at least one typed causal factor.
30. A response that changes the unsafe action, hazard, or obligation concern
    is rejected.
31. Narrative, attack tree, and Gherkin use the same context digest.
32. Stage 6 cannot invent a new structured causal factor.
33. The attack-tree hard template does not pre-seed unsupported active
    mechanisms.
34. Gherkin selects the exact related constraint and has no global fallback.
35. Missing constraint evidence produces unresolved output rather than the
    wrong Gherkin.
36. Concrete Gherkin steps identify state, control action, observable result,
    hazard, and constraint.

### 17.6 Accounting

37. An ICA finding may remain `addressed` when scenario generation fails.
38. That same failure is separately `scenario_realization=unresolved`.
39. Scenario realization requires exact context and consideration continuity.
40. Neither accounting result creates Phase 2 coverage.

## 18. Captured regression fixtures

Sanitized excerpts from the Klarna and NHS call traces must become committed
deterministic fixtures. The fixtures must reproduce these failures without
contacting a model endpoint:

- Stage 2 combined `action` output with missing `ca_id` and `description`;
- missing IDs being assigned by list order;
- a routing batch containing irrelevant audit fields and raw mappings;
- a route whose constraint does not govern its selected hazard;
- a safeguard-shaped ICA;
- mechanically populated timing or duration slots;
- a target prompt that previously exceeded the context window;
- a Stage 5 response that replaces mass-action abuse with PII masking;
- an empty causal-factor list;
- an NHS EHR scenario receiving the unrelated privacy constraint; and
- an obligation/ICA link whose scenario does not realize the concern.

Fixtures must contain only sanitized project data. Tests assert behavioral
invariants rather than exact model prose.

## 19. Live qualification

Live runs happen only after deterministic behavior is complete. They are
explicitly opted in and use the configured provider profile.

For this corrective qualification, the preferred profile is the approved
`gemma4-oc` cluster profile. The approved OpenRouter profile is the fallback
when the cluster is unavailable. The manifest records the actual provider,
model, controls, and endpoint class; results from different profiles are never
presented as the same run.

Qualification proceeds in this order:

1. one control-structure target for each use case;
2. one obligation-routing batch containing a known positive and known negative
   concern;
3. one ordinary target and one obligation-targeted ICA call;
4. one scenario through Stage 5 and all Stage 6 renderers;
5. bounded NHS synthesis;
6. bounded Klarna synthesis; and
7. the full approved runs only after those checks pass.

The live acceptance review checks invariants, not wording:

- no published placeholder control-action descriptions;
- no provider-side context-window failures;
- all target prompts contain only their structural slice;
- no safeguard statements accepted as ICAs;
- every targeted route has a valid hazard/constraint relationship;
- every scenario has causal factors;
- every scenario retains its exact ICA, hazard, loss, and constraint meaning;
- the NHS EHR scenarios use an integrity-relevant governing constraint rather
  than the unrelated PII regex constraint;
- the Klarna mass-action concern is either represented as mass-action abuse or
  retained as unresolved, never silently rewritten as masking; and
- provisional accounting and scenario realization remain distinct.

## 20. Expected implementation seams

The correction should deepen existing modules rather than create a second
parallel STPA pipeline.

| Concern | Existing seam to change | Boundary to preserve |
| --- | --- | --- |
| Control-action schema | `stpa/system_model/prompts/stage2_call2b_*.j2` and `stpa/system_model/control_structure.py` | Final control-structure models and public Stage 2 artifact |
| Strict model drafts | Stage-specific provider adapters; narrowly avoid `stpa/infra/unvalidated_decode.py` for semantic records | Permissive decoding may remain for unrelated legacy callers until migrated |
| Prompt projections | New pure STPA prompt-context leaf used by `stpa/obligation_aware/prompts.py` | Durable Phase 1 and synthesis artifacts remain unchanged |
| Routing | `stpa/obligation_aware/routing.py`, `provider.py`, and `contracts.py` | Phase 1 remains observational and provider-free |
| Revision | `stpa/obligation_aware/revision.py` | One atomic additive round and preserved baseline |
| ICA method | Common instructions from `stpa/threat_enum/prompts/stage3_*.j2` plus `stpa/obligation_aware/slot_filling.py` | `ICAEnumeration` remains the STPA authority |
| Scenario context | `stpa/models/scenario_spec.py`, `stpa/scenario_prod/assembly.py`, and a pure context builder | Existing scenario IDs and canonical `EXEC:*` identity |
| Stage 5 | `stpa/scenario_prod/bdi_generation.py` and `prompts/stage5_*.j2` | Model supplies causal detail, not authoritative source identity |
| Stage 6 | `stpa/scenario_prod/narrative.py`, `attack_tree.py`, `gherkin.py`, and Stage 6 templates | All renderers consume the same accepted context |
| Realization accounting | synthesis accounting models, pipeline, persistence, and report adapter | ICA-level `addressed` and Phase 2 coverage keep their existing meanings |

The shared prompt-context leaf may import inward domain models. It must not
import CLI, filesystem, reports, provider clients, or either workflow's
controller. Templates remain presentation adapters over closed views.

The strict-draft correction should be stage-local first. Changing the generic
tolerant decoder globally would expand the blast radius to unrelated model
calls and is not required to close these failures.

## 21. Implementation sequence

The correction should be built in five vertical slices.

### Slice 1: prompt boundary and control structure

- Add closed prompt views, prompt-contract audit, and model-aware preflight.
- Correct Stage 2 call-2b schema instructions and strict draft parsing.
- Remove order-based semantic ownership recovery.
- Add captured control-structure regressions.

### Slice 2: routing and bounded revision

- Project compact provider obligation questions and STPA target indexes.
- Validate the complete action/hazard/loss/constraint route path.
- Redesign revision gaps and response choices.
- Add deterministic budget splitting and captured route/revision fixtures.

### Slice 3: ordinary STPA method plus obligations

- Extract or reuse the common ordinary Stage 3 method.
- Add the target-scoped obligation section.
- Introduce the structured ICA draft and compiler.
- Validate UCA-type semantics and reject safeguards.
- Cover responsibility and coordination targets.

### Slice 4: scenario context and renderers

- Add the immutable `ScenarioGenerationContext` and persistence binding.
- Make Stage 5 require causal factors and preserve the selected mechanism.
- Make all Stage 6 renderers consume the same context.
- Replace global constraint fallback with exact fail-closed resolution.
- Add separate scenario-realization accounting.

### Slice 5: integration, qualification, then hardening

- Run deterministic synthesis acceptance and compatibility tests.
- Run the bounded NHS and Klarna qualification sequence.
- Inspect generated scenarios and call traces against this specification.
- Correct remaining functional defects before hardening.
- Only after the complete flow works, perform DRY cleanup, branch coverage,
  CRAP, source mutation, Gherkin mutation, full QA, and documentation review.

This ordering deliberately postpones mutation hardening until the functional
contracts and live behavior are stable.

## 22. Quality gates

The final merge evidence must include:

- Gherkin acceptance for the public behaviors above;
- generated acceptance runtime and external standard-reader checks for changed
  artifacts;
- deterministic tests with zero endpoint calls;
- compatibility checks for `generate`, `stpa-run`, and current artifact names;
- branch coverage for every changed prompt projector, validator, and compiler;
- CRAP at or below 6 for changed production modules;
- DRY review of prompt projections, Stage 3 instructions, validators, and
  feature steps;
- targeted differential source mutation for changed production modules;
- Gherkin mutation for new behavioral contracts;
- Ruff format/check and clean diff validation; and
- opt-in live evidence for the bounded NHS and Klarna cases.

Mutation is scoped to the changed modules and acceptance features. It must not
turn into a repository-wide campaign or delay functional integration before
the full correction is ready.

## 23. Exit criteria

The prompt and scenario-continuity correction is complete when:

1. control actions retain meaningful descriptions, explicit ownership, and
   exact targets;
2. no model prompt contains unexplained audit-only metadata or unrelated full
   artifacts;
3. every identifier in a prompt is explained or explicitly copy-only;
4. every call passes model-aware context preflight and the bounded live runs
   have no context-length failure;
5. every targeted route is structurally coherent through action, hazard, loss,
   and constraint;
6. the synthesis ICA stage applies the ordinary STPA method and accepts no
   safeguard-shaped finding;
7. every generated scenario contains validated causal factors;
8. the exact ICA, control path, hazard, loss, constraints, and obligation
   considerations survive through narrative, attack tree, and Gherkin;
9. missing or ambiguous constraint evidence fails closed;
10. scenario realization is reported separately from ICA accounting;
11. taxonomy remains an obligation to consider rather than a scenario recipe;
12. deterministic acceptance, compatibility, DRY, CRAP, mutation, QA, and
    documentation gates pass; and
13. bounded Klarna and NHS outputs pass the semantic invariants in this
    specification on human inspection.

## 24. Decisions fixed by this specification

- Complete source artifacts stay durable; prompts use small typed projections.
- Digests, pins, paths, ranking scores, and raw mapping records stay out of
  provider prompts unless a future stage proves a specific need.
- Strict draft validation replaces silent empty-field recovery for semantic
  model output.
- Control-action ownership is never inferred by response order.
- Obligation routing validates exact hazard/constraint relationships.
- Revision may dismiss unsupported gaps and still remains one atomic additive
  round.
- Obligation-aware ICA reuses the ordinary STPA method.
- Safeguards are not ICAs.
- Prompt fit is checked before every provider call.
- One immutable scenario context carries exact meaning through Stage 5 and
  Stage 6.
- Causal factors are mandatory for a published causal scenario.
- Security constraints are selected from exact related evidence; there is no
  global fallback.
- `addressed` remains an ICA-level provisional result; scenario realization is
  separate.
- Phase 2 remains the only path to confirmed taxonomy correspondence or
  coverage.
