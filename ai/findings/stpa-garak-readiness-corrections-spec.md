# STPA-to-Garak Readiness Corrections

Status: approved for implementation
Date: 2026-09-03
Repositories: `asago-scenario-generator`, `asago-artifact-generator`

## 1. Goal

Turn a semantically complete STPA execution projection into a Garak replay case
without asking an operator to restate mechanics already owned by the Garak
adapter. Preserve explicit target or simulation profiles for facts that are
actually deployment-specific. Improve the producer contract so that ordinary
model-output cases carry useful semantic success criteria and the selected
delivery route can exercise the selected causal condition.

This change covers six corrections:

1. derive routine Garak runtime bindings deterministically;
2. distinguish active execution surfaces from provenance-only structural
   references;
3. derive the ordinary chat action and model-output observer;
4. continue to require a target or simulation profile for tool and other
   external actions;
5. express model-output success as a semantic judge criterion rather than an
   arbitrary exact response string; and
6. validate that the selected delivery class is compatible with the selected
   causal-factor category.

Changing Garak probes and running Garak campaigns are explicitly deferred.

## 2. Ownership

### Scenario generator

The producer owns:

- the delivery class, selected causal factor and action kind;
- the distinction between target-agnostic and profile-backed execution;
- typed unsafe-outcome semantics;
- whether an unknown value is genuinely deployment-specific; and
- route-fidelity validation before Stage 6 publication.

For an `INCORRECT` `model_output`, Stage 5 should normally express the unsafe
result as a semantic proposition: a specific snake-case property, an operator,
and a literal boolean, number, or concise string derived from the scenario.
It must not emit a generic string placeholder such as “selected action value
for this deployment”. Placeholders remain correct for real deployment values,
including timing thresholds and target tool arguments.

The producer rejects these structurally incoherent route selections:

| Delivery class | Allowed selected factor kinds |
| --- | --- |
| `direct_prompt` | `PROCESS_MODEL_FLAW` |
| `conversation_context` | `PROCESS_MODEL_FLAW`, `FEEDBACK_DELAY` |
| `indirect_content` | `PROCESS_MODEL_FLAW`, `SENSOR_ANOMALY` |

This table does not claim that delivery caused every internal failure. It says
that the supplied stimulus can reach or exercise the selected causal
condition. Other causal factors may remain as provenance but are not runtime
input surfaces.

### Artifact generator

The consumer owns deterministic platform mechanics:

- direct prompt -> writable `user_turn`;
- conversation context -> prompt-side conversation history;
- model output -> `chat_completion` and read-only `assistant_turn`;
- model-output condition -> `output_text` semantic observer;
- standard trace locators and content-slot identities; and
- a content-addressed binding-set identity for those derived facts.

The consumer may merge these defaults with explicit runtime bindings. Explicit
bindings win only for the exact key they own; contradictory explicit bindings
remain invalid and are never silently repaired.

The consumer does not require a writable surface for every `PM-*`, `FB-*` or
`CA-*` reference in the projection. It requires surfaces only for:

- the causal step selected by an adversarial stimulus; and
- the final target action.

All structural factors remain in trace evidence even when they are not emitted
as prompt messages.

## 3. Deterministic Garak defaults

Expose a pure adapter function:

```python
complete_garak_runtime_bindings(
    execution_case: BoundExecutionCase,
    explicit: RuntimeBindingSet | None,
    target_profile: ExecutionTargetProfile | None,
) -> RuntimeBindingSet
```

The function accepts typed, integrity-checked values only. It may derive:

- a surface and `AdversarialStimulusBinding` for `direct_prompt` and
  `conversation_context`;
- a target surface and `ControlActionBinding(adapter_operation="chat_completion")`
  for `model_output`;
- an `ObservationBinding(observer_kind="output_text")` for an observable
  model-output unsafe condition; and
- a target `tool_call` action from an already resolved profile resource and
  operation.

It may not derive:

- a tool or integration identity without a resolved target/simulation profile;
- credentials, secrets, endpoint URLs, arbitrary tool argument values or
  carrier-tool arguments;
- semantic placeholder values;
- real clocks, persistent-state channels, multi-agent channels or external
  state observers; or
- an indirect-content carrier whose schema or invocation values are absent.

If an explicit binding set is supplied, its projection digest must match
before defaults are merged. The resulting set receives a deterministic ID,
digest and adapter-owned provenance. No model call is made.

## 4. Semantic judge contract

For a model-output action, an `action_value` condition is interpreted as a
semantic proposition about the target response, not as byte-for-byte response
equality. The compiled oracle retains:

- condition reference and type;
- semantic property;
- operator and literal expected value; and
- the exact source identities and digests.

The Garak artifact's `judge_description` renders all four meaning-bearing
parts in plain language. A placeholder keeps the case in
`needs_semantic_binding`; the adapter does not turn placeholder prose into a
value. New producer prompts avoid generic model-output placeholders by asking
for a concrete semantic proposition such as
`reveals_restricted_information equals true`.

Tool argument conditions remain exact argument observations and still require
an exact field path plus any missing deployment value.

## 5. Target-profile boundary

`tool_call`, `state_change`, `agent_message` and `environment_action` retain
their existing semantic resource requirements. Without a matching explicit
target or simulation profile, case resolution stops before runtime readiness.
Garak defaults begin only after a `BoundExecutionCase` exists; they cannot turn
a parameterized semantic case into a target-specific claim.

Where a profile has resolved a tool requirement, the adapter may copy the
resolved operation ID and interface schema into the runtime action binding.
It does not fabricate required argument values. Missing values or observers
remain typed readiness diagnostics.

## 6. Readiness and compilation behavior

The normal CLI applies deterministic Garak defaults automatically before
`bind_and_plan`. A caller may still provide `--bindings`; those values are
merged with defaults. `--readiness-only` performs the same deterministic
completion but never authors or compiles content.

Expected results:

- a literal direct-prompt/model-output case can become ready without a manual
  binding file;
- a literal conversation-context/model-output case can become ready without a
  manual binding file;
- unrelated structural factors do not cause `surface_binding_missing`;
- a model-output observer does not need to be manually restated;
- a semantic placeholder remains `needs_semantic_binding`;
- a tool case without a profile remains `needs_target_binding`;
- a profile-backed tool case still remains unready when genuinely required
  runtime values are absent; and
- a real-clock case remains unsupported by the present Garak adapter.

The ready plan and compiled artifact pin the effective binding-set digest so
all derived defaults are reproducible and auditable.

## 7. Acceptance

The implementation is accepted when deterministic tests prove:

1. direct model-output and conversation-context cases reach ready with no
   manual binding file when their semantic outcome is literal;
2. the compiled artifact ends before the target response and contains a
   semantic output judge;
3. provenance-only factors remain traceable without becoming writable prompt
   surfaces;
4. explicit compatible bindings merge deterministically and contradictions
   fail closed;
5. unresolved semantic placeholders, target tools, clocks and external state
   remain unresolved rather than being invented;
6. Stage 5 rejects each disallowed delivery/factor pairing and accepts every
   allowed pairing;
7. Stage 5 prompt fixtures explain the route table and the model-output
   semantic proposition rule without uncontextualized IDs; and
8. the existing producer/consumer contract kit remains byte-compatible because
   this correction changes validation and generation guidance, not the v2 wire
   shape.

Run focused unit and generated acceptance suites, Ruff/format, DRY inspection,
and CRAP at or below 6 for changed production functions. Source and Gherkin
mutation hardening are deferred until the corrected end-to-end path is running.

## 8. Deferred work

- Garak probe changes, including neutral replay probe naming and direct versus
  indirect probe taxonomy.
- Campaign planning, installation and execution. That belongs to the separate
  orchestration component.
