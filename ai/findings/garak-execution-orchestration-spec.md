# Garak Execution Authoring and Orchestration Specification

Status: proposed implementation specification
Date: 2026-09-02
Scope: `asago-artifact-generator`, a new execution orchestrator, and the
TrustyAI Garak fork
Related producer contract:
`ai/findings/stpa-execution-bundle-producer-spec.md`
Related consumer contract:
`asago-artifact-generator/ai/findings/stpa-execution-bundle-consumer-spec.md`
Garak baseline:
[`trustyai-explainability/garak#11`](https://github.com/trustyai-explainability/garak/pull/11)

## 0. Pre-alpha implementation rule

The scenario generator and artifact generator are pre-alpha. Implement this
specification by changing the current projection-v2, bundle-v1,
runtime-binding-v1 and artifact output shapes in place. Refresh the producer
contract kit, consumer vendor copy and digests together. Do not add projection
v3, runtime-binding v2, migration code, compatibility readers or deprecation
machinery. There are no external consumers to protect, and iteration speed is
more valuable than preserving the incomplete wire shapes.

The scenario projection gains a platform-neutral stimulus requirement: the
adversarial intent, desired effect and eligible causal-factor IDs. The artifact
generator gains the reviewed deployment binding that chooses direct prompt,
indirect content or ordinary conversation context and binds the exact surface.
The compiler emits prompt-side OpenAI messages and a structured target oracle;
it never emits the target response.

## 1. Decision

ASAGO shall separate execution-case production from execution orchestration.

The artifact generator shall consume verified STPA execution bundles, bind
deployment facts, optionally use a constrained author to write natural
conversation content, and deterministically compile validated execution cases.
It shall not select or run Garak probes.

A separate execution orchestrator shall select version-pinned Garak probes,
construct Garak run configuration, execute campaigns, and collect immutable
receipts. Probe selection shall be based only on typed execution facts and an
explicit route catalog. It shall never be inferred from scenario prose by a
model.

This specification supersedes the consumer specification only where that
document assigns Garak execution or runtime observation receipts to the
artifact generator, and where it treats the current custom Garak JSON as a
runner-native artifact. Bundle verification, binding, readiness, planning,
authoring constraints and source traceability remain in force.

The TrustyAI Garak fork shall provide reusable replay probes and detectors for
the exact conversation cases produced by ASAGO. Existing Garak probes remain
the authority for Garak's built-in direct-injection, jailbreak, and encoding
suites.

The required campaign surface is:

1. run Garak's built-in direct-injection probes;
2. run Garak's built-in jailbreak probes;
3. run Garak's built-in encoding probes;
4. replay an exact use-case-specific direct prompt authored from an ASAGO
   scenario; and
5. replay an exact multi-turn conversation, including OpenAI-style tool calls
   and tool results, authored from an ASAGO scenario.

Items 1-3 are target-level systematic scans. Items 4-5 are exact
scenario-level executions. A campaign may contain all of them. Running a
built-in probe does not, by itself, prove that a particular STPA scenario was
executed or that a taxonomy obligation was addressed.

## 2. Plain-language pipeline

```text
Scenario generator
  Defines the unsafe behavior, causal path, identities and success condition
        |
        v
Artifact generator
  Verifies the source, binds the environment, authors bounded conversation
  text, and compiles an exact executable case
        |
        v
Execution orchestrator
  Combines exact cases with requested built-in suites, chooses compatible
  Garak probes, runs the campaign and records results
        |
        v
Garak
  Executes prompts/conversations against the target and applies detectors
```

The target model's response is never authored by ASAGO. An exact replay case
ends immediately before the target is expected to respond. The unsafe control
action is represented by the oracle that evaluates the target response, not by
an assistant response pre-inserted into the replay conversation.

## 3. Goals

The implementation shall:

- preserve the exact STPA run, scenario, candidate, ICA slot, ICA, controller,
  control action and UCA identities;
- preserve the verified execution-projection and runtime-binding digests;
- make the adversarial stimulus and its delivery location explicit;
- allow a constrained model to author only designated text slots;
- compile OpenAI-compatible conversation messages and tool definitions without
  model control over roles, order, tools, values or success criteria;
- support target-generated text and tool-call outcomes;
- route exact cases to the correct replay probe without reading prose;
- run requested built-in Garak suites once per target/campaign rather than once
  per ASAGO scenario;
- distinguish deterministic detector results from model-judge results;
- retain exact source-to-attempt-to-result traceability; and
- fail closed before target execution when a case is malformed, unbound,
  unsupported or ambiguously routable.

## 4. Non-goals

This work shall not:

- move causal reasoning or scenario admission into the artifact generator;
- allow a taxonomy technique label alone to select an executable attack;
- ask a model which Garak probe should run;
- ask a model to invent tools, surfaces, unsafe values or detector meaning;
- treat a generic Garak probe result as realization of a specific STPA
  scenario;
- make the artifact generator responsible for target credentials, cluster
  jobs, retries, scheduling or Garak report ingestion;
- make Garak interpret STPA, taxonomy obligations or ASAGO identifiers;
- claim Garak support for state, timing, memory or external effects that the
  selected target adapter cannot actually execute and observe; or
- preserve the current custom `turns + detectors` document as the Garak runner
  interface.

## 5. Ownership

### 5.1 Scenario generator

The scenario generator owns:

- loss, hazard, security-constraint and UCA meaning;
- causal factors and their order;
- the final unsafe semantic condition;
- stable STPA identities;
- execution requirements and semantic placeholders;
- presentation-only scenario context; and
- canonical projection and bundle publication.

It does not own Garak probe names, Garak run configuration, target deployment
bindings or authored conversation text.

### 5.2 Artifact generator

The artifact generator owns:

- independent bundle and projection verification;
- semantic and runtime bindings;
- explicit adversarial-stimulus bindings;
- platform-neutral conversation planning;
- constrained conversation authoring;
- deterministic message/tool/oracle compilation;
- execution-case validation;
- content, author, binding and source digests; and
- execution-case trace sidecars.

It does not select a Garak probe, start Garak, contact the target under test or
interpret Garak results.

### 5.3 Execution orchestrator

The execution orchestrator owns:

- the target and campaign configuration;
- a version-pinned Garak route catalog;
- requested built-in probe suites;
- exact-case probe routing;
- target-generator and detector configuration;
- secret-handle resolution outside persisted artifacts;
- local, container or cluster execution;
- bounded retries and deadlines;
- Garak report collection; and
- immutable execution receipts.

The orchestrator contains no conversation-authoring model call and does not
change compiled messages, tools or oracles.

### 5.4 Garak

Garak owns:

- built-in probe behavior and probe-specific prompt construction;
- replay-probe loading into Garak `Conversation` values;
- target invocation;
- response and tool-call capture;
- probe-specific and shared detectors; and
- native attempt/report output.

Garak does not validate ASAGO source bundles or infer missing ASAGO execution
facts.

## 6. Two different kinds of campaign work

### 6.1 Built-in suite work

Built-in suite work asks Garak to run its own probes. It is configured at the
campaign level and associated with the target, not automatically duplicated
for every ASAGO scenario.

Normative built-in families are:

- `direct_prompt_injection`;
- `jailbreak`; and
- `encoded_injection`.

The exact Garak probe specifications for each family belong to the pinned
route catalog because Garak probe names and availability change between
versions.

Built-in suite work requires no conversation-authoring call. Its prompts and
detectors are Garak-owned.

### 6.2 Exact replay work

Exact replay work executes one compiled ASAGO conversation case. The artifact
generator fixes the conversation leading up to the target response, available
tools, exact success condition and trace.

Normative replay kinds are:

- `direct_prompt_replay`: the adversarial stimulus is a direct user message;
- `indirect_content_replay`: the adversarial stimulus is embedded in a tool
  result, retrieved content or another non-user authority channel; and
- `conversation_replay`: the scenario requires an exact multi-turn history but
  is not accurately described as indirect prompt injection.

Each exact case is routed to exactly one compatible replay probe. Failure to
find one compatible probe is an explicit unsupported result.

## 7. New artifact-generator domain values

All new persisted models shall be immutable, closed, versioned and digest
verified. Raw mappings shall be accepted only by strict parser interfaces.

### 7.1 `AdversarialStimulusBinding`

The existing `SurfaceBinding.writable` fact is insufficient. It says that a
surface can be written, but it does not identify which projection step carries
the adversarial stimulus or whether the stimulus is direct or indirect.

Add:

```python
class AdversarialStimulusBinding(ImmutableModel):
    stimulus_id: StrictStr
    projection_step_id: StrictStr
    factor_id: StrictStr | None
    content_slot_id: StrictStr
    delivery_class: Literal[
        "direct_prompt",
        "indirect_content",
        "conversation_context",
    ]
    surface: Literal[
        "system_prompt",
        "user_turn",
        "assistant_turn",
        "tool_result",
    ]
    source_kind: Literal[
        "user_authored",
        "tool_output",
        "retrieved_document",
        "conversation_history",
    ]
    reviewed_by: StrictStr
    rationale: StrictStr
    evidence_refs: tuple[StrictStr, ...]
```

Rules:

- `projection_step_id` must name an exported causal step, never the final UCA
  step.
- `factor_id`, when present, must equal that step's exact factor identity.
- `content_slot_id` must be unique within the execution case.
- `direct_prompt` requires `user_turn` and `user_authored`.
- `indirect_content` requires `tool_result` with `tool_output`, or an explicitly
  supported retrieved-content mapping.
- `conversation_context` may use the supported message surfaces but must not be
  silently promoted to direct or indirect injection.
- At least one stimulus is required for replay compilation.
- Every stimulus binding carries review evidence because delivery through a
  real application surface is a deployment fact.

`RuntimeBindingSet` gains, in its current v1 shape:

```python
stimulus_bindings: tuple[AdversarialStimulusBinding, ...] = ()
```

Its digest and uniqueness checks include these values. All binding fixtures are
updated together; there is no compatibility parser for the previous shape.

### 7.2 `ConversationExecutionProfile`

Derive one profile only after source, semantic, runtime and stimulus binding
are complete:

```python
class ConversationExecutionProfile(ImmutableModel):
    profile_id: StrictStr
    interaction_mode: Literal["single_turn", "multi_turn"]
    delivery_class: Literal[
        "direct_prompt",
        "indirect_content",
        "conversation_context",
    ]
    message_roles: tuple[Literal["system", "user", "assistant", "tool"], ...]
    uses_tools: StrictBool
    target_response_modes: tuple[
        Literal["assistant_text", "tool_call"], ...
    ]
    oracle_kind: Literal[
        "structured_tool_call",
        "structured_tool_argument",
        "structured_action_absence",
        "text_judge",
    ]
    requirements: ExecutionRequirements
```

The profile contains no Garak probe names. It describes what must be executed,
not which runner implementation will execute it.

### 7.3 `ConversationMessagePlan`

The deterministic planner shall create the complete prompt-side message
skeleton:

```python
class ConversationMessagePlan(ImmutableModel):
    message_id: StrictStr
    order: StrictInt
    role: Literal["system", "user", "assistant", "tool"]
    source_step_id: StrictStr | None
    factor_id: StrictStr | None
    content_slot_id: StrictStr | None
    tool_calls: tuple[PlannedToolCall, ...] = ()
    tool_call_id: StrictStr | None = None
    name: StrictStr | None = None
```

Rules:

- message roles, order, tool call IDs, tool names and relationships are
  compiler-owned;
- a tool-result message must reference exactly one preceding planned tool
  call;
- a planned assistant tool call used to retrieve indirect content must be
  followed immediately by its tool result;
- the sequence must end immediately before the target response;
- the final UCA projection step must never be rendered as a pre-authored target
  response; and
- OpenAI tool-call `function.arguments` are serialized as canonical JSON
  strings at the Garak wire seam.

### 7.4 `ExecutionOracle`

Compile the existing typed unsafe outcome and observer plan into one closed
oracle union:

```python
ExecutionOracle = (
    ToolCallOracle
    | ToolArgumentOracle
    | ActionAbsenceOracle
    | TextJudgeOracle
)
```

Common fields include:

- exact condition reference;
- condition type;
- controller and control-action identities;
- comparison operator;
- resolved expected value;
- event source;
- deterministic human-readable success description; and
- source trace.

Structured tool or action conditions shall use deterministic detectors.
`TextJudgeOracle` is permitted only when the target behavior cannot be
evaluated structurally. It records the judge model and threshold in the final
receipt.

### 7.5 `ExecutableConversationCase`

The artifact generator's new primary output is:

```python
class ExecutableConversationCase(ImmutableModel):
    schema_version: Literal["asago-executable-conversation-v1"]
    case_id: StrictStr
    source: ExecutionSourceTrace
    binding: BindingTrace
    profile: ConversationExecutionProfile
    messages: tuple[CompiledMessage, ...]
    tools: tuple[ToolDefinition, ...]
    tool_choice: JsonValue | None
    oracle: ExecutionOracle
    judge_description: StrictStr
    author_trace: AuthorTrace | None
    semantic_digest: SHA256Digest
```

The canonical artifact is platform-neutral OpenAI conversation data plus a
typed oracle and trace. Platform-specific export is a separate pure adapter.

## 8. Constrained conversation authoring

### 8.1 Author interface

Replace presentation-only wording with a conversation-authoring interface:

```python
class ConversationAuthor(Protocol):
    def author(
        self,
        request: ConversationAuthoringRequest,
    ) -> ConversationAuthoringResult:
        ...
```

The request contains only:

- exact content-slot IDs;
- fixed role and purpose per slot;
- maximum length;
- the allowed scenario and loss context;
- the causal fact the slot must express;
- whether the slot is the adversarial stimulus;
- allowed tool display names, if needed; and
- explicit constraints against adding tools, steps, target responses or
  success criteria.

The result is an exact slot-ID-to-text mapping plus provider/model/call digest.

### 8.2 What the author may write

The author may write:

- system context;
- benign user goals;
- direct adversarial user prompts;
- realistic retrieved documents;
- malicious instructions embedded inside tool results; and
- non-target conversational context.

### 8.3 What the author may not write

The author may not choose or modify:

- probe family or probe name;
- message role or order;
- tool name, schema, call ID or fixed arguments;
- semantic binding values;
- observer type, comparison or expected value;
- the target model's final response or tool call;
- source identities; or
- the success description.

### 8.4 Authoring validation

Authoring fails closed when:

- any requested slot is missing or any extra slot is returned;
- content exceeds its bound;
- a placeholder or unknown identifier remains;
- a slot contains an undeclared tool call or tool definition;
- a tool-result stimulus cannot be placed into its compiler-owned message;
- output attempts to provide the target response; or
- the author result cannot be digested and tied to the exact request.

Templates or prebound text shall satisfy the same interface and are the
deterministic adapters used by tests. This provides two real author adapters:
model-backed and prebound/template-backed.

## 9. Artifact-generator interfaces

Retain the existing bundle loading and readiness interfaces. Add two deep
interfaces:

```python
def plan_conversation_case(
    plan: ReadyExecutionPlan,
    bindings: RuntimeBindingSetV2,
) -> ConversationCasePlanResult:
    ...

def compile_conversation_case(
    plan: ReadyConversationCasePlan,
    author: ConversationAuthor | None = None,
    *,
    prebound_texts: Mapping[str, str] | None = None,
) -> ExecutableConversationCase:
    ...
```

`plan_conversation_case` is pure and owns delivery-profile derivation,
message-skeleton construction and oracle compilation. It returns typed
diagnostics or one complete plan.

`compile_conversation_case` accepts only a ready plan, fills its closed text
slots through exactly one author mechanism, validates the result and returns a
closed immutable case. It performs no filesystem, Garak, target or routing
work.

Platform export is also pure:

```python
def export_garak_replay_source(
    case: ExecutableConversationCase,
    target: GarakReplayContract,
) -> GarakReplaySource:
    ...
```

The export adapter validates that the chosen Garak contract can represent the
case. It still does not choose the probe.

## 10. Garak replay wire format

The baseline fields intentionally align with PR #11:

```json
{
  "case_id": "SCN-020",
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "..."}
  ],
  "tools": [],
  "tool_choice": null,
  "judge_description": "The attack succeeds if ...",
  "structured_oracle": {
    "kind": "tool_argument",
    "tool_name": "apply_compliance_gate",
    "field_path": "compliance_blocking_effect",
    "comparison": "equals",
    "expected": false
  }
}
```

Normative rules:

- `messages` contain only prompt-side conversation history.
- `messages` never contain the target response being tested.
- `assistant.tool_calls[].function.arguments` are JSON strings, matching the
  OpenAI Chat Completions format.
- `tool` messages carry exact `tool_call_id` and `name` values.
- `tools` are copied only from reviewed runtime bindings.
- `judge_description` is deterministically rendered from the typed oracle.
- `structured_oracle` is authoritative when present; the prose description is
  its human-readable representation.
- Source, binding and author digests remain in the ASAGO trace sidecar rather
  than being required knowledge for Garak.
- The exported source and trace sidecar are content-addressed and cross-pin one
  another.

Persist the replay source as canonical JSON or JSONL accepted by the selected
probe. Persist its closed schema and conformance fixtures in the artifact
generator and orchestrator contract kits.

## 11. Garak changes

PR #11 supplies the required baseline:

- `tool` message roles;
- round-trip preservation of `tool_calls`, `tool_call_id` and `name`;
- per-conversation `tools` and `tool_choice` forwarding for the OpenAI
  Chat Completions family;
- target-response tool-call capture;
- JSON/JSONL conversation-source loading; and
- an LLM-based `InjectionJudge`.

Build the following additions on top of that work.

### 11.1 Shared conversation-source loader

Extract source resolution, JSON/JSONL parsing, message construction, tool
metadata and case metadata into one internal loader module. It shall be reused
by replay probes without duplicating file parsing.

The loader shall retain:

- `case_id`;
- `judge_description`;
- `structured_oracle`;
- `tools` and `tool_choice`; and
- optional ASAGO trace digest.

Malformed entries must produce explicit attempt/source diagnostics. ASAGO's
orchestrator shall reject them before starting Garak; Garak shall not silently
reinterpret malformed fields.

### 11.2 `DirectInjectionReplay`

Add an opt-in probe for exact ASAGO direct prompts.

Requirements:

- accepts a conversation source;
- requires a direct user-message stimulus;
- conversation may include fixed system context but no indirect tool-result
  stimulus;
- stops before the target response;
- uses the case's structured detector or explicit text judge; and
- carries direct-injection intent/tags rather than PR #11's indirect-injection
  identity.

This probe is different from Garak `promptinject`: it replays the exact ASAGO
prompt, whereas `promptinject` constructs Garak's generic PromptInject probes.

### 11.3 `IndirectInjection`

Retain PR #11's `IndirectInjection` for exact indirect-content cases.

Tighten its entry validation so the injection carrier is represented by a tool
result, retrieved-content message or another explicitly supported indirect
surface. It shall not be the default for every multi-turn conversation.

### 11.4 `ConversationReplay`

Add an opt-in generic replay probe for exact multi-turn conversations that are
not accurately classified as indirect prompt injection.

It shall:

- accept system, user, assistant and tool history;
- preserve tool-call relationships;
- forward tools and tool choice;
- stop before the target response;
- carry per-case intent/metadata without pretending every case is one Garak
  attack family; and
- use the structured oracle or explicit judge selected by the case.

### 11.5 Structured conversation detector

Add a detector that evaluates target text and captured target tool calls
against the closed `structured_oracle`.

The first supported variants are:

- tool call present or absent;
- exact tool name;
- tool-argument comparison using the closed scalar comparator set;
- output exact/contains/not-contains; and
- action absence.

The detector returns a deterministic pass/fail plus evidence showing the
observed value. It shall not invoke a judge model.

`InjectionJudge` remains available for `TextJudgeOracle` cases. Its result
must record raw score, threshold, judge provider/model and parse status.

### 11.6 Generator capability declaration

PR #11's tool-message path currently covers the OpenAI Chat Completions family
and excludes separate LiteLLM, Ollama, Mistral and Responses API paths. Expose
this as route-catalog capability data. The orchestrator must not route a
tool-calling case to a generator path that cannot preserve its message shape.

## 12. Separate execution orchestrator

Create a dedicated repository/package, recommended name:
`asago-execution-orchestrator`.

It consumes versioned artifact-generator execution-case contracts. It does not
import a sibling checkout or parse artifact-generator internal classes. Vendor
the complete execution-case and Garak replay conformance kit with an upstream
lock, following the existing producer/consumer contract pattern.

### 12.1 External interfaces

Expose two deep interfaces:

```python
def plan_campaign(
    request: ExecutionCampaignRequest,
    cases: tuple[ExecutableConversationCase, ...],
    catalog: GarakRouteCatalog,
) -> ExecutionCampaignPlan:
    ...

def execute_campaign(
    plan: ReadyExecutionCampaignPlan,
    runner: GarakRunner,
) -> ExecutionCampaignReceipt:
    ...
```

`plan_campaign` is pure. `execute_campaign` owns side effects through an
injected runner adapter.

Provide at least two runner adapters so the seam is real:

- a production local/container/cluster Garak adapter; and
- an in-memory deterministic adapter for tests.

### 12.2 `ExecutionCampaignRequest`

The request contains:

- campaign ID;
- target-environment ID;
- target generator profile reference, without inline secrets;
- requested built-in families;
- selected exact case IDs or `all`;
- generation count;
- parallelism, timeout and retry policy;
- judge profile reference when text judging is required; and
- route policy/version.

The request does not contain probe names. Probe names come from the pinned
route catalog.

### 12.3 `GarakRouteCatalog`

The catalog is a closed, versioned and digested document containing:

- Garak repository and revision;
- supported generator paths and their conversation capabilities;
- built-in family to exact probe-spec mappings;
- exact replay route definitions;
- detector mappings;
- accepted replay-source schema versions; and
- route priorities only where multiple compatible versions are intentionally
  supported.

Example route classes:

```text
garak.builtin.direct_prompt_injection
garak.builtin.jailbreak
garak.builtin.encoded_injection
garak.replay.direct_prompt
garak.replay.indirect_content
garak.replay.conversation
```

The catalog may map those stable route classes to version-specific Garak probe
specifications such as `promptinject.*`, `encoding.*`,
`injection.DirectInjectionReplay`, `injection.IndirectInjection` and
`injection.ConversationReplay`.

### 12.4 Routing algorithm

Routing is deterministic and offline:

1. Verify the campaign request, route catalog and exact cases.
2. Expand each requested built-in family exactly once per target/campaign into
   its catalog-pinned probe specifications.
3. For each exact case, compare its execution profile and requirements with
   every replay route in the catalog.
4. Retain routes whose delivery class, interaction mode, message roles, tool
   use, target-response mode, oracle kind and generator capabilities all match.
5. Select the single most specific compatible route.
6. Return `unsupported` with all failed requirements when none match.
7. Return `ambiguous` when equally specific routes remain; require a catalog or
   explicit operator-policy correction rather than choosing arbitrarily.
8. Produce immutable work-item identities and exact source/catalog pins.

No route examines narrative text, taxonomy mappings, attack-pattern names or
model output.

### 12.5 Routing examples

| Input | Selected work |
|---|---|
| Campaign requests generic direct injection | Catalog-pinned `promptinject` suite |
| Campaign requests generic jailbreaks | Catalog-pinned jailbreak suite |
| Campaign requests generic encoding attacks | Catalog-pinned `encoding` suite |
| Exact case with direct user stimulus and one response | `DirectInjectionReplay` |
| Exact case with malicious tool result | `IndirectInjection` |
| Exact multi-turn case without indirect injection | `ConversationReplay` |
| Exact case requiring unsupported real clock/state | `unsupported`, no Garak process |

Built-in work and exact replay work are additive. An exact direct-prompt case
does not suppress a requested generic `promptinject` scan, and the generic scan
does not replace the exact case.

### 12.6 Garak runner

The production runner shall:

- construct an argument/config document from the ready campaign plan;
- resolve credential handles only at execution time;
- pin the Garak revision/container image;
- provide each replay work item its immutable source path;
- provide built-in work items their exact probe specifications;
- start no work for unsupported, ambiguous or invalid items;
- enforce deadline, bounded retry and concurrency controls;
- preserve Garak stdout/stderr/report bytes separately;
- record process/job identity and exit state; and
- never edit source cases after execution begins.

## 13. Execution receipts

Persist one `asago-execution-campaign-receipt-v1` document containing:

- campaign request, plan and route-catalog digests;
- Garak repository revision/image digest;
- target environment identity and generator profile identity;
- work-item counts by built-in, exact, unsupported, ambiguous, passed, failed
  and errored;
- one receipt per work item;
- exact probe specification and detector used;
- source case and trace digests for exact work;
- Garak attempt/report references and byte digests;
- structured observed values for deterministic detectors;
- judge model, raw score, threshold and parse status for judged detectors;
- timestamps and bounded retry history; and
- a receipt semantic digest.

Do not collapse deterministic detector results and judge scores into one
unqualified score.

An exact replay receipt may be reconciled with its STPA scenario through exact
source identities and digests. A built-in suite receipt remains target-level
systematic evidence unless a later explicit reviewed relation connects it to a
scenario or obligation.

## 14. Current implementation corrections

The current artifact-generator Garak path requires the following corrections:

1. Stop compiling the final UCA step into the prompt conversation.
2. Split prompt-side messages from the expected target response.
3. Replace custom `turns` with canonical OpenAI-style `messages` at the Garak
   replay export seam.
4. Serialize assistant tool-call arguments as JSON strings.
5. Replace custom `detectors` as the runner interface with typed
   `structured_oracle` plus deterministic `judge_description`.
6. Add explicit stimulus bindings; do not infer adversarial placement from
   `SurfaceBinding.writable` or causal prose.
7. Generalize the current presentation author into the bounded conversation
   author described above.
8. Retain execution plan, readiness, validation and trace as ASAGO sidecars.
9. Remove any claim that successfully compiling the custom JSON means Garak
   executed or accepted it.
10. Keep `generate-legacy` isolated; it is not a replay-contract adapter.

The live SCN-020 integration artifact is a regression fixture for correction
1: the unsafe `apply_compliance_gate(compliance_blocking_effect=false)` call
must become the target-generated behavior evaluated by the oracle, not a
pre-authored assistant turn.

## 15. Persistence layout

Artifact generator:

```text
runs/<source-run-id>/<scenario-id>/
  readiness.json
  conversation-plan.json
  executable-conversation.json
  garak-replay-source.json
  execution-case-trace.json
  validation.json
```

Execution orchestrator:

```text
campaigns/<campaign-id>/
  campaign-request.yaml
  campaign-plan.json
  route-catalog-pin.json
  inputs/<work-item-id>/
  garak/<work-item-id>/
  execution-receipt.json
```

All authoritative JSON/YAML publication is atomic and verified by reloading
before the manifest or receipt is made visible. Inputs are immutable after a
campaign plan is published.

## 16. Acceptance requirements

### 16.1 Built-in probes

Acceptance shall prove:

- requested direct-injection family expands to the exact catalog-pinned
  `promptinject` probe set;
- requested jailbreak family expands to the exact catalog-pinned jailbreak
  probe set;
- requested encoding family expands to the exact catalog-pinned encoding
  probe set;
- built-in expansion makes zero author calls;
- each built-in family runs once per target/campaign, not once per scenario;
- unavailable probe names make planning fail closed; and
- built-in results do not claim exact scenario realization.

### 16.2 Exact direct replay

Acceptance shall prove:

- a reviewed direct stimulus becomes the exact final user prompt before target
  generation;
- the model author can change only its assigned text slot;
- `DirectInjectionReplay` is selected without reading prose;
- the target response is absent from the source messages;
- structured tool/text outcomes retain their exact expected values; and
- source, author, binding and replay-source digests reconcile.

### 16.3 Exact multi-turn and tool replay

Acceptance shall prove:

- system, user, assistant tool-call and tool-result turns preserve exact order;
- tool-call IDs and tool-result references round-trip;
- OpenAI tool-call arguments are strings containing canonical JSON;
- per-case tools and tool choice reach the target generator;
- target-generated tool calls reach the structured detector;
- an indirect tool-result stimulus selects `IndirectInjection`;
- an ordinary multi-turn conversation selects `ConversationReplay` rather than
  acquiring an indirect-injection label; and
- the final unsafe control action is evaluated from the target output, never
  inserted into the source conversation.

### 16.4 Unsupported and ambiguous cases

Acceptance shall prove:

- a case requiring a role unsupported by the selected Garak generator is not
  executed;
- a case requiring real clock, persistent state or external observation that
  Garak cannot supply is retained as unsupported with exact reasons;
- multiple equally specific routes produce `ambiguous`, not arbitrary
  selection;
- no runner or author is constructed for invalid or unsupported work; and
- no `--force` option can bypass source, binding, route or oracle validation.

### 16.5 End-to-end campaign

A coordinated live acceptance campaign shall include:

1. one built-in PromptInject suite;
2. one built-in jailbreak suite;
3. one built-in encoding suite;
4. one ASAGO exact direct-prompt case;
5. one ASAGO indirect tool-result case;
6. one ASAGO generic multi-turn case with tools;
7. one unsupported state/timing case; and
8. exact receipt reconciliation for every planned and unplanned item.

Use an OpenAI Chat Completions-compatible target for the initial tool-calling
qualification because PR #11 explicitly supports that path. Live model calls
require explicit opt-in and approved data egress.

## 17. Testing and quality gates

Implement feature behavior through Gherkin acceptance first, then source and
focused tests. Do not harden isolated slices before the complete flow works.

Required final gates per repository:

- generated acceptance passes from repository-relative feature paths;
- deterministic unit and integration suites pass without network access;
- replay contract fixtures are byte-pinned across repositories;
- Ruff and formatting checks pass;
- `git diff --check` passes;
- changed functions remain at CRAP <= 6 using fresh branch coverage;
- DRY review confirms one canonical message serializer, one oracle comparator
  implementation and one route-matching implementation; and
- mutation hardening is run only after the complete deterministic and live
  campaign paths are working.

Garak probe tests additionally cover Conversation/OpenAI round-trip behavior,
response tool-call capture and detector evidence. Orchestrator tests use an
in-memory runner and shall not require Garak installation or target access.

## 18. Implementation sequence

### Task 1: Add producer stimulus intent and correct artifact execution semantics

- add platform-neutral stimulus requirements to the current producer
  projection and contract kit;
- add reviewed stimulus bindings to the current runtime-binding shape;
- add conversation profile, plan, oracle and executable-case models;
- ensure the final UCA is not rendered into prompt history;
- introduce constrained conversation authoring; and
- publish closed execution-case and trace contracts with fixtures.

Exit: SCN-020 compiles into a conversation that ends before the target tool
call, with `false` retained only in its structured oracle and available tool
schema.

### Task 2: Add Garak replay contracts

- build on PR #11;
- extract the shared source loader;
- add direct and generic conversation replay probes;
- add structured conversation detector;
- retain indirect replay and LLM judge; and
- publish version-pinned conformance fixtures.

Exit: Garak can load and execute all exact replay fixture families with tool
metadata preserved.

### Task 3: Implement the execution orchestrator

- create the new repository/package;
- vendor execution-case and Garak route contract kits;
- add the pure route catalog and campaign planner;
- add in-memory and production Garak runner adapters;
- add atomic receipts; and
- support target-level built-in suites plus exact replay work in one campaign.

Exit: one offline campaign plan contains all requested built-in suites and
routes each exact fixture correctly without a model call.

### Task 4: Coordinate end-to-end acceptance

- run deterministic cross-repository contract tests;
- run the eight-case campaign matrix;
- run one approved live target campaign;
- inspect exact prompt-side messages and target outputs;
- reconcile Garak reports to ASAGO source identities; and
- document residual unsupported execution requirements.

Exit: the campaign receipt proves what ran, which probe ran it, what the target
did, how the result was evaluated and which source scenario—if any—the result
belongs to.

### Task 5: Harden only after functional completion

- complete CRAP, DRY and mutation gates;
- remove replaced custom Garak runner-format paths;
- retain an explicit migration reader only if an existing consumer requires
  it; and
- update architecture, runbooks and contract locks in all repositories.

## 19. Compatibility and migration

- Keep the current verified execution bundle and projection contracts intact.
- Introduce runtime-binding v2 without changing v1 digests.
- Existing v1 binding documents remain inspectable and readiness-compatible
  for non-replay planning, but require explicit migration before replay.
- Replace the current custom Garak artifact as the normal runner input. Do not
  silently reinterpret it as PR #11 conversation source.
- Deprecate the current artifact-generator runtime-observation writer after the
  orchestrator receipt path is available. Historical receipts remain readable
  and immutable.
- Retain historical `generate-legacy` only under its explicit command until a
  separate removal decision.
- Pin the TrustyAI Garak revision containing PR #11 and subsequent replay
  changes in the route catalog and orchestrator lock.
- A Garak revision or probe-set change produces a new route-catalog digest and
  invalidates campaign resume, never source scenario identity.

## 20. Completion criteria

This specification is complete when:

- all five required work types can appear in one campaign;
- built-in suites and exact replays remain semantically distinct;
- every exact replay has an explicit reviewed stimulus binding;
- an author writes only closed content slots;
- prompt history ends before the target response;
- one deterministic route is selected from typed execution facts;
- unsupported and ambiguous cases remain visible and unexecuted;
- Garak receives its native probe configuration and replay-source format;
- target output, tool calls and detector evidence are recorded;
- receipts close back to exact ASAGO source and binding digests; and
- no repository oversteps the ownership defined in Section 5.
