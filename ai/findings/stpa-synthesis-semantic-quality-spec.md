# STPA synthesis semantic-quality improvement

**Status:** Approved, functionally implemented, and live-qualified. Source
mutation hardening remains deliberately deferred.

**Builds on:**
[stpa-obligation-aware-prompt-contract-correction-spec.md](stpa-obligation-aware-prompt-contract-correction-spec.md)

**Evidence:**

- `output/runs/20260901-synthesis-klarna-quality-v6`
- `output/runs/20260901-synthesis-nhs-quality-v14`
- `output/runs/20260901-synthesis-klarna-prompt-contract-v1`
- `output/runs/20260901-synthesis-nhs-prompt-contract-v13`
- `output/runs/20260901-synthesis-klarna-semantic-quality-v2`
- `output/runs/20260901-synthesis-nhs-semantic-quality-v1`
- `output/runs/20260902-nhs-mechanism-verifier-integrated-v2`

## 1. Decision

The synthesis pipeline keeps its current meaning:

1. Every applicable taxonomy obligation is presented to STPA.
2. An obligation asks STPA to consider a known concern; it does not force an
   ICA or scenario.
3. STPA may find an unsafe-control path, prove the concern structurally
   inapplicable, identify missing evidence, or remain unresolved.
4. A plausible attack mechanism may still produce a useful ordinary STPA
   scenario when it does not correspond to the reviewed risk.
5. Such a scenario does not count as addressing that risk's obligation.
6. Phase 2 remains the only authority for confirmed taxonomy/STPA
   correspondence or coverage.

This improvement targets output quality and decision clarity. It must not
restore permissive identity handling, turn obligations into scenario recipes,
or suppress valid scenarios merely because their prose needs editing.

## 2. Observed baseline

### 2.1 ICA writing

The newer ICA contract removed extreme run-on responses, but current prose is
still repetitive.

| Run | Scenarios | Median ICA | Longest ICA | More than 300 characters |
| --- | ---: | ---: | ---: | ---: |
| Klarna quality v6 | 42 | 303 characters / 42 words | 398 / 56 | 22 |
| NHS quality v14 | 27 | 345 characters / 46 words | 437 / 64 | 24 |
| Klarna prompt-contract v1 | 6 | 597 characters / 87 words | 1,697 / 232 | 6 |
| NHS prompt-contract v13 | 10 | 510 characters / 70 words | 2,718 / 398 | 8 |

The final ICA currently concatenates:

```text
responsibility description
+ deterministic unsafe-action phrase containing the exact action
+ model-authored deviation
```

The prompt asks only for a non-empty deviation. The model often repeats the
action and unsafe-action category already supplied by the compiler. Prompt
views also contain duplicate loss records in some target calls; one NHS call
listed L-1 four times and L-2 six times.

### 2.2 Stage 5 source selection

Twelve of the eighteen failed scenario attempts in the earlier NHS and Klarna
runs came from mismatched causal-factor type and source namespace. The old
contract asked the model to choose both values independently. It often
classified a coordination, responsibility, or control-action record as a
process-model flaw.

The implemented request-local source handles have closed this defect:

- older NHS: six wrong source namespaces in eighteen Stage 5 calls;
- older Klarna: six namespace failures in thirteen Stage 5 calls;
- current NHS: zero namespace failures in thirty-two Stage 5 calls; and
- current Klarna: zero namespace failures in forty-two Stage 5 calls.

This improvement must retain the handle-based design. The remaining saved-run
failures are different: six missing controlled-process targets in Klarna and
five empty defender-belief vulnerability descriptions in NHS.

### 2.3 Risk-to-pattern pairing

The taxonomy graph often discovers candidates by expanding through broad
categories rather than by recording a direct pair-specific relationship.

For the 52 applicable NHS obligations:

- 27 use `broad match -> broad category -> attack pattern`;
- 20 use `related match -> broad category -> attack pattern`; and
- only 5 begin with an exact match, after which they still cross a broad
  category.

Each NHS T2 pattern therefore receives the same eight source risks. Klarna has
a median of five patterns per risk and one risk expands to twelve patterns.

The clearest example pairs the NHS risk **Data acquisition restrictions**
with **AP-T2-03 Automated mass-action abuse via tool amplification**. STPA can
plausibly find batch-tool controls for the attack pattern, but that does not
make mass action an expression of legal restrictions on acquiring training
data.

The model received both meanings and was told that the concern was a
hypothesis. It nevertheless followed the attack pattern for this pair while
rejecting a different mismatch in the same response. Pair comparison is
therefore possible but not stable enough as an unstructured prose judgement.

### 2.4 Obligation resolution

Both current runs account for every obligation but resolve only a small share
of the applicable set.

| Run | Applicable | Addressed | Unresolved |
| --- | ---: | ---: | ---: |
| Klarna quality v6 | 52 | 5 | 47 |
| NHS quality v14 | 52 | 8 | 44 |

The unresolved rows stop at different points:

| Stopping point | Klarna | NHS |
| --- | ---: | ---: |
| No supported STPA target | 23 | 9 |
| Not-applicable proposed without complete evidence | 6 | 17 |
| Target selected but ICA consideration unresolved | 18 | 18 |

Thirty-three unresolved Klarna obligations and fourteen unresolved NHS
obligations had been qualified `ready`. The remainder arrived with missing,
contradictory, or structurally infeasible evidence, so an unresolved outcome
is often correct rather than a generation failure.

Current scorecards report quality among surviving scenarios. They can show
100 percent grounding and traceability without showing that only 5 of 52 or 8
of 52 applicable obligations were addressed. Provider-call records also use
`success` for a returned provider response even when later semantic validation
rejects it. The complete decision funnel is not yet visible in one place.

## 3. Goals

The implementation must:

- make the human-facing ICA one concise unsafe-control statement;
- retain full structured hazard, loss, constraint, and consideration evidence
  outside that sentence;
- migrate the remaining obligation-aware prompt bodies from Python strings to
  Jinja templates;
- keep prompt-view projection and domain validation in Python;
- distinguish system mechanism plausibility from correspondence to the
  reviewed risk;
- keep every applicable obligation in the STPA run;
- permit useful STPA scenarios without incorrectly crediting a mismatched
  taxonomy risk;
- classify every unresolved outcome by the point at which analysis stopped;
- distinguish provider response, parsing, semantic validation, and final
  publication outcomes in call evidence;
- reconcile run errors, obligation accounting, scenario realization, and the
  quality scorecard; and
- improve prompt compactness without silently truncating semantic evidence.

## 4. Non-goals

This work does not:

- require one scenario for every obligation;
- discard broad or weak taxonomy mappings;
- allow the model to choose authoritative IDs or causal-factor namespaces;
- treat a generated scenario as Phase 2 correspondence or coverage;
- reject an otherwise valid scenario solely because its ICA prose is long;
- introduce a prose-similarity score as authority;
- combine the three Phase 2 coverage denominators;
- change the public `generate` or `stpa-run` command names; or
- run live models in deterministic tests.

## 5. Jinja prompt migration

### 5.1 Scope

Move the three remaining prompt pairs assembled in
`stpa/obligation_aware/prompts.py` into Jinja templates:

```text
structural_routing_system.j2
structural_routing_user.j2
structural_revision_system.j2
structural_revision_user.j2
synthesis_ica_system.j2
synthesis_ica_user.j2
```

Place them under a dedicated obligation-aware template directory whose name
does not shadow the existing `prompts.py` module. The Python builders retain
their current public signatures and return `(system_prompt, user_prompt)`.

### 5.2 Boundary

Python owns:

- typed prompt-view projection;
- canonical ordering and deduplication;
- relationship validation;
- YAML/JSON serialization supplied to the template;
- context-budget preflight;
- response parsing and compilation; and
- authoritative identity.

Jinja owns:

- explanatory prose;
- headings and examples;
- placement of already-projected sections; and
- small presentation-only loops and conditionals.

Templates must not traverse Phase 1 or STPA domain objects, derive IDs, select
hazards or constraints, interpret mapping evidence, or provide fallback data.

### 5.3 Shared instructions and hashing

Move common unsafe-control definitions and copy-only handle instructions into
Jinja partials within the template search roots. Each meaning has one source of
truth. If a partial is shared across ordinary Stage 3 and obligation-aware ICA
analysis, extend `TemplateLoader` to accept ordered search roots rather than
copying the same instruction into two files.

Prompt evidence must hash the complete rendered prompt and record the hashes
of every top-level template and included partial. Changing an included partial
must invalidate the recorded prompt implementation hash.

Use Jinja `StrictUndefined`. A missing renderer variable fails before any
provider call. Add an architecture test that rejects new multiline provider
instruction bodies assembled directly in `obligation_aware/prompts.py`.

### 5.4 Compatibility

Migration does not require byte-identical prompts. Tests assert semantic
sections, exact projected data, stable ordering, absence of forbidden fields,
and deterministic rendered digests. Provider and artifact interfaces remain
unchanged.

## 6. Concise ICA writing contract

### 6.1 Division of authorship

The compiler continues to own:

- responsibility or coordination description;
- exact control-action description;
- authoritative UCA type; and
- the fixed unsafe-action sentence frame.

The provider supplies only a **deviation clause**: the smallest condition that
makes that exact action unsafe in that exact slot.

Examples:

| Type | Provider supplies |
| --- | --- |
| `NOT_PROVIDED` | `patient authorization has not yet been established` |
| `INCORRECT` | `the masking map leaves direct identifiers recoverable` |
| `WRONG_TIMING` | `validation completes after the EHR update is committed` |
| `WRONG_DURATION` | `suppression continues after policy compliance is restored` |

The provider does not repeat the owner, action, UCA label, hazard, loss,
constraint, taxonomy pattern, or recommendation in the clause.

### 6.2 Quality rules

A deviation clause should:

- contain one condition and one sentence or clause;
- normally remain within 32 words and 220 characters;
- contain no examples, alternative branches, mitigation, or attack narrative;
- avoid repeating a substantial normalized phrase from the action text; and
- use mechanism-specific wording only when exact STPA or typed access evidence
  supports that mechanism.

The word and character bounds are presentation targets, not safety authority.
A semantic error still fails closed. A style violation receives one bounded
style correction using the same evidence. If it remains verbose but
semantically valid, retain the finding and record `ica_prose_quality_warning`;
do not turn the obligation or scenario unresolved solely for style.

### 6.3 Prompt compaction

Before rendering one ICA target:

- deduplicate losses, hazards, constraints, process-model parts, feedback, and
  routed considerations by exact identity;
- retain canonical order after deduplication;
- include each description once and express relationships by ID thereafter;
  and
- keep detailed analysis rationale separate from `ica_text`.

The final ICA remains content-addressed from its authoritative semantic fields.
Whitespace-only normalization may not change its identity unexpectedly.

## 7. Two-part risk and pattern assessment

### 7.1 Provider decision

For each obligation, routing returns two explicit assessments in addition to
the structural route:

```text
mechanism_assessment
  plausible_in_system | absent_from_system | insufficient_evidence
risk_alignment
  supported | mismatch | insufficient_evidence
```

The prompt asks two separate questions:

1. Does the attack pattern describe a mechanism that can occur through the
   supplied system structure?
2. Would that mechanism realize the reviewed risk's subject, operation,
   affected object, and consequence?

Shared words such as `input`, `tool`, `parameter`, `value`, or `threshold` are
not sufficient alignment evidence.

### 7.2 Mapping-strength context

The prompt projector derives a plain mapping-strength label from the exact
mapping path:

- `direct_curated_pair`;
- `exact_then_category_expansion`;
- `broad_category_expansion`; or
- `related_category_expansion`.

The model receives the label and its meaning, not raw serialized mapping JSON.
Category expansion remains discovery evidence and increases the need for an
explicit pair judgement; it is not proof of mismatch by itself.

### 7.3 Outcome rules

- Plausible mechanism plus supported risk alignment may proceed toward an
  obligation-addressing ICA.
- Plausible mechanism plus risk mismatch may still produce or retain an
  ordinary STPA finding and scenario, but the obligation records
  `risk_pattern_mismatch` and is not `addressed`.
- Absent mechanism requires complete structural evidence before a final
  not-applicable result.
- Insufficient evidence remains unresolved with the exact missing fact or
  path.
- ICA filling may correct a provisional routing assessment when it provides
  stronger exact structural evidence, but must retain both assessments and an
  explicit reason for the change.

The NHS data-acquisition/mass-action fixture must demonstrate the second rule:
batch-tool abuse may be a useful scenario, while the legal data-acquisition
obligation remains unaddressed.

## 8. Resolution funnel and call evidence

### 8.1 Stop reasons

Every applicable obligation receives one terminal stop reason drawn from a
closed set:

```text
addressed
risk_pattern_mismatch
mechanism_path_unsubstantiated
no_structural_route
not_applicable_proven
not_applicable_evidence_incomplete
ica_consideration_unresolved
provider_contract_failure
prompt_budget_exceeded
scenario_realized
scenario_generation_failure
scenario_not_requested
```

The accounting and realization artifacts keep their existing dispositions.
Stop reasons explain those dispositions; they do not create a new blended
status or coverage score.

### 8.2 Provider-call lifecycle

Call evidence distinguishes:

```text
provider_response_received
draft_parsed
semantic_validation_passed
compiled
published
terminal_error_codes[]
```

The existing `success` field may remain as a compatibility view of provider
transport success, but reports must label it accordingly. A returned JSON
response that later fails validation is not displayed as a successful stage.

### 8.3 Report reconciliation

The run report presents one funnel:

```text
all plan rows
  -> governance-only
  -> applicable and considered
     -> risk/pattern mismatch
     -> no route
     -> proposed N/A: proven or incomplete
     -> routed to ICA
        -> ICA finding or unresolved
        -> scenario requested
           -> realized or failed
```

The counts must reconcile exactly with obligation accounting, scenario
realization, provider-call terminal outcomes, and run-manifest errors.
Survivor-only measures such as grounding and traceability remain useful, but
their denominator is shown beside the full applicable-obligation denominator.

## 9. Prompt and run efficiency

Routing currently uses about 14,000-15,000 prompt tokens per provider call,
while ICA calls use about 4,800-5,000 at the median. These are diagnostic
baselines, not quotas.

The implementation should reduce avoidable volume by:

- deduplicating exact records before rendering;
- rendering the ID glossary once per call;
- omitting unrelated structural collections from target calls;
- keeping audit evidence outside provider-facing views;
- batching only while every item and its relationship context fit; and
- recording per-stage input, output, retry, and correction totals.

No semantic section is silently truncated to meet a token target. A live
qualification compares token totals with the baseline and explains material
increases or reductions.

## 10. Acceptance behavior

Committed Gherkin and deterministic fixtures must demonstrate:

1. All three obligation-aware prompt pairs render through Jinja with
   `StrictUndefined`.
2. Changing a shared partial changes the prompt implementation hash.
3. Reordered input sets render identical prompts.
4. Exact duplicate losses and hazards appear once in an ICA prompt.
5. Every opaque handle is explained as copy-only.
6. The ICA prompt requests a short deviation clause rather than a complete
   ICA narrative.
7. The compiler preserves exact owner, action, UCA type, hazard, loss, and
   constraint meaning.
8. A concise clause produces concise non-repetitive ICA text.
9. A verbose but semantically valid clause records a style warning rather
   than deleting the scenario.
10. An unsupported mechanism claim remains a semantic failure.
11. A direct pair with exact structural support can address an obligation.
12. A category-expanded pair must return explicit mechanism and risk-alignment
    decisions.
13. A plausible mechanism with mismatched risk may produce an ordinary
    scenario but cannot address the obligation.
14. The NHS data-acquisition/mass-action fixture follows that rule.
15. Every applicable obligation appears exactly once in the resolution
    funnel.
16. Provider success followed by validation failure is reported as a failed
    stage with both lifecycle facts retained.
17. Run-manifest errors reconcile with the scorecard and terminal call
    outcomes.
18. Survivor-only percentages show their exact denominators.
19. No deterministic test constructs or contacts a provider client.
20. Existing `generate`, `stpa-run`, artifact names, and Phase 1/2 authority
    boundaries remain compatible.

## 11. Implementation sequence

### Slice 1: Jinja migration and prompt hygiene

- Add the obligation-aware templates and shared partials.
- Keep typed projectors and serialization in Python.
- Extend template hashing to cover included partials.
- Deduplicate target context by identity.
- Add render-contract and architecture tests.

**Complete when:** all obligation-aware provider prompts render solely through
Jinja, are deterministic, and contain no duplicate semantic records.

### Slice 2: ICA writing quality

- Add the deviation-clause instructions and quality diagnostics.
- Separate semantic rejection from presentation correction.
- Preserve full rationale outside the human-facing ICA.
- Add captured Klarna and NHS long-prose fixtures.

**Complete when:** concise fixtures render compact ICAs and verbose-but-valid
fixtures remain publishable with an explicit warning.

### Slice 3: pair assessment

- Project mapping strength without raw mapping payloads.
- Add the two explicit provider assessments.
- Compile their outcomes into routing, accounting diagnostics, and ICA
  consideration rules.
- Preserve useful STPA-only findings for mismatched pairs.

**Complete when:** the NHS mass-action example can produce a useful scenario
without claiming to address data-acquisition restrictions.

### Slice 4: funnel and evidence reconciliation

- Add closed stop reasons and provider-call lifecycle fields.
- Reconcile accounting, realization, stage errors, and scorecard denominators.
- Update the HTML report and live-run qualification record.

**Complete when:** every applicable obligation and every failed provider stage
has one plain, traceable terminal explanation and all totals reconcile.

### Slice 5: live qualification, then hardening

- Reuse fixed Phase 1 and baseline STPA artifacts for bounded controlled
  comparisons before regenerating full baselines.
- Run NHS and Klarna through the approved cluster profile, using the approved
  OpenRouter profile only when the cluster is unavailable.
- Inspect ICA prose, pair decisions, unresolved reasons, and scenario meaning.
- Correct functional defects before mutation work.
- Then run DRY, branch coverage, CRAP, targeted source mutation, Gherkin
  mutation, full QA, and documentation review.

**Complete when:** both live cases produce useful scenarios, no weak pair is
credited as an addressed risk, all obligations reconcile, and the normal
quality gates pass.

## 12. Expected code seams

| Concern | Primary seam |
| --- | --- |
| Jinja rendering | `stpa/infra/templates.py`, new obligation-aware template directory, `stpa/obligation_aware/prompts.py` |
| Prompt projection and deduplication | `stpa/obligation_aware/prompts.py` and closed prompt-view contracts |
| ICA compilation and style diagnostics | `stpa/obligation_aware/provider.py`, `slot_filling.py`, prompt templates |
| Pair assessment | obligation-aware routing/provider draft contracts and accounting adapter |
| Call lifecycle | provider call record and run-manifest adapters |
| Resolution funnel | synthesis accounting, realization, scorecard, and report adapters |

Inward domain models must not import Jinja, provider clients, CLI, filesystem,
or report code. Prompt templates are presentation adapters over closed views.

## 13. Quality gates

After all functional slices are integrated:

- generated Gherkin acceptance and IR DRY checks;
- deterministic unit, integration, and compatibility tests;
- prompt-template DRY review and included-partial hash verification;
- branch coverage for changed projectors, compilers, and reconciliation code;
- CRAP at or below 6 for changed production modules;
- targeted differential source mutation for changed production files;
- Gherkin mutation for new acceptance contracts;
- independent external QA for prompt and artifact compatibility;
- Ruff format/check and clean diff validation; and
- bounded opt-in NHS and Klarna live qualification.

Mutation hardening begins only after the complete functional workflow is
running and the generated scenarios have been inspected.

## 14. Exit criteria

This improvement is complete when:

1. obligation-aware prompts are maintained as Jinja templates over closed
   prompt views;
2. template hashes cover included partials;
3. ICA text is normally concise and no valid scenario is discarded solely for
   style;
4. prompt views contain no duplicate exact semantic records;
5. causal-factor identity remains compiler-owned and namespace failures stay
   eliminated;
6. mechanism plausibility and reviewed-risk alignment are independent typed
   decisions;
7. all obligations still run;
8. a useful STPA scenario cannot falsely address a mismatched taxonomy risk;
9. every unresolved obligation has one specific stop reason;
10. provider transport success is distinct from semantic and publication
    success;
11. scorecards expose both survivor quality and full obligation denominators;
12. Klarna and NHS totals reconcile across accounting, realization, call
    evidence, and manifests; and
13. acceptance, DRY, CRAP, mutation, QA, compatibility, documentation, and
    live qualification gates pass.
