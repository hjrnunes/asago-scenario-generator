# Specification diagnostics on saved runs

The report-only specification diagnostics
(`asago_scenario_generator.stpa.spec_diagnostics`, listed in
[the STPA relationship checklist](../architecture/stpa-relationship-checklist.md))
were computed offline over 219 saved runs of two evaluation families, `stpo7`
(66 runs) and `stpo7b` (153 runs), across the three synthetic use cases
(airbnb, klarna, occiai). Runs are named by their directory names; the names
are data identifiers only.

**None of these checks is a gate.** They never block a run, never repair an
artifact, and leave every finding's `disposition` unset. The counts below
describe what they would report; they are not pass/fail results.

## Method

```bash
OUT=$(mktemp -d)
uv run --frozen python scripts/spec_diagnostics_sweep.py --out-dir "$OUT/sweep" \
    RUNS/stpo7-* RUNS/stpo7b-*
```

The script reads each run, writes nothing inside any run (it refuses every
destination that would land in one), and calls no model (see its docstring).
A run whose files cannot be read or parsed is skipped with the reason.

A run is diagnosed on its final artifacts, each checked against the identity
its `synthesis-manifest.yaml` pins:

- final loss analysis: `loss-analysis.yaml` (identity matched in every
  diagnosed run);
- final control structure: `control-structure.yaml` with the descriptions of
  `control-action-enrichment.yaml` (no diagnosed run applied a structural
  revision, so none has `control-structure-final.yaml`; identity matched in
  every diagnosed run);
- retained ICAs: the baseline slots of the effective view in
  `target-realization.yaml`, loaded with its integrity check
  (`TargetRealizationResult.from_yaml`) and matched to the manifest's
  `target_realization` identity (both held in every diagnosed run).
  Target-derived slots (present in 19 runs) are outside the retained
  enumeration and were not read.

## Runs diagnosed and skipped

63 runs were diagnosed; 156 were skipped. No run was skipped for an
unreadable schema: every run that reached a synthesis manifest loaded under
the current models.

| Reason skipped | stpo7 | stpo7b | First recorded stage error (count) |
| --- | ---: | ---: | --- |
| No producer output (no `loss-analysis.yaml`) | 4 | 3 | none recorded |
| Stage 2 published no control structure | 30 | 113 | `call_2b_control_elements: LiveRequestBudgetError` (90), `call_1_requirements: LiveRequestBudgetError` (28), `call_2b_control_elements: ValueError` (15), `call_2a_responsibilities: LiveRequestBudgetError` (4), `call_2b_control_elements: missing control action repair failed` (3), `call_2b_control_elements: ValidationError` (2), `assemble_control_structure: ... unresolved references` (1) |
| Control structure but no synthesis manifest | 6 | 0 | none recorded |
| **Total skipped** | **40** | **116** | |

Diagnosed runs per family and use case: stpo7 airbnb 9, klarna 10, occiai 8;
stpo7b airbnb 10, klarna 16, occiai 10.

## Counts per check

Each cell is *runs with at least one finding / runs checked, findings*. Every
check ran on all 63 diagnosed runs (each had a `target-realization.yaml`, so
the ICA checks ran too).

| Check | stpo7 airbnb | stpo7 klarna | stpo7 occiai | stpo7b airbnb | stpo7b klarna | stpo7b occiai | All |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `controlled_process_without_feedback` (a) | 8/9, 47 | 9/10, 23 | 8/8, 37 | 9/10, 66 | 16/16, 54 | 10/10, 51 | 60/63, 278 |
| `controlled_process_unobserved` | 6/9, 10 | 9/10, 15 | 6/8, 15 | 7/10, 24 | 16/16, 44 | 10/10, 32 | 54/63, 140 |
| `hazard_without_ica` (b) | 4/9, 5 | 6/10, 8 | 3/8, 3 | 2/10, 2 | 5/16, 6 | 7/10, 10 | 27/63, 34 |
| `action_without_process_model_refs` (c) | 1/9, 3 | 3/10, 3 | 0/8, 0 | 0/10, 0 | 0/16, 0 | 5/10, 9 | 9/63, 15 |
| `process_model_variable_without_values` (d) | 3/9, 6 | 1/10, 1 | 2/8, 15 | 4/10, 6 | 0/16, 0 | 4/10, 4 | 14/63, 32 |
| `ica_without_related_constraints` | 0/9, 0 | 0/10, 0 | 0/8, 0 | 0/10, 0 | 0/16, 0 | 0/10, 0 | 0/63, 0 |
| `hazard_without_constraint` | 0/9, 0 | 2/10, 4 | 2/8, 2 | 0/10, 0 | 1/16, 1 | 0/10, 0 | 5/63, 7 |

By evaluation arm (the second component of the run name), over the same 63
runs: `baseline` 32 runs, `current` 31 runs.

| Check | baseline | current |
| --- | --- | --- |
| `controlled_process_without_feedback` | 32/32, 165 | 28/31, 113 |
| `controlled_process_unobserved` | 31/32, 81 | 23/31, 59 |
| `hazard_without_ica` | 12/32, 15 | 15/31, 19 |
| `action_without_process_model_refs` | 4/32, 6 | 5/31, 9 |
| `process_model_variable_without_values` | 8/32, 21 | 6/31, 11 |
| `ica_without_related_constraints` | 0/32, 0 | 0/31, 0 |
| `hazard_without_constraint` | 1/32, 3 | 4/31, 4 |

Every `controlled_process_unobserved` finding implies one
`controlled_process_without_feedback` finding per issuing responsibility, so
the two counts overlap; the second also counts processes another
responsibility observes.

`ica_without_related_constraints` found nothing on these runs: the ICA fill
wire requires a governing constraint/hazard pair for every finding. The check
stays because the saved model does not require one (`related_constraints`
defaults to `[]`; see the checklist, row O118).

## Hand-checked sample

Each finding below was read against the run's artifacts and the use case it
was generated from (`use-case.txt`, and the target's tool inventory, whose
every tool declares a required `result` output). Verdicts: **missing
modelling** (the analysis omits something the system has), **system
deficiency** (the system really lacks the relationship: a candidate causal
scenario), **producer bug**, or **undetermined** when the inputs do not
settle it.

### `controlled_process_without_feedback` and `controlled_process_unobserved`

| Run | Finding | Verdict | Basis |
| --- | --- | --- | --- |
| stpo7b-current-airbnb-d1 | CP-6 (Trust and Safety review), RESP-8, CA-8-1 escalate | Missing modelling | `escalate_trust_safety` returns a result and the state summary lists trust cases; RESP-14 observes CP-6, RESP-8 does not. Both responsibilities are the one assistant. |
| stpo7b-current-airbnb-d1 | CP-1 (conversation), RESP-3, CA-3-2 report availability to user | Missing modelling, low value | Six other responsibilities of the same assistant read CP-1; the next user turn is the feedback. |
| stpo7-baseline-airbnb-d1 | CP-6 unobserved, CA-8-1 and CA-11-1 | Missing modelling | Same escalation tool; RESP-8's only channel is sourced from RESP-8 itself. |
| stpo7b-current-klarna-d3 | CP-3 (refund/payment engine) unobserved, CA-3-1 process refund, CA-3-2 schedule payment | Missing modelling | `process_refund` returns a result, and the tool holds or rejects large or ineligible refunds, so whether a refund happened is observable; RESP-3's channels read CP-1 and CP-2 only. |
| stpo7-baseline-klarna-d1 | CP-2 (human agents) unobserved, CA-1-2 escalate | Missing modelling | `escalate_to_human` returns a result and the ledger records escalations. Whether the assistant learns the handoff outcome in the real deployment is not in the inputs. |
| stpo7b-current-occiai-d2 | CP-2 unobserved, RESP-1, CA-1-2 invoke clinical question tool | Missing modelling, safety-relevant | `ask_clinical_question` returns an ESCALATE response for red-flag terms; that result is the feedback the escalation decision needs, and the structure has no channel for it. |
| stpo7-baseline-occiai-d1 | CP-4 (escalation system) unobserved, CA-5-1 create escalation case | Missing modelling | `escalate_to_clinician` returns a result; the ledger lists escalations. |

Across the sample the pattern is the same: actions that write or notify
through a tool have no `operation_result` channel for that tool's result.
The likely cause is in how Stage 2 is prompted, not in what its schema
allows. A feedback channel exists only as the update of a process-model part
(`FeedbackChannel.updates` is required, and Call 2b derives feedback part by
part); Call 2a derives the parts before any action exists and is never asked
what a controller learns from the operations it invokes; and the evidence
block did not say whether an operation returns a result. Call 2b may still
declare an `operation_result` channel from a process, and the critic revision
may add parts and channels, so these explain a tendency to omit the feedback,
not an impossibility. See
[Feedback from invoked operations](#feedback-from-invoked-operations).

### `hazard_without_ica`

| Run | Hazard | Verdict | Basis |
| --- | --- | --- | --- |
| stpo7-current-airbnb-d1-r43 | H-7 `update_listing` by a non-host | Missing modelling | The final structure has one responsibility and two actions (reservation lookup); no action invokes `update_listing`, which the use case documents. SC-7 is cited by no responsibility. |
| stpo7-baseline-airbnb-d1 | H-8 excessive resource consumption | Undetermined | SC-8 is cited by no responsibility; the inputs name no operation that controls resource use, so neither a missing control nor a real deficiency is established. |
| stpo7b-baseline-occiai-d2 | H-7 audit log misses commit attempts | Missing modelling | The ledger is written by the target backend, which the structure does not model as a controller; RESP-7 only reads it, and its ICAs cite H-10 and H-11. |
| stpo7-baseline-klarna-d2 | H-4 output mirrors copyrighted works | Undetermined | No security constraint lists H-4 (also a `hazard_without_constraint` finding), so no responsibility can implement it; the review marked the link unresolved (see below). |
| stpo7-current-occiai-d5-r43 | H-12 service disruption or integration failure | Undetermined | No security constraint lists H-12; as for H-4. |

### `action_without_process_model_refs`

| Run | Finding | Verdict | Basis |
| --- | --- | --- | --- |
| stpo7-current-airbnb-d2 | CA-3-2 invoke `update_listing`, RESP-3 | Missing modelling, safety-relevant | `update_listing` is host-only; the decision needs the actor-is-host variable, which the structure omits. |
| stpo7-current-airbnb-d2 | CA-4-3 invoke `escalate_trust_safety`, RESP-4 | Missing modelling | Escalation is decided on the message's topic; RESP-4 has no topic variable. |
| stpo7-current-klarna-d4 | CA-8-2 retrieve state summary, RESP-8 | Undetermined | A read-only ledger read; whether its context matters depends on what the ledger exposes, which the inputs do not say. |
| stpo7b-baseline-occiai-d4 | CA-9-1 `get_occiai_state_summary`, RESP-9 | Missing modelling | RESP-9 has no process-model part and no feedback channel at all; the structural heuristics report both as errors, which become warnings and do not block. |

### `process_model_variable_without_values`

| Run | Finding | Verdict | Basis |
| --- | --- | --- | --- |
| stpo7-baseline-airbnb-d1 | PM-3-1 "requested listing and date", needed by CA-3-1 and CA-3-2 | Missing modelling | The variable is an identifier, not a decision state; the decision variable (availability) is absent. |
| stpo7-baseline-klarna-d1 | PM-1-1 "conversational context and history", needed by CA-1-1 and CA-1-2 | Missing modelling | Too coarse to have values; the escalation decision it gates needs a trigger variable. |
| stpo7-baseline-occiai-d5 | PM-2-5 "tool argument/session alignment", needed by CA-2-1 to CA-2-3 | Missing modelling | The values are plainly binary. No feedback channel updates the variable either, although the current Call 2b wire rejects an orphan part; which producer version wrote this run was not established. |

### `hazard_without_constraint`

| Run | Hazard | Verdict | Basis |
| --- | --- | --- | --- |
| stpo7b-current-klarna-d5 | H-5 PII disclosed to the wrong recipient | Undetermined | `loss-analysis-gates.yaml` records "post-review unresolved: hazard H-5 has no constraint; the review marked it unresolved" and "constraint SC-6 has no hazard" as advisory, with `passed: true`. |
| stpo7-baseline-klarna-d2 | H-4, H-1, H-7 | Undetermined | Same record for all three, beside three constraints left without a hazard. |
| stpo7-current-occiai-d5-r43 | H-12 | Undetermined | Same record, beside SC-12 left without a hazard. |

All 7 findings of this check are of this kind: the Call 3 semantic review
marked the hazard-constraint link unresolved (a fact the sources lack), and
the density gate exempts such records on purpose
(`loss_analysis_gates._exempt_unresolved`). That is not a producer bug, and
the inputs do not settle whether the link was missing modelling or rightly
dropped.

No sampled finding was a producer bug, in the diagnostics or elsewhere, and
none was established as a system deficiency: in every sampled feedback
finding the target's tool returns a result the structure does not model.

`ica_without_related_constraints` produced no finding to sample.

## Feedback from invoked operations

The Stage 2 evidence block now names the observed operations that declare an
output and asks the model, in Calls 2a and 2b and in the critic and its
revision, what each result tells the responsibility that invokes it: a
process-model variable and a feedback channel only when a later decision
depends on the result, with the channel's `source` and `source_kind` taken
from what the result carries (record or state data, or retrieved free text),
an answer, refusal or hand-off signal returned in reply to a question read as
retrieved text that claims no record state, an acknowledgement read as an
acknowledgement, and nothing added when the
evidence does not say what a result reports. Code adds no channel itself: a
declared output proves only that a payload returns to the caller, not where
its information originates or how far it can be trusted.

This is a prompt change, so it cannot change saved runs and has no offline
after-numbers. The sweep now measures what it targets: each finding of the
two feedback checks lists the `effect_kind` and bound `operation` of the
actions it names, and `feedback_by_action` in the counts splits those
findings into `bound_tool_call` (the finding names a `tool_call` bound to an
observed operation) and `other`.

### Corpus and baseline

The corpus is the 219 run directories matching `stpo7-*` and `stpo7b-*`
under the orchestrator's runs directory (`RUNS`). The sweep's
`spec-diagnostics-runs.jsonl` lists each run with its status; for this corpus
its SHA-256 is
`03cae258afa65871d7c6aa49e577d7328e2325c2270de68ddca0cc7c4109b59e`.

```bash
OUT=$(mktemp -d)
uv run --frozen python scripts/spec_diagnostics_sweep.py --out-dir "$OUT/final" \
    RUNS/stpo7-* RUNS/stpo7b-*
uv run --frozen python scripts/spec_diagnostics_sweep.py --stage2-only \
    --out-dir "$OUT/stage2" RUNS/stpo7-* RUNS/stpo7b-*
```

| Check | Mode | Runs diagnosed | `bound_tool_call` (runs, findings) | `other` (runs, findings) |
| --- | --- | ---: | --- | --- |
| `controlled_process_without_feedback` | final | 63 | 58, 168 | 39, 110 |
| `controlled_process_unobserved` | final | 63 | 51, 118 | 18, 22 |
| `controlled_process_without_feedback` | `--stage2-only` | 69 | 63, 178 | 42, 114 |
| `controlled_process_unobserved` | `--stage2-only` | 69 | 56, 127 | 20, 24 |

`--stage2-only` diagnoses the `loss-analysis.yaml` and
`control-structure.yaml` Stage 2 published, unpinned and without the ICA
checks; it adds the 6 runs that published a structure but no synthesis
manifest. In every run the structure the sweep reads has no bound operation
the evidence did not list, because evidence binding drops one. The prompt
reaches only operations that declare an output; in this corpus every tool of
every run's discovery profile declares one (1823 of 1823 tool rows):

```bash
uv run --frozen python -c 'import glob, json; tools = [t for p in glob.glob("RUNS/stpo7*/stages/discover/output/execution-target-profile.json") for t in json.load(open(p))["inventory"]["tools"]]; print(len(tools), sum(t.get("output_schema") is not None for t in tools))'
```

On the `stpo7b-current` arm, the arm the live check repeats,
`--stage2-only` gives these `controlled_process_without_feedback` findings
that name a bound tool call: airbnb 12 in 5 runs, klarna 22 in 8, occiai 20
in 5 (54 in 18 runs).

### Live check

The instruction's effect needs a live Stage 2 run; it was not run.

- Profile `gemma4-oc`, with the profiles file and seed profile the
  `stpo7b-current` runs recorded.
- Six runs: `stpo7b-current-{airbnb,klarna,occiai}-d1` and `-d2`, each
  repeated with its recorded `generate` arguments and new output directories,
  `--replay-calls` set to the saved run's output directory and
  `--replay-fill`. Stage 1 and Call 1 render as before and replay; Calls 2a,
  2b and 3, the critic and the revision render differently and go live.
- A budget of 16 live requests per run (`--max-live-requests 16`; 96 at
  most). A Stage 2 needs 4 to 6
  live requests without corrections: Calls 2a, 2b and 3, the critic, and the
  revision when the critic reports a gap. The rest covers the bounded
  corrections and transport retries listed in
  `docs/architecture/model-reasks.md`. Later stages exhaust the budget and the
  run stops after Stage 2 has published its structure.
- Measure with `--stage2-only` on the new output directories and compare
  `feedback_by_action.controlled_process_without_feedback.bound_tool_call`
  with the same six saved runs. Also read each new channel sourced from an
  invoked operation's target: its `source_kind` (retrieved free text must not
  be `operation_result`), and for acknowledgement-only operations such as
  escalations, whether the variable claims more than the acknowledgement.
  Report Stage 2 failures (`stage_errors`) separately; spend comes from
  `provider-calls.jsonl`.
