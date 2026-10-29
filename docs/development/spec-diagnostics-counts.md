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

The script reads each run, writes only under `--out-dir`, and calls no model
(see its docstring). A run is diagnosed on its final artifacts, each checked
against the identity its `synthesis-manifest.yaml` pins:

- final loss analysis: `loss-analysis.yaml` (identity matched in every
  diagnosed run);
- final control structure: `control-structure.yaml` with the descriptions of
  `control-action-enrichment.yaml` (no diagnosed run applied a structural
  revision, so none has `control-structure-final.yaml`; identity matched in
  every diagnosed run);
- retained ICAs: the baseline slots of the effective view in
  `target-realization.yaml`, ICA IDs checked against the view's baseline ICA
  IDs. Target-derived slots (present in 19 runs) are outside the retained
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
That the pattern recurs across use cases and arms suggests a systematic
omission in how the structure is derived; this was not traced to a cause.

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
