# Model re-asks

This page lists every request the producer sends after a reply was refused,
or after the request itself failed. Nothing else re-sends a request. When
you add, remove, or change a re-ask, update this page and the summary in
`CLAUDE.md`.

The page counts at two levels:

- An **attempt** is one `call_with_policy` request and one `calls.jsonl`
  entry. Every application-level re-ask below is a new attempt. An attempt
  that the prompt preflight blocks (over budget) still gets its
  `calls.jsonl` entry, but it sends nothing: it has no
  `provider-calls.jsonl` record and is not counted in `CallOutcome.calls`.
- A **provider request** is one record in `provider-calls.jsonl`, which
  `generate` always records. One attempt holds one provider request, plus
  any the client re-sends inside it. The client's re-asks get no
  `calls.jsonl` entry of their own. They share the attempt's entry, which
  names each of its records under `provider_requests`.

A replay-fill run counts provider requests sent live against
`--max-live-requests`. Requests it serves from the record do not count.

Step call counts come from `CallOutcome.calls`. That figure counts the
attempts that were sent, plus the client's transport retries and
service-tier fallback requests. A step that counts requests itself can count
less. The risk-coverage review reports 1
request per batch, or 2 after its empty-reply repeat, so transport retries
never raise its `call_count`.

Paths are relative to `src/asago_scenario_generator/stpa/`. "Max" means the
most extra attempts per unit, on top of the first one. Each bound below
leaves out the client's re-asks. Inside every attempt, the client can still
add a transport retry and a service-tier fallback, and the fallback can take
its own transport retry. With a fallback configured, one attempt can
therefore reach 4 provider requests; without one, 2.

## Client

| Re-ask | Where | Trigger | Sends | Max | If it fails too |
| --- | --- | --- | --- | --- | --- |
| Transport retry | `infra/transport_retry.py` `retry_once`; `infra/provider_record.py` `exchange_with_retry` | HTTP 5xx, or a connection error that is not a timeout. Timeouts, every 4xx (429 included) and invalid answers are not retried here. | The same request, after a 1 s pause. Its record names `retry_of`. A replay re-sends it only when the record holds the retry. | 1 per send | The error reaches the attempt. |
| Service-tier fallback | `infra/llm.py` `_complete` | HTTP 429 when the profile sets `service_tier` and `service_tier_fallback` | The same request on the fallback tier, which can take its own transport retry. The attempt's request controls set `service_tier_fallback_used`. | 1 per attempt | The error reaches the attempt. The fallback has its own `provider-calls.jsonl` record and is counted in `CallOutcome.calls`, as is its transport retry. |

An error that reaches the attempt this way is a provider or transport
failure: a timeout, a 4xx (a 429 included, after any fallback), a 5xx after
the transport retry, or a connection error. `is_provider_failure`
(`infra/llm_helpers.py`) recognizes it, and the routing and governance
adapters raise it as `ProviderCallError`. No caller-level re-ask below
follows such a failure: the client has already made the one retry it earns,
so the step goes straight to its "If it fails too" outcome. Only a reply
that fails decoding or validation earns a re-ask.

## The shared correction policy

`call_with_policy` (`infra/llm_helpers.py`) applies a `CorrectionPolicy` to
each call. Both counts default to 0, so `CorrectionPolicy()` re-asks nothing.

- `json_retries`: a reply that does not decode is sent again with the same
  prompt.
- `validation_retries`: a correction request for a schema, parser, or
  validator failure. It sends the original prompt, then the policy's
  `feedback`, then the exact error. It can also include the prior reply
  (`include_response`) and the schema (`include_schema`).
- `correct_undecodable`: a reply that does not decode, and that no
  `json_retries` repeat covers, also earns that correction.

A JSON repeat that is still undecodable can therefore go on to earn the
correction. Most steps below also make a second call themselves (a
caller-level re-ask), using `CorrectionPolicy()` for it.

## Stage 1a loss analysis

| Re-ask | Where | Trigger | Sends | Max | If it fails too |
| --- | --- | --- | --- | --- | --- |
| Targeted repair | `system_model/loss_analysis.py` `_repair_stage1a_failure` | The first risk-derivation or gap reply fails one of a few repairable classes. A risk reply that declares no grounded loss, or a gap reply that leaves losses with no hazard and no constraint, gets a feedback correction. Unknown reference IDs get a reference repair. Malformed disposition rows or obligation entries get a targeted repair. Every other failure stops the call with no request. | Feedback correction: the original prompt, the finding and the prior reply. The other two send a repair prompt for just the failing lists or rows. | 1 per call. It is 2 when an obligation repair leaves disposition rows failing, which earns one disposition repair. | `StageError`. A reference repair that got an answer drops the references it could not resolve. |
| Graph-revision correction | `system_model/loss_analysis_gates.py` `_run_graph_revision_call` | The revision reply fails parsing or validation, or does not decode | The original prompt, then the correction feedback (decode-specific for an undecodable reply), the error and the prior reply | 1 per revision call | Records whose `rule_span` or `applies_when` is defective are dropped. If that is not enough, a density revision raises `StageError` and a stated-rule revision keeps the unrevised graph. |
| Second density revision round | `loss_analysis_gates.py` `_run_density_revision` (`GRAPH_REVISION_ROUNDS = 2`) | The graph from round 1 still fails a density check | A new revision call on that graph with the checks still failing. Checks round 1 introduced are labelled as such. | 1 round, and it has its own correction | `LossAnalysisGateError` |
| Coverage-review repeat | `system_model/risk_coverage_review.py` `_run_one_review_call` | The reply decodes but carries no row, no invalid row and no failure | The same request | 1 per batch | Its cards are `rows_missing`, and the review is `partial` or `unavailable`. |
| Actionability JSON repeat | `system_model/risk_actionability.py` `_classify_batch` (`json_retries=1`) | The reply does not decode | The same prompt | 1 per request | The request fails, which leaves its cards pending for the retry step. |
| Actionability retry step | `risk_actionability.py` `_classify_with_retry` | After the first step, cards are still undecided. The cause can be a reply that failed decoding or its schema, an omitted card, or a decision that contradicts its own action fields. A provider or transport failure, in either request of the first step, ends the batch with no retry step. | A freshly rendered prompt that lists only the pending cards | 1 step per batch. With the JSON repeat, a batch makes at most 4 attempts. | Each undecided card stays actionable with `source: fallback`. |

## Stage 1b capability profile

| Re-ask | Where | Trigger | Sends | Max | If it fails too |
| --- | --- | --- | --- | --- | --- |
| Profile correction | `system_model/profile.py` `_sample_drafts` | A validation failure, or a reply that does not decode | The original prompt, then decode-aware feedback, the error and the prior reply | 1 per draw | The draw is left out of the vote. The stage fails only when every draw fails. |

## Stage 2 control structure

| Re-ask | Where | Trigger | Sends | Max | If it fails too |
| --- | --- | --- | --- | --- | --- |
| Calls 1, 2a, 2b, 3 | `system_model/control_structure.py` `_run_stage2_llm_call` (`json_retries=1`, `validation_retries=1`, `correct_undecodable`) | A reply that does not decode is repeated. A validation failure, or a repeat that does not decode either, earns the correction. | First the same prompt. Then the original prompt, the feedback, the error and the prior reply. | 2 per call | `StageError`, unless the call's recovery applies |
| Call 2b recovery | `control_structure.py` `_repair_call_2b_missing_actions`, `_correct_call_2b_references` | Once the correction is spent, either a responsibility still has no control action or the reply names an unknown reference. The two cannot both apply. | The original prompt, then feedback naming the missing owners or the valid IDs, then the prior reply | 1 per call | The authority bases that are not supported are dropped when that is enough. Otherwise `StageError`. |
| Call 3 density correction | `control_structure.py` `correct_review`, run by `loss_analysis_gates.py` `_run_post_review_corrections` (`POST_REVIEW_CORRECTION_ROUNDS = 1`) | The reviewed graph fails a density check and the correction scope is not empty | The full Call 3 prompt, the failing checks and the records to review again. Only the review rows of those records are merged back. | 1 Call 3, which can also make the 2 Call 3 re-asks | `LossAnalysisGateError` |
| Critic correction | `system_model/critic.py` (step `critic`) | The findings are inconsistent or the reply does not decode | The original prompt, then the feedback and the error | 1 | The critic returns empty findings. |
| Critic-revision correction | `critic.py` (step `revision`) | A wire, merge or authority failure, or a reply that does not decode | The original prompt, the feedback, the prior reply, the error and an authority note | 1 | The authority bases that are not supported are dropped when that is enough. Otherwise the pre-revision structure is kept. |

## Obligation-aware synthesis

`AnalysisControls.validation_retries` (`obligation_aware/contracts.py`) is
an integer from 0 to 1 and defaults to 1. The pipeline leaves it at the
default.

| Re-ask | Where | Trigger | Sends | Max | If it fails too |
| --- | --- | --- | --- | --- | --- |
| Obligation routing | `obligation_aware/routing.py` `_route_batch`. The provider call uses `validation_retries=0`. | A decode or schema failure of the reply, a batch-identity mismatch, a route whose pattern binding, assessment or references fail, or a route rejected after mechanism verification. A provider or transport failure, and a prompt that preflight refuses as over budget, are not re-asked. | The whole batch again: the original prompt with a `Validation correction:` section that carries the repair text and the error | `validation_retries` per batch | Invalid routes stay `unresolved`. A second reply that is also partial is merged route by route (`_merge_partial`): a route valid in the second reply replaces the first reply's; otherwise a route the first reply validated is kept; otherwise the obligation is `unresolved`. An invalid route never displaces a valid one. |
| Mechanism verification | `obligation_aware/provider.py` `_ask_mechanism_verifier` | A schema failure, or a reply that misses or duplicates an item handle | The original prompt, then the feedback and the error | 1 per verifier call. It runs inside each routing attempt. | No route gets mechanism credit. The failure is not cached, so the next routing attempt asks again. |
| Mechanism-suggestion verification | `obligation_aware/mechanism_suggestion_provider.py` `_verify_batch` | Same as mechanism verification | Same as mechanism verification | 1 per batch | Every candidate in the batch is `INCOMPLETE_VERIFICATION`. |
| Governance routing | `obligation_aware/governance_routing.py` `_run_batch`. The provider call uses `validation_retries=0`. | A decode or schema failure of the reply, a batch-identity or risk-set mismatch, or a placement that names a target outside the index. A provider or transport failure, or a prompt that is over budget, stops the loop. | The whole batch again, with feedback that names each invalid placement | `validation_retries` per batch | The accepted placements are kept. Each invalid risk stays `unresolved`. |
| Structural revision | `provider.py` `revise` | A schema failure | The original prompt, then the feedback and the error | `validation_retries` per request | The baseline structure is kept. |
| ICA slot filling | `provider.py` `fill` | A schema failure or a slot-rule failure | The original prompt, then the feedback, the prior reply and the error | `validation_retries` per target | The slot is unresolved. |
| Context-coverage supplement | `provider.py` `_supplement_context_coverage` | A schema failure or a supplement-rule failure. The supplement is a follow-up request about source contexts the slot reply left unanalyzed; it is not itself a re-ask. | The original prompt, then the feedback and the error | `validation_retries` per target that has gaps | The validated slot payload is kept. |
| ICA hazard verification | `provider.py` `verify_ica_hazards` | A schema failure, or a hazardous absence whose losses or consequence are missing | The original prompt and the error | 1 per verification call | An absence that is still unproven is downgraded. On a schema failure, every ICA in the group is a `provider_failure`. |
| Unchanged ICA correction | `obligation_aware/ica_verification.py` `_prepare_one_correction` | A correction left the ICA request content unchanged | The correction prompt again, with a block saying the first answer changed nothing | 1 per ICA | The ICA is kept unsupported, with its first verdict. |

Two follow-ups are planned and are not re-asks. An ICA the first verdict does
not support gets one correction request. When that correction revises the
ICA, it is verified once more, under the step `correction`; that call can
make its own verification re-ask. The second verification is built as the
first was, from the corrected ICA alone: the first verdict is not sent.

## Stage 5 and scenario production

| Re-ask | Where | Trigger | Sends | Max | If it fails too |
| --- | --- | --- | --- | --- | --- |
| BDI correction | `scenario_prod/stage5/generate.py` `_call_bdi_with_bounded_length_retry` | A schema, parser or validator failure. A reply that does not decode gets no correction. | The original prompt, then the repair codes, the error and the prior reply | 1 | It goes to the concise retry or the condition correction below, or the scenario fails. |
| Concise retry | `generate.py` `_call_bdi_with_bounded_length_retry` | The original reply or its correction stopped at the completion cap | The original prompt, plus an instruction to return only a concise reply. It requests a 2,048-token cap. When the profile sets `reasoning_effort`, the client raises that cap to the profile's `max_completion_tokens` if that is larger (`model_profiles.py` `reasoning_completion_cap`). The retry can earn its own correction. | 1, plus its correction | The scenario fails. If the first stop at the cap returned no content, the remaining Stage 5 candidates are also skipped. |
| Condition correction | `generate.py` and `stage5/condition_retry.py` `earns_second_correction` | After the first correction, the discriminating condition still fails, and the draft without it would be `analytical_only` or `failure_call`. It never follows a concise retry. | The original prompt, then the feedback, the error and the second reply | 1 | A condition-less draft is published if code can recover one. Otherwise the scenario fails. |
| Attack shape | `stage5/shape_step.py` | A schema or rule failure | The original prompt, then the feedback, the error and the prior reply | 1 | The rejected shape is used, or the default shape. |
| Belief | `stage5/belief_step.py` | A schema or belief failure, or a reply that does not decode | The original prompt, then the feedback, the error and the prior reply | 1 | No beliefs are applied. |
| Gherkin | `scenario_prod/model_gherkin.py` | A schema or check failure | The original prompt, then the feedback, the error and the prior reply | 1 | The fallback Gherkin is used. |
| Narration | `scenario_prod/narration.py` | A schema or check failure | The original prompt, then the feedback, the error and the prior reply | 1 | The narration that does not come from the model is kept. |

The BDI call for one scenario makes at most 4 attempts, not counting the
client's re-asks. The worst case is a reply, a correction that stops at the
cap, the concise retry, and the retry's correction.

## Target realization

| Re-ask | Where | Trigger | Sends | Max | If it fails too |
| --- | --- | --- | --- | --- | --- |
| Inventory correction | `target_realization/provider.py` `_map_action` | The mapping picks an operation that was not offered | The original prompt, then the inventory feedback, the error and the prior reply | 1 per control action | The step fails. |
| Extension correction | `provider.py` `extend` | A schema, parser or validator failure | The original prompt, then the feedback, the error and the prior reply | 1 | The valid outcomes are salvaged from the last reply. |
| Duplicate-reference correction | `provider.py` `_correct_repeated_references` | The target-derived ICA draft repeats references | The original prompt, then the feedback, the list of repeats and the prior reply | 1 per request | It is recorded as a provider failure, and the run continues. |
| Omitted-findings verification | `provider.py` `_decisions` | The first verifier reply failed decoding or its schema, or it left findings without a decision. A provider or transport failure gets no retry. | A fresh verifier prompt that covers only those findings | 1 per request | Those findings stay unverified. |

## Calls that make no re-ask

- Stated-rule extraction and mapping.
- Each Stage 1a repair request.
- The routing and governance provider calls, whose re-ask belongs to their
  caller.
- The ICA hazard correction call.
- The target-mapping verifier and the extension verifier.
- Target discovery: the interpreter and its verifier.

Some calls follow a step by design and are not re-asks:

- The first density revision round.
- The stated-rule revision, and the stated-rule re-mapping after it.
- The critic revision request.
- The routing recheck that runs after an applied revision.
- The extra Stage 1b draws, which vote.
