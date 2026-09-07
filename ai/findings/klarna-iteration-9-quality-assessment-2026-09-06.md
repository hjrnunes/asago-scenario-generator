# Klarna iteration 9: yield improved, claimed coverage remains unproven

## Evidence and counts

Run: `output/runs/20260906-klarna-gemma4-oc-semantic-quality-iteration-9`.
Artifact subdirectory: `artifacts-garak/synthesis-20260906T145514.985985Z`.
Source snapshot: `/tmp/asago-klarna-run9.gYA4Z1`.
Provider: the approved private `gemma4-oc` endpoint, model
`gemma-4-26b-a4b-it`. No adversarial target execution was performed.

The final synthesis manifest records 24 attempted candidates, 23 published,
one failed, none skipped: **95.8%**. This is better yield than iteration 7's
83/95 (87.4%), but the candidate universes differ substantially. It does not
establish better completeness. All 33 applicable obligations remain unresolved
in accounting; none receives realized-obligation credit.

The compilation manifest records four generated artifacts, three cases needing
semantic information, three needing runtime information, and 13 excluded.
There were four author calls. The four generated files have positive structural
validation receipts. Independent checks recomputed the source-byte hashes for
all 23 scenario/projection pairs and matched all four artifacts' source IDs,
scenario/projection hashes, projection semantic digests and bundle digest.

These are real integrity improvements, not proof of adequate test semantics.

## Every compiled artifact

| Case | What is traceable | What its evidence does not establish |
| --- | --- | --- |
| SCN-010 | Model-response case tied to CA-1-1 and SC-1/H-1/L-1 | The file has no backend tools or target context, but its requested information is described as backend-derived. The supplied request does not establish an unauthorized recipient. At most, output could show a model's willingness or invented financial text—not verified unauthorized disclosure. |
| SCN-014 | Model-response case tied to CA-4-1 and SC-1/H-1/L-1 | Its criterion treats unredacted financial text as sufficient. The use case permits contextual information from the authenticated customer's own records. Neither an unauthorized recipient nor excessive fields is established. The underlying installed filter is itself an unsupported baseline assumption. This can classify permitted behavior as a loss. |
| SCN-017 | A real observed `escalate_to_human` operation | The target lens maps the external handoff tool to the internal need-for-escalation signal as well as the external transfer action. Absence of that tool cannot establish failure of the internal signal specifically. The case's topic does not demonstrate the selected hazard about fees, refund eligibility or payment terms. |
| SCN-020 | External handoff matches CA-7-1; refund/payment ambiguity is relevant to the use case | The input asserts situational facts not independently present in the captured state. The observed refund rule and absent payment-policy result do not establish all asserted prerequisites. The saved judge correctly says that missing prerequisites or incomplete observations make the result inconclusive. |

Evidence for each row is its `executable-conversation.json`,
`execution-plan.json`, `artifact-trace.json`, and `validation.json` under the
artifact subdirectory. Source evidence is `loss-analysis.yaml`,
`control-structure.yaml`, `target-realization.yaml`, `target-observations.yaml`,
and the original `tmp/use-case-klarna-fs-isac-v36.txt`.

Synthetic request values are not inherently fabricated policy: a test input
can describe a hypothetical situation. The defect is promoting that description
to independently verified target state or to evidence that a conditional rule
actually applies. The assessment does not propose rewriting the saved inputs
or loosening admission checks.

Refund case SCN-023 remains excluded for a missing state-resource binding.
Payment case SCN-024 is not ready because a semantic comparison remains
unresolved. Mentioning refunds or payments in an escalation request is not
equivalent to producing refund-operation or payment-scheduling coverage.

## Root causes, not another compilation workaround

The baseline invents a confidence monitor and a separate installed filtering
layer, while representing financial execution through overlapping generic
actions. Those assumptions are not established by a requirement to escalate
ambiguous requests or protect customer information. The schema can preserve
their identities perfectly without making their meaning correct.

The critic identified missing feedback and authorization-state concepts. Its
revision returned an empty delta. Contrary to the initial review's wording,
the code already detects this no-change outcome and produces an unresolved-gap
warning. Synthesis did not carry that warning forward; a later stage replaced
the shared manifest. This is a diagnostic propagation defect.

The current-source correction preserves baseline assembly, heuristic,
solution-neutrality and post-revision warnings in the product result and
manifest, and shows them separately in the HTML report. It does not change
scenario eligibility, yield, provider calls or artifact content. Historical
iteration 9 files remain untouched.

The next defensible quality work is source-grounded system-model assessment,
explicit distinction between permitted and prohibited behavior, and ensuring
that test verdicts cannot promote asserted prerequisites into established
facts. More mechanically ready files would not resolve these issues.

## Verification and goal status

- Before the diagnostic correction: full generated acceptance 134 passed.
- Initial full unit run: 6,823 passed, one skipped, five failed. One failure
  was an architecture registration; four were stale positive SP1 fixtures.
- Architecture after correction: 105 passed. Worker affected fixture suite:
  187 passed. Parent independently reran all four failed fixture tests: passed.
- Parent synthesis/report and architecture checks: 126 passed.
- New reporting behavior: public red/green regression checks result, saved
  YAML, escaped HTML and unchanged scenario output. Generated synthesis
  acceptance passes all 15 scenarios.
- Fresh focused coverage: 21 synthesis tests passed; both new reporting
  helpers have CRAP 4 at full measured coverage. This is a bounded check,
  not a whole-module CRAP claim.
- Repository quality command and `git diff --check` pass. No mutation run,
  no final full-unit rerun claim, no commits.

**Zero fully qualifying runs.** Iteration 9 meets the numerical yield target,
but not four-family readiness or semantic coverage. The original goal remains
unachieved; compilation has not been substituted for success.
