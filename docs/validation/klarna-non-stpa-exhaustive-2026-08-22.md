# Klarna non-STPA exhaustive validation — 2026-08-22

This record captures the first exhaustive taxonomy/risk run after enabling
compact xgrammar structured output on the Gemma 4 serving runtime.

## Command

The run used local, ignored capability-profile, qualification-fact, endpoint,
and credential configuration:

```bash
uv run --offline asago-scenario-generator generate \
  --use-case @tmp/use-case-klarna-fs-isac-v36.txt \
  --risk-extraction tmp/risk-extraction-fs-isac.json \
  --sssom ../asago-policy-mapper/src/asago_policy_mapper/data/risk_to_category.sssom.tsv \
  --output-dir output/runs/klarna-non-stpa-post-xgrammar-exhaustive-01 \
  --profile tmp/migration-validation/non-stpa-capability-profile.yaml \
  --qualification-facts tmp/migration-validation/klarna-qualification-facts.yaml \
  --model-profile gemma4-oc-taxonomy \
  --generation-mode exhaustive \
  --max-scenario-techniques 2
```

Run ID:
`20260822T172829_466235acac6f9d1d38f10e7ccb60f854`

Source commit: `c1c2af1d90724d0916136d7febd9cfc304582c8d`

Raw output remains ignored under
`output/runs/klarna-non-stpa-post-xgrammar-exhaustive-01/`.

## Result

The run completed all 106 finalization targets in 1 hour, 10 minutes, and 6
seconds. It produced 9 admitted scenario YAML files and 9 corresponding
Gherkin feature files.

| Outcome | Count |
| --- | ---: |
| Admitted | 9 |
| Generation or finalization failed | 93 |
| Rejected by final admission gates | 4 |
| Total terminal decisions | 106 |

The manifest status was `completed_with_errors`, as expected when exhaustive
generation retains terminal failures rather than aborting the corpus.

The pipeline made 385 model calls. No call or stage attempt failed because of
the completion-length/whitespace condition. The preceding exhaustive run had
97 completion-length attempts and admitted only 2 scenarios; the serving
change therefore removed that failure class and increased admissions from 2
to 9 while reducing elapsed time from approximately 2 hours 6 minutes to 1
hour 10 minutes.

## Remaining admission losses

The 97 non-admitted terminal decisions break down as follows:

| Primary terminal violation | Count |
| --- | ---: |
| `projection_infeasible` | 53 |
| `semantic_draft_invalid` | 30 |
| `canonical_identity` | 10 |
| `semantic` | 4 |

Retries create more failed stage attempts than terminal decisions:

| Failed stage | Failed attempts |
| --- | ---: |
| Narrative | 65 |
| Attack tree | 53 |
| Actor | 2 |
| Behavior | 0 |

The dominant concrete signatures were:

- 26 tree projections could not map a `discover_data` external precondition
  to a canonical action.
- 17 generated tree topologies contained no canonical initial ingress.
- 32 narrative attempts combined `memory` and `reasoning` in causal beat 3.
- 20 narrative attempts combined incompatible zone or boundary alternatives in
  causal beat 2.
- 10 terminal canonical-identity failures mapped an ingress leaf to an action
  that did not activate the pinned ingress.
- 4 admission rejections referenced an ATLAS technique outside the candidate's
  pinned technique set.

The model-call distribution confirms the residual problem is semantic
alignment, not response size: actor responses used at most 310 completion
tokens, narratives 719, attack trees 299, and behavior specifications 689.

## Interpretation

The serving incident is resolved for this workload. Increasing token ceilings
will not improve the residual admission rate. The next work should target the
narrative and attack-tree contracts, especially where request-local semantic
choices are broader than the deterministic compiler's canonical realization
space.
