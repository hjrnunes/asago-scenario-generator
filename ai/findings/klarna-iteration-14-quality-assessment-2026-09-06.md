# Klarna iteration 14 — early loss-analysis failure

Run: `output/runs/20260906-klarna-gemma4-oc-semantic-quality-iteration-14`.
Producer snapshot: `/tmp/asago-financial-json-citation.EKWcen`.
Log: `/tmp/klarna-semantic-quality-iteration-14.log`.
Private profile: `gemma4-oc`; same supplied synthetic observations and discovered
target profile as iteration 13. No target operations or adversarial execution.

## Exact result

The fresh run terminated with exit 1 before scenario candidates were attempted.
There are **four actual call records**, zero published scenarios and zero compiled
artifacts. The calls are capability derivation, risk derivation, gap analysis,
and its one correction. The two gap calls failed reference validation.

Both gap responses introduced `H-7` referring to `L-7` without defining that loss
in their returned loss collections. The correction repeated that reference.
The saved run manifest reports the exact unknown-loss error. Investigation must
check the supplied draft and delta protocol before attributing the defect solely
to the model; do not invent a loss or silently reassign the hazard to make it pass.

This run fails the no-fatal-error criterion and cannot count toward the goal.
**Consecutive qualifying fresh runs remain zero.** Publication percentage is
not applicable because no scenario candidates were attempted.

## Concurrent checks

The separate two-case financial diagnostic also failed after four calls because
all responses omitted their literal citations; see the iteration-13 assessment.
The full acceptance pass after the citation-boundary change reported 131 passed
and three failed features, which are under investigation/migration. Neither
partial green checks nor the previous run's 92% yield qualify this run.

The previous status-only turn was no progress; this turn produced a completed
fresh-run result, a completed financial diagnostic, and actionable failure
evidence. No external approval blocker was encountered.

## Deterministic follow-up

After migrating the stale acceptance fixtures to the citation protocol, the
full acceptance suite passes: **134 passed**
(`/tmp/asago-iteration14-acceptance.log`). The full unit run reports
**6,883 passed, 1 skipped** in 176.82 seconds
(`/tmp/asago-iteration13-final-unit.log`). `scripts/quality.sh` and
`git diff --check` pass. These checks do not erase either live failure above.

## Diagnosed corrections

- The risk response defined `L-1` through `L-6`; `L-7` was not dropped by code.
  The gap repair now names the exact loss collection/provenance for a genuinely
  new, source-grounded use-case loss, while allowing correction to an existing
  loss only when its meaning matches. It does not add a loss automatically.
  The saved-response regression verifies the correction protocol, not a promise
  that the model will obey it.
- Independent review ruled out a null-only provider schema: the exact dynamic
  schema offers either a complete `ComparisonEvidence` object or null, and the
  client forwards it unchanged. Repeated null citations are therefore not a
  transport prohibition. The planned simplification makes exact typed JSON
  source matching deterministic, removes citation-only provider retries, and
  keeps source presence distinct from the unverified policy interpretation.
  Explicit invalid citations and absent observed witnesses remain typed unknowns;
  schema defaults, bounds and examples cannot supply policy. Repeated exact
  occurrences across observations are retained as multiple presence witnesses,
  not treated as ambiguity merely because the earlier audit had one source field.
