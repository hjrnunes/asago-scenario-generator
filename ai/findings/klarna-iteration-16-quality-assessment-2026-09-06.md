# Klarna iteration 16: repair normalization order

## Result

The fresh full run exited 1 during risk-derived loss analysis after **three
actual model calls** (capability, risk derivation, risk correction). No scenario
candidates were attempted, no scenarios were published, and no artifacts were
compiled. Publication percentage is not applicable. There are still **zero
qualifying consecutive full runs**.

Run: `output/runs/20260906-klarna-gemma4-oc-semantic-quality-iteration-16`.
Frozen producer: `/tmp/asago-klarna-run16.ynDQNY`.
Log: `/tmp/klarna-semantic-quality-iteration-16.log`.
The normal `run` command used `gemma4-oc` for all stages, the saved discovered
MiniKlarna profile and its matching target-observation capture. No target attack
or target-state refresh was performed.

## Actual prompt and response finding

The first risk response declares L-1 in `risk_card_losses` and L-2 in
`use_case_losses`, although L-2 explicitly has `provenance: risk_card`. It
declares only H-1, then SC-1 through SC-16, leaving H-2 through H-16 undeclared.
The bounded correction receives the rejected object, exact missing-reference
feedback, and explicit empty-retain/nonempty-replace collection semantics.

The corrected response declares six risk losses, six hazards and six constraints
with valid references. It places L-2 in the correct risk collection and slightly
revises its description; the use-case collection is empty. The current merger
patches raw containers before normalizing provenance. Consequently it retains
the old misplaced L-2 and reports a false conflict with the corrected L-2.

Independent replay confirms that **normalizing both drafts by their explicit
provenance before selecting replacement collections** yields the valid exact
correction: six risk losses, zero use-case losses, six hazards and six
constraints. No missing definition, reference or semantic equivalence is
invented. Conflicting duplicates within a response and conflicts against an
already accepted risk baseline must continue to reject.

This is another deterministic repair defect exposed by a malformed first
provider response, not an endpoint or approval failure. The earlier run-15
captured responses now pass the public derivation seam with three calls and
unchanged authoritative L-1/H-1/SC-1 records. The run-16 correction-order fix is
now implemented. A future successful replay is not a successful fresh generation
run.

## Full-seam replay exposed an overbroad semantic heuristic

The corrected graph passes the domain model, but full public-seam replay then
revealed another deterministic rejection. Exact H-6 says:

> The system provides unreliable or unverified responses for critical financial
> tasks, or experiences service failure due to upstream dependency issues.

The component-failure heuristic searched anywhere in the text and treated the
interior words “service failure” as proof that no system condition was stated.
Independent semantic review found that the primary clause explicitly states a
system-level outcome. The trailing cause belongs in the already-existing
nonblocking dependency-wording warning. The bounded correction anchors the
blocking component-failure check to the primary subject; direct claims such as
“The sensor fails” remain errors. No hazard text is rewritten to make a case
compile, and no existing domain-reference validation is relaxed.

The regression now includes the exact H-6 text. The earlier neutralized fixture
proved merge behavior but could not expose this semantic-check false positive;
actual captured-response replay is therefore required before the next run.
