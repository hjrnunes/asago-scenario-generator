# Tracks 1 and 3 integration review (2026-09-14)

Tracks 1 and 3 are integrated into the main producer/consumer checkouts.
All verification in this integration was offline: zero provider requests,
zero target executions, no generation reruns, no benchmark amendments.
Track 2 remains a separate design proposal, not approved or implemented here.

## Integrated revisions

Producer base `07c6ed1`; Track 1 `0c588e7`, `64d9457`, `34febb4`
cherry-picked as `ddb6a84`, `063436d`, `8ca71fc`; Track 3 `f54bab9`
cherry-picked as `ed9c57a`. Consumer base `fdd13c7` fast-forwarded to
`c466ba1`; consumer review corrections committed as `7c1d0e1`.
The producer integration-correction commit containing this report closes
its remaining findings. No changes were pushed.

## Standards review

- **Fixed:** a valid bundle yielding only unbound/excluded entries was
  reported as passing. The driver now requires every entry to compile and
  validate; zero compilation is blocked, partial compilation is partial,
  and both prevent overall success. Ten driver regression tests cover the
  aggregation seam. An actual consumer replay of the omission fixture with
  only its optional profile removed now returns blocked, exit 1.
- **Fixed:** the consumer fixture test guard now rejects `connect_ex` as
  well as ordinary connection paths, with direct guard tests.
- **Fixed:** fixture provenance distinguishes bundle-internal validation
  from documentary source hashes. Missing bundles no longer imply that
  every candidate was functional; their absence is recorded neutrally.
- **Fixed:** eight tracked-ignored reports were moved into durable tracked
  documentation. Seven boundary reports are byte-identical archive copies;
  the context report is explicitly corrected. All eight ignored originals
  still match their original committed bytes. No ignore rule or snapshot
  test was weakened. The original snapshot failure now passes.
- **Qualified:** the initial empty-container finding was too broad.
  Production `{}` and `[]` reads already have root-value handles. Added
  tests establish that behavior, and the renderer now also retains source
  metadata independently when a context has no content handles. This is
  defensive interface behavior, not a newly measured model improvement.
- String-keyed consumer interface plumbing and duplicated test helpers were
  noted as maintainability suggestions, not blockers; no unrelated module
  redesign was included.

## Spec and evidence review

Track 1 restores captured invocation metadata alongside unchanged evidence
handles. Source context is not promoted to policy authority. No response
schema, admission contract, reviewed graph, or detector changed. The final
current-user template SHA-256 is
`3e0269752aa2198a5898990cff624f6c261571e99766fe9ef880ab2b2fc553cd`.

The experiment did not establish improved usable breadth. Its preserved
packet lacks full evidence for the claimed blind semantic review, and the
family table includes inconsistent drafts. The maintained
[context report](read-observation-context-comparison-2026-09-14.md) withdraws
"no measured harm", "no defect increase", usable-family certainty, and broad
gold correspondence. It records additional raw-response conflicts without
inventing an exhaustive retrospective score. Original evidence, family
counts, twelve-call usage, and historical qualification scores are unchanged.

Track 3 exercises the real public consumer chain. Both real saved bundles
passed: Klarna 9/9, OcciAI 4/4. All four portable fixtures also passed, one
entry each. The ordering check preserves both tools, shared predicate,
direction, and null proposition. Structured omission and prepared user
history pass through kit-derived fixtures; those checks are not claimed as
coverage from a real published omission/history bundle. Airbnb still has no
bundle to exercise. These are compile/delivery checks, not target safety.

## Validation

- Producer quality gate: passed; 133 gold-tooling tests.
- Producer generated acceptance: 139 passed.
- Producer full suite: 7,700 passed, 1 skipped; no deselections added.
- Producer replay and smoke-driver suites: 28 passed.
- Authoring/observation focused suites: 43 passed.
- Snapshot plus replay/smoke focused checks: 43 passed.
- Consumer quality gate: passed; full suite 513 passed, 2 subtests passed.
- Explicit lint/format checks for changed qualification tools/tests: passed.
- Both repositories' diff checks passed; tracked-ignored inventory is empty.

The full-suite and focused counts overlap and must not be added together.
Local integration evidence is in
`build/qualification/track-integration-20260914/`: `crossrepo-smoke.json`
(six targets passed) and `missing-profile-smoke.json` (expected blocked).
No sealed run files or accepted inputs were modified.

## Track 2 handoff

The incoming result-observation proposal at `7c077dc` was reviewed separately.
[Required design corrections](track2-result-observation-review-2026-09-14.md)
cover contradictory obligation-authority rules, absent-field profile digest
compatibility, incomplete-result versus safe-refusal semantics, implementable
review boundaries, and per-invocation runtime evidence. Its ignored proposal
and prototype remain in the separate worktree. No profile-v1 amendment or
result-observer implementation is included in this integration.
