# Adaptive redesign revision record

This is the append-only revision record for the adaptive scenario/artifact ownership
redesign. It records the commits made on this branch after the starting pins. Never
rewrite the starting pins in `build/adaptive-redesign-inputs/manifest.json`; add a new
entry here instead.

`python3 build/adaptive-redesign-inputs/verify.py` asserts `HEAD` equals the starting
commits and requires clean tracked trees. After the first implementation commit those
two checks fail by design. The file-hash, plan-hash and configuration-reference checks
must keep passing at all times. A failure of any of those is a real pin violation.

## Starting pins (immutable, from `build/adaptive-redesign-inputs/manifest.json`)

| Repo | Path | Branch | Starting commit |
| --- | --- | --- | --- |
| Producer | `<WT>/asago-scenario-generator` | `codex/adaptive-scenario-artifact-split` | `2f8cc37512e00166ee554b96d1a85b67d37545f4` (`2f8cc37`) |
| Consumer | `<WT>/asago-artifact-generator` | `codex/adaptive-scenario-artifact-split` | `7c1d0e1e34abcb5e81a3b13236040487f4b65dbf` (`7c1d0e1`) |
| mini-agents | `/Users/hjrnunes/workspace/hjrnunes/mini-agents` | runtime only | `f825a03930b51985b4bc77c1da1b746868e7778d` (`f825a03`) |
| Garak (pinned runtime) | `<WT>/.mission-runtime/garak-pinned` | detached | `06aba1a2c9b142d561eeeff08dfaffcbe77487c3` |

`<WT>` = `/Users/hjrnunes/workspace/redhat/hjrnunes/asago-scenario-generator/.worktrees/adaptive-scenario-artifact-split`.

Plan pin: `docs/development/designs/adaptive-scenarios-artifact-ownership-plan-2026-09-14.md`,
sha256 `ae4b1f34b99838c562514b98b7174d8732c041e674fbe4cbb61c50151468de4a`.

## Entry format

Append one entry per work commit, newest last. Keep every prior entry unchanged.

```
### R<n> — <YYYY-MM-DD> — <repo> — <commit>

- Commit: `<full-or-12-char sha>` — `<subject>`
- What changed: <files/areas>
- Why: <reason>
- verify.py: <file-hash/plan/symlink result>; HEAD/clean-tree checks expected to fail by design.
```

## Revisions

### R1 — 2026-09-14 — producer — a4c509b

- Commit: `a4c509b2685c34319b03ae753a1e2206a696bbf4` — `docs(adaptive-redesign): add SCN-007 handoff design fixture and M1 slice documents`
- What changed: added the M1 minimal-handoff slice:
  - `docs/development/adaptive-redesign/scn-007-design-fixture.yaml` — the hand-edited
    SCN-007 design fixture.
  - `docs/development/adaptive-redesign/scn-007-field-ownership.md` — field-ownership
    mapping.
  - `docs/development/adaptive-redesign/scn-007-consumer-interpretation.md` — consumer
    interpretation plus unknowns and limits.
  - `docs/development/adaptive-handoff-slice.md` — the M1 handoff note resolving the
    delivered paths.
  - `tests/test_adaptive_handoff_slice_fixture.py` — ownership-boundary checks.
  This entry was appended by the follow-up commit that records it; the entry itself
  documents commit `a4c509b`.
- Why: settle the producer-to-consumer handoff interface for the excessive-refund slice
  before the first live end-to-end run (M2). The fixture is hand-edited development
  material, not fresh generation and not benchmark recovery.
- verify.py: file-hash, plan-hash and configuration-reference checks pass; the
  `HEAD == starting commits` check now fails by design because HEAD moved past the
  starting pins, and the producer clean-tracked-tree check passes at the branch head.
  Starting pins were not rewritten. The consumer worktree state is outside this
  producer revision.

### R2 — 2026-09-14 — producer — 6b0e4e5

- Commit: `6b0e4e5881fcb5b7b33aa919933d8831064d2aab` — `feat(adaptive-redesign): add M1 run recipe, script and budget registration`
- What changed: added the M1 reproducible run recipe and budget registration:
  - `docs/development/adaptive-redesign/run-recipe.md` — startup (the working
    `OPENAI_BASE_URL` exported from the producer `gemma4-oc` profile, without editing
    `mini-agents/.env`), reset (= restart), seeded-state verification via
    `.mission-runtime/check_state.py`, teardown, and the five M2 evidence locations.
  - `docs/development/adaptive-redesign/budget-registration.md` — the five stage
    estimates as planning estimates with no hard endpoint cap (owner decision
    2026-09-14) and the four discipline rules.
  - `scripts/qualification/run_recipe.py` — maintained script implementing
    `start`/`reset`/`verify`/`dirty`/`status`/`stop`.
  - `tests/test_run_recipe.py` — offline checks for the documented ports, profile
    reader, seed comparison, port polling, and the delivered document paths.
  - `docs/development/adaptive-handoff-slice.md` — the two recipe/budget placeholder
    rows now name the delivered paths; the other rows are unchanged.
  This entry was appended by the follow-up commit that records it; the entry itself
  documents commit `6b0e4e5`.
- Live verification (2026-09-14): `run_recipe.py reset` stopped the running stack and
  restarted it with the endpoint exported; ports 8888–8893 and 8321 listened; the
  seeded summary showed ORD-101 remaining 40.0 refund-eligible, ORD-104 remaining 80.0
  ineligible, refunds empty. `run_recipe.py dirty --domain klarna` completed a 5.0
  refund (ORD-101 remaining 35.0, one refund present); the following `reset` restored
  ORD-101 remaining 40.0 and an empty refunds list. The recipe's verbatim shell startup
  step reproduced the same listeners and seed, and OGX on 8321 listed
  `gemma-4-26b-a4b-it`. `mini-agents/.env` sha256 and `git -C mini-agents status
  --short` were unchanged across the run (no mini-agents source edits).
- Why: the M1 handoff slice needs a reproducible, live-verified target-stack recipe and
  registered budgets before the M2 execution.
- verify.py: file-hash, plan-hash and configuration-reference checks pass; the
  `HEAD == starting commits` check fails by design. Starting pins were not rewritten.

### R3 — 2026-09-14 — producer — 54210b2

- Commit: `54210b2a6671b6997fd04b952525034249c31055` — `fix(typing): support dynamic unions on Python 3.14`
- What changed: replaced direct `typing.Union.__getitem__` descriptor calls with
  supported dynamic `Union[...]` subscriptions in the Stage 5 and obligation-routing
  response-schema builders.
- Why: the M1 scrutiny validator ran under the mission's Python 3.14.3 environment and
  exposed 104 cascading test failures because Python 3.14 no longer accepts the direct
  descriptor calls. The compatibility update restores the response-schema builders
  without changing their union members or discriminators.
- Validation: `uv run pytest tests/ -q` reports 7,730 passed and 1 skipped;
  `./scripts/quality.sh` reports clean Ruff and format checks plus 133 passing gold
  tests.
- verify.py: starting pins were not rewritten. The `HEAD == starting commits` check
  fails by design after implementation commits.

