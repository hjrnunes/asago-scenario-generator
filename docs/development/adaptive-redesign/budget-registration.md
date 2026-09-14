# M1 budget registration: adaptive redesign live-call estimates

This registers the live-call budget for the adaptive scenario/artifact redesign. The
figures are **planning estimates for scheduling and reporting, not enforced ceilings**.
Owner decision, 2026-09-14: there is **no hard endpoint cap** — the private endpoint is
exclusive to this work. The committed plan's finite-budget discipline applies unchanged.

## Stage estimates

| Stage | Estimate | Basis |
| --- | --- | --- |
| Producer generation runs | ~10 runs × ≤40 calls | minimal pinned-loss-analysis run ≈ 20–30 calls; historical v14 = 24; counts scale with (constraint, action) candidates |
| Consumer artifact designs | ~15 × ≤8 calls | one design per scenario/environment combination |
| Target-side Garak generations | ≤60 | includes retries and safe/unsafe diagnostics |
| Semantic judge calls | ~20 | only where a semantic judge is used |
| Smoke/health | ~10 | stack startup, seeded-state checks, endpoint smoke |

The estimates are planning figures. They gate scheduling and reporting only; they do not
stop an execution. Report the actual usage by stage at each milestone.

## Discipline rules

1. **Every attempt is preserved.** Never overwrite or delete an evidence directory;
   suffix reruns (`-attempt2`) and keep the failed attempts beside the successful ones.
2. **Safe server first.** Run against the safe servers (8888/8890/8892). Use the unsafe
   servers (8889/8891/8893) only for an explicit diagnostic question, and record the
   question.
3. **Never retry toward a preferred verdict.** A retry must answer a new diagnostic
   question. Stop repeated attempts that add no new diagnostic evidence, and reuse pinned
   intermediates to diagnose a later stage instead of rerunning earlier ones.
4. **Usage is reported by stage.** Every milestone report states the provider and target
   request counts by stage, alongside what actually ran.

## Reporting and records

- Record usage in the milestone report and in the mission's revision record
  (`docs/development/adaptive-redesign-revisions.md`).
- Record the exact invocations, revisions (producer/consumer/Garak commits), model
  controls, request counts by stage, and target/evidence paths with the run.
- The evidence locations for M2 execution outputs are defined in
  `docs/development/adaptive-redesign/run-recipe.md` (section 5).
