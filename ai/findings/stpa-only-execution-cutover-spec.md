# STPA-Only Execution Cutover Specification

Status: approved direction; implementation specification  
Date: 2026-09-02

## 1. Decision

STPA is the sole authority for generating adversarial scenarios in this
project.

The normal product workflow is the obligation-aware STPA synthesis workflow:

1. load the use case and reviewed risks;
2. derive and retain taxonomy obligations;
3. run the baseline STPA analysis;
4. make STPA consider every obligation;
5. permit at most one bounded additive structural revision;
6. complete STPA ICA and scenario production;
7. account for every obligation and scenario realization; and
8. run non-blocking Phase 2 verification.

The former taxonomy-led scenario generator is retired. Taxonomy remains an
essential evidence and coverage input, but it no longer authors scenarios.

## 2. Public product surface

### 2.1 Canonical command

The sole normal scenario-generation command is:

```text
asago-scenario-generator run
```

`run` exposes the current obligation-aware synthesis inputs and behavior. It
replaces the `synthesis-run` name; there is no second alias for the same
product workflow.

### 2.2 Advanced diagnostic command

`asago-scenario-generator stpa-run` remains temporarily available as an
advanced diagnostic command. It runs baseline STPA without taxonomy
obligation completeness and must identify that limitation in its help and
runtime output.

It exists to:

- isolate defects in SP1, SP2, or SP3;
- qualify STPA prompts and model profiles;
- compare baseline STPA with obligation-aware STPA; and
- support focused development and tests.

It is not the normal product workflow. No user-facing documentation may
present it as equivalent to `run`.

### 2.3 Retired commands

The following legacy execution commands are removed immediately:

- `generate`;
- `resume` for legacy generated runs;
- `synthesis-run` (renamed to `run`);
- legacy `report` and `eval` commands that consume non-STPA run artifacts.

Invoking a removed command must fail as an unknown command. It must not run a
compatibility shim, print a deprecation warning and continue, or silently
redirect to STPA.

The standalone `profile` preparation command may remain only if it is moved
out of the legacy generation command module and does not expose or invoke the
retired runner.

## 3. Domain responsibilities

### 3.1 Taxonomy

Taxonomy owns systematic discovery, reviewed risk-to-pattern provenance,
qualification, obligation formation, and coverage accounting inputs.

Taxonomy does not own scenario narratives, attack trees, behavioral
specifications, or scenario admission.

### 3.2 STPA

STPA owns losses, hazards, constraints, control structure, unsafe control
actions, causal analysis, and all generated scenarios.

An obligation asks STPA to consider a concern. It does not prescribe an attack
sequence and does not force STPA to produce a scenario.

### 3.3 Synthesis

The synthesis module is the only product composition root. Its public
interface hides taxonomy planning, STPA orchestration, obligation
consideration, bounded revision, scenario realization, accounting, and Phase
2 verification behind one run operation.

### 3.4 Phase 2

Phase 2 remains offline verification after scenario generation. It may confirm
or leave unresolved taxonomy-to-STPA correspondence. It never generates,
deletes, or admits a scenario.

## 4. Source-code cutover

The cutover has two deletion classes and both belong to this change series.

### 4.1 Remove now

- CLI registration and implementation for `generate` and legacy `resume`;
- CLI registration for legacy `report` and `eval`;
- public documentation, examples, features, and QA that advertise the retired
  commands as supported product workflows;
- compatibility assertions whose purpose is to keep `generate` unchanged;
- public package exports whose only purpose is invoking the retired runner.

### 4.2 Delete after reachability proof

Delete the legacy runner, generation stages, reports, evaluation adapters,
models, prompts, fixtures, and tests when static imports and the focused suite
show they are used only by the retired workflow.

If synthesis or STPA still imports a useful primitive from the old
`pipeline.generate` package, move that primitive to a neutral inward module
first. Do not keep the legacy workflow alive merely to reuse a helper.

Code retained temporarily under this rule is internal cleanup inventory, not
a supported execution interface. The repository documentation must say so,
and a follow-up deletion inventory must name every retained root.

## 5. Artifacts and compatibility

- `run` preserves the current synthesis artifact set and semantic identities.
- Existing synthesis output directories remain resumable through `run
  --resume` when their pins are intact.
- Legacy non-STPA output directories are read-only historical data. The
  project does not resume, extend, or regenerate them.
- No legacy scenario is converted into an STPA scenario by relabeling fields.
- Offline readers needed for an explicit migration or audit may remain, but
  they must not recreate the retired generation path.

## 6. Acceptance criteria

### Public interface

1. Root help presents `run` as the normal scenario-generation workflow.
2. Root help presents `stpa-run` as advanced/diagnostic.
3. Root help does not expose `generate`, legacy `resume`, `synthesis-run`,
   legacy `report`, or legacy `eval`.
4. Each removed command fails as an unknown command without model or network
   activity.
5. `run --help` exposes the exact former synthesis input contract.

### Behavior

6. `run` executes taxonomy planning before baseline STPA.
7. Every taxonomy obligation is considered and accounted for.
8. Only STPA scenario production emits scenarios.
9. Phase 2 verification runs last and remains non-blocking.
10. `run --resume` resumes only an intact synthesis Phase 1 checkpoint.
11. `stpa-run` continues to run baseline STPA and clearly reports that it omits
    taxonomy obligation completeness.

### Architecture

12. Synthesis and STPA do not import the retired legacy runner.
13. Taxonomy planning does not import either generation workflow.
14. No new code imports from a legacy generation namespace.
15. A checked deletion inventory records any temporarily retained legacy roots
    and why they cannot yet be removed.

### Quality

16. Deterministic unit and generated acceptance tests pass.
17. CLI tests prove the removed commands are absent, rather than maintaining
    their old compatibility.
18. Documentation and domain language describe one product workflow.
19. Live-model qualification is not required for the command cutover because
    the underlying synthesis behavior is unchanged.

## 7. Implementation sequence

1. Register synthesis as `run` and update its language from provisional
   synthesis to the normal product workflow.
2. Remove legacy command-module registrations; split out any retained
   preparation-only commands.
3. Mark `stpa-run` as advanced and print its limitation before execution.
4. Replace peer-workflow compatibility acceptance with STPA-only product
   surface acceptance.
5. Update CLI unit tests, README, architecture documentation, and domain
   glossary.
6. Run a static reachability audit and write the retained/deleted legacy code
   inventory.
7. Delete exclusive legacy implementation and tests in bounded slices,
   rerunning deterministic gates after each slice.

## 8. Non-goals

- changing the STPA methodology or prompts;
- changing synthesis scenario counts or semantic admission;
- making an obligation force STPA to create a scenario;
- treating Phase 2 as scenario generation;
- preserving command compatibility for pre-alpha non-STPA runs; or
- running a lengthy mutation-hardening campaign during the cutover.

## 9. Completion condition

The cutover is complete when a user can generate scenarios only through
`run` or the explicitly advanced baseline `stpa-run`, all product scenarios
come from STPA, the retired command names are absent, and every remaining
legacy implementation root is either deleted or named in the checked cleanup
inventory with a concrete dependency reason.
