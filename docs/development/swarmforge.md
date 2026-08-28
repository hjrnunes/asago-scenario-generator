# SwarmForge development methodology

This repository uses the harness-independent SwarmForge methodology. The
method is normative; any particular agent harness, role installation, or
handoff runtime is replaceable and remains untracked.

## Work contract

GitHub Issues are the durable source of work and decisions. An approved issue
is the approved specification unless an implementation-relevant ambiguity is
discovered. Branches and pull requests carry the implementation, evidence, and
review discussion.

A work item is ready when its behavior, constraints, exclusions, and observable
acceptance criteria are clear. If they are not clear, resolve them in the issue
before implementation.

## The six-pack

The six roles are a sequence of responsibilities, not a requirement for six
processes or a specific harness:

1. **Specifier** — sharpen the issue into observable behavior and acceptance
   examples; identify ambiguity rather than inventing product decisions.
2. **Coder** — work test-first in vertical slices and implement the smallest
   behavior that satisfies each accepted example.
3. **Cleaner** — simplify names, boundaries, duplication, and coupling without
   changing accepted behavior.
4. **Architect** — review the slice for contract coherence, module boundaries,
   dependency direction, and durable documentation.
5. **Hardener** — exercise error paths, properties, mutation resistance, and
   adversarial inputs; make failures explicit and diagnosable.
6. **QA** — run independent deterministic and acceptance gates, verify the
   issue contract, and report reproducible evidence.

Scaffolding a new language or acceptance runtime is bootstrap work outside the
six-pack. Once the project commands exist, every feature follows the six
responsibilities even when one contributor performs several roles.

## Acceptance pipeline

Gherkin in `features/` is committed source. The normal pipeline is:

```text
feature -> APS JSON IR -> IR DRY report -> generated pytest entrypoint
        -> committed acceptance runtime/handler -> project behavior
```

Run generation and generated tests sequentially with
`./scripts/acceptance.sh`. Generated artifacts under `build/acceptance/` and
mutation workspaces are disposable. Step handlers should use regular-expression
captures for repeated shapes and separate literal handlers only for genuinely
different behavior.

Live-model scenarios require `ASAGO_SCENARIO_GENERATOR_QA_PIPELINE=1`.
Everything else must run without a reachable LLM endpoint.

## Quality sequence

The normal merge evidence is:

```bash
./scripts/quality.sh
./scripts/acceptance.sh
uv run pytest tests/ -q
```

Generate acceptance artifacts before the unit suite in a fresh checkout.
Several migration-contract tests deliberately execute the generated acceptance
entrypoints and fail when `build/acceptance/` has not been reconstructed yet.

Changed production code should also be evaluated with the configured coverage,
CRAP, DRY, source mutation, and Gherkin mutation commands where relevant. The
canonical differential mutation invocation is `scripts/differential-mutation.sh
<src>` with per-source test contexts in `config/mutation-test-contexts.tsv`.
The project target is CRAP at or below 6 and mutation score at or above 80.
Tool scope remains `src/`; Ruff also checks `acceptance/`.

Mutation tooling details:

- The mutation tool is the project fork `hjrnunes/mutate4py` (pinned in
  `config/swarmforge.env`); the fork carries a worker-copy patch that
  honors `[tool.uv.workspace].exclude` when materializing per-worker tree
  copies, so the bulky directories excluded in `pyproject.toml`
  (`output/`, `tmp/`, `.worktrees/`, ...) stay out of every worker.
  `build` must remain absent from that exclude list: migration-contract
  tests execute the generated acceptance entrypoints inside workers.
- Manifests live in gitignored sidecar files (`<file>.manifest.json`,
  written with `--manifest-file`), so mutation runs never dirty tracked
  sources. The sidecars inherit the differential state of the embedded
  manifests they replaced.
- `scripts/differential-mutation.sh` also builds a per-source test-context
  coverage db (`--build-test-contexts`, cached by the tool) so each mutant
  runs only the tests that cover its line. Set `ASAGO_MUTATION_CONTEXT_DB=0`
  to skip narrowing and select from the LCOV file alone. With narrowing
  on, the tool hard-errors when a selected line is LCOV-covered but absent
  from the db: the context list in `config/mutation-test-contexts.tsv`
  is missing a test that covers that line — extend the list or run without
  narrowing.
- Stale `mutate4py` worker trees under `.mutate4py/workers/` are pruned to
  the two most recent runs by `scripts/differential-mutation.sh`; the tool
  itself removes a completed run's trees.
- The Gherkin mutation runner adapter
  (`acceptance/gherkin_mutation_runner.py`) gives every runner process a
  private scratch tree, so parallel `gherkin-mutator` workers never splice
  the shared snapshot IR under `build/acceptance/ir/`.
- The heavy clean-checkout QA suite runs its two orderings concurrently and
  `acceptance/qa/run_suites.py` overlaps the clean-checkout suite with the
  pool suites by default (`--serial-first` restores sequential scheduling).

## External tools and pins

`config/swarmforge.env` records repository URLs, exact revisions, commands, and
paths. It does not install anything. A developer or CI job explicitly checks
out or installs those revisions after granting the required network and
installation permissions.

The APS checkout is discovered through
`ASAGO_SCENARIO_GENERATOR_APS_ROOT`, then through the ignored local paths
`.cache/acceptance-pipeline-specification/` and
`tmp/Acceptance-Pipeline-Specification/`. Invalid explicit configuration fails
immediately; the project never silently downloads a replacement.

Update a pin in a dedicated pull request that records upstream changes and runs
the affected quality gate. Harness-specific role prompts, handoff files,
dashboards, Beads state, and local tool clones are not repository content.

## Local orchestrator

The local installation uses the fork `hjrnunes/swarm-forge` (pinned in
`config/swarmforge.env`) with the six-pack order above and the commands in
`config/swarmforge.env`:

- Shared launcher scripts come from the fork's `main` branch and live under
  ignored `swarmforge/scripts/`; the fork carries all of the project's
  local changes (project agent backend, env-gated auto-approve, project-name
  dashboard title, and APS worktree provisioning). The `./swarm` wrapper
  archives the local fork checkout first and falls back to the fork's GitHub
  tarball. No post-fetch patch step exists: the retired patch script was
  deleted because re-applying its unconditional auto-approve shadow over
  the fork's env-gated `should-hold?` would silently override
  `SWARMFORGE_AUTO_APPROVE`. The wrapper exports
  `SWARMFORGE_AUTO_APPROVE=true` by default; set it to false before launching
  to restore the specifier approval gate.
- The `six-pack` configuration lives under ignored `swarmforge/`:
  `swarmforge/swarmforge.conf` runs all six roles on the project's configured
  agent backend in invisible tmux windows (`window-invisible`), and role
  prompts are the auto-approve-adapted six-pack prompts under
  `swarmforge/roles/`.
- Model selection is harness-local: each role prompt has a sibling
  `roles/<role>.settings.json` passed to the agent CLI with `--settings`,
  e.g. specifier/QA on `grok-4.6`, coder on `deepseek-v4-flash-0731`,
  architect on `deepseek-v4-pro`, cleaner/hardender on `gpt-5.6-luna`, with
  matching reasoning effort. These files are ignored, not repository content;
  the reference copies live in `intendente` (`swarmforge/roles/`).
- Runtime stays under `.swarmforge/`, role worktrees under `.worktrees/`.
  Launch from a feature branch with `./swarm`; stop with `./close-swarm` or
  by closing its first terminal window. Handoffs are auto-approved and
  delivered via `ready_for_next.sh` / `done_with_current.sh`.
  `done_with_current_batch.sh` verifies that every item of a multi-item batch
  got exactly one sent `git_handoff` (terminal-role batches and QA-origin
  items exempt) and refuses to complete the batch otherwise; `pack_board.sh`
  suggests the closest board card names when a handoff names an unknown task;
  `swarm_handoff.sh` preserves the drafted task name in multi-item batches
  (it only auto-fills a blank name or corrects drift on single-item batches).

The scaffolder is intentionally absent because the portable acceptance
pipeline is already committed. The project uses ordinary commit messages
without agent-role bylines.

## Completion

A pull request is complete when the issue contract is satisfied, deterministic
gates pass without an endpoint, opt-in behavior is clearly separated, generated
or harness state is absent from the diff, and documentation reflects changed
interfaces. Organization administrators own branch-protection configuration.
