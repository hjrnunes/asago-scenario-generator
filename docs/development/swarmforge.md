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

## The pipeline

The roles are a sequence of responsibilities, not a requirement for one
process per role or a specific harness. The pipeline starts at the coder:

1. **Coder** — read the approved issue text, then work test-first in vertical
   slices. Pin each behavior with a unit test under `tests/` and each required
   or forbidden prompt phrase with a row in `tests/phrases/*.yaml`, and see
   every new test or row fail before implementing the smallest change that
   passes it.
2. **Cleaner** — simplify names, boundaries, duplication, and coupling without
   changing tested behavior.
3. **Architect** — review the slice for contract coherence, module boundaries,
   dependency direction, and durable documentation.
4. **Hardener** — exercise error paths, properties, mutation resistance, and
   adversarial inputs; make failures explicit and diagnosable.
5. **QA** — run the independent deterministic gates, verify the issue
   contract, and report reproducible evidence.

The project has no specifier role and no Gherkin acceptance layer: the issue
text is the specification, and unit tests and phrase rows are its executable
form. Everything must run without a reachable LLM endpoint.

## Quality sequence

The normal merge evidence is:

```bash
./scripts/quality.sh
uv run pytest tests/ -q
```

Changed production code should also be evaluated with the configured coverage,
CRAP, DRY, and source mutation commands where relevant. The
canonical differential mutation invocation is `scripts/differential-mutation.sh
<src>` with per-source test contexts in `config/mutation-test-contexts.tsv`.
The project target is CRAP at or below 6 and mutation score at or above 80.
Tool scope remains `src/`; Ruff also checks `tests/`.

Mutation tooling details:

- The mutation tool is the project fork `hjrnunes/mutate4py` (pinned in
  `config/swarmforge.env`); the fork carries a worker-copy patch that
  honors `[tool.uv.workspace].exclude` when materializing per-worker tree
  copies, so the bulky directories excluded in `pyproject.toml`
  (`output/`, `tmp/`, `.worktrees/`, ...) stay out of every worker.
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
  narrowing. The context list is regenerated from per-test coverage
  contexts (`pytest tests/ --cov=asago_scenario_generator --cov-context=test`
  over the full unit suite, then decoding `.coverage`); every listed test
  covers at least one line of its source file.
- The script runs mutate4py through `uv run --no-cache --with <fork-source>`:
  uv caches wheels built for `file://` sources keyed by package name and
  version, so a same-version fork checkout keeps serving its first build
  even after its code changes (mtime touches and `--refresh-package` do
  not invalidate it). `--no-cache` forces a rebuild per invocation; the
  cost is a ~1s local build per gate invocation.
- Stale `mutate4py` worker trees under `.mutate4py/workers/` are pruned to
  the two most recent runs by `scripts/differential-mutation.sh`; the tool
  itself removes a completed run's trees.

## External tools and pins

`config/swarmforge.env` records repository URLs, exact revisions, commands, and
paths. It does not install anything. A developer or CI job explicitly checks
out or installs those revisions after granting the required network and
installation permissions.

The Acceptance Pipeline Specification (APS) checkout is optional, and no test
needs it. `tests/stpa/test_r5_declarative_gherkin.py` checks the structure of
the rendered native feature (one Feature, one Scenario, only
Given/When/Then/And steps, the trigger as a When step) without the APS parser.
The project never downloads a checkout.

Update a pin in a dedicated pull request that records upstream changes and runs
the affected quality gate. Harness-specific role prompts, handoff files,
dashboards, Beads state, and local tool clones are not repository content.

## Local orchestrator

The local installation uses the fork `hjrnunes/swarm-forge` (pinned in
`config/swarmforge.env`) with the commands in `config/swarmforge.env`. The
fork's `six-pack` still defines a specifier role and a QA role that runs
feature files; until the fork ships a pack without them, start the pipeline at
the coder and give QA only the commands in `config/swarmforge.env`.

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
  to hold each handoff for approval.
- The `six-pack` configuration lives under ignored `swarmforge/`:
  `swarmforge/swarmforge.conf` runs all six roles on the project's configured
  agent backend in invisible tmux windows (`window-invisible`), and role
  prompts are the auto-approve-adapted six-pack prompts under
  `swarmforge/roles/`.
- Model selection is harness-local: each role prompt has a sibling
  `roles/<role>.settings.json` passed to the agent CLI with `--settings`,
  e.g. QA on `grok-4.6`, coder on `deepseek-v4-flash-0731`,
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

The scaffolder is intentionally absent because the project commands already
exist. The project uses ordinary commit messages without agent-role bylines.

## Completion

A pull request is complete when the issue contract is satisfied, deterministic
gates pass without an endpoint, opt-in behavior is clearly separated, generated
or harness state is absent from the diff, and documentation reflects changed
interfaces. Organization administrators own branch-protection configuration.
