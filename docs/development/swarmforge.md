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
project target is CRAP at or below 6 and mutation score at or above 80. Tool
scope remains `src/`; Ruff also checks `acceptance/`.

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
  ignored `swarmforge/scripts/`; the fork carries the project's committed
  patches (droid agent backend, auto-approval of every handoff, and the
  project-name dashboard title). The `./swarm` wrapper archives the local
  fork checkout first and falls back to the fork's GitHub tarball.
- The `six-pack` configuration lives under ignored `swarmforge/`:
  `swarmforge/swarmforge.conf` runs all six roles on the droid agent backend
  in invisible tmux windows (`window-invisible`), role prompts are the
  auto-approve-adapted six-pack prompts under `swarmforge/roles/`, and
  `apply-droid-patch.sh` re-applies the fork patches if scripts were ever
  re-fetched from upstream instead of the fork.
- Model selection is harness-local: each role prompt has a sibling
  `roles/<role>.settings.json` passed to the droid CLI with `--settings`,
  e.g. specifier/QA on `grok-4.6`, coder on `deepseek-v4-flash-0731`,
  architect on `deepseek-v4-pro`, cleaner/hardender on `gpt-5.6-luna`, with
  matching reasoning effort. These files are ignored, not repository content;
  the reference copies live in `intendente` (`swarmforge/roles/`).
- Runtime stays under `.swarmforge/`, role worktrees under `.worktrees/`.
  Launch from a feature branch with `./swarm`; stop with `./close-swarm` or
  by closing its first terminal window. Handoffs are auto-approved and
  delivered via `ready_for_next.sh` / `done_with_current.sh`.

The scaffolder is intentionally absent because the portable acceptance
pipeline is already committed. The project uses ordinary commit messages
without agent-role bylines. The retired SwarmForge-Droid installation (role
prompts and helpers under `.factory/`, runtime under `.swarmforge-droid/`)
is no longer used; do not launch it against a feature branch.

## Completion

A pull request is complete when the issue contract is satisfied, deterministic
gates pass without an endpoint, opt-in behavior is clearly separated, generated
or harness state is absent from the diff, and documentation reflects changed
interfaces. Organization administrators own branch-protection configuration.
