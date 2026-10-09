# Asago Scenario Generator — agent guide

Build useful STPA scenarios and get them through the requested end-to-end path.
Keep this guide short; put contracts, experiments, and incident history in their
own documents.

## Start here

- Check the working directory, branch, and `git status --short`. This project has
  several worktrees with different implementations. Use `git worktree list` to
  locate them; do not assume the main checkout is the active mission checkout.
- Read the task's current specification and the relevant code before editing.
  Follow the user's current decisions over superseded designs or saved reports.
- Preserve unrelated changes and generated evidence. Stage only your own work;
  commit or push when requested.

## Ownership

- The producer owns STPA analysis and scenario meaning: narrative, attack tree,
  Gherkin, failure criterion, safe alternative, and necessary metadata.
- The artifact generator owns concrete attack messages, setup declarations,
  runtime bindings, and semantic judge specifications. Authoring uses supplied context
  without accessing the target.
- Downstream qualification owns live setup, Garak execution, evidence collection,
  detector evaluation, and cleanup. Its tooling lives in the orch repository
  under `src/asago_orch/qualification/`; read `asago-orch/docs/qualification.md`.
- Adapt scenarios to the supplied use-case information. Keep missing facts
  explicit rather than inventing tools, records, permissions, or outcomes.
- Older branches retain legacy execution projections and bundles. Inspect the
  current implementation before changing compatibility; their presence is not
  a reason to restore artifact authoring inside the producer.

## Commands

Run from the intended checkout. Check CLI `--help` for current flags.

```bash
uv sync --locked
uv run asago-scenario-generator generate --help
uv run pytest tests/path_to_changed_test.py -q
./scripts/quality.sh
uv run pytest tests/ -q
```

Use focused tests while implementing. Run the task's required broad gates once
at delivery; repeat them only after a relevant change or unresolved failure.
Deterministic tests must not contact model endpoints or targets. Pin behavior
with unit tests under `tests/` and prompt text with rows in
`tests/phrases/*.yaml`; the repository has no Gherkin acceptance layer, and the
SwarmForge pipeline starts at the coder.

## Prompts and corrections

- The LLM handles semantic choices; code supplies exact schemas, source lookup,
  identifiers, reference validation, and preservation of unchanged material.
- Explain every model-facing field and reference form. Inspect the actual
  rendered request, not just the template or an internal context dictionary.
- Keep reusable instructions separate from scenario data and exact failure
  feedback. Do not add gold answers or case-specific branches to product prompts.
- When the user supplies exact correction text, deliver it verbatim. Preserve
  raw responses and report what failed before spending another request.
- Reuse valid saved work when authorized. A new task name does not reset spend,
  invalidate prior failures, or authorize a retry.

## Live work and evidence

- Before private model use, read `docs/development/private-live-model-approval.md`.
  Carry standing data approval forward; read credentials from the local profile
  without printing or committing them. Data approval is not an unlimited call
  allowance or permission to execute attacks.
- Follow the task's model, thinking, token, request, and target limits. Record
  actual controls and spend. Stop at the specified boundary without hidden
  retries. The one retry the client makes after a transport error (HTTP 5xx or
  a connection error that is not a timeout) is not hidden: it is recorded in
  `provider-calls.jsonl` and counts as a request. Nothing else retries, with
  one stated exception: the Stage 1a risk-coverage review repeats a batch once
  when its reply decodes but carries no row (`{"rows": []}`); the repeat is a
  recorded request and counts too.
- For execution, use `asago-orch/docs/qualification.md` and the existing orch
  stage runner.
  Consumer authoring does not start services or perform setup.
- Keep frozen inputs, packages, and historical evidence unchanged; write new
  attempts and corrections separately. An unavailable fact stays unavailable.
- Report generation, validation, packaging, execution, and recovery separately.
  A tool-call attempt does not prove a backend effect. Tests passing does not
  establish scenario recovery or successful execution.
- Fix the demonstrated blocker and continue toward the requested result. Keep
  unrelated cleanup and speculative hardening outside the critical path.

## Read only what the task needs

| Task | Reference |
| --- | --- |
| Entry points and configuration | `README.md`, CLI `--help` |
| Pipeline or cross-repository contract change | `docs/architecture/overview.md`, applicable schema in `data/contracts/`, current task spec |
| Prompt, response, grounding, or review change | `docs/architecture/model-facing-interfaces.md`, actual prompt builders and tests |
| Live setup, frozen-package execution, cleanup | `asago-orch/docs/qualification.md`; modules live under `asago-orch/src/asago_orch/qualification/` |
| Gold scoring or recovery claims | Scoring lives in the orch repo's score stage and uses `asago_orch.qualification.probe_detector` |
| Development method and SwarmForge roles | `docs/development/swarmforge.md` |

`AGENTS.md` is a symlink to this file. Edit `CLAUDE.md`; preserve the symlink.
