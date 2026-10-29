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
  detector evaluation, and cleanup. The orchestrator runs this tooling.
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
`tests/phrases/*.yaml`; the repository has no Gherkin acceptance layer.

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

- Before private model use, send an endpoint only the project data the owner
  approved for it: use-case, policy, scenario, and synthetic target material,
  never real customer data. Keep its URL and credentials in the local model
  profile without printing or committing them. Do not publish the material or
  switch provider or profile without approval.
- Carry a standing approval forward for work inside its scope; ask only when
  the data or destination materially exceeds it. Data approval is not an
  unlimited call allowance or permission to execute attacks; attacks run only
  against the local safe targets.
- A replay-fill `generate` run sends its unrecorded requests to the endpoint,
  so the same rules apply; set `--max-live-requests` to the task's request
  limit.
- Follow the task's model, thinking, token, request, and target limits. Record
  actual controls and spend. Stop at the specified boundary without hidden
  retries. Every re-ask is recorded in `provider-calls.jsonl`. A step's call
  count can leave out the client's re-asks (see the catalogue below), so take
  spend from that file. The re-asks are bounded:
  - The client retries a transport error (HTTP 5xx, or a connection error that
    is not a timeout) once. With a profile `service_tier_fallback`, it re-sends
    an HTTP 429 once on the fallback tier. No step re-asks after a provider or
    transport failure; steps re-ask only a reply that fails decoding or
    validation.
  - Many model calls earn one correction when a reply fails its schema or
    validators. The correction is the original prompt plus feedback and the
    exact error. Stage 2 Calls 1–3 and the risk-actionability classifier also
    repeat, once, a reply that does not decode.
  - Some steps add bounded re-asks of their own:
    - Stage 1a sends targeted repairs and a second density revision round.
    - The risk review and the risk-actionability classifier each repeat a
      batch or its pending cards.
    - Stage 2 runs the Call 2b repair and the Call 3 density correction.
    - Obligation and governance routing re-ask the whole batch. A partial
      second routing reply is merged route by route with the first.
    - An unchanged ICA correction is asked again.
    - Stage 5 sends its concise retry after a stop at the completion cap and
      its condition correction.
    - Target realization runs its correction and verifier retries.
  - `docs/architecture/model-reasks.md` lists each re-ask with its trigger,
    what it sends, its bound and its fallback. Keep it current when you
    change one.
- For execution, use the orchestrator's existing stage runner. Consumer
  authoring does not start services or perform setup.
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
| Prompt, response, grounding, or review change | The actual prompt builders and their tests; `tests/phrases/*.yaml` pins prompt text |

`AGENTS.md` is a symlink to this file. Edit `CLAUDE.md`; preserve the symlink.
