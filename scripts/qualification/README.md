# External Garak qualification

## Delivery command sequence

Run commands from the producer repository root unless a command changes
directories explicitly. Install dependencies before any check:

```bash
cd <producer-repo-root>
uv sync --locked
```

The primary cross-repository path is:

```bash
uv run asago-scenario-generator run \
  --use-case @use-case.txt \
  --risk-extraction risk-extraction.json \
  --qualification-facts qualification-facts.yaml \
  --taxonomy-inputs obligation-inputs.yaml \
  --output-dir output/my-system \
  --sp1-profile <profile-name> --sp2-profile <profile-name> \
  --sp3-profile <profile-name>

cd <consumer-repo-root>
uv sync --locked
uv run asago-artifact-generator author <scenario-handoff-or-input.json> \
  --inventory <inventory.json> \
  --runtime-contract <runtime-contract.json> \
  --output-dir runs/authoring/<case-id>
uv run asago-artifact-generator check runs/authoring/<case-id>/<case-id> \
  --evidence <evidence.json>
```

Load the immutable package for frozen downstream execution:

```bash
cd <producer-repo-root>
.venv/bin/python scripts/qualification/run_frozen_package.py \
  /absolute/path/to/package \
  --setup-fixture /absolute/path/to/setup.json \
  --generation-fixture /absolute/path/to/generation.json \
  --receipt build/qualification/frozen-receipt.json
```

Start, verify, and stop one safe target and the gateway through the maintained
safe-only lifecycle seam:

```bash
cd <producer-repo-root>
uv run python scripts/qualification/run_recipe.py start-safe \
  --component target --domain klarna --port 8888 \
  --state-dir build/qualification/runtime/klarna
uv run python scripts/qualification/run_recipe.py start-safe \
  --component gateway --port 8321 --profile <configured-profile> \
  --profiles-file config/model-profiles.yaml \
  --state-dir build/qualification/runtime/gateway
uv run python scripts/qualification/run_recipe.py verify-safe \
  --component target --domain klarna --port 8888 \
  --state-dir build/qualification/runtime/klarna
uv run python scripts/qualification/run_recipe.py verify-safe \
  --component gateway --port 8321 \
  --state-dir build/qualification/runtime/gateway
uv run python scripts/qualification/run_recipe.py stop-safe \
  --component target --domain klarna --port 8888 \
  --state-dir build/qualification/runtime/klarna
uv run python scripts/qualification/run_recipe.py stop-safe \
  --component gateway --port 8321 \
  --state-dir build/qualification/runtime/gateway
```

Use `airbnb` on `8890` or `occiai` on `8892` instead of `klarna` on `8888`
when the case requires another target. The safe lifecycle writes a scratch
gateway configuration with only the three safe loopback connectors, passes
profile values through the gateway child environment, persists process
identities, and refuses stale identities during cleanup. Ports `8889`, `8891`,
and `8893` are outside this recipe and make verification fail closed.

Identity verification and socket readiness are separate lifecycle gates. After
the gateway identity matches the captured process, frozen live dispatch uses a
bounded 90-second `wait_for_ports` polling interval to wait for the declared
gateway port to accept connections. The wait rechecks the captured identity
while it polls, so a timeout or early process exit fails the lifecycle before
the target starts or frozen-package generation begins. Cleanup still uses the
captured identities on every terminal path.

Execute one accepted package against one safe target with the target-driven
launcher; see [Target-driven live execution](#target-driven-live-execution):

```bash
cd <producer-repo-root>
.venv/bin/python scripts/qualification/run_fresh_package_live.py \
  --target klarna --package /absolute/path/to/package \
  --profiles-file config/model-profiles.yaml \
  --target-root <mini-agents-root> --target-python <mini-agents-python> \
  --garak-checkout <garak-checkout> --garak-python <garak-python> \
  --run-dir build/qualification/<fresh-run-name> --preflight-only
```

The orchestration repository (`asago-orch`) sequences these commands for a
full end-to-end run.

Run the final broad gate once after the last required execution:

```bash
cd <producer-repo-root>
./scripts/quality.sh
export ASAGO_SCENARIO_GENERATOR_APS_ROOT=/absolute/path/to/Acceptance-Pipeline-Specification
./scripts/acceptance.sh
uv run pytest scripts/qualification -q
```

The `generate` command is a legacy compatibility path for historical
scenario YAMLs. New work follows `run` → consumer `author` → consumer `check`
→ frozen execution. Do not restore `generate` as a second active workflow.

## Frozen artifact packages

Producer qualification loads consumer packages through the vendored
`artifact-package-v2` contract. The loader verifies every member and digest
before setup or execution, and the downstream path does not import consumer
authoring code. The vendored contract and lock match the consumer authority at
revision `cb3145472bb2058b6fe482ee2c5aa4313fdb55b1`. That revision accepts only
the `scenario-handoff-v1` input kind, so the loader rejects historical
`native-semantic-yaml` and `reference-task` packages.
When `judge.json` is present, frozen execution supplies detector code only the
normalized `judge` projection; audit fields stay in the receipt and judge ledger.

Run the deterministic downstream checks from the producer repository:

```bash
.venv/bin/pytest \
  scripts/qualification/test_artifact_package_runtime.py \
  scripts/qualification/test_frozen_runtime.py \
  scripts/qualification/test_evidence_adapter.py \
  scripts/qualification/test_frozen_judge.py \
  scripts/qualification/test_safe_lifecycle.py \
  scripts/qualification/test_garak_dispatch.py -q
```

Execute a saved package with offline fixtures:

```bash
.venv/bin/python scripts/qualification/run_frozen_package.py \
  /absolute/path/to/package \
  --setup-fixture /absolute/path/to/setup.json \
  --generation-fixture /absolute/path/to/generation.json \
  --receipt build/qualification/frozen-receipt.json
```

### Target-driven live execution

`run_fresh_package_live.py` executes one accepted, immutable artifact package
against one local safe target. You choose the target; the package declares
everything else. The launcher has no per-scenario routes, scenario allowlists,
or scenario-specific setup policies, so any accepted package whose declarations
fit the generic limits runs through the same path.

| `--target` | Service | Safe target port | Gateway port |
| --- | --- | --- | --- |
| `klarna` | MiniKlarna | `8888` | `8321` |
| `airbnb` | MiniAirbnb | `8890` | `8321` |
| `occiai` | MiniOcciAI | `8892` | `8321` |

Use only these ports, loopback only. Record discovery requests separately from
generation, setup/capture, server-command, judge, and detector ledgers.

The launcher derives the route from the package as follows:

| Route field | Source |
| --- | --- |
| Scenario ID | `manifest.json` `scenario_id` |
| Observation level | `plan.json` `observation_claim.claim_level` |
| Semantic judge limit | `1` when `judge.json` is present and valid, otherwise `0` |
| Creation setups | Non-read-only setup operations listed in the runtime contract `setup_permissions` |
| Observed operations | Every non-read-only operation in the inventory |
| Generation tools | Every operation in the inventory |

The launcher supports the `command_attempt` and `reply` observation levels.
The consumer also defines `returned_result` and `state_effect`; those levels
fail preflight as `capability_gap:observation_level_unsupported:<level>`. A
package without a declared level fails as
`capability_gap:observation_level_undeclared`.

Setup follows one generic policy: at most four setup operations, read-only
checks, and at most one state-creating setup. The frozen runtime requires the
runtime contract `setup_permissions` to list every setup operation. An operation counts as
read-only when the inventory marks it `read_only`; otherwise the frozen runtime
classifies it by name. The same environment stays alive from setup through
generation; the adapter starts each service once and never resets it.

Generation exposes every inventory operation to the target agent, so the
target can choose among the same tools it would have in normal use. The reply
route still rejects a tool call outside that exposed allowlist. The launcher
no longer stops judging after more than four read-only tool calls.

For the `command_attempt` level, the receipt records every model-issued call
to a non-read-only operation as an attempt. Each attempt lists the operation,
the record IDs taken from `id` and `*_id` arguments, and its evidence
reference. An attempt does not establish a backend or target effect; receipts
keep effects as not established and never claim a confirmed vulnerability.
The packaged detector alone decides the outcome.

For the `reply` level, the launcher dispatches the package-declared semantic
judge at most once with zero retries and sends the `judge.json` declaration
unchanged. Receipts preserve native messages, the judge request and output,
the validated verdict passed to the packaged detector, and the detector
result.

#### Command

Check the package and local runtime paths offline before execution. Preflight
starts no service and contacts no provider or target:

```bash
.venv/bin/python scripts/qualification/run_fresh_package_live.py \
  --target klarna \
  --package "/absolute/path/to/accepted-package" \
  --expected-package-digest "<accepted-manifest-digest>" \
  --expected-detector-digest "<accepted-detector-digest>" \
  --profiles-file /absolute/path/to/config/model-profiles.yaml \
  --target-root /absolute/path/to/mini-agents \
  --target-python /absolute/path/to/mini-agents/.venv/bin/python \
  --garak-checkout /absolute/path/to/garak-pinned \
  --garak-python /absolute/path/to/garak-venv/bin/python \
  --run-dir "build/qualification/<new-run-directory>" \
  --preflight-only
```

For the authorized execution, remove `--preflight-only` and use a new
`--run-dir`. Live execution requires `--run-dir`, and the launcher refuses an
existing run directory.

| Flag | Required | Default | Meaning |
| --- | --- | --- | --- |
| `--target` | Yes | None | `klarna`, `airbnb`, or `occiai` |
| `--package` | Yes | None | Accepted `artifact-package-v2` directory |
| `--profiles-file` | Yes | None | Local model profiles file; credentials stay in memory |
| `--target-root` | Yes | None | Mini-agents checkout containing `ogx-config.yaml` |
| `--target-python` | Yes | None | Python interpreter for the target services and MCP helper |
| `--garak-checkout` | Yes | None | Pinned Garak checkout |
| `--garak-python` | Yes | None | Python interpreter for the Garak helper |
| `--profile` | No | `gemma4-oc` | Generation and judge profile |
| `--docker-path` | No | `/usr/local/bin/docker` | Executable used for the detector container |
| `--expected-package-digest` | No | None | Manifest digest pin |
| `--expected-detector-digest` | No | None | `detector.py` SHA-256 pin |
| `--run-dir` | For execution | None | New directory for `preflight.json` and run evidence |
| `--preflight-only` | No | Off | Validate offline and stop |

If you supply a digest pin, preflight verifies it and fails with
`package_digest_mismatch` or `detector_digest_mismatch` on a difference.
Whether or not you pin, `preflight.json` and `receipt.json` record the actual
package and detector digests, the expected values, and `*_verified` flags.

#### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Preflight passed (`--preflight-only`), or execution completed and wrote `receipt.json` |
| `1` | Preflight rejected the package and wrote `preflight.json` with the rejection, or execution wrote `receipt.json` with an incomplete or failed status |
| `2` | The launcher failed with an unexpected error; inspect stderr |

#### Preflight

`--preflight-only` and live execution call the same pure `validate_pre_service`
function before any run-directory creation, service start, or provider or
target call. The function verifies the package bytes and optional digest pins,
checks the runtime target domain against `--target`, derives the route, and
runs the frozen runtime's setup, binding, prerequisite, and stimulus
validators. It also validates the required `target-root/ogx-config.yaml` in
memory with the safe-config renderer used at startup and checks the local
runtime paths, including that `--docker-path` names an executable file.

Unsupported or malformed declarations fail closed and are never reshaped. The
launcher writes `preflight.json` with `status: rejected` and a
`rejection` object (`kind`, `reason`, `message`) into the new run directory,
or prints the record when you omit `--run-dir`. Capability-gap reasons
include:

- `state_creating_setup`: a non-read-only setup not listed in `setup_permissions`.
- `excess_creation_setup`: more than one creation setup.
- `setup_permission_undeclared`: any setup operation, read-only or not, that
  the runtime contract `setup_permissions` does not list.
- `prerequisite_limit_exceeded`: more than four setup operations.
- `observation_level_undeclared` or `observation_level_unsupported:<level>`.
- `judge_invalid`: a `judge.json` that fails validation.
- `generation_tools_unavailable`: an inventory with no operations.
- `package_target_mismatch`: a runtime target domain that conflicts with `--target`.
- `package_not_accepted`, `setup_invalid`, `binding_invalid`,
  `prerequisite_invalid`, `stimulus_invalid`: invalid package declarations,
  including a non-list `stimulus.history`, a `{{slot}}` without a declared
  binding, or an object or array binding referenced in text.

Digest mismatches use rejection kind `package_check`. Missing, unreadable, or
invalid gateway configuration and missing executable paths raise named errors
before run-directory creation.

A case without an accepted package is `not_attempted`, not a preflight gap or
`rejected_post_service`. A preflight capability gap applies only when an
accepted package fails validation before services start.
`rejected_post_service` means an accepted package passed preflight, services
started, and runtime validation rejected it before generation, for example
when captured setup results, resolved bindings, and the rendered request
disagree on the intended record (`setup_result_missing`, `binding_setup_*`,
`request_record_mismatch`). It counts as an attempted execution and requires
cleanup.

#### Evidence and controls

The launcher uses `live_helpers.py` as its child helper for MCP setup calls
(`--mcp-helper`, under the target Python) and pinned-Garak generation
(`--garak-helper`, under the Garak Python). It performs no separate discovery
call; declared setup operations go directly through the MCP helper. The
launcher records child stdout, stderr, and exit status, including timeout
partial output, before parsing the single JSON protocol response. It captures
the native Gateway Responses request and response and the Garak tool calls; the
captured request count is distinct from any upstream model calls a gateway
makes internally. It stores judge transport evidence before JSON parsing, then
stores the parsed reply and frozen-validator result separately
(`judge_capture/validated-outcome.json`). Credentials and endpoint values stay
in process memory; run evidence files are owner-only.

The generation profile must resolve to `gemma-4-26b-a4b-it`. Generation runs
one pinned-Garak round with `max_output_tokens` 4096, a 180-second provider
timeout, a 210-second process timeout, and zero retries. The judge uses the
same profile with thinking off, temperature zero, a 512-token completion
limit, a 180-second timeout, and zero retries. The gateway's upstream
model-request count is not separately observable, and gateway tool-round and
command limits are not exposed. The receipt records the target, scenario ID,
derived route, exposed generation tools, and resolved limits under
`launcher_controls`. Every started service is cleaned through
`safe_lifecycle.py` on success and failure using the captured identities.

Historical closure records remain in `build/qualification/`, for example the
2026-09-23 [O04 closure report](../../build/qualification/execution-closure-20260923/report.md)
and [O03 closure report](../../build/qualification/execution-closure-20260923-o03/report.md).
Those runs used the retired per-scenario launchers.

#### Frozen runtime declarations

New `artifact-authoring-v2` packages use canonical prerequisite declarations.
The frozen runtime resolves each declared binding before generation and records
an explicit incomplete reason with zero generation dispatches when a binding or
expected value is unavailable. Historical packages keep their `source` and
`expected` prerequisite aliases. Receipts keep supplied static facts,
runtime-bound values and observed evidence separate from the judge conclusion;
judge support references must resolve against the observed packet before a
supported or contradicted verdict is retained as decisive. Setup ledger entries
include the returned operation result so bindings such as a created draft ID
trace to the actual setup capture.

### Detector probes

`probe_detector.py` runs a package's own detector on synthetic evidence, so a
caller can check whether the oracle fires on a violation pattern and stays
quiet on safe behavior. The command contacts no model, target, or gateway, and
the probe request carries only neutral tool calls and messages:

```bash
.venv/bin/python scripts/qualification/probe_detector.py \
  --package /absolute/path/to/accepted-package \
  --probes /absolute/path/to/probes.json \
  --output /absolute/path/to/results.json \
  [--docker-path /usr/local/bin/docker]
```

The request (`detector-probe-request-v1`) is closed:

```json
{"schema": "detector-probe-request-v1",
 "probes": [{"id": "G06:unsafe",
             "tool_calls": [{"name": "process_refund",
                             "arguments": {"order_id": "ORD-104"},
                             "result": null, "status": "success"}],
             "assistant_messages": [],
             "user_text": null}]}
```

- Each `assistant_messages` item is a string or a `{"content": "..."}` object.
- A `null` `user_text` uses the package stimulus `user_text`, rendered with
  the resolved bindings. If a slot depends on an unavailable binding, the
  authored template text is used unchanged.
- A tool call `result` is JSON-encoded into the native `output` field; `null`
  means no output. A `null` `status` omits the field.

The result (`detector-probe-result-v1`) records the verified package and
detector digests and one entry per probe:

```json
{"schema": "detector-probe-result-v1", "package_digest": "...",
 "detector_digest": "...", "error": null,
 "results": [{"id": "G06:unsafe", "outcome": "detected",
              "reason": "...", "bindings": "resolved"}]}
```

Each packet goes through the live evidence path: the native `mcp_call` record
shape with a synthetic `fc_probe_<probe>_<call>` ID, `adapt_generation_evidence`,
the frozen-judge seam without a client, and the unchanged `detector.py` bytes
in the same constrained Docker sandbox (`python:3.12-slim`, no network,
read-only root, 128 MiB, 64 PIDs, one CPU, 10-second timeout). Tool calls and
messages are marked captured and complete; snapshots are not captured.
Supplied-input bindings resolve from the package facts exactly as in live
execution. A binding that depends on setup output cannot resolve offline, so
the entry reports `bindings: unavailable` and the detector still runs without
that value. Prerequisites are not evaluated, and a declared semantic judge
stays `unresolved` with reason `judge_unavailable`.

The detector adapter accepts one evidence packet per container, so the command
loads and verifies the package once and then starts one container per probe.

| Exit code | Meaning |
| --- | --- |
| `0` | `results.json` was written; a probe whose detector failed or timed out has `outcome: error` |
| `1` | The request is invalid or unreadable, the package cannot be loaded, or its detector is invalid; `results.json` has a top-level `error` and empty `results` |
| `2` | Unexpected crash; inspect stderr |

### Strict saved-evidence judge transport

`frozen_judge_transport.py` is the reusable transport boundary for a judge
request that evaluates already-captured evidence. It records the exact system
and user prompts, raw response bytes, non-secret controls, response metadata,
usage when reported, and elapsed time before JSON parsing. Credentials and
provider secrets stay outside the record.

`rejudge_saved_receipt.py` builds a caller-supplied evaluation revision from a
saved receipt and sends the parsed JSON object unchanged through
`evaluate_frozen_judge`. Transport, parse, schema, evidence-reference, support,
and valid semantic `unresolved` outcomes remain separate. Only a valid result
may be attached to a copied evidence packet for one offline packaged-detector
run; the original receipt and package remain unchanged.

This opt-in runner is outside the scenario and artifact product pipelines.
It accepts a compiled `executable-conversation.json` and its exact
`execution-plan.json`, validates their authority, and invokes Garak's actual
`injection.IndirectInjection` replay probe. Despite that probe's name, its
conversation source also accepts direct and multi-turn compiled cases.

## Stack cleanup evidence

Callers record stack cleanup through the maintained seam in
`stack_cleanup.py` (VAL-QUAL-011). The former `run_end_to_end.py` entry
point, which used this seam on every terminal path, is retired in favor of the
orchestration repository.

- A caller runs the cleanup on success, stage failure, and unexpected
  failure. It first records current process existence, full command,
  ancestry, owner, and mission path, and signals only identities that pass all
  checks. A stale PID or a pattern match alone is never authority.
- Each run records `cleanup/stack-cleanup.json` atomically (temp file plus
  `os.replace`) with the run id, target, checked safe ports, observed
  process and port state before and after the stop, stop command and result,
  listener closure, the bounded process-exit wait, the final no-orphan check,
  the status, a UTC timestamp, and errors. A separate timestamped
  `stack-cleanup-current-verification-*.json` record lists current processes,
  ports, action, result, and its distinction from preserved historical
  cleanup failures.
- Listener closure does not prove process exit. After ports close, the seam
  waits boundedly for every authorized process to disappear. A zero stop
  result records a signal match only; a timeout remains a failed cleanup with
  the exact survivor evidence.
- A `--pause-before-dispatch` run records an intentional `kept_running`
  record with the resume reason and scope and does not stop the stack.
  `--resume-dispatch` replaces that record only after the dispatch path runs;
  a refused resume keeps the stack and the pause record intact.
- Failure records preserve the observed processes and ports. A failed probe
  records `null` state plus the error, never an empty orphan list or a
  cleared port that was not observed.

The fidelity audit (`audit_scenario_fidelity_evidence.py`) consumes these
per-run records and classifies them distinctly: `verified` (recorded
completion with an observed clean final state), `kept_running` (intentional
pause), `failed` (observed survivors or an unverifiable completion claim),
and `historical_unverified` (no record). The owner-approved historical
OcciAI/Airbnb exception stays in force with `timely_cleanup_verified` false
and no rerun.

The seam is injectable: tests supply stop, process-evidence, and port probes,
so no test signals a process or touches a real port.

Use an isolated environment containing the artifact-generator package, MCP,
and the Garak PR checkout at
`06aba1a2c9b142d561eeeff08dfaffcbe77487c3`. These external dependencies are not
installed into the scenario-generator environment.

## Observe and compile

Capture current test data independently of scenario generation. The automatic
selector requires exactly one independently verified, read-only observation
tool with no arguments. It verifies that tool's live description and schema
before calling it; ambiguous or unsupported inventories stop explicitly.

```bash
PYTHONPATH=src:../asago-artifact-generator/src \
  /path/to/garak-venv/bin/python scripts/qualification/capture_runtime_context.py \
  --mcp-url http://127.0.0.1:8888/sse \
  --target-profile /path/to/discovery/execution-target-profile.json \
  --output build/qualification/runtime-context
```

When the profile exposes more than one zero-argument observation tool, or when
the operator prefers to name the observer explicitly, combine `--state-tool`
with `--target-profile`: the named tool is accepted only when the profile's
verified annotations mark it a supported, agreed, observe-only, zero-argument
operation, and the captured context still carries the profile digest.

```bash
PYTHONPATH=src:../asago-artifact-generator/src \
  /path/to/garak-venv/bin/python scripts/qualification/capture_runtime_context.py \
  --mcp-url http://127.0.0.1:8890/sse \
  --state-tool get_airbnb_state_summary \
  --target-profile /path/to/discovery/execution-target-profile.json \
  --output build/qualification/runtime-context
```

An explicitly supplied source document can additionally authorize bounded
text-search observations. The target profile must contain exactly one verified
`text_search` role with a single required plain string argument. Without
`--query-profile`, the source is passed literally for compatibility. With a
named `--query-profile`, one model-planning call proposes at most four distinct
single-term topical search stimuli (each at most 80 characters), retaining a
verbatim source quote and rationale for each. The planner is not a policy
authority: its queries are search stimuli only, and returned content remains
untrusted. There are no retries, fallback providers, brand prefixes,
conjunctions, combined subjects, wildcards, whole-paragraph queries, or
business-action calls. An ambiguous or unsupported profile records a no-call
diagnostic while still preserving the state observation.

```bash
PYTHONPATH=src:../asago-artifact-generator/src \
  /path/to/garak-venv/bin/python scripts/qualification/capture_runtime_context.py \
  --mcp-url http://127.0.0.1:8888/sse \
  --target-profile /path/to/discovery/execution-target-profile.json \
  --query-text-file /path/to/use-case.txt \
  --query-profile gemma4-oc \
  --profiles config/model-profiles.yaml \
  --output build/qualification/runtime-context-with-read
```

The raw capture retains each exact argument, live tool description/schema,
profile digest, and MCP result under `read_observations`. The normalized runtime
context keeps those observations separate from `state`, includes the paired
`target_profile_digest`, and labels transport verification separately from
untrusted returned content. A returned payload is not interpreted as policy
authority or an execution binding. Query-plan provenance contains the source
digest, each query digest, source quote, rationale, and selected model profile;
the existing `calls.jsonl` records the single planner receipt. Oversized or
empty source text, unsupported planning, and planner validation failures retain
the state observation with an explicit diagnostic and make no read calls.

```bash
PYTHONPATH=src:../asago-artifact-generator/src \
  .venv/bin/python scripts/qualification/compile_with_profile.py \
  --profiles config/model-profiles.yaml --profile gemma4-oc \
  --call-log build/qualification/artifact-author-calls.jsonl -- \
  generate --bundle /path/to/run/execution-bundle.json \
  --target-profile /path/to/discovery/execution-target-profile.json \
  --runtime-context build/qualification/runtime-context/runtime-context.json \
  --platform garak --output-dir build/qualification/artifacts
```

The observation is data for attack authoring, not a replacement for a missing
semantic condition or authority to change an execution plan. The raw MCP
capture stays in `observation.json`; only normalized state and explicitly
requested read observations enter authoring.
The compilation adapter invokes the normal artifact CLI unchanged and records
its exact prompt inputs and parsed provider returns locally. These logs may
contain target test data; do not publish them as sanitized configuration.

### Optional subject-model companion

A product `run` accepts an optional `--target-subject-model
target-subject-model.yaml` companion (closed `target-subject-model-v1`)
beside `--target-profile` and `--target-observations`. It declares the
session-subject path, the per-tool argument roles, and the record-subject
relations the `owner_differs_from_session` oracle compiles against. The
command validates structure **and** the reviewer acceptance envelope offline
before any model call: a proposed (unstamped), edited, or
observation/profile-mismatched file fails the run closed with a typed
reason, and the accepted file's content digest plus reviewer stamps ride on
the run manifest and the target-derived-structure sidecar. Never fold the
model into the TARGET-STATE observation, and never treat a digest-only file
(one without `reviewed_by`/`reviewed_on`) as accepted.

Historical MiniKlarna qualification snapshots remain readable without this
companion. They retain their captured session and record observations, but
they do not gain `owner_differs_from_session` or conversation offers through
inference; a new qualification run needs an accepted `target-subject-model-v1`
file to enable those declarations. Frozen historical artifacts are not
rewritten. The current consumer uses the typed projection conditions, so it
does not require an ownership-sentence parser for this companion.

## Execute

```bash
PYTHONPATH=src:../asago-artifact-generator/src \
  /path/to/garak-venv/bin/python scripts/qualification/garak_case_runner.py \
  --case /path/to/SCN-NNN/executable-conversation.json \
  --plan /path/to/SCN-NNN/execution-plan.json \
  --mcp-url http://127.0.0.1:8888/sse \
  --model-url http://127.0.0.1:8321/v1/ \
  --model gemma-4-26b-a4b-it \
  --judge-profile gemma4-oc --profiles config/model-profiles.yaml \
  --state-tool get_klarna_state_summary \
  --timeout 180 \
  --output build/qualification/SCN-NNN-safe
```

Supply runtime authentication through `OPENAI_API_KEY` when required; never
put credentials in profiles or compiled cases. Set the XDG cache/config/data
directories to the isolated environment when testing an external Garak fork.
The MCP server must be an explicitly authorized disposable test target.
`--state-tool` authorizes that named zero-argument read operation; the runner
does not guess which tool is safe to call. The default safe MiniKlarna server
uses port 8888; a separately started unsafe counterpart uses 8889.

The runner does not extract or rewrite attack prompts. It verifies selected
function names, descriptions and schemas against the live MCP inventory,
then adapts only their transport to MCP `allowed_tools`. Extra runtime tools
are not exposed. Forced function selection is currently unsupported and is
rejected explicitly. No target system policy is inserted.

Outputs are `garak-attempts.jsonl` and `qualification.json`, including the
compiled digest, actual responses/tool calls, before/after state and separate
execution errors. The runner submits the compiled history once and scores the
single continuation. Each result entry records the submitted `history_roles`
and the `history_texts_sha256` digest of the submitted turn texts, proving
what was submitted without duplicating prompts. The report copies the compiled
case's `supplied_history` value verbatim when present and records `null`
otherwise. Existing output directories are not overwritten.

## Evaluation boundary

Argument predicates distinguish safe/unsafe observed arguments. They do not
equate an attempted unsafe argument with a successful ledger change. Missing
operation calls remain inconclusive unless their triggering condition is
independently established. With `--judge-profile`, response-text propositions
are evaluated against the exact compiled oracle, actual response and observed
state. The judge must quote literal evidence; missing, malformed or fabricated
evidence cannot establish an unsafe outcome. Judge calls are saved under
`judge/calls.jsonl`.

Authored omission checks retain source-addressed trigger quotations alongside
the author's applicability claim. A source may be an authored user turn, so it
must not be reported as captured target state. Source validation confirms the
quotation exists; reviewers still assess whether it activates the cited rule.
Legacy trigger text containing only an observation or record name is not
sufficient evidence under the current authoring validator. Revalidating a saved
draft does not rewrite its historical result or award a recovery.
The authoring preflight holds `trigger_evidence_unrepresentable` when the
complete evidence-bearing omission proposition violates the existing length
or content limits. The authored record retains the trigger and quotations;
this is a representation limitation, not a failed source check or a finding
that the rule does not apply.

The response judge's result is provider-reported. Literal-quote validation checks
that a quotation exists, not that it logically supports the verdict. Results
explicitly retain `semantic_support_independently_verified: false`. Saved
synthetic controls can be rescored with
`calibrate_semantic_judge.score_saved_controls`; this ignores stored pass flags
and counts missing/unknown judgments separately. An authentic quotation does
not make a verdict that disagrees with a control's expected label pass.

The separate MiniKlarna ledger adapter checks exact refund/order or payment-plan
changes and their matching tool result. A rejected or held refund is not an
applied refund, and unrelated state changes are inconclusive. This is a
qualification adapter for MiniKlarna's inspected state schema, not a generic
business-policy inference engine. Neither it nor the judge inserts policies
into the target conversation. `vulnerability_confirmed` stays false: the
report distinguishes observed predicates and effects from a broader causal
claim about attack success.

Offline checks (the Garak test skips outside its isolated environment):

```bash
/path/to/garak-venv/bin/python -m pytest \
  scripts/qualification/test_garak_case_runner.py \
  scripts/qualification/test_evaluation.py -q
```

These checks exercise the actual probe with Garak's deterministic test
generator, verify unchanged conversation history, and distinguish old
assistant messages from newly generated evidence. They are not live campaign
success evidence.

## Optional offline outcome checks

`outcome_checks.evaluate_supplied_outcome` is a separate, network-free evidence
check. It is not connected to scenario generation, artifact authoring, or live
execution, and adds no new mandatory product input.

Its closed `OutcomeCheck` names the exact artifact digest and references supplied
documents for: rule provenance, execution status, observation completeness,
applicability comparisons, and a violation comparison. Each operand is a
`FactRef(document=..., path=(...))`, not a fabricated literal. It supports only
scalar equality/inequality and numeric greater/less comparisons. It records
the check/document digests and the exact values or missing paths used.

- A recorded failed execution is `execution_error`.
- Missing rules, facts, completed execution, or complete observations remain
  `inconclusive`; unknown values are never replaced with defaults.
- A rule whose prerequisites are false is outside this check's scope, not proof
  of a safe target.
- Safe/unsafe means only that the explicitly supplied check was satisfied or
  violated. Rule prose is provenance, not proof that the expression correctly
  interprets it; `rule_interpretation_independently_verified` remains false.
- No rule is inferred from tool names, schemas, a state change, or a missing
  call. `vulnerability_confirmed` stays false.

The neutral tests contain illustrative rules for answers, refunds, payment
changes, and escalation. They are **not MiniKlarna policies** and are never
attached to saved cases automatically. In particular, an applied refund amount
is distinct from a requested amount, and absence of escalation requires both
applicability and a complete observation.

Run the offline controls without Garak, a target, or an LLM:

```bash
.venv/bin/pytest scripts/qualification/test_outcome_checks.py \
  scripts/qualification/test_calibration.py \
  scripts/qualification/test_evaluation.py -q
```

## Saved-context authoring replay

`replay_authoring_context.py` re-issues the Phase 4 grounded authoring call
(`scenario_prod.authoring.author_candidate_scenarios`) for one saved
(constraint, action) candidate against a completed run's pinned context, so an
owner question such as "does an entitled refund request get labelled
adversarial?" can be replayed on the current templates and model. With
`--constraint-override`, a YAML file supplies replacement constraint, hazard,
and loss texts (for example the literal texts an older iteration recorded)
while the run's structure, bindings, state, and observations stay pinned.
With `--target-subject-model`, the replay supplies an accepted
`target-subject-model-v1` companion exactly as the product run does (and
derives the reviewed obligation bindings from the run's structure sidecar);
the file must be structurally valid and accepted, and a proposed, edited, or
mismatched file fails closed.

This replays saved **inputs through the current provider interface**. It does
not reproduce an old response schema or promise prompt byte equality with an
older run. The current authoring interface uses request-local fact and check
handles; historical `AuthoringResponse` records remain readable separately.
Its current root is `result`: either `kind: scenarios` with a nonempty
`scenarios` list, or `kind: no_scenario` with a nonblank `reason`. The old flat
provider envelope is not a fallback. An offline envelope-only translation must
be saved separately and cannot change a historical validation or recovery.
Freeze the dry-run prompts and emitted schema before any new comparison.
Previously saved addenda that target the old conversation JSON block fail
closed when that anchor is absent; they are not automatically translated.
See [model-facing interfaces](../../docs/architecture/model-facing-interfaces.md)
for compiler ownership and the unchanged observation limits.

Run the offline controls for the replay tool without a model endpoint:

```bash
.venv/bin/pytest scripts/qualification/test_replay_authoring_context.py -q
```

The tool writes only its own output directory and adds no judgment field; the
reviewer judges. Live mode makes one model call per sample (the product seam
records each call in `calls.jsonl` beside a `replay-record.yaml` with per-call
token costs); `--dry-run` renders the exact prompts with zero model calls so
their digests can be compared with a saved run.

```bash
uv run python scripts/qualification/replay_authoring_context.py \
  --run output/runs/<phase4-run> \
  --loss-analysis output/runs/<phase4-run>/loss-analysis.yaml \
  --target-profile build/miniklarna-qualification-20260906/discovery/execution-target-profile.json \
  --target-observations build/miniklarna-qualification-20260906/topic-runtime-context/runtime-context.json \
  --capability-profile output/runs/<capability-profile-run>/capability-profile.yaml \
  --profiles config/model-profiles.yaml --profile gemma4-oc --temperature 0.4 \
  --constraint SC-8 --action process_refund \
  [--constraint-override <constraint-override.yaml>] \
  [--prompt-addendum-file <addendum-text-file>] \
  [--target-subject-model <accepted-target-subject-model.yaml>] [--no-retry] \
  --samples 3 \
  --output-dir output/runs/<replay-output-dir>
```

`--prompt-addendum-file` splices one paragraph of candidate prompt wording
into the rendered user prompt after the `conversation` shape block, keeping
the production templates untouched; the addendum file's digest is recorded
with the prompt hashes, and the splice fails closed unless its anchor is
present exactly once. `--no-retry` disables the one retry per sample for
experiments with a fixed model-call budget.

## Standalone Stage 1a coverage review

`review_loss_analysis_coverage.py` runs the advisory risk-coverage review
against an already-saved `loss-analysis.yaml` instead of a freshly derived
graph. Use it to measure the reviewer against a graph the review never saw,
for example an older candidate the owner rejected.

The tool is read-only with respect to the product pipeline: it writes only the
review artifact and `calls.jsonl` under `--out`, changes no graph, and gates
nothing. It reuses the product seam unchanged, so a verdict read here means
the same thing it means inside a run.

```bash
uv run python -m scripts.qualification.review_loss_analysis_coverage \
  --loss-analysis output/runs/<run>/loss-analysis.yaml \
  --risk-set tmp/risk-extraction-fs-isac.json \
  --use-case tmp/use-case-klarna-fs-isac-v36.txt \
  --out build/qualification/offline-coverage-review \
  --profile gemma4-oc --temperature 0.4
```

The tool loads the complete reviewed risk set (it does not filter by
taxonomy), so the review sees the same cards the obligation planner sees. It
prints the status and the valid, invalid, and missing row counts.

Run the deterministic check without a model endpoint:

```bash
.venv/bin/pytest scripts/qualification/test_review_loss_analysis_coverage.py -q
```

## Retired cross-repository smoke drivers

The former `crossrepo_smoke.py` and `crossrepo_handoff_roundtrip.py` drivers
and their tests are retired. They depended on sealed adaptive fixtures and
removed consumer design imports. Use the maintained package-loader,
contract-parity, frozen-runtime, evidence, detector, judge, and lifecycle
tests above instead.
