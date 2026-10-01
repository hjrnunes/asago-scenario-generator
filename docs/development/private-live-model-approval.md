# Private live-model data approval

Approval recorded: 2026-09-04 (Europe/Zurich)
Reaffirmed and clarified by the owner: 2026-09-06 (Europe/Zurich).

The project owner explicitly approved sending the following project data to
the OpenShift model endpoint selected by the `gemma4-oc` model profile:

- MiniKlarna MCP discovery metadata, including tool names, descriptions, and
  input schemas;
- Klarna and NHS use-case, policy, risk, and scenario-generation material;
- prompts and intermediate model context required to qualify the discovered
  target and perform live scenario-generation checks;
- selected records from the saved synthetic MiniKlarna account, order, and
  payment-plan state, used in artifact-author prompts and qualification through
  the same owner-controlled private Gemma OC endpoint.

The owner states that this OpenShift endpoint is private and under their
control. This approval covers live target discovery, qualification, scenario
generation, artifact authoring, and validation for this project. It does not authorize publishing
the material, sending it to unrelated public endpoints, or committing endpoint
URLs, credentials, secrets, or runtime connection details to the repository.

The approval may be withdrawn or narrowed by the project owner at any time.

## Adversarial execution against local safe targets

Approval recorded: 2026-09-25 (Europe/Zurich).

The project owner approved executing adversarial cases from accepted artifact
packages against the local safe MiniKlarna, MiniAirbnb, and MiniOcciAI
targets. The target agent and the semantic judge use the model endpoint
selected by the `gemma4-oc` model profile. Execution uses
`asago-orch/src/asago_orch/qualification/run_fresh_package_live.py` through
the orch qualification runbook in `asago-orch/docs/qualification.md`, within
the task's model, request, and target limits.

This approval does not cover non-local targets, other model providers, or
real customer data.

## OpenAI API for pipeline roles

Approval recorded: 2026-09-28 (Europe/Zurich).

The project owner approved sending the following project data to the OpenAI
API (`https://api.openai.com/v1`) with the owner's API key:

- MiniKlarna, MiniAirbnb, and MiniOcciAI discovery metadata, including tool
  names, descriptions, and input schemas, and selected records from their
  saved synthetic state;
- Klarna, Airbnb, and NHS use-case, policy, risk, and scenario-generation
  material;
- prompts, intermediate model context, scenarios, and artifact packages
  required for discovery, scenario generation, and artifact authoring.

The approved model is GPT-6 Luna (`gpt-6-luna`) on the Flex service tier. The
approval covers the pipeline roles only: discovery, generation, and authoring.
The target agents and the semantic judge stay on the `gemma4-oc` endpoint.
Keep the API key in the local model profile; do not print or commit it. This
approval does not cover real customer data, publication, or other providers.

## Qwen OC profile for pipeline roles

Approval recorded: 2026-09-30 (Europe/Zurich).

The project owner approved sending the data listed above for the `gemma4-oc`
endpoint to the private OpenShift model endpoint selected by the `qwen38-oc`
model profile (`qwen38-27b`), which runs in the same owner-controlled cluster.
The approval covers the pipeline roles only: discovery interpretation and query
planning, scenario generation, and artifact authoring, for comparison runs
against the `gemma4-oc` profile. The target agents, the target gateway, and the
semantic judge stay on the `gemma4-oc` endpoint. Keep the endpoint and
credentials in the local model profile; do not print or commit them. This
approval does not cover real customer data, publication, or other providers.

The same approval covers the `qwen38-oc-8k` profile, which selects the same
endpoint and model with an 8,192-token completion cap, matching `gemma4-oc`.
The owner chose this profile on 2026-09-30 for all qwen pipeline roles in the
comparison, because the 16,384-token cap of `qwen38-oc` leaves artifact
authoring too little prompt budget in the 32,768-token context. The owner also
set its sampling to the Qwen3 non-thinking recommendation (temperature 0.7,
top_p 0.8, top_k 20), just as `gemma4-oc` uses Gemma's recommended sampling.

## Replacement Qwen endpoint for generation and authoring

Approval recorded: 2026-09-30 (Europe/Zurich).

The owner deployed a replacement `qwen38-27b` model (Qwen3.8-27B-FP8) on a
separate owner-controlled OpenShift cluster and approved sending the same data
as above to it for scenario generation and artifact authoring. Discovery, the
target agents, the target gateway, and the semantic judge stay on `gemma4-oc`.
The endpoint is public and unauthenticated; keep its URL in the local model
profile only. The `qwen38-rosa` profile runs it with thinking off, and the
`qwen38-rosa-think` profile runs it with thinking on (`reasoning_effort:
medium`) for generation. Both use a 65,536-token context and a 16,384-token
completion cap. This approval does not cover real customer data, publication,
or other providers.

On 2026-10-01 the owner raised the Gemma server's context to 65,536 tokens.
The `gemma4-oc-65k` profile sends the same data to the same `gemma4-oc` endpoint
and model for scenario generation and artifact authoring, with a 65,536-token
context and a 16,384-token completion cap. Discovery, the target agents, and the
semantic judge keep the unchanged `gemma4-oc` profile.

## Thinking-mode limits

Run Gemma and Qwen pipeline roles with thinking off. Each server fails with
thinking on in a way the pipeline cannot recover from:

| Profile family | Failure with thinking on | Evidence |
| --- | --- | --- |
| Gemma (`gemma4-oc`, `gemma4-oc-65k`) | The server (vLLM 0.1.dev17235) stops enforcing the strict JSON response schema. | A probe of 6 schema-bound requests returned 1 clean response, 2 with junk field values, and 3 wrapped in Markdown. |
| Qwen (`qwen38-rosa-think`) | About 3% of requests hang until the 1,200-second request timeout. | A generation needs many requests, so 3 of 4 generations in the qwen-thinking comparison arm failed on a hung request. |

These limits describe the servers as measured on 2026-09-30 and 2026-10-01.
Probe again before you enable thinking after a server upgrade.

## Carry the approval forward

Use this standing approval for work inside the recorded data and destination
scope, including goal continuations and owner-supplied Gemma OC endpoint
replacements. The owner explicitly reaffirmed that this approval had already
been given repeatedly; do not request it again merely because a turn, worker,
or cluster changed. Read the current endpoint from the local model profile.

Select relevant observations for the author; permission to use the synthetic
fixture is not a reason to include unrelated fields. This approval does not
extend to real customer datasets, unrelated providers, publication, or executing
adversarial cases against targets other than the local safe targets recorded
in the 2026-09-25 approval. Ask only when the proposed data use or
destination materially exceeds this scope. Treat infrastructure availability
and data authorisation as separate questions.
