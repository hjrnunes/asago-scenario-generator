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
