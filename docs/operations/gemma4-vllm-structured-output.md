# Gemma 4 structured output with vLLM

Gemma 4 model deployments used by the taxonomy/risk pipeline must prevent
unbounded whitespace in grammar-constrained JSON responses. Configure vLLM at
server startup with:

```text
--structured-outputs-config={"backend":"xgrammar","disable_any_whitespace":true}
```

This is a serving-runtime requirement, not a model-profile option. The client
already requests Pydantic structured responses. In affected vLLM releases, a
request-level whitespace option is not a reliable replacement for the
server-level setting.

## OpenShift AI example

For a `ServingRuntime`, add the argument to the model-server container:

```yaml
spec:
  containers:
    - args:
        - '--structured-outputs-config={"backend":"xgrammar","disable_any_whitespace":true}'
```

A model with two GPU replicas can deadlock during a default percentage-based
rollout when the cluster has no spare GPU and `maxUnavailable` rounds to zero.
Use an explicitly bounded rolling strategy on the `InferenceService` when that
topology applies:

```yaml
spec:
  predictor:
    deploymentStrategy:
      type: RollingUpdate
      rollingUpdate:
        maxSurge: 1
        maxUnavailable: 1
```

This strategy temporarily allows one existing replica to become unavailable;
apply it only when that availability tradeoff is acceptable.

## Validation

Validate the change in three layers before launching an exhaustive run:

1. Confirm the effective pod arguments contain the compact xgrammar setting.
2. Replay a small fixed-seed structured request and require `finish_reason` to
   be `stop` with schema-valid JSON.
3. Run a bounded application canary and confirm its call log contains no
   completion-length failures with whitespace-only suffixes.

On 2026-08-22, the `gemma-4-26b-a4b-it` deployment in the `model-serving`
namespace passed a 10-seed structured-response matrix with 10/10 valid JSON
responses after this change. Both replicas were ready with zero restarts before
the subsequent exhaustive application run.

The corresponding full-run record is in
[Klarna non-STPA exhaustive validation](../validation/klarna-non-stpa-exhaustive-2026-08-22.md).
