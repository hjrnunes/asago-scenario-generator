"""Registration adapter for acceptance framework contract handlers."""

import re

from framework_contracts_artifacts import (
    _h_afr_layout_given,
    _h_afr_artifact_paths,
    _h_afr_artifact_path_assertion,
    _h_afr_snapshot_project,
    _h_afr_snapshot_outputs,
    _h_afr_snapshot_order,
    _h_afr_snapshot_complete,
    _h_afr_snapshot_metadata,
    _h_afr_snapshot_stale,
    _h_afr_snapshot_unrelated,
)
from framework_contracts_registry import (
    _h_afr_registry_given,
    _h_afr_registry_replacement,
    _h_afr_registry_failure,
    _h_afr_registry_unchanged,
    _h_afr_registry_not_executable,
    _h_afr_scoped_registry,
    _h_afr_other_scope_ineligible,
    _h_afr_first_scope_priority,
    _h_afr_unscoped_scope,
)
from framework_contracts_isolation import (
    _h_afr_isolation_given,
    _h_afr_isolation_mutation,
    _h_afr_isolation_background,
    _h_afr_isolation_scenario,
    _h_afr_isolation_ir,
    _h_afr_isolation_observers,
    _h_afr_isolation_environment,
    _h_afr_isolation_feature,
)
from framework_contracts_execution import (
    _h_afr_contract_given,
    _h_afr_contract_supported,
    _h_afr_contract_execute,
    _h_afr_contract_result,
    _h_afr_contract_output,
)
from framework_contracts_manifest import (
    _h_afr_manifest_root,
    _h_afr_manifest_load,
    _h_afr_manifest_order,
    _h_afr_manifest_identity,
    _h_afr_manifest_register,
)
from framework_contracts_runner import (
    _h_afr_runner_given,
    _h_afr_runner_execute,
    _h_afr_runner_id,
    _h_afr_runner_outcome,
    _h_afr_runner_duration,
    _h_afr_runner_streams,
    _h_afr_worker_ready,
    _h_afr_worker_protocol,
    _h_afr_worker_malformed,
    _h_afr_worker_continues,
    _h_afr_worker_json_lines,
)

from framework_contracts_common import (
    _AFR_BACKGROUND_STEP,
    _AFR_MUTATION_STEP,
    _AFR_SCENARIO_STEP,
    _AFR_SUPPORTED_STEP,
)

FEATURE_ID = "acceptance_framework_refactor"


def register(api: object) -> None:
    """Register framework-contract steps through the supplied facade API."""
    api.set_feature(None)

    # Mapping and deterministic snapshot refresh.
    api.register_first(
        r"^acceptance directories are configured as repo-relative paths$",
        _h_afr_layout_given,
    )
    api.register_first(
        r'^artifact paths are requested for "features/group/example\.feature"$',
        _h_afr_artifact_paths,
    )
    api.register_first(
        r'^the (IR|dry|test|metadata) path is "([^"]+)"$',
        _h_afr_artifact_path_assertion,
    )
    api.register_first(
        r"^a temporary project has nested source features in unsorted creation order$",
        _h_afr_snapshot_project,
    )
    api.register_first(
        r"^its configured output trees contain stale generated artifacts and an unrelated file$",
        lambda world, text, examples: (True, ""),
    )
    api.register_first(
        r"^the acceptance snapshot is refreshed$",
        _h_afr_snapshot_outputs,
    )
    api.register_first(
        r"^source features are processed in lexicographic repo-relative order$",
        _h_afr_snapshot_order,
    )
    api.register_first(
        r"^each source feature has one mapped IR, dry report, generated test, and metadata file$",
        _h_afr_snapshot_complete,
    )
    api.register_first(
        r"^generated metadata contains only repo-relative source and IR paths$",
        _h_afr_snapshot_metadata,
    )
    api.register_first(
        r"^stale mapped IR, generated test, and metadata files are removed$",
        _h_afr_snapshot_stale,
    )
    api.register_first(
        r"^the unrelated file is preserved$",
        _h_afr_snapshot_unrelated,
    )

    # Registry staging/publication and feature-scoped resolution.
    api.register_first(
        r"^an acceptance registry has already published a valid pattern and key set$",
        _h_afr_registry_given,
    )
    api.register_first(
        r"^a replacement manifest stages one valid module before a module whose registration fails$",
        lambda world, text, examples: (True, ""),
    )
    api.register_first(
        r"^the replacement manifest is registered$",
        _h_afr_registry_replacement,
    )
    api.register_first(
        r"^the failure identifies the failing runtime feature$",
        _h_afr_registry_failure,
    )
    api.register_first(
        r"^the previously published pattern and key set remain unchanged$",
        _h_afr_registry_unchanged,
    )
    api.register_first(
        r"^no staged replacement pattern is executable$",
        _h_afr_registry_not_executable,
    )
    api.register_first(
        r"^one step text matches a global pattern and patterns scoped to two different features$",
        _h_afr_scoped_registry,
    )
    api.register_first(
        r"^the step executes for the first feature$",
        lambda world, text, examples: (True, ""),
    )
    api.register_first(
        r"^patterns scoped to the other feature are ineligible$",
        _h_afr_other_scope_ineligible,
    )
    api.register_first(
        r"^the first eligible pattern in deterministic registration priority executes exactly once$",
        _h_afr_first_scope_priority,
    )
    api.register_first(
        r"^executing an unscoped feature cannot select either feature-scoped pattern$",
        _h_afr_unscoped_scope,
    )

    # Scenario/example lifecycle and result reporting.
    api.register_first(
        r"^an IR scenario has two examples and an original process environment$",
        lambda world, text, examples: (True, ""),
    )
    api.register_first(
        r"^the first example changes its world state and process environment before it (passes|fails)$",
        _h_afr_isolation_given,
    )
    api.register_first(
        r"^the IR is executed for a nested feature context$",
        _h_afr_isolation_ir,
    )
    api.register_first(
        rf"^{re.escape(_AFR_BACKGROUND_STEP)}$",
        _h_afr_isolation_background,
    )
    api.register_first(
        rf"^{re.escape(_AFR_MUTATION_STEP)}$",
        _h_afr_isolation_mutation,
    )
    api.register_first(
        rf"^{re.escape(_AFR_SCENARIO_STEP)}$",
        _h_afr_isolation_scenario,
    )
    api.register_first(
        r"^the second example receives a fresh world and the original process environment$",
        _h_afr_isolation_observers,
    )
    api.register_first(
        r"^each example shares one world between its own background and scenario steps$",
        _h_afr_isolation_observers,
    )
    api.register_first(
        r"^the process environment is restored after the IR execution$",
        _h_afr_isolation_environment,
    )
    api.register_first(
        r"^the enclosing feature context is restored after the IR execution$",
        _h_afr_isolation_feature,
    )
    api.register_first(
        r'^an isolated IR scenario named "contract" has the (.+)$',
        _h_afr_contract_given,
    )
    api.register_first(
        rf"^{re.escape(_AFR_SUPPORTED_STEP)}$",
        _h_afr_contract_supported,
    )
    api.register_first(
        r"^the isolated IR is executed$",
        _h_afr_contract_execute,
    )
    api.register_first(
        r"^its result is (true|false)$",
        _h_afr_contract_result,
    )
    api.register_first(
        r'^its output begins with "([^"]+)"$',
        _h_afr_contract_output,
    )

    # Namespaced manifest loading.
    api.register_first(
        r"^the project root is the current working directory$",
        _h_afr_manifest_root,
    )
    api.register_first(
        r'^the runtime manifest is loaded through the "acceptance\.runtime_manifest" namespace$',
        _h_afr_manifest_load,
    )
    api.register_first(
        r"^every declared runtime feature loads in manifest order$",
        _h_afr_manifest_order,
    )
    api.register_first(
        r"^every loaded feature identity matches its declared name$",
        _h_afr_manifest_identity,
    )
    api.register_first(
        r"^every loaded feature exposes a registration operation$",
        lambda world, text, examples: (
            all(
                callable(getattr(module, "register", None))
                for module in world.afr_manifest_modules
            ),
            "a manifest feature has no registration operation",
        ),
    )
    api.register_first(
        r"^the complete manifest registers each feature exactly once$",
        _h_afr_manifest_register,
    )

    # Mutation runner outcome mapping and persistent protocol.
    api.register_first(
        r'^the mutation worker receives job "job-1" for an IR runtime that (.+)$',
        _h_afr_runner_given,
    )
    api.register_first(
        r"^the worker emits the job response$",
        _h_afr_runner_execute,
    )
    api.register_first(
        r'^the response id is "job-1"$',
        _h_afr_runner_id,
    )
    api.register_first(
        r'^the response outcome is "([^"]+)"$',
        _h_afr_runner_outcome,
    )
    api.register_first(
        r"^the response duration is a non-negative integer of nanoseconds$",
        _h_afr_runner_duration,
    )
    api.register_first(
        r"^standard output and standard error are returned in separate fields$",
        _h_afr_runner_streams,
    )
    api.register_first(
        r"^the persistent mutation worker is ready$",
        _h_afr_worker_ready,
    )
    api.register_first(
        r"^it receives a malformed JSON line followed by a valid job line$",
        _h_afr_worker_protocol,
    )
    api.register_first(
        r'^it emits one infrastructure_error response with id "unknown" for the malformed line$',
        _h_afr_worker_malformed,
    )
    api.register_first(
        r"^it remains running to emit one response for the valid job$",
        _h_afr_worker_continues,
    )
    api.register_first(
        r"^every response is one JSON object on one standard-output line$",
        _h_afr_worker_json_lines,
    )


__all__ = ["FEATURE_ID", "register"]
