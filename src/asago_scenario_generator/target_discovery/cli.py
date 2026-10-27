"""Standalone ``asago-target-scan`` command."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer
import yaml
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.execution_classification import DiscoveryMode
from asago_scenario_generator.stpa.models.value_facts import TargetValueFacts

from .contracts import McpInventoryAdapter, McpTargetDiscoveryInputs
from .discovery import discover_mcp_target
from .llm_interpreter import TargetDiscoveryLlmInterpreter
from .persistence import write_target_discovery
from .transport import (
    FileMcpInventoryAdapter,
    HttpMcpInventoryAdapter,
    McpToolsListFileError,
)


app = typer.Typer(
    name="asago-target-scan",
    help="Independently discover and persist an execution target profile.",
    no_args_is_help=True,
)

# Options shared by every inventory source; orchestration builds each command
# line the same way.
TargetIdOption = Annotated[
    str, typer.Option("--target-id", help="Stable non-secret target ID.")
]
AuthorizationScopeOption = Annotated[
    str,
    typer.Option(
        "--authorization-scope", help="Stable non-secret authorization-scope label."
    ),
]
OutputDirOption = Annotated[
    Path,
    typer.Option("--output-dir", help="Directory for the four scanner artifacts."),
]
ProfileOption = Annotated[
    str | None,
    typer.Option(
        "--profile",
        help=(
            "Optional semantic interpreter model-profile label. Without it, "
            "semantic records remain unresolved and no model call is made."
        ),
    ),
]
ProfilesFileOption = Annotated[
    Path,
    typer.Option(
        "--profiles-file",
        help="Named model-profile file used when --profile is supplied.",
    ),
]
ModeOption = Annotated[
    str,
    typer.Option("--mode", help="Discovery mode; only schema_only is supported."),
]
InterpretationBatchSizeOption = Annotated[
    int,
    typer.Option(
        "--interpretation-batch-size",
        min=1,
        max=128,
        help="Maximum tools included in each semantic interpretation call.",
    ),
]
ValueFactsOption = Annotated[
    Path | None,
    typer.Option(
        "--value-facts",
        help=(
            "YAML or JSON file of the record kinds and date formats the target "
            "declares for its argument and state values; the profile carries "
            "it as value_facts, with the date formats the tool input schemas "
            "declare."
        ),
    ),
]


@app.callback()
def main() -> None:
    """Select a protocol-specific target-discovery command."""


@app.command("mcp")
def scan_mcp(
    server_url: str = typer.Option(
        ...,
        "--server-url",
        help="Runtime MCP SSE endpoint; never persisted in the profile.",
    ),
    *,
    target_id: TargetIdOption,
    authorization_scope: AuthorizationScopeOption,
    output_dir: OutputDirOption,
    profile: ProfileOption = None,
    profiles_file: ProfilesFileOption = Path("config/model-profiles.yaml"),
    mode: ModeOption = DiscoveryMode.schema_only.value,
    interpretation_batch_size: InterpretationBatchSizeOption = 8,
    timeout: float = typer.Option(30.0, "--timeout", min=0.1),
    value_facts: ValueFactsOption = None,
) -> None:
    """Scan one MCP tools/list inventory and write a self-contained profile."""
    _scan(
        lambda: HttpMcpInventoryAdapter(server_url, timeout=timeout),
        target_id=target_id,
        authorization_scope=authorization_scope,
        output_dir=output_dir,
        profile=profile,
        profiles_file=profiles_file,
        mode=mode,
        interpretation_batch_size=interpretation_batch_size,
        value_facts=value_facts,
    )


@app.command("file")
def scan_file(
    tools_list: Path = typer.Option(
        ...,
        "--tools-list",
        help=(
            "JSON file holding an MCP tools/list result, or a list of result "
            "pages served in order and linked by nextCursor."
        ),
    ),
    *,
    target_id: TargetIdOption,
    authorization_scope: AuthorizationScopeOption,
    output_dir: OutputDirOption,
    profile: ProfileOption = None,
    profiles_file: ProfilesFileOption = Path("config/model-profiles.yaml"),
    mode: ModeOption = DiscoveryMode.schema_only.value,
    interpretation_batch_size: InterpretationBatchSizeOption = 8,
    value_facts: ValueFactsOption = None,
) -> None:
    """Profile a declared target from an MCP tools/list file without a server."""
    _scan(
        lambda: _file_adapter(tools_list),
        target_id=target_id,
        authorization_scope=authorization_scope,
        output_dir=output_dir,
        profile=profile,
        profiles_file=profiles_file,
        mode=mode,
        interpretation_batch_size=interpretation_batch_size,
        value_facts=value_facts,
    )


def _scan(
    adapter_factory: Callable[[], McpInventoryAdapter],
    *,
    target_id: str,
    authorization_scope: str,
    output_dir: Path,
    profile: str | None,
    profiles_file: Path,
    mode: str,
    interpretation_batch_size: int,
    value_facts: Path | None = None,
) -> None:
    """Discover one inventory, persist its artifacts and set the exit code."""
    if mode != DiscoveryMode.schema_only.value:
        raise typer.BadParameter(
            f"only schema_only is supported, got {mode!r}", param_hint="--mode"
        )
    facts = _load_value_facts(value_facts) if value_facts is not None else None
    adapter = adapter_factory()
    inputs = McpTargetDiscoveryInputs(
        target_id=target_id,
        authorization_scope_id=authorization_scope,
        mode=DiscoveryMode.schema_only,
        model_profile=profile,
        interpretation_batch_size=interpretation_batch_size,
        value_facts=facts,
    )
    interpreter_factory = None
    if profile is not None:
        interpreter_factory = _load_interpreter(profiles_file, profile, output_dir)
        model_name = getattr(interpreter_factory, "model_name", None)
        if model_name is not None:
            inputs = inputs.model_copy(update={"model_name": model_name})
    result = discover_mcp_target(
        inputs,
        adapter,
        interpreter_factory=interpreter_factory,
    )
    written = write_target_discovery(output_dir, result)
    typer.echo(f"target discovery wrote {len(written)} artifact(s) to {output_dir}")
    for path in written.values():
        typer.echo(path.name)
    if result.profile is None:
        raise typer.Exit(code=1)
    if not result.valid:
        raise typer.Exit(code=2)


def _file_adapter(tools_list: Path) -> FileMcpInventoryAdapter:
    """Check the whole file before discovery; a bad file writes nothing.

    The error is one unwrapped line so the file path stays intact in logs.
    """
    try:
        return FileMcpInventoryAdapter(tools_list)
    except McpToolsListFileError as exc:
        typer.echo(f"Error: invalid --tools-list: {exc}", err=True)
        raise typer.Exit(code=2) from exc


def _load_value_facts(path: Path) -> TargetValueFacts:
    """Read the declared value facts; a bad file stops the scan before it starts."""
    try:
        return TargetValueFacts.model_validate(
            yaml.safe_load(path.read_text(encoding="utf-8"))
        )
    except (OSError, yaml.YAMLError, ValidationError) as exc:
        raise typer.BadParameter(
            f"could not read value facts from {path}: {exc}",
            param_hint="--value-facts",
        ) from exc


def _load_interpreter(
    profiles_file: Path, profile: str, output_dir: Path
) -> TargetDiscoveryLlmInterpreter:
    try:
        return TargetDiscoveryLlmInterpreter.from_profile(
            profiles_file, profile, run_dir=output_dir
        )
    except (OSError, ValueError, KeyError) as exc:
        raise typer.BadParameter(
            f"could not load named model profile ({type(exc).__name__})",
            param_hint="--profile",
        ) from exc


__all__ = ["app", "scan_file", "scan_mcp"]


if __name__ == "__main__":  # pragma: no cover - console entry point is preferred
    app()
