"""Standalone ``asago-target-scan`` command."""

from __future__ import annotations

import os
from pathlib import Path

import typer

from asago_scenario_generator.stpa.models.execution_classification import DiscoveryMode

from .contracts import McpTargetDiscoveryInputs
from .discovery import discover_mcp_target
from .llm_interpreter import TargetDiscoveryLlmInterpreter
from .persistence import write_target_discovery
from .transport import HttpMcpInventoryAdapter


app = typer.Typer(
    name="asago-target-scan",
    help="Independently discover and persist an execution target profile.",
    no_args_is_help=True,
)


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
    target_id: str = typer.Option(
        ..., "--target-id", help="Stable non-secret target ID."
    ),
    authorization_scope: str = typer.Option(
        ...,
        "--authorization-scope",
        help="Stable non-secret authorization-scope label.",
    ),
    output_dir: Path = typer.Option(
        ...,
        "--output-dir",
        help="Directory for the four scanner artifacts.",
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        help=(
            "Optional semantic interpreter model-profile label. Without it, "
            "semantic records remain unresolved and no model call is made."
        ),
    ),
    model_name: str | None = typer.Option(
        None,
        "--model-name",
        help="Optional non-secret model identity for provenance.",
    ),
    profiles_file: Path = typer.Option(
        Path("config/model-profiles.yaml"),
        "--profiles-file",
        help="Named model-profile file used when --profile is supplied.",
    ),
    mode: str = typer.Option(
        DiscoveryMode.schema_only.value,
        "--mode",
        help="schema_only or disposable_test_environment.",
    ),
    auth_header_env: str | None = typer.Option(
        None,
        "--auth-header-env",
        help="Environment variable containing a runtime Authorization header value.",
    ),
    inspect_tool: list[str] = typer.Option(
        [],
        "--inspect-tool",
        help="Tool name to call only in disposable_test_environment mode (repeatable).",
    ),
    max_inspection_calls: int = typer.Option(
        8,
        "--max-inspection-calls",
        min=0,
        max=32,
        help="Bound for explicitly requested disposable inspection calls.",
    ),
    interpretation_batch_size: int = typer.Option(
        8,
        "--interpretation-batch-size",
        min=1,
        max=128,
        help="Maximum tools included in each semantic interpretation call.",
    ),
    timeout: float = typer.Option(30.0, "--timeout", min=0.1),
) -> None:
    """Scan one MCP tools/list inventory and write a self-contained profile."""
    try:
        selected_mode = DiscoveryMode(mode)
    except ValueError as exc:
        raise typer.BadParameter(
            "must be schema_only or disposable_test_environment", param_hint="--mode"
        ) from exc
    if inspect_tool and selected_mode is DiscoveryMode.schema_only:
        raise typer.BadParameter(
            "--inspect-tool requires --mode disposable_test_environment",
            param_hint="--inspect-tool",
        )
    headers: dict[str, str] = {}
    if auth_header_env:
        value = os.environ.get(auth_header_env)
        if value:
            headers["Authorization"] = value
        else:
            raise typer.BadParameter(
                f"environment variable {auth_header_env!r} is not set",
                param_hint="--auth-header-env",
            )
    inputs = McpTargetDiscoveryInputs(
        target_id=target_id,
        authorization_scope_id=authorization_scope,
        mode=selected_mode,
        model_profile=profile,
        model_name=model_name,
        active_inspection_tool_names=tuple(inspect_tool),
        max_active_inspection_calls=max_inspection_calls,
        interpretation_batch_size=interpretation_batch_size,
    )
    interpreter_factory = None
    resolved_model_name = model_name
    if profile is not None:
        try:
            interpreter_factory = TargetDiscoveryLlmInterpreter.from_profile(
                profiles_file, profile
            )
        except (OSError, ValueError, KeyError) as exc:
            raise typer.BadParameter(
                f"could not load named model profile ({type(exc).__name__})",
                param_hint="--profile",
            ) from exc
        if resolved_model_name is None:
            resolved_model_name = getattr(interpreter_factory, "model_name", None)
        if resolved_model_name is not None:
            inputs = inputs.model_copy(update={"model_name": resolved_model_name})
    adapter = HttpMcpInventoryAdapter(
        server_url,
        headers=headers,
        timeout=timeout,
    )
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


__all__ = ["app", "scan_mcp"]


if __name__ == "__main__":  # pragma: no cover - console entry point is preferred
    app()
