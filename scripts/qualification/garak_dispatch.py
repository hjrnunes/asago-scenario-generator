"""One generic adapter seam for the pinned Garak runtime."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from request_ledger import RequestLedger

PINNED_GARAK_REVISION = "06aba1a2c9b142d561eeeff08dfaffcbe77487c3"


@dataclass(frozen=True)
class GarakGeneration:
    generation: int
    raw: dict[str, Any]
    server_commands: tuple[dict[str, Any], ...]
    garak_revision: str = PINNED_GARAK_REVISION


def dispatch_pinned_garak(
    stimulus: dict[str, Any],
    *,
    target_url: str,
    model_url: str,
    model: str,
    ledger: RequestLedger,
    dispatch: Callable[..., dict[str, Any]] | None = None,
    timeout_seconds: float = 180.0,
    max_turns: int = 8,
    garak_root: Path | None = None,
) -> GarakGeneration:
    """Dispatch one bounded generation and retain every observed server command.

    Tests and the live runner provide the transport adapter.  The default
    adapter imports only the pinned checkout at call time, never consumer
    authoring modules.
    """

    if ledger.category != "generation":
        raise ValueError("Garak dispatch requires the generation ledger")
    record = ledger.before_dispatch(
        generation=len(ledger.dispatches) + 1,
        target_url=target_url,
        model_url=model_url,
        model=model,
        timeout_seconds=timeout_seconds,
        max_turns=max_turns,
        garak_revision=PINNED_GARAK_REVISION,
        retries=0,
        refresh_models=False,
    )
    adapter = dispatch or _default_dispatch
    try:
        raw = adapter(
            stimulus=stimulus,
            target_url=target_url,
            model_url=model_url,
            model=model,
            timeout_seconds=timeout_seconds,
            max_turns=max_turns,
            garak_root=garak_root,
        )
    except Exception as exc:  # pragma: no cover - live transport boundary
        ledger.complete(record, status="failed", error=str(exc))
        raise
    if not isinstance(raw, dict):
        ledger.complete(
            record, status="failed", error="Garak adapter returned non-object"
        )
        raise ValueError("Garak adapter returned a non-object")
    commands = raw.get("tool_calls", [])
    if not isinstance(commands, list):
        commands = []
    ledger.complete(record, status="completed", server_commands=len(commands))
    return GarakGeneration(ledger.dispatches[-1]["generation"], raw, tuple(commands))


def _default_dispatch(**kwargs: Any) -> dict[str, Any]:
    """Load the pinned dependency lazily and fail closed without a live setup."""

    garak_root = kwargs["garak_root"]
    if garak_root is None:
        raise RuntimeError(
            "pinned Garak checkout is not configured; pass garak_root explicitly"
        )
    if not garak_root.is_dir():
        raise RuntimeError(f"pinned Garak checkout is unavailable: {garak_root}")
    raise RuntimeError(
        "a configured pinned Garak transport adapter is required for live dispatch"
    )


def generation_record_json(generation: GarakGeneration) -> str:
    return json.dumps(
        {
            "generation": generation.generation,
            "garak_revision": generation.garak_revision,
            "raw": generation.raw,
            "server_commands": list(generation.server_commands),
        },
        sort_keys=True,
    )


__all__ = [
    "GarakGeneration",
    "PINNED_GARAK_REVISION",
    "dispatch_pinned_garak",
    "generation_record_json",
]
