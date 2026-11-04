"""The old import path for the target-discovery scanner; M9 removes it.

The scanner moved to the producer's ``asago-target-discovery`` workspace
member, which installs as ``asago_target_discovery``. This package keeps every
package-root name importable for one cycle and restores each pre-move child
module path with a lazy finder on ``sys.meta_path``: importing an old child
path returns the same module object as the member's module, so private names,
``monkeypatch`` targets and the Typer ``app`` keep working. New code imports
``asago_target_discovery``.
"""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.util
import sys
from typing import Any

import asago_target_discovery

__all__ = list(asago_target_discovery.__all__)

_TARGET_PACKAGE = "asago_target_discovery"
_PREFIX = __name__ + "."

# The child modules of the pre-move package. The finder resolves each lazily,
# so importing this package still loads no child module.
_MOVED_MODULES = (
    "cli",
    "contracts",
    "discovery",
    "llm_interpreter",
    "model_adapter",
    "persistence",
    "prompts",
    "redaction",
    "runtime_contract",
    "transport",
)


class _MovedModuleLoader(importlib.abc.Loader):
    """Import the moved module and leave it in place of the old-name module."""

    def __init__(self, target: str) -> None:
        self._target = target

    def exec_module(self, module: Any) -> None:
        sys.modules[module.__name__] = importlib.import_module(self._target)


class _MovedModuleFinder(importlib.abc.MetaPathFinder):
    """Resolve an old child path to the module that moved to the member."""

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        if not fullname.startswith(_PREFIX):
            return None
        child = fullname[len(_PREFIX) :]
        if child not in _MOVED_MODULES:
            return None
        moved = f"{_TARGET_PACKAGE}.{child}"
        return importlib.util.spec_from_loader(
            fullname, _MovedModuleLoader(moved), origin=moved
        )


def _install_moved_module_finder() -> None:
    finders = sys.meta_path
    if not any(isinstance(finder, _MovedModuleFinder) for finder in finders):
        finders.insert(0, _MovedModuleFinder())


_install_moved_module_finder()


def __getattr__(name: str) -> Any:
    try:
        value = getattr(asago_target_discovery, name)
    except AttributeError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *dir(asago_target_discovery)})
