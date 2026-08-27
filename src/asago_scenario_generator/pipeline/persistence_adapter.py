"""Public finalization persistence adapter assembled from local mixins."""

from __future__ import annotations

from .persistence_adapter_core import _PersistenceAdapterCore
from .persistence_adapter_events import _PersistenceAdapterEventMethods
from .persistence_adapter_terminal_methods import _PersistenceAdapterTerminalMethods


class FinalizationPersistenceAdapter(
    _PersistenceAdapterCore,
    _PersistenceAdapterEventMethods,
    _PersistenceAdapterTerminalMethods,
):
    """Journaled, durable implementation of ``FinalizationPersistencePort``."""

    pass
