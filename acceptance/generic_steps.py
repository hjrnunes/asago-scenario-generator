"""Generic step handlers shared by feature steps that check the same thing."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from runtime_shared import _SP1MockLLM
from runtime_world import World

Handler = Callable[[World, str, dict], tuple[bool, str]]


def noop(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Accept a step that asserts nothing."""
    return True, ""


def world_present(*keys: str, message: str) -> Handler:
    """Pass when at least one of the named world attributes is set."""

    def handler(world: World, text: str, examples: dict) -> tuple[bool, str]:
        if all(getattr(world, key) is None for key in keys):
            return False, message
        return True, ""

    return handler


def llm_raises(response_model: Any, message: str) -> Handler:
    """Make the scenario's mock LLM raise for one response model."""

    def handler(world: World, text: str, examples: dict) -> tuple[bool, str]:
        client = world.sp1_mock_client or _SP1MockLLM()
        world.sp1_mock_client = client
        client.set_exception_for(response_model, RuntimeError(message))
        return True, ""

    return handler
