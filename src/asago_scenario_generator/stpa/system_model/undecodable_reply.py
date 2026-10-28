"""The correction wording for a reply that does not decode as JSON."""

from __future__ import annotations

import json
from collections.abc import Callable

from asago_scenario_generator.stpa.infra.templates import TemplateLoader

UNDECODABLE_CORRECTION_TEMPLATE = "undecodable_reply_correction.j2"


def decode_aware_feedback(
    loader: TemplateLoader, *, reply_name: str, feedback: str | None = None
) -> Callable[[Exception], str]:
    """Word a correction for an undecodable reply apart from other failures.

    A decode error gets the undecodable-reply instruction, which names the
    call's reply as *reply_name*.  Every other failure keeps *feedback*, so
    its correction request stays the same.
    """

    def word(error: Exception) -> str:
        if isinstance(error, json.JSONDecodeError):
            return "\n\n" + loader.render_prompt(
                UNDECODABLE_CORRECTION_TEMPLATE, reply_name=reply_name
            )
        return feedback or ""

    return word
