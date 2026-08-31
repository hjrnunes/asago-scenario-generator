"""Typed semantic operations shared by resources and attack-pattern slots."""

from __future__ import annotations

from typing import Literal


ResourceOperation = Literal["retrieve_data", "transmit_data", "execute_code"]
