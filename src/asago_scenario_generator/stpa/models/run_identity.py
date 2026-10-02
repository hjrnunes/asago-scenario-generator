"""Run identity recorded in the SP3 run manifest."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, StrictStr

PRODUCER_NAME = "asago-scenario-generator"
PRODUCER_VERSION = "0.1.0"


class ExecutionRunIdentity(BaseModel):
    """Run identity and producer metadata for one SP3 run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: StrictStr = Field(min_length=1)
    producer_name: StrictStr = PRODUCER_NAME
    producer_version: StrictStr = PRODUCER_VERSION


__all__ = ["PRODUCER_NAME", "PRODUCER_VERSION", "ExecutionRunIdentity"]
