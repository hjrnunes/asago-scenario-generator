"""The Stage 2 review in force, its verdict, and its canonical publication.

One semantic review, the graph it produced and the post-review verdict on that
graph travel together as a :class:`ReviewOutcome`.  The review loop returns the
outcome both when the graph passes and when it fails closed, so the caller can
publish the graph the failure evidence names before it raises.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.infra.yaml_io import VersionChain
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model.semantic_review import (
    ControlStructureSemanticReview,
    SemanticReviewResult,
)


@dataclass(frozen=True)
class ReviewOutcome:
    """The review in force and the post-review verdict on its graph.

    ``review`` is the review whose unresolved records the density re-check
    exempts.  ``failure`` is set when the graph still fails after the bounded
    correction round, and it carries the exact still-failing checks.
    """

    result: SemanticReviewResult
    review: ControlStructureSemanticReview
    failure: StageError | None = None

    @property
    def loss_analysis(self) -> LossAnalysis:
        """Return the reviewed loss graph."""
        return self.result.loss_analysis

    @property
    def control_structure(self) -> ControlStructure:
        """Return the control structure the review left in force."""
        return self.result.control_structure

    @property
    def passed(self) -> bool:
        """Return whether the review's graph passed the post-review check."""
        return self.failure is None

    def raise_for_failure(self) -> None:
        """Raise the recorded failure, if any.

        The caller publishes the outcome first, so a failed run leaves the
        canonical graph and the failure evidence describing the same graph.
        """
        if self.failure is not None:
            raise self.failure


# (failing checks, hazard IDs, constraint IDs) -> the corrected review outcome.
ReviewCorrection = Callable[
    [tuple[str, ...], tuple[str, ...], tuple[str, ...]], ReviewOutcome
]


def publish_review_outcome(outcome: ReviewOutcome, versions: VersionChain) -> None:
    """Write the reviewed graph in force as the canonical ``loss-analysis.yaml``.

    This is the one canonical publication of the stage.  It happens whether
    the outcome passed or failed, so the published graph and the failure
    evidence cannot describe different graphs.
    """
    versions.publish(outcome.loss_analysis, "loss-analysis.yaml")
