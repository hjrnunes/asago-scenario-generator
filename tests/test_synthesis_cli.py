"""Public CLI tests for synthesis terminal outcomes."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from typer.testing import CliRunner

import yaml

from asago_scenario_generator.cli import app
from asago_scenario_generator.cli.synthesis import _synthesis_run_status
from asago_scenario_generator.pipeline.synthesis import SynthesisRunStatus


def _input_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    risk = tmp_path / "risk-extraction.json"
    facts = tmp_path / "qualification-facts.json"
    sssom = tmp_path / "mapping.tsv"
    risk.write_text("{}", encoding="utf-8")
    facts.write_text("{}", encoding="utf-8")
    sssom.write_text("", encoding="utf-8")
    return risk, facts, sssom


def _result(output_dir: Path, status: str) -> SimpleNamespace:
    plan = output_dir / "taxonomy-obligation-plan.yaml"
    plan.parent.mkdir(parents=True, exist_ok=True)
    plan.write_text("schema_version: acceptance\n", encoding="utf-8")
    return SimpleNamespace(
        output_dir=output_dir,
        artifact_paths={"taxonomy-obligation-plan.yaml": plan},
        report_path=None,
        phase2_verification=SimpleNamespace(status="awaiting_evidence"),
        run_status=status,
    )


def _invoke_run(tmp_path: Path, *, status: str) -> object:
    risk, facts, sssom = _input_files(tmp_path)
    output_dir = tmp_path / "run"
    fake = _result(output_dir, status)
    with (
        patch(
            "asago_scenario_generator.data.loaders.load_reviewed_risk_extraction",
            return_value=(),
        ),
        patch(
            "asago_scenario_generator.pipeline.synthesis.run_synthesis",
            return_value=fake,
        ),
    ):
        return CliRunner().invoke(
            app,
            [
                "run",
                "--use-case",
                "a deterministic system",
                "--risk-extraction",
                str(risk),
                "--qualification-facts",
                str(facts),
                "--sssom",
                str(sssom),
                "--output-dir",
                str(output_dir),
            ],
        )


def test_product_cli_returns_nonzero_after_printing_artifacts_for_zero_yield(
    tmp_path: Path,
) -> None:
    """A failed zero-yield run reports its published artifact before exiting."""
    result = _invoke_run(tmp_path, status="failed")

    assert result.exit_code == 1
    assert "Synthesis artifacts written to:" in result.stdout
    assert "taxonomy-obligation-plan.yaml" in result.stdout
    assert "Scenario generation: failed" in result.stdout
    assert "published no scenarios after attempting candidates" in result.stderr


def test_product_cli_keeps_valid_no_candidate_and_degraded_runs_successful(
    tmp_path: Path,
) -> None:
    """No-candidate analysis and partial yield do not become CLI failures."""
    no_candidates = _invoke_run(tmp_path / "none", status="no_candidates")
    degraded = _invoke_run(tmp_path / "partial", status="degraded")

    assert no_candidates.exit_code == 0
    assert "Scenario generation: no_candidates" in no_candidates.stdout
    assert degraded.exit_code == 0
    assert "Scenario generation: degraded" in degraded.stdout


def test_product_cli_threads_pinned_loss_analysis(tmp_path: Path) -> None:
    """A valid --loss-analysis file is threaded to the synthesis inputs."""
    from asago_scenario_generator.pipeline.synthesis import SynthesisInputs
    from tests.stpa.sp1_helpers import valid_loss_analysis_dict

    payload = valid_loss_analysis_dict()
    payload["risk_dispositions"] = [
        {
            "risk_ref": "atlas-001",
            "disposition": "cited",
            "loss_ids": ["L-1"],
            "reason": None,
        }
    ]
    risk, facts, sssom = _input_files(tmp_path)
    pinned = tmp_path / "loss-analysis.yaml"
    pinned.write_text(
        yaml.safe_dump(payload), encoding="utf-8"
    )
    output_dir = tmp_path / "run"
    fake = _result(output_dir, "completed")
    captured: list[SynthesisInputs] = []

    def _capture(inputs, adapter):
        captured.append(inputs)
        return fake

    with (
        patch(
            "asago_scenario_generator.data.loaders.load_reviewed_risk_extraction",
            return_value=(),
        ),
        patch(
            "asago_scenario_generator.pipeline.synthesis.run_synthesis",
            side_effect=_capture,
        ),
    ):
        result = CliRunner().invoke(
            app,
            [
                "run",
                "--use-case",
                "a deterministic system",
                "--risk-extraction",
                str(risk),
                "--qualification-facts",
                str(facts),
                "--sssom",
                str(sssom),
                "--output-dir",
                str(output_dir),
                "--loss-analysis",
                str(pinned),
            ],
        )

    assert result.exit_code == 0
    assert len(captured) == 1
    assert captured[0].loss_analysis_path == pinned


def test_product_cli_rejects_missing_pinned_loss_analysis(tmp_path: Path) -> None:
    """A --loss-analysis path that does not exist aborts the run."""
    risk, facts, sssom = _input_files(tmp_path)
    output_dir = tmp_path / "run"

    result = CliRunner().invoke(
        app,
        [
            "run",
            "--use-case",
            "a deterministic system",
            "--risk-extraction",
            str(risk),
            "--qualification-facts",
            str(facts),
            "--sssom",
            str(sssom),
            "--output-dir",
            str(output_dir),
            "--loss-analysis",
            str(tmp_path / "absent.yaml"),
        ],
    )

    assert result.exit_code != 0
    assert "loss analysis file" in result.stderr


def test_product_cli_rejects_malformed_pinned_loss_analysis(tmp_path: Path) -> None:
    """A pinned file that is not a LossAnalysis aborts before any run work."""
    risk, facts, sssom = _input_files(tmp_path)
    pinned = tmp_path / "loss-analysis.yaml"
    pinned.write_text("not: a loss analysis\n", encoding="utf-8")
    output_dir = tmp_path / "run"

    result = CliRunner().invoke(
        app,
        [
            "run",
            "--use-case",
            "a deterministic system",
            "--risk-extraction",
            str(risk),
            "--qualification-facts",
            str(facts),
            "--sssom",
            str(sssom),
            "--output-dir",
            str(output_dir),
            "--loss-analysis",
            str(pinned),
        ],
    )

    assert result.exit_code != 0


def _target_companion_files(tmp_path: Path) -> tuple[Path, Path]:
    """A valid target profile file and its paired observations file."""
    import json

    from tests.stpa.test_target_derived_structure import _profile

    profile = _profile()
    profile_path = tmp_path / "execution-target-profile.yaml"
    profile_path.write_text(
        yaml.safe_dump(profile.model_dump(mode="json")), encoding="utf-8"
    )
    observations_path = tmp_path / "target-observations.json"
    observations_path.write_text(
        json.dumps(
            {
                "state": {"authenticated_customer_id": "CUST001"},
                "read_observations": [],
                "target_profile_digest": profile.semantic_digest,
            }
        ),
        encoding="utf-8",
    )
    return profile_path, observations_path


def _invoke_run_with_subject_model(
    tmp_path: Path, extra: list[str]
) -> object:
    risk, facts, sssom = _input_files(tmp_path)
    output_dir = tmp_path / "run"
    fake = _result(output_dir, "completed")
    with (
        patch(
            "asago_scenario_generator.data.loaders.load_reviewed_risk_extraction",
            return_value=(),
        ),
        patch(
            "asago_scenario_generator.pipeline.synthesis.run_synthesis",
            return_value=fake,
        ),
    ):
        return CliRunner().invoke(
            app,
            [
                "run",
                "--use-case",
                "a deterministic system",
                "--risk-extraction",
                str(risk),
                "--qualification-facts",
                str(facts),
                "--sssom",
                str(sssom),
                "--output-dir",
                str(output_dir),
                *extra,
            ],
        )


def test_product_cli_subject_model_requires_observations_and_profile(
    tmp_path: Path,
) -> None:
    """--target-subject-model without its target inputs aborts the run."""
    model_path = tmp_path / "target-subject-model.yaml"
    model_path.write_text(
        'session_path: ["authenticated_customer_id"]\n', encoding="utf-8"
    )

    result = _invoke_run_with_subject_model(
        tmp_path, ["--target-subject-model", str(model_path)]
    )

    assert result.exit_code != 0
    assert (
        "--target-subject-model requires --target-observations and "
        "--target-profile" in result.stderr
    )


def test_product_cli_rejects_an_unreviewed_subject_model(tmp_path: Path) -> None:
    """A proposed (unstamped) subject model fails closed before any call."""
    from asago_scenario_generator.stpa.models.target_subject_model import (
        TargetSubjectModel,
    )

    profile_path, observations_path = _target_companion_files(tmp_path)
    model = TargetSubjectModel(
        session_path=("authenticated_customer_id",), subject_noun="customer"
    )
    model_path = tmp_path / "target-subject-model.yaml"
    model_path.write_text(
        yaml.safe_dump(model.model_dump(mode="json", exclude_none=True)),
        encoding="utf-8",
    )

    result = _invoke_run_with_subject_model(
        tmp_path,
        [
            "--target-profile",
            str(profile_path),
            "--target-observations",
            str(observations_path),
            "--target-subject-model",
            str(model_path),
        ],
    )

    assert result.exit_code != 0
    assert "target subject model rejected" in result.stderr
    assert "subject_model_unreviewed" in result.stderr


def test_product_cli_threads_an_accepted_subject_model(tmp_path: Path) -> None:
    """A fully accepted companion reaches the synthesis inputs."""
    from datetime import date

    from asago_scenario_generator.stpa.models.target_subject_model import (
        TargetSubjectModel,
        TargetSubjectModelAcceptance,
    )
    from asago_scenario_generator.stpa.scenario_prod.target_observations import (
        TargetObservationSnapshot,
    )

    profile_path, observations_path = _target_companion_files(tmp_path)
    from tests.stpa.test_target_derived_structure import _profile

    profile = _profile()
    snapshot = TargetObservationSnapshot.from_runtime_context(
        __import__("json").loads(observations_path.read_text(encoding="utf-8"))
    )
    model = TargetSubjectModel(
        session_path=("authenticated_customer_id",),
        subject_noun="customer",
        acceptance=TargetSubjectModelAcceptance(
            reviewed_by="qa",
            reviewed_on=date(2026, 9, 12),
            observations_digest=snapshot.content_digest,
            execution_target_profile_digest=profile.semantic_digest,
            content_digest="0" * 64,
        ),
    )
    digest = model.compute_content_digest()
    model = model.model_copy(
        update={
            "acceptance": model.acceptance.model_copy(
                update={"content_digest": digest}
            )
        }
    )
    model_path = tmp_path / "target-subject-model.yaml"
    model_path.write_text(
        yaml.safe_dump(model.model_dump(mode="json", exclude_none=True)),
        encoding="utf-8",
    )

    captured = []

    def _capture(inputs, adapter):
        captured.append(inputs)
        return _result(tmp_path / "run", "completed")

    risk, facts, sssom = _input_files(tmp_path)
    output_dir = tmp_path / "run"
    with (
        patch(
            "asago_scenario_generator.data.loaders.load_reviewed_risk_extraction",
            return_value=(),
        ),
        patch(
            "asago_scenario_generator.pipeline.synthesis.run_synthesis",
            side_effect=_capture,
        ),
    ):
        result = CliRunner().invoke(
            app,
            [
                "run",
                "--use-case",
                "a deterministic system",
                "--risk-extraction",
                str(risk),
                "--qualification-facts",
                str(facts),
                "--sssom",
                str(sssom),
                "--output-dir",
                str(output_dir),
                "--target-profile",
                str(profile_path),
                "--target-observations",
                str(observations_path),
                "--target-subject-model",
                str(model_path),
            ],
        )

    assert result.exit_code == 0
    assert len(captured) == 1
    assert captured[0].target_subject_model is not None
    assert captured[0].target_subject_model.session_path == (
        "authenticated_customer_id",
    )
    assert captured[0].target_subject_model_path == model_path


def test_synthesis_run_status_reads_public_result_and_legacy_manifest_shapes() -> None:
    """The CLI status seam handles result, enum, manifest, and unknown values."""
    assert _synthesis_run_status(SimpleNamespace(run_status="failed")) == "failed"
    assert (
        _synthesis_run_status(SimpleNamespace(run_status=None, status="degraded"))
        == "degraded"
    )
    assert (
        _synthesis_run_status(
            SimpleNamespace(
                run_status=None, status=None, manifest={"run_status": "completed"}
            )
        )
        == "completed"
    )
    assert (
        _synthesis_run_status(
            SimpleNamespace(
                run_status=None, status=None, manifest={"status": "no_candidates"}
            )
        )
        == "no_candidates"
    )
    assert (
        _synthesis_run_status(SimpleNamespace(run_status=SynthesisRunStatus.FAILED))
        == "failed"
    )
    assert (
        _synthesis_run_status(SimpleNamespace(run_status=None, manifest=object()))
        == "unknown"
    )
