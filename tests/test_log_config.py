"""Tests for the centralized logging configuration."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from asago_scenario_generator.log_config import setup_logging


def _get_sf_logger() -> logging.Logger:
    return logging.getLogger("asago_scenario_generator")


def _cleanup_logger() -> None:
    """Remove all handlers from the asago_scenario_generator logger."""
    logger = _get_sf_logger()
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)
    logger.setLevel(logging.NOTSET)  # restore default (inherit from parent)


class TestSetupLogging:
    """Tests for setup_logging()."""

    def teardown_method(self) -> None:
        _cleanup_logger()

    def test_configures_both_handlers(self, tmp_path: Path) -> None:
        """setup_logging adds console + file handlers."""
        setup_logging(output_dir=tmp_path)
        logger = _get_sf_logger()
        assert len(logger.handlers) == 2
        handler_types = {type(h) for h in logger.handlers}
        assert logging.StreamHandler in handler_types
        assert logging.FileHandler in handler_types

    def test_console_handler_level_matches_parameter(self) -> None:
        """Console handler level follows log_level argument."""
        setup_logging(log_level="WARNING")
        logger = _get_sf_logger()
        console = [
            h for h in logger.handlers if isinstance(h, logging.StreamHandler)
        ][0]
        assert console.level == logging.WARNING

    def test_console_handler_default_info(self) -> None:
        """Console handler defaults to INFO."""
        setup_logging()
        logger = _get_sf_logger()
        console = [
            h for h in logger.handlers if isinstance(h, logging.StreamHandler)
        ][0]
        assert console.level == logging.INFO

    def test_file_handler_always_debug(self, tmp_path: Path) -> None:
        """File handler always logs at DEBUG regardless of log_level."""
        setup_logging(log_level="ERROR", output_dir=tmp_path)
        logger = _get_sf_logger()
        fh = [h for h in logger.handlers if isinstance(h, logging.FileHandler)][0]
        assert fh.level == logging.DEBUG

    def test_file_created_at_output_dir(self, tmp_path: Path) -> None:
        """pipeline.log is created inside output_dir."""
        setup_logging(output_dir=tmp_path)
        assert (tmp_path / "pipeline.log").exists()

    def test_default_file_format_human_readable(self, tmp_path: Path) -> None:
        """Default file format is human-readable with timestamp, level, logger, message."""
        setup_logging(output_dir=tmp_path)
        logger = _get_sf_logger()
        logger.info("test human format")

        content = (tmp_path / "pipeline.log").read_text(encoding="utf-8").strip()
        # Human-readable format: timestamp LEVEL    [logger] message
        assert "INFO" in content
        assert "[asago_scenario_generator]" in content
        assert "test human format" in content
        # Should NOT be valid JSON
        with __import__("contextlib").suppress(json.JSONDecodeError):
            json.loads(content)
            raise AssertionError("Default format should not be JSON")

    def test_structured_produces_json_lines(self, tmp_path: Path) -> None:
        """structured=True produces valid JSON lines in the file."""
        setup_logging(output_dir=tmp_path, structured=True)
        logger = _get_sf_logger()
        logger.info("msg one")
        logger.warning("msg two")

        lines = (
            (tmp_path / "pipeline.log")
            .read_text(encoding="utf-8")
            .strip()
            .splitlines()
        )
        assert len(lines) == 2

        for line in lines:
            obj = json.loads(line)
            assert "timestamp" in obj
            assert "level" in obj
            assert "logger" in obj
            assert "message" in obj

        assert json.loads(lines[0])["message"] == "msg one"
        assert json.loads(lines[0])["level"] == "INFO"
        assert json.loads(lines[1])["message"] == "msg two"
        assert json.loads(lines[1])["level"] == "WARNING"

    def test_structured_does_not_affect_console(self, tmp_path: Path) -> None:
        """Console handler stays human-readable even when structured=True."""
        setup_logging(output_dir=tmp_path, structured=True)
        logger = _get_sf_logger()
        console = [
            h
            for h in logger.handlers
            if isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.FileHandler)
        ][0]
        # The console formatter should NOT be the JSON formatter
        record = logging.LogRecord(
            name="asago_scenario_generator",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test",
            args=(),
            exc_info=None,
        )
        formatted = console.formatter.format(record)
        # Human-readable should NOT parse as JSON with our expected keys
        try:
            obj = json.loads(formatted)
            # If it is JSON, check it's not our structured format
            assert "timestamp" not in obj or "logger" not in obj
        except json.JSONDecodeError:
            pass  # Expected — human-readable is not JSON

    def test_no_output_dir_skips_file_handler(self) -> None:
        """When output_dir is None, only the console handler is added."""
        setup_logging(output_dir=None)
        logger = _get_sf_logger()
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0], logging.StreamHandler)
        assert not isinstance(logger.handlers[0], logging.FileHandler)

    def test_calling_twice_does_not_duplicate_handlers(
        self, tmp_path: Path
    ) -> None:
        """Calling setup_logging twice replaces handlers, not duplicates."""
        setup_logging(output_dir=tmp_path)
        setup_logging(output_dir=tmp_path)
        logger = _get_sf_logger()
        assert len(logger.handlers) == 2  # still just console + file

    def test_child_logger_propagation(self, tmp_path: Path) -> None:
        """Messages from child loggers propagate to the asago_scenario_generator handlers."""
        setup_logging(output_dir=tmp_path)
        child = logging.getLogger("asago_scenario_generator.pipeline.synthesis")
        child.info("child message")

        content = (tmp_path / "pipeline.log").read_text(encoding="utf-8")
        assert "child message" in content
        assert "asago_scenario_generator.pipeline.synthesis" in content

    def test_logger_level_set_to_debug(self, tmp_path: Path) -> None:
        """The asago_scenario_generator logger itself is set to DEBUG to let handlers filter."""
        setup_logging(log_level="ERROR", output_dir=tmp_path)
        logger = _get_sf_logger()
        assert logger.level == logging.DEBUG

    def test_output_dir_created_if_missing(self, tmp_path: Path) -> None:
        """setup_logging creates the output directory if it does not exist."""
        new_dir = tmp_path / "nested" / "logs"
        assert not new_dir.exists()
        setup_logging(output_dir=new_dir)
        assert new_dir.exists()
        assert (new_dir / "pipeline.log").exists()
