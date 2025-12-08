"""Tests for schema_logger module private functions."""

from __future__ import annotations

from io import StringIO
from unittest.mock import MagicMock, patch

from logging_objects_with_schema.errors import _SchemaProblem
from logging_objects_with_schema.schema_logger import _log_schema_problems_and_exit


def test_log_schema_problems_and_exit_writes_to_stderr() -> None:
    """_log_schema_problems_and_exit should write formatted message to stderr."""
    problems = [
        _SchemaProblem("Problem 1"),
        _SchemaProblem("Problem 2"),
    ]

    stderr_capture = StringIO()

    with patch("sys.stderr", stderr_capture), patch("os._exit") as mock_exit:
        _log_schema_problems_and_exit(problems)

    output = stderr_capture.getvalue()
    assert "Schema has problems:" in output
    assert "Problem 1" in output
    assert "Problem 2" in output
    assert output.endswith("\n")
    mock_exit.assert_called_once_with(1)


def test_log_schema_problems_and_exit_calls_os_exit() -> None:
    """_log_schema_problems_and_exit should call os._exit(1)."""
    problems = [_SchemaProblem("Test problem")]

    with patch("os._exit") as mock_exit, patch("sys.stderr"):
        _log_schema_problems_and_exit(problems)

    mock_exit.assert_called_once_with(1)


def test_log_schema_problems_and_exit_with_single_problem() -> None:
    """_log_schema_problems_and_exit should format single problem correctly."""
    problems = [_SchemaProblem("Single problem message")]

    stderr_capture = StringIO()

    with patch("sys.stderr", stderr_capture), patch("os._exit"):
        _log_schema_problems_and_exit(problems)

    output = stderr_capture.getvalue()
    assert "Schema has problems:" in output
    assert "Single problem message" in output
    assert output.endswith("\n")


def test_log_schema_problems_and_exit_with_multiple_problems() -> None:
    """_log_schema_problems_and_exit should format multiple problems correctly."""
    problems = [
        _SchemaProblem("First problem"),
        _SchemaProblem("Second problem"),
        _SchemaProblem("Third problem"),
    ]

    stderr_capture = StringIO()

    with patch("sys.stderr", stderr_capture), patch("os._exit"):
        _log_schema_problems_and_exit(problems)

    output = stderr_capture.getvalue()
    assert "Schema has problems:" in output
    assert "First problem" in output
    assert "Second problem" in output
    assert "Third problem" in output
    assert ";" in output  # Problems should be separated by semicolon


def test_log_schema_problems_and_exit_with_empty_list() -> None:
    """_log_schema_problems_and_exit should handle empty problems list."""
    problems: list[_SchemaProblem] = []

    stderr_capture = StringIO()

    with patch("sys.stderr", stderr_capture), patch("os._exit") as mock_exit:
        _log_schema_problems_and_exit(problems)

    output = stderr_capture.getvalue()
    assert "Schema has problems:" in output
    mock_exit.assert_called_once_with(1)


def test_log_schema_problems_and_exit_flushes_stderr() -> None:
    """_log_schema_problems_and_exit should flush stderr after writing."""
    problems = [_SchemaProblem("Test problem")]

    mock_stderr = MagicMock()

    with patch("sys.stderr", mock_stderr), patch("os._exit"):
        _log_schema_problems_and_exit(problems)

    # Verify flush was called
    mock_stderr.flush.assert_called_once()
    # Verify write was called
    mock_stderr.write.assert_called_once()
