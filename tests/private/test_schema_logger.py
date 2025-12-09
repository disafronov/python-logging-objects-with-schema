"""Tests for schema_logger module private functions."""

from __future__ import annotations

import logging
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from logging_objects_with_schema.errors import _SchemaProblem
from logging_objects_with_schema.schema_logger import (
    SchemaLogger,
    _log_schema_problems_and_exit,
)
from tests.helpers import _write_schema


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


# Tests for SchemaLogger.__init__


def test_schema_logger_init_with_none_forbidden_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger.__init__ should work with forbidden_keys=None."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger", forbidden_keys=None)

    assert isinstance(logger, SchemaLogger)
    assert isinstance(logger, logging.Logger)
    assert logger.name == "test_logger"
    assert hasattr(logger, "_schema")
    assert not logger._schema.is_empty


def test_schema_logger_init_with_empty_set_forbidden_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger.__init__ should work with forbidden_keys=set()."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger", forbidden_keys=set())

    assert isinstance(logger, SchemaLogger)
    assert isinstance(logger, logging.Logger)
    assert logger.name == "test_logger"
    assert hasattr(logger, "_schema")
    assert not logger._schema.is_empty


def test_schema_logger_init_with_non_empty_forbidden_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger.__init__ should work with non-empty forbidden_keys."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger", forbidden_keys={"custom_key"})

    assert isinstance(logger, SchemaLogger)
    assert isinstance(logger, logging.Logger)
    assert logger.name == "test_logger"
    assert hasattr(logger, "_schema")
    assert not logger._schema.is_empty


def test_schema_logger_init_sets_schema_correctly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger.__init__ should set self._schema correctly."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
                "UserID": {"type": "int", "source": "user_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger")

    assert hasattr(logger, "_schema")
    assert not logger._schema.is_empty
    assert len(logger._schema.leaves) == 2
    sources = {leaf.source for leaf in logger._schema.leaves}
    assert sources == {"request_id", "user_id"}


def test_schema_logger_init_calls_super_init(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger.__init__ should call super().__init__ with correct parameters."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger", level=logging.INFO)

    assert isinstance(logger, logging.Logger)
    assert logger.name == "test_logger"
    assert logger.level == logging.INFO


# Tests for SchemaLogger._log


def test_schema_logger_log_with_none_extra(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger._log should handle None extra parameter."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger")
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    logger._log(logging.INFO, "test message", (), extra=None)

    output = stream.getvalue()
    assert "test message" in output


def test_schema_logger_log_with_empty_extra(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger._log should handle empty extra dict."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger")
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    logger._log(logging.INFO, "test message", (), extra={})

    output = stream.getvalue()
    assert "test message" in output


def test_schema_logger_log_with_valid_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger._log should log valid data without problems."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger")
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    logger._log(logging.INFO, "test message", (), extra={"request_id": "abc-123"})

    output = stream.getvalue()
    assert "test message" in output
    # Should not contain validation errors
    assert "validation_errors" not in output


def test_schema_logger_log_with_invalid_data_logs_error_after(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger._log should log validation errors as ERROR after main message."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger")
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    logger._log(logging.INFO, "test message", (), extra={"request_id": 123})

    output = stream.getvalue()
    lines = output.strip().split("\n")
    # First line should be the main message
    assert "test message" in lines[0]
    # Second line should be the validation error
    assert "ERROR" in lines[1] if len(lines) > 1 else False
    assert "validation_errors" in output


def test_schema_logger_log_increments_stacklevel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger._log should increment stacklevel correctly."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger")
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(filename)s:%(lineno)d"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    def test_function() -> None:
        logger._log(logging.INFO, "test", (), stacklevel=1)

    test_function()
    # The output should point to test_function, not to _log
    output = stream.getvalue()
    assert "test_schema_logger.py" in output


def test_schema_logger_log_handles_json_loads_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger._log should handle json.loads exception gracefully."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger")
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    # Create a mock _DataProblem with invalid JSON
    from logging_objects_with_schema.errors import _DataProblem
    from logging_objects_with_schema.schema_applier import _apply_schema_internal

    original_apply = _apply_schema_internal

    def mock_apply(*args, **kwargs):
        result, problems = original_apply(*args, **kwargs)
        # Add a problem with invalid JSON
        problems.append(_DataProblem("invalid json {"))
        return result, problems

    with patch(
        "logging_objects_with_schema.schema_logger._apply_schema_internal", mock_apply
    ):
        logger._log(logging.INFO, "test", (), extra={"request_id": "abc"})

    output = stream.getvalue()
    # Should handle the exception and log a fallback error
    assert "test" in output
    assert "validation_errors" in output


def test_schema_logger_log_handles_json_dumps_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger._log should handle json.dumps exception gracefully."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger")
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    # Mock json.dumps to raise an exception only on first call
    import json

    original_dumps = json.dumps
    call_count = 0

    def mock_dumps(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        # Raise exception only on first call (when trying to serialize
        # validation_errors). Allow second call (fallback error serialization)
        # to succeed.
        if call_count == 1 and "validation_errors" in str(args):
            raise TypeError("Serialization failed")
        return original_dumps(*args, **kwargs)

    with patch("json.dumps", mock_dumps):
        logger._log(logging.INFO, "test", (), extra={"request_id": 123})

    output = stream.getvalue()
    # Should handle the exception and log a fallback error
    assert "test" in output
    assert "validation_errors" in output


def test_schema_logger_log_handles_callhandlers_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger._log should handle callHandlers exception gracefully."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger")
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))

    # Create a handler that raises an exception
    class FailingHandler(logging.StreamHandler):
        def emit(self, record):
            if "validation_errors" in record.getMessage():
                raise RuntimeError("Handler failed")
            super().emit(record)

    failing_handler = FailingHandler(stream)
    logger.addHandler(failing_handler)
    logger.setLevel(logging.INFO)

    stderr_capture = StringIO()
    with patch("sys.stderr", stderr_capture):
        logger._log(logging.INFO, "test", (), extra={"request_id": 123})

    output = stream.getvalue()
    stderr_output = stderr_capture.getvalue()
    # Main message should be logged
    assert "test" in output
    # Error about handler failure should be written to stderr
    assert "Error in logging handler" in stderr_output


def test_schema_logger_log_uses_findcaller_for_python_311_plus(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger._log should use findCaller for Python 3.11+."""
    import sys

    if sys.version_info < (3, 11):
        pytest.skip("Test only for Python 3.11+")

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger")
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    with patch.object(logger, "findCaller") as mock_findcaller:
        mock_findcaller.return_value = ("test.py", 42, "test_func", None)
        logger._log(logging.INFO, "test", (), extra={"request_id": 123})

        # findCaller should be called for validation error logging
        assert mock_findcaller.called


def test_schema_logger_log_uses_inspect_stack_fallback_for_old_python(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger._log should use inspect.stack() fallback for Python < 3.11."""
    import sys

    if sys.version_info >= (3, 11):
        pytest.skip("Test only for Python < 3.11")

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger")
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    with patch("inspect.stack") as mock_stack:
        # Mock stack to return a frame
        mock_frame = MagicMock()
        mock_frame.filename = "test.py"
        mock_frame.lineno = 42
        mock_frame.function = "test_func"
        mock_stack.return_value = [None, None, mock_frame]

        logger._log(logging.INFO, "test", (), extra={"request_id": 123})

        # inspect.stack should be called for validation error logging
        assert mock_stack.called


def test_schema_logger_log_fallback_to_findcaller_when_stack_too_short(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger._log should fallback to findCaller when stack is too short."""
    import sys

    if sys.version_info >= (3, 11):
        pytest.skip("Test only for Python < 3.11")

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger")
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    with (
        patch("inspect.stack") as mock_stack,
        patch.object(logger, "findCaller") as mock_findcaller,
    ):
        # Mock stack to return a short stack (less than expected)
        mock_stack.return_value = [None]  # Too short
        mock_findcaller.return_value = ("test.py", 42, "test_func", None)

        logger._log(logging.INFO, "test", (), extra={"request_id": 123}, stacklevel=10)

        # findCaller should be called as fallback
        assert mock_findcaller.called


def test_schema_logger_log_makerecord_called_with_correct_params(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger._log should call makeRecord with correct parameters."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger")
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    with patch.object(logger, "makeRecord") as mock_makerecord:
        mock_makerecord.return_value = logging.LogRecord(
            name="test_logger",
            level=logging.ERROR,
            pathname="test.py",
            lineno=42,
            msg="test error",
            args=(),
            exc_info=None,
        )

        logger._log(logging.INFO, "test", (), extra={"request_id": 123})

        # makeRecord should be called for validation error
        assert mock_makerecord.called
        call_args = mock_makerecord.call_args
        assert call_args[0][0] == "test_logger"  # name
        assert call_args[0][1] == logging.ERROR  # level
        assert call_args[0][4] == "test error" or "validation_errors" in str(
            call_args[0][4]
        )  # msg


def test_schema_logger_log_validation_errors_logged_after_main_message(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger._log should log validation errors after main message."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logger = SchemaLogger("test_logger")
    messages = []

    class MessageCaptureHandler(logging.Handler):
        def emit(self, record):
            messages.append((record.levelno, record.getMessage()))

    handler = MessageCaptureHandler()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    logger._log(logging.INFO, "main message", (), extra={"request_id": 123})

    # First message should be the main INFO message
    assert len(messages) >= 1
    assert messages[0][0] == logging.INFO
    assert "main message" in messages[0][1]

    # Second message should be the validation ERROR
    if len(messages) > 1:
        assert messages[1][0] == logging.ERROR
        assert "validation_errors" in messages[1][1]
