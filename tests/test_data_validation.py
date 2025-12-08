"""Tests for SchemaLogger data validation."""

from __future__ import annotations

import json
import logging
from io import StringIO
from pathlib import Path

import pytest
from conftest import _write_schema

from logging_objects_with_schema import SchemaLogger
from logging_objects_with_schema.schema_loader import _SCHEMA_FILE_NAME


def _configure_schema_logger(stream: StringIO) -> SchemaLogger:
    """Create a SchemaLogger instance."""

    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = SchemaLogger("schema-logger")
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    return logger


def test_schema_logger_type_mismatch_logs_error_after_logging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Type mismatches should log ERROR message after logging."""

    monkeypatch.chdir(tmp_path)

    schema_path = tmp_path / _SCHEMA_FILE_NAME
    schema_path.write_text(
        json.dumps(
            {
                "ServicePayload": {
                    "UserID": {"type": "int", "source": "user_id"},
                },
            },
        ),
        encoding="utf-8",
    )

    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger = SchemaLogger("schema-logger")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    # Should not raise exception
    logger.info("msg", extra={"user_id": "not-an-int"})

    output = stream.getvalue()
    # user_id should not appear in the main log message (it failed validation)
    # but it should appear in the validation error message
    main_log = output.split("ERROR:")[0]
    assert "user_id" not in main_log
    # Validation error should be logged as ERROR
    assert "ERROR" in output
    # Error message should be JSON with validation_errors
    assert "validation_errors" in output
    # Details of the problem should be included in the error message
    assert "user_id" in output


def test_schema_logger_valid_data_appears_in_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid extra fields should appear in the log record."""

    monkeypatch.chdir(tmp_path)

    schema_path = tmp_path / _SCHEMA_FILE_NAME
    schema_path.write_text(
        json.dumps(
            {
                "ServicePayload": {
                    "RequestID": {"type": "str", "source": "request_id"},
                    "UserID": {"type": "int", "source": "user_id"},
                },
            },
        ),
        encoding="utf-8",
    )

    stream = StringIO()
    handler = logging.StreamHandler(stream)
    # Use formatter that includes ServicePayload to verify it's in the record
    handler.setFormatter(logging.Formatter("%(message)s %(ServicePayload)s"))
    logger = SchemaLogger("schema-logger")
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)

    logger.info("request processed", extra={"request_id": "abc-123", "user_id": 42})

    output = stream.getvalue()
    assert "request processed" in output
    # Verify that valid data appears in the log record
    assert "RequestID" in output
    assert "abc-123" in output
    assert "UserID" in output
    assert "42" in output


def test_validation_error_record_has_function_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validation error log records should have function name."""

    monkeypatch.chdir(tmp_path)

    schema_path = tmp_path / _SCHEMA_FILE_NAME
    schema_path.write_text(
        json.dumps(
            {
                "ServicePayload": {
                    "UserID": {"type": "int", "source": "user_id"},
                },
            },
        ),
        encoding="utf-8",
    )

    # Custom handler that captures log records
    captured_records: list[logging.LogRecord] = []

    class RecordCapturingHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured_records.append(record)

    logger = SchemaLogger("schema-logger")
    handler = RecordCapturingHandler()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    # Log with invalid type to trigger validation error
    def test_function() -> None:
        logger.info("msg", extra={"user_id": "not-an-int"})

    test_function()

    # Should have two records: one INFO and one ERROR for validation
    assert len(captured_records) == 2
    info_record = captured_records[0]
    error_record = captured_records[1]

    # Check INFO record
    assert info_record.levelno == logging.INFO
    assert info_record.msg == "msg"

    # Check ERROR record for validation error
    assert error_record.levelno == logging.ERROR
    # Error message should be JSON with validation_errors
    assert "validation_errors" in str(error_record.msg)

    # Verify that funcName is set (not None) - this is the main fix we made
    # Previously, func was not passed to makeRecord, causing funcName to be None
    assert error_record.funcName is not None
    assert error_record.funcName == "test_function"

    # Verify that exc_info is not set (we don't need traceback for validation errors)
    assert error_record.exc_info is None


def test_logger_handles_missing_extra_fields_gracefully(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Logger should handle missing extra fields without errors."""

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

    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = SchemaLogger("test")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    # Log without extra fields
    logger.info("message without extra")
    output = stream.getvalue()
    assert "message without extra" in output

    # Log with partial extra fields
    logger.info("message with partial", extra={"request_id": "abc-123"})
    output = stream.getvalue()
    assert "message with partial" in output


def test_logger_with_empty_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Logger should treat any extra fields as invalid when schema is empty."""

    monkeypatch.chdir(tmp_path)
    _write_schema(tmp_path, {})

    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger = SchemaLogger("test")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    # Log with extra fields: they should still be ignored in payload, but
    # treated as data errors because schema defines no valid leaves.
    logger.info("message", extra={"unknown_field": "value", "another": 42})

    # Message should be logged
    output = stream.getvalue()
    assert "message" in output
    # Fields should not appear in the main log message (they failed validation)
    # but they should appear in the validation error message
    main_log = output.split("ERROR:")[0]
    assert "unknown_field" not in main_log
    assert "another" not in main_log

    # Validation error should be logged as ERROR
    assert "ERROR" in output
    # Error message should be JSON with validation_errors
    assert "validation_errors" in output
    # Details of problems should be included in the error message
    assert "unknown_field" in output
    assert "another" in output


def test_logger_handles_invalid_json_in_data_problem_message(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Logger should handle DataProblem with invalid JSON in message gracefully.

    This tests the defensive code path when _DataProblem.message is not valid JSON
    (should never happen in normal operation, but protects against data corruption).
    """

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "UserID": {"type": "int", "source": "user_id"},
            },
        },
    )

    from logging_objects_with_schema.errors import _DataProblem
    from logging_objects_with_schema.schema_applier import _apply_schema_internal

    # Create a logger and patch _apply_schema_internal to return a DataProblem
    # with invalid JSON in the message
    logger = SchemaLogger("test")
    original_apply = _apply_schema_internal

    def mock_apply_schema(schema, extra):
        # Call original to get normal result, but replace one problem with invalid JSON
        structured_extra, problems = original_apply(schema, extra)
        if problems:
            # Replace first problem with one that has invalid JSON
            invalid_problem = _DataProblem("not valid json {")
            problems = [invalid_problem] + problems[1:]
        return structured_extra, problems

    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    with monkeypatch.context() as m:
        m.setattr(
            "logging_objects_with_schema.schema_logger._apply_schema_internal",
            mock_apply_schema,
        )
        # Log with invalid type to trigger validation error
        logger.info("msg", extra={"user_id": "not-an-int"})

    output = stream.getvalue()
    # Main message should be logged
    assert "msg" in output
    # Error should be logged with fallback message
    assert "ERROR" in output
    assert "validation_errors" in output
    # Should contain fallback error message
    assert "Failed to parse validation error" in output or "unknown" in output


def test_logger_handles_json_serialization_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Logger should handle JSON serialization errors gracefully.

    This tests the defensive code path when json.dumps fails during error message
    serialization (should never happen in normal operation, but protects against
    edge cases).
    """

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "UserID": {"type": "int", "source": "user_id"},
            },
        },
    )

    import json
    from unittest.mock import patch

    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger = SchemaLogger("test")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    # Mock json.dumps to fail on the second call (when serializing validation errors)
    original_dumps = json.dumps
    call_count = 0

    def mock_dumps(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        # First call is from _create_validation_error_json (should succeed)
        # Second call is from _log when combining errors (should fail)
        if call_count == 2:
            raise TypeError("Serialization failed")
        return original_dumps(*args, **kwargs)

    with patch("json.dumps", side_effect=mock_dumps):
        logger.info("msg", extra={"user_id": "not-an-int"})

    output = stream.getvalue()
    # Main message should be logged
    assert "msg" in output
    # Error should be logged with fallback message
    assert "ERROR" in output
    assert "validation_errors" in output
    # Should contain fallback error message
    assert "Failed to serialize validation errors" in output


def test_logger_handles_handler_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Logger should handle exceptions in handlers gracefully.

    This tests the defensive code path when a handler raises an exception
    while processing a validation error log record.
    """

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "UserID": {"type": "int", "source": "user_id"},
            },
        },
    )

    import sys
    from io import StringIO

    class FailingHandler(logging.StreamHandler):
        def emit(self, record: logging.LogRecord) -> None:
            # Only fail on ERROR level (validation errors)
            if record.levelno == logging.ERROR:
                raise RuntimeError("Handler failed")
            super().emit(record)

    stderr_capture = StringIO()
    stream = StringIO()
    handler = FailingHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger = SchemaLogger("test")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    with monkeypatch.context() as m:
        m.setattr(sys, "stderr", stderr_capture)
        # Log with invalid type to trigger validation error
        logger.info("msg", extra={"user_id": "not-an-int"})

    # Main message should be logged (handler doesn't fail for INFO)
    output = stream.getvalue()
    assert "msg" in output

    # Error should be written to stderr because handler failed
    stderr_output = stderr_capture.getvalue()
    assert "Error in logging handler" in stderr_output


def test_logger_uses_inspect_stack_fallback_for_old_python(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Logger should use inspect.stack() fallback for Python < 3.11.

    This tests the fallback code path when _USE_FINDCALLER is False
    (simulating Python < 3.11 behavior).
    """

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "UserID": {"type": "int", "source": "user_id"},
            },
        },
    )

    from unittest.mock import patch

    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger = SchemaLogger("test")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    # Mock _USE_FINDCALLER to be False to trigger inspect.stack() path
    with patch(
        "logging_objects_with_schema.schema_logger._USE_FINDCALLER",
        False,
    ):
        # Log with invalid type to trigger validation error
        def test_function() -> None:
            logger.info("msg", extra={"user_id": "not-an-int"})

        test_function()

    output = stream.getvalue()
    # Main message should be logged
    assert "msg" in output
    # Error should be logged
    assert "ERROR" in output
    assert "validation_errors" in output


def test_logger_uses_findcaller_fallback_when_stack_too_short(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Logger should use findCaller() fallback when inspect.stack() is too short.

    This tests the fallback within fallback: when _USE_FINDCALLER is False
    but inspect.stack() returns a stack that's shorter than expected.
    """

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "UserID": {"type": "int", "source": "user_id"},
            },
        },
    )

    from unittest.mock import patch

    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger = SchemaLogger("test")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    # Mock _USE_FINDCALLER to be False and inspect.stack() to return short stack
    def mock_stack():
        # Return a very short stack (shorter than expected)
        return [
            type(
                "Frame", (), {"filename": "test.py", "lineno": 1, "function": "test"}
            )()
        ]

    with (
        patch(
            "logging_objects_with_schema.schema_logger._USE_FINDCALLER",
            False,
        ),
        patch("inspect.stack", side_effect=mock_stack),
    ):
        # Log with invalid type to trigger validation error
        logger.info("msg", extra={"user_id": "not-an-int"})

    output = stream.getvalue()
    # Main message should be logged
    assert "msg" in output
    # Error should be logged (fallback to findCaller should work)
    assert "ERROR" in output
    assert "validation_errors" in output
