"""Integration tests for SchemaLogger.

These tests verify the behavior of SchemaLogger in realistic scenarios,
including multiple logger instances and working directory changes.
"""

from __future__ import annotations

import logging
from io import StringIO
from pathlib import Path

import pytest
from conftest import _write_schema

from logging_objects_with_schema import SchemaLogger
from logging_objects_with_schema.schema_loader import SCHEMA_FILE_NAME


def test_multiple_logger_instances_share_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple SchemaLogger instances should work with the same schema."""

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    # Create multiple logger instances
    logger1 = SchemaLogger("logger1")
    logger2 = SchemaLogger("logger2")
    logger3 = SchemaLogger("logger3")

    # All should be valid SchemaLogger instances
    assert isinstance(logger1, SchemaLogger)
    assert isinstance(logger2, SchemaLogger)
    assert isinstance(logger3, SchemaLogger)
    assert isinstance(logger1, logging.Logger)
    assert isinstance(logger2, logging.Logger)
    assert isinstance(logger3, logging.Logger)

    # All should have the same schema
    assert logger1._schema.leaves == logger2._schema.leaves
    assert logger2._schema.leaves == logger3._schema.leaves


def test_logger_instances_with_different_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Logger instances with different names should work independently."""

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

    stream1 = StringIO()
    handler1 = logging.StreamHandler(stream1)
    handler1.setFormatter(logging.Formatter("%(name)s: %(message)s"))

    stream2 = StringIO()
    handler2 = logging.StreamHandler(stream2)
    handler2.setFormatter(logging.Formatter("%(name)s: %(message)s"))

    logger1 = SchemaLogger("service.api")
    logger1.addHandler(handler1)
    logger1.setLevel(logging.INFO)

    logger2 = SchemaLogger("service.db")
    logger2.addHandler(handler2)
    logger2.setLevel(logging.INFO)

    logger1.info("API request", extra={"request_id": "req-1", "user_id": 42})
    logger2.info("DB query", extra={"request_id": "req-2", "user_id": 43})

    output1 = stream1.getvalue()
    output2 = stream2.getvalue()

    assert "service.api" in output1
    assert "API request" in output1
    assert "service.db" in output2
    assert "DB query" in output2


def test_schema_file_in_current_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Schema file should be found in current working directory."""

    # Create schema in tmp_path
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    # Change to that directory
    monkeypatch.chdir(tmp_path)

    # Logger should be created successfully
    logger = SchemaLogger("test")
    assert isinstance(logger, SchemaLogger)

    # Verify it works
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    logger.info("test message", extra={"request_id": "abc-123"})
    output = stream.getvalue()
    assert "test message" in output


def test_schema_file_not_found_terminates_application(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Schema file not found should terminate application."""

    import os
    import sys
    from io import StringIO

    # Change to directory without schema file
    monkeypatch.chdir(tmp_path)

    exit_called = False
    exit_code = None
    stderr_output = StringIO()

    def fake_exit(code: int) -> None:
        nonlocal exit_called, exit_code
        exit_called = True
        exit_code = code
        raise SystemExit(code)

    monkeypatch.setattr(os, "_exit", fake_exit)
    monkeypatch.setattr(sys, "stderr", stderr_output)

    with pytest.raises(SystemExit):
        SchemaLogger("test")

    assert exit_called
    assert exit_code == 1
    stderr_content = stderr_output.getvalue()
    assert "Schema has problems" in stderr_content
    assert "not found" in stderr_content.lower()


def test_schema_validation_error_on_invalid_schema_terminates_application(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid schema should terminate application."""

    import os
    import sys
    from io import StringIO

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "name": {  # Conflicts with LogRecord attribute
                "Value": {"type": "str", "source": "value"},
            },
        },
    )

    exit_called = False
    exit_code = None
    stderr_output = StringIO()

    def fake_exit(code: int) -> None:
        nonlocal exit_called, exit_code
        exit_called = True
        exit_code = code
        raise SystemExit(code)

    monkeypatch.setattr(os, "_exit", fake_exit)
    monkeypatch.setattr(sys, "stderr", stderr_output)

    with pytest.raises(SystemExit):
        SchemaLogger("test")

    assert exit_called
    assert exit_code == 1
    stderr_content = stderr_output.getvalue()
    assert "Schema has problems" in stderr_content
    assert "conflicts with reserved logging fields" in stderr_content


def test_logger_with_setloggerclass_creates_schema_logger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Using setLoggerClass should create SchemaLogger instances."""

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    logging.setLoggerClass(SchemaLogger)
    try:
        logger1 = logging.getLogger("test1")
        logger2 = logging.getLogger("test2")

        assert isinstance(logger1, SchemaLogger)
        assert isinstance(logger2, SchemaLogger)
        assert logger1.name == "test1"
        assert logger2.name == "test2"
    finally:
        logging.setLoggerClass(logging.Logger)


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


def test_logger_validates_data_after_logging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Logger should log validation errors as ERROR messages after logging."""

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "UserID": {"type": "int", "source": "user_id"},
            },
        },
    )

    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger = SchemaLogger("test")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    # Log with invalid type - should not raise exception
    logger.info("message", extra={"user_id": "not-an-int"})

    # Message should be logged
    output = stream.getvalue()
    assert "message" in output

    # Validation error should be logged as ERROR
    assert "ERROR" in output
    assert "Log data does not match schema" in output


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
    assert "Log data does not match schema" in output
    # Details of problems should be included in the error message
    assert "unknown_field" in output
    assert "another" in output


def test_schema_file_permission_error_terminates_application(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unreadable schema file should terminate application."""

    import os
    import sys
    from io import StringIO

    import logging_objects_with_schema.schema_loader as schema_loader

    monkeypatch.chdir(tmp_path)
    # Create a valid schema file before patching Path.open
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    schema_file = tmp_path / SCHEMA_FILE_NAME
    original_open = schema_loader.Path.open  # type: ignore[attr-defined]

    def fake_open(self, *args, **kwargs):  # type: ignore[override]
        if self == schema_file:
            raise PermissionError("permission denied")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(schema_loader.Path, "open", fake_open)

    exit_called = False
    exit_code = None
    stderr_output = StringIO()

    def fake_exit(code: int) -> None:
        nonlocal exit_called, exit_code
        exit_called = True
        exit_code = code
        raise SystemExit(code)

    monkeypatch.setattr(os, "_exit", fake_exit)
    monkeypatch.setattr(sys, "stderr", stderr_output)

    with pytest.raises(SystemExit):
        SchemaLogger("test-permission-error")

    assert exit_called
    assert exit_code == 1
    stderr_content = stderr_output.getvalue()
    assert "Schema has problems" in stderr_content
    assert "Failed to read schema file" in stderr_content
