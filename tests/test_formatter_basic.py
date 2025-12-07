"""Tests for SchemaLogger data validation."""

from __future__ import annotations

import json
import logging
from io import StringIO
from pathlib import Path

import pytest

from logging_objects_with_schema import SchemaLogger
from logging_objects_with_schema.schema_loader import SCHEMA_FILE_NAME


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

    schema_path = tmp_path / SCHEMA_FILE_NAME
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

    schema_path = tmp_path / SCHEMA_FILE_NAME
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

    schema_path = tmp_path / SCHEMA_FILE_NAME
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
