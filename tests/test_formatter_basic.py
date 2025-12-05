"""Tests for SchemaLogger data validation."""

from __future__ import annotations

import json
import logging
from io import StringIO
from pathlib import Path

import pytest

from logging_objects_with_schema import SchemaLogger
from logging_objects_with_schema.errors import DataValidationError
from logging_objects_with_schema.schema_loader import SCHEMA_FILE_NAME


def _configure_schema_logger(stream: StringIO) -> SchemaLogger:
    """Create a SchemaLogger instance."""

    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = SchemaLogger("schema-logger")
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    return logger


def test_schema_logger_type_mismatch_raises_data_error_after_logging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Type mismatches should raise DataValidationError after logging."""

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
    logger = _configure_schema_logger(stream)

    with pytest.raises(DataValidationError):
        logger.info("msg", extra={"user_id": "not-an-int"})

    output = stream.getvalue()
    # No user_id should be present because it failed validation.
    assert "user_id" not in output


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
