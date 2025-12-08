"""Tests for SchemaLogger behaviour mimicking logging.Logger."""

from __future__ import annotations

import logging
from io import StringIO
from pathlib import Path

import pytest
from conftest import _write_schema

from logging_objects_with_schema import SchemaLogger


def test_schema_logger_is_logging_logger_instance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should be an instance of logging.Logger."""

    monkeypatch.chdir(tmp_path)
    _write_schema(tmp_path, {"ServicePayload": {}})

    logger = SchemaLogger("test-logger")

    assert isinstance(logger, logging.Logger)
    assert logger.name == "test-logger"


def test_schema_logger_supports_args_formatting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should support stdlib-style msg % args formatting."""

    monkeypatch.chdir(tmp_path)
    _write_schema(tmp_path, {"ServicePayload": {}})

    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))

    logger = SchemaLogger("test-logger")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    logger.info("user %s logged in", "alice")

    output = stream.getvalue().strip()
    assert output == "user alice logged in"


def test_schema_logger_reports_correct_caller_location(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should report caller location from user code."""

    monkeypatch.chdir(tmp_path)
    _write_schema(tmp_path, {"ServicePayload": {}})

    stream = StringIO()
    # Include caller information in the log output to verify stacklevel handling.
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(pathname)s:%(lineno)d %(message)s"))

    logger = SchemaLogger("test-logger")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    # Log from this test function; caller info should point here.
    logger.info("hello from test")

    output = stream.getvalue().strip()
    assert "hello from test" in output
    # The reported pathname should point to this test module, not schema_logger.py.
    assert output.split(":", 1)[0].endswith("test_logging_compatibility.py")


def test_schema_logger_works_with_setloggerclass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should work when set as LoggerClass via logging.setLoggerClass."""

    monkeypatch.chdir(tmp_path)
    _write_schema(tmp_path, {"ServicePayload": {}})

    logging.setLoggerClass(SchemaLogger)
    try:
        logger = logging.getLogger("test-via-setloggerclass")
        assert isinstance(logger, SchemaLogger)
        assert isinstance(logger, logging.Logger)
    finally:
        # Restore default logger class
        logging.setLoggerClass(logging.Logger)


def test_schema_logger_accepts_extra_fields_without_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should accept extra fields without raising exceptions.

    This test verifies compatibility: SchemaLogger behaves like logging.Logger
    and doesn't raise exceptions when extra fields are provided.
    """

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))

    logger = SchemaLogger("test-logger")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    logger.info("msg", extra={"request_id": "abc-123"})

    output = stream.getvalue()
    assert "msg" in output
