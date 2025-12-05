"""Tests for SchemaLogger behaviour mimicking logging.Logger."""

from __future__ import annotations

import logging
from io import StringIO
from pathlib import Path

import pytest

from logging_objects_with_schema import SchemaLogger
from logging_objects_with_schema.errors import SchemaValidationError
from tests.conftest import _write_schema


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
    assert output.split(":", 1)[0].endswith("test_schema_logger_mimic.py")


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


def test_schema_logger_validates_extra_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should validate extra fields according to schema."""

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


def test_schema_logger_raises_schema_validation_error_on_bad_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should raise SchemaValidationError when schema has problems."""

    monkeypatch.chdir(tmp_path)
    # Use a root key that conflicts with logging.LogRecord field
    _write_schema(
        tmp_path,
        {
            "name": {
                "Value": {"type": "str", "source": "value"},
            },
        },
    )

    with pytest.raises(SchemaValidationError):
        SchemaLogger("test-logger")


def test_schema_logger_does_not_leave_partially_initialised_logger_in_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should not leave broken instances in the logging cache.

    If schema validation fails during initialisation, the partially constructed
    logger instance must not remain registered in logging's internal cache.
    Otherwise, a subsequent logging.getLogger(name) call could return this
    broken instance and lead to AttributeError when accessing _schema.
    """

    monkeypatch.chdir(tmp_path)

    logging.setLoggerClass(SchemaLogger)
    try:
        # 1) Write an invalid schema that triggers SchemaValidationError.
        _write_schema(
            tmp_path,
            {
                "name": {
                    "Value": {"type": "str", "source": "value"},
                },
            },
        )

        # Attempting to create/get the logger should raise SchemaValidationError,
        # and the partially initialised instance must be removed from cache.
        with pytest.raises(SchemaValidationError):
            logging.getLogger("bad-schema-logger")

        # 2) Fix the schema on disk. Because schema compilation result is cached
        # within the same process, subsequent attempts should still raise
        # SchemaValidationError, but must not leave a broken logger instance
        # in logging's internal cache.
        _write_schema(
            tmp_path,
            {
                "ServicePayload": {
                    "RequestID": {"type": "str", "source": "request_id"},
                },
            },
        )

        with pytest.raises(SchemaValidationError):
            logging.getLogger("bad-schema-logger")

        # Ensure that the logger with this name is not left registered in the
        # logging manager cache after failed initialisation.
        assert "bad-schema-logger" not in logging.Logger.manager.loggerDict
    finally:
        logging.setLoggerClass(logging.Logger)
