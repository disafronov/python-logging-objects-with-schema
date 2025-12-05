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


def test_schema_logger_handles_oserror_from_getcwd_and_cleans_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should catch OSError from os.getcwd() and clean up logger.

    If os.getcwd() raises OSError (e.g., when CWD is deleted), the exception
    should be caught, logger should be cleaned up from cache, and exception
    should be re-raised.
    """
    import os

    import logging_objects_with_schema.schema_loader as schema_loader

    monkeypatch.chdir(tmp_path)
    _write_schema(tmp_path, {"ServicePayload": {}})

    original_getcwd = os.getcwd

    def fake_getcwd() -> str:
        raise OSError("Current working directory no longer exists")

    monkeypatch.setattr(os, "getcwd", fake_getcwd)

    logging.setLoggerClass(SchemaLogger)
    try:
        # Clear schema cache to force recompilation
        with schema_loader._cache_lock:
            schema_loader._SCHEMA_CACHE.clear()
        with schema_loader._path_cache_lock:
            schema_loader._resolved_schema_path = None
            schema_loader._cached_cwd = None

        # Attempting to create/get the logger should raise OSError,
        # and the partially initialised instance must be removed from cache.
        with pytest.raises(OSError, match="Current working directory"):
            logging.getLogger("oserror-logger")

        # Ensure that the logger with this name is not left registered in the
        # logging manager cache after failed initialisation.
        assert "oserror-logger" not in logging.Logger.manager.loggerDict
    finally:
        monkeypatch.setattr(os, "getcwd", original_getcwd)
        logging.setLoggerClass(logging.Logger)


def test_schema_logger_handles_runtimeerror_from_lock_and_cleans_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should catch RuntimeError from threading locks and clean up.

    If a threading lock raises RuntimeError (e.g., deadlock detection),
    the exception should be caught, logger should be cleaned up from cache,
    and exception should be re-raised.
    """
    import logging_objects_with_schema.schema_loader as schema_loader

    monkeypatch.chdir(tmp_path)
    _write_schema(tmp_path, {"ServicePayload": {}})

    original_lock = schema_loader._cache_lock

    class FakeLock:
        def __enter__(self) -> None:
            raise RuntimeError("Lock acquisition failed")

        def __exit__(self, *args: object) -> None:
            pass

    fake_lock = FakeLock()
    monkeypatch.setattr(schema_loader, "_cache_lock", fake_lock)

    logging.setLoggerClass(SchemaLogger)
    try:
        # Clear schema cache to force recompilation
        with original_lock:
            schema_loader._SCHEMA_CACHE.clear()
        with schema_loader._path_cache_lock:
            schema_loader._resolved_schema_path = None
            schema_loader._cached_cwd = None

        # Attempting to create/get the logger should raise RuntimeError,
        # and the partially initialised instance must be removed from cache.
        with pytest.raises(RuntimeError, match="Lock acquisition failed"):
            logging.getLogger("runtimeerror-logger")

        # Ensure that the logger with this name is not left registered in the
        # logging manager cache after failed initialisation.
        assert "runtimeerror-logger" not in logging.Logger.manager.loggerDict
    finally:
        monkeypatch.setattr(schema_loader, "_cache_lock", original_lock)
        logging.setLoggerClass(logging.Logger)


def test_schema_logger_handles_valueerror_and_cleans_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should catch ValueError and clean up logger.

    If ValueError is raised during schema compilation (outside of the
    try-except block in _compile_schema_internal), the exception should be
    caught, logger should be cleaned up from cache, and exception should be
    re-raised.
    """
    import logging_objects_with_schema.schema_loader as schema_loader

    monkeypatch.chdir(tmp_path)
    _write_schema(tmp_path, {"ServicePayload": {}})

    original_get_schema_path = schema_loader._get_schema_path

    def fake_get_schema_path() -> Path:
        raise ValueError("Unexpected value error during path resolution")

    monkeypatch.setattr(schema_loader, "_get_schema_path", fake_get_schema_path)

    logging.setLoggerClass(SchemaLogger)
    try:
        # Clear schema cache to force recompilation
        with schema_loader._cache_lock:
            schema_loader._SCHEMA_CACHE.clear()
        with schema_loader._path_cache_lock:
            schema_loader._resolved_schema_path = None
            schema_loader._cached_cwd = None

        # Attempting to create/get the logger should raise ValueError,
        # and the partially initialised instance must be removed from cache.
        with pytest.raises(ValueError, match="Unexpected value error"):
            logging.getLogger("valueerror-logger")

        # Ensure that the logger with this name is not left registered in the
        # logging manager cache after failed initialisation.
        assert "valueerror-logger" not in logging.Logger.manager.loggerDict
    finally:
        monkeypatch.setattr(schema_loader, "_get_schema_path", original_get_schema_path)
        logging.setLoggerClass(logging.Logger)
