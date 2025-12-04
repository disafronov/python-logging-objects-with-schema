"""Tests for thread safety of schema caching and logger creation."""

from __future__ import annotations

import logging
import threading
from pathlib import Path

import pytest

from logging_objects_with_schema import SchemaLogger
from logging_objects_with_schema.errors import SchemaValidationError
from tests.conftest import _write_schema


def test_concurrent_logger_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple threads creating SchemaLogger instances should work safely."""

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

    loggers: list[SchemaLogger] = []
    errors: list[Exception] = []
    lock = threading.Lock()

    def create_logger(thread_id: int) -> None:
        """Create a logger instance in a separate thread."""
        try:
            logger = SchemaLogger(f"logger-{thread_id}")
            with lock:
                loggers.append(logger)
        except Exception as e:
            with lock:
                errors.append(e)

    # Create multiple threads that simultaneously create loggers
    threads = []
    num_threads = 10
    for i in range(num_threads):
        thread = threading.Thread(target=create_logger, args=(i,))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # All loggers should be created successfully
    assert len(errors) == 0, f"Errors occurred: {errors}"
    assert len(loggers) == num_threads

    # All loggers should have the same schema
    first_schema = loggers[0]._schema
    for logger in loggers[1:]:
        assert logger._schema.leaves == first_schema.leaves


def test_concurrent_schema_compilation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Concurrent schema compilation should be thread-safe."""

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    compiled_schemas: list[object] = []
    errors: list[Exception] = []
    lock = threading.Lock()

    def compile_schema() -> None:
        """Compile schema in a separate thread."""
        try:
            from logging_objects_with_schema.schema_loader import (
                _compile_schema_internal as compile_schema_internal,
            )

            compiled, problems = compile_schema_internal()
            if problems:
                raise SchemaValidationError("Schema has problems", problems=problems)
            with lock:
                compiled_schemas.append(compiled)
        except Exception as e:
            with lock:
                errors.append(e)

    # Create multiple threads that simultaneously compile schema
    threads = []
    num_threads = 20
    for _ in range(num_threads):
        thread = threading.Thread(target=compile_schema)
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # All compilations should succeed
    assert len(errors) == 0, f"Errors occurred: {errors}"
    assert len(compiled_schemas) == num_threads

    # All compiled schemas should be identical
    first_schema = compiled_schemas[0]
    for schema in compiled_schemas[1:]:
        assert schema.leaves == first_schema.leaves


def test_concurrent_logging_operations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Concurrent logging operations should work safely."""

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
        logger = logging.getLogger("test-concurrent")

        errors: list[Exception] = []
        lock = threading.Lock()

        def log_message(thread_id: int) -> None:
            """Log a message in a separate thread."""
            try:
                logger.info(
                    f"Message from thread {thread_id}",
                    extra={"request_id": f"req-{thread_id}"},
                )
            except Exception as e:
                with lock:
                    errors.append(e)

        # Create multiple threads that simultaneously log
        threads = []
        num_threads = 10
        for i in range(num_threads):
            thread = threading.Thread(target=log_message, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # All logging operations should succeed
        assert len(errors) == 0, f"Errors occurred: {errors}"
    finally:
        logging.setLoggerClass(logging.Logger)
