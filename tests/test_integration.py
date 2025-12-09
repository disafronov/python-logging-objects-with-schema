"""Integration tests for SchemaLogger.

These tests verify the behavior of SchemaLogger in realistic scenarios,
including multiple logger instances, working directory changes, and error
handling during initialization (schema problems, file system errors, etc.).
"""

from __future__ import annotations

import logging
from io import StringIO
from pathlib import Path

import pytest

from logging_objects_with_schema import SchemaLogger
from logging_objects_with_schema.schema_loader import _SCHEMA_FILE_NAME
from tests.helpers import _write_schema


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


def test_schema_logger_creates_successfully_with_valid_empty_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should create successfully with a valid empty schema.

    A valid empty schema (e.g., {}) should not cause errors or terminate
    the application. The logger should be created successfully.
    """

    monkeypatch.chdir(tmp_path)
    _write_schema(tmp_path, {})

    # Creating logger with empty schema should not raise exceptions or terminate
    logger = SchemaLogger("test-logger")

    assert isinstance(logger, logging.Logger)
    assert logger.name == "test-logger"
    # Verify that the logger has the _schema attribute set
    assert hasattr(logger, "_schema")
    # Verify that the schema is empty (no leaves)
    assert logger._schema.is_empty


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

    schema_file = tmp_path / _SCHEMA_FILE_NAME
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


def test_schema_logger_terminates_on_bad_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should terminate application when schema has problems."""

    import os
    import sys
    from io import StringIO

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
        SchemaLogger("test-logger")

    assert exit_called
    assert exit_code == 1
    assert "Schema has problems" in stderr_output.getvalue()


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

    import os
    import sys
    from io import StringIO

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

    logging.setLoggerClass(SchemaLogger)
    try:
        # 1) Write an invalid schema that triggers termination.
        _write_schema(
            tmp_path,
            {
                "name": {
                    "Value": {"type": "str", "source": "value"},
                },
            },
        )

        # Attempting to create/get the logger should terminate the application,
        # and the partially initialised instance must be removed from cache.
        with pytest.raises(SystemExit):
            logging.getLogger("bad-schema-logger")

        assert exit_called
        assert exit_code == 1

        # Ensure that the logger with this name is not left registered in the
        # logging manager cache after failed initialisation.
        assert "bad-schema-logger" not in logging.Logger.manager.loggerDict
    finally:
        logging.setLoggerClass(logging.Logger)


def test_schema_logger_handles_oserror_from_getcwd_and_terminates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should catch OSError from os.getcwd() and terminate.

    If os.getcwd() raises OSError (e.g., when CWD is deleted), the exception
    should be converted to _SchemaProblem, logger should be cleaned up from cache,
    and application should be terminated.
    """
    import os
    import sys
    from io import StringIO

    import logging_objects_with_schema.schema_loader as schema_loader

    monkeypatch.chdir(tmp_path)
    _write_schema(tmp_path, {"ServicePayload": {}})

    original_getcwd = os.getcwd

    def fake_getcwd() -> str:
        raise OSError("Current working directory no longer exists")

    monkeypatch.setattr(os, "getcwd", fake_getcwd)

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

    logging.setLoggerClass(SchemaLogger)
    try:
        # Clear schema cache to force recompilation
        with schema_loader._cache_lock:
            schema_loader._SCHEMA_CACHE.clear()
        with schema_loader._path_cache_lock:
            schema_loader._resolved_schema_path = None
            schema_loader._cached_cwd = None

        # Attempting to create/get the logger should terminate the application,
        # and the partially initialised instance must be removed from cache.
        with pytest.raises(SystemExit):
            logging.getLogger("oserror-logger")

        assert exit_called
        assert exit_code == 1
        assert "Schema has problems" in stderr_output.getvalue()

        # Ensure that the logger with this name is not left registered in the
        # logging manager cache after failed initialisation.
        assert "oserror-logger" not in logging.Logger.manager.loggerDict
    finally:
        monkeypatch.setattr(os, "getcwd", original_getcwd)
        logging.setLoggerClass(logging.Logger)


def test_schema_logger_handles_runtimeerror_from_lock_and_terminates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should catch RuntimeError from threading locks and terminate.

    If a threading lock raises RuntimeError (e.g., deadlock detection),
    the exception should be converted to _SchemaProblem, logger should be cleaned
    up from cache, and application should be terminated.
    """
    import os
    import sys
    from io import StringIO

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

    logging.setLoggerClass(SchemaLogger)
    try:
        # Clear schema cache to force recompilation
        with original_lock:
            schema_loader._SCHEMA_CACHE.clear()
        with schema_loader._path_cache_lock:
            schema_loader._resolved_schema_path = None
            schema_loader._cached_cwd = None

        # Attempting to create/get the logger should terminate the application,
        # and the partially initialised instance must be removed from cache.
        with pytest.raises(SystemExit):
            logging.getLogger("runtimeerror-logger")

        assert exit_called
        assert exit_code == 1
        assert "Schema has problems" in stderr_output.getvalue()

        # Ensure that the logger with this name is not left registered in the
        # logging manager cache after failed initialisation.
        assert "runtimeerror-logger" not in logging.Logger.manager.loggerDict
    finally:
        monkeypatch.setattr(schema_loader, "_cache_lock", original_lock)
        logging.setLoggerClass(logging.Logger)


def test_schema_logger_handles_valueerror_and_terminates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should catch ValueError and terminate.

    If ValueError is raised during schema compilation (outside of the
    try-except block in _compile_schema_internal), the exception should be
    converted to _SchemaProblem, logger should be cleaned up from cache,
    and application should be terminated.
    """
    import os
    import sys
    from io import StringIO

    import logging_objects_with_schema.schema_loader as schema_loader

    monkeypatch.chdir(tmp_path)
    _write_schema(tmp_path, {"ServicePayload": {}})

    original_get_schema_path = schema_loader._get_schema_path

    def fake_get_schema_path() -> Path:
        raise ValueError("Unexpected value error during path resolution")

    monkeypatch.setattr(schema_loader, "_get_schema_path", fake_get_schema_path)

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

    logging.setLoggerClass(SchemaLogger)
    try:
        # Clear schema cache to force recompilation
        with schema_loader._cache_lock:
            schema_loader._SCHEMA_CACHE.clear()
        with schema_loader._path_cache_lock:
            schema_loader._resolved_schema_path = None
            schema_loader._cached_cwd = None

        # Attempting to create/get the logger should terminate the application,
        # and the partially initialised instance must be removed from cache.
        with pytest.raises(SystemExit):
            logging.getLogger("valueerror-logger")

        assert exit_called
        assert exit_code == 1
        assert "Schema has problems" in stderr_output.getvalue()

        # Ensure that the logger with this name is not left registered in the
        # logging manager cache after failed initialisation.
        assert "valueerror-logger" not in logging.Logger.manager.loggerDict
    finally:
        monkeypatch.setattr(schema_loader, "_get_schema_path", original_get_schema_path)
        logging.setLoggerClass(logging.Logger)


def test_schema_logger_with_forbidden_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SchemaLogger should accept forbidden_keys parameter and use it for validation."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
            "CustomForbidden": {
                "Value": {"type": "str", "source": "value"},
            },
        },
    )

    # Without forbidden_keys, CustomForbidden should be valid
    logger1 = SchemaLogger("logger1")
    assert isinstance(logger1, SchemaLogger)

    # With forbidden_keys, CustomForbidden should cause schema validation to fail
    import sys
    from io import StringIO

    stderr_output = StringIO()
    original_stderr = sys.stderr
    sys.stderr = stderr_output

    exit_called = False
    exit_code = None

    def mock_exit(code: int) -> None:
        nonlocal exit_called, exit_code
        exit_called = True
        exit_code = code

    monkeypatch.setattr("os._exit", mock_exit)

    try:
        SchemaLogger("logger2", forbidden_keys={"CustomForbidden"})
    except SystemExit:
        pass
    finally:
        sys.stderr = original_stderr

    assert exit_called
    assert exit_code == 1
    assert "CustomForbidden" in stderr_output.getvalue()
    assert "conflicts with reserved logging fields" in stderr_output.getvalue()


def test_schema_logger_inheritance_with_forbidden_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Subclass of SchemaLogger can pass forbidden_keys to parent."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
            "ChildForbidden": {
                "Value": {"type": "str", "source": "value"},
            },
        },
    )

    class ChildLogger(SchemaLogger):
        def __init__(self, name: str, level: int = logging.NOTSET) -> None:
            # Child can pass its own forbidden keys to parent
            super().__init__(name, level, forbidden_keys={"ChildForbidden"})

    # Creating child logger should fail because ChildForbidden conflicts
    import sys
    from io import StringIO

    stderr_output = StringIO()
    original_stderr = sys.stderr
    sys.stderr = stderr_output

    exit_called = False
    exit_code = None

    def mock_exit(code: int) -> None:
        nonlocal exit_called, exit_code
        exit_called = True
        exit_code = code

    monkeypatch.setattr("os._exit", mock_exit)

    try:
        ChildLogger("child_logger")
    except SystemExit:
        pass
    finally:
        sys.stderr = original_stderr

    assert exit_called
    assert exit_code == 1
    assert "ChildForbidden" in stderr_output.getvalue()


def test_schema_logger_inheritance_merges_forbidden_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Subclass can merge forbidden_keys from its own subclass and pass to parent."""
    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
            "ParentForbidden": {
                "Value": {"type": "str", "source": "value"},
            },
            "ChildForbidden": {
                "Value": {"type": "str", "source": "value2"},
            },
        },
    )

    class ParentLogger(SchemaLogger):
        def __init__(
            self,
            name: str,
            level: int = logging.NOTSET,
            forbidden_keys: set[str] | None = None,
        ) -> None:
            # Parent merges its own keys with keys from child
            parent_keys = {"ParentForbidden"}
            if forbidden_keys:
                parent_keys = parent_keys | forbidden_keys
            super().__init__(name, level, forbidden_keys=parent_keys)

    class ChildLogger(ParentLogger):
        def __init__(self, name: str, level: int = logging.NOTSET) -> None:
            # Child passes its keys to parent, which merges them
            super().__init__(name, level, forbidden_keys={"ChildForbidden"})

    # Creating child logger should fail because both ParentForbidden and
    # ChildForbidden conflict
    import sys
    from io import StringIO

    stderr_output = StringIO()
    original_stderr = sys.stderr
    sys.stderr = stderr_output

    exit_called = False
    exit_code = None

    def mock_exit(code: int) -> None:
        nonlocal exit_called, exit_code
        exit_called = True
        exit_code = code

    monkeypatch.setattr("os._exit", mock_exit)

    try:
        ChildLogger("child_logger")
    except SystemExit:
        pass
    finally:
        sys.stderr = original_stderr

    assert exit_called
    assert exit_code == 1
    output = stderr_output.getvalue()
    assert "ParentForbidden" in output
    assert "ChildForbidden" in output
