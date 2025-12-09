"""Tests for mypy type checking support."""

from __future__ import annotations

import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

from logging_objects_with_schema import SchemaLogger
from tests.helpers import _write_schema


def test_py_typed_file_exists() -> None:
    """Verify that py.typed marker file exists in the package."""
    package_dir = Path(__file__).parent.parent / "src" / "logging_objects_with_schema"
    py_typed = package_dir / "py.typed"

    assert py_typed.exists(), "py.typed marker file must exist for mypy support"


def test_mypy_type_checking() -> None:
    """Verify that mypy can type-check the package without errors."""
    package_dir = Path(__file__).parent.parent / "src" / "logging_objects_with_schema"

    # Run mypy on the package directory
    result = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-m",
            "mypy",
            str(package_dir),
            "--no-error-summary",
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    assert (
        result.returncode == 0
    ), f"mypy found type errors:\n{result.stdout}\n{result.stderr}"


def test_mypy_strict_type_checking() -> None:
    """Verify that mypy can type-check the package in strict mode without errors."""
    package_dir = Path(__file__).parent.parent / "src" / "logging_objects_with_schema"

    # Run mypy in strict mode on the package directory
    result = subprocess.run(  # nosec B603
        [
            sys.executable,
            "-m",
            "mypy",
            str(package_dir),
            "--strict",
            "--no-error-summary",
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )

    assert (
        result.returncode == 0
    ), f"mypy found type errors in strict mode:\n{result.stdout}\n{result.stderr}"


def test_schema_logger_type_annotations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that SchemaLogger has correct type annotations for mypy."""
    # This test verifies that type annotations are correct by using them
    # If mypy is run on this file, it should not find any errors

    monkeypatch.chdir(tmp_path)
    _write_schema(tmp_path, {"ServicePayload": {}})

    # Test that SchemaLogger can be typed correctly
    logger: SchemaLogger = SchemaLogger("test-logger", forbidden_keys=None)

    # Test that __init__ signature accepts correct types
    logger2: SchemaLogger = SchemaLogger(
        name="test-logger-2",
        level=10,
        forbidden_keys={"key1", "key2"},
    )

    # Test that SchemaLogger is compatible with logging.Logger
    import logging

    def accept_logger(logger: logging.Logger) -> logging.Logger:
        return logger

    # This should work without type errors
    result: logging.Logger = accept_logger(logger)
    assert isinstance(result, SchemaLogger)

    # Test that logger methods are accessible and typed
    logger.info("test message")
    logger.debug("debug message", extra={"key": "value"})
    logger.warning("warning message")

    # Verify logger2 was created successfully (test __init__ signature)
    assert logger2.name == "test-logger-2"
