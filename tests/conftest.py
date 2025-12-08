"""Shared fixtures and helper functions for tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from logging_objects_with_schema import schema_loader
from logging_objects_with_schema.schema_loader import _SCHEMA_FILE_NAME


@pytest.fixture(autouse=True)
def clear_schema_cache() -> None:
    """Clear schema path cache before each test to ensure test isolation."""
    with schema_loader._path_cache_lock:
        schema_loader._resolved_schema_path = None
        schema_loader._cached_cwd = None
    yield
    with schema_loader._path_cache_lock:
        schema_loader._resolved_schema_path = None
        schema_loader._cached_cwd = None


def _write_schema(tmp_path: Path, data: dict) -> None:
    """Write schema file to temporary directory.

    Args:
        tmp_path: Temporary directory path.
        data: Schema data to write as JSON.
    """
    schema_path = tmp_path / _SCHEMA_FILE_NAME
    schema_path.write_text(json.dumps(data), encoding="utf-8")
