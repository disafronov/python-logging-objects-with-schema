"""Shared fixtures for tests."""

from __future__ import annotations

import pytest

from logging_objects_with_schema import schema_loader


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
