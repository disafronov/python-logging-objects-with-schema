"""Shared fixtures for tests."""

import pytest

from logging_objects_with_schema import schema_loader


@pytest.fixture(autouse=True)
def clear_schema_cache() -> None:
    """Clear all schema caches before each test to ensure test isolation."""

    def _clear() -> None:
        with schema_loader._path_cache_lock:
            schema_loader._resolved_schema_path = None
            schema_loader._cached_cwd = None
        with schema_loader._cache_lock:
            schema_loader._SCHEMA_CACHE.clear()

    _clear()
    yield
    _clear()
