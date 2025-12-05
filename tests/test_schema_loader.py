"""Basic tests for schema loading behaviour.

These tests are intentionally minimal and are meant to illustrate the
expected contract rather than exhaustively cover edge cases.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from logging_objects_with_schema.schema_loader import (
    SCHEMA_FILE_NAME,
    CompiledSchema,
)
from logging_objects_with_schema.schema_loader import (
    _compile_schema_internal as compile_schema_internal,
)
from tests.conftest import _write_schema


def test_missing_schema_file_produces_empty_schema_and_problem(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing schema file should result in empty compiled schema and problems."""

    monkeypatch.chdir(tmp_path)

    compiled, problems = compile_schema_internal()

    assert isinstance(compiled, CompiledSchema)
    assert compiled.is_empty
    assert problems


def test_completely_invalid_schema_is_empty_and_reports_problems(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Completely invalid schema should produce empty compiled schema and problems."""

    monkeypatch.chdir(tmp_path)
    _write_schema(tmp_path, {"foo": "not-an-object"})

    compiled, problems = compile_schema_internal()

    assert isinstance(compiled, CompiledSchema)
    assert compiled.is_empty
    assert problems


def test_partially_valid_schema_preserves_valid_leaves(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Partially valid schema should keep valid leaves in compiled_schema."""

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
                "Broken": {"type": "unknown-type", "source": "broken"},
            },
        },
    )

    compiled, problems = compile_schema_internal()
    assert isinstance(compiled, CompiledSchema)
    assert not compiled.is_empty
    assert any(leaf.source == "request_id" for leaf in compiled.leaves)
    assert problems


def test_root_key_conflicting_with_logging_field_produces_problem(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Root key conflicting with logging.LogRecord field produces SchemaProblem."""

    monkeypatch.chdir(tmp_path)
    # Use a known LogRecord attribute like "name" or "levelno"
    _write_schema(
        tmp_path,
        {
            "name": {
                "Value": {"type": "str", "source": "value"},
            },
        },
    )

    compiled, problems = compile_schema_internal()
    assert isinstance(compiled, CompiledSchema)
    assert any(
        "conflicts with reserved logging fields" in problem.message
        for problem in problems
    )


def test_root_key_not_conflicting_passes_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Root key that does not conflict with logging fields should pass validation."""

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
        },
    )

    compiled, problems = compile_schema_internal()
    assert isinstance(compiled, CompiledSchema)
    assert not compiled.is_empty
    # Should not have problems related to root key conflicts
    root_conflict_problems = [
        p for p in problems if "conflicts with reserved logging fields" in p.message
    ]
    assert not root_conflict_problems


def test_empty_schema_produces_empty_compiled_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Empty schema {} should produce empty compiled schema with no problems."""

    monkeypatch.chdir(tmp_path)
    _write_schema(tmp_path, {})

    compiled, problems = compile_schema_internal()
    assert isinstance(compiled, CompiledSchema)
    assert compiled.is_empty
    assert problems == []


def test_schema_with_only_inner_nodes_produces_empty_compiled_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Schema with only inner nodes (no leaves) should produce empty compiled schema."""

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "Metadata": {
                    "Nested": {},
                },
            },
        },
    )

    compiled, problems = compile_schema_internal()
    assert isinstance(compiled, CompiledSchema)
    assert compiled.is_empty
    # Schema with only inner nodes is valid, just empty (no problems)
    assert problems == []


def test_deeply_nested_schema_compiles_correctly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Very deeply nested schema should compile correctly."""

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "Level1": {
                "Level2": {
                    "Level3": {
                        "Level4": {
                            "Level5": {
                                "Value": {"type": "str", "source": "value"},
                            },
                        },
                    },
                },
            },
        },
    )

    compiled, problems = compile_schema_internal()
    assert isinstance(compiled, CompiledSchema)
    assert not compiled.is_empty
    assert len(compiled.leaves) == 1
    assert compiled.leaves[0].source == "value"
    assert compiled.leaves[0].path == (
        "Level1",
        "Level2",
        "Level3",
        "Level4",
        "Level5",
        "Value",
    )
    assert problems == []


def test_duplicate_source_in_different_branches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same source used in different branches should create multiple leaves."""

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "Branch1": {
                "Value": {"type": "str", "source": "shared_id"},
            },
            "Branch2": {
                "Nested": {
                    "ID": {"type": "str", "source": "shared_id"},
                },
            },
        },
    )

    compiled, problems = compile_schema_internal()
    assert isinstance(compiled, CompiledSchema)
    assert not compiled.is_empty
    # Should have two leaves with same source but different paths
    leaves_with_source = [
        leaf for leaf in compiled.leaves if leaf.source == "shared_id"
    ]
    assert len(leaves_with_source) == 2
    assert leaves_with_source[0].path == ("Branch1", "Value")
    assert leaves_with_source[1].path == ("Branch2", "Nested", "ID")
    assert problems == []


def test_incomplete_leaf_missing_type(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Leaf with source but no type should produce problem."""

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"source": "request_id"},  # Missing type
            },
        },
    )

    compiled, problems = compile_schema_internal()
    assert isinstance(compiled, CompiledSchema)
    assert compiled.is_empty
    assert any("type cannot be None or empty" in p.message for p in problems)


def test_incomplete_leaf_missing_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Leaf with type but no source should produce problem."""

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str"},  # Missing source
            },
        },
    )

    compiled, problems = compile_schema_internal()
    assert isinstance(compiled, CompiledSchema)
    assert compiled.is_empty
    assert any("source cannot be None or empty" in p.message for p in problems)


def test_incomplete_leaf_empty_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Leaf with empty source string should produce problem."""

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": ""},  # Empty source
            },
        },
    )

    compiled, problems = compile_schema_internal()
    assert isinstance(compiled, CompiledSchema)
    assert compiled.is_empty
    assert any("source cannot be None or empty" in p.message for p in problems)


def test_incomplete_leaf_empty_type(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Leaf with empty type string should produce problem."""

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "", "source": "request_id"},  # Empty type
            },
        },
    )

    compiled, problems = compile_schema_internal()
    assert isinstance(compiled, CompiledSchema)
    assert compiled.is_empty
    assert any("type cannot be None or empty" in p.message for p in problems)


def test_multiple_root_keys_with_valid_leaves(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple root keys with valid leaves should compile correctly."""

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "ServicePayload": {
                "RequestID": {"type": "str", "source": "request_id"},
            },
            "UserPayload": {
                "UserID": {"type": "int", "source": "user_id"},
            },
            "MetricsPayload": {
                "CPU": {"type": "float", "source": "cpu_usage"},
            },
        },
    )

    compiled, problems = compile_schema_internal()
    assert isinstance(compiled, CompiledSchema)
    assert not compiled.is_empty
    assert len(compiled.leaves) == 3
    sources = {leaf.source for leaf in compiled.leaves}
    assert sources == {"request_id", "user_id", "cpu_usage"}
    assert problems == []


def test_find_schema_file_searches_upward(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_find_schema_file should search upward to find schema file."""

    from logging_objects_with_schema.schema_loader import _find_schema_file

    # Create nested directory structure
    root_dir = tmp_path / "project"
    sub_dir = root_dir / "src" / "app"
    sub_dir.mkdir(parents=True)

    # Place schema file in root
    _write_schema(
        root_dir,
        {"ServicePayload": {"RequestID": {"type": "str", "source": "request_id"}}},
    )

    # Change to subdirectory
    monkeypatch.chdir(sub_dir)

    # Should find schema file in root
    found_path = _find_schema_file()
    assert found_path is not None
    assert found_path == (root_dir / SCHEMA_FILE_NAME).resolve()
    assert found_path.exists()


def test_find_schema_file_returns_none_if_not_found(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_find_schema_file should return None if schema file is not found."""

    from logging_objects_with_schema.schema_loader import _find_schema_file

    # Create directory without schema file
    test_dir = tmp_path / "no_schema"
    test_dir.mkdir()

    # Change to that directory
    monkeypatch.chdir(test_dir)

    # Should return None
    found_path = _find_schema_file()
    assert found_path is None


def test_schema_file_os_error_produces_problem_and_empty_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """I/O errors when reading schema file should produce problems, not OSError."""

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

    schema_file = tmp_path / SCHEMA_FILE_NAME
    original_open = schema_loader.Path.open  # type: ignore[attr-defined]

    def fake_open(self, *args, **kwargs):  # type: ignore[override]
        if self == schema_file:
            raise PermissionError("permission denied")
        return original_open(self, *args, **kwargs)

    # Patch Path.open used inside schema_loader so that reading the schema
    # file raises an OSError (PermissionError in this case).
    monkeypatch.setattr(schema_loader.Path, "open", fake_open)

    compiled, problems = compile_schema_internal()

    assert isinstance(compiled, CompiledSchema)
    assert compiled.is_empty
    assert problems
    assert any("Failed to read schema file" in p.message for p in problems)


def test_schema_changes_on_disk_are_not_reloaded_in_same_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Schema changes on disk should not be reloaded within the same process."""

    monkeypatch.chdir(tmp_path)
    _write_schema(
        tmp_path,
        {
            "Payload": {
                "Value": {"type": "str", "source": "v1"},
            },
        },
    )

    compiled1, problems1 = compile_schema_internal()
    assert isinstance(compiled1, CompiledSchema)
    assert not compiled1.is_empty
    assert any(leaf.source == "v1" for leaf in compiled1.leaves)
    assert problems1 == []

    # Modify schema on disk to use a different source name.
    _write_schema(
        tmp_path,
        {
            "Payload": {
                "Value": {"type": "str", "source": "v2"},
            },
        },
    )

    compiled2, problems2 = compile_schema_internal()
    # Compiled schema and problems should be served from cache, ignoring
    # on-disk changes.
    assert isinstance(compiled2, CompiledSchema)
    assert not compiled2.is_empty
    assert any(leaf.source == "v1" for leaf in compiled2.leaves)
    assert not any(leaf.source == "v2" for leaf in compiled2.leaves)
    assert problems2 == []


def test_invalid_schema_result_is_cached_within_same_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Once an invalid schema is observed, the result is cached for this process."""

    monkeypatch.chdir(tmp_path)

    # 1) Write a completely invalid schema (non-object at top level).
    _write_schema(tmp_path, {"foo": "not-an-object"})

    compiled1, problems1 = compile_schema_internal()
    assert isinstance(compiled1, CompiledSchema)
    assert compiled1.is_empty
    assert problems1

    # 2) Fix schema on disk to a valid one with a proper leaf.
    _write_schema(
        tmp_path,
        {
            "Payload": {
                "Value": {"type": "str", "source": "value"},
            },
        },
    )

    compiled2, problems2 = compile_schema_internal()

    # Still see the cached "invalid" result: no leaves and the original problems.
    assert isinstance(compiled2, CompiledSchema)
    assert compiled2.is_empty
    assert problems2
