"""Basic tests for schema loading behaviour.

These tests are intentionally minimal and are meant to illustrate the
expected contract rather than exhaustively cover edge cases.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import logging_objects_with_schema.schema_loader as schema_loader
from logging_objects_with_schema.errors import _SchemaProblem
from logging_objects_with_schema.schema_loader import (
    _SCHEMA_FILE_NAME,
    MAX_SCHEMA_DEPTH,
)
from logging_objects_with_schema.schema_loader import (
    _cache_and_return_found_path as cache_and_return_found_path,
)
from logging_objects_with_schema.schema_loader import (
    _cache_and_return_missing_path as cache_and_return_missing_path,
)
from logging_objects_with_schema.schema_loader import (
    _check_cached_found_file_path as check_cached_found_file_path,
)
from logging_objects_with_schema.schema_loader import (
    _check_cached_missing_file_path as check_cached_missing_file_path,
)
from logging_objects_with_schema.schema_loader import (
    _check_root_conflicts as check_root_conflicts,
)
from logging_objects_with_schema.schema_loader import (
    _compile_schema_internal as compile_schema_internal,
)
from logging_objects_with_schema.schema_loader import (
    _compile_schema_tree as compile_schema_tree,
)
from logging_objects_with_schema.schema_loader import (
    _CompiledSchema,
)
from logging_objects_with_schema.schema_loader import (
    _create_empty_compiled_schema_with_problems as create_empty_schema,
)
from logging_objects_with_schema.schema_loader import _format_path as format_path
from logging_objects_with_schema.schema_loader import (
    _get_builtin_logrecord_attributes,
)
from logging_objects_with_schema.schema_loader import (
    _get_current_working_directory as get_current_working_directory,
)
from logging_objects_with_schema.schema_loader import (
    _get_schema_path as get_schema_path,
)
from logging_objects_with_schema.schema_loader import (
    _is_empty_or_none as is_empty_or_none,
)
from logging_objects_with_schema.schema_loader import _is_leaf_node as is_leaf_node
from logging_objects_with_schema.schema_loader import (
    _load_raw_schema as load_raw_schema,
)
from logging_objects_with_schema.schema_loader import (
    _SchemaLeaf,
)
from logging_objects_with_schema.schema_loader import (
    _validate_and_create_leaf as validate_and_create_leaf,
)
from tests.helpers import _write_schema


def test_missing_schema_file_produces_empty_schema_and_problem(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing schema file should result in empty compiled schema and problems."""

    monkeypatch.chdir(tmp_path)

    compiled, problems = compile_schema_internal()

    assert isinstance(compiled, _CompiledSchema)
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

    assert isinstance(compiled, _CompiledSchema)
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
    assert isinstance(compiled, _CompiledSchema)
    assert not compiled.is_empty
    assert any(leaf.source == "request_id" for leaf in compiled.leaves)
    assert problems


def test_root_key_conflicting_with_logging_field_produces_problem(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Root key conflicting with logging.LogRecord field produces _SchemaProblem."""

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
    assert isinstance(compiled, _CompiledSchema)
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
    assert isinstance(compiled, _CompiledSchema)
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
    assert isinstance(compiled, _CompiledSchema)
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
    assert isinstance(compiled, _CompiledSchema)
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
    assert isinstance(compiled, _CompiledSchema)
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
    assert isinstance(compiled, _CompiledSchema)
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
    assert isinstance(compiled, _CompiledSchema)
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
    assert isinstance(compiled, _CompiledSchema)
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
    assert isinstance(compiled, _CompiledSchema)
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
    assert isinstance(compiled, _CompiledSchema)
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
    assert isinstance(compiled, _CompiledSchema)
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
    assert found_path == (root_dir / _SCHEMA_FILE_NAME).resolve()
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

    schema_file = tmp_path / _SCHEMA_FILE_NAME
    original_open = schema_loader.Path.open  # type: ignore[attr-defined]

    def fake_open(self, *args, **kwargs):  # type: ignore[override]
        if self == schema_file:
            raise PermissionError("permission denied")
        return original_open(self, *args, **kwargs)

    # Patch Path.open used inside schema_loader so that reading the schema
    # file raises an OSError (PermissionError in this case).
    monkeypatch.setattr(schema_loader.Path, "open", fake_open)

    compiled, problems = compile_schema_internal()

    assert isinstance(compiled, _CompiledSchema)
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
    assert isinstance(compiled1, _CompiledSchema)
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
    assert isinstance(compiled2, _CompiledSchema)
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
    assert isinstance(compiled1, _CompiledSchema)
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
    assert isinstance(compiled2, _CompiledSchema)
    assert compiled2.is_empty
    assert problems2


def test_format_path_without_key() -> None:
    """_format_path should format path tuple without key."""
    assert format_path(("Level1", "Level2")) == "Level1.Level2"
    assert format_path(("ServicePayload",)) == "ServicePayload"
    assert format_path(()) == ""


def test_format_path_with_key() -> None:
    """_format_path should format path tuple with additional key."""
    assert format_path(("Level1", "Level2"), "Level3") == "Level1.Level2.Level3"
    assert format_path(("ServicePayload",), "RequestID") == "ServicePayload.RequestID"
    assert format_path((), "Root") == "Root"


def test_is_empty_or_none_with_none() -> None:
    """_is_empty_or_none should return True for None."""
    assert is_empty_or_none(None) is True


def test_is_empty_or_none_with_empty_string() -> None:
    """_is_empty_or_none should return True for empty string."""
    assert is_empty_or_none("") is True


def test_is_empty_or_none_with_whitespace_only_string() -> None:
    """_is_empty_or_none should return True for whitespace-only strings."""
    assert is_empty_or_none("   ") is True
    assert is_empty_or_none("\t\n") is True
    assert is_empty_or_none(" \t \n ") is True


def test_is_empty_or_none_with_valid_string() -> None:
    """_is_empty_or_none should return False for non-empty strings."""
    assert is_empty_or_none("valid") is False
    assert is_empty_or_none("  valid  ") is False
    assert is_empty_or_none("str") is False


def test_is_empty_or_none_with_non_string_types() -> None:
    """_is_empty_or_none should return False for non-string, non-None types."""
    assert is_empty_or_none(0) is False
    assert is_empty_or_none(42) is False
    assert is_empty_or_none([]) is False
    assert is_empty_or_none({}) is False
    assert is_empty_or_none(True) is False


def test_validate_and_create_leaf_valid_primitive() -> None:
    """_validate_and_create_leaf should create _SchemaLeaf for valid primitive type."""
    problems: list[_SchemaProblem] = []
    value_dict = {"type": "str", "source": "request_id"}

    leaf = validate_and_create_leaf(
        value_dict, ("ServicePayload",), "RequestID", problems
    )

    assert leaf is not None
    assert isinstance(leaf, _SchemaLeaf)
    assert leaf.path == ("ServicePayload", "RequestID")
    assert leaf.source == "request_id"
    assert leaf.expected_type is str
    assert leaf.item_expected_type is None
    assert problems == []


def test_validate_and_create_leaf_valid_list_type() -> None:
    """_validate_and_create_leaf should create _SchemaLeaf for valid list type."""
    problems: list[_SchemaProblem] = []
    value_dict = {"type": "list", "source": "tags", "item_type": "str"}

    leaf = validate_and_create_leaf(value_dict, ("ServicePayload",), "Tags", problems)

    assert leaf is not None
    assert isinstance(leaf, _SchemaLeaf)
    assert leaf.path == ("ServicePayload", "Tags")
    assert leaf.source == "tags"
    assert leaf.expected_type is list
    assert leaf.item_expected_type is str
    assert problems == []


def test_validate_and_create_leaf_missing_type() -> None:
    """_validate_and_create_leaf should return None and add problem for missing type."""
    problems: list[_SchemaProblem] = []
    value_dict = {"source": "request_id"}

    leaf = validate_and_create_leaf(
        value_dict, ("ServicePayload",), "RequestID", problems
    )

    assert leaf is None
    assert len(problems) == 1
    assert "type cannot be None or empty" in problems[0].message


def test_validate_and_create_leaf_missing_source() -> None:
    """_validate_and_create_leaf should return None for missing source."""
    problems: list[_SchemaProblem] = []
    value_dict = {"type": "str"}

    leaf = validate_and_create_leaf(
        value_dict, ("ServicePayload",), "RequestID", problems
    )

    assert leaf is None
    assert len(problems) == 1
    assert "source cannot be None or empty" in problems[0].message


def test_validate_and_create_leaf_empty_type() -> None:
    """_validate_and_create_leaf should return None for empty type string."""
    problems: list[_SchemaProblem] = []
    value_dict = {"type": "", "source": "request_id"}

    leaf = validate_and_create_leaf(
        value_dict, ("ServicePayload",), "RequestID", problems
    )

    assert leaf is None
    assert len(problems) == 1
    assert "type cannot be None or empty" in problems[0].message


def test_validate_and_create_leaf_whitespace_type() -> None:
    """_validate_and_create_leaf should return None for whitespace-only type string."""
    problems: list[_SchemaProblem] = []
    value_dict = {"type": "   ", "source": "request_id"}

    leaf = validate_and_create_leaf(
        value_dict, ("ServicePayload",), "RequestID", problems
    )

    assert leaf is None
    assert len(problems) == 1
    assert "type cannot be None or empty" in problems[0].message


def test_validate_and_create_leaf_empty_source() -> None:
    """_validate_and_create_leaf should return None for empty source string."""
    problems: list[_SchemaProblem] = []
    value_dict = {"type": "str", "source": ""}

    leaf = validate_and_create_leaf(
        value_dict, ("ServicePayload",), "RequestID", problems
    )

    assert leaf is None
    assert len(problems) == 1
    assert "source cannot be None or empty" in problems[0].message


def test_validate_and_create_leaf_whitespace_source() -> None:
    """_validate_and_create_leaf should return None for whitespace source."""
    problems: list[_SchemaProblem] = []
    value_dict = {"type": "str", "source": "\t\n"}

    leaf = validate_and_create_leaf(
        value_dict, ("ServicePayload",), "RequestID", problems
    )

    assert leaf is None
    assert len(problems) == 1
    assert "source cannot be None or empty" in problems[0].message


def test_validate_and_create_leaf_unknown_type() -> None:
    """_validate_and_create_leaf should return None for unknown type."""
    problems: list[_SchemaProblem] = []
    value_dict = {"type": "unknown_type", "source": "request_id"}

    leaf = validate_and_create_leaf(
        value_dict, ("ServicePayload",), "RequestID", problems
    )

    assert leaf is None
    assert len(problems) == 1
    assert "Unknown type" in problems[0].message
    assert "unknown_type" in problems[0].message


def test_validate_and_create_leaf_list_missing_item_type() -> None:
    """_validate_and_create_leaf should return None for list type without item_type."""
    problems: list[_SchemaProblem] = []
    value_dict = {"type": "list", "source": "tags"}

    leaf = validate_and_create_leaf(value_dict, ("ServicePayload",), "Tags", problems)

    assert leaf is None
    assert len(problems) == 1
    assert "item_type is required for list type" in problems[0].message


def test_validate_and_create_leaf_list_empty_item_type() -> None:
    """_validate_and_create_leaf should return None for empty item_type."""
    problems: list[_SchemaProblem] = []
    value_dict = {"type": "list", "source": "tags", "item_type": ""}

    leaf = validate_and_create_leaf(value_dict, ("ServicePayload",), "Tags", problems)

    assert leaf is None
    assert len(problems) == 1
    assert "item_type is required for list type" in problems[0].message


def test_validate_and_create_leaf_list_invalid_item_type() -> None:
    """_validate_and_create_leaf should return None for invalid item_type."""
    problems: list[_SchemaProblem] = []
    value_dict = {"type": "list", "source": "tags", "item_type": "list"}

    leaf = validate_and_create_leaf(value_dict, ("ServicePayload",), "Tags", problems)

    assert leaf is None
    assert len(problems) == 1
    assert "Invalid item_type" in problems[0].message
    assert "only primitive item types" in problems[0].message


def test_validate_and_create_leaf_list_unknown_item_type() -> None:
    """_validate_and_create_leaf should return None for unknown item_type."""
    problems: list[_SchemaProblem] = []
    value_dict = {"type": "list", "source": "tags", "item_type": "unknown"}

    leaf = validate_and_create_leaf(value_dict, ("ServicePayload",), "Tags", problems)

    assert leaf is None
    assert len(problems) == 1
    assert "Invalid item_type" in problems[0].message


def test_validate_and_create_leaf_all_primitive_types() -> None:
    """_validate_and_create_leaf should work with all primitive types."""
    problems: list[_SchemaProblem] = []

    for type_name, expected_type in [
        ("str", str),
        ("int", int),
        ("float", float),
        ("bool", bool),
    ]:
        value_dict = {"type": type_name, "source": f"{type_name}_value"}
        leaf = validate_and_create_leaf(value_dict, ("Payload",), "Value", problems)

        assert leaf is not None
        assert leaf.expected_type is expected_type
        assert problems == []
        problems.clear()


def test_schema_exceeds_max_depth_produces_problem(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Schema exceeding MAX_SCHEMA_DEPTH should produce problem."""

    monkeypatch.chdir(tmp_path)

    # Create a schema that exceeds MAX_SCHEMA_DEPTH (100 levels)
    # We'll create a path with MAX_SCHEMA_DEPTH + 1 levels
    schema = {}
    current = schema
    for i in range(MAX_SCHEMA_DEPTH + 1):
        current[f"Level{i}"] = {}
        current = current[f"Level{i}"]

    # Add a leaf at the deepest level
    current["Value"] = {"type": "str", "source": "value"}

    _write_schema(tmp_path, schema)

    compiled, problems = compile_schema_internal()

    assert isinstance(compiled, _CompiledSchema)
    assert compiled.is_empty
    assert any(
        "exceeds maximum allowed depth" in p.message
        and str(MAX_SCHEMA_DEPTH) in p.message
        for p in problems
    )


def test_schema_at_max_depth_compiles_correctly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Schema at exactly MAX_SCHEMA_DEPTH should compile correctly."""

    monkeypatch.chdir(tmp_path)

    # Create a schema at exactly MAX_SCHEMA_DEPTH levels
    schema = {}
    current = schema
    for i in range(MAX_SCHEMA_DEPTH):
        current[f"Level{i}"] = {}
        current = current[f"Level{i}"]

    # Add a leaf at the deepest level
    current["Value"] = {"type": "str", "source": "value"}

    _write_schema(tmp_path, schema)

    compiled, problems = compile_schema_internal()

    assert isinstance(compiled, _CompiledSchema)
    assert not compiled.is_empty
    assert len(compiled.leaves) == 1
    assert compiled.leaves[0].source == "value"
    assert problems == []


def test_get_schema_path_cached_file_deleted_re_searches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_get_schema_path should re-search if cached file is deleted."""

    monkeypatch.chdir(tmp_path)

    # Create schema file
    _write_schema(
        tmp_path,
        {"ServicePayload": {"RequestID": {"type": "str", "source": "request_id"}}},
    )

    # First call - should find and cache the file
    path1 = get_schema_path()
    assert path1.exists()

    # Delete the file
    path1.unlink()
    assert not path1.exists()

    # Second call - should re-search and return path in current directory
    path2 = get_schema_path()
    assert path2 == (tmp_path / _SCHEMA_FILE_NAME).resolve()
    assert not path2.exists()


def test_get_schema_path_cwd_change_invalidates_cache_when_file_not_found(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_get_schema_path should invalidate cache when CWD changes and file not found."""

    # Create two directories
    dir1 = tmp_path / "dir1"
    dir2 = tmp_path / "dir2"
    dir1.mkdir()
    dir2.mkdir()

    # Start in dir1 (no schema file)
    monkeypatch.chdir(dir1)
    path1 = get_schema_path()
    assert path1 == (dir1 / _SCHEMA_FILE_NAME).resolve()
    assert not path1.exists()

    # Change to dir2 (still no schema file, but different path expected)
    monkeypatch.chdir(dir2)
    path2 = get_schema_path()
    assert path2 == (dir2 / _SCHEMA_FILE_NAME).resolve()
    assert path2 != path1


def test_get_schema_path_cwd_change_preserves_cache_when_file_found(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_get_schema_path should preserve cache when CWD changes but file was found."""

    # Create schema file in root
    _write_schema(
        tmp_path,
        {"ServicePayload": {"RequestID": {"type": "str", "source": "request_id"}}},
    )

    # Create subdirectory
    sub_dir = tmp_path / "subdir"
    sub_dir.mkdir()

    # Start in subdirectory - should find file in parent
    monkeypatch.chdir(sub_dir)
    path1 = get_schema_path()
    assert path1.exists()
    assert path1 == (tmp_path / _SCHEMA_FILE_NAME).resolve()

    # Change to another subdirectory
    sub_dir2 = tmp_path / "subdir2"
    sub_dir2.mkdir()
    monkeypatch.chdir(sub_dir2)

    # Should still return cached path (CWD-independent)
    path2 = get_schema_path()
    assert path2 == path1
    assert path2.exists()


def test_check_cached_found_file_path_returns_path_when_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_check_cached_found_file_path should return path when file exists."""

    monkeypatch.chdir(tmp_path)

    # Create schema file
    schema_file = tmp_path / _SCHEMA_FILE_NAME
    _write_schema(
        tmp_path,
        {"ServicePayload": {"RequestID": {"type": "str", "source": "request_id"}}},
    )

    # Cache the path
    with schema_loader._path_cache_lock:
        schema_loader._resolved_schema_path = schema_file.resolve()
        schema_loader._cached_cwd = None

        # Should return cached path
        result = check_cached_found_file_path()
        assert result == schema_file.resolve()
        assert result.exists()


def test_check_cached_found_file_path_returns_none_when_file_deleted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_check_cached_found_file_path should return None when file is deleted."""

    monkeypatch.chdir(tmp_path)

    # Create and cache schema file
    schema_file = tmp_path / _SCHEMA_FILE_NAME
    _write_schema(
        tmp_path,
        {"ServicePayload": {"RequestID": {"type": "str", "source": "request_id"}}},
    )

    with schema_loader._path_cache_lock:
        schema_loader._resolved_schema_path = schema_file.resolve()
        schema_loader._cached_cwd = None

        # Delete the file
        schema_file.unlink()

        # Should return None and invalidate cache
        result = check_cached_found_file_path()
        assert result is None
        assert schema_loader._resolved_schema_path is None


def test_check_cached_found_file_path_returns_none_when_no_cache() -> None:
    """_check_cached_found_file_path should return None when no cache exists."""

    with schema_loader._path_cache_lock:
        schema_loader._resolved_schema_path = None

        result = check_cached_found_file_path()
        assert result is None


def test_check_cached_missing_file_path_returns_path_when_cwd_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_check_cached_missing_file_path should return path when CWD unchanged."""

    monkeypatch.chdir(tmp_path)

    expected_path = (tmp_path / _SCHEMA_FILE_NAME).resolve()

    with schema_loader._path_cache_lock:
        schema_loader._resolved_schema_path = expected_path
        schema_loader._cached_cwd = tmp_path.resolve()

        result = check_cached_missing_file_path()
        assert result == expected_path


def test_check_cached_missing_file_path_returns_none_when_cwd_changed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_check_cached_missing_file_path should return None when CWD changed."""

    dir1 = tmp_path / "dir1"
    dir2 = tmp_path / "dir2"
    dir1.mkdir()
    dir2.mkdir()

    monkeypatch.chdir(dir1)

    with schema_loader._path_cache_lock:
        schema_loader._resolved_schema_path = (dir1 / _SCHEMA_FILE_NAME).resolve()
        schema_loader._cached_cwd = dir1.resolve()

        # Change CWD
        monkeypatch.chdir(dir2)

        # Should return None and invalidate cache
        result = check_cached_missing_file_path()
        assert result is None
        assert schema_loader._resolved_schema_path is None
        assert schema_loader._cached_cwd is None


def test_check_cached_missing_file_path_returns_none_when_no_cache() -> None:
    """_check_cached_missing_file_path should return None when no cache exists."""

    with schema_loader._path_cache_lock:
        schema_loader._resolved_schema_path = None
        schema_loader._cached_cwd = None

        result = check_cached_missing_file_path()
        assert result is None


def test_cache_and_return_found_path_caches_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_cache_and_return_found_path should cache and return found path."""

    monkeypatch.chdir(tmp_path)

    schema_file = tmp_path / _SCHEMA_FILE_NAME
    _write_schema(
        tmp_path,
        {"ServicePayload": {"RequestID": {"type": "str", "source": "request_id"}}},
    )

    with schema_loader._path_cache_lock:
        result = cache_and_return_found_path(schema_file.resolve())

        assert result == schema_file.resolve()
        assert schema_loader._resolved_schema_path == schema_file.resolve()
        assert schema_loader._cached_cwd is None


def test_cache_and_return_missing_path_caches_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_cache_and_return_missing_path should cache and return missing path."""

    monkeypatch.chdir(tmp_path)

    expected_path = (tmp_path / _SCHEMA_FILE_NAME).resolve()

    with schema_loader._path_cache_lock:
        result = cache_and_return_missing_path()

        assert result == expected_path
        assert schema_loader._resolved_schema_path == expected_path
        assert schema_loader._cached_cwd == tmp_path.resolve()


def test_get_current_working_directory_returns_resolved_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_get_current_working_directory should return resolved absolute path to CWD."""
    monkeypatch.chdir(tmp_path)

    result = get_current_working_directory()

    assert isinstance(result, Path)
    assert result.is_absolute()
    assert result == tmp_path.resolve()


def test_get_current_working_directory_changes_with_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_get_current_working_directory should return different paths for different CWDs."""  # noqa: E501
    dir1 = tmp_path / "dir1"
    dir2 = tmp_path / "dir2"
    dir1.mkdir()
    dir2.mkdir()

    monkeypatch.chdir(dir1)
    path1 = get_current_working_directory()

    monkeypatch.chdir(dir2)
    path2 = get_current_working_directory()

    assert path1 != path2
    assert path1 == dir1.resolve()
    assert path2 == dir2.resolve()


def test_create_empty_compiled_schema_with_problems() -> None:
    """_create_empty_compiled_schema_with_problems creates empty schema with problems."""  # noqa: E501
    problems = [
        _SchemaProblem("Problem 1"),
        _SchemaProblem("Problem 2"),
    ]

    compiled, result_problems = create_empty_schema(problems)

    assert isinstance(compiled, _CompiledSchema)
    assert compiled.is_empty
    assert compiled.leaves == []
    assert result_problems == problems
    assert len(result_problems) == 2


def test_create_empty_compiled_schema_with_empty_problems() -> None:
    """_create_empty_compiled_schema_with_problems works with empty problems list."""  # noqa: E501
    problems: list[_SchemaProblem] = []

    compiled, result_problems = create_empty_schema(problems)

    assert isinstance(compiled, _CompiledSchema)
    assert compiled.is_empty
    assert result_problems == []


def test_load_raw_schema_loads_valid_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_load_raw_schema should load and parse valid JSON schema."""
    monkeypatch.chdir(tmp_path)
    schema_data = {
        "ServicePayload": {
            "RequestID": {"type": "str", "source": "request_id"},
        },
    }
    _write_schema(tmp_path, schema_data)

    schema_path = get_schema_path()
    data, returned_schema_path = load_raw_schema(schema_path)

    assert isinstance(data, dict)
    assert data == schema_data
    assert returned_schema_path == (tmp_path / _SCHEMA_FILE_NAME).resolve()
    assert returned_schema_path.exists()


def test_load_raw_schema_raises_file_not_found_when_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_load_raw_schema should raise FileNotFoundError when schema file is missing."""
    monkeypatch.chdir(tmp_path)

    schema_path = get_schema_path()
    with pytest.raises(FileNotFoundError) as exc_info:
        load_raw_schema(schema_path)

    assert "Schema file not found" in str(exc_info.value)
    assert _SCHEMA_FILE_NAME in str(exc_info.value)


def test_load_raw_schema_raises_value_error_for_invalid_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_load_raw_schema should raise ValueError for invalid JSON."""
    monkeypatch.chdir(tmp_path)
    schema_file = tmp_path / _SCHEMA_FILE_NAME
    schema_file.write_text("{ invalid json }", encoding="utf-8")

    schema_path = get_schema_path()
    with pytest.raises(ValueError) as exc_info:
        load_raw_schema(schema_path)

    assert "Failed to parse JSON schema" in str(exc_info.value)


def test_load_raw_schema_raises_value_error_for_non_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_load_raw_schema should raise ValueError when top-level is not an object."""
    monkeypatch.chdir(tmp_path)
    schema_file = tmp_path / _SCHEMA_FILE_NAME
    # Write a JSON array instead of an object
    schema_file.write_text('["not", "an", "object"]', encoding="utf-8")

    schema_path = get_schema_path()
    with pytest.raises(ValueError) as exc_info:
        load_raw_schema(schema_path)

    assert "Top-level schema must be a JSON object" in str(exc_info.value)


def test_compile_schema_tree_compiles_simple_tree() -> None:
    """_compile_schema_tree should compile a simple schema tree into leaves."""
    problems: list[_SchemaProblem] = []
    node = {
        "ServicePayload": {
            "RequestID": {"type": "str", "source": "request_id"},
            "UserID": {"type": "int", "source": "user_id"},
        },
    }

    leaves = list(compile_schema_tree(node, (), problems))

    assert len(leaves) == 2
    assert all(isinstance(leaf, _SchemaLeaf) for leaf in leaves)
    sources = {leaf.source for leaf in leaves}
    assert sources == {"request_id", "user_id"}
    assert problems == []


def test_compile_schema_tree_handles_nested_structure() -> None:
    """_compile_schema_tree should handle deeply nested structures."""
    problems: list[_SchemaProblem] = []
    node = {
        "Level1": {
            "Level2": {
                "Level3": {
                    "Value": {"type": "str", "source": "value"},
                },
            },
        },
    }

    leaves = list(compile_schema_tree(node, (), problems))

    assert len(leaves) == 1
    assert leaves[0].path == ("Level1", "Level2", "Level3", "Value")
    assert leaves[0].source == "value"
    assert problems == []


def test_compile_schema_tree_reports_invalid_nodes() -> None:
    """_compile_schema_tree should report problems for invalid nodes."""
    problems: list[_SchemaProblem] = []
    node = {
        "Valid": {
            "Leaf": {"type": "str", "source": "valid"},
        },
        "Invalid": "not-an-object",
    }

    leaves = list(compile_schema_tree(node, (), problems))

    assert len(leaves) == 1
    assert leaves[0].source == "valid"
    assert len(problems) == 1
    assert "expected object" in problems[0].message.lower()


def test_compile_schema_tree_respects_max_depth() -> None:
    """_compile_schema_tree should stop processing when max depth is exceeded."""
    problems: list[_SchemaProblem] = []
    # Create a path that exceeds MAX_SCHEMA_DEPTH
    node = {}
    current = node
    for i in range(MAX_SCHEMA_DEPTH + 1):
        current[f"Level{i}"] = {}
        current = current[f"Level{i}"]

    # Add a leaf at the deepest level
    current["Value"] = {"type": "str", "source": "value"}

    leaves = list(compile_schema_tree(node, (), problems))

    # Should not process the leaf beyond max depth
    assert len(leaves) == 0
    assert any("exceeds maximum allowed depth" in p.message for p in problems)


def test__get_builtin_logrecord_attributes_returns_set() -> None:
    """_get_builtin_logrecord_attributes should return a set of attribute names."""
    attributes = _get_builtin_logrecord_attributes()

    assert isinstance(attributes, set)
    assert len(attributes) > 0
    assert all(isinstance(attr, str) for attr in attributes)


def test__get_builtin_logrecord_attributes_includes_common_fields() -> None:
    """_get_builtin_logrecord_attributes should include common LogRecord fields."""
    attributes = _get_builtin_logrecord_attributes()

    # These are standard LogRecord attributes
    assert "name" in attributes
    assert "levelno" in attributes
    assert "pathname" in attributes
    assert "lineno" in attributes
    assert "msg" in attributes


def test__get_builtin_logrecord_attributes_excludes_private_attributes() -> None:
    """_get_builtin_logrecord_attributes should not include private attributes."""
    attributes = _get_builtin_logrecord_attributes()

    # Should not include private attributes (starting with _)
    private_attrs = {attr for attr in attributes if attr.startswith("_")}
    assert not private_attrs


def test__get_builtin_logrecord_attributes_excludes_methods() -> None:
    """_get_builtin_logrecord_attributes should not include callable methods."""
    attributes = _get_builtin_logrecord_attributes()

    # Should not include methods (callable attributes)
    import logging

    record = logging.LogRecord(
        name="",
        level=0,
        pathname="",
        lineno=0,
        msg="",
        args=(),
        exc_info=None,
    )

    # Check that no callable attributes are in the set
    for attr in attributes:
        value = getattr(record, attr, None)
        assert not callable(value), f"Attribute {attr} should not be callable"


def test__get_builtin_logrecord_attributes_is_cached() -> None:
    """_get_builtin_logrecord_attributes is cached (same result on multiple calls)."""  # noqa: E501
    attrs1 = _get_builtin_logrecord_attributes()
    attrs2 = _get_builtin_logrecord_attributes()

    # Should return the same set (cached)
    assert attrs1 is attrs2


def test_check_root_conflicts_reports_conflicts() -> None:
    """_check_root_conflicts should report conflicts with reserved logging fields."""
    problems: list[_SchemaProblem] = []
    schema_dict = {
        "name": {
            "Value": {"type": "str", "source": "value"},
        },
        "levelno": {
            "Value": {"type": "int", "source": "value2"},
        },
    }

    check_root_conflicts(schema_dict, problems)

    assert len(problems) == 2
    assert all("conflicts with reserved logging fields" in p.message for p in problems)


def test_check_root_conflicts_no_conflicts() -> None:
    """_check_root_conflicts should not report problems when no conflicts exist."""
    problems: list[_SchemaProblem] = []
    schema_dict = {
        "ServicePayload": {
            "RequestID": {"type": "str", "source": "request_id"},
        },
        "UserPayload": {
            "UserID": {"type": "int", "source": "user_id"},
        },
    }

    check_root_conflicts(schema_dict, problems)

    assert problems == []


def test_check_root_conflicts_empty_schema() -> None:
    """_check_root_conflicts should handle empty schema."""
    problems: list[_SchemaProblem] = []
    schema_dict: dict[str, Any] = {}

    check_root_conflicts(schema_dict, problems)

    assert problems == []


def test_is_leaf_node_with_type() -> None:
    """_is_leaf_node should return True for node with type field."""
    value_dict = {"type": "str", "source": "request_id"}
    assert is_leaf_node(value_dict) is True


def test_is_leaf_node_with_source() -> None:
    """_is_leaf_node should return True for node with source field."""
    value_dict = {"source": "request_id"}
    assert is_leaf_node(value_dict) is True


def test_is_leaf_node_with_both_fields() -> None:
    """_is_leaf_node should return True for node with both type and source."""
    value_dict = {"type": "int", "source": "user_id"}
    assert is_leaf_node(value_dict) is True


def test_is_leaf_node_without_fields() -> None:
    """_is_leaf_node should return False for inner node without type or source."""
    value_dict = {"nested": {}}
    assert is_leaf_node(value_dict) is False


def test_is_leaf_node_with_empty_dict() -> None:
    """_is_leaf_node should return False for empty dictionary."""
    value_dict: dict[str, Any] = {}
    assert is_leaf_node(value_dict) is False


def test_is_leaf_node_with_type_none() -> None:
    """_is_leaf_node should return True when type is None but source is present."""
    value_dict = {"type": None, "source": "request_id"}
    # Note: get() returns None, so "type" is None, but "source" is not None
    # So this should still return True because source is present
    assert is_leaf_node(value_dict) is True


def test_is_leaf_node_with_source_none() -> None:
    """_is_leaf_node should return True when source is None but type is present."""
    value_dict = {"type": "str", "source": None}
    # Note: get() returns None, so "source" is None, but "type" is not None
    # So this should still return True because type is present
    assert is_leaf_node(value_dict) is True


def test_is_leaf_node_with_both_none() -> None:
    """_is_leaf_node should return False when both type and source are None."""
    value_dict = {"type": None, "source": None}
    assert is_leaf_node(value_dict) is False
