"""Direct tests for schema_applier module functionality.

These tests cover the apply_schema_internal function and strip_empty
functionality directly, without going through SchemaLogger.
"""

from __future__ import annotations

import json

from logging_objects_with_schema.errors import _DataProblem
from logging_objects_with_schema.schema_applier import (
    _apply_schema_internal as apply_schema_internal,
)
from logging_objects_with_schema.schema_applier import (
    _create_validation_error_json as create_validation_error_json,
)
from logging_objects_with_schema.schema_applier import (
    _set_nested_value as set_nested_value,
)
from logging_objects_with_schema.schema_applier import _strip_empty as strip_empty
from logging_objects_with_schema.schema_applier import (
    _validate_and_apply_leaf as validate_and_apply_leaf,
)
from logging_objects_with_schema.schema_applier import (
    _validate_list_value as validate_list_value,
)
from logging_objects_with_schema.schema_loader import _CompiledSchema, _SchemaLeaf


def test_strip_empty_removes_empty_dicts() -> None:
    """strip_empty should remove empty dictionaries."""
    input_data = {
        "a": 1,
        "b": {},
        "c": {"d": {}, "e": 2},
    }
    result = strip_empty(input_data)
    assert result == {"a": 1, "c": {"e": 2}}


def test_strip_empty_removes_none_values() -> None:
    """strip_empty should remove None values."""
    input_data = {
        "a": 1,
        "b": None,
        "c": {"d": None, "e": 2},
    }
    result = strip_empty(input_data)
    assert result == {"a": 1, "c": {"e": 2}}


def test_strip_empty_handles_nested_empty_dicts() -> None:
    """strip_empty should handle deeply nested empty dictionaries."""
    input_data = {
        "a": {
            "b": {
                "c": {},
            },
            "d": 1,
        },
    }
    result = strip_empty(input_data)
    assert result == {"a": {"d": 1}}


def test_strip_empty_preserves_non_dict_values() -> None:
    """strip_empty should preserve non-dict values including empty lists."""
    input_data = {
        "a": [],
        "b": [1, 2, 3],
        "c": "string",
        "d": 42,
    }
    result = strip_empty(input_data)
    assert result == input_data


def test_apply_schema_empty_schema_returns_empty() -> None:
    """apply_schema_internal with empty schema should return empty dict and problems."""
    import json

    schema = _CompiledSchema(leaves=[])
    extra = {"field1": "value1", "field2": 42}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {}
    # All fields are considered redundant even when schema has no leaves.
    problem_fields = []
    for p in problems:
        error_obj = json.loads(p.message)
        problem_fields.append(error_obj["field"])
    assert "'field1'" in problem_fields
    assert "'field2'" in problem_fields


def test_apply_schema_nested_structure() -> None:
    """apply_schema_internal should build nested structures correctly."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "RequestID"),
                source="request_id",
                expected_type=str,
            ),
            _SchemaLeaf(
                path=("ServicePayload", "Metrics", "CPU"),
                source="cpu_usage",
                expected_type=float,
            ),
            _SchemaLeaf(
                path=("ServicePayload", "Metrics", "Memory"),
                source="memory_usage",
                expected_type=float,
            ),
        ],
    )
    extra = {
        "request_id": "abc-123",
        "cpu_usage": 75.5,
        "memory_usage": 60.2,
    }
    result, problems = apply_schema_internal(schema, extra)
    assert result == {
        "ServicePayload": {
            "RequestID": "abc-123",
            "Metrics": {
                "CPU": 75.5,
                "Memory": 60.2,
            },
        },
    }
    assert problems == []


def test_apply_schema_multiple_leaves_same_source_same_type() -> None:
    """Multiple leaves with same source and type should write to all locations."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "RequestID"),
                source="request_id",
                expected_type=str,
            ),
            _SchemaLeaf(
                path=("ServicePayload", "Metadata", "ID"),
                source="request_id",
                expected_type=str,
            ),
        ],
    )
    extra = {"request_id": "abc-123"}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {
        "ServicePayload": {
            "RequestID": "abc-123",
            "Metadata": {
                "ID": "abc-123",
            },
        },
    }
    assert problems == []


def test_apply_schema_multiple_leaves_same_source_different_types() -> None:
    """Multiple leaves with same source but different types validate independently."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "RequestID"), source="id", expected_type=str
            ),
            _SchemaLeaf(
                path=("ServicePayload", "IDNumber"), source="id", expected_type=int
            ),
        ],
    )
    extra = {"id": "abc-123"}
    result, problems = apply_schema_internal(schema, extra)
    # Should only write to str location
    assert result == {
        "ServicePayload": {
            "RequestID": "abc-123",
        },
    }
    assert len(problems) == 1
    assert "expected int" in problems[0].message


def test_apply_schema_empty_list_valid() -> None:
    """Empty lists should be considered valid."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "Tags"),
                source="tags",
                expected_type=list,
                item_expected_type=str,
            ),
        ],
    )
    extra = {"tags": []}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {
        "ServicePayload": {
            "Tags": [],
        },
    }
    assert problems == []


def test_apply_schema_list_with_primitives() -> None:
    """Lists with primitive values should be valid."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "Tags"),
                source="tags",
                expected_type=list,
                item_expected_type=str,
            ),
        ],
    )
    extra = {"tags": ["tag1", "tag2", "tag3"]}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {
        "ServicePayload": {
            "Tags": ["tag1", "tag2", "tag3"],
        },
    }
    assert problems == []


def test_apply_schema_list_with_mixed_primitives() -> None:
    """Lists with mixed primitive types should be invalid."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "Values"),
                source="values",
                expected_type=list,
                item_expected_type=int,
            ),
        ],
    )
    extra = {"values": [1, "two", 3.0, True]}
    result, problems = apply_schema_internal(schema, extra)
    # Whole list should be rejected because not all elements are of type int.
    assert result == {}
    assert len(problems) == 1
    assert "expected all elements to be of type int" in problems[0].message


def test_apply_schema_list_with_non_primitives_invalid() -> None:
    """Lists with non-primitive elements should produce problems."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "Items"),
                source="items",
                expected_type=list,
                item_expected_type=int,
            ),
        ],
    )
    extra = {"items": [1, {"nested": "dict"}, 3]}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {}
    assert len(problems) == 1
    assert "is a list but contains elements" in problems[0].message


def test_apply_schema_list_with_nested_list_invalid() -> None:
    """Nested lists should produce problems."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "Items"),
                source="items",
                expected_type=list,
                item_expected_type=int,
            ),
        ],
    )
    extra = {"items": [1, [2, 3], 4]}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {}
    assert len(problems) == 1
    assert "is a list but contains elements" in problems[0].message


def test_apply_schema_type_mismatch_produces_problem() -> None:
    """Type mismatches should produce problems."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "UserID"), source="user_id", expected_type=int
            ),
        ],
    )
    extra = {"user_id": "not-an-int"}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {}
    assert len(problems) == 1
    assert "expected int" in problems[0].message


def test_apply_schema_none_value_produces_problem() -> None:
    """None values should produce problems."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "UserID"), source="user_id", expected_type=int
            ),
        ],
    )
    extra = {"user_id": None}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {}
    assert len(problems) == 1
    assert "None" in problems[0].message


def test_apply_schema_none_value_with_multiple_leaves_produces_single_problem() -> None:
    """None values with multiple leaves referencing same source produce one problem."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "RequestID"),
                source="request_id",
                expected_type=str,
            ),
            _SchemaLeaf(
                path=("ServicePayload", "Metadata", "ID"),
                source="request_id",
                expected_type=str,
            ),
        ],
    )
    extra = {"request_id": None}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {}
    assert len(problems) == 1  # Should be 1, not 2
    assert "None" in problems[0].message
    assert "request_id" in problems[0].message


def test_apply_schema_partial_validation() -> None:
    """Some fields valid, others invalid should log valid ones and report problems."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "RequestID"),
                source="request_id",
                expected_type=str,
            ),
            _SchemaLeaf(
                path=("ServicePayload", "UserID"), source="user_id", expected_type=int
            ),
        ],
    )
    extra = {
        "request_id": "abc-123",  # valid
        "user_id": "not-an-int",  # invalid
    }
    result, problems = apply_schema_internal(schema, extra)
    # Valid field should be in result
    assert result == {
        "ServicePayload": {
            "RequestID": "abc-123",
        },
    }
    # Invalid field should produce problem
    assert len(problems) == 1
    assert "user_id" in problems[0].message


def test_apply_schema_redundant_fields_with_non_empty_schema() -> None:
    """Redundant fields should produce problems when schema is not empty."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "RequestID"),
                source="request_id",
                expected_type=str,
            ),
        ],
    )
    extra = {
        "request_id": "abc-123",
        "unknown_field": "value",
        "another_unknown": 42,
    }
    result, problems = apply_schema_internal(schema, extra)
    assert result == {
        "ServicePayload": {
            "RequestID": "abc-123",
        },
    }
    assert len(problems) == 2
    problem_messages = [p.message for p in problems]
    assert any("unknown_field" in msg for msg in problem_messages)
    assert any("another_unknown" in msg for msg in problem_messages)


def test_apply_schema_redundant_fields_with_empty_schema() -> None:
    """Redundant fields should produce problems when schema is empty."""
    import json

    schema = _CompiledSchema(leaves=[])
    extra = {
        "unknown_field": "value",
        "another_unknown": 42,
    }
    result, problems = apply_schema_internal(schema, extra)
    assert result == {}
    # Both fields should be reported as redundant.
    problem_fields = []
    for p in problems:
        error_obj = json.loads(p.message)
        problem_fields.append(error_obj["field"])
    assert "'unknown_field'" in problem_fields
    assert "'another_unknown'" in problem_fields


def test_apply_schema_strips_empty_dicts() -> None:
    """apply_schema_internal should strip empty dictionaries from result."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "RequestID"),
                source="request_id",
                expected_type=str,
            ),
            _SchemaLeaf(
                path=("ServicePayload", "Metadata", "ID"),
                source="request_id",
                expected_type=str,
            ),
        ],
    )
    # Only provide one field, which will create nested structure
    extra = {"request_id": "abc-123"}
    result, problems = apply_schema_internal(schema, extra)
    # Should not have empty dicts
    assert "ServicePayload" in result
    assert "Metadata" in result["ServicePayload"]
    # Verify structure is correct
    assert result["ServicePayload"]["RequestID"] == "abc-123"
    assert result["ServicePayload"]["Metadata"]["ID"] == "abc-123"


def test_apply_schema_deeply_nested_structure() -> None:
    """apply_schema_internal should handle deeply nested structures."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("Level1", "Level2", "Level3", "Level4", "Value"),
                source="value",
                expected_type=str,
            ),
        ],
    )
    extra = {"value": "deep-value"}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {
        "Level1": {
            "Level2": {
                "Level3": {
                    "Level4": {
                        "Value": "deep-value",
                    },
                },
            },
        },
    }
    assert problems == []


def test_apply_schema_missing_fields_no_problems() -> None:
    """Missing fields in extra should not produce problems, just be omitted."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "RequestID"),
                source="request_id",
                expected_type=str,
            ),
            _SchemaLeaf(
                path=("ServicePayload", "UserID"), source="user_id", expected_type=int
            ),
        ],
    )
    extra = {}  # No fields provided
    result, problems = apply_schema_internal(schema, extra)
    assert result == {}
    assert problems == []


def test_apply_schema_multiple_sources_different_branches() -> None:
    """Multiple sources in different branches should work independently."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(path=("Branch1", "Value"), source="value1", expected_type=str),
            _SchemaLeaf(path=("Branch2", "Value"), source="value2", expected_type=int),
        ],
    )
    extra = {
        "value1": "string-value",
        "value2": 42,
    }
    result, problems = apply_schema_internal(schema, extra)
    assert result == {
        "Branch1": {"Value": "string-value"},
        "Branch2": {"Value": 42},
    }
    assert problems == []


def test_apply_schema_bool_not_accepted_for_int() -> None:
    """Bool values should not pass validation for int types."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "UserID"), source="user_id", expected_type=int
            ),
        ],
    )
    # True should not pass for int
    extra = {"user_id": True}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {}
    assert len(problems) == 1
    assert "expected int" in problems[0].message
    assert "bool" in problems[0].message.lower()

    # False should not pass for int
    extra = {"user_id": False}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {}
    assert len(problems) == 1
    assert "expected int" in problems[0].message
    assert "bool" in problems[0].message.lower()


def test_apply_schema_int_not_accepted_for_bool() -> None:
    """Int values should not pass validation for bool types."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "IsActive"),
                source="is_active",
                expected_type=bool,
            ),
        ],
    )
    # 1 should not pass for bool
    extra = {"is_active": 1}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {}
    assert len(problems) == 1
    assert "expected bool" in problems[0].message
    assert "int" in problems[0].message.lower()

    # 0 should not pass for bool
    extra = {"is_active": 0}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {}
    assert len(problems) == 1
    assert "expected bool" in problems[0].message
    assert "int" in problems[0].message.lower()


def test_apply_schema_strict_type_checking_for_all_primitives() -> None:
    """Strict type checking should work for all primitive types."""
    schema = _CompiledSchema(
        leaves=[
            _SchemaLeaf(
                path=("ServicePayload", "StringField"),
                source="string_field",
                expected_type=str,
            ),
            _SchemaLeaf(
                path=("ServicePayload", "IntField"),
                source="int_field",
                expected_type=int,
            ),
            _SchemaLeaf(
                path=("ServicePayload", "FloatField"),
                source="float_field",
                expected_type=float,
            ),
            _SchemaLeaf(
                path=("ServicePayload", "BoolField"),
                source="bool_field",
                expected_type=bool,
            ),
        ],
    )

    # Valid values should pass
    extra = {
        "string_field": "text",
        "int_field": 42,
        "float_field": 3.14,
        "bool_field": True,
    }
    result, problems = apply_schema_internal(schema, extra)
    assert result == {
        "ServicePayload": {
            "StringField": "text",
            "IntField": 42,
            "FloatField": 3.14,
            "BoolField": True,
        },
    }
    assert problems == []

    # String should not pass for int
    extra = {"int_field": "42"}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {}
    assert len(problems) == 1
    assert "expected int" in problems[0].message

    # Int should not pass for float
    extra = {"float_field": 42}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {}
    assert len(problems) == 1
    assert "expected float" in problems[0].message

    # Float should not pass for int
    extra = {"int_field": 3.14}
    result, problems = apply_schema_internal(schema, extra)
    assert result == {}
    assert len(problems) == 1
    assert "expected int" in problems[0].message


# Tests for helper functions


def test_validate_list_value_empty_list_returns_none() -> None:
    """validate_list_value should return None for empty lists."""
    result = validate_list_value([], "test_field", str)
    assert result is None


def test_validate_list_value_valid_items_returns_none() -> None:
    """validate_list_value should return None for lists with valid items."""
    result = validate_list_value(["a", "b", "c"], "test_field", str)
    assert result is None

    result = validate_list_value([1, 2, 3], "test_field", int)
    assert result is None

    result = validate_list_value([1.0, 2.5, 3.14], "test_field", float)
    assert result is None

    result = validate_list_value([True, False], "test_field", bool)
    assert result is None


def test_validate_list_value_mixed_types_returns_problem() -> None:
    """validate_list_value should return _DataProblem for mixed types."""
    result = validate_list_value([1, "two", 3], "test_field", int)
    assert isinstance(result, _DataProblem)
    assert "test_field" in result.message
    assert "str" in result.message
    assert "expected all elements to be of type int" in result.message


def test_validate_list_value_none_item_type_returns_problem() -> None:
    """validate_list_value should return _DataProblem when item_expected_type is None."""  # noqa: E501
    result = validate_list_value([1, 2, 3], "test_field", None)
    assert isinstance(result, _DataProblem)
    assert "test_field" in result.message
    assert "no item type configured" in result.message


def test_validate_list_value_nested_list_returns_problem() -> None:
    """validate_list_value should return _DataProblem for nested lists."""
    result = validate_list_value([1, [2, 3], 4], "test_field", int)
    assert isinstance(result, _DataProblem)
    assert "list" in result.message.lower()


def test_validate_list_value_dict_in_list_returns_problem() -> None:
    """validate_list_value should return _DataProblem for dicts in list."""
    result = validate_list_value([1, {"key": "value"}, 3], "test_field", int)
    assert isinstance(result, _DataProblem)
    assert "dict" in result.message.lower()


def test_set_nested_value_single_level() -> None:
    """set_nested_value should set value at single level."""
    target = {}
    set_nested_value(target, ("key",), "value")
    assert target == {"key": "value"}


def test_set_nested_value_two_levels() -> None:
    """set_nested_value should create nested structure for two levels."""
    target = {}
    set_nested_value(target, ("level1", "level2"), "value")
    assert target == {"level1": {"level2": "value"}}


def test_set_nested_value_deeply_nested() -> None:
    """set_nested_value should create deeply nested structure."""
    target = {}
    set_nested_value(target, ("a", "b", "c", "d", "e"), "value")
    assert target == {"a": {"b": {"c": {"d": {"e": "value"}}}}}


def test_set_nested_value_preserves_existing_structure() -> None:
    """set_nested_value should preserve existing dictionary structure."""
    target = {"existing": {"key": "value"}}
    set_nested_value(target, ("existing", "new_key"), "new_value")
    assert target == {"existing": {"key": "value", "new_key": "new_value"}}


def test_set_nested_value_overwrites_existing_value() -> None:
    """set_nested_value should overwrite existing value at path."""
    target = {"level1": {"level2": "old_value"}}
    set_nested_value(target, ("level1", "level2"), "new_value")
    assert target == {"level1": {"level2": "new_value"}}


def test_validate_and_apply_leaf_valid_value() -> None:
    """validate_and_apply_leaf should apply valid value to target."""
    leaf = _SchemaLeaf(
        path=("ServicePayload", "RequestID"),
        source="request_id",
        expected_type=str,
    )
    extra = {}
    problems = []

    validate_and_apply_leaf(leaf, "abc-123", "request_id", extra, problems)

    assert problems == []
    assert extra == {"ServicePayload": {"RequestID": "abc-123"}}


def test_validate_and_apply_leaf_type_mismatch() -> None:
    """validate_and_apply_leaf should add problem for type mismatch."""
    leaf = _SchemaLeaf(
        path=("ServicePayload", "UserID"),
        source="user_id",
        expected_type=int,
    )
    extra = {}
    problems = []

    validate_and_apply_leaf(leaf, "not-an-int", "user_id", extra, problems)

    assert len(problems) == 1
    assert "expected int" in problems[0].message
    assert extra == {}


def test_validate_and_apply_leaf_valid_list() -> None:
    """validate_and_apply_leaf should apply valid list value."""
    leaf = _SchemaLeaf(
        path=("ServicePayload", "Tags"),
        source="tags",
        expected_type=list,
        item_expected_type=str,
    )
    extra = {}
    problems = []

    validate_and_apply_leaf(leaf, ["tag1", "tag2"], "tags", extra, problems)

    assert problems == []
    assert extra == {"ServicePayload": {"Tags": ["tag1", "tag2"]}}


def test_validate_and_apply_leaf_invalid_list() -> None:
    """validate_and_apply_leaf should add problem for invalid list."""
    leaf = _SchemaLeaf(
        path=("ServicePayload", "Values"),
        source="values",
        expected_type=list,
        item_expected_type=int,
    )
    extra = {}
    problems = []

    validate_and_apply_leaf(leaf, [1, "two", 3], "values", extra, problems)

    assert len(problems) == 1
    assert "is a list but contains elements" in problems[0].message
    assert extra == {}


def test_validate_and_apply_leaf_empty_list() -> None:
    """validate_and_apply_leaf should accept empty lists."""
    leaf = _SchemaLeaf(
        path=("ServicePayload", "Tags"),
        source="tags",
        expected_type=list,
        item_expected_type=str,
    )
    extra = {}
    problems = []

    validate_and_apply_leaf(leaf, [], "tags", extra, problems)

    assert problems == []
    assert extra == {"ServicePayload": {"Tags": []}}


def test_validate_and_apply_leaf_list_without_item_type() -> None:
    """validate_and_apply_leaf should add problem when item_expected_type is None."""
    leaf = _SchemaLeaf(
        path=("ServicePayload", "Items"),
        source="items",
        expected_type=list,
        item_expected_type=None,
    )
    extra = {}
    problems = []

    validate_and_apply_leaf(leaf, [1, 2, 3], "items", extra, problems)

    assert len(problems) == 1
    assert "no item type configured" in problems[0].message
    assert extra == {}


# Tests for _create_validation_error_json helper function


def test_create_validation_error_json_with_string() -> None:
    """_create_validation_error_json should create valid JSON with string value."""
    result = create_validation_error_json("user_id", "expected int", "abc-123")

    parsed = json.loads(result)
    assert parsed["field"] == "'user_id'"
    assert parsed["error"] == "'expected int'"
    assert parsed["value"] == "'abc-123'"


def test_create_validation_error_json_with_int() -> None:
    """_create_validation_error_json should use repr() for int values."""
    result = create_validation_error_json("count", "expected str", 42)

    parsed = json.loads(result)
    assert parsed["field"] == "'count'"
    assert parsed["error"] == "'expected str'"
    assert parsed["value"] == "42"


def test_create_validation_error_json_with_float() -> None:
    """_create_validation_error_json should use repr() for float values."""
    result = create_validation_error_json("price", "expected int", 3.14)

    parsed = json.loads(result)
    assert parsed["field"] == "'price'"
    assert parsed["error"] == "'expected int'"
    assert parsed["value"] == "3.14"


def test_create_validation_error_json_with_bool() -> None:
    """_create_validation_error_json should use repr() for bool values."""
    result = create_validation_error_json("is_active", "expected int", True)

    parsed = json.loads(result)
    assert parsed["field"] == "'is_active'"
    assert parsed["error"] == "'expected int'"
    assert parsed["value"] == "True"


def test_create_validation_error_json_with_none() -> None:
    """_create_validation_error_json should use repr() for None value."""
    result = create_validation_error_json("user_id", "is None", None)

    parsed = json.loads(result)
    assert parsed["field"] == "'user_id'"
    assert parsed["error"] == "'is None'"
    assert parsed["value"] == "None"


def test_create_validation_error_json_with_dict() -> None:
    """_create_validation_error_json should use repr() for dict values."""
    dict_value = {"key": "value", "nested": {"inner": 42}}
    result = create_validation_error_json("tags", "invalid type", dict_value)

    parsed = json.loads(result)
    assert parsed["field"] == "'tags'"
    assert parsed["error"] == "'invalid type'"
    # Value should be the repr() string representation
    assert isinstance(parsed["value"], str)
    assert "key" in parsed["value"]
    assert "value" in parsed["value"]


def test_create_validation_error_json_with_list() -> None:
    """_create_validation_error_json should use repr() for list values."""
    list_value = [1, 2, "three", {"key": "value"}]
    result = create_validation_error_json("items", "invalid type", list_value)

    parsed = json.loads(result)
    assert parsed["field"] == "'items'"
    assert parsed["error"] == "'invalid type'"
    # Value should be the repr() string representation
    assert isinstance(parsed["value"], str)
    assert "1" in parsed["value"]
    assert "2" in parsed["value"]


def test_create_validation_error_json_returns_valid_json() -> None:
    """_create_validation_error_json should return valid JSON string."""
    result = create_validation_error_json("field", "error", "value")

    # Should not raise exception
    parsed = json.loads(result)
    assert isinstance(parsed, dict)
    assert "field" in parsed
    assert "error" in parsed
    assert "value" in parsed


def test_create_validation_error_json_all_values_wrapped_in_repr() -> None:
    """_create_validation_error_json should wrap all values in repr()."""
    result = create_validation_error_json("test_field", "test error", "test value")

    parsed = json.loads(result)
    # All values should be strings (wrapped in repr())
    assert isinstance(parsed["field"], str)
    assert isinstance(parsed["error"], str)
    assert isinstance(parsed["value"], str)
    # Field and error should have quotes (repr() of strings)
    assert parsed["field"].startswith("'")
    assert parsed["field"].endswith("'")
    assert parsed["error"].startswith("'")
    assert parsed["error"].endswith("'")


def test_create_validation_error_json_with_special_characters() -> None:
    """_create_validation_error_json should handle special characters via repr()."""
    special_value = "value with\nnewline\tand\ttab"
    result = create_validation_error_json("field", "error", special_value)

    parsed = json.loads(result)
    # repr() should escape special characters
    assert "\\n" in parsed["value"] or "\n" in parsed["value"]
    assert "\\t" in parsed["value"] or "\t" in parsed["value"]


def test_create_validation_error_json_with_unicode() -> None:
    """_create_validation_error_json should handle unicode characters via repr()."""
    unicode_value = "тест 测试 🚀"
    result = create_validation_error_json("field", "error", unicode_value)

    parsed = json.loads(result)
    # Should be valid JSON with unicode preserved
    assert (
        "тест" in parsed["value"] or "\\u0442\\u0435\\u0441\\u0442" in parsed["value"]
    )


def test_create_validation_error_json_with_empty_string() -> None:
    """_create_validation_error_json should handle empty string value."""
    result = create_validation_error_json("field", "error", "")

    parsed = json.loads(result)
    assert parsed["field"] == "'field'"
    assert parsed["error"] == "'error'"
    assert parsed["value"] == "''"
