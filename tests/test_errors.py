"""Tests for errors module private classes."""

from __future__ import annotations

import json

from logging_objects_with_schema.errors import _DataProblem, _SchemaProblem


def test_schema_problem_creation() -> None:
    """_SchemaProblem should be created with message attribute."""
    problem = _SchemaProblem("Test message")
    assert problem.message == "Test message"


def test_schema_problem_with_empty_message() -> None:
    """_SchemaProblem should accept empty message string."""
    problem = _SchemaProblem("")
    assert problem.message == ""


def test_schema_problem_with_multiline_message() -> None:
    """_SchemaProblem should accept multiline message."""
    message = "Line 1\nLine 2\nLine 3"
    problem = _SchemaProblem(message)
    assert problem.message == message


def test_schema_problem_equality() -> None:
    """_SchemaProblem instances with same message should be equal."""
    problem1 = _SchemaProblem("Same message")
    problem2 = _SchemaProblem("Same message")
    assert problem1 == problem2


def test_schema_problem_inequality() -> None:
    """_SchemaProblem instances with different messages should not be equal."""
    problem1 = _SchemaProblem("Message 1")
    problem2 = _SchemaProblem("Message 2")
    assert problem1 != problem2


def test_data_problem_creation() -> None:
    """_DataProblem should be created with message attribute."""
    message = '{"field": "test", "error": "test error", "value": "test value"}'
    problem = _DataProblem(message)
    assert problem.message == message


def test_data_problem_message_is_valid_json() -> None:
    """_DataProblem.message should be a valid JSON string."""
    message = '{"field": "test_field", "error": "test error", "value": "test value"}'
    problem = _DataProblem(message)

    # Should not raise exception
    parsed = json.loads(problem.message)
    assert isinstance(parsed, dict)
    assert "field" in parsed
    assert "error" in parsed
    assert "value" in parsed


def test_data_problem_message_structure() -> None:
    """_DataProblem.message should have correct JSON structure."""
    message = '{"field": "user_id", "error": "expected int", "value": "abc"}'
    problem = _DataProblem(message)

    parsed = json.loads(problem.message)
    assert parsed["field"] == "user_id"
    assert parsed["error"] == "expected int"
    assert parsed["value"] == "abc"


def test_data_problem_equality() -> None:
    """_DataProblem instances with same message should be equal."""
    message = '{"field": "test", "error": "error", "value": "value"}'
    problem1 = _DataProblem(message)
    problem2 = _DataProblem(message)
    assert problem1 == problem2


def test_data_problem_inequality() -> None:
    """_DataProblem instances with different messages should not be equal."""
    message1 = '{"field": "field1", "error": "error1", "value": "value1"}'
    message2 = '{"field": "field2", "error": "error2", "value": "value2"}'
    problem1 = _DataProblem(message1)
    problem2 = _DataProblem(message2)
    assert problem1 != problem2


def test_data_problem_with_repr_values() -> None:
    """_DataProblem.message can contain repr() formatted values."""
    # This is how _create_validation_error_json creates messages
    message = json.dumps(
        {
            "field": repr("user_id"),
            "error": repr("expected int"),
            "value": repr("abc-123"),
        }
    )
    problem = _DataProblem(message)

    parsed = json.loads(problem.message)
    assert parsed["field"] == "'user_id'"
    assert parsed["error"] == "'expected int'"
    assert parsed["value"] == "'abc-123'"


def test_data_problem_with_none_value() -> None:
    """_DataProblem.message can contain None value."""
    message = json.dumps(
        {
            "field": repr("user_id"),
            "error": repr("is None"),
            "value": repr(None),
        }
    )
    problem = _DataProblem(message)

    parsed = json.loads(problem.message)
    assert parsed["value"] == "None"


def test_data_problem_with_complex_value() -> None:
    """_DataProblem.message can contain complex repr() formatted values."""
    complex_value = {"nested": {"key": "value"}}
    message = json.dumps(
        {
            "field": repr("tags"),
            "error": repr("invalid type"),
            "value": repr(complex_value),
        }
    )
    problem = _DataProblem(message)

    parsed = json.loads(problem.message)
    # Value should be the repr() string representation
    assert isinstance(parsed["value"], str)
    assert "nested" in parsed["value"]
