"""Internal schema application logic for logging_objects_with_schema.

This module provides the core function for applying a compiled schema
to user-provided extra fields, used by SchemaLogger.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping, MutableMapping
from typing import Any

from .errors import _DataProblem
from .schema_loader import _CompiledSchema, _SchemaLeaf


def _create_validation_error_json(field: str, error: str, value: Any) -> str:
    """Create JSON string for a single validation error.

    All values are wrapped in repr() before JSON serialization. This ensures:
    - Any value type can be safely serialized (even non-JSON-serializable types)
    - The error message always contains a valid Python representation of the value
    - Security: prevents issues with special characters or control sequences
    - Consistency: all error messages have the same format regardless of value type

    Args:
        field: Field name that caused the validation error.
        error: Error description.
        value: Invalid value that caused the error.

    Returns:
        JSON string with field, error, and value (all via repr() for safety).
    """
    return json.dumps(
        {
            "field": repr(field),
            "error": repr(error),
            "value": repr(value),
        }
    )


def _validate_list_value(
    value: list,
    source: str,
    item_expected_type: type | None,
) -> _DataProblem | None:
    """Validate that a list value matches the expected item type.

    Validates that all elements in the list have the exact type declared by
    ``item_expected_type``. Empty lists are always considered valid.

    Args:
        value: The list value to validate.
        source: The source field name (for error messages).
        item_expected_type: Expected type for list elements. Must not be None
            for list-typed leaves.

    Returns:
        _DataProblem if validation fails, None if validation succeeds.
    """
    if item_expected_type is None:
        error_msg = "is a list but has no item type configured"
        return _DataProblem(_create_validation_error_json(source, error_msg, value))

    if len(value) == 0:
        # Empty lists are always valid
        return None

    # Collect unique type names of items that don't match the expected type.
    # We use a set comprehension to get unique type names (not the types themselves)
    # for the error message. This gives a clear, readable error message showing
    # which types were found (e.g., "int, str") vs what was expected.
    invalid_item_types = {
        type(item).__name__ for item in value if type(item) is not item_expected_type
    }

    if invalid_item_types:
        error_msg = (
            f"is a list but contains elements "
            f"with types {sorted(invalid_item_types)}; "
            f"expected all elements to be of type "
            f"{item_expected_type.__name__}"
        )
        return _DataProblem(_create_validation_error_json(source, error_msg, value))

    return None


def _set_nested_value(
    target: MutableMapping[str, Any],
    path: tuple[str, ...],
    value: Any,
) -> None:
    """Set a value in a nested dictionary structure following the given path.

    Creates intermediate dictionaries as needed. The last element of the path
    is used as the final key for the value.

    Args:
        target: The root dictionary to modify.
        path: Tuple of keys representing the path to the target location.
        value: The value to set at the target location.
    """
    current = target
    # Navigate through intermediate dictionaries, creating them as needed.
    # We iterate through all keys except the last one (path[:-1]) to build
    # the nested structure.
    for key in path[:-1]:
        child = current.get(key)
        # If the key doesn't exist or exists but is not a dict, create a new dict.
        # This overwrites any non-dict value that might have been there (which
        # shouldn't happen in normal operation, but we handle it defensively).
        # We use isinstance() instead of checking for None because we need to
        # ensure the value is actually a dict, not just that the key exists.
        if not isinstance(child, dict):
            child = {}
            current[key] = child
        current = child

    # Set the final value at the last key in the path
    current[path[-1]] = value


def _validate_and_apply_leaf(
    leaf: _SchemaLeaf,
    value: Any,
    source: str,
    extra: MutableMapping[str, Any],
    problems: list[_DataProblem],
) -> None:
    """Validate a value against a schema leaf and apply it if valid.

    Performs strict type checking and list validation. If validation passes,
    the value is written to the target location in the extra dictionary.

    Args:
        leaf: The schema leaf to validate against.
        value: The value to validate and apply.
        source: The source field name (for error messages).
        extra: The target dictionary to write the value to if validation passes.
        problems: List to append validation problems to.
    """
    # Use strict type checking (type() is) instead of isinstance() to
    # prevent bool values from passing validation for int types (since
    # bool is a subclass of int). This ensures that the actual
    # runtime type matches the schema type exactly.
    if type(value) is not leaf.expected_type:
        error_msg = (
            f"has type {type(value).__name__}, "
            f"expected {leaf.expected_type.__name__}"
        )
        problems.append(
            _DataProblem(_create_validation_error_json(source, error_msg, value))
        )
        return

    # For lists, validate that all elements strictly match the declared
    # item_expected_type (homogeneous primitive list).
    # Note: isinstance() check is needed for type narrowing (mypy), even though
    # type(value) is list is already guaranteed by the check above.
    if leaf.expected_type is list and isinstance(value, list):
        list_problem = _validate_list_value(value, source, leaf.item_expected_type)
        if list_problem is not None:
            problems.append(list_problem)
            return

    _set_nested_value(extra, leaf.path, value)


def _strip_empty(node: Any) -> Any:
    """Remove empty dictionaries and None values from a nested structure.

    Recursively walks through a dictionary structure and removes:
    - Empty dictionaries ({})
    - None values

    This helper is used by ``_apply_schema_internal`` on the final payload
    to avoid leaving empty containers created during schema application.

    Note: Lists are not processed (they are returned as-is). This is intentional:
    - Lists in the schema are always homogeneous primitive types (validated earlier)
    - Empty lists are valid and should be preserved
    - We only need to clean up empty dicts that were created as intermediate
      containers during schema application but ended up empty

    Note:
        This function is part of the internal implementation details and is
        not considered a public API. Its signature and behaviour may change
        between releases without preserving backward compatibility.

    Args:
        node: The node to process (can be dict, list, or any other type).

    Returns:
        The cleaned structure with empty dicts and None values removed.
    """
    if isinstance(node, dict):
        cleaned = {k: _strip_empty(v) for k, v in node.items()}
        return {k: v for k, v in cleaned.items() if v != {} and v is not None}
    return node


def _apply_schema_internal(
    compiled: _CompiledSchema,
    extra_values: Mapping[str, Any],
) -> tuple[dict[str, Any], list[_DataProblem]]:
    """Internal function to build structured ``extra`` from compiled schema.

    The function applies a :class:`_CompiledSchema` to user-provided ``extra``
    values and returns a tuple ``(structured_extra, problems)`` where:

    - ``structured_extra`` is a nested dictionary that follows the schema
      structure and contains only fields that passed validation;
    - ``problems`` is a list of :class:`_DataProblem` describing all data
      issues observed during processing.

    Behaviour summary:

    - If the compiled schema is effectively empty (no valid leaves),
      all fields from ``extra_values`` are treated as redundant: the returned
      payload is empty, and a :class:`_DataProblem` is created for each field.
    - For each ``source`` mentioned in the schema when there are valid leaves:
      - if the source is missing from ``extra_values``, it is silently skipped;
      - if the corresponding value is ``None``, a ``_DataProblem`` is recorded
        and the value is not written to the payload.
    - Type checks are strict: the runtime type must exactly match the declared
      Python type (``type(value) is leaf.expected_type``). This prevents
      ``bool`` from being accepted where ``int`` is expected.
    - For list-typed leaves:
      - empty lists are accepted;
      - all elements must have the exact type declared by the leaf
        ``item_expected_type`` (for example, list[str], list[int]);
      - non-primitive elements and elements of a different primitive type are
        rejected with a ``_DataProblem`` and the list value is not written.
    - Redundant fields from ``extra_values`` (not referenced by any leaf
      ``source``) are always reported as problems: each such field generates
      a :class:`_DataProblem` indicating that it is not defined in the schema.
    - A single ``source`` may be used by multiple leaves. The value is
      validated independently for each leaf and written only to locations
      where the type matches; mismatched locations produce ``_DataProblem``
      entries, but do not affect successful locations.

    The function itself does not raise exceptions; it only accumulates
    :class:`_DataProblem` instances for the caller to handle.

    Performance considerations:
        Time complexity is O(n + m) where n is the number of leaves in the
        compiled schema and m is the number of fields in ``extra_values``.
        The function groups leaves by source field name to avoid redundant
        validation when a single source is used by multiple leaves. For typical
        schemas (< 100 leaves) and typical extra dictionaries (< 50 fields),
        the overhead is negligible (< 1ms). Memory complexity is O(n + m) for
        the output structures.

    Limitations:
        - Very large ``extra_values`` dictionaries (> 1000 fields) may cause
          noticeable overhead, but this is uncommon in practice
        - Deeply nested output structures (limited by schema depth) may increase
          memory usage, but the depth is already limited by MAX_SCHEMA_DEPTH
        - All validation errors are collected before returning; for schemas with
          many leaves and many validation failures, the problems list may grow
          large, but this is expected behavior for debugging purposes

    Note:
        This function is used internally by :class:`SchemaLogger` and is not
        considered part of the public API. Its signature and behaviour may
        change between releases without preserving backward compatibility.

    Returns:
        Tuple of (structured_extra, list[_DataProblem]).
    """
    extra: dict[str, Any] = {}
    problems: list[_DataProblem] = []

    # Group leaves by source field name. This is necessary because a single source
    # can be referenced by multiple leaves (allowing the same value to appear in
    # different locations in the output structure). Grouping allows us to process
    # all leaves for a given source together, which is more efficient and allows
    # us to validate the value once per source (e.g., checking for None) rather
    # than once per leaf.
    source_to_leaves: dict[str, list[_SchemaLeaf]] = defaultdict(list)
    for leaf in compiled.leaves:
        source_to_leaves[leaf.source].append(leaf)

    used_sources = set(source_to_leaves.keys())

    # Process each source that appears in the schema. If a source is missing from
    # extra_values, we silently skip it (this is normal - not all sources need to
    # be present in every log call). We only validate and apply sources that are
    # actually provided.
    for source, leaves in source_to_leaves.items():
        if source not in extra_values:
            # Source not provided - this is normal, not an error. Skip it.
            continue

        value = extra_values[source]

        # Check for None values explicitly. None is never allowed for any type,
        # so we check it once per source (not once per leaf) before attempting
        # type-specific validation. This avoids redundant checks when a source
        # is used by multiple leaves.
        if value is None:
            error_msg = "is None"
            problems.append(
                _DataProblem(_create_validation_error_json(source, error_msg, None))
            )
            continue

        # Validate the value against each leaf that references this source.
        # Each leaf validates independently, so a value might pass validation
        # for some leaves (where type matches) but fail for others (where type
        # doesn't match). The value is written only to locations where validation
        # succeeds.
        for leaf in leaves:
            _validate_and_apply_leaf(leaf, value, source, extra, problems)

    # Report redundant fields: any keys in extra_values that are not referenced
    # by any schema leaf. These are fields that the user provided but which are
    # not defined in the schema, so they cannot be included in the log output.
    # Optimization: if schema is empty (no used_sources), all fields are redundant,
    # so we can skip the membership check for each key.
    redundant_keys = (
        extra_values.keys()
        if not used_sources
        else (key for key in extra_values.keys() if key not in used_sources)
    )
    for key in redundant_keys:
        error_msg = "is not defined in schema"
        problems.append(
            _DataProblem(
                _create_validation_error_json(key, error_msg, extra_values[key])
            )
        )

    cleaned_extra = _strip_empty(extra)
    return cleaned_extra, problems
