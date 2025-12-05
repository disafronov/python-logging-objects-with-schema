"""Internal schema application logic for logging_objects_with_schema.

This module provides the core function for applying a compiled schema
to user-provided extra fields, used by SchemaLogger.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping, MutableMapping

from .errors import DataProblem
from .schema_loader import CompiledSchema, SchemaLeaf


def _validate_list_value(
    value: list,
    source: str,
    item_expected_type: type | None,
) -> DataProblem | None:
    """Validate that a list value matches the expected item type.

    Validates that all elements in the list have the exact type declared by
    ``item_expected_type``. Empty lists are always considered valid.

    Args:
        value: The list value to validate.
        source: The source field name (for error messages).
        item_expected_type: Expected type for list elements. Must not be None
            for list-typed leaves.

    Returns:
        DataProblem if validation fails, None if validation succeeds.
    """
    if item_expected_type is None:
        return DataProblem(
            f"Field '{source}' is declared as list in schema but "
            f"has no item type configured",
        )

    if len(value) == 0:
        # Empty lists are always valid
        return None

    invalid_item_types = {
        type(item).__name__ for item in value if type(item) is not item_expected_type
    }

    if invalid_item_types:
        return DataProblem(
            f"Field '{source}' is a list but contains elements "
            f"with types {sorted(invalid_item_types)}; "
            f"expected all elements to be of type "
            f"{item_expected_type.__name__}",
        )

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
    for key in path[:-1]:
        child = current.get(key)
        if not isinstance(child, dict):
            child = {}
            current[key] = child
        current = child

    current[path[-1]] = value


def _validate_and_apply_leaf(
    leaf: SchemaLeaf,
    value: Any,
    source: str,
    extra: MutableMapping[str, Any],
    problems: list[DataProblem],
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
        problems.append(
            DataProblem(
                f"Field '{source}' has type {type(value).__name__}, "
                f"expected {leaf.expected_type.__name__}",
            ),
        )
        return

    # For lists, validate that all elements strictly match the declared
    # item_expected_type (homogeneous primitive list).
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
    compiled: CompiledSchema,
    extra_values: Mapping[str, Any],
) -> tuple[dict[str, Any], list[DataProblem]]:
    """Internal function to build structured ``extra`` from compiled schema.

    The function applies a :class:`CompiledSchema` to user-provided ``extra``
    values and returns a tuple ``(structured_extra, problems)`` where:

    - ``structured_extra`` is a nested dictionary that follows the schema
      structure and contains only fields that passed validation;
    - ``problems`` is a list of :class:`DataProblem` describing all data
      issues observed during processing.

    Behaviour summary:

    - If the compiled schema is effectively empty (no valid leaves),
      all fields from ``extra_values`` are treated as redundant: the returned
      payload is empty, and a :class:`DataProblem` is created for each field.
    - For each ``source`` mentioned in the schema when there are valid leaves:
      - if the source is missing from ``extra_values``, it is silently skipped;
      - if the corresponding value is ``None``, a ``DataProblem`` is recorded
        and the value is not written to the payload.
    - Type checks are strict: the runtime type must exactly match the declared
      Python type (``type(value) is leaf.expected_type``). This prevents
      ``bool`` from being accepted where ``int`` is expected.
    - For list-typed leaves:
      - empty lists are accepted;
      - all elements must have the exact type declared by the leaf
        ``item_expected_type`` (for example, list[str], list[int]);
      - non-primitive elements and elements of a different primitive type are
        rejected with a ``DataProblem`` and the list value is not written.
    - Redundant fields from ``extra_values`` (not referenced by any leaf
      ``source``) are always reported as problems: each such field generates
      a :class:`DataProblem` indicating that it is not defined in the schema.
    - A single ``source`` may be used by multiple leaves. The value is
      validated independently for each leaf and written only to locations
      where the type matches; mismatched locations produce ``DataProblem``
      entries, but do not affect successful locations.

    The function itself does not raise ``DataValidationError``; it only
    accumulates :class:`DataProblem` instances for the caller to handle.

    Note:
        This function is used internally by :class:`SchemaLogger` and is not
        considered part of the public API. Its signature and behaviour may
        change between releases without preserving backward compatibility.

    Returns:
        Tuple of (structured_extra, list[DataProblem]).
    """
    extra: dict[str, Any] = {}
    problems: list[DataProblem] = []

    # Group leaves by source for efficient processing
    source_to_leaves: dict[str, list[SchemaLeaf]] = defaultdict(list)
    for leaf in compiled.leaves:
        source_to_leaves[leaf.source].append(leaf)

    used_sources = set(source_to_leaves.keys())

    for source, leaves in source_to_leaves.items():
        if source not in extra_values:
            continue

        value = extra_values[source]

        # Check for None values explicitly (None values are not allowed)
        # This check must be done once per source, not once per leaf
        if value is None:
            problems.append(
                DataProblem(
                    f"Field '{source}' is None, but None values are not allowed",
                ),
            )
            continue

        for leaf in leaves:
            _validate_and_apply_leaf(leaf, value, source, extra, problems)

    # Report redundant fields for any keys not referenced by schema leaves.
    for key in extra_values.keys():
        if key not in used_sources:
            problems.append(
                DataProblem(
                    f"Field '{key}' is not defined in schema and will be ignored",
                ),
            )

    cleaned_extra = _strip_empty(extra)
    return cleaned_extra, problems
