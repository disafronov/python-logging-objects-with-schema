"""Schema loading and validation for logging_objects_with_schema.

The schema is expected to live in a JSON file named
``logging_objects_with_schema.json`` in the application root
directory. The schema defines which extra fields are allowed to be
emitted and which Python types they must have.
"""

from __future__ import annotations

import functools
import json
import logging
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping

from .errors import SchemaProblem

SCHEMA_FILE_NAME = "logging_objects_with_schema.json"

# Maximum allowed depth for schema nesting (protection against DoS)
MAX_SCHEMA_DEPTH = 100


@dataclass
class SchemaLeaf:
    """Represents a single leaf in the schema tree.

    Attributes:
        path: Full path of keys from the schema root to this leaf.
        source: Name of the field in the ``extra`` mapping.
        expected_type: Expected Python type of the value (str, int, float, bool, list).
        item_expected_type: Expected Python type of list elements when
            ``expected_type`` is ``list``. For non-list leaves this is ``None``.
    """

    path: tuple[str, ...]
    source: str
    expected_type: type
    item_expected_type: type | None = None


@dataclass
class CompiledSchema:
    """Internal representation of a compiled schema."""

    leaves: list[SchemaLeaf]

    @property
    def is_empty(self) -> bool:
        """Return True if there are no valid leaves."""

        return not self.leaves


_TYPE_MAP: Mapping[str, type] = {
    "str": str,
    "int": int,
    "float": float,
    "bool": bool,
    "list": list,
}

# Module-level cache for compiled schemas.
# Key: absolute schema_path, Value: (CompiledSchema, list[SchemaProblem])
# This cache is thread-safe: all read and write operations are protected by
# _cache_lock.
_SCHEMA_CACHE: dict[Path, tuple[CompiledSchema, list[SchemaProblem]]] = {}

_cache_lock = threading.RLock()

# Cache for resolved schema path (to avoid re-searching when CWD changes)
_resolved_schema_path: Path | None = None
# CWD that was used when caching a path for a file that was not found
# None means the cached path is an absolute path to a found file (CWD-independent)
# Non-None means the cached path is an absolute path based on CWD
# when file was not found
_cached_cwd: Path | None = None
_path_cache_lock = threading.Lock()


def _find_schema_file() -> Path | None:
    """Search for schema file by walking up the directory tree.

    Starts from current working directory and searches upward for the schema file.
    If found, returns the absolute path to the file. If not found, returns None.

    Returns:
        Absolute path to schema file if found, None otherwise.
    """
    start_path = Path(os.getcwd()).resolve()
    current = start_path

    while True:
        schema_path = current / SCHEMA_FILE_NAME
        if schema_path.exists():
            return schema_path.resolve()

        # Move to parent directory
        parent = current.parent
        if parent == current:
            # Reached filesystem root, stop searching
            break
        current = parent

    return None


def _check_cached_found_file_path() -> Path | None:
    """Check if cached path for a found file is still valid.

    When a schema file was found, its absolute path is cached as CWD-independent.
    This function checks if the cached path still exists on disk.

    Returns:
        Cached path if file still exists, None if file was deleted (cache invalidated).
    """
    global _resolved_schema_path

    if _resolved_schema_path is None:
        return None

    # Schema file was found, absolute path doesn't depend on CWD
    # Return it if it still exists
    if _resolved_schema_path.exists():
        return _resolved_schema_path

    # If cached path doesn't exist, re-search (schema might have been moved)
    _resolved_schema_path = None
    return None


def _check_cached_missing_file_path() -> Path | None:
    """Check if cached path for a missing file is still valid.

    When a schema file was not found, a path based on CWD is cached.
    This function checks if CWD has changed since caching.

    Returns:
        Cached path if CWD unchanged, None if CWD changed (cache invalidated).
    """
    global _resolved_schema_path, _cached_cwd

    if _resolved_schema_path is None or _cached_cwd is None:
        return None

    # Cached path is based on CWD when file was not found,
    # check if CWD changed
    current_cwd = Path(os.getcwd()).resolve()
    if current_cwd != _cached_cwd:
        # CWD changed, invalidate cache and re-search from new CWD
        _resolved_schema_path = None
        _cached_cwd = None
        return None

    # CWD unchanged, return cached path
    return _resolved_schema_path


def _cache_and_return_found_path(found_path: Path) -> Path:
    """Cache a found schema file path and return it.

    Args:
        found_path: Absolute path to the found schema file.

    Returns:
        The cached path (CWD-independent).
    """
    global _resolved_schema_path, _cached_cwd

    _resolved_schema_path = found_path
    _cached_cwd = None  # Absolute path doesn't depend on CWD
    return found_path


def _cache_and_return_missing_path() -> Path:
    """Cache a missing schema file path and return it.

    Returns:
        Absolute path in current working directory where schema file is expected.
    """
    global _resolved_schema_path, _cached_cwd

    current_cwd = Path(os.getcwd()).resolve()
    schema_path = (current_cwd / SCHEMA_FILE_NAME).resolve()
    _resolved_schema_path = schema_path
    _cached_cwd = current_cwd  # Track CWD since path depends on it
    return schema_path


def _get_schema_path() -> Path:
    """Resolve the absolute path to the JSON schema file with caching semantics.

    The function searches for ``SCHEMA_FILE_NAME`` by walking upward from the
    current working directory and caches the result:

    - When the schema file is found, its absolute path is cached as
      CWD-independent. Subsequent calls reuse this path as long as the file
      still exists on disk.
    - When the schema file is not found, an absolute path based on the current
      CWD is cached (the directory where the file was expected but missing).
      This cache entry is tied to the CWD and is invalidated automatically
      if the process changes CWD, so that a new search can be performed.

    In both cases the returned path may or may not exist and is suitable for
    reporting clear error messages to the caller.

    Returns:
        Absolute path where the schema file is located or expected to be.
    """
    with _path_cache_lock:
        # Check cached path for found file (CWD-independent)
        cached_path = _check_cached_found_file_path()
        if cached_path is not None:
            return cached_path

        # Check cached path for missing file (CWD-dependent)
        cached_path = _check_cached_missing_file_path()
        if cached_path is not None:
            return cached_path

        # Search for schema file
        found_path = _find_schema_file()
        if found_path is not None:
            return _cache_and_return_found_path(found_path)

        # Schema file not found, return absolute path in current working directory
        # (this path may not exist, but allows caller to report proper error)
        return _cache_and_return_missing_path()


def _load_raw_schema() -> tuple[dict[str, Any], Path]:
    """Load raw JSON schema from the application root.

    This function always attempts to read the schema file and records
    any problems as :class:`SchemaProblem` instances.

    Note:
        This helper is part of the internal implementation and is not
        considered a public API.

    Returns:
        Tuple of (schema data, schema file path).
    """
    schema_path = _get_schema_path()

    if not schema_path.exists():
        # Let the caller decide how to report this.
        raise FileNotFoundError(f"Schema file not found: {schema_path}")

    try:
        with schema_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as exc:
        # Normalise I/O errors to ValueError so that _compile_schema_internal()
        # can report them as SchemaProblem instances instead of leaking raw
        # OSError to callers.
        raise ValueError(
            f"Failed to read schema file {schema_path}: {exc}",
        ) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Failed to parse JSON schema: {exc}") from exc

    if not isinstance(data, dict):
        # Normalise non-object top-level schemas into a ValueError so that the
        # caller can report it as a SchemaProblem while keeping type safety.
        raise ValueError("Top-level schema must be a JSON object")

    return data, schema_path


def _format_path(path: tuple[str, ...], key: str | None = None) -> str:
    """Format a schema path tuple into a dot-separated string.

    Args:
        path: Tuple of keys representing the path in the schema tree.
        key: Optional additional key to append to the path.

    Returns:
        Dot-separated string representation of the path.
    """
    if key is not None:
        return ".".join(path + (key,))
    return ".".join(path)


def _is_empty_or_none(value: Any) -> bool:
    """Check if a value is None or an empty string.

    Args:
        value: The value to check.

    Returns:
        True if value is None or an empty/whitespace-only string, False otherwise.
    """
    return value is None or (isinstance(value, str) and value.strip() == "")


def _validate_and_create_leaf(
    value_dict: dict[str, Any],
    path: tuple[str, ...],
    key: str,
    problems: list[SchemaProblem],
) -> SchemaLeaf | None:
    """Validate a leaf node and create SchemaLeaf if valid.

    Args:
        value_dict: Dictionary containing leaf node data.
        path: Current path in the schema tree.
        key: Current key being processed.
        problems: List to collect validation problems.

    Returns:
        SchemaLeaf if validation passes, None otherwise.
    """
    leaf_type = value_dict.get("type")
    leaf_source = value_dict.get("source")

    # This is supposed to be a leaf - validate required fields first.
    type_invalid = _is_empty_or_none(leaf_type)
    source_invalid = _is_empty_or_none(leaf_source)

    if type_invalid:
        problems.append(
            SchemaProblem(
                f"Incomplete leaf at {_format_path(path, key)}: "
                f"type cannot be None or empty",
            ),
        )

    if source_invalid:
        problems.append(
            SchemaProblem(
                f"Incomplete leaf at {_format_path(path, key)}: "
                f"source cannot be None or empty",
            ),
        )

    if type_invalid or source_invalid:
        return None

    expected_type = _TYPE_MAP.get(str(leaf_type))
    if expected_type is None:
        problems.append(
            SchemaProblem(
                f"Unknown type '{leaf_type}' at {_format_path(path, key)}",
            ),
        )
        return None

    item_expected_type: type | None = None
    # For list-typed leaves we require an explicit, primitive item_type
    # to ensure element homogeneity (e.g. list[str], list[int]).
    if expected_type is list:
        item_type_name = value_dict.get("item_type")
        item_type_invalid = _is_empty_or_none(item_type_name)
        if item_type_invalid:
            problems.append(
                SchemaProblem(
                    f"Incomplete leaf at {_format_path(path, key)}: "
                    f"item_type is required for list type and "
                    f"cannot be None or empty",
                ),
            )
            return None

        item_expected_type = _TYPE_MAP.get(str(item_type_name))
        # Item type must be a primitive (str, int, float, bool), not list
        if item_expected_type is None or item_expected_type is list:
            problems.append(
                SchemaProblem(
                    f"Invalid item_type '{item_type_name}' at "
                    f"{_format_path(path, key)}: only primitive item types "
                    f"('str', 'int', 'float', 'bool') are allowed for lists",
                ),
            )
            return None

    return SchemaLeaf(
        path=path + (key,),
        source=str(leaf_source),
        expected_type=expected_type,
        item_expected_type=item_expected_type,
    )


def _compile_schema_tree(
    node: MutableMapping[str, Any],
    path: tuple[str, ...],
    problems: list[SchemaProblem],
) -> Iterable[SchemaLeaf]:
    """Recursively compile a schema node into SchemaLeaf objects.

    Args:
        node: The schema node to compile.
        path: Current path in the schema tree.
        problems: List to collect validation problems.

    Yields:
        SchemaLeaf objects found in the tree.
    """
    # Check for excessive nesting depth
    if len(path) > MAX_SCHEMA_DEPTH:
        problems.append(
            SchemaProblem(
                f"Schema nesting depth exceeds maximum allowed depth of "
                f"{MAX_SCHEMA_DEPTH} at path {_format_path(path)}"
            ),
        )
        return

    for key, value in node.items():
        if not isinstance(value, Mapping):
            problems.append(
                SchemaProblem(
                    f"Invalid schema at {_format_path(path, key)}: expected object"
                ),
            )
            continue

        value_dict = dict(value)
        leaf_type = value_dict.get("type")
        leaf_source = value_dict.get("source")

        if leaf_type is not None or leaf_source is not None:
            leaf = _validate_and_create_leaf(value_dict, path, key, problems)
            if leaf is not None:
                yield leaf
        else:
            # This is an inner node; recurse into children.
            for child_leaf in _compile_schema_tree(value_dict, path + (key,), problems):
                yield child_leaf


@functools.lru_cache(maxsize=1)
def get_builtin_logrecord_attributes() -> set[str]:
    """Get set of standard LogRecord attribute names.

    This function extracts attribute names from LogRecord that represent
    system fields and should not be used as root keys in the schema or
    treated as user-provided extra fields.

    The function creates a minimal LogRecord instance and uses introspection
    to discover all non-callable, non-private attributes. This is the standard
    way to get attribute names from a class instance in Python.

    Returns:
        Set of attribute names that are reserved by the logging system.
        Examples include: 'name', 'levelno', 'pathname', 'lineno', 'msg', etc.

    Example:
        >>> forbidden = get_builtin_logrecord_attributes()
        >>> "name" in forbidden
        True
        >>> "ServicePayload" in forbidden
        False
    """
    # Create a minimal LogRecord instance to inspect its attributes
    # This is necessary because LogRecord attributes are not defined as
    # class attributes but are set in __init__
    record = logging.LogRecord(
        name="",
        level=0,
        pathname="",
        lineno=0,
        msg="",
        args=(),
        exc_info=None,
    )

    # Use dir() to get all attributes, then filter out:
    # - Private attributes (starting with _)
    # - Callable attributes (methods)
    # This leaves only data fields that represent actual LogRecord attributes
    forbidden = set()
    for attr_name in dir(record):
        if attr_name.startswith("_"):
            continue
        attr_value = getattr(record, attr_name, None)
        if not callable(attr_value):
            forbidden.add(attr_name)

    return forbidden


def _check_root_conflicts(
    schema_dict: Mapping[str, Any], problems: list[SchemaProblem]
) -> None:
    """Check schema root keys for conflicts with reserved logging fields."""

    forbidden_root_keys = get_builtin_logrecord_attributes()

    for key in schema_dict.keys():
        if key in forbidden_root_keys:
            problems.append(
                SchemaProblem(
                    f"Root key '{key}' conflicts with reserved logging fields",
                ),
            )


def _compile_schema_internal() -> tuple[CompiledSchema, list[SchemaProblem]]:
    """Compile JSON schema into ``CompiledSchema`` and collect all problems.

    The function loads the raw JSON schema, validates its structure, checks
    root keys for conflicts with reserved ``logging.LogRecord`` attributes
    and compiles all valid leaves into a :class:`CompiledSchema`. All issues
    discovered during this process are reported as :class:`SchemaProblem`
    instances.

    Results are cached process-wide: the cache key is the absolute schema
    file path and the value is a tuple ``(CompiledSchema, list[SchemaProblem])``.
    Once a schema for a given path has been observed (including the cases when
    it is missing or invalid), subsequent calls always return the cached result
    without re-reading or re-compiling the schema. To pick up on-disk changes
    to the schema, the application must restart the process. See the README
    section \"Schema caching and thread safety\" for more details.

    This function never raises ``SchemaValidationError``. It always returns
    the best-effort compiled schema together with a list of problems detected
    during processing (an empty ``CompiledSchema`` when the schema is missing
    or invalid).

    Note:
        This function is used internally by :class:`SchemaLogger` and by the
        test suite. It is not part of the public package API and may change
        between releases without preserving backward compatibility.

    Returns:
        Tuple of (CompiledSchema, list[SchemaProblem]).
    """
    schema_path = _get_schema_path().resolve()

    # Fast-path: if we have already attempted to compile schema for this path,
    # return cached result (successful, missing-file, or invalid-schema).
    with _cache_lock:
        cached = _SCHEMA_CACHE.get(schema_path)
    if cached is not None:
        return cached

    problems: list[SchemaProblem] = []

    try:
        raw_schema, loaded_path = _load_raw_schema()
    except FileNotFoundError as exc:
        problems.append(SchemaProblem(str(exc)))
        result = (CompiledSchema(leaves=[]), problems)
        with _cache_lock:
            _SCHEMA_CACHE[schema_path] = result
        return result
    except ValueError as exc:
        problems.append(SchemaProblem(str(exc)))
        result = (CompiledSchema(leaves=[]), problems)
        with _cache_lock:
            _SCHEMA_CACHE[schema_path] = result
        return result

    _check_root_conflicts(raw_schema, problems)

    leaves: list[SchemaLeaf] = []
    for key, value in raw_schema.items():
        if not isinstance(value, Mapping):
            problems.append(
                SchemaProblem(f"Invalid schema at {key}: expected object"),
            )
            continue

        for leaf in _compile_schema_tree(dict(value), (key,), problems):
            leaves.append(leaf)

    compiled = CompiledSchema(leaves=leaves)
    result = (compiled, problems)

    # Cache the result for this schema path (thread-safe write).
    # NOTE: ``loaded_path`` is expected to be identical to ``schema_path`` here
    # because both are derived from ``_get_schema_path()``. We still use
    # ``schema_path`` as the cache key consistently to avoid any confusion if
    # ``_load_raw_schema()`` implementation changes in the future.
    with _cache_lock:
        _SCHEMA_CACHE[schema_path] = result

    return result
