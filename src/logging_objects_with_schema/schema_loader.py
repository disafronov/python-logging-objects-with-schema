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
from collections.abc import Iterable, Mapping, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import _SchemaProblem

_SCHEMA_FILE_NAME = "logging_objects_with_schema.json"

# Maximum allowed depth for schema nesting (protection against DoS)
MAX_SCHEMA_DEPTH = 100


@dataclass
class _SchemaLeaf:
    """Represents a single leaf in the schema tree.

    This class is part of the internal implementation and is not considered
    a public API. Its signature and behaviour may change between releases
    without preserving backward compatibility.

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
class _CompiledSchema:
    """Internal representation of a compiled schema.

    This class is part of the internal implementation and is not considered
    a public API. Its signature and behaviour may change between releases
    without preserving backward compatibility.
    """

    leaves: list[_SchemaLeaf]

    @property
    def is_empty(self) -> bool:
        """Return True if there are no valid leaves."""

        return not self.leaves


def _create_empty_compiled_schema_with_problems(
    problems: list[_SchemaProblem],
) -> tuple[_CompiledSchema, list[_SchemaProblem]]:
    """Create an empty _CompiledSchema with problems.

    Args:
        problems: List of schema problems.

    Returns:
        Tuple of (empty _CompiledSchema, problems list).
    """
    return (_CompiledSchema(leaves=[]), problems)


_TYPE_MAP: Mapping[str, type] = {
    "str": str,
    "int": int,
    "float": float,
    "bool": bool,
    "list": list,
}

# Two-level caching system for schema loading:
#
# 1. Path cache (_resolved_schema_path, _cached_cwd): Caches the result of
#    searching for the schema file. This avoids re-walking the directory tree
#    on every logger creation. The cache behavior differs based on whether
#    the file was found:
#    - If found: The absolute path is cached (CWD-independent) since the file
#      location doesn't change even if CWD changes.
#    - If not found: The path is based on current CWD (where we expected to
#      find it), so we cache both the path and the CWD. If CWD changes, we
#      invalidate and re-search from the new location.
#
# 2. Compiled schema cache (_SCHEMA_CACHE): Caches the compiled schema and
#    validation problems for a given schema file path. This avoids re-parsing
#    and re-compiling the schema JSON on every logger creation. The cache key
#    is the absolute schema file path from the path cache.
#
# These caches work together: path cache finds the file location, compiled
# cache stores the result of compiling that file. Both are thread-safe and
# use double-checked locking to avoid race conditions.

# Compiled schema cache: Key is tuple of (absolute schema_path, frozenset of
# forbidden_keys), Value is tuple of (_CompiledSchema, list[_SchemaProblem]).
# This cache stores both successful compilations and failures (with problems list).
_SCHEMA_CACHE: dict[
    tuple[Path, frozenset[str]], tuple[_CompiledSchema, list[_SchemaProblem]]
] = {}

_cache_lock = threading.RLock()

# Path cache: Cached absolute path to schema file (or expected location if not found)
_resolved_schema_path: Path | None = None
# CWD that was used when caching a path for a file that was not found.
# None means the cached path is an absolute path to a found file (CWD-independent).
# Non-None means the cached path is an absolute path based on CWD when file
# was not found.
_cached_cwd: Path | None = None
# RLock for thread-safe access to path cache variables.
# RLock (not Lock) is needed because helper functions (_check_cached_found_file_path,
# _check_cached_missing_file_path) are called from _get_schema_path() which already
# holds the lock, and these helpers also need to acquire the lock.
_path_cache_lock = threading.RLock()


def _find_schema_file() -> Path | None:
    """Search for schema file by walking up the directory tree.

    Starts from current working directory and searches upward for the schema file.
    If found, returns the absolute path to the file. If not found, returns None.

    Returns:
        Absolute path to schema file if found, None otherwise.
    """
    start_path = _get_current_working_directory()
    current = start_path

    while True:
        schema_path = current / _SCHEMA_FILE_NAME
        if schema_path.exists():
            # Use resolve() to get an absolute path and resolve any symbolic links.
            # This ensures we have a canonical path that can be used as a cache key
            # and for consistent error reporting.
            return schema_path.resolve()

        # Move to parent directory
        parent = current.parent
        if parent == current:
            # Reached filesystem root, stop searching
            break
        current = parent

    return None


def _get_current_working_directory() -> Path:
    """Get the current working directory as a resolved Path.

    Returns:
        Absolute path to the current working directory.
    """
    return Path(os.getcwd()).resolve()


def _check_cached_found_file_path() -> Path | None:
    """Check if cached path for a found file is still valid.

    When a schema file was found, its absolute path is cached as CWD-independent.
    This function checks if the cached path still exists on disk.

    Returns:
        Cached path if file still exists, None if file was deleted (cache invalidated).
    """
    global _resolved_schema_path

    with _path_cache_lock:
        if _resolved_schema_path is None:
            return None

        # Schema file was found, absolute path doesn't depend on CWD
        # Return it if it still exists
        if _resolved_schema_path.exists():
            return _resolved_schema_path

        # Cached file no longer exists; invalidate cache so caller will re-search
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

    with _path_cache_lock:
        if _resolved_schema_path is None or _cached_cwd is None:
            return None

        # Cached path is based on CWD when file was not found,
        # check if CWD changed
        current_cwd = _get_current_working_directory()
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

    current_cwd = _get_current_working_directory()
    schema_path = (current_cwd / _SCHEMA_FILE_NAME).resolve()
    _resolved_schema_path = schema_path
    _cached_cwd = current_cwd  # Track CWD since path depends on it
    return schema_path


def _get_schema_path() -> Path:
    """Resolve the absolute path to the JSON schema file with caching semantics.

    The function searches for ``_SCHEMA_FILE_NAME`` by walking upward from the
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
        # Check cached path for missing file first (CWD-dependent)
        # This must be checked before found file cache, because
        # _check_cached_found_file_path would invalidate the cache if file
        # doesn't exist, even for missing file cache.
        if _cached_cwd is not None:
            cached_path = _check_cached_missing_file_path()
            if cached_path is not None:
                return cached_path

        # Check cached path for found file (CWD-independent)
        cached_path = _check_cached_found_file_path()
        if cached_path is not None:
            return cached_path

        # Search for schema file
        found_path = _find_schema_file()
        if found_path is not None:
            return _cache_and_return_found_path(found_path)

        # Schema file not found, return absolute path in current working directory
        # (this path may not exist, but allows caller to report proper error)
        return _cache_and_return_missing_path()


def _load_raw_schema(schema_path: Path) -> tuple[dict[str, Any], Path]:
    """Load raw JSON schema from the application root.

    This function attempts to read and parse the schema file. If any problems
    occur (file not found, I/O errors, invalid JSON, wrong top-level type),
    it raises exceptions (FileNotFoundError or ValueError). These exceptions
    are then converted to :class:`_SchemaProblem` instances by the caller
    (_compile_schema_internal).

    Args:
        schema_path: Absolute path to the schema file.

    Raises:
        FileNotFoundError: If the schema file does not exist.
        ValueError: If the file cannot be read, contains invalid JSON, or
            the top-level value is not a JSON object.

    Note:
        This helper is part of the internal implementation and is not
        considered a public API.

    Returns:
        Tuple of (schema data, schema file path).
    """
    if not schema_path.exists():
        # Let the caller decide how to report this.
        raise FileNotFoundError(f"Schema file not found: {schema_path}")

    try:
        with schema_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as exc:
        # Normalise I/O errors when reading the schema file (e.g., permission
        # denied, file not found) to ValueError so that _compile_schema_internal()
        # can report them as _SchemaProblem instances instead of leaking raw
        # OSError to callers. Note: System-level OSError (e.g., from os.getcwd())
        # is not caught here and propagates directly.
        raise ValueError(
            f"Failed to read schema file {schema_path}: {exc}",
        ) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Failed to parse JSON schema: {exc}") from exc

    if not isinstance(data, dict):
        # Normalise non-object top-level schemas into a ValueError so that the
        # caller can report it as a _SchemaProblem while keeping type safety.
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

    This function is used during schema validation to check if required fields
    (type, source, item_type) have valid values. Both None and empty/whitespace-only
    strings are considered invalid because they don't provide meaningful information
    for schema compilation.

    Args:
        value: The value to check.

    Returns:
        True if value is None or an empty/whitespace-only string, False otherwise.
    """
    return value is None or (isinstance(value, str) and value.strip() == "")


def _is_leaf_node(value_dict: dict[str, Any]) -> bool:
    """Check if a schema node is a leaf node.

    A leaf node is identified by having either 'type' or 'source' field.
    Inner nodes have neither of these fields.

    We use `.get()` with `is not None` check instead of `in` operator because:
    - A field might be present but have a None value (which indicates an error)
    - We need to distinguish between "field not present" (inner node) and
      "field present but None" (invalid leaf node that will be caught later)

    Args:
        value_dict: Dictionary containing node data.

    Returns:
        True if the node is a leaf, False if it's an inner node.
    """
    return value_dict.get("type") is not None or value_dict.get("source") is not None


def _validate_and_create_leaf(
    value_dict: dict[str, Any],
    path: tuple[str, ...],
    key: str,
    problems: list[_SchemaProblem],
) -> _SchemaLeaf | None:
    """Validate a leaf node and create _SchemaLeaf if valid.

    Args:
        value_dict: Dictionary containing leaf node data.
        path: Current path in the schema tree.
        key: Current key being processed.
        problems: List to collect validation problems.

    Returns:
        _SchemaLeaf if validation passes, None otherwise.
    """
    leaf_type = value_dict.get("type")
    leaf_source = value_dict.get("source")

    # This is supposed to be a leaf - validate required fields first.
    type_invalid = _is_empty_or_none(leaf_type)
    source_invalid = _is_empty_or_none(leaf_source)

    if type_invalid:
        problems.append(
            _SchemaProblem(
                f"Incomplete leaf at {_format_path(path, key)}: "
                f"type cannot be None or empty",
            ),
        )

    if source_invalid:
        problems.append(
            _SchemaProblem(
                f"Incomplete leaf at {_format_path(path, key)}: "
                f"source cannot be None or empty",
            ),
        )

    if type_invalid or source_invalid:
        return None

    # Convert to string before lookup to handle cases where the JSON parser
    # might return non-string types (though this shouldn't happen with valid JSON).
    # This ensures type safety and consistent behavior.
    expected_type = _TYPE_MAP.get(str(leaf_type))
    if expected_type is None:
        problems.append(
            _SchemaProblem(
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
                _SchemaProblem(
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
                _SchemaProblem(
                    f"Invalid item_type '{item_type_name}' at "
                    f"{_format_path(path, key)}: only primitive item types "
                    f"('str', 'int', 'float', 'bool') are allowed for lists",
                ),
            )
            return None

    return _SchemaLeaf(
        path=path + (key,),
        # Convert to string to ensure type consistency. Even though source should
        # be a string from JSON, this guards against unexpected types and ensures
        # the _SchemaLeaf always has a string source.
        source=str(leaf_source),
        expected_type=expected_type,
        item_expected_type=item_expected_type,
    )


def _compile_schema_tree(
    node: MutableMapping[str, Any],
    path: tuple[str, ...],
    problems: list[_SchemaProblem],
) -> Iterable[_SchemaLeaf]:
    """Recursively compile a schema node into _SchemaLeaf objects.

    This function recursively walks the schema tree structure, identifying leaf
    nodes (those with ``type`` and ``source`` fields) and inner nodes (those
    without these fields). Leaf nodes are validated and converted to
    :class:`_SchemaLeaf` objects, while inner nodes are recursively processed.

    Performance considerations:
        Time complexity is O(n) where n is the total number of nodes in the
        schema tree. Memory complexity is O(d) where d is the maximum nesting
        depth (limited by MAX_SCHEMA_DEPTH). For typical schemas (< 1000 nodes,
        depth < 10), the overhead is negligible.

    Limitations:
        - Maximum nesting depth is limited to MAX_SCHEMA_DEPTH (currently 100)
          to prevent stack overflow and excessive memory usage
        - Very large schemas (> 10,000 nodes) may cause noticeable compilation
          overhead, but this is uncommon in practice

    Args:
        node: The schema node to compile.
        path: Current path in the schema tree.
        problems: List to collect validation problems.

    Yields:
        _SchemaLeaf objects found in the tree.
    """
    # Check for excessive nesting depth (DoS protection: prevent deeply nested
    # schemas that could cause stack overflow or excessive memory usage).
    # This check happens before processing the node to avoid unnecessary work
    # and to provide clear error messages about the problematic path.
    if len(path) > MAX_SCHEMA_DEPTH:
        problems.append(
            _SchemaProblem(
                f"Schema nesting depth exceeds maximum allowed depth of "
                f"{MAX_SCHEMA_DEPTH} at path {_format_path(path)}"
            ),
        )
        return

    for key, value in node.items():
        if not isinstance(value, Mapping):
            problems.append(
                _SchemaProblem(
                    f"Invalid schema at {_format_path(path, key)}: expected object"
                ),
            )
            continue

        # Create a mutable copy of the value dict. This is necessary because
        # we may need to modify it during processing, and the original value
        # might be a read-only Mapping (e.g., from JSON parsing).
        value_dict = dict(value)

        if _is_leaf_node(value_dict):
            leaf = _validate_and_create_leaf(value_dict, path, key, problems)
            if leaf is not None:
                yield leaf
        else:
            # This is an inner node; recurse into children.
            for child_leaf in _compile_schema_tree(value_dict, path + (key,), problems):
                yield child_leaf


@functools.lru_cache(maxsize=1)
def _get_builtin_logrecord_attributes() -> set[str]:
    """Get set of standard LogRecord attribute names.

    This function is part of the internal implementation and is not considered
    a public API. Its signature and behaviour may change between releases
    without preserving backward compatibility.

    This function extracts attribute names from LogRecord that represent
    system fields and should not be used as root keys in the schema or
    treated as user-provided extra fields.

    The function creates a minimal LogRecord instance and uses introspection
    to discover all non-callable, non-private attributes. This is the standard
    way to get attribute names from a class instance in Python.

    The result is cached (maxsize=1) because LogRecord attributes are fixed
    for a given Python version and don't change at runtime. This avoids
    recreating the LogRecord instance and running introspection on every
    schema compilation.

    Returns:
        Set of attribute names that are reserved by the logging system.
        Examples include: 'name', 'levelno', 'pathname', 'lineno', 'msg', etc.

    Example:
        >>> forbidden = _get_builtin_logrecord_attributes()
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
    schema_dict: Mapping[str, Any],
    problems: list[_SchemaProblem],
    forbidden_keys: set[str] | None = None,
) -> None:
    """Check schema root keys for conflicts with reserved logging fields.

    Args:
        schema_dict: The schema dictionary to check.
        problems: List to collect validation problems.
        forbidden_keys: Additional forbidden root keys to check against.
            These keys are merged with builtin LogRecord attributes.
            Builtin keys cannot be replaced, only supplemented.
            Note: None and empty set() are semantically equivalent - both
            mean "no additional forbidden keys" and produce the same result.
    """
    # Builtin keys always present, cannot be replaced
    forbidden_root_keys = _get_builtin_logrecord_attributes()
    # Merge with additional forbidden keys if provided.
    # We use `if forbidden_keys:` instead of `if forbidden_keys is not None:` because
    # both None and empty set() semantically mean "no additional forbidden keys".
    # This check treats them equivalently: None is falsy, and empty set() is also
    # falsy, so both cases skip the merge operation, which is the correct behavior.
    if forbidden_keys:
        forbidden_root_keys = forbidden_root_keys | forbidden_keys

    for key in schema_dict.keys():
        if key in forbidden_root_keys:
            problems.append(
                _SchemaProblem(
                    f"Root key '{key}' conflicts with reserved logging fields",
                ),
            )


def _compile_schema_internal(
    forbidden_keys: set[str] | None = None,
) -> tuple[_CompiledSchema, list[_SchemaProblem]]:
    """Compile JSON schema into ``_CompiledSchema`` and collect all problems.

    The function loads the raw JSON schema, validates its structure, checks
    root keys for conflicts with reserved ``logging.LogRecord`` attributes
    and compiles all valid leaves into a :class:`_CompiledSchema`. All issues
    discovered during this process are reported as :class:`_SchemaProblem`
    instances.

    Results are cached process-wide: the cache key is a tuple of the absolute
    schema file path and the set of additional forbidden keys. The value is a
    tuple ``(_CompiledSchema, list[_SchemaProblem])``. Once a schema for a
    given path and forbidden keys set has been observed (including the cases
    when it is missing or invalid), subsequent calls always return the cached
    result without re-reading or re-compiling the schema. To pick up on-disk
    changes to the schema, the application must restart the process. See the
    README section \"Schema caching and thread safety\" for more details.

    Args:
        forbidden_keys: Additional forbidden root keys to check against.
            These keys are merged with builtin LogRecord attributes.
            Builtin keys cannot be replaced, only supplemented.
            Note: None and empty set() are semantically equivalent - both
            mean "no additional forbidden keys" and produce the same result.
            They also produce the same cache key, so cached results are shared.

    This function never raises exceptions. It always returns the best-effort
    compiled schema together with a list of problems detected during processing
    (an empty ``_CompiledSchema`` when the schema is missing or invalid).

    Performance considerations:
        First compilation of a schema involves file I/O, JSON parsing, and tree
        traversal. For typical schemas (< 1000 nodes), this takes < 10ms. All
        subsequent calls for the same schema path and forbidden keys return
        immediately from cache (< 0.1ms). The cache is process-wide and persists
        for the application lifetime.

    Limitations:
        - Schema changes on disk are not automatically reloaded; the application
          must be restarted to pick up changes
        - Very large schemas (> 10,000 nodes) may cause noticeable compilation
          overhead on first load, but this is uncommon in practice
        - The cache uses absolute file paths and forbidden keys sets as keys, so
          schema files must be accessible via the same path throughout the
          application lifetime

    Note:
        This function is used internally by :class:`SchemaLogger` and by the
        test suite. It is not part of the public package API and may change
        between releases without preserving backward compatibility.

    Returns:
        Tuple of (_CompiledSchema, list[_SchemaProblem]).
    """
    schema_path = _get_schema_path()
    # Create cache key that includes forbidden keys.
    # We use `frozenset(forbidden_keys or ())` instead of checking for None explicitly
    # because both None and empty set() should produce the same cache key (frozenset()).
    # This is semantically correct: both None and set() mean "no additional forbidden
    # keys", so they should share the same cached compilation result. The `or ()`
    # operator converts None to empty tuple, which frozenset() then converts to empty
    # frozenset, and empty set() also becomes empty frozenset, ensuring cache key
    # consistency.
    cache_key = (schema_path, frozenset(forbidden_keys or ()))

    # Fast-path: First check (with lock for thread-safety) if we have already attempted
    # to compile schema for this path and forbidden keys set. This provides thread-safe
    # cache access in the common case when the schema is already cached.
    with _cache_lock:
        cached = _SCHEMA_CACHE.get(cache_key)
    if cached is not None:
        return cached

    # Schema not in cache. We need to compile it. However, between the check above
    # and now, another thread might have started (or even finished) compiling the
    # same schema. We use double-checked locking to handle this race condition:
    # after doing the expensive work (loading/compiling), we check the cache again
    # while holding the lock. If another thread already compiled it, we use that
    # result instead of storing our own (which might be different if the file changed).

    problems: list[_SchemaProblem] = []

    try:
        raw_schema, _ = _load_raw_schema(schema_path)
    except (FileNotFoundError, ValueError) as exc:
        problems.append(_SchemaProblem(str(exc)))
        result = _create_empty_compiled_schema_with_problems(problems)
        # Double-checked locking: Check cache again while holding lock. Another
        # thread might have compiled the schema (or handled the same error) while
        # we were processing the exception. If so, use the cached result.
        with _cache_lock:
            cached = _SCHEMA_CACHE.get(cache_key)
            if cached is not None:
                return cached
            _SCHEMA_CACHE[cache_key] = result
        return result

    # Check root key conflicts before compiling the tree. This allows us to
    # catch conflicts early and report them as schema problems. We do this
    # before tree compilation to avoid unnecessary work if there are conflicts.
    _check_root_conflicts(raw_schema, problems, forbidden_keys)

    # Compile the schema tree into leaves. Each root key becomes a separate
    # tree that we compile recursively. Problems are collected as we go.
    leaves: list[_SchemaLeaf] = []
    for key, value in raw_schema.items():
        if not isinstance(value, Mapping):
            problems.append(
                _SchemaProblem(f"Invalid schema at {key}: expected object"),
            )
            continue

        # Create a mutable copy of the value dict for recursive compilation.
        # This ensures we can safely process nested structures without modifying
        # the original schema dictionary.
        for leaf in _compile_schema_tree(dict(value), (key,), problems):
            leaves.append(leaf)

    compiled = _CompiledSchema(leaves=leaves)
    result = (compiled, problems)

    # Double-checked locking: Check cache again while holding lock. Another thread
    # might have compiled the schema while we were doing the expensive compilation
    # work (parsing JSON, validating, building leaves). If so, use the cached result
    # instead of overwriting it with our own (which might be different if the file
    # was modified between reads).
    with _cache_lock:
        cached = _SCHEMA_CACHE.get(cache_key)
        if cached is not None:
            return cached
        _SCHEMA_CACHE[cache_key] = result

    return result
