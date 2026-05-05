"""Custom exception types used by logging_objects_with_schema."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass
class _SchemaProblem:
    """Describes a single problem encountered while loading the schema.

    This class is part of the internal implementation and is not considered
    a public API. Its signature and behaviour may change between releases
    without preserving backward compatibility.

    This class is used to report schema validation errors during schema
    compilation. Schema problems are fatal: if any are detected during
    logger initialization, the application is terminated after logging
    all problems to stderr via ``os._exit(1)``.

    Schema problems can occur due to:
    - Missing or inaccessible schema file
    - Invalid JSON syntax
    - Invalid schema structure (non-object top-level, missing required fields)
    - Unknown type names or invalid type declarations
    - Root key conflicts with reserved logging fields
    - Excessive nesting depth (exceeds MAX_SCHEMA_DEPTH)

    Attributes:
        message: Human-readable description of the problem. Examples include:
            - "Schema file not found: /path/to/logging_objects_with_schema.json"
            - "Failed to parse JSON schema: Expecting ',' delimiter: line 5 column 10"
            - "Unknown type 'string' at ServicePayload.RequestID"
            - "Root key 'name' conflicts with reserved logging fields"
            - "Schema nesting depth exceeds maximum allowed depth of 100 at "
              "path ServicePayload.Metrics"
    """

    message: str


@dataclass
class _DataProblem:
    """Describes a single problem encountered while validating log data.

    This class is part of the internal implementation and is not considered
    a public API. Its signature and behaviour may change between releases
    without preserving backward compatibility.

    This class is used to report validation errors when applying the compiled
    schema to user-provided ``extra`` fields during logging. Unlike
    :class:`_SchemaProblem`, data problems are not fatal: they are collected
    and logged as ERROR messages *after* the main log record has been emitted,
    ensuring 100% compatibility with standard logger behavior.

    Data problems can occur due to:
    - Type mismatches (e.g., providing str where int is expected)
    - None values (None is never allowed for any type)
    - Invalid list elements (non-homogeneous lists, non-primitive elements)
    - Redundant fields (fields not defined in the schema)

    Attributes:
        data: Dict containing structured error information with keys
            ``field``, ``error``, and ``value`` (all via ``repr()``).
    """

    data: dict[str, Any]

    @property
    def message(self) -> str:
        return json.dumps(self.data)
