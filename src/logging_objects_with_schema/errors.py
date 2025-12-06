"""Custom exception types used by logging_objects_with_schema."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SchemaProblem:
    """Describes a single problem encountered while loading the schema.

    Attributes:
        message: Human-readable description of the problem.
    """

    message: str


class SchemaValidationError(Exception):
    """Raised when there are problems with the JSON schema definition.

    This exception is raised during SchemaLogger initialization when the schema
    file cannot be loaded, parsed, or validated. The logger instance will not
    be created if this exception is raised.

    The human-readable summary is stored in the exception message, while
    detailed information about each violation is available in the ``problems``
    attribute.

    Attributes:
        problems: List of SchemaProblem instances describing each validation issue.

    Example:
        >>> try:
        ...     logger = SchemaLogger("my_logger")
        ... except SchemaValidationError as e:
        ...     for problem in e.problems:
        ...         print(f"Schema error: {problem.message}")
    """

    def __init__(
        self, message: str, problems: list[SchemaProblem] | None = None
    ) -> None:
        super().__init__(message)
        self.problems: list[SchemaProblem] = problems or []


@dataclass
class DataProblem:
    """Describes a single problem encountered while validating log data.

    Attributes:
        message: Human-readable description of the validation problem.
    """

    message: str
