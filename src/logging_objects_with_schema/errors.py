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


class DataValidationError(Exception):
    """Raised when log record data does not satisfy the configured schema.

    This exception is raised *after* the valid part of the log record
    has already been formatted and sent to the underlying handler. This means
    that even if validation fails, the valid fields will still appear in the log.

    The exception message provides a summary description of the validation
    failure, while detailed information about individual problems is exposed
    via the ``problems`` attribute.

    Attributes:
        problems: List of DataProblem instances describing each validation issue.

    Example:
        >>> try:
        ...     logger.info("processing", extra={"user_id": "not-an-int"})
        ... except DataValidationError as e:
        ...     for problem in e.problems:
        ...         print(f"Validation error: {problem.message}")
        ...     # Note: valid fields were already logged before this exception
    """

    def __init__(self, message: str, problems: list[DataProblem] | None = None) -> None:
        super().__init__(message)
        self.problems: list[DataProblem] = problems or []
