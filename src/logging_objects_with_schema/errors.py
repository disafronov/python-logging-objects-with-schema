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
    """Exception for schema validation problems (deprecated).

    This exception class is kept for backward compatibility but is no longer
    raised by :class:`SchemaLogger` during initialization. Schema problems are
    now handled internally: errors are logged to stderr and the application
    is terminated via ``os._exit(1)``.

    The human-readable summary is stored in the exception message, while
    detailed information about each violation is available in the ``problems``
    attribute.

    Attributes:
        problems: List of SchemaProblem instances describing each validation issue.

    Note:
        This exception may still be used internally or in tests, but
        applications should not expect to catch it when creating SchemaLogger
        instances.
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
