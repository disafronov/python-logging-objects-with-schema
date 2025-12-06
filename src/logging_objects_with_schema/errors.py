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


@dataclass
class DataProblem:
    """Describes a single problem encountered while validating log data.

    Attributes:
        message: Human-readable description of the validation problem.
    """

    message: str
