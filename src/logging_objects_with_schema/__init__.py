"""Top-level package for logging_objects_with_schema.

This package provides a logger subclass built on top of the standard
logging package that validates and filters user-provided extra fields
according to an application-defined JSON schema.
"""

from __future__ import annotations

from .errors import DataValidationError, SchemaValidationError
from .schema_logger import SchemaLogger

__all__ = [
    "SchemaLogger",
    "SchemaValidationError",
    "DataValidationError",
]
