"""Logger subclass that applies a JSON schema to extra fields.

This class extends the standard ``logging.Logger`` to validate and filter
user-provided ``extra`` fields according to a compiled JSON schema. It raises
a DataValidationError *after* the log record has been emitted when problems
are detected.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from .errors import DataValidationError, SchemaValidationError
from .schema_applier import _apply_schema_internal
from .schema_loader import CompiledSchema, _compile_schema_internal


class SchemaLogger(logging.Logger):
    """Logger subclass that enforces schema on extra fields.

    This class extends :class:`logging.Logger` to add validation for
    ``extra`` fields according to a compiled JSON schema. It is designed
    to be used as a drop-in replacement via :func:`logging.setLoggerClass`.

    The schema is loaded from ``logging_objects_with_schema.json`` in the
    application root directory during initialization. If the schema cannot
    be loaded or validated, a :class:`SchemaValidationError` is raised.

    Example:
        >>> import logging
        >>> from logging_objects_with_schema import SchemaLogger
        >>> logging.setLoggerClass(SchemaLogger)
        >>> logger = logging.getLogger("my_service")
        >>> logger.info("request processed", extra={"request_id": "abc-123"})
    """

    def __init__(self, name: str, level: int = logging.NOTSET) -> None:
        """Initialise the schema-aware logger.

        The schema is compiled once during construction. If any
        problems are detected in the schema, a SchemaValidationError
        will be raised and this logger instance is not usable.

        Args:
            name: Logger name (same as :class:`logging.Logger`).
            level: Logger level (same as :class:`logging.Logger`).
        """
        super().__init__(name, level)

        try:
            compiled, problems = _compile_schema_internal()
        except Exception:
            # Ensure that a partially initialised logger instance is not left
            # registered in the logging manager if schema compilation fails.
            # Otherwise, subsequent logging.getLogger(name) calls could return
            # this broken instance and lead to AttributeError at runtime.
            self.manager.loggerDict.pop(self.name, None)
            raise

        if problems:
            # Schema is invalid; remove this instance from the logging manager
            # cache before raising, for the same reason as above.
            self.manager.loggerDict.pop(self.name, None)
            raise SchemaValidationError("Schema has problems", problems=problems)

        self._schema: CompiledSchema = compiled

    def _log(
        self,
        level: int,
        msg: object,
        args: tuple[object, ...] | Mapping[str, object],
        exc_info: Any = None,
        extra: Mapping[str, object] | None = None,
        stack_info: bool = False,
        stacklevel: int = 1,
    ) -> None:
        """Log a message with the specified level and schema-validated extra.

        This method validates and filters the ``extra`` parameter according
        to the compiled schema before delegating to the parent class.

        Args:
            level: Logging level.
            msg: Message format string.
            args: Arguments for message formatting.
            exc_info: Exception information.
            extra: Extra fields to include in the log record.
            stack_info: Whether to include stack information.
            stacklevel: Stack level for caller information.

        Raises:
            DataValidationError: If the ``extra`` data does not match the schema.
        """
        structured_extra, data_problems = _apply_schema_internal(
            self._schema,
            extra or {},
        )

        super()._log(
            level,
            msg,
            args,
            exc_info=exc_info,
            extra=structured_extra,
            stack_info=stack_info,
            # Increment stacklevel to account for this override frame so that
            # caller information points to user code instead of SchemaLogger._log.
            stacklevel=stacklevel + 1,
        )

        if data_problems:
            raise DataValidationError(
                "Log data does not match schema",
                problems=data_problems,
            )
