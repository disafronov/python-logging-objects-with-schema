"""Logger subclass that applies a JSON schema to extra fields.

This class extends the standard ``logging.Logger`` to validate and filter
user-provided ``extra`` fields according to a compiled JSON schema. When
validation problems are detected, they are logged as ERROR messages *after*
the log record has been emitted, ensuring 100% compatibility with standard
logger behavior.
"""

from __future__ import annotations

import inspect
import logging
import sys
from collections.abc import Mapping
from typing import Any

from .errors import SchemaValidationError
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
        except (OSError, ValueError, RuntimeError):
            # Catch specific exceptions that can occur during schema compilation:
            # - OSError: system-level file system issues (e.g., os.getcwd() failures
            #   when the current working directory is inaccessible or deleted).
            #   Note: OSError that occurs when reading the schema file (e.g., permission
            #   denied, I/O errors) is converted to SchemaValidationError in
            #   _load_raw_schema() and does not reach this exception handler.
            # - ValueError: path resolution issues (e.g., invalid path characters,
            #   malformed paths during schema file discovery)
            # - RuntimeError: threading issues (e.g., lock acquisition problems)
            # Note: JSON parsing and schema structure validation errors are
            # converted to SchemaProblem instances and do not raise ValueError here.
            # Note: System exceptions (KeyboardInterrupt, SystemExit) are not
            # caught, which is the correct behavior.
            # Ensure that a partially initialised logger instance is not left
            # registered in the logging manager if schema compilation fails.
            # Otherwise, subsequent logging.getLogger(name) calls could return
            # this broken instance and lead to AttributeError at runtime.
            self._cleanup_failed_logger()
            raise

        if problems:
            # Schema is invalid; remove this instance from the logging manager
            # cache before raising, for the same reason as above.
            self._cleanup_failed_logger()
            raise SchemaValidationError("Schema has problems", problems=problems)

        self._schema: CompiledSchema = compiled

    def _cleanup_failed_logger(self) -> None:
        """Remove this logger instance from the logging manager.

        Called when schema compilation fails to prevent broken logger
        instances from being cached and reused.
        """
        self.manager.loggerDict.pop(self.name, None)

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
        to the compiled schema before delegating to the parent class. If
        validation problems are detected, they are logged as ERROR messages
        after the main log record has been emitted, ensuring compatibility
        with standard logger behavior (no exceptions are raised).

        Args:
            level: Logging level.
            msg: Message format string.
            args: Arguments for message formatting.
            exc_info: Exception information.
            extra: Extra fields to include in the log record.
            stack_info: Whether to include stack information.
            stacklevel: Stack level for caller information.
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
            # Log validation errors as ERROR messages
            # Get caller information using inspect.stack() to ensure consistent behavior
            # across different Python versions. The stack looks like:
            # - Frame 0: this function (_log)
            # - Frame 1: logger.info() wrapper
            # - Frame 2: actual caller (test_function)
            # We need to skip frame 0 (this function) and frame 1 (logger.info wrapper),
            # so we use stacklevel + 1 to get to the actual caller.
            stack = inspect.stack()
            frame_idx = (
                stacklevel + 1
            )  # Skip this function (0) + logger.info wrapper (1)
            if frame_idx < len(stack):
                frame = stack[frame_idx]
                fn = frame.filename
                lno = frame.lineno
                func = frame.function
                sinfo = None
            else:
                # Fallback to findCaller if stack is shorter than expected
                fn, lno, func, sinfo = self.findCaller(
                    stack_info=False, stacklevel=stacklevel + 1
                )
            # Format error message with details of all problems
            problem_messages = [problem.message for problem in data_problems]
            error_msg = f"Log data does not match schema: {'; '.join(problem_messages)}"
            error_record = self.makeRecord(
                self.name,
                logging.ERROR,
                fn,
                lno,
                error_msg,
                (),
                None,  # exc_info - not needed
                func,  # func - function name from findCaller
                None,  # extra - not needed
                sinfo,  # sinfo - stack info from findCaller
            )
            try:
                self.callHandlers(error_record)
            except Exception:
                # If handler failed, log error to stderr (standard logging behavior)
                sys.stderr.write(f"Error in logging handler: {error_record}\n")
