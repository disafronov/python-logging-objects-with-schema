"""Logger subclass that applies a JSON schema to extra fields.

This class extends the standard ``logging.Logger`` to validate and filter
user-provided ``extra`` fields according to a compiled JSON schema. When
validation problems are detected, they are logged as ERROR messages *after*
the log record has been emitted, ensuring 100% compatibility with standard
logger behavior.
"""

from __future__ import annotations

import inspect
import json
import logging
import os
import sys
from collections.abc import Mapping
from typing import Any

from .errors import _SchemaProblem
from .schema_applier import _apply_schema_internal
from .schema_loader import _compile_schema_internal, _CompiledSchema

# Python 3.11+ has improved findCaller() implementation with proper stacklevel support.
# For Python < 3.11, we use inspect.stack() as a fallback due to known issues with
# findCaller() and stacklevel parameter.
_USE_FINDCALLER = sys.version_info >= (3, 11)


def _log_schema_problems_and_exit(problems: list[_SchemaProblem]) -> None:
    """Log schema problems to stderr and terminate the application.

    Uses os._exit(1) instead of sys.exit(1) to ensure immediate termination
    without running cleanup handlers (atexit, finally blocks, etc.). This is
    important because schema problems indicate a fatal configuration error that
    should stop the application immediately, and we don't want any cleanup code
    to run (which might try to use the broken logger or cause additional errors).

    Args:
        problems: List of schema problems to log.
    """
    # Format error message with details of all problems
    # (same format as data problems)
    problem_messages = [problem.message for problem in problems]
    error_msg = f"Schema has problems: {'; '.join(problem_messages)}\n"
    sys.stderr.write(error_msg)
    sys.stderr.flush()
    # Use os._exit() for immediate termination without cleanup handlers
    os._exit(1)


class SchemaLogger(logging.Logger):
    """Logger subclass that enforces schema on extra fields.

    This class extends :class:`logging.Logger` to add validation for
    ``extra`` fields according to a compiled JSON schema. It is designed
    to be used as a drop-in replacement via :func:`logging.setLoggerClass`.

    The schema is loaded from ``logging_objects_with_schema.json`` in the
    application root directory during initialization. If the schema cannot
    be loaded or validated, the logger instance is not created, schema
    problems are logged to stderr, and the application is terminated.

    Example:
        >>> import logging
        >>> from logging_objects_with_schema import SchemaLogger
        >>> logging.setLoggerClass(SchemaLogger)
        >>> logger = logging.getLogger("my_service")
        >>> logger.info("request processed", extra={"request_id": "abc-123"})
    """

    def __init__(
        self,
        name: str,
        level: int = logging.NOTSET,
        forbidden_keys: set[str] | None = None,
    ) -> None:
        """Initialise the schema-aware logger.

        The schema is compiled once during construction. If any
        problems are detected in the schema, the logger instance is not
        created, schema problems are logged to stderr, and the application
        is terminated.

        Args:
            name: Logger name (same as :class:`logging.Logger`).
            level: Logger level (same as :class:`logging.Logger`).
            forbidden_keys: Additional forbidden root keys to check against.
                These keys are merged with builtin LogRecord attributes.
                Builtin keys cannot be replaced, only supplemented.
                Subclasses can override this method and pass their own
                forbidden keys to the parent, merging them with keys from
                their own subclasses if needed.
        """
        # Validate schema before creating the logger instance to avoid
        # registering a broken logger in the logging manager cache.
        # Schema is compiled and cached first, then problems are checked.
        try:
            compiled, problems = _compile_schema_internal(forbidden_keys)
        except (OSError, ValueError, RuntimeError) as exc:
            # Convert system-level exceptions to _SchemaProblem so they can be
            # handled the same way as schema validation problems.
            # - OSError: system-level file system issues (e.g., os.getcwd() failures
            #   when the current working directory is inaccessible or deleted).
            #   Note: OSError that occurs when reading the schema file (e.g., permission
            #   denied, I/O errors) is converted to _SchemaProblem in _load_raw_schema()
            #   and does not reach this exception handler.
            # - ValueError: path resolution issues (e.g., invalid path characters,
            #   malformed paths during schema file discovery)
            # - RuntimeError: threading issues (e.g., lock acquisition problems)
            # Note: JSON parsing and schema structure validation errors are
            # converted to _SchemaProblem instances and do not raise ValueError here.
            # Note: System exceptions (KeyboardInterrupt, SystemExit) are not
            # caught, which is the correct behavior.
            problems = [_SchemaProblem(f"Schema compilation failed: {exc}")]
            compiled = _CompiledSchema(leaves=[])

        if problems:
            # Schema is invalid; log problems and terminate without creating
            # the logger instance.
            _log_schema_problems_and_exit(problems)

        # Schema is valid; create the logger instance.
        super().__init__(name, level)
        self._schema: _CompiledSchema = compiled

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

        # Emit the main log record first, even if there are validation problems.
        # This ensures 100% compatibility with standard logger behavior: the user's
        # log message is always emitted, and validation errors are reported separately
        # as additional ERROR messages. This approach guarantees that the application
        # continues to work normally even when validation problems occur (no exceptions
        # are raised, no log records are lost).
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

        # If there were validation problems, log them as separate ERROR messages
        # after the main log record has been emitted. This ensures the main message
        # is always logged first, and validation errors are clearly separated.
        if data_problems:
            # Get caller information for the error log record so that validation
            # errors point to the same location in user code as the original log call.
            # Python 3.11+ has improved findCaller() with proper stacklevel support,
            # so we use it as the primary method for better performance.
            # For Python < 3.11, we fall back to inspect.stack() due to known issues
            # with findCaller() and stacklevel parameter.
            if _USE_FINDCALLER:
                # Use findCaller() for Python 3.11+ (more efficient)
                fn, lno, func, sinfo = self.findCaller(
                    stack_info=False, stacklevel=stacklevel + 1
                )
            else:
                # Fallback to inspect.stack() for Python < 3.11
                # The stack looks like:
                # - Frame 0: this function (_log)
                # - Frame 1: logger.info() wrapper
                # - Frame 2: actual caller (test_function)
                # We need to skip frame 0 (this function) and frame 1
                # (logger.info wrapper), so we use stacklevel + 1 to get to
                # the actual caller.
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
            # Format error message as JSON for machine processing.
            # Each _DataProblem.message is already a JSON string (created by
            # _create_validation_error_json) with structure:
            #   {"field": "...", "error": "...", "value": "..."}
            # We parse them back to dicts and combine into a single JSON object
            # with all validation errors. The final structure is:
            #   {"validation_errors": [{"field": "...", "error": "...",
            #   "value": "..."}, ...]}
            # This allows consumers to parse the error message as structured data
            # and programmatically extract field names, error types, and values.
            validation_errors = []
            for problem in data_problems:
                try:
                    # Parse the JSON string back to a dict so we can combine
                    # all errors into a single JSON object. Each error object
                    # maintains the same structure: field, error, value
                    # (all via repr()).
                    error_obj = json.loads(problem.message)
                    validation_errors.append(error_obj)
                except (json.JSONDecodeError, TypeError) as exc:
                    # Defensive handling: if problem.message is not valid JSON,
                    # create a fallback error object. This should never happen in
                    # normal operation since problem.message is always created via
                    # _create_validation_error_json, but protects against unexpected
                    # data corruption or manual _DataProblem creation. The fallback
                    # preserves the same structure (field, error, value) for
                    # consistency.
                    validation_errors.append(
                        {
                            "field": repr("unknown"),
                            "error": repr(f"Failed to parse validation error: {exc}"),
                            "value": repr(problem.message),
                        }
                    )

            try:
                # Combine all validation errors into a single JSON object.
                # The resulting string will be used as the log message for the
                # ERROR record, allowing structured parsing by log consumers.
                error_msg = json.dumps({"validation_errors": validation_errors})
            except (TypeError, ValueError) as exc:
                # Defensive handling: if serialization fails, create a fallback
                # error message. This should never happen in normal operation since
                # validation_errors contains only dicts with primitive values (all
                # values are already serialized via repr()), but protects against
                # unexpected data corruption or edge cases in JSON serialization.
                # The fallback ensures we always have a valid JSON error message.
                error_msg = json.dumps(
                    {
                        "validation_errors": [
                            {
                                "field": repr("unknown"),
                                "error": repr(
                                    f"Failed to serialize validation errors: {exc}"
                                ),
                                "value": repr(
                                    "validation errors could not be serialized"
                                ),
                            }
                        ]
                    }
                )
            error_record = self.makeRecord(
                self.name,
                logging.ERROR,
                fn,
                lno,
                error_msg,
                (),
                None,  # exc_info - not needed
                func,  # func - function name from caller
                None,  # extra - not needed
                sinfo,  # sinfo - stack info from caller
            )
            try:
                self.callHandlers(error_record)
            except Exception:
                # If handler failed, log error to stderr (standard logging behavior)
                sys.stderr.write(f"Error in logging handler: {error_record}\n")
