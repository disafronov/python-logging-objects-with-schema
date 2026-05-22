"""Logger subclass that applies a JSON schema to extra fields.

This class extends the standard ``logging.Logger`` to validate and filter
user-provided ``extra`` fields according to a compiled JSON schema. When
validation problems are detected, they are logged as ERROR messages *after*
the log record has been emitted, ensuring 100% compatibility with standard
logger behavior.
"""

import json
import logging
import os
import sys
from collections.abc import Mapping
from typing import Any

from .errors import _SchemaProblem
from .schema_applier import _apply_schema_internal
from .schema_loader import _compile_schema_internal, _CompiledSchema


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
    problem_messages = [problem.message for problem in problems]
    error_msg = f"Schema has problems: {'; '.join(problem_messages)}\n"
    sys.stderr.write(error_msg)
    sys.stderr.flush()
    # os._exit skips atexit/finally — prevents cleanup code from touching a
    # broken logger that was never fully registered.
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
                Note: None and empty set() are semantically equivalent - both
                mean "no additional forbidden keys" and produce the same result.
        """
        # Compile before super().__init__() to avoid registering a broken logger
        # in logging's manager cache.
        try:
            compiled, problems = _compile_schema_internal(forbidden_keys)
        except (OSError, ValueError, RuntimeError) as exc:
            # OSError: os.getcwd() failed (inaccessible CWD). File-level OSError is
            # already converted to _SchemaProblem inside _load_raw_schema and won't
            # reach here. ValueError: path resolution. RuntimeError: lock failure.
            problems = [_SchemaProblem(f"Schema compilation failed: {exc}")]
            compiled = _CompiledSchema(leaves=[])

        if problems:
            _log_schema_problems_and_exit(problems)

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

        # Emit user's message first — validation errors follow as separate ERRORs.
        super()._log(
            level,
            msg,
            args,
            exc_info=exc_info,
            extra=structured_extra,
            stack_info=stack_info,
            stacklevel=stacklevel + 1,  # +1 skips this override frame
        )

        if data_problems:
            # stack_info=False: stack trace already attached to the main record above.
            fn, lno, func, sinfo = self.findCaller(
                stack_info=False, stacklevel=stacklevel + 1
            )
            validation_errors = [problem.data for problem in data_problems]

            try:
                error_msg = json.dumps({"validation_errors": validation_errors})
            except (TypeError, ValueError) as exc:
                # Should never happen: repr() in _create_validation_error_dict
                # guarantees all values are JSON-serializable strings.
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
                self.handle(error_record)
            except Exception:
                sys.stderr.write(f"Error in logging handler: {error_record}\n")
