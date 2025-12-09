# python-logging-objects-with-schema

This library provides a logger subclass built on top of the standard `logging`
module that strictly controls additional `extra` fields using a JSON schema.
`SchemaLogger` is a drop-in replacement for `logging.Logger` that validates
`extra` fields against a JSON schema file (`logging_objects_with_schema.json`)
in your application root directory.

## Schema as a contract

The JSON schema is treated as a **contract** between all parties that produce
and consume logs in the system. The schema file (`logging_objects_with_schema.json`)
is a shared, versioned artifact that defines which structured fields are allowed
to appear in logs and which Python types they must have. This contract ensures
that all downstream consumers (search systems, alerts, dashboards, external
systems) can rely on a consistent log structure.

**Strictness guarantees:**

- **`extra` fields never go directly into logs.** They are always projected
  through the schema: values from `extra` are taken by `source` field names
  and placed into the log structure according to the schema paths. Only fields
  explicitly described in the schema (as leaves with `type` and `source`) can
  ever reach your logs. The schema is the only source of truth for which
  `extra` fields are allowed.
- Any `extra` field that is **not** described in the schema is treated as a
  data error: it is dropped from the log output and recorded as a validation
  problem.
- Any mismatch between runtime values and the declared types (wrong types,
  `None` values, disallowed list elements) is also treated as a data error.
- All validation problems are aggregated and logged as a single ERROR message
  **after** the log record has been emitted, ensuring 100% compatibility with
  standard logger behavior (no exceptions are raised).
- Application code must only send `extra` fields that are described in the
  schema and match the declared Python types. Any deviation from the schema
  is considered a contract violation.

## Installation

```bash
pip install logging-objects-with-schema
```

## Basic usage

### Quickstart (complete working example)

First, create a schema file `logging_objects_with_schema.json` in your application root:

```json
{
  "ServicePayload": {
    "RequestID": {"type": "str", "source": "request_id"},
    "UserID": {"type": "int", "source": "user_id"}
  }
}
```

Then, set up and use the logger:

```python
import logging
import sys

from logging_objects_with_schema import SchemaLogger


# Set SchemaLogger as the default logger class
logging.setLoggerClass(SchemaLogger)

# Configure handlers and formatters as usual
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(message)s %(ServicePayload)s"))

# Get loggers using standard logging API
logger = logging.getLogger("service")
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# Use the logger - extra fields are validated against the schema
logger.info("request processed", extra={"request_id": "abc-123", "user_id": 42})
```

### Example with nested structures

Schema with nested structure:

```json
{
  "ServicePayload": {
    "RequestID": {"type": "str", "source": "request_id"},
    "UserID": {"type": "int", "source": "user_id"},
    "Metrics": {
      "CPU": {"type": "float", "source": "cpu_usage"},
      "Memory": {"type": "float", "source": "memory_usage"},
      "Network": {
        "In": {"type": "int", "source": "network_in"},
        "Out": {"type": "int", "source": "network_out"}
      }
    }
  }
}
```

Usage:

```python
logger.info(
    "metrics collected",
    extra={
        "request_id": "req-123",
        "user_id": 42,
        "cpu_usage": 75.5,
        "memory_usage": 60.2,
        "network_in": 1024,
        "network_out": 2048,
    }
)
```

### Error handling example

```python
from logging_objects_with_schema import SchemaLogger

# SchemaLogger is a drop-in replacement - no exception handling needed.
# If the schema has problems, the application will be terminated after
# logging schema problems to stderr.
logging.setLoggerClass(SchemaLogger)
logger = logging.getLogger("service")

# When logging with invalid data, validation errors are automatically
# logged as ERROR messages. No exception handling is needed.
logger.info("processing", extra={"user_id": "not-an-int"})  # Wrong type
# The valid part of the log is emitted, and validation errors are logged
# as ERROR messages in JSON format: {"validation_errors": [{"field": "...", "error": "...", "value": "..."}]}
```

## Schema location and format

The schema file `logging_objects_with_schema.json` must be located in your
application root directory. The library searches upward from the current working
directory until it finds the file or reaches the filesystem root.

**Important**: If there are any problems with the schema (missing file, broken
JSON, invalid structure, etc.), the application is terminated after logging
schema problems to stderr. Schema validation happens when the first logger
instance is created.

**Note**: The schema is compiled once per process and cached. Schema changes
require an application restart to take effect. The library is thread-safe.

A valid empty schema (`{}`) is allowed and will result in no `extra` fields
being included in log records.

An example schema:

```json
{
  "ServicePayload": {
    "RequestID": {"type": "str", "source": "request_id"},
    "UserID": {"type": "int", "source": "user_id"},
    "Metrics": {
      "CPU": {"type": "float", "source": "cpu_usage"},
      "Memory": {"type": "float", "source": "memory_usage"},
      "Network": {
        "In": {"type": "int", "source": "network_in"},
        "Out": {"type": "int", "source": "network_out"}
      }
    }
  }
}
```

An example of a valid empty schema (no leaves, no problems):

```json
{}
```

**Schema structure:**

- **Inner nodes**: Objects without `type` and `source` fields (used for nesting).
- **Leaf nodes**: Objects with both `type` and `source` fields. A valid leaf
  must have both fields present and non-empty.
- **`type`**: One of `"str"`, `"int"`, `"float"`, `"bool"`, or `"list"`.
- **`source`**: The name of the field in `extra` from which the value is taken.
- **Root key restrictions**: Root keys cannot conflict with standard `logging`
  module fields (e.g., `name`, `levelno`, `pathname`). Such conflicts cause
  schema validation to fail.

**List-typed fields:**

For `"type": "list"`, you must also specify `"item_type"` (one of `"str"`,
`"int"`, `"float"`, `"bool"`). Lists must contain homogeneous primitive elements
of the declared type. Empty lists are allowed; nested lists and dictionaries are
not permitted.

Example of a valid list field:

```json
{
  "ServicePayload": {
    "Tags": {
      "type": "list",
      "source": "tags",
      "item_type": "str"
    }
  }
}
```

Usage:

```python
logger.info(
    "request processed",
    extra={
        "tags": ["blue", "fast", "cached"],  # list[str] – valid
    },
)
```

Invalid example (non-primitive elements are rejected):

```python
logger.info("request processed", extra={"tags": [{"key": "color"}]})  # Invalid
# Validation error is logged as ERROR after the log record is emitted
```

**Multiple leaves with the same source:**

A single `source` field name can be used in multiple leaves. The value is
validated independently for each leaf and written to all matching locations.
If types conflict, the value is written only where the type matches, and
validation errors are reported for mismatched locations.

Example:

```json
{
  "ServicePayload": {
    "RequestID": {"type": "str", "source": "request_id"},
    "Metadata": {
      "ID": {"type": "str", "source": "request_id"}
    }
  }
}
```

With `extra={"request_id": "abc-123"}`, the value appears in both
`ServicePayload.RequestID` and `ServicePayload.Metadata.ID`.

## Inheritance and custom forbidden root keys

`SchemaLogger` supports inheritance, allowing subclasses to add additional
forbidden root keys for schema validation. This is useful when you need to
prevent certain root keys from being used in your schema beyond the builtin
`logging.LogRecord` attributes.

### Basic inheritance

Each subclass can pass the `forbidden_keys` parameter to the parent's
`__init__()` method. The builtin set of forbidden keys (standard `logging.LogRecord`
attributes) is always present and cannot be replaced - additional keys are
merged with the builtin set.

Example:

```python
from logging_objects_with_schema import SchemaLogger
import logging

class MyLogger(SchemaLogger):
    def __init__(self, name: str, level: int = logging.NOTSET) -> None:
        # Add custom forbidden keys
        super().__init__(name, level, forbidden_keys={"custom_forbidden_key"})
```

### Multi-level inheritance

When creating a hierarchy of loggers, each subclass can pass `forbidden_keys`
from its own subclasses to the parent, merging them with its own set. The
library does not automatically propagate keys up the inheritance chain - each
subclass must implement this logic itself.

Example:

```python
from logging_objects_with_schema import SchemaLogger
import logging

class ParentLogger(SchemaLogger):
    def __init__(
        self, name: str, level: int = logging.NOTSET, forbidden_keys: set[str] | None = None
    ) -> None:
        # Merge parent's keys with keys from child
        parent_keys = {"parent_forbidden_key"}
        if forbidden_keys:
            parent_keys = parent_keys | forbidden_keys
        super().__init__(name, level, forbidden_keys=parent_keys)

class ChildLogger(ParentLogger):
    def __init__(self, name: str, level: int = logging.NOTSET) -> None:
        # Pass child's keys to parent, which will merge them
        super().__init__(name, level, forbidden_keys={"child_forbidden_key"})
```

In this example, the final set of forbidden keys will be:

- Builtin `logging.LogRecord` attributes (always present)
- `parent_forbidden_key` (from `ParentLogger`)
- `child_forbidden_key` (from `ChildLogger`)

All keys are merged together - they are not replaced, only supplemented.

### Important notes

- The builtin set of forbidden keys (standard `logging.LogRecord` attributes)
  is always present and cannot be replaced or removed
- Additional forbidden keys are merged with the builtin set, not replaced
- Each subclass must implement the logic to pass `forbidden_keys` to its parent
  if it wants to propagate keys from its own subclasses
- The `forbidden_keys` parameter is optional - if not provided, only builtin
  keys are used, maintaining 100% backward compatibility
- `None` and empty `set()` are semantically equivalent for `forbidden_keys` -
  both mean "no additional forbidden keys" and produce the same result
