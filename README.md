# python-logging-objects-with-schema

This library provides a logger subclass built on top of the standard `logging`
module that strictly controls additional `extra` fields using a JSON schema.

## Core idea

- The standard `logging` package is used (your application configures handlers
  and formatting as usual).
- `SchemaLogger` is a subclass of `logging.Logger` designed to be used as a
  drop-in replacement via `logging.setLoggerClass(SchemaLogger)`.
- The schema is stored in a JSON file named `logging_objects_with_schema.json`
  in the application root directory.
- Any user-provided `extra` fields are included in the log **only if** they are
  described in the schema and match the declared Python type.
- The library is universal and works with any formatters from the standard
  `logging` module. It is not tied to any specific log format or logging library.

## Schema as a contract

The JSON schema is treated as a **contract** between all parties that produce
and consume logs in the system. It defines which structured fields are allowed
to appear in logs and which types they must have.

- Application code must only send `extra` fields that are described in the schema
  and match the declared Python types. Any deviation (unknown fields, wrong types,
  `None` values, disallowed list elements) is logged as an ERROR message
  *after* the log record has been emitted.
- The schema file (`logging_objects_with_schema.json`) is a shared, versioned
  artifact that defines the shape of structured log payloads for all downstream
  consumers (search, alerts, dashboards, external systems).

## Strictness guarantees

- Only fields explicitly described in the JSON schema (as leaves with `type` and
  `source`) can ever reach your logs.
- Any `extra` field that is **not** described in the schema is treated as a data
  error: it is dropped from the log output and recorded as a validation problem.
- Any mismatch between runtime values and the declared types is also treated as
  a data error.
- All validation problems (unknown fields, wrong types, disallowed list
  elements, `None` values, etc.) are aggregated and logged as a single
  ERROR message **after** the log record has been emitted, ensuring 100%
  compatibility with standard logger behavior (no exceptions are raised).
- The schema is treated as the only source of truth for which `extra` fields
  are allowed to appear in logs. Any deviation from the schema is considered a
  contract violation between the producer of `extra` and the schema author.

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
# as ERROR messages with details about the problems.
```

### API compatibility with ``logging.Logger``

- ``SchemaLogger`` is a subclass of ``logging.Logger`` and can be used as a
  drop-in replacement via ``logging.setLoggerClass(SchemaLogger)``.
- The public methods of ``SchemaLogger`` mirror the standard ``logging.Logger``
  API and accept the same arguments: ``msg, *args, **kwargs``.
- The only behavioural difference is that the named ``extra`` argument is
  intercepted, validated according to the JSON schema, and only the validated
  subset is passed further into the standard logging pipeline.

## Schema location and format

- Schema file: `logging_objects_with_schema.json`.
- Location: **application root directory**. The library searches upward from the
  current working directory for the schema file itself, walking up the directory
  tree until it finds the file or reaches the filesystem root.
- Schema tree depth is limited to a maximum nesting level (currently 100). Any
  branch that exceeds this depth is ignored and reported as a schema problem.

  If the schema file is not found, or cannot be read/parsed/validated, the
  logger instance is not created, schema problems are logged to stderr, and
  the application is terminated via `os._exit(1)`. The error message contains
  a detailed description of all issues, including the path where the file was
  expected (based on the current working directory at schema discovery time).

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

- An inner node is an object without `type` and `source`.
- A leaf node is an object with both `type` and `source`.
- `type` is one of the allowed Python type names: `"str"`, `"int"`, `"float"`,
  `"bool"`, or `"list"`.
- For `"list"` type, an additional `item_type` field is required to declare
  the element type. Only primitive element types (`"str"`, `"int"`, `"float"`,
  `"bool"`) are allowed. Nested lists and dictionaries are not permitted as
  list elements.
- `source` is the name of the field in `extra` from which the value is taken.

### List-typed fields

When a leaf declares `"type": "list"`, the runtime value must be a Python list
with **homogeneous primitive elements**. The element type is defined by the
mandatory `item_type` field:

- Allowed `item_type` values: `"str"`, `"int"`, `"float"`, `"bool"`
- All elements in the list must have exactly the declared Python type
  (e.g. `type(item) is int` for `"item_type": "int"`)
- Empty lists are allowed
- Nested lists and dictionaries inside the list are not allowed

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

Example of an invalid list field (non-primitive elements):

```python
logger.info(
    "request processed",
    extra={
        "tags": [{"key": "color", "value": "blue"}],  # list[dict] – invalid
    },
)
```

In this case the `tags` value is rejected, a `DataProblem` is recorded with a
message similar to:

> Field 'tags' is a list but contains elements with types [...]; expected all elements to be of type str

and an ERROR message is logged **after** the log record has been emitted.

### Multiple leaves with the same source

A single `source` field name can be used in multiple leaves of the schema. This
allows the same value from `extra` to be placed in different locations of the
output structure.

When a `source` is referenced by multiple leaves:

- The value is validated against each leaf's expected type independently.
- The value is written only to those leaf locations where the runtime type
  matches the expected type.
- For leaf locations where the type does not match, a `DataProblem` is added
  to the ERROR message that is logged after logging.

Example schema with duplicate source usage:

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

In this example, if `extra={"request_id": "abc-123"}`, the value `"abc-123"`
will be written to both `ServicePayload.RequestID` and `ServicePayload.Metadata.ID`.

If the same `source` is used with conflicting types (e.g., one leaf expects
`str` and another expects `int`), the value will only be written to locations
where the type matches, and validation problems will be reported for the
mismatched locations. It is the schema author's responsibility to ensure
consistent type expectations when reusing a `source` field.

## Behaviour when loading the schema

- When a `SchemaLogger` instance is created (via `logging.getLogger()` after
  `logging.setLoggerClass(SchemaLogger)`), the library:
  - searches for `logging_objects_with_schema.json` by walking upward from
    the current working directory until it finds the file or reaches the
    filesystem root;
  - parses the JSON;
  - walks the entire tree and collects all problems with the schema.
- If there are **any** problems with the schema (missing file, broken JSON,
  invalid `type` values, conflicting root fields that match system logging
  fields, malformed structure, etc.):
  - the logger instance is not created;
  - schema problems are logged to stderr in the format:
    `"Schema has problems: {problem1}; {problem2}; ..."`;
  - the application is terminated via `os._exit(1)`.
- If there are no problems:
  - the schema is compiled into a `CompiledSchema`;
  - the logger is created and starts using this schema to validate `extra`
    fields.

**Note**: System-level errors (OSError, ValueError, RuntimeError) that occur
during schema compilation are converted to `SchemaProblem` instances and
handled the same way as schema validation problems - the application is
terminated after logging the error to stderr.

## Schema caching and thread safety

- The library caches compiled schemas to avoid recompiling the same schema file
  on every logger creation.
- The cache is keyed by the absolute schema file path and stores both the
  compiled schema and any discovered problems. Once a schema (or its absence /
  invalidity) has been observed for a given path, subsequent calls reuse the
  cached result within the same process without re-reading or re-compiling the
  schema file.
- This includes invalid schemas: once a schema file has been found to be
  invalid, the corresponding (typically empty) `CompiledSchema` and its
  `SchemaProblem`s are reused for the lifetime of the process.
- Schema compilation and cache access are **thread-safe**: multiple threads can
  safely create `SchemaLogger` instances concurrently without race conditions.
- The schema is effectively loaded and compiled **once per process** for a
  given schema path. Subsequent logger instances reuse the cached compiled
  schema.
- **Note**: The library does not provide a mechanism to reload the schema
  without restarting the application. This is a deliberate design decision to
  ensure schema consistency throughout the application lifecycle.

## Schema root key restrictions

- The library protects system fields from the standard `logging` module
  (attributes of `LogRecord` and logger internals) by preventing their use as
  root keys in the schema.
- If a root key in the schema conflicts with a system logging field, a
  `SchemaProblem` is generated and the schema validation fails.
- Responsibility for ensuring compatibility with other logging libraries and
  formatters lies with the developer when writing the schema.

## Behaviour when logging data

- Any `extra` provided by the application **never goes directly** into the log.
- The only way for additional fields to reach the log:
  1. The field is described as a leaf in the schema (`type` + `source`).
  2. `extra` contains a value under the given `source` name.
  3. The runtime type of the value strictly matches the declared Python type
     (exact type match is used, e.g. `bool` is not accepted where `int` is
     expected, and vice versa).
- If:
  - the compiled schema has no valid leaves (it is effectively empty, so no
    `extra` keys are ever allowed to contribute data);
  - a field is not described in the schema;
  - the type does not match the declared type;
  - the value is None (None values are not allowed);
  - the field is considered redundant,
  **it is simply not included in the final log record**.

In all of these cases a `DataProblem` is recorded for each offending field, and
if at least one problem is present, a single ERROR message is logged
**after** the log record has been emitted.

- When a `source` is used in multiple leaves (see "Multiple leaves with the same
  source" above), the value is validated and written independently for each leaf
  location.
- Before emitting the final structured payload, the library strips empty
  dictionaries and `None` values from nested structures so that only meaningful
  data appears in the resulting log record.

High-level algorithm inside `SchemaLogger`:

- For every call to `logger.info` / `logger.error` / `logger.log`:
  1. All user-provided fields are taken from `extra`.
  2. A new structured payload is built from the schema and the given `extra`.
  3. Only this structured payload is passed to the underlying stdlib logger.
  4. After logging, if any validation problems were detected, a single
     ERROR message is logged with the full `problems` list (no exception
     is raised, ensuring 100% compatibility with standard logger behavior).

## Error handling

- Schema problems are handled internally: errors are logged to stderr and
  the application is terminated via `os._exit(1)`.
- No exceptions are raised by `SchemaLogger` during initialization, making
  it a true drop-in replacement for `logging.Logger`.
