"""Helper functions for tests."""

from __future__ import annotations

import json
from pathlib import Path

from logging_objects_with_schema.schema_loader import _SCHEMA_FILE_NAME


def _write_schema(tmp_path: Path, data: dict) -> None:
    """Write schema file to temporary directory.

    Args:
        tmp_path: Temporary directory path.
        data: Schema data to write as JSON.
    """
    schema_path = tmp_path / _SCHEMA_FILE_NAME
    schema_path.write_text(json.dumps(data), encoding="utf-8")
