"""
Database schema helpers.

The schema itself is created in `database/connection.py` on initialization.
This module provides small helper functions for serialization of complex fields
and for validating data shapes written into the database.
"""

from __future__ import annotations

import json
from typing import Any


def dumps_json(value: Any) -> str:
    """Serialize a Python object to compact JSON for storage."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def loads_json(text: str | None) -> Any:
    """Deserialize JSON from the database; returns None for NULL/empty."""

    if not text:
        return None
    return json.loads(text)

