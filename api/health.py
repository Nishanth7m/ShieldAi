"""
/health endpoint.

Lightweight health check used by dashboards and deployment platforms.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from config import Settings
from database.connection import get_connection


router = APIRouter()


def _settings(request: Request) -> Settings:
    """Get Settings from app state."""

    s = getattr(request.app.state, "settings", None)
    if s is None:
        raise RuntimeError("App settings not initialized.")
    return s


@router.get("/health")
def health(request: Request) -> dict[str, Any]:
    """Return health status."""

    settings = _settings(request)

    db_ok = True
    db_error = None
    try:
        with get_connection(settings) as conn:
            row = conn.execute("SELECT total_scans FROM stats WHERE id = 1;").fetchone()
            _ = int(row["total_scans"]) if row else 0
    except Exception as e:
        db_ok = False
        db_error = str(e)

    return {
        "status": "ONLINE" if db_ok else "DEGRADED",
        "database": {"ok": db_ok, "path": settings.database_path, "error": db_error},
        "anthropic": {"enabled": bool(settings.anthropic_api_key)},
    }

