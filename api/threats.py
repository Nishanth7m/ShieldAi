"""
/threats endpoint.

Returns a recent feed of blocked threats for the dashboard.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request

from config import Settings
from database.operations import get_recent_threats


router = APIRouter()


def _settings(request: Request) -> Settings:
    """Get Settings from app state."""

    s = getattr(request.app.state, "settings", None)
    if s is None:
        raise RuntimeError("App settings not initialized.")
    return s


@router.get("/threats")
def threats(request: Request, limit: int = Query(25, ge=1, le=200)) -> dict[str, Any]:
    """Return recent blocked threats."""

    settings = _settings(request)
    items = get_recent_threats(settings, limit=limit)
    return {"items": items, "count": len(items)}

