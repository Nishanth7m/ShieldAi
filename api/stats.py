"""
/stats endpoint.

Provides aggregated statistics for the dashboard:
- total scans
- total attacks blocked
- attack type breakdown and percentages
- detection accuracy metrics from feedback (if provided)
- recent timeline
- basic system health info
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from config import Settings
from database.operations import get_stats


router = APIRouter()


def _settings(request: Request) -> Settings:
    """Get Settings from app state."""

    s = getattr(request.app.state, "settings", None)
    if s is None:
        raise RuntimeError("App settings not initialized.")
    return s


@router.get("/stats")
def stats(request: Request) -> dict[str, Any]:
    """Return system stats for dashboards and analytics."""

    settings = _settings(request)
    s = get_stats(settings)
    total_scans = int(s.get("total_scans", 0))
    total_blocked = int(s.get("total_attacks_blocked", 0))
    safety_score = 100.0
    if total_scans > 0:
        safety_score = max(0.0, min(100.0, (1.0 - (total_blocked / total_scans)) * 100.0))

    health = {
        "status": "ONLINE",
        "anthropic_enabled": bool(settings.anthropic_api_key),
        "db_path": settings.database_path,
    }

    return {
        "totals": {
            "total_scans": total_scans,
            "total_attacks_blocked": total_blocked,
            "safety_score_percent": round(safety_score, 2),
            "active_agents": 4,
        },
        "breakdown": {
            "attacks_by_type": s.get("attacks_by_type", {}),
            "attacks_by_type_percent": s.get("attacks_by_type_percent", {}),
        },
        "timeline": s.get("timeline", []),
        "accuracy": {
            "feedback_total": s.get("feedback_total", 0),
            "detection_accuracy": s.get("detection_accuracy", None),
        },
        "system": {
            "health": health,
            "last_updated": s.get("last_updated"),
        },
    }

