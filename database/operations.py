"""
CRUD operations and statistics aggregation for ShieldAI.

This module centralizes all SQL statements so the rest of the app can remain
focused on detection logic and API concerns.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from config import Settings
from database.connection import get_connection
from database.models import dumps_json, loads_json


def utc_now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""

    return datetime.now(timezone.utc).isoformat()


def sha256_text(text: str) -> str:
    """Hash text using SHA-256 for safe identifiers and caching keys."""

    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def insert_attack(
    settings: Settings,
    *,
    prompt: str,
    context: str | None,
    attack_type: str,
    confidence: float,
    pattern_matches: list[dict[str, Any]] | None,
    semantic_result: dict[str, Any] | None,
    anomaly_score: float | None,
    final_verdict: str,
    blocked: bool,
    ip_address: str | None,
) -> int:
    """
    Insert an attack scan result row and update global stats.

    Returns the new row ID.
    """

    timestamp = utc_now_iso()
    pattern_json = dumps_json(pattern_matches) if pattern_matches is not None else None
    semantic_json = dumps_json(semantic_result) if semantic_result is not None else None

    with get_connection(settings) as conn:
        conn.execute("BEGIN;")
        try:
            cur = conn.execute(
                """
                INSERT INTO attacks (
                    prompt, context, attack_type, confidence,
                    pattern_matches, semantic_result, anomaly_score,
                    final_verdict, blocked, timestamp, ip_address
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    prompt,
                    context,
                    attack_type,
                    float(confidence),
                    pattern_json,
                    semantic_json,
                    float(anomaly_score) if anomaly_score is not None else None,
                    final_verdict,
                    1 if blocked else 0,
                    timestamp,
                    ip_address,
                ),
            )
            attack_id = int(cur.lastrowid)

            # Update stats table (single-row id=1).
            stats = conn.execute("SELECT * FROM stats WHERE id = 1;").fetchone()
            attacks_by_type = loads_json(stats["attacks_by_type"]) or {}
            daily_stats = loads_json(stats["daily_stats"]) or {}

            total_scans = int(stats["total_scans"]) + 1
            total_blocked = int(stats["total_attacks_blocked"]) + (1 if blocked else 0)

            attacks_by_type[attack_type] = int(attacks_by_type.get(attack_type, 0)) + (1 if blocked else 0)

            day_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            day_obj = daily_stats.get(day_key, {"scans": 0, "blocked": 0, "by_type": {}})
            day_obj["scans"] = int(day_obj.get("scans", 0)) + 1
            day_obj["blocked"] = int(day_obj.get("blocked", 0)) + (1 if blocked else 0)
            by_type = day_obj.get("by_type", {})
            by_type[attack_type] = int(by_type.get(attack_type, 0)) + (1 if blocked else 0)
            day_obj["by_type"] = by_type
            daily_stats[day_key] = day_obj

            # Keep only the last 30 days to prevent unbounded growth.
            if len(daily_stats) > 60:
                keys_sorted = sorted(daily_stats.keys())
                for k in keys_sorted[:-30]:
                    daily_stats.pop(k, None)

            conn.execute(
                """
                UPDATE stats
                SET total_scans = ?,
                    total_attacks_blocked = ?,
                    attacks_by_type = ?,
                    daily_stats = ?,
                    last_updated = datetime('now')
                WHERE id = 1;
                """,
                (total_scans, total_blocked, dumps_json(attacks_by_type), dumps_json(daily_stats)),
            )

            conn.execute("COMMIT;")
            return attack_id
        except Exception:
            conn.execute("ROLLBACK;")
            raise


def get_recent_threats(settings: Settings, *, limit: int = 25) -> list[dict[str, Any]]:
    """Return recent blocked threats for the dashboard feed."""

    limit = max(1, min(int(limit), 200))
    with get_connection(settings) as conn:
        rows = conn.execute(
            """
            SELECT id, attack_type, confidence, final_verdict, blocked, timestamp, ip_address
            FROM attacks
            WHERE blocked = 1
            ORDER BY id DESC
            LIMIT ?;
            """,
            (limit,),
        ).fetchall()
        return [
            {
                "id": int(r["id"]),
                "attack_type": r["attack_type"],
                "confidence": float(r["confidence"]),
                "verdict": r["final_verdict"],
                "blocked": bool(r["blocked"]),
                "timestamp": r["timestamp"],
                "ip_address": r["ip_address"],
            }
            for r in rows
        ]


def get_stats(settings: Settings) -> dict[str, Any]:
    """
    Return aggregate statistics for the dashboard and API.

    Includes:
    - total scans, total blocked
    - attacks by type + percentages
    - recent timeline from `daily_stats`
    - basic accuracy metrics from feedback table
    """

    with get_connection(settings) as conn:
        stats = conn.execute("SELECT * FROM stats WHERE id = 1;").fetchone()
        total_scans = int(stats["total_scans"])
        total_blocked = int(stats["total_attacks_blocked"])
        attacks_by_type = loads_json(stats["attacks_by_type"]) or {}
        daily_stats = loads_json(stats["daily_stats"]) or {}

        # Accuracy metrics from feedback:
        fb = conn.execute("SELECT was_correct, correct_label FROM feedback;").fetchall()
        feedback_total = len(fb)
        feedback_correct = sum(1 for r in fb if int(r["was_correct"]) == 1)
        accuracy = (feedback_correct / feedback_total) if feedback_total else None

        # Normalize type breakdown (percentages out of blocked attacks).
        type_counts = {k: int(v) for k, v in attacks_by_type.items()}
        denom = max(1, sum(type_counts.values()))
        type_percent = {k: round((v / denom) * 100.0, 2) for k, v in type_counts.items()}

        # Timeline arrays
        days_sorted = sorted(daily_stats.keys())
        timeline = [
            {
                "day": d,
                "scans": int(daily_stats[d].get("scans", 0)),
                "blocked": int(daily_stats[d].get("blocked", 0)),
            }
            for d in days_sorted
        ]

        return {
            "total_scans": total_scans,
            "total_attacks_blocked": total_blocked,
            "attacks_by_type": type_counts,
            "attacks_by_type_percent": type_percent,
            "timeline": timeline,
            "feedback_total": feedback_total,
            "detection_accuracy": accuracy,
            "last_updated": stats["last_updated"],
        }


def add_feedback(
    settings: Settings,
    *,
    prompt_id: int,
    was_correct: bool,
    correct_label: str | None,
) -> int:
    """Insert a feedback record for a previous scan result."""

    with get_connection(settings) as conn:
        cur = conn.execute(
            """
            INSERT INTO feedback (prompt_id, was_correct, correct_label, feedback_at)
            VALUES (?, ?, ?, datetime('now'));
            """,
            (int(prompt_id), 1 if was_correct else 0, correct_label),
        )
        return int(cur.lastrowid)

