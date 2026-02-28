"""
/analyze endpoint.

Accepts a prompt and optional context, runs ShieldAI orchestrator, and logs the
result to the SQLite database. Includes a simple per-IP rate limit.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Deque, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from agents.orchestrator import Orchestrator
from config import Settings
from database.operations import insert_attack


router = APIRouter()


class AnalyzeRequest(BaseModel):
    """Request body for /analyze."""

    text: str = Field(..., min_length=1, description="Prompt text to analyze.")
    context: str | None = Field(None, description="Optional surrounding context.")


class AnalyzeResponse(BaseModel):
    """Response body for /analyze."""

    attack_id: int
    result: dict[str, Any]


def get_client_ip(request: Request) -> str:
    """Extract client IP from request headers or connection info."""

    xff = request.headers.get("x-forwarded-for")
    if xff:
        # Use first hop.
        return xff.split(",")[0].strip()
    client = request.client
    return client.host if client else "unknown"


class InMemoryRateLimiter:
    """Simple sliding-window rate limiter (per key) with thread safety."""

    def __init__(self, *, limit: int, window_seconds: int = 3600) -> None:
        self.limit = int(limit)
        self.window = int(window_seconds)
        self._lock = threading.Lock()
        self._hits: dict[str, Deque[float]] = {}

    def check(self, key: str) -> None:
        """Raise HTTPException if the key exceeded the rate limit."""

        now = time.time()
        with self._lock:
            dq = self._hits.get(key)
            if dq is None:
                dq = deque()
                self._hits[key] = dq

            # Drop hits outside the window.
            cutoff = now - self.window
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= self.limit:
                raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")

            dq.append(now)


def _settings(request: Request) -> Settings:
    """Get Settings from app state."""

    s = getattr(request.app.state, "settings", None)
    if s is None:
        raise RuntimeError("App settings not initialized.")
    return s


def _orchestrator(request: Request) -> Orchestrator:
    """Get Orchestrator from app state."""

    o = getattr(request.app.state, "orchestrator", None)
    if o is None:
        raise RuntimeError("Orchestrator not initialized.")
    return o


def _rate_limiter(request: Request) -> InMemoryRateLimiter:
    """Get the RateLimiter from app state."""

    rl = getattr(request.app.state, "rate_limiter", None)
    if rl is None:
        raise RuntimeError("Rate limiter not initialized.")
    return rl


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest, request: Request, test_mode: bool = False) -> AnalyzeResponse:
    """
    Analyze a prompt with ShieldAI.

    Validations:
    - max prompt length enforced by settings (default 10,000)
    - rate-limited to RATE_LIMIT per hour (default 100)
    """

    settings = _settings(request)
    ip = get_client_ip(request)

    text = (req.text or "").strip()
    if len(text) > settings.max_prompt_length:
        raise HTTPException(status_code=413, detail=f"Prompt too large (max {settings.max_prompt_length} chars).")

    # Rate-limit only after basic validation to avoid penalizing rejected requests.
    _rate_limiter(request).check(ip)

    orch = _orchestrator(request)
    result = await orch.analyze(text=text, context=req.context, ip_address=ip)

    attack_id = 0
    if not test_mode:
        # Persist to DB.
        details = result.get("details", {})
        pattern_matches = ((details.get("pattern") or {}).get("matches")) or []
        semantic_result = details.get("semantic") or None
        anomaly_score = ((details.get("anomaly") or {}).get("anomaly_score"))

        attack_id = insert_attack(
            settings,
            prompt=text,
            context=req.context,
            attack_type=str(result.get("attack_type", "benign")),
            confidence=float(result.get("confidence", 0.0)),
            pattern_matches=pattern_matches,
            semantic_result=semantic_result if isinstance(semantic_result, dict) else None,
            anomaly_score=float(anomaly_score) if anomaly_score is not None else None,
            final_verdict=str(result.get("final_verdict", "ALLOW")),
            blocked=bool(result.get("blocked", False)),
            ip_address=ip,
        )

    return AnalyzeResponse(attack_id=attack_id, result=result)

