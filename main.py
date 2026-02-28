from __future__ import annotations

from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

"""
ShieldAI FastAPI application entry point.

Run locally:
  uvicorn main:app --reload --port 8000
"""

from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from agents.orchestrator import Orchestrator
from api.analyze import InMemoryRateLimiter
from api.analyze import router as analyze_router
from api.auth import router as auth_router
from api.health import router as health_router
from api.stats import router as stats_router
from api.threats import router as threats_router
from config import export_attack_patterns_json, get_settings
from database.connection import initialize_database
from models.trainer import train_and_save


def create_app() -> FastAPI:
    """Create and configure the FastAPI app."""

    app = FastAPI(
        title="ShieldAI - Multi-Agent LLM Security Platform",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS enabled for frontend-backend communication (CDN-based static pages).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # API routers
    app.include_router(health_router, prefix="/api", tags=["health"])
    app.include_router(stats_router, prefix="/api", tags=["stats"])
    app.include_router(threats_router, prefix="/api", tags=["threats"])
    app.include_router(analyze_router, prefix="/api", tags=["analyze"])
    app.include_router(auth_router, prefix="/api", tags=["auth"])

    # Static files
    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    def _require_auth(request: Request) -> bool:
        token = request.cookies.get("shieldai_token")
        if not token:
            return False
        try:
            # Import here to avoid import cycles at startup.
            from api.auth import verify_token

            verify_token(request.app.state.settings, token)
            return True
        except Exception:
            return False

    @app.get("/", include_in_schema=False)
    def index(request: Request):
        """Serve the main dashboard."""

        if not _require_auth(request):
            return RedirectResponse(url="/login", status_code=303)
        return FileResponse(str(static_dir / "index.html"))

    @app.get("/scanner", include_in_schema=False)
    def scanner(request: Request):
        """Serve the prompt scanner page."""

        if not _require_auth(request):
            return RedirectResponse(url="/login", status_code=303)
        return FileResponse(str(static_dir / "scanner.html"))

    @app.get("/reports", include_in_schema=False)
    def reports(request: Request):
        """Serve the reports/analytics page."""

        if not _require_auth(request):
            return RedirectResponse(url="/login", status_code=303)
        return FileResponse(str(static_dir / "reports.html"))

    @app.get("/login", include_in_schema=False)
    def login(request: Request):
        """Serve the login page."""

        if _require_auth(request):
            return RedirectResponse(url="/", status_code=303)
        return FileResponse(str(static_dir / "login.html"))

    @app.get("/signup", include_in_schema=False)
    def signup(request: Request):
        """Serve the signup page."""

        if _require_auth(request):
            return RedirectResponse(url="/", status_code=303)
        return FileResponse(str(static_dir / "signup.html"))

    @app.on_event("startup")
    def startup() -> None:
        """Initialize settings, database schema, and optional ML model."""

        try:
            print("=" * 60)
            print("[ShieldAI] Multi-Agent LLM Security Platform")
            print("=" * 60)
            print("Starting up...")
        except Exception:
            # Console encoding issues should not break startup.
            pass

        settings = get_settings()
        app.state.settings = settings

        # Database auto-initialize on first run.
        initialize_database(settings)

        # Initialize orchestrator and rate limiter.
        app.state.orchestrator = Orchestrator(settings)
        app.state.rate_limiter = InMemoryRateLimiter(limit=settings.rate_limit_per_hour, window_seconds=3600)

        # Export attack patterns to JSON for transparency (kept in sync with config.py).
        data_dir = Path(__file__).resolve().parent / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        export_attack_patterns_json(str((data_dir / "attack_patterns.json").resolve()))

        # Ensure an ML model exists (fast offline train on small dataset).
        model_path = Path(settings.model_path)
        if not model_path.exists():
            try:
                train_and_save(settings)
            except Exception:
                # Model is optional; do not fail startup if training fails.
                pass

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()

    # Use PORT from environment (Render sets this)
    port = int(os.environ.get("PORT", settings.port))

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        log_level="info",
        access_log=True,
    )