"""
Authentication endpoints for ShieldAI.

Supports:
- Email/password signup + login (PBKDF2-SHA256)
- Google sign-in (ID token verification via Google's tokeninfo endpoint)

This is intended as a lightweight, dependency-minimal auth layer suitable for demos.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import urllib.parse
import urllib.request
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from config import Settings
from database.connection import get_connection


router = APIRouter()

_COOKIE_NAME = "shieldai_token"

_EMAIL_RE = re.compile(r"(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$")


def _settings(request: Request) -> Settings:
    s = getattr(request.app.state, "settings", None)
    if s is None:
        raise RuntimeError("App settings not initialized.")
    return s


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * ((4 - (len(text) % 4)) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


def _sign(settings: Settings, payload_b64: str) -> str:
    mac = hmac.new(settings.auth_secret_key.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
    return _b64url_encode(mac)


def issue_token(settings: Settings, *, user_id: int, email: str) -> str:
    now = int(time.time())
    payload = {"sub": int(user_id), "email": str(email), "iat": now, "exp": now + int(settings.auth_token_ttl_seconds)}
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    sig = _sign(settings, payload_b64)
    return f"{payload_b64}.{sig}"


def verify_token(settings: Settings, token: str) -> dict[str, Any]:
    try:
        payload_b64, sig = token.split(".", 1)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token.")

    expected = _sign(settings, payload_b64)
    if not hmac.compare_digest(expected, sig):
        raise HTTPException(status_code=401, detail="Invalid token.")

    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8", errors="strict"))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token.")

    exp = int(payload.get("exp") or 0)
    if exp and int(time.time()) > exp:
        raise HTTPException(status_code=401, detail="Token expired.")
    return payload


def _get_bearer_token(request: Request) -> str | None:
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        return None
    return auth.split(" ", 1)[1].strip() or None


def _get_cookie_token(request: Request) -> str | None:
    return request.cookies.get(_COOKIE_NAME) or None


def _set_auth_cookie(response: Response, *, token: str, max_age_seconds: int) -> None:
    response.set_cookie(
        key=_COOKIE_NAME,
        value=token,
        max_age=int(max_age_seconds),
        httponly=True,
        samesite="lax",
        secure=False,  # set True behind HTTPS
        path="/",
    )


def _clear_auth_cookie(response: Response) -> None:
    response.delete_cookie(key=_COOKIE_NAME, path="/")


def _hash_password(password: str, *, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 210_000, dklen=32)


def _password_strength_ok(password: str, *, email: str | None = None) -> tuple[bool, str]:
    pw = password or ""
    if len(pw) < 12:
        return False, "Password must be at least 12 characters."
    if any(c.isspace() for c in pw):
        return False, "Password cannot contain whitespace."

    classes = 0
    classes += 1 if re.search(r"[a-z]", pw) else 0
    classes += 1 if re.search(r"[A-Z]", pw) else 0
    classes += 1 if re.search(r"[0-9]", pw) else 0
    classes += 1 if re.search(r"[^A-Za-z0-9]", pw) else 0
    if classes < 3:
        return False, "Use at least 3 of: lowercase, uppercase, number, symbol."

    if email:
        local = email.split("@", 1)[0].strip().lower()
        if local and local in pw.lower():
            return False, "Password should not contain your email name."

    return True, "OK"


def _normalize_email(email: str) -> str:
    return (email or "").strip().lower()


class SignupRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=1, max_length=512)


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=1, max_length=512)


class GoogleCredentialRequest(BaseModel):
    credential: str = Field(..., min_length=20)


class AuthUser(BaseModel):
    id: int
    email: str
    email_verified: bool


class AuthResponse(BaseModel):
    token: str
    user: AuthUser


@router.get("/public-config")
def public_config(request: Request) -> dict[str, Any]:
    settings = _settings(request)
    return {"google_oauth_client_id": settings.google_oauth_client_id}


@router.post("/auth/signup", response_model=AuthResponse)
def signup(req: SignupRequest, request: Request, response: Response) -> AuthResponse:
    settings = _settings(request)
    email = _normalize_email(req.email)
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")

    ok, msg = _password_strength_ok(req.password, email=email)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    salt = secrets.token_bytes(16)
    pw_hash = _hash_password(req.password, salt=salt)

    with get_connection(settings) as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?;", (email,)).fetchone()
        if existing is not None:
            raise HTTPException(status_code=409, detail="Email is already registered. Please sign in.")

        cur = conn.execute(
            """
            INSERT INTO users (email, password_salt, password_hash, email_verified, created_at)
            VALUES (?, ?, ?, 0, datetime('now'));
            """,
            (email, salt, pw_hash),
        )
        user_id = int(cur.lastrowid)

    token = issue_token(settings, user_id=user_id, email=email)
    _set_auth_cookie(response, token=token, max_age_seconds=settings.auth_token_ttl_seconds)
    return AuthResponse(token=token, user=AuthUser(id=user_id, email=email, email_verified=False))


@router.post("/auth/login", response_model=AuthResponse)
def login(req: LoginRequest, request: Request, response: Response) -> AuthResponse:
    settings = _settings(request)
    email = _normalize_email(req.email)
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Invalid credentials.")

    with get_connection(settings) as conn:
        row = conn.execute(
            "SELECT id, email, password_salt, password_hash, email_verified FROM users WHERE email = ?;",
            (email,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="Invalid credentials.")

        if row["password_salt"] is None or row["password_hash"] is None:
            raise HTTPException(status_code=401, detail="Use Google sign-in for this account.")

        salt = bytes(row["password_salt"])
        expected = bytes(row["password_hash"])
        got = _hash_password(req.password, salt=salt)
        if not hmac.compare_digest(expected, got):
            raise HTTPException(status_code=401, detail="Invalid credentials.")

        user_id = int(row["id"])
        verified = bool(int(row["email_verified"]))

    token = issue_token(settings, user_id=user_id, email=email)
    _set_auth_cookie(response, token=token, max_age_seconds=settings.auth_token_ttl_seconds)
    return AuthResponse(token=token, user=AuthUser(id=user_id, email=email, email_verified=verified))


def _google_tokeninfo(id_token: str) -> dict[str, Any]:
    url = "https://oauth2.googleapis.com/tokeninfo?" + urllib.parse.urlencode({"id_token": id_token})
    with urllib.request.urlopen(url, timeout=10) as r:
        raw = r.read().decode("utf-8", errors="ignore")
    return json.loads(raw)


@router.post("/auth/google", response_model=AuthResponse)
def auth_google(req: GoogleCredentialRequest, request: Request, response: Response) -> AuthResponse:
    settings = _settings(request)
    if not settings.google_oauth_client_id:
        raise HTTPException(status_code=400, detail="Google sign-in is not configured on the server.")

    try:
        info = _google_tokeninfo(req.credential)
    except Exception:
        raise HTTPException(status_code=401, detail="Google token verification failed.")

    aud = str(info.get("aud") or "")
    if aud != settings.google_oauth_client_id:
        raise HTTPException(status_code=401, detail="Google token audience mismatch.")

    email = _normalize_email(str(info.get("email") or ""))
    sub = str(info.get("sub") or "")
    email_verified = str(info.get("email_verified") or "").lower() in {"1", "true", "yes"}
    if not email or not _EMAIL_RE.match(email) or not sub:
        raise HTTPException(status_code=401, detail="Google token missing required fields.")

    with get_connection(settings) as conn:
        # Prefer lookup by google_sub; fall back to email for linking.
        row = conn.execute("SELECT id, email, google_sub, email_verified FROM users WHERE google_sub = ?;", (sub,)).fetchone()
        if row is None:
            row = conn.execute("SELECT id, email, google_sub, email_verified FROM users WHERE email = ?;", (email,)).fetchone()

        if row is None:
            cur = conn.execute(
                """
                INSERT INTO users (email, password_salt, password_hash, google_sub, email_verified, created_at)
                VALUES (?, NULL, NULL, ?, ?, datetime('now'));
                """,
                (email, sub, 1 if email_verified else 0),
            )
            user_id = int(cur.lastrowid)
            verified = bool(email_verified)
        else:
            user_id = int(row["id"])
            # Link google_sub if missing.
            if row["google_sub"] is None:
                conn.execute("UPDATE users SET google_sub = ? WHERE id = ?;", (sub, user_id))
            # Upgrade email_verified if Google says so.
            if email_verified and not bool(int(row["email_verified"])):
                conn.execute("UPDATE users SET email_verified = 1 WHERE id = ?;", (user_id,))
            verified = bool(int(conn.execute("SELECT email_verified FROM users WHERE id = ?;", (user_id,)).fetchone()["email_verified"]))

    token = issue_token(settings, user_id=user_id, email=email)
    _set_auth_cookie(response, token=token, max_age_seconds=settings.auth_token_ttl_seconds)
    return AuthResponse(token=token, user=AuthUser(id=user_id, email=email, email_verified=verified))


@router.get("/auth/me", response_model=AuthUser)
def me(request: Request) -> AuthUser:
    settings = _settings(request)
    tok = _get_bearer_token(request) or _get_cookie_token(request)
    if not tok:
        raise HTTPException(status_code=401, detail="Missing token.")
    payload = verify_token(settings, tok)
    user_id = int(payload.get("sub") or 0)
    email = str(payload.get("email") or "")
    if user_id <= 0 or not email:
        raise HTTPException(status_code=401, detail="Invalid token.")

    with get_connection(settings) as conn:
        row = conn.execute("SELECT id, email, email_verified FROM users WHERE id = ?;", (user_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=401, detail="User not found.")
        return AuthUser(id=int(row["id"]), email=str(row["email"]), email_verified=bool(int(row["email_verified"])))


@router.post("/auth/logout")
def logout(request: Request, response: Response) -> dict[str, Any]:
    _clear_auth_cookie(response)
    return {"ok": True}

