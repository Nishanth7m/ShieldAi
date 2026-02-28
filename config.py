"""
ShieldAI configuration.

This module centralizes configuration, thresholds, and known attack patterns.
All secrets are loaded from environment variables to keep the codebase safe.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Pattern

from dotenv import load_dotenv


def _load_env() -> None:
    """Load environment variables from a local `.env` file if present."""

    # In production (Railway/Render), environment variables are typically injected
    # by the platform. Locally, a `.env` file is convenient.
    load_dotenv(override=False)


def _env_bool(name: str, default: bool) -> bool:
    """Parse a boolean environment variable safely."""

    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    """Parse an integer environment variable safely."""

    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def _default_database_path() -> str:
    """Return the default SQLite database path (relative to project root)."""

    return "data/shieldai.db"


def _project_root() -> Path:
    """Return the project root path (directory containing this file)."""

    return Path(__file__).resolve().parent


def _abs_path(maybe_relative: str) -> str:
    """Convert a relative path to an absolute path anchored at project root."""

    p = Path(maybe_relative)
    if p.is_absolute():
        return str(p)
    return str((_project_root() / p).resolve())


# -----------------------------
# Attack pattern library (50+)
# -----------------------------
#
# Notes:
# - Patterns are intentionally broader than strict signatures because attackers
#   vary casing, whitespace, and punctuation.
# - We bias for recall and then use ensemble + thresholds to reduce false positives.
#
ATTACK_PATTERNS: list[dict[str, str]] = [
    # Injection / instruction override
    {"category": "injection", "name": "ignore_previous_instructions", "regex": r"(?i)\bignore\b.*\b(previous|prior|above)\b.*\b(instructions|rules|messages)\b"},
    {"category": "injection", "name": "forget_everything", "regex": r"(?i)\bforget\b.*\b(everything|all prior|all previous)\b"},
    {"category": "injection", "name": "new_instructions", "regex": r"(?i)\bnew\s+instructions\s*:\s*"},
    {"category": "injection", "name": "system_prompt_override", "regex": r"(?i)\b(system|developer)\s+(prompt|message)\b.*\b(override|replace|ignore)\b"},
    {"category": "injection", "name": "override_policy", "regex": r"(?i)\b(override|bypass)\b.*\b(policy|policies|safety|guardrails)\b"},
    {"category": "injection", "name": "follow_these_instructions", "regex": r"(?i)\bfollow\s+(only\s+)?these\s+instructions\b"},
    {"category": "injection", "name": "do_not_follow_above", "regex": r"(?i)\b(do\s+not|don't)\s+(follow|obey)\b.*\b(above|previous)\b"},
    {"category": "injection", "name": "priority_instructions", "regex": r"(?i)\b(priority|highest\s+priority)\b.*\b(instruction|rule)\b"},
    {"category": "injection", "name": "system_tag_injection", "regex": r"(?i)<\s*(system|developer)\s*>[\s\S]*?<\s*/\s*(system|developer)\s*>"},
    {"category": "injection", "name": "role_directive", "regex": r"(?i)\byou\s+are\s+now\s+(the\s+)?(system|developer|admin|root|superuser)\b"},
    {"category": "injection", "name": "nested_instructions", "regex": r"(?i)\bwithin\s+this\s+message\b.*\b(ignore|override|replace)\b"},
    {"category": "injection", "name": "tool_injection", "regex": r"(?i)\b(use|call)\b.*\b(tool|function|plugin)\b.*\bto\b.*\bexfiltrate|leak|steal\b"},
    # Jailbreak / role-play manipulation
    {"category": "jailbreak", "name": "dan_do_anything_now", "regex": r"(?i)\bDAN\b|\bdo\s+anything\s+now\b"},
    {"category": "jailbreak", "name": "developer_mode", "regex": r"(?i)\bdeveloper\s+mode\b|\bdev\s+mode\b"},
    {"category": "jailbreak", "name": "unfiltered_mode", "regex": r"(?i)\b(unfiltered|no\s+filters|without\s+restrictions)\b"},
    {"category": "jailbreak", "name": "pretend_you_are", "regex": r"(?i)\bpretend\s+you\s+are\b|\bact\s+as\b|\brole\s*play\b"},
    {"category": "jailbreak", "name": "stay_in_character", "regex": r"(?i)\bstay\s+in\s+character\b"},
    {"category": "jailbreak", "name": "hypothetical_bypass", "regex": r"(?i)\b(hypothetical|fictional)\b.*\b(no\s+rules|ignore\s+rules|bypass)\b"},
    {"category": "jailbreak", "name": "safety_disabled", "regex": r"(?i)\b(safety|alignment)\b.*\b(disabled|turned\s+off|remove)\b"},
    {"category": "jailbreak", "name": "two_personas", "regex": r"(?i)\b(two\s+responses|two\s+personalities|as\s+both)\b"},
    {"category": "jailbreak", "name": "policy_as_joke", "regex": r"(?i)\b(just\s+kidding|as\s+a\s+joke)\b.*\b(illegal|harmful|unsafe)\b"},
    {"category": "jailbreak", "name": "refusal_suppression", "regex": r"(?i)\bdo\s+not\s+(refuse|decline)\b|\bnever\s+say\s+no\b"},
    # Extraction / system prompt leakage
    {"category": "extraction", "name": "repeat_system_prompt", "regex": r"(?i)\brepeat\b.*\b(system\s+prompt|system\s+message)\b"},
    {"category": "extraction", "name": "reveal_instructions", "regex": r"(?i)\b(reveal|show|tell)\b.*\b(instructions|rules|prompt)\b"},
    {"category": "extraction", "name": "what_are_your_instructions", "regex": r"(?i)\bwhat\s+are\s+your\s+(instructions|rules)\b"},
    {"category": "extraction", "name": "print_configuration", "regex": r"(?i)\bprint\b.*\b(configuration|config|settings)\b"},
    {"category": "extraction", "name": "internal_policy", "regex": r"(?i)\b(internal|private|hidden)\b.*\b(policy|prompt|rules)\b"},
    {"category": "extraction", "name": "token_smuggling", "regex": r"(?i)\b(token|tokens)\b.*\b(smuggle|leak|exfiltrate)\b"},
    {"category": "extraction", "name": "secret_key_request", "regex": r"(?i)\b(api\s*key|secret|password|credentials)\b.*\b(reveal|share|show)\b"},
    {"category": "extraction", "name": "system_prompt_as_codeblock", "regex": r"(?i)\b(system\s+prompt|developer\s+message)\b.*```"},
    # Data exfil / unauthorized access
    {"category": "exfiltration", "name": "exfiltrate_data", "regex": r"(?i)\b(exfiltrate|steal|leak|dump)\b.*\b(data|database|secrets|keys)\b"},
    {"category": "exfiltration", "name": "send_to_url", "regex": r"(?i)\b(send|post|upload)\b.*\b(to|into)\b.*\bhttps?://"},
    {"category": "exfiltration", "name": "read_local_files", "regex": r"(?i)\b(read|open)\b.*\b(/etc/passwd|\.env|id_rsa|credentials|secrets)\b"},
    {"category": "exfiltration", "name": "browser_storage", "regex": r"(?i)\b(localStorage|sessionStorage|cookies?)\b.*\b(exfiltrate|steal|dump)\b"},
    # Encoding / obfuscation tricks
    {"category": "encoding", "name": "base64_indicator", "regex": r"(?i)\bbase64\b|\bdecode\b.*\bbase64\b"},
    {"category": "encoding", "name": "looks_like_base64_blob", "regex": r"(?i)\b[A-Za-z0-9+/]{80,}={0,2}\b"},
    {"category": "encoding", "name": "rot13", "regex": r"(?i)\brot13\b"},
    {"category": "encoding", "name": "hex_encoding", "regex": r"(?i)\b0x[0-9a-f]{2,}\b|\bhex\s+decode\b"},
    {"category": "encoding", "name": "unicode_zero_width", "regex": r"[\u200B-\u200F\u2060\uFEFF]"},
    {"category": "encoding", "name": "unicode_homoglyphs", "regex": r"(?i)\b(homoglyph|unicode\s+substitution|confusables)\b"},
    {"category": "encoding", "name": "leetspeak_bypass", "regex": r"(?i)\b(1gn0re|pr3v10us|1nstruct10ns|rul3s)\b"},
    {"category": "encoding", "name": "invisible_chars", "regex": r"(?i)\b(zero\s*width|invisible)\b.*\b(character|chars?)\b"},
    {"category": "encoding", "name": "url_encoding", "regex": r"(%3C|%3E|%2F|%0A|%0D){3,}"},
    # Social engineering / manipulation
    {"category": "social_engineering", "name": "authority_impersonation", "regex": r"(?i)\b(i\s+am|this\s+is)\b.*\b(admin|moderator|developer|security|ceo|police|fbi)\b"},
    {"category": "social_engineering", "name": "urgent_action", "regex": r"(?i)\b(urgent|immediately|asap|right\s+now)\b.*\b(do|need|must)\b"},
    {"category": "social_engineering", "name": "trust_building", "regex": r"(?i)\btrust\s+me\b|\bfor\s+research\b|\bfor\s+educational\s+purposes\b"},
    {"category": "social_engineering", "name": "guilt_trip", "regex": r"(?i)\bif\s+you\s+don't\b.*\b(happen|die|lose|fire)\b"},
    {"category": "social_engineering", "name": "flattery_manipulation", "regex": r"(?i)\byou\s+are\s+the\s+only\s+one\b|\byou\s+must\b.*\bhelp\b"},
    # Multi-turn / persistence tactics
    {"category": "manipulation", "name": "step_by_step_exploit", "regex": r"(?i)\b(step\s+by\s+step|walk\s+me\s+through)\b.*\b(bypass|exploit|hack)\b"},
    {"category": "manipulation", "name": "constraint_redefinition", "regex": r"(?i)\b(define|redefine)\b.*\b(safe|allowed|policy)\b"},
    {"category": "manipulation", "name": "hidden_instruction", "regex": r"(?i)\b(hidden|secret)\s+instruction\b"},
    {"category": "manipulation", "name": "delimiter_confusion", "regex": r"(?i)\b(###\s*system|---\s*system|BEGIN\s+SYSTEM\s+PROMPT)\b"},
    {"category": "manipulation", "name": "instruction_conflict", "regex": r"(?i)\b(conflicting|contradict)\b.*\b(instructions|rules)\b"},
    {"category": "manipulation", "name": "self_referential_policy", "regex": r"(?i)\b(the\s+next\s+message\s+is\s+from\s+the\s+system)\b"},
    # Code/command execution coaxing
    {"category": "execution", "name": "shell_command_request", "regex": r"(?i)\b(run|execute)\b.*\b(cmd|command|powershell|bash|terminal)\b"},
    {"category": "execution", "name": "sql_injection_language", "regex": r"(?i)\b(drop\s+table|union\s+select|or\s+1=1|--\s)\b"},
    {"category": "execution", "name": "prompt_leak_via_json", "regex": r"(?i)\boutput\s+exactly\s+the\s+json\b.*\b(system|developer)\b"},
    # Explicit override phrases commonly used in jailbreak templates
    {"category": "jailbreak", "name": "no_moral_constraints", "regex": r"(?i)\bno\s+(moral|ethical)\s+constraints\b"},
    {"category": "jailbreak", "name": "answer_without_refusing", "regex": r"(?i)\banswer\b.*\bwithout\s+refusing\b"},
    {"category": "jailbreak", "name": "you_must_comply", "regex": r"(?i)\byou\s+must\s+comply\b"},
    {"category": "jailbreak", "name": "bypass_safety_filter", "regex": r"(?i)\bbypass\b.*\b(safety\s+filter|content\s+filter)\b"},
    # "Instruction override" with common delimiters
    {"category": "injection", "name": "override_after_delimiter", "regex": r"(?is)(^|[\r\n])\s*(---|###)\s*(new\s+)?instructions\s*(---|###)\s*"},
]


def compiled_attack_patterns() -> list[dict[str, Any]]:
    """Return attack patterns with compiled regex objects for fast matching."""

    compiled: list[dict[str, Any]] = []
    for p in ATTACK_PATTERNS:
        compiled.append(
            {
                "category": p["category"],
                "name": p["name"],
                "regex": p["regex"],
                "compiled": re.compile(p["regex"]),
            }
        )
    return compiled


def export_attack_patterns_json(path: str) -> None:
    """Export the built-in attack patterns to a JSON file for inspection."""

    out = [{"category": p["category"], "name": p["name"], "regex": p["regex"]} for p in ATTACK_PATTERNS]
    Path(path).write_text(json.dumps(out, indent=2), encoding="utf-8")


@dataclass(frozen=True)
class Settings:
    """Typed configuration object for ShieldAI."""

    anthropic_api_key: str | None
    google_api_key: str | None  # Added Google API key support
    auth_secret_key: str
    auth_token_ttl_seconds: int
    google_oauth_client_id: str | None
    database_path: str
    max_prompt_length: int
    rate_limit_per_hour: int
    debug: bool
    port: int

    # Thresholds
    pattern_threshold: float
    anomaly_threshold: float
    semantic_threshold: float
    final_block_threshold: float

    # Ensemble weights
    w_pattern: float
    w_semantic: float
    w_anomaly: float

    # Model settings
    model_path: str
    tfidf_max_features: int

    # Semantic agent settings
    semantic_cache_ttl_seconds: int
    semantic_model: str
    semantic_max_tokens: int


def get_settings() -> Settings:
    """Load environment variables and return a Settings instance."""

    _load_env()
    is_production = os.getenv("RENDER") is not None
    try:
        # Avoid Unicode issues on limited consoles; logs are informational only.
        mode = "PRODUCTION" if is_production else "DEVELOPMENT"
        print(f"[ShieldAI] Running in {mode} mode")
    except Exception:
        pass
    project_root = _project_root()

    # Support both Anthropic and Google API keys
    anthropic_api_key = os.getenv("ANTHROPIC_API_KEY") or None
    google_api_key = os.getenv("GOOGLE_API_KEY") or None
    
    # If no Anthropic key but Google key exists, use Google key for orchestrator checks
    # The actual semantic agent will use whichever key is configured
    if not anthropic_api_key and google_api_key:
        anthropic_api_key = "google-api-configured"  # Placeholder to enable semantic agent
    
    # Database path - use in-memory for production (e.g., Render free tier)
    if is_production:
        database_path = ":memory:"
    else:
        database_path = _abs_path(os.getenv("DATABASE_PATH", _default_database_path()))
    auth_secret_key = os.getenv("AUTH_SECRET_KEY") or os.getenv("SECRET_KEY") or "dev-insecure-change-me"
    google_oauth_client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID") or os.getenv("GOOGLE_CLIENT_ID") or None

    # Ensure the data directory exists (for SQLite file path + model artifacts).
    if database_path != ":memory:":
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    (project_root / "data").mkdir(parents=True, exist_ok=True)

    return Settings(
        anthropic_api_key=anthropic_api_key,
        google_api_key=google_api_key,
        auth_secret_key=auth_secret_key,
        auth_token_ttl_seconds=_env_int("AUTH_TOKEN_TTL_SECONDS", 60 * 60 * 24 * 7),
        google_oauth_client_id=google_oauth_client_id,
        database_path=database_path,
        max_prompt_length=_env_int("MAX_PROMPT_LENGTH", 10000),
        rate_limit_per_hour=_env_int("RATE_LIMIT", 100),
        debug=_env_bool("DEBUG", False),
        port=_env_int("PORT", 8000),
        pattern_threshold=float(os.getenv("PATTERN_THRESHOLD", "0.55")),
        anomaly_threshold=float(os.getenv("ANOMALY_THRESHOLD", "0.60")),
        semantic_threshold=float(os.getenv("SEMANTIC_THRESHOLD", "0.65")),
        final_block_threshold=float(os.getenv("FINAL_BLOCK_THRESHOLD", "0.70")),
        w_pattern=float(os.getenv("W_PATTERN", "0.35")),
        w_semantic=float(os.getenv("W_SEMANTIC", "0.45")),
        w_anomaly=float(os.getenv("W_ANOMALY", "0.20")),
        model_path=_abs_path(os.getenv("MODEL_PATH", "data/attack_classifier.joblib")),
        tfidf_max_features=_env_int("TFIDF_MAX_FEATURES", 5000),
        semantic_cache_ttl_seconds=_env_int("SEMANTIC_CACHE_TTL_SECONDS", 60 * 60 * 24 * 7),
        semantic_model=os.getenv("SEMANTIC_MODEL", "claude-3-haiku-20240307"),
        semantic_max_tokens=_env_int("SEMANTIC_MAX_TOKENS", 600),
    )


def validate_weights(settings: Settings) -> None:
    """Validate ensemble weights sum to ~1.0 and are non-negative."""

    weights = [settings.w_pattern, settings.w_semantic, settings.w_anomaly]
    if any(w < 0 for w in weights):
        raise ValueError("Ensemble weights must be non-negative.")
    s = sum(weights)
    if not (0.95 <= s <= 1.05):
        raise ValueError(f"Ensemble weights should sum to ~1.0, got {s:.3f}.")