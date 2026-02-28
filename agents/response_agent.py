"""
Automated response agent.

This agent decides what to do given a threat level and produces:
- blocking/allow decisions
- sanitized version of the prompt (best-effort)
- incident report and remediation steps
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u2060\uFEFF]")
SYSTEM_TAG_RE = re.compile(r"(?is)<\s*/?\s*(system|developer)\s*>")
BASE64_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b")

SUSPICIOUS_PHRASES = [
    re.compile(r"(?i)\bignore\b.*\b(previous|prior|above)\b.*\b(instructions|rules|messages)\b"),
    re.compile(r"(?i)\bforget\b.*\b(everything|all prior|all previous)\b"),
    re.compile(r"(?i)\breveal\b.*\b(system\s+prompt|developer\s+message|instructions|rules)\b"),
    re.compile(r"(?i)\bdo\s+anything\s+now\b|\bDAN\b"),
    re.compile(r"(?i)\bdeveloper\s+mode\b"),
]


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""

    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ResponseDecision:
    """Structured response returned by the ResponseAgent."""

    threat_level: str
    actions: list[str]
    blocked: bool
    sanitized_prompt: str
    incident_report: dict[str, Any]
    remediation_steps: list[str]


class ResponseAgent:
    """Decide response actions and produce incident reports."""

    def decide(self, *, final_confidence: float, attack_type: str, details: dict[str, Any]) -> ResponseDecision:
        """
        Decide how to respond based on final confidence score.

        Policy:
        - CRITICAL (>0.9): Block + Alert + Log
        - HIGH (>0.7): Block + Log + Sanitize
        - MEDIUM (>0.5): Warn + Log + Monitor
        - LOW (<0.5): Allow + Monitor
        """

        c = float(max(0.0, min(1.0, final_confidence)))
        if c > 0.9:
            level = "CRITICAL"
            actions = ["BLOCK", "ALERT", "LOG"]
            blocked = True
        elif c > 0.7:
            level = "HIGH"
            actions = ["BLOCK", "LOG", "SANITIZE"]
            blocked = True
        elif c > 0.5:
            level = "MEDIUM"
            actions = ["WARN", "LOG", "MONITOR"]
            blocked = False
        else:
            level = "LOW"
            actions = ["ALLOW", "MONITOR"]
            blocked = False

        original_prompt = str(details.get("prompt", ""))
        sanitized = self.sanitize_prompt(original_prompt)

        report = {
            "generated_at": utc_now_iso(),
            "threat_level": level,
            "attack_type": attack_type,
            "final_confidence": c,
            "actions": actions,
            "summary": self._summary(level, attack_type, c),
            "signals": {
                "pattern": details.get("pattern", {}),
                "anomaly": details.get("anomaly", {}),
                "semantic": details.get("semantic", {}),
            },
        }

        remediation = self.remediation_steps(level=level, attack_type=attack_type)
        return ResponseDecision(
            threat_level=level,
            actions=actions,
            blocked=blocked,
            sanitized_prompt=sanitized,
            incident_report=report,
            remediation_steps=remediation,
        )

    def sanitize_prompt(self, text: str) -> str:
        """
        Best-effort sanitization to remove common prompt-injection artifacts.

        This is NOT a guarantee of safety; it is meant to reduce risk for medium/low
        threats and provide a safer prompt preview.
        """

        t = text or ""
        # Remove zero-width characters and explicit system/developer tags.
        t = ZERO_WIDTH_RE.sub("", t)
        t = SYSTEM_TAG_RE.sub("", t)
        # Replace large encoded payloads with a placeholder.
        t = BASE64_BLOB_RE.sub("[REDACTED_BASE64_BLOB]", t)
        # Neutralize common override phrases.
        for pat in SUSPICIOUS_PHRASES:
            t = pat.sub("[REDACTED_SUSPICIOUS_INSTRUCTION]", t)
        # Collapse excessive whitespace.
        t = re.sub(r"[ \t]{3,}", "  ", t)
        t = re.sub(r"\n{4,}", "\n\n\n", t)
        return t.strip()

    def remediation_steps(self, *, level: str, attack_type: str) -> list[str]:
        """Suggest remediation steps tailored to the detected attack type and severity."""

        steps = [
            "Treat untrusted prompts as hostile input; never merge them directly into system/developer instructions.",
            "Use strict role separation: system/developer messages must be server-controlled only.",
            "Add output filtering for sensitive data (API keys, credentials, internal policies).",
        ]
        if attack_type in {"extraction", "exfiltration"}:
            steps.extend(
                [
                    "Prevent the model from accessing secrets: do not include system prompts, keys, or configs in the context window.",
                    "Add canary strings and monitor for leakage attempts in responses.",
                ]
            )
        if attack_type in {"injection", "jailbreak", "manipulation"}:
            steps.extend(
                [
                    "Use prompt templates that explicitly instruct the model to ignore user attempts to override rules.",
                    "Run additional validation on tool calls and enforce allowlists on actions.",
                ]
            )
        if level in {"HIGH", "CRITICAL"}:
            steps.extend(
                [
                    "Block the request and alert security/engineering owners.",
                    "Capture the full prompt, IP address, and timestamp for incident response.",
                    "Add the signature to your pattern library and retrain classifiers with the new sample.",
                ]
            )
        return steps

    def _summary(self, level: str, attack_type: str, confidence: float) -> str:
        """Generate a concise report summary."""

        return f"{level} {attack_type} risk detected (confidence {confidence:.2f})."

