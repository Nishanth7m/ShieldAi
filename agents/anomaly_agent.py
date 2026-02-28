"""
Anomaly detection agent (statistical, no ML model required).

This agent computes a set of text-based features and compares them against
baseline expectations for typical user prompts. The output is an anomaly score
in [0.0, 1.0], plus feature explanations that help analysts understand why.
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Any


ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u2060\uFEFF]")
BASE64_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b")
REPEATED_TOKEN_RE = re.compile(r"(?i)\b(\w{3,})\b(?:\W+\1\b){4,}")


def shannon_entropy(text: str) -> float:
    """Compute Shannon entropy per character for a string."""

    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def clamp01(x: float) -> float:
    """Clamp a float into the [0, 1] interval."""

    return float(max(0.0, min(1.0, x)))


def sigmoid(x: float) -> float:
    """Compute a sigmoid that maps real values to (0, 1)."""

    # Prevent overflow on large inputs.
    x = max(-60.0, min(60.0, x))
    return 1.0 / (1.0 + math.exp(-x))


@dataclass(frozen=True)
class AnomalyAgentResult:
    """Result returned by the AnomalyAgent."""

    anomaly_score: float
    features: dict[str, Any]
    reasons: list[str]   


class AnomalyAgent:
    """
    Compute an anomaly score using hand-crafted features.

    Baselines are conservative and tuned to detect:
    - unusually long prompts
    - high entropy / encoded payloads
    - excessive special characters
    - zero-width / unicode trickery
    - repetition loops used in jailbreak templates
    """

    def __init__(self) -> None:
        """Initialize baselines for typical benign prompts."""

        # Baselines approximate typical "chat prompt" distributions.
        # They are not learned from user data, so they are safe for offline use.
        self.baseline = {
            "length_mean": 320.0,
            "length_std": 260.0,
            "entropy_mean": 4.15,
            "entropy_std": 0.55,
            "special_ratio_mean": 0.08,
            "special_ratio_std": 0.06,
            "non_ascii_ratio_mean": 0.02,
            "non_ascii_ratio_std": 0.03,
        }

    def analyze(self, text: str) -> AnomalyAgentResult:
        """Analyze text and produce anomaly score with feature explanations."""

        text = text or ""
        n = len(text)
        if n == 0:
            return AnomalyAgentResult(anomaly_score=0.0, features={"length": 0}, reasons=[])

        # Basic counts
        non_ascii = sum(1 for ch in text if ord(ch) > 127)
        zero_width = len(ZERO_WIDTH_RE.findall(text))
        whitespace = sum(1 for ch in text if ch.isspace())
        control = sum(1 for ch in text if unicodedata.category(ch).startswith("C"))
        alnum = sum(1 for ch in text if ch.isalnum())
        special = max(0, n - alnum - whitespace)

        special_ratio = special / n
        non_ascii_ratio = non_ascii / n
        entropy = shannon_entropy(text)

        # Heuristic flags
        has_base64_blob = bool(BASE64_BLOB_RE.search(text))
        has_repetition_loop = bool(REPEATED_TOKEN_RE.search(text))
        many_newlines = text.count("\n") >= 12
        delimiter_density = sum(text.count(x) for x in ["###", "---", "BEGIN", "END"]) >= 6

        # Z-scores relative to baselines
        def z(value: float, mean: float, std: float) -> float:
            """Compute z-score with a safe std floor."""

            return (value - mean) / max(1e-6, std)

        z_length = z(float(n), self.baseline["length_mean"], self.baseline["length_std"])
        z_entropy = z(entropy, self.baseline["entropy_mean"], self.baseline["entropy_std"])
        z_special = z(special_ratio, self.baseline["special_ratio_mean"], self.baseline["special_ratio_std"])
        z_non_ascii = z(non_ascii_ratio, self.baseline["non_ascii_ratio_mean"], self.baseline["non_ascii_ratio_std"])

        # Convert signals to scores [0, 1]
        # We allow modest deviations; strong deviations increase rapidly.
        s_length = sigmoid((z_length - 1.1) * 1.25)
        s_entropy = sigmoid((z_entropy - 1.0) * 1.6)
        s_special = sigmoid((z_special - 1.0) * 1.4)
        s_non_ascii = sigmoid((z_non_ascii - 1.2) * 1.4)

        s_zero_width = clamp01(zero_width / 4.0)
        s_control = clamp01(control / 10.0)
        s_repetition = 0.85 if has_repetition_loop else 0.0
        s_base64 = 0.85 if has_base64_blob else 0.0
        s_delims = 0.6 if delimiter_density else 0.0
        s_newlines = 0.35 if many_newlines else 0.0

        # Weighted blend of features
        score = (
            0.20 * s_length
            + 0.18 * s_entropy
            + 0.14 * s_special
            + 0.10 * s_non_ascii
            + 0.10 * s_zero_width
            + 0.06 * s_control
            + 0.10 * s_repetition
            + 0.08 * s_base64
            + 0.02 * s_delims
            + 0.02 * s_newlines
        )
        score = clamp01(score)

        # Base64-like blobs are strong indicators of encoding/obfuscation payloads.
        if has_base64_blob:
            score = max(score, 0.25)

        reasons: list[str] = []
        if s_base64 > 0:
            reasons.append("Detected a long Base64-like blob (possible encoded payload).")
        if zero_width > 0:
            reasons.append("Detected zero-width Unicode characters (possible obfuscation).")
        if has_repetition_loop:
            reasons.append("Detected repeated token sequences (common in jailbreak templates).")
        if entropy >= 5.2:
            reasons.append("High character entropy suggests encoding/obfuscation.")
        if special_ratio >= 0.20:
            reasons.append("Unusually high special-character ratio.")
        if non_ascii_ratio >= 0.15:
            reasons.append("High non-ASCII ratio (possible Unicode substitution tricks).")

        features = {
            "length": n,
            "entropy": round(entropy, 4),
            "special_ratio": round(special_ratio, 4),
            "non_ascii_ratio": round(non_ascii_ratio, 4),
            "zero_width_count": zero_width,
            "control_char_count": control,
            "has_base64_blob": has_base64_blob,
            "has_repetition_loop": has_repetition_loop,
            "many_newlines": many_newlines,
            "delimiter_density": delimiter_density,
            "signal_scores": {
                "length": round(s_length, 4),
                "entropy": round(s_entropy, 4),
                "special": round(s_special, 4),
                "non_ascii": round(s_non_ascii, 4),
                "zero_width": round(s_zero_width, 4),
                "control": round(s_control, 4),
                "repetition": round(s_repetition, 4),
                "base64": round(s_base64, 4),
                "delims": round(s_delims, 4),
                "newlines": round(s_newlines, 4),
            },
        }

        return AnomalyAgentResult(anomaly_score=score, features=features, reasons=reasons)

