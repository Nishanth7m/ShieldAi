"""
Pattern matching agent.

This agent detects known prompt-injection and jailbreak signatures using
compiled regular expressions. It is designed to be fast and requires no API calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from config import compiled_attack_patterns


@dataclass(frozen=True)
class PatternAgentResult:
    """Result object returned by the PatternAgent."""

    confidence: float
    matches: list[dict[str, Any]]
    category_scores: dict[str, float]


class PatternAgent:
    """Detect malicious prompts using a library of regex patterns."""

    def __init__(self) -> None:
        """Initialize the agent and compile attack patterns."""

        self._patterns = compiled_attack_patterns()

    def analyze(self, text: str) -> PatternAgentResult:
        """
        Analyze a prompt and return a confidence score and matched patterns.

        Confidence is computed from:
        - number of unique patterns matched
        - severity-weighted categories (jailbreak/extraction/injection higher)
        - density of matches relative to prompt length (helps penalize very long benign text)
        """

        text = text or ""
        matches: list[dict[str, Any]] = []
        category_hits: dict[str, int] = {}

        for p in self._patterns:
            if p["compiled"].search(text):
                matches.append({"category": p["category"], "name": p["name"], "regex": p["regex"]})
                category_hits[p["category"]] = category_hits.get(p["category"], 0) + 1

        # Category severity weights tuned for LLM attacks.
        severity = {
            "extraction": 1.15,
            "injection": 1.10,
            "jailbreak": 1.05,
            "exfiltration": 1.10,
            "encoding": 0.95,
            "social_engineering": 0.85,
            "manipulation": 0.90,
            "execution": 0.90,
        }

        # Compute per-category scores in [0, 1]
        category_scores: dict[str, float] = {}
        for cat, n in category_hits.items():
            # Diminishing returns: 1 hit is meaningful; additional hits add less.
            base = 1.0 - (0.72 ** n)
            weighted = min(1.0, base * severity.get(cat, 0.85))
            category_scores[cat] = weighted

        # Aggregate confidence with a cap.
        total_hits = len(matches)
        if total_hits == 0:
            return PatternAgentResult(confidence=0.0, matches=[], category_scores={})

        # Length normalization: very small prompts with strong patterns score higher.
        length = max(1, len(text))
        density = min(1.0, total_hits / max(3.0, length / 120.0))

        # Combine: max category score + coverage + density.
        max_cat = max(category_scores.values()) if category_scores else 0.0
        coverage = min(1.0, total_hits / 6.0)

        confidence = (0.55 * max_cat) + (0.25 * coverage) + (0.20 * density)
        confidence = float(max(0.0, min(1.0, confidence)))

        # Escalate confidence for high-signal signatures that strongly indicate
        # jailbreaks/extraction/instruction override even when only one pattern matches.
        high_signal_names = {
            "ignore_previous_instructions",
            "forget_everything",
            "system_prompt_override",
            "system_tag_injection",
            "override_policy",
            "do_not_follow_above",
            "repeat_system_prompt",
            "reveal_instructions",
            "what_are_your_instructions",
            "print_configuration",
            "secret_key_request",
            "dan_do_anything_now",
            "developer_mode",
            "refusal_suppression",
            "bypass_safety_filter",
        }
        high_signal_hits = sum(1 for m in matches if m.get("name") in high_signal_names)
        if high_signal_hits >= 2:
            confidence = max(confidence, 0.92)
        elif high_signal_hits == 1:
            confidence = max(confidence, 0.78)

        return PatternAgentResult(confidence=confidence, matches=matches, category_scores=category_scores)

