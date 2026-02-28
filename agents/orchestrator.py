"""
Master agent orchestrator.

Coordinates all agents:
- PatternAgent (fast regex)
- AnomalyAgent (statistical features)
- SemanticAgent (Claude) — only when needed to save credits
- ResponseAgent (policy decisions + sanitization + reports)

The orchestrator produces a final verdict with full explanation suitable for
API responses and database logging.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from typing import Any, Optional

from config import Settings, validate_weights
from agents.anomaly_agent import AnomalyAgent, AnomalyAgentResult
from agents.pattern_agent import PatternAgent, PatternAgentResult
from agents.response_agent import ResponseAgent
from agents.semantic_agent import SemanticAgent, SemanticAgentResult


def clamp01(x: float) -> float:
    """Clamp a float into [0, 1]."""

    return float(max(0.0, min(1.0, x)))


def _choose_attack_type(
    *,
    semantic: SemanticAgentResult | None,
    pattern: PatternAgentResult,
) -> str:
    """Choose the most likely attack type label."""

    if semantic and semantic.enabled and semantic.malicious and semantic.attack_type:
        return semantic.attack_type

    # Map pattern categories to required classes.
    mapping = {
        "extraction": "extraction",
        "exfiltration": "extraction",
        "injection": "injection",
        "jailbreak": "jailbreak",
        "manipulation": "manipulation",
        "social_engineering": "manipulation",
        "execution": "manipulation",
        "encoding": "manipulation",
    }

    if not pattern.matches:
        return "benign"

    # Choose the category with highest score (ties break by severity order).
    severity_order = ["extraction", "injection", "jailbreak", "manipulation"]
    best = None
    best_score = -1.0
    for cat, score in pattern.category_scores.items():
        cls = mapping.get(cat, "manipulation")
        if score > best_score:
            best_score = score
            best = cls
        elif score == best_score and best is not None:
            # Tie-break: prefer more severe.
            if severity_order.index(cls) < severity_order.index(best):
                best = cls
    return best or "benign"


class Orchestrator:
    """Coordinate agent ensemble and return final security verdict."""

    def __init__(self, settings: Settings) -> None:
        """Initialize all agents and validate ensemble weights."""

        validate_weights(settings)
        self.settings = settings
        self.pattern_agent = PatternAgent()
        self.anomaly_agent = AnomalyAgent()
        self.semantic_agent = SemanticAgent(settings)
        self.response_agent = ResponseAgent()

    def _should_run_semantic(
        self,
        *,
        text: str,
        pattern: PatternAgentResult,
        anomaly: AnomalyAgentResult,
    ) -> bool:
        """Decide whether to spend API credits on semantic analysis."""

        # If no key, never run semantic.
        if not self.settings.anthropic_api_key:
            return False

        # If strong enough signals already, semantic is useful for type + reasoning.
        if pattern.confidence >= self.settings.pattern_threshold:
            return True
        if anomaly.anomaly_score >= self.settings.anomaly_threshold:
            return True

        # If moderate patterns in sensitive categories, semantic can disambiguate.
        sensitive = {"extraction", "injection", "jailbreak"}
        if any(cat in sensitive and score >= 0.45 for cat, score in pattern.category_scores.items()):
            return True

        # If prompt contains suspicious obfuscation reasons, semantic helps.
        if any(
            k in (anomaly.reasons or [])
            for k in [
                "Detected a long Base64-like blob (possible encoded payload).",
                "Detected zero-width Unicode characters (possible obfuscation).",
                "Detected repeated token sequences (common in jailbreak templates).",
            ]
        ):
            return True

        # Save credits otherwise.
        return False

    async def analyze(self, *, text: str, context: str | None = None, ip_address: str | None = None) -> dict[str, Any]:
        """
        Run the full multi-agent analysis pipeline and return a final verdict object.

        Pattern and anomaly agents run in parallel. Semantic agent runs only when
        needed (and when an API key is present).
        """

        prompt_text = text or ""

        # Run pattern + anomaly in parallel (threads) to keep the API handler responsive.
        pattern_task = asyncio.to_thread(self.pattern_agent.analyze, prompt_text)
        anomaly_task = asyncio.to_thread(self.anomaly_agent.analyze, prompt_text)
        pattern_res, anomaly_res = await asyncio.gather(pattern_task, anomaly_task)

        semantic_res: SemanticAgentResult | None = None
        if self._should_run_semantic(text=prompt_text, pattern=pattern_res, anomaly=anomaly_res):
            semantic_res = await self.semantic_agent.analyze(prompt_text, context=context)

        # Semantic maliciousness score: only count toward risk when malicious=True.
        semantic_score = 0.0
        semantic_enabled = bool(semantic_res and semantic_res.enabled and not semantic_res.error)
        if semantic_res and semantic_res.enabled and semantic_res.malicious and not semantic_res.error:
            semantic_score = float(semantic_res.confidence)

        pattern_score = float(pattern_res.confidence)
        anomaly_score = float(anomaly_res.anomaly_score)

        # Weighted ensemble.
        #
        # Important: the platform must work without an API key (degraded mode).
        # If semantic analysis is disabled/skipped, we normalize the remaining
        # weights so pattern/anomaly can still produce high confidence for
        # obvious attacks.
        denom = self.settings.w_pattern + self.settings.w_anomaly + (self.settings.w_semantic if semantic_enabled else 0.0)
        raw = (self.settings.w_pattern * pattern_score) + (self.settings.w_anomaly * anomaly_score)
        if semantic_enabled:
            raw += (self.settings.w_semantic * semantic_score)
        final_confidence = clamp01(raw / max(1e-9, denom))

        # Policy-based escalation for high-confidence pattern matches to ensure
        # strong regex signatures still block even without semantic API.
        high_severity = {"extraction", "injection", "jailbreak"}
        severe_hit = any(cat in high_severity and score >= 0.75 for cat, score in pattern_res.category_scores.items())
        many_hits = len(pattern_res.matches) >= 3
        # Escalate on strong/high-signal pattern agent outcomes.
        high_signal_pattern = pattern_score >= 0.75 and any(cat in high_severity for cat in pattern_res.category_scores.keys())
        if pattern_score >= 0.88 or severe_hit or many_hits or high_signal_pattern:
            final_confidence = max(final_confidence, 0.82)
        if pattern_score >= 0.95 and any(cat in high_severity for cat in pattern_res.category_scores.keys()):
            final_confidence = max(final_confidence, 0.92)

        attack_type = _choose_attack_type(semantic=semantic_res, pattern=pattern_res)

        # Compose explanation.
        explanation_parts: list[str] = []
        if pattern_res.matches:
            explanation_parts.append(f"Pattern agent matched {len(pattern_res.matches)} known attack signature(s).")
        if anomaly_res.reasons:
            explanation_parts.append("Anomaly agent flagged unusual prompt characteristics.")
        if semantic_res and semantic_res.enabled:
            if semantic_res.error:
                explanation_parts.append("Semantic agent encountered an API error; LLM signal was not used.")
            elif semantic_res.cached:
                explanation_parts.append("Semantic agent used cached analysis to conserve credits.")
            else:
                explanation_parts.append("Semantic agent provided intent-based analysis.")
        if not explanation_parts:
            explanation_parts.append("No strong malicious indicators detected.")

        decision_details = {
            "prompt": prompt_text,
            "context": context,
            "ip_address": ip_address,
            "scores": {
                "pattern_score": round(pattern_score, 4),
                "anomaly_score": round(anomaly_score, 4),
                "semantic_score": round(semantic_score, 4),
                "final_confidence": round(final_confidence, 4),
                "semantic_enabled": bool(semantic_enabled),
            },
            "pattern": {
                "confidence": round(pattern_score, 4),
                "matches": pattern_res.matches,
                "category_scores": pattern_res.category_scores,
            },
            "anomaly": {
                "anomaly_score": round(anomaly_score, 4),
                "features": anomaly_res.features,
                "reasons": anomaly_res.reasons,
            },
            "semantic": (
                {
                    "enabled": semantic_res.enabled,
                    "confidence": semantic_res.confidence,
                    "attack_type": semantic_res.attack_type,
                    "malicious": semantic_res.malicious,
                    "rationale": semantic_res.rationale,
                    "indicators": semantic_res.indicators,
                    "cached": semantic_res.cached,
                    "error": semantic_res.error,
                }
                if semantic_res
                else {"enabled": False, "skipped_reason": "not_needed_or_no_key"}
            ),
            "explanation": " ".join(explanation_parts),
        }

        response = self.response_agent.decide(
            final_confidence=final_confidence,
            attack_type=attack_type,
            details=decision_details,
        )

        final_verdict = "BLOCK" if response.blocked else "ALLOW"
        return {
            "final_verdict": final_verdict,
            "attack_type": attack_type,
            "confidence": final_confidence,
            "threat_level": response.threat_level,
            "actions": response.actions,
            "blocked": response.blocked,
            "sanitized_prompt": response.sanitized_prompt,
            "incident_report": response.incident_report,
            "remediation_steps": response.remediation_steps,
            "details": decision_details,
        }

