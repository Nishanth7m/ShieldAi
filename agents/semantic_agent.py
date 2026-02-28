"""
Semantic Agent - Keyword-based semantic analysis (no API needed)
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class SemanticAgentResult:
    """Result from semantic analysis"""
    enabled: bool
    confidence: float
    attack_type: str
    malicious: bool
    rationale: str
    indicators: list[str]
    cached: bool
    error: Optional[str]


class SemanticAgent:
    """Semantic analysis using keyword-based heuristics (no API required)"""
    
    def __init__(self, settings=None):
        """Initialize the semantic agent"""
        self.settings = settings
        self.cache = {}
        self.cache_ttl = 3600
        print("Semantic Agent (Keyword-based) initialized")
    
    def _get_cache_key(self, text: str) -> str:
        """Generate cache key"""
        return hashlib.sha256(text.encode()).hexdigest()
    
    def _check_cache(self, cache_key: str) -> Optional[SemanticAgentResult]:
        """Check cache"""
        if cache_key in self.cache:
            result, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_ttl:
                cached_result = SemanticAgentResult(
                    enabled=result.enabled,
                    confidence=result.confidence,
                    attack_type=result.attack_type,
                    malicious=result.malicious,
                    rationale=result.rationale,
                    indicators=result.indicators,
                    cached=True,
                    error=result.error
                )
                return cached_result
        return None
    
    def _save_cache(self, cache_key: str, result: SemanticAgentResult):
        """Save to cache"""
        self.cache[cache_key] = (result, time.time())
    
    async def analyze(self, text: str, context: Optional[str] = None) -> SemanticAgentResult:
        """
        Analyze text using keyword-based semantic analysis
        """
        
        # Check cache
        cache_key = self._get_cache_key(text)
        cached_result = self._check_cache(cache_key)
        if cached_result:
            return cached_result
        
        text_lower = text.lower()
        
        # Advanced keyword analysis with categories
        threat_keywords = {
            'injection': {
                'keywords': ['ignore', 'previous', 'instructions', 'override', 'forget', 'new instructions'],
                'weight': 1.0,
                'description': 'instruction override attempt'
            },
            'jailbreak': {
                'keywords': ['dan', 'developer mode', 'jailbreak', 'bypass', 'no restrictions', 'unfiltered'],
                'weight': 1.0,
                'description': 'jailbreak attempt'
            },
            'extraction': {
                'keywords': ['system prompt', 'reveal', 'show instructions', 'what are your', 'repeat your'],
                'weight': 1.0,
                'description': 'data extraction attempt'
            },
            'manipulation': {
                'keywords': ['pretend', 'act as', 'roleplay', 'stay in character', 'you must'],
                'weight': 0.8,
                'description': 'role manipulation'
            }
        }
        
        # Analyze
        found_indicators = []
        max_category_score = 0.0
        detected_category = 'none'
        
        for category, data in threat_keywords.items():
            category_score = 0.0
            for keyword in data['keywords']:
                if keyword in text_lower:
                    category_score += data['weight']
                    found_indicators.append(f"{keyword.title()}: {data['description']}")
            
            if category_score > max_category_score:
                max_category_score = category_score
                detected_category = category
        
        # Calculate confidence
        total_matches = len(found_indicators)
        confidence = min(0.3 + (total_matches * 0.15), 0.95)
        
        # Determine if malicious
        is_malicious = total_matches >= 2
        
        # Generate rationale
        if is_malicious:
            rationale = f"Detected {total_matches} suspicious indicators suggesting {detected_category} attack pattern"
        else:
            rationale = "No significant threat patterns detected in semantic analysis"
        
        result = SemanticAgentResult(
            enabled=True,
            confidence=confidence if is_malicious else 0.1,
            attack_type=detected_category if is_malicious else 'none',
            malicious=is_malicious,
            rationale=rationale,
            indicators=found_indicators,
            cached=False,
            error=None
        )
        
        # Cache result
        self._save_cache(cache_key, result)
        
        return result