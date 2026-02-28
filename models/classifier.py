"""
Attack classifier using scikit-learn.

This module provides a TF-IDF + RandomForest model that can classify prompts into:
- benign
- injection
- jailbreak
- extraction
- manipulation

The model is optional: ShieldAI works without it, but it can enhance reporting and
future improvements (e.g., feedback-driven retraining).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline

from config import Settings


LABELS = ["benign", "injection", "jailbreak", "extraction", "manipulation"]


@dataclass
class AttackClassifier:
    """Wrapper around an sklearn Pipeline for training/inference."""

    settings: Settings
    pipeline: Pipeline | None = None

    def build_pipeline(self) -> Pipeline:
        """Build a fresh model pipeline with configured parameters."""

        tfidf = TfidfVectorizer(
            max_features=int(self.settings.tfidf_max_features),
            ngram_range=(1, 2),
            lowercase=True,
            strip_accents="unicode",
        )
        rf = RandomForestClassifier(
            n_estimators=350,
            random_state=42,
            class_weight="balanced_subsample",
            max_depth=None,
            min_samples_split=2,
            n_jobs=-1,
        )
        return Pipeline([("tfidf", tfidf), ("rf", rf)])

    def train(self, texts: list[str], labels: list[str]) -> None:
        """Train the classifier on provided texts and labels."""

        if len(texts) != len(labels):
            raise ValueError("texts and labels must have same length.")
        if not texts:
            raise ValueError("Training data is empty.")
        self.pipeline = self.build_pipeline()
        self.pipeline.fit(texts, labels)

    def predict(self, text: str) -> dict[str, Any]:
        """
        Predict label probabilities for a single prompt.

        Returns a dict with:
        - label: predicted class label
        - probabilities: per-class probabilities (when available)
        """

        if not self.pipeline:
            self.load()
        assert self.pipeline is not None

        label = str(self.pipeline.predict([text])[0])
        probs: dict[str, float] = {}
        if hasattr(self.pipeline, "predict_proba"):
            p = self.pipeline.predict_proba([text])[0]
            classes = list(getattr(self.pipeline, "classes_", LABELS))
            probs = {str(c): float(p[i]) for i, c in enumerate(classes)}
        return {"label": label, "probabilities": probs}

    def save(self) -> str:
        """Save the trained model to disk; returns the saved path."""

        if not self.pipeline:
            raise ValueError("Model is not trained.")
        path = Path(self.settings.model_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.pipeline, str(path))
        return str(path)

    def load(self) -> None:
        """Load a previously trained model from disk."""

        path = Path(self.settings.model_path)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")
        self.pipeline = joblib.load(str(path))

