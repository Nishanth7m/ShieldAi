"""
Model training pipeline for ShieldAI.

This module trains the RandomForest classifier on a local JSON dataset stored in
`data/training_data.json`. The dataset is intentionally small and fully offline,
so it works on free tiers and without external dependencies.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from config import Settings
from models.classifier import AttackClassifier, LABELS


def load_training_data(path: str) -> tuple[list[str], list[str]]:
    """Load training samples from a JSON file."""

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Training data file not found: {p}")
    obj = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(obj, list):
        raise ValueError("Training data JSON must be a list of {text,label} objects.")

    texts: list[str] = []
    labels: list[str] = []
    for item in obj:
        if not isinstance(item, dict):
            continue
        text = str(item.get("text", "")).strip()
        label = str(item.get("label", "")).strip().lower()
        if not text or label not in LABELS:
            continue
        texts.append(text)
        labels.append(label)
    if len(texts) < 20:
        raise ValueError("Training dataset too small; expected at least 20 valid samples.")
    return texts, labels


@dataclass
class TrainingResult:
    """Training artifact summary."""

    model_path: str
    num_samples: int
    labels: dict[str, int]


def train_and_save(settings: Settings) -> TrainingResult:
    """Train the classifier from `data/training_data.json` and save it to disk."""

    data_path = str((Path(__file__).resolve().parent.parent / "data" / "training_data.json").resolve())
    texts, labels = load_training_data(data_path)

    clf = AttackClassifier(settings=settings)
    clf.train(texts, labels)
    model_path = clf.save()

    counts: dict[str, int] = {}
    for lab in labels:
        counts[lab] = counts.get(lab, 0) + 1
    return TrainingResult(model_path=model_path, num_samples=len(texts), labels=counts)

