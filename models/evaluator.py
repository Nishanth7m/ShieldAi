"""
Model evaluation utilities for ShieldAI.

Evaluates the trained model on a holdout split and returns standard metrics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from config import Settings
from models.classifier import AttackClassifier, LABELS
from models.trainer import load_training_data


@dataclass
class EvaluationResult:
    """Evaluation output with report and confusion matrix."""

    report: dict[str, Any]
    confusion_matrix: list[list[int]]
    labels: list[str]


def evaluate(settings: Settings, *, test_size: float = 0.25) -> EvaluationResult:
    """Train/evaluate on a split and return metrics (offline)."""

    data_path = str((__import__("pathlib").Path(__file__).resolve().parent.parent / "data" / "training_data.json").resolve())
    texts, labels = load_training_data(data_path)

    x_train, x_test, y_train, y_test = train_test_split(
        texts,
        labels,
        test_size=float(test_size),
        random_state=42,
        stratify=labels,
    )

    clf = AttackClassifier(settings=settings)
    clf.train(x_train, y_train)

    assert clf.pipeline is not None
    preds = clf.pipeline.predict(x_test)
    report = classification_report(y_test, preds, labels=LABELS, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, preds, labels=LABELS)
    return EvaluationResult(report=report, confusion_matrix=cm.tolist(), labels=LABELS)

