"""Machine-learning classifier: estimates the probability that a line of code is vulnerable.

Model: TF-IDF over code tokens (identifiers are generalized, operators and punctuation are
kept because they carry the signal) + Logistic Regression. It is small, trains in about a
second, needs no GPU and is explainable (see ``top_features``).

Role in the pipeline: a SECOND OPINION on each static finding. It contributes 25% of the
final confidence (see scoring.apply_ai_verdict). It does not create findings on its own.

Two sources of training data:
  * the built-in synthetic corpus (default, see seed_corpus.py),
  * a real dataset given to ``python -m sca train`` (JSON Lines with code + label).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:  # scikit-learn is optional: without it the analyzer still works, minus this layer
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover
    SKLEARN_AVAILABLE = False

from .seed_corpus import build_corpus

TOKEN = re.compile(r"[A-Za-z_][A-Za-z_0-9]*|\d+|\$\{|=>|->|::|[^\sA-Za-z_0-9]")
KEEP_WORDS = None  # all identifiers are kept; TF-IDF down-weights the uninformative ones


def tokenize(code: str) -> List[str]:
    tokens = []
    for tok in TOKEN.findall(code):
        if tok.isdigit():
            tokens.append("<num>")
        else:
            tokens.append(tok.lower() if len(tok) > 1 else tok)
    return tokens


def build_pipeline() -> "Pipeline":
    return Pipeline([
        ("tfidf", TfidfVectorizer(tokenizer=tokenize, lowercase=False, token_pattern=None,
                                  ngram_range=(1, 3), min_df=1, sublinear_tf=True)),
        ("clf", LogisticRegression(C=4.0, max_iter=2000, class_weight="balanced")),
    ])


class VulnerabilityClassifier:
    def __init__(self, pipeline: Any = None, source: str = "untrained") -> None:
        self.pipeline = pipeline
        self.source = source

    @classmethod
    def train(cls, texts: List[str], labels: List[int], source: str) -> "VulnerabilityClassifier":
        if not SKLEARN_AVAILABLE:
            raise RuntimeError("scikit-learn is not installed")
        pipeline = build_pipeline()
        pipeline.fit(texts, labels)
        return cls(pipeline, source)

    @classmethod
    def default(cls) -> "VulnerabilityClassifier":
        texts, labels = build_corpus()
        return cls.train(texts, labels, "built-in synthetic corpus (%d samples)" % len(texts))

    @classmethod
    def load(cls, path: str) -> "VulnerabilityClassifier":
        # joblib files are pickles: only load a model file that you trained yourself.
        import joblib
        data = joblib.load(path)
        return cls(data["pipeline"], data.get("source", path))

    def save(self, path: str) -> None:
        import joblib
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"pipeline": self.pipeline, "source": self.source}, path)

    def score(self, code: str) -> float:
        """Probability (0..1) that ``code`` is vulnerable."""
        return float(self.pipeline.predict_proba([code])[0][1])

    def score_many(self, codes: List[str]) -> List[float]:
        if not codes:
            return []
        return [float(p[1]) for p in self.pipeline.predict_proba(codes)]

    def top_features(self, n: int = 15) -> Dict[str, List[Tuple[str, float]]]:
        """The token n-grams that push hardest towards 'vulnerable' and towards 'safe'."""
        names = self.pipeline.named_steps["tfidf"].get_feature_names_out()
        weights = self.pipeline.named_steps["clf"].coef_[0]
        order = weights.argsort()
        return {
            "vulnerable": [(names[i], round(float(weights[i]), 3)) for i in order[::-1][:n]],
            "safe": [(names[i], round(float(weights[i]), 3)) for i in order[:n]],
        }


_CACHE: Dict[str, VulnerabilityClassifier] = {}


def get_classifier(model_path: Optional[str] = None) -> Optional[VulnerabilityClassifier]:
    """Return a ready classifier, or None when scikit-learn is missing."""
    if not SKLEARN_AVAILABLE:
        return None
    key = model_path or "default"
    if key not in _CACHE:
        if model_path and Path(model_path).is_file():
            _CACHE[key] = VulnerabilityClassifier.load(model_path)
        else:
            _CACHE[key] = VulnerabilityClassifier.default()
    return _CACHE[key]


# ------------------------------------------------------------------ training on datasets
CODE_KEYS = ("code", "func", "function", "source", "text", "func_before")
LABEL_KEYS = ("label", "target", "vul", "vulnerable", "is_vulnerable")


def load_dataset(path: str, limit: int = 0) -> Tuple[List[str], List[int]]:
    """Read a JSON Lines dataset. Accepts the field names used by PrimeVul, DiverseVul,
    Devign and BigVul (func/target) as well as code/label."""
    texts: List[str] = []
    labels: List[int] = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        first = handle.read(1)
        handle.seek(0)
        rows: Iterable[Any]
        if first == "[":
            rows = json.load(handle)
        else:
            rows = (json.loads(line) for line in handle if line.strip())
        for row in rows:
            code = next((row[k] for k in CODE_KEYS if row.get(k)), None)
            label = next((row[k] for k in LABEL_KEYS if k in row), None)
            if code is None or label is None:
                continue
            texts.append(str(code))
            labels.append(1 if str(label).strip().lower() in ("1", "true", "yes") else 0)
            if limit and len(texts) >= limit:
                break
    return texts, labels


def train_and_evaluate(texts: List[str], labels: List[int], source: str,
                       test_size: float = 0.2, seed: int = 42) -> Tuple[
                           VulnerabilityClassifier, Dict[str, float]]:
    """Train on a split of the data and report metrics on the held-out part."""
    from sklearn.metrics import (accuracy_score, f1_score, precision_score, recall_score,
                                 roc_auc_score)
    from sklearn.model_selection import train_test_split

    x_train, x_test, y_train, y_test = train_test_split(
        texts, labels, test_size=test_size, random_state=seed, stratify=labels)
    model = VulnerabilityClassifier.train(x_train, y_train, source)
    probabilities = model.score_many(x_test)
    predicted = [1 if p >= 0.5 else 0 for p in probabilities]
    metrics = {
        "train_samples": len(x_train), "test_samples": len(x_test),
        "accuracy": round(accuracy_score(y_test, predicted), 4),
        "precision": round(precision_score(y_test, predicted, zero_division=0), 4),
        "recall": round(recall_score(y_test, predicted, zero_division=0), 4),
        "f1": round(f1_score(y_test, predicted, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_test, probabilities), 4),
    }
    return model, metrics
