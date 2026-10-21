"""Layer 2: a small trained classifier (TF-IDF + logistic regression). Fast, cheap, retrainable."""
from __future__ import annotations

import math
import pickle

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from .base import InputLayer, Verdict
from .textnorm import normalize


def _prep(t: str) -> str:
    return normalize(t)


def make_pipeline(C: float = 8.0) -> Pipeline:
    feats = FeatureUnion([
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True)),
        ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=1, sublinear_tf=True)),
    ])
    return Pipeline([("f", feats), ("lr", LogisticRegression(C=C, max_iter=2000, class_weight="balanced"))])


class ClassifierLayer(InputLayer):
    name = "clf_in"

    def __init__(self, threshold: float = 0.5, C: float = 8.0):
        self.threshold, self.C, self.pipe = threshold, C, make_pipeline(C)

    def fit(self, texts: list[str], labels: list[int]) -> "ClassifierLayer":
        self.pipe.fit([_prep(t) for t in texts], labels)
        return self

    def score(self, text: str) -> float:
        return float(self.pipe.predict_proba([_prep(text)])[0, 1])

    def scores(self, texts: list[str]) -> list[float]:
        return [float(x) for x in self.pipe.predict_proba([_prep(t) for t in texts])[:, 1]]

    def check(self, text: str) -> Verdict:
        s = self.score(text)
        return Verdict(s >= self.threshold, s, self.name, f"p={s:.2f}")

    def save(self, path: str) -> None:
        with open(path, "wb") as f:
            pickle.dump(self, f)

    @staticmethod
    def load(path: str) -> "ClassifierLayer":
        with open(path, "rb") as f:
            return pickle.load(f)


def calibrate(texts, labels, groups, target_fpr: float = 0.02, attack_miss: float = 0.05, folds: int = 5, C: float = 8.0):
    """Pick operating thresholds from OUT-OF-FOLD scores (folds grouped by template, so no leakage).

    hi: score above which we block outright; chosen so ~target_fpr of benign training text would be blocked.
    lo: score below which we let text through without asking the judge; chosen so ~attack_miss of
        attack training text falls below it.
    """
    from sklearn.model_selection import GroupKFold, cross_val_predict
    oof = cross_val_predict(make_pipeline(C), [_prep(t) for t in texts], labels, groups=groups,
                            cv=GroupKFold(n_splits=folds), method="predict_proba")[:, 1]
    ben = sorted(p for p, y in zip(oof, labels) if y == 0)
    atk = sorted(p for p, y in zip(oof, labels) if y == 1)
    hi = min(1.0, ben[min(len(ben) - 1, math.ceil((1 - target_fpr) * len(ben)) - 1)] + 1e-6)
    lo = atk[int(attack_miss * len(atk))]
    return float(hi), float(min(lo, hi - 0.05))
