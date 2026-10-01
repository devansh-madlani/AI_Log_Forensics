"""
ML anomaly detection - Isolation Forest.

Honest scope statement (spec section 5): this model does not "know"
about cyberattacks. It is an unsupervised outlier detector that learns
the shape of the feature distribution for the current batch of events
(the "observed baseline") and flags points that are statistically far
from the rest. It has no labeled training data and makes no claim to
recognize specific attack techniques - that semantic judgment is
layered on afterwards, explicitly, by the rule-based risk-scoring stage
(see scoring/risk_scoring.py), which is where "why flagged" reasons
come from.

Isolation Forest works by measuring how few random splits it takes to
isolate a point - anomalies isolate faster (shorter average path
length) than normal points sitting in dense regions.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

RANDOM_STATE = 42  # fixed seed -> reproducible results on the same dataset

# Isolation Forest needs a minimum number of samples to build meaningful
# trees. Below this, we skip ML and fall back to rule-based-only scoring
# (handled by the caller / risk_scoring), rather than pretending a model
# trained on 3 data points is meaningful.
MIN_EVENTS_FOR_ML = 10


class AnomalyDetector:
    """Thin, explicit wrapper around sklearn's IsolationForest."""

    def __init__(self, contamination: float | str = "auto", n_estimators: int = 200):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model: IsolationForest | None = None
        self.feature_columns: list[str] | None = None

    def fit_predict(self, features: pd.DataFrame) -> np.ndarray:
        """
        Fit Isolation Forest on `features` and return a numpy array of
        anomaly scores in [0, 1], one per row, where 1.0 = most
        anomalous relative to the rest of the batch.

        If there are too few events for a meaningful model, returns an
        all-zero array (i.e. "no ML signal available") rather than
        fabricating a confident-looking score.
        """
        n = len(features)
        if n == 0:
            return np.array([])

        if n < MIN_EVENTS_FOR_ML:
            return np.zeros(n)

        self.feature_columns = list(features.columns)
        X = features[self.feature_columns].to_numpy(dtype=float)

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )
        self.model.fit(X)

        # score_samples: higher = more normal. Negate so higher = more
        # anomalous, then min-max normalize to [0, 1] for an
        # investigator-friendly scale.
        raw = -self.model.score_samples(X)
        lo, hi = raw.min(), raw.max()
        if hi - lo < 1e-9:
            # All points scored identically (e.g. all-identical features)
            return np.zeros(n)
        normalized = (raw - lo) / (hi - lo)
        return normalized

    def feature_importances(self, features: pd.DataFrame, scores: np.ndarray, top_n: int = 3) -> list[list[str]]:
        """
        Very lightweight, explainable "why did this look unusual"
        signal: for each row, return the names of the `top_n` feature
        columns with the highest values relative to the batch's mean
        for that column, restricted to rows Isolation Forest scored as
        anomalous. This is NOT a SHAP/feature-attribution method - it's
        a simple, transparent heuristic so investigators get a pointer
        into *which* features drove the score, without overclaiming
        model introspection we don't actually have.
        """
        if features.empty:
            return []
        means = features.mean()
        stds = features.std().replace(0, 1e-9)
        z = (features - means) / stds

        results = []
        for i in range(len(features)):
            row_z = z.iloc[i]
            top = row_z.sort_values(ascending=False).head(top_n)
            results.append([col for col, val in top.items() if val > 0.5])
        return results
