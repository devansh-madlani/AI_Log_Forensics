import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np

from app.ml.anomaly_detector import AnomalyDetector, MIN_EVENTS_FOR_ML
from app.features.feature_extraction import extract_features
from app.demo.synthetic_data import generate
from app.normalizer.normalize import normalize_batch


def test_too_few_events_returns_zero_scores():
    detector = AnomalyDetector()
    import pandas as pd
    tiny_df = pd.DataFrame({"a": [1, 2], "b": [3, 4]})
    scores = detector.fit_predict(tiny_df)
    assert len(scores) == 2
    assert all(s == 0.0 for s in scores)


def test_empty_input_returns_empty_array():
    detector = AnomalyDetector()
    import pandas as pd
    scores = detector.fit_predict(pd.DataFrame())
    assert len(scores) == 0


def test_scores_are_normalized_between_0_and_1():
    raw = generate(num_normal_events=60)
    events = normalize_batch(raw)
    df = extract_features(events)
    detector = AnomalyDetector()
    scores = detector.fit_predict(df)
    assert len(scores) == len(events)
    assert scores.min() >= 0.0
    assert scores.max() <= 1.0 + 1e-9


def test_reproducible_with_fixed_seed():
    raw = generate(num_normal_events=60, seed=7)
    events_a = normalize_batch(raw)
    df_a = extract_features(events_a)
    scores_a = AnomalyDetector().fit_predict(df_a)

    events_b = normalize_batch(raw)
    df_b = extract_features(events_b)
    scores_b = AnomalyDetector().fit_predict(df_b)

    np.testing.assert_allclose(scores_a, scores_b, atol=1e-9)


def test_injected_attack_events_score_higher_on_average_than_normal():
    """
    Sanity check that the ML stage is actually doing something useful:
    the synthetic attack storyline events (suspicious PowerShell,
    unusual process, odd outbound connection, log clearing) should, on
    average, receive higher anomaly scores than ordinary background
    logons/app-launches.
    """
    raw = generate(num_normal_events=100)
    events = normalize_batch(raw)
    df = extract_features(events)
    scores = AnomalyDetector().fit_predict(df)

    attack_event_ids = {4740, 1102}  # lockout, log cleared - distinctive, rare event ids
    attack_scores = [s for e, s in zip(events, scores) if e.event_id in attack_event_ids]
    normal_scores = [s for e, s in zip(events, scores) if e.event_id in (4624, 4688) and e.user != "svc_backup"]

    assert len(attack_scores) > 0
    assert len(normal_scores) > 0
    assert np.mean(attack_scores) > np.mean(normal_scores)
