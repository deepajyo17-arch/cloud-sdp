"""Unit tests for IsolationForest anomaly detection engine."""

import numpy as np
import pandas as pd

from src.analytics.anomaly import CloudAnomalyDetector, extract_features
from src.data.generator import generate_synthetic_telemetry


def test_extract_features():
    df = generate_synthetic_telemetry(n_events=40, inject_attacks=True)
    X, feats_df = extract_features(df)
    assert isinstance(X, np.ndarray)
    assert X.shape[0] == len(df)
    assert not np.isnan(X).any()
    assert "hour_sin" in feats_df.columns
    assert "call_velocity" in feats_df.columns
    assert "action_rarity" in feats_df.columns


def test_cloud_anomaly_detector():
    df = generate_synthetic_telemetry(n_events=120, inject_attacks=True)
    detector = CloudAnomalyDetector(contamination=0.1)
    result_df = detector.fit_predict(df)

    assert "is_anomaly" in result_df.columns
    assert "risk_score" in result_df.columns
    assert "severity" in result_df.columns
    assert "anomaly_reasons" in result_df.columns

    # Verify score bounds
    assert result_df["risk_score"].min() >= 0.0
    assert result_df["risk_score"].max() <= 100.0

    # Verify at least one anomaly was flagged
    assert result_df["is_anomaly"].sum() > 0


def test_anomaly_detector_empty_df():
    detector = CloudAnomalyDetector()
    empty_df = pd.DataFrame()
    result = detector.fit_predict(empty_df)
    assert result.empty
