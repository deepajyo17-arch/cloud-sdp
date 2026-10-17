"""Behavioral Anomaly Detection Engine using Scikit-Learn IsolationForest."""

from __future__ import annotations

from typing import Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from src.config import (
    DEFAULT_CONTAMINATION_RATE,
    DEFAULT_N_ESTIMATORS,
    HIGH_RISK_ACTIONS,
    RANDOM_STATE,
)

FEATURE_COLUMNS = [
    "hour_sin",
    "hour_cos",
    "is_off_hours",
    "is_weekend",
    "call_velocity",
    "action_rarity",
    "is_error_flag",
    "mfa_missing_flag",
    "is_sensitive_action",
    "high_risk_country",
]


def extract_features(df: pd.DataFrame) -> Tuple[np.ndarray, pd.DataFrame]:
    """Engineer behavioral and temporal numerical features for IsolationForest."""
    feats = pd.DataFrame(index=df.index)

    # 1. Temporal cyclical features
    timestamps = pd.to_datetime(df["timestamp"], utc=True)
    hours = timestamps.dt.hour + timestamps.dt.minute / 60.0
    feats["hour_sin"] = np.sin(2 * np.pi * hours / 24.0)
    feats["hour_cos"] = np.cos(2 * np.pi * hours / 24.0)

    # 2. Off-hours and weekend indicators (UTC)
    feats["is_off_hours"] = ((hours < 6.0) | (hours > 20.0)).astype(float)
    feats["is_weekend"] = (timestamps.dt.dayofweek >= 5).astype(float)

    # 3. Call velocity (number of calls by the same principal in proximity)
    # Group by principal and calculate rolling density or frequency
    principal_counts = df.groupby("principal")["timestamp"].transform("count")
    # Normalize with log-scaling
    feats["call_velocity"] = np.log1p(principal_counts)

    # 4. Action rarity (inverse frequency of API action)
    action_counts = df["action"].value_counts()
    total_actions = len(df)
    action_freq = df["action"].map(action_counts) / max(total_actions, 1)
    # Rare actions yield values approaching 1.0, common actions approach 0.0
    feats["action_rarity"] = (1.0 - action_freq).fillna(0.5)

    # 5. Error flag (AccessDenied / Unauthorized)
    feats["is_error_flag"] = df["is_error"].astype(float)

    # 6. Missing MFA flag
    if "mfa_authenticated" in df.columns:
        feats["mfa_missing_flag"] = (~df["mfa_authenticated"]).astype(float)
    else:
        feats["mfa_missing_flag"] = 0.0

    # 7. Sensitive action check
    all_high_risk = set()
    for provider_actions in HIGH_RISK_ACTIONS.values():
        all_high_risk.update(provider_actions)

    feats["is_sensitive_action"] = df["action"].apply(
        lambda act: (
            1.0
            if act in all_high_risk or "iam:" in str(act).lower() or "role" in str(act).lower()
            else 0.0
        )
    )

    # 8. High-risk geopolitical origins / unusual destinations
    unusual_countries = {"RUS", "PRK", "IRN", "CHN"}
    feats["high_risk_country"] = df["country_code"].apply(
        lambda cc: 1.0 if str(cc).upper() in unusual_countries else 0.0
    )

    feature_matrix = feats[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    return feature_matrix, feats


class CloudAnomalyDetector:
    """IsolationForest behavioral anomaly detector for cloud telemetry."""

    def __init__(
        self,
        contamination: float = DEFAULT_CONTAMINATION_RATE,
        n_estimators: int = DEFAULT_N_ESTIMATORS,
        random_state: int = RANDOM_STATE,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.is_fitted = False

    def fit_predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fit IsolationForest on event features and return enriched DataFrame."""
        if len(df) == 0:
            return df.copy()

        X, feats_df = extract_features(df)
        self.model.fit(X)
        self.is_fitted = True

        # -1 = anomaly, 1 = normal
        labels = self.model.predict(X)
        raw_scores = self.model.decision_function(X)

        # Calibrate risk score to 0 - 100 range (higher = more dangerous)
        # Decision function is negative for anomalies, positive for normal
        min_score = np.min(raw_scores) if len(raw_scores) > 0 else -0.5
        max_score = np.max(raw_scores) if len(raw_scores) > 0 else 0.5
        range_span = max(max_score - min_score, 1e-6)

        # Invert: lower raw_score -> higher risk_score
        normalized_risk = 100.0 * (1.0 - (raw_scores - min_score) / range_span)

        # Generate human-readable reasons for anomalies
        reasons_list = []
        for idx in range(len(df)):
            reasons = []
            f_row = feats_df.iloc[idx]
            if f_row["high_risk_country"] > 0:
                reasons.append(
                    f"Unusual Geo-Origin ({df.iloc[idx].get('country_code', 'Unknown')})"
                )
            if f_row["is_sensitive_action"] > 0:
                reasons.append("High-Risk IAM / Auth API Method")
            if f_row["mfa_missing_flag"] > 0:
                reasons.append("Missing MFA Verification")
            if f_row["is_off_hours"] > 0:
                reasons.append("Off-Hours Execution Window")
            if f_row["is_error_flag"] > 0:
                reasons.append("Authorization Failure / Error")
            if f_row["action_rarity"] > 0.95:
                reasons.append("Statistically Rare API Call")
            if f_row["call_velocity"] > 4.0:
                reasons.append("High-Volume API Call Burst")

            # Default description if model flagged but no single threshold triggered
            if labels[idx] == -1 and not reasons:
                reasons.append("Multi-Dimensional IsolationForest Behavioral Outlier")
            elif labels[idx] == 1 and not reasons:
                reasons.append("Baseline Activity")

            reasons_list.append("; ".join(reasons))

        result_df = df.copy()
        result_df["anomaly_label"] = labels  # -1 for anomaly, 1 for inlier
        result_df["is_anomaly"] = labels == -1
        result_df["raw_anomaly_score"] = raw_scores
        result_df["risk_score"] = np.round(normalized_risk, 1)
        result_df["anomaly_reasons"] = reasons_list

        # Severity Categorization
        def _get_severity(score: float, is_anom: bool) -> str:
            if is_anom and score >= 80:
                return "Critical"
            elif is_anom and score >= 60:
                return "High"
            elif score >= 40:
                return "Medium"
            return "Low"

        result_df["severity"] = [
            _get_severity(s, a) for s, a in zip(result_df["risk_score"], result_df["is_anomaly"])
        ]

        return result_df
