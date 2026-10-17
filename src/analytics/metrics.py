"""Security Metrics, KPI Calculations, and Posture Grading."""

from __future__ import annotations

from typing import Any, Dict
import pandas as pd


def calculate_posture_score(
    telemetry_df: pd.DataFrame,
    posture_findings: Dict[str, Any],
) -> Dict[str, Any]:
    """Calculate overall security posture score and risk breakdown.

    100 = Impeccable Posture, 0 = High Vulnerability State.
    """
    base_score = 100.0

    # Deductions based on findings
    n_impossible = len(posture_findings.get("impossible_travel", []))
    n_root = len(posture_findings.get("root_account_usage", []))
    n_wildcards = len(posture_findings.get("wildcard_privileges", []))
    n_dormant = len(posture_findings.get("dormant_admin_credentials", []))
    n_privesc = len(posture_findings.get("privilege_escalation_events", []))

    # Anomaly rate deduction
    n_anomalies = 0
    if "is_anomaly" in telemetry_df.columns:
        n_anomalies = int(telemetry_df["is_anomaly"].sum())

    total_events = max(len(telemetry_df), 1)
    anomaly_pct = (n_anomalies / total_events) * 100.0

    # Penalty weights
    penalty = (
        (n_impossible * 12.0)
        + (n_root * 15.0)
        + (n_wildcards * 8.0)
        + (n_privesc * 10.0)
        + (n_dormant * 4.0)
        + (min(anomaly_pct * 1.5, 25.0))
    )

    final_score = max(0.0, min(100.0, base_score - penalty))

    # Posture Grade
    if final_score >= 90:
        grade = "A (Secure)"
        color = "#10B981"  # Emerald
    elif final_score >= 75:
        grade = "B (Good)"
        color = "#3B82F6"  # Blue
    elif final_score >= 60:
        grade = "C (Needs Review)"
        color = "#F59E0B"  # Amber
    elif final_score >= 40:
        grade = "D (Poor)"
        color = "#F97316"  # Orange
    else:
        grade = "F (Critical Vulnerability)"
        color = "#EF4444"  # Red

    # Count findings by severity
    severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    if "severity" in telemetry_df.columns:
        anom_only = telemetry_df[telemetry_df.get("is_anomaly", False)]
        for sev, count in anom_only["severity"].value_counts().items():
            if sev in severities:
                severities[sev] += int(count)

    severities["Critical"] += n_impossible + n_root + n_privesc
    severities["High"] += n_wildcards
    severities["Medium"] += n_dormant

    return {
        "score": round(final_score, 1),
        "grade": grade,
        "grade_color": color,
        "total_events": len(telemetry_df),
        "total_anomalies": n_anomalies,
        "anomaly_rate_pct": round(anomaly_pct, 2),
        "impossible_travel_count": n_impossible,
        "root_abuse_count": n_root,
        "wildcard_count": n_wildcards,
        "dormant_count": n_dormant,
        "privesc_count": n_privesc,
        "severity_counts": severities,
    }


def get_top_risky_principals(df: pd.DataFrame, top_n: int = 5) -> pd.DataFrame:
    """Identify top cloud identities by aggregated risk score and anomaly count."""
    if len(df) == 0 or "risk_score" not in df.columns:
        return pd.DataFrame()

    summary = (
        df.groupby(["principal", "cloud_provider", "principal_type"])
        .agg(
            total_calls=("timestamp", "count"),
            anomaly_calls=("is_anomaly", "sum"),
            avg_risk=("risk_score", "mean"),
            max_risk=("risk_score", "max"),
        )
        .reset_index()
    )

    summary["avg_risk"] = summary["avg_risk"].round(1)
    summary["max_risk"] = summary["max_risk"].round(1)
    summary.sort_values(by=["max_risk", "anomaly_calls"], ascending=[False, False], inplace=True)
    return summary.head(top_n)
