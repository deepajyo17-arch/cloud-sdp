"""Unit tests for security posture metrics and scoring."""

import pandas as pd

from src.analytics.metrics import calculate_posture_score, get_top_risky_principals


def test_calculate_posture_score_clean():
    clean_df = pd.DataFrame(
        [
            {
                "timestamp": pd.Timestamp.now(tz="UTC"),
                "is_anomaly": False,
                "severity": "Low",
                "risk_score": 10.0,
            }
        ]
    )
    findings = {
        "impossible_travel": [],
        "root_account_usage": [],
        "wildcard_privileges": [],
        "dormant_admin_credentials": [],
        "privilege_escalation_events": [],
    }
    summary = calculate_posture_score(clean_df, findings)
    assert summary["score"] >= 95.0
    assert "A" in summary["grade"]


def test_calculate_posture_score_compromised():
    dirty_df = pd.DataFrame(
        [
            {
                "timestamp": pd.Timestamp.now(tz="UTC"),
                "is_anomaly": True,
                "severity": "Critical",
                "risk_score": 95.0,
            }
            for _ in range(10)
        ]
    )
    findings = {
        "impossible_travel": [{"rule_id": "SEC-GEO-001"}],
        "root_account_usage": [{"rule_id": "CIS-AWS-1.1"}],
        "wildcard_privileges": [{"rule_id": "CIS-IAM-1.16"}],
        "dormant_admin_credentials": [{"rule_id": "CIS-IAM-1.3"}],
        "privilege_escalation_events": [{"rule_id": "SEC-IAM-ESC"}],
    }
    summary = calculate_posture_score(dirty_df, findings)
    assert summary["score"] < 60.0
    assert summary["severity_counts"]["Critical"] > 0


def test_get_top_risky_principals():
    df = pd.DataFrame(
        [
            {
                "timestamp": pd.Timestamp.now(tz="UTC"),
                "principal": "user.safe",
                "cloud_provider": "AWS",
                "principal_type": "IAMUser",
                "is_anomaly": False,
                "risk_score": 12.0,
            },
            {
                "timestamp": pd.Timestamp.now(tz="UTC"),
                "principal": "attacker.root",
                "cloud_provider": "AWS",
                "principal_type": "Root",
                "is_anomaly": True,
                "risk_score": 98.0,
            },
        ]
    )
    top_df = get_top_risky_principals(df, top_n=1)
    assert len(top_df) == 1
    assert top_df.iloc[0]["principal"] == "attacker.root"
