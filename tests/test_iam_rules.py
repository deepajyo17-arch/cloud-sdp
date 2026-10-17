"""Unit tests for IAM posture and deterministic CIS benchmark rules."""

import pandas as pd

from src.analytics.iam_rules import (
    detect_impossible_travel,
    detect_root_account_usage,
    evaluate_iam_posture_rules,
    haversine_distance,
)
from src.data.generator import (
    generate_synthetic_iam_hierarchy,
    generate_synthetic_telemetry,
)


def test_haversine_distance():
    # Distance between NYC (40.7128, -74.0060) and London (51.5074, -0.1278) ~ 5570 km
    dist = haversine_distance(40.7128, -74.0060, 51.5074, -0.1278)
    assert 5500 < dist < 5650


def test_detect_impossible_travel():
    # Create two logins 10 mins apart from USA to RUS
    t0 = pd.Timestamp("2026-10-15T10:00:00Z")
    t1 = t0 + pd.Timedelta(minutes=10)
    df = pd.DataFrame(
        [
            {
                "timestamp": t0,
                "principal": "user@corp.com",
                "country_code": "USA",
                "country_name": "United States",
                "latitude": 37.7749,
                "longitude": -122.4194,
                "source_ip": "1.1.1.1",
            },
            {
                "timestamp": t1,
                "principal": "user@corp.com",
                "country_code": "RUS",
                "country_name": "Russia",
                "latitude": 55.7558,
                "longitude": 37.6173,
                "source_ip": "2.2.2.2",
            },
        ]
    )
    findings = detect_impossible_travel(df)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-GEO-001"
    assert findings[0]["principal"] == "user@corp.com"
    assert findings[0]["implied_speed_kmh"] > 1000.0


def test_detect_root_account_usage():
    df = pd.DataFrame(
        [
            {
                "timestamp": pd.Timestamp.now(tz="UTC"),
                "principal": "AWS:root",
                "principal_type": "Root",
                "cloud_provider": "AWS",
                "action": "DeleteTrail",
                "source_ip": "1.2.3.4",
                "country_name": "United States",
                "mfa_authenticated": False,
            }
        ]
    )
    findings = detect_root_account_usage(df)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CIS-AWS-1.1"


def test_evaluate_iam_posture_rules_full():
    df = generate_synthetic_telemetry(n_events=100, inject_attacks=True)
    hierarchy = generate_synthetic_iam_hierarchy()
    results = evaluate_iam_posture_rules(df, hierarchy)

    assert "impossible_travel" in results
    assert "root_account_usage" in results
    assert "wildcard_privileges" in results
    assert "dormant_admin_credentials" in results
    assert "privilege_escalation_events" in results

    assert len(results["wildcard_privileges"]) > 0
    assert len(results["impossible_travel"]) > 0
