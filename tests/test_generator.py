"""Unit tests for synthetic data and attack scenario generator."""

import pandas as pd

from src.data.generator import (
    generate_synthetic_iam_hierarchy,
    generate_synthetic_telemetry,
)


def test_generate_synthetic_telemetry_clean():
    df = generate_synthetic_telemetry(n_events=50, inject_attacks=False)
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 50
    assert "timestamp" in df.columns
    assert "cloud_provider" in df.columns
    assert "attack_type" in df.columns
    assert (df["attack_type"] == "Benign").all()


def test_generate_synthetic_telemetry_with_attacks():
    df = generate_synthetic_telemetry(n_events=100, inject_attacks=True)
    assert len(df) > 100
    attack_types = set(df["attack_type"].unique())
    assert "Impossible Travel" in attack_types
    assert "Privilege Escalation" in attack_types
    assert "Root Account Abuse" in attack_types


def test_generate_synthetic_iam_hierarchy():
    hierarchy = generate_synthetic_iam_hierarchy()
    assert isinstance(hierarchy, list)
    assert len(hierarchy) > 0
    first = hierarchy[0]
    assert "cloud_provider" in first
    assert "role_name" in first
    assert "permission" in first
    assert "risk_level" in first
