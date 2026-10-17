"""Deterministic CIS Benchmark and IAM Privilege Posture Evaluator."""

from __future__ import annotations

import math
from typing import Any, Dict, List
import pandas as pd

from src.config import HIGH_RISK_ACTIONS


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great circle distance between two points in kilometers."""
    r = 6371.0  # Earth's radius in km
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r * c


def detect_impossible_travel(df: pd.DataFrame, max_kmh: float = 800.0) -> List[Dict[str, Any]]:
    """Detect impossible travel: logins by the same principal from distant locations."""
    findings = []
    if "principal" not in df.columns or "latitude" not in df.columns or len(df) == 0:
        return findings

    # Sort strictly by timestamp
    sorted_df = df.sort_values(by="timestamp").copy()
    grouped = sorted_df.groupby("principal")

    for principal, group in grouped:
        if len(group) < 2:
            continue

        prev_row = None
        for _, curr_row in group.iterrows():
            if prev_row is not None:
                # Calculate time difference in hours
                t_diff_hours = (
                    curr_row["timestamp"] - prev_row["timestamp"]
                ).total_seconds() / 3600.0

                # Check if different country or distinct location
                if curr_row["country_code"] != prev_row["country_code"] and t_diff_hours > 0:
                    dist_km = haversine_distance(
                        prev_row["latitude"],
                        prev_row["longitude"],
                        curr_row["latitude"],
                        curr_row["longitude"],
                    )
                    speed_kmh = dist_km / max(t_diff_hours, 0.001)

                    # Threshold: impossible speed (>800 km/h) or under 30 mins between countries
                    if speed_kmh > max_kmh or (dist_km > 1000 and t_diff_hours < 1.0):
                        loc_a = f"{prev_row['country_name']} ({prev_row['country_code']})"
                        loc_b = f"{curr_row['country_name']} ({curr_row['country_code']})"
                        mins = round(t_diff_hours * 60, 1)
                        spd = round(speed_kmh, 0)
                        desc = (
                            f"Principal '{principal}' accessed cloud from "
                            f"{prev_row['country_name']} and then {curr_row['country_name']} "
                            f"within {mins} minutes (speed: {spd} km/h)."
                        )
                        findings.append(
                            {
                                "rule_id": "SEC-GEO-001",
                                "rule_name": "Impossible Travel Velocity",
                                "severity": "Critical",
                                "principal": principal,
                                "time_a": prev_row["timestamp"].isoformat(),
                                "location_a": loc_a,
                                "ip_a": prev_row["source_ip"],
                                "time_b": curr_row["timestamp"].isoformat(),
                                "location_b": loc_b,
                                "ip_b": curr_row["source_ip"],
                                "distance_km": round(dist_km, 1),
                                "duration_hours": round(t_diff_hours, 2),
                                "implied_speed_kmh": round(speed_kmh, 1),
                                "description": desc,
                            }
                        )
            prev_row = curr_row

    return findings


def detect_root_account_usage(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Flag dangerous Root / Global Admin account usage in telemetry."""
    findings = []
    root_events = df[
        (df["principal"] == "AWS:root")
        | (df["principal_type"] == "Root")
        | (df["principal"].str.contains("root", case=False, na=False))
        | (df["principal"].str.contains("GlobalAdmin", case=False, na=False))
    ]

    for _, row in root_events.iterrows():
        findings.append(
            {
                "rule_id": "CIS-AWS-1.1",
                "rule_name": "Root Account Active Usage",
                "severity": "Critical",
                "principal": row["principal"],
                "timestamp": row["timestamp"].isoformat(),
                "cloud_provider": row["cloud_provider"],
                "action": row["action"],
                "source_ip": row["source_ip"],
                "country": row["country_name"],
                "mfa_used": row.get("mfa_authenticated", False),
                "description": (
                    f"Root/Superadmin identity invoked '{row['action']}' from IP "
                    f"{row['source_ip']} in {row['country_name']} "
                    f"(MFA: {row.get('mfa_authenticated', False)})."
                ),
            }
        )

    return findings


def evaluate_iam_posture_rules(
    telemetry_df: pd.DataFrame,
    iam_hierarchy: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Execute full suite of IAM posture checks across telemetry and IAM hierarchy."""
    results: Dict[str, Any] = {
        "impossible_travel": detect_impossible_travel(telemetry_df),
        "root_account_usage": detect_root_account_usage(telemetry_df),
        "wildcard_privileges": [],
        "dormant_admin_credentials": [],
        "privilege_escalation_events": [],
    }

    # Analyze IAM hierarchy / policies for wildcards and dormant credentials
    if iam_hierarchy:
        for entry in iam_hierarchy:
            # 1. Wildcard check
            if entry.get("has_wildcard") or "*" in entry.get("permission", ""):
                perm_desc = (
                    f"Identity '{entry.get('role_name')}' holds wildcard permission "
                    f"'{entry.get('permission')}' on service '{entry.get('service')}' "
                    "violating principle of least privilege."
                )
                results["wildcard_privileges"].append(
                    {
                        "rule_id": "CIS-IAM-1.16",
                        "rule_name": "Excessive Wildcard Admin Privilege",
                        "severity": entry.get("risk_level", "Critical"),
                        "cloud_provider": entry.get("cloud_provider"),
                        "account_id": entry.get("account_id"),
                        "role_name": entry.get("role_name"),
                        "service": entry.get("service"),
                        "permission": entry.get("permission"),
                        "description": perm_desc,
                    }
                )

            # 2. Dormant credentials with sensitive access
            if entry.get("is_dormant"):
                dorm_desc = (
                    f"Identity '{entry.get('role_name')}' has had no activity for >90 days "
                    f"but retains elevated access '{entry.get('permission')}'."
                )
                results["dormant_admin_credentials"].append(
                    {
                        "rule_id": "CIS-IAM-1.3",
                        "rule_name": "Dormant Identity with High Privileges",
                        "severity": "High",
                        "cloud_provider": entry.get("cloud_provider"),
                        "account_id": entry.get("account_id"),
                        "role_name": entry.get("role_name"),
                        "service": entry.get("service"),
                        "permission": entry.get("permission"),
                        "description": dorm_desc,
                    }
                )

    # 3. Privilege Escalation API calls in telemetry
    all_high_risk = set()
    for prov_actions in HIGH_RISK_ACTIONS.values():
        all_high_risk.update(prov_actions)

    priv_esc_events = telemetry_df[telemetry_df["action"].isin(all_high_risk)]
    for _, row in priv_esc_events.iterrows():
        esc_desc = (
            f"Principal '{row['principal']}' executed known privilege escalation action "
            f"'{row['action']}' from {row['country_name']}."
        )
        results["privilege_escalation_events"].append(
            {
                "rule_id": "SEC-IAM-ESC",
                "rule_name": "Privilege Escalation Vector Executed",
                "severity": "Critical",
                "principal": row["principal"],
                "timestamp": row["timestamp"].isoformat(),
                "cloud_provider": row["cloud_provider"],
                "action": row["action"],
                "source_ip": row["source_ip"],
                "country": row["country_name"],
                "description": esc_desc,
            }
        )

    return results
