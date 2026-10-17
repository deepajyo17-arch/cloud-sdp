"""Synthetic Telemetry and IAM Policy Generator.

Generates realistic multi-cloud audit logs containing benign corporate traffic
and realistic cyber attack scenarios:
1. Impossible Travel (Anomalous Geo-Logins)
2. IAM Privilege Escalation Chains
3. Root / Global Admin Misuse
4. Wildcard / Mass Resource Exposure
5. High-Velocity Off-Hours API Reconnaissance
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any, Dict, List
import pandas as pd

from src.config import COUNTRY_COORDINATES

BENIGN_USERS = [
    ("alice.smith@company.com", "IAMUser", "AWS", "USA"),
    ("bob.jones@company.com", "IAMUser", "AWS", "GBR"),
    ("charlie.chen@company.com", "IAMUser", "AWS", "SGP"),
    ("devops-deployer-role", "AssumedRole", "AWS", "USA"),
    ("sre-monitoring-sa@company.iam.gserviceaccount.com", "ServiceAccount", "GCP", "DEU"),
    ("claire.martin@company.com", "User", "Azure", "CAN"),
    ("rohit.sharma@company.com", "IAMUser", "AWS", "IND"),
    ("k8s-cluster-autoscaler", "AssumedRole", "AWS", "USA"),
    ("datadog-agent-sp", "ServicePrincipal", "Azure", "USA"),
]

BENIGN_ACTIONS = {
    "AWS": [
        ("DescribeInstances", "EC2"),
        ("GetCallerIdentity", "STS"),
        ("ListBuckets", "S3"),
        ("GetObject", "S3"),
        ("DescribeLogGroups", "CLOUDWATCH"),
        ("GetSecretValue", "SECRETSMANAGER"),
        ("DescribeDBInstances", "RDS"),
        ("GetParameter", "SSM"),
        ("DescribeKey", "KMS"),
    ],
    "Azure": [
        ("Microsoft.Compute/virtualMachines/read", "Microsoft.Compute"),
        ("Microsoft.Storage/storageAccounts/listKeys/action", "Microsoft.Storage"),
        ("Microsoft.Resources/subscriptions/resourceGroups/read", "Microsoft.Resources"),
        ("Microsoft.Network/networkSecurityGroups/read", "Microsoft.Network"),
        ("Microsoft.KeyVault/vaults/secrets/read", "Microsoft.KeyVault"),
    ],
    "GCP": [
        ("compute.instances.get", "COMPUTE"),
        ("storage.objects.get", "STORAGE"),
        ("logging.logEntries.list", "LOGGING"),
        ("monitoring.metricDescriptors.list", "MONITORING"),
        ("cloudresourcemanager.projects.get", "RESOURCEMANAGER"),
    ],
}


def generate_synthetic_telemetry(
    n_events: int = 1200,
    inject_attacks: bool = True,
    seed: int = 42,
) -> pd.DataFrame:
    """Generate realistic cloud audit telemetry with embedded security incidents."""
    random.seed(seed)
    records: List[Dict[str, Any]] = []

    base_time = datetime.utcnow() - timedelta(days=3)
    curr_time = base_time

    # 1. Generate Benign Baseline Traffic
    for _ in range(n_events):
        curr_time += timedelta(seconds=random.randint(45, 300))
        user_info = random.choice(BENIGN_USERS)
        principal, p_type, provider, default_country = user_info
        action, service = random.choice(BENIGN_ACTIONS[provider])

        # Baseline usually during daytime or automated services
        status = "Success"
        error_code = "None"
        is_error = False
        if random.random() < 0.03:
            status = "Failure"
            error_code = random.choice(
                ["AccessDenied", "ResourceNotFoundException", "Client.Unauthorized"]
            )
            is_error = True

        country_info = COUNTRY_COORDINATES[default_country]
        records.append(
            {
                "timestamp": curr_time,
                "cloud_provider": provider,
                "principal": principal,
                "principal_type": p_type,
                "action": action,
                "service": service,
                "resource": f"arn:cloud:{service.lower()}:prod-cluster-{random.randint(1, 4)}",
                "source_ip": f"198.51.{random.randint(10, 99)}.{random.randint(2, 250)}",
                "country_code": default_country,
                "country_name": country_info["name"],
                "latitude": country_info["lat"] + random.uniform(-0.8, 0.8),
                "longitude": country_info["lon"] + random.uniform(-0.8, 0.8),
                "status": status,
                "error_code": error_code,
                "is_error": is_error,
                "mfa_authenticated": True,
                "attack_type": "Benign",
            }
        )

    if not inject_attacks:
        df = pd.DataFrame(records)
        df.sort_values(by="timestamp", inplace=True)
        df.reset_index(drop=True, inplace=True)
        return df

    # =========================================================================
    # Attack Vector 1: Impossible Travel (Anomalous Geo-Login)
    # =========================================================================
    victim_user = "alice.smith@company.com"
    t_travel = base_time + timedelta(hours=26)

    # Legitimate login in San Francisco, USA
    c_usa = COUNTRY_COORDINATES["USA"]
    records.append(
        {
            "timestamp": t_travel,
            "cloud_provider": "AWS",
            "principal": victim_user,
            "principal_type": "IAMUser",
            "action": "ConsoleLogin",
            "service": "SIGNIN",
            "resource": "arn:aws:signin::console",
            "source_ip": "198.51.100.44",
            "country_code": "USA",
            "country_name": c_usa["name"],
            "latitude": 37.7749,
            "longitude": -122.4194,
            "status": "Success",
            "error_code": "None",
            "is_error": False,
            "mfa_authenticated": True,
            "attack_type": "Impossible Travel",
        }
    )

    # 14 minutes later: Anomaly login from Moscow, Russia (Physically impossible travel)
    c_rus = COUNTRY_COORDINATES["RUS"]
    records.append(
        {
            "timestamp": t_travel + timedelta(minutes=14),
            "cloud_provider": "AWS",
            "principal": victim_user,
            "principal_type": "IAMUser",
            "action": "ConsoleLogin",
            "service": "SIGNIN",
            "resource": "arn:aws:signin::console",
            "source_ip": "185.220.101.5",
            "country_code": "RUS",
            "country_name": c_rus["name"],
            "latitude": c_rus["lat"],
            "longitude": c_rus["lon"],
            "status": "Success",
            "error_code": "None",
            "is_error": False,
            "mfa_authenticated": False,  # MFA bypassed or session hijacking
            "attack_type": "Impossible Travel",
        }
    )

    # =========================================================================
    # Attack Vector 2: IAM Privilege Escalation Chain
    # =========================================================================
    compromised_user = "contractor-qa-temp"
    t_privesc = base_time + timedelta(hours=38)
    priv_actions = [
        ("iam:CreateAccessKey", "IAM", "USA"),
        ("iam:AttachUserPolicy", "IAM", "RUS"),
        ("iam:PassRole", "IAM", "RUS"),
        ("sts:AssumeRole", "STS", "RUS"),
    ]
    for idx, (p_act, p_srv, p_country) in enumerate(priv_actions):
        c_inf = COUNTRY_COORDINATES[p_country]
        records.append(
            {
                "timestamp": t_privesc + timedelta(minutes=idx * 3),
                "cloud_provider": "AWS",
                "principal": compromised_user,
                "principal_type": "IAMUser",
                "action": p_act,
                "service": p_srv,
                "resource": "arn:aws:iam::123456789012:policy/AdministratorAccess",
                "source_ip": "185.220.101.5" if p_country == "RUS" else "198.51.100.82",
                "country_code": p_country,
                "country_name": c_inf["name"],
                "latitude": c_inf["lat"],
                "longitude": c_inf["lon"],
                "status": "Success",
                "error_code": "None",
                "is_error": False,
                "mfa_authenticated": False,
                "attack_type": "Privilege Escalation",
            }
        )

    # =========================================================================
    # Attack Vector 3: AWS Root Account Misuse (CIS Benchmark Failure)
    # =========================================================================
    t_root = base_time + timedelta(hours=45)
    c_prk = COUNTRY_COORDINATES["PRK"]
    for idx, act in enumerate(["DeleteTrail", "StopLogging", "PutBucketPolicy"]):
        records.append(
            {
                "timestamp": t_root + timedelta(minutes=idx * 2),
                "cloud_provider": "AWS",
                "principal": "AWS:root",
                "principal_type": "Root",
                "action": act,
                "service": "CLOUDTRAIL" if "Trail" in act or "Logging" in act else "S3",
                "resource": "arn:aws:cloudtrail:us-east-1:123456789012:trail/security-trail",
                "source_ip": "175.45.176.8",
                "country_code": "PRK",
                "country_name": c_prk["name"],
                "latitude": c_prk["lat"],
                "longitude": c_prk["lon"],
                "status": "Success",
                "error_code": "None",
                "is_error": False,
                "mfa_authenticated": False,
                "attack_type": "Root Account Abuse",
            }
        )

    # =========================================================================
    # Attack Vector 4: High-Velocity Off-Hours API Reconnaissance Sweep
    # =========================================================================
    t_recon = base_time + timedelta(hours=52, minutes=15)  # 2:15 AM off-hours
    c_irn = COUNTRY_COORDINATES["IRN"]
    recon_actions = [
        "DescribeSecurityGroups",
        "DescribeInstances",
        "ListUsers",
        "ListRoles",
        "GetAccountSummary",
        "ListAccessKeys",
        "GetCredentialReport",
        "ListBuckets",
    ]
    for idx in range(85):
        records.append(
            {
                "timestamp": t_recon + timedelta(seconds=idx * 2),
                "cloud_provider": "AWS",
                "principal": "intruder-api-key",
                "principal_type": "IAMUser",
                "action": random.choice(recon_actions),
                "service": "EC2" if "Describe" in recon_actions[0] else "IAM",
                "resource": "arn:aws:all-resources:*",
                "source_ip": "5.253.204.12",
                "country_code": "IRN",
                "country_name": c_irn["name"],
                "latitude": c_irn["lat"] + random.uniform(-0.5, 0.5),
                "longitude": c_irn["lon"] + random.uniform(-0.5, 0.5),
                "status": "Success" if random.random() > 0.3 else "Failure",
                "error_code": "None" if random.random() > 0.3 else "UnauthorizedOperation",
                "is_error": random.random() <= 0.3,
                "mfa_authenticated": False,
                "attack_type": "API Reconnaissance",
            }
        )

    # =========================================================================
    # Attack Vector 5: Azure Mass Role Assignment
    # =========================================================================
    t_az = base_time + timedelta(hours=60)
    c_chn = COUNTRY_COORDINATES["CHN"]
    for idx in range(6):
        records.append(
            {
                "timestamp": t_az + timedelta(minutes=idx * 4),
                "cloud_provider": "Azure",
                "principal": "malicious-spn@azure.internal",
                "principal_type": "ServicePrincipal",
                "action": "Microsoft.Authorization/roleAssignments/write",
                "service": "Microsoft.Authorization",
                "resource": (
                    "/subscriptions/sub-999/providers/"
                    "Microsoft.Authorization/roleAssignments/ra-admin"
                ),
                "source_ip": "114.119.130.2",
                "country_code": "CHN",
                "country_name": c_chn["name"],
                "latitude": c_chn["lat"],
                "longitude": c_chn["lon"],
                "status": "Success",
                "error_code": "None",
                "is_error": False,
                "mfa_authenticated": False,
                "attack_type": "Privilege Escalation",
            }
        )

    df = pd.DataFrame(records)
    df.sort_values(by="timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


def generate_synthetic_iam_hierarchy() -> List[Dict[str, Any]]:
    """Generate structured IAM role-to-permission hierarchy for Sunburst visualization."""
    return [
        # AWS Account: Production
        {
            "cloud_provider": "AWS",
            "account_id": "123456789012 (Prod)",
            "role_name": "DevOps-Admin-Role",
            "identity_type": "Role",
            "service": "IAM",
            "permission": "iam:* (Wildcard Admin)",
            "risk_level": "Critical",
            "has_wildcard": True,
            "is_dormant": False,
        },
        {
            "cloud_provider": "AWS",
            "account_id": "123456789012 (Prod)",
            "role_name": "DevOps-Admin-Role",
            "identity_type": "Role",
            "service": "EC2",
            "permission": "ec2:* (Full Control)",
            "risk_level": "High",
            "has_wildcard": True,
            "is_dormant": False,
        },
        {
            "cloud_provider": "AWS",
            "account_id": "123456789012 (Prod)",
            "role_name": "DevOps-Admin-Role",
            "identity_type": "Role",
            "service": "S3",
            "permission": "s3:* (Public Bucket Access)",
            "risk_level": "High",
            "has_wildcard": True,
            "is_dormant": False,
        },
        {
            "cloud_provider": "AWS",
            "account_id": "123456789012 (Prod)",
            "role_name": "DataEngineering-Runner",
            "identity_type": "ServiceAccount",
            "service": "S3",
            "permission": "s3:GetObject",
            "risk_level": "Low",
            "has_wildcard": False,
            "is_dormant": False,
        },
        {
            "cloud_provider": "AWS",
            "account_id": "123456789012 (Prod)",
            "role_name": "DataEngineering-Runner",
            "identity_type": "ServiceAccount",
            "service": "S3",
            "permission": "s3:PutObject",
            "risk_level": "Low",
            "has_wildcard": False,
            "is_dormant": False,
        },
        {
            "cloud_provider": "AWS",
            "account_id": "123456789012 (Prod)",
            "role_name": "Legacy-Jenkins-Worker",
            "identity_type": "User",
            "service": "KMS",
            "permission": "kms:Decrypt",
            "risk_level": "Medium",
            "has_wildcard": False,
            "is_dormant": True,  # Dormant > 120 days
        },
        {
            "cloud_provider": "AWS",
            "account_id": "123456789012 (Prod)",
            "role_name": "Legacy-Jenkins-Worker",
            "identity_type": "User",
            "service": "IAM",
            "permission": "iam:PassRole",
            "risk_level": "Critical",
            "has_wildcard": False,
            "is_dormant": True,
        },
        # AWS Account: Staging / Dev
        {
            "cloud_provider": "AWS",
            "account_id": "987654321098 (Staging)",
            "role_name": "QA-Tester-Role",
            "identity_type": "Role",
            "service": "EC2",
            "permission": "ec2:DescribeInstances",
            "risk_level": "Low",
            "has_wildcard": False,
            "is_dormant": False,
        },
        {
            "cloud_provider": "AWS",
            "account_id": "987654321098 (Staging)",
            "role_name": "Contractor-Access-Role",
            "identity_type": "Role",
            "service": "IAM",
            "permission": "iam:AttachUserPolicy",
            "risk_level": "Critical",
            "has_wildcard": False,
            "is_dormant": False,
        },
        # Azure Subscription: Enterprise Production
        {
            "cloud_provider": "Azure",
            "account_id": "sub-prod-001 (Azure Prod)",
            "role_name": "GlobalAdministrator-SPN",
            "identity_type": "ServicePrincipal",
            "service": "Microsoft.Authorization",
            "permission": "roleAssignments/write (*)",
            "risk_level": "Critical",
            "has_wildcard": True,
            "is_dormant": False,
        },
        {
            "cloud_provider": "Azure",
            "account_id": "sub-prod-001 (Azure Prod)",
            "role_name": "GlobalAdministrator-SPN",
            "identity_type": "ServicePrincipal",
            "service": "Microsoft.Compute",
            "permission": "virtualMachines/*",
            "risk_level": "High",
            "has_wildcard": True,
            "is_dormant": False,
        },
        {
            "cloud_provider": "Azure",
            "account_id": "sub-prod-001 (Azure Prod)",
            "role_name": "WebBackend-Identity",
            "identity_type": "ManagedIdentity",
            "service": "Microsoft.Storage",
            "permission": "storageAccounts/blobServices/read",
            "risk_level": "Low",
            "has_wildcard": False,
            "is_dormant": False,
        },
        # GCP Project: Corporate Analytics
        {
            "cloud_provider": "GCP",
            "account_id": "corp-analytics-gcp",
            "role_name": "BigQuery-Orchestrator-SA",
            "identity_type": "ServiceAccount",
            "service": "BIGQUERY",
            "permission": "bigquery.tables.getData",
            "risk_level": "Low",
            "has_wildcard": False,
            "is_dormant": False,
        },
        {
            "cloud_provider": "GCP",
            "account_id": "corp-analytics-gcp",
            "role_name": "OverPrivileged-Compute-SA",
            "identity_type": "ServiceAccount",
            "service": "RESOURCEMANAGER",
            "permission": "resourcemanager.projects.setIamPolicy",
            "risk_level": "Critical",
            "has_wildcard": True,
            "is_dormant": False,
        },
    ]
