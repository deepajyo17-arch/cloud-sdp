"""Configuration module for Cloud Security & IAM Privilege Analyzer."""

import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLE_DATA_DIR = BASE_DIR / "sample_data"

# Application Settings
DEFAULT_CONTAMINATION_RATE = float(os.getenv("ANOMALY_CONTAMINATION_RATE", "0.05"))
DEFAULT_N_ESTIMATORS = int(os.getenv("ISOLATION_FOREST_ESTIMATORS", "150"))
RANDOM_STATE = 42

# Critical multi-cloud permissions (Privilege Escalation vectors)
HIGH_RISK_ACTIONS = {
    "AWS": [
        "iam:PassRole",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        "sts:AssumeRole",
        "s3:PutBucketPolicy",
        "s3:PutBucketAcl",
        "kms:ScheduleKeyDeletion",
    ],
    "Azure": [
        "Microsoft.Authorization/roleAssignments/write",
        "Microsoft.Authorization/roleDefinitions/write",
        "Microsoft.Resources/subscriptions/resourceGroups/write",
        "Microsoft.Compute/virtualMachines/runCommand/action",
    ],
    "GCP": [
        "resourcemanager.projects.setIamPolicy",
        "iam.serviceAccounts.actAs",
        "iam.serviceAccountKeys.create",
        "storage.buckets.setIamPolicy",
    ],
}

# Geolocation Reference Coordinates for Visualizations & Country mapping
COUNTRY_COORDINATES = {
    "USA": {"lat": 37.0902, "lon": -95.7129, "iso3": "USA", "name": "United States"},
    "GBR": {"lat": 55.3781, "lon": -3.4360, "iso3": "GBR", "name": "United Kingdom"},
    "DEU": {"lat": 51.1657, "lon": 10.4515, "iso3": "DEU", "name": "Germany"},
    "IND": {"lat": 20.5937, "lon": 78.9629, "iso3": "IND", "name": "India"},
    "SGP": {"lat": 1.3521, "lon": 103.8198, "iso3": "SGP", "name": "Singapore"},
    "AUS": {"lat": -25.2744, "lon": 133.7751, "iso3": "AUS", "name": "Australia"},
    "BRA": {"lat": -14.2350, "lon": -51.9253, "iso3": "BRA", "name": "Brazil"},
    "RUS": {"lat": 61.5240, "lon": 105.3188, "iso3": "RUS", "name": "Russia"},
    "CHN": {"lat": 35.8617, "lon": 104.1954, "iso3": "CHN", "name": "China"},
    "PRK": {"lat": 40.3399, "lon": 127.5101, "iso3": "PRK", "name": "North Korea"},
    "IRN": {"lat": 32.4279, "lon": 53.6880, "iso3": "IRN", "name": "Iran"},
    "NLD": {"lat": 52.1326, "lon": 5.2913, "iso3": "NLD", "name": "Netherlands"},
    "CAN": {"lat": 56.1304, "lon": -106.3468, "iso3": "CAN", "name": "Canada"},
    "JPN": {"lat": 36.2048, "lon": 138.2529, "iso3": "JPN", "name": "Japan"},
}
