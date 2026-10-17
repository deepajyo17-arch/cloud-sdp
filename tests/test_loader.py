import io
from pathlib import Path
import pandas as pd

from src.data.loader import (
    load_telemetry_from_csv,
    load_telemetry_from_json,
    normalize_aws_event,
    normalize_azure_event,
    normalize_gcp_event,
)


def test_normalize_aws_event():
    aws_event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "test.user",
            "arn": "arn:aws:iam::123456789012:user/test.user",
        },
        "eventTime": "2026-10-15T10:00:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "sourceIPAddress": "198.51.100.1",
        "countryCode": "USA",
    }
    normalized = normalize_aws_event(aws_event)
    assert normalized["cloud_provider"] == "AWS"
    assert normalized["principal"] == "test.user"
    assert normalized["action"] == "CreateAccessKey"
    assert normalized["service"] == "IAM"
    assert normalized["country_code"] == "USA"
    assert normalized["country_name"] == "United States"
    assert not normalized["is_error"]


def test_normalize_azure_event():
    azure_event = {
        "eventTimestamp": "2026-10-15T12:00:00Z",
        "caller": "admin@contoso.com",
        "operationName": {"value": "Microsoft.Compute/virtualMachines/restart/action"},
        "callerIpAddress": "203.0.113.5",
        "countryCode": "GBR",
        "status": {"value": "Succeeded"},
    }
    normalized = normalize_azure_event(azure_event)
    assert normalized["cloud_provider"] == "Azure"
    assert normalized["principal"] == "admin@contoso.com"
    assert "Microsoft.Compute" in normalized["service"]
    assert normalized["country_code"] == "GBR"
    assert not normalized["is_error"]


def test_normalize_gcp_event():
    gcp_event = {
        "timestamp": "2026-10-15T14:00:00Z",
        "countryCode": "DEU",
        "protoPayload": {
            "serviceName": "storage.googleapis.com",
            "methodName": "storage.buckets.get",
            "authenticationInfo": {"principalEmail": "sa@project.iam.gserviceaccount.com"},
            "requestMetadata": {"callerIp": "198.51.100.99"},
            "status": {"code": 0},
        },
    }
    normalized = normalize_gcp_event(gcp_event)
    assert normalized["cloud_provider"] == "GCP"
    assert normalized["principal"] == "sa@project.iam.gserviceaccount.com"
    assert normalized["principal_type"] == "ServiceAccount"
    assert normalized["action"] == "storage.buckets.get"
    assert normalized["country_code"] == "DEU"


def test_load_telemetry_from_json_sample():
    sample_path = Path("sample_data/aws_cloudtrail_sample.json")
    if sample_path.exists():
        with open(sample_path, "r") as f:
            df = load_telemetry_from_json(f.read())
        assert isinstance(df, pd.DataFrame)
        assert len(df) > 0
        assert "principal" in df.columns
        assert "action" in df.columns


def test_load_telemetry_from_csv():
    csv_data = io.StringIO(
        "eventTime,userName,eventName,sourceIPAddress,countryCode\n"
        "2026-10-15T12:00:00Z,analyst@company.com,DescribeInstances,1.2.3.4,USA\n"
    )
    df = load_telemetry_from_csv(csv_data)
    assert len(df) == 1
    assert df.iloc[0]["principal"] == "analyst@company.com"
    assert df.iloc[0]["action"] == "DescribeInstances"
