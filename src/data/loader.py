"""Telemetry Loader for Multi-Cloud Security Audit Logs.

Supports:
- AWS CloudTrail Events (JSON / CSV)
- Azure Activity Logs (JSON / CSV)
- Google Cloud Audit Logs (JSON / CSV)
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List
import pandas as pd

from src.config import COUNTRY_COORDINATES


def _lookup_geo(country_code: str) -> tuple[str, float, float]:
    """Resolve country metadata and lat/long coordinates."""
    info = COUNTRY_COORDINATES.get(
        country_code.upper(),
        {"name": country_code, "lat": 0.0, "lon": 0.0, "iso3": country_code},
    )
    return info["name"], info["lat"], info["lon"]


def normalize_aws_event(record: Dict[str, Any]) -> Dict[str, Any]:
    """Extract standard schema from an AWS CloudTrail record."""
    user_id = record.get("userIdentity", {})
    principal_type = user_id.get("type", "Unknown")
    principal = (
        user_id.get("userName")
        or user_id.get("principalId")
        or user_id.get("arn", "UnknownPrincipal")
    )
    if principal_type == "Root":
        principal = "AWS:root"

    # Action and Service
    action = record.get("eventName", "UnknownAction")
    event_source = record.get("eventSource", "")
    service = event_source.replace(".amazonaws.com", "").upper() if event_source else "AWS"

    # Region and Geolocation
    country_code = record.get("countryCode") or record.get("country", "USA")
    country_name, lat, lon = _lookup_geo(country_code)

    # Status / Errors
    error_code = record.get("errorCode")
    is_error = error_code is not None and str(error_code).strip() != ""
    status = "Failure" if is_error else "Success"

    # Timestamp
    raw_time = record.get("eventTime") or datetime.utcnow().isoformat()

    req_params = record.get("requestParameters") or {}
    session_ctx = (user_id.get("sessionContext") or {}) if isinstance(user_id, dict) else {}
    session_attrs = (session_ctx.get("attributes") or {}) if isinstance(session_ctx, dict) else {}

    return {
        "timestamp": pd.to_datetime(raw_time, utc=True),
        "cloud_provider": "AWS",
        "principal": str(principal),
        "principal_type": str(principal_type),
        "action": str(action),
        "service": str(service),
        "resource": (
            str(req_params.get("resourceName") or "arn:aws")
            if isinstance(req_params, dict)
            else "arn:aws"
        ),
        "source_ip": str(record.get("sourceIPAddress", "127.0.0.1")),
        "country_code": country_code.upper(),
        "country_name": country_name,
        "latitude": lat,
        "longitude": lon,
        "status": status,
        "error_code": error_code or "None",
        "is_error": is_error,
        "mfa_authenticated": bool(
            session_attrs.get("mfaAuthenticated", False)
            if isinstance(session_attrs, dict)
            else False
        ),
        "raw_payload": json.dumps(record),
    }


def normalize_azure_event(record: Dict[str, Any]) -> Dict[str, Any]:
    """Extract standard schema from an Azure Activity Log record."""
    claims = record.get("claims") or {}
    if not isinstance(claims, dict):
        claims = {}

    principal = (
        record.get("caller")
        or claims.get("name")
        or claims.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn")
        or "AzurePrincipal"
    )

    op_name = record.get("operationName")
    if isinstance(op_name, dict):
        action = op_name.get("value") or "AzureAction"
    else:
        action = op_name or "AzureAction"

    service = str(action).split("/")[0] if "/" in str(action) else "Azure"

    country_code = record.get("countryCode") or record.get("country", "USA")
    country_name, lat, lon = _lookup_geo(country_code)

    st_obj = record.get("status")
    if isinstance(st_obj, dict):
        status_val = st_obj.get("value") or "Succeeded"
    else:
        status_val = st_obj or "Succeeded"

    is_error = str(status_val).lower() not in ["succeeded", "success", "accepted"]

    raw_time = record.get("eventTimestamp") or record.get("time") or datetime.utcnow().isoformat()

    amr_list = claims.get("amr")
    has_mfa = False
    if isinstance(amr_list, list) and len(amr_list) > 0:
        has_mfa = "mfa" in [str(x).lower() for x in amr_list]

    return {
        "timestamp": pd.to_datetime(raw_time, utc=True),
        "cloud_provider": "Azure",
        "principal": str(principal),
        "principal_type": "ServicePrincipal" if "appId" in claims else "User",
        "action": str(action),
        "service": str(service),
        "resource": str(record.get("resourceId") or "subscriptions/azure"),
        "source_ip": str(record.get("callerIpAddress", "127.0.0.1")),
        "country_code": country_code.upper(),
        "country_name": country_name,
        "latitude": lat,
        "longitude": lon,
        "status": "Failure" if is_error else "Success",
        "error_code": str(status_val) if is_error else "None",
        "is_error": is_error,
        "mfa_authenticated": has_mfa,
        "raw_payload": json.dumps(record),
    }


def normalize_gcp_event(record: Dict[str, Any]) -> Dict[str, Any]:
    """Extract standard schema from a Google Cloud Audit Log record."""
    proto = record.get("protoPayload") or {}
    if not isinstance(proto, dict):
        proto = {}

    auth_info = proto.get("authenticationInfo") or {}
    if not isinstance(auth_info, dict):
        auth_info = {}

    principal = auth_info.get("principalEmail", "gcp-user@service.internal")

    principal_type = "ServiceAccount" if "gserviceaccount.com" in principal else "User"
    action = proto.get("methodName", "gcp.method.unknown")
    service = str(proto.get("serviceName", "gcp.googleapis.com")).split(".")[0].upper()

    req_meta = proto.get("requestMetadata") or {}
    source_ip = req_meta.get("callerIp", "127.0.0.1") if isinstance(req_meta, dict) else "127.0.0.1"

    country_code = record.get("countryCode") or record.get("country", "USA")
    country_name, lat, lon = _lookup_geo(country_code)

    proto_status = proto.get("status") or {}
    is_error = (
        isinstance(proto_status, dict) and "code" in proto_status and proto_status["code"] != 0
    )

    raw_time = record.get("timestamp") or datetime.utcnow().isoformat()

    return {
        "timestamp": pd.to_datetime(raw_time, utc=True),
        "cloud_provider": "GCP",
        "principal": str(principal),
        "principal_type": principal_type,
        "action": str(action),
        "service": str(service),
        "resource": str(proto.get("resourceName") or "projects/gcp"),
        "source_ip": str(source_ip),
        "country_code": country_code.upper(),
        "country_name": country_name,
        "latitude": lat,
        "longitude": lon,
        "status": "Failure" if is_error else "Success",
        "error_code": (
            str(proto_status.get("message", "None"))
            if isinstance(proto_status, dict) and is_error
            else "None"
        ),
        "is_error": is_error,
        "mfa_authenticated": False,
        "raw_payload": json.dumps(record),
    }


def load_telemetry_from_json(json_content: str | bytes | List[Dict[str, Any]]) -> pd.DataFrame:
    """Parse JSON strings, arrays, or files and auto-detect provider schemas."""
    if isinstance(json_content, (str, bytes)):
        data = json.loads(json_content)
    else:
        data = json_content

    # Handle CloudTrail wrapped structure {"Records": [...]}
    if isinstance(data, dict):
        if "Records" in data:
            records = data["Records"]
        elif "records" in data:
            records = data["records"]
        else:
            records = [data]
    elif isinstance(data, list):
        records = data
    else:
        raise ValueError("Invalid JSON log format. Expected list or object with Records.")

    normalized_rows = []
    for record in records:
        if not isinstance(record, dict):
            continue
        # Provider identification heuristics
        if "userIdentity" in record or "eventSource" in record:
            normalized_rows.append(normalize_aws_event(record))
        elif "callerIpAddress" in record or "claims" in record or "operationName" in record:
            normalized_rows.append(normalize_azure_event(record))
        elif "protoPayload" in record:
            normalized_rows.append(normalize_gcp_event(record))
        else:
            # Generic fallback
            provider = record.get("cloud_provider", "AWS")
            if provider == "Azure":
                normalized_rows.append(normalize_azure_event(record))
            elif provider == "GCP":
                normalized_rows.append(normalize_gcp_event(record))
            else:
                normalized_rows.append(normalize_aws_event(record))

    if not normalized_rows:
        return pd.DataFrame()

    df = pd.DataFrame(normalized_rows)
    df.sort_values(by="timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


def load_telemetry_from_csv(csv_path_or_buffer: Any) -> pd.DataFrame:
    """Parse CSV logs and normalize to unified schema."""
    df = pd.read_csv(csv_path_or_buffer)

    # Standardize column names
    col_mapping = {
        "eventTime": "timestamp",
        "eventTimestamp": "timestamp",
        "eventName": "action",
        "operationName": "action",
        "methodName": "action",
        "sourceIPAddress": "source_ip",
        "callerIpAddress": "source_ip",
        "callerIp": "source_ip",
        "userName": "principal",
        "caller": "principal",
        "principalEmail": "principal",
    }
    df.rename(columns=col_mapping, inplace=True)

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    else:
        df["timestamp"] = pd.date_range(
            end=pd.Timestamp.now(tz="UTC"), periods=len(df), freq="1min"
        )

    for col, default in [
        ("cloud_provider", "AWS"),
        ("principal", "admin"),
        ("principal_type", "IAMUser"),
        ("action", "DescribeInstances"),
        ("service", "EC2"),
        ("resource", "arn:aws"),
        ("source_ip", "192.168.1.1"),
        ("country_code", "USA"),
        ("status", "Success"),
        ("error_code", "None"),
        ("is_error", False),
        ("mfa_authenticated", True),
    ]:
        if col not in df.columns:
            df[col] = default

    # Geolocation mapping
    geo_data = [_lookup_geo(str(cc)) for cc in df["country_code"]]
    df["country_name"] = [g[0] for g in geo_data]
    df["latitude"] = [g[1] for g in geo_data]
    df["longitude"] = [g[2] for g in geo_data]

    df.sort_values(by="timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df
