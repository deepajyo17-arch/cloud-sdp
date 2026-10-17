"""Cloud Security Posture & IAM Privilege Analyzer - Streamlit Application."""

from __future__ import annotations

from pathlib import Path
import sys

# Ensure project root is in sys.path for direct Streamlit execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import streamlit as st

from src.analytics.anomaly import CloudAnomalyDetector
from src.analytics.iam_rules import evaluate_iam_posture_rules
from src.analytics.metrics import calculate_posture_score, get_top_risky_principals
from src.config import DEFAULT_CONTAMINATION_RATE, SAMPLE_DATA_DIR
from src.data.generator import (
    generate_synthetic_iam_hierarchy,
    generate_synthetic_telemetry,
)
from src.data.loader import (
    load_telemetry_from_csv,
    load_telemetry_from_json,
)
from src.visualization.charts import (
    create_anomaly_score_distribution,
    create_severity_donut,
    create_timeline_chart,
)
from src.visualization.geo_map import create_anomalous_geo_map
from src.visualization.sunburst import create_iam_sunburst_chart

# Page configuration
st.set_page_config(
    page_title="Cloud Security Posture & IAM Privilege Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for polished styling
st.markdown(
    """
    <style>
    .metric-card {
        background-color: #1e293b;
        border-radius: 8px;
        padding: 16px;
        border-left: 5px solid #3b82f6;
        margin-bottom: 12px;
    }
    .badge-critical {
        background-color: #ef4444;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-high {
        background-color: #f97316;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
    }
    .badge-medium {
        background-color: #f59e0b;
        color: black;
        padding: 3px 8px;
        border-radius: 4px;
    }
    .badge-low {
        background-color: #10b981;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data
def get_synthetic_data(n_events: int, inject_attacks: bool) -> tuple[pd.DataFrame, list]:
    df = generate_synthetic_telemetry(n_events=n_events, inject_attacks=inject_attacks)
    hierarchy = generate_synthetic_iam_hierarchy()
    return df, hierarchy


def main():
    st.title("🛡️ Cloud Security Posture & IAM Privilege Analyzer")
    st.caption(
        "Multi-Cloud Behavioral Anomaly Detection (IsolationForest), "
        "IAM Privilege Hierarchy, and CIS Benchmark Posture Engine"
    )

    # Sidebar: Controls & Ingestion
    with st.sidebar:
        st.header("⚙️ Configuration & Data Source")

        data_source = st.selectbox(
            "Telemetry Ingestion Source",
            [
                "Synthetic Multi-Cloud Threat Generator (Recommended)",
                "Sample AWS CloudTrail Log",
                "Sample Azure Activity Log",
                "Sample GCP Audit Log",
                "Upload Custom JSON / CSV",
            ],
        )

        n_events = 1200
        inject_attacks = True
        uploaded_file = None

        if data_source == "Synthetic Multi-Cloud Threat Generator (Recommended)":
            n_events = st.slider("Simulated Events Count", 200, 3000, 1200, step=100)
            inject_attacks = st.checkbox("Inject Realistic Cyber Attack Scenarios", value=True)
        elif data_source == "Upload Custom JSON / CSV":
            uploaded_file = st.file_uploader(
                "Upload Audit Telemetry (CloudTrail, Azure Activity, GCP Audit)",
                type=["json", "csv"],
            )

        st.divider()
        st.subheader("🤖 IsolationForest Tuning")
        contamination_rate = st.slider(
            "Anomaly Contamination Rate",
            min_value=0.01,
            max_value=0.20,
            value=DEFAULT_CONTAMINATION_RATE,
            step=0.01,
            help="Expected proportion of anomalies in the dataset.",
        )

        st.divider()
        st.markdown("""
            **DevOps Toolchain:**
            - Python 3.11 & Streamlit
            - IsolationForest (scikit-learn)
            - Multi-Stage Docker & DevContainers
            - Trivy DevSecOps Gate
            - Kubernetes Ready
            """)

    # Ingestion Logic
    raw_df = pd.DataFrame()
    iam_hierarchy = generate_synthetic_iam_hierarchy()

    if data_source == "Synthetic Multi-Cloud Threat Generator (Recommended)":
        raw_df, iam_hierarchy = get_synthetic_data(n_events, inject_attacks)
    elif data_source == "Sample AWS CloudTrail Log":
        sample_path = SAMPLE_DATA_DIR / "aws_cloudtrail_sample.json"
        if sample_path.exists():
            with open(sample_path, "r") as f:
                raw_df = load_telemetry_from_json(f.read())
        else:
            raw_df, _ = get_synthetic_data(500, True)
    elif data_source == "Sample Azure Activity Log":
        sample_path = SAMPLE_DATA_DIR / "azure_activity_sample.json"
        if sample_path.exists():
            with open(sample_path, "r") as f:
                raw_df = load_telemetry_from_json(f.read())
        else:
            raw_df, _ = get_synthetic_data(500, True)
    elif data_source == "Sample GCP Audit Log":
        sample_path = SAMPLE_DATA_DIR / "gcp_audit_sample.json"
        if sample_path.exists():
            with open(sample_path, "r") as f:
                raw_df = load_telemetry_from_json(f.read())
        else:
            raw_df, _ = get_synthetic_data(500, True)
    elif data_source == "Upload Custom JSON / CSV":
        if uploaded_file is not None:
            try:
                if uploaded_file.name.endswith(".csv"):
                    raw_df = load_telemetry_from_csv(uploaded_file)
                else:
                    content = uploaded_file.read().decode("utf-8")
                    raw_df = load_telemetry_from_json(content)
                st.success(f"Successfully parsed {len(raw_df)} events from {uploaded_file.name}!")
            except Exception as e:
                st.error(f"Error parsing uploaded telemetry: {e}")
                raw_df, _ = get_synthetic_data(500, True)
        else:
            st.info("Please upload a file or switch to the Synthetic Multi-Cloud Threat Generator.")
            raw_df, _ = get_synthetic_data(500, True)

    if raw_df.empty:
        st.warning("No telemetry records loaded. Please verify data source.")
        return

    # Execute IsolationForest Behavioral Anomaly Detection
    detector = CloudAnomalyDetector(contamination=contamination_rate)
    enriched_df = detector.fit_predict(raw_df)

    # Evaluate Deterministic IAM Posture Rules
    posture_findings = evaluate_iam_posture_rules(enriched_df, iam_hierarchy)
    posture_summary = calculate_posture_score(enriched_df, posture_findings)

    # Top KPI Metrics Header
    kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
    with kpi1:
        st.metric(
            label="Security Posture Score",
            value=f"{posture_summary['score']} / 100",
            delta=posture_summary["grade"],
            delta_color="normal" if posture_summary["score"] >= 75 else "inverse",
        )
    with kpi2:
        st.metric(
            label="Total Telemetry Events",
            value=f"{posture_summary['total_events']:,}",
        )
    with kpi3:
        st.metric(
            label="Anomalous API Calls",
            value=f"{posture_summary['total_anomalies']}",
            delta=f"{posture_summary['anomaly_rate_pct']}% rate",
            delta_color="inverse",
        )
    with kpi4:
        st.metric(
            label="Critical Threats",
            value=posture_summary["severity_counts"].get("Critical", 0),
            delta="Urgent Action Required",
            delta_color="inverse",
        )
    with kpi5:
        st.metric(
            label="Wildcard IAM Policies",
            value=posture_summary["wildcard_count"],
            delta="Privilege Escalation",
            delta_color="inverse",
        )

    st.markdown("---")

    # Primary Navigation Tabs
    tab_overview, tab_geomap, tab_sunburst, tab_ml_deepdive, tab_report = st.tabs(
        [
            "📊 Executive Overview & Posture",
            "🌍 Geo Threat Map (Choropleth)",
            "☀️ IAM Sunburst & Privileges",
            "🔍 Behavioral Anomaly Deep-Dive",
            "📄 Audit Report & Export",
        ]
    )

    # =========================================================================
    # Tab 1: Executive Overview
    # =========================================================================
    with tab_overview:
        col_left, col_right = st.columns([3, 2])

        with col_left:
            st.subheader("🚨 Critical Security Incidents & CIS Policy Violations")

            # Display Impossible Travel Incidents
            if posture_findings["impossible_travel"]:
                for inc in posture_findings["impossible_travel"]:
                    st.error(f"**{inc['rule_name']} [{inc['rule_id']}]**: {inc['description']}")

            # Display Root Account Violations
            if posture_findings["root_account_usage"]:
                for inc in posture_findings["root_account_usage"][:3]:
                    st.warning(f"**{inc['rule_name']} [{inc['rule_id']}]**: {inc['description']}")

            # Display Wildcards
            if posture_findings["wildcard_privileges"]:
                for inc in posture_findings["wildcard_privileges"][:3]:
                    st.warning(f"**{inc['rule_name']} [{inc['rule_id']}]**: {inc['description']}")

            # Top Risky Cloud Principals
            st.subheader("👥 Top Riskiest Cloud Identities")
            risky_principals_df = get_top_risky_principals(enriched_df, top_n=5)
            if not risky_principals_df.empty:
                st.dataframe(
                    risky_principals_df,
                    column_config={
                        "principal": "Identity",
                        "cloud_provider": "Cloud",
                        "principal_type": "Type",
                        "total_calls": "Total Calls",
                        "anomaly_calls": "Anomalies",
                        "avg_risk": "Avg Risk (0-100)",
                        "max_risk": "Max Risk (0-100)",
                    },
                    use_container_width=True,
                    hide_index=True,
                )

        with col_right:
            st.subheader("📈 Threat Severity Breakdown")
            donut_fig = create_severity_donut(posture_summary["severity_counts"])
            st.plotly_chart(donut_fig, use_container_width=True)

            # Quick Provider Breakdown
            st.subheader("☁️ Events by Cloud Provider")
            prov_counts = enriched_df["cloud_provider"].value_counts().reset_index()
            prov_counts.columns = ["Cloud Provider", "Event Count"]
            st.dataframe(prov_counts, use_container_width=True, hide_index=True)

    # =========================================================================
    # Tab 2: Geo Threat Map (Choropleth)
    # =========================================================================
    with tab_geomap:
        st.subheader("🌐 Global Anomalous Geo-Logins & Activity Map")
        st.caption(
            "Plotly Express Choropleth world map visualizes anomalous geographic origins, "
            "impossible travel trajectories, and international access patterns."
        )

        col_metric, col_filter = st.columns([2, 2])
        with col_metric:
            color_metric = st.selectbox(
                "Choropleth Color Metric",
                options=["anomaly_calls", "avg_risk", "total_calls"],
                format_func=lambda x: {
                    "anomaly_calls": "Anomalous Calls Count",
                    "avg_risk": "Average Risk Score",
                    "total_calls": "Total API Volume",
                }[x],
            )
        with col_filter:
            provider_filter = st.multiselect(
                "Filter by Cloud Provider",
                options=enriched_df["cloud_provider"].unique().tolist(),
                default=enriched_df["cloud_provider"].unique().tolist(),
            )

        filtered_geo_df = enriched_df[enriched_df["cloud_provider"].isin(provider_filter)]
        geo_fig = create_anomalous_geo_map(filtered_geo_df, color_metric=color_metric)
        st.plotly_chart(geo_fig, use_container_width=True)

        if posture_findings["impossible_travel"]:
            st.subheader("✈️ Detected Impossible Travel Events")
            imp_df = pd.DataFrame(posture_findings["impossible_travel"])
            st.dataframe(
                imp_df[
                    [
                        "principal",
                        "location_a",
                        "location_b",
                        "distance_km",
                        "duration_hours",
                        "implied_speed_kmh",
                        "severity",
                    ]
                ],
                use_container_width=True,
                hide_index=True,
            )

    # =========================================================================
    # Tab 3: IAM Sunburst & Privileges
    # =========================================================================
    with tab_sunburst:
        st.subheader("☀️ IAM Role-to-Permission Inheritance & Privilege Hierarchy")
        st.caption(
            "Hierarchical Plotly Express Sunburst chart renders "
            "Account -> Role / Identity -> Cloud Service -> Permission Action. "
            "Color represents risk severity (Red = Critical, Orange = High, "
            "Amber = Medium, Green = Low)."
        )

        sunburst_fig = create_iam_sunburst_chart(iam_hierarchy)
        st.plotly_chart(sunburst_fig, use_container_width=True)

        st.subheader("📋 IAM Posture & CIS Policy Violations")
        priv_count = len(posture_findings["privilege_escalation_events"])
        tab_wildcard, tab_dormant, tab_privesc = st.tabs(
            [
                f"Wildcard Permissions ({len(posture_findings['wildcard_privileges'])})",
                f"Dormant Admin Keys ({len(posture_findings['dormant_admin_credentials'])})",
                f"Privilege Escalation Events ({priv_count})",
            ]
        )

        with tab_wildcard:
            if posture_findings["wildcard_privileges"]:
                st.dataframe(
                    pd.DataFrame(posture_findings["wildcard_privileges"]),
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info("No excessive wildcard permissions detected in evaluated policies.")

        with tab_dormant:
            if posture_findings["dormant_admin_credentials"]:
                st.dataframe(
                    pd.DataFrame(posture_findings["dormant_admin_credentials"]),
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info("No dormant administrative credentials found.")

        with tab_privesc:
            if posture_findings["privilege_escalation_events"]:
                st.dataframe(
                    pd.DataFrame(posture_findings["privilege_escalation_events"]),
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info("No privilege escalation API calls observed in current telemetry.")

    # =========================================================================
    # Tab 4: Behavioral Anomaly Deep-Dive
    # =========================================================================
    with tab_ml_deepdive:
        st.subheader("🤖 IsolationForest Behavioral Anomaly Analysis")
        st.caption(
            "Identifies multi-dimensional behavioral anomalies using cyclical time encoding, "
            "API call velocity, rarity indexing, and sensitive service interaction patterns."
        )

        timeline_fig = create_timeline_chart(enriched_df)
        st.plotly_chart(timeline_fig, use_container_width=True)

        col_dist1, col_dist2 = st.columns(2)
        with col_dist1:
            dist_fig = create_anomaly_score_distribution(enriched_df)
            st.plotly_chart(dist_fig, use_container_width=True)
        with col_dist2:
            st.subheader("🔎 Anomaly Search & Filter")
            show_anomalies_only = st.checkbox("Show Flagged Anomalies Only", value=True)
            search_query = st.text_input("Filter by Principal, Action, or IP", value="")

        display_df = enriched_df.copy()
        if show_anomalies_only:
            display_df = display_df[display_df["is_anomaly"]]

        if search_query:
            query = search_query.lower()
            display_df = display_df[
                display_df["principal"].str.lower().str.contains(query)
                | display_df["action"].str.lower().str.contains(query)
                | display_df["source_ip"].str.contains(query)
            ]

        st.dataframe(
            display_df[
                [
                    "timestamp",
                    "cloud_provider",
                    "principal",
                    "action",
                    "severity",
                    "risk_score",
                    "country_name",
                    "source_ip",
                    "anomaly_reasons",
                ]
            ],
            column_config={
                "timestamp": "Timestamp",
                "cloud_provider": "Cloud",
                "principal": "Principal",
                "action": "API Action",
                "severity": "Severity",
                "risk_score": "Risk Score",
                "country_name": "Country",
                "source_ip": "Source IP",
                "anomaly_reasons": "Explainability Insight",
            },
            use_container_width=True,
            hide_index=True,
        )

    # =========================================================================
    # Tab 5: Audit Report & Export
    # =========================================================================
    with tab_report:
        tot_anom = posture_summary["total_anomalies"]
        anom_pct = posture_summary["anomaly_rate_pct"]
        report_md = f"""# Cloud Security Posture & IAM Privilege Audit Report
**Generated:** {pd.Timestamp.now(tz="UTC").isoformat()}
**Security Posture Grade:** {posture_summary['grade']} ({posture_summary['score']}/100)

## Executive Summary
- **Total Telemetry Events Analyzed:** {posture_summary['total_events']:,}
- **Anomalous API Invocations:** {tot_anom} ({anom_pct}%)
- **Impossible Travel Detections:** {posture_summary['impossible_travel_count']}
- **Root Account Abuse Incidents:** {posture_summary['root_abuse_count']}
- **Excessive Wildcard Policies:** {posture_summary['wildcard_count']}
- **Dormant Admin Identities:** {posture_summary['dormant_count']}

## Threat Severity Distribution
- **Critical:** {posture_summary['severity_counts'].get('Critical', 0)}
- **High:** {posture_summary['severity_counts'].get('High', 0)}
- **Medium:** {posture_summary['severity_counts'].get('Medium', 0)}
- **Low:** {posture_summary['severity_counts'].get('Low', 0)}

## Recommended Remediation Steps
1. Revoke excessive wildcard (`*`) permissions on production roles.
2. Enforce Hardware MFA on all Root / Superadmin accounts across AWS, Azure, and GCP.
3. Investigate impossible travel logins and enforce conditional access policies.
4. Rotate credentials or de-provision dormant accounts inactive for > 90 days.
"""

        st.markdown(report_md)

        col_dl1, col_dl2 = st.columns(2)
        with col_dl1:
            st.download_button(
                label="📥 Download Audit Report (Markdown)",
                data=report_md,
                file_name="cloud_security_audit_report.md",
                mime="text/markdown",
            )
        with col_dl2:
            csv_threats = enriched_df[enriched_df["is_anomaly"]].to_csv(index=False)
            st.download_button(
                label="📥 Export Anomaly Threat Log (CSV)",
                data=csv_threats,
                file_name="anomalous_threats_export.csv",
                mime="text/csv",
            )


if __name__ == "__main__":
    main()
