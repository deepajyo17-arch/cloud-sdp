"""Supporting Plotly Visualizations for Cloud Security Dashboards."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def create_timeline_chart(df: pd.DataFrame) -> go.Figure:
    """Render temporal scatter of API calls with highlighted anomaly points."""
    if len(df) == 0:
        return go.Figure()

    fig = px.scatter(
        df,
        x="timestamp",
        y="risk_score",
        color="severity",
        symbol="is_anomaly",
        symbol_map={True: "circle-open-dot", False: "circle"},
        color_discrete_map={
            "Critical": "#EF4444",
            "High": "#F97316",
            "Medium": "#F59E0B",
            "Low": "#10B981",
        },
        hover_data={
            "principal": True,
            "action": True,
            "cloud_provider": True,
            "country_name": True,
            "risk_score": True,
            "anomaly_reasons": True,
        },
        title="Temporal API Activity & Anomaly Risk Scores",
        labels={"timestamp": "Event Timestamp (UTC)", "risk_score": "Risk Score (0-100)"},
    )

    fig.update_layout(
        template="plotly_dark",
        legend_title_text="Threat Severity",
        hovermode="closest",
        margin=dict(t=50, l=10, r=10, b=10),
    )
    return fig


def create_anomaly_score_distribution(df: pd.DataFrame) -> go.Figure:
    """Render distribution of anomaly scores separating normal vs anomalous events."""
    if len(df) == 0:
        return go.Figure()

    fig = px.histogram(
        df,
        x="risk_score",
        color="is_anomaly",
        nbins=40,
        barmode="overlay",
        color_discrete_map={True: "#EF4444", False: "#3B82F6"},
        labels={"risk_score": "Risk Score", "is_anomaly": "Is Anomaly"},
        title="IsolationForest Behavioral Risk Score Distribution",
    )

    fig.update_layout(
        template="plotly_dark",
        margin=dict(t=50, l=10, r=10, b=10),
        xaxis_title="Risk Score (0 = Benign, 100 = Highly Anomalous)",
        yaxis_title="Event Count",
    )
    return fig


def create_severity_donut(severities: dict[str, int]) -> go.Figure:
    """Render donut chart for overall findings breakdown."""
    labels = list(severities.keys())
    values = list(severities.values())

    colors = {
        "Critical": "#EF4444",
        "High": "#F97316",
        "Medium": "#F59E0B",
        "Low": "#10B981",
    }

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.6,
                marker=dict(colors=[colors.get(k, "#3B82F6") for k in labels]),
                textinfo="label+value",
            )
        ]
    )

    fig.update_layout(
        template="plotly_dark",
        title="Findings by Severity",
        showlegend=True,
        margin=dict(t=50, l=10, r=10, b=10),
    )
    return fig
