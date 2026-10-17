"""Sunburst Chart Visualization for IAM Role-to-Permission Inheritance."""

from __future__ import annotations

from typing import Any, Dict, List
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def create_iam_sunburst_chart(
    hierarchy_data: List[Dict[str, Any]] | pd.DataFrame,
) -> go.Figure:
    """Render Plotly Express Sunburst chart of IAM role-to-permission inheritance."""
    if isinstance(hierarchy_data, list):
        df = pd.DataFrame(hierarchy_data)
    else:
        df = hierarchy_data.copy()

    if len(df) == 0:
        fig = go.Figure()
        fig.update_layout(
            title="No IAM Hierarchy Data Available",
            template="plotly_dark",
        )
        return fig

    # Add numeric weight for sizing
    df["value"] = 1

    # Map risk levels to visual severity colors
    color_map = {
        "Critical": "#EF4444",  # Red
        "High": "#F97316",  # Orange
        "Medium": "#F59E0B",  # Amber
        "Low": "#10B981",  # Emerald
    }

    fig = px.sunburst(
        df,
        path=["cloud_provider", "account_id", "role_name", "service", "permission"],
        values="value",
        color="risk_level",
        color_discrete_map=color_map,
        hover_data={
            "identity_type": True,
            "has_wildcard": True,
            "is_dormant": True,
            "value": False,
        },
        title="IAM Role-to-Permission Inheritance & Privilege Hierarchy",
    )

    fig.update_traces(
        textinfo="label+percent entry",
        insidetextorientation="radial",
        leaf=dict(opacity=0.9),
    )

    fig.update_layout(
        template="plotly_dark",
        margin=dict(t=50, l=10, r=10, b=10),
        coloraxis_showscale=False,
    )

    return fig
