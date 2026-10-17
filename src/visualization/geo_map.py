"""Choropleth World Map Visualization for Anomalous Geo-Logins."""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


def create_anomalous_geo_map(
    df: pd.DataFrame,
    color_metric: str = "anomaly_calls",
) -> go.Figure:
    """Render Plotly Express Choropleth world map displaying geo-anomalies."""
    if len(df) == 0:
        fig = go.Figure()
        fig.update_layout(
            title="No Geo-Telemetry Available",
            template="plotly_dark",
        )
        return fig

    # Group by country code for choropleth mapping
    country_stats = (
        df.groupby(["country_code", "country_name"])
        .agg(
            total_calls=("timestamp", "count"),
            anomaly_calls=("is_anomaly", "sum"),
            avg_risk=("risk_score", "mean"),
            max_risk=("risk_score", "max"),
            top_principal=(
                "principal",
                lambda s: s.value_counts().index[0] if len(s) > 0 else "None",
            ),
        )
        .reset_index()
    )

    country_stats["avg_risk"] = country_stats["avg_risk"].round(1)
    country_stats["max_risk"] = country_stats["max_risk"].round(1)

    # Choose color scale based on metric
    if color_metric == "anomaly_calls":
        color_col = "anomaly_calls"
        color_title = "Anomalies Count"
        colorscale = "Reds"
    elif color_metric == "avg_risk":
        color_col = "avg_risk"
        color_title = "Avg Risk Score"
        colorscale = "YlOrRd"
    else:
        color_col = "total_calls"
        color_title = "Total API Calls"
        colorscale = "Blues"

    # Choropleth world map using plotly.express
    fig = px.choropleth(
        country_stats,
        locations="country_code",
        locationmode="ISO-3",
        color=color_col,
        hover_name="country_name",
        hover_data={
            "country_code": True,
            "total_calls": True,
            "anomaly_calls": True,
            "avg_risk": True,
            "max_risk": True,
            "top_principal": True,
        },
        color_continuous_scale=colorscale,
        labels={
            "anomaly_calls": "Anomalies",
            "total_calls": "Total Calls",
            "avg_risk": "Avg Risk",
            "max_risk": "Max Risk",
            "top_principal": "Top Principal",
        },
        title=f"Global Threat Distribution & Anomalous Geo-Logins ({color_title})",
    )

    # Add ScatterGeo pinpoint markers for anomalous coordinates
    anom_events = df[df.get("is_anomaly", False)]
    if len(anom_events) > 0:
        fig.add_trace(
            go.Scattergeo(
                lon=anom_events["longitude"],
                lat=anom_events["latitude"],
                text=anom_events.apply(
                    lambda r: (
                        f"<b>{r['principal']}</b><br>"
                        f"Action: {r['action']}<br>"
                        f"IP: {r['source_ip']}<br>"
                        f"Risk: {r['risk_score']}"
                    ),
                    axis=1,
                ),
                mode="markers",
                marker=dict(
                    size=10,
                    color="crimson",
                    symbol="circle-dot",
                    line=dict(width=1, color="white"),
                ),
                name="Anomalous Session Origin",
                hoverinfo="text",
            )
        )

    fig.update_layout(
        template="plotly_dark",
        margin=dict(l=0, r=0, t=50, b=0),
        geo=dict(
            showframe=False,
            showcoastlines=True,
            projection_type="natural earth",
            bgcolor="rgba(0,0,0,0)",
            lakecolor="#1e293b",
            landcolor="#0f172a",
        ),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
        ),
    )

    return fig
