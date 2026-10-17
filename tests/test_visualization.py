"""Unit tests for Plotly visualizations."""

import pandas as pd
import plotly.graph_objects as go

from src.data.generator import (
    generate_synthetic_iam_hierarchy,
    generate_synthetic_telemetry,
)
from src.analytics.anomaly import CloudAnomalyDetector
from src.visualization.charts import (
    create_anomaly_score_distribution,
    create_severity_donut,
    create_timeline_chart,
)
from src.visualization.geo_map import create_anomalous_geo_map
from src.visualization.sunburst import create_iam_sunburst_chart


def test_create_anomalous_geo_map():
    df = generate_synthetic_telemetry(n_events=30, inject_attacks=True)
    detector = CloudAnomalyDetector(contamination=0.1)
    enriched_df = detector.fit_predict(df)

    fig = create_anomalous_geo_map(enriched_df, color_metric="anomaly_calls")
    assert isinstance(fig, go.Figure)


def test_create_anomalous_geo_map_empty():
    empty_df = pd.DataFrame()
    fig = create_anomalous_geo_map(empty_df)
    assert isinstance(fig, go.Figure)


def test_create_iam_sunburst_chart():
    hierarchy = generate_synthetic_iam_hierarchy()
    fig = create_iam_sunburst_chart(hierarchy)
    assert isinstance(fig, go.Figure)


def test_create_iam_sunburst_chart_empty():
    fig = create_iam_sunburst_chart([])
    assert isinstance(fig, go.Figure)


def test_create_charts():
    df = generate_synthetic_telemetry(n_events=30, inject_attacks=True)
    detector = CloudAnomalyDetector(contamination=0.1)
    enriched_df = detector.fit_predict(df)

    t_fig = create_timeline_chart(enriched_df)
    assert isinstance(t_fig, go.Figure)

    d_fig = create_anomaly_score_distribution(enriched_df)
    assert isinstance(d_fig, go.Figure)

    donut_fig = create_severity_donut({"Critical": 2, "High": 5, "Low": 10})
    assert isinstance(donut_fig, go.Figure)
