"""Tests for the Part 9 dashboard components (data -> figure transforms).

matplotlib runs headless (Agg backend); no browser or Streamlit server is
needed for these tests.
"""

import matplotlib
import pandas as pd
import pytest

matplotlib.use("Agg")
import matplotlib.figure  # noqa: E402

from dashboard.components.charts import (  # noqa: E402
    attack_probability_chart,
    benign_vs_attack_chart,
    detections_over_time_chart,
    response_action_chart,
    severity_distribution_chart,
)
from dashboard.components.tables import DETECTION_COLUMNS  # noqa: E402


def _stats(total_benign=10, total_attacks=2):
    return {
        "total_benign": total_benign,
        "total_attacks": total_attacks,
        "low_severity_count": 9,
        "medium_severity_count": 1,
        "high_severity_count": 2,
        "no_action_count": 10,
        "alert_count": 1,
        "dry_run_block_count": 1,
        "block_requested_count": 0,
    }


def test_response_action_chart_labels_simulation_and_returns_figure():
    figure = response_action_chart(_stats())
    assert isinstance(figure, matplotlib.figure.Figure)
    title = figure.axes[0].get_title().lower()
    assert "simulation" in title and "no real blocking" in title
    xlabels = [t.get_text().lower() for t in figure.axes[0].get_xticklabels()]
    assert any("simulated" in label for label in xlabels)
    assert any("requires adapter" in label for label in xlabels)


def test_detection_distribution_charts_return_figures():
    assert isinstance(benign_vs_attack_chart(_stats()), matplotlib.figure.Figure)
    assert isinstance(severity_distribution_chart(_stats()), matplotlib.figure.Figure)


def test_detections_over_time_chart_handles_rows_and_empty():
    with_rows = detections_over_time_chart(
        [{"timestamp": "2026-10-07T12:00:00", "count": 5}]
    )
    assert isinstance(with_rows, matplotlib.figure.Figure)
    empty = detections_over_time_chart([])
    assert isinstance(empty, matplotlib.figure.Figure)  # honest "No data" chart


def test_attack_probability_chart():
    frame = pd.DataFrame({"attack_probability": [0.9, 0.8, 0.02, None]})
    figure = attack_probability_chart(frame)
    assert isinstance(figure, matplotlib.figure.Figure)
    # None values are dropped, not plotted as zero
    assert figure.axes[0].patches is not None

    assert attack_probability_chart(pd.DataFrame()) is None
    assert attack_probability_chart(pd.DataFrame({"attack_probability": [None]})) is None


def test_detection_table_columns_cover_spec():
    for column in (
        "timestamp", "flow_id", "prediction", "attack_probability", "severity",
        "response_action", "response_mode", "response_status", "model_name",
    ):
        assert column in DETECTION_COLUMNS
